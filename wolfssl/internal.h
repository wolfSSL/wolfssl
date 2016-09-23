/* internal.h
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



#ifndef WOLFSSL_INT_H
#define WOLFSSL_INT_H


#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/ssl.h>
#ifdef HAVE_CRL
    #include <wolfssl/crl.h>
#endif
#include <wolfssl/wolfcrypt/random.h>
#ifndef NO_DES3
    #include <wolfssl/wolfcrypt/des3.h>
#endif
#ifndef NO_HC128
    #include <wolfssl/wolfcrypt/hc128.h>
#endif
#ifndef NO_RABBIT
    #include <wolfssl/wolfcrypt/rabbit.h>
#endif
#ifdef HAVE_CHACHA
    #include <wolfssl/wolfcrypt/chacha.h>
#endif
#ifndef NO_ASN
    #include <wolfssl/wolfcrypt/asn.h>
#endif
#ifndef NO_MD5
    #include <wolfssl/wolfcrypt/md5.h>
#endif
#ifndef NO_SHA
    #include <wolfssl/wolfcrypt/sha.h>
#endif
#ifndef NO_AES
    #include <wolfssl/wolfcrypt/aes.h>
#endif
#ifdef HAVE_POLY1305
    #include <wolfssl/wolfcrypt/poly1305.h>
#endif
#ifdef HAVE_CAMELLIA
    #include <wolfssl/wolfcrypt/camellia.h>
#endif
#include <wolfssl/wolfcrypt/logging.h>
#ifndef NO_HMAC
    #include <wolfssl/wolfcrypt/hmac.h>
#endif
#ifndef NO_RC4
    #include <wolfssl/wolfcrypt/arc4.h>
#endif
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifndef NO_SHA256
    #include <wolfssl/wolfcrypt/sha256.h>
#endif
#ifdef HAVE_OCSP
    #include <wolfssl/ocsp.h>
#endif
#ifdef WOLFSSL_SHA512
    #include <wolfssl/wolfcrypt/sha512.h>
#endif

#ifdef HAVE_AESGCM
    #include <wolfssl/wolfcrypt/sha512.h>
#endif

#ifdef WOLFSSL_RIPEMD
    #include <wolfssl/wolfcrypt/ripemd.h>
#endif

#ifdef HAVE_IDEA
    #include <wolfssl/wolfcrypt/idea.h>
#endif

#include <wolfssl/wolfcrypt/hash.h>

#ifdef WOLFSSL_CALLBACKS
    #include <wolfssl/callbacks.h>
    #include <signal.h>
#endif

#ifdef USE_WINDOWS_API
    #ifdef WOLFSSL_GAME_BUILD
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
#elif defined(FREERTOS) || defined(FREERTOS_TCP) || defined(WOLFSSL_SAFERTOS)
    /* do nothing */
#elif defined(EBSNET)
    /* do nothing */
#elif defined(FREESCALE_MQX) || defined(FREESCALE_KSDK_MQX)
    /* do nothing */
#elif defined(FREESCALE_FREE_RTOS)
    #include "fsl_os_abstraction.h"
#elif defined(WOLFSSL_uITRON4)
        /* do nothing */
#elif defined(WOLFSSL_uTKERNEL2)
        /* do nothing */
#elif defined(WOLFSSL_MDK_ARM)
    #if defined(WOLFSSL_MDK5)
         #include "cmsis_os.h"
    #else
        #include <rtl.h>
    #endif
#elif defined(WOLFSSL_CMSIS_RTOS)
    #include "cmsis_os.h"
#elif defined(MBED)
#elif defined(WOLFSSL_TIRTOS)
    /* do nothing */
#else
    #ifndef SINGLE_THREADED
        #define WOLFSSL_PTHREADS
        #include <pthread.h>
    #endif
    #if defined(OPENSSL_EXTRA) || defined(GOAHEAD_WS)
        #include <unistd.h>      /* for close of BIO */
    #endif
#endif


#ifdef HAVE_LIBZ
    #include "zlib.h"
#endif

#ifdef WOLFSSL_ASYNC_CRYPT
    #include <wolfssl/wolfcrypt/async.h>
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

#ifdef NO_MD5
    #define MD5_DIGEST_SIZE 16
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

/* Define or comment out the cipher suites you'd like to be compiled in
   make sure to use at least one BUILD_SSL_xxx or BUILD_TLS_xxx is defined

   When adding cipher suites, add name to cipher_names, idx to cipher_name_idx

   Now that there is a maximum strength crypto build, the following BUILD_XXX
   flags need to be divided into two groups selected by WOLFSSL_MAX_STRENGTH.
   Those that do not use Perfect Forward Security and do not use AEAD ciphers
   need to be switched off. Allowed suites use (EC)DHE, AES-GCM|CCM, or
   CHACHA-POLY.
*/

/* Check that if WOLFSSL_MAX_STRENGTH is set that all the required options are
 * not turned off. */
#if defined(WOLFSSL_MAX_STRENGTH) && \
    ((!defined(HAVE_ECC) && (defined(NO_DH) || defined(NO_RSA))) || \
     (!defined(HAVE_AESGCM) && !defined(HAVE_AESCCM) && \
      (!defined(HAVE_POLY1305) || !defined(HAVE_CHACHA))) || \
     (defined(NO_SHA256) && !defined(WOLFSSL_SHA384)) || \
     !defined(NO_OLD_TLS))

    #error "You are trying to build max strength with requirements disabled."
#endif

/* Have QSH : Quantum-safe Handshake */
#if defined(HAVE_QSH)
    #define BUILD_TLS_QSH
#endif

#ifndef WOLFSSL_MAX_STRENGTH

    #if !defined(NO_RSA) && !defined(NO_RC4)
        #if defined(WOLFSSL_STATIC_RSA)
            #if !defined(NO_SHA)
                #define BUILD_SSL_RSA_WITH_RC4_128_SHA
            #endif
            #if !defined(NO_MD5)
                #define BUILD_SSL_RSA_WITH_RC4_128_MD5
            #endif
        #endif
        #if !defined(NO_TLS) && defined(HAVE_NTRU) && !defined(NO_SHA) \
            && defined(WOLFSSL_STATIC_RSA)
            #define BUILD_TLS_NTRU_RSA_WITH_RC4_128_SHA
        #endif
    #endif

    #if !defined(NO_RSA) && !defined(NO_DES3)
        #if !defined(NO_SHA)
            #if defined(WOLFSSL_STATIC_RSA)
                #define BUILD_SSL_RSA_WITH_3DES_EDE_CBC_SHA
            #endif
            #if !defined(NO_TLS) && defined(HAVE_NTRU) \
                && defined(WOLFSSL_STATIC_RSA)
                    #define BUILD_TLS_NTRU_RSA_WITH_3DES_EDE_CBC_SHA
            #endif
        #endif
    #endif

    #if !defined(NO_RSA) && defined(HAVE_IDEA)
        #if !defined(NO_SHA) && defined(WOLFSSL_STATIC_RSA)
            #define BUILD_SSL_RSA_WITH_IDEA_CBC_SHA
        #endif
    #endif

    #if !defined(NO_RSA) && !defined(NO_AES) && !defined(NO_TLS)
        #if !defined(NO_SHA)
            #if defined(WOLFSSL_STATIC_RSA)
                #define BUILD_TLS_RSA_WITH_AES_128_CBC_SHA
                #define BUILD_TLS_RSA_WITH_AES_256_CBC_SHA
            #endif
            #if defined(HAVE_NTRU) && defined(WOLFSSL_STATIC_RSA)
                    #define BUILD_TLS_NTRU_RSA_WITH_AES_128_CBC_SHA
                    #define BUILD_TLS_NTRU_RSA_WITH_AES_256_CBC_SHA
            #endif
        #endif
        #if defined(WOLFSSL_STATIC_RSA)
            #if !defined (NO_SHA256)
                #define BUILD_TLS_RSA_WITH_AES_128_CBC_SHA256
                #define BUILD_TLS_RSA_WITH_AES_256_CBC_SHA256
            #endif
            #if defined (HAVE_AESGCM)
                #define BUILD_TLS_RSA_WITH_AES_128_GCM_SHA256
                #if defined (WOLFSSL_SHA384)
                    #define BUILD_TLS_RSA_WITH_AES_256_GCM_SHA384
                #endif
            #endif
            #if defined (HAVE_AESCCM)
                #define BUILD_TLS_RSA_WITH_AES_128_CCM_8
                #define BUILD_TLS_RSA_WITH_AES_256_CCM_8
            #endif
            #if defined(HAVE_BLAKE2)
                #define BUILD_TLS_RSA_WITH_AES_128_CBC_B2B256
                #define BUILD_TLS_RSA_WITH_AES_256_CBC_B2B256
            #endif
        #endif
    #endif

    #if defined(HAVE_CAMELLIA) && !defined(NO_TLS)
        #ifndef NO_RSA
          #if defined(WOLFSSL_STATIC_RSA)
            #if !defined(NO_SHA)
                #define BUILD_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
                #define BUILD_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
            #endif
            #ifndef NO_SHA256
                #define BUILD_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256
                #define BUILD_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256
            #endif
          #endif
            #if !defined(NO_DH)
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

#if defined(WOLFSSL_STATIC_PSK)
    #if !defined(NO_PSK) && !defined(NO_AES) && !defined(NO_TLS)
        #if !defined(NO_SHA)
            #define BUILD_TLS_PSK_WITH_AES_128_CBC_SHA
            #define BUILD_TLS_PSK_WITH_AES_256_CBC_SHA
        #endif
        #ifndef NO_SHA256
            #define BUILD_TLS_PSK_WITH_AES_128_CBC_SHA256
            #ifdef HAVE_AESGCM
                #define BUILD_TLS_PSK_WITH_AES_128_GCM_SHA256
            #endif
            #ifdef HAVE_AESCCM
                #define BUILD_TLS_PSK_WITH_AES_128_CCM_8
                #define BUILD_TLS_PSK_WITH_AES_256_CCM_8
                #define BUILD_TLS_PSK_WITH_AES_128_CCM
                #define BUILD_TLS_PSK_WITH_AES_256_CCM
            #endif
        #endif
        #ifdef WOLFSSL_SHA384
            #define BUILD_TLS_PSK_WITH_AES_256_CBC_SHA384
            #ifdef HAVE_AESGCM
                #define BUILD_TLS_PSK_WITH_AES_256_GCM_SHA384
            #endif
        #endif
    #endif
#endif

    #if !defined(NO_TLS) && defined(HAVE_NULL_CIPHER)
        #if !defined(NO_RSA)
            #if defined(WOLFSSL_STATIC_RSA)
                #if !defined(NO_SHA)
                    #define BUILD_TLS_RSA_WITH_NULL_SHA
                #endif
                #ifndef NO_SHA256
                    #define BUILD_TLS_RSA_WITH_NULL_SHA256
                #endif
            #endif
        #endif
        #if !defined(NO_PSK) && defined(WOLFSSL_STATIC_PSK)
            #if !defined(NO_SHA)
                #define BUILD_TLS_PSK_WITH_NULL_SHA
            #endif
            #ifndef NO_SHA256
                #define BUILD_TLS_PSK_WITH_NULL_SHA256
            #endif
            #ifdef WOLFSSL_SHA384
                #define BUILD_TLS_PSK_WITH_NULL_SHA384
            #endif
        #endif
    #endif

#if defined(WOLFSSL_STATIC_RSA)
    #if !defined(NO_HC128) && !defined(NO_RSA) && !defined(NO_TLS)
        #ifndef NO_MD5
            #define BUILD_TLS_RSA_WITH_HC_128_MD5
        #endif
        #if !defined(NO_SHA)
            #define BUILD_TLS_RSA_WITH_HC_128_SHA
        #endif
        #if defined(HAVE_BLAKE2)
            #define BUILD_TLS_RSA_WITH_HC_128_B2B256
        #endif
    #endif

    #if !defined(NO_RABBIT) && !defined(NO_TLS) && !defined(NO_RSA)
        #if !defined(NO_SHA)
            #define BUILD_TLS_RSA_WITH_RABBIT_SHA
        #endif
    #endif
#endif

    #if !defined(NO_DH) && !defined(NO_AES) && !defined(NO_TLS) && \
        !defined(NO_RSA)

        #if !defined(NO_SHA)
            #define BUILD_TLS_DHE_RSA_WITH_AES_128_CBC_SHA
            #define BUILD_TLS_DHE_RSA_WITH_AES_256_CBC_SHA
            #if !defined(NO_DES3)
                #define BUILD_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
            #endif
        #endif
        #if !defined(NO_SHA256)
            #define BUILD_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
            #define BUILD_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
        #endif
    #endif

    #if defined(HAVE_ANON) && !defined(NO_TLS) && !defined(NO_DH) && \
        !defined(NO_AES) && !defined(NO_SHA)
        #define BUILD_TLS_DH_anon_WITH_AES_128_CBC_SHA
    #endif

    #if !defined(NO_DH) && !defined(NO_PSK) && !defined(NO_TLS)
        #ifndef NO_SHA256
            #ifndef NO_AES
                #define BUILD_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256
            #endif
            #ifdef HAVE_NULL_CIPHER
                #define BUILD_TLS_DHE_PSK_WITH_NULL_SHA256
            #endif
        #endif
        #ifdef WOLFSSL_SHA384
            #ifndef NO_AES
                #define BUILD_TLS_DHE_PSK_WITH_AES_256_CBC_SHA384
            #endif
            #ifdef HAVE_NULL_CIPHER
                #define BUILD_TLS_DHE_PSK_WITH_NULL_SHA384
            #endif
        #endif
    #endif

    #if defined(HAVE_ECC) && !defined(NO_TLS)
        #if !defined(NO_AES)
            #if !defined(NO_SHA)
                #if !defined(NO_RSA)
                    #define BUILD_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
                    #define BUILD_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
                    #if defined(WOLFSSL_STATIC_DH)
                        #define BUILD_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
                        #define BUILD_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
                    #endif
                #endif

                #define BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
                #define BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA

                #if defined(WOLFSSL_STATIC_DH)
                    #define BUILD_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
                    #define BUILD_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
                #endif
            #endif /* NO_SHA */
            #ifndef NO_SHA256
                #if !defined(NO_RSA)
                    #define BUILD_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
                    #if defined(WOLFSSL_STATIC_DH)
                        #define BUILD_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
                    #endif
                #endif
                #define BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
                #if defined(WOLFSSL_STATIC_DH)
                    #define BUILD_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
                #endif
            #endif

            #ifdef WOLFSSL_SHA384
                #if !defined(NO_RSA)
                    #define BUILD_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
                    #if defined(WOLFSSL_STATIC_DH)
                        #define BUILD_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
                    #endif
                #endif
                #define BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
                #if defined(WOLFSSL_STATIC_DH)
                    #define BUILD_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
                #endif
            #endif

            #if defined (HAVE_AESGCM)
                #if !defined(NO_RSA)
                    #if defined(WOLFSSL_STATIC_DH)
                        #define BUILD_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
                    #endif
                    #if defined(WOLFSSL_SHA384)
                        #if defined(WOLFSSL_STATIC_DH)
                            #define BUILD_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
                        #endif
                    #endif
                #endif

                #if defined(WOLFSSL_STATIC_DH)
                    #define BUILD_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
                #endif

                #if defined(WOLFSSL_SHA384)
                    #if defined(WOLFSSL_STATIC_DH)
                        #define BUILD_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
                    #endif
                #endif
            #endif
        #endif /* NO_AES */
        #if !defined(NO_RC4)
            #if !defined(NO_SHA)
                #if !defined(NO_RSA)
                    #define BUILD_TLS_ECDHE_RSA_WITH_RC4_128_SHA
                    #if defined(WOLFSSL_STATIC_DH)
                        #define BUILD_TLS_ECDH_RSA_WITH_RC4_128_SHA
                    #endif
                #endif

                #define BUILD_TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
                #if defined(WOLFSSL_STATIC_DH)
                    #define BUILD_TLS_ECDH_ECDSA_WITH_RC4_128_SHA
                #endif
            #endif
        #endif
        #if !defined(NO_DES3)
            #ifndef NO_SHA
                #if !defined(NO_RSA)
                    #define BUILD_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
                    #if defined(WOLFSSL_STATIC_DH)
                        #define BUILD_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
                    #endif
                #endif

                #define BUILD_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
                #if defined(WOLFSSL_STATIC_DH)
                    #define BUILD_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
                #endif
            #endif /* NO_SHA */
        #endif
        #if defined(HAVE_NULL_CIPHER)
            #if !defined(NO_SHA)
                #define BUILD_TLS_ECDHE_ECDSA_WITH_NULL_SHA
            #endif
            #if !defined(NO_PSK) && !defined(NO_SHA256)
                #define BUILD_TLS_ECDHE_PSK_WITH_NULL_SHA256
            #endif
        #endif
        #if !defined(NO_PSK) && !defined(NO_SHA256) && !defined(NO_AES)
            #define BUILD_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256
        #endif
    #endif
    #if defined(HAVE_CHACHA) && defined(HAVE_POLY1305) && !defined(NO_SHA256)
        #if !defined(NO_OLD_POLY1305)
        #ifdef HAVE_ECC
            #define BUILD_TLS_ECDHE_ECDSA_WITH_CHACHA20_OLD_POLY1305_SHA256
            #ifndef NO_RSA
                #define BUILD_TLS_ECDHE_RSA_WITH_CHACHA20_OLD_POLY1305_SHA256
            #endif
        #endif
        #if !defined(NO_DH) && !defined(NO_RSA)
            #define BUILD_TLS_DHE_RSA_WITH_CHACHA20_OLD_POLY1305_SHA256
        #endif
        #endif /* NO_OLD_POLY1305 */
        #if !defined(NO_PSK)
            #define BUILD_TLS_PSK_WITH_CHACHA20_POLY1305_SHA256
            #ifdef HAVE_ECC
                #define BUILD_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256
            #endif
            #ifndef NO_DH
                #define BUILD_TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256
            #endif
        #endif /* !NO_PSK */
    #endif

#endif /* !WOLFSSL_MAX_STRENGTH */

#if !defined(NO_DH) && !defined(NO_AES) && !defined(NO_TLS) && \
    !defined(NO_RSA) && defined(HAVE_AESGCM)

    #ifndef NO_SHA256
        #define BUILD_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    #endif

    #ifdef WOLFSSL_SHA384
        #define BUILD_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    #endif
#endif

#if !defined(NO_DH) && !defined(NO_PSK) && !defined(NO_TLS)
    #ifndef NO_SHA256
        #ifdef HAVE_AESGCM
            #define BUILD_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
        #endif
        #ifdef HAVE_AESCCM
            #define BUILD_TLS_DHE_PSK_WITH_AES_128_CCM
            #define BUILD_TLS_DHE_PSK_WITH_AES_256_CCM
        #endif
    #endif
    #if defined(WOLFSSL_SHA384) && defined(HAVE_AESGCM)
        #define BUILD_TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
    #endif
#endif

#if defined(HAVE_ECC) && !defined(NO_TLS) && !defined(NO_AES)
    #ifdef HAVE_AESGCM
        #ifndef NO_SHA256
            #define BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            #ifndef NO_RSA
                #define BUILD_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            #endif
        #endif
        #ifdef WOLFSSL_SHA384
            #define BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            #ifndef NO_RSA
                #define BUILD_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            #endif
        #endif
    #endif
    #if defined(HAVE_AESCCM) && !defined(NO_SHA256)
        #define BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CCM
        #define BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
        #define BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8
    #endif
#endif

#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305) && !defined(NO_SHA256)
    #ifdef HAVE_ECC
        #define BUILD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        #ifndef NO_RSA
            #define BUILD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        #endif
    #endif
    #if !defined(NO_DH) && !defined(NO_RSA)
        #define BUILD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
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
    defined(BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256) || \
    defined(BUILD_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256)
    #undef  BUILD_AES
    #define BUILD_AES
#endif

#if defined(BUILD_TLS_RSA_WITH_AES_128_GCM_SHA256) || \
    defined(BUILD_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256) || \
    defined(BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256) || \
    defined(BUILD_TLS_PSK_WITH_AES_128_GCM_SHA256) || \
    defined(BUILD_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256)
    #define BUILD_AESGCM
#endif

#if defined(BUILD_TLS_RSA_WITH_HC_128_SHA) || \
    defined(BUILD_TLS_RSA_WITH_HC_128_MD5) || \
    defined(BUILD_TLS_RSA_WITH_HC_128_B2B256)
    #define BUILD_HC128
#endif

#if defined(BUILD_TLS_RSA_WITH_RABBIT_SHA)
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

#ifdef HAVE_CHACHA
    #define CHACHA20_BLOCK_SIZE 16
#endif

#if defined(WOLFSSL_MAX_STRENGTH) || \
    defined(HAVE_AESGCM) || defined(HAVE_AESCCM) || \
    (defined(HAVE_CHACHA) && defined(HAVE_POLY1305))

    #define HAVE_AEAD
#endif

#if defined(WOLFSSL_MAX_STRENGTH) || \
    defined(HAVE_ECC) || !defined(NO_DH)

    #define HAVE_PFS
#endif

#if defined(BUILD_SSL_RSA_WITH_IDEA_CBC_SHA)
    #define BUILD_IDEA
#endif

/* actual cipher values, 2nd byte */
enum {
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x16,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA  = 0x39,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA  = 0x33,
    TLS_DH_anon_WITH_AES_128_CBC_SHA  = 0x34,
    TLS_RSA_WITH_AES_256_CBC_SHA      = 0x35,
    TLS_RSA_WITH_AES_128_CBC_SHA      = 0x2F,
    TLS_RSA_WITH_NULL_SHA             = 0x02,
    TLS_PSK_WITH_AES_256_CBC_SHA      = 0x8d,
    TLS_PSK_WITH_AES_128_CBC_SHA256   = 0xae,
    TLS_PSK_WITH_AES_256_CBC_SHA384   = 0xaf,
    TLS_PSK_WITH_AES_128_CBC_SHA      = 0x8c,
    TLS_PSK_WITH_NULL_SHA256          = 0xb0,
    TLS_PSK_WITH_NULL_SHA384          = 0xb1,
    TLS_PSK_WITH_NULL_SHA             = 0x2c,
    SSL_RSA_WITH_RC4_128_SHA          = 0x05,
    SSL_RSA_WITH_RC4_128_MD5          = 0x04,
    SSL_RSA_WITH_3DES_EDE_CBC_SHA     = 0x0A,
    SSL_RSA_WITH_IDEA_CBC_SHA         = 0x07,

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
    TLS_ECDHE_ECDSA_WITH_NULL_SHA           = 0x06,
    TLS_ECDHE_PSK_WITH_NULL_SHA256          = 0x3a,
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256   = 0x37,

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

    /* wolfSSL extension - eSTREAM */
    TLS_RSA_WITH_HC_128_MD5       = 0xFB,
    TLS_RSA_WITH_HC_128_SHA       = 0xFC,
    TLS_RSA_WITH_RABBIT_SHA       = 0xFD,

    /* wolfSSL extension - Blake2b 256 */
    TLS_RSA_WITH_AES_128_CBC_B2B256   = 0xF8,
    TLS_RSA_WITH_AES_256_CBC_B2B256   = 0xF9,
    TLS_RSA_WITH_HC_128_B2B256        = 0xFA,   /* eSTREAM too */

    /* wolfSSL extension - NTRU */
    TLS_NTRU_RSA_WITH_RC4_128_SHA      = 0xe5,
    TLS_NTRU_RSA_WITH_3DES_EDE_CBC_SHA = 0xe6,
    TLS_NTRU_RSA_WITH_AES_128_CBC_SHA  = 0xe7,  /* clashes w/official SHA-256 */
    TLS_NTRU_RSA_WITH_AES_256_CBC_SHA  = 0xe8,

    /* wolfSSL extension - NTRU , Quantum-safe Handshake
       first byte is 0xD0 (QSH_BYTE) */
    TLS_QSH      = 0x01,

    /* SHA256 */
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x6b,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x67,
    TLS_RSA_WITH_AES_256_CBC_SHA256     = 0x3d,
    TLS_RSA_WITH_AES_128_CBC_SHA256     = 0x3c,
    TLS_RSA_WITH_NULL_SHA256            = 0x3b,
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 = 0xb2,
    TLS_DHE_PSK_WITH_NULL_SHA256        = 0xb4,

    /* SHA384 */
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 = 0xb3,
    TLS_DHE_PSK_WITH_NULL_SHA384        = 0xb5,

    /* AES-GCM */
    TLS_RSA_WITH_AES_128_GCM_SHA256          = 0x9c,
    TLS_RSA_WITH_AES_256_GCM_SHA384          = 0x9d,
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256      = 0x9e,
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384      = 0x9f,
    TLS_PSK_WITH_AES_128_GCM_SHA256          = 0xa8,
    TLS_PSK_WITH_AES_256_GCM_SHA384          = 0xa9,
    TLS_DHE_PSK_WITH_AES_128_GCM_SHA256      = 0xaa,
    TLS_DHE_PSK_WITH_AES_256_GCM_SHA384      = 0xab,

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
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM   = 0xac,
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = 0xae,
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 = 0xaf,
    TLS_PSK_WITH_AES_128_CCM           = 0xa4,
    TLS_PSK_WITH_AES_256_CCM           = 0xa5,
    TLS_PSK_WITH_AES_128_CCM_8         = 0xa8,
    TLS_PSK_WITH_AES_256_CCM_8         = 0xa9,
    TLS_DHE_PSK_WITH_AES_128_CCM       = 0xa6,
    TLS_DHE_PSK_WITH_AES_256_CCM       = 0xa7,

    /* Camellia */
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA        = 0x41,
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA        = 0x84,
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256     = 0xba,
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256     = 0xc0,
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA    = 0x45,
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA    = 0x88,
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xbe,
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0xc4,

    /* chacha20-poly1305 suites first byte is 0xCC (CHACHA_BYTE) */
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   = 0xa8,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xa9,
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256     = 0xaa,
    TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256   = 0xac,
    TLS_PSK_WITH_CHACHA20_POLY1305_SHA256         = 0xab,
    TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256     = 0xad,

    /* chacha20-poly1305 earlier version of nonce and padding (CHACHA_BYTE) */
    TLS_ECDHE_RSA_WITH_CHACHA20_OLD_POLY1305_SHA256   = 0x13,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_OLD_POLY1305_SHA256 = 0x14,
    TLS_DHE_RSA_WITH_CHACHA20_OLD_POLY1305_SHA256     = 0x15,

    /* Renegotiation Indication Extension Special Suite */
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV        = 0xff
};


#ifndef WOLFSSL_SESSION_TIMEOUT
    #define WOLFSSL_SESSION_TIMEOUT 500
    /* default session resumption cache timeout in seconds */
#endif


enum Misc {
    ECC_BYTE    = 0xC0,            /* ECC first cipher suite byte */
    QSH_BYTE    = 0xD0,            /* Quantum-safe Handshake cipher suite */
    CHACHA_BYTE = 0xCC,            /* ChaCha first cipher suite */

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
    OLD_HELLO_ID    = 0x01,     /* SSLv2 Client Hello Indicator */
    INVALID_BYTE    = 0xff,     /* Used to initialize cipher specs values */
    NO_COMPRESSION  =  0,
    ZLIB_COMPRESSION = 221,     /* wolfSSL zlib compression */
    HELLO_EXT_SIG_ALGO = 13,    /* ID for the sig_algo hello extension */
    HELLO_EXT_EXTMS = 0x0017,   /* ID for the extended master secret ext */
    SECRET_LEN      = 48,       /* pre RSA and all master */
#if defined(WOLFSSL_MYSQL_COMPATIBLE)
    ENCRYPT_LEN     = 1024,     /* allow larger static buffer with mysql */
#else
    ENCRYPT_LEN     = 512,      /* allow 4096 bit static buffer */
#endif
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
    MAX_DH_SZ       = 1036,     /* 4096 p, pub, g + 2 byte size for each */
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
    VERIFY_HEADER  =  2,       /* always use 2 bytes      */
    EXT_ID_SZ      =  2,       /* always use 2 bytes      */
    MAX_DH_SIZE    = 513,      /* 4096 bit plus possible leading 0 */
    SESSION_HINT_SZ = 4,       /* session timeout hint */

    RAN_LEN      = 32,         /* random length           */
    SEED_LEN     = RAN_LEN * 2, /* tls prf seed length    */
    ID_LEN       = 32,         /* session id length       */
    COOKIE_SECRET_SZ = 14,     /* dtls cookie secret size */
    MAX_COOKIE_LEN = 32,       /* max dtls cookie size    */
    COOKIE_SZ    = 20,         /* use a 20 byte cookie    */
    SUITE_LEN    =  2,         /* cipher suite sz length  */
    ENUM_LEN     =  1,         /* always a byte           */
    OPAQUE8_LEN  =  1,         /* 1 byte                  */
    OPAQUE16_LEN =  2,         /* 2 bytes                 */
    OPAQUE24_LEN =  3,         /* 3 bytes                 */
    OPAQUE32_LEN =  4,         /* 4 bytes                 */
    OPAQUE64_LEN =  8,         /* 8 bytes                 */
    COMP_LEN     =  1,         /* compression length      */
    CURVE_LEN    =  2,         /* ecc named curve length  */
    SERVER_ID_LEN = 20,        /* server session id length  */

    HANDSHAKE_HEADER_SZ   = 4,  /* type + length(3)        */
    RECORD_HEADER_SZ      = 5,  /* type + version + len(2) */
    CERT_HEADER_SZ        = 3,  /* always 3 bytes          */
    REQ_HEADER_SZ         = 2,  /* cert request header sz  */
    HINT_LEN_SZ           = 2,  /* length of hint size field */
    TRUNCATED_HMAC_SZ     = 10, /* length of hmac w/ truncated hmac extension */
    HELLO_EXT_SZ          = 4,  /* base length of a hello extension */
    HELLO_EXT_TYPE_SZ     = 2,  /* length of a hello extension type */
    HELLO_EXT_SZ_SZ       = 2,  /* length of a hello extension size */
    HELLO_EXT_SIGALGO_SZ  = 2,  /* length of number of items in sigalgo list */
    HELLO_EXT_SIGALGO_MAX = 32, /* number of items in the signature algo list */

    DTLS_HANDSHAKE_HEADER_SZ = 12, /* normal + seq(2) + offset(3) + length(3) */
    DTLS_RECORD_HEADER_SZ    = 13, /* normal + epoch(2) + seq_num(6) */
    DTLS_HANDSHAKE_EXTRA     = 8,  /* diff from normal */
    DTLS_RECORD_EXTRA        = 8,  /* diff from normal */
    DTLS_HANDSHAKE_SEQ_SZ    = 2,  /* handshake header sequence number */
    DTLS_HANDSHAKE_FRAG_SZ   = 3,  /* fragment offset and length are 24 bit */
    DTLS_POOL_SZ             = 5,  /* buffers to hold in the retry pool */
    DTLS_EXPORT_PRO          = 165,/* wolfSSL protocol for serialized session */
    DTLS_EXPORT_VERSION      = 1,  /* wolfSSL version for serialized session */
    DTLS_EXPORT_OPT_SZ       = 57, /* amount of bytes used from Options */
    DTLS_EXPORT_KEY_SZ       = 331,/* max amount of bytes used from Keys */
    DTLS_EXPORT_MIN_KEY_SZ   = 75, /* min amount of bytes used from Keys */
    DTLS_EXPORT_SPC_SZ       = 16, /* amount of bytes used from CipherSpecs */
    DTLS_EXPORT_LEN          = 2,  /* 2 bytes for length and protocol */
    DTLS_EXPORT_IP           = 46, /* max ip size IPv4 mapped IPv6 */
    MAX_EXPORT_BUFFER        = 500, /* max size of buffer for exporting */
    FINISHED_LABEL_SZ   = 15,  /* TLS finished label size */
    TLS_FINISHED_SZ     = 12,  /* TLS has a shorter size  */
    EXT_MASTER_LABEL_SZ = 22,  /* TLS extended master secret label sz */
    MASTER_LABEL_SZ     = 13,  /* TLS master secret label sz */
    KEY_LABEL_SZ        = 13,  /* TLS key block expansion sz */
    MAX_PRF_HALF        = 256, /* Maximum half secret len */
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

    AEAD_SEQ_OFFSET     = 4,   /* Auth Data: Sequence number */
    AEAD_TYPE_OFFSET    = 8,   /* Auth Data: Type            */
    AEAD_VMAJ_OFFSET    = 9,   /* Auth Data: Major Version   */
    AEAD_VMIN_OFFSET    = 10,  /* Auth Data: Minor Version   */
    AEAD_LEN_OFFSET     = 11,  /* Auth Data: Length          */
    AEAD_AUTH_DATA_SZ   = 13,  /* Size of the data to authenticate */
    AESGCM_IMP_IV_SZ    = 4,   /* Size of GCM/CCM AEAD implicit IV */
    AESGCM_EXP_IV_SZ    = 8,   /* Size of GCM/CCM AEAD explicit IV */
    AESGCM_NONCE_SZ     = AESGCM_EXP_IV_SZ + AESGCM_IMP_IV_SZ,

    CHACHA20_IMP_IV_SZ  = 12,  /* Size of ChaCha20 AEAD implicit IV */
    CHACHA20_NONCE_SZ   = 12,  /* Size of ChacCha20 nonce           */
    CHACHA20_OLD_OFFSET = 8,   /* Offset for seq # in old poly1305  */

    /* For any new implicit/explicit IV size adjust AEAD_MAX_***_SZ */

    AES_GCM_AUTH_SZ     = 16, /* AES-GCM Auth Tag length    */
    AES_CCM_16_AUTH_SZ  = 16, /* AES-CCM-16 Auth Tag length */
    AES_CCM_8_AUTH_SZ   = 8,  /* AES-CCM-8 Auth Tag Length  */

    CAMELLIA_128_KEY_SIZE = 16, /* for 128 bit */
    CAMELLIA_192_KEY_SIZE = 24, /* for 192 bit */
    CAMELLIA_256_KEY_SIZE = 32, /* for 256 bit */
    CAMELLIA_IV_SIZE      = 16, /* always block size */

    CHACHA20_256_KEY_SIZE = 32,  /* for 256 bit             */
    CHACHA20_128_KEY_SIZE = 16,  /* for 128 bit             */
    CHACHA20_IV_SIZE      = 12,  /* 96 bits for iv          */

    POLY1305_AUTH_SZ    = 16,  /* 128 bits                */

    HC_128_KEY_SIZE     = 16,  /* 128 bits                */
    HC_128_IV_SIZE      = 16,  /* also 128 bits           */

    RABBIT_KEY_SIZE     = 16,  /* 128 bits                */
    RABBIT_IV_SIZE      =  8,  /* 64 bits for iv          */

    EVP_SALT_SIZE       =  8,  /* evp salt size 64 bits   */

    ECDHE_SIZE          = 32,  /* ECHDE server size defaults to 256 bit */
    MAX_EXPORT_ECC_SZ   = 256, /* Export ANS X9.62 max future size */

#ifdef HAVE_QSH
    /* qsh handshake sends 600+ size keys over hello extensions */
    MAX_HELLO_SZ       = 2048,  /* max client or server hello */
#else
    MAX_HELLO_SZ       = 128,  /* max client or server hello */
#endif
    MAX_CERT_VERIFY_SZ = 1024, /* max   */
    CLIENT_HELLO_FIRST =  35,  /* Protocol + RAN_LEN + sizeof(id_len) */
    MAX_SUITE_NAME     =  48,  /* maximum length of cipher suite string */

    DTLS_TIMEOUT_INIT       =  1, /* default timeout init for DTLS receive  */
    DTLS_TIMEOUT_MAX        = 64, /* default max timeout for DTLS receive */
    DTLS_TIMEOUT_MULTIPLIER =  2, /* default timeout multiplier for DTLS recv */

    MAX_PSK_ID_LEN     = 128,  /* max psk identity/hint supported */
    MAX_PSK_KEY_LEN    =  64,  /* max psk key supported */

    MAX_WOLFSSL_FILE_SIZE = 1024 * 1024 * 4,  /* 4 mb file size alloc limit */

#if defined(FORTRESS) || defined (HAVE_STUNNEL)
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

    NO_COPY            =   0,  /* should we copy static buffer for write */
    COPY               =   1   /* should we copy static buffer for write */
};


/* Set max implicit IV size for AEAD cipher suites */
#ifdef HAVE_CHACHA
    #define AEAD_MAX_IMP_SZ 12
#else
    #define AEAD_MAX_IMP_SZ 4
#endif

/* Set max explicit IV size for AEAD cipher suites */
#define AEAD_MAX_EXP_SZ 8


#ifndef WOLFSSL_MAX_SUITE_SZ
    #define WOLFSSL_MAX_SUITE_SZ 300
    /* 150 suites for now! */
#endif

/* set minimum ECC key size allowed */
#ifndef WOLFSSL_MIN_ECC_BITS
    #ifdef WOLFSSL_MAX_STRENGTH
        #define WOLFSSL_MIN_ECC_BITS  256
    #else
        #define WOLFSSL_MIN_ECC_BITS 224
    #endif
#endif /* WOLFSSL_MIN_ECC_BITS */
#if (WOLFSSL_MIN_ECC_BITS % 8)
    /* Some ECC keys are not divisable by 8 such as prime239v1 or sect131r1.
       In these cases round down to the nearest value divisable by 8. The
       restriction of being divisable by 8 is in place to match wc_ecc_size
       function from wolfSSL.
     */
    #error ECC minimum bit size must be a multiple of 8
#endif
#define MIN_ECCKEY_SZ (WOLFSSL_MIN_ECC_BITS / 8)

/* set minimum RSA key size allowed */
#ifndef WOLFSSL_MIN_RSA_BITS
    #ifdef WOLFSSL_MAX_STRENGTH
        #define WOLFSSL_MIN_RSA_BITS 2048
    #else
        #define WOLFSSL_MIN_RSA_BITS 1024
    #endif
#endif /* WOLFSSL_MIN_RSA_BITS */
#if (WOLFSSL_MIN_RSA_BITS % 8)
    /* This is to account for the example case of a min size of 2050 bits but
       still allows 2049 bit key. So we need the measurment to be in bytes. */
    #error RSA minimum bit size must be a multiple of 8
#endif
#define MIN_RSAKEY_SZ (WOLFSSL_MIN_RSA_BITS / 8)

/* set minimum DH key size allowed */
#ifndef WOLFSSL_MIN_DHKEY_BITS
    #ifdef WOLFSSL_MAX_STRENGTH
        #define WOLFSSL_MIN_DHKEY_BITS 2048
    #else
        #define WOLFSSL_MIN_DHKEY_BITS 1024
    #endif
#endif
#if (WOLFSSL_MIN_DHKEY_BITS % 8)
    #error DH minimum bit size must be multiple of 8
#endif
#if (WOLFSSL_MIN_DHKEY_BITS > 16000)
    #error DH minimum bit size must not be greater than 16000
#endif
#define MIN_DHKEY_SZ (WOLFSSL_MIN_DHKEY_BITS / 8)


#ifdef SESSION_INDEX
/* Shift values for making a session index */
#define SESSIDX_ROW_SHIFT 4
#define SESSIDX_IDX_MASK  0x0F
#endif


/* max cert chain peer depth */
#ifndef MAX_CHAIN_DEPTH
    #define MAX_CHAIN_DEPTH 9
#endif

/* max size of a certificate message payload */
/* assumes MAX_CHAIN_DEPTH number of certificates at 2kb per certificate */
#ifndef MAX_CERTIFICATE_SZ
    #define MAX_CERTIFICATE_SZ \
                CERT_HEADER_SZ + \
                (MAX_X509_SIZE + CERT_HEADER_SZ) * MAX_CHAIN_DEPTH
#endif

/* max size of a handshake message, currently set to the certificate */
#ifndef MAX_HANDSHAKE_SZ
    #define MAX_HANDSHAKE_SZ MAX_CERTIFICATE_SZ
#endif

#ifndef SESSION_TICKET_LEN
    #define SESSION_TICKET_LEN 256
#endif

#ifndef SESSION_TICKET_HINT_DEFAULT
    #define SESSION_TICKET_HINT_DEFAULT 300
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
    #define WOLFSSL_PACK __attribute__ ((packed))
#else
    #define WOLFSSL_PACK
#endif

/* SSL Version */
typedef struct ProtocolVersion {
    byte major;
    byte minor;
} WOLFSSL_PACK ProtocolVersion;


WOLFSSL_LOCAL ProtocolVersion MakeSSLv3(void);
WOLFSSL_LOCAL ProtocolVersion MakeTLSv1(void);
WOLFSSL_LOCAL ProtocolVersion MakeTLSv1_1(void);
WOLFSSL_LOCAL ProtocolVersion MakeTLSv1_2(void);

#ifdef WOLFSSL_DTLS
    WOLFSSL_LOCAL ProtocolVersion MakeDTLSv1(void);
    WOLFSSL_LOCAL ProtocolVersion MakeDTLSv1_2(void);

    #ifdef WOLFSSL_SESSION_EXPORT
    WOLFSSL_LOCAL int wolfSSL_dtls_import_internal(WOLFSSL* ssl, byte* buf,
                                                                     word32 sz);
    WOLFSSL_LOCAL int wolfSSL_dtls_export_internal(WOLFSSL* ssl, byte* buf,
                                                                     word32 sz);
    WOLFSSL_LOCAL int wolfSSL_send_session(WOLFSSL* ssl);
    #endif
#endif


enum BIO_TYPE {
    BIO_BUFFER = 1,
    BIO_SOCKET = 2,
    BIO_SSL    = 3,
    BIO_MEMORY = 4
};


/* wolfSSL BIO_METHOD type */
struct WOLFSSL_BIO_METHOD {
    byte type;               /* method type */
};


/* wolfSSL BIO type */
struct WOLFSSL_BIO {
    byte        type;          /* method type */
    byte        close;         /* close flag */
    byte        eof;           /* eof flag */
    WOLFSSL*     ssl;           /* possible associated ssl */
    byte*       mem;           /* memory buffer */
    int         memLen;        /* memory buffer length */
    int         fd;            /* possible file descriptor */
    WOLFSSL_BIO* prev;          /* previous in chain */
    WOLFSSL_BIO* next;          /* next in chain */
};


/* wolfSSL method type */
struct WOLFSSL_METHOD {
    ProtocolVersion version;
    byte            side;         /* connection side, server or client */
    byte            downgrade;    /* whether to downgrade version, default no */
};


/* defaults to client */
WOLFSSL_LOCAL void InitSSL_Method(WOLFSSL_METHOD*, ProtocolVersion);

/* for sniffer */
WOLFSSL_LOCAL int DoFinished(WOLFSSL* ssl, const byte* input, word32* inOutIdx,
                            word32 size, word32 totalSz, int sniff);
WOLFSSL_LOCAL int DoApplicationData(WOLFSSL* ssl, byte* input, word32* inOutIdx);


/* wolfSSL buffer type */
typedef struct buffer {
    byte*  buffer;
    word32 length;
} buffer;

#ifndef NO_CERTS
    /* wolfSSL DER buffer */
    typedef struct DerBuffer {
        byte*  buffer;
        void* heap;
        word32 length;
        int type; /* enum CertType */
        int dynType; /* DYNAMIC_TYPE_* */
    } DerBuffer;
#endif /* !NO_CERTS */


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
#ifdef WOLFSSL_SNIFFER
    #define MTU_EXTRA MAX_MTU * 3
#else
    #define MTU_EXTRA 0
#endif


/* embedded callbacks require large static buffers, make sure on */
#ifdef WOLFSSL_CALLBACKS
    #undef  LARGE_STATIC_BUFFERS
    #define LARGE_STATIC_BUFFERS
#endif


/* give user option to use 16K static buffers */
#if defined(LARGE_STATIC_BUFFERS)
    #define RECORD_SIZE MAX_RECORD_SIZE
#else
    #ifdef WOLFSSL_DTLS
        #define RECORD_SIZE MAX_MTU
    #else
        #define RECORD_SIZE 128
    #endif
#endif


/* user option to turn off 16K output option */
/* if using small static buffers (default) and SSL_write tries to write data
   larger than the record we have, dynamically get it, unless user says only
   write in static buffer chunks  */
#ifndef STATIC_CHUNKS_ONLY
    #define OUTPUT_RECORD_SIZE MAX_RECORD_SIZE
#else
    #define OUTPUT_RECORD_SIZE RECORD_SIZE
#endif

/* wolfSSL input buffer

   RFC 2246:

   length
       The length (in bytes) of the following TLSPlaintext.fragment.
       The length should not exceed 2^14.
*/
#if defined(LARGE_STATIC_BUFFERS)
    #define STATIC_BUFFER_LEN RECORD_HEADER_SZ + RECORD_SIZE + COMP_EXTRA + \
             MTU_EXTRA + MAX_MSG_EXTRA
#else
    /* don't fragment memory from the record header */
    #define STATIC_BUFFER_LEN RECORD_HEADER_SZ
#endif

typedef struct {
    ALIGN16 byte staticBuffer[STATIC_BUFFER_LEN];
    byte*  buffer;       /* place holder for static or dynamic buffer */
    word32 length;       /* total buffer length used */
    word32 idx;          /* idx to part of length already consumed */
    word32 bufferSize;   /* current buffer size */
    byte   dynamicFlag;  /* dynamic memory currently in use */
    byte   offset;       /* alignment offset attempt */
} bufferStatic;

/* Cipher Suites holder */
typedef struct Suites {
    word16 suiteSz;                 /* suite length in bytes        */
    word16 hashSigAlgoSz;           /* SigAlgo extension length in bytes */
    byte   suites[WOLFSSL_MAX_SUITE_SZ];
    byte   hashSigAlgo[HELLO_EXT_SIGALGO_MAX]; /* sig/algo to offer */
    byte   setSuites;               /* user set suites from default */
    byte   hashAlgo;                /* selected hash algorithm */
    byte   sigAlgo;                 /* selected sig algorithm */
} Suites;


WOLFSSL_LOCAL
void InitSuites(Suites*, ProtocolVersion, word16, word16, word16, word16,
                word16, word16, word16, int);
WOLFSSL_LOCAL
int  SetCipherList(Suites*, const char* list);

#ifndef PSK_TYPES_DEFINED
    typedef unsigned int (*wc_psk_client_callback)(WOLFSSL*, const char*, char*,
                          unsigned int, unsigned char*, unsigned int);
    typedef unsigned int (*wc_psk_server_callback)(WOLFSSL*, const char*,
                          unsigned char*, unsigned int);
#endif /* PSK_TYPES_DEFINED */
#ifdef WOLFSSL_DTLS
    typedef int (*wc_dtls_export)(WOLFSSL* ssl,
                   unsigned char* exportBuffer, unsigned int sz, void* userCtx);
#endif

#ifdef HAVE_NETX
    WOLFSSL_LOCAL int NetX_Receive(WOLFSSL *ssl, char *buf, int sz, void *ctx);
    WOLFSSL_LOCAL int NetX_Send(WOLFSSL *ssl, char *buf, int sz, void *ctx);
#endif /* HAVE_NETX */


/* wolfSSL Cipher type just points back to SSL */
struct WOLFSSL_CIPHER {
    WOLFSSL* ssl;
};


typedef struct OcspEntry OcspEntry;

#ifdef NO_SHA
    #define OCSP_DIGEST_SIZE SHA256_DIGEST_SIZE
#else
    #define OCSP_DIGEST_SIZE SHA_DIGEST_SIZE
#endif

#ifdef NO_ASN
    /* no_asn won't have */
    typedef struct CertStatus CertStatus;
#endif

struct OcspEntry {
    OcspEntry*  next;                            /* next entry             */
    byte        issuerHash[OCSP_DIGEST_SIZE];    /* issuer hash            */
    byte        issuerKeyHash[OCSP_DIGEST_SIZE]; /* issuer public key hash */
    CertStatus* status;                          /* OCSP response list     */
    int         totalStatus;                     /* number on list         */
};


#ifndef HAVE_OCSP
    typedef struct WOLFSSL_OCSP WOLFSSL_OCSP;
#endif

/* wolfSSL OCSP controller */
struct WOLFSSL_OCSP {
    WOLFSSL_CERT_MANAGER* cm;            /* pointer back to cert manager */
    OcspEntry*            ocspList;      /* OCSP response list */
    wolfSSL_Mutex         ocspLock;      /* OCSP list lock */
};

#ifndef MAX_DATE_SIZE
#define MAX_DATE_SIZE 32
#endif

typedef struct CRL_Entry CRL_Entry;

#ifdef NO_SHA
    #define CRL_DIGEST_SIZE SHA256_DIGEST_SIZE
#else
    #define CRL_DIGEST_SIZE SHA_DIGEST_SIZE
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
    typedef struct WOLFSSL_CRL WOLFSSL_CRL;
#endif

#if defined(HAVE_CRL) && defined(NO_FILESYSTEM)
    #undef HAVE_CRL_MONITOR
#endif

/* wolfSSL CRL controller */
struct WOLFSSL_CRL {
    WOLFSSL_CERT_MANAGER* cm;            /* pointer back to cert manager */
    CRL_Entry*            crlList;       /* our CRL list */
    wolfSSL_Mutex         crlLock;       /* CRL list lock */
    CRL_Monitor           monitors[2];   /* PEM and DER possible */
#ifdef HAVE_CRL_MONITOR
    pthread_cond_t        cond;          /* condition to signal setup */
    pthread_t             tid;           /* monitoring thread */
    int                   mfd;           /* monitor fd, -1 if no init yet */
    int                   setup;         /* thread is setup predicate */
#endif
    void*                 heap;          /* heap hint for dynamic memory */
};


#ifdef NO_ASN
    typedef struct Signer Signer;
#ifdef WOLFSSL_TRUST_PEER_CERT
    typedef struct TrustedPeerCert TrustedPeerCert;
#endif
#endif


#ifndef CA_TABLE_SIZE
    #define CA_TABLE_SIZE 11
#endif
#ifdef WOLFSSL_TRUST_PEER_CERT
    #define TP_TABLE_SIZE 11
#endif

/* wolfSSL Certificate Manager */
struct WOLFSSL_CERT_MANAGER {
    Signer*         caTable[CA_TABLE_SIZE]; /* the CA signer table */
    void*           heap;                /* heap helper */
#ifdef WOLFSSL_TRUST_PEER_CERT
    TrustedPeerCert* tpTable[TP_TABLE_SIZE]; /* table of trusted peer certs */
    wolfSSL_Mutex   tpLock;                  /* trusted peer list lock */
#endif
    WOLFSSL_CRL*    crl;                 /* CRL checker */
    WOLFSSL_OCSP*   ocsp;                /* OCSP checker */
#if !defined(NO_WOLFSSL_SERVER) && (defined(HAVE_CERTIFICATE_STATUS_REQUEST) \
                               ||  defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2))
    WOLFSSL_OCSP*   ocsp_stapling;       /* OCSP checker for OCSP stapling */
#endif
    char*           ocspOverrideURL;     /* use this responder */
    void*           ocspIOCtx;           /* I/O callback CTX */
    CallbackCACache caCacheCallback;     /* CA cache addition callback */
    CbMissingCRL    cbMissingCRL;        /* notify through cb of missing crl */
    CbOCSPIO        ocspIOCb;            /* I/O callback for OCSP lookup */
    CbOCSPRespFree  ocspRespFreeCb;      /* Frees OCSP Response from IO Cb */
    wolfSSL_Mutex   caLock;              /* CA list lock */
    byte            crlEnabled;          /* is CRL on ? */
    byte            crlCheckAll;         /* always leaf, but all ? */
    byte            ocspEnabled;         /* is OCSP on ? */
    byte            ocspCheckAll;        /* always leaf, but all ? */
    byte            ocspSendNonce;       /* send the OCSP nonce ? */
    byte            ocspUseOverrideURL;  /* ignore cert's responder, override */
    byte            ocspStaplingEnabled; /* is OCSP Stapling on ? */

#ifndef NO_RSA
    short           minRsaKeySz;         /* minimum allowed RSA key size */
#endif
#ifdef HAVE_ECC
    short           minEccKeySz;         /* minimum allowed ECC key size */
#endif
};

WOLFSSL_LOCAL int CM_SaveCertCache(WOLFSSL_CERT_MANAGER*, const char*);
WOLFSSL_LOCAL int CM_RestoreCertCache(WOLFSSL_CERT_MANAGER*, const char*);
WOLFSSL_LOCAL int CM_MemSaveCertCache(WOLFSSL_CERT_MANAGER*, void*, int, int*);
WOLFSSL_LOCAL int CM_MemRestoreCertCache(WOLFSSL_CERT_MANAGER*, const void*, int);
WOLFSSL_LOCAL int CM_GetCertCacheMemSize(WOLFSSL_CERT_MANAGER*);

/* wolfSSL Sock Addr */
struct WOLFSSL_SOCKADDR {
    unsigned int sz; /* sockaddr size */
    void*        sa; /* pointer to the sockaddr_in or sockaddr_in6 */
};

typedef struct WOLFSSL_DTLS_CTX {
    WOLFSSL_SOCKADDR peer;
    int fd;
} WOLFSSL_DTLS_CTX;


#ifdef WOLFSSL_DTLS

    #ifdef WORD64_AVAILABLE
        typedef word64 DtlsSeq;
    #else
        typedef word32 DtlsSeq;
    #endif
    #define DTLS_SEQ_BITS (sizeof(DtlsSeq) * CHAR_BIT)

    typedef struct DtlsState {
        DtlsSeq window;     /* Sliding window for current epoch    */
        word16 nextEpoch;   /* Expected epoch in next record       */
        word32 nextSeq;     /* Expected sequence in next record    */

        word16 curEpoch;    /* Received epoch in current record    */
        word32 curSeq;      /* Received sequence in current record */

        DtlsSeq prevWindow; /* Sliding window for old epoch        */
        word32 prevSeq;     /* Next sequence in allowed old epoch  */
    } DtlsState;

#endif /* WOLFSSL_DTLS */


#define MAX_WRITE_IV_SZ 16 /* max size of client/server write_IV */

/* keys and secrets
 * keep as a constant size (no additional ifdefs) for session export */
typedef struct Keys {
    byte client_write_MAC_secret[MAX_DIGEST_SIZE];   /* max sizes */
    byte server_write_MAC_secret[MAX_DIGEST_SIZE];
    byte client_write_key[AES_256_KEY_SIZE];         /* max sizes */
    byte server_write_key[AES_256_KEY_SIZE];
    byte client_write_IV[MAX_WRITE_IV_SZ];               /* max sizes */
    byte server_write_IV[MAX_WRITE_IV_SZ];
#if defined(HAVE_AEAD) || defined(WOLFSSL_SESSION_EXPORT)
    byte aead_exp_IV[AEAD_MAX_EXP_SZ];
    byte aead_enc_imp_IV[AEAD_MAX_IMP_SZ];
    byte aead_dec_imp_IV[AEAD_MAX_IMP_SZ];
#endif

    word32 peer_sequence_number;
    word32 sequence_number;

#ifdef WOLFSSL_DTLS
    DtlsState dtls_state;                       /* Peer's state */
    word16 dtls_peer_handshake_number;
    word16 dtls_expected_peer_handshake_number;

    word32 dtls_sequence_number;                /* Current tx sequence */
    word32 dtls_prev_sequence_number;           /* Previous epoch's seq number*/
    word16 dtls_epoch;                          /* Current tx epoch    */
    word16 dtls_handshake_number;               /* Current tx handshake seq */
#endif

    word32 encryptSz;             /* last size of encrypted data   */
    word32 padSz;                 /* how much to advance after decrypt part */
    byte   encryptionOn;          /* true after change cipher spec */
    byte   decryptedCur;          /* only decrypt current record once */
} Keys;



/** TLS Extensions - RFC 6066 */
#ifdef HAVE_TLS_EXTENSIONS

typedef enum {
    TLSX_SERVER_NAME                = 0x0000, /* a.k.a. SNI  */
    TLSX_MAX_FRAGMENT_LENGTH        = 0x0001,
    TLSX_TRUNCATED_HMAC             = 0x0004,
    TLSX_STATUS_REQUEST             = 0x0005, /* a.k.a. OCSP stapling   */
    TLSX_SUPPORTED_GROUPS           = 0x000a, /* a.k.a. Supported Curves */
    TLSX_APPLICATION_LAYER_PROTOCOL = 0x0010, /* a.k.a. ALPN */
    TLSX_STATUS_REQUEST_V2          = 0x0011, /* a.k.a. OCSP stapling v2 */
    TLSX_QUANTUM_SAFE_HYBRID        = 0x0018, /* a.k.a. QSH  */
    TLSX_SESSION_TICKET             = 0x0023,
    TLSX_RENEGOTIATION_INFO         = 0xff01
} TLSX_Type;

typedef struct TLSX {
    TLSX_Type    type; /* Extension Type  */
    void*        data; /* Extension Data  */
    byte         resp; /* IsResponse Flag */
    struct TLSX* next; /* List Behavior   */
} TLSX;

WOLFSSL_LOCAL TLSX*  TLSX_Find(TLSX* list, TLSX_Type type);
WOLFSSL_LOCAL void   TLSX_FreeAll(TLSX* list, void* heap);
WOLFSSL_LOCAL int    TLSX_SupportExtensions(WOLFSSL* ssl);
WOLFSSL_LOCAL int    TLSX_PopulateExtensions(WOLFSSL* ssl, byte isRequest);

#ifndef NO_WOLFSSL_CLIENT
WOLFSSL_LOCAL word16 TLSX_GetRequestSize(WOLFSSL* ssl);
WOLFSSL_LOCAL word16 TLSX_WriteRequest(WOLFSSL* ssl, byte* output);
#endif

#ifndef NO_WOLFSSL_SERVER
WOLFSSL_LOCAL word16 TLSX_GetResponseSize(WOLFSSL* ssl);
WOLFSSL_LOCAL word16 TLSX_WriteResponse(WOLFSSL* ssl, byte* output);
#endif

WOLFSSL_LOCAL int    TLSX_Parse(WOLFSSL* ssl, byte* input, word16 length,
                                                byte isRequest, Suites *suites);

#elif defined(HAVE_SNI)                           \
   || defined(HAVE_MAX_FRAGMENT)                  \
   || defined(HAVE_TRUNCATED_HMAC)                \
   || defined(HAVE_CERTIFICATE_STATUS_REQUEST)    \
   || defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2) \
   || defined(HAVE_SUPPORTED_CURVES)              \
   || defined(HAVE_ALPN)                          \
   || defined(HAVE_QSH)                           \
   || defined(HAVE_SESSION_TICKET)                \
   || defined(HAVE_SECURE_RENEGOTIATION)

#error Using TLS extensions requires HAVE_TLS_EXTENSIONS to be defined.

#endif /* HAVE_TLS_EXTENSIONS */

/** Server Name Indication - RFC 6066 (session 3) */
#ifdef HAVE_SNI

typedef struct SNI {
    byte                       type;    /* SNI Type          */
    union { char* host_name; } data;    /* SNI Data          */
    struct SNI*                next;    /* List Behavior     */
#ifndef NO_WOLFSSL_SERVER
    byte                       options; /* Behavior options */
    byte                       status;  /* Matching result   */
#endif
} SNI;

WOLFSSL_LOCAL int TLSX_UseSNI(TLSX** extensions, byte type, const void* data,
                                                       word16 size, void* heap);

#ifndef NO_WOLFSSL_SERVER
WOLFSSL_LOCAL void   TLSX_SNI_SetOptions(TLSX* extensions, byte type,
                                                                  byte options);
WOLFSSL_LOCAL byte   TLSX_SNI_Status(TLSX* extensions, byte type);
WOLFSSL_LOCAL word16 TLSX_SNI_GetRequest(TLSX* extensions, byte type,
                                                                   void** data);
WOLFSSL_LOCAL int    TLSX_SNI_GetFromBuffer(const byte* buffer, word32 bufferSz,
                                         byte type, byte* sni, word32* inOutSz);
#endif

#endif /* HAVE_SNI */

/* Application-Layer Protocol Negotiation - RFC 7301 */
#ifdef HAVE_ALPN
typedef struct ALPN {
    char*        protocol_name; /* ALPN protocol name */
    struct ALPN* next;          /* List Behavior      */
    byte         options;       /* Behavior options */
    byte         negotiated;    /* ALPN protocol negotiated or not */
} ALPN;

WOLFSSL_LOCAL int TLSX_ALPN_GetRequest(TLSX* extensions,
                                       void** data, word16 *dataSz);

WOLFSSL_LOCAL int TLSX_UseALPN(TLSX** extensions, const void* data,
                               word16 size, byte options, void* heap);

WOLFSSL_LOCAL int TLSX_ALPN_SetOptions(TLSX** extensions, const byte option);

#endif /* HAVE_ALPN */

/** Maximum Fragment Length Negotiation - RFC 6066 (session 4) */
#ifdef HAVE_MAX_FRAGMENT

WOLFSSL_LOCAL int TLSX_UseMaxFragment(TLSX** extensions, byte mfl, void* heap);

#endif /* HAVE_MAX_FRAGMENT */

/** Truncated HMAC - RFC 6066 (session 7) */
#ifdef HAVE_TRUNCATED_HMAC

WOLFSSL_LOCAL int TLSX_UseTruncatedHMAC(TLSX** extensions, void* heap);

#endif /* HAVE_TRUNCATED_HMAC */

/** Certificate Status Request - RFC 6066 (session 8) */
#ifdef HAVE_CERTIFICATE_STATUS_REQUEST

typedef struct {
    byte status_type;
    byte options;
    union {
        OcspRequest ocsp;
    } request;
} CertificateStatusRequest;

WOLFSSL_LOCAL int   TLSX_UseCertificateStatusRequest(TLSX** extensions,
                                    byte status_type, byte options, void* heap);
WOLFSSL_LOCAL int   TLSX_CSR_InitRequest(TLSX* extensions, DecodedCert* cert,
                                                                    void* heap);
WOLFSSL_LOCAL void* TLSX_CSR_GetRequest(TLSX* extensions);
WOLFSSL_LOCAL int   TLSX_CSR_ForceRequest(WOLFSSL* ssl);

#endif

/** Certificate Status Request v2 - RFC 6961 */
#ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2

typedef struct CSRIv2 {
    byte status_type;
    byte options;
    word16 requests;
    union {
        OcspRequest ocsp[1 + MAX_CHAIN_DEPTH];
    } request;
    struct CSRIv2* next;
} CertificateStatusRequestItemV2;

WOLFSSL_LOCAL int   TLSX_UseCertificateStatusRequestV2(TLSX** extensions,
                                    byte status_type, byte options, void* heap);
WOLFSSL_LOCAL int   TLSX_CSR2_InitRequests(TLSX* extensions, DecodedCert* cert,
                                                       byte isPeer, void* heap);
WOLFSSL_LOCAL void* TLSX_CSR2_GetRequest(TLSX* extensions, byte status_type,
                                                                    byte index);
WOLFSSL_LOCAL int   TLSX_CSR2_ForceRequest(WOLFSSL* ssl);

#endif

/** Supported Elliptic Curves - RFC 4492 (session 4) */
#ifdef HAVE_SUPPORTED_CURVES

typedef struct EllipticCurve {
    word16                name; /* CurveNames    */
    struct EllipticCurve* next; /* List Behavior */
} EllipticCurve;

WOLFSSL_LOCAL int TLSX_UseSupportedCurve(TLSX** extensions, word16 name,
                                                                    void* heap);

#ifndef NO_WOLFSSL_SERVER
WOLFSSL_LOCAL int TLSX_ValidateEllipticCurves(WOLFSSL* ssl, byte first,
                                                                   byte second);
#endif

#endif /* HAVE_SUPPORTED_CURVES */

/** Renegotiation Indication - RFC 5746 */
#ifdef HAVE_SECURE_RENEGOTIATION

enum key_cache_state {
    SCR_CACHE_NULL   = 0,       /* empty / begin state */
    SCR_CACHE_NEEDED,           /* need to cache keys */
    SCR_CACHE_COPY,             /* we have a cached copy */
    SCR_CACHE_PARTIAL,          /* partial restore to real keys */
    SCR_CACHE_COMPLETE          /* complete restore to real keys */
};

/* Additional Connection State according to rfc5746 section 3.1 */
typedef struct SecureRenegotiation {
   byte                 enabled;  /* secure_renegotiation flag in rfc */
   byte                 startScr; /* server requested client to start scr */
   enum key_cache_state cache_status;  /* track key cache state */
   byte                 client_verify_data[TLS_FINISHED_SZ];  /* cached */
   byte                 server_verify_data[TLS_FINISHED_SZ];  /* cached */
   byte                 subject_hash[SHA_DIGEST_SIZE];  /* peer cert hash */
   Keys                 tmp_keys;  /* can't overwrite real keys yet */
} SecureRenegotiation;

WOLFSSL_LOCAL int TLSX_UseSecureRenegotiation(TLSX** extensions, void* heap);

#endif /* HAVE_SECURE_RENEGOTIATION */

/** Session Ticket - RFC 5077 (session 3.2) */
#ifdef HAVE_SESSION_TICKET

typedef struct SessionTicket {
    word32 lifetime;
    byte*  data;
    word16 size;
} SessionTicket;

WOLFSSL_LOCAL int  TLSX_UseSessionTicket(TLSX** extensions,
                                             SessionTicket* ticket, void* heap);
WOLFSSL_LOCAL SessionTicket* TLSX_SessionTicket_Create(word32 lifetime,
                                           byte* data, word16 size, void* heap);
WOLFSSL_LOCAL void TLSX_SessionTicket_Free(SessionTicket* ticket, void* heap);

#endif /* HAVE_SESSION_TICKET */

/** Quantum-Safe-Hybrid - draft-whyte-qsh-tls12-00 */
#ifdef HAVE_QSH

typedef struct QSHScheme {
    struct QSHScheme* next; /* List Behavior   */
    byte*             PK;
    word16            name; /* QSHScheme Names */
    word16            PKLen;
} QSHScheme;

typedef struct QSHkey {
    struct QSHKey* next;
    word16 name;
    buffer pub;
    buffer pri;
} QSHKey;

typedef struct QSHSecret {
    QSHScheme* list;
    buffer* SerSi;
    buffer* CliSi;
} QSHSecret;

/* used in key exchange during handshake */
WOLFSSL_LOCAL int TLSX_QSHCipher_Parse(WOLFSSL* ssl, const byte* input,
                                                  word16 length, byte isServer);
WOLFSSL_LOCAL word16 TLSX_QSHPK_Write(QSHScheme* list, byte* output);
WOLFSSL_LOCAL word16 TLSX_QSH_GetSize(QSHScheme* list, byte isRequest);

/* used by api for setting a specific QSH scheme */
WOLFSSL_LOCAL int TLSX_UseQSHScheme(TLSX** extensions, word16 name,
                                         byte* pKey, word16 pKeySz, void* heap);

/* used when parsing in QSHCipher structs */
WOLFSSL_LOCAL int QSH_Decrypt(QSHKey* key, byte* in, word32 szIn,
                                                      byte* out, word16* szOut);
#ifndef NO_WOLFSSL_SERVER
WOLFSSL_LOCAL int TLSX_ValidateQSHScheme(TLSX** extensions, word16 name);
#endif

#endif /* HAVE_QSH */


/* wolfSSL context type */
struct WOLFSSL_CTX {
    WOLFSSL_METHOD* method;
#ifdef SINGLE_THREADED
    WC_RNG*         rng;          /* to be shared with WOLFSSL w/o locking */
#endif
    wolfSSL_Mutex   countMutex;   /* reference count mutex */
    int         refCount;         /* reference count */
    int         err;              /* error code in case of mutex not created */
#ifndef NO_DH
    buffer      serverDH_P;
    buffer      serverDH_G;
#endif
#ifndef NO_CERTS
    DerBuffer*  certificate;
    DerBuffer*  certChain;
                 /* chain after self, in DER, with leading size for each cert */
    DerBuffer*  privateKey;
    WOLFSSL_CERT_MANAGER* cm;      /* our cert manager, ctx owns SSL will use */
#endif
#ifdef KEEP_OUR_CERT
    WOLFSSL_X509*    ourCert;     /* keep alive a X509 struct of cert */
#endif
    Suites*     suites;           /* make dynamic, user may not need/set */
    void*       heap;             /* for user memory overrides */
    byte        verifyPeer;
    byte        verifyNone;
    byte        failNoCert;
    byte        failNoCertxPSK;   /* fail if no cert with the exception of PSK*/
    byte        sessionCacheOff;
    byte        sessionCacheFlushOff;
    byte        sendVerify;       /* for client side */
    byte        haveRSA;          /* RSA available */
    byte        haveECC;          /* ECC available */
    byte        haveDH;           /* server DH parms set by user */
    byte        haveNTRU;         /* server private NTRU  key loaded */
    byte        haveECDSAsig;     /* server cert signed w/ ECDSA */
    byte        haveStaticECC;    /* static server ECC private key */
    byte        partialWrite;     /* only one msg per write call */
    byte        quietShutdown;    /* don't send close notify */
    byte        groupMessages;    /* group handshake messages before sending */
    byte        minDowngrade;     /* minimum downgrade version */
    byte        haveEMS;          /* have extended master secret extension */
#if defined(WOLFSSL_SCTP) && defined(WOLFSSL_DTLS)
    byte        dtlsSctp;         /* DTLS-over-SCTP mode */
    word16      dtlsMtuSz;        /* DTLS MTU size */
#endif
#ifndef NO_DH
    word16      minDhKeySz;       /* minimum DH key size */
#endif
#ifndef NO_RSA
    short       minRsaKeySz;      /* minimum RSA key size */
#endif
#ifdef HAVE_ECC
    short       minEccKeySz;      /* minimum ECC key size */
#endif
    CallbackIORecv CBIORecv;
    CallbackIOSend CBIOSend;
#ifdef WOLFSSL_DTLS
    CallbackGenCookie CBIOCookie;       /* gen cookie callback */
    wc_dtls_export    dtls_export;      /* export function for DTLS session */
#ifdef WOLFSSL_SESSION_EXPORT
    CallbackGetPeer CBGetPeer;
    CallbackSetPeer CBSetPeer;
#endif
#endif /* WOLFSSL_DTLS */
    VerifyCallback  verifyCallback;     /* cert verification callback */
    word32          timeout;            /* session timeout */
#ifdef HAVE_ECC
    word16          eccTempKeySz;       /* in octets 20 - 66 */
    word32          pkCurveOID;         /* curve Ecc_Sum */
#endif
#ifndef NO_PSK
    byte        havePSK;                /* psk key set by user */
    wc_psk_client_callback client_psk_cb;  /* client callback */
    wc_psk_server_callback server_psk_cb;  /* server callback */
    char        server_hint[MAX_PSK_ID_LEN];
#endif /* NO_PSK */
#ifdef HAVE_ANON
    byte        haveAnon;               /* User wants to allow Anon suites */
#endif /* HAVE_ANON */
#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)
    pem_password_cb passwd_cb;
    void*           userdata;
#endif /* OPENSSL_EXTRA */
#ifdef HAVE_STUNNEL
    void*           ex_data[MAX_EX_DATA];
    CallbackSniRecv sniRecvCb;
    void*           sniRecvCbArg;
#endif
#ifdef HAVE_OCSP
    WOLFSSL_OCSP      ocsp;
#endif
    int             devId;              /* async device id to use */
#ifdef HAVE_TLS_EXTENSIONS
    TLSX* extensions;                  /* RFC 6066 TLS Extensions data */
    #ifndef NO_WOLFSSL_SERVER
        #if defined(HAVE_CERTIFICATE_STATUS_REQUEST) \
         || defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)
            OcspRequest* certOcspRequest;
        #endif
        #if defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)
            OcspRequest* chainOcspRequest[MAX_CHAIN_DEPTH];
        #endif
    #endif
    #if defined(HAVE_SESSION_TICKET) && !defined(NO_WOLFSSL_SERVER)
        SessionTicketEncCb ticketEncCb;   /* enc/dec session ticket Cb */
        void*              ticketEncCtx;  /* session encrypt context */
        int                ticketHint;    /* ticket hint in seconds */
    #endif
#endif
#ifdef ATOMIC_USER
    CallbackMacEncrypt    MacEncryptCb;    /* Atomic User Mac/Encrypt Cb */
    CallbackDecryptVerify DecryptVerifyCb; /* Atomic User Decrypt/Verify Cb */
#endif
#ifdef HAVE_PK_CALLBACKS
    #ifdef HAVE_ECC
        CallbackEccSign   EccSignCb;    /* User EccSign   Callback handler */
        CallbackEccVerify EccVerifyCb;  /* User EccVerify Callback handler */
    #endif /* HAVE_ECC */
    #ifndef NO_RSA
        CallbackRsaSign   RsaSignCb;    /* User RsaSign   Callback handler */
        CallbackRsaVerify RsaVerifyCb;  /* User RsaVerify Callback handler */
        CallbackRsaEnc    RsaEncCb;     /* User Rsa Public Encrypt  handler */
        CallbackRsaDec    RsaDecCb;     /* User Rsa Private Decrypt handler */
    #endif /* NO_RSA */
#endif /* HAVE_PK_CALLBACKS */
#ifdef HAVE_WOLF_EVENT
        WOLF_EVENT_QUEUE event_queue;
#endif /* HAVE_WOLF_EVENT */
};


WOLFSSL_LOCAL
WOLFSSL_CTX* wolfSSL_CTX_new_ex(WOLFSSL_METHOD* method, void* heap);
WOLFSSL_LOCAL
int InitSSL_Ctx(WOLFSSL_CTX*, WOLFSSL_METHOD*, void* heap);
WOLFSSL_LOCAL
void FreeSSL_Ctx(WOLFSSL_CTX*);
WOLFSSL_LOCAL
void SSL_CtxResourceFree(WOLFSSL_CTX*);

WOLFSSL_LOCAL
int DeriveTlsKeys(WOLFSSL* ssl);
WOLFSSL_LOCAL
int ProcessOldClientHello(WOLFSSL* ssl, const byte* input, word32* inOutIdx,
                          word32 inSz, word16 sz);
#ifndef NO_CERTS
    WOLFSSL_LOCAL
    int AddCA(WOLFSSL_CERT_MANAGER* cm, DerBuffer** pDer, int type, int verify);
    WOLFSSL_LOCAL
    int AlreadySigner(WOLFSSL_CERT_MANAGER* cm, byte* hash);
#ifdef WOLFSSL_TRUST_PEER_CERT
    WOLFSSL_LOCAL
    int AddTrustedPeer(WOLFSSL_CERT_MANAGER* cm, DerBuffer** pDer, int verify);
    WOLFSSL_LOCAL
    int AlreadyTrustedPeer(WOLFSSL_CERT_MANAGER* cm, byte* hash);
#endif
#endif

/* All cipher suite related info
 * Keep as a constant size (no ifdefs) for session export */
typedef struct CipherSpecs {
    word16 key_size;
    word16 iv_size;
    word16 block_size;
    word16 aead_mac_size;
    byte bulk_cipher_algorithm;
    byte cipher_type;               /* block, stream, or aead */
    byte mac_algorithm;
    byte kea;                       /* key exchange algo */
    byte sig_algo;
    byte hash_size;
    byte pad_size;
    byte static_ecdh;
} CipherSpecs;


void InitCipherSpecs(CipherSpecs* cs);


/* Supported Message Authentication Codes from page 43 */
enum MACAlgorithm {
    no_mac,
    md5_mac,
    sha_mac,
    sha224_mac,
    sha256_mac,     /* needs to match external KDF_MacAlgorithm */
    sha384_mac,
    sha512_mac,
    rmd_mac,
    blake2b_mac
};


/* Supported Key Exchange Protocols */
enum KeyExchangeAlgorithm {
    no_kea,
    rsa_kea,
    diffie_hellman_kea,
    fortezza_kea,
    psk_kea,
    dhe_psk_kea,
    ecdhe_psk_kea,
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


/* Valid client certificate request types from page 27 */
enum ClientCertificateType {
    rsa_sign            = 1,
    dss_sign            = 2,
    rsa_fixed_dh        = 3,
    dss_fixed_dh        = 4,
    rsa_ephemeral_dh    = 5,
    dss_ephemeral_dh    = 6,
    fortezza_kea_cert   = 20,
    ecdsa_sign          = 64,
    rsa_fixed_ecdh      = 65,
    ecdsa_fixed_ecdh    = 66
};


enum CipherType { stream, block, aead };






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
#ifdef HAVE_CHACHA
    ChaCha*   chacha;
#endif
#ifdef HAVE_HC128
    HC128*  hc128;
#endif
#ifdef BUILD_RABBIT
    Rabbit* rabbit;
#endif
#ifdef HAVE_IDEA
    Idea* idea;
#endif
    byte    setup;       /* have we set it up flag for detection */
} Ciphers;


#ifdef HAVE_ONE_TIME_AUTH
/* Ciphers for one time authentication such as poly1305 */
typedef struct OneTimeAuth {
#ifdef HAVE_POLY1305
    Poly1305* poly1305;
#endif
    byte    setup;      /* flag for if a cipher has been set */

} OneTimeAuth;
#endif


WOLFSSL_LOCAL void InitCiphers(WOLFSSL* ssl);
WOLFSSL_LOCAL void FreeCiphers(WOLFSSL* ssl);


/* hashes type */
typedef struct Hashes {
    #ifndef NO_OLD_TLS
        byte md5[MD5_DIGEST_SIZE];
    #endif
    byte sha[SHA_DIGEST_SIZE];
    #ifndef NO_SHA256
        byte sha256[SHA256_DIGEST_SIZE];
    #endif
    #ifdef WOLFSSL_SHA384
        byte sha384[SHA384_DIGEST_SIZE];
    #endif
    #ifdef WOLFSSL_SHA512
        byte sha512[SHA512_DIGEST_SIZE];
    #endif
} Hashes;


/* Static x509 buffer */
typedef struct x509_buffer {
    int  length;                  /* actual size */
    byte buffer[MAX_X509_SIZE];   /* max static cert size */
} x509_buffer;


/* wolfSSL X509_CHAIN, for no dynamic memory SESSION_CACHE */
struct WOLFSSL_X509_CHAIN {
    int         count;                    /* total number in chain */
    x509_buffer certs[MAX_CHAIN_DEPTH];   /* only allow max depth 4 for now */
};


/* wolfSSL session type */
struct WOLFSSL_SESSION {
    word32          bornOn;                        /* create time in seconds   */
    word32          timeout;                       /* timeout in seconds       */
    byte            sessionID[ID_LEN];             /* id for protocol */
    byte            sessionIDSz;
    byte            masterSecret[SECRET_LEN];      /* stored secret */
    word16          haveEMS;                       /* ext master secret flag */
#ifdef SESSION_CERTS
    WOLFSSL_X509_CHAIN chain;                    /* peer cert chain, static  */
    ProtocolVersion version;                    /* which version was used */
    byte            cipherSuite0;               /* first byte, normally 0 */
    byte            cipherSuite;                /* 2nd byte, actual suite */
#endif
#ifndef NO_CLIENT_CACHE
    word16          idLen;                         /* serverID length */
    byte            serverID[SERVER_ID_LEN];       /* for easier client lookup */
#endif
#ifdef HAVE_SESSION_TICKET
    byte*           ticket;
    word16          ticketLen;
    byte            staticTicket[SESSION_TICKET_LEN];
    byte            isDynamic;
#endif
#ifdef HAVE_STUNNEL
    void*           ex_data[MAX_EX_DATA];
#endif
};


WOLFSSL_LOCAL
WOLFSSL_SESSION* GetSession(WOLFSSL*, byte*, byte);
WOLFSSL_LOCAL
int          SetSession(WOLFSSL*, WOLFSSL_SESSION*);

typedef int (*hmacfp) (WOLFSSL*, byte*, const byte*, word32, int, int);

#ifndef NO_CLIENT_CACHE
    WOLFSSL_SESSION* GetSessionClient(WOLFSSL*, const byte*, int);
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
    ACCEPT_FIRST_REPLY_DONE,
    SERVER_HELLO_SENT,
    CERT_SENT,
    CERT_STATUS_SENT,
    KEY_EXCHANGE_SENT,
    CERT_REQ_SENT,
    SERVER_HELLO_DONE,
    ACCEPT_SECOND_REPLY_DONE,
    TICKET_SENT,
    CHANGE_CIPHER_SENT,
    ACCEPT_FINISHED_DONE,
    ACCEPT_THIRD_REPLY_DONE
};

/* sub-states for send/do key share (key exchange) */
enum KeyShareState {
    KEYSHARE_BEGIN = 0,
    KEYSHARE_BUILD,
    KEYSHARE_DO,
    KEYSHARE_VERIFY,
    KEYSHARE_FINALIZE,
    KEYSHARE_END
};

/* buffers for struct WOLFSSL */
typedef struct Buffers {
    bufferStatic    inputBuffer;
    bufferStatic    outputBuffer;
    buffer          domainName;             /* for client check */
    buffer          clearOutputBuffer;
    buffer          sig;                   /* signature data */
    buffer          digest;                /* digest data */
    int             prevSent;              /* previous plain text bytes sent
                                              when got WANT_WRITE            */
    int             plainSz;               /* plain text bytes in buffer to send
                                              when got WANT_WRITE            */
    byte            weOwnCert;             /* SSL own cert flag */
    byte            weOwnCertChain;        /* SSL own cert chain flag */
    byte            weOwnKey;              /* SSL own key  flag */
    byte            weOwnDH;               /* SSL own dh (p,g)  flag */
#ifndef NO_DH
    buffer          serverDH_P;            /* WOLFSSL_CTX owns, unless we own */
    buffer          serverDH_G;            /* WOLFSSL_CTX owns, unless we own */
    buffer          serverDH_Pub;
    buffer          serverDH_Priv;
#endif
#ifndef NO_CERTS
    DerBuffer*      certificate;           /* WOLFSSL_CTX owns, unless we own */
    DerBuffer*      key;                   /* WOLFSSL_CTX owns, unless we own */
    DerBuffer*      certChain;             /* WOLFSSL_CTX owns, unless we own */
                 /* chain after self, in DER, with leading size for each cert */
#endif
#ifdef WOLFSSL_DTLS
    WOLFSSL_DTLS_CTX dtlsCtx;               /* DTLS connection context */
    #ifndef NO_WOLFSSL_SERVER
        buffer       dtlsCookieSecret;      /* DTLS cookie secret */
    #endif /* NO_WOLFSSL_SERVER */
#endif
#ifdef HAVE_PK_CALLBACKS
    #ifdef HAVE_ECC
        buffer peerEccDsaKey;              /* we own for Ecc Verify Callbacks */
    #endif /* HAVE_ECC */
    #ifndef NO_RSA
        buffer peerRsaKey;                 /* we own for Rsa Verify Callbacks */
    #endif /* NO_RSA */
#endif /* HAVE_PK_CALLBACKS */
} Buffers;

typedef struct Options {
#ifndef NO_PSK
    wc_psk_client_callback client_psk_cb;
    wc_psk_server_callback server_psk_cb;
    word16            havePSK:1;            /* psk key set by user */
#endif /* NO_PSK */

    /* on/off or small bit flags, optimize layout */
    word16            sendVerify:2;     /* false = 0, true = 1, sendBlank = 2 */
    word16            sessionCacheOff:1;
    word16            sessionCacheFlushOff:1;
    word16            side:1;             /* client or server end */
    word16            verifyPeer:1;
    word16            verifyNone:1;
    word16            failNoCert:1;
    word16            failNoCertxPSK:1;   /* fail for no cert except with PSK */
    word16            downgrade:1;        /* allow downgrade of versions */
    word16            resuming:1;
    word16            haveSessionId:1;    /* server may not send */
    word16            tls:1;              /* using TLS ? */
    word16            tls1_1:1;           /* using TLSv1.1+ ? */
    word16            dtls:1;             /* using datagrams ? */
    word16            connReset:1;        /* has the peer reset */
    word16            isClosed:1;         /* if we consider conn closed */
    word16            closeNotify:1;      /* we've received a close notify */
    word16            sentNotify:1;       /* we've sent a close notify */
    word16            usingCompression:1; /* are we using compression */
    word16            haveRSA:1;          /* RSA available */
    word16            haveECC:1;          /* ECC available */
    word16            haveDH:1;           /* server DH parms set by user */
    word16            haveNTRU:1;         /* server NTRU  private key loaded */
    word16            haveQSH:1;          /* have QSH ability */
    word16            haveECDSAsig:1;     /* server ECDSA signed cert */
    word16            haveStaticECC:1;    /* static server ECC private key */
    word16            havePeerCert:1;     /* do we have peer's cert */
    word16            havePeerVerify:1;   /* and peer's cert verify */
    word16            usingPSK_cipher:1;  /* are using psk as cipher */
    word16            usingAnon_cipher:1; /* are we using an anon cipher */
    word16            sendAlertState:1;   /* nonblocking resume */
    word16            partialWrite:1;     /* only one msg per write call */
    word16            quietShutdown:1;    /* don't send close notify */
    word16            certOnly:1;         /* stop once we get cert */
    word16            groupMessages:1;    /* group handshake messages */
    word16            usingNonblock:1;    /* are we using nonblocking socket */
    word16            saveArrays:1;       /* save array Memory for user get keys
                                           or psk */
    word16            weOwnRng:1;         /* will be true unless CTX owns */
#ifdef HAVE_POLY1305
    word16            oldPoly:1;        /* set when to use old rfc way of poly*/
#endif
#ifdef HAVE_ANON
    word16            haveAnon:1;       /* User wants to allow Anon suites */
#endif
#ifdef HAVE_SESSION_TICKET
    word16            createTicket:1;     /* Server to create new Ticket */
    word16            useTicket:1;        /* Use Ticket not session cache */
    word16            rejectTicket:1;     /* Callback rejected ticket */
#endif
#ifdef WOLFSSL_DTLS
    word16            dtlsHsRetain:1;     /* DTLS retaining HS data */
#ifdef WOLFSSL_SCTP
    word16            dtlsSctp:1;         /* DTLS-over-SCTP mode */
#endif
#endif
    word16            haveEMS:1;          /* using extended master secret */

    /* need full byte values for this section */
    byte            processReply;           /* nonblocking resume */
    byte            cipherSuite0;           /* first byte, normally 0 */
    byte            cipherSuite;            /* second byte, actual suite */
    byte            serverState;
    byte            clientState;
    byte            handShakeState;
    byte            handShakeDone;      /* at least one handshake complete */
    byte            minDowngrade;       /* minimum downgrade version */
    byte            connectState;       /* nonblocking resume */
    byte            acceptState;        /* nonblocking resume */
    byte            keyShareState;      /* sub-state for key share (key exchange).
                                           See enum KeyShareState. */
#ifndef NO_DH
    word16          minDhKeySz;         /* minimum DH key size */
    word16          dhKeySz;            /* actual DH key size */
#endif
#ifndef NO_RSA
    short           minRsaKeySz;      /* minimum RSA key size */
#endif
#ifdef HAVE_ECC
    short           minEccKeySz;      /* minimum ECC key size */
#endif

} Options;

typedef struct Arrays {
    byte*           pendingMsg;         /* defrag buffer */
    word32          preMasterSz;        /* differs for DH, actual size */
    word32          pendingMsgSz;       /* defrag buffer size */
    word32          pendingMsgOffset;   /* current offset into defrag buffer */
#ifndef NO_PSK
    word32          psk_keySz;          /* actual size */
    char            client_identity[MAX_PSK_ID_LEN];
    char            server_hint[MAX_PSK_ID_LEN];
    byte            psk_key[MAX_PSK_KEY_LEN];
#endif
    byte            clientRandom[RAN_LEN];
    byte            serverRandom[RAN_LEN];
    byte            sessionID[ID_LEN];
    byte            sessionIDSz;
    byte            preMasterSecret[ENCRYPT_LEN];
    byte            masterSecret[SECRET_LEN];
#ifdef WOLFSSL_DTLS
    byte            cookie[MAX_COOKIE_LEN];
    byte            cookieSz;
#endif
    byte            pendingMsgType;    /* defrag buffer message type */
} Arrays;

#ifndef ASN_NAME_MAX
#define ASN_NAME_MAX 256
#endif

#ifndef MAX_DATE_SZ
#define MAX_DATE_SZ 32
#endif

struct WOLFSSL_X509_NAME {
    char  *name;
    char  staticName[ASN_NAME_MAX];
    int   dynamicName;
    int   sz;
#if defined(OPENSSL_EXTRA) && !defined(NO_ASN)
    DecodedName fullName;
    WOLFSSL_X509_NAME_ENTRY cnEntry;
    WOLFSSL_X509*           x509;   /* x509 that struct belongs to */
#endif /* OPENSSL_EXTRA */
};

#ifndef EXTERNAL_SERIAL_SIZE
    #define EXTERNAL_SERIAL_SIZE 32
#endif

#ifdef NO_ASN
    typedef struct DNS_entry DNS_entry;
#endif

struct WOLFSSL_X509 {
    int              version;
    WOLFSSL_X509_NAME issuer;
    WOLFSSL_X509_NAME subject;
    int              serialSz;
    byte             serial[EXTERNAL_SERIAL_SIZE];
    char             subjectCN[ASN_NAME_MAX];        /* common name short cut */
#ifdef WOLFSSL_SEP
    int              deviceTypeSz;
    byte             deviceType[EXTERNAL_SERIAL_SIZE];
    int              hwTypeSz;
    byte             hwType[EXTERNAL_SERIAL_SIZE];
    int              hwSerialNumSz;
    byte             hwSerialNum[EXTERNAL_SERIAL_SIZE];
    #ifdef OPENSSL_EXTRA
        byte             certPolicySet;
        byte             certPolicyCrit;
    #endif /* OPENSSL_EXTRA */
#endif
    int              notBeforeSz;
    byte             notBefore[MAX_DATE_SZ];
    int              notAfterSz;
    byte             notAfter[MAX_DATE_SZ];
    int              sigOID;
    buffer           sig;
    int              pubKeyOID;
    buffer           pubKey;
    #ifdef HAVE_ECC
        word32       pkCurveOID;
    #endif /* HAVE_ECC */
    #ifndef NO_CERTS
        DerBuffer*   derCert;                        /* may need  */
    #endif
    DNS_entry*       altNames;                       /* alt names list */
    DNS_entry*       altNamesNext;                   /* hint for retrieval */
    void*            heap;                           /* heap hint */
    byte             dynamicMemory;                  /* dynamic memory flag */
    byte             isCa;
#ifdef OPENSSL_EXTRA
    word32           pathLength;
    word16           keyUsage;
    byte             basicConstSet;
    byte             basicConstCrit;
    byte             basicConstPlSet;
    byte             subjAltNameSet;
    byte             subjAltNameCrit;
    byte             authKeyIdSet;
    byte             authKeyIdCrit;
    byte*            authKeyId;
    word32           authKeyIdSz;
    byte             subjKeyIdSet;
    byte             subjKeyIdCrit;
    byte*            subjKeyId;
    word32           subjKeyIdSz;
    byte             keyUsageSet;
    byte             keyUsageCrit;
#endif /* OPENSSL_EXTRA */
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
    word16          epoch[DTLS_POOL_SZ];
    int             used;
} DtlsPool;


typedef struct DtlsFrag {
    word32 begin;
    word32 end;
    struct DtlsFrag* next;
} DtlsFrag;


typedef struct DtlsMsg {
    struct DtlsMsg* next;
    byte*           buf;
    byte*           msg;
    DtlsFrag*       fragList;
    word32          fragSz;    /* Length of fragments received */
    word32          seq;       /* Handshake sequence number    */
    word32          sz;        /* Length of whole mesage       */
    byte            type;
} DtlsMsg;


#ifdef HAVE_NETX

    /* NETX I/O Callback default */
    typedef struct NetX_Ctx {
        NX_TCP_SOCKET* nxSocket;    /* send/recv socket handle */
        NX_PACKET*     nxPacket;    /* incoming packet handle for short reads */
        ULONG          nxOffset;    /* offset already read from nxPacket */
        ULONG          nxWait;      /* wait option flag */
    } NetX_Ctx;

#endif


/* Handshake messages received from peer (plus change cipher */
typedef struct MsgsReceived {
    word16 got_hello_request:1;
    word16 got_client_hello:1;
    word16 got_server_hello:1;
    word16 got_hello_verify_request:1;
    word16 got_session_ticket:1;
    word16 got_certificate:1;
    word16 got_certificate_status:1;
    word16 got_server_key_exchange:1;
    word16 got_certificate_request:1;
    word16 got_server_hello_done:1;
    word16 got_certificate_verify:1;
    word16 got_client_key_exchange:1;
    word16 got_finished:1;
    word16 got_change_cipher:1;
} MsgsReceived;


/* Handshake hashes */
typedef struct HS_Hashes {
    Hashes          verifyHashes;
    Hashes          certHashes;         /* for cert verify */
#ifndef NO_OLD_TLS
#ifndef NO_SHA
    Sha             hashSha;            /* sha hash of handshake msgs */
#endif
#ifndef NO_MD5
    Md5             hashMd5;            /* md5 hash of handshake msgs */
#endif
#endif /* NO_OLD_TLS */
#ifndef NO_SHA256
    Sha256          hashSha256;         /* sha256 hash of handshake msgs */
#endif
#ifdef WOLFSSL_SHA384
    Sha384          hashSha384;         /* sha384 hash of handshake msgs */
#endif
#ifdef WOLFSSL_SHA512
    Sha512          hashSha512;         /* sha512 hash of handshake msgs */
#endif
} HS_Hashes;


/* wolfSSL ssl type */
struct WOLFSSL {
    WOLFSSL_CTX*    ctx;
    Suites*         suites;             /* only need during handshake */
    Arrays*         arrays;
    HS_Hashes*      hsHashes;
    void*           IOCB_ReadCtx;
    void*           IOCB_WriteCtx;
    WC_RNG*         rng;
    void*           verifyCbCtx;        /* cert verify callback user ctx*/
    VerifyCallback  verifyCallback;     /* cert verification callback */
    void*           heap;               /* for user overrides */
#ifdef WOLFSSL_STATIC_MEMORY
    WOLFSSL_HEAP_HINT heap_hint;
#endif
#ifndef NO_HANDSHAKE_DONE_CB
    HandShakeDoneCb hsDoneCb;          /*  notify user handshake done */
    void*           hsDoneCtx;         /*  user handshake cb context  */
#endif
#ifdef WOLFSSL_ASYNC_CRYPT
    AsyncCryptSSLState  async;
    AsyncCryptDev       asyncDev;
#endif
    void*           sigKey;             /* RsaKey or ecc_key allocated from heap */
    word32          sigType;            /* Type of sigKey */
    word32          sigLen;             /* Actual signature length */
    WOLFSSL_CIPHER  cipher;
    hmacfp          hmac;
    Ciphers         encrypt;
    Ciphers         decrypt;
    Buffers         buffers;
    WOLFSSL_SESSION session;
    WOLFSSL_ALERT_HISTORY alert_history;
    int             error;
    int             rfd;                /* read  file descriptor */
    int             wfd;                /* write file descriptor */
    int             rflags;             /* user read  flags */
    int             wflags;             /* user write flags */
    word32          timeout;            /* session timeout */
    word32          fragOffset;         /* fragment offset */
    word16          curSize;
    RecordLayerHeader curRL;
    MsgsReceived    msgsReceived;       /* peer messages received */
    ProtocolVersion version;            /* negotiated version */
    ProtocolVersion chVersion;          /* client hello version */
    CipherSpecs     specs;
    Keys            keys;
    Options         options;
#ifdef OPENSSL_EXTRA
    WOLFSSL_BIO*     biord;              /* socket bio read  to free/close */
    WOLFSSL_BIO*     biowr;              /* socket bio write to free/close */
#endif
#ifndef NO_RSA
    RsaKey*         peerRsaKey;
    byte            peerRsaKeyPresent;
#endif
#ifdef HAVE_QSH
    QSHKey*         QSH_Key;
    QSHKey*         peerQSHKey;
    QSHSecret*      QSH_secret;
    byte            isQSH;             /* is the handshake a QSH? */
    byte            sendQSHKeys;       /* flag for if the client should sen
                                          public keys */
    byte            peerQSHKeyPresent;
    byte            minRequest;
    byte            maxRequest;
    byte            user_set_QSHSchemes;
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
    word32          pkCurveOID;              /* curve Ecc_Sum     */
    word16          eccTempKeySz;            /* in octets 20 - 66 */
    byte            peerEccKeyPresent;
    byte            peerEccDsaKeyPresent;
    byte            eccTempKeyPresent;
#endif
#ifdef HAVE_LIBZ
    z_stream        c_stream;           /* compression   stream */
    z_stream        d_stream;           /* decompression stream */
    byte            didStreamInit;      /* for stream init and end */
#endif
#ifdef WOLFSSL_DTLS
    int             dtls_timeout_init;  /* starting timeout value */
    int             dtls_timeout_max;   /* maximum timeout value */
    int             dtls_timeout;       /* current timeout value, changes */
    DtlsPool*       dtls_pool;
    DtlsMsg*        dtls_msg_list;
    void*           IOCB_CookieCtx;     /* gen cookie ctx */
    word32          dtls_expected_rx;
    wc_dtls_export  dtls_export;        /* export function for session */
#ifdef WOLFSSL_SCTP
    word16          dtlsMtuSz;
#endif /* WOLFSSL_SCTP */
#endif
#ifdef WOLFSSL_CALLBACKS
    HandShakeInfo   handShakeInfo;      /* info saved during handshake */
    TimeoutInfo     timeoutInfo;        /* info saved during handshake */
    byte            hsInfoOn;           /* track handshake info        */
    byte            toInfoOn;           /* track timeout   info        */
#endif
#ifdef HAVE_FUZZER
    CallbackFuzzer  fuzzerCb;           /* for testing with using fuzzer */
    void*           fuzzerCtx;          /* user defined pointer */
#endif
#ifdef KEEP_PEER_CERT
    WOLFSSL_X509     peerCert;           /* X509 peer cert */
#endif
#ifdef KEEP_OUR_CERT
    WOLFSSL_X509*    ourCert;            /* keep alive a X509 struct of cert.
                                            points to ctx if not owned (owned
                                            flag found in buffers.weOwnCert) */
#endif
    byte             keepCert;           /* keep certificate after handshake */
#if defined(FORTRESS) || defined(HAVE_STUNNEL)
    void*           ex_data[MAX_EX_DATA]; /* external data, for Fortress */
#endif
    int              devId;             /* async device id to use */
#ifdef HAVE_ONE_TIME_AUTH
    OneTimeAuth     auth;
#endif
#ifdef HAVE_TLS_EXTENSIONS
    TLSX* extensions;                  /* RFC 6066 TLS Extensions data */
    #ifdef HAVE_MAX_FRAGMENT
        word16 max_fragment;
    #endif
    #ifdef HAVE_TRUNCATED_HMAC
        byte truncated_hmac;
    #endif
    #ifdef HAVE_CERTIFICATE_STATUS_REQUEST
        byte status_request;
    #endif
    #ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2
        byte status_request_v2;
    #endif
    #ifdef HAVE_SECURE_RENEGOTIATION
        SecureRenegotiation* secure_renegotiation; /* valid pointer indicates */
    #endif                                         /* user turned on */
    #ifdef HAVE_ALPN
        char*   alpn_client_list;  /* keep the client's list */
    #endif                         /* of accepted protocols */
    #if !defined(NO_WOLFSSL_CLIENT) && defined(HAVE_SESSION_TICKET)
        CallbackSessionTicket session_ticket_cb;
        void*                 session_ticket_ctx;
        byte                  expect_session_ticket;
    #endif
#endif /* HAVE_TLS_EXTENSIONS */
#ifdef HAVE_NETX
    NetX_Ctx        nxCtx;             /* NetX IO Context */
#endif
#ifdef SESSION_INDEX
    int sessionIndex;                  /* Session's location in the cache. */
#endif
#ifdef ATOMIC_USER
    void*    MacEncryptCtx;    /* Atomic User Mac/Encrypt Callback Context */
    void*    DecryptVerifyCtx; /* Atomic User Decrypt/Verify Callback Context */
#endif
#ifdef HAVE_PK_CALLBACKS
    #ifdef HAVE_ECC
        void* EccSignCtx;     /* Ecc Sign   Callback Context */
        void* EccVerifyCtx;   /* Ecc Verify Callback Context */
    #endif /* HAVE_ECC */
    #ifndef NO_RSA
        void* RsaSignCtx;     /* Rsa Sign   Callback Context */
        void* RsaVerifyCtx;   /* Rsa Verify Callback Context */
        void* RsaEncCtx;      /* Rsa Public  Encrypt   Callback Context */
        void* RsaDecCtx;      /* Rsa Private Decrypt   Callback Context */
    #endif /* NO_RSA */
#endif /* HAVE_PK_CALLBACKS */
#ifdef HAVE_SECRET_CALLBACK
        SessionSecretCb sessionSecretCb;
        void*           sessionSecretCtx;
#endif /* HAVE_SECRET_CALLBACK */
#ifdef WOLFSSL_JNI
        void* jObjectRef;     /* reference to WolfSSLSession in JNI wrapper */
#endif /* WOLFSSL_JNI */
#ifdef HAVE_WOLF_EVENT
    WOLF_EVENT event;
#endif /* HAVE_WOLF_EVENT */
};


WOLFSSL_LOCAL
int  SetSSL_CTX(WOLFSSL*, WOLFSSL_CTX*);
WOLFSSL_LOCAL
int  InitSSL(WOLFSSL*, WOLFSSL_CTX*);
WOLFSSL_LOCAL
void FreeSSL(WOLFSSL*, void* heap);
WOLFSSL_API void SSL_ResourceFree(WOLFSSL*);   /* Micrium uses */


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
    WOLFSSL_CTX* ctx;              /* CTX owner */
} EncryptedInfo;


#ifndef NO_CERTS

    WOLFSSL_LOCAL int AllocDer(DerBuffer** der, word32 length, int type, void* heap);
    WOLFSSL_LOCAL void FreeDer(DerBuffer** der);

    WOLFSSL_LOCAL int PemToDer(const unsigned char* buff, long sz, int type,
                              DerBuffer** pDer, void* heap, EncryptedInfo* info,
                              int* eccKey);

    WOLFSSL_LOCAL int ProcessFile(WOLFSSL_CTX* ctx, const char* fname, int format,
                                 int type, WOLFSSL* ssl, int userChain,
                                WOLFSSL_CRL* crl);
#endif


#ifdef WOLFSSL_CALLBACKS
    WOLFSSL_LOCAL
    void InitHandShakeInfo(HandShakeInfo*, WOLFSSL*);
    WOLFSSL_LOCAL
    void FinishHandShakeInfo(HandShakeInfo*);
    WOLFSSL_LOCAL
    void AddPacketName(const char*, HandShakeInfo*);

    WOLFSSL_LOCAL
    void InitTimeoutInfo(TimeoutInfo*);
    WOLFSSL_LOCAL
    void FreeTimeoutInfo(TimeoutInfo*, void*);
    WOLFSSL_LOCAL
    void AddPacketInfo(const char*, TimeoutInfo*, const byte*, int, void*);
    WOLFSSL_LOCAL
    void AddLateName(const char*, TimeoutInfo*);
    WOLFSSL_LOCAL
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
    byte            message_seq[2];    /* start at 0, retransmit gets same # */
    word24          fragment_offset;   /* bytes in previous fragments */
    word24          fragment_length;   /* length of this fragment */
} DtlsHandShakeHeader;


enum HandShakeType {
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
    finished            = 20,
    certificate_status  = 22,
    change_cipher_hs    = 55,     /* simulate unique handshake type for sanity
                                     checks.  record layer change_cipher
                                     conflicts with handshake finished */
    no_shake            = 255     /* used to initialize the DtlsMsg record */
};


static const byte client[SIZEOF_SENDER] = { 0x43, 0x4C, 0x4E, 0x54 };
static const byte server[SIZEOF_SENDER] = { 0x53, 0x52, 0x56, 0x52 };

static const byte tls_client[FINISHED_LABEL_SZ + 1] = "client finished";
static const byte tls_server[FINISHED_LABEL_SZ + 1] = "server finished";


/* internal functions */
WOLFSSL_LOCAL int SendChangeCipher(WOLFSSL*);
WOLFSSL_LOCAL int SendTicket(WOLFSSL*);
WOLFSSL_LOCAL int DoClientTicket(WOLFSSL*, const byte*, word32);
WOLFSSL_LOCAL int SendData(WOLFSSL*, const void*, int);
WOLFSSL_LOCAL int SendCertificate(WOLFSSL*);
WOLFSSL_LOCAL int SendCertificateRequest(WOLFSSL*);
WOLFSSL_LOCAL int SendCertificateStatus(WOLFSSL*);
WOLFSSL_LOCAL int SendServerKeyExchange(WOLFSSL*);
WOLFSSL_LOCAL int SendBuffered(WOLFSSL*);
WOLFSSL_LOCAL int ReceiveData(WOLFSSL*, byte*, int, int);
WOLFSSL_LOCAL int SendFinished(WOLFSSL*);
WOLFSSL_LOCAL int SendAlert(WOLFSSL*, int, int);
WOLFSSL_LOCAL int ProcessReply(WOLFSSL*);

WOLFSSL_LOCAL int SetCipherSpecs(WOLFSSL*);
WOLFSSL_LOCAL int MakeMasterSecret(WOLFSSL*);

WOLFSSL_LOCAL int AddSession(WOLFSSL*);
WOLFSSL_LOCAL int DeriveKeys(WOLFSSL* ssl);
WOLFSSL_LOCAL int StoreKeys(WOLFSSL* ssl, const byte* keyData);

WOLFSSL_LOCAL int IsTLS(const WOLFSSL* ssl);
WOLFSSL_LOCAL int IsAtLeastTLSv1_2(const WOLFSSL* ssl);

WOLFSSL_LOCAL void FreeHandshakeResources(WOLFSSL* ssl);
WOLFSSL_LOCAL void ShrinkInputBuffer(WOLFSSL* ssl, int forcedFree);
WOLFSSL_LOCAL void ShrinkOutputBuffer(WOLFSSL* ssl);

WOLFSSL_LOCAL int VerifyClientSuite(WOLFSSL* ssl);
#ifndef NO_CERTS
    #ifndef NO_RSA
        WOLFSSL_LOCAL int VerifyRsaSign(WOLFSSL* ssl,
                                        byte* verifySig, word32 sigSz,
                                        const byte* plain, word32 plainSz,
                                        RsaKey* key);
        WOLFSSL_LOCAL int RsaSign(WOLFSSL* ssl, const byte* in, word32 inSz, byte* out,
            word32* outSz, RsaKey* key, const byte* keyBuf, word32 keySz, void* ctx);
        WOLFSSL_LOCAL int RsaVerify(WOLFSSL* ssl, byte* in, word32 inSz,
            byte** out, RsaKey* key, const byte* keyBuf, word32 keySz, void* ctx);
        WOLFSSL_LOCAL int RsaDec(WOLFSSL* ssl, byte* in, word32 inSz, byte** out,
            word32* outSz, RsaKey* key, const byte* keyBuf, word32 keySz, void* ctx);
        WOLFSSL_LOCAL int RsaEnc(WOLFSSL* ssl, const byte* in, word32 inSz, byte* out,
            word32* outSz, RsaKey* key, const byte* keyBuf, word32 keySz, void* ctx);
    #endif /* !NO_RSA */

    #ifdef HAVE_ECC
        WOLFSSL_LOCAL int EccSign(WOLFSSL* ssl, const byte* in, word32 inSz,
            byte* out, word32* outSz, ecc_key* key, byte* keyBuf, word32 keySz,
            void* ctx);
        WOLFSSL_LOCAL int EccVerify(WOLFSSL* ssl, const byte* in, word32 inSz,
            const byte* out, word32 outSz, ecc_key* key, byte* keyBuf, word32 keySz,
            void* ctx);
        WOLFSSL_LOCAL int EccSharedSecret(WOLFSSL* ssl, ecc_key* priv_key,
            ecc_key* pub_key, byte* out, word32* outSz);
    #endif /* HAVE_ECC */

    #ifdef WOLFSSL_TRUST_PEER_CERT

        /* options for searching hash table for a matching trusted peer cert */
        #define WC_MATCH_SKID 0
        #define WC_MATCH_NAME 1

        WOLFSSL_LOCAL TrustedPeerCert* GetTrustedPeer(void* vp, byte* hash,
                                                                      int type);
        WOLFSSL_LOCAL int MatchTrustedPeer(TrustedPeerCert* tp,
                                                             DecodedCert* cert);
    #endif

    WOLFSSL_LOCAL Signer* GetCA(void* cm, byte* hash);
    #ifndef NO_SKID
        WOLFSSL_LOCAL Signer* GetCAByName(void* cm, byte* hash);
    #endif
#endif /* !NO_CERTS */
WOLFSSL_LOCAL int  BuildTlsHandshakeHash(WOLFSSL* ssl, byte* hash,
                                   word32* hashLen);
WOLFSSL_LOCAL int  BuildTlsFinished(WOLFSSL* ssl, Hashes* hashes,
                                   const byte* sender);
WOLFSSL_LOCAL void FreeArrays(WOLFSSL* ssl, int keep);
WOLFSSL_LOCAL  int CheckAvailableSize(WOLFSSL *ssl, int size);
WOLFSSL_LOCAL  int GrowInputBuffer(WOLFSSL* ssl, int size, int usedLength);

#ifndef NO_TLS
    WOLFSSL_LOCAL int  MakeTlsMasterSecret(WOLFSSL*);
    WOLFSSL_LOCAL int  TLS_hmac(WOLFSSL* ssl, byte* digest, const byte* in,
                               word32 sz, int content, int verify);
#endif

#ifndef NO_WOLFSSL_CLIENT
    WOLFSSL_LOCAL int SendClientHello(WOLFSSL*);
    WOLFSSL_LOCAL int SendClientKeyExchange(WOLFSSL*);
    WOLFSSL_LOCAL int SendCertificateVerify(WOLFSSL*);
#endif /* NO_WOLFSSL_CLIENT */

#ifndef NO_WOLFSSL_SERVER
    WOLFSSL_LOCAL int SendServerHello(WOLFSSL*);
    WOLFSSL_LOCAL int SendServerHelloDone(WOLFSSL*);
#endif /* NO_WOLFSSL_SERVER */

#ifdef WOLFSSL_DTLS
    WOLFSSL_LOCAL int  DtlsPoolInit(WOLFSSL*);
    WOLFSSL_LOCAL int  DtlsPoolSave(WOLFSSL*, const byte*, int);
    WOLFSSL_LOCAL int  DtlsPoolTimeout(WOLFSSL*);
    WOLFSSL_LOCAL int  DtlsPoolSend(WOLFSSL*);
    WOLFSSL_LOCAL void DtlsPoolReset(WOLFSSL*);
    WOLFSSL_LOCAL void DtlsPoolDelete(WOLFSSL*);

    WOLFSSL_LOCAL DtlsMsg* DtlsMsgNew(word32, void*);
    WOLFSSL_LOCAL void DtlsMsgDelete(DtlsMsg*, void*);
    WOLFSSL_LOCAL void DtlsMsgListDelete(DtlsMsg*, void*);
    WOLFSSL_LOCAL int  DtlsMsgSet(DtlsMsg*, word32, const byte*, byte,
                                                       word32, word32, void*);
    WOLFSSL_LOCAL DtlsMsg* DtlsMsgFind(DtlsMsg*, word32);
    WOLFSSL_LOCAL DtlsMsg* DtlsMsgStore(DtlsMsg*, word32, const byte*, word32,
                                                byte, word32, word32, void*);
    WOLFSSL_LOCAL DtlsMsg* DtlsMsgInsert(DtlsMsg*, DtlsMsg*);
#endif /* WOLFSSL_DTLS */

#ifndef NO_TLS


#endif /* NO_TLS */


WOLFSSL_LOCAL word32  LowResTimer(void);

#ifndef NO_CERTS
    WOLFSSL_LOCAL void InitX509Name(WOLFSSL_X509_NAME*, int);
    WOLFSSL_LOCAL void FreeX509Name(WOLFSSL_X509_NAME* name, void* heap);
    WOLFSSL_LOCAL void InitX509(WOLFSSL_X509*, int, void* heap);
    WOLFSSL_LOCAL void FreeX509(WOLFSSL_X509*);
    WOLFSSL_LOCAL int  CopyDecodedToX509(WOLFSSL_X509*, DecodedCert*);
#endif

/* used by ssl.c and wolfssl_int.c */
WOLFSSL_LOCAL void c32to24(word32 in, word24 out);

WOLFSSL_LOCAL const char* const* GetCipherNames(void);
WOLFSSL_LOCAL int GetCipherNamesSize(void);
WOLFSSL_LOCAL const char* GetCipherNameInternal(const char* cipherName, int cipherSuite);
WOLFSSL_LOCAL const char* wolfSSL_get_cipher_name_internal(WOLFSSL* ssl);


enum encrypt_side {
    ENCRYPT_SIDE_ONLY = 1,
    DECRYPT_SIDE_ONLY,
    ENCRYPT_AND_DECRYPT_SIDE
};

WOLFSSL_LOCAL int SetKeysSide(WOLFSSL*, enum encrypt_side);


#ifndef NO_DH
    WOLFSSL_LOCAL int DhGenKeyPair(WOLFSSL* ssl,
        byte* p, word32 pSz,
        byte* g, word32 gSz,
        byte* priv, word32* privSz,
        byte* pub, word32* pubSz);
    WOLFSSL_LOCAL int DhAgree(WOLFSSL* ssl,
        byte* p, word32 pSz,
        byte* g, word32 gSz,
        byte* priv, word32* privSz,
        byte* pub, word32* pubSz,
        const byte* otherPub, word32 otherPubSz,
        byte* agree, word32* agreeSz);
#endif

#ifdef HAVE_ECC
    WOLFSSL_LOCAL int EccMakeKey(WOLFSSL* ssl, ecc_key* key, ecc_key* peer);
#endif

WOLFSSL_LOCAL int BuildMessage(WOLFSSL* ssl, byte* output, int outSz,
                        const byte* input, int inSz, int type, int hashOutput,
                        int sizeOnly);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* wolfSSL_INT_H */
