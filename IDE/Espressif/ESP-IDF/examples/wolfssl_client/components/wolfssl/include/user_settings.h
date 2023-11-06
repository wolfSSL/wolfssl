/* user_settings.h
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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

/* This is the user_settings.h file for the wolfssl_client TLS example.
 * For application-specific settings, please see client-tls.h file */

#include <sdkconfig.h> /* essential to chip set detection */

/* optional timezone used when setting time */
#define TIME_ZONE "PST+8PDT,M3.2.0,M11.1.0"

/* #define SHOW_SSID_AND_PASSWORD */ /* remove this to not show in startup log */

#undef WOLFSSL_ESPIDF
#undef WOLFSSL_ESP32
#undef WOLFSSL_ESPWROOM32SE
#undef WOLFSSL_ESP32
#undef WOLFSSL_ESP8266

/* The Espressif sdkconfig will have chipset info.
**
** Possible values:
**
**   CONFIG_IDF_TARGET_ESP32
**   CONFIG_IDF_TARGET_ESP32S2
**   CONFIG_IDF_TARGET_ESP32S3
**   CONFIG_IDF_TARGET_ESP32C3
**   CONFIG_IDF_TARGET_ESP32C6
*/

#define WOLFSSL_ESPIDF

/*
 * choose ONE of these Espressif chips to define:
 *
 * WOLFSSL_ESP32
 * WOLFSSL_ESPWROOM32SE
 * WOLFSSL_ESP8266
 */

#define WOLFSSL_ESP32

#if defined(CONFIG_IDF_TARGET_ESP32)
    /* HW Enabled by default for ESP32. To disable: */
    /* #define NO_ESP32_CRYPT                 */
    /* #define NO_WOLFSSL_ESP32_CRYPT_HASH    */
    /* #define NO_WOLFSSL_ESP32_CRYPT_AES     */
    /* #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI */
#elif defined(CONFIG_IDF_TARGET_ESP32S2)
    /* HW Disabled by default for ESP32-S2.   */
    #define NO_ESP32_CRYPT
    #define NO_WOLFSSL_ESP32_CRYPT_HASH
    #define NO_WOLFSSL_ESP32_CRYPT_AES
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI
#elif defined(CONFIG_IDF_TARGET_ESP32S3)
    /* HW Enabled by default for ESP32. To disable: */
    /* #define NO_ESP32_CRYPT                 */
    /* #define NO_WOLFSSL_ESP32_CRYPT_HASH    */
    /* #define NO_WOLFSSL_ESP32_CRYPT_AES     */
    /* #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI */
#elif defined(CONFIG_IDF_TARGET_ESP32C2)
    #define NO_ESP32_CRYPT
    #define NO_WOLFSSL_ESP32_CRYPT_HASH
    #define NO_WOLFSSL_ESP32_CRYPT_AES
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI
#elif defined(CONFIG_IDF_TARGET_ESP32C3)
    /* HW Disabled by default for ESP32-C3.   */
    #define NO_ESP32_CRYPT
    #define NO_WOLFSSL_ESP32_CRYPT_HASH
    #define NO_WOLFSSL_ESP32_CRYPT_AES
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI
#elif defined(CONFIG_IDF_TARGET_ESP32C6)
    /* HW Disabled by default for ESP32-C6.   */
    #define NO_ESP32_CRYPT
    #define NO_WOLFSSL_ESP32_CRYPT_HASH
    #define NO_WOLFSSL_ESP32_CRYPT_AES
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI
#elif defined(CONFIG_IDF_TARGET_ESP32H2)
    /* HW Disabled by default for ESP32-H2.   */
    #define NO_ESP32_CRYPT
    #define NO_WOLFSSL_ESP32_CRYPT_HASH
    #define NO_WOLFSSL_ESP32_CRYPT_AES
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI
#else
    /* HW Disabled by default for all other ESP32-[?].  */
    #define NO_ESP32_CRYPT
    #define NO_WOLFSSL_ESP32_CRYPT_HASH
    #define NO_WOLFSSL_ESP32_CRYPT_AES
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI
#endif


/* optionally turn off SHA512/224 SHA512/256 */
/* #define WOLFSSL_NOSHA512_224 */
/* #define WOLFSSL_NOSHA512_256 */

#define BENCH_EMBEDDED

/* TLS 1.3                                 */
#define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define WC_RSA_PSS
#define HAVE_HKDF
#define HAVE_AEAD
#define HAVE_SUPPORTED_CURVES

#define WOLFSSL_BENCHMARK_FIXED_UNITS_KB

/* when you want to use SINGLE THREAD */
/* #define SINGLE_THREADED */
#define NO_FILESYSTEM

#define HAVE_AESGCM

#define WOLFSSL_RIPEMD
/* when you want to use SHA224 */
/* #define WOLFSSL_SHA224      */

#define NO_OLD_TLS

/* when you want to use SHA384 */
/* #define WOLFSSL_SHA384 */

/* #define WOLFSSL_SHA3 */

#define WOLFSSL_SHA512
#define HAVE_ECC
#define HAVE_CURVE25519
#define CURVE25519_SMALL
#define HAVE_ED25519

/* when you want to use pkcs7 */
/* #define HAVE_PKCS7 */

#if defined(HAVE_PKCS7)
    #define HAVE_AES_KEYWRAP
    #define HAVE_X963_KDF
    #define WOLFSSL_AES_DIRECT
#endif

/* optional DH */
/* #define PROJECT_DH */
#ifdef PROJECT_DH
    #define HAVE_DH
    #define HAVE_FFDHE_2048
#endif

/* when you want to use aes counter mode */
/* #define WOLFSSL_AES_DIRECT */
/* #define WOLFSSL_AES_COUNTER */

/* esp32-wroom-32se specific definition */
#if defined(WOLFSSL_ESPWROOM32SE)
    #define WOLFSSL_ATECC508A
    #define HAVE_PK_CALLBACKS
    /* when you want to use a custom slot allocation for ATECC608A */
    /* unless your configuration is unusual, you can use default   */
    /* implementation.                                             */
    /* #define CUSTOM_SLOT_ALLOCATION                              */
#endif

/* RSA primitive specific definition */
#if defined(WOLFSSL_ESP32) || defined(WOLFSSL_ESPWROOM32SE)
    /* Define USE_FAST_MATH and SMALL_STACK                        */
    #define ESP32_USE_RSA_PRIMITIVE
    /* threshold for performance adjustment for HW primitive use   */
    /* X bits of G^X mod P greater than                            */
    #define EPS_RSA_EXPT_XBTIS           36
    /* X and Y of X * Y mod P greater than                         */
    #define ESP_RSA_MULM_BITS            36
#endif
#define RSA_LOW_MEM

/* debug options */
/* #define DEBUG_WOLFSSL */
/* #define WOLFSSL_ESP32_CRYPT_DEBUG */
/* #define WOLFSSL_ESP32_HW_LOCK_DEBUG */
/* #define WOLFSSL_ATECC508A_DEBUG          */

/* date/time                               */
/* if it cannot adjust time in the device, */
/* enable macro below                      */
/* #define NO_ASN_TIME */
/* #define XTIME time */

/* adjust wait-timeout count if you see timeout in RSA HW acceleration */
#define ESP_RSA_TIMEOUT_CNT    0x249F00

/* see esp_ShowExtendedSystemInfo in esp32-crypt.h for startup log info */
#define HAVE_VERSION_EXTENDED_INFO


/* debug options */
/* #define ESP_VERIFY_MEMBLOCK              */
#define WOLFSSL_HW_METRICS
/* #define DEBUG_WOLFSSL_VERBOSE            */
/* #define DEBUG_WOLFSSL                    */
/* #define WOLFSSL_ESP32_CRYPT_DEBUG        */
#define NO_RECOVER_SOFTWARE_CALC

/* optionally turn off individual math HW acceleration features */

/* Turn off Large Number Multiplication:
** [Z = X * Y] in esp_mp_mul()                                  */
/* #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL         */

/* Turn off Large Number Modular Exponentiation:
** [Z = X^Y mod M] in esp_mp_exptmod()                          */
/* #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD        */

/* Turn off Large Number Modular Multiplication
** [Z = X × Y mod M] in esp_mp_mulmod()                         */
/* #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD         */


/* this is known to fail in TFM: */
/* #define HONOR_MATH_USED_LENGTH */

/* this is known to fail in TFM */
/* #define CHECK_MP_READ_UNSIGNED_BIN */

#define WOLFSSL_PUBLIC_MP /* used by benchmark */

/* optional SM4 Ciphers. See https://github.com/wolfSSL/wolfsm */
/* Uncomment this section to enable SM
#define WOLFSSL_SM2
#define WOLFSSL_SM3
#define WOLFSSL_SM4
*/

#if defined(WOLFSSL_SM2) || defined(WOLFSSL_SM3) || defined(WOLFSSL_SM4)
    /* see https://github.com/wolfSSL/wolfssl/pull/6537
     *
     * see settings.h for other features turned on with SM4 ciphers.
     */
    #undef  USE_CERT_BUFFERS_1024
    #define USE_CERT_BUFFERS_1024

    #undef  WOLFSSL_SM4_ECB
    #define WOLFSSL_SM4_ECB

    #undef  WOLFSSL_SM4_CBC
    #define WOLFSSL_SM4_CBC

    #undef  WOLFSSL_SM4_CTR
    #define WOLFSSL_SM4_CTR

    #undef  WOLFSSL_SM4_GCM
    #define WOLFSSL_SM4_GCM

    #undef  WOLFSSL_SM4_CCM
    #define WOLFSSL_SM4_CCM

    #define HAVE_POLY1305
    #define HAVE_CHACHA

    #undef  HAVE_AESGCM
    #define HAVE_AESGCM

    #undef  HAVE_ECC
    #define HAVE_ECC

    /* see https://github.com/wolfSSL/wolfssl/pull/6825 */
    #include <wolfssl/certs_test_sm.h>

    #define CTX_CA_CERT          root_sm2
    #define CTX_CA_CERT_SIZE     sizeof_root_sm2
    #define CTX_CA_CERT_TYPE     WOLFSSL_FILETYPE_PEM
    #define CTX_SERVER_CERT      server_sm2
    #define CTX_SERVER_CERT_SIZE sizeof_server_sm2
    #define CTX_SERVER_CERT_TYPE WOLFSSL_FILETYPE_PEM
    #define CTX_SERVER_KEY       server_sm2_priv
    #define CTX_SERVER_KEY_SIZE  sizeof_server_sm2_priv
    #define CTX_SERVER_KEY_TYPE  WOLFSSL_FILETYPE_PEM
/*
 * SM optional cipher suite settings:
 *
    #define WOLFSSL_ESP32_CIPHER_SUITE "TLS13-SM4-GCM-SM3"
    #define WOLFSSL_ESP32_CIPHER_SUITE "TLS13-SM4-CCM-SM3"
    #define WOLFSSL_ESP32_CIPHER_SUITE "ECDHE-ECDSA-SM4-CBC-SM3"
    #define WOLFSSL_ESP32_CIPHER_SUITE "ECDHE-ECDSA-SM4-GCM-SM3"
    #define WOLFSSL_ESP32_CIPHER_SUITE "ECDHE-ECDSA-SM4-CCM-SM3"
*/
    #define WOLFSSL_ESP32_CIPHER_SUITE "TLS13-SM4-GCM-SM3:" \
                                       "TLS13-SM4-CCM-SM3:" \
                                       "TLS-SM4-GCM-SM3:" /* not a valid command-line cipher */ \
                                       "TLS-SM4-CCM-SM3:" /* not a valid command-line cipher */ \
                                       "ECDHE-ECDSA-SM4-CBC-SM3:" \
                                       "ECDHE-ECDSA-SM4-GCM-SM3:" \
                                       "ECDHE-ECDSA-SM4-CCM-SM3"

#else
    /* default settings */
    #define USE_CERT_BUFFERS_2048
    #define USE_CERT_BUFFERS_256
    #define CTX_CA_CERT          ca_cert_der_2048
    #define CTX_CA_CERT_SIZE     sizeof_ca_cert_der_2048
    #define CTX_CA_CERT_TYPE     WOLFSSL_FILETYPE_ASN1
    #define CTX_SERVER_CERT      server_cert_der_2048
    #define CTX_SERVER_CERT_SIZE sizeof_server_cert_der_2048
    #define CTX_SERVER_CERT_TYPE WOLFSSL_FILETYPE_ASN1
    #define CTX_SERVER_KEY       server_key_der_2048
    #define CTX_SERVER_KEY_SIZE  sizeof_server_key_der_2048
    #define CTX_SERVER_KEY_TYPE  WOLFSSL_FILETYPE_ASN1
/*
 * Optional Cipher Suite Specification
 *
 * nothing defined, default used = "TLS13-AES128-GCM-SHA256"
 #define WOLFSSL_ESP32_CIPHER_SUITE "ECDHE-ECDSA-SM4-CBC-SM3"
 #define WOLFSSL_ESP32_CIPHER_SUITE "ECDHE-ECDSA-SM4-CBC-SM3:"
 #define WOLFSSL_ESP32_CIPHER_SUITE "TLS13-AES128-GCM-SHA256"
 #define WOLFSSL_ESP32_CIPHER_SUITE "TLS13-AES128-GCM-SHA256:"
 #define WOLFSSL_ESP32_CIPHER_SUITE "TLS13-AES128-GCM-SHA256:DHE-PSK-AES128-GCM-SHA256"
 #define WOLFSSL_ESP32_CIPHER_SUITE "TLS13-AES128-GCM-SHA256:PSK-AES128-GCM-SHA256:"
 #define WOLFSSL_ESP32_CIPHER_SUITE "TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES128-GCM-SHA256:TLS13-AES256-GCM-SHA384:"
 #define WOLFSSL_ESP32_CIPHER_SUITE "TLS13-CHACHA20-POLY1305-SHA256"
 #define WOLFSSL_ESP32_CIPHER_SUITE "TLS_CHACHA20_POLY1305_SHA256"
 #define WOLFSSL_ESP32_CIPHER_SUITE "TLS_SM4_CCM_SM3"
*/
#endif

    #undef  HAVE_ECC
    #define HAVE_ECC

    #undef  HAVE_SUPPORTED_CURVES
    #define HAVE_SUPPORTED_CURVES

/* Optionally include alternate HW test library: alt_hw_test.h */
/* When enabling, the ./components/wolfssl/CMakeLists.txt file
 * will need the name of the library in the idf_component_register
 * for the PRIV_REQUIRES list. */
/* #define INCLUDE_ALT_HW_TEST */

/* #define NO_HW_MATH_TEST */


/* when turning on ECC508 / ECC608 support
#define WOLFSSL_ESPWROOM32SE
#define HAVE_PK_CALLBACKS
#define WOLFSSL_ATECC508A
#define ATCA_WOLFSSL
*/

/* USE_FAST_MATH is default */
#define USE_FAST_MATH

/* use SP_MATH */
/*
#undef USE_FAST_MATH
#define WOLFSSL_SP_MATH_ALL
*/

/* use integer heap math */
/*
#undef USE_FAST_MATH
#define USE_INTEGER_HEAP_MATH
*/

/* optionally use DPORT_ACCESS_READ_BUFFER */
/*
#define USE_ESP_DPORT_ACCESS_READ_BUFFER
*/
