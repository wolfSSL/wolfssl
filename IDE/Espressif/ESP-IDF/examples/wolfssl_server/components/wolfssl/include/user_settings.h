/* user_settings.h
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

/* Standardized wolfSSL Espressif ESP32 + ESP8266 user_settings.h V5.6.6-01 */

/* This user_settings.h is for Espressif ESP-IDF */

#include "sdkconfig.h"

#define DEBUG_WOLFSSL
/* #define DEBUG_WOLFSSL_VERBOSE */

/* Experimental Kyber */
#if 0
    #define WOLFSSL_EXPERIMENTAL_SETTINGS
    #define WOLFSSL_HAVE_KYBER
    #define WOLFSSL_WC_KYBER
    #define WOLFSSL_SHA3
    #if defined(CONFIG_IDF_TARGET_ESP8266)
        /* With limited RAM, we'll disable some of the Kyber sizes: */
        #define WOLFSSL_NO_KYBER1024
        #define WOLFSSL_NO_KYBER768
    #endif
#endif

/* Pick a cert buffer size: */
/* #define USE_CERT_BUFFERS_2048 */
/* #define USE_CERT_BUFFERS_1024 */
#define USE_CERT_BUFFERS_2048

/* The Espressif sdkconfig will have chipset info.
**
** Some possible values:
**
**   CONFIG_IDF_TARGET_ESP32
**   CONFIG_IDF_TARGET_ESP32S2
**   CONFIG_IDF_TARGET_ESP32S3
**   CONFIG_IDF_TARGET_ESP32C3
**   CONFIG_IDF_TARGET_ESP32C6
*/

#undef  WOLFSSL_ESPIDF
#define WOLFSSL_ESPIDF

/* We don't use WiFi helpers yet, so don't compile in the esp-sdk-lib WiFi */
#define NO_ESP_SDK_WIFI

/*
 * ONE of these Espressif chipsets should be defined:
 *
 * WOLFSSL_ESP32
 * WOLFSSL_ESPWROOM32SE
 * WOLFSSL_ESP8266
 *
 * following ifdef detection only for syntax highlighting:
 */
#ifdef WOLFSSL_ESPWROOM32SE
    #undef WOLFSSL_ESPWROOM32SE
#endif
#ifdef WOLFSSL_ESP8266
    #undef WOLFSSL_ESP8266
#endif
#ifdef WOLFSSL_ESP32
    #undef WOLFSSL_ESP32
#endif
/* See below for chipset detection from sdkconfig.h */

/* Small session cache saves a lot of RAM for ClientCache and SessionCache.
 * Memory requirement is about 5KB, otherwise 20K is needed when not specified.
 * If extra small footprint is needed, try MICRO_SESSION_CACHE (< 1K)
 * When really desperate, try NO_SESSION_CACHE.  */
#define MICRO_SESSION_CACHE

/* optionally turn off SHA512/224 SHA512/256 */
/* #define WOLFSSL_NOSHA512_224 */
/* #define WOLFSSL_NOSHA512_256 */

/* when you want to use SINGLE THREAD. Note Default ESP-IDF is FreeRTOS */
/* #define SINGLE_THREADED */

/* When you don't want to use the old SHA */
/* #define NO_SHA */
/* #define NO_OLD_TLS */

#define BENCH_EMBEDDED

#define WOLFSSL_SMALL_STACK
#define HAVE_ECC
#define RSA_LOW_MEM

/* TLS 1.3                                 */
#define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define WC_RSA_PSS
#define HAVE_HKDF
#define HAVE_AEAD
#define HAVE_SUPPORTED_CURVES

#define WOLFSSL_BENCHMARK_FIXED_UNITS_KB

#define NO_FILESYSTEM

#define NO_OLD_TLS

#define HAVE_AESGCM

/* Optional RIPEMD: RACE Integrity Primitives Evaluation Message Digest */
/* #define WOLFSSL_RIPEMD */

/* when you want to use SHA224 */
#define WOLFSSL_SHA224

/* when you want to use SHA384 */
#define WOLFSSL_SHA384

#if defined(CONFIG_IDF_TARGET_ESP8266)
	/* Some known low-memory devices have features not enabled by default. */
#else
    /* when you want to use SHA512 */
    #define WOLFSSL_SHA512

    /* when you want to use SHA3 */
    #define WOLFSSL_SHA3

	/* ED25519 requires SHA512 */
    #define HAVE_ED25519

    #define HAVE_ECC
    #define HAVE_CURVE25519
    #define CURVE25519_SMALL
    #define HAVE_ED25519
#endif

/* Optional OpenSSL compatibility */
/* #define OPENSSL_EXTRA */

/* when you want to use pkcs7 */
/* #define HAVE_PKCS7 */
#if defined(HAVE_PKCS7)
    #define HAVE_AES_KEYWRAP
    #define HAVE_X963_KDF
    #define WOLFSSL_AES_DIRECT
#endif

/* when you want to use AES counter mode */
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

    #if defined(CONFIG_IDF_TARGET_ESP32)

        /* NOTE HW unreliable for small values! */
        /* threshold for performance adjustment for HW primitive use   */
        /* X bits of G^X mod P greater than                            */
        #undef  ESP_RSA_EXPT_XBITS
        #define ESP_RSA_EXPT_XBITS 32

        /* X and Y of X * Y mod P greater than                         */
        #undef  ESP_RSA_MULM_BITS
        #define ESP_RSA_MULM_BITS  16

    #endif
#endif

/* #define WOLFSSL_ATECC508A_DEBUG         */

/* date/time                               */
/* if it cannot adjust time in the device, */
/* enable macro below                      */
/* #define NO_ASN_TIME */
/* #define XTIME time */


/* adjust wait-timeout count if you see timeout in RSA HW acceleration */
#define ESP_RSA_TIMEOUT_CNT    0x249F00

#define HASH_SIZE_LIMIT /* for test.c */

/* USE_FAST_MATH is default */
#define USE_FAST_MATH

/*****      Use SP_MATH      *****/
/* #undef USE_FAST_MATH          */
/* #define SP_MATH               */
/* #define WOLFSSL_SP_MATH_ALL   */

/***** Use Integer Heap Math *****/
/* #undef USE_FAST_MATH          */
/* #define USE_INTEGER_HEAP_MATH */

#define HAVE_VERSION_EXTENDED_INFO
/* #define HAVE_WC_INTROSPECTION */

#define  HAVE_SESSION_TICKET

/* #define HAVE_HASHDRBG */

#define WOLFSSL_KEY_GEN
#define WOLFSSL_CERT_REQ
#define WOLFSSL_CERT_GEN
#define WOLFSSL_CERT_EXT
#define WOLFSSL_SYS_CA_CERTS

#define WOLFSSL_CERT_TEXT

#define WOLFSSL_ASN_TEMPLATE

/*
#undef  WOLFSSL_KEY_GEN
#undef  WOLFSSL_CERT_REQ
#undef  WOLFSSL_CERT_GEN
#undef  WOLFSSL_CERT_EXT
#undef  WOLFSSL_SYS_CA_CERTS
*/

/* command-line options
--enable-keygen
--enable-certgen
--enable-certreq
--enable-certext
--enable-asn-template
*/

/* Chipset detection from sdkconfig.h
 * Default is HW enabled unless turned off.
 * Uncomment lines to force SW instead of HW acceleration */
#if defined(CONFIG_IDF_TARGET_ESP32)
    #define WOLFSSL_ESP32
    /* wolfSSL HW Acceleration supported on ESP32. Uncomment to disable: */
    /*  #define NO_ESP32_CRYPT                 */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_HASH    */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_AES     */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL  */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD  */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD */

    /*  These are defined automatically in esp32-crypt.h, here for clarity:  */
    #define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA224 /* no SHA224 HW on ESP32  */

    #undef  ESP_RSA_MULM_BITS
    #define ESP_RSA_MULM_BITS 16 /* TODO add compile-time warning */
    /***** END CONFIG_IDF_TARGET_ESP32 *****/

#elif defined(CONFIG_IDF_TARGET_ESP32S2)
    #define WOLFSSL_ESP32
    /* wolfSSL HW Acceleration supported on ESP32-S2. Uncomment to disable: */
    /*  #define NO_ESP32_CRYPT                 */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_HASH    */
    /* Note: There's no AES192 HW on the ESP32-S2; falls back to SW */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_AES     */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL  */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD  */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD */
    /***** END CONFIG_IDF_TARGET_ESP32S2 *****/

#elif defined(CONFIG_IDF_TARGET_ESP32S3)
    #define WOLFSSL_ESP32
    /* wolfSSL HW Acceleration supported on ESP32-S3. Uncomment to disable: */
    /*  #define NO_ESP32_CRYPT                         */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_HASH            */
    /* Note: There's no AES192 HW on the ESP32-S3; falls back to SW */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_AES             */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI         */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL  */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD  */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD */
    /***** END CONFIG_IDF_TARGET_ESP32S3 *****/

#elif defined(CONFIG_IDF_TARGET_ESP32C2) || \
      defined(CONFIG_IDF_TARGET_ESP8684)
    #define WOLFSSL_ESP32
    /* ESP8684 is essentially ESP32-C2 chip + flash embedded together in a
     * single QFN 4x4 mm package. Out of released documentation, Technical
     * Reference Manual as well as ESP-IDF Programming Guide is applicable
     * to both ESP32-C2 and ESP8684.
     *
     * See: https://www.esp32.com/viewtopic.php?f=5&t=27926#:~:text=ESP8684%20is%20essentially%20ESP32%2DC2,both%20ESP32%2DC2%20and%20ESP8684. */

    /* wolfSSL HW Acceleration supported on ESP32-C2. Uncomment to disable: */
    /*  #define NO_ESP32_CRYPT                 */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_HASH    */ /* to disable all SHA HW   */

    /* These are defined automatically in esp32-crypt.h, here for clarity    */
    #define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA384    /* no SHA384 HW on C2  */
    #define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512    /* no SHA512 HW on C2  */

    /* There's no AES or RSA/Math accelerator on the ESP32-C2
     * Auto defined with NO_WOLFSSL_ESP32_CRYPT_RSA_PRI, for clarity: */
    #define NO_WOLFSSL_ESP32_CRYPT_AES
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD
    /***** END CONFIG_IDF_TARGET_ESP32C2 *****/

#elif defined(CONFIG_IDF_TARGET_ESP32C3)
    #define WOLFSSL_ESP32
    /* wolfSSL HW Acceleration supported on ESP32-C3. Uncomment to disable: */

    /*  #define NO_ESP32_CRYPT                 */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_HASH    */ /* to disable all SHA HW   */

    /* These are defined automatically in esp32-crypt.h, here for clarity:  */
    #define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA384    /* no SHA384 HW on C6  */
    #define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512    /* no SHA512 HW on C6  */

    /*  #define NO_WOLFSSL_ESP32_CRYPT_AES             */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI         */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL  */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD  */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD */
    /***** END CONFIG_IDF_TARGET_ESP32C3 *****/

#elif defined(CONFIG_IDF_TARGET_ESP32C6)
    #define WOLFSSL_ESP32
    /* wolfSSL HW Acceleration supported on ESP32-C6. Uncomment to disable: */

    /*  #define NO_ESP32_CRYPT                 */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_HASH    */
    /*  These are defined automatically in esp32-crypt.h, here for clarity:  */
    #define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA384    /* no SHA384 HW on C6  */
    #define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512    /* no SHA512 HW on C6  */

    /*  #define NO_WOLFSSL_ESP32_CRYPT_AES             */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI         */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL  */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD  */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD */
    /***** END CONFIG_IDF_TARGET_ESP32C6 *****/

#elif defined(CONFIG_IDF_TARGET_ESP32H2)
    #define WOLFSSL_ESP32
    /*  wolfSSL Hardware Acceleration not yet implemented */
    #define NO_ESP32_CRYPT
    #define NO_WOLFSSL_ESP32_CRYPT_HASH
    #define NO_WOLFSSL_ESP32_CRYPT_AES
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI
    /***** END CONFIG_IDF_TARGET_ESP32H2 *****/

#elif defined(CONFIG_IDF_TARGET_ESP8266)
    #define WOLFSSL_ESP8266

    /* There's no hardware encryption on the ESP8266 */
    /* Consider using the ESP32-C2/C3/C6
     * See https://www.espressif.com/en/products/socs/esp32-c2 */
    #define NO_ESP32_CRYPT
    #define NO_WOLFSSL_ESP32_CRYPT_HASH
    #define NO_WOLFSSL_ESP32_CRYPT_AES
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI
    /***** END CONFIG_IDF_TARGET_ESP266 *****/

#elif defined(CONFIG_IDF_TARGET_ESP8684)
    /*  There's no Hardware Acceleration available on ESP8684 */
    #define NO_ESP32_CRYPT
    #define NO_WOLFSSL_ESP32_CRYPT_HASH
    #define NO_WOLFSSL_ESP32_CRYPT_AES
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI
    /***** END CONFIG_IDF_TARGET_ESP8684 *****/

#else
    /* Anything else encountered, disable HW accleration */
    #warning "Unexpected CONFIG_IDF_TARGET_NN value"
    #define NO_ESP32_CRYPT
    #define NO_WOLFSSL_ESP32_CRYPT_HASH
    #define NO_WOLFSSL_ESP32_CRYPT_AES
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI
#endif /* CONFIG_IDF_TARGET Check */

/* Debug options:
See wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h for details on debug options

#define ESP_VERIFY_MEMBLOCK
#define DEBUG_WOLFSSL
#define DEBUG_WOLFSSL_VERBOSE
#define DEBUG_WOLFSSL_SHA_MUTEX
#define WOLFSSL_ESP32_CRYPT_DEBUG
#define WOLFSSL_ESP32_CRYPT_HASH_SHA224_DEBUG
#define NO_RECOVER_SOFTWARE_CALC
#define WOLFSSL_TEST_STRAY 1
#define USE_ESP_DPORT_ACCESS_READ_BUFFER
#define WOLFSSL_ESP32_HW_LOCK_DEBUG
#define WOLFSSL_DEBUG_ESP_RSA_MULM_BITS
#define ESP_DISABLE_HW_TASK_LOCK
*/

#define WOLFSSL_ESPIDF_ERROR_PAUSE /* Pause in a loop rather than exit. */
#define WOLFSSL_HW_METRICS

/* #define HASH_SIZE_LIMIT */ /* for test.c */

/* #define NO_HW_MATH_TEST */ /* Optionally turn off HW math checks */

/* Optionally include alternate HW test library: alt_hw_test.h */
/* When enabling, the ./components/wolfssl/CMakeLists.txt file
 * will need the name of the library in the idf_component_register
 * for the PRIV_REQUIRES list. */
/* #define INCLUDE_ALT_HW_TEST */

/* optionally turn off individual math HW acceleration features */

/* Turn off Large Number ESP32 HW Multiplication:
** [Z = X * Y] in esp_mp_mul()                                  */
/* #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL                */

/* Turn off Large Number ESP32 HW Modular Exponentiation:
** [Z = X^Y mod M] in esp_mp_exptmod()                          */
/* #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD               */

/* Turn off Large Number ESP32 HW Modular Multiplication
** [Z = X * Y mod M] in esp_mp_mulmod()                         */
/* #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD                */


/* used by benchmark: */
#define WOLFSSL_PUBLIC_MP

/* when turning on ECC508 / ECC608 support
#define WOLFSSL_ESPWROOM32SE
#define HAVE_PK_CALLBACKS
#define WOLFSSL_ATECC508A
#define ATCA_WOLFSSL
*/

/***************************** Certificate Macros *****************************
 *
 * The section below defines macros used in typically all of the wolfSSL
 * examples such as the client and server for certs stored in header files.
 *
 * There are various certificate examples in this header file:
 * https://github.com/wolfSSL/wolfssl/blob/master/wolfssl/certs_test.h
 *
 * To use the sets of macros below, define *one* of these:
 *
 *    USE_CERT_BUFFERS_1024  - ECC 1024 bit encoded ASN1
 *    USE_CERT_BUFFERS_2048  - RSA 2048 bit encoded ASN1
 *    WOLFSSL_SM[2,3,4]      - SM Ciphers
 *
 * For example: define USE_CERT_BUFFERS_2048 to use CA Certs used in this
 *  wolfSSL function for the `ca_cert_der_2048` buffer, size and types:
 *
 *     ret = wolfSSL_CTX_load_verify_buffer(ctx,
 *                                          CTX_CA_CERT,
 *                                          CTX_CA_CERT_SIZE,
 *                                          CTX_CA_CERT_TYPE);
 *
 * See https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_load_verify_buffer
 *
 * In this case the CTX_CA_CERT will be defined as `ca_cert_der_2048` as
 * defined here: https://github.com/wolfSSL/wolfssl/blob/master/wolfssl/certs_test.h
 *
 * The CTX_CA_CERT_SIZE and CTX_CA_CERT_TYPE are similarly used to reference
 * array size and cert type respectively.
 *
 * Similarly for loading the private client key:
 *
 *  ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx,
 *                                          CTX_CLIENT_KEY,
 *                                          CTX_CLIENT_KEY_SIZE,
 *                                          CTX_CLIENT_KEY_TYPE);
 *
 * see https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_use_privatekey_buffer
 *
 * Similarly, the other macros are for server certificates and keys:
 *   `CTX_SERVER_CERT` and `CTX_SERVER_KEY` are available.
 *
 * The certificate and key names are typically `static const unsigned char`
 * arrays. The [NAME]_size are typically `sizeof([array name])`, and the types
 * are the known wolfSSL encoding type integers (e.g. WOLFSSL_FILETYPE_PEM).
 *
 * See `SSL_FILETYPE_[name]` in
 *   https://github.com/wolfSSL/wolfssl/blob/master/wolfssl/ssl.h
 *
 * See Abstract Syntax Notation One (ASN.1) in:
 *   https://github.com/wolfSSL/wolfssl/blob/master/wolfssl/wolfcrypt/asn.h
 *
 * Optional SM4 Ciphers:
 *
 * Although the SM ciphers are shown here, the `certs_test_sm.h` may not yet
 * be available. See:
 *   https://github.com/wolfSSL/wolfssl/pull/6825
 *   https://github.com/wolfSSL/wolfsm
 *
 * Uncomment these 3 macros to enable the SM Ciphers and use the macros below.
 */

/*
#define WOLFSSL_SM2
#define WOLFSSL_SM3
#define WOLFSSL_SM4
*/

/* Conditional macros used in wolfSSL TLS client and server examples */
#if defined(WOLFSSL_SM2) || defined(WOLFSSL_SM3) || defined(WOLFSSL_SM4)
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

    #undef  WOLFSSL_BASE16
    #define WOLFSSL_BASE16
#else
    #if defined(USE_CERT_BUFFERS_2048)
        #define CTX_CA_CERT          ca_cert_der_2048
        #define CTX_CA_CERT_SIZE     sizeof_ca_cert_der_2048
        #define CTX_CA_CERT_TYPE     WOLFSSL_FILETYPE_ASN1

        #define CTX_SERVER_CERT      server_cert_der_2048
        #define CTX_SERVER_CERT_SIZE sizeof_server_cert_der_2048
        #define CTX_SERVER_CERT_TYPE WOLFSSL_FILETYPE_ASN1
        #define CTX_SERVER_KEY       server_key_der_2048
        #define CTX_SERVER_KEY_SIZE  sizeof_server_key_der_2048
        #define CTX_SERVER_KEY_TYPE  WOLFSSL_FILETYPE_ASN1

        #define CTX_CLIENT_CERT      client_cert_der_2048
        #define CTX_CLIENT_CERT_SIZE sizeof_client_cert_der_2048
        #define CTX_CLIENT_CERT_TYPE WOLFSSL_FILETYPE_ASN1
        #define CTX_CLIENT_KEY       client_key_der_2048
        #define CTX_CLIENT_KEY_SIZE  sizeof_client_key_der_2048
        #define CTX_CLIENT_KEY_TYPE  WOLFSSL_FILETYPE_ASN1

    #elif defined(USE_CERT_BUFFERS_1024)
        #define CTX_CA_CERT          ca_cert_der_1024
        #define CTX_CA_CERT_SIZE     sizeof_ca_cert_der_1024
        #define CTX_CA_CERT_TYPE     WOLFSSL_FILETYPE_ASN1

        #define CTX_CLIENT_CERT      client_cert_der_1024
        #define CTX_CLIENT_CERT_SIZE sizeof_client_cert_der_1024
        #define CTX_CLIENT_CERT_TYPE WOLFSSL_FILETYPE_ASN1
        #define CTX_CLIENT_KEY       client_key_der_1024
        #define CTX_CLIENT_KEY_SIZE  sizeof_client_key_der_1024
        #define CTX_CLIENT_KEY_TYPE  WOLFSSL_FILETYPE_ASN1

        #define CTX_SERVER_CERT      server_cert_der_1024
        #define CTX_SERVER_CERT_SIZE sizeof_server_cert_der_1024
        #define CTX_SERVER_CERT_TYPE WOLFSSL_FILETYPE_ASN1
        #define CTX_SERVER_KEY       server_key_der_1024
        #define CTX_SERVER_KEY_SIZE  sizeof_server_key_der_1024
        #define CTX_SERVER_KEY_TYPE  WOLFSSL_FILETYPE_ASN1
    #else
        /* Optionally define custom cert arrays, sizes, and types here */
        #error "Must define USE_CERT_BUFFERS_2048 or USE_CERT_BUFFERS_1024"
    #endif
#endif /* Conditional key and cert constant names */
