/* wolfssl-component include/user_settings.h
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
#define WOLFSSL_ESPIDF_COMPONENT_VERSION 0x01

/* The Espressif project config file. See also sdkconfig.defaults */
#include "sdkconfig.h"

/* This user_settings.h is for Espressif ESP-IDF
 *
 * Standardized wolfSSL Espressif ESP32 + ESP8266 user_settings.h V5.7.0-1
 *
 * Do not include any wolfssl headers here.
 *
 * When editing this file:
 * ensure all examples match. The template example is the reference.
 */

/* Naming convention: (see also esp32-crypt.h for the reference source).
 *
 * CONFIG_
 *      This prefix indicates the setting came from the sdkconfig / Kconfig.
 *
 *      May or may not be related to wolfSSL.
 *
 *      The name after this prefix must exactly match that in the Kconfig file.
 *
 * WOLFSSL_
 *      Typical of many, but not all wolfSSL macro names.
 *
 *      Applies to all wolfSSL products such as wolfSSH, wolfMQTT, etc.
 *
 *      May or may not have a corresponding sdkconfig / Kconfig control.
 *
 * ESP_WOLFSSL_
 *      These are NOT valid wolfSSL macro names. These are names only used in
 *      the ESP-IDF Kconfig files. When parsed, they will have a "CONFIG_"
 *      suffix added. See next section.
 *
 * CONFIG_ESP_WOLFSSL_
 *      This is a wolfSSL-specific macro that has been defined in the ESP-IDF
 *      via the sdkconfig / menuconfig. Any text after this prefix should
 *      exactly match an existing wolfSSL macro name.
 *
 *      Applies to all wolfSSL products such as wolfSSH, wolfMQTT, etc.
 *
 *      These macros may also be specific to only the project or environment,
 *      and possibly not used anywhere else in the wolfSSL libraries.
 */

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

/* Test various user_settings between applications by selecting example apps
 * in `idf.py menuconfig` for Example wolfSSL Configuration settings: */

/* Turn on messages that are useful to see only in examples. */
#define WOLFSSL_EXAMPLE_VERBOSITY

/* Paths can be long, ensure the entire value printed during debug */
#define WOLFSSL_MAX_ERROR_SZ 500

/* wolfSSL Examples: set macros used in example applications.
 *
 * These Settings NOT available in ESP-IDF (e.g. esp-tls)
 *
 * Any settings needed by ESP-IDF components should be explicitly set,
 * and not by these example-specific settings via CONFIG_WOLFSSL_EXAMPLE_n
 *
 * ESP-IDF settings should be Kconfig "CONFIG_[name]" values when possible. */
#if defined(CONFIG_WOLFSSL_EXAMPLE_NAME_TEMPLATE)
    /* See https://github.com/wolfSSL/wolfssl/tree/master/IDE/Espressif/ESP-IDF/examples/template */
    /* We don't use WiFi, so don't compile in the esp-sdk-lib WiFi helpers: */
    /* #define USE_WOLFSSL_ESP_SDK_WIFI */
#elif defined(CONFIG_WOLFSSL_EXAMPLE_NAME_TEST)
    /* See https://github.com/wolfSSL/wolfssl/tree/master/IDE/Espressif/ESP-IDF/examples/wolfssl_test */
    /* We don't use WiFi, so don't compile in the esp-sdk-lib WiFi helpers: */
    /* #define USE_WOLFSSL_ESP_SDK_WIFI */
    #define TEST_ESPIDF_ALL_WOLFSSL

#elif defined(CONFIG_WOLFSSL_EXAMPLE_NAME_BENCHMARK)
    /* See https://github.com/wolfSSL/wolfssl/tree/master/IDE/Espressif/ESP-IDF/examples/wolfssl_benchmark */
    /* We don't use WiFi, so don't compile in the esp-sdk-lib WiFi helpers: */
    /* #define USE_WOLFSSL_ESP_SDK_WIFI */
    #define WOLFSSL_BENCHMARK_FIXED_UNITS_KB
#elif defined(CONFIG_WOLFSSL_EXAMPLE_NAME_TLS_CLIENT)
    /* See https://github.com/wolfSSL/wolfssl/tree/master/IDE/Espressif/ESP-IDF/examples/wolfssl_client */
    #define USE_WOLFSSL_ESP_SDK_WIFI
#elif defined(CONFIG_WOLFSSL_EXAMPLE_NAME_TLS_SERVER)
    /* See https://github.com/wolfSSL/wolfssl/tree/master/IDE/Espressif/ESP-IDF/examples/wolfssl_server */
    #define USE_WOLFSSL_ESP_SDK_WIFI

/* wolfSSH Examples */
#elif defined(CONFIG_WOLFSSL_EXAMPLE_NAME_WOLFSSH_TEMPLATE)
    /* See https://github.com/wolfSSL/wolfssh/tree/master/ide/Espressif/ESP-IDF/examples/wolfssh_template */
    #define USE_WOLFSSL_ESP_SDK_WIFI
#elif defined(CONFIG_WOLFSSL_EXAMPLE_NAME_WOLFSSH_ECHOSERVER)
    /* See https://github.com/wolfSSL/wolfssh/tree/master/ide/Espressif/ESP-IDF/examples/wolfssh_echoserver */
    #define USE_WOLFSSL_ESP_SDK_WIFI
#elif defined(CONFIG_WOLFSSL_EXAMPLE_NAME_ESP32_SSH_SERVER)
    /* See https://github.com/wolfSSL/wolfssh-examples/tree/main/Espressif/ESP32/ESP32-SSH-Server */
    #define USE_WOLFSSL_ESP_SDK_WIFI
#elif defined(CONFIG_WOLFSSL_EXAMPLE_NAME_ESP8266_SSH_SERVER)
    /* See https://github.com/wolfSSL/wolfssh-examples/tree/main/Espressif/ESP8266/ESP8266-SSH-Server */
    #define USE_WOLFSSL_ESP_SDK_WIFI

/* wolfMQTT Examples */
#elif defined(CONFIG_WOLFSSL_EXAMPLE_NAME_WOLFMQTT_TEMPLATE)
    /* See https://github.com/wolfSSL/wolfMQTT/tree/master/IDE/Espressif/ESP-IDF/examples/wolfmqtt_template */
    #define USE_WOLFSSL_ESP_SDK_WIFI
#elif defined(CONFIG_WOLFSSL_EXAMPLE_NAME_WOLFMQTT_AWS_IOT_MQTT)
    /* See https://github.com/wolfSSL/wolfMQTT/tree/master/IDE/Espressif/ESP-IDF/examples/AWS_IoT_MQTT */
    #define USE_WOLFSSL_ESP_SDK_WIFI

/* wolfTPM Examples */
#elif defined(CONFIG_WOLFTPM_EXAMPLE_NAME_ESPRESSIF)
    /* See https://github.com/wolfSSL/wolfTPM/tree/master/IDE/Espressif */
    #define USE_WOLFSSL_ESP_SDK_WIFI

/* Apple HomeKit Examples */
#elif defined(CONFIG_WOLFSSL_APPLE_HOMEKIT)
    /* See https://github.com/AchimPieters/esp32-homekit-demo */

/* no example selected */
#elif defined(CONFIG_WOLFSSL_EXAMPLE_NAME_NONE)
    /* We'll assume the app needs to use wolfSSL sdk lib function */
    #define USE_WOLFSSL_ESP_SDK_WIFI

/* Other applications detected by cmake */
#elif defined(APP_ESP_HTTP_CLIENT_EXAMPLE)
    /* The wolfSSL Version of the client example */
    #if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32C2)
        /* Less memory available, so smaller key sizes: */
        #define FP_MAX_BITS (4096 * 2)
    #else
        #define FP_MAX_BITS (8192 * 2)
    #endif
    #define HAVE_ALPN
    #define HAVE_SNI
    #define OPENSSL_EXTRA_X509_SMALL
    #define HAVE_TLS_EXTENSIONS
    #define HAVE_SUPPORTED_CURVES
    #define OPENSSL_EXTRA
    #ifndef WOLFSSL_ALWAYS_VERIFY_CB
       #define WOLFSSL_ALWAYS_VERIFY_CB
    #endif
    #ifndef WOLFSSL_VERIFY_CB_ALL_CERTS
        #define WOLFSSL_VERIFY_CB_ALL_CERTS
    #endif
    #ifndef KEEP_PEER_CERT
        #define KEEP_PEER_CERT
    #endif

#elif defined(APP_ESP_HTTP_CLIENT)
    /* The ESP-IDF Version */
    #define FP_MAX_BITS (8192 * 2)
    #define HAVE_ALPN
    #define HAVE_SNI
    #define OPENSSL_EXTRA_X509_SMALL
    #define HAVE_TLS_EXTENSIONS
    #define HAVE_SUPPORTED_CURVES
    #define OPENSSL_EXTRA
    #ifndef WOLFSSL_ALWAYS_VERIFY_CB
       #define WOLFSSL_ALWAYS_VERIFY_CB
    #endif
    #ifndef WOLFSSL_VERIFY_CB_ALL_CERTS
        #define WOLFSSL_VERIFY_CB_ALL_CERTS
    #endif
    #ifndef KEEP_PEER_CERT
        #define KEEP_PEER_CERT
    #endif
#else
    #ifdef WOLFSSL_ESPIDF
        /* #warning "App config undetected" */
    #endif
    /* the code is older or does not have application name defined. */
#endif /* Example wolfSSL Configuration app settings */

/* Experimental Kyber */
#ifdef CONFIG_WOLFSSL_ENABLE_KYBER
    /* Kyber typically needs a minimum 10K stack */
    #define WOLFSSL_EXPERIMENTAL_SETTINGS
    #define WOLFSSL_HAVE_KYBER
    #define WOLFSSL_WC_KYBER
    #define WOLFSSL_SHA3
    #if defined(CONFIG_IDF_TARGET_ESP8266)
        /* With limited RAM, we'll disable some of the Kyber sizes: */
        #define WOLFSSL_NO_KYBER1024
        #define WOLFSSL_NO_KYBER768
        #define NO_SESSION_CACHE
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

/* Optionally enable Apple HomeKit from compiler directive or Kconfig setting */
#if defined(WOLFSSL_APPLE_HOMEKIT) || defined(CONFIG_WOLFSSL_APPLE_HOMEKIT)
     /* SRP is known to need 8K; slow on some devices */
     #define FP_MAX_BITS (8192 * 2)
     #define WOLFCRYPT_HAVE_SRP
     #define HAVE_CHACHA
     #define HAVE_POLY1305
     #define WOLFSSL_BASE64_ENCODE
 #endif /* Apple HomeKit settings */

/* Used by ESP-IDF components: */
#if defined(CONFIG_ESP_TLS_USING_WOLFSSL)
    /* The ESP-TLS */
    #ifndef FP_MAX_BITS
        #if defined(CONFIG_IDF_TARGET_ESP32C2) || \
            defined(CONFIG_IDF_TARGET_ESP8684) || \
            defined(CONFIG_IDF_TARGET_ESP8266)
            /* Optionally set smaller size here */
            #define FP_MAX_BITS MIN_FFDHE_FP_MAX_BITS
        #else
            #define FP_MAX_BITS (4096 * 2)
        #endif
    #endif
    #define HAVE_ALPN
    #ifndef CONFIG_IDF_TARGET_ESP8266
        /* Unless installed in the ESP8266 RTOS SDK locally, the wolfSSL
         * API for SNI will not be seen in the components/esp-tls layer.
         * Only enable SNI for non-ESP8266 targets by default: */
        #define HAVE_SNI
    #endif
    #define OPENSSL_EXTRA_X509_SMALL

    #define HAVE_TLS_EXTENSIONS
    #define HAVE_SUPPORTED_CURVES
#endif

/* Optionally enable some wolfSSH settings */
#if defined(ESP_ENABLE_WOLFSSH) || defined(CONFIG_ESP_ENABLE_WOLFSSH)
    /* The default SSH Windows size is massive for an embedded target.
     * Limit it: */
    #define DEFAULT_WINDOW_SZ 2000

    /* These may be defined in cmake for other examples: */
    #undef  WOLFSSH_TERM
    #define WOLFSSH_TERM

    /* optional debug */
    /* #undef  DEBUG_WOLFSSH */
    /* #define DEBUG_WOLFSSH */

    #undef  WOLFSSL_KEY_GEN
    #define WOLFSSL_KEY_GEN

    #undef  WOLFSSL_PTHREADS
    #define WOLFSSL_PTHREADS

    #define WOLFSSH_TEST_SERVER
    #define WOLFSSH_TEST_THREADING
#endif /* ESP_ENABLE_WOLFSSH */


/* Not yet using WiFi lib, so don't compile in the esp-sdk-lib WiFi helpers: */
/* #define USE_WOLFSSL_ESP_SDK_WIFI */

/*
 * ONE of these Espressif chip families will be detected from sdkconfig:
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

/* when you want to use SINGLE THREAD. Note Default ESP-IDF is FreeRTOS */
#define SINGLE_THREADED

/* Small session cache saves a lot of RAM for ClientCache and SessionCache.
 * Memory requirement is about 5KB, otherwise 20K is needed when not specified.
 * If extra small footprint is needed, try MICRO_SESSION_CACHE (< 1K)
 * When really desperate or no TLS used, try NO_SESSION_CACHE.  */
#define NO_SESSION_CACHE

/* Small Stack uses more heap. */
#define WOLFSSL_SMALL_STACK

/* Full debugging turned off, but show malloc failure detail */
/* #define DEBUG_WOLFSSL */
#define DEBUG_WOLFSSL_MALLOC

/* See test.c that sets cert buffers; we'll set them here: */
#define USE_CERT_BUFFERS_256
#define USE_CERT_BUFFERS_2048

/* RSA_LOW_MEM: Half as much memory but twice as slow. */
#define RSA_LOW_MEM

/* optionally turn off SHA512/224 SHA512/256 */
/* #define WOLFSSL_NOSHA512_224 */
/* #define WOLFSSL_NOSHA512_256 */

/* when you want to use SINGLE THREAD. Note Default ESP-IDF is FreeRTOS */
/* #define SINGLE_THREADED */

/* When you don't want to use the old SHA */
/* #define NO_SHA */
/* #define NO_OLD_TLS */

#define BENCH_EMBEDDED

/* TLS 1.3                                 */
#ifdef CONFIG_WOLFSSL_ALLOW_TLS13
    #define WOLFSSL_TLS13
    #define HAVE_TLS_EXTENSIONS
    #define HAVE_HKDF

    /* May be required */
    #ifndef HAVE_AEAD
    #endif

    /* Required for ECC */
    #define HAVE_SUPPORTED_CURVES

    /* Required for RSA */
    #define WC_RSA_PSS

    /* TLS 1.3 normally requires HAVE_FFDHE */
    #if defined(HAVE_FFDHE_2048) || \
        defined(HAVE_FFDHE_3072) || \
        defined(HAVE_FFDHE_4096) || \
        defined(HAVE_FFDHE_6144) || \
        defined(HAVE_FFDHE_8192)
    #else
        #define HAVE_FFDHE_2048
        /* #error "TLS 1.3 requires HAVE_FFDHE_[nnnn]" */
    #endif
#endif

#if defined(CONFIG_IDF_TARGET_ESP32C2) || \
    defined(CONFIG_IDF_TARGET_ESP8684)
    /* Optionally set smaller size here */
    #define HAVE_FFDHE_4096
#else
    #define HAVE_FFDHE_4096
#endif

#define NO_FILESYSTEM

#define NO_OLD_TLS

#define HAVE_AESGCM

/* Optional RIPEMD: RACE Integrity Primitives Evaluation Message Digest */
/* #define WOLFSSL_RIPEMD */

/* when you want to use SHA224 */
#define WOLFSSL_SHA224

/* when you want to use SHA384 */
#define WOLFSSL_SHA384

/* Some features not enabled for ESP8266: */
#if defined(CONFIG_IDF_TARGET_ESP8266) || \
    defined(CONFIG_IDF_TARGET_ESP32C2)
    /* Some known low-memory devices have features not enabled by default. */
    /* TODO determine low memory configuration for ECC. */
#else
    /* when you want to use SHA512 */
    #define WOLFSSL_SHA512

    /* when you want to use SHA3 */
    /* #define WOLFSSL_SHA3 */

    /* ED25519 requires SHA512 */
    #define HAVE_ED25519
#endif

#if defined(CONFIG_IDF_TARGET_ESP8266) || defined(CONFIG_IDF_TARGET_ESP32C2)
    #define MY_USE_ECC 0
    #define MY_USE_RSA 1
#else
    #define MY_USE_ECC 1
    #define MY_USE_RSA 0
#endif

/* We can use either or both ECC and RSA, but must use at least one. */
#if MY_USE_ECC || MY_USE_RSA
    #if MY_USE_ECC
        /* ---- ECDSA / ECC ---- */
        #define HAVE_ECC
        #define HAVE_CURVE25519
        #define HAVE_ED25519
        #define WOLFSSL_SHA512
        /*
        #define HAVE_ECC384
        #define CURVE25519_SMALL
        */
    #else
        #define WOLFSSH_NO_ECC
        /* WOLFSSH_NO_ECDSA is typically defined automatically,
         * here for clarity: */
        #define WOLFSSH_NO_ECDSA
    #endif

    #if MY_USE_RSA
        /* ---- RSA ----- */
        /* #define RSA_LOW_MEM */

        /* DH disabled by default, needed if ECDSA/ECC also turned off */
        #define HAVE_DH
    #else
        #define WOLFSSH_NO_RSA
    #endif
#else
    #error "Either RSA or ECC must be enabled"
#endif

/* Optional OpenSSL compatibility */
/* #define OPENSSL_EXTRA */

/* #Optional HAVE_PKCS7 */
/* #define HAVE_PKCS7 */

#if defined(HAVE_PKCS7)
    /* HAVE_PKCS7 may enable HAVE_PBKDF2 see settings.h */
    #define NO_PBKDF2

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

/* WC_NO_CACHE_RESISTANT: slower but more secure */
/* #define WC_NO_CACHE_RESISTANT */

/* TFM_TIMING_RESISTANT: slower but more secure */
/* #define TFM_TIMING_RESISTANT */

/* #define WOLFSSL_ATECC508A_DEBUG         */

/* date/time                               */
/* if it cannot adjust time in the device, */
/* enable macro below                      */
/* #define NO_ASN_TIME */
/* #define XTIME time */


/* Adjust wait-timeout count if you see timeout in RSA HW acceleration.
 * Set to very large number and enable WOLFSSL_HW_METRICS to determine max. */
#ifndef ESP_RSA_TIMEOUT_CNT
	#define ESP_RSA_TIMEOUT_CNT 0xFF0000
#endif

/* hash limit for test.c */
#define HASH_SIZE_LIMIT

/* USE_FAST_MATH is default */
#define USE_FAST_MATH

/*****      Use SP_MATH      *****/
/* #undef  USE_FAST_MATH         */
/* #define SP_MATH               */
/* #define WOLFSSL_SP_MATH_ALL   */
/* #define WOLFSSL_SP_RISCV32    */

/***** Use Integer Heap Math *****/
/* #undef USE_FAST_MATH          */
/* #define USE_INTEGER_HEAP_MATH */

/* Just syntax highlighting to check math libraries: */
#if defined(SP_MATH)               || \
    defined(USE_INTEGER_HEAP_MATH) || \
    defined(USE_INTEGER_HEAP_MATH) || \
    defined(USE_FAST_MATH)         || \
    defined(WOLFSSL_SP_MATH_ALL)   || \
    defined(WOLFSSL_SP_RISCV32)
#endif

#define WOLFSSL_SMALL_STACK


#define HAVE_VERSION_EXTENDED_INFO
/* #define HAVE_WC_INTROSPECTION */

#ifndef NO_SESSION_CACHE
    #define  HAVE_SESSION_TICKET
#endif

/* #define HAVE_HASHDRBG */

#if 0
/* Example for additional cert functions */
#define WOLFSSL_KEY_GEN
    #define WOLFSSL_CERT_REQ
    #define WOLFSSL_CERT_GEN
    #define WOLFSSL_CERT_EXT
    #define WOLFSSL_SYS_CA_CERTS


    #define WOLFSSL_CERT_TEXT

    /* command-line options
    --enable-keygen
    --enable-certgen
    --enable-certreq
    --enable-certext
    --enable-asn-template
    */

#endif

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

/* optional SM4 Ciphers. See https://github.com/wolfSSL/wolfsm */
/*
#define WOLFSSL_SM2
#define WOLFSSL_SM3
#define WOLFSSL_SM4
*/

#if defined(WOLFSSL_SM2) || defined(WOLFSSL_SM3) || defined(WOLFSSL_SM4)
    /* SM settings, possible cipher suites:

        TLS13-AES128-GCM-SHA256
        TLS13-CHACHA20-POLY1305-SHA256
        TLS13-SM4-GCM-SM3
        TLS13-SM4-CCM-SM3

    #define WOLFSSL_ESP32_CIPHER_SUITE "TLS13-SM4-GCM-SM3"
    #define WOLFSSL_ESP32_CIPHER_SUITE "TLS13-SM4-CCM-SM3"
    #define WOLFSSL_ESP32_CIPHER_SUITE "ECDHE-ECDSA-SM4-CBC-SM3"
    #define WOLFSSL_ESP32_CIPHER_SUITE "ECDHE-ECDSA-SM4-GCM-SM3"
    #define WOLFSSL_ESP32_CIPHER_SUITE "ECDHE-ECDSA-SM4-CCM-SM3"
    #define WOLFSSL_ESP32_CIPHER_SUITE "TLS13-SM4-GCM-SM3:" \
                                       "TLS13-SM4-CCM-SM3:"
    */

    #undef  WOLFSSL_BASE16
    #define WOLFSSL_BASE16 /* required for WOLFSSL_SM2 */

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
#else
    /* default settings */
    #define USE_CERT_BUFFERS_2048
#endif

/* Chipset detection from sdkconfig.h
 * Default is HW enabled unless turned off.
 * Uncomment lines to force SW instead of HW acceleration */
#if defined(CONFIG_IDF_TARGET_ESP32) || defined(WOLFSSL_ESPWROOM32SE)
    #define WOLFSSL_ESP32
    /*  Alternatively, if there's an ECC Secure Element present: */
    /* #define WOLFSSL_ESPWROOM32SE */

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
    /* Consider using the ESP32-C2/C3/C6 */
    #define NO_ESP32_CRYPT
    #define NO_WOLFSSL_ESP32_CRYPT_HASH
    #define NO_WOLFSSL_ESP32_CRYPT_AES
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI
    #ifndef FP_MAX_BITS
        /* FP_MAX_BITS matters in wolfssl_test, not just TLS setting.   */
        /* MIN_FFDHE_FP_MAX_BITS = (MIN_FFDHE_BITS * 2); see settings.h */
        #define FP_MAX_BITS MIN_FFDHE_FP_MAX_BITS
    #endif
    /***** END CONFIG_IDF_TARGET_ESP266 *****/

#elif defined(CONFIG_IDF_TARGET_ESP8684)
    /*  There's no Hardware Acceleration available on ESP8684 */
    #define NO_ESP32_CRYPT
    #define NO_WOLFSSL_ESP32_CRYPT_HASH
    #define NO_WOLFSSL_ESP32_CRYPT_AES
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI
    /***** END CONFIG_IDF_TARGET_ESP8684 *****/

#else
    /* Anything else encountered, disable HW acceleration */
    #warning "Unexpected CONFIG_IDF_TARGET_NN value"
    #define NO_ESP32_CRYPT
    #define NO_WOLFSSL_ESP32_CRYPT_HASH
    #define NO_WOLFSSL_ESP32_CRYPT_AES
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI
#endif /* CONFIG_IDF_TARGET Check */

/* RSA primitive specific definition, listed AFTER the Chipset detection */
#if defined(WOLFSSL_ESP32) || defined(WOLFSSL_ESPWROOM32SE)
    /* Consider USE_FAST_MATH and SMALL_STACK                        */

    #ifndef NO_RSA
        #define ESP32_USE_RSA_PRIMITIVE

        #if defined(CONFIG_IDF_TARGET_ESP32)
            #ifdef CONFIG_ESP_MAIN_TASK_STACK_SIZE
                #if CONFIG_ESP_MAIN_TASK_STACK_SIZE < 10500
                    #warning "RSA may be difficult with less than 10KB Stack "/
                #endif
            #endif

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
#endif

/* Debug options:
See wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h for details on debug options

optionally increase error message size for very long paths.
#define WOLFSSL_MAX_ERROR_SZ 500

Turn wolfSSL debugging on/off:
    wolfSSL_Debugging_ON();
    wolfSSL_Debugging_OFF();

#define ESP_VERIFY_MEMBLOCK
#define DEBUG_WOLFSSL
#define DEBUG_WOLFSSL_VERBOSE
#define DEBUG_WOLFSSL_SHA_MUTEX
#define WOLFSSL_DEBUG_IGNORE_ASN_TIME
#define WOLFSSL_DEBUG_CERT_BUNDLE
#define WOLFSSL_DEBUG_CERT_BUNDLE_NAME
#define WOLFSSL_ESP32_CRYPT_DEBUG
#define WOLFSSL_ESP32_CRYPT_HASH_SHA224_DEBUG
#define NO_RECOVER_SOFTWARE_CALC
#define WOLFSSL_TEST_STRAY 1
#define USE_ESP_DPORT_ACCESS_READ_BUFFER
#define WOLFSSL_ESP32_HW_LOCK_DEBUG
#define WOLFSSL_DEBUG_MUTEX
#define WOLFSSL_DEBUG_ESP_RSA_MULM_BITS
#define WOLFSSL_DEBUG_ESP_HW_MOD_RSAMAX_BITS
#define WOLFSSL_DEBUG_ESP_HW_MULTI_RSAMAX_BITS
#define ESP_DISABLE_HW_TASK_LOCK
#define ESP_MONITOR_HW_TASK_LOCK
#define USE_ESP_DPORT_ACCESS_READ_BUFFER

See wolfcrypt/benchmark/benchmark.c for debug and other settings:

Turn on benchmark timing debugging (CPU Cycles, RTOS ticks, etc)
#define DEBUG_WOLFSSL_BENCHMARK_TIMING

Turn on timer debugging (used when CPU cycles not available)
#define WOLFSSL_BENCHMARK_TIMER_DEBUG
*/

/* Pause in a loop rather than exit. */
/* #define WOLFSSL_ESPIDF_ERROR_PAUSE */
/* #define WOLFSSL_ESP32_HW_LOCK_DEBUG */

#define WOLFSSL_HW_METRICS

/* for test.c */
/* #define HASH_SIZE_LIMIT */

/* Optionally turn off HW math checks */
/* #define NO_HW_MATH_TEST */

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
 * To use the sample certificates in code (not recommended for production!):
 *
 *    #if defined(USE_CERT_BUFFERS_2048) || defined(USE_CERT_BUFFERS_1024)
 *        #include <wolfssl/certs_test.h>
 *    #endif
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
        #define USE_CERT_BUFFERS_256
        /* Be sure to include in app when using example certs: */
        /* #include <wolfssl/certs_test.h>                     */
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
        #define USE_CERT_BUFFERS_256
        /* Be sure to include in app when using example certs: */
        /* #include <wolfssl/certs_test.h>                     */
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

/******************************************************************************
** Sanity Checks
******************************************************************************/
#if defined(CONFIG_ESP_MAIN_TASK_STACK_SIZE)
    #if defined(WOLFCRYPT_HAVE_SRP)
        #if defined(FP_MAX_BITS)
            #if FP_MAX_BITS <  (8192 * 2)
                #define ESP_SRP_MINIMUM_STACK_8K (24 * 1024)
            #else
                #define ESP_SRP_MINIMUM_STACK_8K (28 * 1024)
            #endif
        #else
            #error "Please define FP_MAX_BITS when using WOLFCRYPT_HAVE_SRP."
        #endif

        #if (CONFIG_ESP_MAIN_TASK_STACK_SIZE < ESP_SRP_MINIMUM_STACK)
            #warning "WOLFCRYPT_HAVE_SRP enabled with small stack size"
        #endif
    #endif
#else
    #warning "CONFIG_ESP_MAIN_TASK_STACK_SIZE not defined!"
#endif
/* See settings.h for some of the possible hardening options:
 *
 *  #define NO_ESPIDF_DEFAULT
 *  #define WC_NO_CACHE_RESISTANT
 *  #define WC_AES_BITSLICED
 *  #define HAVE_AES_ECB
 *  #define HAVE_AES_DIRECT
 */
