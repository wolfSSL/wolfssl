/* settings.h
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

/*
 *   Note, this file should not be edited to activate/deactivate features.
 *
 *   Instead, add/edit user_settings.h, and compile with -DWOLFSSL_USER_SETTINGS
 *
 *         or
 *
 *   ./configure CFLAGS="-DFEATURE_FLAG_TO_DEFINE -UFEATURE_FLAG_TO_CLEAR [...]"
 *
 *   To build using a custom configuration method, define WOLFSSL_CUSTOM_CONFIG
 *
 *   For more information see:
 *
 *   https://www.wolfssl.com/how-do-i-manage-the-build-configuration-of-wolfssl/
 */


/* Place OS specific preprocessor flags, defines, includes here, will be
   included into every file because types.h includes it */


#ifndef WOLF_CRYPT_SETTINGS_H
#define WOLF_CRYPT_SETTINGS_H

#ifdef __cplusplus
    extern "C" {
#endif

/* WOLFSSL_USE_OPTIONS_H directs wolfSSL to include options.h on behalf of
 * application code, rather than the application including it directly.  This is
 * not defined when compiling wolfSSL library objects, which are configured
 * through CFLAGS.
 */
#if (defined(EXTERNAL_OPTS_OPENVPN) || defined(WOLFSSL_USE_OPTIONS_H)) && \
    !defined(WOLFSSL_NO_OPTIONS_H)
    #include <wolfssl/options.h>
#endif

/* Uncomment next line if using IPHONE */
/* #define IPHONE */

/* Uncomment next line if using ThreadX */
/* #define THREADX */

/* Uncomment next line if using Micrium uC/OS-III */
/* #define MICRIUM */

/* Uncomment next line if using Deos RTOS*/
/* #define WOLFSSL_DEOS*/

/* Uncomment next line if using Mbed */
/* #define MBED */

/* Uncomment next line if using Microchip PIC32 ethernet starter kit */
/* #define MICROCHIP_PIC32 */

/* Uncomment next line if using Microchip TCP/IP stack, version 5 */
/* #define MICROCHIP_TCPIP_V5 */

/* Uncomment next line if using Microchip TCP/IP stack, version 6 or later */
/* #define MICROCHIP_TCPIP */

/* Uncomment next line if using above Microchip TCP/IP defines with BSD API */
/* #define MICROCHIP_TCPIP_BSD_API */

/* Uncomment next line if using PIC32MZ Crypto Engine */
/* #define WOLFSSL_MICROCHIP_PIC32MZ */

/* Uncomment next line if using FreeRTOS */
/* #define FREERTOS */

/* Uncomment next line if using FreeRTOS+ TCP */
/* #define FREERTOS_TCP */

/* Uncomment next line if using FreeRTOS Windows Simulator */
/* #define FREERTOS_WINSIM */

/* Uncomment next line if using RTIP */
/* #define EBSNET */

/* Uncomment next line if using lwip */
/* #define WOLFSSL_LWIP */

/* Uncomment next line if building wolfSSL for a game console */
/* #define WOLFSSL_GAME_BUILD */

/* Uncomment next line if building wolfSSL for LSR */
/* #define WOLFSSL_LSR */

/* Uncomment next line if building for Freescale Classic MQX version 5.0 */
/* #define FREESCALE_MQX_5_0 */

/* Uncomment next line if building for Freescale Classic MQX version 4.0 */
/* #define FREESCALE_MQX_4_0 */

/* Uncomment next line if building for Freescale Classic MQX/RTCS/MFS */
/* #define FREESCALE_MQX */

/* Uncomment next line if building for Freescale KSDK MQX/RTCS/MFS */
/* #define FREESCALE_KSDK_MQX */

/* Uncomment next line if building for Freescale KSDK Bare Metal */
/* #define FREESCALE_KSDK_BM */

/* Uncomment next line if building for Freescale KSDK FreeRTOS, */
/* (old name FREESCALE_FREE_RTOS) */
/* #define FREESCALE_KSDK_FREERTOS */

/* Uncomment next line if using STM32F2 */
/* #define WOLFSSL_STM32F2 */

/* Uncomment next line if using STM32F4 */
/* #define WOLFSSL_STM32F4 */

/* Uncomment next line if using STM32FL */
/* #define WOLFSSL_STM32FL */

/* Uncomment next line if using STM32F7 */
/* #define WOLFSSL_STM32F7 */

/* Uncomment next line if using QL SEP settings */
/* #define WOLFSSL_QL */

/* Uncomment next line if building for EROAD */
/* #define WOLFSSL_EROAD */

/* Uncomment next line if building for IAR EWARM */
/* #define WOLFSSL_IAR_ARM */

/* Uncomment next line if building for Rowley CrossWorks ARM */
/* #define WOLFSSL_ROWLEY_ARM */

/* Uncomment next line if using TI-RTOS settings */
/* #define WOLFSSL_TIRTOS */

/* Uncomment next line if building with PicoTCP */
/* #define WOLFSSL_PICOTCP */

/* Uncomment next line if building for PicoTCP demo bundle */
/* #define WOLFSSL_PICOTCP_DEMO */

/* Uncomment next line if building for uITRON4  */
/* #define WOLFSSL_uITRON4 */

/* Uncomment next line if building for uT-Kernel */
/* #define WOLFSSL_uTKERNEL2 */

/* Uncomment next line if using Max Strength build */
/* #define WOLFSSL_MAX_STRENGTH */

/* Uncomment next line if building for VxWorks */
/* #define WOLFSSL_VXWORKS */

/* Uncomment next line if building for Nordic nRF5x platform */
/* #define WOLFSSL_NRF5x */

/* Uncomment next line to enable deprecated less secure static DH suites */
/* #define WOLFSSL_STATIC_DH */

/* Uncomment next line to enable deprecated less secure static RSA suites */
/* #define WOLFSSL_STATIC_RSA */

/* Uncomment next line if building for ARDUINO */
/* Uncomment both lines if building for ARDUINO on INTEL_GALILEO */
/* #define WOLFSSL_ARDUINO */
/* #define INTEL_GALILEO */

/* Uncomment next line to enable asynchronous crypto WC_PENDING_E */
/* #define WOLFSSL_ASYNC_CRYPT */

/* Uncomment next line if building for uTasker */
/* #define WOLFSSL_UTASKER */

/* Uncomment next line if building for embOS */
/* #define WOLFSSL_EMBOS */

/* Uncomment next line if building for RIOT-OS */
/* #define WOLFSSL_RIOT_OS */

/* Uncomment next line if building for using XILINX hardened crypto */
/* #define WOLFSSL_XILINX_CRYPT */

/* Uncomment next line if building for using XILINX */
/* #define WOLFSSL_XILINX */

/* Uncomment next line if building for WICED Studio. */
/* #define WOLFSSL_WICED  */

/* Uncomment next line if building for Nucleus 1.2 */
/* #define WOLFSSL_NUCLEUS_1_2 */

/* Uncomment next line if building for Nucleus Plus 2.3 */
/* #define NUCLEUS_PLUS_2_3 */

/* Uncomment next line if building for using Apache mynewt */
/* #define WOLFSSL_APACHE_MYNEWT */

/* For Espressif chips see example user_settings.h
 *
 * https://github.com/wolfSSL/wolfssl/blob/master/IDE/Espressif/ESP-IDF/user_settings.h
 */

/* Uncomment next line if building for using ESP-IDF */
/* #define WOLFSSL_ESPIDF */

/* Uncomment next line if using Espressif ESP32-WROOM-32 */
/* #define WOLFSSL_ESP32 */

/* Uncomment next line if using Espressif ESP32-WROOM-32SE */
/* #define WOLFSSL_ESPWROOM32SE */

/* Uncomment next line if using ARM CRYPTOCELL*/
/* #define WOLFSSL_CRYPTOCELL */

/* Uncomment next line if using RENESAS TSIP */
/* #define WOLFSSL_RENESAS_TSIP */

/* Uncomment next line if using RENESAS RX64N */
/* #define WOLFSSL_RENESAS_RX65N */

/* Uncomment next line if using RENESAS SCE Protected Mode */
/* #define WOLFSSL_RENESAS_SCEPROTECT */

/* Uncomment next line if using RENESAS RA6M4 */
/* #define WOLFSSL_RENESAS_RA6M4 */

/* Uncomment next line if using RENESAS RX64 hardware acceleration */
/* #define WOLFSSL_RENESAS_RX64_HASH */

/* Uncomment next line if using Solaris OS*/
/* #define WOLFSSL_SOLARIS */

/* Uncomment next line if building for Linux Kernel Module */
/* #define WOLFSSL_LINUXKM */

/* Uncomment next line if building for devkitPro */
/* #define DEVKITPRO */

/* Uncomment next line if building for Dolphin Emulator */
/* #define DOLPHIN_EMULATOR */

/* Uncomment next line if building for WOLFSSL_NDS */
/* #define WOLFSSL_NDS */

/* Uncomment next line if using MAXQ1065 */
/* #define WOLFSSL_MAXQ1065 */

/* Uncomment next line if using MAXQ108x */
/* #define WOLFSSL_MAXQ108X */

/* Uncomment next line if using Raspberry Pi RP2040 or RP2350 */
/* #define WOLFSSL_RPIPICO */

/* Check PLATFORMIO first, as it may define other known environments. */
#ifdef PLATFORMIO
    #ifdef ESP_PLATFORM
        /* Turn on the wolfSSL ESPIDF flag for the PlatformIO ESP-IDF detect */
        #undef  WOLFSSL_ESPIDF
        #define WOLFSSL_ESPIDF
    #endif /* ESP_PLATFORM */

    /* Ensure all PlatformIO boards have the wolfSSL user_setting.h enabled. */
    #ifndef WOLFSSL_USER_SETTINGS
        #define WOLFSSL_USER_SETTINGS
    #endif /* WOLFSSL_USER_SETTINGS */

    /* Similar to Arduino we have limited build control, so suppress warning */
    #undef  WOLFSSL_IGNORE_FILE_WARN
    #define WOLFSSL_IGNORE_FILE_WARN
#endif

#if defined(ARDUINO)
    /* Due to limited build control, we'll ignore file warnings. */
    /* See https://github.com/arduino/arduino-cli/issues/631     */
    #undef  WOLFSSL_IGNORE_FILE_WARN
    #define WOLFSSL_IGNORE_FILE_WARN

    /* we don't have the luxury of compiler options, so manually define */
    #if defined(__arm__)
        #undef  WOLFSSL_ARDUINO
        #define WOLFSSL_ARDUINO
    /* ESP32? */
    #endif

    #undef FREERTOS
    #ifndef WOLFSSL_USER_SETTINGS
        #define WOLFSSL_USER_SETTINGS
    #endif /* WOLFSSL_USER_SETTINGS */

    /* board-specific */
    #if defined(__AVR__)
        #define WOLFSSL_NO_SOCK
        #define NO_WRITEV
    #elif defined(__arm__)
        #define WOLFSSL_NO_SOCK
        #define NO_WRITEV
    #elif defined(ESP32) || defined(ESP8266)
        /* assume sockets available */
    #else
        #define WOLFSSL_NO_SOCK
    #endif
#endif

#if !defined(WOLFSSL_CUSTOM_CONFIG) && \
    ((defined(BUILDING_WOLFSSL) && defined(WOLFSSL_USE_OPTIONS_H)) || \
     (defined(BUILDING_WOLFSSL) && defined(WOLFSSL_OPTIONS_H) &&      \
     !defined(EXTERNAL_OPTS_OPENVPN)))
    #warning wolfssl/options.h included in compiled wolfssl library object.
#endif

#ifdef WOLFSSL_USER_SETTINGS
    #include "user_settings.h"
#elif defined(USE_HAL_DRIVER) && !defined(HAVE_CONFIG_H)
    /* STM Configuration File (generated by CubeMX) */
    #include "wolfSSL.I-CUBE-wolfSSL_conf.h"
#elif defined(NUCLEUS_PLUS_2_3)
    /* NOTE: cyassl_nucleus_defs.h is akin to user_settings.h */
    #include "nucleus.h"
    #include "os/networking/ssl/lite/cyassl_nucleus_defs.h"
#elif !defined(BUILDING_WOLFSSL) && !defined(WOLFSSL_OPTIONS_H) && \
      !defined(WOLFSSL_NO_OPTIONS_H) && !defined(WOLFSSL_CUSTOM_CONFIG)
    /* This warning indicates that wolfSSL features may not have been properly
     * configured before other wolfSSL headers were included. If you are using
     * an alternative configuration method -- e.g. custom header, or CFLAGS in
     * an application build -- then your application can avoid this warning by
     * defining WOLFSSL_NO_OPTIONS_H or WOLFSSL_CUSTOM_CONFIG as appropriate.
     */
    #warning "No configuration for wolfSSL detected, check header order"
#endif

#include <wolfssl/wolfcrypt/visibility.h>

/*------------------------------------------------------------*/
#if defined(WOLFSSL_FIPS_READY) || defined(WOLFSSL_FIPS_DEV)
    #undef HAVE_FIPS_VERSION_MAJOR
    #define HAVE_FIPS_VERSION_MAJOR 7 /* always one more than major version */
                                      /* of most recent FIPS certificate */
    #undef HAVE_FIPS_VERSION
    #define HAVE_FIPS_VERSION HAVE_FIPS_VERSION_MAJOR
    #undef HAVE_FIPS_VERSION_MINOR
    #define HAVE_FIPS_VERSION_MINOR 0 /* always 0 */
    #undef HAVE_FIPS_VERSION_PATCH
    #define HAVE_FIPS_VERSION_PATCH 0 /* always 0 */
#endif

#define WOLFSSL_MAKE_FIPS_VERSION3(major, minor, patch) \
                                (((major) * 65536) + ((minor) * 256) + (patch))
#define WOLFSSL_MAKE_FIPS_VERSION(major, minor) \
                                  WOLFSSL_MAKE_FIPS_VERSION3(major, minor, 0)

#if !defined(HAVE_FIPS)
    #define WOLFSSL_FIPS_VERSION_CODE WOLFSSL_MAKE_FIPS_VERSION3(0,0,0)
    #define WOLFSSL_FIPS_VERSION2_CODE WOLFSSL_FIPS_VERSION_CODE
#elif !defined(HAVE_FIPS_VERSION)
    #define WOLFSSL_FIPS_VERSION_CODE WOLFSSL_MAKE_FIPS_VERSION3(1,0,0)
    #define WOLFSSL_FIPS_VERSION2_CODE WOLFSSL_FIPS_VERSION_CODE
#elif !defined(HAVE_FIPS_VERSION_MINOR)
    #define WOLFSSL_FIPS_VERSION_CODE \
            WOLFSSL_MAKE_FIPS_VERSION3(HAVE_FIPS_VERSION,0,0)
    #define WOLFSSL_FIPS_VERSION2_CODE WOLFSSL_FIPS_VERSION_CODE
#elif !defined(HAVE_FIPS_VERSION_PATCH)
    #define WOLFSSL_FIPS_VERSION_CODE \
            WOLFSSL_MAKE_FIPS_VERSION3(HAVE_FIPS_VERSION, \
                                       HAVE_FIPS_VERSION_MINOR, 0)
    #define WOLFSSL_FIPS_VERSION2_CODE WOLFSSL_FIPS_VERSION_CODE
#else
    #define WOLFSSL_FIPS_VERSION_CODE \
            WOLFSSL_MAKE_FIPS_VERSION3(HAVE_FIPS_VERSION,\
                                       HAVE_FIPS_VERSION_MINOR, \
                                       HAVE_FIPS_VERSION_PATCH)
    #define WOLFSSL_FIPS_VERSION2_CODE \
            WOLFSSL_MAKE_FIPS_VERSION3(HAVE_FIPS_VERSION,\
                                       HAVE_FIPS_VERSION_MINOR, \
                                       0)
#endif

#define FIPS_VERSION_LT(major,minor) \
           (WOLFSSL_FIPS_VERSION2_CODE < WOLFSSL_MAKE_FIPS_VERSION(major,minor))
#define FIPS_VERSION_LE(major,minor) \
          (WOLFSSL_FIPS_VERSION2_CODE <= WOLFSSL_MAKE_FIPS_VERSION(major,minor))
#define FIPS_VERSION_EQ(major,minor) \
          (WOLFSSL_FIPS_VERSION2_CODE == WOLFSSL_MAKE_FIPS_VERSION(major,minor))
#define FIPS_VERSION_GE(major,minor) \
          (WOLFSSL_FIPS_VERSION2_CODE >= WOLFSSL_MAKE_FIPS_VERSION(major,minor))
#define FIPS_VERSION_GT(major,minor) \
           (WOLFSSL_FIPS_VERSION2_CODE > WOLFSSL_MAKE_FIPS_VERSION(major,minor))

#define FIPS_VERSION3_LT(major,minor,patch) \
    (WOLFSSL_FIPS_VERSION_CODE < WOLFSSL_MAKE_FIPS_VERSION3(major,minor,patch))
#define FIPS_VERSION3_LE(major,minor,patch) \
    (WOLFSSL_FIPS_VERSION_CODE <= WOLFSSL_MAKE_FIPS_VERSION3(major,minor,patch))
#define FIPS_VERSION3_EQ(major,minor,patch) \
    (WOLFSSL_FIPS_VERSION_CODE == WOLFSSL_MAKE_FIPS_VERSION3(major,minor,patch))
#define FIPS_VERSION3_GE(major,minor,patch) \
    (WOLFSSL_FIPS_VERSION_CODE >= WOLFSSL_MAKE_FIPS_VERSION3(major,minor,patch))
#define FIPS_VERSION3_GT(major,minor,patch) \
    (WOLFSSL_FIPS_VERSION_CODE > WOLFSSL_MAKE_FIPS_VERSION3(major,minor,patch))
/*------------------------------------------------------------*/


/* make sure old RNG name is used with CTaoCrypt FIPS */
#ifdef HAVE_FIPS
    #if FIPS_VERSION_LT(2,0)
        #define WC_RNG RNG
    #else
        /* RNG needs to be defined to WC_RNG anytime another library on the
         * system or other set of headers included by wolfSSL already defines
         * RNG. Examples are:
         * wolfEngine, wolfProvider and potentially other use-cases */
        #if !defined(RNG) && !defined(NO_OLD_RNGNAME)
            #define RNG WC_RNG
        #endif
    #endif
    /* blinding adds API not available yet in FIPS mode */
    #undef WC_RSA_BLINDING
#endif

/* old FIPS has only AES_BLOCK_SIZE. */
#if !defined(NO_AES) && (defined(HAVE_SELFTEST) || \
     (defined(HAVE_FIPS) && FIPS_VERSION3_LT(7,0,0)))
    #define WC_AES_BLOCK_SIZE AES_BLOCK_SIZE
#endif /* !NO_AES && (HAVE_SELFTEST || FIPS_VERSION3_LT(7,0,0)) */

#ifdef WOLFSSL_HARDEN_TLS
    #if WOLFSSL_HARDEN_TLS != 112 && WOLFSSL_HARDEN_TLS != 128
        #error "WOLFSSL_HARDEN_TLS must be defined either to 112 or 128 bits of security."
    #endif
#endif

/* ---------------------------------------------------------------------------
 * Dual Algorithm Certificate Required Features.
 * ---------------------------------------------------------------------------
 */
#ifdef WOLFSSL_DUAL_ALG_CERTS
    #ifdef NO_RSA
        #error "Need RSA or else dual alg cert example will not work."
    #endif

    #ifndef HAVE_ECC
        #error "Need ECDSA or else dual alg cert example will not work."
    #endif

    #undef WOLFSSL_CERT_GEN
    #define WOLFSSL_CERT_GEN

    #undef WOLFSSL_CUSTOM_OID
    #define WOLFSSL_CUSTOM_OID

    #undef HAVE_OID_ENCODING
    #define HAVE_OID_ENCODING

    #undef WOLFSSL_CERT_EXT
    #define WOLFSSL_CERT_EXT

    #undef OPENSSL_EXTRA
    #define OPENSSL_EXTRA

    #undef HAVE_OID_DECODING
    #define HAVE_OID_DECODING
#endif /* WOLFSSL_DUAL_ALG_CERTS */


#if defined(_WIN32) && !defined(_M_X64) && \
    defined(HAVE_AESGCM) && defined(WOLFSSL_AESNI)

/* The _M_X64 macro is what's used in the headers for MSC to tell if it
 * has the 64-bit versions of the 128-bit integers available. If one is
 * building on 32-bit Windows with AES-NI, turn off the AES-GCMloop
 * unrolling. */

    #define AES_GCM_AESNI_NO_UNROLL
#endif

#ifdef IPHONE
    #define SIZEOF_LONG_LONG 8
#endif

#ifdef THREADX
    #define SIZEOF_LONG_LONG 8
#endif

#ifdef HAVE_NETX
    #ifdef NEED_THREADX_TYPES
        #include <types.h>
    #endif
    #include <nx_api.h>
#endif


#ifdef WOLFSSL_NDS
    #include <stddef.h>
    #define SIZEOF_LONG_LONG 8
    #define socklen_t int
    #define IPPROTO_UDP 17
    #define IPPROTO_TCP 6
    #define NO_WRITEV
#endif

#if defined(ARDUINO)
    #if defined(ESP32)
        #ifndef NO_ARDUINO_DEFAULT
            #define SIZEOF_LONG_LONG 8
            #ifdef FREERTOS
                #undef FREERTOS
            #endif

            #define WOLFSSL_LWIP
            #define NO_WRITEV
            #define NO_WOLFSSL_DIR
            #define WOLFSSL_NO_CURRDIR

            #define TFM_TIMING_RESISTANT
            #define ECC_TIMING_RESISTANT
            #define WC_RSA_BLINDING
            #define WC_NO_CACHE_RESISTANT
        #endif /* !NO_ARDUINO_DEFAULT */
    #elif defined(__arm__)
            #define NO_WRITEV
            #define NO_WOLFSSL_DIR
            #define WOLFSSL_NO_CURRDIR
    #elif defined(OTHERBOARD)
        /* TODO: define other Arduino boards here */
    #endif
#endif

#if defined(WOLFSSL_ESPIDF)
    #define SIZEOF_LONG_LONG 8

    #ifndef WOLFSSL_MAX_ERROR_SZ
        /* Espressif paths can be quite long. Ensure error prints full path. */
        #define WOLFSSL_MAX_ERROR_SZ 200
    #endif

    /* Parse any Kconfig / menuconfig items into wolfSSL macro equivalents.
     * Macros may or may not be defined. If defined, they may have a value of
     *
     *   0 - not enabled (also the equivalent of not defined)
     *   1 - enabled
     *
     * The naming convention is generally an exact match of wolfSSL macros
     * in the Kconfig file. At cmake time, the Kconfig is processed and an
     * sdkconfig.h file is created by the ESP-IDF. Any configured options are
     * named CONFIG_[Kconfig name] and thus CONFIG_[macro name]. Those that
     * are expected to be ESP-IDF specific and may be ambiguous can named
     * with an ESP prefix, for example CONFIG_[ESP_(Kconfig name)]
     *
     * Note there are some inconsistent macro names that may have been
     * used in the esp-wolfssl or other places in the ESP-IDF. They should
     * be always be included for backward compatibility.
     *
     * See also: Espressif api-reference kconfig docs.
     *
     * These settings should be checked and assigned wolfssl equivalents before
     * any others.
     *
     * Only the actual config settings should be defined here. Any others that
     * may be application specific should be conditionally defined in the
     * respective user_settings.h file.
     *
     * See the template example for reference:
     * https://github.com/wolfSSL/wolfssl/tree/master/IDE/Espressif/ESP-IDF/examples/template
     *
     * Reminder that by the time we are here, the user_settings.h has already
     * been processed. The following settings are additive; Enabled settings
     * from user_settings are not disabled here.
     */
    #if defined(CONFIG_ESP_WOLFSSL_TEST_LOOP) && \
                CONFIG_ESP_WOLFSSL_TEST_LOOP
        #define            WOLFSSL_TEST_LOOP 1
    #else
        #define            WOLFSSL_TEST_LOOP 0
    #endif
    #if (defined(CONFIG_DEBUG_WOLFSSL) &&             \
                 CONFIG_DEBUG_WOLFSSL) ||             \
        (defined(CONFIG_ESP_WOLFSSL_DEBUG_WOLFSSL) && \
                 CONFIG_ESP_WOLFSSL_DEBUG_WOLFSSL  )
        #define                     DEBUG_WOLFSSL
    #endif
    #if defined(CONFIG_ESP_WOLFSSL_ENABLE_WOLFSSH) && \
                CONFIG_ESP_WOLFSSL_ENABLE_WOLFSSH
        #define            WOLFSSL_ENABLE_WOLFSSH
    #endif
    #if (defined(CONFIG_TEST_ESPIDF_ALL_WOLFSSL) && \
                 CONFIG_TEST_ESPIDF_ALL_WOLFSSL   )
        #define         TEST_ESPIDF_ALL_WOLFSSL
    #endif
    #if (defined(CONFIG_WOLFSSL_ALT_CERT_CHAINS) && \
                 CONFIG_WOLFSSL_ALT_CERT_CHAINS   )
        #define         WOLFSSL_ALT_CERT_CHAINS
    #endif
    #if defined(CONFIG_WOLFSSL_ASN_ALLOW_0_SERIAL) && \
                CONFIG_WOLFSSL_ASN_ALLOW_0_SERIAL
        #define        WOLFSSL_ASN_ALLOW_0_SERIAL
    #endif
    #if defined(CONFIG_WOLFSSL_NO_ASN_STRICT) && \
                CONFIG_WOLFSSL_NO_ASN_STRICT
        #define        WOLFSSL_NO_ASN_STRICT
    #endif
    #if defined(CONFIG_WOLFSSL_DEBUG_CERT_BUNDLE) && \
                CONFIG_WOLFSSL_DEBUG_CERT_BUNDLE
        #define        WOLFSSL_DEBUG_CERT_BUNDLE
    #endif
    #if defined(CONFIG_USE_WOLFSSL_ESP_SDK_TIME) && \
                CONFIG_USE_WOLFSSL_ESP_SDK_TIME
        #define        USE_WOLFSSL_ESP_SDK_TIME
    #endif
    #if defined(CONFIG_USE_WOLFSSL_ESP_SDK_WIFI) && \
                CONFIG_USE_WOLFSSL_ESP_SDK_WIFI
        #define        USE_WOLFSSL_ESP_SDK_WIFI
    #endif
    #if defined(CONFIG_WOLFSSL_APPLE_HOMEKIT) && \
                CONFIG_WOLFSSL_APPLE_HOMEKIT
        #define        WOLFSSL_APPLE_HOMEKIT
    #endif
    #if defined(CONFIG_ESP_WOLFSSL_DEBUG_ESP_HW_MULTI_RSAMAX_BITS) && \
                CONFIG_ESP_WOLFSSL_DEBUG_ESP_HW_MULTI_RSAMAX_BITS
        #define            WOLFSSL_DEBUG_ESP_HW_MULTI_RSAMAX_BITS
    #endif
    #if defined(CONFIG_ESP_WOLFSSL_DEBUG_ESP_HW_MOD_RSAMAX_BITS) && \
                CONFIG_ESP_WOLFSSL_DEBUG_ESP_HW_MOD_RSAMAX_BITS
        #define            WOLFSSL_DEBUG_ESP_HW_MOD_RSAMAX_BITS
    #endif

    #if defined(CONFIG_TLS_STACK_WOLFSSL) && (CONFIG_TLS_STACK_WOLFSSL)
        /* When using ESP-TLS, some old algorithms such as SHA1 are no longer
         * enabled in wolfSSL, except for the OpenSSL compatibility. So enable
         * that here: */
        #define OPENSSL_EXTRA
    #endif

    /* Optional Apple HomeKit support. See below for related sanity checks. */
    #if defined(WOLFSSL_APPLE_HOMEKIT)
        /* SRP is known to need 8K; slow on some devices */
        #undef  FP_MAX_BITS
        #define FP_MAX_BITS (8192 * 2)
        #define WOLFCRYPT_HAVE_SRP
        #define HAVE_CHACHA
        #define HAVE_POLY1305
        #define WOLFSSL_BASE64_ENCODE
        #define HAVE_HKDF
        #define WOLFSSL_SHA512
     #endif

    /* Enable benchmark code via menuconfig, or when not otherwise disable: */
    #ifdef CONFIG_ESP_WOLFSSL_ENABLE_BENCHMARK
        #ifdef NO_CRYPT_BENCHMARK
            #pragma message("Benchmark conflict:")
            #pragma message("-- NO_CRYPT_BENCHMARK defined.")
            #pragma message("-- CONFIG_WOLFSSL_ENABLE_BENCHMARK also defined.")
            #pragma message("-- NO_CRYPT_BENCHMARK will be undefined.")
            #undef NO_CRYPT_BENCHMARK
        #endif
    #endif

    #if !defined(NO_CRYPT_BENCHMARK) || \
         defined(CONFIG_ESP_WOLFSSL_ENABLE_BENCHMARK)

        #define BENCH_EMBEDDED
        #define WOLFSSL_BENCHMARK_FIXED_UNITS_KB

        /* See wolfcrypt/benchmark/benchmark.c for debug and other settings: */

        /* Turn on benchmark timing debugging (CPU Cycles, RTOS ticks, etc) */
        #ifdef CONFIG_ESP_DEBUG_WOLFSSL_BENCHMARK_TIMING
            #define DEBUG_WOLFSSL_BENCHMARK_TIMING
        #endif

        /* Turn on timer debugging (used when CPU cycles not available) */
        #ifdef CONFIG_ESP_WOLFSSL_BENCHMARK_TIMER_DEBUG
            #define WOLFSSL_BENCHMARK_TIMER_DEBUG
        #endif
    #endif

    /* Typically only used in tests, but available to all apps is
     * the "enable all" feature: */
    #if defined(TEST_ESPIDF_ALL_WOLFSSL)
        #define WOLFSSL_MD2
        #define HAVE_BLAKE2
        #define HAVE_BLAKE2B
        #define HAVE_BLAKE2S

        #define WC_RC2
        #define WOLFSSL_ALLOW_RC4

        #define HAVE_POLY1305

        #define WOLFSSL_AES_128
        #define WOLFSSL_AES_OFB
        #define WOLFSSL_AES_CFB
        #define WOLFSSL_AES_XTS

        /* #define WC_SRTP_KDF */
        /* TODO Causes failure with Espressif AES HW Enabled */
        /* #define HAVE_AES_ECB */
        /* #define HAVE_AESCCM  */
        /* TODO sanity check when missing HAVE_AES_ECB */
        #define WOLFSSL_WOLFSSH

        #define HAVE_AESGCM
        #define WOLFSSL_AES_COUNTER

        #define HAVE_FFDHE
        #define HAVE_FFDHE_2048
        #if defined(CONFIG_IDF_TARGET_ESP8266)
            /* TODO Full size SRP is disabled on the ESP8266 at this time.
             * Low memory issue? */
            #define WOLFCRYPT_HAVE_SRP
            /* MIN_FFDHE_FP_MAX_BITS = (MIN_FFDHE_BITS * 2); see settings.h */
            #define FP_MAX_BITS MIN_FFDHE_FP_MAX_BITS
        #elif defined(CONFIG_IDF_TARGET_ESP32)   || \
              defined(CONFIG_IDF_TARGET_ESP32S2) || \
              defined(CONFIG_IDF_TARGET_ESP32S3)
            #define WOLFCRYPT_HAVE_SRP
            #define FP_MAX_BITS (8192 * 2)
        #elif defined(CONFIG_IDF_TARGET_ESP32C3) || \
              defined(CONFIG_IDF_TARGET_ESP32H2)
            /* SRP Known to be working on this target::*/
            #define WOLFCRYPT_HAVE_SRP
            #define FP_MAX_BITS (8192 * 2)
        #else
            /* For everything else, give a try and see if SRP working: */
            #define WOLFCRYPT_HAVE_SRP
            #define FP_MAX_BITS (8192 * 2)
        #endif

        #define HAVE_DH

        /* TODO: there may be a problem with HAVE_CAMELLIA with HW AES disabled.
         * Do not define NO_WOLFSSL_ESP32_CRYPT_AES when enabled: */
        /* #define HAVE_CAMELLIA */

        /* DSA requires old SHA */
        #define HAVE_DSA

        /* Needs SHA512 ? */
        #define HAVE_HPKE

        /* Not for Espressif? */
        #if defined(CONFIG_IDF_TARGET_ESP32C2) || \
            defined(CONFIG_IDF_TARGET_ESP8684) || \
            defined(CONFIG_IDF_TARGET_ESP32H2) || \
            defined(CONFIG_IDF_TARGET_ESP8266)

            #if defined(CONFIG_IDF_TARGET_ESP8266)
                #undef HAVE_ECC
                #undef HAVE_ECC_CDH
                #undef HAVE_CURVE25519

                #ifdef HAVE_CHACHA
                    #error "HAVE_CHACHA not supported on ESP8266"
                #endif
                #ifdef HAVE_XCHACHA
                    #error "HAVE_XCHACHA not supported on ESP8266"
                #endif
            #else
                #define HAVE_XCHACHA
                #define HAVE_CHACHA
                /* TODO Not enabled at this time, needs further testing:
                 *   #define WC_SRTP_KDF
                 *   #define HAVE_COMP_KEY
                 *   #define WOLFSSL_HAVE_XMSS
                 */
            #endif
            /* TODO AES-EAX needs stesting on this platform */

            /* Optionally disable DH
             *   #undef HAVE_DH
             *   #undef HAVE_FFDHE
             */

            /* ECC_SHAMIR out of memory on ESP32-C2 during ECC  */
            #ifndef HAVE_ECC
                #define ECC_SHAMIR
            #endif
        #else
            #define WOLFSSL_AES_EAX

            #define ECC_SHAMIR
        #endif

        /* Only for WOLFSSL_IMX6_CAAM / WOLFSSL_QNX_CAAM ? */
        /* #define WOLFSSL_CAAM      */
        /* #define WOLFSSL_CAAM_BLOB */

        #define WOLFSSL_AES_SIV
        #define WOLFSSL_CMAC

        #define WOLFSSL_CERT_PIV

        /* HAVE_SCRYPT may turn on HAVE_PBKDF2 see settings.h */
        /* #define HAVE_SCRYPT */
        #define SCRYPT_TEST_ALL
        #define HAVE_X963_KDF
    #endif

    /* Optionally enable some wolfSSH settings via compiler def or Kconfig */
    #if defined(ESP_ENABLE_WOLFSSH)
        /* The default SSH Windows size is massive for an embedded target.
         * Limit it: */
        #define DEFAULT_WINDOW_SZ 2000

        /* These may be defined in cmake for other examples: */
        #undef  WOLFSSH_TERM
        #define WOLFSSH_TERM

        #if defined(CONFIG_ESP_WOLFSSL_DEBUG_WOLFSSH)
            /* wolfSSH debugging enabled via Kconfig / menuconfig */
            #undef  DEBUG_WOLFSSH
            #define DEBUG_WOLFSSH
        #endif

        #undef  WOLFSSL_KEY_GEN
        #define WOLFSSL_KEY_GEN

        #undef  WOLFSSL_PTHREADS
        #define WOLFSSL_PTHREADS

        #define WOLFSSH_TEST_SERVER
        #define WOLFSSH_TEST_THREADING

    #endif /* ESP_ENABLE_WOLFSSH */

    /* Experimental Kyber.  */
    #ifdef CONFIG_ESP_WOLFSSL_ENABLE_KYBER
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

    #ifndef NO_ESPIDF_DEFAULT
        #define FREERTOS
        #define WOLFSSL_LWIP
        #define NO_WRITEV
        #define NO_WOLFSSL_DIR
        #define WOLFSSL_NO_CURRDIR

        #define TFM_TIMING_RESISTANT
        #define ECC_TIMING_RESISTANT

        /* WC_RSA_BLINDING takes up extra space! */
        #define WC_RSA_BLINDING

        /* Cache Resistant features are  on by default, but has performance
         * penalty on embedded systems. May not be needed here. Disabled: */
        #define WC_NO_CACHE_RESISTANT
    #endif /* !WOLFSSL_ESPIDF_NO_DEFAULT */

    #if defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA384) && \
       !defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512)
        #error "NO_WOLFSSL_ESP32_CRYPT_HASH_SHA384 cannot be defined without" \
               "NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512 (enable or disable both)"
    #endif
    #if defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512) && \
       !defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA384)
        #error "NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512 cannot be defined without" \
               "NO_WOLFSSL_ESP32_CRYPT_HASH_SHA384 (enable or disable both)"
    #endif
#if defined(WOLFSSL_ESPWROOM32)
    /* WOLFSSL_ESPWROOM32 is a legacy macro gate.
    ** Not be be confused with WOLFSSL_ESPWROOM32SE, naming a specific board */
    #undef WOLFSSL_ESP32
    #define WOLFSSL_ESP32
#endif

#if defined(NO_ESP32WROOM32_CRYPT)
    #undef NO_ESP32WROOM32_CRYPT
    #define NO_ESP32_CRYPT
    #error "Please use NO_ESP32_CRYPT not NO_ESP32WROOM32_CRYPT"
#endif

#if defined(NO_WOLFSSL_ESP32WROOM32_CRYPT_HASH)
    #undef NO_WOLFSSL_ESP32WROOM32_CRYPT_HASH
    #define NO_WOLFSSL_ESP32_CRYPT_HASH
    #error "Please use NO_WOLFSSL_ESP32_CRYPT_HASH not NO_ESP32WROOM32_CRYPT"
#endif

#if defined(NO_WOLFSSL_ESP32WROOM32_CRYPT_AES)
    #undef NO_WOLFSSL_ESP32WROOM32_CRYPT_AES
    #define NO_WOLFSSL_ESP32_CRYPT_AES
    #error "Please use NO_WOLFSSL_ESP32_CRYPT_AES" \
           " not " "NO_WOLFSSL_ESP32WROOM32_CRYPT_AES"
#endif

#if defined(NO_WOLFSSL_ESP32WROOM32_CRYPT_RSA_PRI)
    #undef NO_WOLFSSL_ESP32WROOM32_CRYPT_RSA_PRI
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI
    #error "Please use NO_WOLFSSL_ESP32_CRYPT_RSA_PRI" \
           " not " "NO_WOLFSSL_ESP32WROOM32_CRYPT_RSA_PRI"
#endif

#if defined(WOLFSSL_ESP32) || defined(WOLFSSL_ESPWROOM32SE)
    #ifndef NO_ESP32_CRYPT
        #define WOLFSSL_ESP32_CRYPT
        #if defined(ESP32_USE_RSA_PRIMITIVE) && \
            !defined(NO_WOLFSSL_ESP32_CRYPT_RSA_PRI)
            #define WOLFSSL_ESP32_CRYPT_RSA_PRI
            #define WOLFSSL_SMALL_STACK
        #endif
    #endif

    #if defined(WOLFSSL_SP_RISCV32)
        #if defined(CONFIG_IDF_TARGET_ESP32C2) || \
            defined(CONFIG_IDF_TARGET_ESP32C3) || \
            defined(CONFIG_IDF_TARGET_ESP32C6)
            /* ok, only the known C2, C3, C6 chips allowed */
        #else
            #error "WOLFSSL_SP_RISCV32 can only be used on RISC-V architecture"
        #endif
    #endif
    #if defined(WOLFSSL_SM2) || defined(WOLFSSL_SM3) || defined(WOLFSSL_SM4)
        /* SM settings */
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

        #undef  HAVE_POLY1305
        #define HAVE_POLY1305

        #undef  HAVE_CHACHA
        #define HAVE_CHACHA

        #undef  HAVE_AESGCM
        #define HAVE_AESGCM
    #endif /* SM */

#endif /* defined(WOLFSSL_ESP32) || defined(WOLFSSL_ESPWROOM32SE) */
    /* Final device-specific hardware settings. user_settings.h loaded above. */

    /* Counters for RSA wait timeout. CPU and frequency specific. */
    #define ESP_RSA_WAIT_TIMEOUT_CNT          0x000020
    #if defined(CONFIG_IDF_TARGET_ESP32) || defined(WOLFSSL_ESPWROOM32SE)
        #ifndef ESP_RSA_TIMEOUT_CNT
            #define ESP_RSA_TIMEOUT_CNT      0x349F00
        #endif
    #elif defined(CONFIG_IDF_TARGET_ESP32S2)
        #ifndef ESP_RSA_TIMEOUT_CNT
            #define ESP_RSA_TIMEOUT_CNT      0x349F00
        #endif
    #elif defined(CONFIG_IDF_TARGET_ESP32S3)
        #ifndef ESP_RSA_TIMEOUT_CNT
            /* Observed: 0xAE8C8F @ 80MHz */
            #define ESP_RSA_TIMEOUT_CNT      0xAF0000
        #endif
    #elif defined(CONFIG_IDF_TARGET_ESP32C2)
        /* See also CONFIG_IDF_TARGET_ESP8684 equivalent */
        #ifndef ESP_RSA_TIMEOUT_CNT
            #define ESP_RSA_TIMEOUT_CNT      0x349F00
        #endif
    #elif defined(CONFIG_IDF_TARGET_ESP32C3)
        #ifndef ESP_RSA_TIMEOUT_CNT
            /* Observed: 0x2624B2 @ 80MHz */
            #define ESP_RSA_TIMEOUT_CNT      0x280000
        #endif
    #elif defined(CONFIG_IDF_TARGET_ESP32C6)
        #ifndef ESP_RSA_TIMEOUT_CNT
            /* Observed: 144323 @ 80MHz */
            #define ESP_RSA_TIMEOUT_CNT      0x160000
        #endif
    #elif defined(CONFIG_IDF_TARGET_ESP32H2)
        #ifndef ESP_RSA_TIMEOUT_CNT
            #define ESP_RSA_TIMEOUT_CNT      0x349F00
        #endif
    #elif defined(CONFIG_IDF_TARGET_ESP8266)
        #ifndef ESP_RSA_TIMEOUT_CNT
            #define ESP_RSA_TIMEOUT_CNT      0x349F00
        #endif
    #elif defined(CONFIG_IDF_TARGET_ESP8684)
        /* See also CONFIG_IDF_TARGET_ESP8684 equivalent */
        #ifndef ESP_RSA_TIMEOUT_CNT
            #define ESP_RSA_TIMEOUT_CNT      0x349F00
        #endif
    #else
        #ifndef ESP_RSA_TIMEOUT_CNT
            #define ESP_RSA_TIMEOUT_CNT      0x349F00
        #endif
    #endif
#endif /* WOLFSSL_ESPIDF */

#if defined(WOLFSSL_RENESAS_TSIP)
    #define TSIP_TLS_HMAC_KEY_INDEX_WORDSIZE 64
    #define TSIP_TLS_MASTERSECRET_SIZE       80   /* 20 words */
    #define TSIP_TLS_ENCPUBKEY_SZ_BY_CERTVRFY 560 /* in byte  */

    #ifdef WOLF_CRYPTO_CB
        /* make sure RSA padding callbacks are enabled */
        #define WOLF_CRYPTO_CB_RSA_PAD
    #endif
#endif /* WOLFSSL_RENESAS_TSIP */

#if !defined(WOLFSSL_NO_HASH_RAW) && defined(WOLFSSL_RENESAS_RX64_HASH)
    /* RAW hash function APIs are not implemented with RX64 hardware acceleration */
    #define WOLFSSL_NO_HASH_RAW
#endif

#if defined(WOLFSSL_RENESAS_SCEPROTECT)
    #define FSPSM_TLS_MASTERSECRET_SIZE         80  /* 20 words */
    #define TSIP_TLS_HMAC_KEY_INDEX_WORDSIZE  64
    #define TSIP_TLS_ENCPUBKEY_SZ_BY_CERTVRFY 560   /* in bytes */
    #define FSPSM_TLS_CLIENTRANDOM_SZ           36  /* in bytes */
    #define FSPSM_TLS_SERVERRANDOM_SZ           36  /* in bytes */
    #define FSPSM_TLS_ENCRYPTED_ECCPUBKEY_SZ    96  /* in bytes */

    #define WOLFSSL_RENESAS_FSPSM_ECC
    #if defined(WOLFSSL_RENESAS_FSPSM_ECC)
        #define HAVE_PK_CALLBACKS
        /* #define DEBUG_PK_CB */
    #endif
#endif
#if defined(WOLFSSL_RENESAS_RA6M3G) || defined(WOLFSSL_RENESAS_RA6M3) ||\
              defined(WOLFSSL_RENESAS_RA6M4)
    /* settings in user_settings.h */
#endif

#if defined(WOLFSSL_LWIP_NATIVE) || \
    defined(HAVE_LWIP_NATIVE) /* using LwIP native TCP socket */
    #undef WOLFSSL_USER_IO
    #define WOLFSSL_USER_IO

    #if defined(HAVE_LWIP_NATIVE)
    #define WOLFSSL_LWIP
    #define NO_WRITEV
    #define SINGLE_THREADED
    #define NO_FILESYSTEM
    #endif
#endif

#if defined(WOLFSSL_CONTIKI)
    #include <contiki.h>
    #define WOLFSSL_UIP
    #define NO_WOLFSSL_MEMORY
    #define NO_WRITEV
    #define SINGLE_THREADED
    #define WOLFSSL_USER_IO
    #define NO_FILESYSTEM
    #ifndef CUSTOM_RAND_GENERATE
        #define CUSTOM_RAND_TYPE uint16_t
        #define CUSTOM_RAND_GENERATE random_rand
    #endif
    static inline word32 LowResTimer(void)
    {
       return clock_seconds();
    }
#endif

#if defined(WOLFSSL_IAR_ARM) || defined(WOLFSSL_ROWLEY_ARM)
    #define NO_MAIN_DRIVER
    #define SINGLE_THREADED
    #if !defined(USE_CERT_BUFFERS_2048) && !defined(USE_CERT_BUFFERS_4096)
        #define USE_CERT_BUFFERS_1024
    #endif
    #define BENCH_EMBEDDED
    #define NO_FILESYSTEM
    #define NO_WRITEV
    #define WOLFSSL_USER_IO
    #define BENCH_EMBEDDED
#endif

#ifdef MICROCHIP_PIC32
    /* #define WOLFSSL_MICROCHIP_PIC32MZ */
    #define SIZEOF_LONG_LONG 8
    #define SINGLE_THREADED
    #ifndef MICROCHIP_TCPIP_BSD_API
        #define WOLFSSL_USER_IO
    #endif
    #define NO_WRITEV
    #define NO_DEV_RANDOM
    #define NO_FILESYSTEM
    #define TFM_TIMING_RESISTANT
#endif

#ifdef WOLFSSL_MICROCHIP_PIC32MZ
    #define WOLFSSL_HAVE_MIN
    #define WOLFSSL_HAVE_MAX

    #ifndef NO_PIC32MZ_CRYPT
        #define WOLFSSL_PIC32MZ_CRYPT
    #endif
    #ifndef NO_PIC32MZ_RNG
        #define WOLFSSL_PIC32MZ_RNG
    #endif
    #ifndef NO_PIC32MZ_HASH
        #define WOLFSSL_PIC32MZ_HASH
    #endif
#endif

#ifdef MICROCHIP_TCPIP_V5
    /* include timer functions */
    #include "TCPIP Stack/TCPIP.h"
#endif

#ifdef MICROCHIP_TCPIP
    /* include timer, NTP functions */
    #ifdef MICROCHIP_MPLAB_HARMONY
        #include "tcpip/tcpip.h"
    #else
        #include "system/system_services.h"
        #include "tcpip/sntp.h"
    #endif
#endif

#ifdef WOLFSSL_ATECC508A
    /* backwards compatibility */
#ifndef WOLFSSL_ATECC_NO_ECDH_ENC
    #define WOLFSSL_ATECC_ECDH_ENC
#endif
    #ifdef WOLFSSL_ATECC508A_DEBUG
        #define WOLFSSL_ATECC_DEBUG
    #endif
#endif

#ifdef MBED
    #define WOLFSSL_USER_IO
    #define NO_FILESYSTEM
    #define NO_CERTS
    #if !defined(USE_CERT_BUFFERS_2048) && !defined(USE_CERT_BUFFERS_4096)
        #define USE_CERT_BUFFERS_1024
    #endif
    #define NO_WRITEV
    #define NO_DEV_RANDOM
    #define NO_SHA512
    #define NO_DH
    /* Allows use of DH with fixed points if uncommented and NO_DH is removed */
    /* WOLFSSL_DH_CONST */
    #define NO_DSA
    #define HAVE_ECC
    #define NO_SESSION_CACHE
    #define WOLFSSL_CMSIS_RTOS
#endif


#ifdef WOLFSSL_EROAD
    #define FREESCALE_MQX
    #define FREESCALE_MMCAU
    #define SINGLE_THREADED
    #define NO_STDIO_FILESYSTEM
    #define WOLFSSL_LEANPSK
    #define HAVE_NULL_CIPHER
    #define NO_OLD_TLS
    #define NO_ASN
    #define NO_BIG_INT
    #define NO_RSA
    #define NO_DSA
    #define NO_DH
    /* Allows use of DH with fixed points if uncommented and NO_DH is removed */
    /* WOLFSSL_DH_CONST */
    #define NO_CERTS
    #define NO_PWDBASED
    #define NO_DES3
    #define NO_MD4
    #define NO_RC4
    #define NO_MD5
    #define NO_SESSION_CACHE
    #define NO_MAIN_DRIVER
#endif

#ifdef WOLFSSL_PICOTCP
    #ifndef errno
        #define errno pico_err
    #endif
    #include "pico_defines.h"
    #include "pico_stack.h"
    #include "pico_constants.h"
    #include "pico_protocol.h"
    #ifndef CUSTOM_RAND_GENERATE
        #define CUSTOM_RAND_GENERATE pico_rand
    #endif
#endif

#ifdef WOLFSSL_PICOTCP_DEMO
    #define WOLFSSL_STM32
    #define TFM_TIMING_RESISTANT
    #define XMALLOC(s, h, type)  ((void)(h), (void)(type), PICO_ZALLOC((s)))
    #define XFREE(p, h, type)    ((void)(h), (void)(type), PICO_FREE((p)))
    #define SINGLE_THREADED
    #define NO_WRITEV
    #define WOLFSSL_USER_IO
    #define NO_DEV_RANDOM
    #define NO_FILESYSTEM
#endif

#ifdef FREERTOS_WINSIM
    #define FREERTOS
    #define USE_WINDOWS_API
#endif


#ifdef WOLFSSL_VXWORKS
    /* VxWorks simulator incorrectly detects building for i386 */
    #ifdef VXWORKS_SIM
        #define TFM_NO_ASM
    #endif
    /* For VxWorks pthreads wrappers for mutexes uncomment the next line. */
    /* #define WOLFSSL_PTHREADS */
    #define WOLFSSL_HAVE_MIN
    #define WOLFSSL_HAVE_MAX
    #define NO_MAIN_DRIVER
    #define NO_DEV_RANDOM
    #define NO_WRITEV
    #define HAVE_STRINGS_H
#endif


#ifdef WOLFSSL_ARDUINO
    /* Define WOLFSSL_USER_IO here to avoid check in internal.c */
    #define WOLFSSL_USER_IO

    #define NO_WRITEV
    #define NO_WOLFSSL_DIR
    #define SINGLE_THREADED
    #define NO_DEV_RANDOM
    #if defined(INTEL_GALILEO) || defined(ESP32)
        /* boards with has time.h compatibility */
    #elif defined(__arm__)
        /* TODO is time really missing from Arduino Due? */
        /* This is a brute-force solution to make it work: */
        #define NO_ASN_TIME
    #else
        #define TIME_OVERRIDES
        #ifndef XTIME
            #error "Must define XTIME externally see porting guide"
            #error "https://www.wolfssl.com/docs/porting-guide/"
        #endif
        #ifndef XGMTIME
            #error "Must define XGMTIME externally see porting guide"
            #error "https://www.wolfssl.com/docs/porting-guide/"
        #endif
    #endif
    #define WOLFSSL_USER_IO
    #define HAVE_ECC
    #define NO_DH
    #define NO_SESSION_CACHE
#endif


#ifdef WOLFSSL_UTASKER
    /* uTasker configuration - used for fnRandom() */
    #include "config.h"

    #define SINGLE_THREADED
    #define NO_WOLFSSL_DIR
    #define WOLFSSL_HAVE_MIN
    #define NO_WRITEV

    #define HAVE_ECC
    #define ALT_ECC_SIZE
    #define TFM_TIMING_RESISTANT
    #define ECC_TIMING_RESISTANT

    /* used in wolfCrypt test */
    #define NO_MAIN_DRIVER
    #define USE_CERT_BUFFERS_2048

    /* uTasker port uses RAW sockets, use I/O callbacks
     * See wolfSSL uTasker example for sample callbacks */
    #define WOLFSSL_USER_IO

    /* uTasker filesystem not ported  */
    #define NO_FILESYSTEM

    /* uTasker RNG is abstracted, calls HW RNG when available */
    #define CUSTOM_RAND_GENERATE    fnRandom
    #define CUSTOM_RAND_TYPE        unsigned short

    /* user needs to define XTIME to function that provides
     * seconds since Unix epoch */
    #ifndef XTIME
        #error XTIME must be defined in wolfSSL settings.h
        /* #define XTIME fnSecondsSinceEpoch */
    #endif

    /* use uTasker std library replacements where available */
    #define STRING_USER
    #define XMEMCPY(d,s,l)         uMemcpy((d),(s),(l))
    #define XMEMSET(b,c,l)         uMemset((b),(c),(l))
    #define XMEMCMP(s1,s2,n)       uMemcmp((s1),(s2),(n))
    #define XMEMMOVE(d,s,l)        memmove((d),(s),(l))

    #define XSTRLEN(s1)            uStrlen((s1))
    #define XSTRNCPY(s1,s2,n)      strncpy((s1),(s2),(n))
    #define XSTRSTR(s1,s2)         strstr((s1),(s2))
    #define XSTRNSTR(s1,s2,n)      mystrnstr((s1),(s2),(n))
    #define XSTRNCMP(s1,s2,n)      strncmp((s1),(s2),(n))
    #define XSTRNCAT(s1,s2,n)      strncat((s1),(s2),(n))
    #define XSTRNCASECMP(s1,s2,n)  _strnicmp((s1),(s2),(n))
    #if defined(WOLFSSL_CERT_EXT) || defined(OPENSSL_EXTRA) || \
        defined(OPENSSL_ALL) || defined(HAVE_ALPN)
        #define XSTRTOK            strtok_r
    #endif
#endif

#ifdef WOLFSSL_EMBOS
    #define NO_FILESYSTEM           /* Not ported at this time */
    #define USE_CERT_BUFFERS_2048   /* use when NO_FILESYSTEM */
    #define NO_MAIN_DRIVER
    #define NO_RC4
#endif

#ifdef WOLFSSL_RIOT_OS
    #define TFM_NO_ASM
    #define NO_FILESYSTEM
    #define USE_CERT_BUFFERS_2048
    #if defined(WOLFSSL_GNRC) && !defined(WOLFSSL_DTLS)
        #define WOLFSSL_DTLS
    #endif
#endif

#ifdef WOLFSSL_CHIBIOS
    /* ChibiOS definitions. This file is distributed with chibiOS. */
    #include "wolfssl_chibios.h"
#endif

#ifdef WOLFSSL_PB
    /* PB is using older 1.2 version of Nucleus */
    #undef WOLFSSL_NUCLEUS
    #define WOLFSSL_NUCLEUS_1_2
#endif

#ifdef WOLFSSL_NUCLEUS_1_2
    #define NO_WRITEV
    #define NO_WOLFSSL_DIR

    #if !defined(NO_ASN_TIME) && !defined(USER_TIME)
        #error User must define XTIME, see manual
    #endif

    #if !defined(XMALLOC_OVERRIDE) && !defined(XMALLOC_USER)
        extern void* nucleus_malloc(unsigned long size, void* heap, int type);
        extern void* nucleus_realloc(void* ptr, unsigned long size, void* heap,
                                     int type);
        extern void  nucleus_free(void* ptr, void* heap, int type);

        #define XMALLOC(s, h, type)  nucleus_malloc((s), (h), (type))
        #define XREALLOC(p, n, h, t) nucleus_realloc((p), (n), (h), (t))
        #define XFREE(p, h, type)    nucleus_free((p), (h), (type))
    #endif
#endif

#ifdef WOLFSSL_NRF5x
        #define SIZEOF_LONG 4
        #define SIZEOF_LONG_LONG 8
        #define NO_DEV_RANDOM
        #define NO_FILESYSTEM
        #define NO_MAIN_DRIVER
        #define NO_WRITEV
        #define SINGLE_THREADED
        #define TFM_TIMING_RESISTANT
        #define WOLFSSL_NRF51
        #define WOLFSSL_USER_IO
        #define NO_SESSION_CACHE
#endif

/* For platforms where the target OS is not Windows, but compilation is
 * done on Windows/Visual Studio, enable a way to disable USE_WINDOWS_API.
 * Examples: Micrium, TenAsus INtime, uTasker, FreeRTOS simulator */
#if defined(_WIN32) && !defined(MICRIUM) && !defined(FREERTOS) && \
    !defined(FREERTOS_TCP) && !defined(EBSNET) && !defined(WOLFSSL_EROAD) && \
    !defined(WOLFSSL_UTASKER) && !defined(INTIME_RTOS) && \
    !defined(WOLFSSL_NOT_WINDOWS_API)
    #define USE_WINDOWS_API
#endif

#if defined(WOLFSSL_uITRON4)

#define XMALLOC_USER
#include <stddef.h>
#define ITRON_POOL_SIZE 1024*20
extern int uITRON4_minit(size_t poolsz) ;
extern void *uITRON4_malloc(size_t sz) ;
extern void *uITRON4_realloc(void *p, size_t sz) ;
extern void uITRON4_free(void *p) ;

#define XMALLOC(sz, heap, type)     ((void)(heap), (void)(type), uITRON4_malloc(sz))
#define XREALLOC(p, sz, heap, type) ((void)(heap), (void)(type), uITRON4_realloc(p, sz))
#define XFREE(p, heap, type)        ((void)(heap), (void)(type), uITRON4_free(p))
#endif

#if defined(WOLFSSL_uTKERNEL2)
  #ifndef NO_TKERNEL_MEM_POOL
    #define XMALLOC_OVERRIDE
    int   uTKernel_init_mpool(unsigned int sz); /* initializing malloc pool */
    void* uTKernel_malloc(unsigned int sz);
    void* uTKernel_realloc(void *p, unsigned int sz);
    void  uTKernel_free(void *p);
    #define XMALLOC(s, h, type)  ((void)(h), (void)(type), uTKernel_malloc((s)))
    #define XREALLOC(p, n, h, t) ((void)(h), (void)(t), uTKernel_realloc((p), (n)))
    #define XFREE(p, h, type)    ((void)(h), (void)(type), uTKernel_free((p)))
  #endif

  #ifndef NO_STDIO_FGETS_REMAP
    #include <stdio.h>
    #include "tm/tmonitor.h"

    /* static char* gets(char *buff); */
    static char* fgets(char *buff, int sz, XFILE fp) {
        char * s = buff;
        *s = '\0';
        while (1) {
            *s = tm_getchar(-1);
            tm_putchar(*s);
            if (*s == '\r') {
                tm_putchar('\n');
                *s = '\0';
                break;
            }
            s++;
        }
        return buff;
    }
  #endif /* !NO_STDIO_FGETS_REMAP */
#endif


#if defined(WOLFSSL_LEANPSK) && !defined(XMALLOC_USER) && \
        !defined(NO_WOLFSSL_MEMORY) && !defined(WOLFSSL_STATIC_MEMORY)
    #include <stdlib.h>
    #define XMALLOC(s, h, type)  ((void)(h), (void)(type), malloc((s))) /* native heap */
    #define XFREE(p, h, type)    ((void)(h), (void)(type), free((p))) /* native heap */
    #define XREALLOC(p, n, h, t) ((void)(h), (void)(t), realloc((p), (n))) /* native heap */
#endif

#if defined(XMALLOC_USER) && defined(SSN_BUILDING_LIBYASSL)
    #undef  XMALLOC
    #define XMALLOC     yaXMALLOC
    #undef  XFREE
    #define XFREE       yaXFREE
    #undef  XREALLOC
    #define XREALLOC    yaXREALLOC
#endif


#ifdef FREERTOS

    #ifdef PLATFORMIO
        #include <freertos/FreeRTOS.h>
        #include <freertos/task.h>
    #else
        #include "FreeRTOS.h"
        #include <task.h>
    #endif

    #if !defined(XMALLOC_USER) && !defined(NO_WOLFSSL_MEMORY) && \
        !defined(WOLFSSL_STATIC_MEMORY) && !defined(WOLFSSL_TRACK_MEMORY)

        /* XMALLOC */
        #if defined(WOLFSSL_ESPIDF) && \
           (defined(DEBUG_WOLFSSL) || defined(DEBUG_WOLFSSL_MALLOC))
            #include <wolfssl/wolfcrypt/port/Espressif/esp-sdk-lib.h>
            #define XMALLOC(s, h, type)  \
                           ((void)(h), (void)(type), wc_debug_pvPortMalloc( \
                           (s), (__FILE__), (__LINE__), (__FUNCTION__) ))
        #else
            #define XMALLOC(s, h, type)  \
                           ((void)(h), (void)(type), pvPortMalloc((s))) /* native heap */
        #endif

        /* XFREE */
        #define XFREE(p, h, type)    ((void)(h), (void)(type), vPortFree((p))) /* native heap */

        /* XREALLOC */
        #if defined(WOLFSSL_ESPIDF)
            /* In the Espressif EDP-IDF, realloc(p, n) is equivalent to
             *     heap_caps_realloc(p, s, MALLOC_CAP_8BIT)
             * There's no pvPortRealloc available:  */
            #define XREALLOC(p, n, h, t) ((void)(h), (void)(t), realloc((p), (n))) /* native heap */
        #elif defined(USE_INTEGER_HEAP_MATH) || defined(OPENSSL_EXTRA) || \
              defined(OPENSSL_ALL)
            /* FreeRTOS pvPortRealloc() implementation can be found here:
             * https://github.com/wolfSSL/wolfssl-freertos/pull/3/files */
            #define XREALLOC(p, n, h, t) ((void)(h), (void)(t), pvPortRealloc((p), (n)))
        #else
            /* no XREALLOC available */
        #endif
    #endif

    #ifndef NO_WRITEV
        #define NO_WRITEV
    #endif
    #ifndef WOLFSSL_SHA512
        #ifndef NO_SHA512
            #define NO_SHA512
        #endif
    #endif
    #ifndef HAVE_DH
        #ifndef NO_DH
            #define NO_DH
        #endif
    #endif
    #ifndef HAVE_DSA
        #ifndef NO_DSA
            #define NO_DSA
        #endif
    #endif

    #ifndef SINGLE_THREADED
        #ifdef PLATFORMIO
            #include <freertos/semphr.h>
        #else
            #include "semphr.h"
        #endif
    #endif
#endif

#ifdef FREERTOS_TCP
    #if !defined(NO_WOLFSSL_MEMORY) && !defined(XMALLOC_USER) && \
        !defined(WOLFSSL_STATIC_MEMORY)
        #ifndef XMALLOC
            #define XMALLOC(s, h, type)  pvPortMalloc((s)) /* native heap */
        #endif
        #ifndef XFREE
            #define XFREE(p, h, type)    vPortFree((p)) /* native heap */
        #endif
    #endif

    #define WOLFSSL_GENSEED_FORTEST

    #define NO_WOLFSSL_DIR
    #define NO_WRITEV
    #define TFM_TIMING_RESISTANT
    #define NO_MAIN_DRIVER
#endif

#ifdef WOLFSSL_TIRTOS
    #define SIZEOF_LONG_LONG 8
    #define NO_WRITEV
    #define NO_WOLFSSL_DIR

    /* Enable SP math by default, unless fast math
     * specified in user_settings.
     */
    #ifndef USE_FAST_MATH
        #define SP_WORD_SIZE 32
        #define WOLFSSL_HAVE_SP_ECC
        #ifndef NO_RSA
            #define WOLFSSL_HAVE_SP_RSA
        #endif
        #ifndef NO_DH
            #define WOLFSSL_HAVE_SP_DH
        #endif
        #if !defined(NO_RSA) || !defined(NO_DH)
            /* DH/RSA 2048, 3072 and 4096 */
            #if defined(SP_INT_MAX_BITS) && SP_INT_MAX_BITS >= 4096
                #define WOLFSSL_SP_4096
            #endif
        #endif
    #endif
    #define TFM_TIMING_RESISTANT
    #define ECC_TIMING_RESISTANT
    #define WC_RSA_BLINDING
    #define NO_DEV_RANDOM
    #define NO_FILESYSTEM
    #define NO_MAIN_DRIVER
    #ifndef NO_CRYPT_TEST
        #define USE_CERT_BUFFERS_2048
    #endif
    #ifndef DEBUG_WOLFSSL
        #define NO_ERROR_STRINGS
    #endif

    #define HAVE_ECC
    #define HAVE_ALPN
    #define USE_WOLF_STRTOK /* use with HAVE_ALPN */
    #define HAVE_TLS_EXTENSIONS
    #define HAVE_SUPPORTED_CURVES

    #define HAVE_AESGCM

    #ifdef __IAR_SYSTEMS_ICC__
        #pragma diag_suppress=Pa089
    #elif !defined(__GNUC__)
        /* Suppress the sslpro warning */
        #pragma diag_suppress=11
    #endif

    /* Uncomment this setting if your toolchain does not offer time.h header */
    /* #define USER_TIME */
    #include <ti/sysbios/hal/Seconds.h>
    #if defined(__ti__) && !defined(USER_TIME)
        /* TI internal time() offsets by 2208988800 (1990 -> 1970),
         * which overflows signed 32-bit */
        #define NO_TIME_SIGNEDNESS_CHECK
    #endif
#endif

#ifdef EBSNET
    #include "rtip.h"

    /* #define DEBUG_WOLFSSL */
    #define NO_WOLFSSL_DIR  /* tbd */

    #if (POLLOS)
        #define SINGLE_THREADED
    #endif

    #if (defined(RTPLATFORM) && (RTPLATFORM != 0))
        #if (!RTP_LITTLE_ENDIAN)
            #define BIG_ENDIAN_ORDER
        #endif
    #else
        #if (!KS_LITTLE_ENDIAN)
            #define BIG_ENDIAN_ORDER
        #endif
    #endif

    #if (WINMSP3)
        #undef SIZEOF_LONG
        #define SIZEOF_LONG_LONG 8
    #else
        #if !defined(SIZEOF_LONG) && !defined(SIZEOF_LONG_LONG)
            #error settings.h - please implement SIZEOF_LONG and SIZEOF_LONG_LONG
        #endif
    #endif

    #if (WINMSP3)
        #define strtok_r strtok_s
    #endif

    #define XMALLOC(s, h, type) ((void)(h), (void)(type), ((void *)rtp_malloc((s), SSL_PRO_MALLOC)))
    #define XFREE(p, h, type) ((void)(h), (void)(type), rtp_free(p))
    #define XREALLOC(p, n, h, t) ((void)(h), rtp_realloc((p), (n), (t)))

    #if (WINMSP3)
        #define XSTRNCASECMP(s1,s2,n)  _strnicmp((s1),(s2),(n))
    #else
        #ifndef XSTRNCASECMP
            #error settings.h - please implement XSTRNCASECMP - needed for HAVE_ECC
        #endif
    #endif

    #define WOLFSSL_HAVE_MAX
    #define WOLFSSL_HAVE_MIN

    #define TFM_TIMING_RESISTANT
    #define WC_RSA_BLINDING
    #define ECC_TIMING_RESISTANT

    #define HAVE_ECC

#endif /* EBSNET */

#ifdef WOLFSSL_GAME_BUILD
    #define SIZEOF_LONG_LONG 8
#endif

#ifdef WOLFSSL_LSR
    #define HAVE_WEBSERVER
    #define SIZEOF_LONG_LONG 8
    #define WOLFSSL_LOW_MEMORY
    #define NO_WRITEV
    #define NO_SHA512
    #define NO_DH
    /* Allows use of DH with fixed points if uncommented and NO_DH is removed */
    /* WOLFSSL_DH_CONST */
    #define NO_DSA
    #define NO_DEV_RANDOM
    #define NO_WOLFSSL_DIR
    #ifndef NO_FILESYSTEM
        #define LSR_FS
        #include "inc/hw_types.h"
        #include "fs.h"
    #endif
    #define WOLFSSL_LWIP
    #include <errno.h>  /* for tcp errno */
    #define WOLFSSL_SAFERTOS
    #if defined(__IAR_SYSTEMS_ICC__)
        /* enum uses enum */
        #pragma diag_suppress=Pa089
    #endif
#endif

#ifdef WOLFSSL_SAFERTOS
    #ifndef SINGLE_THREADED
        #include "SafeRTOS/semphr.h"
    #endif
    #ifndef WOLFSSL_NO_MALLOC
        #include "SafeRTOS/heap.h"
    #endif
    #if !defined(XMALLOC_USER) && !defined(NO_WOLFSSL_MEMORY) && \
        !defined(WOLFSSL_STATIC_MEMORY)
        #define XMALLOC(s, h, type)  ((void)(h), (void)(type), pvPortMalloc((s))) /* native heap */
        #define XFREE(p, h, type)    ((void)(h), (void)(type), vPortFree((p))) /* native heap */

        /* FreeRTOS pvPortRealloc() implementation can be found here:
            https://github.com/wolfSSL/wolfssl-freertos/pull/3/files */
        #if !defined(USE_FAST_MATH) || defined(HAVE_ED25519) || \
            defined(HAVE_ED448)
            #define XREALLOC(p, n, h, t) ((void)(h), (void)(t), pvPortRealloc((p), (n)))
        #endif
    #endif
#endif

#ifdef WOLFSSL_LOW_MEMORY
    #undef  RSA_LOW_MEM
    #define RSA_LOW_MEM
    #undef  WOLFSSL_SMALL_STACK
    #define WOLFSSL_SMALL_STACK
    #undef  TFM_TIMING_RESISTANT
    #define TFM_TIMING_RESISTANT
#endif

/* To support storing some of the large constant tables in flash memory rather than SRAM.
   Useful for processors that have limited SRAM, such as the AVR family of microtrollers. */
#ifdef WOLFSSL_USE_FLASHMEM
    /* This is supported on the avr-gcc compiler, for more information see:
         https://gcc.gnu.org/onlinedocs/gcc/Named-Address-Spaces.html */
    #define FLASH_QUALIFIER __flash

    /* Copy data out of flash memory and into SRAM */
    #define XMEMCPY_P(pdest, psrc, size) memcpy_P((pdest), (psrc), (size))
#else
#ifndef FLASH_QUALIFIER
    #define FLASH_QUALIFIER
#endif
#endif

#ifdef FREESCALE_MQX_5_0
    /* use normal Freescale MQX port, but with minor changes for 5.0 */
    #define FREESCALE_MQX
#endif

#ifdef FREESCALE_MQX_4_0
    /* use normal Freescale MQX port, but with minor changes for 4.0 */
    #define FREESCALE_MQX
#endif

#ifdef FREESCALE_MQX
    #define FREESCALE_COMMON
    #include "mqx.h"
    #ifndef NO_FILESYSTEM
        #include "mfs.h"
        #if (defined(MQX_USE_IO_OLD) && MQX_USE_IO_OLD) || \
            defined(FREESCALE_MQX_5_0)
            #include "fio.h"
            #define NO_STDIO_FILESYSTEM
        #else
            #include "nio.h"
        #endif
    #endif
    #ifndef SINGLE_THREADED
        #include "mutex.h"
    #endif

    #if !defined(XMALLOC_OVERRIDE) && !defined(XMALLOC_USER)
        #define XMALLOC_OVERRIDE
        #define XMALLOC(s, h, t)    ((void)(h), (void)(t), (void *)_mem_alloc_system((s)))
        #ifdef WOLFSSL_XFREE_NO_NULLNESS_CHECK
            #define XFREE(p, h, t)      {(void)(h); (void)(t); _mem_free(p);}
        #else
            #define XFREE(p, h, t)      {void* xp = (p); (void)(h); (void)(t); if ((xp)) _mem_free((xp));}
        #endif

        /* Note: MQX has no realloc, using fastmath above */
    #endif
    #ifdef USE_FAST_MATH
        /* Undef first to avoid re-definition if user_settings.h defines */
        #undef TFM_TIMING_RESISTANT
        #define TFM_TIMING_RESISTANT
        #undef ECC_TIMING_RESISTANT
        #define ECC_TIMING_RESISTANT
        #undef WC_RSA_BLINDING
        #define WC_RSA_BLINDING
    #endif
#endif

#ifdef FREESCALE_KSDK_MQX
    #define FREESCALE_COMMON
    #include <mqx.h>
    #ifndef NO_FILESYSTEM
        #if (defined(MQX_USE_IO_OLD) && MQX_USE_IO_OLD) || \
            defined(FREESCALE_MQX_5_0)
            #include <fio.h>
        #else
            #include <stdio.h>
            #include <nio.h>
        #endif
    #endif
    #ifndef SINGLE_THREADED
        #include <mutex.h>
    #endif

    #define XMALLOC(s, h, t)    ((void)(h), (void)(t), (void *)_mem_alloc_system((s)))
    #ifdef WOLFSSL_XFREE_NO_NULLNESS_CHECK
        #define XFREE(p, h, t)      {(void)(h); (void)(t); _mem_free(p);}
    #else
        #define XFREE(p, h, t)      {void* xp = (p); (void)(h); (void)(t); if ((xp)) _mem_free((xp));}
    #endif
    #define XREALLOC(p, n, h, t) _mem_realloc((p), (n)) /* since MQX 4.1.2 */

    #define MQX_FILE_PTR FILE *
    #define IO_SEEK_SET  SEEK_SET
    #define IO_SEEK_END  SEEK_END
#endif /* FREESCALE_KSDK_MQX */

#if defined(FREESCALE_FREE_RTOS) || defined(FREESCALE_KSDK_FREERTOS)
    #define NO_FILESYSTEM
    #define WOLFSSL_CRYPT_HW_MUTEX 1

    #if !defined(XMALLOC_USER) && !defined(NO_WOLFSSL_MEMORY)
        #define XMALLOC(s, h, type)  ((void)(h), (void)(type), pvPortMalloc((s))) /* native heap */
        #define XFREE(p, h, type)    ((void)(h), (void)(type), vPortFree((p))) /* native heap */
    #endif

    /* #define USER_TICKS */
    /* Allows use of DH with fixed points if uncommented and NO_DH is removed */
    /* WOLFSSL_DH_CONST */
    #define WOLFSSL_LWIP
    #define FREERTOS_TCP

    #define FREESCALE_FREE_RTOS
    #define FREERTOS_SOCKET_ERROR ( -1 )
    #define FREERTOS_EWOULDBLOCK ( -2 )
    #define FREERTOS_EINVAL ( -4 )
    #define FREERTOS_EADDRNOTAVAIL ( -5 )
    #define FREERTOS_EADDRINUSE ( -6 )
    #define FREERTOS_ENOBUFS ( -7 )
    #define FREERTOS_ENOPROTOOPT ( -8 )
#endif /* FREESCALE_FREE_RTOS || FREESCALE_KSDK_FREERTOS */

#ifdef FREESCALE_KSDK_BM
    #define FREESCALE_COMMON
    #define WOLFSSL_USER_IO
    #define SINGLE_THREADED
    #define NO_FILESYSTEM
    #ifndef TIME_OVERRIDES
        #define USER_TICKS
    #endif
#endif /* FREESCALE_KSDK_BM */

#ifdef FREESCALE_COMMON
    #define SIZEOF_LONG_LONG 8

    /* disable features */
    #undef  NO_WRITEV
    #define NO_WRITEV
    #undef  NO_DEV_RANDOM
    #define NO_DEV_RANDOM
    #undef  NO_WOLFSSL_DIR
    #define NO_WOLFSSL_DIR
    #undef  NO_RC4
    #define NO_RC4

    /* enable features */
    #define USE_CERT_BUFFERS_2048
    #define BENCH_EMBEDDED

    #define TFM_TIMING_RESISTANT
    #define ECC_TIMING_RESISTANT

    #undef  HAVE_ECC
    #ifndef WOLFCRYPT_FIPS_RAND
    #define HAVE_ECC
    #endif
    #ifndef NO_AES
        #undef  HAVE_AESCCM
        #define HAVE_AESCCM
        #undef  HAVE_AESGCM
        #define HAVE_AESGCM
        #undef  WOLFSSL_AES_COUNTER
        #define WOLFSSL_AES_COUNTER
        #undef  WOLFSSL_AES_DIRECT
        #define WOLFSSL_AES_DIRECT
    #endif

    #ifdef FREESCALE_KSDK_1_3
        #include "fsl_device_registers.h"
    #elif !defined(FREESCALE_MQX)
        /* Classic MQX does not have fsl_common.h */
        #include "fsl_common.h"
    #endif

    /* random seed */
    #define NO_OLD_RNGNAME
    #if   defined(FREESCALE_NO_RNG)
        /* nothing to define */
    #elif defined(FSL_FEATURE_SOC_TRNG_COUNT) && (FSL_FEATURE_SOC_TRNG_COUNT > 0)
        #define FREESCALE_KSDK_2_0_TRNG
    #elif defined(FSL_FEATURE_SOC_RNG_COUNT) && (FSL_FEATURE_SOC_RNG_COUNT > 0)
        #ifdef FREESCALE_KSDK_1_3
            #include "fsl_rnga_driver.h"
            #define FREESCALE_RNGA
            #define RNGA_INSTANCE (0)
        #else
            #define FREESCALE_KSDK_2_0_RNGA
        #endif
    #elif !defined(FREESCALE_KSDK_BM) && !defined(FREESCALE_FREE_RTOS) && !defined(FREESCALE_KSDK_FREERTOS)
        #define FREESCALE_RNGA
        #define RNGA_INSTANCE (0)
        /* defaulting to K70 RNGA, user should change if different */
        /* #define FREESCALE_K53_RNGB */
        #define FREESCALE_K70_RNGA
    #endif

    /* HW crypto */
    /* automatic enable based on Kinetis feature */
    /* if case manual selection is required, for example for benchmarking purposes,
     * just define FREESCALE_USE_MMCAU or FREESCALE_USE_LTC or none of these two macros (for software only)
     * both can be enabled simultaneously as LTC has priority over MMCAU in source code.
     */
    /* #define FSL_HW_CRYPTO_MANUAL_SELECTION */
    #ifndef FSL_HW_CRYPTO_MANUAL_SELECTION
        #if defined(FSL_FEATURE_SOC_MMCAU_COUNT) && FSL_FEATURE_SOC_MMCAU_COUNT
            #define FREESCALE_USE_MMCAU
        #endif

        #if defined(FSL_FEATURE_SOC_LTC_COUNT) && FSL_FEATURE_SOC_LTC_COUNT
            #define FREESCALE_USE_LTC
        #endif
    #else
        /* #define FREESCALE_USE_MMCAU */
        /* #define FREESCALE_USE_LTC */
    #endif
#endif /* FREESCALE_COMMON */

/* Classic pre-KSDK mmCAU library */
#ifdef FREESCALE_USE_MMCAU_CLASSIC
    #define FREESCALE_USE_MMCAU
    #define FREESCALE_MMCAU_CLASSIC
    #define FREESCALE_MMCAU_CLASSIC_SHA
#endif

/* KSDK mmCAU library */
#ifdef FREESCALE_USE_MMCAU
    /* AES and DES */
    #define FREESCALE_MMCAU
    /* MD5, SHA-1 and SHA-256 */
    #define FREESCALE_MMCAU_SHA
#endif /* FREESCALE_USE_MMCAU */

#ifdef FREESCALE_USE_LTC
    #if defined(FSL_FEATURE_SOC_LTC_COUNT) && FSL_FEATURE_SOC_LTC_COUNT
        #define FREESCALE_LTC
        #define LTC_BASE LTC0

        #if defined(FSL_FEATURE_LTC_HAS_DES) && FSL_FEATURE_LTC_HAS_DES
            #define FREESCALE_LTC_DES
        #endif

        #if defined(FSL_FEATURE_LTC_HAS_GCM) && FSL_FEATURE_LTC_HAS_GCM
            #define FREESCALE_LTC_AES_GCM
        #endif

        #if defined(FSL_FEATURE_LTC_HAS_SHA) && FSL_FEATURE_LTC_HAS_SHA
            #define FREESCALE_LTC_SHA
        #endif

        #if defined(FSL_FEATURE_LTC_HAS_PKHA) && FSL_FEATURE_LTC_HAS_PKHA
            #ifndef WOLFCRYPT_FIPS_RAND
            #define FREESCALE_LTC_ECC
            #endif
            #define FREESCALE_LTC_TFM

            /* the LTC PKHA hardware limit is 2048 bits (256 bytes) for integer arithmetic.
               the LTC_MAX_INT_BYTES defines the size of local variables that hold big integers. */
            /* size is multiplication of 2 big ints */
            #if !defined(NO_RSA) || !defined(NO_DH)
                #define LTC_MAX_INT_BYTES   (256*2)
            #else
                #define LTC_MAX_INT_BYTES   (48*2)
            #endif

            /* This FREESCALE_LTC_TFM_RSA_4096_ENABLE macro can be defined.
             * In such a case both software and hardware algorithm
             * for TFM is linked in. The decision for which algorithm is used is determined at runtime
             * from size of inputs. If inputs and result can fit into LTC (see LTC_MAX_INT_BYTES)
             * then we call hardware algorithm, otherwise we call software algorithm.
             *
             * Chinese reminder theorem is used to break RSA 4096 exponentiations (both public and private key)
             * into several computations with 2048-bit modulus and exponents.
             */
            /* #define FREESCALE_LTC_TFM_RSA_4096_ENABLE */

            /* ECC-384, ECC-256, ECC-224 and ECC-192 have been enabled with LTC PKHA acceleration */
            #ifdef HAVE_ECC
                #undef  ECC_TIMING_RESISTANT
                #define ECC_TIMING_RESISTANT

                /* the LTC PKHA hardware limit is 512 bits (64 bytes) for ECC.
                   the LTC_MAX_ECC_BITS defines the size of local variables that hold ECC parameters
                   and point coordinates */
                #ifndef LTC_MAX_ECC_BITS
                    #define LTC_MAX_ECC_BITS (384)
                #endif

                /* Enable curves up to 384 bits */
                #if !defined(ECC_USER_CURVES) && !defined(HAVE_ALL_CURVES)
                    #define ECC_USER_CURVES
                    #define HAVE_ECC192
                    #define HAVE_ECC224
                    #undef  NO_ECC256
                    #define HAVE_ECC384
                #endif
            #endif
        #endif
    #endif
#endif /* FREESCALE_USE_LTC */

#ifdef FREESCALE_LTC_TFM_RSA_4096_ENABLE
    #undef  USE_CERT_BUFFERS_4096
    #define USE_CERT_BUFFERS_4096
    #undef  FP_MAX_BITS
    #define FP_MAX_BITS (8192)
    #undef  SP_INT_BITS
    #define SP_INT_BITS (4096)

    #undef  NO_DH
    #define NO_DH
    #undef  NO_DSA
    #define NO_DSA
#endif /* FREESCALE_LTC_TFM_RSA_4096_ENABLE */

/* if LTC has AES engine but doesn't have GCM, use software with LTC AES ECB mode */
#if defined(FREESCALE_USE_LTC) && !defined(FREESCALE_LTC_AES_GCM)
    #define GCM_TABLE
#endif

#if defined(WOLFSSL_MAXQ1065) || defined(WOLFSSL_MAXQ108X)

    #define MAXQ10XX_MODULE_INIT

    #define HAVE_PK_CALLBACKS
    #define WOLFSSL_STATIC_PSK
    /* Server side support to be added at a later date. */
    #define NO_WOLFSSL_SERVER

    /* Need WOLFSSL_PUBLIC_ASN to use ProcessPeerCert callback. */
    #define WOLFSSL_PUBLIC_ASN

    #ifdef HAVE_PTHREAD
        #define WOLFSSL_CRYPT_HW_MUTEX 1
        #define MAXQ10XX_MUTEX
    #endif

    #define WOLFSSL_MAXQ10XX_CRYPTO
    #define WOLFSSL_MAXQ10XX_TLS


    #if defined(WOLFSSL_MAXQ1065)
        #define MAXQ_DEVICE_ID 1065
    #elif defined(WOLFSSL_MAXQ108X)
        #define MAXQ_DEVICE_ID 1080
    #else
        #error "There is only support for MAXQ1065 or MAXQ1080"
    #endif

    #if defined(WOLFSSL_TICKET_NONCE_MALLOC)
        #error "WOLFSSL_TICKET_NONCE_MALLOC disables the HKDF expand callbacks."
    #endif

#endif /* WOLFSSL_MAXQ1065 || WOLFSSL_MAXQ108X */

#if defined(WOLFSSL_STM32F2) || defined(WOLFSSL_STM32F4) || \
    defined(WOLFSSL_STM32F7) || defined(WOLFSSL_STM32F1) || \
    defined(WOLFSSL_STM32L4) || defined(WOLFSSL_STM32L5) || \
    defined(WOLFSSL_STM32WB) || defined(WOLFSSL_STM32H7) || \
    defined(WOLFSSL_STM32G0) || defined(WOLFSSL_STM32U5) || \
    defined(WOLFSSL_STM32H5) || defined(WOLFSSL_STM32WL) || \
    defined(WOLFSSL_STM32G4) || defined(WOLFSSL_STM32MP13)

    #define SIZEOF_LONG_LONG 8
    #ifndef CHAR_BIT
      #define CHAR_BIT 8
    #endif
    #define NO_DEV_RANDOM
    #define NO_WOLFSSL_DIR
    #ifndef NO_STM32_RNG
        #undef  STM32_RNG
        #define STM32_RNG
        #ifdef WOLFSSL_STM32F427_RNG
            #include "stm32f427xx.h"
        #endif
    #endif
    #ifndef NO_STM32_CRYPTO
        #undef  STM32_CRYPTO
        #define STM32_CRYPTO

        #if defined(WOLFSSL_STM32L4) || defined(WOLFSSL_STM32L5) || \
            defined(WOLFSSL_STM32WB) || defined(WOLFSSL_STM32U5) || \
            defined(WOLFSSL_STM32WL)
            #define NO_AES_192 /* hardware does not support 192-bit */
        #endif
    #endif
    #ifndef NO_STM32_HASH
        #undef  STM32_HASH
        #define STM32_HASH
    #endif
    #if !defined(__GNUC__) && !defined(__ICCARM__)
        #define KEIL_INTRINSICS
    #endif
    #define NO_OLD_RNGNAME
    #ifdef WOLFSSL_STM32_CUBEMX
        #if defined(WOLFSSL_STM32F1)
            #include "stm32f1xx_hal.h"
        #elif defined(WOLFSSL_STM32F2)
            #include "stm32f2xx_hal.h"
        #elif defined(WOLFSSL_STM32L5)
            #include "stm32l5xx_hal.h"
        #elif defined(WOLFSSL_STM32L4)
            #include "stm32l4xx_hal.h"
        #elif defined(WOLFSSL_STM32F4)
            #include "stm32f4xx_hal.h"
        #elif defined(WOLFSSL_STM32F7)
            #include "stm32f7xx_hal.h"
        #elif defined(WOLFSSL_STM32F1)
            #include "stm32f1xx_hal.h"
        #elif defined(WOLFSSL_STM32H7)
            #include "stm32h7xx_hal.h"
        #elif defined(WOLFSSL_STM32WB)
            #include "stm32wbxx_hal.h"
        #elif defined(WOLFSSL_STM32WL)
            #include "stm32wlxx_hal.h"
        #elif defined(WOLFSSL_STM32G0)
            #include "stm32g0xx_hal.h"
        #elif defined(WOLFSSL_STM32G4)
            #include "stm32g4xx_hal.h"
        #elif defined(WOLFSSL_STM32U5)
            #include "stm32u5xx_hal.h"
        #elif defined(WOLFSSL_STM32H5)
            #include "stm32h5xx_hal.h"
        #elif defined(WOLFSSL_STM32MP13)
            /* HAL headers error on our ASM files */
            #ifndef __ASSEMBLER__
                #include "stm32mp13xx_hal.h"
                #include "stm32mp13xx_hal_conf.h"
            #endif
        #endif
        #if defined(WOLFSSL_CUBEMX_USE_LL) && defined(WOLFSSL_STM32L4)
            #include "stm32l4xx_ll_rng.h"
        #endif

        #ifndef STM32_HAL_TIMEOUT
            #define STM32_HAL_TIMEOUT   0xFF
        #endif

        #if defined(WOLFSSL_STM32_PKA) && !defined(WOLFSSL_SP_INT_NEGATIVE)
            /* enable the negative support for abs(a) |a| */
            #define WOLFSSL_SP_INT_NEGATIVE
        #endif
    #else
        #if defined(WOLFSSL_STM32F2)
            #include "stm32f2xx.h"
            #ifdef STM32_CRYPTO
                #include "stm32f2xx_cryp.h"
            #endif
            #ifdef STM32_HASH
                #include "stm32f2xx_hash.h"
            #endif
        #elif defined(WOLFSSL_STM32F4)
            #include "stm32f4xx.h"
            #ifdef STM32_CRYPTO
                #include "stm32f4xx_cryp.h"
            #endif
            #ifdef STM32_HASH
                #include "stm32f4xx_hash.h"
            #endif
        #elif defined(WOLFSSL_STM32L5)
            #include "stm32l5xx.h"
            #ifdef STM32_CRYPTO
                #include "stm32l5xx_cryp.h"
            #endif
            #ifdef STM32_HASH
                #include "stm32l5xx_hash.h"
            #endif
        #elif defined(WOLFSSL_STM32L4)
            #include "stm32l4xx.h"
            #ifdef STM32_CRYPTO
                #include "stm32l4xx_cryp.h"
            #endif
            #ifdef STM32_HASH
                #include "stm32l4xx_hash.h"
            #endif
        #elif defined(WOLFSSL_STM32F7)
            #include "stm32f7xx.h"
        #elif defined(WOLFSSL_STM32H7)
            #include "stm32h7xx.h"
        #elif defined(WOLFSSL_STM32F1)
            #include "stm32f1xx.h"
        #endif
    #endif /* WOLFSSL_STM32_CUBEMX */
#endif /* WOLFSSL_STM32* */
#ifdef WOLFSSL_DEOS
    #include <deos.h>
    #include <timeout.h>
    #include <socketapi.h>
    #include <lwip-socket.h>
    #include <mem.h>
    #include <string.h>
    #include <stdlib.h> /* for rand_r: pseudo-random number generator */
    #include <stdio.h>  /* for snprintf */

    /* use external memory XMALLOC, XFREE and XREALLOC functions */
    #define XMALLOC_USER

    /* disable fall-back case, malloc, realloc and free are unavailable */
    #define WOLFSSL_NO_MALLOC

    /* file system has not been ported since it is a separate product. */

    #define NO_FILESYSTEM

    #ifdef NO_FILESYSTEM
        #define NO_WOLFSSL_DIR
        #define NO_WRITEV
    #endif

    #define TFM_TIMING_RESISTANT
    #define ECC_TIMING_RESISTANT
    #define WC_RSA_BLINDING

    #define HAVE_ECC
    #define TFM_ECC192
    #define TFM_ECC224
    #define TFM_ECC256
    #define TFM_ECC384
    #define TFM_ECC521

    #define HAVE_TLS_EXTENSIONS
    #define HAVE_SUPPORTED_CURVES
    #define HAVE_EXTENDED_MASTER

    #if (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
        #define BIG_ENDIAN_ORDER
    #else
        #undef  BIG_ENDIAN_ORDER
        #define LITTLE_ENDIAN_ORDER
    #endif
#endif /* WOLFSSL_DEOS*/

#ifdef MICRIUM
    #include <stdlib.h>
    #include <os.h>
    #include <app_cfg.h>
    #if defined(RTOS_MODULE_NET_AVAIL) || (APP_CFG_TCPIP_EN == DEF_ENABLED)
        #include <net_cfg.h>
        #include <net_sock.h>
        #if (OS_VERSION < 50000)
            #include <net_err.h>
        #endif
    #endif
    #include <lib_mem.h>
    #include <lib_math.h>
    #include <lib_str.h>
    #include  <stdio.h>
    #include <string.h>

    #define TFM_TIMING_RESISTANT
    #define ECC_TIMING_RESISTANT
    #define WC_RSA_BLINDING
    #define HAVE_HASHDRBG

    #define HAVE_ECC
    #if !defined(WOLFSSL_STATIC_MEMORY) && !defined(WOLFSSL_NO_MALLOC)
        #define ALT_ECC_SIZE
    #endif
    #define TFM_ECC192
    #define TFM_ECC224
    #define TFM_ECC256
    #define TFM_ECC384
    #define TFM_ECC521

    #define NO_RC4
    #define HAVE_TLS_EXTENSIONS
    #define HAVE_SUPPORTED_CURVES
    #define HAVE_EXTENDED_MASTER

    #define NO_WOLFSSL_DIR
    #define NO_WRITEV

    #if !defined(WOLFSSL_SILABS_SE_ACCEL) && !defined(STM32_RNG) && \
        !defined(CUSTOM_RAND_GENERATE)
        #define CUSTOM_RAND_TYPE     RAND_NBR
        #define CUSTOM_RAND_GENERATE Math_Rand
    #endif
    #define STRING_USER
    #define XSTRCASECMP(s1,s2) strcasecmp((s1),(s2))
    #define XSTRCMP(s1,s2) strcmp((s1),(s2))
    #define XSTRLEN(pstr) ((CPU_SIZE_T)Str_Len((CPU_CHAR *)(pstr)))
    #define XSTRNCPY(pstr_dest, pstr_src, len_max) \
                    ((CPU_CHAR *)Str_Copy_N((CPU_CHAR *)(pstr_dest), \
                     (CPU_CHAR *)(pstr_src), (CPU_SIZE_T)(len_max)))
    #define XSTRNCMP(pstr_1, pstr_2, len_max) \
                    ((CPU_INT16S)Str_Cmp_N((CPU_CHAR *)(pstr_1), \
                     (CPU_CHAR *)(pstr_2), (CPU_SIZE_T)(len_max)))
    #define XSTRNCASECMP(pstr_1, pstr_2, len_max) \
                    ((CPU_INT16S)Str_CmpIgnoreCase_N((CPU_CHAR *)(pstr_1), \
                     (CPU_CHAR *)(pstr_2), (CPU_SIZE_T)(len_max)))
    #define XSTRSTR(pstr, pstr_srch) \
                    ((CPU_CHAR *)Str_Str((CPU_CHAR *)(pstr), \
                     (CPU_CHAR *)(pstr_srch)))
    #define XSTRNSTR(pstr, pstr_srch, len_max) \
                    ((CPU_CHAR *)Str_Str_N((CPU_CHAR *)(pstr), \
                     (CPU_CHAR *)(pstr_srch),(CPU_SIZE_T)(len_max)))
    #define XSTRNCAT(pstr_dest, pstr_cat, len_max) \
                    ((CPU_CHAR *)Str_Cat_N((CPU_CHAR *)(pstr_dest), \
                     (const CPU_CHAR *)(pstr_cat),(CPU_SIZE_T)(len_max)))
    #ifndef XATOI /* if custom XATOI is not already defined */
        #define XATOI(s) atoi((s))
    #endif
    #if defined(USE_WOLF_STRTOK)
        #define XSTRTOK(s1, d, ptr) wc_strtok((s1), (d), (ptr))
    #else
        #define XSTRTOK(s1, d, ptr) strtok_r((s1), (d), (ptr))
    #endif
    #define XMEMSET(pmem, data_val, size) \
                    ((void)Mem_Set((void *)(pmem), \
                    (CPU_INT08U) (data_val), \
                    (CPU_SIZE_T)(size)))
    #define XMEMCPY(pdest, psrc, size) ((void)Mem_Copy((void *)(pdest), \
                     (void *)(psrc), (CPU_SIZE_T)(size)))

    #if (OS_VERSION < 50000)
        #define XMEMCMP(pmem_1, pmem_2, size)                   \
                   (((CPU_BOOLEAN)Mem_Cmp((void *)(pmem_1),     \
                                          (void *)(pmem_2),     \
                     (CPU_SIZE_T)(size))) ? DEF_NO : DEF_YES)
    #else
      /* Work around for Micrium OS version 5.8 change in behavior
       * that returns DEF_NO for 0 size compare
       */
        #define XMEMCMP(pmem_1, pmem_2, size)                           \
            (( (size < 1 ) ||                                           \
               ((CPU_BOOLEAN)Mem_Cmp((void *)(pmem_1),                  \
                                     (void *)(pmem_2),                  \
                                     (CPU_SIZE_T)(size)) == DEF_YES))   \
             ? 0 : 1)
        #define XSNPRINTF snprintf
    #endif

    #define XMEMMOVE(pdest, psrc, size) ((void)Mem_Move((void *)(pdest), \
                     (void *)(psrc), (CPU_SIZE_T)(size)))

    #if (OS_CFG_MUTEX_EN == DEF_DISABLED)
        #define SINGLE_THREADED
    #endif

    #if (CPU_CFG_ENDIAN_TYPE == CPU_ENDIAN_TYPE_BIG)
        #define BIG_ENDIAN_ORDER
    #else
        #undef  BIG_ENDIAN_ORDER
        #define LITTLE_ENDIAN_ORDER
    #endif
#endif /* MICRIUM */

#if defined(sun) || defined(__sun)
# if defined(__SVR4) || defined(__svr4__)
    /* Solaris */
    #ifndef WOLFSSL_SOLARIS
        #define WOLFSSL_SOLARIS
    #endif
# else
    /* SunOS */
# endif
#endif

#ifdef WOLFSSL_SOLARIS
    /* Avoid naming clash with fp_zero from math.h > ieefp.h */
    #define WOLFSSL_DH_CONST
#endif

#ifdef WOLFSSL_MCF5441X
    #define BIG_ENDIAN_ORDER
    #ifndef SIZEOF_LONG
        #define SIZEOF_LONG 4
    #endif
    #ifndef SIZEOF_LONG_LONG
        #define SIZEOF_LONG_LONG 8
    #endif
#endif

#ifdef WOLFSSL_QL
    #ifndef WOLFSSL_SEP
        #define WOLFSSL_SEP
    #endif
    #ifndef OPENSSL_EXTRA
        #define OPENSSL_EXTRA
    #endif
    #ifndef SESSION_CERTS
        #define SESSION_CERTS
    #endif
    #ifndef HAVE_AESCCM
        #define HAVE_AESCCM
    #endif
    #ifndef ATOMIC_USER
        #define ATOMIC_USER
    #endif
    #ifndef WOLFSSL_DER_LOAD
        #define WOLFSSL_DER_LOAD
    #endif
    #ifndef KEEP_PEER_CERT
        #define KEEP_PEER_CERT
    #endif
    #ifndef HAVE_ECC
        #define HAVE_ECC
    #endif
    #ifndef SESSION_INDEX
        #define SESSION_INDEX
    #endif
#endif /* WOLFSSL_QL */


#if defined(WOLFSSL_XILINX)
    #if !defined(WOLFSSL_XILINX_CRYPT_VERSAL)
        #define NO_DEV_RANDOM
    #endif
    #undef  NO_WOLFSSL_DIR
    #define NO_WOLFSSL_DIR

    #undef  HAVE_AESGCM
    #define HAVE_AESGCM
#endif

/* Detect Cortex M3 (no UMAAL) */
#if defined(__ARM_ARCH_7M__) && !defined(WOLFSSL_ARM_ARCH_7M)
    #define WOLFSSL_ARM_ARCH_7M
#endif
#if defined(WOLFSSL_SP_ARM_CORTEX_M_ASM) && defined(WOLFSSL_ARM_ARCH_7M)
    #undef  WOLFSSL_SP_NO_UMAAL
    #define WOLFSSL_SP_NO_UMAAL
#endif

#if defined(WOLFSSL_XILINX_CRYPT) || defined(WOLFSSL_AFALG_XILINX)
    #if defined(WOLFSSL_ARMASM)
        #error can not use both ARMv8 instructions and XILINX hardened crypto
    #endif
    #if defined(WOLFSSL_SHA3)
        /* only SHA3-384 is supported */
        #undef WOLFSSL_NOSHA3_224
        #undef WOLFSSL_NOSHA3_256
        #undef WOLFSSL_NOSHA3_512
        #define WOLFSSL_NOSHA3_224
        #define WOLFSSL_NOSHA3_256
        #define WOLFSSL_NOSHA3_512
        #ifndef WOLFSSL_NO_SHAKE128
            #define WOLFSSL_NO_SHAKE128
        #endif
        #ifndef WOLFSSL_NO_SHAKE256
            #define WOLFSSL_NO_SHAKE256
        #endif
    #endif
    #ifdef WOLFSSL_AFALG_XILINX_AES
        #undef  WOLFSSL_AES_DIRECT
        #define WOLFSSL_AES_DIRECT
    #endif
#endif /*(WOLFSSL_XILINX_CRYPT)*/

#ifdef WOLFSSL_KCAPI_AES
    #define WOLFSSL_AES_GCM_FIXED_IV_AAD
#endif
#ifdef WOLFSSL_KCAPI_ECC
    #undef  ECC_USER_CURVES
    #define ECC_USER_CURVES
    #undef  NO_ECC256
    #undef  HAVE_ECC384
    #define HAVE_ECC384
    #undef  HAVE_ECC521
    #define HAVE_ECC521
#endif

#if defined(WOLFSSL_APACHE_MYNEWT)
    #include "os/os_malloc.h"
    #if !defined(WOLFSSL_LWIP)
        #include <mn_socket/mn_socket.h>
    #endif

    #if !defined(SIZEOF_LONG)
        #define SIZEOF_LONG 4
    #endif
    #if !defined(SIZEOF_LONG_LONG)
        #define SIZEOF_LONG_LONG 8
    #endif
    #if (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
        #define BIG_ENDIAN_ORDER
    #else
        #undef  BIG_ENDIAN_ORDER
        #define LITTLE_ENDIAN_ORDER
    #endif
    #define NO_WRITEV
    #define WOLFSSL_USER_IO
    #define SINGLE_THREADED
    #define NO_DEV_RANDOM
    #define NO_DH
    #define NO_WOLFSSL_DIR
    #define NO_ERROR_STRINGS
    #define HAVE_ECC
    #define NO_SESSION_CACHE
    #define NO_ERROR_STRINGS
    #define XMALLOC_USER
    #define XMALLOC(sz, heap, type)     ((void)(heap), (void)(type), os_malloc(sz))
    #define XREALLOC(p, sz, heap, type) ((void)(heap), (void)(type), os_realloc(p, sz))
    #define XFREE(p, heap, type)        ((void)(heap), (void)(type), os_free(p))

#endif /*(WOLFSSL_APACHE_MYNEWT)*/

#ifdef WOLFSSL_ZEPHYR
    #include <version.h>
#if KERNEL_VERSION_NUMBER >= 0x30100
    #include <zephyr/kernel.h>
    #include <zephyr/sys/printk.h>
    #include <zephyr/sys/util.h>
#else
    #include <kernel.h>
    #include <sys/printk.h>
    #include <sys/util.h>
#endif
    #include <stdlib.h>

    #define WOLFSSL_DH_CONST
    #define WOLFSSL_HAVE_MAX
    #define NO_WRITEV
    #define NO_STDLIB_ISASCII

    #define USE_FLAT_BENCHMARK_H
    #define USE_FLAT_TEST_H
    #define EXIT_FAILURE 1
    #define MAIN_NO_ARGS

    void *z_realloc(void *ptr, size_t size);
    #define realloc   z_realloc
    #define max MAX

    #if !defined(CONFIG_NET_SOCKETS_POSIX_NAMES) && !defined(CONFIG_POSIX_API)
    #define CONFIG_NET_SOCKETS_POSIX_NAMES
    #endif
#endif

#ifdef WOLFSSL_IMX6
    #ifndef SIZEOF_LONG_LONG
        #define SIZEOF_LONG_LONG 8
    #endif
#endif

/* Setting supported CAAM algorithms */
#ifdef WOLFSSL_IMX6Q_CAAM
    #undef  WOLFSSL_CAAM
    #define WOLFSSL_CAAM

    /* hardware does not support AES-GCM and ECC
     * has the low power AES module only (no high power with GCM) */
    #define WOLFSSL_LP_ONLY_CAAM_AES
    #define WOLFSSL_NO_CAAM_ECC
#endif

#ifdef WOLFSSL_SECO_CAAM
    #define WOLFSSL_CAAM

    #define WOLFSSL_HASH_KEEP
    #define WOLFSSL_NO_CAAM_BLOB
#endif

#ifdef WOLFSSL_IMXRT1170_CAAM
    #define WOLFSSL_CAAM
#endif

/* OS specific support so far */
#ifdef WOLFSSL_QNX_CAAM
    /* shim layer for QNX hashing not yet implemented */
    #define WOLFSSL_NO_CAAM_HASH
#endif

#ifdef WOLFSSL_CAAM
    /* switch for all AES type algos */
    #undef  WOLFSSL_CAAM_CIPHER
    #define WOLFSSL_CAAM_CIPHER
    #ifdef WOLFSSL_CAAM_CIPHER
        #ifndef WOLFSSL_LP_ONLY_CAAM_AES
            /* GCM and XTS mode are only available in the high power module */
            #define WOLFSSL_CAAM_AESGCM
            #define WOLFSSL_CAAM_AESXTS
        #endif
        #define WOLFSSL_CAAM_AESCCM
        #define WOLFSSL_CAAM_AESCTR
        #define WOLFSSL_CAAM_AESCBC
        #define WOLFSSL_CAAM_CMAC
    #endif /* WOLFSSL_CAAM_CIPHER */
    #if defined(HAVE_AESGCM) || defined(WOLFSSL_AES_XTS) || \
            defined(WOLFSSL_CMAC)
        /* large performance gain with HAVE_AES_ECB defined */
        #undef HAVE_AES_ECB
        #define HAVE_AES_ECB

        /* @TODO used for now until plugging in caam aes use with qnx */
        #undef WOLFSSL_AES_DIRECT
        #define WOLFSSL_AES_DIRECT
    #endif

    /* switch for all hashing algos */
    #ifndef WOLFSSL_NO_CAAM_HASH
        #define WOLFSSL_CAAM_HASH
    #endif
    #if defined(WOLFSSL_DEVCRYPTO_HMAC)
        /* HMAC is through the devcrypto calls */
        #define WOLFSSL_CAAM_HMAC
    #endif

    /* public key operations */
    #ifndef WOLFSSL_NO_CAAM_ECC
        #undef  WOLFSSL_CAAM_ECC
        #define WOLFSSL_CAAM_ECC
    #endif

    /* so far curve25519 support was only done with the SECO */
    #ifdef WOLFSSL_SECO_CAAM
        #define WOLFSSL_CAAM_CURVE25519
    #endif

    /* Blob support */
    #ifndef WOLFSSL_NO_CAAM_BLOB
        #define WOLFSSL_CAAM_BLOB
    #endif
#endif

#if defined(NO_WC_SSIZE_TYPE) || defined(ssize_t)
    /* ssize_t comes from system headers or user_settings.h */
#elif defined(WC_SSIZE_TYPE)
    typedef WC_SSIZE_TYPE ssize_t;
#elif defined(_MSC_VER)
    #include <BaseTsd.h>
    typedef SSIZE_T ssize_t;
#endif

/* If DCP is used without SINGLE_THREADED, enforce WOLFSSL_CRYPT_HW_MUTEX */
#if defined(WOLFSSL_IMXRT_DCP) && !defined(SINGLE_THREADED)
    #undef WOLFSSL_CRYPT_HW_MUTEX
    #define WOLFSSL_CRYPT_HW_MUTEX 1
#endif

#if !defined(XMALLOC_USER) && !defined(MICRIUM_MALLOC) && \
    !defined(WOLFSSL_LEANPSK) && !defined(NO_WOLFSSL_MEMORY) && \
    !defined(XMALLOC_OVERRIDE)
    #define USE_WOLFSSL_MEMORY
#endif

#ifdef WOLFSSL_EMBOS
    #include "RTOS.h"
    #if !defined(XMALLOC_USER) && !defined(NO_WOLFSSL_MEMORY) && \
        !defined(WOLFSSL_STATIC_MEMORY)
        /* Per the user manual of embOS https://www.segger.com/downloads/embos/UM01001
         * this API has changed with V5. */
        #if (OS_VERSION >= 50000U)
            #define XMALLOC(s, h, type)  ((void)(h), (void)(type), OS_HEAP_malloc((s)))
            #define XFREE(p, h, type)    ((void)(h), (void)(type), OS_HEAP_free((p)))
            #define XREALLOC(p, n, h, t) ((void)(h), (void)(t), OS_HEAP_realloc((p), (n)))
        #else
            #define XMALLOC(s, h, type)  ((void)(h), (void)(type), OS_malloc((s)))
            #define XFREE(p, h, type)    ((void)(h), (void)(type), OS_free((p)))
            #define XREALLOC(p, n, h, t) ((void)(h), (void)(t), OS_realloc((p), (n)))
        #endif
    #endif
#endif


/* stream ciphers except arc4 need 32bit alignment, intel ok without */
#ifndef XSTREAM_ALIGN
    #if defined(__x86_64__) || defined(__ia64__) || defined(__i386__)
        #define NO_XSTREAM_ALIGN
    #else
        #define XSTREAM_ALIGN
    #endif
#endif

/* write dup cannot be used with secure renegotiation because write dup
 * make write side write only and read side read only */
#if defined(HAVE_WRITE_DUP) && defined(HAVE_SECURE_RENEGOTIATION)
    #error "WRITE DUP and SECURE RENEGOTIATION cannot both be on"
#endif

#ifdef WOLFSSL_SGX
    #ifdef _MSC_VER
        #define NO_RC4
        #ifndef HAVE_FIPS
            #define WOLFCRYPT_ONLY
            #define NO_DES3
            #define NO_SHA
            #define NO_MD5
        #else
            #define TFM_TIMING_RESISTANT
            #define NO_WOLFSSL_DIR
            #define NO_WRITEV
            #define NO_MAIN_DRIVER
            #define WOLFSSL_LOG_PRINTF
            #define WOLFSSL_DH_CONST
        #endif
    #else
        #define HAVE_ECC
        #define NO_WRITEV
        #define NO_MAIN_DRIVER
        #define USER_TICKS
        #define WOLFSSL_LOG_PRINTF
        #define WOLFSSL_DH_CONST
    #endif /* _MSC_VER */
    #if !defined(HAVE_FIPS) && !defined(NO_RSA)
        #define WC_RSA_BLINDING
    #endif

    #define NO_FILESYSTEM
    #define ECC_TIMING_RESISTANT
    #define TFM_TIMING_RESISTANT
    #define SINGLE_THREADED
    #define NO_ASN_TIME /* can not use headers such as windows.h */
    #define HAVE_AESGCM
    #define USE_CERT_BUFFERS_2048
#endif /* WOLFSSL_SGX */

/* FreeScale MMCAU hardware crypto has 4 byte alignment.
   However, KSDK fsl_mmcau.h gives API with no alignment
   requirements (4 byte alignment is managed internally by fsl_mmcau.c) */
#ifdef FREESCALE_MMCAU
    #ifdef FREESCALE_MMCAU_CLASSIC
        #define WOLFSSL_MMCAU_ALIGNMENT 4
    #else
        #define WOLFSSL_MMCAU_ALIGNMENT 0
    #endif
#endif

/* if using hardware crypto and have alignment requirements, specify the
   requirement here.  The record header of SSL/TLS will prevent easy alignment.
   This hint tries to help as much as possible.  */
#ifndef WOLFSSL_GENERAL_ALIGNMENT
    #ifdef WOLFSSL_AESNI
        #define WOLFSSL_GENERAL_ALIGNMENT 16
    #elif defined(XSTREAM_ALIGN)
        #define WOLFSSL_GENERAL_ALIGNMENT  4
    #elif defined(FREESCALE_MMCAU) || defined(FREESCALE_MMCAU_CLASSIC)
        #define WOLFSSL_GENERAL_ALIGNMENT  WOLFSSL_MMCAU_ALIGNMENT
    #else
        #define WOLFSSL_GENERAL_ALIGNMENT  0
    #endif
#endif

#if defined(WOLFSSL_GENERAL_ALIGNMENT) && (WOLFSSL_GENERAL_ALIGNMENT > 0)
    #if defined(_MSC_VER)
        #define XGEN_ALIGN __declspec(align(WOLFSSL_GENERAL_ALIGNMENT))
    #elif defined(__GNUC__)
        #define XGEN_ALIGN __attribute__((aligned(WOLFSSL_GENERAL_ALIGNMENT)))
    #else
        #define XGEN_ALIGN
    #endif
#else
    #define XGEN_ALIGN
#endif

#if defined(__mips) || defined(__mips64) || \
    defined(WOLFSSL_SP_MIPS64) || defined(WOLFSSL_SP_MIPS)
    #undef WOLFSSL_SP_INT_DIGIT_ALIGN
    #define WOLFSSL_SP_INT_DIGIT_ALIGN
#endif
#if defined(__sparc)
    #undef WOLFSSL_SP_INT_DIGIT_ALIGN
    #define WOLFSSL_SP_INT_DIGIT_ALIGN
#endif
#if defined(__APPLE__) || defined(WOLF_C89)
    #define WOLFSSL_SP_NO_DYN_STACK
#endif

#if defined(__WATCOMC__) && !defined(WOLF_NO_VARIADIC_MACROS)
    #define WOLF_NO_VARIADIC_MACROS
#endif

#ifdef __INTEL_COMPILER
    #pragma warning(disable:2259) /* explicit casts to smaller sizes, disable */
#endif

/* ---------------------------------------------------------------------------
 * Math Library Selection (in order of preference)
 * ---------------------------------------------------------------------------
 */
#if !defined(HAVE_FIPS_VERSION) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 5))
    #if defined(WOLFSSL_SP_MATH_ALL)
        /*  1) SP Math: wolfSSL proprietary math implementation (sp_int.c).
         *      Constant time: Always
         *      Enable:        WOLFSSL_SP_MATH_ALL
         */
        #undef USE_FAST_MATH
        #undef USE_INTEGER_HEAP_MATH
    #elif defined(WOLFSSL_SP_MATH)
        /*  2) SP Math with restricted key sizes: wolfSSL proprietary math
         *         implementation (sp_*.c).
         *      Constant time: Always
         *      Enable:        WOLFSSL_SP_MATH
         */
        #undef USE_FAST_MATH
        #undef USE_INTEGER_HEAP_MATH
    #elif defined(USE_FAST_MATH)
        /*  3) Tom's Fast Math: Stack based (tfm.c)
         *      Constant time: Only with TFM_TIMING_RESISTANT
         *      Enable:        USE_FAST_MATH
         */
        #undef USE_INTEGER_HEAP_MATH
    #elif defined(USE_INTEGER_HEAP_MATH)
        /*  4) Integer Heap Math:  Heap based (integer.c)
         *      Constant time: Not supported
         *      Enable:        USE_INTEGER_HEAP_MATH
         */
    #elif defined(NO_BIG_INT)
        /*  5) No big integer math libraries
         */
    #else
        /* default is SP Math. */
        #define WOLFSSL_SP_MATH_ALL
    #endif
#else
    /* FIPS 140-2 or older */
    /* Default to fast math (tfm.c), but allow heap math (integer.c) */
    #if !defined(USE_INTEGER_HEAP_MATH)
        #undef  USE_FAST_MATH
        #define USE_FAST_MATH
        #ifndef FP_MAX_BITS
            #define FP_MAX_BITS 8192
        #endif
    #endif
#endif

/* Verify that only one of the above multi-precision math libraries is enabled */
#if (defined(WOLFSSL_SP_MATH_ALL) && \
        (defined(USE_FAST_MATH) || defined(USE_INTEGER_HEAP_MATH))) || \
    (defined(USE_FAST_MATH) && defined(USE_INTEGER_HEAP_MATH))
    #error Cannot enable more than one multiple precision math library!
#endif
/*----------------------------------------------------------------------------*/

/* SP Math specific options */
/* Determine when mp_add_d is required. */
#if !defined(NO_PWDBASED) || defined(WOLFSSL_KEY_GEN) || !defined(NO_DH) || \
    !defined(NO_DSA) || defined(HAVE_ECC) || \
    (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY)) || \
    defined(OPENSSL_EXTRA)
    #define WOLFSSL_SP_ADD_D
#endif

/* Determine when mp_sub_d is required. */
#if (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY)) || \
    !defined(NO_DH) || defined(HAVE_ECC) || !defined(NO_DSA)
    #define WOLFSSL_SP_SUB_D
#endif

/* Determine when mp_read_radix with a radix of 10 is required. */
#if (defined(WOLFSSL_SP_MATH_ALL) && !defined(NO_RSA) && \
    !defined(WOLFSSL_RSA_VERIFY_ONLY)) || defined(HAVE_ECC) || \
    !defined(NO_DSA) || defined(OPENSSL_EXTRA)
    #define WOLFSSL_SP_READ_RADIX_16
#endif

/* Determine when mp_read_radix with a radix of 10 is required. */
#if defined(WOLFSSL_SP_MATH_ALL) && !defined(NO_RSA) && \
    !defined(WOLFSSL_RSA_VERIFY_ONLY)
    #define WOLFSSL_SP_READ_RADIX_10
#endif

/* Determine when mp_invmod is required. */
#if defined(HAVE_ECC) || !defined(NO_DSA) || defined(OPENSSL_EXTRA) || \
    (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY) && \
     !defined(WOLFSSL_RSA_PUBLIC_ONLY))
    #define WOLFSSL_SP_INVMOD
#endif

/* Determine when mp_invmod_mont_ct is required. */
#if defined(WOLFSSL_SP_MATH_ALL) && defined(HAVE_ECC)
    #define WOLFSSL_SP_INVMOD_MONT_CT
#endif

/* Determine when mp_prime_gen is required. */
#if (defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY) && \
    !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || !defined(NO_DH) || \
    (!defined(NO_RSA) && defined(WOLFSSL_KEY_GEN))
    #define WOLFSSL_SP_PRIME_GEN
#endif

#if (defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY)) || \
    (defined(WOLFSSL_KEY_GEN) && !defined(NO_RSA)) || defined(OPENSSL_EXTRA)
    /* Determine when mp_mul_d is required */
    #define WOLFSSL_SP_MUL_D
#endif


/* user can specify what curves they want with ECC_USER_CURVES otherwise
 * all curves are on by default for now */
#ifndef ECC_USER_CURVES
    #ifdef WOLFSSL_SP_MATH
        /* for single precision math only make sure the enabled key sizes are
         * included in the ECC curve table */
        #if defined(WOLFSSL_SP_NO_256) && !defined(NO_ECC256)
            #define NO_ECC256
        #endif
        #if defined(WOLFSSL_SP_384) && !defined(HAVE_ECC384)
            #define HAVE_ECC384
        #endif
        #if defined(WOLFSSL_SP_521) && !defined(HAVE_ECC521)
            #define HAVE_ECC521
        #endif
    #elif !defined(HAVE_ALL_CURVES)
        #define HAVE_ALL_CURVES
    #endif
#endif

/* The minimum allowed ECC key size */
/* Note: 224-bits is equivalent to 2048-bit RSA */
#ifndef ECC_MIN_KEY_SZ
    #ifdef WOLFSSL_MIN_ECC_BITS
        #define ECC_MIN_KEY_SZ WOLFSSL_MIN_ECC_BITS
    #else
        #if defined(WOLFSSL_HARDEN_TLS) && \
            !defined(WOLFSSL_HARDEN_TLS_NO_PKEY_CHECK)
            /* Using guidance from section 5.6.1
             * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf */
            #if WOLFSSL_HARDEN_TLS >= 128
                #define ECC_MIN_KEY_SZ 256
            #elif WOLFSSL_HARDEN_TLS >= 112
                #define ECC_MIN_KEY_SZ 224
            #endif
        #elif FIPS_VERSION_GE(2,0)
            /* FIPSv2 and ready (for now) includes 192-bit support */
            #define ECC_MIN_KEY_SZ 192
        #else
            #define ECC_MIN_KEY_SZ 224
        #endif
    #endif
#endif

#if defined(WOLFSSL_HARDEN_TLS) && ECC_MIN_KEY_SZ < 224 && \
    !defined(WOLFSSL_HARDEN_TLS_NO_PKEY_CHECK)
    /* Implementations MUST NOT negotiate cipher suites offering less than
     * 112 bits of security.
     * https://www.rfc-editor.org/rfc/rfc9325#section-4.1
     * Using guidance from section 5.6.1
     * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf */
    #error "For 112 bits of security ECC needs at least 224 bit keys"
#endif

/* ECC Configs */
#ifdef HAVE_ECC
    /* By default enable Sign, Verify, DHE, Key Import and Key Export unless
     * explicitly disabled */
    #if !defined(NO_ECC_SIGN) && \
            (!defined(ECC_TIMING_RESISTANT) || \
            (defined(ECC_TIMING_RESISTANT) && !defined(WC_NO_RNG)))
        #undef HAVE_ECC_SIGN
        #define HAVE_ECC_SIGN
    #endif
    #ifndef NO_ECC_VERIFY
        #undef HAVE_ECC_VERIFY
        #define HAVE_ECC_VERIFY
    #endif
    #ifndef NO_ECC_CHECK_KEY
        #undef HAVE_ECC_CHECK_KEY
        #define HAVE_ECC_CHECK_KEY
    #endif
    #if !defined(NO_ECC_DHE) && !defined(WC_NO_RNG)
        #undef HAVE_ECC_DHE
        #define HAVE_ECC_DHE
    #endif
    #ifndef NO_ECC_KEY_IMPORT
        #undef HAVE_ECC_KEY_IMPORT
        #define HAVE_ECC_KEY_IMPORT
    #endif
    /* The ECC key export requires mp_int or SP */
    #if (!defined(NO_ECC_KEY_EXPORT) && defined(WOLFSSL_SP_MATH)) || \
        (!defined(NO_ECC_KEY_EXPORT) && !defined(NO_BIG_INT))
        #undef HAVE_ECC_KEY_EXPORT
        #define HAVE_ECC_KEY_EXPORT
    #endif
#endif /* HAVE_ECC */

#if (defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)) && defined(HAVE_ECC) && \
    !defined(WOLFSSL_ATECC508A) && !defined(WOLFSSL_ATECC608A) && \
    !defined(WOLFSSL_CRYPTOCELL) && !defined(WOLFSSL_SE050) && \
    !defined(WOLF_CRYPTO_CB_ONLY_ECC) && !defined(WOLFSSL_STM32_PKA)
    #undef  USE_ECC_B_PARAM
    #define USE_ECC_B_PARAM
#endif

/* Curve25519 Configs */
#ifdef HAVE_CURVE25519
    /* By default enable shared secret, key export and import */
    #ifndef NO_CURVE25519_SHARED_SECRET
        #undef HAVE_CURVE25519_SHARED_SECRET
        #define HAVE_CURVE25519_SHARED_SECRET
    #endif
    #ifndef NO_CURVE25519_KEY_EXPORT
        #undef HAVE_CURVE25519_KEY_EXPORT
        #define HAVE_CURVE25519_KEY_EXPORT
    #endif
    #ifndef NO_CURVE25519_KEY_IMPORT
        #undef HAVE_CURVE25519_KEY_IMPORT
        #define HAVE_CURVE25519_KEY_IMPORT
    #endif
#endif /* HAVE_CURVE25519 */

/* Ed25519 Configs */
#ifdef HAVE_ED25519
    /* By default enable make key, sign, verify, key export and import */
    #ifndef NO_ED25519_MAKE_KEY
        #undef HAVE_ED25519_MAKE_KEY
        #define HAVE_ED25519_MAKE_KEY
    #endif
    #ifndef NO_ED25519_SIGN
        #ifndef HAVE_ED25519_MAKE_KEY
           #error "Need HAVE_ED25519_MAKE_KEY with HAVE_ED25519_SIGN"
        #endif
        #undef HAVE_ED25519_SIGN
        #define HAVE_ED25519_SIGN
    #endif
    #ifndef NO_ED25519_VERIFY
        #undef HAVE_ED25519_VERIFY
        #define HAVE_ED25519_VERIFY
        #ifdef WOLFSSL_ED25519_STREAMING_VERIFY
            #undef WOLFSSL_ED25519_PERSISTENT_SHA
            #define WOLFSSL_ED25519_PERSISTENT_SHA
        #endif
    #endif
    #ifndef NO_ED25519_KEY_EXPORT
        #undef HAVE_ED25519_KEY_EXPORT
        #define HAVE_ED25519_KEY_EXPORT
    #endif
    #ifndef NO_ED25519_KEY_IMPORT
        #undef HAVE_ED25519_KEY_IMPORT
        #define HAVE_ED25519_KEY_IMPORT
    #endif
#endif /* HAVE_ED25519 */

/* Curve448 Configs */
#ifdef HAVE_CURVE448
    /* By default enable shared secret, key export and import */
    #ifndef NO_CURVE448_SHARED_SECRET
        #undef HAVE_CURVE448_SHARED_SECRET
        #define HAVE_CURVE448_SHARED_SECRET
    #endif
    #ifndef NO_CURVE448_KEY_EXPORT
        #undef HAVE_CURVE448_KEY_EXPORT
        #define HAVE_CURVE448_KEY_EXPORT
    #endif
    #ifndef NO_CURVE448_KEY_IMPORT
        #undef HAVE_CURVE448_KEY_IMPORT
        #define HAVE_CURVE448_KEY_IMPORT
    #endif
#endif /* HAVE_CURVE448 */

/* Ed448 Configs */
#ifdef HAVE_ED448
    /* By default enable sign, verify, key export and import */
    #ifndef NO_ED448_SIGN
        #undef HAVE_ED448_SIGN
        #define HAVE_ED448_SIGN
    #endif
    #ifndef NO_ED448_VERIFY
        #undef HAVE_ED448_VERIFY
        #define HAVE_ED448_VERIFY
        #ifdef WOLFSSL_ED448_STREAMING_VERIFY
            #undef WOLFSSL_ED448_PERSISTENT_SHA
            #define WOLFSSL_ED448_PERSISTENT_SHA
        #endif
    #endif
    #ifndef NO_ED448_KEY_EXPORT
        #undef HAVE_ED448_KEY_EXPORT
        #define HAVE_ED448_KEY_EXPORT
    #endif
    #ifndef NO_ED448_KEY_IMPORT
        #undef HAVE_ED448_KEY_IMPORT
        #define HAVE_ED448_KEY_IMPORT
    #endif
#endif /* HAVE_ED448 */

/* FIPS does not support CFB1 or CFB8 */
#if !defined(WOLFSSL_NO_AES_CFB_1_8) && \
    (defined(HAVE_SELFTEST) || \
        (defined(HAVE_FIPS) && FIPS_VERSION3_LT(6,0,0)))
    #define WOLFSSL_NO_AES_CFB_1_8
#endif

/* AES Config */
#ifndef NO_AES
    /* By default enable all AES key sizes, decryption and CBC */
    #ifndef AES_MAX_KEY_SIZE
        #undef  AES_MAX_KEY_SIZE
        #define AES_MAX_KEY_SIZE    256
    #endif

    #ifndef NO_AES_128
        #undef  WOLFSSL_AES_128
        #define WOLFSSL_AES_128
    #endif
    #if !defined(NO_AES_192) && AES_MAX_KEY_SIZE >= 192
        #undef  WOLFSSL_AES_192
        #define WOLFSSL_AES_192
    #endif
    #if !defined(NO_AES_256) && AES_MAX_KEY_SIZE >= 256
        #undef  WOLFSSL_AES_256
        #define WOLFSSL_AES_256
    #endif
    #if !defined(WOLFSSL_AES_128) && !defined(WOLFSSL_AES_256) && \
        defined(HAVE_ECC_ENCRYPT)
        #warning HAVE_ECC_ENCRYPT uses AES 128/256 bit keys
     #endif

    #ifndef NO_AES_DECRYPT
        #undef  HAVE_AES_DECRYPT
        #define HAVE_AES_DECRYPT
    #endif
    #ifndef NO_AES_CBC
        #undef  HAVE_AES_CBC
        #define HAVE_AES_CBC
    #endif
    #ifdef WOLFSSL_AES_XTS
        /* AES-XTS makes calls to AES direct functions */
        #ifndef WOLFSSL_AES_DIRECT
        #define WOLFSSL_AES_DIRECT
        #endif
    #endif
    #ifdef WOLFSSL_AES_CFB
        /* AES-CFB makes calls to AES direct functions */
        #ifndef WOLFSSL_AES_DIRECT
        #define WOLFSSL_AES_DIRECT
        #endif
    #endif
#endif

#if (defined(WOLFSSL_TLS13) && defined(WOLFSSL_NO_TLS12)) || \
    (!defined(HAVE_AES_CBC) && defined(NO_DES3) && defined(NO_RC4) && \
     !defined(HAVE_CAMELLIA) & !defined(HAVE_NULL_CIPHER))
    #define WOLFSSL_AEAD_ONLY
#endif

#if !defined(HAVE_PUBLIC_FFDHE) && !defined(NO_DH) && \
    !defined(WOLFSSL_NO_PUBLIC_FFDHE) && \
    (defined(HAVE_SELFTEST) || FIPS_VERSION_LE(2,0))
    /* This should only be enabled for FIPS v2 or older. It enables use of the
     * older wc_Dh_ffdhe####_Get() API's */
    #define HAVE_PUBLIC_FFDHE
#endif

#if !defined(NO_DH) && !defined(HAVE_FFDHE)
    #if defined(HAVE_FFDHE_2048) || defined(HAVE_FFDHE_3072) || \
            defined(HAVE_FFDHE_4096) || defined(HAVE_FFDHE_6144) || \
            defined(HAVE_FFDHE_8192)
        #define HAVE_FFDHE
    #endif
#endif
#if defined(HAVE_FFDHE_8192)
    #define MIN_FFDHE_BITS 8192
#elif defined(HAVE_FFDHE_6144)
    #define MIN_FFDHE_BITS 6144
#elif defined(HAVE_FFDHE_4096)
    #define MIN_FFDHE_BITS 4096
#elif defined(HAVE_FFDHE_3072)
    #define MIN_FFDHE_BITS 3072
#elif defined(HAVE_FFDHE_2048)
    #define MIN_FFDHE_BITS 2048
#else
    #define MIN_FFDHE_BITS 0
#endif
#define MIN_FFDHE_FP_MAX_BITS   (MIN_FFDHE_BITS * 2)
#if defined(HAVE_FFDHE) && defined(FP_MAX_BITS)
    #if MIN_FFDHE_FP_MAX_BITS > FP_MAX_BITS
        #error "FFDHE parameters are too large for FP_MAX_BIT as set"
    #endif
#endif
#if defined(HAVE_FFDHE) && defined(SP_INT_BITS)
    #if MIN_FFDHE_BITS > SP_INT_BITS
        #error "FFDHE parameters are too large for SP_INT_BIT as set"
    #endif
#endif

/* if desktop type system and fastmath increase default max bits */
#if defined(WOLFSSL_X86_64_BUILD) || defined(WOLFSSL_AARCH64_BUILD)
    #if defined(USE_FAST_MATH) && !defined(FP_MAX_BITS)
        #if MIN_FFDHE_FP_MAX_BITS <= 8192
            #define FP_MAX_BITS     8192
        #else
            #define FP_MAX_BITS     MIN_FFDHE_FP_MAX_BITS
        #endif
    #endif
    #if defined(WOLFSSL_SP_MATH_ALL) && !defined(SP_INT_BITS)
        #ifdef WOLFSSL_MYSQL_COMPATIBLE
            #define SP_INT_BITS     8192
        #elif MIN_FFDHE_BITS <= 4096
            #define SP_INT_BITS     4096
        #else
            #define SP_INT_BITS     MIN_FFDHE_BITS
        #endif
    #endif
#endif

/* If using the max strength build, ensure OLD TLS is disabled. */
#ifdef WOLFSSL_MAX_STRENGTH
    #undef NO_OLD_TLS
    #define NO_OLD_TLS
#endif


/* Default AES minimum auth tag sz, allow user to override */
#ifndef WOLFSSL_MIN_AUTH_TAG_SZ
    #define WOLFSSL_MIN_AUTH_TAG_SZ 12
#endif


/* sniffer requires:
 * static RSA cipher suites
 * session stats and peak stats
 */
#ifdef WOLFSSL_SNIFFER
    #ifndef WOLFSSL_STATIC_RSA
        #define WOLFSSL_STATIC_RSA
    #endif
    #ifndef WOLFSSL_STATIC_DH
        #define WOLFSSL_STATIC_DH
    #endif
    /* Allow option to be disabled. */
    #ifndef WOLFSSL_NO_SESSION_STATS
        #ifndef WOLFSSL_SESSION_STATS
            #define WOLFSSL_SESSION_STATS
        #endif
        #ifndef WOLFSSL_PEAK_SESSIONS
            #define WOLFSSL_PEAK_SESSIONS
        #endif
    #endif
#endif

/* Decode Public Key extras on by default, user can turn off with
 * WOLFSSL_NO_DECODE_EXTRA */
#ifndef WOLFSSL_NO_DECODE_EXTRA
    #ifndef RSA_DECODE_EXTRA
        #define RSA_DECODE_EXTRA
    #endif
    #ifndef ECC_DECODE_EXTRA
        #define ECC_DECODE_EXTRA
    #endif
#endif

/* C Sharp wrapper defines */
#ifdef HAVE_CSHARP
    #ifndef WOLFSSL_DTLS
        #define WOLFSSL_DTLS
    #endif
    #undef NO_PSK
    #undef NO_SHA256
    #undef NO_DH
#endif

/* CryptoCell defines */
#ifdef WOLFSSL_CRYPTOCELL
    #if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN)
        /* Don't attempt to sign/verify an all-zero digest in wolfCrypt tests */
        #define WC_TEST_NO_ECC_SIGN_VERIFY_ZERO_DIGEST
    #endif /* HAVE_ECC && HAVE_ECC_SIGN */
#endif

/* Asynchronous Crypto */
#ifdef WOLFSSL_ASYNC_CRYPT
    #if !defined(HAVE_CAVIUM) && !defined(HAVE_INTEL_QA) && \
        !defined(WOLF_CRYPTO_CB) && !defined(HAVE_PK_CALLBACKS) && \
        !defined(WOLFSSL_ASYNC_CRYPT_SW)
        #error No async backend defined with WOLFSSL_ASYNC_CRYPT!
    #endif

    /* Make sure wolf events are enabled */
    #undef HAVE_WOLF_EVENT
    #define HAVE_WOLF_EVENT

    #ifdef WOLFSSL_ASYNC_CRYPT_SW
        #define WC_ASYNC_DEV_SIZE 168
    #else
        #define WC_ASYNC_DEV_SIZE 336
    #endif

    /* Enable ECC_CACHE_CURVE for ASYNC */
    #if !defined(ECC_CACHE_CURVE) && !defined(NO_ECC_CACHE_CURVE)
        /* Enabled by default for increased async performance,
         * but not required */
        #define ECC_CACHE_CURVE
    #endif

    #if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN)
        /* Don't attempt to sign/verify an all-zero digest in wolfCrypt tests */
        #define WC_TEST_NO_ECC_SIGN_VERIFY_ZERO_DIGEST
    #endif /* HAVE_ECC && HAVE_ECC_SIGN */

#endif /* WOLFSSL_ASYNC_CRYPT */
#ifndef WC_ASYNC_DEV_SIZE
    #define WC_ASYNC_DEV_SIZE 0
#endif
#ifdef HAVE_INTEL_QA /* Disable SHA512/224 and SHA512/256 support for QAT */
    #define WOLFSSL_NOSHA512_224
    #define WOLFSSL_NOSHA512_256
#endif
/* leantls checks */
#ifdef WOLFSSL_LEANTLS
    #ifndef HAVE_ECC
        #error leantls build needs ECC
    #endif
#endif /* WOLFSSL_LEANTLS*/

/* restriction with static memory */
#ifdef WOLFSSL_STATIC_MEMORY
    #if defined(HAVE_IO_POOL) || defined(XMALLOC_USER) || defined(NO_WOLFSSL_MEMORY)
         #error static memory cannot be used with HAVE_IO_POOL, XMALLOC_USER or NO_WOLFSSL_MEMORY
    #endif
    #if !defined(WOLFSSL_SP_MATH_ALL) && !defined(USE_FAST_MATH) && \
        !defined(WOLFSSL_SP_MATH) && !defined(NO_BIG_INT)
         #error The static memory option is only supported for fast math or SP Math
    #endif
#endif /* WOLFSSL_STATIC_MEMORY */

#ifdef HAVE_AES_KEYWRAP
    #ifndef WOLFSSL_AES_DIRECT
        #error AES key wrap requires AES direct please define WOLFSSL_AES_DIRECT
    #endif
#endif

#ifdef HAVE_PKCS7
    #if defined(NO_AES) && defined(NO_DES3)
        #error PKCS7 needs either AES or 3DES enabled, please enable one
    #endif
    #ifndef HAVE_AES_KEYWRAP
        #error PKCS7 requires AES key wrap please define HAVE_AES_KEYWRAP
    #endif
    #if defined(HAVE_ECC) && !defined(HAVE_X963_KDF)
        #error PKCS7 requires X963 KDF please define HAVE_X963_KDF
    #endif
#endif

#ifndef NO_PKCS12
    #undef  HAVE_PKCS12
    #define HAVE_PKCS12
#endif

#if !defined(NO_PKCS8) || defined(HAVE_PKCS12)
    #undef  HAVE_PKCS8
    #define HAVE_PKCS8
#endif

#if !defined(NO_PBKDF1) || defined(WOLFSSL_ENCRYPTED_KEYS) || \
    defined(HAVE_PKCS8) || defined(HAVE_PKCS12)
    #undef  HAVE_PBKDF1
    #define HAVE_PBKDF1
#endif

#if !defined(NO_PBKDF2) || defined(HAVE_PKCS7) || defined(HAVE_SCRYPT)
    #undef  HAVE_PBKDF2
    #define HAVE_PBKDF2
#endif


#if !defined(WOLFCRYPT_ONLY) && !defined(NO_OLD_TLS) && \
        (defined(NO_SHA) || defined(NO_MD5))
    #error old TLS requires MD5 and SHA
#endif

/* for backwards compatibility */
#if defined(TEST_IPV6) && !defined(WOLFSSL_IPV6)
    #define WOLFSSL_IPV6
#endif

/* ---------------------------------------------------------------------------
 * ASN Library Selection (default to ASN_TEMPLATE)
 * ---------------------------------------------------------------------------
 */
#if !defined(WOLFSSL_ASN_TEMPLATE) && !defined(WOLFSSL_ASN_ORIGINAL) && \
    !defined(NO_ASN)
    #define WOLFSSL_ASN_TEMPLATE
#endif

#if defined(WOLFSSL_DUAL_ALG_CERTS) && !defined(WOLFSSL_ASN_TEMPLATE)
    #error "Dual alg cert support requires the ASN.1 template feature."
#endif

#if defined(WOLFSSL_ACERT) && !defined(WOLFSSL_ASN_TEMPLATE)
    #error "Attribute Certificate support requires the ASN.1 template feature."
#endif

#if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
    #undef  WOLFSSL_ASN_ALL
    #define WOLFSSL_ASN_ALL
#endif

/* Enable all parsing features for ASN */
#ifdef WOLFSSL_ASN_ALL
    /* Alternate Names */
    #undef  WOLFSSL_ALT_NAMES
    #define WOLFSSL_ALT_NAMES

    /* Alternate Name: human readable form of IP address*/
    #undef  WOLFSSL_IP_ALT_NAME
    #define WOLFSSL_IP_ALT_NAME

    /* Alternate name: human readable form of registered ID */
    #undef  WOLFSSL_RID_ALT_NAME
    #define WOLFSSL_RID_ALT_NAME

    /* CA Issuer URI */
    #undef  WOLFSSL_ASN_CA_ISSUER
    #define WOLFSSL_ASN_CA_ISSUER

    /* FPKI (Federal PKI) extensions */
    #undef  WOLFSSL_FPKI
    #define WOLFSSL_FPKI

    /* Certificate policies */
    #undef  WOLFSSL_SEP
    #define WOLFSSL_SEP

    /* Support for full AuthorityKeyIdentifier extension.
     * Only supports copying full AKID from an existing certificate */
    #undef  WOLFSSL_AKID_NAME
    #define WOLFSSL_AKID_NAME

    /* Extended ASN.1 parsing support (typically used with cert gen) */
    #undef  WOLFSSL_CERT_EXT
    #define WOLFSSL_CERT_EXT

    /* Support for SubjectDirectoryAttributes extension */
    #undef  WOLFSSL_SUBJ_DIR_ATTR
    #define WOLFSSL_SUBJ_DIR_ATTR

    /* Support for SubjectInfoAccess extension */
    #undef  WOLFSSL_SUBJ_INFO_ACC
    #define WOLFSSL_SUBJ_INFO_ACC

    #undef  WOLFSSL_CERT_NAME_ALL
    #define WOLFSSL_CERT_NAME_ALL

    /* Store pointers to issuer name components (lengths and encodings) */
    #undef  WOLFSSL_HAVE_ISSUER_NAMES
    #define WOLFSSL_HAVE_ISSUER_NAMES

    /* Additional ASN.1 encoded name fields. See CTC_MAX_ATTRIB for max limit */
    #undef  WOLFSSL_MULTI_ATTRIB
    #define WOLFSSL_MULTI_ATTRIB

    /* Parsing of indefinite length encoded ASN.1
     * Optionally used by PKCS7/PKCS12 */
    #undef  ASN_BER_TO_DER
    #define ASN_BER_TO_DER

    /* Enable custom OID support for subject and request extensions */
    #undef  WOLFSSL_CUSTOM_OID
    #define WOLFSSL_CUSTOM_OID

    /* Support for full OID (not just sum) encoding */
    #undef  HAVE_OID_ENCODING
    #define HAVE_OID_ENCODING

    /* Support for full OID (not just sum) decoding */
    #undef  HAVE_OID_DECODING
    #define HAVE_OID_DECODING

    /* S/MIME - Secure Multipurpose Internet Mail Extension (used with PKCS7) */
    #undef  HAVE_SMIME
    #define HAVE_SMIME

    /* Enable compatibility layer function for getting time string */
    #undef  WOLFSSL_ASN_TIME_STRING
    #define WOLFSSL_ASN_TIME_STRING

    /* Support for parsing key usage */
    #undef  WOLFSSL_ASN_PARSE_KEYUSAGE
    #define WOLFSSL_ASN_PARSE_KEYUSAGE

    /* Support for parsing OCSP status */
    #undef  WOLFSSL_OCSP_PARSE_STATUS
    #define WOLFSSL_OCSP_PARSE_STATUS

    /* Extended Key Usage */
    #undef  WOLFSSL_EKU_OID
    #define WOLFSSL_EKU_OID

    /* Attribute Certificate support */
    #if defined(WOLFSSL_ASN_TEMPLATE) && !defined(WOLFSSL_ACERT)
        #define WOLFSSL_ACERT
    #endif
#endif

#if defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA) || \
    defined(WOLFSSL_MYSQL_COMPATIBLE) || defined(WOLFSSL_NGINX) || \
    defined(WOLFSSL_HAPROXY)
    #undef  WOLFSSL_ASN_TIME_STRING
    #define WOLFSSL_ASN_TIME_STRING
#endif

#if (defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT)) || \
    (defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA))
    #undef  WOLFSSL_ASN_PARSE_KEYUSAGE
    #define WOLFSSL_ASN_PARSE_KEYUSAGE
#endif

#if defined(HAVE_OCSP) && !defined(WOLFCRYPT_ONLY) && \
    (defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || \
     defined(WOLFSSL_HAPROXY) || defined(HAVE_LIGHTY) || \
     defined(WOLFSSL_APACHE_HTTPD))
    #undef  WOLFSSL_OCSP_PARSE_STATUS
    #define WOLFSSL_OCSP_PARSE_STATUS
#endif

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL) || \
    defined(OPENSSL_EXTRA_X509_SMALL) || defined(WOLFSSL_CERT_GEN)
    #undef  WOLFSSL_MULTI_ATTRIB
    #define WOLFSSL_MULTI_ATTRIB
#endif

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL) || \
    defined(OPENSSL_EXTRA_X509_SMALL)
    #undef  WOLFSSL_EKU_OID
    #define WOLFSSL_EKU_OID
#endif

/* Disable time checking if no timer */
#if defined(NO_ASN_TIME)
    #define NO_ASN_TIME_CHECK
#endif

/* ASN Unknown Extension Callback support */
#if defined(WOLFSSL_CUSTOM_OID) && defined(HAVE_OID_DECODING) && \
    defined(WOLFSSL_ASN_TEMPLATE)
    #undef  WC_ASN_UNKNOWN_EXT_CB
    #define WC_ASN_UNKNOWN_EXT_CB
#else
    /* if user supplied build option and not using ASN template, raise error */
    #if defined(WC_ASN_UNKNOWN_EXT_CB) && !defined(WOLFSSL_ASN_TEMPLATE)
        #error ASN unknown extension callback is only supported \
            with ASN template
    #endif
#endif


/* Linux Kernel Module */
#ifdef WOLFSSL_LINUXKM
    #ifdef HAVE_CONFIG_H
        #include <config.h>
        #undef HAVE_CONFIG_H
    #endif
    #ifndef NO_DEV_RANDOM
        #define NO_DEV_RANDOM
    #endif
    #ifndef NO_WRITEV
        #define NO_WRITEV
    #endif
    #ifndef NO_FILESYSTEM
        #define NO_FILESYSTEM
    #endif
    #ifndef NO_STDIO_FILESYSTEM
        #define NO_STDIO_FILESYSTEM
    #endif
    #ifndef WOLFSSL_NO_SOCK
        #define WOLFSSL_NO_SOCK
    #endif
    #ifndef WOLFSSL_DH_CONST
        #define WOLFSSL_DH_CONST
    #endif
    #ifndef WOLFSSL_USER_IO
        #define WOLFSSL_USER_IO
    #endif
    #ifndef USE_WOLF_STRTOK
        #define USE_WOLF_STRTOK
    #endif
    #ifndef WOLFSSL_OLD_PRIME_CHECK
        #define WOLFSSL_OLD_PRIME_CHECK
    #endif
    #ifndef WOLFSSL_TEST_SUBROUTINE
        #define WOLFSSL_TEST_SUBROUTINE static
    #endif
    #undef HAVE_PTHREAD
    #undef HAVE_STRINGS_H
    #undef HAVE_ERRNO_H
    #undef HAVE_THREAD_LS
    #undef HAVE_ATEXIT
    #undef WOLFSSL_HAVE_MIN
    #undef WOLFSSL_HAVE_MAX
    #define SIZEOF_LONG         8
    #define SIZEOF_LONG_LONG    8
    #define CHAR_BIT            8
    #ifndef WOLFSSL_SP_DIV_64
        #define WOLFSSL_SP_DIV_64
    #endif
    #ifndef WOLFSSL_SP_DIV_WORD_HALF
        #define WOLFSSL_SP_DIV_WORD_HALF
    #endif
    #ifdef __PIE__
        #define WC_NO_INTERNAL_FUNCTION_POINTERS
    #endif
#endif


/* Place any other flags or defines here */

#if defined(WOLFSSL_MYSQL_COMPATIBLE) && defined(_WIN32) \
                                      && defined(HAVE_GMTIME_R)
    #undef HAVE_GMTIME_R /* don't trust macro with windows */
#endif /* WOLFSSL_MYSQL_COMPATIBLE */

#if (defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || \
    defined(WOLFSSL_HAPROXY) || defined(HAVE_LIGHTY)) && !defined(NO_TLS)
    #define OPENSSL_NO_ENGINE

    /* Session Tickets will be enabled when --enable-opensslall is used.
     * Time is required for ticket expiration checking */
    #if !defined(HAVE_SESSION_TICKET) && !defined(NO_ASN_TIME)
        #define HAVE_SESSION_TICKET
    #endif
    /* OCSP will be enabled in configure.ac when --enable-opensslall is used,
     * but do not force all users to have it enabled. */
    #ifndef HAVE_OCSP
        /*#define HAVE_OCSP*/
    #endif
    #ifndef KEEP_OUR_CERT
        #define KEEP_OUR_CERT
    #endif
    #ifndef HAVE_SNI
        #define HAVE_SNI
    #endif
    #ifndef WOLFSSL_RSA_KEY_CHECK
        #define WOLFSSL_RSA_KEY_CHECK
    #endif
#endif

/* Make sure setting OPENSSL_ALL also sets OPENSSL_EXTRA. */
#if defined(OPENSSL_ALL) && !defined(OPENSSL_EXTRA)
    #define OPENSSL_EXTRA
#endif


#if (defined(OPENSSL_EXTRA) || defined(WOLFSSL_QT)) && \
    !defined(WOLFSSL_ASN_CA_ISSUER)
    #define WOLFSSL_ASN_CA_ISSUER
#endif


/* ---------------------------------------------------------------------------
 * OpenSSL compat layer
 * ---------------------------------------------------------------------------
 */
#ifdef OPENSSL_EXTRA
    #undef  WOLFSSL_ALWAYS_VERIFY_CB
    #define WOLFSSL_ALWAYS_VERIFY_CB

    #undef WOLFSSL_VERIFY_CB_ALL_CERTS
    #define WOLFSSL_VERIFY_CB_ALL_CERTS

    #undef WOLFSSL_EXTRA_ALERTS
    #define WOLFSSL_EXTRA_ALERTS

    #undef HAVE_EXT_CACHE
    #define HAVE_EXT_CACHE

    #undef WOLFSSL_FORCE_CACHE_ON_TICKET
    #define WOLFSSL_FORCE_CACHE_ON_TICKET

    #undef WOLFSSL_AKID_NAME
    #define WOLFSSL_AKID_NAME

    #undef HAVE_CTS
    #define HAVE_CTS

    #undef WOLFSSL_SESSION_ID_CTX
    #define WOLFSSL_SESSION_ID_CTX
#endif /* OPENSSL_EXTRA */

#ifdef OPENSSL_EXTRA_X509_SMALL
    #undef WOLFSSL_NO_OPENSSL_RAND_CB
    #define WOLFSSL_NO_OPENSSL_RAND_CB
#endif

#ifdef HAVE_SNI
    #define SSL_CTRL_SET_TLSEXT_HOSTNAME 55
#endif

/* both CURVE and ED small math should be enabled */
#ifdef CURVED25519_SMALL
    #define CURVE25519_SMALL
    #define ED25519_SMALL
#endif

/* both CURVE and ED small math should be enabled */
#ifdef CURVED448_SMALL
    #define CURVE448_SMALL
    #define ED448_SMALL
#endif


#ifndef WOLFSSL_ALERT_COUNT_MAX
    #define WOLFSSL_ALERT_COUNT_MAX 5
#endif

/* warning for not using harden build options (default with ./configure) */
/* do not warn if big integer support is disabled */
#if !defined(WC_NO_HARDEN) && !defined(NO_BIG_INT)
    #if (defined(USE_FAST_MATH) && !defined(TFM_TIMING_RESISTANT)) || \
        (defined(HAVE_ECC) && !defined(ECC_TIMING_RESISTANT)) || \
        (!defined(NO_RSA) && !defined(WC_RSA_BLINDING) && !defined(HAVE_FIPS) && \
            !defined(WC_NO_RNG))

        #ifndef _MSC_VER
            #warning "For timing resistance / side-channel attack prevention consider using harden options"
        #else
            #pragma message("Warning: For timing resistance / side-channel attack prevention consider using harden options")
        #endif
    #endif
#endif

#ifdef OPENSSL_COEXIST
    /* make sure old names are disabled */
    #ifndef NO_OLD_SSL_NAMES
        #define NO_OLD_SSL_NAMES
    #endif
    #ifndef NO_OLD_WC_NAMES
        #define NO_OLD_WC_NAMES
    #endif
    #if defined(HAVE_SELFTEST) || \
        (defined(HAVE_FIPS) && FIPS_VERSION3_LT(5,0,0))
        /* old FIPS needs this remapping. */
        #define Sha3 wc_Sha3
    #endif
#endif

#if defined(NO_OLD_WC_NAMES) || defined(OPENSSL_EXTRA)
    /* added to have compatibility with SHA256() */
    #if !defined(NO_OLD_SHA_NAMES) && (!defined(HAVE_FIPS) || \
            FIPS_VERSION_GT(2,0))
        #define NO_OLD_SHA_NAMES
    #endif
    #if !defined(NO_OLD_MD5_NAME) && (!defined(HAVE_FIPS) || \
            FIPS_VERSION_GT(2,0))
        #define NO_OLD_MD5_NAME
    #endif
#endif

/* switch for compatibility layer functionality. Has subparts i.e. BIO/X509
 * When opensslextra is enabled all subparts should be turned on. */
#ifdef OPENSSL_EXTRA
    #undef  OPENSSL_EXTRA_X509_SMALL
    #define OPENSSL_EXTRA_X509_SMALL
#endif /* OPENSSL_EXTRA */

/* support for converting DER to PEM */
#if (defined(WOLFSSL_KEY_GEN) && !defined(WOLFSSL_NO_DER_TO_PEM)) || \
    defined(WOLFSSL_CERT_GEN) || defined(OPENSSL_EXTRA)
    #undef  WOLFSSL_DER_TO_PEM
    #define WOLFSSL_DER_TO_PEM
#endif

/* keep backwards compatibility enabling encrypted private key */
#ifndef WOLFSSL_ENCRYPTED_KEYS
    #if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL) || \
        defined(HAVE_WEBSERVER)
        #define WOLFSSL_ENCRYPTED_KEYS
    #endif
#endif

/* support for disabling PEM to DER */
#if !defined(WOLFSSL_NO_PEM) && !defined(NO_CODING)
    #undef  WOLFSSL_PEM_TO_DER
    #define WOLFSSL_PEM_TO_DER
#endif

/* Parts of the openssl compatibility layer require peer certs */
#if (defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL) || \
     defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY) || \
     defined(HAVE_LIGHTY)) && !defined(NO_CERTS)
    #undef  KEEP_PEER_CERT
    #define KEEP_PEER_CERT
#endif

/* Always copy certificate(s) from SSL CTX to each SSL object on creation,
 * if this is not defined then each SSL object shares a pointer to the
 * original certificate buffer owned by the SSL CTX. */
#if defined(OPENSSL_ALL) && !defined(WOLFSSL_NO_COPY_CERT)
    #undef WOLFSSL_COPY_CERT
    #define WOLFSSL_COPY_CERT
#endif

/* Always copy private key from SSL CTX to each SSL object on creation,
 * if this is not defined then each SSL object shares a pointer to the
 * original key buffer owned by the SSL CTX. */
#if defined(OPENSSL_ALL) && !defined(WOLFSSL_NO_COPY_KEY)
    #undef WOLFSSL_COPY_KEY
    #define WOLFSSL_COPY_KEY
#endif

/*
 * Keeps the "Finished" messages after a TLS handshake for use as the so-called
 * "tls-unique" channel binding. See comment in internal.h around clientFinished
 * and serverFinished for more information.
 */
#if defined(OPENSSL_ALL) || defined(WOLFSSL_HAPROXY) || defined(WOLFSSL_WPAS)
    #undef  WOLFSSL_HAVE_TLS_UNIQUE
    #define WOLFSSL_HAVE_TLS_UNIQUE
#endif

/* WPAS Small option requires OPENSSL_EXTRA_X509_SMALL */
#if defined(WOLFSSL_WPAS_SMALL) && !defined(OPENSSL_EXTRA_X509_SMALL)
    #define OPENSSL_EXTRA_X509_SMALL
#endif

/* Web Server needs to enable OPENSSL_EXTRA_X509_SMALL */
#if defined(HAVE_WEBSERVER) && !defined(OPENSSL_EXTRA_X509_SMALL)
    #define OPENSSL_EXTRA_X509_SMALL
#endif

/* The EX data CRYPTO API's used with compatibility */
#if !defined(HAVE_EX_DATA_CRYPTO) && \
    (defined(OPENSSL_ALL) || defined(WOLFSSL_WPAS_SMALL) || \
    defined(HAVE_STUNNEL) || defined(WOLFSSL_NGINX) || \
    defined(HAVE_LIGHTY) || defined(WOLFSSL_HAPROXY) || \
    defined(WOLFSSL_OPENSSH) || defined(HAVE_SBLIM_SFCB) || \
    defined(WOLFSSL_WOLFSENTRY_HOOKS))
    #define HAVE_EX_DATA_CRYPTO
#endif

#if defined(WOLFSSL_WOLFSENTRY_HOOKS) && !defined(HAVE_EX_DATA_CLEANUP_HOOKS)
    #define HAVE_EX_DATA_CLEANUP_HOOKS
#endif

/* Enable EX Data support if required */
#if (defined(HAVE_EX_DATA_CRYPTO) || defined(HAVE_EX_DATA_CLEANUP_HOOKS)) && \
    !defined(HAVE_EX_DATA)
    #define HAVE_EX_DATA
#endif


/* RAW hash function APIs are not implemented */
#if defined(WOLFSSL_ARMASM) || defined(WOLFSSL_AFALG_HASH)
    #undef  WOLFSSL_NO_HASH_RAW
    #define WOLFSSL_NO_HASH_RAW
#endif

#if defined(HAVE_XCHACHA) && !defined(HAVE_CHACHA)
    /* XChacha requires ChaCha */
    #undef HAVE_XCHACHA
#endif

#if !defined(WOLFSSL_SHA384) && !defined(WOLFSSL_SHA512) && defined(NO_AES) && \
                                                          !defined(WOLFSSL_SHA3)
    #undef  WOLFSSL_NO_WORD64_OPS
    #define WOLFSSL_NO_WORD64_OPS
#endif

#if !defined(WOLFCRYPT_ONLY) && \
    (!defined(WOLFSSL_NO_TLS12) || defined(HAVE_KEYING_MATERIAL))
    #undef  WOLFSSL_HAVE_PRF
    #define WOLFSSL_HAVE_PRF
#endif

#if defined(NO_ASN) && defined(WOLFCRYPT_ONLY) && !defined(WOLFSSL_WOLFSSH)
    #undef  WOLFSSL_NO_INT_ENCODE
    #define WOLFSSL_NO_INT_ENCODE
#endif

#if defined(NO_ASN) && defined(WOLFCRYPT_ONLY)
    #undef  WOLFSSL_NO_INT_DECODE
    #define WOLFSSL_NO_INT_DECODE
#endif

#if defined(WOLFCRYPT_ONLY) && defined(WOLFSSL_RSA_VERIFY_ONLY) && \
    defined(WC_NO_RSA_OAEP)
    #undef  WOLFSSL_NO_CT_OPS
    #define WOLFSSL_NO_CT_OPS
#endif

#if defined(WOLFCRYPT_ONLY) && defined(NO_AES) && !defined(HAVE_CURVE25519) && \
        !defined(HAVE_CURVE448) && defined(WC_NO_RNG) && defined(WC_NO_RSA_OAEP)
    #undef  WOLFSSL_NO_CONST_CMP
    #define WOLFSSL_NO_CONST_CMP
#endif

#if defined(WOLFCRYPT_ONLY) && defined(NO_AES) && !defined(WOLFSSL_SHA384) && \
    !defined(WOLFSSL_SHA512) && defined(WC_NO_RNG) && \
    !defined(WOLFSSL_SP_MATH) && !defined(WOLFSSL_SP_MATH_ALL) \
    && !defined(USE_FAST_MATH) && defined(NO_SHA256)
    #undef  WOLFSSL_NO_FORCE_ZERO
    #define WOLFSSL_NO_FORCE_ZERO
#endif

/* Detect old cryptodev name */
#if defined(WOLF_CRYPTO_DEV) && !defined(WOLF_CRYPTO_CB)
    #define WOLF_CRYPTO_CB
#endif

#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_NO_SIGALG)
    #error TLS 1.3 requires the Signature Algorithms extension to be enabled
#endif

#ifndef NO_WOLFSSL_BASE64_DECODE
    #define WOLFSSL_BASE64_DECODE
#endif

#if defined(FORTRESS) && !defined(HAVE_EX_DATA)
    #define HAVE_EX_DATA
#endif

#ifdef HAVE_EX_DATA
    #ifndef MAX_EX_DATA
    #define MAX_EX_DATA 5  /* allow for five items of ex_data */
    #endif
#endif


#ifdef NO_WOLFSSL_SMALL_STACK
    #undef WOLFSSL_SMALL_STACK
#endif

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SMALL_STACK_STATIC) && \
    !defined(NO_WOLFSSL_SMALL_STACK_STATIC)
#define WOLFSSL_SMALL_STACK_STATIC
#endif

#ifdef WOLFSSL_SMALL_STACK_STATIC
    #undef WOLFSSL_SMALL_STACK_STATIC
    #define WOLFSSL_SMALL_STACK_STATIC static
#else
    #define WOLFSSL_SMALL_STACK_STATIC
#endif

/* The client session cache requires time for timeout */
#if defined(NO_ASN_TIME) && !defined(NO_SESSION_CACHE)
    #define NO_SESSION_CACHE
#endif

#if defined(NO_ASN_TIME) && !defined(WOLFSSL_NO_DEF_TICKET_ENC_CB)
    #define WOLFSSL_NO_DEF_TICKET_ENC_CB
#endif
#if defined(NO_ASN_TIME) && defined(HAVE_SESSION_TICKET)
    #undef HAVE_SESSION_TICKET
#endif

/* Use static ECC structs for Position Independent Code (PIC) */
#if defined(__IAR_SYSTEMS_ICC__) && defined(__ROPI__)
    #define WOLFSSL_ECC_CURVE_STATIC
    #define WOLFSSL_NAMES_STATIC
    #define WOLFSSL_NO_CONSTCHARCONST
#endif

/* FIPS v1 does not support TLS v1.3 (requires RSA PSS and HKDF) */
#if FIPS_VERSION_EQ(1,0)
    #undef WC_RSA_PSS
    #undef WOLFSSL_TLS13
#endif

/* FIPS v2 does not support WOLFSSL_PSS_LONG_SALT */
#if FIPS_VERSION_EQ(2,0)
    #ifdef WOLFSSL_PSS_LONG_SALT
        #undef WOLFSSL_PSS_LONG_SALT
    #endif
#endif

/* For FIPSv2 make sure the ECDSA encoding allows extra bytes
 * but make sure users consider enabling it */
#if !defined(NO_STRICT_ECDSA_LEN) && FIPS_VERSION_GE(2,0)
    /* ECDSA length checks off by default for CAVP testing
     * consider enabling strict checks in production */
    #define NO_STRICT_ECDSA_LEN
#endif

/* Do not allow using small stack with no malloc */
#if defined(WOLFSSL_NO_MALLOC) && \
    (defined(WOLFSSL_SMALL_STACK) || defined(WOLFSSL_SMALL_STACK_CACHE)) && \
    !defined(WOLFSSL_STATIC_MEMORY)
    #error Small stack cannot be used with no malloc (WOLFSSL_NO_MALLOC) and \
           without staticmemory (WOLFSSL_STATIC_MEMORY)
#endif

/* If malloc is disabled make sure it is also disabled in SP math */
#if defined(WOLFSSL_NO_MALLOC) && !defined(WOLFSSL_SP_NO_MALLOC) && \
    (defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL))
    #define WOLFSSL_SP_NO_MALLOC
#endif

/* Enable DH Extra for QT, openssl all, openssh and static ephemeral */
/* Allows export/import of DH key and params as DER */
#if !defined(NO_DH) && !defined(WOLFSSL_DH_EXTRA) && \
    (defined(WOLFSSL_QT) || defined(OPENSSL_ALL) || defined(WOLFSSL_OPENSSH) || \
     defined(WOLFSSL_STATIC_EPHEMERAL))
    #define WOLFSSL_DH_EXTRA
#endif

/* DH Extra is not supported on FIPS v1 or v2 (is missing DhKey .pub/.priv) */
#if defined(WOLFSSL_DH_EXTRA) && defined(HAVE_FIPS) && FIPS_VERSION_LE(2,0)
    #undef WOLFSSL_DH_EXTRA
#endif

/* wc_Sha512.devId isn't available before FIPS 5.1 */
#if defined(HAVE_FIPS) && FIPS_VERSION_LT(5,1)
    #define NO_SHA2_CRYPTO_CB
#endif

/* Enable HAVE_ONE_TIME_AUTH by default for use with TLS cipher suites
 * when poly1305 is enabled
 */
#if defined(HAVE_POLY1305) && !defined(HAVE_ONE_TIME_AUTH)
    #define HAVE_ONE_TIME_AUTH
#endif

/* This is checked for in configure.ac, so might want to do it in here as well.
 */
#if defined(HAVE_SECURE_RENEGOTIATION) && defined(HAVE_RENEGOTIATION_INDICATION)
    #error HAVE_RENEGOTIATION_INDICATION cannot be defined together with \
           HAVE_SECURE_RENEGOTIATION
#endif

/* Check for insecure build combination:
 * secure renegotiation   [enabled]
 * extended master secret [disabled]
 * session resumption     [enabled]
 */
#if defined(HAVE_SECURE_RENEGOTIATION) && !defined(HAVE_EXTENDED_MASTER) && \
    (defined(HAVE_SESSION_TICKET) || !defined(NO_SESSION_CACHE))
    /* secure renegotiation requires extended master secret with resumption */
    #ifndef _MSC_VER
        #warning Extended master secret must be enabled with secure renegotiation and session resumption
    #else
        #pragma message("Warning: Extended master secret must be enabled with secure renegotiation and session resumption")
    #endif

    /* Note: "--enable-renegotiation-indication" ("HAVE_RENEGOTIATION_INDICATION")
     * only sends the secure renegotiation extension, but is not actually supported.
     * This was added because some TLS peers required it even if not used, so we call
     * this "(FAKE Secure Renegotiation)"
     */
#endif

/* if secure renegotiation is enabled, make sure server info is enabled */
#if !defined(HAVE_RENEGOTIATION_INDICATION) &&                               \
  !defined(HAVE_SERVER_RENEGOTIATION_INFO) &&   \
  defined(HAVE_SECURE_RENEGOTIATION) &&         \
  !defined(NO_WOLFSSL_SERVER)
    #define HAVE_SERVER_RENEGOTIATION_INFO
#endif

/* Crypto callbacks should enable hash flag support */
#if defined(WOLF_CRYPTO_CB) && !defined(WOLFSSL_HASH_FLAGS)
    /* FIPS v1 and v2 do not support hash flags, so do not allow it with
     * crypto callbacks */
    #if !defined(HAVE_FIPS) || (defined(HAVE_FIPS) && \
            defined(HAVE_FIPS_VERSION) && HAVE_FIPS_VERSION >= 3)
        #define WOLFSSL_HASH_FLAGS
    #endif
#endif

#ifdef WOLFSSL_HAVE_KYBER
#define HAVE_PQC
#endif

/* Enable Post-Quantum Cryptography if we have liboqs from the OpenQuantumSafe
 * group */
#ifdef HAVE_LIBOQS
#define HAVE_PQC
#define HAVE_FALCON
#ifndef HAVE_DILITHIUM
    #define HAVE_DILITHIUM
#endif
#ifndef WOLFSSL_NO_SPHINCS
    #define HAVE_SPHINCS
#endif
#ifndef WOLFSSL_HAVE_KYBER
    #define WOLFSSL_HAVE_KYBER
    #define WOLFSSL_KYBER512
    #define WOLFSSL_KYBER768
    #define WOLFSSL_KYBER1024
#endif
#endif

#if (defined(HAVE_LIBOQS) ||                                            \
     defined(HAVE_LIBXMSS) ||                                           \
     defined(HAVE_LIBLMS) ||                                            \
     defined(WOLFSSL_DUAL_ALG_CERTS)) &&                                \
    !defined(WOLFSSL_EXPERIMENTAL_SETTINGS)
    #error Experimental settings without WOLFSSL_EXPERIMENTAL_SETTINGS
#endif

#if defined(HAVE_PQC) && !defined(HAVE_LIBOQS) && !defined(WOLFSSL_HAVE_KYBER)
#error Please do not define HAVE_PQC yourself.
#endif

#if defined(HAVE_PQC) && defined(WOLFSSL_DTLS13) && \
    !defined(WOLFSSL_DTLS_CH_FRAG)
#warning "Using DTLS 1.3 + pqc without WOLFSSL_DTLS_CH_FRAG will probably" \
         "fail.Use --enable-dtls-frag-ch to enable it."
#endif
#if !defined(WOLFSSL_DTLS13) && defined(WOLFSSL_DTLS_CH_FRAG)
#error "WOLFSSL_DTLS_CH_FRAG only works with DTLS 1.3"
#endif

/* SRTP requires DTLS */
#if defined(WOLFSSL_SRTP) && !defined(WOLFSSL_DTLS)
    #error The SRTP extension requires DTLS
#endif

/* FIPS v5 and older doesn't support WOLF_PRIVATE_KEY_ID with PK callbacks */
#if defined(HAVE_FIPS) && FIPS_VERSION_LT(5,3) && defined(HAVE_PK_CALLBACKS)
    #define NO_WOLF_PRIVATE_KEY_ID
#endif

/* Are we using an external private key store like:
 *     PKCS11 / HSM / crypto callback / PK callback */
#if !defined(WOLF_PRIVATE_KEY_ID) && !defined(NO_WOLF_PRIVATE_KEY_ID) && \
        (defined(HAVE_PKCS11) || defined(HAVE_PK_CALLBACKS) || \
         defined(WOLF_CRYPTO_CB) || defined(WOLFSSL_KCAPI))
         /* Enables support for using wolfSSL_CTX_use_PrivateKey_Id and
          *   wolfSSL_CTX_use_PrivateKey_Label */
        #define WOLF_PRIVATE_KEY_ID
#endif

/* With titan cache size there is too many sessions to fit with the default
 * multiplier of 8 */
#if defined(TITAN_SESSION_CACHE) && !defined(NO_SESSION_CACHE_REF)
    #define NO_SESSION_CACHE_REF
#endif

/* (D)TLS v1.3 requires 64-bit number wrappers as does XMSS and LMS. */
#if defined(WOLFSSL_TLS13) || defined(WOLFSSL_DTLS_DROP_STATS) || \
    (defined(WOLFSSL_WC_XMSS) && (!defined(WOLFSSL_XMSS_MAX_HEIGHT) || \
    WOLFSSL_XMSS_MAX_HEIGHT > 32)) || (defined(WOLFSSL_WC_LMS) && \
    !defined(WOLFSSL_LMS_VERIFY_ONLY))
    #undef WOLFSSL_W64_WRAPPER
    #define WOLFSSL_W64_WRAPPER
#endif

/* wc_xmss and wc_lms require these misc.c functions. */
#if defined(WOLFSSL_WC_XMSS) || defined(WOLFSSL_WC_LMS)
    #undef  WOLFSSL_NO_INT_ENCODE
    #undef  WOLFSSL_NO_INT_DECODE
#endif

/* DTLS v1.3 requires AES ECB if using AES */
#if defined(WOLFSSL_DTLS13) && !defined(NO_AES) && \
    !defined(WOLFSSL_AES_DIRECT)
#define WOLFSSL_AES_DIRECT
#endif

#if defined(WOLFSSL_DTLS13) && (!defined(WOLFSSL_DTLS) || \
                                !defined(WOLFSSL_TLS13))
#error "DTLS v1.3 requires both WOLFSSL_TLS13 and WOLFSSL_DTLS"
#endif

#if defined(WOLFSSL_QUIC) && defined(WOLFSSL_CALLBACKS)
    #error WOLFSSL_QUIC is incompatible with WOLFSSL_CALLBACKS.
#endif

/* RSA Key Checking is disabled by default unless WOLFSSL_RSA_KEY_CHECK is
 *   defined or FIPS v2 3389, FIPS v5 or later.
 * Not allowed for:
 *   RSA public only, CAVP selftest, fast RSA, user RSA, QAT or CryptoCell */
#if (defined(WOLFSSL_RSA_KEY_CHECK) || (defined(HAVE_FIPS) && FIPS_VERSION_GE(2,0))) && \
    !defined(WOLFSSL_NO_RSA_KEY_CHECK) && !defined(WOLFSSL_RSA_PUBLIC_ONLY) && \
    !defined(HAVE_INTEL_QA) && !defined(WOLFSSL_CRYPTOCELL) && \
    !defined(HAVE_SELFTEST)

    #undef  WOLFSSL_RSA_KEY_CHECK
    #define WOLFSSL_RSA_KEY_CHECK
#endif

/* ED448 Requires Shake256 */
#if defined(HAVE_ED448) && defined(WOLFSSL_SHA3)
    #undef  WOLFSSL_SHAKE256
    #define WOLFSSL_SHAKE256
#endif

/* SHAKE - Not allowed in FIPS v5.2 or older */
#if defined(WOLFSSL_SHA3) && (defined(HAVE_SELFTEST) || \
    (defined(HAVE_FIPS) && FIPS_VERSION_LE(5,2)))
    #undef  WOLFSSL_NO_SHAKE128
    #define WOLFSSL_NO_SHAKE128
    #undef  WOLFSSL_NO_SHAKE256
    #define WOLFSSL_NO_SHAKE256
#endif
/* SHAKE Disable */
#ifdef WOLFSSL_NO_SHAKE128
    #undef WOLFSSL_SHAKE128
#endif
#ifdef WOLFSSL_NO_SHAKE256
    #undef WOLFSSL_SHAKE256
#endif


/* Encrypted Client Hello - requires HPKE */
#if defined(HAVE_ECH) && !defined(HAVE_HPKE)
    #define HAVE_HPKE
#endif

/* Provide way to forcefully disable use of XREALLOC */
#ifdef WOLFSSL_NO_REALLOC
    #undef XREALLOC
#endif


/* ---------------------------------------------------------------------------
 * Deprecated Algorithm Handling
 *   Unless allowed via a build macro, disable support
 * ---------------------------------------------------------------------------*/

/* RC4: Per RFC7465 Feb 2015, the cipher suite has been deprecated due to a
 * number of exploits capable of decrypting portions of encrypted messages. */
#ifndef WOLFSSL_ALLOW_RC4
    #undef  NO_RC4
    #define NO_RC4
#endif

#if !defined(WOLFSSL_NO_ASYNC_IO) || defined(WOLFSSL_ASYNC_CRYPT) || \
     defined(WOLFSSL_NONBLOCK_OCSP)
    /* Enable asynchronous support in TLS functions to support one or more of
     * the following:
     * - re-entry after a network blocking return
     * - re-entry after OCSP blocking return
     * - asynchronous cryptography */
    #undef WOLFSSL_ASYNC_IO
    #define WOLFSSL_ASYNC_IO
#endif

#ifdef WOLFSSL_SYS_CA_CERTS
    #ifdef NO_FILESYSTEM
        /* Turning off WOLFSSL_SYS_CA_CERTS b/c NO_FILESYSTEM is defined */
        #undef WOLFSSL_SYS_CA_CERTS
    #endif

    #ifdef NO_CERTS
        /* Turning off WOLFSSL_SYS_CA_CERTS b/c NO_CERTS is defined */
        #undef WOLFSSL_SYS_CA_CERTS
    #endif
#endif /* WOLFSSL_SYS_CA_CERTS */

#if defined(SESSION_CACHE_DYNAMIC_MEM) && defined(PERSIST_SESSION_CACHE)
#error "Dynamic session cache currently does not support persistent session cache."
#endif

#ifdef WOLFSSL_HARDEN_TLS
    #if defined(HAVE_TRUNCATED_HMAC) && !defined(WOLFSSL_HARDEN_TLS_ALLOW_TRUNCATED_HMAC)
        #error "Truncated HMAC Extension not allowed https://www.rfc-editor.org/rfc/rfc9325#section-4.6"
    #endif
    #if !defined(NO_OLD_TLS) && !defined(WOLFSSL_HARDEN_TLS_ALLOW_OLD_TLS)
        #error "TLS < 1.2 protocol versions not allowed https://www.rfc-editor.org/rfc/rfc9325#section-3.1.1"
    #endif
    #if !defined(WOLFSSL_NO_TLS12) && !defined(HAVE_SECURE_RENEGOTIATION) && \
        !defined(HAVE_SERVER_RENEGOTIATION_INFO) && !defined(WOLFSSL_HARDEN_TLS_NO_SCR_CHECK)
        #error "TLS 1.2 requires at least HAVE_SERVER_RENEGOTIATION_INFO to send the secure renegotiation extension https://www.rfc-editor.org/rfc/rfc9325#section-3.5"
    #endif
    #if !defined(WOLFSSL_EXTRA_ALERTS) || !defined(WOLFSSL_CHECK_ALERT_ON_ERR)
        #error "RFC9325 requires some additional alerts to be sent"
    #endif
    /* Ciphersuite check done in internal.h */
#endif

/* Some final sanity checks. See esp32-crypt.h for Apple HomeKit config. */
#if defined(WOLFSSL_APPLE_HOMEKIT) || defined(CONFIG_WOLFSSL_APPLE_HOMEKIT)
    #ifndef WOLFCRYPT_HAVE_SRP
        #error "WOLFCRYPT_HAVE_SRP is required for Apple Homekit"
    #endif
    #ifndef HAVE_CHACHA
        #error "HAVE_CHACHA is required for Apple Homekit"
    #endif
    #ifdef  USE_FAST_MATH
        #ifdef FP_MAX_BITS
            #if FP_MAX_BITS < (8192 * 2)
                #error "HomeKit FP_MAX_BITS must at least (8192 * 2)"
            #endif
        #else
            #error "HomeKit FP_MAX_BITS must be assigned a value (8192 * 2)"
        #endif
    #endif
#endif

#if defined(CONFIG_WOLFSSL_NO_ASN_STRICT) && !defined(WOLFSSL_NO_ASN_STRICT)
    /* The settings.h and/or user_settings.h should have detected config
     * values from Kconfig and set the appropriate wolfSSL macro: */
    #error "CONFIG_WOLFSSL_NO_ASN_STRICT found without WOLFSSL_NO_ASN_STRICT"
#endif

#if defined(WOLFSSL_ESPIDF) && defined(ARDUINO)
    #error "Found both ESPIDF and ARDUINO. Pick one."
#endif

#if defined(CONFIG_MBEDTLS_CERTIFICATE_BUNDLE) && \
    defined(CONFIG_WOLFSSL_CERTIFICATE_BUNDLE) && \
            CONFIG_MBEDTLS_CERTIFICATE_BUNDLE  && \
            CONFIG_WOLFSSL_CERTIFICATE_BUNDLE
    #error "mbedTLS and wolfSSL Certificate Bundles both enabled. Pick one".
#endif

#if defined(HAVE_FIPS) && defined(HAVE_PKCS11)
    #error "PKCS11 not allowed with FIPS enabled (Crypto outside boundary)"
#endif

#if defined(WOLFSSL_CAAM_BLOB)
    #ifndef WOLFSSL_CAAM
        #error "WOLFSSL_CAAM_BLOB requires WOLFSSL_CAAM"
    #endif
#endif

#if defined(HAVE_ED25519)
    #ifndef WOLFSSL_SHA512
        #error "HAVE_ED25519 requires WOLFSSL_SHA512"
    #endif
#endif

#if defined(OPENSSL_ALL) && defined(OPENSSL_COEXIST)
    #error "OPENSSL_ALL can not be defined with OPENSSL_COEXIST"
#endif

#if !defined(NO_DSA) && defined(NO_SHA)
    #error "Please disable DSA if disabling SHA-1"
#endif

#if defined(WOLFSSL_SYS_CRYPTO_POLICY)
    #if !defined(WOLFSSL_CRYPTO_POLICY_FILE)
        #error "WOLFSSL_SYS_CRYPTO_POLICY requires a crypto policy file"
    #endif /* ! WOLFSSL_CRYPTO_POLICY_FILE */

    #if !defined(OPENSSL_EXTRA)
        #error "WOLFSSL_SYS_CRYPTO_POLICY requires OPENSSL_EXTRA"
    #endif /* ! OPENSSL_EXTRA */
#endif /* WOLFSSL_SYS_CRYPTO_POLICY */

/* if configure.ac turned on this feature, HAVE_ENTROPY_MEMUSE will be set,
 * also define HAVE_WOLFENTROPY */
#ifdef HAVE_ENTROPY_MEMUSE
    #ifndef HAVE_WOLFENTROPY
        #define HAVE_WOLFENTROPY
    #endif
#elif defined(HAVE_WOLFENTROPY)
    /* else if user_settings.h only defined HAVE_WOLFENTROPY
     * also define HAVE_ENTROPY_MEMUSE */
    #ifndef HAVE_ENTROPY_MEMUSE
        #define HAVE_ENTROPY_MEMUSE
    #endif
#endif /* HAVE_ENTROPY_MEMUSE */

#ifdef __cplusplus
    }   /* extern "C" */
#endif

#endif
