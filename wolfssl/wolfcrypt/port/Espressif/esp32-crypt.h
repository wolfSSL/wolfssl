/* esp32-crypt.h
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
#ifndef __ESP32_CRYPT_H__

#define __ESP32_CRYPT_H__

/* WOLFSSL_USER_SETTINGS must be defined, typically in the CMakeLists.txt:
 *
 * set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_USER_SETTINGS") */
#include <wolfssl/wolfcrypt/settings.h> /* references user_settings.h */

#if defined(WOLFSSL_ESPIDF) /* Entire file is only for Espressif EDP-IDF */

#ifndef WOLFSSL_USER_SETTINGS
    #error  "WOLFSSL_USER_SETTINGS must be defined for Espressif targets"
#endif

#include "sdkconfig.h" /* ensure ESP-IDF settings are available everywhere */

/* wolfSSL  */
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/types.h>    /* for MATH_INT_T */

/* Espressif */
#include <esp_idf_version.h>
#include <esp_types.h>
#include <esp_log.h>

#ifndef _INTPTR_T_DECLARED
    #define intptr_t (void*)
#endif

#ifndef _UINTPTR_T_DECLARED
    #define uintptr_t (void*)
#endif

#ifndef NULLPTR
    #define NULLPTR ((uintptr_t)NULL)
#endif

#if ESP_IDF_VERSION_MAJOR >= 4
    #define WOLFSSL_ESPIDF_BLANKLINE_MESSAGE ""
#else
    /* Older ESP-IDF such as that for ESP8266 do not support empty strings */
    #define WOLFSSL_ESPIDF_BLANKLINE_MESSAGE "."
#endif

#if defined(WOLFSSL_STACK_CHECK)
    #define CTX_STACK_CHECK(ctx) esp_sha_stack_check(ctx)
#else
    #define CTX_STACK_CHECK(ctx) {}
#endif

#if defined(CONFIG_IDF_TARGET)
    #define FOUND_CONFIG_IDF_TARGET CONFIG_IDF_TARGET
#else
    #define FOUND_CONFIG_IDF_TARGET "(unknown device)"
#endif

/* Optional exit message.
 * The WOLFSSL_COMPLETE keyword exits wolfSSL test harness script. */
#define WOLFSSL_ESPIDF_EXIT_MESSAGE \
    "\n\nDevice: " FOUND_CONFIG_IDF_TARGET  \
    "\n\nDone!"                 \
    "\n\nWOLFSSL_COMPLETE"      \
    "\n\nIf running from idf.py monitor, press twice: Ctrl+]"

#define WOLFSSL_ESPIDF_VERBOSE_EXIT_MESSAGE(s, err) \
    "\n\nDevice: " FOUND_CONFIG_IDF_TARGET  \
    "\n\nExit code: %d "        \
    "\n\n"s                     \
    "\n\nWOLFSSL_COMPLETE"      \
    "\n\nIf running from idf.py monitor, press twice: Ctrl+]", \
    (err)

/* exit codes to be used in tfm.c, sp_int.c, integer.c, etc.
 *
 * see wolfssl/wolfcrypt/error-crypt.h
 *
 * WC_HW_E - generic hardware failure. Consider falling back to SW.
 * WC_HW_WAIT_E - waited too long for HW, fall back to SW
 */

/* Exit codes only used in Espressif port: */
enum {
    ESP_MP_HW_FALLBACK          = (WC_LAST_E - 2),
    ESP_MP_HW_VALIDATION_ACTIVE = (WC_LAST_E - 3)
};

/* MP_HW_FALLBACK: signal to caller to fall back to SW for math:
 *   algorithm not supported in SW
 *   known state needing only SW, (e.g. ctx copy)
 *   any other reason to force SW  (was -108)*/
#define MP_HW_FALLBACK ESP_MP_HW_FALLBACK

/* MP_HW_VALIDATION_ACTIVE this is informative only:
 * typically also means "MP_HW_FALLBACK": fall back to SW.
 *  optional HW validation active, so compute in SW to compare.
 *  fall back to SW, typically only used during debugging. (was -109)
 */
#define MP_HW_VALIDATION_ACTIVE ESP_MP_HW_VALIDATION_ACTIVE

/*
*******************************************************************************
*******************************************************************************
** Global Settings:
**
**   Settings that start with "CONFIG_" are typically defined in sdkconfig.h
**
** Primary Settings:
**
** WC_NO_HARDEN
**   Disables some timing resistance / side-channel attack prevention.
**
** NO_ESPIDF_DEFAULT
**   When defined, disables some default definitions. See wolfcrypt/settings.h
**
** NO_ESP32_CRYPT
**   When defined, disables all hardware acceleration on the ESP32
**
** NO_WOLFSSL_ESP32_CRYPT_HASH
**   Used to disabled only hash hardware, all algorithms: SHA2, etc.
**
**   NO_WOLFSSL_ESP32_CRYPT_HASH_SHA
**     When defined, disables only SHA hardware acceleration, uses SW.
**
**   NO_WOLFSSL_ESP32_CRYPT_HASH_SHA224
**     When defined, disables only SHA-224 hardware acceleration, uses SW.
**
**   NO_WOLFSSL_ESP32_CRYPT_HASH_SHA384
**     When defined, disables only SHA-384 hardware acceleration, uses SW.
**
**   NO_WOLFSSL_ESP32_CRYPT_HASH_SHA256
**     When defined, disables only SHA-256 hardware acceleration, uses SW.
**
**   NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512
**     When defined, disables only SHA-512 hardware acceleration, uses SW.
**
** WOLFSSL_NOSHA512_224
**   Define to disable SHA-512/224
**
** WOLFSSL_NOSHA512_256
**   Define to disable SHA-512/512
**
** WOLFSSL_ESP32_CRYPT_RSA_PRI
**   Defined in wolfSSL settings.h: this turns on or off esp32_mp math library.
**   Unless turned off, this is enabled by default for the ESP32
**
**   NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL
**     Turns off hardware acceleration esp_mp_mul()
**
**   NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD
**     Turns off hardware acceleration esp_mp_exptmod()
**
**   NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD
**     Turns off hardware acceleration esp_mp_mulmod()
**
** NO_WOLFSSL_ESP32_CRYPT_AES
**   Used to disable only AES hardware algorithms. Software used instead.
**
*******************************************************************************
** Math library settings: TFM
*******************************************************************************
** Listed in increasing order of complexity:
**
** WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL
**   When defined, use hardware acceleration esp_mp_mul()
**   for Large Number Multiplication: Z = X * Y
**   Currently defined by default in tfm.c, see above to disable.
**
** WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD
**   When defined, use hardware acceleration esp_mp_exptmod()
**   for Large Number Modular Exponentiation Z = X^Y mod M
**   Currently defined by default in tfm.c, see above to disable.
**
** WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD
**   When defined, use hardware acceleration esp_mp_mulmod()
**   for Large Number Modular Multiplication: Z = X * Y mod M
**   Currently defined by default in tfm.c, see above to disable.
**
**
*******************************************************************************
** Optional Settings:
*******************************************************************************
**
** WOLFSSL_HW_METRICS
**   Enables metric counters for calls to HW, success, fall back, oddities.
**
** WOLFSSL_HAS_METRICS
**   Indicates that we actually have metrics to show. Useful for old wolfSSL
**   libraries tested with newer examples, or when all HW turned off.
**
** DEBUG_WOLFSSL
**   Turns on development testing. Validates HW accelerated results to software
**   - Automatically turns on WOLFSSL_HW_METRICS
**
** DEBUG_WOLFSSL_SHA_MUTEX
**   Turns on diagnostic messages for SHA mutex. Note that given verbosity,
**   there may be TLS timing issues encountered. Use with caution.
**
** DEBUG_WOLFSSL_ESP32_UNFINISHED_HW
**   This may be interesting in that HW may have been unnessearily locked
**   for hash that was never completed. (typically encountered at `free1` time)
**
** LOG_LOCAL_LEVEL
**   Debugging. Default value is ESP_LOG_DEBUG
**
** ESP_VERIFY_MEMBLOCK
**   Used to re-read data from registers in esp32_mp & verify written contents
**   actually match the source data.
**
** WOLFSSL_ESP32_CRYPT_DEBUG
**   When defined, enables hardware cryptography debugging.
**
** WOLFSSL_DEBUG_ESP_RSA_MULM_BITS
**   Shows a warning when mulm falls back for minimum number of bits.
**
** WOLFSSL_DEBUG_ESP_HW_MULTI_RSAMAX_BITS
**   Shows a marning when multiplication math bits have exceeded hardware
**   capabilities and will fall back to slower software.
**
** WOLFSSL_DEBUG_ESP_HW_MOD_RSAMAX_BITS
**   Shows a marning when modular math bits have exceeded hardware capabilities
**   and will fall back to slower software.
**
** NO_HW_MATH_TEST
**   Even if HW is enabled, do not run HW math tests. See HW_MATH_ENABLED.
**
** NO_ESP_MP_MUL_EVEN_ALT_CALC
**   Used during Z = X * Y mod M
**   By default, even moduli use a two step HW esp_mp_mul with SW mp_mod.
**   Enable this to instead fall back to pure software mp_mulmod.
**
** NO_RECOVER_SOFTWARE_CALC
**   When defined, will NOT recover software calculation result when not
**   matched with hardware. Useful only during development. Needs DEBUG_WOLFSSL
**
** ESP_PROHIBIT_SMALL_X
**   When set to 1 X operands less than 8 bits will fall back to SW.
**
** ESP_NO_ERRATA_MITIGATION
**   Disable all errata mitigation code.
**
** USE_ESP_DPORT_ACCESS_READ_BUFFER
**   Sets ESP_NO_ERRATA_MITIGATION and uses esp_dport_access_read_buffer()
**
** ESP_MONITOR_HW_TASK_LOCK
**   Although wolfSSL is in general not fully thread safe, this option
**   enables some features that can be useful in a multi-threaded environment.
**
*******************************************************************************
** Settings used from <esp_idf_version.h>
**   see .\esp-idf\v[N]\components\esp_common\include
*******************************************************************************
**
** ESP_IDF_VERSION_MAJOR
**   Espressif ESP-IDF Version (e.g. 4, 5)
**
*******************************************************************************
** Settings used from ESP-IDF (sdkconfig.h)
*******************************************************************************
**
** CONFIG_IDF_TARGET_[SoC]
**   CONFIG_IDF_TARGET_ESP32
**   CONFIG_IDF_TARGET_ESP32C2
**   CONFIG_IDF_TARGET_ESP32C3
**   CONFIG_IDF_TARGET_ESP32C6
**   CONFIG_IDF_TARGET_ESP32S2
**   CONFIG_IDF_TARGET_ESP32S3
**   CONFIG_IDF_TARGET_ESP32H2
**
]*******************************************************************************
** Informative settings. Not meant to be edited:
*******************************************************************************
**
** HW_MATH_ENABLED
**   Used to detect if any hardware math acceleration algorithms are used.
**   This is typically only used to flag wolfCrypt tests to run HW tests.
**   See NO_HW_MATH_TEST.
**
*******************************************************************************
** WOLFSSL_FULL_WOLFSSH_SUPPORT
**   TODO - there's a known, unresolved problem with SHA256 in wolfSSH
**   Until fixed by a release version or this macro being define once resolved,
**   this macro should remain undefined.
**
*/
#ifdef WOLFSSL_ESP32_CRYPT_DEBUG
    #undef LOG_LOCAL_LEVEL
    #define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#else
    #undef LOG_LOCAL_LEVEL
    #define LOG_LOCAL_LEVEL CONFIG_LOG_DEFAULT_LEVEL
#endif

#include <freertos/FreeRTOS.h>

#if defined(CONFIG_IDF_TARGET_ESP32)
    /* there's no SHA-224 HW on the ESP32 */
    #undef  NO_WOLFSSL_ESP32_CRYPT_HASH_SHA224
    #define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA224
    #include "soc/dport_reg.h"
    #include <soc/hwcrypto_reg.h>

    #if ESP_IDF_VERSION_MAJOR < 5
        #include <soc/cpu.h>
    #endif

    #if defined(ESP_IDF_VERSION_MAJOR) && ESP_IDF_VERSION_MAJOR >= 5
        #include <esp_private/periph_ctrl.h>
    #else
        #include <driver/periph_ctrl.h>
    #endif

    #if ESP_IDF_VERSION_MAJOR >= 4
        #include <esp32/rom/ets_sys.h>
    #else
        #include <rom/ets_sys.h>
    #endif
    #define ESP_PROHIBIT_SMALL_X FALSE
    /***** END CONFIG_IDF_TARGET_ESP32 *****/

#elif defined(CONFIG_IDF_TARGET_ESP32C2) || \
      defined(CONFIG_IDF_TARGET_ESP8684)
    /* ESP8684 is essentially ESP32-C2 chip + flash embedded together in a
     * single QFN 4x4 mm package. Out of released documentation, Technical
     * Reference Manual as well as ESP-IDF Programming Guide is applicable
     * to both ESP32-C2 and ESP8684.
     *
     * Note there is not currently an expected CONFIG_IDF_TARGET_ESP8684.
     * The ESP8684 is detected with CONFIG_IDF_TARGET_ESP32C2.
     * The macro is included for clarity, and possible future rename. */

    /* #define NO_ESP32_CRYPT */
    /* #define NO_WOLFSSL_ESP32_CRYPT_HASH */
    /* No AES HW */
    #define NO_WOLFSSL_ESP32_CRYPT_AES
    /* No RSA HW:               */
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI
    /* No RSA, so no mp_mul:    */
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL
    /* No RSA, so no mp_mulmod: */
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD
    /* No RSA, no mp_exptmod:   */
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD

    #include <soc/dport_access.h>
    #include <soc/hwcrypto_reg.h>

    #if ESP_IDF_VERSION_MAJOR < 5
        #include <soc/cpu.h>
    #endif

    #if defined(ESP_IDF_VERSION_MAJOR) && ESP_IDF_VERSION_MAJOR >= 5
        #include <esp_private/periph_ctrl.h>
    #else
        #include <driver/periph_ctrl.h>
    #endif

    #if ESP_IDF_VERSION_MAJOR >= 4
        /* #include <esp32/rom/ets_sys.h> */
    #else
        #include <rom/ets_sys.h>
    #endif

/* If for some reason there's a desire to disable specific HW on the C2: */
/*  #undef  NO_WOLFSSL_ESP32_CRYPT_HASH_SHA                              */
/*  #define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA     there is SHA HW on C2    */
/*  #undef  NO_WOLFSSL_ESP32_CRYPT_HASH_SHA224                           */
/*  #define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA224  there is SHA224 HW on C2 */
/*  #undef  NO_WOLFSSL_ESP32_CRYPT_HASH_SHA256                           */
/*  #define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA256  there is SHA256 HW on C2 */

    /* Code will fall back to SW with warning if these are removed:
     * Note there is no SHA384/SHA512 HW on ESP32-C3 */
    #undef  NO_WOLFSSL_ESP32_CRYPT_HASH_SHA384
    #define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA384
    #undef  NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512
    #define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512
    /***** END CONFIG_IDF_TARGET_ESP32C2 aka CONFIG_IDF_TARGET_ESP8684 *****/

#elif defined(CONFIG_IDF_TARGET_ESP32C3)
    #include <soc/dport_access.h>
    #include <soc/hwcrypto_reg.h>

    #if ESP_IDF_VERSION_MAJOR < 5
        #include <soc/cpu.h>
    #endif

    #if defined(ESP_IDF_VERSION_MAJOR) && ESP_IDF_VERSION_MAJOR >= 5
        #include <esp_private/periph_ctrl.h>
    #else
        #include <driver/periph_ctrl.h>
    #endif

    #if ESP_IDF_VERSION_MAJOR >= 4
    /* #include <esp32/rom/ets_sys.h> */
    #else
        #include <rom/ets_sys.h>
    #endif

/* If for some reason there's a desire to disable specific HW on the C3: */
/*  #undef  NO_WOLFSSL_ESP32_CRYPT_HASH_SHA                              */
/*  #define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA     there is SHA HW on C3    */
/*  #undef  NO_WOLFSSL_ESP32_CRYPT_HASH_SHA224                           */
/*  #define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA224  there is SHA224 HW on C3 */
/*  #undef  NO_WOLFSSL_ESP32_CRYPT_HASH_SHA256                           */
/*  #define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA256  there is SHA256 HW on C3 */

    /* Code will fall back to SW with warning if these are removed:
     * Note there is no SHA384/SHA512 HW on ESP32-C3 */
    #undef  NO_WOLFSSL_ESP32_CRYPT_HASH_SHA384
    #define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA384
    #undef  NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512
    #define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512
    /***** END CONFIG_IDF_TARGET_ESP32C3 *****/

#elif defined(CONFIG_IDF_TARGET_ESP32C6)
    #include <soc/dport_access.h>
    #include <soc/hwcrypto_reg.h>

    #if ESP_IDF_VERSION_MAJOR < 5
        #include <soc/cpu.h>
    #endif

    #if defined(ESP_IDF_VERSION_MAJOR) && ESP_IDF_VERSION_MAJOR >= 5
        #include <esp_private/periph_ctrl.h>
    #else
        #include <driver/periph_ctrl.h>
    #endif

    #if ESP_IDF_VERSION_MAJOR >= 4
        /* #include <esp32/rom/ets_sys.h> */
    #else
        #include <rom/ets_sys.h>
    #endif

/* If for some reason there's a desire to disable specific SHA HW on the C6: */
/*  #undef  NO_WOLFSSL_ESP32_CRYPT_HASH_SHA                                  */
/*  #define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA     there *is* SHA HW on C6      */
/*  #undef  NO_WOLFSSL_ESP32_CRYPT_HASH_SHA224                               */
/*  #define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA224  there *is* SHA224 HW on C6   */
/*  #undef  NO_WOLFSSL_ESP32_CRYPT_HASH_SHA256                               */
/*  #define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA256  there *is* SHA225 HW on C6   */

    /* Code will fall back to SW with warning if these are removed:
     * note there is no SHA384/SHA512 HW on C6 */
    #undef  NO_WOLFSSL_ESP32_CRYPT_HASH_SHA384
    #define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA384
    #undef  NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512
    #define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512
    /***** END CONFIG_IDF_TARGET_ESP32C6 *****/

#elif defined(CONFIG_IDF_TARGET_ESP32H2)
    /*  wolfSSL Hardware Acceleration not yet implemented. Note: no WiFi.  */
    #define NO_ESP32_CRYPT
    /***** END CONFIG_IDF_TARGET_ESP32H2 *****/

#elif defined(CONFIG_IDF_TARGET_ESP32S2)
    #include "soc/dport_reg.h"
    #include <soc/hwcrypto_reg.h>
    #if defined(ESP_IDF_VERSION_MAJOR) && ESP_IDF_VERSION_MAJOR >= 5
        #include <esp_private/periph_ctrl.h>
    #else
        #include <driver/periph_ctrl.h>
    #endif
    #define ESP_PROHIBIT_SMALL_X 0
    /***** END CONFIG_IDF_TARGET_ESP32S2 *****/

#elif defined(CONFIG_IDF_TARGET_ESP32S3)
    #include "soc/dport_reg.h"
    #include <soc/hwcrypto_reg.h>
    #if defined(ESP_IDF_VERSION_MAJOR) && ESP_IDF_VERSION_MAJOR >= 5
        #include <esp_private/periph_ctrl.h>
    #else
        #include <driver/periph_ctrl.h>
    #endif
    #define ESP_PROHIBIT_SMALL_X 0
    /***** END CONFIG_IDF_TARGET_ESP32S3 *****/
#else
    /* Unknown: Not yet supported. Assume no HW. */
    #define NO_ESP32_CRYPT
    /***** END CONFIG_IDF_TARGET_[x] config unknown *****/

#endif /* CONFIG_IDF_TARGET target check */

#ifdef NO_ESP32_CRYPT
    /* There's no hardware acceleration, so ensure everything is disabled: */
    #undef  NO_WOLFSSL_ESP32_CRYPT_HASH
    #define NO_WOLFSSL_ESP32_CRYPT_HASH
    #undef  NO_WOLFSSL_ESP32_CRYPT_AES
    #define NO_WOLFSSL_ESP32_CRYPT_AES
    #undef  NO_WOLFSSL_ESP32_CRYPT_RSA_PRI
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI
#endif

#ifdef NO_WOLFSSL_ESP32_CRYPT_HASH
    /* There's no SHA hardware acceleration, so ensure all are disabled: */
    #undef  NO_WOLFSSL_ESP32_CRYPT_HASH_SHA
    #define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA
    #undef  NO_WOLFSSL_ESP32_CRYPT_HASH_SHA224
    #define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA224
    #undef  NO_WOLFSSL_ESP32_CRYPT_HASH_SHA256
    #define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA256
    #undef  NO_WOLFSSL_ESP32_CRYPT_HASH_SHA384
    #define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA384
    #undef  NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512
    #define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512
    /***** END CONFIG_IDF_TARGET_[x] config unknown *****/

#endif /* CONFIG_IDF_TARGET target check */

#ifdef NO_WOLFSSL_ESP32_CRYPT_RSA_PRI
    /* With RSA disabled (or not available), explicitly disable each: */
    #undef  NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL
    #undef  NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD
    #undef  NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD
#else
    #if defined(NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL) && \
        defined(NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD) && \
        defined(NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD)
        #warning "MP_MUL, MULMOD, EXPTMOD all turned off. " && \
                 "Define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI to disable all math HW"
        #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI
    #endif
#endif /* !NO_WOLFSSL_ESP32_CRYPT_RSA_PRI */

#if defined(USE_ESP_DPORT_ACCESS_READ_BUFFER)
    #define ESP_NO_ERRATA_MITIGATION
#endif

#ifdef SINGLE_THREADED
    #ifdef WOLFSSL_DEBUG_MUTEX
        #undef  ESP_MONITOR_HW_TASK_LOCK
        #define ESP_MONITOR_HW_TASK_LOCK
    #endif
#else
    /* Unless explicitly disabled, monitor task lock when not single thread. */
    #ifndef ESP_DISABLE_HW_TASK_LOCK
        #define ESP_MONITOR_HW_TASK_LOCK
    #endif
#endif

/* Resulting settings review for syntax highlighter review only: */
#if defined(NO_ESP32_CRYPT)                     || \
    defined(NO_WOLFSSL_ESP32_CRYPT_HASH)        || \
    defined(NO_WOLFSSL_ESP32_CRYPT_AES)         || \
    defined(NO_WOLFSSL_ESP32_CRYPT_RSA_PRI)     || \
    defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA)    || \
    defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA224) || \
    defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA256) || \
    defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA384) || \
    defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512) || \
    defined(WOLFSSL_ESP32_CRYPT_DEBUG)
#endif

/*
******************************************************************************
** wolfssl component Kconfig file settings
******************************************************************************
 * Naming convention:
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



/* Pre-set some hardware acceleration from Kconfig / menuconfig settings */
#ifdef CONFIG_ESP_WOLFSSL_NO_ESP32_CRYPT
    #define NO_ESP32_CRYPT
    #define NO_WOLFSSL_ESP32_CRYPT_AES
    #define NO_WOLFSSL_ESP32_CRYPT_HASH
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD
#endif
#ifdef CONFIG_ESP_WOLFSSL_NO_HW_AES
    #define NO_WOLFSSL_ESP32_CRYPT_AES
#endif
#ifdef CONFIG_ESP_WOLFSSL_NO_HW_HASH
    #define NO_WOLFSSL_ESP32_CRYPT_HASH
#endif
#ifdef CONFIG_ESP_WOLFSSL_NO_HW_RSA_PRI
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD
#endif
#ifdef CONFIG_ESP_WOLFSSL_NO_HW_RSA_PRI_MP_MUL
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL
#endif
#ifdef CONFIG_ESP_WOLFSSL_NO_HW_RSA_PRI_MULMOD
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD
#endif
#ifdef CONFIG_ESP_WOLFSSL_NO_HW_RSA_PRI_EXPTMOD
    #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD
#endif

/* wolfCrypt test settings */
#ifdef CONFIG_ESP_WOLFSSL_ENABLE_TEST
    #ifdef CONFIG_WOLFSSL_HAVE_WOLFCRYPT_TEST_OPTIONS
        #define HAVE_WOLFCRYPT_TEST_OPTIONS
    #endif
#endif

/* debug options */
#if defined(CONFIG_ESP_WOLFSSL_DEBUG_WOLFSSL)
    /* wolfSSH debugging enabled via Kconfig / menuconfig */
    #define DEBUG_WOLFSSL
#endif

/*
******************************************************************************
** END wolfssl component Kconfig file settings
******************************************************************************
*/

#ifdef __cplusplus
extern "C"
{
#endif

/*
******************************************************************************
** Some common esp utilities
******************************************************************************
*/

    WOLFSSL_LOCAL int esp_ShowExtendedSystemInfo(void);

    WOLFSSL_LOCAL esp_err_t esp_DisableWatchdog(void);

    WOLFSSL_LOCAL esp_err_t esp_EnableWatchdog(void);

    /* Compare MATH_INT_T A to MATH_INT_T B
     * During debug, the strings name_A and name_B can help
     * identify variable name. */
    WOLFSSL_LOCAL int esp_mp_cmp(char* name_A, MATH_INT_T* A,
                                 char* name_B, MATH_INT_T* B);

    /* Show MATH_INT_T value attributes.  */
    WOLFSSL_LOCAL int esp_show_mp_attributes(char* c, MATH_INT_T* X);

    /* Show MATH_INT_T value.
     *
     * Calls esp_show_mp_attributes().
     *
     * During debug, the string name_A can help
     * identify variable name. */
    WOLFSSL_LOCAL int esp_show_mp(char* name_X, MATH_INT_T* X);

    /* To use a Mutex, it must first be initialized. */
    WOLFSSL_LOCAL int esp_CryptHwMutexInit(wolfSSL_Mutex* mutex);

    /*  Take the mutex to indicate the HW is in use.  Wait up to [block_time].
     *  When the HW in use the mutex will be locked. */
    WOLFSSL_LOCAL int esp_CryptHwMutexLock(wolfSSL_Mutex* mutex,
                                           TickType_t block_time);

    /* Release the mutex to indicate the HW is no longer in use. */
    WOLFSSL_LOCAL int esp_CryptHwMutexUnLock(wolfSSL_Mutex* mutex);

    /* Validation active check. When active, we'll fall back to SW. */
    WOLFSSL_LOCAL int esp_hw_validation_active(void);

/*
*******************************************************************************
** AES features:
*******************************************************************************
*/

#ifndef NO_AES
    #if ESP_IDF_VERSION_MAJOR >= 4
        #include "esp32/rom/aes.h"
    #elif defined(CONFIG_IDF_TARGET_ESP8266)
        /* no hardware includes for ESP8266*/
    #else
        /* TODO: Confirm for older versions: */
        /* #include "rom/aes.h" */
    #endif

    typedef enum tagES32_AES_PROCESS /* TODO what's this ? */
    {
        ESP32_AES_LOCKHW            = 1,
        ESP32_AES_UPDATEKEY_ENCRYPT = 2,
        ESP32_AES_UPDATEKEY_DECRYPT = 3,
        ESP32_AES_UNLOCKHW          = 4
    } ESP32_AESPROCESS;

    struct Aes; /* see aes.h */
#if  defined(WOLFSSL_HW_METRICS)
    WOLFSSL_LOCAL int esp_hw_show_aes_metrics(void);
    WOLFSSL_LOCAL int wc_esp32AesUnupportedLengthCountAdd(void);
#endif
    WOLFSSL_LOCAL int wc_esp32AesSupportedKeyLenValue(int keylen);
    WOLFSSL_LOCAL int wc_esp32AesSupportedKeyLen(struct Aes* aes);

    WOLFSSL_LOCAL int wc_esp32AesCbcEncrypt(struct Aes* aes,
                                            byte*  out,
                                            const  byte* in,
                                            word32 sz);
    WOLFSSL_LOCAL int wc_esp32AesCbcDecrypt(struct Aes* aes,
                                            byte*  out,
                                            const  byte* in,
                                            word32 sz);
    WOLFSSL_LOCAL int wc_esp32AesEncrypt(   struct Aes* aes,
                                            const  byte* in,
                                            byte*  out);
    WOLFSSL_LOCAL int wc_esp32AesDecrypt(   struct Aes* aes,
                                            const  byte* in,
                                            byte*  out);
#endif /* ! NO_AES */

#ifdef WOLFSSL_ESP32_CRYPT_DEBUG

    void wc_esp32TimerStart(void);
    uint64_t wc_esp32elapsedTime(void);

#endif /* WOLFSSL_ESP32_CRYPT_DEBUG */

/*
*******************************************************************************
** Cryptographic hash algorithms (e.g. SHA[x]):
*******************************************************************************
*/

#if !defined(NO_WOLFSSL_ESP32_CRYPT_HASH) &&     \
   (!defined(NO_SHA) || !defined(NO_SHA256) ||          \
     defined(WOLFSSL_SHA384) || defined(WOLFSSL_SHA512) \
   )

    #define SHA_CTX ETS_SHAContext

    #if ESP_IDF_VERSION_MAJOR >= 4
        #if defined(CONFIG_IDF_TARGET_ESP32)
            #include "esp32/rom/sha.h"
            #define WC_ESP_SHA_TYPE enum SHA_TYPE
        #elif defined(CONFIG_IDF_TARGET_ESP32C2) || \
              defined(CONFIG_IDF_TARGET_ESP8684)
            #include "esp32c2/rom/sha.h"
            #define WC_ESP_SHA_TYPE SHA_TYPE
        #elif defined(CONFIG_IDF_TARGET_ESP32C3)
            #include "esp32c3/rom/sha.h"
            #define WC_ESP_SHA_TYPE SHA_TYPE
        #elif defined(CONFIG_IDF_TARGET_ESP32C6)
            #include "esp32c6/rom/sha.h"
            #define WC_ESP_SHA_TYPE SHA_TYPE
        #elif defined(CONFIG_IDF_TARGET_ESP32H2)
            #include "esp32h2/rom/sha.h"
            #define WC_ESP_SHA_TYPE SHA_TYPE
        #elif defined(CONFIG_IDF_TARGET_ESP32S2)
            #include "esp32s2/rom/sha.h"
            #define WC_ESP_SHA_TYPE SHA_TYPE
        #elif defined(CONFIG_IDF_TARGET_ESP32S3)
            #include "esp32s3/rom/sha.h"
            #define WC_ESP_SHA_TYPE SHA_TYPE
        #else
            #include "rom/sha.h"
            #define WC_ESP_SHA_TYPE SHA_TYPE
        #endif
    #elif defined(CONFIG_IDF_TARGET_ESP8266)
        /* there's no HW to include */
    #else
        #include "rom/sha.h"
    #endif

    #undef SHA_CTX

    typedef enum
    {
        ESP32_SHA_INIT             = 0,
        ESP32_SHA_HW               = 1,
        ESP32_SHA_SW               = 2,
        ESP32_SHA_HW_COPY          = 3,
        ESP32_SHA_FREED            = 4,
        ESP32_SHA_FAIL_NEED_UNROLL = -1
    } ESP32_MODE;

    typedef struct
    {
    #if defined(WOLFSSL_STACK_CHECK)
        word32 first_word;
    #endif
        /* Pointer to object that initialized HW, to track copies: */
        uintptr_t initializer;
    #if defined(ESP_MONITOR_HW_TASK_LOCK) && !defined(SINGLE_THREADED)
        TaskHandle_t task_owner;
    #endif

        /* an ESP32_MODE value; typically:
        **   0 init,
        **   1 HW,
        **   2 SW     */
        ESP32_MODE mode;

        /* see esp_rom/include/esp32/rom/sha.h
        **
        **  the Espressif type: SHA1, SHA256, etc.
        */

        WC_ESP_SHA_TYPE sha_type;

        /* we'll keep track of our own locks.
        ** actual enable/disable only occurs for ref_counts[periph] == 0
        **
        **  see ref_counts[periph] in periph_ctrl.c */
        byte lockDepth : 7; /* 7 bits for a small number, pack with below. */

        /* 0 (false) this is NOT first block.
        ** 1 (true ) this is first block.  */
        byte isfirstblock : 1; /* 1 bit only for true / false */
    #if defined(WOLFSSL_STACK_CHECK)
        word32 last_word;
    #endif
    } WC_ESP32SHA __attribute__((aligned(4)));

    WOLFSSL_LOCAL int esp_sha_need_byte_reversal(WC_ESP32SHA* ctx);
    WOLFSSL_LOCAL int esp_sha_init(WC_ESP32SHA* ctx,
                                   enum wc_HashType hash_type);
    WOLFSSL_LOCAL int esp_sha_init_ctx(WC_ESP32SHA* ctx);
    WOLFSSL_LOCAL int esp_sha_try_hw_lock(WC_ESP32SHA* ctx);
    WOLFSSL_LOCAL int esp_sha_hw_unlock(WC_ESP32SHA* ctx);

    /* esp_sha_hw_islocked: returns 0 if not locked, otherwise owner address */
    WOLFSSL_LOCAL uintptr_t esp_sha_hw_islocked(WC_ESP32SHA* ctx);

    /* esp_sha_hw_in_use returns 1 (true) if SHA HW in use, otherwise 0 */
    WOLFSSL_LOCAL int esp_sha_hw_in_use(void);
    WOLFSSL_LOCAL int esp_sha_call_count(void);
    WOLFSSL_LOCAL int esp_sha_lock_count(void);
    WOLFSSL_LOCAL uintptr_t esp_sha_release_unfinished_lock(WC_ESP32SHA* ctx);
    WOLFSSL_LOCAL uintptr_t esp_sha_set_stray(WC_ESP32SHA* ctx);

#ifndef NO_SHA
    struct wc_Sha;
    WOLFSSL_LOCAL int esp_sha_ctx_copy(struct wc_Sha* src, struct wc_Sha* dst);
    WOLFSSL_LOCAL int esp_sha_digest_process(struct wc_Sha* sha,
                                             byte blockprocess);
    WOLFSSL_LOCAL int esp_sha_process(struct wc_Sha* sha, const byte* data);
#endif /* NO_SHA */

#ifdef WOLFSSL_DEBUG_MUTEX
    /* Testing HW release in task that did not lock: */
    extern WC_ESP32SHA* stray_ctx;
#endif

#ifndef NO_SHA256
    struct wc_Sha256;
    WOLFSSL_LOCAL int esp_sha224_ctx_copy(struct wc_Sha256* src,
                                          struct wc_Sha256* dst);
    WOLFSSL_LOCAL int esp_sha256_ctx_copy(struct wc_Sha256* src,
                                          struct wc_Sha256* dst);
    WOLFSSL_LOCAL int esp_sha256_digest_process(struct wc_Sha256* sha,
                                                byte blockprocess);
    WOLFSSL_LOCAL int esp_sha256_process(struct wc_Sha256* sha,
                                         const byte* data);
    WOLFSSL_LOCAL int esp32_Transform_Sha256_demo(struct wc_Sha256* sha256,
                                                  const byte* data);
#endif

    #if defined(WOLFSSL_SHA512) || defined(WOLFSSL_SHA384)
    struct wc_Sha512;
    WOLFSSL_LOCAL int esp_sha384_ctx_copy(struct wc_Sha512* src,
                                          struct wc_Sha512* dst);
    WOLFSSL_LOCAL int esp_sha512_ctx_copy(struct wc_Sha512* src,
                                          struct wc_Sha512* dst);
    WOLFSSL_LOCAL int esp_sha512_process(struct wc_Sha512* sha);
    WOLFSSL_LOCAL int esp_sha512_digest_process(struct wc_Sha512* sha,
                                                byte blockproc);
#endif

#endif /* NO_SHA && etc */


/*
*******************************************************************************
** RSA Big Math
*******************************************************************************
*/

#if !defined(NO_RSA) || defined(HAVE_ECC)

    #if !defined(ESP_RSA_TIMEOUT_CNT)
        #define ESP_RSA_TIMEOUT_CNT     0x249F00
    #endif

#ifndef NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD
    /*
     * The parameter names in the Espressif implementation are arbitrary.
     *
     * The wolfSSL names come from DH: Y=G^x mod M  (see wolfcrypt/tfm.h)
     *
     * G=base, X is the private exponent, Y is the public value w
     **/

    /* Z = (X ^ Y) mod M   : Espressif generic notation    */
    /* Y = (G ^ X) mod P   : wolfSSL DH reference notation */
    WOLFSSL_LOCAL int esp_mp_exptmod(MATH_INT_T* X,    /* G  */
                                     MATH_INT_T* Y,    /* X  */
                                     MATH_INT_T* M,    /* P  */
                                     MATH_INT_T* Z);   /* Y  */

    /* HW_MATH_ENABLED is typically used in wolfcrypt tests */
    #undef  HW_MATH_ENABLED
    #define HW_MATH_ENABLED
#endif /* ! NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD */

#ifndef NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL
    /* Z = X * Y */
    WOLFSSL_LOCAL int esp_mp_mul(MATH_INT_T* X,
                                 MATH_INT_T* Y,
                                 MATH_INT_T* Z);
    /* HW_MATH_ENABLED is typically used in wolfcrypt tests */
    #undef  HW_MATH_ENABLED
    #define HW_MATH_ENABLED
#endif /* ! NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL */

#ifndef NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD
    /* Z = X * Y (mod M) */
    WOLFSSL_LOCAL int esp_mp_mulmod(MATH_INT_T* X,
                                    MATH_INT_T* Y,
                                    MATH_INT_T* M,
                                    MATH_INT_T* Z);
    /* HW_MATH_ENABLED is typically used in wolfcrypt tests */
    #undef  HW_MATH_ENABLED
    #define HW_MATH_ENABLED
#endif /* ! NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD */

#endif /* !NO_RSA || HAVE_ECC*/


/* Optionally enable some metrics to count interesting usage */
/*
*******************************************************************************
** Usage metrics
*******************************************************************************
*/
#ifdef WOLFSSL_HW_METRICS
    #define WOLFSSL_HAS_METRICS

    /* Allow sha256 code to keep track of SW fallback during active HW */
    WOLFSSL_LOCAL int esp_sw_sha256_count_add(void);

    /* show MP HW Metrics*/
    WOLFSSL_LOCAL int esp_hw_show_mp_metrics(void);

    /* show SHA HW Metrics*/
    WOLFSSL_LOCAL int esp_hw_show_sha_metrics(void);

    /* show all HW Metrics*/
    WOLFSSL_LOCAL int esp_hw_show_metrics(void);
#endif


#if defined(WOLFSSL_STACK_CHECK)

WOLFSSL_LOCAL int esp_sha_stack_check(WC_ESP32SHA* sha);

#endif /* WOLFSSL_STACK_CHECK */

/*
 * Errata Mitigation. See
 *   esp32_errata_en.pdf
 *   esp32-c3_errata_en.pdf
 *   esp32-s3_errata_en.pdf
 */
#define ESP_MP_HW_LOCK_MAX_DELAY ( TickType_t ) 0xffUL

#if defined(CONFIG_IDF_TARGET_ESP32) && !defined(ESP_NO_ERRATA_MITIGATION)
    /* some of these may be tuned for specific silicon versions */
    #define ESP_EM__MP_HW_WAIT_CLEAN     {__asm__ __volatile__("memw");}
    #define ESP_EM__MP_HW_WAIT_DONE      {__asm__ __volatile__("memw");}
    #define ESP_EM__POST_SP_MP_HW_LOCK   {__asm__ __volatile__("memw");}
    #define ESP_EM__PRE_MP_HW_WAIT_CLEAN {__asm__ __volatile__("memw");}
    #define ESP_EM__PRE_DPORT_READ       {__asm__ __volatile__("memw");}
    #define ESP_EM__PRE_DPORT_WRITE      {__asm__ __volatile__("memw");}

    /* Non-FIFO read may not be needed in chip revision v3.0. */
    #define ESP_EM__READ_NON_FIFO_REG    {DPORT_SEQUENCE_REG_READ(0x3FF40078);}

    /* When the CPU frequency is 160 MHz, add six nops between two consecutive
    ** FIFO reads. When the CPU frequency is 240 MHz, add seven nops between
    ** two consecutive FIFO reads.  See 3.16 */
    #if defined(CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ_80)
        #define ESP_EM__3_16 { \
            __asm__ __volatile__("memw");              \
            __asm__ __volatile__("nop"); /* 1 */       \
            __asm__ __volatile__("nop"); /* 2 */       \
            __asm__ __volatile__("nop"); /* 3 */       \
            __asm__ __volatile__("nop"); /* 4 */       \
            __asm__ __volatile__("nop"); /* 5 */       \
        };
    #elif defined(CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ_160)
        #define ESP_EM__3_16 { \
            __asm__ __volatile__("memw");              \
            __asm__ __volatile__("nop"); /* 1 */       \
            __asm__ __volatile__("nop"); /* 2 */       \
            __asm__ __volatile__("nop"); /* 3 */       \
            __asm__ __volatile__("nop"); /* 4 */       \
            __asm__ __volatile__("nop"); /* 5 */       \
            __asm__ __volatile__("nop"); /* 6 */       \
            __asm__ __volatile__("nop"); /* 7 */       \
            __asm__ __volatile__("nop"); /* 8 */       \
        };
    #elif defined(CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ_240)
        #define ESP_EM__3_16 { \
            __asm__ __volatile__("memw");              \
            __asm__ __volatile__("nop"); /* 1 */       \
            __asm__ __volatile__("nop"); /* 2 */       \
            __asm__ __volatile__("nop"); /* 3 */       \
            __asm__ __volatile__("nop"); /* 4 */       \
            __asm__ __volatile__("nop"); /* 5 */       \
            __asm__ __volatile__("nop"); /* 6 */       \
            __asm__ __volatile__("nop"); /* 7 */       \
            __asm__ __volatile__("nop"); /* 8 */       \
            __asm__ __volatile__("nop"); /* 9 */       \
        };
    #else
        #define ESP_EM__3_16  {};
    #endif

    #define ESP_EM__POST_PROCESS_START { ESP_EM__3_16 };
    #define ESP_EM__DPORT_FIFO_READ    { ESP_EM__3_16 };
#else
    #define ESP_EM__3_16                 {};
    #define ESP_EM__MP_HW_WAIT_CLEAN     {};
    #define ESP_EM__MP_HW_WAIT_DONE      {};
    #define ESP_EM__POST_SP_MP_HW_LOCK   {};
    #define ESP_EM__PRE_MP_HW_WAIT_CLEAN {};
    #define ESP_EM__POST_PROCESS_START   {};
    #define ESP_EM__DPORT_FIFO_READ      {};
    #define ESP_EM__READ_NON_FIFO_REG    {};
    #define ESP_EM__PRE_DPORT_READ       {};
    #define ESP_EM__PRE_DPORT_WRITE      {};
#endif

/* end c++ wrapper */
#ifdef __cplusplus
}
#endif

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

#endif /* WOLFSSL_ESPIDF (entire contents excluded when not Espressif ESP-IDF) */

#endif  /* __ESP32_CRYPT_H__ */
