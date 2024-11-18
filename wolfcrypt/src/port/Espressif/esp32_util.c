/* esp32_util.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* Reminder: user_settings.h is needed and included from settings.h
 * Be sure to define WOLFSSL_USER_SETTINGS, typically in CMakeLists.txt */
#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_ESPIDF) /* Entire file is only for Espressif EDP-IDF */
#include "sdkconfig.h" /* programmatically generated from sdkconfig */
#include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>

/* Espressif */
#include <esp_log.h>
#include <esp_err.h>
#if ESP_IDF_VERSION_MAJOR > 4
    #include <hal/efuse_hal.h>
    #include <rtc_wdt.h>
#endif
/* wolfSSL */
#include <wolfssl/wolfcrypt/wolfmath.h> /* needed to print MATH_INT_T value */
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/version.h>

/*
** Version / Platform info.
**
** This could evolve into a wolfSSL-wide feature. For now, here only. See:
** https://github.com/wolfSSL/wolfssl/pull/6149
*/

#define WOLFSSL_VERSION_PRINTF(...) ESP_LOGI(TAG, __VA_ARGS__)
/*
 * If used in other platforms:
 *   #include <stdio.h>
 *   #define WOLFSSL_VERSION_PRINTF(...) { printf(__VA_ARGS__); printf("\n"); }
 */

static const char* TAG = "esp32_util";

/* Variable holding number of times ESP32 restarted since first boot.
 * It is placed into RTC memory using RTC_DATA_ATTR and
 * maintains its value when ESP32 wakes from deep sleep.
 */
RTC_DATA_ATTR static int _boot_count = 0;
static int esp_ShowMacroStatus_need_header = 0;
/* Some helpers for macro display */
#define STRING_OF(macro) #macro
#define STR_IFNDEF(macro) STRING_OF(macro)

#if defined(WOLFSSL_ESP32_CRYPT) && \
  (!defined(NO_AES)        || !defined(NO_SHA) || !defined(NO_SHA256) ||\
   defined(WOLFSSL_SHA384) || defined(WOLFSSL_SHA512))

#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

/* big nums can be very long, perhaps uninitialized, so limit displayed words */
#define MAX_WORDS_ESP_SHOW_MP 32

/*
 * initialize our mutex used to lock hardware access
 *
 * returns:
 *   0 upon success,
 *   BAD_MUTEX_E for null mutex
 *   other value from wc_InitMutex()
 *
 */
int esp_CryptHwMutexInit(wolfSSL_Mutex* mutex) {
    if (mutex == NULL) {
        return BAD_MUTEX_E;
    }

    return wc_InitMutex(mutex);
}

/*
 * Call the ESP-IDF mutex lock; xSemaphoreTake
 * this is a general mutex locker, used for different mutex objects for
 * different HW acclerators or other single-use HW features.
 *
 * We should already have known if the resource is in use or not.
 *
 * Return 0 (ESP_OK) on success, otherwise BAD_MUTEX_E
 */
int esp_CryptHwMutexLock(wolfSSL_Mutex* mutex, TickType_t block_time) {
    int ret;
    if (mutex == NULL) {
        WOLFSSL_ERROR_MSG("esp_CryptHwMutexLock called with null mutex");
        return BAD_MUTEX_E;
    }

#ifdef SINGLE_THREADED
    /* does nothing in single thread mode, always return 0 */
    ret = wc_LockMutex(mutex);
#else
    ret = xSemaphoreTake(*mutex, block_time);
    ESP_LOGV(TAG, "xSemaphoreTake 0x%x = %d", (intptr_t)*mutex, ret);
    if (ret == pdTRUE) {
        ret = ESP_OK;
    }
    else {
        if (ret == pdFALSE) {
            ESP_LOGW(TAG, "xSemaphoreTake failed for 0x%x. Still busy?",
                           (intptr_t)*mutex);
            ret = ESP_ERR_NOT_FINISHED;
        }
        else {
            ESP_LOGE(TAG, "xSemaphoreTake 0x%x unexpected = %d",
                           (intptr_t)*mutex, ret);
            ret = BAD_MUTEX_E;
        }
    }
#endif
    return ret;
}

/*
 * call the ESP-IDF mutex UNlock; xSemaphoreGive
 *
 */
esp_err_t esp_CryptHwMutexUnLock(wolfSSL_Mutex* mutex) {
    int ret = pdTRUE;
    if (mutex == NULL) {
        WOLFSSL_ERROR_MSG("esp_CryptHwMutexLock called with null mutex");
        return BAD_MUTEX_E;
    }

#ifdef SINGLE_THREADED
    ret = wc_UnLockMutex(mutex);
#else
    ESP_LOGV(TAG, ">> xSemaphoreGive 0x%x", (intptr_t)*mutex);
    TaskHandle_t mutexHolder = xSemaphoreGetMutexHolder(*mutex);

    if (mutexHolder == NULL) {
        ESP_LOGW(TAG, "esp_CryptHwMutexUnLock with no lock owner 0x%x",
                        (intptr_t)*mutex);
        ret = ESP_OK;
    }
    else {
        ret = xSemaphoreGive(*mutex);
        if (ret == pdTRUE) {
            ESP_LOGV(TAG, "Success: give mutex 0x%x", (intptr_t)*mutex);
            ret = ESP_OK;
        }
        else {
            ESP_LOGV(TAG, "Failed: give mutex 0x%x", (intptr_t)*mutex);
            ret = ESP_FAIL;
        }
    }
#endif
    return ret;
}
#endif /* WOLFSSL_ESP32_CRYPT, etc. */


/* esp_ShowExtendedSystemInfo and supporting info.
**
** available regardless if HW acceleration is turned on or not.
*/

/*
*******************************************************************************
** Specific Platforms
*******************************************************************************
*/

/*
** Specific platforms: Espressif
*/
#if defined(WOLFSSL_ESPIDF)
static int ShowExtendedSystemInfo_platform_espressif(void)
{
#ifdef WOLFSSL_ESP_NO_WATCHDOG
    ESP_LOGI(TAG, "Found WOLFSSL_ESP_NO_WATCHDOG");
#else
    ESP_LOGW(TAG, "Watchdog active; "
                  "missing WOLFSSL_ESP_NO_WATCHDOG definition.");
#endif

#if defined(CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ)
    WOLFSSL_VERSION_PRINTF("CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ: %u MHz",
                           CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ);
#endif

#if CONFIG_IDF_TARGET_ESP32

    WOLFSSL_VERSION_PRINTF("Xthal_have_ccount: %u",
                           Xthal_have_ccount);
#endif

    /* this is the legacy stack size */
#if defined(CONFIG_MAIN_TASK_STACK_SIZE)
    WOLFSSL_VERSION_PRINTF("CONFIG_MAIN_TASK_STACK_SIZE: %d",
                           CONFIG_MAIN_TASK_STACK_SIZE);
#endif

    /* this is the modern stack size */
#if defined(CONFIG_ESP_MAIN_TASK_STACK_SIZE)
    WOLFSSL_VERSION_PRINTF("CONFIG_ESP_MAIN_TASK_STACK_SIZE: %d",
                           CONFIG_ESP_MAIN_TASK_STACK_SIZE);
#endif

#if defined(CONFIG_TIMER_TASK_STACK_SIZE)
    WOLFSSL_VERSION_PRINTF("CONFIG_TIMER_TASK_STACK_SIZE: %d",
                           CONFIG_TIMER_TASK_STACK_SIZE);
#endif

#if defined(CONFIG_TIMER_TASK_STACK_DEPTH)
    WOLFSSL_VERSION_PRINTF("CONFIG_TIMER_TASK_STACK_DEPTH: %d",
                           CONFIG_TIMER_TASK_STACK_DEPTH);
#endif

#if defined(SINGLE_THREADED)
    /* see also HAVE_STACK_SIZE_VERBOSE */
    char thisHWM = 0;
    WOLFSSL_VERSION_PRINTF("Stack HWM: %x", (size_t) &thisHWM);
#else
    #ifdef INCLUDE_uxTaskGetStackHighWaterMark
    {
        WOLFSSL_VERSION_PRINTF("Stack HWM: %d",
                               uxTaskGetStackHighWaterMark(NULL));
    }
    #endif /* INCLUDE_uxTaskGetStackHighWaterMark */

#endif

/* Platform-specific attributes of interest*/
#if CONFIG_IDF_TARGET_ESP32
    #if defined(CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ)
        WOLFSSL_VERSION_PRINTF("CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ: %u MHz",
                               CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ);
    #endif
    WOLFSSL_VERSION_PRINTF("Xthal_have_ccount: %u",
                           Xthal_have_ccount);

#elif CONFIG_IDF_TARGET_ESP32C2
    /* TODO find Xthal for C2 */
#elif CONFIG_IDF_TARGET_ESP32C3
    /* not supported at this time */
#elif CONFIG_IDF_TARGET_ESP32C6
    /* TODO find Xthal for C6 */
#elif CONFIG_IDF_TARGET_ESP32H2
    /* TODO find Xthal for H2 */
#elif CONFIG_IDF_TARGET_ESP32S2
    ESP_LOGI(TAG, "CONFIG_ESP32S2_DEFAULT_CPU_FREQ_MHZ = %u MHz",
                   CONFIG_ESP32S2_DEFAULT_CPU_FREQ_MHZ
             );
    ESP_LOGI(TAG, "Xthal_have_ccount = %u", Xthal_have_ccount);
#elif CONFIG_IDF_TARGET_ESP32S3
    ESP_LOGI(TAG, "CONFIG_ESP32S3_DEFAULT_CPU_FREQ_MHZ = %u MHz",
                   CONFIG_ESP32S3_DEFAULT_CPU_FREQ_MHZ
             );
    ESP_LOGI(TAG, "Xthal_have_ccount = %u", Xthal_have_ccount);
#elif defined(CONFIG_IDF_TARGET_ESP8684)
    /* TODO find Xthal for ESP8684 */
#else
    /* not supported at this time */
#endif

/* check to see if we are using hardware encryption */
#if defined(CONFIG_IDF_TARGET_ESP8266)
    WOLFSSL_VERSION_PRINTF("No HW acceleration on ESP8266.");
#elif defined(NO_ESP32_CRYPT)
    WOLFSSL_VERSION_PRINTF("NO_ESP32_CRYPT defined! "
                           "HW acceleration DISABLED.");
#else
    /* first show what platform hardware acceleration is enabled
    ** (some new platforms may not be supported yet) */
    #if defined(CONFIG_IDF_TARGET_ESP32)
        WOLFSSL_VERSION_PRINTF("ESP32_CRYPT is enabled for ESP32.");
    #elif defined(CONFIG_IDF_TARGET_ESP32S2)
        WOLFSSL_VERSION_PRINTF("ESP32_CRYPT is enabled for ESP32-S2.");
    #elif defined(CONFIG_IDF_TARGET_ESP32S3)
        WOLFSSL_VERSION_PRINTF("ESP32_CRYPT is enabled for ESP32-S3.");
    #elif defined(CONFIG_IDF_TARGET_ESP32C2) || \
          defined(CONFIG_IDF_TARGET_ESP8684)
        WOLFSSL_VERSION_PRINTF("ESP32_CRYPT is enabled for ESP32-C2.");
    #elif defined(CONFIG_IDF_TARGET_ESP32C3)
        WOLFSSL_VERSION_PRINTF("ESP32_CRYPT is enabled for ESP32-C3.");
    #elif defined(CONFIG_IDF_TARGET_ESP32C6)
        WOLFSSL_VERSION_PRINTF("ESP32_CRYPT is enabled for ESP32-C6.");
    #elif defined(CONFIG_IDF_TARGET_ESP32H2)
        WOLFSSL_VERSION_PRINTF("ESP32_CRYPT is enabled for ESP32-H2.");
    #else
        /* This should have been detected & disabled in user_settins.h */
        #error "ESP32_CRYPT not yet supported on this IDF TARGET"
    #endif

    /* Even though enabled, some specifics may be disabled */
    #if defined(NO_WOLFSSL_ESP32_CRYPT_HASH)
        WOLFSSL_VERSION_PRINTF("NO_WOLFSSL_ESP32_CRYPT_HASH is defined!"
                               "(disabled HW SHA).");
    #endif

    #if defined(NO_WOLFSSL_ESP32_CRYPT_AES)
        WOLFSSL_VERSION_PRINTF("NO_WOLFSSL_ESP32_CRYPT_AES is defined! "
                               "(disabled HW AES).");
    #endif

    #if defined(NO_WOLFSSL_ESP32_CRYPT_RSA_PRI)
        WOLFSSL_VERSION_PRINTF("NO_WOLFSSL_ESP32_CRYPT_RSA_PRI defined! "
                               "(disabled HW RSA)");
    #endif
#endif

#if defined(WOLFSSL_SM2) || defined(WOLFSSL_SM3) || defined(WOLFSSL_SM4)
    WOLFSSL_VERSION_PRINTF("SM Ciphers enabled");
    #if defined(WOLFSSL_SM2)
        WOLFSSL_VERSION_PRINTF("  WOLFSSL_SM2 enabled");
    #else
        WOLFSSL_VERSION_PRINTF(" WOLFSSL_SM2 NOT enabled");
    #endif

    #if defined(WOLFSSL_SM3)
        WOLFSSL_VERSION_PRINTF("  WOLFSSL_SM3 enabled");
    #else
        WOLFSSL_VERSION_PRINTF(" WOLFSSL_SM3 NOT enabled");
    #endif

    #if defined(WOLFSSL_SM4)
        WOLFSSL_VERSION_PRINTF("  WOLFSSL_SM4 enabled");
    #else
        WOLFSSL_VERSION_PRINTF(" WOLFSSL_SM4 NOT enabled");
    #endif
#endif

    return ESP_OK;
}
#endif

/*
*******************************************************************************
** All Platforms
*******************************************************************************
*/

/*
** All platforms: git details
*/
static int ShowExtendedSystemInfo_git(void)
{
    /* Display some interesting git values that may change,
    ** but not desired for introspection which requires object code to be
    ** maximally bitwise-invariant.
    */

#if defined(LIBWOLFSSL_VERSION_GIT_TAG)
    /* git config describe --tags --abbrev=0 */
    WOLFSSL_VERSION_PRINTF("LIBWOLFSSL_VERSION_GIT_TAG = %s",
                           LIBWOLFSSL_VERSION_GIT_TAG);
#endif

#if defined(LIBWOLFSSL_VERSION_GIT_ORIGIN)
    /* git config --get remote.origin.url */
    WOLFSSL_VERSION_PRINTF("LIBWOLFSSL_VERSION_GIT_ORIGIN = %s",
                           LIBWOLFSSL_VERSION_GIT_ORIGIN);
#endif

#if defined(LIBWOLFSSL_VERSION_GIT_BRANCH)
    /* git rev-parse --abbrev-ref HEAD */
    WOLFSSL_VERSION_PRINTF("LIBWOLFSSL_VERSION_GIT_BRANCH = %s",
                           LIBWOLFSSL_VERSION_GIT_BRANCH);
#endif

#if defined(LIBWOLFSSL_VERSION_GIT_HASH)
    /* git rev-parse HEAD */
    WOLFSSL_VERSION_PRINTF("LIBWOLFSSL_VERSION_GIT_HASH = %s",
                           LIBWOLFSSL_VERSION_GIT_HASH);
#endif

#if defined(LIBWOLFSSL_VERSION_GIT_SHORT_HASH )
    /* git rev-parse --short HEAD */
    WOLFSSL_VERSION_PRINTF("LIBWOLFSSL_VERSION_GIT_SHORT_HASH = %s",
                           LIBWOLFSSL_VERSION_GIT_SHORT_HASH);
#endif

#if defined(LIBWOLFSSL_VERSION_GIT_HASH_DATE)
    /* git show --no-patch --no-notes --pretty=\'\%cd\' */
    WOLFSSL_VERSION_PRINTF("LIBWOLFSSL_VERSION_GIT_HASH_DATE = %s",
                           LIBWOLFSSL_VERSION_GIT_HASH_DATE);
#endif

    return ESP_OK;
}

/*
** All platforms: thread details
*/
static int ShowExtendedSystemInfo_thread(void)
{
    /* all platforms: stack high water mark check */
#if defined(SINGLE_THREADED)
    WOLFSSL_VERSION_PRINTF("SINGLE_THREADED");
#else
    WOLFSSL_VERSION_PRINTF("NOT SINGLE_THREADED");
#endif
    return ESP_OK;
}

/*
** All Platforms: platform details
*/
static int ShowExtendedSystemInfo_platform(void)
{
#if defined(WOLFSSL_ESPIDF)
#if defined(CONFIG_IDF_TARGET)
    WOLFSSL_VERSION_PRINTF("CONFIG_IDF_TARGET = %s",
                           CONFIG_IDF_TARGET);
    ShowExtendedSystemInfo_platform_espressif();
#endif
#endif
    return ESP_OK;
}

int esp_increment_boot_count(void)
{
    return ++_boot_count;
}

int esp_current_boot_count(void)
{
    return _boot_count;
}

/* See macro helpers above; not_defined is macro name when *not* defined */
static int show_macro(char* s, char* not_defined)
{
    const char hd1[] = "Macro Name                 Defined   Not Defined";
          char hd2[] = "------------------------- --------- -------------";
          char msg[] = ".........................                        ";
             /*        012345678901234567890123456789012345678901234567890 */
             /*                  1         2         3         4         5 */
    size_t i = 0;
    #define MAX_STATUS_NAME_LENGTH 25
    #define ESP_SMS_ENA_POS 30
    #define ESP_SMS_DIS_POS 42

    /* save our string (s) into the space-padded message (msg) */
    while (s[i] != '\0' && msg[i] != '\0' && (i < MAX_STATUS_NAME_LENGTH)) {
        msg[i] = s[i];
        i++;
    }

    /* Depending on if defined, put an "x" in the appropriate column */
    if (not_defined == NULL || not_defined[0] == '\0') {
        msg[ESP_SMS_ENA_POS] = 'X';
        msg[ESP_SMS_ENA_POS+1] = 0; /* end of line to eliminate space pad */
    }
    else {
        msg[ESP_SMS_DIS_POS] = 'X';
        msg[ESP_SMS_DIS_POS+1] = 0; /* end of line to eliminate space pad */
    }

    /* do we need a header? */
    if (esp_ShowMacroStatus_need_header) {
        ESP_LOGI(TAG, "%s", hd1);
        ESP_LOGI(TAG, "%s", hd2);
        esp_ShowMacroStatus_need_header = 0;
    }

    /* show the macro name with the "x" in the defined/not defined column */
    ESP_LOGI(TAG, "%s", msg);
    return ESP_OK;
}

/* Show some interesting settings */
esp_err_t ShowExtendedSystemInfo_config(void)
{
    esp_ShowMacroStatus_need_header = 1;

    show_macro("NO_ESP32_CRYPT",            STR_IFNDEF(NO_ESP32_CRYPT));
    show_macro("NO_ESPIDF_DEFAULT",         STR_IFNDEF(NO_ESPIDF_DEFAULT));

    show_macro("HW_MATH_ENABLED",           STR_IFNDEF(HW_MATH_ENABLED));

    /* Features */
    show_macro("WOLFSSL_SHA224",            STR_IFNDEF(WOLFSSL_SHA224));
    show_macro("WOLFSSL_SHA384",            STR_IFNDEF(WOLFSSL_SHA384));
    show_macro("WOLFSSL_SHA512",            STR_IFNDEF(WOLFSSL_SHA512));
    show_macro("WOLFSSL_SHA3",              STR_IFNDEF(WOLFSSL_SHA3));
    show_macro("HAVE_ED25519",              STR_IFNDEF(HAVE_ED25519));
    show_macro("HAVE_AES_ECB",              STR_IFNDEF(HAVE_AES_ECB));
    show_macro("HAVE_AES_DIRECT",           STR_IFNDEF(HAVE_AES_DIRECT));

    /* Math Library Selection */
    show_macro("USE_FAST_MATH",             STR_IFNDEF(USE_FAST_MATH));
    show_macro("WOLFSSL_SP_MATH_ALL",       STR_IFNDEF(WOLFSSL_SP_MATH_ALL));
#ifdef WOLFSSL_SP_RISCV32
    show_macro("WOLFSSL_SP_RISCV32",        STR_IFNDEF(WOLFSSL_SP_RISCV32));
#endif
    show_macro("SP_MATH",                   STR_IFNDEF(SP_MATH));

    /* Diagnostics */
    show_macro("WOLFSSL_HW_METRICS",        STR_IFNDEF(WOLFSSL_HW_METRICS));

    /* Optimizations */
    show_macro("RSA_LOW_MEM",               STR_IFNDEF(RSA_LOW_MEM));
    show_macro("SMALL_SESSION_CACHE",       STR_IFNDEF(SMALL_SESSION_CACHE));

    /* Security Hardening */
    show_macro("WC_NO_HARDEN",              STR_IFNDEF(WC_NO_HARDEN));
    show_macro("TFM_TIMING_RESISTANT",      STR_IFNDEF(TFM_TIMING_RESISTANT));
    show_macro("ECC_TIMING_RESISTANT",      STR_IFNDEF(ECC_TIMING_RESISTANT));

    /* WC_NO_CACHE_RESISTANT is only important if another process can be
     * run on the device. With embedded it is less likely to be exploitable.
     * Timing attacks are usually by probe. So typically turn this on: */
    show_macro("WC_NO_CACHE_RESISTANT",     STR_IFNDEF(WC_NO_CACHE_RESISTANT));

    /* Side channel bit slicing */
    show_macro("WC_AES_BITSLICED",          STR_IFNDEF(WC_AES_BITSLICED));

    /* Unrolling will normally improve performance,
     * so make sure WOLFSSL_AES_NO_UNROLL isn't defined unless you want it. */
    show_macro("WOLFSSL_AES_NO_UNROLL",     STR_IFNDEF(WOLFSSL_AES_NO_UNROLL));
    show_macro("TFM_TIMING_RESISTANT",      STR_IFNDEF(TFM_TIMING_RESISTANT));
    show_macro("ECC_TIMING_RESISTANT",      STR_IFNDEF(ECC_TIMING_RESISTANT));

    /* WC_RSA_BLINDING takes up additional space: */
    show_macro("WC_RSA_BLINDING",           STR_IFNDEF(WC_RSA_BLINDING));
    show_macro("NO_WRITEV",                 STR_IFNDEF(NO_WRITEV));

    /* Environment */
    show_macro("FREERTOS",                  STR_IFNDEF(FREERTOS));
    show_macro("NO_WOLFSSL_DIR",            STR_IFNDEF(NO_WOLFSSL_DIR));
    show_macro("WOLFSSL_NO_CURRDIR",        STR_IFNDEF(WOLFSSL_NO_CURRDIR));
    show_macro("WOLFSSL_LWIP",              STR_IFNDEF(WOLFSSL_LWIP));

    ESP_LOGI(TAG, WOLFSSL_ESPIDF_BLANKLINE_MESSAGE);
#if defined(CONFIG_COMPILER_OPTIMIZATION_DEFAULT)
    ESP_LOGI(TAG, "Compiler Optimization: Default");
#elif defined(CONFIG_COMPILER_OPTIMIZATION_SIZE)
    ESP_LOGI(TAG, "Compiler Optimization: Size");
#elif defined(CONFIG_COMPILER_OPTIMIZATION_PERF)
    ESP_LOGI(TAG, "Compiler Optimization: Performance");
#elif defined(CONFIG_COMPILER_OPTIMIZATION_NONE)
    ESP_LOGI(TAG, "Compiler Optimization: None");
#else
    ESP_LOGI(TAG, "Compiler Optimization: Unknown");
#endif
    ESP_LOGI(TAG, WOLFSSL_ESPIDF_BLANKLINE_MESSAGE);

    return ESP_OK;
}
/*
*******************************************************************************
** The internal, portable, but currently private ShowExtendedSystemInfo()
*******************************************************************************
*/
int ShowExtendedSystemInfo(void)
{
#if ESP_IDF_VERSION_MAJOR > 4
    unsigned chip_rev = -1;
#endif

#ifdef HAVE_ESP_CLK
    /* esp_clk.h is private */
    int cpu_freq = 0;
#endif

    WOLFSSL_VERSION_PRINTF("Extended Version and Platform Information.");

#if defined(HAVE_WC_INTROSPECTION) && \
   !defined(ALLOW_BINARY_MISMATCH_INTROSPECTION)
#pragma message("WARNING: both HAVE_VERSION_EXTENDED_INFO and " \
                "HAVE_WC_INTROSPECTION are enabled. Some extended " \
                "information details will not be available.")

    WOLFSSL_VERSION_PRINTF("HAVE_WC_INTROSPECTION enabled. "
                           "Some extended system details not available.");
#endif /* else not HAVE_WC_INTROSPECTION */

#if ESP_IDF_VERSION_MAJOR > 4
    chip_rev = efuse_hal_chip_revision();
    ESP_LOGI(TAG, "Chip revision: v%d.%d", chip_rev / 100, chip_rev % 100);
#endif

#ifdef HAVE_ESP_CLK
    cpu_freq = esp_clk_cpu_freq();
    ESP_EARLY_LOGI(TAG, "cpu freq: %d Hz", cpu_freq);
#endif

#if defined(SHOW_SSID_AND_PASSWORD)
    ESP_LOGW(TAG, "WARNING: SSID and plain text WiFi "
                  "password displayed in startup logs. ");
    ESP_LOGW(TAG, "Remove SHOW_SSID_AND_PASSWORD from user_settings.h "
                  "to disable.");
#else
    ESP_LOGI(TAG, "SSID and plain text WiFi "
                  "password not displayed in startup logs.");
    ESP_LOGI(TAG, "  Define SHOW_SSID_AND_PASSWORD to enable display.");
#endif

#if defined(WOLFSSL_MULTI_INSTALL_WARNING)
    /* CMake may have detected undesired multiple installs, so give warning. */
    WOLFSSL_VERSION_PRINTF(WOLFSSL_ESPIDF_BLANKLINE_MESSAGE);
    WOLFSSL_VERSION_PRINTF("WARNING: Multiple wolfSSL installs found.");
    WOLFSSL_VERSION_PRINTF("Check ESP-IDF components and "
                           "local project [components] directory.");
    WOLFSSL_VERSION_PRINTF(WOLFSSL_ESPIDF_BLANKLINE_MESSAGE);
#else
    #ifdef WOLFSSL_USER_SETTINGS_DIR
    {
        ESP_LOGI(TAG, "Using wolfSSL user_settings.h in %s",
                       WOLFSSL_USER_SETTINGS_DIR);
    }
    #else
    {
        ESP_LOGW(TAG, "Warning: old cmake, user_settings.h location unknown.");
    }
    #endif
#endif

#if defined(LIBWOLFSSL_VERSION_STRING)
    WOLFSSL_VERSION_PRINTF("LIBWOLFSSL_VERSION_STRING = %s",
                            LIBWOLFSSL_VERSION_STRING);
#endif

#if defined(LIBWOLFSSL_VERSION_HEX)
    WOLFSSL_VERSION_PRINTF("LIBWOLFSSL_VERSION_HEX = %x",
                            LIBWOLFSSL_VERSION_HEX);
#endif

    /* some interesting settings are target specific (ESP32, -C3, -S3, etc */
#if defined(CONFIG_IDF_TARGET_ESP32)
    /* ESP_RSA_MULM_BITS should be set to at least 16 for ESP32 */
    #if defined(ESP_RSA_MULM_BITS)
        #if (ESP_RSA_MULM_BITS < 16)
            ESP_LOGW(TAG, "Warning: ESP_RSA_MULM_BITS < 16 for ESP32");
        #endif
    #else
        ESP_LOGW(TAG, "Warning: ESP_RSA_MULM_BITS not defined for ESP32");
    #endif

#elif defined(CONFIG_IDF_TARGET_ESP32C2) || defined(CONFIG_IDF_TARGET_ESP8684)
    ESP_LOGI(TAG, "CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ = %u MHz",
                   CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ
            );
#elif defined(CONFIG_IDF_TARGET_ESP32C3) && \
      defined(CONFIG_ESP32C3_DEFAULT_CPU_FREQ_MHZ)
    ESP_LOGI(TAG, "CONFIG_ESP32C3_DEFAULT_CPU_FREQ_MHZ = %u MHz",
                   CONFIG_ESP32C3_DEFAULT_CPU_FREQ_MHZ
            );

#elif defined(CONFIG_IDF_TARGET_ESP32C6)
    ESP_LOGI(TAG, "CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ = %u MHz",
                   CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ
            );
/*  ESP_LOGI(TAG, "Xthal_have_ccount = %u", Xthal_have_ccount); */

#elif defined(CONFIG_IDF_TARGET_ESP32S2)
    #if defined(CONFIG_ESP32S2_DEFAULT_CPU_FREQ_MHZ)
        ESP_LOGI(TAG, "CONFIG_ESP32S2_DEFAULT_CPU_FREQ_MHZ = %u MHz",
                       CONFIG_ESP32S2_DEFAULT_CPU_FREQ_MHZ
                    );
    #endif

    ESP_LOGI(TAG, "Xthal_have_ccount = %u", Xthal_have_ccount);

#elif defined(CONFIG_IDF_TARGET_ESP32S3)
    #if defined(CONFIG_ESP32S3_DEFAULT_CPU_FREQ_MHZ)
        ESP_LOGI(TAG, "CONFIG_ESP32S3_DEFAULT_CPU_FREQ_MHZ = %u MHz",
                       CONFIG_ESP32S3_DEFAULT_CPU_FREQ_MHZ
                    );
    #endif

    ESP_LOGI(TAG, "Xthal_have_ccount = %u", Xthal_have_ccount);
#else

#endif

    /* all platforms: stack high water mark check */
#ifdef INCLUDE_uxTaskGetStackHighWaterMark
    ESP_LOGI(TAG, "Stack HWM: %d", uxTaskGetStackHighWaterMark(NULL));
#endif
    ESP_LOGI(TAG, WOLFSSL_ESPIDF_BLANKLINE_MESSAGE);

    ShowExtendedSystemInfo_config();
    ShowExtendedSystemInfo_git();
    ShowExtendedSystemInfo_platform();
    ShowExtendedSystemInfo_thread();

    /* show number of RTC sleep boots */
    esp_increment_boot_count();
    ESP_LOGI(TAG, "Boot count: %d", esp_current_boot_count());

    return ESP_OK;
}

esp_err_t esp_ShowExtendedSystemInfo(void)
{
    /* Someday the ShowExtendedSystemInfo may be global.
     * See https://github.com/wolfSSL/wolfssl/pull/6149 */
    return ShowExtendedSystemInfo();
}

/*
 *  Disable the watchdog timer (use with caution)
 */

esp_err_t esp_DisableWatchdog(void)
{
    esp_err_t ret = ESP_OK;
#if defined(CONFIG_IDF_TARGET_ESP8266)
    /* magic bit twiddle to disable WDT on ESP8266 */
    *((volatile uint32_t*) 0x60000900) &= ~(1);
#elif CONFIG_IDF_TARGET_ESP32S3
    ESP_LOGW(TAG, "esp_DisableWatchdog TODO S3");
#else
    #if ESP_IDF_VERSION_MAJOR >= 5
    {
        #if defined(CONFIG_IDF_TARGET_ESP32)
            rtc_wdt_protect_off();
            rtc_wdt_disable();
        #elif defined(CONFIG_IDF_TARGET_ESP32C2) || \
              defined(CONFIG_IDF_TARGET_ESP32C3) || \
              defined(CONFIG_IDF_TARGET_ESP32C6) || \
              defined(CONFIG_IDF_TARGET_ESP32H2)
            ESP_LOGW(TAG, "No known rtc_wdt_protect_off for this platform.");
        #else
            rtc_wdt_protect_off();
            rtc_wdt_disable();
        #endif
    }
    #else
        ESP_LOGW(TAG, "esp_DisableWatchdog not implemented on ESP_OIDF v%d",
                      ESP_IDF_VERSION_MAJOR);
    #endif
#endif

#ifdef DEBUG_WOLFSSL
    ESP_LOGI(TAG, "Watchdog disabled.");
#endif

    return ret;
}

/*
 *  Enable the watchdog timer.
 */

esp_err_t esp_EnabledWatchdog(void)
{
    esp_err_t ret = ESP_OK;
#if defined(CONFIG_IDF_TARGET_ESP8266)
     /* magic bit twiddle to enable WDT on ESP8266 */
     *((volatile uint32_t*) 0x60000900) |= 1;
#elif CONFIG_IDF_TARGET_ESP32S3
    ESP_LOGW(TAG, "esp_EnableWatchdog TODO S3");
#else
    #if ESP_IDF_VERSION_MAJOR >= 5
    {
        #if defined(CONFIG_IDF_TARGET_ESP32)
            rtc_wdt_protect_on();
            rtc_wdt_enable();
        #elif defined(CONFIG_IDF_TARGET_ESP32C2) || \
              defined(CONFIG_IDF_TARGET_ESP32C3) || \
              defined(CONFIG_IDF_TARGET_ESP32C6) || \
              defined(CONFIG_IDF_TARGET_ESP32H2)
            ESP_LOGW(TAG, "No known rtc_wdt_protect_off for this platform.");
        #else
            rtc_wdt_protect_on();
            rtc_wdt_enable();
        #endif
    }
    #else
        ESP_LOGW(TAG, "esp_DisableWatchdog not implemented on ESP_OIDF v%d",
                      ESP_IDF_VERSION_MAJOR);
    #endif
#endif
    return ret;
}



/* Print a MATH_INT_T attribute list.
 *
 * Note with the right string parameters, the result can be pasted as
 * initialization code.
 */
esp_err_t esp_show_mp_attributes(char* c, MATH_INT_T* X)
{
    static const char* MP_TAG = "MATH_INT_T";
    esp_err_t ret = ESP_OK;

    if (X == NULL) {
        ret = ESP_FAIL;
        ESP_LOGV(MP_TAG, "esp_show_mp_attributes called with X == NULL");
    }
    else {
        ESP_LOGI(MP_TAG, WOLFSSL_ESPIDF_BLANKLINE_MESSAGE);
        ESP_LOGI(MP_TAG, "%s.used = %d;", c, X->used);
#if defined(WOLFSSL_SP_INT_NEGATIVE) || defined(USE_FAST_MATH)
        ESP_LOGI(MP_TAG, "%s.sign = %d;", c, X->sign);
#endif
    }
    return ret;
}

/* Print a MATH_INT_T value.
 *
 * Note with the right string parameters, the result can be pasted as
 * initialization code.
 */
esp_err_t esp_show_mp(char* c, MATH_INT_T* X)
{
    static const char* MP_TAG = "MATH_INT_T";
    esp_err_t ret = ESP_OK;
    int words_to_show = 0;

    if (X == NULL) {
        ret = ESP_FAIL;
        ESP_LOGV(MP_TAG, "esp_show_mp called with X == NULL");
    }
    else {
        words_to_show = X->used;
        /* if too small, we'll show just 1 word */
        if (words_to_show < 1) {
            ESP_LOGI(MP_TAG, "Bad word count. Adjusting from %d to %d",
                             words_to_show,
                             1);
            words_to_show = 1;
        }
    #ifdef MAX_WORDS_ESP_SHOW_MP
        /* if too big, we'll show MAX_WORDS_ESP_SHOW_MP words */
        if (words_to_show > MAX_WORDS_ESP_SHOW_MP) {
            ESP_LOGI(MP_TAG, "Limiting word count from %d to %d",
                             words_to_show,
                             MAX_WORDS_ESP_SHOW_MP);
            words_to_show = MAX_WORDS_ESP_SHOW_MP;
        }
    #endif
        ESP_LOGI(MP_TAG, "%s:",c);
        esp_show_mp_attributes(c, X);
        for (size_t i = 0; i < words_to_show; i++) {
            ESP_LOGI(MP_TAG, "%s.dp[%2d] = 0x%08x;  /* %2d */ ",
                                   c, /* the supplied variable name      */
                                   i, /* the index, i for dp[%d]         */
                                   (unsigned int)X->dp[i], /* the value  */
                                   i  /* the index, again, for comment   */
                     );
        }
        ESP_LOGI(MP_TAG, WOLFSSL_ESPIDF_BLANKLINE_MESSAGE);
    }
    return ret;
}

/* Perform a full mp_cmp and binary compare.
 * (typically only used during debugging) */
esp_err_t esp_mp_cmp(char* name_A, MATH_INT_T* A, char* name_B, MATH_INT_T* B)
{
    esp_err_t ret = ESP_OK;
    int e = memcmp(A, B, sizeof(mp_int));
    if (mp_cmp(A, B) == MP_EQ) {
        if (e == 0) {
            /* we always want to be here: both esp_show_mp and binary equal! */
            ESP_LOGV(TAG, "fp_cmp and memcmp match for %s and %s!",
                           name_A, name_B);
        }
        else {
            ret = MP_VAL;
            ESP_LOGE(TAG, "fp_cmp match, memcmp mismatch for %s and %s!",
                           name_A, name_B);
            if (A->dp[0] == 1) {
                ESP_LOGE(TAG, "Both memcmp and fp_cmp fail for %s and %s!",
                               name_A, name_B);
            }
        }
    }
    else {
        ret = MP_VAL;
        if (e == 0) {
            /* if mp_cmp says different,
             * but memcmp says equal, that's a problem */
            ESP_LOGE(TAG, "memcmp error for %s and %s!",
                          name_A, name_B);
        }
        else {
            /* in the normal case where mp_cmp and memcmp say the
             * values are different, we'll optionally show details. */
            ESP_LOGI(TAG, "e = %d", e);
            ESP_LOGE(TAG, "fp_cmp mismatch! memcmp "
                          "offset 0x%02x for %s vs %s!",
                           e, name_A, name_B);
            if (A->dp[0] == 1) {
                ESP_LOGE(TAG, "Both memcmp and fp_cmp fail for %s and %s!",
                               name_A, name_B);
            }
        }
        ESP_LOGV(TAG, "Mismatch for %s and %s!",
                       name_A, name_B);
    }

    if (ret == MP_OKAY) {
        ret = ESP_OK;
        ESP_LOGV(TAG, "esp_mp_cmp equal for %s and %s!",
                       name_A, name_B);
    }
    else {
      /*  esp_show_mp(name_A, A); */
      /*  esp_show_mp(name_B, B); */
    }
    return ret;
}

esp_err_t esp_hw_show_metrics(void)
{
#if  defined(WOLFSSL_HW_METRICS)
    #if defined(WOLFSSL_ESP32_CRYPT)
        esp_hw_show_sha_metrics();
    #else
        ESP_LOGI(TAG, "WOLFSSL_ESP32_CRYPT not defined, "
                      "HW SHA hash not enabled");
    #endif

    #if defined(WOLFSSL_ESP32_CRYPT_RSA_PRI)
        esp_hw_show_mp_metrics();
    #else
        ESP_LOGI(TAG, "WOLFSSL_ESP32_CRYPT_RSA_PRI not defined, "
                      "HW math not enabled");
    #endif

    #if defined(NO_WOLFSSL_ESP32_CRYPT_AES)
        ESP_LOGI(TAG, "NO_WOLFSSL_ESP32_CRYPT_AES is defined, "
                      "HW AES not enabled");
    #else
        esp_hw_show_aes_metrics();
    #endif
#else
    ESP_LOGV(TAG, "WOLFSSL_HW_METRICS is not enabled");
#endif
    return ESP_OK;
}

int show_binary(byte* theVar, size_t dataSz) {
    printf("*****************************************************\n");
    word32 i;
    for (i = 0; i < dataSz; i++)
        printf("%02X", theVar[i]);
    printf("\n");
    printf("******************************************************\n");
    return 0;
}

int hexToBinary(byte* toVar, const char* fromHexString, size_t szHexString ) {
    int ret = 0;
    /* Calculate the actual binary length of the hex string */
    size_t byteLen = szHexString / 2;

    if (toVar == NULL || fromHexString == NULL) {
        ESP_LOGE("ssh", " error");
        return -1;
    }
    if ((szHexString % 2 != 0)) {
        ESP_LOGE("ssh", "fromHexString length not even!");
    }

    ESP_LOGW(TAG, "Replacing %d bytes at %x", byteLen, (word32)toVar);
    memset(toVar, 0, byteLen);
    /* Iterate through the hex string and convert to binary */
    for (size_t i = 0; i < szHexString; i += 2) {
        /* Convert hex character to decimal */
        int decimalValue;
        sscanf(&fromHexString[i], "%2x", &decimalValue);
        size_t index = i / 2;
#if (0)
        /* Optionall peek at new values */
        byte new_val =  (decimalValue & 0x0F) << ((i % 2) * 4);
        ESP_LOGI("hex", "Current char = %d", toVar[index]);
        ESP_LOGI("hex", "New val = %d", decimalValue);
#endif
        toVar[index]  = decimalValue;
    }

    return ret;
}



#endif /* WOLFSSL_ESPIDF */
