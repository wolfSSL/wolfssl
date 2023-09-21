/* esp32_util.c
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

/*
** Version / Platform info.
**
** This could evolve into a wolfSSL-wide feature. For now, here only. See:
** https://github.com/wolfSSL/wolfssl/pull/6149
*/

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/version.h>

#include <wolfssl/wolfcrypt/wolfmath.h> /* needed to print MATH_INT_T value */

#if defined(WOLFSSL_ESPIDF)
    #include <esp_log.h>
    #include "sdkconfig.h"
    #define WOLFSSL_VERSION_PRINTF(...) ESP_LOGI(TAG, __VA_ARGS__)
#else
    #include <stdio.h>
    #define WOLFSSL_VERSION_PRINTF(...) { printf(__VA_ARGS__); printf("\n"); }
#endif

static const char* TAG = "esp32_util";

/* some functions are only applicable when hardware encryption is enabled */
#if defined(WOLFSSL_ESP32_CRYPT) && \
  (!defined(NO_AES)        || !defined(NO_SHA) || !defined(NO_SHA256) ||\
   defined(WOLFSSL_SHA384) || defined(WOLFSSL_SHA512))

#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

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
WOLFSSL_LOCAL int esp_CryptHwMutexInit(wolfSSL_Mutex* mutex) {
    if (mutex == NULL) {
        return BAD_MUTEX_E;
    }

    return wc_InitMutex(mutex);
}

/*
 * call the ESP-IDF mutex lock; xSemaphoreTake
 *
 */
WOLFSSL_LOCAL int esp_CryptHwMutexLock(wolfSSL_Mutex* mutex, TickType_t block_time) {
    if (mutex == NULL) {
        WOLFSSL_ERROR_MSG("esp_CryptHwMutexLock called with null mutex");
        return BAD_MUTEX_E;
    }

#ifdef SINGLE_THREADED
    return wc_LockMutex(mutex); /* xSemaphoreTake take with portMAX_DELAY */
#else
    return ((xSemaphoreTake( *mutex, block_time ) == pdTRUE) ? 0 : BAD_MUTEX_E);
#endif
}

/*
 * call the ESP-IDF mutex UNlock; xSemaphoreGive
 *
 */
WOLFSSL_LOCAL int esp_CryptHwMutexUnLock(wolfSSL_Mutex* mutex) {
    if (mutex == NULL) {
        WOLFSSL_ERROR_MSG("esp_CryptHwMutexLock called with null mutex");
        return BAD_MUTEX_E;
    }

#ifdef SINGLE_THREADED
    return wc_UnLockMutex(mutex);
#else
    xSemaphoreGive(*mutex);
    return 0;
#endif
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
static int ShowExtendedSystemInfo_platform_espressif()
{
#if defined(CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ)
    WOLFSSL_VERSION_PRINTF("CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ: %u MHz",
                           CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ);
#endif

#if CONFIG_IDF_TARGET_ESP32

    WOLFSSL_VERSION_PRINTF("Xthal_have_ccount: %u",
                           Xthal_have_ccount);

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
    WOLFSSL_VERSION_PRINTF("Stack HWM: %d",
                           uxTaskGetStackHighWaterMark(NULL));
#endif

#elif CONFIG_IDF_TARGET_ESP32S2
    WOLFSSL_VERSION_PRINTF("Xthal_have_ccount = %u",
                           Xthal_have_ccount);
#elif CONFIG_IDF_TARGET_ESP32C6
    /* not supported at this time */
#elif CONFIG_IDF_TARGET_ESP32C3
    /* not supported at this time */
#elif CONFIG_IDF_TARGET_ESP32S3
    WOLFSSL_VERSION_PRINTF("Xthal_have_ccount = %u",
                           Xthal_have_ccount);
#elif CONFIG_IDF_TARGET_ESP32H2
    /* not supported at this time */
#elif CONFIG_IDF_TARGET_ESP32C2
    /* not supported at this time */
#else
    /* not supported at this time */
#endif

    /* check to see if we are using hardware encryption */
#if defined(NO_ESP32_CRYPT)
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
#elif defined(CONFIG_IDF_TARGET_ESP32C3)
    WOLFSSL_VERSION_PRINTF("ESP32_CRYPT is enabled for ESP32-C3.");
#elif defined(CONFIG_IDF_TARGET_ESP32C6)
    WOLFSSL_VERSION_PRINTF("ESP32_CRYPT is enabled for ESP32-C6.");
#elif defined(CONFIG_IDF_TARGET_ESP32H2)
    WOLFSSL_VERSION_PRINTF("ESP32_CRYPT is enabled for ESP32-H2.");
#else
    /* this should have been detected & disabled in user_settins.h */
    #error "ESP32_CRYPT not yet supported on this IDF TARGET"
#endif

    /* Even though enabled, some specifics may be disabled */
#if defined(NO_WOLFSSL_ESP32_CRYPT_HASH)
    WOLFSSL_VERSION_PRINTF("NO_WOLFSSL_ESP32_CRYPT_HASH is defined!"
                           "(disabled HW SHA).");
#endif

#if defined(NO_WOLFSSL_ESP32_CRYPT_AES)
    WOLFSSL_VERSION_PRINTF("NO_WOLFSSL_ESP32_CRYPT_AES is defined!"
                           "(disabled HW AES).");
#endif

#if defined(NO_WOLFSSL_ESP32_CRYPT_RSA_PRI)
    WOLFSSL_VERSION_PRINTF("NO_WOLFSSL_ESP32_CRYPT_RSA_PRI defined!"
                           "(disabled HW RSA)");
#endif

#endif /* ! NO_ESP32_CRYPT */

    return 0;
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
static int ShowExtendedSystemInfo_git()
{
#if defined(HAVE_WC_INTROSPECTION) && !defined(ALLOW_BINARY_MISMATCH_INTROSPECTION)
#pragma message("WARNING: both HAVE_VERSION_EXTENDED_INFO and " \
                "HAVE_WC_INTROSPECTION are enabled. Some extended " \
                "information details will not be available.")

    WOLFSSL_VERSION_PRINTF("HAVE_WC_INTROSPECTION enabled. "
                           "Some extended system details not available.");
#else
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

#endif /* else not HAVE_WC_INTROSPECTION */
    return 0;
}

/*
** All platforms: thread details
*/
static int ShowExtendedSystemInfo_thread()
{
    /* all platforms: stack high water mark check */
#if defined(SINGLE_THREADED)
    WOLFSSL_VERSION_PRINTF("SINGLE_THREADED");
#else
    WOLFSSL_VERSION_PRINTF("NOT SINGLE_THREADED");
#endif
    return 0;
}

/*
** All Platforms: platform details
*/
static int ShowExtendedSystemInfo_platform()
{
#if defined(WOLFSSL_ESPIDF)
#if defined(CONFIG_IDF_TARGET)
    WOLFSSL_VERSION_PRINTF("CONFIG_IDF_TARGET = %s",
                           CONFIG_IDF_TARGET);
    ShowExtendedSystemInfo_platform_espressif();
#endif
#endif
    return 0;
}

/*
*******************************************************************************
** The internal, portable, but currently private ShowExtendedSystemInfo()
*******************************************************************************
*/
int ShowExtendedSystemInfo(void)
    {
        WOLFSSL_VERSION_PRINTF("Extended Version and Platform Information.");

#if defined(LIBWOLFSSL_VERSION_STRING)
        WOLFSSL_VERSION_PRINTF("LIBWOLFSSL_VERSION_STRING = %s",
                               LIBWOLFSSL_VERSION_STRING);
#endif

#if defined(LIBWOLFSSL_VERSION_HEX)
        WOLFSSL_VERSION_PRINTF("LIBWOLFSSL_VERSION_HEX = %x",
                               LIBWOLFSSL_VERSION_HEX);
#endif

#if defined(WOLFSSL_MULTI_INSTALL_WARNING)
        /* CMake may have detected undesired multiple installs, so give warning. */
        WOLFSSL_VERSION_PRINTF("");
        WOLFSSL_VERSION_PRINTF("WARNING: Multiple wolfSSL installs found.");
        WOLFSSL_VERSION_PRINTF("Check ESP-IDF and local project [components] directory.");
        WOLFSSL_VERSION_PRINTF("");
#endif

        ShowExtendedSystemInfo_git(); /* may be limited during active introspection */
        ShowExtendedSystemInfo_platform();
        ShowExtendedSystemInfo_thread();
        return 0;
    }

WOLFSSL_LOCAL int esp_ShowExtendedSystemInfo()
{
    return ShowExtendedSystemInfo();
}

/* Print a MATH_INT_T attribute list.
 *
 * Note with the right string parameters, the result can be pasted as
 * initialization code.
 */
WOLFSSL_LOCAL int esp_show_mp_attributes(char* c, MATH_INT_T* X)
{
    static const char* MP_TAG = "MATH_INT_T";
    int ret = 0;
    if (X == NULL) {
        ret = -1;
        ESP_LOGV(MP_TAG, "esp_show_mp_attributes called with X == NULL");
    }
    else {
        ESP_LOGI(MP_TAG, "");
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
WOLFSSL_LOCAL int esp_show_mp(char* c, MATH_INT_T* X)
{
    static const char* MP_TAG = "MATH_INT_T";
    int ret = MP_OKAY;
    int words_to_show = 0;
    size_t i;

    if (X == NULL) {
        ret = -1;
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
        for (i = 0; i < words_to_show; i++) {
            ESP_LOGI(MP_TAG, "%s.dp[%2d] = 0x%08x;  /* %2d */ ",
                                   c, /* the supplied variable name      */
                                   i, /* the index, i for dp[%d]         */
                                   (unsigned int)X->dp[i], /* the value  */
                                   i  /* the index, again, for comment   */
                     );
        }
        ESP_LOGI(MP_TAG, "");
    }
    return ret;
}

/* Perform a full mp_cmp and binary compare.
 * (typically only used during debugging) */
WOLFSSL_LOCAL int esp_mp_cmp(char* name_A, MATH_INT_T* A, char* name_B, MATH_INT_T* B)
{
    int ret = MP_OKAY;
    int e;

    e = memcmp(A, B, sizeof(mp_int));
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
        ESP_LOGV(TAG, "esp_mp_cmp equal for %s and %s!",
                       name_A, name_B);
    }
    else {
#ifdef DEBUG_WOLFSSL
        esp_show_mp(name_A, A);
        esp_show_mp(name_B, B);
#endif
    }
    return ret;
}
