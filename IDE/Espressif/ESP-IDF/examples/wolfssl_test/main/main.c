/* main.c
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

/* ESP-IDF */
#include <esp_log.h>
#include "sdkconfig.h"

/* wolfSSL */
#include <wolfssl/wolfcrypt/settings.h>
#include <user_settings.h>
#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/types.h>

#ifndef WOLFSSL_ESPIDF
#warning "problem with wolfSSL user settings. Check components/wolfssl/include"
#endif

#include <wolfcrypt/test/test.h>
#include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>

/*
** the wolfssl component can be installed in either:
**
**   - the ESP-IDF component directory
**
**       ** OR **
**
**   - the local project component directory
**
** it is not recommended to install in both.
**
*/

/*
** although the wolfcrypt/test includes a default time setting,
** see the enclosed optional time helper for adding NNTP.
** be sure to add "time_helper.c" in main/CMakeLists.txt
*/
#undef WOLFSSL_USE_TIME_HELPER
#if defined(WOLFSSL_USE_TIME_HELPER)
    #include "time_helper.h" */
#endif

/* see wolfssl/wolfcrypt/test/test.h */
extern void wolf_crypt_task();

static const char* const TAG = "wolfssl_test";

#if defined(WOLFSSL_ESPWROOM32SE) && defined(HAVE_PK_CALLBACKS) \
                                  && defined(WOLFSSL_ATECC508A)

#include "wolfssl/wolfcrypt/port/atmel/atmel.h"

/* when you need to use a custom slot allocation, */
/* enable the definition CUSTOM_SLOT_ALLOCAION.   */
#if defined(CUSTOM_SLOT_ALLOCATION)

static byte mSlotList[ATECC_MAX_SLOT];

/* initialize slot array */
void my_atmel_slotInit()
{
    int i;
    for (i = 0; i < ATECC_MAX_SLOT; i++) {
        mSlotList[i] = ATECC_INVALID_SLOT;
    }
}

/* allocate slot depending on slotType */
int my_atmel_alloc(int slotType)
{
    int i, slot = ATECC_INVALID_SLOT;

    switch (slotType) {
        case ATMEL_SLOT_ENCKEY:
            slot = 4;
            break;
        case ATMEL_SLOT_DEVICE:
            slot = 0;
            break;
        case ATMEL_SLOT_ECDHE:
            slot = 0;
            break;
        case ATMEL_SLOT_ECDHE_ENC:
            slot = 4;
            break;
        case ATMEL_SLOT_ANY:
            for (i = 0; i < ATECC_MAX_SLOT; i++) {
                if (mSlotList[i] == ATECC_INVALID_SLOT) {
                    slot = i;
                    break;
                } /* if */
            } /* for */
    } /* switch */

    return slot;
}

/* free slot array       */
void my_atmel_free(int slotId)
{
    if (slotId >= 0 && slotId < ATECC_MAX_SLOT) {
        mSlotList[slotId] = ATECC_INVALID_SLOT;
    }
}

#endif /* CUSTOM_SLOT_ALLOCATION                                        */
#endif /* WOLFSSL_ESPWROOM32SE && HAVE_PK_CALLBACK && WOLFSSL_ATECC508A */

/* entry point */
void app_main(void)
{
    int stack_start = 0;
    esp_err_t ret = 0;
    ESP_LOGI(TAG, "------------------ wolfSSL Test Example ----------------");
    ESP_LOGI(TAG, "--------------------------------------------------------");
    ESP_LOGI(TAG, "--------------------------------------------------------");
    ESP_LOGI(TAG, "---------------------- BEGIN MAIN ----------------------");
    ESP_LOGI(TAG, "--------------------------------------------------------");
    ESP_LOGI(TAG, "--------------------------------------------------------");

#ifdef ESP_TASK_MAIN_STACK
     ESP_LOGI(TAG, "ESP_TASK_MAIN_STACK: %d", ESP_TASK_MAIN_STACK);
#endif
#ifdef TASK_EXTRA_STACK_SIZE
     ESP_LOGI(TAG, "TASK_EXTRA_STACK_SIZE: %d", TASK_EXTRA_STACK_SIZE);
#endif
#ifdef INCLUDE_uxTaskGetStackHighWaterMark
    ESP_LOGI(TAG, "CONFIG_ESP_MAIN_TASK_STACK_SIZE = %d bytes (%d words)",
                   CONFIG_ESP_MAIN_TASK_STACK_SIZE,
                   (int)(CONFIG_ESP_MAIN_TASK_STACK_SIZE / sizeof(void*)));

    /* Returns the high water mark of the stack associated with xTask. That is,
     * the minimum free stack space there has been (in bytes not words, unlike
     * vanilla FreeRTOS) since the task started. The smaller the returned
     * number the closer the task has come to overflowing its stack.
     * see https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/system/freertos_idf.html
     */
    stack_start = uxTaskGetStackHighWaterMark(NULL);
    ESP_LOGI(TAG, "Stack Start HWM: %d bytes", stack_start);
#endif

#ifdef HAVE_VERSION_EXTENDED_INFO
    esp_ShowExtendedSystemInfo();
#endif

    /* some interesting settings are target specific (ESP32, -C3, -S3, etc */
#if defined(CONFIG_IDF_TARGET_ESP32)
    ESP_LOGI(TAG, "CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ = %u MHz",
                   CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ
            );
    ESP_LOGI(TAG, "Xthal_have_ccount = %u", Xthal_have_ccount);
#elif defined(CONFIG_IDF_TARGET_ESP32S2)
    ESP_LOGI(TAG, "CONFIG_ESP32S2_DEFAULT_CPU_FREQ_MHZ = %u MHz",
                   CONFIG_ESP32S2_DEFAULT_CPU_FREQ_MHZ
             );
    ESP_LOGI(TAG, "Xthal_have_ccount = %u", Xthal_have_ccount);
#elif defined(CONFIG_IDF_TARGET_ESP32S3)
    ESP_LOGI(TAG, "CONFIG_ESP32S3_DEFAULT_CPU_FREQ_MHZ = %u MHz",
                   CONFIG_ESP32S3_DEFAULT_CPU_FREQ_MHZ
             );
    ESP_LOGI(TAG, "Xthal_have_ccount = %u", Xthal_have_ccount);
#else
    /* not available for other platformas at this time */
#endif

    /* all platforms: stack high water mark check */
    ESP_LOGI(TAG, "Stack HWM: %d\n", uxTaskGetStackHighWaterMark(NULL));

    /* check to see if we are using hardware encryption
     * TODO: move this to esp_util.c  */
#if defined(NO_ESP32_CRYPT)
    ESP_LOGI(TAG, "NO_ESP32_CRYPT defined! HW acceleration DISABLED.");
#else
    #if defined(CONFIG_IDF_TARGET_ESP32C3)
        ESP_LOGI(TAG, "ESP32_CRYPT is enabled for ESP32-C3.");

    #elif defined(CONFIG_IDF_TARGET_ESP32S2)
        ESP_LOGI(TAG, "ESP32_CRYPT is enabled for ESP32-S2.");

    #elif defined(CONFIG_IDF_TARGET_ESP32S3)
        ESP_LOGI(TAG, "ESP32_CRYPT is enabled for ESP32-S3.");

    #else
        ESP_LOGI(TAG, "ESP32_CRYPT is enabled.");
    #endif
#endif

#if defined (WOLFSSL_USE_TIME_HELPER)
    set_time();
#endif

/* when using atecc608a on esp32-WROOM-32se */
#if defined(WOLFSSL_ESPWROOM32SE) && defined(HAVE_PK_CALLBACKS) \
                                  && defined(WOLFSSL_ATECC508A)
    #if defined(CUSTOM_SLOT_ALLOCATION)
    my_atmel_slotInit();
    /* to register the callback, it needs to be initialized. */
    if ((wolfCrypt_Init()) != 0) {
        ESP_LOGE(TAG, "wolfCrypt_Init failed");
        return;
    }
    atmel_set_slot_allocator(my_atmel_alloc, my_atmel_free);
    #endif
#endif

#ifdef NO_CRYPT_TEST
    ESP_LOGI(TAG, "NO_CRYPT_TEST defined, skipping wolf_test_task");
#else
    /* Although wolfCrypt_Init() may be explicitly called above,
    ** Note it is still always called in wolf_test_task.
    */
    int loops = 0;
    do {
        #if defined(WOLFSSL_HW_METRICS) && defined(WOLFSSL_HAS_METRICS)
            esp_hw_show_metrics();
        #endif
        ret = wolf_test_task();
        ESP_LOGI(TAG, "Stack HWM: %d\n", uxTaskGetStackHighWaterMark(NULL));
        ESP_LOGI(TAG, "loops = %d", loops);

        loops++;
    }
    while (ret == 0);
    ESP_LOGI(TAG, "loops = %d", loops);

    /* note wolfCrypt_Cleanup() should always be called when finished.
    ** This is called at the end of wolf_test_task();
    */

    if (ret == 0) {
        ESP_LOGI(TAG, "wolf_test_task complete success result code = %d", ret);
    }
    else {
        ESP_LOGE(TAG, "wolf_test_task FAIL result code = %d", ret);
        /* see wolfssl/wolfcrypt/error-crypt.h */
    }

#if defined(DEBUG_WOLFSSL) && !defined(NO_WOLFSSL_ESP32_CRYPT_RSA_PRI)
    esp_hw_show_mp_metrics();
#endif

    /* after the test, we'll just wait */
#ifdef INCLUDE_uxTaskGetStackHighWaterMark
        ESP_LOGI(TAG, "Stack HWM: %d", uxTaskGetStackHighWaterMark(NULL));

        ESP_LOGI(TAG, "Stack used: %d", CONFIG_ESP_MAIN_TASK_STACK_SIZE
                                        - (uxTaskGetStackHighWaterMark(NULL)));
#endif

    ESP_LOGI(TAG, "\n\nDone!\n\n"
                  "If running from idf.py monitor, press twice: Ctrl+]");

    /* done */
    while (1) {
#if defined(SINGLE_THREADED)
        while (1);
#else
        vTaskDelay(60000);
#endif
    } /* done while */
#endif
}
