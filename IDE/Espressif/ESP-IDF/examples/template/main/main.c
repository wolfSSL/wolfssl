/* main.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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
 *                      Attention maintainers:
 *
 *  This code is mostly mirrored between client and server examples.
 *
 *                  Please apply any updates to both.
 */
#include "sdkconfig.h"
#include "main.h"

/* ESP specific */
#include <esp_log.h>
#include <esp_event.h>

/* wolfSSL */
/* The wolfSSL user_settings.h is automatically included by settings.h file.
 * Never explicitly include wolfSSL user_settings.h in any source file.
 * The settings.h should also be listed above wolfssl library include files. */
#if defined(WOLFSSL_USER_SETTINGS)
    #include <wolfssl/wolfcrypt/settings.h>
    #if defined(WOLFSSL_ESPIDF)
        #include <wolfssl/version.h>
        #include <wolfssl/wolfcrypt/types.h>

        #include <wolfssl/wolfcrypt/port/Espressif/esp-sdk-lib.h>
        #include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>
    #else
        #error "Problem with wolfSSL user_settings. "           \
               "Check components/wolfssl/include "              \
               "and confirm WOLFSSL_USER_SETTINGS is defined, " \
               "typically in the component CMakeLists.txt"
    #endif
#else
    /* Define WOLFSSL_USER_SETTINGS project wide for settings.h to include   */
    /* wolfSSL user settings in ./components/wolfssl/include/user_settings.h */
    #error "Missing WOLFSSL_USER_SETTINGS in CMakeLists or Makefile:\
    CFLAGS +=-DWOLFSSL_USER_SETTINGS"
#endif

/* Hardware; include after other libraries,
 * particularly after freeRTOS from settings.h */
#include <driver/uart.h>

#define THIS_MONITOR_UART_RX_BUFFER_SIZE 200

#ifdef CONFIG_ESP8266_XTAL_FREQ_26
    /* 26MHz crystal: 74880 bps */
    #define THIS_MONITOR_UART_BAUD_DATE 74880
#else
    /* 40MHz crystal: 115200 bps */
    #define THIS_MONITOR_UART_BAUD_DATE 115200
#endif

/* This project */
#include "main.h"
/*
** The wolfssl component can be installed in either:
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

static const char* const TAG = "My Project";

/* entry point */
void app_main(void)
{
    uart_config_t uart_config = {
        .baud_rate = THIS_MONITOR_UART_BAUD_DATE,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
    };
    int stack_start = 0;
    int heap_start = 0;
    int heap_current = 0;

    esp_err_t ret = 0;

    stack_start = esp_sdk_stack_pointer();

    /* uart_set_pin(UART_NUM_0, TX_PIN, RX_PIN,
     *              UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE); */

    /* Some targets may need to have UART speed set, such as ESP8266 */
    ESP_LOGI(TAG, "UART init");
    uart_param_config(UART_NUM_0, &uart_config);
    uart_driver_install(UART_NUM_0,
                        THIS_MONITOR_UART_RX_BUFFER_SIZE, 0, 0, NULL, 0);

    ESP_LOGI(TAG, "--------------- wolfSSL Template Example ---------------");
    ESP_LOGI(TAG, "--------------------------------------------------------");
    ESP_LOGI(TAG, "--------------------------------------------------------");
    ESP_LOGI(TAG, "---------------------- BEGIN MAIN ----------------------");
    ESP_LOGI(TAG, "--------------------------------------------------------");
    ESP_LOGI(TAG, "--------------------------------------------------------");
    ESP_LOGI(TAG, "Stack Start: 0x%x", stack_start);
#ifdef HAVE_WOLFCRYPT_WARMUP
    /* Unless disabled, we'll try to allocate known, long-term heap items early
     * in an attempt to avoid later allocations that may cause fragmentation. */
    ESP_ERROR_CHECK(esp_sdk_wolfssl_warmup());
#endif
#ifdef DEBUG_WOLFSSL
    /* Turn debugging on and off as needed: */
    wolfSSL_Debugging_ON();
    wolfSSL_Debugging_OFF();
#endif
#ifdef WOLFSSL_ESP_NO_WATCHDOG
    ESP_LOGW(TAG, "Found WOLFSSL_ESP_NO_WATCHDOG, disabling...");
    esp_DisableWatchdog();
#endif

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
     * see Espressif esp32/api-reference/system/freertos_idf.html
     */
    stack_start = uxTaskGetStackHighWaterMark(NULL);
    ESP_LOGI(TAG, "Stack Start HWM: %d bytes", stack_start);
#endif

#if defined(HAVE_VERSION_EXTENDED_INFO)
    esp_ShowExtendedSystemInfo();
#endif

    /* all platforms: stack high water mark check */
    ESP_LOGI(TAG, "Stack HWM: %d\n", uxTaskGetStackHighWaterMark(NULL));

#if defined (WOLFSSL_USE_TIME_HELPER)
    set_time();
#endif

#if !defined(CONFIG_WOLFSSL_EXAMPLE_NAME_TEMPLATE)
    ESP_LOGW(TAG, "Warning: Example wolfSSL misconfigured? Check menuconfig.");
#endif

    ESP_LOGI(TAG, "Hello wolfSSL!");

#ifdef HAVE_VERSION_EXTENDED_INFO
    ret = esp_ShowExtendedSystemInfo();
#endif

#if defined(WOLFSSL_HW_METRICS) && defined(WOLFSSL_HAS_METRICS)
    ret += esp_hw_show_metrics();
#endif

#ifdef WOLFSSL_ESPIDF_VERBOSE_EXIT_MESSAGE
    if (ret == 0) {
        ESP_LOGI(TAG, WOLFSSL_ESPIDF_VERBOSE_EXIT_MESSAGE("Success!", ret));
    }
    else {
        ESP_LOGE(TAG, WOLFSSL_ESPIDF_VERBOSE_EXIT_MESSAGE("Failed!", ret));
    }
#elif defined(WOLFSSL_ESPIDF_EXIT_MESSAGE)
    ESP_LOGI(TAG, WOLFSSL_ESPIDF_EXIT_MESSAGE);
#else
    ESP_LOGI(TAG, "\n\nDone!"
                  "If running from idf.py monitor, press twice: Ctrl+]\n\n"
                  "WOLFSSL_COMPLETE\n" /* exit keyword for wolfssl_monitor.py */
            );
#endif
}
