/* benchmark main.c
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

/* ESP-IDF */
#include "sdkconfig.h"
#include <esp_log.h>

/* wolfSSL */
/* The wolfSSL user_settings.h file is automatically included by the settings.h
 * file and should never be explicitly included in any other source files.
 * The settings.h should also be listed above wolfssl library include files. */
#if defined(WOLFSSL_USER_SETTINGS)
    #include <wolfssl/wolfcrypt/settings.h>
    #if defined(WOLFSSL_ESPIDF)
        #include <wolfssl/version.h>
        #include <wolfssl/wolfcrypt/types.h>
        #include <wolfcrypt/benchmark/benchmark.h>
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

/* set to 0 for one benchmark,
** set to 1 for continuous benchmark loop */
#define BENCHMARK_LOOP 0

#define THIS_MONITOR_UART_RX_BUFFER_SIZE 200

#ifdef CONFIG_ESP8266_XTAL_FREQ_26
    /* 26MHz crystal: 74880 bps */
    #define THIS_MONITOR_UART_BAUD_DATE 74880
#else
    /* 40MHz crystal: 115200 bps */
    #define THIS_MONITOR_UART_BAUD_DATE 115200
#endif

/* check BENCH_ARGV in sdkconfig to determine need to set WOLFSSL_BENCH_ARGV */
#ifdef CONFIG_BENCH_ARGV
    #define WOLFSSL_BENCH_ARGV CONFIG_BENCH_ARGV
    #define WOLFSSL_BENCH_ARGV_MAX_ARGUMENTS 22 /* arbitrary number of max args */
#endif

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

#include "main.h"

static const char* const TAG = "wolfssl_benchmark";

#if defined(WOLFSSL_ESPWROOM32SE) && defined(HAVE_PK_CALLBACKS) \
                                  && defined(WOLFSSL_ATECC508A)

#include "wolfssl/wolfcrypt/port/atmel/atmel.h"

/* when you need to use a custom slot allocation, */
/* enable the definition CUSTOM_SLOT_ALLOCAION.   */
#if defined(CUSTOM_SLOT_ALLOCATION)

static byte mSlotList[ATECC_MAX_SLOT];

int atmel_set_slot_allocator(atmel_slot_alloc_cb alloc, atmel_slot_dealloc_cb dealloc);

/* initialize slot array */
void my_atmel_slotInit()
{
    int i;
    for(i = 0;i < ATECC_MAX_SLOT;i++) {
        mSlotList[i] = ATECC_INVALID_SLOT;
    }
}

/* allocate slot depending on slotType */
int my_atmel_alloc(int slotType)
{
    int i, slot = -1;

    switch(slotType){
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
            for(i = 0;i < ATECC_MAX_SLOT;i++){
                if(mSlotList[i] == ATECC_INVALID_SLOT){
                    slot = i;
                    break;
                }
            }
    }

    return slot;
}

/* free slot array       */
void my_atmel_free(int slotId)
{
    if(slotId >= 0 && slotId < ATECC_MAX_SLOT){
        mSlotList[slotId] = ATECC_INVALID_SLOT;
    }
}

#endif /* CUSTOM_SLOT_ALLOCATION                                       */
#endif /* WOLFSSL_ESPWROOM32SE && HAVE_PK_CALLBACK && WOLFSSL_ATECC508A */

/* the following are needed by benchmark.c with args */
#ifdef WOLFSSL_BENCH_ARGV
char* __argv[WOLFSSL_BENCH_ARGV_MAX_ARGUMENTS];
#define ARG_BUFF_SIZE 16

int construct_argv()
{
    #define ARG_BUFF_SIZE 16
    int cnt = 0;
    int i = 0;
    int len = 0;
    char *_argv; /* buffer for copying the string    */
    char *ch; /* char pointer to trace the string */
    char buff[ARG_BUFF_SIZE] = { 0 }; /* buffer for a argument copy       */

    ESP_LOGI(TAG, "construct_argv arg:%s\n", CONFIG_BENCH_ARGV);
    len = strlen(CONFIG_BENCH_ARGV);
    _argv = (char*)malloc(len + 1);
    if (!_argv) {
        return -1;
    }
    memset(_argv, 0, len + 1);
    memcpy(_argv, CONFIG_BENCH_ARGV, len);
    _argv[len] = '\0';
    ch = _argv;

    __argv[cnt] = malloc(10);
    sprintf(__argv[cnt], "benchmark");
    __argv[cnt][9] = '\0';
    cnt = 1;

    while (*ch != '\0') {
        /* check that we don't overflow manual arg assembly */
        if (cnt >= (WOLFSSL_BENCH_ARGV_MAX_ARGUMENTS)) {
            ESP_LOGE(TAG, "Abort construct_argv;"
                          "Reached maximum defined arguments = %d",
                          WOLFSSL_BENCH_ARGV_MAX_ARGUMENTS);
            break;
        }

        /* skip white-space */
        while (*ch == ' ') { ++ch; }

        memset(buff, 0, sizeof(buff));
        /* copy each args into buffer */
        i = 0;
        while ((*ch != ' ') && (*ch != '\0') && (i <= ARG_BUFF_SIZE)) {
            buff[i] = *ch;
            ++i;
            ++ch;
        }
        /* copy the string into argv */
        __argv[cnt] = (char*)malloc(i + 1);
        memset(__argv[cnt], 0, i + 1);
        memcpy(__argv[cnt], buff, i + 1);
        /* next args */
        ++cnt;
    }

    free(_argv);

    return (cnt);
}
#endif

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
    word32 loops = 0;
    esp_err_t ret = 0;

    stack_start = esp_sdk_stack_pointer();

    /* uart_set_pin(UART_NUM_0, TX_PIN, RX_PIN,
     *              UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE); */

    /* Some targets may need to have UART speed set, such as ESP8266 */
    ESP_LOGI(TAG, "UART init");
    uart_param_config(UART_NUM_0, &uart_config);
    uart_driver_install(UART_NUM_0,
                        THIS_MONITOR_UART_RX_BUFFER_SIZE, 0, 0, NULL, 0);

    ESP_LOGI(TAG, "---------------- wolfSSL Benchmark Example -------------");
    ESP_LOGI(TAG, "--------------------------------------------------------");
    ESP_LOGI(TAG, "--------------------------------------------------------");
    ESP_LOGI(TAG, "---------------------- BEGIN MAIN ----------------------");
    ESP_LOGI(TAG, "--------------------------------------------------------");
    ESP_LOGI(TAG, "--------------------------------------------------------");
    ESP_LOGI(TAG, "Stack Start: 0x%x", stack_start);

#ifdef WOLFSSL_ESP_NO_WATCHDOG
    ESP_LOGW(TAG, "Found WOLFSSL_ESP_NO_WATCHDOG, disabling...");
    esp_DisableWatchdog();
#endif

#if defined(HAVE_VERSION_EXTENDED_INFO) && defined(WOLFSSL_HAS_METRICS)
    esp_ShowExtendedSystemInfo();
#endif

    /* all platforms: stack high water mark check */
    ESP_LOGI(TAG, "app_main CONFIG_BENCH_ARGV = %s", WOLFSSL_BENCH_ARGV);

/* when using atecc608a on esp32-wroom-32se */
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

#ifdef NO_CRYPT_BENCHMARK
    ESP_LOGI(TAG, "NO_CRYPT_BENCHMARK defined, skipping wolf_benchmark_task")
#else

    /* Although wolfCrypt_Init() may be explicitly called above,
    ** note it is still always called in wolf_benchmark_task.
    */
    stack_start = uxTaskGetStackHighWaterMark(NULL);

    do {
        ESP_LOGI(TAG, "Stack HWM: %d\n", uxTaskGetStackHighWaterMark(NULL));

#ifdef WOLFSSL_BENCH_ARGV
        ret = benchmark_test(__argv);
#else
        ret = benchmark_test(NULL);
#endif
        ESP_LOGI(TAG, "Stack used: %d\n",
                      stack_start - uxTaskGetStackHighWaterMark(NULL));

        esp_hw_show_metrics();

        loops++; /* count of the number of tests run before fail. */
        ESP_LOGI(TAG, "Stack HWM: %d\n", uxTaskGetStackHighWaterMark(NULL));
        ESP_LOGI(TAG, "loops = %d", loops);

    } while (BENCHMARK_LOOP && (ret == 0));

    /* Reminder: wolfCrypt_Cleanup() should always be called at completion,
    ** and is called in wolf_benchmark_task().  */

#if defined BENCHMARK_LOOP && (BENCHMARK_LOOP == 1)
    /* If BENCHMARK_LOOP enabled and we get here, there was likely an error. */
    ESP_LOGI(TAG, "Benchmark loops completed: %d", loops);
#endif

#if defined(SINGLE_THREADED)
    /* need stack monitor for single thread */
#else
    ESP_LOGI(TAG, "Stack HWM: %d\n", uxTaskGetStackHighWaterMark(NULL));
#endif

#ifdef INCLUDE_uxTaskGetStackHighWaterMark
    ESP_LOGI(TAG, "Stack HWM: %d", uxTaskGetStackHighWaterMark(NULL));

    ESP_LOGI(TAG, "Stack used: %d", CONFIG_ESP_MAIN_TASK_STACK_SIZE
                                    - (uxTaskGetStackHighWaterMark(NULL)));
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
    ESP_LOGI(TAG, "\n\nDone!\n\n"
                  "If running from idf.py monitor, press twice: Ctrl+]");
#endif

    /* After completion, we'll just wait */
    while (1) {
#if defined(SINGLE_THREADED)
        while (1);
#else
        vTaskDelay(60000);
#endif
    } /* done while */
#endif /* NO_CRYPT_BENCHMARK */
}
