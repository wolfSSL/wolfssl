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
#include <nvs_flash.h>

/* wolfSSL */
/* The wolfSSL user_settings.h is automatically included by settings.h file.
 * Never explicitly include wolfSSL user_settings.h in any source file.
 * The settings.h should also be listed above wolfssl library include files. */
#if defined(WOLFSSL_USER_SETTINGS)
    #include <wolfssl/wolfcrypt/settings.h>
    #ifndef WOLFSSL_ESPIDF
        #warning "Problem with wolfSSL user_settings."
        #warning "Check components/wolfssl/include"
    #endif
    #include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>
    #include <wolfssl/wolfcrypt/port/Espressif/esp-sdk-lib.h>
    #if defined(CONFIG_WOLFSSL_CERTIFICATE_BUNDLE) && \
                CONFIG_WOLFSSL_CERTIFICATE_BUNDLE
        #include <wolfssl/wolfcrypt/port/Espressif/esp_crt_bundle.h>
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

#include "client-tls.h"

#ifdef CONFIG_IDF_TARGET_ESP32H2
    /* There's no WiFi on ESP32-H2, no esp_eth.h in protocol_examples_common.h
     * For wired ethernet, see:
     * https://github.com/wolfSSL/wolfssl-examples/tree/master/ESP32/TLS13-ENC28J60-client */
#else
    /* See CONFIG_WOLFSSL_EXAMPLE_NAME_TLS_CLIENT that defines
     * USE_WOLFSSL_ESP_SDK_WIFI */
    #include "protocol_examples_common.h" /* example connect */
    #include <wolfssl/wolfcrypt/port/Espressif/esp-sdk-lib.h>

    /*
     * Note ModBus TCP cannot be disabled on ESP8266 tos-sdk/v3.4
     * See https://github.com/espressif/esp-modbus/issues/2
     */
#endif

#ifdef WOLFSSL_TRACK_MEMORY
    #include <wolfssl/wolfcrypt/mem_track.h>
#endif

static const char* TAG = "main";

#if defined(WOLFSSL_ESPWROOM32SE) && defined(HAVE_PK_CALLBACKS) \
                                  && defined(WOLFSSL_ATECC508A)

#include "wolfssl/wolfcrypt/port/atmel/atmel.h"

/* when you want to use a custom slot allocation */
/* enable the definition CUSTOM_SLOT_ALLOCATION. */

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

/* Entry for FreeRTOS */
void app_main(void)
{
    uart_config_t uart_config = {
        .baud_rate = THIS_MONITOR_UART_BAUD_DATE,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
    };
    esp_err_t ret = 0;
#if !defined(SINGLE_THREADED) && INCLUDE_uxTaskGetStackHighWaterMark
    int stack_start = 0;
#endif
#if !defined(SINGLE_THREADED)
    int this_heap = 0;
#endif
#ifdef DEBUG_WOLFSSL
    /* Turn debugging on or off: */
    /* wolfSSL_Debugging_ON();   */
    /* wolfSSL_Debugging_OFF();  */
#endif
#if !defined(CONFIG_WOLFSSL_EXAMPLE_NAME_TLS_CLIENT)
    ESP_LOGW(TAG, "Warning: Example wolfSSL misconfigured? Check menuconfig.");
#endif
    /* uart_set_pin(UART_NUM_0, TX_PIN, RX_PIN,
     *              UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE); */

    /* Some targets may need to have UART speed set, such as ESP8266 */
    ESP_LOGI(TAG, "UART init");
    uart_param_config(UART_NUM_0, &uart_config);
    uart_driver_install(UART_NUM_0,
                        THIS_MONITOR_UART_RX_BUFFER_SIZE, 0, 0, NULL, 0);
    ESP_LOGI(TAG, "---------------- wolfSSL TLS Client Example ------------");
    ESP_LOGI(TAG, "--------------------------------------------------------");
    ESP_LOGI(TAG, "--------------------------------------------------------");
    ESP_LOGI(TAG, "---------------------- BEGIN MAIN ----------------------");
    ESP_LOGI(TAG, "--------------------------------------------------------");
    ESP_LOGI(TAG, "--------------------------------------------------------");
#ifdef WOLFSSL_ESP_NO_WATCHDOG
    ESP_LOGW(TAG, "Found WOLFSSL_ESP_NO_WATCHDOG, disabling...");
    esp_DisableWatchdog();
#endif
#if defined(HAVE_VERSION_EXTENDED_INFO)
    esp_ShowExtendedSystemInfo();
#else
    ESP_LOGW(TAG, "HAVE_VERSION_EXTENDED_INFO not defined");
#endif

#if defined(ESP_SDK_MEM_LIB_VERSION) && defined(DEBUG_WOLFSSL)
    sdk_init_meminfo();
#endif
#ifdef ESP_TASK_MAIN_STACK
    ESP_LOGI(TAG, "ESP_TASK_MAIN_STACK: %d", ESP_TASK_MAIN_STACK);
#endif
#ifdef TASK_EXTRA_STACK_SIZE
    ESP_LOGI(TAG, "TASK_EXTRA_STACK_SIZE: %d", TASK_EXTRA_STACK_SIZE);
#endif

#ifdef SINGLE_THREADED
    ESP_LOGI(TAG, "Single threaded");
#else
    ESP_LOGI(TAG, "CONFIG_ESP_MAIN_TASK_STACK_SIZE = %d bytes (%d words)",
                   CONFIG_ESP_MAIN_TASK_STACK_SIZE,
             (int)(CONFIG_ESP_MAIN_TASK_STACK_SIZE / sizeof(void*)));

    #ifdef INCLUDE_uxTaskGetStackHighWaterMark
    {
        /* Returns the high water mark of the stack associated with xTask. That is,
         * the minimum free stack space there has been (in bytes not words, unlike
         * vanilla FreeRTOS) since the task started. The smaller the returned
         * number the closer the task has come to overflowing its stack.
         * see Espressif api-reference/system/freertos_idf
         */
        stack_start = uxTaskGetStackHighWaterMark(NULL);
        #ifdef ESP_SDK_MEM_LIB_VERSION
        {
            sdk_var_whereis("stack_start", &stack_start);
        }
        #endif

        ESP_LOGI(TAG, "Stack Start HWM: %d bytes", stack_start);
    }
    #endif /* INCLUDE_uxTaskGetStackHighWaterMark */
#endif /* SINGLE_THREADED */

#ifdef CONFIG_IDF_TARGET_ESP32H2
    ESP_LOGE(TAG, "No WiFi on the ESP32-H2 and ethernet not yet supported");
    while (1) {
        vTaskDelay(60000);
    }
#endif

    ESP_LOGI(TAG, "nvs flash init..");
    ret = nvs_flash_init();

    /* Optionally erase flash */
#if defined(ESP_ERR_NVS_NO_FREE_PAGES) && defined(ESP_ERR_NVS_NEW_VERSION_FOUND)
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGI(TAG, "nvs flash erase..");
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_LOGI(TAG, "nvs flash erase..");
        ret = nvs_flash_init();
    }
    else {
        ESP_LOGW(TAG, "nvs flash NOT erased");
    }
#else
    #warning "nvs flash not initialized"
#endif

#ifdef FOUND_PROTOCOL_EXAMPLES_DIR
    ESP_LOGI(TAG, "FOUND_PROTOCOL_EXAMPLES_DIR active, using example code.");
    #if defined(CONFIG_IDF_TARGET_ESP32H2)
        ESP_LOGE(TAG, "There's no WiFi on ESP32-H2.");
    #else
        #ifdef CONFIG_EXAMPLE_WIFI_SSID
            if (XSTRCMP(CONFIG_EXAMPLE_WIFI_SSID, "myssid") == 0) {
                ESP_LOGW(TAG, "WARNING: CONFIG_EXAMPLE_WIFI_SSID is myssid.");
                ESP_LOGW(TAG, "  Do you have a WiFi AP called myssid, or ");
                ESP_LOGW(TAG, "  did you forget the ESP-IDF configuration?");
            }
        #else
            #define CONFIG_EXAMPLE_WIFI_SSID "myssid"
            ESP_LOGW(TAG, "WARNING: CONFIG_EXAMPLE_WIFI_SSID not defined.");
        #endif
        #ifdef DEBUG_WOLFSSL
            /* Anytime we are debugging, can also debug WiFi: */
            /* esp_log_level_set("wifi", ESP_LOG_VERBOSE);    */
            /* esp_log_level_set("wpa",  ESP_LOG_VERBOSE);    */
        #endif
        #if defined(USE_WOLFSSL_ESP_SDK_WIFI)
            #if defined(ESP_SDK_WIFI_LIB_VERSION) && \
                       (ESP_SDK_WIFI_LIB_VERSION > 1)
                esp_sdk_wifi_lib_init();
                ret = esp_sdk_wifi_init_sta();
            #else
                ESP_LOGE(TAG, "A newer version of wolfSSL is needed");
                ret = ESP_FAIL;
            #endif

            if (ret == ESP_OK) {
                ESP_LOGI(TAG, "WiFi connect success!");
            }
            else {
                ESP_LOGI(TAG, "ERROR: WiFi connect failed!");
                while (1) {
                    vTaskDelay(10000 / portTICK_PERIOD_MS);
                }
            }
            esp_sdk_wifi_show_ip();
        #else
            ESP_LOGI(TAG, "esp netif init...");
            ESP_ERROR_CHECK(esp_netif_init());
            ESP_LOGI(TAG, "esp event loop create default...");
            ESP_ERROR_CHECK(esp_event_loop_create_default());
            #if defined(CONFIG_IDF_TARGET_ESP32H2)
                ESP_LOGI(TAG, "There's no WiFi on the ESP32-H2");
                while (1) {
                    vTaskDelay(pdMS_TO_TICKS(1000));
                }
            #else
                ESP_LOGI(TAG, "example connect...");
                ESP_ERROR_CHECK(example_connect());
            #endif
        #endif
    #endif
#else
    ESP_ERROR_CHECK(nvs_flash_init());

    /* Initialize NVS */
    ret = nvs_flash_init();
    #if defined(CONFIG_IDF_TARGET_ESP8266)
    {
        if (ret == ESP_ERR_NVS_NO_FREE_PAGES) {
            ESP_ERROR_CHECK(nvs_flash_erase());
            ret = nvs_flash_init();
        }
    }
    #else
    {
        /* Non-ESP8266 initialization is slightly different */
        if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
            ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
            ESP_ERROR_CHECK(nvs_flash_erase());
            ret = nvs_flash_init();
        }
    }
    #endif /* else not CONFIG_IDF_TARGET_ESP8266 */
    ESP_ERROR_CHECK(ret);

    #if defined(CONFIG_IDF_TARGET_ESP32H2)
        ESP_LOGE(TAG, "There's no WiFi on ESP32-H2. ");
    #else
        /* Initialize WiFi */
        ESP_LOGI(TAG, "ESP_WIFI_MODE_STA");
        ret = esp_sdk_wifi_init_sta();
        while (ret != 0) {
            ESP_LOGI(TAG, "Waiting...");
            vTaskDelay(60000 / portTICK_PERIOD_MS);
            ESP_LOGI(TAG, "Trying WiFi again...");
            ret = esp_sdk_wifi_init_sta();
        }
    #endif /* else not CONFIG_IDF_TARGET_ESP32H2 */
#endif /* else FOUND_PROTOCOL_EXAMPLES_DIR not found */

    /* Set time for cert validation.
     * Some lwIP APIs, including SNTP functions, are not thread safe. */
    ret = set_time(); /* need to setup NTP before WiFi */

    /* Once we are connected to the network, start & wait for NTP time */
    ret = set_time_wait_for_ntp();

    switch (ret) {
        case ESP_OK:
            break;
        case ESP_ERR_TIMEOUT:
            ESP_LOGI(TAG, "Waiting 10 more seconds for NTP to complete." );
            vTaskDelay(10000 / portTICK_PERIOD_MS); /* brute-force solution */
            esp_show_current_datetime();
            break;
        default:
            ESP_LOGE(TAG, "set_time_wait_for_ntp error %d", ret);
    } /* switch ret values */

#if defined(SINGLE_THREADED)
    /* just call the task */
    tls_smp_client_task((void*)NULL);
#else
    tls_args args[1] = {0};
    /* start a thread with the task */
    args[0].loops = 10;
    args[0].port = 11111;

    /* HWM is maximum amount of stack space that has been unused, in bytes
     * not words (unlike vanilla freeRTOS). */
    this_heap = esp_get_free_heap_size();
    ESP_LOGI(TAG, "Initial Stack Used (before wolfSSL Server): %d bytes",
                   CONFIG_ESP_MAIN_TASK_STACK_SIZE
                   - (uxTaskGetStackHighWaterMark(NULL))
            );
    ESP_LOGI(TAG, "Starting TLS Client task ...\n");
    ESP_LOGI(TAG, "main tls_smp_client_init heap @ %p = %d",
                  &this_heap, this_heap);
    tls_smp_client_init(args);
/* optional additional client threads
    tls_smp_client_init(args);
    tls_smp_client_init(args);
    tls_smp_client_init(args);
    tls_smp_client_init(args);
    tls_smp_client_init(args);
    tls_smp_client_init(args);
    tls_smp_client_init(args);
*/
#endif

    /* Done */
#ifdef SINGLE_THREADED
    ESP_LOGV(TAG, "\n\nDone!\n\n");
    while (1);
#else
    ESP_LOGV(TAG, "\n\nvTaskDelete...\n\n");
    vTaskDelete(NULL);
    /* done */
    while (1) {
        ESP_LOGV(TAG, "\n\nLoop...\n\n");
    #ifdef INCLUDE_uxTaskGetStackHighWaterMark
        ESP_LOGI(TAG, "Stack HWM: %d", uxTaskGetStackHighWaterMark(NULL));

        ESP_LOGI(TAG, "Stack used: %d", CONFIG_ESP_MAIN_TASK_STACK_SIZE
                                        - (uxTaskGetStackHighWaterMark(NULL) ));
    #endif
        vTaskDelay(60000);
    } /* done while */
#endif /* else not SINGLE_THREADED */

} /* app_main */
