/* esp-sdk-lib.h
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
#ifndef __ESP_SDK_LIB_H__

#define __ESP_SDK_LIB_H__

/* Always include wolfcrypt/settings.h before any other wolfSSL file.      */
/* Reminder: settings.h pulls in user_settings.h; don't include it here.   */
#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_ESPIDF) /* Entire file is only for Espressif EDP-IDF   */

/* WOLFSSL_USER_SETTINGS must be defined, typically in the CMakeLists.txt: */
/*    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_USER_SETTINGS")        */
#ifndef WOLFSSL_USER_SETTINGS
    #error  "WOLFSSL_USER_SETTINGS must be defined for Espressif targts"
#endif

/* FreeRTOS */
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/event_groups.h>

/* Espressif */
#include "sdkconfig.h" /* ensure ESP-IDF settings are available everywhere */
#include <esp_idf_version.h>
#include <esp_log.h>

#define ESP_SDK_MEM_LIB_VERSION 1

/**
 ******************************************************************************
 ******************************************************************************
 ** USER APPLICATION SETTINGS BEGIN
 ******************************************************************************
 ******************************************************************************
 **/

/* when using a private config with plain text passwords,
 * file my_private_config.h should be excluded from git updates */
/* #define  USE_MY_PRIVATE_CONFIG */

/* Note that IntelliSense may not work properly in the next section for the
 * Espressif SDK 3.4 on the ESP8266. Macros should still be defined.
 * See the project-level Makefile. Example found in:
 * https://github.com/wolfSSL/wolfssl/tree/master/IDE/Espressif/ESP-IDF/examples/template
 *
 * The USE_MY_PRIVATE_[OS]_CONFIG is typically an environment variable that
 * triggers the make (not cmake) to add compiler defines.
 */
#if defined(USE_MY_PRIVATE_WINDOWS_CONFIG)
    #include "/workspace/my_private_config.h"
#elif defined(USE_MY_PRIVATE_WSL_CONFIG)
    #include "/mnt/c/workspace/my_private_config.h"
#elif defined(USE_MY_PRIVATE_LINUX_CONFIG)
    #include "~/workspace/my_private_config.h"
#elif defined(USE_MY_PRIVATE_MAC_CONFIG)
    #include "~/Documents/my_private_config.h"
#elif defined(USE_MY_PRIVATE_CONFIG)
    /* This section works best with cmake & non-environment variable setting */
    #if defined(WOLFSSL_CMAKE_SYSTEM_NAME_WINDOWS)
        #define WOLFSSL_CMAKE
        #include "/workspace/my_private_config.h"
    #elif defined(WOLFSSL_MAKE_SYSTEM_NAME_WINDOWS)
        #define WOLFSSL_MAKE
        #include "/workspace/my_private_config.h"
    #elif defined(WOLFSSL_CMAKE_SYSTEM_NAME_WSL)
        #define WOLFSSL_CMAKE
        #include "/mnt/c/workspace/my_private_config.h"
    #elif defined(WOLFSSL_MAKE_SYSTEM_NAME_WSL)
        #define WOLFSSL_MAKE
        #include "/mnt/c/workspace/my_private_config.h"
    #elif defined(WOLFSSL_CMAKE_SYSTEM_NAME_LINUX)
        #define WOLFSSL_CMAKE
        #include "~/workspace/my_private_config.h"
    #elif defined(WOLFSSL_MAKE_SYSTEM_NAME_LINUX)
        #define WOLFSSL_MAKE
        #include "~/workspace/my_private_config.h"
    #elif defined(WOLFSSL_CMAKE_SYSTEM_NAME_APPLE)
        #include "~/Documents/my_private_config.h"
    #elif defined(WOLFSSL_MAKE_SYSTEM_NAME_APPLE)
        #define WOLFSSL_MAKE
        #include "~/Documents/my_private_config.h"
    #elif defined(OS_WINDOWS)
        #include "/workspace/my_private_config.h"
    #else
        /* Edit as needed for your private config: */
        #warning "default private config using /workspace/my_private_config.h"
        #include "/workspace/my_private_config.h"
    #endif
#else

    /*
    ** The examples use WiFi configuration that you can set via project
    ** configuration menu
    **
    ** If you'd rather not, just change the below entries to strings with
    ** the config you want - ie #define EXAMPLE_WIFI_SSID "mywifissid"
    */
    #if defined(CONFIG_ESP_WIFI_SSID)
        /* tyically from ESP32 with ESP-IDF v4 or v5 */
        #define EXAMPLE_ESP_WIFI_SSID CONFIG_ESP_WIFI_SSID
    #elif defined(CONFIG_EXAMPLE_WIFI_SSID)
        /* typically from ESP8266 rtos-sdk/v3.4 */
        #undef  EXAMPLE_ESP_WIFI_SSID
        #define EXAMPLE_ESP_WIFI_SSID CONFIG_EXAMPLE_WIFI_SSID
    #else
        #define EXAMPLE_ESP_WIFI_SSID "MYSSID_WIFI_CONNECT"
    #endif

    #if defined(CONFIG_ESP_WIFI_PASSWORD)
        /* tyically from ESP32 with ESP-IDF v4 or v5 */
        #define EXAMPLE_ESP_WIFI_PASS CONFIG_ESP_WIFI_PASSWORD
    #elif defined(CONFIG_EXAMPLE_WIFI_SSID)
        /* typically from ESP8266 rtos-sdk/v3.4 */
        #undef  EXAMPLE_ESP_WIFI_PASS
        #define EXAMPLE_ESP_WIFI_PASS CONFIG_EXAMPLE_WIFI_PASSWORD
    #else
        #define EXAMPLE_ESP_WIFI_PASS "MYPASSWORD_WIFI_CONNECT"
    #endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

WOLFSSL_LOCAL esp_err_t esp_sdk_time_mem_init(void);

WOLFSSL_LOCAL esp_err_t sdk_var_whereis(const char* v_name, void* v);

WOLFSSL_LOCAL intptr_t esp_sdk_stack_pointer(void);

#if defined(USE_WOLFSSL_ESP_SDK_TIME)

/******************************************************************************
* Time helpers
******************************************************************************/
WOLFSSL_LOCAL esp_err_t esp_sdk_time_mem_init(void);

WOLFSSL_LOCAL esp_err_t esp_sdk_time_lib_init(void);

/* a function to show the current data and time */
WOLFSSL_LOCAL esp_err_t esp_show_current_datetime(void);

/* worst case, if GitHub time not available, used fixed time */
WOLFSSL_LOCAL esp_err_t set_fixed_default_time(void);

/* set time from string (e.g. GitHub commit time) */
WOLFSSL_LOCAL esp_err_t set_time_from_string(const char* time_buffer);

/* set time from NTP servers,
 * also initially calls set_fixed_default_time or set_time_from_string */
WOLFSSL_LOCAL esp_err_t set_time(void);

/* wait NTP_RETRY_COUNT seconds before giving up on NTP time */
WOLFSSL_LOCAL esp_err_t set_time_wait_for_ntp(void);
#endif

#if defined(USE_WOLFSSL_ESP_SDK_WIFI)

/******************************************************************************
* WiFi helpers
******************************************************************************/
/* ESP lwip */
#define EXAMPLE_ESP_MAXIMUM_RETRY       CONFIG_ESP_MAXIMUM_RETRY

#define TLS_SMP_WIFI_SSID                CONFIG_WIFI_SSID
#define TLS_SMP_WIFI_PASS                CONFIG_WIFI_PASSWORD

/* Optionally enable WiFi. Typically not used for wolfcrypt tests */
/* #define USE_WIFI_EXAMPLE */
#ifdef USE_WIFI_EXAMPLE
    #include "esp_netif.h"
    #if defined(CONFIG_IDF_TARGET_ESP8266)
        /* TODO find and implement ESP8266 example include */
    #else
        #include "protocol_examples_common.h" /* see project CMakeLists.txt */
    #endif
#endif


/* ESP lwip */
#define EXAMPLE_ESP_MAXIMUM_RETRY  CONFIG_ESP_MAXIMUM_RETRY

WOLFSSL_LOCAL esp_err_t esp_sdk_wifi_lib_init(void);

WOLFSSL_LOCAL esp_err_t esp_sdk_wifi_init_sta(void);

WOLFSSL_LOCAL esp_err_t esp_sdk_wifi_show_ip(void);

#endif /* USE_WOLFSSL_ESP_SDK_WIFI */

/******************************************************************************
* Debug helpers
******************************************************************************/
WOLFSSL_LOCAL esp_err_t sdk_init_meminfo(void);
WOLFSSL_LOCAL void* wc_debug_pvPortMalloc(size_t size,
                                const char* file, int line, const char* fname);

#ifdef __cplusplus
} /* extern "C" */
#endif

/* Check for traps */
#if defined(CONFIG_IDF_TARGET_ESP8266)
    #if !defined(NO_SESSION_CACHE)    && \
        !defined(MICRO_SESSION_CACHE) && \
        !defined(SMALL_SESSION_CACHE)
        #warning "Limited DRAM/IRAM on ESP8266. Check session cache settings"
    #endif
#endif

#endif /* WOLFSSL_ESPIDF */

#endif /* __ESP_SDK_LIB_H__ */
