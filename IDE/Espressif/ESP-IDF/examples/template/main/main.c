/* main.c
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

/* Espressif */
#include <esp_log.h>

/* wolfSSL */
/* Always include wolfcrypt/settings.h before any other wolfSSL file.    */
/* Reminder: settings.h pulls in user_settings.h; don't include it here. */
#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
    #ifndef WOLFSSL_ESPIDF
        #warning "Problem with wolfSSL user_settings."
        #warning "Check components/wolfssl/include"
    #endif
    #include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>
#else
    /* Define WOLFSSL_USER_SETTINGS project wide for settings.h to include   */
    /* wolfSSL user settings in ./components/wolfssl/include/user_settings.h */
    #error "Missing WOLFSSL_USER_SETTINGS in CMakeLists or Makefile:\
    CFLAGS +=-DWOLFSSL_USER_SETTINGS"
#endif


/* project */
#include "main.h"

static const char* const TAG = "My Project";

void app_main(void)
{
#ifdef WOLFSSL_ESPIDF_VERBOSE_EXIT_MESSAGE
    int ret = 0;
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
