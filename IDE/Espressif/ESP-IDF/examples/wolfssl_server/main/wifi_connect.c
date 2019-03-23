/* wifi_connect.c 
 *
 * Copyright (C) 2006-2019 wolfSSL Inc.
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
/*ESP specific */
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "wifi_connect.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/apps/sntp.h"
#include "nvs_flash.h"

const static int CONNECTED_BIT = BIT0;
static EventGroupHandle_t wifi_event_group;
/* prefix for logging */
const static char *TAG = "tls_server";
/* proto-type difinition */
extern void tls_smp_server_task();
static void tls_smp_server_init();

static void set_time()
{
    /* set dummy wallclock time. */
    struct timeval utctime;
    struct timezone tz;
    struct strftime_buf;
    time_t now;
    struct tm timeinfo;
    char strftime_buf[64];

    utctime.tv_sec = 1542008020; /* dummy time: Mon Nov 12 07:33:40 2018 */
    utctime.tv_usec = 0;
    tz.tz_minuteswest = 0;
    tz.tz_dsttime = 0;
    
    settimeofday(&utctime, &tz);

    time(&now);
    localtime_r(&now, &timeinfo);

    strftime(strftime_buf, sizeof(strftime_buf), "%c", &timeinfo);
    ESP_LOGI(TAG, "The current date/time is: %s", strftime_buf);

    /* wait until wifi connect */
    xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT,
                                            false, true, portMAX_DELAY);
    /* now we start client tasks. */
    tls_smp_server_init();
}

/* create task */
static void tls_smp_server_init(void)
{
    int ret;
    xTaskHandle _handle;
    /* http://esp32.info/docs/esp_idf/html/dd/d3c/group__xTaskCreate.html */
    ret = xTaskCreate(tls_smp_server_task,
                      TLS_SMP_SERVER_TASK_NAME,
                      TLS_SMP_SERVER_TASK_WORDS,
                      NULL,
                      TLS_SMP_SERVER_TASK_PRIORITY,
                      &_handle);

    if (ret != pdPASS) {
        ESP_LOGI(TAG, "create thread %s failed", TLS_SMP_SERVER_TASK_NAME);
    }
}
/* event hander for wifi events */
static esp_err_t wifi_event_handler(void *ctx, system_event_t *event)
{
    switch (event->event_id)
    {
    case SYSTEM_EVENT_STA_START:
        esp_wifi_connect();
        break;
    case SYSTEM_EVENT_STA_GOT_IP:
        ESP_LOGI(TAG, "got ip:%s",
                 ip4addr_ntoa(&event->event_info.got_ip.ip_info.ip));
        /* http://esp32.info/docs/esp_idf/html/dd/d08/group__xEventGroupSetBits.html */
        xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);
        break;
    case SYSTEM_EVENT_STA_DISCONNECTED:
        esp_wifi_connect();
        xEventGroupClearBits(wifi_event_group, CONNECTED_BIT);
        break;
    default:
        break;
    }
    return ESP_OK;
}
/* entry point */
void app_main(void)
{
    ESP_LOGI(TAG, "Start app_main...");
    ESP_ERROR_CHECK(nvs_flash_init());

    ESP_LOGI(TAG, "Initialize wifi");
    /* TCP/IP adapter initialization */
    tcpip_adapter_init();

    /* */
    wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_event_loop_init(wifi_event_handler, NULL));
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = TLS_SMP_WIFI_SSID,
            .password = TLS_SMP_WIFI_PASS,
        },
    };
    /* WiFi station mode */
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA) );
    /* Wifi Set the configuration of the ESP32 STA or AP */ 
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config) );
    /* Start Wifi */
    ESP_ERROR_CHECK(esp_wifi_start() );

    ESP_LOGI(TAG, "wifi_init_sta finished.");
    ESP_LOGI(TAG, "connect to ap SSID:%s password:%s",
                                        TLS_SMP_WIFI_SSID, TLS_SMP_WIFI_PASS);
    ESP_LOGI(TAG, "Set Dummy time...");
    set_time();
}
