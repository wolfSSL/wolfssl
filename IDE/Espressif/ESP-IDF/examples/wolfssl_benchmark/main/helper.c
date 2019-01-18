/* helper.c
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfcrypt/benchmark/benchmark.h>

#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "nvs_flash.h"

#define WOLFSSL_BENCH_ARGV                 CONFIG_BENCH_ARGV
#define WOLFSSLBENCHMARK_TASK_NAME         "wolfsslbenchmark_name"
#define WOLFSSLBENCHMARK_TASK_WORDS        10240
#define WOLFSSLBENCHMARK_TASK_PRIORITY     8

/* proto-type */
extern void wolf_benchmark_task();

static const char* const TAG = "wolfbenchmark";

char* __argv[22];

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

    for(i=0;i<ATECC_MAX_SLOT; i++) {
        mSlotList[i] = ATECC_INVALID_SLOT;
    }
}

/* allocate slot depending on slotType */
int my_atmel_alloc(int slotType)
{
    int i, slot = -1;
 
    ESP_LOGI(TAG, "Enter my_atmel_alloc");

    switch(slotType){
        case ATMEL_SLOT_ENCKEY:
            slot = 4;
            break;
        case ATMEL_SLOT_DEVICE:
            slot = 0;
            break;
        case ATMEL_SLOT_ECDHE:
            slot = 2;
            break;
        case ATMEL_SLOT_ECDHE_ENC:
            slot = 4;
            break;
        case ATMEL_SLOT_ANY:
            for(i=0;i<ATECC_MAX_SLOT;i++){
                if(mSlotList[i] == ATECC_INVALID_SLOT){
                    slot = i;
                    break;
                }
            }
    }

    ESP_LOGI(TAG, "Leave my_atmel_alloc\n");

    return slot;
}

/* free slot array       */
void my_atmel_free(int slotId)
{
    ESP_LOGI(TAG, "Enter my_atmel_alloc");
    
    if(slotId >= 0 && slotId <= ATECC_MAX_SLOT){
        mSlotList[slotId] = ATECC_INVALID_SLOT;
    }
    
    ESP_LOGI(TAG, "Leave my_atmel_alloc");

}

#endif /* CUSTOM_SLOT_ALLOCATION                                       */
#endif /* WOLFSSL_ESPWROOM32SE && HAVE_PK_CALLBACK && WOLFSSL_ATECC508A */

int construct_argv()
{
    int cnt = 0;
    int i = 0;
    int len = 0;
    char *_argv;            /* buffer for copying the string    */
    char *ch;               /* char pointer to trace the string */
    char buff[16] = { 0 };  /* buffer for a argument copy       */

    printf("arg:%s\n", CONFIG_BENCH_ARGV);
    len = strlen(CONFIG_BENCH_ARGV);
    _argv = (char*)malloc(len + 1);
    if (!_argv) {
        return -1;
    }
    memset(_argv, 0, len+1);
    memcpy(_argv, CONFIG_BENCH_ARGV, len);
    _argv[len] = '\0';
    ch = _argv;

    __argv[cnt] = malloc(10);
    sprintf(__argv[cnt], "benchmark");
    __argv[9] = '\0';
    cnt = 1;

    while (*ch != '\0')
    {
        /* skip white-space */
        while (*ch == ' ') { ++ch; }

        memset(buff, 0, sizeof(buff));
        /* copy each args into buffer */
        i = 0;
        while ((*ch != ' ') && (*ch != '\0') && (i < 16)) {
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

/* entry point */
void app_main(void)
{
    ESP_LOGI(TAG, "Start app_main...");
    ESP_ERROR_CHECK(nvs_flash_init());

#ifndef NO_CRYPT_BENCHMARK

    /* when using atecc608a on esp32-wroom-32se */
#if defined(WOLFSSL_ESPWROOM32SE) && defined(HAVE_PK_CALLBACKS) \
                                  && defined(WOLFSSL_ATECC508A)
    #if defined(CUSTOM_SLOT_ALLOCATION)
    ESP_LOGI(TAG, "register callback for slot allocation");
    my_atmel_slotInit();
    /* to register the callback, it needs to be initialized. */
    benchmark_init();
    atmel_set_slot_allocator(my_atmel_alloc, my_atmel_free);
    #endif
#endif
    
    ESP_LOGI(TAG, "Start benchmark..");
    wolf_benchmark_task();

#else
    ESP_LOGI(TAG, "no crypt benchmark");

#endif /* NO_CRYPT_BENCHMARK */

}

