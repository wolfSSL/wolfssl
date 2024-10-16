/* esp_sdk_mem_lib.c
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

/* wolfSSL */
/* Always include wolfcrypt/settings.h before any other wolfSSL file.    */
/* Be sure to define WOLFSSL_USER_SETTINGS, typically in CMakeLists.txt  */
/* Reminder: settings.h pulls in user_settings.h                         */
/*   Do not explicitly include user_settings.h here.                     */
#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_ESPIDF) /* Entire file is only for Espressif EDP-IDF */

#if defined(WOLFSSL_USER_SETTINGS)
    #include <wolfssl/wolfcrypt/types.h>
#else
    /* Define WOLFSSL_USER_SETTINGS project wide for settings.h to include   */
    /* wolfSSL user settings in ./components/wolfssl/include/user_settings.h */
    #error "Missing WOLFSSL_USER_SETTINGS in CMakeLists or Makefile:\
    CFLAGS +=-DWOLFSSL_USER_SETTINGS"
#endif

#ifndef SINGLE_THREADED
    #ifdef PLATFORMIO
        #include <freertos/semphr.h>
    #else
        #include "semphr.h"
    #endif
#endif

/* Espressif */
#include "sdkconfig.h" /* programmatically generated from sdkconfig */
#include <esp_log.h>
#include <esp_err.h>

/* wolfSSL */
#include <wolfssl/wolfcrypt/port/Espressif/esp-sdk-lib.h>

static const char* TAG = "mem lib";
static intptr_t _starting_stack_pointer = 0;
static int _stack_used = 0;


/* see
 * C:\SysGCC\esp8266\rtos-sdk\v3.4\components\esp8266\ld\esp8266.project.ld.in
 */
extern wc_ptr_t _data_start[];
extern wc_ptr_t _data_end[];
extern wc_ptr_t _rodata_start[];
extern wc_ptr_t _rodata_end[];
extern wc_ptr_t _bss_start[];
extern wc_ptr_t _bss_end[];
extern wc_ptr_t _rtc_bss_start[];
extern wc_ptr_t _rtc_bss_end[];
extern wc_ptr_t _iram_start[];
extern wc_ptr_t _iram_end[];
#if defined(CONFIG_IDF_TARGET_ESP8266)
extern wc_ptr_t _init_start[];
extern wc_ptr_t _init_end[];
#endif
extern wc_ptr_t _iram_text_start[];
extern wc_ptr_t _iram_text_end[];
#if defined(CONFIG_IDF_TARGET_ESP32S2)
    /* TODO: Find ESP32-S2 equivalent */
#else
    extern wc_ptr_t _iram_bss_start[];
    extern wc_ptr_t _iram_bss_end[];
#endif
extern wc_ptr_t _noinit_start[];
extern wc_ptr_t _noinit_end[];
extern wc_ptr_t _text_start[];
extern wc_ptr_t _text_end[];
extern wc_ptr_t _heap_start[];
extern wc_ptr_t _heap_end[];
#ifdef CONFIG_IDF_TARGET_ESP32C2
    /* no rtc_data on ESP32-C2*/
#else
    extern wc_ptr_t _rtc_data_start[];
    extern wc_ptr_t _rtc_data_end[];
#endif

#if defined(CONFIG_IDF_TARGET_ARCH_XTENSA) && CONFIG_IDF_TARGET_ARCH_XTENSA == 1
    extern void* _thread_local_start;
    extern void* _thread_local_end;
#endif

/* See https://github.com/esp8266/esp8266-wiki/wiki/Memory-Map */
#define MEM_MAP_IO_START  ((void*)(0x3FF00000))
#define MEM_MAP_IO_END    ((void*)(0x3FF0FFFF))
#define USER_DATA_START   ((void*)(0x3FFE8000))
#define USER_DATA_END     ((void*)(0x3FFE8000 + 0x14000))
#define ETS_SYS_START     ((void*)(0x3FFFC000))
#define ETS_SYS_END       ((void*)(0x3FFFC000 + 0x4000))
#define IRAM1_START       ((void*)(0x40100000))
#define IRAM1_END         ((void*)(0x40100000 + 0x8000))
#define IRAMF1_START      ((void*)(0x40108000))
#define IRAMF1_END        ((void*)(0x40108000 + 0x4000))
#define IRAMF2_START      ((void*)(0x4010C000))
#define IRAMF2_END        ((void*)(0x4010C000 + 0x4000))

enum sdk_memory_segment
{
    /* Ensure this list exactly matches order in sdk_memory_segment_text */
    mem_map_io = 0,
    thread_local,
    data,
    user_data_ram,
    bss,
    noinit,
    ets_system,
    iram1,
    iramf1,
    iramf2,
    iram,
    iram_text,
    iram_bss,
    init,
    text,
    rodata,
    rtc_data,
    SDK_MEMORY_SEGMENT_COUNT
};

static void*      sdk_memory_segment_start[SDK_MEMORY_SEGMENT_COUNT + 1] = {};
static void*        sdk_memory_segment_end[SDK_MEMORY_SEGMENT_COUNT + 1] = {};
static const char* sdk_memory_segment_text[SDK_MEMORY_SEGMENT_COUNT + 1] = {
    "C memory map io ",
    "* thread_local  ",
    "C data          ",
    "* user data ram ",
    "* bss           ",
    "* noinit        ",
    "C ets system    ",
    "C iram1         ",
    "C iramf1        ",
    "C iramf2        ",
    "* iram          ",
    "* iram_text     ",
    "* iram_bss      ",
    "* init          ",
    "* text          ",
    "* rodata        ",
    "* rtc data      ",
    "last item",
};

/* Given a given memory segment [m]: assign text names, starting and ending
 * addresses. See also sdk_var_whereis() that requires this initialization. */
int sdk_log_meminfo(enum sdk_memory_segment m, void* start, void* end)
{
    const char* str;
    word32 len = 0;
    str = sdk_memory_segment_text[m];
    sdk_memory_segment_start[m] = start;
    sdk_memory_segment_end[m] = end;
    /* For ESP8266 See ./build/[Debug|Release]/esp8266/esp8266.project.ld */
    /* For ESP32   See ./build/VisualGDB/Debug/esp-idf/esp_system/ld/     */
    if (m == SDK_MEMORY_SEGMENT_COUNT) {
        ESP_LOGI(TAG, "                    Linker Memory Map");
        ESP_LOGI(TAG, "-----------------------------------------------------");
        ESP_LOGI(TAG, "                  Start         End          Length");
    }
    else {
        len = (word32)end - (word32)start;
        ESP_LOGI(TAG, "%s: %p ~ %p : 0x%05x (%d)", str, start, end, len, len );
    }
    return ESP_OK;
}

/* Show all known linker memory segment names, starting & ending addresses. */
int sdk_init_meminfo(void) {
    void* sample_heap_var;
    int sample_stack_var = 0;

    sdk_log_meminfo(SDK_MEMORY_SEGMENT_COUNT, NULL, NULL); /* print header */
    sdk_log_meminfo(mem_map_io,    MEM_MAP_IO_START,    MEM_MAP_IO_END);
#if defined(CONFIG_IDF_TARGET_ARCH_XTENSA) && CONFIG_IDF_TARGET_ARCH_XTENSA == 1
    sdk_log_meminfo(thread_local,  _thread_local_start, _thread_local_end);
#endif
    sdk_log_meminfo(data,          _data_start,         _data_end);
    sdk_log_meminfo(user_data_ram, USER_DATA_START,     USER_DATA_END);
#if defined(CONFIG_IDF_TARGET_ESP32S2)
    /* TODO: Find ESP32-S2 equivalent of bss */
#else
    sdk_log_meminfo(bss,           _bss_start,          _bss_end);
#endif
    sdk_log_meminfo(noinit,        _noinit_start,       _noinit_end);
    sdk_log_meminfo(ets_system,    ETS_SYS_START,       ETS_SYS_END);
    sdk_log_meminfo(rodata,        _rodata_start,       _rodata_end);
    sdk_log_meminfo(iram1,         IRAM1_START,         IRAM1_END);
    sdk_log_meminfo(iramf1,        IRAMF1_START,        IRAMF1_END);
    sdk_log_meminfo(iramf2,        IRAMF2_START,        IRAMF2_END);
    sdk_log_meminfo(iram,          _iram_start,         _iram_end);
    sdk_log_meminfo(iram_text,     _iram_text_start,    _iram_text_end);
#if defined(CONFIG_IDF_TARGET_ESP32S2)
    /* No iram_bss on ESP32-C2 at this time. TODO: something equivalent? */
#else
    sdk_log_meminfo(iram_bss,      _iram_bss_start,     _iram_bss_end);
#endif
#if defined(CONFIG_IDF_TARGET_ESP8266)
    sdk_log_meminfo(init,          _init_start,         _init_end);
#endif
    sdk_log_meminfo(text,          _text_start,         _text_end);
#if defined(CONFIG_IDF_TARGET_ESP32C2)
    /* No rtc_data on ESP32-C2 at this time. TODO: something equivalent? */
#else
    sdk_log_meminfo(rtc_data,      _rtc_data_start,     _rtc_data_end);
#endif
    ESP_LOGI(TAG, "-----------------------------------------------------");
    sample_heap_var = malloc(1);
    if (sample_heap_var == NULL) {
        ESP_LOGE(TAG, "Unable to allocate heap memory in sdk_var_whereis().");
    }
    else {
        sdk_var_whereis("sample_stack_var", (void*)&sample_stack_var);
        sdk_var_whereis("sample_heap_var", sample_heap_var);
        free(sample_heap_var);
    }
    return ESP_OK;
}

/* Returns ESP_OK if found in known memory map, ESP_FAIL otherwise */
esp_err_t sdk_var_whereis(const char* v_name, void* v) {
    esp_err_t ret = ESP_FAIL;

    for (enum sdk_memory_segment m = 0 ;m < SDK_MEMORY_SEGMENT_COUNT; m++) {
        if (v >= sdk_memory_segment_start[m] &&
            v <= sdk_memory_segment_end[m]) {
                ret = ESP_OK;
                ESP_LOGI(TAG, "Variable [%s] found at %p in %s", v_name, v,
                              sdk_memory_segment_text[m]);
                if (m == user_data_ram) {

                }
            }
    }

    if (ret == ESP_FAIL) {
        ESP_LOGW(TAG, "%s not found in known memory map: %p", v_name, v);
    }
    return ret;
}

intptr_t esp_sdk_stack_pointer(void)
{
    intptr_t sp = 0;
#if defined(CONFIG_IDF_TARGET_ARCH_RISCV)
    if (CONFIG_IDF_TARGET_ARCH_RISCV == 1) {
        __asm volatile("mv %0, sp" : "=r" (sp));
    }
#elif defined(CONFIG_IDF_TARGET_ARCH_XTENSA)
    if (CONFIG_IDF_TARGET_ARCH_XTENSA == 1) {
        __asm volatile("mov %0, sp" : "=r"(sp));
    }
#endif
    if (_starting_stack_pointer == 0) {
        _starting_stack_pointer = sp;
    }
    _stack_used = _starting_stack_pointer - sp;
    return sp;
}

esp_err_t esp_sdk_mem_lib_init(void)
{
    int ret = ESP_OK;
    sdk_init_meminfo();
    ESP_LOGI(TAG, "esp_sdk_mem_lib_init Ver %d", ESP_SDK_MEM_LIB_VERSION);
    return ret;
}

void* wc_debug_pvPortMalloc(size_t size,
                           const char* file, int line, const char* fname) {
    void* ret = NULL;
    ret = pvPortMalloc(size);
    if (ret == NULL) {
        ESP_LOGE("malloc", "%s:%d (%s)", file, line, fname);
        ESP_LOGE("malloc", "Failed Allocating memory of size: %d bytes", size);
    }
    return ret;
}

#endif
