/* esp_sdk_mem_lib.c
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
#ifdef CONFIG_IDF_TARGET_ESP8266
    #include <esp_system.h>
#else
    #include <freertos/FreeRTOS.h>
    #include <freertos/task.h>
#endif

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

#ifdef WOLFSSL_HAVE_LINKER_REGION_PEEK
    /* cmake may have found a ld/region_peek.ld helper file */
    extern wc_ptr_t __dram0_start[]   __attribute__((weak));
    extern wc_ptr_t __dram0_end[]     __attribute__((weak));
    extern wc_ptr_t __drom0_start[]   __attribute__((weak));
    extern wc_ptr_t __drom0_end[]     __attribute__((weak));

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
    #define DRAM0_START        __dram0_start
    #define DRAM0_END          __dram0_end
    #define DROM0_START        __drom0_start
    #define DROM0_END          __drom0_end
#else
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
#endif
#if 0
    /* Optional Stack Debugging */
    extern void *xPortSupervisorStackPointer;
#endif

enum sdk_memory_segment
{
    /* Ensure this list exactly matches order in sdk_memory_segment_text */
    mem_map_io = 0,
    thread_local_mem,
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
    dram_org,
    drom_org,
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
    "C dram_org      ",
    "C drom_org      ",
    "last item",
};

/* Given a given memory segment [m]: assign text names, starting and ending
 * addresses. See also sdk_var_whereis() that requires this initialization. */
int sdk_log_meminfo(enum sdk_memory_segment m, void* start, void* end)
{
    const char* str;
    size_t len = 0;
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
        if (end == NULL) {
            /* The weak attribute: linker probably didn't find a value */
            len = 0;
            ESP_LOGV(TAG, "Value not found for: %s", str);
        }
        else {
            len = (size_t)end - (size_t)start;
            ESP_LOGI(TAG, "%s: %p ~ %p : 0x%05x (%d)",
                          str, start, end, len, len );
        }
    }

    return ESP_OK;
}

/* Show all known linker memory segment names, starting & ending addresses. */
int sdk_init_meminfo(void)
{
    void* sample_heap_var;
    int sample_stack_var = 0;

    sdk_log_meminfo(SDK_MEMORY_SEGMENT_COUNT, NULL, NULL); /* print header */
    sdk_log_meminfo(mem_map_io,    MEM_MAP_IO_START,    MEM_MAP_IO_END);
#if defined(CONFIG_IDF_TARGET_ARCH_XTENSA) && CONFIG_IDF_TARGET_ARCH_XTENSA == 1
    sdk_log_meminfo(thread_local_mem,  _thread_local_start, _thread_local_end);
#endif
    sdk_log_meminfo(data,          _data_start,         _data_end);
    sdk_log_meminfo(user_data_ram, USER_DATA_START,     USER_DATA_END);
#if defined(CONFIG_IDF_TARGET_ESP32S2)
    /* TODO: Find ESP32-S2 equivalent of bss */
#else
    sdk_log_meminfo(bss,           _bss_start,          _bss_end);
#endif
#if defined(WOLFSSL_HAVE_LINKER_REGION_PEEK)
    sdk_log_meminfo(dram_org,      DRAM0_START,         DRAM0_END);
    sdk_log_meminfo(drom_org,      DROM0_START,         DROM0_END);
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
esp_err_t sdk_var_whereis(const char* v_name, void* v)
{
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

static size_t free_heap        = 0; /* current free heap */
static size_t min_free_heap    = 0; /* current minumim heap size */
static size_t min_x_free_heap  = 0; /* smallest seen free_heap  */
static size_t max_x_free_heap  = 0; /* largest seen free_heap */

static size_t last_free_heap   = 0; /* prior         esp_get_free_heap_size */
static size_t last_min_heap    = 0; /* prior esp_get_minimum_free_heap_size */
static size_t heap_peek_ct     = 0;
static size_t stack_hwm        = 0;
static size_t min_stack_hwm    = 0;
static size_t max_stack_hwm    = 0;

static heap_track_reset_t heap_reset_reason = HEAP_TRACK_RESET_NONE;

static size_t largest_allocable(size_t limit) {
    size_t lo = 0, hi = limit, best = 0;
    while (lo <= hi) {
        size_t mid = (lo + hi) / 2;
        void *p = malloc(mid);
        if (p) {
            free(p);
            best = mid;
            lo = mid + 1;
        }
        else {
            hi = (mid == 0 ? 0 : mid - 1);
        }
    }
    return best;
}

static size_t largest_allocable_wolf(size_t limit)
{
    size_t best = 0;
#ifdef WOLFSSL_NO_MALLOC
    #ifdef DEBUG_WOLFSSL
        ESP_LOGE(TAG, "Error: largest_allocable_wolf called with no malloc");
    #endif
#else
    size_t lo;
    size_t hi;
    void* (*mc)(size_t);
    void  (*fc)(void*);
    void* (*rc)(void*, size_t);

    mc = NULL;
    fc = NULL;
    rc = NULL;
    wolfSSL_GetAllocators(&mc, &fc, &rc);

    /* Fallback: if no custom allocators are set, use system malloc/free. */
    if (mc == NULL) {
        mc = malloc;
    }
    if (fc == NULL) {
        fc = free;
    }

    lo = 0;
    hi = limit;
    best = 0;

    while (lo <= hi) {
        size_t mid = (lo + hi) / 2;
        void* p = mc(mid);
        if (p != NULL) {
            fc(p);
            best = mid;
            lo = mid + 1;
        }
        else {
            hi = (mid == 0 ? 0 : mid - 1);
        }
    }
#endif
    return best;
}

static esp_err_t esp_sdk_stack_info(heap_track_reset_t reset)
{
    int ret = ESP_OK;
    const char* this_task;
    size_t max_alloc = 0;

    max_alloc = largest_allocable(10 * 1024);
    ESP_LOGI(TAG, "max_alloc = %d", max_alloc);

    max_alloc = largest_allocable_wolf(12 * 1024);
    ESP_LOGI(TAG, "max_alloc wolf = %d", max_alloc);
#ifdef CONFIG_IDF_TARGET_ESP8266
     /* words not bytes! */
    stack_hwm = uxTaskGetStackHighWaterMark(NULL) * sizeof(StackType_t);
    if (min_stack_hwm == 0) {
        min_stack_hwm = stack_hwm;
    }
    if (stack_hwm < min_stack_hwm) {
        ESP_LOGW(TAG, "New min high watermark:   %u bytes, delta = %d",
                                 min_stack_hwm, stack_hwm - min_stack_hwm);
        min_stack_hwm = stack_hwm;
    }
    if (stack_hwm > max_stack_hwm) {
        ESP_LOGW(TAG, "New max high watermark:   %u bytes, delta = %d",
                                 max_stack_hwm, stack_hwm - max_stack_hwm);
        max_stack_hwm = stack_hwm;
    }
    this_task = "ESP8266";
#elif defined(CONFIG_FREERTOS_USE_TRACE_FACILITY)
    TaskStatus_t status;
    vTaskGetInfo(NULL, &status, pdTRUE, eInvalid);
    stack_hwm = (unsigned)status.usStackHighWaterMark;
    if (status.pcTaskName == NULL || status.pcTaskName[0] == '\0') {
        this_task = "unknown";
        ret = ESP_FAIL;
    }
    else {
        this_task = status.pcTaskName;
    }
#else
    this_task = "unknown";
    ESP_LOGW(TAG, "vTaskGetInfo not available");
#endif

    ESP_LOGI(TAG, "Task: %s, High watermark: %u bytes", this_task, stack_hwm);
    ESP_LOGI(TAG, "Min high watermark:      %u bytes", min_stack_hwm);
    ESP_LOGI(TAG, "Max high watermark:      %u bytes", max_stack_hwm);
    return ret;
} /*  esp_sdk_stack_info */

static esp_err_t esp_sdk_heap_info(heap_track_reset_t reset)
{
    int ret = ESP_OK;

    if (reset != HEAP_TRACK_RESET_NONE) {
        free_heap        = 0;
        min_free_heap    = 0;
        min_x_free_heap  = 0;
        max_x_free_heap  = 0;

        last_free_heap   = 0;
        last_min_heap    = 0;
        heap_peek_ct     = 0;
        heap_reset_reason = reset;
    } /* heap track metric reset */
    heap_peek_ct++;

#ifdef CONFIG_IDF_TARGET_ESP8266
    free_heap     = (unsigned)esp_get_free_heap_size();
    min_free_heap = (unsigned)esp_get_minimum_free_heap_size();
#else
    free_heap     = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
    min_free_heap = heap_caps_get_minimum_free_size(MALLOC_CAP_DEFAULT);
#endif
    if (last_free_heap > 0) {

        if (last_free_heap != free_heap) {
            ESP_LOGW(TAG, "LAST free heap:          %u bytes, delta = %d",
                           last_free_heap,    free_heap - last_free_heap);
        }
        if (free_heap < min_x_free_heap) {
            min_x_free_heap = free_heap;
            ESP_LOGW(TAG, "New min ever free heap   %u bytes", min_x_free_heap);
        }
        if (free_heap > max_x_free_heap) {
            max_x_free_heap = free_heap;
            ESP_LOGW(TAG, "New max ever free heap:  %u bytes", max_x_free_heap);
        }
    }
    else {
        min_x_free_heap = free_heap;
        max_x_free_heap = free_heap;
    }

    if ((last_min_heap > 0) && (last_min_heap != min_free_heap)) {
        ESP_LOGW(TAG, "LAST minimum free heap:  %u bytes", last_min_heap);
    }

    ESP_LOGI(TAG, "Current free heap:       %u bytes", free_heap);
    ESP_LOGI(TAG, "Minimum free heap:       %u bytes", min_free_heap);
    ESP_LOGI(TAG, "Minimum ever free heap:  %u bytes", min_x_free_heap);
    ESP_LOGI(TAG, "Maximum ever free heap:  %u bytes", max_x_free_heap);

    /* Save current values for next query */
    last_free_heap = free_heap;
    last_min_heap = min_free_heap;

    return ret;
} /* esp_sdk_heap_info */

esp_err_t esp_sdk_stack_heap_info(heap_track_reset_t reset)
{
    int ret = ESP_OK;
    ret = esp_sdk_heap_info(reset) +
          esp_sdk_stack_info(reset);
    if (ret != ESP_OK) {
        ret = ESP_FAIL;
    }
    return ret;
}

#if defined(DEBUG_WOLFSSL_MALLOC) || defined(DEBUG_WOLFSSL)
void* wc_debug_pvPortMalloc(size_t size,
                           const char* file, int line, const char* fname)
#else
void* wc_pvPortMalloc(size_t size)
#endif
{
    void* ret = NULL;
#ifdef WOLFSSL_NO_MALLOC
    #ifdef DEBUG_WOLFSSL
        ESP_LOGE(TAG, "Error: wc_pvPortMalloc called with no malloc");
    #endif
#else
    wolfSSL_Malloc_cb  mc;
    wolfSSL_Free_cb    fc;
    wolfSSL_Realloc_cb rc;
    wolfSSL_GetAllocators(&mc, &fc, &rc);

    if (mc == NULL) {
        ret = pvPortMalloc(size);
    }
    else {
#if defined(USE_WOLFSSL_MEMORY) && !defined(NO_WOLFSSL_MEMORY)
        ret = mc(size);
#else
        ret = pvPortMalloc(size);
#endif
    }
#endif
#if defined(DEBUG_WOLFSSL_MALLOC) || defined(DEBUG_WOLFSSL)
    if (ret == NULL) {
        ESP_LOGE("malloc", "%s:%d (%s)", file, line, fname);
        ESP_LOGE("malloc", "Failed Allocating memory of size: %d bytes", size);
    }
#ifdef DEBUG_WOLFSSL_MALLOC_VERBOSE
    else {
        ESP_LOGI("malloc", "%s:%d (%s)", file, line, fname);
        ESP_LOGI("malloc", "Allocate memory at %p of size: %d bytes", ret, size);
    }
#endif /* DEBUG_WOLFSSL_MALLOC_VERBOSE */
#endif
    return ret;
} /* wc_debug_pvPortMalloc */

#if defined(DEBUG_WOLFSSL_MALLOC) || defined(DEBUG_WOLFSSL)
void wc_debug_pvPortFree(void *ptr,
                        const char* file, int line, const char* fname)
#else
void wc_pvPortFree(void *ptr)
#endif
{
#ifdef WOLFSSL_NO_MALLOC
    #ifdef DEBUG_WOLFSSL
        ESP_LOGE(TAG, "Error: wc_pvPortFree called with no malloc");
    #endif
#else
    wolfSSL_Malloc_cb  mc;
    wolfSSL_Free_cb    fc;
    wolfSSL_Realloc_cb rc;
    if (ptr == NULL) {
#ifdef DEBUG_WOLFSSL_MALLOC
        /* It's ok to free a null pointer, and that happens quite frequently */
#endif
    }
    else {
#ifdef DEBUG_WOLFSSL_MALLOC_VERBOSE
        ESP_LOGI("malloc", "free %p %s:%d (%s)", ptr, file, line, fname);
#endif
        wolfSSL_GetAllocators(&mc, &fc, &rc);

        if (fc == NULL) {
            vPortFree(ptr);
        }
        else {
#if defined(USE_WOLFSSL_MEMORY) && !defined(NO_WOLFSSL_MEMORY)
            fc(ptr);
#else
            vPortFree(ptr);
#endif
        }
    }
#endif /* WOLFSSL_NO_MALLOC check */
} /* wc_debug_pvPortFree */

#ifndef WOLFSSL_NO_REALLOC
/* see XREALLOC(p, n, h, t) */
#if defined(DEBUG_WOLFSSL_MALLOC) || defined(DEBUG_WOLFSSL)
void* wc_debug_pvPortRealloc(void* ptr, size_t size,
                             const char* file, int line, const char* fname)
#else
void* wc_pvPortRealloc(void* ptr, size_t size)
#endif
{
    void* ret = NULL;
#ifdef WOLFSSL_NO_MALLOC
    #ifdef DEBUG_WOLFSSL
        ESP_LOGE(TAG, "Error: wc_pvPortRealloc called with no malloc");
    #endif
#else
    wolfSSL_Malloc_cb  mc;
    wolfSSL_Free_cb    fc;
    wolfSSL_Realloc_cb rc;
    wolfSSL_GetAllocators(&mc, &fc, &rc);

    if (mc == NULL) {
        ret = realloc(ptr, size);
    }
    else {
#if defined(USE_WOLFSSL_MEMORY) && !defined(NO_WOLFSSL_MEMORY)
        if (rc != NULL) {
            ret = rc(ptr, size); /* (void *ptr, size_t size) */
        }
        else {
            ret = realloc(ptr, size);
        }
#else
        ret = realloc(ptr, size);
#endif
    }

#if defined(DEBUG_WOLFSSL_MALLOC) || defined(DEBUG_WOLFSSL)
    if (ret == NULL) {
        ESP_LOGE("realloc", "%s:%d (%s)", file, line, fname);
        ESP_LOGE("realloc", "Failed Re-allocating memory of size: %d bytes",
                                                                  size);
    }
#endif /* debug */
#endif /* WOLFSSL_NO_MALLOC check */
    return ret;
} /* wc_debug_pvPortRealloc */
#endif /* WOLFSSL_NO_REALLOC */

#endif
