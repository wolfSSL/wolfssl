/* esp_log.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

/* Host stub for test_esp_crt_bundle.c: all ESP log levels go to
 * test_log(), which keeps them for the test to check. */
#ifndef TEST_ESP_LOG_H
#define TEST_ESP_LOG_H

typedef int esp_err_t;
#define ESP_OK                0
#define ESP_FAIL              (-1)
#define ESP_ERR_NO_MEM        0x101
#define ESP_ERR_INVALID_ARG   0x102
#define ESP_ERR_INVALID_STATE 0x103
#define ESP_ERR_INVALID_SIZE  0x104
#define ESP_ERR_NOT_FOUND     0x105

int test_log(char level, const char* tag, const char* fmt, ...)
    __attribute__((format(printf, 3, 4)));

#define ESP_LOGE(tag, ...) test_log('E', tag, __VA_ARGS__)
#define ESP_LOGW(tag, ...) test_log('W', tag, __VA_ARGS__)
#define ESP_LOGI(tag, ...) test_log('I', tag, __VA_ARGS__)
#define ESP_LOGD(tag, ...) test_log('D', tag, __VA_ARGS__)
#define ESP_LOGV(tag, ...) test_log('V', tag, __VA_ARGS__)

static inline unsigned esp_get_free_heap_size(void) { return 0; }
static inline unsigned esp_get_minimum_free_heap_size(void) { return 0; }

#endif /* TEST_ESP_LOG_H */
