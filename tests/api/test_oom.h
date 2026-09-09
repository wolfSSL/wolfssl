/* test_oom.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 */

/* Shared OOM (out-of-memory) fault-injection callback generator for tests
 * that register with wolfSSL_SetAllocators() to fail a chosen allocation
 * and verify clean error handling. */

#ifndef WOLFSSL_TESTS_API_TEST_OOM_H
#define WOLFSSL_TESTS_API_TEST_OOM_H

/* Defines PREFIX##_active, PREFIX##_count, PREFIX##_fail_at and
 * PREFIX##_failed counters, plus PREFIX##_malloc_cb/_free_cb/_realloc_cb
 * callbacks suitable for wolfSSL_SetAllocators().
 *
 * While PREFIX##_active is set, the PREFIX##_fail_at'th allocation (1-based;
 * 0 disables injection) fails and latches PREFIX##_failed. The caller resets
 * PREFIX##_count/_fail_at/_failed and toggles PREFIX##_active around the
 * code path under test - see test_asn.c / test_mldsa.c for the pattern. */
#ifdef WOLFSSL_DEBUG_MEMORY
#define WOLFSSL_TEST_OOM_CALLBACKS(PREFIX)                                   \
static int PREFIX##_active = 0;                                             \
static int PREFIX##_count = 0;                                              \
static int PREFIX##_fail_at = 0;                                            \
static int PREFIX##_failed = 0;                                             \
                                                                              \
static void* PREFIX##_malloc_cb(size_t size, const char* func,              \
    unsigned int line)                                                      \
{                                                                            \
    (void)func;                                                             \
    (void)line;                                                             \
    if (PREFIX##_active) {                                                  \
        PREFIX##_count++;                                                   \
        if ((PREFIX##_fail_at != 0) &&                                      \
                (PREFIX##_count == PREFIX##_fail_at)) {                     \
            PREFIX##_failed = 1;                                            \
            return NULL;                                                    \
        }                                                                   \
    }                                                                       \
    return malloc(size);                                                    \
}                                                                            \
                                                                              \
static void PREFIX##_free_cb(void* ptr, const char* func, unsigned int line)\
{                                                                            \
    (void)func;                                                             \
    (void)line;                                                             \
    free(ptr);                                                              \
}                                                                            \
                                                                              \
static void* PREFIX##_realloc_cb(void* ptr, size_t size, const char* func,  \
    unsigned int line)                                                      \
{                                                                            \
    (void)func;                                                             \
    (void)line;                                                             \
    return realloc(ptr, size);                                              \
}
#else
#define WOLFSSL_TEST_OOM_CALLBACKS(PREFIX)                                   \
static int PREFIX##_active = 0;                                             \
static int PREFIX##_count = 0;                                              \
static int PREFIX##_fail_at = 0;                                            \
static int PREFIX##_failed = 0;                                             \
                                                                              \
static void* PREFIX##_malloc_cb(size_t size)                                \
{                                                                            \
    if (PREFIX##_active) {                                                  \
        PREFIX##_count++;                                                   \
        if ((PREFIX##_fail_at != 0) &&                                      \
                (PREFIX##_count == PREFIX##_fail_at)) {                     \
            PREFIX##_failed = 1;                                            \
            return NULL;                                                   \
        }                                                                   \
    }                                                                       \
    return malloc(size);                                                    \
}                                                                            \
                                                                              \
static void PREFIX##_free_cb(void* ptr)                                     \
{                                                                            \
    free(ptr);                                                              \
}                                                                            \
                                                                              \
static void* PREFIX##_realloc_cb(void* ptr, size_t size)                    \
{                                                                            \
    return realloc(ptr, size);                                              \
}
#endif /* WOLFSSL_DEBUG_MEMORY */

#endif /* WOLFSSL_TESTS_API_TEST_OOM_H */
