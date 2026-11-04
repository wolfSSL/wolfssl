/* cmsis_os.h
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

/* Stub CMSIS-RTOS v1 header for the thread-types reproducer: only the types
 * wolfSSL's headers name. */
#ifndef WOLFSSL_REPRO_CMSIS_OS_H
#define WOLFSSL_REPRO_CMSIS_OS_H

typedef struct os_mutex_cb* osMutexId;
typedef struct os_thread_cb* osThreadId;
typedef struct os_mutex_def {
    void* cb;
} osMutexDef_t;

#endif
