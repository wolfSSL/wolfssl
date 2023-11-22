/* server-tls.h
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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
#ifndef _SERVER_TLS_
#define _SERVER_TLS_

#define DEFAULT_PORT                     11111

#define TLS_SMP_CLIENT_TASK_NAME         "tls_client_example"
#define TLS_SMP_CLIENT_TASK_WORDS        10240
#define TLS_SMP_CLIENT_TASK_PRIORITY     8

#define TLS_SMP_TARGET_HOST              "192.168.25.109"

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include "user_settings.h"

#if defined(SINGLE_THREADED)
    #define WOLFSSL_ESP_TASK int
#else
    #include "freertos/FreeRTOS.h"
    #define WOLFSSL_ESP_TASK void
#endif

typedef struct {
    int port;
    int loops;
} tls_args;

/* Function to show the ciphers available / in use. */
#if defined(DEBUG_WOLFSSL)
    int ShowCiphers(WOLFSSL* ssl);
#endif

/* This is the TLS Server function, possibly in an RTOS thread. */
WOLFSSL_ESP_TASK tls_smp_server_task(void *args);

/* init will create an RTOS task, otherwise server is simply function call. */
#if defined(SINGLE_THREADED)
    /* no init neded */
#else
    WOLFSSL_ESP_TASK tls_smp_server_init(void* args);
#endif
#endif /* _SERVER_TLS_ */
