/* client-tls.h
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
#ifndef _CLIENT_TLS_H_
#define _CLIENT_TLS_H_

/* Local project, auto-generated configuration */
#include "sdkconfig.h"

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

/* See main/Kconfig.projbuild for default configuration settings */
#ifdef CONFIG_WOLFSSL_TARGET_HOST
    #define TLS_SMP_TARGET_HOST         "192.168.1.36"
#else
    #define TLS_SMP_TARGET_HOST         "192.168.1.41"
#endif

#ifdef CONFIG_WOLFSSL_TARGET_PORT
    #define TLS_SMP_DEFAULT_PORT        CONFIG_WOLFSSL_TARGET_PORT
#else
    #define TLS_SMP_DEFAULT_PORT        11111
#endif

#define TLS_SMP_CLIENT_TASK_NAME        "tls_client_example"

/* Reminder: Vanilla FreeRTOS is words, Espressif is bytes. */
#if defined(WOLFSSL_ESP8266)
    #if defined(WOLFSSL_HAVE_KYBER)
        /* Minimum ESP8266 stack size = 10K with Kyber.
         * Note there's a maximum not far away as Kyber needs heap
         * and the total DRAM is typically only 80KB total. */
        #define TLS_SMP_CLIENT_TASK_BYTES (11 * 1024)
    #else
        /* Minimum ESP8266 stack size = 6K without Kyber */
        #define TLS_SMP_CLIENT_TASK_BYTES (6 * 1024)
    #endif
#else
    #if defined(WOLFSSL_HAVE_KYBER)
        /* Minimum ESP32 stack size = 12K with Kyber enabled. */
        #define TLS_SMP_CLIENT_TASK_BYTES (12 * 1024)
    #else
        /* Minimum ESP32 stack size = 8K without Kyber */
        #define TLS_SMP_CLIENT_TASK_BYTES (8 * 1024)
    #endif
#endif

#define TLS_SMP_CLIENT_TASK_PRIORITY    8

#if defined(SINGLE_THREADED)
    #define WOLFSSL_ESP_TASK int
#else
    #include <freertos/FreeRTOS.h>
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

/* This is the TLS Client function, possibly in an RTOS thread. */
WOLFSSL_ESP_TASK tls_smp_client_task(void* args);

/* init will create an RTOS task, otherwise server is simply function call. */
#if defined(SINGLE_THREADED)
    /* no init neded */
#else
    WOLFSSL_ESP_TASK tls_smp_client_init(void* args);
#endif

#endif /* _SERVER_TLS_ */
