/*
 *  wolfCrypt test application
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
 *
 *
 * This application runs a series of tests from the wolfCrypt library to
 * ensure the algorithms execute as expected. The compiled algorithms may be
 * found in the user_settings_folder.
 *
 * Application Instructions
 *   1. The test results will print to the UART.
 *
 * For wolfSSL debug and WICED security debug uncomment the debug options
 *    DEBUG_WOLFSSL in wolfSSL user_settings.h and WPRINT_ENABLE_SECURITY_DEBUG
 *    in include/wiced_defaults.h.
 *
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/logging.h"
#include "wolfcrypt/test/test.h"
#include "wolfcrypt/benchmark/benchmark.h"
#include "wiced.h"


typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;

void application_start()
{
    func_args args  = { 0 };

    if (wiced_init() != WICED_SUCCESS) {
        WPRINT_APP_INFO(("\nError initializing WICED.\n") );
        return;
    }

    if (wolfcrypt_test(&args) != WICED_SUCCESS) {
        WPRINT_APP_INFO( ("Error in wolfCrypt test.\n") );
        return;
    }

    if (benchmark_test(NULL) != WICED_SUCCESS) {
        WPRINT_APP_INFO( ("Error in benchmark test.\n") );
        return;
    }

    if (wolfCrypt_Cleanup() ) {
           WPRINT_APP_INFO( ("wolfCrypt error wolcCrypt_Cleanup().\n") );
           return;
    }
    else {
           WPRINT_APP_INFO( ("wolfCrypt cleanup success.\n") );
    }
}
