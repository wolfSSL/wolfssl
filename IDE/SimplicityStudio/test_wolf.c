/* test_wolf.c
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

/* Example for running wolfCrypt test and benchmark from
 * SiLabs Simplicity Studio's CLI example */

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfcrypt/test/test.h>
#include <wolfcrypt/benchmark/benchmark.h>
#include <stdio.h>

#include "sl_cli.h"
#include "sl_cli_instances.h"
#include "sl_cli_arguments.h"
#include "sl_cli_handles.h"

#ifndef NO_CRYPT_TEST
typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;

static func_args args = { 0 };
#endif

void wolf_test(sl_cli_command_arg_t *arguments)
{
    int ret;
#ifndef NO_CRYPT_TEST
    wolfCrypt_Init();

    printf("\nCrypt Test\n");
    wolfcrypt_test(&args);
    ret = args.return_code;
    printf("Crypt Test: Return code %d\n", ret);

    wolfCrypt_Cleanup();
#else
    ret = NOT_COMPILED_IN;
#endif
    (void)arguments;
    (void)ret;
}

void wolf_bench(sl_cli_command_arg_t *arguments)
{
    int ret;
#ifndef NO_CRYPT_BENCHMARK
    wolfCrypt_Init();

    printf("\nBenchmark Test\n");
    benchmark_test(&args);
    ret = args.return_code;
    printf("Benchmark Test: Return code %d\n", ret);

    wolfCrypt_Cleanup();
#else
    ret = NOT_COMPILED_IN;
#endif
    (void)arguments;
    (void)ret;
}


