/* wolfssl_test.c
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

#include <stdio.h>

#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfcrypt/test/test.h>
#include <wolfcrypt/benchmark/benchmark.h>

// #define DEBUG_ENTRY_LOOP

int main(void)
{
    int initRet;
    int benchRet;
    wc_test_ret_t testRet;

#ifdef DEBUG_ENTRY_LOOP
    {
        uint32_t spins = 800000000u;
        while (spins--) {
            asm("nop");
        }
    }
#endif


    initRet = wolfCrypt_Init();
    if (initRet != 0) {
        printf("wolfCrypt_Init failed: %d\n", initRet);
        return 1;
    }

    testRet = wolfcrypt_test(NULL);
    if (testRet != 0) {
        wolfCrypt_Cleanup();
        printf("wolfcrypt_test FAILED: %d\n", (int)testRet);
        return 1;
    }
    printf("wolfcrypt_test PASSED\n\n");

    benchRet = benchmark_test(NULL);

    wolfCrypt_Cleanup();

    if (benchRet != 0) {
        printf("benchmark_test FAILED: %d\n", benchRet);
        return 1;
    }

    printf("benchmark_test PASSED\n");
    return 0;
}
