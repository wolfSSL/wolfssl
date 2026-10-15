/* main.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfcrypt/test/test.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define STRINGIFY_(x) #x
#define STRINGIFY(x) STRINGIFY_(x)

#ifdef MSP430_TEST_LARGE
static unsigned char high_message[3]
    __attribute__((section(".upper.data"))) = {'a', 'b', 'c'};

static int __attribute__((section(".upper.text"), noinline)) high_address_test(void)
{
    static const unsigned char expected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    unsigned char digest[32];
    unsigned long address = (unsigned long)(uintptr_t)high_message;
    unsigned long code = (unsigned long)(uintptr_t)high_address_test;
    printf("MSP430_HIGH_ADDRESS data=0x%lx code=0x%lx\n", address, code);
    if (address < 0x10000UL || code < 0x10000UL)
        return -1;
    if (wc_Sha256Hash(high_message, sizeof(high_message), digest) != 0)
        return -1;
    return memcmp(digest, expected, sizeof(expected));
}
#endif

#ifdef MSP430_TEST_ECC
int msp430_ecdsa_regression(void);

/* Deterministic fixture only. Never use this entropy source in firmware. */
int msp430_test_seed(unsigned char* output, unsigned long size)
{
    static unsigned long state = 0x12345678UL;
    while (size-- > 0) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        *output++ = (unsigned char)state;
    }
    return 0;
}
#endif

int main(void)
{
    wc_test_ret_t ret = wolfCrypt_Init();
    printf("MSP430_TEST_START %s\n", STRINGIFY(TEST_NAME));
#ifdef MSP430_TEST_LARGE
    if (ret == 0)
        ret = high_address_test();
#endif
#ifdef MSP430_TEST_ECC
    if (ret == 0) {
        ret = msp430_ecdsa_regression();
        if (ret == 0)
            printf("MSP430_ECDSA_REGRESSION_PASSED\n");
    }
#endif
    if (ret == 0) {
    #ifdef MSP430_FULL_SUITE
        ret = wolfcrypt_test(NULL);
    #else
        ret = TEST_FUNCTION();
    #endif
    }
    if (wolfCrypt_Cleanup() != 0 && ret == 0)
        ret = -1;
    if (ret != 0) {
        printf("MSP430_TEST_FAIL %s %ld\n", STRINGIFY(TEST_NAME), (long)ret);
        return 1;
    }
    printf("MSP430_TEST_PASS %s\n", STRINGIFY(TEST_NAME));
    return 0;
}
