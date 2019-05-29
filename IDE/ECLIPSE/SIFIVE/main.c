/* main.c
 *
 * Copyright (C) 2019 wolfSSL Inc.
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
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfcrypt/test/test.h>
#include <wolfcrypt/benchmark/benchmark.h>

/* wolfCrypt_Init/wolfCrypt_Cleanup */
#include <wolfssl/wolfcrypt/wc_port.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#ifndef NO_CRYPT_BENCHMARK

/*-specs=nano.specs doesn’t include support for floating point in printf()*/
asm (".global _printf_float");

#define RTC_FREQ    32768
#define CLINT_MTIME_ADDR  0x200bff8
#define WOLFSSL_SIFIVE_RISC_V_DEBUG 0

double current_time(int reset)
{
    volatile uint64_t * mtime  = (uint64_t*) (CLINT_MTIME_ADDR);
    uint64_t now = *mtime;
    (void)reset;
    return now/RTC_FREQ;
}
#endif

#if WOLFSSL_SIFIVE_RISC_V_DEBUG
void check(int depth) {
    char ch;
    char *ptr = malloc(1);

    printf("stack at %p, heap at %p\n", &ch, ptr);
    if (depth <= 0) 
        return;
    
    check(depth-1);
    free(ptr);
}

void mtime_sleep( uint64_t ticks) {
    volatile uint64_t * mtime  = (uint64_t*) (CLINT_MTIME_ADDR);
    uint64_t now = *mtime;
    uint64_t then = now + ticks;

    while((*mtime - now) < ticks) {
        
    }
}

void delay(int sec) {
    uint64_t ticks = sec * RTC_FREQ;
    mtime_sleep(ticks);
}
#endif 

/* RNG CODE */
/* TODO: Implement real RNG */
static unsigned int gCounter;
unsigned int hw_rand(void)
{
    /* #warning Must implement your own random source */

    return ++gCounter;
}

unsigned int my_rng_seed_gen(void)
{
    return hw_rand();
}

int my_rng_gen_block(unsigned char* output, unsigned int sz)
{
    uint32_t i = 0;
    uint32_t randReturnSize = sizeof(CUSTOM_RAND_TYPE);

    while (i < sz)
    {
        /* If not aligned or there is odd/remainder */
        if((i + randReturnSize) > sz ||
            ((uint32_t)&output[i] % randReturnSize) != 0 ) {
            /* Single byte at a time */
            output[i++] = (unsigned char)my_rng_seed_gen();
        }
        else {
            /* Use native 8, 16, 32 or 64 copy instruction */
            *((CUSTOM_RAND_TYPE*)&output[i]) = my_rng_seed_gen();
            i += randReturnSize;
        }
    }

    return 0;
}

int main(void) 
{
    int ret;

#if WOLFSSL_SIFIVE_RISC_V_DEBUG
    printf("check stack and heap addresses\n");
    check(8);
    printf("sleep for 10 seconds to verify timer\n");
    delay(10);
    printf("awake after sleeping for 10 seconds\n");
#endif    
    
    #ifdef DEBUG_WOLFSSL
        wolfSSL_Debugging_ON();
    #endif

    if ((ret = wolfCrypt_Init()) != 0) {
        printf("wolfCrypt_Init failed %d\n", ret);
        return -1;
    }

#ifndef NO_CRYPT_TEST
    printf("\nwolfCrypt Test Started\n");
    wolfcrypt_test(NULL);
    printf("\nwolfCrypt Test Completed\n");
#endif

#ifndef NO_CRYPT_BENCHMARK
    printf("\nBenchmark Test Started\n");
    benchmark_test(NULL);
    printf("\nBenchmark Test Completed\n");
#endif
    if ((ret = wolfCrypt_Cleanup()) != 0) {
        printf("wolfCrypt_Cleanup failed %d\n", ret);
        return -1;
    }
    return 0;
}

