/* benchmark_main.c
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfcrypt/benchmark/benchmark.h>
#include <stdio.h>

typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;

static func_args args = { 0 } ;

extern double current_time(int reset);

void main(void) 
{
    int test_num = 0;

    do
    {
        printf("\nBenchmark Test %d:\n", test_num);
        benchmark_test(&args);
        printf("Benchmark Test %d: Return code %d\n", test_num, args.return_code);
        
        test_num++;
    } while(args.return_code == 0);
}

/* 
SAMPLE OUTPUT: Freescale K64 running at 96MHz with no MMCAU:
Benchmark Test 1:
AES      25 kB took 0.073 seconds,    0.334 MB/s
ARC4     25 kB took 0.033 seconds,    0.740 MB/s
RABBIT   25 kB took 0.027 seconds,    0.904 MB/s
3DES     25 kB took 0.375 seconds,    0.065 MB/s
MD5      25 kB took 0.016 seconds,    1.526 MB/s
SHA      25 kB took 0.044 seconds,    0.555 MB/s
SHA-256  25 kB took 0.119 seconds,    0.205 MB/s
RSA 1024 encryption took 91.000 milliseconds, avg over 1 iterations
RSA 1024 decryption took 573.000 milliseconds, avg over 1 iterations
DH  1024 key generation  253.000 milliseconds, avg over 1 iterations
DH  1024 key agreement   311.000 milliseconds, avg over 1 iterations
Benchmark Test 1: Return code 0

SAMPLE OUTPUT: Freescale K64 running at 96MHz with MMCAU enabled:
Benchmark Test 1:
AES      25 kB took 0.019 seconds,    1.285 MB/s
ARC4     25 kB took 0.033 seconds,    0.740 MB/s
RABBIT   25 kB took 0.028 seconds,    0.872 MB/s
3DES     25 kB took 0.026 seconds,    0.939 MB/s
MD5      25 kB took 0.005 seconds,    4.883 MB/s
SHA      25 kB took 0.008 seconds,    3.052 MB/s
SHA-256  25 kB took 0.013 seconds,    1.878 MB/s
RSA 1024 encryption took 89.000 milliseconds, avg over 1 iterations
RSA 1024 decryption took 573.000 milliseconds, avg over 1 iterations
DH  1024 key generation  250.000 milliseconds, avg over 1 iterations
DH  1024 key agreement   308.000 milliseconds, avg over 1 iterations
Benchmark Test 1: Return code 0
*/
