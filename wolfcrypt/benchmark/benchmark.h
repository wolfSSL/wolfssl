/* wolfcrypt/benchmark/benchmark.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
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


#ifndef WOLFCRYPT_BENCHMARK_H
#define WOLFCRYPT_BENCHMARK_H
#define BENCH_NAME_SZ 12
#define BENCH_ERROR_SZ 80

#ifdef __cplusplus
    extern "C" {
#endif

int benchmark_test(void* args);

typedef struct
{
    word64 cycles;
    double total;
    double rate;
    int keySize; /*Initialize for printing; needs to be 0 if no keys.*/
    int outputType;
    char name[BENCH_NAME_SZ];
} benchResult;


/*Passed into init_result to determine the print format for the algorithm. */
enum printFormat{
    mbPerSec,               /* Rate is in MB/S                  */
    encryptMillisecond,     /* Encryption rate is in millisec   */
    decryptMillisecond,     /* Decryption rate is in millisec   */
    keyGen,                 /* Key Generation algorithm format  */
    keyAgree,               /* Key Agreement format             */
    keyGenNoKeysz,          /* Key Generation without key size  */
    keyAgreeNoKeysz,        /* Key Agreement without key size   */
    signTime,               /* Certificate sign time.           */
    verifyTime,             /* Show verify time.                */
    encryptNoKeysz,         /* Encryption without key size.     */
    decryptNoKeysz          /* Decryption without key size.     */
};

enum outputType {
    outputEncrypt,
    outputDecrypt,
    outputBoth
};

/* Output function pointer type - output_cb */
typedef int (*output_cb)(benchResult* result);
/* Benchmark function pointer type - bench_cb */
typedef int (*bench_cb)(benchResult* result, output_cb output);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFCRYPT_BENCHMARK_H */
