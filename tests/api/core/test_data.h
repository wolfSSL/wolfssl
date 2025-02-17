/* test_data.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef WOLFSSL_TEST_DATA_H
#define WOLFSSL_TEST_DATA_H

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

/* Test vector structure */
typedef struct TestVector {
    const byte* input;
    const byte* expected;
    word32 inLen;
    word32 outLen;
    int flags;          /* Optional flags for test case */
    const char* desc;   /* Optional test case description */
} TestVector;

/* Common test data sizes */
#define TEST_DATA_SIZE_1K  1024
#define TEST_DATA_SIZE_4K  4096
#define TEST_DATA_SIZE_16K 16384

/* Test data generation utilities */
byte* GetTestBuffer(word32 size);
void FreeTestBuffer(byte* buffer);

/* Test vector access functions */
const TestVector* GetSharedTestVectors(void);
word32 GetSharedTestVectorCount(void);

#endif /* WOLFSSL_TEST_DATA_H */
