/* test_utils.h
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

#ifndef WOLFSSL_TEST_UTILS_H
#define WOLFSSL_TEST_UTILS_H

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/unit.h>

/* Common test macros for crypto operations */
#define TEST_CRYPTO_OPERATION(name, init_fn, update_fn, final_fn, free_fn, data, len, hash) \
    EXPECT_DECLS; \
    ExpectIntEQ(init_fn(), 0); \
    ExpectIntEQ(update_fn(data, len), 0); \
    ExpectIntEQ(final_fn(hash), 0); \
    if (free_fn) ExpectIntEQ(free_fn(), 0); \
    return EXPECT_RESULT()

/* Common test setup/teardown macros */
#define TEST_SETUP(name) \
    EXPECT_DECLS; \
    if (name##_Setup) ExpectIntEQ(name##_Setup(), 0)

#define TEST_TEARDOWN(name) \
    if (name##_Teardown) ExpectIntEQ(name##_Teardown(), 0); \
    return EXPECT_RESULT()

/* Common test result checking macros */
#define TEST_ASSERT_SUCCESS(fn) \
    ExpectIntEQ(fn, 0)

#define TEST_ASSERT_FAIL(fn, err) \
    ExpectIntEQ(fn, err)

#endif /* WOLFSSL_TEST_UTILS_H */
