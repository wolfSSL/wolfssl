/* test_setup.h
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

#ifndef WOLFSSL_TEST_SETUP_H
#define WOLFSSL_TEST_SETUP_H

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/unit.h>

/* Test environment setup/teardown */
#define TEST_CASE_SETUP(name) \
    static int name##_Setup(void)

#define TEST_CASE_TEARDOWN(name) \
    static int name##_Teardown(void)

/* Test suite setup/teardown */
#define TEST_SUITE_SETUP(name) \
    static int name##_SuiteSetup(void)

#define TEST_SUITE_TEARDOWN(name) \
    static int name##_SuiteTeardown(void)

/* Common setup utilities */
int SetupTestEnvironment(void);
void CleanupTestEnvironment(void);

#endif /* WOLFSSL_TEST_SETUP_H */
