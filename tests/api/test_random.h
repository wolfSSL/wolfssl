/* test_random.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#ifndef WOLFCRYPT_TEST_RANDOM_H
#define WOLFCRYPT_TEST_RANDOM_H

#include <tests/api/api_decl.h>

int test_wc_InitRng(void);
int test_wc_RNG_GenerateBlock_Reseed(void);
int test_wc_RNG_GenerateBlock(void);
int test_wc_RNG_GenerateByte(void);
int test_wc_InitRngNonce(void);
int test_wc_InitRngNonce_ex(void);
int test_wc_GenerateSeed(void);
int test_wc_rng_new(void);
int test_wc_RNG_DRBG_Reseed(void);
int test_wc_RNG_TestSeed(void);
int test_wc_RNG_HealthTest(void);

#define TEST_RANDOM_DECLS                                           \
    TEST_DECL_GROUP("random", test_wc_InitRng),                     \
    TEST_DECL_GROUP("random", test_wc_RNG_GenerateBlock_Reseed),    \
    TEST_DECL_GROUP("random", test_wc_RNG_GenerateBlock),           \
    TEST_DECL_GROUP("random", test_wc_RNG_GenerateByte),            \
    TEST_DECL_GROUP("random", test_wc_InitRngNonce),                \
    TEST_DECL_GROUP("random", test_wc_InitRngNonce_ex),             \
    TEST_DECL_GROUP("random", test_wc_GenerateSeed),                \
    TEST_DECL_GROUP("random", test_wc_rng_new),                     \
    TEST_DECL_GROUP("random", test_wc_RNG_DRBG_Reseed),             \
    TEST_DECL_GROUP("random", test_wc_RNG_TestSeed),                \
    TEST_DECL_GROUP("random", test_wc_RNG_HealthTest)

#endif /* WOLFCRYPT_TEST_RANDOM_H */
