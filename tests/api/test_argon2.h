/* test_argon2.h
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

#ifndef WOLFCRYPT_TEST_ARGON2_H
#define WOLFCRYPT_TEST_ARGON2_H

#include <tests/api/api_decl.h>

int test_wc_Argon2_rfc9106(void);
int test_wc_Argon2_long_tag(void);
int test_wc_Argon2_params(void);
int test_wc_Argon2_variants_differ(void);
int test_wc_Argon2_badargs(void);
int test_wc_Argon2Init(void);
int test_wc_Argon2New(void);
int test_wc_Argon2SetParams(void);
int test_wc_Argon2DeriveTag(void);
int test_wc_Argon2SetThreads(void);

#define TEST_ARGON2_DECLS                                       \
    TEST_DECL_GROUP("argon2", test_wc_Argon2_rfc9106),          \
    TEST_DECL_GROUP("argon2", test_wc_Argon2_long_tag),         \
    TEST_DECL_GROUP("argon2", test_wc_Argon2_params),           \
    TEST_DECL_GROUP("argon2", test_wc_Argon2_variants_differ),  \
    TEST_DECL_GROUP("argon2", test_wc_Argon2_badargs),          \
    TEST_DECL_GROUP("argon2", test_wc_Argon2Init),              \
    TEST_DECL_GROUP("argon2", test_wc_Argon2New),               \
    TEST_DECL_GROUP("argon2", test_wc_Argon2SetParams),         \
    TEST_DECL_GROUP("argon2", test_wc_Argon2DeriveTag),         \
    TEST_DECL_GROUP("argon2", test_wc_Argon2SetThreads)

#endif /* WOLFCRYPT_TEST_ARGON2_H */
