/* test_sha256.h
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

#ifndef WOLFCRYPT_TEST_SHA256_H
#define WOLFCRYPT_TEST_SHA256_H

#include <tests/api/api_decl.h>

int test_wc_InitSha256(void);
int test_wc_Sha256Update(void);
int test_wc_Sha256Final(void);
int test_wc_Sha256FinalRaw(void);
int test_wc_Sha256_KATs(void);
int test_wc_Sha256_other(void);
int test_wc_Sha256Copy(void);
int test_wc_Sha256GetHash(void);
int test_wc_Sha256Transform(void);
int test_wc_Sha256_Flags(void);

int test_wc_InitSha224(void);
int test_wc_Sha224Update(void);
int test_wc_Sha224Final(void);
int test_wc_Sha224_KATs(void);
int test_wc_Sha224_other(void);
int test_wc_Sha224Copy(void);
int test_wc_Sha224GetHash(void);
int test_wc_Sha224_Flags(void);

#define TEST_SHA256_DECLS                               \
    TEST_DECL_GROUP("sha256", test_wc_InitSha256),      \
    TEST_DECL_GROUP("sha256", test_wc_Sha256Update),    \
    TEST_DECL_GROUP("sha256", test_wc_Sha256Final),     \
    TEST_DECL_GROUP("sha256", test_wc_Sha256FinalRaw),  \
    TEST_DECL_GROUP("sha256", test_wc_Sha256_KATs),     \
    TEST_DECL_GROUP("sha256", test_wc_Sha256_other),    \
    TEST_DECL_GROUP("sha256", test_wc_Sha256Copy),      \
    TEST_DECL_GROUP("sha256", test_wc_Sha256GetHash),   \
    TEST_DECL_GROUP("sha256", test_wc_Sha256Transform), \
    TEST_DECL_GROUP("sha256", test_wc_Sha256_Flags)

#define TEST_SHA224_DECLS                               \
    TEST_DECL_GROUP("sha224", test_wc_InitSha224),      \
    TEST_DECL_GROUP("sha224", test_wc_Sha224Update),    \
    TEST_DECL_GROUP("sha224", test_wc_Sha224Final),     \
    TEST_DECL_GROUP("sha224", test_wc_Sha224_KATs),     \
    TEST_DECL_GROUP("sha224", test_wc_Sha224_other),    \
    TEST_DECL_GROUP("sha224", test_wc_Sha224Copy),      \
    TEST_DECL_GROUP("sha224", test_wc_Sha224GetHash),   \
    TEST_DECL_GROUP("sha224", test_wc_Sha224_Flags)

#endif /* WOLFCRYPT_TEST_SHA256_H */
