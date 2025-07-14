/* test_sm3.h
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

#ifndef WOLFCRYPT_TEST_SM3_H
#define WOLFCRYPT_TEST_SM3_H

#include <tests/api/api_decl.h>

int test_wc_InitSm3(void);
int test_wc_Sm3Update(void);
int test_wc_Sm3Final(void);
int test_wc_Sm3FinalRaw(void);
int test_wc_Sm3_KATs(void);
int test_wc_Sm3_other(void);
int test_wc_Sm3Copy(void);
int test_wc_Sm3GetHash(void);
int test_wc_Sm3_Flags(void);

#define TEST_SM3_DECLS                              \
    TEST_DECL_GROUP("sm3", test_wc_InitSm3),        \
    TEST_DECL_GROUP("sm3", test_wc_Sm3Update),      \
    TEST_DECL_GROUP("sm3", test_wc_Sm3Final),       \
    TEST_DECL_GROUP("sm3", test_wc_Sm3FinalRaw),    \
    TEST_DECL_GROUP("sm3", test_wc_Sm3_KATs),       \
    TEST_DECL_GROUP("sm3", test_wc_Sm3_other),      \
    TEST_DECL_GROUP("sm3", test_wc_Sm3Copy),        \
    TEST_DECL_GROUP("sm3", test_wc_Sm3GetHash),     \
    TEST_DECL_GROUP("sm3", test_wc_Sm3_Flags)

#endif /* WOLFCRYPT_TEST_SM3_H */
