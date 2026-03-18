/* test_she.h
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

#ifndef WOLFCRYPT_TEST_SHE_H
#define WOLFCRYPT_TEST_SHE_H

#include <tests/api/api_decl.h>

int test_wc_SHE_Init(void);
int test_wc_SHE_Init_Id(void);
int test_wc_SHE_Init_Label(void);
int test_wc_SHE_Free(void);
int test_wc_SHE_SetUID(void);
int test_wc_SHE_SetAuthKey(void);
int test_wc_SHE_SetNewKey(void);
int test_wc_SHE_SetCounter(void);
int test_wc_SHE_SetFlags(void);
int test_wc_SHE_SetKdfConstants(void);
int test_wc_SHE_SetM2M4Header(void);
int test_wc_SHE_GenerateM1M2M3(void);
int test_wc_She_AesMp16(void);
int test_wc_SHE_GenerateM4M5(void);
int test_wc_SHE_ExportKey(void);
#if defined(WOLF_CRYPTO_CB) && defined(WOLFSSL_SHE)
int test_wc_SHE_CryptoCb(void);
#endif

#define TEST_SHE_DECLS                                          \
    TEST_DECL_GROUP("she", test_wc_SHE_Init),                   \
    TEST_DECL_GROUP("she", test_wc_SHE_Init_Id),                \
    TEST_DECL_GROUP("she", test_wc_SHE_Init_Label),             \
    TEST_DECL_GROUP("she", test_wc_SHE_Free),                   \
    TEST_DECL_GROUP("she", test_wc_SHE_SetUID),                 \
    TEST_DECL_GROUP("she", test_wc_SHE_SetAuthKey),             \
    TEST_DECL_GROUP("she", test_wc_SHE_SetNewKey),              \
    TEST_DECL_GROUP("she", test_wc_SHE_SetCounter),             \
    TEST_DECL_GROUP("she", test_wc_SHE_SetFlags),               \
    TEST_DECL_GROUP("she", test_wc_SHE_SetKdfConstants),          \
    TEST_DECL_GROUP("she", test_wc_SHE_SetM2M4Header),          \
    TEST_DECL_GROUP("she", test_wc_SHE_GenerateM1M2M3),        \
    TEST_DECL_GROUP("she", test_wc_She_AesMp16),               \
    TEST_DECL_GROUP("she", test_wc_SHE_GenerateM4M5),    \
    TEST_DECL_GROUP("she", test_wc_SHE_ExportKey)

#if defined(WOLF_CRYPTO_CB) && defined(WOLFSSL_SHE)
#define TEST_SHE_CB_DECLS \
    TEST_DECL_GROUP("she", test_wc_SHE_CryptoCb)
#else
#define TEST_SHE_CB_DECLS
#endif

#endif /* WOLFCRYPT_TEST_SHE_H */
