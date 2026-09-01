/* test_keystore.h
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


#ifndef WOLFCRYPT_TEST_KEYSTORE_H
#define WOLFCRYPT_TEST_KEYSTORE_H

#include <tests/api/api_decl.h>

int test_wc_KeyStore_ImportPlain(void);
int test_wc_KeyStore_ExportPlain(void);
int test_wc_KeyStore_ImportWrapped(void);
int test_wc_KeyStore_ExportWrapped(void);
int test_wc_KeyStore_Derive(void);
int test_wc_KeyStore_Delete(void);
int test_wc_KeyStore_GetInfo(void);
int test_wc_KeyStore_NoDevice(void);

/* Defined unconditionally, as every other TEST_*_DECLS is: each test body
 * compiles to a skip when the feature is off. A conditionally empty macro
 * would leave a dangling comma at the use site in tests/api.c. */
#define TEST_KEYSTORE_DECLS                                              \
    TEST_DECL_GROUP("keystore", test_wc_KeyStore_ImportPlain),           \
    TEST_DECL_GROUP("keystore", test_wc_KeyStore_ExportPlain),           \
    TEST_DECL_GROUP("keystore", test_wc_KeyStore_ImportWrapped),         \
    TEST_DECL_GROUP("keystore", test_wc_KeyStore_ExportWrapped),         \
    TEST_DECL_GROUP("keystore", test_wc_KeyStore_Derive),                \
    TEST_DECL_GROUP("keystore", test_wc_KeyStore_Delete),                \
    TEST_DECL_GROUP("keystore", test_wc_KeyStore_GetInfo),               \
    TEST_DECL_GROUP("keystore", test_wc_KeyStore_NoDevice)

#endif /* WOLFCRYPT_TEST_KEYSTORE_H */
