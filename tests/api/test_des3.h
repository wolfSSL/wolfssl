/* test_des3.h
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

#ifndef WOLFCRYPT_TEST_DES3_H
#define WOLFCRYPT_TEST_DES3_H

#include <tests/api/api_decl.h>

int test_wc_Des3_SetIV(void);
int test_wc_Des3_SetKey(void);
int test_wc_Des3_CbcEncryptDecrypt(void);
int test_wc_Des3_EcbEncrypt(void);

#define TEST_DES3_DECLS                                         \
    TEST_DECL_GROUP("des3", test_wc_Des3_SetIV),                \
    TEST_DECL_GROUP("des3", test_wc_Des3_SetKey),               \
    TEST_DECL_GROUP("des3", test_wc_Des3_CbcEncryptDecrypt),    \
    TEST_DECL_GROUP("des3", test_wc_Des3_CbcEncryptDecrypt)

#endif /* WOLFCRYPT_TEST_DES3_H */
