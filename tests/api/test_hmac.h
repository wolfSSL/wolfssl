/* test_hmac.h
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

#ifndef WOLFCRYPT_TEST_HMAC_H
#define WOLFCRYPT_TEST_HMAC_H

#include <tests/api/api_decl.h>

int test_wc_Md5HmacSetKey(void);
int test_wc_Md5HmacUpdate(void);
int test_wc_Md5HmacFinal(void);
int test_wc_ShaHmacSetKey(void);
int test_wc_ShaHmacUpdate(void);
int test_wc_ShaHmacFinal(void);
int test_wc_Sha224HmacSetKey(void);
int test_wc_Sha224HmacUpdate(void);
int test_wc_Sha224HmacFinal(void);
int test_wc_Sha256HmacSetKey(void);
int test_wc_Sha256HmacUpdate(void);
int test_wc_Sha256HmacFinal(void);
int test_wc_Sha384HmacSetKey(void);
int test_wc_Sha384HmacUpdate(void);
int test_wc_Sha384HmacFinal(void);

#define TEST_HMAC_DECLS                                 \
    TEST_DECL_GROUP("hmac", test_wc_Md5HmacSetKey),     \
    TEST_DECL_GROUP("hmac", test_wc_Md5HmacUpdate),     \
    TEST_DECL_GROUP("hmac", test_wc_Md5HmacFinal),      \
    TEST_DECL_GROUP("hmac", test_wc_ShaHmacSetKey),     \
    TEST_DECL_GROUP("hmac", test_wc_ShaHmacUpdate),     \
    TEST_DECL_GROUP("hmac", test_wc_ShaHmacFinal),      \
    TEST_DECL_GROUP("hmac", test_wc_Sha224HmacSetKey),  \
    TEST_DECL_GROUP("hmac", test_wc_Sha224HmacUpdate),  \
    TEST_DECL_GROUP("hmac", test_wc_Sha224HmacFinal),   \
    TEST_DECL_GROUP("hmac", test_wc_Sha256HmacSetKey),  \
    TEST_DECL_GROUP("hmac", test_wc_Sha256HmacUpdate),  \
    TEST_DECL_GROUP("hmac", test_wc_Sha256HmacFinal),   \
    TEST_DECL_GROUP("hmac", test_wc_Sha384HmacSetKey),  \
    TEST_DECL_GROUP("hmac", test_wc_Sha384HmacUpdate),  \
    TEST_DECL_GROUP("hmac", test_wc_Sha384HmacFinal)

#endif /* WOLFCRYPT_TEST_HMAC_H */
