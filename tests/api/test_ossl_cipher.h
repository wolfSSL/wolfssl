/* test_ossl_cipher.h
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

#ifndef WOLFCRYPT_TEST_OSSL_CIPHER_H
#define WOLFCRYPT_TEST_OSSL_CIPHER_H

#include <tests/api/api_decl.h>

int test_wolfSSL_DES(void);
int test_wolfSSL_DES_ncbc(void);
int test_wolfSSL_DES_ecb_encrypt(void);
int test_wolfSSL_DES_ede3_cbc_encrypt(void);
int test_wolfSSL_AES_encrypt(void);
int test_wolfSSL_AES_ecb_encrypt(void);
int test_wolfSSL_AES_cbc_encrypt(void);
int test_wolfSSL_AES_cfb128_encrypt(void);
int test_wolfSSL_CRYPTO_cts128(void);
int test_wolfSSL_RC4(void);

#define TEST_OSSL_CIPHER_DECLS                                          \
    TEST_DECL_GROUP("ossl_cipher", test_wolfSSL_DES),                   \
    TEST_DECL_GROUP("ossl_cipher", test_wolfSSL_DES_ncbc),              \
    TEST_DECL_GROUP("ossl_cipher", test_wolfSSL_DES_ecb_encrypt),       \
    TEST_DECL_GROUP("ossl_cipher", test_wolfSSL_DES_ede3_cbc_encrypt),  \
    TEST_DECL_GROUP("ossl_cipher", test_wolfSSL_AES_encrypt),           \
    TEST_DECL_GROUP("ossl_cipher", test_wolfSSL_AES_ecb_encrypt),       \
    TEST_DECL_GROUP("ossl_cipher", test_wolfSSL_AES_cbc_encrypt),       \
    TEST_DECL_GROUP("ossl_cipher", test_wolfSSL_AES_cfb128_encrypt),    \
    TEST_DECL_GROUP("ossl_cipher", test_wolfSSL_CRYPTO_cts128),         \
    TEST_DECL_GROUP("ossl_cipher", test_wolfSSL_RC4)

#endif /* WOLFCRYPT_TEST_OSSL_CIPHER_H */

