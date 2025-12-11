/* test_ossl_bn.h
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

#ifndef WOLFCRYPT_TEST_OSSL_BN_H
#define WOLFCRYPT_TEST_OSSL_BN_H

#include <tests/api/api_decl.h>

int test_wolfSSL_BN_CTX(void);
int test_wolfSSL_BN(void);
int test_wolfSSL_BN_init(void);
int test_wolfSSL_BN_enc_dec(void);
int test_wolfSSL_BN_word(void);
int test_wolfSSL_BN_bits(void);
int test_wolfSSL_BN_shift(void);
int test_wolfSSL_BN_math(void);
int test_wolfSSL_BN_math_mod(void);
int test_wolfSSL_BN_math_other(void);
int test_wolfSSL_BN_rand(void);
int test_wolfSSL_BN_prime(void);

#define TEST_OSSL_ASN1_BN_DECLS                             \
    TEST_DECL_GROUP("ossl_bn", test_wolfSSL_BN_CTX),        \
    TEST_DECL_GROUP("ossl_bn", test_wolfSSL_BN),            \
    TEST_DECL_GROUP("ossl_bn", test_wolfSSL_BN_init),       \
    TEST_DECL_GROUP("ossl_bn", test_wolfSSL_BN_enc_dec),    \
    TEST_DECL_GROUP("ossl_bn", test_wolfSSL_BN_word),       \
    TEST_DECL_GROUP("ossl_bn", test_wolfSSL_BN_bits),       \
    TEST_DECL_GROUP("ossl_bn", test_wolfSSL_BN_shift),      \
    TEST_DECL_GROUP("ossl_bn", test_wolfSSL_BN_math),       \
    TEST_DECL_GROUP("ossl_bn", test_wolfSSL_BN_math_mod),   \
    TEST_DECL_GROUP("ossl_bn", test_wolfSSL_BN_math_other), \
    TEST_DECL_GROUP("ossl_bn", test_wolfSSL_BN_rand),       \
    TEST_DECL_GROUP("ossl_bn", test_wolfSSL_BN_prime)

#endif /* WOLFCRYPT_TEST_OSSL_BN_H */
