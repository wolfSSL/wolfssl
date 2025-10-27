/* test_ossl_sk.h
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

#ifndef WOLFCRYPT_TEST_SSL_SK_H
#define WOLFCRYPT_TEST_SSL_SK_H

#include <tests/api/api_decl.h>

int test_wolfSSL_sk_new_free_node(void);
int test_wolfSSL_sk_push_get_node(void);
int test_wolfSSL_sk_free(void);
int test_wolfSSL_sk_push_pop(void);
int test_wolfSSL_sk_insert(void);
int test_wolfSSL_shallow_sk_dup(void);
int test_wolfSSL_sk_num(void);
int test_wolfSSL_sk_value(void);
int test_wolfssl_sk_GENERIC(void);
int test_wolfssl_sk_SSL_COMP(void);
int test_wolfSSL_sk_CIPHER(void);
int test_wolfssl_sk_WOLFSSL_STRING(void);
int test_wolfssl_lh_retrieve(void);

#define TEST_SSL_SK_DECLS                                       \
    TEST_DECL_GROUP("ossl_sk", test_wolfSSL_sk_new_free_node),  \
    TEST_DECL_GROUP("ossl_sk", test_wolfSSL_sk_push_get_node),  \
    TEST_DECL_GROUP("ossl_sk", test_wolfSSL_sk_free),           \
    TEST_DECL_GROUP("ossl_sk", test_wolfSSL_sk_push_pop),       \
    TEST_DECL_GROUP("ossl_sk", test_wolfSSL_sk_insert),         \
    TEST_DECL_GROUP("ossl_sk", test_wolfSSL_shallow_sk_dup),    \
    TEST_DECL_GROUP("ossl_sk", test_wolfSSL_sk_num),            \
    TEST_DECL_GROUP("ossl_sk", test_wolfSSL_sk_value),          \
    TEST_DECL_GROUP("ossl_sk", test_wolfssl_sk_GENERIC),        \
    TEST_DECL_GROUP("ossl_sk", test_wolfssl_sk_SSL_COMP),       \
    TEST_DECL_GROUP("ossl_sk", test_wolfSSL_sk_CIPHER),         \
    TEST_DECL_GROUP("ossl_sk", test_wolfssl_sk_WOLFSSL_STRING), \
    TEST_DECL_GROUP("ossl_sk", test_wolfssl_lh_retrieve)

#endif /* WOLFCRYPT_TEST_SSL_SK_H */

