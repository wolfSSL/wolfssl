/* test_ossl_dgst.h
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

#ifndef WOLFCRYPT_TEST_OSSL_DGST_H
#define WOLFCRYPT_TEST_OSSL_DGST_H

#include <tests/api/api_decl.h>

int test_wolfSSL_MD4(void);
int test_wolfSSL_MD5(void);
int test_wolfSSL_MD5_Transform(void);
int test_wolfSSL_SHA(void);
int test_wolfSSL_SHA_Transform(void);
int test_wolfSSL_SHA224(void);
int test_wolfSSL_SHA256(void);
int test_wolfSSL_SHA256_Transform(void);
int test_wolfSSL_SHA512_Transform(void);
int test_wolfSSL_SHA512_224_Transform(void);
int test_wolfSSL_SHA512_256_Transform(void);

#define TEST_OSSL_DIGEST_DECLS                                       \
    TEST_DECL_GROUP("ossl_dgst", test_wolfSSL_MD4),                  \
    TEST_DECL_GROUP("ossl_dgst", test_wolfSSL_MD5),                  \
    TEST_DECL_GROUP("ossl_dgst", test_wolfSSL_MD5_Transform),        \
    TEST_DECL_GROUP("ossl_dgst", test_wolfSSL_SHA),                  \
    TEST_DECL_GROUP("ossl_dgst", test_wolfSSL_SHA_Transform),        \
    TEST_DECL_GROUP("ossl_dgst", test_wolfSSL_SHA224),               \
    TEST_DECL_GROUP("ossl_dgst", test_wolfSSL_SHA256),               \
    TEST_DECL_GROUP("ossl_dgst", test_wolfSSL_SHA256_Transform),     \
    TEST_DECL_GROUP("ossl_dgst", test_wolfSSL_SHA512_Transform),     \
    TEST_DECL_GROUP("ossl_dgst", test_wolfSSL_SHA512_224_Transform), \
    TEST_DECL_GROUP("ossl_dgst", test_wolfSSL_SHA512_256_Transform)

#endif /* WOLFCRYPT_TEST_OSSL_DGST_H */

