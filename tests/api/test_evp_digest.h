/* test_evp_digest.h
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

#ifndef WOLFCRYPT_TEST_EVP_DIGEST_H
#define WOLFCRYPT_TEST_EVP_DIGEST_H

#include <tests/api/api_decl.h>

int test_wolfSSL_EVP_shake128(void);
int test_wolfSSL_EVP_shake256(void);
int test_wolfSSL_EVP_sm3(void);
int test_EVP_blake2(void);
int test_wolfSSL_EVP_md4(void);
int test_wolfSSL_EVP_ripemd160(void);
int test_wolfSSL_EVP_get_digestbynid(void);
int test_wolfSSL_EVP_Digest(void);
int test_wolfSSL_EVP_Digest_all(void);
int test_wolfSSL_EVP_DigestFinal_ex(void);
int test_wolfSSL_EVP_DigestFinalXOF(void);
int test_wolfSSL_EVP_MD_nid(void);
int test_EVP_MD_do_all(void);
int test_wolfSSL_EVP_MD_size(void);

#define TEST_EVP_DIGEST_DECLS                                           \
    TEST_DECL_GROUP("evp_digest", test_wolfSSL_EVP_shake128),           \
    TEST_DECL_GROUP("evp_digest", test_wolfSSL_EVP_shake256),           \
    TEST_DECL_GROUP("evp_digest", test_wolfSSL_EVP_sm3),                \
    TEST_DECL_GROUP("evp_digest", test_EVP_blake2),                     \
    TEST_DECL_GROUP("evp_digest", test_wolfSSL_EVP_md4),                \
    TEST_DECL_GROUP("evp_digest", test_wolfSSL_EVP_ripemd160),          \
    TEST_DECL_GROUP("evp_digest", test_wolfSSL_EVP_get_digestbynid),    \
    TEST_DECL_GROUP("evp_digest", test_wolfSSL_EVP_Digest),             \
    TEST_DECL_GROUP("evp_digest", test_wolfSSL_EVP_Digest_all),         \
    TEST_DECL_GROUP("evp_digest", test_wolfSSL_EVP_DigestFinal_ex),     \
    TEST_DECL_GROUP("evp_digest", test_wolfSSL_EVP_DigestFinalXOF),     \
    TEST_DECL_GROUP("evp_digest", test_wolfSSL_EVP_MD_nid),             \
    TEST_DECL_GROUP("evp_digest", test_EVP_MD_do_all),                  \
    TEST_DECL_GROUP("evp_digest", test_wolfSSL_EVP_MD_size)

#endif /* WOLFCRYPT_TEST_EVP_DIGEST_H */
