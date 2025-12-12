/* test_ossl_pem.h
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

#ifndef WOLFCRYPT_TEST_SSL_PEM_H
#define WOLFCRYPT_TEST_SSL_PEM_H

#include <tests/api/api_decl.h>

int test_wolfSSL_PEM_def_callback(void);
int test_wolfSSL_PEM_read_PrivateKey(void);
int test_wolfSSL_PEM_read_PUBKEY(void);
int test_wolfSSL_PEM_PrivateKey_rsa(void);
int test_wolfSSL_PEM_PrivateKey_ecc(void);
int test_wolfSSL_PEM_PrivateKey_dsa(void);
int test_wolfSSL_PEM_PrivateKey_dh(void);
int test_wolfSSL_PEM_PrivateKey(void);
int test_wolfSSL_PEM_file_RSAKey(void);
int test_wolfSSL_PEM_file_RSAPrivateKey(void);
int test_wolfSSL_PEM_read_RSA_PUBKEY(void);
int test_wolfSSL_PEM_read_bio(void);
int test_wolfSSL_PEM_bio_RSAKey(void);
int test_wolfSSL_PEM_bio_RSAPrivateKey(void);
int test_wolfSSL_PEM_bio_DSAKey(void);
int test_wolfSSL_PEM_bio_ECKey(void);
int test_wolfSSL_PEM_PUBKEY(void);


#define TEST_SSL_PEM_DECLS                                              \
    TEST_DECL_GROUP("ossl_pem", test_wolfSSL_PEM_def_callback),         \
    TEST_DECL_GROUP("ossl_pem", test_wolfSSL_PEM_read_PrivateKey),      \
    TEST_DECL_GROUP("ossl_pem", test_wolfSSL_PEM_read_PUBKEY),          \
    TEST_DECL_GROUP("ossl_pem", test_wolfSSL_PEM_PrivateKey_rsa),       \
    TEST_DECL_GROUP("ossl_pem", test_wolfSSL_PEM_PrivateKey_ecc),       \
    TEST_DECL_GROUP("ossl_pem", test_wolfSSL_PEM_PrivateKey_dsa),       \
    TEST_DECL_GROUP("ossl_pem", test_wolfSSL_PEM_PrivateKey_dh),        \
    TEST_DECL_GROUP("ossl_pem", test_wolfSSL_PEM_PrivateKey),           \
    TEST_DECL_GROUP("ossl_pem", test_wolfSSL_PEM_file_RSAKey),          \
    TEST_DECL_GROUP("ossl_pem", test_wolfSSL_PEM_file_RSAPrivateKey),   \
    TEST_DECL_GROUP("ossl_pem", test_wolfSSL_PEM_read_RSA_PUBKEY),      \
    TEST_DECL_GROUP("ossl_pem", test_wolfSSL_PEM_read_bio),             \
    TEST_DECL_GROUP("ossl_pem", test_wolfSSL_PEM_bio_RSAKey),           \
    TEST_DECL_GROUP("ossl_pem", test_wolfSSL_PEM_bio_RSAPrivateKey),    \
    TEST_DECL_GROUP("ossl_pem", test_wolfSSL_PEM_bio_DSAKey),           \
    TEST_DECL_GROUP("ossl_pem", test_wolfSSL_PEM_bio_ECKey),            \
    TEST_DECL_GROUP("ossl_pem", test_wolfSSL_PEM_PUBKEY)

#endif /* WOLFCRYPT_TEST_SSL_PEM_H */
