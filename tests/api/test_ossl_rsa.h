/* test_ossl_rsa.h
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

#ifndef WOLFCRYPT_TEST_OSSL_RSA_H
#define WOLFCRYPT_TEST_OSSL_RSA_H

#include <tests/api/api_decl.h>

int test_wolfSSL_RSA(void);
int test_wolfSSL_RSA_DER(void);
int test_wolfSSL_RSA_print(void);
int test_wolfSSL_RSA_padding_add_PKCS1_PSS(void);
int test_wolfSSL_RSA_sign_sha3(void);
int test_wolfSSL_RSA_get0_key(void);
int test_wolfSSL_RSA_meth(void);
int test_wolfSSL_RSA_verify(void);
int test_wolfSSL_RSA_sign(void);
int test_wolfSSL_RSA_sign_ex(void);
int test_wolfSSL_RSA_public_decrypt(void);
int test_wolfSSL_RSA_private_encrypt(void);
int test_wolfSSL_RSA_public_encrypt(void);
int test_wolfSSL_RSA_private_decrypt(void);
int test_wolfSSL_RSA_GenAdd(void);
int test_wolfSSL_RSA_blinding_on(void);
int test_wolfSSL_RSA_ex_data(void);
int test_wolfSSL_RSA_LoadDer(void);
int test_wolfSSL_RSA_To_Der(void);
int test_wolfSSL_PEM_read_RSAPublicKey(void);
int test_wolfSSL_PEM_write_RSA_PUBKEY(void);
int test_wolfSSL_PEM_write_RSAPrivateKey(void);
int test_wolfSSL_PEM_write_mem_RSAPrivateKey(void);

#define TEST_OSSL_RSA_DECLS                                                 \
    TEST_DECL_GROUP("ossl_rsa", test_wolfSSL_RSA),                          \
    TEST_DECL_GROUP("ossl_rsa", test_wolfSSL_RSA_DER),                      \
    TEST_DECL_GROUP("ossl_rsa", test_wolfSSL_RSA_print),                    \
    TEST_DECL_GROUP("ossl_rsa", test_wolfSSL_RSA_padding_add_PKCS1_PSS),    \
    TEST_DECL_GROUP("ossl_rsa", test_wolfSSL_RSA_sign_sha3),                \
    TEST_DECL_GROUP("ossl_rsa", test_wolfSSL_RSA_get0_key),                 \
    TEST_DECL_GROUP("ossl_rsa", test_wolfSSL_RSA_meth),                     \
    TEST_DECL_GROUP("ossl_rsa", test_wolfSSL_RSA_verify),                   \
    TEST_DECL_GROUP("ossl_rsa", test_wolfSSL_RSA_sign),                     \
    TEST_DECL_GROUP("ossl_rsa", test_wolfSSL_RSA_sign_ex),                  \
    TEST_DECL_GROUP("ossl_rsa", test_wolfSSL_RSA_public_decrypt),           \
    TEST_DECL_GROUP("ossl_rsa", test_wolfSSL_RSA_private_encrypt),          \
    TEST_DECL_GROUP("ossl_rsa", test_wolfSSL_RSA_public_encrypt),           \
    TEST_DECL_GROUP("ossl_rsa", test_wolfSSL_RSA_private_decrypt),          \
    TEST_DECL_GROUP("ossl_rsa", test_wolfSSL_RSA_GenAdd),                   \
    TEST_DECL_GROUP("ossl_rsa", test_wolfSSL_RSA_blinding_on),              \
    TEST_DECL_GROUP("ossl_rsa", test_wolfSSL_RSA_ex_data),                  \
    TEST_DECL_GROUP("ossl_rsa", test_wolfSSL_RSA_LoadDer),                  \
    TEST_DECL_GROUP("ossl_rsa", test_wolfSSL_RSA_To_Der),                   \
    TEST_DECL_GROUP("ossl_rsa", test_wolfSSL_PEM_read_RSAPublicKey),        \
    TEST_DECL_GROUP("ossl_rsa", test_wolfSSL_PEM_write_RSA_PUBKEY),         \
    TEST_DECL_GROUP("ossl_rsa", test_wolfSSL_PEM_write_RSAPrivateKey),      \
    TEST_DECL_GROUP("ossl_rsa", test_wolfSSL_PEM_write_mem_RSAPrivateKey)

#endif /* WOLFCRYPT_TEST_OSSL_RSA_H */

