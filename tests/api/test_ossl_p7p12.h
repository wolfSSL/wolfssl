/* test_ossl_p7p12.h
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

#ifndef WOLFCRYPT_TEST_OSSL_P7P12_H
#define WOLFCRYPT_TEST_OSSL_P7P12_H

#include <tests/api/api_decl.h>

int test_wolfssl_PKCS7(void);
int test_wolfSSL_PKCS7_certs(void);
int test_wolfSSL_PKCS7_sign(void);
int test_wolfSSL_PKCS7_SIGNED_new(void);
int test_wolfSSL_PEM_write_bio_PKCS7(void);
int test_wolfSSL_PEM_write_bio_encryptedKey(void);
int test_wolfSSL_SMIME_read_PKCS7(void);
int test_wolfSSL_SMIME_write_PKCS7(void);
int test_wolfSSL_PKCS12(void);

#define TEST_OSSL_PKCS7_DECLS                                               \
    TEST_DECL_GROUP("ossl_p7", test_wolfssl_PKCS7),                         \
    TEST_DECL_GROUP("ossl_p7", test_wolfSSL_PKCS7_certs),                   \
    TEST_DECL_GROUP("ossl_p7", test_wolfSSL_PKCS7_sign),                    \
    TEST_DECL_GROUP("ossl_p7", test_wolfSSL_PKCS7_SIGNED_new),              \
    TEST_DECL_GROUP("ossl_p7", test_wolfSSL_PEM_write_bio_PKCS7),           \
    TEST_DECL_GROUP("ossl_p7", test_wolfSSL_PEM_write_bio_encryptedKey),    \
    TEST_DECL_GROUP("ossl_p7", test_wolfSSL_RAND_poll)

#define TEST_OSSL_SMIME_DECLS                                        \
    TEST_DECL_GROUP("ossl_smime", test_wolfSSL_SMIME_read_PKCS7),    \
    TEST_DECL_GROUP("ossl_smime", test_wolfSSL_SMIME_write_PKCS7)

#define TEST_OSSL_PKCS12_DECLS                          \
    TEST_DECL_GROUP("ossl_p12", test_wolfSSL_PKCS12)

#endif /* WOLFCRYPT_TEST_OSSL_P7P12_H */

