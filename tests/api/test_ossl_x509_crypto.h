/* test_ossl_x509_crypto.h
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

#ifndef WOLFCRYPT_TEST_OSSL_X509_CRYPTO_H
#define WOLFCRYPT_TEST_OSSL_X509_CRYPTO_H

#include <tests/api/api_decl.h>

int test_wolfSSL_X509_check_private_key(void);
int test_wolfSSL_X509_verify(void);
int test_wolfSSL_X509_sign(void);
int test_wolfSSL_X509_sign2(void);
int test_wolfSSL_make_cert(void);

#define TEST_OSSL_X509_CRYPTO_DECLS                                            \
    TEST_DECL_GROUP("ossl_x509_crypto", test_wolfSSL_X509_check_private_key),  \
    TEST_DECL_GROUP("ossl_x509_crypto", test_wolfSSL_X509_verify),             \
    TEST_DECL_GROUP("ossl_x509_crypto", test_wolfSSL_X509_sign),               \
    TEST_DECL_GROUP("ossl_x509_crypto", test_wolfSSL_X509_sign2),              \
    TEST_DECL_GROUP("ossl_x509_crypto", test_wolfSSL_make_cert)

#endif /* WOLFCRYPT_TEST_OSSL_X509_CRYPTO_H */
