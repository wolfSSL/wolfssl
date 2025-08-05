/* test_ossl_ec.h
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

#ifndef WOLFCRYPT_TEST_OSSL_EC_H
#define WOLFCRYPT_TEST_OSSL_EC_H

#include <tests/api/api_decl.h>

#if defined(HAVE_ECC) && !defined(OPENSSL_NO_PK)

int test_wolfSSL_EC_GROUP(void);
int test_wolfSSL_PEM_read_bio_ECPKParameters(void);
int test_wolfSSL_i2d_ECPKParameters(void);
int test_wolfSSL_EC_POINT(void);
int test_wolfSSL_SPAKE(void);
int test_wolfSSL_EC_KEY_generate(void);
int test_EC_i2d(void);
int test_wolfSSL_EC_curve(void);
int test_wolfSSL_EC_KEY_dup(void);
int test_wolfSSL_EC_KEY_set_group(void);
int test_wolfSSL_EC_KEY_set_conv_form(void);
int test_wolfSSL_EC_KEY_private_key(void);
int test_wolfSSL_EC_KEY_public_key(void);
int test_wolfSSL_EC_KEY_print_fp(void);
int test_wolfSSL_EC_get_builtin_curves(void);
int test_wolfSSL_ECDSA_SIG(void);
int test_ECDSA_size_sign(void);
int test_ECDH_compute_key(void);


#define TEST_OSSL_EC_DECLS                                                  \
    TEST_DECL_GROUP("ossl_ec", test_wolfSSL_EC_GROUP),                      \
    TEST_DECL_GROUP("ossl_ec", test_wolfSSL_PEM_read_bio_ECPKParameters),   \
    TEST_DECL_GROUP("ossl_ec", test_wolfSSL_i2d_ECPKParameters),            \
    TEST_DECL_GROUP("ossl_ec", test_wolfSSL_EC_POINT),                      \
    TEST_DECL_GROUP("ossl_ec", test_wolfSSL_SPAKE),                         \
    TEST_DECL_GROUP("ossl_ec", test_wolfSSL_EC_KEY_generate),               \
    TEST_DECL_GROUP("ossl_ec", test_EC_i2d),                                \
    TEST_DECL_GROUP("ossl_ec", test_wolfSSL_EC_curve),                      \
    TEST_DECL_GROUP("ossl_ec", test_wolfSSL_EC_KEY_dup),                    \
    TEST_DECL_GROUP("ossl_ec", test_wolfSSL_EC_KEY_set_group),              \
    TEST_DECL_GROUP("ossl_ec", test_wolfSSL_EC_KEY_set_conv_form),          \
    TEST_DECL_GROUP("ossl_ec", test_wolfSSL_EC_KEY_private_key),            \
    TEST_DECL_GROUP("ossl_ec", test_wolfSSL_EC_KEY_public_key),             \
    TEST_DECL_GROUP("ossl_ec", test_wolfSSL_EC_KEY_print_fp),               \
    TEST_DECL_GROUP("ossl_ec", test_wolfSSL_EC_get_builtin_curves),         \
    TEST_DECL_GROUP("ossl_ec", test_wolfSSL_ECDSA_SIG),                     \
    TEST_DECL_GROUP("ossl_ec", test_ECDSA_size_sign),                       \
    TEST_DECL_GROUP("ossl_ec", test_ECDH_compute_key)

#endif

#endif /* WOLFCRYPT_TEST_OSSL_EC_H */

