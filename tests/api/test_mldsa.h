/* test_mldsa.h
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

#ifndef WOLFCRYPT_TEST_MLDSA_H
#define WOLFCRYPT_TEST_MLDSA_H

#include <tests/api/api_decl.h>

int test_wc_dilithium(void);
int test_wc_dilithium_make_key(void);
int test_wc_dilithium_sign(void);
int test_wc_dilithium_verify(void);
int test_wc_dilithium_sign_vfy(void);
int test_wc_dilithium_check_key(void);
int test_wc_dilithium_public_der_decode(void);
int test_wc_dilithium_der(void);
int test_wc_dilithium_make_key_from_seed(void);
int test_wc_dilithium_sig_kats(void);
int test_wc_dilithium_verify_kats(void);
int test_mldsa_pkcs8(void);
int test_mldsa_pkcs12(void);

#define TEST_MLDSA_DECLS                                            \
    TEST_DECL_GROUP("mldsa", test_wc_dilithium),                    \
    TEST_DECL_GROUP("mldsa", test_wc_dilithium_make_key),           \
    TEST_DECL_GROUP("mldsa", test_wc_dilithium_sign),               \
    TEST_DECL_GROUP("mldsa", test_wc_dilithium_verify),             \
    TEST_DECL_GROUP("mldsa", test_wc_dilithium_sign_vfy),           \
    TEST_DECL_GROUP("mldsa", test_wc_dilithium_check_key),          \
    TEST_DECL_GROUP("mldsa", test_wc_dilithium_public_der_decode),  \
    TEST_DECL_GROUP("mldsa", test_wc_dilithium_der),                \
    TEST_DECL_GROUP("mldsa", test_wc_dilithium_make_key_from_seed), \
    TEST_DECL_GROUP("mldsa", test_wc_dilithium_sig_kats),           \
    TEST_DECL_GROUP("mldsa", test_wc_dilithium_verify_kats),        \
    TEST_DECL_GROUP("mldsa", test_mldsa_pkcs8),                     \
    TEST_DECL_GROUP("mldsa", test_mldsa_pkcs12)

#endif /* WOLFCRYPT_TEST_MLDSA_H */
