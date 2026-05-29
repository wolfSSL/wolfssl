/* test_mldsa.h
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

#ifndef WOLFCRYPT_TEST_MLDSA_H
#define WOLFCRYPT_TEST_MLDSA_H

#include <tests/api/api_decl.h>

/* Canonical ML-DSA tests defined in tests/api/test_mldsa.c.
 * These exercise the wc_MlDsaKey / wc_MlDsaKey_* / WC_MLDSA_* API surface
 * directly and run under all build configurations. */
int test_mldsa(void);
int test_mldsa_sign_pubonly_fails(void);
int test_mldsa_make_key(void);
int test_mldsa_sign(void);
int test_mldsa_verify(void);
int test_mldsa_sign_vfy(void);
int test_mldsa_check_key(void);
int test_mldsa_public_der_decode(void);
int test_mldsa_der(void);
int test_mldsa_oneasymkey_version(void);
int test_mldsa_make_key_from_seed(void);
int test_mldsa_sig_kats(void);
int test_mldsa_sign_ctx_kats(void);
int test_mldsa_verify_ctx_kats(void);
int test_mldsa_verify_kats(void);
int test_mldsa_sign_mu_kats(void);
int test_mldsa_verify_mu_kats(void);
int test_mldsa_PrivateKeyDecode_OpenSSL_form(void);
int test_mldsa_pkcs8_import_OpenSSL_form(void);
int test_mldsa_pkcs8_export_import_wolfSSL_form(void);
int test_mldsa_encode_w1_large_values(void);
int test_mldsa_pkcs12(void);
int test_mldsa_x509_pubkey_sigtype(void);

/* Negative length-validation regression tests, also defined in
 * tests/api/test_mldsa.c. */
int test_mldsa_verify_hash(void);
int test_dilithium_hash(void);

/* Legacy-name shim coverage defined in tests/api/test_mldsa_legacy.c.
 * Single function -- compile-time wc_static_assert checks for every alias
 * + one runtime smoke test that drives each arg-reordering macro family.
 * Becomes a TEST_SKIPPED stub when WOLFSSL_NO_DILITHIUM_LEGACY_NAMES is
 * defined. */
int test_mldsa_legacy_shim(void);

#define TEST_MLDSA_DECLS                                                       \
    TEST_DECL_GROUP("mldsa", test_mldsa),                                      \
    TEST_DECL_GROUP("mldsa", test_mldsa_sign_pubonly_fails),                   \
    TEST_DECL_GROUP("mldsa", test_mldsa_make_key),                             \
    TEST_DECL_GROUP("mldsa", test_mldsa_sign),                                 \
    TEST_DECL_GROUP("mldsa", test_mldsa_verify),                               \
    TEST_DECL_GROUP("mldsa", test_mldsa_sign_vfy),                             \
    TEST_DECL_GROUP("mldsa", test_mldsa_check_key),                            \
    TEST_DECL_GROUP("mldsa", test_mldsa_public_der_decode),                    \
    TEST_DECL_GROUP("mldsa", test_mldsa_der),                                  \
    TEST_DECL_GROUP("mldsa", test_mldsa_oneasymkey_version),                   \
    TEST_DECL_GROUP("mldsa", test_mldsa_make_key_from_seed),                   \
    TEST_DECL_GROUP("mldsa", test_mldsa_sig_kats),                             \
    TEST_DECL_GROUP("mldsa", test_mldsa_sign_ctx_kats),                        \
    TEST_DECL_GROUP("mldsa", test_mldsa_verify_ctx_kats),                      \
    TEST_DECL_GROUP("mldsa", test_mldsa_verify_kats),                          \
    TEST_DECL_GROUP("mldsa", test_mldsa_sign_mu_kats),                         \
    TEST_DECL_GROUP("mldsa", test_mldsa_verify_mu_kats),                       \
    TEST_DECL_GROUP("mldsa", test_mldsa_PrivateKeyDecode_OpenSSL_form),        \
    TEST_DECL_GROUP("mldsa", test_mldsa_pkcs8_import_OpenSSL_form),            \
    TEST_DECL_GROUP("mldsa", test_mldsa_pkcs8_export_import_wolfSSL_form),     \
    TEST_DECL_GROUP("mldsa", test_mldsa_encode_w1_large_values),               \
    TEST_DECL_GROUP("mldsa", test_mldsa_pkcs12),                               \
    TEST_DECL_GROUP("mldsa", test_mldsa_x509_pubkey_sigtype),                  \
    TEST_DECL_GROUP("mldsa", test_mldsa_verify_hash),                          \
    TEST_DECL_GROUP("mldsa", test_dilithium_hash),                             \
    TEST_DECL_GROUP("mldsa", test_mldsa_legacy_shim)

#endif /* WOLFCRYPT_TEST_MLDSA_H */
