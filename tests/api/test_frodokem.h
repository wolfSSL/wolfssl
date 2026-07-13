/* test_frodokem.h
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

#ifndef WOLFCRYPT_TEST_FRODOKEM_H
#define WOLFCRYPT_TEST_FRODOKEM_H

#include <tests/api/api_decl.h>

int test_wc_frodokem_make_key_kats(void);
int test_wc_frodokem_encapsulate_kats(void);
int test_wc_frodokem_decapsulate_kats(void);
int test_wc_frodokem_roundtrip(void);
int test_wc_frodokem_encode_decode(void);
int test_wc_frodokem_decap_implicit_reject(void);
int test_wc_frodokem_decapsulate_pubonly_fails(void);
int test_wc_frodokem_decode_privkey_bad_pkh(void);
int test_wc_frodokem_bad_args(void);
int test_wc_frodokem_op_len_checks(void);
int test_wc_frodokem_new_delete(void);
int test_wc_frodokem_not_compiled_in(void);
int test_wc_frodokem_asn1(void);
int test_wc_frodokem_key_pem(void);
int test_wc_frodokem_x509(void);
int test_wc_frodokem_cert_file(void);
int test_wc_frodokem_cert_verify(void);

#define TEST_FRODOKEM_DECLS                                                 \
    TEST_DECL_GROUP("frodokem", test_wc_frodokem_make_key_kats),            \
    TEST_DECL_GROUP("frodokem", test_wc_frodokem_encapsulate_kats),         \
    TEST_DECL_GROUP("frodokem", test_wc_frodokem_decapsulate_kats),         \
    TEST_DECL_GROUP("frodokem", test_wc_frodokem_roundtrip),                \
    TEST_DECL_GROUP("frodokem", test_wc_frodokem_encode_decode),            \
    TEST_DECL_GROUP("frodokem", test_wc_frodokem_decap_implicit_reject),    \
    TEST_DECL_GROUP("frodokem", test_wc_frodokem_decapsulate_pubonly_fails),\
    TEST_DECL_GROUP("frodokem", test_wc_frodokem_decode_privkey_bad_pkh),   \
    TEST_DECL_GROUP("frodokem", test_wc_frodokem_bad_args),                 \
    TEST_DECL_GROUP("frodokem", test_wc_frodokem_op_len_checks),            \
    TEST_DECL_GROUP("frodokem", test_wc_frodokem_new_delete),               \
    TEST_DECL_GROUP("frodokem", test_wc_frodokem_not_compiled_in),          \
    TEST_DECL_GROUP("frodokem", test_wc_frodokem_asn1),                     \
    TEST_DECL_GROUP("frodokem", test_wc_frodokem_key_pem),                  \
    TEST_DECL_GROUP("frodokem", test_wc_frodokem_x509),                     \
    TEST_DECL_GROUP("frodokem", test_wc_frodokem_cert_file),                \
    TEST_DECL_GROUP("frodokem", test_wc_frodokem_cert_verify)

#endif /* WOLFCRYPT_TEST_FRODOKEM_H */
