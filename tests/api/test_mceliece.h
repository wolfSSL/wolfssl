/* test_mceliece.h
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

#ifndef WOLFCRYPT_TEST_MCELIECE_H
#define WOLFCRYPT_TEST_MCELIECE_H

#include <tests/api/api_decl.h>

int test_wc_mceliece_roundtrip(void);
int test_wc_mceliece_encode_decode(void);
int test_wc_mceliece_kat_decap(void);
int test_wc_mceliece_kat_keygen_encap(void);
int test_wc_mceliece_make_key_deterministic(void);
int test_wc_mceliece_encapsulate_deterministic(void);
int test_wc_mceliece_decap_pc_reject(void);
int test_wc_mceliece_decap_corrupt_reject(void);
int test_wc_mceliece_decap_reject_deterministic(void);
int test_wc_mceliece_decap_reject_distinct(void);
int test_wc_mceliece_decap_padding_reject(void);
int test_wc_mceliece_encap_tau_8192128(void);
int test_wc_mceliece_decapsulate_pubonly_fails(void);
int test_wc_mceliece_bad_args(void);
int test_wc_mceliece_op_bad_args(void);
int test_wc_mceliece_op_len_checks(void);
int test_wc_mceliece_pk_padding_reject(void);
int test_wc_mceliece_new_delete(void);
int test_wc_mceliece_not_compiled_in(void);

#define TEST_MCELIECE_DECLS                                                 \
    TEST_DECL_GROUP("mceliece", test_wc_mceliece_roundtrip),               \
    TEST_DECL_GROUP("mceliece", test_wc_mceliece_encode_decode),           \
    TEST_DECL_GROUP("mceliece", test_wc_mceliece_kat_decap),               \
    TEST_DECL_GROUP("mceliece", test_wc_mceliece_kat_keygen_encap),        \
    TEST_DECL_GROUP("mceliece", test_wc_mceliece_make_key_deterministic),  \
    TEST_DECL_GROUP("mceliece", test_wc_mceliece_encapsulate_deterministic),\
    TEST_DECL_GROUP("mceliece", test_wc_mceliece_decap_pc_reject),         \
    TEST_DECL_GROUP("mceliece", test_wc_mceliece_decap_corrupt_reject),    \
    TEST_DECL_GROUP("mceliece", test_wc_mceliece_decap_reject_deterministic),\
    TEST_DECL_GROUP("mceliece", test_wc_mceliece_decap_reject_distinct),   \
    TEST_DECL_GROUP("mceliece", test_wc_mceliece_decap_padding_reject),    \
    TEST_DECL_GROUP("mceliece", test_wc_mceliece_encap_tau_8192128),       \
    TEST_DECL_GROUP("mceliece", test_wc_mceliece_decapsulate_pubonly_fails),\
    TEST_DECL_GROUP("mceliece", test_wc_mceliece_bad_args),                \
    TEST_DECL_GROUP("mceliece", test_wc_mceliece_op_bad_args),             \
    TEST_DECL_GROUP("mceliece", test_wc_mceliece_op_len_checks),           \
    TEST_DECL_GROUP("mceliece", test_wc_mceliece_pk_padding_reject),       \
    TEST_DECL_GROUP("mceliece", test_wc_mceliece_new_delete),              \
    TEST_DECL_GROUP("mceliece", test_wc_mceliece_not_compiled_in)

#endif /* WOLFCRYPT_TEST_MCELIECE_H */
