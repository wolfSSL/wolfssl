/* test_tls.h
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

#ifndef TESTS_API_TEST_TLS_H
#define TESTS_API_TEST_TLS_H

int test_utils_memio_move_message(void);
int test_tls12_unexpected_ccs(void);
int test_tls13_unexpected_ccs(void);
int test_tls12_curve_intersection(void);
int test_tls13_curve_intersection(void);
int test_tls_certreq_order(void);
int test_tls12_bad_cv_sig_alg(void);
int test_tls12_no_null_compression(void);
int test_tls12_etm_failed_resumption(void);
int test_tls_set_curves_list_ecc_fallback(void);
int test_tls_tlsx_sni_parse_coverage(void);
int test_tls_tlsx_sni_options_coverage(void);
int test_tls_tlsx_sc_parse_coverage(void);
int test_tls_tlsx_sv_parse_coverage(void);
int test_tls_build_handshake_hash_coverage(void);
int test_tls_tlsx_parse_coverage(void);
int test_tls_tlsx_validate_curves_coverage(void);
int test_tls_tlsx_psk_coverage(void);
int test_tls_tlsx_keyshare_coverage(void);
int test_tls_tlsx_csr_coverage(void);
int test_tls_tlsx_write_request_coverage(void);
int test_tls_tlsx_parse_guards_coverage(void);
int test_tls_tlsx_sc_fuzz_coverage(void);
int test_tls_tlsx_sni_fuzz_coverage(void);
int test_tls_tlsx_psk_fuzz_coverage(void);
int test_tls_tlsx_csr_fuzz_coverage(void);
int test_tls_tlsx_parse_guards_batch4(void);
int test_tls_tlsx_keyshare_parse_batch4(void);
int test_tls_tlsx_support_extensions_batch4(void);
int test_tls_tlsx_psk_parse_sh_batch4(void);
int test_tls_build_handshake_hash_batch4(void);
int test_tls_tlsx_parse_msgtype_batch4(void);

#define TEST_TLS_DECLS                                                         \
        TEST_DECL_GROUP("tls", test_utils_memio_move_message),                 \
        TEST_DECL_GROUP("tls", test_tls12_unexpected_ccs),                     \
        TEST_DECL_GROUP("tls", test_tls13_unexpected_ccs),                     \
        TEST_DECL_GROUP("tls", test_tls12_curve_intersection),                 \
        TEST_DECL_GROUP("tls", test_tls13_curve_intersection),                 \
        TEST_DECL_GROUP("tls", test_tls_certreq_order),                        \
        TEST_DECL_GROUP("tls", test_tls12_bad_cv_sig_alg),                     \
        TEST_DECL_GROUP("tls", test_tls12_no_null_compression),                \
        TEST_DECL_GROUP("tls", test_tls12_etm_failed_resumption),              \
        TEST_DECL_GROUP("tls", test_tls_set_curves_list_ecc_fallback),         \
        TEST_DECL_GROUP("tls", test_tls_tlsx_sni_parse_coverage),              \
        TEST_DECL_GROUP("tls", test_tls_tlsx_sni_options_coverage),            \
        TEST_DECL_GROUP("tls", test_tls_tlsx_sc_parse_coverage),               \
        TEST_DECL_GROUP("tls", test_tls_tlsx_sv_parse_coverage),               \
        TEST_DECL_GROUP("tls", test_tls_build_handshake_hash_coverage),        \
        TEST_DECL_GROUP("tls", test_tls_tlsx_parse_coverage),                  \
        TEST_DECL_GROUP("tls", test_tls_tlsx_validate_curves_coverage),        \
        TEST_DECL_GROUP("tls", test_tls_tlsx_psk_coverage),                    \
        TEST_DECL_GROUP("tls", test_tls_tlsx_keyshare_coverage),               \
        TEST_DECL_GROUP("tls", test_tls_tlsx_csr_coverage),                    \
        TEST_DECL_GROUP("tls", test_tls_tlsx_write_request_coverage),          \
        TEST_DECL_GROUP("tls", test_tls_tlsx_parse_guards_coverage),           \
        TEST_DECL_GROUP("tls", test_tls_tlsx_sc_fuzz_coverage),                \
        TEST_DECL_GROUP("tls", test_tls_tlsx_sni_fuzz_coverage),               \
        TEST_DECL_GROUP("tls", test_tls_tlsx_psk_fuzz_coverage),               \
        TEST_DECL_GROUP("tls", test_tls_tlsx_csr_fuzz_coverage),               \
        TEST_DECL_GROUP("tls", test_tls_tlsx_parse_guards_batch4),             \
        TEST_DECL_GROUP("tls", test_tls_tlsx_keyshare_parse_batch4),           \
        TEST_DECL_GROUP("tls", test_tls_tlsx_support_extensions_batch4),       \
        TEST_DECL_GROUP("tls", test_tls_tlsx_psk_parse_sh_batch4),             \
        TEST_DECL_GROUP("tls", test_tls_build_handshake_hash_batch4),          \
        TEST_DECL_GROUP("tls", test_tls_tlsx_parse_msgtype_batch4)

#endif /* TESTS_API_TEST_TLS_H */
