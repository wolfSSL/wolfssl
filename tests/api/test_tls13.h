/* test_tls13.h
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

#ifndef WOLFCRYPT_TEST_TLS13_H
#define WOLFCRYPT_TEST_TLS13_H

#include <tests/api/api_decl.h>

int test_tls13_apis(void);
int test_tls13_cipher_suites(void);
int test_tls13_bad_psk_binder(void);
int test_tls13_rpk_handshake(void);
int test_tls13_pq_groups(void);
int test_tls13_early_data(void);
int test_tls13_same_ch(void);
int test_tls13_hrr_different_cs(void);
int test_tls13_ch2_different_cs(void);
int test_tls13_sg_missing(void);
int test_tls13_ks_missing(void);
int test_tls13_duplicate_extension(void);
int test_tls13_duplicate_ech_extension(void);
int test_key_share_mismatch(void);
int test_tls13_middlebox_compat_empty_session_id(void);
int test_tls13_plaintext_alert(void);
int test_tls13_warning_alert_is_fatal(void);
int test_tls13_unknown_ext_rejected(void);
int test_tls13_cert_req_sigalgs(void);
int test_tls13_derive_keys_no_key(void);
int test_tls13_pqc_hybrid_truncated_keyshare(void);
int test_tls13_empty_record_limit(void);
int test_tls13_short_session_ticket(void);
int test_tls13_early_data_0rtt_replay(void);
int test_tls13_corrupted_finished(void);
int test_tls13_peerauth_failsafe(void);
int test_tls13_hrr_bad_cookie(void);
int test_tls13_zero_inner_content_type(void);
int test_tls13_downgrade_sentinel(void);
int test_tls13_serverhello_bad_cipher_suites(void);
int test_tls13_cert_with_extern_psk_apis(void);
int test_tls13_cert_with_extern_psk_handshake(void);
int test_tls13_cert_with_extern_psk_requires_key_share(void);
int test_tls13_cert_with_extern_psk_rejects_resumption(void);
int test_tls13_cert_with_extern_psk_sh_missing_key_share(void);
int test_tls13_cert_with_extern_psk_sh_confirms_resumption(void);

#define TEST_TLS13_DECLS                                        \
    TEST_DECL_GROUP("tls13", test_tls13_apis),                  \
    TEST_DECL_GROUP("tls13", test_tls13_cipher_suites),         \
    TEST_DECL_GROUP("tls13", test_tls13_bad_psk_binder),        \
    TEST_DECL_GROUP("tls13", test_tls13_rpk_handshake),         \
    TEST_DECL_GROUP("tls13", test_tls13_pq_groups),             \
    TEST_DECL_GROUP("tls13", test_tls13_early_data),            \
    TEST_DECL_GROUP("tls13", test_tls13_same_ch),               \
    TEST_DECL_GROUP("tls13", test_tls13_hrr_different_cs),      \
    TEST_DECL_GROUP("tls13", test_tls13_ch2_different_cs),      \
    TEST_DECL_GROUP("tls13", test_tls13_sg_missing),            \
    TEST_DECL_GROUP("tls13", test_tls13_ks_missing),            \
    TEST_DECL_GROUP("tls13", test_tls13_duplicate_extension),   \
    TEST_DECL_GROUP("tls13", test_tls13_duplicate_ech_extension), \
    TEST_DECL_GROUP("tls13", test_key_share_mismatch),          \
    TEST_DECL_GROUP("tls13", test_tls13_middlebox_compat_empty_session_id), \
    TEST_DECL_GROUP("tls13", test_tls13_plaintext_alert),       \
    TEST_DECL_GROUP("tls13", test_tls13_warning_alert_is_fatal), \
    TEST_DECL_GROUP("tls13", test_tls13_cert_req_sigalgs),       \
    TEST_DECL_GROUP("tls13", test_tls13_derive_keys_no_key),    \
    TEST_DECL_GROUP("tls13", test_tls13_pqc_hybrid_truncated_keyshare), \
    TEST_DECL_GROUP("tls13", test_tls13_empty_record_limit),    \
    TEST_DECL_GROUP("tls13", test_tls13_short_session_ticket),  \
    TEST_DECL_GROUP("tls13", test_tls13_early_data_0rtt_replay), \
    TEST_DECL_GROUP("tls13", test_tls13_unknown_ext_rejected),  \
    TEST_DECL_GROUP("tls13", test_tls13_corrupted_finished),     \
    TEST_DECL_GROUP("tls13", test_tls13_peerauth_failsafe),    \
    TEST_DECL_GROUP("tls13", test_tls13_hrr_bad_cookie), \
    TEST_DECL_GROUP("tls13", test_tls13_zero_inner_content_type), \
    TEST_DECL_GROUP("tls13", test_tls13_downgrade_sentinel), \
    TEST_DECL_GROUP("tls13", test_tls13_serverhello_bad_cipher_suites), \
    TEST_DECL_GROUP("tls13", test_tls13_cert_with_extern_psk_apis), \
    TEST_DECL_GROUP("tls13", test_tls13_cert_with_extern_psk_handshake), \
    TEST_DECL_GROUP("tls13", test_tls13_cert_with_extern_psk_requires_key_share), \
    TEST_DECL_GROUP("tls13", test_tls13_cert_with_extern_psk_rejects_resumption), \
    TEST_DECL_GROUP("tls13", test_tls13_cert_with_extern_psk_sh_missing_key_share), \
    TEST_DECL_GROUP("tls13", test_tls13_cert_with_extern_psk_sh_confirms_resumption)

#endif /* WOLFCRYPT_TEST_TLS13_H */
