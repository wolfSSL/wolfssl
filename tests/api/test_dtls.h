/* test_dtls.h
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

#ifndef TESTS_API_DTLS_H
#define TESTS_API_DTLS_H

int test_dtls12_basic_connection_id(void);
int test_wolfSSL_dtls_cid_parse(void);
int test_wolfSSL_dtls_set_pending_peer(void);
int test_dtls_version_checking(void);
int test_dtls_short_ciphertext(void);
int test_dtls12_record_length_mismatch(void);
int test_dtls12_short_read(void);
int test_dtls13_longer_length(void);
int test_dtls13_short_read(void);
int test_records_span_network_boundaries(void);
int test_dtls_record_cross_boundaries(void);
int test_dtls_rtx_across_epoch_change(void);
int test_dtls_drop_client_ack(void);
int test_dtls_bogus_finished_epoch_zero(void);
int test_dtls_replay(void);
int test_dtls_timeout(void);
int test_dtls_certreq_order(void);
int test_dtls_memio_wolfio(void);
int test_dtls_memio_wolfio_stateless(void);
int test_dtls_mtu_fragment_headroom(void);
int test_dtls_mtu_split_messages(void);
int test_dtls_set_session_min_downgrade(void);

/* DTLS tests moved out of tests/api.c. */
int test_dtls_msg_from_other_peer(void);
int test_dtls_ipv6_check(void);
int test_dtls_no_extensions(void);
int test_dtls_1_0_hvr_downgrade(void);
int test_dtls_downgrade_scr_server(void);
int test_dtls_downgrade_scr(void);
int test_dtls_client_hello_timeout_downgrade(void);
int test_dtls_client_hello_timeout(void);
int test_dtls_dropped_ccs(void);
int test_dtls_seq_num_downgrade(void);
int test_dtls_old_seq_number(void);
int test_dtls12_missing_finished(void);
int test_wolfSSL_dtls_export(void);
int test_wolfSSL_dtls_export_peers(void);
int test_wolfSSL_dtls_import_state_extra_window_words(void);
int test_wolfSSL_DTLS_either_side(void);
int test_generate_cookie(void);
int test_wolfSSL_dtls_set_mtu(void);
int test_wolfSSL_dtls_plaintext(void);
int test_wolfSSL_dtls_fragments(void);
int test_wolfSSL_ignore_alert_before_cookie(void);
int test_wolfSSL_dtls_bad_record(void);
int test_wolfSSL_dtls_AEAD_limit(void);
int test_wolfSSL_dtls_stateless(void);
int test_wolfSSL_dtls_stateless_hrr_group(void);
int test_wolfSSL_DtlsUpdateWindow(void);
int test_wolfSSL_DTLS_fragment_buckets(void);
int test_wolfSSL_dtls_stateless2(void);
int test_wolfSSL_dtls_stateless_maxfrag(void);
int test_wolfSSL_dtls_stateless_resume(void);
int test_wolfSSL_dtls_stateless_downgrade(void);
int test_WOLFSSL_dtls_version_alert(void);

#define TEST_DTLS_DECLS                                                        \
        TEST_DECL_GROUP("dtls", test_dtls12_basic_connection_id),              \
        TEST_DECL_GROUP("dtls", test_wolfSSL_dtls_cid_parse),                  \
        TEST_DECL_GROUP("dtls", test_wolfSSL_dtls_set_pending_peer),           \
        TEST_DECL_GROUP("dtls", test_dtls_version_checking),                   \
        TEST_DECL_GROUP("dtls", test_dtls_short_ciphertext),                   \
        TEST_DECL_GROUP("dtls", test_dtls12_record_length_mismatch),           \
        TEST_DECL_GROUP("dtls", test_dtls12_short_read),                       \
        TEST_DECL_GROUP("dtls", test_dtls13_longer_length),                    \
        TEST_DECL_GROUP("dtls", test_dtls13_short_read),                       \
        TEST_DECL_GROUP("dtls", test_records_span_network_boundaries),         \
        TEST_DECL_GROUP("dtls", test_dtls_record_cross_boundaries),            \
        TEST_DECL_GROUP("dtls", test_dtls_rtx_across_epoch_change),            \
        TEST_DECL_GROUP("dtls", test_dtls_drop_client_ack),                    \
        TEST_DECL_GROUP("dtls", test_dtls_bogus_finished_epoch_zero),          \
        TEST_DECL_GROUP("dtls", test_dtls_replay),                             \
        TEST_DECL_GROUP("dtls", test_dtls_certreq_order),                      \
        TEST_DECL_GROUP("dtls", test_dtls_timeout),                            \
        TEST_DECL_GROUP("dtls", test_dtls_memio_wolfio),                       \
        TEST_DECL_GROUP("dtls", test_dtls_mtu_fragment_headroom),              \
        TEST_DECL_GROUP("dtls", test_dtls_mtu_split_messages),                 \
        TEST_DECL_GROUP("dtls", test_dtls_memio_wolfio_stateless),             \
        TEST_DECL_GROUP("dtls", test_dtls_set_session_min_downgrade),          \
        TEST_DECL_GROUP("dtls", test_wolfSSL_dtls_export),                     \
        TEST_DECL_GROUP("dtls", test_wolfSSL_dtls_export_peers),               \
        TEST_DECL_GROUP("dtls", test_wolfSSL_dtls_import_state_extra_window_words), \
        TEST_DECL_GROUP("dtls", test_wolfSSL_DTLS_either_side),                \
        TEST_DECL_GROUP("dtls", test_generate_cookie),                         \
        TEST_DECL_GROUP("dtls", test_wolfSSL_dtls_set_mtu),                    \
        TEST_DECL_GROUP("dtls", test_wolfSSL_dtls_plaintext),                  \
        TEST_DECL_GROUP("dtls", test_wolfSSL_dtls_fragments),                  \
        TEST_DECL_GROUP("dtls", test_wolfSSL_ignore_alert_before_cookie),      \
        TEST_DECL_GROUP("dtls", test_wolfSSL_dtls_bad_record),                 \
        TEST_DECL_GROUP("dtls", test_wolfSSL_dtls_AEAD_limit),                 \
        TEST_DECL_GROUP("dtls", test_wolfSSL_dtls_stateless),                  \
        TEST_DECL_GROUP("dtls", test_wolfSSL_dtls_stateless_hrr_group),        \
        TEST_DECL_GROUP("dtls", test_wolfSSL_DtlsUpdateWindow),                \
        TEST_DECL_GROUP("dtls", test_wolfSSL_DTLS_fragment_buckets),           \
        TEST_DECL_GROUP("dtls", test_wolfSSL_dtls_stateless2),                 \
        TEST_DECL_GROUP("dtls", test_wolfSSL_dtls_stateless_maxfrag),          \
        TEST_DECL_GROUP("dtls", test_wolfSSL_dtls_stateless_resume),           \
        TEST_DECL_GROUP("dtls", test_wolfSSL_dtls_stateless_downgrade),        \
        TEST_DECL_GROUP("dtls", test_WOLFSSL_dtls_version_alert),              \
        TEST_DECL_GROUP("dtls", test_dtls_msg_from_other_peer),                \
        TEST_DECL_GROUP("dtls", test_dtls_ipv6_check),                         \
        TEST_DECL_GROUP("dtls", test_dtls_no_extensions),                      \
        TEST_DECL_GROUP("dtls", test_dtls_1_0_hvr_downgrade),                  \
        TEST_DECL_GROUP("dtls", test_dtls_downgrade_scr_server),               \
        TEST_DECL_GROUP("dtls", test_dtls_downgrade_scr),                      \
        TEST_DECL_GROUP("dtls", test_dtls_client_hello_timeout_downgrade),     \
        TEST_DECL_GROUP("dtls", test_dtls_client_hello_timeout),               \
        TEST_DECL_GROUP("dtls", test_dtls_dropped_ccs),                        \
        TEST_DECL_GROUP("dtls", test_dtls_seq_num_downgrade),                  \
        TEST_DECL_GROUP("dtls", test_dtls_old_seq_number),                     \
        TEST_DECL_GROUP("dtls", test_dtls12_missing_finished)
#endif /* TESTS_API_DTLS_H */
