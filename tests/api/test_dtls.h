/* test_dtls.h
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

#ifndef TESTS_API_DTLS_H
#define TESTS_API_DTLS_H

int test_dtls12_basic_connection_id(void);
int test_dtls13_basic_connection_id(void);
int test_dtls13_hrr_want_write(void);
int test_dtls13_every_write_want_write(void);
int test_wolfSSL_dtls_cid_parse(void);
int test_wolfSSL_dtls_set_pending_peer(void);
int test_dtls13_epochs(void);
int test_dtls13_ack_order(void);
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
int test_dtls_srtp(void);
int test_dtls_timeout(void);
int test_dtls_certreq_order(void);
int test_dtls_memio_wolfio(void);
int test_dtls_memio_wolfio_stateless(void);

#define TEST_DTLS_DECLS                                                        \
        TEST_DECL_GROUP("dtls", test_dtls12_basic_connection_id),              \
        TEST_DECL_GROUP("dtls", test_dtls13_basic_connection_id),              \
        TEST_DECL_GROUP("dtls", test_dtls13_hrr_want_write),                   \
        TEST_DECL_GROUP("dtls", test_dtls13_every_write_want_write),           \
        TEST_DECL_GROUP("dtls", test_wolfSSL_dtls_cid_parse),                  \
        TEST_DECL_GROUP("dtls", test_wolfSSL_dtls_set_pending_peer),           \
        TEST_DECL_GROUP("dtls", test_dtls13_epochs),                           \
        TEST_DECL_GROUP("dtls", test_dtls13_ack_order),                        \
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
        TEST_DECL_GROUP("dtls", test_dtls_srtp),                               \
        TEST_DECL_GROUP("dtls", test_dtls_certreq_order),                      \
        TEST_DECL_GROUP("dtls", test_dtls_timeout),                            \
        TEST_DECL_GROUP("dtls", test_dtls_memio_wolfio),                       \
        TEST_DECL_GROUP("dtls", test_dtls_memio_wolfio_stateless)
#endif /* TESTS_API_DTLS_H */
