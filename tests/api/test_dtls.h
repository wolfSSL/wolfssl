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
#endif /* TESTS_API_DTLS_H */
