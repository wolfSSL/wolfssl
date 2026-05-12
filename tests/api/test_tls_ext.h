/* test_tls_ext.h
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

#ifndef TESTS_API_TEST_TLS_EXT_H
#define TESTS_API_TEST_TLS_EXT_H

int test_tls_ems_downgrade(void);
int test_tls_ems_resumption_downgrade(void);
int test_tls12_chacha20_poly1305_bad_tag(void);
int test_tls13_null_cipher_bad_hmac(void);
int test_scr_verify_data_mismatch(void);
int test_tls13_hrr_cipher_suite_mismatch(void);
int test_tls13_ticket_age_out_of_window(void);
int test_wolfSSL_DisableExtendedMasterSecret(void);
int test_certificate_authorities_certificate_request(void);
int test_certificate_authorities_client_hello(void);
int test_TLSX_TCA_Find(void);
int test_TLSX_SNI_GetSize_overflow(void);
int test_TLSX_ECH_msg_type_validation(void);
int test_TLSX_SRTP_msg_type_validation(void);

#endif /* TESTS_API_TEST_TLS_EMS_H */
