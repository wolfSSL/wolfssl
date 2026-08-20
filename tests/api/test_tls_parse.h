/* test_tls_parse.h
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

#ifndef TESTS_API_TEST_TLS_PARSE_H
#define TESTS_API_TEST_TLS_PARSE_H

int test_TLSX_ALPN_parse(void);
int test_TLSX_TCA_parse(void);
int test_TLSX_certtype_parse(void);
int test_TLSX_Cookie_parse(void);
int test_TLSX_EncryptThenMac_parse(void);
int test_TLSX_MFL_parse(void);
int test_TLSX_THM_parse(void);
int test_TLSX_SessionTicket_parse(void);
int test_TLSX_SecureRenegotiation_parse(void);
int test_TLSX_SupportedVersions_parse(void);
int test_TLSX_SignatureAlgorithms_parse(void);
int test_TLSX_CSR_parse(void);
int test_TLSX_PointFormat_parse(void);
int test_TLSX_SNI_parse(void);
int test_TLSX_ValidateSupportedCurves(void);

#define TEST_TLS_PARSE_DECLS                                               \
        TEST_DECL_GROUP("tls", test_TLSX_ALPN_parse),                     \
        TEST_DECL_GROUP("tls", test_TLSX_TCA_parse),                      \
        TEST_DECL_GROUP("tls", test_TLSX_certtype_parse),                 \
        TEST_DECL_GROUP("tls", test_TLSX_Cookie_parse),                   \
        TEST_DECL_GROUP("tls", test_TLSX_EncryptThenMac_parse),           \
        TEST_DECL_GROUP("tls", test_TLSX_MFL_parse),                      \
        TEST_DECL_GROUP("tls", test_TLSX_THM_parse),                      \
        TEST_DECL_GROUP("tls", test_TLSX_SessionTicket_parse),            \
        TEST_DECL_GROUP("tls", test_TLSX_SecureRenegotiation_parse),      \
        TEST_DECL_GROUP("tls", test_TLSX_SupportedVersions_parse),        \
        TEST_DECL_GROUP("tls", test_TLSX_SignatureAlgorithms_parse),      \
        TEST_DECL_GROUP("tls", test_TLSX_CSR_parse),                      \
        TEST_DECL_GROUP("tls", test_TLSX_PointFormat_parse),              \
        TEST_DECL_GROUP("tls", test_TLSX_SNI_parse),                      \
        TEST_DECL_GROUP("tls", test_TLSX_ValidateSupportedCurves)

#endif /* TESTS_API_TEST_TLS_PARSE_H */
