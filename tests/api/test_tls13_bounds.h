/* test_tls13_bounds.h
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

#ifndef WOLFCRYPT_TEST_TLS13_BOUNDS_H
#define WOLFCRYPT_TEST_TLS13_BOUNDS_H

#include <tests/api/api_decl.h>

int test_tls13_ch_legacy_version_is_tls13(void);
int test_tls13_ch_legacy_version_major_above_ssl3(void);
int test_tls13_ch_legacy_version_below_tls12(void);
int test_tls13_sh_legacy_version_below_tls12(void);
int test_tls13_sh_legacy_version_major_mismatch(void);
int test_tls13_server_cert_fragment_want_write(void);
int test_tls13_client_cert_fragment_want_write(void);
int test_tls13_sh_empty_extensions_block(void);
int test_tls13_ch_supported_versions_tls12_only(void);
int test_tls13_ech_accepted_handshake(void);
int test_tls13_ech_rejected_handshake(void);

#define TEST_TLS13_BOUNDS_DECLS                                             \
    TEST_DECL_GROUP("tls13", test_tls13_ch_legacy_version_is_tls13),        \
    TEST_DECL_GROUP("tls13", test_tls13_ch_legacy_version_major_above_ssl3),\
    TEST_DECL_GROUP("tls13", test_tls13_ch_legacy_version_below_tls12),     \
    TEST_DECL_GROUP("tls13", test_tls13_sh_legacy_version_below_tls12),     \
    TEST_DECL_GROUP("tls13", test_tls13_sh_legacy_version_major_mismatch),  \
    TEST_DECL_GROUP("tls13", test_tls13_server_cert_fragment_want_write),   \
    TEST_DECL_GROUP("tls13", test_tls13_client_cert_fragment_want_write),   \
    TEST_DECL_GROUP("tls13", test_tls13_sh_empty_extensions_block),         \
    TEST_DECL_GROUP("tls13", test_tls13_ch_supported_versions_tls12_only),  \
    TEST_DECL_GROUP("tls13", test_tls13_ech_accepted_handshake),            \
    TEST_DECL_GROUP("tls13", test_tls13_ech_rejected_handshake)

#endif /* WOLFCRYPT_TEST_TLS13_BOUNDS_H */
