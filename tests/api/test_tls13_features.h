/* test_tls13_features.h
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

#ifndef WOLFCRYPT_TEST_TLS13_FEATURES_H
#define WOLFCRYPT_TEST_TLS13_FEATURES_H

#include <tests/api/api_decl.h>

int test_tls13_feat_optional_client_cert(void);
int test_tls13_feat_post_handshake_unexpected_msg(void);
int test_tls13_feat_psk_ke_no_dhe(void);
int test_tls13_feat_psk_only_dhe_ignores_psk_ke(void);
int test_tls13_feat_no_ticket_enc_cb(void);
int test_tls13_feat_psk_ke_empty_key_share(void);
int test_tls13_feat_optional_psk_falls_back_to_cert(void);
int test_tls13_feat_pha_ctx_status_request(void);
int test_tls13_feat_psk_ke_server_key_share_unused(void);
int test_tls13_feat_psk_ke_server_no_key_share(void);
int test_tls13_feat_psk_ke_client_require_psk_resumption(void);
int test_tls13_feat_hrr_cookie_handshake(void);
int test_tls13_feat_hrr_cookie_forces_retry(void);
int test_tls13_feat_cert_with_extern_psk_psk_ke_server(void);
int test_tls13_feat_ech_full_handshake(void);
int test_tls13_feat_ech_disabled_client(void);
int test_tls13_feat_ech_disabled_server(void);
int test_tls13_feat_ech_rejected_with_psk(void);
int test_tls13_feat_ech_psk_disabled_client(void);

#define TEST_TLS13_FEATURES_DECLS                                            \
    TEST_DECL_GROUP("tls13", test_tls13_feat_optional_client_cert),          \
    TEST_DECL_GROUP("tls13", test_tls13_feat_post_handshake_unexpected_msg), \
    TEST_DECL_GROUP("tls13", test_tls13_feat_psk_ke_no_dhe),                 \
    TEST_DECL_GROUP("tls13", test_tls13_feat_psk_only_dhe_ignores_psk_ke),   \
    TEST_DECL_GROUP("tls13", test_tls13_feat_no_ticket_enc_cb),                \
    TEST_DECL_GROUP("tls13", test_tls13_feat_psk_ke_empty_key_share),          \
    TEST_DECL_GROUP("tls13", test_tls13_feat_optional_psk_falls_back_to_cert), \
    TEST_DECL_GROUP("tls13", test_tls13_feat_pha_ctx_status_request),          \
    TEST_DECL_GROUP("tls13", test_tls13_feat_psk_ke_server_key_share_unused),  \
    TEST_DECL_GROUP("tls13", test_tls13_feat_psk_ke_server_no_key_share),      \
    TEST_DECL_GROUP("tls13", test_tls13_feat_psk_ke_client_require_psk_resumption), \
    TEST_DECL_GROUP("tls13", test_tls13_feat_hrr_cookie_handshake),            \
    TEST_DECL_GROUP("tls13", test_tls13_feat_hrr_cookie_forces_retry),         \
    TEST_DECL_GROUP("tls13", test_tls13_feat_cert_with_extern_psk_psk_ke_server), \
    TEST_DECL_GROUP("tls13", test_tls13_feat_ech_full_handshake),              \
    TEST_DECL_GROUP("tls13", test_tls13_feat_ech_disabled_client),             \
    TEST_DECL_GROUP("tls13", test_tls13_feat_ech_disabled_server),             \
    TEST_DECL_GROUP("tls13", test_tls13_feat_ech_psk_disabled_client),         \
    TEST_DECL_GROUP("tls13", test_tls13_feat_ech_rejected_with_psk)

#endif /* WOLFCRYPT_TEST_TLS13_FEATURES_H */
