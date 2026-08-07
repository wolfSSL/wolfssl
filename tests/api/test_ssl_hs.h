/* test_ssl_hs.h
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

#ifndef TESTS_API_SSL_HS_H
#define TESTS_API_SSL_HS_H

#include <tests/api/api_decl.h>

int test_wolfSSL_state_string_long(void);
int test_wolfSSL_state_string_long_states(void);
int test_wolfSSL_set_connect_accept_state(void);
int test_wolfSSL_SSL_do_handshake(void);
int test_wolfSSL_SSL_in_init_hs(void);
int test_wolfSSL_is_init_finished(void);
int test_wolfSSL_SetHsDoneCb(void);
int test_wolfSSL_pk_callback_ctx(void);
int test_wolfSSL_set_accept_state_reinit(void);
int test_wolfSSL_set_accept_state_static_ecc(void);
int test_wolfSSL_negotiate_bad_args(void);
int test_wolfSSL_SSL_do_handshake_quic(void);
int test_wolfSSL_set_connect_state_dh(void);
int test_wolfSSL_connect_bad_args(void);
int test_wolfSSL_accept_bad_args(void);
int test_wolfSSL_connect_step_failures(void);
int test_wolfSSL_accept_step_failures(void);
int test_wolfSSL_hs_send_buffered_fail(void);
int test_wolfSSL_hs_send_buffered_advance(void);
int test_wolfSSL_hs_retry_alert_fail(void);
int test_wolfSSL_connect_ex_no_side(void);
int test_wolfSSL_hs_done_cb_error(void);
int test_wolfSSL_hs_info_cb(void);

#define TEST_SSL_HS_DECLS                                                      \
        TEST_DECL_GROUP("ssl_hs", test_wolfSSL_state_string_long),             \
        TEST_DECL_GROUP("ssl_hs", test_wolfSSL_state_string_long_states),      \
        TEST_DECL_GROUP("ssl_hs", test_wolfSSL_set_connect_accept_state),      \
        TEST_DECL_GROUP("ssl_hs", test_wolfSSL_SSL_do_handshake),              \
        TEST_DECL_GROUP("ssl_hs", test_wolfSSL_SSL_in_init_hs),                \
        TEST_DECL_GROUP("ssl_hs", test_wolfSSL_is_init_finished),              \
        TEST_DECL_GROUP("ssl_hs", test_wolfSSL_SetHsDoneCb),                   \
        TEST_DECL_GROUP("ssl_hs", test_wolfSSL_pk_callback_ctx),               \
        TEST_DECL_GROUP("ssl_hs", test_wolfSSL_set_accept_state_reinit),       \
        TEST_DECL_GROUP("ssl_hs", test_wolfSSL_set_accept_state_static_ecc),   \
        TEST_DECL_GROUP("ssl_hs", test_wolfSSL_negotiate_bad_args),            \
        TEST_DECL_GROUP("ssl_hs", test_wolfSSL_SSL_do_handshake_quic),         \
        TEST_DECL_GROUP("ssl_hs", test_wolfSSL_set_connect_state_dh),          \
        TEST_DECL_GROUP("ssl_hs", test_wolfSSL_connect_bad_args),              \
        TEST_DECL_GROUP("ssl_hs", test_wolfSSL_accept_bad_args),               \
        TEST_DECL_GROUP("ssl_hs", test_wolfSSL_connect_step_failures),         \
        TEST_DECL_GROUP("ssl_hs", test_wolfSSL_accept_step_failures),          \
        TEST_DECL_GROUP("ssl_hs", test_wolfSSL_hs_send_buffered_fail),         \
        TEST_DECL_GROUP("ssl_hs", test_wolfSSL_hs_send_buffered_advance),      \
        TEST_DECL_GROUP("ssl_hs", test_wolfSSL_hs_retry_alert_fail),           \
        TEST_DECL_GROUP("ssl_hs", test_wolfSSL_connect_ex_no_side),            \
        TEST_DECL_GROUP("ssl_hs", test_wolfSSL_hs_done_cb_error),              \
        TEST_DECL_GROUP("ssl_hs", test_wolfSSL_hs_info_cb)

#endif /* TESTS_API_SSL_HS_H */
