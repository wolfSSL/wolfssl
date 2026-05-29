/* test_session.h
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

#ifndef WOLFCRYPT_TEST_SESSION_H
#define WOLFCRYPT_TEST_SESSION_H

#include <tests/api/api_decl.h>

int test_wolfSSL_CTX_add_session(void);
int test_wolfSSL_CTX_add_session_ext_tls13(void);
int test_wolfSSL_CTX_add_session_ext_dtls13(void);
int test_wolfSSL_CTX_add_session_ext_tls12(void);
int test_wolfSSL_CTX_add_session_ext_dtls12(void);
int test_wolfSSL_CTX_add_session_ext_tls11(void);
int test_wolfSSL_CTX_add_session_ext_dtls1(void);
int test_wolfSSL_SESSION(void);
int test_wolfSSL_SESSION_expire_downgrade(void);
int test_wolfSSL_CTX_sess_set_remove_cb(void);
int test_wolfSSL_ticket_keys(void);
int test_wolfSSL_SESSION_get_ex_new_index(void);

#define TEST_SESSION_DECLS                                                     \
    TEST_DECL_GROUP("session", test_wolfSSL_CTX_add_session),                  \
    TEST_DECL_GROUP("session", test_wolfSSL_CTX_add_session_ext_tls13),        \
    TEST_DECL_GROUP("session", test_wolfSSL_CTX_add_session_ext_dtls13),       \
    TEST_DECL_GROUP("session", test_wolfSSL_CTX_add_session_ext_tls12),        \
    TEST_DECL_GROUP("session", test_wolfSSL_CTX_add_session_ext_dtls12),       \
    TEST_DECL_GROUP("session", test_wolfSSL_CTX_add_session_ext_tls11),        \
    TEST_DECL_GROUP("session", test_wolfSSL_CTX_add_session_ext_dtls1),        \
    TEST_DECL_GROUP("session", test_wolfSSL_SESSION),                          \
    TEST_DECL_GROUP("session", test_wolfSSL_SESSION_expire_downgrade),         \
    TEST_DECL_GROUP("session", test_wolfSSL_CTX_sess_set_remove_cb),           \
    TEST_DECL_GROUP("session", test_wolfSSL_ticket_keys),                      \
    TEST_DECL_GROUP("session", test_wolfSSL_SESSION_get_ex_new_index)

#endif /* WOLFCRYPT_TEST_SESSION_H */
