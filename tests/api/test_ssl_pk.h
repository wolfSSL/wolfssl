/* test_ssl_pk.h
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

#ifndef TESTS_API_SSL_PK_H
#define TESTS_API_SSL_PK_H

int test_wolfSSL_CTX_SetMinEccKey_Sz(void);
int test_wolfSSL_SetMinEccKey_Sz(void);
int test_wolfSSL_CTX_SetMinRsaKey_Sz(void);
int test_wolfSSL_SetMinRsaKey_Sz(void);
int test_wolfSSL_SetEnableDhKeyTest(void);
int test_wolfSSL_CTX_SetMinDhKey_Sz(void);
int test_wolfSSL_SetMinDhKey_Sz(void);
int test_wolfSSL_CTX_SetMaxDhKey_Sz(void);
int test_wolfSSL_SetMaxDhKey_Sz(void);
int test_wolfSSL_GetDhKey_Sz(void);
int test_wolfSSL_get_privatekey(void);
int test_wolfSSL_get_signature_nid(void);
int test_wolfSSL_get_signature_type_nid(void);
int test_wolfSSL_get_peer_signature_nid(void);
int test_wolfSSL_get_peer_signature_type_nid(void);
int test_wolfSSL_SSL_CTX_set_tmp_ecdh(void);
int test_wolfSSL_CTX_set_dh_auto(void);

#define TEST_SSL_PK_DECLS                                                      \
        TEST_DECL_GROUP("ssl_pk", test_wolfSSL_CTX_SetMinEccKey_Sz),           \
        TEST_DECL_GROUP("ssl_pk", test_wolfSSL_SetMinEccKey_Sz),               \
        TEST_DECL_GROUP("ssl_pk", test_wolfSSL_CTX_SetMinRsaKey_Sz),           \
        TEST_DECL_GROUP("ssl_pk", test_wolfSSL_SetMinRsaKey_Sz),               \
        TEST_DECL_GROUP("ssl_pk", test_wolfSSL_SetEnableDhKeyTest),            \
        TEST_DECL_GROUP("ssl_pk", test_wolfSSL_CTX_SetMinDhKey_Sz),            \
        TEST_DECL_GROUP("ssl_pk", test_wolfSSL_SetMinDhKey_Sz),                \
        TEST_DECL_GROUP("ssl_pk", test_wolfSSL_CTX_SetMaxDhKey_Sz),            \
        TEST_DECL_GROUP("ssl_pk", test_wolfSSL_SetMaxDhKey_Sz),                \
        TEST_DECL_GROUP("ssl_pk", test_wolfSSL_GetDhKey_Sz),                   \
        TEST_DECL_GROUP("ssl_pk", test_wolfSSL_get_privatekey),                \
        TEST_DECL_GROUP("ssl_pk", test_wolfSSL_get_signature_nid),            \
        TEST_DECL_GROUP("ssl_pk", test_wolfSSL_get_signature_type_nid),       \
        TEST_DECL_GROUP("ssl_pk", test_wolfSSL_get_peer_signature_nid),       \
        TEST_DECL_GROUP("ssl_pk", test_wolfSSL_get_peer_signature_type_nid),  \
        TEST_DECL_GROUP("ssl_pk", test_wolfSSL_SSL_CTX_set_tmp_ecdh),         \
        TEST_DECL_GROUP("ssl_pk", test_wolfSSL_CTX_set_dh_auto)

#endif /* TESTS_API_SSL_PK_H */
