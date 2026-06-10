/* test_ssl_cert.h
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

#ifndef TESTS_API_SSL_CERT_H
#define TESTS_API_SSL_CERT_H

int test_wolfSSL_get_verify_mode(void);
int test_wolfSSL_CTX_get_verify_mode(void);
int test_wolfSSL_get_verify_callback(void);
int test_wolfSSL_CTX_get_extra_chain_certs(void);
int test_wolfSSL_get_peer_chain(void);
int test_wolfSSL_get_chain_X509(void);
int test_wolfSSL_get_chain_cert_pem(void);
int test_wolfSSL_cmp_peer_cert_to_file(void);

#define TEST_SSL_CERT_DECLS                                                    \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_get_verify_mode),             \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_CTX_get_verify_mode),         \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_get_verify_callback),         \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_CTX_get_extra_chain_certs),   \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_get_peer_chain),              \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_get_chain_X509),             \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_get_chain_cert_pem),         \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_cmp_peer_cert_to_file)

#endif /* TESTS_API_SSL_CERT_H */
