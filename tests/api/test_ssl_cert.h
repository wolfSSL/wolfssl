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

int test_wolfSSL_cert_api_arg_guards(void);
int test_wolfSSL_crl_ocsp_api_arg_guards(void);
int test_wolfSSL_ocsp_stapling_accessors(void);
int test_wolfSSL_crl_io_mock(void);
int test_wolfSSL_x509_accessor_guards(void);
int test_wolfSSL_dtls_api_on_dtls_object(void);
int test_wolfSSL_load_pathological_files(void);
int test_wolfSSL_load_from_fifo(void);

int test_wolfSSL_get_verify_mode(void);
int test_wolfSSL_CTX_get_verify_mode(void);
int test_wolfSSL_get_verify_callback(void);
int test_wolfSSL_CTX_get_extra_chain_certs(void);
int test_wolfSSL_get_peer_chain(void);
int test_wolfSSL_get_chain_X509(void);
int test_wolfSSL_get_chain_cert_pem(void);
int test_wolfSSL_cmp_peer_cert_to_file(void);
int test_wolfSSL_CTX_set_client_cert_cb(void);
int test_wolfSSL_CTX_set_cert_cb(void);
int test_wolfSSL_cert_setup_cb_ret(void);
int test_wolfSSL_get_peer_cert_chain(void);
int test_wolfSSL_set_peer_cert_chain(void);
int test_wolfSSL_get0_verified_chain(void);
int test_wolfSSL_CA_list_add(void);
int test_wolfSSL_CA_list_get(void);
int test_wolfSSL_load_client_CA_file(void);
int test_wolfSSL_mutual_auth(void);
int test_wolfSSL_post_handshake_auth(void);
int test_wolfSSL_verify_cert_store(void);
int test_wolfSSL_verify_cert_store_follows_ctx(void);
int test_wolfSSL_CTX_cert_store_manager_link(void);
int test_wolfSSL_cert_cb_ctx(void);
int test_wolfSSL_get_certificate_api(void);
int test_wolfSSL_cert_unload(void);

#define TEST_SSL_CERT_DECLS                                                    \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_get_verify_mode),             \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_CTX_get_verify_mode),         \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_get_verify_callback),         \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_CTX_get_extra_chain_certs),   \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_get_peer_chain),              \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_get_chain_X509),              \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_get_chain_cert_pem),          \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_cmp_peer_cert_to_file),       \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_CTX_set_client_cert_cb),      \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_CTX_set_cert_cb),             \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_cert_setup_cb_ret),           \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_get_peer_cert_chain),         \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_set_peer_cert_chain),         \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_get0_verified_chain),         \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_CA_list_add),                 \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_CA_list_get),                 \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_load_client_CA_file),         \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_mutual_auth),                 \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_post_handshake_auth),         \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_verify_cert_store),           \
        TEST_DECL_GROUP("ssl_cert",                                            \
            test_wolfSSL_verify_cert_store_follows_ctx),                       \
        TEST_DECL_GROUP("ssl_cert",                                            \
            test_wolfSSL_CTX_cert_store_manager_link),                         \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_cert_cb_ctx),                 \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_get_certificate_api),         \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_cert_unload),                \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_cert_api_arg_guards),        \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_crl_ocsp_api_arg_guards),    \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_ocsp_stapling_accessors),    \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_crl_io_mock),                 \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_x509_accessor_guards),        \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_dtls_api_on_dtls_object),     \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_load_pathological_files),     \
        TEST_DECL_GROUP("ssl_cert", test_wolfSSL_load_from_fifo)

#endif /* TESTS_API_SSL_CERT_H */
