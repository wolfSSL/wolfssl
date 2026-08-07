/* test_ssl_crl_ocsp.h
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

#ifndef TESTS_API_SSL_CRL_OCSP_H
#define TESTS_API_SSL_CRL_OCSP_H

#include <tests/api/api_decl.h>

int test_wolfSSL_ocsp_url_api(void);
int test_wolfSSL_get_ocsp_producedDate(void);
int test_wolfSSL_tlsext_status_type(void);
int test_wolfSSL_CTX_tlsext_status_cb(void);
int test_wolfSSL_tlsext_status_ocsp_resp(void);
int test_wolfSSL_OCSP_parse_url_api(void);

#define TEST_SSL_CRL_OCSP_DECLS                                                \
        TEST_DECL_GROUP("ssl_crl_ocsp", test_wolfSSL_ocsp_url_api),            \
        TEST_DECL_GROUP("ssl_crl_ocsp", test_wolfSSL_get_ocsp_producedDate),   \
        TEST_DECL_GROUP("ssl_crl_ocsp", test_wolfSSL_tlsext_status_type),      \
        TEST_DECL_GROUP("ssl_crl_ocsp", test_wolfSSL_CTX_tlsext_status_cb),    \
        TEST_DECL_GROUP("ssl_crl_ocsp", test_wolfSSL_tlsext_status_ocsp_resp), \
        TEST_DECL_GROUP("ssl_crl_ocsp", test_wolfSSL_OCSP_parse_url_api)

#endif /* TESTS_API_SSL_CRL_OCSP_H */
