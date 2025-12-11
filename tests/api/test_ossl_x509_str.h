/* test_ossl_x509_str.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#ifndef WOLFCRYPT_TEST_OSSL_X509_STR_H
#define WOLFCRYPT_TEST_OSSL_X509_STR_H

#include <tests/api/api_decl.h>

int test_wolfSSL_X509_STORE_CTX_set_time(void);
int test_wolfSSL_X509_STORE_CTX_get0_store(void);
int test_wolfSSL_X509_STORE_CTX(void);
int test_wolfSSL_X509_STORE_CTX_ex(void);
int test_X509_STORE_untrusted(void);
int test_X509_STORE_InvalidCa(void);
int test_wolfSSL_X509_STORE_CTX_trusted_stack_cleanup(void);
int test_wolfSSL_X509_STORE_CTX_get_issuer(void);
int test_wolfSSL_X509_STORE_set_flags(void);
int test_wolfSSL_X509_STORE(void);
int test_wolfSSL_X509_STORE_load_locations(void);
int test_X509_STORE_get0_objects(void);
int test_wolfSSL_X509_STORE_get1_certs(void);
int test_wolfSSL_X509_STORE_set_get_crl(void);
int test_wolfSSL_X509_CA_num(void);
int test_X509_STORE_No_SSL_CTX(void);

#define TEST_OSSL_X509_STORE_DECLS                                             \
    TEST_DECL_GROUP("ossl_x509_store", test_wolfSSL_X509_STORE_CTX_set_time),  \
    TEST_DECL_GROUP("ossl_x509_store",                                         \
                                      test_wolfSSL_X509_STORE_CTX_get0_store), \
    TEST_DECL_GROUP("ossl_x509_store", test_wolfSSL_X509_STORE_CTX),           \
    TEST_DECL_GROUP("ossl_x509_store", test_wolfSSL_X509_STORE_CTX_ex),        \
    TEST_DECL_GROUP("ossl_x509_store", test_X509_STORE_untrusted),             \
    TEST_DECL_GROUP("ossl_x509_store", test_X509_STORE_InvalidCa),             \
    TEST_DECL_GROUP("ossl_x509_store",                                         \
                           test_wolfSSL_X509_STORE_CTX_trusted_stack_cleanup), \
    TEST_DECL_GROUP("ossl_x509_store",                                         \
                                      test_wolfSSL_X509_STORE_CTX_get_issuer), \
    TEST_DECL_GROUP("ossl_x509_store", test_wolfSSL_X509_STORE_set_flags),     \
    TEST_DECL_GROUP("ossl_x509_store", test_wolfSSL_X509_STORE),               \
    TEST_DECL_GROUP("ossl_x509_store",                                         \
                                      test_wolfSSL_X509_STORE_load_locations), \
    TEST_DECL_GROUP("ossl_x509_store", test_X509_STORE_get0_objects),          \
    TEST_DECL_GROUP("ossl_x509_store", test_wolfSSL_X509_STORE_get1_certs),    \
    TEST_DECL_GROUP("ossl_x509_store", test_wolfSSL_X509_STORE_set_get_crl),   \
    TEST_DECL_GROUP("ossl_x509_store", test_wolfSSL_X509_CA_num),              \
    TEST_DECL_GROUP("ossl_x509_store", test_X509_STORE_No_SSL_CTX)

#endif /* WOLFCRYPT_TEST_OSSL_X509_STR_H */
