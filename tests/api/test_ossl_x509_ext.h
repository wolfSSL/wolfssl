/* test_ossl_x509_ext.h
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

#ifndef WOLFCRYPT_TEST_OSSL_X509_EXT_H
#define WOLFCRYPT_TEST_OSSL_X509_EXT_H

#include <tests/api/api_decl.h>

int test_wolfSSL_X509_get_extension_flags(void);
int test_wolfSSL_X509_get_ext(void);
int test_wolfSSL_X509_get_ext_by_NID(void);
int test_wolfSSL_X509_get_ext_subj_alt_name(void);
int test_wolfSSL_X509_set_ext(void);
int test_wolfSSL_X509_add_ext(void);
int test_wolfSSL_X509_get_ext_count(void);
int test_wolfSSL_X509_stack_extensions(void);
int test_wolfSSL_X509_EXTENSION_new(void);
int test_wolfSSL_X509_EXTENSION_dup(void);
int test_wolfSSL_X509_EXTENSION_get_object(void);
int test_wolfSSL_X509_EXTENSION_get_data(void);
int test_wolfSSL_X509_EXTENSION_get_critical(void);
int test_wolfSSL_X509_EXTENSION_create_by_OBJ(void);
int test_wolfSSL_X509V3_set_ctx(void);
int test_wolfSSL_X509V3_EXT_get(void);
int test_wolfSSL_X509V3_EXT_nconf(void);
int test_wolfSSL_X509V3_EXT_bc(void);
int test_wolfSSL_X509V3_EXT_san(void);
int test_wolfSSL_X509V3_EXT_aia(void);
int test_wolfSSL_X509V3_EXT(void);
int test_wolfSSL_X509V3_EXT_print(void);
int test_wolfSSL_X509_get_ext_d2i_name_constraints(void);
int test_wolfSSL_sk_GENERAL_SUBTREE(void);
int test_wolfSSL_NAME_CONSTRAINTS_types(void);
int test_wolfSSL_NAME_CONSTRAINTS_uri(void);
int test_wolfSSL_NAME_CONSTRAINTS_ipaddr(void);
int test_wolfSSL_NAME_CONSTRAINTS_check_name(void);
int test_wolfSSL_NAME_CONSTRAINTS_dns(void);
int test_wolfSSL_NAME_CONSTRAINTS_excluded(void);

#define TEST_OSSL_X509_EXT_DECLS                                               \
    TEST_DECL_GROUP("ossl_x509_ext", test_wolfSSL_X509_get_extension_flags),   \
    TEST_DECL_GROUP("ossl_x509_ext", test_wolfSSL_X509_get_ext),               \
    TEST_DECL_GROUP("ossl_x509_ext", test_wolfSSL_X509_get_ext_by_NID),        \
    TEST_DECL_GROUP("ossl_x509_ext", test_wolfSSL_X509_get_ext_subj_alt_name), \
    TEST_DECL_GROUP("ossl_x509_ext", test_wolfSSL_X509_set_ext),               \
    TEST_DECL_GROUP("ossl_x509_ext", test_wolfSSL_X509_add_ext),               \
    TEST_DECL_GROUP("ossl_x509_ext", test_wolfSSL_X509_get_ext_count),         \
    TEST_DECL_GROUP("ossl_x509_ext", test_wolfSSL_X509_stack_extensions),      \
    TEST_DECL_GROUP("ossl_x509_ext", test_wolfSSL_X509_EXTENSION_new),         \
    TEST_DECL_GROUP("ossl_x509_ext", test_wolfSSL_X509_EXTENSION_dup),         \
    TEST_DECL_GROUP("ossl_x509_ext", test_wolfSSL_X509_EXTENSION_get_object),  \
    TEST_DECL_GROUP("ossl_x509_ext", test_wolfSSL_X509_EXTENSION_get_data),    \
    TEST_DECL_GROUP("ossl_x509_ext",                                           \
                                    test_wolfSSL_X509_EXTENSION_get_critical), \
    TEST_DECL_GROUP("ossl_x509_ext",                                           \
                                   test_wolfSSL_X509_EXTENSION_create_by_OBJ), \
    TEST_DECL_GROUP("ossl_x509_ext", test_wolfSSL_X509V3_set_ctx),             \
    TEST_DECL_GROUP("ossl_x509_ext", test_wolfSSL_X509V3_EXT_get),             \
    TEST_DECL_GROUP("ossl_x509_ext", test_wolfSSL_X509V3_EXT_nconf),           \
    TEST_DECL_GROUP("ossl_x509_ext", test_wolfSSL_X509V3_EXT_bc),              \
    TEST_DECL_GROUP("ossl_x509_ext", test_wolfSSL_X509V3_EXT_san),             \
    TEST_DECL_GROUP("ossl_x509_ext", test_wolfSSL_X509V3_EXT_aia),             \
    TEST_DECL_GROUP("ossl_x509_ext", test_wolfSSL_X509V3_EXT),                 \
    TEST_DECL_GROUP("ossl_x509_ext", test_wolfSSL_X509V3_EXT_print),           \
    TEST_DECL_GROUP("ossl_x509_ext",                                           \
                          test_wolfSSL_X509_get_ext_d2i_name_constraints),     \
    TEST_DECL_GROUP("ossl_x509_ext", test_wolfSSL_sk_GENERAL_SUBTREE),         \
    TEST_DECL_GROUP("ossl_x509_ext", test_wolfSSL_NAME_CONSTRAINTS_types),     \
    TEST_DECL_GROUP("ossl_x509_ext", test_wolfSSL_NAME_CONSTRAINTS_uri),       \
    TEST_DECL_GROUP("ossl_x509_ext", test_wolfSSL_NAME_CONSTRAINTS_ipaddr),    \
    TEST_DECL_GROUP("ossl_x509_ext", test_wolfSSL_NAME_CONSTRAINTS_check_name),\
    TEST_DECL_GROUP("ossl_x509_ext", test_wolfSSL_NAME_CONSTRAINTS_dns),       \
    TEST_DECL_GROUP("ossl_x509_ext", test_wolfSSL_NAME_CONSTRAINTS_excluded)

#endif /* WOLFCRYPT_TEST_OSSL_X509_EXT_H */
