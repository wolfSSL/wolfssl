/* test_certman.h
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

#ifndef WOLFCRYPT_TEST_CERTMAN_H
#define WOLFCRYPT_TEST_CERTMAN_H

#include <tests/api/api_decl.h>

int test_wolfSSL_CertManagerAPI(void);
int test_wolfSSL_CertManagerLoadCABuffer(void);
int test_wolfSSL_CertManagerLoadCABuffer_ex(void);
int test_wolfSSL_CertManagerLoadCABufferType(void);
int test_wolfSSL_CertManagerGetCerts(void);
int test_wolfSSL_CertManagerSetVerify(void);
int test_wolfSSL_CertManagerNameConstraint(void);
int test_wolfSSL_CertManagerNameConstraint2(void);
int test_wolfSSL_CertManagerNameConstraint3(void);
int test_wolfSSL_CertManagerNameConstraint4(void);
int test_wolfSSL_CertManagerNameConstraint5(void);
int test_wolfSSL_CertManagerCRL(void);
int test_wolfSSL_CRL_static_revoked_list(void);
int test_wolfSSL_CRL_duplicate_extensions(void);
int test_wolfSSL_CertManagerCheckOCSPResponse(void);
int test_various_pathlen_chains(void);

#define TEST_CERTMAN_DECLS                                                  \
    TEST_DECL_GROUP("certman", test_wolfSSL_CertManagerAPI),                \
    TEST_DECL_GROUP("certman", test_wolfSSL_CertManagerLoadCABuffer),       \
    TEST_DECL_GROUP("certman", test_wolfSSL_CertManagerLoadCABuffer_ex),    \
    TEST_DECL_GROUP("certman", test_wolfSSL_CertManagerLoadCABufferType),   \
    TEST_DECL_GROUP("certman", test_wolfSSL_CertManagerGetCerts),           \
    TEST_DECL_GROUP("certman", test_wolfSSL_CertManagerSetVerify),          \
    TEST_DECL_GROUP("certman", test_wolfSSL_CertManagerNameConstraint),     \
    TEST_DECL_GROUP("certman", test_wolfSSL_CertManagerNameConstraint2),    \
    TEST_DECL_GROUP("certman", test_wolfSSL_CertManagerNameConstraint3),    \
    TEST_DECL_GROUP("certman", test_wolfSSL_CertManagerNameConstraint4),    \
    TEST_DECL_GROUP("certman", test_wolfSSL_CertManagerNameConstraint5),    \
    TEST_DECL_GROUP("certman", test_wolfSSL_CertManagerCRL),                \
    TEST_DECL_GROUP("certman", test_wolfSSL_CRL_static_revoked_list),      \
    TEST_DECL_GROUP("certman", test_wolfSSL_CRL_duplicate_extensions),      \
    TEST_DECL_GROUP("certman", test_wolfSSL_CertManagerCheckOCSPResponse),  \
    TEST_DECL_GROUP("certman", test_various_pathlen_chains)

#endif /* WOLFCRYPT_TEST_CERTMAN_H */

