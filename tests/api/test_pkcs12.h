/* test_pkcs12.h
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

#ifndef WOLFCRYPT_TEST_PKCS12_H
#define WOLFCRYPT_TEST_PKCS12_H

#include <tests/api/api_decl.h>

int test_wc_i2d_PKCS12(void);
int test_wc_PKCS12_create(void);
int test_wc_PKCS12_create_guardrails(void);
int test_wc_PKCS12_parse_guardrails(void);
int test_wc_d2i_PKCS12_bad_mac_salt(void);
int test_wc_d2i_PKCS12_oid_underflow(void);
int test_wc_PKCS12_encrypted_content_bounds(void);
int test_wc_PKCS12_PBKDF(void);
int test_wc_PKCS12_PBKDF_ex(void);
int test_wc_PKCS12_PBKDF_ex_sha1(void);
int test_wc_PKCS12_PBKDF_ex_sha512(void);
int test_wc_PKCS12_PBKDF_ex_sha224(void);
int test_wc_PKCS12_PBKDF_ex_sha384(void);
int test_wc_PKCS12_PBKDF_ex_sha512_224(void);
int test_wc_PKCS12_PBKDF_ex_sha512_256(void);
int test_wc_Pkcs12BadArgCoverage(void);
int test_wc_Pkcs12DecisionCoverage(void);
int test_wc_Pkcs12FeatureCoverage(void);
int test_wc_Pkcs12FileCoverage(void);
int test_wc_Pkcs12MacIterCoverage(void);

#define TEST_PKCS12_DECLS                                               \
    TEST_DECL_GROUP("pkcs12", test_wc_i2d_PKCS12),                     \
    TEST_DECL_GROUP("pkcs12", test_wc_PKCS12_create),                  \
    TEST_DECL_GROUP("pkcs12", test_wc_PKCS12_create_guardrails),       \
    TEST_DECL_GROUP("pkcs12", test_wc_PKCS12_parse_guardrails),        \
    TEST_DECL_GROUP("pkcs12", test_wc_d2i_PKCS12_bad_mac_salt),        \
    TEST_DECL_GROUP("pkcs12", test_wc_d2i_PKCS12_oid_underflow),       \
    TEST_DECL_GROUP("pkcs12", test_wc_PKCS12_encrypted_content_bounds), \
    TEST_DECL_GROUP("pkcs12", test_wc_PKCS12_PBKDF),                   \
    TEST_DECL_GROUP("pkcs12", test_wc_PKCS12_PBKDF_ex),                \
    TEST_DECL_GROUP("pkcs12", test_wc_PKCS12_PBKDF_ex_sha1),           \
    TEST_DECL_GROUP("pkcs12", test_wc_PKCS12_PBKDF_ex_sha512),         \
    TEST_DECL_GROUP("pkcs12", test_wc_PKCS12_PBKDF_ex_sha224),         \
    TEST_DECL_GROUP("pkcs12", test_wc_PKCS12_PBKDF_ex_sha384),         \
    TEST_DECL_GROUP("pkcs12", test_wc_PKCS12_PBKDF_ex_sha512_224),     \
    TEST_DECL_GROUP("pkcs12", test_wc_PKCS12_PBKDF_ex_sha512_256),     \
    TEST_DECL_GROUP("pkcs12", test_wc_Pkcs12BadArgCoverage),           \
    TEST_DECL_GROUP("pkcs12", test_wc_Pkcs12DecisionCoverage),         \
    TEST_DECL_GROUP("pkcs12", test_wc_Pkcs12FeatureCoverage),          \
    TEST_DECL_GROUP("pkcs12", test_wc_Pkcs12FileCoverage),             \
    TEST_DECL_GROUP("pkcs12", test_wc_Pkcs12MacIterCoverage)

#endif /* WOLFCRYPT_TEST_PKCS12_H */
