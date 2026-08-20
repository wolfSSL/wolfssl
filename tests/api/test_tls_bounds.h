/* test_tls_bounds.h
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

#ifndef TESTS_API_TEST_TLS_BOUNDS_H
#define TESTS_API_TEST_TLS_BOUNDS_H

int test_TLSX_UseSNI_bounds(void);
int test_TLSX_UseALPN_bounds(void);
int test_TLSX_UseMaxFragment_bounds(void);
int test_TLSX_UseCertificateStatusRequest_bounds(void);
int test_TLSX_UseCertificateStatusRequestV2_bounds(void);
int test_TLSX_SupportExtensions_bounds(void);
int test_TLSX_CSR2_InitRequests_bounds(void);
int test_TLSX_CSR2_ForceRequest_bounds(void);
int test_TLSX_CSR_GetRequest_ex_bounds(void);
int test_wolfSSL_make_eap_keys_bounds(void);
int test_wolfSSL_SetTlsHmacInner_bounds(void);
int test_BuildTlsHandshakeHash_bounds(void);
int test_TLS_hmac_bounds(void);
int test_TLSX_ALPN_GetSize_overflow(void);
int test_TLSX_Cookie_bounds(void);

#define TEST_TLS_BOUNDS_DECLS                                                \
        TEST_DECL_GROUP("tls", test_TLSX_UseSNI_bounds),                     \
        TEST_DECL_GROUP("tls", test_TLSX_UseALPN_bounds),                    \
        TEST_DECL_GROUP("tls", test_TLSX_UseMaxFragment_bounds),             \
        TEST_DECL_GROUP("tls", test_TLSX_UseCertificateStatusRequest_bounds),\
        TEST_DECL_GROUP("tls",                                               \
                test_TLSX_UseCertificateStatusRequestV2_bounds),             \
        TEST_DECL_GROUP("tls", test_TLSX_SupportExtensions_bounds),          \
        TEST_DECL_GROUP("tls", test_TLSX_CSR2_InitRequests_bounds),          \
        TEST_DECL_GROUP("tls", test_TLSX_CSR2_ForceRequest_bounds),          \
        TEST_DECL_GROUP("tls", test_TLSX_CSR_GetRequest_ex_bounds),          \
        TEST_DECL_GROUP("tls", test_wolfSSL_make_eap_keys_bounds),           \
        TEST_DECL_GROUP("tls", test_wolfSSL_SetTlsHmacInner_bounds),         \
        TEST_DECL_GROUP("tls", test_BuildTlsHandshakeHash_bounds),           \
        TEST_DECL_GROUP("tls", test_TLS_hmac_bounds),                       \
        TEST_DECL_GROUP("tls", test_TLSX_ALPN_GetSize_overflow),            \
        TEST_DECL_GROUP("tls", test_TLSX_Cookie_bounds)

#endif /* TESTS_API_TEST_TLS_BOUNDS_H */
