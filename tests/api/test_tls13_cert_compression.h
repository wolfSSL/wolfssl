/* test_tls13_cert_compression.h
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

#ifndef WOLFSSL_TEST_TLS13_CERT_COMPRESSION_H
#define WOLFSSL_TEST_TLS13_CERT_COMPRESSION_H

#include <tests/api/api_decl.h>

int test_tls13_cert_compression_roundTrip(void);
int test_tls13_cert_compression_fragment(void);
int test_tls13_cert_compression_dtls13(void);
int test_tls13_cert_compression_pha(void);
int test_tls13_cert_compression_malformed(void);
int test_tls13_comp_cert_fallback(void);
int test_tls13_cert_compression_turnoff(void);

#define TEST_TLS13_CERT_COMPRESSION_DECLS                                      \
    TEST_DECL_GROUP("tls13", test_tls13_cert_compression_roundTrip),           \
    TEST_DECL_GROUP("tls13", test_tls13_cert_compression_fragment),            \
    TEST_DECL_GROUP("tls13", test_tls13_cert_compression_dtls13),              \
    TEST_DECL_GROUP("tls13", test_tls13_cert_compression_pha),                 \
    TEST_DECL_GROUP("tls13", test_tls13_cert_compression_malformed),           \
    TEST_DECL_GROUP("tls13", test_tls13_comp_cert_fallback),                   \
    TEST_DECL_GROUP("tls13", test_tls13_cert_compression_turnoff)


#endif /* WOLFSSL_TEST_TLS13_CERT_COMPRESSION_H */
