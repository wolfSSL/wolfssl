/* test_evp.h
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

#ifndef WOLFSSL_TEST_EVP_H
#define WOLFSSL_TEST_EVP_H

#include <tests/api/api_decl.h>

int test_wolfSSL_EVP_ENCODE_CTX_new(void);
int test_wolfSSL_EVP_ENCODE_CTX_free(void);
int test_wolfSSL_EVP_EncodeInit(void);
int test_wolfSSL_EVP_EncodeUpdate(void);
int test_wolfSSL_EVP_EncodeFinal(void);
int test_wolfSSL_EVP_DecodeInit(void);
int test_wolfSSL_EVP_DecodeUpdate(void);
int test_wolfSSL_EVP_DecodeFinal(void);

#define TEST_EVP_ENC_DECLS                                          \
    TEST_DECL_GROUP("evp_enc", test_wolfSSL_EVP_ENCODE_CTX_new),    \
    TEST_DECL_GROUP("evp_enc", test_wolfSSL_EVP_ENCODE_CTX_free),   \
    TEST_DECL_GROUP("evp_enc", test_wolfSSL_EVP_EncodeInit),        \
    TEST_DECL_GROUP("evp_enc", test_wolfSSL_EVP_EncodeUpdate),      \
    TEST_DECL_GROUP("evp_enc", test_wolfSSL_EVP_EncodeFinal),       \
    TEST_DECL_GROUP("evp_enc", test_wolfSSL_EVP_DecodeInit),        \
    TEST_DECL_GROUP("evp_enc", test_wolfSSL_EVP_DecodeUpdate),      \
    TEST_DECL_GROUP("evp_enc", test_wolfSSL_EVP_DecodeFinal)

#endif /* WOLFSSL_TEST_EVP_H */
