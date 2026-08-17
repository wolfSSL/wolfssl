/* test_async.h
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

#ifndef WOLFCRYPT_TEST_ASYNC_H
#define WOLFCRYPT_TEST_ASYNC_H

#include <tests/api/api_decl.h>

int test_wc_CryptoCb_AsyncPollAesGcm(void);
int test_wc_CryptoCb_AsyncPollAesCbc(void);
int test_wc_CryptoCb_AsyncPollAesCcm(void);
int test_wc_CryptoCb_AsyncPollDes3(void);
int test_wc_CryptoCb_AsyncPollUnsupported(void);
int test_wc_CryptoCb_AsyncPollChachaUnimpl(void);
int test_wc_CryptoCb_AsyncPollDesUnimpl(void);
int test_wc_CryptoCb_AsyncPollTlsAesGcm(void);
int test_wc_CryptoCb_AsyncPollTlsChachaNotOffloaded(void);
int test_wc_CryptoCb_AsyncPollTlsNoPollFails(void);
int test_wc_CryptoCb_AsyncPollTlsBothDirections(void);

#define TEST_ASYNC_DECLS                                                \
    TEST_DECL_GROUP("async", test_wc_CryptoCb_AsyncPollAesGcm),         \
    TEST_DECL_GROUP("async", test_wc_CryptoCb_AsyncPollAesCbc),         \
    TEST_DECL_GROUP("async", test_wc_CryptoCb_AsyncPollAesCcm),         \
    TEST_DECL_GROUP("async", test_wc_CryptoCb_AsyncPollDes3),           \
    TEST_DECL_GROUP("async", test_wc_CryptoCb_AsyncPollUnsupported),    \
    TEST_DECL_GROUP("async", test_wc_CryptoCb_AsyncPollChachaUnimpl),   \
    TEST_DECL_GROUP("async", test_wc_CryptoCb_AsyncPollDesUnimpl),      \
    TEST_DECL_GROUP("async", test_wc_CryptoCb_AsyncPollTlsAesGcm),      \
    TEST_DECL_GROUP("async",                                            \
        test_wc_CryptoCb_AsyncPollTlsChachaNotOffloaded),              \
    TEST_DECL_GROUP("async", test_wc_CryptoCb_AsyncPollTlsNoPollFails), \
    TEST_DECL_GROUP("async", test_wc_CryptoCb_AsyncPollTlsBothDirections)

#endif /* WOLFCRYPT_TEST_ASYNC_H */
