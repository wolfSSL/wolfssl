/* test_ossl_tsp.h
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

#ifndef WOLFCRYPT_TEST_OSSL_TSP_H
#define WOLFCRYPT_TEST_OSSL_TSP_H

#include <tests/api/api_decl.h>

int test_wolfSSL_TS_REQ(void);
int test_wolfSSL_TS_REQ_long_nonce(void);
int test_wolfSSL_TS_REQ_policy_id(void);
int test_wolfSSL_TS_RESP(void);
int test_wolfSSL_TS_RESP_accuracy_ordering(void);
int test_wolfSSL_TS_STATUS_INFO_failure_info(void);
int test_wolfSSL_TS_RESP_verify_response(void);
int test_wolfSSL_TS_RESP_verify_response_chain(void);
int test_wc_TspResponse_VerifyWithCm(void);
int test_wolfSSL_TS_RESP_verify_data(void);
int test_wolfSSL_TS_TST_INFO_get_tsa(void);
int test_wolfSSL_TS_RESP_CTX(void);
int test_wolfSSL_TS_RESP_verify_token(void);
int test_wolfSSL_TS_RESP_verify_status(void);
int test_wolfSSL_TS_RESP_verify_policy(void);
int test_wolfSSL_TS_VERIFY_CTX(void);
int test_wolfSSL_TS_VERIFY_CTX_cleanup(void);
int test_wolfSSL_TS_bad_args(void);
int test_wolfSSL_TS_view_cache(void);

#define TEST_OSSL_TSP_DECLS                                              \
    TEST_DECL_GROUP("ossl_tsp", test_wolfSSL_TS_REQ),                    \
    TEST_DECL_GROUP("ossl_tsp", test_wolfSSL_TS_REQ_long_nonce),        \
    TEST_DECL_GROUP("ossl_tsp", test_wolfSSL_TS_REQ_policy_id),         \
    TEST_DECL_GROUP("ossl_tsp", test_wolfSSL_TS_RESP),                  \
    TEST_DECL_GROUP("ossl_tsp", test_wolfSSL_TS_RESP_accuracy_ordering),\
    TEST_DECL_GROUP("ossl_tsp", test_wolfSSL_TS_STATUS_INFO_failure_info), \
    TEST_DECL_GROUP("ossl_tsp", test_wolfSSL_TS_RESP_verify_response),  \
    TEST_DECL_GROUP("ossl_tsp", test_wolfSSL_TS_RESP_verify_response_chain), \
    TEST_DECL_GROUP("ossl_tsp", test_wc_TspResponse_VerifyWithCm),      \
    TEST_DECL_GROUP("ossl_tsp", test_wolfSSL_TS_RESP_verify_data),      \
    TEST_DECL_GROUP("ossl_tsp", test_wolfSSL_TS_TST_INFO_get_tsa),      \
    TEST_DECL_GROUP("ossl_tsp", test_wolfSSL_TS_RESP_CTX),             \
    TEST_DECL_GROUP("ossl_tsp", test_wolfSSL_TS_RESP_verify_token),     \
    TEST_DECL_GROUP("ossl_tsp", test_wolfSSL_TS_RESP_verify_status),    \
    TEST_DECL_GROUP("ossl_tsp", test_wolfSSL_TS_RESP_verify_policy),    \
    TEST_DECL_GROUP("ossl_tsp", test_wolfSSL_TS_VERIFY_CTX),            \
    TEST_DECL_GROUP("ossl_tsp", test_wolfSSL_TS_VERIFY_CTX_cleanup),    \
    TEST_DECL_GROUP("ossl_tsp", test_wolfSSL_TS_bad_args),              \
    TEST_DECL_GROUP("ossl_tsp", test_wolfSSL_TS_view_cache)

#endif /* WOLFCRYPT_TEST_OSSL_TSP_H */
