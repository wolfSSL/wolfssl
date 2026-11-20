/* test_ecjpake.h
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

#ifndef WOLFSSL_TEST_ECJPAKE_H
#define WOLFSSL_TEST_ECJPAKE_H

#include <tests/api/api_decl.h>

int test_wolfSSL_ecjpake_dtls12(void);
int test_wolfSSL_ecjpake_wrong_password(void);
int test_wolfSSL_ecjpake_negotiation(void);
int test_wolfSSL_ecjpake_bad_proof(void);
int test_wolfSSL_ecjpake_set_password(void);

#define TEST_ECJPAKE_DECLS                                                \
    TEST_DECL_GROUP("ecjpake", test_wolfSSL_ecjpake_dtls12),              \
    TEST_DECL_GROUP("ecjpake", test_wolfSSL_ecjpake_wrong_password),      \
    TEST_DECL_GROUP("ecjpake", test_wolfSSL_ecjpake_negotiation),         \
    TEST_DECL_GROUP("ecjpake", test_wolfSSL_ecjpake_bad_proof),           \
    TEST_DECL_GROUP("ecjpake", test_wolfSSL_ecjpake_set_password)

#endif /* WOLFSSL_TEST_ECJPAKE_H */
