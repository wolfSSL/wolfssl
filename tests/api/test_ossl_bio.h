/* test_ossl_bio.h
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

#ifndef WOLFCRYPT_TEST_OSSL_BIO_H
#define WOLFCRYPT_TEST_OSSL_BIO_H

#include <tests/api/api_decl.h>

#ifndef NO_BIO
int test_wolfSSL_BIO_gets(void);
int test_wolfSSL_BIO_puts(void);
int test_wolfSSL_BIO_dump(void);
int test_wolfSSL_BIO_should_retry(void);
int test_wolfSSL_BIO_connect(void);
int test_wolfSSL_BIO_tls(void);
int test_wolfSSL_BIO_datagram(void);
int test_wolfSSL_BIO_s_null(void);
int test_wolfSSL_BIO_accept(void);
int test_wolfSSL_BIO_write(void);
int test_wolfSSL_BIO_printf(void);
int test_wolfSSL_BIO_f_md(void);
int test_wolfSSL_BIO_up_ref(void);
int test_wolfSSL_BIO_reset(void);
int test_wolfSSL_BIO_get_len(void);

#define TEST_OSSL_BIO_DECLS                                       \
    TEST_DECL_GROUP("ossl_bio", test_wolfSSL_BIO_gets),           \
    TEST_DECL_GROUP("ossl_bio", test_wolfSSL_BIO_puts),           \
    TEST_DECL_GROUP("ossl_bio", test_wolfSSL_BIO_dump),           \
    TEST_DECL_GROUP("ossl_bio", test_wolfSSL_BIO_should_retry),   \
    TEST_DECL_GROUP("ossl_bio", test_wolfSSL_BIO_s_null),         \
    TEST_DECL_GROUP("ossl_bio", test_wolfSSL_BIO_write),          \
    TEST_DECL_GROUP("ossl_bio", test_wolfSSL_BIO_printf),         \
    TEST_DECL_GROUP("ossl_bio", test_wolfSSL_BIO_f_md),           \
    TEST_DECL_GROUP("ossl_bio", test_wolfSSL_BIO_up_ref),         \
    TEST_DECL_GROUP("ossl_bio", test_wolfSSL_BIO_reset),          \
    TEST_DECL_GROUP("ossl_bio", test_wolfSSL_BIO_get_len)

#define TEST_OSSL_BIO_TLS_DECLS                                   \
    TEST_DECL_GROUP("ossl_bio_tls", test_wolfSSL_BIO_connect),    \
    TEST_DECL_GROUP("ossl_bio_tls", test_wolfSSL_BIO_accept),     \
    TEST_DECL_GROUP("ossl_bio_tls", test_wolfSSL_BIO_tls),        \
    TEST_DECL_GROUP("ossl_bio_tls", test_wolfSSL_BIO_datagram)

#endif

#endif /* WOLFCRYPT_TEST_OSSL_BIO_H */
