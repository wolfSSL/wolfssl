/* test_x509.h
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

#ifndef WOLFCRYPT_TEST_X509_H
#define WOLFCRYPT_TEST_X509_H

int test_x509_rfc2818_verification_callback(void);
int test_wolfSSL_X509_STORE_load_multiple_certs(void);

#define TEST_X509_DECLS                                                        \
    TEST_DECL_GROUP("x509", test_x509_rfc2818_verification_callback),          \
    TEST_DECL_GROUP("x509", test_wolfSSL_X509_STORE_load_multiple_certs)

#endif /* WOLFCRYPT_TEST_X509_H */
