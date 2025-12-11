/* test_curve25519.h
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

#ifndef WOLFCRYPT_TEST_CURVE25519_H
#define WOLFCRYPT_TEST_CURVE25519_H

#include <tests/api/api_decl.h>

int test_wc_curve25519_init(void);
int test_wc_curve25519_size(void);
int test_wc_curve25519_export_key_raw(void);
int test_wc_curve25519_export_key_raw_ex(void);
int test_wc_curve25519_make_key(void);
int test_wc_curve25519_shared_secret_ex(void);
int test_wc_curve25519_make_pub(void);
int test_wc_curve25519_export_public_ex(void);
int test_wc_curve25519_export_private_raw_ex(void);
int test_wc_curve25519_import_private_raw_ex(void);
int test_wc_curve25519_import_private(void);

#define TEST_CURVE25519_DECLS                                                  \
    TEST_DECL_GROUP("curve25519", test_wc_curve25519_init),                    \
    TEST_DECL_GROUP("curve25519", test_wc_curve25519_size),                    \
    TEST_DECL_GROUP("curve25519", test_wc_curve25519_export_key_raw),          \
    TEST_DECL_GROUP("curve25519", test_wc_curve25519_export_key_raw_ex),       \
    TEST_DECL_GROUP("curve25519", test_wc_curve25519_make_key),                \
    TEST_DECL_GROUP("curve25519", test_wc_curve25519_shared_secret_ex),        \
    TEST_DECL_GROUP("curve25519", test_wc_curve25519_make_pub),                \
    TEST_DECL_GROUP("curve25519", test_wc_curve25519_export_public_ex),        \
    TEST_DECL_GROUP("curve25519", test_wc_curve25519_export_private_raw_ex),   \
    TEST_DECL_GROUP("curve25519", test_wc_curve25519_import_private_raw_ex),   \
    TEST_DECL_GROUP("curve25519", test_wc_curve25519_import_private)

#endif /* WOLFCRYPT_TEST_CURVE25519_H */
