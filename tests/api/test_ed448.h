/* test_ed448.h
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

#ifndef WOLFCRYPT_TEST_ED448_H
#define WOLFCRYPT_TEST_ED448_H

#include <tests/api/api_decl.h>

int test_wc_ed448_make_key(void);
int test_wc_ed448_init(void);
int test_wc_ed448_sign_msg(void);
int test_wc_ed448_import_public(void);
int test_wc_ed448_import_private_key(void);
int test_wc_ed448_export(void);
int test_wc_ed448_size(void);
int test_wc_ed448_exportKey(void);
int test_wc_Ed448PublicKeyToDer(void);
int test_wc_Ed448KeyToDer(void);
int test_wc_Ed448PrivateKeyToDer(void);

#define TEST_ED448_DECLS                                          \
    TEST_DECL_GROUP("ed448", test_wc_ed448_make_key),             \
    TEST_DECL_GROUP("ed448", test_wc_ed448_init),                 \
    TEST_DECL_GROUP("ed448", test_wc_ed448_sign_msg),             \
    TEST_DECL_GROUP("ed448", test_wc_ed448_import_public),        \
    TEST_DECL_GROUP("ed448", test_wc_ed448_import_private_key),   \
    TEST_DECL_GROUP("ed448", test_wc_ed448_export),               \
    TEST_DECL_GROUP("ed448", test_wc_ed448_size),                 \
    TEST_DECL_GROUP("ed448", test_wc_ed448_exportKey),            \
    TEST_DECL_GROUP("ed448", test_wc_Ed448PublicKeyToDer),        \
    TEST_DECL_GROUP("ed448", test_wc_Ed448KeyToDer),              \
    TEST_DECL_GROUP("ed448", test_wc_Ed448PrivateKeyToDer)

#endif /* WOLFCRYPT_TEST_ED448_H */
