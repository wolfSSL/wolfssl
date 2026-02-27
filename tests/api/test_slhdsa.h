/* test_slhdsa.h
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

#ifndef WOLFCRYPT_TEST_SLHDSA_H
#define WOLFCRYPT_TEST_SLHDSA_H

#include <tests/api/api_decl.h>

int test_wc_slhdsa(void);
int test_wc_slhdsa_sizes(void);
int test_wc_slhdsa_make_key(void);
int test_wc_slhdsa_sign(void);
int test_wc_slhdsa_verify(void);
int test_wc_slhdsa_sign_vfy(void);
int test_wc_slhdsa_sign_hash(void);
int test_wc_slhdsa_export_import(void);
int test_wc_slhdsa_check_key(void);

#define TEST_SLHDSA_DECLS                                                      \
    TEST_DECL_GROUP("slhdsa", test_wc_slhdsa),                                 \
    TEST_DECL_GROUP("slhdsa", test_wc_slhdsa_sizes),                           \
    TEST_DECL_GROUP("slhdsa", test_wc_slhdsa_make_key),                        \
    TEST_DECL_GROUP("slhdsa", test_wc_slhdsa_sign),                            \
    TEST_DECL_GROUP("slhdsa", test_wc_slhdsa_verify),                          \
    TEST_DECL_GROUP("slhdsa", test_wc_slhdsa_sign_vfy),                        \
    TEST_DECL_GROUP("slhdsa", test_wc_slhdsa_sign_hash),                       \
    TEST_DECL_GROUP("slhdsa", test_wc_slhdsa_export_import),                   \
    TEST_DECL_GROUP("slhdsa", test_wc_slhdsa_check_key)

#endif /* WOLFCRYPT_TEST_SLHDSA_H */
