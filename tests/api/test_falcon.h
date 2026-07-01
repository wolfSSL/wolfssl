/* test_falcon.h
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

#ifndef WOLFCRYPT_TEST_FALCON_H
#define WOLFCRYPT_TEST_FALCON_H

#include <tests/api/api_decl.h>

int test_wc_falcon_sizes(void);
int test_wc_falcon_make_key(void);
int test_wc_falcon_sign_vfy(void);
int test_wc_falcon_import_export(void);
int test_wc_falcon_check_key(void);
int test_wc_falcon_der(void);
int test_wc_falcon_error_paths(void);

#define TEST_FALCON_DECLS                                                      \
    TEST_DECL_GROUP("falcon", test_wc_falcon_sizes),                          \
    TEST_DECL_GROUP("falcon", test_wc_falcon_make_key),                       \
    TEST_DECL_GROUP("falcon", test_wc_falcon_sign_vfy),                       \
    TEST_DECL_GROUP("falcon", test_wc_falcon_import_export),                  \
    TEST_DECL_GROUP("falcon", test_wc_falcon_check_key),                      \
    TEST_DECL_GROUP("falcon", test_wc_falcon_der),                            \
    TEST_DECL_GROUP("falcon", test_wc_falcon_error_paths)

#endif /* WOLFCRYPT_TEST_FALCON_H */
