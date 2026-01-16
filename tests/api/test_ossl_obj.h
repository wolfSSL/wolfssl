/* test_ossl_obj.h
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

#ifndef WOLFCRYPT_TEST_OSSL_OBJ_H
#define WOLFCRYPT_TEST_OSSL_OBJ_H

#include <tests/api/api_decl.h>

int test_OBJ_NAME_do_all(void);
int test_wolfSSL_OBJ(void);
int test_wolfSSL_OBJ_cmp(void);
int test_wolfSSL_OBJ_txt2nid(void);
int test_wolfSSL_OBJ_txt2obj(void);
int test_wolfSSL_OBJ_ln(void);
int test_wolfSSL_OBJ_sn(void);

#define TEST_OSSL_OBJ_DECLS                                 \
    TEST_DECL_GROUP("ossl_obj", test_OBJ_NAME_do_all),      \
    TEST_DECL_GROUP("ossl_obj", test_wolfSSL_OBJ),          \
    TEST_DECL_GROUP("ossl_obj", test_wolfSSL_OBJ_cmp),      \
    TEST_DECL_GROUP("ossl_obj", test_wolfSSL_OBJ_txt2nid),  \
    TEST_DECL_GROUP("ossl_obj", test_wolfSSL_OBJ_txt2obj),  \
    TEST_DECL_GROUP("ossl_obj", test_wolfSSL_OBJ_ln),       \
    TEST_DECL_GROUP("ossl_obj", test_wolfSSL_OBJ_sn)

#endif /* WOLFCRYPT_TEST_OSSL_OBJ_H */

