/* test_md2.h
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

#ifndef WOLFCRYPT_TEST_MD2_H
#define WOLFCRYPT_TEST_MD2_H

#include <tests/api/api_decl.h>

int test_wc_InitMd2(void);
int test_wc_Md2Update(void);
int test_wc_Md2Final(void);
int test_wc_Md2_KATs(void);
int test_wc_Md2_other(void);
int test_wc_Md2Hash(void);

#define TEST_MD2_DECLS                          \
    TEST_DECL_GROUP("md2", test_wc_InitMd2),    \
    TEST_DECL_GROUP("md2", test_wc_Md2Update),  \
    TEST_DECL_GROUP("md2", test_wc_Md2Final),   \
    TEST_DECL_GROUP("md2", test_wc_Md2_KATs),   \
    TEST_DECL_GROUP("md2", test_wc_Md2_other),  \
    TEST_DECL_GROUP("md2", test_wc_Md2Hash)

#endif /* WOLFCRYPT_TEST_MD2_H */
