/* test_ripemd.h
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

#ifndef WOLFCRYPT_TEST_RIPEMD_H
#define WOLFCRYPT_TEST_RIPEMD_H

#include <tests/api/api_decl.h>

int test_wc_InitRipeMd(void);
int test_wc_RipeMdUpdate(void);
int test_wc_RipeMdFinal(void);
int test_wc_RipeMd_KATs(void);
int test_wc_RipeMd_other(void);

#define TEST_RIPEMD_DECLS                               \
    TEST_DECL_GROUP("ripemd", test_wc_InitRipeMd),      \
    TEST_DECL_GROUP("ripemd", test_wc_RipeMdUpdate),    \
    TEST_DECL_GROUP("ripemd", test_wc_RipeMdFinal),     \
    TEST_DECL_GROUP("ripemd", test_wc_RipeMd_KATs),     \
    TEST_DECL_GROUP("ripemd", test_wc_RipeMd_other)

#endif /* WOLFCRYPT_TEST_RIPEMD_H */
