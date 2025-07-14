/* test_arc4.h
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

#ifndef WOLFCRYPT_TEST_ARC4_H
#define WOLFCRYPT_TEST_ARC4_H

#include <tests/api/api_decl.h>

int test_wc_Arc4SetKey(void);
int test_wc_Arc4Process(void);

#define TEST_ARC4_DECLS                             \
    TEST_DECL_GROUP("arc4", test_wc_Arc4SetKey),    \
    TEST_DECL_GROUP("arc4", test_wc_Arc4Process)

#endif /* WOLFCRYPT_TEST_ARC4_H */
