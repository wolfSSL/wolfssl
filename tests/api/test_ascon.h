/* test_ascon.h
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

#ifndef TESTS_API_TEST_ASCON_H
#define TESTS_API_TEST_ASCON_H

#include <tests/api/api_decl.h>

int test_ascon_hash256(void);
int test_ascon_aead128(void);

#define TEST_ASCON_DECLS                            \
    TEST_DECL_GROUP("ascon", test_ascon_hash256),   \
    TEST_DECL_GROUP("ascon", test_ascon_aead128)

#endif /* TESTS_API_TEST_ASCON_H */
