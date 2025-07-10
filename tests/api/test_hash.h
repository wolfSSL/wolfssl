/* test_hash.h
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

#ifndef WOLFCRYPT_TEST_HASH_H
#define WOLFCRYPT_TEST_HASH_H

#include <tests/api/api_decl.h>

int test_wc_HashInit(void);
int test_wc_HashUpdate(void);
int test_wc_HashFinal(void);
int test_wc_HashNewDelete(void);
int test_wc_HashGetDigestSize(void);
int test_wc_HashGetBlockSize(void);
int test_wc_Hash(void);
int test_wc_HashSetFlags(void);
int test_wc_HashGetFlags(void);
int test_wc_Hash_Algs(void);
int test_wc_HashGetOID(void);
int test_wc_OidGetHash(void);

#define TEST_HASH_DECLS                                 \
    TEST_DECL_GROUP("hash", test_wc_HashInit),          \
    TEST_DECL_GROUP("hash", test_wc_HashUpdate),        \
    TEST_DECL_GROUP("hash", test_wc_HashFinal),         \
    TEST_DECL_GROUP("hash", test_wc_HashNewDelete),     \
    TEST_DECL_GROUP("hash", test_wc_HashGetDigestSize), \
    TEST_DECL_GROUP("hash", test_wc_HashGetBlockSize),  \
    TEST_DECL_GROUP("hash", test_wc_Hash),              \
    TEST_DECL_GROUP("hash", test_wc_HashSetFlags),      \
    TEST_DECL_GROUP("hash", test_wc_HashGetFlags),      \
    TEST_DECL_GROUP("hash", test_wc_Hash_Algs),         \
    TEST_DECL_GROUP("hash", test_wc_HashGetOID),        \
    TEST_DECL_GROUP("hash", test_wc_OidGetHash)

#endif /* WOLFCRYPT_TEST_HASH_H */
