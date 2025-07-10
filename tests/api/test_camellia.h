/* test_camellia.h
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

#ifndef WOLFCRYPT_TEST_CAMELLIA_H
#define WOLFCRYPT_TEST_CAMELLIA_H

#include <tests/api/api_decl.h>

int test_wc_CamelliaSetKey(void);
int test_wc_CamelliaSetIV(void);
int test_wc_CamelliaEncryptDecryptDirect(void);
int test_wc_CamelliaCbcEncryptDecrypt(void);

#define TEST_CAMELLIA_DECLS                                             \
    TEST_DECL_GROUP("camellia", test_wc_CamelliaSetKey),                \
    TEST_DECL_GROUP("camellia", test_wc_CamelliaSetIV),                 \
    TEST_DECL_GROUP("camellia", test_wc_CamelliaEncryptDecryptDirect),  \
    TEST_DECL_GROUP("camellia", test_wc_CamelliaCbcEncryptDecrypt)

#endif /* WOLFCRYPT_TEST_CAMELLIA_H */
