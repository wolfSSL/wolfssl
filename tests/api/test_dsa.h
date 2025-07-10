/* test_dsa.h
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

#ifndef WOLFCRYPT_TEST_DSA_H
#define WOLFCRYPT_TEST_DSA_H

#include <tests/api/api_decl.h>

int test_wc_InitDsaKey(void);
int test_wc_DsaSignVerify(void);
int test_wc_DsaPublicPrivateKeyDecode(void);
int test_wc_MakeDsaKey(void);
int test_wc_DsaKeyToDer(void);
int test_wc_DsaKeyToPublicDer(void);
int test_wc_DsaImportParamsRaw(void);
int test_wc_DsaImportParamsRawCheck(void);
int test_wc_DsaExportParamsRaw(void);
int test_wc_DsaExportKeyRaw(void);

#define TEST_DSA_DECLS                                          \
    TEST_DECL_GROUP("dsa", test_wc_InitDsaKey),                 \
    TEST_DECL_GROUP("dsa", test_wc_DsaSignVerify),              \
    TEST_DECL_GROUP("dsa", test_wc_DsaPublicPrivateKeyDecode),  \
    TEST_DECL_GROUP("dsa", test_wc_MakeDsaKey),                 \
    TEST_DECL_GROUP("dsa", test_wc_DsaKeyToDer),                \
    TEST_DECL_GROUP("dsa", test_wc_DsaKeyToPublicDer),          \
    TEST_DECL_GROUP("dsa", test_wc_DsaImportParamsRaw),         \
    TEST_DECL_GROUP("dsa", test_wc_DsaImportParamsRawCheck),    \
    TEST_DECL_GROUP("dsa", test_wc_DsaExportParamsRaw),         \
    TEST_DECL_GROUP("dsa", test_wc_DsaExportKeyRaw)

#endif /* WOLFCRYPT_TEST_DSA_H */
