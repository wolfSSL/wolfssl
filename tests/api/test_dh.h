/* test_dh.h
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

#ifndef WOLFCRYPT_TEST_DH_H
#define WOLFCRYPT_TEST_DH_H

#include <tests/api/api_decl.h>

int test_wc_DhPublicKeyDecode(void);
int test_wc_DhAgree_subgroup_check(void);
int test_wc_DhSetKey(void);
int test_wc_DhSetNamedKey_and_helpers(void);
int test_wc_DhGenerateKeyPair_bad_args(void);
int test_wc_DhGenerateKeyPair_and_Agree(void);
int test_wc_DhAgree_nonblock(void);
int test_wc_DhImportExportKeyPair(void);
int test_wc_DhCheckPubKey(void);
int test_wc_DhCheckPrivKey(void);
int test_wc_DhCheckKeyPair(void);
int test_wc_DhGenerateParams_and_ExportRaw(void);
int test_wc_DhGenerateKeyPair_CheckDhLN(void);

#define TEST_DH_DECLS                                              \
    TEST_DECL_GROUP("dh", test_wc_DhPublicKeyDecode),               \
    TEST_DECL_GROUP("dh", test_wc_DhAgree_subgroup_check),          \
    TEST_DECL_GROUP("dh", test_wc_DhSetKey),                        \
    TEST_DECL_GROUP("dh", test_wc_DhSetNamedKey_and_helpers),       \
    TEST_DECL_GROUP("dh", test_wc_DhGenerateKeyPair_bad_args),      \
    TEST_DECL_GROUP("dh", test_wc_DhGenerateKeyPair_and_Agree),     \
    TEST_DECL_GROUP("dh", test_wc_DhAgree_nonblock),                \
    TEST_DECL_GROUP("dh", test_wc_DhImportExportKeyPair),           \
    TEST_DECL_GROUP("dh", test_wc_DhCheckPubKey),                   \
    TEST_DECL_GROUP("dh", test_wc_DhCheckPrivKey),                  \
    TEST_DECL_GROUP("dh", test_wc_DhCheckKeyPair),                  \
    TEST_DECL_GROUP("dh", test_wc_DhGenerateParams_and_ExportRaw),  \
    TEST_DECL_GROUP("dh", test_wc_DhGenerateKeyPair_CheckDhLN)

#endif /* WOLFCRYPT_TEST_DH_H */
