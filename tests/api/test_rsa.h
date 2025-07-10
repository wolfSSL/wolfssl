/* test_rsa.h
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

#ifndef WOLFCRYPT_TEST_RSA_H
#define WOLFCRYPT_TEST_RSA_H

#include <tests/api/api_decl.h>

int test_wc_InitRsaKey(void);
int test_wc_RsaPrivateKeyDecode(void);
int test_wc_RsaPublicKeyDecode(void);
int test_wc_RsaPublicKeyDecodeRaw(void);
int test_wc_RsaPrivateKeyDecodeRaw(void);
int test_wc_MakeRsaKey(void);
int test_wc_CheckProbablePrime(void);
int test_wc_RsaPSS_Verify(void);
int test_wc_RsaPSS_VerifyCheck(void);
int test_wc_RsaPSS_VerifyCheckInline(void);
int test_wc_RsaKeyToDer(void);
int test_wc_RsaKeyToPublicDer(void);
int test_wc_RsaPublicEncryptDecrypt(void);
int test_wc_RsaPublicEncryptDecrypt_ex(void);
int test_wc_RsaEncryptSize(void);
int test_wc_RsaSSL_SignVerify(void);
int test_wc_RsaFlattenPublicKey(void);
int test_wc_RsaDecrypt_BoundsCheck(void);

#define TEST_RSA_DECLS                                          \
    TEST_DECL_GROUP("rsa", test_wc_InitRsaKey),                 \
    TEST_DECL_GROUP("rsa", test_wc_RsaPrivateKeyDecode),        \
    TEST_DECL_GROUP("rsa", test_wc_RsaPublicKeyDecode),         \
    TEST_DECL_GROUP("rsa", test_wc_RsaPublicKeyDecodeRaw),      \
    TEST_DECL_GROUP("rsa", test_wc_RsaPrivateKeyDecodeRaw),     \
    TEST_DECL_GROUP("rsa", test_wc_MakeRsaKey),                 \
    TEST_DECL_GROUP("rsa", test_wc_CheckProbablePrime),         \
    TEST_DECL_GROUP("rsa", test_wc_RsaPSS_Verify),              \
    TEST_DECL_GROUP("rsa", test_wc_RsaPSS_VerifyCheck),         \
    TEST_DECL_GROUP("rsa", test_wc_RsaPSS_VerifyCheckInline),   \
    TEST_DECL_GROUP("rsa", test_wc_RsaKeyToDer),                \
    TEST_DECL_GROUP("rsa", test_wc_RsaKeyToPublicDer),          \
    TEST_DECL_GROUP("rsa", test_wc_RsaPublicEncryptDecrypt),    \
    TEST_DECL_GROUP("rsa", test_wc_RsaPublicEncryptDecrypt_ex), \
    TEST_DECL_GROUP("rsa", test_wc_RsaEncryptSize),             \
    TEST_DECL_GROUP("rsa", test_wc_RsaSSL_SignVerify),          \
    TEST_DECL_GROUP("rsa", test_wc_RsaFlattenPublicKey),        \
    TEST_DECL_GROUP("rsa", test_wc_RsaDecrypt_BoundsCheck)

#endif /* WOLFCRYPT_TEST_RSA_H */
