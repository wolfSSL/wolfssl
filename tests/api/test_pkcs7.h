/* test_pkcs7.h
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

#ifndef WOLFCRYPT_TEST_PKCS7_H
#define WOLFCRYPT_TEST_PKCS7_H

#include <tests/api/api_decl.h>

int test_wc_PKCS7_New(void);
int test_wc_PKCS7_Init(void);
int test_wc_PKCS7_InitWithCert(void);
int test_wc_PKCS7_EncodeData(void);
int test_wc_PKCS7_EncodeSignedData(void);
int test_wc_PKCS7_EncodeSignedData_ex(void);
int test_wc_PKCS7_VerifySignedData_RSA(void);
int test_wc_PKCS7_VerifySignedData_ECC(void);
int test_wc_PKCS7_DecodeEnvelopedData_stream(void);
int test_wc_PKCS7_EncodeDecodeEnvelopedData(void);
int test_wc_PKCS7_SetAESKeyWrapUnwrapCb(void);
int test_wc_PKCS7_GetEnvelopedDataKariRid(void);
int test_wc_PKCS7_EncodeEncryptedData(void);
int test_wc_PKCS7_DecodeEncryptedKeyPackage(void);
int test_wc_PKCS7_DecodeSymmetricKeyPackage(void);
int test_wc_PKCS7_DecodeOneSymmetricKey(void);
int test_wc_PKCS7_Degenerate(void);
int test_wc_PKCS7_BER(void);
int test_wc_PKCS7_signed_enveloped(void);
int test_wc_PKCS7_NoDefaultSignedAttribs(void);
int test_wc_PKCS7_SetOriEncryptCtx(void);
int test_wc_PKCS7_SetOriDecryptCtx(void);
int test_wc_PKCS7_DecodeCompressedData(void);


#define TEST_PKCS7_DECLS                                        \
    TEST_DECL_GROUP("pkcs7", test_wc_PKCS7_New),                \
    TEST_DECL_GROUP("pkcs7", test_wc_PKCS7_Init)

#define TEST_PKCS7_SIGNED_DATA_DECLS                                    \
    TEST_DECL_GROUP("pkcs7_sd", test_wc_PKCS7_InitWithCert),            \
    TEST_DECL_GROUP("pkcs7_sd", test_wc_PKCS7_EncodeData),              \
    TEST_DECL_GROUP("pkcs7_sd", test_wc_PKCS7_EncodeSignedData),        \
    TEST_DECL_GROUP("pkcs7_sd", test_wc_PKCS7_EncodeSignedData_ex),     \
    TEST_DECL_GROUP("pkcs7_sd", test_wc_PKCS7_VerifySignedData_RSA),    \
    TEST_DECL_GROUP("pkcs7_sd", test_wc_PKCS7_VerifySignedData_ECC),    \
    TEST_DECL_GROUP("pkcs7_sd", test_wc_PKCS7_Degenerate),              \
    TEST_DECL_GROUP("pkcs7_sd", test_wc_PKCS7_BER),                     \
    TEST_DECL_GROUP("pkcs7_sd", test_wc_PKCS7_NoDefaultSignedAttribs)

#define TEST_PKCS7_ENCRYPTED_DATA_DECLS                                     \
    TEST_DECL_GROUP("pkcs7_ed", test_wc_PKCS7_DecodeEnvelopedData_stream),  \
    TEST_DECL_GROUP("pkcs7_ed", test_wc_PKCS7_EncodeDecodeEnvelopedData),   \
    TEST_DECL_GROUP("pkcs7_ed", test_wc_PKCS7_SetAESKeyWrapUnwrapCb),       \
    TEST_DECL_GROUP("pkcs7_ed", test_wc_PKCS7_GetEnvelopedDataKariRid),     \
    TEST_DECL_GROUP("pkcs7_ed", test_wc_PKCS7_EncodeEncryptedData),         \
    TEST_DECL_GROUP("pkcs7_ed", test_wc_PKCS7_DecodeEncryptedKeyPackage),   \
    TEST_DECL_GROUP("pkcs7_ed", test_wc_PKCS7_DecodeSymmetricKeyPackage),   \
    TEST_DECL_GROUP("pkcs7_ed", test_wc_PKCS7_DecodeOneSymmetricKey),       \
    TEST_DECL_GROUP("pkcs7_ed", test_wc_PKCS7_SetOriEncryptCtx),            \
    TEST_DECL_GROUP("pkcs7_ed", test_wc_PKCS7_SetOriDecryptCtx)

#define TEST_PKCS7_SIGNED_ENCRYPTED_DATA_DECLS                              \
    TEST_DECL_GROUP("pkcs7_sed", test_wc_PKCS7_signed_enveloped)

#define TEST_PKCS7_COMPRESSED_DATA_DECLS                                    \
    TEST_DECL_GROUP("pkcs7_cd", test_wc_PKCS7_DecodeCompressedData)

#endif /* WOLFCRYPT_TEST_PKCS7_H */
