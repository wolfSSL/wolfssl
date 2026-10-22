/* test_pkcs11.h
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

#ifndef WOLFCRYPT_TEST_PKCS11_H
#define WOLFCRYPT_TEST_PKCS11_H

#include <tests/api/api_decl.h>

#if defined(HAVE_PKCS11) && defined(HAVE_ECC) && \
    defined(HAVE_ECC_VERIFY) && !defined(WC_NO_RNG) && \
    !defined(NO_ECC256) && !defined(NO_ECC_SECP)

int test_wc_Pkcs11_EcdsaSigDecode(void);
int test_wc_Pkcs11_FreeKeepsTokenKey(void);
int test_wc_Pkcs11_StoreKeyPersistent(void);
int test_wc_Pkcs11_PersistKey(void);
int test_wc_Pkcs11_DeleteKey(void);
int test_wc_Pkcs11_RsaIdNoLeak(void);
int test_wc_Pkcs11_EcKeyUsage(void);
int test_wc_Pkcs11_RsaKeyGenError(void);
int test_wc_Pkcs11_RsaKeyGenExponent(void);
int test_wc_Pkcs11_KeyGenPersistent(void);
int test_wc_Pkcs11_KeyNames(void);
int test_wc_Pkcs11_FreeNoObject(void);
int test_wc_Pkcs11_KeyGenSessionClosed(void);
int test_wc_Pkcs11_SecretKeyPersist(void);
int test_wc_Pkcs11_RsaPersistDelete(void);
int test_wc_Pkcs11_PqcPersistDelete(void);
int test_wc_Pkcs11_PersistPaths(void);
int test_wc_Pkcs11_PqcKeyGen(void);

#define TEST_PKCS11_DECLS                                                   \
    TEST_DECL_GROUP("pkcs11", test_wc_Pkcs11_EcdsaSigDecode),               \
    TEST_DECL_GROUP("pkcs11", test_wc_Pkcs11_FreeKeepsTokenKey),            \
    TEST_DECL_GROUP("pkcs11", test_wc_Pkcs11_StoreKeyPersistent),           \
    TEST_DECL_GROUP("pkcs11", test_wc_Pkcs11_PersistKey),                   \
    TEST_DECL_GROUP("pkcs11", test_wc_Pkcs11_DeleteKey),                    \
    TEST_DECL_GROUP("pkcs11", test_wc_Pkcs11_RsaIdNoLeak),                  \
    TEST_DECL_GROUP("pkcs11", test_wc_Pkcs11_EcKeyUsage),                   \
    TEST_DECL_GROUP("pkcs11", test_wc_Pkcs11_RsaKeyGenError),               \
    TEST_DECL_GROUP("pkcs11", test_wc_Pkcs11_RsaKeyGenExponent),            \
    TEST_DECL_GROUP("pkcs11", test_wc_Pkcs11_KeyGenPersistent),             \
    TEST_DECL_GROUP("pkcs11", test_wc_Pkcs11_KeyNames),                     \
    TEST_DECL_GROUP("pkcs11", test_wc_Pkcs11_FreeNoObject),                 \
    TEST_DECL_GROUP("pkcs11", test_wc_Pkcs11_KeyGenSessionClosed),          \
    TEST_DECL_GROUP("pkcs11", test_wc_Pkcs11_SecretKeyPersist),             \
    TEST_DECL_GROUP("pkcs11", test_wc_Pkcs11_RsaPersistDelete),             \
    TEST_DECL_GROUP("pkcs11", test_wc_Pkcs11_PqcPersistDelete),             \
    TEST_DECL_GROUP("pkcs11", test_wc_Pkcs11_PersistPaths),                 \
    TEST_DECL_GROUP("pkcs11", test_wc_Pkcs11_PqcKeyGen)

#else

#define TEST_PKCS11_DECLS

#endif

#endif /* WOLFCRYPT_TEST_PKCS11_H */
