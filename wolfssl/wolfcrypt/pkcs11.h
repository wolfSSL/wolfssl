/* pkcs11.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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


#ifndef WOLF_CRYPT_PKCS11_H
#define WOLF_CRYPT_PKCS11_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef HAVE_PKCS11

/* SoftHSM includes */
#include <opencryptoki/pkcs11.h>
#include <softhsm/cryptoki.h>


#ifdef __cplusplus
    extern "C" {
#endif

#ifndef CK_SIZE
#define CK_SIZE CK_ULONG
#endif

WOLFSSL_API int wc_PKCS11_Init(void);
WOLFSSL_API void wc_PKCS11_Cleanup(void);

WOLFSSL_API int wc_PKCS11_OpenSession(CK_SLOT_ID slotId, CK_CHAR_PTR pin,
                                      CK_SESSION_HANDLE_PTR sessionId);
WOLFSSL_API void wc_PKCS11_CloseSession(CK_SESSION_HANDLE sessionId);

WOLFSSL_API int wc_PKCS11_KeyLoad(CK_SESSION_HANDLE sessionId,
                                   CK_CHAR_PTR keyName, int keyType,
                                   CK_OBJECT_HANDLE *hKey);
WOLFSSL_API int wc_PKCS11_ReadPublicKey(CK_SESSION_HANDLE sessionId,
                                        CK_OBJECT_HANDLE hkey,
                                        byte **modulus, word32 *modulusSz,
                                        byte **exponent, word32 *exponentSz);
WOLFSSL_API int wc_PKCS11_GetPublicKey(CK_SESSION_HANDLE sessionId,
                                       CK_BYTE_PTR pModulus,
                                       CK_ULONG pModulusSz,
                                       CK_OBJECT_HANDLE_PTR phKpub);
WOLFSSL_API int wc_PKCS11_PrivateKeyEncodeDer(byte* key,
                                              word32 *keySz,
                                              CK_OBJECT_HANDLE hPrvkey,
                                              CK_OBJECT_HANDLE hPubkey);
WOLFSSL_API int wc_PKCS11_GenerateRsa(CK_SESSION_HANDLE sessionId,
                                      CK_SIZE keySize,
                                      CK_CHAR_PTR keyName);
WOLFSSL_API int wc_PKCS11_DeleteRsa(CK_SESSION_HANDLE sessionId,
                                    CK_CHAR_PTR keyName);

WOLFSSL_API int wc_PKCS11_RsaSign(CK_SESSION_HANDLE sessionId,
                                  CK_OBJECT_HANDLE hPrvKey,
                                  CK_BYTE_PTR digest, CK_ULONG digestLen,
                                  CK_BYTE_PTR sign, CK_ULONG_PTR signLen);
WOLFSSL_API int wc_PKCS11_RsaVerify(CK_SESSION_HANDLE sessionId,
                                    CK_OBJECT_HANDLE hPubKey,
                                    CK_BYTE_PTR digest, CK_ULONG digestLen,
                                    CK_BYTE_PTR sign, CK_ULONG signLen);

WOLFSSL_API int wc_PKCS11_RsaEncrypt(CK_SESSION_HANDLE sessionId,
                                     CK_OBJECT_HANDLE hPubKey,
                                     CK_BYTE_PTR data, CK_ULONG dataLen,
                                     CK_BYTE_PTR encData,
                                     CK_ULONG_PTR encDataLen);
WOLFSSL_API int wc_PKCS11_RsaDecrypt(CK_SESSION_HANDLE sessionId,
                                     CK_OBJECT_HANDLE hPrvKey,
                                     CK_BYTE_PTR encData, CK_ULONG encDataLen,
                                     CK_BYTE_PTR data, CK_ULONG_PTR dataLen);

WOLFSSL_API int wc_PKCS11_RsaEncryptRaw(CK_SESSION_HANDLE sessionId,
                                        CK_OBJECT_HANDLE hPubKey,
                                        CK_BYTE_PTR data, CK_ULONG dataLen,
                                        CK_BYTE_PTR encData,
                                        CK_ULONG_PTR encDataLen);
WOLFSSL_API int wc_PKCS11_RsaDecryptRaw(CK_SESSION_HANDLE sessionId,
                                        CK_OBJECT_HANDLE hPrvKey,
                                        CK_BYTE_PTR encData, CK_ULONG encDataLen,
                                        CK_BYTE_PTR data, CK_ULONG_PTR dataLen);

WOLFSSL_API int wc_PKCS11_RsaEncryptOAEP(CK_SESSION_HANDLE sessionId,
                                         CK_OBJECT_HANDLE hPubKey,
                                         CK_BYTE_PTR data, CK_ULONG dataLen,
                                         CK_BYTE_PTR encData,
                                         CK_ULONG_PTR encDataLen,
                                         CK_BYTE_PTR label, CK_ULONG labelLen,
                                         int hash_type, int mgf);
WOLFSSL_API int wc_PKCS11_RsaDecryptOAEP(CK_SESSION_HANDLE sessionId,
                                         CK_OBJECT_HANDLE hPubKey,
                                         CK_BYTE_PTR encData,
                                         CK_ULONG encDataLen,
                                         CK_BYTE_PTR data, CK_ULONG_PTR dataLen,
                                         CK_BYTE_PTR label, CK_ULONG labelLen,
                                         int hash_type, int mgf);
#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_PKCS11 */
#endif /* WOLF_CRYPT_PKCS11_H */

