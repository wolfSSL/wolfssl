/* pkcs12.h
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


#ifndef WOLF_CRYPT_PKCS12_H
#define WOLF_CRYPT_PKCS12_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef __cplusplus
    extern "C" {
#endif


enum {
    WC_PKCS12_KeyBag = 667,
    WC_PKCS12_ShroudedKeyBag = 668,
    WC_PKCS12_CertBag = 669,
    WC_PKCS12_CertBag_Type1 = 675,
    WC_PKCS12_CrlBag = 670,
    WC_PKCS12_SecretBag = 671,
    WC_PKCS12_SafeContentsBag = 672,
    WC_PKCS12_DATA = 651,
    WC_PKCS12_ENCRYPTED_DATA = 656,
};


typedef struct DerCertList DerCertList;
typedef struct DerCertList {
    byte* buffer;
    word32 bufferSz;
    DerCertList* next;
} DerCertList;


typedef struct ContentInfo ContentInfo;
typedef struct ContentInfo {
    byte* data;
    ContentInfo* next;
    word32 encC;  /* encryptedContent */
    word32 dataSz;
    int type; /* DATA / encrypted / envelpoed */
} ContentInfo;


typedef struct AuthenticatedSafe {
    ContentInfo* CI;
    byte* data; /* T contents.... */
    word32 oid; /* encrypted or not */
    word32 numCI; /* number of Content Info structs */
    word32 dataSz;
} AuthenticatedSafe;


typedef struct MacData {
    byte* digest;
    byte* salt;
    word32 oid;
    word32 digestSz;
    word32 saltSz;
    int itt; /* number of itterations when creating HMAC key */
} MacData;


/* for friendlyName, localKeyId .... */
typedef struct WC_PKCS12_ATTRIBUTE {
    byte* data;
    word32 oid;
    word32 dataSz;
} WC_PKCS12_ATTRIBUTE;


typedef struct WC_PKCS12 {
    void* heap;
    AuthenticatedSafe* safe;
    MacData* signData;
    word32 oid; /* DATA / Enveloped DATA ... */
} WC_PKCS12;


WOLFSSL_API WC_PKCS12* wc_PKCS12_new(void);
WOLFSSL_API void wc_PKCS12_free(WC_PKCS12* pkcs12);
WOLFSSL_API int wc_d2i_PKCS12(const byte* der, word32 derSz, WC_PKCS12* pkcs12);
WOLFSSL_API int wc_PKCS12_parse(WC_PKCS12* pkcs12, const char* psw,
        byte** pkey, word32* pkeySz, byte** cert, word32* certSz,
        DerCertList** ca);

WOLFSSL_LOCAL int wc_PKCS12_SetHeap(WC_PKCS12* pkcs12, void* heap);


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLF_CRYPT_PKCS12_H */

