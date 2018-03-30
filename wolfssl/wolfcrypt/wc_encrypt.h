/* wc_encrypt.h
 *
 * Copyright (C) 2006-2017 wolfSSL Inc.
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

/*!
    \file wolfssl/wolfcrypt/wc_encrypt.h
*/


#ifndef WOLF_CRYPT_ENCRYPT_H
#define WOLF_CRYPT_ENCRYPT_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef __cplusplus
    extern "C" {
#endif

enum CipherTypes {
    WC_CIPHER_NONE,
#ifndef NO_AES
    #ifdef HAVE_AES_CBC
        WC_CIPHER_AES_CBC,
    #endif
    #ifdef HAVE_AESGCM
        WC_CIPHER_AES_GCM,
    #endif
    #ifdef WOLFSSL_AES_COUNTER
        WC_CIPHER_AES_CTR,
    #endif
    #ifdef WOLFSSL_AES_XTS
        WC_CIPHER_AES_XTS,
    #endif
    #ifdef WOLFSSL_AES_CFB
        WC_CIPHER_AES_CFB,
    #endif
#endif
#ifndef NO_DES3
    WC_CIPHER_DES3,
#endif
#ifndef NO_DES
    WC_CIPHER_DES,
#endif
#ifdef HAVE_CHAHCA
    WC_CIPHER_CHACHA,
#endif
#ifdef HAVE_HC128
    WC_CIPHER_HC128,
#endif
};


#ifndef NO_AES
WOLFSSL_API int wc_AesCbcEncryptWithKey(byte* out, const byte* in, word32 inSz,
                                        const byte* key, word32 keySz,
                                        const byte* iv);
WOLFSSL_API int wc_AesCbcDecryptWithKey(byte* out, const byte* in, word32 inSz,
                                        const byte* key, word32 keySz,
                                        const byte* iv);
#endif /* !NO_AES */


#ifndef NO_DES3
WOLFSSL_API int wc_Des_CbcDecryptWithKey(byte* out,
                                         const byte* in, word32 sz,
                                         const byte* key, const byte* iv);
WOLFSSL_API int wc_Des_CbcEncryptWithKey(byte* out,
                                         const byte* in, word32 sz,
                                         const byte* key, const byte* iv);
WOLFSSL_API int wc_Des3_CbcEncryptWithKey(byte* out,
                                          const byte* in, word32 sz,
                                          const byte* key, const byte* iv);
WOLFSSL_API int wc_Des3_CbcDecryptWithKey(byte* out,
                                          const byte* in, word32 sz,
                                          const byte* key, const byte* iv);
#endif /* !NO_DES3 */




#ifdef WOLFSSL_ENCRYPTED_KEYS
    struct EncryptedInfo;
    WOLFSSL_API int wc_BufferKeyDecrypt(struct EncryptedInfo* info, byte* der, word32 derSz,
        const byte* password, int passwordSz);
    WOLFSSL_API int wc_BufferKeyEncrypt(struct EncryptedInfo* info, byte* der, word32 derSz,
        const byte* password, int passwordSz);
#endif /* WOLFSSL_ENCRYPTED_KEYS */

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLF_CRYPT_ENCRYPT_H */

