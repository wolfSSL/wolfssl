/* wc_encrypt.c
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/wc_encrypt.h>
#include <wolfssl/wolfcrypt/error-crypt.h>


#ifndef NO_AES
int wc_AesCbcDecryptWithKey(byte* out, const byte* in, word32 inSz,
                                  const byte* key, word32 keySz, const byte* iv)
{
    int  ret = 0;
#ifdef WOLFSSL_SMALL_STACK
    Aes* aes = NULL;
#else
    Aes  aes[1];
#endif

#ifdef WOLFSSL_SMALL_STACK
    aes = (Aes*)XMALLOC(sizeof(Aes), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (aes == NULL)
        return MEMORY_E;
#endif

    ret = wc_AesSetKey(aes, key, keySz, iv, AES_DECRYPTION);
    if (ret == 0)
        ret = wc_AesCbcDecrypt(aes, out, in, inSz); 

#ifdef WOLFSSL_SMALL_STACK
    XFREE(aes, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

int wc_AesCbcEncryptWithKey(byte* out, const byte* in, word32 inSz,
                            const byte* key, word32 keySz, const byte* iv)
{
    int  ret = 0;
#ifdef WOLFSSL_SMALL_STACK
    Aes* aes = NULL;
#else
    Aes  aes[1];
#endif

#ifdef WOLFSSL_SMALL_STACK
    aes = (Aes*)XMALLOC(sizeof(Aes), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (aes == NULL)
        return MEMORY_E;
#endif

    ret = wc_AesSetKey(aes, key, keySz, iv, AES_ENCRYPTION);
    if (ret == 0)
        ret = wc_AesCbcEncrypt(aes, out, in, inSz);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(aes, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}
#endif /* !NO_AES */

