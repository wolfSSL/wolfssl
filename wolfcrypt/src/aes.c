/* aes.c
 *
 * Copyright (C) 2006-2014 wolfSSL Inc.
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

#include <cyassl/ctaocrypt/settings.h>

#ifndef NO_AES

#include <wolfssl/wolfcrypt/aes.h>

#ifdef __cplusplus
    extern "C" {
#endif



int wc_AesSetKey(Aes* aes, const byte* key, word32 len, const byte* iv,
                          int dir)
{
    return AesSetKey(aes, key, len, iv, dir);
}


int wc_AesSetIV(Aes* aes, const byte* iv)
{
    return AesSetIV(aes, iv);
}


int wc_AesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    return AesCbcEncrypt(aes, out, in, sz);
}


int wc_AesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    return AesCbcDecrypt(aes, out, in, sz);
}


int wc_AesCbcDecryptWithKey(byte* out, const byte* in, word32 inSz,
                                 const byte* key, word32 keySz, const byte* iv)
{
    return AesCbcDecryptWithKey(out, in, inSz, key, keySz, iv);
}


/* AES-CTR */
#ifdef CYASSL_AES_COUNTER
void wc_AesCtrEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    AesCtrEncrypt(aes, out, in, sz);
}
#endif

/* AES-DIRECT */
#if defined(CYASSL_AES_DIRECT)
void wc_AesEncryptDirect(Aes* aes, byte* out, const byte* in)
{
    AesEncryptDirect(aes, out, in);
}


void wc_AesDecryptDirect(Aes* aes, byte* out, const byte* in)
{
    AesDecryptDirect(aes, out, in);
}


int wc_AesSetKeyDirect(Aes* aes, const byte* key, word32 len,
                                const byte* iv, int dir)
{
    return AesSetKeyDirect(aes, key, len, iv, dir);
}
#endif


#ifdef HAVE_AESGCM
int wc_AesGcmSetKey(Aes* aes, const byte* key, word32 len)
{
    return AesGcmSetKey(aes, key, len);
}


int wc_AesGcmEncrypt(Aes* aes, byte* out, const byte* in, word32 sz,
                              const byte* iv, word32 ivSz,
                              byte* authTag, word32 authTagSz,
                              const byte* authIn, word32 authInSz)
{
    return AesGcmEncrypt(aes, out, in, sz, iv, ivSz, authTag, authTagSz,
                              authIn, authInSz);
}


int wc_AesGcmDecrypt(Aes* aes, byte* out, const byte* in, word32 sz,
                              const byte* iv, word32 ivSz,
                              const byte* authTag, word32 authTagSz,
                              const byte* authIn, word32 authInSz)
{
    return AesGcmDecrypt(aes, out, in, sz, iv, ivSz, authTag, authTagSz,
                              authIn, authInSz);
}


int wc_GmacSetKey(Gmac* gmac, const byte* key, word32 len)
{
    return GmacSetKey(gmac, key, len);
}


int wc_GmacUpdate(Gmac* gmac, const byte* iv, word32 ivSz,
                              const byte* authIn, word32 authInSz,
                              byte* authTag, word32 authTagSz)
{
    return GmacUpdate(gmac, iv, ivSz, authIn, authInSz,
                      authTag, authTagSz);
}

#endif /* HAVE_AESGCM */
#ifdef HAVE_AESCCM
void wc_AesCcmSetKey(Aes* aes, const byte* key, word32 keySz)
{
    AesCcmSetKey(aes, key, keySz);
}


void wc_AesCcmEncrypt(Aes* aes, byte* out, const byte* in, word32 inSz,
                              const byte* nonce, word32 nonceSz,
                              byte* authTag, word32 authTagSz,
                              const byte* authIn, word32 authInSz)
{
    AesCcmEncrypt(aes, out, in, inSz, nonce, nonceSz, authTag, authTagSz,
                  authIn, authInSz);
}


int  wc_AesCcmDecrypt(Aes* aes, byte* out, const byte* in, word32 inSz,
                              const byte* nonce, word32 nonceSz,
                              const byte* authTag, word32 authTagSz,
                              const byte* authIn, word32 authInSz)
{
    return AesCcmDecrypt(aes, out, in, inSz, nonce, nonceSz, authTag, authTagSz,
                         authIn, authInSz);
}
#endif /* HAVE_AESCCM */

#ifdef HAVE_CAVIUM
int  wc_AesInitCavium(Aes* aes, int i)
{
    return AesInitCavium(aes, i);
}


void wc_AesFreeCavium(Aes* aes)
{
    AesFreeCavium(aes);
}
#endif


#ifdef HAVE_FIPS
    /* fips wrapper calls, user can call direct */
    int  wc_AesSetKey_fips(Aes* aes, const byte* key, word32 len,
                                   const byte* iv, int dir)
    {
        return AesSetKey_fips(aes, key, len, iv, dir);
    }


    int wc_AesSetIV_fips(Aes* aes, const byte* iv)
    {
        return AesSetIV_fips(aes, iv);
    }    


    int wc_AesCbcEncrypt_fips(Aes* aes, byte* out, const byte* in,
                                       word32 sz)
    {
        return AesCbcEncrypt_fips(aes, out, in, sz);
    }

     
    int  wc_AesCbcDecrypt_fips(Aes* aes, byte* out, const byte* in,
                                       word32 sz)
    {    
        return AesCbcDecrypt_fips(aes, out, in, sz);
    }


    int wc_AesGcmSetKey_fips(Aes* aes, const byte* key, word32 len)
    {
        return AesGcmSetKey_fips(aes, key, len);
    }


    int wc_AesGcmEncrypt_fips(Aes* aes, byte* out, const byte* in,
                              word32 sz, const byte* iv, word32 ivSz,
                              byte* authTag, word32 authTagSz,
                              const byte* authIn, word32 authInSz)
    {
        return AesGcmEncrypt_fips(aes, out, in, sz, iv, ivSz,
                              authTag, authTagSz, authIn, authInSz);
    }     


    int wc_AesGcmDecrypt_fips(Aes* aes, byte* out, const byte* in,
                              word32 sz, const byte* iv, word32 ivSz,
                              const byte* authTag, word32 authTagSz,
                              const byte* authIn, word32 authInSz)
    {
        return AesGcmDecrypt_fips(aes, out, in, sz, iv, ivSz,
                              authTag, authTagSz, authIn, authInSz);
    }
    #ifndef FIPS_NO_WRAPPERS
        /* if not impl or fips.c impl wrapper force fips calls if fips build */
        #define AesSetKey     AesSetKey_fips
        #define AesSetIV      AesSetIV_fips
        #define AesCbcEncrypt AesCbcEncrypt_fips
        #define AesCbcDecrypt AesCbcDecrypt_fips
        #define AesGcmSetKey  AesGcmSetKey_fips
        #define AesGcmEncrypt AesGcmEncrypt_fips
        #define AesGcmDecrypt AesGcmDecrypt_fips
    #endif /* FIPS_NO_WRAPPERS */

#endif /* HAVE_FIPS */


#ifdef __cplusplus
    } /* extern "C" */
#endif


#endif /* NO_AES */

