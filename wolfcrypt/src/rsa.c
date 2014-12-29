/* rsa.c
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

#include <wolfssl/wolfcrypt/settings.h>

#ifndef NO_RSA

#include <wolfssl/wolfcrypt/rsa.h>


#ifdef __cplusplus
    extern "C" {
#endif

int  wc_InitRsaKey(RsaKey* key, void* ptr)
{
    return InitRsaKey(key, ptr);
}


int  wc_FreeRsaKey(RsaKey* key)
{
    return FreeRsaKey(key);
}


int  wc_RsaPublicEncrypt(const byte* in, word32 inLen, byte* out,
                                 word32 outLen, RsaKey* key, RNG* rng)
{
    return RsaPublicEncrypt(in, inLen, out, outLen, key, rng);
}


int  wc_RsaPrivateDecryptInline(byte* in, word32 inLen, byte** out,
                                        RsaKey* key)
{
    return RsaPrivateDecryptInline(in, inLen, out, key);
}


int  wc_RsaPrivateDecrypt(const byte* in, word32 inLen, byte* out,
                                  word32 outLen, RsaKey* key)
{
    return RsaPrivateDecrypt(in, inLen, out, outLen, key);
}


int  wc_RsaSSL_Sign(const byte* in, word32 inLen, byte* out,
                            word32 outLen, RsaKey* key, RNG* rng)
{
    return RsaSSL_Sign(in, inLen, out, outLen, key, rng);
}


int  wc_RsaSSL_VerifyInline(byte* in, word32 inLen, byte** out, RsaKey* key)
{
    return RsaSSL_VerifyInline(in, inLen, out, key);
}


int  wc_RsaSSL_Verify(const byte* in, word32 inLen, byte* out,
                              word32 outLen, RsaKey* key)
{
    return RsaSSL_Verify(in, inLen, out, outLen, key);
}


int  wc_RsaEncryptSize(RsaKey* key)
{
    return RsaEncryptSize(key);
}


int wc_RsaPrivateKeyDecode(const byte* input, word32* inOutIdx, RsaKey* key,
                                   word32 sz)
{
    return RsaPrivateKeyDecode(input, inOutIdx, key, sz);
}


int wc_RsaPublicKeyDecode(const byte* input, word32* inOutIdx, RsaKey* key,
                                  word32 sz)
{
    return RsaPublicKeyDecode(input, inOutIdx, key, sz);
}



int wc_RsaPublicKeyDecodeRaw(const byte* n, word32 nSz, const byte* e,
                                     word32 eSz, RsaKey* key)
{
    return RsaPublicKeyDecodeRaw(n, nSz, e, eSz, key);
}


int wc_RsaFlattenPublicKey(RsaKey* key, byte* a, word32* aSz, byte* b,
                           word32* bSz)
{
    return RsaFlattenPublicKey(key, a, aSz, b, bSz);
}
#ifdef CYASSL_KEY_GEN
    int wc_MakeRsaKey(RsaKey* key, int size, long e, RNG* rng)
    {
        return MakeRsaKey(key, size, e, rng);
    }


    int wc_RsaKeyToDer(RsaKey* key, byte* output, word32 inLen)
    {
        return RsaKeyToDer(key, output, inLen);
    }
#endif


#ifdef HAVE_CAVIUM
    int  wc_RsaInitCavium(RsaKey* key, int i)
    {
        return RsaInitCavium(key, i);
    }


    void wc_RsaFreeCavium(RsaKey* key)
    {
        RsaFreeCavium(key);
    }
#endif


#ifdef HAVE_FIPS
    /* fips wrapper calls, user can call direct */
    int  wc_InitRsaKey_fips(RsaKey* key, void* ptr)
    {
        return InitRsaKey_fips(key, ptr);
    }


    int  wc_FreeRsaKey_fips(RsaKey* key)
    {
        return FreeRsaKey_fips(key);
    }


    int  wc_RsaPublicEncrypt_fips(const byte* in,word32 inLen,byte* out,
                                 word32 outLen, RsaKey* key, RNG* rng)
    {
        return RsaPublicEncrypt_fips(in, inLen, out, outLen, key, rng);
    }


    int  wc_RsaPrivateDecryptInline_fips(byte* in, word32 inLen,
                                                 byte** out, RsaKey* key)
    {
        return RsaPrivateDecryptInline_fips(in, inLen, out, key);
    }


    int  wc_RsaPrivateDecrypt_fips(const byte* in, word32 inLen,
                                           byte* out,word32 outLen,RsaKey* key)
    {
        return RsaPrivateDecrypt_fips(in, inLen, out, outLen, key);
    }


    int wc_RsaSSL_Sign_fips(const byte* in, word32 inLen, byte* out,
                            word32 outLen, RsaKey* key, RNG* rng)
    {
        return RsaSSL_Sign_fips(in, inLen, out, outLen, key, rng);
    }


    int  wc_RsaSSL_VerifyInline_fips(byte* in, word32 inLen, byte** out,
                                    RsaKey* key)
    {
        return RsaSSL_VerifyInline_fips(in, inLen, out, key);
    }


    int  wc_RsaSSL_Verify_fips(const byte* in, word32 inLen, byte* out,
                              word32 outLen, RsaKey* key)
    {
        return RsaSSL_Verify_fips(in, inLen, out, outLen, key);
    }


    int  wc_RsaEncryptSize_fips(RsaKey* key)
    {
        return RsaEncryptSize_fips(key);
    }


    int wc_RsaPrivateKeyDecode_fips(const byte* input, word32* inOutIdx,
                                            RsaKey* key, word32 sz)
    {
        return RsaPrivateKeyDecode_fips(input, inOutIdx, key, sz);
    }


    int wc_RsaPublicKeyDecode_fips(const byte* input, word32* inOutIdx,
                                           RsaKey* key, word32 sz)
    {
        return RsaPublicKeyDecode_fips(input, inOutIdx, key, sz);
    }
    #ifndef FIPS_NO_WRAPPERS
        /* if not impl or fips.c impl wrapper force fips calls if fips build */
        #define InitRsaKey              InitRsaKey_fips 
        #define FreeRsaKey              FreeRsaKey_fips 
        #define RsaPublicEncrypt        RsaPublicEncrypt_fips 
        #define RsaPrivateDecryptInline RsaPrivateDecryptInline_fips 
        #define RsaPrivateDecrypt       RsaPrivateDecrypt_fips 
        #define RsaSSL_Sign             RsaSSL_Sign_fips
        #define RsaSSL_VerifyInline     RsaSSL_VerifyInline_fips
        #define RsaSSL_Verify           RsaSSL_Verify_fips
        #define RsaEncryptSize          RsaEncryptSize_fips
        /* no implicit KeyDecodes since in asn.c (not rsa.c) */
    #endif /* FIPS_NO_WRAPPERS */

#endif /* HAVE_FIPS */


#ifdef __cplusplus
    } /* extern "C" */
#endif


#endif /* NO_RSA */

