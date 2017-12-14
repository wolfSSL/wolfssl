/* caam_aes.c
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


#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_IMX6_CAAM) && !defined(NO_AES)

#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/aes.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/port/caam/wolfcaam.h>
#include <wolfssl/wolfcrypt/port/caam/caam_driver.h>

#if defined(WOLFSSL_CAAM_DEBUG) || defined(WOLFSSL_CAAM_PRINT)
#include <stdio.h>
#endif

int  wc_AesSetKey(Aes* aes, const byte* key, word32 len,
                              const byte* iv, int dir)
{
    int ret;
    
    if (aes == NULL || key == NULL) {
	return BAD_FUNC_ARG;
    }
    
    if (len > 32) {
	byte out[32]; /* max AES key size */
	word32 outSz;
        int ret;

	if (len != 64 && len != 72 && len != 80) {
	    return BAD_FUNC_ARG;
	}
	
	outSz = sizeof(out);
        /* if length greater then 32 then try to unencapsulate */
	if ((ret = wc_caamOpenBlob((byte*)key, len, out, &outSz, NULL, 0)) != 0) {
	    return ret;
	}

	XMEMCPY((byte*)aes->key, out, outSz);
        aes->keylen = outSz;
    }
    else {
        if (len != 16 && len != 24 && len != 32) {
	    return BAD_FUNC_ARG;
	}

        XMEMCPY((byte*)aes->key, key, len);
        aes->keylen = len;
    }


    switch (aes->keylen) {
	case 16: aes->rounds = 10; break;
	case 24: aes->rounds = 12; break;
	case 32: aes->rounds = 14; break;
	default:
	    return BAD_FUNC_ARG;
    }
    
    if ((ret = wc_AesSetIV(aes, iv)) != 0) {
        return ret;
    }
     
#ifdef WOLFSSL_AES_COUNTER
    aes->left = 0;
#endif

    return 0;
}


int  wc_AesSetIV(Aes* aes, const byte* iv)
{
     if (aes == NULL) {
	 return BAD_FUNC_ARG;
     }

     if (iv == NULL) {
         XMEMSET((byte*)aes->reg, 0, AES_BLOCK_SIZE);
     }
     else {
         XMEMCPY((byte*)aes->reg, iv, AES_BLOCK_SIZE);
     }
     
     return 0;
}


int  wc_AesCbcEncrypt(Aes* aes, byte* out,
                                  const byte* in, word32 sz)
{
    word32  blocks;
    
    WOLFSSL_ENTER("wc_AesCbcEncrypt");
    if (aes == NULL || out == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }

    blocks = sz / AES_BLOCK_SIZE;
    
    if (blocks > 0) {
        Buffer buf[4];
        word32 arg[4];
        word32 keySz;
        int ret;

        if (wc_AesGetKeySize(aes, &keySz) != 0) {
           return BAD_FUNC_ARG;
        }

        /* Set buffers for key, cipher text, and plain text */
        buf[0].BufferType = DataBuffer;
        buf[0].TheAddress = (Address)aes->key;
        buf[0].Length     = keySz;

        buf[1].BufferType = DataBuffer;
        buf[1].TheAddress = (Address)aes->reg;
        buf[1].Length     = AES_BLOCK_SIZE;
     
        buf[2].BufferType = DataBuffer;
        buf[2].TheAddress = (Address)in;
        buf[2].Length     = blocks * AES_BLOCK_SIZE;

        buf[3].BufferType = DataBuffer | LastBuffer;
        buf[3].TheAddress = (Address)out;
        buf[3].Length     = blocks * AES_BLOCK_SIZE;
	 
        arg[0] = CAAM_ENC;
        arg[1] = keySz;
        arg[2] = sz;
	
        if ((ret = wc_caamAddAndWait(buf, arg, CAAM_AESCBC)) != 0) {
           WOLFSSL_MSG("Error with CAAM AES CBC encrypt");
	   return ret;
        }
    }
    
    return 0;
}


int  wc_AesCbcDecrypt(Aes* aes, byte* out,
                                  const byte* in, word32 sz)
{
    word32  blocks;
    
    WOLFSSL_ENTER("wc_AesCbcDecrypt");
    if (aes == NULL || out == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }

    blocks = sz / AES_BLOCK_SIZE;
    
    if (blocks > 0) {
        Buffer buf[4];
        word32 arg[4];
        word32 keySz;
        int ret;

        if (wc_AesGetKeySize(aes, &keySz) != 0) {
           return BAD_FUNC_ARG;
        }

        /* Set buffers for key, cipher text, and plain text */
        buf[0].BufferType = DataBuffer;
        buf[0].TheAddress = (Address)aes->key;
        buf[0].Length     = keySz;

        buf[1].BufferType = DataBuffer;
        buf[1].TheAddress = (Address)aes->reg;
        buf[1].Length     = AES_BLOCK_SIZE;
     
        buf[2].BufferType = DataBuffer;
        buf[2].TheAddress = (Address)in;
        buf[2].Length     = blocks * AES_BLOCK_SIZE;

        buf[3].BufferType = DataBuffer | LastBuffer;
        buf[3].TheAddress = (Address)out;
        buf[3].Length     = blocks * AES_BLOCK_SIZE;
	 
        arg[0] = CAAM_DEC;
        arg[1] = keySz;
        arg[2] = sz;
     
        if ((ret = wc_caamAddAndWait(buf, arg, CAAM_AESCBC)) != 0) {
           WOLFSSL_MSG("Error with CAAM AES CBC decrypt");
	   return ret;
        }
    }
    
    return 0;
}

#ifdef HAVE_AES_ECB
/* is assumed that input size is a multiple of AES_BLOCK_SIZE */
int wc_AesEcbEncrypt(Aes* aes, byte* out,
                                  const byte* in, word32 sz)
{
    word32  blocks;
    
    if (aes == NULL || out == NULL || in == NULL) {
        BAD_FUNC_ARG;
    }

    blocks = sz / AES_BLOCK_SIZE;
    
    while (blocks > 0) {
        wc_AesEncryptDirect(aes, out, in);
	blocks--;
	out += AES_BLOCK_SIZE;
	in  += AES_BLOCK_SIZE;
    }
    
    return 0;
}


int wc_AesEcbDecrypt(Aes* aes, byte* out,
                                  const byte* in, word32 sz)
{
    word32  blocks;
    
    if (aes == NULL || out == NULL || in == NULL) {
        BAD_FUNC_ARG;
    }

    blocks = sz / AES_BLOCK_SIZE;

    /* @TODO search for more efficient solution */
    while (blocks > 0) {
        wc_AesDecryptDirect(aes, out, in);
	blocks--;
	out += AES_BLOCK_SIZE;
	in  += AES_BLOCK_SIZE;
    }
    
    return 0;
}
#endif

/* AES-CTR */
#ifdef WOLFSSL_AES_COUNTER
/* Increment AES counter (from wolfcrypt/src/aes.c) */
static INLINE void IncrementAesCounter(byte* inOutCtr)
{
    /* in network byte order so start at end and work back */
    int i;
    for (i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
        if (++inOutCtr[i])  /* we're done unless we overflow */
            return;
    }
}

	
int wc_AesCtrEncrypt(Aes* aes, byte* out,
                                   const byte* in, word32 sz)
{
     byte* tmp;
     Buffer buf[4];
     word32 arg[4];
     word32 keySz;
     int ret, blocks;

     if (aes == NULL || out == NULL || in == NULL) {
         return BAD_FUNC_ARG;
     }

     if (wc_AesGetKeySize(aes, &keySz) != 0) {
          return BAD_FUNC_ARG;
     }

     /* consume any unused bytes left in aes->tmp */
     tmp = (byte*)aes->tmp + AES_BLOCK_SIZE - aes->left;
     while (aes->left && sz) {
         *(out++) = *(in++) ^ *(tmp++);
         aes->left--;
         sz--;
     }

     /* do full blocks to then get potential left over amount */
     blocks = sz / AES_BLOCK_SIZE;
     if (blocks > 0) {
         /* Set buffers for key, cipher text, and plain text */
         buf[0].BufferType = DataBuffer;
         buf[0].TheAddress = (Address)aes->key;
         buf[0].Length     = keySz;

         buf[1].BufferType = DataBuffer;
         buf[1].TheAddress = (Address)aes->reg;
         buf[1].Length     = AES_BLOCK_SIZE;
     
         buf[2].BufferType = DataBuffer;
         buf[2].TheAddress = (Address)in;
         buf[2].Length     = blocks * AES_BLOCK_SIZE;

         buf[3].BufferType = DataBuffer | LastBuffer;
         buf[3].TheAddress = (Address)out;
         buf[3].Length     = blocks * AES_BLOCK_SIZE;
	 
         arg[0] = CAAM_ENC;
         arg[1] = keySz;
         arg[2] = sz;
     
         if ((ret = wc_caamAddAndWait(buf, arg, CAAM_AESCTR)) != 0) {
             WOLFSSL_MSG("Error with CAAM AES CTR encrypt");
	     return ret;
         }
	 out += blocks * AES_BLOCK_SIZE;
	 sz  -= blocks * AES_BLOCK_SIZE;
    }

    if (sz) {
        wc_AesEncryptDirect(aes, (byte*)aes->tmp, (byte*)aes->reg);
        IncrementAesCounter((byte*)aes->reg);

        aes->left = AES_BLOCK_SIZE;
        tmp = (byte*)aes->tmp;

        while (sz--) {
            *(out++) = *(in++) ^ *(tmp++);
            aes->left--;
        }
    }
    
    return 0;
}
#endif


/* AES-DIRECT */
#if defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER)
void wc_AesEncryptDirect(Aes* aes, byte* out, const byte* in)
{
     Buffer buf[3];
     word32 arg[4];
     word32 keySz;

     if (aes == NULL || out == NULL || in == NULL) {
         //return BAD_FUNC_ARG;
         return;
     }

     if (wc_AesGetKeySize(aes, &keySz) != 0) {
          //return BAD_FUNC_ARG;
          return;
     }

     /* Set buffers for key, cipher text, and plain text */
     buf[0].BufferType = DataBuffer;
     buf[0].TheAddress = (Address)aes->key;
     buf[0].Length     = keySz;

     buf[1].BufferType = DataBuffer;
     buf[1].TheAddress = (Address)in;
     buf[1].Length     = AES_BLOCK_SIZE;

     buf[2].BufferType = DataBuffer | LastBuffer;
     buf[2].TheAddress = (Address)out;
     buf[2].Length     = AES_BLOCK_SIZE;
	 
     arg[0] = CAAM_ENC;
     arg[1] = keySz;
     arg[2] = AES_BLOCK_SIZE;
     
     if (wc_caamAddAndWait(buf, arg, CAAM_AESECB) != 0) {
         WOLFSSL_MSG("Error with CAAM AES direct encrypt");
     }
}


void wc_AesDecryptDirect(Aes* aes, byte* out, const byte* in)
{
     Buffer buf[3];
     word32 arg[4];
     word32 keySz;

     if (aes == NULL || out == NULL || in == NULL) {
         //return BAD_FUNC_ARG;
         return;
     }

     if (wc_AesGetKeySize(aes, &keySz) != 0) {
          //return BAD_FUNC_ARG;
          return;
     }

     /* Set buffers for key, cipher text, and plain text */
     buf[0].BufferType = DataBuffer;
     buf[0].TheAddress = (Address)aes->key;
     buf[0].Length     = keySz;

     buf[1].BufferType = DataBuffer;
     buf[1].TheAddress = (Address)in;
     buf[1].Length     = AES_BLOCK_SIZE;

     buf[2].BufferType = DataBuffer | LastBuffer;
     buf[2].TheAddress = (Address)out;
     buf[2].Length     = AES_BLOCK_SIZE;
	 
     arg[0] = CAAM_DEC;
     arg[1] = keySz;
     arg[2] = AES_BLOCK_SIZE;
     
     if (wc_caamAddAndWait(buf, arg, CAAM_AESECB) != 0) {
         WOLFSSL_MSG("Error with CAAM AES direct decrypt");
     }
}


int  wc_AesSetKeyDirect(Aes* aes, const byte* key, word32 len,
                                const byte* iv, int dir)
{
     return wc_AesSetKey(aes, key, len, iv, dir);
}
#endif

#ifdef HAVE_AESCCM

#warning AES-CCM mode not complete

/* from wolfcrypt/src/aes.c */
static void roll_auth(const byte* in, word32 inSz, byte* out)
{
    word32 authLenSz;
    word32 remainder;

    /* encode the length in */
    if (inSz <= 0xFEFF) {
        authLenSz = 2;
        out[0] ^= ((inSz & 0xFF00) >> 8);
        out[1] ^=  (inSz & 0x00FF);
    }
    else if (inSz <= 0xFFFFFFFF) {
        authLenSz = 6;
        out[0] ^= 0xFF; out[1] ^= 0xFE;
        out[2] ^= ((inSz & 0xFF000000) >> 24);
        out[3] ^= ((inSz & 0x00FF0000) >> 16);
        out[4] ^= ((inSz & 0x0000FF00) >>  8);
        out[5] ^=  (inSz & 0x000000FF);
    }
    /* Note, the protocol handles auth data up to 2^64, but we are
     * using 32-bit sizes right now, so the bigger data isn't handled
     * else if (inSz <= 0xFFFFFFFFFFFFFFFF) {} */
    else
        return;

    /* start fill out the rest of the first block */
    remainder = AES_BLOCK_SIZE - authLenSz;
    if (inSz >= remainder) {
        /* plenty of bulk data to fill the remainder of this block */
        xorbuf(out + authLenSz, in, remainder);
        inSz -= remainder;
        in += remainder;
    }
    else {
        /* not enough bulk data, copy what is available, and pad zero */
        xorbuf(out + authLenSz, in, inSz);
        inSz = 0;
    }
}


int  wc_AesCcmSetKey(Aes* aes, const byte* key, word32 keySz)
{
    return wc_AesSetKey(aes, key, keySz, NULL, AES_ENCRYPTION);
}


int  wc_AesCcmEncrypt(Aes* aes, byte* out,
                                   const byte* in, word32 inSz,
                                   const byte* nonce, word32 nonceSz,
                                   byte* authTag, word32 authTagSz,
                                   const byte* authIn, word32 authInSz)
{
    Buffer buf[4];
    word32 arg[4];
    word32 keySz;
    word32 i;
    byte B0Ctr0[AES_BLOCK_SIZE + AES_BLOCK_SIZE];
    byte A[AES_BLOCK_SIZE];
    byte ASz = 0;
    int lenSz;
    byte mask = 0xFF;
    const word32 wordSz = (word32)sizeof(word32);
    int ret;
     
    /* sanity check on arguments */
    if (aes == NULL || out == NULL || in == NULL || nonce == NULL
            || authTag == NULL || nonceSz < 7 || nonceSz > 13)
        return BAD_FUNC_ARG;

    if (wc_AesGetKeySize(aes, &keySz) != 0) {
         return BAD_FUNC_ARG;
    }

    /* set up B0 and CTR0 similar to how wolfcrypt/src/aes.c does */
    XMEMCPY(B0Ctr0+1, nonce, nonceSz);
    lenSz = AES_BLOCK_SIZE - 1 - (byte)nonceSz;
    B0Ctr0[0] = (authInSz > 0 ? 64 : 0)
         + (8 * (((byte)authTagSz - 2) / 2))
         + (lenSz - 1);
    for (i = 0; i < lenSz; i++) {
        if (mask && i >= wordSz)
            mask = 0x00;
        B0Ctr0[AES_BLOCK_SIZE - 1 - i] = (inSz >> ((8 * i) & mask)) & mask;
    }

    if (authInSz > 0) {
        ASz = AES_BLOCK_SIZE;
	roll_auth(authIn, authInSz, A);
    }
    
    B0Ctr0[AES_BLOCK_SIZE] = lenSz - 1;
    for (i = 0; i < lenSz; i++)
        B0Ctr0[(AES_BLOCK_SIZE + AES_BLOCK_SIZE) - 1 - i] = 0;
    B0Ctr0[(AES_BLOCK_SIZE + AES_BLOCK_SIZE) - 1] = 1;
    
    /* Set buffers for key, cipher text, and plain text */
    buf[0].BufferType = DataBuffer;
    buf[0].TheAddress = (Address)aes->key;
    buf[0].Length     = keySz;

    buf[1].BufferType = DataBuffer;
    buf[1].TheAddress = (Address)B0Ctr0;
    buf[1].Length     = AES_BLOCK_SIZE + AES_BLOCK_SIZE;
	 
    buf[2].BufferType = DataBuffer;
    buf[2].TheAddress = (Address)in;
    buf[2].Length     = inSz;

    buf[3].BufferType = DataBuffer;
    buf[3].TheAddress = (Address)out;
    buf[3].Length     = inSz;

    buf[3].BufferType = DataBuffer | LastBuffer;
    buf[3].TheAddress = (Address)A;
    buf[3].Length     = ASz;
	 
    arg[0] = CAAM_ENC;
    arg[1] = keySz;
    arg[2] = inSz;
    arg[3] = ASz;
     
    if ((ret = wc_caamAddAndWait(buf, arg, CAAM_AESCCM)) != 0) {
        WOLFSSL_MSG("Error with CAAM AES-CCM encrypt");
	return ret;
    }

    return 0;
}
 

#ifdef HAVE_AES_DECRYPT
int  wc_AesCcmDecrypt(Aes* aes, byte* out,
                                   const byte* in, word32 inSz,
                                   const byte* nonce, word32 nonceSz,
                                   const byte* authTag, word32 authTagSz,
                                   const byte* authIn, word32 authInSz)
{
    Buffer buf[4];
    word32 arg[4];
    word32 keySz;
    word32 i;
    byte B0Ctr0[AES_BLOCK_SIZE + AES_BLOCK_SIZE];
    byte A[AES_BLOCK_SIZE];
    byte ASz = 0;
    int lenSz;
    byte mask = 0xFF;
    const word32 wordSz = (word32)sizeof(word32);
    int ret;
     
    /* sanity check on arguments */
    if (aes == NULL || out == NULL || in == NULL || nonce == NULL
            || authTag == NULL || nonceSz < 7 || nonceSz > 13)
        return BAD_FUNC_ARG;

    if (wc_AesGetKeySize(aes, &keySz) != 0) {
         return BAD_FUNC_ARG;
    }

    /* set up B0 and CTR0 similar to how wolfcrypt/src/aes.c does */
    XMEMCPY(B0Ctr0+1, nonce, nonceSz);
    lenSz = AES_BLOCK_SIZE - 1 - (byte)nonceSz;
    B0Ctr0[0] = (authInSz > 0 ? 64 : 0)
         + (8 * (((byte)authTagSz - 2) / 2))
         + (lenSz - 1);
    for (i = 0; i < lenSz; i++) {
        if (mask && i >= wordSz)
            mask = 0x00;
        B0Ctr0[AES_BLOCK_SIZE - 1 - i] = (inSz >> ((8 * i) & mask)) & mask;
    }

    if (authInSz > 0) {
	ASz = AES_BLOCK_SIZE;
        roll_auth(authIn, authInSz, A);
    }
	
    B0Ctr0[AES_BLOCK_SIZE] = lenSz - 1;
    for (i = 0; i < lenSz; i++)
        B0Ctr0[(AES_BLOCK_SIZE + AES_BLOCK_SIZE) - 1 - i] = 0;
    B0Ctr0[(AES_BLOCK_SIZE + AES_BLOCK_SIZE) - 1] = 1;
    
    /* Set buffers for key, cipher text, and plain text */
    buf[0].BufferType = DataBuffer;
    buf[0].TheAddress = (Address)aes->key;
    buf[0].Length     = keySz;

    buf[1].BufferType = DataBuffer;
    buf[1].TheAddress = (Address)B0Ctr0;
    buf[1].Length     = AES_BLOCK_SIZE + AES_BLOCK_SIZE;
	 
    buf[2].BufferType = DataBuffer;
    buf[2].TheAddress = (Address)in;
    buf[2].Length     = inSz;

    buf[3].BufferType = DataBuffer;
    buf[3].TheAddress = (Address)out;
    buf[3].Length     = inSz;

    buf[3].BufferType = DataBuffer | LastBuffer;
    buf[3].TheAddress = (Address)A;
    buf[3].Length     = ASz;
	 
    arg[0] = CAAM_DEC;
    arg[1] = keySz;
    arg[2] = inSz;
    arg[3] = ASz;
     
    if ((ret = wc_caamAddAndWait(buf, arg, CAAM_AESCCM)) != 0) {
        WOLFSSL_MSG("Error with CAAM AES-CCM derypt");
	return ret;
    }

    return 0;
}
#endif /* HAVE_AES_DECRYPT */
#endif /* HAVE_AESCCM */


int wc_AesGetKeySize(Aes* aes, word32* keySize)
{
    if (aes != NULL && keySize != NULL) {
        *keySize = aes->keylen;

	/* preform sanity check on rounds to conform with test case */
	if (aes->rounds != 10 && aes->rounds != 12 && aes->rounds != 14) {
	    return BAD_FUNC_ARG;
	}
	
        return 0;
    }

    return BAD_FUNC_ARG;
}


int  wc_AesInit(Aes* aes, void* heap, int devId)
{
    if (aes == NULL) {
	return BAD_FUNC_ARG;
    }

    aes->heap = heap;
    (void)devId;
    
    return 0;
}


void wc_AesFree(Aes* aes)
{
    if (aes != NULL) {
        ForceZero((byte*)aes->key, 32);
    }
}


#endif /* WOLFSSL_IMX6_CAAM && !NO_AES */

