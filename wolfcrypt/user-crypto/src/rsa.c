/* rsa.c
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

/*
 Created to use intel's IPP see their license for linking to intel's IPP library
 */

#ifdef HAVE_CONFIG_H /* configure options when using autoconf */
    #include <config.h>
#endif

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#ifndef NO_RSA

#define USER_CRYPTO_ERROR -101

#ifdef OPENSSL_EXTRA
    #include <wolfssl/openssl/rsa.h> /* include for openssl compatibility */
    #include <wolfssl/openssl/bn.h>
#endif
#include "user_rsa.h"

#ifdef DEBUG_WOLFSSL /* debug done without variadric to allow older compilers */
    #include <stdio.h>
    #define USER_DEBUG(x) printf x
#else
    #define USER_DEBUG(x)
#endif

#define ASN_INTEGER    0x02
#define ASN_BIT_STRING 0x03
#define ASN_TAG_NULL   0x05
#define ASN_OBJECT_ID  0x06


/* Make sure compiler doesn't skip -- used from wolfSSL */
static inline void ForceZero(const void* mem, word32 len)
{
    volatile byte* z = (volatile byte*)mem;

    while (len--) *z++ = 0;
}

enum {
    RSA_PUBLIC_ENCRYPT  = 0,
    RSA_PUBLIC_DECRYPT  = 1,
    RSA_PRIVATE_ENCRYPT = 2,
    RSA_PRIVATE_DECRYPT = 3,

    RSA_BLOCK_TYPE_1 = 1,
    RSA_BLOCK_TYPE_2 = 2,

    RSA_MIN_SIZE = 512,
    RSA_MAX_SIZE = 4096, /* max allowed in IPP library */

    RSA_MIN_PAD_SZ   = 11      /* seperator + 0 + pad value + 8 pads */
};


int wc_InitRsaKey(RsaKey* key, void* heap)
{

    USER_DEBUG(("Entering wc_InitRsaKey\n"));

    if (key == NULL)
        return USER_CRYPTO_ERROR;

    /* set full struct as 0 */
    ForceZero(key, sizeof(RsaKey));

    USER_DEBUG(("\tExit wc_InitRsaKey\n"));

    (void)heap;
    return 0;
}


#ifdef WOLFSSL_CERT_GEN /* three functions needed for cert gen */
/* return 1 if there is a leading bit*/
int wc_Rsa_leading_bit(void* bn)
{
    int ret = 0;
    if (ippsExtGet_BN(NULL, &ret, NULL, bn) != ippStsNoErr) {
        USER_DEBUG(("Rsa leading bit error\n"));
        return USER_CRYPTO_ERROR;
    }
    return (ret % 8)? 1 : 0; /* if mod 8 bit then an extra byte is needed */
}


/* get the size in bytes of BN
   cuts off if extra byte is needed so recommended to check wc_Rsa_leading_bit
   and adding it to this return value before mallocing memory needed */
int wc_Rsa_unsigned_bin_size(void* bn)
{
    int ret = 0;
    if (ippsExtGet_BN(NULL, &ret, NULL, bn) != ippStsNoErr) {
        USER_DEBUG(("Rsa unsigned bin size error\n"));
        return USER_CRYPTO_ERROR;
    }
    return ret / 8; /* size in bytes */
}

#ifndef MP_OKAY
#define MP_OKAY 0
#endif

/* extract the bn value to a unsigned byte array and return MP_OKAY on succes */
int wc_Rsa_to_unsigned_bin(void* bn, byte* in, int inLen)
{
    if (ippsGetOctString_BN((Ipp8u*)in, inLen, bn) != ippStsNoErr) {
        USER_DEBUG(("Rsa unsigned bin error\n"));
        return USER_CRYPTO_ERROR;
    }
    return MP_OKAY;
}
#endif /* WOLFSSL_CERT_GEN */


#ifdef OPENSSL_EXTRA /* functions needed for openssl compatibility layer */
static int SetIndividualExternal(WOLFSSL_BIGNUM** bn, IppsBigNumState* in)
{
    IppStatus ret;
    byte* data;
    int sz;

    USER_DEBUG(("Entering SetIndividualExternal\n"));

    if (bn == NULL || in == NULL) {
        USER_DEBUG(("inputs NULL error\n"));
        return USER_CRYPTO_ERROR;
    }

    if (*bn == NULL) {
        *bn = wolfSSL_BN_new();
        if (*bn == NULL) {
            USER_DEBUG(("SetIndividualExternal alloc failed\n"));
            return USER_CRYPTO_ERROR;
        }
    }

    /* get size of array needed and extract oct array of data */
    ret = ippsGetSize_BN(in, &sz);
    if (ret != ippStsNoErr)
        return USER_CRYPTO_ERROR;

    data = XMALLOC(sz, NULL, DYNAMIC_TYPE_USER_CRYPTO);
    if (data == NULL)
        return USER_CRYPTO_ERROR;

    ret = ippsGetOctString_BN(data, sz, in);
    if (ret != ippStsNoErr) {
        XFREE(data, NULL, DYNAMIC_TYPE_USER_CRYPTO);
        return USER_CRYPTO_ERROR;
    }

    /* store the data into a wolfSSL Big Number */
    *bn = wolfSSL_BN_bin2bn(data, sz, *bn);

    XFREE(data, NULL, DYNAMIC_TYPE_USER_CRYPTO);

    return 0;
}


static int SetIndividualInternal(WOLFSSL_BIGNUM* bn, IppsBigNumState** mpi)
{
    int length, ctxSz, sz;
    IppStatus ret;
    Ipp8u* data;

    USER_DEBUG(("Entering SetIndividualInternal\n"));

    if (bn == NULL || bn->internal == NULL) {
        USER_DEBUG(("bn NULL error\n"));
        return USER_CRYPTO_ERROR;
    }

    length = wolfSSL_BN_num_bytes(bn);

    /* if not IPP BN then create one */
    if (*mpi == NULL) {
        ret = ippsBigNumGetSize(length, &ctxSz);
        if (ret != ippStsNoErr)
            return USER_CRYPTO_ERROR;

        *mpi = XMALLOC(ctxSz, 0, DYNAMIC_TYPE_USER_CRYPTO);
        if (*mpi == NULL)
            return USER_CRYPTO_ERROR;

        ret = ippsBigNumInit(length, *mpi);
        if (ret != ippStsNoErr)
            return USER_CRYPTO_ERROR;

    }

    /* get the size of array needed and check IPP BigNum */
    if (ippsGetSize_BN(*mpi, &sz) != ippStsNoErr)
        return USER_CRYPTO_ERROR;

    if (sz < length) {
        USER_DEBUG(("big num size is too small\n"));
        return USER_CRYPTO_ERROR;
    }

    data = XMALLOC(length, NULL, DYNAMIC_TYPE_USER_CRYPTO);
    if (data == NULL)
        return USER_CRYPTO_ERROR;

    /* extract the wolfSSL BigNum and store it into IPP BigNum */
    if (wolfSSL_BN_bn2bin(bn, data) < 0) {
        XFREE(data, NULL, DYNAMIC_TYPE_USER_CRYPTO);
        USER_DEBUG(("error in getting bin from wolfssl bn\n"));
        return USER_CRYPTO_ERROR;
    }

    ret = ippsSetOctString_BN(data, length, *mpi);
    if (ret != ippStsNoErr) {
        XFREE(data, NULL, DYNAMIC_TYPE_USER_CRYPTO);
        return USER_CRYPTO_ERROR;
    }

    XFREE(data, NULL, DYNAMIC_TYPE_USER_CRYPTO);

    return 0;
}


/* WolfSSL -> OpenSSL */
int SetRsaExternal(WOLFSSL_RSA* rsa)
{
    RsaKey* key;
    USER_DEBUG(("Entering SetRsaExternal\n"));

    if (rsa == NULL || rsa->internal == NULL) {
        USER_DEBUG(("rsa key NULL error\n"));
        return USER_CRYPTO_ERROR;
    }

    key = (RsaKey*)rsa->internal;

    if (SetIndividualExternal(&rsa->n, key->n) != 0) {
        USER_DEBUG(("rsa n key error\n"));
        return USER_CRYPTO_ERROR;
    }

    if (SetIndividualExternal(&rsa->e, key->e) != 0) {
        USER_DEBUG(("rsa e key error\n"));
        return USER_CRYPTO_ERROR;
    }

    if (SetIndividualExternal(&rsa->d, key->dipp) != 0) {
        USER_DEBUG(("rsa d key error\n"));
        return USER_CRYPTO_ERROR;
    }

    if (SetIndividualExternal(&rsa->p, key->pipp) != 0) {
        USER_DEBUG(("rsa p key error\n"));
        return USER_CRYPTO_ERROR;
    }

    if (SetIndividualExternal(&rsa->q, key->qipp) != 0) {
        USER_DEBUG(("rsa q key error\n"));
        return USER_CRYPTO_ERROR;
    }

    if (SetIndividualExternal(&rsa->dmp1, key->dPipp) != 0) {
        USER_DEBUG(("rsa dP key error\n"));
        return USER_CRYPTO_ERROR;
    }

    if (SetIndividualExternal(&rsa->dmq1, key->dQipp) != 0) {
        USER_DEBUG(("rsa dQ key error\n"));
        return USER_CRYPTO_ERROR;
    }

    if (SetIndividualExternal(&rsa->iqmp, key->uipp) != 0) {
        USER_DEBUG(("rsa u key error\n"));
        return USER_CRYPTO_ERROR;
    }

    rsa->exSet = 1;

    /* SSL_SUCCESS */
    return 1;
}


/* Openssl -> WolfSSL */
int SetRsaInternal(WOLFSSL_RSA* rsa)
{
    int ctxSz, pSz, qSz;
    IppStatus ret;
    RsaKey* key;
    USER_DEBUG(("Entering SetRsaInternal\n"));

    if (rsa == NULL || rsa->internal == NULL) {
        USER_DEBUG(("rsa key NULL error\n"));
        return USER_CRYPTO_ERROR;
    }

    key = (RsaKey*)rsa->internal;

    if (SetIndividualInternal(rsa->n, &key->n) != 0) {
        USER_DEBUG(("rsa n key error\n"));
        return USER_CRYPTO_ERROR;
    }

    if (SetIndividualInternal(rsa->e, &key->e) != 0) {
        USER_DEBUG(("rsa e key error\n"));
        return USER_CRYPTO_ERROR;
    }

    /* public key */
    key->type = RSA_PUBLIC;

    if (rsa->d != NULL) {
        if (SetIndividualInternal(rsa->d, &key->dipp) != 0) {
            USER_DEBUG(("rsa d key error\n"));
            return USER_CRYPTO_ERROR;
        }

        /* private key */
        key->type = RSA_PRIVATE;
    }

    if (rsa->p != NULL &&
        SetIndividualInternal(rsa->p, &key->pipp) != 0) {
        USER_DEBUG(("rsa p key error\n"));
        return USER_CRYPTO_ERROR;
    }

    if (rsa->q != NULL &&
        SetIndividualInternal(rsa->q, &key->qipp) != 0) {
        USER_DEBUG(("rsa q key error\n"));
        return USER_CRYPTO_ERROR;
    }

    if (rsa->dmp1 != NULL &&
        SetIndividualInternal(rsa->dmp1, &key->dPipp) != 0) {
        USER_DEBUG(("rsa dP key error\n"));
        return USER_CRYPTO_ERROR;
    }

    if (rsa->dmq1 != NULL &&
        SetIndividualInternal(rsa->dmq1, &key->dQipp) != 0) {
        USER_DEBUG(("rsa dQ key error\n"));
        return USER_CRYPTO_ERROR;
    }

    if (rsa->iqmp != NULL &&
        SetIndividualInternal(rsa->iqmp, &key->uipp) != 0) {
        USER_DEBUG(("rsa u key error\n"));
        return USER_CRYPTO_ERROR;
    }

    rsa->inSet = 1;

    /* get sizes of IPP BN key states created from input */
    ret = ippsGetSize_BN(key->n, &key->nSz);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsGetSize_BN error %s\n", ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    ret = ippsGetSize_BN(key->e, &key->eSz);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsGetSize_BN error %s\n", ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    key->sz = key->nSz; /* set modulus size */

    /* convert to size in bits */
    key->nSz = key->nSz * 8;
    key->eSz = key->eSz * 8;

    /* set up public key state */
    ret = ippsRSA_GetSizePublicKey(key->nSz, key->eSz, &ctxSz);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsRSA_GetSizePublicKey error %s\n",
                ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    key->pPub = XMALLOC(ctxSz, NULL, DYNAMIC_TYPE_USER_CRYPTO);
    if (key->pPub == NULL)
        return USER_CRYPTO_ERROR;

    ret = ippsRSA_InitPublicKey(key->nSz, key->eSz, key->pPub, ctxSz);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsRSA_InitPublicKey error %s\n",
                    ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    ret = ippsRSA_SetPublicKey(key->n, key->e, key->pPub);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsRSA_SetPublicKey error %s\n", ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    if (key->pipp != NULL && key->qipp != NULL && key->dipp != NULL &&
            key->dPipp != NULL && key->dQipp != NULL && key->uipp != NULL) {
        /* get bn sizes needed for private key set up */
        ret = ippsGetSize_BN(key->pipp, &pSz);
        if (ret != ippStsNoErr) {
            USER_DEBUG(("ippsGetSize_BN error %s\n", ippGetStatusString(ret)));
            return USER_CRYPTO_ERROR;
        }

        ret = ippsGetSize_BN(key->qipp, &qSz);
        if (ret != ippStsNoErr) {
            USER_DEBUG(("ippsGetSize_BN error %s\n", ippGetStatusString(ret)));
            return USER_CRYPTO_ERROR;
        }

        /* store sizes needed for creating tmp private keys */
        ret = ippsGetSize_BN(key->dipp, &key->dSz);
        if (ret != ippStsNoErr) {
            USER_DEBUG(("ippsGetSize_BN error %s\n", ippGetStatusString(ret)));
            return USER_CRYPTO_ERROR;
        }

        /* convert to size in bits */
        key->dSz = key->dSz * 8;
        pSz = pSz * 8;
        qSz = qSz * 8;

        /* set up private key state */
        ret = ippsRSA_GetSizePrivateKeyType2(pSz, qSz, &ctxSz);
        if (ret != ippStsNoErr) {
            USER_DEBUG(("ippsRSA_GetSizePrivateKey error %s\n",
                    ippGetStatusString(ret)));
            return USER_CRYPTO_ERROR;
        }

        key->prvSz = ctxSz;
        key->pPrv = XMALLOC(ctxSz, 0, DYNAMIC_TYPE_USER_CRYPTO);
        if (key->pPrv == NULL)
            return USER_CRYPTO_ERROR;

        ret = ippsRSA_InitPrivateKeyType2(pSz, qSz, key->pPrv, ctxSz);
        if (ret != ippStsNoErr) {
            USER_DEBUG(("ippsRSA_InitPrivateKey error %s\n",
                        ippGetStatusString(ret)));
            return USER_CRYPTO_ERROR;
        }

        ret = ippsRSA_SetPrivateKeyType2(key->pipp, key->qipp, key->dPipp,
                key->dQipp, key->uipp, key->pPrv);
        if (ret != ippStsNoErr) {
            USER_DEBUG(("ippsRSA_SetPrivateKey error %s\n", ippGetStatusString(ret)));
            return USER_CRYPTO_ERROR;
        }
    }

    /* SSL_SUCCESS */
    return 1;
}
#endif /* OPENSSLEXTRA */


/* Padding scheme function used in wolfSSL for signing needed for matching
   existing API signing scheme
    input : the msg to be signed
    inputLen : length of input msg
    pkcsBlock : the outputed padded msg
    pkcsBlockLen : length of outptued padded msg buffer
    padValue : the padded value after first 00 , is either 01 or 02
    rng : random number generator structure
 */
static int wc_RsaPad(const byte* input, word32 inputLen, byte* pkcsBlock,
                   word32 pkcsBlockLen, byte padValue, WC_RNG* rng)
{
    if (inputLen == 0)
        return 0;

    pkcsBlock[0] = 0x0;       /* set first byte to zero and advance */
    pkcsBlock++; pkcsBlockLen--;
    pkcsBlock[0] = padValue;  /* insert padValue */

    if (padValue == RSA_BLOCK_TYPE_1)
        /* pad with 0xff bytes */
        XMEMSET(&pkcsBlock[1], 0xFF, pkcsBlockLen - inputLen - 2);
    else {
        /* pad with non-zero random bytes */
        word32 padLen = pkcsBlockLen - inputLen - 1, i;
        int    ret    = wc_RNG_GenerateBlock(rng, &pkcsBlock[1], padLen);

        if (ret != 0)
            return ret;

        /* remove zeros */
        for (i = 1; i < padLen; i++)
            if (pkcsBlock[i] == 0) pkcsBlock[i] = 0x01;
    }

    pkcsBlock[pkcsBlockLen-inputLen-1] = 0;     /* separator */
    XMEMCPY(pkcsBlock+pkcsBlockLen-inputLen, input, inputLen);

    return 0;
}


/* UnPad plaintext, set start to *output, return length of plaintext,
 * < 0 on error */
static int RsaUnPad(const byte *pkcsBlock, unsigned int pkcsBlockLen,
                       byte **output, byte padValue)
{
    word32 maxOutputLen = (pkcsBlockLen > 10) ? (pkcsBlockLen - 10) : 0,
           invalid = 0,
           i = 1,
           outputLen;

    if (pkcsBlock[0] != 0x0) /* skip past zero */
        invalid = 1;
    pkcsBlock++; pkcsBlockLen--;

    /* Require block type padValue */
    invalid = (pkcsBlock[0] != padValue) || invalid;

    /* verify the padding until we find the separator */
    if (padValue == RSA_BLOCK_TYPE_1) {
        while (i<pkcsBlockLen && pkcsBlock[i++] == 0xFF) {/* Null body */}
    }
    else {
        while (i<pkcsBlockLen && pkcsBlock[i++]) {/* Null body */}
    }

    if(!(i==pkcsBlockLen || pkcsBlock[i-1]==0)) {
        USER_DEBUG(("RsaUnPad error, bad formatting\n"));
        return USER_CRYPTO_ERROR;
    }

    outputLen = pkcsBlockLen - i;
    invalid = (outputLen > maxOutputLen) || invalid;

    if (invalid) {
        USER_DEBUG(("RsaUnPad error, bad formatting\n"));
        return USER_CRYPTO_ERROR;
    }

    *output = (byte *)(pkcsBlock + i);
    return outputLen;
}


int wc_FreeRsaKey(RsaKey* key)
{
    if (key == NULL)
        return 0;

    USER_DEBUG(("Entering wc_FreeRsaKey\n"));

    if (key->pPub != NULL) {
        XFREE(key->pPub, NULL, DYNAMIC_TYPE_USER_CRYPTO);
        key->pPub = NULL;
    }

    if (key->pPrv != NULL) {
        /* write over senstive information */
        ForceZero(key->pPrv, key->prvSz);
        XFREE(key->pPrv, NULL, DYNAMIC_TYPE_USER_CRYPTO);
        key->pPrv = NULL;
    }

    if (key->n != NULL) {
        XFREE(key->n, NULL, DYNAMIC_TYPE_USER_CRYPTO);
        key->n = NULL;
    }

    if (key->e != NULL) {
        XFREE(key->e, NULL, DYNAMIC_TYPE_USER_CRYPTO);
        key->e = NULL;
    }

    if (key->dipp != NULL) {
        XFREE(key->dipp, NULL, DYNAMIC_TYPE_USER_CRYPTO);
        key->dipp = NULL;
    }

    if (key->pipp != NULL) {
        XFREE(key->pipp, NULL, DYNAMIC_TYPE_USER_CRYPTO);
        key->pipp = NULL;
    }

    if (key->qipp != NULL) {
        XFREE(key->qipp, NULL, DYNAMIC_TYPE_USER_CRYPTO);
        key->qipp = NULL;
    }

    if (key->dPipp != NULL) {
        XFREE(key->dPipp, NULL, DYNAMIC_TYPE_USER_CRYPTO);
        key->dPipp = NULL;
    }

    if (key->dQipp != NULL) {
        XFREE(key->dQipp, NULL, DYNAMIC_TYPE_USER_CRYPTO);
        key->dQipp = NULL;
    }

    if (key->uipp != NULL) {
        XFREE(key->uipp, NULL, DYNAMIC_TYPE_USER_CRYPTO);
        key->uipp = NULL;
    }

    USER_DEBUG(("\tExit wc_FreeRsaKey\n"));
    (void)key;

    return 0;
}


/* Some parsing functions from wolfSSL code needed to match wolfSSL API used */
static int GetLength(const byte* input, word32* inOutIdx, int* len,
                           word32 maxIdx)
{
    int     length = 0;
    word32  i = *inOutIdx;
    byte    b;

    *len = 0;    /* default length */

    if ( (i+1) > maxIdx) {   /* for first read */
        USER_DEBUG(("GetLength bad index on input\n"));
        return USER_CRYPTO_ERROR;
    }

    b = input[i++];
    if (b >= 0x80) {
        word32 bytes = b & 0x7F;

        if ( (i+bytes) > maxIdx) {   /* for reading bytes */
            USER_DEBUG(("GetLength bad long length\n"));
            return USER_CRYPTO_ERROR;
        }

        while (bytes--) {
            b = input[i++];
            length = (length << 8) | b;
        }
    }
    else
        length = b;

    if ( (i+length) > maxIdx) {   /* for user of length */
        USER_DEBUG(("GetLength value exceeds buffer length\n"));
        return USER_CRYPTO_ERROR;
    }

    *inOutIdx = i;
    if (length > 0)
        *len = length;

    return length;
}


static int GetInt(IppsBigNumState** mpi, const byte* input, word32* inOutIdx,
                  word32 maxIdx)
{
    IppStatus ret;
    word32 i = *inOutIdx;
    byte   b = input[i++];
    int    length;
    int    ctxSz;

    if (b != 0x02)
        return USER_CRYPTO_ERROR;

    if (GetLength(input, &i, &length, maxIdx) < 0)
        return USER_CRYPTO_ERROR;

    if ( (b = input[i++]) == 0x00)
        length--;
    else
        i--;

    ret = ippsBigNumGetSize(length, &ctxSz);
    if (ret != ippStsNoErr)
        return USER_CRYPTO_ERROR;

    *mpi = XMALLOC(ctxSz, 0, DYNAMIC_TYPE_USER_CRYPTO);
    if (*mpi == NULL)
        return USER_CRYPTO_ERROR;

    ret = ippsBigNumInit(length, *mpi);
    if (ret != ippStsNoErr)
        return USER_CRYPTO_ERROR;

    ret = ippsSetOctString_BN((Ipp8u*)input + i, length, *mpi);
    if (ret != ippStsNoErr)
        return USER_CRYPTO_ERROR;

    *inOutIdx = i + length;
    return 0;
}


static int GetSequence(const byte* input, word32* inOutIdx, int* len,
                           word32 maxIdx)
{
    int    length = -1;
    word32 idx    = *inOutIdx;

    if (input[idx++] != (0x10 | 0x20) ||
            GetLength(input, &idx, &length, maxIdx) < 0)
        return USER_CRYPTO_ERROR;

    *len      = length;
    *inOutIdx = idx;

    return length;
}


static int GetMyVersion(const byte* input, word32* inOutIdx,
                               int* version)
{
    word32 idx = *inOutIdx;

    if (input[idx++] != 0x02)
        return USER_CRYPTO_ERROR;

    if (input[idx++] != 0x01)
        return USER_CRYPTO_ERROR;

    *version  = input[idx++];
    *inOutIdx = idx;

    return *version;
}


int wc_RsaPrivateKeyDecode(const byte* input, word32* inOutIdx, RsaKey* key,
                        word32 inSz)
{
    int    version, length;
    int  ctxSz, pSz, qSz;
    IppStatus ret;

    USER_DEBUG(("Entering wc_RsaPrivateKeyDecode\n"));

    /* read in key information */
    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return USER_CRYPTO_ERROR;

    if (GetMyVersion(input, inOutIdx, &version) < 0)
        return USER_CRYPTO_ERROR;

    key->type = RSA_PRIVATE;

    if (GetInt(&key->n,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->e,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->dipp,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->pipp,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->qipp,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->dPipp, input, inOutIdx, inSz) < 0 ||
        GetInt(&key->dQipp, input, inOutIdx, inSz) < 0 ||
        GetInt(&key->uipp,  input, inOutIdx, inSz) < 0 )
        return USER_CRYPTO_ERROR;

    /* get sizes of IPP BN key states created from input */
    ret = ippsGetSize_BN(key->n, &key->nSz);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsGetSize_BN error %s\n", ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    ret = ippsGetSize_BN(key->e, &key->eSz);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsGetSize_BN error %s\n", ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    key->sz = key->nSz; /* set modulus size */

    /* convert to size in bits */
    key->nSz = key->nSz * 8;
    key->eSz = key->eSz * 8;

    /* set up public key state */
    ret = ippsRSA_GetSizePublicKey(key->nSz, key->eSz, &ctxSz);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsRSA_GetSizePublicKey error %s\n",
                ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    key->pPub = XMALLOC(ctxSz, NULL, DYNAMIC_TYPE_USER_CRYPTO);
    if (key->pPub == NULL)
        return USER_CRYPTO_ERROR;

    ret = ippsRSA_InitPublicKey(key->nSz, key->eSz, key->pPub, ctxSz);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsRSA_InitPublicKey error %s\n",
                    ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    ret = ippsRSA_SetPublicKey(key->n, key->e, key->pPub);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsRSA_SetPublicKey error %s\n",
                    ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    /* get bn sizes needed for private key set up */
    ret = ippsGetSize_BN(key->pipp, &pSz);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsGetSize_BN error %s\n", ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    ret = ippsGetSize_BN(key->qipp, &qSz);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsGetSize_BN error %s\n", ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    /* store sizes needed for creating tmp private keys */
    ret = ippsGetSize_BN(key->dipp, &key->dSz);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsGetSize_BN error %s\n", ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    /* convert to size in bits */
    key->dSz = key->dSz * 8;
    pSz = pSz * 8;
    qSz = qSz * 8;

    /* set up private key state */
    ret = ippsRSA_GetSizePrivateKeyType2(pSz, qSz, &ctxSz);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsRSA_GetSizePrivateKey error %s\n",
                ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    key->prvSz = ctxSz;
    key->pPrv = XMALLOC(ctxSz, 0, DYNAMIC_TYPE_USER_CRYPTO);
    if (key->pPrv == NULL)
        return USER_CRYPTO_ERROR;

    ret = ippsRSA_InitPrivateKeyType2(pSz, qSz, key->pPrv, ctxSz);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsRSA_InitPrivateKey error %s\n",
                    ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    ret = ippsRSA_SetPrivateKeyType2(key->pipp, key->qipp, key->dPipp,
            key->dQipp, key->uipp, key->pPrv);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsRSA_SetPrivateKey error %s\n",
                    ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    USER_DEBUG(("\tExit wc_RsaPrivateKeyDecode\n"));

    return 0;
}


/* read in a public RSA key */
int wc_RsaPublicKeyDecode(const byte* input, word32* inOutIdx, RsaKey* key,
                       word32 inSz)
{
    int    length;
    int  ctxSz;
    IppStatus ret;

    USER_DEBUG(("Entering wc_RsaPublicKeyDecode\n"));

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return USER_CRYPTO_ERROR;

    key->type = RSA_PUBLIC;

#if defined(OPENSSL_EXTRA) || defined(RSA_DECODE_EXTRA)
    {
    byte b = input[*inOutIdx];
    if (b != ASN_INTEGER) {
        /* not from decoded cert, will have algo id, skip past */
        if (GetSequence(input, inOutIdx, &length, inSz) < 0)
            return USER_CRYPTO_ERROR;

        b = input[(*inOutIdx)++];
        if (b != ASN_OBJECT_ID)
            return USER_CRYPTO_ERROR;

        if (GetLength(input, inOutIdx, &length, inSz) < 0)
            return USER_CRYPTO_ERROR;

        *inOutIdx += length;   /* skip past */

        /* could have NULL tag and 0 terminator, but may not */
        b = input[(*inOutIdx)++];

        if (b == ASN_TAG_NULL) {
            b = input[(*inOutIdx)++];
            if (b != 0)
                return USER_CRYPTO_ERROR;
        }
        else
        /* go back, didn't have it */
            (*inOutIdx)--;

        /* should have bit tag length and seq next */
        b = input[(*inOutIdx)++];
        if (b != ASN_BIT_STRING)
            return USER_CRYPTO_ERROR;

        if (GetLength(input, inOutIdx, &length, inSz) < 0)
            return USER_CRYPTO_ERROR;

        /* could have 0 */
        b = input[(*inOutIdx)++];
        if (b != 0)
            (*inOutIdx)--;

        if (GetSequence(input, inOutIdx, &length, inSz) < 0)
            return USER_CRYPTO_ERROR;
    }  /* end if */
    }  /* openssl var block */
#endif /* OPENSSL_EXTRA */

    if (GetInt(&key->n,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->e,  input, inOutIdx, inSz) < 0 )  return USER_CRYPTO_ERROR;

    /* get sizes set for IPP BN states */
    ret = ippsGetSize_BN(key->n, &key->nSz);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsGetSize_BN error %s\n", ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    ret = ippsGetSize_BN(key->e, &key->eSz);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsGetSize_BN error %s\n", ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    key->sz = key->nSz; /* set modulus size */

    /* convert to size in bits */
    key->nSz = key->nSz * 8;
    key->eSz = key->eSz * 8;

    /* set up public key state */
    ret = ippsRSA_GetSizePublicKey(key->nSz, key->eSz, &ctxSz);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsRSA_GetSizePublicKey error %s\n",
                ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    key->pPub = XMALLOC(ctxSz, NULL, DYNAMIC_TYPE_USER_CRYPTO);
    if (key->pPub == NULL)
        return USER_CRYPTO_ERROR;

    ret = ippsRSA_InitPublicKey(key->nSz, key->eSz, key->pPub, ctxSz);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsRSA_InitPublicKey error %s\n",
                    ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    ret = ippsRSA_SetPublicKey(key->n, key->e, key->pPub);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsRSA_SetPublicKey error %s\n",
                    ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    USER_DEBUG(("\tExit RsaPublicKeyDecode\n"));

    return 0;
}


/* import RSA public key elements (n, e) into RsaKey structure (key) */
int wc_RsaPublicKeyDecodeRaw(const byte* n, word32 nSz, const byte* e,
                             word32 eSz, RsaKey* key)
{
    IppStatus ret;
    int ctxSz;

    USER_DEBUG(("Entering wc_RsaPublicKeyDecodeRaw\n"));

    if (n == NULL || e == NULL || key == NULL)
        return USER_CRYPTO_ERROR;

    /* set up IPP key states -- read in n */
    ret = ippsBigNumGetSize(nSz, &ctxSz);
    if (ret != ippStsNoErr)
        return USER_CRYPTO_ERROR;

    key->n = XMALLOC(ctxSz, 0, DYNAMIC_TYPE_USER_CRYPTO);
    if (key->n == NULL)
        return USER_CRYPTO_ERROR;

    ret = ippsBigNumInit(nSz, key->n);
    if (ret != ippStsNoErr)
        return USER_CRYPTO_ERROR;

    ret = ippsSetOctString_BN((Ipp8u*)n, nSz, key->n);
    if (ret != ippStsNoErr)
        return USER_CRYPTO_ERROR;

    /* read in e */
    ret = ippsBigNumGetSize(eSz, &ctxSz);
    if (ret != ippStsNoErr)
        return USER_CRYPTO_ERROR;

    key->e = XMALLOC(ctxSz, 0, DYNAMIC_TYPE_USER_CRYPTO);
    if (key->e == NULL)
        return USER_CRYPTO_ERROR;

    ret = ippsBigNumInit(eSz, key->e);
    if (ret != ippStsNoErr)
        return USER_CRYPTO_ERROR;

    ret = ippsSetOctString_BN((Ipp8u*)e, eSz, key->e);
    if (ret != ippStsNoErr)
        return USER_CRYPTO_ERROR;

    /* store size and convert to binary */
    key->sz = nSz;
    nSz = nSz * 8;
    eSz = eSz * 8;

    /* set up public key state */
    ret = ippsRSA_GetSizePublicKey(nSz, eSz, &ctxSz);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsRSA_GetSizePublicKey error %s\n",
                ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    key->pPub = XMALLOC(ctxSz, NULL, DYNAMIC_TYPE_USER_CRYPTO);
    if (key->pPub == NULL)
        return USER_CRYPTO_ERROR;

    ret = ippsRSA_InitPublicKey(nSz, eSz, key->pPub, ctxSz);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsRSA_InitPublicKey error %s\n",
                    ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    ret = ippsRSA_SetPublicKey(key->n,key->e, key->pPub);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsRSA_SetPublicKey error %s\n",
                    ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    key->nSz = nSz;
    key->eSz = eSz;
    key->type = RSA_PUBLIC;

    return USER_CRYPTO_ERROR;
}


/* encrypt using PKCS v15 */
int wc_RsaPublicEncrypt(const byte* in, word32 inLen, byte* out, word32 outLen,
                     RsaKey* key, WC_RNG* rng)
{
    IppStatus ret;
    Ipp8u* scratchBuffer;
    int    scratchSz;

    if (key == NULL || in == NULL || out == NULL)
        return USER_CRYPTO_ERROR;

    if (key->pPub == NULL || outLen < key->sz)
        return USER_CRYPTO_ERROR;

    /* set size of scratch buffer */
    ret = ippsRSA_GetBufferSizePublicKey(&scratchSz, key->pPub);
    if (ret != ippStsNoErr)
        return USER_CRYPTO_ERROR;

    scratchBuffer = XMALLOC(scratchSz*(sizeof(Ipp8u)), 0,
                            DYNAMIC_TYPE_USER_CRYPTO);
    if (scratchBuffer == NULL)
        return USER_CRYPTO_ERROR;

    ret = ippsRSAEncrypt_PKCSv15((Ipp8u*)in, inLen, NULL, (Ipp8u*)out,
            key->pPub, scratchBuffer);
    if (ret != ippStsNoErr) {
        XFREE(scratchBuffer, NULL, DYNAMIC_TYPE_USER_CRYPTO);
        USER_DEBUG(("encrypt error of %s\n", ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    XFREE(scratchBuffer, NULL, DYNAMIC_TYPE_USER_CRYPTO);

    (void)rng;
    return key->sz;
}


/* decrypt using PLCS v15 */
int wc_RsaPrivateDecrypt(const byte* in, word32 inLen, byte* out, word32 outLen,
                     RsaKey* key)
{
    IppStatus ret;
    Ipp8u* scratchBuffer;
    int    scratchSz;
    int    outSz;

    if (in == NULL || out == NULL || key == NULL)
        return USER_CRYPTO_ERROR;

    if (key->pPrv == NULL || inLen != key->sz)
        return USER_CRYPTO_ERROR;

    outSz = outLen;

    /* set size of scratch buffer */
    ret = ippsRSA_GetBufferSizePrivateKey(&scratchSz, key->pPrv);
    if (ret != ippStsNoErr) {
        return USER_CRYPTO_ERROR;
    }

    scratchBuffer = XMALLOC(scratchSz*(sizeof(Ipp8u)), 0,
                                        DYNAMIC_TYPE_USER_CRYPTO);
    if (scratchBuffer == NULL) {
        return USER_CRYPTO_ERROR;
    }

    /* perform decryption using IPP */
    ret = ippsRSADecrypt_PKCSv15((Ipp8u*)in, (Ipp8u*)out, &outSz, key->pPrv,
            scratchBuffer);
    if (ret != ippStsNoErr) {
        XFREE(scratchBuffer, NULL, DYNAMIC_TYPE_USER_CRYPTO);
        USER_DEBUG(("decrypt error of %s\n", ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    XFREE(scratchBuffer, NULL, DYNAMIC_TYPE_USER_CRYPTO);

    return outSz;
}


/* out is a pointer that is set to the location in byte array "in" where input
 data has been decrypted */
int wc_RsaPrivateDecryptInline(byte* in, word32 inLen, byte** out, RsaKey* key)
{
    int outSz;
    byte* tmp;

    USER_DEBUG(("Entering wc_RsaPrivateDecryptInline\n"));

    /* allocate a buffer for max decrypted text */
    tmp = XMALLOC(key->sz, NULL, DYNAMIC_TYPE_USER_CRYPTO);
    if (tmp == NULL)
        return USER_CRYPTO_ERROR;

    outSz = wc_RsaPrivateDecrypt(in, inLen, tmp, key->sz, key);
    if (outSz >= 0) {
        XMEMCPY(in, tmp, outSz);
        *out = in;
    }
    else {
        XFREE(tmp, NULL, DYNAMIC_TYPE_USER_CRYPTO);
        return USER_CRYPTO_ERROR;
    }

    XFREE(tmp, NULL, DYNAMIC_TYPE_USER_CRYPTO);
    USER_DEBUG(("\tExit wc_RsaPrivateDecryptInline\n"));

    return outSz;
}


/* Used to clean up memory when exiting, clean up memory used */
static int FreeHelper(IppsBigNumState* pTxt, IppsBigNumState* cTxt,
        Ipp8u* scratchBuffer, void* pPub)
{
    if (pTxt != NULL)
        XFREE(pTxt, NULL, DYNAMIC_TYPE_USER_CRYPTO);
    if (cTxt != NULL)
        XFREE(cTxt, NULL, DYNAMIC_TYPE_USER_CRYPTO);
    if (scratchBuffer != NULL)
        XFREE(scratchBuffer, NULL, DYNAMIC_TYPE_USER_CRYPTO);
    if (pPub != NULL)
        XFREE(pPub, NULL, DYNAMIC_TYPE_USER_CRYPTO);

    return 0;
}


/* for Rsa Verify
    in : byte array to be verified
    inLen : length of input array
    out : pointer to location of in byte array that has been verified
 */
int wc_RsaSSL_VerifyInline(byte* in, word32 inLen, byte** out, RsaKey* key)
{

    int ctxSz;
    int scratchSz;
    Ipp8u* scratchBuffer = NULL;
    IppStatus ret;
    IppsRSAPrivateKeyState* pPub = NULL;
    IppsBigNumState* pTxt = NULL;
    IppsBigNumState* cTxt = NULL;

    USER_DEBUG(("Entering wc_RsaSSL_VerifyInline\n"));

    if (key == NULL || key->n == NULL || key->e == NULL) {
        USER_DEBUG(("n or e element was null\n"));
        return USER_CRYPTO_ERROR;
    }

    if (in == NULL || out == NULL)
        return USER_CRYPTO_ERROR;

    /* set up a private key state using public key values */
    ret = ippsRSA_GetSizePrivateKeyType1(key->nSz, key->eSz, &ctxSz);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsRSA_GetSizePrivateKey error %s\n",
                ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    pPub = XMALLOC(ctxSz, 0, DYNAMIC_TYPE_USER_CRYPTO);
    if (pPub == NULL)
        return USER_CRYPTO_ERROR;

    ret = ippsRSA_InitPrivateKeyType1(key->nSz, key->eSz, pPub, ctxSz);
    if (ret != ippStsNoErr) {
        FreeHelper(pTxt, cTxt, scratchBuffer, pPub);
        USER_DEBUG(("ippsRSA_InitPrivateKey error %s\n",
                    ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }


    ret = ippsRSA_SetPrivateKeyType1(key->n, key->e, pPub);
    if (ret != ippStsNoErr) {
        FreeHelper(pTxt, cTxt, scratchBuffer, pPub);
        USER_DEBUG(("ippsRSA_SetPrivateKey error %s\n",
                    ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    /* set size of scratch buffer */
    ret = ippsRSA_GetBufferSizePrivateKey(&scratchSz, pPub);
    if (ret != ippStsNoErr) {
        FreeHelper(pTxt, cTxt, scratchBuffer, pPub);
        return USER_CRYPTO_ERROR;
    }

    scratchBuffer = XMALLOC(scratchSz*(sizeof(Ipp8u)), 0,
                            DYNAMIC_TYPE_USER_CRYPTO);
    if (scratchBuffer == NULL) {
        FreeHelper(pTxt, cTxt, scratchBuffer, pPub);
        return USER_CRYPTO_ERROR;
    }

    /* load plain and cipher into big num states */
    ret = ippsBigNumGetSize(key->sz, &ctxSz);
    if (ret != ippStsNoErr) {
        FreeHelper(pTxt, cTxt, scratchBuffer, pPub);
        return USER_CRYPTO_ERROR;
    }

    pTxt = XMALLOC(ctxSz, 0, DYNAMIC_TYPE_USER_CRYPTO);
    if (pTxt == NULL) {
        FreeHelper(pTxt, cTxt, scratchBuffer, pPub);
        return USER_CRYPTO_ERROR;
    }

    ret = ippsBigNumInit(key->sz, pTxt);
    if (ret != ippStsNoErr) {
        FreeHelper(pTxt, cTxt, scratchBuffer, pPub);
        return USER_CRYPTO_ERROR;
    }

    ret = ippsSetOctString_BN((Ipp8u*)in, key->sz, pTxt);
    if (ret != ippStsNoErr) {
        FreeHelper(pTxt, cTxt, scratchBuffer, pPub);
        return USER_CRYPTO_ERROR;
    }

    /* set up cipher to hold signature */
    ret = ippsBigNumGetSize(key->sz, &ctxSz);
    if (ret != ippStsNoErr) {
        FreeHelper(pTxt, cTxt, scratchBuffer, pPub);
        return USER_CRYPTO_ERROR;
    }

    cTxt = XMALLOC(ctxSz, 0, DYNAMIC_TYPE_USER_CRYPTO);
    if (cTxt == NULL) {
        FreeHelper(pTxt, cTxt, scratchBuffer, pPub);
        return USER_CRYPTO_ERROR;
    }

    ret = ippsBigNumInit(key->sz, cTxt);
    if (ret != ippStsNoErr) {
        FreeHelper(pTxt, cTxt, scratchBuffer, pPub);
        return USER_CRYPTO_ERROR;
    }

    ret = ippsSetOctString_BN((Ipp8u*)in, key->sz, cTxt);
    if (ret != ippStsNoErr) {
        FreeHelper(pTxt, cTxt, scratchBuffer, pPub);
        return USER_CRYPTO_ERROR;
    }

    /* decrypt using public key information */
    ret = ippsRSA_Decrypt(cTxt, pTxt, pPub, scratchBuffer);
    if (ret != ippStsNoErr) {
        FreeHelper(pTxt, cTxt, scratchBuffer, pPub);
        USER_DEBUG(("decrypt error of %s\n", ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    /* extract big num struct to octect string */
    ret = ippsGetOctString_BN((Ipp8u*)in, key->sz, pTxt);
    if (ret != ippStsNoErr) {
        FreeHelper(pTxt, cTxt, scratchBuffer, pPub);
        USER_DEBUG(("BN get string error of %s\n", ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    FreeHelper(pTxt, cTxt, scratchBuffer, pPub);

    /* unpad the decrypted information and return size of array */
    return RsaUnPad(in, inLen, out, RSA_BLOCK_TYPE_1);
}


/* sets up and call VerifyInline to verify a signature */
int wc_RsaSSL_Verify(const byte* in, word32 inLen, byte* out, word32 outLen,
                     RsaKey* key)
{
    int plainLen;
    byte*  tmp;
    byte*  pad = 0;

    if (out == NULL || in == NULL || key == NULL)
        return USER_CRYPTO_ERROR;

    tmp = (byte*)XMALLOC(inLen, key->heap, DYNAMIC_TYPE_USER_CRYPTO);
    if (tmp == NULL) {
        return USER_CRYPTO_ERROR;
    }

    XMEMCPY(tmp, in, inLen);

    /* verify signature and test if output buffer is large enough */
    plainLen = wc_RsaSSL_VerifyInline(tmp, inLen, &pad, key);
    if (plainLen < 0) {
        XFREE(tmp, NULL, DYNAMIC_TYPE_USER_CRYPTO);
        return plainLen;
    }

    if (plainLen > (int)outLen)
        plainLen = USER_CRYPTO_ERROR;
    else
        XMEMCPY(out, pad, plainLen);

    ForceZero(tmp, inLen);
    XFREE(tmp, NULL, DYNAMIC_TYPE_USER_CRYPTO);

    return plainLen;
}


/* for Rsa Sign */
int wc_RsaSSL_Sign(const byte* in, word32 inLen, byte* out, word32 outLen,
                      RsaKey* key, WC_RNG* rng)
{
    int sz;
    int scratchSz;
    int ctxSz;
    int prvSz;
    IppStatus ret;
    Ipp8u* scratchBuffer = NULL;
    IppsRSAPublicKeyState* pPrv = NULL;
    IppsBigNumState* pTxt = NULL;
    IppsBigNumState* cTxt = NULL;

    sz = key->sz;

    /* set up public key state using private key values */
    ret = ippsRSA_GetSizePublicKey(key->nSz, key->dSz, &ctxSz);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsRSA_GetSizePrivateKey error %s\n",
                ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    prvSz = ctxSz; /* used later to overright sensitive memory */
    pPrv = XMALLOC(ctxSz, 0, DYNAMIC_TYPE_USER_CRYPTO);
    if (pPrv == NULL) {
        USER_DEBUG(("memeory error assinging pPrv\n"));
        return USER_CRYPTO_ERROR;
    }

    ret = ippsRSA_InitPublicKey(key->nSz, key->dSz, pPrv, ctxSz);
    if (ret != ippStsNoErr) {
        FreeHelper(pTxt, cTxt, scratchBuffer, pPrv);
        USER_DEBUG(("ippsRSA_InitPrivateKey error %s\n",
                    ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    ret = ippsRSA_SetPublicKey(key->n, key->dipp, pPrv);
    if (ret != ippStsNoErr) {
        FreeHelper(pTxt, cTxt, scratchBuffer, pPrv);
        USER_DEBUG(("ippsRSA_SetPrivateKey error %s\n",
                    ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    /* set size of scratch buffer */
    ret = ippsRSA_GetBufferSizePublicKey(&scratchSz, pPrv);
    if (ret != ippStsNoErr) {
        FreeHelper(pTxt, cTxt, scratchBuffer, pPrv);
        USER_DEBUG(("ippsRSA_GetBufferSizePublicKey error %s\n",
                ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    scratchBuffer = XMALLOC(scratchSz*(sizeof(Ipp8u)), 0,
                            DYNAMIC_TYPE_USER_CRYPTO);
    if (scratchBuffer == NULL) {
        FreeHelper(pTxt, cTxt, scratchBuffer, pPrv);
        USER_DEBUG(("memory error assigning scratch buffer\n"));
        return USER_CRYPTO_ERROR;
    }

    /* Set up needed pkcs v15 padding */
    if (wc_RsaPad(in, inLen, out, sz, RSA_BLOCK_TYPE_1, rng) != 0) {
        FreeHelper(pTxt, cTxt, scratchBuffer, pPrv);
        return USER_CRYPTO_ERROR;
    }

    /* load plain and cipher into big num states */
    ret = ippsBigNumGetSize(sz, &ctxSz);
    if (ret != ippStsNoErr) {
        FreeHelper(pTxt, cTxt, scratchBuffer, pPrv);
        return USER_CRYPTO_ERROR;
    }

    pTxt = XMALLOC(ctxSz, 0, DYNAMIC_TYPE_USER_CRYPTO);
    if (pTxt == NULL) {
        FreeHelper(pTxt, cTxt, scratchBuffer, pPrv);
        return USER_CRYPTO_ERROR;
    }

    ret = ippsBigNumInit(sz, pTxt);
    if (ret != ippStsNoErr) {
        FreeHelper(pTxt, cTxt, scratchBuffer, pPrv);
        return USER_CRYPTO_ERROR;
    }

    ret = ippsSetOctString_BN((Ipp8u*)out, sz, pTxt);
    if (ret != ippStsNoErr) {
        FreeHelper(pTxt, cTxt, scratchBuffer, pPrv);
        return USER_CRYPTO_ERROR;
    }

    /* set up cipher to hold signature */
    ret = ippsBigNumGetSize(outLen, &ctxSz);
    if (ret != ippStsNoErr) {
        FreeHelper(pTxt, cTxt, scratchBuffer, pPrv);
        return USER_CRYPTO_ERROR;
    }

    cTxt = XMALLOC(ctxSz, 0, DYNAMIC_TYPE_USER_CRYPTO);
    if (cTxt == NULL) {
        FreeHelper(pTxt, cTxt, scratchBuffer, pPrv);
        return USER_CRYPTO_ERROR;
    }

    ret = ippsBigNumInit(outLen, cTxt);
    if (ret != ippStsNoErr) {
        FreeHelper(pTxt, cTxt, scratchBuffer, pPrv);
        return USER_CRYPTO_ERROR;
    }

    ret = ippsSetOctString_BN((Ipp8u*)out, outLen, cTxt);
    if (ret != ippStsNoErr) {
        FreeHelper(pTxt, cTxt, scratchBuffer, pPrv);
        return USER_CRYPTO_ERROR;
    }

    /* encrypt using private key */
    ret = ippsRSA_Encrypt(pTxt, cTxt, pPrv, scratchBuffer);
    if (ret != ippStsNoErr) {
        FreeHelper(pTxt, cTxt, scratchBuffer, pPrv);
        USER_DEBUG(("sign error of %s\n", ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    /* get output string from big number structure */
    ret = ippsGetOctString_BN((Ipp8u*)out, sz, cTxt);
    if (ret != ippStsNoErr) {
        FreeHelper(pTxt, cTxt, scratchBuffer, pPrv);
        USER_DEBUG(("BN get string error of %s\n", ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    /* clean up memory used */
    ForceZero(pPrv, prvSz); /* clear senstive memory */
    FreeHelper(pTxt, cTxt, scratchBuffer, pPrv);

    return sz;
}


int wc_RsaEncryptSize(RsaKey* key)
{
    if (key == NULL)
        return 0;

    return key->sz;
}


/* flatten RsaKey structure into individual elements (e, n) */
int wc_RsaFlattenPublicKey(RsaKey* key, byte* e, word32* eSz, byte* n,
                           word32* nSz)
{
    int sz, bytSz;
    IppStatus ret;

    USER_DEBUG(("Entering wc_RsaFlattenPublicKey\n"));

    if (key == NULL || e == NULL || eSz == NULL || n == NULL || nSz == NULL)
       return USER_CRYPTO_ERROR;

    bytSz = sizeof(byte);
    ret = ippsExtGet_BN(NULL, &sz, NULL, key->e);
    if (ret != ippStsNoErr)
        return USER_CRYPTO_ERROR;

    /* sz is in bits change to bytes */
    sz = (sz / bytSz) + (sz % bytSz);

    if (*eSz < (word32)sz)
        return USER_CRYPTO_ERROR;

    ret = ippsGetOctString_BN(e, sz, key->e);
    if (ret != ippStsNoErr)
        return USER_CRYPTO_ERROR;

    *eSz = (word32)sz;

    /* flatten n */
    ret = ippsExtGet_BN(NULL, &sz, NULL, key->n);
    if (ret != ippStsNoErr)
        return USER_CRYPTO_ERROR;

    /* sz is in bits change to bytes */
    sz = (sz / bytSz) + (sz % bytSz);

    if (*nSz < (word32)sz)
        return USER_CRYPTO_ERROR;

    ret = ippsGetOctString_BN(n, sz, key->n);
    if (ret != ippStsNoErr)
        return USER_CRYPTO_ERROR;

    *nSz = (word32)sz;

    return 0;
}

#ifdef WOLFSSL_KEY_GEN
/* Make an RSA key for size bits, with e specified, 65537 is a good e */
int wc_MakeRsaKey(RsaKey* key, int size, long e, WC_RNG* rng)
{
    IppStatus ret;
    int scratchSz;
    int i; /* for trys on calling make key */
    int ctxSz;

    IppsBigNumState* pSrcPublicExp;
    Ipp8u* scratchBuffer;
    int trys = 8; /* Miller-Rabin test parameter */
    IppsPrimeState* pPrime;
    IppBitSupplier rndFunc;
    IppsPRNGState* rndParam; /* rng context */

    int qBitSz; /* size of q factor */
    int bytSz; /* size of key in bytes */
    int leng;

    USER_DEBUG(("Entering wc_MakeRsaKey\n"));

    qBitSz = size / 2;
    bytSz  = size / 8;

    if (key == NULL)
        return USER_CRYPTO_ERROR;

    if (e < 3 || (e&1) == 0)
        return USER_CRYPTO_ERROR;

    if (size > RSA_MAX_SIZE || size < RSA_MIN_SIZE)
        return USER_CRYPTO_ERROR;

    key->type = RSA_PRIVATE;

    /* set up rng */
    ret = ippsPRNGGetSize(&ctxSz);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsPRNGGetSize error of %s\n", ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    rndParam = XMALLOC(ctxSz, NULL, DYNAMIC_TYPE_USER_CRYPTO);
    if (rndParam == NULL)
        return USER_CRYPTO_ERROR;

    /*@TODO size of seed bits used hard set at 256 */
    ret = ippsPRNGInit(256, rndParam);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsPRNGInit error of %s\n", ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    /* initialize prime number */
    ret = ippsPrimeGetSize(size, &ctxSz); /* size in bits */
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsPrimeGetSize error of %s\n", ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    pPrime = XMALLOC(ctxSz, NULL, DYNAMIC_TYPE_USER_CRYPTO);
    if (pPrime == NULL)
        return USER_CRYPTO_ERROR;

    ret = ippsPrimeInit(size, pPrime);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsPrimeInit error of %s\n", ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    ret = ippsPrimeGen(size, 100, pPrime, ippsPRNGen, rndParam);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsPrimeGen error of %s\n", ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    /* define RSA privete key type 2 */
    /* length in bits of p and q factors */
    ret = ippsRSA_GetSizePrivateKeyType2(qBitSz, qBitSz, &ctxSz);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsRSA_GetSizePrivateKeyType2 error of %s\n",
                ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    key->prvSz = ctxSz; /* used when freeing private key */
    key->pPrv = XMALLOC(ctxSz, NULL, DYNAMIC_TYPE_USER_CRYPTO);
    if (key->pPrv == NULL)
        return USER_CRYPTO_ERROR;

    /* length in bits of p and q factors */
    ret = ippsRSA_InitPrivateKeyType2(qBitSz, qBitSz, key->pPrv, ctxSz);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsRSA_InitPrivateKeyType2 error of %s\n",
                ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    /* allocate scratch buffer */
    ret = ippsRSA_GetBufferSizePrivateKey(&scratchSz, key->pPrv);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsRSA_GetBufferSizePrivateKey error of %s\n",
                ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    scratchBuffer = XMALLOC(scratchSz, 0, DYNAMIC_TYPE_USER_CRYPTO);
    if (scratchBuffer == NULL)
        return USER_CRYPTO_ERROR;

    /* set up initial value of pScrPublicExp */
    leng = (int)sizeof(long); /* # of Ipp32u in long */
    ret = ippsBigNumGetSize(leng, &ctxSz);
    if (ret != ippStsNoErr)
        return USER_CRYPTO_ERROR;

    pSrcPublicExp = XMALLOC(ctxSz, 0, DYNAMIC_TYPE_USER_CRYPTO);
    if (pSrcPublicExp == NULL)
        return USER_CRYPTO_ERROR;

    ret = ippsBigNumInit(leng, pSrcPublicExp);
    if (ret != ippStsNoErr)
        return USER_CRYPTO_ERROR;
    ret = ippsSetOctString_BN((Ipp8u*)&e, leng, pSrcPublicExp);
    if (ret != ippStsNoErr)
        return USER_CRYPTO_ERROR;

    /* initializing key->n */
    ret = ippsBigNumGetSize(bytSz, &ctxSz);
    if (ret != ippStsNoErr)
        return USER_CRYPTO_ERROR;

    key->n = XMALLOC(ctxSz, 0, DYNAMIC_TYPE_USER_CRYPTO);
    if (key->n == NULL)
        return USER_CRYPTO_ERROR;

    key->nSz = size;
    ret = ippsBigNumInit(bytSz, key->n);
    if (ret != ippStsNoErr)
        return USER_CRYPTO_ERROR;

    /* initializing public exponent key->e */
    ret = ippsBigNumGetSize(leng, &ctxSz);
    if (ret != ippStsNoErr)
        return USER_CRYPTO_ERROR;

    key->e = XMALLOC(ctxSz, 0, DYNAMIC_TYPE_USER_CRYPTO);
    if (key->e == NULL)
        return USER_CRYPTO_ERROR;

    ret = ippsBigNumInit(leng, key->e);
    if (ret != ippStsNoErr)
        return USER_CRYPTO_ERROR;

    /* private exponent key->dipp */
    ret = ippsBigNumGetSize(bytSz, &ctxSz);
    if (ret != ippStsNoErr)
        return USER_CRYPTO_ERROR;

    key->dipp = XMALLOC(ctxSz, 0, DYNAMIC_TYPE_USER_CRYPTO);
    if (key->dipp == NULL)
        return USER_CRYPTO_ERROR;

    ret = ippsBigNumInit(bytSz, key->dipp);
    if (ret != ippStsNoErr)
        return USER_CRYPTO_ERROR;

    rndFunc = ippsPRNGen;
    /* call IPP to generate keys, if inseficent entropy error call again
     using for loop to avoid infinte loop */
    for (i = 0; i < 5; i++) {
        ret = ippsRSA_GenerateKeys(pSrcPublicExp, key->n, key->e,
                key->dipp, key->pPrv, scratchBuffer, trys, pPrime,
                rndFunc, rndParam);
        if (ret == ippStsNoErr) {
            break;
        }

        /* catch all errors other than entropy error */
        if (ret != ippStsInsufficientEntropy) {
            USER_DEBUG(("ippsRSA_GeneratKeys error of %s\n",
                    ippGetStatusString(ret)));
            return USER_CRYPTO_ERROR;
        }
    }

    /* get bn sizes needed for private key set up */
    ret = ippsExtGet_BN(NULL, &key->eSz, NULL, key->e);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsGetSize_BN error %s\n", ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    ret = ippsExtGet_BN(NULL, &key->nSz, NULL, key->n);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsGetSize_BN error %s\n", ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    /* set up public key state */
    ret = ippsRSA_GetSizePublicKey(key->nSz, key->eSz, &ctxSz);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsRSA_GetSizePublicKey error %s nSz = %d eSz = %d\n",
                ippGetStatusString(ret), key->nSz, key->eSz));
        return USER_CRYPTO_ERROR;
    }

    key->pPub = XMALLOC(ctxSz, NULL, DYNAMIC_TYPE_USER_CRYPTO);
    if (key->pPub == NULL)
        return USER_CRYPTO_ERROR;

    ret = ippsRSA_InitPublicKey(key->nSz, key->eSz, key->pPub, ctxSz);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsRSA_InitPublicKey error %s\n",
                    ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    ret = ippsRSA_SetPublicKey(key->n, key->e, key->pPub);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsRSA_SetPublicKey error %s\n",
                    ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    /* get private key information for key struct */
    leng = size/16; /* size of q, p, u, dP, dQ */
    ret = ippsBigNumGetSize(leng, &ctxSz); /* get needed ctxSz and use */
    if (ret != ippStsNoErr)
        return USER_CRYPTO_ERROR;

    key->pipp = XMALLOC(ctxSz, 0, DYNAMIC_TYPE_USER_CRYPTO);
    if (key->pipp == NULL)
        return USER_CRYPTO_ERROR;

    ret = ippsBigNumInit(leng, key->pipp);
    if (ret != ippStsNoErr)
        return USER_CRYPTO_ERROR;

    /* set up q BN for key */
    key->qipp = XMALLOC(ctxSz, 0, DYNAMIC_TYPE_USER_CRYPTO);
    if (key->qipp == NULL)
        return USER_CRYPTO_ERROR;

    ret = ippsBigNumInit(leng, key->qipp);
    if (ret != ippStsNoErr)
        return USER_CRYPTO_ERROR;

    /* set up dP BN for key */
    key->dPipp = XMALLOC(ctxSz, 0, DYNAMIC_TYPE_USER_CRYPTO);
    if (key->dPipp == NULL)
        return USER_CRYPTO_ERROR;

    ret = ippsBigNumInit(leng, key->dPipp);
    if (ret != ippStsNoErr)
        return USER_CRYPTO_ERROR;

    /* set up dQ BN for key */
    key->dQipp = XMALLOC(ctxSz, 0, DYNAMIC_TYPE_USER_CRYPTO);
    if (key->dQipp == NULL)
        return USER_CRYPTO_ERROR;

    ret = ippsBigNumInit(leng, key->dQipp);
    if (ret != ippStsNoErr)
        return USER_CRYPTO_ERROR;

    /* set up u BN for key */
    key->uipp = XMALLOC(ctxSz, 0, DYNAMIC_TYPE_USER_CRYPTO);
    if (key->uipp == NULL)
        return USER_CRYPTO_ERROR;

    ret = ippsBigNumInit(leng, key->uipp);
    if (ret != ippStsNoErr)
        return USER_CRYPTO_ERROR;

    /* get values from created key */
    ret = ippsRSA_GetPrivateKeyType2(key->pipp, key->qipp, key->dPipp,
            key->dQipp, key->uipp, key->pPrv);
    if (ret != ippStsNoErr) {
        USER_DEBUG(("ippsRSA_GetPrivateKeyType2 error %s\n",
                ippGetStatusString(ret)));
        return USER_CRYPTO_ERROR;
    }

    /* clean up memory used */
    XFREE(pSrcPublicExp, NULL, DYNAMIC_TYPE_USER_CRYPTO);
    XFREE(scratchBuffer, NULL, DYNAMIC_TYPE_USER_CRYPTO);
    XFREE(pPrime, NULL, DYNAMIC_TYPE_USER_CRYPTO);
    XFREE(rndParam, NULL, DYNAMIC_TYPE_USER_CRYPTO);

    (void)rng;

    return 0;
}

/********** duplicate code needed -- future refactor */
#define MAX_VERSION_SZ 5
#define MAX_SEQ_SZ 5
#define ASN_CONTEXT_SPECIFIC 0x80
#define ASN_CONSTRUCTED 0x20
#define ASN_LONG_LENGTH 0x80
#define ASN_SEQUENCE 0x10
#define RSA_INTS 8
#define FALSE 0
#define TRUE 1

#define MAX_LENGTH_SZ 4
#define RSAk 645
#define keyType 2
#define MAX_RSA_INT_SZ 517
#define MAX_RSA_E_SZ 16
#define MAX_ALGO_SZ 20

static word32 BytePrecision(word32 value)
{
    word32 i;
    for (i = sizeof(value); i; --i)
        if (value >> ((i - 1) * WOLFSSL_BIT_SIZE))
            break;

    return i;
}


static int SetMyVersion(word32 version, byte* output, int header)
{
    int i = 0;

    if (output == NULL)
        return USER_CRYPTO_ERROR;

    if (header) {
        output[i++] = ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED;
        output[i++] = ASN_BIT_STRING;
    }
    output[i++] = ASN_INTEGER;
    output[i++] = 0x01;
    output[i++] = (byte)version;

    return i;
}


static word32 SetLength(word32 length, byte* output)
{
    word32 i = 0, j;

    if (length < 0x80)
        output[i++] = (byte)length;
    else {
        output[i++] = (byte)(BytePrecision(length) | ASN_LONG_LENGTH);

        for (j = BytePrecision(length); j; --j) {
            output[i] = (byte)(length >> ((j - 1) * WOLFSSL_BIT_SIZE));
            i++;
        }
    }

    return i;
}


static word32 SetSequence(word32 len, byte* output)
{
    output[0] = ASN_SEQUENCE | ASN_CONSTRUCTED;
    return SetLength(len, output + 1) + 1;
}


static word32 SetAlgoID(int algoOID, byte* output, int type, int curveSz)
{
    /* adding TAG_NULL and 0 to end */

    /* RSA keyType */
    #ifndef NO_RSA
        static const byte RSA_AlgoID[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                                            0x01, 0x01, 0x01, 0x05, 0x00};
    #endif /* NO_RSA */

    int    algoSz = 0;
    int    tagSz  = 2;   /* tag null and terminator */
    word32 idSz, seqSz;
    const  byte* algoName = 0;
    byte ID_Length[MAX_LENGTH_SZ];
    byte seqArray[MAX_SEQ_SZ + 1];  /* add object_id to end */

    if (type == keyType) {    /* keyType */
        switch (algoOID) {
        #ifndef NO_RSA
            case RSAk:
                algoSz = sizeof(RSA_AlgoID);
                algoName = RSA_AlgoID;
                break;
        #endif /* NO_RSA */
        default:
            /* unknown key algo */
            return 0;
        }
    }
    else {
        /* unknown algo type */
        return 0;
    }

    idSz  = SetLength(algoSz - tagSz, ID_Length); /* don't include tags */
    seqSz = SetSequence(idSz + algoSz + 1 + curveSz, seqArray);
                 /* +1 for object id, curveID of curveSz follows for ecc */
    seqArray[seqSz++] = ASN_OBJECT_ID;

    XMEMCPY(output, seqArray, seqSz);
    XMEMCPY(output + seqSz, ID_Length, idSz);
    XMEMCPY(output + seqSz + idSz, algoName, algoSz);

    return seqSz + idSz + algoSz;

}


/* Write a public RSA key to output */
static int SetRsaPublicKey(byte* output, RsaKey* key,
                           int outLen, int with_header)
{
#ifdef WOLFSSL_SMALL_STACK
    byte* n = NULL;
    byte* e = NULL;
#else
    byte n[MAX_RSA_INT_SZ];
    byte e[MAX_RSA_E_SZ];
#endif
    byte seq[MAX_SEQ_SZ];
    byte len[MAX_LENGTH_SZ + 1];  /* trailing 0 */
    int  nSz;
    int  eSz;
    int  seqSz;
    int  lenSz;
    int  idx;
    int  rawLen;
    int  leadingBit;
    int  err;

    if (output == NULL || key == NULL || outLen < MAX_SEQ_SZ)
        return USER_CRYPTO_ERROR;

    /* n */
#ifdef WOLFSSL_SMALL_STACK
    n = (byte*)XMALLOC(MAX_RSA_INT_SZ, NULL, DYNAMIC_TYPE_USER_CRYPTO);
    if (n == NULL)
        return USER_CRYPTO_ERROR;
#endif

    if (ippsExtGet_BN(NULL, &rawLen, NULL, key->n) != ippStsNoErr)
        return USER_CRYPTO_ERROR;
    leadingBit = rawLen % 8; /* check for if an extra byte is needed */
    rawLen = rawLen/8;       /* convert to byte size */
    rawLen = rawLen + leadingBit;
    n[0] = ASN_INTEGER;
    nSz  = SetLength(rawLen, n + 1) + 1;  /* int tag */

    if ( (nSz + rawLen) < MAX_RSA_INT_SZ) {
        if (leadingBit)
            n[nSz] = 0;
        err = ippsGetOctString_BN((Ipp8u*)n + nSz, rawLen, key->n);
        if (err == ippStsNoErr)
            nSz += rawLen;
        else {
#ifdef WOLFSSL_SMALL_STACK
            XFREE(n, NULL, DYNAMIC_TYPE_USER_CRYPTO);
#endif
            return USER_CRYPTO_ERROR;
        }
    }
    else {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(n, NULL, DYNAMIC_TYPE_USER_CRYPTO);
#endif
        return USER_CRYPTO_ERROR;
    }

    /* e */
#ifdef WOLFSSL_SMALL_STACK
    e = (byte*)XMALLOC(MAX_RSA_E_SZ, NULL, DYNAMIC_TYPE_USER_CRYPTO);
    if (e == NULL) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(n, NULL, DYNAMIC_TYPE_USER_CRYPTO);
#endif
        return USER_CRYPTO_ERROR;
    }
#endif

    if (ippsExtGet_BN(NULL, &rawLen, NULL, key->e) != ippStsNoErr)
        return USER_CRYPTO_ERROR;
    leadingBit = rawLen % 8;
    rawLen = rawLen/8;
    rawLen = rawLen + leadingBit;
    e[0] = ASN_INTEGER;
    eSz  = SetLength(rawLen, e + 1) + 1;  /* int tag */

    if ( (eSz + rawLen) < MAX_RSA_E_SZ) {
        if (leadingBit)
            e[eSz] = 0;
        err = ippsGetOctString_BN((Ipp8u*)e + eSz, rawLen, key->e);
        if (err == ippStsNoErr)
            eSz += rawLen;
        else {
#ifdef WOLFSSL_SMALL_STACK
            XFREE(n, NULL, DYNAMIC_TYPE_USER_CRYPTO);
            XFREE(e, NULL, DYNAMIC_TYPE_USER_CRYPTO);
#endif
            return USER_CRYPTO_ERROR;
        }
    }
    else {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(n, NULL, DYNAMIC_TYPE_USER_CRYPTO);
        XFREE(e, NULL, DYNAMIC_TYPE_USER_CRYPTO);
#endif
        return USER_CRYPTO_ERROR;
    }

    seqSz  = SetSequence(nSz + eSz, seq);

    /* check output size */
    if ( (seqSz + nSz + eSz) > outLen) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(n,    NULL, DYNAMIC_TYPE_USER_CRYPTO);
        XFREE(e,    NULL, DYNAMIC_TYPE_USER_CRYPTO);
#endif
        return USER_CRYPTO_ERROR;
    }

    /* headers */
    if (with_header) {
        int  algoSz;
#ifdef WOLFSSL_SMALL_STACK
        byte* algo = NULL;

        algo = (byte*)XMALLOC(MAX_ALGO_SZ, NULL, DYNAMIC_TYPE_USER_CRYPTO);
        if (algo == NULL) {
            XFREE(n, NULL, DYNAMIC_TYPE_USER_CRYPTO);
            XFREE(e, NULL, DYNAMIC_TYPE_USER_CRYPTO);
            return USER_CRYPTO_ERROR;
        }
#else
        byte algo[MAX_ALGO_SZ];
#endif
        algoSz = SetAlgoID(RSAk, algo, keyType, 0);
        lenSz  = SetLength(seqSz + nSz + eSz + 1, len);
        len[lenSz++] = 0;   /* trailing 0 */

        /* write, 1 is for ASN_BIT_STRING */
        idx = SetSequence(nSz + eSz + seqSz + lenSz + 1 + algoSz, output);

        /* check output size */
        if ( (idx + algoSz + 1 + lenSz + seqSz + nSz + eSz) > outLen) {
            #ifdef WOLFSSL_SMALL_STACK
                XFREE(n,    NULL, DYNAMIC_TYPE_USER_CRYPTO);
                XFREE(e,    NULL, DYNAMIC_TYPE_USER_CRYPTO);
                XFREE(algo, NULL, DYNAMIC_TYPE_USER_CRYPTO);
            #endif

            return USER_CRYPTO_ERROR;
        }

        /* algo */
        XMEMCPY(output + idx, algo, algoSz);
        idx += algoSz;
        /* bit string */
        output[idx++] = ASN_BIT_STRING;
        /* length */
        XMEMCPY(output + idx, len, lenSz);
        idx += lenSz;
#ifdef WOLFSSL_SMALL_STACK
        XFREE(algo, NULL, DYNAMIC_TYPE_USER_CRYPTO);
#endif
    }
    else
        idx = 0;

    /* seq */
    XMEMCPY(output + idx, seq, seqSz);
    idx += seqSz;
    /* n */
    XMEMCPY(output + idx, n, nSz);
    idx += nSz;
    /* e */
    XMEMCPY(output + idx, e, eSz);
    idx += eSz;

#ifdef WOLFSSL_SMALL_STACK
    XFREE(n,    NULL, DYNAMIC_TYPE_USER_CRYPTO);
    XFREE(e,    NULL, DYNAMIC_TYPE_USER_CRYPTO);
#endif

    return idx;
}


static IppsBigNumState* GetRsaInt(RsaKey* key, int idx)
{
    if (idx == 0)
        return key->n;
    if (idx == 1)
        return key->e;
    if (idx == 2)
        return key->dipp;
    if (idx == 3)
        return key->pipp;
    if (idx == 4)
        return key->qipp;
    if (idx == 5)
        return key->dPipp;
    if (idx == 6)
        return key->dQipp;
    if (idx == 7)
        return key->uipp;

    return NULL;
}


/* Release Tmp RSA resources */
static INLINE void FreeTmpRsas(byte** tmps, void* heap)
{
    int i;

    (void)heap;

    for (i = 0; i < RSA_INTS; i++)
        XFREE(tmps[i], heap, DYNAMIC_TYPE_USER_CRYPTO);
}


/* Convert RsaKey key to DER format, write to output (inLen), return bytes
   written */
int wc_RsaKeyToDer(RsaKey* key, byte* output, word32 inLen)
{
    word32 seqSz, verSz, rawLen, intTotalLen = 0;
    word32 sizes[RSA_INTS];
    int    i, j, outLen, ret = 0, lbit;

    byte  seq[MAX_SEQ_SZ];
    byte  ver[MAX_VERSION_SZ];
    byte* tmps[RSA_INTS];

    USER_DEBUG(("Entering RsaKeyToDer\n"));

    if (!key || !output)
        return USER_CRYPTO_ERROR;

    if (key->type != RSA_PRIVATE)
        return USER_CRYPTO_ERROR;

    for (i = 0; i < RSA_INTS; i++)
        tmps[i] = NULL;

    /* write all big ints from key to DER tmps */
    for (i = 0; i < RSA_INTS; i++) {
        Ipp32u isZero;
        IppsBigNumState* keyInt = GetRsaInt(key, i);

        /* leading zero */
        ippsCmpZero_BN(keyInt, &isZero); /* makes isZero 0 if true */
        ippsExtGet_BN(NULL, (int*)&rawLen, NULL, keyInt); /* bit length */
        if (rawLen % 8 || !isZero)
            lbit = 1;
        else
            lbit = 0;

        rawLen /= 8; /* convert to bytes */
        rawLen += lbit;

        tmps[i] = (byte*)XMALLOC(rawLen + MAX_SEQ_SZ, key->heap,
                                 DYNAMIC_TYPE_USER_CRYPTO);
        if (tmps[i] == NULL) {
            ret = USER_CRYPTO_ERROR;
            break;
        }

        tmps[i][0] = ASN_INTEGER;
        sizes[i] = SetLength(rawLen, tmps[i] + 1) + 1 + lbit; /* tag & lbit */

        if (sizes[i] <= MAX_SEQ_SZ) {
            int err;

            /* leading zero */
            if (lbit)
                tmps[i][sizes[i]-1] = 0x00;

            /* extract data*/
            err = ippsGetOctString_BN((Ipp8u*)(tmps[i] + sizes[i]),
                    rawLen, keyInt);
            if (err == ippStsOk) {
                sizes[i] += (rawLen-lbit); /* lbit included in rawLen */
                intTotalLen += sizes[i];
                ret = 0;
            }
            else {
                ret = USER_CRYPTO_ERROR;
                break;
            }
        }
        else {
            ret = USER_CRYPTO_ERROR;
            break;
        }
    }

    if (ret != 0) {
        FreeTmpRsas(tmps, key->heap);
        return ret;
    }

    /* make headers */
    verSz = SetMyVersion(0, ver, FALSE);
    seqSz = SetSequence(verSz + intTotalLen, seq);

    outLen = seqSz + verSz + intTotalLen;
    if (outLen > (int)inLen) {
        return USER_CRYPTO_ERROR;
    }

    /* write to output */
    XMEMCPY(output, seq, seqSz);
    j = seqSz;
    XMEMCPY(output + j, ver, verSz);
    j += verSz;

    for (i = 0; i < RSA_INTS; i++) {
        XMEMCPY(output + j, tmps[i], sizes[i]);
        j += sizes[i];
    }
    FreeTmpRsas(tmps, key->heap);

    return outLen;
}


/* Convert Rsa Public key to DER format, write to output (inLen), return bytes
   written
*/
int wc_RsaKeyToPublicDer(RsaKey* key, byte* output, word32 inLen)
{
    return SetRsaPublicKey(output, key, inLen, 1);
}


#endif /* WOLFSSL_KEY_GEN */

#endif /* NO_RSA */

