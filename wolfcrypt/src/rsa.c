/* rsa.c
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


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifndef NO_RSA

#include <wolfssl/wolfcrypt/rsa.h>

/*
Possible RSA enable options:
 * NO_RSA:              Overall control of RSA                      default: on (not defined)
 * WC_RSA_BLINDING:     Uses Blinding w/ Private Ops                default: off
                        Note: slower by ~20%
 * WOLFSSL_KEY_GEN:     Allows Private Key Generation               default: off
 * RSA_LOW_MEM:         NON CRT Private Operations, less memory     default: off
 * WC_NO_RSA_OAEP:      Disables RSA OAEP padding                   default: on (not defined)

*/

/*
RSA Key Size Configuration:
 * FP_MAX_BITS:         With USE_FAST_MATH only                     default: 4096
    If USE_FAST_MATH then use this to override default.
    Value is key size * 2. Example: RSA 3072 = 6144
*/


#ifdef HAVE_FIPS
int  wc_InitRsaKey(RsaKey* key, void* ptr)
{
    return InitRsaKey_fips(key, ptr);
}

int  wc_InitRsaKey_ex(RsaKey* key, void* ptr, int devId)
{
    (void)devId;
    return InitRsaKey_fips(key, ptr);
}

int  wc_FreeRsaKey(RsaKey* key)
{
    return FreeRsaKey_fips(key);
}


int  wc_RsaPublicEncrypt(const byte* in, word32 inLen, byte* out,
                                 word32 outLen, RsaKey* key, WC_RNG* rng)
{
    return RsaPublicEncrypt_fips(in, inLen, out, outLen, key, rng);
}


int  wc_RsaPrivateDecryptInline(byte* in, word32 inLen, byte** out,
                                        RsaKey* key)
{
    return RsaPrivateDecryptInline_fips(in, inLen, out, key);
}


int  wc_RsaPrivateDecrypt(const byte* in, word32 inLen, byte* out,
                                  word32 outLen, RsaKey* key)
{
    return RsaPrivateDecrypt_fips(in, inLen, out, outLen, key);
}


int  wc_RsaSSL_Sign(const byte* in, word32 inLen, byte* out,
                            word32 outLen, RsaKey* key, WC_RNG* rng)
{
    return RsaSSL_Sign_fips(in, inLen, out, outLen, key, rng);
}


int  wc_RsaSSL_VerifyInline(byte* in, word32 inLen, byte** out, RsaKey* key)
{
    return RsaSSL_VerifyInline_fips(in, inLen, out, key);
}


int  wc_RsaSSL_Verify(const byte* in, word32 inLen, byte* out,
                              word32 outLen, RsaKey* key)
{
    return RsaSSL_Verify_fips(in, inLen, out, outLen, key);
}


int  wc_RsaEncryptSize(RsaKey* key)
{
    return RsaEncryptSize_fips(key);
}


int wc_RsaFlattenPublicKey(RsaKey* key, byte* a, word32* aSz, byte* b,
                           word32* bSz)
{
    /* not specified as fips so not needing _fips */
    return RsaFlattenPublicKey(key, a, aSz, b, bSz);
}
#ifdef WOLFSSL_KEY_GEN
    int wc_MakeRsaKey(RsaKey* key, int size, long e, WC_RNG* rng)
    {
        return MakeRsaKey(key, size, e, rng);
    }
#endif


/* these are functions in asn and are routed to wolfssl/wolfcrypt/asn.c
* wc_RsaPrivateKeyDecode
* wc_RsaPublicKeyDecode
*/

#else /* else build without fips */

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#define ERROR_OUT(x) { ret = (x); goto done;}


#ifdef WOLFSSL_ASYNC_CRYPT
    static int InitAsyncRsaKey(RsaKey* key);
    static int FreeAsyncRsaKey(RsaKey* key);
#endif /* WOLFSSL_ASYNC_CRYPT */

enum {
    RSA_STATE_NONE = 0,

    RSA_STATE_ENCRYPT_PAD,
    RSA_STATE_ENCRYPT_EXPTMOD,
    RSA_STATE_ENCRYPT_RES,

    RSA_STATE_DECRYPT_EXPTMOD,
    RSA_STATE_DECRYPT_UNPAD,
    RSA_STATE_DECRYPT_RES,
};

static void wc_RsaCleanup(RsaKey* key)
{
    if (key && key->tmp) {
        /* make sure any allocated memory is free'd */
        if (key->tmpIsAlloc) {
            if (key->type == RSA_PRIVATE_DECRYPT ||
                key->type == RSA_PRIVATE_ENCRYPT) {
                ForceZero(key->tmp, key->tmpLen);
            }
            XFREE(key->tmp, key->heap, DYNAMIC_TYPE_RSA);
            key->tmpIsAlloc = 0;
        }
        key->tmp = NULL;
        key->tmpLen = 0;
    }
}

int wc_InitRsaKey_ex(RsaKey* key, void* heap, int devId)
{
    int ret = 0;

    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    (void)devId;

    key->type = RSA_TYPE_UNKNOWN;
    key->state = RSA_STATE_NONE;
    key->heap = heap;
    key->tmp = NULL;
    key->tmpLen = 0;
    key->tmpIsAlloc = 0;
#ifdef WC_RSA_BLINDING
    key->rng = NULL;
#endif

#ifdef WOLFSSL_ASYNC_CRYPT
    if (devId != INVALID_DEVID) {
        /* handle as async */
        ret = wolfAsync_DevCtxInit(&key->asyncDev, WOLFSSL_ASYNC_MARKER_RSA,
                                                                        devId);
        if (ret == 0) {
            ret = InitAsyncRsaKey(key);
        }
    }
    else
#endif
    {
    /* For normal math defer the memory allocations */
    #ifndef USE_FAST_MATH
        key->n.dp = key->e.dp = 0;  /* public  alloc parts */
        key->d.dp = key->p.dp  = 0; /* private alloc parts */
        key->q.dp = key->dP.dp = 0;
        key->u.dp = key->dQ.dp = 0;
    #else
        mp_init(&key->n);
        mp_init(&key->e);
        mp_init(&key->d);
        mp_init(&key->p);
        mp_init(&key->q);
        mp_init(&key->dP);
        mp_init(&key->dQ);
        mp_init(&key->u);
    #endif /* USE_FAST_MATH */
    }

    return ret;
}

int wc_InitRsaKey(RsaKey* key, void* heap)
{
    return wc_InitRsaKey_ex(key, heap, INVALID_DEVID);
}

int wc_FreeRsaKey(RsaKey* key)
{
    int ret = 0;

    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    wc_RsaCleanup(key);

#ifdef WOLFSSL_ASYNC_CRYPT
    if (key->asyncDev.marker == WOLFSSL_ASYNC_MARKER_RSA) {
        ret = FreeAsyncRsaKey(key);
        wolfAsync_DevCtxFree(&key->asyncDev);
    }
    else
#endif
    {
        if (key->type == RSA_PRIVATE) {
            mp_forcezero(&key->u);
            mp_forcezero(&key->dQ);
            mp_forcezero(&key->dP);
            mp_forcezero(&key->q);
            mp_forcezero(&key->p);
            mp_forcezero(&key->d);
        }
        mp_clear(&key->e);
        mp_clear(&key->n);
    }

    return ret;
}


#ifndef WC_NO_RSA_OAEP
/* Uses MGF1 standard as a mask generation function
   hType: hash type used
   seed:  seed to use for generating mask
   seedSz: size of seed buffer
   out:   mask output after generation
   outSz: size of output buffer
 */
static int RsaMGF1(enum wc_HashType hType, byte* seed, word32 seedSz,
                                        byte* out, word32 outSz, void* heap)
{
    byte* tmp;
    /* needs to be large enough for seed size plus counter(4) */
    byte  tmpA[WC_MAX_DIGEST_SIZE + 4];
    byte   tmpF;     /* 1 if dynamic memory needs freed */
    word32 tmpSz;
    int hLen;
    int ret;
    word32 counter;
    word32 idx;
    hLen    = wc_HashGetDigestSize(hType);
    counter = 0;
    idx     = 0;

    (void)heap;

    /* check error return of wc_HashGetDigestSize */
    if (hLen < 0) {
        return hLen;
    }

    /* if tmp is not large enough than use some dynamic memory */
    if ((seedSz + 4) > sizeof(tmpA) || (word32)hLen > sizeof(tmpA)) {
        /* find largest amount of memory needed which will be the max of
         * hLen and (seedSz + 4) since tmp is used to store the hash digest */
        tmpSz = ((seedSz + 4) > (word32)hLen)? seedSz + 4: (word32)hLen;
        tmp = (byte*)XMALLOC(tmpSz, heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (tmp == NULL) {
            return MEMORY_E;
        }
        tmpF = 1; /* make sure to free memory when done */
    }
    else {
        /* use array on the stack */
        tmpSz = sizeof(tmpA);
        tmp  = tmpA;
        tmpF = 0; /* no need to free memory at end */
    }

    do {
        int i = 0;
        XMEMCPY(tmp, seed, seedSz);

        /* counter to byte array appended to tmp */
        tmp[seedSz]     = (counter >> 24) & 0xFF;
        tmp[seedSz + 1] = (counter >> 16) & 0xFF;
        tmp[seedSz + 2] = (counter >>  8) & 0xFF;
        tmp[seedSz + 3] = (counter)       & 0xFF;

        /* hash and append to existing output */
        if ((ret = wc_Hash(hType, tmp, (seedSz + 4), tmp, tmpSz)) != 0) {
            /* check for if dynamic memory was needed, then free */
            if (tmpF) {
                XFREE(tmp, heap, DYNAMIC_TYPE_TMP_BUFFER);
            }
            return ret;
        }

        for (i = 0; i < hLen && idx < outSz; i++) {
            out[idx++] = tmp[i];
        }
        counter++;
    } while (idx < outSz);

    /* check for if dynamic memory was needed, then free */
    if (tmpF) {
        XFREE(tmp, heap, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return 0;
}

/* helper function to direct which mask generation function is used
   switeched on type input
 */
static int RsaMGF(int type, byte* seed, word32 seedSz, byte* out,
                                                    word32 outSz, void* heap)
{
    int ret;

    switch(type) {
    #ifndef NO_SHA
        case WC_MGF1SHA1:
            ret = RsaMGF1(WC_HASH_TYPE_SHA, seed, seedSz, out, outSz, heap);
            break;
    #endif
    #ifndef NO_SHA256
    #ifdef WOLFSSL_SHA224
        case WC_MGF1SHA224:
            ret = RsaMGF1(WC_HASH_TYPE_SHA224, seed, seedSz, out, outSz, heap);
            break;
    #endif
        case WC_MGF1SHA256:
            ret = RsaMGF1(WC_HASH_TYPE_SHA256, seed, seedSz, out, outSz, heap);
            break;
    #endif
    #ifdef WOLFSSL_SHA512
    #ifdef WOLFSSL_SHA384
        case WC_MGF1SHA384:
            ret = RsaMGF1(WC_HASH_TYPE_SHA384, seed, seedSz, out, outSz, heap);
            break;
    #endif
        case WC_MGF1SHA512:
            ret = RsaMGF1(WC_HASH_TYPE_SHA512, seed, seedSz, out, outSz, heap);
            break;
    #endif
        default:
            WOLFSSL_MSG("Unknown MGF type: check build options");
            ret = BAD_FUNC_ARG;
    }

    /* in case of default avoid unused warning */
    (void)seed;
    (void)seedSz;
    (void)out;
    (void)outSz;
    (void)heap;

    return ret;
}
#endif /* !WC_NO_RSA_OAEP */


/* Padding */
#ifndef WC_NO_RSA_OAEP
static int RsaPad_OAEP(const byte* input, word32 inputLen, byte* pkcsBlock,
        word32 pkcsBlockLen, byte padValue, WC_RNG* rng,
        enum wc_HashType hType, int mgf, byte* optLabel, word32 labelLen,
        void* heap)
{
    int ret;
    int hLen;
    int psLen;
    int i;
    word32 idx;

    byte* dbMask;

    #ifdef WOLFSSL_SMALL_STACK
        byte* lHash = NULL;
        byte* seed  = NULL;
    #else
        /* must be large enough to contain largest hash */
        byte lHash[WC_MAX_DIGEST_SIZE];
        byte seed[ WC_MAX_DIGEST_SIZE];
    #endif

    /* no label is allowed, but catch if no label provided and length > 0 */
    if (optLabel == NULL && labelLen > 0) {
        return BUFFER_E;
    }

    /* limit of label is the same as limit of hash function which is massive */
    hLen = wc_HashGetDigestSize(hType);
    if (hLen < 0) {
        return hLen;
    }

    #ifdef WOLFSSL_SMALL_STACK
        lHash = (byte*)XMALLOC(hLen, heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (lHash == NULL) {
            return MEMORY_E;
        }
        seed = (byte*)XMALLOC(hLen, heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (seed == NULL) {
            XFREE(lHash, heap, DYNAMIC_TYPE_TMP_BUFFER);
            return MEMORY_E;
        }
    #else
        /* hLen should never be larger than lHash since size is max digest size,
           but check before blindly calling wc_Hash */
        if ((word32)hLen > sizeof(lHash)) {
            WOLFSSL_MSG("OAEP lHash to small for digest!!");
            return MEMORY_E;
        }
    #endif

    if ((ret = wc_Hash(hType, optLabel, labelLen, lHash, hLen)) != 0) {
        WOLFSSL_MSG("OAEP hash type possibly not supported or lHash to small");
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(lHash, heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(seed,  heap, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
        return ret;
    }

    /* handles check of location for idx as well as psLen, cast to int to check
       for pkcsBlockLen(k) - 2 * hLen - 2 being negative
       This check is similar to decryption where k > 2 * hLen + 2 as msg
       size aproaches 0. In decryption if k is less than or equal -- then there
       is no possible room for msg.
       k = RSA key size
       hLen = hash digest size -- will always be >= 0 at this point
     */
    if ((word32)(2 * hLen + 2) > pkcsBlockLen) {
        WOLFSSL_MSG("OAEP pad error hash to big for RSA key size");
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(lHash, heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(seed,  heap, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
        return BAD_FUNC_ARG;
    }

    if (inputLen > (pkcsBlockLen - 2 * hLen - 2)) {
        WOLFSSL_MSG("OAEP pad error message too long");
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(lHash, heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(seed,  heap, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
        return BAD_FUNC_ARG;
    }

    /* concatenate lHash || PS || 0x01 || msg */
    idx = pkcsBlockLen - 1 - inputLen;
    psLen = pkcsBlockLen - inputLen - 2 * hLen - 2;
    if (pkcsBlockLen < inputLen) { /*make sure not writing over end of buffer */
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(lHash, heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(seed,  heap, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
        return BUFFER_E;
    }
    XMEMCPY(pkcsBlock + (pkcsBlockLen - inputLen), input, inputLen);
    pkcsBlock[idx--] = 0x01; /* PS and M separator */
    while (psLen > 0 && idx > 0) {
        pkcsBlock[idx--] = 0x00;
        psLen--;
    }

    idx = idx - hLen + 1;
    XMEMCPY(pkcsBlock + idx, lHash, hLen);

    /* generate random seed */
    if ((ret = wc_RNG_GenerateBlock(rng, seed, hLen)) != 0) {
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(lHash, heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(seed,  heap, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
        return ret;
    }

    /* create maskedDB from dbMask */
    dbMask = (byte*)XMALLOC(pkcsBlockLen - hLen - 1, heap, DYNAMIC_TYPE_RSA);
    if (dbMask == NULL) {
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(lHash, heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(seed,  heap, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
        return MEMORY_E;
    }
    XMEMSET(dbMask, 0, pkcsBlockLen - hLen - 1); /* help static analyzer */

    ret = RsaMGF(mgf, seed, hLen, dbMask, pkcsBlockLen - hLen - 1, heap);
    if (ret != 0) {
        XFREE(dbMask, heap, DYNAMIC_TYPE_RSA);
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(lHash, heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(seed,  heap, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
        return ret;
    }

    i = 0;
    idx = hLen + 1;
    while (idx < pkcsBlockLen && (word32)i < (pkcsBlockLen - hLen -1)) {
        pkcsBlock[idx] = dbMask[i++] ^ pkcsBlock[idx];
        idx++;
    }
    XFREE(dbMask, heap, DYNAMIC_TYPE_RSA);


    /* create maskedSeed from seedMask */
    idx = 0;
    pkcsBlock[idx++] = 0x00;
    /* create seedMask inline */
    if ((ret = RsaMGF(mgf, pkcsBlock + hLen + 1, pkcsBlockLen - hLen - 1,
                                           pkcsBlock + 1, hLen, heap)) != 0) {
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(lHash, heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(seed,  heap, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
        return ret;
    }

    /* xor created seedMask with seed to make maskedSeed */
    i = 0;
    while (idx < (word32)(hLen + 1) && i < hLen) {
        pkcsBlock[idx] = pkcsBlock[idx] ^ seed[i++];
        idx++;
    }

    #ifdef WOLFSSL_SMALL_STACK
        XFREE(lHash, heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(seed,  heap, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
    (void)padValue;

    return 0;
}
#endif /* !WC_NO_RSA_OAEP */


static int RsaPad(const byte* input, word32 inputLen, byte* pkcsBlock,
                           word32 pkcsBlockLen, byte padValue, WC_RNG* rng)
{
    if (input == NULL || inputLen == 0 || pkcsBlock == NULL ||
                                                        pkcsBlockLen == 0) {
        return BAD_FUNC_ARG;
    }

    pkcsBlock[0] = 0x0;       /* set first byte to zero and advance */
    pkcsBlock++; pkcsBlockLen--;
    pkcsBlock[0] = padValue;  /* insert padValue */

    if (padValue == RSA_BLOCK_TYPE_1) {
        if (pkcsBlockLen < inputLen + 2) {
            WOLFSSL_MSG("RsaPad error, invalid length");
            return RSA_PAD_E;
        }

        /* pad with 0xff bytes */
        XMEMSET(&pkcsBlock[1], 0xFF, pkcsBlockLen - inputLen - 2);
    }
    else {
        /* pad with non-zero random bytes */
        word32 padLen, i;
        int    ret;

        if (pkcsBlockLen < inputLen + 1) {
            WOLFSSL_MSG("RsaPad error, invalid length");
            return RSA_PAD_E;
        }

        padLen = pkcsBlockLen - inputLen - 1;
        ret    = wc_RNG_GenerateBlock(rng, &pkcsBlock[1], padLen);
        if (ret != 0) {
            return ret;
        }

        /* remove zeros */
        for (i = 1; i < padLen; i++) {
            if (pkcsBlock[i] == 0) pkcsBlock[i] = 0x01;
        }
    }

    pkcsBlock[pkcsBlockLen-inputLen-1] = 0;     /* separator */
    XMEMCPY(pkcsBlock+pkcsBlockLen-inputLen, input, inputLen);

    return 0;
}

/* helper function to direct which padding is used */
static int wc_RsaPad_ex(const byte* input, word32 inputLen, byte* pkcsBlock,
    word32 pkcsBlockLen, byte padValue, WC_RNG* rng, int padType,
    enum wc_HashType hType, int mgf, byte* optLabel, word32 labelLen,
    void* heap)
{
    int ret;

    switch (padType)
    {
        case WC_RSA_PKCSV15_PAD:
            //WOLFSSL_MSG("wolfSSL Using RSA PKCSV15 padding");
            ret = RsaPad(input, inputLen, pkcsBlock, pkcsBlockLen,
                                                             padValue, rng);
            break;

    #ifndef WC_NO_RSA_OAEP
        case WC_RSA_OAEP_PAD:
            //WOLFSSL_MSG("wolfSSL Using RSA OAEP padding");
            ret = RsaPad_OAEP(input, inputLen, pkcsBlock, pkcsBlockLen,
                         padValue, rng, hType, mgf, optLabel, labelLen, heap);
            break;
    #endif
        default:
            WOLFSSL_MSG("Unknown RSA Pad Type");
            ret = RSA_PAD_E;
    }

    /* silence warning if not used with padding scheme */
    (void)hType;
    (void)mgf;
    (void)optLabel;
    (void)labelLen;
    (void)heap;

    return ret;
}


/* UnPadding */
#ifndef WC_NO_RSA_OAEP
/* UnPad plaintext, set start to *output, return length of plaintext,
 * < 0 on error */
static int RsaUnPad_OAEP(byte *pkcsBlock, unsigned int pkcsBlockLen,
                            byte **output, enum wc_HashType hType, int mgf,
                            byte* optLabel, word32 labelLen, void* heap)
{
    int hLen;
    int ret;
    byte h[WC_MAX_DIGEST_SIZE]; /* max digest size */
    byte* tmp;
    word32 idx;

    /* no label is allowed, but catch if no label provided and length > 0 */
    if (optLabel == NULL && labelLen > 0) {
        return BUFFER_E;
    }

    hLen = wc_HashGetDigestSize(hType);
    if ((hLen < 0) || (pkcsBlockLen < (2 * (word32)hLen + 2))) {
        return BAD_FUNC_ARG;
    }

    tmp = (byte*)XMALLOC(pkcsBlockLen, heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (tmp == NULL) {
        return MEMORY_E;
    }
    XMEMSET(tmp, 0, pkcsBlockLen);

    /* find seedMask value */
    if ((ret = RsaMGF(mgf, (byte*)(pkcsBlock + (hLen + 1)),
                            pkcsBlockLen - hLen - 1, tmp, hLen, heap)) != 0) {
        XFREE(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    /* xor seedMask value with maskedSeed to get seed value */
    for (idx = 0; idx < (word32)hLen; idx++) {
        tmp[idx] = tmp[idx] ^ pkcsBlock[1 + idx];
    }

    /* get dbMask value */
    if ((ret = RsaMGF(mgf, tmp, hLen, tmp + hLen,
                                       pkcsBlockLen - hLen - 1, heap)) != 0) {
        XFREE(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    /* get DB value by doing maskedDB xor dbMask */
    for (idx = 0; idx < (pkcsBlockLen - hLen - 1); idx++) {
        pkcsBlock[hLen + 1 + idx] = pkcsBlock[hLen + 1 + idx] ^ tmp[idx + hLen];
    }

    /* done with use of tmp buffer */
    XFREE(tmp, heap, DYNAMIC_TYPE_TMP_BUFFER);

    /* advance idx to index of PS and msg separator, account for PS size of 0*/
    idx = hLen + 1 + hLen;
    while (idx < pkcsBlockLen && pkcsBlock[idx] == 0) {idx++;}

    /* create hash of label for comparision with hash sent */
    if ((ret = wc_Hash(hType, optLabel, labelLen, h, hLen)) != 0) {
        return ret;
    }

    /* say no to chosen ciphertext attack.
       Comparison of lHash, Y, and separator value needs to all happen in
       constant time.
       Attackers should not be able to get error condition from the timing of
       these checks.
     */
    ret = 0;
    ret |= ConstantCompare(pkcsBlock + hLen + 1, h, hLen);
    ret += pkcsBlock[idx++] ^ 0x01; /* separator value is 0x01 */
    ret += pkcsBlock[0]     ^ 0x00; /* Y, the first value, should be 0 */

    if (ret != 0) {
        return BAD_PADDING_E;
    }

    /* adjust pointer to correct location in array and return size of M */
    *output = (byte*)(pkcsBlock + idx);
    return pkcsBlockLen - idx;
}
#endif /* WC_NO_RSA_OAEP */


/* UnPad plaintext, set start to *output, return length of plaintext,
 * < 0 on error */
static int RsaUnPad(const byte *pkcsBlock, unsigned int pkcsBlockLen,
                                               byte **output, byte padValue)
{
    word32 maxOutputLen = (pkcsBlockLen > 10) ? (pkcsBlockLen - 10) : 0;
    word32 invalid = 0;
    word32 i = 1;
    word32 outputLen;

    if (output == NULL || pkcsBlockLen == 0) {
        return BAD_FUNC_ARG;
    }

    if (pkcsBlock[0] != 0x0) { /* skip past zero */
        invalid = 1;
    }
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
        WOLFSSL_MSG("RsaUnPad error, bad formatting");
        return RSA_PAD_E;
    }

    outputLen = pkcsBlockLen - i;
    invalid = (outputLen > maxOutputLen) || invalid;

    if (invalid) {
        WOLFSSL_MSG("RsaUnPad error, bad formatting");
        return RSA_PAD_E;
    }

    *output = (byte *)(pkcsBlock + i);
    return outputLen;
}

/* helper function to direct unpadding */
static int wc_RsaUnPad_ex(byte* pkcsBlock, word32 pkcsBlockLen, byte** out,
                          byte padValue, int padType, enum wc_HashType hType,
                          int mgf, byte* optLabel, word32 labelLen, void* heap)
{
    int ret;

    switch (padType)
    {
        case WC_RSA_PKCSV15_PAD:
            WOLFSSL_MSG("wolfSSL Using RSA PKCSV15 padding");
            ret = RsaUnPad(pkcsBlock, pkcsBlockLen, out, padValue);
            break;

    #ifndef WC_NO_RSA_OAEP
        case WC_RSA_OAEP_PAD:
            WOLFSSL_MSG("wolfSSL Using RSA OAEP padding");
            ret = RsaUnPad_OAEP((byte*)pkcsBlock, pkcsBlockLen, out,
                                        hType, mgf, optLabel, labelLen, heap);
            break;
    #endif

        default:
            WOLFSSL_MSG("Unknown RSA UnPad Type");
            ret = RSA_PAD_E;
    }

    /* silence warning if not used with padding scheme */
    (void)hType;
    (void)mgf;
    (void)optLabel;
    (void)labelLen;
    (void)heap;

    return ret;
}


#ifdef WC_RSA_BLINDING

/* helper for either lib */
static int get_digit_count(mp_int* a)
{
    if (a == NULL)
        return 0;

    return a->used;
}


static int get_rand_digit(WC_RNG* rng, mp_digit* d)
{
    return wc_RNG_GenerateBlock(rng, (byte*)d, sizeof(mp_digit));
}


static int mp_rand(mp_int* a, int digits, WC_RNG* rng)
{
    int ret;
    mp_digit d;

    if (rng == NULL)
        return MISSING_RNG_E;

    if (a == NULL)
        return BAD_FUNC_ARG;

    mp_zero(a);
    if (digits <= 0) {
        return MP_OKAY;
    }

    /* first place a random non-zero digit */
    do {
        ret = get_rand_digit(rng, &d);
        if (ret != 0) {
            return ret;
        }
    } while (d == 0);

    if ((ret = mp_add_d(a, d, a)) != MP_OKAY) {
        return ret;
    }

    while (--digits > 0) {
        if ((ret = mp_lshd(a, 1)) != MP_OKAY) {
            return ret;
        }
        if ((ret = get_rand_digit(rng, &d)) != 0) {
            return ret;
        }
        if ((ret = mp_add_d(a, d, a)) != MP_OKAY) {
            return ret;
        }
    }

    return ret;
}


#endif /* WC_RSA_BLINGING */


static int wc_RsaFunctionSync(const byte* in, word32 inLen, byte* out,
                          word32* outLen, int type, RsaKey* key, WC_RNG* rng)
{
    mp_int tmp;
#ifdef WC_RSA_BLINDING
    mp_int rnd, rndi;
#endif
    int    ret = 0;
    word32 keyLen, len;

    (void)rng;

    if (mp_init(&tmp) != MP_OKAY)
        return MP_INIT_E;

#ifdef WC_RSA_BLINDING
    if (type == RSA_PRIVATE_DECRYPT || type == RSA_PRIVATE_ENCRYPT) {
        if (mp_init_multi(&rnd, &rndi, NULL, NULL, NULL, NULL) != MP_OKAY) {
            mp_clear(&tmp);
            return MP_INIT_E;
        }
    }
#endif

    if (mp_read_unsigned_bin(&tmp, (byte*)in, inLen) != MP_OKAY)
        ERROR_OUT(MP_READ_E);

    switch(type) {
    case RSA_PRIVATE_DECRYPT:
    case RSA_PRIVATE_ENCRYPT:
    {
    #ifdef WC_RSA_BLINDING
        /* blind */
        ret = mp_rand(&rnd, get_digit_count(&key->n), rng);
        if (ret != MP_OKAY)
            ERROR_OUT(ret);

        /* rndi = 1/rnd mod n */
        if (mp_invmod(&rnd, &key->n, &rndi) != MP_OKAY)
            ERROR_OUT(MP_INVMOD_E);

        /* rnd = rnd^e */
        if (mp_exptmod(&rnd, &key->e, &key->n, &rnd) != MP_OKAY)
            ERROR_OUT(MP_EXPTMOD_E);

        /* tmp = tmp*rnd mod n */
        if (mp_mulmod(&tmp, &rnd, &key->n, &tmp) != MP_OKAY)
            ERROR_OUT(MP_MULMOD_E);
    #endif /* WC_RSA_BLINGING */

    #ifdef RSA_LOW_MEM      /* half as much memory but twice as slow */
        if (mp_exptmod(&tmp, &key->d, &key->n, &tmp) != MP_OKAY)
            ERROR_OUT(MP_EXPTMOD_E);
    #else
        /* Return 0 when cond is false and n when cond is true. */
        #define COND_N(cond, n)    ((0 - (cond)) & (n))
        /* If ret has an error value return it otherwise if r is OK then return
         * 0 otherwise return e.
         */
        #define RET_ERR(ret, r, e) \
            ((ret) | (COND_N((ret) == 0, COND_N((r) != MP_OKAY, (e)))))
    
        { /* tmpa/b scope */
        mp_int tmpa, tmpb;
        int r;

        if (mp_init(&tmpa) != MP_OKAY)
            ERROR_OUT(MP_INIT_E);

        if (mp_init(&tmpb) != MP_OKAY) {
            mp_clear(&tmpa);
            ERROR_OUT(MP_INIT_E);
        }

        /* tmpa = tmp^dP mod p */
        r = mp_exptmod(&tmp, &key->dP, &key->p, &tmpa);
        ret = RET_ERR(ret, r, MP_EXPTMOD_E);

        /* tmpb = tmp^dQ mod q */
        r = mp_exptmod(&tmp, &key->dQ, &key->q, &tmpb);
        ret = RET_ERR(ret, r, MP_EXPTMOD_E);

        /* tmp = (tmpa - tmpb) * qInv (mod p) */
        r = mp_sub(&tmpa, &tmpb, &tmp);
        ret = RET_ERR(ret, r, MP_SUB_E);

        r = mp_mulmod(&tmp, &key->u, &key->p, &tmp);
        ret = RET_ERR(ret, r, MP_MULMOD_E);

        /* tmp = tmpb + q * tmp */
        r = mp_mul(&tmp, &key->q, &tmp);
        ret = RET_ERR(ret, r, MP_MUL_E);

        r = mp_add(&tmp, &tmpb, &tmp);
        ret = RET_ERR(ret, r, MP_ADD_E);

        mp_clear(&tmpa);
        mp_clear(&tmpb);

        if (ret != 0) {
            goto done;
        }
        #undef RET_ERR
        #undef COND_N
        } /* tmpa/b scope */
    #endif   /* RSA_LOW_MEM */

    #ifdef WC_RSA_BLINDING
        /* unblind */
        if (mp_mulmod(&tmp, &rndi, &key->n, &tmp) != MP_OKAY)
            ERROR_OUT(MP_MULMOD_E);
    #endif   /* WC_RSA_BLINDING */

        break;
    }
    case RSA_PUBLIC_ENCRYPT:
    case RSA_PUBLIC_DECRYPT:
        if (mp_exptmod(&tmp, &key->e, &key->n, &tmp) != MP_OKAY)
            ERROR_OUT(MP_EXPTMOD_E);
        break;
    default:
        ERROR_OUT(RSA_WRONG_TYPE_E);
    }

    keyLen = wc_RsaEncryptSize(key);
    if (keyLen > *outLen) {
        ERROR_OUT(RSA_BUFFER_E);
    }

    len = mp_unsigned_bin_size(&tmp);

    /* pad front w/ zeros to match key length */
    while (len < keyLen) {
        *out++ = 0x00;
        len++;
    }

    *outLen = keyLen;

    /* convert */
    if (mp_to_unsigned_bin(&tmp, out) != MP_OKAY)
        ERROR_OUT(MP_TO_E);

done:
    mp_clear(&tmp);
#ifdef WC_RSA_BLINDING
    if (type == RSA_PRIVATE_DECRYPT || type == RSA_PRIVATE_ENCRYPT) {
        mp_clear(&rndi);
        mp_clear(&rnd);
    }
#endif
    if (ret == MP_EXPTMOD_E) {
        WOLFSSL_MSG("RSA_FUNCTION MP_EXPTMOD_E: memory/config problem");
    }
    return ret;
}

#ifdef WOLFSSL_ASYNC_CRYPT
static int wc_RsaFunctionAsync(const byte* in, word32 inLen, byte* out,
                          word32* outLen, int type, RsaKey* key, WC_RNG* rng)
{
    int ret = 0;

#ifdef WOLFSSL_ASYNC_CRYPT_TEST
    AsyncCryptTestDev* testDev = &key->asyncDev.dev;
    if (testDev->type == ASYNC_TEST_NONE) {
        testDev->type = ASYNC_TEST_RSA_FUNC;
        testDev->rsaFunc.in = in;
        testDev->rsaFunc.inSz = inLen;
        testDev->rsaFunc.out = out;
        testDev->rsaFunc.outSz = outLen;
        testDev->rsaFunc.type = type;
        testDev->rsaFunc.key = key;
        testDev->rsaFunc.rng = rng;
        return WC_PENDING_E;
    }
#endif /* WOLFSSL_ASYNC_CRYPT_TEST */

    switch(type) {
    case RSA_PRIVATE_DECRYPT:
    case RSA_PRIVATE_ENCRYPT:
    #ifdef HAVE_CAVIUM
        ret = NitroxRsaExptMod(in, inLen, key->d.dpraw, key->d.used,
                               key->n.dpraw, key->n.used, out, outLen, key);
    #elif defined(HAVE_INTEL_QA)
        /* TODO: Add support for Intel Quick Assist */
        ret = -1;
    #else /* WOLFSSL_ASYNC_CRYPT_TEST */
        ret = wc_RsaFunctionSync(in, inLen, out, outLen, type, key, rng);
    #endif
        break;

    case RSA_PUBLIC_ENCRYPT:
    case RSA_PUBLIC_DECRYPT:
    #ifdef HAVE_CAVIUM
        ret = NitroxRsaExptMod(in, inLen, key->e.dpraw, key->e.used,
                               key->n.dpraw, key->n.used, out, outLen, key);
    #elif defined(HAVE_INTEL_QA)
        /* TODO: Add support for Intel Quick Assist */
        ret = -1;
    #else /* WOLFSSL_ASYNC_CRYPT_TEST */
        ret = wc_RsaFunctionSync(in, inLen, out, outLen, type, key, rng);
    #endif
        break;

    default:
        ret = RSA_WRONG_TYPE_E;
    }

    return ret;
}
#endif /* WOLFSSL_ASYNC_CRYPT */

int wc_RsaFunction(const byte* in, word32 inLen, byte* out,
                          word32* outLen, int type, RsaKey* key, WC_RNG* rng)
{
    int ret;

    if (key == NULL || in == NULL || inLen == 0 || out == NULL ||
            outLen == NULL || *outLen == 0 || type == RSA_TYPE_UNKNOWN) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_ASYNC_CRYPT
    if (key->asyncDev.marker == WOLFSSL_ASYNC_MARKER_RSA) {
        ret = wc_RsaFunctionAsync(in, inLen, out, outLen, type, key, rng);
    }
    else
#endif
    {
        ret = wc_RsaFunctionSync(in, inLen, out, outLen, type, key, rng);
    }

    if (ret == MP_EXPTMOD_E) {
        /* This can happen due to incorrectly set FP_MAX_BITS or missing XREALLOC */
        WOLFSSL_MSG("RSA_FUNCTION MP_EXPTMOD_E: memory/config problem");
    }
    return ret;
}


/* Internal Wrappers */
/* Gives the option of choosing padding type
   in : input to be encrypted
   inLen: length of input buffer
   out: encrypted output
   outLen: length of encrypted output buffer
   key   : wolfSSL initialized RSA key struct
   rng   : wolfSSL initialized random number struct
   rsa_type  : type of RSA: RSA_PUBLIC_ENCRYPT, RSA_PUBLIC_DECRYPT,
        RSA_PRIVATE_ENCRYPT or RSA_PRIVATE_DECRYPT
   pad_value: RSA_BLOCK_TYPE_1 or RSA_BLOCK_TYPE_2
   pad_type  : type of padding: WC_RSA_PKCSV15_PAD or  WC_RSA_OAEP_PAD
   hash  : type of hash algorithm to use found in wolfssl/wolfcrypt/hash.h
   mgf   : type of mask generation function to use
   label : optional label
   labelSz : size of optional label buffer */
static int RsaPublicEncryptEx(const byte* in, word32 inLen, byte* out,
                            word32 outLen, RsaKey* key, int rsa_type,
                            byte pad_value, int pad_type,
                            enum wc_HashType hash, int mgf,
                            byte* label, word32 labelSz, WC_RNG* rng)
{
    int ret = BAD_FUNC_ARG, sz;

    if (in == NULL || inLen == 0 || out == NULL || key == NULL) {
        return ret;
    }

    sz = wc_RsaEncryptSize(key);
    if (sz > (int)outLen) {
        return RSA_BUFFER_E;
    }

    if (sz < RSA_MIN_PAD_SZ) {
        return WC_KEY_SIZE_E;
    }

    if (inLen > (word32)(sz - RSA_MIN_PAD_SZ)) {
        return RSA_BUFFER_E;
    }

    switch (key->state) {
    case RSA_STATE_NONE:
    case RSA_STATE_ENCRYPT_PAD:

    #if defined(WOLFSSL_ASYNC_CRYPT) && defined(HAVE_CAVIUM)
        if (key->asyncDev.marker == WOLFSSL_ASYNC_MARKER_RSA) {
            if (rsa_type == RSA_PUBLIC_ENCRYPT && pad_value == RSA_BLOCK_TYPE_2) {
                key->state = RSA_STATE_ENCRYPT_RES;
                key->tmpLen = key->n.used;
                return NitroxRsaPublicEncrypt(in, inLen, out, outLen, key);
            }
            else if (rsa_type == RSA_PRIVATE_ENCRYPT && pad_value == RSA_BLOCK_TYPE_1) {
                key->state = RSA_STATE_ENCRYPT_RES;
                key->tmpLen = key->n.used;
                return NitroxRsaSSL_Sign(in, inLen, out, outLen, key);
            }
        }
    #endif

        key->state = RSA_STATE_ENCRYPT_EXPTMOD;

        ret = wc_RsaPad_ex(in, inLen, out, sz, pad_value, rng,
                               pad_type, hash, mgf, label, labelSz, key->heap);
        if (ret < 0) {
            break;
        }
        /* fall through */
    case RSA_STATE_ENCRYPT_EXPTMOD:
        key->state = RSA_STATE_ENCRYPT_RES;

        key->tmpLen = outLen;
        ret = wc_RsaFunction(out, sz, out, &key->tmpLen, rsa_type, key, rng);
        if (ret < 0) {
            break;
        }
        /* fall through */
    case RSA_STATE_ENCRYPT_RES:
        key->state = RSA_STATE_NONE;
        ret = key->tmpLen;
        break;

    default:
        ret = BAD_STATE_E;
    }

    /* if async pending then return and skip done cleanup below */
    if (ret == WC_PENDING_E) {
        return ret;
    }

    key->state = RSA_STATE_NONE;

    return ret;
}

/* Gives the option of choosing padding type
   in : input to be decrypted
   inLen: length of input buffer
   out:  decrypted message
   outLen: length of decrypted message in bytes
   outPtr: optional inline output pointer (if provided doing inline)
   key   : wolfSSL initialized RSA key struct
   rsa_type  : type of RSA: RSA_PUBLIC_ENCRYPT, RSA_PUBLIC_DECRYPT,
        RSA_PRIVATE_ENCRYPT or RSA_PRIVATE_DECRYPT
   pad_value: RSA_BLOCK_TYPE_1 or RSA_BLOCK_TYPE_2
   pad_type  : type of padding: WC_RSA_PKCSV15_PAD or  WC_RSA_OAEP_PAD
   hash  : type of hash algorithm to use found in wolfssl/wolfcrypt/hash.h
   mgf   : type of mask generation function to use
   label : optional label
   labelSz : size of optional label buffer */
static int RsaPrivateDecryptEx(byte* in, word32 inLen, byte* out,
                            word32 outLen, byte** outPtr, RsaKey* key,
                            int rsa_type, byte pad_value, int pad_type,
                            enum wc_HashType hash, int mgf,
                            byte* label, word32 labelSz, WC_RNG* rng)
{
    int ret = BAD_FUNC_ARG;

    if (in == NULL || inLen == 0 || out == NULL || key == NULL) {
        return ret;
    }

    switch (key->state) {
    case RSA_STATE_NONE:
    case RSA_STATE_DECRYPT_EXPTMOD:
    #if defined(WOLFSSL_ASYNC_CRYPT) && defined(HAVE_CAVIUM)
        if (key->asyncDev.marker == WOLFSSL_ASYNC_MARKER_RSA) {
            key->tmpLen = 0;
            if (rsa_type == RSA_PRIVATE_DECRYPT && pad_value == RSA_BLOCK_TYPE_2) {
                key->state = RSA_STATE_DECRYPT_RES;
                key->tmp = NULL;
                ret = NitroxRsaPrivateDecrypt(in, inLen, out, outLen, key);
                if (ret > 0) {
                    if (outPtr)
                        *outPtr = in;
                }
                return ret;
            }
            else if (rsa_type == RSA_PUBLIC_DECRYPT && pad_value == RSA_BLOCK_TYPE_1) {
                key->state = RSA_STATE_DECRYPT_RES;
                key->tmp = NULL;
                return NitroxRsaSSL_Verify(in, inLen, out, outLen, key);
            }
        }
    #endif

        key->state = RSA_STATE_DECRYPT_UNPAD;

        /* verify the tmp ptr is NULL, otherwise indicates bad state */
        if (key->tmp != NULL) {
            ERROR_OUT(BAD_STATE_E);
        }

        /* if not doing this inline then allocate a buffer for it */
        key->tmpLen = inLen;
        if (outPtr == NULL) {
            key->tmp = (byte*)XMALLOC(inLen, key->heap, DYNAMIC_TYPE_RSA);
            key->tmpIsAlloc = 1;
            if (key->tmp == NULL) {
                ERROR_OUT(MEMORY_E);
            }
            XMEMCPY(key->tmp, in, inLen);
        }
        else {
            key->tmp = out;
        }
        ret = wc_RsaFunction(key->tmp, inLen, key->tmp, &key->tmpLen,
                                                        rsa_type, key, rng);
        if (ret < 0) {
            break;
        }
        /* fall through */
    case RSA_STATE_DECRYPT_UNPAD:
    {
        byte* pad = NULL;
        key->state = RSA_STATE_DECRYPT_RES;
        ret = wc_RsaUnPad_ex(key->tmp, key->tmpLen, &pad, pad_value, pad_type,
                                        hash, mgf, label, labelSz, key->heap);
        if (ret > 0 && ret <= (int)outLen && pad != NULL) {
            /* only copy output if not inline */
            if (outPtr == NULL) {
                XMEMCPY(out, pad, ret);
            }
            else {
                *outPtr = pad;
            }
        }
        else if (ret >= 0) {
            ret = RSA_BUFFER_E;
        }
        if (ret < 0) {
            break;
        }
        /* fall through */
    }
    case RSA_STATE_DECRYPT_RES:
        key->state = RSA_STATE_NONE;
    #if defined(WOLFSSL_ASYNC_CRYPT) && defined(HAVE_CAVIUM)
        if (key->asyncDev.marker == WOLFSSL_ASYNC_MARKER_RSA) {
            ret = key->tmpLen;
        }
    #endif
        break;
    default:
        ret = BAD_STATE_E;
    }

    /* if async pending then return and skip done cleanup below */
    if (ret == WC_PENDING_E) {
        return ret;
    }

done:

    key->state = RSA_STATE_NONE;
    wc_RsaCleanup(key);

    return ret;
}


/* Public RSA Functions */
int wc_RsaPublicEncrypt(const byte* in, word32 inLen, byte* out, word32 outLen,
                                                     RsaKey* key, WC_RNG* rng)
{
    return RsaPublicEncryptEx(in, inLen, out, outLen, key,
        RSA_PUBLIC_ENCRYPT, RSA_BLOCK_TYPE_2, WC_RSA_PKCSV15_PAD,
        WC_HASH_TYPE_NONE, WC_MGF1NONE, NULL, 0, rng);
}


#ifndef WC_NO_RSA_OAEP
int wc_RsaPublicEncrypt_ex(const byte* in, word32 inLen, byte* out,
                    word32 outLen, RsaKey* key, WC_RNG* rng, int type,
                    enum wc_HashType hash, int mgf, byte* label,
                    word32 labelSz)
{
    return RsaPublicEncryptEx(in, inLen, out, outLen, key, RSA_PUBLIC_ENCRYPT,
        RSA_BLOCK_TYPE_2, type, hash, mgf, label, labelSz, rng);
}
#endif /* WC_NO_RSA_OAEP */


int wc_RsaPrivateDecryptInline(byte* in, word32 inLen, byte** out, RsaKey* key)
{
    WC_RNG* rng = NULL;
#ifdef WC_RSA_BLINDING
    rng = key->rng;
#endif
    return RsaPrivateDecryptEx(in, inLen, in, inLen, out, key,
        RSA_PRIVATE_DECRYPT, RSA_BLOCK_TYPE_2, WC_RSA_PKCSV15_PAD,
        WC_HASH_TYPE_NONE, WC_MGF1NONE, NULL, 0, rng);
}


#ifndef WC_NO_RSA_OAEP
int wc_RsaPrivateDecryptInline_ex(byte* in, word32 inLen, byte** out,
                                  RsaKey* key, int type, enum wc_HashType hash,
                                  int mgf, byte* label, word32 labelSz)
{
    WC_RNG* rng = NULL;
#ifdef WC_RSA_BLINDING
    rng = key->rng;
#endif
    return RsaPrivateDecryptEx(in, inLen, in, inLen, out, key,
        RSA_PRIVATE_DECRYPT, RSA_BLOCK_TYPE_2, type, hash,
        mgf, label, labelSz, rng);
}
#endif /* WC_NO_RSA_OAEP */


int wc_RsaPrivateDecrypt(const byte* in, word32 inLen, byte* out,
                                                 word32 outLen, RsaKey* key)
{
    WC_RNG* rng = NULL;
#ifdef WC_RSA_BLINDING
    rng = key->rng;
#endif
    return RsaPrivateDecryptEx((byte*)in, inLen, out, outLen, NULL, key,
        RSA_PRIVATE_DECRYPT, RSA_BLOCK_TYPE_2, WC_RSA_PKCSV15_PAD,
        WC_HASH_TYPE_NONE, WC_MGF1NONE, NULL, 0, rng);
}


#ifndef WC_NO_RSA_OAEP
int wc_RsaPrivateDecrypt_ex(const byte* in, word32 inLen, byte* out,
                            word32 outLen, RsaKey* key, int type,
                            enum wc_HashType hash, int mgf, byte* label,
                            word32 labelSz)
{
    WC_RNG* rng = NULL;
#ifdef WC_RSA_BLINDING
    rng = key->rng;
#endif
    return RsaPrivateDecryptEx((byte*)in, inLen, out, outLen, NULL, key,
        RSA_PRIVATE_DECRYPT, RSA_BLOCK_TYPE_2, type, hash, mgf, label,
        labelSz, rng);
}
#endif /* WC_NO_RSA_OAEP */


int wc_RsaSSL_VerifyInline(byte* in, word32 inLen, byte** out, RsaKey* key)
{
    WC_RNG* rng = NULL;
#ifdef WC_RSA_BLINDING
    rng = key->rng;
#endif
    return RsaPrivateDecryptEx(in, inLen, in, inLen, out, key,
        RSA_PUBLIC_DECRYPT, RSA_BLOCK_TYPE_1, WC_RSA_PKCSV15_PAD,
        WC_HASH_TYPE_NONE, WC_MGF1NONE, NULL, 0, rng);
}

int wc_RsaSSL_Verify(const byte* in, word32 inLen, byte* out, word32 outLen,
                                                                 RsaKey* key)
{
    WC_RNG* rng = NULL;
#ifdef WC_RSA_BLINDING
    rng = key->rng;
#endif
    return RsaPrivateDecryptEx((byte*)in, inLen, out, outLen, NULL, key,
        RSA_PUBLIC_DECRYPT, RSA_BLOCK_TYPE_1, WC_RSA_PKCSV15_PAD,
        WC_HASH_TYPE_NONE, WC_MGF1NONE, NULL, 0, rng);
}


int wc_RsaSSL_Sign(const byte* in, word32 inLen, byte* out, word32 outLen,
                                                   RsaKey* key, WC_RNG* rng)
{
    return RsaPublicEncryptEx(in, inLen, out, outLen, key,
        RSA_PRIVATE_ENCRYPT, RSA_BLOCK_TYPE_1, WC_RSA_PKCSV15_PAD,
        WC_HASH_TYPE_NONE, WC_MGF1NONE, NULL, 0, rng);
}


int wc_RsaEncryptSize(RsaKey* key)
{
#if defined(WOLFSSL_ASYNC_CRYPT) && defined(HAVE_CAVIUM)
    if (key->asyncDev.marker == WOLFSSL_ASYNC_MARKER_RSA) {
        return key->n.used;
    }
#endif
    return mp_unsigned_bin_size(&key->n);
}


/* flatten RsaKey structure into individual elements (e, n) */
int wc_RsaFlattenPublicKey(RsaKey* key, byte* e, word32* eSz, byte* n,
                                                                   word32* nSz)
{
    int sz, ret;

    if (key == NULL || e == NULL || eSz == NULL || n == NULL || nSz == NULL) {
        return BAD_FUNC_ARG;
    }

    sz = mp_unsigned_bin_size(&key->e);
    if ((word32)sz > *eSz)
        return RSA_BUFFER_E;
    ret = mp_to_unsigned_bin(&key->e, e);
    if (ret != MP_OKAY)
        return ret;
    *eSz = (word32)sz;

    sz = wc_RsaEncryptSize(key);
    if ((word32)sz > *nSz)
        return RSA_BUFFER_E;
    ret = mp_to_unsigned_bin(&key->n, n);
    if (ret != MP_OKAY)
        return ret;
    *nSz = (word32)sz;

    return 0;
}

#ifdef WOLFSSL_KEY_GEN
/* Make an RSA key for size bits, with e specified, 65537 is a good e */
int wc_MakeRsaKey(RsaKey* key, int size, long e, WC_RNG* rng)
{
    mp_int p, q, tmp1, tmp2, tmp3;
    int    err;

    if (key == NULL || rng == NULL)
        return BAD_FUNC_ARG;

    if (size < RSA_MIN_SIZE || size > RSA_MAX_SIZE)
        return BAD_FUNC_ARG;

    if (e < 3 || (e & 1) == 0)
        return BAD_FUNC_ARG;

    if ((err = mp_init_multi(&p, &q, &tmp1, &tmp2, &tmp3, NULL)) != MP_OKAY)
        return err;

    err = mp_set_int(&tmp3, (mp_digit)e);

    /* make p */
    if (err == MP_OKAY) {
        do {
            err = mp_rand_prime(&p, size/16, rng, key->heap); /* size in bytes/2 */

            if (err == MP_OKAY)
                err = mp_sub_d(&p, 1, &tmp1);  /* tmp1 = p-1 */

            if (err == MP_OKAY)
                err = mp_gcd(&tmp1, &tmp3, &tmp2);  /* tmp2 = gcd(p-1, e) */
        } while (err == MP_OKAY && mp_cmp_d(&tmp2, 1) != 0);  /* e divides p-1 */
    }

    /* make q */
    if (err == MP_OKAY) {
        do {
            err = mp_rand_prime(&q, size/16, rng, key->heap); /* size in bytes/2 */

            if (err == MP_OKAY)
                err = mp_sub_d(&q, 1, &tmp1);  /* tmp1 = q-1 */

            if (err == MP_OKAY)
                err = mp_gcd(&tmp1, &tmp3, &tmp2);  /* tmp2 = gcd(q-1, e) */
        } while (err == MP_OKAY && mp_cmp_d(&tmp2, 1) != 0);  /* e divides q-1 */
    }

    if (err == MP_OKAY)
        err = mp_init_multi(&key->n, &key->e, &key->d, &key->p, &key->q, NULL);

    if (err == MP_OKAY)
        err = mp_init_multi(&key->dP, &key->dQ, &key->u, NULL, NULL, NULL);

    if (err == MP_OKAY)
        err = mp_sub_d(&p, 1, &tmp2);  /* tmp2 = p-1 */

    if (err == MP_OKAY)
        err = mp_lcm(&tmp1, &tmp2, &tmp1);  /* tmp1 = lcm(p-1, q-1),last loop */

    /* make key */
    if (err == MP_OKAY)
        err = mp_set_int(&key->e, (mp_digit)e);  /* key->e = e */

    if (err == MP_OKAY)                /* key->d = 1/e mod lcm(p-1, q-1) */
        err = mp_invmod(&key->e, &tmp1, &key->d);

    if (err == MP_OKAY)
        err = mp_mul(&p, &q, &key->n);  /* key->n = pq */

    if (err == MP_OKAY)
        err = mp_sub_d(&p, 1, &tmp1);

    if (err == MP_OKAY)
        err = mp_sub_d(&q, 1, &tmp2);

    if (err == MP_OKAY)
        err = mp_mod(&key->d, &tmp1, &key->dP);

    if (err == MP_OKAY)
        err = mp_mod(&key->d, &tmp2, &key->dQ);

    if (err == MP_OKAY)
        err = mp_invmod(&q, &p, &key->u);

    if (err == MP_OKAY)
        err = mp_copy(&p, &key->p);

    if (err == MP_OKAY)
        err = mp_copy(&q, &key->q);

    if (err == MP_OKAY)
        key->type = RSA_PRIVATE;

    mp_clear(&tmp3);
    mp_clear(&tmp2);
    mp_clear(&tmp1);
    mp_clear(&q);
    mp_clear(&p);

    if (err != MP_OKAY) {
        wc_FreeRsaKey(key);
        return err;
    }

    return 0;
}
#endif /* WOLFSSL_KEY_GEN */


#ifdef WC_RSA_BLINDING

int wc_RsaSetRNG(RsaKey* key, WC_RNG* rng)
{
    if (key == NULL)
        return BAD_FUNC_ARG;

    key->rng = rng;

    return 0;
}

#endif /* WC_RSA_BLINDING */


#ifdef WOLFSSL_ASYNC_CRYPT
int wc_RsaAsyncHandle(RsaKey* key, WOLF_EVENT_QUEUE* queue, WOLF_EVENT* event)
{
    int ret;

    if (key == NULL || queue == NULL || event == NULL) {
        return BAD_FUNC_ARG;
    }

    /* make sure this rsa context had "wc_RsaAsyncInit" called on it */
    if (key->asyncDev.marker != WOLFSSL_ASYNC_MARKER_RSA) {
        return ASYNC_INIT_E;
    }

    /* setup the event and push to queue */
    ret = wolfAsync_EventInit(event, WOLF_EVENT_TYPE_ASYNC_WOLFCRYPT, &key->asyncDev);
    if (ret == 0) {
        ret = wolfEventQueue_Push(queue, event);
    }

    /* check for error (helps with debugging) */
    if (ret != 0) {
        WOLFSSL_MSG("wc_RsaAsyncHandle failed");
    }
    return ret;
}

int wc_RsaAsyncWait(int ret, RsaKey* key)
{
    if (ret == WC_PENDING_E) {
        WOLF_EVENT event;
        XMEMSET(&event, 0, sizeof(event));
        ret = wolfAsync_EventInit(&event, WOLF_EVENT_TYPE_ASYNC_WOLFCRYPT, &key->asyncDev);
        if (ret == 0) {
            ret = wolfAsync_EventWait(&event);
            if (ret == 0 && event.ret >= 0) {
                ret = event.ret;
            }
        }
    }
    return ret;
}

/* Initialize async RSA key */
static int InitAsyncRsaKey(RsaKey* key)
{
    XMEMSET(&key->n,  0, sizeof(key->n));
    XMEMSET(&key->e,  0, sizeof(key->e));
    XMEMSET(&key->d,  0, sizeof(key->d));
    XMEMSET(&key->p,  0, sizeof(key->p));
    XMEMSET(&key->q,  0, sizeof(key->q));
    XMEMSET(&key->dP, 0, sizeof(key->dP));
    XMEMSET(&key->dQ, 0, sizeof(key->dQ));
    XMEMSET(&key->u,  0, sizeof(key->u));

    return 0;
}

/* Free async RSA key */
static int FreeAsyncRsaKey(RsaKey* key)
{
    if (key->type == RSA_PRIVATE) {
        if (key->d.dpraw) {
            ForceZero(key->d.dpraw, key->d.used);
        #ifndef USE_FAST_MATH
            XFREE(key->d.dpraw,  key->heap, DYNAMIC_TYPE_ASYNC_RSA);
        #endif
        }
        if (key->p.dpraw) {
            ForceZero(key->p.dpraw, key->p.used);
        #ifndef USE_FAST_MATH
            XFREE(key->p.dpraw,  key->heap, DYNAMIC_TYPE_ASYNC_RSA);
        #endif
        }
        if (key->q.dpraw) {
            ForceZero(key->q.dpraw, key->q.used);
        #ifndef USE_FAST_MATH
            XFREE(key->q.dpraw,  key->heap, DYNAMIC_TYPE_ASYNC_RSA);
        #endif
        }
        if (key->dP.dpraw) {
            ForceZero(key->dP.dpraw, key->dP.used);
        #ifndef USE_FAST_MATH
            XFREE(key->dP.dpraw, key->heap, DYNAMIC_TYPE_ASYNC_RSA);
        #endif
        }
        if (key->dQ.dpraw) {
            ForceZero(key->dQ.dpraw, key->dQ.used);
        #ifndef USE_FAST_MATH
            XFREE(key->dQ.dpraw, key->heap, DYNAMIC_TYPE_ASYNC_RSA);
        #endif
        }
        if (key->u.dpraw) {
            ForceZero(key->u.dpraw, key->u.used);
        #ifndef USE_FAST_MATH
            XFREE(key->u.dpraw,  key->heap, DYNAMIC_TYPE_ASYNC_RSA);
        #endif
        }
    }

#ifndef USE_FAST_MATH
    XFREE(key->n.dpraw,  key->heap, DYNAMIC_TYPE_ASYNC_RSA);
    XFREE(key->e.dpraw,  key->heap, DYNAMIC_TYPE_ASYNC_RSA);
#endif

    return InitAsyncRsaKey(key);  /* reset pointers */
}

#endif /* WOLFSSL_ASYNC_CRYPT */

#undef ERROR_OUT

#endif /* HAVE_FIPS */
#endif /* NO_RSA */
