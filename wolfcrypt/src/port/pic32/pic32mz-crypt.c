/* pic32mz-crypt.c
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

#ifdef WOLFSSL_MICROCHIP_PIC32MZ

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <wolfssl/wolfcrypt/port/pic32/pic32mz-crypt.h>

#ifdef WOLFSSL_PIC32MZ_CRYPT
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/des3.h>
#endif

#ifdef WOLFSSL_PIC32MZ_HASH
#include <wolfssl/wolfcrypt/md5.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#endif


#if defined(WOLFSSL_PIC32MZ_CRYPT) || defined(WOLFSSL_PIC32MZ_HASH)

static int Pic32GetBlockSize(int algo)
{
    switch (algo) {
        case PIC32_ALGO_HMAC1:
            return PIC32_BLOCKSIZE_HMAC;
        case PIC32_ALGO_SHA256:
            return PIC32_BLOCKSIZE_SHA256;
        case PIC32_ALGO_SHA1:
            return PIC32_BLOCKSIZE_SHA1;
        case PIC32_ALGO_MD5:
            return PIC32_BLOCKSIZE_MD5;
        case PIC32_ALGO_AES:
            return PIC32_BLOCKSIZE_AES;
        case PIC32_ALGO_TDES:
            return PIC32_BLOCKSIZE_TDES;
        case PIC32_ALGO_DES:
            return PIC32_BLOCKSIZE_DES;
    }
    return 0;
}

static int Pic32Crypto(const byte* in, int inLen, word32* out, int outLen,
    int dir, int algo, int cryptoalgo,

    /* For DES/AES only */
    word32* key, int keyLen, word32* iv, int ivLen)
{
    int ret = 0;
    int blockSize = Pic32GetBlockSize(algo);
    volatile bufferDescriptor bd __attribute__((aligned (8)));
    securityAssociation sa __attribute__((aligned (8)));
    securityAssociation *sa_p;
    bufferDescriptor *bd_p;
    byte *in_p;
    byte *out_p;
    word32* dst;
    word32 padRemain;
    int timeout = 0xFFFFFF;

    /* check args */
    if (in == NULL || inLen <= 0 || out == NULL || blockSize == 0) {
        return BAD_FUNC_ARG;
    }

    /* check pointer alignment - must be word aligned */
    if (((size_t)in % sizeof(word32)) || ((size_t)out % sizeof(word32))) {
        return BUFFER_E; /* buffer is not aligned */
    }

    /* get uncached address */
    sa_p = KVA0_TO_KVA1(&sa);
    bd_p = KVA0_TO_KVA1(&bd);
    out_p= KVA0_TO_KVA1(out);

    if (in) {
        in_p = KVA0_TO_KVA1(in);

        /* Sync cache if in physical memory (not flash) */
        if (PIC32MZ_IF_RAM(in_p)) {
            XMEMCPY(in_p, in, inLen);
        }
    }

    /* Set up the Security Association */
    XMEMSET(sa_p, 0, sizeof(sa));
    sa_p->SA_CTRL.ALGO = algo;
    sa_p->SA_CTRL.ENCTYPE = dir;
    sa_p->SA_CTRL.FB = 1; /* first block */
    sa_p->SA_CTRL.LNC = 1; /* Load new set of keys */
    if (key) {
        /* cipher */
        sa_p->SA_CTRL.CRYPTOALGO = cryptoalgo;

        switch (keyLen) {
            case 32:
                sa_p->SA_CTRL.KEYSIZE = PIC32_KEYSIZE_256;
                break;
            case 24:
            case 8: /* DES */
                sa_p->SA_CTRL.KEYSIZE = PIC32_KEYSIZE_192;
                break;
            case 16:
                sa_p->SA_CTRL.KEYSIZE = PIC32_KEYSIZE_128;
                break;
        }

        dst = (word32*)KVA0_TO_KVA1(sa.SA_ENCKEY +
            (sizeof(sa.SA_ENCKEY)/sizeof(word32)) - (keyLen/sizeof(word32)));
        ByteReverseWords(dst, key, keyLen);

        if (iv && ivLen > 0) {
            sa_p->SA_CTRL.LOADIV = 1;
            dst = (word32*)KVA0_TO_KVA1(sa.SA_ENCIV +
                (sizeof(sa.SA_ENCIV)/sizeof(word32)) - (ivLen/sizeof(word32)));
            ByteReverseWords(dst, iv, ivLen);
        }
    }
    else {
        /* hashing */
        sa_p->SA_CTRL.LOADIV = 1;
        sa_p->SA_CTRL.IRFLAG = 0; /* immediate result for hashing */

        dst = (word32*)KVA0_TO_KVA1(sa.SA_AUTHIV +
            (sizeof(sa.SA_AUTHIV)/sizeof(word32)) - (outLen/sizeof(word32)));
        ByteReverseWords(dst, out, outLen);
    }

    /* Set up the Buffer Descriptor */
    XMEMSET(bd_p, 0, sizeof(bd));
    bd_p->BD_CTRL.BUFLEN = inLen;
    padRemain = (inLen % 4); /* make sure buffer is 4-byte multiple */
    if (padRemain != 0) {
        bd_p->BD_CTRL.BUFLEN += (4 - padRemain);
    }
    bd_p->BD_CTRL.SA_FETCH_EN = 1; /* Fetch the security association */
    bd_p->BD_CTRL.PKT_INT_EN = 1;  /* enable interrupt */
    bd_p->BD_CTRL.LAST_BD = 1;     /* last buffer desc in chain */
    bd_p->BD_CTRL.LIFM = 1;        /* last in frame */
    bd_p->SA_ADDR = (unsigned int)KVA_TO_PA(&sa);
    bd_p->SRCADDR = (unsigned int)KVA_TO_PA(in);
    if (key) {
        /* cipher */
        if (in != (byte*)out)
            XMEMSET(out_p, 0, outLen); /* clear output buffer */
        bd_p->DSTADDR = (unsigned int)KVA_TO_PA(out);
    }
    else {
        /* hashing */
        /* digest result returned in UPDPTR */
        bd_p->UPDPTR = (unsigned int)KVA_TO_PA(out);
    }
    bd_p->NXTPTR = (unsigned int)KVA_TO_PA(&bd);
    bd_p->MSGLEN = inLen;          /* actual message size */
    bd_p->BD_CTRL.DESC_EN = 1;     /* enable this descriptor */

    /* begin access to hardware */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Software Reset the Crypto Engine */
        CECON = 1 << 6;
        while (CECON);

        /* Run the engine */
        CEBDPADDR = (unsigned int)KVA_TO_PA(&bd);
        CEINTEN = 0x07; /* enable DMA Packet Completion Interrupt */

        /* input swap, enable BD fetch and start DMA */
    #if PIC32_NO_OUT_SWAP
        CECON = 0x25;
    #else
        CECON = 0xa5; /* bit 7 = enable out swap */
    #endif

        /* wait for operation to complete */
        while (CEINTSRCbits.PKTIF == 0 && --timeout > 0) {};

        /* Clear the interrupt flags */
        CEINTSRC = 0xF;

        /* check for errors */
        if (CESTATbits.ERROP || timeout <= 0) {
        #if 1
            printf("PIC32 Crypto: ERROP %x, ERRPHASE %x, TIMEOUT %d\n",
                CESTATbits.ERROP, CESTATbits.ERRPHASE, timeout);
        #endif
            ret = ASYNC_OP_E;
        }

        wolfSSL_CryptHwMutexUnLock();

        if (iv && ivLen > 0) {
            /* set iv for the next call */
            if (dir == PIC32_ENCRYPTION) {
                XMEMCPY(iv, KVA0_TO_KVA1(out + (outLen - ivLen)), ivLen);
            #if !PIC32_NO_OUT_SWAP
                /* hardware already swapped output, so we need to swap back */
                ByteReverseWords(iv, iv, ivLen);
            #endif
            }
            else {
                ByteReverseWords(iv, KVA0_TO_KVA1(in + (inLen - ivLen)), ivLen);
            }
        }

        if (outLen > 0) {
            /* copy result to output */
        #if PIC32_NO_OUT_SWAP
            /* swap bytes */
            ByteReverseWords(out, (word32*)out_p, outLen);
        #else
            /* sync cache */
            #ifdef _SYS_DEVCON_LOCAL_H
                SYS_DEVCON_DataCacheInvalidate((word32)out, outLen);
            #else
                XMEMCPY(out, out_p, outLen);
            #endif
        #endif
        }
        else {
            /* sync cache */
        #if PIC32_NO_OUT_SWAP
            /* swap bytes */
            ByteReverseWords(out, (word32*)out_p, PIC32_DIGEST_SIZE);
        #else
            /* sync cache */
            #ifdef _SYS_DEVCON_LOCAL_H
                SYS_DEVCON_DataCacheInvalidate((word32)out, PIC32_DIGEST_SIZE);
            #else
                XMEMCPY(out, out_p, PIC32_DIGEST_SIZE);
            #endif
        #endif
        }
    }

    return ret;
}
#endif /* WOLFSSL_PIC32MZ_CRYPT || WOLFSSL_PIC32MZ_HASH */

#ifdef WOLFSSL_PIC32MZ_HASH
int wc_Pic32Hash(const byte* in, int inLen, word32* out, int outLen, int algo)
{
    return Pic32Crypto(in, inLen, out, outLen, PIC32_ENCRYPTION, algo, 0,
        NULL, 0, NULL, 0);
}

int wc_Pic32HashCopy(hashUpdCache* src, hashUpdCache* dst)
{
    /* mark destination as copy, so cache->buf is not free'd */
    if (dst) {
        dst->isCopy = 1;
    }
    return 0;
}

static int wc_Pic32HashUpdate(hashUpdCache* cache, byte* stdBuf, word32 stdBufLen,
 const byte* data, word32 len, void* heap)
{
    /* cache updates */
    word32 newLenUpd, newLenPad, padRemain;
    byte* newBuf;
    int isNewBuf = 0;

    /* calculate new len */
    newLenUpd = cache->updLen + len;

    /* calculate padded len - pad buffer at 64-bytes for hardware */
    newLenPad = newLenUpd;
    padRemain = (newLenUpd % PIC32_BLOCKSIZE_HASH);
    if (padRemain != 0) {
        newLenPad += (PIC32_BLOCKSIZE_HASH - padRemain);
    }

    /* determine buffer source */
    if (newLenPad <= stdBufLen) {
        /* use standard buffer */
        newBuf = stdBuf;
    }
    else if (newLenPad > cache->bufLen) {
        /* alloc buffer */
        newBuf = (byte*)XMALLOC(newLenPad, heap, DYNAMIC_TYPE_HASH_TMP);
        if (newBuf == NULL) {
            if (cache->buf != stdBuf && !cache->isCopy) {
                XFREE(cache->buf, heap, DYNAMIC_TYPE_HASH_TMP);
                cache->buf = NULL;
                cache->updLen = cache->bufLen = 0;
            }
            return MEMORY_E;
        }
        isNewBuf = 1;
        cache->isCopy = 0; /* no longer using copy buffer */
    }
    else {
        /* use existing buffer */
        newBuf = cache->buf;
    }
    if (cache->buf && cache->updLen > 0) {
        XMEMCPY(newBuf, cache->buf, cache->updLen);
        if (isNewBuf && cache->buf != stdBuf) {
            XFREE(cache->buf, heap, DYNAMIC_TYPE_HASH_TMP);
        }
    }
    XMEMCPY(newBuf + cache->updLen, data, len);

    cache->buf = newBuf;
    cache->updLen = newLenUpd;
    cache->bufLen = newLenPad;

    return 0;
}

static int wc_Pic32HashFinal(hashUpdCache* cache, byte* stdBuf, byte* hash,
    int digestSz, int algo, void* heap)
{
    int ret;
    word32 digest[PIC32_DIGEST_SIZE / sizeof(word32)] = {0};

    /* if room add the pad */
    if (cache->updLen < cache->bufLen) {
        cache->buf[cache->updLen] = 0x80;
    }

    ret = wc_Pic32Hash(cache->buf, cache->updLen, digest, digestSz, algo);
    if (ret == 0) {
        XMEMCPY(hash, digest, digestSz);
    }
    if (cache->buf != stdBuf && !cache->isCopy) {
        XFREE(cache->buf, heap, DYNAMIC_TYPE_HASH_TMP);
    }
    cache->buf = NULL;
    cache->bufLen = cache->updLen = 0;

    return ret;
}

/* API's for compatability with Harmony wrappers - not used */
#ifndef NO_MD5
    int wc_InitMd5_ex(Md5* md5, void* heap, int devId)
    {
        if (md5 == NULL)
            return BAD_FUNC_ARG;

        XMEMSET(md5, 0, sizeof(Md5));
        md5->heap = heap;
        (void)devId;
        return 0;
    }

    int wc_Md5Update(Md5* md5, const byte* data, word32 len)
    {
        if (md5 == NULL || (data == NULL && len > 0))
            return BAD_FUNC_ARG;
        return wc_Pic32HashUpdate(&md5->cache, (byte*)md5->buffer,
            sizeof(md5->buffer), data, len, md5->heap);
    }

    int wc_Md5Final(Md5* md5, byte* hash)
    {
        int ret;

        if (md5 == NULL || hash == NULL)
            return BAD_FUNC_ARG;

        ret = wc_Pic32HashFinal(&md5->cache, (byte*)md5->buffer,
            hash, MD5_DIGEST_SIZE, PIC32_ALGO_MD5, md5->heap);

        wc_InitMd5_ex(md5, md5->heap, INVALID_DEVID);  /* reset state */

        return ret;
    }

    void wc_Md5SizeSet(Md5* md5, word32 len)
    {
        (void)md5;
        (void)len;
    }
#endif /* !NO_MD5 */
#ifndef NO_SHA
    int wc_InitSha_ex(Sha* sha, void* heap, int devId)
    {
        if (sha == NULL)
            return BAD_FUNC_ARG;

        XMEMSET(sha, 0, sizeof(Sha));
        sha->heap = heap;
        (void)devId;
        return 0;
    }

    int wc_ShaUpdate(Sha* sha, const byte* data, word32 len)
    {
        if (sha == NULL || (data == NULL && len > 0))
            return BAD_FUNC_ARG;
        return wc_Pic32HashUpdate(&sha->cache, (byte*)sha->buffer,
            sizeof(sha->buffer), data, len, sha->heap);
    }

    int wc_ShaFinal(Sha* sha, byte* hash)
    {
        int ret;

        if (sha == NULL || hash == NULL)
            return BAD_FUNC_ARG;

        ret = wc_Pic32HashFinal(&sha->cache, (byte*)sha->buffer,
            hash, SHA_DIGEST_SIZE, PIC32_ALGO_SHA1, sha->heap);

        wc_InitSha_ex(sha, sha->heap, INVALID_DEVID);  /* reset state */

        return ret;
    }
    void wc_ShaSizeSet(Sha* sha, word32 len)
    {
        (void)sha;
        (void)len;
    }
#endif /* !NO_SHA */
#ifndef NO_SHA256
    int wc_InitSha256_ex(Sha256* sha256, void* heap, int devId)
    {
        if (sha256 == NULL)
            return BAD_FUNC_ARG;

        XMEMSET(sha256, 0, sizeof(Sha256));
        sha256->heap = heap;
        (void)devId;
        return 0;
    }

    int wc_Sha256Update(Sha256* sha256, const byte* data, word32 len)
    {
        if (sha256 == NULL || (data == NULL && len > 0))
            return BAD_FUNC_ARG;
        return wc_Pic32HashUpdate(&sha256->cache, (byte*)sha256->buffer,
            sizeof(sha256->buffer), data, len, sha256->heap);
    }

    int wc_Sha256Final(Sha256* sha256, byte* hash)
    {
        int ret;

        if (sha256 == NULL || hash == NULL)
            return BAD_FUNC_ARG;

        ret = wc_Pic32HashFinal(&sha256->cache, (byte*)sha256->buffer,
            hash, SHA256_DIGEST_SIZE, PIC32_ALGO_SHA256, sha256->heap);

        wc_InitSha256_ex(sha256, sha256->heap, INVALID_DEVID);  /* reset state */

        return ret;
    }

    void wc_Sha256SizeSet(Sha256* sha256, word32 len)
    {
        (void)sha256;
        (void)len;
    }
#endif /* !NO_SHA256 */
#endif


#ifdef WOLFSSL_PIC32MZ_CRYPT
#if !defined(NO_AES)
    int wc_Pic32AesCrypt(word32 *key, int keyLen, word32 *iv, int ivLen,
        byte* out, const byte* in, word32 sz,
        int dir, int algo, int cryptoalgo)
    {
        return Pic32Crypto(in, sz, (word32*)out, sz, dir, algo, cryptoalgo,
            key, keyLen, iv, ivLen);
    }
#endif /* !NO_AES */

#ifndef NO_DES3
    int wc_Pic32DesCrypt(word32 *key, int keyLen, word32 *iv, int ivLen,
        byte* out, const byte* in, word32 sz,
        int dir, int algo, int cryptoalgo)
    {
        return Pic32Crypto(in, sz, (word32*)out, sz, dir, algo, cryptoalgo,
            key, keyLen, iv, ivLen);
    }
#endif /* !NO_DES3 */
#endif /* WOLFSSL_PIC32MZ_CRYPT */

#endif /* WOLFSSL_MICROCHIP_PIC32MZ */
