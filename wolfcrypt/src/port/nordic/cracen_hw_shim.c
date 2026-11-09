/* cracen_hw_shim.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

/* Host-compile stand-in for cracen_hw_bare.c.
 *
 * WOLFSSL_CRACEN_HOST_TEST alone: reports no engines and declines every
 * operation, so the callback wiring and the software fall-back paths build
 * and run on a PC.
 *
 * With WOLFSSL_CRACEN_HOST_EMULATE: computes every operation in software
 * behind the same interface the register driver implements, with the same
 * contract (whole blocks, state export, pre-padded final data, invalid tail
 * bytes for CMAC). The emulated state formats are private to this file; the
 * callers treat them as opaque, exactly as they do the hardware's. Lets the
 * test suite exercise the streaming, padding and counter logic of the
 * callback handlers on the host. The emulated TRNG is a fixed-seed generator
 * and is not entropy. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_NRF54L_CRACEN) && defined(WOLFSSL_CRACEN_HOST_TEST)

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/port/nordic/cracen_regs.h>
#include <wolfssl/wolfcrypt/port/nordic/cracen_hw.h>

#ifdef WOLFSSL_CRACEN_HOST_EMULATE
    #include <wolfssl/wolfcrypt/sha.h>
    #include <wolfssl/wolfcrypt/sha256.h>
    #include <wolfssl/wolfcrypt/sha512.h>
    #include <wolfssl/wolfcrypt/aes.h>
    #ifdef NO_INLINE
        #include <wolfssl/wolfcrypt/misc.h>
    #else
        #define WOLFSSL_MISC_INCLUDED
        #include <wolfcrypt/src/misc.c>
    #endif
#endif

static int gShimInit = 0;

#ifndef WOLFSSL_CRACEN_HOST_EMULATE

int wc_CracenHw_Init(void)
{
    gShimInit = 1;
    return 0;
}

void wc_CracenHw_Cleanup(void)
{
    gShimInit = 0;
}

int wc_CracenHw_GetInfo(wc_CracenHwInfo* info)
{
    if (info == NULL)
        return BAD_FUNC_ARG;
    if (!gShimInit)
        return BAD_STATE_E;
    XMEMSET(info, 0, sizeof(*info));
    return 0;
}

int wc_CracenHw_Hash(word32 algo, const byte* state, word32 stateSz,
    const byte* data, word32 dataSz, byte* out, word32 outSz, int final)
{
    (void)algo; (void)state; (void)stateSz; (void)data; (void)dataSz;
    (void)out; (void)outSz; (void)final;
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}

int wc_CracenHw_AesCrypt(word32 mode, int decrypt, const byte* key,
    word32 keySz, const byte* iv, const wc_CracenSeg* segs, int nSegs)
{
    (void)mode; (void)decrypt; (void)key; (void)keySz; (void)iv; (void)segs;
    (void)nSegs;
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}

int wc_CracenHw_AesGcm(int decrypt, const byte* key, word32 keySz,
    const byte* iv, const byte* aad, word32 aadSz, const byte* in, word32 sz,
    byte* out, byte* tag, word32 tagSz)
{
    (void)decrypt; (void)key; (void)keySz; (void)iv; (void)aad; (void)aadSz;
    (void)in; (void)sz; (void)out; (void)tag; (void)tagSz;
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}

int wc_CracenHw_AesCmac(const byte* key, word32 keySz, const byte* state,
    const byte* data, word32 dataSz, const byte* tail, word32 tailSz,
    byte* out, int final)
{
    (void)key; (void)keySz; (void)state; (void)data; (void)dataSz; (void)tail;
    (void)tailSz; (void)out; (void)final;
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}

int wc_CracenHw_TrngRead(byte* out, word32 sz)
{
    (void)out; (void)sz;
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}

#else /* WOLFSSL_CRACEN_HOST_EMULATE */

static word32 gEmuRng = 0x2545F491UL;

int wc_CracenHw_Init(void)
{
    gShimInit = 1;
    return 0;
}

void wc_CracenHw_Cleanup(void)
{
    gShimInit = 0;
}

int wc_CracenHw_GetInfo(wc_CracenHwInfo* info)
{
    if (info == NULL)
        return BAD_FUNC_ARG;
    if (!gShimInit)
        return BAD_STATE_E;
    XMEMSET(info, 0, sizeof(*info));
    info->engines  = WC_CM_HW_BA411_AES | WC_CM_HW_BA413_HASH |
                     WC_CM_HW_BA431_NDRNG;
    info->aesModes = WC_CM_HW_BA411_MODES_MASK;
    info->aesCtrSz = 128;
    info->hashCfg  = WC_CM_HASH_ALGO_SHA1 | WC_CM_HASH_ALGO_SHA224 |
                     WC_CM_HASH_ALGO_SHA256 | WC_CM_HASH_ALGO_SHA384 |
                     WC_CM_HASH_ALGO_SHA512 | WC_CM_HW_BA413_HW_PADDING;
    return 0;
}

static void emu_put_be32(byte* p, word32 v)
{
    p[0] = (byte)(v >> 24);
    p[1] = (byte)(v >> 16);
    p[2] = (byte)(v >> 8);
    p[3] = (byte)v;
}

/* Emulated hash state: the software object's digest words, copied raw. The
 * data is whole blocks, so an Update leaves nothing buffered; a final request
 * already carries the padding and the digest is the big-endian state. */
int wc_CracenHw_Hash(word32 algo, const byte* state, word32 stateSz,
    const byte* data, word32 dataSz, byte* out, word32 outSz, int final)
{
    int    ret = 0;
    word32 i;

    if (!gShimInit)
        return BAD_STATE_E;
    if (out == NULL || (dataSz == 0 && state == NULL) || (dataSz & 3) != 0)
        return BAD_FUNC_ARG;

    switch (algo) {
#ifndef NO_SHA
        case WC_CM_HASH_ALGO_SHA1:
        {
            wc_Sha sha;
            if (stateSz != WC_SHA_DIGEST_SIZE || (dataSz % WC_SHA_BLOCK_SIZE) != 0)
                return BAD_FUNC_ARG;
            ret = wc_InitSha_ex(&sha, NULL, INVALID_DEVID);
            if (ret == 0 && state != NULL)
                XMEMCPY(sha.digest, state, stateSz);
            if (ret == 0 && dataSz > 0)
                ret = wc_ShaUpdate(&sha, data, dataSz);
            if (ret == 0) {
                if (final) {
                    for (i = 0; i < outSz / 4; i++)
                        emu_put_be32(out + 4 * i, sha.digest[i]);
                }
                else {
                    XMEMCPY(out, sha.digest, stateSz);
                }
            }
            wc_ShaFree(&sha);
            break;
        }
#endif
#ifndef NO_SHA256
        case WC_CM_HASH_ALGO_SHA224:
        case WC_CM_HASH_ALGO_SHA256:
        {
            wc_Sha256 sha;
            if (stateSz != WC_SHA256_DIGEST_SIZE ||
                    (dataSz % WC_SHA256_BLOCK_SIZE) != 0) {
                return BAD_FUNC_ARG;
            }
            ret = wc_InitSha256_ex(&sha, NULL, INVALID_DEVID);
            if (ret == 0 && algo == WC_CM_HASH_ALGO_SHA224 && state == NULL) {
                /* SHA-224 initial values */
                static const word32 iv224[8] = {
                    0xc1059ed8UL, 0x367cd507UL, 0x3070dd17UL, 0xf70e5939UL,
                    0xffc00b31UL, 0x68581511UL, 0x64f98fa7UL, 0xbefa4fa4UL
                };
                XMEMCPY(sha.digest, iv224, sizeof(iv224));
            }
            if (ret == 0 && state != NULL)
                XMEMCPY(sha.digest, state, stateSz);
            if (ret == 0 && dataSz > 0)
                ret = wc_Sha256Update(&sha, data, dataSz);
            if (ret == 0) {
                if (final) {
                    for (i = 0; i < outSz / 4; i++)
                        emu_put_be32(out + 4 * i, sha.digest[i]);
                }
                else {
                    XMEMCPY(out, sha.digest, stateSz);
                }
            }
            wc_Sha256Free(&sha);
            break;
        }
#endif
#if defined(WOLFSSL_SHA384) || defined(WOLFSSL_SHA512)
        case WC_CM_HASH_ALGO_SHA384:
        case WC_CM_HASH_ALGO_SHA512:
        {
            wc_Sha512 sha;
            if (stateSz != WC_SHA512_DIGEST_SIZE ||
                    (dataSz % WC_SHA512_BLOCK_SIZE) != 0) {
                return BAD_FUNC_ARG;
            }
    #ifdef WOLFSSL_SHA384
            if (algo == WC_CM_HASH_ALGO_SHA384)
                ret = wc_InitSha384_ex((wc_Sha384*)&sha, NULL, INVALID_DEVID);
            else
    #endif
    #ifdef WOLFSSL_SHA512
                ret = wc_InitSha512_ex(&sha, NULL, INVALID_DEVID);
    #else
                return BAD_FUNC_ARG;
    #endif
            if (ret == 0 && state != NULL)
                XMEMCPY(sha.digest, state, stateSz);
            if (ret == 0 && dataSz > 0)
                ret = wc_Sha512Update(&sha, data, dataSz);
            if (ret == 0) {
                if (final) {
                    for (i = 0; i < outSz / 8; i++) {
                        emu_put_be32(out + 8 * i, (word32)(sha.digest[i] >> 32));
                        emu_put_be32(out + 8 * i + 4, (word32)sha.digest[i]);
                    }
                }
                else {
                    XMEMCPY(out, sha.digest, stateSz);
                }
            }
            wc_Sha512Free(&sha);
            break;
        }
#endif
        default:
            ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
            break;
    }
    return ret;
}

#ifndef NO_AES
int wc_CracenHw_AesCrypt(word32 mode, int decrypt, const byte* key,
    word32 keySz, const byte* iv, const wc_CracenSeg* segs, int nSegs)
{
    Aes aes;
    int i;
    int ret;

    if (!gShimInit)
        return BAD_STATE_E;
    if (key == NULL || segs == NULL || nSegs < 1)
        return BAD_FUNC_ARG;

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0)
        return ret;

    switch (mode) {
#if defined(HAVE_AES_ECB) || defined(WOLFSSL_AES_DIRECT)
        case WC_CM_AES_MODE_ECB:
            ret = wc_AesSetKey(&aes, key, keySz, NULL,
                decrypt ? AES_DECRYPTION : AES_ENCRYPTION);
            for (i = 0; ret == 0 && i < nSegs; i++) {
                ret = decrypt ?
                    wc_AesEcbDecrypt(&aes, segs[i].out, segs[i].in, segs[i].sz) :
                    wc_AesEcbEncrypt(&aes, segs[i].out, segs[i].in, segs[i].sz);
            }
            break;
#endif
#ifdef HAVE_AES_CBC
        case WC_CM_AES_MODE_CBC:
            ret = wc_AesSetKey(&aes, key, keySz, iv,
                decrypt ? AES_DECRYPTION : AES_ENCRYPTION);
            for (i = 0; ret == 0 && i < nSegs; i++) {
                ret = decrypt ?
                    wc_AesCbcDecrypt(&aes, segs[i].out, segs[i].in, segs[i].sz) :
                    wc_AesCbcEncrypt(&aes, segs[i].out, segs[i].in, segs[i].sz);
            }
            break;
#endif
#ifdef WOLFSSL_AES_COUNTER
        case WC_CM_AES_MODE_CTR:
            ret = wc_AesSetKeyDirect(&aes, key, keySz, iv, AES_ENCRYPTION);
            for (i = 0; ret == 0 && i < nSegs; i++)
                ret = wc_AesCtrEncrypt(&aes, segs[i].out, segs[i].in, segs[i].sz);
            break;
#endif
        default:
            ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
            break;
    }
    wc_AesFree(&aes);
    return ret;
}

#ifdef HAVE_AESGCM
/* Decrypt is emulated with two passes: CTR is its own inverse, so an encrypt
 * of the ciphertext yields the plaintext, and an encrypt of that plaintext
 * yields the tag over the original ciphertext. */
int wc_CracenHw_AesGcm(int decrypt, const byte* key, word32 keySz,
    const byte* iv, const byte* aad, word32 aadSz, const byte* in, word32 sz,
    byte* out, byte* tag, word32 tagSz)
{
    Aes   aes;
    byte  scratchTag[WC_AES_BLOCK_SIZE];
    byte* tmp = NULL;
    int   ret;

    if (!gShimInit)
        return BAD_STATE_E;
    if (key == NULL || iv == NULL || tag == NULL || tagSz < 4 || tagSz > 16)
        return BAD_FUNC_ARG;

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret == 0)
        ret = wc_AesGcmSetKey(&aes, key, keySz);
    if (ret == 0) {
        if (!decrypt) {
            ret = wc_AesGcmEncrypt(&aes, out, in, sz, iv, 12, tag, tagSz, aad,
                aadSz);
        }
        else {
            if (sz > 0) {
                tmp = (byte*)XMALLOC(sz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (tmp == NULL)
                    ret = MEMORY_E;
            }
            if (ret == 0) {
                ret = wc_AesGcmEncrypt(&aes, out, in, sz, iv, 12, scratchTag,
                    tagSz, aad, aadSz);
            }
            if (ret == 0) {
                ret = wc_AesGcmEncrypt(&aes, tmp, out, sz, iv, 12, tag, tagSz,
                    aad, aadSz);
            }
            if (tmp != NULL)
                XFREE(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }
    wc_AesFree(&aes);
    return ret;
}
#endif /* HAVE_AESGCM */

#if defined(WOLFSSL_AES_DIRECT) || defined(HAVE_AES_ECB)
static void emu_dbl(byte* b)
{
    int  i;
    byte carry = (byte)(b[0] & 0x80);
    for (i = 0; i < WC_AES_BLOCK_SIZE - 1; i++)
        b[i] = (byte)((b[i] << 1) | (b[i + 1] >> 7));
    b[WC_AES_BLOCK_SIZE - 1] = (byte)(b[WC_AES_BLOCK_SIZE - 1] << 1);
    if (carry)
        b[WC_AES_BLOCK_SIZE - 1] ^= 0x87;
}

/* Emulated CMAC state: the CBC-MAC chaining value before the final block. */
int wc_CracenHw_AesCmac(const byte* key, word32 keySz, const byte* state,
    const byte* data, word32 dataSz, const byte* tail, word32 tailSz,
    byte* out, int final)
{
    Aes    aes;
    byte   x[WC_AES_BLOCK_SIZE];
    byte   blk[WC_AES_BLOCK_SIZE];
    byte   k[WC_AES_BLOCK_SIZE];
    word32 off;
    int    ret;

    if (!gShimInit)
        return BAD_STATE_E;
    if (key == NULL || out == NULL || (dataSz & 15) != 0 || tailSz > 16)
        return BAD_FUNC_ARG;

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret == 0)
        ret = wc_AesSetKey(&aes, key, keySz, NULL, AES_ENCRYPTION);
    if (ret != 0)
        return ret;

    if (state != NULL)
        XMEMCPY(x, state, sizeof(x));
    else
        XMEMSET(x, 0, sizeof(x));

    for (off = 0; ret == 0 && off < dataSz; off += WC_AES_BLOCK_SIZE) {
        xorbufout(blk, x, data + off, WC_AES_BLOCK_SIZE);
        ret = wc_AesEncryptDirect(&aes, x, blk);
    }

    if (ret == 0 && final) {
        XMEMSET(k, 0, sizeof(k));
        ret = wc_AesEncryptDirect(&aes, k, k);   /* L */
        if (ret == 0) {
            emu_dbl(k);                          /* K1 */
            XMEMSET(blk, 0, sizeof(blk));
            if (tailSz > 0)
                XMEMCPY(blk, tail, tailSz);
            if (tailSz < WC_AES_BLOCK_SIZE) {
                blk[tailSz] = 0x80;
                emu_dbl(k);                      /* K2 */
            }
            xorbuf(blk, k, WC_AES_BLOCK_SIZE);
            xorbuf(blk, x, WC_AES_BLOCK_SIZE);
            ret = wc_AesEncryptDirect(&aes, x, blk);
        }
    }
    if (ret == 0)
        XMEMCPY(out, x, sizeof(x));

    wc_AesFree(&aes);
    ForceZero(k, sizeof(k));
    return ret;
}
#endif /* WOLFSSL_AES_DIRECT || HAVE_AES_ECB */
#endif /* !NO_AES */

int wc_CracenHw_TrngRead(byte* out, word32 sz)
{
    word32 i;

    if (!gShimInit)
        return BAD_STATE_E;
    if (out == NULL && sz > 0)
        return BAD_FUNC_ARG;
    for (i = 0; i < sz; i++) {
        gEmuRng ^= gEmuRng << 13;
        gEmuRng ^= gEmuRng >> 17;
        gEmuRng ^= gEmuRng << 5;
        out[i] = (byte)gEmuRng;
    }
    return 0;
}

#endif /* WOLFSSL_CRACEN_HOST_EMULATE */

#endif /* WOLFSSL_NRF54L_CRACEN && WOLFSSL_CRACEN_HOST_TEST */
