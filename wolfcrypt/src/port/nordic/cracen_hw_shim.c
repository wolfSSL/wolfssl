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
    #ifdef WOLFSSL_CRACEN_PK
        #include <wolfssl/wolfcrypt/wolfmath.h>
        #ifdef HAVE_ECC
            #include <wolfssl/wolfcrypt/ecc.h>
        #endif
        #ifdef HAVE_CURVE25519
            #include <wolfssl/wolfcrypt/curve25519.h>
            #include <wolfssl/wolfcrypt/fe_operations.h>
        #endif
        #ifdef HAVE_ED25519
            #include <wolfssl/wolfcrypt/ge_operations.h>
        #endif
    #endif
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

void wc_CracenHw_TrngOff(void)
{
}

int wc_CracenHw_TrngGetStats(wc_CracenTrngStats* stats)
{
    if (stats == NULL)
        return BAD_FUNC_ARG;
    if (!gShimInit)
        return BAD_STATE_E;
    XMEMSET(stats, 0, sizeof(*stats));
    return 0;
}

#ifdef WOLFSSL_CRACEN_PK
int wc_CracenHw_PkLoadMicrocode(const word32* ucode, word32 words)
{
    (void)ucode; (void)words;
    return gShimInit ? 0 : BAD_STATE_E;
}

int wc_CracenHw_PkReady(void)
{
    return 0;
}

int wc_CracenHw_EccPtMul(const wc_CracenEcCurve* c, const byte* k,
    const byte* px, const byte* py, byte* rx, byte* ry, int cm)
{
    (void)c; (void)k; (void)px; (void)py; (void)rx; (void)ry; (void)cm;
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}

int wc_CracenHw_EccPtOnCurve(const wc_CracenEcCurve* c, const byte* px,
    const byte* py)
{
    (void)c; (void)px; (void)py;
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}

int wc_CracenHw_EccPtOrder(const wc_CracenEcCurve* c, const byte* px,
    const byte* py)
{
    (void)c; (void)px; (void)py;
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}

int wc_CracenHw_EcdsaSign(const wc_CracenEcCurve* c, const byte* d,
    const byte* k, const byte* h, byte* r, byte* s)
{
    (void)c; (void)d; (void)k; (void)h; (void)r; (void)s;
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}

int wc_CracenHw_EcdsaVerify(const wc_CracenEcCurve* c, const byte* qx,
    const byte* qy, const byte* r, const byte* s, const byte* h, int* res)
{
    (void)c; (void)qx; (void)qy; (void)r; (void)s; (void)h; (void)res;
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}

int wc_CracenHw_ModExp(const byte* base, word32 baseSz, const byte* exp,
    word32 expSz, const byte* mod, word32 modSz, byte* out, int cm)
{
    (void)base; (void)baseSz; (void)exp; (void)expSz; (void)mod; (void)modSz;
    (void)out; (void)cm;
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}

int wc_CracenHw_RsaCrt(const byte* in, word32 inSz, const byte* p, word32 pSz,
    const byte* q, word32 qSz, const byte* dP, word32 dPSz, const byte* dQ,
    word32 dQSz, const byte* qInv, word32 qInvSz, byte* out, word32 outSz,
    int cm)
{
    (void)in; (void)inSz; (void)p; (void)pSz; (void)q; (void)qSz; (void)dP;
    (void)dPSz; (void)dQ; (void)dQSz; (void)qInv; (void)qInvSz; (void)out;
    (void)outSz; (void)cm;
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}

int wc_CracenHw_X25519(const byte* k, const byte* u, byte* out)
{
    (void)k; (void)u; (void)out;
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}

int wc_CracenHw_Ed25519PtMul(const byte* scalar64, byte* pt32)
{
    (void)scalar64; (void)pt32;
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}

int wc_CracenHw_Ed25519Sign(const byte* k64, const byte* r64, const byte* s32,
    byte* sigS32)
{
    (void)k64; (void)r64; (void)s32; (void)sigS32;
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}

int wc_CracenHw_Ed25519Verify(const byte* k64, const byte* a32,
    const byte* sigS32, const byte* r32)
{
    (void)k64; (void)a32; (void)sigS32; (void)r32;
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}
#endif /* WOLFSSL_CRACEN_PK */

#else /* WOLFSSL_CRACEN_HOST_EMULATE */

static word32 gEmuRng = 0x2545F491UL;
static wc_CracenTrngStats gEmuTrng;

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
    info->pkCfg    = 0x200UL | WC_PK_HWCONFIG_PRIME_FIELD | WC_PK_HWCONFIG_P256 |
                     WC_PK_HWCONFIG_P384 | WC_PK_HWCONFIG_P521 |
                     WC_PK_HWCONFIG_P192 | WC_PK_HWCONFIG_X25519;
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
    if (gEmuTrng.starts == 0)
        gEmuTrng.starts = 1;
    for (i = 0; i < sz; i++) {
        gEmuRng ^= gEmuRng << 13;
        gEmuRng ^= gEmuRng >> 17;
        gEmuRng ^= gEmuRng << 5;
        out[i] = (byte)gEmuRng;
    }
    gEmuTrng.bytes += sz;
    return 0;
}

void wc_CracenHw_TrngOff(void)
{
    gEmuTrng.starts++;
}

int wc_CracenHw_TrngGetStats(wc_CracenTrngStats* stats)
{
    if (stats == NULL)
        return BAD_FUNC_ARG;
    if (!gShimInit)
        return BAD_STATE_E;
    *stats = gEmuTrng;
    return 0;
}

/* Public key engine, computed with wolfCrypt's own arithmetic. The emulator
 * is "ready" from init: the microcode load is accepted and ignored. */
#ifdef WOLFSSL_CRACEN_PK

int wc_CracenHw_PkLoadMicrocode(const word32* ucode, word32 words)
{
    if (ucode == NULL || words == 0 || words * 4UL > WC_PK_UCODE_MAX_BYTES)
        return BAD_FUNC_ARG;
    return gShimInit ? 0 : BAD_STATE_E;
}

int wc_CracenHw_PkReady(void)
{
    return gShimInit;
}

static int emu_be(mp_int* a, byte* out, word32 sz)
{
    if ((word32)mp_unsigned_bin_size(a) > sz)
        return MP_VAL;
    return mp_to_unsigned_bin_len(a, out, (int)sz);
}

#ifdef HAVE_ECC

typedef struct EmuEcc {
    mp_int     p, a, b, n, k, t1, t2, t3, t4, t5;
    ecc_point* P;
    ecc_point* Q;
    ecc_point* R;
    ecc_point* S;
} EmuEcc;

static void emu_ecc_free(EmuEcc* e)
{
    if (e == NULL)
        return;
    wc_ecc_del_point(e->P);
    wc_ecc_del_point(e->Q);
    wc_ecc_del_point(e->R);
    wc_ecc_del_point(e->S);
    mp_forcezero(&e->k);
    mp_forcezero(&e->t1);
    mp_forcezero(&e->t2);
    mp_forcezero(&e->t3);
    mp_forcezero(&e->t4);
    mp_forcezero(&e->t5);
    mp_clear(&e->p);
    mp_clear(&e->a);
    mp_clear(&e->b);
    mp_clear(&e->n);
    XFREE(e, NULL, DYNAMIC_TYPE_ECC);
}

static EmuEcc* emu_ecc_new(const wc_CracenEcCurve* c, int* ret)
{
    EmuEcc* e;

    if (!gShimInit) {
        *ret = BAD_STATE_E;
        return NULL;
    }
    if (c == NULL || c->sz == 0 || c->sz > WC_CRACEN_ECC_MAX_SZ ||
            c->p == NULL || c->a == NULL || c->b == NULL || c->n == NULL) {
        *ret = BAD_FUNC_ARG;
        return NULL;
    }
    e = (EmuEcc*)XMALLOC(sizeof(*e), NULL, DYNAMIC_TYPE_ECC);
    if (e == NULL) {
        *ret = MEMORY_E;
        return NULL;
    }
    XMEMSET(e, 0, sizeof(*e));
    *ret = mp_init_multi(&e->p, &e->a, &e->b, &e->n, &e->k, &e->t1);
    if (*ret == 0)
        *ret = mp_init_multi(&e->t2, &e->t3, &e->t4, &e->t5, NULL, NULL);
    if (*ret == 0) {
        e->P = wc_ecc_new_point();
        e->Q = wc_ecc_new_point();
        e->R = wc_ecc_new_point();
        e->S = wc_ecc_new_point();
        if (e->P == NULL || e->Q == NULL || e->R == NULL || e->S == NULL)
            *ret = MEMORY_E;
    }
    if (*ret == 0)
        *ret = mp_read_unsigned_bin(&e->p, c->p, c->sz);
    if (*ret == 0)
        *ret = mp_read_unsigned_bin(&e->a, c->a, c->sz);
    if (*ret == 0)
        *ret = mp_read_unsigned_bin(&e->b, c->b, c->sz);
    if (*ret == 0)
        *ret = mp_read_unsigned_bin(&e->n, c->n, c->sz);
    if (*ret != 0) {
        emu_ecc_free(e);
        e = NULL;
    }
    return e;
}

static int emu_pt_set(ecc_point* P, const byte* x, const byte* y, word32 sz)
{
    int ret = mp_read_unsigned_bin(P->x, x, sz);
    if (ret == 0)
        ret = mp_read_unsigned_bin(P->y, y, sz);
    if (ret == 0)
        ret = mp_set(P->z, 1);
    return ret;
}

static int emu_pt_get(ecc_point* P, byte* x, byte* y, word32 sz)
{
    int ret = emu_be(P->x, x, sz);
    if (ret == 0)
        ret = emu_be(P->y, y, sz);
    return ret;
}

/* R = k * P in affine coordinates; ECC_INF_E for the point at infinity. */
static int emu_pt_mul(EmuEcc* e, mp_int* k, ecc_point* P, ecc_point* R)
{
    int ret;

    if (mp_iszero(k))
        return ECC_INF_E;
    ret = wc_ecc_mulmod_ex(k, P, R, &e->a, &e->p, 1, NULL);
    if (ret == 0 && wc_ecc_point_is_at_infinity(R))
        ret = ECC_INF_E;
    return ret;
}

/* (x3, y3) = A + B on affine points, infA/infB flag the point at infinity. */
static int emu_pt_add(EmuEcc* e, ecc_point* A, int infA, ecc_point* B,
    int infB, mp_int* x3, mp_int* y3, int* inf3)
{
    mp_int* l = &e->t4;
    mp_int* t = &e->t5;
    int     ret;

    *inf3 = 0;
    if (infA && infB) {
        *inf3 = 1;
        return 0;
    }
    if (infA) {
        ret = mp_copy(B->x, x3);
        if (ret == 0)
            ret = mp_copy(B->y, y3);
        return ret;
    }
    if (infB) {
        ret = mp_copy(A->x, x3);
        if (ret == 0)
            ret = mp_copy(A->y, y3);
        return ret;
    }

    if (mp_cmp(A->x, B->x) == MP_EQ) {
        if (mp_cmp(A->y, B->y) != MP_EQ || mp_iszero(A->y)) {
            *inf3 = 1;
            return 0;
        }
        /* doubling: l = (3 x^2 + a) / (2 y) */
        ret = mp_sqrmod(A->x, &e->p, l);
        if (ret == 0)
            ret = mp_set(t, 3);
        if (ret == 0)
            ret = mp_mulmod(l, t, &e->p, l);
        if (ret == 0)
            ret = mp_addmod(l, &e->a, &e->p, l);
        if (ret == 0)
            ret = mp_addmod(A->y, A->y, &e->p, t);
    }
    else {
        /* l = (y2 - y1) / (x2 - x1) */
        ret = mp_submod(B->y, A->y, &e->p, l);
        if (ret == 0)
            ret = mp_submod(B->x, A->x, &e->p, t);
    }
    if (ret == 0)
        ret = mp_invmod(t, &e->p, t);
    if (ret == 0)
        ret = mp_mulmod(l, t, &e->p, l);
    /* x3 = l^2 - x1 - x2 */
    if (ret == 0)
        ret = mp_sqrmod(l, &e->p, t);
    if (ret == 0)
        ret = mp_submod(t, A->x, &e->p, t);
    if (ret == 0)
        ret = mp_submod(t, B->x, &e->p, t);
    /* y3 = l (x1 - x3) - y1 */
    if (ret == 0)
        ret = mp_submod(A->x, t, &e->p, y3);
    if (ret == 0)
        ret = mp_mulmod(y3, l, &e->p, y3);
    if (ret == 0)
        ret = mp_submod(y3, A->y, &e->p, y3);
    if (ret == 0)
        ret = mp_copy(t, x3);
    return ret;
}

int wc_CracenHw_EccPtMul(const wc_CracenEcCurve* c, const byte* k,
    const byte* px, const byte* py, byte* rx, byte* ry, int cm)
{
    EmuEcc* e;
    int     ret;

    (void)cm;
    if (k == NULL || px == NULL || py == NULL || rx == NULL || ry == NULL)
        return BAD_FUNC_ARG;
    e = emu_ecc_new(c, &ret);
    if (e == NULL)
        return ret;
    ret = mp_read_unsigned_bin(&e->k, k, c->sz);
    if (ret == 0)
        ret = emu_pt_set(e->P, px, py, c->sz);
    if (ret == 0)
        ret = emu_pt_mul(e, &e->k, e->P, e->R);
    if (ret == 0)
        ret = emu_pt_get(e->R, rx, ry, c->sz);
    emu_ecc_free(e);
    return ret;
}

int wc_CracenHw_EccPtOnCurve(const wc_CracenEcCurve* c, const byte* px,
    const byte* py)
{
    EmuEcc* e;
    int     ret;

    if (px == NULL || py == NULL)
        return BAD_FUNC_ARG;
    e = emu_ecc_new(c, &ret);
    if (e == NULL)
        return ret;
    ret = emu_pt_set(e->P, px, py, c->sz);
    if (ret == 0) {
        if (mp_cmp(e->P->x, &e->p) != MP_LT || mp_cmp(e->P->y, &e->p) != MP_LT)
            ret = ECC_OUT_OF_RANGE_E;
        else
            ret = wc_ecc_is_point(e->P, &e->a, &e->b, &e->p);
    }
    emu_ecc_free(e);
    return ret;
}

int wc_CracenHw_EccPtOrder(const wc_CracenEcCurve* c, const byte* px,
    const byte* py)
{
    EmuEcc* e;
    int     ret;

    if (px == NULL || py == NULL)
        return BAD_FUNC_ARG;
    e = emu_ecc_new(c, &ret);
    if (e == NULL)
        return ret;
    ret = emu_pt_set(e->P, px, py, c->sz);
    if (ret == 0)
        ret = wc_ecc_mulmod_ex(&e->n, e->P, e->R, &e->a, &e->p, 1, NULL);
    if (ret == 0 && !wc_ecc_point_is_at_infinity(e->R))
        ret = ECC_INF_E;
    emu_ecc_free(e);
    return ret;
}

int wc_CracenHw_EcdsaSign(const wc_CracenEcCurve* c, const byte* d,
    const byte* k, const byte* h, byte* r, byte* s)
{
    EmuEcc* e;
    int     ret;

    if (d == NULL || k == NULL || h == NULL || r == NULL || s == NULL ||
            c == NULL || c->gx == NULL || c->gy == NULL) {
        return BAD_FUNC_ARG;
    }
    e = emu_ecc_new(c, &ret);
    if (e == NULL)
        return ret;
    ret = mp_read_unsigned_bin(&e->k, k, c->sz);
    if (ret == 0)
        ret = mp_read_unsigned_bin(&e->t1, d, c->sz);
    if (ret == 0)
        ret = mp_read_unsigned_bin(&e->t2, h, c->sz);
    if (ret == 0)
        ret = emu_pt_set(e->P, c->gx, c->gy, c->sz);
    if (ret == 0)
        ret = emu_pt_mul(e, &e->k, e->P, e->R);
    /* r = (kG).x mod n */
    if (ret == 0)
        ret = mp_mod(e->R->x, &e->n, &e->t3);
    if (ret == 0 && mp_iszero(&e->t3))
        ret = MP_ZERO_E;
    /* s = k^-1 (h + d r) mod n */
    if (ret == 0)
        ret = mp_mulmod(&e->t1, &e->t3, &e->n, &e->t1);
    if (ret == 0)
        ret = mp_mod(&e->t2, &e->n, &e->t2);
    if (ret == 0)
        ret = mp_addmod(&e->t1, &e->t2, &e->n, &e->t1);
    if (ret == 0)
        ret = mp_invmod(&e->k, &e->n, &e->t2);
    if (ret == 0)
        ret = mp_mulmod(&e->t1, &e->t2, &e->n, &e->t1);
    if (ret == 0 && mp_iszero(&e->t1))
        ret = MP_ZERO_E;
    if (ret == 0)
        ret = emu_be(&e->t3, r, c->sz);
    if (ret == 0)
        ret = emu_be(&e->t1, s, c->sz);
    emu_ecc_free(e);
    return ret;
}

int wc_CracenHw_EcdsaVerify(const wc_CracenEcCurve* c, const byte* qx,
    const byte* qy, const byte* r, const byte* s, const byte* h, int* res)
{
    EmuEcc* e;
    int     ret;
    int     inf1 = 0;
    int     inf2 = 0;
    int     inf3 = 0;

    if (qx == NULL || qy == NULL || r == NULL || s == NULL || h == NULL ||
            res == NULL || c == NULL || c->gx == NULL || c->gy == NULL) {
        return BAD_FUNC_ARG;
    }
    *res = 0;
    e = emu_ecc_new(c, &ret);
    if (e == NULL)
        return ret;
    ret = mp_read_unsigned_bin(&e->t1, r, c->sz);
    if (ret == 0)
        ret = mp_read_unsigned_bin(&e->t2, s, c->sz);
    if (ret == 0)
        ret = mp_read_unsigned_bin(&e->t3, h, c->sz);
    if (ret == 0)
        ret = emu_pt_set(e->P, c->gx, c->gy, c->sz);
    if (ret == 0)
        ret = emu_pt_set(e->Q, qx, qy, c->sz);
    if (ret == 0 && (mp_iszero(&e->t1) || mp_iszero(&e->t2) ||
            mp_cmp(&e->t1, &e->n) != MP_LT || mp_cmp(&e->t2, &e->n) != MP_LT)) {
        emu_ecc_free(e);
        return 0;
    }
    /* w = s^-1, u1 = h w, u2 = r w */
    if (ret == 0)
        ret = mp_invmod(&e->t2, &e->n, &e->t2);
    if (ret == 0)
        ret = mp_mod(&e->t3, &e->n, &e->t3);
    if (ret == 0)
        ret = mp_mulmod(&e->t3, &e->t2, &e->n, &e->t3);
    if (ret == 0)
        ret = mp_mulmod(&e->t1, &e->t2, &e->n, &e->k);
    /* X = u1 G + u2 Q */
    if (ret == 0) {
        if (mp_iszero(&e->t3))
            inf1 = 1;
        else
            ret = emu_pt_mul(e, &e->t3, e->P, e->R);
    }
    if (ret == 0) {
        if (mp_iszero(&e->k))
            inf2 = 1;
        else
            ret = emu_pt_mul(e, &e->k, e->Q, e->S);
    }
    if (ret == 0)
        ret = emu_pt_add(e, e->R, inf1, e->S, inf2, &e->t3, &e->t2, &inf3);
    if (ret == 0 && !inf3) {
        ret = mp_mod(&e->t3, &e->n, &e->t3);
        if (ret == 0 && mp_cmp(&e->t3, &e->t1) == MP_EQ)
            *res = 1;
    }
    emu_ecc_free(e);
    return ret;
}
#endif /* HAVE_ECC */

typedef struct EmuMp {
    mp_int v[8];
} EmuMp;

static EmuMp* emu_mp_new(int* ret)
{
    EmuMp* m;

    if (!gShimInit) {
        *ret = BAD_STATE_E;
        return NULL;
    }
    m = (EmuMp*)XMALLOC(sizeof(*m), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (m == NULL) {
        *ret = MEMORY_E;
        return NULL;
    }
    XMEMSET(m, 0, sizeof(*m));
    *ret = mp_init_multi(&m->v[0], &m->v[1], &m->v[2], &m->v[3], &m->v[4],
        &m->v[5]);
    if (*ret == 0)
        *ret = mp_init_multi(&m->v[6], &m->v[7], NULL, NULL, NULL, NULL);
    if (*ret != 0) {
        XFREE(m, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        m = NULL;
    }
    return m;
}

static void emu_mp_free(EmuMp* m)
{
    int i;

    if (m == NULL)
        return;
    for (i = 0; i < 8; i++)
        mp_forcezero(&m->v[i]);
    XFREE(m, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

int wc_CracenHw_ModExp(const byte* base, word32 baseSz, const byte* exp,
    word32 expSz, const byte* mod, word32 modSz, byte* out, int cm)
{
    EmuMp* m;
    int    ret;

    (void)cm;
    if (base == NULL || exp == NULL || mod == NULL || out == NULL)
        return BAD_FUNC_ARG;
    if (modSz == 0 || baseSz > modSz || expSz > modSz)
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    m = emu_mp_new(&ret);
    if (m == NULL)
        return ret;
    ret = mp_read_unsigned_bin(&m->v[0], base, baseSz);
    if (ret == 0)
        ret = mp_read_unsigned_bin(&m->v[1], exp, expSz);
    if (ret == 0)
        ret = mp_read_unsigned_bin(&m->v[2], mod, modSz);
    if (ret == 0 && mp_iszero(&m->v[2]))
        ret = MP_VAL;
    if (ret == 0)
        ret = mp_exptmod(&m->v[0], &m->v[1], &m->v[2], &m->v[3]);
    if (ret == 0)
        ret = emu_be(&m->v[3], out, modSz);
    emu_mp_free(m);
    return ret;
}

int wc_CracenHw_RsaCrt(const byte* in, word32 inSz, const byte* p, word32 pSz,
    const byte* q, word32 qSz, const byte* dP, word32 dPSz, const byte* dQ,
    word32 dQSz, const byte* qInv, word32 qInvSz, byte* out, word32 outSz,
    int cm)
{
    EmuMp*  m;
    mp_int* c;
    mp_int* mp;
    mp_int* mq;
    mp_int* h;
    int     ret;

    (void)cm;
    if (in == NULL || p == NULL || q == NULL || dP == NULL || dQ == NULL ||
            qInv == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }
    if (outSz == 0 || inSz > outSz)
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    m = emu_mp_new(&ret);
    if (m == NULL)
        return ret;
    c  = &m->v[0];
    mp = &m->v[1];
    mq = &m->v[2];
    h  = &m->v[3];
    ret = mp_read_unsigned_bin(c, in, inSz);
    if (ret == 0)
        ret = mp_read_unsigned_bin(&m->v[4], p, pSz);
    if (ret == 0)
        ret = mp_read_unsigned_bin(&m->v[5], q, qSz);
    if (ret == 0)
        ret = mp_read_unsigned_bin(&m->v[6], dP, dPSz);
    if (ret == 0)
        ret = mp_read_unsigned_bin(&m->v[7], dQ, dQSz);
    if (ret == 0 && (mp_iszero(&m->v[4]) || mp_iszero(&m->v[5])))
        ret = MP_VAL;
    if (ret == 0)
        ret = mp_exptmod(c, &m->v[6], &m->v[4], mp);
    if (ret == 0)
        ret = mp_exptmod(c, &m->v[7], &m->v[5], mq);
    if (ret == 0)
        ret = mp_read_unsigned_bin(&m->v[6], qInv, qInvSz);
    /* h = qInv (mp - mq) mod p, out = mq + h q */
    if (ret == 0)
        ret = mp_mod(mq, &m->v[4], h);
    if (ret == 0)
        ret = mp_submod(mp, h, &m->v[4], h);
    if (ret == 0)
        ret = mp_mulmod(h, &m->v[6], &m->v[4], h);
    if (ret == 0)
        ret = mp_mul(h, &m->v[5], h);
    if (ret == 0)
        ret = mp_add(h, mq, h);
    if (ret == 0)
        ret = emu_be(h, out, outSz);
    emu_mp_free(m);
    return ret;
}

#ifdef HAVE_CURVE25519
int wc_CracenHw_X25519(const byte* k, const byte* u, byte* out)
{
    byte kk[CURVE25519_KEYSIZE];
    byte uu[CURVE25519_KEYSIZE];
    int  ret;

    if (!gShimInit)
        return BAD_STATE_E;
    if (k == NULL || u == NULL || out == NULL)
        return BAD_FUNC_ARG;
    XMEMCPY(kk, k, sizeof(kk));
    XMEMCPY(uu, u, sizeof(uu));
    kk[0]  &= 0xF8;
    kk[31]  = (byte)((kk[31] | 0x40) & 0x7F);
    uu[31] &= 0x7F;
    fe_init();
#ifdef WOLFSSL_CURVE25519_BLINDING
    {
        /* the blinded ladder with a zero mask and z = 1: same result */
        byte na[CURVE25519_KEYSIZE];
        byte a[CURVE25519_KEYSIZE];
        byte rz[CURVE25519_KEYSIZE];
        int  i;

        XMEMSET(a, 0, sizeof(a));
        XMEMSET(rz, 0, sizeof(rz));
        rz[0] = 1;
        na[0] = (byte)(kk[0] ^ (byte)(kk[0] << 1));
        for (i = 1; i < CURVE25519_KEYSIZE; i++) {
            na[i] = (byte)(kk[i] ^ (byte)(kk[i] << 1) ^
                           (byte)(kk[i - 1] >> 7));
        }
        ret = curve25519_blind(out, na, a, uu, rz);
        ForceZero(na, sizeof(na));
    }
#else
    ret = curve25519(out, kk, uu);
#endif
    ForceZero(kk, sizeof(kk));
    return ret;
}
#endif /* HAVE_CURVE25519 */

#ifdef HAVE_ED25519
int wc_CracenHw_Ed25519PtMul(const byte* scalar64, byte* pt32)
{
    byte  s[64];
    ge_p3 A;

    if (!gShimInit)
        return BAD_STATE_E;
    if (scalar64 == NULL || pt32 == NULL)
        return BAD_FUNC_ARG;
    XMEMCPY(s, scalar64, sizeof(s));
    sc_reduce(s);
    ge_scalarmult_base(&A, s);
    ge_p3_tobytes(pt32, &A);
    ForceZero(s, sizeof(s));
    ForceZero(&A, sizeof(A));
    return 0;
}

int wc_CracenHw_Ed25519Sign(const byte* k64, const byte* r64, const byte* s32,
    byte* sigS32)
{
    byte k[64];
    byte r[64];

    if (!gShimInit)
        return BAD_STATE_E;
    if (k64 == NULL || r64 == NULL || s32 == NULL || sigS32 == NULL)
        return BAD_FUNC_ARG;
    XMEMCPY(k, k64, sizeof(k));
    XMEMCPY(r, r64, sizeof(r));
    sc_reduce(k);
    sc_reduce(r);
    sc_muladd(sigS32, k, s32, r);
    ForceZero(k, sizeof(k));
    ForceZero(r, sizeof(r));
    return 0;
}

int wc_CracenHw_Ed25519Verify(const byte* k64, const byte* a32,
    const byte* sigS32, const byte* r32)
{
    byte  h[64];
    byte  rc[32];
    ge_p3 A;
    ge_p2 R;

    if (!gShimInit)
        return BAD_STATE_E;
    if (k64 == NULL || a32 == NULL || sigS32 == NULL || r32 == NULL)
        return BAD_FUNC_ARG;
    if (ge_frombytes_negate_vartime(&A, a32) != 0)
        return SIG_VERIFY_E;
    XMEMCPY(h, k64, sizeof(h));
    sc_reduce(h);
    if (ge_double_scalarmult_vartime(&R, h, &A, sigS32) != 0)
        return SIG_VERIFY_E;
    ge_tobytes(rc, &R);
    if (ConstantCompare(rc, r32, sizeof(rc)) != 0)
        return SIG_VERIFY_E;
    return 0;
}
#endif /* HAVE_ED25519 */

#endif /* WOLFSSL_CRACEN_PK */

#endif /* WOLFSSL_CRACEN_HOST_EMULATE */

#endif /* WOLFSSL_NRF54L_CRACEN && WOLFSSL_CRACEN_HOST_TEST */
