/* cracen_cb_cipher.c
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

/* AES ECB/CBC/CTR/GCM through the BA411E engine.
 *
 * The raw key comes from aes->devKey, which wc_AesSetKey() fills for any Aes
 * that carries a devId. Chaining state stays where software keeps it: aes->reg
 * is the CBC chaining block or the CTR counter and aes->tmp/aes->left hold
 * the unused CTR key stream, so a request may be declined to software at any
 * call boundary without losing position in the stream. CCM is not offloaded.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_NRF54L_CRACEN) && defined(WOLFSSL_CRACEN_CIPHER) && \
    !defined(NO_AES)

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/port/nordic/cracen_regs.h>
#include <wolfssl/wolfcrypt/port/nordic/cracen_cryptocb.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

static int cracen_aes_key(const Aes* aes, const byte** key, word32* keySz)
{
    if (aes->keylen != 16 && aes->keylen != 24 && aes->keylen != 32)
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    *key   = (const byte*)aes->devKey;
    *keySz = (word32)aes->keylen;
    return 0;
}

static int cracen_aes_mode_ok(word32 mode)
{
    wc_CracenHwInfo hw;

    if (wc_CracenHw_GetInfo(&hw) != 0)
        return 0;
    return (hw.engines & WC_CM_HW_BA411_AES) != 0 &&
           (hw.aesModes & (mode >> WC_CM_AES_CFG_MODE_SHIFT)) != 0;
}

#if defined(HAVE_AES_ECB) || defined(WOLFSSL_AES_DIRECT) || \
    defined(WOLF_CRYPTO_CB_ONLY_AES)
static int cracen_cipher_ecb(wc_CryptoInfo* info)
{
    Aes*         aes = info->cipher.aesecb.aes;
    const byte*  key;
    word32       keySz;
    wc_CracenSeg seg;
    int          ret;

    if (aes == NULL)
        return BAD_FUNC_ARG;
    if (info->cipher.aesecb.sz == 0)
        return 0;
    if (info->cipher.aesecb.in == NULL || info->cipher.aesecb.out == NULL ||
            (info->cipher.aesecb.sz & 15) != 0 ||
            info->cipher.aesecb.sz >= WC_CM_MAX_LEN ||
            !cracen_aes_mode_ok(WC_CM_AES_MODE_ECB)) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    ret = cracen_aes_key(aes, &key, &keySz);
    if (ret != 0)
        return ret;

    seg.in  = info->cipher.aesecb.in;
    seg.out = info->cipher.aesecb.out;
    seg.sz  = info->cipher.aesecb.sz;
    return wc_CracenHw_AesCrypt(WC_CM_AES_MODE_ECB, !info->cipher.enc, key,
        keySz, NULL, &seg, 1);
}
#endif

#ifdef HAVE_AES_CBC
static int cracen_cipher_cbc(wc_CryptoInfo* info)
{
    Aes*         aes = info->cipher.aescbc.aes;
    const byte*  in  = info->cipher.aescbc.in;
    byte*        out = info->cipher.aescbc.out;
    word32       sz  = info->cipher.aescbc.sz;
    const byte*  key;
    word32       keySz;
    wc_CracenSeg seg;
    byte         lastIn[WC_AES_BLOCK_SIZE];
    int          ret;

    if (aes == NULL)
        return BAD_FUNC_ARG;
    if (sz == 0)
        return 0;
    if (in == NULL || out == NULL || (sz & 15) != 0 || sz >= WC_CM_MAX_LEN ||
            !cracen_aes_mode_ok(WC_CM_AES_MODE_CBC)) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    ret = cracen_aes_key(aes, &key, &keySz);
    if (ret != 0)
        return ret;

    /* in may alias out */
    if (!info->cipher.enc)
        XMEMCPY(lastIn, in + sz - WC_AES_BLOCK_SIZE, WC_AES_BLOCK_SIZE);

    seg.in  = in;
    seg.out = out;
    seg.sz  = sz;
    ret = wc_CracenHw_AesCrypt(WC_CM_AES_MODE_CBC, !info->cipher.enc, key,
        keySz, (const byte*)aes->reg, &seg, 1);
    if (ret == 0) {
        if (info->cipher.enc)
            XMEMCPY(aes->reg, out + sz - WC_AES_BLOCK_SIZE, WC_AES_BLOCK_SIZE);
        else
            XMEMCPY(aes->reg, lastIn, WC_AES_BLOCK_SIZE);
    }
    ForceZero(lastIn, sizeof(lastIn));
    return ret;
}
#endif /* HAVE_AES_CBC */

#ifdef WOLFSSL_AES_COUNTER
/* Big-endian add of n to a 128-bit counter, as the software CTR does once per
 * block. */
static void cracen_ctr_add(byte* ctr, word32 n)
{
    int    i;
    word32 carry = n;

    for (i = WC_AES_BLOCK_SIZE - 1; i >= 0 && carry != 0; i--) {
        word32 s = (word32)ctr[i] + (carry & 0xFF);
        ctr[i] = (byte)s;
        carry = (carry >> 8) + (s >> 8);
    }
}

static int cracen_cipher_ctr(wc_CryptoInfo* info)
{
    Aes*            aes = info->cipher.aesctr.aes;
    const byte*     in  = info->cipher.aesctr.in;
    byte*           out = info->cipher.aesctr.out;
    word32          sz  = info->cipher.aesctr.sz;
    const byte*     key;
    word32          keySz;
    wc_CracenHwInfo hw;
    wc_CracenSeg    segs[2];
    byte            padIn[WC_AES_BLOCK_SIZE];
    word32          drain;
    word32          rest;
    word32          full;
    word32          rem;
    word32          nBlocks;
    int             nSegs = 0;
    int             ret;

    if (aes == NULL)
        return BAD_FUNC_ARG;
    if (sz == 0)
        return 0;
    if (in == NULL || out == NULL || sz >= WC_CM_MAX_LEN ||
            aes->left > WC_AES_BLOCK_SIZE || wc_CracenHw_GetInfo(&hw) != 0 ||
            (hw.engines & WC_CM_HW_BA411_AES) == 0 ||
            (hw.aesModes & (WC_CM_AES_MODE_CTR >> WC_CM_AES_CFG_MODE_SHIFT)) == 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    ret = cracen_aes_key(aes, &key, &keySz);
    if (ret != 0)
        return ret;

    drain   = (aes->left < sz) ? aes->left : sz;
    rest    = sz - drain;
    full    = rest & ~15UL;
    rem     = rest & 15UL;
    nBlocks = full / WC_AES_BLOCK_SIZE + (rem != 0 ? 1 : 0);

    /* Software increments all 128 bits of the counter. Unless the engine
     * reports a 128-bit counter, assume it wraps at 32 bits and leave any
     * operation that would carry past them to software. Decided before any
     * state is touched so a decline is clean. */
    if (nBlocks > 0 && hw.aesCtrSz != 128) {
        const byte* c = (const byte*)aes->reg + 12;
        word32 ctrLo = ((word32)c[0] << 24) | ((word32)c[1] << 16) |
                       ((word32)c[2] << 8) | (word32)c[3];
        if (nBlocks > 0xFFFFFFFFUL - ctrLo)
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    if (drain > 0) {
        xorbufout(out, in, (byte*)aes->tmp + WC_AES_BLOCK_SIZE - aes->left,
            drain);
        out += drain;
        in  += drain;
        aes->left -= drain;
    }
    if (rest == 0)
        return 0;

    if (full > 0) {
        segs[nSegs].in  = in;
        segs[nSegs].out = out;
        segs[nSegs].sz  = full;
        nSegs++;
    }
    if (rem > 0) {
        /* The padded tail block lands in aes->tmp: its first rem bytes are
         * the output, the rest is key stream for the next call. */
        XMEMSET(padIn, 0, sizeof(padIn));
        XMEMCPY(padIn, in + full, rem);
        segs[nSegs].in  = padIn;
        segs[nSegs].out = (byte*)aes->tmp;
        segs[nSegs].sz  = WC_AES_BLOCK_SIZE;
        nSegs++;
    }

    ret = wc_CracenHw_AesCrypt(WC_CM_AES_MODE_CTR, !info->cipher.enc, key,
        keySz, (const byte*)aes->reg, segs, nSegs);
    if (ret == 0) {
        if (rem > 0) {
            XMEMCPY(out + full, aes->tmp, rem);
            aes->left = WC_AES_BLOCK_SIZE - rem;
        }
        cracen_ctr_add((byte*)aes->reg, nBlocks);
    }
    else if (ret == WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
        /* the drain above already consumed key stream */
        ret = WC_HW_E;
    }
    ForceZero(padIn, sizeof(padIn));
    return ret;
}
#endif /* WOLFSSL_AES_COUNTER */

#ifdef HAVE_AESGCM
static int cracen_cipher_gcm(wc_CryptoInfo* info)
{
    Aes*        aes;
    const byte* key;
    word32      keySz;
    const byte* in;
    byte*       out;
    word32      sz;
    const byte* iv;
    word32      ivSz;
    const byte* authIn;
    word32      authInSz;
    word32      authTagSz;
    byte        tag[WC_AES_BLOCK_SIZE];
    int         ret;

    if (info->cipher.enc) {
        aes       = info->cipher.aesgcm_enc.aes;
        in        = info->cipher.aesgcm_enc.in;
        out       = info->cipher.aesgcm_enc.out;
        sz        = info->cipher.aesgcm_enc.sz;
        iv        = info->cipher.aesgcm_enc.iv;
        ivSz      = info->cipher.aesgcm_enc.ivSz;
        authIn    = info->cipher.aesgcm_enc.authIn;
        authInSz  = info->cipher.aesgcm_enc.authInSz;
        authTagSz = info->cipher.aesgcm_enc.authTagSz;
    }
    else {
        aes       = info->cipher.aesgcm_dec.aes;
        in        = info->cipher.aesgcm_dec.in;
        out       = info->cipher.aesgcm_dec.out;
        sz        = info->cipher.aesgcm_dec.sz;
        iv        = info->cipher.aesgcm_dec.iv;
        ivSz      = info->cipher.aesgcm_dec.ivSz;
        authIn    = info->cipher.aesgcm_dec.authIn;
        authInSz  = info->cipher.aesgcm_dec.authInSz;
        authTagSz = info->cipher.aesgcm_dec.authTagSz;
    }

    if (aes == NULL)
        return BAD_FUNC_ARG;
    /* The engine forms J0 from a 96-bit IV only. */
    if (iv == NULL || ivSz != GCM_NONCE_MID_SZ || authTagSz < 4 ||
            authTagSz > WC_AES_BLOCK_SIZE || sz >= WC_CM_MAX_LEN ||
            authInSz >= WC_CM_MAX_LEN ||
            (sz > 0 && (in == NULL || out == NULL)) ||
            (authInSz > 0 && authIn == NULL) ||
            !cracen_aes_mode_ok(WC_CM_AES_MODE_GCM)) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    ret = cracen_aes_key(aes, &key, &keySz);
    if (ret != 0)
        return ret;

    if (info->cipher.enc) {
        return wc_CracenHw_AesGcm(0, key, keySz, iv, authIn, authInSz, in, sz,
            out, info->cipher.aesgcm_enc.authTag, authTagSz);
    }

    ret = wc_CracenHw_AesGcm(1, key, keySz, iv, authIn, authInSz, in, sz, out,
        tag, authTagSz);
    if (ret == 0 && ConstantCompare(tag, info->cipher.aesgcm_dec.authTag,
            (int)authTagSz) != 0) {
        if (out != NULL && sz > 0)
            ForceZero(out, sz);
        ret = AES_GCM_AUTH_E;
    }
    ForceZero(tag, sizeof(tag));
    return ret;
}
#endif /* HAVE_AESGCM */

int wc_CracenCipher(wc_CryptoInfo* info)
{
    int ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);

    if (info == NULL)
        return BAD_FUNC_ARG;
    if (info->algo_type != WC_ALGO_TYPE_CIPHER)
        return ret;

    switch (info->cipher.type) {
#if defined(HAVE_AES_ECB) || defined(WOLFSSL_AES_DIRECT) || \
    defined(WOLF_CRYPTO_CB_ONLY_AES)
        case WC_CIPHER_AES_ECB:
            ret = cracen_cipher_ecb(info);
            break;
#endif
#ifdef HAVE_AES_CBC
        case WC_CIPHER_AES_CBC:
            ret = cracen_cipher_cbc(info);
            break;
#endif
#ifdef WOLFSSL_AES_COUNTER
        case WC_CIPHER_AES_CTR:
            ret = cracen_cipher_ctr(info);
            break;
#endif
#ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM:
            ret = cracen_cipher_gcm(info);
            break;
#endif
        default:
            break;
    }
    return ret;
}

#endif /* WOLFSSL_NRF54L_CRACEN && WOLFSSL_CRACEN_CIPHER && !NO_AES */
