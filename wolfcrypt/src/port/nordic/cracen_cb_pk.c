/* cracen_cb_pk.c
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

/* Public key requests for the CRACEN public key engine (BA414EP). The
 * handlers unpack wolfCrypt's key objects into the fixed-size big-endian (or,
 * for the 25519 curves, little-endian) operands the engine takes, run the
 * primitive, and put the result back the way the software path would. Hashing
 * for Ed25519 goes through wolfCrypt SHA-512 on the key's devId, so it lands
 * on the cryptomaster when that is offloaded too. Anything the engine does
 * not do (RSA padding, key generation for RSA and DH, deterministic ECDSA
 * nonces) is declined and left to software. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_NRF54L_CRACEN) && defined(WOLFSSL_CRACEN_PK)

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/wolfmath.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/port/nordic/cracen_regs.h>
#include <wolfssl/wolfcrypt/port/nordic/cracen_cryptocb.h>

#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifndef NO_RSA
    #include <wolfssl/wolfcrypt/rsa.h>
#endif
#ifndef NO_DH
    #include <wolfssl/wolfcrypt/dh.h>
#endif
#ifdef HAVE_CURVE25519
    #include <wolfssl/wolfcrypt/curve25519.h>
#endif
#ifdef HAVE_ED25519
    #include <wolfssl/wolfcrypt/ed25519.h>
    #include <wolfssl/wolfcrypt/sha512.h>
#endif

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#define CRACEN_UNAVAILABLE WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)

/* Big-endian export of a at exactly sz bytes. */
static int cracen_mp_be(mp_int* a, byte* out, word32 sz)
{
    if ((word32)mp_unsigned_bin_size(a) > sz)
        return MP_VAL;
    return mp_to_unsigned_bin_len(a, out, (int)sz);
}

/* ECC --------------------------------------------------------------------- */

#ifdef HAVE_ECC

typedef struct CracenEcc {
    wc_CracenEcCurve c;
    mp_int           order;
    mp_int           t;
    byte             p[WC_CRACEN_ECC_MAX_SZ];
    byte             n[WC_CRACEN_ECC_MAX_SZ];
    byte             gx[WC_CRACEN_ECC_MAX_SZ];
    byte             gy[WC_CRACEN_ECC_MAX_SZ];
    byte             a[WC_CRACEN_ECC_MAX_SZ];
    byte             b[WC_CRACEN_ECC_MAX_SZ];
    void*            heap;
} CracenEcc;

static word32 cracen_ecc_sel(int id)
{
    switch (id) {
        case ECC_SECP256R1: return WC_PK_CURVE_P256;
        case ECC_SECP384R1: return WC_PK_CURVE_P384;
        case ECC_SECP521R1: return WC_PK_CURVE_P521;
        case ECC_SECP192R1: return WC_PK_CURVE_P192;
        default:            return 0;
    }
}

static int cracen_ecc_param(mp_int* t, const char* hex, byte* out, word32 sz)
{
    int ret;

    if (hex == NULL)
        return BAD_FUNC_ARG;
    ret = mp_read_radix(t, hex, 16);
    if (ret == 0)
        ret = cracen_mp_be(t, out, sz);
    return ret;
}

static void cracen_ecc_free(CracenEcc* e)
{
    if (e == NULL)
        return;
    mp_forcezero(&e->t);
    mp_clear(&e->order);
    XFREE(e, e->heap, DYNAMIC_TYPE_ECC_BUFFER);
}

/* The curve as the engine wants it: every parameter a big-endian value of the
 * curve size. Curves the engine cannot take are declined to software. */
static CracenEcc* cracen_ecc_new(const ecc_set_type* dp, void* heap, int* ret)
{
    CracenEcc* e;
    word32     sz;

    if (dp == NULL || dp->size <= 0 ||
            (word32)dp->size > WC_CRACEN_ECC_MAX_SZ) {
        *ret = CRACEN_UNAVAILABLE;
        return NULL;
    }
    sz = (word32)dp->size;

    e = (CracenEcc*)XMALLOC(sizeof(*e), heap, DYNAMIC_TYPE_ECC_BUFFER);
    if (e == NULL) {
        *ret = MEMORY_E;
        return NULL;
    }
    XMEMSET(e, 0, sizeof(*e));
    e->heap = heap;

    *ret = mp_init_multi(&e->order, &e->t, NULL, NULL, NULL, NULL);
    if (*ret == 0)
        *ret = cracen_ecc_param(&e->t, dp->prime, e->p, sz);
    if (*ret == 0)
        *ret = cracen_ecc_param(&e->t, dp->Gx, e->gx, sz);
    if (*ret == 0)
        *ret = cracen_ecc_param(&e->t, dp->Gy, e->gy, sz);
    if (*ret == 0)
        *ret = cracen_ecc_param(&e->t, dp->Af, e->a, sz);
    if (*ret == 0)
        *ret = cracen_ecc_param(&e->t, dp->Bf, e->b, sz);
    if (*ret == 0)
        *ret = cracen_ecc_param(&e->order, dp->order, e->n, sz);
    if (*ret != 0) {
        /* an odd curve description: let software deal with it */
        if (*ret != MEMORY_E)
            *ret = CRACEN_UNAVAILABLE;
        cracen_ecc_free(e);
        return NULL;
    }

    e->c.sz       = sz;
    e->c.selCurve = cracen_ecc_sel(dp->id);
    e->c.id       = dp->id;
    e->c.p        = e->p;
    e->c.n        = e->n;
    e->c.gx       = e->gx;
    e->c.gy       = e->gy;
    e->c.a        = e->a;
    e->c.b        = e->b;
    return e;
}

/* The digest as the ECDSA primitive takes it: truncated to the order bit
 * length the way wolfCrypt does, then right aligned in a curve-size field. */
static int cracen_ecc_hash(CracenEcc* e, const byte* hash, word32 hashLen,
    byte* out)
{
    int    ret;
    word32 orderBits = (word32)mp_count_bits(&e->order);

    if (hashLen * 8 > orderBits)
        hashLen = (orderBits + 7) / 8;
    ret = mp_read_unsigned_bin(&e->t, hash, hashLen);
    if (ret == 0 && hashLen * 8 > orderBits && (orderBits & 7) != 0)
        ret = mp_rshb(&e->t, (int)(8 - (orderBits & 7)));
    if (ret == 0)
        ret = cracen_mp_be(&e->t, out, e->c.sz);
    return ret;
}

/* wolfCrypt refuses to sign or verify an all-zero digest. */
static int cracen_ecc_digest_ok(const byte* hash, word32 hashLen)
{
#ifndef WC_ALLOW_ECC_ZERO_HASH
    byte   acc = 0;
    word32 i;

    for (i = 0; i < hashLen; i++)
        acc |= hash[i];
    return acc != 0;
#else
    (void)hash;
    (void)hashLen;
    return 1;
#endif
}

static int cracen_ecc_in_order(CracenEcc* e, const byte* v)
{
    int ret = mp_read_unsigned_bin(&e->t, v, e->c.sz);
    if (ret == 0 && (mp_iszero(&e->t) || mp_cmp(&e->t, &e->order) != MP_LT))
        ret = MP_ZERO_E;
    return ret;
}

/* The public point. When the key holds only the private scalar it is derived
 * and stored in the key, as the software verifier does. */
static int cracen_ecc_pub(CracenEcc* e, ecc_key* key, byte* qx, byte* qy)
{
    int ret;

    if (key->type == ECC_PRIVATEKEY_ONLY) {
        byte d[WC_CRACEN_ECC_MAX_SZ];

        if (mp_iszero(ecc_get_k(key)))
            return ECC_PRIV_KEY_E;
        ret = cracen_mp_be(ecc_get_k(key), d, e->c.sz);
        if (ret == 0)
            ret = wc_CracenHw_EccPtMul(&e->c, d, e->gx, e->gy, qx, qy, 1);
        if (ret == 0)
            ret = mp_read_unsigned_bin(key->pubkey.x, qx, e->c.sz);
        if (ret == 0)
            ret = mp_read_unsigned_bin(key->pubkey.y, qy, e->c.sz);
        if (ret == 0)
            ret = mp_set(key->pubkey.z, 1);
        if (ret == 0)
            key->type = ECC_PRIVATEKEY;
        ForceZero(d, sizeof(d));
        return ret;
    }
    ret = cracen_mp_be(key->pubkey.x, qx, e->c.sz);
    if (ret == 0)
        ret = cracen_mp_be(key->pubkey.y, qy, e->c.sz);
    return ret;
}

static int cracen_ecc_keygen(wc_CryptoInfo* info)
{
    ecc_key*   key = info->pk.eckg.key;
    WC_RNG*    rng = info->pk.eckg.rng;
    CracenEcc* e;
    byte       d[WC_CRACEN_ECC_MAX_SZ];
    byte       x[WC_CRACEN_ECC_MAX_SZ];
    byte       y[WC_CRACEN_ECC_MAX_SZ];
    int        ret;

    if (key == NULL || rng == NULL)
        return BAD_FUNC_ARG;
    if (key->dp == NULL) {
        ret = wc_ecc_set_curve(key, info->pk.eckg.size,
            info->pk.eckg.curveId);
        if (ret != 0)
            return ret;
    }
    e = cracen_ecc_new(key->dp, key->heap, &ret);
    if (e == NULL)
        return ret;

    ret = wc_ecc_gen_k(rng, (int)e->c.sz, ecc_get_k_raw(key), &e->order);
    if (ret == 0)
        ret = cracen_mp_be(ecc_get_k_raw(key), d, e->c.sz);
    if (ret == 0)
        ret = wc_CracenHw_EccPtMul(&e->c, d, e->gx, e->gy, x, y, 1);
    if (ret == 0)
        ret = mp_read_unsigned_bin(key->pubkey.x, x, e->c.sz);
    if (ret == 0)
        ret = mp_read_unsigned_bin(key->pubkey.y, y, e->c.sz);
    if (ret == 0)
        ret = mp_set(key->pubkey.z, 1);
    if (ret == 0)
        ret = ecc_blind_k_rng(key, rng);
    if (ret == 0)
        key->type = ECC_PRIVATEKEY;
    else
        mp_forcezero(ecc_get_k_raw(key));

    ForceZero(d, sizeof(d));
    cracen_ecc_free(e);
    return ret;
}

#ifdef HAVE_ECC_DHE
static int cracen_ecdh(wc_CryptoInfo* info)
{
    ecc_key*   priv   = info->pk.ecdh.private_key;
    ecc_key*   pub    = info->pk.ecdh.public_key;
    byte*      out    = info->pk.ecdh.out;
    word32*    outlen = info->pk.ecdh.outlen;
    CracenEcc* e;
    byte       d[WC_CRACEN_ECC_MAX_SZ];
    byte       qx[WC_CRACEN_ECC_MAX_SZ];
    byte       qy[WC_CRACEN_ECC_MAX_SZ];
    byte       rx[WC_CRACEN_ECC_MAX_SZ];
    byte       ry[WC_CRACEN_ECC_MAX_SZ];
    int        ret;

    if (priv == NULL || pub == NULL || out == NULL || outlen == NULL)
        return BAD_FUNC_ARG;
    if (priv->dp == NULL || pub->dp == NULL || priv->dp->cofactor != 1)
        return CRACEN_UNAVAILABLE;
    if (priv->type != ECC_PRIVATEKEY && priv->type != ECC_PRIVATEKEY_ONLY)
        return ECC_BAD_ARG_E;
    if (pub->type != ECC_PUBLICKEY && pub->type != ECC_PRIVATEKEY)
        return ECC_BAD_ARG_E;
    if (priv->dp->id != pub->dp->id || priv->dp->size != pub->dp->size)
        return ECC_BAD_ARG_E;
    if (*outlen < (word32)priv->dp->size)
        return BUFFER_E;

    e = cracen_ecc_new(priv->dp, priv->heap, &ret);
    if (e == NULL)
        return ret;
    if (mp_iszero(ecc_get_k(priv)))
        ret = ECC_PRIV_KEY_E;
    if (ret == 0)
        ret = cracen_mp_be(ecc_get_k(priv), d, e->c.sz);
    if (ret == 0)
        ret = cracen_ecc_pub(e, pub, qx, qy);
    if (ret == 0)
        ret = wc_CracenHw_EccPtMul(&e->c, d, qx, qy, rx, ry, 1);
    if (ret == 0) {
        XMEMCPY(out, rx, e->c.sz);
        *outlen = e->c.sz;
    }

    ForceZero(d, sizeof(d));
    ForceZero(rx, sizeof(rx));
    ForceZero(ry, sizeof(ry));
    cracen_ecc_free(e);
    return ret;
}
#endif /* HAVE_ECC_DHE */

#if defined(HAVE_ECC_SIGN) && !defined(NO_ASN)
static int cracen_ecdsa_sign(wc_CryptoInfo* info)
{
    const byte* in     = info->pk.eccsign.in;
    word32      inlen  = info->pk.eccsign.inlen;
    byte*       out    = info->pk.eccsign.out;
    word32*     outlen = info->pk.eccsign.outlen;
    WC_RNG*     rng    = info->pk.eccsign.rng;
    ecc_key*    key    = info->pk.eccsign.key;
    CracenEcc*  e;
    byte        d[WC_CRACEN_ECC_MAX_SZ];
    byte        k[WC_CRACEN_ECC_MAX_SZ];
    byte        h[WC_CRACEN_ECC_MAX_SZ];
    byte        r[WC_CRACEN_ECC_MAX_SZ];
    byte        s[WC_CRACEN_ECC_MAX_SZ];
    int         ret;

    if (in == NULL || out == NULL || outlen == NULL || key == NULL)
        return BAD_FUNC_ARG;
    if (key->dp == NULL || rng == NULL)
        return CRACEN_UNAVAILABLE;
#if defined(WOLFSSL_ECDSA_SET_K) || defined(WOLFSSL_ECDSA_SET_K_ONE_LOOP) || \
    defined(WOLFSSL_ECDSA_DETERMINISTIC_K) || \
    defined(WOLFSSL_ECDSA_DETERMINISTIC_K_VARIANT)
    /* a caller-chosen nonce stays with the software signer */
    #ifndef WOLFSSL_NO_MALLOC
    if (key->sign_k != NULL)
        return CRACEN_UNAVAILABLE;
    #else
    if (key->sign_k_set)
        return CRACEN_UNAVAILABLE;
    #endif
#endif
#if defined(WOLFSSL_ECDSA_DETERMINISTIC_K) || \
    defined(WOLFSSL_ECDSA_DETERMINISTIC_K_VARIANT)
    if (key->deterministic)
        return CRACEN_UNAVAILABLE;
#endif
    if (key->type != ECC_PRIVATEKEY && key->type != ECC_PRIVATEKEY_ONLY)
        return ECC_BAD_ARG_E;
    if (!cracen_ecc_digest_ok(in, inlen))
        return ECC_BAD_ARG_E;

    e = cracen_ecc_new(key->dp, key->heap, &ret);
    if (e == NULL)
        return ret;
    if (mp_iszero(ecc_get_k(key)))
        ret = ECC_PRIV_KEY_E;
    if (ret == 0)
        ret = cracen_mp_be(ecc_get_k(key), d, e->c.sz);
    if (ret == 0)
        ret = cracen_ecc_hash(e, in, inlen, h);
    if (ret == 0)
        ret = wc_ecc_gen_k(rng, (int)e->c.sz, &e->t, &e->order);
    if (ret == 0)
        ret = cracen_mp_be(&e->t, k, e->c.sz);
    if (ret == 0)
        ret = wc_CracenHw_EcdsaSign(&e->c, d, k, h, r, s);
    if (ret == 0)
        ret = wc_ecc_rs_raw_to_sig(r, e->c.sz, s, e->c.sz, out, outlen);

    ForceZero(d, sizeof(d));
    ForceZero(k, sizeof(k));
    cracen_ecc_free(e);
    return ret;
}
#endif /* HAVE_ECC_SIGN && !NO_ASN */

#if defined(HAVE_ECC_VERIFY) && !defined(NO_ASN)
static int cracen_ecdsa_verify(wc_CryptoInfo* info)
{
    const byte* sig     = info->pk.eccverify.sig;
    word32      siglen  = info->pk.eccverify.siglen;
    const byte* hash    = info->pk.eccverify.hash;
    word32      hashlen = info->pk.eccverify.hashlen;
    int*        res     = info->pk.eccverify.res;
    ecc_key*    key     = info->pk.eccverify.key;
    CracenEcc*  e;
    byte        rs[2 * WC_CRACEN_ECC_MAX_SZ];
    byte        r[WC_CRACEN_ECC_MAX_SZ];
    byte        s[WC_CRACEN_ECC_MAX_SZ];
    byte        h[WC_CRACEN_ECC_MAX_SZ];
    byte        qx[WC_CRACEN_ECC_MAX_SZ];
    byte        qy[WC_CRACEN_ECC_MAX_SZ];
    word32      rLen = WC_CRACEN_ECC_MAX_SZ;
    word32      sLen = WC_CRACEN_ECC_MAX_SZ;
    int         ret;

    if (sig == NULL || hash == NULL || res == NULL || key == NULL)
        return BAD_FUNC_ARG;
    *res = 0;
    if (key->dp == NULL)
        return CRACEN_UNAVAILABLE;
    if (!cracen_ecc_digest_ok(hash, hashlen))
        return ECC_BAD_ARG_E;

    e = cracen_ecc_new(key->dp, key->heap, &ret);
    if (e == NULL)
        return ret;
    ret = wc_ecc_sig_to_rs(sig, siglen, rs, &rLen, rs + WC_CRACEN_ECC_MAX_SZ,
        &sLen);
    if (ret == 0 && (rLen > e->c.sz || sLen > e->c.sz))
        ret = MP_ZERO_E;
    if (ret == 0) {
        XMEMSET(r, 0, sizeof(r));
        XMEMSET(s, 0, sizeof(s));
        XMEMCPY(r + e->c.sz - rLen, rs, rLen);
        XMEMCPY(s + e->c.sz - sLen, rs + WC_CRACEN_ECC_MAX_SZ, sLen);
        ret = cracen_ecc_in_order(e, r);
    }
    if (ret == 0)
        ret = cracen_ecc_in_order(e, s);
    if (ret == 0)
        ret = cracen_ecc_hash(e, hash, hashlen, h);
    if (ret == 0)
        ret = cracen_ecc_pub(e, key, qx, qy);
    if (ret == 0)
        ret = wc_CracenHw_EcdsaVerify(&e->c, qx, qy, r, s, h, res);

    cracen_ecc_free(e);
    return ret;
}
#endif /* HAVE_ECC_VERIFY && !NO_ASN */

static int cracen_ecc_make_pub(wc_CryptoInfo* info)
{
    ecc_key*   key   = info->pk.ecc_make_pub.key;
    byte*      out   = info->pk.ecc_make_pub.pubOut;
    word32*    outSz = info->pk.ecc_make_pub.pubOutSz;
    CracenEcc* e;
    byte       d[WC_CRACEN_ECC_MAX_SZ];
    int        ret;

    if (key == NULL || out == NULL || outSz == NULL)
        return BAD_FUNC_ARG;
    if (key->dp == NULL)
        return CRACEN_UNAVAILABLE;
    if (*outSz < 1 + 2 * (word32)key->dp->size)
        return BUFFER_E;

    e = cracen_ecc_new(key->dp, key->heap, &ret);
    if (e == NULL)
        return ret;
    if (mp_iszero(ecc_get_k(key)))
        ret = ECC_PRIV_KEY_E;
    if (ret == 0)
        ret = cracen_mp_be(ecc_get_k(key), d, e->c.sz);
    if (ret == 0) {
        ret = wc_CracenHw_EccPtMul(&e->c, d, e->gx, e->gy, out + 1,
            out + 1 + e->c.sz, 1);
    }
    if (ret == 0) {
        out[0] = ECC_POINT_UNCOMP;
        *outSz = 1 + 2 * e->c.sz;
    }

    ForceZero(d, sizeof(d));
    cracen_ecc_free(e);
    return ret;
}

#ifdef HAVE_ECC_CHECK_KEY
static int cracen_ecc_check_pub(wc_CryptoInfo* info)
{
    ecc_key*    key      = info->pk.ecc_check_pub.key;
    const byte* pub      = info->pk.ecc_check_pub.pubKey;
    word32      pubSz    = info->pk.ecc_check_pub.pubKeySz;
    const byte* qx       = NULL;
    const byte* qy       = NULL;
    CracenEcc*  e;
    byte        d[WC_CRACEN_ECC_MAX_SZ];
    byte        x[WC_CRACEN_ECC_MAX_SZ];
    byte        y[WC_CRACEN_ECC_MAX_SZ];
    int         ret;

    if (key == NULL)
        return BAD_FUNC_ARG;
    if (key->dp == NULL)
        return CRACEN_UNAVAILABLE;

    e = cracen_ecc_new(key->dp, key->heap, &ret);
    if (e == NULL)
        return ret;

    if (pub != NULL) {
        if (pubSz != 1 + 2 * e->c.sz || pub[0] != ECC_POINT_UNCOMP) {
            ret = BAD_FUNC_ARG;
        }
        else {
            qx  = pub + 1;
            qy  = qx + e->c.sz;
            ret = wc_CracenHw_EccPtOnCurve(&e->c, qx, qy);
            if (ret == 0 && info->pk.ecc_check_pub.checkOrder)
                ret = wc_CracenHw_EccPtOrder(&e->c, qx, qy);
        }
    }

    if (ret == 0 && info->pk.ecc_check_pub.checkPriv &&
            (key->type == ECC_PRIVATEKEY ||
             key->type == ECC_PRIVATEKEY_ONLY)) {
        mp_int* k = ecc_get_k(key);

        if (mp_iszero(k) || mp_cmp(k, &e->order) != MP_LT) {
            ret = ECC_PRIV_KEY_E;
        }
        else if (qx != NULL) {
            ret = cracen_mp_be(k, d, e->c.sz);
            if (ret == 0)
                ret = wc_CracenHw_EccPtMul(&e->c, d, e->gx, e->gy, x, y, 1);
            if (ret == 0 && (XMEMCMP(x, qx, e->c.sz) != 0 ||
                             XMEMCMP(y, qy, e->c.sz) != 0)) {
                ret = ECC_PRIV_KEY_E;
            }
        }
    }

    ForceZero(d, sizeof(d));
    cracen_ecc_free(e);
    return ret;
}
#endif /* HAVE_ECC_CHECK_KEY */

#endif /* HAVE_ECC */

/* RSA --------------------------------------------------------------------- */

#ifndef NO_RSA

#if !defined(WOLFSSL_RSA_PUBLIC_ONLY) && (defined(WOLFSSL_KEY_GEN) || \
    defined(OPENSSL_EXTRA) || !defined(RSA_LOW_MEM))
    #define CRACEN_RSA_CRT
#endif

/* Raw modular exponentiation, in and out of the engine as full modulus-size
 * values; the padding stays in wolfCrypt. */
static int cracen_rsa(wc_CryptoInfo* info)
{
    RsaKey*     key    = info->pk.rsa.key;
    const byte* in     = info->pk.rsa.in;
    word32      inLen  = info->pk.rsa.inLen;
    byte*       out    = info->pk.rsa.out;
    word32*     outLen = info->pk.rsa.outLen;
    int         type   = info->pk.rsa.type;
    byte*       buf    = NULL;
    word32      keyLen;
    int         ret;

#ifdef WOLF_CRYPTO_CB_RSA_PAD
    if (info->pk.rsa.padding != NULL &&
            info->pk.rsa.padding->pad_type != WC_RSA_NO_PAD) {
        return CRACEN_UNAVAILABLE;
    }
#endif
    if (key == NULL || in == NULL || out == NULL || outLen == NULL)
        return BAD_FUNC_ARG;
    if (mp_unsigned_bin_size(&key->n) <= 0)
        return CRACEN_UNAVAILABLE;
    keyLen = (word32)mp_unsigned_bin_size(&key->n);
    if (inLen > keyLen)
        return CRACEN_UNAVAILABLE;
    if (*outLen < keyLen)
        return RSA_BUFFER_E;

    /* six modulus-size operands cover every parameter set below */
    buf = (byte*)XMALLOC(6 * keyLen, key->heap, DYNAMIC_TYPE_RSA_BUFFER);
    if (buf == NULL)
        return MEMORY_E;

    {
        /* the input must be a residue: wolfCrypt rejects the rest, and a
         * ciphertext of 0, 1 or n - 1 on decrypt */
        WC_DECLARE_VAR(c, mp_int, 1, key->heap);
        WC_ALLOC_VAR_EX(c, mp_int, 1, key->heap, DYNAMIC_TYPE_RSA_BUFFER,
            ret = MEMORY_E);
        ret = WC_VAR_OK(c) ? mp_init(c) : MEMORY_E;
        if (ret == 0) {
            ret = mp_read_unsigned_bin(c, in, inLen);
            if (ret == 0 && mp_cmp(c, &key->n) != MP_LT)
                ret = RSA_OUT_OF_RANGE_E;
        #if !defined(NO_RSA_BOUNDS_CHECK) && !defined(WOLFSSL_RSA_VERIFY_ONLY)
            if (ret == 0 && type == RSA_PRIVATE_DECRYPT) {
                if (mp_cmp_d(c, 1) != MP_GT)
                    ret = RSA_OUT_OF_RANGE_E;
                else if (mp_add_d(c, 1, c) != MP_OKAY)
                    ret = MP_ADD_E;
                else if (mp_cmp(c, &key->n) != MP_LT)
                    ret = RSA_OUT_OF_RANGE_E;
            }
        #endif
            mp_clear(c);
        }
        WC_FREE_VAR_EX(c, key->heap, DYNAMIC_TYPE_RSA_BUFFER);
    }

    if (ret == 0) {
        switch (type) {
            case RSA_PUBLIC_ENCRYPT:
            case RSA_PUBLIC_DECRYPT:
            {
                byte*  n   = buf;
                byte*  ex  = buf + keyLen;
                word32 eSz = (word32)mp_unsigned_bin_size(&key->e);

                if (eSz == 0 || eSz > keyLen) {
                    ret = CRACEN_UNAVAILABLE;
                    break;
                }
                ret = cracen_mp_be(&key->n, n, keyLen);
                if (ret == 0)
                    ret = cracen_mp_be(&key->e, ex, eSz);
                if (ret == 0) {
                    ret = wc_CracenHw_ModExp(in, inLen, ex, eSz, n, keyLen,
                        out, 0);
                }
                break;
            }

            case RSA_PRIVATE_ENCRYPT:
            case RSA_PRIVATE_DECRYPT:
            {
            #ifdef WOLFSSL_RSA_PUBLIC_ONLY
                ret = CRACEN_UNAVAILABLE;
            #else
            #ifdef CRACEN_RSA_CRT
                if (!mp_iszero(&key->p) && !mp_iszero(&key->q) &&
                        !mp_iszero(&key->dP) && !mp_iszero(&key->dQ) &&
                        !mp_iszero(&key->u)) {
                    word32 pSz  = (word32)mp_unsigned_bin_size(&key->p);
                    word32 qSz  = (word32)mp_unsigned_bin_size(&key->q);
                    word32 dPSz = (word32)mp_unsigned_bin_size(&key->dP);
                    word32 dQSz = (word32)mp_unsigned_bin_size(&key->dQ);
                    word32 uSz  = (word32)mp_unsigned_bin_size(&key->u);
                    byte*  p    = buf;
                    byte*  q    = p + keyLen;
                    byte*  dP   = q + keyLen;
                    byte*  dQ   = dP + keyLen;
                    byte*  u    = dQ + keyLen;

                    if (pSz > keyLen || qSz > keyLen || dPSz > keyLen ||
                            dQSz > keyLen || uSz > keyLen) {
                        ret = CRACEN_UNAVAILABLE;
                        break;
                    }
                    ret = cracen_mp_be(&key->p, p, pSz);
                    if (ret == 0)
                        ret = cracen_mp_be(&key->q, q, qSz);
                    if (ret == 0)
                        ret = cracen_mp_be(&key->dP, dP, dPSz);
                    if (ret == 0)
                        ret = cracen_mp_be(&key->dQ, dQ, dQSz);
                    if (ret == 0)
                        ret = cracen_mp_be(&key->u, u, uSz);
                    if (ret == 0) {
                        ret = wc_CracenHw_RsaCrt(in, inLen, p, pSz, q, qSz,
                            dP, dPSz, dQ, dQSz, u, uSz, out, keyLen, 1);
                    }
                    break;
                }
            #endif
                if (mp_iszero(&key->d)) {
                    /* not a private key: software reports it */
                    ret = CRACEN_UNAVAILABLE;
                }
                else {
                    byte*  n   = buf;
                    byte*  d   = buf + keyLen;
                    word32 dSz = (word32)mp_unsigned_bin_size(&key->d);

                    if (dSz > keyLen) {
                        ret = CRACEN_UNAVAILABLE;
                        break;
                    }
                    ret = cracen_mp_be(&key->n, n, keyLen);
                    if (ret == 0)
                        ret = cracen_mp_be(&key->d, d, dSz);
                    if (ret == 0) {
                        ret = wc_CracenHw_ModExp(in, inLen, d, dSz, n, keyLen,
                            out, 1);
                    }
                }
            #endif /* WOLFSSL_RSA_PUBLIC_ONLY */
                break;
            }

            default:
                ret = CRACEN_UNAVAILABLE;
                break;
        }
    }
    if (ret == 0)
        *outLen = keyLen;

    ForceZero(buf, 6 * keyLen);
    XFREE(buf, key->heap, DYNAMIC_TYPE_RSA_BUFFER);
    return ret;
}
#endif /* !NO_RSA */

/* DH ---------------------------------------------------------------------- */

#ifndef NO_DH
static int cracen_dh(wc_CryptoInfo* info)
{
    DhKey*      key     = info->pk.dh.key;
    const byte* priv    = info->pk.dh.priv;
    word32      privSz  = info->pk.dh.privSz;
    const byte* pub     = info->pk.dh.otherPub;
    word32      pubSz   = info->pk.dh.pubSz;
    byte*       agree   = info->pk.dh.agree;
    word32*     agreeSz = info->pk.dh.agreeSz;
    byte*       buf;
    byte*       z;
    word32      pSz;
    word32      i;
    int         ret;

    if (key == NULL || priv == NULL || pub == NULL || agree == NULL ||
            agreeSz == NULL) {
        return BAD_FUNC_ARG;
    }
    if (mp_unsigned_bin_size(&key->p) <= 0)
        return CRACEN_UNAVAILABLE;
    pSz = (word32)mp_unsigned_bin_size(&key->p);
    if (pubSz > pSz || privSz > pSz || privSz == 0 || pubSz == 0)
        return CRACEN_UNAVAILABLE;
    if (*agreeSz < pSz)
        return BUFFER_E;

    buf = (byte*)XMALLOC(2 * pSz, key->heap, DYNAMIC_TYPE_DH);
    if (buf == NULL)
        return MEMORY_E;
    z = buf + pSz;

    ret = cracen_mp_be(&key->p, buf, pSz);
    if (ret == 0)
        ret = wc_CracenHw_ModExp(pub, pubSz, priv, privSz, buf, pSz, z, 1);
    if (ret == 0) {
        /* the software path returns the minimal encoding and rejects 1 */
        for (i = 0; i < pSz - 1 && z[i] == 0; i++) {
        }
        if (pSz - i == 1 && z[i] <= 1) {
            ret = MP_VAL;
        }
        else {
            XMEMCPY(agree, z + i, pSz - i);
            *agreeSz = pSz - i;
        }
    }

    ForceZero(buf, 2 * pSz);
    XFREE(buf, key->heap, DYNAMIC_TYPE_DH);
    return ret;
}
#endif /* !NO_DH */

/* X25519 ------------------------------------------------------------------ */

#ifdef HAVE_CURVE25519

static const byte cracen_x25519_base[CURVE25519_KEYSIZE] = { 9 };

static int cracen_x25519_keygen(wc_CryptoInfo* info)
{
    curve25519_key* key = info->pk.curve25519kg.key;
    WC_RNG*         rng = info->pk.curve25519kg.rng;
    int             ret;

    if (key == NULL || rng == NULL)
        return BAD_FUNC_ARG;

    ret = wc_curve25519_make_priv(rng, info->pk.curve25519kg.size, key->k);
    if (ret == 0)
        ret = wc_CracenHw_X25519(key->k, cracen_x25519_base, key->p.point);
#ifdef WOLFSSL_CURVE25519_BLINDING
    if (ret == 0)
        ret = wc_curve25519_set_rng(key, rng);
#endif
    if (ret == 0) {
        key->privSet = 1;
        key->pubSet  = 1;
    }
    else {
        ForceZero(key->k, sizeof(key->k));
    }
    return ret;
}

static int cracen_x25519_shared(wc_CryptoInfo* info)
{
    curve25519_key* priv   = info->pk.curve25519.private_key;
    curve25519_key* pub    = info->pk.curve25519.public_key;
    byte*           out    = info->pk.curve25519.out;
    word32*         outlen = info->pk.curve25519.outlen;
    byte            o[CURVE25519_KEYSIZE];
    byte            acc = 0;
    int             i;
    int             ret;

    if (priv == NULL || pub == NULL || out == NULL || outlen == NULL)
        return BAD_FUNC_ARG;
    if (*outlen < CURVE25519_KEYSIZE)
        return BUFFER_E;
    if (!priv->privSet || !pub->pubSet)
        return ECC_BAD_ARG_E;

    ret = wc_CracenHw_X25519(priv->k, pub->p.point, o);
    if (ret == 0) {
        for (i = 0; i < CURVE25519_KEYSIZE; i++)
            acc |= o[i];
    #ifndef WOLFSSL_NO_ECDHX_SHARED_ZERO_CHECK
        if (acc == 0)
            ret = ECC_OUT_OF_RANGE_E;
    #endif
    }
    if (ret == 0) {
        if (info->pk.curve25519.endian == EC25519_BIG_ENDIAN) {
            for (i = 0; i < CURVE25519_KEYSIZE; i++)
                out[i] = o[CURVE25519_KEYSIZE - 1 - i];
        }
        else {
            XMEMCPY(out, o, CURVE25519_KEYSIZE);
        }
        *outlen = CURVE25519_KEYSIZE;
    }
    ForceZero(o, sizeof(o));
    return ret;
}

static int cracen_x25519_make_pub(byte* pub, word32 pubSz, const byte* priv,
    word32 privSz, const byte* base, word32 baseSz)
{
    if (pub == NULL || priv == NULL || base == NULL)
        return BAD_FUNC_ARG;
    if (pubSz != CURVE25519_KEYSIZE || privSz != CURVE25519_KEYSIZE ||
            baseSz != CURVE25519_KEYSIZE) {
        return ECC_BAD_ARG_E;
    }
    return wc_CracenHw_X25519(priv, base, pub);
}
#endif /* HAVE_CURVE25519 */

/* Ed25519 ----------------------------------------------------------------- */

#ifdef HAVE_ED25519

static const char cracen_ed25519_dom[] = "SigEd25519 no Ed25519 collisions";
#define CRACEN_ED25519_DOM_SZ 32

static const byte cracen_ed25519_order[ED25519_KEY_SIZE] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

/* The y coordinates of the points of order 1, 2, 4 and 8 and their
 * non-canonical encodings, which wolfCrypt refuses to verify against. */
static const byte cracen_ed25519_small[][ED25519_PUB_KEY_SIZE] = {
    {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
     0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
     0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
     0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    {0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
     0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
     0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
     0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    {0x26,0xe8,0x95,0x8f,0xc2,0xb2,0x27,0xb0,
     0x45,0xc3,0xf4,0x89,0xf2,0xef,0x98,0xf0,
     0xd5,0xdf,0xac,0x05,0xd3,0xc6,0x33,0x39,
     0xb1,0x38,0x02,0x88,0x6d,0x53,0xfc,0x05},
    {0xc7,0x17,0x6a,0x70,0x3d,0x4d,0xd8,0x4f,
     0xba,0x3c,0x0b,0x76,0x0d,0x10,0x67,0x0f,
     0x2a,0x20,0x53,0xfa,0x2c,0x39,0xcc,0xc6,
     0x4e,0xc7,0xfd,0x77,0x92,0xac,0x03,0x7a},
    {0xec,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f},
    {0xed,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f},
    {0xee,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f},
};

/* The checks the software verifier applies before any arithmetic: S below
 * the group order and a public key that is not of small order. */
static int cracen_ed25519_verify_ok(const byte* sig, const byte* pub)
{
    byte   y[ED25519_PUB_KEY_SIZE];
    word32 i;
    int    k;

    for (k = ED25519_KEY_SIZE - 1; k >= 0; k--) {
        if (sig[ED25519_SIG_SIZE / 2 + k] > cracen_ed25519_order[k])
            return 0;
        if (sig[ED25519_SIG_SIZE / 2 + k] < cracen_ed25519_order[k])
            break;
    }
    if (k < 0)
        return 0;

    XMEMCPY(y, pub, sizeof(y));
    y[ED25519_PUB_KEY_SIZE - 1] &= 0x7f;
    for (i = 0; i < sizeof(cracen_ed25519_small) / ED25519_PUB_KEY_SIZE; i++) {
        if (XMEMCMP(y, cracen_ed25519_small[i], ED25519_PUB_KEY_SIZE) == 0)
            return 0;
    }
    return 1;
}

/* SHA-512 on the key's devId, with the dom2 prefix for the ctx and ph
 * variants. */
static int cracen_ed25519_hash_init(wc_Sha512* sha, ed25519_key* key,
    byte type, const byte* ctx, byte ctxLen)
{
    int ret = wc_InitSha512_ex(sha, key->heap, key->devId);

    if (ret == 0 && (type == (byte)Ed25519ctx || type == (byte)Ed25519ph)) {
        ret = wc_Sha512Update(sha, (const byte*)cracen_ed25519_dom,
            CRACEN_ED25519_DOM_SZ);
        if (ret == 0)
            ret = wc_Sha512Update(sha, &type, 1);
        if (ret == 0)
            ret = wc_Sha512Update(sha, &ctxLen, 1);
        if (ret == 0 && ctx != NULL && ctxLen > 0)
            ret = wc_Sha512Update(sha, ctx, ctxLen);
    }
    return ret;
}

/* az = SHA-512(seed) with the scalar half clamped. */
static int cracen_ed25519_secret(wc_Sha512* sha, ed25519_key* key, byte* az)
{
    int ret = cracen_ed25519_hash_init(sha, key, (byte)Ed25519, NULL, 0);

    if (ret == 0)
        ret = wc_Sha512Update(sha, key->k, ED25519_KEY_SIZE);
    if (ret == 0)
        ret = wc_Sha512Final(sha, az);
    wc_Sha512Free(sha);
    if (ret == 0) {
        az[0]  &= 248;
        az[31] &= 63;
        az[31] |= 64;
    }
    return ret;
}

static int cracen_ed25519_pub(wc_Sha512* sha, ed25519_key* key, byte* pub)
{
    byte az[WC_SHA512_DIGEST_SIZE];
    int  ret = cracen_ed25519_secret(sha, key, az);

    if (ret == 0) {
        XMEMSET(az + ED25519_KEY_SIZE, 0, ED25519_KEY_SIZE);
        ret = wc_CracenHw_Ed25519PtMul(az, pub);
    }
    ForceZero(az, sizeof(az));
    return ret;
}

static int cracen_ed25519_keygen(wc_Sha512* sha, wc_CryptoInfo* info)
{
    ed25519_key* key = info->pk.ed25519kg.key;
    WC_RNG*      rng = info->pk.ed25519kg.rng;
    int          ret;

    if (key == NULL || rng == NULL)
        return BAD_FUNC_ARG;
    if (info->pk.ed25519kg.size != ED25519_KEY_SIZE)
        return BAD_FUNC_ARG;

    ret = wc_RNG_GenerateBlock(rng, key->k, ED25519_KEY_SIZE);
    if (ret == 0)
        ret = cracen_ed25519_pub(sha, key, key->p);
    if (ret == 0) {
        XMEMCPY(key->k + ED25519_KEY_SIZE, key->p, ED25519_PUB_KEY_SIZE);
        key->privKeySet = 1;
        key->pubKeySet  = 1;
    }
    else {
        ForceZero(key->k, sizeof(key->k));
    }
    return ret;
}

static int cracen_ed25519_make_pub(wc_Sha512* sha, wc_CryptoInfo* info)
{
    ed25519_key* key = info->pk.ed25519makepub.key;
    byte*        out = info->pk.ed25519makepub.pubOut;

    if (key == NULL || out == NULL)
        return BAD_FUNC_ARG;
    if (!key->privKeySet)
        return CRACEN_UNAVAILABLE;
    if (info->pk.ed25519makepub.pubOutSz < ED25519_PUB_KEY_SIZE)
        return BUFFER_E;
    return cracen_ed25519_pub(sha, key, out);
}

static int cracen_ed25519_sign(wc_Sha512* sha, wc_CryptoInfo* info)
{
    const byte*  in     = info->pk.ed25519sign.in;
    word32       inLen  = info->pk.ed25519sign.inLen;
    byte*        out    = info->pk.ed25519sign.out;
    word32*      outLen = info->pk.ed25519sign.outLen;
    ed25519_key* key    = info->pk.ed25519sign.key;
    byte         type   = info->pk.ed25519sign.type;
    const byte*  ctx    = info->pk.ed25519sign.context;
    byte         ctxLen = info->pk.ed25519sign.contextLen;
    byte         az[WC_SHA512_DIGEST_SIZE];
    byte         nonce[WC_SHA512_DIGEST_SIZE];
    byte         hram[WC_SHA512_DIGEST_SIZE];
    int          ret;

    if (in == NULL || out == NULL || outLen == NULL || key == NULL)
        return BAD_FUNC_ARG;
    if (!key->privKeySet || !key->pubKeySet)
        return CRACEN_UNAVAILABLE;
    if (*outLen < ED25519_SIG_SIZE)
        return BUFFER_E;

    /* r = H(dom2, prefix, M), R = r B */
    ret = cracen_ed25519_secret(sha, key, az);
    if (ret == 0)
        ret = cracen_ed25519_hash_init(sha, key, type, ctx, ctxLen);
    if (ret == 0)
        ret = wc_Sha512Update(sha, az + ED25519_KEY_SIZE, ED25519_KEY_SIZE);
    if (ret == 0)
        ret = wc_Sha512Update(sha, in, inLen);
    if (ret == 0)
        ret = wc_Sha512Final(sha, nonce);
    wc_Sha512Free(sha);
    if (ret == 0)
        ret = wc_CracenHw_Ed25519PtMul(nonce, out);

    /* k = H(dom2, R, A, M), S = r + k a mod L */
    if (ret == 0)
        ret = cracen_ed25519_hash_init(sha, key, type, ctx, ctxLen);
    if (ret == 0)
        ret = wc_Sha512Update(sha, out, ED25519_SIG_SIZE / 2);
    if (ret == 0)
        ret = wc_Sha512Update(sha, key->p, ED25519_PUB_KEY_SIZE);
    if (ret == 0)
        ret = wc_Sha512Update(sha, in, inLen);
    if (ret == 0)
        ret = wc_Sha512Final(sha, hram);
    wc_Sha512Free(sha);
    if (ret == 0) {
        ret = wc_CracenHw_Ed25519Sign(hram, nonce, az,
            out + ED25519_SIG_SIZE / 2);
    }
    if (ret == 0)
        *outLen = ED25519_SIG_SIZE;

    ForceZero(az, sizeof(az));
    ForceZero(nonce, sizeof(nonce));
    return ret;
}

static int cracen_ed25519_verify(wc_Sha512* sha, wc_CryptoInfo* info)
{
    const byte*  sig    = info->pk.ed25519verify.sig;
    word32       sigLen = info->pk.ed25519verify.sigLen;
    const byte*  msg    = info->pk.ed25519verify.msg;
    word32       msgLen = info->pk.ed25519verify.msgLen;
    int*         res    = info->pk.ed25519verify.res;
    ed25519_key* key    = info->pk.ed25519verify.key;
    byte         h[WC_SHA512_DIGEST_SIZE];
    int          ret;

    if (sig == NULL || msg == NULL || res == NULL || key == NULL)
        return BAD_FUNC_ARG;
    *res = 0;
    if (!key->pubKeySet)
        return CRACEN_UNAVAILABLE;
    if (sigLen != ED25519_SIG_SIZE || !cracen_ed25519_verify_ok(sig, key->p))
        return BAD_FUNC_ARG;

    ret = cracen_ed25519_hash_init(sha, key, info->pk.ed25519verify.type,
        info->pk.ed25519verify.context, info->pk.ed25519verify.contextLen);
    if (ret == 0)
        ret = wc_Sha512Update(sha, sig, ED25519_SIG_SIZE / 2);
    if (ret == 0)
        ret = wc_Sha512Update(sha, key->p, ED25519_PUB_KEY_SIZE);
    if (ret == 0)
        ret = wc_Sha512Update(sha, msg, msgLen);
    if (ret == 0)
        ret = wc_Sha512Final(sha, h);
    wc_Sha512Free(sha);
    if (ret == 0) {
        ret = wc_CracenHw_Ed25519Verify(h, key->p, sig + ED25519_SIG_SIZE / 2,
            sig);
    }
    if (ret == 0)
        *res = 1;
    return ret;
}

static int cracen_ed25519(wc_CryptoInfo* info)
{
    int ret;
    WC_DECLARE_VAR(sha, wc_Sha512, 1, NULL);

    WC_ALLOC_VAR_EX(sha, wc_Sha512, 1, NULL, DYNAMIC_TYPE_HASHES,
        return MEMORY_E);
    switch (info->pk.type) {
        case WC_PK_TYPE_ED25519_KEYGEN:
            ret = cracen_ed25519_keygen(sha, info);
            break;
        case WC_PK_TYPE_ED25519_MAKE_PUB:
            ret = cracen_ed25519_make_pub(sha, info);
            break;
        case WC_PK_TYPE_ED25519_SIGN:
            ret = cracen_ed25519_sign(sha, info);
            break;
        case WC_PK_TYPE_ED25519_VERIFY:
            ret = cracen_ed25519_verify(sha, info);
            break;
        default:
            ret = CRACEN_UNAVAILABLE;
            break;
    }
    WC_FREE_VAR_EX(sha, NULL, DYNAMIC_TYPE_HASHES);
    return ret;
}
#endif /* HAVE_ED25519 */

/* ------------------------------------------------------------------------- */

int wc_CracenPk(wc_CryptoInfo* info)
{
    int ret = CRACEN_UNAVAILABLE;

    if (info == NULL)
        return BAD_FUNC_ARG;
    if (!wc_CracenHw_PkReady())
        return CRACEN_UNAVAILABLE;

    switch (info->pk.type) {
#ifdef HAVE_ECC
        case WC_PK_TYPE_EC_KEYGEN:
            ret = cracen_ecc_keygen(info);
            break;
    #ifdef HAVE_ECC_DHE
        case WC_PK_TYPE_ECDH:
            ret = cracen_ecdh(info);
            break;
    #endif
    #if defined(HAVE_ECC_SIGN) && !defined(NO_ASN)
        case WC_PK_TYPE_ECDSA_SIGN:
            ret = cracen_ecdsa_sign(info);
            break;
    #endif
    #if defined(HAVE_ECC_VERIFY) && !defined(NO_ASN)
        case WC_PK_TYPE_ECDSA_VERIFY:
            ret = cracen_ecdsa_verify(info);
            break;
    #endif
        case WC_PK_TYPE_EC_MAKE_PUB:
            ret = cracen_ecc_make_pub(info);
            break;
    #ifdef HAVE_ECC_CHECK_KEY
        case WC_PK_TYPE_EC_CHECK_PUB_KEY:
            ret = cracen_ecc_check_pub(info);
            break;
    #endif
#endif /* HAVE_ECC */
#ifndef NO_RSA
        case WC_PK_TYPE_RSA:
            ret = cracen_rsa(info);
            break;
#endif
#ifndef NO_DH
        case WC_PK_TYPE_DH:
            ret = cracen_dh(info);
            break;
#endif
#ifdef HAVE_CURVE25519
        case WC_PK_TYPE_CURVE25519_KEYGEN:
            ret = cracen_x25519_keygen(info);
            break;
        case WC_PK_TYPE_CURVE25519:
            ret = cracen_x25519_shared(info);
            break;
        case WC_PK_TYPE_CURVE25519_MAKE_PUB:
            ret = cracen_x25519_make_pub(info->pk.curve25519makepub.pub,
                info->pk.curve25519makepub.pubSz,
                info->pk.curve25519makepub.priv,
                info->pk.curve25519makepub.privSz,
                cracen_x25519_base, CURVE25519_KEYSIZE);
            break;
        case WC_PK_TYPE_CURVE25519_GENERIC:
            ret = cracen_x25519_make_pub(info->pk.curve25519generic.pub,
                info->pk.curve25519generic.pubSz,
                info->pk.curve25519generic.priv,
                info->pk.curve25519generic.privSz,
                info->pk.curve25519generic.basepoint,
                info->pk.curve25519generic.basepointSz);
            break;
#endif
#ifdef HAVE_ED25519
        case WC_PK_TYPE_ED25519_KEYGEN:
        case WC_PK_TYPE_ED25519_MAKE_PUB:
        case WC_PK_TYPE_ED25519_SIGN:
        case WC_PK_TYPE_ED25519_VERIFY:
            ret = cracen_ed25519(info);
            break;
#endif
        default:
            break;
    }
    return ret;
}

#endif /* WOLFSSL_NRF54L_CRACEN && WOLFSSL_CRACEN_PK */
