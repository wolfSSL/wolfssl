/* nuvoton_cb_pk.c
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

/* Public key work on the M2354 CRPT engine: ECDSA, ECDH, ECC key generation
 * and RSA.
 *
 * The driver takes and returns every value as a NUL terminated hex string
 * rather than as a byte array, so this file spends most of its length
 * converting. It converts with what wolfCrypt already has - mp_tohex and
 * mp_read_radix for anything that is already an mp_int, wc_DataToHexString
 * (asn.c, written for the custom ECC curve parameter strings) for a byte
 * array, and an mp_int round trip coming back - rather than growing its own.
 *
 * Two things about the engine shape the code:
 *
 * The engine signs a number, not a message: the caller reduces the digest to
 * an integer e first, exactly as FIPS 186 describes and as Nuvoton's own
 * mbedTLS layer does in derive_mpi(). That truncation is copied from the
 * software path in wolfcrypt/src/ecc.c so the two agree.
 *
 * The BSP public key drivers block on a flag that only the CRPT interrupt
 * sets. The application must route CRPT_IRQHandler to ECC_DriverISR(); with
 * no handler every call here times out. That is reported as WC_HW_E rather
 * than declined to software, because a missing handler is a wiring mistake
 * and a silent, very slow fallback would hide it. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_NUVOTON_M2354) && defined(WOLF_CRYPTO_CB) && \
    (defined(WOLFSSL_NUVOTON_ECC) || defined(WOLFSSL_NUVOTON_RSA))

#include <wolfssl/wolfcrypt/port/nuvoton/nuvoton_cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/asn.h>
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifndef NO_RSA
    #include <wolfssl/wolfcrypt/rsa.h>
#endif
#ifdef WOLFSSL_NUVOTON_KS
    #include <wolfssl/wolfcrypt/port/nuvoton/nuvoton_key.h>
#endif

#include "wolfcrypt/src/port/nuvoton/nuvoton_hw.h"

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* Room for the largest curve the engine takes, P-521: 66 bytes is 132 hex
 * characters plus the NUL. Rounded up to the width Nuvoton uses for the same
 * strings in ECC_CURVE. */
#define NUVOTON_ECC_HEX_SZ 144

/* Decode one of the driver's hex strings into a fixed width big-endian byte
 * array, left padded with zeros. Goes through an mp_int rather than
 * Base16_Decode() so that an odd number of digits and a value shorter than
 * the field both come out right, and so the port does not need
 * WOLFSSL_BASE16 turned on in every build. */
static int nuvoton_hex_to_bin(const char* hex, byte* out, word32 outSz)
{
    mp_int a[1];
    int    ret;

    if (hex == NULL || out == NULL || outSz == 0) {
        return BAD_FUNC_ARG;
    }

    ret = mp_init(a);
    if (ret != MP_OKAY) {
        return ret;
    }

    ret = mp_read_radix(a, hex, MP_RADIX_HEX);
    if (ret == MP_OKAY) {
        if ((word32)mp_unsigned_bin_size(a) > outSz) {
            ret = BUFFER_E;
        }
    }
    if (ret == MP_OKAY) {
        ret = mp_to_unsigned_bin_len(a, out, (int)outSz);
    }

    mp_forcezero(a);
    mp_free(a);

    return ret;
}

#ifdef WOLFSSL_NUVOTON_ECC

/* Every hex string one ECC request needs, in one allocation. Together they
 * are about a kilobyte, too much to leave on the stack of a caller that may
 * already be deep inside a handshake. */
typedef struct {
    char e[NUVOTON_ECC_HEX_SZ];
    char d[NUVOTON_ECC_HEX_SZ];
    char k[NUVOTON_ECC_HEX_SZ];
    char qx[NUVOTON_ECC_HEX_SZ];
    char qy[NUVOTON_ECC_HEX_SZ];
    char r[NUVOTON_ECC_HEX_SZ];
    char s[NUVOTON_ECC_HEX_SZ];
} NuvotonEccHex;

/* Map a wolfCrypt curve id onto the port's selector, or
 * WC_NUVOTON_CURVE_NONE when the engine has no equivalent. The engine also
 * does the Koblitz and binary field curves and SM2, which wolfCrypt either
 * does not carry or routes elsewhere. */
static int nuvoton_curve_id(int curveId)
{
    switch (curveId) {
#ifdef HAVE_ECC192
        case ECC_SECP192R1:
            return WC_NUVOTON_CURVE_P192;
#endif
#ifdef HAVE_ECC224
        case ECC_SECP224R1:
            return WC_NUVOTON_CURVE_P224;
#endif
#ifndef NO_ECC256
        case ECC_SECP256R1:
            return WC_NUVOTON_CURVE_P256;
#endif
#ifdef HAVE_ECC384
        case ECC_SECP384R1:
            return WC_NUVOTON_CURVE_P384;
#endif
#ifdef HAVE_ECC521
        case ECC_SECP521R1:
            return WC_NUVOTON_CURVE_P521;
#endif
#ifdef HAVE_ECC_BRAINPOOL
    #ifdef HAVE_ECC256
        case ECC_BRAINPOOLP256R1:
            return WC_NUVOTON_CURVE_BP256;
    #endif
    #ifdef HAVE_ECC384
        case ECC_BRAINPOOLP384R1:
            return WC_NUVOTON_CURVE_BP384;
    #endif
    #ifdef HAVE_ECC512
        case ECC_BRAINPOOLP512R1:
            return WC_NUVOTON_CURVE_BP512;
    #endif
#endif
        default:
            return WC_NUVOTON_CURVE_NONE;
    }
}

/* Whether an ecc_key is carrying a Key Store handle rather than ordinary key
 * material. Those are declined: signing from a stored ECC key produces a
 * signature that does not verify, and no slot layout tried on hardware
 * changes that, so the path is not offered rather than offered broken. AES
 * keys from the store are unaffected and are validated. */
static int nuvoton_ecc_is_ks(const ecc_key* key)
{
#ifdef WOLFSSL_NUVOTON_KS
    return (key != NULL && key->devCtx != NULL);
#else
    (void)key;
    return 0;
#endif
}

/* Reduce a digest to the integer the signature equation uses: take the
 * leftmost bytes up to the order size, then shift off the spare bits. Same
 * steps as the software path in wolfcrypt/src/ecc.c, so a signature made here
 * and one made there agree. */
static int nuvoton_digest_to_hex(const byte* digest, word32 digestSz,
    const ecc_set_type* dp, char* out, word32 outSz)
{
    mp_int e[1];
    mp_int order[1];
    int    ret;
    int    orderBits;
    word32 useSz = digestSz;

    if (digest == NULL || dp == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = mp_init_multi(e, order, NULL, NULL, NULL, NULL);
    if (ret != MP_OKAY) {
        return ret;
    }

    ret = mp_read_radix(order, dp->order, MP_RADIX_HEX);
    if (ret == MP_OKAY) {
        orderBits = mp_count_bits(order);

        if ((word32)orderBits < useSz * WOLFSSL_BIT_SIZE) {
            useSz = ((word32)orderBits + WOLFSSL_BIT_SIZE - 1) /
                WOLFSSL_BIT_SIZE;
        }

        ret = mp_read_unsigned_bin(e, digest, useSz);
    }
    if (ret == MP_OKAY) {
        if (useSz * WOLFSSL_BIT_SIZE > (word32)orderBits) {
            ret = mp_rshb(e, (int)(WOLFSSL_BIT_SIZE -
                ((word32)orderBits & 0x7)));
        }
    }
    if (ret == MP_OKAY) {
        if ((word32)mp_unsigned_bin_size(e) * 2 + 1 > outSz) {
            ret = BUFFER_E;
        }
    }
    if (ret == MP_OKAY) {
        ret = mp_tohex(e, out);
    }

    mp_free(order);
    mp_free(e);

    return ret;
}

/* An mp_int as a hex string the driver will take. */
static int nuvoton_mp_to_hex(mp_int* a, char* out, word32 outSz)
{
    if (a == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }
    if ((word32)mp_unsigned_bin_size(a) * 2 + 1 > outSz) {
        return BUFFER_E;
    }

    return mp_tohex(a, out);
}

/* A fresh per-message random in [1, n-1], as a hex string. The engine needs
 * one handed to it; it has no internal source for it. */
static int nuvoton_gen_k_hex(WC_RNG* rng, const ecc_set_type* dp, char* out,
    word32 outSz)
{
    mp_int k[1];
    mp_int order[1];
    int    ret;

    if (rng == NULL || dp == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = mp_init_multi(k, order, NULL, NULL, NULL, NULL);
    if (ret != MP_OKAY) {
        return ret;
    }

    ret = mp_read_radix(order, dp->order, MP_RADIX_HEX);
    if (ret == MP_OKAY) {
        ret = wc_ecc_gen_k(rng, dp->size, k, order);
    }
    if (ret == MP_OKAY) {
        ret = nuvoton_mp_to_hex(k, out, outSz);
    }

    mp_forcezero(k);
    mp_free(order);
    mp_free(k);

    return ret;
}


/* wolfCrypt rejects signing or verifying an all-zero digest, and enforces a
 * digest length range, in wc_ecc_sign_hash_ex() and wc_ecc_verify_hash_ex().
 * A crypto callback intercepts before either runs, so the port has to apply
 * the same contract itself or it silently accepts inputs the software path
 * refuses - which wolfcrypt_test checks for directly. The STM32 PKA path in
 * wolfcrypt/src/ecc.c re-implements it for the same reason. */
static int nuvoton_digest_ok(const byte* digest, word32 digestSz)
{
#ifndef WC_ALLOW_ECC_ZERO_HASH
    byte   isZero = 0;
    word32 i;
#endif

    if (digest == NULL) {
        return ECC_BAD_ARG_E;
    }
    if (digestSz > WC_MAX_DIGEST_SIZE || digestSz < WC_MIN_DIGEST_SIZE) {
        return BAD_LENGTH_E;
    }
#ifndef WC_ALLOW_ECC_ZERO_HASH
    for (i = 0; i < digestSz; i++) {
        isZero |= digest[i];
    }
    if (isZero == 0) {
        return ECC_BAD_ARG_E;
    }
#endif

    return 0;
}

static int nuvoton_ecc_sign(wc_CryptoInfo* info)
{
    NuvotonEccHex*    hex;
    wc_NuvotonEccReq  req;
    ecc_key*          key = info->pk.eccsign.key;
    mp_int            r[1];
    mp_int            s[1];
    int               curveId;
    int               ret;

    if (key == NULL || key->dp == NULL || info->pk.eccsign.in == NULL ||
        info->pk.eccsign.out == NULL || info->pk.eccsign.outlen == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (info->pk.eccsign.rng == NULL) {
        /* No random source means no k, and the engine will not make one. */
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    curveId = nuvoton_curve_id(key->dp->id);
    if (curveId == WC_NUVOTON_CURVE_NONE) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    ret = nuvoton_digest_ok(info->pk.eccsign.in, info->pk.eccsign.inlen);
    if (ret != 0) {
        return ret;
    }

    if (nuvoton_ecc_is_ks(key) || mp_iszero(wc_ecc_key_get_priv(key))) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    hex = (NuvotonEccHex*)XMALLOC(sizeof(NuvotonEccHex), key->heap,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (hex == NULL) {
        return MEMORY_E;
    }
    XMEMSET(hex, 0, sizeof(*hex));

    XMEMSET(&req, 0, sizeof(req));
    req.curveId = curveId;
    req.msg     = hex->e;
    req.r       = hex->r;
    req.s       = hex->s;
    req.keySlot = WC_NUVOTON_NO_SLOT;

    ret = nuvoton_digest_to_hex(info->pk.eccsign.in, info->pk.eccsign.inlen,
        key->dp, hex->e, (word32)sizeof(hex->e));

    if (ret == 0) {
        ret = nuvoton_mp_to_hex(wc_ecc_key_get_priv(key), hex->d,
            (word32)sizeof(hex->d));
        if (ret == 0) {
            ret = nuvoton_gen_k_hex(info->pk.eccsign.rng, key->dp, hex->k,
                (word32)sizeof(hex->k));
        }
        req.d = hex->d;
        req.k = hex->k;
    }

    if (ret == 0) {
        ret = wc_nuvoton_hw_ecc_sign(&req);
    }

    /* wolfCrypt expects the DER encoded signature back, because this callback
     * stands in for the whole of wc_ecc_sign_hash(). */
    if (ret == 0) {
        ret = mp_init_multi(r, s, NULL, NULL, NULL, NULL);
        if (ret == MP_OKAY) {
            ret = mp_read_radix(r, hex->r, MP_RADIX_HEX);
            if (ret == MP_OKAY) {
                ret = mp_read_radix(s, hex->s, MP_RADIX_HEX);
            }
            if (ret == MP_OKAY) {
                ret = StoreECC_DSA_Sig(info->pk.eccsign.out,
                    info->pk.eccsign.outlen, r, s);
            }
            mp_free(s);
            mp_free(r);
        }
    }

    ForceZero(hex, sizeof(*hex));
    XFREE(hex, key->heap, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

static int nuvoton_ecc_verify(wc_CryptoInfo* info)
{
    NuvotonEccHex*   hex;
    wc_NuvotonEccReq req;
    ecc_key*         key = info->pk.eccverify.key;
    mp_int           r[1];
    mp_int           s[1];
    int              curveId;
    int              ret;

    if (key == NULL || key->dp == NULL || info->pk.eccverify.sig == NULL ||
        info->pk.eccverify.hash == NULL || info->pk.eccverify.res == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    curveId = nuvoton_curve_id(key->dp->id);
    if (curveId == WC_NUVOTON_CURVE_NONE) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    ret = nuvoton_digest_ok(info->pk.eccverify.hash, info->pk.eccverify.hashlen);
    if (ret != 0) {
        return ret;
    }

    /* Verifying with a private-only key is legal: wolfCrypt derives the public
     * point from the private scalar on the way through, and callers rely on
     * that - wolfcrypt_test verifies with such a key and then checks that
     * exporting the public part has started working. The engine has no such
     * step; it takes Qx and Qy as inputs. Reading them from a key that has not
     * had them computed hands it zeros, and the engine dutifully reports the
     * signature invalid, which is a wrong answer rather than an error. Leave
     * this case to software, which populates the key as a side effect. */
    if (key->type == ECC_PRIVATEKEY_ONLY ||
        mp_iszero(key->pubkey.x) || mp_iszero(key->pubkey.y)) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    hex = (NuvotonEccHex*)XMALLOC(sizeof(NuvotonEccHex), key->heap,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (hex == NULL) {
        return MEMORY_E;
    }
    XMEMSET(hex, 0, sizeof(*hex));

    ret = mp_init_multi(r, s, NULL, NULL, NULL, NULL);
    if (ret == MP_OKAY) {
        ret = DecodeECC_DSA_Sig(info->pk.eccverify.sig,
            info->pk.eccverify.siglen, r, s);
        if (ret == 0) {
            ret = nuvoton_mp_to_hex(r, hex->r, (word32)sizeof(hex->r));
        }
        if (ret == 0) {
            ret = nuvoton_mp_to_hex(s, hex->s, (word32)sizeof(hex->s));
        }
        mp_free(s);
        mp_free(r);
    }

    if (ret == 0) {
        ret = nuvoton_digest_to_hex(info->pk.eccverify.hash,
            info->pk.eccverify.hashlen, key->dp, hex->e,
            (word32)sizeof(hex->e));
    }
    if (ret == 0) {
        ret = nuvoton_mp_to_hex(key->pubkey.x, hex->qx,
            (word32)sizeof(hex->qx));
    }
    if (ret == 0) {
        ret = nuvoton_mp_to_hex(key->pubkey.y, hex->qy,
            (word32)sizeof(hex->qy));
    }

    if (ret == 0) {
        XMEMSET(&req, 0, sizeof(req));
        req.curveId = curveId;
        req.msg     = hex->e;
        req.qx      = hex->qx;
        req.qy      = hex->qy;
        req.r       = hex->r;
        req.s       = hex->s;
        req.keySlot = WC_NUVOTON_NO_SLOT;

        ret = wc_nuvoton_hw_ecc_verify(&req);

        /* A rejected signature is a result, not an error: report it through
         * res and return success, the way the software path does. */
        if (ret == 0) {
            *info->pk.eccverify.res = 1;
        }
        else if (ret == WC_NO_ERR_TRACE(SIG_VERIFY_E)) {
            *info->pk.eccverify.res = 0;
            ret = 0;
        }
    }

    ForceZero(hex, sizeof(*hex));
    XFREE(hex, key->heap, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

#ifdef HAVE_ECC_DHE
static int nuvoton_ecc_shared(wc_CryptoInfo* info)
{
    NuvotonEccHex*   hex;
    wc_NuvotonEccReq req;
    ecc_key*         priv = info->pk.ecdh.private_key;
    ecc_key*         pub  = info->pk.ecdh.public_key;
    int              curveId;
    int              ret;
    word32           outSz;

    if (priv == NULL || pub == NULL || priv->dp == NULL ||
        info->pk.ecdh.out == NULL || info->pk.ecdh.outlen == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    curveId = nuvoton_curve_id(priv->dp->id);
    if (curveId == WC_NUVOTON_CURVE_NONE) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    outSz = (word32)priv->dp->size;
    if (*info->pk.ecdh.outlen < outSz) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    /* This callback runs ahead of the checks wc_ecc_shared_secret() would
     * make, so anything it would have rejected has to be rejected here too -
     * otherwise a mismatched or malformed key reaches the engine and comes
     * back as a hardware error, or as a shared secret computed over the wrong
     * curve. Declining sends it to software, which reports it properly. */
    if (pub->dp == NULL || pub->dp->id != priv->dp->id ||
        pub->idx != priv->idx || pub->type == ECC_PRIVATEKEY_ONLY ||
        priv->type == ECC_PUBLICKEY) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (mp_iszero(wc_ecc_key_get_priv(priv)) ||
        mp_iszero(pub->pubkey.x) || mp_iszero(pub->pubkey.y)) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    /* A stored private key cannot answer this: ECC_GenerateSecretZ_KS() leaves
     * Z in a slot and hands nothing back. */
    if (nuvoton_ecc_is_ks(priv)) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    hex = (NuvotonEccHex*)XMALLOC(sizeof(NuvotonEccHex), priv->heap,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (hex == NULL) {
        return MEMORY_E;
    }
    XMEMSET(hex, 0, sizeof(*hex));

    ret = nuvoton_mp_to_hex(pub->pubkey.x, hex->qx, (word32)sizeof(hex->qx));
    if (ret == 0) {
        ret = nuvoton_mp_to_hex(pub->pubkey.y, hex->qy,
            (word32)sizeof(hex->qy));
    }
    if (ret == 0) {
        ret = nuvoton_mp_to_hex(wc_ecc_key_get_priv(priv), hex->d,
            (word32)sizeof(hex->d));
    }

    if (ret == 0) {
        XMEMSET(&req, 0, sizeof(req));
        req.curveId = curveId;
        req.qx      = hex->qx;
        req.qy      = hex->qy;
        req.d       = hex->d;
        req.out     = hex->e; /* reuse a spare buffer of the right width */
        req.keySlot = WC_NUVOTON_NO_SLOT;

        ret = wc_nuvoton_hw_ecc_shared(&req);
    }

    if (ret == 0) {
        ret = nuvoton_hex_to_bin(hex->e, info->pk.ecdh.out, outSz);
    }
    if (ret == 0) {
        *info->pk.ecdh.outlen = outSz;
    }

    ForceZero(hex, sizeof(*hex));
    XFREE(hex, priv->heap, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

static int nuvoton_ecc_keygen(wc_CryptoInfo* info)
{
    NuvotonEccHex*   hex;
    wc_NuvotonEccReq req;
    ecc_key*         key = info->pk.eckg.key;
    mp_int           order[1];
    int              curveId;
    int              ret;

    if (key == NULL || info->pk.eckg.rng == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    /* The caller may name a curve, or leave it to the key it passed in. */
    if (info->pk.eckg.curveId != ECC_CURVE_DEF) {
        ret = wc_ecc_set_curve(key, info->pk.eckg.size,
            info->pk.eckg.curveId);
        if (ret != 0) {
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
    }
    if (key->dp == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    curveId = nuvoton_curve_id(key->dp->id);
    if (curveId == WC_NUVOTON_CURVE_NONE) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    hex = (NuvotonEccHex*)XMALLOC(sizeof(NuvotonEccHex), key->heap,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (hex == NULL) {
        return MEMORY_E;
    }
    XMEMSET(hex, 0, sizeof(*hex));

    /* The private scalar is drawn here and the engine only derives the point:
     * the driver has no key generation entry point of its own that returns
     * the private half. */
    ret = mp_init(order);
    if (ret == MP_OKAY) {
        ret = mp_read_radix(order, key->dp->order, MP_RADIX_HEX);
        if (ret == MP_OKAY) {
            ret = wc_ecc_gen_k(info->pk.eckg.rng, key->dp->size,
                wc_ecc_key_get_priv(key), order);
        }
        mp_free(order);
    }
    if (ret == 0) {
        ret = nuvoton_mp_to_hex(wc_ecc_key_get_priv(key), hex->d,
            (word32)sizeof(hex->d));
    }

    if (ret == 0) {
        XMEMSET(&req, 0, sizeof(req));
        req.curveId = curveId;
        req.d       = hex->d;
        req.qx      = hex->qx;
        req.qy      = hex->qy;
        req.keySlot = WC_NUVOTON_NO_SLOT;

        ret = wc_nuvoton_hw_ecc_pubkey(&req);
    }

    if (ret == 0) {
        ret = mp_read_radix(key->pubkey.x, hex->qx, MP_RADIX_HEX);
    }
    if (ret == 0) {
        ret = mp_read_radix(key->pubkey.y, hex->qy, MP_RADIX_HEX);
    }
    if (ret == 0) {
        ret = mp_set(key->pubkey.z, 1);
    }
    if (ret == 0) {
        key->type = ECC_PRIVATEKEY;
    }

    ForceZero(hex, sizeof(*hex));
    XFREE(hex, key->heap, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}
#endif /* HAVE_ECC_DHE */

#endif /* WOLFSSL_NUVOTON_ECC */

#if defined(WOLFSSL_NUVOTON_RSA) && !defined(NO_RSA)

/* Every hex string one RSA request needs. Sized from the key in hand rather
 * than from the 4096 bit maximum, because at that size these four strings
 * come to four kilobytes. */
typedef struct {
    char*  in;
    char*  n;
    char*  e;
    char*  out;
    word32 hexSz; /* characters plus the NUL, one buffer */
} NuvotonRsaHex;

static void nuvoton_rsa_hex_free(NuvotonRsaHex* hex, void* heap)
{
    if (hex->in != NULL) {
        ForceZero(hex->in, hex->hexSz);
        XFREE(hex->in, heap, DYNAMIC_TYPE_TMP_BUFFER);
        hex->in = NULL;
    }
    if (hex->n != NULL) {
        XFREE(hex->n, heap, DYNAMIC_TYPE_TMP_BUFFER);
        hex->n = NULL;
    }
    if (hex->e != NULL) {
        ForceZero(hex->e, hex->hexSz);
        XFREE(hex->e, heap, DYNAMIC_TYPE_TMP_BUFFER);
        hex->e = NULL;
    }
    if (hex->out != NULL) {
        ForceZero(hex->out, hex->hexSz);
        XFREE(hex->out, heap, DYNAMIC_TYPE_TMP_BUFFER);
        hex->out = NULL;
    }
}

static int nuvoton_rsa_hex_alloc(NuvotonRsaHex* hex, word32 hexSz, void* heap)
{
    XMEMSET(hex, 0, sizeof(*hex));
    hex->hexSz = hexSz;

    hex->in  = (char*)XMALLOC(hexSz, heap, DYNAMIC_TYPE_TMP_BUFFER);
    hex->n   = (char*)XMALLOC(hexSz, heap, DYNAMIC_TYPE_TMP_BUFFER);
    hex->e   = (char*)XMALLOC(hexSz, heap, DYNAMIC_TYPE_TMP_BUFFER);
    hex->out = (char*)XMALLOC(hexSz, heap, DYNAMIC_TYPE_TMP_BUFFER);

    if (hex->in == NULL || hex->n == NULL || hex->e == NULL ||
        hex->out == NULL) {
        nuvoton_rsa_hex_free(hex, heap);
        return MEMORY_E;
    }

    return 0;
}

static int nuvoton_rsa(wc_CryptoInfo* info)
{
    NuvotonRsaHex    hex;
    wc_NuvotonRsaReq req;
    RsaKey*          key = info->pk.rsa.key;
    void*            heap;
    mp_int*          exp;
    word32           modSz;
    word32           hexSz;
    int              keyBits;
    int              isPrivate;
    int              ret;

    if (key == NULL || info->pk.rsa.in == NULL ||
        info->pk.rsa.out == NULL || info->pk.rsa.outLen == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    heap    = key->heap;
    modSz   = (word32)mp_unsigned_bin_size(&key->n);
    keyBits = mp_count_bits(&key->n);

    /* The engine takes four sizes and nothing between them. */
    if (keyBits != 1024 && keyBits != 2048 && keyBits != 3072 &&
        keyBits != 4096) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (info->pk.rsa.inLen > modSz || *info->pk.rsa.outLen < modSz) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    isPrivate = (info->pk.rsa.type == RSA_PRIVATE_DECRYPT ||
                 info->pk.rsa.type == RSA_PRIVATE_ENCRYPT);
    if (isPrivate) {
        exp = &key->d;
        if (mp_iszero(exp)) {
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
    }
    else {
        exp = &key->e;
    }

    /* Two hex characters per byte, plus the NUL. */
    hexSz = modSz * 2 + 1;

    ret = nuvoton_rsa_hex_alloc(&hex, hexSz, heap);
    if (ret != 0) {
        return ret;
    }

    /* The base is a byte array, so it takes the byte array converter; the
     * modulus and exponent are already mp_ints. */
    wc_DataToHexString(info->pk.rsa.in, info->pk.rsa.inLen, hex.in);

    ret = mp_tohex(&key->n, hex.n);
    if (ret == MP_OKAY) {
        ret = mp_tohex(exp, hex.e);
    }

    if (ret == 0) {
        XMEMSET(&req, 0, sizeof(req));
        req.in      = hex.in;
        req.n       = hex.n;
        req.e       = hex.e;
        req.out     = hex.out;
        req.outSz   = hexSz;
        req.keyBits = keyBits;
        req.keySlot = WC_NUVOTON_NO_SLOT;

        ret = wc_nuvoton_hw_rsa(&req);
    }

    if (ret == 0) {
        ret = nuvoton_hex_to_bin(hex.out, info->pk.rsa.out, modSz);
    }
    if (ret == 0) {
        *info->pk.rsa.outLen = modSz;
    }

    nuvoton_rsa_hex_free(&hex, heap);

    return ret;
}

#endif /* WOLFSSL_NUVOTON_RSA && !NO_RSA */

int wc_NuvotonCb_Pk(wc_CryptoInfo* info)
{
    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (info->pk.type) {
#if defined(WOLFSSL_NUVOTON_ECC) && defined(HAVE_ECC)
    #ifdef HAVE_ECC_SIGN
        case WC_PK_TYPE_ECDSA_SIGN:
            return nuvoton_ecc_sign(info);
    #endif
    #ifdef HAVE_ECC_VERIFY
        case WC_PK_TYPE_ECDSA_VERIFY:
            return nuvoton_ecc_verify(info);
    #endif
    #ifdef HAVE_ECC_DHE
        case WC_PK_TYPE_ECDH:
            return nuvoton_ecc_shared(info);
        case WC_PK_TYPE_EC_KEYGEN:
            return nuvoton_ecc_keygen(info);
    #endif
#endif
#if defined(WOLFSSL_NUVOTON_RSA) && !defined(NO_RSA)
        case WC_PK_TYPE_RSA:
            return nuvoton_rsa(info);
#endif
        default:
            break;
    }

    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}

#endif /* WOLFSSL_NUVOTON_M2354 && WOLF_CRYPTO_CB &&
        * (WOLFSSL_NUVOTON_ECC || WOLFSSL_NUVOTON_RSA) */
