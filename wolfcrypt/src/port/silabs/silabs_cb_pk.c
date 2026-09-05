/* silabs_cb_pk.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_SILABS_CRYPTOCB) && \
    defined(WOLFSSL_SILABS_CRYPTOCB_ECC) && defined(HAVE_ECC)

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/port/silabs/silabs_cryptocb.h>
#include <wolfssl/wolfcrypt/port/silabs/silabs_ecc.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif


/* Curves the SE supports. P-384 and P-521 need Secure Vault High; on a Vault
 * Mid part those key types do not exist and the curves stay in software. */
static int silabs_pk_curve_ok(const ecc_key* key)
{
    if (key == NULL || key->dp == NULL) {
        return 0;
    }

    /* ECC_MAX_CRYPTO_HW_SIZE sizes ecc_key.key_raw and the raw r||s scratch
     * below, but it is picked by an #elif chain over every enabled hardware
     * backend, and arms that come before the Silicon Labs one (ATECC, TA100)
     * select a smaller value. As a devId-routed callback this port can be
     * built alongside those, so a curve wider than the buffer wolfCrypt
     * actually reserved would overrun it. Decline instead and let software,
     * which sizes from the curve, handle it. */
    if (key->dp->size > ECC_MAX_CRYPTO_HW_SIZE) {
        return 0;
    }

    switch (key->dp->id) {
#ifdef SL_SE_KEY_TYPE_ECC_P192
    case ECC_SECP192R1:
        return 1;
#endif
    case ECC_SECP256R1:
        return 1;
#ifdef SL_SE_KEY_TYPE_ECC_P384
    case ECC_SECP384R1:
        return 1;
#endif
#ifdef SL_SE_KEY_TYPE_ECC_P521
    case ECC_SECP521R1:
        return 1;
#endif
    default:
        break;
    }

    return 0;
}

/* The SE takes the digest as-is and assumes it is exactly the curve size. The
 * ECDSA truncation rules for a digest longer or shorter than the curve order
 * are not applied by the hardware, so hand those to software instead of
 * producing or accepting a wrong result. */
static int silabs_pk_digest_ok(const ecc_key* key, word32 hashLen)
{
    return (key != NULL) && (key->dp != NULL) &&
           (hashLen == (word32)key->dp->size);
}

/* wolfCrypt rejects signing or verifying an all-zero digest unless the
 * application opts in with WC_ALLOW_ECC_ZERO_HASH. The crypto callback runs
 * before that check in ecc.c, so apply the same policy here rather than let
 * the SE sign something the software path would refuse. */
#ifndef WC_ALLOW_ECC_ZERO_HASH
static int silabs_pk_hash_is_zero(const byte* hash, word32 hashLen)
{
    byte acc = 0;
    word32 i;

    if (hash == NULL) {
        return 0;
    }
    for (i = 0; i < hashLen; i++) {
        acc |= hash[i];
    }

    return (acc == 0);
}
#endif

/* The SE works on the flat X||Y||D buffer in the key. The direct port fills it
 * from the wc_ecc_import_* hooks; the callback port leaves those in software,
 * so refresh it here from the key's mp_ints before each operation. */
static int silabs_pk_load(ecc_key* key, int pub, int priv)
{
    int ret;
    int savedType;

    if (key == NULL || key->dp == NULL) {
        return BAD_FUNC_ARG;
    }
    /* A wrapped or built-in key was bound by wc_SilabsSe_EccUse*Key(); the
     * descriptor already names it, and key_raw holds no private scalar to
     * import. */
    if (key->silabsKeySet) {
        return 0;
    }

    /* silabs_ecc_import() rewrites key->type from the pub/priv flags. That is
     * right when wolfCrypt is genuinely importing a key, but here it only
     * refreshes the SE buffer before an operation: a verify needs the public
     * part alone and must not downgrade a key that holds a private scalar,
     * which would break a later private-key export. */
    savedType = key->type;
    ret = silabs_ecc_import(key, (word32)key->dp->size, pub, priv);
    key->type = savedType;

    return ret;
}

/* The ecc_key a PK request operates on, or NULL when the type carries none. */
static ecc_key* silabs_pk_key(const wc_CryptoInfo* info)
{
    switch (info->pk.type) {
#ifdef HAVE_ECC_DHE
    case WC_PK_TYPE_EC_KEYGEN:
        return info->pk.eckg.key;
    case WC_PK_TYPE_ECDH:
        return info->pk.ecdh.private_key;
#endif
#ifdef HAVE_ECC_SIGN
    case WC_PK_TYPE_ECDSA_SIGN:
        return info->pk.eccsign.key;
#endif
#ifdef HAVE_ECC_VERIFY
    case WC_PK_TYPE_ECDSA_VERIFY:
        return info->pk.eccverify.key;
#endif
    default:
        return NULL;
    }
}

static int silabs_pk_dispatch(wc_CryptoInfo* info)
{
    int ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (info->pk.type) {
#ifdef HAVE_ECC_DHE
    case WC_PK_TYPE_EC_KEYGEN:
        if (info->pk.eckg.key == NULL) {
            return BAD_FUNC_ARG;
        }
        /* wc_ecc_make_key_ex sets the curve before dispatching; without it
         * there is nothing to tell the SE which key to make. */
        if (!silabs_pk_curve_ok(info->pk.eckg.key)) {
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
        /* Generating into a key already bound to device-resident material
         * would silently discard that binding. Use
         * wc_SilabsSe_EccGenerateWrappedKey() for that instead. */
        if (info->pk.eckg.key->silabsKeySet) {
            return BAD_FUNC_ARG;
        }
        /* Use the curve's own field size, not the size the caller asked for.
         * wc_ecc_make_key_ex() rounds a requested size up to the next curve,
         * so eckg.size can be smaller than dp->size (40 selects P-384); using
         * it would read the SE's key back at the wrong stride. */
        ret = silabs_cb_status(silabs_ecc_make_key_status(info->pk.eckg.key,
            info->pk.eckg.key->dp->size));
        break;

    case WC_PK_TYPE_ECDH:
        if (info->pk.ecdh.private_key == NULL ||
            info->pk.ecdh.public_key == NULL) {
            return BAD_FUNC_ARG;
        }
        /* Both objects are imported into fixed-size SE buffers below, so the
         * public key's curve has to be checked too, not just the private
         * one. */
        if (!silabs_pk_curve_ok(info->pk.ecdh.private_key) ||
            !silabs_pk_curve_ok(info->pk.ecdh.public_key)) {
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
        /* wc_ecc_shared_secret() validates the key type and that both sides
         * are on the same curve, but it dispatches here first. Repeat those
         * checks so a mismatched pair gets the documented ECC_BAD_ARG_E rather
         * than whatever the SE happens to report. */
        if (info->pk.ecdh.private_key->type != ECC_PRIVATEKEY &&
            info->pk.ecdh.private_key->type != ECC_PRIVATEKEY_ONLY) {
            return ECC_BAD_ARG_E;
        }
        if (info->pk.ecdh.private_key->dp->id !=
                info->pk.ecdh.public_key->dp->id) {
            return ECC_BAD_ARG_E;
        }
        ret = silabs_pk_load(info->pk.ecdh.private_key, 1, 1);
        if (ret == 0) {
            ret = silabs_pk_load(info->pk.ecdh.public_key, 1, 0);
        }
        if (ret == 0) {
            ret = silabs_cb_status(silabs_ecc_shared_secret_status(
                info->pk.ecdh.private_key, info->pk.ecdh.public_key,
                info->pk.ecdh.out, info->pk.ecdh.outlen));
        }
        break;
#endif /* HAVE_ECC_DHE */

#ifdef HAVE_ECC_SIGN
    case WC_PK_TYPE_ECDSA_SIGN:
        if (info->pk.eccsign.key == NULL) {
            return BAD_FUNC_ARG;
        }
        if (!silabs_pk_curve_ok(info->pk.eccsign.key)) {
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
        if (!silabs_pk_digest_ok(info->pk.eccsign.key,
                info->pk.eccsign.inlen)) {
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
    #ifndef WC_ALLOW_ECC_ZERO_HASH
        if (silabs_pk_hash_is_zero(info->pk.eccsign.in,
                info->pk.eccsign.inlen)) {
            return ECC_BAD_ARG_E;
        }
    #endif
        /* A key bound by wc_SilabsSe_EccUse*Key() holds no software private
         * scalar on purpose - the SE has the key and signs with the bound
         * descriptor - so it is a valid private-key source here. Any other key
         * must carry a real scalar: silabs_ecc_sign_hash() would otherwise
         * fall back to the SE attestation key under the direct port, and
         * signing with a different key than the caller supplied is not
         * something this path should do silently. */
        if (!info->pk.eccsign.key->silabsKeySet &&
            (info->pk.eccsign.key->type != ECC_PRIVATEKEY ||
             mp_unsigned_bin_size(
                wc_ecc_key_get_priv(info->pk.eccsign.key)) == 0)) {
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
        ret = silabs_pk_load(info->pk.eccsign.key, 1, 1);
        if (ret == 0) {
            /* The SE emits a raw r||s pair. wc_ecc_sign_hash() hands the
             * callback the buffer for the DER encoded signature, so convert
             * here; under the direct port ecc.c does this after the helper. */
            byte   raw[ECC_MAX_CRYPTO_HW_SIZE * 2];
            word32 rawLen = (word32)sizeof(raw);
            word32 keySz  = (word32)info->pk.eccsign.key->dp->size;

            ret = silabs_cb_status(silabs_ecc_sign_hash_status(
                info->pk.eccsign.in, info->pk.eccsign.inlen, raw, &rawLen,
                info->pk.eccsign.key));
            if (ret == 0) {
                ret = wc_ecc_rs_raw_to_sig(raw, keySz, raw + keySz, keySz,
                    info->pk.eccsign.out, info->pk.eccsign.outlen);
            }
            ForceZero(raw, sizeof(raw));
        }
        break;
#endif /* HAVE_ECC_SIGN */

#ifdef HAVE_ECC_VERIFY
    case WC_PK_TYPE_ECDSA_VERIFY:
        if (info->pk.eccverify.key == NULL) {
            return BAD_FUNC_ARG;
        }
        if (!silabs_pk_curve_ok(info->pk.eccverify.key)) {
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
        if (!silabs_pk_digest_ok(info->pk.eccverify.key,
                info->pk.eccverify.hashlen)) {
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
    #ifndef WC_ALLOW_ECC_ZERO_HASH
        if (silabs_pk_hash_is_zero(info->pk.eccverify.hash,
                info->pk.eccverify.hashlen)) {
            if (info->pk.eccverify.res != NULL) {
                *info->pk.eccverify.res = 0;
            }
            return ECC_BAD_ARG_E;
        }
    #endif
        ret = silabs_pk_load(info->pk.eccverify.key, 1, 0);
        if (ret == 0) {
            /* wolfCrypt passes a DER encoded signature; the SE wants a raw
             * r||s pair of exactly the curve size, left padded. */
            byte   raw[ECC_MAX_CRYPTO_HW_SIZE * 2];
            byte   rBuf[ECC_MAX_CRYPTO_HW_SIZE];
            byte   sBuf[ECC_MAX_CRYPTO_HW_SIZE];
            word32 keySz = (word32)info->pk.eccverify.key->dp->size;
            word32 rLen  = (word32)sizeof(rBuf);
            word32 sLen  = (word32)sizeof(sBuf);

            /* The decoder strips DER's leading zeros, but the SE wants each
             * value at exactly the curve size, so left pad both halves. */
            ret = wc_ecc_sig_to_rs(info->pk.eccverify.sig,
                info->pk.eccverify.siglen, rBuf, &rLen, sBuf, &sLen);
            if (ret == 0 && (rLen > keySz || sLen > keySz)) {
                ret = ASN_PARSE_E;
            }
            if (ret == 0) {
                XMEMSET(raw, 0, sizeof(raw));
                XMEMCPY(raw + (keySz - rLen), rBuf, rLen);
                XMEMCPY(raw + keySz + (keySz - sLen), sBuf, sLen);
                ret = silabs_cb_status(silabs_ecc_verify_hash_status(
                    raw, keySz * 2, info->pk.eccverify.hash,
                    info->pk.eccverify.hashlen, info->pk.eccverify.res,
                    info->pk.eccverify.key));
            }
            ForceZero(raw, sizeof(raw));
            ForceZero(rBuf, sizeof(rBuf));
            ForceZero(sBuf, sizeof(sBuf));
        }
        break;
#endif /* HAVE_ECC_VERIFY */

    default:
        break;
    }

    return ret;
}

/* WC_ALGO_TYPE_PK. Only the ECC operations are offloaded; the Series 2 High
 * Security Engine has no RSA hardware, so RSA always returns unavailable and
 * runs in software.
 *
 * A wrapped or built-in key lives inside the SE and the ecc_key holds no
 * private scalar, so declining would hand the operation to the software ECC
 * path with no key material behind it. Whenever such a key is bound, an
 * unsupported request has to fail outright instead. */
int wc_SilabsPk(wc_CryptoInfo* info)
{
    int      ret;
    ecc_key* key;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = silabs_pk_dispatch(info);
    if (ret == WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
        key = silabs_pk_key(info);
        if (key != NULL && key->silabsKeySet) {
            return WC_HW_E;
        }
    }

    return ret;
}

#endif /* WOLFSSL_SILABS_CRYPTOCB && WOLFSSL_SILABS_CRYPTOCB_ECC && HAVE_ECC */
