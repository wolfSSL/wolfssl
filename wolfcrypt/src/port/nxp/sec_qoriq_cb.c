/* sec_qoriq_cb.c
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

/*
 * Crypto callback router for the QorIQ SEC.
 *
 * Anything the engine cannot do returns CRYPTOCB_UNAVAILABLE so wolfCrypt
 * falls back to software. That fallback is deliberately the default for
 * every case that is not explicitly handled, so an unimplemented algorithm
 * is a performance question rather than a correctness one.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_SEC_QORIQ) && defined(WOLF_CRYPTO_CB) && \
    !defined(WOLFSSL_SEC_QORIQ_NO_CRYPTOCB)

#include <wolfssl/wolfcrypt/port/nxp/sec_qoriq.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#if defined(WOLFSSL_SEC_QORIQ_PKHA) || defined(WOLFSSL_SEC_QORIQ_RSA)
    #ifdef WOLFSSL_SEC_QORIQ_PKHA
        #include <wolfssl/wolfcrypt/ecc.h>
        #include <wolfssl/wolfcrypt/asn.h>
    #endif
    #ifdef WOLFSSL_SEC_QORIQ_RSA
        #include <wolfssl/wolfcrypt/rsa.h>
        #ifndef NO_DH
            #include <wolfssl/wolfcrypt/dh.h>
        #endif
    #endif

    #ifdef NO_INLINE
        #include <wolfssl/wolfcrypt/misc.h>
    #else
        #define WOLFSSL_MISC_INCLUDED
        #include <wolfcrypt/src/misc.c>
    #endif
#endif

/* The fallback promise has to cover run time failures too, not just what
 * secCbCanDo() sees in advance: a non-contiguous buffer, a full ring, a job
 * that times out. All mean "this engine cannot serve this call", and
 * returning them verbatim would abort an operation software handles fine.
 *
 * AES_GCM_AUTH_E is not translated: that is the engine's answer about the
 * data, not about itself, and the caller must see it. */
static int secCbFallback(int ret)
{
    if (ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG) ||
            ret == WC_NO_ERR_TRACE(BUFFER_E) ||
            ret == WC_NO_ERR_TRACE(MEMORY_E) ||
            ret == WC_NO_ERR_TRACE(WC_HW_E)) {
        WOLFSSL_MSG("sec_qoriq: engine declined at run time, using software");
        return CRYPTOCB_UNAVAILABLE;
    }

    return ret;
}

#if defined(WOLFSSL_SEC_QORIQ_PKHA) || defined(WOLFSSL_SEC_QORIQ_RSA)
/* Scratch for key material handed to the engine. Stack resident unless the
 * build asks otherwise, and always zeroed back to memory: it was flushed to
 * DRAM for DMA, so zeroing cache alone leaves the secret behind. */
#ifdef WOLFSSL_SMALL_STACK
    #define SEC_CB_DECL(name, units)  byte* name = NULL
    #define SEC_CB_ALLOC(name, sz)                                        \
        do {                                                              \
            (name) = (byte*)XMALLOC((sz), NULL, DYNAMIC_TYPE_TMP_BUFFER); \
            if ((name) == NULL) {                                         \
                return MEMORY_E;                                          \
            }                                                             \
            XMEMSET((name), 0, (sz));                                     \
        } while (0)
    #define SEC_CB_FREE(name, sz)                                         \
        do {                                                              \
            wc_SecQoriqForceZeroDma((name), (sz));                        \
            XFREE((name), NULL, DYNAMIC_TYPE_TMP_BUFFER);                 \
        } while (0)
#else
    #define SEC_CB_DECL(name, units)  byte name[units]
    #define SEC_CB_ALLOC(name, sz)    XMEMSET((name), 0, (sz))
    #define SEC_CB_FREE(name, sz)     wc_SecQoriqForceZeroDma((name), (sz))
#endif
#endif

#ifndef NO_AES

/* Anything not describable in one descriptor comes back as
 * CRYPTOCB_UNAVAILABLE rather than an error, which would propagate straight
 * out of wc_AesCbcEncrypt and break calls software handles fine (a buffer
 * over 64 KB, or a length that is not a whole number of blocks). */
static int secCbCanDo(word32 sz, int needBlockMultiple)
{
    if (wc_SecQoriqGetDev() == NULL) {
        return 0;
    }
    if (sz < SEC_QORIQ_MIN_OFFLOAD_SZ || sz > SEC_QORIQ_MAX_XFER_SZ) {
        return 0;
    }
    if (needBlockMultiple && (sz % WC_AES_BLOCK_SIZE) != 0) {
        return 0;
    }
    return 1;
}

/* wolfCrypt hands the callback the whole buffer for these modes, so they map
 * straight onto the driver. */
static int secCbAes(wc_CryptoInfo* info)
{
    switch (info->cipher.type) {
    #ifdef HAVE_AES_CBC
        case WC_CIPHER_AES_CBC:
        {
            Aes* aes = info->cipher.aescbc.aes;

            if (aes == NULL || !secCbCanDo(info->cipher.aescbc.sz, 1)) {
                return CRYPTOCB_UNAVAILABLE;
            }
            if (info->cipher.enc) {
                return wc_SecQoriqAesCbcEncrypt((const byte*)aes->devKey,
                    aes->keylen, (byte*)aes->reg, info->cipher.aescbc.in,
                    info->cipher.aescbc.sz, info->cipher.aescbc.out);
            }
            return wc_SecQoriqAesCbcDecrypt((const byte*)aes->devKey,
                aes->keylen, (byte*)aes->reg, info->cipher.aescbc.in,
                info->cipher.aescbc.sz, info->cipher.aescbc.out);
        }
    #endif

    #ifdef WOLFSSL_AES_COUNTER
        case WC_CIPHER_AES_CTR:
        {
            Aes* aes = info->cipher.aesctr.aes;

            if (aes == NULL) {
                return CRYPTOCB_UNAVAILABLE;
            }
            /* wolfCrypt allows a partial trailing block and keeps the
             * leftover keystream in the context; the engine works in whole
             * blocks only. */
            if (aes->left != 0 || !secCbCanDo(info->cipher.aesctr.sz, 1)) {
                return CRYPTOCB_UNAVAILABLE;
            }
            return wc_SecQoriqAesCtrEncrypt((const byte*)aes->devKey,
                aes->keylen, (byte*)aes->reg, info->cipher.aesctr.in,
                info->cipher.aesctr.sz, info->cipher.aesctr.out);
        }
    #endif

    #ifdef HAVE_AES_ECB
        case WC_CIPHER_AES_ECB:
        {
            Aes* aes = info->cipher.aesecb.aes;

            if (aes == NULL || !secCbCanDo(info->cipher.aesecb.sz, 1)) {
                return CRYPTOCB_UNAVAILABLE;
            }
            if (info->cipher.enc) {
                return wc_SecQoriqAesEcbEncrypt((const byte*)aes->devKey,
                    aes->keylen, info->cipher.aesecb.in,
                    info->cipher.aesecb.sz, info->cipher.aesecb.out);
            }
            return wc_SecQoriqAesEcbDecrypt((const byte*)aes->devKey,
                aes->keylen, info->cipher.aesecb.in,
                info->cipher.aesecb.sz, info->cipher.aesecb.out);
        }
    #endif

    #ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM:
            if (info->cipher.enc) {
                Aes* aes = info->cipher.aesgcm_enc.aes;

                if (aes == NULL || wc_SecQoriqGetDev() == NULL ||
                        info->cipher.aesgcm_enc.ivSz != SEC_QORIQ_GCM_IV_SZ ||
                        info->cipher.aesgcm_enc.authTagSz !=
                            SEC_QORIQ_GCM_TAG_SZ ||
                        info->cipher.aesgcm_enc.sz > SEC_QORIQ_MAX_XFER_SZ ||
                        info->cipher.aesgcm_enc.authInSz >
                            SEC_QORIQ_MAX_XFER_SZ) {
                    return CRYPTOCB_UNAVAILABLE;
                }
                return wc_SecQoriqAesGcmEncrypt((const byte*)aes->devKey,
                    aes->keylen,
                    info->cipher.aesgcm_enc.iv, info->cipher.aesgcm_enc.ivSz,
                    info->cipher.aesgcm_enc.authIn,
                    info->cipher.aesgcm_enc.authInSz,
                    info->cipher.aesgcm_enc.in, info->cipher.aesgcm_enc.sz,
                    info->cipher.aesgcm_enc.out,
                    info->cipher.aesgcm_enc.authTag,
                    info->cipher.aesgcm_enc.authTagSz);
            }
            else {
                Aes* aes = info->cipher.aesgcm_dec.aes;

                if (aes == NULL || wc_SecQoriqGetDev() == NULL ||
                        info->cipher.aesgcm_dec.ivSz != SEC_QORIQ_GCM_IV_SZ ||
                        info->cipher.aesgcm_dec.authTagSz !=
                            SEC_QORIQ_GCM_TAG_SZ ||
                        info->cipher.aesgcm_dec.sz > SEC_QORIQ_MAX_XFER_SZ ||
                        info->cipher.aesgcm_dec.authInSz >
                            SEC_QORIQ_MAX_XFER_SZ) {
                    return CRYPTOCB_UNAVAILABLE;
                }
                return wc_SecQoriqAesGcmDecrypt((const byte*)aes->devKey,
                    aes->keylen,
                    info->cipher.aesgcm_dec.iv, info->cipher.aesgcm_dec.ivSz,
                    info->cipher.aesgcm_dec.authIn,
                    info->cipher.aesgcm_dec.authInSz,
                    info->cipher.aesgcm_dec.in, info->cipher.aesgcm_dec.sz,
                    info->cipher.aesgcm_dec.out,
                    info->cipher.aesgcm_dec.authTag,
                    info->cipher.aesgcm_dec.authTagSz);
            }
    #endif

        default:
            break;
    }

    return CRYPTOCB_UNAVAILABLE;
}
#endif /* !NO_AES */

#ifdef WOLFSSL_SEC_QORIQ_PKHA

/* Scratch layout, in units of the curve size: the private key or public
 * point, plus r and s. Verify needs the most at four. */
#define SEC_QORIQ_PK_SCRATCH_UNITS 4


/* The curve id lives in one of two places. -1 matches no curve. */
static int secCbCurveId(ecc_key* key)
{
    const ecc_set_type* dp = key->dp;

    if (dp == NULL) {
        dp = wc_ecc_get_curve_params(key->idx);
    }
    if (dp == NULL) {
        return -1;
    }

    return dp->id;
}

/* Common entry checks for the three public key operations. */
static int secCbEccSetup(ecc_key* key, int* curveId, int* keySz)
{
    if (key == NULL || wc_SecQoriqGetDev() == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }

    *curveId = secCbCurveId(key);
    *keySz = wc_ecc_size(key);
    if (*keySz <= 0 || *keySz > MAX_ECC_BYTES) {
        return CRYPTOCB_UNAVAILABLE;
    }

    if (wc_SecQoriqEccSupported(*curveId, (word32)*keySz) != 0) {
        return CRYPTOCB_UNAVAILABLE;
    }

    return 0;
}

/* Export the public point as raw fixed-width x || y (no 0x04 prefix).
 *
 * A key loaded from a private scalar alone has no public point until
 * something derives it, which wolfCrypt does lazily inside its software
 * verify. The engine cannot, and handing it zeros would produce a spurious
 * "bad signature", so an absent point goes back to software. */
static int secCbExportPub(ecc_key* key, byte* out, int keySz)
{
    if (key->type == ECC_PRIVATEKEY_ONLY) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (mp_iszero(key->pubkey.x) && mp_iszero(key->pubkey.y)) {
        return CRYPTOCB_UNAVAILABLE;
    }

    if (mp_to_unsigned_bin_len(key->pubkey.x, out, keySz) != MP_OKAY) {
        return MP_TO_E;
    }
    if (mp_to_unsigned_bin_len(key->pubkey.y, out + keySz, keySz) != MP_OKAY) {
        return MP_TO_E;
    }

    return 0;
}

#ifdef HAVE_ECC_SIGN
static int secCbEccSign(wc_CryptoInfo* info)
{
    ecc_key* key = info->pk.eccsign.key;
    word32 hashSz;
    int curveId = 0;
    int keySz = 0;
    int ret;
    byte* priv;
    byte* r;
    byte* s;
    mp_int mpr;
    mp_int mps;
    SEC_CB_DECL(buf, MAX_ECC_BYTES * SEC_QORIQ_PK_SCRATCH_UNITS);

    if (info->pk.eccsign.in == NULL || info->pk.eccsign.out == NULL ||
            info->pk.eccsign.outlen == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }

#if defined(WOLFSSL_ECDSA_DETERMINISTIC_K) || \
    defined(WOLFSSL_ECDSA_DETERMINISTIC_K_VARIANT)
    /* The protocol descriptor generates the per-signature nonce inside the
     * engine, so RFC 6979 cannot be honoured on this path. */
    if (key != NULL && key->deterministic) {
        return CRYPTOCB_UNAVAILABLE;
    }
#endif

    ret = secCbEccSetup(key, &curveId, &keySz);
    if (ret != 0) {
        return ret;
    }

    /* A digest wider than the group order is reduced the way ECDSA
     * prescribes down in the PKHA layer, which declines the one shape it
     * cannot express. */
    hashSz = info->pk.eccsign.inlen;
    if (hashSz == 0) {
        return CRYPTOCB_UNAVAILABLE;
    }

    SEC_CB_ALLOC(buf, (word32)keySz * 3);
    priv = buf;
    r    = buf + keySz;
    s    = buf + (keySz * 2);

    if (mp_to_unsigned_bin_len(wc_ecc_key_get_priv(key), priv, keySz) !=
            MP_OKAY) {
        ret = MP_TO_E;
    }
    else {
        ret = wc_SecQoriqEccSign(curveId, priv, info->pk.eccsign.in, hashSz,
            r, s, (word32)keySz);
    }

    /* Rebuild the ASN.1 SEQUENCE the caller expects from the raw pair. */
    if (ret == 0) {
        if (mp_init(&mpr) != MP_OKAY) {
            ret = MP_INIT_E;
        }
        else {
            if (mp_init(&mps) != MP_OKAY) {
                ret = MP_INIT_E;
                mp_free(&mpr);
            }
            else {
                if (mp_read_unsigned_bin(&mpr, r, (word32)keySz) != MP_OKAY ||
                    mp_read_unsigned_bin(&mps, s, (word32)keySz) != MP_OKAY) {
                    ret = MP_READ_E;
                }
                else {
                    ret = StoreECC_DSA_Sig(info->pk.eccsign.out,
                        info->pk.eccsign.outlen, &mpr, &mps);
                }
                mp_free(&mpr);
                mp_free(&mps);
            }
        }
    }

    SEC_CB_FREE(buf, (word32)keySz * 3);

    return ret;
}
#endif /* HAVE_ECC_SIGN */

#ifdef HAVE_ECC_VERIFY
static int secCbEccVerify(wc_CryptoInfo* info)
{
    ecc_key* key = info->pk.eccverify.key;
    word32 hashSz;
    int curveId = 0;
    int keySz = 0;
    int ret;
    byte* pub;
    byte* r;
    byte* s;
    mp_int mpr;
    mp_int mps;
    SEC_CB_DECL(buf, MAX_ECC_BYTES * SEC_QORIQ_PK_SCRATCH_UNITS);

    if (info->pk.eccverify.sig == NULL || info->pk.eccverify.hash == NULL ||
            info->pk.eccverify.res == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }

    ret = secCbEccSetup(key, &curveId, &keySz);
    if (ret != 0) {
        return ret;
    }

    hashSz = info->pk.eccverify.hashlen;
    if (hashSz == 0) {
        return CRYPTOCB_UNAVAILABLE;
    }

    /* Initialise first and use the form that expects it. The decoder clears
     * both halves on its error path, and clearing an mp_int that was never
     * initialised makes sp_clear() zero a garbage number of digits off the
     * stack. wc_ecc_verify_hash() takes the same route for the same reason. */
    if (mp_init_multi(&mpr, &mps, NULL, NULL, NULL, NULL) != MP_OKAY) {
        return CRYPTOCB_UNAVAILABLE;
    }
    ret = DecodeECC_DSA_Sig_Ex(info->pk.eccverify.sig,
        info->pk.eccverify.siglen, &mpr, &mps, 0);
    if (ret != 0) {
        /* A signature this malformed is software's to reject, so that the
         * caller sees exactly the error it would have without the engine.
         * The decoder has already cleared both halves. */
        return CRYPTOCB_UNAVAILABLE;
    }

#ifdef WOLFSSL_SMALL_STACK
    buf = (byte*)XMALLOC((word32)keySz * 4, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL) {
        mp_free(&mpr);
        mp_free(&mps);
        return MEMORY_E;
    }
#endif
    XMEMSET(buf, 0, (word32)keySz * 4);
    pub = buf; /* public data only, so no zeroization needed on the way out */
    r   = buf + (keySz * 2);
    s   = buf + (keySz * 3);

    /* r or s wider than the curve cannot be valid and does not fit the
     * fixed width block either; let software reject it. */
    if (mp_to_unsigned_bin_len(&mpr, r, keySz) != MP_OKAY ||
            mp_to_unsigned_bin_len(&mps, s, keySz) != MP_OKAY) {
        ret = CRYPTOCB_UNAVAILABLE;
    }
    else {
        ret = secCbExportPub(key, pub, keySz);
    }

    if (ret == 0) {
        ret = wc_SecQoriqEccVerify(curveId, pub, info->pk.eccverify.hash,
            hashSz, r, s, (word32)keySz, info->pk.eccverify.res);
    }

    mp_free(&mpr);
    mp_free(&mps);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}
#endif /* HAVE_ECC_VERIFY */

#ifdef HAVE_ECC_DHE
static int secCbEcdh(wc_CryptoInfo* info)
{
    ecc_key* privKey = info->pk.ecdh.private_key;
    ecc_key* pubKey  = info->pk.ecdh.public_key;
    int curveId = 0;
    int keySz = 0;
    int ret;
    byte* priv;
    byte* peer;
    SEC_CB_DECL(buf, MAX_ECC_BYTES * 3);

    if (pubKey == NULL || info->pk.ecdh.out == NULL ||
            info->pk.ecdh.outlen == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }

    ret = secCbEccSetup(privKey, &curveId, &keySz);
    if (ret != 0) {
        return ret;
    }

    /* Both keys have to be on the curve the descriptor names. */
    if (curveId != secCbCurveId(pubKey)) {
        return CRYPTOCB_UNAVAILABLE;
    }

    if (*info->pk.ecdh.outlen < (word32)keySz) {
        return CRYPTOCB_UNAVAILABLE;
    }

    SEC_CB_ALLOC(buf, (word32)keySz * 3);
    priv = buf;
    peer = buf + keySz;

    if (mp_to_unsigned_bin_len(wc_ecc_key_get_priv(privKey), priv, keySz) !=
            MP_OKAY) {
        ret = MP_TO_E;
    }
    else {
        ret = secCbExportPub(pubKey, peer, keySz);
    }

    if (ret == 0) {
        ret = wc_SecQoriqEcdh(curveId, priv, peer, info->pk.ecdh.out,
            (word32)keySz);
    }
    if (ret == 0) {
        *info->pk.ecdh.outlen = (word32)keySz;
    }

    /* priv was flushed to memory for the engine, so zeroing cache alone
     * would leave the scalar in DRAM. */
    SEC_CB_FREE(buf, (word32)keySz * 3);

    return ret;
}
#endif /* HAVE_ECC_DHE */

#endif /* WOLFSSL_SEC_QORIQ_PKHA */

#ifdef WOLFSSL_SEC_QORIQ_RSA

/* Sized by the largest key the build admits, not the largest the engine
 * takes, so an RSA-2048 build carries no 4096 bit buffer. */
#if (RSA_MAX_SIZE / 8) < SEC_QORIQ_PKHA_MAX_RSA_BYTES
    #define SEC_QORIQ_RSA_SCRATCH_BYTES (RSA_MAX_SIZE / 8)
#else
    #define SEC_QORIQ_RSA_SCRATCH_BYTES SEC_QORIQ_PKHA_MAX_RSA_BYTES
#endif

/* The callback is reached at wc_RsaFunction, the raw exponentiation with
 * padding already applied or not yet stripped, so it maps straight onto the
 * engine's RSA protocols.
 *
 * This bypasses wolfCrypt's base blinding for private key operations. That
 * blinding defends the software exponentiation from timing analysis, which
 * is not the code running here; a build that wants it kept can set
 * WOLFSSL_SEC_QORIQ_NO_RSA. */
static int secCbRsa(wc_CryptoInfo* info)
{
    RsaKey* key = info->pk.rsa.key;
    word32 nSz;
    word32 expSz;
#ifndef WOLFSSL_RSA_PUBLIC_ONLY
    int isPrivate;
#endif
    int ret;
    byte* nbuf;
    byte* xbuf;
    SEC_CB_DECL(buf, SEC_QORIQ_RSA_SCRATCH_BYTES * 2);

    if (key == NULL || info->pk.rsa.in == NULL || info->pk.rsa.out == NULL ||
            info->pk.rsa.outLen == NULL || wc_SecQoriqGetDev() == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }

    switch (info->pk.rsa.type) {
        case RSA_PUBLIC_ENCRYPT:
        case RSA_PUBLIC_DECRYPT:
        #ifndef WOLFSSL_RSA_PUBLIC_ONLY
            isPrivate = 0;
        #endif
            break;
        case RSA_PRIVATE_ENCRYPT:
        case RSA_PRIVATE_DECRYPT:
        #ifdef WOLFSSL_RSA_PUBLIC_ONLY
            return CRYPTOCB_UNAVAILABLE;
        #else
            isPrivate = 1;
            break;
        #endif
        default:
            return CRYPTOCB_UNAVAILABLE;
    }

    ret = mp_unsigned_bin_size(&key->n);
    if (ret <= 0) {
        return CRYPTOCB_UNAVAILABLE;
    }
    nSz = (word32)ret;
    if (nSz > SEC_QORIQ_RSA_SCRATCH_BYTES) {
        return CRYPTOCB_UNAVAILABLE;
    }

    /* The engine works on a whole modulus-width block. */
    if (info->pk.rsa.inLen != nSz || *info->pk.rsa.outLen < nSz) {
        return CRYPTOCB_UNAVAILABLE;
    }

#ifndef WOLFSSL_RSA_PUBLIC_ONLY
    ret = mp_unsigned_bin_size(isPrivate ? &key->d : &key->e);
#else
    ret = mp_unsigned_bin_size(&key->e);
#endif
    if (ret <= 0 || (word32)ret > nSz) {
        return CRYPTOCB_UNAVAILABLE;
    }
    expSz = (word32)ret;

    SEC_CB_ALLOC(buf, nSz * 2);
    nbuf = buf;
    xbuf = buf + nSz;

    if (mp_to_unsigned_bin_len(&key->n, nbuf, (int)nSz) != MP_OKAY) {
        ret = MP_TO_E;
    }
#ifndef WOLFSSL_RSA_PUBLIC_ONLY
    else if (isPrivate) {
        if (mp_to_unsigned_bin_len(&key->d, xbuf, (int)expSz) != MP_OKAY) {
            ret = MP_TO_E;
        }
        else {
            ret = wc_SecQoriqModExp(info->pk.rsa.in, xbuf, expSz, nbuf, nSz,
                info->pk.rsa.out);
        }
    }
#endif
    else {
        if (mp_to_unsigned_bin_len(&key->e, xbuf, (int)expSz) != MP_OKAY) {
            ret = MP_TO_E;
        }
        else {
            ret = wc_SecQoriqRsaPublic(info->pk.rsa.in, info->pk.rsa.inLen,
                nbuf, nSz, xbuf, expSz, info->pk.rsa.out);
        }
    }

    if (ret == 0) {
        *info->pk.rsa.outLen = nSz;
    }

    SEC_CB_FREE(buf, nSz * 2); /* xbuf held the private exponent */

    return ret;
}

#ifndef NO_DH
/* Finite field DH is the RSA private path's exponentiation: otherPub^priv
 * mod p. */
static int secCbDh(wc_CryptoInfo* info)
{
    DhKey* key = info->pk.dh.key;
    word32 pSz;
    int ret;
    byte* pbuf;
    SEC_CB_DECL(buf, SEC_QORIQ_RSA_SCRATCH_BYTES);

    if (key == NULL || info->pk.dh.priv == NULL ||
            info->pk.dh.otherPub == NULL || info->pk.dh.agree == NULL ||
            info->pk.dh.agreeSz == NULL || wc_SecQoriqGetDev() == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }

    ret = mp_unsigned_bin_size(&key->p);
    if (ret <= 0 || (word32)ret > SEC_QORIQ_RSA_SCRATCH_BYTES) {
        return CRYPTOCB_UNAVAILABLE;
    }
    pSz = (word32)ret;

    /* wolfCrypt hands the peer public value at its natural length, which is
     * usually but not always the full width. */
    if (info->pk.dh.pubSz != pSz || info->pk.dh.privSz == 0 ||
            info->pk.dh.privSz > pSz) {
        return CRYPTOCB_UNAVAILABLE;
    }

    SEC_CB_ALLOC(buf, pSz);
    pbuf = buf;

    if (mp_to_unsigned_bin_len(&key->p, pbuf, (int)pSz) != MP_OKAY) {
        ret = MP_TO_E;
    }
    else {
        ret = wc_SecQoriqModExp(info->pk.dh.otherPub, info->pk.dh.priv,
            info->pk.dh.privSz, pbuf, pSz, info->pk.dh.agree);
    }

    if (ret == 0) {
        /* wc_DhAgree()'s software paths return the shared secret with
         * leading zero bytes stripped and agreeSz shortened to match; the
         * fixed-width form is the separate wc_DhAgree_ct() contract. The
         * engine always writes a whole modulus, so strip here or a TLS 1.2
         * DHE premaster secret comes out one byte long roughly one time in
         * 256 and the handshake fails. */
        word32 lead = 0;

        while ((lead + 1 < pSz) && (info->pk.dh.agree[lead] == 0)) {
            lead++;
        }
        if (lead > 0) {
            XMEMMOVE(info->pk.dh.agree, info->pk.dh.agree + lead,
                pSz - lead);
        }
        *info->pk.dh.agreeSz = pSz - lead;
    }

    SEC_CB_FREE(buf, pSz); /* the group prime is public, but keep it uniform */

    return ret;
}
#endif /* !NO_DH */

#endif /* WOLFSSL_SEC_QORIQ_RSA */

#if defined(WOLFSSL_SEC_QORIQ_PKHA) || defined(WOLFSSL_SEC_QORIQ_RSA)

static int secCbPk(wc_CryptoInfo* info)
{
    switch (info->pk.type) {
    #ifdef WOLFSSL_SEC_QORIQ_RSA
        case WC_PK_TYPE_RSA:
            return secCbRsa(info);
        #ifndef NO_DH
        case WC_PK_TYPE_DH:
            return secCbDh(info);
        #endif
    #endif
    #ifdef WOLFSSL_SEC_QORIQ_PKHA
        #ifdef HAVE_ECC_SIGN
        case WC_PK_TYPE_ECDSA_SIGN:
            return secCbEccSign(info);
        #endif
        #ifdef HAVE_ECC_VERIFY
        case WC_PK_TYPE_ECDSA_VERIFY:
            return secCbEccVerify(info);
        #endif
        #ifdef HAVE_ECC_DHE
        case WC_PK_TYPE_ECDH:
            return secCbEcdh(info);
        #endif
    #endif
        default:
            break;
    }

    /* Key generation stays in software so the caller's WC_RNG remains the
     * source of the private key. */
    return CRYPTOCB_UNAVAILABLE;
}

#endif /* WOLFSSL_SEC_QORIQ_PKHA || WOLFSSL_SEC_QORIQ_RSA */

/* Hashing is single shot only, but wolfCrypt calls once per Update and
 * again for Final. Serving that needs either the streaming descriptor (class
 * 2 context round tripped per call) or WOLFSSL_HASH_KEEP. */
static int secCbHash(wc_CryptoInfo* info)
{
    (void)info;
    return CRYPTOCB_UNAVAILABLE;
}

static int secQoriqRouter(int devId, wc_CryptoInfo* info, void* ctx)
{
    SecQoriqDev* dev = wc_SecQoriqGetDev();
    int ret = CRYPTOCB_UNAVAILABLE;

    (void)devId;
    (void)ctx;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (info->algo_type) {
        case WC_ALGO_TYPE_CIPHER:
        #ifndef NO_AES
            if (dev != NULL) {
                dev->cbCipherCount++;
            }
            ret = secCbFallback(secCbAes(info));
            if (dev != NULL && ret != CRYPTOCB_UNAVAILABLE) {
                dev->cbCipherOffload++;
            }
        #endif
            break;

        case WC_ALGO_TYPE_PK:
        #if defined(WOLFSSL_SEC_QORIQ_PKHA) || defined(WOLFSSL_SEC_QORIQ_RSA)
            if (dev != NULL) {
                dev->cbPkCount++;
            }
            ret = secCbFallback(secCbPk(info));
            if (dev != NULL && ret != CRYPTOCB_UNAVAILABLE) {
                dev->cbPkOffload++;
            }
        #endif
            break;

        case WC_ALGO_TYPE_HASH:
            if (dev != NULL) {
                dev->cbHashCount++;
            }
            ret = secCbHash(info);
            if (dev != NULL && ret != CRYPTOCB_UNAVAILABLE) {
                dev->cbHashOffload++;
            }
            break;

    #ifndef WC_NO_RNG
        /* Seed only. WC_ALGO_TYPE_RNG is left unhandled so
         * wc_RNG_GenerateBlock keeps running wolfCrypt's DRBG, seeded from
         * the SEC. Answering RNG here would hand callers raw engine output
         * and drop the DRBG's reseeding policy and health checks. */
        case WC_ALGO_TYPE_SEED:
            if (dev != NULL) {
                dev->cbSeedCount++;
            }
            ret = wc_SecQoriqRandomBlock(info->seed.seed, info->seed.sz);
            if (ret != 0) {
                /* Fall back to the platform entropy source rather than
                 * leave the caller with no seed. */
                WOLFSSL_MSG("sec_qoriq: seed failed, falling back");
                ret = CRYPTOCB_UNAVAILABLE;
            }
            break;
    #endif

        default:
            /* everything else falls back to software */
            break;
    }

    return ret;
}

int wc_SecQoriqRegisterCryptoCb(void)
{
    return wc_CryptoCb_RegisterDevice(WOLFSSL_SEC_QORIQ_DEVID,
        secQoriqRouter, NULL);
}

void wc_SecQoriqUnregisterCryptoCb(void)
{
    wc_CryptoCb_UnRegisterDevice(WOLFSSL_SEC_QORIQ_DEVID);
}

#endif /* WOLFSSL_SEC_QORIQ && WOLF_CRYPTO_CB */
