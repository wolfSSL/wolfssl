/* wolfcaam_ecdsa.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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

#if defined(WOLFSSL_QNX_CAAM) && defined(HAVE_ECC)

#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/port/caam/wolfcaam.h>
#include <wolfssl/wolfcrypt/port/caam/wolfcaam_ecdsa.h>

#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/asn.h>

#if defined(WOLFSSL_CAAM_DEBUG) || defined(WOLFSSL_CAAM_PRINT)
#include <stdio.h>
#endif

/* helper function get the ECDSEL value, this is a value that signals the
 * hardware to use preloaded curve parameters
 */
static word32 GetECDSEL(int curveId, word32 PD_BIT)
{
    word32 ecdsel = 0;

    switch (curveId) {
        case ECC_SECP192R1:
            ecdsel = (PD_BIT | CAAM_ECDSA_P192);
            break;

        case ECC_SECP224R1:
            ecdsel = (PD_BIT | CAAM_ECDSA_P224);
            break;

        case ECC_CURVE_DEF:
        case ECC_SECP256R1:
            ecdsel = (PD_BIT | CAAM_ECDSA_P256);
            break;

        case ECC_SECP384R1:
            ecdsel = (PD_BIT | CAAM_ECDSA_P384);
            break;

        case ECC_SECP521R1:
            ecdsel = (PD_BIT | CAAM_ECDSA_P521);
            break;

        default:
            WOLFSSL_MSG("not using preset curve parameters");
    }

    return ecdsel;
}


/* create signature using CAAM
 * returns MP_OKAY on success
 */
int wc_CAAM_EccSign(const byte* in, int inlen, byte* out, word32* outlen,
        WC_RNG *rng, ecc_key *key)
{
    const ecc_set_type* dp;
    word32 args[4] = {0};
    CAAM_BUFFER buf[9]  = {0};
    int ret, keySz;
    word32 ecdsel = 0;
    byte r[MAX_ECC_BYTES] = {0};
    byte s[MAX_ECC_BYTES] = {0};
    word32 idx = 0;

    byte pk[MAX_ECC_BYTES] = {0};

    (void)rng;
    if (key->dp != NULL) {
        dp = key->dp;
    }
    else {
        dp = wc_ecc_get_curve_params(key->idx);
    }

    if (dp->id != ECC_SECP256R1) {
        WOLFSSL_MSG("Limiting CAAM to P256 for now");
        return CRYPTOCB_UNAVAILABLE;
    }

    /* check for known predetermined parameters */
    ecdsel = GetECDSEL(dp->id, CAAM_ECDSA_PD);
    if (ecdsel == 0) {
        WOLFSSL_MSG("Unsupported curve type");
        return BAD_FUNC_ARG;
    }

    keySz  = wc_ecc_size(key);

    /* private key */
    if (key->blackKey > 0) {
        buf[idx].TheAddress = (CAAM_ADDRESS)key->blackKey;
        args[0] = 1; /* is a black key */
    }
    else {
        if (mp_to_unsigned_bin_len(&key->k, pk, keySz) != MP_OKAY) {
            return MP_TO_E;
        }
        buf[idx].TheAddress = (CAAM_ADDRESS)pk;
        args[0] = 0; /* non black key */
    }
    buf[idx].Length = keySz;
    idx++;

    /* hash to sign */
    buf[idx].TheAddress = (CAAM_ADDRESS)in;
    buf[idx].Length = inlen;
    idx++;

    /* r output */
    buf[idx].TheAddress = (CAAM_ADDRESS)r;
    buf[idx].Length = keySz;
    idx++;

    /* s output */
    buf[idx].TheAddress = (CAAM_ADDRESS)s;
    buf[idx].Length = keySz;
    idx++;

    args[1] = ecdsel;
    args[2] = inlen;
    args[3] = keySz;

    ret = wc_caamAddAndWait(buf, idx, args, CAAM_ECDSA_SIGN);
    if (ret != 0)
        return -1;

    /* convert signature from raw bytes to signature format */
    {
        mp_int mpr, mps;
    
        mp_init(&mpr);
        mp_init(&mps);
    
        mp_read_unsigned_bin(&mpr, r, 32);
        mp_read_unsigned_bin(&mps, s, 32);

        ret = StoreECC_DSA_Sig(out, outlen, &mpr, &mps);
        mp_free(&mpr);
        mp_free(&mps);
        if (ret != 0) {
            WOLFSSL_MSG("Issue converting to signature");
            return -1;
        }
    }

    return MP_OKAY;
}


/* verify with individual r and s signature parts
 * returns MP_OKAY on success and sets 'res' to 1 if verified
 */
static int wc_CAAM_EccVerify_ex(mp_int* r, mp_int *s, const byte* hash,
        word32 hashlen, int* res, ecc_key* key)
{
    const ecc_set_type* dp;
    word32 args[4] = {0};
    CAAM_BUFFER buf[9] = {0};
    int ret;
    int keySz;
    word32 idx = 0;
    word32 ecdsel = 0;

    byte rbuf[MAX_ECC_BYTES] = {0};
    byte sbuf[MAX_ECC_BYTES] = {0};

    byte qx[MAX_ECC_BYTES] = {0};
    byte qy[MAX_ECC_BYTES] = {0};
    byte qxy[MAX_ECC_BYTES * 2] = {0};
    byte tmp[MAX_ECC_BYTES * 2] = {0};
    word32 qxLen, qyLen;

    if (key->dp != NULL) {
        dp = key->dp;
    }
    else {
        dp = wc_ecc_get_curve_params(key->idx);
    }

    /* right now only support P256 @TODO */
    if (dp->id != ECC_SECP256R1) {
        WOLFSSL_MSG("Only support P256 verify with CAAM for now");
        return CRYPTOCB_UNAVAILABLE;
    }

    /* check for known predetermined parameters */
    ecdsel = GetECDSEL(dp->id, CAAM_ECDSA_PD);

    if (ecdsel == 0) {
        WOLFSSL_MSG("Curve parameters not supported");
        return CRYPTOCB_UNAVAILABLE;
    }

    /* Wx,y public key */
    keySz = wc_ecc_size(key);
    if (key->securePubKey > 0) {
        buf[idx].TheAddress = (CAAM_ADDRESS)key->securePubKey;
        buf[idx].Length = keySz * 2;
        args[0] = 1; /* using public key in secure memory */
    }
    else {
        qxLen = qyLen = MAX_ECC_BYTES;
        wc_ecc_export_public_raw(key, qx, &qxLen, qy, &qyLen);
        XMEMCPY(qxy, qx, qxLen);
        XMEMCPY(qxy+qxLen, qy, qyLen);
        buf[idx].TheAddress = (CAAM_ADDRESS)qxy;
        buf[idx].Length = qxLen + qyLen;
    }
    idx++;

    buf[idx].TheAddress = (CAAM_ADDRESS)hash;
    buf[idx].Length = hashlen;
    idx++;

    if (mp_to_unsigned_bin_len(r, rbuf, keySz) != MP_OKAY) {
        return MP_TO_E;
    }

    buf[idx].TheAddress = (CAAM_ADDRESS)rbuf;
    buf[idx].Length = keySz;
    idx++;

    if (mp_to_unsigned_bin_len(s, sbuf, keySz) != MP_OKAY) {
        return MP_TO_E;
    }

    buf[idx].TheAddress = (CAAM_ADDRESS)sbuf;
    buf[idx].Length = keySz;
    idx++;

    /* temporary scratch buffer, the manual calls for it and HW expects it */
    buf[idx].TheAddress = (CAAM_ADDRESS)tmp;
    buf[idx].Length = sizeof(tmp);
    idx++;

    args[1] = ecdsel;
    args[2] = hashlen;
    args[3] = wc_ecc_size(key);
    ret = wc_caamAddAndWait(buf, idx, args, CAAM_ECDSA_VERIFY);

    *res = 0;
    if (ret == 0)
        *res = 1;

    return MP_OKAY;
}


/* Verify with ASN1 syntax around the signature
 * returns MP_OKAY on success
 */
int wc_CAAM_EccVerify(const byte* sig, word32 siglen, const byte* hash,
        word32 hashlen, int* res, ecc_key* key)
{
    int ret;
    mp_int r, s;

    ret = DecodeECC_DSA_Sig(sig, siglen, &r, &s);
    if (ret == 0) {
        ret = wc_CAAM_EccVerify_ex(&r, &s, hash, hashlen, res, key);
        mp_free(&r);
        mp_free(&s);
    }

    return ret;
}


/* Does ECDH operation using CAAM and returns MP_OKAY on success */
int wc_CAAM_Ecdh(ecc_key* private_key, ecc_key* public_key, byte* out,
        word32* outlen)
{
    const ecc_set_type* dp;
    word32 args[4] = {0};
    CAAM_BUFFER buf[9]  = {0};
    int ret, keySz;
    word32 ecdsel = 0; /* ecc parameters in hardware */
    word32 idx    = 0;

    byte pk[MAX_ECC_BYTES] = {0};
    byte qx[MAX_ECC_BYTES] = {0};
    byte qy[MAX_ECC_BYTES] = {0};
    byte qxy[MAX_ECC_BYTES * 2] = {0};
    word32 qxSz, qySz;

    if (private_key->dp != NULL) {
        dp = private_key->dp;
    }
    else {
        dp = wc_ecc_get_curve_params(private_key->idx);
    }

    if (dp->id != ECC_SECP256R1) {
        return CRYPTOCB_UNAVAILABLE;
    }

    /* check for known predetermined parameters */
    ecdsel = GetECDSEL(dp->id, CAAM_ECDSA_KEYGEN_PD);
    if (ecdsel == 0) { /* predefined value not known, loading all parameters */
        WOLFSSL_MSG("Unsupported curve parameters");
        return CRYPTOCB_UNAVAILABLE;
    }

    keySz = wc_ecc_size(private_key);
    if (*outlen < (word32)keySz) {
        WOLFSSL_MSG("out buffer is to small");
        return BUFFER_E;
    }

    /* public key */
    if (public_key->securePubKey > 0) {
        buf[idx].TheAddress = (CAAM_ADDRESS)public_key->securePubKey;
        buf[idx].Length = keySz * 2;
        args[1] = 1; /* using public key with secure memory address */
    }
    else {
        qxSz = qySz = MAX_ECC_BYTES;
        wc_ecc_export_public_raw(public_key, qx, &qxSz, qy, &qySz);
        XMEMCPY(qxy, qx, qxSz);
        XMEMCPY(qxy+qxSz, qy, qySz);
        buf[idx].TheAddress = (CAAM_ADDRESS)qxy;
        buf[idx].Length = qxSz + qySz;
    }
    idx++;

    /* private key */
    if (private_key->blackKey > 0) {
        buf[idx].TheAddress = (CAAM_ADDRESS)private_key->blackKey;
        args[0] = 1; /* is a black key */
    }
    else {
        if (keySz > MAX_ECC_BYTES) {
            return BUFFER_E;
        }

        if (mp_to_unsigned_bin_len(&private_key->k, pk, keySz) != MP_OKAY) {
            return MP_TO_E;
        }

        buf[idx].TheAddress = (CAAM_ADDRESS)pk;
        args[0] = 0; /* non black key */
    }
    buf[idx].Length = keySz;
    idx++;

    /* output shared secret */
    buf[idx].TheAddress = (CAAM_ADDRESS)out;
    buf[idx].Length = keySz;
    idx++;

    args[2] = ecdsel;
    args[3] = keySz;
    ret = wc_caamAddAndWait(buf, idx, args, CAAM_ECDSA_ECDH);
    if (ret == 0) {
        *outlen = keySz;
        return MP_OKAY;
    }
    else {
        return -1;
    }
}


/* [ private black key ] [ x , y ] */
int wc_CAAM_MakeEccKey(WC_RNG* rng, int keySize, ecc_key* key, int curveId)
{
    word32 args[4] = {0};
    CAAM_BUFFER buf[2]  = {0};
    word32 ecdsel = 0;

    int ret;

    byte s[MAX_ECC_BYTES] = {0};
    byte xy[MAX_ECC_BYTES*2] = {0};

    key->type = ECC_PRIVATEKEY;

    /* if set to default curve then assume SECP256R1 */
    if (keySize == 32 && curveId == ECC_CURVE_DEF) curveId = ECC_SECP256R1;

    if (curveId != ECC_SECP256R1) {
        /* currently only implemented P256 support */
        return CRYPTOCB_UNAVAILABLE;
    }

    ecdsel = GetECDSEL(curveId, CAAM_ECDSA_KEYGEN_PD);
    if (ecdsel == 0) {
        WOLFSSL_MSG("unknown key type or size");
        return CRYPTOCB_UNAVAILABLE;
    }

    (void)rng;

    buf[0].TheAddress = (CAAM_ADDRESS)s;
    buf[0].Length     = keySize;
    buf[1].TheAddress = (CAAM_ADDRESS)xy;
    buf[1].Length     = keySize*2;

    args[0] = 1; /* Creating Black Key */
    args[1] = ecdsel;

    ret = wc_caamAddAndWait(buf, 2, args, CAAM_ECDSA_KEYPAIR);
    if (args[0] == 1 && ret == 0) { 
        key->blackKey     = (word32)buf[0].TheAddress;
        key->securePubKey = (word32)buf[1].TheAddress;
        key->partNum = args[2];
        return MP_OKAY;
    }
    if (args[0] == 0 && ret == 0) {
        if (wc_ecc_import_unsigned(key, xy, xy + keySize,
                   s, curveId) != 0) {
            WOLFSSL_MSG("issue importing key");
            return -1;
        }
        return MP_OKAY;
    }
    return -1;
}


/* if dealing with a black encrypted key then it can not be checked */
int wc_CAAM_EccCheckPrivKey(ecc_key* key, const byte* pubKey, word32 pubKeySz) {
    (void)pubKey;
    (void)pubKeySz;

    if (key->dp->id == ECC_SECP256R1 && key->blackKey > 0) {
        return 0;
    }
    return CRYPTOCB_UNAVAILABLE;
}

#endif /* WOLFSSL_QNX_CAAM && HAVE_ECC */
