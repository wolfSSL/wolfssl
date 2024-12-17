/* ed25519.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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


 /* Based On Daniel J Bernstein's ed25519 Public Domain ref10 work. */


/* Possible Ed25519 enable options:
 *   WOLFSSL_EDDSA_CHECK_PRIV_ON_SIGN                               Default: OFF
 *     Check that the private key didn't change during the signing operations.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* in case user set HAVE_ED25519 there */
#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_ED25519
#if FIPS_VERSION3_GE(6,0,0)
    /* set NO_WRAPPERS before headers, use direct internal f()s not wrappers */
    #define FIPS_NO_WRAPPERS

       #ifdef USE_WINDOWS_API
               #pragma code_seg(".fipsA$f")
               #pragma const_seg(".fipsB$f")
       #endif
#endif

#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/ge_operations.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#if FIPS_VERSION3_GE(6,0,0)
    const unsigned int wolfCrypt_FIPS_ed25519_ro_sanity[2] =
                                                     { 0x1a2b3c4d, 0x00000006 };
    int wolfCrypt_FIPS_ED25519_sanity(void)
    {
        return 0;
    }
#endif

#ifdef FREESCALE_LTC_ECC
    #include <wolfssl/wolfcrypt/port/nxp/ksdk_port.h>
#endif
#ifdef WOLFSSL_SE050
    #include <wolfssl/wolfcrypt/port/nxp/se050_port.h>
#endif

#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif

#if defined(HAVE_ED25519_SIGN) || defined(HAVE_ED25519_VERIFY)
    /* Set a static message string for "Sig No Collisions Message SNC".
    ** Note this is a static string per spec, see:
    ** https://datatracker.ietf.org/doc/rfc8032/
    */
    #define ED25519CTX_SNC_MESSAGE "SigEd25519 no Ed25519 collisions"
    #define ED25519CTX_SIZE 32 /* 32 chars: fixed length of SNC Message. */

    /* The 32 bytes of ED25519CTX_SIZE is used elsewhere, but we need one
    ** more char for saving the line ending in our ed25519Ctx[] here: */
    static const byte ed25519Ctx[ED25519CTX_SIZE + 1] = ED25519CTX_SNC_MESSAGE;
#endif

static int ed25519_hash_init(ed25519_key* key, wc_Sha512 *sha)
{
    int ret;

#ifndef WOLFSSL_ED25519_PERSISTENT_SHA
    /* when not using persistent SHA, we'll zero the sha param */
    XMEMSET(sha, 0, sizeof(wc_Sha512));
#endif

    ret = wc_InitSha512_ex(sha, key->heap,

#if defined(WOLF_CRYPTO_CB)
                           key->devId
#else
                           INVALID_DEVID
#endif
        );

#ifdef WOLFSSL_ED25519_PERSISTENT_SHA
    if (ret == 0)
        key->sha_clean_flag = 1;
#endif

    return ret;
}

#ifdef WOLFSSL_ED25519_PERSISTENT_SHA
static int ed25519_hash_reset(ed25519_key* key)
{
    int ret;
    if (key->sha_clean_flag)
        ret = 0;
    else {
        wc_Sha512Free(&key->sha);
        ret = wc_InitSha512_ex(&key->sha, key->heap,
#if defined(WOLF_CRYPTO_CB)
                               key->devId
#else
                               INVALID_DEVID
#endif
            );
        if (ret == 0)
            key->sha_clean_flag = 1;
    }
    return ret;
}
#endif /* WOLFSSL_ED25519_PERSISTENT_SHA */

static int ed25519_hash_update(ed25519_key* key, wc_Sha512 *sha,
                               const byte* data, word32 len)
{
#ifdef WOLFSSL_ED25519_PERSISTENT_SHA
    if (key->sha_clean_flag)
        key->sha_clean_flag = 0;
#else
    (void)key;
#endif
    return wc_Sha512Update(sha, data, len);
}

static int ed25519_hash_final(ed25519_key* key, wc_Sha512 *sha, byte* hash)
{
    int ret = wc_Sha512Final(sha, hash);
#ifdef WOLFSSL_ED25519_PERSISTENT_SHA
    if (ret == 0)
        key->sha_clean_flag = 1;
#else
    (void)key;
#endif
    return ret;
}

static void ed25519_hash_free(ed25519_key* key, wc_Sha512 *sha)
{
    wc_Sha512Free(sha);
#ifdef WOLFSSL_ED25519_PERSISTENT_SHA
    key->sha_clean_flag = 0;
#else
    (void)key;
#endif
}


static int ed25519_hash(ed25519_key* key, const byte* in, word32 inLen,
    byte* hash)
{
    int ret;
#ifndef WOLFSSL_ED25519_PERSISTENT_SHA
    wc_Sha512 sha[1];
#else
    wc_Sha512 *sha;
#endif

    if (key == NULL || (in == NULL && inLen > 0) || hash == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_ED25519_PERSISTENT_SHA
    sha = &key->sha;
    ret = ed25519_hash_reset(key);
#else
    ret = ed25519_hash_init(key, sha);
#endif
    if (ret < 0)
        return ret;

    ret = ed25519_hash_update(key, sha, in, inLen);
    if (ret == 0)
        ret = ed25519_hash_final(key, sha, hash);

#ifndef WOLFSSL_ED25519_PERSISTENT_SHA
    ed25519_hash_free(key, sha);
#endif

    return ret;
}

#ifdef HAVE_ED25519_MAKE_KEY
#if FIPS_VERSION3_GE(6,0,0)
/* Performs a Pairwise Consistency Test on an Ed25519 key pair.
 *
 * @param [in] key  Ed25519 key to test.
 * @param [in] rng  Random number generator to use to create random digest.
 * @return  0 on success.
 * @return  ECC_PCT_E when signing or verification fail.
 * @return  Other -ve when random number generation fails.
 */
static int ed25519_pairwise_consistency_test(ed25519_key* key, WC_RNG* rng)
{
    int err = 0;
    byte digest[WC_SHA512_DIGEST_SIZE];
    word32 digestLen = WC_SHA512_DIGEST_SIZE;
    byte sig[ED25519_SIG_SIZE];
    word32 sigLen = ED25519_SIG_SIZE;
    int res = 0;

    /* Generate a random digest to sign. */
    err = wc_RNG_GenerateBlock(rng, digest, digestLen);
    if (err == 0) {
        /* Sign digest without context. */
        err = wc_ed25519_sign_msg_ex(digest, digestLen, sig, &sigLen, key,
            (byte)Ed25519, NULL, 0);
        if (err != 0) {
            /* Any sign failure means test failed. */
            err = ECC_PCT_E;
        }
    }
    if (err == 0) {
        /* Verify digest without context. */
        err = wc_ed25519_verify_msg_ex(sig, sigLen, digest, digestLen, &res,
            key, (byte)Ed25519, NULL, 0);
        if (err != 0) {
            /* Any verification operation failure means test failed. */
            err = ECC_PCT_E;
        }
        /* Check whether the signature verified. */
        else if (res == 0) {
            /* Test failed. */
            err = ECC_PCT_E;
        }
    }

    ForceZero(sig, sigLen);

    return err;
}
#endif

int wc_ed25519_make_public(ed25519_key* key, unsigned char* pubKey,
                           word32 pubKeySz)
{
    int   ret = 0;
    ALIGN16 byte az[ED25519_PRV_KEY_SIZE];
#if !defined(FREESCALE_LTC_ECC)
    ge_p3 A;
#endif

    if (key == NULL || pubKey == NULL || pubKeySz != ED25519_PUB_KEY_SIZE)
        ret = BAD_FUNC_ARG;

    if ((ret == 0) && (!key->privKeySet)) {
        ret = ECC_PRIV_KEY_E;
    }

    if (ret == 0)
        ret = ed25519_hash(key, key->k, ED25519_KEY_SIZE, az);
    if (ret == 0) {
        /* apply clamp */
        az[0]  &= 248;
        az[31] &= 63; /* same than az[31] &= 127 because of az[31] |= 64 */
        az[31] |= 64;

    #ifdef FREESCALE_LTC_ECC
        ltc_pkha_ecc_point_t publicKey = {0};
        publicKey.X = key->pointX;
        publicKey.Y = key->pointY;
        LTC_PKHA_Ed25519_PointMul(LTC_PKHA_Ed25519_BasePoint(), az,
            ED25519_KEY_SIZE, &publicKey, kLTC_Ed25519 /* result on Ed25519 */);
        LTC_PKHA_Ed25519_Compress(&publicKey, pubKey);
    #else
        ge_scalarmult_base(&A, az);
        ge_p3_tobytes(pubKey, &A);
    #endif

        key->pubKeySet = 1;
    }

    return ret;
}

/* generate an ed25519 key pair.
 * returns 0 on success
 */
int wc_ed25519_make_key(WC_RNG* rng, int keySz, ed25519_key* key)
{
    int ret;

    if (rng == NULL || key == NULL)
        return BAD_FUNC_ARG;

    /* ed25519 has 32 byte key sizes */
    if (keySz != ED25519_KEY_SIZE)
        return BAD_FUNC_ARG;

    key->privKeySet = 0;
    key->pubKeySet = 0;

#ifdef WOLF_CRYPTO_CB
    if (key->devId != INVALID_DEVID) {
        ret = wc_CryptoCb_Ed25519Gen(rng, keySz, key);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return ret;
        /* fall-through when unavailable */
    }
#endif

    ret = wc_RNG_GenerateBlock(rng, key->k, ED25519_KEY_SIZE);
    if (ret != 0)
        return ret;

    key->privKeySet = 1;
    ret = wc_ed25519_make_public(key, key->p, ED25519_PUB_KEY_SIZE);
    if (ret != 0) {
        key->privKeySet = 0;
        ForceZero(key->k, ED25519_KEY_SIZE);
        return ret;
    }

    /* put public key after private key, on the same buffer */
    XMEMMOVE(key->k + ED25519_KEY_SIZE, key->p, ED25519_PUB_KEY_SIZE);

#if FIPS_VERSION3_GE(6,0,0)
    ret = wc_ed25519_check_key(key);
    if (ret == 0) {
        ret = ed25519_pairwise_consistency_test(key, rng);
    }
#endif

    return ret;
}
#endif /* HAVE_ED25519_MAKE_KEY */


#ifdef HAVE_ED25519_SIGN
/*
    in          contains the message to sign
    inLen       is the length of the message to sign
    out         is the buffer to write the signature
    outLen      [in/out] input size of out buf
                          output gets set as the final length of out
    key         is the ed25519 key to use when signing
    type        one of Ed25519, Ed25519ctx or Ed25519ph
    context     extra signing data
    contextLen  length of extra signing data
    return 0 on success
 */
int wc_ed25519_sign_msg_ex(const byte* in, word32 inLen, byte* out,
                            word32 *outLen, ed25519_key* key, byte type,
                            const byte* context, byte contextLen)
{
    int    ret;
#ifdef WOLFSSL_SE050
    (void)context;
    (void)contextLen;
    (void)type;
    ret = se050_ed25519_sign_msg(in, inLen, out, outLen, key);
#else
#ifdef FREESCALE_LTC_ECC
    ALIGN16 byte tempBuf[ED25519_PRV_KEY_SIZE];
    ltc_pkha_ecc_point_t ltcPoint = {0};
#else
    ge_p3  R;
#endif
    ALIGN16 byte nonce[WC_SHA512_DIGEST_SIZE];
    ALIGN16 byte hram[WC_SHA512_DIGEST_SIZE];
    ALIGN16 byte az[ED25519_PRV_KEY_SIZE];
#ifdef WOLFSSL_EDDSA_CHECK_PRIV_ON_SIGN
    byte orig_k[ED25519_KEY_SIZE];
#endif

    /* sanity check on arguments */
    if (in == NULL || out == NULL || outLen == NULL || key == NULL ||
                                         (context == NULL && contextLen != 0)) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    if (key->devId != INVALID_DEVID) {
        ret = wc_CryptoCb_Ed25519Sign(in, inLen, out, outLen, key, type,
            context, contextLen);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return ret;
        /* fall-through when unavailable */
    }
#endif

    if (!key->pubKeySet)
        return BAD_FUNC_ARG;

    /* check and set up out length */
    if (*outLen < ED25519_SIG_SIZE) {
        *outLen = ED25519_SIG_SIZE;
        return BUFFER_E;
    }
    *outLen = ED25519_SIG_SIZE;

#ifdef WOLFSSL_EDDSA_CHECK_PRIV_ON_SIGN
    XMEMCPY(orig_k, key->k, ED25519_KEY_SIZE);
#endif

    /* step 1: create nonce to use where nonce is r in
       r = H(h_b, ... ,h_2b-1,M) */
    ret = ed25519_hash(key, key->k, ED25519_KEY_SIZE, az);
    if (ret != 0)
        return ret;

    /* apply clamp */
    az[0]  &= 248;
    az[31] &= 63; /* same than az[31] &= 127 because of az[31] |= 64 */
    az[31] |= 64;

    {
#ifdef WOLFSSL_ED25519_PERSISTENT_SHA
        wc_Sha512 *sha = &key->sha;
#else
        wc_Sha512 sha[1];
        ret = ed25519_hash_init(key, sha);
        if (ret < 0) {
            return ret;
        }
#endif

        if (type == Ed25519ctx || type == Ed25519ph) {
            ret = ed25519_hash_update(key, sha, ed25519Ctx, ED25519CTX_SIZE);
            if (ret == 0)
                ret = ed25519_hash_update(key, sha, &type, sizeof(type));
            if (ret == 0)
                ret = ed25519_hash_update(key, sha, &contextLen,
                                          sizeof(contextLen));
            if (ret == 0 && context != NULL)
                ret = ed25519_hash_update(key, sha, context, contextLen);
        }
        if (ret == 0)
            ret = ed25519_hash_update(key, sha, az + ED25519_KEY_SIZE,
                                      ED25519_KEY_SIZE);
        if (ret == 0)
            ret = ed25519_hash_update(key, sha, in, inLen);
        if (ret == 0)
            ret = ed25519_hash_final(key, sha, nonce);
#ifndef WOLFSSL_ED25519_PERSISTENT_SHA
        ed25519_hash_free(key, sha);
#endif
    }

    if (ret != 0)
        return ret;

#ifdef FREESCALE_LTC_ECC
    ltcPoint.X = &tempBuf[0];
    ltcPoint.Y = &tempBuf[32];
    LTC_PKHA_sc_reduce(nonce);
    LTC_PKHA_Ed25519_PointMul(LTC_PKHA_Ed25519_BasePoint(), nonce,
           ED25519_KEY_SIZE, &ltcPoint, kLTC_Ed25519 /* result on Ed25519 */);
    LTC_PKHA_Ed25519_Compress(&ltcPoint, out);
#else
    sc_reduce(nonce);

    /* step 2: computing R = rB where rB is the scalar multiplication of
       r and B */
    ge_scalarmult_base(&R,nonce);
    ge_p3_tobytes(out,&R);
#endif

    /* step 3: hash R + public key + message getting H(R,A,M) then
       creating S = (r + H(R,A,M)a) mod l */
    {
#ifdef WOLFSSL_ED25519_PERSISTENT_SHA
        wc_Sha512 *sha = &key->sha;
#else
        wc_Sha512 sha[1];

        ret = ed25519_hash_init(key, sha);
        if (ret < 0)
            return ret;
#endif

        if (type == Ed25519ctx || type == Ed25519ph) {
            ret = ed25519_hash_update(key, sha, ed25519Ctx, ED25519CTX_SIZE);
            if (ret == 0)
                ret = ed25519_hash_update(key, sha, &type, sizeof(type));
            if (ret == 0)
                ret = ed25519_hash_update(key, sha, &contextLen,
                                          sizeof(contextLen));
            if (ret == 0 && context != NULL)
                ret = ed25519_hash_update(key, sha, context, contextLen);
        }
        if (ret == 0)
            ret = ed25519_hash_update(key, sha, out, ED25519_SIG_SIZE/2);
        if (ret == 0)
            ret = ed25519_hash_update(key, sha, key->p, ED25519_PUB_KEY_SIZE);
        if (ret == 0)
            ret = ed25519_hash_update(key, sha, in, inLen);
        if (ret == 0)
            ret = ed25519_hash_final(key, sha, hram);
#ifndef WOLFSSL_ED25519_PERSISTENT_SHA
        ed25519_hash_free(key, sha);
#endif
    }

    if (ret != 0)
        return ret;

#ifdef FREESCALE_LTC_ECC
    LTC_PKHA_sc_reduce(hram);
    LTC_PKHA_sc_muladd(out + (ED25519_SIG_SIZE/2), hram, az, nonce);
#else
    sc_reduce(hram);
    sc_muladd(out + (ED25519_SIG_SIZE/2), hram, az, nonce);
#endif
#endif /* WOLFSSL_SE050 */

#ifdef WOLFSSL_EDDSA_CHECK_PRIV_ON_SIGN
    {
        int  i;
        byte c = 0;
        for (i = 0; i < ED25519_KEY_SIZE; i++) {
            c |= key->k[i] ^ orig_k[i];
        }
        ret = ctMaskGT(c, 0) & SIG_VERIFY_E;
    }
#endif

    return ret;
}

/*
    in     contains the message to sign
    inLen  is the length of the message to sign
    out    is the buffer to write the signature
    outLen [in/out] input size of out buf
                     output gets set as the final length of out
    key    is the ed25519 key to use when signing
    return 0 on success
 */
int wc_ed25519_sign_msg(const byte* in, word32 inLen, byte* out,
                        word32 *outLen, ed25519_key* key)
{
    return wc_ed25519_sign_msg_ex(in, inLen, out, outLen, key, (byte)Ed25519,
        NULL, 0);
}

/*
    in          contains the message to sign
    inLen       is the length of the message to sign
    out         is the buffer to write the signature
    outLen      [in/out] input size of out buf
                          output gets set as the final length of out
    key         is the ed25519 key to use when signing
    context     extra signing data
    contextLen  length of extra signing data
    return 0 on success
 */
int wc_ed25519ctx_sign_msg(const byte* in, word32 inLen, byte* out,
                           word32 *outLen, ed25519_key* key,
                           const byte* context, byte contextLen)
{
    return wc_ed25519_sign_msg_ex(in, inLen, out, outLen, key, Ed25519ctx,
                                                           context, contextLen);
}

/*
    hash        contains the SHA-512 hash of the message to sign
    hashLen     is the length of the SHA-512 hash of the message to sign
    out         is the buffer to write the signature
    outLen      [in/out] input size of out buf
                          output gets set as the final length of out
    key         is the ed25519 key to use when signing
    context     extra signing data
    contextLen  length of extra signing data
    return 0 on success
 */
int wc_ed25519ph_sign_hash(const byte* hash, word32 hashLen, byte* out,
                           word32 *outLen, ed25519_key* key,
                           const byte* context, byte contextLen)
{
    return wc_ed25519_sign_msg_ex(hash, hashLen, out, outLen, key, Ed25519ph,
                                                           context, contextLen);
}

/*
    in          contains the message to sign
    inLen       is the length of the message to sign
    out         is the buffer to write the signature
    outLen      [in/out] input size of out buf
                          output gets set as the final length of out
    key         is the ed25519 key to use when signing
    context     extra signing data
    contextLen  length of extra signing data
    return 0 on success
 */
int wc_ed25519ph_sign_msg(const byte* in, word32 inLen, byte* out,
                          word32 *outLen, ed25519_key* key,
                          const byte* context, byte contextLen)
{
    int  ret;
    byte hash[WC_SHA512_DIGEST_SIZE];

    ret = ed25519_hash(key, in, inLen, hash);
    if (ret != 0)
        return ret;

    return wc_ed25519_sign_msg_ex(hash, sizeof(hash), out, outLen, key,
                                                Ed25519ph, context, contextLen);
}
#endif /* HAVE_ED25519_SIGN */

#ifdef HAVE_ED25519_VERIFY
#ifndef WOLFSSL_SE050

#ifdef WOLFSSL_CHECK_VER_FAULTS
static const byte sha512_empty[] = {
    0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
    0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
    0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
    0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
    0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
    0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
    0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
    0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e
};

/* sanity check that hash operation happened
 * returns 0 on success */
static int ed25519_hash_check(ed25519_key* key, byte* h)
{
    (void)key; /* passing in key in case other hash algroithms are used */

    if (XMEMCMP(h, sha512_empty, WC_SHA512_DIGEST_SIZE) != 0) {
        return 0;
    }
    else {
        return BAD_STATE_E;
    }
}
#endif


/*
   sig        is array of bytes containing the signature
   sigLen     is the length of sig byte array
   key        Ed25519 public key
   return     0 on success
   type       variant to use -- Ed25519, Ed25519ctx, or Ed25519ph
   context    extra signing data
   contextLen length of extra signing data
*/
static int ed25519_verify_msg_init_with_sha(const byte* sig, word32 sigLen,
                                            ed25519_key* key, wc_Sha512 *sha,
                                            byte type, const byte* context,
                                            byte contextLen)
{
    int ret;

    /* sanity check on arguments */
    if (sig == NULL || key == NULL ||
        (context == NULL && contextLen != 0)) {
        return BAD_FUNC_ARG;
    }

    /* check on basics needed to verify signature */
    if (sigLen != ED25519_SIG_SIZE || (sig[ED25519_SIG_SIZE-1] & 224))
        return BAD_FUNC_ARG;

    /* find H(R,A,M) and store it as h */

#ifdef WOLFSSL_ED25519_PERSISTENT_SHA
    ret = ed25519_hash_reset(key);
    if (ret != 0)
        return ret;
#else
    ret = 0;
#endif

    if (type == Ed25519ctx || type == Ed25519ph) {
        ret = ed25519_hash_update(key, sha, ed25519Ctx, ED25519CTX_SIZE);
        if (ret == 0)
            ret = ed25519_hash_update(key, sha, &type, sizeof(type));
        if (ret == 0)
            ret = ed25519_hash_update(key, sha, &contextLen, sizeof(contextLen));
        if (ret == 0 && context != NULL)
            ret = ed25519_hash_update(key, sha, context, contextLen);
    }
    if (ret == 0)
        ret = ed25519_hash_update(key, sha, sig, ED25519_SIG_SIZE/2);

#ifdef WOLFSSL_CHECK_VER_FAULTS
    /* sanity check that hash operation happened */
    if (ret == 0) {
        byte h[WC_MAX_DIGEST_SIZE];

        ret = wc_Sha512GetHash(sha, h);
        if (ret == 0) {
            ret = ed25519_hash_check(key, h);
            if (ret != 0) {
                WOLFSSL_MSG("Unexpected initial state of hash found");
            }
        }
    }
#endif

    if (ret == 0)
        ret = ed25519_hash_update(key, sha, key->p, ED25519_PUB_KEY_SIZE);

    return ret;
}

/*
   msgSegment     an array of bytes containing a message segment
   msgSegmentLen  length of msgSegment
   key            Ed25519 public key
   return         0 on success
*/
static int ed25519_verify_msg_update_with_sha(const byte* msgSegment,
                                              word32 msgSegmentLen,
                                              ed25519_key* key,
                                              wc_Sha512 *sha) {
    /* sanity check on arguments */
    if (msgSegment == NULL || key == NULL)
        return BAD_FUNC_ARG;

    return ed25519_hash_update(key, sha, msgSegment, msgSegmentLen);
}

/* ed25519 order in little endian. */
static const byte ed25519_order[] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

/*
   sig     is array of bytes containing the signature
   sigLen  is the length of sig byte array
   res     will be 1 on successful verify and 0 on unsuccessful
   key     Ed25519 public key
   return  0 and res of 1 on success
*/
static int ed25519_verify_msg_final_with_sha(const byte* sig, word32 sigLen,
                                             int* res, ed25519_key* key,
                                             wc_Sha512 *sha)
{
    ALIGN16 byte rcheck[ED25519_KEY_SIZE];
    ALIGN16 byte h[WC_SHA512_DIGEST_SIZE];
#ifndef FREESCALE_LTC_ECC
    ge_p3  A;
    ge_p2  R;
#endif
    int    ret;
    int    i;

    /* sanity check on arguments */
    if (sig == NULL || res == NULL || key == NULL)
        return BAD_FUNC_ARG;

    /* set verification failed by default */
    *res = 0;

    /* check on basics needed to verify signature */
    if (sigLen != ED25519_SIG_SIZE)
        return BAD_FUNC_ARG;
    /* S is not larger or equal to the order:
     *     2^252 + 0x14def9dea2f79cd65812631a5cf5d3ed
     *   = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
     */

    /* Check S is not larger than or equal to order. */
    for (i = (int)sizeof(ed25519_order) - 1; i >= 0; i--) {
        /* Bigger than order. */
        if (sig[ED25519_SIG_SIZE/2 + i] > ed25519_order[i])
            return BAD_FUNC_ARG;
        /* Less than order. */
        if (sig[ED25519_SIG_SIZE/2 + i] < ed25519_order[i])
            break;
    }
    /* Check equal - all bytes match. */
    if (i == -1)
        return BAD_FUNC_ARG;

    /* uncompress A (public key), test if valid, and negate it */
#ifndef FREESCALE_LTC_ECC
    if (ge_frombytes_negate_vartime(&A, key->p) != 0)
        return BAD_FUNC_ARG;
#endif

    /* find H(R,A,M) and store it as h */

    ret = ed25519_hash_final(key, sha, h);
    if (ret != 0)
        return ret;

#ifdef FREESCALE_LTC_ECC
    ret = LTC_PKHA_sc_reduce(h);
    if (ret != kStatus_Success)
        return ret;
    ret = LTC_PKHA_SignatureForVerify(rcheck, h, sig + (ED25519_SIG_SIZE/2), key);
    if (ret != kStatus_Success)
        return ret;
#else
    sc_reduce(h);

    /*
       Uses a fast single-signature verification SB = R + H(R,A,M)A becomes
       SB - H(R,A,M)A saving decompression of R
    */
    ret = ge_double_scalarmult_vartime(&R, h, &A, sig + (ED25519_SIG_SIZE/2));
    if (ret != 0)
        return ret;

    ge_tobytes(rcheck, &R);
#endif /* FREESCALE_LTC_ECC */

    /* comparison of R created to R in sig */
    ret = ConstantCompare(rcheck, sig, ED25519_SIG_SIZE/2);
    if (ret != 0) {
        ret = SIG_VERIFY_E;
    }

#ifdef WOLFSSL_CHECK_VER_FAULTS
    /* redundant comparison as sanity check that first one happened */
    if (ret == 0 && ConstantCompare(rcheck, sig, ED25519_SIG_SIZE/2) != 0) {
        ret = SIG_VERIFY_E;
    }
#endif

    if (ret == 0) {
        /* set the verification status */
        *res = 1;
    }

    return ret;
}
#endif /* WOLFSSL_SE050 */

#if defined(WOLFSSL_ED25519_STREAMING_VERIFY) && !defined(WOLFSSL_SE050)

int wc_ed25519_verify_msg_init(const byte* sig, word32 sigLen, ed25519_key* key,
                               byte type, const byte* context, byte contextLen) {
    return ed25519_verify_msg_init_with_sha(sig, sigLen, key, &key->sha,
                                        type, context, contextLen);
}

int wc_ed25519_verify_msg_update(const byte* msgSegment, word32 msgSegmentLen,
                                        ed25519_key* key) {
    return ed25519_verify_msg_update_with_sha(msgSegment, msgSegmentLen,
                                          key, &key->sha);
}

int wc_ed25519_verify_msg_final(const byte* sig, word32 sigLen, int* res,
                                ed25519_key* key) {
    return ed25519_verify_msg_final_with_sha(sig, sigLen, res,
                                         key, &key->sha);
}

#endif /* WOLFSSL_ED25519_STREAMING_VERIFY && !WOLFSSL_SE050 */

/*
   sig     is array of bytes containing the signature
   sigLen  is the length of sig byte array
   msg     the array of bytes containing the message
   msgLen  length of msg array
   res     will be 1 on successful verify and 0 on unsuccessful
   key     Ed25519 public key
   return  0 and res of 1 on success
*/
int wc_ed25519_verify_msg_ex(const byte* sig, word32 sigLen, const byte* msg,
                              word32 msgLen, int* res, ed25519_key* key,
                              byte type, const byte* context, byte contextLen)
{
    int ret;
#ifdef WOLFSSL_SE050
    (void)type;
    (void)context;
    (void)contextLen;
    (void)ed25519Ctx;
    ret = se050_ed25519_verify_msg(sig, sigLen, msg, msgLen, key, res);
#else
#ifdef WOLFSSL_ED25519_PERSISTENT_SHA
    wc_Sha512 *sha;
#else
    wc_Sha512 sha[1];
#endif

    /* sanity check on arguments */
    if (sig == NULL || msg == NULL || res == NULL || key == NULL ||
                                         (context == NULL && contextLen != 0))
        return BAD_FUNC_ARG;

#ifdef WOLF_CRYPTO_CB
    if (key->devId != INVALID_DEVID) {
        ret = wc_CryptoCb_Ed25519Verify(sig, sigLen, msg, msgLen, res, key,
            type, context, contextLen);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return ret;
        /* fall-through when unavailable */
    }
#endif

#ifdef WOLFSSL_ED25519_PERSISTENT_SHA
    sha = &key->sha;
#else
    ret = ed25519_hash_init(key, sha);
    if (ret < 0) {
        return ret;
    }
#endif /* WOLFSSL_ED25519_PERSISTENT_SHA */

    ret = ed25519_verify_msg_init_with_sha(sig, sigLen, key, sha, type, context,
        contextLen);
    if (ret == 0)
        ret = ed25519_verify_msg_update_with_sha(msg, msgLen, key, sha);
    if (ret == 0)
        ret = ed25519_verify_msg_final_with_sha(sig, sigLen, res, key, sha);

#ifndef WOLFSSL_ED25519_PERSISTENT_SHA
    ed25519_hash_free(key, sha);
#endif
#endif /* WOLFSSL_SE050 */
    return ret;
}

/*
   sig     is array of bytes containing the signature
   sigLen  is the length of sig byte array
   msg     the array of bytes containing the message
   msgLen  length of msg array
   res     will be 1 on successful verify and 0 on unsuccessful
   key     Ed25519 public key
   return  0 and res of 1 on success
*/
int wc_ed25519_verify_msg(const byte* sig, word32 sigLen, const byte* msg,
                          word32 msgLen, int* res, ed25519_key* key)
{
    return wc_ed25519_verify_msg_ex(sig, sigLen, msg, msgLen, res, key,
                                    (byte)Ed25519, NULL, 0);
}

/*
   sig         is array of bytes containing the signature
   sigLen      is the length of sig byte array
   msg         the array of bytes containing the message
   msgLen      length of msg array
   res         will be 1 on successful verify and 0 on unsuccessful
   key         Ed25519 public key
   context     extra signing data
   contextLen  length of extra signing data
   return  0 and res of 1 on success
*/
int wc_ed25519ctx_verify_msg(const byte* sig, word32 sigLen, const byte* msg,
                             word32 msgLen, int* res, ed25519_key* key,
                             const byte* context, byte contextLen)
{
    return wc_ed25519_verify_msg_ex(sig, sigLen, msg, msgLen, res, key,
                                    Ed25519ctx, context, contextLen);
}

/*
   sig         is array of bytes containing the signature
   sigLen      is the length of sig byte array
   hash        the array of bytes containing the SHA-512 hash of the message
   hashLen     length of hash array
   res         will be 1 on successful verify and 0 on unsuccessful
   key         Ed25519 public key
   context     extra signing data
   contextLen  length of extra signing data
   return  0 and res of 1 on success
*/
int wc_ed25519ph_verify_hash(const byte* sig, word32 sigLen, const byte* hash,
                             word32 hashLen, int* res, ed25519_key* key,
                             const byte* context, byte contextLen)
{
    return wc_ed25519_verify_msg_ex(sig, sigLen, hash, hashLen, res, key,
                                    Ed25519ph, context, contextLen);
}

/*
   sig         is array of bytes containing the signature
   sigLen      is the length of sig byte array
   msg         the array of bytes containing the message
   msgLen      length of msg array
   res         will be 1 on successful verify and 0 on unsuccessful
   key         Ed25519 public key
   context     extra signing data
   contextLen  length of extra signing data
   return  0 and res of 1 on success
*/
int wc_ed25519ph_verify_msg(const byte* sig, word32 sigLen, const byte* msg,
                            word32 msgLen, int* res, ed25519_key* key,
                            const byte* context, byte contextLen)
{
    int  ret;
    byte hash[WC_SHA512_DIGEST_SIZE];

    ret = ed25519_hash(key, msg, msgLen, hash);
    if (ret != 0)
        return ret;

    return wc_ed25519_verify_msg_ex(sig, sigLen, hash, sizeof(hash), res, key,
                                    Ed25519ph, context, contextLen);
}
#endif /* HAVE_ED25519_VERIFY */

#ifndef WC_NO_CONSTRUCTORS
ed25519_key* wc_ed25519_new(void* heap, int devId, int *result_code)
{
    int ret;
    ed25519_key* key = (ed25519_key*)XMALLOC(sizeof(ed25519_key), heap,
                        DYNAMIC_TYPE_ED25519);
    if (key == NULL) {
        ret = MEMORY_E;
    }
    else {
        ret = wc_ed25519_init_ex(key, heap, devId);
        if (ret != 0) {
            XFREE(key, heap, DYNAMIC_TYPE_ED25519);
            key = NULL;
        }
    }

    if (result_code != NULL)
        *result_code = ret;

    return key;
}

int wc_ed25519_delete(ed25519_key* key, ed25519_key** key_p) {
    if (key == NULL)
        return BAD_FUNC_ARG;
    wc_ed25519_free(key);
    XFREE(key, key->heap, DYNAMIC_TYPE_ED25519);
    if (key_p != NULL)
        *key_p = NULL;
    return 0;
}
#endif /* !WC_NO_CONSTRUCTORS */

/* initialize information and memory for key */
int wc_ed25519_init_ex(ed25519_key* key, void* heap, int devId)
{
    if (key == NULL)
        return BAD_FUNC_ARG;

    /* for init, ensure the key is zeroed*/
    XMEMSET(key, 0, sizeof(ed25519_key));

#ifdef WOLF_CRYPTO_CB
    key->devId = devId;
#else
    (void)devId;
#endif
    key->heap = heap;

#ifndef FREESCALE_LTC_ECC
    fe_init();
#endif

#ifdef WOLFSSL_CHECK_MEM_ZERO
    wc_MemZero_Add("wc_ed25519_init_ex key->k", &key->k, sizeof(key->k));
#endif

#ifdef WOLFSSL_ED25519_PERSISTENT_SHA
    return ed25519_hash_init(key, &key->sha);
#else /* !WOLFSSL_ED25519_PERSISTENT_SHA */
    return 0;
#endif /* WOLFSSL_ED25519_PERSISTENT_SHA */
}

int wc_ed25519_init(ed25519_key* key)
{
    return wc_ed25519_init_ex(key, NULL, INVALID_DEVID);
}

/* clear memory of key */
void wc_ed25519_free(ed25519_key* key)
{
    if (key == NULL)
        return;

#ifdef WOLFSSL_ED25519_PERSISTENT_SHA
    ed25519_hash_free(key, &key->sha);
#endif

#ifdef WOLFSSL_SE050
    se050_ed25519_free_key(key);
#endif

    ForceZero(key, sizeof(ed25519_key));
#ifdef WOLFSSL_CHECK_MEM_ZERO
    wc_MemZero_Check(key, sizeof(ed25519_key));
#endif
}


#ifdef HAVE_ED25519_KEY_EXPORT

/*
    outLen should contain the size of out buffer when input. outLen is than set
    to the final output length.
    returns 0 on success
 */
int wc_ed25519_export_public(ed25519_key* key, byte* out, word32* outLen)
{
    /* sanity check on arguments */
    if (key == NULL || out == NULL || outLen == NULL)
        return BAD_FUNC_ARG;

    if (*outLen < ED25519_PUB_KEY_SIZE) {
        *outLen = ED25519_PUB_KEY_SIZE;
        return BUFFER_E;
    }

    *outLen = ED25519_PUB_KEY_SIZE;
    XMEMCPY(out, key->p, ED25519_PUB_KEY_SIZE);

    return 0;
}

#endif /* HAVE_ED25519_KEY_EXPORT */


#ifdef HAVE_ED25519_KEY_IMPORT
/*
    Imports a compressed/uncompressed public key.
    in       the byte array containing the public key
    inLen    the length of the byte array being passed in
    key      ed25519 key struct to put the public key in
    trusted  whether the public key is trusted to match private key if set
 */
int wc_ed25519_import_public_ex(const byte* in, word32 inLen, ed25519_key* key,
    int trusted)
{
    int ret = 0;

    /* sanity check on arguments */
    if (in == NULL || key == NULL)
        return BAD_FUNC_ARG;

    if (inLen < ED25519_PUB_KEY_SIZE)
        return BAD_FUNC_ARG;

    /* compressed prefix according to draft
       http://www.ietf.org/id/draft-koch-eddsa-for-openpgp-02.txt */
    if (in[0] == 0x40 && inLen == ED25519_PUB_KEY_SIZE + 1) {
        /* key is stored in compressed format so just copy in */
        XMEMCPY(key->p, (in + 1), ED25519_PUB_KEY_SIZE);
#ifdef FREESCALE_LTC_ECC
        /* recover X coordinate */
        ltc_pkha_ecc_point_t pubKey;
        pubKey.X = key->pointX;
        pubKey.Y = key->pointY;
        LTC_PKHA_Ed25519_PointDecompress(key->p, ED25519_PUB_KEY_SIZE, &pubKey);
#endif
    }
    /* importing uncompressed public key */
    else if (in[0] == 0x04 && inLen > 2*ED25519_PUB_KEY_SIZE) {
#ifdef FREESCALE_LTC_ECC
        /* reverse bytes for little endian byte order */
        for (int i = 0; i < ED25519_KEY_SIZE; i++)
        {
            key->pointX[i] = *(in + ED25519_KEY_SIZE - i);
            key->pointY[i] = *(in + 2*ED25519_KEY_SIZE - i);
        }
        XMEMCPY(key->p, key->pointY, ED25519_KEY_SIZE);
#else
        /* pass in (x,y) and store compressed key */
        ret = ge_compress_key(key->p, in+1,
                              in+1+ED25519_PUB_KEY_SIZE, ED25519_PUB_KEY_SIZE);
#endif /* FREESCALE_LTC_ECC */
    }
    /* if not specified compressed or uncompressed check key size
       if key size is equal to compressed key size copy in key */
    else if (inLen == ED25519_PUB_KEY_SIZE) {
        XMEMCPY(key->p, in, ED25519_PUB_KEY_SIZE);
#ifdef FREESCALE_LTC_ECC
        /* recover X coordinate */
        ltc_pkha_ecc_point_t pubKey;
        pubKey.X = key->pointX;
        pubKey.Y = key->pointY;
        LTC_PKHA_Ed25519_PointDecompress(key->p, ED25519_PUB_KEY_SIZE, &pubKey);
#endif
    }
    else {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        key->pubKeySet = 1;
        if (!trusted) {
            ret = wc_ed25519_check_key(key);
        }
    }
    if (ret != 0) {
        key->pubKeySet = 0;
    }

    /* bad public key format */
    return ret;
}

/*
    Imports a compressed/uncompressed public key.
    in    the byte array containing the public key
    inLen the length of the byte array being passed in
    key   ed25519 key struct to put the public key in
 */
int wc_ed25519_import_public(const byte* in, word32 inLen, ed25519_key* key)
{
    return wc_ed25519_import_public_ex(in, inLen, key, 0);
}

/*
    For importing a private key.
 */
int wc_ed25519_import_private_only(const byte* priv, word32 privSz,
                                                               ed25519_key* key)
{
    int ret = 0;

    /* sanity check on arguments */
    if (priv == NULL || key == NULL)
        return BAD_FUNC_ARG;

    /* key size check */
    if (privSz != ED25519_KEY_SIZE)
        return BAD_FUNC_ARG;

    XMEMCPY(key->k, priv, ED25519_KEY_SIZE);
    key->privKeySet = 1;

    if (key->pubKeySet) {
        /* Validate loaded public key */
        ret = wc_ed25519_check_key(key);
    }
    if (ret != 0) {
        key->privKeySet = 0;
        ForceZero(key->k, ED25519_KEY_SIZE);
    }

    return ret;
}


/* Import an ed25519 private and public keys from byte array(s).
 *
 * priv     [in]  Array holding private key from
 *                wc_ed25519_export_private_only(), or private+public keys from
 *                wc_ed25519_export_private().
 * privSz   [in]  Number of bytes of data in private key array.
 * pub      [in]  Array holding public key (or NULL).
 * pubSz    [in]  Number of bytes of data in public key array (or 0).
 * key      [in]  Ed25519 private/public key.
 * trusted  [in]  Indicates whether the public key data is trusted.
 *                When 0, checks public key matches private key.
 *                When 1, doesn't check public key matches private key.
 * returns BAD_FUNC_ARG when a required parameter is NULL or an invalid
 *         combination of keys/lengths is supplied, 0 otherwise.
 */
int wc_ed25519_import_private_key_ex(const byte* priv, word32 privSz,
    const byte* pub, word32 pubSz, ed25519_key* key, int trusted)
{
    int ret;

    /* sanity check on arguments */
    if (priv == NULL || key == NULL)
        return BAD_FUNC_ARG;

    /* key size check */
    if (privSz != ED25519_KEY_SIZE && privSz != ED25519_PRV_KEY_SIZE)
        return BAD_FUNC_ARG;

    if (pub == NULL) {
        if (pubSz != 0)
            return BAD_FUNC_ARG;
        if (privSz != ED25519_PRV_KEY_SIZE)
            return BAD_FUNC_ARG;
        pub = priv + ED25519_KEY_SIZE;
        pubSz = ED25519_PUB_KEY_SIZE;
    }
    else if (pubSz < ED25519_PUB_KEY_SIZE) {
        return BAD_FUNC_ARG;
    }

    XMEMCPY(key->k, priv, ED25519_KEY_SIZE);
    key->privKeySet = 1;

    /* import public key */
    ret = wc_ed25519_import_public_ex(pub, pubSz, key, trusted);
    if (ret != 0) {
        key->privKeySet = 0;
        ForceZero(key->k, ED25519_KEY_SIZE);
        return ret;
    }

    /* make the private key (priv + pub) */
    XMEMCPY(key->k + ED25519_KEY_SIZE, key->p, ED25519_PUB_KEY_SIZE);

    return ret;
}

/* Import an ed25519 private and public keys from byte array(s).
 *
 * priv    [in]  Array holding private key from wc_ed25519_export_private_only(),
 *               or private+public keys from wc_ed25519_export_private().
 * privSz  [in]  Number of bytes of data in private key array.
 * pub     [in]  Array holding public key (or NULL).
 * pubSz   [in]  Number of bytes of data in public key array (or 0).
 * key     [in]  Ed25519 private/public key.
 * returns BAD_FUNC_ARG when a required parameter is NULL or an invalid
 *         combination of keys/lengths is supplied, 0 otherwise.
 */
int wc_ed25519_import_private_key(const byte* priv, word32 privSz,
    const byte* pub, word32 pubSz, ed25519_key* key)
{
    return wc_ed25519_import_private_key_ex(priv, privSz, pub, pubSz, key, 0);
}
#endif /* HAVE_ED25519_KEY_IMPORT */


#ifdef HAVE_ED25519_KEY_EXPORT

/*
 export private key only (secret part so 32 bytes)
 outLen should contain the size of out buffer when input. outLen is than set
 to the final output length.
 returns 0 on success
 */
int wc_ed25519_export_private_only(ed25519_key* key, byte* out, word32* outLen)
{
    /* sanity checks on arguments */
    if (key == NULL || out == NULL || outLen == NULL)
        return BAD_FUNC_ARG;

    if (*outLen < ED25519_KEY_SIZE) {
        *outLen = ED25519_KEY_SIZE;
        return BUFFER_E;
    }

    *outLen = ED25519_KEY_SIZE;
    XMEMCPY(out, key->k, ED25519_KEY_SIZE);

    return 0;
}

/*
 export private key, including public part
 outLen should contain the size of out buffer when input. outLen is than set
 to the final output length.
 returns 0 on success
 */
int wc_ed25519_export_private(ed25519_key* key, byte* out, word32* outLen)
{
    /* sanity checks on arguments */
    if (key == NULL || out == NULL || outLen == NULL)
        return BAD_FUNC_ARG;

    if (*outLen < ED25519_PRV_KEY_SIZE) {
        *outLen = ED25519_PRV_KEY_SIZE;
        return BUFFER_E;
    }

    *outLen = ED25519_PRV_KEY_SIZE;
    XMEMCPY(out, key->k, ED25519_PRV_KEY_SIZE);

    return 0;
}

/* export full private key and public key
   return 0 on success
 */
int wc_ed25519_export_key(ed25519_key* key,
                          byte* priv, word32 *privSz,
                          byte* pub, word32 *pubSz)
{
    int ret;

    /* export 'full' private part */
    ret = wc_ed25519_export_private(key, priv, privSz);
    if (ret != 0)
        return ret;

    /* export public part */
    ret = wc_ed25519_export_public(key, pub, pubSz);

    return ret;
}

#endif /* HAVE_ED25519_KEY_EXPORT */

/* Check the public key is valid.
 *
 * When private key available, check the calculated public key matches.
 * When no private key, check Y is in range and an X is able to be calculated.
 *
 * @param [in] key  Ed25519 private/public key.
 * @return  0 otherwise.
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  PUBLIC_KEY_E when the public key is not set, doesn't match or is
 *          invalid.
 * @return  other -ve value on hash failure.
 */
int wc_ed25519_check_key(ed25519_key* key)
{
    int ret = 0;

    /* Validate parameter. */
    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }

    /* Check we have a public key to check. */
    if ((ret == 0) && (!key->pubKeySet)) {
        ret = PUBLIC_KEY_E;
    }

#ifdef HAVE_ED25519_MAKE_KEY
    /* If we have a private key just make the public key and compare. */
    if ((ret == 0) && (key->privKeySet)) {
        ALIGN16 unsigned char pubKey[ED25519_PUB_KEY_SIZE];

        ret = wc_ed25519_make_public(key, pubKey, sizeof(pubKey));
        if (ret == 0 && XMEMCMP(pubKey, key->p, ED25519_PUB_KEY_SIZE) != 0)
            ret = PUBLIC_KEY_E;
    }
#else
    (void)key;
#endif /* HAVE_ED25519_MAKE_KEY */

    /* No private key (or ability to make a public key), check Y is valid. */
    if ((ret == 0)
#ifdef HAVE_ED25519_MAKE_KEY
        && (!key->privKeySet)
#endif
        ) {
        /* Verify that Q is not identity element 0.
         * 0 has no representation for Ed25519. */

        /* Verify that xQ and yQ are integers in the interval [0, p - 1].
         * Only have yQ so check that ordinate. p = 2^255 - 19 */
        if ((key->p[ED25519_PUB_KEY_SIZE - 1] & 0x7f) == 0x7f) {
            int i;

            ret = PUBLIC_KEY_E;
            /* Check up to last byte. */
            for (i = ED25519_PUB_KEY_SIZE - 2; i > 0; i--) {
                if (key->p[i] != 0xff) {
                    ret = 0;
                    break;
                }
            }
            /* Bits are all one up to last byte - check less than -19. */
            if ((ret == WC_NO_ERR_TRACE(PUBLIC_KEY_E)) && (key->p[0] < 0xed)) {
                ret = 0;
            }
        }

        if (ret == 0) {
            /* Verify that Q is on the curve.
             * Uncompressing the public key will validate yQ. */
            ge_p3 A;

            if (ge_frombytes_negate_vartime(&A, key->p) != 0) {
                ret = PUBLIC_KEY_E;
            }
        }
    }

    return ret;
}

/* returns the private key size (secret only) in bytes */
int wc_ed25519_size(ed25519_key* key)
{
    if (key == NULL)
        return BAD_FUNC_ARG;

    return ED25519_KEY_SIZE;
}

/* returns the private key size (secret + public) in bytes */
int wc_ed25519_priv_size(ed25519_key* key)
{
    if (key == NULL)
        return BAD_FUNC_ARG;

    return ED25519_PRV_KEY_SIZE;
}

/* returns the compressed key size in bytes (public key) */
int wc_ed25519_pub_size(ed25519_key* key)
{
    if (key == NULL)
        return BAD_FUNC_ARG;

    return ED25519_PUB_KEY_SIZE;
}

/* returns the size of signature in bytes */
int wc_ed25519_sig_size(ed25519_key* key)
{
    if (key == NULL)
        return BAD_FUNC_ARG;

    return ED25519_SIG_SIZE;
}

#endif /* HAVE_ED25519 */
