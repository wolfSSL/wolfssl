/* wc_xmss.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#ifdef WOLFSSL_HAVE_XMSS
#include <wolfssl/wolfcrypt/wc_xmss.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif


/***************************
 * DIGEST init and free.
 ***************************/

/* Initialize the digest algorithm to use.
 *
 * @param [in, out] state  XMSS/MT state including digest and parameters.
 * @return  0 on success.
 * @return  NOT_COMPILED_IN when digest algorithm not supported.
 * @return  Other negative when digest algorithm initialization failed.
 */
static int wc_xmss_digest_init(XmssState* state)
{
    int ret;
    word8 hash = state->params->hash;

#ifdef WC_XMSS_SHA256
    if (hash == WC_HASH_TYPE_SHA256) {
        ret = wc_InitSha256(&state->digest.sha256);
    }
    else
#endif
#ifdef WC_XMSS_SHA512
    if (hash == WC_HASH_TYPE_SHA512) {
        ret = wc_InitSha512(&state->digest.sha512);
    }
    else
#endif
#ifdef WC_XMSS_SHAKE128
    if (hash == WC_HASH_TYPE_SHAKE128) {
        ret = wc_InitShake128(&state->digest.shake, NULL, INVALID_DEVID);
    }
    else
#endif
#ifdef WC_XMSS_SHAKE256
    if (hash == WC_HASH_TYPE_SHAKE256) {
        ret = wc_InitShake256(&state->digest.shake, NULL, INVALID_DEVID);
    }
    else
#endif
    {
        ret = NOT_COMPILED_IN;
    }

    return ret;
}
/* Free the digest algorithm.
 *
 * @param [in, out] state  XMSS/MT state including digest and parameters.
 */
static void wc_xmss_digest_free(XmssState* state)
{
    word8 hash = state->params->hash;

#ifdef WC_XMSS_SHA256
    if (hash == WC_HASH_TYPE_SHA256) {
        wc_Sha256Free(&state->digest.sha256);
    }
    else
#endif
#ifdef WC_XMSS_SHA512
    if (hash == WC_HASH_TYPE_SHA512) {
        wc_Sha512Free(&state->digest.sha512);
    }
    else
#endif
#ifdef WC_XMSS_SHAKE128
    if (hash == WC_HASH_TYPE_SHAKE128) {
        wc_Shake128_Free(&state->digest.shake);
    }
    else
#endif
#ifdef WC_XMSS_SHAKE256
    if (hash == WC_HASH_TYPE_SHAKE256) {
        wc_Shake256_Free(&state->digest.shake);
    }
    else
#endif
    {
        /* Do nothing. */
    }
}

/* Initialize the XMSS/MT state.
 *
 * @param [in, out] state   XMSS/MT state including digest and parameters.
 * @param [in]      params  Parameters for key.
 * @return  0 on success.
 * @return  NOT_COMPILED_IN when digest algorithm not supported.
 * @return  Other negative when digest algorithm initialization failed.
 */
static WC_INLINE int wc_xmss_state_init(XmssState* state,
    const XmssParams* params)
{
    state->params = params;
    state->ret = 0;
    return wc_xmss_digest_init(state);
}

/* Free the XMSS/MT state.
 *
 * @param [in, out] state  XMSS/MT state including digest and parameters.
 */
static WC_INLINE void wc_xmss_state_free(XmssState* state)
{
    wc_xmss_digest_free(state);
}


/***************************
 * XMSS PARAMS
 ***************************/

/* Map of XMSS/MT string name to OID.
 */
typedef struct wc_XmssString {
    /* Name of algorithm as a string. */
    const char* str;
    /* OID for algorithm. */
    word32 oid;
    /* XMSS parameters. */
    XmssParams params;
} wc_XmssString;

#ifndef WOLFSSL_WC_XMSS_SMALL

/* Size of BDS State encoded numbers - offset=1, next=3. */
#define XMSS_BDS_NUMS_SZ      4
/* Size of treehash encoding - nextIdx=3, completed|used=1. */
#define XMSS_TREEHASH_SZ      4

/* Calculate Secret key length.
 *
 * See wc_xmss_bds_state_save() and wc_xmss_bds_state_load().
 *
 * SK = idx || wots_sk || SK_PRF || root || SEED || BDSs || OTHER
 * BDSs = (2 * depth - 1) * BDS
 * BDS = stack || height || authPath || keep || nodes || retain ||
 *       offset || next || TREEHASHes
 * TREEHASHes = (Subtree height - BDS k param) * TREEHASH
 * TREEHASH = nextIdx || completed || used
 *
 * @param [in] n  Number of bytes to hash output.
 * @param [in] h  Height of full tree.
 * @param [in] d  Depth of trees (number of subtrees).
 * @param [in] s  Subtree height.
 * @param [in] i  Length of index encoding in bytes.
 * @param [in] k  BDS k parameter.
 * @return  Secret key length in bytes.
 */
#define XMSS_SK_LEN(n, h, d, s, i, k)                               \
    (((i) + 4 * (n)) +                                              \
     (2 * (d) - 1) * (((s) + 1) * (n) +                             \
                    (s) + 1 +                                       \
                    (s) * (n) +                                     \
                    ((s) >> 1) * (n) +                              \
                    ((s) - (k)) * XMSS_TREEHASH_SZ +                \
                    ((s) - (k)) * (n) +                             \
                    XMSS_RETAIN_LEN(k, n) +                         \
                    XMSS_BDS_NUMS_SZ) +                             \
     ((d) - 1) * (n) * ((n) * 2 + 3))

#else

/* Calculate Secret key length.
 *
 * SK = idx || wots_sk || SK_PRF || root || SEED
 *
 * @param [in] n  Number of bytes to hash output.
 * @param [in] h  Height of full tree. Unused.
 * @param [in] d  Depth of trees (number of subtrees). Unused.
 * @param [in] s  Subtree height. Unused.
 * @param [in] i  Length of index encoding in bytes.
 * @param [in] k  BDS k parameter. Unused.
 * @return  Secret key length.
 */
#define XMSS_SK_LEN(n, h, d, s, i, k)                               \
    ((i) + 4 * (n))

#endif

#ifndef WOLFSSL_XMSS_LARGE_SECRET_KEY
/* Choose the smaller BDS K parameter. */
#define XMSS_K(k, kl)   (k)
#else
/* Choose the larger BDS K parameter. */
#define XMSS_K(k, kl)   (kl)
#endif

/* Calculate all fixed parameter values and output an array declaration.
 *
 * @param [in] hash  Hash algorithm to use.
 * @param [in] n     Number of bytes to hash output.
 * @param [in] p     Number of bytes of padding.
 * @param [in] h     Height of full tree.
 * @param [in] d     Depth of trees (number of subtrees).
 * @param [in] i     Length of index encoding in bytes.
 * @param [in] k     BDS k parameter. 0 or >= 2 but (h/d - k) is even.
 * @param [in] kl    BDS k parameter when large signatures.
 * @return  XMSS/XMSS^MT parameters array declaration.
 */
#define XMSS_PARAMS(hash, n, p, h, d, i, k, kl)                             \
    { hash, n, p, (n) * 2 + 3, (n) * ((n) * 2 + 3), h, (h) / (d), (d), (i), \
      (i) + (n) + (d) * (((n) * 2 + 3) * (n)) + (h) * (n),                  \
      XMSS_SK_LEN(n, h, d, ((h) / (d)), i, XMSS_K(k, kl)), (n) * 2,         \
      XMSS_K(k, kl) }
    /* hash, d, pad_len, wots_len, wots_sig_len, h, sub_h, d, idx_len,
     * sig_len,
     * sk_len, pk_len,
     * bds_k */

#if WOLFSSL_XMSS_MIN_HEIGHT <= 20
/* List of known XMSS algorithm strings and their OIDs. */
static const wc_XmssString wc_xmss_alg[] = {
#ifdef WC_XMSS_SHA256
#if WOLFSSL_WC_XMSS_MIN_HASH_SIZE <= 256 && WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 256
#if WOLFSSL_XMSS_MIN_HEIGHT <= 10 && WOLFSSL_XMSS_MAX_HEIGHT >= 10
    { "XMSS-SHA2_10_256",     WC_XMSS_OID_SHA2_10_256    ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA256,   32, 32, 10, 1, 4, 0, 4), },
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 16 && WOLFSSL_XMSS_MAX_HEIGHT >= 16
    { "XMSS-SHA2_16_256",     WC_XMSS_OID_SHA2_16_256    ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA256,   32, 32, 16, 1, 4, 0, 0), },
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 20 && WOLFSSL_XMSS_MAX_HEIGHT >= 20
    { "XMSS-SHA2_20_256",     WC_XMSS_OID_SHA2_20_256    ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA256,   32, 32, 20, 1, 4, 0, 0), },
#endif
#endif /* HASH_SIZE 256 */
#endif /* WC_XMSS_SHA256 */
#ifdef WC_XMSS_SHA512
#if WOLFSSL_WC_XMSS_MIN_HASH_SIZE <= 512 && WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 512
#if WOLFSSL_XMSS_MIN_HEIGHT <= 10 && WOLFSSL_XMSS_MAX_HEIGHT >= 10
    { "XMSS-SHA2_10_512",     WC_XMSS_OID_SHA2_10_512    ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA512,   64, 64, 10, 1, 4, 0, 4), },
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 16 && WOLFSSL_XMSS_MAX_HEIGHT >= 16
    { "XMSS-SHA2_16_512",     WC_XMSS_OID_SHA2_16_512    ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA512,   64, 64, 16, 1, 4, 0, 0), },
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 20 && WOLFSSL_XMSS_MAX_HEIGHT >= 20
    { "XMSS-SHA2_20_512",     WC_XMSS_OID_SHA2_20_512    ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA512,   64, 64, 20, 1, 4, 0, 0), },
#endif
#endif /* HASH_SIZE 512 */
#endif /* WC_XMSS_SHA512 */

#ifdef WC_XMSS_SHAKE128
#if WOLFSSL_WC_XMSS_MIN_HASH_SIZE <= 256 && WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 256
#if WOLFSSL_XMSS_MIN_HEIGHT <= 10 && WOLFSSL_XMSS_MAX_HEIGHT >= 10
    { "XMSS-SHAKE_10_256",    WC_XMSS_OID_SHAKE_10_256   ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE128, 32, 32, 10, 1, 4, 0, 4), },
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 16 && WOLFSSL_XMSS_MAX_HEIGHT >= 16
    { "XMSS-SHAKE_16_256",    WC_XMSS_OID_SHAKE_16_256   ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE128, 32, 32, 16, 1, 4, 0, 0), },
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 20 && WOLFSSL_XMSS_MAX_HEIGHT >= 20
    { "XMSS-SHAKE_20_256",    WC_XMSS_OID_SHAKE_20_256   ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE128, 32, 32, 20, 1, 4, 0, 0), },
#endif
#endif /* HASH_SIZE 256 */
#endif /* WC_XMSS_SHAKE128 */

#ifdef WC_XMSS_SHAKE256
#if WOLFSSL_WC_XMSS_MIN_HASH_SIZE <= 512 && WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 512
#if WOLFSSL_XMSS_MIN_HEIGHT <= 10 && WOLFSSL_XMSS_MAX_HEIGHT >= 10
    { "XMSS-SHAKE_10_512",    WC_XMSS_OID_SHAKE_10_512   ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 64, 64, 10, 1, 4, 0, 4), },
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 16 && WOLFSSL_XMSS_MAX_HEIGHT >= 16
    { "XMSS-SHAKE_16_512",    WC_XMSS_OID_SHAKE_16_512   ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 64, 64, 16, 1, 4, 0, 0), },
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 20 && WOLFSSL_XMSS_MAX_HEIGHT >= 20
    { "XMSS-SHAKE_20_512",    WC_XMSS_OID_SHAKE_20_512   ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 64, 64, 20, 1, 4, 0, 0), },
#endif
#endif /* HASH_SIZE 512 */
#endif /* WC_XMSS_SHAKE256 */

#ifdef WC_XMSS_SHA256
#if WOLFSSL_WC_XMSS_MIN_HASH_SIZE <= 192 && WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 192
#if WOLFSSL_XMSS_MIN_HEIGHT <= 10 && WOLFSSL_XMSS_MAX_HEIGHT >= 10
    { "XMSS-SHA2_10_192",     WC_XMSS_OID_SHA2_10_192    ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA256,   24,  4, 10, 1, 4, 0, 4), },
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 16 && WOLFSSL_XMSS_MAX_HEIGHT >= 16
    { "XMSS-SHA2_16_192",     WC_XMSS_OID_SHA2_16_192    ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA256,   24,  4, 16, 1, 4, 0, 0), },
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 20 && WOLFSSL_XMSS_MAX_HEIGHT >= 20
    { "XMSS-SHA2_20_192",     WC_XMSS_OID_SHA2_20_192    ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA256,   24,  4, 20, 1, 4, 0, 0), },
#endif
#endif /* HASH_SIZE 192 */
#endif /* WC_XMSS_SHA256 */

#ifdef WC_XMSS_SHAKE256
#if WOLFSSL_WC_XMSS_MIN_HASH_SIZE <= 256 && WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 256
#if WOLFSSL_XMSS_MIN_HEIGHT <= 10 && WOLFSSL_XMSS_MAX_HEIGHT >= 10
    { "XMSS-SHAKE256_10_256", WC_XMSS_OID_SHAKE256_10_256,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 32, 32, 10, 1, 4, 0, 4), },
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 16 && WOLFSSL_XMSS_MAX_HEIGHT >= 16
    { "XMSS-SHAKE256_16_256", WC_XMSS_OID_SHAKE256_16_256,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 32, 32, 16, 1, 4, 0, 0), },
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 20 && WOLFSSL_XMSS_MAX_HEIGHT >= 20
    { "XMSS-SHAKE256_20_256", WC_XMSS_OID_SHAKE256_20_256,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 32, 32, 20, 1, 4, 0, 0), },
#endif
#endif /* HASH_SIZE 256 */
#endif /* WC_XMSS_SHAKE256 */

#ifdef WC_XMSS_SHAKE256
#if WOLFSSL_WC_XMSS_MIN_HASH_SIZE <= 192 && WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 192
#if WOLFSSL_XMSS_MIN_HEIGHT <= 10 && WOLFSSL_XMSS_MAX_HEIGHT >= 10
    { "XMSS-SHAKE256_10_192", WC_XMSS_OID_SHAKE256_10_192,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 24,  4, 10, 1, 4, 0, 4), },
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 16 && WOLFSSL_XMSS_MAX_HEIGHT >= 16
    { "XMSS-SHAKE256_16_192", WC_XMSS_OID_SHAKE256_16_192,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 24,  4, 16, 1, 4, 0, 0), },
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 20 && WOLFSSL_XMSS_MAX_HEIGHT >= 20
    { "XMSS-SHAKE256_20_192", WC_XMSS_OID_SHAKE256_20_192,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 24,  4, 20, 1, 4, 0, 0), },
#endif
#endif /* HASH_SIZE 192 */
#endif /* WC_XMSS_SHAKE256 */
};
/* Length of array of known XMSS algorithms. */
#define WC_XMSS_ALG_LEN     (sizeof(wc_xmss_alg) / sizeof(*wc_xmss_alg))
#endif

/* Convert XMSS algorithm string to an OID - object identifier.
 *
 * @param [out] oid     OID value corresponding to string.
 * @param [in]  s       String to convert.
 * @param [out] params  XMSS/MT parameters.
 * @return  0 on success.
 * @return  NOT_COMPILED_IN on failure.
 */
static int wc_xmss_str_to_params(const char *s, word32* oid,
    const XmssParams** params)
{
    int ret = WC_NO_ERR_TRACE(NOT_COMPILED_IN);
#if WOLFSSL_XMSS_MIN_HEIGHT <= 20
    unsigned int i;

    ret = WC_NO_ERR_TRACE(NOT_COMPILED_IN);
    for (i = 0; i < WC_XMSS_ALG_LEN; i++) {
         if (XSTRCMP(s, wc_xmss_alg[i].str) == 0) {
             *oid = wc_xmss_alg[i].oid;
             *params = &wc_xmss_alg[i].params;
             ret = 0;
             break;
         }
    }
#else
    (void)s;
    (void)oid;
    (void)params;
    ret = NOT_COMPILED_IN;
#endif

    return ret;
}

#if WOLFSSL_XMSS_MAX_HEIGHT >= 20
/* List of known XMSS^MT algorithm strings and their OIDs. */
static const wc_XmssString wc_xmssmt_alg[] = {
#ifdef WC_XMSS_SHA256
#if WOLFSSL_WC_XMSS_MIN_HASH_SIZE <= 256 && WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 256
#if WOLFSSL_XMSS_MIN_HEIGHT <= 20 && WOLFSSL_XMSS_MAX_HEIGHT >= 20
    { "XMSSMT-SHA2_20/2_256",      WC_XMSSMT_OID_SHA2_20_2_256     ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA256,   32, 32, 20,  2, 3, 2, 4), },
    { "XMSSMT-SHA2_20/4_256",      WC_XMSSMT_OID_SHA2_20_4_256     ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA256,   32, 32, 20,  4, 3, 0, 0), },
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 40 && WOLFSSL_XMSS_MAX_HEIGHT >= 40
    { "XMSSMT-SHA2_40/2_256",      WC_XMSSMT_OID_SHA2_40_2_256     ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA256,   32, 32, 40,  2, 5, 2, 4), },
    { "XMSSMT-SHA2_40/4_256",      WC_XMSSMT_OID_SHA2_40_4_256     ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA256,   32, 32, 40,  4, 5, 2, 4), },
    { "XMSSMT-SHA2_40/8_256",      WC_XMSSMT_OID_SHA2_40_8_256     ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA256,   32, 32, 40,  8, 5, 0, 0), },
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 60 && WOLFSSL_XMSS_MAX_HEIGHT >= 60
    { "XMSSMT-SHA2_60/3_256",      WC_XMSSMT_OID_SHA2_60_3_256     ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA256,   32, 32, 60,  3, 8, 2, 4), },
    { "XMSSMT-SHA2_60/6_256",      WC_XMSSMT_OID_SHA2_60_6_256     ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA256,   32, 32, 60,  6, 8, 2, 4), },
    { "XMSSMT-SHA2_60/12_256",     WC_XMSSMT_OID_SHA2_60_12_256    ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA256,   32, 32, 60, 12, 8, 0, 0), },
#endif
#endif /* HASH_SIZE 256 */
#endif /* WC_XMSS_SHA256 */
#ifdef WC_XMSS_SHA512
#if WOLFSSL_WC_XMSS_MIN_HASH_SIZE <= 512 && WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 512
#if WOLFSSL_XMSS_MIN_HEIGHT <= 20 && WOLFSSL_XMSS_MAX_HEIGHT >= 20
    { "XMSSMT-SHA2_20/2_512",      WC_XMSSMT_OID_SHA2_20_2_512     ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA512,   64, 64, 20,  2, 3, 2, 4), },
    { "XMSSMT-SHA2_20/4_512",      WC_XMSSMT_OID_SHA2_20_4_512     ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA512,   64, 64, 20,  4, 3, 0, 0), },
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 40 && WOLFSSL_XMSS_MAX_HEIGHT >= 40
    { "XMSSMT-SHA2_40/2_512",      WC_XMSSMT_OID_SHA2_40_2_512     ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA512,   64, 64, 40,  2, 5, 2, 4), },
    { "XMSSMT-SHA2_40/4_512",      WC_XMSSMT_OID_SHA2_40_4_512     ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA512,   64, 64, 40,  4, 5, 2, 4), },
    { "XMSSMT-SHA2_40/8_512",      WC_XMSSMT_OID_SHA2_40_8_512     ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA512,   64, 64, 40,  8, 5, 0, 0), },
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 60 && WOLFSSL_XMSS_MAX_HEIGHT >= 60
    { "XMSSMT-SHA2_60/3_512",      WC_XMSSMT_OID_SHA2_60_3_512     ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA512,   64, 64, 60,  3, 8, 2, 4), },
    { "XMSSMT-SHA2_60/6_512",      WC_XMSSMT_OID_SHA2_60_6_512     ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA512,   64, 64, 60,  6, 8, 2, 4), },
    { "XMSSMT-SHA2_60/12_512",     WC_XMSSMT_OID_SHA2_60_12_512    ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA512,   64, 64, 60, 12, 8, 0, 0), },
#endif
#endif /* HASH_SIZE 512 */
#endif /* WC_XMSS_SHA512 */

#ifdef WC_XMSS_SHAKE128
#if WOLFSSL_WC_XMSS_MIN_HASH_SIZE <= 256 && WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 256
#if WOLFSSL_XMSS_MIN_HEIGHT <= 20 && WOLFSSL_XMSS_MAX_HEIGHT >= 20
    { "XMSSMT-SHAKE_20/2_256",     WC_XMSSMT_OID_SHAKE_20_2_256    ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE128, 32, 32, 20,  2, 3, 2, 4), },
    { "XMSSMT-SHAKE_20/4_256",     WC_XMSSMT_OID_SHAKE_20_4_256    ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE128, 32, 32, 20,  4, 3, 0, 0), },
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 40 && WOLFSSL_XMSS_MAX_HEIGHT >= 40
    { "XMSSMT-SHAKE_40/2_256",     WC_XMSSMT_OID_SHAKE_40_2_256    ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE128, 32, 32, 40,  2, 5, 2, 4), },
    { "XMSSMT-SHAKE_40/4_256",     WC_XMSSMT_OID_SHAKE_40_4_256    ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE128, 32, 32, 40,  4, 5, 2, 4), },
    { "XMSSMT-SHAKE_40/8_256",     WC_XMSSMT_OID_SHAKE_40_8_256    ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE128, 32, 32, 40,  8, 5, 0, 0), },
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 60 && WOLFSSL_XMSS_MAX_HEIGHT >= 60
    { "XMSSMT-SHAKE_60/3_256",     WC_XMSSMT_OID_SHAKE_60_3_256    ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE128, 32, 32, 60,  3, 8, 2, 4), },
    { "XMSSMT-SHAKE_60/6_256",     WC_XMSSMT_OID_SHAKE_60_6_256    ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE128, 32, 32, 60,  6, 8, 2, 4), },
    { "XMSSMT-SHAKE_60/12_256",    WC_XMSSMT_OID_SHAKE_60_12_256   ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE128, 32, 32, 60, 12, 8, 0, 0), },
#endif
#endif /* HASH_SIZE 256 */
#endif /* WC_XMSS_SHAKE128 */

#ifdef WC_XMSS_SHAKE256
#if WOLFSSL_WC_XMSS_MIN_HASH_SIZE <= 512 && WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 512
#if WOLFSSL_XMSS_MIN_HEIGHT <= 20 && WOLFSSL_XMSS_MAX_HEIGHT >= 20
    { "XMSSMT-SHAKE_20/2_512",     WC_XMSSMT_OID_SHAKE_20_2_512    ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 64, 64, 20,  2, 3, 2, 4), },
    { "XMSSMT-SHAKE_20/4_512",     WC_XMSSMT_OID_SHAKE_20_4_512    ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 64, 64, 20,  4, 3, 0, 0), },
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 40 && WOLFSSL_XMSS_MAX_HEIGHT >= 40
    { "XMSSMT-SHAKE_40/2_512",     WC_XMSSMT_OID_SHAKE_40_2_512    ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 64, 64, 40,  2, 5, 2, 4), },
    { "XMSSMT-SHAKE_40/4_512",     WC_XMSSMT_OID_SHAKE_40_4_512    ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 64, 64, 40,  4, 5, 2, 4), },
    { "XMSSMT-SHAKE_40/8_512",     WC_XMSSMT_OID_SHAKE_40_8_512    ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 64, 64, 40,  8, 5, 0, 0), },
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 60 && WOLFSSL_XMSS_MAX_HEIGHT >= 60
    { "XMSSMT-SHAKE_60/3_512",     WC_XMSSMT_OID_SHAKE_60_3_512    ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 64, 64, 60,  3, 8, 2, 4), },
    { "XMSSMT-SHAKE_60/6_512",     WC_XMSSMT_OID_SHAKE_60_6_512    ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 64, 64, 60,  6, 8, 2, 4), },
    { "XMSSMT-SHAKE_60/12_512",    WC_XMSSMT_OID_SHAKE_60_12_512   ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 64, 64, 60, 12, 8, 0, 0), },
#endif
#endif /* HASH_SIZE 512 */
#endif /* WC_XMSS_SHAKE256 */

#ifdef WC_XMSS_SHA256
#if WOLFSSL_WC_XMSS_MIN_HASH_SIZE <= 192 && WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 192
#if WOLFSSL_XMSS_MIN_HEIGHT <= 20 && WOLFSSL_XMSS_MAX_HEIGHT >= 20
    { "XMSSMT-SHA2_20/2_192",      WC_XMSSMT_OID_SHA2_20_2_192     ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA256,   24,  4, 20,  2, 3, 2, 4), },
    { "XMSSMT-SHA2_20/4_192",      WC_XMSSMT_OID_SHA2_20_4_192     ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA256,   24,  4, 20,  4, 3, 0, 0), },
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 40 && WOLFSSL_XMSS_MAX_HEIGHT >= 40
    { "XMSSMT-SHA2_40/2_192",      WC_XMSSMT_OID_SHA2_40_2_192     ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA256,   24,  4, 40,  2, 5, 2, 4), },
    { "XMSSMT-SHA2_40/4_192",      WC_XMSSMT_OID_SHA2_40_4_192     ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA256,   24,  4, 40,  4, 5, 2, 4), },
    { "XMSSMT-SHA2_40/8_192",      WC_XMSSMT_OID_SHA2_40_8_192     ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA256,   24,  4, 40,  8, 5, 0, 0), },
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 60 && WOLFSSL_XMSS_MAX_HEIGHT >= 60
    { "XMSSMT-SHA2_60/3_192",      WC_XMSSMT_OID_SHA2_60_3_192     ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA256,   24,  4, 60,  3, 8, 2, 4), },
    { "XMSSMT-SHA2_60/6_192",      WC_XMSSMT_OID_SHA2_60_6_192     ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA256,   24,  4, 60,  6, 8, 2, 4), },
    { "XMSSMT-SHA2_60/12_192",     WC_XMSSMT_OID_SHA2_60_12_192    ,
      XMSS_PARAMS(WC_HASH_TYPE_SHA256,   24,  4, 60, 12, 8, 0, 0), },
#endif
#endif /* HASH_SIZE 192 */
#endif /* WC_XMSS_SHA256 */

#ifdef WC_XMSS_SHAKE256
#if WOLFSSL_WC_XMSS_MIN_HASH_SIZE <= 256 && WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 256
#if WOLFSSL_XMSS_MIN_HEIGHT <= 20 && WOLFSSL_XMSS_MAX_HEIGHT >= 20
    { "XMSSMT-SHAKE256_20/2_256",  WC_XMSSMT_OID_SHAKE256_20_2_256 ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 32, 32, 20,  2, 3, 2, 4), },
    { "XMSSMT-SHAKE256_20/4_256",  WC_XMSSMT_OID_SHAKE256_20_4_256 ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 32, 32, 20,  4, 3, 0, 0), },
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 40 && WOLFSSL_XMSS_MAX_HEIGHT >= 40
    { "XMSSMT-SHAKE256_40/2_256",  WC_XMSSMT_OID_SHAKE256_40_2_256 ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 32, 32, 40,  2, 5, 2, 4), },
    { "XMSSMT-SHAKE256_40/4_256",  WC_XMSSMT_OID_SHAKE256_40_4_256 ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 32, 32, 40,  4, 5, 2, 4), },
    { "XMSSMT-SHAKE256_40/8_256",  WC_XMSSMT_OID_SHAKE256_40_8_256 ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 32, 32, 40,  8, 5, 0, 0), },
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 60 && WOLFSSL_XMSS_MAX_HEIGHT >= 60
    { "XMSSMT-SHAKE256_60/3_256",  WC_XMSSMT_OID_SHAKE256_60_3_256 ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 32, 32, 60,  3, 8, 2, 4), },
    { "XMSSMT-SHAKE256_60/6_256",  WC_XMSSMT_OID_SHAKE256_60_6_256 ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 32, 32, 60,  6, 8, 2, 4), },
    { "XMSSMT-SHAKE256_60/12_256", WC_XMSSMT_OID_SHAKE256_60_12_256,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 32, 32, 60, 12, 8, 0, 0), },
#endif
#endif /* HASH_SIZE 256 */
#endif /* WC_XMSS_SHAKE256 */

#ifdef WC_XMSS_SHAKE256
#if WOLFSSL_WC_XMSS_MIN_HASH_SIZE <= 192 && WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 192
#if WOLFSSL_XMSS_MIN_HEIGHT <= 20 && WOLFSSL_XMSS_MAX_HEIGHT >= 20
    { "XMSSMT-SHAKE256_20/2_192",  WC_XMSSMT_OID_SHAKE256_20_2_192 ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 24,  4, 20,  2, 3, 2, 4), },
    { "XMSSMT-SHAKE256_20/4_192",  WC_XMSSMT_OID_SHAKE256_20_4_192 ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 24,  4, 20,  4, 3, 0, 0), },
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 40 && WOLFSSL_XMSS_MAX_HEIGHT >= 40
    { "XMSSMT-SHAKE256_40/2_192",  WC_XMSSMT_OID_SHAKE256_40_2_192 ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 24,  4, 40,  2, 5, 2, 4), },
    { "XMSSMT-SHAKE256_40/4_192",  WC_XMSSMT_OID_SHAKE256_40_4_192 ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 24,  4, 40,  4, 5, 2, 4), },
    { "XMSSMT-SHAKE256_40/8_192",  WC_XMSSMT_OID_SHAKE256_40_8_192 ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 24,  4, 40,  8, 5, 0, 0), },
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 60 && WOLFSSL_XMSS_MAX_HEIGHT >= 60
    { "XMSSMT-SHAKE256_60/3_192",  WC_XMSSMT_OID_SHAKE256_60_3_192 ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 24,  4, 60,  3, 8, 2, 4), },
    { "XMSSMT-SHAKE256_60/6_192",  WC_XMSSMT_OID_SHAKE256_60_6_192 ,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 24,  4, 60,  6, 8, 2, 4), },
    { "XMSSMT-SHAKE256_60/12_192", WC_XMSSMT_OID_SHAKE256_60_12_192,
      XMSS_PARAMS(WC_HASH_TYPE_SHAKE256, 24,  4, 60, 12, 8, 0, 0), },
#endif
#endif /* HASH_SIZE 192 */
#endif /* WC_XMSS_SHAKE256 */
};
/* Length of array of known XMSS^MT algorithms. */
#define WC_XMSSMT_ALG_LEN   (sizeof(wc_xmssmt_alg) / sizeof(*wc_xmssmt_alg))
#endif

/* Convert XMSS^MT algorithm string to an OID - object identifier.
 *
 * @param [out] oid     OID value corresponding to string.
 * @param [in]  s       String to convert.
 * @param [out] params  XMSS/MT parameters.
 * @return  0 on success.
 * @return  NOT_COMPILED_IN on failure.
 */
static int wc_xmssmt_str_to_params(const char *s, word32* oid,
    const XmssParams** params)
{
    int ret = WC_NO_ERR_TRACE(NOT_COMPILED_IN);
#if WOLFSSL_XMSS_MAX_HEIGHT >= 20
    unsigned int i;

    ret = WC_NO_ERR_TRACE(NOT_COMPILED_IN);
    for (i = 0; i < WC_XMSSMT_ALG_LEN; i++) {
         if (XSTRCMP(s, wc_xmssmt_alg[i].str) == 0) {
             *oid = wc_xmssmt_alg[i].oid;
             *params = &wc_xmssmt_alg[i].params;
             ret = 0;
             break;
         }
    }
#else
    (void)s;
    (void)oid;
    (void)params;
    ret = NOT_COMPILED_IN;
#endif

    return ret;
}

/***************************
 * OTHER Internal APIs
 ***************************/

#ifndef WOLFSSL_XMSS_VERIFY_ONLY
/* Allocates the XMSS secret key (sk) array.
 *
 * The XMSS/XMSS^MT secret key length is a function of the
 * parameters, and can't be allocated until the param string
 * has been set with SetParamStr.
 *
 * This is only called by MakeKey() and Reload().
 *
 * Note: the XMSS sk array is force zeroed after every use.
 *
 * @param [in] key  The XMSS key.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  BAD_FUNC_ARG when private key already allocated.
 * @return  MEMORY_E when allocating dynamic memory fails.
 */
static int wc_xmsskey_alloc_sk(XmssKey* key)
{
    int ret = 0;

    /* Validate parameter. */
    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    /* Ensure the private key doesn't exist. */
    else if (key->sk != NULL) {
        WOLFSSL_MSG("error: XMSS secret key already exists");
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* The XMSS/XMSS^MT secret key length is a function of the
         * parameters. Therefore can't allocate this until param
         * string has been set. */
        ret = wc_XmssKey_GetPrivLen(key, &key->sk_len);
    }
    if (ret == 0) {
        /* Allocate a buffer to hold secret key. */
        key->sk = (unsigned char *)XMALLOC(key->sk_len, NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (key->sk == NULL) {
            WOLFSSL_MSG("error: malloc XMSS key->sk failed");
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        /* Zeroize private key buffer. */
        ForceZero(key->sk, key->sk_len);
    }

    return ret;
}

/* Signs the message using the XMSS secret key, and
 * updates the secret key on NV storage.
 *
 * Both operations must succeed to be considered
 * successful.
 *
 * On success:  sets key state to WC_XMSS_STATE_OK.
 * On failure:  sets key state to WC_XMSS_STATE_BAD
 *
 * If no signatures are left, sets state to WC_XMSS_STATE_NOSIGS.
 *
 * @return  IO_FAILED_E when reading or writing private key failed.
 * @return  KEY_EXHAUSTED_E when no more keys in private key available.
 * @return  BAD_COND_E when generated signature length is invalid.
 */
static WC_INLINE int wc_xmsskey_signupdate(XmssKey* key, byte* sig,
    const byte* msg, int msgLen)
{
    int            ret = 0;
    enum wc_XmssRc cb_rc = WC_XMSS_RC_NONE;

    /* Set the key state to bad by default. State is presumed bad unless a
     * correct sign and update operation happen together. */
    key->state = WC_XMSS_STATE_BAD;

    /* Read the current secret key from NV storage.*/
    cb_rc = key->read_private_key(key->sk, key->sk_len, key->context);
    if (cb_rc != WC_XMSS_RC_READ_TO_MEMORY) {
        /* Read from NV storage failed. */
        WOLFSSL_MSG("error: XMSS read_private_key failed");
        ret = IO_FAILED_E;
    }

    if (ret == 0) {
    #ifdef WOLFSSL_SMALL_STACK
        XmssState* state;
    #else
        XmssState state[1];
    #endif

    #ifdef WOLFSSL_SMALL_STACK
        state = XMALLOC(sizeof(XmssState), NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (state == NULL) {
            ret = MEMORY_E;
        }
        if (ret == 0)
    #endif
        {
            /* Initialize state for use in signing. */
            ret = wc_xmss_state_init(state, key->params);
            if (ret == 0) {
                /* Read was good. Now sign and update the secret key in memory.
                 */
            #ifndef WOLFSSL_WC_XMSS_SMALL
                if (key->is_xmssmt) {
                    ret = wc_xmssmt_sign(state, msg, msgLen, key->sk, sig);
                }
                else {
                    ret = wc_xmss_sign(state, msg, msgLen, key->sk, sig);
                }
            #else
                ret = wc_xmssmt_sign(state, msg, msgLen, key->sk, sig);
            #endif
                if (ret == WC_NO_ERR_TRACE(KEY_EXHAUSTED_E)) {
                    /* Signature space exhausted. */
                    key->state = WC_XMSS_STATE_NOSIGS;
                    WOLFSSL_MSG("error: no XMSS signatures remaining");
                }
                else if (ret != 0) {
                    /* Something failed or inconsistent in signature. Erase the
                     * signature just to be safe. */
                    ForceZero(sig, key->params->sig_len);
                    WOLFSSL_MSG("error: XMSS sign failed");
                }
                /* Free state after use. */
                wc_xmss_state_free(state);
            }
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(state, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
        }
    }

    if (ret == 0) {
        /* The signature succeeded. key->sk is now updated and must be
         * committed to NV storage. */
        cb_rc = key->write_private_key(key->sk, key->sk_len, key->context);
        if (cb_rc != WC_XMSS_RC_SAVED_TO_NV_MEMORY) {
            /* Write to NV storage failed. Erase the signature from
             * memory. */
            ForceZero(sig, key->params->sig_len);
            WOLFSSL_MSG("error: XMSS write_private_key failed");
            ret = IO_FAILED_E;
        }
    }
    if (ret == 0) {
        /* key->sk was successfully committed to NV storage. Set the
         * key state to OK, and set the sigLen. */
        key->state = WC_XMSS_STATE_OK;
    }

    /* Force zero the secret key from memory always. */
    ForceZero(key->sk, key->sk_len);

    return ret;
}
#endif /* !WOLFSSL_XMSS_VERIFY_ONLY */

/***************************
 * PUBLIC API
 ***************************/

/* Init an XMSS key.
 *
 * Call this before setting the parms of an XMSS key.
 *
 * @param [in] key    The XMSS key to init.
 * @param [in] heap   Unused.
 * @param [in] devId  Unused.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 */
int wc_XmssKey_Init(XmssKey* key, void* heap, int devId)
{
    int ret = 0;

    (void) heap;
    (void) devId;

    /* Validate parameters. */
    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Zeroize key and set state to initialized. */
        ForceZero(key, sizeof(XmssKey));
        key->state = WC_XMSS_STATE_INITED;
    }

    return ret;
}

/* Set the XMSS key parameter string.
 *
 * The input string must be one of the supported parm set names in
 * the "Name" section from the table in wolfssl/wolfcrypt/xmss.h,
 * e.g. "XMSS-SHA2_10_256" or "XMSSMT-SHA2_20/4_256".
 *
 * @param [in] key  The XMSS key to set.
 * @param [in] str  The XMSS/XMSS^MT parameter string.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  BAD_FUNC_ARG when string not recognized.
 * @return  BAD_STATE_E when wrong state for operation.
 * @return  NOT_COMPILED_IN when string not supported.
 */
int wc_XmssKey_SetParamStr(XmssKey* key, const char* str)
{
    int      ret = 0;
    word32   oid = 0;
    int      is_xmssmt = 0;

    /* Validate parameters. */
    if ((key == NULL) || (str == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    /* Validate state. */
    if ((ret == 0) && (key->state != WC_XMSS_STATE_INITED)) {
        WOLFSSL_MSG("error: XMSS key needs init");
        ret = BAD_STATE_E;
    }

    if (ret == 0) {
        /* Check which type of algorithm the string is for. */
        is_xmssmt = (XMEMCMP(str, "XMSS-", 5) != 0);

        /* Convert XMSS param string to OID. */
        if (is_xmssmt) {
            ret = wc_xmssmt_str_to_params(str, &oid, &key->params);
        }
        else {
            ret = wc_xmss_str_to_params(str, &oid, &key->params);
        }
        if (ret != 0) {
            WOLFSSL_MSG("error: xmssmt_str_to_params failed");
            ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0) {
        /* Set key info. */
        key->oid = oid;
        key->is_xmssmt = is_xmssmt;
        key->state = WC_XMSS_STATE_PARMSET;
    }

    return ret;
}

/* Force zeros and frees the XMSS key from memory.
 *
 * This does not touch the private key saved to non-volatile storage.
 *
 * This is the only function that frees the key->sk array.
 *
 * @param [in] key  XMSS key.
 */
void wc_XmssKey_Free(XmssKey* key)
{
    /* Validate parameter. */
    if (key != NULL) {
    #ifndef WOLFSSL_XMSS_VERIFY_ONLY
        if (key->sk != NULL) {
            /* Zeroize private key. */
            ForceZero(key->sk, key->sk_len);
            XFREE(key->sk, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            key->sk = NULL;
            key->sk_len = 0;
        }
    #endif /* !WOLFSSL_XMSS_VERIFY_ONLY */

        /* Ensure all data is zeroized. */
        ForceZero(key, sizeof(XmssKey));

        /* Set the state to freed. */
        key->state = WC_XMSS_STATE_FREED;
    }
}

#ifndef WOLFSSL_XMSS_VERIFY_ONLY
/* Sets the XMSS write private key callback.
 *
 * The callback must be able to write/update the private key to
 * non-volatile storage.
 *
 * @param [in] key       The XMSS key.
 * @param [in] write_cb  The write private key callback.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  BAD_STATE_E when wrong state for operation.
 */
int wc_XmssKey_SetWriteCb(XmssKey* key, wc_xmss_write_private_key_cb write_cb)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (write_cb == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Changing the write callback of an already working key is forbidden. */
    else if (key->state == WC_XMSS_STATE_OK) {
        WOLFSSL_MSG("error: wc_XmssKey_SetWriteCb: key in use");
        ret = BAD_STATE_E;
    }
    else {
        /* Set write callback for storing private key. */
        key->write_private_key = write_cb;
    }

    return ret;
}

/* Sets the XMSS read private key callback.
 *
 * The callback must be able to read the private key from
 * non-volatile storage.
 *
 * @param [in] key      The XMSS key.
 * @param [in] read_cb  The read private key callback.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  BAD_STATE_E when wrong state for operation.
 */
int wc_XmssKey_SetReadCb(XmssKey* key, wc_xmss_read_private_key_cb read_cb)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (read_cb == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Changing the read callback of an already working key is forbidden. */
    else if (key->state == WC_XMSS_STATE_OK) {
        WOLFSSL_MSG("error: wc_XmssKey_SetReadCb: key in use");
        ret = BAD_STATE_E;
    }
    else {
        /* Set write callback for getting private key. */
        key->read_private_key = read_cb;
    }

    return ret;
}

/* Sets the XMSS context to be used by write and read callbacks.
 *
 * E.g. this could be a filename if the callbacks write/read to file.
 *
 * @param [in] key      The XMSS key.
 * @param [in] context  The context pointer.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  BAD_STATE_E when wrong state for operation.
 */
int wc_XmssKey_SetContext(XmssKey* key, void* context)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (context == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Setting context of an already working key is forbidden. */
    else if (key->state == WC_XMSS_STATE_OK) {
        WOLFSSL_MSG("error: wc_XmssKey_SetContext: key in use");
        ret = BAD_STATE_E;
    }
    else {
        /* Set read/write callback context for accessing the private key. */
        key->context = context;
    }

    return ret;
}

/* Make the XMSS/XMSS^MT private/public key pair. The key must have its
 * parameters set before calling this.
 *
 * Write/read callbacks, and context data, must be set prior.
 * Key must have parameters set.
 *
 * This function and Reload() are the only functions that allocate
 * key->sk array. wc_XmssKey_FreeKey is the only function that
 * deallocates key->sk.
 *
 * @param [in] key  The XMSS key to make.
 * @param [in] rng  Initialized WC_RNG pointer.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  BAD_FUNC_ARG when a write private key is not set.
 * @return  BAD_FUNC_ARG when a read/write private key context is not set.
 * @return  BAD_FUNC_ARG when private key already allocated.
 * @return  MEMORY_E when allocating dynamic memory fails.
 * @return  BAD_STATE_E when wrong state for operation.
 * @return  IO_FAILED_E when writing private key failed.
 * @return  Other negative when random number generation failed.
 */
int wc_XmssKey_MakeKey(XmssKey* key, WC_RNG* rng)
{
    int            ret = 0;
    enum wc_XmssRc cb_rc = WC_XMSS_RC_NONE;
#ifdef WOLFSSL_SMALL_STACK
    unsigned char* seed = NULL;
#else
    unsigned char  seed[3 * WC_XMSS_MAX_N];
#endif

    /* Validate parameters */
    if ((key == NULL) || (rng == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Validate state. */
    if ((ret == 0) && (key->state != WC_XMSS_STATE_PARMSET)) {
        WOLFSSL_MSG("error: XmssKey not ready for generation");
        ret = BAD_STATE_E;
    }
    /* Ensure write callback available. */
    if ((ret == 0) && (key->write_private_key == NULL)) {
        WOLFSSL_MSG("error: XmssKey write callback is not set");
        ret = BAD_FUNC_ARG;
    }
    /* Ensure read/write callback context available. */
    if ((ret == 0) && (key->context == NULL)) {
        WOLFSSL_MSG("error: XmssKey context is not set");
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Allocate sk array. */
        ret = wc_xmsskey_alloc_sk(key);
    }
#ifdef WOLFSSL_SMALL_STACK
    if (ret == 0) {
        seed = (unsigned char*)XMALLOC(3 * key->params->n, NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (seed == NULL) {
            ret = MEMORY_E;
        }
    }
#endif

    if (ret == 0) {
        /* Generate three random seeds. */
        ret = wc_RNG_GenerateBlock(rng, seed, 3 * key->params->n);
    }

    if (ret == 0) {
    #ifdef WOLFSSL_SMALL_STACK
        XmssState* state;
    #else
        XmssState state[1];
    #endif

    #ifdef WOLFSSL_SMALL_STACK
        state = XMALLOC(sizeof(XmssState), NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (state == NULL) {
            ret = MEMORY_E;
        }
        if (ret == 0)
    #endif
        {
            /* Initialize state for use in key generation. */
            ret = wc_xmss_state_init(state, key->params);
            if (ret == 0) {
                /* Finally make the private/public key pair. Immediately write
                 * it to NV storage and then clear from memory. */
            #ifndef WOLFSSL_WC_XMSS_SMALL
                if (key->is_xmssmt) {
                    ret = wc_xmssmt_keygen(state, seed, key->sk, key->pk);
                }
                else {
                    ret = wc_xmss_keygen(state, seed, key->sk, key->pk);
                }
            #else
                ret = wc_xmssmt_keygen(state, seed, key->sk, key->pk);
            #endif
                if (ret != 0) {
                    WOLFSSL_MSG("error: XMSS keygen failed");
                    key->state = WC_XMSS_STATE_BAD;
                }
                /* Free state after use. */
                wc_xmss_state_free(state);
            }
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(state, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
        }
    }

    if (ret == 0) {
        /* Write out private key. */
        cb_rc = key->write_private_key(key->sk, key->sk_len, key->context);
        /* Zeroize private key data whether it was saved or not. */
        ForceZero(key->sk, key->sk_len);
        /* Check writing succeeded. */
        if (cb_rc != WC_XMSS_RC_SAVED_TO_NV_MEMORY) {
            WOLFSSL_MSG("error: XMSS write to NV storage failed");
            key->state = WC_XMSS_STATE_BAD;
            ret = IO_FAILED_E;
        }
    }

    if (ret == 0) {
        key->state = WC_XMSS_STATE_OK;
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(seed, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return ret;
}

/* This function allocates the secret key buffer, and does a
 * quick sanity check to verify the secret key is readable
 * from NV storage, and then force zeros the key from memory.
 *
 * On success it sets the key state to OK.
 *
 * Use this function to resume signing with an already existing
 * XMSS key pair.
 *
 * Write/read callbacks, and context data, must be set prior.
 * Key must have parameters set.
 *
 * This function and MakeKey are the only functions that allocate
 * key->sk array. wc_XmssKey_FreeKey is the only function that
 * deallocates key->sk.
 *
 * @params [in] key  XMSS key to load.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  BAD_FUNC_ARG when a read or write function is not set.
 * @return  BAD_FUNC_ARG when a read/write function context is not set.
 * @return  BAD_FUNC_ARG when private key already allocated.
 * @return  MEMORY_E when allocating dynamic memory fails.
 * @return  BAD_STATE_E when wrong state for operation.
 * @return  IO_FAILED_E when reading private key failed.
 */
int wc_XmssKey_Reload(XmssKey* key)
{
    int            ret = 0;
    enum wc_XmssRc cb_rc = WC_XMSS_RC_NONE;

    /* Validate parameter. */
    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    /* Validate state. */
    if ((ret == 0) && (key->state != WC_XMSS_STATE_PARMSET)) {
        WOLFSSL_MSG("error: XmssKey not ready for reload");
        ret = BAD_STATE_E;
    }
    /* Ensure read and write callbacks are available. */
    if ((ret == 0) && ((key->write_private_key == NULL) ||
            (key->read_private_key == NULL))) {
        WOLFSSL_MSG("error: XmssKey write/read callbacks are not set");
        ret = BAD_FUNC_ARG;
    }
    /* Ensure read and write callback context is available. */
    if ((ret == 0) && (key->context == NULL)) {
        WOLFSSL_MSG("error: XmssKey context is not set");
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Allocate sk array. */
        ret = wc_xmsskey_alloc_sk(key);
    }

    if (ret == 0) {
        /* Read the current secret key from NV storage. Force clear it
         * immediately. This is just to sanity check the secret key
         * is readable from permanent storage. */
        cb_rc = key->read_private_key(key->sk, key->sk_len, key->context);
        ForceZero(key->sk, key->sk_len);
        /* Check reading succeeded. */
        if (cb_rc != WC_XMSS_RC_READ_TO_MEMORY) {
            WOLFSSL_MSG("error: XMSS read from NV storage failed");
            key->state = WC_XMSS_STATE_BAD;
            ret = IO_FAILED_E;
        }
    }
    if (ret == 0) {
        key->state = WC_XMSS_STATE_OK;
    }

    return ret;
}

/* Gets the XMSS/XMSS^MT private key length.
 *
 * Parameters must be set before calling this, as the key size (sk_len)
 * is a function of the parameters.
 *
 * Note: the XMSS/XMSS^MT private key format is implementation specific,
 * and not standardized. Interoperability of XMSS private keys should
 * not be expected.
 *
 * @param [in]  key  XMSS key.
 * @param [out] len  Length of the private key in bytes.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  BAD_STATE_E when wrong state for operation.
 * */
int wc_XmssKey_GetPrivLen(const XmssKey* key, word32* len)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (len == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Validate state. */
    if ((ret == 0) && ((key->state != WC_XMSS_STATE_OK) &&
            (key->state != WC_XMSS_STATE_PARMSET))) {
        /* params->sk_len not set yet. */
        ret = BAD_STATE_E;
    }

    if (ret == 0) {
        /* Calculate private key length: OID + private key bytes. */
        *len = XMSS_OID_LEN + (word32)key->params->sk_len;
    }

    return ret;
}

/* Sign the message using the XMSS secret key.
 *
 * @param [in]      key     XMSS key to use to sign.
 * @param [in]      sig     Buffer to write signature into.
 * @param [in, out] sigLen  On in, size of buffer.
 *                          On out, the length of the signature in bytes.
 * @param [in]      msg     Message to sign.
 * @param [in]      msgLen  Length of the message in bytes.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  BAD_FUNC_ARG when a write private key is not set.
 * @return  BAD_FUNC_ARG when a read/write private key context is not set.
 * @return  BAD_STATE_E when wrong state for operation.
 * @return  BUFFER_E when sigLen is too small.
 * @return  IO_FAILED_E when reading or writing private key failed.
 * @return  KEY_EXHAUSTED_E when no more keys in private key available.
 * @return  BAD_COND_E when generated signature length is invalid.
 */
int wc_XmssKey_Sign(XmssKey* key, byte* sig, word32* sigLen, const byte* msg,
    int msgLen)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (sig == NULL) || (sigLen == NULL) || (msg == NULL) ||
            (msgLen <= 0)) {
        ret = BAD_FUNC_ARG;
    }
    /* Validate state. */
    if ((ret == 0) && (key->state == WC_XMSS_STATE_NOSIGS)) {
        WOLFSSL_MSG("error: XMSS signatures exhausted");
        ret = BAD_STATE_E;
    }
    if ((ret == 0) && (key->state != WC_XMSS_STATE_OK)) {
       /* The key had an error the last time it was used, and we
        * can't guarantee its state. */
        WOLFSSL_MSG("error: can't sign, XMSS key not in good state");
        ret = BAD_STATE_E;
    }
    /* Check signature buffer size. */
    if ((ret == 0) && (*sigLen < key->params->sig_len)) {
        /* Signature buffer too small. */
        WOLFSSL_MSG("error: XMSS sig buffer too small");
        ret = BUFFER_E;
    }
    /* Check read and write callbacks available. */
    if ((ret == 0) && ((key->write_private_key == NULL) ||
            (key->read_private_key == NULL))) {
        WOLFSSL_MSG("error: XmssKey write/read callbacks are not set");
        ret = BAD_FUNC_ARG;
    }
    /* Check read/write callback context available. */
    if ((ret == 0) && (key->context == NULL)) {
        WOLFSSL_MSG("error: XmssKey context is not set");
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        *sigLen = key->params->sig_len;
        /* Finally, sign and update the secret key. */
        ret = wc_xmsskey_signupdate(key, sig, msg, msgLen);
    }

    return ret;
}

/* Check if more signatures are possible with key.
 *
 * @param [in] key  XMSS key to check.
 * @return  1 when signatures possible.
 * @return  0 when key exhausted.
 */
int  wc_XmssKey_SigsLeft(XmssKey* key)
{
    int ret;

    /* Validate parameter. */
    if (key == NULL) {
        ret = 0;
    }
    /* Validate state. */
    else if (key->state == WC_XMSS_STATE_NOSIGS) {
        WOLFSSL_MSG("error: XMSS signatures exhausted");
        ret = 0;
    }
    else if (key->state != WC_XMSS_STATE_OK) {
        WOLFSSL_MSG("error: can't sign, XMSS key not in good state");
        ret = 0;
    }
    /* Read the current secret key from NV storage.*/
    else if (key->read_private_key(key->sk, key->sk_len, key->context) !=
             WC_XMSS_RC_READ_TO_MEMORY) {
        WOLFSSL_MSG("error: XMSS read_private_key failed");
        ret = 0;
    }
    else {
        /* Ask implementation to check index in private key. */
        ret = wc_xmss_sigsleft(key->params, key->sk);
    }

    return ret;
}
#endif /* !WOLFSSL_XMSS_VERIFY_ONLY*/

/* Get the XMSS/XMSS^MT public key length.
 *
 * The public key is static in size and does not depend on parameters,
 * other than the choice of SHA256 as hashing function.
 *
 * @param [in]  key  XMSS key.
 * @param [out] len  Length of the public key.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  NOT_COMPILED_IN when a hash algorithm not supported.
 */
int wc_XmssKey_GetPubLen(const XmssKey* key, word32* len)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (len == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        *len = XMSS_OID_LEN + key->params->pk_len;
    }

    return ret;
}

/* Export public key and parameters from one XmssKey to another.
 *
 * Use this to prepare a signature verification XmssKey that is pub only.
 *
 * @param [out] keyDst  Destination key for copy.
 * @param [in]  keySrc  Source key for copy.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a key is NULL.
 * @return  Other negative when digest algorithm initialization failed.
 */
int wc_XmssKey_ExportPub(XmssKey* keyDst, const XmssKey* keySrc)
{
    int ret = 0;

    /* Validate parameters. */
    if ((keyDst == NULL) || (keySrc == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Zeroize the new key. */
        ForceZero(keyDst, sizeof(XmssKey));

        /* Copy over the public key. */
        XMEMCPY(keyDst->pk, keySrc->pk, sizeof(keySrc->pk));

        /* Copy over the key info. */
        keyDst->oid = keySrc->oid;
        keyDst->is_xmssmt = keySrc->is_xmssmt;
        keyDst->params = keySrc->params;
    }
    if (ret == 0) {
        /* Mark keyDst as verify only, to prevent misuse. */
        keyDst->state = WC_XMSS_STATE_VERIFYONLY;
    }

    return 0;
}

/* Exports the raw XMSS public key buffer from key to out buffer.
 *
 * The out buffer should be large enough to hold the public key, and
 * outLen should indicate the size of the buffer.
 *
 * @param [in]       key     XMSS key.
 * @param [out]      out     Array holding public key.
 * @param [in, out]  outLen  On in, size of buffer.
 *                           On out, the length of the public key.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  BUFFER_E if array is too small.
 */
int wc_XmssKey_ExportPubRaw(const XmssKey* key, byte* out, word32* outLen)
{
    int    ret = 0;
    word32 pubLen = 0;

    /* Validate parameters. */
    if ((key == NULL) || (out == NULL) || (outLen == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    /* Get the public key length. */
    if (ret == 0) {
        ret = wc_XmssKey_GetPubLen(key, &pubLen);
    }
    /* Check the output buffer is large enough. */
    if ((ret == 0) && (*outLen < pubLen)) {
        ret = BUFFER_E;
    }

    if (ret == 0) {
        int i = 0;
        /* First copy the oid into buffer. */
        for (; i < XMSS_OID_LEN; i++) {
            out[XMSS_OID_LEN - i - 1] = (key->oid >> (8 * i)) & 0xFF;
        }
        /* Copy the public key data into buffer after oid. */
        XMEMCPY(out + XMSS_OID_LEN, key->pk, pubLen - XMSS_OID_LEN);
        /* Return actual public key length. */
        *outLen = pubLen;
    }

    return ret;
}

/* Imports a raw public key buffer from in array to XmssKey key.
 *
 * The XMSS parameters must be set first with wc_XmssKey_SetParamStr,
 * and inLen must match the length returned by wc_XmssKey_GetPubLen.
 *
 * @param [in, out] key     XMSS key.
 * @param [in]      in      Array holding public key.
 * @param [in]       inLen  Length of array in bytes.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  BUFFER_E if array is incorrect size.
 * @return  BAD_STATE_E when wrong state for operation.
 * */
int wc_XmssKey_ImportPubRaw(XmssKey* key, const byte* in, word32 inLen)
{
    int    ret = 0;
    word32 pubLen = 0;

    /* Validate parameters. */
    if ((key == NULL) || (in == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Validate state. */
    if ((ret == 0) && (key->state != WC_XMSS_STATE_PARMSET)) {
        /* XMSS key not ready for import. Param str must be set first. */
        WOLFSSL_MSG("error: XMSS key not ready for import");
        ret = BAD_STATE_E;
    }

    /* Get the public key length. */
    if (ret == 0) {
        ret = wc_XmssKey_GetPubLen(key, &pubLen);
    }
    /* Check the input buffer is the right size. */
    if ((ret == 0) && (inLen != pubLen)) {
        /* Something inconsistent. Parameters weren't set, or input
         * pub key is wrong.*/
        ret = BUFFER_E;
    }

    if (ret == 0) {
        /* Copy the public key data into key. */
        XMEMCPY(key->pk, in + XMSS_OID_LEN, pubLen - XMSS_OID_LEN);

        /* Update state to verify-only as we don't have a private key. */
        key->state = WC_XMSS_STATE_VERIFYONLY;
    }

    return ret;
}

/* Gets the XMSS/XMSS^MT signature length.
 *
 * Parameters must be set before calling this, as the signature size
 * is a function of the parameters.
 *
 * Note: call this before wc_XmssKey_Sign or Verify so you know the
 * length of the required signature buffer.
 *
 * @param [in]  key  XMSS key to use to sign.
 * @param [out] len  The length of the signature in bytes.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  BAD_STATE_E when wrong state for operation.
 * */
int wc_XmssKey_GetSigLen(const XmssKey* key, word32* len)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (len == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Validate state. */
    if ((ret == 0) && (key->state != WC_XMSS_STATE_OK) &&
            (key->state != WC_XMSS_STATE_PARMSET)) {
        ret = BAD_STATE_E;
    }

    if (ret == 0) {
        /* Return the calculated signature length. */
        *len = key->params->sig_len;
    }

    return ret;
}

/* Verify the signature using the XMSS public key.
 *
 * Requires that XMSS parameters have been set with
 * wc_XmssKey_SetParamStr, and that a public key is available
 * from importing or MakeKey().
 *
 * Call wc_XmssKey_GetSigLen() before this function to determine
 * length of the signature buffer.
 *
 * @param [in] key     XMSS key to use to verify.
 * @param [in] sig     Signature to verify.
 * @param [in] sigLen  Size of signature in bytes.
 * @param [in] m       Message to verify.
 * @param [in] mLen    Length of the message in bytes.
 *
 * @return  0 on success.
 * @return  SIG_VERIFY_E when signature did not verify message.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  BAD_STATE_E when wrong state for operation.
 * @return  BUFFER_E when sigLen is too small.
 */
int wc_XmssKey_Verify(XmssKey* key, const byte* sig, word32 sigLen,
    const byte* m, int mLen)
{
    int            ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (sig == NULL) || (m == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Validate state. */
    if ((ret == 0) && (key->state != WC_XMSS_STATE_OK) &&
            (key->state != WC_XMSS_STATE_VERIFYONLY)) {
        /* XMSS key not ready for verification. Param str must be
         * set first, and Reload() called. */
        WOLFSSL_MSG("error: XMSS key not ready for verification");
        ret = BAD_STATE_E;
    }
    /* Check the signature is the big enough. */
    if ((ret == 0) && (sigLen < key->params->sig_len)) {
        /* Signature buffer too small. */
        ret = BUFFER_E;
    }

    if (ret == 0) {
    #ifdef WOLFSSL_SMALL_STACK
        XmssState* state;
    #else
        XmssState state[1];
    #endif

    #ifdef WOLFSSL_SMALL_STACK
        state = XMALLOC(sizeof(XmssState), NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (state == NULL) {
            ret = MEMORY_E;
        }
        if (ret == 0)
    #endif
        {
            /* Initialize state for use in verification. */
            ret = wc_xmss_state_init(state, key->params);
            if (ret == 0) {
                /* Verify using either XMSS^MT function as it works for both. */
                ret = wc_xmssmt_verify(state, m, mLen, sig, key->pk);
                /* Free state after use. */
                wc_xmss_state_free(state);
            }
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(state, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
        }
    }

    return ret;
}

#endif /* WOLFSSL_HAVE_XMSS */
