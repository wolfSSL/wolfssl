/* wc_slhdsa.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#ifndef WOLF_CRYPT_WC_SLHDSA_H
#define WOLF_CRYPT_WC_SLHDSA_H

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha3.h>

#ifdef WOLFSSL_HAVE_SLHDSA

/* When a bits/opt is defined then ensure 'NO' defines are off. */
#ifdef WOLFSSL_SLHDSA_PARAM_128S
    #undef WOLFSSL_SLHDSA_PARAM_NO_128S
    #undef WOLFSSL_SLHDSA_PARAM_NO_128
    #undef WOLFSSL_SLHDSA_PARAM_NO_SMALL
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_128F
    #undef WOLFSSL_SLHDSA_PARAM_NO_128F
    #undef WOLFSSL_SLHDSA_PARAM_NO_128
    #undef WOLFSSL_SLHDSA_PARAM_NO_FAST
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_192S
    #undef WOLFSSL_SLHDSA_PARAM_NO_192S
    #undef WOLFSSL_SLHDSA_PARAM_NO_192
    #undef WOLFSSL_SLHDSA_PARAM_NO_SMALL
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_192F
    #undef WOLFSSL_SLHDSA_PARAM_NO_192F
    #undef WOLFSSL_SLHDSA_PARAM_NO_192
    #undef WOLFSSL_SLHDSA_PARAM_NO_FAST
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_256S
    #undef WOLFSSL_SLHDSA_PARAM_NO_256S
    #undef WOLFSSL_SLHDSA_PARAM_NO_256
    #undef WOLFSSL_SLHDSA_PARAM_NO_SMALL
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_256F
    #undef WOLFSSL_SLHDSA_PARAM_NO_256F
    #undef WOLFSSL_SLHDSA_PARAM_NO_256
    #undef WOLFSSL_SLHDSA_PARAM_NO_FAST
#endif

/* When 'NO' defines are on then define no parameter set. */
#if defined(WOLFSSL_SLHDSA_PARAM_NO_128S) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_128F)
    #undef WOLFSSL_SLHDSA_NO_128
    #define WOLFSSL_SLHDSA_NO_128
#endif
#if defined(WOLFSSL_SLHDSA_PARAM_NO_192S) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_192F)
    #undef WOLFSSL_SLHDSA_NO_192
    #define WOLFSSL_SLHDSA_NO_192
#endif
#if defined(WOLFSSL_SLHDSA_PARAM_NO_256S) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_256F)
    #undef WOLFSSL_SLHDSA_NO_256
    #define WOLFSSL_SLHDSA_NO_256
#endif
#if defined(WOLFSSL_SLHDSA_PARAM_NO_128S) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_192S) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_256S)
    #undef WOLFSSL_SLHDSA_PARAM_NO_SMALL
    #define WOLFSSL_SLHDSA_PARAM_NO_SMALL
#endif
#if defined(WOLFSSL_SLHDSA_PARAM_NO_128F) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_192F) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_256F)
    #undef WOLFSSL_SLHDSA_PARAM_NO_FAST
    #define WOLFSSL_SLHDSA_PARAM_NO_FAST
#endif

/* Turn on parameter set based on 'NO' defines. */
#if !defined(WOLFSSL_SLHDSA_PARAM_NO_128S) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_128) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_SMALL)
    #undef WOLFSSL_SLHDSA_PARAM_128S
    #define WOLFSSL_SLHDSA_PARAM_128S
#endif
#if !defined(WOLFSSL_SLHDSA_PARAM_NO_128F) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_128) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_FAST)
    #undef WOLFSSL_SLHDSA_PARAM_128F
    #define WOLFSSL_SLHDSA_PARAM_128F
#endif
#if !defined(WOLFSSL_SLHDSA_PARAM_NO_192S) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_192) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_SMALL)
    #undef WOLFSSL_SLHDSA_PARAM_192S
    #define WOLFSSL_SLHDSA_PARAM_192S
#endif
#if !defined(WOLFSSL_SLHDSA_PARAM_NO_192F) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_192) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_FAST)
    #undef WOLFSSL_SLHDSA_PARAM_192F
    #define WOLFSSL_SLHDSA_PARAM_192F
#endif
#if !defined(WOLFSSL_SLHDSA_PARAM_NO_256S) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_256) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_SMALL)
    #undef WOLFSSL_SLHDSA_PARAM_256S
    #define WOLFSSL_SLHDSA_PARAM_256S
#endif
#if !defined(WOLFSSL_SLHDSA_PARAM_NO_256F) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_256) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_FAST)
    #undef WOLFSSL_SLHDSA_PARAM_256F
    #define WOLFSSL_SLHDSA_PARAM_256F
#endif

#if defined(WOLFSSL_SLHDSA_PARAM_NO_128S) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_192S) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_256S)
    #undef WOLFSSL_SLHDSA_PARAM_NO_SMALL
    #define WOLFSSL_SLHDSA_PARAM_NO_SMALL
#endif
#if defined(WOLFSSL_SLHDSA_PARAM_NO_128F) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_192F) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_256F)
    #undef WOLFSSL_SLHDSA_PARAM_NO_FAST
    #define WOLFSSL_SLHDSA_PARAM_NO_FAST
#endif
#if defined(WOLFSSL_SLHDSA_PARAM_NO_128S) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_128F)
    #undef WOLFSSL_SLHDSA_PARAM_NO_128
    #define WOLFSSL_SLHDSA_PARAM_NO_128
#endif
#if defined(WOLFSSL_SLHDSA_PARAM_NO_192S) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_192F)
    #undef WOLFSSL_SLHDSA_PARAM_NO_192
    #define WOLFSSL_SLHDSA_PARAM_NO_192
#endif
#if defined(WOLFSSL_SLHDSA_PARAM_NO_256S) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_256F)
    #undef WOLFSSL_SLHDSA_PARAM_NO_256
    #define WOLFSSL_SLHDSA_PARAM_NO_256
#endif


/* Private key length for SLH-DSA SHAKE-128s. */
#define WC_SLHDSA_SHAKE128S_PRIV_LEN    (4 * 16)
/* Public key length for SLH-DSA SHAKE-128s. */
#define WC_SLHDSA_SHAKE128S_PUB_LEN     (2 * 16)
/* Signature length for SLH-DSA SHAKE-128s. */
#define WC_SLHDSA_SHAKE128S_SIG_LEN     7856

/* Private key length for SLH-DSA SHAKE-128f. */
#define WC_SLHDSA_SHAKE128F_PRIV_LEN    (4 * 16)
/* Public key length for SLH-DSA SHAKE-128f. */
#define WC_SLHDSA_SHAKE128F_PUB_LEN     (2 * 16)
/* Signature length for SLH-DSA SHAKE-128f. */
#define WC_SLHDSA_SHAKE128F_SIG_LEN     17088

/* Private key length for SLH-DSA SHAKE-192s. */
#define WC_SLHDSA_SHAKE192S_PRIV_LEN    (4 * 24)
/* Public key length for SLH-DSA SHAKE-192s. */
#define WC_SLHDSA_SHAKE192S_PUB_LEN     (2 * 24)
/* Signature length for SLH-DSA SHAKE-192s. */
#define WC_SLHDSA_SHAKE192S_SIG_LEN     16225

/* Private key length for SLH-DSA SHAKE-192f. */
#define WC_SLHDSA_SHAKE192F_PRIV_LEN    (4 * 24)
/* Public key length for SLH-DSA SHAKE-192f. */
#define WC_SLHDSA_SHAKE192F_PUB_LEN     (2 * 24)
/* Signature length for SLH-DSA SHAKE-192f. */
#define WC_SLHDSA_SHAKE192F_SIG_LEN     35664

/* Private key length for SLH-DSA SHAKE-256s. */
#define WC_SLHDSA_SHAKE256S_PRIV_LEN    (4 * 32)
/* Public key length for SLH-DSA SHAKE-256s. */
#define WC_SLHDSA_SHAKE256S_PUB_LEN     (2 * 32)
/* Signature length for SLH-DSA SHAKE-256s. */
#define WC_SLHDSA_SHAKE256S_SIG_LEN     29792

/* Private key length for SLH-DSA SHAKE-256f. */
#define WC_SLHDSA_SHAKE256F_PRIV_LEN    (4 * 32)
/* Public key length for SLH-DSA SHAKE-256f. */
#define WC_SLHDSA_SHAKE256F_PUB_LEN     (2 * 32)
/* Signature length for SLH-DSA SHAKE-256f. */
#define WC_SLHDSA_SHAKE256F_SIG_LEN     49856

/* Determine maximum private and public key lengths based on maximum SHAKE-256
 * output length. */
#ifndef WOLFSSL_SLHDSA_PARAM_NO_256
    /* Maximum private key length. */
    #define WC_SLHDSA_MAX_PRIV_LEN          WC_SLHDSA_SHAKE256F_PRIV_LEN
    /* Maximum public key length. */
    #define WC_SLHDSA_MAX_PUB_LEN           WC_SLHDSA_SHAKE256F_PUB_LEN
#elif !defined(WOLFSSL_SLHDSA_PARAM_NO_192)
    /* Maximum private key length. */
    #define WC_SLHDSA_MAX_PRIV_LEN          WC_SLHDSA_SHAKE192F_PRIV_LEN
    /* Maximum public key length. */
    #define WC_SLHDSA_MAX_PUB_LEN           WC_SLHDSA_SHAKE192F_PUB_LEN
#else
    /* Maximum private key length. */
    #define WC_SLHDSA_MAX_PRIV_LEN          WC_SLHDSA_SHAKE128F_PRIV_LEN
    /* Maximum public key length. */
    #define WC_SLHDSA_MAX_PUB_LEN           WC_SLHDSA_SHAKE128F_PUB_LEN
#endif
/* Determine maximum signature length depending on the parameters compiled in.
 */
#if !defined(WOLFSSL_SLHDSA_PARAM_NO_256) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_FAST)
    /* Maximum signature length. */
    #define WC_SLHDSA_MAX_SIG_LEN           WC_SLHDSA_SHAKE256F_SIG_LEN
#elif !defined(WOLFSSL_SLHDSA_PARAM_NO_192) && \
      !defined(WOLFSSL_SLHDSA_PARAM_NO_FAST)
    /* Maximum signature length. */
    #define WC_SLHDSA_MAX_SIG_LEN           WC_SLHDSA_SHAKE192F_SIG_LEN
#elif !defined(WOLFSSL_SLHDSA_PARAM_NO_256) && \
      !defined(WOLFSSL_SLHDSA_PARAM_NO_SMALL)
    /* Maximum signature length. */
    #define WC_SLHDSA_MAX_SIG_LEN           WC_SLHDSA_SHAKE256S_SIG_LEN
#elif !defined(WOLFSSL_SLHDSA_PARAM_NO_128) && \
      !defined(WOLFSSL_SLHDSA_PARAM_NO_FAST)
    /* Maximum signature length. */
    #define WC_SLHDSA_MAX_SIG_LEN           WC_SLHDSA_SHAKE128F_SIG_LEN
#elif !defined(WOLFSSL_SLHDSA_PARAM_NO_192) && \
      !defined(WOLFSSL_SLHDSA_PARAM_NO_SMALL)
    /* Maximum signature length. */
    #define WC_SLHDSA_MAX_SIG_LEN           WC_SLHDSA_SHAKE192S_SIG_LEN
#elif !defined(WOLFSSL_SLHDSA_PARAM_NO_128) && \
      !defined(WOLFSSL_SLHDSA_PARAM_NO_SMALL)
    /* Maximum signature length. */
    #define WC_SLHDSA_MAX_SIG_LEN           WC_SLHDSA_SHAKE128S_SIG_LEN
#else
    #error "No parameters defined"
#endif

/* Ids for supported SLH-DSA parameters. */
enum SlhDsaParam {
    SLHDSA_SHAKE128S = 0,   /* SLH-DSA SHAKE128s */
    SLHDSA_SHAKE128F = 1,   /* SLH-DSA SHAKE128f */
    SLHDSA_SHAKE192S = 2,   /* SLH-DSA SHAKE192s */
    SLHDSA_SHAKE192F = 3,   /* SLH-DSA SHAKE192f */
    SLHDSA_SHAKE256S = 4,   /* SLH-DSA SHAKE256s */
    SLHDSA_SHAKE256F = 5,   /* SLH-DSA SHAKE256f */
};

/* Pre-defined parameter values. */
typedef struct SlhDsaParameters {
    enum SlhDsaParam param;     /* Parameter set id. */
    byte n;                     /* Size of digest output. */
    byte h;                     /* Total tree height. */
    byte d;                     /* Depth of subtree. */
    byte h_m;                   /* Height of message tree - XMSS tree. */
    byte a;                     /* Number of authenthication nodes. */
    byte k;                     /* Number of FORS signatures. */
    byte len;                   /* Length of WOTS+ encoded message with csum. */
    byte dl1;                   /* Length first part of message digest. */
    byte dl2;                   /* Length second part of message digest. */
    byte dl3;                   /* Length third part of message digest. */
    word32 sigLen;              /* Signature length in bytes. */
} SlhDsaParameters;

#define WC_SLHDSA_FLAG_PRIVATE       0x0001
#define WC_SLHDSA_FLAG_PUBLIC        0x0002
#define WC_SLHDSA_FLAG_BOTH_KEYS     (WC_SLHDSA_FLAG_PRIVATE | \
                                      WC_SLHDSA_FLAG_PUBLIC)

/* SLH-DSA key data and state. */
typedef struct SlhDsaKey {
    /* Parameters. */
    const SlhDsaParameters* params;
    /* Flags of the key. */
    int flags;
    /* Dynamic memory hint. */
    void* heap;
#ifdef WOLF_CRYPTO_CB
    /* Device Identifier. */
    int devId;
#endif

    /* sk_seed | sk_prf | pk_seed, pk_root */
    byte sk[32 * 4];
    /* First SHAKE-256 object. */
    wc_Shake shake;
    /* Second SHAKE-256 object. */
    wc_Shake shake2;
} SlhDsaKey;

WOLFSSL_API int  wc_SlhDsaKey_Init(SlhDsaKey* key, enum SlhDsaParam param,
    void* heap, int devId);
WOLFSSL_API void wc_SlhDsaKey_Free(SlhDsaKey* key);

WOLFSSL_API int  wc_SlhDsaKey_MakeKey(SlhDsaKey* key, WC_RNG* rng);
WOLFSSL_API int  wc_SlhDsaKey_MakeKeyWithRandom(SlhDsaKey* key,
    const byte* sk_seed, word32 sk_seed_len,
    const byte* sk_prf, word32 sk_prf_len,
    const byte* pk_seed, word32 pk_seed_len);

WOLFSSL_API int  wc_SlhDsaKey_SignDeterministic(SlhDsaKey* key, const byte* ctx,
    byte ctxSz, const byte* msg, word32 msgSz, byte* sig, word32* sigSz);
WOLFSSL_API int  wc_SlhDsaKey_SignWithRandom(SlhDsaKey* key, const byte* ctx,
    byte ctxSz, const byte* msg, word32 msgSz, byte* sig, word32* sigSz,
    const byte* addRnd);
WOLFSSL_API int  wc_SlhDsaKey_Sign(SlhDsaKey* key, const byte* ctx,
    byte ctxSz, const byte* msg, word32 msgSz, byte* sig, word32* sigSz,
    WC_RNG* rng);
WOLFSSL_API int  wc_SlhDsaKey_Verify(SlhDsaKey* key, const byte* ctx,
    byte ctxSz, const byte* msg, word32 msgSz, const byte* sig, word32 sigSz);

WOLFSSL_API int  wc_SlhDsaKey_SignHashDeterministic(SlhDsaKey* key,
    const byte* ctx, byte ctxSz, const byte* msg, word32 msgSz,
    enum wc_HashType hashType, byte* sig, word32* sigSz);
WOLFSSL_API int  wc_SlhDsaKey_SignHashWithRandom(SlhDsaKey* key,
    const byte* ctx, byte ctxSz, const byte* msg, word32 msgSz,
    enum wc_HashType hashType, byte* sig, word32* sigSz, byte* addRnd);
WOLFSSL_API int  wc_SlhDsaKey_SignHash(SlhDsaKey* key, const byte* ctx,
    byte ctxSz, const byte* msg, word32 msgSz, enum wc_HashType hashType,
    byte* sig, word32* sigSz, WC_RNG* rng);
WOLFSSL_API int  wc_SlhDsaKey_VerifyHash(SlhDsaKey* key, const byte* ctx,
    byte ctxSz, const byte* msg, word32 msgSz, enum wc_HashType hashType,
    const byte* sig, word32 sigSz);

WOLFSSL_API int  wc_SlhDsaKey_ImportPrivate(SlhDsaKey* key, const byte* in,
    word32 inLen);
WOLFSSL_API int  wc_SlhDsaKey_ImportPublic(SlhDsaKey* key, const byte* in,
    word32 inLen);
WOLFSSL_API int  wc_SlhDsaKey_CheckKey(SlhDsaKey* key);

WOLFSSL_API int  wc_SlhDsaKey_ExportPrivate(SlhDsaKey* key, byte* out,
    word32* outLen);
WOLFSSL_API int  wc_SlhDsaKey_ExportPublic(SlhDsaKey* key, byte* out,
    word32* outLen);

WOLFSSL_API int  wc_SlhDsaKey_PrivateSize(SlhDsaKey* key);
WOLFSSL_API int  wc_SlhDsaKey_PublicSize(SlhDsaKey* key);
WOLFSSL_API int  wc_SlhDsaKey_SigSize(SlhDsaKey* key);

#endif /* WOLFSSL_HAVE_SLHDSA */

#endif /* WOLF_CRYPT_WC_SLHDSA_H */
