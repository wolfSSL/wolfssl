/* falcon.h
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

/*!
    \file wolfssl/wolfcrypt/falcon.h
*/

/* Interfaces for Falcon NIST Level 1 (Falcon512) and Falcon NIST Level 5
 * (Falcon1024). */

#ifndef WOLF_CRYPT_FALCON_H
#define WOLF_CRYPT_FALCON_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif

#if defined(HAVE_FALCON)

/* wc_falcon_sign_msg / wc_falcon_make_key are declared with a WC_RNG* even in
 * verify-only builds (the sign path then returns NOT_COMPILED_IN), so WC_RNG
 * must be visible unconditionally. */
#include <wolfssl/wolfcrypt/random.h>

/* Falcon is a NIST post-quantum signature scheme that has NOT been standardized
 * yet. wolfCrypt exposes it under its current name -- "falcon" (wc_falcon_* /
 * falcon_key) -- and it requires --enable-experimental to build.
 *
 * NOTE: this API and its "falcon" spelling are TEMPORARY and subject to change.
 * Once the algorithm is standardized, the canonical API is expected to be
 * renamed to the standardized name -- exactly as the pre-standardization Kyber
 * and Dilithium APIs were renamed to ML-KEM (FIPS 203) and ML-DSA (FIPS 204) in
 * wolfSSL 5.7 -- and this <falcon.h> is expected to be retained thereafter as a
 * temporary compatibility shim. Application code that uses wc_falcon_* /
 * falcon_key should expect to migrate to the standardized spelling. */

/* This is the native wolfCrypt implementation (no liboqs dependency). */

/* Per-key signing caches, off by default and documented with the other tuning
 * knobs at the top of wolfcrypt/src/falcon.c. They exist only in builds that
 * sign in software. */
#if defined(WOLFSSL_FALCON_VERIFY_ONLY) || defined(WOLF_CRYPTO_CB_ONLY_FALCON)
    #undef WC_FALCON_CACHE_EXPANDED_KEY
    #undef WC_FALCON_CACHE_PRIV_BASIS
#endif

/* Resolve WC_FALCON_CACHE_EXPANDED_KEY to what the selected signer can
 * actually hold: the expanded key in the tree signer, the secret basis alone
 * in a small-mem build. */
#if defined(WC_FALCON_CACHE_EXPANDED_KEY) && \
    !defined(WOLFSSL_FALCON_SIGN_SMALL_MEM)
    /* Internal: the expanded key is really held in the key structure. */
    #define WC_FALCON_CACHE_TREE
    /* The expanded key already contains the basis, and the basis cache is read
     * only until the expansion exists. Asking for both would keep a second
     * copy of secret material alive that nothing reads again. */
    #undef WC_FALCON_CACHE_PRIV_BASIS
#elif defined(WC_FALCON_CACHE_EXPANDED_KEY)
    #ifndef WC_FALCON_CACHE_PRIV_BASIS
        #define WC_FALCON_CACHE_PRIV_BASIS
    #endif
#endif

/* WOLFSSL_FALCON_DYNAMIC_KEYS moves the encoded key buffers to the heap, sized
 * for the level in use rather than for the highest enabled one. It trades two
 * allocations per key for a much smaller falcon_key. */
#if defined(WOLFSSL_FALCON_DYNAMIC_KEYS) && defined(WOLFSSL_NO_MALLOC)
    #error "WOLFSSL_FALCON_DYNAMIC_KEYS needs an allocator; not WOLFSSL_NO_MALLOC."
#endif

#ifdef __cplusplus
    extern "C" {
#endif

/* Macro Definitions */

/* Security level identifiers. */
#define FALCON_LEVEL1     1   /* Falcon-512  */
#define FALCON_LEVEL5     5   /* Falcon-1024 */

/* Ring modulus q = 12289 and degree parameters. */
#define FALCON_Q              12289
#define FALCON_LEVEL1_LOGN    9
#define FALCON_LEVEL1_N       (1 << FALCON_LEVEL1_LOGN)   /* 512  */
#define FALCON_LEVEL5_LOGN    10
#define FALCON_LEVEL5_N       (1 << FALCON_LEVEL5_LOGN)   /* 1024 */

/* Salt/nonce prepended to the message before hash-to-point. */
#define FALCON_NONCE_SIZE     40

/* Encoded sizes (Falcon specification, Table 3.3): 14-bit packed public key,
 * (header|f|g|F) secret key, compressed signature. */
#define FALCON_LEVEL1_KEY_SIZE     1281
#define FALCON_LEVEL1_SIG_SIZE     666
#define FALCON_LEVEL1_PUB_KEY_SIZE 897
#define FALCON_LEVEL1_PRV_KEY_SIZE (FALCON_LEVEL1_PUB_KEY_SIZE+FALCON_LEVEL1_KEY_SIZE)

#define FALCON_LEVEL5_KEY_SIZE     2305
#define FALCON_LEVEL5_SIG_SIZE     1280
#define FALCON_LEVEL5_PUB_KEY_SIZE 1793
#define FALCON_LEVEL5_PRV_KEY_SIZE (FALCON_LEVEL5_PUB_KEY_SIZE+FALCON_LEVEL5_KEY_SIZE)

/* Every FALCON_MAX_* bound follows the highest enabled level, so
 * WOLFSSL_NO_FALCON_LEVEL5 shrinks the key structure and the verify stack
 * arena to Falcon-512 sizes. WOLFSSL_NO_FALCON_LEVEL1 changes no bound. */
#if defined(WOLFSSL_NO_FALCON_LEVEL1) && defined(WOLFSSL_NO_FALCON_LEVEL5)
    #error "Falcon needs at least one of level 1 and level 5 enabled."
#endif

#ifndef WOLFSSL_NO_FALCON_LEVEL5
#define FALCON_MAX_LEVEL        FALCON_LEVEL5
#define FALCON_MAX_N            FALCON_LEVEL5_N
#define FALCON_MAX_KEY_SIZE     FALCON_LEVEL5_KEY_SIZE
#define FALCON_MAX_SIG_SIZE     FALCON_LEVEL5_SIG_SIZE
#define FALCON_MAX_PUB_KEY_SIZE FALCON_LEVEL5_PUB_KEY_SIZE
#define FALCON_MAX_PRV_KEY_SIZE FALCON_LEVEL5_PRV_KEY_SIZE
#else
#define FALCON_MAX_LEVEL        FALCON_LEVEL1
#define FALCON_MAX_N            FALCON_LEVEL1_N
#define FALCON_MAX_KEY_SIZE     FALCON_LEVEL1_KEY_SIZE
#define FALCON_MAX_SIG_SIZE     FALCON_LEVEL1_SIG_SIZE
#define FALCON_MAX_PUB_KEY_SIZE FALCON_LEVEL1_PUB_KEY_SIZE
#define FALCON_MAX_PRV_KEY_SIZE FALCON_LEVEL1_PRV_KEY_SIZE
#endif

/* Encoding header bytes: high nibble = format, low nibble = logn. */
#define FALCON_SIG_HEAD_COMPRESSED    0x30
#define FALCON_PUB_HEAD               0x00

#ifdef WOLF_PRIVATE_KEY_ID
#define FALCON_MAX_ID_LEN    32
#define FALCON_MAX_LABEL_LEN 32
#endif


/* Structs */

struct falcon_key {
    WC_BITFIELD pubKeySet:1;
    WC_BITFIELD prvKeySet:1;
    byte level;

    void* heap;

#ifdef WOLF_CRYPTO_CB
    void* devCtx;
    int   devId;
#endif
#ifdef WOLF_PRIVATE_KEY_ID
    byte id[FALCON_MAX_ID_LEN];
    int  idLen;
    char label[FALCON_MAX_LABEL_LEN];
    int  labelLen;
#endif

    /* p holds the encoded public key, k the private key only (header | f | g |
     * F). wc_falcon_export_private rebuilds the concat(priv,pub) layout on
     * demand, so no duplicate copy is kept here.
     *
     * With WOLFSSL_FALCON_DYNAMIC_KEYS both are heap buffers sized for the
     * key's own level, allocated by wc_falcon_set_level, which shrinks the
     * structure itself to a few dozen bytes. Otherwise they are inline arrays
     * bounded by the highest enabled level. */
#ifdef WOLFSSL_FALCON_DYNAMIC_KEYS
    byte* p;
    byte* k;
    /* Allocated length of k. The release path zeroizes and must not take a
     * length from key->level, which callers can set to anything. */
    word32 kSz;
#else
    byte p[FALCON_MAX_PUB_KEY_SIZE];
    byte k[FALCON_MAX_KEY_SIZE];
#endif

    /* Both caches below hold secret material and are zeroized before release.
     * Their allocated lengths are kept alongside them for the same reason kSz
     * is. */
#ifdef WC_FALCON_CACHE_TREE
    /* Expanded key (basis in FFT form plus the normalized ffLDL tree), built on
     * the first sign and reused by every later one. Typed word64 because the
     * internal fpr type is private to falcon.c. Secret: zeroized before free. */
    word64* expanded;
    word32 expandedSz;
    WC_BITFIELD expandedSet:1;
#endif
#ifdef WC_FALCON_CACHE_PRIV_BASIS
    /* Secret basis f | g | F | G, 4n bytes, decoded and completed once. */
    sword8* basis;
    word32 basisSz;
    WC_BITFIELD basisSet:1;
#endif
};

#ifndef WC_FALCONKEY_TYPE_DEFINED
    typedef struct falcon_key falcon_key;
    #define WC_FALCONKEY_TYPE_DEFINED
#endif

/* Functions */

#ifndef WOLFSSL_FALCON_VERIFY_ONLY
WOLFSSL_API
int wc_falcon_make_key(falcon_key* key, WC_RNG* rng);
#endif
/* With WC_FALCON_CACHE_EXPANDED_KEY or WC_FALCON_CACHE_PRIV_BASIS this writes
 * to 'key': the first call fills the per-key cache, later ones read it. Such a
 * key must not be signed with from two threads at once, nor freed, re-levelled
 * or re-imported while a signature is in flight; the cache is unsynchronized. */
WOLFSSL_API
int wc_falcon_sign_msg(const byte* in, word32 inLen, byte* out, word32 *outLen,
                       falcon_key* key, WC_RNG* rng);
WOLFSSL_API
int wc_falcon_verify_msg(const byte* sig, word32 sigLen, const byte* msg,
                         word32 msgLen, int* res, falcon_key* key);

/* Initialize a falcon_key. The structure may own heap allocations - the
 * encoded key buffers and the signing caches - so this takes an unused or
 * already-freed one. Re-initializing a used key without wc_falcon_free()
 * first orphans those allocations with the secret material still in them. */
WOLFSSL_API
int wc_falcon_init(falcon_key* key);

WOLFSSL_API
int wc_falcon_init_ex(falcon_key* key, void* heap, int devId);

#ifdef WOLF_PRIVATE_KEY_ID
WOLFSSL_API
int wc_falcon_init_id(falcon_key* key, const unsigned char* id, int len,
                      void* heap, int devId);
WOLFSSL_API
int wc_falcon_init_label(falcon_key* key, const char* label, void* heap,
                         int devId);
#endif

WOLFSSL_API
int wc_falcon_set_level(falcon_key* key, byte level);
WOLFSSL_API
int wc_falcon_get_level(falcon_key* key, byte* level);
WOLFSSL_API
void wc_falcon_free(falcon_key* key);

WOLFSSL_API
int wc_falcon_import_public(const byte* in, word32 inLen, falcon_key* key);
WOLFSSL_API
int wc_falcon_import_private_only(const byte* priv, word32 privSz,
                                  falcon_key* key);
WOLFSSL_API
int wc_falcon_import_private_key(const byte* priv, word32 privSz,
                                 const byte* pub, word32 pubSz,
                                 falcon_key* key);

WOLFSSL_API
int wc_falcon_export_public(falcon_key* key, byte* out, word32* outLen);
WOLFSSL_API
int wc_falcon_export_private_only(falcon_key* key, byte* out, word32* outLen);
WOLFSSL_API
int wc_falcon_export_private(falcon_key* key, byte* out, word32* outLen);
WOLFSSL_API
int wc_falcon_export_key(falcon_key* key, byte* priv, word32 *privSz,
                         byte* pub, word32 *pubSz);

WOLFSSL_API
int wc_falcon_check_key(falcon_key* key);

WOLFSSL_API
int wc_falcon_size(falcon_key* key);
WOLFSSL_API
int wc_falcon_priv_size(falcon_key* key);
WOLFSSL_API
int wc_falcon_pub_size(falcon_key* key);
WOLFSSL_API
int wc_falcon_sig_size(falcon_key* key);

WOLFSSL_API int wc_Falcon_PrivateKeyDecode(const byte* input, word32* inOutIdx,
                                           falcon_key* key, word32 inSz);
WOLFSSL_API int wc_Falcon_PublicKeyDecode(const byte* input, word32* inOutIdx,
                                          falcon_key* key, word32 inSz);
WOLFSSL_API int wc_Falcon_KeyToDer(falcon_key* key, byte* output,
                                   word32 inLen);
WOLFSSL_API int wc_Falcon_PrivateKeyToDer(falcon_key* key, byte* output,
                                          word32 inLen);
WOLFSSL_API int wc_Falcon_PublicKeyToDer(falcon_key* key, byte* output,
                                         word32 inLen, int withAlg);

/* Native implementation core (internal). The public wc_falcon_* functions in
 * falcon.c wrap these with cryptocb dispatch and argument checking. With
 * WOLF_CRYPTO_CB_ONLY_FALCON the native core is not compiled: all operations go
 * through the crypto callback. */
#ifndef WOLF_CRYPTO_CB_ONLY_FALCON
#ifndef WOLFSSL_FALCON_VERIFY_ONLY
/* Signals that native signing and key generation are available. */
#define WC_FALCON_HAVE_NATIVE_SIGN
WOLFSSL_LOCAL int falcon_native_make_key(falcon_key* key, WC_RNG* rng);
WOLFSSL_LOCAL int falcon_native_sign_msg(const byte* in, word32 inLen,
        byte* out, word32* outLen, falcon_key* key, WC_RNG* rng);
WOLFSSL_LOCAL int falcon_native_check_key(falcon_key* key);
#endif
WOLFSSL_LOCAL int falcon_native_verify_msg(const byte* sig, word32 sigLen,
        const byte* msg, word32 msgLen, int* res, falcon_key* key);
#endif /* !WOLF_CRYPTO_CB_ONLY_FALCON */

#ifdef __cplusplus
    }    /* extern "C" */
#endif

#endif /* HAVE_FALCON */
#endif /* WOLF_CRYPT_FALCON_H */
