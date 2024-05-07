/* wc_lms.h
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

/* Implementation based on:
 *   RFC 8554: Leighton-Micali Hash-Based Signatures
 *   https://datatracker.ietf.org/doc/html/rfc8554
 * Implementation by Sean Parkinson.
 */

/* Possible LMS options:
 *
 * WOLFSSL_LMS_LARGE_CACHES                             Default: OFF
 *   Authentication path caches are large and signing faster.
 * WOLFSSL_LMS_ROOT_LEVELS                              Default: 5 (Large: 7)
 *   Number of levels of interior nodes from the to to cached.
 *   Valid value are: 1..height of subtree.
 *   The bigger the number, the larger the LmsKey but faster signing.
 *   Only applies when !WOLFSSL_WC_LMS_SMALL.
 * WOLFSSL_LMS_CACHE_BITS                               Default: 5 (Large: 7)
 *   2 to the power of the value is the number of leaf nodes to cache.
 *   Maximum valid value is height of subtree.
 *   Valid value are: 0..height of subtree.
 *   The bigger the number, the larger the LmsKey but faster signing.
 *   Only applies when !WOLFSSL_WC_LMS_SMALL.
 *
 * Memory/Level | R/C | Approx. Time (% of 5/5)
 *      (Bytes) |     |  H=10  |  H=15  |  H=20
 * -------------+--------------+--------+--------
 *         2016 | 5/5 | 100.0% | 100.0% | 100.0%
 *         3040 | 5/6 |  75.5% |  89.2% |
 *         4064 | 6/6 |  75.3% |  78.8% |
 *         4576 | 4/7 |  72.4% |  87.6% |
 *         6112 | 6/7 |  72.1% |  67.5% |
 *         8160 | 7/7 |  72.2% |  56.8% |
 *         8416 | 3/8 |  66.4% |  84.9% |
 *        12256 | 7/8 |  66.5% |  45.9% |
 *        16352 | 8/8 |  66.0% |  35.0% |
 *        16416 | 1/9 |  54.1% |  79.5% |
 * R = Root levels
 * C = Cache bits
 * To mimic the dynamic memory usage of XMSS, use 3/3.
 *
 * WOLFSSL_LMS_NO_SIGN SMOOTHING                        Default: OFF
 *   Disable precalculation of next subtree.
 *   Use less dynamic memory.
 *   At certain indexes, signing will take a long time compared to the mean.
 *   When OFF, the private key holds a second copy of caches.
 *
 * WOLFSSL_LMS_NO_SIG_CACHE                             Default: OFF
 *   Signature cache is disabled.
 *   This will use less dynamic memory and make signing slower when multiple
 *   levels.
 *
 * Sig cache holds the C and y hashes for a tree that is not the lowest.
 * Sig cache size = (levels - 1) * (1 + p) * 32 bytes
 * p is the number of y terms based on Winternitz width.
 *
 *  w |  p | l | Bytes
 * ---+----+---+------
 *  4 | 67 | 2 |  2176
 *  4 | 67 | 3 |  4353
 *  4 | 67 | 4 |  6528
 *  8 | 34 | 2 |  1120
 *  8 | 34 | 3 |  2240
 *  8 | 34 | 4 |  3360
 * w = Winternitz width
 * l = #levels
 */

#ifndef WC_LMS_H
#define WC_LMS_H

#if defined(WOLFSSL_HAVE_LMS) && defined(WOLFSSL_WC_LMS)

#include <wolfssl/wolfcrypt/lms.h>
#include <wolfssl/wolfcrypt/sha256.h>

#ifdef WOLFSSL_LMS_MAX_LEVELS
    /* Maximum number of levels of trees supported by implementation. */
    #define LMS_MAX_LEVELS          WOLFSSL_LMS_MAX_LEVELS
#else
    /* Maximum number of levels of trees supported by implementation. */
    #define LMS_MAX_LEVELS          4
#endif
#if (LMS_MAX_LEVELS < 1) || (LMS_MAX_LEVELS > 4)
    #error "LMS parameters only support heights 1-4."
#endif

/* Smoothing is only used when there are 2 or more levels. */
#if LMS_MAX_LEVELS == 1 && !defined(WOLFSSL_LMS_NO_SIGN_SMOOTHING)
    #define WOLFSSL_LMS_NO_SIGN_SMOOTHING
#endif

#ifdef WOLFSSL_LMS_MAX_HEIGHT
    /* Maximum height of a tree supported by implementation. */
    #define LMS_MAX_HEIGHT          WOLFSSL_LMS_MAX_HEIGHT
#else
    /* Maximum height of a tree supported by implementation. */
    #define LMS_MAX_HEIGHT          20
#endif
#if (LMS_MAX_HEIGHT < 5) || (LMS_MAX_HEIGHT > 20)
    #error "LMS parameters only support heights 5-20."
#endif

/* Length of I in bytes. */
#define LMS_I_LEN                   16
/* Length of L in bytes. */
#define LMS_L_LEN                   4
/* Length of Q for a level. */
#define LMS_Q_LEN                   4
/* Length of P in bytes. */
#define LMS_P_LEN                   2
/* Length of W in bytes. */
#define LMS_W_LEN                   1

/* Length of numeric types when encoding. */
#define LMS_TYPE_LEN                4

/* Maximum size of a node hash. */
#define LMS_MAX_NODE_LEN            WC_SHA256_DIGEST_SIZE
/* Maximum size of SEED (produced by hash). */
#define LMS_SEED_LEN                WC_SHA256_DIGEST_SIZE
/* Maximum number of P, number of n-byte string elements in LM-OTS signature.
 * Value of P when N=32 and W=1.
 */
#define LMS_MAX_P                   265
/* Length of SEED and I in bytes. */
#define LMS_SEED_I_LEN              (LMS_SEED_LEN + LMS_I_LEN)


#ifndef WOLFSSL_LMS_ROOT_LEVELS
    #ifdef WOLFSSL_LMS_LARGE_CACHES
        /* Number of root levels of interior nodes to store.  */
        #define LMS_ROOT_LEVELS         7
    #else
        /* Number of root levels of interior nodes to store.  */
        #define LMS_ROOT_LEVELS         5
    #endif
#else
    #define LMS_ROOT_LEVELS             WOLFSSL_LMS_ROOT_LEVELS
#endif
#if LMS_ROOT_LEVELS <= 0
    #error "LMS_ROOT_LEVELS must be greater than 0."
#endif
/* Count of root nodes to store per level. */
#define LMS_ROOT_COUNT              ((1 << (LMS_ROOT_LEVELS)) - 1)

#ifndef WOLFSSL_LMS_CACHE_BITS
    #ifdef WOLFSSL_LMS_LARGE_CACHES
        /* 2 to the power of the value is the number of leaf nodes to cache. */
        #define LMS_CACHE_BITS          7
    #else
        /* 2 to the power of the value is the number of leaf nodes to cache. */
        #define LMS_CACHE_BITS          5
    #endif
#else
    #define LMS_CACHE_BITS              WOLFSSL_LMS_CACHE_BITS
#endif
#if LMS_CACHE_BITS < 0
    #error "LMS_CACHE_BITS must be greater than or equal to 0."
#endif
/* Number of leaf nodes to cache. */
#define LMS_LEAF_CACHE              (1 << LMS_CACHE_BITS)

/* Maximum number of levels of trees described in private key. */
#define HSS_MAX_LEVELS              8
/* Length of full Q in bytes. Q from all levels combined. */
#define HSS_Q_LEN                   8

/* Compressed parameter set length in bytes. */
#define HSS_COMPRESS_PARAM_SET_LEN  1
/* Total compressed parameter set length for private key in bytes. */
#define HSS_PRIV_KEY_PARAM_SET_LEN  \
    (HSS_COMPRESS_PARAM_SET_LEN * HSS_MAX_LEVELS)

/* Private key length for one level. */
#define LMS_PRIV_LEN                \
    (LMS_Q_LEN + LMS_SEED_LEN + LMS_I_LEN)
/* Public key length in signature. */
#define LMS_PUBKEY_LEN              \
    (LMS_TYPE_LEN + LMS_TYPE_LEN + LMS_I_LEN + LMS_MAX_NODE_LEN)

/* LMS signature data length. */
#define LMS_SIG_LEN(h, p)                                                   \
    (LMS_Q_LEN + LMS_TYPE_LEN + LMS_MAX_NODE_LEN + (p) * LMS_MAX_NODE_LEN + \
     LMS_TYPE_LEN + (h) * LMS_MAX_NODE_LEN)

/* Length of public key. */
#define HSS_PUBLIC_KEY_LEN          (LMS_L_LEN + LMS_PUBKEY_LEN)
/* Length of private key. */
#define HSS_PRIVATE_KEY_LEN         \
    (HSS_Q_LEN + HSS_PRIV_KEY_PARAM_SET_LEN + LMS_SEED_LEN + LMS_I_LEN)
/* Maximum public key length - length is constant for all parameters. */
#define HSS_MAX_PRIVATE_KEY_LEN     HSS_PRIVATE_KEY_LEN
/* Maximum private key length - length is constant for all parameters. */
#define HSS_MAX_PUBLIC_KEY_LEN      HSS_PUBLIC_KEY_LEN
/* Maximum signature length. */
#define HSS_MAX_SIG_LEN                                                        \
    (LMS_TYPE_LEN +                                                            \
     LMS_MAX_LEVELS * (LMS_Q_LEN + LMS_TYPE_LEN + LMS_TYPE_LEN +               \
                       LMS_MAX_NODE_LEN * (1 + LMS_MAX_P + LMS_MAX_HEIGHT)) +  \
     (LMS_MAX_LEVELS - 1) * LMS_PUBKEY_LEN                                     \
     )

/* Maximum buffer length required for use when hashing. */
#define LMS_MAX_BUFFER_LEN          \
    (LMS_I_LEN + LMS_Q_LEN + LMS_P_LEN + LMS_W_LEN + 2 * LMS_MAX_NODE_LEN)


/* Private key data length.
 *
 * HSSPrivKey.priv
 */
#define LMS_PRIV_KEY_LEN(l) \
    ((l) * LMS_PRIV_LEN)

/* Stack of nodes. */
#define LMS_STACK_CACHE_LEN(h)              \
     (((h) + 1) * LMS_MAX_NODE_LEN)

/* Root cache length. */
#define LMS_ROOT_CACHE_LEN(rl)              \
    (((1 << (rl)) - 1) * LMS_MAX_NODE_LEN)

/* Leaf cache length. */
#define LMS_LEAF_CACHE_LEN(cb)              \
    ((1 << (cb)) * LMS_MAX_NODE_LEN)

/* Length of LMS private key state.
 *
 * LmsPrivState
 *   auth_path +
 *   root +
 *   stack.stack + stack.offset +
 *   cache.leaf + cache.index + cache.offset
 */
#define LMS_PRIV_STATE_LEN(h, rl, cb)   \
    (((h) * LMS_MAX_NODE_LEN) +         \
     LMS_STACK_CACHE_LEN(h) + 4 +       \
     LMS_ROOT_CACHE_LEN(rl) +           \
     LMS_LEAF_CACHE_LEN(cb) + 4 + 4)

#ifndef WOLFSSL_WC_LMS_SMALL
    /* Private key data state for all levels. */
    #define LMS_PRIV_STATE_ALL_LEN(l, h, rl, cb)    \
         ((l) * LMS_PRIV_STATE_LEN(h, rl, cb))
#else
    /* Private key data state for all levels. */
    #define LMS_PRIV_STATE_ALL_LEN(l, h, rl, cb)    0
#endif

#ifndef WOLFSSL_LMS_NO_SIGN_SMOOTHING
    /* Extra private key data for smoothing. */
    #define LMS_PRIV_SMOOTH_LEN(l, h, rl, cb)       \
        (LMS_PRIV_KEY_LEN(l) +                      \
         ((l) - 1) * LMS_PRIV_STATE_LEN(h, rl, cb))
#else
    /* Extra private key data for smoothing. */
    #define LMS_PRIV_SMOOTH_LEN(l, h, rl, cb)       0
#endif

#ifndef WOLFSSL_LMS_NO_SIG_CACHE
    #define LMS_PRIV_Y_TREE_LEN(p)                                  \
        (LMS_MAX_NODE_LEN + (p) * LMS_MAX_NODE_LEN)
    /* Length of the y data cached in private key data. */
    #define LMS_PRIV_Y_LEN(l, p)                                    \
        (((l) - 1) * (LMS_MAX_NODE_LEN + (p) * LMS_MAX_NODE_LEN))
#else
    /* Length of the y data cached in private key data. */
    #define LMS_PRIV_Y_LEN(l, p)    0
#endif

#ifndef WOLFSSL_WC_LMS_SMALL
/* Length of private key data. */
#define LMS_PRIV_DATA_LEN(l, h, p, rl, cb)   \
    (LMS_PRIV_KEY_LEN(l) +                   \
     LMS_PRIV_STATE_ALL_LEN(l, h, rl, cb) +  \
     LMS_PRIV_SMOOTH_LEN(l, h, rl, cb) +     \
     LMS_PRIV_Y_LEN(l, p))
#else
#define LMS_PRIV_DATA_LEN(l, h, p, rl, cb)   \
    LMS_PRIV_KEY_LEN(l)
#endif


/* LMS Parameters. */
/* SHA-256 hash, 32-bytes of hash used, tree height of 5. */
#define LMS_SHA256_M32_H5           5
/* SHA-256 hash, 32-bytes of hash used, tree height of 10. */
#define LMS_SHA256_M32_H10          6
/* SHA-256 hash, 32-bytes of hash used, tree height of 15. */
#define LMS_SHA256_M32_H15          7
/* SHA-256 hash, 32-bytes of hash used, tree height of 20. */
#define LMS_SHA256_M32_H20          8
/* SHA-256 hash, 32-bytes of hash used, tree height of 25. */
#define LMS_SHA256_M32_H25          9

/* SHA-256 hash, 32-bytes of hash used, Winternitz width of 1 bit. */
#define LMOTS_SHA256_N32_W1         1
/* SHA-256 hash, 32-bytes of hash used, Winternitz width of 2 bits. */
#define LMOTS_SHA256_N32_W2         2
/* SHA-256 hash, 32-bytes of hash used, Winternitz width of 4 bits. */
#define LMOTS_SHA256_N32_W4         3
/* SHA-256 hash, 32-bytes of hash used, Winternitz width of 8 bits. */
#define LMOTS_SHA256_N32_W8         4

typedef struct LmsParams {
    /* Number of tree levels. */
    word8 levels;
    /* Height of each tree. */
    word8 height;
    /* Width or Winternitz coefficient. */
    word8 width;
    /* Number of left-shift bits used in checksum calculation. */
    word8 ls;
    /* Number of n-byte string elements in LM-OTS signature. */
    word16 p;
    /* LMS type. */
    word16 lmsType;
    /* LMOTS type. */
    word16 lmOtsType;
    /* Length of LM-OTS signature. */
    word16 sig_len;
#ifndef WOLFSSL_WC_LMS_SMALL
    /* Number of root levels of interior nodes to store. */
    word8 rootLevels;
    /* 2 to the power of the value is the number of leaf nodes to cache. */
    word8 cacheBits;
#endif
} LmsParams;

/* Mapping of id and string to parameters. */
typedef struct wc_LmsParamsMap {
    /* Identifier of parameters. */
    enum wc_LmsParm id;
    /* String representation of identifier of parameters. */
    const char* str;
    /* LMS parameter set. */
    LmsParams params;
} wc_LmsParamsMap;

typedef struct LmsState {
    /* Buffer to hold data to hash. */
    ALIGN16 byte buffer[LMS_MAX_BUFFER_LEN];
#ifdef WOLFSSL_SMALL_STACK
    /* Buffer to hold expanded Q coefficients. */
    ALIGN16 byte a[LMS_MAX_P];
#endif
    /* LMS parameters. */
    const LmsParams* params;
    /* Hash algorithm. */
    wc_Sha256 hash;
    /* Hash algorithm for calculating K. */
    wc_Sha256 hash_k;
} LmsState;

#ifndef WOLFSSL_WC_LMS_SMALL
/* Stack of interior node hashes. */
typedef struct LmsStack {
    /* Stack nodes. */
    byte* stack;
    /* Top of stack offset. */
    word32 offset;
} LmsStack;

/* Cache of leaf hashes. */
typedef struct HssLeafCache {
    /* Cache of leaf nodes. Circular queue. */
    byte* cache;
    /* Start index of cached leaf nodes. */
    word32 idx;
    /* Index into cache of first leaf node. */
    word32 offset;
} HssLeafCache;

typedef struct LmsPrivState {
    /* Authentication path for current index. */
    byte* auth_path;
    /* Stack nodes. */
    LmsStack stack;
    /* Root nodes. */
    byte* root;
    /* Cache of leaf nodes. */
    HssLeafCache leaf;
} LmsPrivState;
#endif /* WOLFSSL_WC_LMS_SMALL */

typedef struct HssPrivKey {
    /* Private key. */
    byte* priv;
#ifndef WOLFSSL_WC_LMS_SMALL
    /* Per level state of the private key. */
    LmsPrivState state[LMS_MAX_LEVELS];
#ifndef WOLFSSL_LMS_NO_SIGN_SMOOTHING
    /* Next private key. */
    byte* next_priv;
    /* Next private state. */
    LmsPrivState next_state[LMS_MAX_LEVELS - 1];
#endif
#ifndef WOLFSSL_LMS_NO_SIG_CACHE
    /* Per level state of the private key. */
    byte* y;
#endif
    /* Indicates the key has all levels initialized. */
    word8 inited:1;
#endif
} HssPrivKey;

struct LmsKey {
    /* Public key. */
    ALIGN16 byte pub[HSS_PUBLIC_KEY_LEN];
#ifndef WOLFSSL_LMS_VERIFY_ONLY
    /* Encoded private key. */
    ALIGN16 byte priv_raw[HSS_PRIVATE_KEY_LEN];

    /* Packed private key data. */
    byte* priv_data;
    /* HSS Private key. */
    HssPrivKey priv;

    /* Callback to write/update key. */
    wc_lms_write_private_key_cb write_private_key;
    /* Callback to read key. */
    wc_lms_read_private_key_cb  read_private_key;
    /* Context arg passed to callbacks. */
    void*                context;
    /* Dynamic memory hint. */
    void* heap;
#endif /* !WOLFSSL_LMS_VERIFY_ONLY */
    /* Parameters of key. */
    const LmsParams* params;
    /* Current state of key. */
    enum wc_LmsState state;
#ifdef WOLF_CRYPTO_CB
    /* Device Identifier. */
    int devId;
#endif
};

int wc_hss_make_key(LmsState* state, WC_RNG* rng, byte* priv_raw,
    HssPrivKey* priv_key, byte* priv_data, byte* pub);
int wc_hss_reload_key(LmsState* state, const byte* priv_raw,
    HssPrivKey* priv_key, byte* priv_data, byte* pub_root);
int wc_hss_sign(LmsState* state, byte* priv_raw, HssPrivKey* priv_key,
    byte* priv_data, const byte* msg, word32 msgSz, byte* sig);
int wc_hss_sigsleft(const LmsParams* params, const byte* priv_raw);
int wc_hss_verify(LmsState* state, const byte* pub, const byte* msg,
    word32 msgSz, const byte* sig);

#endif /* WOLFSSL_HAVE_LMS && WOLFSSL_WC_LMS */

#endif /* WC_LMS_H */
