/* wc_lms.h
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
    \file wolfssl/wolfcrypt/wc_lms.h
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
 * WOLFSSL_LMS_NO_SIGN_SMOOTHING                        Default: OFF
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

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_HAVE_LMS

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#ifdef WOLFSSL_LMS_SHAKE256
#include <wolfssl/wolfcrypt/sha3.h>
#endif

/* When raw hash access APIs are disabled or unavailable (WOLFSSL_NO_HASH_RAW),
 * fall back to using the full hash API calls. */
#if defined(WOLFSSL_NO_HASH_RAW) && !defined(WC_LMS_FULL_HASH)
    #define WC_LMS_FULL_HASH
#endif

/* Length of the Key ID. */
#define WC_LMS_I_LEN    16

/* Private key write and read callbacks. */
typedef int (*wc_lms_write_private_key_cb)(const byte * priv, word32 privSz, void *context);
typedef int (*wc_lms_read_private_key_cb)(byte * priv, word32 privSz, void *context);

/* Return codes returned by private key callbacks. */
enum wc_LmsRc {
  WC_LMS_RC_NONE,
  WC_LMS_RC_BAD_ARG,            /* Bad arg in read or write callback. */
  WC_LMS_RC_WRITE_FAIL,         /* Write or update private key failed. */
  WC_LMS_RC_READ_FAIL,          /* Read private key failed. */
  WC_LMS_RC_SAVED_TO_NV_MEMORY, /* Wrote private key to nonvolatile storage. */
  WC_LMS_RC_READ_TO_MEMORY      /* Read private key from storage. */
};

/* LMS/HSS signatures are defined by 3 parameters:
 *   levels: number of levels of Merkle trees.
 *   height: height of an individual Merkle tree.
 *   winternitz: number of bits from hash used in a Winternitz chain.
 *
 * The acceptable parameter values are those in RFC8554:
 *   levels = {1..8}
 *   height = {5, 10, 15, 20, 25}
 *   winternitz = {1, 2, 4, 8}
 *
 * The number of available signatures is:
 *   N = 2 ** (levels * height)
 *
 * Signature sizes are determined by levels and winternitz
 * parameters primarily, and height to a lesser extent:
 *   - Larger levels values increase signature size significantly.
 *   - Larger height values increase signature size moderately.
 *   - Larger winternitz values will reduce the signature size, at
 *     the expense of longer key generation and sign/verify times.
 *
 * Key generation time is strongly determined by the height of
 * the first level tree. A 3 level, 5 height tree is much faster
 * than 1 level, 15 height at initial key gen, even if the number
 * of available signatures is the same.
 * */

/* Predefined LMS/HSS parameter sets for convenience.
 *
 * Not predefining many sets with Winternitz=1, because the signatures
 * will be large. */
enum wc_LmsParm {
#ifndef WOLFSSL_NO_LMS_SHA256_256
    WC_LMS_PARM_NONE = 0,
    WC_LMS_PARM_L1_H5_W1 = 1,
    WC_LMS_PARM_L1_H5_W2 = 2,
    WC_LMS_PARM_L1_H5_W4 = 3,
    WC_LMS_PARM_L1_H5_W8 = 4,
    WC_LMS_PARM_L1_H10_W2 = 5,
    WC_LMS_PARM_L1_H10_W4 = 6,
    WC_LMS_PARM_L1_H10_W8 = 7,
    WC_LMS_PARM_L1_H15_W2 = 8,
    WC_LMS_PARM_L1_H15_W4 = 9,
    WC_LMS_PARM_L1_H15_W8 = 10,
    WC_LMS_PARM_L1_H20_W2 = 11,
    WC_LMS_PARM_L1_H20_W4 = 12,
    WC_LMS_PARM_L1_H20_W8 = 13,
    WC_LMS_PARM_L2_H5_W2 = 14,
    WC_LMS_PARM_L2_H5_W4 = 15,
    WC_LMS_PARM_L2_H5_W8 = 16,
    WC_LMS_PARM_L2_H10_W2 = 17,
    WC_LMS_PARM_L2_H10_W4 = 18,
    WC_LMS_PARM_L2_H10_W8 = 19,
    WC_LMS_PARM_L2_H15_W2 = 20,
    WC_LMS_PARM_L2_H15_W4 = 21,
    WC_LMS_PARM_L2_H15_W8 = 22,
    WC_LMS_PARM_L2_H20_W2 = 23,
    WC_LMS_PARM_L2_H20_W4 = 24,
    WC_LMS_PARM_L2_H20_W8 = 25,
    WC_LMS_PARM_L3_H5_W2 = 26,
    WC_LMS_PARM_L3_H5_W4 = 27,
    WC_LMS_PARM_L3_H5_W8 = 28,
    WC_LMS_PARM_L3_H10_W4 = 29,
    WC_LMS_PARM_L3_H10_W8 = 30,
    WC_LMS_PARM_L4_H5_W2 = 31,
    WC_LMS_PARM_L4_H5_W4 = 32,
    WC_LMS_PARM_L4_H5_W8 = 33,
    WC_LMS_PARM_L4_H10_W4 = 34,
    WC_LMS_PARM_L4_H10_W8 = 35,
    /* H25 parameter sets for SHA-256/256 */
    WC_LMS_PARM_L1_H25_W1 = 56,
    WC_LMS_PARM_L1_H25_W2 = 57,
    WC_LMS_PARM_L1_H25_W4 = 58,
    WC_LMS_PARM_L1_H25_W8 = 59,
    /* W1 for non-H5 heights */
    WC_LMS_PARM_L1_H10_W1 = 60,
    WC_LMS_PARM_L1_H15_W1 = 61,
    WC_LMS_PARM_L1_H20_W1 = 62,
#endif

#ifdef WOLFSSL_LMS_SHA256_192
    WC_LMS_PARM_SHA256_192_L1_H5_W1  = 36,
    WC_LMS_PARM_SHA256_192_L1_H5_W2  = 37,
    WC_LMS_PARM_SHA256_192_L1_H5_W4  = 38,
    WC_LMS_PARM_SHA256_192_L1_H5_W8  = 39,
    WC_LMS_PARM_SHA256_192_L1_H10_W2 = 40,
    WC_LMS_PARM_SHA256_192_L1_H10_W4 = 41,
    WC_LMS_PARM_SHA256_192_L1_H10_W8 = 42,
    WC_LMS_PARM_SHA256_192_L1_H15_W2 = 43,
    WC_LMS_PARM_SHA256_192_L1_H15_W4 = 44,
    WC_LMS_PARM_SHA256_192_L1_H20_W2 = 53,
    WC_LMS_PARM_SHA256_192_L1_H20_W4 = 54,
    WC_LMS_PARM_SHA256_192_L1_H20_W8 = 55,
    WC_LMS_PARM_SHA256_192_L2_H10_W2 = 45,
    WC_LMS_PARM_SHA256_192_L2_H10_W4 = 46,
    WC_LMS_PARM_SHA256_192_L2_H10_W8 = 47,
    WC_LMS_PARM_SHA256_192_L3_H5_W2  = 48,
    WC_LMS_PARM_SHA256_192_L3_H5_W4  = 49,
    WC_LMS_PARM_SHA256_192_L3_H5_W8  = 50,
    WC_LMS_PARM_SHA256_192_L3_H10_W4 = 51,
    WC_LMS_PARM_SHA256_192_L4_H5_W8  = 52,
    /* H25 for SHA-256/192 */
    WC_LMS_PARM_SHA256_192_L1_H25_W1 = 63,
    WC_LMS_PARM_SHA256_192_L1_H25_W2 = 64,
    WC_LMS_PARM_SHA256_192_L1_H25_W4 = 65,
    WC_LMS_PARM_SHA256_192_L1_H25_W8 = 66,
    /* W1 for non-H5 heights (SHA-256/192) */
    WC_LMS_PARM_SHA256_192_L1_H10_W1 = 67,
    WC_LMS_PARM_SHA256_192_L1_H15_W1 = 68,
    WC_LMS_PARM_SHA256_192_L1_H20_W1 = 69,
    WC_LMS_PARM_SHA256_192_L1_H15_W8 = 70,
#endif

#ifdef WOLFSSL_LMS_SHAKE256
    /* SHAKE256/256, 32-byte output */
    WC_LMS_PARM_SHAKE_L1_H5_W1  = 100,
    WC_LMS_PARM_SHAKE_L1_H5_W2  = 101,
    WC_LMS_PARM_SHAKE_L1_H5_W4  = 102,
    WC_LMS_PARM_SHAKE_L1_H5_W8  = 103,
    WC_LMS_PARM_SHAKE_L1_H10_W1 = 104,
    WC_LMS_PARM_SHAKE_L1_H10_W2 = 105,
    WC_LMS_PARM_SHAKE_L1_H10_W4 = 106,
    WC_LMS_PARM_SHAKE_L1_H10_W8 = 107,
    WC_LMS_PARM_SHAKE_L1_H15_W1 = 108,
    WC_LMS_PARM_SHAKE_L1_H15_W2 = 109,
    WC_LMS_PARM_SHAKE_L1_H15_W4 = 110,
    WC_LMS_PARM_SHAKE_L1_H15_W8 = 111,
    WC_LMS_PARM_SHAKE_L1_H20_W1 = 112,
    WC_LMS_PARM_SHAKE_L1_H20_W2 = 113,
    WC_LMS_PARM_SHAKE_L1_H20_W4 = 114,
    WC_LMS_PARM_SHAKE_L1_H20_W8 = 115,
    WC_LMS_PARM_SHAKE_L1_H25_W1 = 116,
    WC_LMS_PARM_SHAKE_L1_H25_W2 = 117,
    WC_LMS_PARM_SHAKE_L1_H25_W4 = 118,
    WC_LMS_PARM_SHAKE_L1_H25_W8 = 119,
    /* SHAKE256/192, 24-byte output */
    WC_LMS_PARM_SHAKE192_L1_H5_W1  = 120,
    WC_LMS_PARM_SHAKE192_L1_H5_W2  = 121,
    WC_LMS_PARM_SHAKE192_L1_H5_W4  = 122,
    WC_LMS_PARM_SHAKE192_L1_H5_W8  = 123,
    WC_LMS_PARM_SHAKE192_L1_H10_W1 = 124,
    WC_LMS_PARM_SHAKE192_L1_H10_W2 = 125,
    WC_LMS_PARM_SHAKE192_L1_H10_W4 = 126,
    WC_LMS_PARM_SHAKE192_L1_H10_W8 = 127,
    WC_LMS_PARM_SHAKE192_L1_H15_W1 = 128,
    WC_LMS_PARM_SHAKE192_L1_H15_W2 = 129,
    WC_LMS_PARM_SHAKE192_L1_H15_W4 = 130,
    WC_LMS_PARM_SHAKE192_L1_H15_W8 = 131,
    WC_LMS_PARM_SHAKE192_L1_H20_W1 = 132,
    WC_LMS_PARM_SHAKE192_L1_H20_W2 = 133,
    WC_LMS_PARM_SHAKE192_L1_H20_W4 = 134,
    WC_LMS_PARM_SHAKE192_L1_H20_W8 = 135,
    WC_LMS_PARM_SHAKE192_L1_H25_W1 = 136,
    WC_LMS_PARM_SHAKE192_L1_H25_W2 = 137,
    WC_LMS_PARM_SHAKE192_L1_H25_W4 = 138,
    WC_LMS_PARM_SHAKE192_L1_H25_W8 = 139,
#endif
};

/* enum wc_LmsState is to help track the state of an LMS/HSS Key. */
enum wc_LmsState {
    WC_LMS_STATE_FREED,      /* Key has been freed from memory. */
    WC_LMS_STATE_INITED,     /* Key has been inited, ready to set params.*/
    WC_LMS_STATE_PARMSET,    /* Params are set, ready to MakeKey or Reload. */
    WC_LMS_STATE_OK,         /* Able to sign signatures and verify. */
    WC_LMS_STATE_VERIFYONLY, /* A public only LmsKey. */
    WC_LMS_STATE_BAD,        /* Can't guarantee key's state. */
    WC_LMS_STATE_NOSIGS      /* Signatures exhausted. */
};

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
    #define LMS_MAX_HEIGHT          25
#endif
#if (LMS_MAX_HEIGHT < 5) || (LMS_MAX_HEIGHT > 25)
    #error "LMS parameters only support heights 5-25."
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

/* Size of digest output when truncatint SHA-256 to 192 bits. */
#define WC_SHA256_192_DIGEST_SIZE   24

/* Maximum size of a node hash. */
#define LMS_MAX_NODE_LEN            WC_SHA256_DIGEST_SIZE
/* Maximum size of SEED (produced by hash). */
#define LMS_SEED_LEN                WC_SHA256_DIGEST_SIZE
/* Maximum number of P, number of n-byte string elements in LM-OTS signature.
 * Value of P when N=32 and W=1.
 */
#define LMS_MAX_P                   265


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
#define LMS_PRIV_LEN(hLen)          \
    (LMS_Q_LEN + (hLen) + LMS_I_LEN)
/* Public key length in signature. */
#define LMS_PUBKEY_LEN(hLen)        \
    (LMS_TYPE_LEN + LMS_TYPE_LEN + LMS_I_LEN + (hLen))

/* LMS signature data length. */
#define LMS_SIG_LEN(h, p, hLen)                                                \
    (LMS_Q_LEN + LMS_TYPE_LEN + (hLen) + (p) * (hLen) + LMS_TYPE_LEN +         \
     (h) * (hLen))

/* Length of public key. */
#define HSS_PUBLIC_KEY_LEN(hLen)        (LMS_L_LEN + LMS_PUBKEY_LEN(hLen))
/* Length of private key. */
#define HSS_PRIVATE_KEY_LEN(hLen)   \
    (HSS_Q_LEN + HSS_PRIV_KEY_PARAM_SET_LEN + (hLen) + LMS_I_LEN)
/* Maximum public key length - length is constant for all parameters. */
#define HSS_MAX_PRIVATE_KEY_LEN     HSS_PRIVATE_KEY_LEN(LMS_MAX_NODE_LEN)
/* Maximum private key length - length is constant for all parameters. */
#define HSS_MAX_PUBLIC_KEY_LEN      HSS_PUBLIC_KEY_LEN(LMS_MAX_NODE_LEN)
/* Maximum signature length. */
#define HSS_MAX_SIG_LEN                                                        \
    (LMS_TYPE_LEN +                                                            \
     LMS_MAX_LEVELS * (LMS_Q_LEN + LMS_TYPE_LEN + LMS_TYPE_LEN +               \
                       LMS_MAX_NODE_LEN * (1 + LMS_MAX_P + LMS_MAX_HEIGHT)) +  \
     (LMS_MAX_LEVELS - 1) * LMS_PUBKEY_LEN(LMS_MAX_NODE_LEN))

/* Maximum buffer length required for use when hashing. */
#define LMS_MAX_BUFFER_LEN          \
    (LMS_I_LEN + LMS_Q_LEN + LMS_P_LEN + LMS_W_LEN + 2 * LMS_MAX_NODE_LEN)


/* Private key data length.
 *
 * HSSPrivKey.priv
 */
#define LMS_PRIV_KEY_LEN(l, hLen)           \
    ((l) * LMS_PRIV_LEN(hLen))

/* Stack of nodes. */
#define LMS_STACK_CACHE_LEN(h, hLen)        \
     (((h) + 1) * (hLen))

/* Root cache length. */
#define LMS_ROOT_CACHE_LEN(rl, hLen)        \
    (((1 << (rl)) - 1) * (hLen))

/* Leaf cache length. */
#define LMS_LEAF_CACHE_LEN(cb, hLen)        \
    ((1 << (cb)) * (hLen))

/* Length of LMS private key state.
 *
 * LmsPrivState
 *   auth_path +
 *   root +
 *   stack.stack + stack.offset +
 *   cache.leaf + cache.index + cache.offset
 */
#define LMS_PRIV_STATE_LEN(h, rl, cb, hLen)     \
    (((h) * (hLen)) +                           \
     LMS_STACK_CACHE_LEN(h, hLen) + 4 +         \
     LMS_ROOT_CACHE_LEN(rl, hLen) +             \
     LMS_LEAF_CACHE_LEN(cb, hLen) + 4 + 4)

#ifndef WOLFSSL_WC_LMS_SMALL
    /* Private key data state for all levels. */
    #define LMS_PRIV_STATE_ALL_LEN(l, h, rl, cb, hLen)  \
         ((l) * LMS_PRIV_STATE_LEN(h, rl, cb, hLen))
#else
    /* Private key data state for all levels. */
    #define LMS_PRIV_STATE_ALL_LEN(l, h, rl, cb, hLen)  0
#endif

#ifndef WOLFSSL_LMS_NO_SIGN_SMOOTHING
    /* Extra private key data for smoothing. */
    #define LMS_PRIV_SMOOTH_LEN(l, h, rl, cb, hLen)         \
        (LMS_PRIV_KEY_LEN(l, hLen) +                        \
         ((l) - 1) * LMS_PRIV_STATE_LEN(h, rl, cb, hLen))
#else
    /* Extra private key data for smoothing. */
    #define LMS_PRIV_SMOOTH_LEN(l, h, rl, cb, hLen)     0
#endif

#ifndef WOLFSSL_LMS_NO_SIG_CACHE
    #define LMS_PRIV_Y_TREE_LEN(p, hLen)                            \
        ((hLen) + (p) * (hLen))
    /* Length of the y data cached in private key data. */
    #define LMS_PRIV_Y_LEN(l, p, hLen)                              \
        (((l) - 1) * ((hLen) + (p) * (hLen)))
#else
    /* Length of the y data cached in private key data. */
    #define LMS_PRIV_Y_LEN(l, p, hLen)      0
#endif

#ifndef WOLFSSL_WC_LMS_SMALL
/* Length of private key data. */
#define LMS_PRIV_DATA_LEN(l, h, p, rl, cb, hLen)    \
    (LMS_PRIV_KEY_LEN(l, hLen) +                    \
     LMS_PRIV_STATE_ALL_LEN(l, h, rl, cb, hLen) +   \
     LMS_PRIV_SMOOTH_LEN(l, h, rl, cb, hLen) +      \
     LMS_PRIV_Y_LEN(l, p, hLen))
#else
#define LMS_PRIV_DATA_LEN(l, h, p, rl, cb, hLen)    \
    LMS_PRIV_KEY_LEN(l, hLen)
#endif

/* Indicates using SHA-256 for hashing. */
#define LMS_SHA256                  0x0000
/* Indicates using SHA-256/192 for hashing. */
#define LMS_SHA256_192              0x1000
/* Indicates using SHAKE256/256 for hashing. */
#define LMS_SHAKE256                0x2000
/* Indicates using SHAKE256/192 for hashing. */
#define LMS_SHAKE256_192            0x3000
/* Mask to get hashing algorithm from type. */
#define LMS_HASH_MASK               0xf000
/* Mask to get height or Winternitz width from type. */
#define LMS_H_W_MASK                0x0fff
/* Bit test: non-zero if type uses SHAKE256. */
#define LMS_IS_SHAKE(type)          (((type) & 0x2000) != 0)

/* LMS Parameters. */
/* SHA-256 hash, 32-bytes of hash used, tree height of 5. */
#define LMS_SHA256_M32_H5           0x05
/* SHA-256 hash, 32-bytes of hash used, tree height of 10. */
#define LMS_SHA256_M32_H10          0x06
/* SHA-256 hash, 32-bytes of hash used, tree height of 15. */
#define LMS_SHA256_M32_H15          0x07
/* SHA-256 hash, 32-bytes of hash used, tree height of 20. */
#define LMS_SHA256_M32_H20          0x08
/* SHA-256 hash, 32-bytes of hash used, tree height of 25. */
#define LMS_SHA256_M32_H25          0x09

/* SHA-256 hash, 32-bytes of hash used, Winternitz width of 1 bit. */
#define LMOTS_SHA256_N32_W1         0x01
/* SHA-256 hash, 32-bytes of hash used, Winternitz width of 2 bits. */
#define LMOTS_SHA256_N32_W2         0x02
/* SHA-256 hash, 32-bytes of hash used, Winternitz width of 4 bits. */
#define LMOTS_SHA256_N32_W4         0x03
/* SHA-256 hash, 32-bytes of hash used, Winternitz width of 8 bits. */
#define LMOTS_SHA256_N32_W8         0x04

/* SHA-256 hash, 32-bytes of hash used, tree height of 5. */
#define LMS_SHA256_M24_H5           (0x0a | LMS_SHA256_192)
/* SHA-256 hash, 32-bytes of hash used, tree height of 10. */
#define LMS_SHA256_M24_H10          (0x0b | LMS_SHA256_192)
/* SHA-256 hash, 32-bytes of hash used, tree height of 15. */
#define LMS_SHA256_M24_H15          (0x0c | LMS_SHA256_192)
/* SHA-256 hash, 32-bytes of hash used, tree height of 20. */
#define LMS_SHA256_M24_H20          (0x0d | LMS_SHA256_192)
/* SHA-256 hash, 32-bytes of hash used, tree height of 25. */
#define LMS_SHA256_M24_H25          (0x0e | LMS_SHA256_192)

/* SHA-256 hash, 24-bytes of hash used, Winternitz width of 1 bit. */
#define LMOTS_SHA256_N24_W1         (0x05 | LMS_SHA256_192)
/* SHA-256 hash, 24-bytes of hash used, Winternitz width of 2 bits. */
#define LMOTS_SHA256_N24_W2         (0x06 | LMS_SHA256_192)
/* SHA-256 hash, 24-bytes of hash used, Winternitz width of 4 bits. */
#define LMOTS_SHA256_N24_W4         (0x07 | LMS_SHA256_192)
/* SHA-256 hash, 24-bytes of hash used, Winternitz width of 8 bits. */
#define LMOTS_SHA256_N24_W8         (0x08 | LMS_SHA256_192)

/* SHAKE256 hash, 32-bytes of hash used, tree height of 5. */
#define LMS_SHAKE_M32_H5            (0x0f | LMS_SHAKE256)
/* SHAKE256 hash, 32-bytes of hash used, tree height of 10. */
#define LMS_SHAKE_M32_H10           (0x10 | LMS_SHAKE256)
/* SHAKE256 hash, 32-bytes of hash used, tree height of 15. */
#define LMS_SHAKE_M32_H15           (0x11 | LMS_SHAKE256)
/* SHAKE256 hash, 32-bytes of hash used, tree height of 20. */
#define LMS_SHAKE_M32_H20           (0x12 | LMS_SHAKE256)
/* SHAKE256 hash, 32-bytes of hash used, tree height of 25. */
#define LMS_SHAKE_M32_H25           (0x13 | LMS_SHAKE256)

/* SHAKE256 hash, 32-bytes of hash used, Winternitz width of 1 bit. */
#define LMOTS_SHAKE_N32_W1          (0x09 | LMS_SHAKE256)
/* SHAKE256 hash, 32-bytes of hash used, Winternitz width of 2 bits. */
#define LMOTS_SHAKE_N32_W2          (0x0a | LMS_SHAKE256)
/* SHAKE256 hash, 32-bytes of hash used, Winternitz width of 4 bits. */
#define LMOTS_SHAKE_N32_W4          (0x0b | LMS_SHAKE256)
/* SHAKE256 hash, 32-bytes of hash used, Winternitz width of 8 bits. */
#define LMOTS_SHAKE_N32_W8          (0x0c | LMS_SHAKE256)

/* SHAKE256 hash, 24-bytes of hash used, tree height of 5. */
#define LMS_SHAKE_M24_H5            (0x14 | LMS_SHAKE256_192)
/* SHAKE256 hash, 24-bytes of hash used, tree height of 10. */
#define LMS_SHAKE_M24_H10           (0x15 | LMS_SHAKE256_192)
/* SHAKE256 hash, 24-bytes of hash used, tree height of 15. */
#define LMS_SHAKE_M24_H15           (0x16 | LMS_SHAKE256_192)
/* SHAKE256 hash, 24-bytes of hash used, tree height of 20. */
#define LMS_SHAKE_M24_H20           (0x17 | LMS_SHAKE256_192)
/* SHAKE256 hash, 24-bytes of hash used, tree height of 25. */
#define LMS_SHAKE_M24_H25           (0x18 | LMS_SHAKE256_192)

/* SHAKE256 hash, 24-bytes of hash used, Winternitz width of 1 bit. */
#define LMOTS_SHAKE_N24_W1          (0x0d | LMS_SHAKE256_192)
/* SHAKE256 hash, 24-bytes of hash used, Winternitz width of 2 bits. */
#define LMOTS_SHAKE_N24_W2          (0x0e | LMS_SHAKE256_192)
/* SHAKE256 hash, 24-bytes of hash used, Winternitz width of 4 bits. */
#define LMOTS_SHAKE_N24_W4          (0x0f | LMS_SHAKE256_192)
/* SHAKE256 hash, 24-bytes of hash used, Winternitz width of 8 bits. */
#define LMOTS_SHAKE_N24_W8          (0x10 | LMS_SHAKE256_192)

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
    /* Length of seed. */
    word16 hash_len;
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
#ifdef WOLFSSL_NAMES_STATIC
    const char str[32]; /* large enough for largest string in wc_lms_map[] */
#else
    const char* str;
#endif
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
#ifdef WOLFSSL_LMS_SHAKE256
    /* The LMS instance uses exactly one hash family at a time, selected at
     * init time by params->lmOtsType (see wc_lms.c LMS_IS_SHAKE dispatch).
     * The two contexts are unionized to shrink LmsState; access via the
     * LMS_STATE_HASH / LMS_STATE_SHAKE macros below. Anonymous unions
     * would avoid the macros but require C11 (HAVE_ANONYMOUS_INLINE_AGGREGATES)
     * gating that ends up uglier than the named form here. */
    union {
        wc_Sha256 sha256;
        wc_Shake  shake;
    } hash;
    union {
        wc_Sha256 sha256;
        wc_Shake  shake;
    } hash_k;
#else
    /* Hash algorithm (SHA-256). */
    wc_Sha256 hash;
    /* Hash algorithm for calculating K (SHA-256). */
    wc_Sha256 hash_k;
#endif
} LmsState;

/* Access macros for the LmsState hash contexts. All call sites use the
 * address-of form, so the macros yield pointers directly. In the
 * SHAKE-disabled build the SHAKE macros are intentionally undefined --
 * the only callers are themselves under #ifdef WOLFSSL_LMS_SHAKE256. */
#ifdef WOLFSSL_LMS_SHAKE256
    #define LMS_STATE_HASH(state)    (&(state)->hash.sha256)
    #define LMS_STATE_HASH_K(state)  (&(state)->hash_k.sha256)
    #define LMS_STATE_SHAKE(state)   (&(state)->hash.shake)
    #define LMS_STATE_SHAKE_K(state) (&(state)->hash_k.shake)
#else
    #define LMS_STATE_HASH(state)    (&(state)->hash)
    #define LMS_STATE_HASH_K(state)  (&(state)->hash_k)
#endif

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

typedef struct LmsKey {
    /* Public key. */
    ALIGN16 byte pub[HSS_PUBLIC_KEY_LEN(LMS_MAX_NODE_LEN)];
#ifndef WOLFSSL_LMS_VERIFY_ONLY
    /* Encoded private key. */
    ALIGN16 byte priv_raw[HSS_MAX_PRIVATE_KEY_LEN];

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
} LmsKey;

#ifdef __cplusplus
    extern "C" {
#endif

WOLFSSL_API int  wc_LmsKey_Init(LmsKey * key, void * heap, int devId);
WOLFSSL_API int  wc_LmsKey_SetLmsParm(LmsKey * key, enum wc_LmsParm lmsParm);
WOLFSSL_API int  wc_LmsKey_SetParameters(LmsKey * key, int levels,
    int height, int winternitz);
WOLFSSL_API int  wc_LmsKey_GetParameters(const LmsKey * key, int * levels,
    int * height, int * winternitz);
#ifndef WOLFSSL_LMS_VERIFY_ONLY
WOLFSSL_API int  wc_LmsKey_SetWriteCb(LmsKey * key,
    wc_lms_write_private_key_cb write_cb);
WOLFSSL_API int  wc_LmsKey_SetReadCb(LmsKey * key,
    wc_lms_read_private_key_cb read_cb);
WOLFSSL_API int  wc_LmsKey_SetContext(LmsKey * key, void * context);
WOLFSSL_API int  wc_LmsKey_MakeKey(LmsKey * key, WC_RNG * rng);
WOLFSSL_API int  wc_LmsKey_Reload(LmsKey * key);
WOLFSSL_API int  wc_LmsKey_GetPrivLen(const LmsKey * key, word32 * len);
WOLFSSL_API int  wc_LmsKey_Sign(LmsKey * key, byte * sig, word32 * sigSz,
    const byte * msg, int msgSz);
WOLFSSL_API int  wc_LmsKey_SigsLeft(LmsKey * key);
#endif /* ifndef WOLFSSL_LMS_VERIFY_ONLY */
WOLFSSL_API void wc_LmsKey_Free(LmsKey * key);
WOLFSSL_API int  wc_LmsKey_GetSigLen(const LmsKey * key, word32 * len);
WOLFSSL_API int  wc_LmsKey_GetPubLen(const LmsKey * key, word32 * len);
WOLFSSL_API int  wc_LmsKey_ExportPub(LmsKey * keyDst, const LmsKey * keySrc);
WOLFSSL_API int  wc_LmsKey_ExportPubRaw(const LmsKey * key, byte * out,
    word32 * outLen);
WOLFSSL_API int  wc_LmsKey_ImportPubRaw(LmsKey * key, const byte * in,
    word32 inLen);
WOLFSSL_API int  wc_LmsKey_Verify(LmsKey * key, const byte * sig, word32 sigSz,
    const byte * msg, int msgSz);
WOLFSSL_API const char * wc_LmsKey_ParmToStr(enum wc_LmsParm lmsParm);
WOLFSSL_API const char * wc_LmsKey_RcToStr(enum wc_LmsRc lmsRc);

WOLFSSL_API int wc_LmsKey_GetKid(LmsKey * key, const byte ** kid,
    word32* kidSz);
WOLFSSL_API const byte * wc_LmsKey_GetKidFromPrivRaw(const byte * priv,
    word32 privSz);

int wc_hss_make_key(LmsState* state, WC_RNG* rng, byte* priv_raw,
    HssPrivKey* priv_key, byte* priv_data, byte* pub);
int wc_hss_reload_key(LmsState* state, const byte* priv_raw,
    HssPrivKey* priv_key, byte* priv_data, byte* pub_root);
int wc_hss_sign(LmsState* state, byte* priv_raw, HssPrivKey* priv_key,
    byte* priv_data, const byte* msg, word32 msgSz, byte* sig);
int wc_hss_sigsleft(const LmsParams* params, const byte* priv_raw);
WOLFSSL_API
int wc_hss_verify(LmsState* state, const byte* pub, const byte* msg,
    word32 msgSz, const byte* sig, word32 sigSz);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* WOLFSSL_HAVE_LMS */

#endif /* WC_LMS_H */
