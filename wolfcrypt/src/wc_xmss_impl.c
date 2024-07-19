/* wc_xmss_impl.c
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

/* Based on:
 *  o RFC 8391 - XMSS: eXtended Merkle Signature Scheme
 *  o [HDSS] "Hash-based Digital Signature Schemes", Buchmann, Dahmen and Szydlo
 *    from "Post Quantum Cryptography", Springer 2009.
 *  o [OPX] "Optimal Parameters for XMSS^MT", Hulsing, Rausch and Buchmann
 *
 * TODO: "Simple and Memory-efficient Signature Generation of XMSS^MT"
 *       (https://ece.engr.uvic.ca/~raltawy/SAC2021/9.pdf)
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#include <wolfssl/wolfcrypt/wc_xmss.h>
#include <wolfssl/wolfcrypt/hash.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#if defined(WOLFSSL_HAVE_XMSS)

/* Indices into Hash Address. */
#define XMSS_ADDR_LAYER                 0
#define XMSS_ADDR_TREE_HI               1
#define XMSS_ADDR_TREE                  2
#define XMSS_ADDR_TYPE                  3
#define XMSS_ADDR_OTS                   4
#define XMSS_ADDR_LTREE                 4
#define XMSS_ADDR_TREE_ZERO             4
#define XMSS_ADDR_CHAIN                 5
#define XMSS_ADDR_TREE_HEIGHT           5
#define XMSS_ADDR_HASH                  6
#define XMSS_ADDR_TREE_INDEX            6
#define XMSS_ADDR_KEY_MASK              7

/* Types of hash addresses. */
#define WC_XMSS_ADDR_TYPE_OTS        0
#define WC_XMSS_ADDR_TYPE_LTREE      1
#define WC_XMSS_ADDR_TYPE_TREE       2

/* Byte to include in hash to create unique sequence. */
#define XMSS_HASH_PADDING_F             0
#define XMSS_HASH_PADDING_H             1
#define XMSS_HASH_PADDING_HASH          2
#define XMSS_HASH_PADDING_PRF           3
#define XMSS_HASH_PADDING_PRF_KEYGEN    4

/* Fixed parameter values. */
#define XMSS_WOTS_W                     16
#define XMSS_WOTS_LOG_W                 4
#define XMSS_WOTS_LEN2                  3
#define XMSS_CSUM_SHIFT                 4
#define XMSS_CSUM_LEN                   2

/* Length of the message to the PRF. */
#define XMSS_PRF_M_LEN                  32

/* Length of index encoding when doing XMSS. */
#define XMSS_IDX_LEN                    4

/* Size of the N when using SHA-256 and 32 byte padding. */
#define XMSS_SHA256_32_N                WC_SHA256_DIGEST_SIZE
/* Size of the padding when using SHA-256 and 32 byte padding. */
#define XMSS_SHA256_32_PAD_LEN          32

/* Calculate PRF data length for parameters. */
#define XMSS_HASH_PRF_DATA_LEN(params)                              \
    ((params)->pad_len + (params)->n + WC_XMSS_ADDR_LEN)
/* PRF data length when using SHA-256 with 32 byte padding. */
#define XMSS_HASH_PRF_DATA_LEN_SHA256_32                            \
    (XMSS_SHA256_32_PAD_LEN + XMSS_SHA256_32_N + WC_XMSS_ADDR_LEN)

/* Calculate chain hash data length for parameters. */
#define XMSS_CHAIN_HASH_DATA_LEN(params)                            \
    ((params)->pad_len + 2 * (params)->n)
/* Chain hash data length when using SHA-256 with 32 byte padding. */
#define XMSS_CHAIN_HASH_DATA_LEN_SHA256_32                          \
    (XMSS_SHA256_32_PAD_LEN + 2 * XMSS_SHA256_32_N)

/* Calculate rand hash data length for parameters. */
#define XMSS_RAND_HASH_DATA_LEN(params)                             \
    ((params)->pad_len + 3 * (params)->n)
/* Rand hash data length when using SHA-256 with 32 byte padding. */
#define XMSS_RAND_HASH_DATA_LEN_SHA256_32                           \
    (XMSS_SHA256_32_PAD_LEN + 3 * XMSS_SHA256_32_N)

/* Encode pad value into byte array. Front fill with 0s.
 *
 * RFC 8391: 2.4
 *
 * @param [in]  n   Number to encode.
 * @param [out] a   Array to hold encoding.
 * @param [in]  l   Length of array.
 */
#define XMSS_PAD_ENC(n, a, l)   \
do {                            \
    XMEMSET(a, 0, l);           \
    (a)[(l) - 1] = (n);         \
} while (0)


/********************************************
 * Index 32/64 bits
 ********************************************/

/* Index of 32 or 64 bits. */
typedef union wc_Idx {
#if WOLFSSL_XMSS_MAX_HEIGHT > 32
    /* 64-bit representation. */
    w64wrapper u64;
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 32
    /* 32-bit representation. */
    word32     u32;
#endif
} wc_Idx;

#if WOLFSSL_XMSS_MAX_HEIGHT > 32
/* Set index to zero.
 *
 * Index is up to 64-bits.
 *
 * @param [out] idx  32/64-bit index to zero.
 */
#define WC_IDX_ZERO(idx)    w64Zero(&(idx).u64)
#else
/* Set index to zero.
 *
 * Index is no more than 32-bits.
 *
 * @param [out] idx  32/64-bit index to zero.
 */
#define WC_IDX_ZERO(idx)    idx.u32 = 0
#endif

#if WOLFSSL_XMSS_MAX_HEIGHT > 32
/* Decode 64-bit index.
 *
 * @param [out] i    Index from encoding.
 * @param [in]  c    Count of bytes to decode to index.
 * @param [in]  a    Array to decode from.
 * @param [out] ret  Return value.
 */
#define IDX64_DECODE(i, c, a, ret)                      \
    if ((c) == 5) {                                     \
        word32 t;                                       \
        ato32((a) + 1, &t);                             \
        (i) = w64From32((a)[0], t);                     \
    }                                                   \
    else if ((c) == 8) {                                \
        ato64(a, &(i));                                 \
    }

/* Decode 64-bit index.
 *
 * @param [out] i    Index from encoding.
 * @param [in]  c    Count of bytes to decode to index.
 * @param [in]  a    Array to decode from.
 * @param [out] ret  Return value.
 */
#define XMSS_IDX64_DECODE(i, c, a, ret)                 \
do {                                                    \
    IDX64_DECODE(i, c, a, ret)                          \
    else {                                              \
        (ret) = NOT_COMPILED_IN;                        \
    }                                                   \
} while (0)

/* Check whether index is valid.
 *
 * @param [in] i  Index to check.
 * @param [in] c  Count of bytes i was encoded in.
 * @param [in] h  Full tree Height.
 */
#define IDX64_INVALID(i, c, h)                              \
    ((w64GetHigh32(w64Add32(i, 1, NULL)) >> ((h) - 32)) != 0)

/* Set 64-bit index as hash address value for tree.
 *
 * @param [in]  i  Index to set.
 * @param [in]  c  Count of bytes to encode into.
 * @param [in]  h  Height of tree.
 * @param [out] a  Hash address to encode into.
 * @param [out] l  Index of leaf.
 */
#define IDX64_SET_ADDR_TREE(i, c, h, a, l)              \
    if ((c) > 4) {                                      \
        (l) = w64GetLow32(i) & (((word32)1 << (h)) - 1);\
        (i) = w64ShiftRight(i, h);                      \
        (a)[XMSS_ADDR_TREE_HI] = w64GetHigh32(i);       \
        (a)[XMSS_ADDR_TREE] = w64GetLow32(i);           \
    }
#endif /* WOLFSSL_XMSS_MAX_HEIGHT > 32 */

#if WOLFSSL_XMSS_MIN_HEIGHT <= 32
/* Decode 32-bit index.
 *
 * @param [out] i    Index from encoding.
 * @param [in]  c    Count of bytes to decode to index.
 * @param [in]  a    Array to decode from.
 * @param [out] ret  Return value.
 */
#define IDX32_DECODE(i, c, a, ret)                      \
    if ((c) == 4) {                                     \
        ato32(a, &(i));                                 \
    }                                                   \
    else if ((c) == 3) {                                \
        ato24(a, &(i));                                 \
    }

/* Decode 32-bit index.
 *
 * @param [out] i    Index from encoding.
 * @param [in]  c    Count of bytes to decode to index.
 * @param [in]  a    Array to decode from.
 * @param [out] ret  Return value.
 */
#define XMSS_IDX32_DECODE(i, c, a, ret)                 \
do {                                                    \
    IDX32_DECODE(i, c, a, ret)                          \
    else {                                              \
        (ret) = NOT_COMPILED_IN;                        \
    }                                                   \
} while (0)

/* Check whether 32-bit index is valid.
 *
 * @param [in] i  Index to check.
 * @param [in] c  Count of bytes i was encoded in.
 * @param [in] h  Full tree Height.
 */
#define IDX32_INVALID(i, c, h)                          \
    ((((i) + 1) >> (h)) != 0)

/* Set 32-bit index as hash address value for tree.
 *
 * @param [in]  i  Index to set.
 * @param [in]  c  Count of bytes to encode into.
 * @param [in]  h  Height of tree.
 * @param [out] a  Hash address to encode into.
 * @param [out] l  Index of leaf.
 */
#define IDX32_SET_ADDR_TREE(i, c, h, a, l)              \
    if ((c) <= 4) {                                     \
        (l) = ((i) & ((1 << (h)) - 1));                 \
        (i) >>= params->sub_h;                          \
        (a)[XMSS_ADDR_TREE] = (i);                      \
    }

#endif /* WOLFSSL_XMSS_MIN_HEIGHT <= 32 */

#if (WOLFSSL_XMSS_MAX_HEIGHT > 32) && (WOLFSSL_XMSS_MIN_HEIGHT <= 32)

/* Decode 32/64-bit index.
 *
 * @param [out] idx  Index from encoding.
 * @param [in]  c    Count of bytes to decode to index.
 * @param [in]  a    Array to decode from.
 * @param [out] ret  Return value.
 */
#define WC_IDX_DECODE(idx, c, a, ret)                   \
do {                                                    \
    IDX64_DECODE((idx).u64, c, a, ret)                  \
    else                                                \
    IDX32_DECODE((idx).u32, c, a, ret)                  \
    else {                                              \
        (ret) = NOT_COMPILED_IN;                        \
    }                                                   \
} while (0)

/* Check whether index is valid.
 *
 * @param [in] i  Index to check.
 * @param [in] c  Count of bytes i was encoded in.
 * @param [in] h  Full tree Height.
 */
#define WC_IDX_INVALID(i, c, h)                         \
    ((((c) >  4) && IDX64_INVALID((i).u64, c, h)) ||    \
     (((c) <= 4) && IDX32_INVALID((i).u32, c, h)))

/* Set 32/64-bit index as hash address value for tree.
 *
 * @param [in]  i  Index to set.
 * @param [in]  c  Count of bytes to encode into.
 * @param [in]  h  Height of tree.
 * @param [out] a  Hash address to encode into.
 * @param [out] l  Index of leaf.
 */
#define WC_IDX_SET_ADDR_TREE(idx, c, h, a, l)           \
do {                                                    \
    IDX64_SET_ADDR_TREE((idx).u64, c, h, a, l)          \
    else                                                \
    IDX32_SET_ADDR_TREE((idx).u32, c, h, a, l)          \
} while (0)

#elif WOLFSSL_XMSS_MAX_HEIGHT > 32

/* Decode 64-bit index.
 *
 * @param [out] idx  Index from encoding.
 * @param [in]  c    Count of bytes to decode to index.
 * @param [in]  a    Array to decode from.
 * @param [out] ret  Return value.
 */
#define WC_IDX_DECODE(idx, c, a, ret)                   \
do {                                                    \
    IDX64_DECODE((idx).u64, c, a, ret)                  \
} while (0)

/* Check whether index is valid.
 *
 * @param [in] i  Index to check.
 * @param [in] c  Count of bytes i was encoded in.
 * @param [in] h  Full tree Height.
 */
#define WC_IDX_INVALID(i, c, h)                         \
    IDX64_INVALID((i).u64, c, h)

/* Set 64-bit index as hash address value for tree.
 *
 * @param [in]  i  Index to set.
 * @param [in]  c  Count of bytes to encode into.
 * @param [in]  h  Height of tree.
 * @param [out] a  Hash address to encode into.
 * @param [out] l  Index of leaf.
 */
#define WC_IDX_SET_ADDR_TREE(idx, c, h, a, l)           \
do {                                                    \
    IDX64_SET_ADDR_TREE((idx).u64, c, h, a, l)          \
} while (0)

#else

/* Decode 32-bit index.
 *
 * @param [out] idx  Index from encoding.
 * @param [in]  c    Count of bytes to decode to index.
 * @param [in]  a    Array to decode from.
 * @param [out] ret  Return value.
 */
#define WC_IDX_DECODE(idx, c, a, ret)                   \
do {                                                    \
    IDX32_DECODE((idx).u32, c, a, ret)                  \
    else {                                              \
        (ret) = NOT_COMPILED_IN;                        \
    }                                                   \
} while (0)

/* Check whether index is valid.
 *
 * @param [in] i  Index to check.
 * @param [in] c  Count of bytes i was encoded in.
 * @param [in] h  Full tree Height.
 */
#define WC_IDX_INVALID(i, c, h)                         \
    IDX32_INVALID((i).u32, c, h)

/* Set 32-bit index as hash address value for tree.
 *
 * @param [in]  i  Index to set.
 * @param [in]  c  Count of bytes to encode into.
 * @param [in]  h  Height of tree.
 * @param [out] a  Hash address to encode into.
 * @param [out] l  Index of leaf.
 */
#define WC_IDX_SET_ADDR_TREE(idx, c, h, a, l)           \
do {                                                    \
    IDX32_SET_ADDR_TREE(idx.u32, c, h, a, l)            \
} while (0)

#endif /* (WOLFSSL_XMSS_MAX_HEIGHT > 32) && (WOLFSSL_XMSS_MIN_HEIGHT <= 32) */

#ifndef WOLFSSL_XMSS_VERIFY_ONLY
/* Update index by adding one to big-endian encoded value.
 *
 * @param [in, out] a  Array index is encoded in.
 * @param [in]      l  Length of encoded index.
 */
static void wc_idx_update(unsigned char* a, word8 l)
{
    sword8 i;

    for (i = l - 1; i >= 0; i--) {
        if ((++a[i]) != 0) {
            break;
        }
    }
}

/* Copy index from source buffer to destination buffer.
 *
 * Index is put into the front of the destination buffer with the length of the
 * source.
 *
 * @param [in]      s   Source buffer.
 * @param [in]      sl  Length of index in source.
 * @param [in, out] d   Destination buffer.
 * @param [in]      dl  Length of destination buffer.
 */
static void wc_idx_copy(const unsigned char* s, word8 sl, unsigned char* d,
    word8 dl)
{
    XMEMCPY(d, s, sl);
    XMEMSET(d + sl, 0, dl - sl);
}
#endif

/********************************************
 * Hash Address.
 ********************************************/

/* Set the hash address based on subtree.
 *
 * @param [out] a  Hash address.
 * @param [in]  s  Subtree hash address.
 * @param [in]  t  Type of hash address.
 */
#define XMSS_ADDR_SET_SUBTREE(a, s, t)                \
do {                                                  \
    (a)[XMSS_ADDR_LAYER]   = (s)[XMSS_ADDR_LAYER];    \
    (a)[XMSS_ADDR_TREE_HI] = (s)[XMSS_ADDR_TREE_HI];  \
    (a)[XMSS_ADDR_TREE]    = (s)[XMSS_ADDR_TREE];     \
    (a)[XMSS_ADDR_TYPE]    = (t);                     \
    XMEMSET((a) + 4, 0, sizeof(a) - 4 * sizeof(*(a)));\
} while (0)

/* Set the OTS hash address based on subtree.
 *
 * @param [out] a  Hash address.
 * @param [in]  s  Subtree hash address.
 */
#define XMSS_ADDR_OTS_SET_SUBTREE(a, s) \
    XMSS_ADDR_SET_SUBTREE(a, s, WC_XMSS_ADDR_TYPE_OTS)
/* Set the L-tree address based on subtree.
 *
 * @param [out] a  Hash address.
 * @param [in]  s  Subtree hash address.
 */
#define XMSS_ADDR_LTREE_SET_SUBTREE(a, s) \
    XMSS_ADDR_SET_SUBTREE(a, s, WC_XMSS_ADDR_TYPE_LTREE)
/* Set the hash tree address based on subtree.
 *
 * @param [out] a  Hash address.
 * @param [in]  s  Subtree hash address.
 */
#define XMSS_ADDR_TREE_SET_SUBTREE(a, s) \
    XMSS_ADDR_SET_SUBTREE(a, s, WC_XMSS_ADDR_TYPE_TREE)

#ifdef LITTLE_ENDIAN_ORDER

/* Set a byte value into a word of an encoded address.
 *
 * @param [in, out] a  Encoded hash address.
 * @param [in]      i  Index of word.
 * @param [in]      b  Byte to set.
 */
#define XMSS_ADDR_SET_BYTE(a, i, b)     \
    ((word32*)(a))[i] = (word32)(b) << 24

#else

/* Set a byte value into a word of an encoded address.
 *
 * @param [in, out] a  Encoded hash address.
 * @param [in]      i  Index of word.
 * @param [in]      b  Byte to set.
 */
#define XMSS_ADDR_SET_BYTE(a, i, b)     \
    ((word32*)(a))[i] = (b)

#endif /* LITTLE_ENDIAN_ORDER */

/* Convert hash address to bytes.
 *
 * @param [out] bytes  Array to encode into.
 * @param [in]  addr   Hash address.
 */
static void wc_xmss_addr_encode(const HashAddress addr, byte* bytes)
{
    c32toa((addr)[0], (bytes) + (0 * 4));
    c32toa((addr)[1], (bytes) + (1 * 4));
    c32toa((addr)[2], (bytes) + (2 * 4));
    c32toa((addr)[3], (bytes) + (3 * 4));
    c32toa((addr)[4], (bytes) + (4 * 4));
    c32toa((addr)[5], (bytes) + (5 * 4));
    c32toa((addr)[6], (bytes) + (6 * 4));
    c32toa((addr)[7], (bytes) + (7 * 4));
}

/********************************************
 * HASHING
 ********************************************/

#if !defined(WOLFSSL_WC_XMSS_SMALL) && defined(WC_XMSS_SHA256) && \
    !defined(WC_XMSS_FULL_HASH)

/* Set hash data and length into SHA-256 digest.
 *
 * @param [in, out] state      XMSS/MT state with SHA-256 digest.
 * @param [in]      data       Data to add to hash.
 * @param [in]      len        Number of bytes in data.
 *                             Must be less than a block.
 * @param [in]      total_len  Number of bytes updated so far.
 */
#define XMSS_SHA256_SET_DATA(state, data, len, total_len)           \
do {                                                                \
    XMEMCPY((state)->digest.sha256.buffer, data, len);              \
    (state)->digest.sha256.buffLen = (len);                         \
    (state)->digest.sha256.loLen = (total_len);                     \
} while (0)

/* Save the SHA-256 state to cache.
 *
 * @param [in, out] state  XMSS/MT state with SHA-256 digest and state cache.
 */
#define XMSS_SHA256_STATE_CACHE(state)                              \
    (state)->dgst_state[0] = (state)->digest.sha256.digest[0];      \
    (state)->dgst_state[1] = (state)->digest.sha256.digest[1];      \
    (state)->dgst_state[2] = (state)->digest.sha256.digest[2];      \
    (state)->dgst_state[3] = (state)->digest.sha256.digest[3];      \
    (state)->dgst_state[4] = (state)->digest.sha256.digest[4];      \
    (state)->dgst_state[5] = (state)->digest.sha256.digest[5];      \
    (state)->dgst_state[6] = (state)->digest.sha256.digest[6];      \
    (state)->dgst_state[7] = (state)->digest.sha256.digest[7];      \

/* Restore the SHA-256 state from cache and set length.
 *
 * @param [in, out] state  XMSS/MT state with SHA-256 digest and state cache.
 * @param [in]      len    Number of bytes of data hashed so far.
 */
#define XMSS_SHA256_STATE_RESTORE(state, len)                       \
do {                                                                \
    (state)->digest.sha256.digest[0] = (state)->dgst_state[0];      \
    (state)->digest.sha256.digest[1] = (state)->dgst_state[1];      \
    (state)->digest.sha256.digest[2] = (state)->dgst_state[2];      \
    (state)->digest.sha256.digest[3] = (state)->dgst_state[3];      \
    (state)->digest.sha256.digest[4] = (state)->dgst_state[4];      \
    (state)->digest.sha256.digest[5] = (state)->dgst_state[5];      \
    (state)->digest.sha256.digest[6] = (state)->dgst_state[6];      \
    (state)->digest.sha256.digest[7] = (state)->dgst_state[7];      \
    (state)->digest.sha256.loLen = (len);                           \
} while (0)

/* Restore the SHA-256 state from cache and set data and length.
 *
 * @param [in, out] state      XMSS/MT state with SHA-256 digest and cache.
 * @param [in]      data       Data to add to hash.
 * @param [in]      len        Number of bytes in data.
 *                             Must be less than a block.
 * @param [in]      total_len  Number of bytes updated so far.
 */
#define XMSS_SHA256_STATE_RESTORE_DATA(state, data, len, total_len) \
do {                                                                \
    (state)->digest.sha256.digest[0] = (state)->dgst_state[0];      \
    (state)->digest.sha256.digest[1] = (state)->dgst_state[1];      \
    (state)->digest.sha256.digest[2] = (state)->dgst_state[2];      \
    (state)->digest.sha256.digest[3] = (state)->dgst_state[3];      \
    (state)->digest.sha256.digest[4] = (state)->dgst_state[4];      \
    (state)->digest.sha256.digest[5] = (state)->dgst_state[5];      \
    (state)->digest.sha256.digest[6] = (state)->dgst_state[6];      \
    (state)->digest.sha256.digest[7] = (state)->dgst_state[7];      \
    XMSS_SHA256_SET_DATA(state, data, len, total_len);              \
} while (0)

#endif /* !WOLFSSL_WC_XMSS_SMALL && WC_XMSS_SHA256 && !WC_XMSS_FULL_HASH */

/* Hash the data into output buffer.
 *
 * @param [in]  state   XMSS/MT state including digest and parameters.
 * @param [in]  in      Data to digest.
 * @param [in]  inlen   Length of data to digest in bytes.
 * @param [out] out     Buffer to put digest into.
 */
static WC_INLINE void wc_xmss_hash(XmssState* state, const byte* in,
    word32 inlen, byte* out)
{
    int ret;
    const XmssParams* params = state->params;

#ifdef WC_XMSS_SHA256
    /* Full SHA-256 digest. */
    if ((params->hash == WC_HASH_TYPE_SHA256) &&
            (params->n == WC_SHA256_DIGEST_SIZE)) {
        ret = wc_Sha256Update(&state->digest.sha256, in, inlen);
        if (ret == 0) {
            ret = wc_Sha256Final(&state->digest.sha256, out);
        }
    }
#if WOLFSSL_WC_XMSS_MIN_HASH_SIZE <= 192 && WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 192
    /* Partial SHA-256 digest. */
    else if (params->hash == WC_HASH_TYPE_SHA256) {
        byte buf[WC_SHA256_DIGEST_SIZE];
        ret = wc_Sha256Update(&state->digest.sha256, in, inlen);
        if (ret == 0) {
            ret = wc_Sha256Final(&state->digest.sha256, buf);
        }
        if (ret == 0) {
            XMEMCPY(out, buf, params->n);
        }
    }
#endif
    else
#endif /* WC_XMSS_SHA256 */
#ifdef WC_XMSS_SHA512
    /* Full SHA-512 digest. */
    if (params->hash == WC_HASH_TYPE_SHA512) {
        ret = wc_Sha512Update(&state->digest.sha512, in, inlen);
        if (ret == 0) {
            ret = wc_Sha512Final(&state->digest.sha512, out);
        }
    }
    else
#endif /* WC_XMSS_SHA512 */
#ifdef WC_XMSS_SHAKE128
    /* Digest with SHAKE-128. */
    if (params->hash == WC_HASH_TYPE_SHAKE128) {
        ret = wc_Shake128_Update(&state->digest.shake, in, inlen);
        if (ret == 0) {
            ret = wc_Shake128_Final(&state->digest.shake, out, params->n);
        }
    }
    else
#endif /* WC_XMSS_SHAKE128 */
#ifdef WC_XMSS_SHAKE256
    /* Digest with SHAKE-256. */
    if (params->hash == WC_HASH_TYPE_SHAKE256) {
        ret = wc_Shake256_Update(&state->digest.shake, in, inlen);
        if (ret == 0) {
            ret = wc_Shake256_Final(&state->digest.shake, out, params->n);
        }
    }
    else
#endif /* WC_XMSS_SHAKE256 */
    {
        /* Unsupported digest function. */
        ret = NOT_COMPILED_IN;
    }

    if (state->ret == 0) {
        /* Store any digest failures for public APIs to return. */
        state->ret = ret;
    }
}

#if !defined(WOLFSSL_WC_XMSS_SMALL) && defined(WC_XMSS_SHA256)
#ifndef WC_XMSS_FULL_HASH
/* Chain hashing.
 *
 * RFC 8391: 3.1.2, Algorithm 2: chain - Chaining Function
 *     ...
 *     ADRS.setKeyAndMask(0);
 *     KEY = PRF(SEED, ADRS);
 *     ADRS.setKeyAndMask(1);
 *     BM = PRF(SEED, ADRS);
 *     tmp = F(KEY, tmp XOR BM);
 *     return tmp;
 *
 * @param [in]  state  XMSS/MT state including digest and parameters.
 * @param [in]  tmp    Temporary buffer holding chain data.
 * @param [in]  addr   Hash address as a byte array.
 * @param [out] hash   Buffer to hold hash.
 */
static void wc_xmss_chain_hash_sha256_32(XmssState* state, const byte* tmp,
    byte* addr, byte* hash)
{
    /* Offsets into chain hash data. */
    byte* pad = state->buf;
    byte* key = pad + XMSS_SHA256_32_PAD_LEN;
    byte* bm = key + XMSS_SHA256_32_N;
    int ret;

    /* Calculate n-byte key - KEY. */
    ((word32*)addr)[XMSS_ADDR_KEY_MASK] = 0;
    /* Copy back state after first 64 bytes. */
    XMSS_SHA256_STATE_RESTORE_DATA(state, addr, WC_XMSS_ADDR_LEN,
        XMSS_HASH_PRF_DATA_LEN_SHA256_32);
    /* Calculate hash. */
    ret = wc_Sha256Final(&state->digest.sha256, key);

    if (ret == 0) {
        /* Calculate n-byte bit mask - BM. */
        addr[XMSS_ADDR_KEY_MASK * 4 + 3] = 1;
        /* Copy back state after first 64 bytes. */
        XMSS_SHA256_STATE_RESTORE_DATA(state, addr, WC_XMSS_ADDR_LEN,
            XMSS_HASH_PRF_DATA_LEN_SHA256_32);
        /* Calculate hash. */
        ret = wc_Sha256Final(&state->digest.sha256, bm);
    }

    if (ret == 0) {
        /* Function padding set in caller. */
        xorbuf(bm, tmp, XMSS_SHA256_32_N);
        ret = wc_Sha256Update(&state->digest.sha256, state->buf,
             XMSS_CHAIN_HASH_DATA_LEN_SHA256_32);
    }
    if (ret == 0) {
        /* Calculate the chain hash. */
        ret = wc_Sha256Final(&state->digest.sha256, hash);
    }
    if (state->ret == 0) {
        /* Store any digest failures for public APIs to return. */
        state->ret = ret;
    }
}
#else
/* Chain hashing.
 *
 * Padding, seed, addr for PRF set by caller into prf_buf.
 *
 * RFC 8391: 3.1.2, Algorithm 2: chain - Chaining Function
 *     ...
 *     ADRS.setKeyAndMask(0);
 *     KEY = PRF(SEED, ADRS);
 *     ADRS.setKeyAndMask(1);
 *     BM = PRF(SEED, ADRS);
 *     tmp = F(KEY, tmp XOR BM);
 *     return tmp;
 *
 * @param [in]  state  XMSS/MT state including digest and parameters.
 * @param [in]  tmp    Temporary buffer holding chain data.
 * @param [out] out    Buffer to hold hash.
 */
static void wc_xmss_chain_hash_sha256_32(XmssState* state, const byte* tmp,
    byte* hash)
{
    byte* addr = state->prf_buf + XMSS_SHA256_32_PAD_LEN + XMSS_SHA256_32_N;
    /* Offsets into chain hash data. */
    byte* pad = state->buf;
    byte* key = pad + XMSS_SHA256_32_PAD_LEN;
    byte* bm = key + XMSS_SHA256_32_N;

    /* Calculate n-byte key - KEY. */
    ((word32*)addr)[XMSS_ADDR_KEY_MASK] = 0;
    wc_xmss_hash(state, state->prf_buf, XMSS_HASH_PRF_DATA_LEN_SHA256_32, key);
    /* Calculate the n-byte mask. */
    addr[XMSS_ADDR_KEY_MASK * 4 + 3] = 1;
    wc_xmss_hash(state, state->prf_buf, XMSS_HASH_PRF_DATA_LEN_SHA256_32, bm);

    /* Function padding set in caller. */
    xorbuf(bm, tmp, XMSS_SHA256_32_N);
    /* Calculate the chain hash. */
    wc_xmss_hash(state, state->buf, XMSS_CHAIN_HASH_DATA_LEN_SHA256_32, hash);
}
#endif /* !WC_XMSS_FULL_HASH */
#endif /* !WOLFSSL_WC_XMSS_SMALL && WC_XMSS_SHA256 */

/* Chain hashing.
 *
 * Padding, seed, addr for PRF set by caller into prf_buf.
 *
 * RFC 8391: 3.1.2, Algorithm 2: chain - Chaining Function
 *     ...
 *     ADRS.setKeyAndMask(0);
 *     KEY = PRF(SEED, ADRS);
 *     ADRS.setKeyAndMask(1);
 *     BM = PRF(SEED, ADRS);
 *     tmp = F(KEY, tmp XOR BM);
 *     return tmp;
 *
 * @param [in]  state  XMSS/MT state including digest and parameters.
 * @param [in]  tmp    Temporary buffer holding chain data.
 * @param [out] hash   Buffer to hold hash.
 */
static void wc_xmss_chain_hash(XmssState* state, const byte* tmp, byte* hash)
{
    const XmssParams* params = state->params;
    byte* addr = state->prf_buf + params->pad_len + params->n;
    /* Offsets into chain hash data. */
    byte* pad = state->buf;
    byte* key = pad + params->pad_len;
    byte* bm = key + params->n;

    /* Calculate n-byte key - KEY. */
    ((word32*)addr)[XMSS_ADDR_KEY_MASK] = 0;
    wc_xmss_hash(state, state->prf_buf, XMSS_HASH_PRF_DATA_LEN(params), key);
    /* Calculate n-byte bit mask - BM. */
    addr[XMSS_ADDR_KEY_MASK * 4 + 3] = 1;
    wc_xmss_hash(state, state->prf_buf, XMSS_HASH_PRF_DATA_LEN(params), bm);

    /* Function padding set in caller. */
    xorbuf(bm, tmp, params->n);
    /* Calculate the chain hash. */
    wc_xmss_hash(state, state->buf, XMSS_CHAIN_HASH_DATA_LEN(params), hash);
}

#if !defined(WOLFSSL_WC_XMSS_SMALL) && defined(WC_XMSS_SHA256)
#ifndef WC_XMSS_FULL_HASH
/* Randomized tree hashing.
 *
 * RFC 8391: 4.1.4, Algorithm 7: RAND_HASH
 *     ...
 *     ADRS.setKeyAndMask(0);
 *     KEY = PRF(SEED, ADRS);
 *     ADRS.setKeyAndMask(1);
 *     BM_0 = PRF(SEED, ADRS);
 *     ADRS.setKeyAndMask(2);
 *     BM_1 = PRF(SEED, ADRS);
 *     return H(KEY, (LEFT XOR BM_0) || (RIGHT XOR BM_1));
 *
 * @param [in]  state  XMSS/MT state including digest and parameters.
 * @param [in]  data   Input data.
 * @param [in]  addr   Hash address.
 * @param [out] hash   Buffer to hold hash.
 */
static void wc_xmss_rand_hash_sha256_32_prehash(XmssState* state,
    const byte* data, HashAddress addr, byte* hash)
{
    int ret;
    /* Offsets into rand hash data. */
    byte* pad = state->buf;
    byte* key = pad + XMSS_SHA256_32_PAD_LEN;
    byte* bm0 = key + XMSS_SHA256_32_N;
    byte* bm1 = bm0 + XMSS_SHA256_32_N;
    byte addr_buf[WC_XMSS_ADDR_LEN];

    addr[XMSS_ADDR_KEY_MASK] = 0;
    wc_xmss_addr_encode(addr, addr_buf);

    /* Calculate n-byte key - KEY. */
    XMSS_SHA256_STATE_RESTORE_DATA(state, addr_buf, WC_XMSS_ADDR_LEN,
        XMSS_HASH_PRF_DATA_LEN_SHA256_32);
    /* Calculate hash. */
    ret = wc_Sha256Final(&state->digest.sha256, key);

    /* Calculate n-byte mask - BM_0. */
    if (ret == 0) {
        addr_buf[XMSS_ADDR_KEY_MASK * 4 + 3] = 1;
        /* Copy back state after first 64 bytes. */
        XMSS_SHA256_STATE_RESTORE_DATA(state, addr_buf, WC_XMSS_ADDR_LEN,
            XMSS_HASH_PRF_DATA_LEN_SHA256_32);
        /* Calculate hash. */
        ret = wc_Sha256Final(&state->digest.sha256, bm0);
    }

    /* Calculate n-byte mask - BM_1. */
    if (ret == 0) {
        addr_buf[XMSS_ADDR_KEY_MASK * 4 + 3] = 2;
        /* Copy back state after first 64 bytes. */
        XMSS_SHA256_STATE_RESTORE_DATA(state, addr_buf, WC_XMSS_ADDR_LEN,
            XMSS_HASH_PRF_DATA_LEN_SHA256_32);
        /* Calculate hash. */
        ret = wc_Sha256Final(&state->digest.sha256, bm1);
    }

    if (ret == 0) {
        XMSS_PAD_ENC(XMSS_HASH_PADDING_H, pad, XMSS_SHA256_32_PAD_LEN);
        /* XOR into bm0 and bm1. */
        xorbuf(bm0, data, XMSS_SHA256_32_N * 2);
        ret = wc_Sha256Update(&state->digest.sha256, state->buf,
            XMSS_RAND_HASH_DATA_LEN_SHA256_32);
    }
    if (ret == 0) {
        ret = wc_Sha256Final(&state->digest.sha256, hash);
    }
    if (state->ret == 0) {
        /* Store any digest failures for public APIs to return. */
        state->ret = ret;
    }
}
#endif /* !WC_XMSS_FULL_HASH */

/* Randomized tree hashing.
 *
 * RFC 8391: 4.1.4, Algorithm 7: RAND_HASH
 *     ...
 *     ADRS.setKeyAndMask(0);
 *     KEY = PRF(SEED, ADRS);
 *     ADRS.setKeyAndMask(1);
 *     BM_0 = PRF(SEED, ADRS);
 *     ADRS.setKeyAndMask(2);
 *     BM_1 = PRF(SEED, ADRS);
 *     return H(KEY, (LEFT XOR BM_0) || (RIGHT XOR BM_1));
 *
 * @param [in]  state    XMSS/MT state including digest and parameters.
 * @param [in]  data     Input data.
 * @param [in]  pk_seed  Random public seed.
 * @param [in]  addr     Hash address.
 * @param [out] hash     Buffer to hold hash.
 */
static void wc_xmss_rand_hash_sha256_32(XmssState* state, const byte* data,
    const byte* pk_seed, HashAddress addr, byte* hash)
{
    byte* addr_buf = state->prf_buf + XMSS_SHA256_32_PAD_LEN +
        XMSS_SHA256_32_N;
    /* Offsets into rand hash data. */
    byte* pad = state->buf;
    byte* key = pad + XMSS_SHA256_32_PAD_LEN;
    byte* bm0 = key + XMSS_SHA256_32_N;
    byte* bm1 = bm0 + XMSS_SHA256_32_N;
#ifndef WC_XMSS_FULL_HASH
    int ret;

    /* Encode padding byte for PRF. */
    XMSS_PAD_ENC(XMSS_HASH_PADDING_PRF, state->prf_buf, XMSS_SHA256_32_PAD_LEN);
    /* Append public seed for PRF. */
    XMEMCPY(state->prf_buf + XMSS_SHA256_32_PAD_LEN, pk_seed,
        XMSS_SHA256_32_N);

    /* Set key mask to initial value and append encoding. */
    addr[XMSS_ADDR_KEY_MASK] = 0;
    wc_xmss_addr_encode(addr, addr_buf);

    /* Calculate n-byte key - KEY. */
    ret = wc_Sha256Update(&state->digest.sha256, state->prf_buf,
        XMSS_SHA256_32_PAD_LEN + XMSS_SHA256_32_N);
    if (ret == 0) {
        /* Copy state after first 64 bytes. */
        XMSS_SHA256_STATE_CACHE(state);
        /* Copy in remaining 32 bytes to buffer. */
        XMSS_SHA256_SET_DATA(state, addr_buf, WC_XMSS_ADDR_LEN,
            XMSS_HASH_PRF_DATA_LEN_SHA256_32);
        /* Calculate hash. */
        ret = wc_Sha256Final(&state->digest.sha256, key);
    }

    /* Calculate n-byte mask - BM_0. */
    if (ret == 0) {
        addr_buf[XMSS_ADDR_KEY_MASK * 4 + 3] = 1;
        /* Copy back state after first 64 bytes. */
        XMSS_SHA256_STATE_RESTORE_DATA(state, addr_buf, WC_XMSS_ADDR_LEN,
            XMSS_HASH_PRF_DATA_LEN_SHA256_32);
        /* Calculate hash. */
        ret = wc_Sha256Final(&state->digest.sha256, bm0);
    }

    /* Calculate n-byte mask - BM_1. */
    if (ret == 0) {
        addr_buf[XMSS_ADDR_KEY_MASK * 4 + 3] = 2;
        /* Copy back state after first 64 bytes. */
        XMSS_SHA256_STATE_RESTORE_DATA(state, addr_buf, WC_XMSS_ADDR_LEN,
            XMSS_HASH_PRF_DATA_LEN_SHA256_32);
        /* Calculate hash. */
        ret = wc_Sha256Final(&state->digest.sha256, bm1);
    }

    if (ret == 0) {
        XMSS_PAD_ENC(XMSS_HASH_PADDING_H, pad, XMSS_SHA256_32_PAD_LEN);
        /* XOR into bm0 and bm1. */
        xorbuf(bm0, data, 2 * XMSS_SHA256_32_N);
        ret = wc_Sha256Update(&state->digest.sha256, state->buf,
            XMSS_RAND_HASH_DATA_LEN_SHA256_32);
    }
    if (ret == 0) {
        ret = wc_Sha256Final(&state->digest.sha256, hash);
    }
    if (state->ret == 0) {
        /* Store any digest failures for public APIs to return. */
        state->ret = ret;
    }
#else
    /* Encode padding byte for PRF. */
    XMSS_PAD_ENC(XMSS_HASH_PADDING_PRF, state->prf_buf, XMSS_SHA256_32_PAD_LEN);
    /* Append public seed for PRF. */
    XMEMCPY(state->prf_buf + XMSS_SHA256_32_PAD_LEN, pk_seed,
        XMSS_SHA256_32_N);

    /* Set key mask to initial value and append encoding. */
    addr[XMSS_ADDR_KEY_MASK] = 0;
    wc_xmss_addr_encode(addr, addr_buf);

    /* Calculate n-byte key - KEY. */
    wc_xmss_hash(state, state->prf_buf, XMSS_HASH_PRF_DATA_LEN_SHA256_32, key);
    /* Calculate n-byte mask - BM_0. */
    addr_buf[XMSS_ADDR_KEY_MASK * 4 + 3] = 1;
    wc_xmss_hash(state, state->prf_buf, XMSS_HASH_PRF_DATA_LEN_SHA256_32, bm0);
    /* Calculate n-byte mask - BM_1. */
    addr_buf[XMSS_ADDR_KEY_MASK * 4 + 3] = 2;
    wc_xmss_hash(state, state->prf_buf, XMSS_HASH_PRF_DATA_LEN_SHA256_32, bm1);

    XMSS_PAD_ENC(XMSS_HASH_PADDING_H, state->buf, XMSS_SHA256_32_PAD_LEN);
    xorbuf(bm0, data, 2 * XMSS_SHA256_32_N);
    wc_xmss_hash(state, state->buf, XMSS_RAND_HASH_DATA_LEN_SHA256_32, hash);
#endif /* WC_XMSS_FULL_HASH */
}
#endif /* !WOLFSSL_WC_XMSS_SMALL && WC_XMSS_SHA256 */

/* Randomized tree hashing.
 *
 * RFC 8391: 4.1.4, Algorithm 7: RAND_HASH
 *     ...
 *     ADRS.setKeyAndMask(0);
 *     KEY = PRF(SEED, ADRS);
 *     ADRS.setKeyAndMask(1);
 *     BM_0 = PRF(SEED, ADRS);
 *     ADRS.setKeyAndMask(2);
 *     BM_1 = PRF(SEED, ADRS);
 *     return H(KEY, (LEFT XOR BM_0) || (RIGHT XOR BM_1));
 *
 * @param [in]  state    XMSS/MT state including digest and parameters.
 * @param [in]  data     Input data.
 * @param [in]  pk_seed  Random public seed.
 * @param [in]  addr     Hash address.
 * @param [out] hash     Buffer to hold hash.
 */
static void wc_xmss_rand_hash(XmssState* state, const byte* data,
    const byte* pk_seed, HashAddress addr, byte* hash)
{
    const XmssParams* params = state->params;

#if !defined(WOLFSSL_WC_XMSS_SMALL) && defined(WC_XMSS_SHA256)
    if ((params->pad_len == XMSS_SHA256_32_PAD_LEN) &&
            (params->n == XMSS_SHA256_32_N) &&
            (params->hash == WC_HASH_TYPE_SHA256)) {
        wc_xmss_rand_hash_sha256_32(state, data, pk_seed, addr, hash);
    }
    else
#endif /* !WOLFSSL_WC_XMSS_SMALL && WC_XMSS_SHA256 */
    {
        byte* addr_buf = state->prf_buf + params->pad_len + params->n;
        /* Offsets into rand hash data. */
        byte* pad = state->buf;
        byte* key = pad + params->pad_len;
        byte* bm0 = key + params->n;
        byte* bm1 = bm0 + params->n;
        const word32 len = params->pad_len + params->n + WC_XMSS_ADDR_LEN;

        /* Encode padding byte for PRF. */
        XMSS_PAD_ENC(XMSS_HASH_PADDING_PRF, state->prf_buf, params->pad_len);
        /* Append public seed for PRF. */
        XMEMCPY(state->prf_buf + params->pad_len, pk_seed, params->n);

        /* Set key mask to initial value and append encoding. */
        addr[XMSS_ADDR_KEY_MASK] = 0;
        wc_xmss_addr_encode(addr, addr_buf);

        /* Calculate n-byte key - KEY. */
        wc_xmss_hash(state, state->prf_buf, len, key);
        /* Calculate n-byte mask - BM_0. */
        addr_buf[XMSS_ADDR_KEY_MASK * 4 + 3] = 1;
        wc_xmss_hash(state, state->prf_buf, len, bm0);
        /* Calculate n-byte mask - BM_1. */
        addr_buf[XMSS_ADDR_KEY_MASK * 4 + 3] = 2;
        wc_xmss_hash(state, state->prf_buf, len, bm1);

        XMSS_PAD_ENC(XMSS_HASH_PADDING_H, pad, params->pad_len);
        xorbuf(bm0, data, 2 * params->n);
        wc_xmss_hash(state, state->buf, params->pad_len + 3 * params->n,
            hash);
    }
}

#if !defined(WOLFSSL_WC_XMSS_SMALL) || defined(WOLFSSL_XMSS_VERIFY_ONLY)
#if !defined(WOLFSSL_WC_XMSS_SMALL) && defined(WC_XMSS_SHA256)
/* Randomized tree hashing.
 *
 * RFC 8391: 4.1.4, Algorithm 7: RAND_HASH
 *     ...
 *     ADRS.setKeyAndMask(0);
 *     KEY = PRF(SEED, ADRS);
 *     ADRS.setKeyAndMask(1);
 *     BM_0 = PRF(SEED, ADRS);
 *     ADRS.setKeyAndMask(2);
 *     BM_1 = PRF(SEED, ADRS);
 *     return H(KEY, (LEFT XOR BM_0) || (RIGHT XOR BM_1));
 *
 * @param [in]  state    XMSS/MT state including digest and parameters.
 * @param [in]  left     First half of data.
 * @param [in]  right    Second half of data.
 * @param [in]  pk_seed  Random public seed.
 * @param [in]  addr     Hash address.
 * @param [out] hash     Buffer to hold hash.
 */
static void wc_xmss_rand_hash_lr_sha256_32(XmssState* state, const byte* left,
    const byte* right, const byte* pk_seed, HashAddress addr, byte* hash)
{
    byte* addr_buf = state->prf_buf + XMSS_SHA256_32_PAD_LEN +
        XMSS_SHA256_32_N;
    /* Offsets into rand hash data. */
    byte* pad = state->buf;
    byte* key = pad + XMSS_SHA256_32_PAD_LEN;
    byte* bm0 = key + XMSS_SHA256_32_N;
    byte* bm1 = bm0 + XMSS_SHA256_32_N;
#ifndef WC_XMSS_FULL_HASH
    int ret;

    /* Encode padding byte for PRF. */
    XMSS_PAD_ENC(XMSS_HASH_PADDING_PRF, state->prf_buf, XMSS_SHA256_32_PAD_LEN);
    /* Append public seed for PRF. */
    XMEMCPY(state->prf_buf + XMSS_SHA256_32_PAD_LEN, pk_seed,
        XMSS_SHA256_32_N);

    /* Set key mask to initial value and append encoding. */
    addr[XMSS_ADDR_KEY_MASK] = 0;
    wc_xmss_addr_encode(addr, addr_buf);

    /* Calculate n-byte key - KEY. */
    ret = wc_Sha256Update(&state->digest.sha256, state->prf_buf,
        XMSS_SHA256_32_PAD_LEN + XMSS_SHA256_32_N);
    if (ret == 0) {
        /* Copy state after first 64 bytes. */
        XMSS_SHA256_STATE_CACHE(state);
        /* Copy in remaining 32 bytes to buffer. */
        XMSS_SHA256_SET_DATA(state, addr_buf, WC_XMSS_ADDR_LEN,
            XMSS_HASH_PRF_DATA_LEN_SHA256_32);
        /* Calculate hash. */
        ret = wc_Sha256Final(&state->digest.sha256, key);
    }

    /* Calculate n-byte mask - BM_0. */
    if (ret == 0) {
        addr_buf[XMSS_ADDR_KEY_MASK * 4 + 3] = 1;
        /* Copy back state after first 64 bytes. */
        XMSS_SHA256_STATE_RESTORE_DATA(state, addr_buf, WC_XMSS_ADDR_LEN,
            XMSS_HASH_PRF_DATA_LEN_SHA256_32);
        /* Calculate hash. */
        ret = wc_Sha256Final(&state->digest.sha256, bm0);
    }

    /* Calculate n-byte mask - BM_1. */
    if (ret == 0) {
        addr_buf[XMSS_ADDR_KEY_MASK * 4 + 3] = 2;
        /* Copy back state after first 64 bytes. */
        XMSS_SHA256_STATE_RESTORE_DATA(state, addr_buf, WC_XMSS_ADDR_LEN,
            XMSS_HASH_PRF_DATA_LEN_SHA256_32);
        /* Calculate hash. */
        ret = wc_Sha256Final(&state->digest.sha256, bm1);
    }

    if (ret == 0) {
        XMSS_PAD_ENC(XMSS_HASH_PADDING_H, pad, XMSS_SHA256_32_PAD_LEN);
        /* XOR into bm0 and bm1. */
        XMEMCPY(state->prf_buf, left, XMSS_SHA256_32_N);
        XMEMCPY(state->prf_buf + XMSS_SHA256_32_N, right, XMSS_SHA256_32_N);
        xorbuf(bm0, state->prf_buf, 2 * XMSS_SHA256_32_N);
        ret = wc_Sha256Update(&state->digest.sha256, state->buf,
            XMSS_RAND_HASH_DATA_LEN_SHA256_32);
    }
    if (ret == 0) {
        ret = wc_Sha256Final(&state->digest.sha256, hash);
    }
    if (state->ret == 0) {
        /* Store any digest failures for public APIs to return. */
        state->ret = ret;
    }
#else
    /* Encode padding byte for PRF. */
    XMSS_PAD_ENC(XMSS_HASH_PADDING_PRF, state->prf_buf, XMSS_SHA256_32_PAD_LEN);
    /* Append public seed for PRF. */
    XMEMCPY(state->prf_buf + XMSS_SHA256_32_PAD_LEN, pk_seed, XMSS_SHA256_32_N);

    /* Set key mask to initial value and append encoding. */
    addr[XMSS_ADDR_KEY_MASK] = 0;
    wc_xmss_addr_encode(addr, addr_buf);

    /* Calculate n-byte key - KEY. */
    wc_xmss_hash(state, state->prf_buf, XMSS_HASH_PRF_DATA_LEN_SHA256_32, key);
    /* Calculate n-byte mask - BM_0. */
    addr_buf[XMSS_ADDR_KEY_MASK * 4 + 3] = 1;
    wc_xmss_hash(state, state->prf_buf, XMSS_HASH_PRF_DATA_LEN_SHA256_32, bm0);
    /* Calculate n-byte mask - BM_1. */
    addr_buf[XMSS_ADDR_KEY_MASK * 4 + 3] = 2;
    wc_xmss_hash(state, state->prf_buf, XMSS_HASH_PRF_DATA_LEN_SHA256_32, bm1);

    XMSS_PAD_ENC(XMSS_HASH_PADDING_H, state->buf, XMSS_SHA256_32_PAD_LEN);
    XMEMCPY(state->prf_buf, left, XMSS_SHA256_32_N);
    XMEMCPY(state->prf_buf + XMSS_SHA256_32_N, right, XMSS_SHA256_32_N);
    xorbuf(bm0, state->prf_buf, 2 * XMSS_SHA256_32_N);
    wc_xmss_hash(state, state->buf, XMSS_RAND_HASH_DATA_LEN_SHA256_32, hash);
#endif /* WC_XMSS_FULL_HASH */
}
#endif /* !WOLFSSL_WC_XMSS_SMALL && WC_XMSS_SHA256 */
/* Randomized tree hashing - left and right separate parameters.
 *
 * RFC 8391: 4.1.4, Algorithm 7: RAND_HASH
 *     ...
 *     ADRS.setKeyAndMask(0);
 *     KEY = PRF(SEED, ADRS);
 *     ADRS.setKeyAndMask(1);
 *     BM_0 = PRF(SEED, ADRS);
 *     ADRS.setKeyAndMask(2);
 *     BM_1 = PRF(SEED, ADRS);
 *     return H(KEY, (LEFT XOR BM_0) || (RIGHT XOR BM_1));
 *
 * @param [in]  state    XMSS/MT state including digest and parameters.
 * @param [in]  left     First half of data.
 * @param [in]  right    Second half of data.
 * @param [in]  pk_seed  Random public seed.
 * @param [in]  addr     Hash address.
 * @param [out] hash     Buffer to hold hash.
 */
static void wc_xmss_rand_hash_lr(XmssState* state, const byte* left,
    const byte* right, const byte* pk_seed, HashAddress addr, byte* hash)
{
    const XmssParams* params = state->params;

#if !defined(WOLFSSL_WC_XMSS_SMALL) && defined(WC_XMSS_SHA256)
    if ((params->pad_len == XMSS_SHA256_32_PAD_LEN) &&
            (params->n == XMSS_SHA256_32_N) &&
            (params->hash == WC_HASH_TYPE_SHA256)) {
        wc_xmss_rand_hash_lr_sha256_32(state, left, right, pk_seed, addr, hash);
    }
    else
#endif /* !WOLFSSL_WC_XMSS_SMALL && WC_XMSS_SHA256 */
    {
        byte* addr_buf = state->prf_buf + params->pad_len + params->n;
        /* Offsets into rand hash data. */
        byte* pad = state->buf;
        byte* key = pad + params->pad_len;
        byte* bm0 = key + params->n;
        byte* bm1 = bm0 + params->n;
        const word32 len = params->pad_len + params->n + WC_XMSS_ADDR_LEN;

        /* Encode padding byte for PRF. */
        XMSS_PAD_ENC(XMSS_HASH_PADDING_PRF, state->prf_buf, params->pad_len);
        /* Append public seed for PRF. */
        XMEMCPY(state->prf_buf + params->pad_len, pk_seed, params->n);

        /* Set key mask to initial value and append encoding. */
        addr[XMSS_ADDR_KEY_MASK] = 0;
        wc_xmss_addr_encode(addr, addr_buf);

        /* Calculate n-byte key - KEY. */
        wc_xmss_hash(state, state->prf_buf, len, key);
        /* Calculate n-byte mask - BM_0. */
        addr_buf[XMSS_ADDR_KEY_MASK * 4 + 3] = 1;
        wc_xmss_hash(state, state->prf_buf, len, bm0);
        /* Calculate n-byte mask - BM_1. */
        addr_buf[XMSS_ADDR_KEY_MASK * 4 + 3] = 2;
        wc_xmss_hash(state, state->prf_buf, len, bm1);

        XMSS_PAD_ENC(XMSS_HASH_PADDING_H, pad, params->pad_len);
        XMEMCPY(state->prf_buf, left, params->n);
        XMEMCPY(state->prf_buf + params->n, right, params->n);
        xorbuf(bm0, state->prf_buf, 2 * params->n);
        wc_xmss_hash(state, state->buf, params->pad_len + 3 * params->n,
            hash);
    }
}
#endif /* !WOLFSSL_WC_XMSS_SMALL || WOLFSSL_XMSS_VERIFY_ONLY */

/* Compute message hash from the random r, root, index and message.
 *
 * RFC 8391: 4.1.9, Algorithm 12: XMSS_sign
 *    ...
 *    byte[n] M' = H_msg(r || getRoot(SK) || (toByte(idx_sig, n)), M);
 * RFC 8391: 5.1
 *    H_msg: SHA2-256(toByte(2, 32) || KEY || M)
 *    H_msg: SHA2-512(toByte(2, 64) || KEY || M)
 *    H_msg: SHAKE128(toByte(2, 32) || KEY || M, 256)
 *    H_msg: SHAKE256(toByte(2, 64) || KEY || M, 512)
 *
 * @param [in]  state     XMSS/MT state including digest and parameters.
 * @param [in]  random    Random value of n bytes.
 * @param [in]  root      Public root.
 * @param [in]  idx       Buffer holding encoded index.
 * @param [in]  idx_len   Length of encoded index in bytes.
 * @param [in]  m         Message to hash.
 * @param [in]  mlen      Length of message.
 * @param [out] hash      Buffer to hold hash.
 */
static void wc_xmss_hash_message(XmssState* state, const byte* random,
    const byte* root, const byte* idx, word8 idx_len, const byte* m,
    word32 mlen, byte* hash)
{
    int ret;
    const XmssParams* params = state->params;
    word32 padKeyLen = params->pad_len + 3 * params->n;
    /* Offsets into message hash data. */
    byte* padKey = state->buf;
    byte* pad = padKey;
    byte* key = pad + params->pad_len;
    byte* root_sk = key + params->n;
    byte* idx_sig = root_sk + params->n;

    /* Set prefix data before message. */
    XMSS_PAD_ENC(XMSS_HASH_PADDING_HASH, pad, params->pad_len);
    XMEMCPY(key, random, params->n);
    XMEMCPY(root_sk, root, params->n);
    XMEMSET(idx_sig, 0, params->n - idx_len);
    XMEMCPY(idx_sig + params->n - idx_len, idx, idx_len);

    /* Hash the padding and key first. */
#ifdef WC_XMSS_SHA256
    if (params->hash == WC_HASH_TYPE_SHA256) {
        ret = wc_Sha256Update(&state->digest.sha256, padKey, padKeyLen);
    }
    else
#endif /* WC_XMSS_SHA256 */
#ifdef WC_XMSS_SHA512
    if (params->hash == WC_HASH_TYPE_SHA512) {
        ret = wc_Sha512Update(&state->digest.sha512, padKey, padKeyLen);
    }
    else
#endif /* WC_XMSS_SHA512 */
#ifdef WC_XMSS_SHAKE128
    if (params->hash == WC_HASH_TYPE_SHAKE128) {
        ret = wc_Shake128_Update(&state->digest.shake, padKey, padKeyLen);
    }
    else
#endif /* WC_XMSS_SHAKE128 */
#ifdef WC_XMSS_SHAKE256
    if (params->hash == WC_HASH_TYPE_SHAKE256) {
        ret = wc_Shake256_Update(&state->digest.shake, padKey, padKeyLen);
    }
    else
#endif /* WC_XMSS_SHAKE256 */
    {
        /* Unsupported digest function. */
        ret = NOT_COMPILED_IN;
    }
    if (ret == 0) {
        /* Generate hash of message - M'. */
        wc_xmss_hash(state, m, mlen, hash);
    }
    else if (state->ret == 0) {
        /* Store any digest failures for public APIs to return. */
        state->ret = ret;
    }
}

#ifndef WOLFSSL_XMSS_VERIFY_ONLY

/* Compute PRF with key and message.
 *
 * RFC 8391: 5.1
 *   PRF: SHA2-256(toByte(3, 32) || KEY || M)
 *   PRF: SHA2-512(toByte(3, 64) || KEY || M)
 *   PRF: SHAKE128(toByte(3, 32) || KEY || M, 256)
 *   PRF: SHAKE256(toByte(3, 64) || KEY || M, 512)
 *
 * @param [in]  state    XMSS/MT state including digest and parameters.
 * @param [in]  key      Key used to derive pseudo-random from.
 * @param [in]  m        32 bytes of data to derive pseudo-random from.
 * @param [out] prf      Buffer to hold pseudo-random data.
 */
static void wc_xmss_prf(XmssState* state, const byte* key, const byte* m,
    byte* prf)
{
    const XmssParams* params = state->params;
    byte* pad = state->prf_buf;
    byte* key_buf = pad + params->pad_len;
    byte* m_buf = key_buf + params->n;

    /* 00[0..pl-1] || 03 || key[0..n-1] || m[0..31] */
    XMSS_PAD_ENC(XMSS_HASH_PADDING_PRF, pad, params->pad_len);
    XMEMCPY(key_buf, key, params->n);
    XMEMCPY(m_buf, m, XMSS_PRF_M_LEN);

    /* Hash the PRF data. */
    wc_xmss_hash(state, state->prf_buf, params->pad_len + params->n +
        XMSS_PRF_M_LEN, prf);
}

#ifdef XMSS_CALL_PRF_KEYGEN
/* Compute PRF for keygen with key and message.
 *
 * NIST SP 800-208: 5.1, 5.2, 5.3, 5.4
 *   PRFkeygen (KEY, M): SHA-256(toByte(4, 32) || KEY || M)
 *   PRFkeygen (KEY, M): T192(SHA-256(toByte(4, 4) || KEY || M))
 *   PRFkeygen (KEY, M): SHAKE256(toByte(4, 32) || KEY || M, 256)
 *   PRFkeygen (KEY, M): SHAKE256(toByte(4, 4) || KEY || M, 192)
 *
 * @param [in]  state    XMSS/MT state including digest and parameters.
 * @param [in]  key      Key of n bytes used to derive pseudo-random from.
 * @param [in]  m        n + 32 bytes of data to derive pseudo-random from.
 * @param [out] prf      Buffer to hold pseudo-random data.
 */
static void wc_xmss_prf_keygen(XmssState* state, const byte* key,
    const byte* m, byte* prf)
{
    const XmssParams* params = state->params;
    byte* pad = state->prf_buf;
    byte* key_buf = pad + params->pad_len;
    byte* m_buf = key_buf + params->n;

    /* 00[0..pl-1] || 04 || key[0..n-1] || m[0..n+31] */
    XMSS_PAD_ENC(XMSS_HASH_PADDING_PRF_KEYGEN, pad, params->pad_len);
    XMEMCPY(key_buf, key, params->n);
    XMEMCPY(m_buf, m, params->n + XMSS_PRF_M_LEN);

    /* Hash the PRF keygen data. */
    wc_xmss_hash(state, state->prf_buf, params->pad_len + 2 * params->n +
        XMSS_PRF_M_LEN, prf);
}
#endif /* XMSS_CALL_PRF_KEYGEN */

#endif /* !WOLFSSL_XMSS_VERIFY_ONLY */

/********************************************
 * WOTS
 ********************************************/

#ifndef WOLFSSL_XMSS_VERIFY_ONLY

#if !defined(WOLFSSL_WC_XMSS_SMALL) && defined(WC_XMSS_SHA256)
/* Expand private seed with PRF keygen.
 *
 * RFC 8391: 4.1.3
 *   "the existence of a method getWOTS_SK(SK, i) is assumed"
 * NIST SP 800-208: 7.2.1, Algorithm 10'
 *     ...
 *     for ( j=0; j < len; j++) {
 *       ADRS.setChainAddress(j);
 *       sk[j] = PRFkeygen(S_XMSS, SEED || ADRS);
 *     }
 *
 * @param [in]  state     XMSS/MT state including digest and parameters.
 * @param [in]  sk_seed   Buffer holding private seed.
 * @param [in]  pk_seed   Random public seed.
 * @param [in]  addr      Hash address as a byte array.
 * @param [out] gen_seed  Buffer to hold seeds.
 */
static void wc_xmss_wots_get_wots_sk_sha256_32(XmssState* state,
    const byte* sk_seed, const byte* pk_seed, byte* addr, byte* gen_seed)
{
    const XmssParams* params = state->params;
    word32 i;
    byte* pad = state->prf_buf;
    byte* s_xmss = pad + XMSS_SHA256_32_PAD_LEN;
    byte* seed = s_xmss + XMSS_SHA256_32_N;
    byte* addr_buf = seed + XMSS_SHA256_32_N;
    int ret;

    ((word32*)addr)[XMSS_ADDR_CHAIN] = 0;
    ((word32*)addr)[XMSS_ADDR_HASH] = 0;
    ((word32*)addr)[XMSS_ADDR_KEY_MASK] = 0;

    XMSS_PAD_ENC(XMSS_HASH_PADDING_PRF_KEYGEN, pad, XMSS_SHA256_32_PAD_LEN);
    XMEMCPY(s_xmss, sk_seed, XMSS_SHA256_32_N);
    XMEMCPY(seed, pk_seed, XMSS_SHA256_32_N);
    XMEMCPY(addr_buf, addr, WC_XMSS_ADDR_LEN);

#ifndef WC_XMSS_FULL_HASH
    ret = wc_Sha256Update(&state->digest.sha256, pad, XMSS_SHA256_32_PAD_LEN +
        XMSS_SHA256_32_N);
    if (ret == 0) {
        /* Copy state after first 64 bytes. */
        XMSS_SHA256_STATE_CACHE(state);
        ret = wc_Sha256Update(&state->digest.sha256, seed, XMSS_SHA256_32_N +
            WC_XMSS_ADDR_LEN);
    }
    if (ret == 0) {
        ret = wc_Sha256Final(&state->digest.sha256, gen_seed);
    }
    for (i = 1; (ret == 0) && (i < params->wots_len); i++) {
        gen_seed += XMSS_SHA256_32_N;
        addr_buf[XMSS_ADDR_CHAIN * 4 + 3] = i;
        XMSS_SHA256_STATE_RESTORE(state, 64);
        ret = wc_Sha256Update(&state->digest.sha256, seed, XMSS_SHA256_32_N +
            WC_XMSS_ADDR_LEN);
        if (ret == 0) {
            ret = wc_Sha256Final(&state->digest.sha256, gen_seed);
        }
    }
#else
    ret = wc_Sha256Update(&state->digest.sha256, state->prf_buf,
        XMSS_SHA256_32_PAD_LEN + 2 * XMSS_SHA256_32_N + WC_XMSS_ADDR_LEN);
    if (ret == 0) {
        ret = wc_Sha256Final(&state->digest.sha256, gen_seed);
    }
    for (i = 1; (ret == 0) && i < params->wots_len; i++) {
        gen_seed += XMSS_SHA256_32_N;
        addr_buf[XMSS_ADDR_CHAIN * 4 + 3] = i;
        ret = wc_Sha256Update(&state->digest.sha256, state->prf_buf,
            XMSS_SHA256_32_PAD_LEN + 2 * XMSS_SHA256_32_N + WC_XMSS_ADDR_LEN);
        if (ret == 0) {
            ret = wc_Sha256Final(&state->digest.sha256, gen_seed);
        }
    }
#endif /*  WC_XMSS_FULL_HASH*/

    if (state->ret == 0) {
        /* Store any digest failures for public APIs to return. */
        state->ret = ret;
    }
}
#endif /* !WOLFSSL_WC_XMSS_SMALL && WC_XMSS_SHA256 */

/* Expand private seed with PRF keygen.
 *
 * RFC 8391: 4.1.3
 *   "the existence of a method getWOTS_SK(SK, i) is assumed"
 * NIST SP 800-208: 7.2.1
 *   Algorithm 10'
 *     ...
 *     for ( j=0; j < len; j++) {
 *       ADRS.setChainAddress(j);
 *       sk[j] = PRFkeygen(S_XMSS, SEED || ADRS);
 *     }
 *
 * @param [in]  state     XMSS/MT state including digest and parameters.
 * @param [in]  sk_seed   Buffer holding private seed.
 * @param [in]  pk_seed   Random public seed.
 * @param [in]  addr      Hash address as a byte array.
 * @param [out] gen_seed  Buffer to hold seeds.
 */
static void wc_xmss_wots_get_wots_sk(XmssState* state, const byte* sk_seed,
    const byte* pk_seed, byte* addr, byte* gen_seed)
{
    const XmssParams* params = state->params;
    word32 i;
#ifdef XMSS_CALL_PRF_KEYGEN
    byte* seed = state->buf;
    byte* addr_buf = seed + params->n;
#else
    byte* pad = state->prf_buf;
    byte* s_xmss = pad + params->pad_len;
    byte* seed = s_xmss + params->n;
    byte* addr_buf = seed + params->n;
    const word32 len = params->pad_len + params->n * 2 + WC_XMSS_ADDR_LEN;
#endif /* XMSS_CALL_PRF_KEYGEN */

    /* Ensure hash address fields are 0. */
    ((word32*)addr)[XMSS_ADDR_CHAIN] = 0;
    ((word32*)addr)[XMSS_ADDR_HASH] = 0;
    ((word32*)addr)[XMSS_ADDR_KEY_MASK] = 0;

#ifdef XMSS_CALL_PRF_KEYGEN
    /* Copy the seed and address into PRF keygen message buffer. */
    XMEMCPY(seed, pk_seed, params->n);
    XMEMCPY(addr_buf, addr, WC_XMSS_ADDR_LEN);

    wc_xmss_prf_keygen(state, sk_seed, state->buf, gen_seed);
    for (i = 1; i < params->wots_len; i++) {
        gen_seed += params->n;
        addr_buf[XMSS_ADDR_CHAIN * 4 + 3] = i;
        wc_xmss_prf_keygen(state, sk_seed, state->buf, gen_seed);
    }
#else
    /* Copy the PRF keygen fields into one buffer. */
    XMSS_PAD_ENC(XMSS_HASH_PADDING_PRF_KEYGEN, pad, params->pad_len);
    XMEMCPY(s_xmss, sk_seed, params->n);
    XMEMCPY(seed, pk_seed, params->n);
    XMEMCPY(addr_buf, addr, WC_XMSS_ADDR_LEN);

    /* Fill output with hashes of different chain hash addresses. */
    wc_xmss_hash(state, state->prf_buf, len, gen_seed);
    for (i = 1; i < params->wots_len; i++) {
        gen_seed += params->n;
        addr_buf[XMSS_ADDR_CHAIN * 4 + 3] = i;
        wc_xmss_hash(state, state->prf_buf, len, gen_seed);
    }
#endif /* XMSS_CALL_PRF_KEYGEN */
}

#endif /* !WOLFSSL_XMSS_VERIFY_ONLY */

#if !defined(WOLFSSL_WC_XMSS_SMALL) && defined(WC_XMSS_SHA256)
/* Chain hashing to calculate node hash.
 *
 * RFC 8391: 3.1.2, Algorithm 2 - recursive.
 * This function is an iterative version.
 *
 * @param [in]  state    XMSS/MT state including digest and parameters.
 * @param [in]  data     Initial data to hash.
 * @param [in]  start    Starting hash value in hash address.
 * @param [in]  steps    Size of step.
 * @param [in]  pk_seed  Random public seed.
 * @param [in]  addr     Hash address as a byte array.
 * @param [out] hash     Chained hash.
 */
static void wc_xmss_chain_sha256_32(XmssState* state, const byte* data,
    unsigned int start, unsigned int steps, const byte* pk_seed, byte* addr,
    byte* hash)
{
    if (steps > 0) {
        word32 i;
        byte* pad = state->prf_buf;
        byte* seed = pad + XMSS_SHA256_32_PAD_LEN;
#ifndef WC_XMSS_FULL_HASH
        int ret;

        /* Set data for PRF hash. */
        XMSS_PAD_ENC(XMSS_HASH_PADDING_PRF, pad, XMSS_SHA256_32_PAD_LEN);
        XMEMCPY(seed, pk_seed, XMSS_SHA256_32_N);

        /* Hash first 64 bytes. */
        ret = wc_Sha256Update(&state->digest.sha256, state->prf_buf,
             XMSS_SHA256_32_PAD_LEN + XMSS_SHA256_32_N);
        if (ret == 0) {
            /* Copy state after first 64 bytes. */
            XMSS_SHA256_STATE_CACHE(state);
            /* Only do this once for all chain hash calls. */
            XMSS_PAD_ENC(XMSS_HASH_PADDING_F, state->buf,
                state->params->pad_len);

            /* Set address. */
            XMSS_ADDR_SET_BYTE(addr, XMSS_ADDR_HASH, start);
            wc_xmss_chain_hash_sha256_32(state, data, addr, hash);
            /* Iterate 'steps' calls to the hash function. */
            for (i = start+1; i < (start+steps) && i < XMSS_WOTS_W; i++) {
                addr[XMSS_ADDR_HASH * 4 + 3] = i;
                wc_xmss_chain_hash_sha256_32(state, hash, addr, hash);
            }
        }
        else if (state->ret == 0) {
            /* Store any digest failures for public APIs to return. */
            state->ret = ret;
        }
#else
        const XmssParams* params = state->params;
        byte* addr_buf = seed + XMSS_SHA256_32_N;

        /* Set data for PRF hash. */
        XMSS_PAD_ENC(XMSS_HASH_PADDING_PRF, pad, XMSS_SHA256_32_PAD_LEN);
        XMEMCPY(seed, pk_seed, params->n);
        XMEMCPY(addr_buf, addr, WC_XMSS_ADDR_LEN);

        /* Only do this once for all chain hash calls. */
        XMSS_PAD_ENC(XMSS_HASH_PADDING_F, state->buf, params->pad_len);

        /* Set address. */
        XMSS_ADDR_SET_BYTE(addr_buf, XMSS_ADDR_HASH, start);
        wc_xmss_chain_hash_sha256_32(state, data, hash);
        /* Iterate 'steps' calls to the hash function. */
        for (i = start+1; i < (start+steps) && i < XMSS_WOTS_W; i++) {
            addr_buf[XMSS_ADDR_HASH * 4 + 3] = i;
            wc_xmss_chain_hash_sha256_32(state, hash, hash);
        }
#endif /* !WC_XMSS_FULL_HASH */
    }
    else if (hash != data) {
        XMEMCPY(hash, data, XMSS_SHA256_32_N);
    }
}
#endif /* !WOLFSSL_WC_XMSS_SMALL && WC_XMSS_SHA256 */

/* Chain hashing to calculate node hash.
 *
 * RFC 8391: 3.1.2, Algorithm 2 - recursive.
 * This function is an iterative version.
 *
 * @param [in]  state    XMSS/MT state including digest and parameters.
 * @param [in]  data     Initial data to hash.
 * @param [in]  start    Starting hash value in hash address.
 * @param [in]  steps    Size of step.
 * @param [in]  pk_seed  Random public seed.
 * @param [in]  addr     Hash address as a byte array.
 * @param [out] hash     Chained hash.
 */
static void wc_xmss_chain(XmssState* state, const byte* data,
    unsigned int start, unsigned int steps, const byte* pk_seed, byte* addr,
    byte* hash)
{
    const XmssParams* params = state->params;

    if (steps > 0) {
        word32 i;
        byte* pad = state->prf_buf;
        byte* seed = pad + params->pad_len;
        byte* addr_buf = seed + params->n;

        /* Set data for PRF hash. */
        XMSS_PAD_ENC(XMSS_HASH_PADDING_PRF, pad, params->pad_len);
        XMEMCPY(seed, pk_seed, params->n);
        XMEMCPY(addr_buf, addr, 32);

        /* Only do this once for all chain hash calls. */
        XMSS_PAD_ENC(XMSS_HASH_PADDING_F, state->buf, params->pad_len);

        /* Set address. */
        XMSS_ADDR_SET_BYTE(addr_buf, XMSS_ADDR_HASH, start);
        wc_xmss_chain_hash(state, data, hash);
        /* Iterate 'steps' calls to the hash function. */
        for (i = start+1; i < (start+steps) && i < XMSS_WOTS_W; i++) {
            addr_buf[XMSS_ADDR_HASH * 4 + 3] = i;
            wc_xmss_chain_hash(state, hash, hash);
        }
    }
    else if (hash != data) {
        XMEMCPY(hash, data, params->n);
    }
}

/* Convert base on message and add checksum.
 *
 * RFC 8391:, 2.6, Algorithm 1: base_w
 *     int in = 0;
 *     int out = 0;
 *     unsigned int total = 0;
 *     int bits = 0;
 *     int consumed;
 *
 *     for ( consumed = 0; consumed < out_len; consumed++ ) {
 *         if ( bits == 0 ) {
 *             total = X[in];
 *             in++;
 *             bits += 8;
 *         }
 *         bits -= lg(w);
 *         basew[out] = (total >> bits) AND (w - 1);
 *         out++;
 *     }
 *     return basew;
 *
 * base_w implemented for w == 16 (lg(w) == 4).
 *
 * RFC 8391: 3.1.5, Algorithm 5:
 *     ...
 *     csum = 0;
 *
 *     # Convert message to base w
 *     msg = base_w(M, w, len_1);
 *     # Compute checksum
 *     for ( i = 0; i < len_1; i++ ) {
 *           csum = csum + w - 1 - msg[i];
 *     }
 *
 *     # Convert csum to base w
 *     csum = csum << ( 8 - ( ( len_2 * lg(w) ) % 8 ));
 *     len_2_bytes = ceil( ( len_2 * lg(w) ) / 8 );
 *     msg = msg || base_w(toByte(csum, len_2_bytes), w, len_2);
 *
 * len_1 == 8 * n / 4 = n * 2
 * Implemented for len_2 == 3
 *
 * @param [in]  m      Message data.
 * @param [in]  n      Number of bytes in hash.
 * @param [out] msg    Message in new base.
 */
static void wc_xmss_msg_convert(const byte* m, word8 n, word8* msg)
{
    word8 i;
    word16 csum = 0;

    /* Split each full byte of m into two bytes of msg. */
    for (i = 0; i < n; i++) {
        msg[0] = m[i] >> 4;
        msg[1] = m[i] & 0xf;
        csum += XMSS_WOTS_W - 1 - msg[0];
        csum += XMSS_WOTS_W - 1 - msg[1];
        msg += 2;
    }

    /* Append checksum to message. (Maximum value: 1920 = 64 * 2 * 15) */
    msg[0] = (csum >> 8)       ;
    msg[1] = (csum >> 4) & 0x0f;
    msg[2] = (csum     ) & 0x0f;
}

#ifndef WOLFSSL_XMSS_VERIFY_ONLY

/* WOTS+ generate public key with private seed.
 *
 * RFC 8391: 4.1.6, Algorithm 9:
 *     ...
 *     pk = WOTS_genPK (getWOTS_SK(SK, s + i), SEED, ADRS);
 * RFC 8391, 3.1.4, Algorithm 4: WOTS_genPK
 *     ...
 *     for ( i = 0; i < len; i++ ) {
 *       ADRS.setChainAddress(i);
 *       pk[i] = chain(sk[i], 0, w - 1, SEED, ADRS);
 *     }
 *     return pk;
 *
 * WOTS_genPK only used in Algorithm 9 and it is convenient to combine with
 * getWOTS_SK due to parameter specific implementations.
 *
 * @param [in]  state  XMSS/MT state including digest and parameters.
 * @param [in]  sk     Random private seed.
 * @param [in]  seed   Random public seed.
 * @param [in]  addr   Hashing address.
 * @param [out] pk     Public key.
 */
static void wc_xmss_wots_gen_pk(XmssState* state, const byte* sk,
    const byte* seed, HashAddress addr, byte* pk)
{
    const XmssParams* params = state->params;
    byte* addr_buf = state->encMsg;
    word32 i;

    /* Ensure chain address is 0 and encode into a buffer. */
    addr[XMSS_ADDR_CHAIN] = 0;
    wc_xmss_addr_encode(addr, addr_buf);

#if !defined(WOLFSSL_WC_XMSS_SMALL) && defined(WC_XMSS_SHA256)
    if ((params->pad_len == XMSS_SHA256_32_PAD_LEN) &&
            (params->n == XMSS_SHA256_32_N) &&
            (params->hash == WC_HASH_TYPE_SHA256)) {
        /* Expand the private seed - getWOTS_SK */
        wc_xmss_wots_get_wots_sk_sha256_32(state, sk, seed, addr_buf,
            pk);

        /* Calculate chain hash. */
        wc_xmss_chain_sha256_32(state, pk, 0, XMSS_WOTS_W - 1, seed, addr_buf,
            pk);
        for (i = 1; i < params->wots_len; i++) {
            pk += params->n;
            addr_buf[XMSS_ADDR_CHAIN * 4 + 3] = i;
            wc_xmss_chain_sha256_32(state, pk, 0, XMSS_WOTS_W - 1, seed,
                addr_buf, pk);
        }
    }
    else
#endif /* !WOLFSSL_WC_XMSS_SMALL && WC_XMSS_SHA256 */
    {
        /* Expand the private seed - getWOTS_SK */
        wc_xmss_wots_get_wots_sk(state, sk, seed, addr_buf, pk);

        /* Calculate chain hash. */
        wc_xmss_chain(state, pk, 0, XMSS_WOTS_W - 1, seed, addr_buf, pk);
        for (i = 1; i < params->wots_len; i++) {
            pk += params->n;
            addr_buf[XMSS_ADDR_CHAIN * 4 + 3] = i;
            wc_xmss_chain(state, pk, 0, XMSS_WOTS_W - 1, seed, addr_buf, pk);
        }
    }
}
/* Generate a signature from a privatge key and message.
 *
 * RFC 8391: 4.1.9, Algorithm 11: treeSig
 *     sig_ots = WOTS_sign(getWOTS_SK(SK, idx_sig),
 *                         M', getSEED(SK), ADRS);
 * RFC 8391: 3.1.5, Algorithm 5: WOTS_sign
 *     (Convert message to base w and append checksum in base w)
 *     ...
 *     for ( i = 0; i < len; i++ ) {
 *          ADRS.setChainAddress(i);
 *          sig[i] = chain(sk[i], 0, msg[i], SEED, ADRS);
 *     }
 *     return sig;
 *
 * WOTS_sign only used in Algorithm 11 and convenient to do getWOTS_SK due to
 * hash address reuse and parameter specific implementations.
 *
 * @param [in]  state  XMSS/MT state including digest and parameters.
 * @param [in]  m      Message hash to sign.
 * @param [in]  sk     Random private seed.
 * @param [in]  seed   Random public seed.
 * @param [in]  addr   Hashing address.
 * @param [out] sig    Calculated XMSS/MT signature.
 */
static void wc_xmss_wots_sign(XmssState* state, const byte* m,
    const byte* sk, const byte* seed, HashAddress addr, byte* sig)
{
    const XmssParams* params = state->params;
    byte* addr_buf = state->pk;
    word32 i;

    /* Convert message to base w and append checksum in base w. */
    wc_xmss_msg_convert(m, params->n, state->encMsg);

    /* Set initial chain value and encode hash address. */
    addr[XMSS_ADDR_CHAIN] = 0;
    wc_xmss_addr_encode(addr, addr_buf);

#if !defined(WOLFSSL_WC_XMSS_SMALL) && defined(WC_XMSS_SHA256)
    if ((params->pad_len == XMSS_SHA256_32_PAD_LEN) &&
            (params->n == XMSS_SHA256_32_N) &&
            (params->hash == WC_HASH_TYPE_SHA256)) {
        /* Expand the private seed - getWOTS_SK */
        wc_xmss_wots_get_wots_sk_sha256_32(state, sk, seed, addr_buf, sig);

        /* Calculate chain hash. */
        wc_xmss_chain_sha256_32(state, sig, 0, state->encMsg[0], seed, addr_buf,
            sig);
        for (i = 1; i < params->wots_len; i++) {
            sig += params->n;
            addr_buf[XMSS_ADDR_CHAIN * 4 + 3] = i;
            wc_xmss_chain_sha256_32(state, sig, 0, state->encMsg[i], seed,
                addr_buf, sig);
        }
    }
    else
#endif /* !WOLFSSL_WC_XMSS_SMALL && WC_XMSS_SHA256 */
    {
        /* Expand the private seed - getWOTS_SK */
        wc_xmss_wots_get_wots_sk(state, sk, seed, addr_buf, sig);

       /* Calculate chain hash. */
        wc_xmss_chain(state, sig, 0, state->encMsg[0], seed, addr_buf, sig);
        for (i = 1; i < params->wots_len; i++) {
            sig += params->n;
            addr_buf[XMSS_ADDR_CHAIN * 4 + 3] = i;
            wc_xmss_chain(state, sig, 0, state->encMsg[i], seed, addr_buf, sig);
        }
    }
}

#endif /* !WOLFSSL_XMSS_VERIFY_ONLY */

/* Compute WOTS+ public key value from signature and message.
 *
 * RFC 8319: 3.1.6
 *   Algorithm 6: WOTS_pkFromSig
 *     (Convert message to base w and append checksum in base w)
 *     ...
 *     for ( i = 0; i < len; i++ ) {
 *          ADRS.setChainAddress(i);
 *          tmp_pk[i] = chain(sig[i], msg[i], w - 1 - msg[i], SEED, ADRS);
 *     }
 *     return tmp_pk;
 *
 * @param [in]  state  XMSS/MT state including digest and parameters.
 * @param [in]  sig    XMSS/MT Signature.
 * @param [in]  m      Message to verify.
 * @param [in]  seed   Random public seed.
 * @param [in]  addr   Hashing address.
 * @param [out] pk     Public key.
 */
static void wc_xmss_wots_pk_from_sig(XmssState* state, const byte* sig,
    const byte* m, const byte* seed, HashAddress addr, byte* pk)
{
    const XmssParams* params = state->params;
    byte* addr_buf = state->stack;
    word32 i;

    /* Convert message to base w and append checksum in base w. */
    wc_xmss_msg_convert(m, params->n, state->encMsg);

    /* Start with address with chain value of 0. */
    addr[XMSS_ADDR_CHAIN] = 0;
    wc_xmss_addr_encode(addr, addr_buf);

#if !defined(WOLFSSL_WC_XMSS_SMALL) && defined(WC_XMSS_SHA256)
    if ((params->pad_len == XMSS_SHA256_32_PAD_LEN) &&
            (params->n == XMSS_SHA256_32_N) &&
            (params->hash == WC_HASH_TYPE_SHA256)) {
        /* Calculate chain hash. */
        wc_xmss_chain_sha256_32(state, sig, state->encMsg[0],
            XMSS_WOTS_W - 1 - state->encMsg[0], seed, addr_buf, pk);
        for (i = 1; i < params->wots_len; i++) {
            sig += params->n;
            pk += params->n;
            /* Update chain. */
            addr_buf[XMSS_ADDR_CHAIN * 4 + 3] = i;
            wc_xmss_chain_sha256_32(state, sig, state->encMsg[i],
                XMSS_WOTS_W - 1 - state->encMsg[i], seed, addr_buf, pk);
        }
    }
    else
#endif /* !WOLFSSL_WC_XMSS_SMALL && WC_XMSS_SHA256 */
    {
        /* Calculate chain hash. */
        wc_xmss_chain(state, sig, state->encMsg[0],
            XMSS_WOTS_W - 1 - state->encMsg[0], seed, addr_buf, pk);
        for (i = 1; i < params->wots_len; i++) {
            sig += params->n;
            pk += params->n;
            /* Update chain. */
            addr_buf[XMSS_ADDR_CHAIN * 4 + 3] = i;
            wc_xmss_chain(state, sig, state->encMsg[i],
                XMSS_WOTS_W - 1 - state->encMsg[i], seed, addr_buf, pk);
        }
    }
}

/********************************************
 * L-TREE - unbalanced binary hash tree
 ********************************************/

/* Compute leaves of L-tree from WOTS+ public key and compress to single value.
 *
 * RFC 8391: 4.1.5, Algorithm 8: ltree
 *     unsigned int len' = len;
 *     ADRS.setTreeHeight(0);
 *     while ( len' > 1 ) {
 *       for ( i = 0; i < floor(len' / 2); i++ ) {
 *         ADRS.setTreeIndex(i);
 *         pk[i] = RAND_HASH(pk[2i], pk[2i + 1], SEED, ADRS);
 *       }
 *       if ( len' % 2 == 1 ) {
 *         pk[floor(len' / 2)] = pk[len' - 1];
 *       }
 *       len' = ceil(len' / 2);
 *       ADRS.setTreeHeight(ADRS.getTreeHeight() + 1);
 *     }
 *     return pk[0];
 *
 * @param [in]  state  XMSS/MT state including digest and parameters.
 * @param [in]  pk     WOTS+ public key.
 * @param [in]  seed   Random public seed.
 * @param [in]  addr   Hashing address.
 * @param [out] pk0    N-byte compressed public key value pk[0].
 */
static void wc_xmss_ltree(XmssState* state, byte* pk, const byte* seed,
    HashAddress addr, byte* pk0)
{
    const XmssParams* params = state->params;
    word8 len = params->wots_len;
    word32 h = 0;

#if !defined(WOLFSSL_WC_XMSS_SMALL) && defined(WC_XMSS_SHA256) && \
    !defined(WC_XMSS_FULL_HASH)
    /* Precompute hash state after first 64 bytes (common to all hashes). */
    if ((params->pad_len == XMSS_SHA256_32_PAD_LEN) &&
            (params->n == XMSS_SHA256_32_N) &&
            (params->hash == WC_HASH_TYPE_SHA256)) {
        byte* prf_buf = state->prf_buf;
        int ret;

        XMSS_PAD_ENC(XMSS_HASH_PADDING_PRF, prf_buf, XMSS_SHA256_32_PAD_LEN);
        XMEMCPY(prf_buf + XMSS_SHA256_32_PAD_LEN, seed, XMSS_SHA256_32_N);

        ret = wc_Sha256Update(&state->digest.sha256, prf_buf,
            XMSS_SHA256_32_PAD_LEN + XMSS_SHA256_32_N);
        if (ret == 0) {
            /* Copy state after first 64 bytes. */
            XMSS_SHA256_STATE_CACHE(state);
        }
        else if (state->ret == 0) {
            /* Store any digest failures for public APIs to return. */
            state->ret = ret;
        }
    }
#endif /* !WOLFSSL_WC_XMSS_SMALL && WC_XMSS_SHA256 && !WC_XMSS_FULL_HASH */
    while (len > 1) {
        word8 i;
        word8 len2 = len >> 1;

        addr[XMSS_ADDR_TREE_HEIGHT] = h++;

        for (i = 0; i < len2; i++) {
            addr[XMSS_ADDR_TREE_INDEX] = i;
        #if !defined(WOLFSSL_WC_XMSS_SMALL) && defined(WC_XMSS_SHA256) && \
            !defined(WC_XMSS_FULL_HASH)
            if ((params->pad_len == XMSS_SHA256_32_PAD_LEN) &&
                    (params->n == XMSS_SHA256_32_N) &&
                    (params->hash == WC_HASH_TYPE_SHA256)) {
                wc_xmss_rand_hash_sha256_32_prehash(state,
                    pk + i * 2 * XMSS_SHA256_32_N, addr,
                    pk + i * XMSS_SHA256_32_N);
            }
            else
        #endif /* !WOLFSSL_WC_XMSS_SMALL && WC_XMSS_SHA256 &&
                * !WC_XMSS_FULL_HASH */
            {
                wc_xmss_rand_hash(state, pk + i * 2 * params->n,
                    seed, addr, pk + i * params->n);
            }
        }
        if (len & 1) {
            XMEMCPY(pk + len2 * params->n, pk + (len - 1) * params->n,
                params->n);
        }
        len = len2 + (len & 1);
    }
    /* Return compressed public key value pk[0]. */
    XMEMCPY(pk0, pk, params->n);
}

#ifndef WOLFSSL_XMSS_VERIFY_ONLY

#ifdef WOLFSSL_WC_XMSS_SMALL

/********************************************
 * TREE HASH
 ********************************************/

#ifndef WOLFSSL_SMALL_STACK
/* Compute internal nodes of Merkle tree.
 *
 * Implementation always starts at index 0. (s = 0)
 *
 * Build authentication path, if required, rather than duplicating work.
 * When node is generated, copy out to authentication path array of nodes.
 *
 * RFC 8391: 4.1.6, Algorithm 9: treeHash
 *     if( s % (1 << t) != 0 ) return -1;
 *     for ( i = 0; i < 2^t; i++ ) {
 *       SEED = getSEED(SK);
 *       ADRS.setType(0);   # Type = OTS hash address
 *       ADRS.setOTSAddress(s + i);
 *       pk = WOTS_genPK (getWOTS_SK(SK, s + i), SEED, ADRS);
 *       ADRS.setType(1);   # Type = L-tree address
 *       ADRS.setLTreeAddress(s + i);
 *       node = ltree(pk, SEED, ADRS);
 *       ADRS.setType(2);   # Type = hash tree address
 *       ADRS.setTreeHeight(0);
 *       ADRS.setTreeIndex(i + s);
 *       while ( Top node on Stack has same height t' as node ) {
 *          ADRS.setTreeIndex((ADRS.getTreeIndex() - 1) / 2);
 *          node = RAND_HASH(Stack.pop(), node, SEED, ADRS);
 *          ADRS.setTreeHeight(ADRS.getTreeHeight() + 1);
 *       }
 *       Stack.push(node);
 *     }
 *     return Stack.pop();
 * RFC 8391: 4.1.9, (Example) buildAuth
 *     for ( j = 0; j < h; j++ ) {
 *       k = floor(i / (2^j)) XOR 1;
 *       auth[j] = treeHash(SK, k * 2^j, j, ADRS);
 *     }
 *
 * @param [in]  state         XMSS/MT state including digest and parameters.
 * @param [in]  sk_seed       Random private seed.
 * @param [in]  pk_seed       Random public seed.
 * @param [in]  leafIdx       Index of lead node.
 * @param [in]  subtree_addr  Address of subtree.
 * @param [out] root          Root node of the tree.
 * @param [out] auth_path     Nodes of the authentication path.
 */
static void wc_xmss_treehash(XmssState* state, const byte* sk_seed,
    const byte* pk_seed, word32 leafIdx, const word32* subtree, byte* root,
    byte* auth_path)
{
    const XmssParams* params = state->params;
    const word8 n = params->n;
    byte* node = state->stack;
    HashAddress ots;
    HashAddress ltree;
    HashAddress tree;
    word8 height[WC_XMSS_MAX_TREE_HEIGHT + 1];
    word8 offset = 0;
    word32 max = (word32)1 << params->sub_h;
    word32 i;

    /* Copy hash address into one for each purpose.  */
    XMSS_ADDR_OTS_SET_SUBTREE(ots, subtree);
    XMSS_ADDR_LTREE_SET_SUBTREE(ltree, subtree);
    XMSS_ADDR_TREE_SET_SUBTREE(tree, subtree);

    for (i = 0; i < max; i++) {
        word8 h;

        /* Calculate WOTS+ public key. */
        ots[XMSS_ADDR_OTS] = i;
        wc_xmss_wots_gen_pk(state, sk_seed, pk_seed, ots, state->pk);
        /* Calculate public value. */
        ltree[XMSS_ADDR_LTREE] = i;
        wc_xmss_ltree(state, state->pk, pk_seed, ltree, node);

        /* Initial height at this offset is 0. */
        h = height[offset] = 0;
        /* Copy node, at height 0, out if on authentication path. */
        if ((auth_path != NULL) && ((leafIdx ^ 0x1) == i)) {
            XMEMCPY(auth_path, node, n);
        }

        /* Top node on Stack has same height t' as node. */
        while ((offset >= 1) && (h == height[offset - 1])) {
            word32 tree_idx = i >> (h + 1);

            node -= n;
            /* Calculate hash of node. */
            tree[XMSS_ADDR_TREE_HEIGHT] = h;
            tree[XMSS_ADDR_TREE_INDEX] = tree_idx;
            wc_xmss_rand_hash(state, node, pk_seed, tree, node);

            /* Update offset and height. */
            offset--;
            h = ++height[offset];

            /* Copy node out if on authentication path. */
            if ((auth_path != NULL) && (((leafIdx >> h) ^ 0x1) == tree_idx)) {
                XMEMCPY(auth_path + h * n, node, n);
            }
        }
        offset++;
        node += n;
    }

    /* Copy the root node. */
    XMEMCPY(root, state->stack, n);
}
#else
/* Compute internal nodes of Merkle tree.
 *
 * Implementation always starts at index 0. (s = 0)
 *
 * Build authentication path, if required, rather than duplicating work.
 * When node is generated, copy out to authentication path array of nodes.
 *
 * RFC 8391: 4.1.6, Algorithm 9: treeHash
 *     if( s % (1 << t) != 0 ) return -1;
 *     for ( i = 0; i < 2^t; i++ ) {
 *       SEED = getSEED(SK);
 *       ADRS.setType(0);   # Type = OTS hash address
 *       ADRS.setOTSAddress(s + i);
 *       pk = WOTS_genPK (getWOTS_SK(SK, s + i), SEED, ADRS);
 *       ADRS.setType(1);   # Type = L-tree address
 *       ADRS.setLTreeAddress(s + i);
 *       node = ltree(pk, SEED, ADRS);
 *       ADRS.setType(2);   # Type = hash tree address
 *       ADRS.setTreeHeight(0);
 *       ADRS.setTreeIndex(i + s);
 *       while ( Top node on Stack has same height t' as node ) {
 *          ADRS.setTreeIndex((ADRS.getTreeIndex() - 1) / 2);
 *          node = RAND_HASH(Stack.pop(), node, SEED, ADRS);
 *          ADRS.setTreeHeight(ADRS.getTreeHeight() + 1);
 *       }
 *       Stack.push(node);
 *     }
 *     return Stack.pop();
 * RFC 8391: 4.1.9, (Example) buildAuth
 *     for ( j = 0; j < h; j++ ) {
 *       k = floor(i / (2^j)) XOR 1;
 *       auth[j] = treeHash(SK, k * 2^j, j, ADRS);
 *     }
 *
 * @param [in]  state         XMSS/MT state including digest and parameters.
 * @param [in]  sk_seed       Random private seed.
 * @param [in]  pk_seed       Random public seed.
 * @param [in]  leafIdx       Index of lead node.
 * @param [in]  subtree_addr  Address of subtree.
 * @param [out] root          Root node of the tree.
 * @param [out] auth_path     Nodes of the authentication path.
 */
static void wc_xmss_treehash(XmssState* state, const byte* sk_seed,
    const byte* pk_seed, word32 leafIdx, const word32* subtree, byte* root,
    byte* auth_path)
{
    const XmssParams* params = state->params;
    const word8 n = params->n;
    byte* node = state->stack;
    HashAddress addr;
    word8 height[WC_XMSS_MAX_TREE_HEIGHT + 1];
    word8 offset = 0;
    word32 max = (word32)1 << params->sub_h;
    word32 i;

    XMSS_ADDR_SET_SUBTREE(addr, subtree, 0);

    for (i = 0; i < max; i++) {
        word8 h;

        /* Calculate WOTS+ public key. */
        addr[XMSS_ADDR_TYPE] = WC_XMSS_ADDR_TYPE_OTS;
        addr[XMSS_ADDR_LTREE] = i;
        wc_xmss_wots_gen_pk(state, sk_seed, pk_seed, addr, state->pk);
        /* Calculate public value. */
        addr[XMSS_ADDR_TYPE] = WC_XMSS_ADDR_TYPE_LTREE;
        wc_xmss_ltree(state, state->pk, pk_seed, addr, node);
        addr[XMSS_ADDR_TYPE] = WC_XMSS_ADDR_TYPE_TREE;
        addr[XMSS_ADDR_TREE_ZERO] = 0;

        /* Initial height at this offset is 0. */
        h = height[offset] = 0;
        /* Copy node out if on authentication path. */
        if ((auth_path != NULL) && ((leafIdx ^ 0x1) == i)) {
            XMEMCPY(auth_path, node, n);
        }

        /* Top node on Stack has same height t' as node. */
        while ((offset >= 1) && (h == height[offset - 1])) {
            word32 tree_idx = i >> (h + 1);

            node -= n;
            /* Calculate hash of node. */
            addr[XMSS_ADDR_TREE_HEIGHT] = h;
            addr[XMSS_ADDR_TREE_INDEX] = tree_idx;
            wc_xmss_rand_hash(state, node, pk_seed, addr, node);

            /* Update offset and height. */
            offset--;
            h = ++height[offset];

            /* Copy node out if on authentication path. */
            if ((auth_path != NULL) && (((leafIdx >> h) ^ 0x1) == tree_idx)) {
                XMEMCPY(auth_path + h * n, node, n);
            }
        }
        offset++;
        node += n;
        /* Reset hash address ready for use as OTS and LTREE. */
        addr[XMSS_ADDR_TREE_HEIGHT] = 0;
        addr[XMSS_ADDR_TREE_INDEX] = 0;
    }

    /* Copy the root node. */
    XMEMCPY(root, state->stack, n);
}
#endif /* !WOLFSSL_SMALL_STACK */

/********************************************
 * MAKE KEY
 ********************************************/

/* Derives XMSSMT (and XMSS) key pair from seeds.
 *
 * RFC 8391: 4.1.7, Algorithm 10: XMSS_keyGen.
 *     ...
 *     initialize SK_PRF with a uniformly random n-byte string;
 *     setSK_PRF(SK, SK_PRF);
 *
 *     # Initialization for common contents
 *     initialize SEED with a uniformly random n-byte string;
 *     setSEED(SK, SEED);
 *     setWOTS_SK(SK, wots_sk));
 *     ADRS = toByte(0, 32);
 *     root = treeHash(SK, 0, h, ADRS);
 *
 *     SK = idx || wots_sk || SK_PRF || root || SEED;
 *     PK = OID || root || SEED;
 *     return (SK || PK);
 *
 * wots_sk, SK_PRF and SEED passed in as seed.
 * Store seed for wots_sk instead of generated wots_sk.
 * OID not stored in PK this is handled in upper layer.
 *
 * @param [in]  state   XMSS/MT state including digest and parameters.
 * @param [in]  seed    Random seeds.
 * @param [out] sk      Secret/Private key.
 * @param [out] pk      Public key.
 * @return  0 on success.
 * @return  <0 on digest failure.
 */
int wc_xmssmt_keygen(XmssState* state, const unsigned char* seed,
    unsigned char* sk, unsigned char* pk)
{
    const XmssParams* params = state->params;
    const word8 n = params->n;
    const byte* seed_priv = seed;
    const byte* seed_pub  = seed + 2 * n;
    /* Offsets into secret/private key. */
    byte* sk_idx  = sk;
    byte* sk_seed = sk_idx + params->idx_len;
    byte* sk_pub  = sk_seed + 2 * n;
    /* Offsets into public key. */
    byte* pk_root = pk;
    byte* pk_seed = pk_root + n;

    /* Set first index to 0 in private key. */
    XMEMSET(sk_idx, 0, params->idx_len);
    /* Set private key seed and private key for PRF in to private key. */
    XMEMCPY(sk_seed, seed_priv, 2 * n);
    /* Set public key seed into public key. */
    XMEMCPY(pk_seed, seed_pub, n);

    /* Set all address values to zero. */
    XMEMSET(state->addr, 0, sizeof(HashAddress));
    /* Set depth into address. */
    state->addr[XMSS_ADDR_LAYER] = params->d - 1;
    /* Compute root node into public key. */
    wc_xmss_treehash(state, sk_seed, pk_seed, 0, state->addr, pk_root, NULL);

    /* Append public key (root node and public seed) to private key. */
    XMEMCPY(sk_pub, pk_root, 2 * n);

    /* Return any errors that occurred during hashing. */
    return state->ret;
}

/********************************************
 * SIGN
 ********************************************/

/**
 * Sign message using XMSS/XMSS^MT.
 *
 * RFC 8391: 4.1.9, Algorithm 11: treeSig
 *     auth = buildAuth(SK, idx_sig, ADRS);
 *     ADRS.setType(0);   # Type = OTS hash address
 *     ADRS.setOTSAddress(idx_sig);
 *     sig_ots = WOTS_sign(getWOTS_SK(SK, idx_sig),
 *                         M', getSEED(SK), ADRS);
 *     Sig = sig_ots || auth;
 *     return Sig;
 * RFC 8391: 4.2.4, Algorithm 16: XMSSMT_sign
 *     # Init
 *     ADRS = toByte(0, 32);
 *     SEED = getSEED(SK_MT);
 *     SK_PRF = getSK_PRF(SK_MT);
 *     idx_sig = getIdx(SK_MT);
 *
 *     # Update SK_MT
 *     setIdx(SK_MT, idx_sig + 1);
 *
 *     # Message compression
 *     byte[n] r = PRF(SK_PRF, toByte(idx_sig, 32));
 *     byte[n] M' = H_msg(r || getRoot(SK_MT) || (toByte(idx_sig, n)), M);
 *
 *     # Sign
 *     Sig_MT = idx_sig;
 *     unsigned int idx_tree
 *                   = (h - h / d) most significant bits of idx_sig;
 *     unsigned int idx_leaf = (h / d) least significant bits of idx_sig;
 *     SK = idx_leaf || getXMSS_SK(SK_MT, idx_tree, 0) || SK_PRF
 *           || toByte(0, n) || SEED;
 *     ADRS.setLayerAddress(0);
 *     ADRS.setTreeAddress(idx_tree);
 *     Sig_tmp = treeSig(M', SK, idx_leaf, ADRS);
 *     Sig_MT = Sig_MT || r || Sig_tmp;
 *     for ( j = 1; j < d; j++ ) {
 *        root = treeHash(SK, 0, h / d, ADRS);
 *        idx_leaf = (h / d) least significant bits of idx_tree;
 *        idx_tree = (h - j * (h / d)) most significant bits of idx_tree;
 *        SK = idx_leaf || getXMSS_SK(SK_MT, idx_tree, j) || SK_PRF
 *               || toByte(0, n) || SEED;
 *        ADRS.setLayerAddress(j);
 *        ADRS.setTreeAddress(idx_tree);
 *        Sig_tmp = treeSig(root, SK, idx_leaf, ADRS);
 *        Sig_MT = Sig_MT || Sig_tmp;
 *     }
 *     return SK_MT || Sig_MT
 *
 * buildAuth from treeSig done inside treeHash as this is more efficient.
 *
 * @param [in]      state   XMSS/MT state including digest and parameters.
 * @param [in]      m       Buffer holding message.
 * @param [in]      mlen    Length of message in buffer.
 * @param [in, out] sk      Secret/Private key.
 * @param [out]     sig     Signature.
 * @return  0 on success.
 * @return  <0 on digest failure.
 */
int wc_xmssmt_sign(XmssState* state, const unsigned char* m, word32 mlen,
    unsigned char* sk, unsigned char* sig)
{
    int ret = 0;
    const XmssParams* params = state->params;
    const word8 n = params->n;
    const word8 hs = params->sub_h;
    const word16 hsn = (word16)hs * n;
    const byte* sk_seed = sk + params->idx_len;
    const byte* pk_seed = sk + params->idx_len + 3 * n;
    wc_Idx idx;
    byte* sig_r = sig + params->idx_len;
    byte root[WC_XMSS_MAX_N];
    unsigned int i;

    WC_IDX_ZERO(idx);
    /* Set all address values to zero and set type to OTS. */
    XMEMSET(state->addr, 0, sizeof(HashAddress));
    state->addr[XMSS_ADDR_TYPE] = WC_XMSS_ADDR_TYPE_OTS;

    /* Copy the index into the signature data: Sig_MT = idx_sig. */
    XMEMCPY(sig, sk, params->idx_len);

    /* Read index from the secret key. */
    WC_IDX_DECODE(idx, params->idx_len, sk, ret);
    /* Validate index in secret key. */
    if ((ret == 0) && (WC_IDX_INVALID(idx, params->idx_len, params->h))) {
        /* Set index to maximum value to distinguish from valid value. */
        XMEMSET(sk, 0xFF, params->idx_len);
        /* Zeroize the secret key. */
        ForceZero(sk + params->idx_len, params->sk_len - params->idx_len);
        ret = KEY_EXHAUSTED_E;
    }

    /* Update SK_MT */
    if (ret == 0) {
        /* Increment the index in the secret key. */
        wc_idx_update(sk, params->idx_len);
    }

    /* Message compression */
    if (ret == 0) {
        const byte* sk_prf = sk + params->idx_len + n;

        /* byte[n] r = PRF(SK_PRF, toByte(idx_sig, 32)); */
        wc_idx_copy(sig, params->idx_len, state->buf, XMSS_PRF_M_LEN);
        wc_xmss_prf(state, sk_prf, state->buf, sig_r);
        ret = state->ret;
    }
    if (ret == 0) {
        const byte* pub_root = sk + params->idx_len + 2 * n;
        /* byte[n] M' = H_msg(r || getRoot(SK_MT) || (toByte(idx_sig, n)), M);
         */
        wc_xmss_hash_message(state, sig_r, pub_root, sig, params->idx_len, m,
            mlen, root);
        ret = state->ret;
        /* Place WOTS+ signatures after index and 'r'. */
        sig += params->idx_len + n;
    }

    /* Sign. */
    for (i = 0; (ret == 0) && (i < params->d); i++) {
        word32 idx_leaf = 0;

        /* Set layer, tree and OTS leaf index into hash address. */
        state->addr[XMSS_ADDR_LAYER] = i;
        WC_IDX_SET_ADDR_TREE(idx, params->idx_len, hs, state->addr, idx_leaf);
        /* treeSig || treeHash = sig_ots || auth */
        state->addr[XMSS_ADDR_OTS] = idx_leaf;
        /*   Create WOTS+ signature for tree into signature (sig_ots). */
        wc_xmss_wots_sign(state, root, sk_seed, pk_seed, state->addr, sig);
        ret = state->ret;
        if (ret == 0) {
            sig += params->wots_sig_len;
            /*   Add authentication path (auth) and calc new root. */
            wc_xmss_treehash(state, sk_seed, pk_seed, idx_leaf, state->addr,
                root, sig);
            ret = state->ret;
            sig += hsn;
        }
    }

    return ret;
}

#else

/********************************************
 * Fast C implementation
 ********************************************/

/* Tree hash data - needs to be unpacked from binary. */
typedef struct TreeHash {
    /* Next index to update in tree - max 20 bits. */
    word32 nextIdx;
    /* Number of stack entries used by tree - 0..<subtree height>. */
    word8  used;
    /* Tree is finished. */
    word8  completed;
} TreeHash;

/* BDS state. */
typedef struct BdsState {
    /* Stack of nodes - subtree height + 1 nodes. */
    byte*     stack;
    /* Height of stack node - subtree height + 1 of 0..<subtree height - 1>. */
    byte*     height;
    /* Authentication path for next index - subtree height nodes. */
    byte*     authPath;
    /* Hashes of nodes kept - subtree height / 2 nodes. */
    byte*     keep;
    /* Tree hash instances - subtree height minus K instances. */
    byte*     treeHash;
    /* Hashes of nodes for tree hash - one for each tree hash instance. */
    byte*     treeHashNode;
    /* Hashes of nodes to retain - based on K parameter. */
    byte*     retain;
    /* Next leaf to calculate - max 20 bits. */
    word32    next;
    /* Current offset into stack - 0..<subtree height>. */
    word8     offset;
} BdsState;

/* Index to BDS state accounting for swapping.
 *
 * @param [in] idx  Index of node.
 * @param [in] i    Depth of tree.
 * @param [in] hs   Height of subtree.
 * @param [in] d    Depth/number of trees.
 * @return  Index of working BDS state.
 */
#define BDS_IDX(idx, i, hs, d)      \
    (((((idx) >> ((hs) * ((i) + 1))) & 1) == 0) ? (i) : ((d) + (i)))
/* Index to alternate BDS state accounting for swapping.
 *
 * @param [in] idx  Index of node.
 * @param [in] i    Depth of tree.
 * @param [in] hs   Height of subtree.
 * @param [in] d    Depth/number of trees.
 * @return  Index of alternate BDS state.
 */
#define BDS_ALT_IDX(idx, i, hs, d)  \
    (((((idx) >> ((hs) * ((i) + 1))) & 1) == 0) ? ((d) + (i)) : (i))

/********************************************
 * Tree Hash APIs
 ********************************************/

/* Initialize the tree hash data at specified index for the BDS state.
 *
 * @param [in, out] bds  BDS state.
 * @param [in]      i    Index of tree hash.
 */
static void wc_xmss_bds_state_treehash_init(BdsState* bds, int i)
{
    byte* sk = bds->treeHash + i * 4;
    c32to24(0, sk);
    sk[3] = 0 | (1 << 7);
}

/* Set next index into tree hash data at specified index for the BDS state.
 *
 * @param [in, out] bds      BDS state.
 * @param [in]      i        Index of tree hash.
 * @param [in]      nextIdx  Next index for tree hash.
 */
static void wc_xmss_bds_state_treehash_set_next_idx(BdsState* bds, int i,
    word32 nextIdx)
{
    byte* sk = bds->treeHash + i * 4;
    c32to24(nextIdx, sk);
    sk[3] = 0 | (0 << 7);
}

/* Mark tree hash, at specified index for the BDS state, as complete.
 *
 * @param [in, out] bds  BDS state.
 * @param [in]      i    Index of tree hash.
 */
static void wc_xmss_bds_state_treehash_complete(BdsState* bds, int i)
{
    byte* sk = bds->treeHash + i * 4;
    sk[3] |= 1 << 7;
}

/* Get the tree hash data at specified index for the BDS state.
 *
 * @param [in]  bds       BDS state.
 * @param [in]  i         Index of tree hash.
 * @param [out] treeHash  Tree hash instance to fill out.
 */
static void wc_xmss_bds_state_treehash_get(BdsState* bds, int i,
    TreeHash* treeHash)
{
    byte* sk = bds->treeHash + i * 4;
    ato24(sk, &treeHash->nextIdx);
    treeHash->used = sk[3] & 0x7f;
    treeHash->completed = sk[3] >> 7;
}

/* Set the tree hash data at specified index for the BDS state.
 *
 * @param [in, out]  bds       BDS state.
 * @param [in]       i         Index of tree hash.
 * @param [in]       treeHash  Tree hash data.
 */
static void wc_xmss_bds_state_treehash_set(BdsState* bds, int i,
    TreeHash* treeHash)
{
    byte* sk = bds->treeHash + i * 4;
    c32to24(treeHash->nextIdx, sk);
    sk[3] = treeHash->used | (treeHash->completed << 7);
}

/********************************************
 * BDS State APIs
 ********************************************/

/* Allocate memory for BDS state.
 *
 * When using a static BDS state (XMSS) then pass in handle to data for bds.
 *
 * @param [in]      params    XMSS/MT parameters.
 * @param [in, out] bds       Handle to BDS state. May be NULL if not allocated.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int wc_xmss_bds_state_alloc(const XmssParams* params, BdsState** bds)
{
    const word8 cnt = 2 * params->d - 1;
    int ret = 0;

    if (*bds == NULL) {
        /* Allocate memory for BDS states. */
        *bds = (BdsState*)XMALLOC(sizeof(BdsState) * cnt, NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (*bds == NULL) {
            ret = MEMORY_E;
        }
    }

    return ret;
}

/* Dispose of allocated memory associated with BDS state.
 *
 * @param [in] bds    BDS state.
 */
static void wc_xmss_bds_state_free(BdsState* bds)
{
    /* BDS states was allocated - must free. */
    XFREE(bds, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

/* Load the BDS state from the secret/private key.
 *
 * @param [in]  state      XMSS/MT state including digest and parameters.
 * @param [in]  sk         Secret/private key.
 * @param [out] bds        BDS states.
 * @param [out] wots_sigs  WOTS signatures when XMSS^MT.
 */
static void wc_xmss_bds_state_load(const XmssState* state, byte* sk,
    BdsState* bds, byte** wots_sigs)
{
    const XmssParams* params = state->params;
    const word8 n = params->n;
    const word8 hs = params->sub_h;
    const word8 hsk = params->sub_h - params->bds_k;
    const word8 k = params->bds_k;
    const word32 retainLen = XMSS_RETAIN_LEN(k, n);
    int i;

    /* Skip past standard SK = idx || wots_sk || SK_PRF || root || SEED; */
    sk += params->idx_len + 4 * n;

    for (i = 0; i < 2 * (int)params->d - 1; i++) {
        /* Set pointers into SK. */
        bds[i].stack = sk;
        sk += (hs + 1) * n;
        bds[i].height = sk;
        sk += hs + 1;
        bds[i].authPath = sk;
        sk += hs * n;
        bds[i].keep = sk;
        sk += (hs >> 1) * n;
        bds[i].treeHash = sk;
        sk += hsk * 4;
        bds[i].treeHashNode = sk;
        sk += hsk * n;
        bds[i].retain = sk;
        sk += retainLen;
        /* Load values - big-endian encoded. */
        ato24(sk, &bds[i].next);
        sk += 3;
        bds[i].offset = sk[0];
        sk += 1;
    }

    if (wots_sigs != NULL) {
        *wots_sigs = sk;
    }
}

/* Store the BDS state into the secret/private key.
 *
 * @param [in]      state   XMSS/MT state including digest and parameters.
 * @param [in, out] sk      Secret/private key.
 * @param [in]      bds     BDS states.
 */
static void wc_xmss_bds_state_store(const XmssState* state, byte* sk,
    BdsState* bds)
{
    int i;
    const XmssParams* params = state->params;
    const word8 n = params->n;
    const word8 hs = params->sub_h;
    const word8 hsk = params->sub_h - params->bds_k;
    const word8 k = params->bds_k;
    const word32 skip = (hs + 1) * n +            /* BdsState.stack */
                        hs + 1 +                  /* BdsState.height */
                        hs * n +                  /* BdsState.authPath */
                        (hs >> 1) * n +           /* BdsState.keep */
                        hsk * 4 +                 /* BdsState.treeHash */
                        hsk * n +                 /* BdsState.treeHashNode */
                        XMSS_RETAIN_LEN(k, n);    /* BdsState.retain */

    /* Ignore standard SK = idx || wots_sk || SK_PRF || root || SEED; */
    sk += params->idx_len + 4 * n;

    for (i = 0; i < 2 * (int)params->d - 1; i++) {
        /* Skip pointers into sk. */
        sk += skip;
        /* Save values - big-endian encoded. */
        c32to24(bds[i].next, sk);
        sk += 3;
        sk[0] = bds[i].offset;
        sk += 1;
    }
}

/********************************************
 * BDS
 ********************************************/

/* Compute node at next index.
 *
 * RFC 8391: 4.1.6, Algorithm 9: treeHash
 *       ...
 *       ADRS.setType(0);   # Type = OTS hash address
 *       ADRS.setOTSAddress(s + i);
 *       pk = WOTS_genPK (getWOTS_SK(SK, s + i), SEED, ADRS);
 *       ADRS.setType(1);   # Type = L-tree address
 *       ADRS.setLTreeAddress(s + i);
 *       node = ltree(pk, SEED, ADRS);
 *       ADRS.setType(2);   # Type = hash tree address
 *       ADRS.setTreeHeight(0);
 *       ADRS.setTreeIndex(i + s);
 *       while ( Top node on Stack has same height t' as node ) {
 *          ADRS.setTreeIndex((ADRS.getTreeIndex() - 1) / 2);
 *          node = RAND_HASH(Stack.pop(), node, SEED, ADRS);
 *          ADRS.setTreeHeight(ADRS.getTreeHeight() + 1);
 *       }
 *       Stack.push(node);
 *       ...
 *
 * @param [in]  state    XMSS/MT state including digest and parameters.
 * @param [in]  bds      BDS state.
 * @param [in]  sk_seed  Random secret/private seed.
 * @param [in]  pk_seed  Random public seed.
 * @param [in]  addr     Hash address.
 * @param [out] root     Root node.
 */
static void wc_xmss_bds_next_idx(XmssState* state, BdsState* bds,
    const byte* sk_seed, const byte* pk_seed, HashAddress addr, int i,
    word8* height, word8* offset, word8** sp)
{
    const XmssParams* params = state->params;
    const word8 hs = params->sub_h;
    const word8 hsk = params->sub_h - params->bds_k;
    const word8 n = params->n;
    word8 o = *offset;
    word8* node = *sp;
    word8 h;

    /* Calculate WOTS+ public key. */
    addr[XMSS_ADDR_TYPE] = WC_XMSS_ADDR_TYPE_OTS;
    addr[XMSS_ADDR_OTS] = i;
    wc_xmss_wots_gen_pk(state, sk_seed, pk_seed, addr, state->pk);
    /* Calculate public value. */
    addr[XMSS_ADDR_TYPE] = WC_XMSS_ADDR_TYPE_LTREE;
    wc_xmss_ltree(state, state->pk, pk_seed, addr, node);
    addr[XMSS_ADDR_TYPE] = WC_XMSS_ADDR_TYPE_TREE;
    addr[XMSS_ADDR_TREE_ZERO] = 0;

    /* Initial height at this offset is 0. */
    h = height[o] = 0;
    /* HDSS, Section 4.5, 2: TREEHASH[h].push(v[h][3])
     * Copy right node to tree hash nodes if second right node. */
    if ((hsk > 0) && (i == 3)) {
        XMEMCPY(bds->treeHashNode, node + n, n);
    }

    /* Top node on Stack has same height t' as node. */
    while ((o >= 1) && (h == height[o - 1])) {
        /* HDSS, Section 4.5, 1: AUTH[h] = v[h][1], h = 0,...,H-1.
         * Cache left node if on authentication path. */
        if ((i >> h) == 1) {
            XMEMCPY(bds->authPath + h * n, node, n);
        }
        /* This is a right node. */
        else if (h < hsk) {
            /* HDSS, Section 4.5, 2: TREEHASH[h].push(v[h][3])
             * Copy right node to tree hash if second right node. */
            if ((i >> h) == 3) {
                XMEMCPY(bds->treeHashNode + h * n, node, n);
            }
        }
        else {
            /* HDSS, Section 4.5, 3: RETAIN[h].push(v[j][2j+3] for
             *   h = H-K,...,H-2 and j = 2^(H-h-1)-2,...,0.
             * Retain high right nodes.
             */
            word32 ro = (1 << (hs - 1 - h)) + h - hs + (((i >> h) - 3) >> 1);
            XMEMCPY(bds->retain + ro * n, node, n);
        }

        node -= n;
        /* Calculate hash of node. */
        addr[XMSS_ADDR_TREE_HEIGHT] = h;
        addr[XMSS_ADDR_TREE_INDEX] = i >> (h + 1);
        wc_xmss_rand_hash(state, node, pk_seed, addr, node);

        /* Update offset and height. */
        o--;
        h = ++height[o];
    }

    *offset = o;
    *sp = node;
}

/* Compute initial Merkle tree and store nodes.
 *
 * HDSS, Section 4.5, The algorithm, Initialization.
 *   1. We store the authentication path for the first leaf (s = 0):
 *   AUTH[h] = v[h][1], h = 0,...,H-1.
 *   2. Depending on the parameter K, we store the next right authentication
 *   node for each height h = 0,...,H-K-1 in the treehash instances:
 *   TREEHASH[h].push(v[h][3]).
 *   3. Finally we store the right authentication nodes clode to the root using
 *   the stacks RETAIN[h]:
 *   RETAIN[h].push(v[j][2j+3] for h = H-K,...,H-2 and j = 2^(H-h-1)-2,...,0.
 *
 * RFC 8391: 4.1.6, Algorithm 9: treeHash
 *     if( s % (1 << t) != 0 ) return -1;
 *     for ( i = 0; i < 2^t; i++ ) {
 *       SEED = getSEED(SK);
 *       [Compute node at next index]
 *     }
 *     return Stack.pop();
 *
 * @param [in]  state    XMSS/MT state including digest and parameters.
 * @param [in]  bds      BDS state.
 * @param [in]  sk_seed  Random secret/private seed.
 * @param [in]  pk_seed  Random public seed.
 * @param [in]  addr     Hash address.
 * @param [out] root     Root node.
 */
static void wc_xmss_bds_treehash_initial(XmssState* state, BdsState* bds,
    const byte* sk_seed, const byte* pk_seed, const HashAddress addr,
    byte* root)
{
    const XmssParams* params = state->params;
    const word8 hsk = params->sub_h - params->bds_k;
    const word8 n = params->n;
    word8* node = state->stack;
    HashAddress addrCopy;
    word8 height[WC_XMSS_MAX_TREE_HEIGHT + 1];
    word8 offset = 0;
    word32 maxIdx = (word32)1 << params->sub_h;
    word32 i;

    /* First signing index will be 0 - setup BDS state. */
    bds->offset = 0;
    bds->next = 0;
    /* Reset the hash tree status. */
    for (i = 0; i < hsk; i++) {
        wc_xmss_bds_state_treehash_init(bds, i);
    }

    /* Copy hash address into local. */
    XMSS_ADDR_OTS_SET_SUBTREE(addrCopy, addr);

    /* Compute each node in tree. */
    for (i = 0; i < maxIdx; i++) {
        wc_xmss_bds_next_idx(state, bds, sk_seed, pk_seed, addrCopy, i, height,
            &offset, &node);
        offset++;
        node += n;
        /* Rest the hash address for reuse. */
        addrCopy[XMSS_ADDR_TREE_HEIGHT] = 0;
        addrCopy[XMSS_ADDR_TREE_INDEX] = 0;
    }

    /* Copy the root node. */
    XMEMCPY(root, state->stack, n);
}

/* Update internal nodes of Merkle tree at next index.
 *
 * RFC 8391: 4.1.6, Algorithm 9: treeHash
 *       ...
 *       SEED = getSEED(SK);
 *       ADRS.setType(0);   # Type = OTS hash address
 *       ADRS.setOTSAddress(s + i);
 *       pk = WOTS_genPK (getWOTS_SK(SK, s + i), SEED, ADRS);
 *       ADRS.setType(1);   # Type = L-tree address
 *       ADRS.setLTreeAddress(s + i);
 *       node = ltree(pk, SEED, ADRS);
 *       ADRS.setType(2);   # Type = hash tree address
 *       ADRS.setTreeHeight(0);
 *       ADRS.setTreeIndex(i + s);
 *       while ( Top node on Stack has same height t' as node ) {
 *          ADRS.setTreeIndex((ADRS.getTreeIndex() - 1) / 2);
 *          node = RAND_HASH(Stack.pop(), node, SEED, ADRS);
 *          ADRS.setTreeHeight(ADRS.getTreeHeight() + 1);
 *       }
 *       Stack.push(node);
 *
 * @param [in]      state    XMSS/MT state including digest and parameters.
 * @param [in, out] bds      BDS state.
 * @param [in]      height   Height of nodes to update.
 * @param [in]      sk_seed  Random secret/private seed.
 * @param [in]      pk_seed  Random public seed.
 * @param [in]      addr     Hash address.
 */
static void wc_xmss_bds_treehash_update(XmssState* state, BdsState* bds,
    word8 height, const byte* sk_seed, const byte* pk_seed,
    const HashAddress addr)
{
    const XmssParams* params = state->params;
    const word8 n = params->n;
    HashAddress addrLocal;
    TreeHash treeHash[1];
    byte* sp = bds->stack + bds->offset * n;
    byte* node = state->stack + WC_XMSS_MAX_STACK_LEN - n;
    word8 h;

    /* Get the tree hash data. */
    wc_xmss_bds_state_treehash_get(bds, height, treeHash);
    /* Copy hash address into local as OTS type. */
    XMSS_ADDR_OTS_SET_SUBTREE(addrLocal, addr);
    /* Calculate WOTS+ public key. */
    addrLocal[XMSS_ADDR_OTS] = treeHash->nextIdx;
    wc_xmss_wots_gen_pk(state, sk_seed, pk_seed, addrLocal, state->pk);
    /* Calculate public value. */
    addrLocal[XMSS_ADDR_TYPE] = WC_XMSS_ADDR_TYPE_LTREE;
    wc_xmss_ltree(state, state->pk, pk_seed, addrLocal, node);
    addrLocal[XMSS_ADDR_TYPE] = WC_XMSS_ADDR_TYPE_TREE;
    addrLocal[XMSS_ADDR_TREE_ZERO] = 0;

    /* Initial height is 0. */
    h = 0;

    /* Top node on Stack has same height t' as node. */
    while ((treeHash->used > 0) && (h == bds->height[bds->offset - 1])) {
        sp -= n;
        /* Copy from stack to before last calculated node. */
        node -= n;
        XMEMCPY(node, sp, n);

        /* Calculate hash of node. */
        addrLocal[XMSS_ADDR_TREE_HEIGHT] = h;
        addrLocal[XMSS_ADDR_TREE_INDEX] = treeHash->nextIdx >> (h + 1);
        wc_xmss_rand_hash(state, node, pk_seed, addrLocal, node);

        /* Update used, offset and height. */
        treeHash->used--;
        bds->offset--;
        h++;
    }

    /* Check whether we reached the height we wanted to update. */
    if (h == height) {
        /* Cache node. */
        XMEMCPY(bds->treeHashNode + height * n, node, n);
        treeHash->completed = 1;
    }
    else {
        /* Push calculated node onto stack. */
        XMEMCPY(sp, node, n);
        treeHash->used++;
        /* Update BDS state. */
        bds->height[bds->offset] = h;
        bds->offset++;
        treeHash->nextIdx++;
    }

    /* Set the tree hash data back. */
    wc_xmss_bds_state_treehash_set(bds, height, treeHash);
}

/* Updates hash trees that need it most.
 *
 * Algorithm 4.6: Authentication path computation, Step 5.
 *
 * @param [in]      state    XMSS/MT state including digest and parameters.
 * @param [in, out] bds      BDS state.
 * @param [in]      updates  Current number of updates.
 * @param [in]      sk_seed  Random secret/private seed.
 * @param [in]      pk_seed  Random public seed.
 * @param [in]      addr     Hash address.
 * @return  Number of available updates.
 */
static word8 wc_xmss_bds_treehash_updates(XmssState* state, BdsState* bds,
    word8 updates, const byte* sk_seed, const byte* pk_seed,
    const HashAddress addr)
{
    const XmssParams* params = state->params;
    const word8 hs = params->sub_h;
    const word8 hsk = params->sub_h - params->bds_k;

    while (updates > 0) {
        word8 minH = hs;
        word8 h = hsk;
        word8 i;

        /* Step 5.a. k <- min{ h: TREEHASH(h).height() =
                                  min[j=0..H-K-1]{TREEHASH(j.height()} } */
        for (i = 0; i < hsk; i++) {
            TreeHash treeHash[1];

            wc_xmss_bds_state_treehash_get(bds, i, treeHash);

            if (treeHash->completed) {
                /* Finished - ignore. */
            }
            else if (treeHash->used == 0) {
                /* None used, low height. */
                if (i < minH) {
                    h = i;
                    minH = i;
                }
            }
            /* Find the height of lowest in cache. */
            else {
                word8 j;
                word8 lowH = hs;
                byte* height = bds->height + bds->offset - treeHash->used;

                for (j = 0; j < treeHash->used; j++) {
                    lowH = min(height[j], lowH);
                }
                if (lowH < minH) {
                    /* New lowest height. */
                    h = i;
                    minH = lowH;
                }
            }
        }
        /* If none lower, then stop. */
        if (h == hsk) {
            break;
        }

        /* Step 5.b. TREEHASH(k).update() */
        /* Update tree to the lowest height. */
        wc_xmss_bds_treehash_update(state, bds, h, sk_seed, pk_seed, addr);
        updates--;
    }
    return updates;
}

/* Update BDS at next leaf.
 *
 * Don't do anything if processed all leaves.
 *
 * @param [in]      state     XMSS/MT state including digest and parameters.
 * @param [in, out] bds       BDS state.
 * @param [in]      sk_seed   Random secret/private seed.
 * @param [in]      pk_seed   Random public seed.
 * @param [in]      addr      Hash address.
 */
static void wc_xmss_bds_update(XmssState* state, BdsState* bds,
    const byte* sk_seed, const byte* pk_seed, const HashAddress addr)
{
    if (bds->next < ((word32)1 << state->params->sub_h)) {
        const XmssParams* params = state->params;
        byte* sp = bds->stack + bds->offset * params->n;
        HashAddress addrCopy;

        XMSS_ADDR_OTS_SET_SUBTREE(addrCopy, addr);
        wc_xmss_bds_next_idx(state, bds, sk_seed, pk_seed, addrCopy, bds->next,
            bds->height, &bds->offset, &sp);
        bds->offset++;
        bds->next++;
    }
}

/* Find index of lowest zero bit.
 *
 * Supports max up to 31.
 *
 * @param [in]  n    Number to evaluate.
 * @param [in]  max  Max number of bits.
 * @param [out] b    Next bit above first zero bit.
 * @return  Index of lowest bit that is zero.
 */
static word8 wc_xmss_lowest_zero_bit_index(word32 n, word8 max, word8* b)
{
    word8 i;

    /* Check each bit from lowest for a zero bit. */
    for (i = 0; i < max; i++) {
        if ((n & 1) == 0) {
            break;
        }
        n >>= 1;
    }

    /* Return next bit after 0 bit. */
    *b = (n >> 1) & 1;
    return i;
}

/* Returns auth path for node leafIdx and computes for next leaf node.
 *
 * HDSS, Algorithm 4.6: Authentication path computation, Steps 1-4.
 *
 * @param [in]      state    XMSS/MT state including digest and parameters.
 * @param [in, out] bds      BDS state.
 * @param [in]      leafIdx  Current leaf index.
 * @param [in]      sk_seed  Random secret/private seed.
 * @param [in]      pk_seed  Random public seed.
 * @param [in]      addr     Hash address.
 */
static void wc_xmss_bds_auth_path(XmssState* state, BdsState* bds,
    const word32 leafIdx, const byte* sk_seed, const byte* pk_seed,
    HashAddress addr)
{
    const XmssParams* params = state->params;
    const word8 n = params->n;
    const word8 hs = params->sub_h;
    const word8 hsk = params->sub_h - params->bds_k;
    word8 tau;
    byte* node = state->encMsg;
    word8 parent;

    /* Step 1. Find the height of first left node in authentication path. */
    tau = wc_xmss_lowest_zero_bit_index(leafIdx, hs, &parent);
    if (tau == 0) {
        /* Step 2. Keep node if parent is a left node.
         *     if s/(2^tau+1) is even and tau < H-1 then KEEP[tau] <- AUTH[tau]
         */
        if (parent == 0) {
            XMEMCPY(bds->keep, bds->authPath, n);
        }

        /* Step 3. if tau = 0 then AUTH[0] <- LEAFCALC(s) */
        /* Calculate WOTS+ public key. */
        addr[XMSS_ADDR_TYPE] = WC_XMSS_ADDR_TYPE_OTS;
        addr[XMSS_ADDR_OTS] = leafIdx;
        wc_xmss_wots_gen_pk(state, sk_seed, pk_seed, addr, state->pk);
        /* Calculate public value. */
        addr[XMSS_ADDR_TYPE] = WC_XMSS_ADDR_TYPE_LTREE;
        wc_xmss_ltree(state, state->pk, pk_seed, addr, bds->authPath);
    }
    else {
        byte* authPath;
        byte* nodes;
        word8 i;

        authPath = bds->authPath + tau * n;
        /* Step 4.a. <node> = AUTH[tau-1] || KEEP[tau-1]
         * Only keeping half of nodes, so need to copy out before updating.
         */
        XMEMCPY(node, authPath - n, n);
        XMEMCPY(node + n, bds->keep + ((tau - 1) >> 1) * n, n);

        /* Step 2. Keep node if parent is a left node.
         *     if s/(2^tau+1) is even and tau < H-1 then KEEP[tau] <- AUTH[tau]
         */
        if ((tau < hs - 1) && (parent == 0)) {
            XMEMCPY(bds->keep + (tau >> 1) * n, authPath, n);
        }

        /* Step 4.a. AUTH[tau] <- g(<node>) */
        addr[XMSS_ADDR_TYPE] = WC_XMSS_ADDR_TYPE_TREE;
        addr[XMSS_ADDR_TREE_ZERO] = 0;
        addr[XMSS_ADDR_TREE_HEIGHT] = tau - 1;
        addr[XMSS_ADDR_TREE_INDEX] = leafIdx >> tau;
        wc_xmss_rand_hash(state, node, pk_seed, addr, authPath);

        /* Step 4.b. <Calculate new right nodes on lower heights> */
        authPath = bds->authPath;
        nodes = bds->treeHashNode;
        /*   for h = 0 to tau - 1 do */
        for (i = 0; i < tau; i++) {
            /*   if h < H - K then AUTH[h] <- TREEHASH[h].pop()*/
            if (i < hsk) {
                XMEMCPY(authPath, nodes, n);
                nodes += n;
            }
            /*   if h >= H - K then AUTH[h] <- RETAIN[h].pop()*/
            else {
                word32 o = (1 << (hs - 1 - i)) + i - hs +
                           (((leafIdx >> i) - 1) >> 1);
                XMEMCPY(authPath, bds->retain + o * n, n);
            }
            authPath += n;
        }

        /* Step 4.c. Initialize treehash instances for heights:
         *           0, ..., min{tau-1, H - K - 1} */
        tau = min(tau, hsk);
        for (i = 0; i < tau; i++) {
            word32 startIdx = leafIdx + 1 + 3 * (1 << i);
            if (startIdx < ((word32)1 << hs)) {
                wc_xmss_bds_state_treehash_set_next_idx(bds, i, startIdx);
            }
        }
    }
}

/********************************************
 * XMSS
 ********************************************/

/* Derives XMSS key pair from seeds.
 *
 * RFC 8391: 4.1.7, Algorithm 10: XMSS_keyGen.
 *     ...
 *     initialize SK_PRF with a uniformly random n-byte string;
 *     setSK_PRF(SK, SK_PRF);
 *
 *     # Initialization for common contents
 *     initialize SEED with a uniformly random n-byte string;
 *     setSEED(SK, SEED);
 *     setWOTS_SK(SK, wots_sk));
 *     ADRS = toByte(0, 32);
 *     root = treeHash(SK, 0, h, ADRS);
 *
 *     SK = idx || wots_sk || SK_PRF || root || SEED;
 *     PK = OID || root || SEED;
 *     return (SK || PK);
 *
 * HDSS, Section 4.5, The algorithm, Initialization.
 *
 * wots_sk, SK_PRF and SEED passed in as seed.
 * Store seed for wots_sk instead of generated wots_sk.
 * OID not stored in PK this is handled in upper layer.
 * BDS state is appended to SK:
 *     SK = idx || wots_sk || SK_PRF || root || SEED || BDS_STATE;
 *
 * @param [in]  state  XMSS/MT state including digest and parameters.
 * @param [in]  seed   Secret/Private and public seed.
 * @param [out] sk     Secret key.
 * @param [out] pk     Public key.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  <0 on digest failure.
 */
int wc_xmss_keygen(XmssState* state, const unsigned char* seed,
    unsigned char* sk, unsigned char* pk)
{
#if WOLFSSL_XMSS_MIN_HEIGHT <= 32
    int ret = 0;
    const XmssParams* params = state->params;
    const word8 n = params->n;
    /* Offset of root node in public key. */
    byte* pk_root = pk;
#ifdef WOLFSSL_SMALL_STACK
    BdsState* bds = NULL;
#else
    BdsState bds[1];
#endif

#ifdef WOLFSSL_SMALL_STACK
    /* Allocate memory for tree hash instances and put in BDS state. */
    ret = wc_xmss_bds_state_alloc(params, &bds);
    if (ret == 0)
#endif
    {
        /* Offsets into seed. */
        const byte* seed_priv = seed;
        const byte* seed_pub = seed + 2 * n;
        /* Offsets into secret/private key. */
        word32* sk_idx = (word32*)sk;
        byte* sk_seeds = sk + params->idx_len;
        /* Offsets into public key. */
        byte* pk_seed = pk + n;

        /* Setup pointers into sk - assumes sk is initialized to zeros. */
        wc_xmss_bds_state_load(state, sk, bds, NULL);

        /* Set first index to 0 in private key. idx_len always 4. */
        *sk_idx = 0;
        /* Set private key seed and private key for PRF in to private key. */
        XMEMCPY(sk_seeds, seed_priv, 2 * n);
        /* Set public key seed into public key. */
        XMEMCPY(pk_seed, seed_pub, n);

        /* Set all address values to zero. */
        XMEMSET(state->addr, 0, sizeof(HashAddress));
        /* Hash address layer is 0. */
        /* Compute root node into public key. */
        wc_xmss_bds_treehash_initial(state, bds, sk_seeds, pk_seed,
            state->addr, pk_root);
        /* Return any errors that occurred during hashing. */
        ret = state->ret;
    }
    if (ret == 0) {
        /* Offset of root node in private key. */
        byte* sk_root = sk + params->idx_len + 2 * n;

        /* Append public key (root node and public seed) to private key. */
        XMEMCPY(sk_root, pk_root, 2 * n);

        /* Store BDS state back into secret/private key. */
        wc_xmss_bds_state_store(state, sk, bds);
    }

#ifdef WOLFSSL_SMALL_STACK
    /* Dispose of allocated data of BDS states. */
    wc_xmss_bds_state_free(bds);
#endif
    return ret;
#else
    (void)state;
    (void)pk;
    (void)sk;
    (void)seed;

    return NOT_COMPILED_IN;
#endif /* WOLFSSL_XMSS_MIN_HEIGHT <= 32 */
}

/* Sign a message with XMSS.
 *
 * RFC 8391: 4.1.9, Algorithm 11: treeSig
 *     ...
 *     ADRS.setType(0);   # Type = OTS hash address
 *     ADRS.setOTSAddress(idx_sig);
 *     sig_ots = WOTS_sign(getWOTS_SK(SK, idx_sig),
 *                         M', getSEED(SK), ADRS);
 *     Sig = sig_ots || auth;
 *     return Sig;
 * RFC 8391: 4.1.9, Algorithm 12: XMSS_sign
 *     idx_sig = getIdx(SK);
 *     setIdx(SK, idx_sig + 1);
 *     ADRS = toByte(0, 32);
 *     byte[n] r = PRF(getSK_PRF(SK), toByte(idx_sig, 32));
 *     byte[n] M' = H_msg(r || getRoot(SK) || (toByte(idx_sig, n)), M);
 *     Sig = idx_sig || r || treeSig(M', SK, idx_sig, ADRS);
 *     return (SK || Sig);
 *
 * HDSS, Section 4.5, The algorithm, Update and output phase.
 *
 * 'auth' was built at key generation or after computing previous signature.
 * Build next authentication path after signature created.
 *
 * @param [in]      state   XMSS/MT state including digest and parameters.
 * @param [in]      m       Buffer holding message.
 * @param [in]      mlen    Length of message in buffer.
 * @param [in, out] sk      Secret/Private key.
 * @param [out]     sm      Signature and message data.
 * @param [in, out] smlen   On in, length of signature and message buffer.
 *                          On out, length of signature and message data.
 * @return  0 on success.
 * @return  <0 on digest failure.
 */
int wc_xmss_sign(XmssState* state, const unsigned char* m, word32 mlen,
    unsigned char* sk, unsigned char* sig)
{
#if WOLFSSL_XMSS_MIN_HEIGHT <= 32
    int ret = 0;
    const XmssParams* params = state->params;
    const word8 n = params->n;
    const word8 h = params->h;
    const word8 hk = params->h - params->bds_k;
    const byte* sk_seed = sk + XMSS_IDX_LEN;
    const byte* pk_seed = sk + XMSS_IDX_LEN + 3 * n;
    byte node[WC_XMSS_MAX_N];
    word32 idx;
    byte* sig_r = sig + XMSS_IDX_LEN;
#ifdef WOLFSSL_SMALL_STACK
    BdsState* bds = NULL;
#else
    BdsState bds[1];
#endif

#ifdef WOLFSSL_SMALL_STACK
    /* Allocate memory for tree hash instances and put in BDS state. */
    ret = wc_xmss_bds_state_alloc(params, &bds);
    if (ret == 0)
#endif
    {
        /* Load the BDS state from secret/private key. */
        wc_xmss_bds_state_load(state, sk, bds, NULL);

        /* Copy the index into the signature data: Sig = idx_sig || ... */
        *((word32*)sig) = *((word32*)sk);
        /* Read index from the secret key. */
        ato32(sk, &idx);

        /* Check index is valid. */
        if (IDX32_INVALID(idx, XMSS_IDX_LEN, h)) {
            /* Set index to maximum value to distinguish from valid value. */
            XMEMSET(sk, 0xFF, XMSS_IDX_LEN);
            /* Zeroize the secret key. */
            ForceZero(sk + XMSS_IDX_LEN, params->sk_len - XMSS_IDX_LEN);
            ret = KEY_EXHAUSTED_E;
        }
    }

    /* Update SK_MT */
    if (ret == 0) {
        /* Increment the index in the secret key. */
        c32toa(idx + 1, sk);
    }

    /* Message compression */
    if (ret == 0) {
        const byte* sk_prf = sk + XMSS_IDX_LEN + n;

        /* byte[n] r = PRF(SK_PRF, toByte(idx_sig, 32)); */
        wc_idx_copy(sig, params->idx_len, state->buf, XMSS_PRF_M_LEN);
        wc_xmss_prf(state, sk_prf, state->buf, sig_r);
        ret = state->ret;
    }
    if (ret == 0) {
        const byte* pub_root = sk + XMSS_IDX_LEN + 2 * n;

        /* Compute the message hash. */
        wc_xmss_hash_message(state, sig_r, pub_root, sig, XMSS_IDX_LEN, m, mlen,
            node);
        ret = state->ret;
        /* Place new signature data after index and 'r'. */
        sig += XMSS_IDX_LEN + n;
    }

    if (ret == 0) {
        /* Set all address values to zero and set type to OTS. */
        XMEMSET(state->addr, 0, sizeof(HashAddress));
        state->addr[XMSS_ADDR_TYPE] = WC_XMSS_ADDR_TYPE_OTS;
        /* treeSig || treeHash = sig_ots || auth */
        state->addr[XMSS_ADDR_OTS] = idx;
        /*   Create WOTS+ signature for tree into signature (sig_ots). */
        wc_xmss_wots_sign(state, node, sk_seed, pk_seed, state->addr, sig);
        ret = state->ret;
    }
    if (ret == 0) {
        sig += params->wots_sig_len;
        /*   Add authentication path (auth) and calc new root. */
        XMEMCPY(sig, bds->authPath, h * n);
        ret = state->ret;
    }

    if (ret == 0) {
        /* Update BDS state - update authentication path for next index. */
        /* Check not last node. */
        if (idx < ((word32)1 << h) - 1) {
            /* Calculate next authentication path node. */
            wc_xmss_bds_auth_path(state, bds, idx, sk_seed, pk_seed,
                state->addr);
            ret = state->ret;
            if (ret == 0) {
                /* Algorithm 4.6: Step 5. */
                wc_xmss_bds_treehash_updates(state, bds, hk >> 1, sk_seed,
                    pk_seed, state->addr);
                ret = state->ret;
            }
        }
    }
    if (ret == 0) {
        /* Store BDS state back into secret/private key. */
        wc_xmss_bds_state_store(state, sk, bds);
    }

#ifdef WOLFSSL_SMALL_STACK
    /* Dispose of allocated data of BDS states. */
    wc_xmss_bds_state_free(bds);
#endif
    return ret;
#else
    (void)state;
    (void)m;
    (void)mlen;
    (void)sk;
    (void)sig;

    return NOT_COMPILED_IN;
#endif /* WOLFSSL_XMSS_MIN_HEIGHT <= 32 */
}

/********************************************
 * XMSS^MT
 ********************************************/

/* Generate a XMSS^MT key pair from seeds.
 *
 * RFC 8391: 4.2.2, Algorithm 15: XMSS^MT_keyGen.
 *     ...
 *     # Example initialization
 *     idx_MT = 0;
 *     setIdx(SK_MT, idx_MT);
 *     initialize SK_PRF with a uniformly random n-byte string;
 *     setSK_PRF(SK_MT, SK_PRF);
 *     initialize SEED with a uniformly random n-byte string;
 *     setSEED(SK_MT, SEED);
 *
 *     # Generate reduced XMSS private keys
 *     ADRS = toByte(0, 32);
 *     for ( layer = 0; layer < d; layer++ ) {
 *        ADRS.setLayerAddress(layer);
 *        for ( tree = 0; tree <
 *              (1 << ((d - 1 - layer) * (h / d)));
 *              tree++ ) {
 *           ADRS.setTreeAddress(tree);
 *           for ( i = 0; i < 2^(h / d); i++ ) {
 *             wots_sk[i] = WOTS_genSK();
 *           }
 *           setXMSS_SK(SK_MT, wots_sk, tree, layer);
 *        }
 *     }
 *
 *     SK = getXMSS_SK(SK_MT, 0, d - 1);
 *     setSEED(SK, SEED);
 *     root = treeHash(SK, 0, h / d, ADRS);
 *     setRoot(SK_MT, root);
 *
 *     PK_MT = OID || root || SEED;
 *     return (SK_MT || PK_MT);
 *
 * HDSS, Section 4.5, The algorithm, Initialization.
 * OPX, Section 2, Key Generation.
 *
 * wots_sk, SK_PRF and SEED passed in as seed.
 * Store seed for wots_sk instead of generated wots_sk.
 * OID not stored in PK this is handled in upper layer.
 * BDS state is appended to SK:
 *     SK = idx || wots_sk || SK_PRF || root || SEED || BDS_STATE;
 *
 * @param [in]  state   XMSS/MT state including digest and parameters.
 * @param [in]  seed    Secret/Private and public seed.
 * @param [out] sk      Secret key.
 * @param [out] pk      Public key.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  <0 on digest failure.
 */
int wc_xmssmt_keygen(XmssState* state, const unsigned char* seed,
    unsigned char* sk, unsigned char* pk)
{
    int ret = 0;
    const XmssParams* params = state->params;
    const word8 n = params->n;
    unsigned char* sk_seed = sk + params->idx_len;
    unsigned char* pk_root = pk;
    unsigned char* pk_seed = pk + n;
    word8 i;
    byte* wots_sigs;
    BdsState* bds = NULL;

    /* Allocate memory for BDS states and tree hash instances. */
    ret = wc_xmss_bds_state_alloc(params, &bds);
    if (ret == 0) {
        /* Offsets into seed. */
        const byte* seed_priv = seed;
        const byte* seed_pub  = seed + 2 * params->n;

        /* Load the BDS state from secret/private key. */
        wc_xmss_bds_state_load(state, sk, bds, &wots_sigs);

        /* Set first index to 0 in private key. */
        XMEMSET(sk, 0, params->idx_len);
        /* Set private key seed and private key for PRF in to private key. */
        XMEMCPY(sk_seed, seed_priv, 2 * n);
        /* Set public key seed into public key. */
        XMEMCPY(pk_seed, seed_pub, n);

        /* Set all address values to zero. */
        XMEMSET(state->addr, 0, sizeof(HashAddress));
        /* Hash address layer is 0 = bottom-most layer. */
    }

    /* Setup state and compute WOTS+ signatures for all but top-most subtree. */
    for (i = 0; (ret == 0) && (i < params->d - 1); i++) {
        /* Compute root for subtree. */
        wc_xmss_bds_treehash_initial(state, bds + i, sk_seed, pk_seed,
            state->addr, pk_root);
        ret = state->ret;
        if (ret == 0) {
            /* Create signature for subtree for first index. */
            state->addr[XMSS_ADDR_LAYER] = i+1;
            wc_xmss_wots_sign(state, pk_root, sk_seed, pk_seed, state->addr,
                wots_sigs + i * params->wots_sig_len);
            ret = state->ret;
        }
    }
    if (ret == 0) {
        /* Compute root for top-most subtree. */
        wc_xmss_bds_treehash_initial(state, bds + i, sk_seed, pk_seed,
            state->addr, pk_root);
        /* Return any errors that occurred during hashing. */
        ret = state->ret;
    }

    if (ret == 0) {
        /* Offset of root node in private key. */
        unsigned char* sk_root = sk_seed + 2 * n;

        /* Append public key (root node and public seed) to private key. */
        XMEMCPY(sk_root, pk_root, 2 * n);

        /* Store BDS state back into secret/private key. */
        wc_xmss_bds_state_store(state, sk, bds);
    }

    /* Dispose of allocated data of BDS states. */
    wc_xmss_bds_state_free(bds);
    return ret;
}


#if !defined(WORD64_AVAILABLE) && (WOLFSSL_XMSS_MAX_HEIGHT > 32)
    #error "Support not available - use XMSS small code option"
#endif

#if (WOLFSSL_XMSS_MAX_HEIGHT > 32)
    typedef word64 XmssIdx;
    #define IDX_MAX_BITS    64
#else
    typedef word32 XmssIdx;
    #define IDX_MAX_BITS    32
#endif

/* Decode index into word.
 *
 * @param [out] idx  Index from encoding.
 * @param [in]  c    Count of bytes to decode to index.
 * @param [in]  a    Array to decode from.
 */
static void xmss_idx_decode(XmssIdx* idx, word8 c, const unsigned char* a)
{
    word8 i;
    XmssIdx n = 0;

    for (i = 0; i < c; i++) {
        n <<= 8;
        n += a[i];
    }

    *idx = n;
}

/* Check whether index is valid.
 *
 * @param [in] i  Index to check.
 * @param [in] h  Full tree Height.
 */
static int xmss_idx_invalid(XmssIdx i, word8 h)
{
    return ((i + 1) >> h) != 0;
}

/* Get tree and leaf index from index.
 *
 * @param [in]  i  Index to split.
 * @param [in]  h  Tree height.
 * @param [out] t  Tree index.
 * @param [out] l  Leaf index.
 */
static void xmss_idx_get_tree_leaf(XmssIdx i, word8 h, XmssIdx* t, word32* l)
{
    *l = (word32)i & (((word32)1 << h) - 1);
    *t = i >> h;
}

/* Set the index into address as the tree index.
 *
 * @param [in]      i  Tree index.
 * @param [in, out] a  Hash address.
 */
static void xmss_idx_set_addr_tree(XmssIdx i, HashAddress a)
{
#if IDX_MAX_BITS == 32
    a[XMSS_ADDR_TREE_HI] = 0;
    a[XMSS_ADDR_TREE]    = i;
#else
    a[XMSS_ADDR_TREE_HI] = (word32)(i >> 32);
    a[XMSS_ADDR_TREE]    = (word32)(i      );
#endif
}

/* Sign message with XMSS^MT.
 *
 * RFC 8391: 4.1.9, Algorithm 11: treeSig
 *     ...
 *     ADRS.setType(0);   # Type = OTS hash address
 *     ADRS.setOTSAddress(idx_sig);
 *     sig_ots = WOTS_sign(getWOTS_SK(SK, idx_sig),
 *                         M', getSEED(SK), ADRS);
 *     Sig = sig_ots || auth;
 *     return Sig;
 * RFC 8391: 4.2.4, Algorithm 16: XMSS^MT_sign.
 *      ...
 *      # Init
 *     ADRS = toByte(0, 32);
 *     SEED = getSEED(SK_MT);
 *     SK_PRF = getSK_PRF(SK_MT);
 *     idx_sig = getIdx(SK_MT);
 *
 *     # Update SK_MT
 *     setIdx(SK_MT, idx_sig + 1);
 *
 *     # Message compression
 *     byte[n] r = PRF(SK_PRF, toByte(idx_sig, 32));
 *     byte[n] M' = H_msg(r || getRoot(SK_MT) || (toByte(idx_sig, n)), M);
 *
 *     # Sign
 *     Sig_MT = idx_sig;
 *     unsigned int idx_tree
 *                   = (h - h / d) most significant bits of idx_sig;
 *     unsigned int idx_leaf = (h / d) least significant bits of idx_sig;
 *     SK = idx_leaf || getXMSS_SK(SK_MT, idx_tree, 0) || SK_PRF
 *           || toByte(0, n) || SEED;
 *     ADRS.setLayerAddress(0);
 *     ADRS.setTreeAddress(idx_tree);
 *     Sig_tmp = treeSig(M', SK, idx_leaf, ADRS);
 *     Sig_MT = Sig_MT || r || Sig_tmp;
 *     for ( j = 1; j < d; j++ ) {
 *        root = treeHash(SK, 0, h / d, ADRS);
 *        idx_leaf = (h / d) least significant bits of idx_tree;
 *        idx_tree = (h - j * (h / d)) most significant bits of idx_tree;
 *        SK = idx_leaf || getXMSS_SK(SK_MT, idx_tree, j) || SK_PRF
 *               || toByte(0, n) || SEED;
 *        ADRS.setLayerAddress(j);
 *        ADRS.setTreeAddress(idx_tree);
 *        Sig_tmp = treeSig(root, SK, idx_leaf, ADRS);
 *        Sig_MT = Sig_MT || Sig_tmp;
 *     }
 *     return SK_MT || Sig_MT;
 *
 * 'auth' was built at key generation or after computing previous signature.
 *
 * @param [in]      state      XMSS/MT state including digest and parameters.
 * @param [in, out] bds        BDS state.
 * @param [in]      idx        Index to sign with.
 * @param [in]      wots_sigs  Pre-computed WOTS+ signatures.
 * @param [in]      m          Buffer holding message.
 * @param [in]      mlen       Length of message in buffer.
 * @param [in, out] sk         Secret/Private key.
 * @param [out]     sig        Signature and message data.
 * @return  0 on success.
 * @return  <0 on digest failure.
 */
static int wc_xmssmt_sign_msg(XmssState* state, BdsState* bds, XmssIdx idx,
    byte* wots_sigs, const unsigned char* m, word32 mlen, unsigned char* sk,
    unsigned char* sig)
{
    int ret;
    const XmssParams* params = state->params;
    const word8 n = params->n;
    const word8 hs = params->sub_h;
    const word8 idx_len = params->idx_len;
    const byte* sk_prf = sk + idx_len + n;
    byte* sig_mt = sig;
    byte* sig_r = sig + idx_len;
    byte node[WC_XMSS_MAX_N];

    /* Message compression */
    /* byte[n] r = PRF(SK_PRF, toByte(idx_sig, 32)); */
    wc_idx_copy(sig_mt, idx_len, state->buf, XMSS_PRF_M_LEN);
    wc_xmss_prf(state, sk_prf, state->buf, sig_r);
    ret = state->ret;
    if (ret == 0) {
        const byte* pub_root = sk + idx_len + 2 * n;
        /* byte[n] M' = H_msg(r || getRoot(SK_MT) || (toByte(idx_sig, n)), M);
         */
        wc_xmss_hash_message(state, sig_r, pub_root, sig, idx_len, m, mlen,
            node);
        ret = state->ret;
        /* Place new signature data after index and 'r'. */
        sig += idx_len + n;
    }

    /* Sign */
    if (ret == 0) {
        const byte* sk_seed = sk + idx_len;
        const byte* pk_seed = sk + idx_len + 3 * n;
        XmssIdx idx_tree;
        word32 idx_leaf;

        /* Set all address values to zero and set type to OTS. */
        XMEMSET(state->addr, 0, sizeof(HashAddress));
        state->addr[XMSS_ADDR_TYPE] = WC_XMSS_ADDR_TYPE_OTS;

        /* Fist iteration - calculate signature. */
        /* Set layer, tree and OTS leaf index into hash address. */
        state->addr[XMSS_ADDR_LAYER] = 0;
        xmss_idx_get_tree_leaf(idx, hs, &idx_tree, &idx_leaf);
        xmss_idx_set_addr_tree(idx_tree, state->addr);
        /* treeSig || treeHash = sig_ots || auth */
        state->addr[XMSS_ADDR_OTS] = idx_leaf;
        /*   Create WOTS+ signature for tree into signature (sig_ots). */
        wc_xmss_wots_sign(state, node, sk_seed, pk_seed, state->addr, sig);
        ret = state->ret;
    }
    if (ret == 0) {
        word8 i;

        sig += params->wots_sig_len;
        /*   Add authentication path. */
        XMEMCPY(sig, bds[BDS_IDX(idx, 0, hs, params->d)].authPath, hs * n);
        sig += hs * n;

        /* Remaining iterations from storage. */
        for (i = 1; i < params->d; i++) {
            /* Copy out precomputed signature into signature (sig_ots). */
            XMEMCPY(sig, wots_sigs + (i - 1) * params->wots_sig_len,
                params->wots_sig_len);
            sig += params->wots_sig_len;
            /* Add authentication path (auth) and calc new root. */
            XMEMCPY(sig, bds[BDS_IDX(idx, i, hs, params->d)].authPath, hs * n);
            sig += hs * n;
        }
        ret = state->ret;
    }

    return ret;
}

/* Compute BDS state for signing next index.
 *
 * HDSS, Section 4.5, The algorithm, Update and output phase.
 * OPX, Section 2, Signature Generation. Para 2 and 3.
 *
 * @param [in]      state      XMSS/MT state including digest and parameters.
 * @param [in, out] bds        BDS state.
 * @param [in]      idx        Index to sign with.
 * @param [in]      wots_sigs  Pre-computed WOTS+ signatures.
 * @param [in]      m          Buffer holding message.
 * @param [in]      mlen       Length of message in buffer.
 * @param [in, out] sk         Secret/Private key.
 * @param [out]     sig        Signature and message data.
 * @return  0 on success.
 * @return  <0 on digest failure.
 */
static int wc_xmssmt_sign_next_idx(XmssState* state, BdsState* bds, XmssIdx idx,
    byte* wots_sigs, unsigned char* sk)
{
    int ret = 0;
    const XmssParams* params = state->params;
    const word8 n = params->n;
    const word8 h = params->h;
    const word8 hs = params->sub_h;
    const word8 hsk = params->sub_h - params->bds_k;
    const byte* sk_seed = sk + params->idx_len;
    const byte* pk_seed = sk + params->idx_len + 3 * n;
    XmssIdx idx_tree;
    int computeAuthPath = 1;
    unsigned int updates;
    word8 i;

    /* Update BDS state - update authentication path for next index. */
    /* HDSS, Algorithm 4.6, Step 5: repeat (H - K) / 2 times. */
    updates = hsk >> 1;

    idx_tree = (idx >> hs) + 1;
    /* Check whether last tree. */
    if (idx_tree < ((XmssIdx)1 << (h - hs))) {
        /* Set hash address to next tree. */
        state->addr[XMSS_ADDR_LAYER] = 0;
        xmss_idx_set_addr_tree(idx_tree, state->addr);
        /* Update BDS state. */
        wc_xmss_bds_update(state, &bds[BDS_ALT_IDX(idx, 0, hs, params->d)],
            sk_seed, pk_seed, state->addr);
        ret = state->ret;
    }

    for (i = 0; (ret == 0) && (i < params->d); i++) {
        word32 idx_leaf;
        word8 bds_i = BDS_IDX(idx, i, hs, params->d);
        word8 alt_i = BDS_ALT_IDX(idx, i, hs, params->d);

        /* Check not last at height. */
        if (((idx + 1) << (IDX_MAX_BITS - ((i + 1) * hs))) != 0) {
            state->addr[XMSS_ADDR_LAYER] = i;
            xmss_idx_get_tree_leaf(idx >> (hs * i), hs, &idx_tree, &idx_leaf);
            xmss_idx_set_addr_tree(idx_tree, state->addr);
            idx_tree++;

            if (computeAuthPath) {
                /* Compute authentication path for tree. */
                wc_xmss_bds_auth_path(state, &bds[bds_i], idx_leaf, sk_seed,
                    pk_seed, state->addr);
                ret = state->ret;
                computeAuthPath = 0;
            }

            if (ret == 0) {
                /* HDSS, Algorithm 4.6: Step 5. */
                updates = wc_xmss_bds_treehash_updates(state, &bds[bds_i],
                    updates, sk_seed, pk_seed, state->addr);
                ret = state->ret;
            }

            /* Check tree not first, updates to do, tree not last at height and
             * next leaf in alt state is not last. */
            if ((ret == 0) && (i > 0) && (updates > 0) &&
                    (idx_tree < ((XmssIdx)1 << (h - (hs * (i + 1))))) &&
                    (bds[alt_i].next < ((XmssIdx)1 << h))) {
                xmss_idx_set_addr_tree(idx_tree, state->addr);
                /* Update alternative BDS state. */
                wc_xmss_bds_update(state, &bds[alt_i], sk_seed, pk_seed,
                    state->addr);
                ret = state->ret;
                updates--;
            }
        }
        /* Last at height. */
        else {
            /* Set layer, tree and OTS leaf index into hash address. */
            state->addr[XMSS_ADDR_LAYER] = i + 1;
            idx_tree = (idx + 1) >> ((i + 1) * hs);
            xmss_idx_get_tree_leaf(idx_tree, hs, &idx_tree, &idx_leaf);
            xmss_idx_set_addr_tree(idx_tree, state->addr);
            /* Cache WOTS+ signature for new tree. */
            state->addr[XMSS_ADDR_OTS] = idx_leaf;
            wc_xmss_wots_sign(state, bds[alt_i].stack, sk_seed, pk_seed,
                state->addr, wots_sigs + i * params->wots_sig_len);
            ret = state->ret;

            if (ret == 0) {
                word8 d;

                /* Reset old BDS state. */
                bds[bds_i].offset = 0;
                bds[bds_i].next = 0;

                /* Done an update. */
                updates--;
                /* Need to compute authentication path in next tree up. */
                computeAuthPath = 1;
                /* Mark the tree hashes as complete in new BDS state. */
                for (d = 0; d < hsk; d++) {
                    wc_xmss_bds_state_treehash_complete(&bds[alt_i], d);
                }
            }
        }
    }

    return ret;
}

/* Sign a message with XMSS^MT and update BDS state for signing next index.
 *
 * RFC 8391: 4.2.4, Algorithm 16: XMSS^MT_sign.
 * HDSS, Section 4.5, The algorithm, Update and output phase.
 *
 * @param [in]      state   XMSS/MT state including digest and parameters.
 * @param [in]      m       Buffer holding message.
 * @param [in]      mlen    Length of message in buffer.
 * @param [in, out] sk      Secret/Private key.
 * @param [out]     sig     Signature and message data.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  <0 on digest failure.
 */
int wc_xmssmt_sign(XmssState* state, const unsigned char* m, word32 mlen,
    unsigned char* sk, unsigned char* sig)
{
    int ret = 0;
    const XmssParams* params = state->params;
    const word8 h = params->h;
    const word8 idx_len = params->idx_len;
    XmssIdx idx = 0;
    byte* sig_mt = sig;
    byte* wots_sigs;
    BdsState* bds = NULL;

    /* Allocate memory for BDS states and tree hash instances. */
    ret = wc_xmss_bds_state_alloc(params, &bds);
    if (ret == 0) {
        /* Load the BDS state from secret/private key. */
        wc_xmss_bds_state_load(state, sk, bds, &wots_sigs);

        /* Copy the index into the signature data: Sig_MT = idx_sig. */
        XMEMCPY(sig_mt, sk, idx_len);

        /* Read index from the secret key. */
        xmss_idx_decode(&idx, idx_len, sk);
    }
    if ((ret == 0) && xmss_idx_invalid(idx, h)) {
        /* Set index to maximum value to distinguish from valid value. */
        XMEMSET(sk, 0xFF, idx_len);
        /* Zeroize the secret key. */
        ForceZero(sk + idx_len, params->sk_len - idx_len);
        ret = KEY_EXHAUSTED_E;
    }

    if (ret == 0) {
        /* Increment the index in the secret key. */
        wc_idx_update(sk, idx_len);

        /* Compute signature. */
        ret = wc_xmssmt_sign_msg(state, bds, idx, wots_sigs, m, mlen, sk, sig);
    }

    /* Only update if not last index. */
    if ((ret == 0) && (idx < (((XmssIdx)1 << h) - 1))) {
        /* Update BDS state for signing next index. */
        ret = wc_xmssmt_sign_next_idx(state, bds, idx, wots_sigs, sk);
    }

    if (ret == 0) {
        /* Store BDS state back into secret/private key. */
        wc_xmss_bds_state_store(state, sk, bds);
    }

    /* Dispose of allocated data of BDS states. */
    wc_xmss_bds_state_free(bds);
    return ret;
}

#endif /* WOLFSSL_WC_XMSS_SMALL */

/* Check if more signatures are possible with secret/private key.
 *
 * @param [in] params  XMSS parameters
 * @param [in] sk      Secret/private key.
 * @return  1 when signatures possible.
 * @return  0 when key exhausted.
 */

int wc_xmss_sigsleft(const XmssParams* params, unsigned char* sk)
{
    int ret = 0;
    wc_Idx idx;

    WC_IDX_ZERO(idx);
    /* Read index from the secret key. */
    WC_IDX_DECODE(idx, params->idx_len, sk, ret);
    /* Check validity of index. */
    if ((ret == 0) && (WC_IDX_INVALID(idx, params->idx_len, params->h))) {
        ret = KEY_EXHAUSTED_E;
    }

    return ret == 0;
}
#endif /* !WOLFSSL_XMSS_VERIFY_ONLY */

/********************************************
 * SIGN OPEN - Verify
 ********************************************/

#if !defined(WOLFSSL_WC_XMSS_SMALL) || defined(WOLFSSL_XMSS_VERIFY_ONLY)
/* Compute root node with leaf and authentication path.
 *
 * RFC 8391: 4.1.10, Algorithm 13: XMSS_rootFromSig
 *     ...
 *     for ( k = 0; k < h; k++ ) {
 *       ADRS.setTreeHeight(k);
 *       if ( (floor(idx_sig / (2^k)) % 2) == 0 ) {
 *         ADRS.setTreeIndex(ADRS.getTreeIndex() / 2);
 *         node[1] = RAND_HASH(node[0], auth[k], SEED, ADRS);
 *       } else {
 *         ADRS.setTreeIndex((ADRS.getTreeIndex() - 1) / 2);
 *         node[1] = RAND_HASH(auth[k], node[0], SEED, ADRS);
 *       }
 *       node[0] = node[1];
 *     }
 *     return node[0];
 *
 * @param [in]      state      XMSS/MT state including digest and parameters.
 * @param [in]      idx_leaf   Index of leaf node.
 * @param [in]      auth_path  Authentication path.
 * @param [in]      pk_seed    Random public seed.
 * @param [in]      addr       Hash address.
 * @param [in, out] root       On in, leaf node. On out, root node.
 */
static void wc_xmss_compute_root(XmssState* state, word32 idx_leaf,
    const byte* auth_path, const byte* pk_seed, HashAddress addr, byte* root)
{
    const XmssParams* params = state->params;
    const word8 n = params->n;
    const byte* b[2][2] = { { root, auth_path }, { auth_path, root } };
    word8 i;

    for (i = 0; i < params->sub_h; i++) {
        /* Get which side the leaf is on. */
        word8 s = idx_leaf & 1;
        /* Set tree height and index. */
        addr[XMSS_ADDR_TREE_HEIGHT] = i;
        idx_leaf >>= 1;
        addr[XMSS_ADDR_TREE_INDEX] = idx_leaf;

        /* Put the result into buffer position for next RAND_HASH. */
        wc_xmss_rand_hash_lr(state, b[s][0], b[s][1], pk_seed, addr, root);
        /* Move to next auth path node. */
        b[0][1] += n;
        b[1][0] += n;
    }
}
#else
/* Compute root node with leaf and authentication path.
 *
 * RFC 8391: 4.1.10, Algorithm 13: XMSS_rootFromSig
 *     ...
 *     for ( k = 0; k < h; k++ ) {
 *       ADRS.setTreeHeight(k);
 *       if ( (floor(idx_sig / (2^k)) % 2) == 0 ) {
 *         ADRS.setTreeIndex(ADRS.getTreeIndex() / 2);
 *         node[1] = RAND_HASH(node[0], auth[k], SEED, ADRS);
 *       } else {
 *         ADRS.setTreeIndex((ADRS.getTreeIndex() - 1) / 2);
 *         node[1] = RAND_HASH(auth[k], node[0], SEED, ADRS);
 *       }
 *       node[0] = node[1];
 *     }
 *     return node[0];
 *
 * @param [in]      state      XMSS/MT state including digest and parameters.
 * @param [in]      idx_leaf   Index of leaf node.
 * @param [in]      auth_path  Authentication path.
 * @param [in]      pk_seed    Random public seed.
 * @param [in]      addr       Hash address.
 * @param [in, out] node       On in, leaf node. On out, root node.
 */
static void wc_xmss_compute_root(XmssState* state, word32 idx_leaf,
    const byte* auth_path, const byte* pk_seed, HashAddress addr, byte* node)
{
    const XmssParams* params = state->params;
    const word8 n = params->n;
    byte buffer[2 * WC_XMSS_MAX_N];
    byte* b[2][2] = { { buffer, buffer + n }, { buffer + n, buffer } };
    word8 i;

    /* Setup buffer for first RAND_HASH. */
    XMEMCPY(b[idx_leaf & 1][0], node, n);
    XMEMCPY(b[idx_leaf & 1][1], auth_path, n);
    auth_path += n;

    for (i = 0; i < params->sub_h - 1; i++) {
        /* Set tree height and index. */
        addr[XMSS_ADDR_TREE_HEIGHT] = i;
        idx_leaf >>= 1;
        addr[XMSS_ADDR_TREE_INDEX] = idx_leaf;

        /* Put the result into buffer position for next RAND_HASH. */
        wc_xmss_rand_hash(state, buffer, pk_seed, addr, b[idx_leaf & 1][0]);
        /* Put auth path node into other half of buffer. */
        XMEMCPY(b[idx_leaf & 1][1], auth_path, n);
        /* Move to next auth path node. */
        auth_path += n;
    }

    addr[XMSS_ADDR_TREE_HEIGHT] = i;
    idx_leaf >>= 1;
    addr[XMSS_ADDR_TREE_INDEX] = idx_leaf;
    /* Last iteration into output node. */
    wc_xmss_rand_hash(state, buffer, pk_seed, addr, node);
}
#endif /* !WOLFSSL_WC_XMSS_SMALL || WOLFSSL_XMSS_VERIFY_ONLY */

/* Compute a root node from a tree signature.
 *
 * RFC 8391: 4.1.10, Algorithm 13: XMSS_rootFromSig
 *     ADRS.setType(0);   # Type = OTS hash address
 *     ADRS.setOTSAddress(idx_sig);
 *     pk_ots = WOTS_pkFromSig(sig_ots, M', SEED, ADRS);
 *     ADRS.setType(1);   # Type = L-tree address
 *     ADRS.setLTreeAddress(idx_sig);
 *     byte[n][2] node;
 *     node[0] = ltree(pk_ots, SEED, ADRS);
 *     ADRS.setType(2);   # Type = hash tree address
 *     ADRS.setTreeIndex(idx_sig);
 *     [Compute root with leaf and authentication path]
 *
 * Computing the root from the leaf and authentication path can be implemented
 * in different ways and is therefore extracted to its own function.
 *
 * @param [in]      state    XMSS/MT state including digest and parameters.
 * @param [in]      pk_seed  Random public seed.
 * @param [in]      sig      WOTS+ signature for this tree.
 * @param [in]      idx_sig  Index of signature leaf in this tree.
 * @param [in, out] addr     Hash address.
 * @param [in, out] node     On in, previous root node.
 *                           On out, root node of this subtree.
 */
static void wc_xmss_root_from_sig(XmssState* state, const byte* pk_seed,
    const byte* sig, word32 idx_sig, HashAddress addr, byte* node)
{
    const XmssParams* params = state->params;
    byte* wots_pk = state->pk;
    const byte* auth_path = sig + params->wots_sig_len;

    /* Compute WOTS+ public key value from signature. */
    addr[XMSS_ADDR_TYPE] = WC_XMSS_ADDR_TYPE_OTS;
    addr[XMSS_ADDR_OTS] = idx_sig;
    wc_xmss_wots_pk_from_sig(state, sig, node, pk_seed, addr, wots_pk);

    /* Compute leaves of L-tree from WOTS+ public key. */
    addr[XMSS_ADDR_TYPE] = WC_XMSS_ADDR_TYPE_LTREE;
    /* XMSS_ADDR_LTREE is same as XMSS_ADDR_OTS in index and value. */
    wc_xmss_ltree(state, wots_pk, pk_seed, addr, node);

    /* Compute root node from leaf and authentication path. */
    addr[XMSS_ADDR_TYPE] = WC_XMSS_ADDR_TYPE_TREE;
    addr[XMSS_ADDR_TREE_ZERO] = 0;
    wc_xmss_compute_root(state, idx_sig, auth_path, pk_seed, addr, node);
}

/* Verify message with signature using XMSS/MT.
 *
 * RFC 8391: 4.2.5, Algorithm 17: XMSSMT_verify
 *     idx_sig = getIdx(Sig_MT);
 *     SEED = getSEED(PK_MT);
 *     ADRS = toByte(0, 32);
 *
 *     byte[n] M' = H_msg(getR(Sig_MT) || getRoot(PK_MT)
 *                        || (toByte(idx_sig, n)), M);
 *
 *     unsigned int idx_leaf
 *                   = (h / d) least significant bits of idx_sig;
 *     unsigned int idx_tree
 *                   = (h - h / d) most significant bits of idx_sig;
 *     Sig' = getXMSSSignature(Sig_MT, 0);
 *     ADRS.setLayerAddress(0);
 *     ADRS.setTreeAddress(idx_tree);
 *     byte[n] node = XMSS_rootFromSig(idx_leaf, getSig_ots(Sig'),
 *                                      getAuth(Sig'), M', SEED, ADRS);
 *     for ( j = 1; j < d; j++ ) {
 *        idx_leaf = (h / d) least significant bits of idx_tree;
 *        idx_tree = (h - j * h / d) most significant bits of idx_tree;
 *        Sig' = getXMSSSignature(Sig_MT, j);
 *        ADRS.setLayerAddress(j);
 *        ADRS.setTreeAddress(idx_tree);
 *        node = XMSS_rootFromSig(idx_leaf, getSig_ots(Sig'),
 *                              getAuth(Sig'), node, SEED, ADRS);
 *     }
 *     if ( node == getRoot(PK_MT) ) {
 *       return true;
 *     } else {
 *       return false;
 *     }
 *
 * @param [in]       state    XMSS/MT state including digest and parameters.
 * @param [in]       m        Message buffer.
 * @param [in]       mlen     Length of message in bytes.
 * @param [in]       sig      Buffer holding signature.
 * @param [in]       pk       Public key.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SIG_VERIFY_E on verification failure.
 * @return  <0 on digest failure.
 */
int wc_xmssmt_verify(XmssState* state, const unsigned char* m, word32 mlen,
    const unsigned char* sig, const unsigned char* pk)
{
    const XmssParams* params = state->params;
    const word8 n = params->n;
    int ret = 0;
    const byte* pub_root = pk;
    const byte* pk_seed = pk + n;
    byte node[WC_XMSS_MAX_N];
    wc_Idx idx;
    word32 idx_leaf = 0;
    unsigned int i;

    /* Set 32/64-bit index to 0. */
    WC_IDX_ZERO(idx);
    /* Set all address values to zero. */
    XMEMSET(state->addr, 0, sizeof(HashAddress));

    if (ret == 0) {
        /* Convert the index bytes from the signature to an integer. */
        WC_IDX_DECODE(idx, params->idx_len, sig, ret);
    }

    if (ret == 0) {
        const byte* sig_r = sig + params->idx_len;
        /* byte[n] M' = H_msg(getR(Sig_MT) || getRoot(PK_MT) ||
         *                    (toByte(idx_sig, n)), M);
         */
        wc_xmss_hash_message(state, sig_r, pub_root, sig, params->idx_len, m,
            mlen, node);
        ret = state->ret;
    }

    if (ret == 0) {
        /* Set tree of hash address. */
        WC_IDX_SET_ADDR_TREE(idx, params->idx_len, params->sub_h, state->addr,
            idx_leaf);

        /* Skip to first WOTS+ signature and derive root. */
        sig += params->idx_len + n;
        wc_xmss_root_from_sig(state, pk_seed, sig, idx_leaf, state->addr,
            node);
        ret = state->ret;
    }
    /* Calculate root of remaining subtrees up to top. */
    for (i = 1; (ret == 0) && (i < params->d); i++) {
        /* Set layer and tree. */
        state->addr[XMSS_ADDR_LAYER] = i;
        WC_IDX_SET_ADDR_TREE(idx, params->idx_len, params->sub_h, state->addr,
            idx_leaf);
        /* Skip to next WOTS+ signature and derive root. */
        sig += params->wots_sig_len + params->sub_h * n;
        wc_xmss_root_from_sig(state, pk_seed, sig, idx_leaf, state->addr,
            node);
        ret = state->ret;
    }
    /* Compare calculated node with public key root. */
    if ((ret == 0) && (XMEMCMP(node, pub_root, n) != 0)) {
        ret = SIG_VERIFY_E;
    }

    return ret;
}
#endif /* WOLFSSL_HAVE_XMSS */

