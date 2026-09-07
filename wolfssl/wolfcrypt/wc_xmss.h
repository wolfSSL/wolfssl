/* wc_xmss.h
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
    \file wolfssl/wolfcrypt/wc_xmss.h
 */

/* Based on:
 *  o RFC 8391 - XMSS: eXtended Merkle Signature Scheme
 *  o [HDSS] "Hash-based Digital Signature Schemes", Buchmann, Dahmen and Szydlo
 *    from "Post Quantum Cryptography", Springer 2009.
 */

#ifndef WC_XMSS_H
#define WC_XMSS_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_HAVE_XMSS

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/sha3.h>


/* When raw hash access APIs are disabled or unavailable (WOLFSSL_NO_HASH_RAW),
 * fall back to using the full hash API calls. */
#if defined(WOLFSSL_NO_HASH_RAW) && !defined(WC_XMSS_FULL_HASH)
    #define WC_XMSS_FULL_HASH
#endif

/* Note on XMSS/XMSS^MT pub/priv key sizes:
 *   - The XMSS/XMSS^MT pub key has a defined format and size.
 *   - The XMSS/XMSS^MT private key is implementation and parameter
 *     specific. It does not have a standardized format or size.
 *
 * The XMSS/XMSS^MT public and secret key format and length is:
 *   PK = OID || root || SEED;
 *   PK_len = 4 + 2 * n
 *
 *   SK = OID || (implementation defined)
 *   SK_len = 4 + (implementation defined)
 *
 * where n is the number of bytes in the hash function, which is 32
 * in this SHA256 implementation.
 *
 * However the private key is implementation specific. For example,
 * in xmss-reference the private key size varies from 137 bytes to
 * 1377 bytes between slow and fast implementations with param name
 * "XMSSMT-SHA2_20/2_256".
 *
 * References:
 *   - RFC 8391
 *   - Table 2 of Kampanakis, Fluhrer, IACR, 2017.
 * */

#define XMSS_SHA256_PUBLEN (68)

/* Supported XMSS/XMSS^MT parameter set names:
 * We are supporting all SHA256 parameter sets with n=32 and
 * Winternitz=16, from RFC 8391 and NIST SP 800-208.
 *
 *         ----------------------------------------------------------
 *         | Name                     OID         n   w  len  h   d  |
 * XMSS:   | "XMSS-SHA2_10_256"       0x00000001  32  16  67  10  1  |
 *         | "XMSS-SHA2_16_256"       0x00000002  32  16  67  16  1  |
 *         | "XMSS-SHA2_20_256"       0x00000003  32  16  67  20  1  |
 *         |                                                         |
 * XMSSMT: | "XMSSMT-SHA2_20/2_256"   0x00000001  32  16  67  20  2  |
 *         | "XMSSMT-SHA2_20/4_256"   0x00000002  32  16  67  20  4  |
 *         | "XMSSMT-SHA2_40/2_256"   0x00000003  32  16  67  40  2  |
 *         | "XMSSMT-SHA2_40/4_256"   0x00000004  32  16  67  40  4  |
 *         | "XMSSMT-SHA2_40/8_256"   0x00000005  32  16  67  40  8  |
 *         | "XMSSMT-SHA2_60/3_256"   0x00000006  32  16  67  60  3  |
 *         | "XMSSMT-SHA2_60/6_256"   0x00000007  32  16  67  60  6  |
 *         | "XMSSMT-SHA2_60/12_256"  0x00000008  32  16  67  60  12 |
 *         ----------------------------------------------------------
 *
 * Note that some XMSS and XMSSMT names do have overlapping OIDs.
 *
 * References:
 *   1. NIST SP 800-208
 *   2. RFC 8391
 * */

#define XMSS_NAME_LEN       (16) /* strlen("XMSS-SHA2_10_256") */
#define XMSSMT_NAME_MIN_LEN (20) /* strlen("XMSSMT-SHA2_20/2_256") */
#define XMSSMT_NAME_MAX_LEN (21) /* strlen("XMSSMT-SHA2_60/12_256") */

#if defined(HAVE_FIPS)
    #undef WOLFSSL_WC_XMSS_NO_SHA512
    #define WOLFSSL_WC_XMSS_NO_SHA512
    #undef WOLFSSL_WC_XMSS_NO_SHAKE128
    #define WOLFSSL_WC_XMSS_NO_SHAKE128
    #undef WOLFSSL_WC_XMSS_MAX_HASH_SIZE
    #define WOLFSSL_WC_XMSS_MIN_HASH_SIZE       192
    #define WOLFSSL_WC_XMSS_MAX_HASH_SIZE       256
#endif

#if !defined(NO_SHA256) && !defined(WOLFSSL_WC_XMSS_NO_SHA256)
    #define WC_XMSS_SHA256
#endif
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_WC_XMSS_NO_SHA512)
    #define WC_XMSS_SHA512
#endif
#if defined(WOLFSSL_SHAKE128) && !defined(WOLFSSL_WC_XMSS_NO_SHAKE128)
    #define WC_XMSS_SHAKE128
#endif
#if defined(WOLFSSL_SHAKE256) && !defined(WOLFSSL_WC_XMSS_NO_SHAKE256)
    #define WC_XMSS_SHAKE256
#endif

#ifndef WOLFSSL_WC_XMSS_MIN_HASH_SIZE
    #define WOLFSSL_WC_XMSS_MIN_HASH_SIZE       192
#endif
#ifndef WOLFSSL_WC_XMSS_MAX_HASH_SIZE
    #define WOLFSSL_WC_XMSS_MAX_HASH_SIZE       512
#endif
#if WOLFSSL_WC_XMSS_MIN_HASH_SIZE > WOLFSSL_WC_XMSS_MAX_HASH_SIZE
    #error "XMSS minimum hash size is greater than maximum hash size"
#endif

#ifndef WOLFSSL_XMSS_MIN_HEIGHT
    #define WOLFSSL_XMSS_MIN_HEIGHT             10
#endif
#ifndef WOLFSSL_XMSS_MAX_HEIGHT
    #define WOLFSSL_XMSS_MAX_HEIGHT             60
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT > WOLFSSL_XMSS_MAX_HEIGHT
    #error "XMSS minimum height is greater than maximum height"
#endif

/* Return codes returned by private key callbacks. */
enum wc_XmssRc {
  WC_XMSS_RC_NONE,
  WC_XMSS_RC_BAD_ARG,            /* Bad arg in read or write callback. */
  WC_XMSS_RC_WRITE_FAIL,         /* Write or update private key failed. */
  WC_XMSS_RC_READ_FAIL,          /* Read private key failed. */
  WC_XMSS_RC_SAVED_TO_NV_MEMORY, /* Wrote private key to nonvolatile storage. */
  WC_XMSS_RC_READ_TO_MEMORY      /* Read private key from storage. */
};

/* enum wc_XmssState is to help track the state of an XMSS Key. */
enum wc_XmssState {
    WC_XMSS_STATE_FREED,      /* Key has been freed from memory. */
    WC_XMSS_STATE_INITED,     /* Key has been inited, ready to set params.*/
    WC_XMSS_STATE_PARMSET,    /* Params are set, ready to MakeKey or Reload. */
    WC_XMSS_STATE_OK,         /* Able to sign signatures and verify. */
    WC_XMSS_STATE_VERIFYONLY, /* A public only XmssKey. */
    WC_XMSS_STATE_BAD,        /* Can't guarantee key's state. */
    WC_XMSS_STATE_NOSIGS      /* Signatures exhausted. */
};

/* Private key write and read callbacks. */
typedef enum wc_XmssRc (*wc_xmss_write_private_key_cb)(const byte* priv, word32 privSz,
    void* context);
typedef enum wc_XmssRc (*wc_xmss_read_private_key_cb)(byte* priv, word32 privSz,
    void* context);

#if (defined(WC_XMSS_SHA512) || defined(WC_XMSS_SHAKE256)) && \
        (WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 512)
    #define WC_XMSS_MAX_N               64U
    #define WC_XMSS_MAX_PADDING_LEN     64U
#else
    #define WC_XMSS_MAX_N               32U
    #define WC_XMSS_MAX_PADDING_LEN     32U
#endif
#define WC_XMSS_MAX_MSG_PRE_LEN     \
    (WC_XMSS_MAX_PADDING_LEN + 3U * WC_XMSS_MAX_N)
#define WC_XMSS_MAX_TREE_HEIGHT     20U
#define WC_XMSS_MAX_CSUM_BYTES       4U
#define WC_XMSS_MAX_WOTS_LEN        (8U * WC_XMSS_MAX_N / 4U + 3U)
#define WC_XMSS_MAX_WOTS_SIG_LEN    (WC_XMSS_MAX_WOTS_LEN * WC_XMSS_MAX_N)
#define WC_XMSS_MAX_STACK_LEN       \
    ((WC_XMSS_MAX_TREE_HEIGHT + 1U) * WC_XMSS_MAX_N)
#define WC_XMSS_MAX_D               12U
#define WC_XMSS_MAX_BDS_STATES      (2U * WC_XMSS_MAX_D - 1U)
#define WC_XMSS_MAX_TREE_HASH       \
    ((2U * WC_XMSS_MAX_D - 1U) * WC_XMSS_MAX_TREE_HEIGHT)
#define WC_XMSS_MAX_BDS_K           0U

#define WC_XMSS_ADDR_LEN            32U

#define WC_XMSS_HASH_PRF_MAX_DATA_LEN               \
    (WC_XMSS_MAX_PADDING_LEN + 2U * WC_XMSS_MAX_N + WC_XMSS_ADDR_LEN)
#define WC_XMSS_HASH_MAX_DATA_LEN                   \
    (WC_XMSS_MAX_PADDING_LEN + 3U * WC_XMSS_MAX_N)


#define WC_XMSS_SHA256_N            32U
#define WC_XMSS_SHA256_PADDING_LEN  32U
#define WC_XMSS_SHA256_WOTS_LEN     67U

#define XMSS_OID_LEN                   4U

#define XMSS_MAX_HASH_LEN              WC_SHA256_DIGEST_SIZE

#define XMSS_RETAIN_LEN(k, n)   \
    (((word32)((k) != 0)) * (((word32)1U << (k)) - (word32)(k) - 1U) *  \
     (word32)(n))

/* XMMS Algorithm OIDs
 * Note: values are used in mathematical calculations in OID to parames. */
#define WC_XMSS_OID_SHA2_10_256        0x01
#define WC_XMSS_OID_SHA2_16_256        0x02
#define WC_XMSS_OID_SHA2_20_256        0x03
#define WC_XMSS_OID_SHA2_10_512        0x04
#define WC_XMSS_OID_SHA2_16_512        0x05
#define WC_XMSS_OID_SHA2_20_512        0x06
#define WC_XMSS_OID_SHAKE_10_256       0x07
#define WC_XMSS_OID_SHAKE_16_256       0x08
#define WC_XMSS_OID_SHAKE_20_256       0x09
#define WC_XMSS_OID_SHAKE_10_512       0x0a
#define WC_XMSS_OID_SHAKE_16_512       0x0b
#define WC_XMSS_OID_SHAKE_20_512       0x0c
#define WC_XMSS_OID_SHA2_10_192        0x0d
#define WC_XMSS_OID_SHA2_16_192        0x0e
#define WC_XMSS_OID_SHA2_20_192        0x0f
#define WC_XMSS_OID_SHAKE256_10_256    0x10
#define WC_XMSS_OID_SHAKE256_16_256    0x11
#define WC_XMSS_OID_SHAKE256_20_256    0x12
#define WC_XMSS_OID_SHAKE256_10_192    0x13
#define WC_XMSS_OID_SHAKE256_16_192    0x14
#define WC_XMSS_OID_SHAKE256_20_192    0x15
#define WC_XMSS_OID_FIRST              WC_XMSS_OID_SHA2_10_256
#define WC_XMSS_OID_LAST               WC_XMSS_OID_SHAKE256_20_192

/* XMMS^MT Algorithm OIDs
 * Note: values are used in mathematical calculations in OID to parames. */
#define WC_XMSSMT_OID_SHA2_20_2_256        0x01
#define WC_XMSSMT_OID_SHA2_20_4_256        0x02
#define WC_XMSSMT_OID_SHA2_40_2_256        0x03
#define WC_XMSSMT_OID_SHA2_40_4_256        0x04
#define WC_XMSSMT_OID_SHA2_40_8_256        0x05
#define WC_XMSSMT_OID_SHA2_60_3_256        0x06
#define WC_XMSSMT_OID_SHA2_60_6_256        0x07
#define WC_XMSSMT_OID_SHA2_60_12_256       0x08
#define WC_XMSSMT_OID_SHA2_20_2_512        0x09
#define WC_XMSSMT_OID_SHA2_20_4_512        0x0a
#define WC_XMSSMT_OID_SHA2_40_2_512        0x0b
#define WC_XMSSMT_OID_SHA2_40_4_512        0x0c
#define WC_XMSSMT_OID_SHA2_40_8_512        0x0d
#define WC_XMSSMT_OID_SHA2_60_3_512        0x0e
#define WC_XMSSMT_OID_SHA2_60_6_512        0x0f
#define WC_XMSSMT_OID_SHA2_60_12_512       0x10
#define WC_XMSSMT_OID_SHAKE_20_2_256       0x11
#define WC_XMSSMT_OID_SHAKE_20_4_256       0x12
#define WC_XMSSMT_OID_SHAKE_40_2_256       0x13
#define WC_XMSSMT_OID_SHAKE_40_4_256       0x14
#define WC_XMSSMT_OID_SHAKE_40_8_256       0x15
#define WC_XMSSMT_OID_SHAKE_60_3_256       0x16
#define WC_XMSSMT_OID_SHAKE_60_6_256       0x17
#define WC_XMSSMT_OID_SHAKE_60_12_256      0x18
#define WC_XMSSMT_OID_SHAKE_20_2_512       0x19
#define WC_XMSSMT_OID_SHAKE_20_4_512       0x1a
#define WC_XMSSMT_OID_SHAKE_40_2_512       0x1b
#define WC_XMSSMT_OID_SHAKE_40_4_512       0x1c
#define WC_XMSSMT_OID_SHAKE_40_8_512       0x1d
#define WC_XMSSMT_OID_SHAKE_60_3_512       0x1e
#define WC_XMSSMT_OID_SHAKE_60_6_512       0x1f
#define WC_XMSSMT_OID_SHAKE_60_12_512      0x20
#define WC_XMSSMT_OID_SHA2_20_2_192        0x21
#define WC_XMSSMT_OID_SHA2_20_4_192        0x22
#define WC_XMSSMT_OID_SHA2_40_2_192        0x23
#define WC_XMSSMT_OID_SHA2_40_4_192        0x24
#define WC_XMSSMT_OID_SHA2_40_8_192        0x25
#define WC_XMSSMT_OID_SHA2_60_3_192        0x26
#define WC_XMSSMT_OID_SHA2_60_6_192        0x27
#define WC_XMSSMT_OID_SHA2_60_12_192       0x28
#define WC_XMSSMT_OID_SHAKE256_20_2_256    0x29
#define WC_XMSSMT_OID_SHAKE256_20_4_256    0x2a
#define WC_XMSSMT_OID_SHAKE256_40_2_256    0x2b
#define WC_XMSSMT_OID_SHAKE256_40_4_256    0x2c
#define WC_XMSSMT_OID_SHAKE256_40_8_256    0x2d
#define WC_XMSSMT_OID_SHAKE256_60_3_256    0x2e
#define WC_XMSSMT_OID_SHAKE256_60_6_256    0x2f
#define WC_XMSSMT_OID_SHAKE256_60_12_256   0x30
#define WC_XMSSMT_OID_SHAKE256_20_2_192    0x31
#define WC_XMSSMT_OID_SHAKE256_20_4_192    0x32
#define WC_XMSSMT_OID_SHAKE256_40_2_192    0x33
#define WC_XMSSMT_OID_SHAKE256_40_4_192    0x34
#define WC_XMSSMT_OID_SHAKE256_40_8_192    0x35
#define WC_XMSSMT_OID_SHAKE256_60_3_192    0x36
#define WC_XMSSMT_OID_SHAKE256_60_6_192    0x37
#define WC_XMSSMT_OID_SHAKE256_60_12_192   0x38
#define WC_XMSSMT_OID_FIRST            WC_XMSSMT_OID_SHA2_20_2_256
#define WC_XMSSMT_OID_LAST             WC_XMSSMT_OID_SHAKE256_60_12_192


/* Type for hash address. */
#ifndef WC_HASHADDRESS_TYPE_DEFINED
typedef word32 HashAddress[8];
    #define WC_HASHADDRESS_TYPE_DEFINED
#endif

/* XMSS/XMSS^MT fixed parameters. */
typedef struct XmssParams {
    /* Hash algorithm to use. */
    word8  hash;
    /* Size of hash output. */
    word8  n;
    /* Number of bytes of padding before rest of hash data. */
    word8  pad_len;
    /* Number of values to chain = 2 * n + 3. */
    word8  wots_len;
    /* Number of bytes in each WOTS+ signature. */
    word16 wots_sig_len;
    /* Full height of tree. */
    word8  h;
    /* Height of tree each subtree. */
    word8  sub_h;
    /* Number of subtrees = h / sub_h. */
    word8  d;
    /* Number of bytes to encode index into in private/secret key. */
    word8  idx_len;
    /* Number of bytes in a signature. */
    word32 sig_len;
    /* Number of bytes in a secret/private key. */
    word32 sk_len;
    /* Number of bytes in a public key. */
    word8  pk_len;
    /* BDS parameter for fast C implementation. */
    word8  bds_k;
} XmssParams;

#ifndef XMSS_MAX_ID_LEN
#define XMSS_MAX_ID_LEN              32
#endif
#ifndef XMSS_MAX_LABEL_LEN
#define XMSS_MAX_LABEL_LEN           32
#endif

struct XmssKey {
    /* Public key. */
    unsigned char        pk[2 * WC_XMSS_MAX_N];
    /* OID that identifies parameters. */
    word32               oid;
    /* Indicates whether the parameters are for XMSS^MT. */
    int                  is_xmssmt;
    /* XMSS/XMSS^MT parameters. */
    const XmssParams*    params;
#ifndef WOLFSSL_XMSS_VERIFY_ONLY
    /* Secret/private key. */
    unsigned char*       sk;
    /* Length of secret key. */
    word32               sk_len;
    /* Callback to write/update key. */
    wc_xmss_write_private_key_cb write_private_key;
    /* Callback to read key. */
    wc_xmss_read_private_key_cb  read_private_key;
    /* Context arg passed to callbacks. */
    void*                context;
#endif /* ifndef WOLFSSL_XMSS_VERIFY_ONLY */
    /* Dynamic memory hint. */
    void*                heap;
    /* State of key. */
    enum wc_XmssState    state;
#ifdef WOLF_CRYPTO_CB
    /* Device Identifier. */
    int                  devId;
    /* Per-device opaque context, populated by the callback. */
    void*                devCtx;
#endif
#ifdef WOLF_PRIVATE_KEY_ID
    /* Optional device-side key identifier. */
    byte                 id[XMSS_MAX_ID_LEN];
    int                  idLen;
    /* Optional device-side key label. */
    char                 label[XMSS_MAX_LABEL_LEN];
    int                  labelLen;
#endif
};

#ifndef WC_XMSSKEY_TYPE_DEFINED
    typedef struct XmssKey XmssKey;
    #define WC_XMSSKEY_TYPE_DEFINED
#endif

#ifdef USE_INTEL_SPEEDUP
/* AVX-512 assembly for XMSS is built (and dispatched at run time on capable
 * CPUs) whenever the Intel speedups are enabled and AVX-512 is not opted
 * out.  Matches the HAVE_INTEL_AVX512 guard around the generated
 * assembly. */
#ifndef NO_AVX512_SUPPORT
    #define WOLFSSL_XMSS_HAVE_INTEL_AVX512
#endif
#endif

/* Whether the multi-buffer SHA-256 chain path is built.  It needs the cached
 * PRF midstate and the laid-out hash blocks of the prehash SHA-256/32 path,
 * which the small-memory and full-hash variants do not have. */
#if defined(WC_SHA256_N_WAY) && !defined(WOLFSSL_WC_XMSS_SMALL) && \
    defined(WC_XMSS_SHA256) && !defined(WC_XMSS_FULL_HASH)
    #define WC_XMSS_SHA256_N_WAY
#endif
/* The SHAKE-128 parameter sets - n = 32, 32-byte padding - hash 96 bytes per
 * PRF or chain call, one permutation, so they batch through the multi-buffer
 * Keccak.  The SHAKE-256 sets are n = 64 and span two permutations; they stay
 * on the serial path. */
#if defined(WC_SHAKE_N_WAY) && !defined(WOLFSSL_WC_XMSS_SMALL) && \
    defined(WC_XMSS_SHAKE128) && !defined(WC_XMSS_FULL_HASH)
    #define WC_XMSS_SHAKE_N_WAY
#endif

/* The SHA-512 parameter sets - n = 64, 64-byte padding - hash the same way as
 * the SHA-256 ones a block wider: padding || SEED is exactly one 128-byte
 * block, so the PRF is one block from that midstate and the chain hash two
 * from the initial value. */
#if defined(WC_SHA512_N_WAY) && !defined(WOLFSSL_WC_XMSS_SMALL) && \
    defined(WC_XMSS_SHA512) && !defined(WC_XMSS_FULL_HASH)
    #define WC_XMSS_SHA512_N_WAY
#endif

#if defined(WC_XMSS_SHA256_N_WAY) || defined(WC_XMSS_SHAKE_N_WAY) || \
    defined(WC_XMSS_SHA512_N_WAY)
    #define WC_XMSS_N_WAY
    /* Widest batch either hash can run, and the batch buffer each needs: two
     * 64-byte blocks per lane for SHA-256, two 96-byte messages for SHAKE. */
    #ifdef WC_XMSS_SHA256_N_WAY
        #define WC_XMSS_N_WAY_SHA256_CNT  WC_SHA256_N_WAY_MAX_CNT
        #define WC_XMSS_N_WAY_SHA256_BUF  \
            (WC_SHA256_N_WAY_MAX_CNT * 2 * WC_SHA256_BLOCK_SIZE)
    #else
        #define WC_XMSS_N_WAY_SHA256_CNT  0
        #define WC_XMSS_N_WAY_SHA256_BUF  0
    #endif
    #ifdef WC_XMSS_SHAKE_N_WAY
        #define WC_XMSS_N_WAY_SHAKE_CNT   WC_SHAKE_N_WAY_MAX_CNT
        #define WC_XMSS_N_WAY_SHAKE_BUF   (WC_SHAKE_N_WAY_MAX_CNT * 2 * 3 * 32)
    #else
        #define WC_XMSS_N_WAY_SHAKE_CNT   0
        #define WC_XMSS_N_WAY_SHAKE_BUF   0
    #endif
    #ifdef WC_XMSS_SHA512_N_WAY
        #define WC_XMSS_N_WAY_SHA512_CNT  WC_SHA512_N_WAY_CNT
        #define WC_XMSS_N_WAY_SHA512_BUF  (2 * WC_SHA512_N_WAY_BLK_SZ)
    #else
        #define WC_XMSS_N_WAY_SHA512_CNT  0
        #define WC_XMSS_N_WAY_SHA512_BUF  0
    #endif
/* The fused kernels are AVX-512 only - sixteen lanes of SHA-256 or eight of
 * SHA-512 - and the hash size they assume is checked at run time. */
#if defined(WC_XMSS_SHA256_N_WAY) && defined(WOLFSSL_XMSS_HAVE_INTEL_AVX512)
    #define WC_XMSS_SHA256_N_WAY_FUSED
#endif
#if defined(WC_XMSS_SHA512_N_WAY) && defined(WOLFSSL_XMSS_HAVE_INTEL_AVX512)
    #define WC_XMSS_SHA512_N_WAY_FUSED
#endif
/* SHAKE has fused kernels at both widths, so this needs no AVX-512. */
#ifdef WC_XMSS_SHAKE_N_WAY
    #define WC_XMSS_SHAKE_N_WAY_FUSED
#endif
#if defined(WC_XMSS_SHA256_N_WAY_FUSED) || \
    defined(WC_XMSS_SHA512_N_WAY_FUSED) || \
    defined(WC_XMSS_SHAKE_N_WAY_FUSED)
    #define WC_XMSS_N_WAY_FUSED
#endif

    #if WC_XMSS_N_WAY_SHA256_CNT >= WC_XMSS_N_WAY_SHAKE_CNT
        #define WC_XMSS_N_WAY_CNT_A       WC_XMSS_N_WAY_SHA256_CNT
    #else
        #define WC_XMSS_N_WAY_CNT_A       WC_XMSS_N_WAY_SHAKE_CNT
    #endif
    #if WC_XMSS_N_WAY_CNT_A >= WC_XMSS_N_WAY_SHA512_CNT
        #define WC_XMSS_N_WAY_MAX_CNT     WC_XMSS_N_WAY_CNT_A
    #else
        #define WC_XMSS_N_WAY_MAX_CNT     WC_XMSS_N_WAY_SHA512_CNT
    #endif
    #if WC_XMSS_N_WAY_SHA256_BUF >= WC_XMSS_N_WAY_SHAKE_BUF
        #define WC_XMSS_N_WAY_BUF_A       WC_XMSS_N_WAY_SHA256_BUF
    #else
        #define WC_XMSS_N_WAY_BUF_A       WC_XMSS_N_WAY_SHAKE_BUF
    #endif
    #if WC_XMSS_N_WAY_BUF_A >= WC_XMSS_N_WAY_SHA512_BUF
        #define WC_XMSS_N_WAY_BUF_SZ      WC_XMSS_N_WAY_BUF_A
    #else
        #define WC_XMSS_N_WAY_BUF_SZ      WC_XMSS_N_WAY_SHA512_BUF
    #endif
#endif

typedef struct XmssState {
    const XmssParams* params;
    void* heap;

    /* Digest is assumed to be at the end. */
    union {
    #ifdef WC_XMSS_SHA256
       wc_Sha256 sha256;
    #endif
    #ifdef WC_XMSS_SHA512
       wc_Sha512 sha512;
    #endif
    #if defined(WC_XMSS_SHAKE128) || defined(WC_XMSS_SHAKE256)
       wc_Shake shake;
    #endif
    } digest;
#if !defined(WOLFSSL_WC_XMSS_SMALL) && defined(WC_XMSS_SHA256) && \
    !defined(WC_XMSS_FULL_HASH)
    ALIGN16 word32 dgst_state[WC_SHA256_DIGEST_SIZE / sizeof(word32)];
#endif
/* Sibling of the SHA-256 block above, not nested in it: WC_XMSS_N_WAY is set
 * by any of the three n-way families, and the SHAKE-128 and SHA-512 ones do
 * not need WC_XMSS_SHA256.  Nesting made a build with WOLFSSL_WC_XMSS_NO_SHA256
 * (or NO_SHA256) plus SHAKE-128 or SHA-512 reference members that were never
 * declared. */
#ifdef WC_XMSS_N_WAY
    /* Step several WOTS+ chains at a time with the multi-buffer hash.
     *
     * The chains of one WOTS+ key do not feed each other, so a group can be
     * advanced together.  Two message groups: the PRF messages that produce
     * KEY and BM live in the first, and F's message - padding || KEY ||
     * (tmp XOR BM) - in the second.  For SHA-256 dgst_state holds the
     * midstate of the PRF prefix those share. */
    ALIGN64 byte n_way_buf[WC_XMSS_N_WAY_BUF_SZ];
    /* The digests a batch produces. */
    ALIGN64 byte n_way_hash[WC_XMSS_N_WAY_MAX_CNT * WC_XMSS_MAX_N];
#ifdef WC_XMSS_SHA256_N_WAY_FUSED
    /* Chain value, KEY and BM of sixteen chains, lane-interleaved.  The
     * fused kernels hand these to one another as they are: a chain runs PRF,
     * PRF and F without any of the three reading a byte buffer, and the
     * chain value only becomes bytes again when its chain ends. */
    ALIGN64 word32 n_way_st[WC_SHA256_N_WAY_MAX_CNT * 8];
    ALIGN64 word32 n_way_key[WC_SHA256_N_WAY_MAX_CNT * 8];
    ALIGN64 word32 n_way_bm[WC_SHA256_N_WAY_MAX_CNT * 8];
#endif
#ifdef WC_XMSS_SHAKE_N_WAY
    /* Interleaved Keccak state the SHAKE batch permutes. */
    ALIGN64 word64 n_way_state[WC_SHAKE_N_WAY_MAX_STATE_W];
#ifdef WC_XMSS_SHAKE_N_WAY_FUSED
    /* KEY and BM get a whole state each so that the fused kernel can leave
     * them where they fall and F can read them there: the chain value then
     * stays in n_way_state from one link to the next, never becoming bytes. */
    ALIGN64 word64 n_way_key_st[WC_SHAKE_N_WAY_MAX_STATE_W];
    ALIGN64 word64 n_way_bm_st[WC_SHAKE_N_WAY_MAX_STATE_W];
#endif
#endif
#ifdef WC_XMSS_SHA512_N_WAY
    /* SHA-512 state after the PRF prefix; dgst_state is the SHA-256 one. */
    ALIGN64 word64 n_way_mid512[WC_SHA512_DIGEST_SIZE / sizeof(word64)];
    /* Lane-interleaved SHA-512 state the batch compresses into. */
    ALIGN64 word64 n_way_st512[WC_SHA512_N_WAY_CNT *
                             (WC_SHA512_DIGEST_SIZE / sizeof(word64))];
#ifdef WC_XMSS_SHA512_N_WAY_FUSED
    /* KEY and BM of eight chains, lane-interleaved, as the fused kernels
     * pass them to one another; n_way_st512 holds the chain values. */
    ALIGN64 word64 n_way_key512[WC_SHA512_N_WAY_CNT *
                              (WC_SHA512_DIGEST_SIZE / sizeof(word64))];
    ALIGN64 word64 n_way_bm512[WC_SHA512_N_WAY_CNT *
                             (WC_SHA512_DIGEST_SIZE / sizeof(word64))];
#endif
#endif
#endif
    ALIGN16 byte prf_buf[WC_XMSS_HASH_PRF_MAX_DATA_LEN];
    ALIGN16 byte buf[WC_XMSS_HASH_MAX_DATA_LEN];
    ALIGN16 byte pk[WC_XMSS_MAX_WOTS_SIG_LEN];
#ifndef WOLFSSL_XMSS_VERIFY_ONLY
    ALIGN16 byte stack[WC_XMSS_MAX_STACK_LEN];
#else
    ALIGN16 byte stack[WC_XMSS_ADDR_LEN];
#endif
    byte encMsg[WC_XMSS_MAX_WOTS_LEN];
    HashAddress addr;

    int ret;
} XmssState;

#ifdef __cplusplus
    extern "C" {
#endif

#if FIPS_VERSION3_GE(7,0,0)
    extern const unsigned int wolfCrypt_FIPS_xmss_ro_sanity[2];
    WOLFSSL_LOCAL int wolfCrypt_FIPS_XMSS_sanity(void);
#endif

WOLFSSL_API int  wc_XmssKey_Init(XmssKey* key, void* heap, int devId);
#ifdef WOLF_PRIVATE_KEY_ID
WOLFSSL_API int  wc_XmssKey_InitId(XmssKey* key, const unsigned char* id,
    int len, void* heap, int devId);
WOLFSSL_API int  wc_XmssKey_InitLabel(XmssKey* key, const char* label,
    void* heap, int devId);
#endif
WOLFSSL_API int  wc_XmssKey_SetParamStr(XmssKey* key, const char* str);
WOLFSSL_API int  wc_XmssKey_GetParamStr(const XmssKey* key, const char** str);
#ifndef WOLFSSL_XMSS_VERIFY_ONLY
WOLFSSL_API int  wc_XmssKey_SetWriteCb(XmssKey* key,
    wc_xmss_write_private_key_cb write_cb);
WOLFSSL_API int  wc_XmssKey_SetReadCb(XmssKey* key,
    wc_xmss_read_private_key_cb read_cb);
WOLFSSL_API int  wc_XmssKey_SetContext(XmssKey* key, void* context);
WOLFSSL_API int  wc_XmssKey_MakeKey(XmssKey* key, WC_RNG* rng);
WOLFSSL_API int  wc_XmssKey_Reload(XmssKey* key);
WOLFSSL_API int  wc_XmssKey_GetPrivLen(const XmssKey* key, word32* len);
WOLFSSL_API int  wc_XmssKey_Sign(XmssKey* key, byte* sig, word32* sigSz,
    const byte* msg, int msgSz);
WOLFSSL_API int  wc_XmssKey_SigsLeft(XmssKey* key);
WOLFSSL_API int  wc_XmssKey_PublicKeyToDer(const XmssKey* key, byte* output,
    word32 outLen, int withAlg);
#endif /* ifndef WOLFSSL_XMSS_VERIFY_ONLY */
WOLFSSL_API void wc_XmssKey_Free(XmssKey* key);
WOLFSSL_API int  wc_XmssKey_GetSigLen(const XmssKey* key, word32* len);
WOLFSSL_API int  wc_XmssKey_GetPubLen(const XmssKey* key, word32* len);
WOLFSSL_API int  wc_XmssKey_ExportPub(XmssKey* keyDst, const XmssKey* keySrc);
WOLFSSL_API int  wc_XmssKey_ExportPub_ex(XmssKey* keyDst, const XmssKey* keySrc,
    void* heap, int devId);
WOLFSSL_API int  wc_XmssKey_ExportPubRaw(const XmssKey* key, byte* out,
    word32* outLen);
WOLFSSL_API int  wc_XmssKey_ImportPubRaw(XmssKey* key, const byte* in,
    word32 inLen);
WOLFSSL_API int  wc_XmssKey_ImportPubRaw_ex(XmssKey* key, const byte* in,
    word32 inLen, int is_xmssmt);
WOLFSSL_API int  wc_XmssKey_Verify(XmssKey* key, const byte* sig, word32 sigSz,
    const byte* msg, int msgSz);

WOLFSSL_LOCAL int wc_xmssmt_keygen(XmssState *state, const unsigned char* seed,
    unsigned char *sk, unsigned char *pk);
/* Work out what the CPU can do; called from wc_XmssKey_Init(). */
WOLFSSL_LOCAL void wc_xmss_init(void);

WOLFSSL_LOCAL int wc_xmss_keygen(XmssState *state, const unsigned char* seed,
    unsigned char *sk, unsigned char *pk);

WOLFSSL_LOCAL int wc_xmssmt_sign(XmssState *state, const unsigned char *m,
    word32 mlen, unsigned char *sk, unsigned char *sm);
WOLFSSL_LOCAL int wc_xmss_sign(XmssState *state, const unsigned char *m,
    word32 mlen, unsigned char *sk, unsigned char *sm);

WOLFSSL_LOCAL int wc_xmss_sigsleft(const XmssParams* params, unsigned char* sk);

WOLFSSL_LOCAL int wc_xmssmt_verify(XmssState *state, const unsigned char *m,
    word32 mlen, const unsigned char *sm, const unsigned char *pk);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* WOLFSSL_HAVE_XMSS */
#endif /* WC_XMSS_H */
