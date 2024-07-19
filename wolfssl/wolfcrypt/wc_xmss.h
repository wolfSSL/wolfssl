/* wc_xmss.h
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
 */

#ifndef WC_XMSS_H
#define WC_XMSS_H

#ifdef WOLFSSL_HAVE_XMSS
#include <wolfssl/wolfcrypt/xmss.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/sha3.h>

#if !defined(WOLFSSL_WC_XMSS)
    #error "This code is incompatible with external implementation of XMSS."
#endif

#if (defined(WC_XMSS_SHA512) || defined(WC_XMSS_SHAKE256)) && \
        (WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 512)
    #define WC_XMSS_MAX_N               64
    #define WC_XMSS_MAX_PADDING_LEN     64
#else
    #define WC_XMSS_MAX_N               32
    #define WC_XMSS_MAX_PADDING_LEN     32
#endif
#define WC_XMSS_MAX_MSG_PRE_LEN     \
    (WC_XMSS_MAX_PADDING_LEN + 3 * WC_XMSS_MAX_N)
#define WC_XMSS_MAX_TREE_HEIGHT     20
#define WC_XMSS_MAX_CSUM_BYTES       4
#define WC_XMSS_MAX_WOTS_LEN        (8 * WC_XMSS_MAX_N / 4 + 3)
#define WC_XMSS_MAX_WOTS_SIG_LEN    (WC_XMSS_MAX_WOTS_LEN * WC_XMSS_MAX_N)
#define WC_XMSS_MAX_STACK_LEN       \
    ((WC_XMSS_MAX_TREE_HEIGHT + 1) * WC_XMSS_MAX_N)
#define WC_XMSS_MAX_D               12
#define WC_XMSS_MAX_BDS_STATES      (2 * WC_XMSS_MAX_D - 1)
#define WC_XMSS_MAX_TREE_HASH       \
    ((2 * WC_XMSS_MAX_D - 1) * WC_XMSS_MAX_TREE_HEIGHT)
#define WC_XMSS_MAX_BDS_K           0

#define WC_XMSS_ADDR_LEN            32

#define WC_XMSS_HASH_PRF_MAX_DATA_LEN               \
    (WC_XMSS_MAX_PADDING_LEN + 2 * WC_XMSS_MAX_N + WC_XMSS_ADDR_LEN)
#define WC_XMSS_HASH_MAX_DATA_LEN                   \
    (WC_XMSS_MAX_PADDING_LEN + 3 * WC_XMSS_MAX_N)


#define WC_XMSS_SHA256_N            32
#define WC_XMSS_SHA256_PADDING_LEN  32
#define WC_XMSS_SHA256_WOTS_LEN     67

#define XMSS_OID_LEN                   4

#define XMSS_MAX_HASH_LEN              WC_SHA256_DIGEST_SIZE

#define XMSS_RETAIN_LEN(k, n)   ((!!(k)) * ((1 << (k)) - (k) - 1) * (n))

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
typedef word32 HashAddress[8];

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
    /* State of key. */
    enum wc_XmssState    state;
};

typedef struct XmssState {
    const XmssParams* params;

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

WOLFSSL_LOCAL int wc_xmssmt_keygen(XmssState *state, const unsigned char* seed,
    unsigned char *sk, unsigned char *pk);
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

