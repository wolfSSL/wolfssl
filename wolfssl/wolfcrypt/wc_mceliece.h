/* wc_mceliece.h
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
    \file wolfssl/wolfcrypt/wc_mceliece.h
*/

/* Implementation of the Classic McEliece KEM based on binary Goppa codes, as
 * specified in draft-josefsson-mceliece-05. This is a code-based KEM (like
 * ML-KEM and FrodoKEM); it trades a large public key for conservative,
 * well-studied security. All parameter sets use m = 13 (field GF(2^13)). */

#ifndef WOLF_CRYPT_WC_MCELIECE_H
#define WOLF_CRYPT_WC_MCELIECE_H

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha3.h>

#ifdef WOLFSSL_HAVE_MCELIECE

#ifdef __cplusplus
    extern "C" {
#endif

/* Define algorithm parameter sets when not excluded. */
#ifndef WOLFSSL_NO_MCELIECE_6688128
    #define WOLFSSL_WC_MCELIECE_6688128
#endif
#ifndef WOLFSSL_NO_MCELIECE_6960119
    #define WOLFSSL_WC_MCELIECE_6960119
#endif
#ifndef WOLFSSL_NO_MCELIECE_8192128
    #define WOLFSSL_WC_MCELIECE_8192128
#endif

#if !defined(WOLFSSL_WC_MCELIECE_6688128) && \
    !defined(WOLFSSL_WC_MCELIECE_6960119) && \
    !defined(WOLFSSL_WC_MCELIECE_8192128)
    #error "No Classic McEliece parameter set chosen."
#endif

/* Operations are individually selectable: define WOLFSSL_MCELIECE_NO_MAKE_KEY,
 * WOLFSSL_MCELIECE_NO_ENCAPSULATE and/or WOLFSSL_MCELIECE_NO_DECAPSULATE to
 * exclude them. At least one operation must remain. */
#if defined(WOLFSSL_MCELIECE_NO_MAKE_KEY) && \
    defined(WOLFSSL_MCELIECE_NO_ENCAPSULATE) && \
    defined(WOLFSSL_MCELIECE_NO_DECAPSULATE)
    #error "No Classic McEliece operations to be built."
#endif

/* Parameter-set variants (forms) are individually selectable, each excluded
 * from every base set by its macro: WOLFSSL_MCELIECE_NO_PLAIN (no modifier),
 * WOLFSSL_MCELIECE_NO_F (semi-systematic), WOLFSSL_MCELIECE_NO_PC (plaintext
 * confirmation) and WOLFSSL_MCELIECE_NO_PCF (both). Combined with the per-set
 * WOLFSSL_NO_MCELIECE_<set> switches, a build can include as little as a single
 * one of the twelve parameter types. At least one form must remain. */
#if defined(WOLFSSL_MCELIECE_NO_PLAIN) && defined(WOLFSSL_MCELIECE_NO_F) && \
    defined(WOLFSSL_MCELIECE_NO_PC) && defined(WOLFSSL_MCELIECE_NO_PCF)
    #error "No Classic McEliece parameter variant to be built."
#endif

/* Field extension degree - constant across all draft parameter sets. */
#define MCELIECE_M              13
/* Field size q = 2^m. */
#define MCELIECE_Q             (1 << MCELIECE_M)
/* Mask for a field element (low m bits). */
#define MCELIECE_GF_MASK       (MCELIECE_Q - 1)

/* Bytes per field element: CEILING(m / 8). */
#define MCELIECE_GF_BYTES      ((MCELIECE_M + 7) / 8)

/* Length in bytes of the delta seed and the shared secret / session key. */
#define MCELIECE_SEED_SZ       32
#define MCELIECE_SS_SZ         32
/* Hash output length in bytes (HashLen / 8 = 256 / 8). */
#define MCELIECE_HASH_SZ       32
/* Length in bytes of the private-key column-selection field c. Always 8 for
 * the draft parameter sets ((u, v) = (0, 0) or (32, 64), CEILING(v / 8)). */
#define MCELIECE_C_SZ          8

/* Bytes of Benes-network control bits stored in a private key:
 * CEILING((2m - 1) * 2^(m - 4)) = 25 * 512 = 12800 for m = 13. */
#define MCELIECE_COND_BYTES \
    ((2 * MCELIECE_M - 1) * (1 << (MCELIECE_M - 4)))

/* Derived parameter helpers from code length n and error weight t. */
#define MCELIECE_MT(t)         (MCELIECE_M * (t))
#define MCELIECE_K(n, t)       ((n) - MCELIECE_MT(t))
/* FixedWeight draws tau samples per attempt: t when n == q (= 2^m), else 2t
 * (draft: tau = t if n == q; 2t if q/2 <= n < q). Only mceliece8192128 has
 * n == q. */
#define MCELIECE_TAU(n, t)     (((n) == (1 << MCELIECE_M)) ? (t) : (2 * (t)))
/* Irreducible Goppa polynomial: t coefficients, each CEILING(m / 8) bytes. */
#define MCELIECE_IRR_SZ(t)     ((t) * MCELIECE_GF_BYTES)
/* Syndrome / non-pc ciphertext length: CEILING(mt / 8). */
#define MCELIECE_SYND_SZ(t)    ((MCELIECE_MT(t) + 7) / 8)
/* Error / implicit-rejection vector length: CEILING(n / 8). */
#define MCELIECE_S_SZ(n)       (((n) + 7) / 8)

/* Public key T: mt rows, each CEILING(k / 8) bytes. */
#define MCELIECE_PK_SZ(n, t) \
    (MCELIECE_MT(t) * ((MCELIECE_K(n, t) + 7) / 8))
/* Private key: delta || c || g || control-bits || s. */
#define MCELIECE_SK_SZ(n, t) \
    (MCELIECE_SEED_SZ + MCELIECE_C_SZ + MCELIECE_IRR_SZ(t) + \
     MCELIECE_COND_BYTES + MCELIECE_S_SZ(n))
/* Ciphertext without / with plaintext confirmation. */
#define MCELIECE_CT_SZ(t)      (MCELIECE_SYND_SZ(t))
#define MCELIECE_CT_PC_SZ(t)   (MCELIECE_SYND_SZ(t) + MCELIECE_HASH_SZ)

/* mceliece6688128 parameters. */
#define WC_MCELIECE_6688128_N            6688
#define WC_MCELIECE_6688128_T            128
#define WC_MCELIECE_6688128_PUBLIC_KEY_SIZE \
    MCELIECE_PK_SZ(WC_MCELIECE_6688128_N, WC_MCELIECE_6688128_T)
#define WC_MCELIECE_6688128_PRIVATE_KEY_SIZE \
    MCELIECE_SK_SZ(WC_MCELIECE_6688128_N, WC_MCELIECE_6688128_T)
#define WC_MCELIECE_6688128_CIPHER_TEXT_SIZE \
    MCELIECE_CT_SZ(WC_MCELIECE_6688128_T)
#define WC_MCELIECE_6688128_PC_CIPHER_TEXT_SIZE \
    MCELIECE_CT_PC_SZ(WC_MCELIECE_6688128_T)

/* mceliece6960119 parameters. */
#define WC_MCELIECE_6960119_N            6960
#define WC_MCELIECE_6960119_T            119
#define WC_MCELIECE_6960119_PUBLIC_KEY_SIZE \
    MCELIECE_PK_SZ(WC_MCELIECE_6960119_N, WC_MCELIECE_6960119_T)
#define WC_MCELIECE_6960119_PRIVATE_KEY_SIZE \
    MCELIECE_SK_SZ(WC_MCELIECE_6960119_N, WC_MCELIECE_6960119_T)
#define WC_MCELIECE_6960119_CIPHER_TEXT_SIZE \
    MCELIECE_CT_SZ(WC_MCELIECE_6960119_T)
#define WC_MCELIECE_6960119_PC_CIPHER_TEXT_SIZE \
    MCELIECE_CT_PC_SZ(WC_MCELIECE_6960119_T)

/* mceliece8192128 parameters. */
#define WC_MCELIECE_8192128_N            8192
#define WC_MCELIECE_8192128_T            128
#define WC_MCELIECE_8192128_PUBLIC_KEY_SIZE \
    MCELIECE_PK_SZ(WC_MCELIECE_8192128_N, WC_MCELIECE_8192128_T)
#define WC_MCELIECE_8192128_PRIVATE_KEY_SIZE \
    MCELIECE_SK_SZ(WC_MCELIECE_8192128_N, WC_MCELIECE_8192128_T)
#define WC_MCELIECE_8192128_CIPHER_TEXT_SIZE \
    MCELIECE_CT_SZ(WC_MCELIECE_8192128_T)
#define WC_MCELIECE_8192128_PC_CIPHER_TEXT_SIZE \
    MCELIECE_CT_PC_SZ(WC_MCELIECE_8192128_T)

/* Shared-secret size is constant across all parameter sets. */
#define WC_MCELIECE_SS_SIZE             MCELIECE_SS_SZ

/* Maximum public-/private-key sizes over the enabled parameter sets. Public
 * key sizes increase 6688128 < 6960119 < 8192128, as do private key sizes, so
 * a simple cascade selects the maximum. */
#ifdef WOLFSSL_WC_MCELIECE_8192128
    #define MCELIECE_MAX_PUBLIC_KEY_SIZE \
        WC_MCELIECE_8192128_PUBLIC_KEY_SIZE
    #define MCELIECE_MAX_PRIVATE_KEY_SIZE \
        WC_MCELIECE_8192128_PRIVATE_KEY_SIZE
#elif defined(WOLFSSL_WC_MCELIECE_6960119)
    #define MCELIECE_MAX_PUBLIC_KEY_SIZE \
        WC_MCELIECE_6960119_PUBLIC_KEY_SIZE
    #define MCELIECE_MAX_PRIVATE_KEY_SIZE \
        WC_MCELIECE_6960119_PRIVATE_KEY_SIZE
#else
    #define MCELIECE_MAX_PUBLIC_KEY_SIZE \
        WC_MCELIECE_6688128_PUBLIC_KEY_SIZE
    #define MCELIECE_MAX_PRIVATE_KEY_SIZE \
        WC_MCELIECE_6688128_PRIVATE_KEY_SIZE
#endif

/* Maximum ciphertext size over the enabled sets. The pc variants add 32 bytes;
 * mt is largest (1664) for the 128-error sets, so their pc ciphertext (240) is
 * the overall maximum when either is enabled, else 6960119's pc size (226). */
#if defined(WOLFSSL_WC_MCELIECE_8192128) || \
    defined(WOLFSSL_WC_MCELIECE_6688128)
    #define MCELIECE_MAX_CIPHER_TEXT_SIZE \
        MCELIECE_CT_PC_SZ(WC_MCELIECE_8192128_T)
#else
    #define MCELIECE_MAX_CIPHER_TEXT_SIZE \
        MCELIECE_CT_PC_SZ(WC_MCELIECE_6960119_T)
#endif


enum {
    /* Base parameter sets. On their own these select the standard Classic
     * McEliece using systematic MatGen and no plaintext confirmation. */
    WC_MCELIECE_6688128 = 0,
    WC_MCELIECE_6960119 = 1,
    WC_MCELIECE_8192128 = 2,

    /* Modifier bits OR'd with a base parameter set to form a key type. */
    MCELIECE_F  = 0x10, /* Semi-systematic MatGen, (mu, nu) = (32, 64). */
    MCELIECE_PC = 0x20, /* Plaintext confirmation (extra 32-byte C1). */

    /* Mask to extract the base parameter set from a type. */
    MCELIECE_BASE_MASK = 0x0F,

    /* Explicit named types: standard (systematic, no plaintext confirm). */
    WC_MCELIECE_6688128F   = WC_MCELIECE_6688128 | MCELIECE_F,
    WC_MCELIECE_6688128PC  = WC_MCELIECE_6688128 | MCELIECE_PC,
    WC_MCELIECE_6688128PCF = WC_MCELIECE_6688128 | MCELIECE_PC | MCELIECE_F,
    WC_MCELIECE_6960119F   = WC_MCELIECE_6960119 | MCELIECE_F,
    WC_MCELIECE_6960119PC  = WC_MCELIECE_6960119 | MCELIECE_PC,
    WC_MCELIECE_6960119PCF = WC_MCELIECE_6960119 | MCELIECE_PC | MCELIECE_F,
    WC_MCELIECE_8192128F   = WC_MCELIECE_8192128 | MCELIECE_F,
    WC_MCELIECE_8192128PC  = WC_MCELIECE_8192128 | MCELIECE_PC,
    WC_MCELIECE_8192128PCF = WC_MCELIECE_8192128 | MCELIECE_PC | MCELIECE_F,

    /* Flags indicating what is stored in a key. */
    MCELIECE_FLAG_PRIV_SET = 0x0001,
    MCELIECE_FLAG_PUB_SET  = 0x0002,
    MCELIECE_FLAG_BOTH_SET = 0x0003
};


/* Run-time parameters for a Classic McEliece parameter set. The definition is
 * internal (see wc_mceliece_mat.h); a key only holds a pointer to a constant
 * instance selected by wc_McElieceKey_Init. */
typedef struct McElieceParams McElieceParams;


/* Classic McEliece key.
 *
 * Unlike ML-KEM and FrodoKEM, the public key (about 1 MB) and the private key
 * (about 14 KB) are heap-allocated with the memory hint rather than embedded in
 * the struct, because embedding a 1 MB array per key is not viable. The struct
 * therefore holds pointers that are allocated on demand (MakeKey / Decode*) and
 * released by wc_McElieceKey_Free. */
typedef struct McElieceKey {
    /* Type of key: a base parameter set optionally OR'd with MCELIECE_F and/or
     * MCELIECE_PC. */
    int type;
    /* Parameters for this key type (points to a constant). Set by Init. */
    const McElieceParams* params;
    /* Dynamic memory allocation hint. */
    void* heap;
    /* Device Id. */
    int devId;
    /* Flags indicating what is stored in the key. */
    int flags;

    /* Heap-allocated encoded public key T (params->pubSz bytes) or NULL. */
    byte* pub;
    /* Heap-allocated encoded private key (params->privSz bytes) or NULL. */
    byte* priv;

    /* Reusable SHAKE-256 object for the PRG and all hashing. Embedded (not
     * allocated); initialized by wc_McElieceKey_Init. */
    wc_Shake shake;
} McElieceKey;


#ifndef WC_NO_CONSTRUCTORS
WOLFSSL_API McElieceKey* wc_McElieceKey_New(int type, void* heap, int devId);
WOLFSSL_API int wc_McElieceKey_Delete(McElieceKey* key, McElieceKey** key_p);
#endif

WOLFSSL_API int wc_McElieceKey_Init(McElieceKey* key, int type, void* heap,
    int devId);
WOLFSSL_API int wc_McElieceKey_Free(McElieceKey* key);

#ifndef WOLFSSL_MCELIECE_NO_MAKE_KEY
WOLFSSL_API int wc_McElieceKey_MakeKey(McElieceKey* key, WC_RNG* rng);
WOLFSSL_API int wc_McElieceKey_MakeKeyWithRandom(McElieceKey* key,
    const unsigned char* rand, int len);
#endif

WOLFSSL_API int wc_McElieceKey_CipherTextSize(const McElieceKey* key,
    word32* len);
WOLFSSL_API int wc_McElieceKey_SharedSecretSize(const McElieceKey* key,
    word32* len);

#ifndef WOLFSSL_MCELIECE_NO_ENCAPSULATE
WOLFSSL_API int wc_McElieceKey_Encapsulate(McElieceKey* key, unsigned char* ct,
    unsigned char* ss, WC_RNG* rng);
WOLFSSL_API int wc_McElieceKey_EncapsulateWithRandom(McElieceKey* key,
    unsigned char* ct, unsigned char* ss, const unsigned char* rand, int len);
#endif
#ifndef WOLFSSL_MCELIECE_NO_DECAPSULATE
WOLFSSL_API int wc_McElieceKey_Decapsulate(McElieceKey* key, unsigned char* ss,
    const unsigned char* ct, word32 len);
#endif

WOLFSSL_API int wc_McElieceKey_DecodePrivateKey(McElieceKey* key,
    const unsigned char* in, word32 len);
WOLFSSL_API int wc_McElieceKey_DecodePublicKey(McElieceKey* key,
    const unsigned char* in, word32 len);

WOLFSSL_API int wc_McElieceKey_PrivateKeySize(const McElieceKey* key,
    word32* len);
WOLFSSL_API int wc_McElieceKey_PublicKeySize(const McElieceKey* key,
    word32* len);
WOLFSSL_API int wc_McElieceKey_EncodePrivateKey(McElieceKey* key,
    unsigned char* out, word32 len);
WOLFSSL_API int wc_McElieceKey_EncodePublicKey(McElieceKey* key,
    unsigned char* out, word32 len);


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_HAVE_MCELIECE */

#endif /* WOLF_CRYPT_WC_MCELIECE_H */
