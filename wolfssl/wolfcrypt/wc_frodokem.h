/* wc_frodokem.h
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
    \file wolfssl/wolfcrypt/wc_frodokem.h
*/

#ifndef WOLF_CRYPT_WC_FRODOKEM_H
#define WOLF_CRYPT_WC_FRODOKEM_H

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha3.h>
#ifdef WOLFSSL_FRODOKEM_AES
    #include <wolfssl/wolfcrypt/aes.h>
#endif

#ifdef WOLFSSL_HAVE_FRODOKEM

#ifdef __cplusplus
    extern "C" {
#endif

/* Define algorithm parameter sets when not excluded. */
#ifndef WOLFSSL_NO_FRODOKEM_640
    #define WOLFSSL_WC_FRODOKEM_640
#endif
#ifndef WOLFSSL_NO_FRODOKEM_976
    #define WOLFSSL_WC_FRODOKEM_976
#endif
#ifndef WOLFSSL_NO_FRODOKEM_1344
    #define WOLFSSL_WC_FRODOKEM_1344
#endif

#if !defined(WOLFSSL_WC_FRODOKEM_640) && !defined(WOLFSSL_WC_FRODOKEM_976) && \
    !defined(WOLFSSL_WC_FRODOKEM_1344)
    #error "No FrodoKEM parameter set chosen."
#endif

/* Matrix A generation method(s). AES-128 (Section 6.7.1) and SHAKE-128
 * (Section 6.7.2) are independently selectable build options; at least one
 * must be enabled. */
#if !defined(WOLFSSL_FRODOKEM_AES) && !defined(WOLFSSL_FRODOKEM_SHAKE)
    #error "FrodoKEM needs WOLFSSL_FRODOKEM_AES and/or WOLFSSL_FRODOKEM_SHAKE."
#endif

/* WOLFSSL_FRODOKEM_EPHEMERAL enables the eFrodoKEM (ephemeral, salt-less)
 * parameter set types. */

/* Operations are individually selectable: define WOLFSSL_FRODOKEM_NO_MAKE_KEY,
 * WOLFSSL_FRODOKEM_NO_ENCAPSULATE and/or WOLFSSL_FRODOKEM_NO_DECAPSULATE to
 * exclude them. At least one operation must remain. */
#if defined(WOLFSSL_FRODOKEM_NO_MAKE_KEY) && \
    defined(WOLFSSL_FRODOKEM_NO_ENCAPSULATE) && \
    defined(WOLFSSL_FRODOKEM_NO_DECAPSULATE)
    #error "No FrodoKEM operations to be built."
#endif

/* Number of columns in the "small" matrices - constant across all parameter
 * sets (n-bar = m-bar = 8). */
#define FRODOKEM_NBAR       8

/* Number of elements in an nbar x nbar matrix. */
#define FRODOKEM_NBAR_SQ    (FRODOKEM_NBAR * FRODOKEM_NBAR)

/* Length of the seed for generating matrix A (lenA / 8 = 128 / 8). */
#define FRODOKEM_SEEDA_SZ   16

/* Size in bytes of a public key: seedA || b (b = nbar * n coefficients of D
 * bits each = D * n bytes, nbar == 8). */
#define FRODOKEM_PK_SZ(n, d)        (FRODOKEM_SEEDA_SZ + ((d) * (n)))
/* Size in bytes of a private key: s || seedA || b || S^T || pkh.
 * S^T holds nbar * n coefficients, each stored as 2 bytes. */
#define FRODOKEM_SK_SZ(n, d, ls)    ((ls) + FRODOKEM_SEEDA_SZ + ((d) * (n)) + \
                                     (2 * FRODOKEM_NBAR * (n)) + (ls))
/* Size in bytes of a ciphertext: c1 || c2 || salt.
 * c1 = D * nbar * n bits, c2 = D * nbar * nbar bits. */
#define FRODOKEM_CT_SZ(n, d, lsalt) (((d) * (n)) + ((d) * FRODOKEM_NBAR) + \
                                     (lsalt))

/* FrodoKEM-640 parameters. */
#define WC_FRODOKEM_640_N               640
#define WC_FRODOKEM_640_D               15
#define WC_FRODOKEM_640_LENSEC          16      /* lensec  / 8 = 128 / 8  */
#define WC_FRODOKEM_640_LENSE           32      /* lenSE   / 8 = 256 / 8  */
#define WC_FRODOKEM_640_LENSALT         32      /* lensalt / 8 = 256 / 8  */
#define WC_FRODOKEM_640_PUBLIC_KEY_SIZE \
    FRODOKEM_PK_SZ(WC_FRODOKEM_640_N, WC_FRODOKEM_640_D)
#define WC_FRODOKEM_640_PRIVATE_KEY_SIZE \
    FRODOKEM_SK_SZ(WC_FRODOKEM_640_N, WC_FRODOKEM_640_D, WC_FRODOKEM_640_LENSEC)
#define WC_FRODOKEM_640_CIPHER_TEXT_SIZE \
    FRODOKEM_CT_SZ(WC_FRODOKEM_640_N, WC_FRODOKEM_640_D, \
        WC_FRODOKEM_640_LENSALT)
#define WC_FRODOKEM_640_SS_SIZE         WC_FRODOKEM_640_LENSEC
#define WC_FRODOKEM_640_MAKEKEY_RAND_SZ \
    (WC_FRODOKEM_640_LENSEC + WC_FRODOKEM_640_LENSE + FRODOKEM_SEEDA_SZ)
#define WC_FRODOKEM_640_ENC_RAND_SZ \
    (WC_FRODOKEM_640_LENSEC + WC_FRODOKEM_640_LENSALT)

/* FrodoKEM-976 parameters. */
#define WC_FRODOKEM_976_N               976
#define WC_FRODOKEM_976_D               16
#define WC_FRODOKEM_976_LENSEC          24      /* lensec  / 8 = 192 / 8  */
#define WC_FRODOKEM_976_LENSE           48      /* lenSE   / 8 = 384 / 8  */
#define WC_FRODOKEM_976_LENSALT         48      /* lensalt / 8 = 384 / 8  */
#define WC_FRODOKEM_976_PUBLIC_KEY_SIZE \
    FRODOKEM_PK_SZ(WC_FRODOKEM_976_N, WC_FRODOKEM_976_D)
#define WC_FRODOKEM_976_PRIVATE_KEY_SIZE \
    FRODOKEM_SK_SZ(WC_FRODOKEM_976_N, WC_FRODOKEM_976_D, WC_FRODOKEM_976_LENSEC)
#define WC_FRODOKEM_976_CIPHER_TEXT_SIZE \
    FRODOKEM_CT_SZ(WC_FRODOKEM_976_N, WC_FRODOKEM_976_D, \
        WC_FRODOKEM_976_LENSALT)
#define WC_FRODOKEM_976_SS_SIZE         WC_FRODOKEM_976_LENSEC
#define WC_FRODOKEM_976_MAKEKEY_RAND_SZ \
    (WC_FRODOKEM_976_LENSEC + WC_FRODOKEM_976_LENSE + FRODOKEM_SEEDA_SZ)
#define WC_FRODOKEM_976_ENC_RAND_SZ \
    (WC_FRODOKEM_976_LENSEC + WC_FRODOKEM_976_LENSALT)

/* FrodoKEM-1344 parameters. */
#define WC_FRODOKEM_1344_N              1344
#define WC_FRODOKEM_1344_D              16
#define WC_FRODOKEM_1344_LENSEC         32      /* lensec  / 8 = 256 / 8  */
#define WC_FRODOKEM_1344_LENSE          64      /* lenSE   / 8 = 512 / 8  */
#define WC_FRODOKEM_1344_LENSALT        64      /* lensalt / 8 = 512 / 8  */
#define WC_FRODOKEM_1344_PUBLIC_KEY_SIZE \
    FRODOKEM_PK_SZ(WC_FRODOKEM_1344_N, WC_FRODOKEM_1344_D)
#define WC_FRODOKEM_1344_PRIVATE_KEY_SIZE \
    FRODOKEM_SK_SZ(WC_FRODOKEM_1344_N, WC_FRODOKEM_1344_D, \
        WC_FRODOKEM_1344_LENSEC)
#define WC_FRODOKEM_1344_CIPHER_TEXT_SIZE \
    FRODOKEM_CT_SZ(WC_FRODOKEM_1344_N, WC_FRODOKEM_1344_D, \
        WC_FRODOKEM_1344_LENSALT)
#define WC_FRODOKEM_1344_SS_SIZE        WC_FRODOKEM_1344_LENSEC
#define WC_FRODOKEM_1344_MAKEKEY_RAND_SZ \
    (WC_FRODOKEM_1344_LENSEC + WC_FRODOKEM_1344_LENSE + FRODOKEM_SEEDA_SZ)
#define WC_FRODOKEM_1344_ENC_RAND_SZ \
    (WC_FRODOKEM_1344_LENSEC + WC_FRODOKEM_1344_LENSALT)

/* Maximum dimensions and sizes over the enabled parameter sets. */
#ifdef WOLFSSL_WC_FRODOKEM_1344
    #define FRODOKEM_MAX_N                  WC_FRODOKEM_1344_N
    #define FRODOKEM_MAX_LENSEC             WC_FRODOKEM_1344_LENSEC
    #define FRODOKEM_MAX_LENSE              WC_FRODOKEM_1344_LENSE
    #define FRODOKEM_MAX_LENSALT            WC_FRODOKEM_1344_LENSALT
    #define FRODOKEM_MAX_D                  WC_FRODOKEM_1344_D
    #define FRODOKEM_MAX_PUBLIC_KEY_SIZE    WC_FRODOKEM_1344_PUBLIC_KEY_SIZE
    #define FRODOKEM_MAX_PRIVATE_KEY_SIZE   WC_FRODOKEM_1344_PRIVATE_KEY_SIZE
    #define FRODOKEM_MAX_CIPHER_TEXT_SIZE   WC_FRODOKEM_1344_CIPHER_TEXT_SIZE
#elif defined(WOLFSSL_WC_FRODOKEM_976)
    #define FRODOKEM_MAX_N                  WC_FRODOKEM_976_N
    #define FRODOKEM_MAX_LENSEC             WC_FRODOKEM_976_LENSEC
    #define FRODOKEM_MAX_LENSE              WC_FRODOKEM_976_LENSE
    #define FRODOKEM_MAX_LENSALT            WC_FRODOKEM_976_LENSALT
    #define FRODOKEM_MAX_D                  WC_FRODOKEM_976_D
    #define FRODOKEM_MAX_PUBLIC_KEY_SIZE    WC_FRODOKEM_976_PUBLIC_KEY_SIZE
    #define FRODOKEM_MAX_PRIVATE_KEY_SIZE   WC_FRODOKEM_976_PRIVATE_KEY_SIZE
    #define FRODOKEM_MAX_CIPHER_TEXT_SIZE   WC_FRODOKEM_976_CIPHER_TEXT_SIZE
#else
    #define FRODOKEM_MAX_N                  WC_FRODOKEM_640_N
    #define FRODOKEM_MAX_LENSEC             WC_FRODOKEM_640_LENSEC
    #define FRODOKEM_MAX_LENSE              WC_FRODOKEM_640_LENSE
    #define FRODOKEM_MAX_LENSALT            WC_FRODOKEM_640_LENSALT
    #define FRODOKEM_MAX_D                  WC_FRODOKEM_640_D
    #define FRODOKEM_MAX_PUBLIC_KEY_SIZE    WC_FRODOKEM_640_PUBLIC_KEY_SIZE
    #define FRODOKEM_MAX_PRIVATE_KEY_SIZE   WC_FRODOKEM_640_PRIVATE_KEY_SIZE
    #define FRODOKEM_MAX_CIPHER_TEXT_SIZE   WC_FRODOKEM_640_CIPHER_TEXT_SIZE
#endif

/* Size in bytes of the packed public matrix b (D * n bits => D * n bytes as
 * nbar == 8). */
#define FRODOKEM_MAX_B_SZ       (FRODOKEM_MAX_D * FRODOKEM_MAX_N)
/* Number of coefficients in the secret matrix S^T (nbar * n). */
#define FRODOKEM_MAX_S_CNT      (FRODOKEM_NBAR * FRODOKEM_MAX_N)


enum {
    /* Base parameter sets. On their own these select the standard (salted)
     * FrodoKEM using SHAKE-128 to generate matrix A. */
    WC_FRODOKEM_640  = 0,
    WC_FRODOKEM_976  = 1,
    WC_FRODOKEM_1344 = 2,

    /* Modifier bits OR'd with a base parameter set to form a key type. */
    FRODOKEM_AES        = 0x10, /* Generate matrix A with AES-128. */
    FRODOKEM_EPHEMERAL  = 0x20, /* eFrodoKEM: ephemeral, no salt. */

    /* Mask to extract the base parameter set from a type. */
    FRODOKEM_BASE_MASK  = 0x0F,

    /* Explicit named types: FrodoKEM (standard, salted). */
    WC_FRODOKEM_640_SHAKE   = WC_FRODOKEM_640,
    WC_FRODOKEM_976_SHAKE   = WC_FRODOKEM_976,
    WC_FRODOKEM_1344_SHAKE  = WC_FRODOKEM_1344,
    WC_FRODOKEM_640_AES     = WC_FRODOKEM_640  | FRODOKEM_AES,
    WC_FRODOKEM_976_AES     = WC_FRODOKEM_976  | FRODOKEM_AES,
    WC_FRODOKEM_1344_AES    = WC_FRODOKEM_1344 | FRODOKEM_AES,

    /* Explicit named types: eFrodoKEM (ephemeral). */
    WC_EFRODOKEM_640_SHAKE  = WC_FRODOKEM_640  | FRODOKEM_EPHEMERAL,
    WC_EFRODOKEM_976_SHAKE  = WC_FRODOKEM_976  | FRODOKEM_EPHEMERAL,
    WC_EFRODOKEM_1344_SHAKE = WC_FRODOKEM_1344 | FRODOKEM_EPHEMERAL,
    WC_EFRODOKEM_640_AES    = WC_EFRODOKEM_640_SHAKE  | FRODOKEM_AES,
    WC_EFRODOKEM_976_AES    = WC_EFRODOKEM_976_SHAKE  | FRODOKEM_AES,
    WC_EFRODOKEM_1344_AES   = WC_EFRODOKEM_1344_SHAKE | FRODOKEM_AES,

    /* Flags indicating what is stored in a key. */
    FRODOKEM_FLAG_PRIV_SET = 0x0001,
    FRODOKEM_FLAG_PUB_SET  = 0x0002,
    FRODOKEM_FLAG_BOTH_SET = 0x0003,
    FRODOKEM_FLAG_PKH_SET  = 0x0004
};


/* Run-time parameters for a FrodoKEM parameter set. The definition is internal
 * (see wc_frodokem_mat.h); a key only holds a pointer to a constant instance. */
typedef struct FrodoKemParams FrodoKemParams;


/* FrodoKEM key. */
typedef struct FrodoKemKey {
    /* Type of key: a base parameter set optionally OR'd with FRODOKEM_AES
     * and/or FRODOKEM_EPHEMERAL. */
    int type;
    /* Parameters for this key type (points to a constant). Set by Init. */
    const FrodoKemParams* params;
    /* Dynamic memory allocation hint. */
    void* heap;
    /* Device Id. */
    int devId;
    /* Flags indicating what is stored in the key. */
    int flags;

    /* Secret value used for implicit rejection (length lenSec). */
    byte s[FRODOKEM_MAX_LENSEC];
    /* Secret matrix S^T (nbar x n) stored row-major as residues modulo q. */
    word16 sMat[FRODOKEM_MAX_S_CNT];

    /* Seed used to generate matrix A. */
    byte seedA[FRODOKEM_SEEDA_SZ];
    /* Packed public matrix B (D * n bytes). */
    byte b[FRODOKEM_MAX_B_SZ];
    /* Hash of the public key (length lenSec). */
    byte pkh[FRODOKEM_MAX_LENSEC];

    /* Reusable SHAKE object for all hashing and matrix-A generation. Embedded
     * (not allocated); initialized by wc_FrodoKemKey_Init for the key's SHAKE
     * variant. Matrix-A generation always uses SHAKE-128; the hashing SHAKE is
     * SHAKE-128 for FrodoKEM-640 and SHAKE-256 for -976 / -1344. */
    wc_Shake shake;
#ifdef WOLFSSL_FRODOKEM_AES
    /* Reusable AES-128 object for matrix-A generation (AES key type). Embedded
     * (not allocated); wc_AesInit'd by wc_FrodoKemKey_Init and re-keyed with
     * seedA per operation. */
    Aes aes;
#endif
} FrodoKemKey;


WOLFSSL_API FrodoKemKey* wc_FrodoKemKey_New(int type, void* heap, int devId);
WOLFSSL_API int wc_FrodoKemKey_Delete(FrodoKemKey* key, FrodoKemKey** key_p);

WOLFSSL_API int wc_FrodoKemKey_Init(FrodoKemKey* key, int type, void* heap,
    int devId);
WOLFSSL_API int wc_FrodoKemKey_Free(FrodoKemKey* key);

#ifndef WOLFSSL_FRODOKEM_NO_MAKE_KEY
WOLFSSL_API int wc_FrodoKemKey_MakeKey(FrodoKemKey* key, WC_RNG* rng);
WOLFSSL_API int wc_FrodoKemKey_MakeKeyWithRandom(FrodoKemKey* key,
    const unsigned char* rand, int len);
#endif

WOLFSSL_API int wc_FrodoKemKey_CipherTextSize(const FrodoKemKey* key,
    word32* len);
WOLFSSL_API int wc_FrodoKemKey_SharedSecretSize(const FrodoKemKey* key,
    word32* len);

#ifndef WOLFSSL_FRODOKEM_NO_ENCAPSULATE
WOLFSSL_API int wc_FrodoKemKey_Encapsulate(FrodoKemKey* key, unsigned char* ct,
    unsigned char* ss, WC_RNG* rng);
WOLFSSL_API int wc_FrodoKemKey_EncapsulateWithRandom(FrodoKemKey* key,
    unsigned char* ct, unsigned char* ss, const unsigned char* rand, int len);
#endif
#ifndef WOLFSSL_FRODOKEM_NO_DECAPSULATE
WOLFSSL_API int wc_FrodoKemKey_Decapsulate(FrodoKemKey* key, unsigned char* ss,
    const unsigned char* ct, word32 len);
#endif

WOLFSSL_API int wc_FrodoKemKey_DecodePrivateKey(FrodoKemKey* key,
    const unsigned char* in, word32 len);
WOLFSSL_API int wc_FrodoKemKey_DecodePublicKey(FrodoKemKey* key,
    const unsigned char* in, word32 len);

WOLFSSL_API int wc_FrodoKemKey_PrivateKeySize(const FrodoKemKey* key,
    word32* len);
WOLFSSL_API int wc_FrodoKemKey_PublicKeySize(const FrodoKemKey* key,
    word32* len);
WOLFSSL_API int wc_FrodoKemKey_EncodePrivateKey(FrodoKemKey* key,
    unsigned char* out, word32 len);
WOLFSSL_API int wc_FrodoKemKey_EncodePublicKey(FrodoKemKey* key,
    unsigned char* out, word32 len);



#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_HAVE_FRODOKEM */

#endif /* WOLF_CRYPT_WC_FRODOKEM_H */
