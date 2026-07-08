/* wc_frodokem.c
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

/* Reference implementation of FrodoKEM.
 *
 * Implementation based on:
 *   https://www.ietf.org/archive/id/draft-longa-cfrg-frodokem-03.txt
 *
 * Matrix A is generated using SHAKE128 (Section 6.7.2 of the draft) and the
 * hashing function SHAKE is SHAKE128 for FrodoKEM-640 and SHAKE256 for
 * FrodoKEM-976 and FrodoKEM-1344 (Table 1).  The "standard" (salted) FrodoKEM
 * variants are implemented.
 *
 * The API mirrors the wolfCrypt ML-KEM API (see wc_mlkem.c), using FrodoKem in
 * the names in place of MlKem.
 */

#define _WC_BUILDING_WC_FRODOKEM_C

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#include <wolfssl/wolfcrypt/wc_frodokem_mat.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/memory.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifdef WOLFSSL_HAVE_FRODOKEM

/* Domain separator prepended to seedSE when generating key generation noise. */
#define FRODOKEM_DOMAIN_KEYGEN  0x5F
/* Domain separator prepended to seedSE when generating encapsulation noise. */
#define FRODOKEM_DOMAIN_ENCAPS  0x96

/******************************************************************************/
/* Parameter sets.                                                            */
/******************************************************************************/

#ifdef WOLFSSL_WC_FRODOKEM_640
/* CDF table for FrodoKEM-640 (Table 5). */
static const word16 frodokem_cdf_640[] = {
    4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745,
    32762, 32766, 32767
};
#endif

#ifdef WOLFSSL_WC_FRODOKEM_976
/* CDF table for FrodoKEM-976 (Table 5). */
static const word16 frodokem_cdf_976[] = {
    5638, 15915, 23689, 28571, 31116, 32217, 32613, 32731, 32760, 32766, 32767
};
#endif

#ifdef WOLFSSL_WC_FRODOKEM_1344
/* CDF table for FrodoKEM-1344 (Table 5). */
static const word16 frodokem_cdf_1344[] = {
    9142, 23462, 30338, 32361, 32725, 32765, 32767
};
#endif

/* Constant parameter sets.
 *
 * FrodoKemParams field order:
 *   n, d, qMask, b, cdf, cdfLen, lenSec, useShake256, pkSize, skSize,
 *   lenSE, lenSalt, ctSize, useAes
 * A base macro supplies the fields common to all variants of a parameter set
 * (through skSize); the per-type initializer appends lenSE, lenSalt, ctSize and
 * useAes. Standard FrodoKEM uses lenSE = lenSalt = 2 * lenSec and a salted
 * ciphertext; eFrodoKEM (ephemeral) uses lenSE = lenSec and no salt.
 */
#ifdef WOLFSSL_WC_FRODOKEM_640
#define FRODOKEM_BASE_640 \
    WC_FRODOKEM_640_N, WC_FRODOKEM_640_D, 0x7FFF, 2, frodokem_cdf_640, \
    (int)(sizeof(frodokem_cdf_640) / sizeof(frodokem_cdf_640[0])), \
    WC_FRODOKEM_640_LENSEC, 0, \
    WC_FRODOKEM_640_PUBLIC_KEY_SIZE, WC_FRODOKEM_640_PRIVATE_KEY_SIZE
#ifdef WOLFSSL_FRODOKEM_SHAKE
static const FrodoKemParams frodokem_p_640_shake =
    { FRODOKEM_BASE_640, WC_FRODOKEM_640_LENSE, WC_FRODOKEM_640_LENSALT,
      WC_FRODOKEM_640_CIPHER_TEXT_SIZE, 0 };
#ifdef WOLFSSL_FRODOKEM_EPHEMERAL
static const FrodoKemParams frodokem_ep_640_shake =
    { FRODOKEM_BASE_640, WC_FRODOKEM_640_LENSEC, 0,
      FRODOKEM_CT_SZ(WC_FRODOKEM_640_N, WC_FRODOKEM_640_D, 0), 0 };
#endif
#endif
#ifdef WOLFSSL_FRODOKEM_AES
static const FrodoKemParams frodokem_p_640_aes =
    { FRODOKEM_BASE_640, WC_FRODOKEM_640_LENSE, WC_FRODOKEM_640_LENSALT,
      WC_FRODOKEM_640_CIPHER_TEXT_SIZE, 1 };
#ifdef WOLFSSL_FRODOKEM_EPHEMERAL
static const FrodoKemParams frodokem_ep_640_aes =
    { FRODOKEM_BASE_640, WC_FRODOKEM_640_LENSEC, 0,
      FRODOKEM_CT_SZ(WC_FRODOKEM_640_N, WC_FRODOKEM_640_D, 0), 1 };
#endif
#endif
#endif /* WOLFSSL_WC_FRODOKEM_640 */

#ifdef WOLFSSL_WC_FRODOKEM_976
#define FRODOKEM_BASE_976 \
    WC_FRODOKEM_976_N, WC_FRODOKEM_976_D, 0xFFFF, 3, frodokem_cdf_976, \
    (int)(sizeof(frodokem_cdf_976) / sizeof(frodokem_cdf_976[0])), \
    WC_FRODOKEM_976_LENSEC, 1, \
    WC_FRODOKEM_976_PUBLIC_KEY_SIZE, WC_FRODOKEM_976_PRIVATE_KEY_SIZE
#ifdef WOLFSSL_FRODOKEM_SHAKE
static const FrodoKemParams frodokem_p_976_shake =
    { FRODOKEM_BASE_976, WC_FRODOKEM_976_LENSE, WC_FRODOKEM_976_LENSALT,
      WC_FRODOKEM_976_CIPHER_TEXT_SIZE, 0 };
#ifdef WOLFSSL_FRODOKEM_EPHEMERAL
static const FrodoKemParams frodokem_ep_976_shake =
    { FRODOKEM_BASE_976, WC_FRODOKEM_976_LENSEC, 0,
      FRODOKEM_CT_SZ(WC_FRODOKEM_976_N, WC_FRODOKEM_976_D, 0), 0 };
#endif
#endif
#ifdef WOLFSSL_FRODOKEM_AES
static const FrodoKemParams frodokem_p_976_aes =
    { FRODOKEM_BASE_976, WC_FRODOKEM_976_LENSE, WC_FRODOKEM_976_LENSALT,
      WC_FRODOKEM_976_CIPHER_TEXT_SIZE, 1 };
#ifdef WOLFSSL_FRODOKEM_EPHEMERAL
static const FrodoKemParams frodokem_ep_976_aes =
    { FRODOKEM_BASE_976, WC_FRODOKEM_976_LENSEC, 0,
      FRODOKEM_CT_SZ(WC_FRODOKEM_976_N, WC_FRODOKEM_976_D, 0), 1 };
#endif
#endif
#endif /* WOLFSSL_WC_FRODOKEM_976 */

#ifdef WOLFSSL_WC_FRODOKEM_1344
#define FRODOKEM_BASE_1344 \
    WC_FRODOKEM_1344_N, WC_FRODOKEM_1344_D, 0xFFFF, 4, frodokem_cdf_1344, \
    (int)(sizeof(frodokem_cdf_1344) / sizeof(frodokem_cdf_1344[0])), \
    WC_FRODOKEM_1344_LENSEC, 1, \
    WC_FRODOKEM_1344_PUBLIC_KEY_SIZE, WC_FRODOKEM_1344_PRIVATE_KEY_SIZE
#ifdef WOLFSSL_FRODOKEM_SHAKE
static const FrodoKemParams frodokem_p_1344_shake =
    { FRODOKEM_BASE_1344, WC_FRODOKEM_1344_LENSE, WC_FRODOKEM_1344_LENSALT,
      WC_FRODOKEM_1344_CIPHER_TEXT_SIZE, 0 };
#ifdef WOLFSSL_FRODOKEM_EPHEMERAL
static const FrodoKemParams frodokem_ep_1344_shake =
    { FRODOKEM_BASE_1344, WC_FRODOKEM_1344_LENSEC, 0,
      FRODOKEM_CT_SZ(WC_FRODOKEM_1344_N, WC_FRODOKEM_1344_D, 0), 0 };
#endif
#endif
#ifdef WOLFSSL_FRODOKEM_AES
static const FrodoKemParams frodokem_p_1344_aes =
    { FRODOKEM_BASE_1344, WC_FRODOKEM_1344_LENSE, WC_FRODOKEM_1344_LENSALT,
      WC_FRODOKEM_1344_CIPHER_TEXT_SIZE, 1 };
#ifdef WOLFSSL_FRODOKEM_EPHEMERAL
static const FrodoKemParams frodokem_ep_1344_aes =
    { FRODOKEM_BASE_1344, WC_FRODOKEM_1344_LENSEC, 0,
      FRODOKEM_CT_SZ(WC_FRODOKEM_1344_N, WC_FRODOKEM_1344_D, 0), 1 };
#endif
#endif
#endif /* WOLFSSL_WC_FRODOKEM_1344 */

/* Get the constant parameters for a key type.
 *
 * A type is a base parameter set (WC_FRODOKEM_640/976/1344) optionally OR'd
 * with FRODOKEM_AES (AES-128 matrix A) and/or FRODOKEM_EPHEMERAL (eFrodoKEM).
 *
 * @param  [in]  type  Type of key.
 * @return  Pointer to the constant parameters, or NULL when the type or a
 *          requested modifier is not compiled in.
 */
static const FrodoKemParams* frodokem_get_params(int type)
{
    const FrodoKemParams* p = NULL;

    switch (type) {
#ifdef WOLFSSL_WC_FRODOKEM_640
#ifdef WOLFSSL_FRODOKEM_SHAKE
    case WC_FRODOKEM_640_SHAKE:
        p = &frodokem_p_640_shake;
        break;
#ifdef WOLFSSL_FRODOKEM_EPHEMERAL
    case WC_EFRODOKEM_640_SHAKE:
        p = &frodokem_ep_640_shake;
        break;
#endif
#endif
#ifdef WOLFSSL_FRODOKEM_AES
    case WC_FRODOKEM_640_AES:
        p = &frodokem_p_640_aes;
        break;
#ifdef WOLFSSL_FRODOKEM_EPHEMERAL
    case WC_EFRODOKEM_640_AES:
        p = &frodokem_ep_640_aes;
        break;
#endif
#endif
#endif /* WOLFSSL_WC_FRODOKEM_640 */
#ifdef WOLFSSL_WC_FRODOKEM_976
#ifdef WOLFSSL_FRODOKEM_SHAKE
    case WC_FRODOKEM_976_SHAKE:
        p = &frodokem_p_976_shake;
        break;
#ifdef WOLFSSL_FRODOKEM_EPHEMERAL
    case WC_EFRODOKEM_976_SHAKE:
        p = &frodokem_ep_976_shake;
        break;
#endif
#endif
#ifdef WOLFSSL_FRODOKEM_AES
    case WC_FRODOKEM_976_AES:
        p = &frodokem_p_976_aes;
        break;
#ifdef WOLFSSL_FRODOKEM_EPHEMERAL
    case WC_EFRODOKEM_976_AES:
        p = &frodokem_ep_976_aes;
        break;
#endif
#endif
#endif /* WOLFSSL_WC_FRODOKEM_976 */
#ifdef WOLFSSL_WC_FRODOKEM_1344
#ifdef WOLFSSL_FRODOKEM_SHAKE
    case WC_FRODOKEM_1344_SHAKE:
        p = &frodokem_p_1344_shake;
        break;
#ifdef WOLFSSL_FRODOKEM_EPHEMERAL
    case WC_EFRODOKEM_1344_SHAKE:
        p = &frodokem_ep_1344_shake;
        break;
#endif
#endif
#ifdef WOLFSSL_FRODOKEM_AES
    case WC_FRODOKEM_1344_AES:
        p = &frodokem_p_1344_aes;
        break;
#ifdef WOLFSSL_FRODOKEM_EPHEMERAL
    case WC_EFRODOKEM_1344_AES:
        p = &frodokem_ep_1344_aes;
        break;
#endif
#endif
#endif /* WOLFSSL_WC_FRODOKEM_1344 */
    default:
        break;
    }

    return p;
}

/******************************************************************************/
/* Key object management.                                                     */
/******************************************************************************/

#ifndef WC_NO_CONSTRUCTORS
/* Create a new FrodoKEM key object.
 *
 * @param  [in]  type   Type of key.
 * @param  [in]  heap   Dynamic memory hint.
 * @param  [in]  devId  Device Id.
 * @return  Pointer to new FrodoKemKey object on success.
 * @return  NULL on failure.
 */
FrodoKemKey* wc_FrodoKemKey_New(int type, void* heap, int devId)
{
    int ret;
    FrodoKemKey* key;

    key = (FrodoKemKey*)XMALLOC(sizeof(FrodoKemKey), heap,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (key != NULL) {
        ret = wc_FrodoKemKey_Init(key, type, heap, devId);
        if (ret != 0) {
            XFREE(key, heap, DYNAMIC_TYPE_TMP_BUFFER);
            key = NULL;
        }
    }

    return key;
}

/* Delete and free a FrodoKEM key object.
 *
 * @param  [in]       key    FrodoKEM key object to delete.
 * @param  [in, out]  key_p  Pointer to key pointer to set to NULL.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 */
int wc_FrodoKemKey_Delete(FrodoKemKey* key, FrodoKemKey** key_p)
{
    int ret = 0;

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        void* heap = key->heap;

        wc_FrodoKemKey_Free(key);
        XFREE(key, heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (key_p != NULL) {
            *key_p = NULL;
        }
    }

    return ret;
}
#endif /* !WC_NO_CONSTRUCTORS */

/* Initialize the FrodoKEM key.
 *
 * @param  [out]  key    FrodoKEM key object to initialize.
 * @param  [in]   type   Type of key.
 * @param  [in]   heap   Dynamic memory hint.
 * @param  [in]   devId  Device Id.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL or type has invalid bits set.
 * @return  NOT_COMPILED_IN when the key type is not compiled in.
 */
int wc_FrodoKemKey_Init(FrodoKemKey* key, int type, void* heap, int devId)
{
    int ret = 0;
    const FrodoKemParams* p = NULL;

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    /* Reject types with bits outside the known base and modifier ranges. */
    else if ((type & ~(FRODOKEM_BASE_MASK | FRODOKEM_AES | FRODOKEM_EPHEMERAL))
            != 0) {
        ret = BAD_FUNC_ARG;
    }
    /* Reject undefined base parameter sets: only 640/976/1344 exist, so a base
     * value above WC_FRODOKEM_1344 is a bad argument, not a disabled feature. */
    else if ((type & FRODOKEM_BASE_MASK) > WC_FRODOKEM_1344) {
        ret = BAD_FUNC_ARG;
    }
    else {
        /* Resolve the constant parameters. NULL means the base parameter set
         * or a requested modifier (AES / ephemeral) is not compiled in. */
        p = frodokem_get_params(type);
        if (p == NULL) {
            ret = NOT_COMPILED_IN;
        }
    }

    if (ret == 0) {
        XMEMSET(key, 0, sizeof(*key));
        key->type = type;
        key->params = p;
        key->heap = heap;
        key->devId = devId;
        key->flags = 0;

        /* Cache CPU feature flags for SIMD dispatch in matrix-A generation. */
        frodokem_init();

        /* Initialize the reusable SHAKE object. Init is variant-agnostic and
         * the hashing/matrix-A helpers re-initialize it as SHAKE-128 or -256
         * as needed, so the always-present SHAKE-128 init is used here. */
        ret = wc_InitShake128(&key->shake, NULL, INVALID_DEVID);
#ifdef WOLFSSL_FRODOKEM_AES
        /* Initialize the reusable AES object; re-keyed with seedA per op. */
        if (ret == 0) {
            ret = wc_AesInit(&key->aes, heap, INVALID_DEVID);
            if (ret != 0) {
                /* Free the SHAKE state so a caller that treats an Init failure
                 * as needing no cleanup does not leak it. */
                wc_Shake128_Free(&key->shake);
            }
        }
#endif
    }

    return ret;
}

/* Free the FrodoKEM key.
 *
 * Zeroizes secret material.
 *
 * @param  [in, out]  key  FrodoKEM key object.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 */
int wc_FrodoKemKey_Free(FrodoKemKey* key)
{
    int ret = 0;

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        /* Zeroize secret material. */
        ForceZero(key->s, sizeof(key->s));
        ForceZero(key->sMat, sizeof(key->sMat));
        ForceZero(key->pkh, sizeof(key->pkh));
        /* Free the reusable SHAKE object (zeroizes its state). Free is variant
         * agnostic; SHAKE-128 is always compiled in, so use it. */
        wc_Shake128_Free(&key->shake);
#ifdef WOLFSSL_FRODOKEM_AES
        /* Free the reusable AES object (zeroizes its key schedule). */
        wc_AesFree(&key->aes);
#endif
        key->flags = 0;
    }

    return ret;
}

/******************************************************************************/
/* Sizes.                                                                     */
/******************************************************************************/

/* Get the size in bytes of the ciphertext.
 *
 * @param  [in]   key  FrodoKEM key object.
 * @param  [out]  len  Ciphertext size in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or len is NULL.
 * @return  NOT_COMPILED_IN when key type is not supported.
 */
int wc_FrodoKemKey_CipherTextSize(const FrodoKemKey* key, word32* len)
{
    int ret = 0;
    const FrodoKemParams* p = NULL;

    if ((key == NULL) || (len == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        p = key->params;
        if (p == NULL) {
            ret = NOT_COMPILED_IN;
        }
    }

    if (ret == 0) {
        *len = (word32)p->ctSize;
    }

    return ret;
}

/* Get the size in bytes of the shared secret.
 *
 * @param  [in]   key  FrodoKEM key object.
 * @param  [out]  len  Shared secret size in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or len is NULL.
 * @return  NOT_COMPILED_IN when key type is not supported.
 */
int wc_FrodoKemKey_SharedSecretSize(const FrodoKemKey* key, word32* len)
{
    int ret = 0;
    const FrodoKemParams* p = NULL;

    if ((key == NULL) || (len == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        p = key->params;
        if (p == NULL) {
            ret = NOT_COMPILED_IN;
        }
    }

    if (ret == 0) {
        *len = (word32)p->lenSec;
    }

    return ret;
}

/* Get the size in bytes of an encoded private key.
 *
 * @param  [in]   key  FrodoKEM key object.
 * @param  [out]  len  Private key size in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or len is NULL.
 * @return  NOT_COMPILED_IN when key type is not supported.
 */
int wc_FrodoKemKey_PrivateKeySize(const FrodoKemKey* key, word32* len)
{
    int ret = 0;
    const FrodoKemParams* p = NULL;

    if ((key == NULL) || (len == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        p = key->params;
        if (p == NULL) {
            ret = NOT_COMPILED_IN;
        }
    }

    if (ret == 0) {
        *len = (word32)p->skSize;
    }

    return ret;
}

/* Get the size in bytes of an encoded public key.
 *
 * @param  [in]   key  FrodoKEM key object.
 * @param  [out]  len  Public key size in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or len is NULL.
 * @return  NOT_COMPILED_IN when key type is not supported.
 */
int wc_FrodoKemKey_PublicKeySize(const FrodoKemKey* key, word32* len)
{
    int ret = 0;
    const FrodoKemParams* p = NULL;

    if ((key == NULL) || (len == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        p = key->params;
        if (p == NULL) {
            ret = NOT_COMPILED_IN;
        }
    }

    if (ret == 0) {
        *len = (word32)p->pkSize;
    }

    return ret;
}

/* Wipe the secret-derived Keccak state retained in the reusable SHAKE object
 * after an operation.
 *
 * Encapsulation and decapsulation finish by hashing the shared-secret key
 * material, leaving it in the reusable SHAKE state until the next use. Every
 * SHAKE use re-initializes the object first, so re-initializing here zeroizes
 * that residue (InitSha3 clears the state) and leaves it ready. Best-effort: an
 * init failure is not propagated as the object is re-initialized on next use.
 *
 * @param  [in, out]  key  FrodoKEM key object whose SHAKE state is wiped.
 */
static void frodokem_wipe_shake(FrodoKemKey* key)
{
    if (key != NULL) {
        (void)wc_InitShake128(&key->shake, NULL, INVALID_DEVID);
    }
}

/******************************************************************************/
/* Key generation.                                                            */
/******************************************************************************/

#ifndef WOLFSSL_FRODOKEM_NO_MAKE_KEY

/* Make a FrodoKEM key object using random data.
 *
 * Implements FrodoKEM.KeyGenInternal(s, seedSE, z).  The random data is the
 * concatenation s || seedSE || z.
 *
 * @param  [in, out]  key   FrodoKEM key object.
 * @param  [in]       rand  Random data.
 * @param  [in]       len   Length of random data in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or rand is NULL.
 * @return  BUFFER_E when len is not the expected size.
 * @return  NOT_COMPILED_IN when key type is not supported.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
int wc_FrodoKemKey_MakeKeyWithRandom(FrodoKemKey* key,
    const unsigned char* rand, int len)
{
    const FrodoKemParams* p = NULL;
    int ret = 0;
    int n = 0;
    void* heap = NULL;
    const byte* seedSE;
    const byte* z;
    /* One buffer holds E (B computed in place over it), a scratch slot of
     * FRODOKEM_ROW_MULT A-rows for on-the-fly matrix-A generation, and seInput
     * (the domain-prefixed seed) in a trailing byte region. */
    word16* bMat = NULL;
    word16* row = NULL;
    byte* seInput = NULL;

    if ((key == NULL) || (rand == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        p = key->params;
        if (p == NULL) {
            ret = NOT_COMPILED_IN;
        }
        else if (len != p->lenSec + p->lenSE + FRODOKEM_SEEDA_SZ) {
            ret = BUFFER_E;
        }
    }

    if (ret == 0) {
        n = p->n;
        heap = key->heap;
        seedSE = rand + p->lenSec;
        z = rand + p->lenSec + p->lenSE;

        /* Store s (implicit rejection value). */
        XMEMCPY(key->s, rand, (size_t)p->lenSec);

        /* seedA = SHAKE(z, lenA). */
        ret = frodokem_shake_seeda(p, &key->shake, z, key->seedA);
    }
    if (ret == 0) {
        bMat = (word16*)XMALLOC(
            (size_t)(n * FRODOKEM_NBAR + FRODOKEM_ROW_MULT * n) *
                sizeof(word16) + (size_t)(1 + p->lenSE),
            heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (bMat == NULL) {
            ret = MEMORY_E;
        }
        else {
            row = bMat + n * FRODOKEM_NBAR;
            /* seInput (domain || seedSE) follows the word16 arena. */
            seInput = (byte*)(bMat + n * FRODOKEM_NBAR +
                FRODOKEM_ROW_MULT * n);
        }
    }

    if (ret == 0) {
        /* Generate and sample S^T (nbar x n) into key->sMat and E (n x nbar)
         * into bMat (separate buffers) from SHAKE(0x5F || seedSE). Assemble the
         * domain-prefixed seed; the row scratch is free here, so use it as the
         * SHAKE block scratch. */
        seInput[0] = FRODOKEM_DOMAIN_KEYGEN;
        XMEMCPY(seInput + 1, seedSE, (size_t)p->lenSE);
        ret = frodokem_gen_noise(p, &key->shake, seInput, (byte*)row,
            key->sMat, FRODOKEM_NBAR * n, bMat, n * FRODOKEM_NBAR);
    }
    if (ret == 0) {
        /* B = A * S + E, accumulated in place over E in bMat. */
        ret = frodokem_mul_add_as_plus_e(key, bMat, key->sMat, row);
    }
    if (ret == 0) {
        /* b = Pack(B, n, nbar). */
        frodokem_pack(key->b, bMat, n * FRODOKEM_NBAR, p->d);
        /* pkh = SHAKE(pk, lensec). seedA and b are contiguous in the key so
         * the public key is a single buffer of length pkSize. */
        ret = frodokem_shake_oneshot(p, &key->shake, key->seedA,
            (word32)p->pkSize, key->pkh, (word32)p->lenSec);
    }
    if (ret == 0) {
        key->flags |= FRODOKEM_FLAG_PRIV_SET | FRODOKEM_FLAG_PUB_SET |
            FRODOKEM_FLAG_PKH_SET;
    }

    /* bMat held the secret error matrix E and the seed (in seInput), so
     * zeroize it before freeing. */
    if (bMat != NULL) {
        ForceZero(bMat,
            (word32)(n * FRODOKEM_NBAR + FRODOKEM_ROW_MULT * n) *
                sizeof(word16) + (word32)(1 + p->lenSE));
        XFREE(bMat, heap, DYNAMIC_TYPE_TMP_BUFFER);
    }

    /* Wipe secret-derived residue from the reusable SHAKE state. */
    frodokem_wipe_shake(key);

    return ret;
}

/* Make a FrodoKEM key object using a random number generator.
 *
 * @param  [in, out]  key  FrodoKEM key object.
 * @param  [in]       rng  Random number generator.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or rng is NULL.
 * @return  NOT_COMPILED_IN when no RNG is compiled in or key type unsupported.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
int wc_FrodoKemKey_MakeKey(FrodoKemKey* key, WC_RNG* rng)
{
    int ret = 0;
#ifndef WC_NO_RNG
    const FrodoKemParams* p = NULL;
    int randLen = 0;
#ifdef WOLFSSL_SMALL_STACK
    byte* rand = NULL;
#else
    byte rand[WC_FRODOKEM_1344_MAKEKEY_RAND_SZ];
#endif

    if ((key == NULL) || (rng == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        p = key->params;
        if (p == NULL) {
            ret = NOT_COMPILED_IN;
        }
    }

    if (ret == 0) {
        randLen = p->lenSec + p->lenSE + FRODOKEM_SEEDA_SZ;
    }
#ifdef WOLFSSL_SMALL_STACK
    /* Keep the random data off the stack. */
    if (ret == 0) {
        rand = (byte*)XMALLOC((size_t)randLen, key->heap,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (rand == NULL) {
            ret = MEMORY_E;
        }
    }
#endif
    if (ret == 0) {
        ret = wc_RNG_GenerateBlock(rng, rand, (word32)randLen);
    }
    if (ret == 0) {
        ret = wc_FrodoKemKey_MakeKeyWithRandom(key, rand, randLen);
    }

#ifdef WOLFSSL_SMALL_STACK
    if (rand != NULL) {
        ForceZero(rand, (word32)randLen);
        XFREE(rand, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
#else
    ForceZero(rand, sizeof(rand));
#endif
#else
    (void)key;
    (void)rng;
    ret = NOT_COMPILED_IN;
#endif
    return ret;
}
#endif /* !WOLFSSL_FRODOKEM_NO_MAKE_KEY */

/******************************************************************************/
/* Encapsulation.                                                             */
/******************************************************************************/

#ifndef WOLFSSL_FRODOKEM_NO_ENCAPSULATE

/* Encapsulate to a FrodoKEM public key using random data.
 *
 * Implements FrodoKEM.Encaps with the random data being u || salt.
 *
 * @param  [in]   key   FrodoKEM key object with public key set.
 * @param  [out]  ct    Ciphertext.
 * @param  [out]  ss    Shared secret.
 * @param  [in]   rand  Random data (u || salt).
 * @param  [in]   len   Length of random data in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a pointer is NULL.
 * @return  BUFFER_E when len is not the expected size.
 * @return  BAD_STATE_E when public key is not set.
 * @return  NOT_COMPILED_IN when key type is not supported.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
int wc_FrodoKemKey_EncapsulateWithRandom(FrodoKemKey* key, unsigned char* ct,
    unsigned char* ss, const unsigned char* rand, int len)
{
    const FrodoKemParams* p = NULL;
    int ret = 0;
    int n = 0;
    int nn = FRODOKEM_NBAR_SQ;
    void* heap = NULL;
    const byte* u;
    const byte* salt;
    byte* c1;
    byte* c2;
    byte* saltOut;
    /* One arena holds S' (nbar x n), a reused slot (E' -> B' -> B) (nbar x n)
     * and E'' (nbar x nbar), contiguous so their noise is one region, plus a
     * FRODOKEM_ROW_MULT-row scratch slot for matrix-A generation. */
    word16* mat = NULL;
    word16* sp = NULL;
    word16* work = NULL;
    word16* epp = NULL;
    word16* row = NULL;
#ifdef WOLFSSL_SMALL_STACK
    /* seedSEk and pkh are carved from the mat allocation to keep them off the
     * stack. */
    byte* seedSEk = NULL;
    byte* pkh = NULL;
#else
    byte seedSEk[1 + FRODOKEM_MAX_LENSE + FRODOKEM_MAX_LENSEC];
    byte pkh[FRODOKEM_MAX_LENSEC];
#endif
    byte* kVal;
    size_t matSz = 0;

    if ((key == NULL) || (ct == NULL) || (ss == NULL) || (rand == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        p = key->params;
        if (p == NULL) {
            ret = NOT_COMPILED_IN;
        }
        else if ((key->flags & FRODOKEM_FLAG_PUB_SET) == 0) {
            ret = BAD_STATE_E;
        }
        else if (len != p->lenSec + p->lenSalt) {
            ret = BUFFER_E;
        }
    }

    if (ret == 0) {
        n = p->n;
        heap = key->heap;
        u = rand;
        salt = rand + p->lenSec;
        c1 = ct;
        c2 = ct + (p->d * n);
        saltOut = ct + (p->d * n) + (p->d * FRODOKEM_NBAR);

        matSz = (size_t)(2 * FRODOKEM_NBAR * n + FRODOKEM_NBAR_SQ +
            FRODOKEM_ROW_MULT * n) * sizeof(word16);
#ifdef WOLFSSL_SMALL_STACK
        /* seedSEk (1 + lenSE + lenSec) and pkh (lenSec) follow the arena. */
        matSz += (size_t)(1 + p->lenSE + 2 * p->lenSec);
#endif
        mat = (word16*)XMALLOC(matSz, heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (mat == NULL) {
            ret = MEMORY_E;
        }
        else {
            sp = mat;
            work = mat + FRODOKEM_NBAR * n;
            epp = mat + 2 * FRODOKEM_NBAR * n;
            row = mat + 2 * FRODOKEM_NBAR * n + FRODOKEM_NBAR_SQ;
#ifdef WOLFSSL_SMALL_STACK
            seedSEk = (byte*)(mat + 2 * FRODOKEM_NBAR * n + FRODOKEM_NBAR_SQ +
                FRODOKEM_ROW_MULT * n);
            pkh = seedSEk + (1 + p->lenSE + p->lenSec);
#endif
        }
    }

    if (ret == 0) {
        /* pkh = SHAKE(pk, lensec). seedA and b are contiguous in the key so
         * the public key is a single buffer of length pkSize. */
        ret = frodokem_shake_oneshot(p, &key->shake, key->seedA,
            (word32)p->pkSize, pkh, (word32)p->lenSec);
    }
    if (ret == 0) {
        /* seedSEk = domain || seedSE || k: the leading byte is the noise domain
         * and seedSE || k = SHAKE(pkh || u || salt, lenSE + lensec) is written
         * after it. rand is the message u || salt, one contiguous buffer. */
        seedSEk[0] = FRODOKEM_DOMAIN_ENCAPS;
        ret = frodokem_gen_seedse_k(p, &key->shake, pkh, rand, seedSEk + 1);
    }
    if (ret == 0) {
        kVal = seedSEk + 1 + p->lenSE;

        /* Generate and sample S' | E' | E'' from SHAKE(domain || seedSE). The
         * three are contiguous from sp, so they form a single noise region. The
         * row scratch is free here, so use it as the SHAKE block scratch. */
        ret = frodokem_gen_noise(p, &key->shake, seedSEk, (byte*)row,
            sp, 2 * FRODOKEM_NBAR * n + FRODOKEM_NBAR_SQ, NULL, 0);
    }
    if (ret == 0) {
        /* B' = S' * A + E', accumulated in place over E' in work. */
        ret = frodokem_mul_add_sa_plus_e(key, work, sp, row);
    }
    if (ret == 0) {
        /* c1 = Pack(B', nbar, n). */
        frodokem_pack(c1, work, FRODOKEM_NBAR * n, p->d);
        /* B' no longer needed: reuse work for B = Unpack(b, n, nbar). */
        frodokem_unpack(work, key->b, n * FRODOKEM_NBAR, p->d);
        /* V = S' * B + E'', accumulated in place over E'' in epp. */
        frodokem_mul_add_sb_plus_e(epp, work, sp, p->n, (int)p->qMask);
        /* C = V + Encode(u). B is finished, so reuse work for Encode(u). */
        frodokem_key_encode(work, u, p->d, p->b);
        frodokem_add(epp, work, (int)p->qMask);
        /* c2 = Pack(C, nbar, nbar). */
        frodokem_pack(c2, epp, nn, p->d);
        /* salt is appended to the ciphertext. */
        XMEMCPY(saltOut, salt, (size_t)p->lenSalt);

        /* ss = SHAKE(c1 || c2 || salt || k, lensec). c1 || c2 || salt is the
         * leading part of ct. */
        ret = frodokem_shake(p, &key->shake, ct,
            (word32)((p->d * n) + (p->d * FRODOKEM_NBAR) + p->lenSalt),
            kVal, (word32)p->lenSec, ss, (word32)p->lenSec);
    }

#ifndef WOLFSSL_SMALL_STACK
    ForceZero(pkh, sizeof(pkh));
    ForceZero(seedSEk, sizeof(seedSEk));
#endif
    /* Encode(u), V/E'' and B' live in mat (as do seedSEk and pkh under small
     * stack), all zeroized on free below. */
    if (mat != NULL) {
        ForceZero(mat, (word32)matSz);
        XFREE(mat, heap, DYNAMIC_TYPE_TMP_BUFFER);
    }

    /* Wipe secret-derived residue from the reusable SHAKE state. */
    frodokem_wipe_shake(key);

    return ret;
}

/* Encapsulate to a FrodoKEM public key using a random number generator.
 *
 * @param  [in]   key  FrodoKEM key object with public key set.
 * @param  [out]  ct   Ciphertext.
 * @param  [out]  ss   Shared secret.
 * @param  [in]   rng  Random number generator.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a pointer is NULL.
 * @return  NOT_COMPILED_IN when no RNG is compiled in or key type unsupported.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
int wc_FrodoKemKey_Encapsulate(FrodoKemKey* key, unsigned char* ct,
    unsigned char* ss, WC_RNG* rng)
{
    int ret = 0;
#ifndef WC_NO_RNG
    const FrodoKemParams* p = NULL;
    int randLen = 0;
#ifdef WOLFSSL_SMALL_STACK
    byte* rand = NULL;
#else
    byte rand[WC_FRODOKEM_1344_ENC_RAND_SZ];
#endif

    if ((key == NULL) || (ct == NULL) || (ss == NULL) || (rng == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        p = key->params;
        if (p == NULL) {
            ret = NOT_COMPILED_IN;
        }
    }

    if (ret == 0) {
        randLen = p->lenSec + p->lenSalt;
    }
#ifdef WOLFSSL_SMALL_STACK
    /* Keep the random data off the stack. */
    if (ret == 0) {
        rand = (byte*)XMALLOC((size_t)randLen, key->heap,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (rand == NULL) {
            ret = MEMORY_E;
        }
    }
#endif
    if (ret == 0) {
        ret = wc_RNG_GenerateBlock(rng, rand, (word32)randLen);
    }
    if (ret == 0) {
        ret = wc_FrodoKemKey_EncapsulateWithRandom(key, ct, ss, rand, randLen);
    }

#ifdef WOLFSSL_SMALL_STACK
    if (rand != NULL) {
        ForceZero(rand, (word32)randLen);
        XFREE(rand, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
#else
    ForceZero(rand, sizeof(rand));
#endif
#else
    (void)key;
    (void)ct;
    (void)ss;
    (void)rng;
    ret = NOT_COMPILED_IN;
#endif
    return ret;
}
#endif /* !WOLFSSL_FRODOKEM_NO_ENCAPSULATE */

/******************************************************************************/
/* Decapsulation.                                                             */
/******************************************************************************/

#ifndef WOLFSSL_FRODOKEM_NO_DECAPSULATE
/* Decapsulate a FrodoKEM ciphertext.
 *
 * Implements FrodoKEM.Decaps with implicit rejection.
 *
 * @param  [in]   key  FrodoKEM key object with private key set.
 * @param  [out]  ss   Shared secret.
 * @param  [in]   ct   Ciphertext.
 * @param  [in]   len  Length of ciphertext in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a pointer is NULL.
 * @return  BUFFER_E when len is not the expected size.
 * @return  BAD_STATE_E when private key is not set.
 * @return  NOT_COMPILED_IN when key type is not supported.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
int wc_FrodoKemKey_Decapsulate(FrodoKemKey* key, unsigned char* ss,
    const unsigned char* ct, word32 len)
{
    const FrodoKemParams* p = NULL;
    int ret = 0;
    int n = 0;
    int i;
    int nn = FRODOKEM_NBAR_SQ;
    void* heap = NULL;
    const byte* c1;
    const byte* c2;
    const byte* salt;
    /* Arena: B' (kept for compare), then S' | E'(-> B'' -> B) | E'' contiguous
     * so their noise is one region, plus a FRODOKEM_ROW_MULT-row scratch slot
     * for matrix-A generation. */
    word16* mat = NULL;
    word16* bpIn = NULL;
    word16* sp = NULL;
    word16* work = NULL;
    word16* epp = NULL;
    word16* row = NULL;
    /* uSalt holds the decoded u' followed by a copy of the ciphertext salt, so
     * u' || salt is contiguous for gen_seedse_k. */
#ifdef WOLFSSL_SMALL_STACK
    /* cIn, v, cEnc, seedSEk and uSalt are carved from the mat allocation to
     * keep them off the stack. */
    word16* cIn = NULL;
    word16* v = NULL;
    word16* cEnc = NULL;
    byte* seedSEk = NULL;
    byte* uSalt = NULL;
#else
    byte seedSEk[1 + FRODOKEM_MAX_LENSE + FRODOKEM_MAX_LENSEC];
    byte uSalt[FRODOKEM_MAX_LENSEC + FRODOKEM_MAX_LENSALT];
    word16 cIn[FRODOKEM_NBAR_SQ];
    word16 v[FRODOKEM_NBAR_SQ];
    word16 cEnc[FRODOKEM_NBAR_SQ];
#endif
    byte* kPrime;
    word16 diff = 0;
    word32 isEq;
    byte mask;
    size_t matSz = 0;

    if ((key == NULL) || (ss == NULL) || (ct == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        p = key->params;
        if (p == NULL) {
            ret = NOT_COMPILED_IN;
        }
        else if ((key->flags & FRODOKEM_FLAG_PRIV_SET) == 0) {
            ret = BAD_STATE_E;
        }
        else if (len != (word32)p->ctSize) {
            ret = BUFFER_E;
        }
    }

    if (ret == 0) {
        n = p->n;
        heap = key->heap;
        c1 = ct;
        c2 = ct + (p->d * n);
        salt = ct + (p->d * n) + (p->d * FRODOKEM_NBAR);

        matSz = (size_t)(3 * FRODOKEM_NBAR * n + FRODOKEM_NBAR_SQ +
            FRODOKEM_ROW_MULT * n) * sizeof(word16);
#ifdef WOLFSSL_SMALL_STACK
        /* cIn, v, cEnc (3 * nbar^2 words), then seedSEk (1 + lenSE + lenSec)
         * and uSalt (lenSec + lensalt) bytes, all follow the matrix arena. */
        matSz += (size_t)(3 * FRODOKEM_NBAR_SQ) * sizeof(word16);
        matSz += (size_t)(1 + p->lenSE + 2 * p->lenSec + p->lenSalt);
#endif
        mat = (word16*)XMALLOC(matSz, heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (mat == NULL) {
            ret = MEMORY_E;
        }
        else {
            bpIn = mat;
            sp = mat + FRODOKEM_NBAR * n;
            work = mat + 2 * FRODOKEM_NBAR * n;
            epp = mat + 3 * FRODOKEM_NBAR * n;
            row = mat + 3 * FRODOKEM_NBAR * n + FRODOKEM_NBAR_SQ;
#ifdef WOLFSSL_SMALL_STACK
            cIn = row + FRODOKEM_ROW_MULT * n;
            v = cIn + FRODOKEM_NBAR_SQ;
            cEnc = v + FRODOKEM_NBAR_SQ;
            seedSEk = (byte*)(cEnc + FRODOKEM_NBAR_SQ);
            uSalt = seedSEk + (1 + p->lenSE + p->lenSec);
#endif
        }
    }

    if (ret == 0) {
        /* B' = Unpack(c1, nbar, n) and C = Unpack(c2, nbar, nbar). */
        frodokem_unpack(bpIn, c1, FRODOKEM_NBAR * n, p->d);
        frodokem_unpack(cIn, c2, nn, p->d);
        /* M = C - B' * S, computed in place: v holds B' * S, then M. */
        frodokem_mul_bs(v, bpIn, key->sMat, p->n, (int)p->qMask);
        for (i = 0; i < nn; i++) {
            v[i] = (word16)((cIn[i] - v[i]) & p->qMask);
        }
        /* u' = Decode(M), placed next to a copy of the ciphertext salt so
         * u' || salt is contiguous for the hash below. */
        frodokem_key_decode(uSalt, v, p);
        XMEMCPY(uSalt + p->lenSec, salt, (size_t)p->lenSalt);

        /* seedSEk = domain || seedSE' || k': seedSE' || k' = SHAKE(pkh || u' ||
         * salt, lenSE + lensec) written after the leading domain byte. */
        seedSEk[0] = FRODOKEM_DOMAIN_ENCAPS;
        ret = frodokem_gen_seedse_k(p, &key->shake, key->pkh, uSalt,
            seedSEk + 1);
    }
    if (ret == 0) {
        /* Generate and sample S' | E' | E'' from SHAKE(domain || seedSE'). The
         * three are contiguous from sp, so they form a single noise region. The
         * row scratch is free here, so use it as the SHAKE block scratch. */
        ret = frodokem_gen_noise(p, &key->shake, seedSEk, (byte*)row,
            sp, 2 * FRODOKEM_NBAR * n + FRODOKEM_NBAR_SQ, NULL, 0);
    }
    if (ret == 0) {
        /* B'' = S' * A + E', accumulated in place over E' in work. */
        ret = frodokem_mul_add_sa_plus_e(key, work, sp, row);
    }
    if (ret == 0) {
        /* Compare B' (bpIn) against B'' (work) before reusing work. */
        for (i = 0; i < FRODOKEM_NBAR * n; i++) {
            diff |= (word16)(bpIn[i] ^ work[i]);
        }
        /* B'' no longer needed: reuse work for B = Unpack(b, n, nbar). */
        frodokem_unpack(work, key->b, n * FRODOKEM_NBAR, p->d);
        /* V = S' * B + E'' (in place over E'' in epp); C' = V + Encode(u'). */
        frodokem_mul_add_sb_plus_e(epp, work, sp, p->n, (int)p->qMask);
        frodokem_key_encode(cEnc, uSalt, p->d, p->b);
        frodokem_add(epp, cEnc, (int)p->qMask);
        /* Compare C (cIn) against C' (epp). */
        for (i = 0; i < nn; i++) {
            diff |= (word16)(cIn[i] ^ epp[i]);
        }

        kPrime = seedSEk + 1 + p->lenSE;
        /* isEq is 1 when diff == 0, else 0. */
        isEq = (word32)(((word32)diff - 1) >> 31);
        mask = (byte)(0 - isEq);

        /* kHat = k' if ciphertext valid, else s (implicit rejection). Selected
         * in place over k' (kPrime) in seedSEk. */
        for (i = 0; i < p->lenSec; i++) {
            kPrime[i] = (byte)((kPrime[i] & mask) | (key->s[i] & (byte)~mask));
        }

        /* ss = SHAKE(c1 || c2 || salt || kHat, lensec). c1 || c2 || salt is
         * the leading part of ct. */
        ret = frodokem_shake(p, &key->shake, ct,
            (word32)((p->d * n) + (p->d * FRODOKEM_NBAR) + p->lenSalt),
            kPrime, (word32)p->lenSec, ss, (word32)p->lenSec);
    }

#ifndef WOLFSSL_SMALL_STACK
    ForceZero(uSalt, sizeof(uSalt));
    ForceZero(seedSEk, sizeof(seedSEk));
    /* Zeroize the secret-derived stack matrices (E'' lives in mat). */
    ForceZero(v, sizeof(v));
    ForceZero(cEnc, sizeof(cEnc));
#endif
    /* Under small stack uSalt, seedSEk, cIn, v and cEnc live in mat, zeroized
     * below along with the rest of the arena. */
    if (mat != NULL) {
        ForceZero(mat, (word32)matSz);
        XFREE(mat, heap, DYNAMIC_TYPE_TMP_BUFFER);
    }

    /* Wipe secret-derived residue from the reusable SHAKE state. */
    frodokem_wipe_shake(key);

    return ret;
}
#endif /* !WOLFSSL_FRODOKEM_NO_DECAPSULATE */

/******************************************************************************/
/* Key encoding and decoding.                                                 */
/******************************************************************************/

/* Encode the FrodoKEM public key: seedA || b.
 *
 * @param  [in]   key  FrodoKEM key object with public key set.
 * @param  [out]  out  Output buffer.
 * @param  [in]   len  Length of output buffer in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or out is NULL.
 * @return  BAD_STATE_E when public key is not set.
 * @return  BUFFER_E when len is not the expected size.
 * @return  NOT_COMPILED_IN when key type is not supported.
 */
int wc_FrodoKemKey_EncodePublicKey(FrodoKemKey* key, unsigned char* out,
    word32 len)
{
    int ret = 0;
    const FrodoKemParams* p = NULL;

    if ((key == NULL) || (out == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        p = key->params;
        if (p == NULL) {
            ret = NOT_COMPILED_IN;
        }
        else if ((key->flags & FRODOKEM_FLAG_PUB_SET) == 0) {
            ret = BAD_STATE_E;
        }
        else if (len != (word32)p->pkSize) {
            ret = BUFFER_E;
        }
    }

    if (ret == 0) {
        XMEMCPY(out, key->seedA, FRODOKEM_SEEDA_SZ);
        XMEMCPY(out + FRODOKEM_SEEDA_SZ, key->b, (size_t)(p->d * p->n));
    }

    return ret;
}

/* Decode a FrodoKEM public key: seedA || b.
 *
 * @param  [in, out]  key  FrodoKEM key object.
 * @param  [in]       in   Encoded public key.
 * @param  [in]       len  Length of encoded public key in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or in is NULL.
 * @return  BUFFER_E when len is not the expected size.
 * @return  NOT_COMPILED_IN when key type is not supported.
 */
int wc_FrodoKemKey_DecodePublicKey(FrodoKemKey* key, const unsigned char* in,
    word32 len)
{
    int ret = 0;
    const FrodoKemParams* p = NULL;

    if ((key == NULL) || (in == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        p = key->params;
        if (p == NULL) {
            ret = NOT_COMPILED_IN;
        }
        else if (len != (word32)p->pkSize) {
            ret = BUFFER_E;
        }
    }

    if (ret == 0) {
        XMEMCPY(key->seedA, in, FRODOKEM_SEEDA_SZ);
        XMEMCPY(key->b, in + FRODOKEM_SEEDA_SZ, (size_t)(p->d * p->n));
        /* No value validation is required: seedA is an unconstrained seed and,
         * because q is a power of two, every coefficient unpacked from b is
         * already a valid residue in [0, q). No embedded hash to check. */
        /* This object now holds only a public key: replace any prior state
         * (e.g. from a private key) rather than OR-ing in, so the flags cannot
         * describe a mismatched public/private pair. Wipe any secret material
         * (implicit-rejection s and secret matrix S^T) left from a prior
         * private key so it is not retained in a public-only object. */
        ForceZero(key->s, sizeof(key->s));
        ForceZero(key->sMat, sizeof(key->sMat));
        key->flags = FRODOKEM_FLAG_PUB_SET;
    }

    return ret;
}

/* Encode the FrodoKEM private key: s || seedA || b || S^T || pkh.
 *
 * The secret matrix S^T is stored as little-endian 16-bit residues.
 *
 * @param  [in]   key  FrodoKEM key object with private key set.
 * @param  [out]  out  Output buffer.
 * @param  [in]   len  Length of output buffer in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or out is NULL.
 * @return  BAD_STATE_E when private key is not set.
 * @return  BUFFER_E when len is not the expected size.
 * @return  NOT_COMPILED_IN when key type is not supported.
 */
int wc_FrodoKemKey_EncodePrivateKey(FrodoKemKey* key, unsigned char* out,
    word32 len)
{
    int ret = 0;
    const FrodoKemParams* p = NULL;
    int sCnt;
    byte* o;

    if ((key == NULL) || (out == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        p = key->params;
        if (p == NULL) {
            ret = NOT_COMPILED_IN;
        }
        else if (((key->flags & FRODOKEM_FLAG_BOTH_SET) !=
                FRODOKEM_FLAG_BOTH_SET) ||
                ((key->flags & FRODOKEM_FLAG_PKH_SET) == 0)) {
            ret = BAD_STATE_E;
        }
        else if (len != (word32)p->skSize) {
            ret = BUFFER_E;
        }
    }

    if (ret == 0) {
        sCnt = FRODOKEM_NBAR * p->n;
        o = out;
        XMEMCPY(o, key->s, (size_t)p->lenSec);
        o += p->lenSec;
        XMEMCPY(o, key->seedA, FRODOKEM_SEEDA_SZ);
        o += FRODOKEM_SEEDA_SZ;
        XMEMCPY(o, key->b, (size_t)(p->d * p->n));
        o += p->d * p->n;
        frodokem_store_matrix(o, key->sMat, sCnt);
        o += 2 * sCnt;
        XMEMCPY(o, key->pkh, (size_t)p->lenSec);
    }

    return ret;
}

/* Validate a decoded FrodoKEM private key.
 *
 * The only decoded value with a condition on it is the stored public-key hash:
 * it must equal SHAKE(seedA || b). (seedA, b and the secret matrix are
 * otherwise unconstrained - q is a power of two, so every unpacked coefficient
 * is already a valid residue in [0, q).)
 *
 * @param  [in]  p    FrodoKEM parameters.
 * @param  [in]  key  Key with seedA, b and pkh populated.
 * @return  0 when the stored hash matches.
 * @return  WC_KEY_MISMATCH_E when the stored hash is inconsistent.
 * @return  Negative on hash error.
 */
static int frodokem_check_priv_key(const FrodoKemParams* p, FrodoKemKey* key)
{
    byte pkh[FRODOKEM_MAX_LENSEC];
    int ret;

    ret = frodokem_shake_oneshot(p, &key->shake, key->seedA, (word32)p->pkSize,
        pkh, (word32)p->lenSec);
    if ((ret == 0) && (XMEMCMP(pkh, key->pkh, (size_t)p->lenSec) != 0)) {
        ret = WC_KEY_MISMATCH_E;
    }

    return ret;
}

/* Decode a FrodoKEM private key: s || seedA || b || S^T || pkh.
 *
 * @param  [in, out]  key  FrodoKEM key object.
 * @param  [in]       in   Encoded private key.
 * @param  [in]       len  Length of encoded private key in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or in is NULL.
 * @return  BUFFER_E when len is not the expected size.
 * @return  NOT_COMPILED_IN when key type is not supported.
 * @return  WC_KEY_MISMATCH_E when the embedded public-key hash is inconsistent.
 */
int wc_FrodoKemKey_DecodePrivateKey(FrodoKemKey* key, const unsigned char* in,
    word32 len)
{
    const FrodoKemParams* p = NULL;
    int ret = 0;
    int sCnt;
    const byte* o;

    if ((key == NULL) || (in == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        p = key->params;
        if (p == NULL) {
            ret = NOT_COMPILED_IN;
        }
        else if (len != (word32)p->skSize) {
            ret = BUFFER_E;
        }
    }

    if (ret == 0) {
        sCnt = FRODOKEM_NBAR * p->n;
        o = in;
        XMEMCPY(key->s, o, (size_t)p->lenSec);
        o += p->lenSec;
        XMEMCPY(key->seedA, o, FRODOKEM_SEEDA_SZ);
        o += FRODOKEM_SEEDA_SZ;
        XMEMCPY(key->b, o, (size_t)(p->d * p->n));
        o += p->d * p->n;
        frodokem_load_matrix(key->sMat, o, sCnt);
        o += 2 * sCnt;
        XMEMCPY(key->pkh, o, (size_t)p->lenSec);

        /* Validate the decoded data before marking the key usable. */
        ret = frodokem_check_priv_key(p, key);
        if (ret == 0) {
            key->flags |= FRODOKEM_FLAG_PRIV_SET | FRODOKEM_FLAG_PUB_SET |
                FRODOKEM_FLAG_PKH_SET;
        }
        else {
            /* Leave the key object unusable and wipe the secret material that
             * was copied in before validation failed. Only the secrets (s and
             * S^T) are wiped; the non-secret fields copied in above (pkh, seedA
             * and b) are intentionally left in place, as they are public and
             * unreachable while flags == 0 (every consumer gates on the
             * FRODOKEM_FLAG_*_SET bits cleared here). */
            ForceZero(key->s, sizeof(key->s));
            ForceZero(key->sMat, sizeof(key->sMat));
            key->flags = 0;
        }
    }

    return ret;
}

#endif /* WOLFSSL_HAVE_FRODOKEM */
