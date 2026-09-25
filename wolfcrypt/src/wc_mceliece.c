/* wc_mceliece.c
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

/* Implementation of the Classic McEliece KEM based on binary Goppa codes.
 *
 * Implementation based on:
 *   https://www.ietf.org/archive/id/draft-josefsson-mceliece-05.txt
 *
 * This file holds the KEM / API glue: key life cycle, size queries, key
 * encoding/decoding, the Fujisaki-Okamoto hashing (PRG and Hash), and the
 * MakeKey / Encapsulate / Decapsulate entry points. The field, polynomial,
 * matrix and code machinery (SeededKeyGen, MatGen, Encode, Decode) lives in
 * wc_mceliece_mat.c.
 *
 * The API mirrors the wolfCrypt FrodoKEM API (see wc_frodokem.c), using
 * McEliece in the names in place of FrodoKem.
 */

#define _WC_BUILDING_WC_MCELIECE_C

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#include <wolfssl/wolfcrypt/wc_mceliece_mat.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifdef WOLFSSL_HAVE_MCELIECE

/* Domain-separation prefix bytes for SHAKE-256 (draft sections 7 and 9.1). The
 * PRG prefix is 64; the Hash prefix is 0, 1 or 2 and never collides with 64. */
#define MCELIECE_HASH_PREFIX_0  0
#define MCELIECE_HASH_PREFIX_1  1
#define MCELIECE_HASH_PREFIX_2  2

/******************************************************************************/
/* Parameter sets.                                                            */
/******************************************************************************/

/* Expand to a static const McElieceParams instance. nm is a token used only to
 * name the instance; tp is the full key type; nn and tt are n and t; pcf and
 * ff are the plaintext-confirmation and semi-systematic flags. */
#define MCELIECE_PARAM(nm, tp, nn, tt, pcf, ff)                             \
    static const McElieceParams mceliece_params_##nm = {                    \
        (tp), (nn), (tt), MCELIECE_TAU(nn, tt), MCELIECE_MT(tt),           \
        MCELIECE_K(nn, tt),                                                \
        (byte)(pcf), (byte)(ff),                                            \
        MCELIECE_PK_SZ(nn, tt), MCELIECE_SK_SZ(nn, tt),                     \
        (pcf) ? MCELIECE_CT_PC_SZ(tt) : MCELIECE_CT_SZ(tt),                 \
        MCELIECE_SYND_SZ(tt), MCELIECE_S_SZ(nn), MCELIECE_IRR_SZ(tt)        \
    }

#ifdef WOLFSSL_WC_MCELIECE_6688128
#ifndef WOLFSSL_MCELIECE_NO_PLAIN
MCELIECE_PARAM(6688128,    WC_MCELIECE_6688128,    WC_MCELIECE_6688128_N,
    WC_MCELIECE_6688128_T, 0, 0);
#endif
#ifndef WOLFSSL_MCELIECE_NO_F
MCELIECE_PARAM(6688128f,   WC_MCELIECE_6688128F,   WC_MCELIECE_6688128_N,
    WC_MCELIECE_6688128_T, 0, 1);
#endif
#ifndef WOLFSSL_MCELIECE_NO_PC
MCELIECE_PARAM(6688128pc,  WC_MCELIECE_6688128PC,  WC_MCELIECE_6688128_N,
    WC_MCELIECE_6688128_T, 1, 0);
#endif
#ifndef WOLFSSL_MCELIECE_NO_PCF
MCELIECE_PARAM(6688128pcf, WC_MCELIECE_6688128PCF, WC_MCELIECE_6688128_N,
    WC_MCELIECE_6688128_T, 1, 1);
#endif
#endif

#ifdef WOLFSSL_WC_MCELIECE_6960119
#ifndef WOLFSSL_MCELIECE_NO_PLAIN
MCELIECE_PARAM(6960119,    WC_MCELIECE_6960119,    WC_MCELIECE_6960119_N,
    WC_MCELIECE_6960119_T, 0, 0);
#endif
#ifndef WOLFSSL_MCELIECE_NO_F
MCELIECE_PARAM(6960119f,   WC_MCELIECE_6960119F,   WC_MCELIECE_6960119_N,
    WC_MCELIECE_6960119_T, 0, 1);
#endif
#ifndef WOLFSSL_MCELIECE_NO_PC
MCELIECE_PARAM(6960119pc,  WC_MCELIECE_6960119PC,  WC_MCELIECE_6960119_N,
    WC_MCELIECE_6960119_T, 1, 0);
#endif
#ifndef WOLFSSL_MCELIECE_NO_PCF
MCELIECE_PARAM(6960119pcf, WC_MCELIECE_6960119PCF, WC_MCELIECE_6960119_N,
    WC_MCELIECE_6960119_T, 1, 1);
#endif
#endif

#ifdef WOLFSSL_WC_MCELIECE_8192128
#ifndef WOLFSSL_MCELIECE_NO_PLAIN
MCELIECE_PARAM(8192128,    WC_MCELIECE_8192128,    WC_MCELIECE_8192128_N,
    WC_MCELIECE_8192128_T, 0, 0);
#endif
#ifndef WOLFSSL_MCELIECE_NO_F
MCELIECE_PARAM(8192128f,   WC_MCELIECE_8192128F,   WC_MCELIECE_8192128_N,
    WC_MCELIECE_8192128_T, 0, 1);
#endif
#ifndef WOLFSSL_MCELIECE_NO_PC
MCELIECE_PARAM(8192128pc,  WC_MCELIECE_8192128PC,  WC_MCELIECE_8192128_N,
    WC_MCELIECE_8192128_T, 1, 0);
#endif
#ifndef WOLFSSL_MCELIECE_NO_PCF
MCELIECE_PARAM(8192128pcf, WC_MCELIECE_8192128PCF, WC_MCELIECE_8192128_N,
    WC_MCELIECE_8192128_T, 1, 1);
#endif
#endif

/* Resolve constant parameters for a key type, or NULL when the base parameter
 * set is not compiled in. The type has already been range-checked by the
 * caller. */
static const McElieceParams* wc_mceliece_get_params(int type)
{
    const McElieceParams* p = NULL;

    switch (type) {
#ifdef WOLFSSL_WC_MCELIECE_6688128
#ifndef WOLFSSL_MCELIECE_NO_PLAIN
    case WC_MCELIECE_6688128:
        p = &mceliece_params_6688128;
        break;
#endif
#ifndef WOLFSSL_MCELIECE_NO_F
    case WC_MCELIECE_6688128F:
        p = &mceliece_params_6688128f;
        break;
#endif
#ifndef WOLFSSL_MCELIECE_NO_PC
    case WC_MCELIECE_6688128PC:
        p = &mceliece_params_6688128pc;
        break;
#endif
#ifndef WOLFSSL_MCELIECE_NO_PCF
    case WC_MCELIECE_6688128PCF:
        p = &mceliece_params_6688128pcf;
        break;
#endif
#endif
#ifdef WOLFSSL_WC_MCELIECE_6960119
#ifndef WOLFSSL_MCELIECE_NO_PLAIN
    case WC_MCELIECE_6960119:
        p = &mceliece_params_6960119;
        break;
#endif
#ifndef WOLFSSL_MCELIECE_NO_F
    case WC_MCELIECE_6960119F:
        p = &mceliece_params_6960119f;
        break;
#endif
#ifndef WOLFSSL_MCELIECE_NO_PC
    case WC_MCELIECE_6960119PC:
        p = &mceliece_params_6960119pc;
        break;
#endif
#ifndef WOLFSSL_MCELIECE_NO_PCF
    case WC_MCELIECE_6960119PCF:
        p = &mceliece_params_6960119pcf;
        break;
#endif
#endif
#ifdef WOLFSSL_WC_MCELIECE_8192128
#ifndef WOLFSSL_MCELIECE_NO_PLAIN
    case WC_MCELIECE_8192128:
        p = &mceliece_params_8192128;
        break;
#endif
#ifndef WOLFSSL_MCELIECE_NO_F
    case WC_MCELIECE_8192128F:
        p = &mceliece_params_8192128f;
        break;
#endif
#ifndef WOLFSSL_MCELIECE_NO_PC
    case WC_MCELIECE_8192128PC:
        p = &mceliece_params_8192128pc;
        break;
#endif
#ifndef WOLFSSL_MCELIECE_NO_PCF
    case WC_MCELIECE_8192128PCF:
        p = &mceliece_params_8192128pcf;
        break;
#endif
#endif
    default:
        break;
    }

    return p;
}

/******************************************************************************/
/* Key life cycle.                                                            */
/******************************************************************************/

/* Initialize a McElieceKey.
 *
 * PRECONDITION: key must be fresh (as from wc_McElieceKey_New) or previously
 * released with wc_McElieceKey_Free. Init overwrites the pub/priv pointers and
 * the embedded SHAKE object without releasing them, so calling it on a key that
 * already holds generated/decoded material leaks those heap buffers (and does
 * not zeroize the private one). A code-level auto-free is not possible here:
 * on first init those pointers are indeterminate. Call _Free before reusing a
 * key - the same contract as the other wolfCrypt _Init functions. */
int wc_McElieceKey_Init(McElieceKey* key, int type, void* heap, int devId)
{
    int ret = 0;
    const McElieceParams* p = NULL;

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    /* Reject types with bits outside the known base and modifier ranges. */
    else if ((type & ~(MCELIECE_BASE_MASK | MCELIECE_F | MCELIECE_PC)) != 0) {
        ret = BAD_FUNC_ARG;
    }
    /* Reject undefined base parameter sets: only three exist, so a base value
     * above WC_MCELIECE_8192128 is a bad argument, not a disabled feature. */
    else if ((type & MCELIECE_BASE_MASK) > WC_MCELIECE_8192128) {
        ret = BAD_FUNC_ARG;
    }
    else {
        /* NULL means the requested base parameter set is not compiled in. */
        p = wc_mceliece_get_params(type);
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
        key->pub = NULL;
        key->priv = NULL;

        /* Retrieve CPU feature flags once for the assembly dispatch. */
        mceliece_init();

        /* Initialize the reusable SHAKE-256 object used for the PRG and all
         * hashing. */
        ret = wc_InitShake256(&key->shake, heap, key->devId);
    }

    return ret;
}

/* Erase any residual secret (the decapsulated shared secret and absorbed error
 * vector) left in the reusable SHAKE-256 sponge. Re-initialising resets the
 * Keccak state; if that fails, clear it directly. Heap and devId are preserved
 * so the object stays usable for a later operation.
 *
 * @param  [in,out]  key  Key whose SHAKE sponge is wiped.
 */
static void wc_mceliece_wipe_shake(McElieceKey* key)
{
    if (key != NULL) {
        if (wc_InitShake256(&key->shake, key->heap, key->devId) != 0) {
            ForceZero(&key->shake, sizeof(key->shake));
        }
    }
}

/*
 * Releases the heap buffers held by a McElieceKey initialized with
 * wc_McElieceKey_Init() and zeroizes secret material. Does not free the key
 * object itself.
 *
 * @param  [in, out]  key  The McElieceKey to release.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG if key is NULL.
 */
int wc_McElieceKey_Free(McElieceKey* key)
{
    int ret = 0;

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        const McElieceParams* p = key->params;

        /* Release the heap-allocated public key. */
        if (key->pub != NULL) {
            XFREE(key->pub, key->heap, DYNAMIC_TYPE_PUBLIC_KEY);
            key->pub = NULL;
        }
        /* Zeroize then release the heap-allocated private key. */
        if (key->priv != NULL) {
            if (p != NULL) {
                ForceZero(key->priv, p->privSz);
            }
            XFREE(key->priv, key->heap, DYNAMIC_TYPE_PRIVATE_KEY);
            key->priv = NULL;
        }
        /* Wipe any residual shared secret from the sponge, then free it
         * (wc_Shake256_Free does not clear the Keccak state). */
        wc_mceliece_wipe_shake(key);
        wc_Shake256_Free(&key->shake);
        key->flags = 0;
    }

    return ret;
}

#ifndef WC_NO_CONSTRUCTORS
/*
 * Allocates and initializes a new McElieceKey on the heap. The returned pointer
 * must be released with wc_McElieceKey_Delete().
 *
 * Classic McEliece is a conservative, code-based key encapsulation mechanism
 * built on binary Goppa codes (draft-josefsson-mceliece). The type parameter is
 * a base parameter set - WC_MCELIECE_6688128, WC_MCELIECE_6960119 or
 * WC_MCELIECE_8192128 (all NIST level 5) - optionally OR'd with MCELIECE_F
 * (semi-systematic MatGen, which speeds up key generation) and/or MCELIECE_PC
 * (plaintext confirmation). Named combinations such as WC_MCELIECE_6688128F and
 * WC_MCELIECE_8192128PCF are provided. Public keys are large (~1 MB), so the
 * key object holds heap-allocated buffers.
 *
 * @param  [in]  type   McEliece key type: a base parameter set optionally OR'd
 *                      with MCELIECE_F and/or MCELIECE_PC.
 * @param  [in]  heap   Heap hint for dynamic memory allocation. May be NULL.
 * @param  [in]  devId  Device identifier for hardware crypto callbacks. Use
 *                      INVALID_DEVID for software-only.
 * @return  Pointer to a freshly allocated McElieceKey on success.
 * @return  NULL on allocation failure or if type is invalid.
 */
McElieceKey* wc_McElieceKey_New(int type, void* heap, int devId)
{
    int ret;
    McElieceKey* key;

    key = (McElieceKey*)XMALLOC(sizeof(McElieceKey), heap,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (key != NULL) {
        ret = wc_McElieceKey_Init(key, type, heap, devId);
        if (ret != 0) {
            XFREE(key, heap, DYNAMIC_TYPE_TMP_BUFFER);
            key = NULL;
        }
    }

    return key;
}

/*
 * Frees and zeros a heap-allocated McElieceKey previously returned by
 * wc_McElieceKey_New(), and clears the caller's pointer.
 *
 * @param  [in, out]  key    The McElieceKey to free.
 * @param  [in, out]  key_p  Optional address of the caller's pointer to the
 *                           key; set to NULL on return so the pointer cannot be
 *                           reused. May be NULL.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG if key is NULL.
 */
int wc_McElieceKey_Delete(McElieceKey* key, McElieceKey** key_p)
{
    int ret = 0;

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        void* heap = key->heap;

        wc_McElieceKey_Free(key);
        XFREE(key, heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (key_p != NULL) {
            *key_p = NULL;
        }
    }

    return ret;
}
#endif /* !WC_NO_CONSTRUCTORS */

/******************************************************************************/
/* Size queries.                                                              */
/******************************************************************************/

/*
 * Returns the ciphertext length in bytes for the key's parameter set (this
 * depends on the base set and whether MCELIECE_PC is set).
 *
 * @param  [in]   key  A McElieceKey with a resolved parameter set.
 * @param  [out]  len  The ciphertext length in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG if key or len is NULL.
 */
int wc_McElieceKey_CipherTextSize(const McElieceKey* key, word32* len)
{
    int ret = 0;

    if ((key == NULL) || (key->params == NULL) || (len == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        *len = key->params->ctSz;
    }

    return ret;
}

/*
 * Returns the shared secret length in bytes (always 32 for Classic McEliece).
 *
 * @param  [in]   key  A McElieceKey with a resolved parameter set.
 * @param  [out]  len  The shared secret length in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG if key or len is NULL.
 */
int wc_McElieceKey_SharedSecretSize(const McElieceKey* key, word32* len)
{
    int ret = 0;

    if ((key == NULL) || (len == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        *len = MCELIECE_SS_SZ;
    }

    return ret;
}

/*
 * Returns the encoded public key length in bytes for the key's parameter set
 * (approximately 1 MB).
 *
 * @param  [in]   key  A McElieceKey with a resolved parameter set.
 * @param  [out]  len  The encoded public key length in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG if key or len is NULL.
 */
int wc_McElieceKey_PublicKeySize(const McElieceKey* key, word32* len)
{
    int ret = 0;

    if ((key == NULL) || (key->params == NULL) || (len == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        *len = key->params->pubSz;
    }

    return ret;
}

/*
 * Returns the encoded private key length in bytes for the key's parameter set.
 *
 * @param  [in]   key  A McElieceKey with a resolved parameter set.
 * @param  [out]  len  The encoded private key length in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG if key or len is NULL.
 */
int wc_McElieceKey_PrivateKeySize(const McElieceKey* key, word32* len)
{
    int ret = 0;

    if ((key == NULL) || (key->params == NULL) || (len == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        *len = key->params->privSz;
    }

    return ret;
}

/******************************************************************************/
/* Key encode / decode (raw draft section 9.2 byte strings).                  */
/******************************************************************************/

/* Ensure key->pub is allocated for the current parameter set. */
static int wc_mceliece_alloc_pub(McElieceKey* key)
{
    int ret = 0;

    if (key->pub == NULL) {
        key->pub = (byte*)XMALLOC(key->params->pubSz, key->heap,
            DYNAMIC_TYPE_PUBLIC_KEY);
        if (key->pub == NULL) {
            ret = MEMORY_E;
        }
    }

    return ret;
}

/* Ensure key->priv is allocated for the current parameter set. */
static int wc_mceliece_alloc_priv(McElieceKey* key)
{
    int ret = 0;

    if (key->priv == NULL) {
        key->priv = (byte*)XMALLOC(key->params->privSz, key->heap,
            DYNAMIC_TYPE_PRIVATE_KEY);
        if (key->priv == NULL) {
            ret = MEMORY_E;
        }
    }

    return ret;
}

/*
 * Exports the public key in its standard byte encoding.
 *
 * @param  [in]   key  A McElieceKey with a public key set.
 * @param  [out]  out  Output buffer of wc_McElieceKey_PublicKeySize() bytes.
 * @param  [in]   len  Length of out in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG if key or out is NULL.
 * @return  BUFFER_E if len is smaller than the encoded public key size.
 * @return  BAD_STATE_E if the key has no public key set.
 */
int wc_McElieceKey_EncodePublicKey(McElieceKey* key, unsigned char* out,
    word32 len)
{
    int ret = 0;

    if ((key == NULL) || (key->params == NULL) || (out == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else if ((key->flags & MCELIECE_FLAG_PUB_SET) == 0) {
        ret = BAD_STATE_E;
    }
    else if (len < key->params->pubSz) {
        ret = BUFFER_E;
    }
    else {
        XMEMCPY(out, key->pub, key->params->pubSz);
    }

    return ret;
}

/* Verify the unused high padding bits of a public key are zero. Only parameter
 * sets whose k is not a multiple of 8 (mceliece6960119) have such bits; for
 * byte-aligned sets this is a no-op. Returns 0 when valid, BAD_FUNC_ARG when a
 * padding bit is set. */
static int wc_mceliece_check_pk_padding(const McElieceParams* p, const byte* pk)
{
    word32 rowBytes;
    word32 i;
    byte b = 0;
    int ret = 0;

    if ((p->k & 0x7) != 0) {
        rowBytes = (p->k + 7) >> 3;
        for (i = 0; i < p->mt; i++) {
            b |= pk[i * rowBytes + (rowBytes - 1)];
        }
        b = (byte)(b >> (p->k & 0x7));
        ret = (b == 0) ? 0 : BAD_FUNC_ARG;
    }

    return ret;
}

/*
 * Imports a public key from its standard byte encoding into an initialized key
 * object, so the key can be used for encapsulation. The unused padding bits are
 * checked for parameter sets that require it.
 *
 * @param  [in, out]  key  An initialized McElieceKey to load the key into.
 * @param  [in]       in   The encoded public key.
 * @param  [in]       len  Length of in in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG if key or in is NULL, or the unused padding bits are
 *          non-zero.
 * @return  BUFFER_E if len does not match the public key size.
 * @return  MEMORY_E if the public key buffer could not be allocated.
 */
int wc_McElieceKey_DecodePublicKey(McElieceKey* key, const unsigned char* in,
    word32 len)
{
    int ret = 0;

    if ((key == NULL) || (key->params == NULL) || (in == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else if (len != key->params->pubSz) {
        ret = BUFFER_E;
    }
    else {
        ret = wc_mceliece_alloc_pub(key);
    }

    if (ret == 0) {
        /* Committing to the new key: drop the set flag so a subsequent
         * validation failure cannot leave it set over now-invalid data. */
        key->flags &= ~MCELIECE_FLAG_PUB_SET;
        XMEMCPY(key->pub, in, key->params->pubSz);
        /* Reject at import a key whose unused high padding bits are not zero
         * (the draft requires them zero); only mceliece6960119 has such bits. */
        ret = wc_mceliece_check_pk_padding(key->params, key->pub);
    }
    if (ret == 0) {
        key->flags |= MCELIECE_FLAG_PUB_SET;
    }

    return ret;
}

/*
 * Exports the private key in its standard byte encoding. The output contains
 * secret material and should be protected.
 *
 * @param  [in]   key  A McElieceKey with a private key set.
 * @param  [out]  out  Output buffer of wc_McElieceKey_PrivateKeySize() bytes.
 * @param  [in]   len  Length of out in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG if key or out is NULL.
 * @return  BUFFER_E if len is smaller than the encoded private key size.
 * @return  BAD_STATE_E if the key has no private key set.
 */
int wc_McElieceKey_EncodePrivateKey(McElieceKey* key, unsigned char* out,
    word32 len)
{
    int ret = 0;

    if ((key == NULL) || (key->params == NULL) || (out == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else if ((key->flags & MCELIECE_FLAG_PRIV_SET) == 0) {
        ret = BAD_STATE_E;
    }
    else if (len < key->params->privSz) {
        ret = BUFFER_E;
    }
    else {
        XMEMCPY(out, key->priv, key->params->privSz);
    }

    return ret;
}

/*
 * Imports a private key from its standard byte encoding into an initialized key
 * object, so the key can be used for decapsulation.
 *
 * @param  [in, out]  key  An initialized McElieceKey to load the key into.
 * @param  [in]       in   The encoded private key.
 * @param  [in]       len  Length of in in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG if key or in is NULL.
 * @return  BUFFER_E if len does not match the private key size.
 */
int wc_McElieceKey_DecodePrivateKey(McElieceKey* key, const unsigned char* in,
    word32 len)
{
    int ret = 0;

    if ((key == NULL) || (key->params == NULL) || (in == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else if (len != key->params->privSz) {
        ret = BUFFER_E;
    }
    else {
        ret = wc_mceliece_alloc_priv(key);
    }

    if (ret == 0) {
        /* Committing to the new key: clear then set so a failure cannot leave
         * the flag set over stale data. */
        key->flags &= ~MCELIECE_FLAG_PRIV_SET;
        XMEMCPY(key->priv, in, key->params->privSz);
        key->flags |= MCELIECE_FLAG_PRIV_SET;
    }

    return ret;
}

/******************************************************************************/
/* Fujisaki-Okamoto hashing (draft sections 7 and 8).                         */
/******************************************************************************/

#if !defined(WOLFSSL_MCELIECE_NO_ENCAPSULATE) || \
    !defined(WOLFSSL_MCELIECE_NO_DECAPSULATE)
/* Compute Hash(prefix, e, c) = first 32 bytes of SHAKE-256(prefix || e || c),
 * the Fujisaki-Okamoto hash (draft sections 7 and 8).
 *
 * @param  [in]   shake   Reusable SHAKE-256 object.
 * @param  [in]   prefix  Domain-separation byte (0, 1 or 2).
 * @param  [in]   e       Error vector.
 * @param  [in]   eLen    Length of e in bytes.
 * @param  [in]   c       Ciphertext, or NULL for the pc C1 = Hash(2, e) case.
 * @param  [in]   cLen    Length of c in bytes (0 when c is NULL).
 * @param  [out]  out     Hash output (MCELIECE_HASH_SZ bytes).
 * @return  0 on success.
 * @return  A SHAKE error on hashing failure.
 */
static int wc_mceliece_hash(wc_Shake* shake, byte prefix, const byte* e,
    word32 eLen, const byte* c, word32 cLen, byte* out)
{
    int ret;

    int devId = INVALID_DEVID;
#ifdef WOLF_CRYPTO_CB
    devId = shake->devId;
#endif

    /* Re-initialise the sponge first so each call hashes exactly
     * prefix || e || c, independent of any prior absorb or squeeze left on
     * this reusable object (the PRG, or an earlier hash that returned on error
     * before its finalising reset). Preserve the object's heap and devId so a
     * configured crypto callback / heap hint survives the reset. */
    ret = wc_InitShake256(shake, shake->heap, devId);
    if (ret == 0) {
        ret = wc_Shake256_Update(shake, &prefix, 1);
    }
    if (ret == 0) {
        ret = wc_Shake256_Update(shake, e, eLen);
    }
    if ((ret == 0) && (c != NULL) && (cLen > 0)) {
        ret = wc_Shake256_Update(shake, c, cLen);
    }
    if (ret == 0) {
        ret = wc_Shake256_Final(shake, out, MCELIECE_HASH_SZ);
    }

    return ret;
}
#endif /* !NO_ENCAPSULATE || !NO_DECAPSULATE */

#ifndef WOLFSSL_MCELIECE_NO_DECAPSULATE
/* Report whether the unused high padding bits of a ciphertext syndrome are
 * zero. Only sets whose mt is not a multiple of 8 (mceliece6960119) have such
 * bits; byte-aligned sets always report valid. Returns 1 when valid, 0 when
 * the padding is non-zero (the caller folds this into implicit rejection). */
static int wc_mceliece_ct_padding_ok(const McElieceParams* p, const byte* ct)
{
    byte b;
    int ret = 1;

    if ((p->mt & 0x7) != 0) {
        b = (byte)(ct[p->syndBytes - 1] >> (p->mt & 0x7));
        ret = (b == 0) ? 1 : 0;
    }

    return ret;
}
#endif /* !WOLFSSL_MCELIECE_NO_DECAPSULATE */

/******************************************************************************/
/* Key generation.                                                            */
/******************************************************************************/

#ifndef WOLFSSL_MCELIECE_NO_MAKE_KEY

/* Core key generation from a 32-byte delta seed: allocate the public/private
 * key buffers and one scratch buffer, then run SeededKeyGen.
 *
 * @param  [in, out]  key    Key to populate (pub and priv allocated on demand).
 * @param  [in]       delta  32-byte seed.
 * @return  0 on success.
 * @return  MEMORY_E on allocation failure.
 * @return  A negative keygen error otherwise.
 */
static int wc_mceliece_make_key(McElieceKey* key, const byte* delta)
{
    int ret;
    byte* scratch = NULL;
    word32 scratchSz = 0;
    byte* newpub;

    /* A regeneration rewrites the public/private buffers in place, so drop the
     * set flags up front: a failed attempt then leaves the key unusable rather
     * than advertising half-written material as a valid key. */
    key->flags &= ~MCELIECE_FLAG_BOTH_SET;

    /* The public-key buffer doubles as the MatGen matrix during keygen (the
     * matrix is built in place there to avoid a separate ~1.3-1.7 MB scratch
     * buffer), so it is (re)allocated at the larger matrix size here and shrunk
     * to pubSz once the key is built. XREALLOC(NULL, ...) acts as XMALLOC. */
    newpub = (byte*)XREALLOC(key->pub,
        wc_mceliece_keygen_pk_sz(key->params), key->heap,
        DYNAMIC_TYPE_PUBLIC_KEY);
    if (newpub == NULL) {
        ret = MEMORY_E;
    }
    else {
        key->pub = newpub;
        ret = 0;
    }
    if (ret == 0) {
        ret = wc_mceliece_alloc_priv(key);
    }
    if (ret == 0) {
        scratchSz = wc_mceliece_keygen_scratch_sz(key->params);
        /* A 0 size means the layout probe itself failed to allocate (small-
         * stack OOM); treat it as MEMORY_E rather than XMALLOC(0). */
        if (scratchSz == 0) {
            ret = MEMORY_E;
        }
        else {
            scratch = (byte*)XMALLOC(scratchSz, key->heap,
                DYNAMIC_TYPE_TMP_BUFFER);
            if (scratch == NULL) {
                ret = MEMORY_E;
            }
        }
    }
    if (ret == 0) {
        ret = wc_mceliece_keypair(key->params, &key->shake, delta, key->pub,
            key->priv, scratch);
    }
    if (ret == 0) {
        key->flags |= MCELIECE_FLAG_BOTH_SET;
    }
    else {
        /* A failed keypair leaves secret-derived intermediates behind: the
         * public buffer is used in place as the MatGen matrix (g-related data),
         * and the private buffer holds partially written key material. Wipe
         * both so nothing secret lingers until Free. The public buffer is only
         * at the larger matrix size once its (re)allocation succeeded (newpub
         * != NULL); a failed allocation leaves key->pub at its old, smaller
         * size or NULL, so it must not be written at the matrix size. The flags
         * are already cleared, so the key is not advertised as valid. */
        if ((newpub != NULL) && (key->pub != NULL)) {
            ForceZero(key->pub, wc_mceliece_keygen_pk_sz(key->params));
        }
        if (key->priv != NULL) {
            ForceZero(key->priv, key->params->privSz);
        }
    }

    if (scratch != NULL) {
        /* The scratch holds secret intermediates (poly, permutation). */
        ForceZero(scratch, scratchSz);
        XFREE(scratch, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }

    /* Release the extra matrix space by shrinking pk back to pubSz. After
     * elimination the buffer holds only [I | T] (public), so the freed tail
     * carries no secret. Keep the larger buffer if the shrink fails - it is
     * still a valid public key. */
    if ((ret == 0) && (key->pub != NULL)) {
        byte* shrunk = (byte*)XREALLOC(key->pub, key->params->pubSz, key->heap,
            DYNAMIC_TYPE_PUBLIC_KEY);

        if (shrunk != NULL) {
            key->pub = shrunk;
        }
    }

    return ret;
}

/*
 * Generates a McEliece key pair from caller-supplied randomness rather than an
 * RNG. Exactly the 32-byte delta seed is consumed; all internal retries are
 * SHAKE-256 derived. Useful for reproducing known answer test vectors.
 *
 * @param  [in, out]  key   An initialized McElieceKey to populate.
 * @param  [in]       rand  The 32-byte delta seed.
 * @param  [in]       len   Length of rand in bytes (must be 32).
 * @return  0 on success.
 * @return  BAD_FUNC_ARG if key or rand is NULL, or len is not the required seed
 *          length.
 * @return  NOT_COMPILED_IN if key generation was disabled.
 */
int wc_McElieceKey_MakeKeyWithRandom(McElieceKey* key,
    const unsigned char* rand, int len)
{
    int ret = 0;

    if ((key == NULL) || (key->params == NULL) || (rand == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else if (len != MCELIECE_SEED_SZ) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_mceliece_make_key(key, rand);
    }

    return ret;
}

/*
 * Generates a McEliece key pair into an initialized key object, using the
 * supplied RNG (SeededKeyGen: a 32-byte delta seed is drawn and all retries are
 * derived internally with SHAKE-256).
 *
 * @param  [in, out]  key  An initialized McElieceKey to populate.
 * @param  [in]       rng  An initialized WC_RNG.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG if key or rng is NULL.
 * @return  NOT_COMPILED_IN if key generation was disabled
 *          (WOLFSSL_MCELIECE_NO_MAKE_KEY).
 * @return  A negative error code on RNG or generation failure.
 */
int wc_McElieceKey_MakeKey(McElieceKey* key, WC_RNG* rng)
{
    int ret = 0;
    byte delta[MCELIECE_SEED_SZ];

    if ((key == NULL) || (key->params == NULL) || (rng == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        ret = wc_RNG_GenerateBlock(rng, delta, MCELIECE_SEED_SZ);
    }
    if (ret == 0) {
        ret = wc_mceliece_make_key(key, delta);
    }

    ForceZero(delta, sizeof(delta));

    return ret;
}

#endif /* WOLFSSL_MCELIECE_NO_MAKE_KEY */

/******************************************************************************/
/* Encapsulation.                                                             */
/******************************************************************************/

#ifndef WOLFSSL_MCELIECE_NO_ENCAPSULATE

/* Core encapsulation: Encode the error vector, then form the ciphertext (with
 * the pc confirmation hash when p->pc) and the shared secret K = Hash(1, e, C).
 *
 * @param  [in]   key         Key with a public key set.
 * @param  [out]  e           Weight-t error vector scratch (p->sBytes bytes).
 * @param  [out]  ct          Ciphertext (p->ctSz bytes).
 * @param  [out]  ss          Shared secret (MCELIECE_SS_SZ bytes).
 * @param  [in]   rand        Randomness for FixedWeight.
 * @param  [in]   randLen     Length of rand in bytes.
 * @param  [in]   encScratch  Encap scratch (wc_mceliece_encap_scratch_sz(p)).
 * @return  0 on success.
 * @return  MCELIECE_RAND_DEPLETED when rand is exhausted before a weight-t
 *          vector is found.
 * @return  A negative encode / hash error otherwise.
 */
static int wc_mceliece_encapsulate(McElieceKey* key, byte* e, unsigned char* ct,
    unsigned char* ss, const byte* rand, word32 randLen, byte* encScratch)
{
    int ret;
    const McElieceParams* p = key->params;

    /* Reject a public key whose unused padding bits are not zero. */
    ret = wc_mceliece_check_pk_padding(p, key->pub);
    /* Encode: e <- FixedWeight(rand); C0 = He. */
    if (ret == 0) {
        ret = wc_mceliece_encap(p, key->pub, rand, randLen, e, ct, encScratch);
    }
    if (ret == 0) {
        /* pc: C1 = Hash(2, e) is appended after the syndrome C0. */
        if (p->pc) {
            ret = wc_mceliece_hash(&key->shake, MCELIECE_HASH_PREFIX_2, e,
                p->sBytes, NULL, 0, ct + p->syndBytes);
        }
    }
    if (ret == 0) {
        /* K = Hash(1, e, C). */
        ret = wc_mceliece_hash(&key->shake, MCELIECE_HASH_PREFIX_1, e,
            p->sBytes, ct, p->ctSz, ss);
    }
    /* Erase the shared secret left in the SHAKE sponge by the Hash step. */
    wc_mceliece_wipe_shake(key);

    return ret;
}

/*
 * Encapsulates using caller-supplied randomness rather than an RNG. The bytes
 * are consumed in fixed-weight rejection attempts; if the supplied randomness
 * is exhausted before a valid error vector is found, an error is returned
 * (unlike the RNG path, which draws more). Useful for reproducing known answer
 * test vectors.
 *
 * @param  [in]   key   A McElieceKey with a public key set.
 * @param  [out]  ct    Ciphertext buffer of wc_McElieceKey_CipherTextSize()
 *                      bytes.
 * @param  [out]  ss    Shared secret buffer of 32 bytes.
 * @param  [in]   rand  Randomness for the fixed-weight error draw.
 * @param  [in]   len   Length of rand in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG if any argument is NULL or len is negative.
 * @return  BAD_STATE_E if the key has no public key set.
 * @return  BUFFER_E if the supplied randomness is exhausted before a valid
 *          error vector is found.
 * @return  MEMORY_E if a temporary allocation fails.
 * @return  NOT_COMPILED_IN if encapsulation was disabled.
 */
int wc_McElieceKey_EncapsulateWithRandom(McElieceKey* key, unsigned char* ct,
    unsigned char* ss, const unsigned char* rand, int len)
{
    int ret = 0;
    byte* scratch = NULL;
    word32 total = 0;
    word32 eSz = 0;
    const McElieceParams* p = NULL;

    if ((key == NULL) || (key->params == NULL) || (ct == NULL) ||
            (ss == NULL) || (rand == NULL) || (len < 0)) {
        ret = BAD_FUNC_ARG;
    }
    else if ((key->flags & MCELIECE_FLAG_PUB_SET) == 0) {
        ret = BAD_STATE_E;
    }
    else {
        p = key->params;
        /* One allocation: e (weight-t vector) followed by the encap scratch. */
        eSz = (p->sBytes + 7u) & ~(word32)7u;
        total = wc_mceliece_encap_scratch_sz(p);
        /* 0 => the layout probe failed to allocate; not a valid size. */
        if (total == 0) {
            ret = MEMORY_E;
        }
        else {
            total += eSz;
            scratch = (byte*)XMALLOC(total, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
            if (scratch == NULL) {
                ret = MEMORY_E;
            }
        }
    }

    if (ret == 0) {
        ret = wc_mceliece_encapsulate(key, scratch, ct, ss, rand, (word32)len,
            scratch + eSz);
        /* MCELIECE_RAND_DEPLETED is an internal sentinel that drives the retry
         * loop in the RNG-based wc_McElieceKey_Encapsulate. Reaching it here
         * means the caller-supplied randomness ran out before FixedWeight
         * sampling produced a weight-t vector - map it to a real (negative)
         * error so callers using the usual "ret < 0" check see the failure. */
        if (ret == MCELIECE_RAND_DEPLETED) {
            ret = BUFFER_E;
        }
    }

    if (scratch != NULL) {
        ForceZero(scratch, total);
        XFREE(scratch, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return ret;
}

/*
 * Encapsulates to a public key: draws a fixed-weight error vector from the RNG,
 * computes the ciphertext, and derives the 32-byte shared secret via the
 * Fujisaki-Okamoto transform. The key must have a public key set (from
 * wc_McElieceKey_MakeKey() or wc_McElieceKey_DecodePublicKey()).
 *
 * @param  [in]   key  A McElieceKey with a public key set.
 * @param  [out]  ct   Ciphertext buffer of wc_McElieceKey_CipherTextSize()
 *                     bytes.
 * @param  [out]  ss   Shared secret buffer of 32 bytes.
 * @param  [in]   rng  An initialized WC_RNG.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG if any argument is NULL.
 * @return  BAD_STATE_E if the key has no public key set.
 * @return  NOT_COMPILED_IN if encapsulation was disabled
 *          (WOLFSSL_MCELIECE_NO_ENCAPSULATE).
 */
int wc_McElieceKey_Encapsulate(McElieceKey* key, unsigned char* ct,
    unsigned char* ss, WC_RNG* rng)
{
    int ret = 0;
    byte* scratch = NULL;
    byte* rand = NULL;
    word32 randLen = 0;
    word32 total = 0;
    word32 eSz = 0;
    word32 rSz = 0;
    const McElieceParams* p = NULL;

    if ((key == NULL) || (key->params == NULL) || (ct == NULL) ||
            (ss == NULL) || (rng == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else if ((key->flags & MCELIECE_FLAG_PUB_SET) == 0) {
        ret = BAD_STATE_E;
    }
    else {
        p = key->params;
        /* Draw one FixedWeight attempt at a time. The retry loop below redraws
         * on the (rare) rejection, trading a few extra RNG calls for a smaller
         * randomness buffer. */
        randLen = (word32)MCELIECE_FIXEDWEIGHT_ATTEMPT_SZ(p->tau);
        /* One allocation: e || rand || encap scratch. */
        eSz = (p->sBytes + 7u) & ~(word32)7u;
        rSz = (randLen + 7u) & ~(word32)7u;
        total = wc_mceliece_encap_scratch_sz(p);
        /* 0 => the layout probe failed to allocate; not a valid size. */
        if (total == 0) {
            ret = MEMORY_E;
        }
        else {
            total += eSz + rSz;
            scratch = (byte*)XMALLOC(total, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
            if (scratch == NULL) {
                ret = MEMORY_E;
            }
        }
    }

    if (ret == 0) {
        rand = scratch + eSz;
        /* FixedWeight rejection can (rarely) exhaust one batch of randomness.
         * On depletion, draw a fresh batch and retry, matching the reference
         * gen_e which loops until it succeeds. */
        do {
            ret = wc_RNG_GenerateBlock(rng, rand, randLen);
            if (ret == 0) {
                ret = wc_mceliece_encapsulate(key, scratch, ct, ss, rand,
                    randLen, scratch + eSz + rSz);
            }
        } while (ret == MCELIECE_RAND_DEPLETED);
    }

    if (scratch != NULL) {
        ForceZero(scratch, total);
        XFREE(scratch, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return ret;
}

#endif /* WOLFSSL_MCELIECE_NO_ENCAPSULATE */

/******************************************************************************/
/* Decapsulation.                                                             */
/******************************************************************************/

#ifndef WOLFSSL_MCELIECE_NO_DECAPSULATE

/*
 * Decapsulates a ciphertext with the private key, recovering the 32-byte shared
 * secret. On a decoding failure the Fujisaki-Okamoto transform yields an
 * implicit-rejection secret in constant time rather than signalling an error,
 * so a wrong ciphertext does not leak.
 *
 * @param  [in]   key  A McElieceKey with a private key set.
 * @param  [out]  ss   Shared secret buffer of 32 bytes.
 * @param  [in]   ct   The ciphertext.
 * @param  [in]   len  Length of ct in bytes.
 * @return  0 on success (including the implicit-rejection case).
 * @return  BAD_FUNC_ARG if any argument is NULL.
 * @return  BUFFER_E if len is not the expected ciphertext length.
 * @return  BAD_STATE_E if the key has no private key set.
 * @return  NOT_COMPILED_IN if decapsulation was disabled
 *          (WOLFSSL_MCELIECE_NO_DECAPSULATE).
 */
int wc_McElieceKey_Decapsulate(McElieceKey* key, unsigned char* ss,
    const unsigned char* ct, word32 len)
{
    int ret = 0;
    byte* scratch = NULL;
    byte* e = NULL;
    word32 total = 0;
    word32 eSz = 0;
    const McElieceParams* p = NULL;
    const byte* s = NULL;
    byte b = 1;
    int decRet = 0;
    word32 reject = 0;
    byte rmask = 0;
    word32 i;

    if ((key == NULL) || (key->params == NULL) || (ss == NULL) ||
            (ct == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else if ((key->flags & MCELIECE_FLAG_PRIV_SET) == 0) {
        ret = BAD_STATE_E;
    }
    else if (len != key->params->ctSz) {
        ret = BUFFER_E;
    }
    else {
        p = key->params;
        /* One allocation: e (weight-t vector) then the decode scratch. */
        eSz = (p->sBytes + 7u) & ~(word32)7u;
        total = wc_mceliece_decode_scratch_sz(p);
        /* 0 => the layout probe failed to allocate; not a valid size. */
        if (total == 0) {
            ret = MEMORY_E;
        }
        else {
            total += eSz;
            scratch = (byte*)XMALLOC(total, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
            if (scratch == NULL) {
                ret = MEMORY_E;
            }
            else {
                e = scratch;
            }
        }
    }

    if (ret == 0) {
        /* Decode C0 to recover the weight-t error vector e. */
        decRet = wc_mceliece_decode(p, key->priv, ct, e, scratch + eSz);
        if (decRet < 0) {
            ret = decRet;
        }
    }

    if (ret == 0) {
        /* s is the last sBytes of the private key (implicit-rejection value).
         * Layout: delta || c || g || control-bits || s. */
        s = key->priv + (p->privSz - p->sBytes);

        /* Constant-time implicit rejection: build an all-ones mask when the
         * ciphertext must be rejected, then select e <- s unconditionally so
         * neither the decode-success bit nor the pc result is revealed by a
         * branch or by whether the copy runs.
         *   decRet is 0 (ok) or 1 (MCELIECE_DECODE_FAIL) here (negatives were
         *   handled above); padding-ok is 1 (ok) or 0 (bad, public data). */
        reject = (word32)0 - (word32)decRet;
        reject |= (word32)wc_mceliece_ct_padding_ok(p, ct) - 1u;
        rmask = (byte)reject;
        for (i = 0; i < p->sBytes; i++) {
            e[i] = (byte)((e[i] & (byte)~rmask) | (s[i] & rmask));
        }
    }

    if ((ret == 0) && p->pc) {
        /* pc: recompute C1' = Hash(2, e); on mismatch select e <- s (again,
         * branchlessly). The compare and the select are both constant-time. */
        byte c1[MCELIECE_HASH_SZ];
        byte diff = 0;

        ret = wc_mceliece_hash(&key->shake, MCELIECE_HASH_PREFIX_2, e,
            p->sBytes, NULL, 0, c1);
        if (ret == 0) {
            word32 pcrej;

            for (i = 0; i < MCELIECE_HASH_SZ; i++) {
                diff |= (byte)(c1[i] ^ ct[p->syndBytes + i]);
            }
            /* pcrej = all-ones iff diff != 0, with no branch on diff. */
            pcrej = (word32)0 - (((word32)diff + 0xFFu) >> 8);
            reject |= pcrej;
            rmask = (byte)pcrej;
            for (i = 0; i < p->sBytes; i++) {
                e[i] = (byte)((e[i] & (byte)~rmask) | (s[i] & rmask));
            }
        }
        ForceZero(c1, sizeof(c1));
    }

    if (ret == 0) {
        /* b = 0 on any rejection, else 1 - the Hash domain separator. */
        b = (byte)(~reject & 1u);
        /* K = Hash(b, e, C). */
        ret = wc_mceliece_hash(&key->shake, b, e, p->sBytes, ct, p->ctSz, ss);
    }

    if (scratch != NULL) {
        /* Clear the whole allocation: e, the secret decode buffers, and the
         * asm driver scratch at the tail. That tail holds private-key-derived
         * material (e.g. the expanded Benes control bits on AVX2/AVX512), so it
         * must not be left behind in freed heap. */
        ForceZero(scratch, total);
        XFREE(scratch, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    /* Erase the shared secret left in the SHAKE sponge by the Hash step. */
    wc_mceliece_wipe_shake(key);

    return ret;
}

#endif /* WOLFSSL_MCELIECE_NO_DECAPSULATE */

#endif /* WOLFSSL_HAVE_MCELIECE */
