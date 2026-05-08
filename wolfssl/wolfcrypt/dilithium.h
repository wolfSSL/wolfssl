/* dilithium.h
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
    \file wolfssl/wolfcrypt/dilithium.h
*/

/* TEMPORARY legacy compatibility shim. The pre-standardization Dilithium
 * signature algorithm was standardized by NIST as ML-DSA (FIPS 204); the
 * canonical implementation lives in <wolfssl/wolfcrypt/wc_mldsa.h>.
 *
 * This file performs two TEMPORARY compatibility services and will be
 * removed in a future wolfSSL release:
 *
 *   1. A sub-config build-gate translation block (legacy
 *      WOLFSSL_DILITHIUM_* / WC_DILITHIUM_* <-> canonical WOLFSSL_MLDSA_* /
 *      WC_MLDSA_*). The forward arm runs BEFORE this file's #include of
 *      wc_mldsa.h so wc_mldsa.h's own conditional declarations always
 *      read the canonical gate, regardless of which spelling
 *      user_settings.h or the build system used. The reverse arm runs
 *      AFTER the include so derived canonical gates that wc_mldsa.h
 *      computes from WOLFSSL_MLDSA_NO_* (e.g. WOLFSSL_MLDSA_PUBLIC_KEY,
 *      WOLFSSL_MLDSA_PRIVATE_KEY, WOLFSSL_MLDSA_CHECK_KEY) are visible
 *      to the reverse propagation. Suppressed by defining
 *      WOLFSSL_NO_DILITHIUM_LEGACY_GATES.
 *
 *      The parent gate (HAVE_DILITHIUM / WOLFSSL_HAVE_MLDSA) is mapped
 *      earlier in <wolfssl/wolfcrypt/settings.h> with an asymmetric
 *      contract: the forward arm (legacy -> canonical) is unconditional
 *      because wc_mldsa.h itself reads only the canonical name; the
 *      reverse arm (canonical -> legacy) honors
 *      WOLFSSL_NO_DILITHIUM_LEGACY_GATES. In normal builds the two parent
 *      names are functionally equivalent, since at least one direction
 *      always fires whenever either is defined; the legacy spelling
 *      remains as an alias kept around for unmigrated consumer code.
 *
 *   2. Macro / static-inline aliases for the legacy type and function
 *      names (dilithium_key, wc_dilithium_params, wc_dilithium_*,
 *      wc_Dilithium_*) so application code written against the
 *      pre-standardization API keeps compiling. Suppressed by defining
 *      WOLFSSL_NO_DILITHIUM_LEGACY_NAMES.
 *
 * New code must include <wolfssl/wolfcrypt/wc_mldsa.h> directly and use
 * the MlDsaKey / wc_MlDsaKey_* / WOLFSSL_MLDSA_* names. */

#ifndef WOLF_CRYPT_DILITHIUM_H
#define WOLF_CRYPT_DILITHIUM_H

/* === Sub-config build-gate translations =============================== */

/* The two sub-gates that <wolfssl/certs_test.h> (auto-generated, no
 * #includes) reads -- WOLFSSL_DILITHIUM_NO_SIGN /
 * WOLFSSL_DILITHIUM_NO_VERIFY -- are forward-translated in
 * <wolfssl/wolfcrypt/settings.h> so that header sees the canonical
 * spelling without going through dilithium.h. The block below covers
 * the remaining sub-gates, all of which are read only by wc_mldsa.h /
 * wc_mldsa.c (which transitively include this file first). */

#ifndef WOLFSSL_NO_DILITHIUM_LEGACY_GATES

/* Legacy -> canonical (forward arm, remainder). For the gates handled in
 * settings.h see the comment block there. */
#ifdef WOLFSSL_DILITHIUM_NO_MAKE_KEY
    #ifndef WOLFSSL_MLDSA_NO_MAKE_KEY
        #define WOLFSSL_MLDSA_NO_MAKE_KEY
    #endif
#endif
#ifdef WOLFSSL_DILITHIUM_VERIFY_ONLY
    #ifndef WOLFSSL_MLDSA_VERIFY_ONLY
        #define WOLFSSL_MLDSA_VERIFY_ONLY
    #endif
#endif
#ifdef WOLFSSL_DILITHIUM_NO_CTX
    #ifndef WOLFSSL_MLDSA_NO_CTX
        #define WOLFSSL_MLDSA_NO_CTX
    #endif
#endif
#ifdef WOLFSSL_DILITHIUM_NO_ASN1
    #ifndef WOLFSSL_MLDSA_NO_ASN1
        #define WOLFSSL_MLDSA_NO_ASN1
    #endif
#endif
#ifdef WOLFSSL_DILITHIUM_NO_LARGE_CODE
    #ifndef WOLFSSL_MLDSA_NO_LARGE_CODE
        #define WOLFSSL_MLDSA_NO_LARGE_CODE
    #endif
#endif
#ifdef WOLFSSL_DILITHIUM_SMALL
    #ifndef WOLFSSL_MLDSA_SMALL
        #define WOLFSSL_MLDSA_SMALL
    #endif
#endif
#ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
    #ifndef WOLFSSL_MLDSA_SMALL_MEM_POLY64
        #define WOLFSSL_MLDSA_SMALL_MEM_POLY64
    #endif
#endif
#ifdef WOLFSSL_DILITHIUM_VERIFY_NO_MALLOC
    #ifndef WOLFSSL_MLDSA_VERIFY_NO_MALLOC
        #define WOLFSSL_MLDSA_VERIFY_NO_MALLOC
    #endif
#endif
#ifdef WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM
    #ifndef WOLFSSL_MLDSA_VERIFY_SMALL_MEM
        #define WOLFSSL_MLDSA_VERIFY_SMALL_MEM
    #endif
#endif
#ifdef WOLFSSL_DILITHIUM_MAKE_KEY_SMALL_MEM
    #ifndef WOLFSSL_MLDSA_MAKE_KEY_SMALL_MEM
        #define WOLFSSL_MLDSA_MAKE_KEY_SMALL_MEM
    #endif
#endif
#ifdef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM
    #ifndef WOLFSSL_MLDSA_SIGN_SMALL_MEM
        #define WOLFSSL_MLDSA_SIGN_SMALL_MEM
    #endif
#endif
#ifdef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC
    #ifndef WOLFSSL_MLDSA_SIGN_SMALL_MEM_PRECALC
        #define WOLFSSL_MLDSA_SIGN_SMALL_MEM_PRECALC
    #endif
#endif
#ifdef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A
    #ifndef WOLFSSL_MLDSA_SIGN_SMALL_MEM_PRECALC_A
        #define WOLFSSL_MLDSA_SIGN_SMALL_MEM_PRECALC_A \
            WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A
    #endif
#endif
#ifdef WOLFSSL_DILITHIUM_SIGN_CHECK_W0
    #ifndef WOLFSSL_MLDSA_SIGN_CHECK_W0
        #define WOLFSSL_MLDSA_SIGN_CHECK_W0
    #endif
#endif
#ifdef WOLFSSL_DILITHIUM_SIGN_CHECK_Y
    #ifndef WOLFSSL_MLDSA_SIGN_CHECK_Y
        #define WOLFSSL_MLDSA_SIGN_CHECK_Y
    #endif
#endif
#ifdef WOLFSSL_DILITHIUM_CHECK_KEY
    #ifndef WOLFSSL_MLDSA_CHECK_KEY
        #define WOLFSSL_MLDSA_CHECK_KEY
    #endif
#endif
#ifdef WOLFSSL_DILITHIUM_NO_CHECK_KEY
    #ifndef WOLFSSL_MLDSA_NO_CHECK_KEY
        #define WOLFSSL_MLDSA_NO_CHECK_KEY
    #endif
#endif
#ifdef WOLFSSL_DILITHIUM_PUBLIC_KEY
    #ifndef WOLFSSL_MLDSA_PUBLIC_KEY
        #define WOLFSSL_MLDSA_PUBLIC_KEY
    #endif
#endif
#ifdef WOLFSSL_DILITHIUM_PRIVATE_KEY
    #ifndef WOLFSSL_MLDSA_PRIVATE_KEY
        #define WOLFSSL_MLDSA_PRIVATE_KEY
    #endif
#endif
#ifdef WOLFSSL_DILITHIUM_DYNAMIC_KEYS
    #ifndef WOLFSSL_MLDSA_DYNAMIC_KEYS
        #define WOLFSSL_MLDSA_DYNAMIC_KEYS
    #endif
#endif
#ifdef WOLFSSL_DILITHIUM_ASSIGN_KEY
    #ifndef WOLFSSL_MLDSA_ASSIGN_KEY
        #define WOLFSSL_MLDSA_ASSIGN_KEY
    #endif
#endif
#ifdef WOLFSSL_DILITHIUM_ALIGNMENT
    #ifndef WOLFSSL_MLDSA_ALIGNMENT
        #define WOLFSSL_MLDSA_ALIGNMENT WOLFSSL_DILITHIUM_ALIGNMENT
    #endif
#endif
#ifdef WOLFSSL_DILITHIUM_FIPS204_DRAFT
    #ifndef WOLFSSL_MLDSA_FIPS204_DRAFT
        #define WOLFSSL_MLDSA_FIPS204_DRAFT
    #endif
#endif
#ifdef WOLFSSL_DILITHIUM_NO_MAKE
    #ifndef WOLFSSL_MLDSA_NO_MAKE
        #define WOLFSSL_MLDSA_NO_MAKE
    #endif
#endif
#ifdef WOLFSSL_DILITHIUM_REVERSE_HASH_OID
    #ifndef WOLFSSL_MLDSA_REVERSE_HASH_OID
        #define WOLFSSL_MLDSA_REVERSE_HASH_OID
    #endif
#endif
#ifdef WC_DILITHIUM_CACHE_MATRIX_A
    #ifndef WC_MLDSA_CACHE_MATRIX_A
        #define WC_MLDSA_CACHE_MATRIX_A
    #endif
#endif
#ifdef WC_DILITHIUM_CACHE_PRIV_VECTORS
    #ifndef WC_MLDSA_CACHE_PRIV_VECTORS
        #define WC_MLDSA_CACHE_PRIV_VECTORS
    #endif
#endif
#ifdef WC_DILITHIUM_CACHE_PUB_VECTORS
    #ifndef WC_MLDSA_CACHE_PUB_VECTORS
        #define WC_MLDSA_CACHE_PUB_VECTORS
    #endif
#endif
#ifdef WC_DILITHIUM_FIXED_ARRAY
    #ifndef WC_MLDSA_FIXED_ARRAY
        #define WC_MLDSA_FIXED_ARRAY
    #endif
#endif

#endif /* !WOLFSSL_NO_DILITHIUM_LEGACY_GATES */

/* === wc_mldsa.h is now reachable with canonical gates correctly set === */

#include <wolfssl/wolfcrypt/wc_mldsa.h>

/* Canonical -> legacy (reverse arm). When the canonical name is defined
 * (e.g. by a build system that emits -DWOLFSSL_HAVE_MLDSA), also define
 * the legacy gate name so unmigrated consumer code that still gates on
 * WOLFSSL_DILITHIUM_* / WC_DILITHIUM_* keeps compiling. The library's own
 * sources gate on the canonical names; this arm exists for in-tree
 * consumer files that haven't been migrated yet (and for downstream code
 * that mixes legacy + canonical references).
 *
 * Runs AFTER the include of wc_mldsa.h so derived canonical gates that
 * are computed inside wc_mldsa.h (WOLFSSL_MLDSA_PUBLIC_KEY,
 * WOLFSSL_MLDSA_PRIVATE_KEY, WOLFSSL_MLDSA_CHECK_KEY) are visible to the
 * reverse propagation. */
#ifndef WOLFSSL_NO_DILITHIUM_LEGACY_GATES
#if defined(WOLFSSL_MLDSA_NO_MAKE_KEY) && !defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY)
    #define WOLFSSL_DILITHIUM_NO_MAKE_KEY
#endif
#if defined(WOLFSSL_MLDSA_NO_SIGN) && !defined(WOLFSSL_DILITHIUM_NO_SIGN)
    #define WOLFSSL_DILITHIUM_NO_SIGN
#endif
#if defined(WOLFSSL_MLDSA_NO_VERIFY) && !defined(WOLFSSL_DILITHIUM_NO_VERIFY)
    #define WOLFSSL_DILITHIUM_NO_VERIFY
#endif
#if defined(WOLFSSL_MLDSA_VERIFY_ONLY) && !defined(WOLFSSL_DILITHIUM_VERIFY_ONLY)
    #define WOLFSSL_DILITHIUM_VERIFY_ONLY
#endif
#if defined(WOLFSSL_MLDSA_NO_CTX) && !defined(WOLFSSL_DILITHIUM_NO_CTX)
    #define WOLFSSL_DILITHIUM_NO_CTX
#endif
#if defined(WOLFSSL_MLDSA_NO_ASN1) && !defined(WOLFSSL_DILITHIUM_NO_ASN1)
    #define WOLFSSL_DILITHIUM_NO_ASN1
#endif
#if defined(WOLFSSL_MLDSA_NO_LARGE_CODE) && !defined(WOLFSSL_DILITHIUM_NO_LARGE_CODE)
    #define WOLFSSL_DILITHIUM_NO_LARGE_CODE
#endif
#if defined(WOLFSSL_MLDSA_NO_MAKE) && !defined(WOLFSSL_DILITHIUM_NO_MAKE)
    #define WOLFSSL_DILITHIUM_NO_MAKE
#endif
#if defined(WOLFSSL_MLDSA_SMALL) && !defined(WOLFSSL_DILITHIUM_SMALL)
    #define WOLFSSL_DILITHIUM_SMALL
#endif
#if defined(WOLFSSL_MLDSA_SMALL_MEM_POLY64) && !defined(WOLFSSL_DILITHIUM_SMALL_MEM_POLY64)
    #define WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
#endif
#if defined(WOLFSSL_MLDSA_VERIFY_NO_MALLOC) && !defined(WOLFSSL_DILITHIUM_VERIFY_NO_MALLOC)
    #define WOLFSSL_DILITHIUM_VERIFY_NO_MALLOC
#endif
#if defined(WOLFSSL_MLDSA_VERIFY_SMALL_MEM) && !defined(WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM)
    #define WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM
#endif
#if defined(WOLFSSL_MLDSA_MAKE_KEY_SMALL_MEM) && !defined(WOLFSSL_DILITHIUM_MAKE_KEY_SMALL_MEM)
    #define WOLFSSL_DILITHIUM_MAKE_KEY_SMALL_MEM
#endif
#if defined(WOLFSSL_MLDSA_SIGN_SMALL_MEM) && !defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM)
    #define WOLFSSL_DILITHIUM_SIGN_SMALL_MEM
#endif
#if defined(WOLFSSL_MLDSA_SIGN_SMALL_MEM_PRECALC) && !defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC)
    #define WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC
#endif
#if defined(WOLFSSL_MLDSA_SIGN_SMALL_MEM_PRECALC_A) && !defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A)
    #define WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A \
        WOLFSSL_MLDSA_SIGN_SMALL_MEM_PRECALC_A
#endif
#if defined(WOLFSSL_MLDSA_SIGN_CHECK_W0) && !defined(WOLFSSL_DILITHIUM_SIGN_CHECK_W0)
    #define WOLFSSL_DILITHIUM_SIGN_CHECK_W0
#endif
#if defined(WOLFSSL_MLDSA_SIGN_CHECK_Y) && !defined(WOLFSSL_DILITHIUM_SIGN_CHECK_Y)
    #define WOLFSSL_DILITHIUM_SIGN_CHECK_Y
#endif
#if defined(WOLFSSL_MLDSA_CHECK_KEY) && !defined(WOLFSSL_DILITHIUM_CHECK_KEY)
    #define WOLFSSL_DILITHIUM_CHECK_KEY
#endif
#if defined(WOLFSSL_MLDSA_NO_CHECK_KEY) && !defined(WOLFSSL_DILITHIUM_NO_CHECK_KEY)
    #define WOLFSSL_DILITHIUM_NO_CHECK_KEY
#endif
#if defined(WOLFSSL_MLDSA_PUBLIC_KEY) && !defined(WOLFSSL_DILITHIUM_PUBLIC_KEY)
    #define WOLFSSL_DILITHIUM_PUBLIC_KEY
#endif
#if defined(WOLFSSL_MLDSA_PRIVATE_KEY) && !defined(WOLFSSL_DILITHIUM_PRIVATE_KEY)
    #define WOLFSSL_DILITHIUM_PRIVATE_KEY
#endif
#if defined(WOLFSSL_MLDSA_DYNAMIC_KEYS) && !defined(WOLFSSL_DILITHIUM_DYNAMIC_KEYS)
    #define WOLFSSL_DILITHIUM_DYNAMIC_KEYS
#endif
#if defined(WOLFSSL_MLDSA_ASSIGN_KEY) && !defined(WOLFSSL_DILITHIUM_ASSIGN_KEY)
    #define WOLFSSL_DILITHIUM_ASSIGN_KEY
#endif
#if defined(WOLFSSL_MLDSA_ALIGNMENT) && !defined(WOLFSSL_DILITHIUM_ALIGNMENT)
    #define WOLFSSL_DILITHIUM_ALIGNMENT WOLFSSL_MLDSA_ALIGNMENT
#endif
#if defined(WOLFSSL_MLDSA_FIPS204_DRAFT) && !defined(WOLFSSL_DILITHIUM_FIPS204_DRAFT)
    #define WOLFSSL_DILITHIUM_FIPS204_DRAFT
#endif
#if defined(WOLFSSL_MLDSA_REVERSE_HASH_OID) && !defined(WOLFSSL_DILITHIUM_REVERSE_HASH_OID)
    #define WOLFSSL_DILITHIUM_REVERSE_HASH_OID
#endif
#if defined(WC_MLDSA_CACHE_MATRIX_A) && !defined(WC_DILITHIUM_CACHE_MATRIX_A)
    #define WC_DILITHIUM_CACHE_MATRIX_A
#endif
#if defined(WC_MLDSA_CACHE_PRIV_VECTORS) && !defined(WC_DILITHIUM_CACHE_PRIV_VECTORS)
    #define WC_DILITHIUM_CACHE_PRIV_VECTORS
#endif
#if defined(WC_MLDSA_CACHE_PUB_VECTORS) && !defined(WC_DILITHIUM_CACHE_PUB_VECTORS)
    #define WC_DILITHIUM_CACHE_PUB_VECTORS
#endif
#if defined(WC_MLDSA_FIXED_ARRAY) && !defined(WC_DILITHIUM_FIXED_ARRAY)
    #define WC_DILITHIUM_FIXED_ARRAY
#endif
#endif /* !WOLFSSL_NO_DILITHIUM_LEGACY_GATES */

#if defined(WOLFSSL_HAVE_MLDSA) && !defined(WOLFSSL_NO_DILITHIUM_LEGACY_NAMES)

/* Legacy type aliases. WC_DILITHIUMKEY_TYPE_DEFINED is set so that
 * <wolfssl/wolfcrypt/asn_public.h> does not emit its own
 * `typedef struct MlDsaKey dilithium_key;` (which would expand under this
 * macro alias to `typedef struct MlDsaKey MlDsaKey;` -- a typedef
 * redefinition that strict C99 / older MSVC reject as a constraint
 * violation). */
#define dilithium_key                       MlDsaKey
#ifndef WC_DILITHIUMKEY_TYPE_DEFINED
    #define WC_DILITHIUMKEY_TYPE_DEFINED
#endif
#define wc_dilithium_params                 MlDsaParams

/* Legacy function aliases - simple symbol redirects. Signature is unchanged
 * vs the canonical name, so a #define is sufficient: call sites and `&name`
 * expressions both expand token-wise to the canonical symbol. Note that
 * `&wc_dilithium_make_key` therefore yields the address of
 * wc_MlDsaKey_MakeKey, NOT a distinct legacy export - consumers using
 * dlsym() or callback tables that key off the legacy spelling will see the
 * canonical name in the resulting pointer. */
#define wc_dilithium_init_ex                wc_MlDsaKey_Init
#define wc_dilithium_init_id                wc_MlDsaKey_InitId
#define wc_dilithium_init_label             wc_MlDsaKey_InitLabel
#define wc_dilithium_new                    wc_MlDsaKey_New
#define wc_dilithium_delete                 wc_MlDsaKey_Delete
#define wc_dilithium_free                   wc_MlDsaKey_Free
#define wc_dilithium_set_level              wc_MlDsaKey_SetParams
#define wc_dilithium_get_level              wc_MlDsaKey_GetParams
#define wc_dilithium_make_key               wc_MlDsaKey_MakeKey
#define wc_dilithium_make_key_from_seed     wc_MlDsaKey_MakeKeyFromSeed
#define wc_dilithium_size                   wc_MlDsaKey_Size
#define wc_dilithium_priv_size              wc_MlDsaKey_PrivSize
#define wc_dilithium_pub_size               wc_MlDsaKey_PubSize
#define wc_dilithium_sig_size               wc_MlDsaKey_SigSize
#define wc_dilithium_check_key              wc_MlDsaKey_CheckKey
#define wc_dilithium_export_public          wc_MlDsaKey_ExportPubRaw
#define wc_dilithium_export_private         wc_MlDsaKey_ExportPrivRaw
#define wc_dilithium_export_private_only    wc_MlDsaKey_ExportPrivRaw
#define wc_dilithium_export_key             wc_MlDsaKey_ExportKey
#define wc_Dilithium_PublicKeyToDer         wc_MlDsaKey_PublicKeyToDer
#define wc_Dilithium_PrivateKeyToDer        wc_MlDsaKey_PrivateKeyToDer
#define wc_Dilithium_KeyToDer               wc_MlDsaKey_KeyToDer

/* Legacy default-args / arg-reorder wrappers. The legacy form takes the key
 * pointer last (or near last); the FIPS 204 / ML-KEM convention used by the
 * canonical wc_MlDsaKey_* names puts the key first. The wrappers below are
 * static inline functions (rather than function-like macros) so that
 * (a) `&wc_dilithium_init`-style address-of expressions remain valid in
 * source (they yield the inline wrapper's address - note this is a
 * translation-unit-local symbol, not the previously-exported library
 * symbol) and (b) each wrapper preserves the legacy signature byte-for-byte.
 * Each wrapper is gated to match its canonical target's gating so
 * unused-on-this-build wrappers don't reference undeclared symbols. */

#ifdef __GNUC__
    /* Suppress -Wunused-function for translation units that don't call every
     * legacy wrapper. */
    #define WOLFSSL_DILITHIUM_LEGACY_INLINE static __inline__ \
        __attribute__((unused, always_inline))
#else
    #define WOLFSSL_DILITHIUM_LEGACY_INLINE static WC_INLINE
#endif

WOLFSSL_DILITHIUM_LEGACY_INLINE
int wc_dilithium_init(MlDsaKey* key) {
    return wc_MlDsaKey_Init(key, NULL, INVALID_DEVID);
}

#ifdef WOLFSSL_MLDSA_PUBLIC_KEY
WOLFSSL_DILITHIUM_LEGACY_INLINE
int wc_dilithium_import_public(const byte* in, word32 inLen, MlDsaKey* key) {
    return wc_MlDsaKey_ImportPubRaw(key, in, inLen);
}
#endif

#ifdef WOLFSSL_MLDSA_PRIVATE_KEY
WOLFSSL_DILITHIUM_LEGACY_INLINE
int wc_dilithium_import_private(const byte* priv, word32 privSz, MlDsaKey* key) {
    return wc_MlDsaKey_ImportPrivRaw(key, priv, privSz);
}
WOLFSSL_DILITHIUM_LEGACY_INLINE
int wc_dilithium_import_private_only(const byte* in, word32 inLen, MlDsaKey* key) {
    return wc_MlDsaKey_ImportPrivRaw(key, in, inLen);
}
WOLFSSL_DILITHIUM_LEGACY_INLINE
int wc_dilithium_import_key(const byte* priv, word32 privSz, const byte* pub,
                            word32 pubSz, MlDsaKey* key) {
    return wc_MlDsaKey_ImportKey(key, priv, privSz, pub, pubSz);
}
#endif /* WOLFSSL_MLDSA_PRIVATE_KEY */

#ifndef WOLFSSL_MLDSA_VERIFY_ONLY
#ifdef WOLFSSL_MLDSA_NO_CTX
WOLFSSL_DILITHIUM_LEGACY_INLINE
int wc_dilithium_sign_msg(const byte* msg, word32 msgLen, byte* sig,
                          word32* sigLen, MlDsaKey* key, WC_RNG* rng) {
    return wc_MlDsaKey_Sign(key, sig, sigLen, msg, msgLen, rng);
}
WOLFSSL_DILITHIUM_LEGACY_INLINE
int wc_dilithium_sign_msg_with_seed(const byte* msg, word32 msgLen, byte* sig,
                                    word32* sigLen, MlDsaKey* key,
                                    const byte* seed) {
    return wc_MlDsaKey_SignWithSeed(key, sig, sigLen, msg, msgLen, seed);
}
#endif /* WOLFSSL_MLDSA_NO_CTX */
WOLFSSL_DILITHIUM_LEGACY_INLINE
int wc_dilithium_sign_ctx_msg(const byte* ctx, byte ctxLen, const byte* msg,
                              word32 msgLen, byte* sig, word32* sigLen,
                              MlDsaKey* key, WC_RNG* rng) {
    return wc_MlDsaKey_SignCtx(key, ctx, ctxLen, sig, sigLen, msg, msgLen, rng);
}
WOLFSSL_DILITHIUM_LEGACY_INLINE
int wc_dilithium_sign_ctx_hash(const byte* ctx, byte ctxLen, int hashAlg,
                               const byte* hash, word32 hashLen, byte* sig,
                               word32* sigLen, MlDsaKey* key, WC_RNG* rng) {
    return wc_MlDsaKey_SignCtxHash(key, ctx, ctxLen, sig, sigLen, hash,
                                   hashLen, hashAlg, rng);
}
WOLFSSL_DILITHIUM_LEGACY_INLINE
int wc_dilithium_sign_ctx_msg_with_seed(const byte* ctx, byte ctxLen,
                                        const byte* msg, word32 msgLen,
                                        byte* sig, word32* sigLen,
                                        MlDsaKey* key, const byte* seed) {
    return wc_MlDsaKey_SignCtxWithSeed(key, ctx, ctxLen, sig, sigLen, msg,
                                       msgLen, seed);
}
WOLFSSL_DILITHIUM_LEGACY_INLINE
int wc_dilithium_sign_ctx_hash_with_seed(const byte* ctx, byte ctxLen,
                                         int hashAlg, const byte* hash,
                                         word32 hashLen, byte* sig,
                                         word32* sigLen, MlDsaKey* key,
                                         const byte* seed) {
    return wc_MlDsaKey_SignCtxHashWithSeed(key, ctx, ctxLen, sig, sigLen,
                                           hash, hashLen, hashAlg, seed);
}
WOLFSSL_DILITHIUM_LEGACY_INLINE
int wc_dilithium_sign_mu_with_seed(const byte* mu, word32 muLen, byte* sig,
                                   word32* sigLen, MlDsaKey* key,
                                   const byte* seed) {
    return wc_MlDsaKey_SignMuWithSeed(key, sig, sigLen, mu, muLen, seed);
}
#endif /* !WOLFSSL_MLDSA_VERIFY_ONLY */

#ifdef WOLFSSL_MLDSA_NO_CTX
WOLFSSL_DILITHIUM_LEGACY_INLINE
int wc_dilithium_verify_msg(const byte* sig, word32 sigLen, const byte* msg,
                            word32 msgLen, int* res, MlDsaKey* key) {
    return wc_MlDsaKey_Verify(key, sig, sigLen, msg, msgLen, res);
}
#endif /* WOLFSSL_MLDSA_NO_CTX */
WOLFSSL_DILITHIUM_LEGACY_INLINE
int wc_dilithium_verify_ctx_msg(const byte* sig, word32 sigLen, const byte* ctx,
                                byte ctxLen, const byte* msg, word32 msgLen,
                                int* res, MlDsaKey* key) {
    return wc_MlDsaKey_VerifyCtx(key, sig, sigLen, ctx, ctxLen, msg, msgLen,
                                 res);
}
WOLFSSL_DILITHIUM_LEGACY_INLINE
int wc_dilithium_verify_ctx_hash(const byte* sig, word32 sigLen, const byte* ctx,
                                 byte ctxLen, int hashAlg, const byte* hash,
                                 word32 hashLen, int* res, MlDsaKey* key) {
    return wc_MlDsaKey_VerifyCtxHash(key, sig, sigLen, ctx, ctxLen, hash,
                                     hashLen, hashAlg, res);
}
WOLFSSL_DILITHIUM_LEGACY_INLINE
int wc_dilithium_verify_mu(const byte* sig, word32 sigLen, const byte* mu,
                           word32 muLen, int* res, MlDsaKey* key) {
    return wc_MlDsaKey_VerifyMu(key, sig, sigLen, mu, muLen, res);
}

#ifndef WOLFSSL_MLDSA_NO_ASN1
#ifdef WOLFSSL_MLDSA_PRIVATE_KEY
WOLFSSL_DILITHIUM_LEGACY_INLINE
int wc_Dilithium_PrivateKeyDecode(const byte* input, word32* inOutIdx,
                                  MlDsaKey* key, word32 inSz) {
    return wc_MlDsaKey_PrivateKeyDecode(key, input, inSz, inOutIdx);
}
#endif
#ifdef WOLFSSL_MLDSA_PUBLIC_KEY
WOLFSSL_DILITHIUM_LEGACY_INLINE
int wc_Dilithium_PublicKeyDecode(const byte* input, word32* inOutIdx,
                                 MlDsaKey* key, word32 inSz) {
    return wc_MlDsaKey_PublicKeyDecode(key, input, inSz, inOutIdx);
}
#endif
#endif /* !WOLFSSL_MLDSA_NO_ASN1 */

/* Internal-helper aliases. These cover symbols that are *not* part of the
 * public API (WOLFSSL_LOCAL `mldsa_get_oid_sum` and WOLFSSL_TEST_VIS
 * `wc_mldsa_encode_w1_*`); they exist only to keep the unmigrated in-tree
 * consumers building through this shim (src/ssl_load.c for
 * `dilithium_get_oid_sum`, tests/api/test_mldsa.c for the encoders).
 * Application code must not rely on them. These aliases live and die with
 * the rest of the shim and will be removed when it is. */
#define dilithium_get_oid_sum               mldsa_get_oid_sum
#define wc_dilithium_encode_w1_88           wc_mldsa_encode_w1_88
#define wc_dilithium_encode_w1_32           wc_mldsa_encode_w1_32

#endif /* WOLFSSL_HAVE_MLDSA && !WOLFSSL_NO_DILITHIUM_LEGACY_NAMES */

#endif /* WOLF_CRYPT_DILITHIUM_H */
