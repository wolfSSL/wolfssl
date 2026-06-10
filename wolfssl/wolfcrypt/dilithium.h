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
 *   2. Macro aliases for the legacy type and function names (dilithium_key,
 *      wc_dilithium_params, wc_dilithium_*, wc_Dilithium_*) so application code
 *      written against the pre-standardization API keeps compiling. Suppressed
 *      by defining WOLFSSL_NO_DILITHIUM_LEGACY_NAMES.
 *
 *      WOLFSSL_NO_DILITHIUM_LEGACY_NAMES additionally suppresses several
 *      identifier families that share its opt-out gate but are not
 *      defined inside this header:
 *
 *        - `ML_DSA_LEVEL{2,3,5}_TYPE` / `_KEY` / `k`, `CTC_ML_DSA_LEVEL{2,3,5}`
 *          aliases in <wolfssl/wolfcrypt/asn_public.h>,
 *          <wolfssl/wolfcrypt/asn.h>, <wolfssl/wolfcrypt/oid_sum.h>.
 *          These were spelled in ML-DSA form on master but used the
 *          pre-standardization NIST-security-category numbering (2/3/5)
 *          rather than the FIPS 204 parameter-set numbers (44/65/87).
 *
 *        - The `DILITHIUM_KEY_SIZE_E` error-code alias in
 *          <wolfssl/error-ssl.h>.
 *
 *        - The three per-parameter-set size-constant alias families
 *          (`ML_DSA_LEVEL{2,3,5}_*_SIZE`,
 *          `DILITHIUM_LEVEL{2,3,5}_*_SIZE`,
 *          `DILITHIUM_ML_DSA_{44,65,87}_*_SIZE`) defined immediately
 *          below in this header.
 *
 * New code must include <wolfssl/wolfcrypt/wc_mldsa.h> directly and use
 * the wc_MlDsaKey / wc_MlDsaKey_* / WOLFSSL_MLDSA_* names. */

#ifndef WOLF_CRYPT_DILITHIUM_H
#define WOLF_CRYPT_DILITHIUM_H

/* === Sub-config build-gate translations =============================== */

/* The two sub-gates that <wolfssl/certs_test.h> (auto-generated, no
 * #includes) reads -- WOLFSSL_DILITHIUM_NO_SIGN /
 * WOLFSSL_DILITHIUM_NO_VERIFY -- are forward-translated in
 * <wolfssl/wolfcrypt/settings.h> so that header sees the canonical
 * spelling without going through dilithium.h. The block below covers
 * the remaining sub-gates, all of which are read only by wc_mldsa.h /
 * wc_mldsa.c. wc_mldsa.h pulls this file in at its own top (see the
 * #include block in <wolfssl/wolfcrypt/wc_mldsa.h>) so the forward arm
 * fires before wc_mldsa.h reads any canonical gate -- including when
 * wc_mldsa.h is reached transitively via <asn.h> / <asn_public.h>. */

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

/* Developer / performance tuning knobs documented at the top of
 * wolfcrypt/src/wc_mldsa.c. These are user-set in user_settings.h or
 * via -D on the compiler command line; forward-translate so a
 * consumer with the legacy DILITHIUM_* spelling still gets the
 * intended code path. */
#ifdef DEBUG_DILITHIUM
    #ifndef DEBUG_MLDSA
        #define DEBUG_MLDSA
    #endif
#endif
#ifdef DILITHIUM_MUL_SLOW
    #ifndef MLDSA_MUL_SLOW
        #define MLDSA_MUL_SLOW
    #endif
#endif
#ifdef DILITHIUM_MUL_44_SLOW
    #ifndef MLDSA_MUL_44_SLOW
        #define MLDSA_MUL_44_SLOW
    #endif
#endif
#ifdef DILITHIUM_MUL_11_SLOW
    #ifndef MLDSA_MUL_11_SLOW
        #define MLDSA_MUL_11_SLOW
    #endif
#endif
#ifdef DILITHIUM_MUL_QINV_SLOW
    #ifndef MLDSA_MUL_QINV_SLOW
        #define MLDSA_MUL_QINV_SLOW
    #endif
#endif
#ifdef DILITHIUM_MUL_Q_SLOW
    #ifndef MLDSA_MUL_Q_SLOW
        #define MLDSA_MUL_Q_SLOW
    #endif
#endif
#ifdef DILITHIUM_USE_HINT_CT
    #ifndef MLDSA_USE_HINT_CT
        #define MLDSA_USE_HINT_CT
    #endif
#endif

#endif /* !WOLFSSL_NO_DILITHIUM_LEGACY_GATES */

/* === Derived canonical gates ========================================== */

/* Derive secondary canonical gates from the primary NO_* gates. Lives in
 * this file (rather than in wc_mldsa.h alongside the struct definition)
 * so the reverse arm at the bottom of this file sees the derived set
 * fully populated without needing wc_mldsa.h to finish parsing first.
 * wc_mldsa.h includes this file at its top, so by the time control
 * returns from that include the gates are already set and wc_mldsa.h's
 * struct definition / conditional declarations read them directly. */
#if defined(WOLFSSL_HAVE_MLDSA)
#if defined(WOLFSSL_MLDSA_NO_MAKE_KEY) && \
        defined(WOLFSSL_MLDSA_NO_SIGN) && \
        !defined(WOLFSSL_MLDSA_NO_VERIFY) && \
        !defined(WOLFSSL_MLDSA_VERIFY_ONLY)
    #define WOLFSSL_MLDSA_VERIFY_ONLY
#endif
#ifdef WOLFSSL_MLDSA_VERIFY_ONLY
    #ifndef WOLFSSL_MLDSA_NO_MAKE_KEY
        #define WOLFSSL_MLDSA_NO_MAKE_KEY
    #endif
    #ifndef WOLFSSL_MLDSA_NO_SIGN
        #define WOLFSSL_MLDSA_NO_SIGN
    #endif
#endif
#if !defined(WOLFSSL_MLDSA_NO_MAKE_KEY) || \
        !defined(WOLFSSL_MLDSA_NO_VERIFY)
    #define WOLFSSL_MLDSA_PUBLIC_KEY
#endif
#if !defined(WOLFSSL_MLDSA_NO_MAKE_KEY) || \
        !defined(WOLFSSL_MLDSA_NO_SIGN)
    #define WOLFSSL_MLDSA_PRIVATE_KEY
#endif
#if defined(WOLFSSL_MLDSA_PUBLIC_KEY) && \
        defined(WOLFSSL_MLDSA_PRIVATE_KEY) && \
        !defined(WOLFSSL_MLDSA_NO_CHECK_KEY) && \
        !defined(WOLFSSL_MLDSA_CHECK_KEY)
    #define WOLFSSL_MLDSA_CHECK_KEY
#endif
#endif /* WOLFSSL_HAVE_MLDSA */

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

/* Legacy type aliases. The wc_MlDsaKey-related typedefs (dilithium_key,
 * MlDsaKey) live in <wolfssl/wolfcrypt/asn_public.h> so that consumers
 * that include only asn_public.h still see them. The wc_MlDsaParams
 * legacy typedef (MlDsaParams) lives in <wolfssl/wolfcrypt/wc_mldsa.h>
 * alongside the canonical struct definition. */
#define wc_dilithium_params                 wc_MlDsaParams

/* Legacy function aliases - simple symbol redirects. Signature is unchanged
 * vs the canonical name, so a #define is sufficient: call sites and `&name`
 * expressions both expand token-wise to the canonical symbol. Note that
 * `&wc_dilithium_make_key` therefore yields the address of
 * wc_MlDsaKey_MakeKey, NOT a distinct legacy export - consumers using
 * dlsym() or callback tables that key off the legacy spelling will see the
 * canonical name in the resulting pointer. */
#define wc_dilithium_init_ex                wc_MlDsaKey_Init
#ifdef WOLF_PRIVATE_KEY_ID
    #define wc_dilithium_init_id            wc_MlDsaKey_InitId
    #define wc_dilithium_init_label         wc_MlDsaKey_InitLabel
#endif
#ifndef WC_NO_CONSTRUCTORS
    #define wc_dilithium_new                wc_MlDsaKey_New
    #define wc_dilithium_delete             wc_MlDsaKey_Delete
#endif
#define wc_dilithium_free                   wc_MlDsaKey_Free
#define wc_dilithium_set_level              wc_MlDsaKey_SetParams
#define wc_dilithium_get_level              wc_MlDsaKey_GetParams
#ifndef WOLFSSL_MLDSA_VERIFY_ONLY
    #define wc_dilithium_make_key           wc_MlDsaKey_MakeKey
    #define wc_dilithium_make_key_from_seed wc_MlDsaKey_MakeKeyFromSeed
#endif
#ifdef WOLFSSL_MLDSA_PRIVATE_KEY
    #define wc_dilithium_size               wc_MlDsaKey_Size
#endif
#if defined(WOLFSSL_MLDSA_PRIVATE_KEY) && defined(WOLFSSL_MLDSA_PUBLIC_KEY)
    #define wc_dilithium_priv_size          wc_MlDsaKey_PrivSize
#endif
#ifdef WOLFSSL_MLDSA_PUBLIC_KEY
    #define wc_dilithium_pub_size           wc_MlDsaKey_PubSize
#endif
#if !defined(WOLFSSL_MLDSA_NO_SIGN) || !defined(WOLFSSL_MLDSA_NO_VERIFY)
    #define wc_dilithium_sig_size           wc_MlDsaKey_SigSize
#endif
#ifdef WOLFSSL_MLDSA_CHECK_KEY
    #define wc_dilithium_check_key          wc_MlDsaKey_CheckKey
#endif
#ifdef WOLFSSL_MLDSA_PUBLIC_KEY
    #define wc_dilithium_export_public      wc_MlDsaKey_ExportPubRaw
#endif
#ifdef WOLFSSL_MLDSA_PRIVATE_KEY
    #define wc_dilithium_export_private         wc_MlDsaKey_ExportPrivRaw
    #define wc_dilithium_export_private_only    wc_MlDsaKey_ExportPrivRaw
    #define wc_dilithium_export_key             wc_MlDsaKey_ExportKey
#endif
#ifndef WOLFSSL_MLDSA_NO_ASN1
    #ifdef WC_ENABLE_ASYM_KEY_EXPORT
        #define wc_Dilithium_PublicKeyToDer     wc_MlDsaKey_PublicKeyToDer
    #endif
    #ifdef WOLFSSL_MLDSA_PRIVATE_KEY
        #define wc_Dilithium_PrivateKeyToDer    wc_MlDsaKey_PrivateKeyToDer
        #define wc_Dilithium_KeyToDer           wc_MlDsaKey_KeyToDer
    #endif
#endif /* !WOLFSSL_MLDSA_NO_ASN1 */

/* Legacy default-args / arg-reorder wrappers. The legacy form takes the key
 * pointer last (or near last); the FIPS 204 / ML-KEM convention used by the
 * canonical wc_MlDsaKey_* names puts the key first. */

#define wc_dilithium_init(key) \
    wc_MlDsaKey_Init(key, NULL, INVALID_DEVID)
#ifdef WOLFSSL_MLDSA_PUBLIC_KEY
    #define wc_dilithium_import_public(in, inLen, key) wc_MlDsaKey_ImportPubRaw(key, in, inLen)
#endif
#ifdef WOLFSSL_MLDSA_PRIVATE_KEY
    #define wc_dilithium_import_private(priv, privSz, key) \
        wc_MlDsaKey_ImportPrivRaw(key, priv, privSz)
    #define wc_dilithium_import_private_only(in, inLen, key) \
        wc_MlDsaKey_ImportPrivRaw(key, in, inLen)
    #define wc_dilithium_import_key(priv, privSz, pub, pubSz, key) \
        wc_MlDsaKey_ImportKey(key, priv, privSz, pub, pubSz)
#endif /* WOLFSSL_MLDSA_PRIVATE_KEY */
#ifndef WOLFSSL_MLDSA_VERIFY_ONLY
    #ifdef WOLFSSL_MLDSA_NO_CTX
        #define wc_dilithium_sign_msg(msg, msgLen, sig, sigLen, key, rng) \
            wc_MlDsaKey_Sign(key, sig, sigLen, msg, msgLen, rng)
        #define wc_dilithium_sign_msg_with_seed(msg, msgLen, sig, sigLen, key, seed) \
            wc_MlDsaKey_SignWithSeed(key, sig, sigLen, msg, msgLen, seed)
    #endif /* WOLFSSL_MLDSA_NO_CTX */
    #define wc_dilithium_sign_ctx_msg(ctx, ctxLen, msg, msgLen, sig, sigLen, key, rng) \
        wc_MlDsaKey_SignCtx(key, ctx, ctxLen, sig, sigLen, msg, msgLen, rng)
    #define wc_dilithium_sign_ctx_hash(ctx, ctxLen, hashAlg, hash, hashLen, sig, sigLen, key, rng) \
        wc_MlDsaKey_SignCtxHash(key, ctx, ctxLen, sig, sigLen, hash, hashLen, hashAlg, rng)
    #define wc_dilithium_sign_ctx_msg_with_seed(ctx, ctxLen, msg, msgLen, sig, sigLen, key, seed) \
        wc_MlDsaKey_SignCtxWithSeed(key, ctx, ctxLen, sig, sigLen, msg, msgLen, seed)
    #define wc_dilithium_sign_ctx_hash_with_seed(ctx, ctxLen, hashAlg, hash, hashLen, sig, sigLen, key, seed) \
        wc_MlDsaKey_SignCtxHashWithSeed(key, ctx, ctxLen, sig, sigLen, hash, hashLen, hashAlg, seed)
    #define wc_dilithium_sign_mu_with_seed(mu, muLen, sig, sigLen, key, seed) \
        wc_MlDsaKey_SignMuWithSeed(key, sig, sigLen, mu, muLen, seed)
#endif /* !WOLFSSL_MLDSA_VERIFY_ONLY */
#ifdef WOLFSSL_MLDSA_NO_CTX
    #define wc_dilithium_verify_msg(sig, sigLen, msg, msgLen, res, key) \
        wc_MlDsaKey_Verify(key, sig, sigLen, msg, msgLen, res)
#endif /* WOLFSSL_MLDSA_NO_CTX */
#define wc_dilithium_verify_ctx_msg(sig, sigLen, ctx, ctxLen, msg, msgLen, res, key) \
    wc_MlDsaKey_VerifyCtx(key, sig, sigLen, ctx, ctxLen, msg, msgLen, res)
#define wc_dilithium_verify_ctx_hash(sig, sigLen, ctx, ctxLen, hashAlg, hash, hashLen, res, key) \
    wc_MlDsaKey_VerifyCtxHash(key, sig, sigLen, ctx, ctxLen, hash, hashLen, hashAlg, res)
#define wc_dilithium_verify_mu(sig, sigLen, mu, muLen, res, key) \
    wc_MlDsaKey_VerifyMu(key, sig, sigLen, mu, muLen, res)
#ifndef WOLFSSL_MLDSA_NO_ASN1
    #ifdef WOLFSSL_MLDSA_PRIVATE_KEY
        #define wc_Dilithium_PrivateKeyDecode(input, inOutIdx, key, inSz) \
            wc_MlDsaKey_PrivateKeyDecode(key, input, inSz, inOutIdx)
    #endif
    #ifdef WOLFSSL_MLDSA_PUBLIC_KEY
        #define wc_Dilithium_PublicKeyDecode(input, inOutIdx, key, inSz) \
            wc_MlDsaKey_PublicKeyDecode(key, input, inSz, inOutIdx)
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

/* Legacy parameter / size macros. wc_mldsa.h now defines the canonical
 * MLDSA_* spellings; these aliases keep the pre-standardization
 * DILITHIUM_* names reachable for unmigrated in-tree consumers
 * (wolfcrypt/src/asn.c, src/ssl_load.c, src/internal.c, src/tls13.c,
 * src/ssl.c, src/x509.c, src/ssl_api_pk.c, src/ssl_certman.c,
 * wolfssl/internal.h, wolfssl/wolfcrypt/asn.h, asn_public.h,
 * oid_sum.h, examples/configs/user_settings_pq.h,
 * wolfcrypt/benchmark/benchmark.c, wolfcrypt/test/test.c,
 * tests/api/test_mldsa.c) and for downstream code. The DILITHIUM_ML_DSA_NN_*
 * spellings collapse to MLDSA_NN_* (the intermediate _ML_DSA_ is
 * redundant once the outer prefix is MLDSA_; the resulting MLDSA_44 /
 * _65 / _87 names match the FIPS 204 parameter-set spellings). */

/* Algorithm parameters (FIPS 204 Section 4) */
#define DILITHIUM_Q                         MLDSA_Q
#define DILITHIUM_Q_BITS                    MLDSA_Q_BITS
#define DILITHIUM_N                         MLDSA_N
#define DILITHIUM_D                         MLDSA_D
#define DILITHIUM_D_MAX                     MLDSA_D_MAX
#define DILITHIUM_D_MAX_HALF                MLDSA_D_MAX_HALF
#define DILITHIUM_U                         MLDSA_U
#define DILITHIUM_GAMMA1_17                 MLDSA_GAMMA1_17
#define DILITHIUM_GAMMA1_19                 MLDSA_GAMMA1_19
#define DILITHIUM_GAMMA1_BITS_17            MLDSA_GAMMA1_BITS_17
#define DILITHIUM_GAMMA1_BITS_19            MLDSA_GAMMA1_BITS_19
#define DILITHIUM_GAMMA1_17_ENC_BITS        MLDSA_GAMMA1_17_ENC_BITS
#define DILITHIUM_GAMMA1_19_ENC_BITS        MLDSA_GAMMA1_19_ENC_BITS
#define DILITHIUM_Q_LOW_32                  MLDSA_Q_LOW_32
#define DILITHIUM_Q_LOW_32_2                MLDSA_Q_LOW_32_2
#define DILITHIUM_Q_LOW_88                  MLDSA_Q_LOW_88
#define DILITHIUM_Q_LOW_88_2                MLDSA_Q_LOW_88_2
#define DILITHIUM_Q_HI_32_ENC_BITS          MLDSA_Q_HI_32_ENC_BITS
#define DILITHIUM_Q_HI_88_ENC_BITS          MLDSA_Q_HI_88_ENC_BITS
#define DILITHIUM_ETA_2                     MLDSA_ETA_2
#define DILITHIUM_ETA_2_BITS                MLDSA_ETA_2_BITS
#define DILITHIUM_ETA_2_MOD                 MLDSA_ETA_2_MOD
#define DILITHIUM_ETA_4                     MLDSA_ETA_4
#define DILITHIUM_ETA_4_BITS                MLDSA_ETA_4_BITS
#define DILITHIUM_ETA_4_MOD                 MLDSA_ETA_4_MOD
#define DILITHIUM_POLY_SIZE                 MLDSA_POLY_SIZE
#define DILITHIUM_REJ_NTT_POLY_H_SIZE       MLDSA_REJ_NTT_POLY_H_SIZE

/* Seed / label / hash sizes */
#define DILITHIUM_PUB_SEED_SZ               MLDSA_PUB_SEED_SZ
#define DILITHIUM_PRIV_SEED_SZ              MLDSA_PRIV_SEED_SZ
#define DILITHIUM_PRIV_RAND_SEED_SZ         MLDSA_PRIV_RAND_SEED_SZ
#define DILITHIUM_SEED_SZ                   MLDSA_SEED_SZ
#define DILITHIUM_SEEDS_SZ                  MLDSA_SEEDS_SZ
#define DILITHIUM_K_SZ                      MLDSA_K_SZ
#define DILITHIUM_TR_SZ                     MLDSA_TR_SZ
#define DILITHIUM_MU_SZ                     MLDSA_MU_SZ
#define DILITHIUM_RND_SZ                    MLDSA_RND_SZ

/* ExpandA / ExpandS sampling block constants (FIPS 204 Section 8.4) */
#define DILITHIUM_GEN_A_BLOCK_BYTES         MLDSA_GEN_A_BLOCK_BYTES
#define DILITHIUM_GEN_A_BYTES               MLDSA_GEN_A_BYTES
#define DILITHIUM_GEN_A_NBLOCKS             MLDSA_GEN_A_NBLOCKS
#define DILITHIUM_GEN_C_BLOCK_BYTES         MLDSA_GEN_C_BLOCK_BYTES

/* Per-parameter-set sizes. The canonical spelling in
 * <wolfssl/wolfcrypt/wc_mldsa.h> is WC_MLDSA_{44,65,87}_*_SIZE. The
 * aliases below keep three legacy spelling families reachable for
 * unmigrated consumers:
 *   - "LEVEL2/3/5" forms (`ML_DSA_LEVEL2_KEY_SIZE`,
 *     `DILITHIUM_LEVEL2_KEY_SIZE`) - the three NIST security
 *     categories (2 / 3 / 5).
 *   - The pre-standardization `DILITHIUM_ML_DSA_44_*` form. */

/* LEVEL2 (= ML-DSA-44) */
#define ML_DSA_LEVEL2_KEY_SIZE              WC_MLDSA_44_KEY_SIZE
#define ML_DSA_LEVEL2_PRV_KEY_SIZE          WC_MLDSA_44_PRV_KEY_SIZE
#define ML_DSA_LEVEL2_PUB_KEY_SIZE          WC_MLDSA_44_PUB_KEY_SIZE
#define ML_DSA_LEVEL2_SIG_SIZE              WC_MLDSA_44_SIG_SIZE
#define ML_DSA_LEVEL2_PRV_KEY_DER_SIZE      WC_MLDSA_44_PRV_KEY_DER_SIZE
#define ML_DSA_LEVEL2_PUB_KEY_DER_SIZE      WC_MLDSA_44_PUB_KEY_DER_SIZE
#define ML_DSA_LEVEL2_BOTH_KEY_DER_SIZE     WC_MLDSA_44_BOTH_KEY_DER_SIZE
#define ML_DSA_LEVEL2_BOTH_KEY_PEM_SIZE     WC_MLDSA_44_BOTH_KEY_PEM_SIZE
#define DILITHIUM_LEVEL2_KEY_SIZE           WC_MLDSA_44_KEY_SIZE
#define DILITHIUM_LEVEL2_PRV_KEY_SIZE       WC_MLDSA_44_PRV_KEY_SIZE
#define DILITHIUM_LEVEL2_PUB_KEY_SIZE       WC_MLDSA_44_PUB_KEY_SIZE
#define DILITHIUM_LEVEL2_SIG_SIZE           WC_MLDSA_44_SIG_SIZE
#define DILITHIUM_LEVEL2_PRV_KEY_DER_SIZE   WC_MLDSA_44_PRV_KEY_DER_SIZE
#define DILITHIUM_LEVEL2_PUB_KEY_DER_SIZE   WC_MLDSA_44_PUB_KEY_DER_SIZE
#define DILITHIUM_LEVEL2_BOTH_KEY_DER_SIZE  WC_MLDSA_44_BOTH_KEY_DER_SIZE
#define DILITHIUM_LEVEL2_BOTH_KEY_PEM_SIZE  WC_MLDSA_44_BOTH_KEY_PEM_SIZE

/* LEVEL3 (= ML-DSA-65) */
#define ML_DSA_LEVEL3_KEY_SIZE              WC_MLDSA_65_KEY_SIZE
#define ML_DSA_LEVEL3_PRV_KEY_SIZE          WC_MLDSA_65_PRV_KEY_SIZE
#define ML_DSA_LEVEL3_PUB_KEY_SIZE          WC_MLDSA_65_PUB_KEY_SIZE
#define ML_DSA_LEVEL3_SIG_SIZE              WC_MLDSA_65_SIG_SIZE
#define ML_DSA_LEVEL3_PRV_KEY_DER_SIZE      WC_MLDSA_65_PRV_KEY_DER_SIZE
#define ML_DSA_LEVEL3_PUB_KEY_DER_SIZE      WC_MLDSA_65_PUB_KEY_DER_SIZE
#define ML_DSA_LEVEL3_BOTH_KEY_DER_SIZE     WC_MLDSA_65_BOTH_KEY_DER_SIZE
#define ML_DSA_LEVEL3_BOTH_KEY_PEM_SIZE     WC_MLDSA_65_BOTH_KEY_PEM_SIZE
#define DILITHIUM_LEVEL3_KEY_SIZE           WC_MLDSA_65_KEY_SIZE
#define DILITHIUM_LEVEL3_PRV_KEY_SIZE       WC_MLDSA_65_PRV_KEY_SIZE
#define DILITHIUM_LEVEL3_PUB_KEY_SIZE       WC_MLDSA_65_PUB_KEY_SIZE
#define DILITHIUM_LEVEL3_SIG_SIZE           WC_MLDSA_65_SIG_SIZE
#define DILITHIUM_LEVEL3_PRV_KEY_DER_SIZE   WC_MLDSA_65_PRV_KEY_DER_SIZE
#define DILITHIUM_LEVEL3_PUB_KEY_DER_SIZE   WC_MLDSA_65_PUB_KEY_DER_SIZE
#define DILITHIUM_LEVEL3_BOTH_KEY_DER_SIZE  WC_MLDSA_65_BOTH_KEY_DER_SIZE
#define DILITHIUM_LEVEL3_BOTH_KEY_PEM_SIZE  WC_MLDSA_65_BOTH_KEY_PEM_SIZE

/* LEVEL5 (= ML-DSA-87) */
#define ML_DSA_LEVEL5_KEY_SIZE              WC_MLDSA_87_KEY_SIZE
#define ML_DSA_LEVEL5_PRV_KEY_SIZE          WC_MLDSA_87_PRV_KEY_SIZE
#define ML_DSA_LEVEL5_PUB_KEY_SIZE          WC_MLDSA_87_PUB_KEY_SIZE
#define ML_DSA_LEVEL5_SIG_SIZE              WC_MLDSA_87_SIG_SIZE
#define ML_DSA_LEVEL5_PRV_KEY_DER_SIZE      WC_MLDSA_87_PRV_KEY_DER_SIZE
#define ML_DSA_LEVEL5_PUB_KEY_DER_SIZE      WC_MLDSA_87_PUB_KEY_DER_SIZE
#define ML_DSA_LEVEL5_BOTH_KEY_DER_SIZE     WC_MLDSA_87_BOTH_KEY_DER_SIZE
#define ML_DSA_LEVEL5_BOTH_KEY_PEM_SIZE     WC_MLDSA_87_BOTH_KEY_PEM_SIZE
#define DILITHIUM_LEVEL5_KEY_SIZE           WC_MLDSA_87_KEY_SIZE
#define DILITHIUM_LEVEL5_PRV_KEY_SIZE       WC_MLDSA_87_PRV_KEY_SIZE
#define DILITHIUM_LEVEL5_PUB_KEY_SIZE       WC_MLDSA_87_PUB_KEY_SIZE
#define DILITHIUM_LEVEL5_SIG_SIZE           WC_MLDSA_87_SIG_SIZE
#define DILITHIUM_LEVEL5_PRV_KEY_DER_SIZE   WC_MLDSA_87_PRV_KEY_DER_SIZE
#define DILITHIUM_LEVEL5_PUB_KEY_DER_SIZE   WC_MLDSA_87_PUB_KEY_DER_SIZE
#define DILITHIUM_LEVEL5_BOTH_KEY_DER_SIZE  WC_MLDSA_87_BOTH_KEY_DER_SIZE
#define DILITHIUM_LEVEL5_BOTH_KEY_PEM_SIZE  WC_MLDSA_87_BOTH_KEY_PEM_SIZE

/* Pre-standardization DILITHIUM_ML_DSA_NN_* spelling. */
#define DILITHIUM_ML_DSA_44_KEY_SIZE        WC_MLDSA_44_KEY_SIZE
#define DILITHIUM_ML_DSA_44_PRV_KEY_SIZE    WC_MLDSA_44_PRV_KEY_SIZE
#define DILITHIUM_ML_DSA_44_PUB_KEY_SIZE    WC_MLDSA_44_PUB_KEY_SIZE
#define DILITHIUM_ML_DSA_44_SIG_SIZE        WC_MLDSA_44_SIG_SIZE
#define DILITHIUM_ML_DSA_65_KEY_SIZE        WC_MLDSA_65_KEY_SIZE
#define DILITHIUM_ML_DSA_65_PRV_KEY_SIZE    WC_MLDSA_65_PRV_KEY_SIZE
#define DILITHIUM_ML_DSA_65_PUB_KEY_SIZE    WC_MLDSA_65_PUB_KEY_SIZE
#define DILITHIUM_ML_DSA_65_SIG_SIZE        WC_MLDSA_65_SIG_SIZE
#define DILITHIUM_ML_DSA_87_KEY_SIZE        WC_MLDSA_87_KEY_SIZE
#define DILITHIUM_ML_DSA_87_PRV_KEY_SIZE    WC_MLDSA_87_PRV_KEY_SIZE
#define DILITHIUM_ML_DSA_87_PUB_KEY_SIZE    WC_MLDSA_87_PUB_KEY_SIZE
#define DILITHIUM_ML_DSA_87_SIG_SIZE        WC_MLDSA_87_SIG_SIZE

/* Maxima (largest value across the three parameter sets, used for
 * stack/heap sizing) */
#define DILITHIUM_MAX_KEY_SIZE              MLDSA_MAX_KEY_SIZE
#define DILITHIUM_MAX_PRV_KEY_SIZE          MLDSA_MAX_PRV_KEY_SIZE
#define DILITHIUM_MAX_PUB_KEY_SIZE          MLDSA_MAX_PUB_KEY_SIZE
#define DILITHIUM_MAX_SIG_SIZE              MLDSA_MAX_SIG_SIZE
#define DILITHIUM_MAX_PRV_KEY_DER_SIZE      MLDSA_MAX_PRV_KEY_DER_SIZE
#define DILITHIUM_MAX_PUB_KEY_DER_SIZE      MLDSA_MAX_PUB_KEY_DER_SIZE
#define DILITHIUM_MAX_BOTH_KEY_DER_SIZE     MLDSA_MAX_BOTH_KEY_DER_SIZE
#define DILITHIUM_MAX_BOTH_KEY_PEM_SIZE     MLDSA_MAX_BOTH_KEY_PEM_SIZE
#ifdef WOLF_PRIVATE_KEY_ID
    #define DILITHIUM_MAX_LABEL_LEN         MLDSA_MAX_LABEL_LEN
    #define DILITHIUM_MAX_ID_LEN            MLDSA_MAX_ID_LEN
#endif
#define DILITHIUM_MAX_LAMBDA                MLDSA_MAX_LAMBDA
#define DILITHIUM_MAX_K_VECTOR_COUNT        MLDSA_MAX_K_VECTOR_COUNT
#define DILITHIUM_MAX_L_VECTOR_COUNT        MLDSA_MAX_L_VECTOR_COUNT
#define DILITHIUM_MAX_MATRIX_COUNT          MLDSA_MAX_MATRIX_COUNT
#define DILITHIUM_MAX_W1_ENC_SZ             MLDSA_MAX_W1_ENC_SZ


#endif /* WOLFSSL_HAVE_MLDSA && !WOLFSSL_NO_DILITHIUM_LEGACY_NAMES */

#endif /* WOLF_CRYPT_DILITHIUM_H */
