/* test_mldsa_legacy.c
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

/* Coverage for the temporary Dilithium -> ML-DSA legacy-name shim
 * (<wolfssl/wolfcrypt/dilithium.h>). The shim is purely a set of
 * #define aliases and typedef redirects; correctness reduces to:
 *
 *   1. every legacy name resolves to the canonical symbol / value, and
 *   2. the arg-reordering wrappers dispatch to the canonical function
 *      with the arguments in the right slots.
 *
 * This file exercises both axes:
 *
 *   - Compile-time: wc_static_assert checks every per-level size-constant
 *     spelling and every public-enum alias against the canonical value;
 *     typed function-pointer assignments (no casts) verify every
 *     symbol-form alias has the canonical signature; a never-called
 *     `if (0)` block invokes every arg-reordering macro with correctly
 *     typed dummy arguments so the compiler type-checks the expanded
 *     canonical call.
 *
 *   - Runtime: a single make-key / sign / verify / export / import /
 *     DER round-trip drives the arg-reordering macros with valid inputs,
 *     so a same-type arg swap (which the compile-time invocation can't
 *     catch) shows up as a verification or import failure.
 *
 * Functional coverage of the canonical ML-DSA API itself lives in
 * tests/api/test_mldsa.c (~24 test_mldsa_* functions),
 * wolfcrypt/test/test.c::mldsa_test, and the TLS / X.509 paths in
 * tests/api.c that exercise ML-DSA end-to-end; this file is solely a
 * regression net for the shim. When WOLFSSL_NO_DILITHIUM_LEGACY_NAMES
 * is defined every test below becomes a TEST_SKIPPED stub.
 *
 * Note on verify-only builds: the runtime smoke test below requires the
 * sign side too (to produce a signature against a freshly-made key).
 * In a verify-only build the compile-time invocation block still drives
 * every verify-side shim macro through its arg-reordering expansion, so
 * signature / arg-count regressions are caught at compile time even
 * without a KAT-driven runtime verify. A same-type arg swap on the
 * verify side specifically (e.g. swapping the two `const byte*` /
 * `word32` pairs in `wc_dilithium_verify_ctx_msg`) would not be caught
 * in a verify-only build by this file alone; the canonical KAT-driven
 * tests in test_mldsa.c::test_mldsa_verify_*_kats cover that case in
 * builds that include the canonical headers (which all in-tree builds
 * do). */

#include <tests/unit.h>

#include <wolfssl/wolfcrypt/asn_public.h>
#ifdef WOLFSSL_HAVE_MLDSA
    #include <wolfssl/wolfcrypt/dilithium.h>
    #include <wolfssl/wolfcrypt/wc_mldsa.h>
#endif
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_mldsa.h>

#if defined(WOLFSSL_HAVE_MLDSA) && !defined(WOLFSSL_NO_DILITHIUM_LEGACY_NAMES)

/* === Compile-time checks =============================================== */

/* Type aliases collapse to the canonical struct. A sizeof-equality check is
 * a sufficient and portable proxy for "same type": both legacy spellings
 * are typedefs of `struct wc_MlDsaKey`, so any divergence in the typedef
 * chain would change sizeof and trip the assert at compile time. */
wc_static_assert(sizeof(dilithium_key) == sizeof(wc_MlDsaKey));
wc_static_assert(sizeof(MlDsaKey)      == sizeof(wc_MlDsaKey));
wc_static_assert(sizeof(wc_dilithium_params) == sizeof(wc_MlDsaParams));

/* Per-parameter-set size constants. Every spelling family (LEVEL{2,3,5}_*,
 * DILITHIUM_LEVEL{2,3,5}_*, DILITHIUM_ML_DSA_{44,65,87}_*) lives in its own
 * `#define` line in <dilithium.h>, so each is checked separately. */
#define MLDSA_LEGACY_SIZE_ASSERT(LEGACY, CANONICAL) \
    wc_static_assert((LEGACY) == (CANONICAL))

/* LEVEL2 = ML-DSA-44 */
MLDSA_LEGACY_SIZE_ASSERT(ML_DSA_LEVEL2_KEY_SIZE,           WC_MLDSA_44_KEY_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(ML_DSA_LEVEL2_PRV_KEY_SIZE,       WC_MLDSA_44_PRV_KEY_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(ML_DSA_LEVEL2_PUB_KEY_SIZE,       WC_MLDSA_44_PUB_KEY_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(ML_DSA_LEVEL2_SIG_SIZE,           WC_MLDSA_44_SIG_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(ML_DSA_LEVEL2_PRV_KEY_DER_SIZE,   WC_MLDSA_44_PRV_KEY_DER_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(ML_DSA_LEVEL2_PUB_KEY_DER_SIZE,   WC_MLDSA_44_PUB_KEY_DER_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(ML_DSA_LEVEL2_BOTH_KEY_DER_SIZE,  WC_MLDSA_44_BOTH_KEY_DER_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(ML_DSA_LEVEL2_BOTH_KEY_PEM_SIZE,  WC_MLDSA_44_BOTH_KEY_PEM_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_LEVEL2_KEY_SIZE,        WC_MLDSA_44_KEY_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_LEVEL2_PRV_KEY_SIZE,    WC_MLDSA_44_PRV_KEY_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_LEVEL2_PUB_KEY_SIZE,    WC_MLDSA_44_PUB_KEY_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_LEVEL2_SIG_SIZE,        WC_MLDSA_44_SIG_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_LEVEL2_PRV_KEY_DER_SIZE,WC_MLDSA_44_PRV_KEY_DER_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_LEVEL2_PUB_KEY_DER_SIZE,WC_MLDSA_44_PUB_KEY_DER_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_LEVEL2_BOTH_KEY_DER_SIZE,WC_MLDSA_44_BOTH_KEY_DER_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_LEVEL2_BOTH_KEY_PEM_SIZE,WC_MLDSA_44_BOTH_KEY_PEM_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_ML_DSA_44_KEY_SIZE,     WC_MLDSA_44_KEY_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_ML_DSA_44_PRV_KEY_SIZE, WC_MLDSA_44_PRV_KEY_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_ML_DSA_44_PUB_KEY_SIZE, WC_MLDSA_44_PUB_KEY_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_ML_DSA_44_SIG_SIZE,     WC_MLDSA_44_SIG_SIZE);

/* LEVEL3 = ML-DSA-65 */
MLDSA_LEGACY_SIZE_ASSERT(ML_DSA_LEVEL3_KEY_SIZE,           WC_MLDSA_65_KEY_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(ML_DSA_LEVEL3_PRV_KEY_SIZE,       WC_MLDSA_65_PRV_KEY_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(ML_DSA_LEVEL3_PUB_KEY_SIZE,       WC_MLDSA_65_PUB_KEY_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(ML_DSA_LEVEL3_SIG_SIZE,           WC_MLDSA_65_SIG_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(ML_DSA_LEVEL3_PRV_KEY_DER_SIZE,   WC_MLDSA_65_PRV_KEY_DER_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(ML_DSA_LEVEL3_PUB_KEY_DER_SIZE,   WC_MLDSA_65_PUB_KEY_DER_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(ML_DSA_LEVEL3_BOTH_KEY_DER_SIZE,  WC_MLDSA_65_BOTH_KEY_DER_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(ML_DSA_LEVEL3_BOTH_KEY_PEM_SIZE,  WC_MLDSA_65_BOTH_KEY_PEM_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_LEVEL3_KEY_SIZE,        WC_MLDSA_65_KEY_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_LEVEL3_PRV_KEY_SIZE,    WC_MLDSA_65_PRV_KEY_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_LEVEL3_PUB_KEY_SIZE,    WC_MLDSA_65_PUB_KEY_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_LEVEL3_SIG_SIZE,        WC_MLDSA_65_SIG_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_LEVEL3_PRV_KEY_DER_SIZE,WC_MLDSA_65_PRV_KEY_DER_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_LEVEL3_PUB_KEY_DER_SIZE,WC_MLDSA_65_PUB_KEY_DER_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_LEVEL3_BOTH_KEY_DER_SIZE,WC_MLDSA_65_BOTH_KEY_DER_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_LEVEL3_BOTH_KEY_PEM_SIZE,WC_MLDSA_65_BOTH_KEY_PEM_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_ML_DSA_65_KEY_SIZE,     WC_MLDSA_65_KEY_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_ML_DSA_65_PRV_KEY_SIZE, WC_MLDSA_65_PRV_KEY_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_ML_DSA_65_PUB_KEY_SIZE, WC_MLDSA_65_PUB_KEY_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_ML_DSA_65_SIG_SIZE,     WC_MLDSA_65_SIG_SIZE);

/* LEVEL5 = ML-DSA-87 */
MLDSA_LEGACY_SIZE_ASSERT(ML_DSA_LEVEL5_KEY_SIZE,           WC_MLDSA_87_KEY_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(ML_DSA_LEVEL5_PRV_KEY_SIZE,       WC_MLDSA_87_PRV_KEY_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(ML_DSA_LEVEL5_PUB_KEY_SIZE,       WC_MLDSA_87_PUB_KEY_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(ML_DSA_LEVEL5_SIG_SIZE,           WC_MLDSA_87_SIG_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(ML_DSA_LEVEL5_PRV_KEY_DER_SIZE,   WC_MLDSA_87_PRV_KEY_DER_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(ML_DSA_LEVEL5_PUB_KEY_DER_SIZE,   WC_MLDSA_87_PUB_KEY_DER_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(ML_DSA_LEVEL5_BOTH_KEY_DER_SIZE,  WC_MLDSA_87_BOTH_KEY_DER_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(ML_DSA_LEVEL5_BOTH_KEY_PEM_SIZE,  WC_MLDSA_87_BOTH_KEY_PEM_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_LEVEL5_KEY_SIZE,        WC_MLDSA_87_KEY_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_LEVEL5_PRV_KEY_SIZE,    WC_MLDSA_87_PRV_KEY_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_LEVEL5_PUB_KEY_SIZE,    WC_MLDSA_87_PUB_KEY_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_LEVEL5_SIG_SIZE,        WC_MLDSA_87_SIG_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_LEVEL5_PRV_KEY_DER_SIZE,WC_MLDSA_87_PRV_KEY_DER_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_LEVEL5_PUB_KEY_DER_SIZE,WC_MLDSA_87_PUB_KEY_DER_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_LEVEL5_BOTH_KEY_DER_SIZE,WC_MLDSA_87_BOTH_KEY_DER_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_LEVEL5_BOTH_KEY_PEM_SIZE,WC_MLDSA_87_BOTH_KEY_PEM_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_ML_DSA_87_KEY_SIZE,     WC_MLDSA_87_KEY_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_ML_DSA_87_PRV_KEY_SIZE, WC_MLDSA_87_PRV_KEY_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_ML_DSA_87_PUB_KEY_SIZE, WC_MLDSA_87_PUB_KEY_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_ML_DSA_87_SIG_SIZE,     WC_MLDSA_87_SIG_SIZE);

/* Maxima (used as stack/heap sizing on the call sites). */
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_MAX_KEY_SIZE,           MLDSA_MAX_KEY_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_MAX_PRV_KEY_SIZE,       MLDSA_MAX_PRV_KEY_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_MAX_PUB_KEY_SIZE,       MLDSA_MAX_PUB_KEY_SIZE);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_MAX_SIG_SIZE,           MLDSA_MAX_SIG_SIZE);

/* FIPS 204 algorithm-parameter constants -- spot-check the families that
 * exist as both DILITHIUM_* and MLDSA_* spellings. */
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_Q,                      MLDSA_Q);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_N,                      MLDSA_N);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_SEED_SZ,                MLDSA_SEED_SZ);
MLDSA_LEGACY_SIZE_ASSERT(DILITHIUM_TR_SZ,                  MLDSA_TR_SZ);

#undef MLDSA_LEGACY_SIZE_ASSERT

/* Public-enum aliases (asn_public.h / asn.h / oid_sum.h). These are
 * #define aliases for FIPS 204 enumerators that were renamed in this
 * PR; the legacy LEVEL{2,3,5} spellings live behind the same
 * WOLFSSL_NO_DILITHIUM_LEGACY_NAMES gate as the dilithium.h shim. Casts
 * are deliberately omitted: enum constants are integer constant
 * expressions in C, and a hidden enum-width divergence is itself a
 * regression worth surfacing. */
wc_static_assert(ML_DSA_LEVEL2_TYPE == ML_DSA_44_TYPE);
wc_static_assert(ML_DSA_LEVEL3_TYPE == ML_DSA_65_TYPE);
wc_static_assert(ML_DSA_LEVEL5_TYPE == ML_DSA_87_TYPE);
#ifdef WOLFSSL_CERT_GEN
wc_static_assert(ML_DSA_LEVEL2_KEY  == ML_DSA_44_KEY);
wc_static_assert(ML_DSA_LEVEL3_KEY  == ML_DSA_65_KEY);
wc_static_assert(ML_DSA_LEVEL5_KEY  == ML_DSA_87_KEY);
#endif
wc_static_assert(ML_DSA_LEVEL2k     == ML_DSA_44k);
wc_static_assert(ML_DSA_LEVEL3k     == ML_DSA_65k);
wc_static_assert(ML_DSA_LEVEL5k     == ML_DSA_87k);
wc_static_assert(CTC_ML_DSA_LEVEL2  == CTC_ML_DSA_44);
wc_static_assert(CTC_ML_DSA_LEVEL3  == CTC_ML_DSA_65);
wc_static_assert(CTC_ML_DSA_LEVEL5  == CTC_ML_DSA_87);

/* Error-code rename: the symbol stays at the same numeric value, and the
 * legacy spelling is a #define for the canonical enumerator. */
wc_static_assert(WC_NO_ERR_TRACE(DILITHIUM_KEY_SIZE_E) ==
                 WC_NO_ERR_TRACE(MLDSA_KEY_SIZE_E));

/* Function-symbol aliases. Each entry below is a #define legacy canonical
 * (a pure symbol redirect, no arg reordering). Assigning to a typed
 * function pointer **without a cast** is the actual check: the compiler
 * fails the build if the alias's signature drifts from the typedef. The
 * casts are deliberately absent -- adding them would silently coerce
 * signature mismatches and defeat the purpose. */
static void mldsa_legacy_shim_symbol_aliases_compile_check(void)
{
    typedef int  (*size_fn)(wc_MlDsaKey*);
    typedef int  (*check_fn)(wc_MlDsaKey*);
    typedef int  (*export_fn)(wc_MlDsaKey*, byte*, word32*);

#ifdef WOLFSSL_MLDSA_PRIVATE_KEY
    {
        size_fn   f_size        = &wc_dilithium_size;
        export_fn f_export_priv = &wc_dilithium_export_private;
        (void)f_size; (void)f_export_priv;
    #ifdef WOLFSSL_MLDSA_PUBLIC_KEY
        {
            size_fn f_priv_size = &wc_dilithium_priv_size;
            (void)f_priv_size;
        }
    #endif
    }
#endif
#ifdef WOLFSSL_MLDSA_PUBLIC_KEY
    {
        size_fn   f_pub_size   = &wc_dilithium_pub_size;
        export_fn f_export_pub = &wc_dilithium_export_public;
        (void)f_pub_size; (void)f_export_pub;
    }
#endif

#ifdef WOLFSSL_MLDSA_CHECK_KEY
    {
        check_fn f_check = &wc_dilithium_check_key;
        (void)f_check;
    }
#else
    (void)((check_fn)NULL);
#endif

#ifdef WOLF_PRIVATE_KEY_ID
    {
        typedef int (*init_id_fn)(wc_MlDsaKey*, const unsigned char*, int,
            void*, int);
        typedef int (*init_label_fn)(wc_MlDsaKey*, const char*, void*, int);
        init_id_fn    f_init_id    = &wc_dilithium_init_id;
        init_label_fn f_init_label = &wc_dilithium_init_label;
        (void)f_init_id; (void)f_init_label;
    }
#endif

#if !defined(WOLFSSL_MLDSA_NO_ASN1)
    {
    #ifdef WC_ENABLE_ASYM_KEY_EXPORT
        {
            typedef int (*to_der_fn)(wc_MlDsaKey*, byte*, word32, int);
            to_der_fn f_pub_to_der = &wc_Dilithium_PublicKeyToDer;
            (void)f_pub_to_der;
        }
    #endif
    #ifdef WOLFSSL_MLDSA_PRIVATE_KEY
        {
            typedef int (*to_der_priv_fn)(wc_MlDsaKey*, byte*, word32);
            to_der_priv_fn f_priv_to_der = &wc_Dilithium_PrivateKeyToDer;
            to_der_priv_fn f_key_to_der  = &wc_Dilithium_KeyToDer;
            (void)f_priv_to_der; (void)f_key_to_der;
        }
    #endif
    }
#endif
}

/* Compile-time invocation of every arg-reordering shim macro. The macros
 * are function-like #defines, so they can only be checked by expansion at
 * a call site. The block below is guarded by `if (0)` so it never runs at
 * runtime -- the compiler still parses and type-checks every macro
 * expansion, so a signature regression or arg-count change in the shim
 * trips a build error here even in configurations (e.g. verify-only)
 * where the happy-path runtime test below is skipped.
 *
 * Limitation: a same-type arg swap inside a shim macro (e.g. swapping the
 * two `const byte*` operands in `wc_dilithium_verify_msg`) compiles
 * cleanly here and is caught only by the runtime smoke test, which
 * requires sign+verify. */
static void mldsa_legacy_shim_macro_invocations_compile_check(void)
{
    wc_MlDsaKey* key   = NULL;
    const byte*  inp   = NULL;
    byte*        outp  = NULL;
    word32       inLen = 0;
    word32       outLen = 0;
    word32       idx   = 0;
    int          res   = 0;
    WC_RNG*      rng   = NULL;
    const byte*  seed  = NULL;

    /* The bodies are dead code (`if (0)`), but the macro expansions are
     * still parsed and type-checked. Return values are discarded with a
     * cast to `(void)`. */
    if (0) {
#ifdef WOLFSSL_MLDSA_PUBLIC_KEY
        (void)wc_dilithium_import_public(inp, inLen, key);
#endif
#ifdef WOLFSSL_MLDSA_PRIVATE_KEY
        (void)wc_dilithium_import_private(inp, inLen, key);
        (void)wc_dilithium_import_private_only(inp, inLen, key);
        (void)wc_dilithium_import_key(inp, inLen, inp, inLen, key);
#endif
#ifndef WOLFSSL_MLDSA_VERIFY_ONLY
    #ifdef WOLFSSL_MLDSA_NO_CTX
        (void)wc_dilithium_sign_msg(inp, inLen, outp, &outLen, key, rng);
        (void)wc_dilithium_sign_msg_with_seed(inp, inLen, outp, &outLen,
            key, seed);
    #endif
        (void)wc_dilithium_sign_ctx_msg(inp, (byte)0, inp, inLen,
            outp, &outLen, key, rng);
        (void)wc_dilithium_sign_ctx_hash(inp, (byte)0, 0, inp, inLen,
            outp, &outLen, key, rng);
        (void)wc_dilithium_sign_ctx_msg_with_seed(inp, (byte)0, inp, inLen,
            outp, &outLen, key, seed);
        (void)wc_dilithium_sign_ctx_hash_with_seed(inp, (byte)0, 0, inp,
            inLen, outp, &outLen, key, seed);
        (void)wc_dilithium_sign_mu_with_seed(inp, inLen, outp, &outLen,
            key, seed);
#endif
#ifdef WOLFSSL_MLDSA_NO_CTX
        (void)wc_dilithium_verify_msg(inp, inLen, inp, inLen, &res, key);
#endif
        (void)wc_dilithium_verify_ctx_msg(inp, inLen, inp, (byte)0, inp,
            inLen, &res, key);
        (void)wc_dilithium_verify_ctx_hash(inp, inLen, inp, (byte)0, 0, inp,
            inLen, &res, key);
        (void)wc_dilithium_verify_mu(inp, inLen, inp, inLen, &res, key);
#if !defined(WOLFSSL_MLDSA_NO_ASN1)
    #ifdef WOLFSSL_MLDSA_PRIVATE_KEY
        (void)wc_Dilithium_PrivateKeyDecode(inp, &idx, key, inLen);
    #endif
    #ifdef WOLFSSL_MLDSA_PUBLIC_KEY
        (void)wc_Dilithium_PublicKeyDecode(inp, &idx, key, inLen);
    #endif
#endif
        /* 1-arg init shim. */
        (void)wc_dilithium_init(key);
    }
    (void)key; (void)inp; (void)outp; (void)inLen; (void)outLen;
    (void)idx; (void)res; (void)rng; (void)seed;
}

/* === Runtime checks ==================================================== */

/* Smoke test exercising the arg-reordering macros that are reachable
 * end-to-end via a make-key / sign / verify / export / import / decode
 * happy-path. A same-type arg swap inside any of these macros shows up as
 * a verification or import failure here.
 *
 * Verify-only / sign-only / no-ASN1 builds skip the corresponding
 * sub-blocks; the compile-time invocation check above still type-checks
 * every shim macro in those configurations. */
int test_mldsa_legacy_shim(void)
{
    EXPECT_DECLS;

    /* Reference the compile-only checks so the compiler doesn't drop them
     * (and so -Wunused-function stays quiet under strict warning levels).
     * These are no-ops at runtime; the work is in the parse/type-check
     * the compiler did on the file. */
    (void)&mldsa_legacy_shim_symbol_aliases_compile_check;
    (void)&mldsa_legacy_shim_macro_invocations_compile_check;

#if !defined(WOLFSSL_MLDSA_NO_MAKE_KEY) && !defined(WOLFSSL_MLDSA_NO_SIGN) && \
    !defined(WOLFSSL_MLDSA_NO_VERIFY) && !defined(WOLFSSL_NO_ML_DSA_44) && \
    defined(WOLFSSL_MLDSA_PUBLIC_KEY) && defined(WOLFSSL_MLDSA_PRIVATE_KEY) && \
    !defined(WC_NO_RNG)
    {
        dilithium_key  key;        /* legacy typedef */
        WC_RNG         rng;
        byte           level = 0;
        byte           pubBuf[WC_MLDSA_44_PUB_KEY_SIZE];
        byte           privBuf[WC_MLDSA_44_KEY_SIZE];
        word32         pubLen  = (word32)sizeof(pubBuf);
        word32         privLen = (word32)sizeof(privBuf);
        static const byte msg[] = "wolfSSL ML-DSA legacy shim smoke test";

        XMEMSET(&key, 0, sizeof(key));
        XMEMSET(&rng, 0, sizeof(rng));

        ExpectIntEQ(wc_InitRng(&rng), 0);

        /* 1-arg shim macro -> wc_MlDsaKey_Init(key, NULL, INVALID_DEVID). */
        ExpectIntEQ(wc_dilithium_init(&key), 0);
        ExpectIntEQ(wc_dilithium_set_level(&key, WC_ML_DSA_44), 0);
        ExpectIntEQ(wc_dilithium_get_level(&key, &level), 0);
        ExpectIntEQ((int)level, WC_ML_DSA_44);

        /* Sizes -- pure symbol aliases. PrivSize is the export size of the
         * "private key" form (priv + pub combined), not the raw secret-key
         * buffer. */
        ExpectIntEQ(wc_dilithium_priv_size(&key), WC_MLDSA_44_PRV_KEY_SIZE);
        ExpectIntEQ(wc_dilithium_pub_size(&key),  WC_MLDSA_44_PUB_KEY_SIZE);
        ExpectIntEQ(wc_dilithium_sig_size(&key),  WC_MLDSA_44_SIG_SIZE);

        PRIVATE_KEY_UNLOCK();
        ExpectIntEQ(wc_dilithium_make_key(&key, &rng), 0);
        PRIVATE_KEY_LOCK();

    #ifdef WOLFSSL_MLDSA_CHECK_KEY
        ExpectIntEQ(wc_dilithium_check_key(&key), 0);
    #endif

        /* Sign + verify drive the arg-reordering sign/verify shim macros
         * with a real signature; a same-type arg swap shows up as a
         * verification failure. */
    #ifdef WOLFSSL_MLDSA_NO_CTX
        {
            byte    sig[WC_MLDSA_44_SIG_SIZE];
            word32  sigLen = (word32)sizeof(sig);
            int     verifyRes = 0;

            ExpectIntEQ(wc_dilithium_sign_msg(msg, (word32)sizeof(msg),
                sig, &sigLen, &key, &rng), 0);
            ExpectIntEQ(wc_dilithium_verify_msg(sig, sigLen,
                msg, (word32)sizeof(msg), &verifyRes, &key), 0);
            ExpectIntEQ(verifyRes, 1);
        }
    #else
        {
            byte    sig[WC_MLDSA_44_SIG_SIZE];
            word32  sigLen = (word32)sizeof(sig);
            int     verifyRes = 0;

            ExpectIntEQ(wc_dilithium_sign_ctx_msg(NULL, 0,
                msg, (word32)sizeof(msg), sig, &sigLen, &key, &rng), 0);
            ExpectIntEQ(wc_dilithium_verify_ctx_msg(sig, sigLen, NULL, 0,
                msg, (word32)sizeof(msg), &verifyRes, &key), 0);
            ExpectIntEQ(verifyRes, 1);
        }
    #endif

        /* Export raw key material and re-import via the legacy arg order. */
        ExpectIntEQ(wc_dilithium_export_public(&key, pubBuf, &pubLen), 0);
        ExpectIntEQ((int)pubLen, WC_MLDSA_44_PUB_KEY_SIZE);
        ExpectIntEQ(wc_dilithium_export_private(&key, privBuf, &privLen), 0);
        ExpectIntEQ((int)privLen, WC_MLDSA_44_KEY_SIZE);

        {
            dilithium_key imported;
            XMEMSET(&imported, 0, sizeof(imported));
            ExpectIntEQ(wc_dilithium_init(&imported), 0);
            ExpectIntEQ(wc_dilithium_set_level(&imported, WC_ML_DSA_44), 0);
            ExpectIntEQ(wc_dilithium_import_public(pubBuf, pubLen, &imported),
                0);
            ExpectIntEQ(wc_dilithium_import_private(privBuf, privLen,
                &imported), 0);
            wc_dilithium_free(&imported);
        }

        /* ASN.1 round-trip through the legacy Decode wrapper (arg order:
         * input, inOutIdx, key, inSz). */
    #if !defined(WOLFSSL_MLDSA_NO_ASN1)
        {
            byte          der[MLDSA_MAX_PRV_KEY_DER_SIZE];
            int           derSz;
            word32        idx = 0;
            dilithium_key decoded;

            XMEMSET(&decoded, 0, sizeof(decoded));
            derSz = wc_Dilithium_PrivateKeyToDer(&key, der,
                (word32)sizeof(der));
            ExpectIntGT(derSz, 0);

            ExpectIntEQ(wc_dilithium_init(&decoded), 0);
            ExpectIntEQ(wc_dilithium_set_level(&decoded, WC_ML_DSA_44), 0);
            PRIVATE_KEY_UNLOCK();
            ExpectIntEQ(wc_Dilithium_PrivateKeyDecode(der, &idx, &decoded,
                (word32)derSz), 0);
            PRIVATE_KEY_LOCK();
            wc_dilithium_free(&decoded);
        }
    #endif

        wc_dilithium_free(&key);
        wc_FreeRng(&rng);
    }
#endif /* sign+verify happy-path */

    return EXPECT_RESULT();
}

#else /* !WOLFSSL_HAVE_MLDSA || WOLFSSL_NO_DILITHIUM_LEGACY_NAMES */

int test_mldsa_legacy_shim(void)
{
    return TEST_SKIPPED;
}

#endif
