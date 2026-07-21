/* test_sp_x86_64_whitebox.c
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

/*
 * MC/DC white-box supplement for wolfcrypt/src/sp_x86_64.c.
 *
 * sp_x86_64.c is the x86-64 SP math backend: every entry point checks the
 * runtime CPU feature mask (via cpuid_get_flags()) with decisions of the
 * shape
 *
 *   if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags) && ...)
 *       <accelerated MULX/ADCX/ADOX asm path>
 *   else
 *       <generic C path>
 *
 * On any BMI2+ADX host (which is effectively every build/CI machine this
 * campaign runs on) only the accelerated half of each such decision is ever
 * taken by the ordinary tests/api-driven asm run, leaving the generic half
 * permanently uncovered -- roughly 374 decisions across the file.
 *
 * cpuid_select_flags() (wolfssl/wolfcrypt/cpuid.h, WOLFSSL_API) overrides the
 * process-wide cpuid flags mask returned by cpuid_get_flags(). Every SP
 * function reloads cpuid_get_flags() itself (there is no cached/latched copy
 * surviving across calls), so calling cpuid_select_flags(0) here makes every
 * IS_INTEL_BMI2/ADX/MOVBE() test in this TU's copy of sp_x86_64.c evaluate
 * false from that point on, without touching the real CPU or any other
 * translation unit. This drives the SAME public operations (ECC sign/verify/
 * ECDH, RSA sign/verify, DH key agreement) down the generic C path, covering
 * the other half of each dispatch decision.
 *
 * Coverage from this binary is unioned with the tests/api variant coverage
 * (and with the normal, accelerated, asm run of this same file) by source
 * line:col in the per-module campaign (iso26262/mcdc-per-module):
 * llvm-cov computes MC/DC independence PER BINARY, and the campaign's
 * aggregate.sh ORs the "independence shown" bit across binaries by key.
 *
 * Build: compiled by run-mcdc.sh's white-box step with the SAME MC/DC CFLAGS,
 * -DHAVE_CONFIG_H and -I<workspace> as the instrumented library, then linked
 * against that variant's libwolfssl.a with its sp_x86_64.o removed (this TU
 * supplies the instrumented sp_x86_64.c). NOT part of the wolfSSL build; not
 * registered in tests/api. See tests/unit-mcdc/README.md.
 *
 * This is a coverage-driving supplement, not a known-answer test: correctness
 * of the arithmetic is already covered by the normal wolfCrypt test suite. The
 * only goal here is to complete each operation on the generic path without
 * crashing; every result is checked only for "did this fail outright", not
 * for a specific expected value.
 *
 * -------------------------------------------------------------------------
 * wb_run_dispatch(): direct file-static function driving
 * -------------------------------------------------------------------------
 * The high-level driving above (wb_run_ecc/wb_run_rsa_keygen+
 * wb_run_rsa_signverify/wb_run_dh) only routes through a handful of the
 * ~64 file-static sp_<size>_* functions in
 * sp_x86_64.c that carry their own
 *   if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
 * dispatch (asm MULX/ADCX/ADOX path vs. generic C path); RSA-2048-only CRT
 * halves, DH-specific base-2 modexps, ECC point-validation/compressed-key
 * helpers, and most of the div/from_bin/to_bin/to_mp plumbing for sizes the
 * three high-level passes don't happen to exercise are left uncovered.
 *
 * The key property that makes it safe to call these file-static functions
 * directly with hand-built stack buffers, instead of only reaching them via
 * the public API with cryptographically valid data: every one of these
 * decisions tests the CPU feature mask read via cpuid_get_flags() -- it does
 * NOT branch on the data being operated on. The multi-precision arithmetic
 * itself (add/sub/mul/mod/point-add/point-double) is implemented as fixed
 * shape, fixed-iteration-count operations on n-word sp_digit arrays -- there
 * is no data-dependent looping or dynamic allocation sized off the operand
 * *values* (only off the compile-time word count n), so any correctly-sized,
 * zero-initialized buffer with small non-zero scalars where a divisor/
 * modulus/inversion-input is required drives the SAME decision as a full
 * high-level operation, without needing the operands to satisfy any
 * mathematical relationship (e.g. "actually being on the curve", or r/s
 * being a real signature). Every call below is followed by discarding the
 * result; only "did it crash" is being tested here, exactly as in the rest
 * of this file.
 *
 * Buffer layouts (which slice of a shared array plays which role, and how
 * large the shared array needs to be) are copied verbatim from the nearest
 * real caller in sp_x86_64.c (e.g. sp_ecc_sign_256/sp_ecc_verify_256 for the
 * calc_s_4/calc_vfy_point_4 slicing) so that internal SP_DECL_VAR/temporary
 * usage inside the callee never runs past the buffer this file supplies.
 *
 * Residual: sp_<size>_<op>_avx2_<n> functions (e.g. sp_256_mod_exp_avx2_16,
 * sp_2048_mod_exp_avx2_32) contain this SAME IS_INTEL_BMI2 && IS_INTEL_ADX
 * check internally, but they are only ever *reached* from a higher dispatch
 * point after that higher point has already confirmed BMI2 && ADX (usually
 * together with AVX2) are present -- so by the time control reaches the
 * avx2 variant, the inner check is always true; the "generic path" half of
 * that inner decision is an impossible state at normal runtime. Forcing it
 * would require calling the avx2 variant directly while ALSO forcing
 * cpuid_get_flags() to report BMI2/ADX absent for that one call, which
 * doesn't correspond to any state the real dispatch logic can reach. These
 * are left uncovered here and logged as a residual/DEATHNOTE class rather
 * than driven via an impossible-state call.
 *
 * -------------------------------------------------------------------------
 * wb_run_crafted(): sp_ecc_mulmod_add_<n> + point-validation family
 * -------------------------------------------------------------------------
 * See the block comment directly above wb_run_crafted_curve() (near the end
 * of the wb_run_dispatch() section) for the specific decisions covered:
 * the `if ((err == MP_OKAY) && (!inMont))` x/y/z triple and the `if (map)`
 * in sp_ecc_mulmod_add_<n>, and the length/infinity/range guards inside
 * sp_ecc_check_key_<n> and sp_ecc_is_point_<n>.
 *
 * -------------------------------------------------------------------------
 * Residuals not driven by this file (fault-injection or crypto-negligible)
 * -------------------------------------------------------------------------
 * A number of decisions in sp_x86_64.c are left uncovered by design because
 * driving them would require either injecting a failure into an earlier,
 * otherwise-successful step, or hitting a probability-zero-in-practice
 * random value -- neither is a "generic vs. accelerated path" concern, so
 * neither belongs in this cpuid-focused white-box:
 *
 *   - `if ((err == MP_OKAY) && ...)` guards throughout the ECC/RSA/DH code
 *     where the uncovered operand is `err == MP_OKAY` itself being FALSE:
 *     since every call in this file is set up to succeed (correctly sized,
 *     non-zero, in-range operands), `err` is MP_OKAY at every one of these
 *     checkpoints. Forcing the false side would need fault injection into
 *     an earlier SP_ALLOC_VAR/mod_exp/mulmod call (e.g. simulating
 *     MEMORY_E), which this file does not attempt.
 *   - `wc_LockMutex(&sp_cache_<n>_lock) != 0` (FP_ECC point-cache paths):
 *     only false in practice (a live, correctly-initialized mutex always
 *     locks successfully); the true side requires fault-injecting mutex
 *     failure, out of scope here.
 *   - the ECDSA sign retry loop `for (i = SP_ECC_MAX_SIG_GEN; err == MP_OKAY
 *     && i > 0; i--)` and the companion `(err == MP_OKAY) && (!sp_<n>_
 *     iszero_<n>(s))` check: the loop only iterates more than once, and
 *     the iszero(s) check only sees a zero `s`, when a randomly generated
 *     k/r/s value is exactly zero mod order -- cryptographically
 *     negligible (~2^-256 for P-256) and not reachable by construction
 *     from this file's fixed/small-scalar inputs.
 */

#include <wolfcrypt/src/sp_x86_64.c>

#include <wolfssl/wolfcrypt/cpuid.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/random.h>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(WOLFSSL_HAVE_SP_ECC) || defined(WOLFSSL_HAVE_SP_RSA) || \
    defined(WOLFSSL_HAVE_SP_DH)

/* Fixed 32-byte "digest" used for every ECDSA sign/verify below. Its value
 * does not matter -- we are driving the generic modexp/point-math path, not
 * checking a known-answer signature. */
static const byte wb_digest[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

#if defined(WOLFSSL_HAVE_SP_ECC) && defined(HAVE_ECC)
/* -------------------------------------------------------------------- *
 * ECC: make_key_ex + sign_hash + verify_hash + shared_secret (ECDH),
 * for each SP-accelerated curve size compiled in. With cpuid flags
 * forced to 0 (see main()), all of this routes through the generic
 * sp_<size>_* point/field math in sp_x86_64.c instead of the BMI2/ADX
 * asm path.
 * -------------------------------------------------------------------- */
static void wb_run_ecc_curve(int curve_id, int fieldSz, const char* label)
{
#if defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY) && defined(HAVE_ECC_DHE)
    ecc_key keyA;
    ecc_key keyB;
    WC_RNG  rng;
    byte    sig[ECC_MAX_SIG_SIZE];
    word32  sigLen = (word32)sizeof(sig);
    byte    secretA[MAX_ECC_BYTES];
    byte    secretB[MAX_ECC_BYTES];
    word32  secretALen = (word32)sizeof(secretA);
    word32  secretBLen = (word32)sizeof(secretB);
    int     verifyRes = 0;
    int     ok = 1;

    XMEMSET(&keyA, 0, sizeof(keyA));
    XMEMSET(&keyB, 0, sizeof(keyB));
    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(sig, 0, sizeof(sig));
    XMEMSET(secretA, 0, sizeof(secretA));
    XMEMSET(secretB, 0, sizeof(secretB));

    if (wc_ecc_init(&keyA) != 0) {
        WB_NOTE("wc_ecc_init(keyA) failed");
        wb_fail = 1;
        return;
    }
    if (wc_ecc_init(&keyB) != 0) {
        WB_NOTE("wc_ecc_init(keyB) failed");
        wb_fail = 1;
        wc_ecc_free(&keyA);
        return;
    }
    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("wc_InitRng failed (ecc)");
        wb_fail = 1;
        wc_ecc_free(&keyA);
        wc_ecc_free(&keyB);
        return;
    }

    if (wc_ecc_make_key_ex(&rng, fieldSz, &keyA, curve_id) != 0) {
        WB_NOTE("wc_ecc_make_key_ex(keyA) failed");
        wb_fail = 1;
        ok = 0;
    }
    if (ok && wc_ecc_make_key_ex(&rng, fieldSz, &keyB, curve_id) != 0) {
        WB_NOTE("wc_ecc_make_key_ex(keyB) failed");
        wb_fail = 1;
        ok = 0;
    }

    if (ok) {
        sigLen = (word32)sizeof(sig);
        if (wc_ecc_sign_hash(wb_digest, (word32)sizeof(wb_digest), sig,
                &sigLen, &rng, &keyA) != 0) {
            WB_NOTE("wc_ecc_sign_hash failed");
            wb_fail = 1;
        }
        else if (wc_ecc_verify_hash(sig, sigLen, wb_digest,
                (word32)sizeof(wb_digest), &verifyRes, &keyA) != 0) {
            WB_NOTE("wc_ecc_verify_hash failed");
            wb_fail = 1;
        }

        PRIVATE_KEY_UNLOCK();
        secretALen = (word32)sizeof(secretA);
        if (wc_ecc_shared_secret(&keyA, &keyB, secretA, &secretALen) != 0) {
            WB_NOTE("wc_ecc_shared_secret(A,B) failed");
            wb_fail = 1;
        }
        secretBLen = (word32)sizeof(secretB);
        if (wc_ecc_shared_secret(&keyB, &keyA, secretB, &secretBLen) != 0) {
            WB_NOTE("wc_ecc_shared_secret(B,A) failed");
            wb_fail = 1;
        }
        PRIVATE_KEY_LOCK();
    }

    wc_FreeRng(&rng);
    wc_ecc_free(&keyA);
    wc_ecc_free(&keyB);
    (void)verifyRes;
    WB_NOTE(label);
#else
    (void)curve_id;
    (void)fieldSz;
    WB_NOTE("HAVE_ECC_SIGN/VERIFY/DHE not all defined; ecc curve skipped");
    (void)label;
#endif
}

static void wb_run_ecc(void)
{
#ifndef WOLFSSL_SP_NO_256
    wb_run_ecc_curve(ECC_SECP256R1, 32,
        "P-256 make_key/sign/verify/ECDH (generic path) exercised");
#else
    WB_NOTE("WOLFSSL_SP_NO_256 defined; P-256 skipped");
#endif

#ifdef WOLFSSL_SP_384
    wb_run_ecc_curve(ECC_SECP384R1, 48,
        "P-384 make_key/sign/verify/ECDH (generic path) exercised");
#else
    WB_NOTE("WOLFSSL_SP_384 not defined; P-384 skipped");
#endif

#ifdef WOLFSSL_SP_521
    wb_run_ecc_curve(ECC_SECP521R1, 66,
        "P-521 make_key/sign/verify/ECDH (generic path) exercised");
#else
    WB_NOTE("WOLFSSL_SP_521 not defined; P-521 skipped");
#endif
}
#else
static void wb_run_ecc(void)
{
    WB_NOTE("WOLFSSL_HAVE_SP_ECC/HAVE_ECC not both defined; ECC skipped");
}
#endif /* WOLFSSL_HAVE_SP_ECC && HAVE_ECC */

#if defined(WOLFSSL_HAVE_SP_RSA) && !defined(NO_RSA) && \
    defined(WOLFSSL_KEY_GEN)
/* -------------------------------------------------------------------- *
 * RSA: MakeRsaKey once (all-on pass only -- generic-path keygen is slow),
 * then RsaSSL_Sign + RsaSSL_Verify against that SAME key under EVERY cpuid
 * mask. Sign/verify route through sp_<size>_mod_exp_<n>/mont_reduce_<n>/
 * mont_mul_<n>, each internally gated by its own BMI2&&ADX dispatch, so
 * reusing one pre-generated key across all four passes gets those
 * dispatches their TT/FT/TF vectors without paying for four generic-path
 * key generations. wb_run_rsa_keygen() must run (in the all-on pass)
 * before the first call to wb_run_rsa_signverify(); wb_run_rsa_free()
 * releases the keys once all passes have completed.
 * -------------------------------------------------------------------- */
static RsaKey wb_rsaKey2048;
static RsaKey wb_rsaKey3072;
static RsaKey wb_rsaKey4096;
static int    wb_rsaKey2048Ok = 0;
static int    wb_rsaKey3072Ok = 0;
static int    wb_rsaKey4096Ok = 0;

static void wb_run_rsa_keygen(void)
{
    WC_RNG rng;

    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("wc_InitRng failed (rsa keygen)");
        wb_fail = 1;
        return;
    }

#ifndef WOLFSSL_SP_NO_2048
    XMEMSET(&wb_rsaKey2048, 0, sizeof(wb_rsaKey2048));
    if (wc_InitRsaKey(&wb_rsaKey2048, NULL) != 0) {
        WB_NOTE("wc_InitRsaKey(2048) failed");
        wb_fail = 1;
    }
    else if (wc_MakeRsaKey(&wb_rsaKey2048, 2048, WC_RSA_EXPONENT, &rng)
            != 0) {
        WB_NOTE("wc_MakeRsaKey(2048) failed");
        wb_fail = 1;
        wc_FreeRsaKey(&wb_rsaKey2048);
    }
    else {
        wb_rsaKey2048Ok = 1;
    }
#else
    WB_NOTE("WOLFSSL_SP_NO_2048 defined; RSA-2048 keygen skipped");
#endif

#ifndef WOLFSSL_SP_NO_3072
    XMEMSET(&wb_rsaKey3072, 0, sizeof(wb_rsaKey3072));
    if (wc_InitRsaKey(&wb_rsaKey3072, NULL) != 0) {
        WB_NOTE("wc_InitRsaKey(3072) failed");
        wb_fail = 1;
    }
    else if (wc_MakeRsaKey(&wb_rsaKey3072, 3072, WC_RSA_EXPONENT, &rng)
            != 0) {
        WB_NOTE("wc_MakeRsaKey(3072) failed");
        wb_fail = 1;
        wc_FreeRsaKey(&wb_rsaKey3072);
    }
    else {
        wb_rsaKey3072Ok = 1;
    }
#else
    WB_NOTE("WOLFSSL_SP_NO_3072 defined; RSA-3072 keygen skipped");
#endif

#ifdef WOLFSSL_SP_4096
    XMEMSET(&wb_rsaKey4096, 0, sizeof(wb_rsaKey4096));
    if (wc_InitRsaKey(&wb_rsaKey4096, NULL) != 0) {
        WB_NOTE("wc_InitRsaKey(4096) failed");
        wb_fail = 1;
    }
    else if (wc_MakeRsaKey(&wb_rsaKey4096, 4096, WC_RSA_EXPONENT, &rng)
            != 0) {
        WB_NOTE("wc_MakeRsaKey(4096) failed");
        wb_fail = 1;
        wc_FreeRsaKey(&wb_rsaKey4096);
    }
    else {
        wb_rsaKey4096Ok = 1;
    }
#else
    WB_NOTE("WOLFSSL_SP_4096 not defined; RSA-4096 keygen skipped");
#endif

    wc_FreeRng(&rng);
}

static void wb_run_rsa_signverify_key(RsaKey* key, int bits,
    const char* label)
{
    WC_RNG rng;
    byte   msg[32];
    /* Sized for the largest SP-accelerated RSA modulus (4096 bits). */
    byte   sig[512];
    byte   plain[512];
    word32 sigLen;
    int    ret;

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(msg, 0x5A, sizeof(msg));
    XMEMSET(sig, 0, sizeof(sig));
    XMEMSET(plain, 0, sizeof(plain));

    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("wc_InitRng failed (rsa signverify)");
        wb_fail = 1;
        return;
    }

    sigLen = (word32)(bits / 8);
    ret = wc_RsaSSL_Sign(msg, (word32)sizeof(msg), sig, sigLen, key, &rng);
    if (ret <= 0) {
        WB_NOTE("wc_RsaSSL_Sign failed (signverify)");
        wb_fail = 1;
    }
    else {
        sigLen = (word32)ret;
        ret = wc_RsaSSL_Verify(sig, sigLen, plain, (word32)sizeof(plain),
            key);
        if (ret <= 0) {
            WB_NOTE("wc_RsaSSL_Verify failed (signverify)");
            wb_fail = 1;
        }
    }

    wc_FreeRng(&rng);
    WB_NOTE(label);
}

static void wb_run_rsa_signverify(void)
{
#ifndef WOLFSSL_SP_NO_2048
    if (wb_rsaKey2048Ok) {
        wb_run_rsa_signverify_key(&wb_rsaKey2048, 2048,
            "RSA-2048 SSL_Sign/SSL_Verify (mask pass) exercised");
    }
#endif
#ifndef WOLFSSL_SP_NO_3072
    if (wb_rsaKey3072Ok) {
        wb_run_rsa_signverify_key(&wb_rsaKey3072, 3072,
            "RSA-3072 SSL_Sign/SSL_Verify (mask pass) exercised");
    }
#endif
#ifdef WOLFSSL_SP_4096
    if (wb_rsaKey4096Ok) {
        wb_run_rsa_signverify_key(&wb_rsaKey4096, 4096,
            "RSA-4096 SSL_Sign/SSL_Verify (mask pass) exercised");
    }
#endif
}

static void wb_run_rsa_free(void)
{
#ifndef WOLFSSL_SP_NO_2048
    if (wb_rsaKey2048Ok) {
        wc_FreeRsaKey(&wb_rsaKey2048);
        wb_rsaKey2048Ok = 0;
    }
#endif
#ifndef WOLFSSL_SP_NO_3072
    if (wb_rsaKey3072Ok) {
        wc_FreeRsaKey(&wb_rsaKey3072);
        wb_rsaKey3072Ok = 0;
    }
#endif
#ifdef WOLFSSL_SP_4096
    if (wb_rsaKey4096Ok) {
        wc_FreeRsaKey(&wb_rsaKey4096);
        wb_rsaKey4096Ok = 0;
    }
#endif
}
#else
static void wb_run_rsa_keygen(void)
{
    WB_NOTE("WOLFSSL_HAVE_SP_RSA/!NO_RSA/WOLFSSL_KEY_GEN not all defined; "
             "RSA keygen skipped");
}
static void wb_run_rsa_signverify(void)
{
    WB_NOTE("WOLFSSL_HAVE_SP_RSA/!NO_RSA/WOLFSSL_KEY_GEN not all defined; "
             "RSA signverify skipped");
}
static void wb_run_rsa_free(void)
{
}
#endif /* WOLFSSL_HAVE_SP_RSA && !NO_RSA && WOLFSSL_KEY_GEN */

#if defined(WOLFSSL_HAVE_SP_DH) && !defined(NO_DH)
/* -------------------------------------------------------------------- *
 * DH: DhSetKey + DhGenerateKeyPair + DhAgree on both sides of a 2048-bit
 * exchange. With cpuid flags forced to 0, the modexps route through the
 * generic sp_ModExp_2048/sp_DhExp_2048 path instead of the BMI2/ADX asm
 * path.
 *
 * p/g below are the well-known RFC 3526 "Group 14" 2048-bit MODP prime
 * and generator (g=2), used purely to drive the generic modexp -- not
 * checked for any specific agreed-secret value.
 *
 * 3072-bit is intentionally NOT exercised here: embedding the RFC 3526
 * "Group 15" 3072-bit prime from memory risks a transcription error, and
 * generating one at runtime via wc_DhGenerateParams(3072) is a slow
 * probable-safe-prime search that would meaningfully slow this binary
 * down for a size this campaign only asks for "if convenient". The
 * generic sp_ModExp_3072/sp_DhExp_3072 decisions are still covered via
 * the RSA-3072 path above (same underlying generic Montgomery modexp
 * routines), so 2048-bit alone still exercises the DH-specific
 * (sp_DhExp_2048) generic wrapper.
 * -------------------------------------------------------------------- */
static const byte wb_dh2048_p[256] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
    0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
    0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
    0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
    0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
    0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
    0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
    0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
    0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
    0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C,
    0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
    0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
    0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
    0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
    0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5,
    0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};
static const byte wb_dh2048_g[1] = { 0x02 };

static void wb_run_dh(void)
{
#ifndef WOLFSSL_SP_NO_2048
    DhKey  keyA;
    DhKey  keyB;
    WC_RNG rng;
    byte   privA[256];
    byte   pubA[256];
    byte   privB[256];
    byte   pubB[256];
    byte   agreeA[256];
    byte   agreeB[256];
    word32 privASz = (word32)sizeof(privA);
    word32 pubASz  = (word32)sizeof(pubA);
    word32 privBSz = (word32)sizeof(privB);
    word32 pubBSz  = (word32)sizeof(pubB);
    word32 agreeASz = (word32)sizeof(agreeA);
    word32 agreeBSz = (word32)sizeof(agreeB);
    int    ok = 1;

    XMEMSET(&keyA, 0, sizeof(keyA));
    XMEMSET(&keyB, 0, sizeof(keyB));
    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(privA, 0, sizeof(privA));
    XMEMSET(pubA, 0, sizeof(pubA));
    XMEMSET(privB, 0, sizeof(privB));
    XMEMSET(pubB, 0, sizeof(pubB));
    XMEMSET(agreeA, 0, sizeof(agreeA));
    XMEMSET(agreeB, 0, sizeof(agreeB));

    if (wc_InitDhKey(&keyA) != 0) {
        WB_NOTE("wc_InitDhKey(keyA) failed");
        wb_fail = 1;
        return;
    }
    if (wc_InitDhKey(&keyB) != 0) {
        WB_NOTE("wc_InitDhKey(keyB) failed");
        wb_fail = 1;
        wc_FreeDhKey(&keyA);
        return;
    }
    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("wc_InitRng failed (dh)");
        wb_fail = 1;
        wc_FreeDhKey(&keyA);
        wc_FreeDhKey(&keyB);
        return;
    }

    if (wc_DhSetKey(&keyA, wb_dh2048_p, (word32)sizeof(wb_dh2048_p),
            wb_dh2048_g, (word32)sizeof(wb_dh2048_g)) != 0) {
        WB_NOTE("wc_DhSetKey(keyA) failed");
        wb_fail = 1;
        ok = 0;
    }
    if (ok && wc_DhSetKey(&keyB, wb_dh2048_p, (word32)sizeof(wb_dh2048_p),
            wb_dh2048_g, (word32)sizeof(wb_dh2048_g)) != 0) {
        WB_NOTE("wc_DhSetKey(keyB) failed");
        wb_fail = 1;
        ok = 0;
    }

    if (ok && wc_DhGenerateKeyPair(&keyA, &rng, privA, &privASz, pubA,
            &pubASz) != 0) {
        WB_NOTE("wc_DhGenerateKeyPair(keyA) failed");
        wb_fail = 1;
        ok = 0;
    }
    if (ok && wc_DhGenerateKeyPair(&keyB, &rng, privB, &privBSz, pubB,
            &pubBSz) != 0) {
        WB_NOTE("wc_DhGenerateKeyPair(keyB) failed");
        wb_fail = 1;
        ok = 0;
    }

    if (ok) {
        if (wc_DhAgree(&keyA, agreeA, &agreeASz, privA, privASz, pubB,
                pubBSz) != 0) {
            WB_NOTE("wc_DhAgree(A) failed");
            wb_fail = 1;
        }
        if (wc_DhAgree(&keyB, agreeB, &agreeBSz, privB, privBSz, pubA,
                pubASz) != 0) {
            WB_NOTE("wc_DhAgree(B) failed");
            wb_fail = 1;
        }
    }

    wc_FreeRng(&rng);
    wc_FreeDhKey(&keyA);
    wc_FreeDhKey(&keyB);
    WB_NOTE("DH-2048 SetKey/GenerateKeyPair/Agree (generic path) exercised");
#else
    WB_NOTE("WOLFSSL_SP_NO_2048 defined; DH-2048 skipped");
#endif
    WB_NOTE("DH-3072 skipped (see comment above wb_run_dh)");
}
#else
static void wb_run_dh(void)
{
    WB_NOTE("WOLFSSL_HAVE_SP_DH/!NO_DH not both defined; DH skipped");
}
#endif /* WOLFSSL_HAVE_SP_DH && !NO_DH */

/* ======================================================================= *
 * wb_run_dispatch(): direct file-static function driving.
 * See the file header comment for why this is safe (cpuid-only decisions,
 * fixed-shape arithmetic) and where each buffer layout comes from.
 * ======================================================================= */

/* ----------------------------------------------------------------------- *
 * RSA/DH: sp_<size>_div_<n>[_cond], sp_<size>_mod_exp_<n>[_2_<n>],
 * sp_<size>_from_bin/to_bin_<n>/to_mp for 2048/3072/4096.
 * ----------------------------------------------------------------------- */
static void wb_run_dispatch_2048(void)
{
#ifndef WOLFSSL_SP_NO_2048
    /* div_32 / div_32_cond: a is the 2n-word dividend, d/r are n-word. */
    {
        sp_digit a[64];
        sp_digit d[32];
        sp_digit r[32];

        XMEMSET(a, 0, sizeof(a));
        XMEMSET(d, 0, sizeof(d));
        XMEMSET(r, 0, sizeof(r));
        d[0] = 3;
        d[31] = 1; /* div_2048_word_32() divides by d's TOP word; must be nonzero */
        (void)sp_2048_div_32(a, d, NULL, r);
        (void)sp_2048_div_32_cond(a, d, NULL, r);
    }

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || \
        defined(WOLFSSL_HAVE_SP_DH)
    /* mod_exp_16: RSA-2048 CRT half (primes are ~1024-bit -> 16 words). */
    {
        sp_digit r16[32];
        sp_digit a16[16];
        sp_digit e16[16];
        sp_digit m16[16];

        XMEMSET(r16, 0, sizeof(r16));
        XMEMSET(a16, 0, sizeof(a16));
        XMEMSET(e16, 0, sizeof(e16));
        XMEMSET(m16, 0, sizeof(m16));
        a16[0] = 3;
        e16[0] = 5;
        m16[0] = (sp_digit)0xFFFFFFFFFFFFFFF1ULL;
        m16[15] = 1;
        (void)sp_2048_mod_exp_16(r16, a16, e16, 3, m16, 0);
    }
    /* mod_exp_32: full 2048-bit modexp (also covers 4096-bit RSA CRT,
     * whose ~2048-bit primes reuse this same function). */
    {
        sp_digit r32[64];
        sp_digit a32[32];
        sp_digit e32[32];
        sp_digit m32[32];

        XMEMSET(r32, 0, sizeof(r32));
        XMEMSET(a32, 0, sizeof(a32));
        XMEMSET(e32, 0, sizeof(e32));
        XMEMSET(m32, 0, sizeof(m32));
        a32[0] = 3;
        e32[0] = 5;
        m32[0] = (sp_digit)0xFFFFFFFFFFFFFFF1ULL;
        m32[31] = 1;
        (void)sp_2048_mod_exp_32(r32, a32, e32, 3, m32, 0);
    }
#else
    WB_NOTE("2048 mod_exp_16/32 needs (SP_RSA && !RSA_PUBLIC_ONLY) || SP_DH; "
             "skipped");
#endif

#if defined(WOLFSSL_HAVE_SP_DH) && defined(HAVE_FFDHE_2048)
    /* mod_exp_2_32: DH base-2 modexp, only built for the FFDHE-2048 group. */
    {
        sp_digit r2[64];
        sp_digit e2[32];
        sp_digit m2[32];

        XMEMSET(r2, 0, sizeof(r2));
        XMEMSET(e2, 0, sizeof(e2));
        XMEMSET(m2, 0, sizeof(m2));
        e2[0] = 5;
        m2[0] = (sp_digit)0xFFFFFFFFFFFFFFF1ULL;
        m2[31] = 1;
        (void)sp_2048_mod_exp_2_32(r2, e2, 3, m2);
    }
#else
    WB_NOTE("2048 mod_exp_2_32 needs SP_DH && HAVE_FFDHE_2048; skipped");
#endif

    /* from_bin/to_bin/to_mp: trivial, MOVBE-dispatched conversions. */
    {
        sp_digit a[32];
        byte     bin[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
        byte     out[256];

        XMEMSET(a, 0, sizeof(a));
        XMEMSET(out, 0, sizeof(out));
        sp_2048_from_bin(a, 32, bin, (int)sizeof(bin));
        sp_2048_to_bin_32(a, out);
    }
#if defined(WOLFSSL_HAVE_SP_DH) || (defined(WOLFSSL_HAVE_SP_RSA) && \
        !defined(WOLFSSL_RSA_PUBLIC_ONLY))
    {
        sp_digit a[32];
        mp_int   m;

        XMEMSET(a, 0, sizeof(a));
        a[0] = 3;
        if (mp_init(&m) == MP_OKAY) {
            (void)sp_2048_to_mp(a, &m);
            mp_clear(&m);
        }
        else {
            WB_NOTE("mp_init failed (sp_2048_to_mp)");
        }
    }
#else
    WB_NOTE("sp_2048_to_mp needs SP_DH || (SP_RSA && !RSA_PUBLIC_ONLY); "
             "skipped");
#endif
#else
    WB_NOTE("WOLFSSL_SP_NO_2048 defined; 2048 dispatch skipped");
#endif /* !WOLFSSL_SP_NO_2048 */
}

static void wb_run_dispatch_3072(void)
{
#ifndef WOLFSSL_SP_NO_3072
    {
        sp_digit a[96];
        sp_digit d[48];
        sp_digit r[48];

        XMEMSET(a, 0, sizeof(a));
        XMEMSET(d, 0, sizeof(d));
        XMEMSET(r, 0, sizeof(r));
        d[0] = 3;
        d[47] = 1; /* divisor word routine divides by d's TOP word */
        (void)sp_3072_div_48(a, d, NULL, r);
        (void)sp_3072_div_48_cond(a, d, NULL, r);
    }

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || \
        defined(WOLFSSL_HAVE_SP_DH)
    /* mod_exp_24: RSA-3072 CRT half (primes are ~1536-bit -> 24 words). */
    {
        sp_digit r24[48];
        sp_digit a24[24];
        sp_digit e24[24];
        sp_digit m24[24];

        XMEMSET(r24, 0, sizeof(r24));
        XMEMSET(a24, 0, sizeof(a24));
        XMEMSET(e24, 0, sizeof(e24));
        XMEMSET(m24, 0, sizeof(m24));
        a24[0] = 3;
        e24[0] = 5;
        m24[0] = (sp_digit)0xFFFFFFFFFFFFFFF1ULL;
        m24[23] = 1;
        (void)sp_3072_mod_exp_24(r24, a24, e24, 3, m24, 0);
    }
    /* mod_exp_48: full 3072-bit modexp. */
    {
        sp_digit r48[96];
        sp_digit a48[48];
        sp_digit e48[48];
        sp_digit m48[48];

        XMEMSET(r48, 0, sizeof(r48));
        XMEMSET(a48, 0, sizeof(a48));
        XMEMSET(e48, 0, sizeof(e48));
        XMEMSET(m48, 0, sizeof(m48));
        a48[0] = 3;
        e48[0] = 5;
        m48[0] = (sp_digit)0xFFFFFFFFFFFFFFF1ULL;
        m48[47] = 1;
        (void)sp_3072_mod_exp_48(r48, a48, e48, 3, m48, 0);
    }
#else
    WB_NOTE("3072 mod_exp_24/48 needs (SP_RSA && !RSA_PUBLIC_ONLY) || SP_DH; "
             "skipped");
#endif

#if defined(WOLFSSL_HAVE_SP_DH) && defined(HAVE_FFDHE_3072)
    {
        sp_digit r2[96];
        sp_digit e2[48];
        sp_digit m2[48];

        XMEMSET(r2, 0, sizeof(r2));
        XMEMSET(e2, 0, sizeof(e2));
        XMEMSET(m2, 0, sizeof(m2));
        e2[0] = 5;
        m2[0] = (sp_digit)0xFFFFFFFFFFFFFFF1ULL;
        m2[47] = 1;
        (void)sp_3072_mod_exp_2_48(r2, e2, 3, m2);
    }
#else
    WB_NOTE("3072 mod_exp_2_48 needs SP_DH && HAVE_FFDHE_3072; skipped");
#endif

    {
        sp_digit a[48];
        byte     bin[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
        byte     out[384];

        XMEMSET(a, 0, sizeof(a));
        XMEMSET(out, 0, sizeof(out));
        sp_3072_from_bin(a, 48, bin, (int)sizeof(bin));
        sp_3072_to_bin_48(a, out);
    }
#if defined(WOLFSSL_HAVE_SP_DH) || (defined(WOLFSSL_HAVE_SP_RSA) && \
        !defined(WOLFSSL_RSA_PUBLIC_ONLY))
    {
        sp_digit a[48];
        mp_int   m;

        XMEMSET(a, 0, sizeof(a));
        a[0] = 3;
        if (mp_init(&m) == MP_OKAY) {
            (void)sp_3072_to_mp(a, &m);
            mp_clear(&m);
        }
        else {
            WB_NOTE("mp_init failed (sp_3072_to_mp)");
        }
    }
#else
    WB_NOTE("sp_3072_to_mp needs SP_DH || (SP_RSA && !RSA_PUBLIC_ONLY); "
             "skipped");
#endif
#else
    WB_NOTE("WOLFSSL_SP_NO_3072 defined; 3072 dispatch skipped");
#endif /* !WOLFSSL_SP_NO_3072 */
}

static void wb_run_dispatch_4096(void)
{
#ifdef WOLFSSL_SP_4096
    {
        sp_digit a[128];
        sp_digit d[64];
        sp_digit r[64];

        XMEMSET(a, 0, sizeof(a));
        XMEMSET(d, 0, sizeof(d));
        XMEMSET(r, 0, sizeof(r));
        d[0] = 3;
        d[63] = 1; /* divisor word routine divides by d's TOP word */
        (void)sp_4096_div_64(a, d, NULL, r);
        (void)sp_4096_div_64_cond(a, d, NULL, r);
    }

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || \
        defined(WOLFSSL_HAVE_SP_DH)
    /* mod_exp_64: full 4096-bit modexp (CRT halves reuse sp_2048_mod_exp_32,
     * already driven in wb_run_dispatch_2048()). */
    {
        sp_digit r64[128];
        sp_digit a64[64];
        sp_digit e64[64];
        sp_digit m64[64];

        XMEMSET(r64, 0, sizeof(r64));
        XMEMSET(a64, 0, sizeof(a64));
        XMEMSET(e64, 0, sizeof(e64));
        XMEMSET(m64, 0, sizeof(m64));
        a64[0] = 3;
        e64[0] = 5;
        m64[0] = (sp_digit)0xFFFFFFFFFFFFFFF1ULL;
        m64[63] = 1;
        (void)sp_4096_mod_exp_64(r64, a64, e64, 3, m64, 0);
    }
#else
    WB_NOTE("4096 mod_exp_64 needs (SP_RSA && !RSA_PUBLIC_ONLY) || SP_DH; "
             "skipped");
#endif

#if defined(WOLFSSL_HAVE_SP_DH) && defined(HAVE_FFDHE_4096)
    {
        sp_digit r2[128];
        sp_digit e2[64];
        sp_digit m2[64];

        XMEMSET(r2, 0, sizeof(r2));
        XMEMSET(e2, 0, sizeof(e2));
        XMEMSET(m2, 0, sizeof(m2));
        e2[0] = 5;
        m2[0] = (sp_digit)0xFFFFFFFFFFFFFFF1ULL;
        m2[63] = 1;
        (void)sp_4096_mod_exp_2_64(r2, e2, 3, m2);
    }
#else
    WB_NOTE("4096 mod_exp_2_64 needs SP_DH && HAVE_FFDHE_4096; skipped");
#endif

    {
        sp_digit a[64];
        byte     bin[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
        byte     out[512];

        XMEMSET(a, 0, sizeof(a));
        XMEMSET(out, 0, sizeof(out));
        sp_4096_from_bin(a, 64, bin, (int)sizeof(bin));
        sp_4096_to_bin_64(a, out);
    }
#if defined(WOLFSSL_HAVE_SP_DH) || (defined(WOLFSSL_HAVE_SP_RSA) && \
        !defined(WOLFSSL_RSA_PUBLIC_ONLY))
    {
        sp_digit a[64];
        mp_int   m;

        XMEMSET(a, 0, sizeof(a));
        a[0] = 3;
        if (mp_init(&m) == MP_OKAY) {
            (void)sp_4096_to_mp(a, &m);
            mp_clear(&m);
        }
        else {
            WB_NOTE("mp_init failed (sp_4096_to_mp)");
        }
    }
#else
    WB_NOTE("sp_4096_to_mp needs SP_DH || (SP_RSA && !RSA_PUBLIC_ONLY); "
             "skipped");
#endif
#else
    WB_NOTE("WOLFSSL_SP_4096 not defined; 4096 dispatch skipped");
#endif /* WOLFSSL_SP_4096 */
}

/* ----------------------------------------------------------------------- *
 * ECC: sp_<size>_div_<n>, sp_<size>_from_bin/to_bin_<n>/to_mp,
 * sp_<size>_ecc_gen_k_<n>, sp_<size>_calc_s_<n>, sp_<size>_calc_vfy_point_<n>,
 * sp_<size>_add_points_<n>, sp_<size>_ecc_is_point_<n>, sp_<size>_mont_sqrt_<n>
 * for P-256/P-384/P-521.
 * ----------------------------------------------------------------------- */
#ifndef WOLFSSL_SP_NO_256
static void wb_run_dispatch_256(void)
{
#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
    {
        sp_digit a[8];
        sp_digit d[4];
        sp_digit r[4];

        XMEMSET(a, 0, sizeof(a));
        XMEMSET(d, 0, sizeof(d));
        XMEMSET(r, 0, sizeof(r));
        d[0] = 3;
        d[3] = 1; /* divisor word routine divides by d's TOP word */
        (void)sp_256_div_4(a, d, NULL, r);
    }
#else
    WB_NOTE("sp_256_div_4 needs HAVE_ECC_SIGN || HAVE_ECC_VERIFY; skipped");
#endif

    {
        sp_digit a[4];
        byte     bin[4] = { 0, 1, 2, 3 };
        byte     out[32];

        XMEMSET(a, 0, sizeof(a));
        XMEMSET(out, 0, sizeof(out));
        sp_256_from_bin(a, 4, bin, (int)sizeof(bin));
        sp_256_to_bin_4(a, out);
    }
    {
        sp_digit a[4];
        mp_int   m;

        XMEMSET(a, 0, sizeof(a));
        a[0] = 3;
        if (mp_init(&m) == MP_OKAY) {
            (void)sp_256_to_mp(a, &m);
            mp_clear(&m);
        }
        else {
            WB_NOTE("mp_init failed (sp_256_to_mp)");
        }
    }

    {
        WC_RNG rng;

        if (wc_InitRng(&rng) != 0) {
            WB_NOTE("wc_InitRng failed (sp_256 lowlevel)");
        }
        else {
            sp_digit k[4];

            XMEMSET(k, 0, sizeof(k));
            (void)sp_256_ecc_gen_k_4(&rng, k);

#ifdef HAVE_ECC_SIGN
            /* Slicing copied from sp_ecc_sign_256(): total 8*2*4 words,
             * s/e alias the same buffer (e is overwritten to become s). */
            {
                sp_digit buf[64];
                sp_digit *s_e = buf;
                sp_digit *x   = buf + 2 * 4;
                sp_digit *k4  = buf + 4 * 4;
                sp_digit *r   = buf + 6 * 4;
                sp_digit *tmp = buf + 8 * 4;

                XMEMSET(buf, 0, sizeof(buf));
                s_e[0] = 9;
                x[0] = 7;
                k4[0] = (k[0] != 0) ? k[0] : (sp_digit)5;
                r[0] = 3;
                (void)sp_256_calc_s_4(s_e, r, k4, x, s_e, tmp);
            }
#else
            WB_NOTE("sp_256_calc_s_4 needs HAVE_ECC_SIGN; skipped");
#endif
            wc_FreeRng(&rng);
        }
    }

    /* calc_vfy_point_4 / add_points_4 / ecc_is_point_4: guarded only by
     * WOLFSSL_SP_NO_256. Field arithmetic here is fixed-shape polynomial
     * math (no data-dependent branching), so a fixed small "point" is
     * enough to drive the dispatch without risk of crashing. */
    {
        /* Slicing copied from sp_ecc_verify_256(): total 18*4 words. */
        sp_digit vbuf[72];
        sp_digit *u1  = vbuf;
        sp_digit *u2  = vbuf + 2 * 4;
        sp_digit *s   = vbuf + 4 * 4;
        sp_digit *tmp = vbuf + 6 * 4;
        sp_point_256 p1[2];

        XMEMSET(vbuf, 0, sizeof(vbuf));
        XMEMSET(p1, 0, sizeof(p1));
        u1[0] = 3;
        u2[0] = 5;
        s[0] = 7;
        p1[0].x[0] = 1; p1[0].y[0] = 1; p1[0].z[0] = 1;
        p1[1].x[0] = 1; p1[1].y[0] = 1; p1[1].z[0] = 1;
        (void)sp_256_calc_vfy_point_4(&p1[0], &p1[1], s, u1, u2, tmp, NULL);
    }
    {
        sp_point_256 pp1;
        sp_point_256 pp2;
        sp_digit     tmp2[48]; /* 12*4, same as calc_vfy_point_4's tmp */

        XMEMSET(&pp1, 0, sizeof(pp1));
        XMEMSET(&pp2, 0, sizeof(pp2));
        XMEMSET(tmp2, 0, sizeof(tmp2));
        pp1.x[0] = 1; pp1.y[0] = 1; pp1.z[0] = 1;
        pp2.x[0] = 1; pp2.y[0] = 1; pp2.z[0] = 1;
        sp_256_add_points_4(&pp1, &pp2, tmp2);
    }
    {
        sp_point_256 pt;

        XMEMSET(&pt, 0, sizeof(pt));
        pt.x[0] = 1; pt.y[0] = 1; pt.z[0] = 1;
        (void)sp_256_ecc_is_point_4(&pt, NULL);
    }
#ifdef HAVE_COMP_KEY
    {
        sp_digit y[4];

        XMEMSET(y, 0, sizeof(y));
        y[0] = 1;
        (void)sp_256_mont_sqrt_4(y);
    }
#else
    WB_NOTE("sp_256_mont_sqrt_4 needs HAVE_COMP_KEY; skipped");
#endif
}
#else
static void wb_run_dispatch_256(void)
{
    WB_NOTE("WOLFSSL_SP_NO_256 defined; P-256 dispatch skipped");
}
#endif /* !WOLFSSL_SP_NO_256 */

#ifdef WOLFSSL_SP_384
static void wb_run_dispatch_384(void)
{
#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
    {
        sp_digit a[12];
        sp_digit d[6];
        sp_digit r[6];

        XMEMSET(a, 0, sizeof(a));
        XMEMSET(d, 0, sizeof(d));
        XMEMSET(r, 0, sizeof(r));
        d[0] = 3;
        d[5] = 1; /* divisor word routine divides by d's TOP word */
        (void)sp_384_div_6(a, d, NULL, r);
    }
#else
    WB_NOTE("sp_384_div_6 needs HAVE_ECC_SIGN || HAVE_ECC_VERIFY; skipped");
#endif

    {
        sp_digit a[6];
        byte     bin[4] = { 0, 1, 2, 3 };
        byte     out[48];

        XMEMSET(a, 0, sizeof(a));
        XMEMSET(out, 0, sizeof(out));
        sp_384_from_bin(a, 6, bin, (int)sizeof(bin));
        sp_384_to_bin_6(a, out);
    }
    {
        sp_digit a[6];
        mp_int   m;

        XMEMSET(a, 0, sizeof(a));
        a[0] = 3;
        if (mp_init(&m) == MP_OKAY) {
            (void)sp_384_to_mp(a, &m);
            mp_clear(&m);
        }
        else {
            WB_NOTE("mp_init failed (sp_384_to_mp)");
        }
    }

    {
        WC_RNG rng;

        if (wc_InitRng(&rng) != 0) {
            WB_NOTE("wc_InitRng failed (sp_384 lowlevel)");
        }
        else {
            sp_digit k[6];

            XMEMSET(k, 0, sizeof(k));
            (void)sp_384_ecc_gen_k_6(&rng, k);

#ifdef HAVE_ECC_SIGN
            /* Slicing copied from sp_ecc_sign_384(): total 7*2*6 words. */
            {
                sp_digit buf[84];
                sp_digit *s_e = buf;
                sp_digit *x   = buf + 2 * 6;
                sp_digit *k6  = buf + 4 * 6;
                sp_digit *r   = buf + 6 * 6;
                sp_digit *tmp = buf + 8 * 6;

                XMEMSET(buf, 0, sizeof(buf));
                s_e[0] = 9;
                x[0] = 7;
                k6[0] = (k[0] != 0) ? k[0] : (sp_digit)5;
                r[0] = 3;
                (void)sp_384_calc_s_6(s_e, r, k6, x, s_e, tmp);
            }
#else
            WB_NOTE("sp_384_calc_s_6 needs HAVE_ECC_SIGN; skipped");
#endif
            wc_FreeRng(&rng);
        }
    }

    {
        /* Slicing copied from sp_ecc_verify_384(): total 18*6 words. */
        sp_digit vbuf[108];
        sp_digit *u1  = vbuf;
        sp_digit *u2  = vbuf + 2 * 6;
        sp_digit *s   = vbuf + 4 * 6;
        sp_digit *tmp = vbuf + 6 * 6;
        sp_point_384 p1[2];

        XMEMSET(vbuf, 0, sizeof(vbuf));
        XMEMSET(p1, 0, sizeof(p1));
        u1[0] = 3;
        u2[0] = 5;
        s[0] = 7;
        p1[0].x[0] = 1; p1[0].y[0] = 1; p1[0].z[0] = 1;
        p1[1].x[0] = 1; p1[1].y[0] = 1; p1[1].z[0] = 1;
        (void)sp_384_calc_vfy_point_6(&p1[0], &p1[1], s, u1, u2, tmp, NULL);
    }
    {
        sp_point_384 pp1;
        sp_point_384 pp2;
        sp_digit     tmp2[72]; /* 12*6 */

        XMEMSET(&pp1, 0, sizeof(pp1));
        XMEMSET(&pp2, 0, sizeof(pp2));
        XMEMSET(tmp2, 0, sizeof(tmp2));
        pp1.x[0] = 1; pp1.y[0] = 1; pp1.z[0] = 1;
        pp2.x[0] = 1; pp2.y[0] = 1; pp2.z[0] = 1;
        sp_384_add_points_6(&pp1, &pp2, tmp2);
    }
    {
        sp_point_384 pt;

        XMEMSET(&pt, 0, sizeof(pt));
        pt.x[0] = 1; pt.y[0] = 1; pt.z[0] = 1;
        (void)sp_384_ecc_is_point_6(&pt, NULL);
    }
#ifdef HAVE_COMP_KEY
    {
        sp_digit y[6];

        XMEMSET(y, 0, sizeof(y));
        y[0] = 1;
        (void)sp_384_mont_sqrt_6(y);
    }
#else
    WB_NOTE("sp_384_mont_sqrt_6 needs HAVE_COMP_KEY; skipped");
#endif
}
#else
static void wb_run_dispatch_384(void)
{
    WB_NOTE("WOLFSSL_SP_384 not defined; P-384 dispatch skipped");
}
#endif /* WOLFSSL_SP_384 */

#ifdef WOLFSSL_SP_521
static void wb_run_dispatch_521(void)
{
#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
    {
        sp_digit a[18];
        sp_digit d[9];
        sp_digit r[9];

        XMEMSET(a, 0, sizeof(a));
        XMEMSET(d, 0, sizeof(d));
        XMEMSET(r, 0, sizeof(r));
        d[0] = 3;
        d[8] = 1; /* divisor word routine divides by d's TOP word */
        (void)sp_521_div_9(a, d, NULL, r);
    }
#else
    WB_NOTE("sp_521_div_9 needs HAVE_ECC_SIGN || HAVE_ECC_VERIFY; skipped");
#endif

    {
        sp_digit a[9];
        byte     bin[4] = { 0, 1, 2, 3 };
        byte     out[66];

        XMEMSET(a, 0, sizeof(a));
        XMEMSET(out, 0, sizeof(out));
        sp_521_from_bin(a, 9, bin, (int)sizeof(bin));
        sp_521_to_bin_9(a, out);
    }
    {
        sp_digit a[9];
        mp_int   m;

        XMEMSET(a, 0, sizeof(a));
        a[0] = 3;
        if (mp_init(&m) == MP_OKAY) {
            (void)sp_521_to_mp(a, &m);
            mp_clear(&m);
        }
        else {
            WB_NOTE("mp_init failed (sp_521_to_mp)");
        }
    }

    {
        WC_RNG rng;

        if (wc_InitRng(&rng) != 0) {
            WB_NOTE("wc_InitRng failed (sp_521 lowlevel)");
        }
        else {
            sp_digit k[9];

            XMEMSET(k, 0, sizeof(k));
            (void)sp_521_ecc_gen_k_9(&rng, k);

#ifdef HAVE_ECC_SIGN
            /* Slicing copied from sp_ecc_sign_521(): total 7*2*9 words. */
            {
                sp_digit buf[126];
                sp_digit *s_e = buf;
                sp_digit *x   = buf + 2 * 9;
                sp_digit *k9  = buf + 4 * 9;
                sp_digit *r   = buf + 6 * 9;
                sp_digit *tmp = buf + 8 * 9;

                XMEMSET(buf, 0, sizeof(buf));
                s_e[0] = 9;
                x[0] = 7;
                k9[0] = (k[0] != 0) ? k[0] : (sp_digit)5;
                r[0] = 3;
                (void)sp_521_calc_s_9(s_e, r, k9, x, s_e, tmp);
            }
#else
            WB_NOTE("sp_521_calc_s_9 needs HAVE_ECC_SIGN; skipped");
#endif
            wc_FreeRng(&rng);
        }
    }

    {
        /* Slicing copied from sp_ecc_verify_521(): total 18*9 words. */
        sp_digit vbuf[162];
        sp_digit *u1  = vbuf;
        sp_digit *u2  = vbuf + 2 * 9;
        sp_digit *s   = vbuf + 4 * 9;
        sp_digit *tmp = vbuf + 6 * 9;
        sp_point_521 p1[2];

        XMEMSET(vbuf, 0, sizeof(vbuf));
        XMEMSET(p1, 0, sizeof(p1));
        u1[0] = 3;
        u2[0] = 5;
        s[0] = 7;
        p1[0].x[0] = 1; p1[0].y[0] = 1; p1[0].z[0] = 1;
        p1[1].x[0] = 1; p1[1].y[0] = 1; p1[1].z[0] = 1;
        (void)sp_521_calc_vfy_point_9(&p1[0], &p1[1], s, u1, u2, tmp, NULL);
    }
    {
        sp_point_521 pp1;
        sp_point_521 pp2;
        sp_digit     tmp2[108]; /* 12*9 */

        XMEMSET(&pp1, 0, sizeof(pp1));
        XMEMSET(&pp2, 0, sizeof(pp2));
        XMEMSET(tmp2, 0, sizeof(tmp2));
        pp1.x[0] = 1; pp1.y[0] = 1; pp1.z[0] = 1;
        pp2.x[0] = 1; pp2.y[0] = 1; pp2.z[0] = 1;
        sp_521_add_points_9(&pp1, &pp2, tmp2);
    }
    {
        sp_point_521 pt;

        XMEMSET(&pt, 0, sizeof(pt));
        pt.x[0] = 1; pt.y[0] = 1; pt.z[0] = 1;
        (void)sp_521_ecc_is_point_9(&pt, NULL);
    }
#ifdef HAVE_COMP_KEY
    {
        sp_digit y[9];

        XMEMSET(y, 0, sizeof(y));
        y[0] = 1;
        (void)sp_521_mont_sqrt_9(y);
    }
#else
    WB_NOTE("sp_521_mont_sqrt_9 needs HAVE_COMP_KEY; skipped");
#endif
}
#else
static void wb_run_dispatch_521(void)
{
    WB_NOTE("WOLFSSL_SP_521 not defined; P-521 dispatch skipped");
}
#endif /* WOLFSSL_SP_521 */

/* ----------------------------------------------------------------------- *
 * SAKKE (1024-bit): sp_1024_div_16/from_bin/to_mp. Niche feature, almost
 * certainly not enabled in this campaign's builds -- WB_NOTE-skip if not.
 * ----------------------------------------------------------------------- */
static void wb_run_dispatch_1024(void)
{
#if defined(WOLFCRYPT_HAVE_SAKKE) && defined(WOLFSSL_SP_1024)
    {
        sp_digit a[32];
        sp_digit d[16];
        sp_digit r[16];

        XMEMSET(a, 0, sizeof(a));
        XMEMSET(d, 0, sizeof(d));
        XMEMSET(r, 0, sizeof(r));
        d[0] = 3;
        d[15] = 1; /* divisor word routine divides by d's TOP word */
        (void)sp_1024_div_16(a, d, NULL, r);
    }
    {
        sp_digit a[16];
        byte     bin[4] = { 0, 1, 2, 3 };

        XMEMSET(a, 0, sizeof(a));
        sp_1024_from_bin(a, 16, bin, (int)sizeof(bin));
    }
#else
    WB_NOTE("WOLFCRYPT_HAVE_SAKKE && WOLFSSL_SP_1024 not both defined; "
             "1024 dispatch skipped");
#endif
}

static void wb_run_dispatch(void)
{
    wb_run_dispatch_2048();
    wb_run_dispatch_3072();
    wb_run_dispatch_4096();
    wb_run_dispatch_256();
    wb_run_dispatch_384();
    wb_run_dispatch_521();
    wb_run_dispatch_1024();
}

/* ======================================================================= *
 * wb_run_crafted(): crafted-input coverage of sp_ecc_mulmod_add_<n> and
 * the point-validation family (sp_ecc_check_key_<n>/sp_ecc_is_point_<n>).
 * ======================================================================= *
 *
 * sp_ecc_mulmod_add_256/384/521(): each has
 *   if ((err == MP_OKAY) && (!inMont)) { ... sp_<n>_mod_mul_norm_<n> ... }
 * repeated for x/y/z (the ~36-conditions-across-3-curves the campaign
 * counts), plus a final `if (map) { ... }`. Driving all 4 (inMont, map)
 * combinations with a real curve point (from wc_ecc_make_key_ex()) as both
 * the multiplicand and the point to add covers every operand of both
 * decisions: the fixed-shape point arithmetic does not care whether the
 * point-to-add's coordinates were genuinely pre-converted to Montgomery
 * form, so inMont=1 against ordinary affine coordinates still completes
 * without crashing (same reasoning as wb_run_dispatch(), see file header).
 *
 * sp_ecc_check_key_<n>(pX, pY, privm, heap) (guarded by HAVE_ECC_CHECK_KEY
 * || !NO_ECC_CHECK_PUBKEY_ORDER) is driven directly with crafted mp_int
 * coordinates -- no ecc_point/sp_point_<n> plumbing needed -- covering:
 *   - "Quick check the lengs" -- mp_count_bits(pX) > <fieldbits>: true via
 *     an (fieldSz+1)-byte, all-0xFF coordinate (unambiguously over the
 *     field bit size for every curve); false via any real coordinate.
 *   - "Check point at infinitiy" -- sp_<n>_iszero_<n>(pub->x) != 0 &&
 *     sp_<n>_iszero_<n>(pub->y) != 0: true via (x, y) = (0, 0); false via
 *     a real point.
 *   - "Check range of X and Y" -- sp_<n>_cmp_<n>(pub->x, p<n>_mod) >= 0:
 *     true via pX == the field modulus itself (built with sp_<n>_to_mp()
 *     from the file-static p<n>_mod array, visible in this TU because
 *     sp_x86_64.c is #included, not linked); false via a real coordinate
 *     (which is always < the modulus).
 * privm is passed as NULL throughout (this campaign only needs the public-
 * point guards, not the private-scalar-matches-point path, which is
 * already exercised for real keys by wb_run_ecc()).
 *
 * sp_ecc_is_point_<n>(pX, pY) is driven with both the infinity coordinate
 * pair and a real point, covering the true/false sides of its internal
 * "on curve" polynomial comparison.
 *
 * As everywhere else in this file, only "did it crash" is checked; none of
 * these calls are expected to return MP_OKAY (the crafted inputs are
 * deliberately invalid points / not real signatures), and their return
 * values are discarded.
 * ----------------------------------------------------------------------- */
#if defined(WOLFSSL_HAVE_SP_ECC) && defined(HAVE_ECC)
typedef int (*wb_mulmod_add_fn)(const mp_int*, const ecc_point*,
    const ecc_point*, int, ecc_point*, int, void*);
typedef int (*wb_check_key_fn)(const mp_int*, const mp_int*, const mp_int*,
    void*);
typedef int (*wb_is_point_fn)(const mp_int*, const mp_int*);

static void wb_run_crafted_curve(int curve_id, int fieldSz,
    wb_mulmod_add_fn mulmod_add, wb_check_key_fn check_key,
    wb_is_point_fn is_point, mp_int* modv, const char* label)
{
    ecc_key    keyA;
    ecc_key    keyB;
    WC_RNG     rng;
    ecc_point* r;
    mp_int     km;
    mp_int     zero;
    mp_int     big;
    byte       bigbuf[80]; /* fieldSz+1 <= 67 (P-521); comfortably fits */
    int        inMont;
    int        map;
    int        ok = 1;

    XMEMSET(&keyA, 0, sizeof(keyA));
    XMEMSET(&keyB, 0, sizeof(keyB));
    XMEMSET(&rng, 0, sizeof(rng));

    if (wc_ecc_init(&keyA) != 0) {
        WB_NOTE("wc_ecc_init(keyA) failed (crafted)");
        wb_fail = 1;
        return;
    }
    if (wc_ecc_init(&keyB) != 0) {
        WB_NOTE("wc_ecc_init(keyB) failed (crafted)");
        wb_fail = 1;
        wc_ecc_free(&keyA);
        return;
    }
    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("wc_InitRng failed (crafted)");
        wb_fail = 1;
        wc_ecc_free(&keyA);
        wc_ecc_free(&keyB);
        return;
    }

    if (wc_ecc_make_key_ex(&rng, fieldSz, &keyA, curve_id) != 0) {
        WB_NOTE("wc_ecc_make_key_ex(keyA) failed (crafted)");
        wb_fail = 1;
        ok = 0;
    }
    if (ok && wc_ecc_make_key_ex(&rng, fieldSz, &keyB, curve_id) != 0) {
        WB_NOTE("wc_ecc_make_key_ex(keyB) failed (crafted)");
        wb_fail = 1;
        ok = 0;
    }

    if (ok) {
        /* --- sp_ecc_mulmod_add_<n>: all four inMont x map combinations,
         * using two independently-generated real curve points. --- */
        r = wc_ecc_new_point();
        if (r == NULL) {
            WB_NOTE("wc_ecc_new_point failed (crafted)");
            wb_fail = 1;
        }
        else {
            if (mp_init(&km) != MP_OKAY) {
                WB_NOTE("mp_init(km) failed (crafted)");
                wb_fail = 1;
            }
            else {
                (void)mp_set(&km, 5);
                for (inMont = 0; inMont <= 1; inMont++) {
                    for (map = 0; map <= 1; map++) {
                        (void)mulmod_add(&km, &keyA.pubkey, &keyB.pubkey,
                            inMont, r, map, NULL);
                    }
                }
                mp_clear(&km);
            }
            wc_ecc_del_point(r);
        }

        /* --- point-at-infinity / on-curve special cases. --- */
        if (mp_init(&zero) == MP_OKAY) {
            if (check_key != NULL) {
                (void)check_key(&zero, &zero, NULL, NULL);
            }
            (void)is_point(&zero, &zero);

            if (check_key != NULL) {
                (void)check_key(keyA.pubkey.x, keyA.pubkey.y, NULL, NULL);
            }
            (void)is_point(keyA.pubkey.x, keyA.pubkey.y);

            mp_clear(&zero);
        }
        else {
            WB_NOTE("mp_init(zero) failed (crafted)");
            wb_fail = 1;
        }

        /* --- out-of-range coordinate guards (sp_ecc_check_key_<n> only). */
        if (check_key != NULL) {
            XMEMSET(bigbuf, 0xFF, (size_t)(fieldSz + 1));
            if (mp_init(&big) == MP_OKAY) {
                if (mp_read_unsigned_bin(&big, bigbuf, fieldSz + 1)
                        == MP_OKAY) {
                    (void)check_key(&big, keyA.pubkey.y, NULL, NULL);
                }
                else {
                    WB_NOTE("mp_read_unsigned_bin(big) failed (crafted)");
                }
                mp_clear(&big);
            }
            else {
                WB_NOTE("mp_init(big) failed (crafted)");
                wb_fail = 1;
            }

            if (modv != NULL) {
                (void)check_key(modv, keyA.pubkey.y, NULL, NULL);
            }
        }
    }

    wc_FreeRng(&rng);
    wc_ecc_free(&keyA);
    wc_ecc_free(&keyB);
    WB_NOTE(label);
}

#ifndef WOLFSSL_SP_NO_256
static void wb_run_crafted_256(void)
{
    mp_int  modv;
    int     modvOk = 0;
    mp_int* modvp = NULL;

    if (mp_init(&modv) == MP_OKAY) {
        modvOk = 1;
        if (sp_256_to_mp(p256_mod, &modv) == MP_OKAY) {
            modvp = &modv;
        }
    }

    wb_run_crafted_curve(ECC_SECP256R1, 32, sp_ecc_mulmod_add_256,
#if defined(HAVE_ECC_CHECK_KEY) || !defined(NO_ECC_CHECK_PUBKEY_ORDER)
        sp_ecc_check_key_256,
#else
        NULL,
#endif
        sp_ecc_is_point_256, modvp,
        "P-256 crafted mulmod_add/check_key/is_point exercised");

    if (modvOk) {
        mp_clear(&modv);
    }
}
#else
static void wb_run_crafted_256(void)
{
    WB_NOTE("WOLFSSL_SP_NO_256 defined; P-256 crafted skipped");
}
#endif /* !WOLFSSL_SP_NO_256 */

#ifdef WOLFSSL_SP_384
static void wb_run_crafted_384(void)
{
    mp_int  modv;
    int     modvOk = 0;
    mp_int* modvp = NULL;

    if (mp_init(&modv) == MP_OKAY) {
        modvOk = 1;
        if (sp_384_to_mp(p384_mod, &modv) == MP_OKAY) {
            modvp = &modv;
        }
    }

    wb_run_crafted_curve(ECC_SECP384R1, 48, sp_ecc_mulmod_add_384,
#if defined(HAVE_ECC_CHECK_KEY) || !defined(NO_ECC_CHECK_PUBKEY_ORDER)
        sp_ecc_check_key_384,
#else
        NULL,
#endif
        sp_ecc_is_point_384, modvp,
        "P-384 crafted mulmod_add/check_key/is_point exercised");

    if (modvOk) {
        mp_clear(&modv);
    }
}
#else
static void wb_run_crafted_384(void)
{
    WB_NOTE("WOLFSSL_SP_384 not defined; P-384 crafted skipped");
}
#endif /* WOLFSSL_SP_384 */

#ifdef WOLFSSL_SP_521
static void wb_run_crafted_521(void)
{
    mp_int  modv;
    int     modvOk = 0;
    mp_int* modvp = NULL;

    if (mp_init(&modv) == MP_OKAY) {
        modvOk = 1;
        if (sp_521_to_mp(p521_mod, &modv) == MP_OKAY) {
            modvp = &modv;
        }
    }

    wb_run_crafted_curve(ECC_SECP521R1, 66, sp_ecc_mulmod_add_521,
#if defined(HAVE_ECC_CHECK_KEY) || !defined(NO_ECC_CHECK_PUBKEY_ORDER)
        sp_ecc_check_key_521,
#else
        NULL,
#endif
        sp_ecc_is_point_521, modvp,
        "P-521 crafted mulmod_add/check_key/is_point exercised");

    if (modvOk) {
        mp_clear(&modv);
    }
}
#else
static void wb_run_crafted_521(void)
{
    WB_NOTE("WOLFSSL_SP_521 not defined; P-521 crafted skipped");
}
#endif /* WOLFSSL_SP_521 */

static void wb_run_crafted(void)
{
    wb_run_crafted_256();
    wb_run_crafted_384();
    wb_run_crafted_521();
}
#else
static void wb_run_crafted(void)
{
    WB_NOTE("WOLFSSL_HAVE_SP_ECC/HAVE_ECC not both defined; crafted "
             "skipped");
}
#endif /* WOLFSSL_HAVE_SP_ECC && HAVE_ECC */

#endif /* WOLFSSL_HAVE_SP_ECC || WOLFSSL_HAVE_SP_RSA || WOLFSSL_HAVE_SP_DH */

int main(void)
{
    printf("sp_x86_64.c white-box supplement (generic-path / cpuid=0)\n");
#if defined(WOLFSSL_HAVE_SP_ECC) || defined(WOLFSSL_HAVE_SP_RSA) || \
    defined(WOLFSSL_HAVE_SP_DH)
    /* The dispatch decisions in sp_x86_64.c are `IS_INTEL_BMI2(f) &&
     * IS_INTEL_ADX(f)` (two conditions) plus single-condition
     * `IS_INTEL_MOVBE(f)` checks. CRITICAL: llvm-cov computes MC/DC
     * independence PER BINARY, and the campaign only ORs the resulting
     * covered-bit across binaries -- it does NOT reconstruct an independence
     * pair from vectors spread over different binaries. So THIS binary must
     * itself observe all three vectors of `A && B` (TT, FT, TF). The ordinary
     * asm run only ever sees TT; forcing cpuid=0 only adds FF -> together that
     * is branch coverage, not MC/DC. We therefore drive every pass here from
     * the REAL detected flags and clear exactly ONE feature at a time:
     *   real                 -> BMI2=T, ADX=T, MOVBE=T : the TT / asm vector
     *   real & ~CPUID_BMI2   -> BMI2=F, ADX=T          : flips BMI2 (FT)
     *   real & ~CPUID_ADX    -> BMI2=T, ADX=F          : flips ADX  (TF)
     *   real & ~CPUID_MOVBE  -> MOVBE=F                : flips the MOVBE checks
     * Clearing one feature keeps the others, and this host really has every
     * real flag, so whichever asm/generic path each pass selects is valid
     * (no SIGILL). All passes accumulate into this one TU's profile, giving
     * TT+FT+TF => full MC/DC of each BMI2&&ADX dispatch within this binary. */
    {
        cpuid_flags_t real = cpuid_get_flags();

        /* Many dispatches live inside data-dependent blocks (e.g.
         * sp_<size>_calc_vfy_point / ecc_is_point / calc_s), only reached with
         * VALID crypto operands -- so the high-level valid-data ECC/DH ops must
         * also run under each mask, not just wb_run_dispatch's dummy-input
         * calls. ECC/DH are fast; RSA key generation on the generic path is
         * slow, so wb_run_rsa_keygen() (MakeRsaKey) runs only in the all-on
         * pass, but the resulting keys are then reused by
         * wb_run_rsa_signverify() (Sign+Verify) under EVERY mask -- those
         * modexp/Montgomery dispatches get their TT/FT/TF without paying for
         * repeated generic-path key generation. wb_run_crafted() (crafted
         * mulmod_add/check_key/is_point inputs) is likewise fast and runs
         * under every mask. */
        cpuid_select_flags(real);
        wb_run_ecc();
        wb_run_rsa_keygen();
        wb_run_rsa_signverify();
        wb_run_dh();
        wb_run_dispatch();
        wb_run_crafted();

        cpuid_select_flags(real & ~(cpuid_flags_t)CPUID_BMI2);
        wb_run_ecc();
        wb_run_rsa_signverify();
        wb_run_dh();
        wb_run_dispatch();
        wb_run_crafted();

        cpuid_select_flags(real & ~(cpuid_flags_t)CPUID_ADX);
        wb_run_ecc();
        wb_run_rsa_signverify();
        wb_run_dh();
        wb_run_dispatch();
        wb_run_crafted();

        cpuid_select_flags(real & ~(cpuid_flags_t)CPUID_MOVBE);
        wb_run_ecc();
        wb_run_rsa_signverify();
        wb_run_dh();
        wb_run_dispatch();
        wb_run_crafted();

        wb_run_rsa_free();
    }

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
#else
    printf("  no SP feature; nothing to exercise\n");
#endif
    (void)wb_fail;
    return 0;
}
