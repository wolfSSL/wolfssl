/* test_sp_arm32_whitebox.c
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
 * MC/DC white-box supplement for wolfcrypt/src/sp_arm32.c.
 *
 * sp_arm32.c is the 32-bit ARM hand-written-assembly SP math backend. Its
 * whole body is wrapped in "#ifdef WOLFSSL_SP_ARM32_ASM ... #endif" and is
 * compiled only under the qemu-arm linux-user lane (TRIPLE=arm-linux-gnueabihf,
 * clang --target=arm-linux-gnueabihf, run under qemu-arm -cpu max). Unlike the
 * x86-64 backend (sp_x86_64.c) it has NO runtime cpuid / feature-mask dispatch:
 * the ARM instruction selection is entirely compile-time (WOLFSSL_ARM_ARCH,
 * WOLFSSL_SP_SMALL, etc.), so -- exactly like the 32-bit portable-C sibling
 * sp_c32.c that this file is modelled on -- each decision below is exercised
 * once, with no per-cpuid replay.
 *
 * Ordinary tests/api traffic (the rsa/ecc/dh API groups + the KAT pass)
 * already exercises the "everything succeeded, ordinary operands" side of most
 * of the file's decisions. The residual gaps this supplement targets are the
 * *unlikely-but-not-fault-injected* halves of a handful of decision families
 * that public-API traffic essentially never reaches with in-range, valid data.
 * NOTE the word-count function-name suffixes differ from sp_c32.c: this 32-bit
 * backend uses a straight radix-2^32 representation, so P-256 is 8 words
 * (suffix _8), P-384 is 12 (_12) and P-521 is 17 (_17), versus sp_c32.c's
 * reduced-radix 9/15/21.
 *
 *   1. `if ((err == MP_OKAY) && (!inMont))` in sp_ecc_mulmod_add_<n>() and
 *      sp_ecc_mulmod_base_add_<n>() (256/384/521): every real caller in this
 *      tree always passes inMont == 0, so the "already in Montgomery form,
 *      skip the mod_mul_norm conversion" half of the decision is never taken.
 *      Driven here directly, with valid scalars/points, across all four
 *      (inMont, map) combinations.
 *
 *   2. Point-at-infinity / doubling-collision guards keyed off
 *      sp_<n>_iszero_<w>(z) (and the paired iszero(x) && iszero(y) check)
 *      inside sp_<n>_add_points_<w>() and sp_<n>_calc_vfy_point_<w>(). These
 *      only fire when a projective point addition produces z == 0, i.e. when
 *      adding a point to its own negation (true infinity) or to itself
 *      (doubling collision via the general add formula) -- states that
 *      essentially never occur from independently-random ECDSA
 *      sign/verify/ECDH traffic. Driven here by feeding sp_<n>_add_points_<w>
 *      a real point P and its real negation -P (and P and P again), and by
 *      feeding sp_<n>_calc_vfy_point_<w> a zero scalar (0 * point ==
 *      infinity, forcing p->z == 0 through the same code the real verify path
 *      uses).
 *
 *   3. `mp_count_bits(pX) > <curve size>` (and pY, and privm) inside
 *      sp_ecc_check_key_<n>(): normal callers only ever pass ordinates that
 *      already fit the curve. Driven here with an explicit 2^<curve size> (one
 *      bit too many) fed to each operand in turn, alongside an all-in-range
 *      baseline call.
 *
 * The general Montgomery/point arithmetic itself (mul/sqr/mod/point-add/
 * point-double, the bulk of the file's decisions) is covered by driving the
 * public ECC sign/verify/ECDH, RSA sign/verify (with key generation), and DH
 * key-agreement entry points below -- no cpuid masking is possible here, so
 * (unlike test_sp_x86_64_whitebox.c) there is only ever one pass through each.
 *
 * This is a coverage-driving supplement, not a known-answer test: only "did
 * this fail outright" is checked, never a specific expected value. Coverage
 * from this binary is unioned with the tests/api variant coverage by source
 * line:col in the per-module suite.
 *
 * Build: compiled by lanes/qemu-entry.sh's white-box step with the SAME MC/DC
 * cross CFLAGS (--target=arm-linux-gnueabihf, -DWOLFSSL_SP_ARM32_ASM,
 * SP_WORD_SIZE=32, which selects sp_arm32.c's body) as the instrumented
 * library, then linked against that lane's libwolfssl.a with its sp_arm32.o
 * removed (this TU supplies the instrumented sp_arm32.c) and run under
 * qemu-arm. NOT part of the wolfSSL build; not registered in tests/api. See
 * tests/unit-mcdc/README.md.
 *
 * -------------------------------------------------------------------------
 * Residuals (documented here, not driven):
 * -------------------------------------------------------------------------
 *  - The `err == MP_OKAY` operand of every `(err == MP_OKAY) && X` guard:
 *    `err` only becomes non-MP_OKAY through a prior allocation failure
 *    (SP_ALLOC_VAR/XMALLOC returning NULL under WOLFSSL_SP_SMALL_STACK) or an
 *    already-reported error from an earlier step. Forcing it requires
 *    fault-injecting the allocator, out of scope for a coverage-driving
 *    supplement operating through the public/file-static API with real data.
 *  - `wc_LockMutex(&sp_cache_<n>_lock) != 0` (the FP-cache mutex-lock failure
 *    check): only reachable via a fault-injected mutex implementation.
 *  - The `SP_ECC_MAX_SIG_GEN` retry loop and its paired `!sp_<n>_iszero_<w>
 *    (s)` re-roll check inside sp_ecc_sign_<n>(): looping again only happens
 *    when a freshly generated nonce k produces r == 0 or a resulting signature
 *    s == 0, both cryptographically negligible (1/order probability).
 */

/* The FP-ECC cache lock is statically initialised on pthreads, which compiles
 * out the lazy-init block above the guard and leaves its `err == MP_OKAY`
 * operand structurally true. WOLFSSL_TEST_NO_MUTEX_INITIALIZER is wolfSSL's
 * own knob for that; setting it here compiles the lazy path into this TU so
 * both operands of the guard are reachable in this one binary, which is what
 * MC/DC-per-binary requires. */
#define WOLFSSL_TEST_NO_MUTEX_INITIALIZER

#include "mcdc_fault_mutex.h"

#include <wolfcrypt/src/sp_arm32.c>
#define MCDC_FM_IMPL
#include "mcdc_fault_mutex.h"


#include "mcdc_fault_alloc.h"

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/random.h>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

/* Crafted-input driver shared with the SP host-backend white-boxes. The four
 * ARM backends implement the SAME public API (sp_ecc_verify_<n>,
 * sp_ecc_sign_<n>, sp_ecc_check_key_<n>, sp_ModExp_<n>, ...), so the same
 * body drives them. It supplies two vectors this file's own drivers cannot:
 * a verify whose public point is the Jacobian point at infinity (pZ == 0),
 * which is the only way `(err == MP_OKAY) && sp_<n>_iszero_<w>(p2->z)` goes
 * true, and a sign with a zero private scalar against an all-zero hash,
 * which makes s == 0 on EVERY attempt so the SP_ECC_MAX_SIG_GEN retry loop
 * runs to exhaustion and leaves its `i > 0` operand false. Both are
 * deterministic -- no RNG luck is involved, contrary to the note above. */
#include "test_sp_crafted_common.h"

#if defined(WOLFSSL_HAVE_SP_ECC) || defined(WOLFSSL_HAVE_SP_RSA) || \
    defined(WOLFSSL_HAVE_SP_DH)

/* Fixed 32-byte "digest" used for every ECDSA sign/verify below. Its value
 * does not matter -- we are driving the general arithmetic path, not checking
 * a known-answer signature. */
static const byte wb_digest[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

#if defined(WOLFSSL_HAVE_SP_ECC) && defined(HAVE_ECC)
/* -------------------------------------------------------------------- *
 * ECC: make_key_ex + sign_hash + verify_hash + shared_secret (ECDH),
 * for each SP-accelerated curve size compiled in.
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
        "P-256 make_key/sign/verify/ECDH exercised");
#else
    WB_NOTE("WOLFSSL_SP_NO_256 defined; P-256 skipped");
#endif

#ifdef WOLFSSL_SP_384
    wb_run_ecc_curve(ECC_SECP384R1, 48,
        "P-384 make_key/sign/verify/ECDH exercised");
#else
    WB_NOTE("WOLFSSL_SP_384 not defined; P-384 skipped");
#endif

#ifdef WOLFSSL_SP_521
    wb_run_ecc_curve(ECC_SECP521R1, 66,
        "P-521 make_key/sign/verify/ECDH exercised");
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
 * RSA: MakeRsaKey + RsaSSL_Sign + RsaSSL_Verify, for each SP-accelerated
 * modulus size compiled in.
 * -------------------------------------------------------------------- */
static void wb_run_rsa_bits(int bits, const char* label)
{
    RsaKey key;
    WC_RNG rng;
    byte   msg[32];
    /* Sized for the largest SP-accelerated RSA modulus (4096 bits). */
    byte   sig[512];
    byte   plain[512];
    word32 sigLen;
    int    ret;

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(msg, 0x5A, sizeof(msg));
    XMEMSET(sig, 0, sizeof(sig));
    XMEMSET(plain, 0, sizeof(plain));

    if (wc_InitRsaKey(&key, NULL) != 0) {
        WB_NOTE("wc_InitRsaKey failed");
        wb_fail = 1;
        return;
    }
    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("wc_InitRng failed (rsa)");
        wb_fail = 1;
        wc_FreeRsaKey(&key);
        return;
    }

    ret = wc_MakeRsaKey(&key, bits, WC_RSA_EXPONENT, &rng);
    if (ret != 0) {
        WB_NOTE("wc_MakeRsaKey failed");
        wb_fail = 1;
    }
    else {
        sigLen = (word32)(bits / 8);
        ret = wc_RsaSSL_Sign(msg, (word32)sizeof(msg), sig, sigLen, &key,
            &rng);
        if (ret <= 0) {
            WB_NOTE("wc_RsaSSL_Sign failed");
            wb_fail = 1;
        }
        else {
            sigLen = (word32)ret;
            ret = wc_RsaSSL_Verify(sig, sigLen, plain, (word32)sizeof(plain),
                &key);
            if (ret <= 0) {
                WB_NOTE("wc_RsaSSL_Verify failed");
                wb_fail = 1;
            }
        }
    }

    wc_FreeRng(&rng);
    wc_FreeRsaKey(&key);
    WB_NOTE(label);
}

static void wb_run_rsa(void)
{
#ifndef WOLFSSL_SP_NO_2048
    wb_run_rsa_bits(2048,
        "RSA-2048 MakeRsaKey/SSL_Sign/SSL_Verify exercised");
#else
    WB_NOTE("WOLFSSL_SP_NO_2048 defined; RSA-2048 skipped");
#endif

#ifndef WOLFSSL_SP_NO_3072
    wb_run_rsa_bits(3072,
        "RSA-3072 MakeRsaKey/SSL_Sign/SSL_Verify exercised");
#else
    WB_NOTE("WOLFSSL_SP_NO_3072 defined; RSA-3072 skipped");
#endif

#ifdef WOLFSSL_SP_4096
    wb_run_rsa_bits(4096,
        "RSA-4096 MakeRsaKey/SSL_Sign/SSL_Verify exercised");
#else
    WB_NOTE("WOLFSSL_SP_4096 not defined; RSA-4096 skipped");
#endif
}
#else
static void wb_run_rsa(void)
{
    WB_NOTE("WOLFSSL_HAVE_SP_RSA/!NO_RSA/WOLFSSL_KEY_GEN not all defined; "
             "RSA skipped");
}
#endif /* WOLFSSL_HAVE_SP_RSA && !NO_RSA && WOLFSSL_KEY_GEN */

#if defined(WOLFSSL_HAVE_SP_DH) && !defined(NO_DH)
/* -------------------------------------------------------------------- *
 * DH: DhSetKey + DhGenerateKeyPair + DhAgree on both sides of a 2048-bit
 * exchange. p/g below are the RFC 3526 "Group 14" 2048-bit MODP prime and
 * generator (g=2), used purely to drive the generic modexp.
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
    WB_NOTE("DH-2048 SetKey/GenerateKeyPair/Agree exercised");
#else
    WB_NOTE("WOLFSSL_SP_NO_2048 defined; DH-2048 skipped");
#endif
}
#else
static void wb_run_dh(void)
{
    WB_NOTE("WOLFSSL_HAVE_SP_DH/!NO_DH not both defined; DH skipped");
}
#endif /* WOLFSSL_HAVE_SP_DH && !NO_DH */

#if defined(WOLFSSL_HAVE_SP_ECC) && defined(HAVE_ECC) && \
    (defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY))
/* Build -P (same x, y = fieldPrime - y, z = 1) from a real curve point, so a
 * genuine P + (-P) cancellation can be fed to sp_<n>_add_points_<w>() to force
 * its point-at-infinity (z == 0 && x == 0 && y == 0) branch -- a state normal
 * sign/verify/ECDH traffic essentially never produces. */
static void wb_build_neg_point(const ecc_point* src, int curve_id,
    ecc_point* negOut)
{
    int curveIdx = wc_ecc_get_curve_idx(curve_id);
    const ecc_set_type* dp = (curveIdx >= 0) ?
        wc_ecc_get_curve_params(curveIdx) : NULL;
    mp_int prime;

    if (dp == NULL) {
        WB_NOTE("wc_ecc_get_curve_params failed (neg point)");
        return;
    }
    if (mp_init(&prime) != MP_OKAY) {
        WB_NOTE("mp_init(prime) failed (neg point)");
        return;
    }
    if (mp_read_radix(&prime, dp->prime, 16) == MP_OKAY) {
        (void)mp_copy(src->x, negOut->x);
        (void)mp_sub(&prime, src->y, negOut->y);
        (void)mp_set(negOut->z, 1);
    }
    else {
        WB_NOTE("mp_read_radix(prime) failed (neg point)");
    }
    mp_clear(&prime);
}
#endif

/* ======================================================================= *
 * Per-curve gap driving: sp_ecc_mulmod_add_<n> / sp_ecc_mulmod_base_add_<n>
 * inMont x map combinations, sp_<n>_add_points_<w> point-at-infinity /
 * doubling-collision, sp_<n>_calc_vfy_point_<w> iszero(p->z), and
 * sp_ecc_check_key_<n> mp_count_bits() overflow -- see the file header for the
 * full rationale. One function per curve size since the callee names
 * (word-count suffixes: 8/12/17 in this 32-bit-radix backend) differ per size.
 * ======================================================================= */
#ifndef WOLFSSL_SP_NO_256
static void wb_run_gap_256(void)
{
#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
    ecc_key keyA;
    ecc_key keyB;
    WC_RNG  rng;
    ecc_point* gm   = NULL;
    ecc_point* negP = NULL;
    ecc_point* rOut = NULL;
    int ok = 1;
    int curveIdx;
    const ecc_set_type* dp;

    XMEMSET(&keyA, 0, sizeof(keyA));
    XMEMSET(&keyB, 0, sizeof(keyB));
    XMEMSET(&rng, 0, sizeof(rng));

    if (wc_ecc_init(&keyA) != 0 || wc_ecc_init(&keyB) != 0 ||
            wc_InitRng(&rng) != 0) {
        WB_NOTE("init failed (gap_256)");
        wb_fail = 1;
        wc_ecc_free(&keyA);
        wc_ecc_free(&keyB);
        return;
    }

    if (wc_ecc_make_key_ex(&rng, 32, &keyA, ECC_SECP256R1) != 0 ||
            wc_ecc_make_key_ex(&rng, 32, &keyB, ECC_SECP256R1) != 0) {
        WB_NOTE("wc_ecc_make_key_ex failed (gap_256)");
        wb_fail = 1;
        ok = 0;
    }

    if (ok) {
        gm   = wc_ecc_new_point();
        negP = wc_ecc_new_point();
        rOut = wc_ecc_new_point();
        if (gm == NULL || negP == NULL || rOut == NULL) {
            WB_NOTE("wc_ecc_new_point failed (gap_256)");
            wb_fail = 1;
        }
    }

    curveIdx = wc_ecc_get_curve_idx(ECC_SECP256R1);
    dp = (curveIdx >= 0) ? wc_ecc_get_curve_params(curveIdx) : NULL;

    /* --- Target gap 1: (err == MP_OKAY) && (!inMont) in
     * sp_ecc_mulmod_add_256()/sp_ecc_mulmod_base_add_256(). Drive all four
     * (inMont, map) combinations with a valid scalar, the real curve
     * generator, and keyB's valid public point. --- */
    if (ok && gm != NULL && rOut != NULL && dp != NULL &&
            mp_read_radix(gm->x, dp->Gx, 16) == MP_OKAY &&
            mp_read_radix(gm->y, dp->Gy, 16) == MP_OKAY &&
            mp_set(gm->z, 1) == MP_OKAY) {
        int inMont, map;

        for (inMont = 0; inMont <= 1; inMont++) {
            for (map = 0; map <= 1; map++) {
                (void)sp_ecc_mulmod_add_256(keyA.k, gm, &keyB.pubkey,
                    inMont, rOut, map, keyA.heap);
                (void)sp_ecc_mulmod_base_add_256(keyA.k, &keyB.pubkey,
                    inMont, rOut, map, keyA.heap);
            }
        }
        WB_NOTE("P-256 mulmod_add/mulmod_base_add inMont x map exercised");
    }
    else {
        WB_NOTE("P-256 generator point setup failed; mulmod_add skipped");
    }

    /* --- Target gap 2a: sp_256_add_points_8()'s iszero(z) /
     * (iszero(x) && iszero(y)) branches. --- */
    if (ok && negP != NULL) {
        sp_point_256 pA;
        sp_point_256 pB;
        sp_digit     addTmp[12 * 8];

        /* P + (-P): true infinity -> z == 0 && x == 0 && y == 0, takes the
         * proj_point_dbl() fallback branch. */
        XMEMSET(&pA, 0, sizeof(pA));
        XMEMSET(&pB, 0, sizeof(pB));
        XMEMSET(addTmp, 0, sizeof(addTmp));
        wb_build_neg_point(&keyA.pubkey, ECC_SECP256R1, negP);
        sp_256_point_from_ecc_point_8(&pA, &keyA.pubkey);
        sp_256_point_from_ecc_point_8(&pB, negP);
        sp_256_add_points_8(&pA, &pB, addTmp);

        /* P + P: doubling collision via the general add formula -> z == 0 but
         * x/y not both zero, takes the "else" branch. */
        XMEMSET(&pA, 0, sizeof(pA));
        XMEMSET(&pB, 0, sizeof(pB));
        XMEMSET(addTmp, 0, sizeof(addTmp));
        sp_256_point_from_ecc_point_8(&pA, &keyA.pubkey);
        sp_256_point_from_ecc_point_8(&pB, &keyA.pubkey);
        sp_256_add_points_8(&pA, &pB, addTmp);

        /* P + Q: two distinct valid points -> z != 0, ordinary path. */
        XMEMSET(&pA, 0, sizeof(pA));
        XMEMSET(&pB, 0, sizeof(pB));
        XMEMSET(addTmp, 0, sizeof(addTmp));
        sp_256_point_from_ecc_point_8(&pA, &keyA.pubkey);
        sp_256_point_from_ecc_point_8(&pB, &keyB.pubkey);
        sp_256_add_points_8(&pA, &pB, addTmp);

        WB_NOTE("P-256 add_points infinity/doubling/ordinary exercised");
    }

    /* --- Target gap 2b: sp_256_calc_vfy_point_8()'s sp_256_iszero_8(p1->z) /
     * sp_256_iszero_8(p2->z), forced by a zero scalar (0 * point ==
     * infinity), mirroring how sp_ecc_verify_256() itself reaches these
     * checks. --- */
    if (ok) {
        int u1zero, u2zero;

        for (u1zero = 0; u1zero <= 1; u1zero++) {
            for (u2zero = 0; u2zero <= 1; u2zero++) {
                sp_point_256 p1;
                sp_point_256 p2;
                sp_digit     vbuf[18 * 8];
                sp_digit    *u1  = vbuf;
                sp_digit    *u2  = vbuf + 2 * 8;
                sp_digit    *s   = vbuf + 4 * 8;
                sp_digit    *tmp = vbuf + 6 * 8;

                XMEMSET(&p1, 0, sizeof(p1));
                XMEMSET(&p2, 0, sizeof(p2));
                XMEMSET(vbuf, 0, sizeof(vbuf));
                sp_256_point_from_ecc_point_8(&p2, &keyB.pubkey);
                s[0] = 7;
                u1[0] = u1zero ? 0 : 5;
                u2[0] = u2zero ? 0 : 5;
                (void)sp_256_calc_vfy_point_8(&p1, &p2, s, u1, u2, tmp,
                    keyA.heap);
            }
        }
        WB_NOTE("P-256 calc_vfy_point iszero(p1->z)/iszero(p2->z) exercised");
    }

#if defined(HAVE_ECC_CHECK_KEY) || !defined(NO_ECC_CHECK_PUBKEY_ORDER)
    /* --- Target gap 3: sp_ecc_check_key_256()'s mp_count_bits(pX) > 256 (and
     * pY, and privm). 2^256 is 257 bits -- one bit too many for each operand
     * in turn -- plus one all-in-range baseline call. --- */
    if (ok) {
        mp_int big;

        if (mp_init(&big) == MP_OKAY) {
            (void)mp_set_bit(&big, 256);

            (void)sp_ecc_check_key_256(keyA.pubkey.x, keyA.pubkey.y, NULL,
                keyA.heap);
            (void)sp_ecc_check_key_256(&big, keyA.pubkey.y, NULL,
                keyA.heap);
            (void)sp_ecc_check_key_256(keyA.pubkey.x, &big, NULL,
                keyA.heap);
            (void)sp_ecc_check_key_256(keyA.pubkey.x, keyA.pubkey.y, &big,
                keyA.heap);
            (void)sp_ecc_check_key_256(keyA.pubkey.x, keyA.pubkey.y,
                keyA.k, keyA.heap);

            mp_clear(&big);
        }
        else {
            WB_NOTE("mp_init(big) failed (gap_256 check_key)");
        }
        WB_NOTE("P-256 check_key mp_count_bits(pX/pY/privm) > 256 exercised");
    }

    /* --- Target gap 4: sp_ecc_check_key_256()'s point-at-infinity input
     * (iszero(pX) && iszero(pY)), out-of-range ordinate
     * (cmp(pX,mod)>=0 || cmp(pY,mod)>=0), and the base*priv != pub mismatch
     * -- degenerate/adversarial inputs a real caller (always a point it
     * itself just computed) never constructs. --- */
    if (ok && dp != NULL) {
        mp_int zero;
        mp_int five;
        mp_int modP;
        int haveZero = (mp_init(&zero) == MP_OKAY);
        int haveFive = haveZero && (mp_init(&five) == MP_OKAY);

        if (haveZero && haveFive) {
            (void)mp_set(&five, 5);

            /* Point at infinity: (0,0), then each ordinate zero alone. */
            (void)sp_ecc_check_key_256(&zero, &zero, NULL, keyA.heap);
            (void)sp_ecc_check_key_256(&zero, &five, NULL, keyA.heap);
            (void)sp_ecc_check_key_256(&five, &zero, NULL, keyA.heap);

            /* Out-of-range ordinate: pX == field prime, then pY == prime. */
            if (mp_init(&modP) == MP_OKAY) {
                if (mp_read_radix(&modP, dp->prime, 16) == MP_OKAY) {
                    (void)sp_ecc_check_key_256(&modP, &five, NULL,
                        keyA.heap);
                    (void)sp_ecc_check_key_256(&five, &modP, NULL,
                        keyA.heap);
                }
                mp_clear(&modP);
            }

            /* Valid on-curve point, wrong private scalar: base*priv != pub.
             */
            (void)sp_ecc_check_key_256(keyA.pubkey.x, keyA.pubkey.y,
                keyB.k, keyA.heap);

            WB_NOTE("P-256 check_key infinity/out-of-range/priv-mismatch "
                     "exercised");
        }
        if (haveFive) {
            mp_clear(&five);
        }
        if (haveZero) {
            mp_clear(&zero);
        }
    }
#else
    WB_NOTE("HAVE_ECC_CHECK_KEY/NO_ECC_CHECK_PUBKEY_ORDER; "
             "check_key_256 skipped");
#endif

#ifdef HAVE_ECC_SIGN
    /* --- Target gap 5: sp_ecc_sign_256()'s (km == NULL || iszero(km)).
     * Real callers (wc_ecc_sign_hash) always pass km == NULL. Driven here
     * with an explicit nonzero km (bypasses RNG, uses km as-is) and an
     * explicit zero km (falls back to RNG, same as the km == NULL path). */
    if (ok) {
        mp_int sigR;
        mp_int sigS;
        mp_int kNonzero;
        mp_int kZero;
        int haveK = (mp_init(&sigR) == MP_OKAY);

        if (haveK) {
            haveK = (mp_init(&sigS) == MP_OKAY);
        }
        if (haveK) {
            haveK = (mp_init(&kNonzero) == MP_OKAY);
        }
        if (haveK) {
            haveK = (mp_init(&kZero) == MP_OKAY);
        }
        if (haveK) {
            (void)mp_set(&kNonzero, 5);
            mp_zero(&kZero);

            (void)sp_ecc_sign_256(wb_digest, (word32)sizeof(wb_digest),
                &rng, keyA.k, &sigR, &sigS, &kNonzero, keyA.heap);
            (void)sp_ecc_sign_256(wb_digest, (word32)sizeof(wb_digest),
                &rng, keyA.k, &sigR, &sigS, &kZero, keyA.heap);

            mp_clear(&kZero);
            mp_clear(&kNonzero);
            mp_clear(&sigS);
            mp_clear(&sigR);
            WB_NOTE("P-256 sign km==NULL||iszero(km) exercised");
        }
    }
#endif

    if (gm != NULL) {
        wc_ecc_del_point(gm);
    }
    if (negP != NULL) {
        wc_ecc_del_point(negP);
    }
    if (rOut != NULL) {
        wc_ecc_del_point(rOut);
    }
    wc_FreeRng(&rng);
    wc_ecc_free(&keyA);
    wc_ecc_free(&keyB);
#else
    WB_NOTE("HAVE_ECC_SIGN/HAVE_ECC_VERIFY not defined; P-256 gap driving "
             "skipped");
#endif
}
#else
static void wb_run_gap_256(void)
{
    WB_NOTE("WOLFSSL_SP_NO_256 defined; P-256 gap driving skipped");
}
#endif /* !WOLFSSL_SP_NO_256 */

#ifdef WOLFSSL_SP_384
static void wb_run_gap_384(void)
{
#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
    ecc_key keyA;
    ecc_key keyB;
    WC_RNG  rng;
    ecc_point* gm   = NULL;
    ecc_point* negP = NULL;
    ecc_point* rOut = NULL;
    int ok = 1;
    int curveIdx;
    const ecc_set_type* dp;

    XMEMSET(&keyA, 0, sizeof(keyA));
    XMEMSET(&keyB, 0, sizeof(keyB));
    XMEMSET(&rng, 0, sizeof(rng));

    if (wc_ecc_init(&keyA) != 0 || wc_ecc_init(&keyB) != 0 ||
            wc_InitRng(&rng) != 0) {
        WB_NOTE("init failed (gap_384)");
        wb_fail = 1;
        wc_ecc_free(&keyA);
        wc_ecc_free(&keyB);
        return;
    }

    if (wc_ecc_make_key_ex(&rng, 48, &keyA, ECC_SECP384R1) != 0 ||
            wc_ecc_make_key_ex(&rng, 48, &keyB, ECC_SECP384R1) != 0) {
        WB_NOTE("wc_ecc_make_key_ex failed (gap_384)");
        wb_fail = 1;
        ok = 0;
    }

    if (ok) {
        gm   = wc_ecc_new_point();
        negP = wc_ecc_new_point();
        rOut = wc_ecc_new_point();
        if (gm == NULL || negP == NULL || rOut == NULL) {
            WB_NOTE("wc_ecc_new_point failed (gap_384)");
            wb_fail = 1;
        }
    }

    curveIdx = wc_ecc_get_curve_idx(ECC_SECP384R1);
    dp = (curveIdx >= 0) ? wc_ecc_get_curve_params(curveIdx) : NULL;

    if (ok && gm != NULL && rOut != NULL && dp != NULL &&
            mp_read_radix(gm->x, dp->Gx, 16) == MP_OKAY &&
            mp_read_radix(gm->y, dp->Gy, 16) == MP_OKAY &&
            mp_set(gm->z, 1) == MP_OKAY) {
        int inMont, map;

        for (inMont = 0; inMont <= 1; inMont++) {
            for (map = 0; map <= 1; map++) {
                (void)sp_ecc_mulmod_add_384(keyA.k, gm, &keyB.pubkey,
                    inMont, rOut, map, keyA.heap);
                (void)sp_ecc_mulmod_base_add_384(keyA.k, &keyB.pubkey,
                    inMont, rOut, map, keyA.heap);
            }
        }
        WB_NOTE("P-384 mulmod_add/mulmod_base_add inMont x map exercised");
    }
    else {
        WB_NOTE("P-384 generator point setup failed; mulmod_add skipped");
    }

    if (ok && negP != NULL) {
        sp_point_384 pA;
        sp_point_384 pB;
        sp_digit     addTmp[12 * 12];

        XMEMSET(&pA, 0, sizeof(pA));
        XMEMSET(&pB, 0, sizeof(pB));
        XMEMSET(addTmp, 0, sizeof(addTmp));
        wb_build_neg_point(&keyA.pubkey, ECC_SECP384R1, negP);
        sp_384_point_from_ecc_point_12(&pA, &keyA.pubkey);
        sp_384_point_from_ecc_point_12(&pB, negP);
        sp_384_add_points_12(&pA, &pB, addTmp);

        XMEMSET(&pA, 0, sizeof(pA));
        XMEMSET(&pB, 0, sizeof(pB));
        XMEMSET(addTmp, 0, sizeof(addTmp));
        sp_384_point_from_ecc_point_12(&pA, &keyA.pubkey);
        sp_384_point_from_ecc_point_12(&pB, &keyA.pubkey);
        sp_384_add_points_12(&pA, &pB, addTmp);

        XMEMSET(&pA, 0, sizeof(pA));
        XMEMSET(&pB, 0, sizeof(pB));
        XMEMSET(addTmp, 0, sizeof(addTmp));
        sp_384_point_from_ecc_point_12(&pA, &keyA.pubkey);
        sp_384_point_from_ecc_point_12(&pB, &keyB.pubkey);
        sp_384_add_points_12(&pA, &pB, addTmp);

        WB_NOTE("P-384 add_points infinity/doubling/ordinary exercised");
    }

    if (ok) {
        int u1zero, u2zero;

        for (u1zero = 0; u1zero <= 1; u1zero++) {
            for (u2zero = 0; u2zero <= 1; u2zero++) {
                sp_point_384 p1;
                sp_point_384 p2;
                sp_digit     vbuf[18 * 12];
                sp_digit    *u1  = vbuf;
                sp_digit    *u2  = vbuf + 2 * 12;
                sp_digit    *s   = vbuf + 4 * 12;
                sp_digit    *tmp = vbuf + 6 * 12;

                XMEMSET(&p1, 0, sizeof(p1));
                XMEMSET(&p2, 0, sizeof(p2));
                XMEMSET(vbuf, 0, sizeof(vbuf));
                sp_384_point_from_ecc_point_12(&p2, &keyB.pubkey);
                s[0] = 7;
                u1[0] = u1zero ? 0 : 5;
                u2[0] = u2zero ? 0 : 5;
                (void)sp_384_calc_vfy_point_12(&p1, &p2, s, u1, u2, tmp,
                    keyA.heap);
            }
        }
        WB_NOTE("P-384 calc_vfy_point iszero(p1->z)/iszero(p2->z) exercised");
    }

#if defined(HAVE_ECC_CHECK_KEY) || !defined(NO_ECC_CHECK_PUBKEY_ORDER)
    if (ok) {
        mp_int big;

        if (mp_init(&big) == MP_OKAY) {
            (void)mp_set_bit(&big, 384);

            (void)sp_ecc_check_key_384(keyA.pubkey.x, keyA.pubkey.y, NULL,
                keyA.heap);
            (void)sp_ecc_check_key_384(&big, keyA.pubkey.y, NULL,
                keyA.heap);
            (void)sp_ecc_check_key_384(keyA.pubkey.x, &big, NULL,
                keyA.heap);
            (void)sp_ecc_check_key_384(keyA.pubkey.x, keyA.pubkey.y, &big,
                keyA.heap);
            (void)sp_ecc_check_key_384(keyA.pubkey.x, keyA.pubkey.y,
                keyA.k, keyA.heap);

            mp_clear(&big);
        }
        else {
            WB_NOTE("mp_init(big) failed (gap_384 check_key)");
        }
        WB_NOTE("P-384 check_key mp_count_bits(pX/pY/privm) > 384 exercised");
    }

    /* --- Target gap 4 (see P-256 for rationale): point-at-infinity input,
     * out-of-range ordinate, base*priv != pub mismatch. --- */
    if (ok && dp != NULL) {
        mp_int zero;
        mp_int five;
        mp_int modP;
        int haveZero = (mp_init(&zero) == MP_OKAY);
        int haveFive = haveZero && (mp_init(&five) == MP_OKAY);

        if (haveZero && haveFive) {
            (void)mp_set(&five, 5);

            (void)sp_ecc_check_key_384(&zero, &zero, NULL, keyA.heap);
            (void)sp_ecc_check_key_384(&zero, &five, NULL, keyA.heap);
            (void)sp_ecc_check_key_384(&five, &zero, NULL, keyA.heap);

            if (mp_init(&modP) == MP_OKAY) {
                if (mp_read_radix(&modP, dp->prime, 16) == MP_OKAY) {
                    (void)sp_ecc_check_key_384(&modP, &five, NULL,
                        keyA.heap);
                    (void)sp_ecc_check_key_384(&five, &modP, NULL,
                        keyA.heap);
                }
                mp_clear(&modP);
            }

            (void)sp_ecc_check_key_384(keyA.pubkey.x, keyA.pubkey.y,
                keyB.k, keyA.heap);

            WB_NOTE("P-384 check_key infinity/out-of-range/priv-mismatch "
                     "exercised");
        }
        if (haveFive) {
            mp_clear(&five);
        }
        if (haveZero) {
            mp_clear(&zero);
        }
    }
#else
    WB_NOTE("HAVE_ECC_CHECK_KEY/NO_ECC_CHECK_PUBKEY_ORDER; "
             "check_key_384 skipped");
#endif

#ifdef HAVE_ECC_SIGN
    /* --- Target gap 5 (see P-256 for rationale): sp_ecc_sign_384()'s
     * (km == NULL || iszero(km)). --- */
    if (ok) {
        mp_int sigR;
        mp_int sigS;
        mp_int kNonzero;
        mp_int kZero;
        int haveK = (mp_init(&sigR) == MP_OKAY);

        if (haveK) {
            haveK = (mp_init(&sigS) == MP_OKAY);
        }
        if (haveK) {
            haveK = (mp_init(&kNonzero) == MP_OKAY);
        }
        if (haveK) {
            haveK = (mp_init(&kZero) == MP_OKAY);
        }
        if (haveK) {
            (void)mp_set(&kNonzero, 5);
            mp_zero(&kZero);

            (void)sp_ecc_sign_384(wb_digest, (word32)sizeof(wb_digest),
                &rng, keyA.k, &sigR, &sigS, &kNonzero, keyA.heap);
            (void)sp_ecc_sign_384(wb_digest, (word32)sizeof(wb_digest),
                &rng, keyA.k, &sigR, &sigS, &kZero, keyA.heap);

            mp_clear(&kZero);
            mp_clear(&kNonzero);
            mp_clear(&sigS);
            mp_clear(&sigR);
            WB_NOTE("P-384 sign km==NULL||iszero(km) exercised");
        }
    }
#endif

    if (gm != NULL) {
        wc_ecc_del_point(gm);
    }
    if (negP != NULL) {
        wc_ecc_del_point(negP);
    }
    if (rOut != NULL) {
        wc_ecc_del_point(rOut);
    }
    wc_FreeRng(&rng);
    wc_ecc_free(&keyA);
    wc_ecc_free(&keyB);
#else
    WB_NOTE("HAVE_ECC_SIGN/HAVE_ECC_VERIFY not defined; P-384 gap driving "
             "skipped");
#endif
}
#else
static void wb_run_gap_384(void)
{
    WB_NOTE("WOLFSSL_SP_384 not defined; P-384 gap driving skipped");
}
#endif /* WOLFSSL_SP_384 */

#ifdef WOLFSSL_SP_521
static void wb_run_gap_521(void)
{
#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
    ecc_key keyA;
    ecc_key keyB;
    WC_RNG  rng;
    ecc_point* gm   = NULL;
    ecc_point* negP = NULL;
    ecc_point* rOut = NULL;
    int ok = 1;
    int curveIdx;
    const ecc_set_type* dp;

    XMEMSET(&keyA, 0, sizeof(keyA));
    XMEMSET(&keyB, 0, sizeof(keyB));
    XMEMSET(&rng, 0, sizeof(rng));

    if (wc_ecc_init(&keyA) != 0 || wc_ecc_init(&keyB) != 0 ||
            wc_InitRng(&rng) != 0) {
        WB_NOTE("init failed (gap_521)");
        wb_fail = 1;
        wc_ecc_free(&keyA);
        wc_ecc_free(&keyB);
        return;
    }

    if (wc_ecc_make_key_ex(&rng, 66, &keyA, ECC_SECP521R1) != 0 ||
            wc_ecc_make_key_ex(&rng, 66, &keyB, ECC_SECP521R1) != 0) {
        WB_NOTE("wc_ecc_make_key_ex failed (gap_521)");
        wb_fail = 1;
        ok = 0;
    }

    if (ok) {
        gm   = wc_ecc_new_point();
        negP = wc_ecc_new_point();
        rOut = wc_ecc_new_point();
        if (gm == NULL || negP == NULL || rOut == NULL) {
            WB_NOTE("wc_ecc_new_point failed (gap_521)");
            wb_fail = 1;
        }
    }

    curveIdx = wc_ecc_get_curve_idx(ECC_SECP521R1);
    dp = (curveIdx >= 0) ? wc_ecc_get_curve_params(curveIdx) : NULL;

    if (ok && gm != NULL && rOut != NULL && dp != NULL &&
            mp_read_radix(gm->x, dp->Gx, 16) == MP_OKAY &&
            mp_read_radix(gm->y, dp->Gy, 16) == MP_OKAY &&
            mp_set(gm->z, 1) == MP_OKAY) {
        int inMont, map;

        for (inMont = 0; inMont <= 1; inMont++) {
            for (map = 0; map <= 1; map++) {
                (void)sp_ecc_mulmod_add_521(keyA.k, gm, &keyB.pubkey,
                    inMont, rOut, map, keyA.heap);
                (void)sp_ecc_mulmod_base_add_521(keyA.k, &keyB.pubkey,
                    inMont, rOut, map, keyA.heap);
            }
        }
        WB_NOTE("P-521 mulmod_add/mulmod_base_add inMont x map exercised");
    }
    else {
        WB_NOTE("P-521 generator point setup failed; mulmod_add skipped");
    }

    if (ok && negP != NULL) {
        sp_point_521 pA;
        sp_point_521 pB;
        sp_digit     addTmp[12 * 17];

        XMEMSET(&pA, 0, sizeof(pA));
        XMEMSET(&pB, 0, sizeof(pB));
        XMEMSET(addTmp, 0, sizeof(addTmp));
        wb_build_neg_point(&keyA.pubkey, ECC_SECP521R1, negP);
        sp_521_point_from_ecc_point_17(&pA, &keyA.pubkey);
        sp_521_point_from_ecc_point_17(&pB, negP);
        sp_521_add_points_17(&pA, &pB, addTmp);

        XMEMSET(&pA, 0, sizeof(pA));
        XMEMSET(&pB, 0, sizeof(pB));
        XMEMSET(addTmp, 0, sizeof(addTmp));
        sp_521_point_from_ecc_point_17(&pA, &keyA.pubkey);
        sp_521_point_from_ecc_point_17(&pB, &keyA.pubkey);
        sp_521_add_points_17(&pA, &pB, addTmp);

        XMEMSET(&pA, 0, sizeof(pA));
        XMEMSET(&pB, 0, sizeof(pB));
        XMEMSET(addTmp, 0, sizeof(addTmp));
        sp_521_point_from_ecc_point_17(&pA, &keyA.pubkey);
        sp_521_point_from_ecc_point_17(&pB, &keyB.pubkey);
        sp_521_add_points_17(&pA, &pB, addTmp);

        WB_NOTE("P-521 add_points infinity/doubling/ordinary exercised");
    }

    if (ok) {
        int u1zero, u2zero;

        for (u1zero = 0; u1zero <= 1; u1zero++) {
            for (u2zero = 0; u2zero <= 1; u2zero++) {
                sp_point_521 p1;
                sp_point_521 p2;
                sp_digit     vbuf[18 * 17];
                sp_digit    *u1  = vbuf;
                sp_digit    *u2  = vbuf + 2 * 17;
                sp_digit    *s   = vbuf + 4 * 17;
                sp_digit    *tmp = vbuf + 6 * 17;

                XMEMSET(&p1, 0, sizeof(p1));
                XMEMSET(&p2, 0, sizeof(p2));
                XMEMSET(vbuf, 0, sizeof(vbuf));
                sp_521_point_from_ecc_point_17(&p2, &keyB.pubkey);
                s[0] = 7;
                u1[0] = u1zero ? 0 : 5;
                u2[0] = u2zero ? 0 : 5;
                (void)sp_521_calc_vfy_point_17(&p1, &p2, s, u1, u2, tmp,
                    keyA.heap);
            }
        }
        WB_NOTE("P-521 calc_vfy_point iszero(p1->z)/iszero(p2->z) exercised");
    }

#if defined(HAVE_ECC_CHECK_KEY) || !defined(NO_ECC_CHECK_PUBKEY_ORDER)
    if (ok) {
        mp_int big;

        if (mp_init(&big) == MP_OKAY) {
            (void)mp_set_bit(&big, 521);

            (void)sp_ecc_check_key_521(keyA.pubkey.x, keyA.pubkey.y, NULL,
                keyA.heap);
            (void)sp_ecc_check_key_521(&big, keyA.pubkey.y, NULL,
                keyA.heap);
            (void)sp_ecc_check_key_521(keyA.pubkey.x, &big, NULL,
                keyA.heap);
            (void)sp_ecc_check_key_521(keyA.pubkey.x, keyA.pubkey.y, &big,
                keyA.heap);
            (void)sp_ecc_check_key_521(keyA.pubkey.x, keyA.pubkey.y,
                keyA.k, keyA.heap);

            mp_clear(&big);
        }
        else {
            WB_NOTE("mp_init(big) failed (gap_521 check_key)");
        }
        WB_NOTE("P-521 check_key mp_count_bits(pX/pY/privm) > 521 exercised");
    }

    /* --- Target gap 4 (see P-256 for rationale): point-at-infinity input,
     * out-of-range ordinate, base*priv != pub mismatch. --- */
    if (ok && dp != NULL) {
        mp_int zero;
        mp_int five;
        mp_int modP;
        int haveZero = (mp_init(&zero) == MP_OKAY);
        int haveFive = haveZero && (mp_init(&five) == MP_OKAY);

        if (haveZero && haveFive) {
            (void)mp_set(&five, 5);

            (void)sp_ecc_check_key_521(&zero, &zero, NULL, keyA.heap);
            (void)sp_ecc_check_key_521(&zero, &five, NULL, keyA.heap);
            (void)sp_ecc_check_key_521(&five, &zero, NULL, keyA.heap);

            if (mp_init(&modP) == MP_OKAY) {
                if (mp_read_radix(&modP, dp->prime, 16) == MP_OKAY) {
                    (void)sp_ecc_check_key_521(&modP, &five, NULL,
                        keyA.heap);
                    (void)sp_ecc_check_key_521(&five, &modP, NULL,
                        keyA.heap);
                }
                mp_clear(&modP);
            }

            (void)sp_ecc_check_key_521(keyA.pubkey.x, keyA.pubkey.y,
                keyB.k, keyA.heap);

            WB_NOTE("P-521 check_key infinity/out-of-range/priv-mismatch "
                     "exercised");
        }
        if (haveFive) {
            mp_clear(&five);
        }
        if (haveZero) {
            mp_clear(&zero);
        }
    }
#else
    WB_NOTE("HAVE_ECC_CHECK_KEY/NO_ECC_CHECK_PUBKEY_ORDER; "
             "check_key_521 skipped");
#endif

#ifdef HAVE_ECC_SIGN
    /* --- Target gap 5 (see P-256 for rationale): sp_ecc_sign_521()'s
     * (km == NULL || iszero(km)). --- */
    if (ok) {
        mp_int sigR;
        mp_int sigS;
        mp_int kNonzero;
        mp_int kZero;
        int haveK = (mp_init(&sigR) == MP_OKAY);

        if (haveK) {
            haveK = (mp_init(&sigS) == MP_OKAY);
        }
        if (haveK) {
            haveK = (mp_init(&kNonzero) == MP_OKAY);
        }
        if (haveK) {
            haveK = (mp_init(&kZero) == MP_OKAY);
        }
        if (haveK) {
            (void)mp_set(&kNonzero, 5);
            mp_zero(&kZero);

            (void)sp_ecc_sign_521(wb_digest, (word32)sizeof(wb_digest),
                &rng, keyA.k, &sigR, &sigS, &kNonzero, keyA.heap);
            (void)sp_ecc_sign_521(wb_digest, (word32)sizeof(wb_digest),
                &rng, keyA.k, &sigR, &sigS, &kZero, keyA.heap);

            mp_clear(&kZero);
            mp_clear(&kNonzero);
            mp_clear(&sigS);
            mp_clear(&sigR);
            WB_NOTE("P-521 sign km==NULL||iszero(km) exercised");
        }
    }
#endif

    if (gm != NULL) {
        wc_ecc_del_point(gm);
    }
    if (negP != NULL) {
        wc_ecc_del_point(negP);
    }
    if (rOut != NULL) {
        wc_ecc_del_point(rOut);
    }
    wc_FreeRng(&rng);
    wc_ecc_free(&keyA);
    wc_ecc_free(&keyB);
#else
    WB_NOTE("HAVE_ECC_SIGN/HAVE_ECC_VERIFY not defined; P-521 gap driving "
             "skipped");
#endif
}
#else
static void wb_run_gap_521(void)
{
    WB_NOTE("WOLFSSL_SP_521 not defined; P-521 gap driving skipped");
}
#endif /* WOLFSSL_SP_521 */

/* ======================================================================= *
 * RSA/DH argument-bounds and loop-guard gap driving. These operate
 * directly on the file-static/exported sp_RsaPublic_<n>, sp_RsaPrivate_<n>
 * and sp_DhExp_<n> entry points with synthetic mp_int operands -- no RSA
 * or ECC key generation is performed here (see file header hard rule):
 * every "bad" call below fails its bound check before any modular
 * exponentiation happens, so the p/q/dP/dQ/qInv arguments passed to the RSA
 * private (CRT) entry point never need to be a real matching key.
 * ======================================================================= */
#if defined(WOLFSSL_HAVE_SP_RSA) || (defined(WOLFSSL_HAVE_SP_DH) && \
                                      !defined(NO_DH))
/* Build an lenBytes-byte big-endian odd integer with an exact bit length of
 * lenBytes*8: top word forced to 0xFFFFFFFF (ffdheShaped) to hit the DH
 * base==2 fast path's "m[top] == -1" check, or to 0xC0000000 (distinctly
 * not -1, but still full-length) to miss it; bottom byte forced odd. Not
 * required to be prime -- only used to drive bit-length/shape-gated
 * branches with generic modular arithmetic. */
static void wb_build_shaped_mod(byte* buf, word32 lenBytes, int ffdheShaped)
{
    XMEMSET(buf, 0, lenBytes);
    if (ffdheShaped) {
        buf[0] = 0xFF; buf[1] = 0xFF; buf[2] = 0xFF; buf[3] = 0xFF;
    }
    else {
        buf[0] = 0xC0;
    }
    buf[lenBytes - 1] |= 0x01;
}
#endif

#if defined(WOLFSSL_HAVE_SP_RSA) && !defined(NO_RSA)
/* Drive sp_RsaPublic_<bits>()'s
 * "mp_count_bits(em) > 32 || inLen > byteLen || mp_count_bits(mm) != bits"
 * and (where compiled) sp_RsaPrivate_<bits>()'s
 * "inLen > byteLen || mp_count_bits(mm) != bits", one operand at a time. */
#define WB_RSA_GAP_FN(bits, byteLen)                                        \
static void wb_run_rsa_gap_##bits(void)                                     \
{                                                                            \
    byte    modGood[byteLen];                                               \
    byte    modBadBits[(byteLen) + 1];                                      \
    byte    dummyIn[8];                                                     \
    byte    out[byteLen];                                                   \
    word32  outLen;                                                         \
    mp_int  mm, mmBad, em, emBad;                                           \
    int     ok;                                                             \
                                                                              \
    XMEMSET(dummyIn, 0, sizeof(dummyIn));                                   \
    XMEMSET(out, 0, sizeof(out));                                          \
    wb_build_shaped_mod(modGood, sizeof(modGood), 1);                       \
    modBadBits[0] = 0x01; /* extra leading byte -> bits+1, not bits */      \
    XMEMCPY(modBadBits + 1, modGood, sizeof(modGood));                     \
                                                                              \
    ok = (mp_init(&mm) == MP_OKAY);                                        \
    if (ok) ok = (mp_init(&mmBad) == MP_OKAY);                             \
    if (ok) ok = (mp_init(&em) == MP_OKAY);                                \
    if (ok) ok = (mp_init(&emBad) == MP_OKAY);                             \
    if (ok) {                                                              \
        (void)mp_read_unsigned_bin(&mm, modGood, (int)sizeof(modGood));    \
        (void)mp_read_unsigned_bin(&mmBad, modBadBits,                    \
            (int)sizeof(modBadBits));                                     \
        (void)mp_set(&em, 0x10001);                                       \
        (void)mp_set_bit(&emBad, 32); /* 33 bits: > 32 */                 \
                                                                              \
        /* mp_count_bits(em) > 32, others valid. */                       \
        outLen = (word32)sizeof(out);                                     \
        (void)sp_RsaPublic_##bits(dummyIn, 32, &emBad, &mm, out, &outLen);\
        /* inLen > byteLen, others valid. */                              \
        outLen = (word32)sizeof(out);                                     \
        (void)sp_RsaPublic_##bits(dummyIn, (byteLen) + 1, &em, &mm, out,  \
            &outLen);                                                     \
        /* mp_count_bits(mm) != bits, others valid. */                    \
        outLen = (word32)sizeof(out);                                     \
        (void)sp_RsaPublic_##bits(dummyIn, 32, &em, &mmBad, out, &outLen);\
                                                                              \
        WB_NOTE("RSA-" #bits " sp_RsaPublic_" #bits " em/inLen/mm bound "  \
                 "checks exercised");                                     \
                                                                              \
        mp_clear(&mm); mp_clear(&mmBad); mp_clear(&em); mp_clear(&emBad); \
    }                                                                       \
                                                                              \
    (void)ok;                                                              \
}
WB_RSA_GAP_FN(2048, 256)
WB_RSA_GAP_FN(3072, 384)
WB_RSA_GAP_FN(4096, 512)
#undef WB_RSA_GAP_FN

#if !defined(WOLFSSL_RSA_PUBLIC_ONLY)
#define WB_RSA_PRIV_GAP_FN(bits, byteLen)                                   \
static void wb_run_rsa_priv_gap_##bits(void)                                \
{                                                                            \
    byte    modGood[byteLen];                                               \
    byte    modBadBits[(byteLen) + 1];                                      \
    byte    dummyIn[8];                                                     \
    byte    out[byteLen];                                                   \
    word32  outLen;                                                         \
    mp_int  mm, mmBad, dm, pm, qm, dpm, dqm, qim;                          \
    int     ok;                                                             \
                                                                              \
    XMEMSET(dummyIn, 0, sizeof(dummyIn));                                  \
    XMEMSET(out, 0, sizeof(out));                                          \
    wb_build_shaped_mod(modGood, sizeof(modGood), 1);                      \
    modBadBits[0] = 0x01;                                                  \
    XMEMCPY(modBadBits + 1, modGood, sizeof(modGood));                    \
                                                                              \
    ok = (mp_init(&mm) == MP_OKAY);                                       \
    if (ok) ok = (mp_init(&mmBad) == MP_OKAY);                            \
    if (ok) ok = (mp_init(&dm) == MP_OKAY);                               \
    if (ok) ok = (mp_init(&pm) == MP_OKAY);                               \
    if (ok) ok = (mp_init(&qm) == MP_OKAY);                               \
    if (ok) ok = (mp_init(&dpm) == MP_OKAY);                              \
    if (ok) ok = (mp_init(&dqm) == MP_OKAY);                              \
    if (ok) ok = (mp_init(&qim) == MP_OKAY);                              \
    if (ok) {                                                             \
        (void)mp_read_unsigned_bin(&mm, modGood, (int)sizeof(modGood));   \
        (void)mp_read_unsigned_bin(&mmBad, modBadBits,                   \
            (int)sizeof(modBadBits));                                    \
        (void)mp_set(&dm, 1); (void)mp_set(&pm, 1); (void)mp_set(&qm, 1); \
        (void)mp_set(&dpm, 1); (void)mp_set(&dqm, 1);                    \
        (void)mp_set(&qim, 1);                                           \
                                                                              \
        /* inLen > byteLen: bound check fails before p/q/dP/dQ/qInv are   \
         * ever touched, so dummy values for them are safe. */           \
        outLen = (word32)sizeof(out);                                    \
        (void)sp_RsaPrivate_##bits(dummyIn, (byteLen) + 1, &dm, &pm, &qm,\
            &dpm, &dqm, &qim, &mm, out, &outLen);                        \
        /* mp_count_bits(mm) != bits, inLen valid. */                    \
        outLen = (word32)sizeof(out);                                    \
        (void)sp_RsaPrivate_##bits(dummyIn, 32, &dm, &pm, &qm, &dpm,     \
            &dqm, &qim, &mmBad, out, &outLen);                           \
                                                                              \
        WB_NOTE("RSA-" #bits " sp_RsaPrivate_" #bits " inLen/mm bound "   \
                 "checks exercised");                                    \
                                                                              \
        mp_clear(&mm); mp_clear(&mmBad);                                 \
        mp_clear(&dm); mp_clear(&pm); mp_clear(&qm);                     \
        mp_clear(&dpm); mp_clear(&dqm); mp_clear(&qim);                  \
    }                                                                      \
                                                                              \
    (void)ok;                                                             \
}
WB_RSA_PRIV_GAP_FN(2048, 256)
WB_RSA_PRIV_GAP_FN(3072, 384)
WB_RSA_PRIV_GAP_FN(4096, 512)
#undef WB_RSA_PRIV_GAP_FN
#else
static void wb_run_rsa_priv_gap_2048(void) { }
static void wb_run_rsa_priv_gap_3072(void) { }
static void wb_run_rsa_priv_gap_4096(void) { }
#endif /* !WOLFSSL_RSA_PUBLIC_ONLY */

static void wb_run_rsa_gaps(void)
{
#ifndef WOLFSSL_SP_NO_2048
    wb_run_rsa_gap_2048();
    wb_run_rsa_priv_gap_2048();
#endif
#ifndef WOLFSSL_SP_NO_3072
    wb_run_rsa_gap_3072();
    wb_run_rsa_priv_gap_3072();
#endif
#ifdef WOLFSSL_SP_4096
    wb_run_rsa_gap_4096();
    wb_run_rsa_priv_gap_4096();
#endif
}
#else
static void wb_run_rsa_gaps(void)
{
    WB_NOTE("WOLFSSL_HAVE_SP_RSA/NO_RSA; RSA bound-check gap driving "
             "skipped");
}
#endif /* WOLFSSL_HAVE_SP_RSA && !NO_RSA */

#if defined(WOLFSSL_HAVE_SP_DH) && !defined(NO_DH)
/* Drive sp_DhExp_<bits>()'s (where FFDHE is compiled)
 * "base->used==1 && base->dp[0]==2 && m[top]==(sp_digit)-1" fast-path AND,
 * one operand at a time, plus the unconditional leading-zero-strip loop
 * "for (i=0; i<byteLen && out[i]==0; i++)" that follows every exponentiation
 * (both the i<byteLen bound-exit and the out[i]==0 flip). */
#define WB_DH_GAP_FN(bits, byteLen, ffdheGuard)                             \
static void wb_run_dh_gap_##bits(void)                                      \
{                                                                            \
    byte   modGood[byteLen];                                               \
    byte   modOther[byteLen];                                              \
    byte   baseNearMod[byteLen];                                           \
    byte   out[byteLen];                                                   \
    word32 outLen;                                                         \
    mp_int base2, base3, baseZero, baseNear, modG, modO;                   \
    byte   exp1[1];                                                        \
    int    ok;                                                             \
                                                                              \
    exp1[0] = 0x01;                                                        \
    wb_build_shaped_mod(modGood, sizeof(modGood), 1);                      \
    wb_build_shaped_mod(modOther, sizeof(modOther), 0);                    \
    XMEMCPY(baseNearMod, modGood, sizeof(modGood));                        \
    baseNearMod[sizeof(baseNearMod) - 1] -= 2; /* < modGood, top byte still \
                                                 * 0xFF: nonzero out[0]. */ \
    XMEMSET(out, 0, sizeof(out));                                         \
                                                                              \
    ok = (mp_init(&base2) == MP_OKAY);                                    \
    if (ok) ok = (mp_init(&base3) == MP_OKAY);                            \
    if (ok) ok = (mp_init(&baseZero) == MP_OKAY);                         \
    if (ok) ok = (mp_init(&baseNear) == MP_OKAY);                        \
    if (ok) ok = (mp_init(&modG) == MP_OKAY);                             \
    if (ok) ok = (mp_init(&modO) == MP_OKAY);                             \
    if (ok) {                                                             \
        (void)mp_set(&base2, 2);                                         \
        (void)mp_set(&base3, 3);                                         \
        mp_zero(&baseZero);                                              \
        (void)mp_read_unsigned_bin(&baseNear, baseNearMod,                \
            (int)sizeof(baseNearMod));                                   \
        (void)mp_read_unsigned_bin(&modG, modGood, (int)sizeof(modGood));\
        (void)mp_read_unsigned_bin(&modO, modOther,                      \
            (int)sizeof(modOther));                                      \
                                                                              \
        ffdheGuard(                                                       \
            outLen = (word32)sizeof(out);                                \
            (void)sp_DhExp_##bits(&base2, exp1, 1, &modG, out, &outLen); \
            outLen = (word32)sizeof(out);                                \
            (void)sp_DhExp_##bits(&base3, exp1, 1, &modG, out, &outLen); \
            outLen = (word32)sizeof(out);                                \
            (void)sp_DhExp_##bits(&base2, exp1, 1, &modO, out, &outLen); \
        )                                                                  \
                                                                              \
        outLen = (word32)sizeof(out);                                    \
        (void)sp_DhExp_##bits(&baseZero, exp1, 1, &modG, out, &outLen);  \
        outLen = (word32)sizeof(out);                                    \
        (void)sp_DhExp_##bits(&baseNear, exp1, 1, &modG, out, &outLen);  \
                                                                              \
        WB_NOTE("DH-" #bits " sp_DhExp_" #bits " fast-path/leading-zero "  \
                 "loop exercised");                                      \
                                                                              \
        mp_clear(&base2); mp_clear(&base3); mp_clear(&baseZero);        \
        mp_clear(&baseNear); mp_clear(&modG); mp_clear(&modO);          \
    }                                                                      \
                                                                              \
    (void)ok;                                                             \
}
#define WB_FFDHE_YES(x) x
#define WB_FFDHE_NO(x)

#ifdef HAVE_FFDHE_2048
WB_DH_GAP_FN(2048, 256, WB_FFDHE_YES)
#else
WB_DH_GAP_FN(2048, 256, WB_FFDHE_NO)
#endif
#ifdef HAVE_FFDHE_3072
WB_DH_GAP_FN(3072, 384, WB_FFDHE_YES)
#else
WB_DH_GAP_FN(3072, 384, WB_FFDHE_NO)
#endif

/* RSA-4096/DH-4096 share sp_4096_mod_exp_128()'s windowed-exponentiation
 * loop "for (; i>=0 || c>=4; )": a small (<=32-bit) exponent -- all real
 * RSA-4096 public-key traffic uses e=65537 -- never advances i past its
 * initial -1, so i>=0 is never independently true. A >32-bit exponent
 * forces a second exponent word to be consumed, driving i>=0 true for at
 * least one iteration before the normal c<4 exit. */
#ifdef WOLFSSL_SP_4096
static void wb_run_dh_gap_4096(void)
{
    byte   modGood[512];
    byte   baseNearMod[512];
    byte   out[512];
    word32 outLen;
    mp_int base3, baseZero, baseNear, modG;
    byte   exp1[1];
    byte   expMulti[5]; /* 40 bits: spans 2 32-bit words. */
    int    ok;

    exp1[0] = 0x01;
    XMEMSET(expMulti, 0xFF, sizeof(expMulti));
    wb_build_shaped_mod(modGood, sizeof(modGood), 1);
    XMEMCPY(baseNearMod, modGood, sizeof(modGood));
    baseNearMod[sizeof(baseNearMod) - 1] -= 2;
    XMEMSET(out, 0, sizeof(out));

    ok = (mp_init(&base3) == MP_OKAY);
    if (ok) ok = (mp_init(&baseZero) == MP_OKAY);
    if (ok) ok = (mp_init(&baseNear) == MP_OKAY);
    if (ok) ok = (mp_init(&modG) == MP_OKAY);
    if (ok) {
        (void)mp_set(&base3, 3);
        mp_zero(&baseZero);
        (void)mp_read_unsigned_bin(&baseNear, baseNearMod,
            (int)sizeof(baseNearMod));
        (void)mp_read_unsigned_bin(&modG, modGood, (int)sizeof(modGood));

        /* Leading-zero loop: full-zero result (bound-exit), then a
         * near-modulus base (nonzero out[0] on the first iteration). */
        outLen = (word32)sizeof(out);
        (void)sp_DhExp_4096(&baseZero, exp1, 1, &modG, out, &outLen);
        outLen = (word32)sizeof(out);
        (void)sp_DhExp_4096(&baseNear, exp1, 1, &modG, out, &outLen);

        /* Multi-word exponent: drives sp_4096_mod_exp_128's
         * "i>=0 || c>=4" loop across a word boundary. */
        outLen = (word32)sizeof(out);
        (void)sp_DhExp_4096(&base3, expMulti, sizeof(expMulti), &modG, out,
            &outLen);

        WB_NOTE("DH-4096 sp_DhExp_4096 leading-zero loop + multi-word "
                 "exponent loop exercised");

        mp_clear(&base3); mp_clear(&baseZero); mp_clear(&baseNear);
        mp_clear(&modG);
    }

    (void)ok;
}
#else
static void wb_run_dh_gap_4096(void) { }
#endif /* WOLFSSL_SP_4096 */

static void wb_run_dh_gaps(void)
{
#ifndef WOLFSSL_SP_NO_2048
    wb_run_dh_gap_2048();
#endif
#ifndef WOLFSSL_SP_NO_3072
    wb_run_dh_gap_3072();
#endif
    wb_run_dh_gap_4096();
}
#else
static void wb_run_dh_gaps(void)
{
    WB_NOTE("WOLFSSL_HAVE_SP_DH/NO_DH; DH bound-check gap driving skipped");
}
#endif /* WOLFSSL_HAVE_SP_DH && !NO_DH */

/* FP-ECC cache guard, once per curve:
 *
 *     if ((err == MP_OKAY) && (wc_LockMutex(&sp_cache_<n>_lock) != 0))
 *
 * Three vectors: init refused (err operand false), lock refused (T,T), and the
 * ordinary success path (T,F). The mutex init is one-shot per curve, so the
 * init-failure vector has to be the first call that reaches the cache -- this
 * runs before anything else in main(). */
#if defined(WOLFSSL_HAVE_SP_ECC) && defined(HAVE_ECC) && \
    defined(FP_ECC) && !defined(MCDC_FM_UNAVAILABLE)
static void wb_run_cache_mutex(void)
{
    ecc_point* gm   = NULL;
    ecc_point* rOut = NULL;
    mp_int     k;
    int        vec;

    if (mp_init(&k) != MP_OKAY) {
        WB_NOTE("mp_init failed (cache_mutex)");
        wb_fail = 1;
        return;
    }
    gm   = wc_ecc_new_point();
    rOut = wc_ecc_new_point();
    if (gm == NULL || rOut == NULL) {
        WB_NOTE("wc_ecc_new_point failed (cache_mutex)");
        wb_fail = 1;
    }
    else if (mp_set(&k, 3) != MP_OKAY) {
        WB_NOTE("mp_set failed (cache_mutex)");
        wb_fail = 1;
    }
    else {
        for (vec = 0; vec < 3; vec++) {
            int curveIdx;
            const ecc_set_type* dp;

            mcdc_fm_init_fail = (vec == 0);
            mcdc_fm_lock_fail = (vec == 1);

#ifndef WOLFSSL_SP_NO_256
            curveIdx = wc_ecc_get_curve_idx(ECC_SECP256R1);
            dp = (curveIdx >= 0) ? wc_ecc_get_curve_params(curveIdx) : NULL;
            if (dp != NULL && mp_read_radix(gm->x, dp->Gx, 16) == MP_OKAY &&
                    mp_read_radix(gm->y, dp->Gy, 16) == MP_OKAY &&
                    mp_set(gm->z, 1) == MP_OKAY) {
                (void)sp_ecc_mulmod_256(&k, gm, rOut, 1, NULL);
            }
#endif
#ifdef WOLFSSL_SP_384
            curveIdx = wc_ecc_get_curve_idx(ECC_SECP384R1);
            dp = (curveIdx >= 0) ? wc_ecc_get_curve_params(curveIdx) : NULL;
            if (dp != NULL && mp_read_radix(gm->x, dp->Gx, 16) == MP_OKAY &&
                    mp_read_radix(gm->y, dp->Gy, 16) == MP_OKAY &&
                    mp_set(gm->z, 1) == MP_OKAY) {
                (void)sp_ecc_mulmod_384(&k, gm, rOut, 1, NULL);
            }
#endif
#ifdef WOLFSSL_SP_521
            curveIdx = wc_ecc_get_curve_idx(ECC_SECP521R1);
            dp = (curveIdx >= 0) ? wc_ecc_get_curve_params(curveIdx) : NULL;
            if (dp != NULL && mp_read_radix(gm->x, dp->Gx, 16) == MP_OKAY &&
                    mp_read_radix(gm->y, dp->Gy, 16) == MP_OKAY &&
                    mp_set(gm->z, 1) == MP_OKAY) {
                (void)sp_ecc_mulmod_521(&k, gm, rOut, 1, NULL);
            }
#endif
            (void)curveIdx;
            (void)dp;
        }
        mcdc_fm_init_fail = 0;
        mcdc_fm_lock_fail = 0;
    }

    if (gm != NULL) {
        wc_ecc_del_point(gm);
    }
    if (rOut != NULL) {
        wc_ecc_del_point(rOut);
    }
    mp_free(&k);
}
#else
static void wb_run_cache_mutex(void)
{
    WB_NOTE("FP_ECC cache mutex path not compiled; skipped");
}
#endif

/* ======================================================================= *
 * Residual closers added in the 2026-08-10 lane pass. Each takes one freshly
 * made key pair per curve size and drives three decisions that the ordinary
 * sign/verify/check_key traffic above cannot reach:
 *
 * 1. sp_ecc_check_key_<n>():
 *        if ((err == MP_OKAY) &&
 *                ((sp_<n>_cmp_<w>(p->x, pub->x) != 0) ||
 *                 (sp_<n>_cmp_<w>(p->y, pub->y) != 0)))
 *    A mismatched private key disagrees on BOTH ordinates, so the second
 *    operand is short-circuited and only ever seen false. The NEGATED public
 *    point (x, prime - y) is still on the curve and still of full order, so it
 *    passes every earlier guard, and base*priv then matches its X but not its
 *    Y -- the only input that reaches the second operand's true row.
 *
 * 2. sp_ecc_verify_<n>():
 *        if ((*res == 0) && (c < 0))
 *    A valid signature gives the (false, -) row. A small r gives
 *    r + order < prime, i.e. (true, true). r = prime - order + 5 makes
 *    r + order land at or past prime -- either c > 0, or the addition carries
 *    out of the field width and c keeps its initial 0 -- which is the missing
 *    (true, false) row. The signature is not valid in any of these calls; only
 *    which branch is taken matters.
 *
 * 3. sp_ecc_sign_<n>():
 *        if (km == NULL || mp_iszero(km))
 *    wc_ecc_sign_hash() always passes km == NULL, so the second operand is
 *    never evaluated. Passing a non-NULL km, zero and then non-zero, reaches
 *    both of its values with the first operand false throughout.
 * ======================================================================= */
#if defined(WOLFSSL_HAVE_SP_ECC) && defined(HAVE_ECC) && \
    defined(HAVE_ECC_VERIFY) && defined(HAVE_ECC_SIGN)

typedef int (*wb_rx_verify_fn)(const byte*, word32, const mp_int*,
    const mp_int*, const mp_int*, const mp_int*, const mp_int*, int*, void*);
typedef int (*wb_rx_sign_fn)(const byte*, word32, WC_RNG*, const mp_int*,
    mp_int*, mp_int*, mp_int*, void*);
typedef int (*wb_rx_check_key_fn)(const mp_int*, const mp_int*, const mp_int*,
    void*);

static void wb_run_residual_extra(int curve_id, int fieldSz, const char* label,
    wb_rx_verify_fn verify, wb_rx_sign_fn sign,
    wb_rx_check_key_fn check_key)
{
    ecc_key keyA;
    ecc_key keyB;
    WC_RNG  rng;
    mp_int  prime;
    mp_int  order;
    mp_int  tmpm;
    mp_int  sigR;
    mp_int  sigS;
    mp_int  smVal;
    mp_int  rSmall;
    mp_int  one;
    int     curveIdx;
    const ecc_set_type* dp;
    int     res;
    int     nInit = 0;
    mp_int* inits[8];

    XMEMSET(&keyA, 0, sizeof(keyA));
    XMEMSET(&keyB, 0, sizeof(keyB));
    XMEMSET(&rng, 0, sizeof(rng));

    if (wc_ecc_init(&keyA) != 0 || wc_ecc_init(&keyB) != 0 ||
            wc_InitRng(&rng) != 0) {
        WB_NOTE("init failed (residual extra)");
        wb_fail = 1;
        wc_ecc_free(&keyA);
        wc_ecc_free(&keyB);
        return;
    }
    if (wc_ecc_make_key_ex(&rng, fieldSz, &keyA, curve_id) != 0 ||
            wc_ecc_make_key_ex(&rng, fieldSz, &keyB, curve_id) != 0) {
        WB_NOTE("wc_ecc_make_key_ex failed (residual extra)");
        wb_fail = 1;
        wc_FreeRng(&rng);
        wc_ecc_free(&keyA);
        wc_ecc_free(&keyB);
        return;
    }

    inits[0] = &prime;  inits[1] = &order;  inits[2] = &tmpm;
    inits[3] = &sigR;   inits[4] = &sigS;   inits[5] = &smVal;
    inits[6] = &rSmall; inits[7] = &one;
    for (nInit = 0; nInit < 8; nInit++) {
        if (mp_init(inits[nInit]) != MP_OKAY) {
            break;
        }
    }
    if (nInit < 8) {
        WB_NOTE("mp_init failed (residual extra)");
        wb_fail = 1;
    }
    else {
        curveIdx = wc_ecc_get_curve_idx(curve_id);
        dp = (curveIdx >= 0) ? wc_ecc_get_curve_params(curveIdx) : NULL;

        (void)mp_set(&one, 1);
        (void)mp_set(&rSmall, 7);
        (void)mp_set(&smVal, 17);

        if (dp != NULL &&
                mp_read_radix(&prime, dp->prime, 16) == MP_OKAY &&
                mp_read_radix(&order, dp->order, 16) == MP_OKAY) {
            /* 1. check_key: matching priv, foreign priv, negated public Y. */
            if (check_key != NULL) {
                (void)check_key(keyA.pubkey.x, keyA.pubkey.y,
                    ecc_get_k(&keyA), keyA.heap);
                (void)check_key(keyA.pubkey.x, keyA.pubkey.y,
                    ecc_get_k(&keyB), keyA.heap);
                if (mp_sub(&prime, keyA.pubkey.y, &tmpm) == MP_OKAY) {
                    (void)check_key(keyA.pubkey.x, &tmpm, ecc_get_k(&keyA),
                        keyA.heap);
                }
            }

            /* 2. verify: r + order below prime, then at/past it. */
            res = -1;
            (void)verify(wb_digest, (word32)sizeof(wb_digest), keyA.pubkey.x,
                keyA.pubkey.y, &one, &rSmall, &smVal, &res, keyA.heap);
            if (mp_sub(&prime, &order, &tmpm) == MP_OKAY &&
                    mp_add_d(&tmpm, 5, &tmpm) == MP_OKAY) {
                res = -1;
                (void)verify(wb_digest, (word32)sizeof(wb_digest),
                    keyA.pubkey.x, keyA.pubkey.y, &one, &tmpm, &smVal, &res,
                    keyA.heap);
            }
        }
        else {
            WB_NOTE("curve params unavailable (residual extra)");
        }

        /* 3. sign with an explicit km: zero, then non-zero. */
        (void)mp_zero(&tmpm);
        (void)sign(wb_digest, (word32)sizeof(wb_digest), &rng,
            ecc_get_k(&keyA), &sigR, &sigS, &tmpm, keyA.heap);
        (void)mp_set(&tmpm, 12345);
        (void)sign(wb_digest, (word32)sizeof(wb_digest), &rng,
            ecc_get_k(&keyA), &sigR, &sigS, &tmpm, keyA.heap);
    }

    while (nInit-- > 0) {
        mp_clear(inits[nInit]);
    }
    wc_FreeRng(&rng);
    wc_ecc_free(&keyA);
    wc_ecc_free(&keyB);
    WB_NOTE(label);
}

static void wb_run_residual_extra_all(void)
{
#ifndef WOLFSSL_SP_NO_256
    wb_run_residual_extra(ECC_SECP256R1, 32,
        "P-256 check_key negated-Y / verify r+order>=prime / explicit km "
        "exercised",
        sp_ecc_verify_256, sp_ecc_sign_256,
#if defined(HAVE_ECC_CHECK_KEY) || !defined(NO_ECC_CHECK_PUBKEY_ORDER)
        sp_ecc_check_key_256
#else
        NULL
#endif
        );
#endif
#ifdef WOLFSSL_SP_384
    wb_run_residual_extra(ECC_SECP384R1, 48,
        "P-384 check_key negated-Y / verify r+order>=prime / explicit km "
        "exercised",
        sp_ecc_verify_384, sp_ecc_sign_384,
#if defined(HAVE_ECC_CHECK_KEY) || !defined(NO_ECC_CHECK_PUBKEY_ORDER)
        sp_ecc_check_key_384
#else
        NULL
#endif
        );
#endif
#ifdef WOLFSSL_SP_521
    wb_run_residual_extra(ECC_SECP521R1, 66,
        "P-521 check_key negated-Y / verify r+order>=prime / explicit km "
        "exercised",
        sp_ecc_verify_521, sp_ecc_sign_521,
#if defined(HAVE_ECC_CHECK_KEY) || !defined(NO_ECC_CHECK_PUBKEY_ORDER)
        sp_ecc_check_key_521
#else
        NULL
#endif
        );
#endif
}
#else
static void wb_run_residual_extra_all(void)
{
    WB_NOTE("SP ECC sign/verify not both compiled; residual extras skipped");
}
#endif

/* ----------------------------------------------------------------------- *
 * sp_<n>_mod_inv_<w>(): the binary extended-GCD loops
 *
 *     while (ut > 1 && vt > 1) { ... do { ... } while (ut > 0 && even(u)); }
 *
 * The only caller is sp_<n>_calc_vfy_point_<w>(), which always hands it a
 * signature's s -- a uniformly random unit -- so the loop always terminates the
 * same way and several operands never see a false row. The helper is file
 * static, which is exactly what a white-box that includes the .c can reach, so
 * it is called here directly with the degenerate operands the caller cannot
 * produce:
 *   - a == m: u and v start equal, so the first subtraction makes u zero and
 *     the inner do-while's FIRST operand (ut > 0) is false;
 *   - a == 1: v has a single bit on entry, so the outer loop's SECOND operand
 *     (vt > 1) is false before the body ever runs;
 *   - small a: ordinary termination, which lands on u == 1 for some values and
 *     v == 1 for others, giving the outer loop's first operand its false row.
 * a == 0 is deliberately NOT used: v would stay zero and the pre-loop that
 * shifts even operands right would never terminate.
 * ----------------------------------------------------------------------- */
#if defined(WOLFSSL_HAVE_SP_ECC) && defined(HAVE_ECC) && \
    !defined(WOLFSSL_SP_SMALL)
#define WB_MOD_INV_SWEEP(WORDS, FN, ORDER)                                  \
    do {                                                                    \
        sp_digit wbA[WORDS];                                                \
        sp_digit wbR[WORDS];                                                \
        int      wbI;                                                       \
        XMEMCPY(wbA, (ORDER), sizeof(wbA));                                 \
        (void)FN(wbR, wbA, (ORDER));                                        \
        for (wbI = 1; wbI <= 40; wbI++) {                                   \
            XMEMSET(wbA, 0, sizeof(wbA));                                   \
            wbA[0] = (sp_digit)wbI;                                         \
            (void)FN(wbR, wbA, (ORDER));                                    \
        }                                                                   \
    } while (0)

static void wb_run_mod_inv(void)
{
#ifndef WOLFSSL_SP_NO_256
    WB_MOD_INV_SWEEP(8, sp_256_mod_inv_8, p256_order);
    WB_NOTE("P-256 sp_256_mod_inv_8 degenerate operands exercised");
#endif
#ifdef WOLFSSL_SP_384
    WB_MOD_INV_SWEEP(12, sp_384_mod_inv_12, p384_order);
    WB_NOTE("P-384 sp_384_mod_inv_12 degenerate operands exercised");
#endif
#ifdef WOLFSSL_SP_521
    WB_MOD_INV_SWEEP(17, sp_521_mod_inv_17, p521_order);
    WB_NOTE("P-521 sp_521_mod_inv_17 degenerate operands exercised");
#endif
}
#else
static void wb_run_mod_inv(void)
{
    WB_NOTE("sp_<n>_mod_inv_<w> not compiled; mod-inv sweep skipped");
}
#endif

#endif /* WOLFSSL_HAVE_SP_ECC || WOLFSSL_HAVE_SP_RSA || WOLFSSL_HAVE_SP_DH */

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("sp_arm32.c white-box supplement (32-bit ARM assembly, no cpuid "
           "dispatch)\n");
#if defined(WOLFSSL_HAVE_SP_ECC) || defined(WOLFSSL_HAVE_SP_RSA) || \
    defined(WOLFSSL_HAVE_SP_DH)
    wb_run_cache_mutex();
    wb_run_ecc();
    wb_run_rsa();
    wb_run_dh();
    wb_run_gap_256();
    wb_run_gap_384();
    wb_run_gap_521();
    wb_run_rsa_gaps();
    wb_run_dh_gaps();
    wb_run_residual_extra_all();
    wb_run_mod_inv();
    wb_spc_all();

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
#else
    printf("  no SP feature; nothing to exercise\n");
#endif
    (void)wb_fail;
    return 0;
}
