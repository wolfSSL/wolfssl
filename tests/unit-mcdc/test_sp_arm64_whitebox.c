/* test_sp_arm64_whitebox.c
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
 * MC/DC white-box supplement for wolfcrypt/src/sp_arm64.c.
 *
 * sp_arm64.c is the AArch64 armasm SP math backend: the file body is a single
 * `#ifdef WOLFSSL_SP_ARM64_ASM` block, and that macro is selected at COMPILE
 * time (via the arm64 lane's user_settings.h + --enable-armasm), NOT by any
 * runtime cpuid dispatch. So -- unlike test_sp_x86_64_whitebox.c, which has to
 * force a file-static cpuid mask to reach each SIMD path -- there is nothing to
 * toggle at run time here: every C-level decision in this file is reached by
 * constructing the right *data* and calling the right entry point ONCE. The
 * asm inner loops (add/sub/mul/sqr/mont) carry no MC/DC decisions of their own
 * (they are hand-written assembly, not C the coverage mapping instruments);
 * the instrumented decisions live in the C wrappers around them -- the same
 * shapes as sp_c64.c:
 *   - argument range checks (mp_count_bits(...) > N),
 *   - point-at-infinity checks (sp_<n>_iszero_<n>(...)),
 *   - a caller-supplied flag (`inMont` in sp_ecc_mulmod_add_<n> /
 *     sp_ecc_mulmod_base_add_<n>),
 *   - and the `err == MP_OKAY` error-propagation guards (which need an EARLIER
 *     step to have failed -- fault injection, out of scope; see residuals).
 *
 * The public sp_ecc_*_<size>() / sp_ecc_is_point_<size>() /
 * sp_ecc_check_key_<size>() entry points are ordinary global functions in
 * sp_arm64.c (not file-static), so this TU just #includes the .c file and
 * calls them -- no access trick needed. Sizes compiled by the arm64 config:
 * ECC P-256/384/521 (full mulmod_add + point specials) and RSA/DH modexp
 * 2048/3072/4096 (P-521 is the widest ECC; the SAKKE-only 1024 curve is not
 * enabled). This mirrors test_sp_c64_whitebox.c one-for-one because sp_arm64.c
 * exposes the identical entry-point set; only the compiled arithmetic backend
 * differs.
 *
 * This is a coverage-driving supplement, not a known-answer test: correctness
 * of the arithmetic is already covered by the normal wolfCrypt test suite. The
 * only goal here is to reach each guard with a true and a false operand vector
 * where that is possible without solving a discrete log, and WITHOUT crashing
 * (a qemu segfault fails the whole lane); every result is discarded except the
 * coarse "did it fail outright" checks used to decide whether to WB_NOTE a
 * skip.
 *
 * -------------------------------------------------------------------------
 * sp_ecc_mulmod_add_<n>() / sp_ecc_mulmod_base_add_<n>(): the biggest gap
 * -------------------------------------------------------------------------
 * Both functions contain (for each of x/y/z):
 *   if ((err == MP_OKAY) && (!inMont)) {
 *       err = sp_<n>_mod_mul_norm_<w>(addP->?, addP->?, p<n>_mod);
 *   }
 * The only real callers of these two public entry points are eccsi.c and
 * sakke.c, and BOTH always pass inMont == 0 -- so the `!inMont` == false
 * (inMont == 1) side of every one of these decisions is permanently uncovered
 * by the ordinary test suite. wb_run_mulmod_add below calls both functions
 * directly with a real (on-curve) point pair for every combination of inMont
 * in {0, 1} and map in {0, 1}: inMont == 1 mathematically mistreats an ordinary
 * affine point as already being in Montgomery form, which produces a "wrong"
 * but perfectly well-defined result through the same fixed-shape field
 * arithmetic -- exactly the "did it crash" bar this supplement holds itself to.
 *
 * -------------------------------------------------------------------------
 * Point special cases and range guards
 * -------------------------------------------------------------------------
 * sp_ecc_is_point_<n>() and sp_ecc_check_key_<n>() are called directly with:
 *   - (0, 0): point at infinity, driving the
 *     `(sp_<n>_iszero_<n>(pub->x) != 0) && (sp_<n>_iszero_<n>(pub->y) != 0)`
 *     branch in sp_ecc_check_key_<n>() true.
 *   - an oversized ordinate/private scalar (more bytes, all-0xFF, than the
 *     curve's field width) driving each operand of
 *     `(mp_count_bits(pX) > N) || (mp_count_bits(pY) > N) ||
 *      ((privm != NULL) && (mp_count_bits(privm) > N))` true independently.
 *   - a small, well-formed-but-off-curve pair (3, 3), which reaches (and
 *     exercises, with a clean MP_VAL failure rather than a crash) the
 *     is-point-on-curve check without needing a real key.
 *
 * -------------------------------------------------------------------------
 * Residuals (documented, not driven)
 * -------------------------------------------------------------------------
 * - The `err == MP_OKAY` operand of every `(err == MP_OKAY) && X` decision in
 *   this file (dozens): every one needs an EARLIER step in the same function to
 *   have already failed (MEMORY_E from an allocator not faked here, or a
 *   downstream MP_VAL/ECC_* from a prior stage) -- fault injection, out of
 *   scope for a coverage supplement that must not touch control flow.
 * - `wc_LockMutex(&sp_cache_<n>_lock) != 0` in the ECC point-cache logic:
 *   requires the mutex to fail to lock -- fault injection.
 * - `for (i = SP_ECC_MAX_SIG_GEN; err == MP_OKAY && i > 0; i--)` with
 *   `(err == MP_OKAY) && (!sp_<n>_iszero_<n>(s))` inside sp_ecc_sign_<n>():
 *   the retry-on-r==0-or-s==0 loop needs the random per-signature scalar to
 *   land on a vanishingly small set of values -- cryptographically negligible.
 */

/* The FP-ECC cache lock is statically initialised on pthreads, which compiles
 * out the lazy-init block above the guard and leaves its `err == MP_OKAY`
 * operand structurally true. WOLFSSL_TEST_NO_MUTEX_INITIALIZER is wolfSSL's
 * own knob for that; setting it here compiles the lazy path into this TU so
 * both operands of the guard are reachable in this one binary, which is what
 * MC/DC-per-binary requires. */
#define WOLFSSL_TEST_NO_MUTEX_INITIALIZER

#include "mcdc_fault_mutex.h"

#include <wolfcrypt/src/sp_arm64.c>
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

/* Build an mp_int from nbytes of 0xFF -- an odd, deliberately oversized (or
 * boundary-length) value used only to reach an argument-bounds guard; its
 * numeric value carries no cryptographic meaning. */
static int wb_mp_set_ones(mp_int* m, int nbytes)
{
    byte buf[512];
    if (nbytes > (int)sizeof(buf)) {
        nbytes = (int)sizeof(buf);
    }
    XMEMSET(buf, 0xFF, (size_t)nbytes);
    return mp_read_unsigned_bin(m, buf, (word32)nbytes);
}

/* Build an mp_int exactly fieldBits long (the unused top bits of the
 * leading byte are masked off so mp_count_bits() == fieldBits, not more).
 * Its value is the maximum representable in that bit width, so it is both
 * a "bits == fieldBits" length guard pass AND is numerically at-or-above
 * any field prime/modulus of that width -- useful for a ">= modulus"
 * range guard too. */
static int wb_mp_set_at_bit_boundary(mp_int* m, int fieldBits)
{
    /* Sized for the widest caller (RSA/DH 4096-bit moduli), not just the ECC
     * field widths: a buffer too small to hold fieldBits silently produced a
     * SHORTER value, which made every sp_RsaPublic_ and sp_DhExp_ call below
     * bail at its "mp_count_bits(mod) != N" guard instead of reaching the
     * FFDHE fast path, the windowed modexp and the leading-zero trim loop. */
    byte buf[512];
    int  fieldBytes = (fieldBits + 7) / 8;
    int  topBits = fieldBits - (fieldBytes - 1) * 8;
    byte topMask = (byte)((topBits >= 8) ? 0xFFu :
        (byte)((1u << topBits) - 1u));
    if (fieldBytes > (int)sizeof(buf)) {
        fieldBytes = (int)sizeof(buf);
    }
    XMEMSET(buf, 0xFF, (size_t)fieldBytes);
    buf[0] = topMask;
    return mp_read_unsigned_bin(m, buf, (word32)fieldBytes);
}

#if defined(WOLFSSL_HAVE_SP_ECC) && defined(HAVE_ECC)
/* -------------------------------------------------------------------- *
 * ECC: make_key_ex + sign_hash + verify_hash + shared_secret (ECDH), for
 * each SP-accelerated curve size compiled in. This drives the general
 * sp_<size>_* point/field math in sp_arm64.c.
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

        /* Also exercise wc_ecc_check_key() (-> sp_ecc_check_key_<n>()) on a
         * real, valid key: every guard inside it should evaluate false. */
        if (wc_ecc_check_key(&keyA) != 0) {
            WB_NOTE("wc_ecc_check_key(keyA) failed on a freshly made key");
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
        "P-256 make_key/sign/verify/check_key/ECDH exercised");
#else
    WB_NOTE("WOLFSSL_SP_NO_256 defined; P-256 skipped");
#endif

#ifdef WOLFSSL_SP_384
    wb_run_ecc_curve(ECC_SECP384R1, 48,
        "P-384 make_key/sign/verify/check_key/ECDH exercised");
#else
    WB_NOTE("WOLFSSL_SP_384 not defined; P-384 skipped");
#endif

#ifdef WOLFSSL_SP_521
    wb_run_ecc_curve(ECC_SECP521R1, 66,
        "P-521 make_key/sign/verify/check_key/ECDH exercised");
#else
    WB_NOTE("WOLFSSL_SP_521 not defined; P-521 skipped");
#endif
}

/* ----------------------------------------------------------------------- *
 * sp_ecc_mulmod_add_<n>() / sp_ecc_mulmod_base_add_<n>(): drive every
 * combination of inMont in {0, 1} and map in {0, 1} directly, using a real
 * on-curve point pair from two freshly made keys. See file header for why
 * this is the single biggest coverage gap in the file.
 * ----------------------------------------------------------------------- */
static void wb_run_mulmod_add(int curve_id, int fieldSz, const char* label,
    int (*mulmod_add)(const mp_int*, const ecc_point*, const ecc_point*, int,
        ecc_point*, int, void*),
    int (*mulmod_base_add)(const mp_int*, const ecc_point*, int, ecc_point*,
        int, void*))
{
    ecc_key    keyA;
    ecc_key    keyB;
    WC_RNG     rng;
    ecc_point* r;
    int        inMont;
    int        map;

    XMEMSET(&keyA, 0, sizeof(keyA));
    XMEMSET(&keyB, 0, sizeof(keyB));
    XMEMSET(&rng, 0, sizeof(rng));

    if (wc_ecc_init(&keyA) != 0) {
        WB_NOTE("wc_ecc_init(keyA) failed (mulmod_add)");
        wb_fail = 1;
        return;
    }
    if (wc_ecc_init(&keyB) != 0) {
        WB_NOTE("wc_ecc_init(keyB) failed (mulmod_add)");
        wb_fail = 1;
        wc_ecc_free(&keyA);
        return;
    }
    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("wc_InitRng failed (mulmod_add)");
        wb_fail = 1;
        wc_ecc_free(&keyA);
        wc_ecc_free(&keyB);
        return;
    }

    if (wc_ecc_make_key_ex(&rng, fieldSz, &keyA, curve_id) != 0 ||
            wc_ecc_make_key_ex(&rng, fieldSz, &keyB, curve_id) != 0) {
        WB_NOTE("wc_ecc_make_key_ex failed (mulmod_add)");
        wb_fail = 1;
    }
    else {
        r = wc_ecc_new_point();
        if (r == NULL) {
            WB_NOTE("wc_ecc_new_point failed (mulmod_add)");
            wb_fail = 1;
        }
        else {
            for (inMont = 0; inMont <= 1; inMont++) {
                for (map = 0; map <= 1; map++) {
                    (void)mulmod_add(ecc_get_k(&keyA), &keyB.pubkey,
                        &keyA.pubkey, inMont, r, map, keyA.heap);
                    (void)mulmod_base_add(ecc_get_k(&keyA), &keyA.pubkey,
                        inMont, r, map, keyA.heap);
                }
            }
            wc_ecc_del_point(r);
        }
    }

    wc_FreeRng(&rng);
    wc_ecc_free(&keyA);
    wc_ecc_free(&keyB);
    WB_NOTE(label);
}

static void wb_run_mulmod_add_all(void)
{
#ifndef WOLFSSL_SP_NO_256
    wb_run_mulmod_add(ECC_SECP256R1, 32,
        "P-256 sp_ecc_mulmod_add_256/mulmod_base_add_256 "
        "inMont x map exercised",
        sp_ecc_mulmod_add_256, sp_ecc_mulmod_base_add_256);
#else
    WB_NOTE("WOLFSSL_SP_NO_256 defined; P-256 mulmod_add skipped");
#endif

#ifdef WOLFSSL_SP_384
    wb_run_mulmod_add(ECC_SECP384R1, 48,
        "P-384 sp_ecc_mulmod_add_384/mulmod_base_add_384 "
        "inMont x map exercised",
        sp_ecc_mulmod_add_384, sp_ecc_mulmod_base_add_384);
#else
    WB_NOTE("WOLFSSL_SP_384 not defined; P-384 mulmod_add skipped");
#endif

#ifdef WOLFSSL_SP_521
    wb_run_mulmod_add(ECC_SECP521R1, 66,
        "P-521 sp_ecc_mulmod_add_521/mulmod_base_add_521 "
        "inMont x map exercised",
        sp_ecc_mulmod_add_521, sp_ecc_mulmod_base_add_521);
#else
    WB_NOTE("WOLFSSL_SP_521 not defined; P-521 mulmod_add skipped");
#endif
}

/* ----------------------------------------------------------------------- *
 * sp_ecc_is_point_<n>() / sp_ecc_check_key_<n>(): point-at-infinity and
 * out-of-range-ordinate special cases, driven directly with hand-built
 * mp_int inputs (no need for a valid key -- these functions only inspect
 * the ordinates handed to them).
 * ----------------------------------------------------------------------- */
static void wb_run_point_specials(int fieldBits, const char* label,
    int (*is_point)(const mp_int*, const mp_int*),
    int (*check_key)(const mp_int*, const mp_int*, const mp_int*, void*))
{
    mp_int zero;
    mp_int small;
    mp_int big;
    byte   bigbuf[96];
    int    nbytes = fieldBits / 8 + 9; /* comfortably more bits than fieldBits */

    if (nbytes > (int)sizeof(bigbuf)) {
        nbytes = (int)sizeof(bigbuf);
    }
    XMEMSET(bigbuf, 0xFF, sizeof(bigbuf));

    if (mp_init(&zero) != MP_OKAY) {
        WB_NOTE("mp_init(zero) failed (point specials)");
        wb_fail = 1;
        return;
    }
    if (mp_init(&small) != MP_OKAY) {
        WB_NOTE("mp_init(small) failed (point specials)");
        wb_fail = 1;
        mp_clear(&zero);
        return;
    }
    if (mp_init(&big) != MP_OKAY) {
        WB_NOTE("mp_init(big) failed (point specials)");
        wb_fail = 1;
        mp_clear(&zero);
        mp_clear(&small);
        return;
    }

    mp_set(&small, 3);
    if (mp_read_unsigned_bin(&big, bigbuf, (word32)nbytes) != MP_OKAY) {
        WB_NOTE("mp_read_unsigned_bin(big) failed (point specials)");
        wb_fail = 1;
    }
    else {
        /* Point at infinity (x == 0 && y == 0). is_point() has no
         * bit-length guard, so this only drives its general field math
         * with a degenerate operand -- it is check_key() below that has
         * the explicit "point at infinity" branch. */
        (void)is_point(&zero, &zero);
        /* A small, well-formed, off-curve pair: exercises the same field
         * math with a non-degenerate, non-infinity operand. */
        (void)is_point(&small, &small);

        if (check_key != NULL) {
            /* (sp_<n>_iszero_<n>(pub->x) != 0) &&
             * (sp_<n>_iszero_<n>(pub->y) != 0) -- point at infinity. */
            (void)check_key(&zero, &zero, NULL, NULL);
            /* mp_count_bits(pX) > fieldBits, independently true. */
            (void)check_key(&big, &small, NULL, NULL);
            /* mp_count_bits(pY) > fieldBits, independently true. */
            (void)check_key(&small, &big, NULL, NULL);
            /* (privm != NULL) && (mp_count_bits(privm) > fieldBits),
             * independently true. */
            (void)check_key(&small, &small, &big, NULL);
            /* privm != NULL and in range: falls through to the
             * is-point-on-curve / order / private-key checks. (3, 3) is
             * not on the curve, so this reaches (and cleanly fails) that
             * logic without needing a real key. */
            (void)check_key(&small, &small, &small, NULL);
        }
        else {
            WB_NOTE("check_key needs HAVE_ECC_CHECK_KEY || "
                     "!NO_ECC_CHECK_PUBKEY_ORDER; skipped");
        }
    }

    mp_clear(&big);
    mp_clear(&small);
    mp_clear(&zero);
    WB_NOTE(label);
}

static void wb_run_point_specials_all(void)
{
#ifndef WOLFSSL_SP_NO_256
    wb_run_point_specials(256,
        "P-256 sp_ecc_is_point_256/sp_ecc_check_key_256 special cases "
        "exercised",
        sp_ecc_is_point_256,
#if defined(HAVE_ECC_CHECK_KEY) || !defined(NO_ECC_CHECK_PUBKEY_ORDER)
        sp_ecc_check_key_256
#else
        NULL
#endif
        );
#else
    WB_NOTE("WOLFSSL_SP_NO_256 defined; P-256 point specials skipped");
#endif

#ifdef WOLFSSL_SP_384
    wb_run_point_specials(384,
        "P-384 sp_ecc_is_point_384/sp_ecc_check_key_384 special cases "
        "exercised",
        sp_ecc_is_point_384,
#if defined(HAVE_ECC_CHECK_KEY) || !defined(NO_ECC_CHECK_PUBKEY_ORDER)
        sp_ecc_check_key_384
#else
        NULL
#endif
        );
#else
    WB_NOTE("WOLFSSL_SP_384 not defined; P-384 point specials skipped");
#endif

#ifdef WOLFSSL_SP_521
    wb_run_point_specials(521,
        "P-521 sp_ecc_is_point_521/sp_ecc_check_key_521 special cases "
        "exercised",
        sp_ecc_is_point_521,
#if defined(HAVE_ECC_CHECK_KEY) || !defined(NO_ECC_CHECK_PUBKEY_ORDER)
        sp_ecc_check_key_521
#else
        NULL
#endif
        );
#else
    WB_NOTE("WOLFSSL_SP_521 not defined; P-521 point specials skipped");
#endif
}

/* ----------------------------------------------------------------------- *
 * Residual-closing extras for sp_ecc_sign_<n>() / sp_ecc_verify_<n>() /
 * sp_ecc_check_key_<n>():
 *
 * - sp_ecc_sign_<n>(): the public path (wc_ecc_sign_hash) always passes
 *   km == NULL, so `mp_iszero(km)` in `(km == NULL || mp_iszero(km))` is
 *   never evaluated. Passing a non-NULL km directly (zero, then non-zero)
 *   reaches both its values while km == NULL stays false throughout.
 *
 * - sp_ecc_verify_<n>(): a normal, valid signature always verifies on the
 *   first comparison, so the `(*res == 0) && (c < 0)` fallback path (and
 *   the p1/p2-at-infinity checks feeding into it) are never reached. A
 *   zero hash forces u1 == 0 -> [u1]G == infinity; rm == 0 forces u2 == 0
 *   -> [u2]Q == infinity; rm at (prime - order + 5) forces the r+order
 *   re-check to land >= prime (c >= 0) instead of the otherwise-universal
 *   c < 0. None of these are valid signatures -- res is expected to stay
 *   0 -- the goal is only to reach each guard without crashing.
 *
 * - sp_ecc_check_key_<n>(): one extra (x == 0, y != 0) vector closes the
 *   point-at-infinity AND's second operand independently of the existing
 *   (0, 0) vector; one ordinate pinned to the field's bit-boundary value
 *   (>= the curve prime, still within the bit-length guard) closes each
 *   operand of the X/Y range check independently.
 * ----------------------------------------------------------------------- */
static void wb_run_ecc_extra(int curve_id, int fieldSz, int fieldBits,
    const char* label,
    int (*sign)(const byte*, word32, WC_RNG*, const mp_int*, mp_int*,
        mp_int*, mp_int*, void*),
    int (*verify)(const byte*, word32, const mp_int*, const mp_int*,
        const mp_int*, const mp_int*, const mp_int*, int*, void*),
    int (*check_key)(const mp_int*, const mp_int*, const mp_int*, void*),
    const byte* rHi, int rHiLen)
{
#if defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY)
    ecc_key keyA;
    WC_RNG  rng;
    mp_int  priv, kmZero, kmSet, rm, sm, one, zero, small, atX, atY, rHiM;
    byte    zerohash[32];
    int     res;

    XMEMSET(&keyA, 0, sizeof(keyA));
    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(zerohash, 0, sizeof(zerohash));

    if (wc_ecc_init(&keyA) != 0) {
        WB_NOTE("wc_ecc_init failed (ecc extra)");
        wb_fail = 1;
        return;
    }
    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("wc_InitRng failed (ecc extra)");
        wb_fail = 1;
        wc_ecc_free(&keyA);
        return;
    }
    if (wc_ecc_make_key_ex(&rng, fieldSz, &keyA, curve_id) != 0) {
        WB_NOTE("wc_ecc_make_key_ex failed (ecc extra)");
        wb_fail = 1;
        wc_FreeRng(&rng);
        wc_ecc_free(&keyA);
        return;
    }

    if (mp_init(&priv) != MP_OKAY || mp_init(&kmZero) != MP_OKAY ||
            mp_init(&kmSet) != MP_OKAY || mp_init(&rm) != MP_OKAY ||
            mp_init(&sm) != MP_OKAY || mp_init(&one) != MP_OKAY ||
            mp_init(&zero) != MP_OKAY || mp_init(&small) != MP_OKAY ||
            mp_init(&atX) != MP_OKAY || mp_init(&atY) != MP_OKAY ||
            mp_init(&rHiM) != MP_OKAY) {
        WB_NOTE("mp_init failed (ecc extra)");
        wb_fail = 1;
        wc_FreeRng(&rng);
        wc_ecc_free(&keyA);
        return;
    }

    /* sign(): explicit km, both (km != NULL, iszero(km)) values. */
    mp_set(&priv, 3);
    mp_zero(&kmZero);
    (void)sign(wb_digest, (word32)sizeof(wb_digest), &rng, &priv, &rm, &sm,
        &kmZero, keyA.heap);
    mp_set(&kmSet, 12345);
    (void)sign(wb_digest, (word32)sizeof(wb_digest), &rng, &priv, &rm, &sm,
        &kmSet, keyA.heap);

    /* verify(): u1 == 0 (hash == 0) -> p1 at infinity; c < 0 side of the
     * res/c guard (order comfortably under the prime for any small r). */
    mp_set(&one, 1);
    mp_set(&rm, 7);
    mp_set(&sm, 11);
    res = -1;
    (void)verify(zerohash, (word32)sizeof(zerohash), keyA.pubkey.x,
        keyA.pubkey.y, &one, &rm, &sm, &res, keyA.heap);

    /* verify(): u2 == 0 (rm == 0) -> p2 at infinity; same c < 0 side. */
    mp_zero(&rm);
    mp_set(&sm, 13);
    res = -1;
    (void)verify(wb_digest, (word32)sizeof(wb_digest), keyA.pubkey.x,
        keyA.pubkey.y, &one, &rm, &sm, &res, keyA.heap);

    /* verify(): rm == (prime - order + 5) -> r + order >= prime, closing
     * the c >= 0 side of the same guard. */
    if (mp_read_unsigned_bin(&rHiM, rHi, (word32)rHiLen) == MP_OKAY) {
        mp_set(&sm, 17);
        res = -1;
        (void)verify(wb_digest, (word32)sizeof(wb_digest), keyA.pubkey.x,
            keyA.pubkey.y, &one, &rHiM, &sm, &res, keyA.heap);
    }

    if (check_key != NULL) {
        /* (x == 0) && (y != 0): closes the point-at-infinity AND's second
         * operand (the (0, 0) case is already driven elsewhere). */
        mp_zero(&zero);
        mp_set(&small, 3);
        (void)check_key(&zero, &small, NULL, NULL);

        /* Ordinate at the field's bit-boundary (>= curve prime, still
         * within the bit-length guard): each of X, Y independently. */
        if (wb_mp_set_at_bit_boundary(&atX, fieldBits) == MP_OKAY) {
            (void)check_key(&atX, &small, NULL, NULL);
        }
        if (wb_mp_set_at_bit_boundary(&atY, fieldBits) == MP_OKAY) {
            (void)check_key(&small, &atY, NULL, NULL);
        }
    }

    mp_clear(&rHiM);
    mp_clear(&atY);
    mp_clear(&atX);
    mp_clear(&small);
    mp_clear(&zero);
    mp_clear(&one);
    mp_clear(&sm);
    mp_clear(&rm);
    mp_clear(&kmSet);
    mp_clear(&kmZero);
    mp_clear(&priv);

    wc_FreeRng(&rng);
    wc_ecc_free(&keyA);
    WB_NOTE(label);
#else
    (void)curve_id;
    (void)fieldSz;
    (void)fieldBits;
    (void)sign;
    (void)verify;
    (void)check_key;
    (void)rHi;
    (void)rHiLen;
    WB_NOTE("HAVE_ECC_SIGN/HAVE_ECC_VERIFY not both defined; ecc extra "
             "skipped");
    (void)label;
#endif
}

/* prime - order + 5 for each curve: comfortably inside the field, but
 * with r + order >= prime (see wb_run_ecc_extra() above). */
static const byte wb_rHi_256[16] = {
    0x43, 0x19, 0x05, 0x53, 0x58, 0xE8, 0x61, 0x7B,
    0x0C, 0x46, 0x35, 0x3D, 0x03, 0x9C, 0xDA, 0xB3
};
static const byte wb_rHi_384[24] = {
    0x38, 0x9C, 0xB2, 0x7E, 0x0B, 0xC8, 0xD2, 0x1F,
    0xA7, 0xE5, 0xF2, 0x4C, 0xB7, 0x4F, 0x58, 0x85,
    0x13, 0x13, 0xE6, 0x96, 0x33, 0x3A, 0xD6, 0x91
};
static const byte wb_rHi_521[33] = {
    0x05, 0xAE, 0x79, 0x78, 0x7C, 0x40, 0xD0, 0x69,
    0x94, 0x80, 0x33, 0xFE, 0xB7, 0x08, 0xF6, 0x5A,
    0x2F, 0xC4, 0x4A, 0x36, 0x47, 0x76, 0x63, 0xB8,
    0x51, 0x44, 0x90, 0x48, 0xE1, 0x6E, 0xC7, 0x9B,
    0xFB
};

static void wb_run_ecc_extra_all(void)
{
#ifndef WOLFSSL_SP_NO_256
    wb_run_ecc_extra(ECC_SECP256R1, 32, 256,
        "P-256 sign/verify/check_key residual extras exercised",
        sp_ecc_sign_256, sp_ecc_verify_256,
#if defined(HAVE_ECC_CHECK_KEY) || !defined(NO_ECC_CHECK_PUBKEY_ORDER)
        sp_ecc_check_key_256,
#else
        NULL,
#endif
        wb_rHi_256, (int)sizeof(wb_rHi_256));
#else
    WB_NOTE("WOLFSSL_SP_NO_256 defined; P-256 ecc extra skipped");
#endif

#ifdef WOLFSSL_SP_384
    wb_run_ecc_extra(ECC_SECP384R1, 48, 384,
        "P-384 sign/verify/check_key residual extras exercised",
        sp_ecc_sign_384, sp_ecc_verify_384,
#if defined(HAVE_ECC_CHECK_KEY) || !defined(NO_ECC_CHECK_PUBKEY_ORDER)
        sp_ecc_check_key_384,
#else
        NULL,
#endif
        wb_rHi_384, (int)sizeof(wb_rHi_384));
#else
    WB_NOTE("WOLFSSL_SP_384 not defined; P-384 ecc extra skipped");
#endif

#ifdef WOLFSSL_SP_521
    wb_run_ecc_extra(ECC_SECP521R1, 66, 521,
        "P-521 sign/verify/check_key residual extras exercised",
        sp_ecc_sign_521, sp_ecc_verify_521,
#if defined(HAVE_ECC_CHECK_KEY) || !defined(NO_ECC_CHECK_PUBKEY_ORDER)
        sp_ecc_check_key_521,
#else
        NULL,
#endif
        wb_rHi_521, (int)sizeof(wb_rHi_521));
#else
    WB_NOTE("WOLFSSL_SP_521 not defined; P-521 ecc extra skipped");
#endif
}

#else /* !(WOLFSSL_HAVE_SP_ECC && HAVE_ECC) */
static void wb_run_ecc(void)
{
    WB_NOTE("WOLFSSL_HAVE_SP_ECC/HAVE_ECC not both defined; ECC skipped");
}
static void wb_run_mulmod_add_all(void)
{
    WB_NOTE("WOLFSSL_HAVE_SP_ECC/HAVE_ECC not both defined; mulmod_add "
             "skipped");
}
static void wb_run_point_specials_all(void)
{
    WB_NOTE("WOLFSSL_HAVE_SP_ECC/HAVE_ECC not both defined; point "
             "specials skipped");
}
static void wb_run_ecc_extra_all(void)
{
    WB_NOTE("WOLFSSL_HAVE_SP_ECC/HAVE_ECC not both defined; ecc extra "
             "skipped");
}
#endif /* WOLFSSL_HAVE_SP_ECC && HAVE_ECC */

#if defined(WOLFSSL_HAVE_SP_RSA) && !defined(NO_RSA) && \
    defined(WOLFSSL_KEY_GEN)
/* -------------------------------------------------------------------- *
 * RSA: MakeRsaKey + RsaSSL_Sign + RsaSSL_Verify, for each SP-accelerated
 * modulus size compiled in. Drives the generic sp_<size>_* Montgomery
 * math used for key generation and the sign/verify modexps.
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
 * exchange. Drives sp_ModExp_2048/sp_DhExp_2048.
 *
 * p/g below are the well-known RFC 3526 "Group 14" 2048-bit MODP prime
 * and generator (g=2), used purely to drive the modexp -- not checked for
 * any specific agreed-secret value.
 *
 * 3072-bit is intentionally NOT exercised here: embedding the RFC 3526
 * "Group 15" 3072-bit prime from memory risks a transcription error, and
 * generating one at runtime via wc_DhGenerateParams(3072) is a slow
 * probable-safe-prime search. The generic sp_ModExp_3072/sp_DhExp_3072
 * decisions are still covered via the RSA-3072 path above (same
 * underlying generic Montgomery modexp routines), so 2048-bit alone
 * still exercises the DH-specific (sp_DhExp_2048) wrapper.
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
    WB_NOTE("DH-3072 skipped (see comment above wb_run_dh)");
}
#else
static void wb_run_dh(void)
{
    WB_NOTE("WOLFSSL_HAVE_SP_DH/!NO_DH not both defined; DH skipped");
}
#endif /* WOLFSSL_HAVE_SP_DH && !NO_DH */

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(NO_RSA)) || \
    (defined(WOLFSSL_HAVE_SP_DH) && !defined(NO_DH))
/* ----------------------------------------------------------------------- *
 * sp_RsaPublic_<n>() / sp_RsaPrivate_<n>() (CRT path) / sp_DhExp_<n>():
 * every one guards its inputs with an
 *   mp_count_bits(exponent) > N || inLen > bytes || mp_count_bits(mod) != N
 * style check (RsaPrivate's CRT path only has the last two operands). The
 * normal sign/verify/DH-agree paths above only ever call these with
 * in-range, exact-size operands -- the "all false" row -- so every
 * operand's "true" row is still missing. These call the sp_* entry points
 * directly with out-of-range/boundary operands; none of it needs to be a
 * valid key, only reach the guard without crashing (err short-circuits
 * before the operand is ever read for its bit pattern, so oversized
 * lengths paired with an undersized buffer are safe).
 *
 * sp_DhExp_2048/_3072() additionally special-case base == 2 with an
 * all-ones top digit (FFDHE fast squaring, only compiled when
 * HAVE_FFDHE_2048/_3072 is defined -- no HAVE_FFDHE_4096 in this lane, so
 * sp_DhExp_4096() has no such branch) and trim leading zero bytes off the
 * result. A small odd base with a 1-byte exponent yields a result that is
 * zero in every byte but the last -- driving the trim loop through nearly
 * every index before finding the non-zero one -- while base == 0 drives it
 * through every index (result == 0). The same base == 3 call, given a
 * wider (32-byte) exponent instead, drives the generic windowed modexp's
 * `for (; i>=0 || c>=4; )` digit/nibble scan (sp_4096_mod_exp_64()) through
 * its full natural termination -- a moderate exponent width keeps this
 * cheap relative to the full RSA-4096 keygen already exercised above.
 * ----------------------------------------------------------------------- */
static void wb_run_rsa_dh_bounds(void)
{
    mp_int em;
    mp_int mm;
    mp_int dummy;
    mp_int base;
    byte   in[512];
    byte   out[512];
    byte   exp32[32];
    byte   one = 0x01;
    word32 outLen;

    XMEMSET(in, 0, sizeof(in));
    XMEMSET(out, 0, sizeof(out));
    XMEMSET(exp32, 0xA5, sizeof(exp32));

    if (mp_init(&em) != MP_OKAY) {
        WB_NOTE("mp_init(em) failed (rsa/dh bounds)");
        wb_fail = 1;
        return;
    }
    if (mp_init(&mm) != MP_OKAY) {
        WB_NOTE("mp_init(mm) failed (rsa/dh bounds)");
        wb_fail = 1;
        mp_clear(&em);
        return;
    }
    if (mp_init(&dummy) != MP_OKAY) {
        WB_NOTE("mp_init(dummy) failed (rsa/dh bounds)");
        wb_fail = 1;
        mp_clear(&em);
        mp_clear(&mm);
        return;
    }
    if (mp_init(&base) != MP_OKAY) {
        WB_NOTE("mp_init(base) failed (rsa/dh bounds)");
        wb_fail = 1;
        mp_clear(&em);
        mp_clear(&mm);
        mp_clear(&dummy);
        return;
    }
    mp_set(&dummy, 3);

#if defined(WOLFSSL_HAVE_SP_RSA) && !defined(NO_RSA)
#ifndef WOLFSSL_SP_NO_2048
    if (wb_mp_set_at_bit_boundary(&mm, 2048) == MP_OKAY) {
        (void)wb_mp_set_ones(&em, 9); /* 72 bits: em > 64 alone */
        outLen = (word32)sizeof(out);
        (void)sp_RsaPublic_2048(in, 32, &em, &mm, out, &outLen);
        mp_set(&em, 0x10001);
        outLen = (word32)sizeof(out);
        (void)sp_RsaPublic_2048(in, 257, &em, &mm, out, &outLen); /* inLen */
    }
    if (wb_mp_set_ones(&mm, 128) == MP_OKAY) { /* 1024 bits, != 2048 */
        outLen = (word32)sizeof(out);
        (void)sp_RsaPublic_2048(in, 32, &em, &mm, out, &outLen);
    }
    if (wb_mp_set_at_bit_boundary(&mm, 2048) == MP_OKAY) {
        outLen = (word32)sizeof(out);
        (void)sp_RsaPrivate_2048(in, 257, &dummy, &dummy, &dummy, &dummy,
            &dummy, &dummy, &mm, out, &outLen); /* inLen */
    }
    if (wb_mp_set_ones(&mm, 128) == MP_OKAY) {
        outLen = (word32)sizeof(out);
        (void)sp_RsaPrivate_2048(in, 32, &dummy, &dummy, &dummy, &dummy,
            &dummy, &dummy, &mm, out, &outLen); /* mm != 2048 */
    }
#endif
#ifndef WOLFSSL_SP_NO_3072
    if (wb_mp_set_at_bit_boundary(&mm, 3072) == MP_OKAY) {
        (void)wb_mp_set_ones(&em, 9);
        outLen = (word32)sizeof(out);
        (void)sp_RsaPublic_3072(in, 48, &em, &mm, out, &outLen);
        mp_set(&em, 0x10001);
        outLen = (word32)sizeof(out);
        (void)sp_RsaPublic_3072(in, 385, &em, &mm, out, &outLen);
    }
    if (wb_mp_set_ones(&mm, 128) == MP_OKAY) {
        outLen = (word32)sizeof(out);
        (void)sp_RsaPublic_3072(in, 48, &em, &mm, out, &outLen);
    }
    if (wb_mp_set_at_bit_boundary(&mm, 3072) == MP_OKAY) {
        outLen = (word32)sizeof(out);
        (void)sp_RsaPrivate_3072(in, 385, &dummy, &dummy, &dummy, &dummy,
            &dummy, &dummy, &mm, out, &outLen);
    }
    if (wb_mp_set_ones(&mm, 128) == MP_OKAY) {
        outLen = (word32)sizeof(out);
        (void)sp_RsaPrivate_3072(in, 48, &dummy, &dummy, &dummy, &dummy,
            &dummy, &dummy, &mm, out, &outLen);
    }
#endif
#ifdef WOLFSSL_SP_4096
    if (wb_mp_set_at_bit_boundary(&mm, 4096) == MP_OKAY) {
        (void)wb_mp_set_ones(&em, 9);
        outLen = (word32)sizeof(out);
        (void)sp_RsaPublic_4096(in, 64, &em, &mm, out, &outLen);
        mp_set(&em, 0x10001);
        outLen = (word32)sizeof(out);
        (void)sp_RsaPublic_4096(in, 513, &em, &mm, out, &outLen);
    }
    if (wb_mp_set_ones(&mm, 128) == MP_OKAY) {
        outLen = (word32)sizeof(out);
        (void)sp_RsaPublic_4096(in, 64, &em, &mm, out, &outLen);
    }
    if (wb_mp_set_at_bit_boundary(&mm, 4096) == MP_OKAY) {
        outLen = (word32)sizeof(out);
        (void)sp_RsaPrivate_4096(in, 513, &dummy, &dummy, &dummy, &dummy,
            &dummy, &dummy, &mm, out, &outLen);
    }
    if (wb_mp_set_ones(&mm, 128) == MP_OKAY) {
        outLen = (word32)sizeof(out);
        (void)sp_RsaPrivate_4096(in, 64, &dummy, &dummy, &dummy, &dummy,
            &dummy, &dummy, &mm, out, &outLen);
    }
#endif
#endif /* WOLFSSL_HAVE_SP_RSA && !NO_RSA */

#if defined(WOLFSSL_HAVE_SP_DH) && !defined(NO_DH)
#ifndef WOLFSSL_SP_NO_2048
    if (wb_mp_set_at_bit_boundary(&mm, 2048) == MP_OKAY) {
        mp_set(&base, 2); /* dp[0]==2 true, top digit all-ones: true */
        outLen = (word32)sizeof(out);
        (void)sp_DhExp_2048(&base, &one, 1, &mm, out, &outLen);
        mp_set(&base, 3); /* FFDHE fast-path dp[0]==2 operand: false */
        outLen = (word32)sizeof(out);
        (void)sp_DhExp_2048(&base, &one, 1, &mm, out, &outLen);
        mp_set(&base, 0); /* result == 0: trim loop runs to the boundary */
        outLen = (word32)sizeof(out);
        (void)sp_DhExp_2048(&base, &one, 1, &mm, out, &outLen);
    }
    {
        /* dp[0]==2 true, top digit NOT all-ones: closes that operand's
         * independence pair without disturbing the other two. */
        byte buf2048[256];
        XMEMSET(buf2048, 0xFF, sizeof(buf2048));
        buf2048[0] = 0xFE;
        if (mp_read_unsigned_bin(&mm, buf2048, (word32)sizeof(buf2048))
                == MP_OKAY) {
            mp_set(&base, 2);
            outLen = (word32)sizeof(out);
            (void)sp_DhExp_2048(&base, &one, 1, &mm, out, &outLen);
        }
    }
#endif
#if !defined(WOLFSSL_SP_NO_3072) && defined(HAVE_FFDHE_3072)
    if (wb_mp_set_at_bit_boundary(&mm, 3072) == MP_OKAY) {
        mp_set(&base, 2); /* dp[0]==2 true, top digit all-ones: true */
        outLen = (word32)sizeof(out);
        (void)sp_DhExp_3072(&base, &one, 1, &mm, out, &outLen);
        mp_set(&base, 3); /* dp[0]==2 false */
        outLen = (word32)sizeof(out);
        (void)sp_DhExp_3072(&base, &one, 1, &mm, out, &outLen);
        mp_set(&base, 0);
        outLen = (word32)sizeof(out);
        (void)sp_DhExp_3072(&base, &one, 1, &mm, out, &outLen);
    }
    {
        /* dp[0]==2 true, top digit NOT all-ones: closes that operand's
         * independence pair without disturbing the other two. */
        byte buf3072[384];
        XMEMSET(buf3072, 0xFF, sizeof(buf3072));
        buf3072[0] = 0xFE;
        if (mp_read_unsigned_bin(&mm, buf3072, (word32)sizeof(buf3072))
                == MP_OKAY) {
            mp_set(&base, 2);
            outLen = (word32)sizeof(out);
            (void)sp_DhExp_3072(&base, &one, 1, &mm, out, &outLen);
        }
    }
#endif
#ifdef WOLFSSL_SP_4096
    if (wb_mp_set_at_bit_boundary(&mm, 4096) == MP_OKAY) {
        mp_set(&base, 3);
        outLen = (word32)sizeof(out);
        (void)sp_DhExp_4096(&base, &one, 1, &mm, out, &outLen);
        mp_set(&base, 0);
        outLen = (word32)sizeof(out);
        (void)sp_DhExp_4096(&base, &one, 1, &mm, out, &outLen);

        /* Wider exponent: drives the windowed modexp digit-scan loop
         * `for (; i>=0 || c>=4; )` past the end of the exponent array, so
         * both its operands see a false row (i < 0 with c >= 4, then i < 0
         * with c < 4). Nine bytes is enough to spill past one 64-bit digit
         * while keeping the 4096-bit modexp cheap on an emulated lane. */
        mp_set(&base, 3);
        outLen = (word32)sizeof(out);
        (void)sp_DhExp_4096(&base, exp32, 9, &mm, out, &outLen);
    }
#endif
#endif /* WOLFSSL_HAVE_SP_DH && !NO_DH */

    mp_clear(&em);
    mp_clear(&mm);
    mp_clear(&dummy);
    mp_clear(&base);
    WB_NOTE("RSA/DH argument-bounds, FFDHE fast-path, and trim-loop guards "
             "exercised");
}
#else
static void wb_run_rsa_dh_bounds(void)
{
    WB_NOTE("neither WOLFSSL_HAVE_SP_RSA nor WOLFSSL_HAVE_SP_DH enabled; "
             "rsa/dh bounds skipped");
}
#endif /* (WOLFSSL_HAVE_SP_RSA && !NO_RSA) || (WOLFSSL_HAVE_SP_DH && !NO_DH) */

/* ----------------------------------------------------------------------- *
 * sp_ecc_check_key_<n>(): the private-key cross-check
 *
 *     if ((err == MP_OKAY) &&
 *             ((sp_<n>_cmp_<w>(p->x, pub->x) != 0) ||
 *              (sp_<n>_cmp_<w>(p->y, pub->y) != 0)))
 *
 * Real callers only ever pass a matching (pub, priv) pair, so both comparison
 * operands are permanently false. Three vectors close them:
 *   - (pub, its own priv)          -> (F, F): the existing all-match row;
 *   - (pub, ANOTHER key's priv)    -> (T, -): X differs, second operand
 *                                     short-circuited;
 *   - ((pubX, prime - pubY), priv) -> (F, T): the negated public point is
 *     still on the curve and still of full order, so it passes every earlier
 *     guard, and base*priv then matches its X but not its Y -- the only way to
 *     reach the second operand's true row.
 * ----------------------------------------------------------------------- */
#if defined(WOLFSSL_HAVE_SP_ECC) && defined(HAVE_ECC) && \
    (defined(HAVE_ECC_CHECK_KEY) || !defined(NO_ECC_CHECK_PUBKEY_ORDER))
static void wb_run_check_key_priv(int curve_id, int fieldSz, const char* label,
    int (*check_key)(const mp_int*, const mp_int*, const mp_int*, void*))
{
    ecc_key keyA;
    ecc_key keyB;
    WC_RNG  rng;
    mp_int  prime;
    mp_int  negY;
    int     curveIdx;
    const ecc_set_type* dp;

    XMEMSET(&keyA, 0, sizeof(keyA));
    XMEMSET(&keyB, 0, sizeof(keyB));
    XMEMSET(&rng, 0, sizeof(rng));

    if (wc_ecc_init(&keyA) != 0 || wc_ecc_init(&keyB) != 0 ||
            wc_InitRng(&rng) != 0) {
        WB_NOTE("init failed (check_key priv)");
        wb_fail = 1;
        wc_ecc_free(&keyA);
        wc_ecc_free(&keyB);
        return;
    }

    if (wc_ecc_make_key_ex(&rng, fieldSz, &keyA, curve_id) != 0 ||
            wc_ecc_make_key_ex(&rng, fieldSz, &keyB, curve_id) != 0) {
        WB_NOTE("wc_ecc_make_key_ex failed (check_key priv)");
        wb_fail = 1;
    }
    else if (mp_init(&prime) != MP_OKAY) {
        WB_NOTE("mp_init(prime) failed (check_key priv)");
        wb_fail = 1;
    }
    else {
        if (mp_init(&negY) == MP_OKAY) {
            curveIdx = wc_ecc_get_curve_idx(curve_id);
            dp = (curveIdx >= 0) ? wc_ecc_get_curve_params(curveIdx) : NULL;

            /* Matching pair: both comparison operands false. */
            (void)check_key(keyA.pubkey.x, keyA.pubkey.y, ecc_get_k(&keyA),
                keyA.heap);
            /* Foreign private key: the X comparison alone is true. */
            (void)check_key(keyA.pubkey.x, keyA.pubkey.y, ecc_get_k(&keyB),
                keyA.heap);
            /* Negated public point: X matches, Y does not. */
            if (dp != NULL &&
                    mp_read_radix(&prime, dp->prime, 16) == MP_OKAY &&
                    mp_sub(&prime, keyA.pubkey.y, &negY) == MP_OKAY) {
                (void)check_key(keyA.pubkey.x, &negY, ecc_get_k(&keyA),
                    keyA.heap);
            }
            else {
                WB_NOTE("curve prime unavailable; negated-Y vector skipped");
            }
            mp_clear(&negY);
        }
        mp_clear(&prime);
    }

    wc_FreeRng(&rng);
    wc_ecc_free(&keyA);
    wc_ecc_free(&keyB);
    WB_NOTE(label);
}

static void wb_run_check_key_priv_all(void)
{
#ifndef WOLFSSL_SP_NO_256
    wb_run_check_key_priv(ECC_SECP256R1, 32,
        "P-256 check_key private-key cross-check exercised",
        sp_ecc_check_key_256);
#endif
#ifdef WOLFSSL_SP_384
    wb_run_check_key_priv(ECC_SECP384R1, 48,
        "P-384 check_key private-key cross-check exercised",
        sp_ecc_check_key_384);
#endif
#ifdef WOLFSSL_SP_521
    wb_run_check_key_priv(ECC_SECP521R1, 66,
        "P-521 check_key private-key cross-check exercised",
        sp_ecc_check_key_521);
#endif
}
#else
static void wb_run_check_key_priv_all(void)
{
    WB_NOTE("sp_ecc_check_key_<n> not compiled; priv cross-check skipped");
}
#endif

/* ----------------------------------------------------------------------- *
 * sp_<n>_mod_inv_<w>(): the binary extended-GCD loops
 *
 *     while (ut > 1 && vt > 1) { ... do { ... } while (ut > 0 && even(u)); }
 *
 * The only caller is sp_<n>_calc_vfy_point_<w>(), which always hands it a
 * signature's s -- a uniformly random unit -- so the loop always terminates the
 * same way and the operands' false rows are never seen. The helper is file
 * static, which is exactly what this white-box has access to, so it is called
 * here directly with the degenerate operands the caller cannot produce:
 *   - a == 1: v has one bit on entry, so the outer loop's SECOND operand is
 *     false before the body ever runs;
 *   - a == m: u and v are equal, so the first subtraction makes u zero and the
 *     inner do-while's FIRST operand is false;
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
    /* P-256 is omitted on this backend: sp_256_mod_inv_4() is hand-written
     * AArch64 assembly with no C-level decision to drive. */
#ifdef WOLFSSL_SP_384
    WB_MOD_INV_SWEEP(6, sp_384_mod_inv_6, p384_order);
    WB_NOTE("P-384 sp_384_mod_inv_6 degenerate operands exercised");
#endif
#ifdef WOLFSSL_SP_521
    WB_MOD_INV_SWEEP(9, sp_521_mod_inv_9, p521_order);
    WB_NOTE("P-521 sp_521_mod_inv_9 degenerate operands exercised");
#endif
}
#else
static void wb_run_mod_inv(void)
{
    WB_NOTE("sp_<n>_mod_inv_<w> not compiled; mod-inv sweep skipped");
}
#endif

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

#endif /* WOLFSSL_HAVE_SP_ECC || WOLFSSL_HAVE_SP_RSA || WOLFSSL_HAVE_SP_DH */

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("sp_arm64.c white-box supplement\n");
#if defined(WOLFSSL_HAVE_SP_ECC) || defined(WOLFSSL_HAVE_SP_RSA) || \
    defined(WOLFSSL_HAVE_SP_DH)
    wb_run_cache_mutex();
    wb_run_ecc();
    wb_run_rsa();
    wb_run_dh();
    wb_run_mulmod_add_all();
    wb_run_point_specials_all();
    wb_run_ecc_extra_all();
    wb_run_rsa_dh_bounds();
    wb_run_check_key_priv_all();
    wb_run_mod_inv();
    wb_spc_all();

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
#else
    printf("  no SP feature; nothing to exercise\n");
#endif
    (void)wb_fail;
    return 0;
}
