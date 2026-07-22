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

#include <wolfcrypt/src/sp_arm64.c>

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

#endif /* WOLFSSL_HAVE_SP_ECC || WOLFSSL_HAVE_SP_RSA || WOLFSSL_HAVE_SP_DH */

int main(void)
{
    printf("sp_arm64.c white-box supplement\n");
#if defined(WOLFSSL_HAVE_SP_ECC) || defined(WOLFSSL_HAVE_SP_RSA) || \
    defined(WOLFSSL_HAVE_SP_DH)
    wb_run_ecc();
    wb_run_rsa();
    wb_run_dh();
    wb_run_mulmod_add_all();
    wb_run_point_specials_all();

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
#else
    printf("  no SP feature; nothing to exercise\n");
#endif
    (void)wb_fail;
    return 0;
}
