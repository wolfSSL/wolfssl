/* test_sp_arm_fault_common.h
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
 * Shared body for the ARM-lane SP backend heap-fault white-boxes
 * (sp_arm64.c / sp_arm32.c / sp_armthumb.c).
 *
 * WHY
 * ---
 * Each of those files carries ~35 uncovered decision conditions of the shape
 *
 *     if ((err == MP_OKAY) && <next step>)          -- the err operand's FALSE
 *
 * and the reason the FALSE half is missing is not that it is hard to reach, it
 * is that nothing in the compiled code can produce it. SP_ALLOC_VAR is
 *
 *     #ifdef WOLFSSL_SP_SMALL_STACK
 *         if (err == MP_OKAY) {
 *             (NAME) = XMALLOC(...);
 *             if ((NAME) == NULL) { err = MEMORY_E; }
 *         }
 *     #else
 *         WC_DO_NOTHING
 *
 * so without WOLFSSL_SP_SMALL_STACK the SP temporaries are plain stack arrays,
 * `err` is MP_OKAY from entry to exit, and every downstream operand is dead by
 * construction. No sp-arm-lanes variant sets that macro, and adding one would
 * mean a whole extra cross build + emulator pass per lane.
 *
 * The including TU therefore defines WOLFSSL_SP_SMALL_STACK for ITSELF, before
 * it #includes the sp_arm*.c under test. That is sound for this suite and
 * cheaper than a variant:
 *   - the lane's white-box recipe (suite/lanes/qemu-entry.sh) compiles the
 *     wb TU with the library's own captured compile line and links it against
 *     libwolfssl.a with the target file's object REMOVED, so the wb binary
 *     contains exactly one copy of sp_arm*.c -- this one -- and there is no
 *     ODR/ABI split with the rest of the library (the macro only changes
 *     function-local storage inside sp_arm*.c; no header and no struct layout
 *     reacts to it);
 *   - WOLFSSL_SP_SMALL_STACK adds no decision to the compiled region of these
 *     files (SP_ALLOC_VAR/SP_FREE_VAR expand to single-condition ifs, which
 *     carry no MC/DC record, and the multi-condition #if-swapped variants live
 *     in the WOLFCRYPT_HAVE_SAKKE 1024-bit block that this lane's config does
 *     not compile), so the file's MC/DC total is unchanged and the union with
 *     the other rows stays key-compatible.
 *
 * HOW
 * ---
 * mcdc_fault_alloc.h fails the n-th and every later heap allocation. This
 * driver calls the SP entry points DIRECTLY rather than through wc_ecc_*: the
 * allocation counter then starts inside the function under test, so a small
 * sweep (n = 1..SP_ARM_FAULT_MAX_N) walks the MEMORY_E down that one function's
 * own success chain instead of being consumed by ecc.c/RNG bookkeeping. It is
 * also much cheaper on an emulated lane -- an armed call bails within a few
 * instructions of the failed allocation instead of doing the whole point
 * multiplication.
 *
 * Every operand is prepared while the injector is DISARMED, because
 * mcdc_fa_arm(n) fails allocation n AND every later one: a blanket arming
 * makes the driver's own key setup fail and the target is never entered.
 *
 * Nothing here is a known-answer test. Results are all discarded; the only
 * requirement is that an armed call returns cleanly rather than crashing (a
 * qemu segfault would lose the whole white-box row).
 *
 * The including TU defines SP_ARM_FAULT_LABEL and #includes the wolfCrypt .c
 * under test before including this header.
 */

#ifndef SP_ARM_FAULT_LABEL
    #error "define SP_ARM_FAULT_LABEL before test_sp_arm_fault_common.h"
#endif

#include "mcdc_fault_alloc.h"

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

/* Sweep depth. Each SP entry point allocates one or two temporaries of its
 * own and then calls helpers that allocate one or two more, so the failure
 * index only has to walk a little past the deepest chain. Kept low on purpose:
 * these lanes run under qemu-user, TEST_TIMEOUT is wall clock, and lanes run
 * concurrently under MAXPAR -- a driver that finishes alone can still be killed
 * under load, and a killed driver is a silent skip. */
#ifndef SP_ARM_FAULT_MAX_N
    #define SP_ARM_FAULT_MAX_N 8
#endif

#if defined(WOLFSSL_HAVE_SP_ECC) && defined(HAVE_ECC) && \
    !defined(MCDC_FA_UNAVAILABLE) && \
    defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY)

/* Fixed 32-byte stand-in digest. Its value is irrelevant: the sweep drives
 * allocation failure positions, not a signature. */
static const byte wb_fa_digest[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

typedef int (*wb_fa_mulmod_add_fn)(const mp_int*, const ecc_point*,
    const ecc_point*, int, ecc_point*, int, void*);
typedef int (*wb_fa_mulmod_base_add_fn)(const mp_int*, const ecc_point*, int,
    ecc_point*, int, void*);
typedef int (*wb_fa_sign_fn)(const byte*, word32, WC_RNG*, const mp_int*,
    mp_int*, mp_int*, mp_int*, void*);
typedef int (*wb_fa_verify_fn)(const byte*, word32, const mp_int*,
    const mp_int*, const mp_int*, const mp_int*, const mp_int*, int*, void*);
typedef int (*wb_fa_check_key_fn)(const mp_int*, const mp_int*, const mp_int*,
    void*);

/* Widest hash the SP signers accept (P-521 takes 66 bytes). */
#define WB_FA_MAX_HASH 66

/* buf <<= 7, in place, over `len` big-endian bytes. Only used on a P-521
 * value, which is at most 521 bits wide in a 528-bit (66-byte) buffer, so
 * nothing is shifted out of the top. Done on the bytes rather than with
 * mp_mul_2d() because that helper is not compiled in every SP math
 * configuration this header is included from. */
static void wb_fa_shl7(byte* buf, int len)
{
    int i;

    for (i = 0; i < (len - 1); i++) {
        buf[i] = (byte)(((unsigned)buf[i] << 7) | ((unsigned)buf[i + 1] >> 1));
    }
    buf[len - 1] = (byte)((unsigned)buf[len - 1] << 7);
}

/* Encode `e` as the fixed-width hash that sp_ecc_sign_<n>() will read back as
 * exactly `e`. All the signers do sp_<n>_from_bin() over the whole buffer, so
 * a plain fixed-length big-endian encoding round-trips -- except P-521, which
 * then takes "the 521 leftmost bits" by shifting the 528-bit buffer right by
 * 7, so its value has to be shifted left by 7 on the way in. */
static int wb_fa_encode_hash(mp_int* e, byte* buf, int fieldSz)
{
    int ret = mp_to_unsigned_bin_len(e, buf, fieldSz);

    if ((ret == MP_OKAY) && (fieldSz == 66)) {
        wb_fa_shl7(buf, fieldSz);
    }
    return ret;
}

/* ---------------------------------------------------------------------- *
 * sp_ecc_sign_<n>(): the "signature is usable" guard
 *
 *     if ((err == MP_OKAY) && (!sp_<n>_iszero_<w>(s))) {
 *         break;
 *     }
 *
 * Every signature any driver has ever produced had a non-zero s, so the
 * second operand only ever ran true and the retry it guards was dead. s is
 *
 *     s = (e + r*x) / k   mod order
 *
 * so s == 0 needs e == -r*x mod order, which needs the private scalar x --
 * not reachable from the caller's side. It is reachable INDIRECTLY, using the
 * signer itself as the oracle and the fact that r depends only on k:
 *
 *   pass 1: sign with a supplied k = K and a hash encoding e1. r is
 *           (K.G)->x mod order and the returned s1 = (e1 + r*x)/K, hence
 *           r*x == s1*K - e1 (mod order);
 *   pass 2: sign with the SAME K and a hash encoding e2 = e1 - s1*K. r comes
 *           out identical, so e2 + r*x == 0 (mod order) and s is zero.
 *
 * No private-key arithmetic is needed: every operand is either chosen here or
 * handed back by pass 1. Only the first loop iteration of pass 2 sees s == 0;
 * sp_ecc_sign_<n>() zeroes the supplied km after using it, so the retry falls
 * back to a generated k and the call finishes with a normal signature.
 *
 * The `err == MP_OKAY` operand of the same decision is left alone on purpose:
 * sp_<n>_calc_s_<w>() has no allocation and no failing step on these
 * backends, so its false row cannot be produced at all.
 * ---------------------------------------------------------------------- */
static void wb_fa_sign_zero_s(wb_fa_sign_fn sign, ecc_key* key, WC_RNG* rng,
    int curveId, int fieldSz, const char* label)
{
    mp_int kConst;
    mp_int kArg;
    mp_int rOut2;
    mp_int sOut;
    mp_int e1;
    mp_int e2;
    mp_int scratch;
    mp_int ordV;
    byte   hash[WB_FA_MAX_HASH];
    int    curveIdx;
    const ecc_set_type* dp;
    int    nInit;
    mp_int* inits[8];

    if ((fieldSz <= 0) || (fieldSz > WB_FA_MAX_HASH)) {
        WB_NOTE("unsupported field size (zero-s sign)");
        return;
    }

    inits[0] = &kConst;  inits[1] = &kArg;    inits[2] = &rOut2;
    inits[3] = &sOut;    inits[4] = &e1;      inits[5] = &e2;
    inits[6] = &scratch; inits[7] = &ordV;
    for (nInit = 0; nInit < 8; nInit++) {
        if (mp_init(inits[nInit]) != MP_OKAY) {
            break;
        }
    }
    if (nInit < 8) {
        WB_NOTE("mp_init failed (zero-s sign)");
        wb_fail = 1;
        while (nInit-- > 0) {
            mp_clear(inits[nInit]);
        }
        return;
    }

    curveIdx = wc_ecc_get_curve_idx(curveId);
    dp = (curveIdx >= 0) ? wc_ecc_get_curve_params(curveIdx) : NULL;

    if ((dp == NULL) || (mp_read_radix(&ordV, dp->order, 16) != MP_OKAY)) {
        WB_NOTE("curve order unavailable (zero-s sign)");
    }
    else {
        /* Any fixed non-zero K below the order works; the value is never
         * secret and never reused outside this driver. */
        (void)mp_set(&kConst, 0x5A5A5);
        (void)mp_set(&e1, 1);

        XMEMSET(hash, 0, sizeof(hash));
        /* e2 = e1 + (order - (s1*K mod order)) mod order, built from mp_mul /
         * mp_mod / mp_sub / mp_add only: the modular one-liners (mp_mulmod,
         * mp_submod) are not compiled in every SP math configuration this
         * header is included from, and every intermediate here stays
         * non-negative, which WOLFSSL_SP_INT_NEGATIVE-less builds require. */
        if ((wb_fa_encode_hash(&e1, hash, fieldSz) == MP_OKAY) &&
                (mp_copy(&kConst, &kArg) == MP_OKAY) &&
                (sign(hash, (word32)fieldSz, rng, ecc_get_k(key), &rOut2,
                     &sOut, &kArg, key->heap) == 0) &&
                (mp_mul(&sOut, &kConst, &scratch) == MP_OKAY) &&
                (mp_mod(&scratch, &ordV, &e2) == MP_OKAY) &&
                (mp_sub(&ordV, &e2, &scratch) == MP_OKAY) &&
                (mp_add(&scratch, &e1, &scratch) == MP_OKAY) &&
                (mp_mod(&scratch, &ordV, &e2) == MP_OKAY)) {
            XMEMSET(hash, 0, sizeof(hash));
            if (wb_fa_encode_hash(&e2, hash, fieldSz) == MP_OKAY) {
                (void)mp_copy(&kConst, &kArg);
                (void)sign(hash, (word32)fieldSz, rng, ecc_get_k(key),
                    &rOut2, &sOut, &kArg, key->heap);
            }
        }
        else {
            WB_NOTE("oracle sign failed (zero-s sign)");
        }
    }

    while (nInit-- > 0) {
        mp_clear(inits[nInit]);
    }
    WB_NOTE(label);
}

/* One curve size: sweep the failure index across each public SP entry point
 * that carries an (err == MP_OKAY) success chain. */
static void wb_fa_curve(int curveId, int fieldSz, const char* label,
    wb_fa_mulmod_add_fn mulmod_add,
    wb_fa_mulmod_base_add_fn mulmod_base_add,
    wb_fa_sign_fn sign, wb_fa_verify_fn verify,
    wb_fa_check_key_fn check_key)
{
    ecc_key    keyA;
    ecc_key    keyB;
    WC_RNG     rng;
    ecc_point* rOut = NULL;
    mp_int     sigR;
    mp_int     sigS;
    mp_int     one;
    int        haveMp = 0;
    int        n;
    int        res = 0;

    XMEMSET(&keyA, 0, sizeof(keyA));
    XMEMSET(&keyB, 0, sizeof(keyB));
    XMEMSET(&rng, 0, sizeof(rng));

    if (wc_ecc_init(&keyA) != 0 || wc_ecc_init(&keyB) != 0 ||
            wc_InitRng(&rng) != 0) {
        WB_NOTE("init failed (fault curve)");
        wb_fail = 1;
        wc_ecc_free(&keyA);
        wc_ecc_free(&keyB);
        return;
    }

    /* Setup, injector disarmed: everything below must succeed so the armed
     * calls start from a valid state. */
    if (wc_ecc_make_key_ex(&rng, fieldSz, &keyA, curveId) != 0 ||
            wc_ecc_make_key_ex(&rng, fieldSz, &keyB, curveId) != 0) {
        WB_NOTE("wc_ecc_make_key_ex failed (fault curve)");
        wb_fail = 1;
        wc_FreeRng(&rng);
        wc_ecc_free(&keyA);
        wc_ecc_free(&keyB);
        return;
    }

    rOut = wc_ecc_new_point();
    haveMp = (mp_init(&sigR) == MP_OKAY) && (mp_init(&sigS) == MP_OKAY) &&
             (mp_init(&one) == MP_OKAY);
    if (haveMp) {
        (void)mp_set(&one, 1);
        /* A real signature, made disarmed, so the verify sweep below has a
         * well-formed (r, s) to walk. */
        if (sign(wb_fa_digest, (word32)sizeof(wb_fa_digest), &rng,
                ecc_get_k(&keyA), &sigR, &sigS, NULL, keyA.heap) != 0) {
            WB_NOTE("baseline sign failed (fault curve)");
            wb_fail = 1;
        }
    }
    else {
        WB_NOTE("mp_init failed (fault curve)");
        wb_fail = 1;
    }

    /* Crafted sign vector, run with the injector DISARMED. See the block
     * comment on wb_fa_sign_zero_s() for what it closes and why it lives in
     * this TU.
     *
     * TWO OTHER CRAFTED SHAPES WERE TRIED HERE AND REMOVED; do not re-add
     * them without new evidence, both were measured on this module:
     *
     *  - verify with an all-zero hash (u1 == 0) and with r == 0 (u2 == 0), to
     *    put `(err == MP_OKAY) && sp_<n>_iszero_<w>(p?->z)` in
     *    sp_<n>_calc_vfy_point_<w>() into its true row. It does not work on
     *    these backends: [0]G and [0]Q come out of the windowed
     *    mulmod/mulmod_base with z still at the Montgomery norm constant and
     *    infinity signalled by the point's separate `infinity` flag, never by
     *    a zero z. Both operands of both guards stayed uncovered, exactly as
     *    they already had for the equivalent vectors the cortexm driver runs
     *    (its V1/V2).
     *
     *  - verify with s == order, to hand sp_<n>_mod_inv_<w>() a == m. That is
     *    the right idea (it is how the inner `while (ut > 0 && ...)` reaches
     *    its first operand's false row) but it must NOT be driven through
     *    P-256 on sp_arm64.c: sp_256_mod_inv_4() there is hand-written
     *    AArch64 assembly whose loop does not terminate for a == m, and the
     *    white-box hung until TEST_TIMEOUT killed it -- which the harness
     *    records as a silent skip of the whole row. The C mod_inv bodies are
     *    reached instead by the direct sweep in the ordinary white-boxes
     *    (wb_run_mod_inv), which can pick the curves it calls. */
    if (haveMp) {
        wb_fa_sign_zero_s(sign, &keyA, &rng, curveId, fieldSz,
            "zero-s sign vector done");
    }

    for (n = 1; (n <= SP_ARM_FAULT_MAX_N) && haveMp; n++) {
        /* sp_ecc_mulmod_add_<n>() / sp_ecc_mulmod_base_add_<n>(): three
         * consecutive `(err == MP_OKAY) && (!inMont)` guards each. inMont == 0
         * so the second operand stays true and the sweep is what moves err. */
        if (rOut != NULL) {
            mcdc_fa_arm(n);
            (void)mulmod_add(ecc_get_k(&keyA), &keyB.pubkey, &keyA.pubkey, 0,
                rOut, 1, keyA.heap);
            mcdc_fa_disarm();

            mcdc_fa_arm(n);
            (void)mulmod_base_add(ecc_get_k(&keyA), &keyA.pubkey, 0, rOut, 1,
                keyA.heap);
            mcdc_fa_disarm();
        }

        /* sp_ecc_sign_<n>(): the retry loop's `err == MP_OKAY` operand and the
         * `(err == MP_OKAY) && (!iszero(s))` guard after it. */
        mcdc_fa_arm(n);
        (void)sign(wb_fa_digest, (word32)sizeof(wb_fa_digest), &rng,
            ecc_get_k(&keyA), &sigR, &sigS, NULL, keyA.heap);
        mcdc_fa_disarm();

        /* sp_ecc_verify_<n>() -> sp_<n>_calc_vfy_point_<w>(): the
         * `(err == MP_OKAY) && iszero(p1->z)` / `p2->z` guards. */
        res = 0;
        mcdc_fa_arm(n);
        (void)verify(wb_fa_digest, (word32)sizeof(wb_fa_digest), keyA.pubkey.x,
            keyA.pubkey.y, &one, &sigR, &sigS, &res, keyA.heap);
        mcdc_fa_disarm();

        /* sp_ecc_check_key_<n>(): the point-order and private-key comparison
         * guards, both fronted by `err == MP_OKAY`. */
        if (check_key != NULL) {
            mcdc_fa_arm(n);
            (void)check_key(keyA.pubkey.x, keyA.pubkey.y, ecc_get_k(&keyA),
                keyA.heap);
            mcdc_fa_disarm();
        }
    }

    mcdc_fa_disarm();

    if (haveMp) {
        mp_clear(&one);
        mp_clear(&sigS);
        mp_clear(&sigR);
    }
    if (rOut != NULL) {
        wc_ecc_del_point(rOut);
    }
    wc_FreeRng(&rng);
    wc_ecc_free(&keyA);
    wc_ecc_free(&keyB);
    WB_NOTE(label);
}

static void wb_fa_all(void)
{
#ifndef WOLFSSL_SP_NO_256
    wb_fa_curve(ECC_SECP256R1, 32, "P-256 SP alloc-fault sweep done",
        sp_ecc_mulmod_add_256, sp_ecc_mulmod_base_add_256,
        sp_ecc_sign_256, sp_ecc_verify_256,
#if defined(HAVE_ECC_CHECK_KEY) || !defined(NO_ECC_CHECK_PUBKEY_ORDER)
        sp_ecc_check_key_256
#else
        NULL
#endif
        );
#else
    WB_NOTE("WOLFSSL_SP_NO_256 defined; P-256 fault sweep skipped");
#endif

#ifdef WOLFSSL_SP_384
    wb_fa_curve(ECC_SECP384R1, 48, "P-384 SP alloc-fault sweep done",
        sp_ecc_mulmod_add_384, sp_ecc_mulmod_base_add_384,
        sp_ecc_sign_384, sp_ecc_verify_384,
#if defined(HAVE_ECC_CHECK_KEY) || !defined(NO_ECC_CHECK_PUBKEY_ORDER)
        sp_ecc_check_key_384
#else
        NULL
#endif
        );
#else
    WB_NOTE("WOLFSSL_SP_384 not defined; P-384 fault sweep skipped");
#endif

#ifdef WOLFSSL_SP_521
    wb_fa_curve(ECC_SECP521R1, 66, "P-521 SP alloc-fault sweep done",
        sp_ecc_mulmod_add_521, sp_ecc_mulmod_base_add_521,
        sp_ecc_sign_521, sp_ecc_verify_521,
#if defined(HAVE_ECC_CHECK_KEY) || !defined(NO_ECC_CHECK_PUBKEY_ORDER)
        sp_ecc_check_key_521
#else
        NULL
#endif
        );
#else
    WB_NOTE("WOLFSSL_SP_521 not defined; P-521 fault sweep skipped");
#endif
}

#else /* feature set not present: keep the TU building everywhere */

static void wb_fa_all(void)
{
#ifdef MCDC_FA_UNAVAILABLE
    WB_NOTE("allocator hooks unavailable in this config; nothing to sweep");
#else
    WB_NOTE("SP ECC sign/verify not all compiled; nothing to sweep");
#endif
}

#endif

int main(void)
{
    /* Unbuffered: on a timeout the process is killed and anything still
     * buffered is lost, which reads as an empty log. */
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("%s heap-fault white-box supplement\n", SP_ARM_FAULT_LABEL);

#ifndef WOLFSSL_SP_SMALL_STACK
    WB_NOTE("WOLFSSL_SP_SMALL_STACK off in this TU: SP temporaries are stack "
            "arrays and err cannot leave MP_OKAY; sweep runs but cannot fail "
            "an SP allocation");
#endif

    mcdc_fa_install();
    wb_fa_all();
    mcdc_fa_disarm();
    mcdc_fa_restore();

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Always 0: a nonzero exit discards this white-box row's coverage. */
    (void)wb_fail;
    return 0;
}
