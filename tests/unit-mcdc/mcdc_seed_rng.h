/* mcdc_seed_rng.h
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
 * mcdc_seed_rng.h -- deterministic RNG for the per-module MC/DC campaign.
 *
 * WHY THIS EXISTS
 * ---------------
 * Some decisions are only reached when a random draw lands in a narrow range:
 * falcon's Babai clamp fires when a keygen coefficient overflows, the ECDSA
 * retry loops need r or s to come out zero, and the PQC rejection samplers
 * need one lane to fall short. Driven by real entropy these are *sometimes*
 * covered -- falcon:5606 was recorded as covered in the baseline but fires in
 * roughly one run in eight.
 *
 * A condition covered seven runs out of eight is not covered. For ASIL-D the
 * evidence has to be reproducible, and a baseline recorded from a lucky run
 * cannot be defended: the next honest run reads as a regression.
 *
 * WHAT IT DOES, AND WHAT IT DOES NOT
 * ----------------------------------
 * It makes the stream reproducible. It does NOT manufacture coverage: with a
 * pinned seed a target condition becomes deterministically covered, or
 * deterministically uncovered. The second outcome is still an improvement --
 * it says plainly that a driver is needed, instead of leaving a lottery in the
 * evidence.
 *
 * The stream is a SHAKE-256 squeeze over the pinned seed, so it is stable
 * across hosts, builds and library versions -- unlike the DRBG, whose output
 * depends on the entropy source. Byte-for-byte identical on every run.
 *
 * USAGE
 * -----
 *     #include "mcdc_seed_rng.h"
 *     #include <wolfcrypt/src/falcon.c>
 *     #define MCDC_SR_IMPL
 *     #include "mcdc_seed_rng.h"
 *
 *     mcdc_sr_arm(0x5eed0001);   -- deterministic from here
 *     ... drive the operation ...
 *     mcdc_sr_disarm();          -- back to the real RNG
 *
 * Setup should run disarmed so a fixture is built from real randomness; arm
 * only around the operation under test, exactly as the fault injectors do.
 *
 * SEED SELECTION IS EVIDENCE
 * --------------------------
 * A seed chosen because it happens to reach a condition is a legitimate test
 * vector -- that is what a KAT is -- but it must be recorded in the module's
 * residual note, or the next person cannot reproduce the result. Note also
 * that a future change to how the code consumes randomness can move the
 * stream underneath a pinned seed; that shows up as a regression and should be
 * re-hunted rather than assumed to be lost coverage.
 *
 * Different variants consume randomness differently (an AVX2 path and a
 * generic-C path do not draw the same number of bytes), so expect a seed to be
 * per (module, variant) rather than universal.
 *
 * Where SHAKE is unavailable (MCDC_SR_UNAVAILABLE) the API is still defined,
 * as inert stubs, so a caller always compiles -- see the note in the
 * implementation half for why that matters.
 */

/* SHAKE-256 is gated positively by WOLFSSL_SHAKE256; there is no NO_SHA3. */
#if !defined(WOLFSSL_SHAKE256) || defined(WOLFSSL_NO_SHAKE256) || \
    defined(WC_NO_RNG)
    #define MCDC_SR_UNAVAILABLE
#endif

#ifndef MCDC_SR_IMPL

#ifndef MCDC_SEED_RNG_H
#define MCDC_SEED_RNG_H

static int mcdc_sr_active = 0;

#ifndef MCDC_SR_UNAVAILABLE
    /* Pull random.h in FIRST and declare the hook explicitly, rather than
     * relying on the macro to rewrite random.h's own prototype into that
     * declaration. The rewrite trick only works when this header is included
     * before anything else drags random.h in; when it is not, the include
     * guard skips the prototype, the hook is never declared, and every call
     * site inside the .c under test fails with "use of undeclared
     * identifier". That is a compile failure, which the campaign scores as a
     * SILENT SKIP -- the dh module read 107/173 with 6 of 12 variants
     * aggregating instead of 158/173, and still reported success.
     *
     * Declaring it here makes the header independent of include order. */
    #include <wolfssl/wolfcrypt/random.h>

    int mcdc_sr_block(WC_RNG* rng, byte* out, word32 sz);

    #define wc_RNG_GenerateBlock(rng, out, sz) mcdc_sr_block(rng, out, sz)
#endif

#endif /* MCDC_SEED_RNG_H */

#else /* MCDC_SR_IMPL */

#ifndef MCDC_SR_UNAVAILABLE

#undef wc_RNG_GenerateBlock

static wc_Shake mcdc_sr_shake;
static int      mcdc_sr_ready = 0;

/* wc_Shake256_SqueezeBlocks()'s third argument is a BLOCK COUNT, not a byte
 * count -- squeezing sz blocks into an sz-byte buffer overruns it by a factor
 * of the 136-byte rate. Squeeze whole blocks into this staging buffer and hand
 * out bytes from it, carrying the remainder so the stream stays continuous
 * across calls of any size. */
static byte     mcdc_sr_buf[WC_SHA3_256_BLOCK_SIZE];
static word32   mcdc_sr_left = 0;

/* Arm with a pinned seed. The stream is SHAKE-256(seed) squeezed forward, so
 * it is identical on every host and build. */
static void mcdc_sr_arm(unsigned long seed)
{
    byte s[8];
    int i;

    /* Drop any staging bytes left from a previous arming, or re-arming the
     * same seed hands those out before restarting the seeded squeeze. */
    mcdc_sr_left = 0;
    for (i = 0; i < 8; i++) {
        s[i] = (byte)((seed >> (8 * i)) & 0xff);
    }
    if (mcdc_sr_ready) {
        wc_Shake256_Free(&mcdc_sr_shake);
        mcdc_sr_ready = 0;
    }
    if (wc_InitShake256(&mcdc_sr_shake, NULL, INVALID_DEVID) != 0) {
        return;
    }
    if (wc_Shake256_Absorb(&mcdc_sr_shake, s, (word32)sizeof(s)) != 0) {
        wc_Shake256_Free(&mcdc_sr_shake);
        return;
    }
    mcdc_sr_ready = 1;
    mcdc_sr_active = 1;
}

static void mcdc_sr_disarm(void)
{
    mcdc_sr_active = 0;
}

/* Rewind to the start of the pinned stream without re-absorbing. */
static void mcdc_sr_rewind(unsigned long seed)
{
    mcdc_sr_left = 0;
    mcdc_sr_arm(seed);
}

static void mcdc_sr_restore(void)
{
    mcdc_sr_active = 0;
    mcdc_sr_left = 0;
    if (mcdc_sr_ready) {
        wc_Shake256_Free(&mcdc_sr_shake);
        mcdc_sr_ready = 0;
    }
}

int mcdc_sr_block(WC_RNG* rng, byte* out, word32 sz)
{
    if (!mcdc_sr_active || !mcdc_sr_ready) {
        return wc_RNG_GenerateBlock(rng, out, sz);
    }
    if (out == NULL) {
        return BAD_FUNC_ARG;
    }
    while (sz > 0) {
        word32 n;

        if (mcdc_sr_left == 0) {
            int ret = wc_Shake256_SqueezeBlocks(&mcdc_sr_shake, mcdc_sr_buf, 1);

            if (ret != 0) {
                return ret;
            }
            mcdc_sr_left = (word32)sizeof(mcdc_sr_buf);
        }
        n = (sz < mcdc_sr_left) ? sz : mcdc_sr_left;
        XMEMCPY(out, mcdc_sr_buf + (sizeof(mcdc_sr_buf) - mcdc_sr_left), n);
        out += n;
        sz -= n;
        mcdc_sr_left -= n;
    }
    return 0;
}

#else /* MCDC_SR_UNAVAILABLE */

/* Inert stubs. Without these a TU that calls mcdc_sr_arm() fails to COMPILE in
 * any variant lacking SHAKE -- and the campaign scores a white-box that fails
 * to compile as a SILENT SKIP, losing the whole file's coverage rather than
 * reporting an error. (Observed on the dh module: 12 variants aggregated
 * became 6, and dh.c read 107/173 instead of 158/173.) A header that is
 * conditionally available must still define its API unconditionally, exactly
 * as mcdc_fault_alloc.h does. */
static void mcdc_sr_arm(unsigned long seed)     { (void)seed; }
static void mcdc_sr_rewind(unsigned long seed)  { (void)seed; }
static void mcdc_sr_disarm(void)                { }
static void mcdc_sr_restore(void)               { }

#endif /* !MCDC_SR_UNAVAILABLE */

#endif /* MCDC_SR_IMPL */
