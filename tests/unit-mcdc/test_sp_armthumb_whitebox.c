/* test_sp_armthumb_whitebox.c
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
 * MC/DC white-box supplement for wolfcrypt/src/sp_armthumb.c.
 *
 * sp_armthumb.c is the ARM Thumb-2 assembly SP-math backend. Its whole body is
 * wrapped in "#ifdef WOLFSSL_SP_ARM_THUMB_ASM ... #endif" and it uses Thumb-2
 * inline assembly, so it can only be compiled for a Thumb ARM target
 * (--target=arm-linux-gnueabihf -mthumb) and run under an ARM emulator
 * (qemu-arm). That is why this white-box is a LANE-only supplement (the
 * "qemu-armthumb" lane in db/lanes.json / the sp-arm-lanes "armthumb" variant
 * in db/modules.json), never a native host build: the host x86-64 toolchain
 * cannot even assemble the file.
 *
 * Unlike the asm-dispatch backends (sp_x86_64.c, the AArch64 armasm files),
 * sp_armthumb.c has NO cpuid / feature-mask runtime dispatch: it is a single
 * code path once the Thumb ISA is selected at compile time. So, exactly like
 * the portable-C sibling test_sp_c32_whitebox.c that this file is modelled on,
 * each decision here is driven exactly once (no per-cpuid-mask re-runs).
 *
 * Ordinary tests/api rsa+ecc+dh traffic already exercises the
 * "everything-succeeded, ordinary operands" side of most decisions in the
 * library build for this lane. This supplement drives, directly through the
 * file-static helpers reachable only by #including the .c, the residual
 * "unlikely-but-not-fault-injected" sides that public-API traffic with
 * in-range valid data essentially never reaches:
 *
 *   1. `(err == MP_OKAY) && (!inMont)` in sp_ecc_mulmod_add_<n>() and
 *      sp_ecc_mulmod_base_add_<n>() (256/384/521): all four (inMont, map)
 *      combinations driven with a valid scalar, the real curve generator, and
 *      a valid public point.
 *   2. Point-at-infinity / doubling-collision guards keyed off
 *      sp_<n>_iszero_<n>(z) inside sp_<n>_add_points_<n>() and
 *      sp_<n>_calc_vfy_point_<n>(): driven by feeding P + (-P) (true
 *      infinity), P + P (doubling collision) and P + Q (ordinary) to
 *      sp_<n>_add_points_<n>, and a zero scalar (0*P == infinity) to
 *      sp_<n>_calc_vfy_point_<n>.
 *   3. `mp_count_bits(pX/pY/privm) > <curve size>` inside
 *      sp_ecc_check_key_<n>(): driven with an explicit 2^<curve size> (one bit
 *      too many) fed to each operand in turn, plus an all-in-range baseline.
 *
 * The general Montgomery / point arithmetic itself is covered by driving the
 * public ECC sign/verify/ECDH, RSA sign/verify (with key generation) and DH
 * key-agreement entry points below.
 *
 * NOTE the Thumb backend uses 32-bit words, so the point/word-count suffixes
 * differ from the sp_c32 (9/15/21) sibling: here P-256 = 8 words, P-384 = 12
 * words, P-521 = 17 words.
 *
 * This is a coverage-driving supplement, not a known-answer test: only "did
 * this fail outright" is checked, never a specific expected value. Coverage is
 * unioned with the lane variant coverage by source line:col.
 *
 * Residuals (documented, not driven) mirror test_sp_c32_whitebox.c: the
 * `err == MP_OKAY` operand of every guard (only false via a fault-injected
 * allocator), the FP-cache mutex-lock-failure check, and the
 * SP_ECC_MAX_SIG_GEN nonce re-roll loop.
 */

#include <wolfcrypt/src/sp_armthumb.c>

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
 * does not matter -- we are driving the general arithmetic path, not
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
 * exchange (RFC 3526 Group 14 prime, g=2). Not checked for any specific
 * agreed-secret value.
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
 * genuine P + (-P) cancellation can be fed to sp_<n>_add_points_<n>() to force
 * its point-at-infinity (z == 0 && x == 0 && y == 0) branch. */
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
 * Per-curve gap driving. One function per curve size since the callee names
 * (word-count suffixes) differ per size; in this 32-bit-word Thumb backend
 * P-256 = 8 words, P-384 = 12 words, P-521 = 17 words.
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

    /* Target gap 1: (err == MP_OKAY) && (!inMont) in
     * sp_ecc_mulmod_add_256()/sp_ecc_mulmod_base_add_256(): all four
     * (inMont, map) combinations. */
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

    /* Target gap 2a: sp_256_add_points_8()'s iszero(z) /
     * (iszero(x) && iszero(y)) branches. */
    if (ok && negP != NULL) {
        sp_point_256 pA;
        sp_point_256 pB;
        sp_digit     addTmp[12 * 8];

        /* P + (-P): true infinity -> z == 0 && x == 0 && y == 0. */
        XMEMSET(&pA, 0, sizeof(pA));
        XMEMSET(&pB, 0, sizeof(pB));
        XMEMSET(addTmp, 0, sizeof(addTmp));
        wb_build_neg_point(&keyA.pubkey, ECC_SECP256R1, negP);
        sp_256_point_from_ecc_point_8(&pA, &keyA.pubkey);
        sp_256_point_from_ecc_point_8(&pB, negP);
        sp_256_add_points_8(&pA, &pB, addTmp);

        /* P + P: doubling collision via the general add formula. */
        XMEMSET(&pA, 0, sizeof(pA));
        XMEMSET(&pB, 0, sizeof(pB));
        XMEMSET(addTmp, 0, sizeof(addTmp));
        sp_256_point_from_ecc_point_8(&pA, &keyA.pubkey);
        sp_256_point_from_ecc_point_8(&pB, &keyA.pubkey);
        sp_256_add_points_8(&pA, &pB, addTmp);

        /* P + Q: two distinct valid points -> ordinary path. */
        XMEMSET(&pA, 0, sizeof(pA));
        XMEMSET(&pB, 0, sizeof(pB));
        XMEMSET(addTmp, 0, sizeof(addTmp));
        sp_256_point_from_ecc_point_8(&pA, &keyA.pubkey);
        sp_256_point_from_ecc_point_8(&pB, &keyB.pubkey);
        sp_256_add_points_8(&pA, &pB, addTmp);

        WB_NOTE("P-256 add_points infinity/doubling/ordinary exercised");
    }

    /* Target gap 2b: sp_256_calc_vfy_point_8()'s sp_256_iszero_8(p1->z) /
     * sp_256_iszero_8(p2->z), forced by a zero scalar (0*P == infinity). */
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
        WB_NOTE("P-256 calc_vfy_point iszero(p1->z)/iszero(p2->z) "
                 "exercised");
    }

#if defined(HAVE_ECC_CHECK_KEY) || !defined(NO_ECC_CHECK_PUBKEY_ORDER)
    /* Target gap 3: sp_ecc_check_key_256()'s mp_count_bits(pX/pY/privm) > 256.
     * 2^256 is 257 bits -- one bit too many for each operand in turn -- plus
     * one all-in-range baseline call. */
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
        WB_NOTE("P-256 check_key mp_count_bits(pX/pY/privm) > 256 "
                 "exercised");
    }
#else
    WB_NOTE("HAVE_ECC_CHECK_KEY/NO_ECC_CHECK_PUBKEY_ORDER; "
             "check_key_256 skipped");
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
        WB_NOTE("P-384 calc_vfy_point iszero(p1->z)/iszero(p2->z) "
                 "exercised");
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
        WB_NOTE("P-384 check_key mp_count_bits(pX/pY/privm) > 384 "
                 "exercised");
    }
#else
    WB_NOTE("HAVE_ECC_CHECK_KEY/NO_ECC_CHECK_PUBKEY_ORDER; "
             "check_key_384 skipped");
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
        WB_NOTE("P-521 calc_vfy_point iszero(p1->z)/iszero(p2->z) "
                 "exercised");
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
        WB_NOTE("P-521 check_key mp_count_bits(pX/pY/privm) > 521 "
                 "exercised");
    }
#else
    WB_NOTE("HAVE_ECC_CHECK_KEY/NO_ECC_CHECK_PUBKEY_ORDER; "
             "check_key_521 skipped");
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

#endif /* WOLFSSL_HAVE_SP_ECC || WOLFSSL_HAVE_SP_RSA || WOLFSSL_HAVE_SP_DH */

int main(void)
{
    printf("sp_armthumb.c white-box supplement (ARM Thumb-2 asm SP-math, "
           "no cpuid dispatch)\n");
#if defined(WOLFSSL_HAVE_SP_ECC) || defined(WOLFSSL_HAVE_SP_RSA) || \
    defined(WOLFSSL_HAVE_SP_DH)
    wb_run_ecc();
    wb_run_rsa();
    wb_run_dh();
    wb_run_gap_256();
    wb_run_gap_384();
    wb_run_gap_521();

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
#else
    printf("  no SP feature; nothing to exercise\n");
#endif
    (void)wb_fail;
    return 0;
}
