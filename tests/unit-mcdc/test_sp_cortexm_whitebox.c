/* test_sp_cortexm_whitebox.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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
 * MC/DC white-box supplement for the Cortex-M SP backend
 * (wolfcrypt/src/sp_cortexm.c), driven under the bare-metal m33mu emulator
 * lane (campaign lane "m33mu", config configs/sp-arm-lanes/user_settings.cortexm.h).
 *
 * LANE CONTRACT / WHY A CONSTRUCTOR (not the usual #include-the-.c whitebox):
 *   The m33mu lane instruments sp_cortexm.c as its own clang TU and links it
 *   into a firmware whose fixed entry is wolfcrypt_test_main() (the KAT suite,
 *   wolfcrypt/test/test.c). It exposes no per-module main() and no
 *   #include-and-trim mechanism, so a classic whitebox that
 *   `#include <wolfcrypt/src/sp_cortexm.c>` would duplicate every non-static
 *   symbol at link. Instead this TU is wired in as a lane_extra_source
 *   (EXTRA_SRCS): it is compiled by the firmware's gcc (NOT instrumented) and
 *   its coverage lands in the already-instrumented sp_cortexm.c counters via
 *   real calls to that module's EXTERNAL-linkage entry points (sp.h's
 *   WOLFSSL_LOCAL sp_ecc_*_256 / sp_ModExp_2048 -- external linkage, reachable
 *   from another TU; the sp_256_ and sp_2048_ helpers underneath are static
 *   and are reached transitively).
 *
 *   The driver runs from a __attribute__((constructor)): the harness'
 *   Reset_Handler calls __libc_init_array() (which runs .init_array) BEFORE
 *   main(), so these calls execute and accumulate into the profile counters
 *   that main() later streams out over the UART on KAT success. target.ld
 *   KEEP()s .init_array, so -gc-sections cannot drop the constructor.
 *
 * WHAT IT ADDS over the KATs: the P-256 KAT exercises make_key / secret_gen /
 * sign / verify with map=1 only, and the RSA-2048 KAT only ever calls the SP
 * RSA path with well-formed input. This driver additionally reaches
 * sp_ecc_mulmod_256 with map=0, sp_ecc_mulmod_base_256, sp_ecc_is_point_256
 * (valid AND invalid point -> both sides of the on-curve decision),
 * sp_ecc_check_key_256, sp_ecc_proj_add_point_256 (distinct / equal / infinity
 * operands -> the add-vs-double and identity special-case decisions),
 * sp_ecc_proj_dbl_point_256, sp_ecc_map_256, sp_ecc_uncompress_256 (both
 * y-parities), sp_ecc_mulmod_add_256 / sp_ecc_mulmod_base_add_256 (the
 * add-point Montgomery-form flag), sp_ecc_sign_256 (deterministic supplied-k
 * and a NULL-RNG failure path), sp_ecc_verify_256 (steering the internal
 * u1/u2 scalars through hash/r to hit the point-at-infinity, P==Q/P==-Q and
 * signature-malleability fallback branches), sp_ecc_check_key_256's guard
 * clauses, and the RSA-2048/3072 and DH-2048/3072 SP entry points' length
 * guards and windowed-modexp loops (none of which the RSA-2048-only KAT
 * drives past its own well-formed input). All calls are crash-safe: every
 * buffer is zero-initialised, every mp_int is mp_init'd, and no result is
 * asserted (a nonzero return only bumps a counter, never faults the
 * firmware). None of the RSA/DH/ECC values below are real keys or a real
 * transcript -- they are fixed constants chosen only to steer a decision.
 */

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_SP_ARM_CORTEX_M_ASM) && defined(WOLFSSL_HAVE_SP_ECC) && \
    !defined(WOLFSSL_SP_NO_256) && defined(HAVE_ECC)

#include <wolfssl/wolfcrypt/sp.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/integer.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* NIST P-256 base point G and group order n (big-endian hex). */
static const char* P256_GX =
    "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";
static const char* P256_GY =
    "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5";
static const char* P256_N =
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";
/* NIST P-256 field prime p (used to negate a Y ordinate: -Y = p - Y). */
static const char* P256_PRIME =
    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";

/* Fixed-width odd moduli for the RSA/DH SP entry points below. Not prime and
 * not a real key: guard-clause and windowed-modexp-loop targets only care
 * about bit length and parity (odd, so mp_iseven() bails do not trigger where
 * unwanted), never about factorization or cryptographic correctness. */
static const char* RSA2048_N =
    "8FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD";
static const char* RSA3072_N =
    "8FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD";
/* Two distinct 1536-bit odd halves: stand-ins for RSA-3072 CRT p and q. Only
 * bit width (1536) and parity matter to sp_3072_mod_exp_48(); the CRT combine
 * step is never asserted for correctness. */
static const char* RSA3072_P =
    "8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA3";
static const char* RSA3072_Q =
    "8555555555555555555555555555555555555555555555555555555555555555"
    "5555555555555555555555555555555555555555555555555555555555555555"
    "5555555555555555555555555555555555555555555555555555555555555555"
    "5555555555555555555555555555555555555555555555555555555555555555"
    "5555555555555555555555555555555555555555555555555555555555555555"
    "5555555555555555555555555555555555555555555555555555555555555557";

/* Visible so the run is observable but never asserted: number of sp_cortexm.c
 * entry-point calls that returned an unexpected status. Non-fatal by design. */
volatile unsigned int wb_sp_cortexm_fail = 0u;
volatile unsigned int wb_sp_cortexm_calls = 0u;

static void wb_note(int ret, int ok)
{
    wb_sp_cortexm_calls++;
    if (ret != ok) {
        wb_sp_cortexm_fail++;
    }
}

/* mp_int is large under SP_MATH; keep these off the constructor's stack. */
static mp_int wb_gx, wb_gy, wb_gz, wb_n, wb_k;
static mp_int wb_rx, wb_ry, wb_rz;
static mp_int wb_sx, wb_sy, wb_sz;
static ecc_point wb_g, wb_r;

/* --- extra state for the RSA/DH/ECC gap-closing calls below. Same
 * file-static, never-on-the-constructor's-stack rule as above. */
static mp_int wb2_mm2048, wb2_mm3072, wb2_p1536, wb2_q1536;
static mp_int wb2_p256_prime, wb2_gy_neg;
static mp_int wb2_zero, wb2_five, wb2_one, wb2_e65537;
static mp_int wb2_base, wb2_r, wb2_s, wb2_rlarge, wb2_negr, wb2_kval;
static mp_int wb2_rm_out, wb2_sm_out;
static ecc_point wb2_t;
static byte wb2_in[400];
static byte wb2_out[400];
static byte wb2_hash[32];
static const byte wb2_dh_exp_65537[3] = { 0x01, 0x00, 0x01 };
static const byte wb2_dh_exp_3[1] = { 0x03 };

static int wb_mp_hex(mp_int* a, const char* s)
{
    if (mp_init(a) != MP_OKAY) {
        return -1;
    }
    return mp_read_radix(a, s, MP_RADIX_HEX);
}

/* Encode an mp_int as a fixed 32-byte big-endian "hash" so its value can be
 * driven in through sp_ecc_sign_256()/sp_ecc_verify_256()'s hash argument
 * (used to steer the internal u1/u2 scalars from outside). */
static void wb2_mp_to_hash(mp_int* v)
{
    XMEMSET(wb2_hash, 0, sizeof(wb2_hash));
    (void)mp_to_unsigned_bin_len(v, wb2_hash, (int)sizeof(wb2_hash));
}

__attribute__((constructor))
static void sp_cortexm_whitebox_drive(void)
{
    int ret;
    int res;

    /* Zero every aggregate before use (crash-safety on bare metal). */
    XMEMSET(&wb_g, 0, sizeof(wb_g));
    XMEMSET(&wb_r, 0, sizeof(wb_r));

    if (mp_init(&wb_gz) != MP_OKAY || mp_init(&wb_k) != MP_OKAY ||
        mp_init(&wb_rx) != MP_OKAY || mp_init(&wb_ry) != MP_OKAY ||
        mp_init(&wb_rz) != MP_OKAY || mp_init(&wb_sx) != MP_OKAY ||
        mp_init(&wb_sy) != MP_OKAY || mp_init(&wb_sz) != MP_OKAY) {
        return;
    }
    if (mp_init(wb_g.x) != MP_OKAY || mp_init(wb_g.y) != MP_OKAY ||
        mp_init(wb_g.z) != MP_OKAY || mp_init(wb_r.x) != MP_OKAY ||
        mp_init(wb_r.y) != MP_OKAY || mp_init(wb_r.z) != MP_OKAY) {
        return;
    }
    if (wb_mp_hex(&wb_gx, P256_GX) != MP_OKAY ||
        wb_mp_hex(&wb_gy, P256_GY) != MP_OKAY ||
        wb_mp_hex(&wb_n, P256_N) != MP_OKAY) {
        return;
    }

    /* Base point G = (Gx, Gy, 1). */
    (void)mp_copy(&wb_gx, wb_g.x);
    (void)mp_copy(&wb_gy, wb_g.y);
    (void)mp_set(wb_g.z, 1);
    (void)mp_set(&wb_gz, 1);

    /* --- on-curve decision: valid point, then a deliberately invalid one. */
    res = 0;
    ret = sp_ecc_is_point_256(&wb_gx, &wb_gy);
    wb_note(ret, MP_OKAY);                 /* G is on the curve */
    ret = sp_ecc_is_point_256(&wb_gx, &wb_gx); /* (Gx,Gx) is not */
    wb_note((ret != MP_OKAY) ? 0 : -1, 0);

    /* --- scalar mul of the base point, map=1 (affine) and map=0 (Jacobian).
     * k = 3 exercises the window/add path beyond the KAT's random scalar. */
    (void)mp_set(&wb_k, 3);
    ret = sp_ecc_mulmod_base_256(&wb_k, &wb_r, 1, NULL);
    wb_note(ret, MP_OKAY);
    ret = sp_ecc_mulmod_256(&wb_k, &wb_g, &wb_r, 0, NULL); /* map=0 side */
    wb_note(ret, MP_OKAY);

    /* --- projective double of G, then map back to affine. */
    ret = sp_ecc_proj_dbl_point_256(wb_g.x, wb_g.y, wb_g.z,
                                    &wb_rx, &wb_ry, &wb_rz);
    wb_note(ret, MP_OKAY);
    ret = sp_ecc_map_256(&wb_rx, &wb_ry, &wb_rz);
    wb_note(ret, MP_OKAY);

    /* --- projective add: distinct operands (G + 2G). */
    (void)mp_set(wb_r.z, 1);
    ret = sp_ecc_proj_add_point_256(wb_g.x, wb_g.y, wb_g.z,
                                    &wb_rx, &wb_ry, &wb_rz,
                                    &wb_sx, &wb_sy, &wb_sz);
    wb_note(ret, MP_OKAY);

    /* --- projective add: equal operands (G + G) -> internal doubling path. */
    ret = sp_ecc_proj_add_point_256(wb_g.x, wb_g.y, wb_g.z,
                                    wb_g.x, wb_g.y, wb_g.z,
                                    &wb_sx, &wb_sy, &wb_sz);
    wb_note(ret, MP_OKAY);

    /* --- projective add: identity operand (Z=0 point at infinity). */
    (void)mp_set(&wb_rz, 0);
    ret = sp_ecc_proj_add_point_256(wb_g.x, wb_g.y, wb_g.z,
                                    &wb_rx, &wb_ry, &wb_rz,
                                    &wb_sx, &wb_sy, &wb_sz);
    wb_note(ret, MP_OKAY);

    /* --- public-key validation (on-curve + order check). */
    ret = sp_ecc_check_key_256(&wb_gx, &wb_gy, &wb_k, NULL);
    wb_note(ret, MP_OKAY);

    /* --- point decompression, both y parities (the sqrt/odd decision). */
    ret = sp_ecc_uncompress_256(&wb_gx, 0, &wb_ry);
    wb_note(ret, MP_OKAY);
    ret = sp_ecc_uncompress_256(&wb_gx, 1, &wb_ry);
    wb_note(ret, MP_OKAY);

    /* ================================================================
     * Extra coverage: RSA-2048/3072 and DH-2048/3072 guard clauses and
     * windowed-modexp loops, plus ECC sign/verify/check-key paths that the
     * P-256 KAT and the calls above never reach. All values below are
     * fixed constants chosen to steer a decision, not a real key or a real
     * DH/RSA transcript; nothing here is asserted beyond a wb_note() tally.
     * ================================================================ */
    if (mp_init(&wb2_gy_neg) != MP_OKAY || mp_init(&wb2_zero) != MP_OKAY ||
        mp_init(&wb2_five) != MP_OKAY || mp_init(&wb2_one) != MP_OKAY ||
        mp_init(&wb2_e65537) != MP_OKAY || mp_init(&wb2_base) != MP_OKAY ||
        mp_init(&wb2_r) != MP_OKAY || mp_init(&wb2_s) != MP_OKAY ||
        mp_init(&wb2_rlarge) != MP_OKAY || mp_init(&wb2_negr) != MP_OKAY ||
        mp_init(&wb2_kval) != MP_OKAY || mp_init(&wb2_rm_out) != MP_OKAY ||
        mp_init(&wb2_sm_out) != MP_OKAY) {
        return;
    }
    XMEMSET(&wb2_t, 0, sizeof(wb2_t));
    if (mp_init(wb2_t.x) != MP_OKAY || mp_init(wb2_t.y) != MP_OKAY ||
        mp_init(wb2_t.z) != MP_OKAY) {
        return;
    }
    if (wb_mp_hex(&wb2_mm2048, RSA2048_N) != MP_OKAY ||
        wb_mp_hex(&wb2_mm3072, RSA3072_N) != MP_OKAY ||
        wb_mp_hex(&wb2_p1536, RSA3072_P) != MP_OKAY ||
        wb_mp_hex(&wb2_q1536, RSA3072_Q) != MP_OKAY ||
        wb_mp_hex(&wb2_p256_prime, P256_PRIME) != MP_OKAY) {
        return;
    }
    (void)mp_set(&wb2_zero, 0);
    (void)mp_set(&wb2_five, 5);
    (void)mp_set(&wb2_one, 1);
    (void)mp_set(&wb2_e65537, 0x10001);
    (void)mp_set(&wb2_base, 3);
    (void)mp_sub(&wb2_p256_prime, &wb_gy, &wb2_gy_neg); /* -Gy = p - Gy */
    (void)mp_sub_d(&wb_n, 1, &wb2_rlarge);              /* order - 1 */

    /* --- sp_RsaPublic_2048 guard: mp_count_bits(em)>32 || inLen>256 ||
     * mp_count_bits(mm)!=2048. All-false baseline is already exercised by
     * the KAT's real RSA-2048 sign/verify; each call below flips one
     * condition and bails (MP_READ_E) before any modexp -- cheap. */
    {
        word32 outLen = sizeof(wb2_out);
        ret = sp_RsaPublic_2048(wb2_in, 4, &wb2_mm2048 /* em: >32 bits */,
            &wb2_mm2048, wb2_out, &outLen);
        wb_note((ret == MP_READ_E) ? 0 : -1, 0);

        outLen = sizeof(wb2_out);
        ret = sp_RsaPublic_2048(wb2_in, 257 /* inLen > 256 */, &wb2_e65537,
            &wb2_mm2048, wb2_out, &outLen);
        wb_note((ret == MP_READ_E) ? 0 : -1, 0);

        outLen = sizeof(wb2_out);
        ret = sp_RsaPublic_2048(wb2_in, 4, &wb2_e65537,
            &wb_n /* mm: 256 bits, not 2048 */, wb2_out, &outLen);
        wb_note((ret == MP_READ_E) ? 0 : -1, 0);
    }

    /* --- sp_RsaPrivate_2048 (CRT branch) guard: inLen>256 ||
     * mp_count_bits(mm)!=2048. dm/pm/qm/dpm/dqm/qim are never read once the
     * guard trips, so a shared dummy is fine. */
    {
        word32 outLen = sizeof(wb2_out);
        ret = sp_RsaPrivate_2048(wb2_in, 257, &wb_k, &wb_k, &wb_k, &wb_k,
            &wb_k, &wb_k, &wb2_mm2048, wb2_out, &outLen);
        wb_note((ret == MP_READ_E) ? 0 : -1, 0);

        outLen = sizeof(wb2_out);
        ret = sp_RsaPrivate_2048(wb2_in, 4, &wb_k, &wb_k, &wb_k, &wb_k,
            &wb_k, &wb_k, &wb_n, wb2_out, &outLen);
        wb_note((ret == MP_READ_E) ? 0 : -1, 0);
    }

    /* --- sp_DhExp_2048: FFDHE-2 fast path `base->used==1 && base->dp[0]==2
     * && m[63]==-1` -- flip the dp[0]==2 operand (base=3, still used==1),
     * routing through the general modexp; a small (0x10001) exponent keeps
     * it cheap and gives a dense, non-zero-leading result that closes the
     * trailing zero-strip loop's "found a non-zero byte" row. The base=0
     * call gives an all-zero result, closing that loop's i==256 boundary
     * row. */
    {
        word32 outLen = sizeof(wb2_out);
        ret = sp_DhExp_2048(&wb2_base /* =3, not 2 */, wb2_dh_exp_65537,
            sizeof(wb2_dh_exp_65537), &wb2_mm2048, wb2_out, &outLen);
        wb_note(ret, MP_OKAY);

        outLen = sizeof(wb2_out);
        ret = sp_DhExp_2048(&wb2_zero, wb2_dh_exp_3, sizeof(wb2_dh_exp_3),
            &wb2_mm2048, wb2_out, &outLen);
        wb_note(ret, MP_OKAY);
    }

    /* --- sp_RsaPublic_3072 guard, same 3-way OR as the 2048 sibling.
     * Nothing else in this build drives the 3072 SP path, so the first call
     * is also the all-false baseline: e=0x10001 takes the cheap repeated-
     * squaring fast path instead of a general modexp. */
    {
        word32 outLen = sizeof(wb2_out);
        ret = sp_RsaPublic_3072(wb2_in, 4, &wb2_e65537, &wb2_mm3072,
            wb2_out, &outLen);
        wb_note(ret, MP_OKAY);

        outLen = sizeof(wb2_out);
        ret = sp_RsaPublic_3072(wb2_in, 4, &wb2_mm3072 /* em: >32 bits */,
            &wb2_mm3072, wb2_out, &outLen);
        wb_note((ret == MP_READ_E) ? 0 : -1, 0);

        outLen = sizeof(wb2_out);
        ret = sp_RsaPublic_3072(wb2_in, 385 /* inLen > 384 */, &wb2_e65537,
            &wb2_mm3072, wb2_out, &outLen);
        wb_note((ret == MP_READ_E) ? 0 : -1, 0);

        outLen = sizeof(wb2_out);
        ret = sp_RsaPublic_3072(wb2_in, 4, &wb2_e65537,
            &wb_n /* mm: 256 bits, not 3072 */, wb2_out, &outLen);
        wb_note((ret == MP_READ_E) ? 0 : -1, 0);
    }

    /* --- sp_RsaPrivate_3072 (CRT branch) guard: inLen>384 ||
     * mp_count_bits(mm)!=3072. The first call is the all-false baseline and
     * also the only way in this lane to drive sp_3072_mod_exp_48() (the
     * fixed-1536-bit CRT half-exponent windowed loop): p/q are fixed
     * 1536-bit odd stand-ins, not a real key, and dp/dq/qi only need to be
     * present to keep that fixed-length loop's shape -- their value does
     * not matter. */
    {
        word32 outLen = sizeof(wb2_out);
        ret = sp_RsaPrivate_3072(wb2_in, 4, &wb_k, &wb2_p1536, &wb2_q1536,
            &wb_k, &wb_k, &wb_k, &wb2_mm3072, wb2_out, &outLen);
        wb_note(ret, MP_OKAY);

        outLen = sizeof(wb2_out);
        ret = sp_RsaPrivate_3072(wb2_in, 385, &wb_k, &wb_k, &wb_k, &wb_k,
            &wb_k, &wb_k, &wb2_mm3072, wb2_out, &outLen);
        wb_note((ret == MP_READ_E) ? 0 : -1, 0);

        outLen = sizeof(wb2_out);
        ret = sp_RsaPrivate_3072(wb2_in, 4, &wb_k, &wb_k, &wb_k, &wb_k,
            &wb_k, &wb_k, &wb_n, wb2_out, &outLen);
        wb_note((ret == MP_READ_E) ? 0 : -1, 0);
    }

    /* --- sp_DhExp_3072: no FFDHE_3072 fast path compiled into this build,
     * so this only needs to drive sp_3072_mod_exp_96()'s windowed loop and
     * the trailing zero-strip loop, mirroring the 2048 case above. */
    {
        word32 outLen = sizeof(wb2_out);
        ret = sp_DhExp_3072(&wb2_base, wb2_dh_exp_65537,
            sizeof(wb2_dh_exp_65537), &wb2_mm3072, wb2_out, &outLen);
        wb_note(ret, MP_OKAY);

        outLen = sizeof(wb2_out);
        ret = sp_DhExp_3072(&wb2_zero, wb2_dh_exp_3, sizeof(wb2_dh_exp_3),
            &wb2_mm3072, wb2_out, &outLen);
        wb_note(ret, MP_OKAY);
    }

    /* --- sp_ecc_mulmod_add_256 / sp_ecc_mulmod_base_add_256: each has
     * three `(err == MP_OKAY) && (!inMont)` guards on converting the
     * add-point into Montgomery form. err is structurally always MP_OKAY
     * at these sites in this build (nothing here can fail without a heap
     * allocator -- see report), so only the inMont operand is closable;
     * map=0 skips the extra point-map modular inverse to keep both calls
     * cheap. */
    ret = sp_ecc_mulmod_add_256(&wb_k, &wb_g, &wb_r, 0, &wb2_t, 0, NULL);
    wb_note(ret, MP_OKAY);
    ret = sp_ecc_mulmod_add_256(&wb_k, &wb_g, &wb_r, 1, &wb2_t, 0, NULL);
    wb_note(ret, MP_OKAY);

    ret = sp_ecc_mulmod_base_add_256(&wb_k, &wb_r, 0, &wb2_t, 0, NULL);
    wb_note(ret, MP_OKAY);
    ret = sp_ecc_mulmod_base_add_256(&wb_k, &wb_r, 1, &wb2_t, 0, NULL);
    wb_note(ret, MP_OKAY);

    /* --- sp_ecc_sign_256: `km == NULL || mp_iszero(km)`. SGN1 passes a
     * non-NULL *zero* km (mp_iszero side true) together with a NULL rng, so
     * the internal ephemeral-k generator hands a NULL WC_RNG* to
     * wc_RNG_GenerateBlock(), which null-checks its first argument and
     * fails immediately -- this is also the only reachable way to flip the
     * signing for-loop's `err == MP_OKAY` operand without exhausting all
     * SP_ECC_MAX_SIG_GEN retries. SGN2 supplies a real (fixed, not
     * generated) nonzero km, taking the deterministic-k branch for one
     * real, bounded-cost sign. */
    (void)mp_set(&wb2_zero, 0);
    ret = sp_ecc_sign_256(wb2_hash, sizeof(wb2_hash), NULL, &wb_k,
        &wb2_rm_out, &wb2_sm_out, &wb2_zero, NULL);
    wb_note((ret == MP_OKAY) ? -1 : 0, 0);

    (void)mp_set(&wb2_kval, 777);
    ret = sp_ecc_sign_256(wb2_hash, sizeof(wb2_hash), NULL, &wb_k,
        &wb2_rm_out, &wb2_sm_out, &wb2_kval, NULL);
    wb_note(ret, MP_OKAY);

    /* --- sp_ecc_verify_256 with pub = G (z=1): internally u1 = e/s and
     * u2 = r/s mod order, so hash (=e) and r steer the *points* fed to
     * sp_256_add_points_8()/sp_256_calc_vfy_point_8() without needing a
     * forged or real signature. s cancels out of the u1:u2 ratio, so it is
     * free to vary per call -- used here to also diversify
     * sp_256_mod_inv_8()'s binary-gcd input. */

    /* V1: hash=0 => u1=0 => p1 = 0*G = infinity (calc_vfy_point_8's
     * `iszero(p1->z)` true row). r=1 is small enough that r+order < prime,
     * landing verify's fallback `(*res==0) && (c<0)` in its true row. */
    XMEMSET(wb2_hash, 0, sizeof(wb2_hash));
    (void)mp_set(&wb2_r, 1);
    (void)mp_set(&wb2_s, 3);
    ret = sp_ecc_verify_256(wb2_hash, sizeof(wb2_hash), wb_g.x, wb_g.y,
        wb_g.z, &wb2_r, &wb2_s, &res, NULL);
    wb_note(ret, MP_OKAY);

    /* V2: r=0 => u2=0 => p2 = 0*Q = infinity (calc_vfy_point_8's
     * `iszero(p2->z)` true row). */
    XMEMSET(wb2_hash, 0x11, sizeof(wb2_hash));
    (void)mp_set(&wb2_r, 0);
    (void)mp_set(&wb2_s, 5);
    ret = sp_ecc_verify_256(wb2_hash, sizeof(wb2_hash), wb_g.x, wb_g.y,
        wb_g.z, &wb2_r, &wb2_s, &res, NULL);
    wb_note(ret, MP_OKAY);

    /* V3: hash = r = R => u1 == u2 => p1 == p2 = R*G, both the *same*
     * point => sp_256_add_points_8()'s `iszero(x) && iszero(y)` true row
     * (the P==Q / needs-doubling signal). */
    (void)mp_set_int(&wb2_r, 123456789UL);
    wb2_mp_to_hash(&wb2_r);
    (void)mp_set(&wb2_s, 3);
    ret = sp_ecc_verify_256(wb2_hash, sizeof(wb2_hash), wb_g.x, wb_g.y,
        wb_g.z, &wb2_r, &wb2_s, &res, NULL);
    wb_note(ret, MP_OKAY);

    /* V4: hash = order - r => u1 == -u2 => p1 == -p2 (R*G + (-R)*G = O via
     * the true point-negation path) => the same iszero(x)&&iszero(y) check
     * false (P==-Q, genuine point at infinity, not the doubling signal). */
    (void)mp_sub(&wb_n, &wb2_r, &wb2_negr);
    wb2_mp_to_hash(&wb2_negr);
    (void)mp_set(&wb2_s, 0xFFFF);
    ret = sp_ecc_verify_256(wb2_hash, sizeof(wb2_hash), wb_g.x, wb_g.y,
        wb_g.z, &wb2_r, &wb2_s, &res, NULL);
    wb_note(ret, MP_OKAY);

    /* V5: r = order-1 => r+order >= prime, closing verify's fallback
     * `(*res==0) && (c<0)` false row (c>=0). */
    XMEMSET(wb2_hash, 0x22, sizeof(wb2_hash));
    (void)mp_set(&wb2_s, 7);
    ret = sp_ecc_verify_256(wb2_hash, sizeof(wb2_hash), wb_g.x, wb_g.y,
        wb_g.z, &wb2_rlarge, &wb2_s, &res, NULL);
    wb_note(ret, MP_OKAY);

    /* --- sp_ecc_check_key_256: the quick length guard is
     * A||B||(C&&D) with A=pX>256 bits, B=pY>256 bits, C=privm!=NULL,
     * D=privm>256 bits. K3 (all-false) is the baseline; K1/K2/K4 flip one
     * leaf each. */
    ret = sp_ecc_check_key_256(&wb2_mm2048, &wb_gy, NULL, NULL); /* K1: A */
    wb_note((ret == ECC_OUT_OF_RANGE_E) ? 0 : -1, 0);
    ret = sp_ecc_check_key_256(&wb_gx, &wb2_mm2048, NULL, NULL); /* K2: B */
    wb_note((ret == ECC_OUT_OF_RANGE_E) ? 0 : -1, 0);
    ret = sp_ecc_check_key_256(&wb_gx, &wb_gy, NULL, NULL);      /* K3 */
    wb_note(ret, MP_OKAY);
    ret = sp_ecc_check_key_256(&wb_gx, &wb_gy, &wb2_mm2048, NULL); /* K4 */
    wb_note((ret == ECC_OUT_OF_RANGE_E) ? 0 : -1, 0);

    /* Point-at-infinity check `iszero(x) && iszero(y)`: K5 both zero (T,T),
     * K6/K7 flip one ordinate each. */
    ret = sp_ecc_check_key_256(&wb2_zero, &wb2_zero, NULL, NULL); /* K5 */
    wb_note((ret == ECC_INF_E) ? 0 : -1, 0);
    ret = sp_ecc_check_key_256(&wb2_five, &wb2_zero, NULL, NULL); /* K6 */
    wb_note((ret != MP_OKAY) ? 0 : -1, 0);
    ret = sp_ecc_check_key_256(&wb2_zero, &wb2_five, NULL, NULL); /* K7 */
    wb_note((ret != MP_OKAY) ? 0 : -1, 0);

    /* Ordinate-range check `cmp(x,mod)>=0 || cmp(y,mod)>=0`: K8/K9 set one
     * ordinate to the field prime itself (equal, so cmp>=0). */
    ret = sp_ecc_check_key_256(&wb2_p256_prime, &wb_gy, NULL, NULL); /* K8 */
    wb_note((ret == ECC_OUT_OF_RANGE_E) ? 0 : -1, 0);
    ret = sp_ecc_check_key_256(&wb_gx, &wb2_p256_prime, NULL, NULL); /* K9 */
    wb_note((ret == ECC_OUT_OF_RANGE_E) ? 0 : -1, 0);

    /* Private-key-matches-public-key check
     * `cmp(p->x,pub->x)!=0 || cmp(p->y,pub->y)!=0`: K10 uses pub = -G with
     * privm=1 (1*G = G), so X matches but Y does not (closes the Y leaf).
     * K11 reuses the existing off-curve (Gx,Gx) point to fail the earlier
     * on-curve check with privm supplied, closing the `err == MP_OKAY`
     * leaf (the only reachable way: see report). */
    ret = sp_ecc_check_key_256(&wb_gx, &wb2_gy_neg, &wb2_one, NULL); /* K10 */
    wb_note((ret == ECC_PRIV_KEY_E) ? 0 : -1, 0);
    ret = sp_ecc_check_key_256(&wb_gx, &wb_gx, &wb_k, NULL);         /* K11 */
    wb_note((ret != MP_OKAY) ? 0 : -1, 0);

    mp_free(&wb2_mm2048); mp_free(&wb2_mm3072);
    mp_free(&wb2_p1536); mp_free(&wb2_q1536);
    mp_free(&wb2_p256_prime); mp_free(&wb2_gy_neg);
    mp_free(&wb2_zero); mp_free(&wb2_five); mp_free(&wb2_one);
    mp_free(&wb2_e65537); mp_free(&wb2_base);
    mp_free(&wb2_r); mp_free(&wb2_s); mp_free(&wb2_rlarge); mp_free(&wb2_negr);
    mp_free(&wb2_kval); mp_free(&wb2_rm_out); mp_free(&wb2_sm_out);
    mp_free(wb2_t.x); mp_free(wb2_t.y); mp_free(wb2_t.z);

    mp_free(&wb_gx); mp_free(&wb_gy); mp_free(&wb_n); mp_free(&wb_k);
    mp_free(&wb_gz);
    mp_free(&wb_rx); mp_free(&wb_ry); mp_free(&wb_rz);
    mp_free(&wb_sx); mp_free(&wb_sy); mp_free(&wb_sz);
    mp_free(wb_g.x); mp_free(wb_g.y); mp_free(wb_g.z);
    mp_free(wb_r.x); mp_free(wb_r.y); mp_free(wb_r.z);
}

#else

/* Config does not select the Cortex-M SP ECC backend: empty TU. */
typedef int sp_cortexm_whitebox_not_configured;

#endif
