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
 * sign / verify with map=1 only. This driver additionally reaches
 * sp_ecc_mulmod_256 with map=0, sp_ecc_mulmod_base_256, sp_ecc_is_point_256
 * (valid AND invalid point -> both sides of the on-curve decision),
 * sp_ecc_check_key_256, sp_ecc_proj_add_point_256 (distinct / equal / infinity
 * operands -> the add-vs-double and identity special-case decisions),
 * sp_ecc_proj_dbl_point_256, sp_ecc_map_256 and sp_ecc_uncompress_256 (both
 * y-parities). All calls are crash-safe: every buffer is zero-initialised,
 * every mp_int is mp_init'd, and no result is asserted (a nonzero return only
 * bumps a counter, never faults the firmware).
 */

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_SP_ARM_CORTEX_M_ASM) && defined(WOLFSSL_HAVE_SP_ECC) && \
    defined(WOLFSSL_SP_256) && defined(HAVE_ECC)

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

static int wb_mp_hex(mp_int* a, const char* s)
{
    if (mp_init(a) != MP_OKAY) {
        return -1;
    }
    return mp_read_radix(a, s, MP_RADIX_HEX);
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
