/* test_sp_arm_point_specials.h
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

#ifndef WOLFSSL_TEST_SP_ARM_POINT_SPECIALS_H
#define WOLFSSL_TEST_SP_ARM_POINT_SPECIALS_H

/* Included after the SP backend and the white-box status helpers. */
#if defined(WOLFSSL_HAVE_SP_ECC) && defined(HAVE_ECC) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)

/* ----------------------------------------------------------------------- *
 * sp_ecc_is_point_<n>() / sp_ecc_check_key_<n>(): point-at-infinity and
 * out-of-range-ordinate special cases, driven directly with hand-built
 * mp_int inputs (no need for a valid key -- these functions only inspect
 * the ordinates handed to them).
 * ----------------------------------------------------------------------- */
/* A row that targets a range or sign guard must be rejected by it; anything
 * else means that guard was lost in a regeneration of the SP back end. */
static void wb_expect_range(int ret, const char* what)
{
    if (ret != WC_NO_ERR_TRACE(ECC_OUT_OF_RANGE_E)) {
        printf("  [wb][FAIL] %s did not return ECC_OUT_OF_RANGE_E (got %d)\n",
            what, ret);
        wb_bad = 1;
    }
}

static void wb_run_point_specials(int fieldBits, const char* label,
    int (*is_point)(const mp_int*, const mp_int*),
    int (*check_key)(const mp_int*, const mp_int*, const mp_int*, void*))
{
    mp_int zero;
    mp_int small;
    mp_int big;
    mp_int atMax;
    mp_int neg;
    int    haveNeg;
    byte   bigbuf[96];
    byte   maxbuf[128];
    int    nbytes = fieldBits / 8 + 9; /* comfortably more bits than fieldBits */
    int    maxbytes = (fieldBits + 7) / 8;
    int    topbits = fieldBits - ((maxbytes - 1) * 8);

    if (nbytes > (int)sizeof(bigbuf)) {
        nbytes = (int)sizeof(bigbuf);
    }
    XMEMSET(bigbuf, 0xFF, sizeof(bigbuf));
    /* Exactly fieldBits wide and all ones, so it is not less than any of the
     * moduli here while still passing the bit-length guard. */
    XMEMSET(maxbuf, 0xFF, sizeof(maxbuf));
    maxbuf[0] = (byte)((1u << topbits) - 1u);

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
    if (mp_init(&atMax) != MP_OKAY) {
        WB_NOTE("mp_init(atMax) failed (point specials)");
        wb_fail = 1;
        mp_clear(&zero);
        mp_clear(&small);
        mp_clear(&big);
        return;
    }
    if (mp_init(&neg) != MP_OKAY) {
        WB_NOTE("mp_init(neg) failed (point specials)");
        wb_fail = 1;
        mp_clear(&zero);
        mp_clear(&small);
        mp_clear(&big);
        mp_clear(&atMax);
        return;
    }

    mp_set(&small, 3);
    /* mp_setneg() is a no-op unless the math back end was built with negative
     * support, so ask the value itself rather than the build macros. */
    mp_set(&neg, 3);
    mp_setneg(&neg);
    haveNeg = mp_isneg(&neg) ? 1 : 0;
    if ((mp_read_unsigned_bin(&big, bigbuf, (word32)nbytes) != MP_OKAY) ||
            (mp_read_unsigned_bin(&atMax, maxbuf, (word32)maxbytes)
                != MP_OKAY)) {
        WB_NOTE("mp_read_unsigned_bin failed (point specials)");
        wb_fail = 1;
    }
    else {
        /* Point at infinity (x == 0 && y == 0). is_point() has no explicit
         * "point at infinity" branch, so this drives its general field math
         * with a degenerate operand; check_key() below has that branch. */
        (void)is_point(&zero, &zero);
        /* A small, well-formed, off-curve pair: exercises the same field
         * math with a non-degenerate, non-infinity operand. */
        (void)is_point(&small, &small);
        /* mp_count_bits(pX) > fieldBits, independently true. */
        wb_expect_range(is_point(&big, &small), "is_point(big, small)");
        /* mp_count_bits(pY) > fieldBits, independently true. */
        wb_expect_range(is_point(&small, &big), "is_point(small, big)");
        /* The bit-length guard passes, so only sp_<n>_cmp_<m>(pub->x, mod)
         * >= 0 can reject: that arm independently true. */
        wb_expect_range(is_point(&atMax, &small), "is_point(atMax, small)");
        /* Same for the pub->y arm of that compare. */
        wb_expect_range(is_point(&small, &atMax), "is_point(small, atMax)");
        if (haveNeg) {
            /* mp_isneg(pX), then mp_isneg(pY), independently true. */
            wb_expect_range(is_point(&neg, &small), "is_point(neg, small)");
            wb_expect_range(is_point(&small, &neg), "is_point(small, neg)");
        }
        else {
            WB_NOTE("math back end has no negative support; sign rows "
                    "skipped");
        }

        if (check_key != NULL) {
            /* (sp_<n>_iszero_<n>(pub->x) != 0) &&
             * (sp_<n>_iszero_<n>(pub->y) != 0) -- point at infinity. */
            (void)check_key(&zero, &zero, NULL, NULL);
            /* mp_count_bits(pX) > fieldBits, independently true. */
            wb_expect_range(check_key(&big, &small, NULL, NULL),
                "check_key(big, small)");
            /* mp_count_bits(pY) > fieldBits, independently true. */
            wb_expect_range(check_key(&small, &big, NULL, NULL),
                "check_key(small, big)");
            /* (privm != NULL) && (mp_count_bits(privm) > fieldBits),
             * independently true. */
            wb_expect_range(check_key(&small, &small, &big, NULL),
                "check_key(small, small, big)");
            /* privm != NULL and in range: falls through to the
             * is-point-on-curve / order / private-key checks. (3, 3) is
             * not on the curve, so this reaches (and cleanly fails) that
             * logic without needing a real key. */
            (void)check_key(&small, &small, &small, NULL);
            if (haveNeg) {
                /* mp_isneg(pX), then mp_isneg(pY), independently true. */
                wb_expect_range(check_key(&neg, &small, NULL, NULL),
                    "check_key(neg, small)");
                wb_expect_range(check_key(&small, &neg, NULL, NULL),
                    "check_key(small, neg)");
            }
        }
        else {
            WB_NOTE("check_key needs HAVE_ECC_CHECK_KEY || "
                     "!NO_ECC_CHECK_PUBKEY_ORDER; skipped");
        }
    }

    mp_clear(&neg);
    mp_clear(&atMax);
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

#endif
#endif
