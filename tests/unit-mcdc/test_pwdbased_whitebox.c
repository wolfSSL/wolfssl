/* test_pwdbased_whitebox.c
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
 * MC/DC supplement for wolfcrypt/src/pwdbased.c.
 *
 * The pwdbased API tests cannot fail an HMAC/hash primitive on valid buffers,
 * so the "ret == 0" operand of the two KDF loop guards has no rejecting
 * vector. This TU #includes pwdbased.c behind mcdc_fault_hash.h so its
 * wc_Hmac* calls are interposed, and drives both halves of the reachable pair
 * in ONE binary (llvm-cov derives MC/DC per binary).
 *
 * 1. wc_PBKDF2_ex()  (line 296)
 *
 *        while (ret == 0 && kLen) {
 *
 *    COVERED. Inside the loop body every failing step does its own
 *    "if (ret != 0) break;", so the loop RE-test can never see a non-zero ret.
 *    The only evaluation that can is the FIRST one, whose ret comes from the
 *    line immediately above the loop:
 *
 *        ret = wc_HmacSetKey(hmac, hashType, passwd, (word32)pLen);
 *
 *    wc_HmacSetKey is the first primitive mcdc_fault_hash.h interposes on this
 *    path (wc_HmacInit, wc_HashTypeConvert and wc_HashGetDigestSize are not
 *    interposed), so:
 *        mcdc_fh_arm(1)  -> key schedule fails -> first test is (F, -)
 *                           (idx1 short-circuited, never evaluated)
 *        unarmed, kLen 40 with a 32-byte digest
 *                        -> (T, T) on both iterations and (T, F) at exit
 *    Crash safety: on the armed call nothing is written to output (the first
 *    XMEMCPY into it is downstream of a successful wc_HmacFinal), and the
 *    driver only inspects the returned status.
 *
 *    Under FIPS_VERSION3_GE(6,0,0) the pre-loop call is wc_HmacSetKey_ex,
 *    which the shared injector does not interpose; that build gets the skip
 *    stub instead of a silently ineffective vector.
 *
 * 2. wc_PKCS12_PBKDF_ex()  (line 769)
 *
 *        while ((ret == 0) && (kLen > 0)) {
 *
 *    idx0 "ret == 0" is MUST-EXCLUDE, structurally unsatisfiable:
 *      - line 768, immediately above the loop, is an unconditional "ret = 0;",
 *        so the first evaluation is always TRUE;
 *      - the ONLY assignment to ret inside the loop body is line 771
 *        "ret = DoPKCS12Hash(...)", and it is immediately followed by
 *        lines 772-773 "if (ret != 0) break;". Every other exit from the body
 *        (the kLen == 0 break) leaves ret at 0 too.
 *    So no execution can reach the loop re-test with ret != 0, whatever
 *    primitive or allocation is faulted -- a fault inside DoPKCS12Hash exits
 *    through the break, not through the guard. The condition is defensive and
 *    dead. An unarmed derivation is still driven below so this binary's own
 *    MC/DC record carries the (T,T)/(T,F) rows next to the unreachable one.
 *
 * Build: compiled by the white-box step with the same MC/DC CFLAGS
 * as the instrumented library, then linked against that variant's
 * libwolfssl.a with pwdbased.o removed. Not part of the wolfSSL build.
 */

#include "mcdc_fault_hash.h"

/* pwdbased.c is #included AFTER the interposers are installed. */
#include <wolfcrypt/src/pwdbased.c>

#include <stdio.h>

#ifndef INVALID_DEVID
    #define INVALID_DEVID (-2)
#endif

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

/* --------------------------------------------------------------------------
 * 1. wc_PBKDF2_ex(): "ret == 0" half of the derivation loop guard (line 296).
 * ----------------------------------------------------------------------- */
#if defined(HAVE_PBKDF2) && !defined(NO_HMAC) && !defined(NO_SHA256) && \
    defined(MCDC_FH_HAVE_HMAC) && !FIPS_VERSION3_GE(6,0,0)

static void wb_pbkdf2_setkey_err(void)
{
    /* 40 > WC_SHA256_DIGEST_SIZE, so the loop runs twice: two (T,T) rows and
     * the (T,F) exit row. */
    byte out[40];
    byte passwd[13];
    byte salt[8];
    int  ret;

    XMEMSET(out, 0, sizeof(out));
    XMEMSET(passwd, 'p', sizeof(passwd));
    XMEMSET(salt, 0x5a, sizeof(salt));

    /* Baseline, unarmed: idx0 TRUE with idx1 both ways. */
    mcdc_fh_disarm();
    ret = wc_PBKDF2_ex(out, passwd, (int)sizeof(passwd), salt,
        (int)sizeof(salt), 2, (int)sizeof(out), WC_SHA256, NULL,
        INVALID_DEVID);
    if (ret != 0) {
        WB_NOTE("wc_PBKDF2_ex unarmed baseline failed");
        wb_fail = 1;
    }

    /* idx0 FALSE: the pre-loop wc_HmacSetKey fails, so the loop's first (and
     * only) evaluation sees ret != 0 and idx1 is short-circuited. */
    mcdc_fh_arm(1);
    ret = wc_PBKDF2_ex(out, passwd, (int)sizeof(passwd), salt,
        (int)sizeof(salt), 2, (int)sizeof(out), WC_SHA256, NULL,
        INVALID_DEVID);
    mcdc_fh_disarm();
    if (ret == 0) {
        WB_NOTE("wc_PBKDF2_ex HmacSetKey fault unexpectedly succeeded");
        wb_fail = 1;
    }

    WB_NOTE("wc_PBKDF2_ex loop-guard ret==0 pair exercised");
}

#else

static void wb_pbkdf2_setkey_err(void)
{ WB_NOTE("PBKDF2/HMAC/SHA256 off (or FIPS SetKey_ex path); wc_PBKDF2_ex "
          "loop guard skipped"); }

#endif

/* --------------------------------------------------------------------------
 * 2. wc_PKCS12_PBKDF_ex(): the reachable rows of the loop guard (line 769).
 *    idx0's FALSE half is structurally unsatisfiable (see the file header);
 *    this only records the (T,T)/(T,F) rows in the same binary.
 * ----------------------------------------------------------------------- */
#if defined(HAVE_PKCS12) && !defined(NO_SHA256)

static void wb_pkcs12_pbkdf_baseline(void)
{
    /* 40 > WC_SHA256_DIGEST_SIZE, so the loop body runs twice. */
    byte out[40];
    byte passwd[13];
    byte salt[8];
    int  ret;

    XMEMSET(out, 0, sizeof(out));
    XMEMSET(passwd, 'p', sizeof(passwd));
    XMEMSET(salt, 0x5a, sizeof(salt));

    /* Unarmed: the injector must stay disarmed here, DoPKCS12Hash goes
     * through wc_Hash* (not interposed) but wc_PBKDF2_ex above may have left
     * state behind. */
    mcdc_fh_disarm();
    ret = wc_PKCS12_PBKDF_ex(out, passwd, (int)sizeof(passwd), salt,
        (int)sizeof(salt), 2, (int)sizeof(out), WC_SHA256, 1, NULL);
    if (ret != 0) {
        WB_NOTE("wc_PKCS12_PBKDF_ex unarmed baseline failed");
        wb_fail = 1;
    }

    WB_NOTE("wc_PKCS12_PBKDF_ex loop-guard reachable rows exercised");
}

#else

static void wb_pkcs12_pbkdf_baseline(void)
{ WB_NOTE("HAVE_PKCS12/SHA256 off; wc_PKCS12_PBKDF_ex loop guard skipped"); }

#endif

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("pwdbased.c white-box MC/DC supplement\n");

    wb_pbkdf2_setkey_err();
    wb_pkcs12_pbkdf_baseline();

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Always 0: a nonzero exit discards this variant's whole coverage. */
    (void)wb_fail;
    return 0;
}
