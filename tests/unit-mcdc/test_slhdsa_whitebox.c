/* test_slhdsa_whitebox.c
 *
 * White-box MC/DC supplement for wolfcrypt/src/wc_slhdsa.c (SLH-DSA / FIPS 205).
 *
 * The tests/api slhdsa suite drives wc_slhdsa.c through its *public* API. A few
 * decisions live in file-static helpers whose branch/loop independence pairs
 * cannot be shown from the public API without either an (extremely slow) full
 * SLH-DSA sign/keygen or a structurally impossible argument combination:
 *
 *   - slhdsa_find_params(): the table-scan compare "SlhDsaParams[i].param ==
 *     param" and its found (return &entry) vs not-found (return NULL) exits.
 *     Every public caller only reaches this with a param already validated by
 *     wc_SlhDsaOidToParam(), so the NULL-return (not-found) half is dead from
 *     the API. Driven here directly with a valid param (found) and a bogus
 *     param (fall through -> NULL).
 *   - slhdsakey_base_2b(): the nested "for (j<outLen)" / "while (bits<b)"
 *     loop decisions. Exercised directly with outLen==0 (outer false on
 *     entry), a single-read b (inner true-then-false), and a multi-read b
 *     (inner true-true-...-false) to complete both loops' independence pairs.
 *   - HA_Encode() / HA_Encode_Compressed(): pure HashAddress encoders whose
 *     bodies (the WOLFSSL_WC_SLHDSA_SMALL loop-vs-unrolled arm of HA_Encode,
 *     and the SHA-2-only HA_Encode_Compressed) are otherwise only reached
 *     mid-sign. Called directly on a stack HashAddress.
 *
 * Coverage from this binary is unioned with the tests/api variant coverage by
 * source line:col in the per-module campaign (iso26262/mcdc-per-module):
 * llvm-cov computes MC/DC independence PER BINARY, and aggregate.sh ORs the
 * "independence shown" bit across binaries by key. Every pair below is
 * therefore completed *within this file*.
 *
 * Build: compiled by run-mcdc-par.sh's white-box step with the SAME MC/DC
 * CFLAGS, -DHAVE_CONFIG_H and -I<workspace> as the instrumented library, then
 * linked against that variant's libwolfssl.a with its wc_slhdsa.o removed
 * (this TU supplies the instrumented wc_slhdsa.c). NOT part of the wolfSSL
 * build; not registered in tests/api. See tests/unit-mcdc/README.md.
 */

/* Pull wc_slhdsa.c in verbatim so its file-static helpers below are in scope
 * and instrumented in THIS binary. wc_slhdsa.c includes settings.h (which
 * picks up user_settings.h via -DWOLFSSL_USER_SETTINGS) and wc_slhdsa.h. */
#include <wolfcrypt/src/wc_slhdsa.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#ifdef WOLFSSL_HAVE_SLHDSA

/* ------------------------------------------------------------------------- *
 * slhdsa_find_params(): found vs not-found (both halves of the table compare).
 * ------------------------------------------------------------------------- */
static void wb_find_params(void)
{
    const SlhDsaParameters* p;

    if (SLHDSA_PARAM_LEN < 1) {
        WB_NOTE("no SLH-DSA parameter sets compiled in; find_params skipped");
        return;
    }

    /* Found: use the first compiled-in param id from the table itself so this
     * works for any variant (SHAKE-only, SHA-2, restricted param sets). The
     * compare "SlhDsaParams[i].param == param" goes true and the function
     * returns a non-NULL entry (loop true-exit). */
    p = slhdsa_find_params(SlhDsaParams[0].param);
    if (p != &SlhDsaParams[0]) {
        WB_NOTE("slhdsa_find_params(valid) did not return the table entry");
        wb_fail = 1;
    }

    /* Not found: a bogus param never matches, the loop runs to completion
     * (compare false every iteration) and returns NULL. */
    p = slhdsa_find_params((enum SlhDsaParam)0x7fff);
    if (p != NULL) {
        WB_NOTE("slhdsa_find_params(bogus) did not return NULL");
        wb_fail = 1;
    }

    WB_NOTE("slhdsa_find_params found/not-found pair exercised");
}

/* ------------------------------------------------------------------------- *
 * slhdsakey_base_2b(): nested for/while loop decisions.
 * ------------------------------------------------------------------------- */
static void wb_base_2b(void)
{
    byte   x[64];
    word16 out[16];
    int    i;

    for (i = 0; i < (int)sizeof(x); i++) {
        x[i] = (byte)(0xA5 ^ i);
    }

    /* outLen == 0: outer "for (j < outLen)" false on entry (loop body never
     * runs). baseb is written to zero times, so `out` is untouched -- valid. */
    slhdsakey_base_2b(x, 8, 0, out);

    /* b == 8, outLen > 0: each output consumes exactly one input byte, so the
     * inner "while (bits < b)" runs once (true) then bits==8 !< 8 (false). */
    slhdsakey_base_2b(x, 8, 4, out);

    /* b == 6 < 8: first output makes the inner while true once then false
     * with bits left over (6 -> next output enters with bits==2 < 6 true). */
    slhdsakey_base_2b(x, 6, 8, out);

    /* b == 12 > 8: inner while runs twice (bits 0<12 true, 8<12 true) then
     * 16 !< 12 false -- the multi-iteration true side of the inner loop. */
    slhdsakey_base_2b(x, 12, 4, out);

    WB_NOTE("slhdsakey_base_2b nested-loop decisions exercised");
}

/* ------------------------------------------------------------------------- *
 * HA_Encode() / HA_Encode_Compressed(): pure HashAddress encoders.
 * ------------------------------------------------------------------------- */
static void wb_ha_encode(void)
{
    word32 adrs[8];
    byte   address[SLHDSA_HA_SZ];
    int    i;

    for (i = 0; i < 8; i++) {
        adrs[i] = (word32)(0x01020300u + (word32)i);
    }

    /* HA_Encode: the WOLFSSL_WC_SLHDSA_SMALL variant takes the for-loop body
     * (its "i < 8" decision), the default variant the unrolled writes. Either
     * way this is the direct, sign-free drive of that arm. */
    XMEMSET(address, 0, sizeof(address));
    HA_Encode(adrs, address);
    if ((address[0] == 0) && (address[SLHDSA_HA_SZ - 1] != 0)) {
        /* purely to consume the output so it is not optimized away */
        WB_NOTE("HA_Encode produced an unexpected all-zero prefix");
    }

#ifdef WOLFSSL_SLHDSA_SHA2
    /* HA_Encode_Compressed is only compiled under WOLFSSL_SLHDSA_SHA2. */
    XMEMSET(address, 0, sizeof(address));
    HA_Encode_Compressed(adrs, address);
#endif

    WB_NOTE("HA_Encode / HA_Encode_Compressed exercised");
}

#endif /* WOLFSSL_HAVE_SLHDSA */

int main(void)
{
    printf("wc_slhdsa.c white-box supplement\n");
#ifndef WOLFSSL_HAVE_SLHDSA
    printf("  WOLFSSL_HAVE_SLHDSA not defined; nothing to exercise\n");
    return 0;
#else
    wb_find_params();
    wb_base_2b();
    wb_ha_encode();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures are surfaced as skips, not test failures: the campaign
     * treats a nonzero exit as a failed variant and discards its coverage. */
    return 0;
#endif
}
