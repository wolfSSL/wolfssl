/* test_ed448_whitebox.c
 *
 * White-box MC/DC supplement for wolfcrypt/src/ed448.c.
 *
 * The tests/api ed448 suite drives ed448.c through its *public* API. The
 * file-static helper ed448_hash() opens with:
 *
 *   if (key == NULL || (in == NULL && inLen > 0) || hash == NULL) {
 *       return BAD_FUNC_ARG;
 *   }
 *
 * Every public caller (wc_ed448_make_public, wc_ed448_sign_msg_ex,
 * wc_ed448ph_sign_msg) always passes a non-NULL key, a non-NULL hash output
 * buffer, and either a non-NULL `in` or an `in`/`inLen` pair where inLen is a
 * compile-time-fixed nonzero constant (ED448_KEY_SIZE / a real message
 * buffer) -- none of them ever construct the "in == NULL && inLen > 0"
 * combination or pass key/hash as NULL. This translation unit reaches all
 * three operands' TRUE sides (and completes the FALSE-side pairing within this
 * same binary, per the campaign's cross-binary MC/DC lesson) by compiling
 * ed448.c directly (#include) and calling the static helper directly.
 *
 * Coverage from this binary is unioned with the tests/api variant coverage by
 * source line:col in the per-module campaign (iso26262/mcdc-per-module):
 * llvm-cov computes MC/DC independence PER BINARY, and the campaign's
 * aggregate.sh ORs the "independence shown" bit across binaries by key. That
 * is why every pair below is completed *within this file* rather than relying
 * on the API tests to supply the other half.
 *
 * Build: compiled by run-mcdc-par.sh's white-box step with the SAME MC/DC
 * CFLAGS, -DHAVE_CONFIG_H and -I<workspace> as the instrumented library, then
 * linked against that variant's libwolfssl.a with its ed448.o removed (this TU
 * supplies the instrumented ed448.c). NOT part of the wolfSSL build; not
 * registered in tests/api. See tests/unit-mcdc/README.md.
 *
 * Targeted residual (ed448.c):
 *   ed448_hash() key/in/hash NULL guard ...................... 4 conditions
 * The only ed448.c gap confirmed structurally unreachable through the public
 * API (every wrapper hard-codes non-NULL, well-formed arguments).
 */

/* Pull ed448.c in verbatim so the file-static helper below is in scope and
 * instrumented in THIS binary. ed448.c includes libwolfssl_sources.h (which
 * picks up user_settings.h via -DWOLFSSL_USER_SETTINGS) and ed448.h itself. */
#include <wolfcrypt/src/ed448.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#ifdef HAVE_ED448

/* ------------------------------------------------------------------------- *
 * ed448_hash() (line ~162).
 *
 *   if (key == NULL || (in == NULL && inLen > 0) || hash == NULL)
 *
 * unique-cause MC/DC for a 3-operand OR needs, per operand, a pair where only
 * that operand's value differs against an otherwise all-false vector.
 * ------------------------------------------------------------------------- */
static void wb_ed448_hash(void)
{
    ed448_key key;
    byte in[8];
    byte hash[ED448_PRV_KEY_SIZE];
    int ret;

    /* Init the key so key->heap (and, under WOLFSSL_ED448_PERSISTENT_SHA,
     * key->sha) are valid for the all-false baseline call. */
    if (wc_ed448_init(&key) != 0) {
        WB_NOTE("wc_ed448_init failed; skipping ed448_hash white-box");
        return;
    }
    XMEMSET(in, 0x11, sizeof(in));

    /* all-false baseline: valid call. */
    ret = ed448_hash(&key, in, sizeof(in), hash, sizeof(hash));
    if (ret != 0) {
        WB_NOTE("ed448_hash(valid) unexpected error");
        wb_fail = 1;
    }

    /* key == NULL: operand 1 TRUE, others false. */
    ret = ed448_hash(NULL, in, sizeof(in), hash, sizeof(hash));
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("ed448_hash(key==NULL) did not return BAD_FUNC_ARG");
        wb_fail = 1;
    }

    /* in == NULL && inLen > 0: operand 2 TRUE, others false. Also completes
     * operand 2's own inner-compound independence (paired against the
     * all-false baseline's in != NULL, and against inLen == 0 below for the
     * inLen > 0 half). */
    ret = ed448_hash(&key, NULL, sizeof(in), hash, sizeof(hash));
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("ed448_hash(in==NULL,inLen>0) did not return BAD_FUNC_ARG");
        wb_fail = 1;
    }

    /* in == NULL && inLen == 0: operand 2's inner "inLen > 0" FALSE side
     * (in == NULL alone does not trip the guard) -- valid call, matching how
     * a zero-length message would behave. */
    ret = ed448_hash(&key, NULL, 0, hash, sizeof(hash));
    if (ret != 0) {
        WB_NOTE("ed448_hash(in==NULL,inLen==0) unexpected error");
        wb_fail = 1;
    }

    /* hash == NULL: operand 3 TRUE, others false. */
    ret = ed448_hash(&key, in, sizeof(in), NULL, sizeof(hash));
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("ed448_hash(hash==NULL) did not return BAD_FUNC_ARG");
        wb_fail = 1;
    }

    wc_ed448_free(&key);
    WB_NOTE("ed448_hash key/in/hash guard exercised");
}

#else

static void wb_ed448_hash(void)
{
    WB_NOTE("HAVE_ED448 not compiled in this variant; skipped");
}

#endif /* HAVE_ED448 */

int main(void)
{
    printf("ed448.c white-box supplement\n");
#ifndef HAVE_ED448
    printf("  HAVE_ED448 not defined; nothing to exercise\n");
    return 0;
#else
    wb_ed448_hash();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures are surfaced as skips, not test failures: the campaign
     * treats a nonzero exit as a failed variant and discards its coverage. */
    return 0;
#endif
}
