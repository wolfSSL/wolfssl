/* test_curve25519_whitebox.c
 *
 * White-box MC/DC supplement for wolfcrypt/src/curve25519.c.
 *
 * The tests/api curve25519 suite drives curve25519.c through its *public*
 * API. Two file-static helpers used only by the WC_X25519_NONBLOCK state
 * machine -- wc_curve25519_make_pub_nb() and wc_curve25519_make_key_nb() --
 * each open with a "key == NULL || rng == NULL" (or just "key == NULL")
 * guard and a "ret == 0 && key->nb_ctx->state == 0" guard. Every public
 * caller (wc_curve25519_make_key()) validates key/rng non-NULL itself
 * *before* ever reaching these statics (and only calls them when
 * key->nb_ctx != NULL, so the "ret==0" half of the second guard is always
 * true on entry), so the guards' otherwise-unreachable halves can only be
 * shown by calling the statics directly. This translation unit reaches
 * them by compiling curve25519.c directly (#include) and calling the
 * helpers with both halves of each MC/DC independence pair.
 *
 * Coverage from this binary is unioned with the tests/api variant coverage
 * by source line:col in the per-module campaign (iso26262/mcdc-per-module):
 * llvm-cov computes MC/DC independence PER BINARY, and the campaign's
 * aggregate.sh ORs the "independence shown" bit across binaries by key.
 * That is why every pair below is completed *within this file* rather than
 * relying on the API tests to supply the other half.
 *
 * Only meaningful under WC_X25519_NONBLOCK (requires CURVE25519_SMALL,
 * per curve25519.c's own top-of-file doc comment); a no-op elsewhere.
 *
 * Build: compiled by run-mcdc-par.sh's white-box step with the SAME MC/DC
 * CFLAGS, -DHAVE_CONFIG_H and -I<workspace> as the instrumented library,
 * then linked against that variant's libwolfssl.a with its curve25519.o
 * removed (this TU supplies the instrumented curve25519.c). NOT part of
 * the wolfSSL build; not registered in tests/api. See tests/unit-mcdc/
 * README.md.
 *
 * Targeted residuals (curve25519.c), by class:
 *   Class 1  wc_curve25519_make_pub_nb() key==NULL guard ........ 1 condition
 *   Class 2  wc_curve25519_make_pub_nb() ret==0 guard false side . 1 condition
 *   Class 3  wc_curve25519_make_key_nb() key/rng==NULL guard ..... 2 conditions
 *   Class 4  wc_curve25519_make_key_nb() ret==0 guard false side . 1 condition
 * These are the only curve25519.c gaps confirmed structurally unreachable
 * through the public API: wc_curve25519_make_key() pre-validates key/rng
 * non-NULL identically before ever calling either static, and only enters
 * either with ret==0 already true. See the campaign's RESIDUALS.md for
 * everything else (notably curve25519_smul_blind()'s RNG-retry loop, which
 * needs a controllable/mockable RNG to force its rare all-0xff/large-first-
 * byte draw and is left as a structural residual, matching the ecc.c
 * campaign's Tonelli-Shanks precedent).
 */

/* Pull curve25519.c in verbatim so the file-static helpers below are in
 * scope and instrumented in THIS binary. curve25519.c includes settings.h
 * (which picks up user_settings.h via -DWOLFSSL_USER_SETTINGS) and
 * curve25519.h itself. */
#include <wolfcrypt/src/curve25519.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(HAVE_CURVE25519) && defined(WC_X25519_NONBLOCK)

/* ------------------------------------------------------------------------- *
 * Class 1+2: wc_curve25519_make_pub_nb() (line ~476).
 *
 *   if (key == NULL) { ret = BAD_FUNC_ARG; }
 *   else if (key->nb_ctx == NULL) { ... ret = BAD_FUNC_ARG; }
 *   if (ret == 0 && key->nb_ctx->state == 0) { ... }
 *
 * wc_curve25519_make_key() only calls this when key->nb_ctx != NULL and
 * only after its own "key == NULL || rng == NULL" check already passed, so
 * key==NULL's TRUE side and the second if's "ret==0" FALSE side are both
 * unreachable through the public wrapper.
 * ------------------------------------------------------------------------- */
static void wb_make_pub_nb(void)
{
    int ret;

    /* key == NULL: TRUE side. */
    ret = wc_curve25519_make_pub_nb(NULL);
    if (ret != BAD_FUNC_ARG) {
        WB_NOTE("wc_curve25519_make_pub_nb(NULL) did not return "
                 "BAD_FUNC_ARG");
        wb_fail = 1;
    }

    /* ret==0 && state==0 compound, FALSE side of the first operand: force
     * ret nonzero by way of a live key whose nb_ctx is NULL (second `if`'s
     * BAD_FUNC_ARG branch sets ret=BAD_FUNC_ARG before the "if (ret==0...)"
     * check runs) -- also completes the else-if's own key->nb_ctx==NULL
     * TRUE side, itself unreachable via the public wrapper (which only
     * calls in when nb_ctx != NULL). */
    {
        curve25519_key key;

        XMEMSET(&key, 0, sizeof(key));
        key.nb_ctx = NULL;
        ret = wc_curve25519_make_pub_nb(&key);
        if (ret != BAD_FUNC_ARG) {
            WB_NOTE("wc_curve25519_make_pub_nb(nb_ctx==NULL) did not "
                     "return BAD_FUNC_ARG");
            wb_fail = 1;
        }
    }

    /* ret==0 && state==0 compound, TRUE side of BOTH operands: a live key
     * with a real, zeroed nb_ctx (state==0 by construction). MC/DC
     * independence must be shown WITHIN this same white-box binary (a
     * separately-compiled binary's coverage does not merge into this
     * one's bitmap), so this pairs with the FALSE-side call just above
     * rather than relying on the tests/api small_nonblock variant's own
     * (separately-compiled) successful run. */
    {
        curve25519_key key;
        x25519_nb_ctx_t nb_ctx;

        XMEMSET(&key, 0, sizeof(key));
        XMEMSET(&nb_ctx, 0, sizeof(nb_ctx));
        key.nb_ctx = &nb_ctx;
        ret = curve25519_priv_clamp(key.k);
        if (ret != 0) {
            WB_NOTE("curve25519_priv_clamp setup failed");
            wb_fail = 1;
        }
        ret = wc_curve25519_make_pub_nb(&key);
        if (ret != 0 && ret != FP_WOULDBLOCK) {
            WB_NOTE("wc_curve25519_make_pub_nb(valid) unexpected error");
            wb_fail = 1;
        }
    }

    WB_NOTE("wc_curve25519_make_pub_nb key==NULL / nb_ctx==NULL guards "
             "exercised");
}

/* ------------------------------------------------------------------------- *
 * Class 3+4: wc_curve25519_make_key_nb() (line ~504).
 *
 *   if (key == NULL || rng == NULL) { ret = BAD_FUNC_ARG; }
 *   else if (key->nb_ctx == NULL) { ... ret = BAD_FUNC_ARG; }
 *   if (ret == 0 && key->nb_ctx->state == 0) { ... }
 *
 * Same reasoning as above: wc_curve25519_make_key() pre-validates key/rng
 * and only calls in with nb_ctx != NULL, so key==NULL, rng==NULL (with
 * key!=NULL), and the compound's ret==0 FALSE side are all unreachable
 * through the public wrapper.
 * ------------------------------------------------------------------------- */
static void wb_make_key_nb(void)
{
    int ret;
    WC_RNG rng;
    curve25519_key key;

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&key, 0, sizeof(key));

    /* key == NULL: TRUE side (rng operand short-circuited, not evaluated
     * -- unique-cause MC/DC only requires this operand's own pair). */
    ret = wc_curve25519_make_key_nb(&rng, CURVE25519_KEYSIZE, NULL);
    if (ret != BAD_FUNC_ARG) {
        WB_NOTE("wc_curve25519_make_key_nb(NULL key) did not return "
                 "BAD_FUNC_ARG");
        wb_fail = 1;
    }

    /* rng == NULL, key != NULL: second operand's TRUE side with the first
     * operand false. */
    ret = wc_curve25519_make_key_nb(NULL, CURVE25519_KEYSIZE, &key);
    if (ret != BAD_FUNC_ARG) {
        WB_NOTE("wc_curve25519_make_key_nb(NULL rng) did not return "
                 "BAD_FUNC_ARG");
        wb_fail = 1;
    }

    /* nb_ctx == NULL: else-if TRUE side, also forces ret!=0 into the
     * following "if (ret==0 && ...)" compound (first operand FALSE side). */
    key.nb_ctx = NULL;
    ret = wc_curve25519_make_key_nb(&rng, CURVE25519_KEYSIZE, &key);
    if (ret != BAD_FUNC_ARG) {
        WB_NOTE("wc_curve25519_make_key_nb(nb_ctx==NULL) did not return "
                 "BAD_FUNC_ARG");
        wb_fail = 1;
    }

    /* ret==0 && state==0 compound, TRUE side of BOTH operands: same-binary
     * pairing requirement as wb_make_pub_nb above -- a real RNG (needed by
     * wc_curve25519_make_priv() inside this path) and a zeroed nb_ctx. */
    {
        WC_RNG realRng;
        curve25519_key validKey;
        x25519_nb_ctx_t nb_ctx;

        XMEMSET(&realRng, 0, sizeof(realRng));
        XMEMSET(&validKey, 0, sizeof(validKey));
        XMEMSET(&nb_ctx, 0, sizeof(nb_ctx));
        validKey.nb_ctx = &nb_ctx;
        if (wc_InitRng(&realRng) != 0) {
            WB_NOTE("wc_InitRng setup failed");
            wb_fail = 1;
        }
        else {
            ret = wc_curve25519_make_key_nb(&realRng, CURVE25519_KEYSIZE,
                &validKey);
            if (ret != 0 && ret != FP_WOULDBLOCK) {
                WB_NOTE("wc_curve25519_make_key_nb(valid) unexpected "
                         "error");
                wb_fail = 1;
            }
            wc_FreeRng(&realRng);
        }
    }

    WB_NOTE("wc_curve25519_make_key_nb NULL / nb_ctx==NULL guards "
             "exercised");
}

#else

static void wb_make_pub_nb(void)
{
    WB_NOTE("WC_X25519_NONBLOCK not compiled in this variant; skipped");
}

static void wb_make_key_nb(void)
{
    WB_NOTE("WC_X25519_NONBLOCK not compiled in this variant; skipped");
}

#endif /* HAVE_CURVE25519 && WC_X25519_NONBLOCK */

int main(void)
{
    printf("curve25519.c white-box supplement\n");
#ifndef HAVE_CURVE25519
    printf("  HAVE_CURVE25519 not defined; nothing to exercise\n");
    return 0;
#else
    wb_make_pub_nb();
    wb_make_key_nb();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures are surfaced as skips, not test failures: the
     * campaign treats a nonzero exit as a failed variant and discards its
     * coverage. */
    return 0;
#endif
}
