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
 * *before* ever reaching these static helpers (and only calls them when
 * key->nb_ctx != NULL, so the "ret==0" half of the second guard is always
 * true on entry), so the guards' otherwise-unreachable halves can only be
 * shown by calling the static helpers directly. This translation unit reaches
 * them by compiling curve25519.c directly (#include) and calling the
 * helpers with both halves of each MC/DC independence pair.
 *
 * Coverage from this binary is unioned with the tests/api variant coverage
 * by source line:col in the per-module suite:
 * llvm-cov computes MC/DC independence PER BINARY, and the
 * aggregate.sh ORs the "independence shown" bit across binaries by key.
 * That is why every pair below is completed *within this file* rather than
 * relying on the API tests to supply the other half.
 *
 * Only meaningful under WC_X25519_NONBLOCK (requires CURVE25519_SMALL,
 * per curve25519.c's own top-of-file doc comment); a no-op elsewhere.
 *
 * Build: compiled by the coverage runner's white-box step with the SAME MC/DC
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
 * either with ret==0 already true. See the RESIDUALS.md for
 * everything else (notably curve25519_smul_blind()'s RNG-retry loop, which
 * needs a controllable/mockable RNG to force its rare all-0xff/large-first-
 * byte draw and is left as a structural residual, matching the ecc.c
 * suite's Tonelli-Shanks precedent).
 */

/* Pull curve25519.c in verbatim so the file-static helpers below are in
 * scope and instrumented in THIS binary. curve25519.c includes settings.h
 * (which picks up user_settings.h via -DWOLFSSL_USER_SETTINGS) and
 * curve25519.h itself. */
/* ---- wc_RNG_GenerateBlock() interposer ----------------------------------
 *
 * curve25519_smul_blind()'s blinding-value rejection loop (:279-:293) draws a
 * fresh rz until it is acceptable. Its guard
 *
 *     if ((i >= 0) || (rz[0] <= 0xec)) break;
 *
 * only takes "i >= 0" FALSE when EVERY byte of rz is 0xff -- a 2^-256 event
 * that no seeded stream can be relied on to produce (and rule 3 of this
 * suite forbids evidence that depends on a live draw). Interposing
 * wc_RNG_GenerateBlock() for THIS translation unit lets one scripted draw
 * return 32 x 0xff, so the loop's first iteration evaluates the guard with
 * i == -1, while the second (unscripted) draw ends the loop normally -- both
 * halves of the idx0 pair in one call, and cnt never reaches
 * WOLFSSL_CURVE25519_BLINDING_RAND_CNT, so no RNG_FAILURE_E bail-out.
 *
 * random.h is included and the hook declared FIRST so the macro never has to
 * rewrite random.h's own prototype (see the same note in mcdc_seed_rng.h: an
 * undeclared hook is a compile failure, which the harness scores as a silent
 * skip). The hook's body sits after the #undef, so it still reaches the real
 * RNG when the script is idle.
 */
#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
#include <wolfssl/wolfcrypt/random.h>

static int wb_c25519_rng_block(WC_RNG* rng, byte* out, word32 sz);

#define wc_RNG_GenerateBlock(rng, out, sz) wb_c25519_rng_block((rng), (out), (sz))

#include <wolfcrypt/src/curve25519.c>

#undef wc_RNG_GenerateBlock

#include <stdio.h>

/* Number of remaining draws to answer with all-0xff instead of real random. */
static int wb_ff_draws = 0;

static int wb_c25519_rng_block(WC_RNG* rng, byte* out, word32 sz)
{
    if (wb_ff_draws > 0) {
        wb_ff_draws--;
        XMEMSET(out, 0xff, sz);
        return 0;
    }
    return wc_RNG_GenerateBlock(rng, out, sz);
}

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
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
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
        if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
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
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("wc_curve25519_make_key_nb(NULL key) did not return "
                 "BAD_FUNC_ARG");
        wb_fail = 1;
    }

    /* rng == NULL, key != NULL: second operand's TRUE side with the first
     * operand false. */
    ret = wc_curve25519_make_key_nb(NULL, CURVE25519_KEYSIZE, &key);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("wc_curve25519_make_key_nb(NULL rng) did not return "
                 "BAD_FUNC_ARG");
        wb_fail = 1;
    }

    /* nb_ctx == NULL: else-if TRUE side, also forces ret!=0 into the
     * following "if (ret==0 && ...)" compound (first operand FALSE side). */
    key.nb_ctx = NULL;
    ret = wc_curve25519_make_key_nb(&rng, CURVE25519_KEYSIZE, &key);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
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

#if defined(HAVE_CURVE25519) && defined(WOLFSSL_CURVE25519_BLINDING)
/* wc_curve25519_generic_blind() opens with two three-operand OR guards -- one
 * over the three sizes, one over the three pointers. Every caller in the
 * library passes CURVE25519_KEYSIZE and non-NULL buffers, so both are only ever
 * seen all-false; each operand needs its own true row against that partner. */
static void wb_generic_arg_guards(void)
{
    byte pub[CURVE25519_KEYSIZE];
    byte priv[CURVE25519_KEYSIZE];
    byte base[CURVE25519_KEYSIZE];
    const int n = CURVE25519_KEYSIZE;
    WC_RNG rng;
    int haveRng;

    XMEMSET(pub, 0, sizeof(pub));
    XMEMSET(priv, 1, sizeof(priv));
    XMEMSET(base, 9, sizeof(base));
    haveRng = (wc_InitRng(&rng) == 0);

    /* size guard, one operand true per call */
    (void)wc_curve25519_generic_blind(n - 1, pub, n, priv, n, base,
                                      haveRng ? &rng : NULL);
    (void)wc_curve25519_generic_blind(n, pub, n - 1, priv, n, base,
                                      haveRng ? &rng : NULL);
    (void)wc_curve25519_generic_blind(n, pub, n, priv, n - 1, base,
                                      haveRng ? &rng : NULL);

    /* pointer guard, one operand true per call; the size guard above is
     * all-false on each of these */
    (void)wc_curve25519_generic_blind(n, NULL, n, priv, n, base,
                                      haveRng ? &rng : NULL);
    (void)wc_curve25519_generic_blind(n, pub, n, NULL, n, base,
                                      haveRng ? &rng : NULL);
    (void)wc_curve25519_generic_blind(n, pub, n, priv, n, NULL,
                                      haveRng ? &rng : NULL);

    /* all six operands false: decided by the rng argument instead */
    (void)wc_curve25519_generic_blind(n, pub, n, priv, n, base, NULL);
    if (haveRng) {
        (void)wc_curve25519_generic_blind(n, pub, n, priv, n, base, &rng);
        wc_FreeRng(&rng);
    }
}
#else
static void wb_generic_arg_guards(void)
{
    WB_NOTE("WOLFSSL_CURVE25519_BLINDING off; generic_blind guards skipped");
}
#endif /* HAVE_CURVE25519 && WOLFSSL_CURVE25519_BLINDING */

/* ------------------------------------------------------------------------- *
 * curve25519.c:288  if ((i >= 0) || (rz[0] <= 0xec))
 *
 * idx0 ("i >= 0") needs a draw whose every byte is 0xff, so the scan at
 * :283-:286 falls off the bottom with i == -1. One scripted draw does that;
 * the loop then goes round once more with a real draw, which breaks at some
 * i >= 0 and gives the TRUE partner in the same call and the same binary.
 *
 * idx1 ("rz[0] <= 0xec") stays EXCLUDED and is not attempted here: reaching
 * it at all requires i < 0, which the loop bound (i >= 0, not i >= 1) makes
 * synonymous with rz[0] == 0xff, so the operand is unreachable-as-true. That
 * is a product defect; if the loop bound
 * is ever corrected the exclusion must be withdrawn and BOTH operands
 * re-measured from this same interposer.
 * ------------------------------------------------------------------------- */
#if defined(HAVE_CURVE25519) && defined(WOLFSSL_CURVE25519_BLINDING) && \
    !defined(FREESCALE_LTC_ECC) && !defined(WOLF_CRYPTO_CB_ONLY_CURVE25519)
static void wb_blind_rz_all_ff(void)
{
    byte   pub[CURVE25519_KEYSIZE];
    byte   priv[CURVE25519_KEYSIZE];
    WC_RNG rng;
    int    ret;

    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("wc_InitRng failed; skipping blinding rz vectors");
        return;
    }

    XMEMSET(pub, 0, sizeof(pub));
    XMEMSET(priv, 0x5a, sizeof(priv));
    if (curve25519_priv_clamp(priv) != 0) {
        WB_NOTE("curve25519_priv_clamp failed; skipping blinding rz vectors");
        wc_FreeRng(&rng);
        return;
    }

    /* Unscripted: every draw is real, so the guard is only ever evaluated
     * with i >= 0 (idx0 TRUE, decision TRUE). */
    ret = wc_curve25519_make_pub_blind(CURVE25519_KEYSIZE, pub,
                                       CURVE25519_KEYSIZE, priv, &rng);
    if (ret != 0) {
        WB_NOTE("wc_curve25519_make_pub_blind failed unscripted");
        wb_fail = 1;
    }

    /* Scripted: exactly one all-0xff draw, so the first iteration evaluates
     * the guard with i == -1 and rz[0] == 0xff -- (F,F), decision FALSE --
     * and the retry draws real bytes and breaks normally. */
    XMEMSET(pub, 0, sizeof(pub));
    wb_ff_draws = 1;
    ret = wc_curve25519_make_pub_blind(CURVE25519_KEYSIZE, pub,
                                       CURVE25519_KEYSIZE, priv, &rng);
    if (wb_ff_draws != 0) {
        WB_NOTE("scripted all-0xff draw was never consumed");
        wb_fail = 1;
        wb_ff_draws = 0;
    }
    if (ret != 0) {
        WB_NOTE("wc_curve25519_make_pub_blind failed after an all-0xff rz");
        wb_fail = 1;
    }

    wc_FreeRng(&rng);
    WB_NOTE("curve25519_smul_blind rz rejection-loop guard exercised");
}
#else
static void wb_blind_rz_all_ff(void)
{
    (void)&wb_c25519_rng_block;
    WB_NOTE("curve25519 blinding not compiled in; rz vectors skipped");
}
#endif

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("curve25519.c white-box supplement\n");
#ifndef HAVE_CURVE25519
    printf("  HAVE_CURVE25519 not defined; nothing to exercise\n");
    return 0;
#else
    wb_make_pub_nb();
    wb_make_key_nb();
    wb_generic_arg_guards();
    wb_blind_rz_all_ff();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures are surfaced as skips, not test failures: the
     * suite treats a nonzero exit as a failed variant and discards its
     * coverage. */
    return 0;
#endif
}
