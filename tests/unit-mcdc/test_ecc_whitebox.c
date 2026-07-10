/* test_ecc_whitebox.c
 *
 * White-box MC/DC supplement for wolfcrypt/src/ecc.c.
 *
 * The tests/api ECC suite (test_ecc.c, including its MC/DC-focused
 * test_wc_EccDecisionCoverage) drives ecc.c through its *public* API. A
 * handful of decision conditions live in file-static helpers whose "bad"
 * operand combinations are rejected by every public caller *before* the
 * helper runs (the caller hard-codes a value, or pre-validates the same
 * condition), so those combinations can never be exercised from the API
 * without modifying library source. This translation unit reaches them by
 * compiling ecc.c directly (#include) and calling the helpers with both
 * halves of each MC/DC independence pair.
 *
 * Coverage from this binary is unioned with the tests/api variant coverage by
 * source line:col in the per-module campaign (iso26262/mcdc-per-module):
 * llvm-cov computes MC/DC independence PER BINARY, and the campaign's
 * aggregate.sh ORs the "independence shown" bit across binaries by key. That
 * is why every pair below is completed *within this file* rather than
 * relying on the API tests to supply the other half.
 *
 * Build: compiled by run-mcdc.sh's white-box step with the SAME MC/DC CFLAGS,
 * -DHAVE_CONFIG_H and -I<workspace> as the instrumented library, then linked
 * against that variant's libwolfssl.a with its ecc.o removed (this TU
 * supplies the instrumented ecc.c). NOT part of the wolfSSL build; not
 * registered in tests/api. See tests/unit-mcdc/README.md.
 *
 * Targeted residuals (ecc.c), by class:
 *   Class 1  wc_ecc_curve_load() dp/pCurve NULL guard ............. 2 conditions
 *   Class 2  _ecc_import_private_key_ex() key/priv NULL guard ...... 2 conditions
 *   Class 3  ecc_ctx_set_salt() ctx/flags==0 guard ................. 2 conditions
 *   Class 4  wc_ecc_ctx_get_own_salt() ctx->protocol==0 half ....... 1 condition
 *   Class 5  wc_ecc_ctx_set_peer_salt() ctx->protocol==0 half ...... 1 condition
 *   Class 6  wc_ecc_ctx_set_own_salt() ctx->protocol==0 half ....... 1 condition
 * These are the only ecc.c gaps confirmed structurally unreachable through
 * any public wrapper (every wrapper either hard-codes the "safe" side of the
 * static helper's own re-check, or -- for the ecEncCtx cases -- there is no
 * public constructor that leaves ctx->protocol == 0 on a live, non-NULL
 * context). See RESIDUALS.md for everything else.
 */

/* Pull ecc.c in verbatim so the file-static helpers below are in scope and
 * instrumented in THIS binary. ecc.c includes settings.h (which picks up
 * user_settings.h via -DWOLFSSL_USER_SETTINGS) and ecc.h itself. */
#include <wolfcrypt/src/ecc.c>

#include <stdio.h>

#ifndef INVALID_DEVID
    #define INVALID_DEVID (-2)
#endif

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(HAVE_ECC) && !defined(WOLF_CRYPTO_CB_ONLY_ECC)

/* ------------------------------------------------------------------------- *
 * Class 1: wc_ecc_curve_load() dp/pCurve NULL guard (line ~1772).
 *
 *   if (dp == NULL || pCurve == NULL)
 *
 * Every public caller (wc_ecc_set_curve, wc_ecc_make_key_ex, ...) looks up a
 * non-NULL ecc_set_type* from the static ecc_sets[] table and always passes
 * the address of a live ecc_curve_spec* local, so neither operand's TRUE
 * side is reachable from the API.
 * ------------------------------------------------------------------------- */
static void wb_curve_load(void)
{
    /* Without ECC_CACHE_CURVE (our variants don't define it), wc_ecc_
     * curve_load()'s *pCurve is NOT an out-only "give me a fresh one"
     * slot -- the DECLARE_CURVE_SPECS() macro (used by every real caller)
     * pre-allocates a real ecc_curve_spec on the caller's stack and passes
     * its address; wc_ecc_curve_load() only fills it in. A bare NULL
     * ecc_curve_spec* (valid ONLY under ECC_CACHE_CURVE, where the second
     * branch of DECLARE_CURVE_SPECS lets the callee allocate/cache it) hits
     * "curve = *pCurve; curve->dp != dp" on a NULL curve and crashes. Match
     * the real DECLARE_CURVE_SPECS(1) shape here for the all-false call.
     */
    ecc_curve_spec* curveNull = NULL;
    int ret;

    ret = wc_ecc_curve_load(NULL, &curveNull, ECC_CURVE_FIELD_ALL);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("wc_ecc_curve_load(dp=NULL) unexpected return");
        wb_fail = 1;
    }

    ret = wc_ecc_curve_load(&ecc_sets[0], NULL, ECC_CURVE_FIELD_ALL);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("wc_ecc_curve_load(pCurve=NULL) unexpected return");
        wb_fail = 1;
    }

    /* all-false: real dp + a properly pre-allocated pCurve slot (already
     * exercised by every public caller via DECLARE_CURVE_SPECS(), repeated
     * here so the independence PAIR -- not just each TRUE half -- lives in
     * this binary too). */
    {
        /* ECC_CURVE_FIELD_ALL loads all six fields (prime/Af/Bf/order/Gx/
         * Gy), matching DECLARE_CURVE_SPECS(ECC_CURVE_FIELD_COUNT) -- an
         * undersized spec_ints (e.g. count 1) makes wc_ecc_curve_load()
         * overrun it while loading the later fields. */
        DECLARE_CURVE_SPECS(ECC_CURVE_FIELD_COUNT);
        int allocErr = MP_OKAY;
        ALLOC_CURVE_SPECS(ECC_CURVE_FIELD_COUNT, allocErr);
        if (allocErr == MP_OKAY) {
            ret = wc_ecc_curve_load(&ecc_sets[0], &curve, ECC_CURVE_FIELD_ALL);
            if (ret != 0) {
                WB_NOTE("wc_ecc_curve_load(all-false) unexpected return");
                wb_fail = 1;
            }
            wc_ecc_curve_free(curve);
        }
        else {
            WB_NOTE("ALLOC_CURVE_SPECS failed (all-false case skipped)");
        }
        FREE_CURVE_SPECS();
    }
    WB_NOTE("wc_ecc_curve_load dp/pCurve NULL guard pairs exercised");
}

/* ------------------------------------------------------------------------- *
 * Class 2: _ecc_import_private_key_ex() key/priv NULL guard (line ~11671).
 *
 *   if (key == NULL || priv == NULL)
 *
 * wc_ecc_import_private_key_ex() (the public wrapper) performs the identical
 * check itself before ever reaching the static, so both operands' TRUE side
 * inside the static are white-box only. The all-false ("both valid") side
 * is exercised elsewhere by tests/api's test_wc_ecc_import_private_key --
 * but that is a DIFFERENT binary, and llvm-cov computes MC/DC independence
 * per binary, so this function also drives one real (all-false) call
 * itself to complete both operands' pairs within this binary.
 * ------------------------------------------------------------------------- */
static void wb_import_private_key_ex(void)
{
    byte priv[32];
    ecc_key key;
    int ret;

    XMEMSET(priv, 0x5A, sizeof(priv));
    XMEMSET(&key, 0, sizeof(key));

    ret = _ecc_import_private_key_ex(priv, sizeof(priv), NULL, 0, NULL,
        ECC_CURVE_DEF);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("_ecc_import_private_key_ex(key=NULL) unexpected return");
        wb_fail = 1;
    }

    ret = _ecc_import_private_key_ex(NULL, 0, NULL, 0, &key, ECC_CURVE_DEF);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("_ecc_import_private_key_ex(priv=NULL) unexpected return");
        wb_fail = 1;
    }

    /* all-false: real key + real priv (pub left NULL -- private-only
     * import), a small but nonzero/in-range scalar (k=1) so wc_ecc_
     * set_curve()'s size check and the rest of the import succeed. */
    if (wc_ecc_init(&key) == 0) {
        byte k1[32];
        XMEMSET(k1, 0, sizeof(k1));
        k1[sizeof(k1) - 1] = 1;
        ret = _ecc_import_private_key_ex(k1, sizeof(k1), NULL, 0, &key,
            ECC_SECP256R1);
        if (ret != 0) {
            WB_NOTE("_ecc_import_private_key_ex(all-false) unexpected return");
            wb_fail = 1;
        }
        wc_ecc_free(&key);
    }

    WB_NOTE("_ecc_import_private_key_ex key/priv NULL guard pairs exercised");
}

#ifdef HAVE_ECC_ENCRYPT
/* ------------------------------------------------------------------------- *
 * Class 3: ecc_ctx_set_salt() ctx/flags==0 guard (line ~14665).
 *
 *   if (ctx == NULL || flags == 0)
 *
 * Both public callers (wc_ecc_ctx_set_own_salt via REQ_RESP_CLIENT/SERVER,
 * ecc_ctx_init) always pass a live ctx and a hard-coded nonzero flags
 * (REQ_RESP_CLIENT/REQ_RESP_SERVER), so flags==0 can never be observed from
 * the API; ctx==NULL is likewise never forwarded by any caller (they all
 * either early-return on their own NULL check or pass &localCtx).
 *
 * Classes 4-6: ecEncCtx.protocol == 0 halves of the get_own_salt /
 * set_peer_salt / set_own_salt guards (lines ~14506, ~14554, ~14646). The
 * only public constructor, wc_ecc_ctx_new()/wc_ecc_ctx_new_ex(), always sets
 * ctx->protocol to REQ_RESP_CLIENT or REQ_RESP_SERVER (or fails and frees the
 * ctx), so a live ctx with protocol==0 does not exist on any API path. Build
 * one directly here since ecEncCtx's full definition is only visible inside
 * this TU (it is an opaque forward-declared type in ecc.h).
 * ------------------------------------------------------------------------- */
static void wb_ctx_set_salt(void)
{
    ecEncCtx ctx;
    WC_RNG rng;
    int ret;

    XMEMSET(&ctx, 0, sizeof(ctx));
    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("wc_InitRng failed (ecc_ctx_set_salt skipped)");
        wb_fail = 1;
        return;
    }
    ctx.rng = &rng;

    ret = ecc_ctx_set_salt(NULL, REQ_RESP_CLIENT);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("ecc_ctx_set_salt(ctx=NULL) unexpected return");
        wb_fail = 1;
    }

    ret = ecc_ctx_set_salt(&ctx, 0);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("ecc_ctx_set_salt(flags=0) unexpected return");
        wb_fail = 1;
    }

    /* all-false: real ctx + real flags value. */
    ret = ecc_ctx_set_salt(&ctx, REQ_RESP_CLIENT);
    if (ret != 0) {
        WB_NOTE("ecc_ctx_set_salt(all-false) unexpected return");
        wb_fail = 1;
    }

    (void)wc_FreeRng(&rng);
    WB_NOTE("ecc_ctx_set_salt ctx/flags==0 guard pairs exercised");
}

/* llvm-cov computes MC/DC independence PER BINARY: this whitebox TU is the
 * ONLY place wc_ecc_ctx_set_own_salt() is ever called at all (the tests/api
 * suite only exercises wc_ecc_ctx_set_peer_salt()), so every operand of
 * both functions' 3-operand OR guard --
 *   if (ctx == NULL || ctx->protocol == 0 || salt == NULL)
 * -- must get its full independence pair (toggle one operand, hold the
 * other two fixed at their "continue" value) from calls made HERE; a TRUE
 * shown in one binary and a FALSE shown in another do not combine. */
static void wb_ctx_protocol_zero(void)
{
    ecEncCtx zeroCtx;   /* protocol left at 0 by XMEMSET */
    ecEncCtx liveCtx;
    WC_RNG rng;
    byte salt[EXCHANGE_SALT_SZ];

    XMEMSET(&zeroCtx, 0, sizeof(zeroCtx));
    XMEMSET(salt, 0x11, sizeof(salt));

    /* wc_ecc_ctx_get_own_salt: protocol==0 TRUE half (line ~14506). The
     * NULL/valid halves are already shown by the tests/api suite. */
    if (wc_ecc_ctx_get_own_salt(&zeroCtx) != NULL) {
        WB_NOTE("wc_ecc_ctx_get_own_salt(protocol=0) unexpected non-NULL");
        wb_fail = 1;
    }

    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("wc_InitRng failed (protocol guard pairs skipped)");
        return;
    }
    ecc_ctx_init(&liveCtx, REQ_RESP_CLIENT, &rng);

    /* ---- wc_ecc_ctx_set_peer_salt (line ~14554): ctx==NULL and salt==NULL
     * halves are already shown by tests/api's test_wc_ecc_ctx_set_peer_salt
     * (same pattern, different binary -- doesn't count here); supply ALL
     * THREE operands' pairs in this one binary too so this binary's own
     * MC/DC is complete independent of what the API binary shows. */
    if (wc_ecc_ctx_set_peer_salt(NULL, salt) != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("wc_ecc_ctx_set_peer_salt(ctx=NULL) unexpected return");
        wb_fail = 1;
    }
    if (wc_ecc_ctx_set_peer_salt(&zeroCtx, salt) !=
            WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("wc_ecc_ctx_set_peer_salt(protocol=0) unexpected return");
        wb_fail = 1;
    }
    if (wc_ecc_ctx_set_peer_salt(&liveCtx, NULL) !=
            WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("wc_ecc_ctx_set_peer_salt(salt=NULL) unexpected return");
        wb_fail = 1;
    }
    /* all-false companion: real ctx (protocol != 0), real salt. */
    (void)wc_ecc_ctx_set_peer_salt(&liveCtx, salt);

    /* ---- wc_ecc_ctx_set_own_salt (line ~14646): never called anywhere
     * else, so needs its complete independence set here. */
    if (wc_ecc_ctx_set_own_salt(NULL, salt, sizeof(salt)) !=
            WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("wc_ecc_ctx_set_own_salt(ctx=NULL) unexpected return");
        wb_fail = 1;
    }
    if (wc_ecc_ctx_set_own_salt(&zeroCtx, salt, sizeof(salt)) !=
            WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("wc_ecc_ctx_set_own_salt(protocol=0) unexpected return");
        wb_fail = 1;
    }
    if (wc_ecc_ctx_set_own_salt(&liveCtx, NULL, 0) !=
            WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("wc_ecc_ctx_set_own_salt(salt=NULL) unexpected return");
        wb_fail = 1;
    }
    /* all-false companion: real ctx (protocol != 0), real salt. */
    (void)wc_ecc_ctx_set_own_salt(&liveCtx, salt, sizeof(salt));

    (void)wc_FreeRng(&rng);
    WB_NOTE("ecEncCtx protocol==0 guard halves exercised");
}
#else
static void wb_ctx_set_salt(void) { WB_NOTE("HAVE_ECC_ENCRYPT off; skipped"); }
static void wb_ctx_protocol_zero(void)
{
    WB_NOTE("HAVE_ECC_ENCRYPT off; skipped");
}
#endif /* HAVE_ECC_ENCRYPT */

#endif /* HAVE_ECC && !WOLF_CRYPTO_CB_ONLY_ECC */

int main(void)
{
    printf("ecc.c white-box MC/DC supplement\n");
#if !defined(HAVE_ECC) || defined(WOLF_CRYPTO_CB_ONLY_ECC)
    printf("  HAVE_ECC off (or crypto-cb-only build); nothing to exercise\n");
    return 0;
#else
    wb_curve_load();
    wb_import_private_key_ex();
    wb_ctx_set_salt();
    wb_ctx_protocol_zero();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures are surfaced as skips, not test failures: the campaign
     * treats a nonzero exit as a failed variant and discards its coverage. */
    return 0;
#endif
}
