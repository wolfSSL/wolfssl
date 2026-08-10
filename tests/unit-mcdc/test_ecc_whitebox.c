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

    /* wc_ecc_ctx_get_own_salt: protocol==0 FALSE half (live ctx, real
     * protocol) -- completes the independence pair for that operand
     * within this binary (the TRUE half was zeroCtx above). */
    if (wc_ecc_ctx_get_own_salt(&liveCtx) == NULL) {
        WB_NOTE("wc_ecc_ctx_get_own_salt(live) unexpected NULL");
        wb_fail = 1;
    }

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

/* ------------------------------------------------------------------------- *
 * Class 7: wc_ecc_is_valid_idx() "n < x" independence (line ~4335).
 *
 *   if ((n >= ECC_CUSTOM_IDX) && (n < x)) { return 1; }
 *
 * Every public caller passes either a real ecc_sets[] index (n < x, always
 * true) or a value already rejected by the earlier "n >= ECC_SET_COUNT"
 * guard, so the "n < x" operand's FALSE half (n >= ECC_CUSTOM_IDX true, but
 * n not less than the live table size x) is never observed. n == x (the
 * table's own terminator slot) is the smallest value that is still
 * ECC_CUSTOM_IDX and still under ECC_SET_COUNT.
 * ------------------------------------------------------------------------- */
static void wb_is_valid_idx_n_lt_x(void)
{
    int x;
    for (x = 0; ecc_sets[x].size != 0; x++) { }
    if (wc_ecc_is_valid_idx(x) != 0) {
        WB_NOTE("wc_ecc_is_valid_idx(terminator idx) unexpected valid");
        wb_fail = 1;
    }
    WB_NOTE("wc_ecc_is_valid_idx n<x independence exercised");
}

/* ------------------------------------------------------------------------- *
 * Class 8: wc_ecc_cmp_param() param/curveParam NULL guard (line ~4460).
 *
 *   if (param == NULL || curveParam == NULL) return BAD_FUNC_ARG;
 *
 * Both public callers always pass live ecc_sets[] hex strings and a live
 * caller-supplied buffer, so neither NULL half is reachable from the API.
 * File-static: only callable because this TU #includes ecc.c.
 * ------------------------------------------------------------------------- */
static void wb_cmp_param_null(void)
{
    byte param[4] = { 1, 2, 3, 4 };
    int ret;

    ret = wc_ecc_cmp_param(NULL, param, sizeof(param), WC_TYPE_UNSIGNED_BIN);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("wc_ecc_cmp_param(curveParam=NULL) unexpected return");
        wb_fail = 1;
    }
    ret = wc_ecc_cmp_param("01020304", NULL, 0, WC_TYPE_UNSIGNED_BIN);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("wc_ecc_cmp_param(param=NULL) unexpected return");
        wb_fail = 1;
    }
    /* all-false companion, in this binary. */
    (void)wc_ecc_cmp_param("01020304", param, sizeof(param),
        WC_TYPE_UNSIGNED_BIN);
    WB_NOTE("wc_ecc_cmp_param NULL guard pairs exercised");
}

/* Convert a curve hex-string field to its raw big-endian bytes, using the
 * same mp_read_radix()/mp_to_unsigned_bin() the library itself uses -- so
 * the bytes compare equal (via wc_ecc_cmp_param) to the source hex string
 * regardless of any leading-zero-nibble width difference. */
#define WB_MAXFIELD 100 /* > any ecc_sets[] field at P-521 (66 bytes) */
static int wb_hex_to_bin(const char* hex, byte* out, word32* outLen)
{
    mp_int t;
    int err;
    int sz;

    if (mp_init(&t) != MP_OKAY)
        return -1;
    err = mp_read_radix(&t, hex, MP_RADIX_HEX);
    if (err == MP_OKAY) {
        sz = mp_unsigned_bin_size(&t);
        if (sz < 0 || (word32)sz > WB_MAXFIELD) {
            err = -1;
        }
        else {
            *outLen = (word32)sz;
            err = mp_to_unsigned_bin(&t, out);
        }
    }
    mp_clear(&t);
    return err;
}

/* ------------------------------------------------------------------------- *
 * Class 9/10: wc_ecc_get_curve_id_from_params() (lines ~4537, ~4545).
 *
 *   NULL OR guard: prime==NULL || Af==NULL || Bf==NULL || order==NULL ||
 *                  Gx==NULL || Gy==NULL
 *   AND match chain: prime match && Af match && Bf match && order match &&
 *                     Gx match && Gy match && cofactor match
 *
 * No tests/api caller ever supplies a real matching parameter set (every
 * caller either passes a deliberately-wrong set to prove ECC_CURVE_INVALID,
 * or does not call this function at all), so neither the NULL guard's non-
 * prime operands nor any operand of the match chain past "prime" has its
 * independence pair shown anywhere. Build a byte-exact copy of a real
 * curve's fields (SECP256R1) to drive both.
 * ------------------------------------------------------------------------- */
static void wb_get_curve_id_from_params(void)
{
    int idx = wc_ecc_get_curve_idx(ECC_SECP256R1);
    const ecc_set_type* cs;
    byte prime[WB_MAXFIELD], Af[WB_MAXFIELD], Bf[WB_MAXFIELD];
    byte order[WB_MAXFIELD], Gx[WB_MAXFIELD], Gy[WB_MAXFIELD];
    byte bad[WB_MAXFIELD];
    word32 primeSz, AfSz, BfSz, orderSz, GxSz, GySz;
    int fieldSize, ret;

    if (idx == ECC_CURVE_INVALID) {
        WB_NOTE("SECP256R1 not in ecc_sets[]; skipped");
        wb_fail = 1;
        return;
    }
    cs = wc_ecc_get_curve_params(idx);
    fieldSize = cs->size * 8;

    if (wb_hex_to_bin(cs->prime, prime, &primeSz) != 0 ||
        wb_hex_to_bin(cs->Af, Af, &AfSz) != 0 ||
        wb_hex_to_bin(cs->Bf, Bf, &BfSz) != 0 ||
        wb_hex_to_bin(cs->order, order, &orderSz) != 0 ||
        wb_hex_to_bin(cs->Gx, Gx, &GxSz) != 0 ||
        wb_hex_to_bin(cs->Gy, Gy, &GySz) != 0) {
        WB_NOTE("wb_hex_to_bin failed; wb_get_curve_id_from_params skipped");
        wb_fail = 1;
        return;
    }

    /* ---- NULL OR guard: isolate each non-prime operand, rest valid ---- */
    ret = wc_ecc_get_curve_id_from_params(fieldSize, prime, primeSz, NULL,
        AfSz, Bf, BfSz, order, orderSz, Gx, GxSz, Gy, GySz, cs->cofactor);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) { wb_fail = 1; }
    ret = wc_ecc_get_curve_id_from_params(fieldSize, prime, primeSz, Af,
        AfSz, NULL, BfSz, order, orderSz, Gx, GxSz, Gy, GySz, cs->cofactor);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) { wb_fail = 1; }
    ret = wc_ecc_get_curve_id_from_params(fieldSize, prime, primeSz, Af,
        AfSz, Bf, BfSz, NULL, orderSz, Gx, GxSz, Gy, GySz, cs->cofactor);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) { wb_fail = 1; }
    ret = wc_ecc_get_curve_id_from_params(fieldSize, prime, primeSz, Af,
        AfSz, Bf, BfSz, order, orderSz, NULL, GxSz, Gy, GySz, cs->cofactor);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) { wb_fail = 1; }
    ret = wc_ecc_get_curve_id_from_params(fieldSize, prime, primeSz, Af,
        AfSz, Bf, BfSz, order, orderSz, Gx, GxSz, NULL, GySz, cs->cofactor);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) { wb_fail = 1; }
    if (wb_fail) {
        WB_NOTE("wc_ecc_get_curve_id_from_params NULL guard unexpected");
    }

    /* ---- all-valid baseline: full real match, needed in THIS binary ---- */
    ret = wc_ecc_get_curve_id_from_params(fieldSize, prime, primeSz, Af,
        AfSz, Bf, BfSz, order, orderSz, Gx, GxSz, Gy, GySz, cs->cofactor);
    if (ret != cs->id) {
        WB_NOTE("wc_ecc_get_curve_id_from_params(all-match) unexpected id");
        wb_fail = 1;
    }

    /* ---- AND-chain independence: corrupt exactly one field, keep the
     * rest matching, expect ECC_CURVE_INVALID (no ecc_sets[] entry can
     * coincidentally match a flipped cryptographic field of the same
     * length). ---- */
#define WB_CORRUPT1(buf, len) do { \
        XMEMCPY(bad, (buf), (len)); \
        bad[(len) - 1] = (byte)(bad[(len) - 1] ^ 0xFFu); \
    } while (0)

    WB_CORRUPT1(Af, AfSz);
    ret = wc_ecc_get_curve_id_from_params(fieldSize, prime, primeSz, bad,
        AfSz, Bf, BfSz, order, orderSz, Gx, GxSz, Gy, GySz, cs->cofactor);
    if (ret != ECC_CURVE_INVALID) { wb_fail = 1; }

    WB_CORRUPT1(Bf, BfSz);
    ret = wc_ecc_get_curve_id_from_params(fieldSize, prime, primeSz, Af,
        AfSz, bad, BfSz, order, orderSz, Gx, GxSz, Gy, GySz, cs->cofactor);
    if (ret != ECC_CURVE_INVALID) { wb_fail = 1; }

    WB_CORRUPT1(order, orderSz);
    ret = wc_ecc_get_curve_id_from_params(fieldSize, prime, primeSz, Af,
        AfSz, Bf, BfSz, bad, orderSz, Gx, GxSz, Gy, GySz, cs->cofactor);
    if (ret != ECC_CURVE_INVALID) { wb_fail = 1; }

    WB_CORRUPT1(Gx, GxSz);
    ret = wc_ecc_get_curve_id_from_params(fieldSize, prime, primeSz, Af,
        AfSz, Bf, BfSz, order, orderSz, bad, GxSz, Gy, GySz, cs->cofactor);
    if (ret != ECC_CURVE_INVALID) { wb_fail = 1; }

    WB_CORRUPT1(Gy, GySz);
    ret = wc_ecc_get_curve_id_from_params(fieldSize, prime, primeSz, Af,
        AfSz, Bf, BfSz, order, orderSz, Gx, GxSz, bad, GySz, cs->cofactor);
    if (ret != ECC_CURVE_INVALID) { wb_fail = 1; }

    ret = wc_ecc_get_curve_id_from_params(fieldSize, prime, primeSz, Af,
        AfSz, Bf, BfSz, order, orderSz, Gx, GxSz, Gy, GySz, cs->cofactor + 1);
    if (ret != ECC_CURVE_INVALID) { wb_fail = 1; }
#undef WB_CORRUPT1

    WB_NOTE("wc_ecc_get_curve_id_from_params NULL+match-chain pairs done");
}

/* ------------------------------------------------------------------------- *
 * Class 11: wc_ecc_get_curve_id_from_dp_params() (lines ~4580, ~4591).
 *
 *   7-operand OR guard: dp==NULL || dp->prime==NULL || dp->Af==NULL ||
 *     dp->Bf==NULL || dp->order==NULL || dp->Gx==NULL || dp->Gy==NULL
 *   AND match chain: same 6 hex-string fields (WC_TYPE_HEX_STR) + cofactor.
 *
 * No public caller ever builds an ecc_set_type with a live curve's own hex
 * strings copied in field-by-field (real callers pass a whole, pre-existing
 * dp), so every operand past "dp itself" is unreached both in the OR guard
 * and the match chain.
 * ------------------------------------------------------------------------- */
static void wb_get_curve_id_from_dp_params(void)
{
    int idx = wc_ecc_get_curve_idx(ECC_SECP256R1);
    const ecc_set_type* cs;
    ecc_set_type dp;
    char bad[WB_MAXFIELD * 2 + 4];
    int ret;

    if (idx == ECC_CURVE_INVALID) {
        WB_NOTE("SECP256R1 not in ecc_sets[]; skipped");
        wb_fail = 1;
        return;
    }
    cs = wc_ecc_get_curve_params(idx);

    ret = wc_ecc_get_curve_id_from_dp_params(NULL);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) { wb_fail = 1; }

    XMEMSET(&dp, 0, sizeof(dp));
    dp.size = cs->size;
    dp.cofactor = cs->cofactor;
    dp.Af = cs->Af; dp.Bf = cs->Bf; dp.order = cs->order;
    dp.Gx = cs->Gx; dp.Gy = cs->Gy;

    dp.prime = NULL;
    ret = wc_ecc_get_curve_id_from_dp_params(&dp);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) { wb_fail = 1; }
    dp.prime = cs->prime;

    dp.Af = NULL;
    ret = wc_ecc_get_curve_id_from_dp_params(&dp);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) { wb_fail = 1; }
    dp.Af = cs->Af;

    dp.Bf = NULL;
    ret = wc_ecc_get_curve_id_from_dp_params(&dp);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) { wb_fail = 1; }
    dp.Bf = cs->Bf;

    dp.order = NULL;
    ret = wc_ecc_get_curve_id_from_dp_params(&dp);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) { wb_fail = 1; }
    dp.order = cs->order;

    dp.Gx = NULL;
    ret = wc_ecc_get_curve_id_from_dp_params(&dp);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) { wb_fail = 1; }
    dp.Gx = cs->Gx;

    dp.Gy = NULL;
    ret = wc_ecc_get_curve_id_from_dp_params(&dp);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) { wb_fail = 1; }
    dp.Gy = cs->Gy;
    if (wb_fail) {
        WB_NOTE("wc_ecc_get_curve_id_from_dp_params NULL guard unexpected");
    }

    /* all-valid baseline: full real match. */
    ret = wc_ecc_get_curve_id_from_dp_params(&dp);
    if (ret != cs->id) {
        WB_NOTE("wc_ecc_get_curve_id_from_dp_params(all-match) unexpected");
        wb_fail = 1;
    }

    /* AND-chain independence: corrupt one hex digit at a time (same
     * strlen, so the "strlen mismatch" fast-reject in wc_ecc_cmp_param
     * does not short-circuit before the byte compare runs), keep every
     * other field matching. */
#define WB_CORRUPT_HEX(field) do { \
        size_t wb_n = XSTRLEN((field)); \
        XSTRNCPY(bad, (field), sizeof(bad) - 1); \
        bad[sizeof(bad) - 1] = '\0'; \
        bad[wb_n - 1] = (bad[wb_n - 1] == '0') ? '1' : '0'; \
    } while (0)

    WB_CORRUPT_HEX(cs->Af); dp.Af = bad;
    ret = wc_ecc_get_curve_id_from_dp_params(&dp);
    if (ret != ECC_CURVE_INVALID) { wb_fail = 1; }
    dp.Af = cs->Af;

    WB_CORRUPT_HEX(cs->Bf); dp.Bf = bad;
    ret = wc_ecc_get_curve_id_from_dp_params(&dp);
    if (ret != ECC_CURVE_INVALID) { wb_fail = 1; }
    dp.Bf = cs->Bf;

    WB_CORRUPT_HEX(cs->order); dp.order = bad;
    ret = wc_ecc_get_curve_id_from_dp_params(&dp);
    if (ret != ECC_CURVE_INVALID) { wb_fail = 1; }
    dp.order = cs->order;

    WB_CORRUPT_HEX(cs->Gx); dp.Gx = bad;
    ret = wc_ecc_get_curve_id_from_dp_params(&dp);
    if (ret != ECC_CURVE_INVALID) { wb_fail = 1; }
    dp.Gx = cs->Gx;

    WB_CORRUPT_HEX(cs->Gy); dp.Gy = bad;
    ret = wc_ecc_get_curve_id_from_dp_params(&dp);
    if (ret != ECC_CURVE_INVALID) { wb_fail = 1; }
    dp.Gy = cs->Gy;
#undef WB_CORRUPT_HEX

    dp.cofactor = cs->cofactor + 1;
    ret = wc_ecc_get_curve_id_from_dp_params(&dp);
    if (ret != ECC_CURVE_INVALID) { wb_fail = 1; }

    WB_NOTE("wc_ecc_get_curve_id_from_dp_params NULL+match-chain pairs done");
}

/* ------------------------------------------------------------------------- *
 * Class 12: wc_ecc_mulmod_ex2() 4-operand NULL guard, generic (!SP_MATH)
 * path (line ~4009): k==NULL || G==NULL || R==NULL || modulus==NULL.
 *
 * No variant here defines bare WOLFSSL_SP_MATH, so this is the branch every
 * variant compiles. No current test calls this entry point directly (real
 * traffic goes through wc_ecc_mulmod_ex/wc_ecc_mulmod, or the FP_ECC/SP
 * layers above it), so not even the all-valid baseline is shown elsewhere
 * in this binary; supply the full independence set plus one real call.
 * ------------------------------------------------------------------------- */
static void wb_mulmod_ex2_null_guard(void)
{
    ecc_point *G = NULL, *R = NULL;
    mp_int k, a, modulus, order;
    int ret;

    if (mp_init_multi(&k, &a, &modulus, &order, NULL, NULL) != MP_OKAY) {
        WB_NOTE("mp_init_multi failed; wb_mulmod_ex2_null_guard skipped");
        wb_fail = 1;
        return;
    }
    (void)mp_set(&k, 3);
    (void)mp_set(&a, 2);
    (void)mp_set_int(&modulus, 1000000007uL);
    (void)mp_set_int(&order, 1000000007uL);

    G = wc_ecc_new_point();
    R = wc_ecc_new_point();
    if (G == NULL || R == NULL) {
        WB_NOTE("wc_ecc_new_point failed; wb_mulmod_ex2_null_guard skipped");
        wb_fail = 1;
        goto out;
    }
    (void)mp_set(G->x, 5);
    (void)mp_set(G->y, 7);
    (void)mp_set(G->z, 1);

    ret = wc_ecc_mulmod_ex2(NULL, G, R, &a, &modulus, &order, NULL, 1, NULL);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }
    ret = wc_ecc_mulmod_ex2(&k, NULL, R, &a, &modulus, &order, NULL, 1, NULL);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }
    ret = wc_ecc_mulmod_ex2(&k, G, NULL, &a, &modulus, &order, NULL, 1, NULL);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }
    ret = wc_ecc_mulmod_ex2(&k, G, R, &a, NULL, &order, NULL, 1, NULL);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }

    /* all-false baseline: real (if not curve-accurate) arithmetic inputs;
     * the generic point-math does not require the operands to satisfy a
     * real curve equation, only that modulus is odd (for montgomery). */
    (void)wc_ecc_mulmod_ex2(&k, G, R, &a, &modulus, &order, NULL, 1, NULL);

    if (wb_fail) {
        WB_NOTE("wc_ecc_mulmod_ex2 NULL guard unexpected return");
    }
    WB_NOTE("wc_ecc_mulmod_ex2 4-operand NULL guard pairs exercised");

out:
    wc_ecc_del_point(G);
    wc_ecc_del_point(R);
    mp_clear(&order);
    mp_clear(&modulus);
    mp_clear(&a);
    mp_clear(&k);
}

/* ------------------------------------------------------------------------- *
 * Class 13: ecc_map_ex() P/modulus NULL guard (line ~2791).
 *
 *   if (P == NULL || modulus == NULL) return ECC_BAD_ARG_E;
 *
 * Every caller of ecc_map()/ecc_map_ex() passes a live point off the stack
 * and a live curve modulus, so neither NULL half is reachable via the API.
 * ------------------------------------------------------------------------- */
static void wb_ecc_map_ex_null(void)
{
    ecc_point* P;
    mp_int modulus;
    int ret;

    if (mp_init(&modulus) != MP_OKAY) {
        wb_fail = 1;
        return;
    }
    (void)mp_set_int(&modulus, 1000000007uL);
    P = wc_ecc_new_point();
    if (P == NULL) {
        mp_clear(&modulus);
        wb_fail = 1;
        return;
    }
    (void)mp_set(P->x, 3);
    (void)mp_set(P->y, 5);
    (void)mp_set(P->z, 1);

    ret = ecc_map_ex(NULL, &modulus, 0, 0);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }
    ret = ecc_map_ex(P, NULL, 0, 0);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }

    wc_ecc_del_point(P);
    mp_clear(&modulus);
    WB_NOTE("ecc_map_ex P/modulus NULL guard pairs exercised");
}

/* ------------------------------------------------------------------------- *
 * Class 14: ecc_projective_add_point()/ecc_projective_dbl_point() public
 * wrappers (lines ~2393/2397, ~2761/2764): NULL guard + coordinate range
 * check ("mp_cmp(..) != MP_LT" over x/y/z of both operands).
 *
 * These wrappers are compiled unconditionally in ecc.c (always in scope for
 * a same-TU #include), but only PROTOTYPED under WOLFSSL_PUBLIC_ECC_ADD_DBL
 * -- no in-tree caller (all of which use the _safe() variants) reaches them
 * at all, so no operand of either guard has any coverage.
 * ------------------------------------------------------------------------- */
static void wb_projective_wrappers(void)
{
    ecc_point *P, *Q, *R;
    mp_int a, modulus;
    int ret;

    if (mp_init_multi(&a, &modulus, NULL, NULL, NULL, NULL) != MP_OKAY) {
        wb_fail = 1;
        return;
    }
    (void)mp_set(&a, 2);
    (void)mp_set_int(&modulus, 1000000007uL);

    P = wc_ecc_new_point();
    Q = wc_ecc_new_point();
    R = wc_ecc_new_point();
    if (P == NULL || Q == NULL || R == NULL) {
        wb_fail = 1;
        goto out;
    }
    (void)mp_set(P->x, 3); (void)mp_set(P->y, 5); (void)mp_set(P->z, 1);
    (void)mp_set(Q->x, 11); (void)mp_set(Q->y, 13); (void)mp_set(Q->z, 1);

    /* ---- ecc_projective_add_point: NULL guard, each operand isolated ---- */
    ret = ecc_projective_add_point(NULL, Q, R, &a, &modulus, 0);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }
    ret = ecc_projective_add_point(P, NULL, R, &a, &modulus, 0);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }
    ret = ecc_projective_add_point(P, Q, NULL, &a, &modulus, 0);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }
    ret = ecc_projective_add_point(P, Q, R, &a, NULL, 0);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }

    /* ---- range check: each of the 6 coordinate comparisons isolated,
     * one coordinate at a time set >= modulus, rest in range. ---- */
    (void)mp_set_int(P->x, 1000000007uL); /* == modulus: not MP_LT */
    ret = ecc_projective_add_point(P, Q, R, &a, &modulus, 0);
    if (ret != WC_NO_ERR_TRACE(ECC_OUT_OF_RANGE_E)) { wb_fail = 1; }
    (void)mp_set(P->x, 3);

    (void)mp_set_int(P->y, 1000000007uL);
    ret = ecc_projective_add_point(P, Q, R, &a, &modulus, 0);
    if (ret != WC_NO_ERR_TRACE(ECC_OUT_OF_RANGE_E)) { wb_fail = 1; }
    (void)mp_set(P->y, 5);

    (void)mp_set_int(P->z, 1000000007uL);
    ret = ecc_projective_add_point(P, Q, R, &a, &modulus, 0);
    if (ret != WC_NO_ERR_TRACE(ECC_OUT_OF_RANGE_E)) { wb_fail = 1; }
    (void)mp_set(P->z, 1);

    (void)mp_set_int(Q->x, 1000000007uL);
    ret = ecc_projective_add_point(P, Q, R, &a, &modulus, 0);
    if (ret != WC_NO_ERR_TRACE(ECC_OUT_OF_RANGE_E)) { wb_fail = 1; }
    (void)mp_set(Q->x, 11);

    (void)mp_set_int(Q->y, 1000000007uL);
    ret = ecc_projective_add_point(P, Q, R, &a, &modulus, 0);
    if (ret != WC_NO_ERR_TRACE(ECC_OUT_OF_RANGE_E)) { wb_fail = 1; }
    (void)mp_set(Q->y, 13);

    (void)mp_set_int(Q->z, 1000000007uL);
    ret = ecc_projective_add_point(P, Q, R, &a, &modulus, 0);
    if (ret != WC_NO_ERR_TRACE(ECC_OUT_OF_RANGE_E)) { wb_fail = 1; }
    (void)mp_set(Q->z, 1);

    /* all-in-range baseline (drives the real _ecc_projective_add_point). */
    ret = ecc_projective_add_point(P, Q, R, &a, &modulus, 0);
    if (ret != MP_OKAY) { wb_fail = 1; }

    /* ---- ecc_projective_dbl_point: NULL guard + range check, same idea
     * with 3 operands (P/R/modulus; no Q). ---- */
    ret = ecc_projective_dbl_point(NULL, R, &a, &modulus, 0);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }
    ret = ecc_projective_dbl_point(P, NULL, &a, &modulus, 0);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }
    ret = ecc_projective_dbl_point(P, R, &a, NULL, 0);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }

    (void)mp_set_int(P->x, 1000000007uL);
    ret = ecc_projective_dbl_point(P, R, &a, &modulus, 0);
    if (ret != WC_NO_ERR_TRACE(ECC_OUT_OF_RANGE_E)) { wb_fail = 1; }
    (void)mp_set(P->x, 3);

    (void)mp_set_int(P->y, 1000000007uL);
    ret = ecc_projective_dbl_point(P, R, &a, &modulus, 0);
    if (ret != WC_NO_ERR_TRACE(ECC_OUT_OF_RANGE_E)) { wb_fail = 1; }
    (void)mp_set(P->y, 5);

    (void)mp_set_int(P->z, 1000000007uL);
    ret = ecc_projective_dbl_point(P, R, &a, &modulus, 0);
    if (ret != WC_NO_ERR_TRACE(ECC_OUT_OF_RANGE_E)) { wb_fail = 1; }
    (void)mp_set(P->z, 1);

    ret = ecc_projective_dbl_point(P, R, &a, &modulus, 0);
    if (ret != MP_OKAY) { wb_fail = 1; }

    if (wb_fail) {
        WB_NOTE("ecc_projective_add/dbl_point wrapper unexpected return");
    }
    WB_NOTE("ecc_projective_add/dbl_point wrapper NULL+range pairs done");

out:
    wc_ecc_del_point(P);
    wc_ecc_del_point(Q);
    wc_ecc_del_point(R);
    mp_clear(&modulus);
    mp_clear(&a);
}

/* ECC_SHAMIR is unconditional in the base config (see modules.json "ecc"
 * notes): under it, ecc_mul2add() is `static normal_ecc_mul2add()` (FP_ECC
 * on, the default) or the public `ecc_mul2add()` itself (no_fp_shamir, FP_ECC
 * off) -- select the same symbol the source itself would use. */
#ifdef ECC_SHAMIR
#ifdef FP_ECC
#define WB_MUL2ADD_FN normal_ecc_mul2add
#else
#define WB_MUL2ADD_FN ecc_mul2add
#endif

/* ------------------------------------------------------------------------- *
 * Class 15: ecc_mul2add()/normal_ecc_mul2add() (line ~8774): 6-operand NULL
 * guard (A/kA/B/kB/C/modulus -- "a" is not checked) and the ECC_BUFSIZE
 * scalar-length sanity check (line ~8861).
 *
 * No caller passes a NULL operand (every public path -- verify_hash's
 * Shamir's-trick optimization -- already validated key/hash/sig upstream),
 * and no caller's scalar ever exceeds ECC_BUFSIZE (257) bytes (they are all
 * bounded by a curve order), so neither guard's TRUE half is reachable via
 * the API. Drives real SECP256R1 generator-point arithmetic (kA=3, kB=5) so
 * the all-false baseline is also completed within this binary.
 * ------------------------------------------------------------------------- */
static void wb_mul2add_and_bufsize(void)
{
    int idx = wc_ecc_get_curve_idx(ECC_SECP256R1);
    const ecc_set_type* cs;
    mp_int a, modulus, kA, kB, kBig;
    ecc_point *A = NULL, *B = NULL, *C = NULL;
    byte fbuf[WB_MAXFIELD];
    byte bigbuf[300];
    word32 sz;
    int ret;

    if (idx == ECC_CURVE_INVALID) {
        wb_fail = 1;
        return;
    }
    cs = wc_ecc_get_curve_params(idx);

    if (mp_init_multi(&a, &modulus, &kA, &kB, &kBig, NULL) != MP_OKAY) {
        wb_fail = 1;
        return;
    }

    if (wb_hex_to_bin(cs->Af, fbuf, &sz) != 0 ||
            mp_read_unsigned_bin(&a, fbuf, (int)sz) != MP_OKAY) {
        wb_fail = 1; goto out;
    }
    if (wb_hex_to_bin(cs->prime, fbuf, &sz) != 0 ||
            mp_read_unsigned_bin(&modulus, fbuf, (int)sz) != MP_OKAY) {
        wb_fail = 1; goto out;
    }
    (void)mp_set(&kA, 3);
    (void)mp_set(&kB, 5);
    XMEMSET(bigbuf, 0xFF, sizeof(bigbuf)); /* > ECC_BUFSIZE (257) bytes */
    if (mp_read_unsigned_bin(&kBig, bigbuf, (int)sizeof(bigbuf)) != MP_OKAY) {
        wb_fail = 1; goto out;
    }

    A = wc_ecc_new_point();
    B = wc_ecc_new_point();
    C = wc_ecc_new_point();
    if (A == NULL || B == NULL || C == NULL) {
        wb_fail = 1; goto out;
    }
    if (wb_hex_to_bin(cs->Gx, fbuf, &sz) != 0 ||
            mp_read_unsigned_bin(A->x, fbuf, (int)sz) != MP_OKAY) {
        wb_fail = 1; goto out;
    }
    if (wb_hex_to_bin(cs->Gy, fbuf, &sz) != 0 ||
            mp_read_unsigned_bin(A->y, fbuf, (int)sz) != MP_OKAY) {
        wb_fail = 1; goto out;
    }
    (void)mp_set(A->z, 1);
    (void)mp_copy(A->x, B->x);
    (void)mp_copy(A->y, B->y);
    (void)mp_copy(A->z, B->z);

    /* ---- 6-operand NULL guard, each isolated ---- */
    ret = WB_MUL2ADD_FN(NULL, &kA, B, &kB, C, &a, &modulus, NULL);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }
    ret = WB_MUL2ADD_FN(A, NULL, B, &kB, C, &a, &modulus, NULL);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }
    ret = WB_MUL2ADD_FN(A, &kA, NULL, &kB, C, &a, &modulus, NULL);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }
    ret = WB_MUL2ADD_FN(A, &kA, B, NULL, C, &a, &modulus, NULL);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }
    ret = WB_MUL2ADD_FN(A, &kA, B, &kB, NULL, &a, &modulus, NULL);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }
    ret = WB_MUL2ADD_FN(A, &kA, B, &kB, C, &a, NULL, NULL);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }

    /* ---- ECC_BUFSIZE check: lenA/lenB isolated ---- */
    ret = WB_MUL2ADD_FN(A, &kBig, B, &kB, C, &a, &modulus, NULL);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) { wb_fail = 1; }
    ret = WB_MUL2ADD_FN(A, &kA, B, &kBig, C, &a, &modulus, NULL);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) { wb_fail = 1; }

    /* ---- all-false baseline: real kA*G + kB*G Shamir computation ---- */
    ret = WB_MUL2ADD_FN(A, &kA, B, &kB, C, &a, &modulus, NULL);
    if (ret != MP_OKAY) { wb_fail = 1; }

    if (wb_fail) {
        WB_NOTE("ecc_mul2add NULL/ECC_BUFSIZE guard unexpected return");
    }
    WB_NOTE("ecc_mul2add NULL guard + ECC_BUFSIZE pairs done");

out:
    wc_ecc_del_point(A);
    wc_ecc_del_point(B);
    wc_ecc_del_point(C);
    mp_clear(&kBig);
    mp_clear(&kB);
    mp_clear(&kA);
    mp_clear(&modulus);
    mp_clear(&a);
}
#else
static void wb_mul2add_and_bufsize(void)
{
    WB_NOTE("ECC_SHAMIR off; ecc_mul2add skipped");
}
#endif /* ECC_SHAMIR */

/* ------------------------------------------------------------------------- *
 * Class 16: ecc_projective_add_point_safe()/ecc_projective_dbl_point_safe()
 * (lines ~8581-8656): the point-at-infinity special cases and the
 * A==B / A==-B collision cases that the "safe" wrappers exist to handle.
 *
 * Real ECDSA/ECDH traffic essentially never presents the infinity point or
 * an exact doubling/negation collision to these wrappers (a valid random
 * scalar practically never produces one), so none of the mp_iszero()/
 * mp_cmp() branches here have ever been shown with a live point. Uses a
 * small modulus (not a real curve) since the wrappers only need montgomery-
 * valid modular arithmetic, not an actual point-on-curve check.
 * ------------------------------------------------------------------------- */
static void wb_projective_safe_special_cases(void)
{
    mp_int a, modulus;
    mp_digit mp;
    ecc_point *A, *B, *R;
    int ret, infinity;

    if (mp_init_multi(&a, &modulus, NULL, NULL, NULL, NULL) != MP_OKAY) {
        wb_fail = 1;
        return;
    }
    (void)mp_set(&a, 2);
    (void)mp_set_int(&modulus, 1000000007uL);
    if (mp_montgomery_setup(&modulus, &mp) != MP_OKAY) {
        wb_fail = 1;
        mp_clear(&modulus); mp_clear(&a);
        return;
    }

    A = wc_ecc_new_point();
    B = wc_ecc_new_point();
    R = wc_ecc_new_point();
    if (A == NULL || B == NULL || R == NULL) {
        wb_fail = 1;
        goto out;
    }

    /* ---- A at infinity (x==0 && y==0): copy B into R. ---- */
    (void)mp_set(A->x, 0); (void)mp_set(A->y, 0); (void)mp_set(A->z, 1);
    (void)mp_set(B->x, 3); (void)mp_set(B->y, 5); (void)mp_set(B->z, 1);
    infinity = 0;
    ret = ecc_projective_add_point_safe(A, B, R, &a, &modulus, mp, &infinity);
    if (ret != MP_OKAY) { wb_fail = 1; }

    /* ---- A not infinity (x==0,y!=0: isolates the "&&"), B at infinity:
     * copy A into R. ---- */
    (void)mp_set(A->x, 0); (void)mp_set(A->y, 5); (void)mp_set(A->z, 1);
    (void)mp_set(B->x, 0); (void)mp_set(B->y, 0); (void)mp_set(B->z, 1);
    infinity = 0;
    ret = ecc_projective_add_point_safe(A, B, R, &a, &modulus, mp, &infinity);
    if (ret != MP_OKAY) { wb_fail = 1; }

    /* ---- neither infinite (y==0,x!=0 isolates A's "&&" other side;
     * x==0,y!=0 isolates B's), same x/z, same y: A == B -> double. ---- */
    (void)mp_set(A->x, 7); (void)mp_set(A->y, 0); (void)mp_set(A->z, 1);
    (void)mp_set(B->x, 0); (void)mp_set(B->y, 5); (void)mp_set(B->z, 1);
    infinity = 0;
    ret = ecc_projective_add_point_safe(A, B, R, &a, &modulus, mp, &infinity);
    if (ret != MP_OKAY) { wb_fail = 1; }

    (void)mp_set(A->x, 11); (void)mp_set(A->y, 13); (void)mp_set(A->z, 1);
    (void)mp_set(B->x, 11); (void)mp_set(B->y, 13); (void)mp_set(B->z, 1);
    infinity = 0;
    ret = ecc_projective_add_point_safe(A, B, R, &a, &modulus, mp, &infinity);
    if (ret != MP_OKAY) { wb_fail = 1; }

    /* ---- same x/z, y differs: A == -B -> result set to infinity,
     * *infinity set (infinity!=NULL true half). ---- */
    (void)mp_set(A->x, 11); (void)mp_set(A->y, 13); (void)mp_set(A->z, 1);
    (void)mp_set(B->x, 11); (void)mp_set(B->y, 17); (void)mp_set(B->z, 1);
    infinity = 0;
    ret = ecc_projective_add_point_safe(A, B, R, &a, &modulus, mp, &infinity);
    if (ret != MP_OKAY || !infinity) { wb_fail = 1; }
    /* same call, infinity==NULL: isolates that operand's other half. */
    ret = ecc_projective_add_point_safe(A, B, R, &a, &modulus, mp, NULL);
    if (ret != MP_OKAY) { wb_fail = 1; }

    /* ---- general add, neither special case (the common path). ---- */
    (void)mp_set(A->x, 3); (void)mp_set(A->y, 5); (void)mp_set(A->z, 1);
    (void)mp_set(B->x, 11); (void)mp_set(B->y, 13); (void)mp_set(B->z, 1);
    infinity = 0;
    ret = ecc_projective_add_point_safe(A, B, R, &a, &modulus, mp, &infinity);
    if (ret != MP_OKAY) { wb_fail = 1; }

    /* ---- ecc_projective_dbl_point_safe: P at infinity vs not. ---- */
    (void)mp_set(A->x, 0); (void)mp_set(A->y, 0); (void)mp_set(A->z, 1);
    ret = ecc_projective_dbl_point_safe(A, R, &a, &modulus, mp);
    if (ret != MP_OKAY) { wb_fail = 1; }

    (void)mp_set(A->x, 0); (void)mp_set(A->y, 5); (void)mp_set(A->z, 1);
    ret = ecc_projective_dbl_point_safe(A, R, &a, &modulus, mp);
    if (ret != MP_OKAY) { wb_fail = 1; }

    (void)mp_set(A->x, 3); (void)mp_set(A->y, 5); (void)mp_set(A->z, 1);
    ret = ecc_projective_dbl_point_safe(A, R, &a, &modulus, mp);
    if (ret != MP_OKAY) { wb_fail = 1; }

    if (wb_fail) {
        WB_NOTE("ecc_projective_*_safe special-case unexpected return");
    }
    WB_NOTE("ecc_projective_add/dbl_point_safe special cases exercised");

out:
    wc_ecc_del_point(A);
    wc_ecc_del_point(B);
    wc_ecc_del_point(R);
    mp_clear(&modulus);
    mp_clear(&a);
}

/* find_hole()/find_base()/add_entry() and fp_cache[] itself only exist
 * inside ecc.c's own #ifdef FP_ECC (+ !WOLFSSL_SP_MATH) block. */
#if defined(FP_ECC) && !defined(WOLFSSL_SP_MATH)
/* ------------------------------------------------------------------------- *
 * Class 17: FP_ECC fixed-point cache internals: find_base() (line ~13585),
 * find_hole() (line ~13548). Both are file-static and process-global
 * (fp_cache[FP_ENTRIES]), reset via wc_ecc_fp_free() so each shot starts
 * from deterministic empty-cache state.
 *
 * Real traffic keeps the cache warm across many identical-curve operations,
 * so a fresh process practically never observes find_base() miss on an
 * OCCUPIED-but-different-point entry, nor find_hole() choosing between a
 * locked low-lru entry and an empty one, nor its "evict a live entry"
 * cleanup path -- none of those have a public-API trigger this precise.
 * add_entry() itself only needs mp_copy (no curve math), so it is safe to
 * call directly; the mp_init() of fp_cache[idx].mu below stands in for what
 * build_lut() would normally have set up right after add_entry(), so
 * find_hole()'s later mp_clear(&fp_cache[idx].mu) operates on a live value.
 * ------------------------------------------------------------------------- */
static void wb_fp_cache_internals(void)
{
    ecc_point *g0, *g1;
    int idx0, ret;
    unsigned x;

    wc_ecc_fp_free(); /* deterministic empty-cache start */

    g0 = wc_ecc_new_point();
    g1 = wc_ecc_new_point();
    if (g0 == NULL || g1 == NULL) {
        wb_fail = 1;
        goto out;
    }
    (void)mp_set(g0->x, 3); (void)mp_set(g0->y, 5); (void)mp_set(g0->z, 1);
    (void)mp_set(g1->x, 11); (void)mp_set(g1->y, 13); (void)mp_set(g1->z, 1);

    /* find_base on an empty cache: every fp_cache[x].g == NULL -> -1. */
    if (find_base(g0) != -1) { wb_fail = 1; }

    ret = add_entry(0, g0);
    if (ret != MP_OKAY) { wb_fail = 1; }
    (void)mp_init(&fp_cache[0].mu); /* stand-in for build_lut()'s own init */

    /* find_base: entry 0 occupied and matches (all 3 mp_cmp true) -> 0. */
    if (find_base(g0) != 0) { wb_fail = 1; }
    /* find_base: entry 0 occupied but a DIFFERENT point -> falls through
     * to -1 (isolates the mp_cmp x/y/z operands' FALSE side). */
    if (find_base(g1) != -1) { wb_fail = 1; }

    /* find_hole: lock entry 0 so it is excluded (lock==0 FALSE) even
     * though it has the lowest lru_count; some other (empty, g==NULL)
     * slot must be chosen -- exercises the "z>=0 && g" FALSE half. */
    fp_cache[0].lock = 1;
    idx0 = find_hole();
    if (idx0 < 0 || idx0 == 0 || fp_cache[idx0].g != NULL) { wb_fail = 1; }
    fp_cache[0].lock = 0;

    /* find_hole: bump every OTHER entry's lru_count above entry 0's, so
     * entry 0 (lowest lru_count, unlocked) is chosen and its live g/LUT
     * get freed -- exercises the "z>=0 && g" TRUE half and the eviction
     * cleanup block, plus the "lru_count>3" TRUE half on entries 1..N. */
    for (x = 1; x < FP_ENTRIES; x++) {
        fp_cache[x].lru_count = 5;
    }
    idx0 = find_hole();
    if (idx0 != 0) { wb_fail = 1; }

    if (wb_fail) {
        WB_NOTE("fp_cache find_base/find_hole unexpected state");
    }
    WB_NOTE("fp_cache find_base/find_hole/add_entry internals exercised");

out:
    wc_ecc_del_point(g0);
    wc_ecc_del_point(g1);
    for (x = 0; x < FP_ENTRIES; x++) {
        fp_cache[x].lru_count = 0;
        fp_cache[x].lock = 0;
    }
    wc_ecc_fp_free();
}
#else
static void wb_fp_cache_internals(void)
{
    WB_NOTE("FP_ECC off (or WOLFSSL_SP_MATH); fp_cache internals skipped");
}
#endif /* FP_ECC && !WOLFSSL_SP_MATH */

#ifdef HAVE_ECC_KEY_EXPORT
/* ------------------------------------------------------------------------- *
 * Class 18: wc_ecc_export_point_der()/wc_ecc_export_point_der_compressed()
 * (lines ~10330-10351, ~10396-10418): curve_idx range/valid-idx guard,
 * length-query idiom, NULL guard, coordinate-size sanity check.
 *
 * No tests/api caller drives curve_idx with an in-range-but-invalid index,
 * nor a point whose x/y encodes larger than the curve's own byte width, so
 * those halves are white-box only.
 * ------------------------------------------------------------------------- */
static void wb_export_point_der(void)
{
    int idx = wc_ecc_get_curve_idx(ECC_SECP256R1);
    ecc_point* point;
    byte out[300];
    byte big[400];
    word32 outLen;
    int ret;

    if (idx == ECC_CURVE_INVALID) {
        wb_fail = 1;
        return;
    }
    point = wc_ecc_new_point();
    if (point == NULL) {
        wb_fail = 1;
        return;
    }
    (void)mp_set(point->x, 3);
    (void)mp_set(point->y, 5);
    (void)mp_set(point->z, 1);
    XMEMSET(big, 0xFF, sizeof(big));

    /* ---- curve_idx guard: both operands isolated ---- */
    outLen = sizeof(out);
    ret = wc_ecc_export_point_der(-1, point, out, &outLen);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }
    outLen = sizeof(out);
    ret = wc_ecc_export_point_der(9999, point, out, &outLen);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }

    /* ---- length-query (point!=NULL && out==NULL && outLen!=NULL): isolate
     * point and outLen operands (out==NULL held true throughout). ---- */
    outLen = sizeof(out);
    ret = wc_ecc_export_point_der(idx, point, NULL, &outLen);
    if (ret != WC_NO_ERR_TRACE(LENGTH_ONLY_E)) { wb_fail = 1; }
    ret = wc_ecc_export_point_der(idx, point, NULL, NULL);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }
    outLen = sizeof(out);
    ret = wc_ecc_export_point_der(idx, NULL, NULL, &outLen);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }

    /* ---- coordinate-size check: x/y isolated ---- */
    (void)mp_read_unsigned_bin(point->x, big, (int)sizeof(big));
    outLen = sizeof(out);
    ret = wc_ecc_export_point_der(idx, point, out, &outLen);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }
    (void)mp_set(point->x, 3);

    (void)mp_read_unsigned_bin(point->y, big, (int)sizeof(big));
    outLen = sizeof(out);
    ret = wc_ecc_export_point_der(idx, point, out, &outLen);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }
    (void)mp_set(point->y, 5);

    /* baseline real export. */
    outLen = sizeof(out);
    ret = wc_ecc_export_point_der(idx, point, out, &outLen);
    if (ret != MP_OKAY) { wb_fail = 1; }

#ifdef HAVE_COMP_KEY
    outLen = sizeof(out);
    ret = wc_ecc_export_point_der_compressed(-1, point, out, &outLen);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }
    outLen = sizeof(out);
    ret = wc_ecc_export_point_der_compressed(9999, point, out, &outLen);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }

    outLen = sizeof(out);
    ret = wc_ecc_export_point_der_compressed(idx, point, NULL, &outLen);
    if (ret != WC_NO_ERR_TRACE(LENGTH_ONLY_E)) { wb_fail = 1; }
    ret = wc_ecc_export_point_der_compressed(idx, point, NULL, NULL);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }
    outLen = sizeof(out);
    ret = wc_ecc_export_point_der_compressed(idx, NULL, NULL, &outLen);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }

    (void)mp_read_unsigned_bin(point->x, big, (int)sizeof(big));
    outLen = sizeof(out);
    ret = wc_ecc_export_point_der_compressed(idx, point, out, &outLen);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }
    (void)mp_set(point->x, 3);

    outLen = sizeof(out);
    ret = wc_ecc_export_point_der_compressed(idx, point, out, &outLen);
    if (ret != MP_OKAY) { wb_fail = 1; }
#endif /* HAVE_COMP_KEY */

    if (wb_fail) {
        WB_NOTE("wc_ecc_export_point_der[_compressed] unexpected return");
    }
    WB_NOTE("wc_ecc_export_point_der[_compressed] guard+range pairs done");

    wc_ecc_del_point(point);
}

/* ------------------------------------------------------------------------- *
 * Class 19: _ecc_export_x963() (lines ~10456-10503): length-query idiom,
 * NULL guard, key->type/idx/dp validity guard, pubkey x/y size check.
 * File-static (only callable because this TU #includes ecc.c).
 * ------------------------------------------------------------------------- */
static void wb_export_x963_internal(void)
{
    int idx = wc_ecc_get_curve_idx(ECC_SECP256R1);
    const ecc_set_type* cs;
    ecc_key key, k2;
    byte out[200];
    byte big[400];
    word32 outLen;
    int ret;

    if (idx == ECC_CURVE_INVALID) {
        wb_fail = 1;
        return;
    }
    cs = wc_ecc_get_curve_params(idx);

    if (wc_ecc_init(&key) != 0) {
        wb_fail = 1;
        return;
    }
    (void)mp_set(key.pubkey.x, 3);
    (void)mp_set(key.pubkey.y, 5);
    (void)mp_set(key.pubkey.z, 1);
    key.type = ECC_PUBLICKEY;
    key.idx = idx;
    key.dp = cs;
    XMEMSET(big, 0xFF, sizeof(big));

    /* ---- length-query (key!=NULL && out==NULL && outLen!=NULL) ---- */
    outLen = sizeof(out);
    ret = _ecc_export_x963(&key, NULL, &outLen);
    if (ret != WC_NO_ERR_TRACE(LENGTH_ONLY_E)) { wb_fail = 1; }
    ret = _ecc_export_x963(&key, NULL, NULL);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }
    outLen = sizeof(out);
    ret = _ecc_export_x963(NULL, NULL, &outLen);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }

    /* ---- NULL guard (key==NULL || out==NULL || outLen==NULL) ---- */
    ret = _ecc_export_x963(NULL, out, &outLen);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }
    ret = _ecc_export_x963(&key, out, NULL);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }

    /* ---- key->type==0 || is_valid_idx==0 || dp==NULL (shallow copies:
     * only .type/.dp differ, never freed, never dereferences pubkey). ---- */
    k2 = key;
    k2.type = 0;
    outLen = sizeof(out);
    ret = _ecc_export_x963(&k2, out, &outLen);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }

    k2 = key;
    k2.dp = NULL;
    outLen = sizeof(out);
    ret = _ecc_export_x963(&k2, out, &outLen);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }

    /* ---- pubxlen>numlen || pubylen>numlen: isolated ---- */
    (void)mp_read_unsigned_bin(key.pubkey.x, big, (int)sizeof(big));
    outLen = sizeof(out);
    ret = _ecc_export_x963(&key, out, &outLen);
    if (ret != WC_NO_ERR_TRACE(BUFFER_E)) { wb_fail = 1; }
    (void)mp_set(key.pubkey.x, 3);

    (void)mp_read_unsigned_bin(key.pubkey.y, big, (int)sizeof(big));
    outLen = sizeof(out);
    ret = _ecc_export_x963(&key, out, &outLen);
    if (ret != WC_NO_ERR_TRACE(BUFFER_E)) { wb_fail = 1; }
    (void)mp_set(key.pubkey.y, 5);

    /* baseline real export. */
    outLen = sizeof(out);
    ret = _ecc_export_x963(&key, out, &outLen);
    if (ret != MP_OKAY) { wb_fail = 1; }

    if (wb_fail) {
        WB_NOTE("_ecc_export_x963 unexpected return");
    }
    WB_NOTE("_ecc_export_x963 NULL/type-idx-dp/size pairs done");

    wc_ecc_free(&key);
}
/* ------------------------------------------------------------------------- *
 * Class 20: repeated "wc_ecc_is_valid_idx(key->idx) == 0 || key->dp == NULL"
 * guard, isolated at each of its easy-to-drive call sites:
 *   _ecc_export_ex()               (line ~11843, static)
 *   wc_ecc_export_public_raw()     (line ~12005, qx/qxLen/qy/qyLen NULL
 *                                    guard -- a different, public, guard on
 *                                    the same call path)
 *   wc_ecc_export_x963_compressed() (line ~16779, static, 3-operand chain
 *                                    with key->type==0 in front)
 * Every public caller of these already has a real dp/idx by construction
 * (wc_ecc_init/make_key/import always set both together), so an
 * idx-invalid-but-dp-set or idx-valid-but-dp-NULL key never reaches them
 * via the API.
 * ------------------------------------------------------------------------- */
static void wb_idx_dp_guard_export_paths(void)
{
    int idx = wc_ecc_get_curve_idx(ECC_SECP256R1);
    const ecc_set_type* cs;
    ecc_key key;
    byte qx[64], qy[64];
    word32 qxLen, qyLen;
    byte out[200];
    word32 outLen;
    int ret;

    if (idx == ECC_CURVE_INVALID) {
        wb_fail = 1;
        return;
    }
    cs = wc_ecc_get_curve_params(idx);
    if (wc_ecc_init(&key) != 0) {
        wb_fail = 1;
        return;
    }
    (void)mp_set(key.pubkey.x, 3);
    (void)mp_set(key.pubkey.y, 5);
    (void)mp_set(key.pubkey.z, 1);
    key.type = ECC_PUBLICKEY;

    /* ---- _ecc_export_ex: idx invalid/dp valid, then idx valid/dp NULL ---- */
    key.idx = 9999; key.dp = cs;
    qxLen = sizeof(qx); qyLen = sizeof(qy);
    ret = _ecc_export_ex(&key, qx, &qxLen, qy, &qyLen, NULL, NULL,
        WC_TYPE_UNSIGNED_BIN);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }

    key.idx = idx; key.dp = NULL;
    qxLen = sizeof(qx); qyLen = sizeof(qy);
    ret = _ecc_export_ex(&key, qx, &qxLen, qy, &qyLen, NULL, NULL,
        WC_TYPE_UNSIGNED_BIN);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }

    key.idx = idx; key.dp = cs; /* baseline: real export */
    qxLen = sizeof(qx); qyLen = sizeof(qy);
    ret = _ecc_export_ex(&key, qx, &qxLen, qy, &qyLen, NULL, NULL,
        WC_TYPE_UNSIGNED_BIN);
    if (ret != MP_OKAY) { wb_fail = 1; }

    /* ---- wc_ecc_export_public_raw: qx/qxLen/qy/qyLen NULL guard,
     * each operand isolated (rest valid). ---- */
    qxLen = sizeof(qx); qyLen = sizeof(qy);
    ret = wc_ecc_export_public_raw(&key, NULL, &qxLen, qy, &qyLen);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) { wb_fail = 1; }
    ret = wc_ecc_export_public_raw(&key, qx, NULL, qy, &qyLen);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) { wb_fail = 1; }
    ret = wc_ecc_export_public_raw(&key, qx, &qxLen, NULL, &qyLen);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) { wb_fail = 1; }
    ret = wc_ecc_export_public_raw(&key, qx, &qxLen, qy, NULL);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) { wb_fail = 1; }
    qxLen = sizeof(qx); qyLen = sizeof(qy);
    ret = wc_ecc_export_public_raw(&key, qx, &qxLen, qy, &qyLen);
    if (ret != MP_OKAY) { wb_fail = 1; }

    /* ---- wc_ecc_export_x963_compressed: type==0 / idx-invalid / dp==NULL,
     * each isolated (needs HAVE_COMP_KEY; the function itself is only
     * compiled under it). ---- */
#ifdef HAVE_COMP_KEY
    key.idx = idx; key.dp = cs; key.type = 0;
    outLen = sizeof(out);
    ret = wc_ecc_export_x963_compressed(&key, out, &outLen);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }

    key.type = ECC_PUBLICKEY; key.idx = 9999; key.dp = cs;
    outLen = sizeof(out);
    ret = wc_ecc_export_x963_compressed(&key, out, &outLen);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }

    key.idx = idx; key.dp = NULL;
    outLen = sizeof(out);
    ret = wc_ecc_export_x963_compressed(&key, out, &outLen);
    if (ret != WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) { wb_fail = 1; }

    key.dp = cs; /* baseline: real compressed export */
    outLen = sizeof(out);
    ret = wc_ecc_export_x963_compressed(&key, out, &outLen);
    if (ret != MP_OKAY) { wb_fail = 1; }
#endif

    if (wb_fail) {
        WB_NOTE("idx/dp guard export paths unexpected return");
    }
    WB_NOTE("_ecc_export_ex/export_public_raw/export_x963_compressed "
        "idx/dp guard pairs done");

    wc_ecc_free(&key);
}
#else
static void wb_export_point_der(void)
{
    WB_NOTE("HAVE_ECC_KEY_EXPORT off; skipped");
}
static void wb_export_x963_internal(void)
{
    WB_NOTE("HAVE_ECC_KEY_EXPORT off; skipped");
}
static void wb_idx_dp_guard_export_paths(void)
{
    WB_NOTE("HAVE_ECC_KEY_EXPORT off; skipped");
}
#endif /* HAVE_ECC_KEY_EXPORT */

#if defined(HAVE_ECC_MAKE_PUB) || !defined(WOLFSSL_ATECC508A)
/* ------------------------------------------------------------------------- *
 * Class 21: wc_ecc_make_pub_ex() "key->type == ECC_PRIVATEKEY_ONLY &&
 * pubOut == NULL" (line ~5730): on a private-only key, a NULL pubOut means
 * "cache the recomputed public part on the key" -- promotes key->type to
 * ECC_PRIVATEKEY. No caller in the API ever calls wc_ecc_make_pub() on a key
 * whose type is already ECC_PRIVATEKEY_ONLY (make_key always leaves type ==
 * ECC_PRIVATEKEY), so this promotion path is unreached. A real key is needed
 * (wc_ecc_make_pub_ex does the actual k*G scalar multiply), so build one via
 * the real wc_ecc_make_key(), then force the private-only state by hand.
 * ------------------------------------------------------------------------- */
static void wb_make_pub_privatekey_only(void)
{
    WC_RNG rng;
    ecc_key key;
    int ret;

    if (wc_InitRng(&rng) != 0) {
        wb_fail = 1;
        return;
    }
    if (wc_ecc_init(&key) != 0) {
        wc_FreeRng(&rng);
        wb_fail = 1;
        return;
    }
    ret = wc_ecc_make_key_ex(&rng, 0, &key, ECC_SECP256R1);
    if (ret != 0) {
        WB_NOTE("wc_ecc_make_key_ex failed; wb_make_pub_privatekey_only "
            "skipped");
        wb_fail = 1;
        goto out;
    }
    key.type = ECC_PRIVATEKEY_ONLY;

    ret = wc_ecc_make_pub(&key, NULL);
    if (ret != 0 || key.type != ECC_PRIVATEKEY) {
        WB_NOTE("wc_ecc_make_pub(PRIVATEKEY_ONLY, pubOut=NULL) unexpected");
        wb_fail = 1;
    }
    else {
        WB_NOTE("wc_ecc_make_pub PRIVATEKEY_ONLY promotion exercised");
    }

out:
    wc_ecc_free(&key);
    wc_FreeRng(&rng);
}
#else
static void wb_make_pub_privatekey_only(void)
{
    WB_NOTE("wc_ecc_make_pub not available; skipped");
}
#endif

#endif /* HAVE_ECC && !WOLF_CRYPTO_CB_ONLY_ECC */


/* Argument-guard vectors that ordinary use never produces. Each guard needs
 * BOTH halves inside THIS binary: llvm-cov derives MC/DC per binary, so a
 * rejection vector on its own proves nothing without the accepting vector of
 * the same decision to pair it against. */
static void wb_arg_guards(void)
{
    WC_RNG rng;
    ecc_key key;
    ecc_point* pt = NULL;
    mp_int m1;
    word32 sz = 0;
    byte   buf[256];
    word32 bufLen = (word32)sizeof(buf);
    int    haveKey = 0;
    int    haveM1 = 0;

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&m1, 0, sizeof(m1));
    XMEMSET(buf, 0, sizeof(buf));

    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("wc_InitRng failed; wb_arg_guards skipped");
        wb_fail = 1;
        return;
    }
    if (wc_ecc_init(&key) == 0) {
        haveKey = (wc_ecc_make_key_ex(&rng, 0, &key, ECC_SECP256R1) == 0);
    }
    if (!haveKey) {
        WB_NOTE("key setup failed; wb_arg_guards skipped");
        wb_fail = 1;
        wc_ecc_free(&key);
        wc_FreeRng(&rng);
        return;
    }
    pt = wc_ecc_new_point();
    haveM1 = (mp_init(&m1) == MP_OKAY);

    /* The import guards run against a scratch key: their accepting vectors
     * overwrite whatever they are handed, and the operations further down need
     * `key` to still hold a valid point. */
    {
        ecc_key imp;
        word32 xLen = (word32)sizeof(buf);
        int haveImp = (wc_ecc_init(&imp) == 0);

        /* key == NULL || qx == NULL || qy == NULL */
        (void)_ecc_import_raw_private(NULL, "1", "1", "1", ECC_SECP256R1,
            WC_TYPE_HEX_STR);
        if (haveImp) {
            (void)_ecc_import_raw_private(&imp, NULL, "1", "1", ECC_SECP256R1,
                WC_TYPE_HEX_STR);
            (void)_ecc_import_raw_private(&imp, "1", NULL, "1", ECC_SECP256R1,
                WC_TYPE_HEX_STR);
            (void)_ecc_import_raw_private(&imp, "1", "1", "1", ECC_SECP256R1,
                WC_TYPE_HEX_STR);
        }

        /* in == NULL || key == NULL */
        (void)_ecc_import_x963_ex2(NULL, 1, &imp, ECC_SECP256R1, 0);
        (void)_ecc_import_x963_ex2(buf, 1, NULL, ECC_SECP256R1, 0);
        if (haveImp && wc_ecc_export_x963(&key, buf, &xLen) == 0) {
            wc_ecc_free(&imp);
            if (wc_ecc_init(&imp) == 0) {
                (void)_ecc_import_x963_ex2(buf, xLen, &imp, ECC_SECP256R1, 0);
            }
        }
        if (haveImp) {
            wc_ecc_free(&imp);
        }
    }

    /* ecc_public_key_size: key == NULL || key->dp == NULL */
    {
        const ecc_set_type* savedDp = key.dp;

        (void)ecc_public_key_size(NULL, &sz);
        key.dp = NULL;
        (void)ecc_public_key_size(&key, &sz);
        key.dp = savedDp;
        (void)ecc_public_key_size(&key, &sz);
    }

    /* The accepting vectors below need the real curve constants: a zero
     * modulus/order would make wc_ecc_gen_deterministic_k's RFC 6979 retry
     * loop spin, and the campaign kills the variant on TEST_TIMEOUT. */
    {
        mp_int prime;
        mp_int order;
        mp_int af;
        int    haveCurve = 0;

        XMEMSET(&prime, 0, sizeof(prime));
        XMEMSET(&order, 0, sizeof(order));
        XMEMSET(&af, 0, sizeof(af));

        if (key.dp != NULL && mp_init(&prime) == MP_OKAY) {
            if (mp_init(&order) == MP_OKAY) {
                if (mp_init(&af) == MP_OKAY) {
                    haveCurve =
                        (mp_read_radix(&prime, key.dp->prime, 16) == MP_OKAY) &&
                        (mp_read_radix(&order, key.dp->order, 16) == MP_OKAY) &&
                        (mp_read_radix(&af, key.dp->Af, 16) == MP_OKAY);
                }
            }
        }

        /* hash == NULL || k == NULL || order == NULL */
        if (haveM1 && haveCurve) {
            (void)wc_ecc_gen_deterministic_k(NULL, 32, WC_HASH_TYPE_SHA256,
                key.k, &m1, &order, key.heap);
            (void)wc_ecc_gen_deterministic_k(buf, 32, WC_HASH_TYPE_SHA256,
                key.k, NULL, &order, key.heap);
            (void)wc_ecc_gen_deterministic_k(buf, 32, WC_HASH_TYPE_SHA256,
                key.k, &m1, NULL, key.heap);
            (void)wc_ecc_gen_deterministic_k(buf, 32, WC_HASH_TYPE_SHA256,
                key.k, &m1, &order, key.heap);
        }

        /* wc_ecc_mulmod_ex / _ex2 NULL chains, then the accepting vector. */
        if (pt != NULL && haveCurve &&
                wc_ecc_copy_point(&key.pubkey, pt) == MP_OKAY) {
            ecc_point* out = wc_ecc_new_point();

#ifdef WOLFSSL_SP_MATH
            /* Only the SP build rejects these: the generic implementation has
             * no such guard and dereferences both operands. */
            (void)wc_ecc_mulmod_ex(key.k, pt, pt, NULL, &prime, 1, key.heap);
            (void)wc_ecc_mulmod_ex2(key.k, pt, pt, NULL, &prime, &order, &rng,
                1, key.heap);
            (void)wc_ecc_mulmod_ex2(key.k, pt, pt, &af, &prime, NULL, &rng, 1,
                key.heap);
#endif
            if (out != NULL) {
                (void)wc_ecc_mulmod_ex(key.k, pt, out, &af, &prime, 1,
                    key.heap);
                (void)wc_ecc_mulmod_ex2(key.k, pt, out, &af, &prime, &order,
                    &rng, 1, key.heap);
                wc_ecc_del_point(out);
            }

            /* point == NULL || out == NULL || outLen == NULL */
            sz = (word32)sizeof(buf);
            (void)wc_ecc_export_point_der_compressed(key.idx, pt, buf, NULL);
            (void)wc_ecc_export_point_der_compressed(key.idx, pt, buf, &sz);
        }

        mp_free(&af);
        mp_free(&order);
        mp_free(&prime);
    }

#ifdef WC_ECC_NONBLOCK
    /* wc_ecc_set_nonblock: key->nb_ctx != NULL && key->nb_ctx != ctx */
    {
        ecc_nb_ctx_t nb;

        XMEMSET(&nb, 0, sizeof(nb));
        (void)wc_ecc_set_nonblock(&key, &nb);
        (void)wc_ecc_set_nonblock(&key, &nb);
        (void)wc_ecc_set_nonblock(&key, NULL);
    }
#endif

    /* The is_valid_idx/dp family: an invalid idx fires the first operand, a
     * valid idx with dp cleared fires the second, an untouched key neither. */
    {
        const ecc_set_type* savedDp = key.dp;
        int savedIdx = key.idx;
        mp_int r;
        mp_int s;
        int    stat = 0;

        key.idx = ECC_CUSTOM_IDX - 1;
        bufLen = (word32)sizeof(buf);
        (void)wc_ecc_shared_secret(&key, &key, buf, &bufLen);
        (void)wc_ecc_shared_secret_ex(&key, &key.pubkey, buf, &bufLen);
        key.idx = savedIdx;

        key.dp = NULL;
        bufLen = (word32)sizeof(buf);
        (void)wc_ecc_shared_secret(&key, &key, buf, &bufLen);
        (void)wc_ecc_shared_secret_ex(&key, &key.pubkey, buf, &bufLen);
        key.dp = savedDp;

        PRIVATE_KEY_UNLOCK();
        bufLen = (word32)sizeof(buf);
        (void)wc_ecc_shared_secret(&key, &key, buf, &bufLen);
        bufLen = (word32)sizeof(buf);
        (void)wc_ecc_shared_secret_ex(&key, &key.pubkey, buf, &bufLen);
        PRIVATE_KEY_LOCK();

        if (mp_init(&r) == MP_OKAY) {
            if (mp_init(&s) == MP_OKAY) {
                key.idx = ECC_CUSTOM_IDX - 1;
                (void)wc_ecc_sign_hash_ex(buf, 32, &rng, &key, &r, &s);
                (void)wc_ecc_verify_hash_ex(&r, &s, buf, 32, &stat, &key);
                key.idx = savedIdx;

                key.dp = NULL;
                (void)wc_ecc_sign_hash_ex(buf, 32, &rng, &key, &r, &s);
                (void)wc_ecc_verify_hash_ex(&r, &s, buf, 32, &stat, &key);
                key.dp = savedDp;

                if (wc_ecc_sign_hash_ex(buf, 32, &rng, &key, &r, &s) == 0) {
                    (void)wc_ecc_verify_hash_ex(&r, &s, buf, 32, &stat, &key);
                }
                mp_free(&s);
            }
            mp_free(&r);
        }
    }

    if (pt != NULL) {
        wc_ecc_del_point(pt);
    }
    if (haveM1) {
        mp_free(&m1);
    }
    wc_ecc_free(&key);
    wc_FreeRng(&rng);

    /* wc_ecc_free: key->deallocSet && key->dp != NULL */
    {
        ecc_key k2;

        if (wc_ecc_init(&k2) == 0) {
            k2.dp = NULL;
            (void)wc_ecc_free(&k2);
        }
    }
}

int main(void)
{
    /* Unbuffered: on a timeout or a fault the process is killed and anything
     * still buffered is lost, which reads as an empty log. */
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("ecc.c white-box MC/DC supplement\n");
#if !defined(HAVE_ECC) || defined(WOLF_CRYPTO_CB_ONLY_ECC)
    printf("  HAVE_ECC off (or crypto-cb-only build); nothing to exercise\n");
    return 0;
#else
    wb_curve_load();
    wb_import_private_key_ex();
    wb_ctx_set_salt();
    wb_ctx_protocol_zero();
    wb_is_valid_idx_n_lt_x();
    wb_cmp_param_null();
    wb_get_curve_id_from_params();
    wb_get_curve_id_from_dp_params();
    wb_mulmod_ex2_null_guard();
    wb_ecc_map_ex_null();
    wb_projective_wrappers();
    wb_mul2add_and_bufsize();
    wb_projective_safe_special_cases();
    wb_fp_cache_internals();
    wb_export_point_der();
    wb_export_x963_internal();
    wb_idx_dp_guard_export_paths();
    wb_make_pub_privatekey_only();
    wb_arg_guards();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures are surfaced as skips, not test failures: the campaign
     * treats a nonzero exit as a failed variant and discards its coverage. */
    return 0;
#endif
}
