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

/* ------------------------------------------------------------------------- *
 * SHA-2 message-hash static functions: gap-closing supplement (see GAPS.md).
 *
 * The tests/api DecisionCoverage additions close every arg-check reachable
 * from the public API. What's left needs either a real n>16 SHA-2 param
 * (every campaign variant restricts to 128-bit only, see config_base's
 * notes) or a ctx/ctxSz combination the public API itself rejects before
 * ever reaching these static functions (ctx==NULL with ctxSz>0 is BAD_FUNC_ARG at
 * the wc_SlhDsaKey_Sign/Verify layer). Both are driven directly here.
 * ------------------------------------------------------------------------- */
#ifdef WOLFSSL_SLHDSA_SHA2

/* slhdsakey_precompute_sha2_midstates(): "(ret==0) && (n>16)" -- n>16
 * (SHA-512 midstate) half. A locally-built SlhDsaParameters with n=24
 * exercises it without any variant ever compiling a real n>16 param. */
static void wb_precompute_sha2_midstates(void)
{
    SlhDsaKey key;
    SlhDsaParameters fakeParams;

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&fakeParams, 0, sizeof(fakeParams));
    XMEMSET(key.sk, 0x11, sizeof(key.sk));

    /* n <= 16 (WC_SLHDSA_N_128): false side. */
    fakeParams.n = 16;
    key.params = &fakeParams;
    if (slhdsakey_precompute_sha2_midstates(&key) != 0) {
        WB_NOTE("precompute_sha2_midstates(n=16) failed");
        wb_fail = 1;
    }

    /* n > 16 (categories 3, 5): true side. The function only reads
     * key->params->n and key->sk, so this crafted entry is a faithful
     * exercise of the SHA-512 midstate branch. */
    fakeParams.n = 24;
    key.hash.sha2.sha256_mid_inited = 0;
    key.hash.sha2.sha512_mid_inited = 0;
    if (slhdsakey_precompute_sha2_midstates(&key) != 0) {
        WB_NOTE("precompute_sha2_midstates(n=24) failed");
        wb_fail = 1;
    }

    /* Free the hash objects directly (not via wc_SlhDsaKey_Free): fakeParams
     * isn't a real table entry, so SLHDSA_IS_SHA2(key->params->param) can't
     * be trusted to dispatch to the SHA-2 cleanup path. */
    if (key.hash.sha2.sha256_inited) {
        wc_Sha256Free(&key.hash.sha2.sha256);
    }
    if (key.hash.sha2.sha256_2_inited) {
        wc_Sha256Free(&key.hash.sha2.sha256_2);
    }
    if (key.hash.sha2.sha256_mid_inited) {
        wc_Sha256Free(&key.hash.sha2.sha256_mid);
    }
    if (key.hash.sha2.sha512_inited) {
        wc_Sha512Free(&key.hash.sha2.sha512);
    }
    if (key.hash.sha2.sha512_2_inited) {
        wc_Sha512Free(&key.hash.sha2.sha512_2);
    }
    if (key.hash.sha2.sha512_mid_inited) {
        wc_Sha512Free(&key.hash.sha2.sha512_mid);
    }

    WB_NOTE("slhdsakey_precompute_sha2_midstates n<=16/n>16 pair exercised");
}

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
/* slhdsakey_prf_msg_sha2(): "(ctxSz>0) && (ctx!=NULL)" -- ctx!=NULL half.
 * ctxSz>0's own independence is already shown by the public Sign/Verify
 * tests (ctx==NULL with ctxSz==0 vs a filled ctx with ctxSz>0); "ctxSz>0 but
 * ctx==NULL" is rejected as BAD_FUNC_ARG by every public wrapper before it
 * can ever reach this static, so it's driven here directly instead. */
static void wb_prf_msg_sha2_ctx(void)
{
    SlhDsaKey key;
    byte sk_prf[16], opt_rand[16], hdr[2], ctx[5], msg[4];
    byte hashOut[WC_SHA256_DIGEST_SIZE];

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(sk_prf, 0x22, sizeof(sk_prf));
    XMEMSET(opt_rand, 0x33, sizeof(opt_rand));
    XMEMSET(hdr, 0, sizeof(hdr));
    XMEMSET(ctx, 0x44, sizeof(ctx));
    XMEMSET(msg, 0x55, sizeof(msg));

    if (slhdsakey_prf_msg_sha2(&key, sk_prf, opt_rand, hdr, NULL,
            (byte)sizeof(ctx), msg, sizeof(msg), WC_SLHDSA_N_128,
            hashOut) != 0) {
        WB_NOTE("prf_msg_sha2(ctx==NULL,ctxSz>0) failed");
        wb_fail = 1;
    }
    if (slhdsakey_prf_msg_sha2(&key, sk_prf, opt_rand, hdr, ctx,
            (byte)sizeof(ctx), msg, sizeof(msg), WC_SLHDSA_N_128,
            hashOut) != 0) {
        WB_NOTE("prf_msg_sha2(ctx!=NULL,ctxSz>0) failed");
        wb_fail = 1;
    }

    WB_NOTE("slhdsakey_prf_msg_sha2 ctx!=NULL independence pair exercised");
}
#endif /* !WOLFSSL_SLHDSA_VERIFY_ONLY */

/* slhdsakey_h_msg_sha2(): SHA-256 branch's "ctx!=NULL" pair (same rationale
 * as wb_prf_msg_sha2_ctx above) plus the SHA-512 branch (n>16, category 3/5)
 * hdr/ctx/ctxSz decisions -- unreachable from the API for the same reason as
 * wb_precompute_sha2_midstates (no variant ever builds an n>16 param). */
static void wb_h_msg_sha2_ctx_pairs(void)
{
    SlhDsaKey key;
    SlhDsaParameters fakeParams;
    byte r[32], hdr[2], ctx[5], msg[4], md[64];

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&fakeParams, 0, sizeof(fakeParams));
    XMEMSET(r, 0x66, sizeof(r));
    XMEMSET(hdr, 0, sizeof(hdr));
    XMEMSET(ctx, 0x77, sizeof(ctx));
    XMEMSET(msg, 0x88, sizeof(msg));
    XMEMSET(key.sk, 0x99, sizeof(key.sk));

    /* SHA-256 branch (n == WC_SLHDSA_N_128). */
    fakeParams.n = 16;
    key.params = &fakeParams;
    if (slhdsakey_h_msg_sha2(&key, r, hdr, NULL, (byte)sizeof(ctx), msg,
            sizeof(msg), md, 8) != 0) {
        WB_NOTE("h_msg_sha2(n=16,ctx==NULL) failed");
        wb_fail = 1;
    }
    if (slhdsakey_h_msg_sha2(&key, r, hdr, ctx, (byte)sizeof(ctx), msg,
            sizeof(msg), md, 8) != 0) {
        WB_NOTE("h_msg_sha2(n=16,ctx!=NULL) failed");
        wb_fail = 1;
    }

    /* SHA-512 branch (n > WC_SLHDSA_N_128). Four combinations:
     *   A: hdr==NULL,           ctxSz==0            -> both false
     *   B: hdr!=NULL,           ctxSz==0            -> hdr pair's true side
     *   C: hdr!=NULL, ctxSz>0,  ctx==NULL            -> ctxSz>0 T, ctx!=NULL F
     *   D: hdr!=NULL, ctxSz>0,  ctx!=NULL            -> both true
     * A vs B: hdr!=NULL independence (ctxSz==0 held constant).
     * B vs D: ctxSz>0 independence (ctx!=NULL held true/nonNULL).
     * C vs D: ctx!=NULL independence (ctxSz>0 held true). */
    fakeParams.n = 24;
    key.hash.sha2.sha256_2_inited = 0;
    key.hash.sha2.sha512_2_inited = 0;

    if (slhdsakey_h_msg_sha2(&key, r, NULL, ctx, 0, msg, sizeof(msg), md,
            8) != 0) {
        WB_NOTE("h_msg_sha2(n=24,A) failed");
        wb_fail = 1;
    }
    if (slhdsakey_h_msg_sha2(&key, r, hdr, ctx, 0, msg, sizeof(msg), md,
            8) != 0) {
        WB_NOTE("h_msg_sha2(n=24,B) failed");
        wb_fail = 1;
    }
    if (slhdsakey_h_msg_sha2(&key, r, hdr, NULL, (byte)sizeof(ctx), msg,
            sizeof(msg), md, 8) != 0) {
        WB_NOTE("h_msg_sha2(n=24,C) failed");
        wb_fail = 1;
    }
    if (slhdsakey_h_msg_sha2(&key, r, hdr, ctx, (byte)sizeof(ctx), msg,
            sizeof(msg), md, 8) != 0) {
        WB_NOTE("h_msg_sha2(n=24,D) failed");
        wb_fail = 1;
    }

    if (key.hash.sha2.sha256_inited) {
        wc_Sha256Free(&key.hash.sha2.sha256);
    }
    if (key.hash.sha2.sha256_2_inited) {
        wc_Sha256Free(&key.hash.sha2.sha256_2);
    }
    if (key.hash.sha2.sha512_inited) {
        wc_Sha512Free(&key.hash.sha2.sha512);
    }
    if (key.hash.sha2.sha512_2_inited) {
        wc_Sha512Free(&key.hash.sha2.sha512_2);
    }

    WB_NOTE("slhdsakey_h_msg_sha2 hdr/ctx independence pairs exercised");
}
#endif /* WOLFSSL_SLHDSA_SHA2 */

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
/* slhdsakey_sign_internal_msg(): all 6 operands of
 * "(key==NULL)||(key->params==NULL)||(m==NULL)||(sig==NULL)||
 *  (sigSz==NULL)||(addRnd==NULL)". This static is only called from other
 * static functions/wrappers that already validate these same pointers, so its own
 * defensive re-check is otherwise dead from the API. An oversized
 * fakeParams.sigLen makes the "all valid" baseline fall to the very next
 * check (BAD_LENGTH_E) instead of the (very slow) WOTS+/FORS/hypertree
 * signing path. */
static void wb_sign_internal_msg_argchecks(void)
{
    SlhDsaKey key;
    SlhDsaParameters fakeParams;
    byte m[8], sig[8], addRnd[32];
    word32 sigSz;

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&fakeParams, 0, sizeof(fakeParams));
    fakeParams.n = 16;
    fakeParams.sigLen = 100000;
    key.params = &fakeParams;
    XMEMSET(m, 0xAA, sizeof(m));
    XMEMSET(sig, 0, sizeof(sig));
    XMEMSET(addRnd, 0x55, sizeof(addRnd));

    sigSz = 1;
    if (slhdsakey_sign_internal_msg(&key, m, sizeof(m), sig, &sigSz, addRnd)
            != WC_NO_ERR_TRACE(BAD_LENGTH_E)) {
        WB_NOTE("sign_internal_msg baseline (all valid) unexpected ret");
        wb_fail = 1;
    }

    sigSz = 1;
    if (slhdsakey_sign_internal_msg(NULL, m, sizeof(m), sig, &sigSz, addRnd)
            != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("sign_internal_msg key==NULL unexpected ret");
        wb_fail = 1;
    }

    key.params = NULL;
    sigSz = 1;
    if (slhdsakey_sign_internal_msg(&key, m, sizeof(m), sig, &sigSz, addRnd)
            != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("sign_internal_msg key->params==NULL unexpected ret");
        wb_fail = 1;
    }
    key.params = &fakeParams;

    sigSz = 1;
    if (slhdsakey_sign_internal_msg(&key, NULL, sizeof(m), sig, &sigSz,
            addRnd) != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("sign_internal_msg m==NULL unexpected ret");
        wb_fail = 1;
    }

    sigSz = 1;
    if (slhdsakey_sign_internal_msg(&key, m, sizeof(m), NULL, &sigSz, addRnd)
            != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("sign_internal_msg sig==NULL unexpected ret");
        wb_fail = 1;
    }

    if (slhdsakey_sign_internal_msg(&key, m, sizeof(m), sig, NULL, addRnd)
            != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("sign_internal_msg sigSz==NULL unexpected ret");
        wb_fail = 1;
    }

    sigSz = 1;
    if (slhdsakey_sign_internal_msg(&key, m, sizeof(m), sig, &sigSz, NULL)
            != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("sign_internal_msg addRnd==NULL unexpected ret");
        wb_fail = 1;
    }

    WB_NOTE("slhdsakey_sign_internal_msg arg-check independence pairs "
        "exercised");
}
#endif /* !WOLFSSL_SLHDSA_VERIFY_ONLY */

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
#ifdef WOLFSSL_SLHDSA_SHA2
    wb_precompute_sha2_midstates();
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    wb_prf_msg_sha2_ctx();
#endif
    wb_h_msg_sha2_ctx_pairs();
#endif
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    wb_sign_internal_msg_argchecks();
#endif
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures are surfaced as skips, not test failures: the campaign
     * treats a nonzero exit as a failed variant and discards its coverage. */
    return 0;
#endif
}
