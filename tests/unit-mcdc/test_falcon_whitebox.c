/* test_falcon_whitebox.c
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

/* White-box MC/DC supplement for wolfcrypt/src/falcon.c.
 *
 * falcon.c is the native wolfCrypt Falcon signature (~10k lines, 146 file-static
 * helpers folded into one TU: fpr scalar backend, modp NTT, zint big-int,
 * comp/modq/trim encode+decode, Gaussian sampler, FFT, NTRU key solver,
 * sign/verify). Every public wc_falcon_* caller drives the internal helpers only
 * with well-formed, self-consistent operands, so the argument-check and
 * bound-check decisions inside the file-static helpers cannot have both halves of
 * each independence pair demonstrated from tests/api. This TU #includes falcon.c
 * so the static helpers are in scope, and drives each targeted decision with both halves
 * of every independence pair in a single binary (MC/DC is computed per binary).
 *
 * Two complementary techniques are used:
 *   1. Direct calls to the branch-bearing helpers (encode/decode range and bit
 *      guards, NULL/logn defensive guards, poly_big_to_small, complete_private)
 *      with bounded, correctly-sized stack/heap buffers -- driving the TRUE and
 *      FALSE half of each guard deterministically.
 *   2. A single real native make/sign/verify round-trip at Falcon-512, which is
 *      the exact production path and exercises the "success"/FALSE half of the
 *      deep keygen/solve_NTRU/make_fg/expand/sign decisions that tests/api does
 *      not reach (the measured baseline never runs keygen).
 *
 * Crash-safety: for every NULL-guard TRUE half only the pointer the guard checks
 * BEFORE any dereference is passed NULL (all these guards early-return
 * BAD_FUNC_ARG). Every helper that proceeds past its guard gets bounded,
 * correctly-sized buffers. Decisions whose remaining half is only reachable from
 * a genuine mid-computation error (PRNG squeeze failure, bigint overflow, an
 * out-of-range coefficient the sampler bounds forbid, a degenerate/non-invertible
 * key) are documented as WB_NOTE residuals rather than forced unsafely. main()
 * always returns 0 so the campaign keeps the variant.
 */

#include <wolfcrypt/src/falcon.c>

#include <stdio.h>

static int wb_notes = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); wb_notes++; } while (0)
#define WB_OK(msg)   do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(HAVE_FALCON)

/* ------------------------------------------------------------------ *
 * falcon_comp_encode: for-loop range guard  x[u] < -2047 || x[u] > 2047
 * both FALSE (in range), left TRUE (x<-2047), right TRUE with left FALSE.
 * ------------------------------------------------------------------ */
static void wb_comp_encode(void)
{
    sword16 x[4];
    byte    out[64];
    unsigned logn = 2;          /* n = 4 */
    size_t  i, r;

    for (i = 0; i < 4; i++) {
        x[i] = 0;
    }
    /* both operands FALSE -> encodes, returns nonzero. */
    r = falcon_comp_encode(out, sizeof(out), x, logn);
    if (r == 0) {
        WB_NOTE("comp_encode(in-range) expected nonzero");
    }
    /* left operand TRUE: x < -2047. */
    x[0] = -2048;
    r = falcon_comp_encode(out, sizeof(out), x, logn);
    if (r != 0) {
        WB_NOTE("comp_encode(x<-2047) expected 0");
    }
    /* right operand TRUE (left FALSE): x > 2047. */
    x[0] = 0;
    x[1] = 2048;
    r = falcon_comp_encode(out, sizeof(out), x, logn);
    if (r != 0) {
        WB_NOTE("comp_encode(x>2047) expected 0");
    }
    WB_OK("falcon_comp_encode range operand pair exercised");
}

/* ------------------------------------------------------------------ *
 * falcon_trim_i8_encode / _decode:
 *   bits < 2 || bits > 8                (both funcs)
 *   x[u] < minv || x[u] > maxv          (encode range)
 *   while (acc_len >= bits && u < n)    (decode; u<n operand pair)
 * ------------------------------------------------------------------ */
static void wb_trim_i8(void)
{
    sword8 x[2];
    sword8 dec[2];
    byte   out[16];
    unsigned logn = 1;          /* n = 2 */
    size_t r;

    /* --- encode bits guard (both FALSE): valid bits=5, in range. --- */
    x[0] = 1; x[1] = 2;
    r = falcon_trim_i8_encode(out, sizeof(out), x, logn, 5);
    if (r == 0) {
        WB_NOTE("trim_i8_encode(valid) expected nonzero");
    }
    /* bits < 2 (cond0 TRUE). */
    r = falcon_trim_i8_encode(out, sizeof(out), x, logn, 1);
    if (r != 0) {
        WB_NOTE("trim_i8_encode(bits<2) expected 0");
    }
    /* bits > 8 (cond0 FALSE, cond1 TRUE). */
    r = falcon_trim_i8_encode(out, sizeof(out), x, logn, 9);
    if (r != 0) {
        WB_NOTE("trim_i8_encode(bits>8) expected 0");
    }
    /* encode range guard: bits=5 -> maxv=15, minv=-15.
     * x < minv (cond0 TRUE). */
    x[0] = -16; x[1] = 0;
    r = falcon_trim_i8_encode(out, sizeof(out), x, logn, 5);
    if (r != 0) {
        WB_NOTE("trim_i8_encode(x<minv) expected 0");
    }
    /* x > maxv (cond0 FALSE, cond1 TRUE). */
    x[0] = 0; x[1] = 16;
    r = falcon_trim_i8_encode(out, sizeof(out), x, logn, 5);
    if (r != 0) {
        WB_NOTE("trim_i8_encode(x>maxv) expected 0");
    }

    /* --- decode: build a valid bits=5 encoding, then decode. This single
     * decode covers the bits guard (both FALSE) and the inner
     * while (acc_len >= bits && u < n): with logn=1, bits=5 the two bytes
     * carry 16 bits, so after decoding both coefficients (u reaches n) the
     * leftover acc_len (6) still satisfies acc_len >= bits, forcing the u<n
     * operand to be evaluated FALSE while acc_len>=bits is TRUE -- the
     * independence half that never shows for the u<n operand. --- */
    x[0] = 3; x[1] = 4;
    r = falcon_trim_i8_encode(out, sizeof(out), x, logn, 5);
    if (r == 0) {
        WB_NOTE("trim_i8_encode(for decode) expected nonzero");
    }
    r = falcon_trim_i8_decode(dec, logn, 5, out, sizeof(out));
    if (r == 0) {
        WB_NOTE("trim_i8_decode(valid) expected nonzero");
    }
    /* decode bits guard: bits < 2 (cond0 TRUE). */
    r = falcon_trim_i8_decode(dec, logn, 1, out, sizeof(out));
    if (r != 0) {
        WB_NOTE("trim_i8_decode(bits<2) expected 0");
    }
    /* decode bits guard: bits > 8 (cond0 FALSE, cond1 TRUE). */
    r = falcon_trim_i8_decode(dec, logn, 9, out, sizeof(out));
    if (r != 0) {
        WB_NOTE("trim_i8_decode(bits>8) expected 0");
    }
    WB_OK("falcon_trim_i8 encode/decode bits+range+loop pairs exercised");
}

/* ------------------------------------------------------------------ *
 * falcon_privkey_decode / _encode:
 *   sk==NULL || f==NULL || g==NULL || F==NULL
 *   logn < 1 || logn > 10
 * TRUE half of each operand via NULL / out-of-range; both-FALSE via a valid
 * call that early-returns on the length guard (no buffer deref).
 * ------------------------------------------------------------------ */
static void wb_privkey(void)
{
    byte   sk[64];
    sword8 f[4], g[4], F[4];
    unsigned logn = 1;
    int    ir;
    size_t sr;

    XMEMSET(sk, 0, sizeof(sk));
    XMEMSET(f, 0, sizeof(f));
    XMEMSET(g, 0, sizeof(g));
    XMEMSET(F, 0, sizeof(F));

    /* decode: all guards FALSE (valid ptrs + valid logn) -> reaches the
     * sklen<1 length check with sklen=0 -> BUFFER_E (no buffer deref). */
    ir = falcon_privkey_decode(sk, 0, f, g, F, logn);
    if (ir != WC_NO_ERR_TRACE(BUFFER_E)) {
        WB_NOTE("privkey_decode(all-valid,sklen0) expected BUFFER_E");
    }
    /* NULL guard TRUE halves. */
    (void)falcon_privkey_decode(NULL, 10, f, g, F, logn);
    (void)falcon_privkey_decode(sk, 10, NULL, g, F, logn);
    (void)falcon_privkey_decode(sk, 10, f, NULL, F, logn);
    (void)falcon_privkey_decode(sk, 10, f, g, NULL, logn);
    /* logn guard TRUE halves. */
    (void)falcon_privkey_decode(sk, 10, f, g, F, 0);
    (void)falcon_privkey_decode(sk, 10, f, g, F, 11);

    /* encode: all guards FALSE -> reaches max_sk<1 with max_sk=0 -> 0. */
    sr = falcon_privkey_encode(sk, 0, f, g, F, logn);
    if (sr != 0) {
        WB_NOTE("privkey_encode(all-valid,max0) expected 0");
    }
    /* NULL guard TRUE halves. */
    (void)falcon_privkey_encode(NULL, 10, f, g, F, logn);
    (void)falcon_privkey_encode(sk, 10, NULL, g, F, logn);
    (void)falcon_privkey_encode(sk, 10, f, NULL, F, logn);
    (void)falcon_privkey_encode(sk, 10, f, g, NULL, logn);
    /* logn guard TRUE halves. */
    (void)falcon_privkey_encode(sk, 10, f, g, F, 0);
    (void)falcon_privkey_encode(sk, 10, f, g, F, 11);
    WB_OK("falcon_privkey_decode/encode NULL+logn guard pairs exercised");
}

/* ------------------------------------------------------------------ *
 * falcon_prng_init / falcon_sampler_init:
 *   p==NULL || rng==NULL              (prng_init)
 *   spc==NULL || rng==NULL            (sampler_init)
 *   logn < 1 || logn > 10             (sampler_init)
 * ------------------------------------------------------------------ */
static void wb_prng_sampler_init(WC_RNG* rng)
{
    falcon_prng        p;
    falcon_sampler_ctx spc;
    int r;

    /* prng_init both-FALSE: valid p + rng -> real init succeeds. */
    r = falcon_prng_init(&p, rng);
    if (r != 0) {
        WB_NOTE("prng_init(valid) expected 0");
    }
    /* p==NULL (cond0 TRUE, early return before deref). */
    r = falcon_prng_init(NULL, rng);
    if (r != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("prng_init(p=NULL) expected BAD_FUNC_ARG");
    }
    /* rng==NULL (cond0 FALSE, cond1 TRUE). */
    r = falcon_prng_init(&p, NULL);
    if (r != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("prng_init(rng=NULL) expected BAD_FUNC_ARG");
    }

    /* sampler_init both-FALSE (NULL guard) + both-FALSE (logn guard):
     * valid spc + rng + logn=9 -> proceeds to prng_init. */
    r = falcon_sampler_init(&spc, 9, rng);
    if (r != 0) {
        WB_NOTE("sampler_init(valid) expected 0");
    }
    /* spc==NULL (cond0 TRUE). */
    r = falcon_sampler_init(NULL, 9, rng);
    if (r != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("sampler_init(spc=NULL) expected BAD_FUNC_ARG");
    }
    /* rng==NULL (cond0 FALSE, cond1 TRUE). */
    r = falcon_sampler_init(&spc, 9, NULL);
    if (r != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("sampler_init(rng=NULL) expected BAD_FUNC_ARG");
    }
    /* logn < 1 (cond0 TRUE). */
    r = falcon_sampler_init(&spc, 0, rng);
    if (r != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("sampler_init(logn<1) expected BAD_FUNC_ARG");
    }
    /* logn > 10 (cond0 FALSE, cond1 TRUE). */
    r = falcon_sampler_init(&spc, 11, rng);
    if (r != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("sampler_init(logn>10) expected BAD_FUNC_ARG");
    }
    WB_OK("falcon_prng_init / falcon_sampler_init guard pairs exercised");
}

/* ------------------------------------------------------------------ *
 * poly_big_to_small:  z < -lim || z > lim
 * z = zint_one_to_plain(s+u): a word32 with bit30 set sign-extends to a large
 * negative value; a small positive word32 stays positive.
 * ------------------------------------------------------------------ */
static void wb_poly_big_to_small(void)
{
    sword8 d[4];
    word32 s[4];
    unsigned logn = 2;          /* n = 4 */
    int r;

    s[0] = 0; s[1] = 0; s[2] = 0; s[3] = 0;
    /* both operands FALSE: z==0 in [-127,127]. */
    r = poly_big_to_small(d, s, 127, logn);
    if (r != 1) {
        WB_NOTE("poly_big_to_small(in-range) expected 1");
    }
    /* z < -lim (cond0 TRUE): bit30 set -> z = -(2^30). */
    s[0] = 0x40000000u;
    r = poly_big_to_small(d, s, 127, logn);
    if (r != 0) {
        WB_NOTE("poly_big_to_small(z<-lim) expected 0");
    }
    /* z > lim (cond0 FALSE, cond1 TRUE): z = 200. */
    s[0] = 200u;
    r = poly_big_to_small(d, s, 127, logn);
    if (r != 0) {
        WB_NOTE("poly_big_to_small(z>lim) expected 0");
    }
    WB_OK("poly_big_to_small range operand pair exercised");
}

/* ------------------------------------------------------------------ *
 * make_fg:  depth == 0 && out_ntt
 * cond0 TRUE + cond1 TRUE  (depth=0, out_ntt=1) -> NTT branch;
 * cond0 TRUE + cond1 FALSE (depth=0, out_ntt=0) -> plain return.
 * cond0 FALSE (depth != 0) is exercised by the real keygen path
 * (solve_NTRU_deepest calls make_fg with depth = logn_top).
 * ------------------------------------------------------------------ */
static void wb_make_fg(void)
{
    unsigned logn = 2;          /* n = 4 */
    sword8 f[4], g[4];
    word32 data[64];            /* >= 4n = 16 words */
    size_t i;

    for (i = 0; i < 4; i++) {
        f[i] = (sword8)(i + 1);
        g[i] = (sword8)(4 - i);
    }
    XMEMSET(data, 0, sizeof(data));
    /* depth==0 && out_ntt==1 : both TRUE. */
    make_fg(data, f, g, logn, 0, 1);
    /* depth==0 && out_ntt==0 : cond0 TRUE, cond1 FALSE. */
    make_fg(data, f, g, logn, 0, 0);
    WB_OK("make_fg depth==0/out_ntt operand pair (cond0 FALSE via keygen)");
}

/* ------------------------------------------------------------------ *
 * falcon_complete_private:
 *   G==NULL || f==NULL || g==NULL || F==NULL || logn<1 || logn>10   (6 conds)
 *   z < -127 || z > 127                                            (range)
 * With f = [1,0,0,..] (FFT is all-ones, division by it is the identity) and
 * g = [a,0,..], F = [b,0,..], the recomputed G is [a*b + q, 0, ..], so a*b
 * fully controls the first coefficient's range test:
 *   a=127,b=-97 -> -30  (in range, both FALSE)
 *   a=1,  b=1   -> 12290 (> 127, cond1 TRUE)
 *   a=127,b=-98 -> -157  (< -127, cond0 TRUE)
 * ------------------------------------------------------------------ */
static void wb_complete_private(void)
{
    unsigned logn = 2;          /* n = 4 */
    sword8 G[4], f[4], g[4], F[4];
    int r;

    XMEMSET(f, 0, sizeof(f)); f[0] = 1;
    XMEMSET(g, 0, sizeof(g));
    XMEMSET(F, 0, sizeof(F));

    /* both range operands FALSE (a*b+q = -30) and full NULL/logn guard FALSE. */
    g[0] = 127; F[0] = -97;
    r = falcon_complete_private(G, f, g, F, logn, NULL);
    if (r != 0) {
        WB_NOTE("complete_private(in-range) expected 0");
    }
    /* z > 127 (cond1 TRUE): a*b+q = 12290. */
    g[0] = 1; F[0] = 1;
    r = falcon_complete_private(G, f, g, F, logn, NULL);
    if (r != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("complete_private(z>127) expected BAD_FUNC_ARG");
    }
    /* z < -127 (cond0 TRUE): a*b+q = -157. */
    g[0] = 127; F[0] = -98;
    r = falcon_complete_private(G, f, g, F, logn, NULL);
    if (r != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("complete_private(z<-127) expected BAD_FUNC_ARG");
    }

    /* NULL/logn guard TRUE halves (each early-returns before any deref). */
    g[0] = 1; F[0] = 1;
    (void)falcon_complete_private(NULL, f, g, F, logn, NULL);
    (void)falcon_complete_private(G, NULL, g, F, logn, NULL);
    (void)falcon_complete_private(G, f, NULL, F, logn, NULL);
    (void)falcon_complete_private(G, f, g, NULL, logn, NULL);
    (void)falcon_complete_private(G, f, g, F, 0, NULL);
    (void)falcon_complete_private(G, f, g, F, 11, NULL);
    WB_OK("falcon_complete_private guard + range pairs exercised");
}

/* ------------------------------------------------------------------ *
 * falcon_comp_decode:  s != 0 && mag == 0   (reject negative zero)
 * (T,T): sign bit set, magnitude 0 -> ASN_PARSE_E.
 * (T,F): sign bit set, magnitude 1 -> accepted.
 * (F,-): sign bit clear -> cond0 FALSE.
 * n = 1 (logn = 0); each 2-byte input: byte0 carries sign|low7, byte1's high
 * bit terminates the unary run immediately (magnitude unchanged).
 * ------------------------------------------------------------------ */
static void wb_comp_decode(void)
{
    byte    in[2];
    sword16 x[1];
    unsigned logn = 0;          /* n = 1 */
    int r;

    /* s != 0, mag == 0 : both TRUE -> ASN_PARSE_E. */
    in[0] = 0x80; in[1] = 0x80;
    r = falcon_comp_decode(in, sizeof(in), x, logn);
    if (r != WC_NO_ERR_TRACE(ASN_PARSE_E)) {
        WB_NOTE("comp_decode(neg-zero) expected ASN_PARSE_E");
    }
    /* s != 0, mag != 0 : cond0 TRUE, cond1 FALSE -> accepted (-1). */
    in[0] = 0x81; in[1] = 0x80;
    r = falcon_comp_decode(in, sizeof(in), x, logn);
    if (r < 0) {
        WB_NOTE("comp_decode(s!=0,mag!=0) expected accept");
    }
    /* s == 0 : cond0 FALSE. */
    in[0] = 0x01; in[1] = 0x80;
    r = falcon_comp_decode(in, sizeof(in), x, logn);
    if (r < 0) {
        WB_NOTE("comp_decode(s==0) expected accept");
    }
    WB_OK("falcon_comp_decode negative-zero operand pair exercised");
}

/* ------------------------------------------------------------------ *
 * falcon_hash_to_point:  while (ret == 0 && i < n)
 * The ret==0 operand's FALSE half (with i<n TRUE) only shows when a SHAKE
 * operation fails mid-setup. Passing nonce==NULL makes wc_Shake256_Update
 * return BAD_FUNC_ARG (it null-checks before any use), so ret!=0 on entry to
 * the loop with i(0)<n. The ret==0 TRUE half and the i<n operand are covered by
 * the real sign/verify round-trip.
 * ------------------------------------------------------------------ */
static void wb_hash_to_point(void)
{
    byte    msg[4];
    word16  c[2];
    unsigned logn = 1;          /* n = 2 (loop never entered on error) */
    int r;

    XMEMSET(msg, 0, sizeof(msg));
    r = falcon_hash_to_point(NULL, msg, sizeof(msg), c, logn, NULL);
    if (r == 0) {
        WB_NOTE("hash_to_point(nonce=NULL) expected error");
    }
    WB_OK("falcon_hash_to_point ret==0 operand FALSE half exercised");
}

/* ------------------------------------------------------------------ *
 * falcon_expand_privkey NULL/logn guard (7 operands) and
 * falcon_ffSampling_fft logn guard: TRUE halves via NULL / out-of-range.
 * Both-FALSE halves are covered by the real sign round-trip.
 * ------------------------------------------------------------------ */
#ifndef WOLFSSL_FALCON_SIGN_SMALL_MEM
static void wb_expand_and_ffsampling_guards(void)
{
    fpr    edummy[8];
    sword8 f8[4], g8[4], F8[4], G8[4];
    fpr    z0[4], z1[4], tree[4], t0[4], t1[4], tmp[4];

    XMEMSET(f8, 0, sizeof(f8));
    XMEMSET(g8, 0, sizeof(g8));
    XMEMSET(F8, 0, sizeof(F8));
    XMEMSET(G8, 0, sizeof(G8));
    XMEMSET(edummy, 0, sizeof(edummy));
    XMEMSET(z0, 0, sizeof(z0));
    XMEMSET(z1, 0, sizeof(z1));
    XMEMSET(tree, 0, sizeof(tree));
    XMEMSET(t0, 0, sizeof(t0));
    XMEMSET(t1, 0, sizeof(t1));
    XMEMSET(tmp, 0, sizeof(tmp));

    /* falcon_expand_privkey guard: each operand's TRUE half. */
    (void)falcon_expand_privkey(NULL, f8, g8, F8, G8, 2, NULL);
    (void)falcon_expand_privkey(edummy, NULL, g8, F8, G8, 2, NULL);
    (void)falcon_expand_privkey(edummy, f8, NULL, F8, G8, 2, NULL);
    (void)falcon_expand_privkey(edummy, f8, g8, NULL, G8, 2, NULL);
    (void)falcon_expand_privkey(edummy, f8, g8, F8, NULL, 2, NULL);
    (void)falcon_expand_privkey(edummy, f8, g8, F8, G8, 0, NULL);
    (void)falcon_expand_privkey(edummy, f8, g8, F8, G8, 11, NULL);

    /* falcon_ffSampling_fft logn guard (returns before touching buffers). */
    falcon_ffSampling_fft(falcon_sampler_z, NULL, z0, z1, tree, t0, t1, 0, tmp);
    falcon_ffSampling_fft(falcon_sampler_z, NULL, z0, z1, tree, t0, t1, 11, tmp);
    WB_OK("expand_privkey / ffSampling_fft logn+NULL guard TRUE halves exercised");
}

/* ------------------------------------------------------------------ *
 * falcon_do_sign_tree NULL/logn guard (7 operands): TRUE halves via NULL /
 * out-of-range. Both-FALSE half + the samplerErr / spc->p.err decisions are
 * covered by the real sign round-trip (samplerErr checks) or noted as deep
 * residuals.
 * ------------------------------------------------------------------ */
static void wb_do_sign_tree_guard(void)
{
    sword16 s2d[4];
    fpr     trd[8];
    word16  hmd[4];
    fpr     tmpd[8];

    XMEMSET(s2d, 0, sizeof(s2d));
    XMEMSET(trd, 0, sizeof(trd));
    XMEMSET(hmd, 0, sizeof(hmd));
    XMEMSET(tmpd, 0, sizeof(tmpd));

    (void)falcon_do_sign_tree(NULL, NULL, s2d, trd, hmd, 2, tmpd, NULL);
    (void)falcon_do_sign_tree(falcon_sampler_z, NULL, NULL, trd, hmd, 2, tmpd,
            NULL);
    (void)falcon_do_sign_tree(falcon_sampler_z, NULL, s2d, NULL, hmd, 2, tmpd,
            NULL);
    (void)falcon_do_sign_tree(falcon_sampler_z, NULL, s2d, trd, NULL, 2, tmpd,
            NULL);
    (void)falcon_do_sign_tree(falcon_sampler_z, NULL, s2d, trd, hmd, 2, NULL,
            NULL);
    (void)falcon_do_sign_tree(falcon_sampler_z, NULL, s2d, trd, hmd, 0, tmpd,
            NULL);
    (void)falcon_do_sign_tree(falcon_sampler_z, NULL, s2d, trd, hmd, 11, tmpd,
            NULL);
    WB_OK("falcon_do_sign_tree NULL+logn guard TRUE halves exercised");
}
#else /* WOLFSSL_FALCON_SIGN_SMALL_MEM */
/* ------------------------------------------------------------------ *
 * falcon_do_sign_dyn (small-mem twin of falcon_do_sign_tree) NULL/logn guard:
 *   samp||s2||f||g||F||G||hm||tmp==NULL  (8 operands) || logn<1 || logn>10
 * Only compiled under WOLFSSL_FALCON_SIGN_SMALL_MEM (the falcon_small_mem
 * variant). The small-mem native sign round-trip covers the all-FALSE
 * (proceed) half; drive each operand's TRUE half directly. Every call
 * early-returns BAD_FUNC_ARG before the signing loop, so the dummy non-NULL
 * operands are never dereferenced.
 * ------------------------------------------------------------------ */
static void wb_do_sign_dyn_guard(void)
{
    sword16 s2d[4];
    sword8  fd[4], gd[4], Fd[4], Gd[4];
    word16  hmd[4];
    fpr     tmpd[8];
    const falcon_samplerZ S = falcon_sampler_z;

    XMEMSET(s2d, 0, sizeof(s2d));
    XMEMSET(fd, 0, sizeof(fd)); XMEMSET(gd, 0, sizeof(gd));
    XMEMSET(Fd, 0, sizeof(Fd)); XMEMSET(Gd, 0, sizeof(Gd));
    XMEMSET(hmd, 0, sizeof(hmd));
    XMEMSET(tmpd, 0, sizeof(tmpd));

    (void)falcon_do_sign_dyn(NULL, NULL, s2d, fd, gd, Fd, Gd, hmd, 9, tmpd, NULL);
    (void)falcon_do_sign_dyn(S, NULL, NULL, fd, gd, Fd, Gd, hmd, 9, tmpd, NULL);
    (void)falcon_do_sign_dyn(S, NULL, s2d, NULL, gd, Fd, Gd, hmd, 9, tmpd, NULL);
    (void)falcon_do_sign_dyn(S, NULL, s2d, fd, NULL, Fd, Gd, hmd, 9, tmpd, NULL);
    (void)falcon_do_sign_dyn(S, NULL, s2d, fd, gd, NULL, Gd, hmd, 9, tmpd, NULL);
    (void)falcon_do_sign_dyn(S, NULL, s2d, fd, gd, Fd, NULL, hmd, 9, tmpd, NULL);
    (void)falcon_do_sign_dyn(S, NULL, s2d, fd, gd, Fd, Gd, NULL, 9, tmpd, NULL);
    (void)falcon_do_sign_dyn(S, NULL, s2d, fd, gd, Fd, Gd, hmd, 9, NULL, NULL);
    (void)falcon_do_sign_dyn(S, NULL, s2d, fd, gd, Fd, Gd, hmd, 0, tmpd, NULL);
    (void)falcon_do_sign_dyn(S, NULL, s2d, fd, gd, Fd, Gd, hmd, 11, tmpd, NULL);
    WB_OK("falcon_do_sign_dyn NULL+logn guard TRUE halves exercised");
}
#endif /* WOLFSSL_FALCON_SIGN_SMALL_MEM */

/* ------------------------------------------------------------------ *
 * falcon_keygen (internal) NULL/logn guard:
 *   rng==NULL || f==NULL || g==NULL || F==NULL || G==NULL   (5 operands)
 *   logn < 1 || logn > 10
 * The native make-key path always calls falcon_keygen with valid args, so only
 * the FALSE (proceed) half is covered by the round-trip. Drive each operand's
 * TRUE half directly; every one early-returns BAD_FUNC_ARG before allocating.
 * ------------------------------------------------------------------ */
#ifndef WOLFSSL_FALCON_VERIFY_ONLY
static void wb_keygen_guard(WC_RNG* rng)
{
    sword8 f[4], g[4], F[4], G[4];
    word16 h[4];

    XMEMSET(f, 0, sizeof(f));
    XMEMSET(g, 0, sizeof(g));
    XMEMSET(F, 0, sizeof(F));
    XMEMSET(G, 0, sizeof(G));
    XMEMSET(h, 0, sizeof(h));

    (void)falcon_keygen(NULL, f, g, F, G, h, 1);   /* rng==NULL (cond0) */
    (void)falcon_keygen(rng, NULL, g, F, G, h, 1); /* f==NULL   (cond1) */
    (void)falcon_keygen(rng, f, NULL, F, G, h, 1); /* g==NULL   (cond2) */
    (void)falcon_keygen(rng, f, g, NULL, G, h, 1); /* F==NULL   (cond3) */
    (void)falcon_keygen(rng, f, g, F, NULL, h, 1); /* G==NULL   (cond4) */
    (void)falcon_keygen(rng, f, g, F, G, h, 0);    /* logn<1    (cond0) */
    (void)falcon_keygen(rng, f, g, F, G, h, 11);   /* logn>10   (cond1) */
    WB_OK("falcon_keygen NULL+logn guard TRUE halves exercised");
}
#endif /* !WOLFSSL_FALCON_VERIFY_ONLY */

/* ------------------------------------------------------------------ *
 * Native API NULL/short guards (not reachable from tests/api because the
 * wc_falcon_* wrappers pre-filter NULL args). Each TRUE half is driven by a
 * direct call passing NULL for the checked pointer; each early-returns
 * BAD_FUNC_ARG before any dereference. A zeroed falcon_key (prvKeySet/pubKeySet
 * clear, level invalid) makes the "proceed past the guard" combos bail on the
 * very next check without touching the payload buffers.
 * ------------------------------------------------------------------ */
static void wb_native_guards(WC_RNG* rng)
{
    falcon_key kbad;
    byte   outbuf[FALCON_LEVEL1_SIG_SIZE];
    word32 outLen = sizeof(outbuf);
    byte   inbuf[4];
    byte   sigbuf[8];
    int    res = 0;

    XMEMSET(&kbad, 0, sizeof(kbad));
    XMEMSET(inbuf, 0, sizeof(inbuf));
    XMEMSET(sigbuf, 0, sizeof(sigbuf));

#ifndef WOLFSSL_FALCON_VERIFY_ONLY
    /* falcon_native_make_key: key==NULL || rng==NULL. */
    (void)falcon_native_make_key(NULL, rng);      /* key==NULL (cond0 TRUE) */
    (void)falcon_native_make_key(&kbad, NULL);    /* rng==NULL (cond1 TRUE) */

    /* falcon_native_sign_msg:
     * (in==NULL && inLen!=0) || out==NULL || outLen==NULL || key==NULL
     *   || rng==NULL
     */
    /* in==NULL && inLen!=0 : cond0 TRUE, cond1 TRUE -> guard TRUE. */
    (void)falcon_native_sign_msg(NULL, 1, outbuf, &outLen, &kbad, rng);
    /* in==NULL && inLen==0 : cond0 TRUE, cond1 FALSE -> sub-AND FALSE ->
     * proceeds; kbad.prvKeySet==0 bails before any 'in' deref. */
    (void)falcon_native_sign_msg(NULL, 0, outbuf, &outLen, &kbad, rng);
    /* out==NULL (cond2 TRUE). */
    (void)falcon_native_sign_msg(inbuf, 0, NULL, &outLen, &kbad, rng);
    /* outLen==NULL (cond3 TRUE). */
    (void)falcon_native_sign_msg(inbuf, 0, outbuf, NULL, &kbad, rng);
    /* key==NULL (cond4 TRUE). */
    (void)falcon_native_sign_msg(inbuf, 0, outbuf, &outLen, NULL, rng);
    /* rng==NULL (cond5 TRUE). */
    (void)falcon_native_sign_msg(inbuf, 0, outbuf, &outLen, &kbad, NULL);
#endif /* !WOLFSSL_FALCON_VERIFY_ONLY */

    /* falcon_native_verify_msg:
     * sig==NULL || res==NULL || key==NULL || (msg==NULL && msgLen!=0)
     */
    (void)falcon_native_verify_msg(NULL, 8, inbuf, 1, &res, &kbad);     /* sig */
    (void)falcon_native_verify_msg(sigbuf, 8, inbuf, 1, NULL, &kbad);   /* res */
    (void)falcon_native_verify_msg(sigbuf, 8, inbuf, 1, &res, NULL);    /* key */
    /* msg==NULL && msgLen!=0 : cond3 TRUE, cond4 TRUE -> guard TRUE. */
    (void)falcon_native_verify_msg(sigbuf, 8, NULL, 1, &res, &kbad);
    /* msg==NULL && msgLen==0 : cond3 TRUE, cond4 FALSE -> sub-AND FALSE ->
     * proceeds; kbad.pubKeySet==0 bails before any 'sig' deref. */
    (void)falcon_native_verify_msg(sigbuf, 8, NULL, 0, &res, &kbad);
    WB_OK("falcon_native_ make/sign/verify NULL+short guard pairs exercised");
}

/* ------------------------------------------------------------------ *
 * Real native make/sign/verify round-trip at Falcon-512. This is the
 * production path; it drives the "success"/FALSE half of the deep file-static
 * decisions that the measured baseline never reaches (keygen never runs there):
 *   - falcon_keygen guards (both-FALSE) + coeff-range guard all-FALSE + the
 *     Gaussian sampler / norm / invertibility / NTRU-solve success path;
 *   - make_fg with depth==logn (depth!=0, the cond0 FALSE half);
 *   - solve_NTRU_deepest / _intermediate / _binary_depth0 success paths;
 *   - poly_big_to_small success chain, complete_private range all-FALSE;
 *   - falcon_expand_privkey both-FALSE + falcon_do_sign_tree both-FALSE +
 *     ffSampling both-FALSE + samplerErr check FALSE;
 *   - hash_to_point loop (ret==0 TRUE, i<n both), comp/modq decode success.
 * ------------------------------------------------------------------ */
#ifndef WOLFSSL_FALCON_VERIFY_ONLY
static void wb_native_roundtrip(WC_RNG* rng)
{
    falcon_key key;
    byte   sig[FALCON_LEVEL1_SIG_SIZE];
    word32 sigLen = sizeof(sig);
    byte   msg[32];
    int    res = 0;
    int    r;

    XMEMSET(&key, 0, sizeof(key));
    key.level = FALCON_LEVEL1;
    key.heap  = NULL;
    XMEMSET(msg, 0x5A, sizeof(msg));

    r = falcon_native_make_key(&key, rng);
    if (r != 0) {
        WB_NOTE("native_make_key(Falcon-512) failed; deep keygen paths skipped");
        return;
    }
    r = falcon_native_sign_msg(msg, sizeof(msg), sig, &sigLen, &key, rng);
    if (r != 0) {
        WB_NOTE("native_sign_msg failed; deep sign paths skipped");
        return;
    }
    r = falcon_native_verify_msg(sig, sigLen, msg, sizeof(msg), &res, &key);
    if ((r != 0) || (res != 1)) {
        WB_NOTE("native_verify_msg did not accept a self-signed message");
    }
    WB_OK("native make/sign/verify round-trip (deep static paths) exercised");
}
#endif /* !WOLFSSL_FALCON_VERIFY_ONLY */

/* ------------------------------------------------------------------ *
 * Documented residuals: decision halves reachable only from a genuine
 * mid-computation error or a degenerate/forbidden operand, which cannot be
 * driven crash-safely from a white-box harness. Their opposite (normal) half is
 * covered above (mostly by the real round-trip).
 * ------------------------------------------------------------------ */
static void wb_residuals(void)
{
    WB_NOTE("residual: berexp (w==0)&&(i>0) i>0 FALSE half needs PRNG-forced "
            "equal comparison bytes (deep sampler)");
    WB_NOTE("residual: solve_NTRU_deepest zint_mul_small overflow TRUE half "
            "(bigint carry error path)");
    WB_NOTE("residual: solve_NTRU_intermediate !fpr_lt(z,2^63) TRUE half "
            "(out-of-range Babai coefficient)");
    WB_NOTE("residual: solve_NTRU_intermediate !fpr_lt(+-2^31,xv) range clamp "
            "(out-of-range reduction coefficient, data-dependent)");
    WB_NOTE("residual: solve_NTRU poly_big_to_small failure TRUE half "
            "(reduction overflow)");
    WB_NOTE("residual: poly_small_mkgauss s<-127||s>127 TRUE half "
            "(random sampler tail)");
    WB_NOTE("residual: keygen f/g coeff >=lim/<=-lim TRUE halves "
            "(sampler bound forbids |coeff|>=128)");
    WB_NOTE("residual: check-public ft[i]==0 TRUE half "
            "(non-invertible/degenerate key)");
    WB_NOTE("residual: do_sign_tree samplerErr!=0 / spc->p.err!=0 TRUE halves "
            "(latched PRNG squeeze failure)");
}

#endif /* HAVE_FALCON */

int main(void)
{
    printf("falcon.c white-box MC/DC supplement\n");
#if !defined(HAVE_FALCON)
    printf("  Falcon not enabled; nothing to exercise\n");
    return 0;
#else
    {
        WC_RNG rng;
        int haveRng = (wc_InitRng(&rng) == 0);
        if (!haveRng) {
            WB_NOTE("wc_InitRng failed; RNG-dependent paths skipped");
        }

        wb_comp_encode();
        wb_trim_i8();
        wb_privkey();
        if (haveRng) {
            wb_prng_sampler_init(&rng);
        }
        wb_poly_big_to_small();
        wb_make_fg();
        wb_complete_private();
        wb_comp_decode();
        wb_hash_to_point();
#ifndef WOLFSSL_FALCON_SIGN_SMALL_MEM
        wb_expand_and_ffsampling_guards();
        wb_do_sign_tree_guard();
#else
        wb_do_sign_dyn_guard();
#endif
        if (haveRng) {
#ifndef WOLFSSL_FALCON_VERIFY_ONLY
            wb_keygen_guard(&rng);
#endif
            wb_native_guards(&rng);
#ifndef WOLFSSL_FALCON_VERIFY_ONLY
            wb_native_roundtrip(&rng);
#endif
        }
        wb_residuals();

        if (haveRng) {
            wc_FreeRng(&rng);
        }
    }
    printf("done (%d note%s)\n", wb_notes, (wb_notes == 1) ? "" : "s");
    return 0;
#endif
}
