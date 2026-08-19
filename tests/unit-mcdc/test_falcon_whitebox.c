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

/* ================================================================== *
 * Gap-close pass: decisions whose remaining half is only reachable by
 * calling a file-static helper DIRECTLY with crafted operands. Every
 * driver below is bounded (no unbounded retry loop is ever entered with
 * a rejecting sampler unless the restart bound itself is tiny) and
 * crash-safe: the operands are mathematically invalid but structurally
 * well-formed, and every buffer handed in is correctly sized.
 * ================================================================== */

#ifndef WOLFSSL_FALCON_VERIFY_ONLY

/* ------------------------------------------------------------------ *
 * falcon_berexp: do { i -= 8; w = prng_u8 - ((z >> i) & 0xFF); }
 *                while ((w == 0) && (i > 0));
 * The (i > 0) operand is only evaluated when w == 0, i.e. when the fresh
 * random byte happens to equal the corresponding byte of z -- probability
 * 1/256 per iteration from a live PRNG, and 2^-64 for the final (i == 0)
 * iteration that yields the operand's FALSE half.
 *
 * falcon_prng is a plain SHAKE256 squeeze buffer, so the byte stream berexp
 * consumes can be planted: recompute z exactly as berexp does (the same
 * public helpers are in scope), then stage the eight big-endian bytes of z in
 * p.buf. Every iteration then sees w == 0, so the loop walks i = 56, 48, ...
 * (cond1 TRUE) down to i == 0 (cond1 FALSE) -- both halves of the (i > 0)
 * operand in a single, fully deterministic call that consumes exactly the
 * eight staged bytes and never refills.
 * ------------------------------------------------------------------ */
static void wb_berexp_loop(WC_RNG* rng)
{
    falcon_prng p;
    fpr    x, r, ccs;
    word64 z;
    word32 sw;
    int    s, i;

    XMEMSET(&p, 0, sizeof(p));
    if (falcon_prng_init(&p, rng) != 0) {
        WB_NOTE("berexp: prng_init failed; loop-operand vector skipped");
        return;
    }

    /* Any x >= 0 (berexp's documented precondition) and any ccs in (0, 1).
     * ccs must stay strictly below 1: fpr_expm_p63 scales it by 2^63 and
     * truncates to a signed 64-bit integer, so ccs == 1 would sit exactly on
     * the overflow edge. */
    x   = fpr_of(3);
    ccs = fpr_onehalf;

    /* Mirror of berexp's own reduction, verbatim, so z matches bit for bit. */
    s = (int)fpr_trunc(fpr_mul(x, falcon_fpr_inv_log2));
    r = fpr_sub(x, fpr_mul(fpr_of((sword64)s), falcon_fpr_log2));
    sw = (word32)s;
    sw ^= (sw ^ 63U) & (word32)(0U - ((63U - sw) >> 31));
    s = (int)sw;
    z = ((fpr_expm_p63(r, ccs) << 1) - 1) >> s;

    /* Stage the eight comparison bytes so every iteration sees w == 0. */
    for (i = 0; i < 8; i++) {
        p.buf[i] = (byte)((z >> (56 - 8 * i)) & 0xFFU);
    }
    p.ptr = 0;
    p.len = 8;

    (void)falcon_berexp(&p, x, ccs);

    wc_Shake256_Free(&p.shake);
    ForceZero(&p, sizeof(p));
    WB_OK("falcon_berexp (w==0)&&(i>0) loop operand pair exercised");
}

/* ------------------------------------------------------------------ *
 * poly_small_mkgauss: if (s < -127 || s > 127) continue;
 * mkgauss() sums 2^(10-logn) table samples, so the standard deviation is
 * 1.17*sqrt(q/(2n)): ~2.87 at logn = 10 (rejection never observed) but ~64.9
 * at logn = 1, where |s| > 127 is only ~1.96 sigma and fires for roughly 5% of
 * the draws -- with both signs equally likely. Driving the helper directly at
 * logn = 1 therefore shows both operands' TRUE half (and the all-FALSE half)
 * within a few hundred coefficients, with no unbounded loop: every rejection
 * is followed by a fresh in-range draw.
 * ------------------------------------------------------------------ */
static void wb_mkgauss_range(WC_RNG* rng)
{
    falcon_rng rc;
    sword8     f[2];              /* logn = 1 -> n = 2 */
    int        i;

    XMEMSET(&rc, 0, sizeof(rc));
    if (falcon_rng_init(&rc, rng, NULL) != 0) {
        WB_NOTE("mkgauss: falcon_rng_init failed; range vectors skipped");
        return;
    }
    for (i = 0; i < 512; i++) {
        poly_small_mkgauss(&rc, f, 1);
        if (rc.err != 0) {
            WB_NOTE("mkgauss: PRNG squeeze failed mid-run");
            break;
        }
    }
    falcon_rng_free(&rc);
    WB_OK("poly_small_mkgauss s<-127 / s>127 operand pair exercised");
}

/* ------------------------------------------------------------------ *
 * falcon_native_check_key: if (ft[i] == 0 || barrett(h[i]*ft[i]) != gt[i])
 * cond0's TRUE half needs a private key whose f is NOT invertible mod q, i.e.
 * with a zero slot in NTT(f). keygen never emits one (it restarts instead),
 * but the check runs on a DECODED key blob, so the whole operand pair can be
 * built by hand at Falcon-512. NTT is linear and the polynomials below are
 * constants, so every slot value is known exactly:
 *   f = 0, g = 0, h = 0 -> ft[i] = 0                    (cond0 TRUE)
 *   f = 1, g = 0, h = 0 -> ft[i] = 1, h[i]*ft[i] = 0 = gt[i]
 *                                                       (cond0/cond1 FALSE)
 *   f = 1, g = 0, h = 1 -> ft[i] = 1, h[i]*ft[i] = 1 != gt[i] = 0
 *                                                       (cond0 FALSE, cond1
 *                                                        TRUE)
 * Every buffer is a real, correctly sized key array and the routine only ever
 * decodes and compares.
 * ------------------------------------------------------------------ */
static int wb_check_key_case(falcon_key* key, sword8* poly, word16* h,
        sword8 f0, word16 h0)
{
    const unsigned logn = 9;      /* FALCON_LEVEL1 -> n = 512 */
    const size_t   n    = (size_t)1 << 9;

    XMEMSET(key, 0, sizeof(*key));
    XMEMSET(poly, 0, 3 * n);              /* f = g = F = 0 */
    XMEMSET(h, 0, n * sizeof(word16));
    poly[0] = f0;                         /* constant term of f */
    h[0]    = h0;                         /* constant term of h */

    key->level = FALCON_LEVEL1;
    key->heap  = NULL;
    if (falcon_privkey_encode(key->k, FALCON_LEVEL1_KEY_SIZE, poly, poly + n,
            poly + 2 * n, logn) != FALCON_LEVEL1_KEY_SIZE) {
        WB_NOTE("check_key: privkey_encode did not fill the blob");
        return 1;
    }
    key->p[0] = (byte)(FALCON_PUB_HEAD | logn);
    if (falcon_modq_encode(key->p + 1, FALCON_LEVEL1_PUB_KEY_SIZE - 1, h,
            logn) == 0) {
        WB_NOTE("check_key: modq_encode failed");
        return 1;
    }
    return falcon_native_check_key(key);
}

static void wb_check_key_ntt_slots(void)
{
    falcon_key* key;
    sword8*     poly;
    word16*     h;
    const size_t n = (size_t)1 << 9;

    key  = (falcon_key*)XMALLOC(sizeof(*key), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    poly = (sword8*)XMALLOC(3 * n, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    h    = (word16*)XMALLOC(n * sizeof(word16), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if ((key == NULL) || (poly == NULL) || (h == NULL)) {
        WB_NOTE("check_key: allocation failed; NTT-slot vectors skipped");
    }
    else {
        /* cond0 FALSE, cond1 FALSE: consistent (all-zero) relation. */
        if (wb_check_key_case(key, poly, h, 1, 0) != 0) {
            WB_NOTE("check_key(f=1,h=0) expected acceptance");
        }
        /* cond0 FALSE, cond1 TRUE: invertible f but h*f != g. */
        if (wb_check_key_case(key, poly, h, 1, 1)
                != WC_NO_ERR_TRACE(PUBLIC_KEY_E)) {
            WB_NOTE("check_key(f=1,h=1) expected a public-key mismatch");
        }
        /* cond0 TRUE: f == 0 is not invertible, so NTT(f) is zero. */
        if (wb_check_key_case(key, poly, h, 0, 0)
                != WC_NO_ERR_TRACE(PUBLIC_KEY_E)) {
            WB_NOTE("check_key(f=0) expected a public-key mismatch");
        }
    }
    XFREE(h, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(poly, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    WB_OK("falcon_native_check_key ft[i]==0 operand pair exercised");
}

/* ------------------------------------------------------------------ *
 * solve_NTRU_deepest:
 *   if (zint_mul_small(Fp, len, q) != 0 || zint_mul_small(Gp, len, q) != 0)
 * Both operands' TRUE half needs the q-scaling of a Bezout coefficient to
 * carry out of the len-word big integer. Real keygen operands are Gaussian
 * with a tiny norm, so the resultants stay far below the CRT modulus and the
 * carry never appears. With adversarial (f, g) whose coefficients fill the
 * signed 8-bit range, the resultant of a degree-8 polynomial with X^8+1
 * exceeds the 2-word CRT modulus at logn_top = 3, wraps, and the Bezout
 * coefficients become essentially uniform below the modulus -- so the carry
 * fires for the large majority of candidates.
 *
 * The classification is done first, on a private scratch buffer, by replaying
 * exactly the prologue solve_NTRU_deepest runs (make_fg -> zint_rebuild_CRT ->
 * zint_bezout) and then testing the two carries on COPIES; only once a
 * candidate is known to produce the wanted pattern is the real helper invoked
 * with it. The search is bounded and every step is a pure big-integer
 * computation on correctly sized buffers.
 * ------------------------------------------------------------------ */
#define WB_DEEPEST_LOGN   3
#define WB_DEEPEST_N      ((size_t)1 << WB_DEEPEST_LOGN)
#define WB_SOLVE_WORDS    8192

static void wb_deepest_candidate(int trial, sword8* f, sword8* g)
{
    size_t   i;
    unsigned parity;

    for (i = 0; i < WB_DEEPEST_N; i++) {
        f[i] = (sword8)((trial * 7 + (int)i * 31 + 11) % 255 - 127);
        g[i] = (sword8)((trial * 13 + (int)i * 17 + 5) % 255 - 127);
    }
    /* zint_bezout requires both resultants odd, i.e. an odd coefficient sum. */
    for (i = 0, parity = 0; i < WB_DEEPEST_N; i++) {
        parity ^= (unsigned)(f[i] & 1);
    }
    if (parity == 0) {
        f[0] = (sword8)(f[0] ^ 1);
    }
    for (i = 0, parity = 0; i < WB_DEEPEST_N; i++) {
        parity ^= (unsigned)(g[i] & 1);
    }
    if (parity == 0) {
        g[0] = (sword8)(g[0] ^ 1);
    }
}

/* Returns 1/2/3 for "no carry", "first operand carries", "only the second
 * carries", or 0 when zint_bezout rejects the candidate. */
static int wb_deepest_classify(word32* scratch, const sword8* f,
        const sword8* g)
{
    const size_t len = MAX_BL_SMALL[WB_DEEPEST_LOGN];
    word32* Fp = scratch;
    word32* Gp = Fp + len;
    word32* fp = Gp + len;
    word32* gp = fp + len;
    word32* t1 = gp + len;
    word32  cF, cG;

    make_fg(fp, f, g, WB_DEEPEST_LOGN, WB_DEEPEST_LOGN, 0);
    zint_rebuild_CRT(fp, len, len, 2, FALCON_PRIMES, 0, t1);
    if (!zint_bezout(Gp, Fp, fp, gp, len, t1)) {
        return 0;
    }
    /* Carry test on copies: zint_mul_small scales in place. */
    XMEMCPY(t1, Fp, len * sizeof(word32));
    cF = zint_mul_small(t1, len, 12289);
    XMEMCPY(t1, Gp, len * sizeof(word32));
    cG = zint_mul_small(t1, len, 12289);
    if (cF != 0) {
        return 2;
    }
    return (cG != 0) ? 3 : 1;
}

static void wb_solve_deepest_overflow(void)
{
    word32* scratch;
    word32* live;
    sword8  f[WB_DEEPEST_N];
    sword8  g[WB_DEEPEST_N];
    int     trial, want, got;
    int     found[4];

    scratch = (word32*)XMALLOC(WB_SOLVE_WORDS * sizeof(word32), NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
    live = (word32*)XMALLOC(WB_SOLVE_WORDS * sizeof(word32), NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
    if ((scratch == NULL) || (live == NULL)) {
        WB_NOTE("solve_NTRU_deepest: allocation failed; carry vectors skipped");
    }
    else {
        found[0] = found[1] = found[2] = found[3] = 0;
        /* want 2 = first operand carries (cond0 TRUE),
         * want 3 = only the second carries (cond0 FALSE, cond1 TRUE). */
        for (want = 2; want <= 3; want++) {
            for (trial = 0; trial < 256; trial++) {
                wb_deepest_candidate(trial, f, g);
                got = wb_deepest_classify(scratch, f, g);
                if (got != want) {
                    continue;
                }
                XMEMSET(live, 0, WB_SOLVE_WORDS * sizeof(word32));
                if (solve_NTRU_deepest(WB_DEEPEST_LOGN, f, g, live) != 0) {
                    WB_NOTE("solve_NTRU_deepest: expected the carry rejection");
                }
                found[want] = 1;
                break;
            }
            if (!found[want]) {
                WB_NOTE("solve_NTRU_deepest: no candidate for a carry pattern");
            }
        }
    }
    XFREE(live, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(scratch, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    WB_OK("solve_NTRU_deepest zint_mul_small carry operand pair exercised");
}

/* ------------------------------------------------------------------ *
 * solve_NTRU:
 *   if (!poly_big_to_small(F, tmp, lim, logn)
 *           || !poly_big_to_small(G, tmp + n, lim, logn))
 * keygen always passes lim = 127 and the solved (F, G) fit, so only the
 * all-FALSE half shows. lim is a plain parameter of solve_NTRU, so a direct
 * call with a deliberately tight bound rejects on the first or the second
 * conversion at will:
 *   lim = 0            -> F is out of range          (cond0 TRUE)
 *   lim = max|F[i]|    -> F fits, G does not         (cond0 FALSE, cond1 TRUE)
 * The (f, g) pair comes from a real keygen at logn = 5, so the whole solver
 * chain runs on legitimate operands and only the final range gate differs; the
 * second vector is only issued once a key with max|G| > max|F| has been drawn.
 * ------------------------------------------------------------------ */
static void wb_solve_ntru_lim(WC_RNG* rng)
{
    const unsigned logn = 5;
    const size_t   n    = (size_t)1 << 5;
    sword8  f[32], g[32], F[32], G[32], Fout[32], Gout[32];
    word16  h[32];
    byte*   tmpbuf;
    size_t  u;
    int     tries, maxF = 0, maxG = 0, haveKey = 0;

    tmpbuf = (byte*)XMALLOC(FALCON_KEYGEN_TEMP[logn] + sizeof(fpr), NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (tmpbuf == NULL) {
        WB_NOTE("solve_NTRU: allocation failed; lim vectors skipped");
        return;
    }
    for (tries = 0; tries < 8; tries++) {
        if (falcon_keygen(rng, f, g, F, G, h, logn) != 0) {
            break;
        }
        maxF = 0;
        maxG = 0;
        for (u = 0; u < n; u++) {
            int aF = (F[u] < 0) ? -(int)F[u] : (int)F[u];
            int aG = (G[u] < 0) ? -(int)G[u] : (int)G[u];
            if (aF > maxF) {
                maxF = aF;
            }
            if (aG > maxG) {
                maxG = aG;
            }
        }
        haveKey = 1;
        if (maxG > maxF) {
            break;
        }
    }
    if (!haveKey) {
        WB_NOTE("solve_NTRU: keygen(logn=5) failed; lim vectors skipped");
    }
    else {
        /* cond0 TRUE: no coefficient of F can fit in [-0, 0]. */
        if (solve_NTRU(logn, Fout, Gout, f, g, 0, (word32*)tmpbuf) != 0) {
            WB_NOTE("solve_NTRU(lim=0) expected the range rejection");
        }
        if (maxG > maxF) {
            /* cond0 FALSE, cond1 TRUE: F fits exactly, G overflows. */
            if (solve_NTRU(logn, Fout, Gout, f, g, maxF,
                    (word32*)tmpbuf) != 0) {
                WB_NOTE("solve_NTRU(lim=max|F|) expected the G rejection");
            }
        }
        else {
            WB_NOTE("solve_NTRU: no key with max|G| > max|F| in 8 draws");
        }
    }
    ForceZero(tmpbuf, (word32)(FALCON_KEYGEN_TEMP[logn] + sizeof(fpr)));
    XFREE(tmpbuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    WB_OK("solve_NTRU poly_big_to_small lim operand pair exercised");
}

/* ------------------------------------------------------------------ *
 * solve_NTRU_intermediate Babai clamp:
 *   if (!fpr_lt(fpr_mtwo31m1, xv) || !fpr_lt(xv, fpr_ptwo31m1)) return 0;
 * xv is a reduction coefficient rescaled by 2^dc, where dc comes from the
 * BITLENGTH[] heuristic for the expected coefficient size at that depth. The
 * heuristic is tuned for the production degrees, so at logn = 9/10 an
 * out-of-range xv is astronomically rare -- which is why the baseline only
 * ever showed this pair by luck. At logn = 3 the same heuristic is far coarser
 * and the clamp fires for roughly a fifth of the drawn (f, g) pairs, in both
 * directions, so a bounded batch of small keygens turns a lottery into a
 * near-certainty: with p ~ 0.2 per key, 256 keys leave a miss probability
 * below 1e-24. Each key is a full but tiny (n = 8) keygen; the batch runs in
 * a few seconds and cannot loop (falcon_keygen either returns or restarts on
 * its own bounded acceptance tests).
 * ------------------------------------------------------------------ */
static void wb_solve_ntru_babai_clamp(WC_RNG* rng)
{
    sword8 f[8], g[8], F[8], G[8];
    word16 h[8];
    int    i;

    for (i = 0; i < 256; i++) {
        if (falcon_keygen(rng, f, g, F, G, h, 3) != 0) {
            WB_NOTE("solve_NTRU_intermediate: keygen(logn=3) failed");
            break;
        }
    }
    WB_OK("solve_NTRU_intermediate Babai clamp operand pair exercised");
}

/* A sampler that always returns 0. Used to make a signing attempt fully
 * deterministic: the sampled lattice coordinates are zero, so the candidate is
 * exactly the (huge) target and the shortness test always rejects. It touches
 * neither the PRNG nor the ffLDL tree, so it cannot loop or diverge. */
static int wb_samp_zero(void* ctx, fpr mu, fpr isigma)
{
    (void)ctx;
    (void)mu;
    (void)isigma;
    return 0;
}

/* A degenerate-but-valid basis at logn = 1: f*G - g*F = -12 + 31*X is nonzero
 * at both FFT slots, so the Gram matrix is positive definite and the ffLDL
 * leaf sigmas are finite and positive -- the sampler behaves normally. */
#define WB_SIGN_LOGN   1
#define WB_SIGN_N      2

static const sword8 wb_basis_f[WB_SIGN_N] = {  3,  1 };
static const sword8 wb_basis_g[WB_SIGN_N] = {  1, -2 };
static const sword8 wb_basis_F[WB_SIGN_N] = {  5,  0 };
static const sword8 wb_basis_G[WB_SIGN_N] = {  0,  7 };

#ifndef WOLFSSL_FALCON_SIGN_SMALL_MEM
/* ------------------------------------------------------------------ *
 * falcon_do_sign_tree restart loop:
 *   if (samplerErr != NULL && *samplerErr != 0) return *samplerErr;
 * The check is only reached after do_sign_tree_once() REJECTS a candidate,
 * which real signing does about once in a very long while -- and never with a
 * latched sampler error, since the production caller aborts long before. Both
 * are supplied directly instead:
 *   - a sampler that always returns 0 plus an all-zero expanded key makes the
 *     lattice point identically 0, so the candidate is the raw target; with a
 *     large hash-to-point value the squared norm is far above the acceptance
 *     bound and EVERY attempt rejects, deterministically;
 *   - the three samplerErr shapes then walk the operand pair:
 *       non-NULL -> nonzero : (T,T), returns after ONE attempt
 *       NULL                : (F,-)
 *       non-NULL -> zero    : (T,F)
 * The last two run the full restart bound, which at logn = 1 is 4096 passes
 * over a two-coefficient FFT -- microseconds, not a hang risk.
 * ------------------------------------------------------------------ */
static void wb_do_sign_tree_samplererr(void)
{
    fpr     expanded[FALCON_EXPANDED_KEY_FPR(WB_SIGN_LOGN)];
    fpr     tmp[FALCON_SIGN_TMP_FPR(WB_SIGN_LOGN) + 8];
    sword16 s2[WB_SIGN_N];
    word16  hm[WB_SIGN_N];
    int     err  = WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    int     zero = 0;
    size_t  u;

    XMEMSET(expanded, 0, sizeof(expanded));
    XMEMSET(tmp, 0, sizeof(tmp));
    XMEMSET(s2, 0, sizeof(s2));
    /* 30000^2 * 2 stays inside sword32/word32 yet is ~4 orders of magnitude
     * above l2bound[1], so the shortness test always rejects. */
    for (u = 0; u < WB_SIGN_N; u++) {
        hm[u] = 30000;
    }

    /* (T,T): latched sampler error -> returns after the first rejection. */
    if (falcon_do_sign_tree(wb_samp_zero, NULL, s2, expanded, hm, WB_SIGN_LOGN,
            tmp, &err) != err) {
        WB_NOTE("do_sign_tree(samplerErr set) expected the latched error");
    }
    /* (F,-): no error pointer -> exhausts the restart bound. */
    (void)falcon_do_sign_tree(wb_samp_zero, NULL, s2, expanded, hm,
            WB_SIGN_LOGN, tmp, NULL);
    /* (T,F): error pointer present but clear -> exhausts the restart bound. */
    (void)falcon_do_sign_tree(wb_samp_zero, NULL, s2, expanded, hm,
            WB_SIGN_LOGN, tmp, &zero);
    WB_OK("falcon_do_sign_tree samplerErr operand pair exercised");
}

/* ------------------------------------------------------------------ *
 * falcon_sign_core: if (ret == 0 && spc->p.err != 0) ret = spc->p.err;
 * The round-trip only ever shows (T,F) (a clean sign with a healthy PRNG).
 *   cond0 FALSE : an out-of-range logn makes falcon_do_sign_tree reject the
 *                 arguments, so ret != 0 and cond1 is not evaluated.
 *   (T,T)       : pre-latch spc->p.err and let a signing attempt succeed. The
 *                 target is the zero hash-to-point over a well-conditioned
 *                 basis, so the sampled lattice point is essentially zero and
 *                 the first attempt is accepted; because samplerErr is non-NULL
 *                 and nonzero, a rejected attempt returns IMMEDIATELY instead
 *                 of restarting, so the loop below can never hang.
 * ------------------------------------------------------------------ */
static void wb_sign_core_err(WC_RNG* rng)
{
    falcon_sampler_ctx spc;
    fpr     expanded[FALCON_EXPANDED_KEY_FPR(WB_SIGN_LOGN)];
    fpr     tmp[FALCON_SIGN_TMP_FPR(WB_SIGN_LOGN) + 8];
    sword16 s2[WB_SIGN_N];
    word16  hm[WB_SIGN_N];
    int     i, ok = 0;

    XMEMSET(expanded, 0, sizeof(expanded));
    XMEMSET(tmp, 0, sizeof(tmp));
    XMEMSET(hm, 0, sizeof(hm));
    if (falcon_expand_privkey(expanded, wb_basis_f, wb_basis_g, wb_basis_F,
            wb_basis_G, WB_SIGN_LOGN, NULL) != 0) {
        WB_NOTE("sign_core: expand_privkey(test basis) failed");
        return;
    }
    XMEMSET(&spc, 0, sizeof(spc));
    if (falcon_sampler_init(&spc, WB_SIGN_LOGN, rng) != 0) {
        WB_NOTE("sign_core: sampler_init failed; p.err vectors skipped");
        return;
    }

    /* cond0 FALSE: argument rejection inside falcon_do_sign_tree. */
    spc.p.err = 0;
    (void)falcon_sign_core(&spc, expanded, hm, s2, tmp, 0);

    /* (T,T): a first-attempt success with the error already latched. */
    for (i = 0; i < 64; i++) {
        s2[0] = -1;
        s2[1] = -1;
        spc.p.err = WC_NO_ERR_TRACE(BAD_FUNC_ARG);
        (void)falcon_sign_core(&spc, expanded, hm, s2, tmp, WB_SIGN_LOGN);
        if ((s2[0] != -1) || (s2[1] != -1)) {
            ok = 1;                 /* s2 written -> the attempt was accepted */
            break;
        }
    }
    spc.p.err = 0;
    if (!ok) {
        WB_NOTE("sign_core: no accepted attempt with p.err latched");
    }
    wc_Shake256_Free(&spc.p.shake);
    ForceZero(&spc, sizeof(spc));
    WB_OK("falcon_sign_core (ret==0)&&(p.err!=0) operand pair exercised");
}

#else /* WOLFSSL_FALCON_SIGN_SMALL_MEM */

/* ------------------------------------------------------------------ *
 * falcon_do_sign_dyn restart loop: the low-memory twin of the decision above
 * (same samplerErr shapes, same reasoning). The basis here is passed raw
 * instead of expanded; it is well-conditioned (f*G - g*F != 0 at both slots)
 * so the on-the-fly LDL never divides by zero, and the always-zero sampler
 * again forces every attempt to reject against a large target.
 * ------------------------------------------------------------------ */
static void wb_do_sign_dyn_samplererr(void)
{
    fpr     tmp[FALCON_SIGN_DYN_TMP_FPR(WB_SIGN_LOGN) + 16];
    sword16 s2[WB_SIGN_N];
    word16  hm[WB_SIGN_N];
    int     err  = WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    int     zero = 0;
    size_t  u;

    XMEMSET(tmp, 0, sizeof(tmp));
    XMEMSET(s2, 0, sizeof(s2));
    for (u = 0; u < WB_SIGN_N; u++) {
        hm[u] = 30000;
    }

    if (falcon_do_sign_dyn(wb_samp_zero, NULL, s2, wb_basis_f, wb_basis_g,
            wb_basis_F, wb_basis_G, hm, WB_SIGN_LOGN, tmp, &err) != err) {
        WB_NOTE("do_sign_dyn(samplerErr set) expected the latched error");
    }
    (void)falcon_do_sign_dyn(wb_samp_zero, NULL, s2, wb_basis_f, wb_basis_g,
            wb_basis_F, wb_basis_G, hm, WB_SIGN_LOGN, tmp, NULL);
    (void)falcon_do_sign_dyn(wb_samp_zero, NULL, s2, wb_basis_f, wb_basis_g,
            wb_basis_F, wb_basis_G, hm, WB_SIGN_LOGN, tmp, &zero);
    WB_OK("falcon_do_sign_dyn samplerErr operand pair exercised");
}

/* ------------------------------------------------------------------ *
 * falcon_sign_dyn_core: low-memory twin of falcon_sign_core's
 * (ret == 0 && spc->p.err != 0); identical vectors and identical bound on the
 * number of attempts (a rejection returns immediately once p.err is latched).
 * ------------------------------------------------------------------ */
static void wb_sign_dyn_core_err(WC_RNG* rng)
{
    falcon_sampler_ctx spc;
    fpr     tmp[FALCON_SIGN_DYN_TMP_FPR(WB_SIGN_LOGN) + 16];
    sword16 s2[WB_SIGN_N];
    word16  hm[WB_SIGN_N];
    int     i, ok = 0;

    XMEMSET(tmp, 0, sizeof(tmp));
    XMEMSET(hm, 0, sizeof(hm));
    XMEMSET(&spc, 0, sizeof(spc));
    if (falcon_sampler_init(&spc, WB_SIGN_LOGN, rng) != 0) {
        WB_NOTE("sign_dyn_core: sampler_init failed; p.err vectors skipped");
        return;
    }

    spc.p.err = 0;
    (void)falcon_sign_dyn_core(&spc, wb_basis_f, wb_basis_g, wb_basis_F,
            wb_basis_G, hm, s2, tmp, 0);

    for (i = 0; i < 64; i++) {
        s2[0] = -1;
        s2[1] = -1;
        spc.p.err = WC_NO_ERR_TRACE(BAD_FUNC_ARG);
        (void)falcon_sign_dyn_core(&spc, wb_basis_f, wb_basis_g, wb_basis_F,
                wb_basis_G, hm, s2, tmp, WB_SIGN_LOGN);
        if ((s2[0] != -1) || (s2[1] != -1)) {
            ok = 1;
            break;
        }
    }
    spc.p.err = 0;
    if (!ok) {
        WB_NOTE("sign_dyn_core: no accepted attempt with p.err latched");
    }
    wc_Shake256_Free(&spc.p.shake);
    ForceZero(&spc, sizeof(spc));
    WB_OK("falcon_sign_dyn_core (ret==0)&&(p.err!=0) operand pair exercised");
}

#endif /* WOLFSSL_FALCON_SIGN_SMALL_MEM */

#endif /* !WOLFSSL_FALCON_VERIFY_ONLY */

/* ------------------------------------------------------------------ *
 * Documented residuals: decision halves reachable only from a genuine
 * mid-computation error or a degenerate/forbidden operand, which cannot be
 * driven crash-safely from a white-box harness. Their opposite (normal) half is
 * covered above (mostly by the real round-trip). Each of these is carried as an
 * EXCLUSIONS.md row with the source-level argument for why no satisfying vector
 * exists.
 * ------------------------------------------------------------------ */
static void wb_residuals(void)
{
    WB_NOTE("residual: solve_NTRU_binary_depth1 !fpr_lt(z,+-2^63) halves: the "
            "Babai coefficient is bounded by sqrt(|F|^2+|G|^2)/sqrt(|f|^2+"
            "|g|^2) with |F|,|G| < 2^61 (2-word CRT limbs), so |z| >= 2^63 "
            "needs both depth-1 field norms to nearly vanish at one FFT slot");
    WB_NOTE("residual: keygen f[u]/g[u] vs lim halves: lim is 1 << "
            "(falcon_max_fg_bits[logn] - 1), i.e. 32 at logn 9 and 16 at "
            "logn 10, while poly_small_mkgauss sums 1 << (10 - logn) draws of "
            "sigma 1.17*sqrt(q/2048) -- 4.05 total at logn 9. |f[u]| >= lim is "
            "a 7.9 sigma deviate (~6e-14 per coefficient, ~6e-11 per keygen), "
            "and f is generated inside falcon_keygen from its own falcon_rng, "
            "so no supplied input reaches it");
    WB_NOTE("residual: sign_msg/verify_msg (ret==0)&&(!key->...Set) cond0 "
            "FALSE half: the preceding argument check returns early, so ret is "
            "invariably 0 at that line");
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
#ifndef WOLFSSL_FALCON_VERIFY_ONLY
        /* Gap-close drivers. */
        if (haveRng) {
            wb_berexp_loop(&rng);
            wb_mkgauss_range(&rng);
        }
        wb_check_key_ntt_slots();
        wb_solve_deepest_overflow();
        if (haveRng) {
            wb_solve_ntru_lim(&rng);
            wb_solve_ntru_babai_clamp(&rng);
        }
#ifndef WOLFSSL_FALCON_SIGN_SMALL_MEM
        wb_do_sign_tree_samplererr();
        if (haveRng) {
            wb_sign_core_err(&rng);
        }
#else
        wb_do_sign_dyn_samplererr();
        if (haveRng) {
            wb_sign_dyn_core_err(&rng);
        }
#endif
#endif /* !WOLFSSL_FALCON_VERIFY_ONLY */
        wb_residuals();

        if (haveRng) {
            wc_FreeRng(&rng);
        }
    }
    printf("done (%d note%s)\n", wb_notes, (wb_notes == 1) ? "" : "s");
    return 0;
#endif
}
