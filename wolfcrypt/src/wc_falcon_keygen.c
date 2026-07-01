/* wc_falcon_keygen.c
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

/* FN-DSA / Falcon key-pair generation. See wolfssl/wolfcrypt/wc_falcon_keygen.h.
 *
 * Faithful port of the key-generation half of the MIT-licensed Falcon
 * reference implementation keygen.c (Thomas Pornin, Falcon Project,
 * 2017-2019). The big-integer / RNS layer (modp_* / zint_* / FALCON_PRIMES) is
 * the validated wc_falcon_bigint module; the floating-point seam, FFT and
 * FFT-domain polynomial primitives come from wc_falcon_fpr / fft / poly. The
 * SHAKE256 sampler stream that drives the discrete Gaussian is seeded from a
 * WC_RNG. */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if defined(HAVE_FALCON) && !defined(WOLFSSL_FALCON_VERIFY_ONLY) && !defined(WOLF_CRYPTO_CB_ONLY_FALCON)

#include <wolfssl/wolfcrypt/wc_falcon_keygen.h>
#include <wolfssl/wolfcrypt/wc_falcon_bigint.h>
#include <wolfssl/wolfcrypt/wc_falcon_fpr.h>
#include <wolfssl/wolfcrypt/wc_falcon_fft.h>
#include <wolfssl/wolfcrypt/wc_falcon_poly.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#define MKN(logn)   ((size_t)1 << (logn))

#define FALCON_Q     12289

/* IEEE-754 binary64 bit patterns (the fpr seam carries doubles as word64).
 * These mirror the named constants in the reference fpr.h that are not part of
 * the public wc_falcon_fpr.h API. */
static const fpr fpr_q         = 4667981563525332992ULL; /* (double)12289      */
static const fpr fpr_bnorm_max = 4670353323383631276ULL; /* 1.17^2 * q bound   */

/* Per-level coefficient bounds, indexed by logn (1..10). Ported from the
 * reference codec.c (max_fg_bits / max_FG_bits). */
static const byte falcon_max_fg_bits[] = {
    0, 8, 8, 8, 8, 8, 7, 7, 6, 6, 5
};
static const byte falcon_max_FG_bits[] = {
    0, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8
};

/* Required temporary buffer size, in bytes, indexed by logn (1..10). This is
 * 28*2^logn bytes, except for the smallest degrees. Ported from the reference
 * inner.h FALCON_KEYGEN_TEMP_* macros. */
static const size_t FALCON_KEYGEN_TEMP[] = {
    0, 136, 272, 224, 448, 896, 1792, 3584, 7168, 14336, 28672
};

/* ==================================================================== */
/* modp helper local to keygen (not part of the shared bigint API).      */

/*
 * Given polynomial f in NTT representation modulo p, compute f' of degree
 * less than N/2 such that f' = f0^2 - X*f1^2 (the resultant recursion step
 * used in the binary depth-1 solver).
 */
static void modp_poly_rec_res(word32* f, unsigned logn,
        word32 p, word32 p0i, word32 R2)
{
    size_t hn, u;

    hn = (size_t)1 << (logn - 1);
    for (u = 0; u < hn; u++) {
        word32 w0, w1;

        w0 = f[(u << 1) + 0];
        w1 = f[(u << 1) + 1];
        f[u] = modp_montymul(modp_montymul(w0, w1, p, p0i), R2, p, p0i);
    }
}

/* ==================================================================== */
/* SHAKE256 stream RNG (seeded from WC_RNG).                             */

typedef struct {
    wc_Shake shake;
    byte buf[WC_SHA3_256_BLOCK_SIZE];   /* 136-byte SHAKE256 rate block */
    size_t ptr;                          /* next unread byte in buf      */
    int err;                             /* sticky squeeze error         */
} falcon_rng;

static int falcon_rng_init(falcon_rng* r, WC_RNG* rng, void* heap)
{
    byte seed[48];
    int ret;

    XMEMSET(r, 0, sizeof(*r));
    ret = wc_RNG_GenerateBlock(rng, seed, (word32)sizeof(seed));
    if (ret != 0) {
        return ret;
    }
    ret = wc_InitShake256(&r->shake, heap, INVALID_DEVID);
    if (ret != 0) {
        return ret;
    }
    ret = wc_Shake256_Absorb(&r->shake, seed, (word32)sizeof(seed));
    if (ret != 0) {
        wc_Shake256_Free(&r->shake);
        return ret;
    }
    /* Force a squeeze on the first extraction. */
    r->ptr = sizeof(r->buf);
    wc_ForceZero(seed, sizeof(seed));   /* seed determines the secret key */
    return 0;
}

static void falcon_rng_free(falcon_rng* r)
{
    wc_Shake256_Free(&r->shake);
    /* The SHAKE sponge state and buffer derive the secret key. */
    wc_ForceZero(r, sizeof(*r));
}

/*
 * Get a random 8-byte integer from the SHAKE256 stream, in little-endian
 * order (consistent interpretation across platforms). The rate block is
 * 136 bytes = 17 * 8, so 8 always divides evenly into a fresh block.
 */
static word64 get_rng_u64(falcon_rng* r)
{
    const byte* p;
    word64 v;

    if (r->ptr >= sizeof(r->buf)) {
        int ret = wc_Shake256_SqueezeBlocks(&r->shake, r->buf, 1);
        if (ret != 0) {
            r->err = ret;
        }
        r->ptr = 0;
    }
    p = r->buf + r->ptr;
    r->ptr += 8;
    v = (word64)p[0]
      | ((word64)p[1] << 8)
      | ((word64)p[2] << 16)
      | ((word64)p[3] << 24)
      | ((word64)p[4] << 32)
      | ((word64)p[5] << 40)
      | ((word64)p[6] << 48)
      | ((word64)p[7] << 56);
    return v;
}

/* ==================================================================== */
/* Self-contained mod-q (q = 12289) negacyclic NTT used only to compute  */
/* the public key h = g/f mod q. (modp_* targets 31-bit primes, so a     */
/* dedicated small-modulus transform is used for q here.)                */

static word32 mq_modpow(word32 b, word32 e)
{
    word64 r = 1, bb = b % FALCON_Q;
    while (e != 0) {
        if ((e & 1) != 0) {
            r = (r * bb) % FALCON_Q;
        }
        bb = (bb * bb) % FALCON_Q;
        e >>= 1;
    }
    return (word32)r;
}

static word32 mq_modinv(word32 a)
{
    return mq_modpow(a, FALCON_Q - 2);
}

static unsigned int mq_brv(unsigned int x, int bits)
{
    unsigned int r = 0;
    int i;
    for (i = 0; i < bits; i++) {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    return r;
}

static void mq_build_tables(int logn, word32 psi, word16* zetas,
        word16* izetas)
{
    int n = 1 << logn;
    word32 ipsi = mq_modinv(psi);
    int i;
    for (i = 0; i < n; i++) {
        unsigned int e = mq_brv((unsigned int)i, logn);
        zetas[i]  = (word16)mq_modpow(psi,  e);
        izetas[i] = (word16)mq_modpow(ipsi, e);
    }
}

/* Forward negacyclic NTT, Cooley-Tukey: natural -> bit-reversed order. */
static void mq_ntt(word16* a, int n, const word16* zetas)
{
    int t = n, m, i, j;
    for (m = 1; m < n; m <<= 1) {
        t >>= 1;
        for (i = 0; i < m; i++) {
            word32 z = zetas[m + i];
            int start = 2 * i * t;
            for (j = start; j < start + t; j++) {
                word32 u = a[j];
                word32 v = (word32)(((word64)a[j + t] * z) % FALCON_Q);
                a[j]     = (word16)((u + v) % FALCON_Q);
                a[j + t] = (word16)((u + FALCON_Q - v) % FALCON_Q);
            }
        }
    }
}

/* Inverse negacyclic NTT, Gentleman-Sande: bit-reversed -> natural order. */
static void mq_intt(word16* a, int n, const word16* izetas)
{
    int t = 1, m, i, j;
    word32 ninv;
    for (m = n; m > 1; m >>= 1) {
        int h = m >> 1;
        int j1 = 0;
        for (i = 0; i < h; i++) {
            word32 z = izetas[h + i];
            int start = j1;
            for (j = start; j < start + t; j++) {
                word32 u = a[j];
                word32 v = a[j + t];
                a[j]     = (word16)((u + v) % FALCON_Q);
                a[j + t] = (word16)(((word64)((u + FALCON_Q - v) % FALCON_Q)
                                * z) % FALCON_Q);
            }
            j1 += 2 * t;
        }
        t <<= 1;
    }
    ninv = mq_modinv((word32)n);
    for (j = 0; j < n; j++) {
        a[j] = (word16)(((word64)a[j] * ninv) % FALCON_Q);
    }
}

/*
 * Compute the public key h = g/f mod (X^n+1) mod q. Returns 1 on success, or
 * 0 if f is not invertible modulo q (i.e. some NTT coefficient of f is zero),
 * in which case the (f,g) pair is rejected. -1 is returned on allocation
 * failure.
 */
static int falcon_compute_public(word16* h, const sword8* f, const sword8* g,
        unsigned logn, void* heap)
{
    int n = 1 << logn;
    int u;
    word32 psi;
    word16* zetas;
    word16* izetas;
    word16* ff;

    zetas = (word16*)XMALLOC((size_t)3 * (size_t)n * sizeof(word16), heap,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (zetas == NULL) {
        return -1;
    }
    izetas = zetas + n;
    ff = izetas + n;

    psi = mq_modpow(11 /* generator of Z_q^* */,
            (FALCON_Q - 1) / (word32)(2 * n));
    mq_build_tables((int)logn, psi, zetas, izetas);

    for (u = 0; u < n; u++) {
        int xf = f[u], xg = g[u];
        if (xf < 0) {
            xf += FALCON_Q;
        }
        if (xg < 0) {
            xg += FALCON_Q;
        }
        ff[u] = (word16)xf;
        h[u]  = (word16)xg;
    }
    mq_ntt(ff, n, zetas);
    mq_ntt(h, n, zetas);
    for (u = 0; u < n; u++) {
        if (ff[u] == 0) {
            XFREE(zetas, heap, DYNAMIC_TYPE_TMP_BUFFER);
            return 0;
        }
        h[u] = (word16)(((word64)h[u] * mq_modinv(ff[u])) % FALCON_Q);
    }
    mq_intt(h, n, izetas);

    XFREE(zetas, heap, DYNAMIC_TYPE_TMP_BUFFER);
    return 1;
}

/* ==================================================================== */
/* Polynomial <-> floating-point conversions (port of keygen.c).         */

/*
 * Convert a big-integer polynomial to floating-point. Each coefficient has
 * length flen words, and starts fstride words after the previous.
 */
static void poly_big_to_fp(fpr* d, const word32* f, size_t flen, size_t fstride,
        unsigned logn)
{
    size_t n, u;

    n = MKN(logn);
    if (flen == 0) {
        for (u = 0; u < n; u++) {
            d[u] = fpr_zero;
        }
        return;
    }
    for (u = 0; u < n; u++, f += fstride) {
        size_t v;
        word32 neg, cc, xm;
        fpr x, fsc;

        neg = -(f[flen - 1] >> 30);
        xm = neg >> 1;
        cc = neg & 1;
        x = fpr_zero;
        fsc = fpr_one;
        for (v = 0; v < flen; v++, fsc = fpr_mul(fsc, fpr_ptwo31)) {
            word32 w;

            w = (f[v] ^ xm) + cc;
            cc = w >> 31;
            w &= 0x7FFFFFFF;
            w -= (w << 1) & neg;
            x = fpr_add(x, fpr_mul(fpr_of(*(sword32*)&w), fsc));
        }
        d[u] = x;
    }
}

/*
 * Convert a polynomial to small integers. Source values are one-word signed
 * integers (31 bits). Returns 0 if any coefficient exceeds lim in absolute
 * value, 1 on success. Not constant-time (a failure discards the key).
 */
static int poly_big_to_small(sword8* d, const word32* s, int lim, unsigned logn)
{
    size_t n, u;

    n = MKN(logn);
    for (u = 0; u < n; u++) {
        sword32 z;

        z = zint_one_to_plain(s + u);
        if (z < -lim || z > lim) {
            return 0;
        }
        d[u] = (sword8)z;
    }
    return 1;
}

/*
 * Subtract k*f from F, where F, f and k are polynomials modulo X^N+1.
 * Coefficients of k are scaled by 2^sc, with sch = sc/31 and scl = sc%31.
 * Quadratic-time, space-efficient variant.
 */
static void poly_sub_scaled(word32* F, size_t Flen, size_t Fstride,
        const word32* f, size_t flen, size_t fstride,
        const sword32* k, word32 sch, word32 scl, unsigned logn)
{
    size_t n, u;

    n = MKN(logn);
    for (u = 0; u < n; u++) {
        sword32 kf;
        size_t v;
        word32* x;
        const word32* y;

        kf = -k[u];
        x = F + u * Fstride;
        y = f;
        for (v = 0; v < n; v++) {
            zint_add_scaled_mul_small(x, Flen, y, flen, kf, sch, scl);
            if (u + v == n - 1) {
                x = F;
                kf = -kf;
            }
            else {
                x += Fstride;
            }
            y += fstride;
        }
    }
}

/*
 * Subtract k*f from F using the NTT (for large degree / small integers).
 */
static void poly_sub_scaled_ntt(word32* F, size_t Flen, size_t Fstride,
        const word32* f, size_t flen, size_t fstride,
        const sword32* k, word32 sch, word32 scl, unsigned logn,
        word32* tmp)
{
    word32* gm;
    word32* igm;
    word32* fk;
    word32* t1;
    word32* x;
    const word32* y;
    size_t n, u, tlen;
    const falcon_small_prime* primes;

    n = MKN(logn);
    tlen = flen + 1;
    gm = tmp;
    igm = gm + MKN(logn);
    fk = igm + MKN(logn);
    t1 = fk + n * tlen;

    primes = FALCON_PRIMES;

    /* Compute k*f in fk[], in RNS notation. */
    for (u = 0; u < tlen; u++) {
        word32 p, p0i, R2, Rx;
        size_t v;

        p = primes[u].p;
        p0i = modp_ninv31(p);
        R2 = modp_R2(p, p0i);
        Rx = modp_Rx((unsigned)flen, p, p0i, R2);
        modp_mkgm2(gm, igm, logn, primes[u].g, p, p0i);

        for (v = 0; v < n; v++) {
            t1[v] = modp_set(k[v], p);
        }
        modp_NTT2(t1, gm, logn, p, p0i);
        for (v = 0, y = f, x = fk + u;
                v < n; v++, y += fstride, x += tlen) {
            *x = zint_mod_small_signed(y, flen, p, p0i, R2, Rx);
        }
        modp_NTT2_ext(fk + u, tlen, gm, logn, p, p0i);
        for (v = 0, x = fk + u; v < n; v++, x += tlen) {
            *x = modp_montymul(
                    modp_montymul(t1[v], *x, p, p0i), R2, p, p0i);
        }
        modp_iNTT2_ext(fk + u, tlen, igm, logn, p, p0i);
    }

    /* Rebuild k*f. */
    zint_rebuild_CRT(fk, tlen, tlen, n, primes, 1, t1);

    /* Subtract k*f, scaled, from F. */
    for (u = 0, x = F, y = fk; u < n; u++, x += Fstride, y += tlen) {
        zint_sub_scaled(x, Flen, y, tlen, sch, scl);
    }
}

/* ==================================================================== */
/* Discrete Gaussian sampler (port of keygen.c).                         */

/*
 * Discrete Gaussian distribution table for sigma = 1.17*sqrt(q/(2*N)),
 * q = 12289, N = 1024. Element 0 is P(x = 0); for k > 0 element k is
 * P(x >= k+1 | x > 0). Probabilities scaled by 2^63.
 */
static const word64 gauss_1024_12289[] = {
    1283868770400643928ULL,  6416574995475331444ULL,  4078260278032692663ULL,
    2353523259288686585ULL,  1227179971273316331ULL,   575931623374121527ULL,
    242543240509105209ULL,    91437049221049666ULL,    30799446349977173ULL,
    9255276791179340ULL,     2478152334826140ULL,      590642893610164ULL,
    125206034929641ULL,       23590435911403ULL,        3948334035941ULL,
    586753615614ULL,          77391054539ULL,           9056793210ULL,
    940121950ULL,             86539696ULL,              7062824ULL,
    510971ULL,                32764ULL,                 1862ULL,
    94ULL,                    4ULL,                    0ULL
};

/*
 * Generate one value with a Gaussian distribution centered on 0. Standard
 * deviation is 1.17*sqrt(q/(2*N)); the table is for N = 1024, and lower
 * dimensions sum several samples (sigma scales by sqrt(2)).
 */
static int mkgauss(falcon_rng* rng, unsigned logn)
{
    unsigned u, g;
    int val;

    g = 1U << (10 - logn);
    val = 0;
    for (u = 0; u < g; u++) {
        word64 r;
        word32 f, v, k, neg;

        /*
         * First value: 'neg' is a random sign; 'f' is set to 1 if the
         * generated value is zero.
         */
        r = get_rng_u64(rng);
        neg = (word32)(r >> 63);
        r &= ~((word64)1 << 63);
        f = (word32)((r - gauss_1024_12289[0]) >> 63);

        /*
         * Second value: locate the first table element not greater than
         * r (full table read for constant-time behaviour).
         */
        v = 0;
        r = get_rng_u64(rng);
        r &= ~((word64)1 << 63);
        for (k = 1; k < (word32)((sizeof gauss_1024_12289)
                / (sizeof gauss_1024_12289[0])); k++) {
            word32 t;

            t = (word32)((r - gauss_1024_12289[k]) >> 63) ^ 1;
            v |= k & -(t & (f ^ 1));
            f |= t;
        }

        /* Apply the sign (no effect when the value is zero). */
        v = (v ^ -neg) + neg;

        val += *(sword32*)&v;
    }
    return val;
}

/* ==================================================================== */
/* Length / bit-length parameter tables for the NTRU solver.             */

/*
 * MAX_BL_SMALL[depth]: word length of input f,g at that depth.
 * MAX_BL_LARGE[depth]: word length of the unreduced F,G at that depth.
 */
static const size_t MAX_BL_SMALL[] = {
    1, 1, 2, 2, 4, 7, 14, 27, 53, 106, 209
};
static const size_t MAX_BL_LARGE[] = {
    2, 2, 5, 7, 12, 21, 40, 78, 157, 308
};

/* Average / standard deviation (in bits) of the max coefficient size of
 * (f,g) per depth, used to compute Babai-reduction bounds. */
static const struct {
    int avg;
    int std;
} BITLENGTH[] = {
    {    4,  0 },
    {   11,  1 },
    {   24,  1 },
    {   50,  1 },
    {  102,  1 },
    {  202,  2 },
    {  401,  4 },
    {  794,  5 },
    { 1577,  8 },
    { 3138, 13 },
    { 6308, 25 }
};

/* Minimal recursion depth at which intermediate f,g are rebuilt. */
#define DEPTH_INT_FG   4

/*
 * Squared norm of a short vector, saturated to 2^32-1 if it reaches 2^31.
 */
static word32 poly_small_sqnorm(const sword8* f, unsigned logn)
{
    size_t n, u;
    word32 s, ng;

    n = MKN(logn);
    s = 0;
    ng = 0;
    for (u = 0; u < n; u++) {
        sword32 z;

        z = f[u];
        s += (word32)(z * z);
        ng |= s;
    }
    return s | -(ng >> 31);
}

/* Align 'data' upwards relative to 'base' to a multiple of sizeof(fpr). */
static fpr* align_fpr(void* base, void* data)
{
    byte* cb;
    byte* cd;
    size_t k, km;

    cb = (byte*)base;
    cd = (byte*)data;
    k = (size_t)(cd - cb);
    km = k % sizeof(fpr);
    if (km) {
        k += sizeof(fpr) - km;
    }
    return (fpr*)(cb + k);
}

/* Align 'data' upwards relative to 'base' to a multiple of sizeof(word32). */
static word32* align_u32(void* base, void* data)
{
    byte* cb;
    byte* cd;
    size_t k, km;

    cb = (byte*)base;
    cd = (byte*)data;
    k = (size_t)(cd - cb);
    km = k % sizeof(word32);
    if (km) {
        k += sizeof(word32) - km;
    }
    return (word32*)(cb + k);
}

/* Convert a small vector to floating point. */
static void poly_small_to_fp(fpr* x, const sword8* f, unsigned logn)
{
    size_t n, u;

    n = MKN(logn);
    for (u = 0; u < n; u++) {
        x[u] = fpr_of(f[u]);
    }
}

/*
 * Input: f,g of degree N = 2^logn ('depth' is used only for their lengths).
 * Output: f',g' of degree N/2 with the length for 'depth+1'. Values are in
 * RNS; input and/or output may also be in NTT.
 */
static void make_fg_step(word32* data, unsigned logn, unsigned depth,
        int in_ntt, int out_ntt)
{
    size_t n, hn, u;
    size_t slen, tlen;
    word32* fd;
    word32* gd;
    word32* fs;
    word32* gs;
    word32* gm;
    word32* igm;
    word32* t1;
    const falcon_small_prime* primes;

    n = (size_t)1 << logn;
    hn = n >> 1;
    slen = MAX_BL_SMALL[depth];
    tlen = MAX_BL_SMALL[depth + 1];
    primes = FALCON_PRIMES;

    fd = data;
    gd = fd + hn * tlen;
    fs = gd + hn * tlen;
    gs = fs + n * slen;
    gm = gs + n * slen;
    igm = gm + n;
    t1 = igm + n;
    XMEMMOVE(fs, data, 2 * n * slen * sizeof(*data));

    /* First slen words: use input values directly, applying inverse NTT. */
    for (u = 0; u < slen; u++) {
        word32 p, p0i, R2;
        size_t v;
        word32* x;

        p = primes[u].p;
        p0i = modp_ninv31(p);
        R2 = modp_R2(p, p0i);
        modp_mkgm2(gm, igm, logn, primes[u].g, p, p0i);

        for (v = 0, x = fs + u; v < n; v++, x += slen) {
            t1[v] = *x;
        }
        if (!in_ntt) {
            modp_NTT2(t1, gm, logn, p, p0i);
        }
        for (v = 0, x = fd + u; v < hn; v++, x += tlen) {
            word32 w0, w1;

            w0 = t1[(v << 1) + 0];
            w1 = t1[(v << 1) + 1];
            *x = modp_montymul(modp_montymul(w0, w1, p, p0i), R2, p, p0i);
        }
        if (in_ntt) {
            modp_iNTT2_ext(fs + u, slen, igm, logn, p, p0i);
        }

        for (v = 0, x = gs + u; v < n; v++, x += slen) {
            t1[v] = *x;
        }
        if (!in_ntt) {
            modp_NTT2(t1, gm, logn, p, p0i);
        }
        for (v = 0, x = gd + u; v < hn; v++, x += tlen) {
            word32 w0, w1;

            w0 = t1[(v << 1) + 0];
            w1 = t1[(v << 1) + 1];
            *x = modp_montymul(modp_montymul(w0, w1, p, p0i), R2, p, p0i);
        }
        if (in_ntt) {
            modp_iNTT2_ext(gs + u, slen, igm, logn, p, p0i);
        }

        if (!out_ntt) {
            modp_iNTT2_ext(fd + u, tlen, igm, logn - 1, p, p0i);
            modp_iNTT2_ext(gd + u, tlen, igm, logn - 1, p, p0i);
        }
    }

    /* fs and gs have been de-NTTized; rebuild via CRT. */
    zint_rebuild_CRT(fs, slen, slen, n, primes, 1, gm);
    zint_rebuild_CRT(gs, slen, slen, n, primes, 1, gm);

    /* Remaining words: modular reductions. */
    for (u = slen; u < tlen; u++) {
        word32 p, p0i, R2, Rx;
        size_t v;
        word32* x;

        p = primes[u].p;
        p0i = modp_ninv31(p);
        R2 = modp_R2(p, p0i);
        Rx = modp_Rx((unsigned)slen, p, p0i, R2);
        modp_mkgm2(gm, igm, logn, primes[u].g, p, p0i);
        for (v = 0, x = fs; v < n; v++, x += slen) {
            t1[v] = zint_mod_small_signed(x, slen, p, p0i, R2, Rx);
        }
        modp_NTT2(t1, gm, logn, p, p0i);
        for (v = 0, x = fd + u; v < hn; v++, x += tlen) {
            word32 w0, w1;

            w0 = t1[(v << 1) + 0];
            w1 = t1[(v << 1) + 1];
            *x = modp_montymul(modp_montymul(w0, w1, p, p0i), R2, p, p0i);
        }
        for (v = 0, x = gs; v < n; v++, x += slen) {
            t1[v] = zint_mod_small_signed(x, slen, p, p0i, R2, Rx);
        }
        modp_NTT2(t1, gm, logn, p, p0i);
        for (v = 0, x = gd + u; v < hn; v++, x += tlen) {
            word32 w0, w1;

            w0 = t1[(v << 1) + 0];
            w1 = t1[(v << 1) + 1];
            *x = modp_montymul(modp_montymul(w0, w1, p, p0i), R2, p, p0i);
        }

        if (!out_ntt) {
            modp_iNTT2_ext(fd + u, tlen, igm, logn - 1, p, p0i);
            modp_iNTT2_ext(gd + u, tlen, igm, logn - 1, p, p0i);
        }
    }
}

/*
 * Compute f and g at a specific depth, in RNS notation, stored at slen words
 * per integer. 0 <= depth <= logn.
 */
static void make_fg(word32* data, const sword8* f, const sword8* g,
        unsigned logn, unsigned depth, int out_ntt)
{
    size_t n, u;
    word32* ft;
    word32* gt;
    word32 p0;
    unsigned d;
    const falcon_small_prime* primes;

    n = MKN(logn);
    ft = data;
    gt = ft + n;
    primes = FALCON_PRIMES;
    p0 = primes[0].p;
    for (u = 0; u < n; u++) {
        ft[u] = modp_set(f[u], p0);
        gt[u] = modp_set(g[u], p0);
    }

    if (depth == 0 && out_ntt) {
        word32* gm;
        word32* igm;
        word32 p, p0i;

        p = primes[0].p;
        p0i = modp_ninv31(p);
        gm = gt + n;
        igm = gm + MKN(logn);
        modp_mkgm2(gm, igm, logn, primes[0].g, p, p0i);
        modp_NTT2(ft, gm, logn, p, p0i);
        modp_NTT2(gt, gm, logn, p, p0i);
        return;
    }

    if (depth == 0) {
        return;
    }

    if (depth == 1) {
        make_fg_step(data, logn, 0, 0, out_ntt);
        return;
    }

    make_fg_step(data, logn, 0, 0, 1);
    for (d = 1; d + 1 < depth; d++) {
        make_fg_step(data, logn - d, d, 1, 1);
    }
    make_fg_step(data, logn - depth + 1, depth - 1, 1, out_ntt);
}

/* ==================================================================== */
/* NTRU equation solver (recursive ntru_solve, port of keygen.c).        */

/*
 * Deepest level: compute the resultants of f and g with X^N+1, then apply
 * binary GCD. F and G are returned in tmp[]. Returns 1 on success.
 */
static int solve_NTRU_deepest(unsigned logn_top,
        const sword8* f, const sword8* g, word32* tmp)
{
    size_t len;
    word32* Fp;
    word32* Gp;
    word32* fp;
    word32* gp;
    word32* t1;
    word32 q;
    const falcon_small_prime* primes;

    len = MAX_BL_SMALL[logn_top];
    primes = FALCON_PRIMES;

    Fp = tmp;
    Gp = Fp + len;
    fp = Gp + len;
    gp = fp + len;
    t1 = gp + len;

    make_fg(fp, f, g, logn_top, logn_top, 0);

    /* Rebuild the (always nonnegative) resultants as big integers. */
    zint_rebuild_CRT(fp, len, len, 2, primes, 0, t1);

    /* Binary GCD (requires both inputs odd). */
    if (!zint_bezout(Gp, Fp, fp, gp, len, t1)) {
        return 0;
    }

    /* Multiply by q; a nonzero carry means overflow -> reject. */
    q = 12289;
    if (zint_mul_small(Fp, len, q) != 0
            || zint_mul_small(Gp, len, q) != 0) {
        return 0;
    }

    return 1;
}

/*
 * Intermediate level. On entry the F,G from the previous (deeper) level are
 * in tmp[]. May be invoked at the top level (depth = 0). Returns 1 on success.
 */
static int solve_NTRU_intermediate(unsigned logn_top,
        const sword8* f, const sword8* g, unsigned depth, word32* tmp)
{
    unsigned logn;
    size_t n, hn, slen, dlen, llen, rlen, FGlen, u;
    word32* Fd;
    word32* Gd;
    word32* Ft;
    word32* Gt;
    word32* ft;
    word32* gt;
    word32* t1;
    fpr* rt1;
    fpr* rt2;
    fpr* rt3;
    fpr* rt4;
    fpr* rt5;
    int scale_fg, minbl_fg, maxbl_fg, maxbl_FG, scale_k;
    word32* x;
    word32* y;
    sword32* k;
    const falcon_small_prime* primes;

    logn = logn_top - depth;
    n = (size_t)1 << logn;
    hn = n >> 1;

    slen = MAX_BL_SMALL[depth];
    dlen = MAX_BL_SMALL[depth + 1];
    llen = MAX_BL_LARGE[depth];
    primes = FALCON_PRIMES;

    /* Fd, Gd are the F,G from the deeper level. */
    Fd = tmp;
    Gd = Fd + dlen * hn;

    /* Compute input f,g for this level (RNS + NTT representation). */
    ft = Gd + dlen * hn;
    make_fg(ft, f, g, logn_top, depth, 1);

    /* Move f,g to make room for our unreduced candidate F,G. */
    Ft = tmp;
    Gt = Ft + n * llen;
    t1 = Gt + n * llen;
    XMEMMOVE(t1, ft, 2 * n * slen * sizeof(*ft));
    ft = t1;
    gt = ft + slen * n;
    t1 = gt + slen * n;

    /* Move Fd, Gd after f,g. */
    XMEMMOVE(t1, Fd, 2 * hn * dlen * sizeof(*Fd));
    Fd = t1;
    Gd = Fd + hn * dlen;

    /* Reduce Fd,Gd modulo all needed primes into Ft,Gt (n/2 values each). */
    for (u = 0; u < llen; u++) {
        word32 p, p0i, R2, Rx;
        size_t v;
        word32* xs;
        word32* ys;
        word32* xd;
        word32* yd;

        p = primes[u].p;
        p0i = modp_ninv31(p);
        R2 = modp_R2(p, p0i);
        Rx = modp_Rx((unsigned)dlen, p, p0i, R2);
        for (v = 0, xs = Fd, ys = Gd, xd = Ft + u, yd = Gt + u;
                v < hn;
                v++, xs += dlen, ys += dlen, xd += llen, yd += llen) {
            *xd = zint_mod_small_signed(xs, dlen, p, p0i, R2, Rx);
            *yd = zint_mod_small_signed(ys, dlen, p, p0i, R2, Rx);
        }
    }

    /* Compute F,G modulo sufficiently many small primes. */
    for (u = 0; u < llen; u++) {
        word32 p, p0i, R2;
        word32* gm;
        word32* igm;
        word32* fx;
        word32* gx;
        word32* Fp;
        word32* Gp;
        size_t v;

        p = primes[u].p;
        p0i = modp_ninv31(p);
        R2 = modp_R2(p, p0i);

        /* Once slen words are processed, f,g are de-NTTized -> rebuild. */
        if (u == slen) {
            zint_rebuild_CRT(ft, slen, slen, n, primes, 1, t1);
            zint_rebuild_CRT(gt, slen, slen, n, primes, 1, t1);
        }

        gm = t1;
        igm = gm + n;
        fx = igm + n;
        gx = fx + n;

        modp_mkgm2(gm, igm, logn, primes[u].g, p, p0i);

        if (u < slen) {
            for (v = 0, x = ft + u, y = gt + u;
                    v < n; v++, x += slen, y += slen) {
                fx[v] = *x;
                gx[v] = *y;
            }
            modp_iNTT2_ext(ft + u, slen, igm, logn, p, p0i);
            modp_iNTT2_ext(gt + u, slen, igm, logn, p, p0i);
        }
        else {
            word32 Rx;

            Rx = modp_Rx((unsigned)slen, p, p0i, R2);
            for (v = 0, x = ft, y = gt;
                    v < n; v++, x += slen, y += slen) {
                fx[v] = zint_mod_small_signed(x, slen, p, p0i, R2, Rx);
                gx[v] = zint_mod_small_signed(y, slen, p, p0i, R2, Rx);
            }
            modp_NTT2(fx, gm, logn, p, p0i);
            modp_NTT2(gx, gm, logn, p, p0i);
        }

        /* Get F',G' modulo p in NTT representation (degree n/2). */
        Fp = gx + n;
        Gp = Fp + hn;
        for (v = 0, x = Ft + u, y = Gt + u;
                v < hn; v++, x += llen, y += llen) {
            Fp[v] = *x;
            Gp[v] = *y;
        }
        modp_NTT2(Fp, gm, logn - 1, p, p0i);
        modp_NTT2(Gp, gm, logn - 1, p, p0i);

        for (v = 0, x = Ft + u, y = Gt + u; v < hn;
                v++, x += (llen << 1), y += (llen << 1)) {
            word32 ftA, ftB, gtA, gtB;
            word32 mFp, mGp;

            ftA = fx[(v << 1) + 0];
            ftB = fx[(v << 1) + 1];
            gtA = gx[(v << 1) + 0];
            gtB = gx[(v << 1) + 1];
            mFp = modp_montymul(Fp[v], R2, p, p0i);
            mGp = modp_montymul(Gp[v], R2, p, p0i);
            x[0] = modp_montymul(gtB, mFp, p, p0i);
            x[llen] = modp_montymul(gtA, mFp, p, p0i);
            y[0] = modp_montymul(ftB, mGp, p, p0i);
            y[llen] = modp_montymul(ftA, mGp, p, p0i);
        }
        modp_iNTT2_ext(Ft + u, llen, igm, logn, p, p0i);
        modp_iNTT2_ext(Gt + u, llen, igm, logn, p, p0i);
    }

    /* Rebuild F,G with the CRT. */
    zint_rebuild_CRT(Ft, llen, llen, n, primes, 1, t1);
    zint_rebuild_CRT(Gt, llen, llen, n, primes, 1, t1);

    /* Babai reduction (FFT-based) to bring F,G back to size slen. */
    rt3 = align_fpr(tmp, t1);
    rt4 = rt3 + n;
    rt5 = rt4 + n;
    rt1 = rt5 + (n >> 1);
    k = (sword32*)align_u32(tmp, rt1);
    rt2 = align_fpr(tmp, k + n);
    if (rt2 < (rt1 + n)) {
        rt2 = rt1 + n;
    }
    t1 = (word32*)k + n;

    if (slen > 10) {
        rlen = 10;
    }
    else {
        rlen = slen;
    }
    poly_big_to_fp(rt3, ft + slen - rlen, rlen, slen, logn);
    poly_big_to_fp(rt4, gt + slen - rlen, rlen, slen, logn);

    scale_fg = 31 * (int)(slen - rlen);

    minbl_fg = BITLENGTH[depth].avg - 6 * BITLENGTH[depth].std;
    maxbl_fg = BITLENGTH[depth].avg + 6 * BITLENGTH[depth].std;

    /* Compute 1/(f*adj(f)+g*adj(g)) in rt5; keep adj(f),adj(g) in rt3,rt4. */
    falcon_FFT(rt3, logn);
    falcon_FFT(rt4, logn);
    falcon_poly_invnorm2_fft(rt5, rt3, rt4, logn);
    falcon_poly_adj_fft(rt3, logn);
    falcon_poly_adj_fft(rt4, logn);

    FGlen = llen;
    maxbl_FG = 31 * (int)llen;
    scale_k = maxbl_FG - minbl_fg;

    for (;;) {
        int scale_FG, dc, new_maxbl_FG;
        word32 scl, sch;
        fpr pdc, pt;

        if (FGlen > 10) {
            rlen = 10;
        }
        else {
            rlen = FGlen;
        }
        scale_FG = 31 * (int)(FGlen - rlen);
        poly_big_to_fp(rt1, Ft + FGlen - rlen, rlen, llen, logn);
        poly_big_to_fp(rt2, Gt + FGlen - rlen, rlen, llen, logn);

        /* (F*adj(f)+G*adj(g))/(f*adj(f)+g*adj(g)) in rt2. */
        falcon_FFT(rt1, logn);
        falcon_FFT(rt2, logn);
        falcon_poly_mul_fft(rt1, rt3, logn);
        falcon_poly_mul_fft(rt2, rt4, logn);
        falcon_poly_add(rt2, rt1, logn);
        falcon_poly_mul_autoadj_fft(rt2, rt5, logn);
        falcon_iFFT(rt2, logn);

        dc = scale_k - scale_FG + scale_fg;

        if (dc < 0) {
            dc = -dc;
            pt = fpr_two;
        }
        else {
            pt = fpr_onehalf;
        }
        pdc = fpr_one;
        while (dc != 0) {
            if ((dc & 1) != 0) {
                pdc = fpr_mul(pdc, pt);
            }
            dc >>= 1;
            pt = fpr_sqr(pt);
        }

        for (u = 0; u < n; u++) {
            fpr xv;

            xv = fpr_mul(rt2[u], pdc);

            if (!fpr_lt(fpr_mtwo31m1, xv) || !fpr_lt(xv, fpr_ptwo31m1)) {
                return 0;
            }
            k[u] = (sword32)fpr_rint(xv);
        }

        sch = (word32)(scale_k / 31);
        scl = (word32)(scale_k % 31);
        if (depth <= DEPTH_INT_FG) {
            poly_sub_scaled_ntt(Ft, FGlen, llen, ft, slen, slen,
                    k, sch, scl, logn, t1);
            poly_sub_scaled_ntt(Gt, FGlen, llen, gt, slen, slen,
                    k, sch, scl, logn, t1);
        }
        else {
            poly_sub_scaled(Ft, FGlen, llen, ft, slen, slen,
                    k, sch, scl, logn);
            poly_sub_scaled(Gt, FGlen, llen, gt, slen, slen,
                    k, sch, scl, logn);
        }

        new_maxbl_FG = scale_k + maxbl_fg + 10;
        if (new_maxbl_FG < maxbl_FG) {
            maxbl_FG = new_maxbl_FG;
            if ((int)FGlen * 31 >= maxbl_FG + 31) {
                FGlen--;
            }
        }

        if (scale_k <= 0) {
            break;
        }
        scale_k -= 25;
        if (scale_k < 0) {
            scale_k = 0;
        }
    }

    /* Re-extend the sign if (F,G) length dropped below slen. */
    if (FGlen < slen) {
        for (u = 0; u < n; u++, Ft += llen, Gt += llen) {
            size_t v;
            word32 sw;

            sw = -(Ft[FGlen - 1] >> 30) >> 1;
            for (v = FGlen; v < slen; v++) {
                Ft[v] = sw;
            }
            sw = -(Gt[FGlen - 1] >> 30) >> 1;
            for (v = FGlen; v < slen; v++) {
                Gt[v] = sw;
            }
        }
    }

    /* Compress all values to slen words (expected output format). */
    for (u = 0, x = tmp, y = tmp;
            u < (n << 1); u++, x += slen, y += llen) {
        XMEMMOVE(x, y, slen * sizeof(*y));
    }
    return 1;
}

/*
 * Binary case, depth = 1. On entry F,G from the deeper level are in tmp[].
 * Returns 1 on success.
 */
static int solve_NTRU_binary_depth1(unsigned logn_top,
        const sword8* f, const sword8* g, word32* tmp)
{
    unsigned depth, logn;
    size_t n_top, n, hn, slen, dlen, llen, u;
    word32* Fd;
    word32* Gd;
    word32* Ft;
    word32* Gt;
    word32* ft;
    word32* gt;
    word32* t1;
    fpr* rt1;
    fpr* rt2;
    fpr* rt3;
    fpr* rt4;
    fpr* rt5;
    fpr* rt6;
    word32* x;
    word32* y;

    depth = 1;
    n_top = (size_t)1 << logn_top;
    logn = logn_top - depth;
    n = (size_t)1 << logn;
    hn = n >> 1;

    slen = MAX_BL_SMALL[depth];
    dlen = MAX_BL_SMALL[depth + 1];
    llen = MAX_BL_LARGE[depth];

    Fd = tmp;
    Gd = Fd + dlen * hn;
    Ft = Gd + dlen * hn;
    Gt = Ft + llen * n;

    /* Reduce Fd,Gd modulo all needed primes into Ft,Gt. */
    for (u = 0; u < llen; u++) {
        word32 p, p0i, R2, Rx;
        size_t v;
        word32* xs;
        word32* ys;
        word32* xd;
        word32* yd;

        p = FALCON_PRIMES[u].p;
        p0i = modp_ninv31(p);
        R2 = modp_R2(p, p0i);
        Rx = modp_Rx((unsigned)dlen, p, p0i, R2);
        for (v = 0, xs = Fd, ys = Gd, xd = Ft + u, yd = Gt + u;
                v < hn;
                v++, xs += dlen, ys += dlen, xd += llen, yd += llen) {
            *xd = zint_mod_small_signed(xs, dlen, p, p0i, R2, Rx);
            *yd = zint_mod_small_signed(ys, dlen, p, p0i, R2, Rx);
        }
    }

    /* Squeeze out Fd,Gd. */
    XMEMMOVE(tmp, Ft, llen * n * sizeof(word32));
    Ft = tmp;
    XMEMMOVE(Ft + llen * n, Gt, llen * n * sizeof(word32));
    Gt = Ft + llen * n;
    ft = Gt + llen * n;
    gt = ft + slen * n;
    t1 = gt + slen * n;

    /* Compute F,G modulo sufficiently many small primes. */
    for (u = 0; u < llen; u++) {
        word32 p, p0i, R2;
        word32* gm;
        word32* igm;
        word32* fx;
        word32* gx;
        word32* Fp;
        word32* Gp;
        unsigned e;
        size_t v;

        p = FALCON_PRIMES[u].p;
        p0i = modp_ninv31(p);
        R2 = modp_R2(p, p0i);

        gm = t1;
        igm = gm + n_top;
        fx = igm + n;
        gx = fx + n_top;
        modp_mkgm2(gm, igm, logn_top, FALCON_PRIMES[u].g, p, p0i);

        for (v = 0; v < n_top; v++) {
            fx[v] = modp_set(f[v], p);
            gx[v] = modp_set(g[v], p);
        }

        modp_NTT2(fx, gm, logn_top, p, p0i);
        modp_NTT2(gx, gm, logn_top, p, p0i);
        for (e = logn_top; e > logn; e--) {
            modp_poly_rec_res(fx, e, p, p0i, R2);
            modp_poly_rec_res(gx, e, p, p0i, R2);
        }

        /* Save space: from here we only need degree-n tables. */
        XMEMMOVE(gm + n, igm, n * sizeof(*igm));
        igm = gm + n;
        XMEMMOVE(igm + n, fx, n * sizeof(*ft));
        fx = igm + n;
        XMEMMOVE(fx + n, gx, n * sizeof(*gt));
        gx = fx + n;

        /* F',G' modulo p in NTT representation (degree n/2). */
        Fp = gx + n;
        Gp = Fp + hn;
        for (v = 0, x = Ft + u, y = Gt + u;
                v < hn; v++, x += llen, y += llen) {
            Fp[v] = *x;
            Gp[v] = *y;
        }
        modp_NTT2(Fp, gm, logn - 1, p, p0i);
        modp_NTT2(Gp, gm, logn - 1, p, p0i);

        for (v = 0, x = Ft + u, y = Gt + u;
                v < hn; v++, x += (llen << 1), y += (llen << 1)) {
            word32 ftA, ftB, gtA, gtB;
            word32 mFp, mGp;

            ftA = fx[(v << 1) + 0];
            ftB = fx[(v << 1) + 1];
            gtA = gx[(v << 1) + 0];
            gtB = gx[(v << 1) + 1];
            mFp = modp_montymul(Fp[v], R2, p, p0i);
            mGp = modp_montymul(Gp[v], R2, p, p0i);
            x[0] = modp_montymul(gtB, mFp, p, p0i);
            x[llen] = modp_montymul(gtA, mFp, p, p0i);
            y[0] = modp_montymul(ftB, mGp, p, p0i);
            y[llen] = modp_montymul(ftA, mGp, p, p0i);
        }
        modp_iNTT2_ext(Ft + u, llen, igm, logn, p, p0i);
        modp_iNTT2_ext(Gt + u, llen, igm, logn, p, p0i);

        /* Also save ft,gt up to size slen. */
        if (u < slen) {
            modp_iNTT2(fx, igm, logn, p, p0i);
            modp_iNTT2(gx, igm, logn, p, p0i);
            for (v = 0, x = ft + u, y = gt + u;
                    v < n; v++, x += slen, y += slen) {
                *x = fx[v];
                *y = gx[v];
            }
        }
    }

    /* Rebuild f,g,F,G with the CRT (consecutive in RAM). */
    zint_rebuild_CRT(Ft, llen, llen, n << 1, FALCON_PRIMES, 1, t1);
    zint_rebuild_CRT(ft, slen, slen, n << 1, FALCON_PRIMES, 1, t1);

    /* Babai reduction, specialized for depth 1 (single pass, no scaling). */
    rt1 = align_fpr(tmp, gt + slen * n);
    rt2 = rt1 + n;
    poly_big_to_fp(rt1, Ft, llen, llen, logn);
    poly_big_to_fp(rt2, Gt, llen, llen, logn);

    XMEMMOVE(tmp, ft, 2 * slen * n * sizeof(*ft));
    ft = tmp;
    gt = ft + slen * n;
    rt3 = align_fpr(tmp, gt + slen * n);
    XMEMMOVE(rt3, rt1, 2 * n * sizeof(*rt1));
    rt1 = rt3;
    rt2 = rt1 + n;
    rt3 = rt2 + n;
    rt4 = rt3 + n;

    poly_big_to_fp(rt3, ft, slen, slen, logn);
    poly_big_to_fp(rt4, gt, slen, slen, logn);

    XMEMMOVE(tmp, rt1, 4 * n * sizeof(*rt1));
    rt1 = (fpr*)tmp;
    rt2 = rt1 + n;
    rt3 = rt2 + n;
    rt4 = rt3 + n;

    /* rt1=F rt2=G rt3=f rt4=g; convert all to FFT. */
    falcon_FFT(rt1, logn);
    falcon_FFT(rt2, logn);
    falcon_FFT(rt3, logn);
    falcon_FFT(rt4, logn);

    rt5 = rt4 + n;
    rt6 = rt5 + n;
    falcon_poly_add_muladj_fft(rt5, rt1, rt2, rt3, rt4, logn);
    falcon_poly_invnorm2_fft(rt6, rt3, rt4, logn);
    falcon_poly_mul_autoadj_fft(rt5, rt6, logn);

    falcon_iFFT(rt5, logn);
    for (u = 0; u < n; u++) {
        fpr z;

        z = rt5[u];
        if (!fpr_lt(z, fpr_ptwo63m1) || !fpr_lt(fpr_mtwo63m1, z)) {
            return 0;
        }
        rt5[u] = fpr_of(fpr_rint(z));
    }
    falcon_FFT(rt5, logn);

    /* Subtract k*f from F, k*g from G. */
    falcon_poly_mul_fft(rt3, rt5, logn);
    falcon_poly_mul_fft(rt4, rt5, logn);
    falcon_poly_sub(rt1, rt3, logn);
    falcon_poly_sub(rt2, rt4, logn);
    falcon_iFFT(rt1, logn);
    falcon_iFFT(rt2, logn);

    /* Convert back F,G to integers. */
    Ft = tmp;
    Gt = Ft + n;
    rt3 = align_fpr(tmp, Gt + n);
    XMEMMOVE(rt3, rt1, 2 * n * sizeof(*rt1));
    rt1 = rt3;
    rt2 = rt1 + n;
    for (u = 0; u < n; u++) {
        Ft[u] = (word32)fpr_rint(rt1[u]);
        Gt[u] = (word32)fpr_rint(rt2[u]);
    }

    return 1;
}

/*
 * Binary case, depth = 0 (top level). On entry F,G from the deeper level are
 * in tmp[]. Returns 1 on success.
 */
static int solve_NTRU_binary_depth0(unsigned logn,
        const sword8* f, const sword8* g, word32* tmp)
{
    size_t n, hn, u;
    word32 p, p0i, R2;
    word32* Fp;
    word32* Gp;
    word32* t1;
    word32* t2;
    word32* t3;
    word32* t4;
    word32* t5;
    word32* gm;
    word32* igm;
    word32* ft;
    word32* gt;
    fpr* rt2;
    fpr* rt3;

    n = (size_t)1 << logn;
    hn = n >> 1;

    p = FALCON_PRIMES[0].p;
    p0i = modp_ninv31(p);
    R2 = modp_R2(p, p0i);

    Fp = tmp;
    Gp = Fp + hn;
    ft = Gp + hn;
    gt = ft + n;
    gm = gt + n;
    igm = gm + n;

    modp_mkgm2(gm, igm, logn, FALCON_PRIMES[0].g, p, p0i);

    /* Convert F',G' to NTT representation. */
    for (u = 0; u < hn; u++) {
        Fp[u] = modp_set(zint_one_to_plain(Fp + u), p);
        Gp[u] = modp_set(zint_one_to_plain(Gp + u), p);
    }
    modp_NTT2(Fp, gm, logn - 1, p, p0i);
    modp_NTT2(Gp, gm, logn - 1, p, p0i);

    /* Load f,g and convert to NTT. */
    for (u = 0; u < n; u++) {
        ft[u] = modp_set(f[u], p);
        gt[u] = modp_set(g[u], p);
    }
    modp_NTT2(ft, gm, logn, p, p0i);
    modp_NTT2(gt, gm, logn, p, p0i);

    /* Build the unreduced F,G in ft,gt. */
    for (u = 0; u < n; u += 2) {
        word32 ftA, ftB, gtA, gtB;
        word32 mFp, mGp;

        ftA = ft[u + 0];
        ftB = ft[u + 1];
        gtA = gt[u + 0];
        gtB = gt[u + 1];
        mFp = modp_montymul(Fp[u >> 1], R2, p, p0i);
        mGp = modp_montymul(Gp[u >> 1], R2, p, p0i);
        ft[u + 0] = modp_montymul(gtB, mFp, p, p0i);
        ft[u + 1] = modp_montymul(gtA, mFp, p, p0i);
        gt[u + 0] = modp_montymul(ftB, mGp, p, p0i);
        gt[u + 1] = modp_montymul(ftA, mGp, p, p0i);
    }
    modp_iNTT2(ft, igm, logn, p, p0i);
    modp_iNTT2(gt, igm, logn, p, p0i);

    Gp = Fp + n;
    t1 = Gp + n;
    XMEMMOVE(Fp, ft, 2 * n * sizeof(*ft));

    /* Babai reduction. */
    t2 = t1 + n;
    t3 = t2 + n;
    t4 = t3 + n;
    t5 = t4 + n;

    modp_mkgm2(t1, t2, logn, FALCON_PRIMES[0].g, p, p0i);

    modp_NTT2(Fp, t1, logn, p, p0i);
    modp_NTT2(Gp, t1, logn, p, p0i);

    /* Load f and adj(f) in t4,t5, convert to NTT. */
    t4[0] = t5[0] = modp_set(f[0], p);
    for (u = 1; u < n; u++) {
        t4[u] = modp_set(f[u], p);
        t5[n - u] = modp_set(-f[u], p);
    }
    modp_NTT2(t4, t1, logn, p, p0i);
    modp_NTT2(t5, t1, logn, p, p0i);

    /* F*adj(f) in t2, f*adj(f) in t3. */
    for (u = 0; u < n; u++) {
        word32 w;

        w = modp_montymul(t5[u], R2, p, p0i);
        t2[u] = modp_montymul(w, Fp[u], p, p0i);
        t3[u] = modp_montymul(w, t4[u], p, p0i);
    }

    /* Load g and adj(g) in t4,t5, convert to NTT. */
    t4[0] = t5[0] = modp_set(g[0], p);
    for (u = 1; u < n; u++) {
        t4[u] = modp_set(g[u], p);
        t5[n - u] = modp_set(-g[u], p);
    }
    modp_NTT2(t4, t1, logn, p, p0i);
    modp_NTT2(t5, t1, logn, p, p0i);

    /* Add G*adj(g) to t2, g*adj(g) to t3. */
    for (u = 0; u < n; u++) {
        word32 w;

        w = modp_montymul(t5[u], R2, p, p0i);
        t2[u] = modp_add(t2[u], modp_montymul(w, Gp[u], p, p0i), p);
        t3[u] = modp_add(t3[u], modp_montymul(w, t4[u], p, p0i), p);
    }

    /* Convert t2,t3 back to normal representation (normalized around 0). */
    modp_mkgm2(t1, t4, logn, FALCON_PRIMES[0].g, p, p0i);
    modp_iNTT2(t2, t4, logn, p, p0i);
    modp_iNTT2(t3, t4, logn, p, p0i);
    for (u = 0; u < n; u++) {
        t1[u] = (word32)modp_norm(t2[u], p);
        t2[u] = (word32)modp_norm(t3[u], p);
    }

    /* Divide t1 by t2 via the FFT (auto-adjoint denominator). */
    rt3 = align_fpr(tmp, t3);
    for (u = 0; u < n; u++) {
        rt3[u] = fpr_of(((sword32*)t2)[u]);
    }
    falcon_FFT(rt3, logn);
    rt2 = align_fpr(tmp, t2);
    XMEMMOVE(rt2, rt3, hn * sizeof(*rt3));

    rt3 = rt2 + hn;
    for (u = 0; u < n; u++) {
        rt3[u] = fpr_of(((sword32*)t1)[u]);
    }
    falcon_FFT(rt3, logn);

    falcon_poly_div_autoadj_fft(rt3, rt2, logn);
    falcon_iFFT(rt3, logn);
    for (u = 0; u < n; u++) {
        t1[u] = modp_set((sword32)fpr_rint(rt3[u]), p);
    }

    /* Compute F-k*f, G-k*g. */
    t2 = t1 + n;
    t3 = t2 + n;
    t4 = t3 + n;
    t5 = t4 + n;
    modp_mkgm2(t2, t3, logn, FALCON_PRIMES[0].g, p, p0i);
    for (u = 0; u < n; u++) {
        t4[u] = modp_set(f[u], p);
        t5[u] = modp_set(g[u], p);
    }
    modp_NTT2(t1, t2, logn, p, p0i);
    modp_NTT2(t4, t2, logn, p, p0i);
    modp_NTT2(t5, t2, logn, p, p0i);
    for (u = 0; u < n; u++) {
        word32 kw;

        kw = modp_montymul(t1[u], R2, p, p0i);
        Fp[u] = modp_sub(Fp[u], modp_montymul(kw, t4[u], p, p0i), p);
        Gp[u] = modp_sub(Gp[u], modp_montymul(kw, t5[u], p, p0i), p);
    }
    modp_iNTT2(Fp, t3, logn, p, p0i);
    modp_iNTT2(Gp, t3, logn, p, p0i);
    for (u = 0; u < n; u++) {
        Fp[u] = (word32)modp_norm(Fp[u], p);
        Gp[u] = (word32)modp_norm(Gp[u], p);
    }

    return 1;
}

/*
 * Solve the NTRU equation. Returns 1 on success, 0 on failure. G may be NULL
 * (then computed internally but not returned). If any coefficient of F or G
 * exceeds lim in absolute value, 0 is returned.
 */
static int solve_NTRU(unsigned logn, sword8* F, sword8* G,
        const sword8* f, const sword8* g, int lim, word32* tmp)
{
    size_t n, u;
    word32* ft;
    word32* gt;
    word32* Ft;
    word32* Gt;
    word32* gm;
    word32 p, p0i, r;
    const falcon_small_prime* primes;

    n = MKN(logn);

    if (!solve_NTRU_deepest(logn, f, g, tmp)) {
        return 0;
    }

    if (logn <= 2) {
        unsigned depth;

        depth = logn;
        while (depth-- > 0) {
            if (!solve_NTRU_intermediate(logn, f, g, depth, tmp)) {
                return 0;
            }
        }
    }
    else {
        unsigned depth;

        depth = logn;
        while (depth-- > 2) {
            if (!solve_NTRU_intermediate(logn, f, g, depth, tmp)) {
                return 0;
            }
        }
        if (!solve_NTRU_binary_depth1(logn, f, g, tmp)) {
            return 0;
        }
        if (!solve_NTRU_binary_depth0(logn, f, g, tmp)) {
            return 0;
        }
    }

    /* Use a temporary buffer for G if none provided. */
    if (G == NULL) {
        G = (sword8*)(tmp + 2 * n);
    }

    /* Final F,G are in tmp[], one word per coefficient (signed 31 bits). */
    if (!poly_big_to_small(F, tmp, lim, logn)
            || !poly_big_to_small(G, tmp + n, lim, logn)) {
        return 0;
    }

    /* Verify g*F - f*G = q modulo a small prime, using the NTT. */
    Gt = tmp;
    ft = Gt + n;
    gt = ft + n;
    Ft = gt + n;
    gm = Ft + n;

    primes = FALCON_PRIMES;
    p = primes[0].p;
    p0i = modp_ninv31(p);
    modp_mkgm2(gm, tmp, logn, primes[0].g, p, p0i);
    for (u = 0; u < n; u++) {
        Gt[u] = modp_set(G[u], p);
    }
    for (u = 0; u < n; u++) {
        ft[u] = modp_set(f[u], p);
        gt[u] = modp_set(g[u], p);
        Ft[u] = modp_set(F[u], p);
    }
    modp_NTT2(ft, gm, logn, p, p0i);
    modp_NTT2(gt, gm, logn, p, p0i);
    modp_NTT2(Ft, gm, logn, p, p0i);
    modp_NTT2(Gt, gm, logn, p, p0i);
    r = modp_montymul(12289, 1, p, p0i);
    for (u = 0; u < n; u++) {
        word32 z;

        z = modp_sub(modp_montymul(ft[u], Gt[u], p, p0i),
                modp_montymul(gt[u], Ft[u], p, p0i), p);
        if (z != r) {
            return 0;
        }
    }

    return 1;
}

/*
 * Generate a Gaussian-distributed polynomial whose resultant with phi is odd
 * (sum of coefficients is 1 mod 2).
 */
static void poly_small_mkgauss(falcon_rng* rng, sword8* f, unsigned logn)
{
    size_t n, u;
    unsigned mod2;

    n = MKN(logn);
    mod2 = 0;
    for (u = 0; u < n; u++) {
        int s;

        for (;;) {
            s = mkgauss(rng, logn);

            /* Abort on a PRNG failure: stale bytes would otherwise make the
             * parity constraint below unsatisfiable and spin forever. */
            if (rng->err != 0) {
                f[u] = 0;
                break;
            }

            /* Coefficient must fit in -127..+127. */
            if (s < -127 || s > 127) {
                continue;
            }

            /* The sum of all coefficients must be odd. */
            if (u == n - 1) {
                if ((mod2 ^ (unsigned)(s & 1)) == 0) {
                    continue;
                }
            }
            else {
                mod2 ^= (unsigned)(s & 1);
            }
            f[u] = (sword8)s;
            break;
        }
    }
}

/* ==================================================================== */
/* Public entry point.                                                   */

int falcon_keygen(WC_RNG* rng, sword8* f, sword8* g, sword8* F, sword8* G,
        word16* h, unsigned logn)
{
    size_t n;
    falcon_rng rc;
    byte* tmpbuf = NULL;
    word16* hwork = NULL;
    void* heap = NULL;
    size_t tmpSz;
    int ret;

    if (rng == NULL || f == NULL || g == NULL || F == NULL || G == NULL) {
        return BAD_FUNC_ARG;
    }
    if (logn < 1 || logn > 10) {
        return BAD_FUNC_ARG;
    }
    n = MKN(logn);

    /* Temporary buffer (sized per the reference; padded for fpr alignment). */
    tmpSz = FALCON_KEYGEN_TEMP[logn] + sizeof(fpr);
    tmpbuf = (byte*)XMALLOC(tmpSz, heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (tmpbuf == NULL) {
        return MEMORY_E;
    }

    /* We always need h to test invertibility; allocate scratch if caller
     * did not supply one. */
    if (h == NULL) {
        hwork = (word16*)XMALLOC(n * sizeof(word16), heap,
                DYNAMIC_TYPE_TMP_BUFFER);
        if (hwork == NULL) {
            XFREE(tmpbuf, heap, DYNAMIC_TYPE_TMP_BUFFER);
            return MEMORY_E;
        }
    }
    else {
        hwork = h;
    }

    ret = falcon_rng_init(&rc, rng, heap);
    if (ret != 0) {
        if (h == NULL) {
            XFREE(hwork, heap, DYNAMIC_TYPE_TMP_BUFFER);
        }
        XFREE(tmpbuf, heap, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    /*
     * Sample (f,g) until: coefficients are in bounds, (g,-f) norm and the
     * orthogonalized vector norm are under the 1.17*sqrt(q) bound, f is
     * invertible mod q, and the NTRU equation can be solved.
     */
    for (;;) {
        fpr* rt1;
        fpr* rt2;
        fpr* rt3;
        fpr bnorm;
        word32 normf, normg, norm;
        int lim;
        size_t u;
        int cp;

        poly_small_mkgauss(&rc, f, logn);
        poly_small_mkgauss(&rc, g, logn);
        if (rc.err != 0) {
            ret = rc.err;
            goto out;
        }

        /* Coefficient bound check (FALCON_COMP_TRIM encodability). */
        lim = 1 << (falcon_max_fg_bits[logn] - 1);
        for (u = 0; u < n; u++) {
            if (f[u] >= lim || f[u] <= -lim
                    || g[u] >= lim || g[u] <= -lim) {
                lim = -1;
                break;
            }
        }
        if (lim < 0) {
            continue;
        }

        /* Squared norm of (g,-f); bound is (1.17^2)*q = 16822.41 -> 16823. */
        normf = poly_small_sqnorm(f, logn);
        normg = poly_small_sqnorm(g, logn);
        norm = (normf + normg) | -((normf | normg) >> 31);
        if (norm >= 16823) {
            continue;
        }

        /* Orthogonalized vector norm. */
        rt1 = (fpr*)tmpbuf;
        rt2 = rt1 + n;
        rt3 = rt2 + n;
        poly_small_to_fp(rt1, f, logn);
        poly_small_to_fp(rt2, g, logn);
        falcon_FFT(rt1, logn);
        falcon_FFT(rt2, logn);
        falcon_poly_invnorm2_fft(rt3, rt1, rt2, logn);
        falcon_poly_adj_fft(rt1, logn);
        falcon_poly_adj_fft(rt2, logn);
        falcon_poly_mulconst(rt1, fpr_q, logn);
        falcon_poly_mulconst(rt2, fpr_q, logn);
        falcon_poly_mul_autoadj_fft(rt1, rt3, logn);
        falcon_poly_mul_autoadj_fft(rt2, rt3, logn);
        falcon_iFFT(rt1, logn);
        falcon_iFFT(rt2, logn);
        bnorm = fpr_zero;
        for (u = 0; u < n; u++) {
            bnorm = fpr_add(bnorm, fpr_sqr(rt1[u]));
            bnorm = fpr_add(bnorm, fpr_sqr(rt2[u]));
        }
        if (!fpr_lt(bnorm, fpr_bnorm_max)) {
            continue;
        }

        /* Public key h = g/f mod q; restart if f not invertible. */
        cp = falcon_compute_public(hwork, f, g, logn, heap);
        if (cp < 0) {
            ret = MEMORY_E;
            goto out;
        }
        if (cp == 0) {
            continue;
        }

        /* Solve the NTRU equation to get F,G. */
        lim = (1 << (falcon_max_FG_bits[logn] - 1)) - 1;
        if (!solve_NTRU(logn, F, G, f, g, lim, (word32*)tmpbuf)) {
            continue;
        }

        /* Success. */
        break;
    }

    ret = 0;

out:
    falcon_rng_free(&rc);
    if (h == NULL) {
        XFREE(hwork, heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    /* tmpbuf held the full secret-key expansion (f,g in RNS/NTT, F,G, FFT
     * images, Babai reduction vectors). */
    if (tmpbuf != NULL) {
        wc_ForceZero(tmpbuf, (word32)tmpSz);
    }
    XFREE(tmpbuf, heap, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

#endif /* HAVE_FALCON && !WOLFSSL_FALCON_VERIFY_ONLY */
