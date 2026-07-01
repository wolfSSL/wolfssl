/* wc_falcon.c
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

/* Native FN-DSA (FIPS 206 draft) / Falcon implementation for wolfCrypt.
 *
 * Phase 1: verification only (integer arithmetic, no floating point).
 * The signature/keygen paths and the floating-point primitive seam are added
 * in later phases. See wolfssl/wolfcrypt/falcon.h. */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if defined(HAVE_FALCON) && !defined(WOLF_CRYPTO_CB_ONLY_FALCON)

#include <wolfssl/wolfcrypt/falcon.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/sha3.h>
#ifndef WOLFSSL_FALCON_VERIFY_ONLY
    #include <wolfssl/wolfcrypt/wc_falcon_keygen.h>
    #include <wolfssl/wolfcrypt/wc_falcon_codec.h>
    #include <wolfssl/wolfcrypt/wc_falcon_sign.h>
#endif

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* Squared L2-norm acceptance bounds, indexed by logn. Values from the Falcon
 * specification / reference implementation (l2bound table). */
static const word32 falcon_l2bound[] = {
    /* 0..8 unused */ 0, 0, 0, 0, 0, 0, 0, 0, 0,
    34034726u,   /* logn = 9  (FN-DSA-512)  */
    70265242u    /* logn = 10 (FN-DSA-1024) */
};

/* ------------------------------------------------------------------------ */
/* Small modular helpers (correctness-first; hot paths are accelerated by the
 * generated per-arch backends in a later phase).                            */
/* ------------------------------------------------------------------------ */

static word32 falcon_modpow(word32 b, word32 e)
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

/* q is prime, so a^(q-2) == a^-1 (mod q). */
static word32 falcon_modinv(word32 a)
{
    return falcon_modpow(a, FALCON_Q - 2);
}

static unsigned int falcon_brv(unsigned int x, int bits)
{
    unsigned int r = 0;
    int i;
    for (i = 0; i < bits; i++) {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    return r;
}

/* Build bit-reversed twiddle tables for a degree-n negacyclic NTT.
 * psi is a primitive 2n-th root of unity (psi^n == -1 mod q). */
static void falcon_build_tables(int logn, word32 psi, word16* zetas,
        word16* izetas)
{
    int n = 1 << logn;
    word32 ipsi = falcon_modinv(psi);
    int i;
    for (i = 0; i < n; i++) {
        unsigned int e = falcon_brv((unsigned int)i, logn);
        zetas[i]  = (word16)falcon_modpow(psi,  e);
        izetas[i] = (word16)falcon_modpow(ipsi, e);
    }
}

/* Twiddle tables are identical for every verification at a given level, so
 * compute them once and cache them (the previous code rebuilt them per call
 * via O(n) modular exponentiations — the dominant verify cost). The lazy-init
 * race is benign: the values are deterministic, so concurrent first-callers
 * write identical data. */
static word16 falcon_zetas_l1[FALCON_LEVEL1_N];
static word16 falcon_izetas_l1[FALCON_LEVEL1_N];
static word16 falcon_zetas_l5[FALCON_LEVEL5_N];
static word16 falcon_izetas_l5[FALCON_LEVEL5_N];
static volatile int falcon_tab_l1 = 0;
static volatile int falcon_tab_l5 = 0;

static void falcon_get_tables(unsigned logn, const word16** zetas,
        const word16** izetas)
{
    if (logn == FALCON_LEVEL1_LOGN) {
        if (!falcon_tab_l1) {
            word32 psi = falcon_modpow(11, (FALCON_Q - 1) /
                    (2 * FALCON_LEVEL1_N));
            falcon_build_tables(FALCON_LEVEL1_LOGN, psi, falcon_zetas_l1,
                    falcon_izetas_l1);
            falcon_tab_l1 = 1;
        }
        *zetas = falcon_zetas_l1;
        *izetas = falcon_izetas_l1;
    }
    else {
        if (!falcon_tab_l5) {
            word32 psi = falcon_modpow(11, (FALCON_Q - 1) /
                    (2 * FALCON_LEVEL5_N));
            falcon_build_tables(FALCON_LEVEL5_LOGN, psi, falcon_zetas_l5,
                    falcon_izetas_l5);
            falcon_tab_l5 = 1;
        }
        *zetas = falcon_zetas_l5;
        *izetas = falcon_izetas_l5;
    }
}

/* Division-free modular reductions for the NTT. Hardware integer division is
 * absent on Cortex-M0/M3 (a slow library call) and multi-cycle elsewhere, so
 * the inner loops use a Barrett multiply + a conditional subtract instead of
 * '%'. Both are bit-identical to a mod q and constant-time.
 *   falcon_barrett: a in [0, q^2) -> [0, q)  (349496 = floor(2^32 / q)).
 *   falcon_csub:    a in [0, 2q)  -> [0, q). */
static WC_INLINE word32 falcon_barrett(word32 a)
{
    word32 t = (word32)(((word64)a * 349496u) >> 32);
    a -= t * FALCON_Q;
    a -= FALCON_Q & (word32)((sword32)(FALCON_Q - 1 - a) >> 31);
    return a;
}
static WC_INLINE word32 falcon_csub(word32 a)
{
    a -= FALCON_Q & (word32)((sword32)(FALCON_Q - 1 - a) >> 31);
    return a;
}

/* Forward negacyclic NTT, Cooley-Tukey: natural -> bit-reversed order. */
static void falcon_ntt(word16* a, int n, const word16* zetas)
{
    int t = n, m, i, j;
    for (m = 1; m < n; m <<= 1) {
        t >>= 1;
        for (i = 0; i < m; i++) {
            word32 z = zetas[m + i];
            int start = 2 * i * t;
            for (j = start; j < start + t; j++) {
                word32 u = a[j];
                word32 v = falcon_barrett((word32)a[j + t] * z);
                a[j]     = (word16)falcon_csub(u + v);
                a[j + t] = (word16)falcon_csub(u + FALCON_Q - v);
            }
        }
    }
}

/* Inverse negacyclic NTT, Gentleman-Sande: bit-reversed -> natural order. */
static void falcon_intt(word16* a, int n, const word16* izetas)
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
                word32 w = falcon_csub(u + FALCON_Q - v);
                a[j]     = (word16)falcon_csub(u + v);
                a[j + t] = (word16)falcon_barrett(w * z);
            }
            j1 += 2 * t;
        }
        t <<= 1;
    }
    ninv = falcon_modinv((word32)n);
    for (j = 0; j < n; j++) {
        a[j] = (word16)falcon_barrett((word32)a[j] * ninv);
    }
}

/* ------------------------------------------------------------------------ */
/* Codec                                                                     */
/* ------------------------------------------------------------------------ */

/* Decode the public key polynomial h: n coefficients packed 14 bits each,
 * most-significant bit first. Each coefficient must be < q. Returns the number
 * of input bytes consumed, or a negative wolfCrypt error. */
static int falcon_modq_decode(const byte* in, word32 inLen, word16* x,
        unsigned logn)
{
    size_t n = (size_t)1 << logn;
    size_t need = ((n * 14) + 7) >> 3;
    word32 acc = 0;
    int acc_bits = 0;
    size_t in_i = 0, out_i = 0;

    if (inLen < need) {
        return BUFFER_E;
    }
    while (out_i < n) {
        acc = (acc << 8) | in[in_i++];
        acc_bits += 8;
        if (acc_bits >= 14) {
            word32 w;
            acc_bits -= 14;
            w = (acc >> acc_bits) & 0x3FFF;
            if (w >= FALCON_Q) {
                return ASN_PARSE_E;
            }
            x[out_i++] = (word16)w;
        }
    }
    /* Unused trailing bits in the final byte must be zero. */
    if ((acc & (((word32)1 << acc_bits) - 1)) != 0) {
        return ASN_PARSE_E;
    }
    return (int)need;
}

/* Decode the compressed signature polynomial s2 (Golomb-Rice, k=7). Returns
 * the number of input bytes consumed, or a negative wolfCrypt error. Ported
 * from the Falcon reference comp_decode. */
static int falcon_comp_decode(const byte* in, word32 inLen, sword16* x,
        unsigned logn)
{
    size_t n = (size_t)1 << logn;
    word32 acc = 0;
    unsigned int acc_len = 0;
    size_t v = 0, u;

    for (u = 0; u < n; u++) {
        unsigned int b, s, mag;

        if (v >= inLen) {
            return BUFFER_E;
        }
        acc = (acc << 8) | (word32)in[v++];
        b = acc >> acc_len;
        s = b & 128;
        mag = b & 127;

        /* High bits: unary-coded run of zeros terminated by a one bit. */
        for (;;) {
            if (acc_len == 0) {
                if (v >= inLen) {
                    return BUFFER_E;
                }
                acc = (acc << 8) | (word32)in[v++];
                acc_len = 8;
            }
            acc_len--;
            if (((acc >> acc_len) & 1) != 0) {
                break;
            }
            mag += 128;
            if (mag > 2047) {
                return ASN_PARSE_E;
            }
        }
        /* Negative zero is not a valid encoding. */
        if (s != 0 && mag == 0) {
            return ASN_PARSE_E;
        }
        x[u] = (sword16)(s != 0 ? -(int)mag : (int)mag);
    }
    /* Unused trailing bits must be zero. */
    if ((acc & (((word32)1 << acc_len) - 1)) != 0) {
        return ASN_PARSE_E;
    }
    return (int)v;
}

/* hash-to-point (variable time; inputs are public). Absorbs nonce||msg into a
 * fresh SHAKE256 context and samples n coefficients in [0,q) by rejection. */
static int falcon_hash_to_point(const byte* nonce, const byte* msg,
        word32 msgLen, word16* c, unsigned logn, void* heap)
{
    wc_Shake shake;
    byte block[WC_SHA3_256_BLOCK_SIZE];
    byte* absorbBuf;
    size_t n = (size_t)1 << logn;
    size_t i = 0;
    int bi = WC_SHA3_256_BLOCK_SIZE;   /* force an initial squeeze */
    int ret;
    int shakeInit = 0;

    /* Guard against size_t wrap of (nonce || msg) on 32-bit targets. */
    if (msgLen > (word32)(0xFFFFFFFFUL - FALCON_NONCE_SIZE)) {
        return BAD_FUNC_ARG;
    }
    absorbBuf = (byte*)XMALLOC((size_t)FALCON_NONCE_SIZE + msgLen, heap,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (absorbBuf == NULL) {
        return MEMORY_E;
    }
    XMEMCPY(absorbBuf, nonce, FALCON_NONCE_SIZE);
    if (msgLen > 0) {
        XMEMCPY(absorbBuf + FALCON_NONCE_SIZE, msg, msgLen);
    }

    ret = wc_InitShake256(&shake, heap, INVALID_DEVID);
    if (ret == 0) {
        shakeInit = 1;
        ret = wc_Shake256_Absorb(&shake, absorbBuf,
                (word32)(FALCON_NONCE_SIZE + msgLen));
    }

    while (ret == 0 && i < n) {
        word32 w;
        if (bi >= WC_SHA3_256_BLOCK_SIZE) {
            ret = wc_Shake256_SqueezeBlocks(&shake, block, 1);
            if (ret != 0) {
                break;
            }
            bi = 0;
        }
        w = ((word32)block[bi] << 8) | (word32)block[bi + 1];
        bi += 2;
        /* 61445 == 5 * q: keeps the distribution uniform mod q. */
        if (w < 61445u) {
            while (w >= FALCON_Q) {
                w -= FALCON_Q;
            }
            c[i++] = (word16)w;
        }
    }

    /* Only free the SHAKE context if it was successfully initialized
     * (wc_Shake256_Free touches device state in async builds). */
    if (shakeInit) {
        wc_Shake256_Free(&shake);
    }
    /* nonce || msg are public; no zeroization needed. */
    XFREE(absorbBuf, heap, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* Center x (given in [0,q)) into (-q/2, q/2]. */
static WC_INLINE sword32 falcon_center(word32 x)
{
    sword32 r = (sword32)x;
    if (r > (FALCON_Q >> 1)) {
        r -= FALCON_Q;
    }
    return r;
}

/* ------------------------------------------------------------------------ */
/* Public API                                                                */
/* ------------------------------------------------------------------------ */

static int falcon_level_params(byte level, unsigned* logn, int* n, word32* pubSz)
{
    switch (level) {
        case FALCON_LEVEL1:
            *logn = FALCON_LEVEL1_LOGN;
            *n = FALCON_LEVEL1_N;
            *pubSz = FALCON_LEVEL1_PUB_KEY_SIZE;
            return 0;
        case FALCON_LEVEL5:
            *logn = FALCON_LEVEL5_LOGN;
            *n = FALCON_LEVEL5_N;
            *pubSz = FALCON_LEVEL5_PUB_KEY_SIZE;
            return 0;
        default:
            return BAD_FUNC_ARG;
    }
}

#ifndef WOLFSSL_FALCON_VERIFY_ONLY
int falcon_native_make_key(falcon_key* key, WC_RNG* rng)
{
    int ret = 0;
    unsigned logn = 0;
    int n = 0;
    word32 pubSz = 0, keySz = 0;
    sword8 *f = NULL, *g = NULL, *F = NULL, *G = NULL;
    word16* h = NULL;
    void* heap;

    if (key == NULL || rng == NULL) {
        return BAD_FUNC_ARG;
    }
    if (falcon_level_params(key->level, &logn, &n, &pubSz) != 0) {
        return BAD_FUNC_ARG;
    }
    keySz = (key->level == FALCON_LEVEL1) ? FALCON_LEVEL1_KEY_SIZE
                                            : FALCON_LEVEL5_KEY_SIZE;
    heap = key->heap;

    f = (sword8*)XMALLOC((size_t)n, heap, DYNAMIC_TYPE_TMP_BUFFER);
    g = (sword8*)XMALLOC((size_t)n, heap, DYNAMIC_TYPE_TMP_BUFFER);
    F = (sword8*)XMALLOC((size_t)n, heap, DYNAMIC_TYPE_TMP_BUFFER);
    G = (sword8*)XMALLOC((size_t)n, heap, DYNAMIC_TYPE_TMP_BUFFER);
    h = (word16*)XMALLOC(sizeof(word16) * (size_t)n, heap,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (f == NULL || g == NULL || F == NULL || G == NULL || h == NULL) {
        ret = MEMORY_E;
        goto out;
    }

    ret = falcon_keygen(rng, f, g, F, G, h, logn);
    if (ret != 0) {
        goto out;
    }

    /* Encode the public key: header byte then 14-bit packed h. */
    key->p[0] = (byte)(FALCON_PUB_HEAD | logn);
    if (falcon_modq_encode(key->p + 1, (size_t)(pubSz - 1), h, logn) == 0) {
        ret = BAD_FUNC_ARG;
        goto out;
    }

    /* Encode the secret key (header | f | g | F) into key->k. */
    if (falcon_privkey_encode(key->k, keySz, f, g, F, logn) != (size_t)keySz) {
        ret = BAD_FUNC_ARG;
        goto out;
    }

    key->pubKeySet = 1;
    key->prvKeySet = 1;

out:
    if (f != NULL) { ForceZero(f, (word32)n); XFREE(f, heap, DYNAMIC_TYPE_TMP_BUFFER); }
    if (g != NULL) { ForceZero(g, (word32)n); XFREE(g, heap, DYNAMIC_TYPE_TMP_BUFFER); }
    if (F != NULL) { ForceZero(F, (word32)n); XFREE(F, heap, DYNAMIC_TYPE_TMP_BUFFER); }
    if (G != NULL) { ForceZero(G, (word32)n); XFREE(G, heap, DYNAMIC_TYPE_TMP_BUFFER); }
    if (h != NULL) { XFREE(h, heap, DYNAMIC_TYPE_TMP_BUFFER); }
    return ret;
}

int falcon_native_sign_msg(const byte* in, word32 inLen, byte* out, word32* outLen,
        falcon_key* key, WC_RNG* rng)
{
    int ret = 0;
    unsigned logn = 0;
    int n = 0;
    word32 pubSz = 0, keySz = 0, sigMax = 0;
    sword8 *f = NULL, *g = NULL, *F = NULL, *G = NULL;
    word16* c = NULL;
    sword16* s2 = NULL;
    fpr *expanded = NULL, *tmp = NULL;
    falcon_sampler_ctx spc;
    byte nonce[FALCON_NONCE_SIZE];
    void* heap;
    int attempt, haveSpc = 0;
    size_t clen = 0;

    if ((in == NULL && inLen != 0) || out == NULL || outLen == NULL ||
            key == NULL || rng == NULL) {
        return BAD_FUNC_ARG;
    }
    if (!key->prvKeySet) {
        return BAD_FUNC_ARG;
    }
    if (falcon_level_params(key->level, &logn, &n, &pubSz) != 0) {
        return BAD_FUNC_ARG;
    }
    keySz  = (key->level == FALCON_LEVEL1) ? FALCON_LEVEL1_KEY_SIZE
                                             : FALCON_LEVEL5_KEY_SIZE;
    sigMax = (key->level == FALCON_LEVEL1) ? FALCON_LEVEL1_SIG_SIZE
                                             : FALCON_LEVEL5_SIG_SIZE;
    if (*outLen < sigMax) {
        *outLen = sigMax;
        return BUFFER_E;
    }
    heap = key->heap;

    f  = (sword8*)XMALLOC((size_t)n, heap, DYNAMIC_TYPE_TMP_BUFFER);
    g  = (sword8*)XMALLOC((size_t)n, heap, DYNAMIC_TYPE_TMP_BUFFER);
    F  = (sword8*)XMALLOC((size_t)n, heap, DYNAMIC_TYPE_TMP_BUFFER);
    G  = (sword8*)XMALLOC((size_t)n, heap, DYNAMIC_TYPE_TMP_BUFFER);
    c  = (word16*)XMALLOC(sizeof(word16) * (size_t)n, heap, DYNAMIC_TYPE_TMP_BUFFER);
    s2 = (sword16*)XMALLOC(sizeof(sword16) * (size_t)n, heap, DYNAMIC_TYPE_TMP_BUFFER);
    expanded = (fpr*)XMALLOC(sizeof(fpr) * FALCON_EXPANDED_KEY_FPR(logn), heap,
            DYNAMIC_TYPE_TMP_BUFFER);
    tmp = (fpr*)XMALLOC(sizeof(fpr) * FALCON_SIGN_TMP_FPR(logn), heap,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (f == NULL || g == NULL || F == NULL || G == NULL || c == NULL ||
            s2 == NULL || expanded == NULL || tmp == NULL) {
        ret = MEMORY_E;
        goto out;
    }

    /* Decode the secret basis, recompute G, expand to the ffLDL tree. */
    ret = falcon_privkey_decode(key->k, keySz, f, g, F, logn);
    if (ret != 0) {
        goto out;
    }
    ret = falcon_complete_private(G, f, g, F, logn);
    if (ret != 0) {
        goto out;
    }
    ret = falcon_expand_privkey(expanded, f, g, F, G, logn);
    if (ret != 0) {
        goto out;
    }
    ret = falcon_sampler_init(&spc, (int)logn, rng);
    if (ret != 0) {
        goto out;
    }
    haveSpc = 1;

    /* Each attempt draws a fresh nonce and samples a signature; retry if the
     * compressed form does not fit the level's maximum length. */
    for (attempt = 0; attempt < 32; attempt++) {
        ret = wc_RNG_GenerateBlock(rng, nonce, FALCON_NONCE_SIZE);
        if (ret != 0) {
            goto out;
        }
        ret = falcon_hash_to_point(nonce, in, inLen, c, logn, heap);
        if (ret != 0) {
            goto out;
        }
        ret = falcon_sign_core(&spc, expanded, c, s2, tmp, logn);
        if (ret != 0) {
            goto out;
        }
        out[0] = (byte)(FALCON_SIG_HEAD_COMPRESSED | logn);
        XMEMCPY(out + 1, nonce, FALCON_NONCE_SIZE);
        clen = falcon_comp_encode(out + 1 + FALCON_NONCE_SIZE,
                (size_t)(*outLen - 1 - FALCON_NONCE_SIZE), s2, logn);
        if (clen != 0) {
            break;
        }
    }
    if (clen == 0) {
        ret = BUFFER_E;
        goto out;
    }
    *outLen = (word32)(1 + FALCON_NONCE_SIZE + clen);

out:
    /* Always zeroize: the SHAKE sponge may hold seed-derived state even if
     * falcon_sampler_init failed after absorbing the seed. */
    (void)haveSpc;
    ForceZero(&spc, sizeof(spc));
    if (f != NULL)     { ForceZero(f, (word32)n); XFREE(f, heap, DYNAMIC_TYPE_TMP_BUFFER); }
    if (g != NULL)     { ForceZero(g, (word32)n); XFREE(g, heap, DYNAMIC_TYPE_TMP_BUFFER); }
    if (F != NULL)     { ForceZero(F, (word32)n); XFREE(F, heap, DYNAMIC_TYPE_TMP_BUFFER); }
    if (G != NULL)     { ForceZero(G, (word32)n); XFREE(G, heap, DYNAMIC_TYPE_TMP_BUFFER); }
    if (s2 != NULL)    XFREE(s2, heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (c != NULL)     XFREE(c, heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (expanded != NULL) {
        ForceZero(expanded, (word32)(sizeof(fpr) * FALCON_EXPANDED_KEY_FPR(logn)));
        XFREE(expanded, heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (tmp != NULL) {
        ForceZero(tmp, (word32)(sizeof(fpr) * FALCON_SIGN_TMP_FPR(logn)));
        XFREE(tmp, heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    return ret;
}
#endif /* !WOLFSSL_FALCON_VERIFY_ONLY */

int falcon_native_verify_msg(const byte* sig, word32 sigLen, const byte* msg,
        word32 msgLen, int* res, falcon_key* key)
{
    int ret = 0;
    unsigned logn = 0;
    int n = 0;
    word32 pubSz = 0;
    const byte* sigData;
    word32 sigDataLen;
    word16* h = NULL;
    word16* c = NULL;
    word16* t = NULL;
    const word16* zetas = NULL;
    const word16* izetas = NULL;
    sword16* s2 = NULL;
    void* heap;

    if (sig == NULL || res == NULL || key == NULL ||
            (msg == NULL && msgLen != 0)) {
        return BAD_FUNC_ARG;
    }
    *res = 0;
    if (!key->pubKeySet) {
        return BAD_FUNC_ARG;
    }
    if (falcon_level_params(key->level, &logn, &n, &pubSz) != 0) {
        return BAD_FUNC_ARG;
    }
    heap = key->heap;

    /* Signature framing: 1 header byte | 40-byte nonce | compressed s2. The
     * compressed encoding is variable length but bounded by the level's max. */
    if (sigLen < (word32)(1 + FALCON_NONCE_SIZE + 1)) {
        return BUFFER_E;
    }
    if (sigLen > (word32)(key->level == FALCON_LEVEL1 ?
            FALCON_LEVEL1_SIG_SIZE : FALCON_LEVEL5_SIG_SIZE)) {
        return BUFFER_E;
    }
    if (sig[0] != (byte)(FALCON_SIG_HEAD_COMPRESSED | logn)) {
        return ASN_PARSE_E;
    }
    sigData = sig + 1 + FALCON_NONCE_SIZE;
    sigDataLen = sigLen - 1 - FALCON_NONCE_SIZE;

    h      = (word16*)XMALLOC(sizeof(word16) * n, heap, DYNAMIC_TYPE_TMP_BUFFER);
    c      = (word16*)XMALLOC(sizeof(word16) * n, heap, DYNAMIC_TYPE_TMP_BUFFER);
    t      = (word16*)XMALLOC(sizeof(word16) * n, heap, DYNAMIC_TYPE_TMP_BUFFER);
    s2     = (sword16*)XMALLOC(sizeof(sword16) * n, heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (h == NULL || c == NULL || t == NULL || s2 == NULL) {
        ret = MEMORY_E;
        goto out;
    }

    /* Decode public key h (skip the 0x0n header byte). */
    if (key->p[0] != (byte)(FALCON_PUB_HEAD | logn)) {
        ret = ASN_PARSE_E;
        goto out;
    }
    {
        int rc = falcon_modq_decode(key->p + 1, pubSz - 1, h, logn);
        if (rc < 0) {
            ret = rc;
            goto out;
        }
    }

    /* Decode compressed s2; the encoding must consume the whole buffer. */
    {
        int rc = falcon_comp_decode(sigData, sigDataLen, s2, logn);
        if (rc < 0) {
            ret = rc;
            goto out;
        }
        if ((word32)rc != sigDataLen) {
            ret = ASN_PARSE_E;
            goto out;
        }
    }

    /* c = HashToPoint(nonce || msg). */
    ret = falcon_hash_to_point(sig + 1, msg, msgLen, c, logn, heap);
    if (ret != 0) {
        goto out;
    }

    /* t = s2 * h mod (x^n + 1) mod q, via NTT. Twiddle tables are cached. */
    falcon_get_tables(logn, &zetas, &izetas);
    {
        int i;
        for (i = 0; i < n; i++) {
            sword32 v = s2[i];
            if (v < 0) {
                v += FALCON_Q;
            }
            t[i] = (word16)v;
        }
    }
    falcon_ntt(t, n, zetas);
    falcon_ntt(h, n, zetas);
    {
        int i;
        for (i = 0; i < n; i++) {
            t[i] = (word16)falcon_barrett((word32)t[i] * h[i]);
        }
    }
    falcon_intt(t, n, izetas);

    /* s1 = c - s2*h mod q (centered); accept iff ||(s1,s2)||^2 <= bound. */
    {
        word64 norm = 0;
        int i;
        for (i = 0; i < n; i++) {
            word32 d = falcon_csub(c[i] + FALCON_Q - t[i]);
            sword32 s1c = falcon_center(d);
            sword32 s2c = s2[i];
            norm += (word64)((sword64)s1c * s1c);
            norm += (word64)((sword64)s2c * s2c);
        }
        if (norm <= (word64)falcon_l2bound[logn]) {
            *res = 1;
        }
    }

out:
    if (h != NULL)      XFREE(h, heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (c != NULL)      XFREE(c, heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (t != NULL)      XFREE(t, heap, DYNAMIC_TYPE_TMP_BUFFER);
    /* zetas/izetas point at static caches; not freed. */
    if (s2 != NULL)     XFREE(s2, heap, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}


#endif /* HAVE_FALCON */
