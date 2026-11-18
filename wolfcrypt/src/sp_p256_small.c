/* sp_p256_small.c
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

/* Size-first P-256 for WOLFSSL_SP_P256_SMALL: Montgomery arithmetic on eight
 * 32-bit words, complete projective addition (Renes-Costello-Batina 2016,
 * a = -3) and a Montgomery ladder over all 256 scalar bits. */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if defined(WOLFSSL_SP_P256_SMALL) && defined(WOLFSSL_HAVE_SP_ECC)

#include <wolfssl/wolfcrypt/sp.h>
#include <wolfssl/wolfcrypt/random.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#define P256_WORDS       8
#define P256_BYTES       32
#define P256_MAX_SIG_GEN 64
#define P256_MAX_GEN_K   8

typedef struct p256_mod {
    word32 m[P256_WORDS];
    word32 r2[P256_WORDS];
    word32 mp;
} p256_mod;

typedef struct p256_point {
    word32 x[P256_WORDS];
    word32 y[P256_WORDS];
    word32 z[P256_WORDS];
} p256_point;

/* Words are least significant first; mp is -m^-1 mod 2^32. */
static const p256_mod p256_p = {
    { 0xffffffffU, 0xffffffffU, 0xffffffffU, 0x00000000U,
      0x00000000U, 0x00000000U, 0x00000001U, 0xffffffffU },
    { 0x00000003U, 0x00000000U, 0xffffffffU, 0xfffffffbU,
      0xfffffffeU, 0xffffffffU, 0xfffffffdU, 0x00000004U },
    0x00000001U
};

static const p256_mod p256_n = {
    { 0xfc632551U, 0xf3b9cac2U, 0xa7179e84U, 0xbce6faadU,
      0xffffffffU, 0xffffffffU, 0x00000000U, 0xffffffffU },
    { 0xbe79eea2U, 0x83244c95U, 0x49bd6fa6U, 0x4699799cU,
      0x2b6bec59U, 0x2845b239U, 0xf3d95620U, 0x66e12d94U },
    0xee00bc4fU
};

/* b in Montgomery form */
static const word32 p256_b[P256_WORDS] = {
    0x29c4bddfU, 0xd89cdf62U, 0x78843090U, 0xacf005cdU,
    0xf7212ed6U, 0xe5a220abU, 0x04874834U, 0xdc30061dU
};

/* Generator in Montgomery form; z is R mod p, the Montgomery one. */
static const p256_point p256_base = {
    { 0x18a9143cU, 0x79e730d4U, 0x5fedb601U, 0x75ba95fcU,
      0x77622510U, 0x79fb732bU, 0xa53755c6U, 0x18905f76U },
    { 0xce95560aU, 0xddf25357U, 0xba19e45cU, 0x8b4ab8e4U,
      0xdd21f325U, 0xd2e88688U, 0x25885d85U, 0x8571ff18U },
    { 0x00000001U, 0x00000000U, 0x00000000U, 0xffffffffU,
      0xffffffffU, 0xffffffffU, 0xfffffffeU, 0x00000000U }
};

#define p256_mont_one p256_base.z

static const word32 p256_one[P256_WORDS] = { 1 };

/* Hides a select mask's value from the optimizer so selects stay branch free */
static word32 p256_opaque(word32 mask)
{
    volatile word32 v = mask;
    word32 r = v;

    v = 0;
    return r;
}

/* z = x + (y & mask), returns the carry */
static word32 p256_add_w(word32* z, const word32* x, const word32* y,
    word32 mask)
{
    word64 t = 0;
    int i;

    mask = p256_opaque(mask);
    for (i = 0; i < P256_WORDS; i++) {
        t += (word64)x[i] + (y[i] & mask);
        z[i] = (word32)t;
        t >>= 32;
    }
    return (word32)t;
}

/* z = x - (y & mask), returns the borrow */
static word32 p256_sub_w(word32* z, const word32* x, const word32* y,
    word32 mask)
{
    word64 t = 0;
    int i;

    mask = p256_opaque(mask);
    for (i = 0; i < P256_WORDS; i++) {
        t = (word64)x[i] - (y[i] & mask) - t;
        z[i] = (word32)t;
        t = (t >> 32) & 1U;
    }
    return (word32)t;
}

/* z = x when mask is all ones, unchanged when mask is zero */
static void p256_cmov(word32* z, const word32* x, word32 mask)
{
    int i;

    mask = p256_opaque(mask);
    for (i = 0; i < P256_WORDS; i++) {
        z[i] ^= (z[i] ^ x[i]) & mask;
    }
}

/* Returns 1 when a is zero, else 0 */
static word32 p256_iszero(const word32* a)
{
    word32 acc = 0;
    int i;

    for (i = 0; i < P256_WORDS; i++) {
        acc |= a[i];
    }
    return ((acc | ((word32)0 - acc)) >> 31) ^ 1U;
}

/* Returns 1 when a == b, else 0 */
static word32 p256_eq(const word32* a, const word32* b)
{
    word32 t[P256_WORDS];
    word32 r;

    (void)p256_sub_w(t, a, b, (word32)0xffffffffU);
    r = p256_iszero(t);
    ForceZero(t, sizeof(t));
    return r;
}

/* Returns 1 when a < m, else 0 */
static word32 p256_lt(const word32* a, const word32* m)
{
    word32 t[P256_WORDS];
    word32 b;

    b = p256_sub_w(t, a, m, (word32)0xffffffffU);
    ForceZero(t, sizeof(t));
    return b;
}

/* a = a mod m for a < 2m */
static void p256_reduce_once(word32* a, const word32* m)
{
    word32 t[P256_WORDS];
    word32 b;

    b = p256_sub_w(t, a, m, (word32)0xffffffffU);
    p256_cmov(a, t, b - 1U);
    ForceZero(t, sizeof(t));
}

/* z = (x + y) mod m for x, y < m */
static void p256_mod_add(word32* z, const word32* x, const word32* y,
    const word32* m)
{
    word32 t[P256_WORDS];
    word32 c;
    word32 b;

    c = p256_add_w(z, x, y, (word32)0xffffffffU);
    b = p256_sub_w(t, z, m, (word32)0xffffffffU);
    p256_cmov(z, t, (word32)0 - (c | (b ^ 1U)));
    ForceZero(t, sizeof(t));
}

/* z = (x - y) mod m for x, y < m */
static void p256_mod_sub(word32* z, const word32* x, const word32* y,
    const word32* m)
{
    word32 b;

    b = p256_sub_w(z, x, y, (word32)0xffffffffU);
    (void)p256_add_w(z, z, m, (word32)0 - b);
}

/* z = x * y / 2^256 mod m; output < m when either input is < m */
static void p256_mont_mul(word32* z, const word32* x, const word32* y,
    const p256_mod* md)
{
    word32 t[P256_WORDS + 2];
    word32 u;
    word32 b;
    word64 c;
    int i;
    int j;

    XMEMSET(t, 0, sizeof(t));
    for (i = 0; i < P256_WORDS; i++) {
        c = 0;
        for (j = 0; j < P256_WORDS; j++) {
            c += (word64)x[i] * y[j] + t[j];
            t[j] = (word32)c;
            c >>= 32;
        }
        c += t[P256_WORDS];
        t[P256_WORDS] = (word32)c;
        t[P256_WORDS + 1] = (word32)(c >> 32);

        u = t[0] * md->mp;
        c = ((word64)u * md->m[0] + t[0]) >> 32;
        for (j = 1; j < P256_WORDS; j++) {
            c += (word64)u * md->m[j] + t[j];
            t[j - 1] = (word32)c;
            c >>= 32;
        }
        c += t[P256_WORDS];
        t[P256_WORDS - 1] = (word32)c;
        t[P256_WORDS] = t[P256_WORDS + 1] + (word32)(c >> 32);
    }
    b = p256_sub_w(z, t, md->m, (word32)0xffffffffU);
    p256_cmov(z, t, (word32)0 - ((t[P256_WORDS] ^ 1U) & b));
    ForceZero(t, sizeof(t));
}

/* z = x^e in Montgomery form; e is public */
static void p256_mont_pow(word32* z, const word32* x, const word32* e,
    const p256_mod* md)
{
    word32 t[P256_WORDS];
    int i;

    /* R mod m is 2^256 - m since m > 2^255 */
    XMEMSET(t, 0, sizeof(t));
    (void)p256_sub_w(t, t, md->m, (word32)0xffffffffU);
    for (i = 255; i >= 0; i--) {
        p256_mont_mul(t, t, t, md);
        if (((e[i / 32] >> (i % 32)) & 1U) != 0) {
            p256_mont_mul(t, t, x, md);
        }
    }
    XMEMCPY(z, t, sizeof(t));
    ForceZero(t, sizeof(t));
}

/* z = x^-1 by Fermat; zero maps to zero */
static void p256_mont_inv(word32* z, const word32* x, const p256_mod* md)
{
    word32 e[P256_WORDS];

    XMEMCPY(e, md->m, sizeof(e));
    e[0] -= 2;
    p256_mont_pow(z, x, e, md);
}

static void p256_fmul(word32* z, const word32* x, const word32* y)
{
    p256_mont_mul(z, x, y, &p256_p);
}

static void p256_fadd(word32* z, const word32* x, const word32* y)
{
    p256_mod_add(z, x, y, p256_p.m);
}

static void p256_fsub(word32* z, const word32* x, const word32* y)
{
    p256_mod_sub(z, x, y, p256_p.m);
}

/* Renes-Costello-Batina 2016 Algorithm 4 (a = -3), one op per entry:
 * op << 12 | dst << 8 | src1 << 4 | src2 with op 0 mul, 1 add, 2 sub.
 * Registers 0-7 are t0-t4, X3, Y3, Z3; 8-10 are p; 11-13 are q; 14 is b. */
static const word16 p256_add_prog[] = {
    0x008bU, 0x019cU, 0x02adU, 0x1389U, 0x14bcU, 0x0334U, 0x1401U, 0x2334U,
    0x149aU, 0x15cdU, 0x0445U, 0x1512U, 0x2445U, 0x158aU, 0x16bdU, 0x0556U,
    0x1602U, 0x2656U, 0x07e2U, 0x2567U, 0x1755U, 0x1557U, 0x2715U, 0x1515U,
    0x06e6U, 0x1122U, 0x1212U, 0x2662U, 0x2660U, 0x1166U, 0x1616U, 0x1100U,
    0x1010U, 0x2002U, 0x0146U, 0x0206U, 0x0657U, 0x1662U, 0x0553U, 0x2551U,
    0x0747U, 0x0130U, 0x1771U
};

static const word32* p256_coord(const p256_point* p, int i)
{
    const word32* r = p->z;

    if (i == 0) {
        r = p->x;
    }
    else if (i == 1) {
        r = p->y;
    }
    return r;
}

static const word32* p256_add_reg(word32 (*t)[P256_WORDS],
    const p256_point* p, const p256_point* q, int idx)
{
    const word32* r;

    if (idx < 8) {
        r = t[idx];
    }
    else if (idx < 11) {
        r = p256_coord(p, idx - 8);
    }
    else if (idx < 14) {
        r = p256_coord(q, idx - 11);
    }
    else {
        r = p256_b;
    }
    return r;
}

/* r = p + q, complete for every input including p == q and infinity */
static void p256_point_add(p256_point* r, const p256_point* p,
    const p256_point* q)
{
    word32 t[8][P256_WORDS];
    const word32* a;
    const word32* b;
    word32* d;
    word16 op;
    int i;

    for (i = 0; i < (int)(sizeof(p256_add_prog) / sizeof(word16)); i++) {
        op = p256_add_prog[i];
        d = t[(op >> 8) & 0xf];
        a = p256_add_reg(t, p, q, (op >> 4) & 0xf);
        b = p256_add_reg(t, p, q, op & 0xf);
        if ((op >> 12) == 0) {
            p256_fmul(d, a, b);
        }
        else if ((op >> 12) == 1) {
            p256_fadd(d, a, b);
        }
        else {
            p256_fsub(d, a, b);
        }
    }
    XMEMCPY(r->x, t[5], sizeof(r->x));
    XMEMCPY(r->y, t[6], sizeof(r->y));
    XMEMCPY(r->z, t[7], sizeof(r->z));
    ForceZero(t, sizeof(t));
}

static void p256_cswap(word32* a, word32* b, word32 mask)
{
    word32 t;
    int i;

    mask = p256_opaque(mask);
    for (i = 0; i < P256_WORDS; i++) {
        t = (a[i] ^ b[i]) & mask;
        a[i] ^= t;
        b[i] ^= t;
    }
}

static void p256_point_cswap(p256_point* a, p256_point* b, word32 mask)
{
    p256_cswap(a->x, b->x, mask);
    p256_cswap(a->y, b->y, mask);
    p256_cswap(a->z, b->z, mask);
}

/* r = k * p in constant time; the ladder runs on k + n or k + 2n, which
 * always has bit 256 set, so no step starts from the identity */
static void p256_ladder(p256_point* r, const word32* k, const p256_point* p)
{
    p256_point r0;
    p256_point r1;
    word32 kk[P256_WORDS];
    word32 mask;
    int i;

    XMEMCPY(kk, k, sizeof(kk));
    p256_reduce_once(kk, p256_n.m);
    mask = p256_add_w(kk, kk, p256_n.m, (word32)0xffffffffU);
    (void)p256_add_w(kk, kk, p256_n.m, mask - 1U);
    XMEMCPY(&r0, p, sizeof(r0));
    p256_point_add(&r1, p, p);
    for (i = 255; i >= 0; i--) {
        mask = (word32)0 - ((kk[i / 32] >> (i % 32)) & 1U);
        p256_point_cswap(&r0, &r1, mask);
        p256_point_add(&r1, &r0, &r1);
        p256_point_add(&r0, &r0, &r0);
        p256_point_cswap(&r0, &r1, mask);
    }
    XMEMCPY(r, &r0, sizeof(r0));
    ForceZero(&r0, sizeof(r0));
    ForceZero(&r1, sizeof(r1));
    ForceZero(kk, sizeof(kk));
}

/* Affine x, y out of Montgomery form; returns 1 at infinity, else 0 */
static word32 p256_to_affine(word32* x, word32* y, const p256_point* p)
{
    word32 zi[P256_WORDS];

    p256_mont_inv(zi, p->z, &p256_p);
    p256_fmul(zi, zi, p256_one);
    p256_fmul(x, p->x, zi);
    p256_fmul(y, p->y, zi);
    ForceZero(zi, sizeof(zi));
    return p256_iszero(p->z);
}

/* Jacobian (X/Z^2, Y/Z^3) to homogeneous (X/Z, Y/Z) in place */
static void p256_jac_to_hom(p256_point* p)
{
    word32 z2[P256_WORDS];
    word32 inf;

    /* (0, 0) is not on the curve, so wolfSSL uses it for infinity too */
    inf = (word32)0 - (p256_iszero(p->z) |
        (p256_iszero(p->x) & p256_iszero(p->y)));
    p256_fmul(z2, p->z, p->z);
    p256_fmul(p->x, p->x, p->z);
    p256_fmul(p->z, z2, p->z);
    ForceZero(z2, sizeof(z2));
    p256_cmov(p->x, z2, inf);
    p256_cmov(p->z, z2, inf);
    p256_cmov(p->y, p256_mont_one, inf);
}

static void p256_hom_to_jac(p256_point* p)
{
    word32 z2[P256_WORDS];

    p256_fmul(z2, p->z, p->z);
    p256_fmul(p->x, p->x, p->z);
    p256_fmul(p->y, p->y, z2);
    ForceZero(z2, sizeof(z2));
}

/* t = x^3 - 3x + b, all in Montgomery form */
static void p256_curve_rhs(word32* t, const word32* x)
{
    p256_fmul(t, x, x);
    p256_fmul(t, t, x);
    p256_fsub(t, t, x);
    p256_fsub(t, t, x);
    p256_fsub(t, t, x);
    p256_fadd(t, t, p256_b);
}

/* Big-endian bytes, len <= P256_BYTES, right-aligned into z */
static void p256_from_bin(word32* z, const byte* b, word32 len)
{
    word32 i;

    XMEMSET(z, 0, P256_WORDS * sizeof(word32));
    for (i = 0; i < len; i++) {
        z[(len - 1 - i) / 4] |= (word32)b[i] << (8 * ((len - 1 - i) % 4));
    }
}

static void p256_to_bin(byte* b, const word32* z)
{
    int i;

    for (i = 0; i < P256_BYTES; i++) {
        b[i] = (byte)(z[(P256_BYTES - 1 - i) / 4] >>
            (8 * ((P256_BYTES - 1 - i) % 4)));
    }
}

/* Fails with MP_VAL when a is negative or uses more than 256 bits of digits */
static int p256_from_mp(word32* z, const mp_int* a)
{
    byte b[P256_BYTES];
    int err = MP_OKAY;

    if (mp_isneg(a) ||
            (a->used > (P256_BYTES * 8 + SP_WORD_SIZE - 1) / SP_WORD_SIZE)) {
        err = MP_VAL;
    }
    if (err == MP_OKAY) {
        err = mp_to_unsigned_bin_len_ct(a, b, (int)sizeof(b));
    }
    if (err == MP_OKAY) {
        p256_from_bin(z, b, P256_BYTES);
    }
    ForceZero(b, sizeof(b));
    return err;
}

static int p256_to_mp(const word32* a, mp_int* r)
{
    byte b[P256_BYTES];
    int err;

    p256_to_bin(b, a);
    err = mp_read_unsigned_bin(r, b, (word32)sizeof(b));
    ForceZero(b, sizeof(b));
    return err;
}

/* Loads an affine public point into Montgomery form and checks it lies on the
 * curve; a z coordinate, when given, must be 1 */
static int p256_load_pub(p256_point* p, const mp_int* x, const mp_int* y,
    const mp_int* z)
{
    word32 t[P256_WORDS];
    int err;

    err = p256_from_mp(p->x, x);
    if (err == MP_OKAY) {
        err = p256_from_mp(p->y, y);
    }
    if ((err != MP_OKAY) || (p256_lt(p->x, p256_p.m) == 0) ||
            (p256_lt(p->y, p256_p.m) == 0)) {
        err = ECC_OUT_OF_RANGE_E;
    }
    /* Only affine points (Z = 1) are taken; others are refused, not guessed */
    if ((err == MP_OKAY) && (z != NULL) &&
            ((p256_from_mp(p->z, z) != MP_OKAY) ||
             (p256_eq(p->z, p256_one) == 0))) {
        err = ECC_BAD_ARG_E;
    }
    if (err == MP_OKAY) {
        p256_fmul(p->x, p->x, p256_p.r2);
        p256_fmul(p->y, p->y, p256_p.r2);
        p256_curve_rhs(t, p->x);
        p256_fmul(p->z, p->y, p->y);
        if (p256_eq(t, p->z) == 0) {
            err = MP_VAL;
        }
        XMEMCPY(p->z, p256_mont_one, sizeof(p->z));
    }
    return err;
}

/* Loads a Jacobian point as homogeneous Montgomery coordinates */
static int p256_load_jac(p256_point* p, const mp_int* x, const mp_int* y,
    const mp_int* z, int inMont)
{
    const word32* f;
    int err;

    err = p256_from_mp(p->x, x);
    if (err == MP_OKAY) {
        err = p256_from_mp(p->y, y);
    }
    if (err == MP_OKAY) {
        err = p256_from_mp(p->z, z);
    }
    if (err == MP_OKAY) {
        /* Multiplying by R mod p keeps a Montgomery value and reduces it */
        f = inMont ? p256_mont_one : p256_p.r2;
        p256_fmul(p->x, p->x, f);
        p256_fmul(p->y, p->y, f);
        p256_fmul(p->z, p->z, f);
        p256_jac_to_hom(p);
    }
    return err;
}

/* map: affine with z = 1; otherwise Jacobian in Montgomery form */
static int p256_store(p256_point* p, mp_int* x, mp_int* y, mp_int* z,
    int map)
{
    int err;

    if (map) {
        (void)p256_to_affine(p->x, p->y, p);
        XMEMCPY(p->z, p256_one, sizeof(p->z));
    }
    else {
        p256_hom_to_jac(p);
    }
    err = p256_to_mp(p->x, x);
    if (err == MP_OKAY) {
        err = p256_to_mp(p->y, y);
    }
    if (err == MP_OKAY) {
        err = p256_to_mp(p->z, z);
    }
    return err;
}

/* 0 < k < n by rejection sampling */
static int p256_gen_k(WC_RNG* rng, word32* k)
{
#ifndef WC_NO_RNG
    byte b[P256_BYTES];
    word32 ok = 0;
    int err = 0;
    int i;

    for (i = 0; (err == 0) && (ok == 0) && (i < P256_MAX_GEN_K); i++) {
        err = wc_RNG_GenerateBlock(rng, b, (word32)sizeof(b));
        if (err == 0) {
            p256_from_bin(k, b, P256_BYTES);
            ok = p256_lt(k, p256_n.m) & (p256_iszero(k) ^ 1U);
        }
    }
    if ((err == 0) && (ok == 0)) {
        err = RNG_FAILURE_E;
    }
    ForceZero(b, sizeof(b));
    return err;
#else
    (void)rng;
    (void)k;
    return NOT_COMPILED_IN;
#endif
}

#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
/* e = leftmost 256 bits of the hash, reduced mod n */
static void p256_hash_to_e(word32* e, const byte* hash, word32 hashLen)
{
    if (hashLen > P256_BYTES) {
        hashLen = P256_BYTES;
    }
    p256_from_bin(e, hash, hashLen);
    p256_reduce_once(e, p256_n.m);
}
#endif

int sp_ecc_mulmod_256(const mp_int* km, const ecc_point* gm, ecc_point* r,
    int map, void* heap)
{
    p256_point p;
    word32 k[P256_WORDS];
    int err;

    (void)heap;
    err = p256_from_mp(k, km);
    if (err == MP_OKAY) {
        err = p256_load_jac(&p, gm->x, gm->y, gm->z, 0);
    }
    if (err == MP_OKAY) {
        p256_ladder(&p, k, &p);
        err = p256_store(&p, r->x, r->y, r->z, map);
    }
    ForceZero(k, sizeof(k));
    ForceZero(&p, sizeof(p));
    return err;
}

int sp_ecc_mulmod_add_256(const mp_int* km, const ecc_point* gm,
    const ecc_point* am, int inMont, ecc_point* r, int map, void* heap)
{
    p256_point p;
    p256_point a;
    word32 k[P256_WORDS];
    int err;

    (void)heap;
    err = p256_from_mp(k, km);
    if (err == MP_OKAY) {
        err = p256_load_jac(&p, gm->x, gm->y, gm->z, 0);
    }
    if (err == MP_OKAY) {
        err = p256_load_jac(&a, am->x, am->y, am->z, inMont);
    }
    if (err == MP_OKAY) {
        p256_ladder(&p, k, &p);
        p256_point_add(&p, &p, &a);
        err = p256_store(&p, r->x, r->y, r->z, map);
    }
    ForceZero(k, sizeof(k));
    ForceZero(&p, sizeof(p));
    return err;
}

int sp_ecc_mulmod_base_256(const mp_int* km, ecc_point* r, int map,
    void* heap)
{
    p256_point p;
    word32 k[P256_WORDS];
    int err;

    (void)heap;
    err = p256_from_mp(k, km);
    if (err == MP_OKAY) {
        p256_ladder(&p, k, &p256_base);
        err = p256_store(&p, r->x, r->y, r->z, map);
    }
    ForceZero(k, sizeof(k));
    ForceZero(&p, sizeof(p));
    return err;
}

int sp_ecc_mulmod_base_add_256(const mp_int* km, const ecc_point* am,
    int inMont, ecc_point* r, int map, void* heap)
{
    p256_point p;
    p256_point a;
    word32 k[P256_WORDS];
    int err;

    (void)heap;
    err = p256_from_mp(k, km);
    if (err == MP_OKAY) {
        err = p256_load_jac(&a, am->x, am->y, am->z, inMont);
    }
    if (err == MP_OKAY) {
        p256_ladder(&p, k, &p256_base);
        p256_point_add(&p, &p, &a);
        err = p256_store(&p, r->x, r->y, r->z, map);
    }
    ForceZero(k, sizeof(k));
    ForceZero(&p, sizeof(p));
    return err;
}

int sp_ecc_make_key_256(WC_RNG* rng, mp_int* priv, ecc_point* pub, void* heap)
{
    p256_point p;
    word32 k[P256_WORDS];
    int err;

    (void)heap;
    err = p256_gen_k(rng, k);
    if (err == MP_OKAY) {
        p256_ladder(&p, k, &p256_base);
        err = p256_to_mp(k, priv);
    }
    if (err == MP_OKAY) {
        err = p256_store(&p, pub->x, pub->y, pub->z, 1);
    }
    ForceZero(k, sizeof(k));
    ForceZero(&p, sizeof(p));
    return err;
}

#ifdef HAVE_ECC_DHE
int sp_ecc_secret_gen_256(const mp_int* priv, const ecc_point* pub,
    byte* out, word32* outLen, void* heap)
{
    p256_point p;
    word32 k[P256_WORDS];
    int err = MP_OKAY;

    (void)heap;
    if (*outLen < P256_BYTES) {
        err = BUFFER_E;
    }
    if (err == MP_OKAY) {
        err = p256_from_mp(k, priv);
    }
    if (err == MP_OKAY) {
        err = p256_load_pub(&p, pub->x, pub->y, pub->z);
    }
    if (err == MP_OKAY) {
        p256_ladder(&p, k, &p);
        if (p256_to_affine(p.x, p.y, &p) != 0) {
            err = ECC_INF_E;
        }
    }
    if (err == MP_OKAY) {
        p256_to_bin(out, p.x);
        *outLen = P256_BYTES;
    }
    ForceZero(k, sizeof(k));
    ForceZero(&p, sizeof(p));
    return err;
}
#endif /* HAVE_ECC_DHE */

#ifdef HAVE_ECC_SIGN
int sp_ecc_sign_256(const byte* hash, word32 hashLen, WC_RNG* rng,
    const mp_int* priv, mp_int* rm, mp_int* sm, mp_int* km, void* heap)
{
    p256_point p;
    word32 e[P256_WORDS];
    word32 d[P256_WORDS];
    word32 k[P256_WORDS];
    word32 r[P256_WORDS];
    word32 s[P256_WORDS];
    word32 done = 0;
    int err;
    int i;

    (void)heap;
    p256_hash_to_e(e, hash, hashLen);
    err = p256_from_mp(d, priv);
    for (i = 0; (err == MP_OKAY) && (done == 0) && (i < P256_MAX_SIG_GEN);
            i++) {
        if ((km != NULL) && !mp_iszero(km)) {
            err = p256_from_mp(k, km);
            mp_zero(km);
        }
        else {
            err = p256_gen_k(rng, k);
        }
        if (err == MP_OKAY) {
            p256_ladder(&p, k, &p256_base);
            (void)p256_to_affine(r, p.y, &p);
            p256_reduce_once(r, p256_n.m);

            /* s = k^-1 (e + r d) mod n */
            p256_mont_mul(k, k, p256_n.r2, &p256_n);
            p256_mont_inv(k, k, &p256_n);
            p256_mont_mul(s, r, p256_n.r2, &p256_n);
            p256_mont_mul(s, s, d, &p256_n);
            p256_mod_add(s, s, e, p256_n.m);
            p256_mont_mul(s, k, s, &p256_n);
            done = (p256_iszero(r) | p256_iszero(s)) ^ 1U;
        }
    #ifdef WOLFSSL_ECDSA_SET_K_ONE_LOOP
        i = P256_MAX_SIG_GEN;
    #endif
    }
    if ((err == MP_OKAY) && (done == 0)) {
        err = RNG_FAILURE_E;
    }
    if (err == MP_OKAY) {
        err = p256_to_mp(r, rm);
    }
    if (err == MP_OKAY) {
        err = p256_to_mp(s, sm);
    }
    ForceZero(e, sizeof(e));
    ForceZero(d, sizeof(d));
    ForceZero(k, sizeof(k));
    ForceZero(r, sizeof(r));
    ForceZero(s, sizeof(s));
    ForceZero(&p, sizeof(p));
    return err;
}
#endif /* HAVE_ECC_SIGN */

#ifdef HAVE_ECC_VERIFY
int sp_ecc_verify_256(const byte* hash, word32 hashLen, const mp_int* pX,
    const mp_int* pY, const mp_int* pZ, const mp_int* rm, const mp_int* sm,
    int* res, void* heap)
{
    p256_point q;
    p256_point g;
    word32 e[P256_WORDS];
    word32 r[P256_WORDS];
    word32 s[P256_WORDS];
    word32 ok;
    int err;

    (void)heap;
    *res = 0;
    p256_hash_to_e(e, hash, hashLen);
    err = p256_load_pub(&q, pX, pY, pZ);
    if (err == MP_OKAY) {
        ok = (word32)((p256_from_mp(r, rm) == MP_OKAY) &&
            (p256_from_mp(s, sm) == MP_OKAY));
        /* out-of-range r or s is an invalid signature, not an error */
        if (ok != 0) {
            ok = p256_lt(r, p256_n.m) & p256_lt(s, p256_n.m) &
                 (p256_iszero(r) ^ 1U) & (p256_iszero(s) ^ 1U);
        }
        if (ok != 0) {
            p256_mont_mul(s, s, p256_n.r2, &p256_n);
            p256_mont_inv(s, s, &p256_n);
            p256_mont_mul(e, s, e, &p256_n);
            p256_mont_mul(s, s, r, &p256_n);
            p256_ladder(&g, e, &p256_base);
            p256_ladder(&q, s, &q);
            p256_point_add(&g, &g, &q);
            ok = p256_to_affine(g.x, g.y, &g) ^ 1U;
        }
        if (ok != 0) {
            p256_reduce_once(g.x, p256_n.m);
            *res = (int)p256_eq(g.x, r);
        }
    }
    ForceZero(e, sizeof(e));
    return err;
}
#endif /* HAVE_ECC_VERIFY */

int sp_ecc_is_point_256(const mp_int* pX, const mp_int* pY)
{
    p256_point p;

    return p256_load_pub(&p, pX, pY, NULL);
}

#if defined(HAVE_ECC_CHECK_KEY) || !defined(NO_ECC_CHECK_PUBKEY_ORDER)
/* P-256 has cofactor 1, so every finite point on the curve has order n */
int sp_ecc_check_key_256(const mp_int* pX, const mp_int* pY,
    const mp_int* privm, void* heap)
{
    p256_point p;
    p256_point q;
    word32 d[P256_WORDS];
    int err = MP_OKAY;

    (void)heap;
    if (mp_iszero(pX) && mp_iszero(pY)) {
        err = ECC_INF_E;
    }
    if (err == MP_OKAY) {
        err = p256_load_pub(&p, pX, pY, NULL);
    }
    if ((err == MP_OKAY) && (privm != NULL)) {
        if (p256_from_mp(d, privm) != MP_OKAY) {
            err = ECC_OUT_OF_RANGE_E;
        }
        if (err == MP_OKAY) {
            p256_ladder(&q, d, &p256_base);
            (void)p256_to_affine(q.x, q.y, &q);
            (void)p256_to_affine(p.x, p.y, &p);
            if ((p256_eq(q.x, p.x) & p256_eq(q.y, p.y)) == 0) {
                err = ECC_PRIV_KEY_E;
            }
        }
        ForceZero(d, sizeof(d));
        ForceZero(&q, sizeof(q));
    }
    return err;
}
#endif

#ifdef WOLFSSL_PUBLIC_ECC_ADD_DBL
int sp_ecc_proj_add_point_256(mp_int* pX, mp_int* pY, mp_int* pZ,
    mp_int* qX, mp_int* qY, mp_int* qZ, mp_int* rX, mp_int* rY, mp_int* rZ)
{
    p256_point p;
    p256_point q;
    int err;

    err = p256_load_jac(&p, pX, pY, pZ, 1);
    if (err == MP_OKAY) {
        err = p256_load_jac(&q, qX, qY, qZ, 1);
    }
    if (err == MP_OKAY) {
        p256_point_add(&p, &p, &q);
        err = p256_store(&p, rX, rY, rZ, 0);
    }
    return err;
}

int sp_ecc_proj_dbl_point_256(mp_int* pX, mp_int* pY, mp_int* pZ,
    mp_int* rX, mp_int* rY, mp_int* rZ)
{
    p256_point p;
    int err;

    err = p256_load_jac(&p, pX, pY, pZ, 1);
    if (err == MP_OKAY) {
        p256_point_add(&p, &p, &p);
        err = p256_store(&p, rX, rY, rZ, 0);
    }
    return err;
}

int sp_ecc_map_256(mp_int* pX, mp_int* pY, mp_int* pZ)
{
    p256_point p;
    int err;

    err = p256_load_jac(&p, pX, pY, pZ, 1);
    if (err == MP_OKAY) {
        err = p256_store(&p, pX, pY, pZ, 1);
    }
    return err;
}
#endif /* WOLFSSL_PUBLIC_ECC_ADD_DBL */

#ifdef HAVE_COMP_KEY
/* (p + 1) / 4, the square-root exponent since p = 3 mod 4 */
static const word32 p256_sqrt_e[P256_WORDS] = {
    0x00000000U, 0x00000000U, 0x40000000U, 0x00000000U,
    0x00000000U, 0x40000000U, 0xc0000000U, 0x3fffffffU
};

int sp_ecc_uncompress_256(mp_int* xm, int odd, mp_int* ym)
{
    word32 x[P256_WORDS];
    word32 y[P256_WORDS];
    word32 t[P256_WORDS];
    int err;

    err = p256_from_mp(x, xm);
    if ((err != MP_OKAY) || (p256_lt(x, p256_p.m) == 0)) {
        err = MP_VAL;
    }
    if (err == MP_OKAY) {
        p256_fmul(x, x, p256_p.r2);
        p256_curve_rhs(t, x);
        p256_mont_pow(y, t, p256_sqrt_e, &p256_p);
        p256_fmul(x, y, y);
        if (p256_eq(x, t) == 0) {
            err = MP_VAL;
        }
    }
    if (err == MP_OKAY) {
        p256_fmul(y, y, p256_one);
        XMEMSET(t, 0, sizeof(t));
        p256_mod_sub(t, t, y, p256_p.m);
        p256_cmov(y, t, (word32)0 - ((y[0] ^ (word32)odd) & 1U));
        err = p256_to_mp(y, ym);
    }
    return err;
}
#endif /* HAVE_COMP_KEY */

#endif /* WOLFSSL_SP_P256_SMALL && WOLFSSL_HAVE_SP_ECC */
