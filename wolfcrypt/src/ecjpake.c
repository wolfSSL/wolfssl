/* ecjpake.c
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

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef WOLFCRYPT_HAVE_ECJPAKE

#include <wolfssl/wolfcrypt/ecjpake.h>
#include <wolfssl/wolfcrypt/hash.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#define ECJPAKE_FLAG_KEYS           0x01
#define ECJPAKE_FLAG_ROUND1_WRITTEN 0x02
#define ECJPAKE_FLAG_ROUND1_READ    0x04
#define ECJPAKE_FLAG_ROUND2_READ    0x08

#define ECJPAKE_ID_SZ               6

static const byte ecjpakeIdClient[ECJPAKE_ID_SZ] = {
    'c', 'l', 'i', 'e', 'n', 't'
};
static const byte ecjpakeIdServer[ECJPAKE_ID_SZ] = {
    's', 'e', 'r', 'v', 'e', 'r'
};

/* ECParameters: curve_type named_curve(3), NamedCurve secp256r1(23) */
static const byte ecjpakeEcParams[WC_ECJPAKE_ECPARAMS_SZ] = {
    0x03, 0x00, 0x17
};

static const byte* ecjpake_id(int role)
{
    return (role == WC_ECJPAKE_CLIENT) ? ecjpakeIdClient : ecjpakeIdServer;
}

static void ecjpake_free_points(EcJpake* jp)
{
    wc_ecc_del_point_h(jp->G, jp->heap);
    wc_ecc_del_point_h(jp->Xm1, jp->heap);
    wc_ecc_del_point_h(jp->Xm2, jp->heap);
    wc_ecc_del_point_h(jp->Xp1, jp->heap);
    wc_ecc_del_point_h(jp->Xp2, jp->heap);
    wc_ecc_del_point_h(jp->Xp, jp->heap);
    jp->G = jp->Xm1 = jp->Xm2 = jp->Xp1 = jp->Xp2 = jp->Xp = NULL;
}

/* Writes the SEC1 uncompressed encoding of an affine point. */
static int ecjpake_point_encode(ecc_point* p, byte* out)
{
    int err;

    out[0] = ECC_POINT_UNCOMP;
    err = mp_to_unsigned_bin_len(p->x, out + 1, WC_ECJPAKE_FIELD_SZ);
    if (err == MP_OKAY) {
        err = mp_to_unsigned_bin_len(p->y, out + 1 + WC_ECJPAKE_FIELD_SZ,
                                     WC_ECJPAKE_FIELD_SZ);
    }
    return err;
}

/* Writes a TLS ECPoint: opaque point <1..2^8-1>. */
static int ecjpake_write_point(ecc_point* p, byte* out, word32* idx)
{
    int err;

    out[*idx] = WC_ECJPAKE_POINT_SZ;
    err = ecjpake_point_encode(p, out + *idx + 1);
    if (err == MP_OKAY) {
        *idx += 1 + WC_ECJPAKE_POINT_SZ;
    }
    return err;
}

/* Reads a TLS ECPoint and validates it as a point on the curve. P-256 has a
 * cofactor of one and no affine encoding of infinity, so this is full public
 * key validation. */
static int ecjpake_read_point(EcJpake* jp, const byte* in, word32 inSz,
                              word32* idx, ecc_point* p)
{
    int err;
    const byte* pt;

    if (inSz - *idx < 1 + WC_ECJPAKE_POINT_SZ) {
        return BUFFER_E;
    }
    pt = in + *idx + 1;
    if (in[*idx] != WC_ECJPAKE_POINT_SZ || pt[0] != ECC_POINT_UNCOMP) {
        return ECC_BAD_ARG_E;
    }

    err = mp_read_unsigned_bin(p->x, pt + 1, WC_ECJPAKE_FIELD_SZ);
    if (err == MP_OKAY) {
        err = mp_read_unsigned_bin(p->y, pt + 1 + WC_ECJPAKE_FIELD_SZ,
                                   WC_ECJPAKE_FIELD_SZ);
    }
    if (err == MP_OKAY) {
        err = mp_set(p->z, 1);
    }
    if (err == MP_OKAY) {
        err = wc_ecc_point_is_on_curve(p, jp->curveIdx);
    }
    if (err == MP_OKAY) {
        *idx += 1 + WC_ECJPAKE_POINT_SZ;
    }
    return err;
}

/* R = k * P, affine. */
static int ecjpake_mul(EcJpake* jp, mp_int* k, ecc_point* P, ecc_point* R,
                       WC_RNG* rng)
{
    return wc_ecc_mulmod_ex2(k, P, R, &jp->a, &jp->prime, &jp->order, rng, 1,
                             jp->heap);
}

static int ecjpake_to_mont(EcJpake* jp, ecc_point* p, ecc_point* r)
{
    int err;

    err = mp_mulmod(p->x, &jp->mu, &jp->prime, r->x);
    if (err == MP_OKAY) {
        err = mp_mulmod(p->y, &jp->mu, &jp->prime, r->y);
    }
    if (err == MP_OKAY) {
        err = mp_copy(&jp->mu, r->z);
    }
    return err;
}

/* R = A + B for affine A and B, affine. ECC_INF_E when the sum is the point
 * at infinity. */
static int ecjpake_add(EcJpake* jp, ecc_point* A, ecc_point* B, ecc_point* R)
{
    int err = MP_OKAY;
    int inf = 0;
    ecc_point* tA;
    ecc_point* tB;

    tA = wc_ecc_new_point_h(jp->heap);
    tB = wc_ecc_new_point_h(jp->heap);
    if (tA == NULL || tB == NULL) {
        err = MEMORY_E;
    }
    if (err == MP_OKAY) {
        err = ecjpake_to_mont(jp, A, tA);
    }
    if (err == MP_OKAY) {
        err = ecjpake_to_mont(jp, B, tB);
    }
    if (err == MP_OKAY) {
        err = ecc_projective_add_point_safe(tA, tB, R, &jp->a, &jp->prime,
                                            jp->mp, &inf);
    }
    if (err == MP_OKAY && (inf || wc_ecc_point_is_at_infinity(R))) {
        err = ECC_INF_E;
    }
    if (err == MP_OKAY) {
        err = ecc_map_ex(R, &jp->prime, jp->mp, 1);
    }

    wc_ecc_del_point_h(tB, jp->heap);
    wc_ecc_del_point_h(tA, jp->heap);
    return err;
}

/* R = A + B + C */
static int ecjpake_add3(EcJpake* jp, ecc_point* A, ecc_point* B,
                        ecc_point* C, ecc_point* R)
{
    int err = ecjpake_add(jp, A, B, R);
    if (err == MP_OKAY) {
        err = ecjpake_add(jp, R, C, R);
    }
    return err;
}

/* h = int(SHA-256(lenG || G || lenV || V || lenX || X || lenID || ID)) mod n
 * (draft-cragie-tls-ecjpake-01 Section 8.2, RFC 8235 Section 3.3). */
static int ecjpake_zkp_hash(EcJpake* jp, ecc_point* gen, ecc_point* V,
                            ecc_point* X, const byte* id, mp_int* h)
{
    int err;
    int i;
    wc_Sha256 sha;
    byte len[4];
    byte pt[WC_ECJPAKE_POINT_SZ];
    byte digest[WC_SHA256_DIGEST_SIZE];
    ecc_point* pts[3];

    pts[0] = gen;
    pts[1] = V;
    pts[2] = X;

    err = wc_InitSha256_ex(&sha, jp->heap, INVALID_DEVID);
    if (err != 0) {
        return err;
    }

    c32toa(WC_ECJPAKE_POINT_SZ, len);
    for (i = 0; i < 3 && err == 0; i++) {
        err = ecjpake_point_encode(pts[i], pt);
        if (err == 0) {
            err = wc_Sha256Update(&sha, len, sizeof(len));
        }
        if (err == 0) {
            err = wc_Sha256Update(&sha, pt, sizeof(pt));
        }
    }
    if (err == 0) {
        c32toa(ECJPAKE_ID_SZ, len);
        err = wc_Sha256Update(&sha, len, sizeof(len));
    }
    if (err == 0) {
        err = wc_Sha256Update(&sha, id, ECJPAKE_ID_SZ);
    }
    if (err == 0) {
        err = wc_Sha256Final(&sha, digest);
    }
    wc_Sha256Free(&sha);

    if (err == 0) {
        err = mp_read_unsigned_bin(h, digest, sizeof(digest));
    }
    if (err == 0) {
        err = mp_mod(h, &jp->order, h);
    }
    return err;
}

/* Writes ECSchnorrZKP proving knowledge of x where X = gen * x. */
static int ecjpake_zkp_write(EcJpake* jp, ecc_point* gen, mp_int* x,
                             ecc_point* X, WC_RNG* rng, byte* out,
                             word32* idx)
{
    int err = MP_OKAY;
    ecc_point* V;

    V = wc_ecc_new_point_h(jp->heap);
    if (V == NULL) {
        err = MEMORY_E;
    }
    if (err == MP_OKAY) {
        err = wc_ecc_gen_k(rng, WC_ECJPAKE_FIELD_SZ, &jp->k, &jp->order);
    }
    if (err == MP_OKAY) {
        err = ecjpake_mul(jp, &jp->k, gen, V, rng);
    }
    if (err == MP_OKAY) {
        err = ecjpake_zkp_hash(jp, gen, V, X, ecjpake_id(jp->role), &jp->h);
    }
    /* r = v - x*h mod n */
    if (err == MP_OKAY) {
        err = mp_mulmod(x, &jp->h, &jp->order, &jp->h);
    }
    if (err == MP_OKAY) {
        err = mp_submod(&jp->k, &jp->h, &jp->order, &jp->k);
    }
    if (err == MP_OKAY) {
        err = ecjpake_write_point(V, out, idx);
    }
    if (err == MP_OKAY) {
        out[*idx] = WC_ECJPAKE_FIELD_SZ;
        err = mp_to_unsigned_bin_len(&jp->k, out + *idx + 1,
                                     WC_ECJPAKE_FIELD_SZ);
    }
    if (err == MP_OKAY) {
        *idx += 1 + WC_ECJPAKE_FIELD_SZ;
    }

    mp_forcezero(&jp->k);
    mp_forcezero(&jp->h);
    wc_ecc_del_point_h(V, jp->heap);
    return err;
}

/* Reads ECSchnorrZKP and verifies V == X*h + gen*r. */
static int ecjpake_zkp_read(EcJpake* jp, ecc_point* gen, ecc_point* X,
                            const byte* in, word32 inSz, word32* idx)
{
    int err;
    word32 rSz = 0;
    ecc_point* V;
    ecc_point* Xh;
    ecc_point* Gr;

    V = wc_ecc_new_point_h(jp->heap);
    Xh = wc_ecc_new_point_h(jp->heap);
    Gr = wc_ecc_new_point_h(jp->heap);
    if (V == NULL || Xh == NULL || Gr == NULL) {
        err = MEMORY_E;
    }
    else {
        err = ecjpake_read_point(jp, in, inSz, idx, V);
    }

    /* opaque r<1..2^8-1>, leading zero octets permitted */
    if (err == MP_OKAY) {
        if (inSz - *idx < 1) {
            err = BUFFER_E;
        }
        else {
            rSz = in[(*idx)++];
            if (rSz == 0 || inSz - *idx < rSz) {
                err = BUFFER_E;
            }
        }
    }
    if (err == MP_OKAY) {
        while (rSz > WC_ECJPAKE_FIELD_SZ && in[*idx] == 0) {
            (*idx)++;
            rSz--;
        }
        if (rSz > WC_ECJPAKE_FIELD_SZ) {
            err = ECC_OUT_OF_RANGE_E;
        }
    }
    if (err == MP_OKAY) {
        err = mp_read_unsigned_bin(&jp->k, in + *idx, rSz);
        *idx += rSz;
    }
    if (err == MP_OKAY && (mp_cmp(&jp->k, &jp->order) != MP_LT ||
                           mp_iszero(&jp->k))) {
        err = SIG_VERIFY_E;
    }

    if (err == MP_OKAY) {
        err = ecjpake_zkp_hash(jp, gen, V, X,
                               ecjpake_id(!jp->role), &jp->h);
    }
    if (err == MP_OKAY && mp_iszero(&jp->h)) {
        err = SIG_VERIFY_E;
    }
    if (err == MP_OKAY) {
        err = ecjpake_mul(jp, &jp->h, X, Xh, NULL);
    }
    if (err == MP_OKAY) {
        err = ecjpake_mul(jp, &jp->k, gen, Gr, NULL);
    }
    if (err == MP_OKAY) {
        err = ecjpake_add(jp, Xh, Gr, Xh);
        if (err == WC_NO_ERR_TRACE(ECC_INF_E)) {
            err = SIG_VERIFY_E;
        }
    }
    if (err == MP_OKAY && wc_ecc_cmp_point(Xh, V) != MP_EQ) {
        err = SIG_VERIFY_E;
    }

    wc_ecc_del_point_h(Gr, jp->heap);
    wc_ecc_del_point_h(Xh, jp->heap);
    wc_ecc_del_point_h(V, jp->heap);
    return err;
}

/* Writes ECJPAKEKeyKP for the key pair (x, X = gen * x). */
static int ecjpake_kkp_write(EcJpake* jp, ecc_point* gen, mp_int* x,
                             ecc_point* X, WC_RNG* rng, byte* out,
                             word32* idx)
{
    int err = ecjpake_write_point(X, out, idx);
    if (err == MP_OKAY) {
        err = ecjpake_zkp_write(jp, gen, x, X, rng, out, idx);
    }
    return err;
}

/* Reads ECJPAKEKeyKP into X, verifying its proof against gen. */
static int ecjpake_kkp_read(EcJpake* jp, ecc_point* gen, ecc_point* X,
                            const byte* in, word32 inSz, word32* idx)
{
    int err = ecjpake_read_point(jp, in, inSz, idx, X);
    if (err == MP_OKAY) {
        err = ecjpake_zkp_read(jp, gen, X, in, inSz, idx);
    }
    return err;
}

int wc_EcJpakeInit(EcJpake* jp, int role, int curveId, const byte* secret,
                   word32 secretSz, void* heap)
{
    int err;
    const ecc_set_type* dp = NULL;

    if (jp == NULL || secret == NULL || secretSz == 0 ||
            (role != WC_ECJPAKE_CLIENT && role != WC_ECJPAKE_SERVER)) {
        return BAD_FUNC_ARG;
    }
    if (curveId != ECC_SECP256R1) {
        return ECC_CURVE_OID_E;
    }

    XMEMSET(jp, 0, sizeof(*jp));
    jp->role = role;
    jp->heap = heap;
    jp->curveIdx = wc_ecc_get_curve_idx(curveId);

    err = mp_init_multi(&jp->prime, &jp->a, &jp->order, &jp->mu, &jp->s,
                        &jp->xm1);
    if (err == MP_OKAY) {
        err = mp_init_multi(&jp->xm2, &jp->k, &jp->h, &jp->t, NULL, NULL);
    }
    if (err != MP_OKAY) {
        return err;
    }

    jp->G = wc_ecc_new_point_h(heap);
    jp->Xm1 = wc_ecc_new_point_h(heap);
    jp->Xm2 = wc_ecc_new_point_h(heap);
    jp->Xp1 = wc_ecc_new_point_h(heap);
    jp->Xp2 = wc_ecc_new_point_h(heap);
    jp->Xp = wc_ecc_new_point_h(heap);
    if (jp->G == NULL || jp->Xm1 == NULL || jp->Xm2 == NULL ||
            jp->Xp1 == NULL || jp->Xp2 == NULL || jp->Xp == NULL) {
        err = MEMORY_E;
    }

    if (err == MP_OKAY) {
        dp = wc_ecc_get_curve_params(jp->curveIdx);
        if (dp == NULL) {
            err = ECC_CURVE_OID_E;
        }
    }
    if (err == MP_OKAY) {
        err = mp_read_radix(&jp->prime, dp->prime, MP_RADIX_HEX);
    }
    if (err == MP_OKAY) {
        err = mp_read_radix(&jp->a, dp->Af, MP_RADIX_HEX);
    }
    if (err == MP_OKAY) {
        err = mp_read_radix(&jp->order, dp->order, MP_RADIX_HEX);
    }
    if (err == MP_OKAY) {
        err = mp_read_radix(jp->G->x, dp->Gx, MP_RADIX_HEX);
    }
    if (err == MP_OKAY) {
        err = mp_read_radix(jp->G->y, dp->Gy, MP_RADIX_HEX);
    }
    if (err == MP_OKAY) {
        err = mp_set(jp->G->z, 1);
    }
    if (err == MP_OKAY) {
        err = mp_montgomery_setup(&jp->prime, &jp->mp);
    }
    if (err == MP_OKAY) {
        err = mp_montgomery_calc_normalization(&jp->mu, &jp->prime);
    }

    /* s = int(password) mod n, which RFC 8236 requires to be non-zero */
    if (err == MP_OKAY) {
        err = mp_read_unsigned_bin(&jp->s, secret, secretSz);
    }
    if (err == MP_OKAY) {
        err = mp_mod(&jp->s, &jp->order, &jp->s);
    }
    if (err == MP_OKAY && mp_iszero(&jp->s)) {
        err = ECC_OUT_OF_RANGE_E;
    }

    if (err != MP_OKAY) {
        wc_EcJpakeFree(jp);
    }
    return err;
}

void wc_EcJpakeFree(EcJpake* jp)
{
    if (jp == NULL) {
        return;
    }

    mp_forcezero(&jp->s);
    mp_forcezero(&jp->xm1);
    mp_forcezero(&jp->xm2);
    mp_forcezero(&jp->k);
    mp_forcezero(&jp->h);
    mp_forcezero(&jp->t);
    mp_free(&jp->prime);
    mp_free(&jp->a);
    mp_free(&jp->order);
    mp_free(&jp->mu);
    ecjpake_free_points(jp);
    jp->flags = 0;
}

int wc_EcJpakeWriteRound1(EcJpake* jp, WC_RNG* rng, byte* out, word32* outSz)
{
    int err;
    word32 idx = 0;

    if (jp == NULL || rng == NULL || out == NULL || outSz == NULL) {
        return BAD_FUNC_ARG;
    }
    if (jp->flags & ECJPAKE_FLAG_KEYS) {
        return BAD_STATE_E;
    }
    if (*outSz < WC_ECJPAKE_ROUND1_SZ) {
        return BUFFER_E;
    }

    err = wc_ecc_gen_k(rng, WC_ECJPAKE_FIELD_SZ, &jp->xm1, &jp->order);
    if (err == MP_OKAY) {
        err = wc_ecc_gen_k(rng, WC_ECJPAKE_FIELD_SZ, &jp->xm2, &jp->order);
    }
    if (err == MP_OKAY) {
        err = ecjpake_mul(jp, &jp->xm1, jp->G, jp->Xm1, rng);
    }
    if (err == MP_OKAY) {
        err = ecjpake_mul(jp, &jp->xm2, jp->G, jp->Xm2, rng);
    }
    if (err == MP_OKAY) {
        err = ecjpake_kkp_write(jp, jp->G, &jp->xm1, jp->Xm1, rng, out, &idx);
    }
    if (err == MP_OKAY) {
        err = ecjpake_kkp_write(jp, jp->G, &jp->xm2, jp->Xm2, rng, out, &idx);
    }

    if (err == MP_OKAY) {
        jp->flags |= ECJPAKE_FLAG_KEYS | ECJPAKE_FLAG_ROUND1_WRITTEN;
        *outSz = idx;
    }
    else {
        mp_forcezero(&jp->xm1);
        mp_forcezero(&jp->xm2);
    }
    return err;
}

int wc_EcJpakeSetRound1Keys(EcJpake* jp, WC_RNG* rng, const byte* x1,
                            word32 x1Sz, const byte* x2, word32 x2Sz)
{
    int err;

    if (jp == NULL || x1 == NULL || x2 == NULL || x1Sz == 0 || x2Sz == 0) {
        return BAD_FUNC_ARG;
    }
    if (jp->flags & ECJPAKE_FLAG_KEYS) {
        return BAD_STATE_E;
    }

    err = mp_read_unsigned_bin(&jp->xm1, x1, x1Sz);
    if (err == MP_OKAY) {
        err = mp_read_unsigned_bin(&jp->xm2, x2, x2Sz);
    }
    if (err == MP_OKAY && (mp_iszero(&jp->xm1) || mp_iszero(&jp->xm2) ||
                           mp_cmp(&jp->xm1, &jp->order) != MP_LT ||
                           mp_cmp(&jp->xm2, &jp->order) != MP_LT)) {
        err = ECC_OUT_OF_RANGE_E;
    }
    if (err == MP_OKAY) {
        err = ecjpake_mul(jp, &jp->xm1, jp->G, jp->Xm1, rng);
    }
    if (err == MP_OKAY) {
        err = ecjpake_mul(jp, &jp->xm2, jp->G, jp->Xm2, rng);
    }

    if (err == MP_OKAY) {
        jp->flags |= ECJPAKE_FLAG_KEYS;
    }
    else {
        mp_forcezero(&jp->xm1);
        mp_forcezero(&jp->xm2);
    }
    return err;
}

int wc_EcJpakeReadRound1(EcJpake* jp, const byte* in, word32 inSz)
{
    int err;
    word32 idx = 0;

    if (jp == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }
    if (jp->flags & ECJPAKE_FLAG_ROUND1_READ) {
        return BAD_STATE_E;
    }

    err = ecjpake_kkp_read(jp, jp->G, jp->Xp1, in, inSz, &idx);
    if (err == MP_OKAY) {
        err = ecjpake_kkp_read(jp, jp->G, jp->Xp2, in, inSz, &idx);
    }
    if (err == MP_OKAY && idx != inSz) {
        err = BUFFER_E;
    }

    if (err == MP_OKAY) {
        jp->flags |= ECJPAKE_FLAG_ROUND1_READ;
    }
    return err;
}

int wc_EcJpakeWriteRound2(EcJpake* jp, WC_RNG* rng, byte* out, word32* outSz)
{
    int err = MP_OKAY;
    word32 idx = 0;
    word32 need;
    ecc_point* gen;
    ecc_point* Xm;

    if (jp == NULL || rng == NULL || out == NULL || outSz == NULL) {
        return BAD_FUNC_ARG;
    }
    if ((jp->flags & (ECJPAKE_FLAG_KEYS | ECJPAKE_FLAG_ROUND1_READ)) !=
            (ECJPAKE_FLAG_KEYS | ECJPAKE_FLAG_ROUND1_READ)) {
        return BAD_STATE_E;
    }
    need = WC_ECJPAKE_KKP_SZ;
    if (jp->role == WC_ECJPAKE_SERVER) {
        need += WC_ECJPAKE_ECPARAMS_SZ;
    }
    if (*outSz < need) {
        return BUFFER_E;
    }

    gen = wc_ecc_new_point_h(jp->heap);
    Xm = wc_ecc_new_point_h(jp->heap);
    if (gen == NULL || Xm == NULL) {
        err = MEMORY_E;
    }

    /* Client: GA = X1 + X3 + X4, xc = x2*s, Xc = GA*xc
     * Server: GB = X3 + X1 + X2, xs = x4*s, Xs = GB*xs */
    if (err == MP_OKAY) {
        err = ecjpake_add3(jp, jp->Xm1, jp->Xp1, jp->Xp2, gen);
    }
    if (err == MP_OKAY) {
        err = mp_mulmod(&jp->xm2, &jp->s, &jp->order, &jp->t);
    }
    if (err == MP_OKAY) {
        err = ecjpake_mul(jp, &jp->t, gen, Xm, rng);
    }

    if (err == MP_OKAY && jp->role == WC_ECJPAKE_SERVER) {
        XMEMCPY(out, ecjpakeEcParams, WC_ECJPAKE_ECPARAMS_SZ);
        idx += WC_ECJPAKE_ECPARAMS_SZ;
    }
    if (err == MP_OKAY) {
        err = ecjpake_kkp_write(jp, gen, &jp->t, Xm, rng, out, &idx);
    }
    if (err == MP_OKAY) {
        *outSz = idx;
    }

    mp_forcezero(&jp->t);
    wc_ecc_del_point_h(Xm, jp->heap);
    wc_ecc_del_point_h(gen, jp->heap);
    return err;
}

int wc_EcJpakeReadRound2(EcJpake* jp, const byte* in, word32 inSz)
{
    int err = MP_OKAY;
    word32 idx = 0;
    ecc_point* gen;

    if (jp == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }
    if ((jp->flags & (ECJPAKE_FLAG_KEYS | ECJPAKE_FLAG_ROUND1_READ |
                      ECJPAKE_FLAG_ROUND2_READ)) !=
            (ECJPAKE_FLAG_KEYS | ECJPAKE_FLAG_ROUND1_READ)) {
        return BAD_STATE_E;
    }

    if (jp->role == WC_ECJPAKE_CLIENT) {
        if (inSz < WC_ECJPAKE_ECPARAMS_SZ) {
            return BUFFER_E;
        }
        if (XMEMCMP(in, ecjpakeEcParams, WC_ECJPAKE_ECPARAMS_SZ) != 0) {
            return ECC_CURVE_OID_E;
        }
        idx += WC_ECJPAKE_ECPARAMS_SZ;
    }

    gen = wc_ecc_new_point_h(jp->heap);
    if (gen == NULL) {
        err = MEMORY_E;
    }

    /* Client: GB = X1 + X2 + X3; Server: GA = X3 + X4 + X1 */
    if (err == MP_OKAY) {
        err = ecjpake_add3(jp, jp->Xm1, jp->Xm2, jp->Xp1, gen);
    }
    if (err == MP_OKAY) {
        err = ecjpake_kkp_read(jp, gen, jp->Xp, in, inSz, &idx);
    }
    if (err == MP_OKAY && idx != inSz) {
        err = BUFFER_E;
    }

    if (err == MP_OKAY) {
        jp->flags |= ECJPAKE_FLAG_ROUND2_READ;
    }
    wc_ecc_del_point_h(gen, jp->heap);
    return err;
}

int wc_EcJpakeDeriveSecret(EcJpake* jp, WC_RNG* rng, byte* out,
                           word32* outSz)
{
    int err = MP_OKAY;
    ecc_point* K;
    byte kx[WC_ECJPAKE_FIELD_SZ];

    if (jp == NULL || rng == NULL || out == NULL || outSz == NULL) {
        return BAD_FUNC_ARG;
    }
    if (!(jp->flags & ECJPAKE_FLAG_ROUND2_READ)) {
        return BAD_STATE_E;
    }
    if (*outSz < WC_ECJPAKE_SECRET_SZ) {
        return BUFFER_E;
    }

    K = wc_ecc_new_point_h(jp->heap);
    if (K == NULL) {
        err = MEMORY_E;
    }

    /* Client: K = (Xs - X4*(x2*s)) * x2
     * Server: K = (Xc - X2*(x4*s)) * x4 */
    if (err == MP_OKAY) {
        err = mp_mulmod(&jp->xm2, &jp->s, &jp->order, &jp->t);
    }
    if (err == MP_OKAY) {
        err = mp_sub(&jp->order, &jp->t, &jp->t);
    }
    if (err == MP_OKAY) {
        err = ecjpake_mul(jp, &jp->t, jp->Xp2, K, rng);
    }
    if (err == MP_OKAY) {
        err = ecjpake_add(jp, jp->Xp, K, K);
    }
    if (err == MP_OKAY) {
        err = ecjpake_mul(jp, &jp->xm2, K, K, rng);
    }

    /* PMS = SHA-256(str(32, K.x)) */
    if (err == MP_OKAY) {
        err = mp_to_unsigned_bin_len(K->x, kx, WC_ECJPAKE_FIELD_SZ);
    }
    if (err == MP_OKAY) {
        err = wc_Sha256Hash(kx, WC_ECJPAKE_FIELD_SZ, out);
    }
    if (err == MP_OKAY) {
        *outSz = WC_ECJPAKE_SECRET_SZ;
    }

    ForceZero(kx, sizeof(kx));
    mp_forcezero(&jp->t);
    if (K != NULL) {
        wc_ecc_forcezero_point(K);
    }
    wc_ecc_del_point_h(K, jp->heap);
    return err;
}

#endif /* WOLFCRYPT_HAVE_ECJPAKE */
