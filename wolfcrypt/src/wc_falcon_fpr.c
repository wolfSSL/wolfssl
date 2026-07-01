/* wc_falcon_fpr.c
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

/* Integer-emulated IEEE-754 binary64 backend for the FN-DSA / Falcon
 * floating-point primitive seam (wolfssl/wolfcrypt/wc_falcon_fpr.h).
 *
 * This is the portable, FP-unit-free, fully deterministic and constant-time
 * backend: every operation is performed with integer arithmetic only (64-bit
 * mantissa multiply-accumulate, shifts and CLZ-style normalization). No
 * hardware FPU is used and there is no branch or memory access that depends on
 * an operand value, so results are bit-identical to round-to-nearest-even
 * IEEE-754 binary64 on every platform.
 *
 * The algorithm is a port of the well-known Falcon reference "fpr" emulated
 * implementation by Thomas Pornin (MIT licensed), adapted to wolfSSL house
 * style (word64 / sword64 / word32). See https://falcon-sign.info/ and the
 * NIST PQC / Falcon round-3 reference code. */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if defined(HAVE_FALCON) && !defined(WOLF_CRYPTO_CB_ONLY_FALCON)

#include <wolfssl/wolfcrypt/wc_falcon_fpr.h>

/* ------------------------------------------------------------------------ */
/* Low-level helpers.                                                        */
/*                                                                           */
/* These shift helpers tolerate a (possibly secret) shift count in 0..63 in  */
/* constant time: a variable shift is split into a fixed conditional 32-bit  */
/* part plus a 0..31 part, avoiding both undefined behaviour and any         */
/* operand-dependent timing on platforms whose shift is data dependent.      */
/* ------------------------------------------------------------------------ */

/* Right-shift a 64-bit unsigned value by n (0..63), constant-time. */
static WC_INLINE fpr fpr_ursh(word64 x, int n)
{
    x ^= (x ^ (x >> 32)) & ((word64)0 - (word64)(n >> 5));
    return x >> (n & 31);
}

/* Right-shift a 64-bit signed value by n (0..63), constant-time. */
static WC_INLINE sword64 fpr_irsh(sword64 x, int n)
{
    x ^= (x ^ (x >> 32)) & ((sword64)0 - (sword64)(n >> 5));
    return x >> (n & 31);
}

/* Left-shift a 64-bit unsigned value by n (0..63), constant-time. */
static WC_INLINE word64 fpr_ulsh(word64 x, int n)
{
    x ^= (x ^ (x << 32)) & ((word64)0 - (word64)(n >> 5));
    return x << (n & 31);
}

/* Pack a sign s (0/1), unbiased exponent e and mantissa m (2^54 <= m < 2^55,
 * with the low 3 bits carrying guard/round/sticky information) into the
 * IEEE-754 binary64 bit pattern, applying round-to-nearest-even.
 *
 * If m == 0 a (signed) zero is produced. If e < -1076 the value underflows to
 * a (signed) zero. */
static WC_INLINE fpr FPR(int s, int e, word64 m)
{
    fpr x;
    word32 t;
    unsigned int f;

    /* If e >= -1076 the value is "normal"; otherwise it would be subnormal,
     * which we clamp down to zero. */
    e += 1076;
    t = (word32)e >> 31;
    m &= (word64)t - 1;

    /* If m == 0 we want a zero: force e to 0 too (the sign is conserved). */
    t = (word32)(m >> 54);
    e &= -(int)t;

    /* The 52 stored mantissa bits come from m. Its top set bit (bit 54)
     * increments the exponent field by one when added, which is what we want
     * (and produces 0 for m == 0). */
    x = (((word64)s << 63) | (m >> 2)) + ((word64)(word32)e << 52);

    /* Round to nearest, ties to even: increment when the low 3 bits of m are
     * 011, 110 or 111. A carry spilling into the exponent field is the desired
     * behaviour. */
    f = (unsigned int)m & 7U;
    x += (0xC8U >> f) & 1U;
    return x;
}

/* Normalize mantissa m so its top bit (bit 63) is set, adjusting exponent e so
 * that m * 2^e is preserved. A zero m is left unchanged. Constant-time. */
#define FPR_NORM64(m, e)   do {                                  \
        word32 nt_;                                              \
                                                                \
        (e) -= 63;                                              \
                                                                \
        nt_ = (word32)((m) >> 32);                               \
        nt_ = (nt_ | (word32)(0U - nt_)) >> 31;                  \
        (m) ^= ((m) ^ ((m) << 32)) & ((word64)nt_ - 1);         \
        (e) += (int)(nt_ << 5);                                  \
                                                                \
        nt_ = (word32)((m) >> 48);                               \
        nt_ = (nt_ | (word32)(0U - nt_)) >> 31;                  \
        (m) ^= ((m) ^ ((m) << 16)) & ((word64)nt_ - 1);         \
        (e) += (int)(nt_ << 4);                                  \
                                                                \
        nt_ = (word32)((m) >> 56);                               \
        nt_ = (nt_ | (word32)(0U - nt_)) >> 31;                  \
        (m) ^= ((m) ^ ((m) <<  8)) & ((word64)nt_ - 1);         \
        (e) += (int)(nt_ << 3);                                  \
                                                                \
        nt_ = (word32)((m) >> 60);                               \
        nt_ = (nt_ | (word32)(0U - nt_)) >> 31;                  \
        (m) ^= ((m) ^ ((m) <<  4)) & ((word64)nt_ - 1);         \
        (e) += (int)(nt_ << 2);                                  \
                                                                \
        nt_ = (word32)((m) >> 62);                               \
        nt_ = (nt_ | (word32)(0U - nt_)) >> 31;                  \
        (m) ^= ((m) ^ ((m) <<  2)) & ((word64)nt_ - 1);         \
        (e) += (int)(nt_ << 1);                                  \
                                                                \
        nt_ = (word32)((m) >> 63);                               \
        (m) ^= ((m) ^ ((m) <<  1)) & ((word64)nt_ - 1);         \
        (e) += (int)(nt_);                                       \
    } while (0)

/* ------------------------------------------------------------------------ */
/* Constructors / conversions.                                               */
/* ------------------------------------------------------------------------ */

#ifndef WOLFSSL_FALCON_FPR_DOUBLE   /* inline backend provides fpr_scaled */
fpr fpr_scaled(sword64 i, int sc)
{
    /* Convert i * 2^sc to fpr: take the sign and absolute value, normalize the
     * magnitude so the top bit is set, round down to a 55-bit mantissa (with a
     * sticky low bit) and pack. The source integer is assumed not to be
     * -2^63. */
    int s, e;
    word32 t;
    word64 m;

    /* Sign and absolute value (-i == 1 + ~i). */
    s = (int)((word64)i >> 63);
    i ^= -(sword64)s;
    i += s;

    /* Suppose i != 0 for now: normalize it so the top bit is set. */
    m = (word64)i;
    e = 9 + sc;
    FPR_NORM64(m, e);

    /* m is now in 2^63..2^64-1; divide by 512 into the 2^54..2^55-1 range,
     * folding any dropped bit into the sticky low bit. */
    m |= ((word32)m & 0x1FF) + 0x1FF;
    m >>= 9;

    /* Corrective action for i == 0: clamp e and m to zero. */
    t = (word32)((word64)((word64)i | (word64)(0 - (word64)i)) >> 63);
    m &= (word64)0 - (word64)t;
    e &= -(int)t;

    /* FPR() handles exponents that are too low. */
    return FPR(s, e, m);
}
#endif /* !WOLFSSL_FALCON_FPR_DOUBLE */

#if !defined(WOLFSSL_FALCON_FPR_ASM) && !defined(WOLFSSL_FALCON_FPR_DOUBLE)
/* The scalar fpr operations below are supplied by the per-architecture assembly
 * backend (wc_falcon_fpr_x86_64_asm.S, WOLFSSL_FALCON_FPR_ASM) or by the inline
 * native-double backend (WOLFSSL_FALCON_FPR_DOUBLE) when either is set;
 * otherwise this constant-time integer emulation is used. fpr_expm_p63 and the
 * fpr constants (below) always come from this file. */
fpr fpr_of(sword64 i)
{
    return fpr_scaled(i, 0);
}

sword64 fpr_rint(fpr x)
{
    word64 m, d;
    int e;
    word32 s, dd, f;

    /* Assuming the value fits in -(2^63-1)..+(2^63-1), extract the mantissa as
     * a 63-bit integer and right-shift it as needed. */
    m = ((x << 10) | ((word64)1 << 62)) & (((word64)1 << 63) - 1);
    e = 1085 - ((int)(x >> 52) & 0x7FF);

    /* A shift of more than 63 bits sets m to zero (also covers x == 0). */
    m &= (word64)0 - (word64)((word32)(e - 64) >> 31);
    e &= 63;

    /* Right-shift m by e, rounding to nearest with ties to even. We build a
     * word holding all dropped bits plus the lowest kept bit, then shrink it
     * to three bits, the lowest being sticky. */
    d = fpr_ulsh(m, 63 - e);
    dd = (word32)d | ((word32)(d >> 32) & 0x1FFFFFFF);
    f = (word32)(d >> 61) | ((dd | (word32)(0U - dd)) >> 31);
    m = fpr_ursh(m, e) + (word64)((0xC8U >> f) & 1U);

    /* Apply the sign bit. */
    s = (word32)(x >> 63);
    return ((sword64)m ^ -(sword64)s) + (sword64)s;
}

sword64 fpr_floor(fpr x)
{
    word64 t;
    sword64 xi;
    int e, cc;

    /* Extract the value as a signed scaled integer in the 2^62..2^63-1 range
     * (absolute value), so only a right-shift is needed afterwards. */
    e = (int)(x >> 52) & 0x7FF;
    t = x >> 63;
    xi = (sword64)(((x << 10) | ((word64)1 << 62)) & (((word64)1 << 63) - 1));
    xi = (xi ^ -(sword64)t) + (sword64)t;
    cc = 1085 - e;

    /* An arithmetic right-shift implements floor() (round toward -inf) for
     * both positive and negative values. */
    xi = fpr_irsh(xi, cc & 63);

    /* If the true shift count was 64 or more, replace xi with 0 (nonnegative)
     * or -1 (negative). This also fixes the bogus implicit-bit assumption for
     * a zero input. */
    xi ^= (xi ^ -(sword64)t) & -(sword64)((word32)(63 - cc) >> 31);
    return xi;
}

sword64 fpr_trunc(fpr x)
{
    word64 t, xu;
    int e, cc;

    /* Extract the absolute value as a scaled integer in the 2^62..2^63-1
     * range, then right-shift. */
    e = (int)(x >> 52) & 0x7FF;
    xu = ((x << 10) | ((word64)1 << 62)) & (((word64)1 << 63) - 1);
    cc = 1085 - e;
    xu = fpr_ursh(xu, cc & 63);

    /* If the exponent is too low (cc > 63), clamp to zero (also covers
     * x == 0). */
    xu &= (word64)0 - (word64)((word32)(cc - 64) >> 31);

    /* Apply the sign. */
    t = x >> 63;
    xu = (xu ^ ((word64)0 - t)) + t;
    return (sword64)xu;
}

/* ------------------------------------------------------------------------ */
/* Arithmetic.                                                               */
/* ------------------------------------------------------------------------ */

fpr fpr_add(fpr x, fpr y)
{
    word64 m, xu, yu, za;
    word32 cs;
    int ex, ey, sx, sy, cc;

    /* Ensure x has the larger absolute value, so the exponent of y is no
     * greater than that of x. We also conditionally swap when abs(x) == abs(y)
     * and the sign of x is 1, which guarantees the result keeps the sign of x
     * (and is +0 in the exact-cancellation case). */
    m = ((word64)1 << 63) - 1;
    za = (x & m) - (y & m);
    cs = (word32)(za >> 63)
         | ((1U - (word32)(((word64)0 - za) >> 63)) & (word32)(x >> 63));
    m = (x ^ y) & ((word64)0 - (word64)cs);
    x ^= m;
    y ^= m;

    /* Extract sign bits, biased exponents and mantissas. The mantissas are
     * scaled up to the 2^55..2^56-1 range. A zero operand gets mantissa 0 and
     * exponent -1078. */
    ex = (int)(x >> 52);
    sx = ex >> 11;
    ex &= 0x7FF;
    m = (word64)(word32)((ex + 0x7FF) >> 11) << 52;
    xu = ((x & (((word64)1 << 52) - 1)) | m) << 3;
    ex -= 1078;
    ey = (int)(y >> 52);
    sy = ey >> 11;
    ey &= 0x7FF;
    m = (word64)(word32)((ey + 0x7FF) >> 11) << 52;
    yu = ((y & (((word64)1 << 52) - 1)) | m) << 3;
    ey -= 1078;

    /* x has the larger exponent; right-shift y to align. A shift of 60 bits or
     * more clamps y to zero. */
    cc = ex - ey;
    yu &= (word64)0 - (word64)((word32)(cc - 60) >> 31);
    cc &= 63;

    /* The lowest bit of yu becomes sticky over the shifted-out bits. */
    m = fpr_ulsh(1, cc) - 1;
    yu |= (yu & m) + m;
    yu = fpr_ursh(yu, cc);

    /* Same sign: add mantissas; differing signs: subtract. */
    xu += yu - ((yu << 1) & ((word64)0 - (word64)(sx ^ sy)));

    /* Renormalize the (possibly cancelled or carried) result. */
    FPR_NORM64(xu, ex);

    /* Scale down to the 2^54..2^55-1 range, keeping a sticky low bit. */
    xu |= ((word32)xu & 0x1FF) + 0x1FF;
    xu >>= 9;
    ex += 9;

    /* The result keeps the sign of x (the swap above made the -0 corner cases
     * impossible); FPR() clamps a too-low exponent to zero without altering
     * the sign. */
    return FPR(sx, ex, xu);
}

fpr fpr_sub(fpr x, fpr y)
{
    y ^= (word64)1 << 63;
    return fpr_add(x, y);
}

fpr fpr_neg(fpr x)
{
    x ^= (word64)1 << 63;
    return x;
}

fpr fpr_half(fpr x)
{
    /* Halving subtracts 1 from the exponent; handle zero specially. */
    word32 t;

    x -= (word64)1 << 52;
    t = (((word32)(x >> 52) & 0x7FF) + 1) >> 11;
    x &= (word64)t - 1;
    return x;
}

fpr fpr_double(fpr x)
{
    /* Doubling increments the exponent; handle zero specially. Infinities and
     * NaNs are not a concern for this backend. */
    x += (word64)((((unsigned int)(x >> 52) & 0x7FFU) + 0x7FFU) >> 11) << 52;
    return x;
}

fpr fpr_mul(fpr x, fpr y)
{
    word64 xu, yu, w, zu, zv;
    word32 x0, x1, y0, y1, z0, z1, z2;
    int ex, ey, d, e, s;

    /* Extract mantissas (with implicit bit) as 53-bit integers. */
    xu = (x & (((word64)1 << 52) - 1)) | ((word64)1 << 52);
    yu = (y & (((word64)1 << 52) - 1)) | ((word64)1 << 52);

    /* Multiply the two 53-bit integers using 25-bit low halves so the low
     * limbs (z0, z1) only ever matter for the sticky bit. */
    x0 = (word32)xu & 0x01FFFFFF;
    x1 = (word32)(xu >> 25);
    y0 = (word32)yu & 0x01FFFFFF;
    y1 = (word32)(yu >> 25);
    w = (word64)x0 * (word64)y0;
    z0 = (word32)w & 0x01FFFFFF;
    z1 = (word32)(w >> 25);
    w = (word64)x0 * (word64)y1;
    z1 += (word32)w & 0x01FFFFFF;
    z2 = (word32)(w >> 25);
    w = (word64)x1 * (word64)y0;
    z1 += (word32)w & 0x01FFFFFF;
    z2 += (word32)(w >> 25);
    zu = (word64)x1 * (word64)y1;
    z2 += (z1 >> 25);
    z1 &= 0x01FFFFFF;
    zu += z2;

    /* The product is in 2^104..2^106-1. Keep the top part (zu); fold the low
     * limbs into a sticky bit. */
    zu |= ((z0 | z1) + 0x01FFFFFF) >> 25;

    /* Normalize zu to 2^54..2^55-1; it may be one bit too large. The
     * conditional right-shift preserves the sticky bit. */
    zv = (zu >> 1) | (zu & 1);
    w = zu >> 55;
    zu ^= (zu ^ zv) & ((word64)0 - w);

    /* Aggregate scaling factor: sum the exponents, remove 2*(1023+52), then
     * add 50 + w (the right-shift amounts applied above). */
    ex = (int)((x >> 52) & 0x7FF);
    ey = (int)((y >> 52) & 0x7FF);
    e = ex + ey - 2100 + (int)w;

    /* Result sign is the XOR of the operand signs. */
    s = (int)((x ^ y) >> 63);

    /* Corrective action: if either operand is zero, clamp the mantissa. */
    d = ((ex + 0x7FF) & (ey + 0x7FF)) >> 11;
    zu &= (word64)0 - (word64)d;

    return FPR(s, e, zu);
}

fpr fpr_sqr(fpr x)
{
    return fpr_mul(x, x);
}

fpr fpr_div(fpr x, fpr y)
{
    word64 xu, yu, q, q2, w;
    int i, ex, ey, e, d, s;

    /* Extract mantissas (with implicit bit). */
    xu = (x & (((word64)1 << 52) - 1)) | ((word64)1 << 52);
    yu = (y & (((word64)1 << 52) - 1)) | ((word64)1 << 52);

    /* Bit-by-bit long division of xu by yu, for 55 bits. */
    q = 0;
    for (i = 0; i < 55; i++) {
        word64 b;

        b = ((xu - yu) >> 63) - 1;
        xu -= b & yu;
        q |= b & 1;
        xu <<= 1;
        q <<= 1;
    }

    /* Make the 56th (extra) bit sticky: set it iff the remainder is nonzero. */
    q |= (xu | ((word64)0 - xu)) >> 63;

    /* Normalize q to the 2^54..2^55-1 range (conditional shift, sticky-aware);
     * the top bit may be zero but then the next bit is one. */
    q2 = (q >> 1) | (q & 1);
    w = q >> 55;
    q ^= (q ^ q2) & ((word64)0 - w);

    /* Scaling: exponent biases cancel; remove 55 (division shift) and add w. */
    ex = (int)((x >> 52) & 0x7FF);
    ey = (int)((y >> 52) & 0x7FF);
    e = ex - ey - 55 + (int)w;

    /* Result sign is the XOR of the operand signs. */
    s = (int)((x ^ y) >> 63);

    /* Corrective action for x == 0 (division by zero is excluded by the
     * caller's contract). */
    d = (ex + 0x7FF) >> 11;
    s &= d;
    e &= -d;
    q &= (word64)0 - (word64)d;

    return FPR(s, e, q);
}

fpr fpr_inv(fpr x)
{
    /* 1.0 / x: fpr_one is the bit pattern of the double 1.0. */
    return fpr_div(fpr_one, x);
}

fpr fpr_sqrt(fpr x)
{
    word64 xu, q, s, r;
    int i, ex, e;

    /* Extract the mantissa and the true exponent (mantissa in 1..2). The sign
     * is ignored: the operand is assumed nonnegative. */
    xu = (x & (((word64)1 << 52) - 1)) | ((word64)1 << 52);
    ex = (int)((x >> 52) & 0x7FF);
    e = ex - 1023;

    /* If the exponent is odd, double the mantissa and decrement the exponent,
     * then halve the exponent for the square root. */
    xu += xu & ((word64)0 - (word64)(e & 1));
    e >>= 1;

    /* Double the mantissa: now in 2^53..2^55-1, representing a value in
     * [1, 4) with 53 fractional bits. */
    xu <<= 1;

    /* Compute the square root bit by bit. */
    q = 0;
    s = 0;
    r = (word64)1 << 53;
    for (i = 0; i < 54; i++) {
        word64 t, b;

        t = s + r;
        b = ((xu - t) >> 63) - 1;
        s += (r << 1) & b;
        xu -= t & b;
        q += r & b;
        xu <<= 1;
        r >>= 1;
    }

    /* q is a rounded-low 54-bit value (leading 1, 52 fractional digits and a
     * guard bit); add a sticky bit for the remaining operand. */
    q <<= 1;
    q |= (xu | ((word64)0 - xu)) >> 63;

    /* q is now an integer in 2^54..2^55-1; bias the exponent by 54. */
    e -= 54;

    /* Corrective action for an operand of value zero. */
    q &= (word64)0 - (word64)((ex + 0x7FF) >> 11);

    return FPR(0, e, q);
}

/* ------------------------------------------------------------------------ */
/* Predicates.                                                               */
/* ------------------------------------------------------------------------ */

int fpr_lt(fpr x, fpr y)
{
    /* For equal signs a signed comparison of the bit patterns yields the
     * correct order (and x - y does not overflow). For differing signs the
     * sign of x decides. For two negatives the order is reversed, so we
     * combine sgn(x-y) and sgn(y-x). */
    int cc0, cc1;
    sword64 sx;
    sword64 sy;

    sx = (sword64)x;
    sy = (sword64)y;
    sy &= ~((sx ^ sy) >> 63); /* sy = 0 if the signs differ */

    cc0 = (int)((sx - sy) >> 63) & 1; /* neither subtraction overflows when */
    cc1 = (int)((sy - sx) >> 63) & 1; /* the signs are the same             */

    return cc0 ^ ((cc0 ^ cc1) & (int)((x & y) >> 63));
}
#endif /* !WOLFSSL_FALCON_FPR_ASM */

/* ------------------------------------------------------------------------ */
/* Sampler support: ccs * exp(-x) in fixed point scaled by 2^63.            */
/* ------------------------------------------------------------------------ */

/* Top 64 bits of the 128-bit product z*y. This is the inner operation of the
 * Bernoulli-exp polynomial and the hottest scalar op in signing. On 64-bit
 * targets it is a single multiply instruction; the portable 32x32 fallback
 * (one MUL becomes four) is kept for platforms without a 128-bit integer type
 * (e.g. Cortex-M). Both paths are constant-time and bit-identical. */
#if defined(__SIZEOF_INT128__)
#define FALCON_MULHI(z, y) \
    ((word64)(((unsigned __int128)(word64)(z) * (unsigned __int128)(word64)(y)) >> 64))
#else
static WC_INLINE word64 falcon_mulhi(word64 z, word64 y)
{
    word32 z0 = (word32)z, z1 = (word32)(z >> 32);
    word32 y0 = (word32)y, y1 = (word32)(y >> 32);
    word64 a = ((word64)z0 * (word64)y1) + (((word64)z0 * (word64)y0) >> 32);
    word64 b = ((word64)z1 * (word64)y0);
    word64 c = (a >> 32) + (b >> 32);
    c += (((word64)(word32)a + (word64)(word32)b) >> 32);
    c += (word64)z1 * (word64)y1;
    return c;
}
#define FALCON_MULHI(z, y) falcon_mulhi((z), (y))
#endif

word64 fpr_expm_p63(fpr x, fpr ccs)
{
    /* Polynomial approximation of exp(-x), coefficients from FACCT
     * (https://eprint.iacr.org/2018/1234, https://github.com/raykzhao/gaussian)
     * scaled up by 2^63 and converted to integers. The maximum observed
     * deviation from the true value over the 0..log(2) range is below
     * 2^(-50). */
    static const word64 C[] = {
        0x00000004741183A3u,
        0x00000036548CFC06u,
        0x0000024FDCBF140Au,
        0x0000171D939DE045u,
        0x0000D00CF58F6F84u,
        0x000680681CF796E3u,
        0x002D82D8305B0FEAu,
        0x011111110E066FD0u,
        0x0555555555070F00u,
        0x155555555581FF00u,
        0x400000000002B400u,
        0x7FFFFFFFFFFF4800u,
        0x8000000000000000u
    };

    word64 z, y;

    /* Horner evaluation of the degree-12 polynomial; each step keeps the top
     * 64 bits of z*y. Fully unrolled (the loop bound is a compile-time 13). */
    y = C[0];
    z = (word64)fpr_trunc(fpr_mul(x, fpr_ptwo63)) << 1;
    y = C[1]  - FALCON_MULHI(z, y);
    y = C[2]  - FALCON_MULHI(z, y);
    y = C[3]  - FALCON_MULHI(z, y);
    y = C[4]  - FALCON_MULHI(z, y);
    y = C[5]  - FALCON_MULHI(z, y);
    y = C[6]  - FALCON_MULHI(z, y);
    y = C[7]  - FALCON_MULHI(z, y);
    y = C[8]  - FALCON_MULHI(z, y);
    y = C[9]  - FALCON_MULHI(z, y);
    y = C[10] - FALCON_MULHI(z, y);
    y = C[11] - FALCON_MULHI(z, y);
    y = C[12] - FALCON_MULHI(z, y);

    /* Apply the scaling factor ccs (converted to the same fixed-point format)
     * with a final 64x64->high-64 multiplication. */
    z = (word64)fpr_trunc(fpr_mul(ccs, fpr_ptwo63)) << 1;
    y = FALCON_MULHI(z, y);

    return y;
}

/* ------------------------------------------------------------------------ */
/* Named constants: IEEE-754 binary64 bit patterns.                          */
/* ------------------------------------------------------------------------ */

const fpr fpr_zero      = 0;
const fpr fpr_one       = 4607182418800017408U;   /*  1.0            */
const fpr fpr_two       = 4611686018427387904U;   /*  2.0            */
const fpr fpr_onehalf   = 4602678819172646912U;   /*  0.5            */
const fpr fpr_invsqrt2  = 4604544271217802189U;   /*  1/sqrt(2)      */
const fpr fpr_invsqrt8  = 4600040671590431693U;   /*  1/sqrt(8)      */
const fpr fpr_ptwo31    = 4746794007248502784U;   /*  2^31           */
const fpr fpr_ptwo31m1  = 4746794007244308480U;   /*  2^31 - 1       */
const fpr fpr_mtwo31m1  = 13970166044099084288U;  /* -(2^31 - 1)     */
const fpr fpr_ptwo63m1  = 4890909195324358656U;   /*  2^63 - 1       */
const fpr fpr_mtwo63m1  = 14114281232179134464U;  /* -(2^63 - 1)     */
const fpr fpr_ptwo63    = 4890909195324358656U;   /*  2^63           */

#endif /* HAVE_FALCON */
