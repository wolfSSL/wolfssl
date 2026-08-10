/* test_sp_crafted_common.h
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

/*
 * Crafted-input driver shared by the three SP host-backend white-boxes
 * (sp_x86_64.c / sp_c64.c / sp_c32.c).
 *
 * WHY A SHARED HEADER
 * -------------------
 * The three backends are three implementations of ONE API: every public
 * entry point in them has the same name and the same signature
 * (sp_ecc_mulmod_256, sp_ecc_check_key_384, sp_DhExp_2048, ...). Only the
 * internal digit-level helpers differ (sp_256_iszero_4 vs _5 vs _9), and
 * nothing here touches those. So one body, included after the .c under
 * test, drives all three.
 *
 * WHAT IT ADDS OVER THE EXISTING DRIVERS
 * --------------------------------------
 * The existing white-boxes drive the backends through the public wc_*
 * API plus a few direct calls. That leaves whole functions never entered
 * and, inside the ones that are entered, leaves the guards that sit
 * BEHIND a successful earlier step unreached. Concretely:
 *
 * 1. Entry points nothing in the wc_* API reaches on this configuration:
 *    sp_ecc_mulmod_<n>, sp_ecc_mulmod_base_<n>, sp_ecc_mulmod_base_add_<n>
 *    and sp_ecc_uncompress_<n>. Each carries a cpuid dispatch (on the asm
 *    backend) that cannot be measured at all until the function runs.
 *
 * 2. sp_ecc_check_key_<n> past its argument checks. The earlier drivers
 *    only ever handed it deliberately invalid coordinates -- (0,0), an
 *    oversized ordinate, the field modulus -- every one of which fails
 *    before "Check point is on curve". Everything after that point (the
 *    order-multiply dispatch, the "result is infinity" test and the
 *    "private key matches public point" test) therefore never ran. A REAL
 *    (pub, priv) pair reaches all of it; a real pub with a WRONG priv
 *    gives the mismatch test its other side.
 *
 * 3. sp_ecc_verify_<n> on a signature that does NOT verify. Every earlier
 *    verify succeeded, so `*res` was always 1 and the "reload r, add the
 *    order and compare again" recovery block was dead. Two failing
 *    verifies are used, chosen so the recovery block's second operand
 *    goes both ways: r == 1 makes r + order fit under the prime (compare
 *    < 0, block entered), while a full-width r from a real signature
 *    overflows the addition (carry != 0, compare left at 0, block
 *    skipped).
 *
 * 4. sp_ecc_verify_<n> where the verification point is the point at
 *    infinity. u1 = e/s and u2 = r/s, so an all-zero hash forces u1 == 0
 *    ([0]G == infinity, p1->z == 0) and r == 0 forces u2 == 0
 *    (p2->z == 0). Both are ordinary numbers to pass in, and both are
 *    the only way those two `sp_<n>_iszero_<n>(p?->z)` guards go true.
 *
 * 5. sp_ecc_sign_<n> with a caller-supplied k. The `km == NULL ||
 *    mp_iszero(km)` guard is short-circuited by every wc_* caller, which
 *    always passes NULL; passing a zero k and then a non-zero k gives the
 *    second operand both of its vectors.
 *
 * 6. sp_ModExp_<n> / sp_DhExp_<n> / sp_RsaPublic_<n> / sp_RsaPrivate_<n>
 *    argument-range checks, and the two data-dependent shapes inside
 *    sp_DhExp_<n>: the `base == 2 && top word of modulus is all ones`
 *    fast path (driven with base 3, and with a modulus whose top word has
 *    a bit cleared), and the leading-zero trim loop over the output
 *    (driven with base 0, whose exponentiation result is zero, so the
 *    loop runs the full width instead of stopping at the first byte).
 *
 * Nothing here is a known-answer test: correctness of the arithmetic is
 * the job of the ordinary wolfCrypt suite. Return values are discarded --
 * several calls are EXPECTED to fail, that is the point -- and the bar
 * every call has to clear is only "completes without crashing".
 *
 * The including TU must have already included the wolfCrypt .c under test
 * (so the file-static curve constants are visible) and ecc.h/dh.h/rsa.h.
 */

#ifndef TEST_SP_CRAFTED_COMMON_H
#define TEST_SP_CRAFTED_COMMON_H

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/random.h>

#include <stdio.h>

#define WB_SPC_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

/* Fixed message digest. Its value is irrelevant; only its width matters. */
static const byte wb_spc_digest[32] = {
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
};
/* An all-zero digest makes u1 = e/s == 0 in the verify point calculation,
 * i.e. [0]G, the point at infinity. */
static const byte wb_spc_zdigest[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* ======================================================================= *
 * ECC: one driver per compiled-in curve, generated from the curve size.
 * ======================================================================= */
#if defined(WOLFSSL_HAVE_SP_ECC) && defined(HAVE_ECC)

#if defined(HAVE_ECC_CHECK_KEY) || !defined(NO_ECC_CHECK_PUBKEY_ORDER)
    #define WB_SPC_HAVE_CHECK_KEY
#endif

#define WB_SPC_DEFINE_CURVE(BITS, SZ, CURVE_ID)                             \
static void wb_spc_ecc_##BITS(void)                                         \
{                                                                           \
    ecc_key     key;                                                        \
    WC_RNG      rng;                                                        \
    ecc_point*  rp = NULL;                                                  \
    mp_int      k;                                                          \
    mp_int      one;                                                        \
    mp_int      zero;                                                       \
    mp_int      modv;                                                       \
    mp_int      rmv;                                                        \
    mp_int      smv;                                                        \
    mp_int      kmv;                                                        \
    mp_int      yv;                                                         \
    int         res = 0;                                                    \
    int         inMont;                                                     \
    int         map;                                                        \
    int         okKey = 0;                                                  \
                                                                            \
    XMEMSET(&key, 0, sizeof(key));                                          \
    XMEMSET(&rng, 0, sizeof(rng));                                          \
                                                                            \
    if (wc_InitRng(&rng) != 0) {                                            \
        WB_SPC_NOTE("wc_InitRng failed (crafted " #BITS ")");               \
        return;                                                             \
    }                                                                       \
    if (wc_ecc_init(&key) != 0) {                                           \
        WB_SPC_NOTE("wc_ecc_init failed (crafted " #BITS ")");              \
        wc_FreeRng(&rng);                                                   \
        return;                                                             \
    }                                                                       \
    if (mp_init_multi(&k, &one, &zero, &modv, &rmv, &smv) != MP_OKAY) {     \
        WB_SPC_NOTE("mp_init_multi failed (crafted " #BITS ")");            \
        wc_ecc_free(&key);                                                  \
        wc_FreeRng(&rng);                                                   \
        return;                                                             \
    }                                                                       \
    if (mp_init_multi(&kmv, &yv, NULL, NULL, NULL, NULL) != MP_OKAY) {      \
        WB_SPC_NOTE("mp_init_multi failed (crafted " #BITS ")");            \
        mp_clear(&k); mp_clear(&one); mp_clear(&zero);                      \
        mp_clear(&modv); mp_clear(&rmv); mp_clear(&smv);                    \
        wc_ecc_free(&key);                                                  \
        wc_FreeRng(&rng);                                                   \
        return;                                                             \
    }                                                                       \
                                                                            \
    (void)mp_set(&k, 5);                                                    \
    (void)mp_set(&one, 1);                                                  \
    mp_zero(&zero);                                                         \
    (void)sp_##BITS##_to_mp(p##BITS##_mod, &modv);                          \
                                                                            \
    if (wc_ecc_make_key_ex(&rng, SZ, &key, CURVE_ID) == 0) {                \
        okKey = 1;                                                          \
    }                                                                       \
    else {                                                                  \
        WB_SPC_NOTE("wc_ecc_make_key_ex failed (crafted " #BITS ")");       \
    }                                                                       \
                                                                            \
    rp = wc_ecc_new_point();                                                \
    if (okKey && (rp != NULL)) {                                            \
        /* Entry points the wc_* API never takes on this configuration. */  \
        (void)sp_ecc_mulmod_##BITS(&k, &key.pubkey, rp, 1, NULL);           \
        (void)sp_ecc_mulmod_##BITS(&k, &key.pubkey, rp, 0, NULL);           \
        (void)sp_ecc_mulmod_base_##BITS(&k, rp, 1, NULL);                   \
        (void)sp_ecc_mulmod_base_##BITS(&k, rp, 0, NULL);                   \
        for (inMont = 0; inMont <= 1; inMont++) {                           \
            for (map = 0; map <= 1; map++) {                                \
                (void)sp_ecc_mulmod_base_add_##BITS(&k, &key.pubkey,        \
                    inMont, rp, map, NULL);                                 \
                (void)sp_ecc_mulmod_add_##BITS(&k, &key.pubkey,             \
                    &key.pubkey, inMont, rp, map, NULL);                    \
            }                                                               \
        }                                                                   \
    }                                                                       \
    if (rp != NULL) {                                                       \
        wc_ecc_del_point(rp);                                               \
    }                                                                       \
                                                                            \
    if (okKey) {                                                            \
        /* A real point, so the on-curve test passes and everything         \
         * behind it runs for the first time. */                            \
        (void)sp_ecc_is_point_##BITS(key.pubkey.x, key.pubkey.y);           \
    }                                                                       \
                                                                            \
    WB_SPC_CHECK_KEY_BODY(BITS)                                             \
    WB_SPC_UNCOMPRESS_BODY(BITS)                                            \
    WB_SPC_SIGNVERIFY_BODY(BITS)                                            \
                                                                            \
    mp_clear(&yv);                                                          \
    mp_clear(&kmv);                                                         \
    mp_clear(&smv);                                                         \
    mp_clear(&rmv);                                                         \
    mp_clear(&modv);                                                        \
    mp_clear(&zero);                                                        \
    mp_clear(&one);                                                         \
    mp_clear(&k);                                                           \
    wc_ecc_free(&key);                                                      \
    wc_FreeRng(&rng);                                                       \
    WB_SPC_NOTE("crafted SP entry points exercised (P-" #BITS ")");         \
}

#ifdef WB_SPC_HAVE_CHECK_KEY
/* x == 0 with a non-zero y gives the point-at-infinity test its second
 * operand's false side; the real (pub, priv) pair walks the whole
 * function; the real pub with k == 5 as the "private key" makes the
 * final "private key matches public point" comparison go true. */
#define WB_SPC_CHECK_KEY_BODY(BITS)                                         \
    if (okKey) {                                                            \
        (void)sp_ecc_check_key_##BITS(key.pubkey.x, key.pubkey.y,           \
            ecc_get_k(&key), NULL);                                         \
        (void)sp_ecc_check_key_##BITS(key.pubkey.x, key.pubkey.y,           \
            NULL, NULL);                                                    \
        (void)sp_ecc_check_key_##BITS(key.pubkey.x, key.pubkey.y,           \
            &k, NULL);                                                      \
        (void)sp_ecc_check_key_##BITS(&zero, key.pubkey.y, NULL, NULL);     \
        (void)sp_ecc_check_key_##BITS(key.pubkey.x, &zero, NULL, NULL);     \
        (void)sp_ecc_check_key_##BITS(key.pubkey.x, &modv, NULL, NULL);     \
        (void)sp_ecc_check_key_##BITS(&modv, key.pubkey.y, NULL, NULL);     \
        /* (order - d) * G is the negation of the public point: same x,    \
         * different y. That is the only way the final comparison's        \
         * second operand goes true with its first one false. kmv is       \
         * scratch here; the sign/verify body below resets it. */          \
        if ((sp_##BITS##_to_mp(p##BITS##_order, &kmv) == MP_OKAY) &&       \
                (mp_sub(&kmv, ecc_get_k(&key), &yv) == MP_OKAY)) {         \
            (void)sp_ecc_check_key_##BITS(key.pubkey.x, key.pubkey.y,      \
                &yv, NULL);                                                \
        }                                                                  \
    }
#else
#define WB_SPC_CHECK_KEY_BODY(BITS) /* not compiled in this config */
#endif

#ifdef HAVE_COMP_KEY
#define WB_SPC_UNCOMPRESS_BODY(BITS)                                        \
    if (okKey) {                                                            \
        (void)sp_ecc_uncompress_##BITS(key.pubkey.x, 0, &yv);               \
        (void)sp_ecc_uncompress_##BITS(key.pubkey.x, 1, &yv);               \
    }
#else
#define WB_SPC_UNCOMPRESS_BODY(BITS) /* needs HAVE_COMP_KEY */
#endif

#if defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY)
#define WB_SPC_SIGNVERIFY_BODY(BITS)                                        \
    if (okKey) {                                                            \
        /* km supplied and zero, then km supplied and non-zero: the only    \
         * two vectors of the `km == NULL || mp_iszero(km)` second          \
         * operand, which every wc_* caller short-circuits with NULL. */    \
        mp_zero(&kmv);                                                      \
        (void)sp_ecc_sign_##BITS(wb_spc_digest, 32, &rng,                   \
            ecc_get_k(&key), &rmv, &smv, &kmv, NULL);                       \
        (void)mp_set(&kmv, 7);                                              \
        (void)sp_ecc_sign_##BITS(wb_spc_digest, 32, &rng,                   \
            ecc_get_k(&key), &rmv, &smv, &kmv, NULL);                       \
                                                                            \
        if (sp_ecc_sign_##BITS(wb_spc_digest, 32, &rng, ecc_get_k(&key),    \
                &rmv, &smv, NULL, NULL) == 0) {                             \
            /* Valid. */                                                    \
            (void)sp_ecc_verify_##BITS(wb_spc_digest, 32, key.pubkey.x,     \
                key.pubkey.y, &one, &rmv, &smv, &res, NULL);                \
            /* Invalid, full-width r: r + order overflows, so the           \
             * recovery block's compare is left alone and skips it. */      \
            (void)sp_ecc_verify_##BITS(wb_spc_zdigest, 32, key.pubkey.x,    \
                key.pubkey.y, &one, &rmv, &smv, &res, NULL);                \
            /* Invalid, r == 1: r + order stays under the prime, so the     \
             * recovery block runs. */                                      \
            (void)sp_ecc_verify_##BITS(wb_spc_digest, 32, key.pubkey.x,     \
                key.pubkey.y, &one, &one, &smv, &res, NULL);                \
            /* r == 0 => u2 == 0 => [0]Q is the point at infinity. */       \
            (void)sp_ecc_verify_##BITS(wb_spc_digest, 32, key.pubkey.x,     \
                key.pubkey.y, &one, &zero, &smv, &res, NULL);               \
            /* e == 0 => u1 == 0 => [0]G is the point at infinity. */       \
            (void)sp_ecc_verify_##BITS(wb_spc_zdigest, 32, key.pubkey.x,    \
                key.pubkey.y, &one, &one, &smv, &res, NULL);                \
        }                                                                   \
    }
#else
#define WB_SPC_SIGNVERIFY_BODY(BITS) /* needs HAVE_ECC_SIGN/VERIFY */
#endif

#ifndef WOLFSSL_SP_NO_256
WB_SPC_DEFINE_CURVE(256, 32, ECC_SECP256R1)
#endif
#ifdef WOLFSSL_SP_384
WB_SPC_DEFINE_CURVE(384, 48, ECC_SECP384R1)
#endif
#ifdef WOLFSSL_SP_521
WB_SPC_DEFINE_CURVE(521, 66, ECC_SECP521R1)
#endif

static void wb_spc_ecc_all(void)
{
#ifndef WOLFSSL_SP_NO_256
    wb_spc_ecc_256();
#endif
#ifdef WOLFSSL_SP_384
    wb_spc_ecc_384();
#endif
#ifdef WOLFSSL_SP_521
    wb_spc_ecc_521();
#endif
}

#else /* !(WOLFSSL_HAVE_SP_ECC && HAVE_ECC) */
static void wb_spc_ecc_all(void)
{
    WB_SPC_NOTE("SP ECC not compiled; crafted ECC skipped");
}
#endif

/* ======================================================================= *
 * RSA / DH / ModExp: argument-range guards and the two data-dependent
 * shapes inside sp_DhExp_<n>.
 * ======================================================================= */

/* Scratch big enough for a 4096-bit modulus. */
#define WB_SPC_MAXBYTES 512

/* Build an odd number of exactly `bits` bits whose TOP word is not all
 * ones (bit `bits-2` cleared), so the sp_DhExp fast-path test
 * `m[top] == (sp_digit)-1` goes false while the bit-count check still
 * passes. */
static int wb_spc_make_modulus(mp_int* m, int bits)
{
    byte buf[WB_SPC_MAXBYTES];
    int  bytes = bits / 8;
    int  i;

    if ((bytes <= 0) || (bytes > (int)sizeof(buf))) {
        return -1;
    }
    for (i = 0; i < bytes; i++) {
        buf[i] = 0xFF;
    }
    buf[0] = 0xBF;            /* top bit set (keeps the bit count), next
                               * bit cleared (top word is not all ones) */
    buf[bytes - 1] = 0xFD;    /* odd */
    return mp_read_unsigned_bin(m, buf, (word32)bytes);
}

#if defined(WOLFSSL_HAVE_SP_DH) && !defined(NO_DH)
/* sp_DhExp_<n> over a modulus built by wb_spc_make_modulus(): right bit
 * width, odd, but its top word is NOT all ones. Base 2 then drives the
 * fast-path test's last operand false, base 3 drives its middle operand
 * false, and base 0 makes the exponentiation result zero so the output's
 * leading-zero trim loop runs the full width instead of stopping at the
 * first byte. The all-operands-true vector of that test comes from the
 * ordinary named-FFDHE key agreement the drivers already run. */
#define WB_SPC_DHEXP(BITS)                                                 \
do {                                                                       \
    mp_int b2;                                                             \
    mp_int b3;                                                             \
    mp_int b0;                                                             \
    mp_int mv;                                                             \
    byte   out[WB_SPC_MAXBYTES];                                           \
    byte   ex[8];                                                          \
    word32 outLen;                                                         \
                                                                           \
    XMEMSET(ex, 0, sizeof(ex));                                            \
    ex[sizeof(ex) - 1] = 0x0b;                                             \
    if (mp_init_multi(&b2, &b3, &b0, &mv, NULL, NULL) == MP_OKAY) {        \
        (void)mp_set(&b2, 2);                                              \
        (void)mp_set(&b3, 3);                                              \
        mp_zero(&b0);                                                      \
        if (wb_spc_make_modulus(&mv, (BITS)) == MP_OKAY) {                 \
            outLen = (word32)((BITS) / 8);                                 \
            (void)sp_DhExp_##BITS(&b2, ex, (word32)sizeof(ex), &mv,        \
                out, &outLen);                                             \
            outLen = (word32)((BITS) / 8);                                 \
            (void)sp_DhExp_##BITS(&b3, ex, (word32)sizeof(ex), &mv,        \
                out, &outLen);                                             \
            outLen = (word32)((BITS) / 8);                                 \
            (void)sp_DhExp_##BITS(&b0, ex, (word32)sizeof(ex), &mv,        \
                out, &outLen);                                             \
        }                                                                  \
        mp_clear(&mv);                                                     \
        mp_clear(&b0);                                                     \
        mp_clear(&b3);                                                     \
        mp_clear(&b2);                                                     \
    }                                                                      \
} while (0)
#endif /* WOLFSSL_HAVE_SP_DH && !NO_DH */

/* sp_ModExp_<n>: an odd modulus of exactly the right width is all its
 * argument checks want, and reaching past them is what puts its cpuid
 * dispatch on the measured path. */
#define WB_SPC_MODEXP(BITS)                                                \
do {                                                                       \
    mp_int b;                                                              \
    mp_int e;                                                              \
    mp_int m;                                                              \
    mp_int r;                                                              \
                                                                           \
    if (mp_init_multi(&b, &e, &m, &r, NULL, NULL) == MP_OKAY) {            \
        (void)mp_set(&b, 3);                                               \
        (void)mp_set(&e, 65537);                                           \
        if (wb_spc_make_modulus(&m, (BITS)) == MP_OKAY) {                  \
            (void)sp_ModExp_##BITS(&b, &e, &m, &r);                        \
        }                                                                  \
        mp_clear(&r);                                                      \
        mp_clear(&m);                                                      \
        mp_clear(&e);                                                      \
        mp_clear(&b);                                                      \
    }                                                                      \
} while (0)

#if defined(WOLFSSL_HAVE_SP_RSA) && !defined(NO_RSA)
/* sp_RsaPublic_<n> / sp_RsaPrivate_<n> argument-range guards. Each call
 * makes exactly one operand of the range chain true, with the earlier
 * ones false, which is what the chain's MC/DC pairs need. The output
 * buffer is deliberately large enough that the `*outLen` guard ahead of
 * the chain does not fire and hide it. */
#define WB_SPC_RSA_ARGS(BITS, WIDTH)                                       \
do {                                                                       \
    mp_int bigE;                                                           \
    mp_int smallE;                                                         \
    mp_int badM;                                                           \
    byte   in[8];                                                          \
    byte   ebuf[16];                                                       \
    byte   out[WB_SPC_MAXBYTES];                                           \
    word32 outLen;                                                         \
                                                                           \
    XMEMSET(in, 0x11, sizeof(in));                                         \
    XMEMSET(ebuf, 0xAA, sizeof(ebuf));                                     \
    if (mp_init_multi(&bigE, &smallE, &badM, NULL, NULL, NULL)             \
            == MP_OKAY) {                                                  \
        /* 128 bits, so the exponent-width operand goes true. */           \
        if (mp_read_unsigned_bin(&bigE, ebuf, (word32)sizeof(ebuf))        \
                == MP_OKAY) {                                              \
            outLen = (word32)(WIDTH);                                      \
            (void)sp_RsaPublic_##BITS(in, (word32)sizeof(in), &bigE,       \
                &bigE, out, &outLen);                                      \
        }                                                                  \
        (void)mp_set(&smallE, 65537);                                      \
        (void)mp_set(&badM, 3);                                            \
        /* inLen past the modulus width: middle operand true. */           \
        outLen = (word32)(WIDTH);                                          \
        (void)sp_RsaPublic_##BITS(in, (word32)(WIDTH) + 1, &smallE,        \
            &badM, out, &outLen);                                          \
        /* Everything in range but the modulus the wrong width. */         \
        outLen = (word32)(WIDTH);                                          \
        (void)sp_RsaPublic_##BITS(in, (word32)sizeof(in), &smallE,         \
            &badM, out, &outLen);                                          \
                                                                           \
        outLen = (word32)(WIDTH);                                          \
        (void)sp_RsaPrivate_##BITS(in, (word32)(WIDTH) + 1, &smallE,       \
            &smallE, &smallE, &smallE, &smallE, &smallE, &badM, out,       \
            &outLen);                                                      \
        outLen = (word32)(WIDTH);                                          \
        (void)sp_RsaPrivate_##BITS(in, (word32)sizeof(in), &smallE,        \
            &smallE, &smallE, &smallE, &smallE, &smallE, &badM, out,       \
            &outLen);                                                      \
                                                                           \
        mp_clear(&badM);                                                   \
        mp_clear(&smallE);                                                 \
        mp_clear(&bigE);                                                   \
    }                                                                      \
} while (0)
#endif /* WOLFSSL_HAVE_SP_RSA && !NO_RSA */

static void wb_spc_bigint_all(void)
{
#if defined(WOLFSSL_HAVE_SP_DH) && !defined(NO_DH)
    #ifndef WOLFSSL_SP_NO_2048
    WB_SPC_DHEXP(2048);
    #endif
    #ifndef WOLFSSL_SP_NO_3072
    WB_SPC_DHEXP(3072);
    #endif
    #ifdef WOLFSSL_SP_4096
    WB_SPC_DHEXP(4096);
    #endif
#endif

#if defined(WOLFSSL_HAVE_SP_DH) || \
    (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY))
    #ifndef WOLFSSL_SP_NO_2048
    WB_SPC_MODEXP(1024);
    WB_SPC_MODEXP(2048);
    #endif
    #ifndef WOLFSSL_SP_NO_3072
    WB_SPC_MODEXP(1536);
    WB_SPC_MODEXP(3072);
    #endif
    #ifdef WOLFSSL_SP_4096
    WB_SPC_MODEXP(4096);
    #endif
#endif

#if defined(WOLFSSL_HAVE_SP_RSA) && !defined(NO_RSA)
    #ifndef WOLFSSL_SP_NO_2048
    WB_SPC_RSA_ARGS(2048, 256);
    #endif
    #ifndef WOLFSSL_SP_NO_3072
    WB_SPC_RSA_ARGS(3072, 384);
    #endif
    #ifdef WOLFSSL_SP_4096
    WB_SPC_RSA_ARGS(4096, 512);
    #endif
#endif
    WB_SPC_NOTE("crafted ModExp/DhExp/RSA argument guards exercised");
}

static void wb_spc_all(void)
{
    /* Referenced unconditionally: which of these the preprocessor leaves
     * with a live use depends on the variant, and an unused static is a
     * warning this campaign's builds treat as noise to be avoided. */
    (void)wb_spc_digest;
    (void)wb_spc_zdigest;
    (void)wb_spc_make_modulus;

    wb_spc_ecc_all();
    wb_spc_bigint_all();
}

#endif /* TEST_SP_CRAFTED_COMMON_H */
