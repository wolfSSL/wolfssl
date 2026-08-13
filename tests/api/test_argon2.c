/* test_argon2.c
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

#include <tests/unit.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/argon2.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_argon2.h>

/*
 * The three RFC 9106 section 5 test vectors. All share the same inputs:
 * p=4, T=32, m=32, t=3, v=0x13, with secret and associated data supplied.
 */
int test_wc_Argon2_rfc9106(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ARGON2
    /* RFC 9106 section 5.1 */
    WOLFSSL_SMALL_STACK_STATIC const byte expD[] = {
        0x51, 0x2b, 0x39, 0x1b, 0x6f, 0x11, 0x62, 0x97,
        0x53, 0x71, 0xd3, 0x09, 0x19, 0x73, 0x42, 0x94,
        0xf8, 0x68, 0xe3, 0xbe, 0x39, 0x84, 0xf3, 0xc1,
        0xa1, 0x3a, 0x4d, 0xb9, 0xfa, 0xbe, 0x4a, 0xcb
    };
    /* RFC 9106 section 5.2 */
    WOLFSSL_SMALL_STACK_STATIC const byte expI[] = {
        0xc8, 0x14, 0xd9, 0xd1, 0xdc, 0x7f, 0x37, 0xaa,
        0x13, 0xf0, 0xd7, 0x7f, 0x24, 0x94, 0xbd, 0xa1,
        0xc8, 0xde, 0x6b, 0x01, 0x6d, 0xd3, 0x88, 0xd2,
        0x99, 0x52, 0xa4, 0xc4, 0x67, 0x2b, 0x6c, 0xe8
    };
    /* RFC 9106 section 5.3 */
    WOLFSSL_SMALL_STACK_STATIC const byte expID[] = {
        0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c,
        0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9,
        0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e,
        0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59
    };
    byte pwd[32], salt[16], secret[8], ad[12], out[32];

    XMEMSET(pwd,    0x01, sizeof(pwd));
    XMEMSET(salt,   0x02, sizeof(salt));
    XMEMSET(secret, 0x03, sizeof(secret));
    XMEMSET(ad,     0x04, sizeof(ad));

    XMEMSET(out, 0, sizeof(out));
    ExpectIntEQ(wc_Argon2_ex(WC_ARGON2_D, out, sizeof(out), pwd, sizeof(pwd),
        salt, sizeof(salt), secret, sizeof(secret), ad, sizeof(ad),
        4, 32, 3, HEAP_HINT), 0);
    ExpectIntEQ(XMEMCMP(out, expD, sizeof(expD)), 0);

    XMEMSET(out, 0, sizeof(out));
    ExpectIntEQ(wc_Argon2_ex(WC_ARGON2_I, out, sizeof(out), pwd, sizeof(pwd),
        salt, sizeof(salt), secret, sizeof(secret), ad, sizeof(ad),
        4, 32, 3, HEAP_HINT), 0);
    ExpectIntEQ(XMEMCMP(out, expI, sizeof(expI)), 0);

    XMEMSET(out, 0, sizeof(out));
    ExpectIntEQ(wc_Argon2_ex(WC_ARGON2_ID, out, sizeof(out), pwd, sizeof(pwd),
        salt, sizeof(salt), secret, sizeof(secret), ad, sizeof(ad),
        4, 32, 3, HEAP_HINT), 0);
    ExpectIntEQ(XMEMCMP(out, expID, sizeof(expID)), 0);
#endif
    return EXPECT_RESULT();
}

/*
 * Tag lengths around the H' boundary of RFC 9106 section 3.3.
 *
 * A tag of 64 bytes or fewer is one BLAKE2b digest; beyond that H' emits the
 * first 32 bytes of each of a chain of digests and the last one whole. The
 * sizes here cover both sides of that split and the two awkward points
 * inside it:
 *   T=64  the largest single-digest tag, one below the split
 *   T=65  the smallest chained tag: one 32-byte chunk and a 33-byte tail
 *   T=96  the tail digest is exactly 64 bytes, so the chain loop never runs
 *   T=97  the first size at which the chain loop body does run
 */
int test_wc_Argon2_long_tag(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ARGON2
    /* Argon2d, p=4, m=32, t=1, 64-byte tag: still a single digest. */
    WOLFSSL_SMALL_STACK_STATIC const byte exp64[] = {
        0xbf, 0xdd, 0x76, 0x8e, 0xfe, 0xbc, 0xa5, 0x8d,
        0xa2, 0x9c, 0x6f, 0x9c, 0x93, 0xc4, 0x72, 0x89,
        0x37, 0xf4, 0x94, 0x72, 0x62, 0x88, 0x3d, 0x50,
        0x6e, 0x75, 0xad, 0xf2, 0x0e, 0x75, 0x19, 0x04,
        0xbc, 0x65, 0x30, 0x01, 0x8c, 0xe4, 0x53, 0xbd,
        0x6e, 0xa5, 0x2f, 0xad, 0xd0, 0x28, 0x58, 0x0e,
        0xdd, 0xd9, 0xe2, 0xff, 0xf3, 0x00, 0x9d, 0x49,
        0xe2, 0xbb, 0x85, 0xdc, 0x71, 0x44, 0x0f, 0x5b
    };
    /* Argon2id, p=1, m=32, t=2, T=65: one chunk plus a 33-byte tail. */
    WOLFSSL_SMALL_STACK_STATIC const byte exp65[] = {
        0xcd, 0x5f, 0x3e, 0x16, 0x2d, 0x1a, 0xa8, 0x30,
        0x65, 0x40, 0x0b, 0xb2, 0x91, 0xdc, 0x93, 0xe6,
        0x17, 0xaf, 0x50, 0xac, 0x1b, 0xb2, 0x20, 0xd8,
        0x0e, 0x14, 0x50, 0x6a, 0x91, 0xa3, 0xe7, 0xf1,
        0x35, 0x14, 0x31, 0x64, 0x7e, 0xcd, 0x89, 0x32,
        0xc8, 0xbc, 0xa6, 0x40, 0x2f, 0x59, 0x0e, 0xcc,
        0xb0, 0x66, 0xca, 0xa5, 0x45, 0x34, 0xa0, 0x52,
        0x0c, 0xbe, 0xa7, 0xe0, 0xea, 0xd3, 0x08, 0x63,
        0xd5
    };
    /* Argon2id, p=1, m=32, t=2, T=96: tail is exactly one whole digest. */
    WOLFSSL_SMALL_STACK_STATIC const byte exp96[] = {
        0x4e, 0xd5, 0xc0, 0x54, 0x21, 0xe1, 0x9e, 0xdc,
        0xc2, 0x29, 0x48, 0xff, 0x44, 0xb1, 0x38, 0x64,
        0xf2, 0x80, 0xce, 0x37, 0x14, 0x32, 0x62, 0x5c,
        0xa7, 0x6e, 0x36, 0x29, 0x38, 0x69, 0x70, 0x9d,
        0x36, 0xaf, 0x46, 0x04, 0x29, 0xd3, 0x05, 0x01,
        0xeb, 0xf8, 0x17, 0x4e, 0xc7, 0xed, 0x60, 0xa4,
        0x13, 0x41, 0x09, 0x32, 0xe8, 0x71, 0xbd, 0x03,
        0x83, 0xa3, 0x01, 0x61, 0x18, 0x59, 0x04, 0x03,
        0xa1, 0xa6, 0xc7, 0x70, 0x9b, 0xfc, 0x09, 0x3b,
        0x6c, 0x06, 0xe9, 0x3a, 0x88, 0xb8, 0xd3, 0xa1,
        0x73, 0x33, 0xbe, 0x4f, 0x61, 0x33, 0x51, 0x6a,
        0xf1, 0x72, 0xb6, 0x59, 0x39, 0x04, 0xce, 0xcc
    };
    /* Argon2id, p=1, m=32, t=2, T=97: the chain loop runs once. */
    WOLFSSL_SMALL_STACK_STATIC const byte exp97[] = {
        0x73, 0x4a, 0xfa, 0x8d, 0xb7, 0xc3, 0xa2, 0x71,
        0x4a, 0xb2, 0xaf, 0x8a, 0xdc, 0xe6, 0xff, 0x44,
        0x3d, 0xdb, 0x9c, 0xa3, 0xb2, 0xd7, 0x77, 0x61,
        0x69, 0x43, 0x58, 0xcf, 0x57, 0x05, 0x05, 0x1c,
        0xc2, 0xf2, 0x87, 0xb1, 0x9b, 0xd6, 0x73, 0x35,
        0xce, 0x4c, 0x7f, 0x30, 0x57, 0xa1, 0xc8, 0x7f,
        0x9a, 0xf3, 0x11, 0x3e, 0xc5, 0x2b, 0x6c, 0xf3,
        0x1c, 0x69, 0x3b, 0xd9, 0xb2, 0x52, 0x8b, 0x45,
        0x41, 0xe0, 0xcb, 0xd3, 0xde, 0x14, 0xc1, 0xb0,
        0x49, 0xe8, 0xa1, 0x92, 0x52, 0xcb, 0x5c, 0x4e,
        0x05, 0xb2, 0x47, 0x74, 0x23, 0x3d, 0x20, 0x23,
        0xc8, 0x93, 0x0a, 0x9b, 0xdd, 0x2d, 0x99, 0xd8,
        0xd5
    };
    const byte* pwd  = (const byte*)"password";
    const byte* salt = (const byte*)"somesalt";
    byte out[97];
    byte shortOut[WC_ARGON2_MIN_OUTLEN];

    /* T=64: the largest tag that is still a single digest. */
    XMEMSET(out, 0, sizeof(out));
    ExpectIntEQ(wc_Argon2(WC_ARGON2_D, out, (word32)sizeof(exp64), pwd, 8,
        salt, 8, 4, 32, 1), 0);
    ExpectIntEQ(XMEMCMP(out, exp64, sizeof(exp64)), 0);

    /* T=65: the smallest tag that takes the chain. */
    XMEMSET(out, 0, sizeof(out));
    ExpectIntEQ(wc_Argon2(WC_ARGON2_ID, out, (word32)sizeof(exp65), pwd, 8,
        salt, 8, 1, 32, 2), 0);
    ExpectIntEQ(XMEMCMP(out, exp65, sizeof(exp65)), 0);

    /* T=96: tail digest is exactly 64 bytes, so the loop never runs. */
    XMEMSET(out, 0, sizeof(out));
    ExpectIntEQ(wc_Argon2(WC_ARGON2_ID, out, (word32)sizeof(exp96), pwd, 8,
        salt, 8, 1, 32, 2), 0);
    ExpectIntEQ(XMEMCMP(out, exp96, sizeof(exp96)), 0);

    /* T=97: one pass through the loop body, then a 33-byte tail. */
    XMEMSET(out, 0, sizeof(out));
    ExpectIntEQ(wc_Argon2(WC_ARGON2_ID, out, (word32)sizeof(exp97), pwd, 8,
        salt, 8, 1, 32, 2), 0);
    ExpectIntEQ(XMEMCMP(out, exp97, sizeof(exp97)), 0);

    /* The shortest permitted tag is still well defined. */
    ExpectIntEQ(wc_Argon2(WC_ARGON2_ID, shortOut, sizeof(shortOut),
        pwd, 8, salt, 8, 1, 8, 1), 0);
#endif
    return EXPECT_RESULT();
}

/*
 * Parameter combinations away from the RFC vectors: more than one lane, and
 * a segment long enough (m/(4p) > 128) that Argon2i has to generate more
 * than one block of addresses per segment.
 */
int test_wc_Argon2_params(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ARGON2
    /* Argon2id, p=2, m=64, t=2 */
    WOLFSSL_SMALL_STACK_STATIC const byte expMultiLane[] = {
        0x94, 0x38, 0x74, 0x15, 0xdf, 0xb8, 0x4e, 0xd1,
        0x97, 0x74, 0x65, 0xa1, 0xe8, 0x62, 0x60, 0x73,
        0xad, 0xf4, 0x2b, 0xd4, 0xee, 0xae, 0x1f, 0xaa,
        0x1d, 0xd4, 0xe2, 0x3a, 0x1f, 0xf6, 0x85, 0x9f
    };
    /* Argon2i, p=1, m=1024, t=1: segment length 256 > 128 addresses. */
    WOLFSSL_SMALL_STACK_STATIC const byte expLongSeg[] = {
        0x95, 0x46, 0x6c, 0xc4, 0xf9, 0x2f, 0x87, 0x49,
        0x54, 0x61, 0x7e, 0xec, 0x0a, 0xa1, 0x19, 0x5d,
        0x22, 0x98, 0x0a, 0xbd, 0x62, 0x5e, 0x5c, 0xac,
        0x44, 0x76, 0x3a, 0xe3, 0xa9, 0xcb, 0x6a, 0xb7
    };
    const byte* pwd  = (const byte*)"password";
    const byte* salt = (const byte*)"somesalt";
    byte out[32];
    byte again[32];

    XMEMSET(out, 0, sizeof(out));
    ExpectIntEQ(wc_Argon2(WC_ARGON2_ID, out, sizeof(out), pwd, 8, salt, 8,
        2, 64, 2), 0);
    ExpectIntEQ(XMEMCMP(out, expMultiLane, sizeof(expMultiLane)), 0);

    /* Same inputs must give the same tag. */
    XMEMSET(again, 0, sizeof(again));
    ExpectIntEQ(wc_Argon2(WC_ARGON2_ID, again, sizeof(again), pwd, 8, salt, 8,
        2, 64, 2), 0);
    ExpectIntEQ(XMEMCMP(out, again, sizeof(out)), 0);

    XMEMSET(out, 0, sizeof(out));
    ExpectIntEQ(wc_Argon2(WC_ARGON2_I, out, sizeof(out), pwd, 8, salt, 8,
        1, 1024, 1), 0);
    ExpectIntEQ(XMEMCMP(out, expLongSeg, sizeof(expLongSeg)), 0);

    /* A different salt must give a different tag. */
    XMEMSET(again, 0, sizeof(again));
    ExpectIntEQ(wc_Argon2(WC_ARGON2_I, again, sizeof(again), pwd, 8,
        (const byte*)"othersal", 8, 1, 1024, 1), 0);
    ExpectIntNE(XMEMCMP(out, again, sizeof(out)), 0);

    /* An empty password is permitted when the length says so. */
    ExpectIntEQ(wc_Argon2(WC_ARGON2_ID, out, sizeof(out), NULL, 0, salt, 8,
        1, 8, 1), 0);
#endif
    return EXPECT_RESULT();
}

/*
 * The three variants must not agree with each other on identical input.
 */
int test_wc_Argon2_variants_differ(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ARGON2
    const byte* pwd  = (const byte*)"password";
    const byte* salt = (const byte*)"somesalt";
    byte d[32], i[32], id[32];

    XMEMSET(d,  0, sizeof(d));
    XMEMSET(i,  0, sizeof(i));
    XMEMSET(id, 0, sizeof(id));

    ExpectIntEQ(wc_Argon2(WC_ARGON2_D,  d,  sizeof(d),  pwd, 8, salt, 8,
        2, 32, 2), 0);
    ExpectIntEQ(wc_Argon2(WC_ARGON2_I,  i,  sizeof(i),  pwd, 8, salt, 8,
        2, 32, 2), 0);
    ExpectIntEQ(wc_Argon2(WC_ARGON2_ID, id, sizeof(id), pwd, 8, salt, 8,
        2, 32, 2), 0);

    ExpectIntNE(XMEMCMP(d, i,  sizeof(d)), 0);
    ExpectIntNE(XMEMCMP(d, id, sizeof(d)), 0);
    ExpectIntNE(XMEMCMP(i, id, sizeof(i)), 0);
#endif
    return EXPECT_RESULT();
}

/*
 * Out-of-range and malformed parameters.
 */
int test_wc_Argon2_badargs(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ARGON2
    const byte* pwd  = (const byte*)"password";
    const byte* salt = (const byte*)"somesalt";
    byte out[32];

    /* NULL output and NULL salt. */
    ExpectIntEQ(wc_Argon2(WC_ARGON2_ID, NULL, sizeof(out), pwd, 8, salt, 8,
        1, 8, 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Argon2(WC_ARGON2_ID, out, sizeof(out), pwd, 8, NULL, 8,
        1, 8, 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* NULL password with a non-zero length. */
    ExpectIntEQ(wc_Argon2(WC_ARGON2_ID, out, sizeof(out), NULL, 8, salt, 8,
        1, 8, 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* NULL secret / associated data with a non-zero length. */
    ExpectIntEQ(wc_Argon2_ex(WC_ARGON2_ID, out, sizeof(out), pwd, 8, salt, 8,
        NULL, 8, NULL, 0, 1, 8, 1, HEAP_HINT), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Argon2_ex(WC_ARGON2_ID, out, sizeof(out), pwd, 8, salt, 8,
        NULL, 0, NULL, 8, 1, 8, 1, HEAP_HINT), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Unknown variant. */
    ExpectIntEQ(wc_Argon2(-1, out, sizeof(out), pwd, 8, salt, 8, 1, 8, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Argon2(3, out, sizeof(out), pwd, 8, salt, 8, 1, 8, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Tag below WC_ARGON2_MIN_OUTLEN and salt below WC_ARGON2_MIN_SALT_LEN. */
    ExpectIntEQ(wc_Argon2(WC_ARGON2_ID, out, 3, pwd, 8, salt, 8, 1, 8, 1),
        WC_NO_ERR_TRACE(BAD_LENGTH_E));
    ExpectIntEQ(wc_Argon2(WC_ARGON2_ID, out, sizeof(out), pwd, 8, salt, 7,
        1, 8, 1), WC_NO_ERR_TRACE(BAD_LENGTH_E));

    /* Zero passes and zero lanes. */
    ExpectIntEQ(wc_Argon2(WC_ARGON2_ID, out, sizeof(out), pwd, 8, salt, 8,
        1, 8, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Argon2(WC_ARGON2_ID, out, sizeof(out), pwd, 8, salt, 8,
        0, 8, 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Memory below the 8p floor, and below the absolute floor. */
    ExpectIntEQ(wc_Argon2(WC_ARGON2_ID, out, sizeof(out), pwd, 8, salt, 8,
        4, 31, 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Argon2(WC_ARGON2_ID, out, sizeof(out), pwd, 8, salt, 8,
        1, 7, 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Lanes beyond WC_ARGON2_MAX_LANES. */
    ExpectIntEQ(wc_Argon2(WC_ARGON2_ID, out, sizeof(out), pwd, 8, salt, 8,
        WC_ARGON2_MAX_LANES + 1, 8, 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* The minimum accepted parameter set must still succeed. */
    ExpectIntEQ(wc_Argon2(WC_ARGON2_ID, out, WC_ARGON2_MIN_OUTLEN, pwd, 8,
        salt, WC_ARGON2_MIN_SALT_LEN, 1, WC_ARGON2_MIN_MEMORY, 1), 0);
#endif
    return EXPECT_RESULT();
}

/*
 * Testing wc_Argon2Init() and wc_Argon2Free().
 */
int test_wc_Argon2Init(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ARGON2
    Argon2Ctx a;

    XMEMSET(&a, 0, sizeof(a));

    ExpectIntEQ(wc_Argon2Init(NULL, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_Argon2Init(&a, HEAP_HINT, INVALID_DEVID), 0);
    /* No parameters set yet, so no block array has been allocated. */
    ExpectNull(a.memory);

    /* Freeing without parameters ever being set is allowed, as is freeing
     * twice and freeing NULL. */
    wc_Argon2Free(&a);
    wc_Argon2Free(&a);
    wc_Argon2Free(NULL);
#endif
    return EXPECT_RESULT();
}

/*
 * Testing wc_Argon2New() and wc_Argon2Delete().
 */
int test_wc_Argon2New(void)
{
#if defined(HAVE_ARGON2) && !defined(WC_NO_CONSTRUCTORS)
    EXPECT_DECLS;
    Argon2Ctx* a = NULL;
    int result = -1;
    int delRet;
    const byte* pwd  = (const byte*)"password";
    const byte* salt = (const byte*)"somesalt";
    byte out[32];
    byte oneShot[32];

    a = wc_Argon2New(HEAP_HINT, INVALID_DEVID, &result);
    ExpectNotNull(a);
    ExpectIntEQ(result, 0);

    /* A new context is usable once parameters are set. */
    ExpectIntEQ(wc_Argon2SetParams(a, WC_ARGON2_ID, 2, 64, 2), 0);
    ExpectIntEQ(wc_Argon2DeriveTag(a, out, sizeof(out), pwd, 8, salt, 8,
        NULL, 0, NULL, 0), 0);

    /* It must agree with the one-shot API. */
    ExpectIntEQ(wc_Argon2(WC_ARGON2_ID, oneShot, sizeof(oneShot), pwd, 8,
        salt, 8, 2, 64, 2), 0);
    ExpectIntEQ(XMEMCMP(out, oneShot, sizeof(out)), 0);

    /* Delete clears the caller's pointer. The call is made outside the check
     * so that a failure above cannot skip it and leak the context - the
     * Expect macros stop evaluating once one of them has failed. */
    if (a != NULL) {
        delRet = wc_Argon2Delete(a, &a);
        ExpectIntEQ(delRet, 0);
    }
    ExpectNull(a);

    ExpectIntEQ(wc_Argon2Delete(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* The result code pointer is optional. */
    a = wc_Argon2New(HEAP_HINT, INVALID_DEVID, NULL);
    ExpectNotNull(a);
    if (a != NULL) {
        /* The pointer-to-pointer is optional too; clear the local instead. */
        delRet = wc_Argon2Delete(a, NULL);
        ExpectIntEQ(delRet, 0);
        /* Delete cannot clear the caller's pointer when handed NULL for it,
         * so clear it here - leaving it dangling would turn any later
         * cleanup into a double free. */
        a = NULL;
    }

    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

/*
 * Testing wc_Argon2SetParams().
 */
int test_wc_Argon2SetParams(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ARGON2
    Argon2Ctx a;

    XMEMSET(&a, 0, sizeof(a));
    ExpectIntEQ(wc_Argon2Init(&a, HEAP_HINT, INVALID_DEVID), 0);

    ExpectIntEQ(wc_Argon2SetParams(NULL, WC_ARGON2_ID, 1, 8, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Unknown variant. */
    ExpectIntEQ(wc_Argon2SetParams(&a, 3, 1, 8, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Argon2SetParams(&a, -1, 1, 8, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Zero lanes and lanes beyond the maximum. */
    ExpectIntEQ(wc_Argon2SetParams(&a, WC_ARGON2_ID, 0, 8, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Argon2SetParams(&a, WC_ARGON2_ID,
        WC_ARGON2_MAX_LANES + 1, 8, 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Zero passes. */
    ExpectIntEQ(wc_Argon2SetParams(&a, WC_ARGON2_ID, 1, 8, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Memory below the 8p floor and below the absolute floor. */
    ExpectIntEQ(wc_Argon2SetParams(&a, WC_ARGON2_ID, 4, 31, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Argon2SetParams(&a, WC_ARGON2_ID, 1, 7, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Valid parameters allocate the block array. */
    ExpectIntEQ(wc_Argon2SetParams(&a, WC_ARGON2_ID, 1, 8, 1), 0);
    ExpectNotNull(a.memory);
    ExpectIntEQ(a.memoryBlocks, 8);
    ExpectIntEQ(a.laneLength, 8);
    ExpectIntEQ(a.segmentLength, 2);

    /* Setting the same parameters again keeps the allocation. */
    ExpectIntEQ(wc_Argon2SetParams(&a, WC_ARGON2_ID, 1, 8, 1), 0);
    ExpectNotNull(a.memory);

    /* Changing to larger parameters reallocates. */
    ExpectIntEQ(wc_Argon2SetParams(&a, WC_ARGON2_I, 2, 64, 3), 0);
    ExpectNotNull(a.memory);
    ExpectIntEQ(a.memoryBlocks, 64);
    ExpectIntEQ(a.lanes, 2);
    ExpectIntEQ(a.passes, 3);
    ExpectIntEQ(a.type, WC_ARGON2_I);

    /* m is rounded down to a multiple of 4p, but the requested value is
     * kept because H0 commits to it. */
    ExpectIntEQ(wc_Argon2SetParams(&a, WC_ARGON2_ID, 5, 41, 1), 0);
    ExpectIntEQ(a.memCost, 41);
    ExpectIntEQ(a.memoryBlocks, 40);

    wc_Argon2Free(&a);
#endif
    return EXPECT_RESULT();
}

/*
 * Testing wc_Argon2DeriveTag(), including reuse of one context for several
 * derivations.
 */
int test_wc_Argon2DeriveTag(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ARGON2
    Argon2Ctx a;
    const byte* pwd  = (const byte*)"password";
    const byte* salt = (const byte*)"somesalt";
    byte out[32];
    byte again[32];
    byte oneShot[32];

    XMEMSET(&a, 0, sizeof(a));
    ExpectIntEQ(wc_Argon2Init(&a, HEAP_HINT, INVALID_DEVID), 0);

    /* Deriving before parameters are set is a state error. */
    ExpectIntEQ(wc_Argon2DeriveTag(&a, out, sizeof(out), pwd, 8, salt, 8,
        NULL, 0, NULL, 0), WC_NO_ERR_TRACE(BAD_STATE_E));

    ExpectIntEQ(wc_Argon2SetParams(&a, WC_ARGON2_ID, 2, 64, 2), 0);

    /* Bad arguments. */
    ExpectIntEQ(wc_Argon2DeriveTag(NULL, out, sizeof(out), pwd, 8, salt, 8,
        NULL, 0, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Argon2DeriveTag(&a, NULL, sizeof(out), pwd, 8, salt, 8,
        NULL, 0, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Argon2DeriveTag(&a, out, sizeof(out), pwd, 8, NULL, 8,
        NULL, 0, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Argon2DeriveTag(&a, out, sizeof(out), NULL, 8, salt, 8,
        NULL, 0, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Argon2DeriveTag(&a, out, 3, pwd, 8, salt, 8,
        NULL, 0, NULL, 0), WC_NO_ERR_TRACE(BAD_LENGTH_E));
    ExpectIntEQ(wc_Argon2DeriveTag(&a, out, sizeof(out), pwd, 8, salt, 7,
        NULL, 0, NULL, 0), WC_NO_ERR_TRACE(BAD_LENGTH_E));

    /* The tag must match the one-shot API for the same parameters. */
    ExpectIntEQ(wc_Argon2DeriveTag(&a, out, sizeof(out), pwd, 8, salt, 8,
        NULL, 0, NULL, 0), 0);
    ExpectIntEQ(wc_Argon2(WC_ARGON2_ID, oneShot, sizeof(oneShot), pwd, 8,
        salt, 8, 2, 64, 2), 0);
    ExpectIntEQ(XMEMCMP(out, oneShot, sizeof(out)), 0);

    /* Reusing the context must give the same answer: the block array is
     * left over from the previous derivation and must not affect it. */
    ExpectIntEQ(wc_Argon2DeriveTag(&a, again, sizeof(again), pwd, 8, salt, 8,
        NULL, 0, NULL, 0), 0);
    ExpectIntEQ(XMEMCMP(out, again, sizeof(out)), 0);

    /* A different password on the same context gives a different tag. */
    ExpectIntEQ(wc_Argon2DeriveTag(&a, again, sizeof(again),
        (const byte*)"passworE", 8, salt, 8, NULL, 0, NULL, 0), 0);
    ExpectIntNE(XMEMCMP(out, again, sizeof(out)), 0);

    /* Secret and associated data are honoured through the context, and
     * agree with the one-shot extended API. */
    ExpectIntEQ(wc_Argon2DeriveTag(&a, out, sizeof(out), pwd, 8, salt, 8,
        (const byte*)"pepper", 6, (const byte*)"alice", 5), 0);
    ExpectIntEQ(wc_Argon2_ex(WC_ARGON2_ID, oneShot, sizeof(oneShot), pwd, 8,
        salt, 8, (const byte*)"pepper", 6, (const byte*)"alice", 5,
        2, 64, 2, HEAP_HINT), 0);
    ExpectIntEQ(XMEMCMP(out, oneShot, sizeof(out)), 0);

    /* Changing parameters on a used context works, and again agrees with
     * the one-shot API. */
    ExpectIntEQ(wc_Argon2SetParams(&a, WC_ARGON2_D, 1, 32, 1), 0);
    ExpectIntEQ(wc_Argon2DeriveTag(&a, out, sizeof(out), pwd, 8, salt, 8,
        NULL, 0, NULL, 0), 0);
    ExpectIntEQ(wc_Argon2(WC_ARGON2_D, oneShot, sizeof(oneShot), pwd, 8,
        salt, 8, 1, 32, 1), 0);
    ExpectIntEQ(XMEMCMP(out, oneShot, sizeof(out)), 0);

    wc_Argon2Free(&a);
#endif
    return EXPECT_RESULT();
}

/*
 * Testing wc_Argon2SetThreads(). The thread count must not change the tag:
 * the synchronization point at the end of every slice makes the result the
 * same however many threads fill it.
 */
int test_wc_Argon2SetThreads(void)
{
#if defined(HAVE_ARGON2) && defined(WOLFSSL_ARGON2_THREADS)
    EXPECT_DECLS;
    Argon2Ctx a;
    const byte* pwd  = (const byte*)"password";
    const byte* salt = (const byte*)"somesalt";
    byte seq[32];
    byte seq2[32];
    byte out[32];
    word32 threads;

    /* Sequential references from the one-shot API, for each lane count the
     * test goes on to use. */
    ExpectIntEQ(wc_Argon2(WC_ARGON2_ID, seq, sizeof(seq), pwd, 8, salt, 8,
        4, 256, 2), 0);
    ExpectIntEQ(wc_Argon2(WC_ARGON2_ID, seq2, sizeof(seq2), pwd, 8, salt, 8,
        2, 256, 2), 0);

    XMEMSET(&a, 0, sizeof(a));
    ExpectIntEQ(wc_Argon2Init(&a, HEAP_HINT, INVALID_DEVID), 0);

    /* A fresh context is sequential. */
    ExpectIntEQ(a.threads, 1);

    ExpectIntEQ(wc_Argon2SetThreads(NULL, 2),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Argon2SetThreads(&a, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Argon2SetThreads(&a, WC_ARGON2_MAX_THREADS + 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Set before the parameters: the allocation waits until the lane count
     * is known. */
    ExpectIntEQ(wc_Argon2SetThreads(&a, 4), 0);
    ExpectIntEQ(a.threads, 4);
    ExpectIntEQ(wc_Argon2SetParams(&a, WC_ARGON2_ID, 4, 256, 2), 0);
    ExpectIntEQ(a.workerCnt, 4);

    /* Every thread count must reproduce the sequential tag. */
    for (threads = 1; threads <= 8; threads++) {
        ExpectIntEQ(wc_Argon2SetThreads(&a, threads), 0);
        XMEMSET(out, 0, sizeof(out));
        ExpectIntEQ(wc_Argon2DeriveTag(&a, out, sizeof(out), pwd, 8, salt, 8,
            NULL, 0, NULL, 0), 0);
        ExpectIntEQ(XMEMCMP(out, seq, sizeof(seq)), 0);
    }

    /* More threads than lanes is allowed but allocates no more workers than
     * there are lanes, since a slice has only that many segments. */
    ExpectIntEQ(wc_Argon2SetThreads(&a, 64), 0);
    ExpectIntEQ(a.threads, 64);
    ExpectIntEQ(a.workerCnt, 4);
    XMEMSET(out, 0, sizeof(out));
    ExpectIntEQ(wc_Argon2DeriveTag(&a, out, sizeof(out), pwd, 8, salt, 8,
        NULL, 0, NULL, 0), 0);
    ExpectIntEQ(XMEMCMP(out, seq, sizeof(seq)), 0);

    /* Lowering the lane count lowers the worker count with it. */
    ExpectIntEQ(wc_Argon2SetParams(&a, WC_ARGON2_ID, 2, 256, 2), 0);
    ExpectIntEQ(a.workerCnt, 2);

    /* Setting the same count again takes the no-op path. The tag is checked
     * against the sequential two-lane answer, not just the return code: a
     * wrong worker/scratch split under this configuration would still
     * return 0. */
    ExpectIntEQ(wc_Argon2SetThreads(&a, 64), 0);
    XMEMSET(out, 0, sizeof(out));
    ExpectIntEQ(wc_Argon2DeriveTag(&a, out, sizeof(out), pwd, 8, salt, 8,
        NULL, 0, NULL, 0), 0);
    ExpectIntEQ(XMEMCMP(out, seq2, sizeof(seq2)), 0);

    wc_Argon2Free(&a);

    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}
