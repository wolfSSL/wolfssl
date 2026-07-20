/* test_pwdbased.c
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
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <tests/api/api.h>
#include <tests/api/test_pwdbased.h>

/* test that wc_PBKDF1_ex rejects iterations <= 0 */
int test_wc_PBKDF1_ex_iterations(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PBKDF1) && !defined(NO_PWDBASED) && !defined(NO_SHA) && \
    !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0))

    static const byte passwd[] = { 'p', 'a', 's', 's' };
    static const byte salt[]   = { 0x78, 0x57, 0x8E, 0x5a,
                                   0x5d, 0x63, 0xcb, 0x06 };
    byte derived[16];

    ExpectIntEQ(wc_PBKDF1_ex(derived, (int)sizeof(derived), NULL, 0,
                    passwd, (int)sizeof(passwd),
                    salt, (int)sizeof(salt), 0, WC_SHA, HEAP_HINT),
                BAD_FUNC_ARG);
    ExpectIntEQ(wc_PBKDF1_ex(derived, (int)sizeof(derived), NULL, 0,
                    passwd, (int)sizeof(passwd),
                    salt, (int)sizeof(salt), -1, WC_SHA, HEAP_HINT),
                BAD_FUNC_ARG);
#endif
    return EXPECT_RESULT();
}

/* test that wc_PBKDF2_ex rejects iterations <= 0 */
int test_wc_PBKDF2_ex_iterations(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PBKDF2) && !defined(NO_PWDBASED) && !defined(NO_HMAC) && \
    !defined(NO_SHA256) && !defined(HAVE_SELFTEST) && \
    (!defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0))
    static const byte passwd[] = { 'p', 'a', 's', 's' };
    static const byte salt[]   = { 0x78, 0x57, 0x8E, 0x5a,
                                   0x5d, 0x63, 0xcb, 0x06 };
    byte derived[24];

    ExpectIntEQ(wc_PBKDF2_ex(derived, passwd, (int)sizeof(passwd),
                    salt, (int)sizeof(salt), 0,
                    (int)sizeof(derived), WC_SHA256, HEAP_HINT, INVALID_DEVID),
                BAD_FUNC_ARG);
    ExpectIntEQ(wc_PBKDF2_ex(derived, passwd, (int)sizeof(passwd),
                    salt, (int)sizeof(salt), -1,
                    (int)sizeof(derived), WC_SHA256, HEAP_HINT, INVALID_DEVID),
                BAD_FUNC_ARG);
#endif
    return EXPECT_RESULT();
}

/* MC/DC decision coverage of wc_PBKDF1_ex: independence pair for each operand
 * of the argument-check OR, the iteration ceiling, the invalid-hash path, and
 * one valid derivation. */
int test_wc_PBKDF1DecisionCoverage(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PBKDF1) && !defined(NO_PWDBASED) && !defined(NO_SHA) && \
    !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0))
    static const byte passwd[] = { 'p', 'a', 's', 's' };
    static const byte salt[]   = { 0x78, 0x57, 0x8E, 0x5a,
                                   0x5d, 0x63, 0xcb, 0x06 };
    byte derived[16] = {0};
    int  prevMax;

    /* argument-check OR: key==NULL || keyLen<0 || passwdLen<0 || saltLen<0 ||
     * ivLen<0 -- vary each operand alone (others valid). */
    ExpectIntEQ(wc_PBKDF1_ex(NULL, (int)sizeof(derived), NULL, 0,
                    passwd, (int)sizeof(passwd), salt, (int)sizeof(salt),
                    2, WC_SHA, HEAP_HINT), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PBKDF1_ex(derived, -1, NULL, 0,
                    passwd, (int)sizeof(passwd), salt, (int)sizeof(salt),
                    2, WC_SHA, HEAP_HINT), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PBKDF1_ex(derived, (int)sizeof(derived), NULL, 0,
                    passwd, -1, salt, (int)sizeof(salt),
                    2, WC_SHA, HEAP_HINT), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PBKDF1_ex(derived, (int)sizeof(derived), NULL, 0,
                    passwd, (int)sizeof(passwd), salt, -1,
                    2, WC_SHA, HEAP_HINT), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PBKDF1_ex(derived, (int)sizeof(derived), NULL, -1,
                    passwd, (int)sizeof(passwd), salt, (int)sizeof(salt),
                    2, WC_SHA, HEAP_HINT), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* iterations <= 0 */
    ExpectIntEQ(wc_PBKDF1_ex(derived, (int)sizeof(derived), NULL, 0,
                    passwd, (int)sizeof(passwd), salt, (int)sizeof(salt),
                    0, WC_SHA, HEAP_HINT), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* iterations > current max */
    prevMax = wc_PBKDF_max_iterations_get();
    ExpectIntGT(wc_PBKDF_max_iterations_set(2), 0);
    ExpectIntEQ(wc_PBKDF1_ex(derived, (int)sizeof(derived), NULL, 0,
                    passwd, (int)sizeof(passwd), salt, (int)sizeof(salt),
                    3, WC_SHA, HEAP_HINT), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntGT(wc_PBKDF_max_iterations_set(prevMax), 0);

    /* invalid hash type -> error out of wc_HashGetDigestSize (not 0) */
    ExpectIntNE(wc_PBKDF1_ex(derived, (int)sizeof(derived), NULL, 0,
                    passwd, (int)sizeof(passwd), salt, (int)sizeof(salt),
                    2, WC_HASH_TYPE_NONE, HEAP_HINT), 0);

    /* valid derivation (keyLen spanning >1 digest block) */
    ExpectIntEQ(wc_PBKDF1_ex(derived, (int)sizeof(derived), NULL, 0,
                    passwd, (int)sizeof(passwd), salt, (int)sizeof(salt),
                    2, WC_SHA, HEAP_HINT), 0);

    /* `if (ivLeft && digestLeft)` independence pairs. keyLen == digestLen
     * (20 for SHA-1) with ivLen > 0: the first D-iteration exactly
     * exhausts the digest into the key (digestLeft becomes 0), so
     * ivLeft(true) && digestLeft(false) -> false; the following
     * iteration resets digestLeft and drains the iv, so
     * ivLeft(true) && digestLeft(true) -> true. Paired with the
     * ivLen == 0 calls above (ivLeft always false) for the ivLeft
     * operand's independence pair. */
    {
        byte key20[20] = {0};
        byte iv8[8] = {0};

        ExpectIntEQ(wc_PBKDF1_ex(key20, (int)sizeof(key20), iv8,
                        (int)sizeof(iv8), passwd, (int)sizeof(passwd),
                        salt, (int)sizeof(salt), 2, WC_SHA, HEAP_HINT), 0);
    }
#endif
    return EXPECT_RESULT();
}

/* MC/DC decision coverage of wc_PBKDF2_ex argument checks + edges. */
int test_wc_PBKDF2DecisionCoverage(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PBKDF2) && !defined(NO_PWDBASED) && !defined(NO_HMAC) && \
    !defined(NO_SHA256) && !defined(HAVE_SELFTEST) && \
    (!defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0))
    static const byte passwd[] = { 'p', 'a', 's', 's' };
    static const byte salt[]   = { 0x78, 0x57, 0x8E, 0x5a,
                                   0x5d, 0x63, 0xcb, 0x06 };
    byte derived[24] = {0};
    int  prevMax;

    /* output==NULL || pLen<0 || sLen<0 || kLen<0 -- vary each operand alone. */
    ExpectIntEQ(wc_PBKDF2_ex(NULL, passwd, (int)sizeof(passwd),
                    salt, (int)sizeof(salt), 2, (int)sizeof(derived),
                    WC_SHA256, HEAP_HINT, INVALID_DEVID),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PBKDF2_ex(derived, passwd, -1,
                    salt, (int)sizeof(salt), 2, (int)sizeof(derived),
                    WC_SHA256, HEAP_HINT, INVALID_DEVID),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PBKDF2_ex(derived, passwd, (int)sizeof(passwd),
                    salt, -1, 2, (int)sizeof(derived),
                    WC_SHA256, HEAP_HINT, INVALID_DEVID),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PBKDF2_ex(derived, passwd, (int)sizeof(passwd),
                    salt, (int)sizeof(salt), 2, -1,
                    WC_SHA256, HEAP_HINT, INVALID_DEVID),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* iterations <= 0 */
    ExpectIntEQ(wc_PBKDF2_ex(derived, passwd, (int)sizeof(passwd),
                    salt, (int)sizeof(salt), 0, (int)sizeof(derived),
                    WC_SHA256, HEAP_HINT, INVALID_DEVID),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* iterations > current max */
    prevMax = wc_PBKDF_max_iterations_get();
    ExpectIntGT(wc_PBKDF_max_iterations_set(2), 0);
    ExpectIntEQ(wc_PBKDF2_ex(derived, passwd, (int)sizeof(passwd),
                    salt, (int)sizeof(salt), 3, (int)sizeof(derived),
                    WC_SHA256, HEAP_HINT, INVALID_DEVID),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntGT(wc_PBKDF_max_iterations_set(prevMax), 0);

    /* invalid hash type -> hLen<0 -> BAD_FUNC_ARG */
    ExpectIntEQ(wc_PBKDF2_ex(derived, passwd, (int)sizeof(passwd),
                    salt, (int)sizeof(salt), 2, (int)sizeof(derived),
                    WC_HASH_TYPE_NONE, HEAP_HINT, INVALID_DEVID),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* valid derivation */
    ExpectIntEQ(wc_PBKDF2_ex(derived, passwd, (int)sizeof(passwd),
                    salt, (int)sizeof(salt), 2, (int)sizeof(derived),
                    WC_SHA256, HEAP_HINT, INVALID_DEVID), 0);
#endif
    return EXPECT_RESULT();
}

/* MC/DC decision coverage of wc_PKCS12_PBKDF argument checks + edges. */
int test_wc_PKCS12_PBKDFDecisionCoverage(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS12) && !defined(NO_PWDBASED) && !defined(NO_SHA256) && \
    !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0))
    static const byte passwd[] = { 'p', 'a', 's', 's' };
    static const byte salt[]   = { 0x78, 0x57, 0x8E, 0x5a,
                                   0x5d, 0x63, 0xcb, 0x06 };
    byte derived[24] = {0};
    int  prevMax;
    const int id = 1; /* key material id (RFC 7292) */

    /* output==NULL || passLen<=0 || saltLen<=0 || kLen<0 -- vary each. */
    ExpectIntEQ(wc_PKCS12_PBKDF(NULL, passwd, (int)sizeof(passwd),
                    salt, (int)sizeof(salt), 2, (int)sizeof(derived),
                    WC_SHA256, id), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PKCS12_PBKDF(derived, passwd, 0,
                    salt, (int)sizeof(salt), 2, (int)sizeof(derived),
                    WC_SHA256, id), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PKCS12_PBKDF(derived, passwd, (int)sizeof(passwd),
                    salt, 0, 2, (int)sizeof(derived),
                    WC_SHA256, id), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PKCS12_PBKDF(derived, passwd, (int)sizeof(passwd),
                    salt, (int)sizeof(salt), 2, -1,
                    WC_SHA256, id), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* iterations <= 0 */
    ExpectIntEQ(wc_PKCS12_PBKDF(derived, passwd, (int)sizeof(passwd),
                    salt, (int)sizeof(salt), 0, (int)sizeof(derived),
                    WC_SHA256, id), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* iterations > current max */
    prevMax = wc_PBKDF_max_iterations_get();
    ExpectIntGT(wc_PBKDF_max_iterations_set(2), 0);
    ExpectIntEQ(wc_PKCS12_PBKDF(derived, passwd, (int)sizeof(passwd),
                    salt, (int)sizeof(salt), 3, (int)sizeof(derived),
                    WC_SHA256, id), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntGT(wc_PBKDF_max_iterations_set(prevMax), 0);

    /* invalid hash type -> error out of wc_HashGetDigestSize (not 0) */
    ExpectIntNE(wc_PKCS12_PBKDF(derived, passwd, (int)sizeof(passwd),
                    salt, (int)sizeof(salt), 2, (int)sizeof(derived),
                    WC_HASH_TYPE_NONE, id), 0);

    /* valid derivation */
    ExpectIntEQ(wc_PKCS12_PBKDF(derived, passwd, (int)sizeof(passwd),
                    salt, (int)sizeof(salt), 2, (int)sizeof(derived),
                    WC_SHA256, id), 0);

    /* inner `while ((ret == 0) && (kLen > 0))` independence pair for the
     * kLen operand: kLen == 0 is a valid request (not caught by the
     * kLen < 0 arg-check) so the loop body never executes and
     * kLen > 0 evaluates false with ret == 0 held true, paired with the
     * "valid derivation" call above where kLen > 0 evaluates true. */
    ExpectIntEQ(wc_PKCS12_PBKDF(derived, passwd, (int)sizeof(passwd),
                    salt, (int)sizeof(salt), 2, 0,
                    WC_SHA256, id), 0);
#endif
    return EXPECT_RESULT();
}
