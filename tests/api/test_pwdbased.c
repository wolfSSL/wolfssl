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
