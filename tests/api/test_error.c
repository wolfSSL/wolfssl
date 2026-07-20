/* test_error.c
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
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <tests/api/api.h>
#include <tests/api/test_error.h>

/*
 * MC/DC / decision coverage for wolfcrypt/src/error.c (wc_GetErrorString /
 * wc_ErrorString). error.c is a single large switch mapping every
 * wolfCrypt_ErrorCodes value to its string; decision coverage means taking
 * each case arm plus the default (unknown) arm. We sweep the whole error-code
 * numeric span (span 1: -97..-299, span 2: -1000..-1019) so every case is
 * taken, and also feed values outside every span so the default arm is taken.
 *
 * When NO_ERROR_STRINGS is defined the two symbols collapse to macros that
 * return / copy a fixed "no support" string; the same calls still compile and
 * return non-NULL, so this test is valid in both configurations (that is the
 * NO_ERROR_STRINGS compiled-out path the coding-standard asks us to exercise).
 */
int test_wc_GetErrorStringDecisionCoverage(void)
{
    EXPECT_DECLS;
    int e;

    /* Sweep span 1 and the gap below it down through span 2, taking every
     * defined case arm and, on the undefined values in between, the default
     * arm. Every arm returns a non-NULL string. */
    for (e = -1; e >= -1030; e--) {
        ExpectNotNull(wc_GetErrorString(e));
    }

    /* Values well outside every span exercise the default arm explicitly. */
    ExpectNotNull(wc_GetErrorString(0));
    ExpectNotNull(wc_GetErrorString(1));
    ExpectNotNull(wc_GetErrorString(-123456));
    ExpectNotNull(wc_GetErrorString(-2000));

#ifndef NO_ERROR_STRINGS
    /* An unknown code returns the sentinel string from the default arm. */
    ExpectNotNull(wc_GetErrorString(-123456));
    ExpectIntEQ(XSTRNCMP(wc_GetErrorString(-123456), "unknown error number",
                         20), 0);
    /* A known code returns something other than the unknown sentinel. */
    ExpectIntNE(XSTRNCMP(wc_GetErrorString(WC_NO_ERR_TRACE(BUFFER_E)),
                         "unknown error number", 20), 0);
#endif
    return EXPECT_RESULT();
}

/* wc_ErrorString() copies the (truncated) string into the caller buffer. */
int test_wc_ErrorStringDecisionCoverage(void)
{
    EXPECT_DECLS;
    char buffer[WOLFSSL_MAX_ERROR_SZ];

    XMEMSET(buffer, 0, sizeof(buffer));
    wc_ErrorString(WC_NO_ERR_TRACE(BUFFER_E), buffer);
    ExpectIntGT((int)XSTRLEN(buffer), 0);

    XMEMSET(buffer, 0, sizeof(buffer));
    wc_ErrorString(-123456, buffer);
    ExpectIntGT((int)XSTRLEN(buffer), 0);

    return EXPECT_RESULT();
}
