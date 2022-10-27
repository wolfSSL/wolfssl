/* error_test.c
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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


#include "wolfcrypt/test/test.h"

#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"


WOLFSSL_TEST_SUBROUTINE int error_test(void)
{
    const char* errStr;
    char        out[WOLFSSL_MAX_ERROR_SZ];
    const char* unknownStr = wc_GetErrorString(0);

#ifdef NO_ERROR_STRINGS
    /* Ensure a valid error code's string matches an invalid code's.
     * The string is that error strings are not available.
     */
    errStr = wc_GetErrorString(OPEN_RAN_E);
    wc_ErrorString(OPEN_RAN_E, out);
    if (XSTRCMP(errStr, unknownStr) != 0)
        return -1100;
    if (XSTRCMP(out, unknownStr) != 0)
        return -1101;
#else
    int i;
    int j = 0;
    /* Values that are not or no longer error codes. */
    int missing[] = { -122, -123, -124,       -127, -128, -129, -159,
                      -163, -164, -165, -166, -167, -168, -169, -233,
                      0 };

    /* Check that all errors have a string and it's the same through the two
     * APIs. Check that the values that are not errors map to the unknown
     * string.
     */
    for (i = MAX_CODE_E-1; i >= WC_LAST_E; i--) {
        errStr = wc_GetErrorString(i);
        wc_ErrorString(i, out);

        if (i != missing[j]) {
            if (XSTRCMP(errStr, unknownStr) == 0)
                return -1102;
            if (XSTRCMP(out, unknownStr) == 0)
                return -1103;
            if (XSTRCMP(errStr, out) != 0)
                return -1104;
            if (XSTRLEN(errStr) >= WOLFSSL_MAX_ERROR_SZ)
                return -1105;
        }
        else {
            j++;
            if (XSTRCMP(errStr, unknownStr) != 0)
                return -1106;
            if (XSTRCMP(out, unknownStr) != 0)
                return -1107;
        }
    }

    /* Check if the next possible value has been given a string. */
    errStr = wc_GetErrorString(i);
    wc_ErrorString(i, out);
    if (XSTRCMP(errStr, unknownStr) != 0)
        return -1108;
    if (XSTRCMP(out, unknownStr) != 0)
        return -1109;
#endif

    return 0;
}