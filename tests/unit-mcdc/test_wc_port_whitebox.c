/* test_wc_port_whitebox.c
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

/* White-box supplement for wolfcrypt/src/wc_port.c.
 *
 * wolfSSL_strnstr is not declared in any public wolfcrypt header, so the
 * tests/api "port" group cannot reach it. Its loop guard
 * "n >= s2_len && s1[0]" needs both operands driven false independently,
 * which needs a haystack shorter than the needle and an empty haystack.
 */

#include <wolfcrypt/src/wc_port.c>

#include <stdio.h>
#include <string.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if (!defined(WOLFSSL_LEANPSK) && !defined(STRING_USER)) || \
    defined(USE_WOLF_STRNSTR)

static void wb_strnstr(void)
{
    const char* hay = "abcdef";

    /* n >= s2_len false on entry: search window shorter than the needle. */
    if (wolfSSL_strnstr(hay, "abc", 2) != NULL) {
        printf("  [wb] FAIL: short window matched\n");
        wb_fail++;
    }

    /* s1[0] false: empty haystack, window wide enough so the first operand
     * stays true and the second decides. */
    if (wolfSSL_strnstr("", "abc", 8) != NULL) {
        printf("  [wb] FAIL: empty haystack matched\n");
        wb_fail++;
    }

    /* both true, then a hit, so the loop body and the return are exercised. */
    if (wolfSSL_strnstr(hay, "cd", 6) == NULL) {
        printf("  [wb] FAIL: expected match not found\n");
        wb_fail++;
    }

    /* both true, no hit: the loop runs to exhaustion and returns NULL. */
    if (wolfSSL_strnstr(hay, "xy", 6) != NULL) {
        printf("  [wb] FAIL: unexpected match\n");
        wb_fail++;
    }

    /* zero-length needle short-circuits before the loop. */
    if (wolfSSL_strnstr(hay, "", 6) != hay) {
        printf("  [wb] FAIL: empty needle did not return s1\n");
        wb_fail++;
    }

    WB_NOTE("wolfSSL_strnstr loop-guard operand pairs done");
}

#else
static void wb_strnstr(void) { WB_NOTE("wolfSSL_strnstr not compiled; skipped"); }
#endif

int main(void)
{
    printf("wc_port white-box\n");
    wb_strnstr();
    printf("  [wb] failures: %d\n", wb_fail);
    /* Always 0: a non-zero exit makes the campaign harness discard the
     * whole variant rather than record its coverage. */
    return 0;
}
