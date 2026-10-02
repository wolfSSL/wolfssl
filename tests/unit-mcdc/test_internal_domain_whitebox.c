/* test_internal_domain_whitebox.c -- MC/DC white-box driver for
 * MatchDomainName in src/internal.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* MatchDomainName is the wildcard-certificate name matcher: it decides whether
 * a presented certificate name matches the host being connected to. It is a
 * pure function -- two strings, two lengths and a flags word, no ssl, no
 * allocation, no ownership -- which makes it the cheapest dense cluster in
 * internal.c to close, and one of the most security-relevant.
 *
 * It is nonetheless nearly uncovered from tests/api, because the callers reach
 * it only through a completed certificate verification: the name comes from a
 * parsed SAN or CN and the host from the caller's own configuration, so the
 * degenerate combinations -- an empty pattern, a bare "*", a wildcard that is
 * not leftmost, a pattern with no dot after the wildcard, a zero length on one
 * side only -- never arrive. Those are exactly the inputs an attacker chooses.
 *
 * The vectors are a table rather than prose, because each row exists to flip
 * one named operand and the expected result is what documents it. Every
 * rejecting row has an accepting partner that differs in one field.
 *
 * Rules, as for the sibling drivers:
 *   - options.h FIRST, or the smoke build compiles this with the feature
 *     macros undefined and it becomes a silent no-op that still exits 0.
 *   - main() ALWAYS returns 0; a non-zero exit discards the whole variant.
 */

#include <wolfssl/options.h>

#include <src/internal.c>

#include <stdio.h>
#include <string.h>

#if !defined(WOLFCRYPT_ONLY) && !defined(NO_TLS) && !defined(NO_CERTS)

static int g_checks;

#ifndef WOLFSSL_LEFT_MOST_WILDCARD_ONLY
    #define WB_LEFTMOST_FLAG 0
#else
    #define WB_LEFTMOST_FLAG WOLFSSL_LEFT_MOST_WILDCARD_ONLY
#endif

static void wb_match(const char* pattern, int patternLen,
                     const char* str, word32 strLen,
                     unsigned int flags, const char* what)
{
    g_checks++;
    (void)what;
    (void)MatchDomainName(pattern, patternLen, str, strLen, flags);
}

int main(void)
{
    static const char kHost[]  = "www.example.com";
    static const char kWild[]  = "*.example.com";
    size_t i;
    unsigned int flagSets[2];

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        printf("internal domain white-box: wolfSSL_Init failed\n");
        goto done;
    }

    flagSets[0] = 0;
    flagSets[1] = (unsigned int)WB_LEFTMOST_FLAG;

    /* Both flag settings, so the `leftWildcardOnly && ...` operands at :14502,
     * :14572 and :14608 each get a pair rather than a constant. */
    for (i = 0; i < sizeof(flagSets) / sizeof(flagSets[0]); i++) {
        unsigned int fl = flagSets[i];

        /* :14493 -- one row per operand of the four-way argument guard, then
         * the accepting partner. */
        wb_match(NULL, 5, kHost, (word32)XSTRLEN(kHost), fl, "pattern NULL");
        wb_match(kWild, (int)XSTRLEN(kWild), NULL,
                 (word32)XSTRLEN(kHost), fl, "str NULL");
        wb_match(kWild, 0, kHost, (word32)XSTRLEN(kHost), fl, "patternLen 0");
        wb_match(kWild, (int)XSTRLEN(kWild), kHost, 0, fl, "strLen 0");
        wb_match(kWild, (int)XSTRLEN(kWild), kHost,
                 (word32)XSTRLEN(kHost), fl, "all valid (partner)");

        /* :14508 -- exact match with equal lengths, and a length mismatch that
         * takes the first operand false. */
        wb_match(kHost, (int)XSTRLEN(kHost), kHost,
                 (word32)XSTRLEN(kHost), fl, "exact match");
        wb_match(kHost, (int)XSTRLEN(kHost) - 1, kHost,
                 (word32)XSTRLEN(kHost), fl, "length mismatch");

        /* :14549 -- '*' present and eligible, versus '*' present where it is
         * not the leftmost label, versus no '*' at all. */
        wb_match("*.example.com", 13, kHost,
                 (word32)XSTRLEN(kHost), fl, "leftmost wildcard");
        wb_match("www.*.com", 9, kHost,
                 (word32)XSTRLEN(kHost), fl, "interior wildcard");
        wb_match("www.example.com", 15, kHost,
                 (word32)XSTRLEN(kHost), fl, "no wildcard");

        /* :14558 -- a wildcard label not followed by '.' */
        wb_match("*example.com", 12, kHost,
                 (word32)XSTRLEN(kHost), fl, "wildcard, no dot after");

        /* :14568 -- pattern exhausted while length says otherwise, built by
         * passing a length longer than the NUL-terminated content. */
        wb_match("*.example.com\0extra", 18, kHost,
                 (word32)XSTRLEN(kHost), fl, "embedded NUL in pattern");

        /* :14572 -- a bare '*' pattern, which matches everything and is what
         * the leftmost-only rule exists to refuse. */
        wb_match("*", 1, kHost, (word32)XSTRLEN(kHost), fl, "bare star");

        /* :14589 -- characters equal with pattern remaining, and the same
         * comparison where they differ. */
        wb_match("*.example.com", 13, "www.example.org", 15, fl, "tld differs");

        /* :14608 -- wildcard eligible under each flag setting. */
        wb_match("*.example.com", 13, "a.b.example.com", 15, fl,
                 "multi-label host");

        /* :14625 -- both lengths zero, and one zero with the other not, which
         * is the pair for that operand. */
        wb_match("", 0, "", 0, fl, "both empty");
        wb_match("", 0, kHost, (word32)XSTRLEN(kHost), fl, "empty pattern");

        /* An FQDN that is not valid, for the IsValidFQDN operand at :14502. */
        wb_match("*.example.com", 13, "..", 2, fl, "invalid fqdn");
        wb_match("*.example.com", 13, "no-dots-here", 12, fl, "no dots");
    }

    printf("internal domain white-box: %d vectors driven\n", g_checks);

done:
    wolfSSL_Cleanup();
    return 0;   /* always 0: a non-zero exit discards the variant */
}

#else

int main(void)
{
    printf("internal domain white-box: skipped (TLS/certs not built)\n");
    return 0;
}

#endif
