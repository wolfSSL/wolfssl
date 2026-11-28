/* test_internal_suites_whitebox.c -- MC/DC white-box driver for the cipher
 * suite table in src/internal.c
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

/* WHY A WHITE-BOX FOR THIS.
 *
 * InitSuites() is one long table of decisions of the shape
 *
 *     if (tls1_2 && haveECC && haveAES128) { suites[idx++] = ...; }
 *
 * over twelve have* parameters and a protocol version. It is the densest
 * single cluster of uncovered conditions in internal.c.
 *
 * A handshake cannot drive it. Every caller -- InitSSL_Suites,
 * InitCtxSuitesWithMutex, AllocateSuites -- derives the have* flags from what
 * the build compiled in and what the CTX was loaded with, so on any one binary
 * they are near enough constant: a build with ECC gives haveECC=1 in every
 * call it ever makes. The operands therefore have no independence pair from
 * outside, however many handshakes are run.
 *
 * The vector set is a one-at-a-time sweep from an all-ones baseline. For a
 * decision `A && B && C`, the all-ones call takes it true, and the call with
 * exactly one flag cleared takes that operand false with the others true --
 * which is precisely the independence pair MC/DC asks for, for every operand
 * of every decision in the table, from n+1 calls rather than 2^n.
 *
 * The version is swept too, because tls, tls1_2 and tls1_3 are derived from
 * pv and appear as the leading operand of most rows.
 *
 * Rules, same as the sibling drivers:
 *   - options.h FIRST, or the smoke build compiles this with the feature
 *     macros undefined and it silently becomes a no-op that still exits 0.
 *   - main() ALWAYS returns 0; a non-zero exit discards the whole variant.
 *   - Bail paths print, so "covered nothing" is distinguishable from
 *     "had nothing to say".
 */

#include <wolfssl/options.h>

#include <src/internal.c>

#include <stdio.h>
#include <string.h>

#if !defined(WOLFCRYPT_ONLY) && !defined(NO_TLS)

static int g_calls;

/* The twelve have* parameters, in the order InitSuites takes them. Index into
 * this to clear exactly one per call. */
enum {
    F_RSA = 0, F_PSK, F_DH, F_ECDSASIG, F_ECC, F_STATICRSA, F_STATICECC,
    F_ANON, F_NULL, F_AES128, F_SHA1, F_RC4, F_COUNT
};

static const char* const kFlagName[F_COUNT] = {
    "haveRSA", "havePSK", "haveDH", "haveECDSAsig", "haveECC", "haveStaticRSA",
    "haveStaticECC", "haveAnon", "haveNull", "haveAES128", "haveSHA1", "haveRC4"
};

static void wb_call(ProtocolVersion pv, const word16 f[F_COUNT], int side)
{
    /* Suites is large and InitSuites appends from idx 0, so a fresh zeroed
     * struct per call keeps each vector independent of the last. */
    Suites* suites = (Suites*)XMALLOC(sizeof(Suites), NULL,
                                      DYNAMIC_TYPE_SUITES);
    if (suites == NULL)
        return;
    XMEMSET(suites, 0, sizeof(*suites));
    InitSuites(suites, pv, 2048 / 8,
               f[F_RSA], f[F_PSK], f[F_DH], f[F_ECDSASIG], f[F_ECC],
               f[F_STATICRSA], f[F_STATICECC], f[F_ANON], f[F_NULL],
               f[F_AES128], f[F_SHA1], f[F_RC4], side);
    g_calls++;
    XFREE(suites, NULL, DYNAMIC_TYPE_SUITES);
}

static void wb_sweep_version(ProtocolVersion pv, const char* what)
{
    word16 f[F_COUNT];
    int i, side;
    const int sides[2] = { WOLFSSL_CLIENT_END, WOLFSSL_SERVER_END };

    for (side = 0; side < 2; side++) {
        /* All ones: takes every AND chain in the table true, and is the
         * accepting partner for every operand cleared below. */
        for (i = 0; i < F_COUNT; i++)
            f[i] = 1;
        wb_call(pv, f, sides[side]);

        /* One at a time: this operand false, all others true. */
        for (i = 0; i < F_COUNT; i++) {
            int j;
            for (j = 0; j < F_COUNT; j++)
                f[j] = 1;
            f[i] = 0;
            wb_call(pv, f, sides[side]);
        }
    }
    (void)what;
    (void)kFlagName;
}

/* ---------------------------------------------------------- main */

int main(void)
{
    ProtocolVersion pv;

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        printf("internal suites white-box: wolfSSL_Init failed\n");
        goto done;
    }

    /* tls is false, so the leading operand of every `tls && ...` row is
     * exercised false with the rest true. */
    pv.major = SSLv3_MAJOR; pv.minor = SSLv3_MINOR;
    wb_sweep_version(pv, "SSLv3");

    /* tls true, tls1_2 false. */
    pv.major = SSLv3_MAJOR; pv.minor = TLSv1_MINOR;
    wb_sweep_version(pv, "TLSv1.0");

    /* tls1_2 true, tls1_3 false: the bulk of the table. */
    pv.major = SSLv3_MAJOR; pv.minor = TLSv1_2_MINOR;
    wb_sweep_version(pv, "TLSv1.2");

    /* tls1_3 true. */
    pv.major = SSLv3_MAJOR; pv.minor = TLSv1_3_MINOR;
    wb_sweep_version(pv, "TLSv1.3");

#ifdef WOLFSSL_DTLS
    /* The DTLS branch inverts the minor comparison, so both DTLS versions are
     * needed to pair the operands inside `pv.major == DTLS_MAJOR`. */
    pv.major = DTLS_MAJOR; pv.minor = DTLSv1_2_MINOR;
    wb_sweep_version(pv, "DTLSv1.2");
    pv.major = DTLS_MAJOR; pv.minor = DTLS_MINOR;
    wb_sweep_version(pv, "DTLSv1.3");
#endif

    printf("internal suites white-box: %d InitSuites calls\n", g_calls);

done:
    wolfSSL_Cleanup();
    return 0;   /* always 0: a non-zero exit discards the variant */
}

#else /* WOLFCRYPT_ONLY || NO_TLS */

int main(void)
{
    printf("internal suites white-box: skipped (TLS not built)\n");
    return 0;
}

#endif
