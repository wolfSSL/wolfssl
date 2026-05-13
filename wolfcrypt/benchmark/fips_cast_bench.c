/* fips_cast_bench.c
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

/* FIPS CAST benchmark.
 *
 * Measures the wall-clock cost of each Conditional Algorithm Self-Test (CAST)
 * defined by the wolfCrypt v7.0.0 FIPS module so operators can budget module
 * power-on latency on resource-constrained operational environments (DSP,
 * MCU) where every additional CAST is directly observable as boot-time delay.
 *
 * Compiled only when HAVE_FIPS is defined (see wolfcrypt/benchmark/include.am
 * BUILD_FIPS gate).  Calls wc_RunCast_fips(id) repeatedly per CAST and reports
 * mean / stddev / min / max for each, plus total time for one pass over all
 * enabled CASTs (the cost paid by callers that invoke wc_RunAllCast_fips() at
 * application start).
 *
 * Citations:
 *   FIPS 140-3 sec 7.10 (Self-Tests) - CAST framework
 *   FIPS 140-3 IG 10.3.A           - Algorithm-by-algorithm CAST coverage
 *   ISO/IEC 19790:2012 sec 7.10.2  - Conditional self-test execution
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#if !defined(WOLFSSL_USER_SETTINGS) && !defined(WOLFSSL_NO_OPTIONS_H)
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h> /* also picks up user_settings.h */

#ifdef HAVE_FIPS

#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/fips_test.h>
#include <wolfssl/wolfcrypt/random.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
#else
    #include <time.h>
#endif


#define BENCH_DEFAULT_ITERS 10

/* Map FIPS_CAST_* enum value to a printable name.  Kept in sync with
 * wolfssl/wolfcrypt/fips_test.h FipsCastId enum. */
static const char* cast_name(int id)
{
    switch (id) {
        case FIPS_CAST_AES_CBC:           return "AES-CBC";
        case FIPS_CAST_AES_GCM:           return "AES-GCM";
        case FIPS_CAST_HMAC_SHA1:         return "HMAC-SHA-1";
        case FIPS_CAST_HMAC_SHA2_256:     return "HMAC-SHA2-256";
        case FIPS_CAST_HMAC_SHA2_512:     return "HMAC-SHA2-512";
        case FIPS_CAST_HMAC_SHA3_256:     return "HMAC-SHA3-256";
        case FIPS_CAST_DRBG:              return "DRBG (SHA-256)";
        case FIPS_CAST_RSA_SIGN_PKCS1v15: return "RSA-SIGN-PKCS1v15";
        case FIPS_CAST_ECC_CDH:           return "ECC-CDH";
        case FIPS_CAST_ECC_PRIMITIVE_Z:   return "ECC-Primitive-Z";
        case FIPS_CAST_DH_PRIMITIVE_Z:    return "DH-Primitive-Z";
        case FIPS_CAST_ECDSA:             return "ECDSA";
        case FIPS_CAST_KDF_TLS12:         return "KDF-TLS12";
        case FIPS_CAST_KDF_TLS13:         return "KDF-TLS13";
        case FIPS_CAST_KDF_SSH:           return "KDF-SSH";
#if defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(6,0)
        case FIPS_CAST_KDF_SRTP:          return "KDF-SRTP";
        case FIPS_CAST_ED25519:           return "Ed25519";
        case FIPS_CAST_ED448:             return "Ed448";
        case FIPS_CAST_PBKDF2:            return "PBKDF2";
#endif
#if defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(7,0)
        case FIPS_CAST_AES_ECB:           return "AES-ECB";
        case FIPS_CAST_ML_KEM:            return "ML-KEM";
        case FIPS_CAST_ML_DSA:            return "ML-DSA";
        case FIPS_CAST_LMS:               return "LMS";
        case FIPS_CAST_XMSS:              return "XMSS";
        case FIPS_CAST_DRBG_SHA512:       return "DRBG (SHA-512)";
        case FIPS_CAST_SLH_DSA:           return "SLH-DSA";
        case FIPS_CAST_AES_CMAC:          return "AES-CMAC";
        case FIPS_CAST_SHAKE:             return "SHAKE";
        case FIPS_CAST_AES_KW:            return "AES-KW";
#endif
        default:                          return "(unknown)";
    }
}


/* Monotonic clock in nanoseconds.  POSIX clock_gettime(CLOCK_MONOTONIC) on
 * Unix-like systems; QueryPerformanceCounter on Windows. */
static long long now_ns(void)
{
#ifdef _WIN32
    static LARGE_INTEGER freq = { 0 };
    LARGE_INTEGER count;
    if (freq.QuadPart == 0)
        QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    /* Multiply before divide to keep precision; freq is typically 10MHz. */
    return (long long)((count.QuadPart * 1000000000LL) / freq.QuadPart);
#else
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (long long)ts.tv_sec * 1000000000LL + (long long)ts.tv_nsec;
#endif
}


/* Run a single CAST iters times, populate stats (in milliseconds).
 * Returns 0 on success, non-zero on first CAST failure. */
static int run_one_cast(int id, int iters,
                        double* out_mean_ms, double* out_stddev_ms,
                        double* out_min_ms, double* out_max_ms)
{
    int i;
    long long total = 0;
    long long mn = LLONG_MAX;
    long long mx = 0;
    long long* samples;
    double mean_ns;
    double variance_acc = 0.0;

    if (iters <= 0)
        return BAD_FUNC_ARG;

    samples = (long long*)XMALLOC((size_t)iters * sizeof(long long), NULL,
                                  DYNAMIC_TYPE_TMP_BUFFER);
    if (samples == NULL)
        return MEMORY_E;

    for (i = 0; i < iters; i++) {
        long long t0, t1, dt;
        int rc;

        t0 = now_ns();
        rc = wc_RunCast_fips(id);
        t1 = now_ns();
        if (rc != 0) {
            XFREE(samples, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return rc;
        }
        dt = t1 - t0;
        if (dt < 0)
            dt = 0;
        samples[i] = dt;
        total += dt;
        if (dt < mn)
            mn = dt;
        if (dt > mx)
            mx = dt;
    }

    mean_ns = (double)total / (double)iters;
    for (i = 0; i < iters; i++) {
        double d = (double)samples[i] - mean_ns;
        variance_acc += d * d;
    }
    XFREE(samples, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    *out_mean_ms   = mean_ns / 1.0e6;
    *out_stddev_ms = sqrt(variance_acc / (double)iters) / 1.0e6;
    *out_min_ms    = (double)mn / 1.0e6;
    *out_max_ms    = (double)mx / 1.0e6;
    return 0;
}


static void usage(const char* prog)
{
    printf("usage: %s [-i ITERS] [-c CAST_ID] [-l]\n", prog);
    printf("  -i ITERS    iterations per CAST (default %d)\n",
           BENCH_DEFAULT_ITERS);
    printf("  -c CAST_ID  benchmark only the named CAST id\n");
    printf("  -l          list CAST ids and names; do not run\n");
    printf("  -h          show this help\n");
}


int main(int argc, char** argv)
{
    int iters = BENCH_DEFAULT_ITERS;
    int single = -1;
    int list_only = 0;
    int i;
    int first, last;
    int failures = 0;
    int run_count = 0;
    double total_mean_ms = 0.0;

    for (i = 1; i < argc; i++) {
        if (XSTRCMP(argv[i], "-i") == 0 && i + 1 < argc) {
            iters = atoi(argv[++i]);
            if (iters <= 0) {
                fprintf(stderr, "-i requires a positive iteration count\n");
                return 2;
            }
        } else if (XSTRCMP(argv[i], "-c") == 0 && i + 1 < argc) {
            single = atoi(argv[++i]);
        } else if (XSTRCMP(argv[i], "-l") == 0) {
            list_only = 1;
        } else if (XSTRCMP(argv[i], "-h") == 0
                || XSTRCMP(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "unknown argument: %s\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    if (list_only) {
        printf("FIPS CAST IDs (FIPS_CAST_COUNT = %d):\n", FIPS_CAST_COUNT);
        for (i = 0; i < FIPS_CAST_COUNT; i++)
            printf("  %2d  %s\n", i, cast_name(i));
        return 0;
    }

    if (single >= 0 && single >= FIPS_CAST_COUNT) {
        fprintf(stderr, "CAST id %d out of range (0..%d)\n",
                single, FIPS_CAST_COUNT - 1);
        return 2;
    }

    printf("wolfCrypt FIPS CAST benchmark\n");
    printf("Library version: %s\n", LIBWOLFSSL_VERSION_STRING);
    printf("FIPS_CAST_COUNT: %d\n", FIPS_CAST_COUNT);
    printf("Iterations per CAST: %d\n", iters);
    printf("Clock: %s\n",
#ifdef _WIN32
           "QueryPerformanceCounter"
#else
           "clock_gettime(CLOCK_MONOTONIC)"
#endif
           );
    printf("\n");

    /* Register the default DRBG seed callback (mirrors benchmark.c and
     * wolfcrypt/test/test.c).  Builds with WC_RNG_SEED_CB - which include
     * the FIPS optest CFLAGS - require every application that initializes
     * the RNG to register a seed generator before _InitRng can produce a
     * working DRBG; without it, wc_InitRng inside the ECC_PRIMITIVE_Z and
     * ECDSA CASTs returns -199 (RNG_FAILURE_E) and the dependent CASTs
     * cascade-fail. */
#ifdef WC_RNG_SEED_CB
    {
        int seed_cb_rc = wc_SetSeed_Cb(WC_GENERATE_SEED_DEFAULT);
        if (seed_cb_rc != 0) {
            fprintf(stderr,
                "wc_SetSeed_Cb returned %d - DRBG-using CASTs will fail.\n",
                seed_cb_rc);
        }
    }
#endif

    /* Prime: run every CAST once via wc_RunAllCast_fips() so each CAST
     * reaches FIPS_CAST_STATE_SUCCESS before we begin measuring.  This
     * isolates the per-CAST KAT runtime cost from the cascading
     * recursive-CAST init chain that fires on the first invocation of a
     * cold CAST whose KAT internally calls FIPS-wrapped primitives whose
     * own CASTs are still in INIT state.  Customers calling
     * wc_RunAllCast_fips() at boot pay this one-time cost up front, so
     * priming here matches that real-world workflow. */
    {
        int prime_rc = wc_RunAllCast_fips();
        if (prime_rc != 0) {
            fprintf(stderr,
                "wc_RunAllCast_fips() prime returned %d - some CASTs may have failed.\n"
                "Per-CAST measurements continue but failed CASTs will report errors.\n\n",
                prime_rc);
        }
    }

    printf("ID | Name                | Mean(ms) | StdDev(ms) | Min(ms) "
           "| Max(ms)\n");
    printf("---+---------------------+----------+------------+---------"
           "+---------\n");

    first = (single >= 0) ? single : 0;
    last  = (single >= 0) ? single + 1 : FIPS_CAST_COUNT;

    for (i = first; i < last; i++) {
        double mean_ms = 0, sd_ms = 0, mn_ms = 0, mx_ms = 0;
        int rc = run_one_cast(i, iters, &mean_ms, &sd_ms, &mn_ms, &mx_ms);
        if (rc != 0) {
            printf("%2d | %-19s | FAILED rc=%d (%s)\n",
                   i, cast_name(i), rc, wc_GetErrorString(rc));
            failures++;
            continue;
        }
        printf("%2d | %-19s | %8.3f | %10.3f | %7.3f | %7.3f\n",
               i, cast_name(i), mean_ms, sd_ms, mn_ms, mx_ms);
        total_mean_ms += mean_ms;
        run_count++;
    }

    printf("\n");
    if (run_count > 0) {
        printf("Sum of mean CAST times (one wc_RunAllCast_fips() pass): "
               "%.3f ms\n", total_mean_ms);
    }
    if (failures > 0) {
        printf("WARN: %d CAST(s) failed.\n", failures);
        return 1;
    }
    return 0;
}

#else /* !HAVE_FIPS */

#include <stdio.h>

int main(void)
{
    fprintf(stderr,
            "fips_cast_bench: built without HAVE_FIPS - nothing to measure\n");
    return 0;
}

#endif /* HAVE_FIPS */
