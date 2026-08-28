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

/* Times the module's self-tests so an operator can budget start-up on slow
 * hardware.  Two kinds, costing very different amounts:
 *      per-algorithm known-answer tests, run once each (FIPS 140-3 IG 10.3.A)
 *   -p key-pair tests, run on EVERY key generation
 *      (ISO/IEC 19790:2012 sec 7.10.3.3)
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#if !defined(WOLFSSL_USER_SETTINGS) && !defined(WOLFSSL_NO_OPTIONS_H)
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h> /* also picks up user_settings.h */

/* wc_RunCast_fips() is v7.0.0+ and needs fips.c, which dev-no-post compiles
 * only into linuxkm, not libwolfssl.  Both flavors use the stub below. */
#if defined(HAVE_FIPS) && FIPS_VERSION3_GE(7,0,0) && \
    !defined(WOLFSSL_FIPS_DEV_NO_POST)

#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/fips_test.h>
#include <wolfssl/wolfcrypt/random.h>
#ifdef WOLFSSL_HAVE_MLKEM
    #include <wolfssl/wolfcrypt/wc_mlkem.h>
#endif
#ifdef WOLFSSL_HAVE_MLDSA
    #include <wolfssl/wolfcrypt/wc_mldsa.h>
#endif
#ifdef WOLFSSL_HAVE_SLHDSA
    #include <wolfssl/wolfcrypt/wc_slhdsa.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>
#include <errno.h>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
#else
    #include <time.h>
#endif


#define BENCH_DEFAULT_ITERS 10
/* Upper bound for -i, far above any useful run. */
#define BENCH_MAX_ITERS     1000000

/* Names for the CAST ids in wolfssl/wolfcrypt/fips_test.h.  Hand-maintained,
 * so an id added there and not here prints "(unknown)" rather than silently
 * going missing. */
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


/* Wall-clock seconds, the way benchmark.c's current_time() does it: convert
 * to double before dividing, so no integer overflow is possible. */
static double bench_now(void)
{
#ifdef _WIN32
    static LARGE_INTEGER freq = { 0 };
    LARGE_INTEGER count;
    if (freq.QuadPart == 0) {
        if (!QueryPerformanceFrequency(&freq) || (freq.QuadPart == 0))
            return -1.0;
    }
    if (!QueryPerformanceCounter(&count))
        return -1.0;
    return (double)count.QuadPart / (double)freq.QuadPart;
#else
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return -1.0;
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
#endif
}


/* Run a single CAST iters times, populate stats (in milliseconds).
 * Returns 0 on success, non-zero on first CAST failure. */
static int run_one_cast(int id, int iters,
                        double* out_mean_ms, double* out_stddev_ms,
                        double* out_min_ms, double* out_max_ms)
{
    int i;
    double mn = 0.0;
    double mx = 0.0;
    double mean = 0.0;   /* running mean, seconds */
    double m2 = 0.0;     /* running sum of squared deviations */

    if (iters <= 0)
        return BAD_FUNC_ARG;

    /* Welford's method, so the samples need not be kept. */
    for (i = 0; i < iters; i++) {
        double t0, t1, dt, d;
        int rc;

        t0 = bench_now();
        rc = wc_RunCast_fips(id);
        t1 = bench_now();
        if (rc != 0)
            return rc;
        dt = t1 - t0;
        if (dt < 0.0)
            dt = 0.0;
        if ((i == 0) || (dt < mn))
            mn = dt;
        if (dt > mx)
            mx = dt;

        d = dt - mean;
        mean += d / (double)(i + 1);
        m2 += d * (dt - mean);
    }

    *out_mean_ms   = mean * 1000.0;
    *out_stddev_ms = sqrt(m2 / (double)iters) * 1000.0;
    *out_min_ms    = mn * 1000.0;
    *out_max_ms    = mx * 1000.0;
    return 0;
}


/* Pairwise consistency tests.
 *
 * A CAST runs once at start-up.  This test runs on every key generation, so
 * the application keeps paying it and none of it shows in the CAST numbers.
 * ISO/IEC 19790:2012 sec 7.10.3.3.
 *
 *   KeyGen+PCT  what a caller pays today.  MEASURED.
 *   PCT alone   the same test repeated on the finished key.  MEASURED.
 *   KeyGen raw  the difference.  DERIVED: no build generates a key without
 *               the test, so it cannot be measured directly.
 */

#define BENCH_PCT_DEFAULT_ITERS 1

#if defined(WOLFSSL_HAVE_MLKEM) || defined(WOLFSSL_HAVE_MLDSA) || \
    defined(WOLFSSL_HAVE_SLHDSA)
    #define BENCH_HAVE_PCT
#endif
#if defined(WOLFSSL_HAVE_MLKEM) || defined(WOLFSSL_HAVE_MLDSA)
    /* The two families that share the four-column table. */
    #define BENCH_HAVE_PCT_TABLE
#endif

#ifdef BENCH_HAVE_PCT

/* Largest seed size over the FIPS 205 parameter sets.  Checked against the
 * key at run time, so a set with a bigger one is skipped with a message
 * rather than overflowing these buffers. */
#define BENCH_SLHDSA_MAX_N 32

#ifdef BENCH_HAVE_PCT_TABLE
/* KeyGen raw goes negative if the test is not actually inside key generation.
 * Compiling the SLH-DSA one out took it from +54.8 ms to -365.5 ms, which set
 * the margin below; noise cannot swing that far.
 * Returns 1 when key generation does not appear to run the test. */
static int pct_missing(double raw_ms, double pct_ms)
{
    return (raw_ms < 0.0) && ((-raw_ms) > (pct_ms * 0.05));
}

static void pct_hdr(const char* title, const char* what)
{
    printf("%s\n", title);
    printf("  PCT = %s\n", what);
    printf("Alg             | KeyGen+PCT | PCT alone  | KeyGen raw | PCT share\n");
    printf("                |       (ms) |       (ms) | (ms) DERIV |       (%%)\n");
    printf("----------------+------------+------------+------------+----------\n");
}

/* Returns 1 when the row shows the PCT missing from key generation. */
static int pct_row(const char* name, double kg_s, double pct_s, int iters)
{
    double kg    = kg_s  / (double)iters * 1000.0;
    double pct   = pct_s / (double)iters * 1000.0;
    double raw   = kg - pct;
    double share = (kg > 0.0) ? (pct * 100.0 / kg) : 0.0;

    printf("%-15s | %10.3f | %10.3f | %10.3f | %8.1f%s\n",
           name, kg, pct, raw, share,
           pct_missing(raw, pct) ? "   PCT NOT IN KEYGEN" : "");

    return pct_missing(raw, pct);
}
#endif /* BENCH_HAVE_PCT_TABLE */

static void pct_skip(const char* name, int rc)
{
    printf("%-15s | not available in this build (rc=%d, %s)\n",
           name, rc, wc_GetErrorString(rc));
}

static void pct_fail(const char* name, int rc)
{
    printf("%-15s | FAILED rc=%d (%s)\n", name, rc, wc_GetErrorString(rc));
}
#endif /* BENCH_HAVE_PCT */


#ifdef WOLFSSL_HAVE_MLKEM
/* Repeats what wc_mlkem.c's test does, fixed `m` included, so the number is
 * for the same work and not a different round trip. */
static int bench_pct_mlkem(int iters)
{
    static const int   types[] = { WC_ML_KEM_512, WC_ML_KEM_768,
                                   WC_ML_KEM_1024 };
    static const char* names[] = { "ML-KEM-512", "ML-KEM-768",
                                   "ML-KEM-1024" };
    static const byte  pct_m[WC_ML_KEM_ENC_RAND_SZ] = {
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB
    };
    byte   kgrand[WC_ML_KEM_MAKEKEY_RAND_SZ];
    byte   ss1[WC_ML_KEM_SS_SZ];
    byte   ss2[WC_ML_KEM_SS_SZ];
    byte*  ct;
    int    failures = 0;
    size_t t;

    ct = (byte*)XMALLOC(WC_ML_KEM_MAX_CIPHER_TEXT_SIZE, NULL,
                        DYNAMIC_TYPE_TMP_BUFFER);
    if (ct == NULL)
        return MEMORY_E;

    XMEMSET(kgrand, 0x5A, sizeof(kgrand));

    pct_hdr("ML-KEM (FIPS 203)", "encapsulate + decapsulate + compare");

    for (t = 0; t < sizeof(types) / sizeof(types[0]); t++) {
        MlKemKey  key;
        double kg_s = 0.0;
        double pct_s = 0.0;
        int       i;
        int       rc;

        rc = wc_MlKemKey_Init(&key, types[t], NULL, INVALID_DEVID);
        if (rc != 0) {
            pct_skip(names[t], rc);
            continue;
        }

        for (i = 0; i < iters; i++) {
            double t0, t1;
            word32    ctSz = 0;

            /* Vary the key each round so nothing measured is a repeat of
             * byte-identical work. */
            kgrand[0] = (byte)i;

            t0 = bench_now();
            rc = wc_MlKemKey_MakeKeyWithRandom(&key, kgrand,
                    (int)sizeof(kgrand));
            t1 = bench_now();
            if (rc != 0)
                break;
            kg_s += t1 - t0;

            t0 = bench_now();
            rc = wc_MlKemKey_CipherTextSize(&key, &ctSz);
            if (rc == 0) {
                rc = wc_MlKemKey_EncapsulateWithRandom(&key, ct, ss1, pct_m,
                        (int)sizeof(pct_m));
            }
            if (rc == 0)
                rc = wc_MlKemKey_Decapsulate(&key, ss2, ct, ctSz);
            if ((rc == 0) && (XMEMCMP(ss1, ss2, WC_ML_KEM_SS_SZ) != 0))
                rc = ML_KEM_PCT_E;
            t1 = bench_now();
            if (rc != 0)
                break;
            pct_s += t1 - t0;
        }

        if (rc != 0) {
            pct_fail(names[t], rc);
            failures++;
        }
        else {
            failures += pct_row(names[t], kg_s, pct_s, iters);
        }
        wc_MlKemKey_Free(&key);
    }

    /* Fixed-seed material, not a live key, but leaving a shared secret on the
     * stack of a FIPS benchmark costs nothing to avoid. */
    XMEMSET(ss1, 0, sizeof(ss1));
    XMEMSET(ss2, 0, sizeof(ss2));
    XFREE(ct, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    printf("\n");
    return failures;
}
#endif /* WOLFSSL_HAVE_MLKEM */


#ifdef WOLFSSL_HAVE_MLDSA
/* Repeats what mldsa_pct() in wc_mldsa.c does, same message and same all-zero
 * rnd, so this times the path the module actually runs. */
static int bench_pct_mldsa(int iters)
{
    static const byte  levels[] = { WC_ML_DSA_44, WC_ML_DSA_65, WC_ML_DSA_87 };
    static const char* names[]  = { "ML-DSA-44", "ML-DSA-65", "ML-DSA-87" };
    static const byte  pct_msg[] = "wolfSSL ML-DSA PCT";
    static const byte  pct_seed[MLDSA_SEED_SZ] = { 0 };
    byte   seed[MLDSA_SEED_SZ];
    byte*  sig;
    int    failures = 0;
    size_t t;

    sig = (byte*)XMALLOC(MLDSA_MAX_SIG_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sig == NULL)
        return MEMORY_E;

    XMEMSET(seed, 0x3C, sizeof(seed));

    pct_hdr("ML-DSA (FIPS 204)", "sign + verify");

    for (t = 0; t < sizeof(levels) / sizeof(levels[0]); t++) {
        wc_MlDsaKey key;
        double      kg_s = 0.0;
        double      pct_s = 0.0;
        int         i;
        int         rc;
        int         inited = 0;

        rc = wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID);
        if (rc == 0) {
            inited = 1;
            rc = wc_MlDsaKey_SetParams(&key, levels[t]);
        }
        if (rc != 0) {
            pct_skip(names[t], rc);
            if (inited)
                wc_MlDsaKey_Free(&key);
            continue;
        }

        for (i = 0; i < iters; i++) {
            double t0, t1;
            word32    sigSz = MLDSA_MAX_SIG_SIZE;
            int       res = 0;

            seed[0] = (byte)i;

            t0 = bench_now();
            rc = wc_MlDsaKey_MakeKeyFromSeed(&key, seed);
            t1 = bench_now();
            if (rc != 0)
                break;
            kg_s += t1 - t0;

            t0 = bench_now();
            rc = wc_MlDsaKey_SignCtxWithSeed(&key, NULL, 0, sig, &sigSz,
                    pct_msg, (word32)sizeof(pct_msg), pct_seed);
            if (rc == 0) {
                rc = wc_MlDsaKey_VerifyCtx(&key, sig, sigSz, NULL, 0, pct_msg,
                        (word32)sizeof(pct_msg), &res);
            }
            if ((rc == 0) && (res != 1))
                rc = ML_DSA_PCT_E;
            t1 = bench_now();
            if (rc != 0)
                break;
            pct_s += t1 - t0;
        }

        if (rc != 0) {
            pct_fail(names[t], rc);
            failures++;
        }
        else {
            failures += pct_row(names[t], kg_s, pct_s, iters);
        }
        wc_MlDsaKey_Free(&key);
    }

    XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    printf("\n");
    return failures;
}
#endif /* WOLFSSL_HAVE_MLDSA */


#ifdef WOLFSSL_HAVE_SLHDSA
/* SLH-DSA elected the root recompute over sign and verify.  This times what
 * the module costs now, and the alternative it rejected, so the decision can
 * be rechecked rather than remembered. */
static void bench_pct_slhdsa_notes(void)
{
    printf(
"KeyGen+PCT  what the module costs now: generate the key, then recompute the\n"
"            public root from the private seed and compare.  The recompute is\n"
"            a second root computation, so this is roughly double a key\n"
"            generation with no test at all.\n"
"sign+vfy    the alternative NOT taken.  Compare it with KeyGen+PCT to see\n"
"            what electing the root recompute saved.\n"
"PK.seed     the shortcut FIPS 140-3 IG 10.3.A Additional Comment 1 allows for\n"
"            SLH-DSA.  IT PROVES NOTHING HERE: the public key is a slice of\n"
"            the private one, so it compares bytes with themselves and can\n"
"            never fail.  Timed only so the claim rests on a measurement.\n");
}

static int bench_pct_slhdsa(int iters)
{
    static const int params[] = {
        SLHDSA_SHAKE128S, SLHDSA_SHAKE128F, SLHDSA_SHAKE192S,
        SLHDSA_SHAKE192F, SLHDSA_SHAKE256S, SLHDSA_SHAKE256F
#ifdef WOLFSSL_SLHDSA_SHA2
        , SLHDSA_SHA2_128S, SLHDSA_SHA2_128F, SLHDSA_SHA2_192S,
        SLHDSA_SHA2_192F, SLHDSA_SHA2_256S, SLHDSA_SHA2_256F
#endif
    };
    static const char* names[] = {
        "SHAKE-128s", "SHAKE-128f", "SHAKE-192s",
        "SHAKE-192f", "SHAKE-256s", "SHAKE-256f"
#ifdef WOLFSSL_SLHDSA_SHA2
        , "SHA2-128s", "SHA2-128f", "SHA2-192s",
        "SHA2-192f", "SHA2-256s", "SHA2-256f"
#endif
    };
    static const byte pct_msg[] = "wolfSSL SLH-DSA PCT";
    byte   sk_seed[BENCH_SLHDSA_MAX_N];
    byte   sk_prf[BENCH_SLHDSA_MAX_N];
    byte   pk_seed[BENCH_SLHDSA_MAX_N];
    byte   pub[BENCH_SLHDSA_MAX_N * 2];
    int    failures = 0;
    size_t t;

    printf("SLH-DSA (FIPS 205)\n");
    printf("Param           | KeyGen+PCT | sign+vfy | PK.seed |"
           " elected saves\n");
    printf("                |       (ms) |     (ms) |    (ms) |"
           "              \n");
    printf("----------------+------------+----------+---------+"
           "--------------\n");

    for (t = 0; t < sizeof(params) / sizeof(params[0]); t++) {
        SlhDsaKey key;
        double kg_s = 0.0;
        double a_s = 0.0;
        double c_s = 0.0;
        byte*     sig = NULL;
        int       sigLen;
        int       privLen;
        int       n;
        int       i;
        int       rc;

        rc = wc_SlhDsaKey_Init(&key, (enum SlhDsaParam)params[t], NULL,
                INVALID_DEVID);
        if (rc != 0) {
            pct_skip(names[t], rc);
            continue;
        }

        privLen = wc_SlhDsaKey_PrivateSize(&key);
        sigLen  = wc_SlhDsaKey_SigSize(&key);
        n       = (privLen > 0) ? (privLen / 4) : 0;
        if ((n <= 0) || (n > BENCH_SLHDSA_MAX_N) || (sigLen <= 0)) {
            printf("%-15s | skipped: n=%d sigLen=%d outside what this"
                   " benchmark allocates\n", names[t], n, sigLen);
            wc_SlhDsaKey_Free(&key);
            continue;
        }

        sig = (byte*)XMALLOC((size_t)sigLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (sig == NULL) {
            wc_SlhDsaKey_Free(&key);
            return MEMORY_E;
        }

        for (i = 0; i < iters; i++) {
            double t0, t1;
            word32    sigSz = (word32)sigLen;
            word32    ul = (word32)(n * 2);

            XMEMSET(sk_seed, (byte)(0x11 + i), (size_t)n);
            XMEMSET(sk_prf,  (byte)(0x22 + i), (size_t)n);
            XMEMSET(pk_seed, (byte)(0x33 + i), (size_t)n);

            t0 = bench_now();
            rc = wc_SlhDsaKey_MakeKeyWithRandom(&key, sk_seed, (word32)n,
                    sk_prf, (word32)n, pk_seed, (word32)n);
            t1 = bench_now();
            if (rc != 0)
                break;
            kg_s += t1 - t0;

            /* The alternative not taken, timed for comparison. */
            t0 = bench_now();
            rc = wc_SlhDsaKey_SignDeterministic(&key, NULL, 0, pct_msg,
                    (word32)sizeof(pct_msg), sig, &sigSz);
            if (rc == 0) {
                rc = wc_SlhDsaKey_Verify(&key, NULL, 0, pct_msg,
                        (word32)sizeof(pct_msg), sig, sigSz);
            }
            t1 = bench_now();
            if (rc != 0)
                break;
            a_s += t1 - t0;

            /* The IG shortcut.  See bench_pct_slhdsa_notes(). */
            t0 = bench_now();
            rc = wc_SlhDsaKey_ExportPublic(&key, pub, &ul);
            if ((rc == 0) && (XMEMCMP(pub, key.sk + (size_t)(n * 2),
                    (size_t)n) != 0)) {
                rc = SLH_DSA_PCT_E;
            }
            t1 = bench_now();
            if (rc != 0)
                break;
            c_s += t1 - t0;
        }

        if (rc != 0) {
            pct_fail(names[t], rc);
            failures++;
        }
        else {
            double kg = kg_s / (double)iters * 1000.0;
            double a  = a_s  / (double)iters * 1000.0;
            double c  = c_s  / (double)iters * 1000.0;

            /* The elected test must be the cheap one.  If someone puts sign
             * and verify back inside key generation, KeyGen+PCT swallows it
             * and stops being the smaller number, which is the one thing
             * worth failing on here. */
            if (kg < a) {
                printf("%-15s | %10.3f | %8.3f | %7.4f | %8.1fx\n",
                       names[t], kg, a, c, (kg > 0.0) ? (a / kg) : 0.0);
            }
            else {
                printf("%-15s | %10.3f | %8.3f | %7.4f |"
                       " SIGN+VERIFY IN KEYGEN\n", names[t], kg, a, c);
                failures++;
            }
        }

        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        wc_SlhDsaKey_Free(&key);
    }

    printf("\n");
    bench_pct_slhdsa_notes();
    printf("\n");
    return failures;
}
#endif /* WOLFSSL_HAVE_SLHDSA */


/* Returns the number of algorithms whose PCT measurement failed. */
static int bench_pct(int iters, const char* only)
{
    int failures = 0;
    int ran = 0;
#ifdef BENCH_HAVE_PCT
    int rc;
#endif

#ifndef BENCH_HAVE_PCT
    (void)iters;
#endif

    /* The tests below call private-key operations from outside the module,
     * where a FIPS build gates them behind the private-key lock and they
     * would return -287.  The module's own tests run inside and never meet
     * that gate, so unlock here, outside every timed region, rather than
     * charge them for a check they do not pay. */
#ifdef BENCH_HAVE_PCT
    PRIVATE_KEY_UNLOCK();
#endif

    printf("KeyGen+PCT and PCT alone are MEASURED; KeyGen raw is DERIVED as\n"
           "the difference, because no build of this module generates a key\n"
           "without running the PCT.\n\n");

    /* Each helper returns a count of failed rows, or a negative wolfCrypt
     * error if it could not run.  Keep those apart: summing them lets a
     * -125 cancel real failures and report success. */
#ifdef WOLFSSL_HAVE_MLKEM
    if ((only == NULL) || (XSTRCMP(only, "mlkem") == 0)) {
        rc = bench_pct_mlkem(iters);
        if (rc < 0)
            return rc;
        failures += rc;
        ran++;
    }
#endif
#ifdef WOLFSSL_HAVE_MLDSA
    if ((only == NULL) || (XSTRCMP(only, "mldsa") == 0)) {
        rc = bench_pct_mldsa(iters);
        if (rc < 0)
            return rc;
        failures += rc;
        ran++;
    }
#endif
#ifdef WOLFSSL_HAVE_SLHDSA
    if ((only == NULL) || (XSTRCMP(only, "slhdsa") == 0)) {
        rc = bench_pct_slhdsa(iters);
        if (rc < 0)
            return rc;
        failures += rc;
        ran++;
    }
#endif

    /* Otherwise an algorithm this build lacks prints a header and no rows,
     * which reads as "measured, costs nothing". */
#ifdef BENCH_HAVE_PCT
    PRIVATE_KEY_LOCK();
#endif

    if (ran == 0) {
        fprintf(stderr, "no PCT algorithm to benchmark%s%s\n",
                (only != NULL) ? " for -a " : "",
                (only != NULL) ? only : "");
        return -1;
    }
    return failures;
}

static void usage(const char* prog)
{
    printf("usage: %s [-i ITERS] [-c CAST_ID] [-l] [-p [-a FAMILY]]\n", prog);
    printf("  -i ITERS    iterations (default %d for CASTs, %d for -p)\n",
           BENCH_DEFAULT_ITERS, BENCH_PCT_DEFAULT_ITERS);
    printf("  -c CAST_ID  benchmark only the named CAST id\n");
    printf("  -l          list CAST ids and names; do not run\n");
    printf("  -p          benchmark the Pairwise Consistency Tests instead\n");
    printf("  -a FAMILY   with -p, one of mlkem, mldsa, slhdsa\n");
    printf("  -h          show this help\n");
}

/* atoi() silently truncates a too-large number, and the wrapped value lands
 * inside the range checks below: "-i 4294967297" ran 1 iteration and
 * "-c 4294967296" ran CAST 0, neither complaining.  strtol() lets us reject
 * both trailing garbage and out-of-range input.
 * Returns 0 and stores the value, or -1 on bad input. */
static int parse_int_arg(const char* s, long* out)
{
    char* end = NULL;
    long  v;

    errno = 0;
    v = strtol(s, &end, 10);
    if ((end == s) || (*end != '\0') || (errno == ERANGE) ||
            (v < (long)INT_MIN) || (v > (long)INT_MAX)) {
        return -1;
    }

    *out = v;
    return 0;
}


int main(int argc, char** argv)
{
    int iters = BENCH_DEFAULT_ITERS;
    int iters_set = 0;
    int single = -1;
    int list_only = 0;
    int pct_only = 0;
    const char* pct_family = NULL;
    int i;
    int first, last;
    int failures = 0;
    int run_count = 0;
    double total_mean_ms = 0.0;

    for (i = 1; i < argc; i++) {
        if (XSTRCMP(argv[i], "-i") == 0 && i + 1 < argc) {
            long v = 0;
            if ((parse_int_arg(argv[++i], &v) != 0) || (v <= 0) ||
                    (v > BENCH_MAX_ITERS)) {
                fprintf(stderr, "-i requires an iteration count in 1..%d\n",
                        BENCH_MAX_ITERS);
                return 2;
            }
            iters = (int)v;
            iters_set = 1;
        } else if (XSTRCMP(argv[i], "-p") == 0) {
            pct_only = 1;
        } else if (XSTRCMP(argv[i], "-a") == 0 && i + 1 < argc) {
            pct_family = argv[++i];
            if ((XSTRCMP(pct_family, "mlkem") != 0) &&
                    (XSTRCMP(pct_family, "mldsa") != 0) &&
                    (XSTRCMP(pct_family, "slhdsa") != 0)) {
                fprintf(stderr,
                        "-a requires one of mlkem, mldsa, slhdsa\n");
                return 2;
            }
        } else if (XSTRCMP(argv[i], "-c") == 0 && i + 1 < argc) {
            long v = 0;
            if ((parse_int_arg(argv[++i], &v) != 0) || (v < 0)) {
                fprintf(stderr, "-c requires a non-negative CAST id\n");
                return 2;
            }
            single = (int)v;
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

    if ((pct_family != NULL) && !pct_only) {
        fprintf(stderr, "-a selects a PCT family and only applies with -p\n");
        return 2;
    }
    if (pct_only && (single >= 0)) {
        fprintf(stderr, "-c names a CAST id and does not apply with -p\n");
        return 2;
    }
    /* One round of -p costs far more than one CAST, so it defaults lower.
     * An explicit -i still wins. */
    if (pct_only && !iters_set)
        iters = BENCH_PCT_DEFAULT_ITERS;

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

    printf("wolfCrypt FIPS %s benchmark\n", pct_only ? "PCT" : "CAST");
    printf("Library version: %s\n", LIBWOLFSSL_VERSION_STRING);
    printf("FIPS_CAST_COUNT: %d\n", FIPS_CAST_COUNT);
    printf("Iterations per %s: %d\n", pct_only ? "algorithm" : "CAST", iters);
    printf("Clock: %s\n",
#ifdef _WIN32
           "QueryPerformanceCounter"
#else
           "clock_gettime(CLOCK_MONOTONIC)"
#endif
           );
    printf("\n");

    /* The RNG needs a seed source registered before it will start, the same
     * as benchmark.c and wolfcrypt/test/test.c do. */
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

    /* Run every CAST once first, so what we time afterwards is the test
     * itself and not the one-off set-up behind it. */
    {
        int prime_rc = wc_RunAllCast_fips();
        if (prime_rc != 0) {
            fprintf(stderr,
                "wc_RunAllCast_fips() prime returned %d - some CASTs may have failed.\n"
                "Per-CAST measurements continue but failed CASTs will report errors.\n\n",
                prime_rc);
        }
    }

    if (pct_only) {
        int pct_rc = bench_pct(iters, pct_family);
        if (pct_rc != 0)
            return 1;
        return 0;
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

#else /* !(HAVE_FIPS && v7.0.0+ && !WOLFSSL_FIPS_DEV_NO_POST) */

#include <stdio.h>

int main(void)
{
#ifndef HAVE_FIPS
    fprintf(stderr,
            "fips_cast_bench: built without HAVE_FIPS - nothing to measure\n");
#elif defined(WOLFSSL_FIPS_DEV_NO_POST)
    fprintf(stderr,
            "fips_cast_bench: dev-no-post compiles fips.c only into linuxkm, "
            "so the CAST entry points are absent from libwolfssl - "
            "nothing to measure\n");
#else
    fprintf(stderr,
            "fips_cast_bench: requires v7.0.0+ FIPS module "
            "(wc_RunCast_fips / wc_RunAllCast_fips were added in v7) - "
            "nothing to measure on this older module flavor\n");
#endif
    return 0;
}

#endif /* HAVE_FIPS && v7.0.0+ && !WOLFSSL_FIPS_DEV_NO_POST */

