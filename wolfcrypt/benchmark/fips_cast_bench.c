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
 * in the wolfCrypt v7.0.0 FIPS module, so operators can budget power-on
 * latency on constrained OEs.
 *
 * Citations:
 *   FIPS 140-3 sec 7.10 (Self-Tests) - CAST framework
 *   FIPS 140-3 IG 10.3.A             - Algorithm-by-algorithm CAST coverage
 *   ISO/IEC 19790:2012 sec 7.10.2    - Conditional self-test execution
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
/* Bounds -i.  Keeps iters * sizeof(long long) well inside size_t on a
 * 32-bit target, where SIZE_MAX/8 is about 2.68e8, and is far above any
 * useful benchmark run. */
#define BENCH_MAX_ITERS     1000000

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


/* --------------------------------------------------------------- PCT ---
 *
 * The table above measures wc_RunCast_fips(), the per-algorithm Known Answer
 * Test.  A CAST runs once per algorithm; a Pairwise Consistency Test runs on
 * EVERY key generation, so its cost is paid by the application for the life
 * of the process and does not appear anywhere in the CAST numbers.
 *
 * FIPS 140-3 IG 10.3.A Additional Comment 1 (TE10.35.01 for a KEM,
 * TE10.35.02 for a signature) / ISO/IEC 19790:2012 sec 7.10.3.3.
 *
 * Three quantities per algorithm:
 *
 *   KeyGen+PCT  the generation call as the module ships it.  The PCT is
 *               unconditional inside that call, so this is what a caller
 *               actually pays.  MEASURED.
 *   PCT alone   the same operations the module's PCT performs, run again on
 *               the key that generation produced.  MEASURED.
 *   KeyGen raw  KeyGen+PCT minus PCT alone.  DERIVED, and labelled as such
 *               in the header: no build of this module generates a key
 *               without running the PCT, so there is nothing to measure.
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

/* Largest n (security parameter) over the FIPS 205 parameter sets, which is
 * 32 for the category 5 sets.  Checked against the key at run time rather
 * than assumed, so a parameter set with a larger n is skipped with a message
 * instead of overflowing the seed buffers. */
#define BENCH_SLHDSA_MAX_N 32

/* KeyGen raw is KeyGen+PCT minus PCT alone, so it is positive only while the
 * PCT really is inside the generation call.  Compiling the SLH-DSA PCT out
 * and re-running took KeyGen raw for SHAKE-128s from +54.8 ms to -365.5 ms,
 * which is how this test was calibrated.  Noise cannot produce that: the
 * margin below asks for a deficit worth more than a twentieth of the PCT
 * before it says anything.
 *
 * Returns 1 when key generation does not appear to run the PCT. */
static int pct_missing(double raw_ms, double pct_ms)
{
    return (raw_ms < 0.0) && ((-raw_ms) > (pct_ms * 0.05));
}

#ifdef BENCH_HAVE_PCT_TABLE
static void pct_hdr(const char* title, const char* what)
{
    printf("%s\n", title);
    printf("  PCT = %s\n", what);
    printf("Alg             | KeyGen+PCT | PCT alone  | KeyGen raw | PCT share\n");
    printf("                |       (ms) |       (ms) | (ms) DERIV |       (%%)\n");
    printf("----------------+------------+------------+------------+----------\n");
}

/* Returns 1 when the row shows the PCT missing from key generation. */
static int pct_row(const char* name, long long kg_ns, long long pct_ns,
                   int iters)
{
    double kg    = (double)kg_ns  / (double)iters / 1.0e6;
    double pct   = (double)pct_ns / (double)iters / 1.0e6;
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
/* ML-KEM PCT: encapsulate with ek, decapsulate with dk, compare the two
 * shared secrets.  Mirrors the block in wc_mlkem.c, including the fixed `m`,
 * so the measurement is of the same work and not of a different round trip. */
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
        long long kg_ns = 0;
        long long pct_ns = 0;
        int       i;
        int       rc;

        rc = wc_MlKemKey_Init(&key, types[t], NULL, INVALID_DEVID);
        if (rc != 0) {
            pct_skip(names[t], rc);
            continue;
        }

        for (i = 0; i < iters; i++) {
            long long t0;
            long long t1;
            word32    ctSz = 0;

            /* Different key material each iteration, so no measurement here
             * can be a repeat of byte-identical work. */
            kgrand[0] = (byte)i;

            t0 = now_ns();
            rc = wc_MlKemKey_MakeKeyWithRandom(&key, kgrand,
                    (int)sizeof(kgrand));
            t1 = now_ns();
            if (rc != 0)
                break;
            kg_ns += t1 - t0;

            t0 = now_ns();
            rc = wc_MlKemKey_CipherTextSize(&key, &ctSz);
            if (rc == 0) {
                rc = wc_MlKemKey_EncapsulateWithRandom(&key, ct, ss1, pct_m,
                        (int)sizeof(pct_m));
            }
            if (rc == 0)
                rc = wc_MlKemKey_Decapsulate(&key, ss2, ct, ctSz);
            if ((rc == 0) && (XMEMCMP(ss1, ss2, WC_ML_KEM_SS_SZ) != 0))
                rc = ML_KEM_PCT_E;
            t1 = now_ns();
            if (rc != 0)
                break;
            pct_ns += t1 - t0;
        }

        if (rc != 0) {
            pct_fail(names[t], rc);
            failures++;
        }
        else {
            failures += pct_row(names[t], kg_ns, pct_ns, iters);
        }
        wc_MlKemKey_Free(&key);
    }

    /* Fixed-seed test material, not live key material, but leaving a shared
     * secret on the stack of a FIPS benchmark reads badly and costs nothing
     * to avoid. */
    XMEMSET(ss1, 0, sizeof(ss1));
    XMEMSET(ss2, 0, sizeof(ss2));
    XFREE(ct, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    printf("\n");
    return failures;
}
#endif /* WOLFSSL_HAVE_MLKEM */


#ifdef WOLFSSL_HAVE_MLDSA
/* ML-DSA PCT: sign with the new sk, verify with the matching pk.  Mirrors
 * mldsa_pct() in wc_mldsa.c, same message and same all-zero rnd, so the
 * deterministic-signing path measured here is the one the module runs. */
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
        long long   kg_ns = 0;
        long long   pct_ns = 0;
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
            long long t0;
            long long t1;
            word32    sigSz = MLDSA_MAX_SIG_SIZE;
            int       res = 0;

            seed[0] = (byte)i;

            t0 = now_ns();
            rc = wc_MlDsaKey_MakeKeyFromSeed(&key, seed);
            t1 = now_ns();
            if (rc != 0)
                break;
            kg_ns += t1 - t0;

            t0 = now_ns();
            rc = wc_MlDsaKey_SignCtxWithSeed(&key, NULL, 0, sig, &sigSz,
                    pct_msg, (word32)sizeof(pct_msg), pct_seed);
            if (rc == 0) {
                rc = wc_MlDsaKey_VerifyCtx(&key, sig, sigSz, NULL, 0, pct_msg,
                        (word32)sizeof(pct_msg), &res);
            }
            if ((rc == 0) && (res != 1))
                rc = ML_DSA_PCT_E;
            t1 = now_ns();
            if (rc != 0)
                break;
            pct_ns += t1 - t0;
        }

        if (rc != 0) {
            pct_fail(names[t], rc);
            failures++;
        }
        else {
            failures += pct_row(names[t], kg_ns, pct_ns, iters);
        }
        wc_MlDsaKey_Free(&key);
    }

    XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    printf("\n");
    return failures;
}
#endif /* WOLFSSL_HAVE_MLDSA */


#ifdef WOLFSSL_HAVE_SLHDSA
/* SLH-DSA is the one where the choice of PCT is open, so three candidates are
 * timed side by side.  What each one proves is spelled out by
 * bench_pct_slhdsa_notes() below; read that before using the numbers. */
static void bench_pct_slhdsa_notes(void)
{
    printf(
"A  sign + verify.  What wc_SlhDsaKey_MakeKeyWithRandom() does today.\n"
"B  recompute PK.root from SK.seed and compare it with the stored root -- what\n"
"   wc_SlhDsaKey_CheckKey() already implements.  Its cost is the raw key\n"
"   generation, because for SLH-DSA generating the key IS computing PK.root,\n"
"   so column B is the KeyGen raw figure rather than a second measurement of\n"
"   the same work.\n"
"C  compare PK.SEED between the public and the private key -- the relaxation\n"
"   FIPS 140-3 IG 10.3.A Additional Comment 1 permits for SLH-DSA.\n"
"   VACUOUS IN THIS IMPLEMENTATION, and the number below must not be read as\n"
"   an option.  SlhDsaKey holds a single buffer, sk = SK.seed | SK.prf |\n"
"   PK.seed | PK.root; wc_SlhDsaKey_ExportPrivate() returns sk and\n"
"   wc_SlhDsaKey_ExportPublic() returns sk + 2n.  The two copies of PK.seed\n"
"   are the same bytes, so the comparison cannot fail and detects nothing.\n"
"   It is timed only to show it was measured rather than assumed.\n");
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
    byte   priv[BENCH_SLHDSA_MAX_N * 4];
    byte   pub[BENCH_SLHDSA_MAX_N * 2];
    int    failures = 0;
    size_t t;

    printf("SLH-DSA (FIPS 205)\n");
    printf("Param           | KeyGen+A | A sign+vfy | KeyGen raw"
           " | B root recomp | C PK.seed\n");
    printf("                |     (ms) |       (ms) | (ms) DERIV"
           " |    (ms) DERIV |      (ms)\n");
    printf("----------------+----------+------------+-----------"
           "-+---------------+----------\n");

    for (t = 0; t < sizeof(params) / sizeof(params[0]); t++) {
        SlhDsaKey key;
        long long kg_ns = 0;
        long long a_ns = 0;
        long long c_ns = 0;
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
            long long t0;
            long long t1;
            word32    sigSz = (word32)sigLen;
            word32    pl = (word32)privLen;
            word32    ul = (word32)(n * 2);

            XMEMSET(sk_seed, (byte)(0x11 + i), (size_t)n);
            XMEMSET(sk_prf,  (byte)(0x22 + i), (size_t)n);
            XMEMSET(pk_seed, (byte)(0x33 + i), (size_t)n);

            t0 = now_ns();
            rc = wc_SlhDsaKey_MakeKeyWithRandom(&key, sk_seed, (word32)n,
                    sk_prf, (word32)n, pk_seed, (word32)n);
            t1 = now_ns();
            if (rc != 0)
                break;
            kg_ns += t1 - t0;

            /* Option A, as the module runs it now. */
            t0 = now_ns();
            rc = wc_SlhDsaKey_SignDeterministic(&key, NULL, 0, pct_msg,
                    (word32)sizeof(pct_msg), sig, &sigSz);
            if (rc == 0) {
                rc = wc_SlhDsaKey_Verify(&key, NULL, 0, pct_msg,
                        (word32)sizeof(pct_msg), sig, sigSz);
            }
            t1 = now_ns();
            if (rc != 0)
                break;
            a_ns += t1 - t0;

            /* Option C, the IG relaxation.  See bench_pct_slhdsa_notes(). */
            t0 = now_ns();
            rc = wc_SlhDsaKey_ExportPrivate(&key, priv, &pl);
            if (rc == 0)
                rc = wc_SlhDsaKey_ExportPublic(&key, pub, &ul);
            if ((rc == 0) &&
                    (XMEMCMP(priv + (size_t)(n * 2), pub, (size_t)n) != 0)) {
                rc = SLH_DSA_PCT_E;
            }
            t1 = now_ns();
            if (rc != 0)
                break;
            c_ns += t1 - t0;
        }

        if (rc != 0) {
            pct_fail(names[t], rc);
            failures++;
        }
        else {
            double kg  = (double)kg_ns / (double)iters / 1.0e6;
            double a   = (double)a_ns  / (double)iters / 1.0e6;
            double c   = (double)c_ns  / (double)iters / 1.0e6;
            double raw = kg - a;

            printf("%-15s | %8.3f | %10.3f | %10.3f | %13.3f | %9.4f%s\n",
                   names[t], kg, a, raw, raw, c,
                   pct_missing(raw, a) ? "   PCT NOT IN KEYGEN" : "");
            failures += pct_missing(raw, a);
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

#ifndef BENCH_HAVE_PCT
    (void)iters;
#endif

    /* The replicas below drive private-key operations through the public API
     * -- ML-KEM decapsulate, ML-DSA and SLH-DSA sign, SLH-DSA ExportPrivate.
     * In a FIPS build those are gated by the private-key lock
     * (PRIVATE_KEY_UNLOCK, types.h), and without this they return -287.  The
     * module's own PCTs run inside the boundary and never meet that gate, so
     * the unlock is taken here, outside every timed region, rather than
     * charging a PCT for a check it does not actually pay. */
#ifdef BENCH_HAVE_PCT
    PRIVATE_KEY_UNLOCK();
#endif

    printf("KeyGen+PCT and PCT alone are MEASURED; KeyGen raw is DERIVED as\n"
           "the difference, because no build of this module generates a key\n"
           "without running the PCT.\n\n");

#ifdef WOLFSSL_HAVE_MLKEM
    if ((only == NULL) || (XSTRCMP(only, "mlkem") == 0)) {
        failures += bench_pct_mlkem(iters);
        ran++;
    }
#endif
#ifdef WOLFSSL_HAVE_MLDSA
    if ((only == NULL) || (XSTRCMP(only, "mldsa") == 0)) {
        failures += bench_pct_mldsa(iters);
        ran++;
    }
#endif
#ifdef WOLFSSL_HAVE_SLHDSA
    if ((only == NULL) || (XSTRCMP(only, "slhdsa") == 0)) {
        failures += bench_pct_slhdsa(iters);
        ran++;
    }
#endif

    /* Selecting a family that this build does not have would otherwise print
     * a header and nothing else, which reads as "measured, no cost". */
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

/* atoi() is undefined on a value too large for an int, and the truncation glibc
 * actually performs lands inside the range checks below: "-i 4294967297" ran 1
 * iteration and "-c 4294967296" ran CAST 0, both without complaint. Parse with
 * strtol() so trailing garbage and out-of-range values are rejected instead.
 * Returns 0 and stores the value on success, -1 on any bad input. */
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
            /* Upper bound as well as lower: run_one_cast() allocates
             * iters * sizeof(long long), and on a 32-bit size_t an iters above
             * SIZE_MAX/8 wraps that product, yielding a short buffer and an
             * out-of-bounds write in the sample loop. */
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
    /* The PCT families are far more expensive per iteration than a CAST --
     * an SLH-DSA 's' key generation is seconds, not milliseconds -- so -p
     * defaults lower.  An explicit -i still wins. */
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

    /* Under WC_RNG_SEED_CB the RNG needs a seed generator before _InitRng can
     * build a working DRBG (mirrors benchmark.c and wolfcrypt/test/test.c). */
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

    /* Prime every CAST once so each reaches FIPS_CAST_STATE_SUCCESS before
     * measuring, isolating KAT runtime from the cold-CAST init chain. */
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

