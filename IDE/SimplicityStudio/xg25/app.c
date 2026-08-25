/* app.c
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

/* wolfCrypt test and benchmark entry point for the EFR32xG25. */

#include <stdio.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/version.h>
#ifdef WOLFSSL_XG25_TLS13
    #include <wolfssl/ssl.h>
#endif

#include <sl_se_manager.h>
#include <sl_se_manager_util.h>
#include <sl_sleeptimer.h>

#ifdef WOLFSSL_XG25_TLS13
#include <sys/time.h>
#endif

#ifdef WOLFSSL_XG25_TLS13
/* The kit has no battery-backed real time clock, and newlib's _gettimeofday is
 * a weak stub that fails, so time() returns -1 and every certificate looks
 * not-yet-valid (ASN_BEFORE_DATE_E). Certificate date validation is worth
 * keeping on, so seed a clock from the build date and let the sleep timer
 * advance it.
 *
 * This is adequate for a self-contained demo and nothing more. A device that
 * cannot tell the time cannot tell a valid certificate from an expired one:
 * a real design needs an RTC, a time server, or a provisioned time, and the
 * clock must not be attacker-controlled. */

/* Days from 1970-01-01 to y-m-d, proleptic Gregorian, for y >= 1970. */
static long xg25_days_from_civil(long y, long m, long d)
{
    long era, yoe, doy, doe;

    y -= (m <= 2);
    era = ((y >= 0) ? y : (y - 399)) / 400;
    yoe = y - era * 400;
    doy = (153 * (m + ((m > 2) ? -3 : 9)) + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

/* Seconds since the epoch for __DATE__ ("Mmm dd yyyy"), midnight UTC. Derived
 * from the build so it cannot drift out of the test certificates' validity
 * window the way a hardcoded constant would. */
static long xg25_build_epoch(void)
{
    static const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    const char* bd = __DATE__;
    long mon = 0;
    long day, year;
    int i;

    for (i = 0; i < 12; i++) {
        if (bd[0] == months[i * 3] &&
            bd[1] == months[i * 3 + 1] &&
            bd[2] == months[i * 3 + 2]) {
            mon = i + 1;
            break;
        }
    }
    if (mon == 0) {
        mon = 1;
    }

    day = (bd[4] == ' ') ? (bd[5] - '0')
                         : ((bd[4] - '0') * 10 + (bd[5] - '0'));
    year = (bd[7] - '0') * 1000 + (bd[8] - '0') * 100 +
           (bd[9] - '0') * 10 + (bd[10] - '0');

    return xg25_days_from_civil(year, mon, day) * 86400L;
}

/* Strong override of newlib's weak stub. */
int _gettimeofday(struct timeval* tv, void* tzvp)
{
    (void)tzvp;
    if (tv == NULL) {
        return -1;
    }
    tv->tv_sec = (time_t)(xg25_build_epoch() +
        (long)(sl_sleeptimer_get_tick_count64() /
               sl_sleeptimer_get_timer_frequency()));
    tv->tv_usec = 0;
    return 0;
}
#endif /* WOLFSSL_XG25_TLS13 */

extern int wolfcrypt_test(void* args);
extern int benchmark_test(void* args);
#ifdef WOLFSSL_XG25_TLS13
extern int xg25_tls13_test(void);
#endif

/* The benchmark needs a coarse wall clock. Bench iterations are sized in
 * BENCH_EMBEDDED mode, so a low resolution tick is adequate. */
double current_time(int reset)
{
    (void)reset;
    return (double)sl_sleeptimer_get_tick_count64()
           / (double)sl_sleeptimer_get_timer_frequency();
}

/* Report the Secure Element firmware version and the part's security level, so
 * a captured log says which silicon produced the numbers below it. */
static void print_se_info(void)
{
    sl_se_command_context_t cmd = SL_SE_COMMAND_CONTEXT_INIT;
    uint32_t version = 0;

    if (sl_se_get_se_version(&cmd, &version) == SL_STATUS_OK) {
        printf("SE firmware  : %lu.%lu.%lu\n",
            (unsigned long)((version >> 16) & 0xFF),
            (unsigned long)((version >> 8) & 0xFF),
            (unsigned long)(version & 0xFF));
    }
    else {
        printf("SE firmware  : unavailable\n");
    }

#if defined(_SILICON_LABS_SECURITY_FEATURE) && \
    (_SILICON_LABS_SECURITY_FEATURE == _SILICON_LABS_SECURITY_FEATURE_VAULT)
    printf("Secure Vault : High\n");
#else
    printf("Secure Vault : Mid (SHA-384/512, P-384/521, ChaCha20-Poly1305,\n"
           "               the SE KDFs and wrapped keys run in software)\n");
#endif
}

void app_init(void)
{
    int ret;

    printf("\n\nwolfSSL %s - EFR32xG25 Secure Element crypto callback\n",
        LIBWOLFSSL_VERSION_STRING);
    /* Name the software backend: it is what the benchmark's SW column
     * measures, and what the SE is being compared against. */
#ifdef WOLFSSL_ARMASM
    printf("Software path: Thumb2 assembly (WOLFSSL_ARMASM)\n");
#else
    printf("Software path: C\n");
#endif
    print_se_info();

#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
#endif

    /* In TLS mode the library layer has to be initialised and torn down as a
     * pair: creating a WOLFSSL_CTX takes its own wolfCrypt reference through
     * wolfSSL_Init(), so a lone wolfCrypt_Cleanup() would leave the TLS
     * globals and one SE callback registration outstanding at exit. */
#ifdef WOLFSSL_XG25_TLS13
    ret = wolfSSL_Init();
    if (ret != WOLFSSL_SUCCESS) {
        printf("wolfSSL_Init failed: %d\n", ret);
        return;
    }
    ret = 0;
#else
    ret = wolfCrypt_Init();
#endif
    if (ret != 0) {
        printf("wolfCrypt_Init failed: %d\n", ret);
        return;
    }

    printf("\n--- wolfCrypt test ---\n");
    ret = wolfcrypt_test(NULL);
    printf("wolfcrypt_test returned %d (%s)\n", ret,
        (ret == 0) ? "PASS" : "FAIL");

#ifdef WOLFSSL_XG25_TLS13
    printf("\n--- TLS 1.3 over the Secure Element ---\n");
    ret = xg25_tls13_test();
    printf("tls13_test returned %d (%s)\n", ret, (ret == 0) ? "PASS" : "FAIL");
#endif

    printf("\n--- wolfCrypt benchmark ---\n");
    printf("Rows marked HW run on the Secure Element, SW in software.\n");
    ret = benchmark_test(NULL);
    printf("benchmark_test returned %d\n", ret);

#ifdef WOLFSSL_XG25_TLS13
    wolfSSL_Cleanup();
#else
    wolfCrypt_Cleanup();
#endif
    printf("\n--- done ---\n");
}

void app_process_action(void)
{
}
