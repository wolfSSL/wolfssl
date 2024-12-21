/* benchmark.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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


/* wolfCrypt benchmark */

/* Some common, optional build settings:
 * these can also be set in wolfssl/options.h or user_settings.h
 * -------------------------------------------------------------
 * make the binary always use CSV format:
 * WOLFSSL_BENCHMARK_FIXED_CSV
 *
 * choose to use the same units, regardless of scale. pick 1:
 * WOLFSSL_BENCHMARK_FIXED_UNITS_GB
 * WOLFSSL_BENCHMARK_FIXED_UNITS_MB
 * WOLFSSL_BENCHMARK_FIXED_UNITS_KB
 * WOLFSSL_BENCHMARK_FIXED_UNITS_B
 *
 * when the output should be in machine-parseable format:
 * GENERATE_MACHINE_PARSEABLE_REPORT
 *
 * use microseconds as the unit of time:
 * BENCH_MICROSECOND
 *
 * display mean, max, min and sd of operation durations:
 * MULTI_VALUE_STATISTICS
 *
 * Enable tracking of the stats into an allocated linked list:
 * (use -print to display results):
 * WC_BENCH_TRACK_STATS
 *
 * set the default devId for cryptocb to the value instead of INVALID_DEVID
 * WC_USE_DEVID=0x1234
 *
 * Turn on benchmark timing debugging (CPU Cycles, RTOS ticks, etc)
 * DEBUG_WOLFSSL_BENCHMARK_TIMING
 *
 * Turn on timer debugging (used when CPU cycles not available)
 * WOLFSSL_BENCHMARK_TIMER_DEBUG
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#if !defined(WOLFSSL_USER_SETTINGS) && !defined(WOLFSSL_NO_OPTIONS_H)
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h> /* also picks up user_settings.h */

/* Macro to disable benchmark */
#ifndef NO_CRYPT_BENCHMARK

#define WC_ALLOC_DO_ON_FAILURE() do { printf("out of memory at benchmark.c L %d\n", __LINE__); ret = MEMORY_E; goto exit; } while (0)

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/wolfmath.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/version.h>

#ifdef WOLFSSL_LINUXKM
    /* remap current_time() -- collides with a function in kernel linux/fs.h */
    #define current_time benchmark_current_time
#endif /* WOLFSSL_LINUXKM */

#ifdef HAVE_CHACHA
    #include <wolfssl/wolfcrypt/chacha.h>
#endif
#ifdef HAVE_POLY1305
    #include <wolfssl/wolfcrypt/poly1305.h>
#endif
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    #include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#endif
#ifndef NO_AES
    #include <wolfssl/wolfcrypt/aes.h>
#endif
#ifdef HAVE_CAMELLIA
    #include <wolfssl/wolfcrypt/camellia.h>
#endif
#ifdef WOLFSSL_SM4
    #include <wolfssl/wolfcrypt/sm4.h>
#endif
#ifndef NO_MD5
    #include <wolfssl/wolfcrypt/md5.h>
#endif
#ifndef NO_SHA
    #include <wolfssl/wolfcrypt/sha.h>
#endif
#ifndef NO_SHA256
    #include <wolfssl/wolfcrypt/sha256.h>
#endif
#if defined(WOLFSSL_SHA512) || defined(WOLFSSL_SHA384)
    #include <wolfssl/wolfcrypt/sha512.h>
#endif
#ifdef WOLFSSL_SHA3
    #include <wolfssl/wolfcrypt/sha3.h>
#endif
#ifdef WOLFSSL_SM3
     #include <wolfssl/wolfcrypt/sm3.h>
#endif
#ifndef NO_RSA
    #include <wolfssl/wolfcrypt/rsa.h>
#endif
#ifdef WOLFSSL_RIPEMD
    #include <wolfssl/wolfcrypt/ripemd.h>
#endif
#ifdef WOLFSSL_CMAC
    #include <wolfssl/wolfcrypt/cmac.h>
#endif
#ifndef NO_DH
    #include <wolfssl/wolfcrypt/dh.h>
#endif
#ifndef NO_DES3
    #include <wolfssl/wolfcrypt/des3.h>
#endif
#ifndef NO_RC4
    #include <wolfssl/wolfcrypt/arc4.h>
#endif
#ifndef NO_HMAC
    #include <wolfssl/wolfcrypt/hmac.h>
#endif
#ifdef WOLFSSL_SIPHASH
    #include <wolfssl/wolfcrypt/siphash.h>
#endif
  #include <wolfssl/wolfcrypt/kdf.h>
#ifndef NO_PWDBASED
    #include <wolfssl/wolfcrypt/pwdbased.h>
#endif
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifdef WOLFSSL_SM2
    #include <wolfssl/wolfcrypt/sm2.h>
#endif
#ifdef HAVE_CURVE25519
    #include <wolfssl/wolfcrypt/curve25519.h>
#endif
#ifdef HAVE_ED25519
    #include <wolfssl/wolfcrypt/ed25519.h>
#endif
#ifdef HAVE_CURVE448
    #include <wolfssl/wolfcrypt/curve448.h>
#endif
#ifdef HAVE_ED448
    #include <wolfssl/wolfcrypt/ed448.h>
#endif
#ifdef WOLFSSL_HAVE_KYBER
    #include <wolfssl/wolfcrypt/kyber.h>
    #ifdef WOLFSSL_WC_KYBER
        #include <wolfssl/wolfcrypt/wc_kyber.h>
    #endif
    #if defined(HAVE_LIBOQS)
        #include <wolfssl/wolfcrypt/ext_kyber.h>
    #endif
#endif
#if defined(WOLFSSL_HAVE_LMS) && !defined(WOLFSSL_LMS_VERIFY_ONLY)
    #include <wolfssl/wolfcrypt/lms.h>
    #ifdef HAVE_LIBLMS
        #include <wolfssl/wolfcrypt/ext_lms.h>
    #else
        #include <wolfssl/wolfcrypt/wc_lms.h>
    #endif
#endif
#if defined(WOLFSSL_HAVE_XMSS) && !defined(WOLFSSL_XMSS_VERIFY_ONLY)
    #include <wolfssl/wolfcrypt/xmss.h>
    #ifdef HAVE_LIBXMSS
        #include <wolfssl/wolfcrypt/ext_xmss.h>
    #else
        #include <wolfssl/wolfcrypt/wc_xmss.h>
    #endif
#endif
#ifdef WOLFCRYPT_HAVE_ECCSI
    #include <wolfssl/wolfcrypt/eccsi.h>
#endif
#ifdef WOLFCRYPT_HAVE_SAKKE
    #include <wolfssl/wolfcrypt/sakke.h>
#endif

#if defined(HAVE_FALCON)
    #include <wolfssl/wolfcrypt/falcon.h>
#endif
#if defined(HAVE_DILITHIUM)
    #include <wolfssl/wolfcrypt/dilithium.h>
#endif
#if defined(HAVE_SPHINCS)
    #include <wolfssl/wolfcrypt/sphincs.h>
#endif

#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
    #ifdef HAVE_INTEL_QA_SYNC
        #include <wolfssl/wolfcrypt/port/intel/quickassist_sync.h>
    #endif
    #ifdef HAVE_CAVIUM_OCTEON_SYNC
        #include <wolfssl/wolfcrypt/port/cavium/cavium_octeon_sync.h>
    #endif
    #ifdef HAVE_RENESAS_SYNC
        #include <wolfssl/wolfcrypt/port/renesas/renesas_sync.h>
    #endif
    #if defined(WOLFSSL_MAX3266X) || defined(WOLFSSL_MAX3266X_OLD)
        #include <wolfssl/wolfcrypt/port/maxim/max3266x-cryptocb.h>
    #endif
#endif

#ifdef WOLFSSL_ASYNC_CRYPT
    #include <wolfssl/wolfcrypt/async.h>
#endif

#include <wolfssl/wolfcrypt/cpuid.h>

#ifdef USE_FLAT_BENCHMARK_H
    #include "benchmark.h"
#else
    #include "wolfcrypt/benchmark/benchmark.h"
#endif

/* define the max length for each string of metric reported */
#ifndef WC_BENCH_MAX_LINE_LEN
#define WC_BENCH_MAX_LINE_LEN 150
#endif

/* default units per second. See WOLFSSL_BENCHMARK_FIXED_UNITS_* to change */
#define WOLFSSL_FIXED_UNIT "MB" /* may be re-set by fixed units */
#define MILLION_VALUE 1000000.0

#ifdef BENCH_MICROSECOND
    #define WOLFSSL_FIXED_TIME_UNIT "μs"
    #define WOLFSSL_BENCHMARK_FIXED_UNITS_KB
#else
    #define WOLFSSL_FIXED_TIME_UNIT "s"
#endif

#ifdef MULTI_VALUE_STATISTICS
    #define STATS_CLAUSE_SEPARATOR ""
    #define DECLARE_MULTI_VALUE_STATS_VARS() double max = 0, min = 0, sum = 0,\
                                         squareSum = 0, prev = 0, delta;\
                                         int    runs = 0;
    #define RECORD_MULTI_VALUE_STATS()  if (runs == 0) {\
                                            delta = current_time(0) - start;\
                                            min = delta;\
                                            max = delta;\
                                        }\
                                        else {\
                                            delta = current_time(0) - prev;\
                                        }\
                                        if (max < delta)\
                                            max = delta;\
                                        else if (min > delta)\
                                            min = delta;\
                                        sum += delta;\
                                        squareSum += delta * delta;\
                                        runs++;\
                                        prev = current_time(0)
    #define RESET_MULTI_VALUE_STATS_VARS()   prev = 0;\
                                        runs = 0;\
                                        sum  = 0;\
                                        squareSum = 0
#else
    #define STATS_CLAUSE_SEPARATOR "\n"
    #define DECLARE_MULTI_VALUE_STATS_VARS()
    #define RECORD_MULTI_VALUE_STATS()  WC_DO_NOTHING
    #define RESET_MULTI_VALUE_STATS_VARS()   WC_DO_NOTHING
#endif

#ifdef WOLFSSL_NO_FLOAT_FMT
    #define FLT_FMT "%0ld,%09lu"
    #define FLT_FMT_PREC "%0ld.%0*lu"
    #define FLT_FMT_PREC2 FLT_FMT_PREC
    #define FLT_FMT_ARGS(x) (long)(x), ((x) < 0) ?                        \
        (unsigned long)(-(((x) - (double)(long)(x)) * 1000000000.0)) :    \
        (unsigned long)(((x) - (double)(long)(x)) * 1000000000.0)
    static const double pow_10_array[] = { 0.0, 1.0, 10.0, 100.0, 1000.0, \
                                           10000.0, 100000.0, 1000000.0,  \
                                           10000000.0, 100000000.0,       \
                                           1000000000.0 };
    #define FLT_FMT_PREC_ARGS(p, x) \
            (long)(x), \
                p, \
            (x) >= 0.0 ?                                                  \
                (unsigned long int)((((x) - (double)(long)(x)) *          \
                                     pow_10_array[(p)+1]) + 0.5) :        \
                (unsigned long int)((((-(x)) - (double)((long)-(x))) *    \
                                     pow_10_array[(p)+1]) + 0.5)
    #define FLT_FMT_PREC2_ARGS(w, p, x) FLT_FMT_PREC_ARGS(p, x)
#else
    #define FLT_FMT "%f"
    #define FLT_FMT_PREC "%.*f"
    #define FLT_FMT_PREC2 "%*.*f"
    #define FLT_FMT_ARGS(x) x
    #define FLT_FMT_PREC_ARGS(p, x) p, x
    #define FLT_FMT_PREC2_ARGS(w, p, x) w, p, x
#endif /* WOLFSSL_NO_FLOAT_FMT */

#ifdef WOLFSSL_ESPIDF
    #include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>

    /* Benchmark uses 64 bit integer formatting support. When new nanolib is
     * enabled, all if the values in report are blank. */
    #ifdef CONFIG_NEWLIB_NANO_FORMAT
        #if CONFIG_NEWLIB_NANO_FORMAT == 1
            #error "Nano newlib formatting must not be enabled for benchmark"
        #endif
    #endif
    #if ESP_IDF_VERSION_MAJOR >= 5
        #define TFMT "%lu"
    #else
        #define TFMT "%d"
    #endif

    #ifdef configTICK_RATE_HZ
        /* Define CPU clock cycles per tick of FreeRTOS clock
         *   CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ is typically a value like 240
         *   configTICK_RATE_HZ is typically 100 or 1000.
         **/
        #if defined(CONFIG_IDF_TARGET_ESP8266)
            #ifndef CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ
                #define CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ \
                        CONFIG_ESP8266_DEFAULT_CPU_FREQ_MHZ
            #endif
            #ifndef CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ
                #define CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ configCPU_CLOCK_HZ
            #endif
        #endif
        #ifndef CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ
            /* This section is for pre-v5 ESP-IDF */
            #if defined(CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ)
                #define CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ \
                        CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ
            #elif defined(CONFIG_ESP32C2_DEFAULT_CPU_FREQ_MHZ)
                #define CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ \
                        CONFIG_ESP32C2_DEFAULT_CPU_FREQ_MHZ
            #elif defined(CONFIG_ESP32S2_DEFAULT_CPU_FREQ_MHZ)
                #define CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ \
                        CONFIG_ESP32S2_DEFAULT_CPU_FREQ_MHZ
            #elif defined(CONFIG_ESP32S3_DEFAULT_CPU_FREQ_MHZ)
                #define CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ \
                        CONFIG_ESP32S3_DEFAULT_CPU_FREQ_MHZ
            #elif defined(CONFIG_ESP32H2_DEFAULT_CPU_FREQ_MHZ)
                #define CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ \
                        CONFIG_ESP32H2_DEFAULT_CPU_FREQ_MHZ
            #else
                /* TODO unsupported */
            #endif /* older CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ */
        #endif
        #define CPU_TICK_CYCLES (                               \
              (CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ * MILLION_VALUE) \
              / configTICK_RATE_HZ                              \
            )
    #endif /* WOLFSSL_ESPIDF configTICK_RATE_HZ */

    #if defined(CONFIG_IDF_TARGET_ESP32C2)
        #include "driver/gptimer.h"
        static gptimer_handle_t esp_gptimer = NULL;
        static gptimer_config_t esp_timer_config = {
                            .clk_src = GPTIMER_CLK_SRC_DEFAULT,
                            .direction = GPTIMER_COUNT_UP,
                            .resolution_hz = CONFIG_XTAL_FREQ * 100000,
                         };
    #elif defined(CONFIG_IDF_TARGET_ESP32C3) || \
          defined(CONFIG_IDF_TARGET_ESP32C6)
        #include <esp_cpu.h>
        #if ESP_IDF_VERSION_MAJOR >= 5
            #include <driver/gptimer.h>
        #endif
        #ifdef WOLFSSL_BENCHMARK_TIMER_DEBUG
            #define RESOLUTION_SCALE 100
            /* CONFIG_XTAL_FREQ = 40, CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ = 160  */
            static gptimer_handle_t esp_gptimer = NULL;
            static gptimer_config_t esp_timer_config = {
                .clk_src = GPTIMER_CLK_SRC_DEFAULT,
                .direction = GPTIMER_COUNT_UP,
                /* CONFIG_XTAL_FREQ = 40,
                 * CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ = 160  */
                .resolution_hz = CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ *
                                 (MILLION_VALUE / RESOLUTION_SCALE),
                };
        #endif /* WOLFSSL_BENCHMARK_TIMER_DEBUG */

    #elif defined(CONFIG_IDF_TARGET_ESP32) || \
          defined(CONFIG_IDF_TARGET_ESP32S2) || \
          defined(CONFIG_IDF_TARGET_ESP32S3)
        #include <xtensa/hal.h>
    #elif defined(CONFIG_IDF_TARGET_ESP8266)
        /* no CPU HAL for ESP8266, we'll use RTOS tick calc estimates */
        #include <FreeRTOS.h>
        #include <esp_system.h>
        #include <esp_timer.h>
        #include <xtensa/hal.h>
    #elif defined(CONFIG_IDF_TARGET_ESP32H2)
        /* TODO add ESP32-H2 benchmark support */
    #else
        /* Other platform */
    #endif
    #include <esp_log.h>
#endif /* WOLFSSL_ESPIDF */

#if defined(HAVE_PTHREAD) ||                                          \
    (!defined(NO_CRYPT_BENCHMARK) && !defined(NO_STDIO_FILESYSTEM) && \
     !defined(NO_ERROR_STRINGS) && !defined(NO_MAIN_DRIVER) &&        \
     !defined(BENCH_EMBEDDED))
    #include <errno.h>
    #if !defined(WOLFSSL_ZEPHYR) && !defined(_WIN32)
        #include <unistd.h>
    #endif
#endif

#if defined(WOLFSSL_ZEPHYR) || defined(NO_STDIO_FILESYSTEM) || !defined(XFFLUSH)
    /* fflush in Zephyr doesn't work on stdout and stderr. Use
    * CONFIG_LOG_MODE_IMMEDIATE compilation option instead. */
    #undef  XFFLUSH
    #define XFFLUSH(...) WC_DO_NOTHING
#endif

/* only for stack size check */
#include <wolfssl/wolfcrypt/mem_track.h>

#if defined(WOLFSSL_ASYNC_CRYPT) && !defined(WC_NO_ASYNC_THREADING)
    #define WC_ENABLE_BENCH_THREADING
#endif
/* enable tracking of stats for threaded benchmark */
#if defined(WC_ENABLE_BENCH_THREADING) && !defined(WC_BENCH_TRACK_STATS)
    #define WC_BENCH_TRACK_STATS
#endif

#ifdef GENERATE_MACHINE_PARSEABLE_REPORT
    static const char info_prefix[] = "###, ";
    static const char err_prefix[] = "!!!, ";
#else
    static const char info_prefix[] = "";
    static const char err_prefix[] = "";
#endif


/* printf mappings */
#ifdef FREESCALE_MQX
    #include <mqx.h>
    /* see wc_port.h for fio.h and nio.h includes */
#elif defined(FREESCALE_KSDK_1_3)
    #include "fsl_debug_console.h"
    #include "fsl_os_abstraction.h"

    #undef printf
    #define printf PRINTF
#elif defined(WOLFSSL_DEOS)
    #include <deos.h>
    #include <printx.h>
    #undef printf
    #define printf printx
#elif defined(MICRIUM)
    #if (OS_VERSION < 50000)
        #include <bsp_ser.h>
        void BSP_Ser_Printf (CPU_CHAR* format, ...);
        #undef printf
        #define printf BSP_Ser_Printf
    #endif
#elif defined(WOLFSSL_ZEPHYR)
    #include <stdio.h>
    #include <stdarg.h>
    #define BENCH_EMBEDDED
    #define printf printfk
    static int printfk(const char *fmt, ...)
    {
        int ret;
        char line[WC_BENCH_MAX_LINE_LEN];
        va_list ap;

        va_start(ap, fmt);

        ret = vsnprintf(line, sizeof(line), fmt, ap);
        line[sizeof(line)-1] = '\0';
        printk("%s", line);

        va_end(ap);

        return ret;
    }

#elif defined(WOLFSSL_TELIT_M2MB)
    #include <stdarg.h>
    #include <stdio.h>
    #include <string.h>
    #include "m2m_log.h" /* for M2M_LOG_INFO - not standard API */
    /* remap printf */
    #undef printf
    #define printf M2M_LOG_INFO
    /* OS requires occasional sleep() */
    #ifndef TEST_SLEEP_MS
        #define TEST_SLEEP_MS 50
    #endif
    #define TEST_SLEEP() m2mb_os_taskSleep(M2MB_OS_MS2TICKS(TEST_SLEEP_MS))
    /* don't use file system for these tests, since ./certs dir isn't loaded */
    #undef  NO_FILESYSTEM
    #define NO_FILESYSTEM

/* ANDROID_V454 (for android studio) displays information in a textview
 * and redirects printf to the textview output instead of using
 * __android_log_print() */
#elif defined(ANDROID) && !defined(ANDROID_V454)
    #ifdef XMALLOC_USER
        #include <stdlib.h>  /* we're using malloc / free direct here */
    #endif
    #ifndef STRING_USER
        #include <stdio.h>
    #endif
    #include <android/log.h>

    #define printf(...)       \
             __android_log_print(ANDROID_LOG_DEBUG, "[WOLFCRYPT]", __VA_ARGS__)
    #define fprintf(fp, ...)  \
             __android_log_print(ANDROID_LOG_DEBUG, "[WOLFCRYPT]", __VA_ARGS__)

#else
    #if defined(XMALLOC_USER) || defined(FREESCALE_MQX)
        /* MQX classic needs for EXIT_FAILURE */
        #include <stdlib.h>  /* we're using malloc / free direct here */
    #endif

    #if !defined(STRING_USER) && !defined(NO_STDIO_FILESYSTEM)
        #include <string.h>
        #include <stdio.h>
    #endif

    /* enable way for customer to override test/bench printf */
    #ifdef XPRINTF
        #undef  printf
        #define printf XPRINTF
    #elif defined(NETOS)
        #undef printf
        #define printf dc_log_printf
    #endif
#endif

#ifdef HAVE_FIPS
    #include <wolfssl/wolfcrypt/fips_test.h>

    static void myFipsCb(int ok, int err, const char* hash)
    {
        printf("%sin my Fips callback, ok = %d, err = %d\n",
               ok ? info_prefix : err_prefix, ok, err);
        printf("%smessage = %s\n", ok ? info_prefix : err_prefix,
               wc_GetErrorString(err));
        printf("%shash = %s\n", ok ? info_prefix : err_prefix, hash);

        if (err == WC_NO_ERR_TRACE(IN_CORE_FIPS_E)) {
            printf("%sIn core integrity hash check failure, copy above hash\n",
                   err_prefix);
            printf("%sinto verifyCore[] in fips_test.c and rebuild\n",
                   err_prefix);
        }
    }
#endif

#ifdef WOLFSSL_STATIC_MEMORY
    static WOLFSSL_HEAP_HINT* HEAP_HINT;
#else
    #define HEAP_HINT NULL
#endif /* WOLFSSL_STATIC_MEMORY */

#ifndef EXIT_FAILURE
#define EXIT_FAILURE 1
#endif

#undef LIBCALL_CHECK_RET
#if defined(NO_STDIO_FILESYSTEM) || defined(NO_ERROR_STRINGS) || \
    defined(NO_MAIN_DRIVER) || defined(BENCH_EMBEDDED)
#define LIBCALL_CHECK_RET(...) __VA_ARGS__
#else
#define LIBCALL_CHECK_RET(...) do {                           \
        int _libcall_ret = (__VA_ARGS__);                     \
        if (_libcall_ret < 0) {                               \
            printf("%s%s L%d error %d for \"%s\"\n",          \
                    err_prefix, __FILE__, __LINE__,           \
                    errno, #__VA_ARGS__);                     \
            XFFLUSH(stdout);                                  \
            _exit(1);                                         \
        }                                                     \
    } while(0)
#endif

#undef THREAD_CHECK_RET
#define THREAD_CHECK_RET(...) do {                                   \
        int _thread_ret = (__VA_ARGS__);                             \
        if (_thread_ret != 0) {                                      \
            errno = _thread_ret;                                     \
            printf("%s%s L%d error %d for \"%s\"\n",                 \
                   err_prefix, __FILE__, __LINE__,                   \
                   _thread_ret, #__VA_ARGS__);                       \
            XFFLUSH(stdout);                                         \
            _exit(1);                                                \
        }                                                            \
    } while(0)

/* optional macro to add sleep between tests */
#ifndef TEST_SLEEP
    /* stub the sleep macro */
    #define TEST_SLEEP() WC_DO_NOTHING
#endif

#define TEST_STRING    "Everyone gets Friday off."
#define TEST_STRING_SZ 25


/* Bit values for each algorithm that is able to be benchmarked.
 * Common grouping of algorithms also.
 * Each algorithm has a unique value for its type e.g. cipher.
 */
/* Cipher algorithms. */
#define BENCH_AES_CBC            0x00000001
#define BENCH_AES_GCM            0x00000002
#define BENCH_AES_ECB            0x00000004
#define BENCH_AES_XTS            0x00000008
#define BENCH_AES_CTR            0x00000010
#define BENCH_AES_CCM            0x00000020
#define BENCH_CAMELLIA           0x00000100
#define BENCH_ARC4               0x00000200
#define BENCH_CHACHA20           0x00001000
#define BENCH_CHACHA20_POLY1305  0x00002000
#define BENCH_DES                0x00004000
#define BENCH_AES_CFB            0x00010000
#define BENCH_AES_OFB            0x00020000
#define BENCH_AES_SIV            0x00040000
#define BENCH_SM4_CBC            0x00080000
#define BENCH_SM4_GCM            0x00100000
#define BENCH_SM4_CCM            0x00200000
#define BENCH_SM4                (BENCH_SM4_CBC | BENCH_SM4_GCM | BENCH_SM4_CCM)
/* Digest algorithms. */
#define BENCH_MD5                0x00000001
#define BENCH_POLY1305           0x00000002
#define BENCH_SHA                0x00000004
#define BENCH_SHA224             0x00000010
#define BENCH_SHA256             0x00000020
#define BENCH_SHA384             0x00000040
#define BENCH_SHA512             0x00000080
#define BENCH_SHA2               (BENCH_SHA224 | BENCH_SHA256 | \
                                  BENCH_SHA384 | BENCH_SHA512)
#define BENCH_SHA3_224           0x00000100
#define BENCH_SHA3_256           0x00000200
#define BENCH_SHA3_384           0x00000400
#define BENCH_SHA3_512           0x00000800
#define BENCH_SHA3               (BENCH_SHA3_224 | BENCH_SHA3_256 | \
                                  BENCH_SHA3_384 | BENCH_SHA3_512)
#define BENCH_SHAKE128           0x00001000
#define BENCH_SHAKE256           0x00002000
#define BENCH_SHAKE              (BENCH_SHAKE128 | BENCH_SHAKE256)
#define BENCH_RIPEMD             0x00004000
#define BENCH_BLAKE2B            0x00008000
#define BENCH_BLAKE2S            0x00010000
#define BENCH_SM3                0x00020000

/* MAC algorithms. */
#define BENCH_CMAC               0x00000001
#define BENCH_HMAC_MD5           0x00000002
#define BENCH_HMAC_SHA           0x00000004
#define BENCH_HMAC_SHA224        0x00000010
#define BENCH_HMAC_SHA256        0x00000020
#define BENCH_HMAC_SHA384        0x00000040
#define BENCH_HMAC_SHA512        0x00000080
#define BENCH_HMAC               (BENCH_HMAC_MD5    | BENCH_HMAC_SHA    | \
                                  BENCH_HMAC_SHA224 | BENCH_HMAC_SHA256 | \
                                  BENCH_HMAC_SHA384 | BENCH_HMAC_SHA512)
#define BENCH_PBKDF2             0x00000100
#define BENCH_SIPHASH            0x00000200

/* KDF algorithms */
#define BENCH_SRTP_KDF           0x00000001

/* Asymmetric algorithms. */
#define BENCH_RSA_KEYGEN         0x00000001
#define BENCH_RSA                0x00000002
#define BENCH_RSA_SZ             0x00000004
#define BENCH_DH                 0x00000010
#define BENCH_ECC_MAKEKEY        0x00001000
#define BENCH_ECC                0x00002000
#define BENCH_ECC_ENCRYPT        0x00004000
#define BENCH_ECC_ALL            0x00008000
#define BENCH_CURVE25519_KEYGEN  0x00010000
#define BENCH_CURVE25519_KA      0x00020000
#define BENCH_ED25519_KEYGEN     0x00040000
#define BENCH_ED25519_SIGN       0x00080000
#define BENCH_CURVE448_KEYGEN    0x00100000
#define BENCH_CURVE448_KA        0x00200000
#define BENCH_ED448_KEYGEN       0x00400000
#define BENCH_ED448_SIGN         0x00800000
#define BENCH_ECC_P256           0x01000000
#define BENCH_ECC_P384           0x02000000
#define BENCH_ECC_P521           0x04000000
#define BENCH_SM2                0x08000000
#define BENCH_ECCSI_KEYGEN       0x00000020
#define BENCH_ECCSI_PAIRGEN      0x00000040
#define BENCH_ECCSI_VALIDATE     0x00000080
#define BENCH_ECCSI              0x00000400
#define BENCH_SAKKE_KEYGEN       0x10000000
#define BENCH_SAKKE_RSKGEN       0x20000000
#define BENCH_SAKKE_VALIDATE     0x40000000
#define BENCH_SAKKE              0x80000000

/* Post-Quantum Asymmetric algorithms. */
#define BENCH_KYBER512                  0x00000020
#define BENCH_KYBER768                  0x00000040
#define BENCH_KYBER1024                 0x00000080
#define BENCH_KYBER                     (BENCH_KYBER512 | BENCH_KYBER768 | \
                                         BENCH_KYBER1024)
#define BENCH_ML_KEM_512                0x00000020
#define BENCH_ML_KEM_768                0x00000040
#define BENCH_ML_KEM_1024               0x00000080
#define BENCH_ML_KEM                    (BENCH_ML_KEM_512 | BENCH_ML_KEM_768 | \
                                         BENCH_ML_KEM_1024)
#define BENCH_FALCON_LEVEL1_SIGN        0x00000001
#define BENCH_FALCON_LEVEL5_SIGN        0x00000002
#define BENCH_DILITHIUM_LEVEL2_SIGN     0x04000000
#define BENCH_DILITHIUM_LEVEL3_SIGN     0x08000000
#define BENCH_DILITHIUM_LEVEL5_SIGN     0x10000000
#define BENCH_ML_DSA_44_SIGN            0x04000000
#define BENCH_ML_DSA_65_SIGN            0x08000000
#define BENCH_ML_DSA_87_SIGN            0x10000000
#define BENCH_ML_DSA_SIGN               (BENCH_ML_DSA_44_SIGN | \
                                         BENCH_ML_DSA_65_SIGN | \
                                         BENCH_ML_DSA_87_SIGN)

/* Post-Quantum Asymmetric algorithms. (Part 2) */
#define BENCH_SPHINCS_FAST_LEVEL1_SIGN  0x00000001
#define BENCH_SPHINCS_FAST_LEVEL3_SIGN  0x00000002
#define BENCH_SPHINCS_FAST_LEVEL5_SIGN  0x00000004
#define BENCH_SPHINCS_SMALL_LEVEL1_SIGN 0x00000008
#define BENCH_SPHINCS_SMALL_LEVEL3_SIGN 0x00000010
#define BENCH_SPHINCS_SMALL_LEVEL5_SIGN 0x00000020

/* Post-Quantum Stateful Hash-Based sig algorithms. */
#define BENCH_LMS_HSS                   0x00000001
#define BENCH_XMSS_XMSSMT_SHA256        0x00000002
#define BENCH_XMSS_XMSSMT_SHA512        0x00000004
#define BENCH_XMSS_XMSSMT_SHAKE128      0x00000008
#define BENCH_XMSS_XMSSMT_SHAKE256      0x00000010
#ifndef NO_SHA256
#define BENCH_XMSS_XMSSMT               BENCH_XMSS_XMSSMT_SHA256
#elif defined(WOLFSSL_SHA512)
#define BENCH_XMSS_XMSSMT               BENCH_XMSS_XMSSMT_SHA512
#elif defined(WOLFSSL_SHAKE128)
#define BENCH_XMSS_XMSSMT               BENCH_XMSS_XMSSMT_SHAKE128
#elif defined(WOLFSSL_SHAKE256)
#define BENCH_XMSS_XMSSMT               BENCH_XMSS_XMSSMT_SHAKE256
#else
#define BENCH_XMSS_XMSSMT               0x00000000
#endif

/* Other */
#define BENCH_RNG                0x00000001
#define BENCH_SCRYPT             0x00000002

#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
/* Define AES_AUTH_ADD_SZ already here, since it's used in the
 * static declaration of `bench_Usage_msg1`. */
#if !defined(AES_AUTH_ADD_SZ) && \
        defined(STM32_CRYPTO) && !defined(STM32_AESGCM_PARTIAL) || \
        defined(WOLFSSL_XILINX_CRYPT_VERSAL)
    /* For STM32 use multiple of 4 to leverage crypto hardware
     * Xilinx Versal requires to use multiples of 16 bytes */
    #define AES_AUTH_ADD_SZ 16
#endif
#ifndef AES_AUTH_ADD_SZ
    #define AES_AUTH_ADD_SZ 13
#endif
#endif

#if (defined(WOLFSSL_HAVE_LMS) && !defined(WOLFSSL_LMS_VERIFY_ONLY)) || \
    (defined(WOLFSSL_HAVE_XMSS) && !defined(WOLFSSL_XMSS_VERIFY_ONLY))
    #define BENCH_PQ_STATEFUL_HBS
#endif

/* Benchmark all compiled in algorithms.
 * When 1, ignore other benchmark algorithm values.
 *      0, only benchmark algorithm values set.
 */
static int bench_all = 1;
/* Cipher algorithms to benchmark. */
static word32 bench_cipher_algs = 0;
/* Digest algorithms to benchmark. */
static word32 bench_digest_algs = 0;
/* MAC algorithms to benchmark. */
static word32 bench_mac_algs = 0;
/* KDF algorithms to benchmark. */
static word32 bench_kdf_algs = 0;
/* Asymmetric algorithms to benchmark. */
static word32 bench_asym_algs = 0;
/* Post-Quantum Asymmetric algorithms to benchmark. */
static word32 bench_pq_asym_algs = 0;
/* Post-Quantum Asymmetric algorithms to benchmark. (Part 2)*/
static word32 bench_pq_asym_algs2 = 0;
/* Other cryptographic algorithms to benchmark. */
static word32 bench_other_algs = 0;
/* Post-Quantum Stateful Hash-Based sig algorithms to benchmark. */
static word32 bench_pq_hash_sig_algs = 0;

#if !defined(WOLFSSL_BENCHMARK_ALL) && !defined(NO_MAIN_DRIVER)

/* The mapping of command line option to bit values. */
typedef struct bench_alg {
    /* Command line option string. */
    const char* str;
    /* Bit values to set. */
    word32 val;
} bench_alg;

#ifndef MAIN_NO_ARGS
/* All recognized cipher algorithm choosing command line options. */
static const bench_alg bench_cipher_opt[] = {
    { "-cipher",             0xffffffff              },
#ifdef HAVE_AES_CBC
    { "-aes-cbc",            BENCH_AES_CBC           },
#endif
#ifdef HAVE_AESGCM
    { "-aes-gcm",            BENCH_AES_GCM           },
#endif
#ifdef WOLFSSL_AES_DIRECT
    { "-aes-ecb",            BENCH_AES_ECB           },
#endif
#ifdef WOLFSSL_AES_XTS
    { "-aes-xts",            BENCH_AES_XTS           },
#endif
#ifdef WOLFSSL_AES_CFB
    { "-aes-cfb",            BENCH_AES_CFB           },
#endif
#ifdef WOLFSSL_AES_OFB
    { "-aes-ofb",            BENCH_AES_OFB           },
#endif
#ifdef WOLFSSL_AES_COUNTER
    { "-aes-ctr",            BENCH_AES_CTR           },
#endif
#ifdef HAVE_AESCCM
    { "-aes-ccm",            BENCH_AES_CCM           },
#endif
#ifdef WOLFSSL_AES_SIV
    { "-aes-siv",            BENCH_AES_SIV           },
#endif
#ifdef HAVE_CAMELLIA
    { "-camellia",           BENCH_CAMELLIA          },
#endif
#ifndef NO_RC4
    { "-arc4",               BENCH_ARC4              },
#endif
#ifdef HAVE_CHACHA
    { "-chacha20",           BENCH_CHACHA20          },
#endif
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    { "-chacha20-poly1305",  BENCH_CHACHA20_POLY1305 },
#endif
#ifdef WOLFSSL_SM4_CBC
    { "-sm4-cbc",            BENCH_SM4_CBC           },
#endif
#ifdef WOLFSSL_SM4_GCM
    { "-sm4-gcm",            BENCH_SM4_GCM           },
#endif
#ifdef WOLFSSL_SM4_CCM
    { "-sm4-ccm",            BENCH_SM4_CCM           },
#endif
#ifdef WOLFSSL_SM4
    { "-sm4",                BENCH_SM4               },
#endif
#ifndef NO_DES3
    { "-des",                BENCH_DES               },
#endif
    { NULL, 0 }
};

/* All recognized digest algorithm choosing command line options. */
static const bench_alg bench_digest_opt[] = {
    { "-digest",             0xffffffff              },
#ifndef NO_MD5
    { "-md5",                BENCH_MD5               },
#endif
#ifdef HAVE_POLY1305
    { "-poly1305",           BENCH_POLY1305          },
#endif
#ifndef NO_SHA
    { "-sha",                BENCH_SHA               },
#endif
#if defined(WOLFSSL_SHA224) || !defined(NO_SHA256) || defined(WOLFSSL_SHA384) \
                                                   || defined(WOLFSSL_SHA512)
    { "-sha2",               BENCH_SHA2              },
#endif
#ifdef WOLFSSL_SHA224
    { "-sha224",             BENCH_SHA224            },
#endif
#ifndef NO_SHA256
    { "-sha256",             BENCH_SHA256            },
#endif
#ifdef WOLFSSL_SHA384
    { "-sha384",             BENCH_SHA384            },
#endif
#ifdef WOLFSSL_SHA512
    { "-sha512",             BENCH_SHA512            },
#endif
#ifdef WOLFSSL_SHA3
    { "-sha3",               BENCH_SHA3              },
    #ifndef WOLFSSL_NOSHA3_224
    { "-sha3-224",           BENCH_SHA3_224          },
    #endif
    #ifndef WOLFSSL_NOSHA3_256
    { "-sha3-256",           BENCH_SHA3_256          },
    #endif
    #ifndef WOLFSSL_NOSHA3_384
    { "-sha3-384",           BENCH_SHA3_384          },
    #endif
    #ifndef WOLFSSL_NOSHA3_512
    { "-sha3-512",           BENCH_SHA3_512          },
    #endif
    #if defined(WOLFSSL_SHAKE128) || defined(WOLFSSL_SHAKE256)
    { "-shake",              BENCH_SHAKE             },
    #endif
    #ifdef WOLFSSL_SHAKE128
    { "-shake128",           BENCH_SHAKE128          },
    #endif
    #ifdef WOLFSSL_SHAKE256
    { "-shake256",           BENCH_SHAKE256          },
    #endif
#endif
#ifdef WOLFSSL_SM3
    { "-sm3",                BENCH_SM3               },
#endif
#ifdef WOLFSSL_RIPEMD
    { "-ripemd",             BENCH_RIPEMD            },
#endif
#ifdef HAVE_BLAKE2
    { "-blake2b",            BENCH_BLAKE2B           },
#endif
#ifdef HAVE_BLAKE2S
    { "-blake2s",            BENCH_BLAKE2S           },
#endif
    { NULL, 0 }
};

/* All recognized MAC algorithm choosing command line options. */
static const bench_alg bench_mac_opt[] = {
    { "-mac",                0xffffffff              },
#ifdef WOLFSSL_CMAC
    { "-cmac",               BENCH_CMAC              },
#endif
#ifndef NO_HMAC
    { "-hmac",               BENCH_HMAC              },
    #ifndef NO_MD5
    { "-hmac-md5",           BENCH_HMAC_MD5          },
    #endif
    #ifndef NO_SHA
    { "-hmac-sha",           BENCH_HMAC_SHA          },
    #endif
    #ifdef WOLFSSL_SHA224
    { "-hmac-sha224",        BENCH_HMAC_SHA224       },
    #endif
    #ifndef NO_SHA256
    { "-hmac-sha256",        BENCH_HMAC_SHA256       },
    #endif
    #ifdef WOLFSSL_SHA384
    { "-hmac-sha384",        BENCH_HMAC_SHA384       },
    #endif
    #ifdef WOLFSSL_SHA512
    { "-hmac-sha512",        BENCH_HMAC_SHA512       },
    #endif
    #ifndef NO_PWDBASED
    { "-pbkdf2",             BENCH_PBKDF2            },
    #endif
#endif
    #ifdef WOLFSSL_SIPHASH
    { "-siphash",            BENCH_SIPHASH           },
    #endif
    { NULL, 0 }
};

/* All recognized KDF algorithm choosing command line options. */
static const bench_alg bench_kdf_opt[] = {
    { "-kdf",                0xffffffff              },
#ifdef WC_SRTP_KDF
    { "-srtp-kdf",           BENCH_SRTP_KDF          },
#endif
    { NULL, 0 }
};

/* All recognized asymmetric algorithm choosing command line options. */
static const bench_alg bench_asym_opt[] = {
    { "-asym",               0xffffffff              },
#ifndef NO_RSA
    #ifdef WOLFSSL_KEY_GEN
    { "-rsa-kg",             BENCH_RSA_KEYGEN        },
    #endif
    { "-rsa",                BENCH_RSA               },
    #ifdef WOLFSSL_KEY_GEN
    { "-rsa-sz",             BENCH_RSA_SZ            },
    #endif
#endif
#ifndef NO_DH
    { "-dh",                 BENCH_DH                },
#endif
#ifdef HAVE_ECC
    { "-ecc-kg",             BENCH_ECC_MAKEKEY       },
    { "-ecc",                BENCH_ECC               },
    #ifdef HAVE_ECC_ENCRYPT
    { "-ecc-enc",            BENCH_ECC_ENCRYPT       },
    #endif
    { "-ecc-all",            BENCH_ECC_ALL           },
#endif
#ifdef WOLFSSL_SM2
    { "-sm2",                BENCH_SM2               },
#endif
#ifdef HAVE_CURVE25519
    { "-curve25519-kg",      BENCH_CURVE25519_KEYGEN },
    #ifdef HAVE_CURVE25519_SHARED_SECRET
    { "-x25519",             BENCH_CURVE25519_KA     },
    #endif
#endif
#ifdef HAVE_ED25519
    { "-ed25519-kg",         BENCH_ED25519_KEYGEN    },
    { "-ed25519",            BENCH_ED25519_SIGN      },
#endif
#ifdef HAVE_CURVE448
    { "-curve448-kg",        BENCH_CURVE448_KEYGEN   },
    #ifdef HAVE_CURVE448_SHARED_SECRET
    { "-x448",               BENCH_CURVE448_KA       },
    #endif
#endif
#ifdef HAVE_ED448
    { "-ed448-kg",           BENCH_ED448_KEYGEN      },
    { "-ed448",              BENCH_ED448_SIGN        },
#endif
#ifdef WOLFCRYPT_HAVE_ECCSI
    { "-eccsi-kg",           BENCH_ECCSI_KEYGEN      },
    { "-eccsi-pair",         BENCH_ECCSI_PAIRGEN     },
    { "-eccsi-val",          BENCH_ECCSI_VALIDATE    },
    { "-eccsi",              BENCH_ECCSI             },
#endif
#ifdef WOLFCRYPT_HAVE_SAKKE
    { "-sakke-kg",           BENCH_SAKKE_KEYGEN      },
    { "-sakke-rsk",          BENCH_SAKKE_RSKGEN      },
    { "-sakke-val",          BENCH_SAKKE_VALIDATE    },
    { "-sakke",              BENCH_SAKKE             },
#endif
    { NULL, 0 }
};

/* All recognized other cryptographic algorithm choosing command line options.
 */
static const bench_alg bench_other_opt[] = {
    { "-other",              0xffffffff              },
#ifndef WC_NO_RNG
    { "-rng",                BENCH_RNG               },
#endif
#ifdef HAVE_SCRYPT
    { "-scrypt",             BENCH_SCRYPT            },
#endif
    { NULL, 0}
};
#endif /* MAIN_NO_ARGS */

#endif /* !WOLFSSL_BENCHMARK_ALL && !NO_MAIN_DRIVER */

#if defined(BENCH_PQ_STATEFUL_HBS)
typedef struct bench_pq_hash_sig_alg {
    /* Command line option string. */
    const char* str;
    /* Bit values to set. */
    word32 val;
} bench_pq_hash_sig_alg;

static const bench_pq_hash_sig_alg bench_pq_hash_sig_opt[] = {
    { "-pq_hash_sig", 0xffffffff},
#if defined(WOLFSSL_HAVE_LMS) && !defined(WOLFSSL_LMS_VERIFY_ONLY)
    { "-lms_hss", BENCH_LMS_HSS},
#endif
#if defined(WOLFSSL_HAVE_XMSS) && !defined(WOLFSSL_XMSS_VERIFY_ONLY)
    { "-xmss_xmssmt",          BENCH_XMSS_XMSSMT},
#ifdef WC_XMSS_SHA256
    { "-xmss_xmssmt_sha256",   BENCH_XMSS_XMSSMT_SHA256},
#endif
#ifdef WC_XMSS_SHA512
#if WOLFSSL_WC_XMSS_MIN_HASH_SIZE <= 512 && WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 512
    { "-xmss_xmssmt_sha512",   BENCH_XMSS_XMSSMT_SHA512},
#endif
#endif
#ifdef WC_XMSS_SHAKE128
#if WOLFSSL_WC_XMSS_MIN_HASH_SIZE <= 256 && WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 256
    { "-xmss_xmssmt_shake128", BENCH_XMSS_XMSSMT_SHAKE128},
#endif
#endif
#ifdef WC_XMSS_SHAKE256
    { "-xmss_xmssmt_shake256", BENCH_XMSS_XMSSMT_SHAKE256},
#endif
#endif
    { NULL, 0}
};
#endif /* BENCH_PQ_STATEFUL_HBS */

#if defined(WOLFSSL_HAVE_KYBER) || defined(HAVE_FALCON) || \
    defined(HAVE_DILITHIUM) || defined(HAVE_SPHINCS)
/* The post-quantum-specific mapping of command line option to bit values and
 * OQS name. */
typedef struct bench_pq_alg {
    /* Command line option string. */
    const char* str;
    /* Bit values to set. */
    word32 val;
} bench_pq_alg;

/* All recognized post-quantum asymmetric algorithm choosing command line
 * options. */
static const bench_pq_alg bench_pq_asym_opt[] = {
    { "-pq",                0xffffffff },
#ifdef WOLFSSL_HAVE_KYBER
    { "-kyber",             BENCH_KYBER             },
    { "-kyber512",          BENCH_KYBER512          },
    { "-kyber768",          BENCH_KYBER768          },
    { "-kyber1024",         BENCH_KYBER1024         },
    { "-ml-kem",            BENCH_ML_KEM            },
    { "-ml-kem-512",        BENCH_ML_KEM_512        },
    { "-ml-kem-768",        BENCH_ML_KEM_768        },
    { "-ml-kem-1024",       BENCH_ML_KEM_1024       },
#endif
#if defined(HAVE_FALCON)
    { "-falcon_level1",     BENCH_FALCON_LEVEL1_SIGN },
    { "-falcon_level5",     BENCH_FALCON_LEVEL5_SIGN },
#endif
#if defined(HAVE_DILITHIUM)
    { "-dilithium_level2",  BENCH_DILITHIUM_LEVEL2_SIGN },
    { "-dilithium_level3",  BENCH_DILITHIUM_LEVEL3_SIGN },
    { "-dilithium_level5",  BENCH_DILITHIUM_LEVEL5_SIGN },
    { "-ml-dsa",            BENCH_ML_DSA_SIGN           },
    { "-ml-dsa-44",         BENCH_ML_DSA_44_SIGN        },
    { "-ml-dsa-65",         BENCH_ML_DSA_65_SIGN        },
    { "-ml-dsa-87",         BENCH_ML_DSA_87_SIGN        },
#endif
    { NULL, 0 }
};

#if defined(HAVE_SPHINCS)
/* All recognized post-quantum asymmetric algorithm choosing command line
 * options. (Part 2) */
static const bench_pq_alg bench_pq_asym_opt2[] = {
    { "-pq",                 0xffffffff },
    { "-sphincs_fast_level1", BENCH_SPHINCS_FAST_LEVEL1_SIGN },
    { "-sphincs_fast_level3", BENCH_SPHINCS_FAST_LEVEL3_SIGN },
    { "-sphincs_fast_level5", BENCH_SPHINCS_FAST_LEVEL5_SIGN },
    { "-sphincs_small_level1", BENCH_SPHINCS_SMALL_LEVEL1_SIGN },
    { "-sphincs_small_level3", BENCH_SPHINCS_SMALL_LEVEL3_SIGN },
    { "-sphincs_small_level5", BENCH_SPHINCS_SMALL_LEVEL5_SIGN },
    { NULL, 0, }
};
#endif /* HAVE_SPHINCS */
#endif

#ifdef HAVE_WNR
    const char* wnrConfigFile = "wnr-example.conf";
#endif

#if defined(WOLFSSL_MDK_ARM)
    extern XFILE wolfSSL_fopen(const char *fname, const char *mode);
    #define fopen wolfSSL_fopen
#endif

static int lng_index = 0;

#ifndef NO_MAIN_DRIVER
#ifndef MAIN_NO_ARGS
static const char* bench_Usage_msg1[][25] = {
    /* 0 English  */
    {   "-? <num>    Help, print this usage\n",
        "            0: English, 1: Japanese\n",
        "-csv        Print terminal output in csv format\n",
        "-base10     Display bytes as power of 10 (eg 1 kB = 1000 Bytes)\n",
        "-no_aad     No additional authentication data passed.\n",
        "-aad_size <num>   With <num> bytes of AAD.\n",
       ("-all_aad    With AAD length of 0, "
                     WC_STRINGIFY(AES_AUTH_ADD_SZ)
                     " and\n"
        "            (if set via -aad_size) <aad_size> bytes.\n"
       ),
        "-dgst_full  Full digest operation performed.\n",
        "-rsa_sign   Measure RSA sign/verify instead of encrypt/decrypt.\n",
        "<keySz> -rsa-sz\n            Measure RSA <key size> performance.\n",
        "-ffhdhe2048 Measure DH using FFDHE 2048-bit parameters.\n",
        "-ffhdhe3072 Measure DH using FFDHE 3072-bit parameters.\n",
        "-p256       Measure ECC using P-256 curve.\n",
        "-p384       Measure ECC using P-384 curve.\n",
        "-p521       Measure ECC using P-521 curve.\n",
        "-ecc-all    Bench all enabled ECC curves.\n",
        "-<alg>      Algorithm to benchmark. Available algorithms include:\n",
        ("-lng <num>  Display benchmark result by specified language.\n"
         "            0: English, 1: Japanese\n"
        ),
        "<num>       Size of block in bytes\n",
       ("-blocks <num>  Number of blocks. Can be used together with the "
        "'Size of block'\n"
        "            option, but must be used after that one.\n"
       ),
        "-threads <num> Number of threads to run\n",
        "-print      Show benchmark stats summary\n",
        "-hash_input   <file>   Input data to use for hash benchmarking\n",
        "-cipher_input <file>   Input data to use for cipher benchmarking\n",
        "-min_runs     <num>    Specify minimum number of operation runs\n"
    },
#ifndef NO_MULTIBYTE_PRINT
    /* 1 Japanese */
    {   "-? <num>    ヘルプ, 使い方を表示します。\n",
        "            0: 英語、 1: 日本語\n",
        "-csv        csv 形式で端末に出力します。\n",
        "-base10     バイトを10のべき乗で表示します。(例 1 kB = 1000 Bytes)\n",
        "-no_aad     追加の認証データを使用しません.\n",
        "-aad_size <num>  TBD.\n",
        "-all_aad    TBD.\n",
        "-dgst_full  フルの digest 暗号操作を実施します。\n",
        "-rsa_sign   暗号/復号化の代わりに RSA の署名/検証を測定します。\n",
        "<keySz> -rsa-sz\n            RSA <key size> の性能を測定します。\n",
        "-ffhdhe2048 Measure DH using FFDHE 2048-bit parameters.\n",
        "-ffhdhe3072 Measure DH using FFDHE 3072-bit parameters.\n",
        "-p256       Measure ECC using P-256 curve.\n",
        "-p384       Measure ECC using P-384 curve.\n",
        "-p521       Measure ECC using P-521 curve.\n",
        "-ecc-all    Bench all enabled ECC curves.\n",
       ("-<alg>      アルゴリズムのベンチマークを実施します。\n"
        "            利用可能なアルゴリズムは下記を含みます:\n"
       ),
       ("-lng <num>  指定された言語でベンチマーク結果を表示します。\n"
        "            0: 英語、 1: 日本語\n"
       ),
        "<num>       ブロックサイズをバイト単位で指定します。\n",
        "-blocks <num>  TBD.\n",
        "-threads <num> 実行するスレッド数\n",
        "-print      ベンチマーク統計の要約を表示する\n",
        /* TODO: translate below */
        "-hash_input   <file>   Input data to use for hash benchmarking\n",
        "-cipher_input <file>   Input data to use for cipher benchmarking\n",
        "-min_runs     <num>    Specify minimum number of operation runs\n"
    },
#endif
};
#endif /* MAIN_NO_ARGS */
#endif

static const char* bench_result_words1[][4] = {
    { "took",
#ifdef BENCH_MICROSECOND
      "microseconds"
#else
      "seconds"
#endif
    , "Cycles per byte", NULL }, /* 0 English */
#ifndef NO_MULTIBYTE_PRINT
    { "を"   , "秒で処理", "1バイトあたりのサイクル数", NULL },     /* 1 Japanese */
#endif
};

#if !defined(NO_RSA) || \
    defined(HAVE_ECC) || !defined(NO_DH) || defined(HAVE_ECC_ENCRYPT) || \
    defined(HAVE_CURVE25519) || defined(HAVE_CURVE25519_SHARED_SECRET)  || \
    defined(HAVE_ED25519) || defined(HAVE_CURVE448) || \
    defined(HAVE_CURVE448_SHARED_SECRET) || defined(HAVE_ED448) || \
    defined(WOLFSSL_HAVE_KYBER) || defined(HAVE_DILITHIUM)

static const char* bench_desc_words[][15] = {
    /* 0           1          2         3        4        5         6            7            8          9        10        11       12          13       14 */
    {"public", "private", "key gen", "agree" , "sign", "verify", "encrypt", "decrypt", "rsk gen", "encap", "derive", "valid", "pair gen", "decap", NULL}, /* 0 English */
#ifndef NO_MULTIBYTE_PRINT
    {"公開鍵", "秘密鍵" ,"鍵生成" , "鍵共有" , "署名", "検証"  , "暗号化"    , "復号化"    , "rsk gen", "encap", "derive", "valid", "pair gen", "decap", NULL}, /* 1 Japanese */
#endif
};

#endif

#ifdef MULTI_VALUE_STATISTICS
static const char* bench_result_words3[][5] = {
    /* 0 English  */
    { "max duration", "min duration" , "mean duration", "sd", NULL },
    /* TODO: Add japenese version */
    { "max duration", "min duration" , "mean duration", "sd", NULL }
};
#endif

#if defined(__GNUC__) && defined(__x86_64__) && !defined(NO_ASM) && !defined(WOLFSSL_SGX)
    #define HAVE_GET_CYCLES
    static WC_INLINE word64 get_intel_cycles(void);
    static THREAD_LS_T word64 total_cycles;
    #define INIT_CYCLE_COUNTER
    #define BEGIN_INTEL_CYCLES total_cycles = get_intel_cycles();
    #define END_INTEL_CYCLES   total_cycles = get_intel_cycles() - total_cycles;
    /* s == size in bytes that 1 count represents, normally BENCH_SIZE */
    #define SHOW_INTEL_CYCLES(b, n, s)                                         \
        (void)XSNPRINTF((b) + XSTRLEN(b), (n) - XSTRLEN(b),                    \
            " %s = " FLT_FMT_PREC2 STATS_CLAUSE_SEPARATOR,                     \
            bench_result_words1[lng_index][2],                                 \
            FLT_FMT_PREC2_ARGS(6, 2, count == 0 ? 0 :                          \
            (double)total_cycles / ((word64)count*(s))))
    #define SHOW_INTEL_CYCLES_CSV(b, n, s)                                     \
        (void)XSNPRINTF((b) + XSTRLEN(b), (n) - XSTRLEN(b), FLT_FMT_PREC ","   \
            STATS_CLAUSE_SEPARATOR, FLT_FMT_PREC_ARGS(6, count == 0 ? 0 :      \
            (double)total_cycles / ((word64)count*(s))))
#elif defined(LINUX_CYCLE_COUNT)
    #include <linux/perf_event.h>
    #include <sys/syscall.h>
    #include <unistd.h>

    static THREAD_LS_T word64 begin_cycles;
    static THREAD_LS_T word64 total_cycles;
    static THREAD_LS_T int cycles = -1;
    static THREAD_LS_T struct perf_event_attr atr;

    #define INIT_CYCLE_COUNTER do {                                             \
        atr.type   = PERF_TYPE_HARDWARE;                                        \
        atr.config = PERF_COUNT_HW_CPU_CYCLES;                                  \
        cycles = (int)syscall(__NR_perf_event_open, &atr, 0, -1, -1, 0);        \
    } while (0);

    #define BEGIN_INTEL_CYCLES read(cycles, &begin_cycles, sizeof(begin_cycles));
    #define END_INTEL_CYCLES   do {                                             \
        read(cycles, &total_cycles, sizeof(total_cycles));                      \
        total_cycles = total_cycles - begin_cycles;                             \
    } while (0);

    /* s == size in bytes that 1 count represents, normally BENCH_SIZE */
    #define SHOW_INTEL_CYCLES(b, n, s)                                         \
        (void)XSNPRINTF(b + XSTRLEN(b), n - XSTRLEN(b),                        \
            " %s = " FLT_FMT_PREC2 STATS_CLAUSE_SEPARATOR,                     \
        bench_result_words1[lng_index][2],                                     \
                        FLT_FMT_PREC2_ARGS(6, 2, (double)total_cycles /        \
                            (count*s)))
    #define SHOW_INTEL_CYCLES_CSV(b, n, s)                                     \
        (void)XSNPRINTF(b + XSTRLEN(b), n - XSTRLEN(b), FLT_FMT_PREC ","       \
            STATS_CLAUSE_SEPARATOR, FLT_FMT_PREC_ARGS(6, (double)total_cycles  \
                / (count*s)))

#elif defined(SYNERGY_CYCLE_COUNT)
    #include "hal_data.h"
    static THREAD_LS_T word64 begin_cycles;
    static THREAD_LS_T word64 total_cycles;

    #define INIT_CYCLE_COUNTER
    #define BEGIN_INTEL_CYCLES begin_cycles = DWT->CYCCNT = 0;
    #define END_INTEL_CYCLES   total_cycles =  DWT->CYCCNT - begin_cycles;

    /* s == size in bytes that 1 count represents, normally BENCH_SIZE */
    #define SHOW_INTEL_CYCLES(b, n, s)                                         \
        (void)XSNPRINTF(b + XSTRLEN(b), n - XSTRLEN(b),                        \
        " %s = " FLT_FMT_PREC2 STATS_CLAUSE_SEPARATOR,                         \
        bench_result_words1[lng_index][2],                                     \
            FLT_FMT_PREC2_ARGS(6, 2, (double)total_cycles / (count*s)))
    #define SHOW_INTEL_CYCLES_CSV(b, n, s)                                     \
        (void)XSNPRINTF(b + XSTRLEN(b), n - XSTRLEN(b), FLT_FMT_PREC ",\n",    \
            FLT_FMT_PREC_ARGS(6, (double)total_cycles / (count*s)))
#elif defined(WOLFSSL_ESPIDF)
    /* TAG for ESP_LOGx() */
    static const char* TAG = "wolfssl_benchmark";

    static THREAD_LS_T word64 begin_cycles = 0;
    static THREAD_LS_T word64 begin_cycles_ticks = 0;
    static THREAD_LS_T word64 end_cycles = 0;
    static THREAD_LS_T word64 total_cycles = 0;

    /* the return value, as a global var */
    static THREAD_LS_T word64 _esp_get_cycle_count_ex = 0;

    /* the last value seen, adjusted for an overflow, as a global var */
    static THREAD_LS_T word64 _esp_cpu_count_last = 0;

    static THREAD_LS_T TickType_t last_tickCount = 0; /* last FreeRTOS value */

    /* esp_get_cpu_benchmark_cycles(void):
     *
     *   Architecture-independant CPU clock counter.
     *   WARNING: the hal UINT xthal_get_ccount() quietly rolls over. */
    static WC_INLINE word64 esp_get_cpu_benchmark_cycles(void);

    /* Some vars for debugging, compare ticks to cycles */
    #ifdef WOLFSSL_BENCHMARK_TIMER_DEBUG
        static THREAD_LS_T word64 _esp_cpu_timer_last = 0;
        static THREAD_LS_T word64 _esp_cpu_timer_diff = 0;
        static THREAD_LS_T word64 _xthal_get_ccount_exAlt = 0;
        static THREAD_LS_T word64 _xthal_get_ccount_exDiff = 0;
    #endif /* WOLFSSL_BENCHMARK_TIMER_DEBUG */

    /* The ESP32 (both Xtensa and RISC-V have raw CPU counters). */
    #if ESP_IDF_VERSION_MAJOR >= 5
        /* esp_cpu_set_cycle_count() introduced in ESP-IDF v5 */
        #define HAVE_GET_CYCLES
        #define INIT_CYCLE_COUNTER do {          \
            ESP_LOGV(TAG, "INIT_CYCLE_COUNTER"); \
            esp_cpu_set_cycle_count(0);          \
        } while (0);
    #else
        #define HAVE_GET_CYCLES
        #define INIT_CYCLE_COUNTER do {          \
            ESP_LOGV(TAG, "INIT_CYCLE_COUNTER"); \
        } while (0);
    #endif

    #define BEGIN_ESP_CYCLES do {                        \
        ESP_LOGV(TAG, "BEGIN_ESP_CYCLES");               \
        begin_cycles = esp_get_cpu_benchmark_cycles();   \
        begin_cycles_ticks = xTaskGetTickCount();        \
    } while (0);

    /* since it rolls over, we have something that will tolerate one */
    #define END_ESP_CYCLES                                             \
        end_cycles = esp_get_cpu_benchmark_cycles();                   \
        ESP_LOGV(TAG,"END_ESP_CYCLES %llu - %llu",                     \
                     end_cycles,                                       \
                     begin_cycles                                      \
                );                                                     \
        total_cycles = (end_cycles - begin_cycles);

    #define SHOW_ESP_CYCLES(b, n, s) \
        (void)XSNPRINTF(b + XSTRLEN(b), n - XSTRLEN(b),                \
            " %s = " FLT_FMT_PREC2 "\n",                               \
            bench_result_words1[lng_index][2],                         \
            FLT_FMT_PREC2_ARGS(6, 2, (double)total_cycles / (count*s)) \
        )

    #define SHOW_ESP_CYCLES_CSV(b, n, s) \
        (void)XSNPRINTF(b + XSTRLEN(b), n - XSTRLEN(b), FLT_FMT_PREC ",\n", \
            FLT_FMT_PREC_ARGS(6, (double)total_cycles / (count*s)))

    #ifdef WOLFSSL_BENCHMARK_TIMER_DEBUG
        /* 64 bit, unisgned, absolute difference
         * used in CPU cycle counter debug calcs. */
        static uint64_t esp_cycle_abs_diff(uint64_t x, uint64_t y)
        {
            uint64_t ret;
            ret =  (x > y) ? (x - y) : (y - x);
            return ret;
        }
    #endif

    /* esp_get_cycle_count_ex() is a single-overflow-tolerant extension to
    ** the Espressif `unsigned xthal_get_ccount()` (Xtensa) or
    ** `esp_cpu_get_cycle_count` (RISC-V) which are known to overflow
    ** at least once during full benchmark tests.
    **
    ** To test timing overflow, add a delay longer than max cycles:
    **   vTaskDelay( (const TickType_t)(configTICK_RATE_HZ * 17 * 5) );
    */
    uint64_t esp_get_cycle_count_ex()
    {
        /* reminder: unsigned long long max = 18,446,744,073,709,551,615    */
        /*           unsigned int max       =              4,294,967,295    */
        uint64_t thisVal = 0; /* CPU counter, "this current value" as read. */
        uint64_t thisIncrement = 0; /* The adjusted increment amount.       */
        uint64_t expected_diff = 0; /* FreeRTOS estimated expected CPU diff.*/
    #ifdef DEBUG_WOLFSSL_BENCHMARK_TIMING
        uint64_t tickCount = 0; /* Current rtos tick counter.               */
        uint64_t tickDiff = 0;  /* Tick difference from last check.         */
        uint64_t tickBeginDiff = 0; /* Tick difference from beginning.      */
    #endif
    #ifdef WOLFSSL_BENCHMARK_TIMER_DEBUG
        uint64_t thisTimerVal = 0; /* Timer Value as alternate to compare */
        uint64_t diffDiff = 0;   /* Difference between CPU & Timer differences:
                                  * (current - last) */
    #endif
    #if defined(CONFIG_IDF_TARGET_ESP32C2) || \
        defined(CONFIG_IDF_TARGET_ESP32C3) || \
        defined(CONFIG_IDF_TARGET_ESP32C6)

        #ifdef WOLFSSL_BENCHMARK_TIMER_DEBUG
            ESP_ERROR_CHECK(gptimer_get_raw_count(esp_gptimer, &thisTimerVal));
            thisTimerVal = thisTimerVal * RESOLUTION_SCALE;
        #endif /* WOLFSSL_BENCHMARK_TIMER_DEBUG */

        #if ESP_IDF_VERSION_MAJOR >= 5
            thisVal = esp_cpu_get_cycle_count();
        #else
            thisVal = cpu_hal_get_cycle_count();
        #endif

    #elif defined(CONFIG_IDF_TARGET_ESP32H2)
        thisVal = esp_cpu_get_cycle_count();
    #elif defined(CONFIG_IDF_TARGET_ESP8266)
        thisVal = esp_timer_get_time();
    #else
        /* TODO: Why doesn't esp_cpu_get_cycle_count work for Xtensa?
         * Calling current_time(1) to reset time causes thisVal overflow,
         * on Xtensa, but not on RISC-V architecture. See also, below */
        #if defined(CONFIG_IDF_TARGET_ESP8266) || (ESP_IDF_VERSION_MAJOR < 5)
            #ifndef configCPU_CLOCK_HZ
                /* esp_cpu_get_cycle_count not available in ESP-IDF v4 */
                #define configCPU_CLOCK_HZ \
                       (CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ * MILLION_VALUE)
            #endif
            /* There's no CPU counter on the ESP8266 (Tensilica). Using RTOS */
            thisVal =  (uint64_t)xTaskGetTickCount() *
                        (uint64_t)(configCPU_CLOCK_HZ / CONFIG_FREERTOS_HZ);
        #elif defined(__XTENSA__)
            thisVal = esp_cpu_get_cycle_count();
        #else
            /* Not Tensilica(ESP8266), not Xtensa(ESP32/-S2/-S3, then RISC-V */
            thisVal = xthal_get_ccount(); /* or esp_cpu_get_cycle_count(); */
        #endif
    #endif

        #ifdef DEBUG_WOLFSSL_BENCHMARK_TIMING
        {
            tickCount = xTaskGetTickCount(); /* Our local FreeRTOS tick count */
            tickDiff = tickCount - last_tickCount; /* ticks since bench start */
            expected_diff = CPU_TICK_CYCLES * tickDiff; /* CPU expected count */
            ESP_LOGV(TAG, "CPU_TICK_CYCLES = %d", (int)CPU_TICK_CYCLES);
            ESP_LOGV(TAG, "tickCount           = %llu", tickCount);
            ESP_LOGV(TAG, "last_tickCount      = " TFMT, last_tickCount);
            ESP_LOGV(TAG, "tickDiff            = %llu", tickDiff);
            ESP_LOGV(TAG, "expected_diff1      = %llu", expected_diff);
        }
        #endif

        /* If either thisVal is smaller than last (overflow), and/or the
         * expected value calculated from FreeRTOS tick difference that would
         * have never fit into an unsigned 32 bit integer anyhow... then we
         * need to adjust thisVal to save. */
        if ( (thisVal < _esp_cpu_count_last) || (expected_diff > UINT_MAX) )
        {
            /* Warning: we assume the return type of esp_cpu_get_cycle_count()
            ** will always be unsigned int (or uint32_t) to add UINT_MAX.
            **
            ** NOTE for long duration between calls with multiple overflows:
            **
            **   WILL NOT BE DETECTED - the return value will be INCORRECT.
            **
            ** At this time no single test overflows. This is currently only a
            ** concern for cumulative counts over multiple tests. As long
            ** as well call xthal_get_ccount_ex() with no more than one
            ** overflow CPU tick count, all will be well.
            */
            #ifdef DEBUG_WOLFSSL_BENCHMARK_TIMING
                ESP_LOGW(TAG, "Alert: Detected xthal_get_ccount overflow at "
                              "(%llu < %llu) adding UINT_MAX = %llu.",
                         thisVal, _esp_cpu_count_last, (uint64_t) UINT_MAX);
            #endif
            #if !defined(CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ) && \
                !defined(CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ)
                #error "CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ not found"
            #endif

            /* double check expected diff calc */
            #ifdef DEBUG_WOLFSSL_BENCHMARK_TIMING
                #if  defined(CONFIG_IDF_TARGET_ESP8266)
                    expected_diff = (CONFIG_ESP8266_DEFAULT_CPU_FREQ_MHZ
                                     * MILLION_VALUE)
                                     * tickDiff / configTICK_RATE_HZ;
                #else
                    expected_diff = (CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ * MILLION_VALUE)
                                    * tickDiff / configTICK_RATE_HZ;

                #endif
                ESP_LOGI(TAG, "expected_diff2      = %llu", expected_diff);
            #endif
            if (expected_diff > UINT_MAX) {
                /* The number of cycles expected from FreeRTOS ticks is
                 * greater than the maximum size of an unsigned 32-bit
                 * integer, meaning multiple overflows occurred. */
                #ifdef DEBUG_WOLFSSL_BENCHMARK_TIMING
                    ESP_LOGW(TAG, "expected_diff > UINT_MAX (%u)", UINT_MAX);
                #endif
                thisVal += expected_diff; /* FreeRTOS calc to our 64 bit val */
            }
            else {
                thisVal += (word64)UINT_MAX; /* add 32 bit max to our 64 bit */
            }

            #ifdef DEBUG_WOLFSSL_BENCHMARK_TIMING
            {
                tickBeginDiff = tickCount - begin_cycles_ticks;

                ESP_LOGI(TAG, "begin_cycles_ticks  = %llu", begin_cycles_ticks);
                ESP_LOGI(TAG, "tickDiff            = %llu", tickDiff);
                ESP_LOGI(TAG, "expected_diff       = %llu", expected_diff);
                ESP_LOGI(TAG, "tickBeginDiff       = %llu", tickBeginDiff);

                ESP_LOGW(TAG, WOLFSSL_ESPIDF_BLANKLINE_MESSAGE);
            }
            #endif
        }
        else {
            #ifdef DEBUG_WOLFSSL_BENCHMARK_TIMING
                ESP_LOGI(TAG, "thisVal, read CPU   = %llu", thisVal);
            #endif
        } /* if thisVal adjustment check */

        #ifdef WOLFSSL_BENCHMARK_TIMER_DEBUG
            if (thisTimerVal < _esp_cpu_timer_last)
            {
                ESP_LOGW(TAG, "Alert: Detected xthal_get_ccountAlt overflow, "
                              "adding %ull", UINT_MAX);
                thisTimerVal += (word64)UINT_MAX;
            }
            /* Check an alternate counter using a timer */

            _esp_cpu_timer_diff      = esp_cycle_abs_diff(_esp_cpu_count_last, _esp_cpu_timer_last);
        #endif /* WOLFSSL_BENCHMARK_TIMER_DEBUG */

        /* Adjust our actual returned value that takes into account overflow,
         * increment 64 bit extended total by this 32 bit differential: */
        thisIncrement = (thisVal - _esp_cpu_count_last);

        #ifdef DEBUG_WOLFSSL_BENCHMARK_TIMING
            ESP_LOGI(TAG, "thisIncrement       = %llu", thisIncrement);
        #endif

        /* Add our adjustment, taking into account overflows (see above) */
        _esp_get_cycle_count_ex += thisIncrement;

        #ifdef WOLFSSL_BENCHMARK_TIMER_DEBUG
            _xthal_get_ccount_exDiff = esp_cycle_abs_diff(_esp_get_cycle_count_ex, _xthal_get_ccount_exAlt);
            _xthal_get_ccount_exAlt += (thisTimerVal - _esp_cpu_timer_last);
            diffDiff                 = esp_cycle_abs_diff(_xthal_get_ccount_exDiff, _esp_cpu_timer_diff);
        #endif /* WOLFSSL_BENCHMARK_TIMER_DEBUG */

        /* all of this took some time, so reset the "last seen" value
         * for the next measurement. */
        #if defined(CONFIG_IDF_TARGET_ESP32C2) || \
            defined(CONFIG_IDF_TARGET_ESP32C3) || \
            defined(CONFIG_IDF_TARGET_ESP32C6)
        {
            #ifdef WOLFSSL_BENCHMARK_TIMER_DEBUG
                ESP_ERROR_CHECK(gptimer_get_raw_count(esp_gptimer,
                                                      &_esp_cpu_timer_last));
                ESP_LOGI(TAG, "thisVal                  = %llu", thisVal);
                ESP_LOGI(TAG, "thisTimerVal             = %llu", thisTimerVal);
                ESP_LOGI(TAG, "diffDiff                 = %llu", diffDiff);
                ESP_LOGI(TAG, "_xthal_get_ccount_exDiff = %llu", _xthal_get_ccount_exDiff);
            #endif /* WOLFSSL_BENCHMARK_TIMER_DEBUG */

            #if ESP_IDF_VERSION_MAJOR >= 5
                _esp_cpu_count_last = esp_cpu_get_cycle_count();
            #else
                _esp_cpu_count_last = cpu_hal_get_cycle_count();
            #endif

            ESP_LOGV(TAG, "_xthal_get_ccount_last   = %llu", _esp_cpu_count_last);
        }
        #elif defined(CONFIG_IDF_TARGET_ESP32H2)
            _esp_cpu_count_last = esp_cpu_get_cycle_count();
        #else
            /* TODO: Why doesn't esp_cpu_get_cycle_count work for Xtensa
             * when resetting CPU cycle counter? FreeRTOS tick collision?
             *    thisVal = esp_cpu_get_cycle_count(); See also, above
             * or thisVal = xthal_get_ccount(); */
            #if defined(CONFIG_IDF_TARGET_ESP8266)
                /* There's no CPU counter on the ESP8266, so we'll estimate
                 * cycles based on defined CPU frequency from sdkconfig and
                 * the RTOS tick frequency */
                _esp_cpu_count_last = (uint64_t)xTaskGetTickCount() *
                           (uint64_t)(configCPU_CLOCK_HZ / CONFIG_FREERTOS_HZ);
            #elif ESP_IDF_VERSION_MAJOR < 5
                _esp_cpu_count_last = xthal_get_ccount();
            #else
                _esp_cpu_count_last = esp_cpu_get_cycle_count();
            #endif
        #endif

        #ifdef DEBUG_WOLFSSL_BENCHMARK_TIMING
            ESP_LOGI(TAG, "_esp_cpu_count_last = %llu", _esp_cpu_count_last);
        #endif

        /* Return the 64 bit extended total from 32 bit counter. */
        return _esp_get_cycle_count_ex;
    } /* esp_get_cycle_count_ex for esp_get_cpu_benchmark_cycles() */

/* implement other architecture cycle counters here */

#else
    /* if we don't know the platform, it is unlikely we can count CPU cycles */
    #undef HAVE_GET_CYCLES

    #define INIT_CYCLE_COUNTER
    #define BEGIN_INTEL_CYCLES
    #define END_INTEL_CYCLES
    #ifdef MULTI_VALUE_STATISTICS
        #define SHOW_INTEL_CYCLES(b, n, s) WC_DO_NOTHING
        #define SHOW_INTEL_CYCLES_CSV(b, n, s) WC_DO_NOTHING
    #else
        #define SHOW_INTEL_CYCLES(b, n, s)     b[XSTRLEN(b)] = '\n'
        #define SHOW_INTEL_CYCLES_CSV(b, n, s)     b[XSTRLEN(b)] = '\n'
    #endif
#endif

/* determine benchmark buffer to use (if NO_FILESYSTEM) */
#if !defined(USE_CERT_BUFFERS_1024) && !defined(USE_CERT_BUFFERS_2048) && \
    !defined(USE_CERT_BUFFERS_3072) && !defined(USE_CERT_BUFFERS_4096)
    #define USE_CERT_BUFFERS_2048 /* default to 2048 */
#endif

#if defined(USE_CERT_BUFFERS_1024) || defined(USE_CERT_BUFFERS_2048) || \
    defined(USE_CERT_BUFFERS_3072) || defined(USE_CERT_BUFFERS_4096) || \
    !defined(NO_DH)
    /* include test cert and key buffers for use with NO_FILESYSTEM */
    #include <wolfssl/certs_test.h>
#endif

#if defined(HAVE_BLAKE2) || defined(HAVE_BLAKE2S)
    #include <wolfssl/wolfcrypt/blake2.h>
#endif

#ifdef _MSC_VER
    /* 4996 warning to use MS extensions e.g., strcpy_s instead of strncpy */
    #pragma warning(disable: 4996)
#endif

#ifdef WOLFSSL_CURRTIME_REMAP
    #define current_time WOLFSSL_CURRTIME_REMAP
#else
    double current_time(int reset);
#endif

#ifdef LINUX_RUSAGE_UTIME
    static void check_for_excessive_stime(const char *desc,
                                          const char *desc_extra);
#endif

#if !defined(WC_NO_RNG) && \
        ((!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY)) \
        || !defined(NO_DH) || defined(WOLFSSL_KEY_GEN) || defined(HAVE_ECC) \
        || defined(HAVE_CURVE25519) || defined(HAVE_ED25519) \
        || defined(HAVE_CURVE448) || defined(HAVE_ED448) \
        || defined(WOLFSSL_HAVE_KYBER))
    #define HAVE_LOCAL_RNG
    static THREAD_LS_T WC_RNG gRng;
    #define GLOBAL_RNG &gRng
#else
    #define GLOBAL_RNG NULL
#endif

#if defined(HAVE_ED25519) || defined(HAVE_CURVE25519) || \
    defined(HAVE_CURVE448) || defined(HAVE_ED448) || \
    defined(HAVE_ECC) || !defined(NO_DH) || \
    !defined(NO_RSA) || defined(HAVE_SCRYPT) || \
    defined(WOLFSSL_HAVE_KYBER) || defined(HAVE_DILITHIUM) || \
    defined(WOLFSSL_HAVE_LMS)
    #define BENCH_ASYM
#endif

#if defined(BENCH_ASYM)
#if defined(HAVE_ECC) || !defined(NO_RSA) || !defined(NO_DH) || \
    defined(HAVE_CURVE25519) || defined(HAVE_ED25519) || \
    defined(HAVE_CURVE448) || defined(HAVE_ED448) || \
    defined(WOLFSSL_HAVE_KYBER) || defined(HAVE_DILITHIUM) || \
    defined(WOLFSSL_HAVE_LMS)
static const char* bench_result_words2[][5] = {
#ifdef BENCH_MICROSECOND
    { "ops took", "μsec"     , "avg" , "ops/μsec", NULL },   /* 0 English
                                                                for μsec */
#else
    { "ops took", "sec"     , "avg" , "ops/sec", NULL },   /* 0 English  */
#endif
#ifndef NO_MULTIBYTE_PRINT
    { "回処理を", "秒で実施", "平均", "処理/秒", NULL },     /* 1 Japanese */
#endif
};
#endif
#endif

#ifdef WOLFSSL_CAAM
    #include <wolfssl/wolfcrypt/port/caam/wolfcaam.h>
    #ifdef WOLFSSL_SECO_CAAM
        #define SECO_MAX_UPDATES 10000
        #define SECO_BENCHMARK_NONCE 0x7777
        #define SECO_KEY_STORE_ID 1
    #endif

    static THREAD_LS_T int devId = WOLFSSL_CAAM_DEVID;
#else
  #ifdef WC_USE_DEVID
    static THREAD_LS_T int devId = WC_USE_DEVID;
  #else
    static THREAD_LS_T int devId = INVALID_DEVID;
  #endif
#endif

/* Asynchronous helper macros */
#ifdef WC_ENABLE_BENCH_THREADING
    typedef struct ThreadData {
        pthread_t thread_id;
    } ThreadData;
    static ThreadData* g_threadData;
    static volatile int g_threadCount;
#endif

#if defined(WOLFSSL_ASYNC_CRYPT) || defined(WOLFSSL_CAAM) || defined(WC_USE_DEVID)
    #ifndef NO_HW_BENCH
        #define BENCH_DEVID
    #endif
    #ifndef HAVE_RENESAS_SYNC
        #define BENCH_DEVID_GET_NAME(useDeviceID) (useDeviceID) ? "HW" : "SW"
    #else
        #define BENCH_DEVID_GET_NAME(useDeviceID) ""
    #endif
#else
    #define BENCH_DEVID_GET_NAME(useDeviceID) ""
#endif

#ifdef WOLFSSL_ASYNC_CRYPT
    static WOLF_EVENT_QUEUE eventQueue;

    #define BENCH_ASYNC_GET_DEV(obj)      (&(obj)->asyncDev)
    #define BENCH_MAX_PENDING             (WOLF_ASYNC_MAX_PENDING)


    static int bench_async_check(int* ret, WC_ASYNC_DEV* asyncDev,
        int callAgain, int* times, int limit, int* pending)
    {
        int allowNext = 0;

        /* this state can be set from a different thread */
        WOLF_EVENT_STATE state = asyncDev->event.state;

        /* if algo doesn't require calling again then use this flow */
        if (state == WOLF_EVENT_STATE_DONE) {
            if (callAgain) {
                /* needs called again, so allow it and handle completion in
                * bench_async_handle */
                allowNext = 1;
            }
            else {
                *ret = asyncDev->event.ret;
                asyncDev->event.state = WOLF_EVENT_STATE_READY;
                (*times)++;
                if (*pending > 0) /* to support case where async blocks */
                    (*pending)--;

                if ((*times + *pending) < limit)
                    allowNext = 1;
            }
        }

        /* if slot is available and we haven't reached limit, start another */
        else if (state == WOLF_EVENT_STATE_READY && (*times + *pending) < limit) {
            allowNext = 1;
        }

        return allowNext;
    }

    static int bench_async_handle(int* ret, WC_ASYNC_DEV* asyncDev,
        int callAgain, int* times, int* pending)
    {
        WOLF_EVENT_STATE state = asyncDev->event.state;

        if (*ret == WC_NO_ERR_TRACE(WC_PENDING_E)) {
            if (state == WOLF_EVENT_STATE_DONE) {
                *ret = asyncDev->event.ret;
                asyncDev->event.state = WOLF_EVENT_STATE_READY;
                (*times)++;
                (*pending)--;
            }
            else {
                (*pending)++;
                *ret = wc_AsyncHandle(asyncDev, &eventQueue,
                    callAgain ? WC_ASYNC_FLAG_CALL_AGAIN : WC_ASYNC_FLAG_NONE);
            }
        }
        else if (*ret >= 0) {
            *ret = asyncDev->event.ret;
            asyncDev->event.state = WOLF_EVENT_STATE_READY;
            (*times)++;
            if (*pending > 0)  /* to support case where async blocks */
                (*pending)--;
        }

        return (*ret >= 0) ? 1 : 0;
    }

    static WC_INLINE int bench_async_poll(int* pending)
    {
        int ret, asyncDone = 0;

        ret = wolfAsync_EventQueuePoll(&eventQueue, NULL, NULL, 0,
                                       WOLF_POLL_FLAG_CHECK_HW, &asyncDone);
        if (ret != 0) {
            printf("%sAsync poll failed %d\n", err_prefix, ret);
            return ret;
        }

        if (asyncDone == 0) {
        #ifndef WC_NO_ASYNC_THREADING
            /* give time to other threads */
            wc_AsyncThreadYield();
        #endif
        }

        (void)pending;

        return asyncDone;
    }

#else
    #define BENCH_MAX_PENDING             1
    #define BENCH_ASYNC_GET_DEV(obj)      NULL

    static WC_INLINE int bench_async_check(int* ret, void* asyncDev,
        int callAgain, int* times, int limit, int* pending)
    {
        (void)ret;
        (void)asyncDev;
        (void)callAgain;
        (void)times;
        (void)limit;
        (void)pending;

        return 1;
    }

    static WC_INLINE int bench_async_handle(int* ret, void* asyncDev,
        int callAgain, int* times, int* pending)
    {
        (void)asyncDev;
        (void)callAgain;
        (void)pending;

        if (*ret >= 0) {
            /* operation completed */
            (*times)++;
            return 1;
        }
        return 0;
    }
    #define bench_async_poll(p) WC_DO_NOTHING
#endif /* WOLFSSL_ASYNC_CRYPT */



/* maximum runtime for each benchmark */
#ifndef BENCH_MIN_RUNTIME_SEC
    #define BENCH_MIN_RUNTIME_SEC   1.0F
#endif

#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
    #define AES_AUTH_TAG_SZ 16
    #define BENCH_CIPHER_ADD AES_AUTH_TAG_SZ
    static word32 aesAuthAddSz = AES_AUTH_ADD_SZ;
    #if !defined(AES_AAD_OPTIONS_DEFAULT)
        #if !defined(NO_MAIN_DRIVER)
            #define AES_AAD_OPTIONS_DEFAULT 0x1U
        #else
            #define AES_AAD_OPTIONS_DEFAULT 0x3U
        #endif
    #endif
    #define AES_AAD_STRING(s) \
        (aesAuthAddSz == 0 ? (s "-no_AAD") : \
            (aesAuthAddSz == AES_AUTH_ADD_SZ ? (s) : (s "-custom")))
    enum en_aad_options {
        AAD_SIZE_DEFAULT = 0x1U,
        AAD_SIZE_ZERO = 0x2U,
        AAD_SIZE_CUSTOM = 0x4U,
    };
    static word32 aes_aad_options = AES_AAD_OPTIONS_DEFAULT;
    static word32 aes_aad_size = 0;
    static void bench_aes_aad_options_wrap(void (*fn)(int), int i)
    {
        word32 aesAuthAddSz_orig = aesAuthAddSz;
        word32 options = aes_aad_options;
        while(options) {
            if (options & AAD_SIZE_DEFAULT) {
                aesAuthAddSz = AES_AUTH_ADD_SZ;
                options &= ~(word32)AAD_SIZE_DEFAULT;
            }
            else if (options & AAD_SIZE_ZERO) {
                aesAuthAddSz = 0;
                options &= ~(word32)AAD_SIZE_ZERO;
            }
            else if (options & AAD_SIZE_CUSTOM) {
                aesAuthAddSz = aes_aad_size;
                options &= ~(word32)AAD_SIZE_CUSTOM;
            }
            fn(i);
            aesAuthAddSz = aesAuthAddSz_orig;
        }
    }
#endif

#ifndef BENCH_CIPHER_ADD
    #define BENCH_CIPHER_ADD 0
#endif



#if defined(WOLFSSL_DEVCRYPTO) && defined(WOLFSSL_AUTHSZ_BENCH)
    #warning Large/Unalligned AuthSz could result in errors with /dev/crypto
#endif

/* use kB instead of mB for embedded benchmarking */
#ifdef BENCH_EMBEDDED
    #ifndef BENCH_NTIMES
    #define BENCH_NTIMES 2
    #endif
    #ifndef BENCH_AGREETIMES
    #define BENCH_AGREETIMES 2
    #endif
    enum BenchmarkBounds {
        scryptCnt  = 1,
        ntimes     = BENCH_NTIMES,
        genTimes   = BENCH_MAX_PENDING,
        agreeTimes = BENCH_AGREETIMES
    };
    /* how many kB to test (en/de)cryption */
    #define NUM_BLOCKS 25
    #define BENCH_SIZE (1024uL)
#else
    #ifndef BENCH_NTIMES
    #define BENCH_NTIMES 100
    #endif
    #ifndef BENCH_AGREETIMES
    #define BENCH_AGREETIMES 100
    #endif
    enum BenchmarkBounds {
        scryptCnt  = 10,
        ntimes     = BENCH_NTIMES,
        genTimes   = BENCH_MAX_PENDING, /* must be at least BENCH_MAX_PENDING */
        agreeTimes = BENCH_AGREETIMES
    };
    /* how many megs to test (en/de)cryption */
    #define NUM_BLOCKS 5
    #define BENCH_SIZE (1024*1024uL)
#endif

static int    numBlocks  = NUM_BLOCKS;
static word32 bench_size = BENCH_SIZE;
static int base2 = 1;
static int digest_stream = 1;
#ifdef HAVE_CHACHA
static int encrypt_only = 0;
#endif
#ifdef HAVE_AES_CBC
static int cipher_same_buffer = 0;
#endif

#ifdef MULTI_VALUE_STATISTICS
static int minimum_runs = 0;
#endif

#ifndef NO_RSA
    /* Don't measure RSA sign/verify by default */
    static int rsa_sign_verify = 0;
#endif

#ifndef NO_DH
    /* Use the FFDHE parameters */
    static int use_ffdhe = 0;
#endif

/* Don't print out in CSV format by default */
static int csv_format = 0;

#ifdef WOLFSSL_XILINX_CRYPT_VERSAL
    /* Versal PLM maybe prints an error message to the same console.
     * In order to not mix those outputs up, sleep a little while
     * before erroring out.
     */
    #define SLEEP_ON_ERROR(ret) do{ if (ret != 0) { sleep(1); } }while(0)
#else
    #define SLEEP_ON_ERROR(ret) do{ /* noop */ }while(0)
#endif

/* globals for cipher tests */
static THREAD_LS_T byte* bench_plain = NULL;
static THREAD_LS_T byte* bench_cipher = NULL;
#ifndef NO_FILESYSTEM
static THREAD_LS_T char* hash_input = NULL;
static THREAD_LS_T char* cipher_input = NULL;
#endif

static const XGEN_ALIGN byte bench_key_buf[] =
{
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    0xfe,0xde,0xba,0x98,0x76,0x54,0x32,0x10,
    0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67,
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
    0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff,
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
};

static const XGEN_ALIGN byte bench_iv_buf[] =
{
    0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef,
    0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
    0x11,0x21,0x31,0x41,0x51,0x61,0x71,0x81
};
static THREAD_LS_T byte* bench_key = NULL;
static THREAD_LS_T byte* bench_iv = NULL;
#ifdef HAVE_RENESAS_SYNC
static THREAD_LS_T byte* bench_key1 = NULL;
static THREAD_LS_T byte* bench_key2 = NULL;
#endif
#ifdef WOLFSSL_STATIC_MEMORY
    #ifdef WOLFSSL_STATIC_MEMORY_TEST_SZ
        static byte gBenchMemory[WOLFSSL_STATIC_MEMORY_TEST_SZ];
    #elif defined(BENCH_EMBEDDED)
        static byte gBenchMemory[50000];
    #else
        static byte gBenchMemory[400000];
    #endif
#endif


/* This code handles cases with systems where static (non cost) ram variables
    aren't properly initialized with data */
static void benchmark_static_init(int force)
{
    static int gBenchStaticInit = 0;
    if (gBenchStaticInit == 0 || force) {
        gBenchStaticInit = 1;

        /* Init static variables */
        numBlocks  = NUM_BLOCKS;
        bench_size = BENCH_SIZE;
    #if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
        aesAuthAddSz    = AES_AUTH_ADD_SZ;
        aes_aad_options = AES_AAD_OPTIONS_DEFAULT;
        aes_aad_size    = 0;
    #endif
        base2 = 1;
        digest_stream = 1;
    #ifdef MULTI_VALUE_STATISTICS
        minimum_runs = 0;
    #endif

        bench_all = 1;
        bench_cipher_algs = 0;
        bench_digest_algs = 0;
        bench_mac_algs = 0;
        bench_kdf_algs = 0;
        bench_asym_algs = 0;
        bench_pq_asym_algs = 0;
        bench_other_algs = 0;
        bench_pq_hash_sig_algs = 0;
        csv_format = 0;
    }
}



/*****************************************************************************/
/* Begin Stats Functions                                                     */
/*****************************************************************************/
typedef enum bench_stat_type {
    BENCH_STAT_ASYM,
    BENCH_STAT_SYM,
    BENCH_STAT_IGNORE,
} bench_stat_type_t;

#ifdef WC_BENCH_TRACK_STATS
    static int gPrintStats = 0;
    #ifdef WC_ENABLE_BENCH_THREADING
        static pthread_mutex_t bench_lock = PTHREAD_MUTEX_INITIALIZER;
    #endif
    #ifndef BENCH_MAX_NAME_SZ
    #define BENCH_MAX_NAME_SZ 24
    #endif
    typedef struct bench_stats {
        struct bench_stats* next;
        struct bench_stats* prev;
        char algo[BENCH_MAX_NAME_SZ+1]; /* may not be static, so make copy */
        const char* desc;
        double perfsec;
        int strength;
        int useDeviceID;
        int finishCount;
        bench_stat_type_t type;
        int lastRet;
        const char* perftype;
    } bench_stats_t;
    static bench_stats_t* bench_stats_head;
    static bench_stats_t* bench_stats_tail;

    static bench_stats_t* bench_stats_add(bench_stat_type_t type,
        const char* algo, int strength, const char* desc, int useDeviceID,
        double perfsec, const char* perftype, int ret)
    {
        bench_stats_t* bstat = NULL;

    #ifdef WC_ENABLE_BENCH_THREADING
        /* protect bench_stats_head and bench_stats_tail access */
        THREAD_CHECK_RET(pthread_mutex_lock(&bench_lock));
    #endif

        if (algo != NULL) {
            /* locate existing in list */
            for (bstat = bench_stats_head; bstat != NULL; bstat = bstat->next) {
                /* match based on algo, strength and desc */
                if (XSTRNCMP(bstat->algo, algo, BENCH_MAX_NAME_SZ) == 0 &&
                    bstat->strength == strength &&
                    bstat->desc == desc &&
                    bstat->useDeviceID == useDeviceID) {
                    break;
                }
            }
        }

        if (bstat == NULL) {
            /* allocate new and put on list */
            bstat = (bench_stats_t*)XMALLOC(sizeof(bench_stats_t), NULL,
                DYNAMIC_TYPE_INFO);
            if (bstat) {
                XMEMSET(bstat, 0, sizeof(bench_stats_t));

                /* add to list */
                bstat->next = NULL;
                if (bench_stats_tail == NULL)  {
                    bench_stats_head = bstat;
                }
                else {
                    bench_stats_tail->next = bstat;
                    bstat->prev = bench_stats_tail;
                }
                bench_stats_tail = bstat; /* add to the end either way */
            }
        }
        if (bstat) {
            bstat->type = type;
            if (algo != NULL)
                XSTRNCPY(bstat->algo, algo, BENCH_MAX_NAME_SZ);
            bstat->strength = strength;
            bstat->desc = desc;
            bstat->useDeviceID = useDeviceID;
            bstat->perfsec += perfsec;
            bstat->finishCount++;
            bstat->perftype = perftype;
            if (bstat->lastRet > ret)
                bstat->lastRet = ret; /* track last error */
        }
    #ifdef WC_ENABLE_BENCH_THREADING
        THREAD_CHECK_RET(pthread_mutex_unlock(&bench_lock));
    #endif
        return bstat;
    }

    void bench_stats_print(void)
    {
        bench_stats_t* bstat;
        int digits;

    #ifdef WC_ENABLE_BENCH_THREADING
        /* protect bench_stats_head and bench_stats_tail access */
        THREAD_CHECK_RET(pthread_mutex_lock(&bench_lock));
    #endif

    #ifdef BENCH_MICROSECOND
        digits = 5;
    #else
        digits = 3;
    #endif

        for (bstat = bench_stats_head; bstat != NULL; ) {
            if (bstat->type == BENCH_STAT_SYM) {
                printf("%-16s%s " FLT_FMT_PREC2 " %s/" WOLFSSL_FIXED_TIME_UNIT
                    "\n", bstat->desc,
                    BENCH_DEVID_GET_NAME(bstat->useDeviceID),
                    FLT_FMT_PREC2_ARGS(8, digits, bstat->perfsec),
                    base2 ? "MB" : "mB");
            }
            else {
                printf("%-5s %4d %-9s %s " FLT_FMT_PREC " ops/"
                    WOLFSSL_FIXED_TIME_UNIT "ec\n",
                    bstat->algo, bstat->strength, bstat->desc,
                    BENCH_DEVID_GET_NAME(bstat->useDeviceID),
                    FLT_FMT_PREC_ARGS(digits, bstat->perfsec));
            }

            bstat = bstat->next;
        }

    #ifdef WC_ENABLE_BENCH_THREADING
        THREAD_CHECK_RET(pthread_mutex_unlock(&bench_lock));
    #endif
    }
#endif /* WC_BENCH_TRACK_STATS */

static WC_INLINE void bench_stats_init(void)
{
#ifdef WC_BENCH_TRACK_STATS
    bench_stats_head = NULL;
    bench_stats_tail = NULL;
#endif
    INIT_CYCLE_COUNTER
}

static WC_INLINE void bench_stats_start(int* count, double* start)
{
    *count = 0;
    *start = current_time(1);

#ifdef WOLFSSL_ESPIDF
    #ifdef DEBUG_WOLFSSL_BENCHMARK_TIMING
        ESP_LOGI(TAG, "bench_stats_start total_cycles = %llu"
                      ", start=" FLT_FMT,
                      total_cycles, FLT_FMT_ARGS(*start) );
    #endif
    BEGIN_ESP_CYCLES
#else
    BEGIN_INTEL_CYCLES
#endif
}

#ifdef WOLFSSL_LINUXKM_USE_SAVE_VECTOR_REGISTERS
    #define bench_stats_start(count, start) do {                               \
        SAVE_VECTOR_REGISTERS(pr_err(                                          \
            "SAVE_VECTOR_REGISTERS failed for benchmark run.");                \
                              return; );                                       \
        bench_stats_start(count, start);                                       \
    } while (0)
#endif

static WC_INLINE int bench_stats_check(double start)
{
    int ret = 0;
    double this_current_time = 0.0;
    this_current_time = current_time(0); /* get the timestamp, no reset */

#if defined(DEBUG_WOLFSSL_BENCHMARK_TIMING) && defined(WOLFSSL_ESPIDF)
    #if defined(WOLFSSL_ESPIDF)
        ESP_LOGI(TAG, "bench_stats_check Current time = %f, start = %f",
                       this_current_time, start );
    #endif
#endif

    ret = ((this_current_time - start) < BENCH_MIN_RUNTIME_SEC
#ifdef BENCH_MICROSECOND
            * 1000000
#endif
           );

    return ret;
}

/* return text for units and scale the value of blocks as needed */
static const char* get_blocktype(double* blocks)
{
    const char* rt;

#if (  defined(WOLFSSL_BENCHMARK_FIXED_UNITS_G) || \
       defined(WOLFSSL_BENCHMARK_FIXED_UNITS_GB))
    #undef  WOLFSSL_FIXED_UNIT
    #define WOLFSSL_FIXED_UNIT "GB"
    *blocks /= (1024UL * 1024UL * 1024UL);
    rt = "GiB";
#elif (defined(WOLFSSL_BENCHMARK_FIXED_UNITS_M) || \
       defined(WOLFSSL_BENCHMARK_FIXED_UNITS_MB))
    #undef  WOLFSSL_FIXED_UNIT
    #define WOLFSSL_FIXED_UNIT "MB"
    *blocks /= (1024UL * 1024UL);
    rt = "MiB";
#elif (defined(WOLFSSL_BENCHMARK_FIXED_UNITS_K) || \
       defined(WOLFSSL_BENCHMARK_FIXED_UNITS_KB))
    #undef  WOLFSSL_FIXED_UNIT
    #define WOLFSSL_FIXED_UNIT "KB"
    *blocks /= 1024;
    rt = "KiB";
#elif  defined (WOLFSSL_BENCHMARK_FIXED_UNITS_B)
    #undef  WOLFSSL_FIXED_UNIT
    #define WOLFSSL_FIXED_UNIT "bytes"
    (void)(*blocks); /* no adjustment, just appease compiler for not used */
    rt = "bytes";
#else
    /* If no user-specified, auto-scale each metric (results vary).
     * Determine if we should show as KB or MB or bytes. No GiB here. */
    if (*blocks > (1024UL * 1024UL)) {
        *blocks /= (1024UL * 1024UL);
        rt = "MiB";
    }
    else if (*blocks > 1024) {
        *blocks /= 1024;
        rt = "KiB";
    }
    else {
        rt = "bytes";
    }
#endif

    return rt;
}

/* return text for units and scale the value of blocks as needed for base2 */
static const char* get_blocktype_base10(double* blocks)
{
    const char* rt;

#if (  defined(WOLFSSL_BENCHMARK_FIXED_UNITS_G) || \
       defined(WOLFSSL_BENCHMARK_FIXED_UNITS_GB))
    *blocks /= (1000UL * 1000UL * 1000UL);
    rt = "GB";
#elif (defined(WOLFSSL_BENCHMARK_FIXED_UNITS_M) || \
       defined(WOLFSSL_BENCHMARK_FIXED_UNITS_MB))
    *blocks /= (1000UL * 1000UL);
    rt = "MB";
#elif (defined(WOLFSSL_BENCHMARK_FIXED_UNITS_K) || \
       defined(WOLFSSL_BENCHMARK_FIXED_UNITS_KB))
    *blocks /= (1000UL);
    rt = "KB";
#elif     defined (WOLFSSL_BENCHMARK_FIXED_UNITS_B)
    (void)(*blocks); /* no adjustment, just appease compiler */
    rt = "bytes";
#else
    /* If not user-specified, auto-scale each metric (results vary).
     * Determine if we should show as KB or MB or bytes */
    if (*blocks > (1000UL * 1000UL)) {
        *blocks /= (1000UL * 1000UL);
        rt = "MB";
    }
    else if (*blocks > 1000) {
        *blocks /= 1000; /* make KB */
        rt = "KB";
    }
    else {
        rt = "bytes";
    }
#endif

    return rt;
}

#ifdef MULTI_VALUE_STATISTICS
static double wc_sqroot(double in)
{
    /* do 32 iterations for the sqroot */
    int iter = 32;
    double root = in/3.0;

    if (in < 0.0)
        return -1;

    for (int i=0; i < iter; i++)
        root = (root + in / root) / 2.0;

    return root;
}

static void bench_multi_value_stats(double max, double min, double sum,
        double squareSum, int runs)
{
    double mean = 0;
    double sd   = 0;
    char   msg[WC_BENCH_MAX_LINE_LEN];
    const char** word = bench_result_words3[lng_index];

    XMEMSET(msg, 0, sizeof(msg));

    mean = sum / runs;

    /* Calculating standard deviation */
    sd = (squareSum / runs) - (mean * mean);
    sd = wc_sqroot(sd);

    if (csv_format == 1) {
        (void)XSNPRINTF(msg, sizeof(msg), FLT_FMT_PREC2 ","
                FLT_FMT_PREC2 "," FLT_FMT_PREC2 "," FLT_FMT_PREC2 ",\n",
                FLT_FMT_PREC2_ARGS(3, 3, max),
                FLT_FMT_PREC2_ARGS(3, 3, min),
                FLT_FMT_PREC2_ARGS(3, 3, mean),
                FLT_FMT_PREC2_ARGS(3, 3, sd));
    }
    else{
        (void)XSNPRINTF(msg, sizeof(msg), ", %s " FLT_FMT_PREC2 " "
                WOLFSSL_FIXED_TIME_UNIT ", %s " FLT_FMT_PREC2 " "
                WOLFSSL_FIXED_TIME_UNIT ", %s " FLT_FMT_PREC2 " "
                WOLFSSL_FIXED_TIME_UNIT ", %s " FLT_FMT_PREC2 " "
                WOLFSSL_FIXED_TIME_UNIT "\n",
                word[0], FLT_FMT_PREC2_ARGS(3, 3, max),
                word[1], FLT_FMT_PREC2_ARGS(3, 3, min),
                word[2], FLT_FMT_PREC2_ARGS(3, 3, mean),
                word[3], FLT_FMT_PREC2_ARGS(3, 3, sd));
    }
    printf("%s", msg);

#ifndef WOLFSSL_SGX
    XFFLUSH(stdout);
#endif

}
#endif

/* countSz is number of bytes that 1 count represents. Normally bench_size,
 * except for AES direct that operates on WC_AES_BLOCK_SIZE blocks */
static void bench_stats_sym_finish(const char* desc, int useDeviceID,
                                   int count, word32 countSz,
                                   double start, int ret)
{
    double total, persec = 0, blocks = (double)count;
    const char* blockType;
    char msg[WC_BENCH_MAX_LINE_LEN];
    const char** word = bench_result_words1[lng_index];
    static int sym_header_printed = 0;

    XMEMSET(msg, 0, sizeof(msg));

#ifdef WOLFSSL_ESPIDF
    END_ESP_CYCLES
#else
    END_INTEL_CYCLES
#endif

    total = current_time(0) - start;

#if defined(WOLFSSL_ESPIDF) && defined(DEBUG_WOLFSSL_BENCHMARK_TIMING)
    ESP_LOGI(TAG, "%s total_cycles = %llu", desc, total_cycles);
#endif

#ifdef LINUX_RUSAGE_UTIME
    check_for_excessive_stime(desc, "");
#endif

    /* calculate actual bytes */
    blocks *= countSz;
    if (csv_format == 1) {
        /* only print out header once */
        if (sym_header_printed == 0) {

#ifdef GENERATE_MACHINE_PARSEABLE_REPORT
    /* machine parseable CSV */
    #ifdef HAVE_GET_CYCLES
            printf("%s", "\"sym\",Algorithm,HW/SW,bytes_total,"
                WOLFSSL_FIXED_TIME_UNIT "econds_total,"
                WOLFSSL_FIXED_UNIT "/" WOLFSSL_FIXED_TIME_UNIT
                ",cycles_total,Cycles per byte,");
    #else
            printf("%s", "\"sym\",Algorithm,HW/SW,bytes_total,"
                WOLFSSL_FIXED_TIME_UNIT "econds_total,"
                WOLFSSL_FIXED_UNIT "/" WOLFSSL_FIXED_TIME_UNIT
                ",cycles_total,");
    #endif
#else
    /* normal CSV */
    #ifdef BENCH_DEVID
        #define BENCH_DEVID_COLUMN_HEADER "HW/SW,"
    #else
        #define BENCH_DEVID_COLUMN_HEADER
    #endif
    #ifdef HAVE_GET_CYCLES
            printf("\n\nSymmetric Ciphers:\n\n");
            printf("Algorithm,"
               BENCH_DEVID_COLUMN_HEADER
               WOLFSSL_FIXED_UNIT "/" WOLFSSL_FIXED_TIME_UNIT
               ",Cycles per byte,");
    #else
            printf("\n\nSymmetric Ciphers:\n\n");
            printf("Algorithm,"
               BENCH_DEVID_COLUMN_HEADER
               WOLFSSL_FIXED_UNIT "/" WOLFSSL_FIXED_TIME_UNIT ",");
    #endif
#endif
        #ifdef MULTI_VALUE_STATISTICS
            printf("max duration,min duration,mean duration,sd,\n");
        #else
            printf("\n");
        #endif
            sym_header_printed = 1;
        }
    }

    /* determine if we have fixed units, or auto-scale bits or bytes for units.
     * note that the blockType text is assigned AND the blocks param is scaled.
     */
    if (base2) {
        blockType = get_blocktype(&blocks);
    }
    else {
        blockType = get_blocktype_base10(&blocks);
    }

    /* calculate blocks per second */
    if (total > 0) {
        persec = (1 / total) * blocks;
    }

    SLEEP_ON_ERROR(ret);
    /* format and print to terminal */
    if (csv_format == 1) {

#ifdef GENERATE_MACHINE_PARSEABLE_REPORT
    #ifdef WOLFSSL_ESPIDF
        unsigned long bytes_processed =
            (unsigned long)count * (unsigned long)countSz;
    #else
        word64 bytes_processed = (word64)count * (word64)countSz;
    #endif

    /* note this codepath brings in all the fields from the non-CSV case. */
    #ifdef WOLFSSL_ESPIDF
        #ifdef HAVE_GET_CYCLES
            (void)XSNPRINTF(msg, sizeof(msg),
                            "sym,%s,%s,%lu," FLT_FMT "," FLT_FMT ",%lu,", desc,
                            BENCH_DEVID_GET_NAME(useDeviceID),
                            bytes_processed, FLT_FMT_ARGS(total),
                            FLT_FMT_ARGS(persec),
                            (long unsigned int) total_cycles);
        #else
            #warning "HAVE_GET_CYCLES should be defined for WOLFSSL_ESPIDF"
        #endif

    /* implement other architectures here */

    #else
        #ifdef HAVE_GET_CYCLES
            (void)XSNPRINTF(msg, sizeof(msg),
                            "sym,%s,%s,%lu," FLT_FMT "," FLT_FMT ",%lu,", desc,
                            BENCH_DEVID_GET_NAME(useDeviceID),
                            bytes_processed, FLT_FMT_ARGS(total),
                            FLT_FMT_ARGS(persec), total_cycles);
        #else
            (void)XSNPRINTF(msg, sizeof(msg),
                            "sym,%s,%s,%lu," FLT_FMT "," FLT_FMT ",", desc,
                            BENCH_DEVID_GET_NAME(useDeviceID),
                            bytes_processed, FLT_FMT_ARGS(total),
                            FLT_FMT_ARGS(persec));
        #endif
    #endif
#elif defined(BENCH_DEVID)
        (void)XSNPRINTF(msg, sizeof(msg), "%s,%s," FLT_FMT ",", desc,
                       BENCH_DEVID_GET_NAME(useDeviceID), FLT_FMT_ARGS(persec));
#else
        (void)XSNPRINTF(msg, sizeof(msg), "%s," FLT_FMT ",", desc,
            FLT_FMT_ARGS(persec));
#endif

    #ifdef WOLFSSL_ESPIDF
        SHOW_ESP_CYCLES_CSV(msg, sizeof(msg), countSz);
        #ifdef DEBUG_WOLFSSL_BENCHMARK_TIMING
            ESP_LOGI(TAG, "bench_stats_sym_finish total_cycles = %llu",
                           total_cycles);
        #endif

        /* implement other cycle counters here */

    #else
        /* the default cycle counter is Intel */
        SHOW_INTEL_CYCLES_CSV(msg, sizeof(msg), (unsigned)countSz);
    #endif
    } /* if (csv_format == 1) */

    else {
#ifdef GENERATE_MACHINE_PARSEABLE_REPORT
    #ifdef HAVE_GET_CYCLES
        (void)XSNPRINTF(msg, sizeof(msg),
            "%-24s%s " FLT_FMT_PREC2 " %s %s " FLT_FMT_PREC2 " %s, "
            FLT_FMT_PREC2 " %s/" WOLFSSL_FIXED_TIME_UNIT ", %lu cycles,",
            desc, BENCH_DEVID_GET_NAME(useDeviceID),
            FLT_FMT_PREC2_ARGS(5, 0, blocks), blockType,
            word[0], FLT_FMT_PREC2_ARGS(5, 3, total), word[1],
            FLT_FMT_PREC2_ARGS(8, 3, persec), blockType,
             (unsigned long) total_cycles);
  #else
        (void)XSNPRINTF(msg, sizeof(msg),
                "%-24s%s " FLT_FMT_PREC2 " %s %s " FLT_FMT_PREC2 " %s, "
                FLT_FMT_PREC2 " %s/" WOLFSSL_FIXED_TIME_UNIT ",",
                desc, BENCH_DEVID_GET_NAME(useDeviceID),
                FLT_FMT_PREC2_ARGS(5, 0, blocks), blockType,
                word[0], FLT_FMT_PREC2_ARGS(5, 3, total), word[1],
                FLT_FMT_PREC2_ARGS(8, 3, persec), blockType);
  #endif /* HAVE_GET_CYCLES */
#else
        (void)XSNPRINTF(msg, sizeof(msg),
                "%-24s%s " FLT_FMT_PREC2 " %s %s " FLT_FMT_PREC2 " %s, "
                FLT_FMT_PREC2 " %s/" WOLFSSL_FIXED_TIME_UNIT,
                desc, BENCH_DEVID_GET_NAME(useDeviceID),
                FLT_FMT_PREC2_ARGS(5, 0, blocks), blockType,
                word[0], FLT_FMT_PREC2_ARGS(5, 3, total), word[1],
                FLT_FMT_PREC2_ARGS(8, 3, persec), blockType);
#endif

#ifdef WOLFSSL_ESPIDF
        SHOW_ESP_CYCLES(msg, sizeof(msg), countSz);

/* implement other architecture cycle counters here */

#else
        SHOW_INTEL_CYCLES(msg, sizeof(msg), (unsigned)countSz);
#endif
    } /* not CSV format */

    printf("%s", msg);

    /* show errors */
    if (ret < 0) {
        printf("%sBenchmark %s failed: %d\n", err_prefix, desc, ret);
    }

#ifndef WOLFSSL_SGX
    XFFLUSH(stdout);
#endif

#ifdef WC_BENCH_TRACK_STATS
    /* Add to thread stats */
    bench_stats_add(BENCH_STAT_SYM, desc, 0, desc, useDeviceID, persec,
        blockType, ret);
#endif

    (void)useDeviceID;
    (void)ret;

#ifdef WOLFSSL_LINUXKM_USE_SAVE_VECTOR_REGISTERS
    RESTORE_VECTOR_REGISTERS();
#endif

    TEST_SLEEP();
} /* bench_stats_sym_finish */

#ifdef BENCH_ASYM
#if defined(HAVE_ECC) || !defined(NO_RSA) || !defined(NO_DH) || \
    defined(HAVE_CURVE25519) || defined(HAVE_ED25519) || \
    defined(HAVE_CURVE448) || defined(HAVE_ED448) || \
    defined(WOLFSSL_HAVE_KYBER) || defined(HAVE_DILITHIUM) || \
    defined(WOLFSSL_HAVE_LMS)
static void bench_stats_asym_finish_ex(const char* algo, int strength,
    const char* desc, const char* desc_extra, int useDeviceID, int count,
    double start, int ret)
{
    double total, each = 0, opsSec, milliEach;
    const char **word = bench_result_words2[lng_index];
#ifdef WC_BENCH_TRACK_STATS
    const char* kOpsSec = "Ops/Sec";
#endif
    char msg[256];
    static int asym_header_printed = 0;
#ifdef BENCH_MICROSECOND
    const int digits = 5;
#else
    const int digits = 3;
#endif

    XMEMSET(msg, 0, sizeof(msg));

    total = current_time(0) - start;

#ifdef LINUX_RUSAGE_UTIME
    check_for_excessive_stime(desc, desc_extra);
#endif

#ifdef GENERATE_MACHINE_PARSEABLE_REPORT
    #ifdef WOLFSSL_ESPIDF
        END_ESP_CYCLES
    #else
        END_INTEL_CYCLES
    #endif
#endif

    /* some sanity checks on the final numbers */
    if (count > 0) {
        each  = total / count; /* per second  */
    }
    else {
        count = 0;
        each = 0;
    }

    if (total > 0) {
        opsSec = count / total;    /* ops second */
    }
    else {
        opsSec = 0;
    }

#ifdef BENCH_MICROSECOND
    milliEach = each / 1000;   /* milliseconds */
#else
    milliEach = each * 1000;   /* milliseconds */
#endif

    SLEEP_ON_ERROR(ret);

#ifdef MULTI_VALUE_STATISTICS  /* Print without avg ms */
    (void)milliEach;

    /* format and print to terminal */
    if (csv_format == 1) {
        /* only print out header once */
        if (asym_header_printed == 0) {
#ifdef GENERATE_MACHINE_PARSEABLE_REPORT
    #ifdef HAVE_GET_CYCLES
            printf("%s", "\"asym\",Algorithm,key size,operation,ops/"
                    WOLFSSL_FIXED_TIME_UNIT "ec,ops," WOLFSSL_FIXED_TIME_UNIT
                    "ecs,cycles,cycles/op,");
    #else
            printf("%s", "\"asym\",Algorithm,key size,operation,ops/"
                    WOLFSSL_FIXED_TIME_UNIT "ec,ops," WOLFSSL_FIXED_TIME_UNIT
                    "ecs,");
    #endif
#else
            printf("\n%sAsymmetric Ciphers:\n\n", info_prefix);
            printf("%sAlgorithm,key size,operation,ops/"
                    WOLFSSL_FIXED_TIME_UNIT "ec,", info_prefix);
#endif
            printf("max duration,min duration,mean duration,sd,\n");
            asym_header_printed = 1;
        }
#ifdef GENERATE_MACHINE_PARSEABLE_REPORT
    #ifdef HAVE_GET_CYCLES
        (void)XSNPRINTF(msg, sizeof(msg),
                        "asym,%s,%d,%s%s," FLT_FMT_PREC ",%d,"
                        FLT_FMT ",%lu," FLT_FMT_PREC STATS_CLAUSE_SEPARATOR,
                        algo, strength, desc, desc_extra,
                        FLT_FMT_PREC_ARGS(digits, opsSec),
                        count, FLT_FMT_ARGS(total), (unsigned long)total_cycles,
                        FLT_FMT_PREC_ARGS(6,
                            (double)total_cycles / (double)count));
    #else
        (void)XSNPRINTF(msg, sizeof(msg),
                        "asym,%s,%d,%s%s," FLT_FMT_PREC ",%d,"
                        FLT_FMT STATS_CLAUSE_SEPARATOR,
                        algo, strength, desc, desc_extra,
                        FLT_FMT_PREC_ARGS(digits, opsSec),
                        count, FLT_FMT_ARGS(total));
    #endif
#else
        (void)XSNPRINTF(msg, sizeof(msg), "%s,%d,%s%s,"
                        FLT_FMT_PREC "," STATS_CLAUSE_SEPARATOR,
                        algo, strength, desc, desc_extra,
                        FLT_FMT_PREC_ARGS(digits, opsSec));
#endif
    } /* if (csv_format == 1) */

    else {
#ifdef GENERATE_MACHINE_PARSEABLE_REPORT
    #ifdef HAVE_GET_CYCLES
        (void)XSNPRINTF(msg, sizeof(msg),
                        "%-6s %5d %8s%-2s %s %6d %s " FLT_FMT_PREC2 " %s, "
                        FLT_FMT_PREC " %s, %lu cycles" STATS_CLAUSE_SEPARATOR,
                        algo, strength, desc, desc_extra,
                        BENCH_DEVID_GET_NAME(useDeviceID), count, word[0],
                        FLT_FMT_PREC2_ARGS(5, 3, total), word[1],
                        FLT_FMT_PREC_ARGS(digits, opsSec), word[3],
                        (unsigned long)total_cycles);
    #else
        (void)XSNPRINTF(msg, sizeof(msg),
                        "%-6s %5d %8s%-2s %s %6d %s " FLT_FMT_PREC2 " %s, "
                        FLT_FMT_PREC " %s" STATS_CLAUSE_SEPARATOR,
                        algo, strength, desc, desc_extra,
                        BENCH_DEVID_GET_NAME(useDeviceID), count, word[0],
                        FLT_FMT_PREC2_ARGS(5, 3, total), word[1],
                        FLT_FMT_PREC_ARGS(digits, opsSec), word[3]);
    #endif /* HAVE_GET_CYCLES */
#else
        (void)XSNPRINTF(msg, sizeof(msg),
                        "%-6s %5d %8s%-2s %s %6d %s " FLT_FMT_PREC2 " %s, "
                        FLT_FMT_PREC " %s" STATS_CLAUSE_SEPARATOR,
                        algo, strength, desc, desc_extra,
                        BENCH_DEVID_GET_NAME(useDeviceID), count, word[0],
                        FLT_FMT_PREC2_ARGS(5, 3, total), word[1],
                        FLT_FMT_PREC_ARGS(digits, opsSec), word[3]);
#endif
    }
#else /* MULTI_VALUE_STATISTICS. Print with avg ms */
    /* format and print to terminal */
    if (csv_format == 1) {
        /* only print out header once */
        if (asym_header_printed == 0) {
#ifdef GENERATE_MACHINE_PARSEABLE_REPORT
    #ifdef HAVE_GET_CYCLES
            printf("%s", "\"asym\",Algorithm,key size,operation,avg ms,ops/"
                    WOLFSSL_FIXED_TIME_UNIT "ec,ops," WOLFSSL_FIXED_TIME_UNIT
                    "ecs,cycles,cycles/op,");
    #else
            printf("%s", "\"asym\",Algorithm,key size,operation,avg ms,ops/"
                    WOLFSSL_FIXED_TIME_UNIT "ec,ops," WOLFSSL_FIXED_TIME_UNIT
                    "ecs,");
    #endif
#else
            printf("\n%sAsymmetric Ciphers:\n\n", info_prefix);
            printf("%sAlgorithm,key size,operation,avg ms,ops/"
                    WOLFSSL_FIXED_TIME_UNIT "ec,", info_prefix);
#endif
            printf("\n");
            asym_header_printed = 1;
        }
#ifdef GENERATE_MACHINE_PARSEABLE_REPORT
    #ifdef HAVE_GET_CYCLES
        (void)XSNPRINTF(msg, sizeof(msg),
                        "asym,%s,%d,%s%s," FLT_FMT_PREC "," FLT_FMT_PREC ",%d,"
                        FLT_FMT ",%lu," FLT_FMT_PREC STATS_CLAUSE_SEPARATOR,
                        algo, strength, desc, desc_extra,
                        FLT_FMT_PREC_ARGS(3, milliEach),
                        FLT_FMT_PREC_ARGS(digits, opsSec),
                        count, FLT_FMT_ARGS(total), (unsigned long)total_cycles,
                        FLT_FMT_PREC_ARGS(6,
                            (double)total_cycles / (double)count));
    #else
        (void)XSNPRINTF(msg, sizeof(msg),
                        "asym,%s,%d,%s%s," FLT_FMT_PREC "," FLT_FMT_PREC ",%d,"
                        FLT_FMT STATS_CLAUSE_SEPARATOR,
                        algo, strength, desc, desc_extra,
                        FLT_FMT_PREC_ARGS(3, milliEach),
                        FLT_FMT_PREC_ARGS(digits, opsSec),
                        count, FLT_FMT_ARGS(total));
    #endif
#else
        (void)XSNPRINTF(msg, sizeof(msg), "%s,%d,%s%s," FLT_FMT_PREC ","
                        FLT_FMT_PREC "," STATS_CLAUSE_SEPARATOR,
                        algo, strength, desc, desc_extra,
                        FLT_FMT_PREC_ARGS(3, milliEach),
                        FLT_FMT_PREC_ARGS(digits, opsSec));
#endif
    } /* if (csv_format == 1) */

    else {
#ifdef GENERATE_MACHINE_PARSEABLE_REPORT
    #ifdef HAVE_GET_CYCLES
        (void)XSNPRINTF(msg, sizeof(msg),
                        "%-6s %5d %8s%-2s %s %6d %s " FLT_FMT_PREC2 " %s, %s "
                        FLT_FMT_PREC2 " ms, " FLT_FMT_PREC " %s, %lu cycles"
                        STATS_CLAUSE_SEPARATOR,
                        algo, strength, desc, desc_extra,
                        BENCH_DEVID_GET_NAME(useDeviceID), count, word[0],
                        FLT_FMT_PREC2_ARGS(5, 3, total), word[1], word[2],
                        FLT_FMT_PREC2_ARGS(5, 3, milliEach),
                        FLT_FMT_PREC_ARGS(digits, opsSec), word[3],
                        (unsigned long)total_cycles);
    #else
        (void)XSNPRINTF(msg, sizeof(msg),
                        "%-6s %5d %8s%-2s %s %6d %s " FLT_FMT_PREC2 " %s, %s "
                        FLT_FMT_PREC2 " ms, " FLT_FMT_PREC " %s"
                        STATS_CLAUSE_SEPARATOR,
                        algo, strength, desc, desc_extra,
                        BENCH_DEVID_GET_NAME(useDeviceID), count, word[0],
                        FLT_FMT_PREC2_ARGS(5, 3, total), word[1], word[2],
                        FLT_FMT_PREC2_ARGS(5, 3, milliEach),
                        FLT_FMT_PREC_ARGS(digits, opsSec), word[3]);
    #endif /* HAVE_GET_CYCLES */
#else
        (void)XSNPRINTF(msg, sizeof(msg),
                        "%-6s %5d %8s%-2s %s %6d %s " FLT_FMT_PREC2 " %s, %s "
                        FLT_FMT_PREC2 " ms, " FLT_FMT_PREC " %s"
                        STATS_CLAUSE_SEPARATOR,
                        algo, strength, desc, desc_extra,
                        BENCH_DEVID_GET_NAME(useDeviceID), count, word[0],
                        FLT_FMT_PREC2_ARGS(5, 3, total), word[1], word[2],
                        FLT_FMT_PREC2_ARGS(5, 3, milliEach),
                        FLT_FMT_PREC_ARGS(digits, opsSec), word[3]);
#endif
    }
#endif /* MULTI_VALUE_STATISTICS */
    printf("%s", msg);

    /* show errors */
    if (ret < 0) {
        printf("%sBenchmark %s %s %d failed: %d\n",
               err_prefix, algo, desc, strength, ret);
    }

#ifndef WOLFSSL_SGX
    XFFLUSH(stdout);
#endif

#ifdef WC_BENCH_TRACK_STATS
    /* Add to thread stats */
    bench_stats_add(BENCH_STAT_ASYM, algo, strength, desc, useDeviceID, opsSec,
                    kOpsSec, ret);
#endif

    (void)useDeviceID;
    (void)ret;

#ifdef WOLFSSL_LINUXKM_USE_SAVE_VECTOR_REGISTERS
    RESTORE_VECTOR_REGISTERS();
#endif

    TEST_SLEEP();
} /* bench_stats_asym_finish_ex */

static void bench_stats_asym_finish(const char* algo, int strength,
    const char* desc, int useDeviceID, int count, double start, int ret)
{
    bench_stats_asym_finish_ex(algo, strength, desc, "", useDeviceID, count,
                               start, ret);
}
#endif
#endif /* BENCH_ASYM */

static WC_INLINE void bench_stats_free(void)
{
#ifdef WC_BENCH_TRACK_STATS
    bench_stats_t* bstat;
    for (bstat = bench_stats_head; bstat != NULL; ) {
        bench_stats_t* next = bstat->next;
        XFREE(bstat, NULL, DYNAMIC_TYPE_INFO);
        bstat = next;
    }
    bench_stats_head = NULL;
    bench_stats_tail = NULL;
#endif
}

/*****************************************************************************/
/* End Stats Functions */
/*****************************************************************************/


static void* benchmarks_do(void* args)
{
    long bench_buf_size;

#ifdef WOLFSSL_ASYNC_CRYPT
#ifndef WC_NO_ASYNC_THREADING
    ThreadData* threadData = (ThreadData*)args;

    if (wolfAsync_DevOpenThread(&devId, &threadData->thread_id) < 0)
#else
    if (wolfAsync_DevOpen(&devId) < 0)
#endif
    {
        printf("%sAsync device open failed\n%sRunning without async\n",
               err_prefix, err_prefix);
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    (void)args;

#ifdef WOLFSSL_ASYNC_CRYPT
    if (wolfEventQueue_Init(&eventQueue) != 0) {
        printf("%sAsync event queue init failure!\n", err_prefix);
    }
#endif

#ifdef WOLF_CRYPTO_CB
#ifdef HAVE_INTEL_QA_SYNC
    devId = wc_CryptoCb_InitIntelQa();
    if (devId == INVALID_DEVID) {
        printf("%sCouldn't init the Intel QA\n", err_prefix);
    }
#endif
#ifdef HAVE_CAVIUM_OCTEON_SYNC
    devId = wc_CryptoCb_InitOcteon();
    if (devId == INVALID_DEVID) {
        printf("%sCouldn't get the Octeon device ID\n", err_prefix);
    }
#endif
#ifdef HAVE_RENESAS_SYNC
    devId = wc_CryptoCb_CryptInitRenesasCmn(NULL, &guser_PKCbInfo);
    if (devId == INVALID_DEVID) {
        printf("%sCouldn't get the Renesas device ID\n", err_prefix);
    }
#endif
#endif

#if defined(HAVE_LOCAL_RNG)
    {
        int rngRet;

#ifndef HAVE_FIPS
        rngRet = wc_InitRng_ex(&gRng, HEAP_HINT, devId);
#else
        rngRet = wc_InitRng(&gRng);
#endif
        if (rngRet < 0) {
            printf("%sInitRNG failed\n", err_prefix);
            return NULL;
        }
    }
#endif

    /* setup bench plain, cipher, key and iv globals */
    /* make sure bench buffer is multiple of 16 (AES block size) */
    bench_buf_size = (int)bench_size + BENCH_CIPHER_ADD;
    if (bench_buf_size % 16)
        bench_buf_size += 16 - (bench_buf_size % 16);

#ifdef WOLFSSL_AFALG_XILINX_AES
    bench_plain = (byte*)aligned_alloc(64, (size_t)bench_buf_size + 16); /* native heap */
    bench_cipher = (byte*)aligned_alloc(64, (size_t)bench_buf_size + 16); /* native heap */
#else
    bench_plain = (byte*)XMALLOC((size_t)bench_buf_size + 16,
                                 HEAP_HINT, DYNAMIC_TYPE_WOLF_BIGINT);
    bench_cipher = (byte*)XMALLOC((size_t)bench_buf_size + 16,
                                 HEAP_HINT, DYNAMIC_TYPE_WOLF_BIGINT);
#endif
    if (bench_plain == NULL || bench_cipher == NULL) {
        XFREE(bench_plain, HEAP_HINT, DYNAMIC_TYPE_WOLF_BIGINT);
        XFREE(bench_cipher, HEAP_HINT, DYNAMIC_TYPE_WOLF_BIGINT);
        bench_plain = bench_cipher = NULL;

        printf("%sBenchmark block buffer alloc failed!\n", err_prefix);
        goto exit;
    }

#ifndef NO_FILESYSTEM
    if (hash_input) {
        size_t rawSz;
        XFILE  file;
        file = XFOPEN(hash_input, "rb");
        if (file == XBADFILE)
            goto exit;

        if (XFSEEK(file, 0, XSEEK_END) != 0) {
            XFCLOSE(file);
            goto exit;
        }

        bench_buf_size = XFTELL(file);
        if(XFSEEK(file, 0, XSEEK_SET) != 0) {
            XFCLOSE(file);
            goto exit;
        }

        XFREE(bench_plain, HEAP_HINT, DYNAMIC_TYPE_WOLF_BIGINT);

        rawSz = (size_t)bench_buf_size;
        if (bench_buf_size % 16)
            bench_buf_size += 16 - (bench_buf_size % 16);

        bench_size = (word32)bench_buf_size;

        bench_plain = (byte*)XMALLOC((size_t)bench_buf_size + 16*2,
                                 HEAP_HINT, DYNAMIC_TYPE_WOLF_BIGINT);

        if (bench_plain == NULL) {
            XFCLOSE(file);
            goto exit;
        }

        if ((size_t)XFREAD(bench_plain, 1, rawSz, file)
                != rawSz) {
            XFCLOSE(file);
            goto exit;
        }

        XFCLOSE(file);
    }
    else {
        XMEMSET(bench_plain, 0, (size_t)bench_buf_size);
    }

    if (cipher_input) {
        size_t rawSz;
        XFILE  file;
        file = XFOPEN(cipher_input, "rb");
        if (file == XBADFILE)
            goto exit;

        if (XFSEEK(file, 0, XSEEK_END) != 0) {
            XFCLOSE(file);
            goto exit;
        }

        bench_buf_size = XFTELL(file);
        if(XFSEEK(file, 0, XSEEK_SET) != 0) {
            XFCLOSE(file);
            goto exit;
        }

        XFREE(bench_cipher, HEAP_HINT, DYNAMIC_TYPE_WOLF_BIGINT);

        rawSz = (size_t)bench_buf_size;
        if (bench_buf_size % 16)
            bench_buf_size += 16 - (bench_buf_size % 16);

        if (bench_size > (word32)bench_buf_size)
            bench_size = (word32)bench_buf_size;

        bench_cipher = (byte*)XMALLOC((size_t)bench_buf_size + 16*2,
                                 HEAP_HINT, DYNAMIC_TYPE_WOLF_BIGINT);

        if (bench_cipher == NULL) {
            XFCLOSE(file);
            goto exit;
        }

        if ((size_t)XFREAD(bench_cipher, 1, rawSz, file)
                != rawSz) {
            XFCLOSE(file);
            goto exit;
        }

        XFCLOSE(file);
    }
    else {
        XMEMSET(bench_cipher, 0, (size_t)bench_buf_size);
    }
#endif

#if defined(WOLFSSL_ASYNC_CRYPT) || defined(HAVE_INTEL_QA_SYNC)
    bench_key = (byte*)XMALLOC(sizeof(bench_key_buf),
                               HEAP_HINT, DYNAMIC_TYPE_WOLF_BIGINT);
    bench_iv = (byte*)XMALLOC(sizeof(bench_iv_buf),
                              HEAP_HINT, DYNAMIC_TYPE_WOLF_BIGINT);

    if (bench_key == NULL || bench_iv == NULL) {
        XFREE(bench_key, HEAP_HINT, DYNAMIC_TYPE_WOLF_BIGINT);
        XFREE(bench_iv, HEAP_HINT, DYNAMIC_TYPE_WOLF_BIGINT);
        bench_key = bench_iv = NULL;

        printf("%sBenchmark cipher buffer alloc failed!\n", err_prefix);
        goto exit;
    }
    XMEMCPY(bench_key, bench_key_buf, sizeof(bench_key_buf));
    XMEMCPY(bench_iv, bench_iv_buf, sizeof(bench_iv_buf));
#elif defined(HAVE_RENESAS_SYNC)
    bench_key1 = (byte*)guser_PKCbInfo.wrapped_key_aes128;
    bench_key2 = (byte*)guser_PKCbInfo.wrapped_key_aes256;
    bench_key = (byte*)bench_key_buf;
    bench_iv = (byte*)bench_iv_buf;
#else
    bench_key = (byte*)bench_key_buf;
    bench_iv = (byte*)bench_iv_buf;
#endif

#ifndef WC_NO_RNG
    if (bench_all || (bench_other_algs & BENCH_RNG))
        bench_rng();
#endif /* WC_NO_RNG */
#ifndef NO_AES
#ifdef HAVE_AES_CBC
    if (bench_all || (bench_cipher_algs & BENCH_AES_CBC)) {
    #ifndef NO_SW_BENCH
        bench_aescbc(0);
    #endif
    #if defined(BENCH_DEVID)
        bench_aescbc(1);
    #endif
    }
#endif
#ifdef HAVE_AESGCM
    if (bench_all || (bench_cipher_algs & BENCH_AES_GCM)) {
    #ifndef NO_SW_BENCH
        bench_aes_aad_options_wrap(bench_aesgcm, 0);
    #endif
    #if ((defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_3DES)) || \
         defined(HAVE_INTEL_QA_SYNC) || defined(HAVE_CAVIUM_OCTEON_SYNC) || \
         defined(HAVE_RENESAS_SYNC)  || defined(WOLFSSL_CAAM)) || \
         ((defined(WOLFSSL_MAX3266X) || defined(WOLFSSL_MAX3266X_OLD)) && \
         defined(WOLF_CRYPTO_CB)) && !defined(NO_HW_BENCH)
        bench_aes_aad_options_wrap(bench_aesgcm, 1);
    #endif
    #ifndef NO_SW_BENCH
        bench_gmac(0);
    #endif
    #if defined(BENCH_DEVID)
        bench_gmac(1);
    #endif
    }
#endif
#ifdef HAVE_AES_ECB
    if (bench_all || (bench_cipher_algs & BENCH_AES_ECB)) {
    #ifndef NO_SW_BENCH
        bench_aesecb(0);
    #endif
    #ifdef BENCH_DEVID
        bench_aesecb(1);
    #endif
    }
#endif
#ifdef WOLFSSL_AES_XTS
    if (bench_all || (bench_cipher_algs & BENCH_AES_XTS))
        bench_aesxts();
#endif
#ifdef WOLFSSL_AES_CFB
    if (bench_all || (bench_cipher_algs & BENCH_AES_CFB))
        bench_aescfb();
#endif
#ifdef WOLFSSL_AES_OFB
    if (bench_all || (bench_cipher_algs & BENCH_AES_OFB))
        bench_aesofb();
#endif
#ifdef WOLFSSL_AES_COUNTER
    if (bench_all || (bench_cipher_algs & BENCH_AES_CTR)) {
        bench_aesctr(0);
    #ifdef BENCH_DEVID
        bench_aesctr(1);
    #endif
    }
#endif
#ifdef HAVE_AESCCM
    if (bench_all || (bench_cipher_algs & BENCH_AES_CCM)) {
        bench_aes_aad_options_wrap(bench_aesccm, 0);
    #ifdef BENCH_DEVID
        bench_aes_aad_options_wrap(bench_aesccm, 1);
    #endif
    }
#endif
#ifdef WOLFSSL_AES_SIV
    if (bench_all || (bench_cipher_algs & BENCH_AES_SIV))
        bench_aessiv();
#endif
#endif /* !NO_AES */

#ifdef HAVE_CAMELLIA
    if (bench_all || (bench_cipher_algs & BENCH_CAMELLIA))
        bench_camellia();
#endif
#ifdef WOLFSSL_SM4_CBC
    if (bench_all || (bench_cipher_algs & BENCH_SM4_CBC))
        bench_sm4_cbc();
#endif
#ifdef WOLFSSL_SM4_GCM
    if (bench_all || (bench_cipher_algs & BENCH_SM4_GCM))
        bench_sm4_gcm();
#endif
#ifdef WOLFSSL_SM4_CCM
    if (bench_all || (bench_cipher_algs & BENCH_SM4_CCM))
        bench_sm4_ccm();
#endif
#ifndef NO_RC4
    if (bench_all || (bench_cipher_algs & BENCH_ARC4)) {
    #ifndef NO_SW_BENCH
        bench_arc4(0);
    #endif
    #ifdef BENCH_DEVID
        bench_arc4(1);
    #endif
    }
#endif
#ifdef HAVE_CHACHA
    if (bench_all || (bench_cipher_algs & BENCH_CHACHA20))
        bench_chacha();
#endif
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    if (bench_all || (bench_cipher_algs & BENCH_CHACHA20_POLY1305))
        bench_chacha20_poly1305_aead();
#endif
#ifndef NO_DES3
    if (bench_all || (bench_cipher_algs & BENCH_DES)) {
    #ifndef NO_SW_BENCH
        bench_des(0);
    #endif
    #ifdef BENCH_DEVID
        bench_des(1);
    #endif
    }
#endif
#ifndef NO_MD5
    if (bench_all || (bench_digest_algs & BENCH_MD5)) {
    #ifndef NO_SW_BENCH
        bench_md5(0);
    #endif
    #ifdef BENCH_DEVID
        bench_md5(1);
    #endif
    }
#endif
#ifdef HAVE_POLY1305
    if (bench_all || (bench_digest_algs & BENCH_POLY1305))
        bench_poly1305();
#endif
#ifndef NO_SHA
    if (bench_all || (bench_digest_algs & BENCH_SHA)) {
    #ifndef NO_SW_BENCH
        bench_sha(0);
    #endif
    #ifdef BENCH_DEVID
        bench_sha(1);
    #endif
    }
#endif
#ifdef WOLFSSL_SHA224
    if (bench_all || (bench_digest_algs & BENCH_SHA224)) {
    #ifndef NO_SW_BENCH
        bench_sha224(0);
    #endif
    #ifdef BENCH_DEVID
        bench_sha224(1);
    #endif
    }
#endif
#ifndef NO_SHA256
    if (bench_all || (bench_digest_algs & BENCH_SHA256)) {
    #ifndef NO_SW_BENCH
        bench_sha256(0);
    #endif
    #ifdef BENCH_DEVID
        bench_sha256(1);
    #endif
    }
#endif
#ifdef WOLFSSL_SHA384
    if (bench_all || (bench_digest_algs & BENCH_SHA384)) {
    #ifndef NO_SW_BENCH
        bench_sha384(0);
    #endif
    #ifdef BENCH_DEVID
        bench_sha384(1);
    #endif
    }
#endif
#ifdef WOLFSSL_SHA512
    if (bench_all || (bench_digest_algs & BENCH_SHA512)) {
    #ifndef NO_SW_BENCH
        bench_sha512(0);
    #endif
    #ifdef BENCH_DEVID
        bench_sha512(1);
    #endif
    }

#if !defined(WOLFSSL_NOSHA512_224) && \
   (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 3)) && !defined(HAVE_SELFTEST)
    if (bench_all || (bench_digest_algs & BENCH_SHA512)) {
    #ifndef NO_SW_BENCH
        bench_sha512_224(0);
    #endif
    #ifdef BENCH_DEVID
        bench_sha512_224(1);
    #endif
    }
#endif /* WOLFSSL_NOSHA512_224 */

#if !defined(WOLFSSL_NOSHA512_256) && \
   (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 3)) && !defined(HAVE_SELFTEST)
    if (bench_all || (bench_digest_algs & BENCH_SHA512)) {
    #ifndef NO_SW_BENCH
        bench_sha512_256(0);
    #endif
    #ifdef BENCH_DEVID
        bench_sha512_256(1);
    #endif
    }
#endif /* WOLFSSL_NOSHA512_256 */
#endif /* WOLFSSL_SHA512 */

#ifdef WOLFSSL_SHA3
    #ifndef WOLFSSL_NOSHA3_224
    if (bench_all || (bench_digest_algs & BENCH_SHA3_224)) {
    #ifndef NO_SW_BENCH
        bench_sha3_224(0);
    #endif
    #ifdef BENCH_DEVID
        bench_sha3_224(1);
    #endif
    }
    #endif /* WOLFSSL_NOSHA3_224 */
    #ifndef WOLFSSL_NOSHA3_256
    if (bench_all || (bench_digest_algs & BENCH_SHA3_256)) {
    #ifndef NO_SW_BENCH
        bench_sha3_256(0);
    #endif
    #ifdef BENCH_DEVID
        bench_sha3_256(1);
    #endif
    }
    #endif /* WOLFSSL_NOSHA3_256 */
    #ifndef WOLFSSL_NOSHA3_384
    if (bench_all || (bench_digest_algs & BENCH_SHA3_384)) {
    #ifndef NO_SW_BENCH
        bench_sha3_384(0);
    #endif
    #ifdef BENCH_DEVID
        bench_sha3_384(1);
    #endif
    }
    #endif /* WOLFSSL_NOSHA3_384 */
    #ifndef WOLFSSL_NOSHA3_512
    if (bench_all || (bench_digest_algs & BENCH_SHA3_512)) {
    #ifndef NO_SW_BENCH
        bench_sha3_512(0);
    #endif
    #ifdef BENCH_DEVID
        bench_sha3_512(1);
    #endif
    }
    #endif /* WOLFSSL_NOSHA3_512 */
    #ifdef WOLFSSL_SHAKE128
    if (bench_all || (bench_digest_algs & BENCH_SHAKE128)) {
    #ifndef NO_SW_BENCH
        bench_shake128(0);
    #endif
    #ifdef BENCH_DEVID
        bench_shake128(1);
    #endif
    }
    #endif /* WOLFSSL_SHAKE128 */
    #ifdef WOLFSSL_SHAKE256
    if (bench_all || (bench_digest_algs & BENCH_SHAKE256)) {
    #ifndef NO_SW_BENCH
        bench_shake256(0);
    #endif
    #ifdef BENCH_DEVID
        bench_shake256(1);
    #endif
    }
    #endif /* WOLFSSL_SHAKE256 */
#endif
#ifdef WOLFSSL_SM3
    if (bench_all || (bench_digest_algs & BENCH_SM3)) {
    #ifndef NO_SW_BENCH
        bench_sm3(0);
    #endif
    #ifdef BENCH_DEVID
        bench_sm3(1);
    #endif
    }
#endif
#ifdef WOLFSSL_RIPEMD
    if (bench_all || (bench_digest_algs & BENCH_RIPEMD))
        bench_ripemd();
#endif
#ifdef HAVE_BLAKE2
    if (bench_all || (bench_digest_algs & BENCH_BLAKE2B))
        bench_blake2b();
#endif
#ifdef HAVE_BLAKE2S
    if (bench_all || (bench_digest_algs & BENCH_BLAKE2S))
        bench_blake2s();
#endif
#ifdef WOLFSSL_CMAC
    if (bench_all || (bench_mac_algs & BENCH_CMAC)) {
        bench_cmac(0);
    #ifdef BENCH_DEVID
        bench_cmac(1);
    #endif
    }
#endif

#ifndef NO_HMAC
    #ifndef NO_MD5
        if (bench_all || (bench_mac_algs & BENCH_HMAC_MD5)) {
        #ifndef NO_SW_BENCH
            bench_hmac_md5(0);
        #endif
        #ifdef BENCH_DEVID
            bench_hmac_md5(1);
        #endif
        }
    #endif
    #ifndef NO_SHA
        if (bench_all || (bench_mac_algs & BENCH_HMAC_SHA)) {
        #ifndef NO_SW_BENCH
            bench_hmac_sha(0);
        #endif
        #ifdef BENCH_DEVID
            bench_hmac_sha(1);
        #endif
        }
    #endif
    #ifdef WOLFSSL_SHA224
        if (bench_all || (bench_mac_algs & BENCH_HMAC_SHA224)) {
        #ifndef NO_SW_BENCH
            bench_hmac_sha224(0);
        #endif
        #ifdef BENCH_DEVID
            bench_hmac_sha224(1);
        #endif
        }
    #endif
    #ifndef NO_SHA256
        if (bench_all || (bench_mac_algs & BENCH_HMAC_SHA256)) {
        #ifndef NO_SW_BENCH
            bench_hmac_sha256(0);
        #endif
        #ifdef BENCH_DEVID
            bench_hmac_sha256(1);
        #endif
        }
    #endif
    #ifdef WOLFSSL_SHA384
        if (bench_all || (bench_mac_algs & BENCH_HMAC_SHA384)) {
        #ifndef NO_SW_BENCH
            bench_hmac_sha384(0);
        #endif
        #ifdef BENCH_DEVID
            bench_hmac_sha384(1);
        #endif
        }
    #endif
    #ifdef WOLFSSL_SHA512
        if (bench_all || (bench_mac_algs & BENCH_HMAC_SHA512)) {
        #ifndef NO_SW_BENCH
            bench_hmac_sha512(0);
        #endif
        #ifdef BENCH_DEVID
            bench_hmac_sha512(1);
        #endif
        }
    #endif
    #ifndef NO_PWDBASED
        if (bench_all || (bench_mac_algs & BENCH_PBKDF2)) {
            bench_pbkdf2();
        }
    #endif
#endif /* NO_HMAC */
#ifdef WOLFSSL_SIPHASH
    if (bench_all || (bench_mac_algs & BENCH_SIPHASH)) {
        bench_siphash();
    }
#endif

#ifdef WC_SRTP_KDF
    if (bench_all || (bench_kdf_algs & BENCH_SRTP_KDF)) {
        bench_srtpkdf();
    }
#endif

#ifdef HAVE_SCRYPT
    if (bench_all || (bench_other_algs & BENCH_SCRYPT))
        bench_scrypt();
#endif

#ifndef NO_RSA
#ifndef HAVE_RENESAS_SYNC
    #ifdef WOLFSSL_KEY_GEN
        if (bench_all || (bench_asym_algs & BENCH_RSA_KEYGEN)) {
        #ifndef NO_SW_BENCH
            if (((word32)bench_asym_algs == 0xFFFFFFFFU) ||
                        (bench_asym_algs & BENCH_RSA_SZ) == 0) {
                bench_rsaKeyGen(0);
            }
            else {
                bench_rsaKeyGen_size(0, bench_size);
            }
        #endif
        #ifdef BENCH_DEVID
            if (bench_asym_algs & BENCH_RSA_SZ) {
                bench_rsaKeyGen_size(1, bench_size);
            }
            else {
                bench_rsaKeyGen(1);
            }
        #endif
        }
    #endif
    if (bench_all || (bench_asym_algs & BENCH_RSA)) {
    #ifndef NO_SW_BENCH
        bench_rsa(0);
    #endif
    #ifdef BENCH_DEVID
        bench_rsa(1);
    #endif
    }

    #ifdef WOLFSSL_KEY_GEN
    if (bench_asym_algs & BENCH_RSA_SZ) {
    #ifndef NO_SW_BENCH
        bench_rsa_key(0, bench_size);
    #endif
    #ifdef BENCH_DEVID
        bench_rsa_key(1, bench_size);
    #endif
    }
    #endif
#endif
#endif

#ifndef NO_DH
    if (bench_all || (bench_asym_algs & BENCH_DH)) {
    #ifndef NO_SW_BENCH
        bench_dh(0);
    #endif
    #ifdef BENCH_DEVID
        bench_dh(1);
    #endif
    }
#endif

#ifdef WOLFSSL_HAVE_KYBER
    if (bench_all || (bench_pq_asym_algs & BENCH_KYBER)) {
#ifndef WOLFSSL_NO_ML_KEM
    #ifdef WOLFSSL_KYBER512
        if (bench_all || (bench_pq_asym_algs & BENCH_KYBER512)) {
            bench_kyber(WC_ML_KEM_512);
        }
    #endif
    #ifdef WOLFSSL_KYBER768
        if (bench_all || (bench_pq_asym_algs & BENCH_KYBER768)) {
            bench_kyber(WC_ML_KEM_768);
        }
    #endif
    #ifdef WOLFSSL_KYBER1024
        if (bench_all || (bench_pq_asym_algs & BENCH_KYBER1024)) {
            bench_kyber(WC_ML_KEM_1024);
        }
    #endif
#endif
#ifdef WOLFSSL_KYBER_ORIGINAL
    #ifdef WOLFSSL_KYBER512
        if (bench_all || (bench_pq_asym_algs & BENCH_KYBER512)) {
            bench_kyber(KYBER512);
        }
    #endif
    #ifdef WOLFSSL_KYBER768
        if (bench_all || (bench_pq_asym_algs & BENCH_KYBER768)) {
            bench_kyber(KYBER768);
        }
    #endif
    #ifdef WOLFSSL_KYBER1024
        if (bench_all || (bench_pq_asym_algs & BENCH_KYBER1024)) {
            bench_kyber(KYBER1024);
        }
    #endif
#endif
    }
#endif

#if defined(WOLFSSL_HAVE_LMS) && !defined(WOLFSSL_LMS_VERIFY_ONLY)
    if (bench_all || (bench_pq_hash_sig_algs & BENCH_LMS_HSS)) {
        bench_lms();
    }
#endif /* if defined(WOLFSSL_HAVE_LMS) && !defined(WOLFSSL_LMS_VERIFY_ONLY) */

#if defined(WOLFSSL_HAVE_XMSS) && !defined(WOLFSSL_XMSS_VERIFY_ONLY)
    if (bench_all) {
        bench_pq_hash_sig_algs |= BENCH_XMSS_XMSSMT;
    }
#ifndef NO_SHA256
    if (bench_pq_hash_sig_algs & BENCH_XMSS_XMSSMT_SHA256) {
        bench_xmss(WC_HASH_TYPE_SHA256);
    }
#endif
#ifdef WOLFSSL_SHA512
    if (bench_pq_hash_sig_algs & BENCH_XMSS_XMSSMT_SHA512) {
        bench_xmss(WC_HASH_TYPE_SHA512);
    }
#endif
#ifdef WOLFSSL_SHAKE128
    if (bench_pq_hash_sig_algs & BENCH_XMSS_XMSSMT_SHAKE128) {
        bench_xmss(WC_HASH_TYPE_SHAKE128);
    }
#endif
#ifdef WOLFSSL_SHAKE256
    if (bench_pq_hash_sig_algs & BENCH_XMSS_XMSSMT_SHAKE256) {
        bench_xmss(WC_HASH_TYPE_SHAKE256);
    }
#endif
#endif /* if defined(WOLFSSL_HAVE_XMSS) && !defined(WOLFSSL_XMSS_VERIFY_ONLY) */

#ifdef HAVE_ECC
    if (bench_all || (bench_asym_algs & BENCH_ECC_MAKEKEY) ||
            (bench_asym_algs & BENCH_ECC) ||
            (bench_asym_algs & BENCH_ECC_ALL) ||
            (bench_asym_algs & BENCH_ECC_ENCRYPT)) {

        if (bench_asym_algs & BENCH_ECC_ALL) {
            #if defined(HAVE_FIPS) || defined(HAVE_SELFTEST)
            printf("%snot supported in FIPS mode (no ending enum value)\n",
                   err_prefix);
            #else
            int curveId = (int)ECC_SECP192R1;

            /* set make key and encrypt */
            bench_asym_algs |= BENCH_ECC_MAKEKEY | BENCH_ECC |
                               BENCH_ECC_ENCRYPT;
            if (csv_format != 1) {
                printf("\n%sECC Benchmarks:\n", info_prefix);
            }

            do {
            #ifdef WOLFCRYPT_HAVE_SAKKE
                /* SAKKE is not usable with ECDH/ECDSA. Run separate test. */
                if (curveId == ECC_SAKKE_1) {
                    curveId++;
                    continue;
                }
            #endif

                if (wc_ecc_get_curve_size_from_id(curveId) !=
                        WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) {
                    bench_ecc_curve(curveId);
                    if (csv_format != 1) {
                        printf("\n");
                    }
                }
                curveId++;
            } while (curveId != (int)ECC_CURVE_MAX);
            #endif
        }
        else if (bench_asym_algs & BENCH_ECC_P256) {
            bench_ecc_curve((int)ECC_SECP256R1);
        }
        else if (bench_asym_algs & BENCH_ECC_P384) {
            bench_ecc_curve((int)ECC_SECP384R1);
        }
        else if (bench_asym_algs & BENCH_ECC_P521) {
            bench_ecc_curve((int)ECC_SECP521R1);
        }
        else {
            #ifndef NO_ECC256
            bench_ecc_curve((int)ECC_SECP256R1);
            #elif defined(HAVE_ECC384)
            bench_ecc_curve((int)ECC_SECP384R1);
            #elif defined(HAVE_ECC521)
            bench_ecc_curve((int)ECC_SECP521R1);
            #endif
            #ifdef HAVE_ECC_BRAINPOOL
            bench_ecc_curve((int)ECC_BRAINPOOLP256R1);
            #endif
        }
    }
#endif
#ifdef WOLFSSL_SM2
    if (bench_all || (bench_asym_algs & BENCH_SM2)) {
        bench_sm2(0);
    }
#endif

#ifdef HAVE_CURVE25519
    if (bench_all || (bench_asym_algs & BENCH_CURVE25519_KEYGEN)) {
        bench_curve25519KeyGen(0);
    #ifdef BENCH_DEVID
        bench_curve25519KeyGen(1);
    #endif
    }

    #ifdef HAVE_CURVE25519_SHARED_SECRET
    if (bench_all || (bench_asym_algs & BENCH_CURVE25519_KA)) {
        bench_curve25519KeyAgree(0);
    #ifdef BENCH_DEVID
        bench_curve25519KeyAgree(1);
    #endif
    }
    #endif
#endif

#ifdef HAVE_ED25519
    if (bench_all || (bench_asym_algs & BENCH_ED25519_KEYGEN))
        bench_ed25519KeyGen();
    if (bench_all || (bench_asym_algs & BENCH_ED25519_SIGN))
        bench_ed25519KeySign();
#endif

#ifdef HAVE_CURVE448
    if (bench_all || (bench_asym_algs & BENCH_CURVE448_KEYGEN))
        bench_curve448KeyGen();
    #ifdef HAVE_CURVE448_SHARED_SECRET
    if (bench_all || (bench_asym_algs & BENCH_CURVE448_KA))
        bench_curve448KeyAgree();
    #endif
#endif

#ifdef HAVE_ED448
    if (bench_all || (bench_asym_algs & BENCH_ED448_KEYGEN))
        bench_ed448KeyGen();
    if (bench_all || (bench_asym_algs & BENCH_ED448_SIGN))
        bench_ed448KeySign();
#endif

#ifdef WOLFCRYPT_HAVE_ECCSI
    #ifdef WOLFCRYPT_ECCSI_KMS
        if (bench_all || (bench_asym_algs & BENCH_ECCSI_KEYGEN)) {
            bench_eccsiKeyGen();
        }
        if (bench_all || (bench_asym_algs & BENCH_ECCSI_PAIRGEN)) {
            bench_eccsiPairGen();
        }
    #endif
    #ifdef WOLFCRYPT_ECCSI_CLIENT
        if (bench_all || (bench_asym_algs & BENCH_ECCSI_VALIDATE)) {
            bench_eccsiValidate();
        }
        if (bench_all || (bench_asym_algs & BENCH_ECCSI)) {
            bench_eccsi();
        }
    #endif
#endif

#ifdef WOLFCRYPT_HAVE_SAKKE
    #ifdef WOLFCRYPT_SAKKE_KMS
        if (bench_all || (bench_asym_algs & BENCH_SAKKE_KEYGEN)) {
            bench_sakkeKeyGen();
        }
        if (bench_all || (bench_asym_algs & BENCH_SAKKE_RSKGEN)) {
            bench_sakkeRskGen();
        }
    #endif
    #ifdef WOLFCRYPT_SAKKE_CLIENT
        if (bench_all || (bench_asym_algs & BENCH_SAKKE_VALIDATE)) {
            bench_sakkeValidate();
        }
        if (bench_all || (bench_asym_algs & BENCH_SAKKE)) {
            bench_sakke();
        }
    #endif
#endif

#ifdef HAVE_FALCON
    if (bench_all || (bench_pq_asym_algs & BENCH_FALCON_LEVEL1_SIGN))
        bench_falconKeySign(1);
    if (bench_all || (bench_pq_asym_algs & BENCH_FALCON_LEVEL5_SIGN))
        bench_falconKeySign(5);
#endif
#ifdef HAVE_DILITHIUM
#ifndef WOLFSSL_NO_ML_DSA_44
    if (bench_all || (bench_pq_asym_algs & BENCH_DILITHIUM_LEVEL2_SIGN))
        bench_dilithiumKeySign(2);
#endif
#ifndef WOLFSSL_NO_ML_DSA_65
    if (bench_all || (bench_pq_asym_algs & BENCH_DILITHIUM_LEVEL3_SIGN))
        bench_dilithiumKeySign(3);
#endif
#ifndef WOLFSSL_NO_ML_DSA_87
    if (bench_all || (bench_pq_asym_algs & BENCH_DILITHIUM_LEVEL5_SIGN))
        bench_dilithiumKeySign(5);
#endif
#endif
#ifdef HAVE_SPHINCS
    if (bench_all || (bench_pq_asym_algs2 & BENCH_SPHINCS_FAST_LEVEL1_SIGN))
        bench_sphincsKeySign(1, FAST_VARIANT);
    if (bench_all || (bench_pq_asym_algs2 & BENCH_SPHINCS_FAST_LEVEL3_SIGN))
        bench_sphincsKeySign(3, FAST_VARIANT);
    if (bench_all || (bench_pq_asym_algs2 & BENCH_SPHINCS_FAST_LEVEL5_SIGN))
        bench_sphincsKeySign(5, FAST_VARIANT);
    if (bench_all || (bench_pq_asym_algs2 & BENCH_SPHINCS_SMALL_LEVEL1_SIGN))
        bench_sphincsKeySign(1, SMALL_VARIANT);
    if (bench_all || (bench_pq_asym_algs2 & BENCH_SPHINCS_SMALL_LEVEL3_SIGN))
        bench_sphincsKeySign(3, SMALL_VARIANT);
    if (bench_all || (bench_pq_asym_algs2 & BENCH_SPHINCS_SMALL_LEVEL5_SIGN))
        bench_sphincsKeySign(5, SMALL_VARIANT);
#endif

exit:
    /* free benchmark buffers */
    XFREE(bench_plain, HEAP_HINT, DYNAMIC_TYPE_WOLF_BIGINT);
    XFREE(bench_cipher, HEAP_HINT, DYNAMIC_TYPE_WOLF_BIGINT);
#ifdef WOLFSSL_ASYNC_CRYPT
    XFREE(bench_key, HEAP_HINT, DYNAMIC_TYPE_WOLF_BIGINT);
    XFREE(bench_iv, HEAP_HINT, DYNAMIC_TYPE_WOLF_BIGINT);
#endif

#if defined(HAVE_LOCAL_RNG)
    wc_FreeRng(&gRng);
#endif

/* cleanup the thread if fixed point cache is enabled and have thread local */
#if defined(HAVE_THREAD_LS) && defined(HAVE_ECC) && defined(FP_ECC)
    wc_ecc_fp_free();
#endif

    (void)bench_cipher_algs;
    (void)bench_digest_algs;
    (void)bench_mac_algs;
    (void)bench_asym_algs;
    (void)bench_other_algs;
    (void)bench_pq_asym_algs;
    (void)bench_pq_asym_algs2;

    return NULL;
}

#if defined(HAVE_CPUID) && defined(WOLFSSL_TEST_STATIC_BUILD)
static void print_cpu_features(void)
{
    word32 cpuid_flags = cpuid_get_flags();

    printf("CPU: ");
#ifdef HAVE_CPUID_INTEL
    printf("Intel");
#ifdef WOLFSSL_X86_64_BUILD
    printf(" x86_64");
#else
    printf(" x86");
#endif
    printf(" -");
    if (IS_INTEL_AVX1(cpuid_flags))   printf(" avx1");
    if (IS_INTEL_AVX2(cpuid_flags))   printf(" avx2");
    if (IS_INTEL_RDRAND(cpuid_flags)) printf(" rdrand");
    if (IS_INTEL_RDSEED(cpuid_flags)) printf(" rdseed");
    if (IS_INTEL_BMI2(cpuid_flags))   printf(" bmi2");
    if (IS_INTEL_AESNI(cpuid_flags))  printf(" aesni");
    if (IS_INTEL_ADX(cpuid_flags))    printf(" adx");
    if (IS_INTEL_MOVBE(cpuid_flags))  printf(" movbe");
    if (IS_INTEL_BMI1(cpuid_flags))   printf(" bmi1");
    if (IS_INTEL_SHA(cpuid_flags))    printf(" sha");
#endif
#ifdef __aarch64__
    printf("Aarch64 -");
    if (IS_AARCH64_AES(cpuid_flags))    printf(" aes");
    if (IS_AARCH64_PMULL(cpuid_flags))  printf(" pmull");
    if (IS_AARCH64_SHA256(cpuid_flags)) printf(" sha256");
    if (IS_AARCH64_SHA512(cpuid_flags)) printf(" sha512");
    if (IS_AARCH64_RDM(cpuid_flags))    printf(" rdm");
    if (IS_AARCH64_SHA3(cpuid_flags))   printf(" sha3");
    if (IS_AARCH64_SM3(cpuid_flags))    printf(" sm3");
    if (IS_AARCH64_SM4(cpuid_flags))    printf(" sm4");
#endif
    printf("\n");
}
#endif

int benchmark_init(void)
{
    int ret = 0;

    benchmark_static_init(0);

#ifdef WOLFSSL_STATIC_MEMORY
    ret = wc_LoadStaticMemory(&HEAP_HINT, gBenchMemory,
                              sizeof(gBenchMemory), WOLFMEM_GENERAL, 1);

    if (ret != 0) {
        printf("%sunable to load static memory %d\n", err_prefix, ret);
    }
#endif /* WOLFSSL_STATIC_MEMORY */

    if ((ret = wolfCrypt_Init()) != 0) {
        printf("%swolfCrypt_Init failed %d\n", err_prefix, ret);
        return EXIT_FAILURE;
    }

#if defined(HAVE_CPUID) && defined(WOLFSSL_TEST_STATIC_BUILD)
    print_cpu_features();
#endif

#ifdef HAVE_WC_INTROSPECTION
    printf("Math: %s\n", wc_GetMathInfo());
#endif

#ifdef WOLFSSL_SECO_CAAM
    if (wc_SECO_OpenHSM(SECO_KEY_STORE_ID,
            SECO_BENCHMARK_NONCE, SECO_MAX_UPDATES, CAAM_KEYSTORE_CREATE)
            != 0) {
        printf("%sunable to open HSM\n", err_prefix);
        wolfCrypt_Cleanup();
        return EXIT_FAILURE;
    }
#endif

#ifdef WC_RNG_SEED_CB
    wc_SetSeed_Cb(wc_GenerateSeed);
#endif

    bench_stats_init();

#if defined(DEBUG_WOLFSSL) && !defined(HAVE_VALGRIND)
    wolfSSL_Debugging_ON();
#endif

    printf("%swolfCrypt Benchmark (block bytes %d, min " FLT_FMT_PREC " sec each)\n",
           info_prefix, (int)bench_size, FLT_FMT_PREC_ARGS(1, BENCH_MIN_RUNTIME_SEC));

#ifndef GENERATE_MACHINE_PARSEABLE_REPORT
    if (csv_format == 1) {
        printf("This format allows you to easily copy "
               "the output to a csv file.");
    }
#endif

#ifdef HAVE_WNR
    ret = wc_InitNetRandom(wnrConfigFile, NULL, 5000);
    if (ret != 0) {
        printf("%sWhitewood netRandom config init failed %d\n",
               err_prefix, ret);
    }
#endif /* HAVE_WNR */

    return ret;
}

int benchmark_free(void)
{
    int ret;

#ifdef WC_BENCH_TRACK_STATS
    if (gPrintStats || devId != INVALID_DEVID) {
        bench_stats_print();
    }
#endif

    bench_stats_free();

#ifdef WOLF_CRYPTO_CB
#ifdef HAVE_INTEL_QA_SYNC
    wc_CryptoCb_CleanupIntelQa(&devId);
#endif
#ifdef HAVE_CAVIUM_OCTEON_SYNC
    wc_CryptoCb_CleanupOcteon(&devId);
#endif
#ifdef HAVE_RENESAS_SYNC
    wc_CryptoCb_CleanupRenesasCmn(&devId);
#endif
#endif

#ifdef WOLFSSL_ASYNC_CRYPT
    /* free event queue */
    wolfEventQueue_Free(&eventQueue);

    /* close device */
    wolfAsync_DevClose(&devId);
#endif

#ifdef HAVE_WNR
    ret = wc_FreeNetRandom();
    if (ret < 0) {
        printf("%sFailed to free netRandom context %d\n", err_prefix, ret);
    }
#endif

#ifdef WOLFSSL_SECO_CAAM
    if (wc_SECO_CloseHSM() != 0) {
        printf("%sError closing down the key store\n", err_prefix);
    }
#endif

    if ((ret = wolfCrypt_Cleanup()) != 0) {
        printf("%serror %d with wolfCrypt_Cleanup\n", err_prefix, ret);
    }

    return ret;
}


#if defined(WC_ENABLE_BENCH_THREADING) && !defined(WOLFSSL_ASYNC_CRYPT)
static THREAD_RETURN WOLFSSL_THREAD run_bench(void* args)
{
    benchmark_test(args);

    EXIT_TEST(0);
}

static int benchmark_test_threaded(void* args)
{
    int i;

    printf("%sThreads: %d\n", info_prefix, g_threadCount);

    g_threadData = (ThreadData*)XMALLOC(sizeof(ThreadData) * g_threadCount,
        HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (g_threadData == NULL) {
        printf("%sThread data alloc failed!\n", err_prefix);
        return EXIT_FAILURE;
    }

    for (i = 0; i < g_threadCount; i++) {
        THREAD_CHECK_RET(pthread_create(&g_threadData[i].thread_id,
                                         NULL, run_bench, args));
    }

    for (i = 0; i < g_threadCount; i++) {
        THREAD_CHECK_RET(pthread_join(g_threadData[i].thread_id, 0));
    }

    printf("\n");
    bench_stats_print();

    return 0;
}
#endif

/* so embedded projects can pull in tests on their own */
#ifdef HAVE_STACK_SIZE
THREAD_RETURN WOLFSSL_THREAD benchmark_test(void* args)
#else
int benchmark_test(void *args)
#endif
{
    int ret;

    (void)args;

#ifdef HAVE_FIPS
    wolfCrypt_SetCb_fips(myFipsCb);
#endif

    ret = benchmark_init();
    if (ret != 0)
        EXIT_TEST(ret);

#if defined(WOLFSSL_ASYNC_CRYPT) && !defined(WC_NO_ASYNC_THREADING)
{
    /* See the documentation when turning on WOLFSSL_ASYNC_CRYPT
    **
    ** Chapter Two, Build Options:
    **
    ** https://www.wolfssl.com/documentation/manuals/wolfssl/wolfSSL-Manual.pdf
    **
    ** asynchronous cryptography using hardware based adapters such as
    ** the Intel QuickAssist or Marvell (Cavium) Nitrox V.
    */
    int i;

    if (g_threadCount == 0) {
    #ifdef WC_ASYNC_BENCH_THREAD_COUNT
        g_threadCount = WC_ASYNC_BENCH_THREAD_COUNT;
    #else
        g_threadCount = wc_AsyncGetNumberOfCpus();
        if (g_threadCount > 0) {
            g_threadCount /= 2; /* use physical core count */
        }
    #endif
    }
    if (g_threadCount <= 0) {
        g_threadCount = 1;
    }

    printf("%sCPUs: %d\n", info_prefix, g_threadCount);

    g_threadData = (ThreadData*)XMALLOC(sizeof(ThreadData) * g_threadCount,
        HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (g_threadData == NULL) {
        printf("%sThread data alloc failed!\n", err_prefix);
        EXIT_TEST(EXIT_FAILURE);
    }

    /* Create threads */
    for (i = 0; i < g_threadCount; i++) {
        ret = wc_AsyncThreadCreate(&g_threadData[i].thread_id,
            benchmarks_do, &g_threadData[i]);
        if (ret != 0) {
            printf("%sError creating benchmark thread %d\n", err_prefix, ret);
            EXIT_TEST(EXIT_FAILURE);
        }
    }

    /* Start threads */
    for (i = 0; i < g_threadCount; i++) {
        wc_AsyncThreadJoin(&g_threadData[i].thread_id);
    }

    XFREE(g_threadData, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
}
#else
    benchmarks_do(NULL);
#endif
    SLEEP_ON_ERROR(1);
    printf("%sBenchmark complete\n", info_prefix);

    ret = benchmark_free();

    EXIT_TEST(ret);
}


#ifndef WC_NO_RNG
void bench_rng(void)
{
    int    ret, i, count;
    double start;
    long   pos, len, remain;
    WC_RNG myrng;
    DECLARE_MULTI_VALUE_STATS_VARS()

#ifndef HAVE_FIPS
    ret = wc_InitRng_ex(&myrng, HEAP_HINT, devId);
#else
    ret = wc_InitRng(&myrng);
#endif
    if (ret < 0) {
        printf("InitRNG failed %d\n", ret);
        return;
    }

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            /* Split request to handle large RNG request */
            pos = 0;
            remain = (int)bench_size;
            while (remain > 0) {
                len = remain;
                if (len > RNG_MAX_BLOCK_LEN)
                    len = RNG_MAX_BLOCK_LEN;
                ret = wc_RNG_GenerateBlock(&myrng, &bench_plain[pos],
                                           (word32)len);
                if (ret < 0)
                    goto exit_rng;

                remain -= len;
                pos += len;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
#endif
           );
exit_rng:
    bench_stats_sym_finish("RNG", 0, count, bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    wc_FreeRng(&myrng);
}
#endif /* WC_NO_RNG */


#ifndef NO_AES

#ifdef HAVE_AES_CBC
static void bench_aescbc_internal(int useDeviceID,
                                  const byte* key, word32 keySz,
                                  const byte* iv, const char* encLabel,
                                  const char* decLabel)
{
    const byte* in = bench_cipher;
    byte* out = bench_plain;
    int    ret = 0, i, count = 0, times, pending = 0;
    WC_DECLARE_ARRAY(enc, Aes, BENCH_MAX_PENDING,
                     sizeof(Aes), HEAP_HINT);
    double start;
    DECLARE_MULTI_VALUE_STATS_VARS()

    WC_CALLOC_ARRAY(enc, Aes, BENCH_MAX_PENDING,
                     sizeof(Aes), HEAP_HINT);

    /* init keys */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        if ((ret = wc_AesInit(enc[i], HEAP_HINT,
                                useDeviceID ? devId: INVALID_DEVID)) != 0) {
            printf("AesInit failed at L%d, ret = %d\n", __LINE__, ret);
            goto exit;
        }

        ret = wc_AesSetKey(enc[i], key, keySz, iv, AES_ENCRYPTION);
        if (ret != 0) {
            printf("AesSetKey failed, ret = %d\n", ret);
            goto exit;
        }
    }

    if (cipher_same_buffer) {
        in = bench_plain;
    }

    bench_stats_start(&count, &start);
    do {
        for (times = 0; times < numBlocks || pending > 0; ) {
            bench_async_poll(&pending);

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(enc[i]), 0,
                                      &times, numBlocks, &pending)) {
                    ret = wc_AesCbcEncrypt(enc[i], out, in, bench_size);

                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(enc[i]),
                                            0, &times, &pending)) {
                        goto exit_aes_enc;
                    }
                }
            } /* for i */
            RECORD_MULTI_VALUE_STATS();
        } /* for times */
        count += times;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
#endif
           );

exit_aes_enc:
    bench_stats_sym_finish(encLabel, useDeviceID, count,
                           bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    if (ret < 0) {
        goto exit;
    }

#ifdef HAVE_AES_DECRYPT
    /* init keys */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        ret = wc_AesSetKey(enc[i], key, keySz, iv, AES_DECRYPTION);
        if (ret != 0) {
            printf("AesSetKey failed, ret = %d\n", ret);
            goto exit;
        }
    }

    RESET_MULTI_VALUE_STATS_VARS();

    bench_stats_start(&count, &start);
    do {
        for (times = 0; times < numBlocks || pending > 0; ) {
            bench_async_poll(&pending);

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(enc[i]), 0,
                                      &times, numBlocks, &pending)) {
                    ret = wc_AesCbcDecrypt(enc[i], out, in, bench_size);

                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(enc[i]),
                                            0, &times, &pending)) {
                        goto exit_aes_dec;
                    }
                }
            } /* for i */
            RECORD_MULTI_VALUE_STATS();
        } /* for times */
        count += times;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
#endif
           );

exit_aes_dec:
    bench_stats_sym_finish(decLabel, useDeviceID, count, bench_size,
                           start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

#endif /* HAVE_AES_DECRYPT */

    (void)decLabel;
exit:

    if (WC_ARRAY_OK(enc)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            wc_AesFree(enc[i]);
        }
        WC_FREE_ARRAY(enc, BENCH_MAX_PENDING, HEAP_HINT);
    }
}

void bench_aescbc(int useDeviceID)
{
#ifdef WOLFSSL_AES_128
#ifdef HAVE_RENESAS_SYNC
    bench_aescbc_internal(useDeviceID, bench_key1, 16, bench_iv,
                 "AES-128-CBC-enc", "AES-128-CBC-dec");
#else
    bench_aescbc_internal(useDeviceID, bench_key, 16, bench_iv,
                 "AES-128-CBC-enc", "AES-128-CBC-dec");
#endif
#endif
#ifdef WOLFSSL_AES_192
    bench_aescbc_internal(useDeviceID, bench_key, 24, bench_iv,
                 "AES-192-CBC-enc", "AES-192-CBC-dec");
#endif
#ifdef WOLFSSL_AES_256
#ifdef HAVE_RENESAS_SYNC
    bench_aescbc_internal(useDeviceID, bench_key2, 32, bench_iv,
                 "AES-256-CBC-enc", "AES-256-CBC-dec");
#else
    bench_aescbc_internal(useDeviceID, bench_key, 32, bench_iv,
                 "AES-256-CBC-enc", "AES-256-CBC-dec");
#endif
#endif
}

#endif /* HAVE_AES_CBC */

#ifdef HAVE_AESGCM
static void bench_aesgcm_internal(int useDeviceID,
                                  const byte* key, word32 keySz,
                                  const byte* iv,  word32 ivSz,
                                  const char* encLabel, const char* decLabel)
{
    int    ret = 0, i, count = 0, times, pending = 0;
    WC_DECLARE_ARRAY(enc, Aes, BENCH_MAX_PENDING,
                     sizeof(Aes), HEAP_HINT);
#ifdef HAVE_AES_DECRYPT
    WC_DECLARE_ARRAY(dec, Aes, BENCH_MAX_PENDING,
                     sizeof(Aes), HEAP_HINT);
#endif
    double start;
    DECLARE_MULTI_VALUE_STATS_VARS()
    WC_DECLARE_VAR(bench_additional, byte, AES_AUTH_ADD_SZ, HEAP_HINT);
    WC_DECLARE_VAR(bench_tag, byte, AES_AUTH_TAG_SZ, HEAP_HINT);

    WC_ALLOC_VAR(bench_additional, byte, AES_AUTH_ADD_SZ, HEAP_HINT);
    WC_ALLOC_VAR(bench_tag, byte, AES_AUTH_TAG_SZ, HEAP_HINT);
    WC_CALLOC_ARRAY(enc, Aes, BENCH_MAX_PENDING,
                  sizeof(Aes), HEAP_HINT);
#ifdef HAVE_AES_DECRYPT
    WC_CALLOC_ARRAY(dec, Aes, BENCH_MAX_PENDING,
                  sizeof(Aes), HEAP_HINT);
#endif

    XMEMSET(bench_additional, 0, AES_AUTH_ADD_SZ);
    XMEMSET(bench_tag, 0, AES_AUTH_TAG_SZ);

    /* init keys */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        if ((ret = wc_AesInit(enc[i], HEAP_HINT,
                        useDeviceID ? devId: INVALID_DEVID)) != 0) {
            printf("AesInit failed at L%d, ret = %d\n", __LINE__, ret);
            goto exit;
        }

        ret = wc_AesGcmSetKey(enc[i], key, keySz);
        if (ret != 0) {
            printf("AesGcmSetKey failed, ret = %d\n", ret);
            goto exit;
        }
    }

    /* GCM uses same routine in backend for both encrypt and decrypt */
    bench_stats_start(&count, &start);
    do {
        for (times = 0; times < numBlocks || pending > 0; ) {
            bench_async_poll(&pending);

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(enc[i]), 0,
                                      &times, numBlocks, &pending)) {
                    ret = wc_AesGcmEncrypt(enc[i], bench_cipher,
                        bench_plain, bench_size,
                        iv, ivSz, bench_tag, AES_AUTH_TAG_SZ,
                        bench_additional, aesAuthAddSz);
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(enc[i]),
                                            0, &times, &pending)) {
                        goto exit_aes_gcm;
                    }
                }
            } /* for i */
            RECORD_MULTI_VALUE_STATS();
        } /* for times */
        count += times;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
#endif
           );

exit_aes_gcm:
    bench_stats_sym_finish(encLabel, useDeviceID, count, bench_size,
                           start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

#ifdef HAVE_AES_DECRYPT

    RESET_MULTI_VALUE_STATS_VARS();

    /* init keys */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        if ((ret = wc_AesInit(dec[i], HEAP_HINT,
                        useDeviceID ? devId: INVALID_DEVID)) != 0) {
            printf("AesInit failed at L%d, ret = %d\n", __LINE__, ret);
            goto exit;
        }

        ret = wc_AesGcmSetKey(dec[i], key, keySz);
        if (ret != 0) {
            printf("AesGcmSetKey failed, ret = %d\n", ret);
            goto exit;
        }
    }

    bench_stats_start(&count, &start);
    do {
        for (times = 0; times < numBlocks || pending > 0; ) {
            bench_async_poll(&pending);

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(dec[i]), 0,
                                      &times, numBlocks, &pending)) {
                    ret = wc_AesGcmDecrypt(dec[i], bench_plain,
                        bench_cipher, bench_size,
                        iv, ivSz, bench_tag, AES_AUTH_TAG_SZ,
                        bench_additional, aesAuthAddSz);
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(dec[i]),
                                            0, &times, &pending)) {
                        goto exit_aes_gcm_dec;
                    }
                }
            } /* for i */
            RECORD_MULTI_VALUE_STATS();
        } /* for times */
        count += times;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
#endif
           );

exit_aes_gcm_dec:
    bench_stats_sym_finish(decLabel, useDeviceID, count, bench_size,
                           start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif
#endif /* HAVE_AES_DECRYPT */

    (void)decLabel;

exit:

    if (ret < 0) {
        printf("bench_aesgcm failed: %d\n", ret);
    }
#ifdef HAVE_AES_DECRYPT
    if (WC_ARRAY_OK(dec)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            wc_AesFree(dec[i]);
        }
        WC_FREE_ARRAY(dec, BENCH_MAX_PENDING, HEAP_HINT);
    }
#endif
    if (WC_ARRAY_OK(enc)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            wc_AesFree(enc[i]);
        }
        WC_FREE_ARRAY(enc, BENCH_MAX_PENDING, HEAP_HINT);
    }

    WC_FREE_VAR(bench_additional, HEAP_HINT);
    WC_FREE_VAR(bench_tag, HEAP_HINT);
}

#ifdef WOLFSSL_AESGCM_STREAM
static void bench_aesgcm_stream_internal(int useDeviceID,
    const byte* key, word32 keySz, const byte* iv,  word32 ivSz,
    const char* encLabel, const char* decLabel)
{
    int    ret = 0, i, count = 0, times, pending = 0;
    WC_DECLARE_ARRAY(enc, Aes, BENCH_MAX_PENDING,
                     sizeof(Aes), HEAP_HINT);
#ifdef HAVE_AES_DECRYPT
    WC_DECLARE_ARRAY(dec, Aes, BENCH_MAX_PENDING,
                     sizeof(Aes), HEAP_HINT);
#endif
    double start;
    DECLARE_MULTI_VALUE_STATS_VARS()

    WC_DECLARE_VAR(bench_additional, byte, AES_AUTH_ADD_SZ, HEAP_HINT);
    WC_DECLARE_VAR(bench_tag, byte, AES_AUTH_TAG_SZ, HEAP_HINT);

    WC_ALLOC_VAR(bench_additional, byte, AES_AUTH_ADD_SZ, HEAP_HINT);
    WC_ALLOC_VAR(bench_tag, byte, AES_AUTH_TAG_SZ, HEAP_HINT);

    WC_CALLOC_ARRAY(enc, Aes, BENCH_MAX_PENDING,
                  sizeof(Aes), HEAP_HINT);
#ifdef HAVE_AES_DECRYPT
    WC_CALLOC_ARRAY(dec, Aes, BENCH_MAX_PENDING,
                  sizeof(Aes), HEAP_HINT);
#endif

    XMEMSET(bench_additional, 0, AES_AUTH_ADD_SZ);
    XMEMSET(bench_tag, 0, AES_AUTH_TAG_SZ);

    /* init keys */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        if ((ret = wc_AesInit(enc[i], HEAP_HINT,
                        useDeviceID ? devId: INVALID_DEVID)) != 0) {
            printf("AesInit failed at L%d, ret = %d\n", __LINE__, ret);
            goto exit;
        }

        ret = wc_AesGcmSetKey(enc[i], key, keySz);
        if (ret != 0) {
            printf("AesGcmSetKey failed, ret = %d\n", ret);
            goto exit;
        }
    }

    /* GCM uses same routine in backend for both encrypt and decrypt */
    bench_stats_start(&count, &start);
    do {
        for (times = 0; times < numBlocks || pending > 0; ) {
            bench_async_poll(&pending);

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(enc[i]), 0,
                                      &times, numBlocks, &pending)) {
                    ret = wc_AesGcmEncryptInit(enc[i], NULL, 0, iv, ivSz);
                    if (ret == 0) {
                        ret = wc_AesGcmEncryptUpdate(enc[i], bench_cipher,
                            bench_plain, bench_size, bench_additional,
                            aesAuthAddSz);
                    }
                    if (ret == 0) {
                        ret = wc_AesGcmEncryptFinal(enc[i], bench_tag,
                            AES_AUTH_TAG_SZ);
                    }
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(enc[i]),
                                            0, &times, &pending)) {
                        goto exit_aes_gcm;
                    }
                }
            } /* for i */
            RECORD_MULTI_VALUE_STATS();
        } /* for times */
        count += times;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
#endif
           );

exit_aes_gcm:
    bench_stats_sym_finish(encLabel, useDeviceID, count, bench_size,
                           start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

#ifdef HAVE_AES_DECRYPT
    /* init keys */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        if ((ret = wc_AesInit(dec[i], HEAP_HINT,
                        useDeviceID ? devId: INVALID_DEVID)) != 0) {
            printf("AesInit failed at L%d, ret = %d\n", __LINE__, ret);
            goto exit;
        }

        ret = wc_AesGcmSetKey(dec[i], key, keySz);
        if (ret != 0) {
            printf("AesGcmSetKey failed, ret = %d\n", ret);
            goto exit;
        }
    }

    RESET_MULTI_VALUE_STATS_VARS();

    bench_stats_start(&count, &start);
    do {
        for (times = 0; times < numBlocks || pending > 0; ) {
            bench_async_poll(&pending);

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(dec[i]), 0,
                                      &times, numBlocks, &pending)) {
                    ret = wc_AesGcmDecryptInit(enc[i], NULL, 0, iv, ivSz);
                    if (ret == 0) {
                        ret = wc_AesGcmDecryptUpdate(enc[i], bench_plain,
                            bench_cipher, bench_size, bench_additional,
                            aesAuthAddSz);
                    }
                    if (ret == 0) {
                        ret = wc_AesGcmDecryptFinal(enc[i], bench_tag,
                            AES_AUTH_TAG_SZ);
                    }
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(dec[i]),
                                            0, &times, &pending)) {
                        goto exit_aes_gcm_dec;
                    }
                }
            } /* for i */
            RECORD_MULTI_VALUE_STATS();
        } /* for times */
        count += times;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
#endif
           );

exit_aes_gcm_dec:
    bench_stats_sym_finish(decLabel, useDeviceID, count, bench_size,
                           start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif
#endif /* HAVE_AES_DECRYPT */

    (void)decLabel;

exit:

    if (ret < 0) {
        printf("bench_aesgcm failed: %d\n", ret);
    }
#ifdef HAVE_AES_DECRYPT
    if (WC_ARRAY_OK(dec)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            wc_AesFree(dec[i]);
        }
        WC_FREE_ARRAY(dec, BENCH_MAX_PENDING, HEAP_HINT);
    }
#endif
    if (WC_ARRAY_OK(enc)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            wc_AesFree(enc[i]);
        }
        WC_FREE_ARRAY(enc, BENCH_MAX_PENDING, HEAP_HINT);
    }

    WC_FREE_VAR(bench_additional, HEAP_HINT);
    WC_FREE_VAR(bench_tag, HEAP_HINT);
}
#endif

void bench_aesgcm(int useDeviceID)
{
#define AES_GCM_STRING(n, dir)  AES_AAD_STRING("AES-" #n "-GCM-" #dir)
#if defined(WOLFSSL_AES_128) && !defined(WOLFSSL_AFALG_XILINX_AES) \
        && !defined(WOLFSSL_XILINX_CRYPT)                          \
        ||  defined(WOLFSSL_XILINX_CRYPT_VERSAL)
#ifdef HAVE_RENESAS_SYNC
    bench_aesgcm_internal(useDeviceID, bench_key1, 16, bench_iv, 12,
                          AES_GCM_STRING(128, enc), AES_GCM_STRING(128, dec));
#else
    bench_aesgcm_internal(useDeviceID, bench_key, 16, bench_iv, 12,
                          AES_GCM_STRING(128, enc), AES_GCM_STRING(128, dec));
#endif
#endif
#if defined(WOLFSSL_AES_192) && !defined(WOLFSSL_AFALG_XILINX_AES) \
        && !defined(WOLFSSL_XILINX_CRYPT)
    bench_aesgcm_internal(useDeviceID, bench_key, 24, bench_iv, 12,
                          AES_GCM_STRING(192, enc), AES_GCM_STRING(192, dec));
#endif
#ifdef WOLFSSL_AES_256
#ifdef HAVE_RENESAS_SYNC
    bench_aesgcm_internal(useDeviceID, bench_key2, 32, bench_iv, 12,
                          AES_GCM_STRING(256, enc), AES_GCM_STRING(256, dec));
#else
    bench_aesgcm_internal(useDeviceID, bench_key, 32, bench_iv, 12,
                          AES_GCM_STRING(256, enc), AES_GCM_STRING(256, dec));
#endif
#endif
#ifdef WOLFSSL_AESGCM_STREAM
#undef AES_GCM_STRING
#define AES_GCM_STRING(n, dir)  AES_AAD_STRING("AES-" #n "-GCM-STREAM-" #dir)
#if defined(WOLFSSL_AES_128) && !defined(WOLFSSL_AFALG_XILINX_AES) \
        && !defined(WOLFSSL_XILINX_CRYPT)                          \
        ||  defined(WOLFSSL_XILINX_CRYPT_VERSAL)
    bench_aesgcm_stream_internal(useDeviceID, bench_key, 16, bench_iv, 12,
        AES_GCM_STRING(128, enc), AES_GCM_STRING(128, dec));
#endif
#if defined(WOLFSSL_AES_192) && !defined(WOLFSSL_AFALG_XILINX_AES) \
        && !defined(WOLFSSL_XILINX_CRYPT)
    bench_aesgcm_stream_internal(useDeviceID, bench_key, 24, bench_iv, 12,
        AES_GCM_STRING(192, enc), AES_GCM_STRING(192, dec));
#endif
#ifdef WOLFSSL_AES_256
    bench_aesgcm_stream_internal(useDeviceID, bench_key, 32, bench_iv, 12,
        AES_GCM_STRING(256, enc), AES_GCM_STRING(256, dec));
#endif
#endif /* WOLFSSL_AESGCM_STREAM */
#undef AES_GCM_STRING
}

/* GMAC */
void bench_gmac(int useDeviceID)
{
    int ret, count = 0;
    Gmac gmac;
    double start;
    byte tag[AES_AUTH_TAG_SZ];
    DECLARE_MULTI_VALUE_STATS_VARS()

    /* determine GCM GHASH method */
#ifdef GCM_SMALL
    const char* gmacStr = "GMAC Small";
#elif defined(GCM_TABLE)
    const char* gmacStr = "GMAC Table";
#elif defined(GCM_TABLE_4BIT)
    const char* gmacStr = "GMAC Table 4-bit";
#elif defined(GCM_WORD32)
    const char* gmacStr = "GMAC Word32";
#else
    const char* gmacStr = "GMAC Default";
#endif

/* Implementations of /Dev/Crypto will error out if the size of Auth in is */
/* greater than the system's page size */
#if defined(WOLFSSL_DEVCRYPTO) && defined(WOLFSSL_AUTHSZ_BENCH)
    bench_size = WOLFSSL_AUTHSZ_BENCH;
#elif defined(WOLFSSL_DEVCRYPTO)
    bench_size = sysconf(_SC_PAGESIZE);
#endif

    /* init keys */
    XMEMSET(bench_plain, 0, bench_size);
    XMEMSET(tag, 0, sizeof(tag));
    XMEMSET(&gmac, 0, sizeof(Gmac)); /* clear context */
    (void)wc_AesInit((Aes*)&gmac, HEAP_HINT,
                useDeviceID ? devId: INVALID_DEVID);
#ifdef HAVE_RENESAS_SYNC
    wc_GmacSetKey(&gmac, bench_key1, 16);
#else
    wc_GmacSetKey(&gmac, bench_key, 16);
#endif
    bench_stats_start(&count, &start);
    do {
        ret = wc_GmacUpdate(&gmac, bench_iv, 12, bench_plain, bench_size,
            tag, sizeof(tag));

        count++;
        RECORD_MULTI_VALUE_STATS();
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
#endif
           );

    wc_AesFree((Aes*)&gmac);

    bench_stats_sym_finish(gmacStr, 0, count, bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif
#if defined(WOLFSSL_DEVCRYPTO)
    if (ret != 0 && (bench_size > sysconf(_SC_PAGESIZE))) {
        printf("authIn Buffer Size[%d] greater than System Page Size[%ld]\n",
                        bench_size, sysconf(_SC_PAGESIZE));
    }
    bench_size = BENCH_SIZE;
#endif
}

#endif /* HAVE_AESGCM */


#ifdef HAVE_AES_ECB
static void bench_aesecb_internal(int useDeviceID,
                                  const byte* key, word32 keySz,
                                  const char* encLabel, const char* decLabel)
{
    int    ret = 0, i, count = 0, times, pending = 0;
    WC_DECLARE_ARRAY(enc, Aes, BENCH_MAX_PENDING,
                     sizeof(Aes), HEAP_HINT);
    double start;
    DECLARE_MULTI_VALUE_STATS_VARS()
#ifdef HAVE_FIPS
    const word32 benchSz = WC_AES_BLOCK_SIZE;
#else
    const word32 benchSz = bench_size;
#endif

    WC_CALLOC_ARRAY(enc, Aes, BENCH_MAX_PENDING,
                     sizeof(Aes), HEAP_HINT);

    /* init keys */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        if ((ret = wc_AesInit(enc[i], HEAP_HINT,
                                useDeviceID ? devId: INVALID_DEVID)) != 0) {
            printf("AesInit failed at L%d, ret = %d\n", __LINE__, ret);
            goto exit;
        }

        ret = wc_AesSetKey(enc[i], key, keySz, bench_iv, AES_ENCRYPTION);
        if (ret != 0) {
            printf("AesSetKey failed, ret = %d\n", ret);
            goto exit;
        }
    }

    bench_stats_start(&count, &start);
    do {
        int outer_loop_limit = (int)((bench_size / benchSz) * 10) + 1;
        for (times = 0;
             times < outer_loop_limit /* numBlocks */ || pending > 0;
            ) {
            bench_async_poll(&pending);

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(enc[i]), 0,
                                      &times, outer_loop_limit, &pending)) {
                #ifdef HAVE_FIPS
                    wc_AesEncryptDirect(enc[i], bench_cipher, bench_plain);
                #else
                    wc_AesEcbEncrypt(enc[i], bench_cipher, bench_plain,
                        benchSz);
                #endif
                    ret = 0;
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(enc[i]),
                                            0, &times, &pending)) {
                        goto exit_aes_enc;
                    }
                }
            } /* for i */
            RECORD_MULTI_VALUE_STATS();
        } /* for times */
        count += times;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
#endif
           );

exit_aes_enc:
    bench_stats_sym_finish(encLabel, useDeviceID, count, benchSz,
                           start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

#ifdef HAVE_AES_DECRYPT
    /* init keys */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        ret = wc_AesSetKey(enc[i], key, keySz, bench_iv, AES_DECRYPTION);
        if (ret != 0) {
            printf("AesSetKey failed, ret = %d\n", ret);
            goto exit;
        }
    }

    RESET_MULTI_VALUE_STATS_VARS();

    bench_stats_start(&count, &start);
    do {
        int outer_loop_limit = (int)(10 * (bench_size / benchSz)) + 1;
        for (times = 0; times < outer_loop_limit || pending > 0; ) {
            bench_async_poll(&pending);

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(enc[i]), 0,
                                      &times, outer_loop_limit, &pending)) {
                #ifdef HAVE_FIPS
                    wc_AesDecryptDirect(enc[i], bench_plain, bench_cipher);
                #else
                    wc_AesEcbDecrypt(enc[i], bench_plain, bench_cipher,
                        benchSz);
                #endif
                    ret = 0;
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(enc[i]),
                                            0, &times, &pending)) {
                        goto exit_aes_dec;
                    }
                }
            } /* for i */
            RECORD_MULTI_VALUE_STATS();
        } /* for times */
        count += times;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
#endif
           );

exit_aes_dec:
    bench_stats_sym_finish(decLabel, useDeviceID, count, benchSz,
                           start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

#endif /* HAVE_AES_DECRYPT */

    (void)decLabel;

exit:

    if (WC_ARRAY_OK(enc)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            wc_AesFree(enc[i]);
        }
        WC_FREE_ARRAY(enc, BENCH_MAX_PENDING, HEAP_HINT);
    }
}

void bench_aesecb(int useDeviceID)
{
#ifdef WOLFSSL_AES_128
    bench_aesecb_internal(useDeviceID, bench_key, 16,
                 "AES-128-ECB-enc", "AES-128-ECB-dec");
#endif
#ifdef WOLFSSL_AES_192
    bench_aesecb_internal(useDeviceID, bench_key, 24,
                 "AES-192-ECB-enc", "AES-192-ECB-dec");
#endif
#ifdef WOLFSSL_AES_256
    bench_aesecb_internal(useDeviceID, bench_key, 32,
                 "AES-256-ECB-enc", "AES-256-ECB-dec");
#endif
}
#endif /* HAVE_AES_ECB */

#ifdef WOLFSSL_AES_CFB
static void bench_aescfb_internal(const byte* key,
                                  word32 keySz, const byte* iv,
                                  const char* label)
{
    Aes    enc;
    double start;
    int    i, ret, count;
    DECLARE_MULTI_VALUE_STATS_VARS()

    ret = wc_AesInit(&enc, HEAP_HINT, INVALID_DEVID);
    if (ret != 0) {
        printf("AesInit failed at L%d, ret = %d\n", __LINE__, ret);
        return;
    }

    ret = wc_AesSetKey(&enc, key, keySz, iv, AES_ENCRYPTION);
    if (ret != 0) {
        printf("AesSetKey failed, ret = %d\n", ret);
        goto out;
    }

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            if((ret = wc_AesCfbEncrypt(&enc, bench_plain, bench_cipher,
                            bench_size)) != 0) {
                printf("wc_AesCfbEncrypt failed, ret = %d\n", ret);
                goto out;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
#endif
           );

    bench_stats_sym_finish(label, 0, count, bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

out:

    wc_AesFree(&enc);
    return;
}

void bench_aescfb(void)
{
#ifdef WOLFSSL_AES_128
    bench_aescfb_internal(bench_key, 16, bench_iv, "AES-128-CFB");
#endif
#ifdef WOLFSSL_AES_192
    bench_aescfb_internal(bench_key, 24, bench_iv, "AES-192-CFB");
#endif
#ifdef WOLFSSL_AES_256
    bench_aescfb_internal(bench_key, 32, bench_iv, "AES-256-CFB");
#endif
}
#endif /* WOLFSSL_AES_CFB */


#ifdef WOLFSSL_AES_OFB
static void bench_aesofb_internal(const byte* key,
                                  word32 keySz, const byte* iv,
                                  const char* label)
{
    Aes    enc;
    double start;
    int    i, ret, count;
    DECLARE_MULTI_VALUE_STATS_VARS()

    ret = wc_AesInit(&enc, NULL, INVALID_DEVID);
    if (ret != 0) {
        printf("AesInit failed at L%d, ret = %d\n", __LINE__, ret);
        return;
    }

    ret = wc_AesSetKey(&enc, key, keySz, iv, AES_ENCRYPTION);
    if (ret != 0) {
        printf("AesSetKey failed, ret = %d\n", ret);
        return;
    }

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            if((ret = wc_AesOfbEncrypt(&enc, bench_plain, bench_cipher,
                            bench_size)) != 0) {
                printf("wc_AesCfbEncrypt failed, ret = %d\n", ret);
                return;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
#endif
           );

    bench_stats_sym_finish(label, 0, count, bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    wc_AesFree(&enc);
}

void bench_aesofb(void)
{
#ifdef WOLFSSL_AES_128
    bench_aesofb_internal(bench_key, 16, bench_iv, "AES-128-OFB");
#endif
#ifdef WOLFSSL_AES_192
    bench_aesofb_internal(bench_key, 24, bench_iv, "AES-192-OFB");
#endif
#ifdef WOLFSSL_AES_256
    bench_aesofb_internal(bench_key, 32, bench_iv, "AES-256-OFB");
#endif
}
#endif /* WOLFSSL_AES_CFB */


#ifdef WOLFSSL_AES_XTS
void bench_aesxts(void)
{
    WC_DECLARE_VAR(aes, XtsAes, 1, HEAP_HINT);
    double start;
    int    i, count, ret;
    DECLARE_MULTI_VALUE_STATS_VARS()

    static const unsigned char k1[] = {
        0xa1, 0xb9, 0x0c, 0xba, 0x3f, 0x06, 0xac, 0x35,
        0x3b, 0x2c, 0x34, 0x38, 0x76, 0x08, 0x17, 0x62,
        0x09, 0x09, 0x23, 0x02, 0x6e, 0x91, 0x77, 0x18,
        0x15, 0xf2, 0x9d, 0xab, 0x01, 0x93, 0x2f, 0x2f
    };

    static const unsigned char i1[] = {
        0x4f, 0xae, 0xf7, 0x11, 0x7c, 0xda, 0x59, 0xc6,
        0x6e, 0x4b, 0x92, 0x01, 0x3e, 0x76, 0x8a, 0xd5
    };

    WC_ALLOC_VAR(aes, XtsAes, 1, HEAP_HINT);

    ret = wc_AesXtsSetKey(aes, k1, sizeof(k1), AES_ENCRYPTION,
            HEAP_HINT, devId);
    if (ret != 0) {
        printf("wc_AesXtsSetKey failed, ret = %d\n", ret);
        goto exit;
    }

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            if ((ret = wc_AesXtsEncrypt(aes, bench_cipher, bench_plain,
                            bench_size, i1, sizeof(i1))) != 0) {
                printf("wc_AesXtsEncrypt failed, ret = %d\n", ret);
                goto exit;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
#endif
           );

    bench_stats_sym_finish("AES-XTS-enc", 0, count, bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif
    wc_AesXtsFree(aes);

    /* decryption benchmark */
    ret = wc_AesXtsSetKey(aes, k1, sizeof(k1), AES_DECRYPTION,
            HEAP_HINT, devId);
    if (ret != 0) {
        printf("wc_AesXtsSetKey failed, ret = %d\n", ret);
        goto exit;
    }

    RESET_MULTI_VALUE_STATS_VARS();

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            if ((ret = wc_AesXtsDecrypt(aes, bench_plain, bench_cipher,
                            bench_size, i1, sizeof(i1))) != 0) {
                printf("wc_AesXtsDecrypt failed, ret = %d\n", ret);
                goto exit;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
#endif
           );

    bench_stats_sym_finish("AES-XTS-dec", 0, count, bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

exit:

    wc_AesXtsFree(aes);
    WC_FREE_VAR(aes, HEAP_HINT);
}
#endif /* WOLFSSL_AES_XTS */


#ifdef WOLFSSL_AES_COUNTER
static void bench_aesctr_internal(const byte* key, word32 keySz,
                                  const byte* iv,  const char* label,
                                  int useDeviceID)
{
    Aes    enc;
    double start;
    int    i, count, ret = 0;
    DECLARE_MULTI_VALUE_STATS_VARS()

    if ((ret = wc_AesInit(&enc, HEAP_HINT,
        useDeviceID ? devId : INVALID_DEVID)) != 0) {
        printf("wc_AesInit failed, ret = %d\n", ret);
    }

    if (wc_AesSetKeyDirect(&enc, key, keySz, iv, AES_ENCRYPTION) < 0) {
        printf("wc_AesSetKeyDirect failed, ret = %d\n", ret);
        return;
    }

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            if((ret = wc_AesCtrEncrypt(&enc, bench_plain, bench_cipher,
                                       bench_size)) != 0) {
                printf("wc_AesCtrEncrypt failed, ret = %d\n", ret);
                return;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
#endif
           );

    bench_stats_sym_finish(label, useDeviceID, count, bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    wc_AesFree(&enc);
}

void bench_aesctr(int useDeviceID)
{
#ifdef WOLFSSL_AES_128
    bench_aesctr_internal(bench_key, 16, bench_iv, "AES-128-CTR", useDeviceID);
#endif
#ifdef WOLFSSL_AES_192
    bench_aesctr_internal(bench_key, 24, bench_iv, "AES-192-CTR", useDeviceID);
#endif
#ifdef WOLFSSL_AES_256
    bench_aesctr_internal(bench_key, 32, bench_iv, "AES-256-CTR", useDeviceID);
#endif
}
#endif /* WOLFSSL_AES_COUNTER */


#ifdef HAVE_AESCCM
void bench_aesccm(int useDeviceID)
{
    Aes    enc;
    int    enc_inited = 0;
    double start;
    int    ret, i, count;
    DECLARE_MULTI_VALUE_STATS_VARS()

    WC_DECLARE_VAR(bench_additional, byte, AES_AUTH_ADD_SZ, HEAP_HINT);
    WC_DECLARE_VAR(bench_tag, byte, AES_AUTH_TAG_SZ, HEAP_HINT);

    WC_ALLOC_VAR(bench_additional, byte, AES_AUTH_ADD_SZ, HEAP_HINT);
    WC_ALLOC_VAR(bench_tag, byte, AES_AUTH_TAG_SZ, HEAP_HINT);

    XMEMSET(bench_tag, 0, AES_AUTH_TAG_SZ);
    XMEMSET(bench_additional, 0, AES_AUTH_ADD_SZ);

    if ((ret = wc_AesInit(&enc, HEAP_HINT,
        useDeviceID ? devId : INVALID_DEVID)) != 0)
    {
        printf("wc_AesInit failed, ret = %d\n", ret);
        goto exit;
    }

    if ((ret = wc_AesCcmSetKey(&enc, bench_key, 16)) != 0) {
        printf("wc_AesCcmSetKey failed, ret = %d\n", ret);
        goto exit;
    }
    enc_inited = 1;

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            ret |= wc_AesCcmEncrypt(&enc, bench_cipher, bench_plain, bench_size,
                bench_iv, 12, bench_tag, AES_AUTH_TAG_SZ,
                bench_additional, 0);
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
#endif
           );

    bench_stats_sym_finish(AES_AAD_STRING("AES-CCM-enc"), useDeviceID, count,
        bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif
    if (ret != 0) {
        printf("wc_AesCcmEncrypt failed, ret = %d\n", ret);
        goto exit;
    }

#ifdef HAVE_AES_DECRYPT
    RESET_MULTI_VALUE_STATS_VARS();

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            ret |= wc_AesCcmDecrypt(&enc, bench_plain, bench_cipher, bench_size,
                bench_iv, 12, bench_tag, AES_AUTH_TAG_SZ,
                bench_additional, 0);
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
#endif
           );

    bench_stats_sym_finish(AES_AAD_STRING("AES-CCM-dec"), useDeviceID, count,
        bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif
    if (ret != 0) {
        printf("wc_AesCcmEncrypt failed, ret = %d\n", ret);
        goto exit;
    }
#endif

  exit:

    if (enc_inited)
        wc_AesFree(&enc);

    WC_FREE_VAR(bench_additional, HEAP_HINT);
    WC_FREE_VAR(bench_tag, HEAP_HINT);
}
#endif /* HAVE_AESCCM */


#ifdef WOLFSSL_AES_SIV
static void bench_aessiv_internal(const byte* key, word32 keySz, const char*
                                  encLabel, const char* decLabel)
{
    int i;
    int ret = 0;
    byte assoc[WC_AES_BLOCK_SIZE];
    byte nonce[WC_AES_BLOCK_SIZE];
    byte siv[WC_AES_BLOCK_SIZE];
    int count = 0;
    double start;
    DECLARE_MULTI_VALUE_STATS_VARS()

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            ret = wc_AesSivEncrypt(key, keySz, assoc, WC_AES_BLOCK_SIZE, nonce,
                                   WC_AES_BLOCK_SIZE, bench_plain, bench_size,
                                   siv, bench_cipher);
            if (ret != 0) {
                printf("wc_AesSivEncrypt failed (%d)\n", ret);
                return;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
#endif
           );

    bench_stats_sym_finish(encLabel, 0, count, bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    RESET_MULTI_VALUE_STATS_VARS();

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            ret = wc_AesSivDecrypt(key, keySz, assoc, WC_AES_BLOCK_SIZE, nonce,
                                   WC_AES_BLOCK_SIZE, bench_cipher, bench_size,
                                   siv, bench_plain);
            if (ret != 0) {
                printf("wc_AesSivDecrypt failed (%d)\n", ret);
                return;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
#endif
           );

    bench_stats_sym_finish(decLabel, 0, count, bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif
}

void bench_aessiv(void)
{
    bench_aessiv_internal(bench_key, 32, "AES-256-SIV-enc", "AES-256-SIV-dec");
    bench_aessiv_internal(bench_key, 48, "AES-384-SIV-enc", "AES-384-SIV-dec");
    bench_aessiv_internal(bench_key, 64, "AES-512-SIV-enc", "AES-512-SIV-dec");
}
#endif /* WOLFSSL_AES_SIV */
#endif /* !NO_AES */


#ifdef HAVE_POLY1305
void bench_poly1305(void)
{
    Poly1305 enc;
    byte     mac[16];
    double   start;
    int      ret = 0, i, count;
    DECLARE_MULTI_VALUE_STATS_VARS()

    if (digest_stream) {
        ret = wc_Poly1305SetKey(&enc, bench_key, 32);
        if (ret != 0) {
            printf("Poly1305SetKey failed, ret = %d\n", ret);
            return;
        }

        bench_stats_start(&count, &start);
        do {
            for (i = 0; i < numBlocks; i++) {
                ret = wc_Poly1305Update(&enc, bench_plain, bench_size);
                if (ret != 0) {
                    printf("Poly1305Update failed: %d\n", ret);
                    break;
                }
                RECORD_MULTI_VALUE_STATS();
            }
            wc_Poly1305Final(&enc, mac);
            count += i;
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
    else {
        bench_stats_start(&count, &start);
        do {
            for (i = 0; i < numBlocks; i++) {
                ret = wc_Poly1305SetKey(&enc, bench_key, 32);
                if (ret != 0) {
                    printf("Poly1305SetKey failed, ret = %d\n", ret);
                    return;
                }
                ret = wc_Poly1305Update(&enc, bench_plain, bench_size);
                if (ret != 0) {
                    printf("Poly1305Update failed: %d\n", ret);
                    break;
                }
                wc_Poly1305Final(&enc, mac);
                RECORD_MULTI_VALUE_STATS();
            }
            count += i;
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
    bench_stats_sym_finish("POLY1305", 0, count, bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif
}
#endif /* HAVE_POLY1305 */


#ifdef HAVE_CAMELLIA
void bench_camellia(void)
{
    wc_Camellia cam;
    double   start;
    int      ret, i, count;
    DECLARE_MULTI_VALUE_STATS_VARS()

    ret = wc_CamelliaSetKey(&cam, bench_key, 16, bench_iv);
    if (ret != 0) {
        printf("CamelliaSetKey failed, ret = %d\n", ret);
        return;
    }

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            ret = wc_CamelliaCbcEncrypt(&cam, bench_cipher, bench_plain,
                                                            bench_size);
            if (ret < 0) {
                printf("CamelliaCbcEncrypt failed: %d\n", ret);
                return;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
   } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_sym_finish("Camellia", 0, count, bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif
}
#endif

#ifdef WOLFSSL_SM4_CBC
void bench_sm4_cbc(void)
{
    wc_Sm4 sm4;
    double start;
    int    ret;
    int    i;
    int    count;
    DECLARE_MULTI_VALUE_STATS_VARS()

    ret = wc_Sm4SetKey(&sm4, bench_key, SM4_KEY_SIZE);
    if (ret != 0) {
        printf("Sm4SetKey failed, ret = %d\n", ret);
        return;
    }
    ret = wc_Sm4SetIV(&sm4, bench_iv);
    if (ret != 0) {
        printf("Sm4SetIV failed, ret = %d\n", ret);
        return;
    }

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            ret = wc_Sm4CbcEncrypt(&sm4, bench_cipher, bench_plain, bench_size);
            if (ret < 0) {
                printf("Sm4CbcEncrypt failed: %d\n", ret);
                return;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_sym_finish("SM4-CBC-enc", 0, count, bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    RESET_MULTI_VALUE_STATS_VARS();

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            ret = wc_Sm4CbcDecrypt(&sm4, bench_plain, bench_cipher, bench_size);
            if (ret < 0) {
                printf("Sm4CbcDecrypt failed: %d\n", ret);
                return;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_sym_finish("SM4-CBC-dec", 0, count, bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif
}
#endif

#ifdef WOLFSSL_SM4_GCM
void bench_sm4_gcm(void)
{
    wc_Sm4 sm4;
    double start;
    int    ret;
    int    i;
    int    count;
    DECLARE_MULTI_VALUE_STATS_VARS()

    WC_DECLARE_VAR(bench_additional, byte, AES_AUTH_ADD_SZ, HEAP_HINT);
    WC_DECLARE_VAR(bench_tag, byte, AES_AUTH_TAG_SZ, HEAP_HINT);

    WC_ALLOC_VAR(bench_additional, byte, AES_AUTH_ADD_SZ, HEAP_HINT);
    WC_ALLOC_VAR(bench_tag, byte, AES_AUTH_TAG_SZ, HEAP_HINT);

    ret = wc_Sm4GcmSetKey(&sm4, bench_key, SM4_KEY_SIZE);
    if (ret != 0) {
        printf("Sm4GcmSetKey failed, ret = %d\n", ret);
        goto exit;
    }

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            ret = wc_Sm4GcmEncrypt(&sm4, bench_cipher, bench_plain, bench_size,
                bench_iv, GCM_NONCE_MID_SZ, bench_tag, SM4_BLOCK_SIZE,
                bench_additional, aesAuthAddSz);
            if (ret < 0) {
                printf("Sm4GcmEncrypt failed: %d\n", ret);
                goto exit;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_sym_finish("SM4-GCM-enc", 0, count, bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    RESET_MULTI_VALUE_STATS_VARS();

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            ret = wc_Sm4GcmDecrypt(&sm4, bench_plain, bench_cipher, bench_size,
                bench_iv, GCM_NONCE_MID_SZ, bench_tag, SM4_BLOCK_SIZE,
                bench_additional, aesAuthAddSz);
            if (ret < 0) {
                printf("Sm4GcmDecrypt failed: %d\n", ret);
                goto exit;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_sym_finish("SM4-GCM-dec", 0, count, bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

exit:

    WC_FREE_VAR(bench_additional, HEAP_HINT);
    WC_FREE_VAR(bench_tag, HEAP_HINT);
}
#endif

#ifdef WOLFSSL_SM4_CCM
void bench_sm4_ccm(void)
{
    wc_Sm4 enc;
    double start;
    int    ret, i, count;
    DECLARE_MULTI_VALUE_STATS_VARS()

    WC_DECLARE_VAR(bench_additional, byte, AES_AUTH_ADD_SZ, HEAP_HINT);
    WC_DECLARE_VAR(bench_tag, byte, AES_AUTH_TAG_SZ, HEAP_HINT);

    WC_ALLOC_VAR(bench_additional, byte, AES_AUTH_ADD_SZ, HEAP_HINT);
    WC_ALLOC_VAR(bench_tag, byte, AES_AUTH_TAG_SZ, HEAP_HINT);

    XMEMSET(bench_tag, 0, AES_AUTH_TAG_SZ);
    XMEMSET(bench_additional, 0, AES_AUTH_ADD_SZ);

    if ((ret = wc_Sm4SetKey(&enc, bench_key, 16)) != 0) {
        printf("wc_Sm4SetKey failed, ret = %d\n", ret);
        goto exit;
    }

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            ret |= wc_Sm4CcmEncrypt(&enc, bench_cipher, bench_plain, bench_size,
                bench_iv, 12, bench_tag, AES_AUTH_TAG_SZ,
                bench_additional, 0);
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_sym_finish("SM4-CCM-enc", 0, count, bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif
    if (ret != 0) {
        printf("wc_Sm4Encrypt failed, ret = %d\n", ret);
        goto exit;
    }

    RESET_MULTI_VALUE_STATS_VARS();

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            ret |= wc_Sm4CcmDecrypt(&enc, bench_plain, bench_cipher, bench_size,
                bench_iv, 12, bench_tag, AES_AUTH_TAG_SZ,
                bench_additional, 0);
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_sym_finish("SM4-CCM-dec", 0, count, bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif
    if (ret != 0) {
        printf("wc_Sm4Decrypt failed, ret = %d\n", ret);
        goto exit;
    }

  exit:

    WC_FREE_VAR(bench_additional, HEAP_HINT);
    WC_FREE_VAR(bench_tag, HEAP_HINT);
}
#endif /* HAVE_AESCCM */
#ifndef NO_DES3
void bench_des(int useDeviceID)
{
    int    ret = 0, i, count = 0, times, pending = 0;
    WC_DECLARE_ARRAY(enc, Des3, BENCH_MAX_PENDING,
                     sizeof(Des3), HEAP_HINT);
    double start;
    DECLARE_MULTI_VALUE_STATS_VARS()

    WC_CALLOC_ARRAY(enc, Des3, BENCH_MAX_PENDING,
                     sizeof(Des3), HEAP_HINT);

    /* init keys */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        if ((ret = wc_Des3Init(enc[i], HEAP_HINT,
                                useDeviceID ? devId : INVALID_DEVID)) != 0) {
            printf("Des3Init failed, ret = %d\n", ret);
            goto exit;
        }

        ret = wc_Des3_SetKey(enc[i], bench_key, bench_iv, DES_ENCRYPTION);
        if (ret != 0) {
            printf("Des3_SetKey failed, ret = %d\n", ret);
            goto exit;
        }
    }

    bench_stats_start(&count, &start);
    do {
        for (times = 0; times < numBlocks || pending > 0; ) {
            bench_async_poll(&pending);

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(enc[i]), 0,
                                      &times, numBlocks, &pending)) {
                    ret = wc_Des3_CbcEncrypt(enc[i],
                                             bench_cipher,
                                             bench_plain, bench_size);
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(enc[i]),
                                            0, &times, &pending)) {
                        goto exit_3des;
                    }
                }
            } /* for i */
            RECORD_MULTI_VALUE_STATS();
        } /* for times */
        count += times;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

exit_3des:
    bench_stats_sym_finish("3DES", useDeviceID, count, bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

exit:

    if (WC_ARRAY_OK(enc)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            wc_Des3Free(enc[i]);
        }
        WC_FREE_ARRAY(enc, BENCH_MAX_PENDING, HEAP_HINT);
    }
}
#endif /* !NO_DES3 */


#ifndef NO_RC4
void bench_arc4(int useDeviceID)
{
    int    ret = 0, i, count = 0, times, pending = 0;
    WC_DECLARE_ARRAY(enc, Arc4, BENCH_MAX_PENDING,
                     sizeof(Arc4), HEAP_HINT);
    double start;
    DECLARE_MULTI_VALUE_STATS_VARS()

    WC_CALLOC_ARRAY(enc, Arc4, BENCH_MAX_PENDING,
                     sizeof(Arc4), HEAP_HINT);

    /* init keys */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        if ((ret = wc_Arc4Init(enc[i], HEAP_HINT,
                            useDeviceID ? devId : INVALID_DEVID)) != 0) {
            printf("Arc4Init failed, ret = %d\n", ret);
            goto exit;
        }

        ret = wc_Arc4SetKey(enc[i], bench_key, 16);
        if (ret != 0) {
            printf("Arc4SetKey failed, ret = %d\n", ret);
            goto exit;
        }
    }

    bench_stats_start(&count, &start);
    do {
        for (times = 0; times < numBlocks || pending > 0; ) {
            bench_async_poll(&pending);

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(enc[i]), 0,
                                      &times, numBlocks, &pending)) {
                    ret = wc_Arc4Process(enc[i], bench_cipher, bench_plain,
                                         bench_size);
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(enc[i]),
                                            0, &times, &pending)) {
                        goto exit_arc4;
                    }
                }
            } /* for i */
            RECORD_MULTI_VALUE_STATS();
        } /* for times */
        count += times;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

exit_arc4:
    bench_stats_sym_finish("ARC4", useDeviceID, count, bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

exit:

    if (WC_ARRAY_OK(enc)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            wc_Arc4Free(enc[i]);
        }
        WC_FREE_ARRAY(enc, BENCH_MAX_PENDING, HEAP_HINT);
    }
}
#endif /* !NO_RC4 */


#ifdef HAVE_CHACHA
void bench_chacha(void)
{
    WC_DECLARE_VAR(enc, ChaCha, 1, HEAP_HINT);
    double start;
    int    ret, i, count;
    DECLARE_MULTI_VALUE_STATS_VARS()

    WC_ALLOC_VAR(enc, ChaCha, 1, HEAP_HINT);

    XMEMSET(enc, 0, sizeof(ChaCha));
    wc_Chacha_SetKey(enc, bench_key, 16);

    if (encrypt_only) {
        ret = wc_Chacha_SetIV(enc, bench_iv, 0);
        if (ret < 0) {
            printf("wc_Chacha_SetIV error: %d\n", ret);
            goto exit;
        }
        bench_stats_start(&count, &start);
        do {
            for (i = 0; i < numBlocks; i++) {
                ret = wc_Chacha_Process(enc, bench_cipher, bench_plain,
                    bench_size);
                if (ret < 0) {
                    printf("wc_Chacha_Process error: %d\n", ret);
                    goto exit;
                }
                RECORD_MULTI_VALUE_STATS();
            }
            count += i;
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
            || runs < minimum_runs
    #endif
            );
    }
    else {
        bench_stats_start(&count, &start);
        do {
            for (i = 0; i < numBlocks; i++) {
                ret = wc_Chacha_SetIV(enc, bench_iv, 0);
                if (ret < 0) {
                    printf("wc_Chacha_SetIV error: %d\n", ret);
                    goto exit;
                }
                ret = wc_Chacha_Process(enc, bench_cipher, bench_plain,
                    bench_size);
                if (ret < 0) {
                    printf("wc_Chacha_Process error: %d\n", ret);
                    goto exit;
                }
                RECORD_MULTI_VALUE_STATS();
            }
            count += i;
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
            || runs < minimum_runs
    #endif
            );
    }

    bench_stats_sym_finish("CHACHA", 0, count, bench_size, start, 0);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

exit:
    WC_FREE_VAR(enc, HEAP_HINT);
}
#endif /* HAVE_CHACHA*/

#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
void bench_chacha20_poly1305_aead(void)
{
    double start;
    int    ret = 0, i, count;
    DECLARE_MULTI_VALUE_STATS_VARS()

    WC_DECLARE_VAR(authTag, byte, CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE, HEAP_HINT);
    WC_ALLOC_VAR(authTag, byte, CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE, HEAP_HINT);
    XMEMSET(authTag, 0, CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE);

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            ret = wc_ChaCha20Poly1305_Encrypt(bench_key, bench_iv, NULL, 0,
                bench_plain, bench_size, bench_cipher, authTag);
            if (ret < 0) {
                printf("wc_ChaCha20Poly1305_Encrypt error: %d\n", ret);
                goto exit;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
        || runs < minimum_runs
#endif
        );

    bench_stats_sym_finish("CHA-POLY", 0, count, bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

exit:

    WC_FREE_VAR(authTag, HEAP_HINT);
}
#endif /* HAVE_CHACHA && HAVE_POLY1305 */


#ifndef NO_MD5
void bench_md5(int useDeviceID)
{
    WC_DECLARE_ARRAY(hash, wc_Md5, BENCH_MAX_PENDING,
                     sizeof(wc_Md5), HEAP_HINT);
    double start = 0;
    int    ret = 0, i, count = 0, times, pending = 0;
    DECLARE_MULTI_VALUE_STATS_VARS()
    WC_DECLARE_ARRAY(digest, byte, BENCH_MAX_PENDING,
                     WC_MD5_DIGEST_SIZE, HEAP_HINT);

    WC_CALLOC_ARRAY(hash, wc_Md5, BENCH_MAX_PENDING,
                     sizeof(wc_Md5), HEAP_HINT);
    WC_ALLOC_ARRAY(digest, byte, BENCH_MAX_PENDING,
                  WC_MD5_DIGEST_SIZE, HEAP_HINT);

    if (digest_stream) {
        /* init keys */
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            ret = wc_InitMd5_ex(hash[i], HEAP_HINT,
                        useDeviceID ? devId : INVALID_DEVID);
            if (ret != 0) {
                printf("InitMd5_ex failed, ret = %d\n", ret);
                goto exit;
            }
        #ifdef WOLFSSL_PIC32MZ_HASH
            wc_Md5SizeSet(hash[i], numBlocks * bench_size);
        #endif
        }

        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < numBlocks || pending > 0; ) {
                bench_async_poll(&pending);

                /* while free pending slots in queue, submit ops */
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(hash[i]),
                                          0, &times, numBlocks, &pending)) {
                        ret = wc_Md5Update(hash[i], bench_plain,
                                           bench_size);
                        if (!bench_async_handle(&ret,
                                                BENCH_ASYNC_GET_DEV(hash[i]),
                                                0, &times, &pending)) {
                            goto exit_md5;
                        }
                    }
                } /* for i */
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;

            times = 0;
            do {
                bench_async_poll(&pending);

                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(hash[i]),
                                          0, &times, numBlocks, &pending)) {
                        ret = wc_Md5Final(hash[i], digest[i]);
                        if (!bench_async_handle(&ret,
                            BENCH_ASYNC_GET_DEV(hash[i]), 0,
                                                &times, &pending)) {
                            goto exit_md5;
                        }
                    }
                } /* for i */
            } while (pending > 0);
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
        || runs < minimum_runs
    #endif
        );
    }
    else {
        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < numBlocks; times++) {
                ret = wc_InitMd5_ex(hash[0], HEAP_HINT, INVALID_DEVID);
                if (ret == 0)
                    ret = wc_Md5Update(hash[0], bench_plain, bench_size);
                if (ret == 0)
                    ret = wc_Md5Final(hash[0], digest[0]);
                if (ret != 0)
                    goto exit_md5;
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
        || runs < minimum_runs
    #endif
        );
    }
exit_md5:
    bench_stats_sym_finish("MD5", useDeviceID, count, bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

exit:

#ifdef WOLFSSL_ASYNC_CRYPT
    if (WC_ARRAY_OK(hash)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            wc_Md5Free(hash[i]);
        }
    }
#endif

    WC_FREE_ARRAY(hash, BENCH_MAX_PENDING, HEAP_HINT);
    WC_FREE_ARRAY(digest, BENCH_MAX_PENDING, HEAP_HINT);
}
#endif /* !NO_MD5 */


#ifndef NO_SHA
void bench_sha(int useDeviceID)
{
    WC_DECLARE_ARRAY(hash, wc_Sha, BENCH_MAX_PENDING,
                     sizeof(wc_Sha), HEAP_HINT);
    double start;
    int    ret = 0, i, count = 0, times, pending = 0;
    DECLARE_MULTI_VALUE_STATS_VARS()
    WC_DECLARE_ARRAY(digest, byte, BENCH_MAX_PENDING,
                     WC_SHA_DIGEST_SIZE, HEAP_HINT);

    WC_CALLOC_ARRAY(hash, wc_Sha, BENCH_MAX_PENDING,
                     sizeof(wc_Sha), HEAP_HINT);
    WC_ALLOC_ARRAY(digest, byte, BENCH_MAX_PENDING,
                  WC_SHA_DIGEST_SIZE, HEAP_HINT);

    if (digest_stream) {
        /* init keys */
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            ret = wc_InitSha_ex(hash[i], HEAP_HINT,
                useDeviceID ? devId : INVALID_DEVID);
            if (ret != 0) {
                printf("InitSha failed, ret = %d\n", ret);
                goto exit;
            }
        #ifdef WOLFSSL_PIC32MZ_HASH
            wc_ShaSizeSet(hash[i], numBlocks * bench_size);
        #endif
        }

        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < numBlocks || pending > 0; ) {
                bench_async_poll(&pending);

                /* while free pending slots in queue, submit ops */
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(hash[i]),
                                          0, &times, numBlocks, &pending)) {
                        ret = wc_ShaUpdate(hash[i], bench_plain,
                            bench_size);
                        if (!bench_async_handle(&ret,
                            BENCH_ASYNC_GET_DEV(hash[i]), 0,
                                                &times, &pending)) {
                            goto exit_sha;
                        }
                    }
                } /* for i */
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;

            times = 0;
            do {
                bench_async_poll(&pending);

                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(hash[i]),
                                          0, &times, numBlocks, &pending)) {
                        ret = wc_ShaFinal(hash[i], digest[i]);
                        if (!bench_async_handle(&ret,
                            BENCH_ASYNC_GET_DEV(hash[i]), 0,
                                                &times, &pending)) {
                            goto exit_sha;
                        }
                    }
                } /* for i */
            } while (pending > 0);
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
        || runs < minimum_runs
    #endif
        );
    }
    else {
        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < numBlocks; times++) {
                ret = wc_InitSha_ex(hash[0], HEAP_HINT,
                    useDeviceID ? devId : INVALID_DEVID);
                if (ret == 0)
                    ret = wc_ShaUpdate(hash[0], bench_plain, bench_size);
                if (ret == 0)
                    ret = wc_ShaFinal(hash[0], digest[0]);
                if (ret != 0)
                    goto exit_sha;
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
        || runs < minimum_runs
    #endif
        );
    }
exit_sha:
    bench_stats_sym_finish("SHA", useDeviceID, count, bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

exit:

    if (WC_ARRAY_OK(hash)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            wc_ShaFree(hash[i]);
        }
        WC_FREE_ARRAY(hash, BENCH_MAX_PENDING, HEAP_HINT);
    }
    WC_FREE_ARRAY(digest, BENCH_MAX_PENDING, HEAP_HINT);
}
#endif /* NO_SHA */


#ifdef WOLFSSL_SHA224
void bench_sha224(int useDeviceID)
{
    WC_DECLARE_ARRAY(hash, wc_Sha224, BENCH_MAX_PENDING,
                     sizeof(wc_Sha224), HEAP_HINT);
    double start;
    int    ret = 0, i, count = 0, times, pending = 0;
    DECLARE_MULTI_VALUE_STATS_VARS()
    WC_DECLARE_ARRAY(digest, byte, BENCH_MAX_PENDING,
                     WC_SHA224_DIGEST_SIZE, HEAP_HINT);

    WC_CALLOC_ARRAY(hash, wc_Sha224, BENCH_MAX_PENDING,
                     sizeof(wc_Sha224), HEAP_HINT);
    WC_ALLOC_ARRAY(digest, byte, BENCH_MAX_PENDING,
                  WC_SHA224_DIGEST_SIZE, HEAP_HINT);

    if (digest_stream) {
        /* init keys */
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            ret = wc_InitSha224_ex(hash[i], HEAP_HINT,
                useDeviceID ? devId : INVALID_DEVID);
            if (ret != 0) {
                printf("InitSha224_ex failed, ret = %d\n", ret);
                goto exit;
            }
        }

        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < numBlocks || pending > 0; ) {
                bench_async_poll(&pending);

                /* while free pending slots in queue, submit ops */
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(hash[i]),
                                          0, &times, numBlocks, &pending)) {
                        ret = wc_Sha224Update(hash[i], bench_plain,
                            bench_size);
                        if (!bench_async_handle(&ret,
                            BENCH_ASYNC_GET_DEV(hash[i]), 0,
                                                &times, &pending)) {
                            goto exit_sha224;
                        }
                    }
                } /* for i */
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;

            times = 0;
            do {
                bench_async_poll(&pending);
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(hash[i]),
                                          0, &times, numBlocks, &pending)) {
                        ret = wc_Sha224Final(hash[i], digest[i]);
                        if (!bench_async_handle(&ret,
                            BENCH_ASYNC_GET_DEV(hash[i]), 0,
                                                &times, &pending)) {
                            goto exit_sha224;
                        }
                    }
                } /* for i */
            } while (pending > 0);
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
        || runs < minimum_runs
    #endif
        );
    }
    else {
        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < numBlocks; times++) {
                ret = wc_InitSha224_ex(hash[0], HEAP_HINT,
                    useDeviceID ? devId : INVALID_DEVID);
                if (ret == 0)
                    ret = wc_Sha224Update(hash[0], bench_plain, bench_size);
                if (ret == 0)
                    ret = wc_Sha224Final(hash[0], digest[0]);
                if (ret != 0)
                    goto exit_sha224;
            } /* for times */
            count += times;
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
        || runs < minimum_runs
    #endif
        );
    }
exit_sha224:
    bench_stats_sym_finish("SHA-224", useDeviceID, count,
                           bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

exit:

    if (WC_ARRAY_OK(hash)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            wc_Sha224Free(hash[i]);
        }
        WC_FREE_ARRAY(hash, BENCH_MAX_PENDING, HEAP_HINT);
    }
    WC_FREE_ARRAY(digest, BENCH_MAX_PENDING, HEAP_HINT);
}
#endif


#ifndef NO_SHA256
void bench_sha256(int useDeviceID)
{
    WC_DECLARE_ARRAY(hash, wc_Sha256, BENCH_MAX_PENDING,
                     sizeof(wc_Sha256), HEAP_HINT);
    double start;
    int    ret = 0, i, count = 0, times, pending = 0;
    DECLARE_MULTI_VALUE_STATS_VARS()
    WC_DECLARE_ARRAY(digest, byte, BENCH_MAX_PENDING,
                     WC_SHA256_DIGEST_SIZE, HEAP_HINT);

    WC_CALLOC_ARRAY(hash, wc_Sha256, BENCH_MAX_PENDING,
                     sizeof(wc_Sha256), HEAP_HINT);
    WC_ALLOC_ARRAY(digest, byte, BENCH_MAX_PENDING,
                  WC_SHA256_DIGEST_SIZE, HEAP_HINT);

    if (digest_stream) {
        /* init keys */
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            ret = wc_InitSha256_ex(hash[i], HEAP_HINT,
                useDeviceID ? devId: INVALID_DEVID);
            if (ret != 0) {
                printf("InitSha256_ex failed, ret = %d\n", ret);
                goto exit;
            }
        #ifdef WOLFSSL_PIC32MZ_HASH
            wc_Sha256SizeSet(hash[i], numBlocks * bench_size);
        #endif
        }

        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < numBlocks || pending > 0; ) {
                bench_async_poll(&pending);

                /* while free pending slots in queue, submit ops */
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(hash[i]),
                                          0, &times, numBlocks, &pending)) {
                        ret = wc_Sha256Update(hash[i], bench_plain,
                            bench_size);
                        if (!bench_async_handle(&ret,
                            BENCH_ASYNC_GET_DEV(hash[i]), 0,
                                                &times, &pending)) {
                            goto exit_sha256;
                        }
                    }
                } /* for i */
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;

            times = 0;
            do {
                bench_async_poll(&pending);
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(hash[i]),
                                          0, &times, numBlocks, &pending)) {
                        ret = wc_Sha256Final(hash[i], digest[i]);
                        if (!bench_async_handle(&ret,
                            BENCH_ASYNC_GET_DEV(hash[i]), 0,
                                                &times, &pending)) {
                            goto exit_sha256;
                        }
                    }
                } /* for i */
            } while (pending > 0);
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
    else {
        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < numBlocks; times++) {
                ret = wc_InitSha256_ex(hash[0], HEAP_HINT,
                    useDeviceID ? devId: INVALID_DEVID);
                if (ret == 0)
                    ret = wc_Sha256Update(hash[0], bench_plain, bench_size);
                if (ret == 0)
                    ret = wc_Sha256Final(hash[0], digest[0]);
                if (ret != 0)
                    goto exit_sha256;
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
exit_sha256:
    bench_stats_sym_finish("SHA-256", useDeviceID, count, bench_size,
                           start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif
exit:
    if (WC_ARRAY_OK(hash)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            wc_Sha256Free(hash[i]);
        }
        WC_FREE_ARRAY(hash, BENCH_MAX_PENDING, HEAP_HINT);
    }
    WC_FREE_ARRAY(digest, BENCH_MAX_PENDING, HEAP_HINT);
}
#endif

#ifdef WOLFSSL_SHA384
void bench_sha384(int useDeviceID)
{
    WC_DECLARE_ARRAY(hash, wc_Sha384, BENCH_MAX_PENDING,
                     sizeof(wc_Sha384), HEAP_HINT);
    double start;
    int    ret = 0, i, count = 0, times, pending = 0;
    DECLARE_MULTI_VALUE_STATS_VARS()
    WC_DECLARE_ARRAY(digest, byte, BENCH_MAX_PENDING,
                     WC_SHA384_DIGEST_SIZE, HEAP_HINT);

    WC_CALLOC_ARRAY(hash, wc_Sha384, BENCH_MAX_PENDING,
                     sizeof(wc_Sha384), HEAP_HINT);
    WC_ALLOC_ARRAY(digest, byte, BENCH_MAX_PENDING,
                  WC_SHA384_DIGEST_SIZE, HEAP_HINT);

    if (digest_stream) {
        /* init keys */
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            ret = wc_InitSha384_ex(hash[i], HEAP_HINT,
                useDeviceID ? devId : INVALID_DEVID);
            if (ret != 0) {
                printf("InitSha384_ex failed, ret = %d\n", ret);
                goto exit;
            }
        }

        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < numBlocks || pending > 0; ) {
                bench_async_poll(&pending);

                /* while free pending slots in queue, submit ops */
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(hash[i]),
                                          0, &times, numBlocks, &pending)) {
                        ret = wc_Sha384Update(hash[i], bench_plain,
                            bench_size);
                        if (!bench_async_handle(&ret,
                            BENCH_ASYNC_GET_DEV(hash[i]), 0,
                                                &times, &pending)) {
                            goto exit_sha384;
                        }
                    }
                } /* for i */
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;

            times = 0;
            do {
                bench_async_poll(&pending);
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(hash[i]),
                                          0, &times, numBlocks, &pending)) {
                        ret = wc_Sha384Final(hash[i], digest[i]);
                        if (!bench_async_handle(&ret,
                            BENCH_ASYNC_GET_DEV(hash[i]), 0,
                                                &times, &pending)) {
                            goto exit_sha384;
                        }
                    }
                } /* for i */
            } while (pending > 0);
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
    else {
        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < numBlocks; times++) {
                ret = wc_InitSha384_ex(hash[0], HEAP_HINT,
                    useDeviceID ? devId : INVALID_DEVID);
                if (ret == 0)
                    ret = wc_Sha384Update(hash[0], bench_plain, bench_size);
                if (ret == 0)
                    ret = wc_Sha384Final(hash[0], digest[0]);
                if (ret != 0)
                    goto exit_sha384;
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
exit_sha384:
    bench_stats_sym_finish("SHA-384", useDeviceID, count, bench_size,
                           start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

exit:

    if (WC_ARRAY_OK(hash)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            wc_Sha384Free(hash[i]);
        }
        WC_FREE_ARRAY(hash, BENCH_MAX_PENDING, HEAP_HINT);
    }
    WC_FREE_ARRAY(digest, BENCH_MAX_PENDING, HEAP_HINT);
}
#endif

#ifdef WOLFSSL_SHA512
void bench_sha512(int useDeviceID)
{
    WC_DECLARE_ARRAY(hash, wc_Sha512, BENCH_MAX_PENDING,
                     sizeof(wc_Sha512), HEAP_HINT);
    double start;
    int    ret = 0, i, count = 0, times, pending = 0;
    DECLARE_MULTI_VALUE_STATS_VARS()
    WC_DECLARE_ARRAY(digest, byte, BENCH_MAX_PENDING,
                     WC_SHA512_DIGEST_SIZE, HEAP_HINT);

    WC_CALLOC_ARRAY(hash, wc_Sha512, BENCH_MAX_PENDING,
                     sizeof(wc_Sha512), HEAP_HINT);
    WC_ALLOC_ARRAY(digest, byte, BENCH_MAX_PENDING,
                  WC_SHA512_DIGEST_SIZE, HEAP_HINT);

    if (digest_stream) {
        /* init keys */
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            ret = wc_InitSha512_ex(hash[i], HEAP_HINT,
                useDeviceID ? devId : INVALID_DEVID);
            if (ret != 0) {
                printf("InitSha512_ex failed, ret = %d\n", ret);
                goto exit;
            }
        }

        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < numBlocks || pending > 0; ) {
                bench_async_poll(&pending);

                /* while free pending slots in queue, submit ops */
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(hash[i]),
                                          0, &times, numBlocks, &pending)) {
                        ret = wc_Sha512Update(hash[i], bench_plain,
                            bench_size);
                        if (!bench_async_handle(&ret,
                            BENCH_ASYNC_GET_DEV(hash[i]), 0,
                                                &times, &pending)) {
                            goto exit_sha512;
                        }
                    }
                } /* for i */
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;

            times = 0;
            do {
                bench_async_poll(&pending);
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(hash[i]),
                                          0, &times, numBlocks, &pending)) {
                        ret = wc_Sha512Final(hash[i], digest[i]);
                        if (!bench_async_handle(&ret,
                            BENCH_ASYNC_GET_DEV(hash[i]), 0,
                                                &times, &pending)) {
                            goto exit_sha512;
                        }
                    }
                } /* for i */
            } while (pending > 0);
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
    else {
        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < numBlocks; times++) {
                ret = wc_InitSha512_ex(hash[0], HEAP_HINT,
                    useDeviceID ? devId : INVALID_DEVID);
                if (ret == 0)
                    ret = wc_Sha512Update(hash[0], bench_plain, bench_size);
                if (ret == 0)
                    ret = wc_Sha512Final(hash[0], digest[0]);
                if (ret != 0)
                    goto exit_sha512;
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
exit_sha512:
    bench_stats_sym_finish("SHA-512", useDeviceID, count, bench_size,
                           start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

exit:

    if (WC_ARRAY_OK(hash)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            wc_Sha512Free(hash[i]);
        }
        WC_FREE_ARRAY(hash, BENCH_MAX_PENDING, HEAP_HINT);
    }
    WC_FREE_ARRAY(digest, BENCH_MAX_PENDING, HEAP_HINT);
}

#if !defined(WOLFSSL_NOSHA512_224) && \
   (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 3)) && !defined(HAVE_SELFTEST)
void bench_sha512_224(int useDeviceID)
{
    WC_DECLARE_ARRAY(hash, wc_Sha512_224, BENCH_MAX_PENDING,
                     sizeof(wc_Sha512_224), HEAP_HINT);
    double start;
    int    ret = 0, i, count = 0, times, pending = 0;
    DECLARE_MULTI_VALUE_STATS_VARS()
    WC_DECLARE_ARRAY(digest, byte, BENCH_MAX_PENDING,
                     WC_SHA512_224_DIGEST_SIZE, HEAP_HINT);

    WC_CALLOC_ARRAY(hash, wc_Sha512_224, BENCH_MAX_PENDING,
                     sizeof(wc_Sha512_224), HEAP_HINT);
    WC_ALLOC_ARRAY(digest, byte, BENCH_MAX_PENDING,
                  WC_SHA512_224_DIGEST_SIZE, HEAP_HINT);

    if (digest_stream) {
        /* init keys */
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            ret = wc_InitSha512_224_ex(hash[i], HEAP_HINT,
                useDeviceID ? devId : INVALID_DEVID);
            if (ret != 0) {
                printf("InitSha512_224_ex failed, ret = %d\n", ret);
                goto exit;
            }
        }

        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < numBlocks || pending > 0; ) {
                bench_async_poll(&pending);

                /* while free pending slots in queue, submit ops */
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(hash[i]),
                                          0, &times, numBlocks, &pending)) {
                        ret = wc_Sha512_224Update(hash[i], bench_plain,
                            bench_size);
                        if (!bench_async_handle(&ret,
                            BENCH_ASYNC_GET_DEV(hash[i]), 0,
                                                &times, &pending)) {
                            goto exit_sha512_224;
                        }
                    }
                } /* for i */
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;

            times = 0;
            do {
                bench_async_poll(&pending);
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(hash[i]),
                                          0, &times, numBlocks, &pending)) {
                        ret = wc_Sha512_224Final(hash[i], digest[i]);
                        if (!bench_async_handle(&ret,
                            BENCH_ASYNC_GET_DEV(hash[i]), 0,
                                                &times, &pending)) {
                            goto exit_sha512_224;
                        }
                    }
                } /* for i */
            } while (pending > 0);
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
    else {
        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < numBlocks; times++) {
                ret = wc_InitSha512_224_ex(hash[0], HEAP_HINT,
                    useDeviceID ? devId : INVALID_DEVID);
                if (ret == 0)
                    ret = wc_Sha512_224Update(hash[0], bench_plain, bench_size);
                if (ret == 0)
                    ret = wc_Sha512_224Final(hash[0], digest[0]);
                if (ret != 0)
                    goto exit_sha512_224;
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
exit_sha512_224:
    bench_stats_sym_finish("SHA-512/224", useDeviceID, count, bench_size,
                           start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

exit:

    if (WC_ARRAY_OK(hash)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            wc_Sha512_224Free(hash[i]);
        }
        WC_FREE_ARRAY(hash, BENCH_MAX_PENDING, HEAP_HINT);
    }
    WC_FREE_ARRAY(digest, BENCH_MAX_PENDING, HEAP_HINT);
}
#endif /* WOLFSSL_NOSHA512_224 && !FIPS ... */

#if !defined(WOLFSSL_NOSHA512_256) && \
   (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 3)) && !defined(HAVE_SELFTEST)
void bench_sha512_256(int useDeviceID)
{
    WC_DECLARE_ARRAY(hash, wc_Sha512_256, BENCH_MAX_PENDING,
                     sizeof(wc_Sha512_256), HEAP_HINT);
    double start;
    int    ret = 0, i, count = 0, times, pending = 0;
    DECLARE_MULTI_VALUE_STATS_VARS()
    WC_DECLARE_ARRAY(digest, byte, BENCH_MAX_PENDING,
                     WC_SHA512_256_DIGEST_SIZE, HEAP_HINT);

    WC_CALLOC_ARRAY(hash, wc_Sha512_256, BENCH_MAX_PENDING,
                     sizeof(wc_Sha512_256), HEAP_HINT);
    WC_ALLOC_ARRAY(digest, byte, BENCH_MAX_PENDING,
                  WC_SHA512_256_DIGEST_SIZE, HEAP_HINT);

    if (digest_stream) {
        /* init keys */
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            ret = wc_InitSha512_256_ex(hash[i], HEAP_HINT,
                useDeviceID ? devId : INVALID_DEVID);
            if (ret != 0) {
                printf("InitSha512_256_ex failed, ret = %d\n", ret);
                goto exit;
            }
        }

        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < numBlocks || pending > 0; ) {
                bench_async_poll(&pending);

                /* while free pending slots in queue, submit ops */
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(hash[i]),
                                          0, &times, numBlocks, &pending)) {
                        ret = wc_Sha512_256Update(hash[i], bench_plain,
                            bench_size);
                        if (!bench_async_handle(&ret,
                            BENCH_ASYNC_GET_DEV(hash[i]), 0,
                                                &times, &pending)) {
                            goto exit_sha512_256;
                        }
                    }
                } /* for i */
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;

            times = 0;
            do {
                bench_async_poll(&pending);
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(hash[i]),
                                          0, &times, numBlocks, &pending)) {
                        ret = wc_Sha512_256Final(hash[i], digest[i]);
                        if (!bench_async_handle(&ret,
                            BENCH_ASYNC_GET_DEV(hash[i]), 0,
                                                &times, &pending)) {
                            goto exit_sha512_256;
                        }
                    }
                } /* for i */
            } while (pending > 0);
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
    else {
        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < numBlocks; times++) {
                ret = wc_InitSha512_256_ex(hash[0], HEAP_HINT,
                    useDeviceID ? devId : INVALID_DEVID);
                if (ret == 0)
                    ret = wc_Sha512_256Update(hash[0], bench_plain, bench_size);
                if (ret == 0)
                    ret = wc_Sha512_256Final(hash[0], digest[0]);
                if (ret != 0)
                    goto exit_sha512_256;
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
exit_sha512_256:
    bench_stats_sym_finish("SHA-512/256", useDeviceID, count, bench_size,
                           start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

exit:

    if (WC_ARRAY_OK(hash)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            wc_Sha512_256Free(hash[i]);
        }
        WC_FREE_ARRAY(hash, BENCH_MAX_PENDING, HEAP_HINT);
    }
    WC_FREE_ARRAY(digest, BENCH_MAX_PENDING, HEAP_HINT);
}
#endif /* WOLFSSL_NOSHA512_256 && !FIPS ... */

#endif /* WOLFSSL_SHA512 */


#ifdef WOLFSSL_SHA3
#ifndef WOLFSSL_NOSHA3_224
void bench_sha3_224(int useDeviceID)
{
    WC_DECLARE_ARRAY(hash, wc_Sha3, BENCH_MAX_PENDING,
                     sizeof(wc_Sha3), HEAP_HINT);
    double start;
    int    ret = 0, i, count = 0, times, pending = 0;
    DECLARE_MULTI_VALUE_STATS_VARS()
    WC_DECLARE_ARRAY(digest, byte, BENCH_MAX_PENDING,
                     WC_SHA3_224_DIGEST_SIZE, HEAP_HINT);

    WC_CALLOC_ARRAY(hash, wc_Sha3, BENCH_MAX_PENDING,
                     sizeof(wc_Sha3), HEAP_HINT);
    WC_ALLOC_ARRAY(digest, byte, BENCH_MAX_PENDING,
                  WC_SHA3_224_DIGEST_SIZE, HEAP_HINT);

    if (digest_stream) {
        /* init keys */
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            ret = wc_InitSha3_224(hash[i], HEAP_HINT,
                useDeviceID ? devId : INVALID_DEVID);
            if (ret != 0) {
                printf("InitSha3_224 failed, ret = %d\n", ret);
                goto exit;
            }
        }

        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < numBlocks || pending > 0; ) {
                bench_async_poll(&pending);

                /* while free pending slots in queue, submit ops */
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(hash[i]),
                                          0, &times, numBlocks, &pending)) {
                        ret = wc_Sha3_224_Update(hash[i], bench_plain,
                            bench_size);
                        if (!bench_async_handle(&ret,
                            BENCH_ASYNC_GET_DEV(hash[i]), 0,
                                                &times, &pending)) {
                            goto exit_sha3_224;
                        }
                    }
                } /* for i */
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;

            times = 0;
            do {
                bench_async_poll(&pending);
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(hash[i]),
                                          0, &times, numBlocks, &pending)) {
                        ret = wc_Sha3_224_Final(hash[i], digest[i]);
                        if (!bench_async_handle(&ret,
                            BENCH_ASYNC_GET_DEV(hash[i]), 0,
                                                &times, &pending)) {
                            goto exit_sha3_224;
                        }
                    }
                } /* for i */
            } while (pending > 0);
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
    else {
        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < numBlocks; times++) {
                ret = wc_InitSha3_224(hash[0], HEAP_HINT,
                    useDeviceID ? devId : INVALID_DEVID);
                if (ret == 0)
                    ret = wc_Sha3_224_Update(hash[0], bench_plain, bench_size);
                if (ret == 0)
                    ret = wc_Sha3_224_Final(hash[0], digest[0]);
                if (ret != 0)
                    goto exit_sha3_224;
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
exit_sha3_224:
    bench_stats_sym_finish("SHA3-224", useDeviceID, count, bench_size,
                           start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

exit:

    if (WC_ARRAY_OK(hash)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            wc_Sha3_224_Free(hash[i]);
        }
        WC_FREE_ARRAY(hash, BENCH_MAX_PENDING, HEAP_HINT);
    }
    WC_FREE_ARRAY(digest, BENCH_MAX_PENDING, HEAP_HINT);
}
#endif /* WOLFSSL_NOSHA3_224 */

#ifndef WOLFSSL_NOSHA3_256
void bench_sha3_256(int useDeviceID)
{
    WC_DECLARE_ARRAY(hash, wc_Sha3, BENCH_MAX_PENDING,
                     sizeof(wc_Sha3), HEAP_HINT);
    double start;
    DECLARE_MULTI_VALUE_STATS_VARS()
    int    ret = 0, i, count = 0, times, pending = 0;
    WC_DECLARE_ARRAY(digest, byte, BENCH_MAX_PENDING,
                     WC_SHA3_256_DIGEST_SIZE, HEAP_HINT);

    WC_CALLOC_ARRAY(hash, wc_Sha3, BENCH_MAX_PENDING,
                     sizeof(wc_Sha3), HEAP_HINT);
    WC_ALLOC_ARRAY(digest, byte, BENCH_MAX_PENDING,
                  WC_SHA3_256_DIGEST_SIZE, HEAP_HINT);

    if (digest_stream) {
        /* init keys */
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            ret = wc_InitSha3_256(hash[i], HEAP_HINT,
                useDeviceID ? devId : INVALID_DEVID);
            if (ret != 0) {
                printf("InitSha3_256 failed, ret = %d\n", ret);
                goto exit;
            }
        }

        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < numBlocks || pending > 0; ) {
                bench_async_poll(&pending);

                /* while free pending slots in queue, submit ops */
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(hash[i]),
                                          0, &times, numBlocks, &pending)) {
                        ret = wc_Sha3_256_Update(hash[i], bench_plain,
                            bench_size);
                        if (!bench_async_handle(&ret,
                            BENCH_ASYNC_GET_DEV(hash[i]), 0,
                                                &times, &pending)) {
                            goto exit_sha3_256;
                        }
                    }
                } /* for i */
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;

            times = 0;
            do {
                bench_async_poll(&pending);
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(hash[i]),
                                          0, &times, numBlocks, &pending)) {
                        ret = wc_Sha3_256_Final(hash[i], digest[i]);
                        if (!bench_async_handle(&ret,
                            BENCH_ASYNC_GET_DEV(hash[i]), 0,
                                                &times, &pending)) {
                            goto exit_sha3_256;
                        }
                    }
                } /* for i */
            } while (pending > 0);
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
    else {
        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < numBlocks; times++) {
                ret = wc_InitSha3_256(hash[0], HEAP_HINT,
                    useDeviceID ? devId : INVALID_DEVID);
                if (ret == 0)
                    ret = wc_Sha3_256_Update(hash[0], bench_plain, bench_size);
                if (ret == 0)
                    ret = wc_Sha3_256_Final(hash[0], digest[0]);
                if (ret != 0)
                    goto exit_sha3_256;
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
exit_sha3_256:
    bench_stats_sym_finish("SHA3-256", useDeviceID, count, bench_size,
                           start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

exit:

    if (WC_ARRAY_OK(hash)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            wc_Sha3_256_Free(hash[i]);
        }
        WC_FREE_ARRAY(hash, BENCH_MAX_PENDING, HEAP_HINT);
    }
    WC_FREE_ARRAY(digest, BENCH_MAX_PENDING, HEAP_HINT);
}
#endif /* WOLFSSL_NOSHA3_256 */

#ifndef WOLFSSL_NOSHA3_384
void bench_sha3_384(int useDeviceID)
{
    WC_DECLARE_ARRAY(hash, wc_Sha3, BENCH_MAX_PENDING,
                     sizeof(wc_Sha3), HEAP_HINT);
    double start;
    int    ret = 0, i, count = 0, times, pending = 0;
    DECLARE_MULTI_VALUE_STATS_VARS()
    WC_DECLARE_ARRAY(digest, byte, BENCH_MAX_PENDING,
                     WC_SHA3_384_DIGEST_SIZE, HEAP_HINT);

    WC_CALLOC_ARRAY(hash, wc_Sha3, BENCH_MAX_PENDING,
                     sizeof(wc_Sha3), HEAP_HINT);
    WC_ALLOC_ARRAY(digest, byte, BENCH_MAX_PENDING,
                  WC_SHA3_384_DIGEST_SIZE, HEAP_HINT);

    if (digest_stream) {
        /* init keys */
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            ret = wc_InitSha3_384(hash[i], HEAP_HINT,
                useDeviceID ? devId : INVALID_DEVID);
            if (ret != 0) {
                printf("InitSha3_384 failed, ret = %d\n", ret);
                goto exit;
            }
        }

        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < numBlocks || pending > 0; ) {
                bench_async_poll(&pending);

                /* while free pending slots in queue, submit ops */
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(hash[i]),
                                          0, &times, numBlocks, &pending)) {
                        ret = wc_Sha3_384_Update(hash[i], bench_plain,
                            bench_size);
                        if (!bench_async_handle(&ret,
                            BENCH_ASYNC_GET_DEV(hash[i]), 0,
                                                &times, &pending)) {
                            goto exit_sha3_384;
                        }
                    }
                } /* for i */
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;

            times = 0;
            do {
                bench_async_poll(&pending);
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(hash[i]),
                                          0, &times, numBlocks, &pending)) {
                        ret = wc_Sha3_384_Final(hash[i], digest[i]);
                        if (!bench_async_handle(&ret,
                            BENCH_ASYNC_GET_DEV(hash[i]), 0,
                                                &times, &pending)) {
                            goto exit_sha3_384;
                        }
                    }
                } /* for i */
            } while (pending > 0);
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
    else {
        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < numBlocks; times++) {
                ret = wc_InitSha3_384(hash[0], HEAP_HINT,
                    useDeviceID ? devId : INVALID_DEVID);
                if (ret == 0)
                    ret = wc_Sha3_384_Update(hash[0], bench_plain, bench_size);
                if (ret == 0)
                    ret = wc_Sha3_384_Final(hash[0], digest[0]);
                if (ret != 0)
                    goto exit_sha3_384;
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
exit_sha3_384:
    bench_stats_sym_finish("SHA3-384", useDeviceID, count, bench_size,
                           start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

exit:

    if (WC_ARRAY_OK(hash)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            wc_Sha3_384_Free(hash[i]);
        }
        WC_FREE_ARRAY(hash, BENCH_MAX_PENDING, HEAP_HINT);
    }
    WC_FREE_ARRAY(digest, BENCH_MAX_PENDING, HEAP_HINT);
}
#endif /* WOLFSSL_NOSHA3_384 */

#ifndef WOLFSSL_NOSHA3_512
void bench_sha3_512(int useDeviceID)
{
    WC_DECLARE_ARRAY(hash, wc_Sha3, BENCH_MAX_PENDING,
                     sizeof(wc_Sha3), HEAP_HINT);
    double start;
    int    ret = 0, i, count = 0, times, pending = 0;
    DECLARE_MULTI_VALUE_STATS_VARS()
    WC_DECLARE_ARRAY(digest, byte, BENCH_MAX_PENDING,
                     WC_SHA3_512_DIGEST_SIZE, HEAP_HINT);

    WC_CALLOC_ARRAY(hash, wc_Sha3, BENCH_MAX_PENDING,
                     sizeof(wc_Sha3), HEAP_HINT);
    WC_ALLOC_ARRAY(digest, byte, BENCH_MAX_PENDING,
                  WC_SHA3_512_DIGEST_SIZE, HEAP_HINT);

    if (digest_stream) {
        /* init keys */
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            ret = wc_InitSha3_512(hash[i], HEAP_HINT,
                useDeviceID ? devId : INVALID_DEVID);
            if (ret != 0) {
                printf("InitSha3_512 failed, ret = %d\n", ret);
                goto exit;
            }
        }

        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < numBlocks || pending > 0; ) {
                bench_async_poll(&pending);

                /* while free pending slots in queue, submit ops */
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(hash[i]),
                                          0, &times, numBlocks, &pending)) {
                        ret = wc_Sha3_512_Update(hash[i], bench_plain,
                            bench_size);
                        if (!bench_async_handle(&ret,
                            BENCH_ASYNC_GET_DEV(hash[i]), 0,
                                                &times, &pending)) {
                            goto exit_sha3_512;
                        }
                    }
                } /* for i */
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;

            times = 0;
            do {
                bench_async_poll(&pending);
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(hash[i]),
                                          0, &times, numBlocks, &pending)) {
                        ret = wc_Sha3_512_Final(hash[i], digest[i]);
                        if (!bench_async_handle(&ret,
                            BENCH_ASYNC_GET_DEV(hash[i]), 0,
                                                &times, &pending)) {
                            goto exit_sha3_512;
                        }
                    }
                } /* for i */
            } while (pending > 0);
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
    else {
        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < numBlocks; times++) {
                ret = wc_InitSha3_512(hash[0], HEAP_HINT,
                    useDeviceID ? devId : INVALID_DEVID);
                if (ret == 0)
                    ret = wc_Sha3_512_Update(hash[0], bench_plain, bench_size);
                if (ret == 0)
                    ret = wc_Sha3_512_Final(hash[0], digest[0]);
                if (ret != 0)
                    goto exit_sha3_512;
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
exit_sha3_512:
    bench_stats_sym_finish("SHA3-512", useDeviceID, count, bench_size,
                           start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

exit:

    if (WC_ARRAY_OK(hash)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            wc_Sha3_512_Free(hash[i]);
        }
        WC_FREE_ARRAY(hash, BENCH_MAX_PENDING, HEAP_HINT);
    }
    WC_FREE_ARRAY(digest, BENCH_MAX_PENDING, HEAP_HINT);
}
#endif /* WOLFSSL_NOSHA3_512 */

#ifdef WOLFSSL_SHAKE128
void bench_shake128(int useDeviceID)
{
    WC_DECLARE_ARRAY(hash, wc_Shake, BENCH_MAX_PENDING,
                     sizeof(wc_Shake), HEAP_HINT);
    double start;
    int    ret = 0, i, count = 0, times, pending = 0;
    DECLARE_MULTI_VALUE_STATS_VARS()
    WC_DECLARE_ARRAY(digest, byte, BENCH_MAX_PENDING,
                     WC_SHA3_128_BLOCK_SIZE, HEAP_HINT);

    WC_CALLOC_ARRAY(hash, wc_Shake, BENCH_MAX_PENDING,
                     sizeof(wc_Shake), HEAP_HINT);
    WC_ALLOC_ARRAY(digest, byte, BENCH_MAX_PENDING,
                  WC_SHA3_128_BLOCK_SIZE, HEAP_HINT);

    if (digest_stream) {
        /* init keys */
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            ret = wc_InitShake128(hash[i], HEAP_HINT,
                useDeviceID ? devId : INVALID_DEVID);
            if (ret != 0) {
                printf("InitShake128 failed, ret = %d\n", ret);
                goto exit;
            }
        }

        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < numBlocks || pending > 0; ) {
                bench_async_poll(&pending);

                /* while free pending slots in queue, submit ops */
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(hash[i]),
                                          0, &times, numBlocks, &pending)) {
                        ret = wc_Shake128_Update(hash[i], bench_plain,
                            bench_size);
                        if (!bench_async_handle(&ret,
                            BENCH_ASYNC_GET_DEV(hash[i]), 0,
                                                &times, &pending)) {
                            goto exit_shake128;
                        }
                    }
                } /* for i */
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;

            times = 0;
            do {
                bench_async_poll(&pending);
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(hash[i]),
                                          0, &times, numBlocks, &pending)) {
                        ret = wc_Shake128_Final(hash[i], digest[i],
                            WC_SHA3_128_BLOCK_SIZE);
                        if (!bench_async_handle(&ret,
                            BENCH_ASYNC_GET_DEV(hash[i]), 0,
                                                &times, &pending)) {
                            goto exit_shake128;
                        }
                    }
                } /* for i */
            } while (pending > 0);
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
    else {
        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < numBlocks; times++) {
                ret = wc_InitShake128(hash[0], HEAP_HINT,
                    useDeviceID ? devId : INVALID_DEVID);
                if (ret == 0)
                    ret = wc_Shake128_Update(hash[0], bench_plain, bench_size);
                if (ret == 0)
                    ret = wc_Shake128_Final(hash[0], digest[0],
                        WC_SHA3_128_BLOCK_SIZE);
                if (ret != 0)
                    goto exit_shake128;
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
exit_shake128:
    bench_stats_sym_finish("SHAKE128", useDeviceID, count, bench_size,
                           start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

exit:

    if (WC_ARRAY_OK(hash)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            wc_Shake128_Free(hash[i]);
        }
        WC_FREE_ARRAY(hash, BENCH_MAX_PENDING, HEAP_HINT);
    }
    WC_FREE_ARRAY(digest, BENCH_MAX_PENDING, HEAP_HINT);
}
#endif /* WOLFSSL_SHAKE128 */

#ifdef WOLFSSL_SHAKE256
void bench_shake256(int useDeviceID)
{
    WC_DECLARE_ARRAY(hash, wc_Shake, BENCH_MAX_PENDING,
                     sizeof(wc_Shake), HEAP_HINT);
    double start;
    int    ret = 0, i, count = 0, times, pending = 0;
    DECLARE_MULTI_VALUE_STATS_VARS()
    WC_DECLARE_ARRAY(digest, byte, BENCH_MAX_PENDING,
                     WC_SHA3_256_BLOCK_SIZE, HEAP_HINT);

    WC_CALLOC_ARRAY(hash, wc_Shake, BENCH_MAX_PENDING,
                     sizeof(wc_Shake), HEAP_HINT);
    WC_ALLOC_ARRAY(digest, byte, BENCH_MAX_PENDING,
                  WC_SHA3_256_BLOCK_SIZE, HEAP_HINT);

    if (digest_stream) {
        /* init keys */
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            ret = wc_InitShake256(hash[i], HEAP_HINT,
                useDeviceID ? devId : INVALID_DEVID);
            if (ret != 0) {
                printf("InitShake256 failed, ret = %d\n", ret);
                goto exit;
            }
        }

        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < numBlocks || pending > 0; ) {
                bench_async_poll(&pending);

                /* while free pending slots in queue, submit ops */
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(hash[i]),
                                          0, &times, numBlocks, &pending)) {
                        ret = wc_Shake256_Update(hash[i], bench_plain,
                            bench_size);
                        if (!bench_async_handle(&ret,
                            BENCH_ASYNC_GET_DEV(hash[i]), 0,
                                                &times, &pending)) {
                            goto exit_shake256;
                        }
                    }
                } /* for i */
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;

            times = 0;
            do {
                bench_async_poll(&pending);
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(hash[i]),
                                          0, &times, numBlocks, &pending)) {
                        ret = wc_Shake256_Final(hash[i], digest[i],
                            WC_SHA3_256_BLOCK_SIZE);
                        if (!bench_async_handle(&ret,
                            BENCH_ASYNC_GET_DEV(hash[i]), 0,
                                                &times, &pending)) {
                            goto exit_shake256;
                        }
                    }
                } /* for i */
            } while (pending > 0);
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
    else {
        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < numBlocks; times++) {
                ret = wc_InitShake256(hash[0], HEAP_HINT,
                    useDeviceID ? devId : INVALID_DEVID);
                if (ret == 0)
                    ret = wc_Shake256_Update(hash[0], bench_plain, bench_size);
                if (ret == 0)
                    ret = wc_Shake256_Final(hash[0], digest[0],
                        WC_SHA3_256_BLOCK_SIZE);
                if (ret != 0)
                    goto exit_shake256;
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
exit_shake256:
    bench_stats_sym_finish("SHAKE256", useDeviceID, count, bench_size,
                           start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

exit:

    if (WC_ARRAY_OK(hash)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            wc_Shake256_Free(hash[i]);
        }
        WC_FREE_ARRAY(hash, BENCH_MAX_PENDING, HEAP_HINT);
    }
    WC_FREE_ARRAY(digest, BENCH_MAX_PENDING, HEAP_HINT);
}
#endif /* WOLFSSL_SHAKE256 */
#endif

#ifdef WOLFSSL_SM3
void bench_sm3(int useDeviceID)
{
    WC_DECLARE_ARRAY(hash, wc_Sm3, BENCH_MAX_PENDING,
                     sizeof(wc_Sm3), HEAP_HINT);
    double start;
    int    ret = 0, i, count = 0, times, pending = 0;
    DECLARE_MULTI_VALUE_STATS_VARS()
    WC_DECLARE_ARRAY(digest, byte, BENCH_MAX_PENDING, WC_SM3_DIGEST_SIZE,
        HEAP_HINT);

    WC_CALLOC_ARRAY(hash, wc_Sm3, BENCH_MAX_PENDING,
                     sizeof(wc_Sm3), HEAP_HINT);
    WC_ALLOC_ARRAY(digest, byte, BENCH_MAX_PENDING, WC_SM3_DIGEST_SIZE,
        HEAP_HINT);

    if (digest_stream) {
        /* init keys */
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            ret = wc_InitSm3(hash[i], HEAP_HINT,
                useDeviceID ? devId: INVALID_DEVID);
            if (ret != 0) {
                printf("InitSm3 failed, ret = %d\n", ret);
                goto exit;
            }
        }

        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < numBlocks || pending > 0; ) {
                bench_async_poll(&pending);

                /* while free pending slots in queue, submit ops */
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(hash[i]),
                                              0, &times, numBlocks, &pending)) {
                        ret = wc_Sm3Update(hash[i], bench_plain,
                            bench_size);
                        if (!bench_async_handle(&ret,
                            BENCH_ASYNC_GET_DEV(hash[i]), 0, &times, &pending)) {
                            goto exit_sm3;
                        }
                    }
                } /* for i */
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;

            times = 0;
            do {
                bench_async_poll(&pending);
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(hash[i]),
                                              0, &times, numBlocks, &pending)) {
                        ret = wc_Sm3Final(hash[i], digest[i]);
                        if (!bench_async_handle(&ret,
                            BENCH_ASYNC_GET_DEV(hash[i]), 0, &times, &pending)) {
                            goto exit_sm3;
                        }
                    }
                } /* for i */
            } while (pending > 0);
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
    else {
        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < numBlocks; times++) {
                ret = wc_InitSm3(hash[0], HEAP_HINT,
                    useDeviceID ? devId: INVALID_DEVID);
                if (ret == 0)
                    ret = wc_Sm3Update(hash[0], bench_plain, bench_size);
                if (ret == 0)
                    ret = wc_Sm3Final(hash[0], digest[0]);
                if (ret != 0)
                    goto exit_sm3;
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
exit_sm3:
    bench_stats_sym_finish("SM3", useDeviceID, count, bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

exit:

    if (WC_ARRAY_OK(hash)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            wc_Sm3Free(hash[i]);
        }
        WC_FREE_ARRAY(hash, BENCH_MAX_PENDING, HEAP_HINT);
    }
    WC_FREE_ARRAY(digest, BENCH_MAX_PENDING, HEAP_HINT);
}
#endif


#ifdef WOLFSSL_RIPEMD
void bench_ripemd(void)
{
    RipeMd hash;
    byte   digest[RIPEMD_DIGEST_SIZE];
    double start;
    int    i, count, ret = 0;
    DECLARE_MULTI_VALUE_STATS_VARS()

    if (digest_stream) {
        ret = wc_InitRipeMd(&hash);
        if (ret != 0) {
            printf("wc_InitRipeMd failed, retval %d\n", ret);
            return;
        }

        bench_stats_start(&count, &start);
        do {
            for (i = 0; i < numBlocks; i++) {
                ret = wc_RipeMdUpdate(&hash, bench_plain, bench_size);
                if (ret != 0) {
                    printf("wc_RipeMdUpdate failed, retval %d\n", ret);
                    return;
                }
                RECORD_MULTI_VALUE_STATS();
            }
            ret = wc_RipeMdFinal(&hash, digest);
            if (ret != 0) {
                printf("wc_RipeMdFinal failed, retval %d\n", ret);
                return;
            }

            count += i;
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
    else {
        bench_stats_start(&count, &start);
        do {
            for (i = 0; i < numBlocks; i++) {
                ret = wc_InitRipeMd(&hash);
                if (ret != 0) {
                    printf("wc_InitRipeMd failed, retval %d\n", ret);
                    return;
                }
                ret = wc_RipeMdUpdate(&hash, bench_plain, bench_size);
                if (ret != 0) {
                    printf("wc_RipeMdUpdate failed, retval %d\n", ret);
                    return;
                }
                ret = wc_RipeMdFinal(&hash, digest);
                if (ret != 0) {
                    printf("wc_RipeMdFinal failed, retval %d\n", ret);
                    return;
                }
                RECORD_MULTI_VALUE_STATS();
            }
            count += i;
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
    bench_stats_sym_finish("RIPEMD", 0, count, bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    return;
}
#endif


#ifdef HAVE_BLAKE2
void bench_blake2b(void)
{
    Blake2b b2b;
    byte    digest[64];
    double  start;
    int     ret = 0, i, count;
    DECLARE_MULTI_VALUE_STATS_VARS()

    if (digest_stream) {
        ret = wc_InitBlake2b(&b2b, 64);
        if (ret != 0) {
            printf("InitBlake2b failed, ret = %d\n", ret);
            return;
        }

        bench_stats_start(&count, &start);
        do {
            for (i = 0; i < numBlocks; i++) {
                ret = wc_Blake2bUpdate(&b2b, bench_plain, bench_size);
                if (ret != 0) {
                    printf("Blake2bUpdate failed, ret = %d\n", ret);
                    return;
                }
                RECORD_MULTI_VALUE_STATS();
            }
            ret = wc_Blake2bFinal(&b2b, digest, 64);
            if (ret != 0) {
                printf("Blake2bFinal failed, ret = %d\n", ret);
                return;
            }
            count += i;
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
    else {
        bench_stats_start(&count, &start);
        do {
            for (i = 0; i < numBlocks; i++) {
                ret = wc_InitBlake2b(&b2b, 64);
                if (ret != 0) {
                    printf("InitBlake2b failed, ret = %d\n", ret);
                    return;
                }
                ret = wc_Blake2bUpdate(&b2b, bench_plain, bench_size);
                if (ret != 0) {
                    printf("Blake2bUpdate failed, ret = %d\n", ret);
                    return;
                }
                ret = wc_Blake2bFinal(&b2b, digest, 64);
                if (ret != 0) {
                    printf("Blake2bFinal failed, ret = %d\n", ret);
                    return;
                }
                RECORD_MULTI_VALUE_STATS();
            }
            count += i;
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
    bench_stats_sym_finish("BLAKE2b", 0, count, bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif
}
#endif

#if defined(HAVE_BLAKE2S)
void bench_blake2s(void)
{
    Blake2s b2s;
    byte    digest[32];
    double  start;
    int     ret = 0, i, count;
    DECLARE_MULTI_VALUE_STATS_VARS()

    if (digest_stream) {
        ret = wc_InitBlake2s(&b2s, 32);
        if (ret != 0) {
            printf("InitBlake2s failed, ret = %d\n", ret);
            return;
        }

        bench_stats_start(&count, &start);
        do {
            for (i = 0; i < numBlocks; i++) {
                ret = wc_Blake2sUpdate(&b2s, bench_plain, bench_size);
                if (ret != 0) {
                    printf("Blake2sUpdate failed, ret = %d\n", ret);
                    return;
                }
                RECORD_MULTI_VALUE_STATS();
            }
            ret = wc_Blake2sFinal(&b2s, digest, 32);
            if (ret != 0) {
                printf("Blake2sFinal failed, ret = %d\n", ret);
                return;
            }
            count += i;
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
    else {
        bench_stats_start(&count, &start);
        do {
            for (i = 0; i < numBlocks; i++) {
                ret = wc_InitBlake2s(&b2s, 32);
                if (ret != 0) {
                    printf("InitBlake2b failed, ret = %d\n", ret);
                    return;
                }
                ret = wc_Blake2sUpdate(&b2s, bench_plain, bench_size);
                if (ret != 0) {
                    printf("Blake2bUpdate failed, ret = %d\n", ret);
                    return;
                }
                ret = wc_Blake2sFinal(&b2s, digest, 32);
                if (ret != 0) {
                    printf("Blake2sFinal failed, ret = %d\n", ret);
                    return;
                }
                RECORD_MULTI_VALUE_STATS();
            }
            count += i;
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );
    }
    bench_stats_sym_finish("BLAKE2s", 0, count, bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif
}
#endif


#ifdef WOLFSSL_CMAC

static void bench_cmac_helper(word32 keySz, const char* outMsg, int useDeviceID)
{
    Cmac    cmac;
    byte    digest[WC_AES_BLOCK_SIZE];
    word32  digestSz = sizeof(digest);
    double  start;
    int     ret, i, count;
    DECLARE_MULTI_VALUE_STATS_VARS()
#ifdef WOLFSSL_SECO_CAAM
    unsigned int keyID;
    int keyGroup = 1; /* group one was chosen arbitrarily */
    int keyInfo = CAAM_KEY_TRANSIENT;
    int keyType = CAAM_KEYTYPE_AES128;
    byte pubKey[AES_256_KEY_SIZE];

    if (keySz == AES_256_KEY_SIZE) {
        keyType = CAAM_KEYTYPE_AES256;
    }

    if (useDeviceID &&
            wc_SECO_GenerateKey(CAAM_GENERATE_KEY, keyGroup, pubKey, 0, keyType,
            keyInfo, &keyID) != 0) {
        printf("Error generating key in hsm\n");
        return;
    }
#endif
    (void)useDeviceID;

    bench_stats_start(&count, &start);
    do {
    #ifdef HAVE_FIPS
        ret = wc_InitCmac(&cmac, bench_key, keySz, WC_CMAC_AES, NULL);
    #else
        ret = wc_InitCmac_ex(&cmac, bench_key, keySz, WC_CMAC_AES, NULL,
            HEAP_HINT, useDeviceID ? devId : INVALID_DEVID);
    #endif
        if (ret != 0) {
            printf("InitCmac failed, ret = %d\n", ret);
            return;
        }
    #ifdef WOLFSSL_SECO_CAAM
        if (useDeviceID) {
            wc_SECO_CMACSetKeyID(&cmac, keyID);
        }
    #endif

        for (i = 0; i < numBlocks; i++) {
            ret = wc_CmacUpdate(&cmac, bench_plain, bench_size);
            if (ret != 0) {
                printf("CmacUpdate failed, ret = %d\n", ret);
                return;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        /* Note: final force zero's the Cmac struct */
        ret = wc_CmacFinal(&cmac, digest, &digestSz);
        if (ret != 0) {
            printf("CmacFinal failed, ret = %d\n", ret);
            return;
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_sym_finish(outMsg, useDeviceID, count, bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif
}

void bench_cmac(int useDeviceID)
{
#ifdef WOLFSSL_AES_128
    bench_cmac_helper(16, "AES-128-CMAC", useDeviceID);
#endif
#ifdef WOLFSSL_AES_256
    bench_cmac_helper(32, "AES-256-CMAC", useDeviceID);
#endif

}
#endif /* WOLFSSL_CMAC */

#ifdef HAVE_SCRYPT

void bench_scrypt(void)
{
    byte   derived[64];
    double start;
    int    ret, i, count;
    DECLARE_MULTI_VALUE_STATS_VARS()

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < scryptCnt; i++) {
            ret = wc_scrypt(derived, (byte*)"pleaseletmein", 13,
                            (byte*)"SodiumChloride", 14, 14, 8, 1,
                            sizeof(derived));
            if (ret != 0) {
                printf("scrypt failed, ret = %d\n", ret);
                goto exit;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

exit:
    bench_stats_asym_finish("scrypt", 17, "", 0, count, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif
}

#endif /* HAVE_SCRYPT */

#ifndef NO_HMAC

static void bench_hmac(int useDeviceID, int type, int digestSz,
                       const byte* key, word32 keySz, const char* label)
{
    WC_DECLARE_ARRAY(hmac, Hmac, BENCH_MAX_PENDING,
                     sizeof(Hmac), HEAP_HINT);
    double start;
    int    ret = 0, i, count = 0, times, pending = 0;
    DECLARE_MULTI_VALUE_STATS_VARS()
#ifdef WOLFSSL_ASYNC_CRYPT
    WC_DECLARE_ARRAY(digest, byte, BENCH_MAX_PENDING,
                     WC_MAX_DIGEST_SIZE, HEAP_HINT);
    WC_ALLOC_ARRAY(digest, byte, BENCH_MAX_PENDING,
                  WC_MAX_DIGEST_SIZE, HEAP_HINT);
#else
    byte digest[BENCH_MAX_PENDING][WC_MAX_DIGEST_SIZE];
#endif

    (void)digestSz;

    WC_CALLOC_ARRAY(hmac, Hmac, BENCH_MAX_PENDING,
                     sizeof(Hmac), HEAP_HINT);

    /* init keys */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        ret = wc_HmacInit(hmac[i], HEAP_HINT,
                useDeviceID ? devId : INVALID_DEVID);
        if (ret != 0) {
            printf("wc_HmacInit failed for %s, ret = %d\n", label, ret);
            goto exit;
        }

        ret = wc_HmacSetKey(hmac[i], type, key, keySz);
        if (ret != 0) {
            printf("wc_HmacSetKey failed for %s, ret = %d\n", label, ret);
            goto exit;
        }
    }

    bench_stats_start(&count, &start);
    do {
        for (times = 0; times < numBlocks || pending > 0; ) {
            bench_async_poll(&pending);

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret,
                                      BENCH_ASYNC_GET_DEV(hmac[i]), 0,
                                      &times, numBlocks, &pending)) {
                    ret = wc_HmacUpdate(hmac[i], bench_plain, bench_size);
                    if (!bench_async_handle(&ret,
                                            BENCH_ASYNC_GET_DEV(hmac[i]),
                                            0, &times, &pending)) {
                        goto exit_hmac;
                    }
                }
            } /* for i */
        } /* for times */
        count += times;

        times = 0;
        do {
            bench_async_poll(&pending);

            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret,
                                      BENCH_ASYNC_GET_DEV(hmac[i]), 0,
                                      &times, numBlocks, &pending)) {
                    ret = wc_HmacFinal(hmac[i], digest[i]);
                    if (!bench_async_handle(&ret,
                                            BENCH_ASYNC_GET_DEV(hmac[i]),
                                            0, &times, &pending)) {
                        goto exit_hmac;
                    }
                }
                RECORD_MULTI_VALUE_STATS();
            } /* for i */
        } while (pending > 0);
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

exit_hmac:
    bench_stats_sym_finish(label, useDeviceID, count, bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

exit:

    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        wc_HmacFree(hmac[i]);
    }

    WC_FREE_ARRAY(hmac, BENCH_MAX_PENDING, HEAP_HINT);
#ifdef WOLFSSL_ASYNC_CRYPT
    WC_FREE_ARRAY(digest, BENCH_MAX_PENDING, HEAP_HINT);
#endif
}

#ifndef NO_MD5

void bench_hmac_md5(int useDeviceID)
{
    WOLFSSL_SMALL_STACK_STATIC const byte key[] = {
                   0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                   0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };

    bench_hmac(useDeviceID, WC_MD5, WC_MD5_DIGEST_SIZE, key, sizeof(key),
               "HMAC-MD5");
}

#endif /* NO_MD5 */

#ifndef NO_SHA

void bench_hmac_sha(int useDeviceID)
{
    WOLFSSL_SMALL_STACK_STATIC const byte key[] = {
                   0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                   0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                   0x0b, 0x0b, 0x0b, 0x0b };

    bench_hmac(useDeviceID, WC_SHA, WC_SHA_DIGEST_SIZE, key, sizeof(key),
               "HMAC-SHA");
}

#endif /* NO_SHA */

#ifdef WOLFSSL_SHA224

void bench_hmac_sha224(int useDeviceID)
{
    WOLFSSL_SMALL_STACK_STATIC const byte key[] = {
                   0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                   0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                   0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                   0x0b, 0x0b, 0x0b, 0x0b };

    bench_hmac(useDeviceID, WC_SHA224,
               WC_SHA224_DIGEST_SIZE, key, sizeof(key),
               "HMAC-SHA224");
}

#endif /* WOLFSSL_SHA224 */

#ifndef NO_SHA256

void bench_hmac_sha256(int useDeviceID)
{
    WOLFSSL_SMALL_STACK_STATIC const byte key[] = {
                   0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                   0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                   0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                   0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };

    bench_hmac(useDeviceID, WC_SHA256, WC_SHA256_DIGEST_SIZE, key, sizeof(key),
               "HMAC-SHA256");
}

#endif /* NO_SHA256 */

#ifdef WOLFSSL_SHA384

void bench_hmac_sha384(int useDeviceID)
{
    WOLFSSL_SMALL_STACK_STATIC const byte key[] = {
                   0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                   0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                   0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                   0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                   0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                   0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };

    bench_hmac(useDeviceID, WC_SHA384, WC_SHA384_DIGEST_SIZE, key, sizeof(key),
               "HMAC-SHA384");
}

#endif /* WOLFSSL_SHA384 */

#ifdef WOLFSSL_SHA512

void bench_hmac_sha512(int useDeviceID)
{
    WOLFSSL_SMALL_STACK_STATIC const byte key[] = {
                   0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                   0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                   0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                   0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                   0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                   0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                   0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                   0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };

    bench_hmac(useDeviceID, WC_SHA512, WC_SHA512_DIGEST_SIZE, key, sizeof(key),
               "HMAC-SHA512");
}

#endif /* WOLFSSL_SHA512 */

#ifndef NO_PWDBASED
void bench_pbkdf2(void)
{
    double start;
    int    ret = 0, count = 0;
    const char* passwd32 = "passwordpasswordpasswordpassword";
    WOLFSSL_SMALL_STACK_STATIC const byte salt32[] = {
                            0x78, 0x57, 0x8E, 0x5a, 0x5d, 0x63, 0xcb, 0x06,
                            0x78, 0x57, 0x8E, 0x5a, 0x5d, 0x63, 0xcb, 0x06,
                            0x78, 0x57, 0x8E, 0x5a, 0x5d, 0x63, 0xcb, 0x06,
                            0x78, 0x57, 0x8E, 0x5a, 0x5d, 0x63, 0xcb, 0x06 };
    byte derived[32];
    DECLARE_MULTI_VALUE_STATS_VARS()

    bench_stats_start(&count, &start);
    PRIVATE_KEY_UNLOCK();
    do {
        ret = wc_PBKDF2(derived, (const byte*)passwd32, (int)XSTRLEN(passwd32),
            salt32, (int)sizeof(salt32), 1000, 32, WC_SHA256);
        count++;
        RECORD_MULTI_VALUE_STATS();
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );
    PRIVATE_KEY_LOCK();

    bench_stats_sym_finish("PBKDF2", 32, count, 32, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif
}
#endif /* !NO_PWDBASED */

#endif /* NO_HMAC */

#ifdef WOLFSSL_SIPHASH
void bench_siphash(void)
{
    double start;
    int    ret = 0, count;
    const char* passwd16 = "passwordpassword";
    byte out[16];
    int    i;
    DECLARE_MULTI_VALUE_STATS_VARS()

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            ret = wc_SipHash((const byte*)passwd16, bench_plain, bench_size,
                out, 8);
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_sym_finish("SipHash-8", 1, count, bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    RESET_MULTI_VALUE_STATS_VARS();

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            ret = wc_SipHash((const byte*)passwd16, bench_plain, bench_size,
                out, 16);
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_sym_finish("SipHash-16", 1, count, bench_size, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif
}
#endif

#ifdef WC_SRTP_KDF
void bench_srtpkdf(void)
{
    double start;
    int count;
    int ret = 0;
    byte keyE[32];
    byte keyA[20];
    byte keyS[14];
    const byte *key = bench_key_buf;
    const byte salt[14] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                           0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e };
    const byte index[6] = { 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA };
    int kdrIdx = 0;
    int i;
    DECLARE_MULTI_VALUE_STATS_VARS()

    bench_stats_start(&count, &start);
    PRIVATE_KEY_UNLOCK();
    do {
        for (i = 0; i < numBlocks; i++) {
            ret = wc_SRTP_KDF(key, AES_128_KEY_SIZE, salt, sizeof(salt),
                kdrIdx, index, keyE, AES_128_KEY_SIZE, keyA, sizeof(keyA),
                keyS, sizeof(keyS));
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );
    PRIVATE_KEY_LOCK();
    bench_stats_asym_finish("KDF", 128, "SRTP", 0, count, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    RESET_MULTI_VALUE_STATS_VARS();

    bench_stats_start(&count, &start);
    PRIVATE_KEY_UNLOCK();
    do {
        for (i = 0; i < numBlocks; i++) {
            ret = wc_SRTP_KDF(key, AES_256_KEY_SIZE, salt, sizeof(salt),
                kdrIdx, index, keyE, AES_256_KEY_SIZE, keyA, sizeof(keyA),
                keyS, sizeof(keyS));
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );
    PRIVATE_KEY_LOCK();
    bench_stats_asym_finish("KDF", 256, "SRTP", 0, count, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    RESET_MULTI_VALUE_STATS_VARS();

    bench_stats_start(&count, &start);
    PRIVATE_KEY_UNLOCK();
    do {
        for (i = 0; i < numBlocks; i++) {
            ret = wc_SRTCP_KDF(key, AES_128_KEY_SIZE, salt, sizeof(salt),
                kdrIdx, index, keyE, AES_128_KEY_SIZE, keyA, sizeof(keyA),
                keyS, sizeof(keyS));
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );
    PRIVATE_KEY_LOCK();
    bench_stats_asym_finish("KDF", 128, "SRTCP", 0, count, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    RESET_MULTI_VALUE_STATS_VARS();

    bench_stats_start(&count, &start);
    PRIVATE_KEY_UNLOCK();
    do {
        for (i = 0; i < numBlocks; i++) {
            ret = wc_SRTCP_KDF(key, AES_256_KEY_SIZE, salt, sizeof(salt),
                kdrIdx, index, keyE, AES_256_KEY_SIZE, keyA, sizeof(keyA),
                keyS, sizeof(keyS));
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );
    PRIVATE_KEY_LOCK();
    bench_stats_asym_finish("KDF", 256, "SRTCP", 0, count, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

}
#endif

#ifndef NO_RSA

#if defined(WOLFSSL_KEY_GEN)
static void bench_rsaKeyGen_helper(int useDeviceID, word32 keySz)
{
    WC_DECLARE_ARRAY(genKey, RsaKey, BENCH_MAX_PENDING,
                     sizeof(RsaKey), HEAP_HINT);
    double start = 0;
    int    ret = 0, i, count = 0, times, pending = 0;
    const long rsa_e_val = WC_RSA_EXPONENT;
    const char**desc = bench_desc_words[lng_index];
    DECLARE_MULTI_VALUE_STATS_VARS()

    WC_CALLOC_ARRAY(genKey, RsaKey, BENCH_MAX_PENDING,
                     sizeof(RsaKey), HEAP_HINT);

    bench_stats_start(&count, &start);
    do {
        /* while free pending slots in queue, submit ops */
        for (times = 0; times < genTimes || pending > 0; ) {
            bench_async_poll(&pending);

            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(genKey[i]),
                                      0, &times, genTimes, &pending)) {
                    wc_FreeRsaKey(genKey[i]);
                    ret = wc_InitRsaKey_ex(genKey[i], HEAP_HINT, devId);
                    if (ret < 0) {
                        goto exit;
                    }

                    ret = wc_MakeRsaKey(genKey[i], (int)keySz, rsa_e_val,
                                        &gRng);
                    if (!bench_async_handle(&ret,
                        BENCH_ASYNC_GET_DEV(genKey[i]), 0,
                                            &times, &pending)) {
                        goto exit;
                    }
                }
            } /* for i */
            RECORD_MULTI_VALUE_STATS();
        } /* for times */
        count += times;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

exit:
    bench_stats_asym_finish("RSA", (int)keySz, desc[2], useDeviceID, count,
                            start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    /* cleanup */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        wc_FreeRsaKey(genKey[i]);
    }

    WC_FREE_ARRAY(genKey, BENCH_MAX_PENDING, HEAP_HINT);
}

void bench_rsaKeyGen(int useDeviceID)
{
    int    k;

#if !defined(RSA_MAX_SIZE) || !defined(RSA_MIN_SIZE)
    static const word32  keySizes[2] = {1024, 2048 };
#elif RSA_MAX_SIZE >= 4096
    #if (!defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)) &&      \
        (RSA_MIN_SIZE <= 1024)
        static const word32  keySizes[4] = {1024, 2048, 3072, 4096 };
    #else
        static const word32  keySizes[3] = {2048, 3072, 4096};
    #endif
#elif RSA_MAX_SIZE >= 3072
    #if (!defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)) &&      \
        (RSA_MIN_SIZE <= 1024)
        static const word32  keySizes[3] = {1024, 2048, 3072 };
    #else
        static const word32  keySizes[2] = {2048, 3072 };
    #endif
#elif RSA_MAX_SIZE >= 2048
    #if (!defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)) &&      \
        (RSA_MIN_SIZE <= 1024)
        static const word32  keySizes[2] = {1024, 2048 };
    #else
        static const word32  keySizes[1] = {2048};
    #endif
#else
    #if (!defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)) &&      \
        (RSA_MIN_SIZE <= 1024)
        static const word32  keySizes[1] = {1024 };
    #else
        #error No candidate RSA key sizes to benchmark.
    #endif
#endif

    for (k = 0; k < (int)(sizeof(keySizes)/sizeof(int)); k++) {
        bench_rsaKeyGen_helper(useDeviceID, keySizes[k]);
    }
}


void bench_rsaKeyGen_size(int useDeviceID, word32 keySz)
{
    bench_rsaKeyGen_helper(useDeviceID, keySz);
}
#endif /* WOLFSSL_KEY_GEN */

#if !defined(USE_CERT_BUFFERS_1024) && !defined(USE_CERT_BUFFERS_2048) && \
    !defined(USE_CERT_BUFFERS_3072) && !defined(USE_CERT_BUFFERS_4096)
    #if defined(WOLFSSL_MDK_SHELL)
        static char *certRSAname = "certs/rsa2048.der";
        /* set by shell command */
        static void set_Bench_RSA_File(char * cert) { certRSAname = cert ; }
    #elif defined(FREESCALE_MQX)
        static char *certRSAname = "a:\\certs\\rsa2048.der";
    #else
        static const char *certRSAname = "certs/rsa2048.der";
    #endif
#endif

#define RSA_BUF_SIZE 384  /* for up to 3072 bit */

#if defined(WOLFSSL_RSA_VERIFY_INLINE) || defined(WOLFSSL_RSA_PUBLIC_ONLY)
#if defined(USE_CERT_BUFFERS_2048)
static const unsigned char rsa_2048_sig[] = {
    0x8c, 0x9e, 0x37, 0xbf, 0xc3, 0xa6, 0xba, 0x1c,
    0x53, 0x22, 0x40, 0x4b, 0x8b, 0x0d, 0x3c, 0x0e,
    0x2e, 0x8c, 0x31, 0x2c, 0x47, 0xbf, 0x03, 0x48,
    0x18, 0x46, 0x73, 0x8d, 0xd7, 0xdd, 0x17, 0x64,
    0x0d, 0x7f, 0xdc, 0x74, 0xed, 0x80, 0xc3, 0xe8,
    0x9a, 0x18, 0x33, 0xd4, 0xe6, 0xc5, 0xe1, 0x54,
    0x75, 0xd1, 0xbb, 0x40, 0xde, 0xa8, 0xb9, 0x1b,
    0x14, 0xe8, 0xc1, 0x39, 0xeb, 0xa0, 0x69, 0x8a,
    0xc6, 0x9b, 0xef, 0x53, 0xb5, 0x23, 0x2b, 0x78,
    0x06, 0x43, 0x37, 0x11, 0x81, 0x84, 0x73, 0x33,
    0x33, 0xfe, 0xf7, 0x5d, 0x2b, 0x84, 0xd6, 0x83,
    0xd6, 0xdd, 0x55, 0x33, 0xef, 0xd1, 0xf7, 0x12,
    0xb0, 0xc2, 0x0e, 0xb1, 0x78, 0xd4, 0xa8, 0xa3,
    0x25, 0xeb, 0xed, 0x9a, 0xb3, 0xee, 0xc3, 0x7e,
    0xce, 0x13, 0x18, 0x86, 0x31, 0xe1, 0xef, 0x01,
    0x0f, 0x6e, 0x67, 0x24, 0x74, 0xbd, 0x0b, 0x7f,
    0xa9, 0xca, 0x6f, 0xaa, 0x83, 0x28, 0x90, 0x40,
    0xf1, 0xb5, 0x10, 0x0e, 0x26, 0x03, 0x05, 0x5d,
    0x87, 0xb4, 0xe0, 0x4c, 0x98, 0xd8, 0xc6, 0x42,
    0x89, 0x77, 0xeb, 0xb6, 0xd4, 0xe6, 0x26, 0xf3,
    0x31, 0x25, 0xde, 0x28, 0x38, 0x58, 0xe8, 0x2c,
    0xf4, 0x56, 0x7c, 0xb6, 0xfd, 0x99, 0xb0, 0xb0,
    0xf4, 0x83, 0xb6, 0x74, 0xa9, 0x5b, 0x9f, 0xe8,
    0xe9, 0xf1, 0xa1, 0x2a, 0xbd, 0xf6, 0x83, 0x28,
    0x09, 0xda, 0xa6, 0xd6, 0xcd, 0x61, 0x60, 0xf7,
    0x13, 0x4e, 0x46, 0x57, 0x38, 0x1e, 0x11, 0x92,
    0x6b, 0x6b, 0xcf, 0xd3, 0xf4, 0x8b, 0x66, 0x03,
    0x25, 0xa3, 0x7a, 0x2f, 0xce, 0xc1, 0x85, 0xa5,
    0x48, 0x91, 0x8a, 0xb3, 0x4f, 0x5d, 0x98, 0xb1,
    0x69, 0x58, 0x47, 0x69, 0x0c, 0x52, 0xdc, 0x42,
    0x4c, 0xef, 0xe8, 0xd4, 0x4d, 0x6a, 0x33, 0x7d,
    0x9e, 0xd2, 0x51, 0xe6, 0x41, 0xbf, 0x4f, 0xa2
};
#elif defined(USE_CERT_BUFFERS_3072)
static const unsigned char rsa_3072_sig[] = {
    0x1a, 0xd6, 0x0d, 0xfd, 0xe3, 0x41, 0x95, 0x76,
    0x27, 0x16, 0x7d, 0xc7, 0x94, 0x16, 0xca, 0xa8,
    0x26, 0x08, 0xbe, 0x78, 0x87, 0x72, 0x4c, 0xd9,
    0xa7, 0xfc, 0x33, 0x77, 0x2d, 0x53, 0x07, 0xb5,
    0x8c, 0xce, 0x48, 0x17, 0x9b, 0xff, 0x9f, 0x9b,
    0x17, 0xc4, 0xbb, 0x72, 0xed, 0xdb, 0xa0, 0x34,
    0x69, 0x5b, 0xc7, 0x4e, 0xbf, 0xec, 0x13, 0xc5,
    0x98, 0x71, 0x9a, 0x4e, 0x18, 0x0e, 0xcb, 0xe7,
    0xc6, 0xd5, 0x21, 0x31, 0x7c, 0x0d, 0xae, 0x14,
    0x2b, 0x87, 0x4f, 0x77, 0x95, 0x2e, 0x26, 0xe2,
    0x83, 0xfe, 0x49, 0x1e, 0x87, 0x19, 0x4a, 0x63,
    0x73, 0x75, 0xf1, 0xf5, 0x71, 0xd2, 0xce, 0xd4,
    0x39, 0x2b, 0xd9, 0xe0, 0x76, 0x70, 0xc8, 0xf8,
    0xed, 0xdf, 0x90, 0x57, 0x17, 0xb9, 0x16, 0xf6,
    0xe9, 0x49, 0x48, 0xce, 0x5a, 0x8b, 0xe4, 0x84,
    0x7c, 0xf3, 0x31, 0x68, 0x97, 0x45, 0x68, 0x38,
    0x50, 0x3a, 0x70, 0xbd, 0xb3, 0xd3, 0xd2, 0xe0,
    0x56, 0x5b, 0xc2, 0x0c, 0x2c, 0x10, 0x70, 0x7b,
    0xd4, 0x99, 0xf9, 0x38, 0x31, 0xb1, 0x86, 0xa0,
    0x07, 0xf1, 0xf6, 0x53, 0xb0, 0x44, 0x82, 0x40,
    0xd2, 0xab, 0x0e, 0x71, 0x5d, 0xe1, 0xea, 0x3a,
    0x77, 0xc9, 0xef, 0xfe, 0x54, 0x65, 0xa3, 0x49,
    0xfd, 0xa5, 0x33, 0xaa, 0x16, 0x1a, 0x38, 0xe7,
    0xaa, 0xb7, 0x13, 0xb2, 0x3b, 0xc7, 0x00, 0x87,
    0x12, 0xfe, 0xfd, 0xf4, 0x55, 0x6d, 0x1d, 0x4a,
    0x0e, 0xad, 0xd0, 0x4c, 0x55, 0x91, 0x60, 0xd9,
    0xef, 0x74, 0x69, 0x22, 0x8c, 0x51, 0x65, 0xc2,
    0x04, 0xac, 0xd3, 0x8d, 0xf7, 0x35, 0x29, 0x13,
    0x6d, 0x61, 0x7c, 0x39, 0x2f, 0x41, 0x4c, 0xdf,
    0x38, 0xfd, 0x1a, 0x7d, 0x42, 0xa7, 0x6f, 0x3f,
    0x3d, 0x9b, 0xd1, 0x97, 0xab, 0xc0, 0xa7, 0x28,
    0x1c, 0xc0, 0x02, 0x26, 0xeb, 0xce, 0xf9, 0xe1,
    0x34, 0x45, 0xaf, 0xbf, 0x8d, 0xb8, 0xe0, 0xff,
    0xd9, 0x6f, 0x77, 0xf3, 0xf7, 0xed, 0x6a, 0xbb,
    0x03, 0x52, 0xfb, 0x38, 0xfc, 0xea, 0x9f, 0xc9,
    0x98, 0xed, 0x21, 0x45, 0xaf, 0x43, 0x2b, 0x64,
    0x96, 0x82, 0x30, 0xe9, 0xb4, 0x36, 0x89, 0x77,
    0x07, 0x4a, 0xc6, 0x1f, 0x38, 0x7a, 0xee, 0xb6,
    0x86, 0xf6, 0x2f, 0x03, 0xec, 0xa2, 0xe5, 0x48,
    0xe5, 0x5a, 0xf5, 0x1c, 0xd2, 0xd9, 0xd8, 0x2d,
    0x9d, 0x06, 0x07, 0xc9, 0x8b, 0x5d, 0xe0, 0x0f,
    0x5e, 0x0c, 0x53, 0x27, 0xff, 0x23, 0xee, 0xca,
    0x5e, 0x4d, 0xf1, 0x95, 0x77, 0x78, 0x1f, 0xf2,
    0x44, 0x5b, 0x7d, 0x01, 0x49, 0x61, 0x6f, 0x6d,
    0xbf, 0xf5, 0x19, 0x06, 0x39, 0xe9, 0xe9, 0x29,
    0xde, 0x47, 0x5e, 0x2e, 0x1f, 0x68, 0xf4, 0x32,
    0x5e, 0xe9, 0xd0, 0xa7, 0xb4, 0x2a, 0x45, 0xdf,
    0x15, 0x7d, 0x0d, 0x5b, 0xef, 0xc6, 0x23, 0xac
};
#else
    #error Not Supported Yet!
#endif
#endif /* WOLFSSL_RSA_VERIFY_INLINE || WOLFSSL_RSA_PUBLIC_ONLY */

static void bench_rsa_helper(int useDeviceID,
                             WC_ARRAY_ARG(rsaKey,
                                          RsaKey,
                                          BENCH_MAX_PENDING,
                                          sizeof(RsaKey)),
                             word32 rsaKeySz)
{
    int         ret = 0, i, times, count = 0, pending = 0;
    word32      idx = 0;
#ifndef WOLFSSL_RSA_VERIFY_ONLY
    const char* messageStr = TEST_STRING;
    const int   len = (int)TEST_STRING_SZ;
#endif
    double      start = 0.0F;
    const char**desc = bench_desc_words[lng_index];
    DECLARE_MULTI_VALUE_STATS_VARS()
#ifndef WOLFSSL_RSA_VERIFY_ONLY
    WC_DECLARE_VAR(message, byte, TEST_STRING_SZ, HEAP_HINT);
#endif
    WC_DECLARE_HEAP_ARRAY(enc, byte, BENCH_MAX_PENDING,
                                 rsaKeySz, HEAP_HINT);

#if (!defined(WOLFSSL_RSA_VERIFY_INLINE) && \
     !defined(WOLFSSL_RSA_PUBLIC_ONLY))
    WC_DECLARE_HEAP_ARRAY(out, byte, BENCH_MAX_PENDING,
                                    rsaKeySz, HEAP_HINT);
#else
    byte* out[BENCH_MAX_PENDING];
#endif

    XMEMSET(out, 0, sizeof(out));

    WC_ALLOC_HEAP_ARRAY(enc, byte, BENCH_MAX_PENDING,
                                 rsaKeySz, HEAP_HINT);

#if (!defined(WOLFSSL_RSA_VERIFY_INLINE) && \
     !defined(WOLFSSL_RSA_PUBLIC_ONLY))
    WC_ALLOC_HEAP_ARRAY(out, byte, BENCH_MAX_PENDING,
                                    rsaKeySz, HEAP_HINT);
    if (out[0] == NULL) {
        ret = MEMORY_E;
        goto exit;
    }
#endif
    if (enc[0] == NULL) {
        ret = MEMORY_E;
        goto exit;
    }

#ifndef WOLFSSL_RSA_VERIFY_ONLY
    WC_ALLOC_VAR(message, byte, TEST_STRING_SZ, HEAP_HINT);
    XMEMCPY(message, messageStr, len);
#endif

    if (!rsa_sign_verify) {
#ifndef WOLFSSL_RSA_VERIFY_ONLY
        /* begin public RSA */
        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < ntimes || pending > 0; ) {
                bench_async_poll(&pending);

                /* while free pending slots in queue, submit ops */
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret,
                                          BENCH_ASYNC_GET_DEV(rsaKey[i]),
                                          1, &times, ntimes, &pending)) {
                        ret = wc_RsaPublicEncrypt(message, (word32)len, enc[i],
                                                  rsaKeySz/8, rsaKey[i],
                                                  GLOBAL_RNG);
                        if (!bench_async_handle(&ret,
                                                BENCH_ASYNC_GET_DEV(
                                                rsaKey[i]), 1, &times,
                                                &pending)) {
                            goto exit_rsa_verify;
                        }
                    }
                } /* for i */
            RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );

exit_rsa_verify:
        bench_stats_asym_finish("RSA", (int)rsaKeySz, desc[0],
                                useDeviceID, count, start, ret);
    #ifdef MULTI_VALUE_STATISTICS
        bench_multi_value_stats(max, min, sum, squareSum, runs);
    #endif
#endif /* !WOLFSSL_RSA_VERIFY_ONLY */

#ifndef WOLFSSL_RSA_PUBLIC_ONLY
        if (ret < 0) {
            goto exit;
        }

        RESET_MULTI_VALUE_STATS_VARS();

        /* capture resulting encrypt length */
        idx = (word32)(rsaKeySz/8);

        /* begin private async RSA */
        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < ntimes || pending > 0; ) {
                bench_async_poll(&pending);

                /* while free pending slots in queue, submit ops */
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret,
                                          BENCH_ASYNC_GET_DEV(rsaKey[i]),
                                          1, &times, ntimes, &pending)) {
                        ret = wc_RsaPrivateDecrypt(enc[i], idx, out[i],
                                                   rsaKeySz/8, rsaKey[i]);
                        if (!bench_async_handle(&ret,
                                           BENCH_ASYNC_GET_DEV(rsaKey[i]),
                                                1, &times, &pending)) {
                            goto exit_rsa_pub;
                        }
                    }
                } /* for i */
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );

exit_rsa_pub:
        bench_stats_asym_finish("RSA", (int)rsaKeySz, desc[1],
                                useDeviceID, count, start, ret);
    #ifdef MULTI_VALUE_STATISTICS
        bench_multi_value_stats(max, min, sum, squareSum, runs);
    #endif
#endif /* !WOLFSSL_RSA_PUBLIC_ONLY */
    }
    else {
#if !defined(WOLFSSL_RSA_PUBLIC_ONLY) && !defined(WOLFSSL_RSA_VERIFY_ONLY)
        /* begin RSA sign */
        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < ntimes || pending > 0; ) {
                bench_async_poll(&pending);

                /* while free pending slots in queue, submit ops */
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret,
                                          BENCH_ASYNC_GET_DEV(rsaKey[i]),
                                          1, &times, ntimes, &pending)) {
                        ret = wc_RsaSSL_Sign(message, len, enc[i],
                                            rsaKeySz/8, rsaKey[i], GLOBAL_RNG);
                        if (!bench_async_handle(&ret,
                                           BENCH_ASYNC_GET_DEV(rsaKey[i]),
                                           1, &times, &pending)) {
                            goto exit_rsa_sign;
                        }
                    }
                } /* for i */
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
           || runs < minimum_runs
    #endif
           );

exit_rsa_sign:
        bench_stats_asym_finish("RSA", (int)rsaKeySz, desc[4], useDeviceID,
                                count, start, ret);
    #ifdef MULTI_VALUE_STATISTICS
        bench_multi_value_stats(max, min, sum, squareSum, runs);
    #endif
        if (ret < 0) {
            goto exit;
        }

        RESET_MULTI_VALUE_STATS_VARS();

#endif /* !WOLFSSL_RSA_PUBLIC_ONLY && !WOLFSSL_RSA_VERIFY_ONLY */

        /* capture resulting encrypt length */
        idx = rsaKeySz/8;

        /* begin RSA verify */
        bench_stats_start(&count, &start);
        do {
            for (times = 0; times < ntimes || pending > 0; ) {
                bench_async_poll(&pending);

                /* while free pending slots in queue, submit ops */
                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret,
                                          BENCH_ASYNC_GET_DEV(rsaKey[i]),
                                          1, &times, ntimes, &pending)) {
                    #if !defined(WOLFSSL_RSA_VERIFY_INLINE) && \
                        !defined(WOLFSSL_RSA_PUBLIC_ONLY)
                        ret = wc_RsaSSL_Verify(enc[i], idx, out[i],
                                                      rsaKeySz/8, rsaKey[i]);
                    #elif defined(USE_CERT_BUFFERS_2048)
                        XMEMCPY(enc[i], rsa_2048_sig, sizeof(rsa_2048_sig));
                        idx = sizeof(rsa_2048_sig);
                        out[i] = NULL;
                        ret = wc_RsaSSL_VerifyInline(enc[i], idx,
                                                     &out[i], rsaKey[i]);
                        if (ret > 0) {
                            ret = 0;
                        }

                    #elif defined(USE_CERT_BUFFERS_3072)
                        XMEMCPY(enc[i], rsa_3072_sig, sizeof(rsa_3072_sig));
                        idx = sizeof(rsa_3072_sig);
                        out[i] = NULL;
                        ret = wc_RsaSSL_VerifyInline(enc[i], idx,
                                                     &out[i], rsaKey[i]);
                        if (ret > 0)
                            ret = 0;
                    #endif
                        if (!bench_async_handle(&ret,
                                              BENCH_ASYNC_GET_DEV(rsaKey[i]),
                                              1, &times, &pending)) {
                            goto exit_rsa_verifyinline;
                        }
                    }
                } /* for i */
                RECORD_MULTI_VALUE_STATS();
            } /* for times */
            count += times;
        } while (bench_stats_check(start)
    #ifdef MULTI_VALUE_STATISTICS
          || runs < minimum_runs
    #endif
           );

exit_rsa_verifyinline:
        bench_stats_asym_finish("RSA", (int)rsaKeySz, desc[5],
                                 useDeviceID, count,  start, ret);
    #ifdef MULTI_VALUE_STATISTICS
        bench_multi_value_stats(max, min, sum, squareSum, runs);
    #endif
    }

exit:

    WC_FREE_HEAP_ARRAY(enc, BENCH_MAX_PENDING, HEAP_HINT);
#if !defined(WOLFSSL_RSA_VERIFY_INLINE) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
    WC_FREE_HEAP_ARRAY(out, BENCH_MAX_PENDING, HEAP_HINT);
#endif
#ifndef WOLFSSL_RSA_VERIFY_ONLY
    WC_FREE_VAR(message, HEAP_HINT);
#endif
}

void bench_rsa(int useDeviceID)
{
    int         i;
    WC_DECLARE_ARRAY(rsaKey, RsaKey, BENCH_MAX_PENDING,
                     sizeof(RsaKey), HEAP_HINT);
    int         ret = 0;
    word32      rsaKeySz = 0;
    const byte* tmp;
    size_t      bytes;
#if !defined(WOLFSSL_RSA_PUBLIC_ONLY) && !defined(WOLFSSL_RSA_VERIFY_ONLY)
    word32      idx;
#endif

    WC_CALLOC_ARRAY(rsaKey, RsaKey, BENCH_MAX_PENDING,
                     sizeof(RsaKey), HEAP_HINT);

#ifdef USE_CERT_BUFFERS_1024
    tmp = rsa_key_der_1024;
    bytes = (size_t)sizeof_rsa_key_der_1024;
    rsaKeySz = 1024;
#elif defined(USE_CERT_BUFFERS_2048)
    tmp = rsa_key_der_2048;
    bytes = (size_t)sizeof_rsa_key_der_2048;
    rsaKeySz = 2048;
#elif defined(USE_CERT_BUFFERS_3072)
    tmp = rsa_key_der_3072;
    bytes = (size_t)sizeof_rsa_key_der_3072;
    rsaKeySz = 3072;
#elif defined(USE_CERT_BUFFERS_4096)
    tmp = client_key_der_4096;
    bytes = (size_t)sizeof_client_key_der_4096;
    rsaKeySz = 4096;
#else
    #error "need a cert buffer size"
#endif /* USE_CERT_BUFFERS */

    /* init keys */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        /* setup an async context for each key */
        ret = wc_InitRsaKey_ex(rsaKey[i], HEAP_HINT,
            useDeviceID ? devId : INVALID_DEVID);
        if (ret < 0) {
            goto exit;
        }

#if !defined(WOLFSSL_RSA_PUBLIC_ONLY) && !defined(WOLFSSL_RSA_VERIFY_ONLY)
    #ifdef WC_RSA_BLINDING
        ret = wc_RsaSetRNG(rsaKey[i], &gRng);
        if (ret != 0)
            goto exit;
    #endif
#endif

#if !defined(WOLFSSL_RSA_PUBLIC_ONLY) && !defined(WOLFSSL_RSA_VERIFY_ONLY)
        /* decode the private key */
        idx = 0;
        if ((ret = wc_RsaPrivateKeyDecode(tmp, &idx,
                                          rsaKey[i], (word32)bytes)) != 0) {
            printf("wc_RsaPrivateKeyDecode failed! %d\n", ret);
            goto exit;
        }
#elif defined(WOLFSSL_PUBLIC_MP)
        /* get offset to public portion of the RSA key */
    #ifdef USE_CERT_BUFFERS_1024
        bytes = 11;
    #elif defined(USE_CERT_BUFFERS_2048) || defined(USE_CERT_BUFFERS_3072)
        bytes = 12;
    #endif
        ret = mp_read_unsigned_bin(&rsaKey[i]->n, &tmp[bytes], rsaKeySz/8);
        if (ret != 0) {
            printf("wc_RsaPrivateKeyDecode failed! %d\n", ret);
            goto exit;
        }
        ret = mp_set_int(&rsaKey[i]->e, WC_RSA_EXPONENT);
        if (ret != 0) {
            printf("wc_RsaPrivateKeyDecode failed! %d\n", ret);
            goto exit;
        }
#else
        /* Note: To benchmark public only define WOLFSSL_PUBLIC_MP */
        rsaKeySz = 0;
#endif
    }

    if (rsaKeySz > 0) {
        bench_rsa_helper(useDeviceID, rsaKey, rsaKeySz);
    }

    (void)bytes;
    (void)tmp;

exit:
    /* cleanup */
    if (WC_ARRAY_OK(rsaKey)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            wc_FreeRsaKey(rsaKey[i]);
        }
        WC_FREE_ARRAY(rsaKey, BENCH_MAX_PENDING, HEAP_HINT);
    }
}


#ifdef WOLFSSL_KEY_GEN
/* bench any size of RSA key */
void bench_rsa_key(int useDeviceID, word32 rsaKeySz)
{
    int     ret = 0, i, pending = 0;
    WC_DECLARE_ARRAY(rsaKey, RsaKey, BENCH_MAX_PENDING,
                     sizeof(RsaKey), HEAP_HINT);
    int isPending[BENCH_MAX_PENDING];
    long    exp = 65537L;

    /* clear for done cleanup */
    XMEMSET(isPending, 0, sizeof(isPending));

    WC_CALLOC_ARRAY(rsaKey, RsaKey, BENCH_MAX_PENDING,
                     sizeof(RsaKey), HEAP_HINT);

    /* init keys */
    do {
        pending = 0;
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            if (!isPending[i]) { /* if making the key is pending then just call
                                  * wc_MakeRsaKey again */
                /* setup an async context for each key */
                if (wc_InitRsaKey_ex(rsaKey[i], HEAP_HINT,
                        useDeviceID ? devId : INVALID_DEVID) < 0) {
                    goto exit;
                }

            #ifdef WC_RSA_BLINDING
                ret = wc_RsaSetRNG(rsaKey[i], &gRng);
                if (ret != 0)
                    goto exit;
            #endif
            }

            /* create the RSA key */
            ret = wc_MakeRsaKey(rsaKey[i], (int)rsaKeySz, exp, &gRng);
            if (ret == WC_NO_ERR_TRACE(WC_PENDING_E)) {
                isPending[i] = 1;
                pending      = 1;
            }
            else if (ret != 0) {
                printf("wc_MakeRsaKey failed! %d\n", ret);
                goto exit;
            }
        } /* for i */
    } while (pending > 0);

    bench_rsa_helper(useDeviceID, rsaKey, rsaKeySz);
exit:

    /* cleanup */
    if (WC_ARRAY_OK(rsaKey)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            wc_FreeRsaKey(rsaKey[i]);
        }
        WC_FREE_ARRAY(rsaKey, BENCH_MAX_PENDING, HEAP_HINT);
    }
}
#endif /* WOLFSSL_KEY_GEN */
#endif /* !NO_RSA */


#ifndef NO_DH

#if !defined(USE_CERT_BUFFERS_1024) && !defined(USE_CERT_BUFFERS_2048) && \
    !defined(USE_CERT_BUFFERS_3072) && !defined(USE_CERT_BUFFERS_4096)
    #if defined(WOLFSSL_MDK_SHELL)
        static char *certDHname = "certs/dh2048.der";
        /* set by shell command */
        void set_Bench_DH_File(char * cert) { certDHname = cert ; }
    #elif defined(FREESCALE_MQX)
        static char *certDHname = "a:\\certs\\dh2048.der";
    #elif defined(NO_ASN)
        /* do nothing, but don't need a file */
    #else
        static const char *certDHname = "certs/dh2048.der";
    #endif
#endif

#ifdef HAVE_FFDHE_4096
#define BENCH_DH_KEY_SIZE  512 /* for 4096 bit */
#else
#define BENCH_DH_KEY_SIZE  384 /* for 3072 bit */
#endif
#define BENCH_DH_PRIV_SIZE (BENCH_DH_KEY_SIZE/8)

void bench_dh(int useDeviceID)
{
    int    ret = 0, i;
    int    count = 0, times, pending = 0;
    const byte* tmp = NULL;
    double start = 0.0F;
    WC_DECLARE_ARRAY(dhKey, DhKey, BENCH_MAX_PENDING,
                     sizeof(DhKey), HEAP_HINT);
    int    dhKeySz = BENCH_DH_KEY_SIZE * 8; /* used in printf */
    const char**desc = bench_desc_words[lng_index];
#ifndef NO_ASN
    size_t bytes = 0;
    word32 idx;
#endif
    word32 pubSz[BENCH_MAX_PENDING];
    word32 privSz[BENCH_MAX_PENDING];
    word32 pubSz2 = BENCH_DH_KEY_SIZE;
    word32 privSz2 = BENCH_DH_PRIV_SIZE;
    word32 agreeSz[BENCH_MAX_PENDING];
#if defined(HAVE_FFDHE_2048) || defined(HAVE_FFDHE_3072) || defined(HAVE_FFDHE_4096)
#ifdef HAVE_PUBLIC_FFDHE
    const DhParams *params = NULL;
#else
    int paramName = 0;
#endif
#endif
    DECLARE_MULTI_VALUE_STATS_VARS()

    WC_DECLARE_ARRAY(pub, byte, BENCH_MAX_PENDING,
                     BENCH_DH_KEY_SIZE, HEAP_HINT);
    WC_DECLARE_VAR(pub2, byte,
                     BENCH_DH_KEY_SIZE, HEAP_HINT);
    WC_DECLARE_ARRAY(agree, byte, BENCH_MAX_PENDING,
                     BENCH_DH_KEY_SIZE, HEAP_HINT);
    WC_DECLARE_ARRAY(priv, byte, BENCH_MAX_PENDING,
                     BENCH_DH_PRIV_SIZE, HEAP_HINT);
    WC_DECLARE_VAR(priv2, byte,
                     BENCH_DH_PRIV_SIZE, HEAP_HINT);

    /* old scan-build misfires -Wmaybe-uninitialized on these. */
    XMEMSET(pub, 0, sizeof(pub));
    XMEMSET(agree, 0, sizeof(agree));
    XMEMSET(priv, 0, sizeof(priv));

    WC_CALLOC_ARRAY(dhKey, DhKey, BENCH_MAX_PENDING,
                     sizeof(DhKey), HEAP_HINT);
    WC_ALLOC_ARRAY(pub, byte,
                  BENCH_MAX_PENDING, BENCH_DH_KEY_SIZE, HEAP_HINT);
    WC_ALLOC_ARRAY(agree, byte,
                  BENCH_MAX_PENDING, BENCH_DH_KEY_SIZE, HEAP_HINT);
    WC_ALLOC_ARRAY(priv, byte,
                  BENCH_MAX_PENDING, BENCH_DH_PRIV_SIZE, HEAP_HINT);

    WC_ALLOC_VAR(pub2, byte, BENCH_DH_KEY_SIZE, HEAP_HINT);
    WC_ALLOC_VAR(priv2, byte, BENCH_DH_PRIV_SIZE, HEAP_HINT);

    (void)tmp;

    if (!use_ffdhe) {
#if defined(NO_ASN)
        dhKeySz = 1024;
        /* do nothing, but don't use default FILE */
#elif defined(USE_CERT_BUFFERS_1024)
        tmp = dh_key_der_1024;
        bytes = (size_t)sizeof_dh_key_der_1024;
        dhKeySz = 1024;
#elif defined(USE_CERT_BUFFERS_2048)
        tmp = dh_key_der_2048;
        bytes = (size_t)sizeof_dh_key_der_2048;
        dhKeySz = 2048;
#elif defined(USE_CERT_BUFFERS_3072)
        tmp = dh_key_der_3072;
        bytes = (size_t)sizeof_dh_key_der_3072;
        dhKeySz = 3072;
#elif defined(USE_CERT_BUFFERS_4096)
        tmp = dh_key_der_4096;
        bytes = (size_t)sizeof_dh_key_der_4096;
        dhKeySz = 4096;
#else
    #error "need to define a cert buffer size"
#endif /* USE_CERT_BUFFERS */
    }
#ifdef HAVE_FFDHE_2048
    else if (use_ffdhe == 2048) {
#ifdef HAVE_PUBLIC_FFDHE
        params = wc_Dh_ffdhe2048_Get();
#else
        paramName = WC_FFDHE_2048;
#endif
        dhKeySz = 2048;
    }
#endif
#ifdef HAVE_FFDHE_3072
    else if (use_ffdhe == 3072) {
#ifdef HAVE_PUBLIC_FFDHE
        params = wc_Dh_ffdhe3072_Get();
#else
        paramName = WC_FFDHE_3072;
#endif
        dhKeySz = 3072;
    }
#endif
#ifdef HAVE_FFDHE_4096
    else if (use_ffdhe == 4096) {
#ifdef HAVE_PUBLIC_FFDHE
        params = wc_Dh_ffdhe4096_Get();
#else
        paramName = WC_FFDHE_4096;
#endif
        dhKeySz = 4096;
    }
#endif

    /* init keys */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        /* setup an async context for each key */
        ret = wc_InitDhKey_ex(dhKey[i], HEAP_HINT,
                        useDeviceID ? devId : INVALID_DEVID);
        if (ret != 0)
            goto exit;

        /* setup key */
        if (!use_ffdhe) {
    #ifdef NO_ASN
            ret = wc_DhSetKey(dhKey[i], dh_p,
                              sizeof(dh_p), dh_g, sizeof(dh_g));
    #else
            idx = 0;
            ret = wc_DhKeyDecode(tmp, &idx, dhKey[i], (word32)bytes);
    #endif
        }
    #if defined(HAVE_FFDHE_2048) || defined(HAVE_FFDHE_3072)
    #ifdef HAVE_PUBLIC_FFDHE
        else if (params != NULL) {
            ret = wc_DhSetKey(dhKey[i], params->p, params->p_len,
                              params->g, params->g_len);
        }
    #else
        else if (paramName != 0) {
            ret = wc_DhSetNamedKey(dhKey[i], paramName);
        }
    #endif
    #endif
        if (ret != 0) {
            printf("DhKeyDecode failed %d, can't benchmark\n", ret);
            goto exit;
        }
    }


    /* Key Gen */
    bench_stats_start(&count, &start);
    PRIVATE_KEY_UNLOCK();
    do {
        /* while free pending slots in queue, submit ops */
        for (times = 0; times < genTimes || pending > 0; ) {
            bench_async_poll(&pending);

            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(dhKey[i]),
                                      0, &times, genTimes, &pending)) {
                    privSz[i] = BENCH_DH_PRIV_SIZE;
                    pubSz[i] = BENCH_DH_KEY_SIZE;
                    ret = wc_DhGenerateKeyPair(dhKey[i], &gRng,
                                               priv[i], &privSz[i],
                                               pub[i], &pubSz[i]);
                    if (!bench_async_handle(&ret,
                                            BENCH_ASYNC_GET_DEV(dhKey[i]),
                                            0, &times, &pending)) {
                        goto exit_dh_gen;
                    }
                }
            } /* for i */
            RECORD_MULTI_VALUE_STATS();
        } /* for times */
        count += times;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    PRIVATE_KEY_LOCK();
exit_dh_gen:
    bench_stats_asym_finish("DH", dhKeySz, desc[2],
                            useDeviceID, count, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    if (ret < 0) {
        goto exit;
    }

    RESET_MULTI_VALUE_STATS_VARS();

    /* Generate key to use as other public */
    PRIVATE_KEY_UNLOCK();
    ret = wc_DhGenerateKeyPair(dhKey[0], &gRng,
                               priv2, &privSz2, pub2, &pubSz2);
    PRIVATE_KEY_LOCK();
#ifdef WOLFSSL_ASYNC_CRYPT
    ret = wc_AsyncWait(ret, &dhKey[0]->asyncDev, WC_ASYNC_FLAG_NONE);
#endif

    /* Key Agree */
    bench_stats_start(&count, &start);
    PRIVATE_KEY_UNLOCK();
    do {
        for (times = 0; times < agreeTimes || pending > 0; ) {
            bench_async_poll(&pending);

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(dhKey[i]),
                                      0, &times, agreeTimes, &pending)) {
                    ret = wc_DhAgree(dhKey[i], agree[i], &agreeSz[i], priv[i],
                                     privSz[i], pub2, pubSz2);
                    if (!bench_async_handle(&ret,
                        BENCH_ASYNC_GET_DEV(dhKey[i]), 0, &times, &pending)) {
                        goto exit;
                    }
                }
            } /* for i */
            RECORD_MULTI_VALUE_STATS();
        } /* for times */
        count += times;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    PRIVATE_KEY_LOCK();

exit:
    bench_stats_asym_finish("DH", dhKeySz, desc[3],
    useDeviceID, count, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    /* cleanup */
    if (WC_ARRAY_OK(dhKey)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            wc_FreeDhKey(dhKey[i]);
        }
        WC_FREE_ARRAY(dhKey, BENCH_MAX_PENDING, HEAP_HINT);
    }
    WC_FREE_ARRAY(pub, BENCH_MAX_PENDING, HEAP_HINT);
    WC_FREE_VAR(pub2, HEAP_HINT);
    WC_FREE_ARRAY(priv, BENCH_MAX_PENDING, HEAP_HINT);
    WC_FREE_VAR(priv2, HEAP_HINT);
    WC_FREE_ARRAY(agree, BENCH_MAX_PENDING, HEAP_HINT);
}
#endif /* !NO_DH */

#ifdef WOLFSSL_HAVE_KYBER
static void bench_kyber_keygen(int type, const char* name, int keySize,
    KyberKey* key)
{
    int ret = 0, times, count, pending = 0;
    double start;
    const char**desc = bench_desc_words[lng_index];
    DECLARE_MULTI_VALUE_STATS_VARS()

    /* KYBER Make Key */
    bench_stats_start(&count, &start);
    do {
        /* while free pending slots in queue, submit ops */
        for (times = 0; times < agreeTimes || pending > 0; times++) {
            wc_KyberKey_Free(key);
            ret = wc_KyberKey_Init(type, key, HEAP_HINT, INVALID_DEVID);
            if (ret != 0)
                goto exit;

#ifdef KYBER_NONDETERMINISTIC
            ret = wc_KyberKey_MakeKey(key, &gRng);
#else
            unsigned char rand[KYBER_MAKEKEY_RAND_SZ] = {0,};
            ret = wc_KyberKey_MakeKeyWithRandom(key, rand, sizeof(rand));
#endif
            if (ret != 0)
                goto exit;
            RECORD_MULTI_VALUE_STATS();
        } /* for times */
        count += times;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

exit:
    bench_stats_asym_finish(name, keySize, desc[2], 0, count, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif
}

static void bench_kyber_encap(const char* name, int keySize, KyberKey* key)
{
    int ret = 0, times, count, pending = 0;
    double start;
    const char**desc = bench_desc_words[lng_index];
    byte ct[KYBER_MAX_CIPHER_TEXT_SIZE];
    byte ss[KYBER_SS_SZ];
    word32 ctSz;
    DECLARE_MULTI_VALUE_STATS_VARS()

    ret = wc_KyberKey_CipherTextSize(key, &ctSz);
    if (ret != 0) {
        return;
    }

    /* KYBER Encapsulate */
    bench_stats_start(&count, &start);
    do {
        /* while free pending slots in queue, submit ops */
        for (times = 0; times < agreeTimes || pending > 0; times++) {
#ifdef KYBER_NONDETERMINISTIC
            ret = wc_KyberKey_Encapsulate(key, ct, ss, &gRng);
#else
            unsigned char rand[KYBER_ENC_RAND_SZ] = {0,};
            ret = wc_KyberKey_EncapsulateWithRandom(key, ct, ss, rand,
                sizeof(rand));
#endif
            if (ret != 0)
                goto exit_encap;
            RECORD_MULTI_VALUE_STATS();
        } /* for times */
        count += times;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

exit_encap:
    bench_stats_asym_finish(name, keySize, desc[9], 0, count, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    RESET_MULTI_VALUE_STATS_VARS();

    /* KYBER Decapsulate */
    bench_stats_start(&count, &start);
    do {
        /* while free pending slots in queue, submit ops */
        for (times = 0; times < agreeTimes || pending > 0; times++) {
            ret = wc_KyberKey_Decapsulate(key, ss, ct, ctSz);
            if (ret != 0)
                goto exit_decap;
            RECORD_MULTI_VALUE_STATS();
        } /* for times */
        count += times;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

exit_decap:
    bench_stats_asym_finish(name, keySize, desc[13], 0, count, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif
}

void bench_kyber(int type)
{
    KyberKey key;
    const char* name = NULL;
    int keySize = 0;

    switch (type) {
#ifndef WOLFSSL_NO_ML_KEM
#ifdef WOLFSSL_WC_ML_KEM_512
    case WC_ML_KEM_512:
        name = "ML-KEM 512 ";
        keySize = 128;
        break;
#endif
#ifdef WOLFSSL_WC_ML_KEM_768
    case WC_ML_KEM_768:
        name = "ML-KEM 768 ";
        keySize = 192;
        break;
#endif
#ifdef WOLFSSL_WC_ML_KEM_1024
    case WC_ML_KEM_1024:
        name = "ML-KEM 1024 ";
        keySize = 256;
        break;
#endif
#endif
#ifdef WOLFSSL_KYBER_ORIGINAL
#ifdef WOLFSSL_KYBER512
    case KYBER512:
        name = "KYBER512 ";
        keySize = 128;
        break;
#endif
#ifdef WOLFSSL_KYBER768
    case KYBER768:
        name = "KYBER768 ";
        keySize = 192;
        break;
#endif
#ifdef WOLFSSL_KYBER1024
    case KYBER1024:
        name = "KYBER1024";
        keySize = 256;
        break;
#endif
#endif
    }

    bench_kyber_keygen(type, name, keySize, &key);
    bench_kyber_encap(name, keySize, &key);

    wc_KyberKey_Free(&key);
}
#endif

#if defined(WOLFSSL_HAVE_LMS) && !defined(WOLFSSL_LMS_VERIFY_ONLY)
#ifndef WOLFSSL_NO_LMS_SHA256_256
/* WC_LMS_PARM_L2_H10_W2
 * signature length: 9300 */
static const byte lms_priv_L2_H10_W2[64] =
{
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x62,0x62,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xC7,0x74,0x25,0x5B,0x2C,0xE8,0xDA,0x53,
    0xF0,0x7C,0x04,0x3F,0x64,0x2D,0x26,0x2C,
    0x46,0x1D,0xC8,0x90,0x77,0x59,0xD6,0xC0,
    0x56,0x46,0x7D,0x97,0x64,0xF2,0xA3,0xA1,
    0xF8,0xD0,0x3B,0x5F,0xAC,0x40,0xB9,0x9E,
    0x83,0x67,0xBF,0x92,0x8D,0xFE,0x45,0x79
};

static const byte lms_pub_L2_H10_W2[60] =
{
    0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x06,
    0x00,0x00,0x00,0x02,0xF8,0xD0,0x3B,0x5F,
    0xAC,0x40,0xB9,0x9E,0x83,0x67,0xBF,0x92,
    0x8D,0xFE,0x45,0x79,0x41,0xBC,0x2A,0x3B,
    0x9F,0xC0,0x11,0x12,0x93,0xF0,0x5A,0xA5,
    0xC1,0x88,0x29,0x79,0x6C,0x3E,0x0A,0x0F,
    0xEC,0x3B,0x3E,0xE4,0x38,0xD3,0xD2,0x34,
    0x7F,0xC8,0x91,0xB0
};

/* WC_LMS_PARM_L2_H10_W4
 * signature length: 5076 */
static const byte lms_priv_L2_H10_W4[64] =
{
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x63,0x63,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xAE,0x28,0x87,0x19,0x4F,0x4B,0x68,0x61,
    0x93,0x9A,0xC7,0x0E,0x33,0xB8,0xCE,0x96,
    0x66,0x0D,0xC7,0xB1,0xFA,0x94,0x80,0xA2,
    0x28,0x9B,0xCF,0xE2,0x08,0xB5,0x25,0xAC,
    0xFB,0xB8,0x65,0x5E,0xD1,0xCC,0x31,0xDA,
    0x2E,0x49,0x3A,0xEE,0xAF,0x63,0x70,0x5E
};

static const byte lms_pub_L2_H10_W4[60] =
{
    0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x06,
    0x00,0x00,0x00,0x03,0xFB,0xB8,0x65,0x5E,
    0xD1,0xCC,0x31,0xDA,0x2E,0x49,0x3A,0xEE,
    0xAF,0x63,0x70,0x5E,0xA2,0xD5,0xB6,0x15,
    0x33,0x8C,0x9B,0xE9,0xE1,0x91,0x40,0x1A,
    0x12,0xE0,0xD7,0xBD,0xE4,0xE0,0x76,0xF5,
    0x04,0x90,0x76,0xA5,0x9A,0xA7,0x4E,0xFE,
    0x6B,0x9A,0xD3,0x14
};

/* WC_LMS_PARM_L3_H5_W4
 * signature length: 7160 */
static const byte lms_priv_L3_H5_W4[64] =
{
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x53,0x53,0x53,0xFF,0xFF,0xFF,0xFF,0xFF,
    0x38,0xD1,0xBE,0x68,0xD1,0x93,0xE1,0x14,
    0x6C,0x8B,0xED,0xE2,0x25,0x88,0xED,0xAC,
    0x57,0xBD,0x87,0x9F,0x54,0xF3,0x58,0xD9,
    0x4D,0xF5,0x6A,0xBD,0x71,0x99,0x6A,0x28,
    0x2F,0xE1,0xFC,0xD1,0xD1,0x0C,0x7C,0xF8,
    0xB4,0xDC,0xDF,0x7F,0x14,0x1A,0x7B,0x50
};

static const byte lms_pub_L3_H5_W4[60] =
{
    0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x05,
    0x00,0x00,0x00,0x03,0x2F,0xE1,0xFC,0xD1,
    0xD1,0x0C,0x7C,0xF8,0xB4,0xDC,0xDF,0x7F,
    0x14,0x1A,0x7B,0x50,0x8E,0x3A,0xD4,0x05,
    0x0C,0x95,0x59,0xA0,0xCA,0x7A,0xD8,0xD6,
    0x5D,0xBD,0x42,0xBB,0xD5,0x82,0xB8,0x9C,
    0x52,0x37,0xB7,0x45,0x03,0xC2,0x06,0xCE,
    0xAB,0x4B,0x51,0x39
};

/* WC_LMS_PARM_L3_H5_W8
 * signature length: 3992 */
static const byte lms_priv_L3_H5_W8[64] =
{
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x54,0x54,0x54,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xA5,0x46,0x97,0x0C,0xA1,0x3C,0xEA,0x17,
    0x5C,0x9D,0x59,0xF4,0x0E,0x27,0x37,0xF3,
    0x6A,0x1C,0xF7,0x29,0x4A,0xCC,0xCD,0x7B,
    0x4F,0xE7,0x37,0x6E,0xEF,0xC1,0xBD,0xBD,
    0x04,0x5D,0x8E,0xDD,0xAA,0x47,0xCC,0xE6,
    0xCE,0x78,0x46,0x20,0x41,0x87,0xE0,0x85
};

static const byte lms_pub_L3_H5_W8[60] =
{
    0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x05,
    0x00,0x00,0x00,0x04,0x04,0x5D,0x8E,0xDD,
    0xAA,0x47,0xCC,0xE6,0xCE,0x78,0x46,0x20,
    0x41,0x87,0xE0,0x85,0x0D,0x2C,0x46,0xB9,
    0x39,0x8C,0xA3,0x92,0x4F,0xCE,0x50,0x96,
    0x90,0x9C,0xF3,0x36,0x2E,0x09,0x15,0x3B,
    0x4B,0x34,0x17,0xE7,0xE2,0x55,0xFC,0x5B,
    0x83,0xAB,0x43,0xAF
};

/* WC_LMS_PARM_L3_H10_W4
 * signature length: 7640 */
static const byte lms_priv_L3_H10_W4[64] =
{
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x63,0x63,0x63,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xDF,0x98,0xAB,0xEC,0xFE,0x13,0x9F,0xF8,
    0xD7,0x2B,0x4F,0x4C,0x79,0x34,0xB8,0x89,
    0x24,0x6B,0x26,0x7D,0x7A,0x2E,0xA2,0xCB,
    0x82,0x75,0x4E,0x96,0x54,0x49,0xED,0xA0,
    0xAF,0xC7,0xA5,0xEE,0x8A,0xA2,0x83,0x99,
    0x4B,0x18,0x59,0x2B,0x66,0xC0,0x32,0xDB
};

static const byte lms_pub_L3_H10_W4[60] =
{
    0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x06,
    0x00,0x00,0x00,0x03,0xAF,0xC7,0xA5,0xEE,
    0x8A,0xA2,0x83,0x99,0x4B,0x18,0x59,0x2B,
    0x66,0xC0,0x32,0xDB,0xC4,0x18,0xEB,0x11,
    0x17,0x7D,0xAA,0x93,0xFD,0xA0,0x70,0x4D,
    0x68,0x4B,0x63,0x8F,0xC2,0xE7,0xCA,0x34,
    0x14,0x31,0x0D,0xAA,0x18,0xBF,0x9B,0x32,
    0x8D,0x78,0xD5,0xA8
};

/* WC_LMS_PARM_L4_H5_W8
 * signature length: 5340 */
static const byte lms_priv_L4_H5_W8[64] =
{
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x54,0x54,0x54,0x54,0xFF,0xFF,0xFF,0xFF,
    0x46,0x8F,0x2A,0x4A,0x14,0x26,0xF0,0x89,
    0xFE,0xED,0x66,0x0F,0x73,0x69,0xB1,0x4C,
    0x47,0xA1,0x35,0x9F,0x7B,0xBA,0x08,0x03,
    0xEE,0xA2,0xEB,0xAD,0xB4,0x82,0x52,0x1F,
    0xFD,0x9B,0x22,0x82,0x42,0x1A,0x96,0x1E,
    0xE4,0xA1,0x9C,0x33,0xED,0xE6,0x9F,0xAB
};

static const byte lms_pub_L4_H5_W8[60] =
{
    0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x05,
    0x00,0x00,0x00,0x04,0xFD,0x9B,0x22,0x82,
    0x42,0x1A,0x96,0x1E,0xE4,0xA1,0x9C,0x33,
    0xED,0xE6,0x9F,0xAB,0x6B,0x47,0x05,0x5B,
    0xA7,0xAD,0xF6,0x88,0xA5,0x4F,0xCD,0xF1,
    0xDA,0x29,0x67,0xC3,0x7F,0x2C,0x11,0xFE,
    0x85,0x1A,0x7A,0xD8,0xD5,0x46,0x74,0x3B,
    0x74,0x24,0x12,0xC8
};
#endif

static int lms_write_key_mem(const byte* priv, word32 privSz, void* context)
{
   /* WARNING: THIS IS AN INSECURE WRITE CALLBACK THAT SHOULD ONLY
    * BE USED FOR TESTING PURPOSES! Production applications should
    * write only to non-volatile storage. */
    XMEMCPY(context, priv, privSz);
    return WC_LMS_RC_SAVED_TO_NV_MEMORY;
}

static int lms_read_key_mem(byte* priv, word32 privSz, void* context)
{
   /* WARNING: THIS IS AN INSECURE READ CALLBACK THAT SHOULD ONLY
    * BE USED FOR TESTING PURPOSES! */
    XMEMCPY(priv, context, privSz);
    return WC_LMS_RC_READ_TO_MEMORY;
}
static byte lms_priv[HSS_MAX_PRIVATE_KEY_LEN];

static void bench_lms_keygen(enum wc_LmsParm parm, byte* pub)
{
    WC_RNG      rng;
    LmsKey      key;
    int         ret;
    word32      pubLen = HSS_MAX_PUBLIC_KEY_LEN;
    int         times = 0;
    int         count = 0;
    double      start = 0.0F;
    int         levels;
    int         height;
    int         winternitz;
    const char* str = wc_LmsKey_ParmToStr(parm);
    DECLARE_MULTI_VALUE_STATS_VARS()

#ifndef HAVE_FIPS
    ret = wc_InitRng_ex(&rng, HEAP_HINT, INVALID_DEVID);
#else
    ret = wc_InitRng(&rng);
#endif
    if (ret != 0) {
        fprintf(stderr, "error: wc_InitRng failed: %d\n", ret);
        return;
    }

    ret = wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    if (ret) {
        printf("wc_LmsKey_Init failed: %d\n", ret);
        wc_FreeRng(&rng);
        return;
    }

    count = 0;
    bench_stats_start(&count, &start);

    do {
        /* LMS is stateful. Async queuing not practical. */
        for (times = 0; times < 1; ++times) {

            wc_LmsKey_Free(&key);

            ret = wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
            if (ret) {
                printf("wc_LmsKey_Init failed: %d\n", ret);
                goto exit_lms_keygen;
            }

            ret = wc_LmsKey_SetLmsParm(&key, parm);
            if (ret) {
                printf("wc_LmsKey_SetLmsParm failed: %d\n", ret);
                goto exit_lms_keygen;
            }

            ret = wc_LmsKey_GetParameters(&key, &levels, &height, &winternitz);
            if (ret) {
                fprintf(stderr, "error: wc_LmsKey_GetParameters failed: %d\n",
                    ret);
                goto exit_lms_keygen;
            }

            ret = wc_LmsKey_SetWriteCb(&key, lms_write_key_mem);
            if (ret) {
                fprintf(stderr, "error: wc_LmsKey_SetWriteCb failed: %d\n",
                    ret);
                goto exit_lms_keygen;
            }

            ret = wc_LmsKey_SetReadCb(&key, lms_read_key_mem);
            if (ret) {
                fprintf(stderr, "error: wc_LmsKey_SetReadCb failed: %d\n", ret);
                goto exit_lms_keygen;
            }

            ret = wc_LmsKey_SetContext(&key, (void*)lms_priv);
            if (ret) {
                fprintf(stderr, "error: wc_LmsKey_SetContext failed: %d\n",
                    ret);
                goto exit_lms_keygen;
            }

            ret = wc_LmsKey_MakeKey(&key, &rng);
            if (ret) {
                printf("wc_LmsKey_MakeKey failed: %d\n", ret);
                goto exit_lms_keygen;
            }

            RECORD_MULTI_VALUE_STATS();
        }

        count += times;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_asym_finish(str, levels * height, "keygen", 0,
                            count, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    ret = wc_LmsKey_ExportPubRaw(&key, pub, &pubLen);
    if (ret) {
        fprintf(stderr, "error: wc_LmsKey_ExportPubRaw failed: %d\n", ret);
    }

exit_lms_keygen:
    wc_LmsKey_Free(&key);
    wc_FreeRng(&rng);
}

static void bench_lms_sign_verify(enum wc_LmsParm parm, byte* pub)
{
    LmsKey       key;
    int          ret = 0;
    const char * msg = TEST_STRING;
    word32       msgSz = TEST_STRING_SZ;
    byte *       sig = NULL;
    word32       sigSz = 0;
    word32       privLen = 0;
    int          loaded = 0;
    int          times = 0;
    int          count = 0;
    double       start = 0.0F;
    const char * str = wc_LmsKey_ParmToStr(parm);
    DECLARE_MULTI_VALUE_STATS_VARS()

    ret = wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    if (ret) {
        printf("wc_LmsKey_Init failed: %d\n", ret);
        goto exit_lms_sign_verify;
    }

    ret = wc_LmsKey_SetLmsParm(&key, parm);
    if (ret) {
        printf("wc_LmsKey_SetLmsParm failed: %d\n", ret);
        goto exit_lms_sign_verify;
    }

    switch (parm) {
#ifndef WOLFSSL_NO_LMS_SHA256_256
    case WC_LMS_PARM_L2_H10_W2:
        XMEMCPY(lms_priv, lms_priv_L2_H10_W2, sizeof(lms_priv_L2_H10_W2));
        XMEMCPY(key.pub, lms_pub_L2_H10_W2, HSS_MAX_PUBLIC_KEY_LEN);
        break;

    case WC_LMS_PARM_L2_H10_W4:
        XMEMCPY(lms_priv, lms_priv_L2_H10_W4, sizeof(lms_priv_L2_H10_W4));
        XMEMCPY(key.pub, lms_pub_L2_H10_W4, HSS_MAX_PUBLIC_KEY_LEN);
        break;

    case WC_LMS_PARM_L3_H5_W4:
        XMEMCPY(lms_priv, lms_priv_L3_H5_W4, sizeof(lms_priv_L3_H5_W4));
        XMEMCPY(key.pub, lms_pub_L3_H5_W4, HSS_MAX_PUBLIC_KEY_LEN);
        break;

    case WC_LMS_PARM_L3_H5_W8:
        XMEMCPY(lms_priv, lms_priv_L3_H5_W8, sizeof(lms_priv_L3_H5_W8));
        XMEMCPY(key.pub, lms_pub_L3_H5_W8, HSS_MAX_PUBLIC_KEY_LEN);
        break;

    case WC_LMS_PARM_L3_H10_W4:
        XMEMCPY(lms_priv, lms_priv_L3_H10_W4, sizeof(lms_priv_L3_H10_W4));
        XMEMCPY(key.pub, lms_pub_L3_H10_W4, HSS_MAX_PUBLIC_KEY_LEN);
        break;

    case WC_LMS_PARM_L4_H5_W8:
        XMEMCPY(lms_priv, lms_priv_L4_H5_W8, sizeof(lms_priv_L4_H5_W8));
        XMEMCPY(key.pub, lms_pub_L4_H5_W8, HSS_MAX_PUBLIC_KEY_LEN);
        break;

    case WC_LMS_PARM_NONE:
    case WC_LMS_PARM_L1_H15_W2:
    case WC_LMS_PARM_L1_H15_W4:
    case WC_LMS_PARM_L2_H10_W8:
    case WC_LMS_PARM_L3_H5_W2:
    case WC_LMS_PARM_L1_H5_W1:
    case WC_LMS_PARM_L1_H5_W2:
    case WC_LMS_PARM_L1_H5_W4:
    case WC_LMS_PARM_L1_H5_W8:
    case WC_LMS_PARM_L1_H10_W2:
    case WC_LMS_PARM_L1_H10_W4:
    case WC_LMS_PARM_L1_H10_W8:
    case WC_LMS_PARM_L1_H15_W8:
    case WC_LMS_PARM_L1_H20_W2:
    case WC_LMS_PARM_L1_H20_W4:
    case WC_LMS_PARM_L1_H20_W8:
    case WC_LMS_PARM_L2_H5_W2:
    case WC_LMS_PARM_L2_H5_W4:
    case WC_LMS_PARM_L2_H5_W8:
    case WC_LMS_PARM_L2_H15_W2:
    case WC_LMS_PARM_L2_H15_W4:
    case WC_LMS_PARM_L2_H15_W8:
    case WC_LMS_PARM_L2_H20_W2:
    case WC_LMS_PARM_L2_H20_W4:
    case WC_LMS_PARM_L2_H20_W8:
    case WC_LMS_PARM_L3_H10_W8:
    case WC_LMS_PARM_L4_H5_W2:
    case WC_LMS_PARM_L4_H5_W4:
    case WC_LMS_PARM_L4_H10_W4:
    case WC_LMS_PARM_L4_H10_W8:
#endif

#ifdef WOLFSSL_LMS_SHA256_192
    case WC_LMS_PARM_SHA256_192_L1_H5_W1:
    case WC_LMS_PARM_SHA256_192_L1_H5_W2:
    case WC_LMS_PARM_SHA256_192_L1_H5_W4:
    case WC_LMS_PARM_SHA256_192_L1_H5_W8:
    case WC_LMS_PARM_SHA256_192_L1_H10_W2:
    case WC_LMS_PARM_SHA256_192_L1_H10_W4:
    case WC_LMS_PARM_SHA256_192_L1_H10_W8:
    case WC_LMS_PARM_SHA256_192_L1_H15_W2:
    case WC_LMS_PARM_SHA256_192_L1_H15_W4:
    case WC_LMS_PARM_SHA256_192_L2_H10_W2:
    case WC_LMS_PARM_SHA256_192_L2_H10_W4:
    case WC_LMS_PARM_SHA256_192_L2_H10_W8:
    case WC_LMS_PARM_SHA256_192_L3_H5_W2:
    case WC_LMS_PARM_SHA256_192_L3_H5_W4:
    case WC_LMS_PARM_SHA256_192_L3_H5_W8:
    case WC_LMS_PARM_SHA256_192_L3_H10_W4:
    case WC_LMS_PARM_SHA256_192_L4_H5_W8:
#endif

    default:
        XMEMCPY(key.pub, pub, HSS_MAX_PUBLIC_KEY_LEN);
        break;
    }

    ret = wc_LmsKey_SetWriteCb(&key, lms_write_key_mem);
    if (ret) {
        fprintf(stderr, "error: wc_LmsKey_SetWriteCb failed: %d\n", ret);
        goto exit_lms_sign_verify;
    }

    ret = wc_LmsKey_SetReadCb(&key, lms_read_key_mem);
    if (ret) {
        fprintf(stderr, "error: wc_LmsKey_SetReadCb failed: %d\n", ret);
        goto exit_lms_sign_verify;
    }

    ret = wc_LmsKey_SetContext(&key, (void*)lms_priv);
    if (ret) {
        fprintf(stderr, "error: wc_LmsKey_SetContext failed: %d\n", ret);
        goto exit_lms_sign_verify;
    }

    /* Even with saved priv/pub keys, we must still reload the private
     * key before using it. Reloading the private key is the bottleneck
     * for larger heights. Only print load time in debug builds. */
    count = 0;
    bench_stats_start(&count, &start);

#ifndef WOLFSSL_WC_LMS_SMALL
    do {
    #ifdef WOLFSSL_WC_LMS
        key.priv.inited = 0;
        key.state = WC_LMS_STATE_PARMSET;
    #endif
        ret = wc_LmsKey_Reload(&key);
        if (ret) {
            printf("wc_LmsKey_Reload failed: %d\n", ret);
            goto exit_lms_sign_verify;
        }
        RECORD_MULTI_VALUE_STATS();

        count++;

        ret = wc_LmsKey_GetSigLen(&key, &sigSz);
        if (ret) {
            printf("wc_LmsKey_GetSigLen failed: %d\n", ret);
            goto exit_lms_sign_verify;
        }

        ret = wc_LmsKey_GetPrivLen(&key, &privLen);
        if (ret) {
            printf("wc_LmsKey_GetPrivLen failed: %d\n", ret);
            goto exit_lms_sign_verify;
        }
    #ifdef HAVE_LIBLMS
        break;
    #endif
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_asym_finish(str, (int)privLen, "load", 0,
                            count, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    RESET_MULTI_VALUE_STATS_VARS();
#else
    ret = wc_LmsKey_Reload(&key);
    if (ret) {
        printf("wc_LmsKey_Reload failed: %d\n", ret);
        goto exit_lms_sign_verify;
    }
    ret = wc_LmsKey_GetSigLen(&key, &sigSz);
    if (ret) {
        printf("wc_LmsKey_GetSigLen failed: %d\n", ret);
        goto exit_lms_sign_verify;
    }
    ret = wc_LmsKey_GetPrivLen(&key, &privLen);
    if (ret) {
        printf("wc_LmsKey_GetPrivLen failed: %d\n", ret);
        goto exit_lms_sign_verify;
    }
#endif

    loaded = 1;

    sig = (byte *)XMALLOC(sigSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (sig == NULL) {
        printf("bench_lms_sign_verify malloc failed\n");
        goto exit_lms_sign_verify;
    }

    count = 0;
    bench_stats_start(&count, &start);

    do {
        /* LMS is stateful. Async queuing not practical. */
#ifndef WOLFSSL_WC_LMS_SMALL
        for (times = 0; times < ntimes; ++times)
#else
        for (times = 0; times < 1; ++times)
#endif
        {
            ret = wc_LmsKey_Sign(&key, sig, &sigSz, (byte *) msg, msgSz);
            if (ret) {
                printf("wc_LmsKey_Sign failed: %d\n", ret);
                goto exit_lms_sign_verify;
            }
            RECORD_MULTI_VALUE_STATS();
            if (!wc_LmsKey_SigsLeft(&key)) {
                break;
            }
        }

        count += times;
    } while (wc_LmsKey_SigsLeft(&key) && (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       ));

    bench_stats_asym_finish(str, (int)sigSz, "sign", 0,
                            count, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    RESET_MULTI_VALUE_STATS_VARS();
    count = 0;
    bench_stats_start(&count, &start);

    do {
        /* LMS is stateful. Async queuing not practical. */
        for (times = 0; times < ntimes; ++times) {
            ret = wc_LmsKey_Verify(&key, sig, sigSz, (byte *) msg, msgSz);
            if (ret) {
                printf("wc_LmsKey_Verify failed: %d\n", ret);
                goto exit_lms_sign_verify;
            }
            RECORD_MULTI_VALUE_STATS();
        }

        count += times;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

exit_lms_sign_verify:
    bench_stats_asym_finish(str, (int)sigSz, "verify", 0,
                            count, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif


    if (loaded) {
        wc_LmsKey_Free(&key);
    }
    XFREE(sig, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    return;
}

void bench_lms(void)
{
    byte pub[HSS_MAX_PUBLIC_KEY_LEN];

#ifndef WOLFSSL_NO_LMS_SHA256_256
#ifdef BENCH_LMS_SLOW_KEYGEN
#if !defined(WOLFSSL_WC_LMS) || (LMS_MAX_HEIGHT >= 15)
    bench_lms_keygen(WC_LMS_PARM_L1_H15_W2, pub);
    bench_lms_sign_verify(WC_LMS_PARM_L1_H15_W2, pub);
    bench_lms_keygen(WC_LMS_PARM_L1_H15_W4, pub);
    bench_lms_sign_verify(WC_LMS_PARM_L1_H15_W4, pub);
    #undef LMS_PARAMS_BENCHED
    #define LMS_PARAMS_BENCHED
#endif
#endif
#if !defined(WOLFSSL_WC_LMS) || ((LMS_MAX_LEVELS >= 2) && \
        (LMS_MAX_HEIGHT >= 10))
    bench_lms_keygen(WC_LMS_PARM_L2_H10_W2, pub);
    bench_lms_sign_verify(WC_LMS_PARM_L2_H10_W2, pub);
    bench_lms_keygen(WC_LMS_PARM_L2_H10_W4, pub);
    bench_lms_sign_verify(WC_LMS_PARM_L2_H10_W4, pub);
    #undef LMS_PARAMS_BENCHED
    #define LMS_PARAMS_BENCHED
#ifdef BENCH_LMS_SLOW_KEYGEN
    bench_lms_keygen(WC_LMS_PARM_L2_H10_W8, pub);
    bench_lms_sign_verify(WC_LMS_PARM_L2_H10_W8, pub);
#endif
#endif
#if !defined(WOLFSSL_WC_LMS) || (LMS_MAX_LEVELS >= 3)
    bench_lms_keygen(WC_LMS_PARM_L3_H5_W4, pub);
    bench_lms_sign_verify(WC_LMS_PARM_L3_H5_W4, pub);
    bench_lms_keygen(WC_LMS_PARM_L3_H5_W8, pub);
    bench_lms_sign_verify(WC_LMS_PARM_L3_H5_W8, pub);
    #undef LMS_PARAMS_BENCHED
    #define LMS_PARAMS_BENCHED
#endif
#if !defined(WOLFSSL_WC_LMS) || ((LMS_MAX_LEVELS >= 3) && \
        (LMS_MAX_HEIGHT >= 10))
    bench_lms_keygen(WC_LMS_PARM_L3_H10_W4, pub);
    bench_lms_sign_verify(WC_LMS_PARM_L3_H10_W4, pub);
#endif
#if !defined(WOLFSSL_WC_LMS) || (LMS_MAX_LEVELS >= 4)
    bench_lms_keygen(WC_LMS_PARM_L4_H5_W8, pub);
    bench_lms_sign_verify(WC_LMS_PARM_L4_H5_W8, pub);
#endif

#if defined(WOLFSSL_WC_LMS) && !defined(LMS_PARAMS_BENCHED)
    bench_lms_keygen(WC_LMS_PARM_L1_H5_W1, pub);
    bench_lms_sign_verify(WC_LMS_PARM_L1_H5_W1, pub);
#endif
#endif /* !WOLFSSL_NO_LMS_SHA256_256 */

#ifdef WOLFSSL_LMS_SHA256_192
#ifdef BENCH_LMS_SLOW_KEYGEN
#if !defined(WOLFSSL_WC_LMS) || (LMS_MAX_HEIGHT >= 15)
    bench_lms_keygen(WC_LMS_PARM_SHA256_192_L1_H15_W2, pub);
    bench_lms_sign_verify(WC_LMS_PARM_SHA256_192_L1_H15_W2, pub);
    bench_lms_keygen(WC_LMS_PARM_SHA256_192_L1_H15_W4, pub);
    bench_lms_sign_verify(WC_LMS_PARM_SHA256_192_L1_H15_W4, pub);
    #undef LMS_PARAMS_BENCHED
    #define LMS_PARAMS_BENCHED
#endif
#endif
#if !defined(WOLFSSL_WC_LMS) || ((LMS_MAX_LEVELS >= 2) && \
        (LMS_MAX_HEIGHT >= 10))
    bench_lms_keygen(WC_LMS_PARM_SHA256_192_L2_H10_W2, pub);
    bench_lms_sign_verify(WC_LMS_PARM_SHA256_192_L2_H10_W2, pub);
    bench_lms_keygen(WC_LMS_PARM_SHA256_192_L2_H10_W4, pub);
    bench_lms_sign_verify(WC_LMS_PARM_SHA256_192_L2_H10_W4, pub);
    #undef LMS_PARAMS_BENCHED
    #define LMS_PARAMS_BENCHED
#ifdef BENCH_LMS_SLOW_KEYGEN
    bench_lms_keygen(WC_LMS_PARM_SHA256_192_L2_H10_W8, pub);
    bench_lms_sign_verify(WC_LMS_PARM_SHA256_192_L2_H10_W8, pub);
#endif
#endif
#if !defined(WOLFSSL_WC_LMS) || (LMS_MAX_LEVELS >= 3)
    bench_lms_keygen(WC_LMS_PARM_SHA256_192_L3_H5_W4, pub);
    bench_lms_sign_verify(WC_LMS_PARM_SHA256_192_L3_H5_W4, pub);
    bench_lms_keygen(WC_LMS_PARM_SHA256_192_L3_H5_W8, pub);
    bench_lms_sign_verify(WC_LMS_PARM_SHA256_192_L3_H5_W8, pub);
    #undef LMS_PARAMS_BENCHED
    #define LMS_PARAMS_BENCHED
#endif
#if !defined(WOLFSSL_WC_LMS) || ((LMS_MAX_LEVELS >= 3) && \
        (LMS_MAX_HEIGHT >= 10))
    bench_lms_keygen(WC_LMS_PARM_SHA256_192_L3_H10_W4, pub);
    bench_lms_sign_verify(WC_LMS_PARM_SHA256_192_L3_H10_W4, pub);
#endif
#if !defined(WOLFSSL_WC_LMS) || (LMS_MAX_LEVELS >= 4)
    bench_lms_keygen(WC_LMS_PARM_SHA256_192_L4_H5_W8, pub);
    bench_lms_sign_verify(WC_LMS_PARM_SHA256_192_L4_H5_W8, pub);
#endif

#if defined(WOLFSSL_WC_LMS) && !defined(LMS_PARAMS_BENCHED)
    bench_lms_keygen(WC_LMS_PARM_SHA256_192_L1_H5_W1, pub);
    bench_lms_sign_verify(WC_LMS_PARM_SHA256_192_L1_H5_W1, pub);
#endif
#endif /* WOLFSSL_LMS_SHA256_192 */

    return;
}

#endif /* if defined(WOLFSSL_HAVE_LMS) && !defined(WOLFSSL_LMS_VERIFY_ONLY) */

#if defined(WOLFSSL_HAVE_XMSS) && !defined(WOLFSSL_XMSS_VERIFY_ONLY)

static enum wc_XmssRc xmss_write_key_mem(const byte * priv, word32 privSz,
    void *context)
{
   /* WARNING: THIS IS AN INSECURE WRITE CALLBACK THAT SHOULD ONLY
    * BE USED FOR TESTING PURPOSES! Production applications should
    * write only to non-volatile storage. */
    XMEMCPY(context, priv, privSz);
    return WC_XMSS_RC_SAVED_TO_NV_MEMORY;
}

static enum wc_XmssRc xmss_read_key_mem(byte * priv, word32 privSz,
    void *context)
{
   /* WARNING: THIS IS AN INSECURE READ CALLBACK THAT SHOULD ONLY
    * BE USED FOR TESTING PURPOSES! */
    XMEMCPY(priv, context, privSz);
    return WC_XMSS_RC_READ_TO_MEMORY;
}

static void bench_xmss_sign_verify(const char * params)
{
    WC_RNG          rng;
    XmssKey         key;
    word32          pkSz = 0;
    word32          skSz = 0;
    int             freeRng = 0;
    int             freeKey = 0;
    unsigned char * sk = NULL;
    const char *    msg = "XMSS post quantum signature test";
    word32          msgSz = (word32) XSTRLEN(msg);
    int             ret = 0;
    byte *          sig = NULL;
    word32          sigSz = 0;
    int             times = 0;
    int             count = 0;
    double          start = 0.0F;

#ifndef HAVE_FIPS
    ret = wc_InitRng_ex(&rng, HEAP_HINT, INVALID_DEVID);
#else
    ret = wc_InitRng(&rng);
#endif
    if (ret != 0) {
        fprintf(stderr, "error: wc_InitRng failed: %d\n", ret);
        goto exit_xmss_sign_verify;
    }

    freeRng = 1;

    ret = wc_XmssKey_Init(&key, NULL, INVALID_DEVID);
    if (ret != 0) {
        fprintf(stderr, "wc_XmssKey_Init failed: %d\n", ret);
        goto exit_xmss_sign_verify;
    }

    ret = wc_XmssKey_SetParamStr(&key, params);
    if (ret != 0) {
        fprintf(stderr, "wc_XmssKey_SetParamStr failed: %d\n", ret);
        goto exit_xmss_sign_verify;
    }

    ret = wc_XmssKey_GetPubLen(&key, &pkSz);
    if (ret != 0) {
        fprintf(stderr, "wc_XmssKey_GetPubLen failed: %d\n", ret);
        goto exit_xmss_sign_verify;
    }
#ifndef WOLFSSL_WC_XMSS
    if (pkSz != XMSS_SHA256_PUBLEN) {
        fprintf(stderr, "error: xmss pub len: got %u, expected %d\n", pkSz,
                XMSS_SHA256_PUBLEN);
        goto exit_xmss_sign_verify;
    }
#endif

    ret = wc_XmssKey_GetPrivLen(&key, &skSz);
    if (ret != 0 || skSz <= 0) {
        fprintf(stderr, "error: wc_XmssKey_GetPrivLen failed\n");
        goto exit_xmss_sign_verify;
    }

    ret = wc_XmssKey_GetSigLen(&key, &sigSz);
    if (ret != 0 || sigSz <= 0) {
        fprintf(stderr, "error: wc_XmssKey_GetSigLen failed\n");
        goto exit_xmss_sign_verify;
    }

    /* Allocate secret keys.*/
    sk = (unsigned char *)XMALLOC(skSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (sk == NULL) {
        fprintf(stderr, "error: allocate xmss sk failed\n");
        goto exit_xmss_sign_verify;
    }

    /* Allocate signature array. */
    sig = (byte *)XMALLOC(sigSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (sig == NULL) {
        fprintf(stderr, "error: allocate xmss sig failed\n");
        goto exit_xmss_sign_verify;
    }

    ret = wc_XmssKey_SetWriteCb(&key, xmss_write_key_mem);
    if (ret != 0) {
        fprintf(stderr, "error: wc_XmssKey_SetWriteCb failed: %d\n", ret);
        goto exit_xmss_sign_verify;
    }

    ret = wc_XmssKey_SetReadCb(&key, xmss_read_key_mem);
    if (ret != 0) {
        fprintf(stderr, "error: wc_XmssKey_SetReadCb failed: %d\n", ret);
        goto exit_xmss_sign_verify;
    }

    ret = wc_XmssKey_SetContext(&key, (void *)sk);
    if (ret != 0) {
        fprintf(stderr, "error: wc_XmssKey_SetContext failed: %d\n", ret);
        goto exit_xmss_sign_verify;
    }

#if defined(DEBUG_WOLFSSL) || defined(WOLFSSL_DEBUG_NONBLOCK)
    fprintf(stderr, "params: %s\n", params);
    fprintf(stderr, "pkSz:   %d\n", pkSz);
    fprintf(stderr, "skSz:   %d\n", skSz);
    fprintf(stderr, "sigSz:  %d\n", sigSz);
#endif

    /* Making the private key is the bottleneck for larger heights. */
    count = 0;
    bench_stats_start(&count, &start);

    ret = wc_XmssKey_MakeKey(&key, &rng);
    if (ret != 0) {
        printf("wc_XmssKey_MakeKey failed: %d\n", ret);
        goto exit_xmss_sign_verify;
    }
    /* Can only do one at a time - state changes after make key. */

    count +=1;

    bench_stats_check(start);
    bench_stats_asym_finish(params, (int)skSz, "gen", 0, count, start, ret);

    freeKey = 1;

    count = 0;
    bench_stats_start(&count, &start);

    do {
        /* XMSS is stateful. Async queuing not practical. */
#ifndef WOLFSSL_WC_XMSS_SMALL
        for (times = 0; times < ntimes; ++times)
#else
        for (times = 0; times < 1; ++times)
#endif
        {
            if (!wc_XmssKey_SigsLeft(&key))
                break;
            ret = wc_XmssKey_Sign(&key, sig, &sigSz, (byte *) msg, msgSz);
            if (ret) {
                printf("wc_XmssKey_Sign failed: %d\n", ret);
                goto exit_xmss_sign_verify;
            }
        }
        count += times;
    } while (wc_XmssKey_SigsLeft(&key) && bench_stats_check(start));

    bench_stats_asym_finish(params, (int)sigSz, "sign", 0, count, start, ret);

    count = 0;
    bench_stats_start(&count, &start);

    do {
        /* XMSS is stateful. Async queuing not practical. */
        for (times = 0; times < ntimes; ++times) {
            ret = wc_XmssKey_Verify(&key, sig, sigSz, (byte *) msg, msgSz);
            if (ret) {
                printf("wc_XmssKey_Verify failed: %d\n", ret);
                goto exit_xmss_sign_verify;
            }
        }
        count += times;
    } while (bench_stats_check(start));

exit_xmss_sign_verify:
    bench_stats_asym_finish(params, (int)sigSz, "verify", 0, count, start, ret);

    /* Cleanup everything. */
    XFREE(sig, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    sig = NULL;

    XFREE(sk, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    sk = NULL;

    if (freeRng) {
        wc_FreeRng(&rng);
    }

    if (freeKey) {
        wc_XmssKey_Free(&key);
    }

    return;
}

void bench_xmss(int hash)
{
    /* All NIST SP 800-208 approved SHA256 XMSS/XMSS^MT parameter
     * sets.
     *
     * Note: not testing "XMSS-SHA2_16_256", "XMSS-SHA2_20_256",
     * and "XMSSMT-SHA2_60/3_256", because their keygen can be
     * very slow, their signatures and private keys quite large,
     * and xmss private keys are not portable across different
     * XMSS/XMSS^MT implementations.
     *
     * The bottleneck in key generation is the height of the first
     * level tree (or h/d).
     *
     * h is the total height of the hyper tree, and d the number of
     * trees.
     */
                                                            /* h/d    h   d */
#ifdef WC_XMSS_SHA256
    if (hash == WC_HASH_TYPE_SHA256) {
#if WOLFSSL_WC_XMSS_MIN_HASH_SIZE <= 256 && WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 256
#if WOLFSSL_XMSS_MIN_HEIGHT <= 10 && WOLFSSL_XMSS_MAX_HEIGHT >= 10
        bench_xmss_sign_verify("XMSS-SHA2_10_256");         /*  10   10   1 */
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 16 && WOLFSSL_XMSS_MAX_HEIGHT >= 16
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSS-SHA2_16_256");         /*  16   16   1 */
#endif
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 20 && WOLFSSL_XMSS_MAX_HEIGHT >= 20
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSS-SHA2_20_256");         /*  20   20   1 */
#endif
#endif
#endif /* HASH_SIZE 256 */
#if WOLFSSL_WC_XMSS_MIN_HASH_SIZE <= 192 && WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 192
#if WOLFSSL_XMSS_MIN_HEIGHT <= 10 && WOLFSSL_XMSS_MAX_HEIGHT >= 10
        bench_xmss_sign_verify("XMSS-SHA2_10_192");         /*  10   10   1 */
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 16 && WOLFSSL_XMSS_MAX_HEIGHT >= 16
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSS-SHA2_16_192");         /*  16   16   1 */
#endif
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 20 && WOLFSSL_XMSS_MAX_HEIGHT >= 20
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSS-SHA2_20_192");         /*  20   20   1 */
#endif
#endif
#endif /* HASH_SIZE 192 */
#if WOLFSSL_WC_XMSS_MIN_HASH_SIZE <= 256 && WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 256
#if WOLFSSL_XMSS_MIN_HEIGHT <= 20 && WOLFSSL_XMSS_MAX_HEIGHT >= 20
        bench_xmss_sign_verify("XMSSMT-SHA2_20/2_256");     /*  10   20   2 */
        bench_xmss_sign_verify("XMSSMT-SHA2_20/4_256");     /*   5   20   4 */
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 40 && WOLFSSL_XMSS_MAX_HEIGHT >= 40
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSSMT-SHA2_40/2_256");     /*  20   40   4 */
#endif
        bench_xmss_sign_verify("XMSSMT-SHA2_40/4_256");     /*  10   40   4 */
        bench_xmss_sign_verify("XMSSMT-SHA2_40/8_256");     /*   5   40   8 */
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 60 && WOLFSSL_XMSS_MAX_HEIGHT >= 60
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSSMT-SHA2_60/3_256");     /*  20   60   3 */
#endif
        bench_xmss_sign_verify("XMSSMT-SHA2_60/6_256");     /*  10   60   6 */
        bench_xmss_sign_verify("XMSSMT-SHA2_60/12_256");    /*   5   60  12 */
#endif
#endif /* HASH_SIZE 256 */
#if WOLFSSL_WC_XMSS_MIN_HASH_SIZE <= 192 && WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 192
#if WOLFSSL_XMSS_MIN_HEIGHT <= 20 && WOLFSSL_XMSS_MAX_HEIGHT >= 20
        bench_xmss_sign_verify("XMSSMT-SHA2_20/2_192");     /*  10   20   2 */
        bench_xmss_sign_verify("XMSSMT-SHA2_20/4_192");     /*   5   20   4 */
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 40 && WOLFSSL_XMSS_MAX_HEIGHT >= 40
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSSMT-SHA2_40/2_192");     /*  20   40   4 */
#endif
        bench_xmss_sign_verify("XMSSMT-SHA2_40/4_192");     /*  10   40   4 */
        bench_xmss_sign_verify("XMSSMT-SHA2_40/8_192");     /*   5   40   8 */
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 60 && WOLFSSL_XMSS_MAX_HEIGHT >= 60
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSSMT-SHA2_60/3_192");     /*  20   60   3 */
#endif
        bench_xmss_sign_verify("XMSSMT-SHA2_60/6_192");     /*  10   60   6 */
        bench_xmss_sign_verify("XMSSMT-SHA2_60/12_192");    /*   5   60  12 */
#endif
#endif /* HASH_SIZE 192 */
    }
#endif
#ifdef WC_XMSS_SHA512
#if WOLFSSL_WC_XMSS_MIN_HASH_SIZE <= 512 && WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 512
    if (hash == WC_HASH_TYPE_SHA512) {
#if WOLFSSL_XMSS_MIN_HEIGHT <= 10 && WOLFSSL_XMSS_MAX_HEIGHT >= 10
        bench_xmss_sign_verify("XMSS-SHA2_10_512");         /*  10   10   1 */
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 16 && WOLFSSL_XMSS_MAX_HEIGHT >= 16
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSS-SHA2_16_512");         /*  16   16   1 */
#endif
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 20 && WOLFSSL_XMSS_MAX_HEIGHT >= 20
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSS-SHA2_20_512");         /*  20   20   1 */
#endif
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 20 && WOLFSSL_XMSS_MAX_HEIGHT >= 20
        bench_xmss_sign_verify("XMSSMT-SHA2_20/2_512");     /*  10   20   2 */
        bench_xmss_sign_verify("XMSSMT-SHA2_20/4_512");     /*   5   20   4 */
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 40 && WOLFSSL_XMSS_MAX_HEIGHT >= 40
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSSMT-SHA2_40/2_512");     /*  20   40   4 */
#endif
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSSMT-SHA2_40/4_512");     /*  10   40   4 */
#endif
        bench_xmss_sign_verify("XMSSMT-SHA2_40/8_512");     /*   5   40   8 */
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 60 && WOLFSSL_XMSS_MAX_HEIGHT >= 60
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSSMT-SHA2_60/3_512");     /*  20   60   3 */
#endif
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSSMT-SHA2_60/6_512");     /*  10   60   6 */
#endif
        bench_xmss_sign_verify("XMSSMT-SHA2_60/12_512");    /*   5   60  12 */
#endif
    }
#endif /* HASH_SIZE 512 */
#endif
#ifdef WC_XMSS_SHAKE128
#if WOLFSSL_WC_XMSS_MIN_HASH_SIZE <= 256 && WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 256
    if (hash == WC_HASH_TYPE_SHAKE128) {
#if WOLFSSL_XMSS_MIN_HEIGHT <= 10 && WOLFSSL_XMSS_MAX_HEIGHT >= 10
        bench_xmss_sign_verify("XMSS-SHAKE_10_256");        /*  10   10   1 */
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 16 && WOLFSSL_XMSS_MAX_HEIGHT >= 16
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSS-SHAKE_16_256");        /*  16   16   1 */
#endif
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 20 && WOLFSSL_XMSS_MAX_HEIGHT >= 20
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSS-SHAKE_20_256");        /*  20   20   1 */
#endif
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 20 && WOLFSSL_XMSS_MAX_HEIGHT >= 20
        bench_xmss_sign_verify("XMSSMT-SHAKE_20/2_256");    /*  10   20   2 */
        bench_xmss_sign_verify("XMSSMT-SHAKE_20/4_256");    /*   5   20   4 */
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 40 && WOLFSSL_XMSS_MAX_HEIGHT >= 40
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSSMT-SHAKE_40/2_256");    /*  20   40   4 */
#endif
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSSMT-SHAKE_40/4_256");    /*  10   40   4 */
#endif
        bench_xmss_sign_verify("XMSSMT-SHAKE_40/8_256");    /*   5   40   8 */
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 60 && WOLFSSL_XMSS_MAX_HEIGHT >= 60
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSSMT-SHAKE_60/3_256");    /*  20   60   3 */
#endif
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSSMT-SHAKE_60/6_256");    /*  10   60   6 */
#endif
        bench_xmss_sign_verify("XMSSMT-SHAKE_60/12_256");   /*   5   60  12 */
#endif
    }
#endif /* HASH_SIZE 256 */
#endif
#ifdef WC_XMSS_SHAKE256
    if (hash == WC_HASH_TYPE_SHAKE256) {
#if WOLFSSL_WC_XMSS_MIN_HASH_SIZE <= 512 && WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 512
#if WOLFSSL_XMSS_MIN_HEIGHT <= 10 && WOLFSSL_XMSS_MAX_HEIGHT >= 10
        bench_xmss_sign_verify("XMSS-SHAKE_10_512");        /*  10   10   1 */
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 16 && WOLFSSL_XMSS_MAX_HEIGHT >= 16
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSS-SHAKE_16_512");        /*  16   16   1 */
#endif
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 20 && WOLFSSL_XMSS_MAX_HEIGHT >= 20
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSS-SHAKE_20_512");        /*  20   20   1 */
#endif
#endif
#endif /* HASH_SIZE 512 */
#if WOLFSSL_WC_XMSS_MIN_HASH_SIZE <= 256 && WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 256
#if WOLFSSL_XMSS_MIN_HEIGHT <= 10 && WOLFSSL_XMSS_MAX_HEIGHT >= 10
        bench_xmss_sign_verify("XMSS-SHAKE256_10_256");     /*  10   10   1 */
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 16 && WOLFSSL_XMSS_MAX_HEIGHT >= 16
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSS-SHAKE256_16_256");     /*  16   16   1 */
#endif
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 20 && WOLFSSL_XMSS_MAX_HEIGHT >= 20
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSS-SHAKE256_20_256");     /*  20   20   1 */
#endif
#endif
#endif /* HASH_SIZE 256 */
#if WOLFSSL_WC_XMSS_MIN_HASH_SIZE <= 192 && WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 192
#if WOLFSSL_XMSS_MIN_HEIGHT <= 10 && WOLFSSL_XMSS_MAX_HEIGHT >= 10
        bench_xmss_sign_verify("XMSS-SHAKE256_10_192");     /*  10   10   1 */
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 16 && WOLFSSL_XMSS_MAX_HEIGHT >= 16
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSS-SHAKE256_16_192");     /*  16   16   1 */
#endif
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 20 && WOLFSSL_XMSS_MAX_HEIGHT >= 20
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSS-SHAKE256_20_192");     /*  20   20   1 */
#endif
#endif
#endif /* HASH_SIZE 192 */
#if WOLFSSL_WC_XMSS_MIN_HASH_SIZE <= 512 && WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 512
#if WOLFSSL_XMSS_MIN_HEIGHT <= 20 && WOLFSSL_XMSS_MAX_HEIGHT >= 20
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSSMT-SHAKE_20/2_512");    /*  10   20   2 */
#endif
        bench_xmss_sign_verify("XMSSMT-SHAKE_20/4_512");    /*   5   20   4 */
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 40 && WOLFSSL_XMSS_MAX_HEIGHT >= 40
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSSMT-SHAKE_40/2_512");    /*  20   40   4 */
#endif
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSSMT-SHAKE_40/4_512");    /*  10   40   4 */
#endif
        bench_xmss_sign_verify("XMSSMT-SHAKE_40/8_512");    /*   5   40   8 */
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 60 && WOLFSSL_XMSS_MAX_HEIGHT >= 60
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSSMT-SHAKE_60/3_512");    /*  20   60   3 */
#endif
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSSMT-SHAKE_60/6_512");    /*  10   60   6 */
#endif
        bench_xmss_sign_verify("XMSSMT-SHAKE_60/12_512");   /*   5   60  12 */
#endif
#endif /* HASH_SIZE 512 */
#if WOLFSSL_WC_XMSS_MIN_HASH_SIZE <= 256 && WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 256
#if WOLFSSL_XMSS_MIN_HEIGHT <= 20 && WOLFSSL_XMSS_MAX_HEIGHT >= 20
        bench_xmss_sign_verify("XMSSMT-SHAKE256_20/2_256"); /*  10   20   2 */
        bench_xmss_sign_verify("XMSSMT-SHAKE256_20/4_256"); /*   5   20   4 */
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 40 && WOLFSSL_XMSS_MAX_HEIGHT >= 40
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSSMT-SHAKE256_40/2_256"); /*  20   40   4 */
#endif
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSSMT-SHAKE256_40/4_256"); /*  10   40   4 */
#endif
        bench_xmss_sign_verify("XMSSMT-SHAKE256_40/8_256"); /*   5   40   8 */
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 60 && WOLFSSL_XMSS_MAX_HEIGHT >= 60
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSSMT-SHAKE256_60/3_256"); /*  20   60   3 */
#endif
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSSMT-SHAKE256_60/6_256"); /*  10   60   6 */
#endif
        bench_xmss_sign_verify("XMSSMT-SHAKE256_60/12_256");/*   5   60  12 */
#endif
#endif /* HASH_SIZE 256 */
#if WOLFSSL_WC_XMSS_MIN_HASH_SIZE <= 192 && WOLFSSL_WC_XMSS_MAX_HASH_SIZE >= 192
#if WOLFSSL_XMSS_MIN_HEIGHT <= 20 && WOLFSSL_XMSS_MAX_HEIGHT >= 20
        bench_xmss_sign_verify("XMSSMT-SHAKE256_20/2_192"); /*  10   20   2 */
        bench_xmss_sign_verify("XMSSMT-SHAKE256_20/4_192"); /*   5   20   4 */
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 40 && WOLFSSL_XMSS_MAX_HEIGHT >= 40
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSSMT-SHAKE256_40/2_192"); /*  20   40   4 */
#endif
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSSMT-SHAKE256_40/4_192"); /*  10   40   4 */
#endif
        bench_xmss_sign_verify("XMSSMT-SHAKE256_40/8_192"); /*   5   40   8 */
#endif
#if WOLFSSL_XMSS_MIN_HEIGHT <= 60 && WOLFSSL_XMSS_MAX_HEIGHT >= 60
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSSMT-SHAKE256_60/3_192"); /*  20   60   3 */
#endif
#ifdef BENCH_XMSS_SLOW_KEYGEN
        bench_xmss_sign_verify("XMSSMT-SHAKE256_60/6_192"); /*  10   60   6 */
#endif
        bench_xmss_sign_verify("XMSSMT-SHAKE256_60/12_192");/*   5   60  12 */
#endif
#endif /* HASH_SIZE 192 */
    }
#endif
    return;
}
#endif /* if defined(WOLFSSL_HAVE_XMSS) && !defined(WOLFSSL_XMSS_VERIFY_ONLY) */

#ifdef HAVE_ECC

/* Maximum ECC name plus null terminator:
 * "ECC   [%15s]" and "ECDHE [%15s]" and "ECDSA [%15s]" */
#define BENCH_ECC_NAME_SZ (ECC_MAXNAME + 8)

/* run all benchmarks on a curve */
void bench_ecc_curve(int curveId)
{
    if (bench_all || (bench_asym_algs & BENCH_ECC_MAKEKEY)) {
    #ifndef NO_SW_BENCH
        bench_eccMakeKey(0, curveId);
    #endif
    #if defined(BENCH_DEVID)
        bench_eccMakeKey(1, curveId);
    #endif
    }
    if (bench_all || (bench_asym_algs & BENCH_ECC)) {
    #ifndef NO_SW_BENCH
        bench_ecc(0, curveId);
    #endif
    #if defined(BENCH_DEVID)
        bench_ecc(1, curveId);
    #endif
    }
    #ifdef HAVE_ECC_ENCRYPT
    if (bench_all || (bench_asym_algs & BENCH_ECC_ENCRYPT))
        bench_eccEncrypt(curveId);
    #endif
}


void bench_eccMakeKey(int useDeviceID, int curveId)
{
    int ret = 0, i, times, count = 0, pending = 0;
    int deviceID;
    int keySize = 0;
    WC_DECLARE_ARRAY(genKey, ecc_key, BENCH_MAX_PENDING,
                     sizeof(ecc_key), HEAP_HINT);
    char name[BENCH_ECC_NAME_SZ];
    double start = 0;
    const char**desc = bench_desc_words[lng_index];
    DECLARE_MULTI_VALUE_STATS_VARS()

    WC_CALLOC_ARRAY(genKey, ecc_key, BENCH_MAX_PENDING,
                     sizeof(ecc_key), HEAP_HINT);

    deviceID = useDeviceID ? devId : INVALID_DEVID;
    keySize = wc_ecc_get_curve_size_from_id(curveId);

    /* ECC Make Key */
    bench_stats_start(&count, &start);
    do {
        /* while free pending slots in queue, submit ops */
        for (times = 0; times < agreeTimes || pending > 0; ) {
            bench_async_poll(&pending);

            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret,
                                      BENCH_ASYNC_GET_DEV(genKey[i]), 0,
                                      &times, agreeTimes, &pending)) {

                    wc_ecc_free(genKey[i]);
                    ret = wc_ecc_init_ex(genKey[i], HEAP_HINT, deviceID);
                    if (ret < 0) {
                        goto exit;
                    }

                    ret = wc_ecc_make_key_ex(&gRng, keySize, genKey[i],
                            curveId);
                    if (!bench_async_handle(&ret,
                                BENCH_ASYNC_GET_DEV(genKey[i]), 0, &times,
                                &pending)) {
                        goto exit;
                    }
                }
            } /* for i */
            RECORD_MULTI_VALUE_STATS();
        } /* for times */
        count += times;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

exit:
    (void)XSNPRINTF(name, BENCH_ECC_NAME_SZ, "ECC   [%15s]",
            wc_ecc_get_name(curveId));
    bench_stats_asym_finish(name, keySize * 8, desc[2],
                            useDeviceID, count, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    /* cleanup */
    if (WC_ARRAY_OK(genKey)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            wc_ecc_free(genKey[i]);
        }
        WC_FREE_ARRAY(genKey, BENCH_MAX_PENDING, HEAP_HINT);
    }
}


void bench_ecc(int useDeviceID, int curveId)
{
    int ret = 0, i, times, count, pending = 0;
    int deviceID;
    int  keySize;
    char name[BENCH_ECC_NAME_SZ];
    WC_DECLARE_ARRAY(genKey, ecc_key, BENCH_MAX_PENDING,
                     sizeof(ecc_key), HEAP_HINT);
#ifdef HAVE_ECC_DHE
    WC_DECLARE_ARRAY(genKey2, ecc_key, BENCH_MAX_PENDING,
                     sizeof(ecc_key), HEAP_HINT);
#endif

#if !defined(NO_ASN) && defined(HAVE_ECC_SIGN)
    #ifdef HAVE_ECC_VERIFY
        int verify[BENCH_MAX_PENDING];
    #endif
#endif

    word32 x[BENCH_MAX_PENDING];
    double start = 0;
    const char**desc = bench_desc_words[lng_index];
    DECLARE_MULTI_VALUE_STATS_VARS()

#ifdef HAVE_ECC_DHE
    WC_DECLARE_ARRAY(shared, byte,
                     BENCH_MAX_PENDING, MAX_ECC_BYTES, HEAP_HINT);
#endif

#if !defined(NO_ASN) && defined(HAVE_ECC_SIGN)
    WC_DECLARE_ARRAY(sig, byte,
                     BENCH_MAX_PENDING, ECC_MAX_SIG_SIZE, HEAP_HINT);
    WC_DECLARE_ARRAY(digest, byte,
                     BENCH_MAX_PENDING, MAX_ECC_BYTES, HEAP_HINT);
#endif

#if !defined(NO_ASN) && defined(HAVE_ECC_SIGN)
    /* old scan-build misfires -Wmaybe-uninitialized on these. */
    XMEMSET(sig, 0, sizeof(sig));
    XMEMSET(digest, 0, sizeof(digest));
#endif

#ifdef HAVE_ECC_DHE
    XMEMSET(shared, 0, sizeof(shared));
#endif
    WC_CALLOC_ARRAY(genKey, ecc_key, BENCH_MAX_PENDING,
                     sizeof(ecc_key), HEAP_HINT);

#ifdef HAVE_ECC_DHE
    WC_CALLOC_ARRAY(genKey2, ecc_key, BENCH_MAX_PENDING,
                     sizeof(ecc_key), HEAP_HINT);
    WC_ALLOC_ARRAY(shared, byte,
                  BENCH_MAX_PENDING, MAX_ECC_BYTES, HEAP_HINT);
#endif

#if !defined(NO_ASN) && defined(HAVE_ECC_SIGN)
    WC_ALLOC_ARRAY(sig, byte, BENCH_MAX_PENDING, ECC_MAX_SIG_SIZE, HEAP_HINT);
    WC_ALLOC_ARRAY(digest, byte, BENCH_MAX_PENDING, MAX_ECC_BYTES, HEAP_HINT);
#endif
    deviceID = useDeviceID ? devId : INVALID_DEVID;

    keySize = wc_ecc_get_curve_size_from_id(curveId);

    /* init keys */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        /* setup an context for each key */
        if ((ret = wc_ecc_init_ex(genKey[i], HEAP_HINT, deviceID)) < 0) {
            goto exit;
        }
        ret = wc_ecc_make_key_ex(&gRng, keySize, genKey[i], curveId);
    #ifdef WOLFSSL_ASYNC_CRYPT
        ret = wc_AsyncWait(ret, &genKey[i]->asyncDev, WC_ASYNC_FLAG_NONE);
    #endif
        if (ret < 0) {
            goto exit;
        }

    #ifdef HAVE_ECC_DHE
        if ((ret = wc_ecc_init_ex(genKey2[i], HEAP_HINT, deviceID)) < 0) {
            goto exit;
        }
        if ((ret = wc_ecc_make_key_ex(&gRng, keySize, genKey2[i],
                    curveId)) > 0) {
            goto exit;
        }
    #endif
    }

#ifdef HAVE_ECC_DHE
#if defined(ECC_TIMING_RESISTANT) && (!defined(HAVE_FIPS) || \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION != 2))) && \
    !defined(HAVE_SELFTEST)
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        (void)wc_ecc_set_rng(genKey[i], &gRng);
    }
#endif

    /* ECC Shared Secret */
    bench_stats_start(&count, &start);
    PRIVATE_KEY_UNLOCK();
    do {
        for (times = 0; times < agreeTimes || pending > 0; ) {
            bench_async_poll(&pending);

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(genKey[i]), 1,
                                      &times, agreeTimes, &pending)) {
                    x[i] = (word32)keySize;
                    ret = wc_ecc_shared_secret(genKey[i], genKey2[i],
                            shared[i], &x[i]);
                    if (!bench_async_handle(&ret,
                                BENCH_ASYNC_GET_DEV(genKey[i]), 1, &times,
                                &pending)) {
                        goto exit_ecdhe;
                    }
                }
            } /* for i */
            RECORD_MULTI_VALUE_STATS();
        } /* for times */
        count += times;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    PRIVATE_KEY_UNLOCK();
exit_ecdhe:
    (void)XSNPRINTF(name, BENCH_ECC_NAME_SZ, "ECDHE [%15s]",
                    wc_ecc_get_name(curveId));

    bench_stats_asym_finish(name, keySize * 8, desc[3],
                            useDeviceID, count, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    RESET_MULTI_VALUE_STATS_VARS();

    if (ret < 0) {
        goto exit;
    }

#endif /* HAVE_ECC_DHE */

#if !defined(NO_ASN) && defined(HAVE_ECC_SIGN)

    /* Init digest to sign */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        for (count = 0; count < keySize; count++) {
            digest[i][count] = (byte)count;
        }
    }

    /* ECC Sign */
    bench_stats_start(&count, &start);
    do {
        for (times = 0; times < agreeTimes || pending > 0; ) {
            bench_async_poll(&pending);

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(genKey[i]), 1,
                                      &times, agreeTimes, &pending)) {

                    if (genKey[i]->state == 0) {
                        x[i] = ECC_MAX_SIG_SIZE;
                    }

                    ret = wc_ecc_sign_hash(digest[i], (word32)keySize, sig[i],
                                           &x[i], GLOBAL_RNG, genKey[i]);

                    if (!bench_async_handle(&ret,
                                BENCH_ASYNC_GET_DEV(genKey[i]), 1, &times,
                                &pending)) {
                        goto exit_ecdsa_sign;
                    }
                } /* bench_async_check */
            } /* for i */
            RECORD_MULTI_VALUE_STATS();
        } /* for times */
        count += times;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

exit_ecdsa_sign:
    (void)XSNPRINTF(name, BENCH_ECC_NAME_SZ, "ECDSA [%15s]",
                    wc_ecc_get_name(curveId));

    bench_stats_asym_finish(name, keySize * 8, desc[4],
                            useDeviceID, count, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    RESET_MULTI_VALUE_STATS_VARS();

    if (ret < 0) {
        goto exit;
    }

#ifdef HAVE_ECC_VERIFY

    /* ECC Verify */
    bench_stats_start(&count, &start);
    do {
        for (times = 0; times < agreeTimes || pending > 0; ) {
            bench_async_poll(&pending);

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(genKey[i]), 1,
                                      &times, agreeTimes, &pending)) {
                    if (genKey[i]->state == 0) {
                        verify[i] = 0;
                    }

                    ret = wc_ecc_verify_hash(sig[i], x[i], digest[i],
                                             (word32)keySize, &verify[i],
                                             genKey[i]);

                    if (!bench_async_handle(&ret,
                                            BENCH_ASYNC_GET_DEV(genKey[i]),
                                                                1, &times,
                                                                &pending)) {
                        goto exit_ecdsa_verify;
                    }
                } /* if bench_async_check */
            } /* for i */
            RECORD_MULTI_VALUE_STATS();
        } /* for times */
        count += times;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

exit_ecdsa_verify:
    (void)XSNPRINTF(name, BENCH_ECC_NAME_SZ, "ECDSA [%15s]",
                    wc_ecc_get_name(curveId));

    bench_stats_asym_finish(name, keySize * 8, desc[5],
                            useDeviceID, count, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif
#endif /* HAVE_ECC_VERIFY */
#endif /* !NO_ASN && HAVE_ECC_SIGN */

exit:

    /* cleanup */
    if (WC_ARRAY_OK(genKey)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++)
            wc_ecc_free(genKey[i]);
        WC_FREE_ARRAY(genKey, BENCH_MAX_PENDING, HEAP_HINT);
    }
    #ifdef HAVE_ECC_DHE
    if (WC_ARRAY_OK(genKey2)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++)
            wc_ecc_free(genKey2[i]);
        WC_FREE_ARRAY(genKey2, BENCH_MAX_PENDING, HEAP_HINT);
    }
    #endif

#ifdef HAVE_ECC_DHE
    WC_FREE_ARRAY(shared, BENCH_MAX_PENDING, HEAP_HINT);
#endif
#if !defined(NO_ASN) && defined(HAVE_ECC_SIGN)
    WC_FREE_ARRAY(sig, BENCH_MAX_PENDING, HEAP_HINT);
    WC_FREE_ARRAY(digest, BENCH_MAX_PENDING, HEAP_HINT);
#endif

    (void)useDeviceID;
    (void)pending;
    (void)x;
    (void)count;
    (void)times;
    (void)desc;
    (void)start;
    (void)name;
}


#ifdef HAVE_ECC_ENCRYPT
void bench_eccEncrypt(int curveId)
{
#define BENCH_ECCENCRYPT_MSG_SIZE 48
#define BENCH_ECCENCRYPT_OUT_SIZE (BENCH_ECCENCRYPT_MSG_SIZE + \
                                   WC_SHA256_DIGEST_SIZE + \
                                   (MAX_ECC_BITS+3)/4 + 2)
    word32   outSz = BENCH_ECCENCRYPT_OUT_SIZE;
#ifdef WOLFSSL_SMALL_STACK
    ecc_key *userA = NULL, *userB = NULL;
    byte    *msg = NULL;
    byte    *out = NULL;
#else
    ecc_key userA[1], userB[1];
    byte    msg[BENCH_ECCENCRYPT_MSG_SIZE];
    byte    out[BENCH_ECCENCRYPT_OUT_SIZE];
#endif
    char    name[BENCH_ECC_NAME_SZ];
    int     keySize;
    word32  bench_plainSz = bench_size;
    int     ret, i, count;
    double start;
    const char**desc = bench_desc_words[lng_index];
    DECLARE_MULTI_VALUE_STATS_VARS()

#ifdef WOLFSSL_SMALL_STACK
    userA = (ecc_key *)XMALLOC(sizeof(*userA),
                               HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    userB = (ecc_key *)XMALLOC(sizeof(*userB),
                               HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    msg = (byte *)XMALLOC(BENCH_ECCENCRYPT_MSG_SIZE,
                          HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    out = (byte *)XMALLOC(outSz,
                          HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if ((! userA) || (! userB) || (! msg) || (! out)) {
        printf("bench_eccEncrypt malloc failed\n");
        goto exit;
    }
#endif

    keySize = wc_ecc_get_curve_size_from_id(curveId);
    ret = wc_ecc_init_ex(userA, HEAP_HINT, devId);
    if (ret != 0) {
        printf("wc_ecc_encrypt make key A failed: %d\n", ret);
        goto exit;
    }

    ret = wc_ecc_init_ex(userB, HEAP_HINT, devId);
    if (ret != 0) {
        printf("wc_ecc_encrypt make key B failed: %d\n", ret);
        goto exit;
    }

#if defined(ECC_TIMING_RESISTANT) && (!defined(HAVE_FIPS) || \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION != 2))) && \
    !defined(HAVE_SELFTEST)
    ret = wc_ecc_set_rng(userA, &gRng);
    if (ret != 0) {
        goto exit;
    }
    ret = wc_ecc_set_rng(userB, &gRng);
    if (ret != 0) {
        goto exit;
    }
#endif

    ret = wc_ecc_make_key_ex(&gRng, keySize, userA, curveId);
#ifdef WOLFSSL_ASYNC_CRYPT
    ret = wc_AsyncWait(ret, &userA->asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret != 0)
        goto exit;
    ret = wc_ecc_make_key_ex(&gRng, keySize, userB, curveId);
#ifdef WOLFSSL_ASYNC_CRYPT
    ret = wc_AsyncWait(ret, &userB->asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret != 0)
        goto exit;

    for (i = 0; i < BENCH_ECCENCRYPT_MSG_SIZE; i++) {
        msg[i] = (byte)i;
    }

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < ntimes; i++) {
            /* encrypt msg to B */
            ret = wc_ecc_encrypt(userA, userB, msg, BENCH_ECCENCRYPT_MSG_SIZE,
                                 out, &outSz, NULL);
            if (ret != 0) {
                printf("wc_ecc_encrypt failed! %d\n", ret);
                goto exit_enc;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

exit_enc:
    (void)XSNPRINTF(name, BENCH_ECC_NAME_SZ, "ECC   [%15s]",
                    wc_ecc_get_name(curveId));
    bench_stats_asym_finish(name, keySize * 8, desc[6], 0, count, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    RESET_MULTI_VALUE_STATS_VARS();

    if (ret != 0)
        goto exit;

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < ntimes; i++) {
            /* decrypt msg from A */
            ret = wc_ecc_decrypt(userB, userA, out, outSz, bench_plain,
                    &bench_plainSz, NULL);
            if (ret != 0) {
                printf("wc_ecc_decrypt failed! %d\n", ret);
                goto exit_dec;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

exit_dec:
    bench_stats_asym_finish(name, keySize * 8, desc[7], 0, count, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

exit:

    /* cleanup */
#ifdef WOLFSSL_SMALL_STACK
    if (userA) {
        wc_ecc_free(userA);
        XFREE(userA, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (userB) {
        wc_ecc_free(userB);
        XFREE(userB, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    XFREE(msg, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(out, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
#else
    wc_ecc_free(userB);
    wc_ecc_free(userA);
#endif
}
#endif

#ifdef WOLFSSL_SM2
static void bench_sm2_MakeKey(int useDeviceID)
{
    int ret = 0, i, times, count = 0, pending = 0;
    int deviceID;
    int keySize;
    WC_DECLARE_ARRAY(genKey, ecc_key, BENCH_MAX_PENDING,
                     sizeof(ecc_key), HEAP_HINT);
    char name[BENCH_ECC_NAME_SZ];
    double start = 0;
    const char**desc = bench_desc_words[lng_index];
    DECLARE_MULTI_VALUE_STATS_VARS()

    deviceID = useDeviceID ? devId : INVALID_DEVID;
    keySize = wc_ecc_get_curve_size_from_id(ECC_SM2P256V1);

    WC_CALLOC_ARRAY(genKey, ecc_key, BENCH_MAX_PENDING,
                     sizeof(ecc_key), HEAP_HINT);

    /* ECC Make Key */
    bench_stats_start(&count, &start);
    do {
        /* while free pending slots in queue, submit ops */
        for (times = 0; times < agreeTimes || pending > 0; ) {
            bench_async_poll(&pending);

            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(genKey[i]), 0,
                            &times, agreeTimes, &pending)) {

                    wc_ecc_free(genKey[i]);
                    ret = wc_ecc_init_ex(genKey[i], HEAP_HINT, deviceID);
                    if (ret < 0) {
                        goto exit;
                    }

                    ret = wc_ecc_sm2_make_key(&gRng, genKey[i],
                        WC_ECC_FLAG_NONE);
                    if (!bench_async_handle(&ret,
                                BENCH_ASYNC_GET_DEV(genKey[i]), 0, &times,
                                &pending)) {
                        goto exit;
                    }
                }
            } /* for i */
            RECORD_MULTI_VALUE_STATS();
        } /* for times */
        count += times;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

exit:
    (void)XSNPRINTF(name, BENCH_ECC_NAME_SZ, "ECC   [%15s]",
            wc_ecc_get_name(ECC_SM2P256V1));
    bench_stats_asym_finish(name, keySize * 8, desc[2], useDeviceID, count,
            start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    /* cleanup */
    if (WC_ARRAY_OK(genKey)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++) {
            wc_ecc_free(genKey[i]);
        }
        WC_FREE_ARRAY(genKey, BENCH_MAX_PENDING, HEAP_HINT);
    }
}


void bench_sm2(int useDeviceID)
{
    int ret = 0, i, times, count, pending = 0;
    int deviceID;
    int  keySize;
    char name[BENCH_ECC_NAME_SZ];
    WC_DECLARE_ARRAY(genKey, ecc_key, BENCH_MAX_PENDING,
                     sizeof(ecc_key), HEAP_HINT);
#ifdef HAVE_ECC_DHE
    WC_DECLARE_ARRAY(genKey2, ecc_key, BENCH_MAX_PENDING,
                     sizeof(ecc_key), HEAP_HINT);
#endif
#if !defined(NO_ASN) && defined(HAVE_ECC_SIGN)
#ifdef HAVE_ECC_VERIFY
    int verify[BENCH_MAX_PENDING];
#endif
#endif
    word32 x[BENCH_MAX_PENDING];
    double start = 0;
    const char**desc = bench_desc_words[lng_index];
    DECLARE_MULTI_VALUE_STATS_VARS()

#ifdef HAVE_ECC_DHE
    WC_DECLARE_ARRAY(shared, byte, BENCH_MAX_PENDING, MAX_ECC_BYTES, HEAP_HINT);
#endif
#if !defined(NO_ASN) && defined(HAVE_ECC_SIGN)
    WC_DECLARE_ARRAY(sig, byte, BENCH_MAX_PENDING, ECC_MAX_SIG_SIZE, HEAP_HINT);
    WC_DECLARE_ARRAY(digest, byte, BENCH_MAX_PENDING, MAX_ECC_BYTES, HEAP_HINT);
#endif

#ifdef HAVE_ECC_DHE
    WC_ALLOC_ARRAY(shared, byte, BENCH_MAX_PENDING, MAX_ECC_BYTES, HEAP_HINT);
#endif
#if !defined(NO_ASN) && defined(HAVE_ECC_SIGN)
    WC_ALLOC_ARRAY(sig, byte, BENCH_MAX_PENDING, ECC_MAX_SIG_SIZE, HEAP_HINT);
    WC_ALLOC_ARRAY(digest, byte, BENCH_MAX_PENDING, MAX_ECC_BYTES, HEAP_HINT);
#endif
    deviceID = useDeviceID ? devId : INVALID_DEVID;

    bench_sm2_MakeKey(useDeviceID);

    WC_CALLOC_ARRAY(genKey, ecc_key, BENCH_MAX_PENDING,
                     sizeof(ecc_key), HEAP_HINT);
#ifdef HAVE_ECC_DHE
    WC_CALLOC_ARRAY(genKey2, ecc_key, BENCH_MAX_PENDING,
                     sizeof(ecc_key), HEAP_HINT);
#endif

    keySize = wc_ecc_get_curve_size_from_id(ECC_SM2P256V1);

    /* init keys */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        /* setup an context for each key */
        if ((ret = wc_ecc_init_ex(genKey[i], HEAP_HINT, deviceID)) < 0) {
            goto exit;
        }
        ret = wc_ecc_sm2_make_key(&gRng, genKey[i], WC_ECC_FLAG_NONE);
    #ifdef WOLFSSL_ASYNC_CRYPT
        ret = wc_AsyncWait(ret, genKey[i].asyncDev, WC_ASYNC_FLAG_NONE);
    #endif
        if (ret < 0) {
            goto exit;
        }

    #ifdef HAVE_ECC_DHE
        if ((ret = wc_ecc_init_ex(genKey2[i], HEAP_HINT, deviceID)) < 0) {
            goto exit;
        }
        if ((ret = wc_ecc_sm2_make_key(&gRng, genKey2[i],
                WC_ECC_FLAG_NONE)) > 0) {
            goto exit;
        }
    #endif
    }

#ifdef HAVE_ECC_DHE
#if defined(ECC_TIMING_RESISTANT) && (!defined(HAVE_FIPS) || \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION != 2))) && \
    !defined(HAVE_SELFTEST)
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        (void)wc_ecc_set_rng(genKey[i], &gRng);
    }
#endif

    /* ECC Shared Secret */
    bench_stats_start(&count, &start);
    PRIVATE_KEY_UNLOCK();
    do {
        for (times = 0; times < agreeTimes || pending > 0; ) {
            bench_async_poll(&pending);

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(genKey[i]), 1,
                            &times, agreeTimes, &pending)) {
                    x[i] = (word32)keySize;
                    ret = wc_ecc_sm2_shared_secret(genKey[i], genKey2[i],
                            shared[i], &x[i]);
                    if (!bench_async_handle(&ret,
                                BENCH_ASYNC_GET_DEV(genKey[i]), 1, &times,
                                &pending)) {
                        goto exit_ecdhe;
                    }
                }
            } /* for i */
            RECORD_MULTI_VALUE_STATS();
        } /* for times */
        count += times;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    PRIVATE_KEY_UNLOCK();
exit_ecdhe:
    (void)XSNPRINTF(name, BENCH_ECC_NAME_SZ, "ECDHE [%15s]",
            wc_ecc_get_name(ECC_SM2P256V1));

    bench_stats_asym_finish(name, keySize * 8, desc[3], useDeviceID, count,
            start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    if (ret < 0) {
        goto exit;
    }
#endif /* HAVE_ECC_DHE */

#if !defined(NO_ASN) && defined(HAVE_ECC_SIGN)

    /* Init digest to sign */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        for (count = 0; count < keySize; count++) {
            digest[i][count] = (byte)count;
        }
    }

    RESET_MULTI_VALUE_STATS_VARS();

    /* ECC Sign */
    bench_stats_start(&count, &start);
    do {
        for (times = 0; times < agreeTimes || pending > 0; ) {
            bench_async_poll(&pending);

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(genKey[i]), 1,
                            &times, agreeTimes, &pending)) {
                    if (genKey[i]->state == 0)
                        x[i] = ECC_MAX_SIG_SIZE;
                    ret = wc_ecc_sm2_sign_hash(digest[i], (word32)keySize,
                            sig[i], &x[i], &gRng, genKey[i]);
                    if (!bench_async_handle(&ret,
                                BENCH_ASYNC_GET_DEV(genKey[i]), 1, &times,
                                &pending)) {
                        goto exit_ecdsa_sign;
                    }
                }
            } /* for i */
            RECORD_MULTI_VALUE_STATS();
        } /* for times */
        count += times;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

exit_ecdsa_sign:
    (void)XSNPRINTF(name, BENCH_ECC_NAME_SZ, "ECDSA [%15s]",
            wc_ecc_get_name(ECC_SM2P256V1));

    bench_stats_asym_finish(name, keySize * 8, desc[4], useDeviceID, count,
            start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    if (ret < 0) {
        goto exit;
    }

#ifdef HAVE_ECC_VERIFY

    /* ECC Verify */
    bench_stats_start(&count, &start);
    do {
        for (times = 0; times < agreeTimes || pending > 0; ) {
            bench_async_poll(&pending);

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(genKey[i]), 1,
                            &times, agreeTimes, &pending)) {
                    if (genKey[i]->state == 0)
                        verify[i] = 0;
                    ret = wc_ecc_sm2_verify_hash(sig[i], x[i], digest[i],
                                       (word32)keySize, &verify[i], genKey[i]);
                    if (!bench_async_handle(&ret,
                                BENCH_ASYNC_GET_DEV(genKey[i]), 1, &times,
                                &pending)) {
                        goto exit_ecdsa_verify;
                    }
                }
            } /* for i */
            RECORD_MULTI_VALUE_STATS();
        } /* for times */
        count += times;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

exit_ecdsa_verify:
    (void)XSNPRINTF(name, BENCH_ECC_NAME_SZ, "ECDSA [%15s]",
            wc_ecc_get_name(ECC_SM2P256V1));

    bench_stats_asym_finish(name, keySize * 8, desc[5], useDeviceID, count,
            start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

#endif /* HAVE_ECC_VERIFY */
#endif /* !NO_ASN && HAVE_ECC_SIGN */

exit:

    /* cleanup */
    if (WC_ARRAY_OK(genKey)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++)
            wc_ecc_free(genKey[i]);
        WC_FREE_ARRAY(genKey, BENCH_MAX_PENDING, HEAP_HINT);
    }
    #ifdef HAVE_ECC_DHE
    if (WC_ARRAY_OK(genKey2)) {
        for (i = 0; i < BENCH_MAX_PENDING; i++)
            wc_ecc_free(genKey2[i]);
        WC_FREE_ARRAY(genKey2, BENCH_MAX_PENDING, HEAP_HINT);
    }
    #endif

#ifdef HAVE_ECC_DHE
    WC_FREE_ARRAY(shared, BENCH_MAX_PENDING, HEAP_HINT);
#endif
#if !defined(NO_ASN) && defined(HAVE_ECC_SIGN)
    WC_FREE_ARRAY(sig, BENCH_MAX_PENDING, HEAP_HINT);
    WC_FREE_ARRAY(digest, BENCH_MAX_PENDING, HEAP_HINT);
#endif


    (void)useDeviceID;
    (void)pending;
    (void)x;
    (void)count;
    (void)times;
    (void)desc;
    (void)start;
    (void)name;
}
#endif /* WOLFSSL_SM2 */
#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519
void bench_curve25519KeyGen(int useDeviceID)
{
    curve25519_key genKey;
    double start;
    int    ret = 0, i, count;
    const char**desc = bench_desc_words[lng_index];
    DECLARE_MULTI_VALUE_STATS_VARS()

    /* Key Gen */
    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < genTimes; i++) {
            ret = wc_curve25519_init_ex(&genKey, HEAP_HINT,
                                        useDeviceID ? devId : INVALID_DEVID);
            if (ret != 0) {
                printf("wc_curve25519_init_ex failed: %d\n", ret);
                break;
            }

            ret = wc_curve25519_make_key(&gRng, 32, &genKey);
            wc_curve25519_free(&genKey);
            if (ret != 0) {
                printf("wc_curve25519_make_key failed: %d\n", ret);
                break;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_asym_finish("CURVE", 25519, desc[2], useDeviceID, count, start,
        ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif
}

#ifdef HAVE_CURVE25519_SHARED_SECRET
void bench_curve25519KeyAgree(int useDeviceID)
{
    curve25519_key genKey, genKey2;
    double start;
    int    ret, i, count;
    byte   shared[32];
    const char**desc = bench_desc_words[lng_index];
    word32 x = 0;
    DECLARE_MULTI_VALUE_STATS_VARS()

    wc_curve25519_init_ex(&genKey,  HEAP_HINT,
        useDeviceID ? devId : INVALID_DEVID);
    wc_curve25519_init_ex(&genKey2, HEAP_HINT,
        useDeviceID ? devId : INVALID_DEVID);

    ret = wc_curve25519_make_key(&gRng, 32, &genKey);
    if (ret != 0) {
        printf("curve25519_make_key failed\n");
        return;
    }
    ret = wc_curve25519_make_key(&gRng, 32, &genKey2);
    if (ret != 0) {
        printf("curve25519_make_key failed: %d\n", ret);
        wc_curve25519_free(&genKey);
        return;
    }

    /* Shared secret */
    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < agreeTimes; i++) {
            x = sizeof(shared);
            ret = wc_curve25519_shared_secret(&genKey, &genKey2, shared, &x);
            if (ret != 0) {
                printf("curve25519_shared_secret failed: %d\n", ret);
                goto exit;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

exit:
    bench_stats_asym_finish("CURVE", 25519, desc[3], useDeviceID, count, start,
        ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    wc_curve25519_free(&genKey2);
    wc_curve25519_free(&genKey);
}
#endif /* HAVE_CURVE25519_SHARED_SECRET */
#endif /* HAVE_CURVE25519 */

#ifdef HAVE_ED25519
void bench_ed25519KeyGen(void)
{
#ifdef HAVE_ED25519_MAKE_KEY
    ed25519_key genKey;
    double start;
    int    i, count;
    const char**desc = bench_desc_words[lng_index];
    DECLARE_MULTI_VALUE_STATS_VARS()

    /* Key Gen */
    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < genTimes; i++) {
            wc_ed25519_init(&genKey);
            (void)wc_ed25519_make_key(&gRng, 32, &genKey);
            wc_ed25519_free(&genKey);
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_asym_finish("ED", 25519, desc[2], 0, count, start, 0);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif
#endif /* HAVE_ED25519_MAKE_KEY */
}


void bench_ed25519KeySign(void)
{
#ifdef HAVE_ED25519_MAKE_KEY
    int    ret;
#endif
    ed25519_key genKey;
#ifdef HAVE_ED25519_SIGN
    double start;
    int    i, count;
    byte   sig[ED25519_SIG_SIZE];
    byte   msg[512];
    word32 x = 0;
    const char**desc = bench_desc_words[lng_index];
    DECLARE_MULTI_VALUE_STATS_VARS()
#endif

    wc_ed25519_init(&genKey);

#ifdef HAVE_ED25519_MAKE_KEY
    ret = wc_ed25519_make_key(&gRng, ED25519_KEY_SIZE, &genKey);
    if (ret != 0) {
        printf("ed25519_make_key failed\n");
        return;
    }
#endif

#ifdef HAVE_ED25519_SIGN
    /* make dummy msg */
    for (i = 0; i < (int)sizeof(msg); i++)
        msg[i] = (byte)i;

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < agreeTimes; i++) {
            x = sizeof(sig);
            ret = wc_ed25519_sign_msg(msg, sizeof(msg), sig, &x, &genKey);
            if (ret != 0) {
                printf("ed25519_sign_msg failed\n");
                goto exit_ed_sign;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

exit_ed_sign:
    bench_stats_asym_finish("ED", 25519, desc[4], 0, count, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    RESET_MULTI_VALUE_STATS_VARS();

#ifdef HAVE_ED25519_VERIFY
    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < agreeTimes; i++) {
            int verify = 0;
            ret = wc_ed25519_verify_msg(sig, x, msg, sizeof(msg), &verify,
                                        &genKey);
            if (ret != 0 || verify != 1) {
                printf("ed25519_verify_msg failed\n");
                goto exit_ed_verify;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

exit_ed_verify:
    bench_stats_asym_finish("ED", 25519, desc[5], 0, count, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif
#endif /* HAVE_ED25519_VERIFY */
#endif /* HAVE_ED25519_SIGN */

    wc_ed25519_free(&genKey);
}
#endif /* HAVE_ED25519 */

#ifdef HAVE_CURVE448
void bench_curve448KeyGen(void)
{
    curve448_key genKey;
    double start;
    int    ret = 0, i, count;
    const char**desc = bench_desc_words[lng_index];
    DECLARE_MULTI_VALUE_STATS_VARS()

    /* Key Gen */
    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < genTimes; i++) {
            ret = wc_curve448_make_key(&gRng, 56, &genKey);
            wc_curve448_free(&genKey);
            if (ret != 0) {
                printf("wc_curve448_make_key failed: %d\n", ret);
                break;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_asym_finish("CURVE", 448, desc[2], 0, count, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif
}

#ifdef HAVE_CURVE448_SHARED_SECRET
void bench_curve448KeyAgree(void)
{
    curve448_key genKey, genKey2;
    double start;
    int    ret, i, count;
    byte   shared[56];
    const char**desc = bench_desc_words[lng_index];
    word32 x = 0;
    DECLARE_MULTI_VALUE_STATS_VARS()

    wc_curve448_init(&genKey);
    wc_curve448_init(&genKey2);

    ret = wc_curve448_make_key(&gRng, 56, &genKey);
    if (ret != 0) {
        printf("curve448_make_key failed\n");
        return;
    }
    ret = wc_curve448_make_key(&gRng, 56, &genKey2);
    if (ret != 0) {
        printf("curve448_make_key failed: %d\n", ret);
        wc_curve448_free(&genKey);
        return;
    }

    /* Shared secret */
    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < agreeTimes; i++) {
            x = sizeof(shared);
            ret = wc_curve448_shared_secret(&genKey, &genKey2, shared, &x);
            if (ret != 0) {
                printf("curve448_shared_secret failed: %d\n", ret);
                goto exit;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

exit:
    bench_stats_asym_finish("CURVE", 448, desc[3], 0, count, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    wc_curve448_free(&genKey2);
    wc_curve448_free(&genKey);
}
#endif /* HAVE_CURVE448_SHARED_SECRET */
#endif /* HAVE_CURVE448 */

#ifdef HAVE_ED448
void bench_ed448KeyGen(void)
{
    ed448_key genKey;
    double start;
    int    i, count;
    const char**desc = bench_desc_words[lng_index];
    DECLARE_MULTI_VALUE_STATS_VARS()

    /* Key Gen */
    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < genTimes; i++) {
            wc_ed448_init(&genKey);
            (void)wc_ed448_make_key(&gRng, ED448_KEY_SIZE, &genKey);
            wc_ed448_free(&genKey);
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_asym_finish("ED", 448, desc[2], 0, count, start, 0);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif
}

void bench_ed448KeySign(void)
{
    int    ret;
    WC_DECLARE_VAR(genKey, ed448_key, 1, HEAP_HINT);
#ifdef HAVE_ED448_SIGN
    double start;
    int    i, count;
    byte   sig[ED448_SIG_SIZE];
    byte   msg[512];
    word32 x = 0;
    const char**desc = bench_desc_words[lng_index];
    DECLARE_MULTI_VALUE_STATS_VARS()
#endif

    WC_ALLOC_VAR(genKey, ed448_key, 1, HEAP_HINT);

    wc_ed448_init(genKey);

    ret = wc_ed448_make_key(&gRng, ED448_KEY_SIZE, genKey);
    if (ret != 0) {
        printf("ed448_make_key failed\n");
        goto exit;
    }

#ifdef HAVE_ED448_SIGN
    /* make dummy msg */
    for (i = 0; i < (int)sizeof(msg); i++)
        msg[i] = (byte)i;

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < agreeTimes; i++) {
            x = sizeof(sig);
            ret = wc_ed448_sign_msg(msg, sizeof(msg), sig, &x, genKey,
                                    NULL, 0);
            if (ret != 0) {
                printf("ed448_sign_msg failed\n");
                goto exit;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_asym_finish("ED", 448, desc[4], 0, count, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    RESET_MULTI_VALUE_STATS_VARS();

#ifdef HAVE_ED448_VERIFY
    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < agreeTimes; i++) {
            int verify = 0;
            ret = wc_ed448_verify_msg(sig, x, msg, sizeof(msg), &verify,
                                      genKey, NULL, 0);
            if (ret != 0 || verify != 1) {
                printf("ed448_verify_msg failed\n");
                goto exit;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_asym_finish("ED", 448, desc[5], 0, count, start, ret);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif
#endif /* HAVE_ED448_VERIFY */
#endif /* HAVE_ED448_SIGN */

exit:

    wc_ed448_free(genKey);
    WC_FREE_VAR(genKey, HEAP_HINT);
}
#endif /* HAVE_ED448 */

#ifdef WOLFCRYPT_HAVE_ECCSI
#ifdef WOLFCRYPT_ECCSI_KMS
void bench_eccsiKeyGen(void)
{
    WC_DECLARE_VAR(genKey, EccsiKey, 1, HEAP_HINT);
    double start;
    int    i, count;
    const char**desc = bench_desc_words[lng_index];
    int    ret;
    DECLARE_MULTI_VALUE_STATS_VARS()

    WC_ALLOC_VAR(genKey, EccsiKey, 1, HEAP_HINT);

    /* Key Gen */
    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < genTimes; i++) {
            wc_InitEccsiKey(genKey, NULL, INVALID_DEVID);
            ret = wc_MakeEccsiKey(genKey, &gRng);
            wc_FreeEccsiKey(genKey);
            if (ret != 0) {
                printf("wc_MakeEccsiKey failed: %d\n", ret);
                goto exit;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_asym_finish("ECCSI", 256, desc[2], 0, count, start, 0);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

exit:

    WC_FREE_VAR(genKey, HEAP_HINT);
}

void bench_eccsiPairGen(void)
{
    WC_DECLARE_VAR(genKey, EccsiKey, 1, HEAP_HINT);
    double start;
    int    i, count;
    const char**desc = bench_desc_words[lng_index];
    WC_DECLARE_VAR(ssk, mp_int, 1, HEAP_HINT);
    ecc_point* pvt;
    static const byte id[] = { 0x01, 0x23, 0x34, 0x45 };
    int ret;
    DECLARE_MULTI_VALUE_STATS_VARS()

    WC_ALLOC_VAR(genKey, EccsiKey, 1, HEAP_HINT);
    WC_ALLOC_VAR(ssk, mp_int, 1, HEAP_HINT);

    (void)mp_init(ssk);
    pvt = wc_ecc_new_point();
    wc_InitEccsiKey(genKey, NULL, INVALID_DEVID);
    (void)wc_MakeEccsiKey(genKey, &gRng);

    /* RSK Gen */
    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < genTimes; i++) {
            ret = wc_MakeEccsiPair(genKey, &gRng, WC_HASH_TYPE_SHA256, id,
                                   sizeof(id), ssk, pvt);
            if (ret != 0) {
                printf("wc_MakeEccsiPair failed: %d\n", ret);
                goto exit;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_asym_finish("ECCSI", 256, desc[12], 0, count, start, 0);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    wc_FreeEccsiKey(genKey);
    wc_ecc_del_point(pvt);
    mp_free(ssk);

exit:

    WC_FREE_VAR(genKey, HEAP_HINT);
    WC_FREE_VAR(ssk, HEAP_HINT);
}
#endif

#ifdef WOLFCRYPT_ECCSI_CLIENT
void bench_eccsiValidate(void)
{
    WC_DECLARE_VAR(genKey, EccsiKey, 1, HEAP_HINT);
    double start;
    int    i, count;
    const char**desc = bench_desc_words[lng_index];
    WC_DECLARE_VAR(ssk, mp_int, 1, HEAP_HINT);
    ecc_point* pvt;
    static const byte id[] = { 0x01, 0x23, 0x34, 0x45 };
    int valid;
    int ret;
    DECLARE_MULTI_VALUE_STATS_VARS()

    WC_ALLOC_VAR(genKey, EccsiKey, 1, HEAP_HINT);
    WC_ALLOC_VAR(ssk, mp_int, 1, HEAP_HINT);

    (void)mp_init(ssk);
    pvt = wc_ecc_new_point();
    wc_InitEccsiKey(genKey, NULL, INVALID_DEVID);
    (void)wc_MakeEccsiKey(genKey, &gRng);
    (void)wc_MakeEccsiPair(genKey, &gRng, WC_HASH_TYPE_SHA256, id, sizeof(id),
                           ssk, pvt);

    /* Validation of RSK */
    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < genTimes; i++) {
            ret = wc_ValidateEccsiPair(genKey, WC_HASH_TYPE_SHA256, id,
                                       sizeof(id), ssk, pvt, &valid);
            if (ret != 0 || !valid) {
                printf("wc_ValidateEccsiPair failed: %d (valid=%d))\n", ret,
                       valid);
                goto exit;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_asym_finish("ECCSI", 256, desc[11], 0, count, start, 0);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    wc_FreeEccsiKey(genKey);
    wc_ecc_del_point(pvt);
    mp_free(ssk);

exit:

    WC_FREE_VAR(genKey, HEAP_HINT);
    WC_FREE_VAR(ssk, HEAP_HINT);
}

void bench_eccsi(void)
{
    WC_DECLARE_VAR(genKey, EccsiKey, 1, HEAP_HINT);
    double start;
    int    i, count;
    const char**desc = bench_desc_words[lng_index];
    WC_DECLARE_VAR(ssk, mp_int, 1, HEAP_HINT);
    ecc_point* pvt;
    static const byte id[] = { 0x01, 0x23, 0x34, 0x45 };
    static const byte msg[] = { 0x01, 0x23, 0x34, 0x45 };
    byte hash[WC_SHA256_DIGEST_SIZE];
    byte hashSz = (byte)sizeof(hash);
    byte sig[257];
    word32 sigSz = sizeof(sig);
    int ret;
    int verified;
    DECLARE_MULTI_VALUE_STATS_VARS()

    WC_ALLOC_VAR(genKey, EccsiKey, 1, HEAP_HINT);
    WC_ALLOC_VAR(ssk, mp_int, 1, HEAP_HINT);

    (void)mp_init(ssk);
    pvt = wc_ecc_new_point();
    (void)wc_InitEccsiKey(genKey, NULL, INVALID_DEVID);
    (void)wc_MakeEccsiKey(genKey, &gRng);
    (void)wc_MakeEccsiPair(genKey, &gRng, WC_HASH_TYPE_SHA256, id, sizeof(id),
                           ssk, pvt);
    (void)wc_HashEccsiId(genKey, WC_HASH_TYPE_SHA256, id, sizeof(id), pvt,
                         hash, &hashSz);
    (void)wc_SetEccsiHash(genKey, hash, hashSz);
    (void)wc_SetEccsiPair(genKey, ssk, pvt);

    /* Encapsulate */
    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < genTimes; i++) {
            ret = wc_SignEccsiHash(genKey, &gRng, WC_HASH_TYPE_SHA256, msg,
                                   sizeof(msg), sig, &sigSz);
            if (ret != 0) {
                printf("wc_SignEccsiHash failed: %d\n", ret);
                break;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_asym_finish("ECCSI", 256, desc[4], 0, count, start, 0);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    RESET_MULTI_VALUE_STATS_VARS();

    /* Derive */
    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < genTimes; i++) {
            ret = wc_VerifyEccsiHash(genKey, WC_HASH_TYPE_SHA256, msg,
                                     sizeof(msg), sig, sigSz, &verified);

            if (ret != 0 || !verified) {
                printf("wc_VerifyEccsiHash failed: %d (verified: %d)\n", ret,
                       verified);
                goto exit;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_asym_finish("ECCSI", 256, desc[5], 0, count, start, 0);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    wc_FreeEccsiKey(genKey);
    wc_ecc_del_point(pvt);

exit:

    WC_FREE_VAR(genKey, HEAP_HINT);
    WC_FREE_VAR(ssk, HEAP_HINT);
}
#endif /* WOLFCRYPT_ECCSI_CLIENT */
#endif /* WOLFCRYPT_HAVE_ECCSI */

#ifdef WOLFCRYPT_HAVE_SAKKE
#ifdef WOLFCRYPT_SAKKE_KMS
void bench_sakkeKeyGen(void)
{
    WC_DECLARE_VAR(genKey, SakkeKey, 1, HEAP_HINT);
    double start;
    int    i, count;
    const char**desc = bench_desc_words[lng_index];
    int    ret;
    DECLARE_MULTI_VALUE_STATS_VARS()

    WC_ALLOC_VAR(genKey, SakkeKey, 1, HEAP_HINT);

    /* Key Gen */
    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < genTimes; i++) {
            wc_InitSakkeKey_ex(genKey, 128, ECC_SAKKE_1, NULL, INVALID_DEVID);
            ret = wc_MakeSakkeKey(genKey, &gRng);
            if (ret != 0) {
                printf("wc_MakeSakkeKey failed: %d\n", ret);
                goto exit;
            }
            wc_FreeSakkeKey(genKey);
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_asym_finish("SAKKE", 1024, desc[2], 0, count, start, 0);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

exit:

    WC_FREE_VAR(genKey, HEAP_HINT);
}

void bench_sakkeRskGen(void)
{
    WC_DECLARE_VAR(genKey, SakkeKey, 1, HEAP_HINT);
    double start;
    int    i, count;
    const char**desc = bench_desc_words[lng_index];
    ecc_point* rsk;
    static const byte id[] = { 0x01, 0x23, 0x34, 0x45 };
    int ret;
    DECLARE_MULTI_VALUE_STATS_VARS()

    WC_ALLOC_VAR(genKey, SakkeKey, 1, HEAP_HINT);

    rsk = wc_ecc_new_point();
    wc_InitSakkeKey_ex(genKey, 128, ECC_SAKKE_1, NULL, INVALID_DEVID);
    (void)wc_MakeSakkeKey(genKey, &gRng);

    /* RSK Gen */
    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < genTimes; i++) {
            ret = wc_MakeSakkeRsk(genKey, id, sizeof(id), rsk);
            if (ret != 0) {
                printf("wc_MakeSakkeRsk failed: %d\n", ret);
                goto exit;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_asym_finish("SAKKE", 1024, desc[8], 0, count, start, 0);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    wc_FreeSakkeKey(genKey);
    wc_ecc_del_point(rsk);

exit:

    WC_FREE_VAR(genKey, HEAP_HINT);
}
#endif

#ifdef WOLFCRYPT_SAKKE_CLIENT
void bench_sakkeValidate(void)
{
    WC_DECLARE_VAR(genKey, SakkeKey, 1, HEAP_HINT);
    double start;
    int    i, count;
    const char**desc = bench_desc_words[lng_index];
    ecc_point* rsk;
    static const byte id[] = { 0x01, 0x23, 0x34, 0x45 };
    int valid;
    int ret;
    DECLARE_MULTI_VALUE_STATS_VARS()

    WC_ALLOC_VAR(genKey, SakkeKey, 1, HEAP_HINT);

    rsk = wc_ecc_new_point();
    (void)wc_InitSakkeKey_ex(genKey, 128, ECC_SAKKE_1, NULL, INVALID_DEVID);
    (void)wc_MakeSakkeKey(genKey, &gRng);
    (void)wc_MakeSakkeRsk(genKey, id, sizeof(id), rsk);
    (void)wc_ValidateSakkeRsk(genKey, id, sizeof(id), rsk, &valid);

    /* Validation of RSK */
    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < genTimes; i++) {
            ret = wc_ValidateSakkeRsk(genKey, id, sizeof(id), rsk, &valid);
            if (ret != 0 || !valid) {
                printf("wc_ValidateSakkeRsk failed: %d (valid=%d))\n", ret,
                       valid);
                goto exit;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_asym_finish("SAKKE", 1024, desc[11], 0, count, start, 0);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    wc_FreeSakkeKey(genKey);
    wc_ecc_del_point(rsk);

exit:

    WC_FREE_VAR(genKey, HEAP_HINT);
}

void bench_sakke(void)
{
    WC_DECLARE_VAR(genKey, SakkeKey, 1, HEAP_HINT);
    double start;
    int    i, count;
    const char**desc = bench_desc_words[lng_index];
    ecc_point* rsk;
    static const byte id[] = { 0x01, 0x23, 0x34, 0x45 };
    static const byte ssv_init[] = { 0x01, 0x23, 0x34, 0x45 };
    byte ssv[sizeof(ssv_init)];
    byte derSSV[sizeof(ssv)];
    byte auth[257];
    word16 authSz = sizeof(auth);
    int ret = 0;
    byte* table = NULL;
    word32 len = 0;
    byte* iTable = NULL;
    word32 iTableLen = 0;
    DECLARE_MULTI_VALUE_STATS_VARS()

    WC_ALLOC_VAR(genKey, SakkeKey, 1, HEAP_HINT);

    XMEMCPY(ssv, ssv_init, sizeof ssv);

    rsk = wc_ecc_new_point();
    (void)wc_InitSakkeKey_ex(genKey, 128, ECC_SAKKE_1, NULL, INVALID_DEVID);
    (void)wc_MakeSakkeKey(genKey, &gRng);
    (void)wc_MakeSakkeRsk(genKey, id, sizeof(id), rsk);
    (void)wc_SetSakkeRsk(genKey, rsk, NULL, 0);
    (void)wc_SetSakkeIdentity(genKey, id, sizeof(id));

    /* Encapsulate */
    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < genTimes; i++) {
            ret = wc_MakeSakkeEncapsulatedSSV(genKey,
                                              WC_HASH_TYPE_SHA256,
                                              ssv, sizeof(ssv), auth, &authSz);
            if (ret != 0) {
                printf("wc_MakeSakkeEncapsulatedSSV failed: %d\n", ret);
                break;
            }
            RECORD_MULTI_VALUE_STATS();
        } /* for */
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_asym_finish_ex("SAKKE", 1024, desc[9], "-1",
                               0, count, start, 0);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    RESET_MULTI_VALUE_STATS_VARS();

    /* Derive */
    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < genTimes; i++) {
            XMEMCPY(derSSV, ssv, sizeof(ssv));
            ret = wc_DeriveSakkeSSV(genKey, WC_HASH_TYPE_SHA256, derSSV,
                                    sizeof(derSSV), auth, authSz);
            if (ret != 0) {
                printf("wc_DeriveSakkeSSV failed: %d\n", ret);
                break;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        if (ret != 0) break;
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_asym_finish_ex("SAKKE", 1024, desc[10], "-1",
                               0, count, start, 0);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    /* Calculate Point I and generate table. */
    (void)wc_MakeSakkePointI(genKey, id, sizeof(id));
    iTableLen = 0;
    (void)wc_GenerateSakkePointITable(genKey, NULL, &iTableLen);
    if (iTableLen != 0) {
        iTable = (byte*)XMALLOC(iTableLen, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (iTable == NULL)
            WC_ALLOC_DO_ON_FAILURE();
        (void)wc_GenerateSakkePointITable(genKey, iTable, &iTableLen);
    }

    /* Encapsulate with Point I table */
    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < genTimes; i++) {
            ret = wc_MakeSakkeEncapsulatedSSV(genKey,
                                              WC_HASH_TYPE_SHA256, ssv,
                                              sizeof(ssv), auth, &authSz);
            if (ret != 0) {
                printf("wc_MakeSakkeEncapsulatedSSV failed: %d\n", ret);
                break;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_asym_finish_ex("SAKKE", 1024, desc[9], "-2", 0,
                               count, start, 0);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    RESET_MULTI_VALUE_STATS_VARS();

    (void)wc_SetSakkeRsk(genKey, rsk, table, len);

    /* Derive with Point I table */
    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < genTimes; i++) {
            XMEMCPY(derSSV, ssv, sizeof(ssv));
            ret = wc_DeriveSakkeSSV(genKey, WC_HASH_TYPE_SHA256, derSSV,
                                    sizeof(derSSV), auth, authSz);
            if (ret != 0) {
                printf("wc_DeriveSakkeSSV failed: %d\n", ret);
                break;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        if (ret != 0) break;
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_asym_finish_ex("SAKKE", 1024, desc[10], "-2", 0,
                               count, start, 0);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    RESET_MULTI_VALUE_STATS_VARS();

    len = 0;
    (void)wc_GenerateSakkeRskTable(genKey, rsk, NULL, &len);
    if (len > 0) {
        table = (byte*)XMALLOC(len, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (table == NULL)
            WC_ALLOC_DO_ON_FAILURE();
        (void)wc_GenerateSakkeRskTable(genKey, rsk, table, &len);
    }
    (void)wc_SetSakkeRsk(genKey, rsk, table, len);

    /* Derive with Point I table and RSK table */
    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < genTimes; i++) {
            XMEMCPY(derSSV, ssv, sizeof(ssv));
            ret = wc_DeriveSakkeSSV(genKey, WC_HASH_TYPE_SHA256, derSSV,
                                    sizeof(derSSV), auth, authSz);
            if (ret != 0) {
                printf("wc_DeriveSakkeSSV failed: %d\n", ret);
                break;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        if (ret != 0) break;
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_asym_finish_ex("SAKKE", 1024, desc[10], "-3",
                               0, count, start, 0);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    RESET_MULTI_VALUE_STATS_VARS();

    wc_ClearSakkePointITable(genKey);
    /* Derive with RSK table */
    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < genTimes; i++) {
            XMEMCPY(derSSV, ssv, sizeof(ssv));
            ret = wc_DeriveSakkeSSV(genKey, WC_HASH_TYPE_SHA256, derSSV,
                                    sizeof(derSSV), auth, authSz);
            if (ret != 0) {
                printf("wc_DeriveSakkeSSV failed: %d\n", ret);
                break;
            }
            RECORD_MULTI_VALUE_STATS();
        }
        if (ret != 0) break;
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    bench_stats_asym_finish_ex("SAKKE", 1024, desc[10], "-4", 0,
                               count, start, 0);
#ifdef MULTI_VALUE_STATISTICS
    bench_multi_value_stats(max, min, sum, squareSum, runs);
#endif

    wc_FreeSakkeKey(genKey);
    wc_ecc_del_point(rsk);

exit:

    XFREE(iTable, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    XFREE(table, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    WC_FREE_VAR(genKey, HEAP_HINT);
}
#endif /* WOLFCRYPT_SAKKE_CLIENT */
#endif /* WOLFCRYPT_HAVE_SAKKE */

#ifdef HAVE_FALCON
void bench_falconKeySign(byte level)
{
    int    ret = 0;
    falcon_key key;
    double start;
    int    i, count;
    byte   sig[FALCON_MAX_SIG_SIZE];
    byte   msg[512];
    word32 x = 0;
    const char**desc = bench_desc_words[lng_index];
    DECLARE_MULTI_VALUE_STATS_VARS()

    ret = wc_falcon_init(&key);
    if (ret != 0) {
        printf("wc_falcon_init failed %d\n", ret);
        return;
    }

    ret = wc_falcon_set_level(&key, level);
    if (ret != 0) {
        printf("wc_falcon_set_level failed %d\n", ret);
    }

    if (ret == 0) {
        if (level == 1) {
            ret = wc_falcon_import_private_key(bench_falcon_level1_key,
                                               sizeof_bench_falcon_level1_key,
                                               NULL, 0, &key);
        }
        else {
            ret = wc_falcon_import_private_key(bench_falcon_level5_key,
                                               sizeof_bench_falcon_level5_key,
                                               NULL, 0, &key);
        }

        if (ret != 0) {
            printf("wc_falcon_import_private_key failed %d\n", ret);
        }
    }

    /* make dummy msg */
    for (i = 0; i < (int)sizeof(msg); i++) {
        msg[i] = (byte)i;
    }

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < agreeTimes; i++) {
            if (ret == 0) {
                if (level == 1) {
                    x = FALCON_LEVEL1_SIG_SIZE;
                }
                else {
                    x = FALCON_LEVEL5_SIG_SIZE;
                }

                ret = wc_falcon_sign_msg(msg, sizeof(msg), sig, &x, &key, GLOBAL_RNG);
                if (ret != 0) {
                    printf("wc_falcon_sign_msg failed\n");
                }
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    if (ret == 0) {
        bench_stats_asym_finish("FALCON", level, desc[4], 0,
                                count, start, ret);
    #ifdef MULTI_VALUE_STATISTICS
        bench_multi_value_stats(max, min, sum, squareSum, runs);
    #endif
    }

    RESET_MULTI_VALUE_STATS_VARS();

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < agreeTimes; i++) {
            if (ret == 0) {
                int verify = 0;
                ret = wc_falcon_verify_msg(sig, x, msg, sizeof(msg), &verify,
                                           &key);
                if (ret != 0 || verify != 1) {
                    printf("wc_falcon_verify_msg failed %d, verify %d\n",
                           ret, verify);
                    ret = -1;
                }
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    if (ret == 0) {
        bench_stats_asym_finish("FALCON", level, desc[5],
                                0, count, start, ret);
    #ifdef MULTI_VALUE_STATISTICS
        bench_multi_value_stats(max, min, sum, squareSum, runs);
    #endif
    }

    wc_falcon_free(&key);
}
#endif /* HAVE_FALCON */

#ifdef HAVE_DILITHIUM

#if defined(WOLFSSL_DILITHIUM_NO_SIGN) && !defined(WOLFSSL_DILITHIUM_NO_VERIFY)

#ifndef WOLFSSL_NO_ML_DSA_44
static const unsigned char bench_dilithium_level2_sig[] = {
    0x5e, 0xc1, 0xce, 0x0e, 0x31, 0xea, 0x10, 0x52, 0xa3, 0x7a,
    0xfe, 0x4d, 0xac, 0x07, 0x89, 0x5a, 0x45, 0xbd, 0x5a, 0xe5,
    0x22, 0xed, 0x98, 0x4d, 0x2f, 0xc8, 0x27, 0x00, 0x99, 0x40,
    0x00, 0x79, 0xcd, 0x93, 0x27, 0xd0, 0x40, 0x33, 0x79, 0x4f,
    0xe5, 0x16, 0x89, 0x9f, 0xbd, 0xa6, 0x3f, 0xdd, 0x68, 0x74,
    0x73, 0xc3, 0x97, 0x54, 0x11, 0x1d, 0xc8, 0xb8, 0xc8, 0xfd,
    0x3a, 0xbe, 0xca, 0x17, 0x0f, 0x10, 0x6d, 0x89, 0x6d, 0xe0,
    0xb2, 0xff, 0x3b, 0xe5, 0xa1, 0x75, 0xea, 0x35, 0x16, 0xa3,
    0x0c, 0x6e, 0x4a, 0x7b, 0xdb, 0x28, 0xc6, 0x2a, 0x76, 0x0e,
    0x78, 0x78, 0xa0, 0x4f, 0x4e, 0xf8, 0x99, 0xff, 0xe7, 0x47,
    0x7e, 0xc4, 0x62, 0xa7, 0xb4, 0xb9, 0x2b, 0xc1, 0xc7, 0xd0,
    0x00, 0xb6, 0xaa, 0xa7, 0x37, 0xd5, 0x1e, 0x19, 0xc4, 0xc4,
    0x59, 0x2f, 0xa5, 0x09, 0xa3, 0xda, 0x5d, 0xd4, 0x48, 0x64,
    0x16, 0x0e, 0x92, 0xdf, 0x61, 0xb7, 0x25, 0x3b, 0x90, 0x5a,
    0x08, 0xb5, 0x88, 0xe8, 0x64, 0x80, 0x63, 0xee, 0xbf, 0x59,
    0x0f, 0x4a, 0x48, 0x1e, 0x77, 0xa9, 0x46, 0xc6, 0x9c, 0x0b,
    0x83, 0xad, 0xb5, 0xbf, 0xb5, 0x5b, 0x99, 0xf3, 0x55, 0xe8,
    0xe5, 0xe7, 0x5c, 0x12, 0xac, 0x06, 0x06, 0xe0, 0xc0, 0x32,
    0x5d, 0xb6, 0x9f, 0x2b, 0x8e, 0x19, 0x5c, 0x2a, 0x58, 0xbb,
    0x37, 0xf1, 0x68, 0x56, 0x8b, 0x74, 0x94, 0x58, 0x48, 0x28,
    0xee, 0xf7, 0x0a, 0x8f, 0xad, 0x43, 0x67, 0xe1, 0xa3, 0x8c,
    0x3b, 0x35, 0x48, 0xcc, 0x52, 0x14, 0x36, 0x99, 0x18, 0x71,
    0x1c, 0xb2, 0xfc, 0x82, 0xda, 0xac, 0xd5, 0x55, 0x0a, 0x77,
    0x44, 0x6a, 0x48, 0xed, 0xfc, 0x5a, 0x68, 0xa6, 0x4d, 0x65,
    0xe7, 0x30, 0xaa, 0x23, 0x66, 0x84, 0xdf, 0x83, 0xf1, 0x17,
    0x5c, 0x46, 0xfe, 0x63, 0xcb, 0xc3, 0x6e, 0x4e, 0x47, 0x8d,
    0x30, 0x48, 0x06, 0xda, 0x97, 0x6b, 0x04, 0x5d, 0x44, 0xf3,
    0xb7, 0x2a, 0x6d, 0x2b, 0xbb, 0xcd, 0x97, 0x4e, 0x26, 0x8e,
    0xc9, 0x03, 0x0b, 0x5d, 0x68, 0xed, 0x81, 0xf7, 0x19, 0x61,
    0x81, 0xe9, 0xac, 0x3a, 0x35, 0xcd, 0xe8, 0xfd, 0x99, 0xdb,
    0x89, 0x83, 0x7d, 0x23, 0x6a, 0xc1, 0xc1, 0x10, 0xe9, 0xd3,
    0xfa, 0x9e, 0x5a, 0xcd, 0x73, 0xa3, 0x0a, 0x37, 0xa3, 0x12,
    0xef, 0x72, 0xa2, 0x28, 0xd4, 0x3d, 0x67, 0x53, 0x24, 0x0d,
    0x61, 0x98, 0xbb, 0x07, 0xf3, 0xa7, 0x79, 0x22, 0x74, 0x57,
    0x99, 0xe8, 0x7a, 0xbf, 0x90, 0x84, 0xa2, 0x6b, 0x29, 0x34,
    0xac, 0xc9, 0xff, 0x67, 0x82, 0xd0, 0xd2, 0x7d, 0x69, 0xc0,
    0xf3, 0xd7, 0x4b, 0x5c, 0xf2, 0xa8, 0x53, 0x8b, 0x78, 0x57,
    0xfc, 0x74, 0xf5, 0x81, 0x6e, 0xc2, 0x5b, 0x32, 0x52, 0x9e,
    0x58, 0x84, 0xa1, 0x71, 0xd5, 0x8c, 0xf5, 0x16, 0x36, 0x4d,
    0x11, 0xd4, 0xb5, 0xc2, 0x05, 0xc4, 0x03, 0xce, 0x83, 0xea,
    0x0b, 0x6a, 0x2e, 0xf6, 0x28, 0x5e, 0xb2, 0x40, 0x8c, 0xa3,
    0x6a, 0xc7, 0xee, 0x04, 0x54, 0x93, 0x0f, 0x3b, 0xf9, 0x57,
    0x92, 0x00, 0xf1, 0xc7, 0x1b, 0x48, 0x63, 0xcb, 0xd3, 0xdd,
    0x40, 0x90, 0x46, 0xb0, 0x87, 0x2a, 0xb8, 0xec, 0xbc, 0x07,
    0x09, 0x83, 0x25, 0xb1, 0x88, 0x2c, 0xa0, 0x0a, 0x40, 0x4f,
    0xfd, 0xec, 0xfd, 0xbe, 0x18, 0xae, 0xdd, 0x83, 0x89, 0x83,
    0x2d, 0x10, 0xb4, 0x14, 0x30, 0xac, 0x6c, 0xd9, 0xc9, 0xaa,
    0xbc, 0xdb, 0x5e, 0x14, 0xab, 0x19, 0x64, 0xaa, 0xb1, 0x9c,
    0xc3, 0xf5, 0xdc, 0x2b, 0xcd, 0x26, 0x0b, 0x81, 0x1a, 0x0e,
    0x0a, 0xd6, 0x39, 0x79, 0x10, 0x06, 0xbf, 0xe0, 0xc1, 0x8b,
    0x20, 0x24, 0x90, 0x8b, 0x0f, 0xa4, 0x2d, 0x2d, 0x46, 0x2a,
    0xd4, 0xf3, 0xa9, 0x58, 0x4b, 0xd9, 0xa6, 0x6c, 0x75, 0x3d,
    0xbc, 0x36, 0x76, 0x7f, 0xef, 0x1b, 0xa1, 0x41, 0xba, 0xd0,
    0xfe, 0x16, 0x19, 0xc3, 0x92, 0xe3, 0x59, 0x07, 0x3f, 0x48,
    0x11, 0x70, 0xe0, 0x8a, 0xff, 0x97, 0xbc, 0x71, 0xd5, 0xb9,
    0x4a, 0x9b, 0x4c, 0xb8, 0x4b, 0x50, 0xd6, 0x43, 0xe8, 0x84,
    0x0a, 0x95, 0xd0, 0x20, 0x28, 0xd3, 0x20, 0x4a, 0x0e, 0x1b,
    0xe6, 0x5d, 0x2f, 0x0c, 0xdb, 0x76, 0xab, 0xa3, 0xc2, 0xad,
    0xd5, 0x86, 0xae, 0xb9, 0x26, 0xb2, 0x5d, 0x72, 0x27, 0xbb,
    0xec, 0x23, 0x9f, 0x42, 0x90, 0x58, 0xe1, 0xf8, 0xe9, 0x63,
    0xdf, 0x1a, 0x46, 0x53, 0x65, 0x05, 0xfb, 0x20, 0x21, 0xa6,
    0x64, 0xc8, 0x5c, 0x67, 0x6b, 0x41, 0x6c, 0x04, 0x34, 0xeb,
    0x05, 0x71, 0xeb, 0xbe, 0xed, 0x6d, 0xa2, 0x96, 0x67, 0x45,
    0xe7, 0x47, 0x22, 0x64, 0xaf, 0x82, 0xf8, 0x78, 0x0e, 0xe6,
    0xa1, 0x4a, 0x2d, 0x82, 0x1e, 0xd0, 0xc2, 0x79, 0x4e, 0x29,
    0x89, 0xd9, 0xf3, 0x3f, 0xb6, 0xc4, 0xee, 0x69, 0xb2, 0x8f,
    0x8b, 0xd9, 0x13, 0xd9, 0x6e, 0x3a, 0xc5, 0x9f, 0xdf, 0x25,
    0xb7, 0xc3, 0x16, 0xb8, 0xa2, 0x85, 0x17, 0xae, 0xe9, 0x95,
    0x5d, 0xb8, 0x1d, 0x21, 0xbb, 0xd9, 0x38, 0x11, 0x8f, 0x44,
    0xea, 0xe8, 0x4c, 0x91, 0x82, 0xf5, 0x45, 0xee, 0x8f, 0xf5,
    0x6a, 0x0d, 0x08, 0xe7, 0x6b, 0xb0, 0x91, 0xd5, 0x42, 0x17,
    0x8c, 0x37, 0x6a, 0x5a, 0x0a, 0x87, 0x53, 0x76, 0xc3, 0x59,
    0x35, 0x13, 0x1c, 0xf1, 0x72, 0x2c, 0x2b, 0xb2, 0x9e, 0xda,
    0x10, 0x2a, 0xce, 0x38, 0xb4, 0x67, 0x8c, 0x4b, 0x08, 0xa1,
    0xb6, 0xa3, 0x08, 0x9c, 0xeb, 0xd8, 0x93, 0x1b, 0x29, 0x5a,
    0xa7, 0x03, 0x17, 0x7e, 0xec, 0x58, 0x6b, 0x5b, 0xc5, 0x46,
    0x03, 0x33, 0x7f, 0x0e, 0x93, 0x9a, 0xdd, 0xb5, 0x89, 0xb1,
    0x16, 0x4c, 0xa7, 0xd8, 0x0e, 0x73, 0xd8, 0xc3, 0xd2, 0x36,
    0x85, 0x66, 0xcb, 0x5b, 0x64, 0xf2, 0xdc, 0xba, 0x39, 0xcc,
    0xa5, 0xe0, 0x9b, 0xaa, 0x2a, 0x95, 0x6d, 0xdc, 0x49, 0xde,
    0x3b, 0x61, 0xa2, 0x3b, 0x1f, 0xed, 0x32, 0xfa, 0x10, 0xe4,
    0x88, 0x59, 0xca, 0x5a, 0xe4, 0xf9, 0x5e, 0xe2, 0xca, 0x21,
    0x5a, 0xdc, 0x02, 0x73, 0x7a, 0xc8, 0x90, 0x7a, 0x8e, 0x91,
    0x19, 0x04, 0x53, 0x3c, 0x50, 0x15, 0x8a, 0x84, 0x93, 0x8f,
    0xac, 0x99, 0x82, 0xdd, 0xc6, 0xce, 0xfb, 0x18, 0x84, 0x29,
    0x2a, 0x8d, 0xa2, 0xc5, 0x7f, 0x87, 0xce, 0x4c, 0xf5, 0xdf,
    0x73, 0xd2, 0xba, 0xc2, 0x4f, 0xe3, 0x74, 0xa5, 0x8f, 0xc3,
    0xf4, 0x99, 0xd1, 0xe8, 0x4e, 0xb8, 0xe0, 0x2e, 0xef, 0xd6,
    0x87, 0x70, 0xcf, 0x45, 0x3b, 0xff, 0x03, 0xfd, 0x59, 0x7f,
    0x7c, 0xd0, 0x4e, 0x49, 0xf7, 0xd5, 0x08, 0xd9, 0x06, 0x53,
    0x90, 0x0a, 0x5a, 0x1b, 0x2e, 0xf5, 0xb0, 0x85, 0xb6, 0xb6,
    0x61, 0xa5, 0x71, 0x47, 0xbf, 0x4a, 0xf6, 0xae, 0x9a, 0x19,
    0x6c, 0xd8, 0x2d, 0x9b, 0xb4, 0x40, 0x9e, 0x15, 0x77, 0x2e,
    0x7e, 0xe9, 0xb4, 0x3d, 0x0f, 0x1b, 0xb5, 0x1c, 0xc2, 0x58,
    0x4e, 0x4b, 0xf6, 0x53, 0x9e, 0x6f, 0x09, 0x55, 0xa0, 0xb8,
    0x73, 0x11, 0x64, 0x70, 0x54, 0xb4, 0xcb, 0xb7, 0x27, 0xe5,
    0xdf, 0x58, 0x67, 0x5b, 0xc0, 0xd6, 0xf5, 0x64, 0xa6, 0x66,
    0x6d, 0xdf, 0xd8, 0xf8, 0xd6, 0x85, 0xba, 0xba, 0x30, 0xa7,
    0xca, 0x34, 0xf4, 0x9a, 0xba, 0x0a, 0xfb, 0x0e, 0xa0, 0x65,
    0x98, 0x78, 0xee, 0xaa, 0x14, 0x6a, 0x99, 0x77, 0x67, 0xad,
    0x01, 0x95, 0x5e, 0x50, 0x22, 0xe9, 0x74, 0x95, 0xa7, 0x13,
    0x3f, 0xdd, 0xa6, 0x69, 0x64, 0xf6, 0x50, 0x06, 0x6d, 0xba,
    0x90, 0x5a, 0x8c, 0x81, 0xa0, 0xda, 0x55, 0xe9, 0x97, 0x0e,
    0xd7, 0x10, 0x8e, 0x1f, 0x23, 0x65, 0xd9, 0x14, 0xd4, 0xde,
    0xa5, 0xf9, 0xec, 0xb6, 0xad, 0x65, 0xce, 0x0b, 0x1b, 0x0a,
    0x4c, 0x7d, 0xb0, 0x97, 0xa6, 0xfe, 0x67, 0xfb, 0x4f, 0x8f,
    0x00, 0x92, 0xb6, 0x0d, 0x20, 0x78, 0x65, 0x1d, 0x9a, 0x56,
    0x57, 0xc6, 0x15, 0x88, 0xba, 0x55, 0x02, 0x7a, 0x9a, 0xac,
    0x50, 0x4c, 0xc7, 0x9e, 0x66, 0x8b, 0xfc, 0xf3, 0x67, 0x48,
    0x07, 0xbf, 0x84, 0x94, 0x9b, 0x22, 0x2a, 0xae, 0x1b, 0x25,
    0xe9, 0x94, 0x06, 0xa7, 0xe8, 0x61, 0x52, 0x89, 0xdc, 0x93,
    0x6e, 0x89, 0xdc, 0x30, 0x6e, 0xd9, 0xee, 0xcb, 0x12, 0x38,
    0x58, 0x9d, 0x8b, 0xc5, 0x05, 0x2c, 0x50, 0x4e, 0xc8, 0xc2,
    0xe0, 0x65, 0xb6, 0x49, 0xc4, 0xf0, 0x1e, 0x5c, 0x8e, 0x3c,
    0xe9, 0x77, 0xd2, 0x9e, 0xa8, 0xd5, 0xf5, 0xd9, 0xc5, 0xad,
    0x5b, 0x74, 0x48, 0x08, 0x3a, 0x30, 0x84, 0x57, 0x71, 0x1e,
    0x69, 0x45, 0x09, 0xdd, 0xea, 0x62, 0xec, 0x7c, 0xa3, 0xf9,
    0x92, 0xee, 0x16, 0xdc, 0xe5, 0x9d, 0xcf, 0xb7, 0x08, 0x51,
    0x8a, 0x76, 0x3a, 0x23, 0x94, 0x50, 0x8e, 0x4d, 0x3a, 0xea,
    0xf3, 0xc1, 0x53, 0x2c, 0x65, 0x9c, 0x36, 0x8c, 0x10, 0xe3,
    0x9c, 0x01, 0xa4, 0xe6, 0x45, 0x77, 0xa6, 0x5d, 0x7e, 0x37,
    0x31, 0x95, 0x2f, 0xec, 0x61, 0x92, 0x69, 0x65, 0x53, 0x54,
    0x6d, 0xbe, 0x9e, 0x5a, 0x68, 0x12, 0xc4, 0xe7, 0xe4, 0x06,
    0x51, 0x5a, 0xc0, 0x63, 0xb9, 0x69, 0xb8, 0x3c, 0xd8, 0xae,
    0x8b, 0xff, 0x96, 0x4d, 0x55, 0xce, 0x25, 0x2b, 0x8b, 0x89,
    0xc9, 0x3a, 0x16, 0x48, 0x2a, 0x73, 0xb2, 0x70, 0x8b, 0x62,
    0xd5, 0xb1, 0xa0, 0x30, 0xe5, 0x46, 0xab, 0x8b, 0xc3, 0xeb,
    0x37, 0x2f, 0xbd, 0xb8, 0x4e, 0x6c, 0x30, 0xdc, 0x6c, 0x8a,
    0xf1, 0x89, 0x06, 0xce, 0x64, 0x0a, 0x3e, 0xb2, 0x16, 0x31,
    0xa1, 0xe4, 0x4b, 0x98, 0xe7, 0xf1, 0x99, 0x76, 0x00, 0x5f,
    0xd2, 0xd3, 0x30, 0xf0, 0xbf, 0xa7, 0x4a, 0xf6, 0x9e, 0xa5,
    0x75, 0x74, 0x78, 0xfe, 0xec, 0x72, 0x7c, 0x89, 0xe9, 0xf6,
    0x0d, 0x7e, 0x15, 0xd6, 0xd8, 0x79, 0x85, 0x3c, 0xcf, 0xb0,
    0x21, 0xc8, 0x9c, 0x54, 0x87, 0x63, 0xb3, 0x05, 0xbb, 0x8a,
    0x02, 0xe4, 0x79, 0xdc, 0xa1, 0xa2, 0xd3, 0x19, 0xd8, 0x86,
    0xff, 0x8a, 0x0e, 0x82, 0x89, 0xaf, 0xaa, 0x62, 0x2e, 0xd4,
    0xb2, 0xd0, 0x5d, 0x0d, 0x4f, 0x2a, 0xda, 0x0e, 0x9f, 0x8a,
    0x2b, 0x32, 0xe9, 0x09, 0xf5, 0x55, 0x51, 0xe7, 0xd5, 0x69,
    0x12, 0xdd, 0x33, 0x6b, 0x3d, 0xd7, 0xe9, 0xfd, 0xb2, 0xa7,
    0xf5, 0x97, 0x2a, 0x6d, 0x89, 0x30, 0x65, 0x2a, 0x0d, 0xf2,
    0x00, 0x81, 0xbe, 0xfb, 0xd9, 0xd7, 0x1b, 0xc2, 0x48, 0x7a,
    0x22, 0x30, 0xae, 0x35, 0xf6, 0x32, 0x41, 0x9d, 0xd9, 0x12,
    0xb3, 0xa7, 0x6d, 0xba, 0x74, 0x93, 0x2d, 0x0d, 0xb2, 0xb6,
    0xdc, 0xa9, 0x98, 0x5b, 0x3b, 0xaa, 0x2b, 0x47, 0x06, 0xc4,
    0x36, 0xfd, 0x04, 0x10, 0x94, 0x61, 0x61, 0x47, 0x1c, 0x02,
    0x54, 0x85, 0x4a, 0xcb, 0x75, 0x6b, 0x75, 0xf5, 0xb4, 0x61,
    0x26, 0xb3, 0x12, 0x43, 0x31, 0x55, 0xb5, 0xda, 0x4b, 0xb5,
    0x11, 0xb4, 0xb8, 0xfb, 0x0a, 0xd9, 0xa7, 0x0e, 0x9f, 0x2a,
    0x74, 0x01, 0xf6, 0x1a, 0x33, 0x10, 0x9e, 0x66, 0xff, 0x82,
    0xfa, 0xa9, 0xa4, 0xa0, 0x9b, 0x25, 0x2d, 0x16, 0xbf, 0x60,
    0x0d, 0x87, 0xea, 0x94, 0xad, 0xdd, 0xc4, 0xd0, 0xa8, 0xdd,
    0x2d, 0xc7, 0xc8, 0xac, 0x39, 0x9e, 0x87, 0x69, 0xc4, 0x3a,
    0xbc, 0x28, 0x7e, 0x36, 0x69, 0xfd, 0x20, 0x25, 0xac, 0xa3,
    0xa7, 0x37, 0x96, 0xe9, 0x8a, 0x65, 0xe4, 0xb0, 0x2a, 0x61,
    0x23, 0x28, 0x64, 0xff, 0x17, 0x6c, 0x36, 0x9e, 0x0a, 0xba,
    0xe4, 0x4b, 0xeb, 0x84, 0x24, 0x20, 0x57, 0x0f, 0x34, 0x05,
    0x95, 0x56, 0xc3, 0x2f, 0x2b, 0xf0, 0x36, 0xef, 0xca, 0x68,
    0xfe, 0x78, 0xf8, 0x98, 0x09, 0x4a, 0x25, 0xcc, 0x17, 0xbe,
    0x05, 0x00, 0xff, 0xf9, 0xa5, 0x5b, 0xe6, 0xaa, 0x5b, 0x56,
    0xb6, 0x89, 0x64, 0x9c, 0x16, 0x48, 0xe1, 0xcd, 0x67, 0x87,
    0xdd, 0xba, 0xbd, 0x02, 0x0d, 0xd8, 0xb4, 0xc9, 0x7c, 0x37,
    0x92, 0xd0, 0x39, 0x46, 0xd2, 0xc4, 0x78, 0x13, 0xf0, 0x76,
    0x45, 0x5f, 0xeb, 0x52, 0xd2, 0x3f, 0x61, 0x87, 0x34, 0x09,
    0xb7, 0x24, 0x4e, 0x93, 0xf3, 0xc5, 0x10, 0x19, 0x66, 0x66,
    0x3f, 0x15, 0xe3, 0x05, 0x55, 0x43, 0xb7, 0xf4, 0x62, 0x57,
    0xb4, 0xd9, 0xef, 0x46, 0x47, 0xb5, 0xfb, 0x79, 0xc9, 0x67,
    0xc5, 0xc3, 0x18, 0x91, 0x73, 0x75, 0xec, 0xd5, 0x68, 0x2b,
    0xf6, 0x42, 0xb4, 0xff, 0xfb, 0x27, 0x61, 0x77, 0x28, 0x10,
    0x6b, 0xce, 0x19, 0xad, 0x87, 0xc3, 0x85, 0xe3, 0x78, 0x00,
    0xdb, 0x21, 0xee, 0xd8, 0xfa, 0x9c, 0x81, 0x11, 0x97, 0xac,
    0xd0, 0x50, 0x89, 0x45, 0x23, 0xf6, 0x85, 0x7d, 0x60, 0xb2,
    0xad, 0x0c, 0x5d, 0xd8, 0x9e, 0xe4, 0xe1, 0x25, 0xb2, 0x13,
    0x1a, 0x54, 0x54, 0xfd, 0x7b, 0xab, 0x85, 0x20, 0xe8, 0xda,
    0x52, 0x0f, 0xac, 0x49, 0x70, 0xf1, 0x4c, 0x66, 0x74, 0x8c,
    0x87, 0x6e, 0xca, 0xc1, 0x0d, 0x92, 0xc0, 0xa8, 0x08, 0xfd,
    0x0f, 0x60, 0x55, 0xaf, 0x24, 0xcb, 0x04, 0xb7, 0xff, 0xa9,
    0xc5, 0x07, 0x26, 0xf6, 0xe2, 0x1e, 0x2f, 0xd1, 0x99, 0x6d,
    0xef, 0xc0, 0xdb, 0x5b, 0xf7, 0x06, 0x80, 0x92, 0x5f, 0x56,
    0x54, 0xdb, 0x2e, 0xba, 0x93, 0xb2, 0x94, 0xf2, 0xad, 0xbc,
    0x91, 0x6e, 0x4e, 0xce, 0x21, 0xc4, 0x8b, 0x18, 0xc4, 0xfc,
    0xab, 0xb4, 0x4f, 0xd7, 0xa2, 0xef, 0x55, 0x00, 0x6d, 0x34,
    0x17, 0x59, 0x8d, 0x79, 0x75, 0x02, 0xa3, 0x7a, 0x52, 0x57,
    0x5c, 0x26, 0xb9, 0xae, 0xd6, 0x19, 0x2e, 0x31, 0x02, 0x98,
    0x98, 0xe5, 0x3d, 0xc2, 0xa5, 0x56, 0xb6, 0x02, 0xae, 0x0d,
    0x3b, 0x35, 0x97, 0xd2, 0x43, 0x38, 0x8a, 0x65, 0xfa, 0x86,
    0x20, 0xb7, 0xb5, 0xb0, 0xda, 0x19, 0x01, 0x2f, 0x13, 0xb5,
    0x6d, 0xbd, 0xb2, 0x34, 0xa7, 0xff, 0xae, 0x7e, 0x8f, 0x98,
    0x1b, 0xc4, 0x27, 0xbd, 0xa9, 0x64, 0xdc, 0xab, 0x2a, 0xd2,
    0xb4, 0x27, 0xd0, 0x25, 0xdd, 0xff, 0xdc, 0x0a, 0x96, 0xd3,
    0x85, 0x3e, 0xc5, 0x11, 0x34, 0x60, 0xa2, 0x33, 0x92, 0x90,
    0xbb, 0x4c, 0x86, 0xdd, 0xd6, 0x1e, 0xcb, 0x0a, 0x17, 0xc6,
    0x87, 0x4e, 0x3e, 0x7a, 0x4b, 0xab, 0xef, 0x0a, 0x00, 0x3d,
    0x94, 0x34, 0x8b, 0x63, 0x36, 0xd9, 0xaf, 0x5d, 0x63, 0x40,
    0xbb, 0x32, 0x4b, 0x64, 0xf0, 0x31, 0x48, 0xdb, 0x44, 0x2b,
    0x48, 0x60, 0x6a, 0xea, 0xa4, 0x8c, 0xdd, 0xaf, 0x81, 0x3f,
    0x86, 0x81, 0x99, 0x7a, 0x98, 0xe1, 0xff, 0x21, 0x7a, 0x28,
    0xbc, 0x33, 0xe6, 0x4e, 0xb0, 0x85, 0x6b, 0xec, 0x11, 0x37,
    0x81, 0x7f, 0xf9, 0xdc, 0xbf, 0x1a, 0xa6, 0x6d, 0x4d, 0x0f,
    0x5b, 0x99, 0x73, 0xb8, 0xd2, 0x6e, 0x37, 0xf0, 0x71, 0xf1,
    0x1a, 0xc3, 0x5c, 0xea, 0x12, 0x5f, 0x2e, 0x85, 0x3f, 0xfd,
    0xd5, 0x87, 0x67, 0x9f, 0x67, 0x9f, 0xd7, 0xef, 0x9f, 0x81,
    0xa4, 0xbc, 0x63, 0x1d, 0x00, 0x81, 0xf6, 0x20, 0x77, 0xae,
    0x0b, 0x90, 0xe5, 0x9c, 0xa9, 0x44, 0xb5, 0xd7, 0xb1, 0x61,
    0x33, 0x4f, 0x75, 0xa9, 0xb7, 0xf4, 0xa4, 0x72, 0x9e, 0x72,
    0xec, 0x7b, 0xcd, 0x83, 0xb3, 0xd6, 0x22, 0x50, 0x50, 0x97,
    0x0f, 0x63, 0x0f, 0xe1, 0x15, 0xb3, 0x07, 0xb6, 0xa3, 0xfa,
    0x2f, 0xb5, 0xf3, 0x5b, 0x5d, 0x7f, 0x90, 0x20, 0xcd, 0x5f,
    0x40, 0x48, 0x87, 0x43, 0xfd, 0xa3, 0x69, 0xdc, 0xf8, 0x51,
    0x08, 0x67, 0xc2, 0x2d, 0xff, 0xfe, 0xbf, 0x85, 0x3e, 0x80,
    0xff, 0x91, 0x62, 0xc5, 0x83, 0xe0, 0x80, 0xeb, 0xce, 0xdc,
    0xff, 0xb1, 0xdb, 0x02, 0xb7, 0x01, 0x1e, 0xa6, 0xf0, 0x32,
    0xfb, 0x95, 0x6a, 0x47, 0x44, 0x84, 0x42, 0x6e, 0x3a, 0xb1,
    0xcf, 0xf9, 0x28, 0xb4, 0x3a, 0x8e, 0xa7, 0x8d, 0x48, 0x81,
    0x1c, 0x7e, 0xf5, 0x0b, 0x46, 0x7e, 0x92, 0x4e, 0xb9, 0xa8,
    0x36, 0xb8, 0x81, 0x6d, 0x8c, 0x70, 0x59, 0x33, 0x12, 0x61,
    0xbb, 0xe6, 0x10, 0x8a, 0xe4, 0xc1, 0x2c, 0x50, 0x12, 0xbf,
    0xd3, 0xc6, 0x3c, 0x53, 0x91, 0x50, 0x07, 0xc8, 0x85, 0x32,
    0x3c, 0xe1, 0x67, 0x99, 0x68, 0xc1, 0xf4, 0x74, 0x86, 0x35,
    0x8a, 0x6c, 0x75, 0x1d, 0x8f, 0x8a, 0x60, 0xe1, 0xc7, 0x59,
    0x4e, 0xb0, 0xe0, 0x45, 0x5a, 0x11, 0x05, 0x24, 0xa7, 0x8d,
    0x39, 0x93, 0x60, 0x4c, 0xc5, 0x9e, 0x8a, 0x70, 0xcc, 0x44,
    0x96, 0x92, 0xc8, 0xf7, 0x23, 0x14, 0xc7, 0xf4, 0x82, 0x9d,
    0x5b, 0x1c, 0x26, 0xd0, 0x3c, 0x76, 0x36, 0xe9, 0x98, 0x8a,
    0xbb, 0xe6, 0xa0, 0xad, 0xed, 0xf7, 0xd9, 0x06, 0x50, 0x67,
    0x79, 0x50, 0x4e, 0xd5, 0x80, 0x4e, 0x59, 0x72, 0x5d, 0x8b,
    0xcb, 0x86, 0x3b, 0x57, 0xc4, 0xb2, 0x3d, 0xbc, 0x35, 0x6d,
    0xb1, 0x50, 0xf5, 0x8c, 0xf2, 0x89, 0x72, 0x20, 0xd0, 0x47,
    0x68, 0x13, 0x42, 0x25, 0x1a, 0xb6, 0xc5, 0x07, 0xdf, 0x45,
    0x11, 0xa9, 0x05, 0x5d, 0xad, 0xf0, 0x49, 0x9e, 0x70, 0x78,
    0xed, 0xe7, 0xf9, 0x00, 0x1f, 0x62, 0x76, 0x47, 0xb5, 0x48,
    0x4f, 0x2c, 0x2e, 0xe3, 0x78, 0x6a, 0x44, 0x46, 0x1e, 0x6b,
    0x00, 0x74, 0x54, 0xb9, 0xd1, 0x4f, 0x6d, 0x45, 0xc1, 0xa6,
    0x45, 0x2e, 0x1a, 0xaf, 0x94, 0x3f, 0xd0, 0x72, 0x67, 0x0d,
    0x2e, 0xa9, 0x8d, 0x16, 0xc4, 0x05, 0x01, 0x07, 0x13, 0x1b,
    0x1c, 0x3d, 0x43, 0x71, 0x91, 0x95, 0x9a, 0xae, 0xaf, 0xc4,
    0xe5, 0xe6, 0xe9, 0xff, 0x02, 0x0c, 0x0f, 0x3e, 0x62, 0x67,
    0x68, 0x81, 0xc7, 0xd0, 0xd8, 0xdd, 0xe0, 0xf5, 0x0b, 0x25,
    0x35, 0x45, 0x4a, 0x4b, 0x63, 0x74, 0x79, 0x7e, 0x82, 0xa2,
    0xaf, 0xc6, 0xc7, 0xcc, 0xd2, 0xfa, 0x2a, 0x2d, 0x2f, 0x32,
    0x35, 0x38, 0x3f, 0x4c, 0x7f, 0x80, 0x81, 0x8b, 0x9b, 0x9c,
    0x9d, 0xa7, 0xa9, 0xcb, 0xe9, 0xf0, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x20, 0x32, 0x46,
};
static const int sizeof_bench_dilithium_level2_sig =
    sizeof(bench_dilithium_level2_sig);
#endif

#ifndef WOLFSSL_NO_ML_DSA_65
static const unsigned char bench_dilithium_level3_sig[] = {
    0x3e, 0xff, 0xf4, 0x48, 0x80, 0x2d, 0x88, 0x87, 0xf4, 0xcc,
    0xa4, 0x61, 0xe1, 0x27, 0x20, 0x55, 0x66, 0xc8, 0xfe, 0x3e,
    0xdd, 0xf5, 0x5c, 0x70, 0x6c, 0x54, 0xba, 0x50, 0x8a, 0xa2,
    0x4b, 0x88, 0xbc, 0xb8, 0x87, 0xf9, 0x4e, 0x50, 0x3a, 0x04,
    0x18, 0xb3, 0xf4, 0x5f, 0x77, 0x4a, 0x7e, 0xa8, 0xf5, 0xca,
    0x49, 0x00, 0xdc, 0x24, 0xaa, 0x05, 0x35, 0x0f, 0x34, 0xf7,
    0xbf, 0x09, 0xa6, 0xcf, 0x75, 0x37, 0x07, 0xcd, 0x07, 0x99,
    0x92, 0x1d, 0xc7, 0xc9, 0x17, 0x1c, 0xdd, 0x27, 0x8c, 0x66,
    0xf2, 0x8b, 0x75, 0xb0, 0x86, 0x2d, 0xbd, 0x51, 0x16, 0xc2,
    0x50, 0xe0, 0x7e, 0x0a, 0x21, 0x58, 0x93, 0x22, 0x06, 0xcb,
    0x85, 0x8b, 0xfd, 0x97, 0x61, 0xc0, 0xdb, 0xab, 0xfa, 0x4a,
    0x69, 0xef, 0x9c, 0xc1, 0x4e, 0xae, 0xb2, 0xb3, 0xa2, 0x74,
    0xa4, 0x94, 0x0a, 0xed, 0x39, 0x9e, 0xe8, 0x58, 0xeb, 0xfd,
    0x43, 0x05, 0x73, 0x38, 0xd6, 0xbb, 0xeb, 0xb9, 0x9d, 0x3b,
    0xf8, 0x85, 0xb4, 0x4b, 0x16, 0x5c, 0x9e, 0xfe, 0xb8, 0x13,
    0xf8, 0x68, 0x44, 0x90, 0x05, 0x61, 0xb3, 0xed, 0x6f, 0x47,
    0xc9, 0x50, 0xcf, 0x6c, 0xc0, 0xac, 0xdf, 0x4c, 0x4c, 0x1b,
    0x42, 0xce, 0x0a, 0x32, 0x69, 0xb0, 0xfd, 0x87, 0xef, 0xf3,
    0x9c, 0xcc, 0xba, 0x2f, 0x03, 0xd7, 0xdb, 0x76, 0xee, 0xa0,
    0x71, 0x4a, 0x80, 0xcb, 0x90, 0x9e, 0xbb, 0x8f, 0x00, 0x46,
    0x81, 0xe0, 0xde, 0xa6, 0x43, 0xb5, 0x37, 0x79, 0xf2, 0x35,
    0xce, 0x9e, 0xd2, 0xb1, 0x5b, 0xff, 0x91, 0xfb, 0x98, 0xc1,
    0xe1, 0x66, 0x2c, 0x00, 0x1b, 0x89, 0xf2, 0x57, 0x81, 0x73,
    0x7e, 0x9f, 0x8d, 0x50, 0xd0, 0xe0, 0xe3, 0x93, 0xf2, 0x87,
    0x41, 0x64, 0x6c, 0xb7, 0x09, 0x60, 0x91, 0x4e, 0x0b, 0xbe,
    0xbe, 0xd4, 0x98, 0xfa, 0x14, 0x8c, 0x46, 0x09, 0xfa, 0xaa,
    0x82, 0xd6, 0xdd, 0x65, 0x93, 0x39, 0x45, 0x50, 0x90, 0x10,
    0xae, 0x1b, 0xff, 0xab, 0x7e, 0x86, 0xda, 0xb9, 0x4d, 0xf1,
    0xc2, 0x00, 0x54, 0x66, 0xee, 0x40, 0xc0, 0x56, 0x2f, 0xe8,
    0x43, 0x89, 0xbb, 0xb8, 0x59, 0x24, 0x63, 0x45, 0x9a, 0xde,
    0x08, 0xf3, 0x16, 0x94, 0xd2, 0x8d, 0xee, 0xf9, 0xbe, 0x4f,
    0x29, 0xe1, 0x4b, 0x5e, 0x2b, 0x14, 0xef, 0x66, 0xe2, 0x12,
    0xf8, 0x87, 0x2e, 0xb1, 0x75, 0x8b, 0x21, 0xb5, 0x8f, 0x8e,
    0xc5, 0x0e, 0x60, 0x27, 0x15, 0xbd, 0x72, 0xe4, 0x26, 0x4e,
    0x62, 0x7d, 0x3a, 0x46, 0x49, 0x93, 0xa9, 0x52, 0x7f, 0xc2,
    0x27, 0xb9, 0x55, 0x6a, 0x45, 0x9f, 0x2c, 0x7a, 0x5a, 0xc9,
    0xf4, 0x55, 0xaf, 0x49, 0xb3, 0xd5, 0xc0, 0x84, 0xdb, 0x89,
    0x5f, 0x21, 0x04, 0xf5, 0x4c, 0x66, 0x1e, 0x2e, 0x69, 0xdf,
    0x5b, 0x14, 0x60, 0x89, 0x84, 0xf8, 0xa3, 0xaf, 0xdf, 0xb9,
    0x18, 0x5e, 0xbf, 0x81, 0x95, 0x9a, 0x5e, 0x4f, 0x24, 0x45,
    0xad, 0xab, 0xe2, 0x36, 0x7c, 0x19, 0xde, 0xc0, 0xf4, 0x1a,
    0x42, 0xb2, 0xc2, 0x58, 0x2f, 0x5f, 0xd0, 0x2e, 0x28, 0x33,
    0x59, 0x75, 0xc2, 0xde, 0x41, 0xe3, 0x9b, 0x85, 0x46, 0xad,
    0x6d, 0xf1, 0x06, 0xf0, 0x6a, 0xb9, 0xed, 0x71, 0x7b, 0xfd,
    0xf1, 0xc4, 0x56, 0xd8, 0xb3, 0x1a, 0x5f, 0x04, 0xae, 0xe8,
    0xce, 0xde, 0xa1, 0x6d, 0x46, 0x2a, 0x4f, 0x62, 0xee, 0x25,
    0xdf, 0x22, 0x21, 0xb2, 0x8f, 0x5f, 0x26, 0x33, 0x5a, 0xdd,
    0xbe, 0x08, 0xb3, 0x93, 0x16, 0x16, 0xad, 0x2e, 0x00, 0xb8,
    0x14, 0x0c, 0x10, 0xa3, 0x29, 0x89, 0x1f, 0xd7, 0x06, 0x7a,
    0x09, 0xf3, 0x84, 0xf9, 0x18, 0x04, 0x56, 0x2f, 0x7f, 0xbd,
    0x8e, 0x12, 0xdf, 0x4d, 0x58, 0x5c, 0x1d, 0x81, 0x0c, 0x7d,
    0x62, 0x02, 0xe0, 0xf9, 0x1b, 0x69, 0xe9, 0x38, 0x45, 0x84,
    0x2d, 0x9a, 0x4a, 0x3d, 0x7b, 0x48, 0xd5, 0x0d, 0x76, 0xba,
    0xff, 0x20, 0x00, 0xf8, 0x42, 0x7f, 0xd2, 0x25, 0x70, 0x90,
    0x88, 0xb3, 0x98, 0xac, 0xe9, 0xd9, 0xac, 0x58, 0xa6, 0x49,
    0xcc, 0x93, 0xa5, 0x04, 0x0c, 0x68, 0x53, 0x64, 0x72, 0x8c,
    0xfc, 0x8d, 0x61, 0xeb, 0x3f, 0x93, 0x8b, 0x85, 0x98, 0x05,
    0xce, 0x06, 0xd7, 0xbf, 0xbb, 0xa5, 0x22, 0xda, 0xe9, 0x8a,
    0x29, 0x30, 0x5e, 0x82, 0xe4, 0x46, 0x7c, 0x36, 0x5e, 0xf5,
    0xc7, 0xe3, 0x09, 0xdf, 0x20, 0x76, 0x73, 0x33, 0x31, 0x75,
    0xc2, 0x99, 0xe9, 0x74, 0x43, 0x82, 0xb1, 0xeb, 0x74, 0x6f,
    0xad, 0x59, 0x48, 0x12, 0xa0, 0x24, 0xe3, 0x38, 0x48, 0x61,
    0x0c, 0xf6, 0x38, 0x83, 0x3a, 0xcd, 0xd6, 0x45, 0x10, 0x0e,
    0x09, 0x79, 0x31, 0x30, 0x80, 0xfb, 0x34, 0x60, 0x1e, 0x72,
    0x98, 0xe9, 0x5c, 0xbf, 0xab, 0x21, 0x7f, 0xa3, 0x19, 0x7e,
    0x8c, 0xa9, 0xa7, 0xfc, 0x25, 0xe0, 0x8e, 0x6d, 0xa1, 0xb9,
    0x7b, 0x5b, 0x37, 0x33, 0x96, 0xd8, 0x6e, 0x7a, 0xce, 0xa6,
    0x1a, 0xbd, 0xe6, 0x6e, 0x62, 0xc4, 0x8c, 0x69, 0xfe, 0xe4,
    0xcb, 0x0a, 0xa1, 0x6c, 0x66, 0x0e, 0x1a, 0x5e, 0xb9, 0xd1,
    0x4a, 0xa3, 0x91, 0x39, 0xcf, 0x85, 0x07, 0x5b, 0xaf, 0x99,
    0x11, 0xca, 0xee, 0x6f, 0x2e, 0x33, 0xda, 0x60, 0xbf, 0xd6,
    0xa0, 0x7a, 0xdb, 0x91, 0x13, 0xb7, 0xa3, 0x5d, 0x0e, 0x1e,
    0x3b, 0xf9, 0x7a, 0x3e, 0x4f, 0x8d, 0xb3, 0x81, 0xe8, 0x0c,
    0x4d, 0x48, 0x61, 0x06, 0x14, 0x0f, 0x3e, 0x33, 0x9e, 0xea,
    0xa6, 0xd8, 0xd8, 0x4d, 0x9b, 0x00, 0x34, 0x0d, 0x31, 0x62,
    0x54, 0x93, 0x04, 0xd2, 0x02, 0x21, 0x38, 0x91, 0x58, 0xca,
    0x77, 0xd3, 0x6c, 0xd1, 0x94, 0x05, 0xfa, 0x30, 0x6a, 0x0b,
    0xf0, 0x52, 0x52, 0xb7, 0xdb, 0x34, 0xff, 0x18, 0x5c, 0x78,
    0x25, 0x44, 0x39, 0xe4, 0x54, 0x8a, 0xf1, 0x49, 0x04, 0xab,
    0x8a, 0x5f, 0x87, 0xe1, 0x6e, 0x1a, 0xf2, 0xba, 0x39, 0xb4,
    0x7c, 0x71, 0x5b, 0xbe, 0x8d, 0xbb, 0xed, 0x3b, 0xed, 0x20,
    0x95, 0xdf, 0xa7, 0x50, 0xb5, 0x66, 0xff, 0xd0, 0x3a, 0x92,
    0xde, 0xf2, 0xa3, 0xf2, 0xd6, 0x48, 0x6b, 0xd8, 0xef, 0x80,
    0x4d, 0xc2, 0x3c, 0xc7, 0xc6, 0x6e, 0xdf, 0xd1, 0x54, 0xfb,
    0x22, 0xac, 0x1a, 0x11, 0x81, 0x02, 0xc7, 0x66, 0xe0, 0xf3,
    0xad, 0x0b, 0xd0, 0xec, 0xae, 0x93, 0x53, 0xa5, 0xbf, 0xa5,
    0x17, 0x59, 0x14, 0x7d, 0x7e, 0x1e, 0x26, 0x15, 0x7a, 0x74,
    0xfb, 0xb1, 0x7a, 0x0e, 0xd3, 0xb5, 0x7c, 0x8c, 0x3a, 0xd7,
    0x45, 0x38, 0x55, 0xae, 0x4b, 0xe1, 0xfe, 0x5b, 0x57, 0x20,
    0x73, 0x38, 0xb9, 0x67, 0x34, 0xb1, 0xf3, 0x15, 0xb0, 0xb7,
    0x46, 0xa7, 0x1b, 0x19, 0x6d, 0xaf, 0x5e, 0x2c, 0x9c, 0x02,
    0x3f, 0x0f, 0xa3, 0x56, 0x2f, 0x9f, 0x1a, 0x82, 0x0e, 0xb4,
    0x46, 0xf5, 0x69, 0x89, 0x91, 0xf9, 0x2d, 0x99, 0x45, 0xa6,
    0x3c, 0x82, 0x74, 0xac, 0xeb, 0x58, 0x4a, 0xdd, 0x03, 0xaf,
    0xd1, 0x0a, 0xca, 0x4b, 0xe8, 0x4c, 0x63, 0xd4, 0x73, 0x94,
    0xbf, 0xd1, 0xc5, 0x8a, 0x3f, 0x6e, 0x58, 0xfc, 0x70, 0x76,
    0x69, 0x92, 0x05, 0xe0, 0xb9, 0xed, 0x5f, 0x19, 0xd7, 0x6f,
    0xd0, 0x35, 0xbb, 0x5a, 0x8d, 0x45, 0xac, 0x43, 0xcb, 0x74,
    0xcc, 0x92, 0xc3, 0x62, 0x56, 0x02, 0xb0, 0x0a, 0xb6, 0x88,
    0x40, 0x6f, 0x76, 0x1b, 0x89, 0xe4, 0x51, 0xeb, 0x7e, 0x08,
    0x8c, 0xce, 0x24, 0xc8, 0xd8, 0x58, 0xbd, 0x0e, 0x48, 0x57,
    0xc8, 0x9f, 0xad, 0x64, 0xcf, 0x69, 0x72, 0x35, 0xbf, 0x04,
    0x09, 0xfb, 0x0e, 0x62, 0x92, 0x76, 0x8b, 0x8d, 0xd5, 0x16,
    0xa2, 0x51, 0xdb, 0x71, 0xa9, 0x08, 0xb2, 0xf9, 0x1e, 0x07,
    0xe7, 0xf8, 0xf4, 0x79, 0x59, 0x2f, 0x8f, 0xf1, 0x5b, 0x45,
    0xe1, 0xb8, 0xb7, 0xef, 0x86, 0x69, 0x71, 0x51, 0x1c, 0xe5,
    0x61, 0xee, 0xb8, 0x1d, 0xa7, 0xdc, 0x48, 0xba, 0x51, 0xa5,
    0x70, 0x4d, 0xfd, 0x2c, 0x46, 0x21, 0x63, 0x0c, 0x9f, 0xb7,
    0x68, 0x58, 0x7b, 0xb3, 0x7d, 0x64, 0xfd, 0xaf, 0x87, 0x3d,
    0x86, 0x06, 0x36, 0x8a, 0x6d, 0xfe, 0xdf, 0xce, 0xa8, 0x16,
    0x42, 0x46, 0x15, 0xe5, 0xcf, 0x48, 0xa6, 0x4b, 0xe5, 0xc1,
    0xad, 0x14, 0x3a, 0x6d, 0xeb, 0xf9, 0xc9, 0x32, 0xd1, 0x82,
    0x60, 0x23, 0xf0, 0xff, 0xa7, 0xe6, 0x2e, 0xd6, 0x8d, 0x9d,
    0x4f, 0x6d, 0xb3, 0xc4, 0xad, 0xd9, 0xf0, 0xf5, 0x5c, 0x47,
    0x6c, 0x67, 0xf4, 0x0e, 0x18, 0x25, 0xbb, 0x67, 0xfa, 0x11,
    0x70, 0xd5, 0xbc, 0x3a, 0x34, 0xae, 0xa2, 0x76, 0x4b, 0x9f,
    0x59, 0x01, 0x18, 0x69, 0x44, 0xc4, 0x8a, 0xff, 0x00, 0xfc,
    0x2a, 0x45, 0xa9, 0x50, 0x8e, 0x37, 0x6b, 0x78, 0x14, 0x69,
    0xe7, 0x92, 0x3d, 0xf1, 0x34, 0xd5, 0x5c, 0x48, 0xc2, 0x50,
    0xb3, 0x0c, 0x7d, 0x54, 0x05, 0x31, 0x1e, 0xce, 0xaa, 0xc1,
    0x4c, 0xc9, 0x13, 0x33, 0x26, 0x1f, 0x56, 0x7e, 0x7e, 0x74,
    0xd3, 0x78, 0x3e, 0x00, 0x4a, 0xc8, 0xc6, 0x20, 0x5b, 0xb8,
    0x80, 0xb4, 0x13, 0x35, 0x23, 0xff, 0x50, 0xde, 0x25, 0x92,
    0x67, 0x08, 0xb8, 0xa3, 0xb6, 0x39, 0xd4, 0x30, 0xdc, 0xa5,
    0x88, 0x8a, 0x44, 0x08, 0x8b, 0x6d, 0x2e, 0xb8, 0xf3, 0x0d,
    0x23, 0xda, 0x35, 0x08, 0x5a, 0x92, 0xe1, 0x40, 0xac, 0xc7,
    0x15, 0x05, 0x8a, 0xdf, 0xe5, 0x71, 0xd8, 0xe0, 0xd7, 0x9f,
    0x58, 0x03, 0xf4, 0xec, 0x99, 0x3c, 0xb0, 0xe0, 0x07, 0x42,
    0x9b, 0xa0, 0x10, 0x7c, 0x24, 0x60, 0x19, 0xe8, 0x84, 0xd4,
    0xb1, 0x86, 0x19, 0x0a, 0x52, 0x70, 0x6e, 0xc2, 0x3c, 0xe2,
    0x73, 0x8d, 0xfe, 0xf8, 0x7e, 0xdf, 0x78, 0xe7, 0x92, 0x36,
    0x10, 0xf7, 0x2d, 0x76, 0x93, 0x8a, 0x0f, 0x20, 0xc8, 0x30,
    0x59, 0x81, 0xff, 0x3b, 0x70, 0x22, 0xce, 0x6e, 0x23, 0x68,
    0x35, 0x59, 0x0e, 0xcf, 0xf8, 0xf6, 0xcd, 0x45, 0xb6, 0x41,
    0xba, 0xda, 0xe6, 0x35, 0x0b, 0xd1, 0xef, 0xa5, 0x7c, 0xe0,
    0xb9, 0x6f, 0x5b, 0xa9, 0xab, 0x87, 0xe3, 0x3b, 0x92, 0xce,
    0xbe, 0xfe, 0xf7, 0xab, 0x82, 0xa3, 0xe6, 0xbd, 0xfe, 0xce,
    0xa6, 0x17, 0xcb, 0x4c, 0xb4, 0x4c, 0xd6, 0xfe, 0xbb, 0x1c,
    0x10, 0xde, 0x29, 0x3e, 0x92, 0x66, 0x20, 0xf8, 0xee, 0x83,
    0x86, 0x66, 0xe0, 0x66, 0x97, 0x85, 0xaf, 0x3a, 0x8f, 0xa9,
    0x97, 0x09, 0xde, 0x77, 0xda, 0xb7, 0x81, 0x41, 0x10, 0xca,
    0x66, 0x00, 0xec, 0xf8, 0x46, 0x73, 0xa6, 0x24, 0x36, 0xec,
    0x25, 0xbe, 0x93, 0x5e, 0x74, 0x9f, 0xbe, 0xf4, 0x84, 0x15,
    0x9c, 0xc5, 0x43, 0xd9, 0xea, 0x5a, 0xcc, 0x2c, 0x4e, 0x2e,
    0x4e, 0x32, 0xa6, 0x88, 0xb1, 0x25, 0x34, 0xf7, 0xba, 0xab,
    0xd3, 0xa0, 0xc2, 0x06, 0x70, 0xed, 0x66, 0x4d, 0x71, 0x34,
    0xaf, 0x10, 0x99, 0x10, 0x11, 0x4f, 0xe4, 0x7d, 0x42, 0x03,
    0x04, 0x02, 0xc2, 0x41, 0x85, 0x1e, 0xc4, 0xca, 0xae, 0xf0,
    0x83, 0x78, 0x34, 0x98, 0x55, 0x8b, 0x4c, 0xa0, 0x14, 0xea,
    0x15, 0x2c, 0xa1, 0x30, 0xd8, 0xcf, 0xac, 0xd4, 0xca, 0xf7,
    0xf4, 0xc4, 0x20, 0xca, 0xa1, 0xef, 0xce, 0x5d, 0x6b, 0x32,
    0xb6, 0xf0, 0x22, 0x08, 0x49, 0x21, 0x0c, 0x57, 0x0f, 0xf8,
    0xc0, 0xd2, 0xe3, 0xc0, 0xa6, 0x31, 0xc7, 0x87, 0x96, 0xa9,
    0xfe, 0x69, 0xa0, 0x7f, 0xf7, 0x8e, 0x31, 0x92, 0x37, 0xce,
    0xde, 0x36, 0x3f, 0xf5, 0x7d, 0x07, 0xaa, 0xa9, 0x43, 0xee,
    0x3c, 0x8c, 0xd3, 0x7d, 0x2c, 0xa6, 0xc3, 0x98, 0xab, 0xbe,
    0x90, 0x4c, 0xa5, 0x5a, 0x27, 0xeb, 0x0e, 0xed, 0xa1, 0x1e,
    0x3e, 0x44, 0xa3, 0x4b, 0x49, 0xad, 0xe4, 0x19, 0x90, 0xc8,
    0x9e, 0x6e, 0x5b, 0x68, 0xbc, 0x37, 0x54, 0xaf, 0xa6, 0xb7,
    0x71, 0x5c, 0x5d, 0x74, 0x83, 0xf4, 0xb9, 0x2f, 0xe5, 0x1a,
    0x0c, 0x73, 0x30, 0x56, 0x82, 0x04, 0xb3, 0x0e, 0x32, 0x98,
    0xfd, 0x27, 0xa0, 0xfe, 0xe0, 0xe0, 0xf5, 0xb7, 0xe0, 0x47,
    0x2a, 0xa6, 0x4a, 0xe0, 0xfc, 0xb5, 0xd8, 0xfd, 0x01, 0xfe,
    0x4e, 0x96, 0x17, 0x06, 0xcc, 0x92, 0x7c, 0xa1, 0x2f, 0xb5,
    0x04, 0x08, 0x76, 0xcc, 0x40, 0x75, 0x37, 0x4d, 0x2c, 0x74,
    0xcd, 0xc7, 0x62, 0xa6, 0xe6, 0xd8, 0x9e, 0x21, 0x7f, 0x2e,
    0xf5, 0x2c, 0xcf, 0x0b, 0x3f, 0xd7, 0xed, 0x17, 0xee, 0x92,
    0xaf, 0xf9, 0xa4, 0x71, 0x5d, 0x5f, 0x81, 0xb9, 0x2f, 0x12,
    0xe5, 0x57, 0x2d, 0x1e, 0xf1, 0x67, 0x47, 0x2a, 0xde, 0xab,
    0xf2, 0xea, 0xb7, 0xb5, 0x83, 0xdc, 0x46, 0xd4, 0xf3, 0x25,
    0x65, 0x15, 0x4d, 0x66, 0x34, 0x54, 0xab, 0x94, 0x89, 0x80,
    0x39, 0xd3, 0x39, 0xe3, 0xa2, 0xb1, 0x91, 0x2a, 0x5e, 0x55,
    0xe1, 0xa4, 0x0f, 0xc3, 0x4b, 0x5a, 0xa5, 0x4a, 0xb3, 0xc0,
    0x40, 0xea, 0x16, 0x0c, 0xd5, 0x2d, 0x83, 0x3e, 0x28, 0x20,
    0xac, 0x0a, 0x1b, 0x5b, 0x87, 0xcf, 0xf1, 0x51, 0xd6, 0xda,
    0xd1, 0xc9, 0xb1, 0x27, 0xf5, 0x62, 0x03, 0x10, 0xcf, 0x76,
    0x28, 0xa2, 0xea, 0x4b, 0x76, 0xaf, 0x9c, 0x3d, 0xf1, 0x1b,
    0x92, 0xff, 0xb0, 0xca, 0x16, 0xa2, 0x29, 0x94, 0x0e, 0x1e,
    0x51, 0xfb, 0xe1, 0x2b, 0x5a, 0x50, 0xfd, 0xaf, 0xab, 0xd7,
    0x32, 0xaa, 0x43, 0xa7, 0xcb, 0xd3, 0xd3, 0xe9, 0x1e, 0xb1,
    0x70, 0xd2, 0xbb, 0x15, 0x68, 0x49, 0xee, 0x6e, 0x1e, 0xc5,
    0x64, 0x4b, 0x26, 0x08, 0xe7, 0x32, 0x1c, 0x1d, 0x73, 0x8f,
    0x42, 0xfe, 0xeb, 0x67, 0x89, 0x42, 0x25, 0x40, 0xd6, 0x15,
    0x02, 0x55, 0x87, 0xe3, 0x87, 0xdd, 0x78, 0xc1, 0x01, 0x94,
    0xbc, 0x30, 0x5f, 0xbd, 0x89, 0xe1, 0xb0, 0x5c, 0xcd, 0xb7,
    0x68, 0xd5, 0xbb, 0xf4, 0xa0, 0x5d, 0x3d, 0xdd, 0x89, 0x12,
    0xc7, 0xb8, 0x5d, 0x51, 0x8a, 0xf4, 0xd5, 0x05, 0xc6, 0xdd,
    0x7b, 0x44, 0x38, 0xce, 0xb1, 0x24, 0x24, 0xe1, 0x9d, 0xc7,
    0x80, 0x86, 0x46, 0x2a, 0xd2, 0xa4, 0x0f, 0xec, 0xd3, 0x6b,
    0x31, 0xc0, 0x05, 0x31, 0xff, 0xf5, 0x1a, 0x33, 0x35, 0x68,
    0x2e, 0x68, 0x24, 0xbd, 0x62, 0xfc, 0x46, 0x79, 0x54, 0x5e,
    0x1e, 0x27, 0x93, 0x07, 0xed, 0x78, 0x94, 0x50, 0x42, 0x98,
    0x53, 0x88, 0xb7, 0x57, 0x04, 0x7d, 0xe2, 0xe1, 0xb5, 0x61,
    0x9e, 0x5a, 0x88, 0x31, 0x3e, 0x6c, 0x69, 0xbc, 0x8a, 0xe6,
    0xbc, 0x9d, 0x20, 0x7a, 0x86, 0xe5, 0x73, 0x93, 0x02, 0xc5,
    0xde, 0xdc, 0xcc, 0xbf, 0x89, 0x76, 0xdc, 0x4e, 0xa1, 0x89,
    0xe7, 0x95, 0x75, 0x01, 0xf7, 0x43, 0xaa, 0x3f, 0x1b, 0xb7,
    0x8c, 0x92, 0x66, 0x22, 0xbe, 0x34, 0xf1, 0x2f, 0xc3, 0xc7,
    0x21, 0xaf, 0x25, 0x57, 0x9a, 0x2c, 0x80, 0xf0, 0xb3, 0xdd,
    0xb3, 0xb2, 0x82, 0x97, 0x85, 0x73, 0xa9, 0x76, 0xe4, 0x37,
    0xa2, 0x65, 0xf9, 0xc1, 0x3d, 0x11, 0xbf, 0xcb, 0x3c, 0x8e,
    0xdd, 0xaf, 0x98, 0x57, 0x6a, 0xe1, 0x33, 0xe7, 0xf0, 0xff,
    0xed, 0x61, 0x53, 0xfe, 0x1e, 0x2d, 0x06, 0x2f, 0xb8, 0x9e,
    0xf9, 0xa5, 0x21, 0x06, 0xf3, 0x72, 0xf6, 0xa3, 0x77, 0xbb,
    0x63, 0x6e, 0x52, 0xb2, 0x42, 0x47, 0x9b, 0x92, 0x4c, 0xf8,
    0xd2, 0xe6, 0x02, 0xa5, 0x57, 0x2d, 0x6f, 0x30, 0x05, 0xe2,
    0xfd, 0x33, 0xe5, 0xb6, 0x23, 0x85, 0x89, 0x4a, 0x99, 0x20,
    0x33, 0xea, 0x2f, 0xcd, 0x28, 0x27, 0xff, 0xfd, 0x2e, 0x73,
    0x52, 0x29, 0x19, 0x7c, 0x65, 0xf5, 0x6a, 0xaa, 0x97, 0x6e,
    0xe9, 0x42, 0xa8, 0x55, 0x97, 0x56, 0x92, 0x9d, 0xd2, 0xd1,
    0xc4, 0x30, 0xaa, 0x95, 0x86, 0xba, 0x71, 0xdd, 0x2f, 0xf1,
    0xed, 0x66, 0x54, 0x78, 0x4b, 0x13, 0x31, 0xed, 0x9d, 0x2c,
    0xae, 0x0a, 0xc3, 0xca, 0xfb, 0x3f, 0x92, 0x92, 0x30, 0xa3,
    0x8e, 0xc8, 0x6d, 0x7b, 0x42, 0xd5, 0x5d, 0x99, 0x79, 0x42,
    0x28, 0x63, 0x9f, 0x97, 0x8e, 0x94, 0x6d, 0x1d, 0xb4, 0x21,
    0x39, 0xc7, 0x64, 0x48, 0x44, 0x5e, 0x15, 0x10, 0x45, 0x9f,
    0x8a, 0x01, 0x45, 0x20, 0x5c, 0xd1, 0x28, 0x0d, 0xe9, 0xfb,
    0xa9, 0x72, 0x68, 0x07, 0x31, 0x20, 0x75, 0x76, 0x82, 0x76,
    0x5d, 0x7c, 0xc1, 0x5d, 0x42, 0x40, 0xfd, 0x06, 0xa9, 0x66,
    0xb0, 0x36, 0x55, 0x86, 0x6c, 0x96, 0xbd, 0xb8, 0xf7, 0x36,
    0x87, 0xf2, 0xa1, 0x37, 0xd8, 0x2d, 0x83, 0xf5, 0xdc, 0xd8,
    0xde, 0x9e, 0x69, 0xd6, 0xe1, 0x0d, 0xd5, 0x93, 0xc5, 0xee,
    0xba, 0xd3, 0x40, 0x71, 0xbb, 0xc7, 0xbb, 0x50, 0x1a, 0x10,
    0x80, 0x99, 0x62, 0x1c, 0xe3, 0x1f, 0xa2, 0xcc, 0x98, 0xe1,
    0xaa, 0xff, 0xd9, 0x69, 0xe7, 0x87, 0x04, 0x87, 0x76, 0xec,
    0x55, 0x18, 0xaf, 0x82, 0x34, 0x4d, 0x4f, 0xf7, 0x57, 0x1f,
    0xa5, 0x43, 0xcc, 0xe9, 0x7a, 0x4a, 0xc8, 0xb4, 0x1f, 0x61,
    0x40, 0x5e, 0x1d, 0x11, 0xdd, 0xdc, 0xdc, 0xb4, 0x57, 0xf9,
    0x47, 0x96, 0xbc, 0x47, 0x29, 0xf8, 0xf2, 0x43, 0xc4, 0xa0,
    0x8c, 0x14, 0x5e, 0x73, 0x52, 0xac, 0xac, 0x39, 0x3b, 0x06,
    0x19, 0x1a, 0xca, 0x22, 0xc8, 0x96, 0x12, 0x2e, 0x4c, 0x7b,
    0xa0, 0x96, 0x53, 0x16, 0xce, 0x6d, 0x6e, 0xac, 0xb2, 0x07,
    0x17, 0x22, 0x07, 0x30, 0x20, 0x84, 0x9b, 0x0e, 0x92, 0x31,
    0x07, 0xe2, 0x77, 0xcd, 0x6a, 0x3e, 0x16, 0x4f, 0xd6, 0x12,
    0x88, 0x8a, 0x70, 0x5a, 0x87, 0xd8, 0xb9, 0xef, 0x76, 0xab,
    0x14, 0x65, 0x87, 0x3a, 0xef, 0xd8, 0x0e, 0x24, 0x40, 0x73,
    0x93, 0x2b, 0xbf, 0xac, 0xfe, 0x96, 0x8a, 0x9d, 0x12, 0xe6,
    0xc1, 0x5b, 0x00, 0x3b, 0x23, 0xee, 0xe2, 0x10, 0xb6, 0xbe,
    0x0e, 0x2f, 0xa2, 0x77, 0x16, 0x17, 0xfc, 0x4b, 0x2c, 0xd7,
    0x9c, 0xad, 0x66, 0xb4, 0xf2, 0xfd, 0xc1, 0xaf, 0x81, 0x12,
    0xd9, 0xed, 0x14, 0x32, 0xcf, 0x1b, 0xee, 0xc6, 0x63, 0xe8,
    0xe5, 0xe6, 0xb6, 0x91, 0x8d, 0x1b, 0x90, 0x75, 0x5d, 0x69,
    0x4c, 0x5d, 0xd6, 0xac, 0x79, 0xe8, 0xb6, 0xdf, 0xbf, 0x43,
    0x39, 0xd3, 0xb8, 0xf0, 0x39, 0xf4, 0x90, 0xaf, 0x73, 0x26,
    0xc7, 0x73, 0x6f, 0x93, 0xbb, 0xce, 0x6e, 0xdc, 0x1c, 0xd0,
    0x36, 0x23, 0x17, 0xb2, 0x39, 0x37, 0x15, 0xf5, 0x3a, 0x61,
    0xa9, 0x15, 0x52, 0x6e, 0xc5, 0x3a, 0x63, 0x79, 0x5d, 0x45,
    0xdc, 0x3a, 0xd5, 0x26, 0x01, 0x56, 0x97, 0x80, 0x7f, 0x83,
    0xf9, 0xec, 0xde, 0xa0, 0x2e, 0x7a, 0xb2, 0x4b, 0x04, 0x63,
    0x60, 0x05, 0xce, 0x96, 0xeb, 0xe0, 0x0a, 0x5f, 0xb0, 0x7e,
    0x6d, 0x0a, 0x24, 0x32, 0x47, 0x82, 0x7f, 0x0b, 0xd7, 0xe9,
    0xd5, 0x14, 0xa9, 0x6b, 0x10, 0x5d, 0x1e, 0x1f, 0x8a, 0xad,
    0x70, 0x91, 0xd4, 0x33, 0x1d, 0xc2, 0x3e, 0xf8, 0xc8, 0x52,
    0x9a, 0x27, 0x1f, 0x45, 0x2f, 0xb5, 0xc7, 0xb1, 0x8b, 0xf9,
    0xc6, 0x7b, 0xb5, 0x92, 0x7a, 0xdd, 0xeb, 0x07, 0x6c, 0x6f,
    0x11, 0xd7, 0x5b, 0x56, 0x56, 0xec, 0x88, 0x1c, 0xc9, 0xb4,
    0xe8, 0x43, 0xab, 0xdf, 0x0b, 0xc5, 0x28, 0xba, 0x70, 0x5d,
    0xd3, 0xb2, 0xe2, 0xcf, 0xa7, 0xbb, 0x53, 0x04, 0x6b, 0x73,
    0xdf, 0x27, 0xa6, 0x63, 0x58, 0xe1, 0x39, 0x26, 0x2a, 0x1a,
    0x21, 0xec, 0xbb, 0x5f, 0x46, 0x98, 0x3d, 0x48, 0x66, 0xfe,
    0xf3, 0xcb, 0xfc, 0x6e, 0x99, 0x82, 0x91, 0xce, 0x53, 0xfd,
    0x75, 0xc9, 0xb6, 0x08, 0xa8, 0xf3, 0xe4, 0xe0, 0xa0, 0x24,
    0x45, 0xb4, 0x69, 0x11, 0xac, 0x06, 0x1c, 0x39, 0x71, 0xcf,
    0x72, 0xfc, 0x77, 0x9b, 0x5f, 0xf4, 0x8b, 0x02, 0x31, 0xf3,
    0x67, 0xd1, 0x9b, 0xe0, 0x49, 0xa4, 0x69, 0x20, 0x99, 0x38,
    0xa7, 0xf5, 0x43, 0xd2, 0x45, 0x9f, 0x7a, 0xe7, 0xad, 0x7e,
    0x36, 0xee, 0xfd, 0x8c, 0xc5, 0x6a, 0x12, 0x58, 0x15, 0x3b,
    0x02, 0x81, 0x73, 0x8b, 0x10, 0xda, 0x21, 0xc7, 0x1d, 0x38,
    0xd8, 0x40, 0x7a, 0xa3, 0x59, 0x55, 0x35, 0x44, 0xa9, 0x9c,
    0xf5, 0xf4, 0xe4, 0x14, 0xc1, 0xc4, 0x15, 0x26, 0x01, 0xe3,
    0x31, 0xbf, 0xdc, 0xbc, 0x69, 0x0b, 0xcf, 0x71, 0x8c, 0xdb,
    0x16, 0xab, 0x36, 0x3e, 0xb3, 0xa4, 0x9f, 0xcc, 0xbf, 0xa2,
    0x93, 0x93, 0x9a, 0x3b, 0xaf, 0x72, 0x8d, 0x8b, 0x92, 0x44,
    0x5d, 0x6f, 0xc5, 0xf0, 0xdc, 0x65, 0x62, 0xea, 0xba, 0x33,
    0xe7, 0x6c, 0xa4, 0x35, 0xcf, 0xd9, 0xbc, 0x3c, 0xbf, 0x25,
    0x7b, 0x7c, 0x0b, 0x62, 0x92, 0x5a, 0x66, 0x63, 0xe1, 0x27,
    0x89, 0x12, 0xe2, 0xae, 0xb7, 0xf8, 0x04, 0x70, 0xda, 0x4a,
    0x3d, 0xa6, 0x67, 0x12, 0x14, 0x9e, 0x8e, 0xdc, 0xa2, 0xf2,
    0x3d, 0xc7, 0xd2, 0x8f, 0x18, 0x3a, 0x53, 0x8c, 0x83, 0x5d,
    0x66, 0xbb, 0x9f, 0x8c, 0xaf, 0xa8, 0x73, 0x08, 0x2e, 0x6d,
    0x30, 0xa0, 0xd0, 0x20, 0x94, 0x48, 0xad, 0x5e, 0x31, 0xfd,
    0x5e, 0xfd, 0xf9, 0xb5, 0xa2, 0x39, 0xa3, 0xb9, 0xdf, 0x4d,
    0xa4, 0xb1, 0x54, 0xcc, 0x92, 0x63, 0x2c, 0x66, 0x2d, 0x01,
    0x88, 0x8b, 0x7d, 0xc6, 0x5c, 0x9f, 0x18, 0x9a, 0x53, 0x91,
    0x59, 0x66, 0x70, 0xd7, 0x81, 0x0e, 0xa1, 0x3c, 0x7e, 0x86,
    0x85, 0x64, 0x38, 0x6f, 0xec, 0x76, 0x57, 0x80, 0x41, 0x9d,
    0xef, 0x61, 0xb8, 0xb2, 0x8a, 0xeb, 0xe9, 0x26, 0xbb, 0x69,
    0xb3, 0x8d, 0xd4, 0x6b, 0x05, 0xd8, 0x55, 0x1c, 0xbd, 0x9f,
    0x6b, 0x23, 0x46, 0x2b, 0xf7, 0xfb, 0x4d, 0x33, 0x3b, 0x21,
    0x6d, 0xea, 0x1b, 0x15, 0xaf, 0x0f, 0x8c, 0x98, 0xc8, 0xf4,
    0xd1, 0x3c, 0xdd, 0x21, 0xd0, 0x45, 0xdc, 0xaf, 0x89, 0x89,
    0xbf, 0xde, 0xbf, 0x46, 0x9e, 0x9e, 0x18, 0x56, 0x9d, 0x05,
    0x4d, 0x63, 0x5f, 0x1c, 0xd9, 0x15, 0xd1, 0x43, 0x17, 0x0c,
    0x48, 0x3d, 0x36, 0x8b, 0x14, 0x87, 0xc8, 0x10, 0x44, 0xdf,
    0x9c, 0xfd, 0x6e, 0x88, 0x88, 0xae, 0x7f, 0x7f, 0x67, 0xa3,
    0x33, 0x4d, 0xa3, 0x84, 0x8b, 0x58, 0x07, 0x17, 0xd8, 0x1d,
    0x9e, 0x43, 0xd6, 0x41, 0x9c, 0xff, 0xfa, 0x35, 0xa2, 0x42,
    0xa9, 0x5d, 0xa9, 0x4b, 0x95, 0x23, 0x6a, 0x6e, 0x42, 0xd7,
    0xa2, 0x0a, 0x70, 0x00, 0x61, 0x8b, 0x45, 0xbb, 0xac, 0x20,
    0x27, 0xcd, 0xfc, 0x61, 0x17, 0xfe, 0xab, 0x6b, 0xe8, 0xe0,
    0x51, 0xab, 0xa3, 0xbf, 0xe4, 0x85, 0x69, 0x8e, 0xd7, 0xa6,
    0x62, 0x33, 0x8f, 0x7c, 0xba, 0x48, 0xfa, 0x83, 0x94, 0xa5,
    0xdf, 0xa1, 0x76, 0xdc, 0xa9, 0x4b, 0x3c, 0x27, 0xff, 0xd9,
    0xbe, 0xf4, 0x80, 0x5a, 0xca, 0x33, 0xf3, 0x9a, 0x1d, 0xf8,
    0xf3, 0xe1, 0x83, 0x27, 0x0b, 0x59, 0x87, 0x31, 0x7d, 0x4f,
    0x5a, 0x5e, 0xe1, 0xbe, 0xa9, 0x68, 0xe9, 0x6f, 0x10, 0x0a,
    0xe2, 0x70, 0x05, 0xaa, 0xcb, 0xdd, 0x41, 0xd7, 0x49, 0x8a,
    0x98, 0xa0, 0x40, 0x2d, 0xc6, 0x56, 0x49, 0xca, 0x60, 0x16,
    0x9c, 0x38, 0xc9, 0xfe, 0x99, 0x15, 0xfb, 0x79, 0x01, 0x33,
    0xcd, 0x54, 0x2f, 0xf3, 0x70, 0x37, 0x82, 0x36, 0x32, 0x76,
    0x8f, 0x63, 0x00, 0xa2, 0x42, 0xce, 0x39, 0x90, 0xfc, 0xf8,
    0xff, 0x34, 0x38, 0x0a, 0x17, 0x5e, 0x9d, 0x34, 0x86, 0xde,
    0x33, 0x45, 0xac, 0xbf, 0x81, 0xdf, 0xd2, 0xbc, 0xc7, 0xd7,
    0xd1, 0xee, 0xde, 0x2b, 0x5b, 0x50, 0x56, 0xb5, 0x88, 0x00,
    0x92, 0x76, 0x5a, 0x34, 0x0c, 0xfe, 0x8f, 0xc5, 0xa0, 0x92,
    0xb0, 0xed, 0x43, 0xe7, 0x81, 0x39, 0x36, 0x6e, 0xb7, 0x4d,
    0x5b, 0xcf, 0xc7, 0xf0, 0x83, 0xe5, 0xdc, 0xb7, 0x74, 0xf4,
    0xf3, 0xbd, 0xa8, 0xa6, 0x7b, 0xe0, 0xc5, 0x50, 0xaa, 0xc7,
    0x83, 0x4d, 0xd9, 0xc5, 0x97, 0x03, 0x7c, 0x0c, 0x3b, 0x3a,
    0x18, 0xb2, 0x8c, 0xee, 0x67, 0x91, 0x38, 0x84, 0x8f, 0xef,
    0xb4, 0xf4, 0xe4, 0x7c, 0x1a, 0x3f, 0xa3, 0x0a, 0xd9, 0xba,
    0xff, 0x56, 0xd8, 0xe2, 0x82, 0xfc, 0x58, 0x8f, 0xf6, 0x12,
    0x10, 0x65, 0x6a, 0x68, 0x53, 0x2d, 0x9f, 0x2c, 0x77, 0xd1,
    0xb8, 0x21, 0x8a, 0xcb, 0xe9, 0xd4, 0x25, 0x18, 0x22, 0x46,
    0x3e, 0x72, 0x29, 0x2a, 0x68, 0x70, 0x73, 0xe2, 0x61, 0xa2,
    0xa8, 0x1f, 0x24, 0x48, 0x92, 0xa0, 0xd4, 0xdd, 0xde, 0xe5,
    0x02, 0x1b, 0x59, 0x5c, 0x7e, 0x92, 0x9c, 0xd8, 0xf4, 0x2d,
    0x6b, 0x79, 0x7b, 0xc7, 0xcd, 0xef, 0x21, 0x2a, 0x50, 0x7e,
    0xba, 0xdd, 0x02, 0x45, 0x7e, 0xc1, 0xdd, 0xeb, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x03, 0x0c, 0x15, 0x1c, 0x22, 0x28,
};
static const int sizeof_bench_dilithium_level3_sig =
    sizeof(bench_dilithium_level3_sig);
#endif

#ifndef WOLFSSL_NO_ML_DSA_87
static const unsigned char bench_dilithium_level5_sig[] = {
    0x78, 0xed, 0x1a, 0x3f, 0x41, 0xab, 0xf8, 0x93, 0x80, 0xf0,
    0xc6, 0xbf, 0x4a, 0xde, 0xaf, 0x29, 0x93, 0xe5, 0x9a, 0xbf,
    0x38, 0x08, 0x18, 0x33, 0xca, 0x7d, 0x5e, 0x65, 0xa4, 0xd2,
    0xd7, 0x45, 0xe3, 0xe7, 0x58, 0xfb, 0x05, 0xab, 0x65, 0x57,
    0xac, 0x6f, 0xf5, 0x43, 0x28, 0x5f, 0x9c, 0x9a, 0x3e, 0x35,
    0x84, 0xe4, 0xef, 0xa5, 0x57, 0x17, 0xad, 0x51, 0x44, 0x70,
    0x09, 0x00, 0x81, 0xbe, 0xfe, 0x14, 0x01, 0xfe, 0x0c, 0x94,
    0xbe, 0xa9, 0x89, 0xfd, 0x47, 0xfc, 0xb9, 0xd8, 0x17, 0x4d,
    0xd8, 0x73, 0xd5, 0x50, 0x9f, 0x13, 0x6c, 0x07, 0x71, 0x47,
    0xaa, 0x3c, 0xc0, 0x64, 0x00, 0x19, 0x2e, 0x74, 0x51, 0x0e,
    0x0f, 0x25, 0x30, 0x7f, 0x13, 0x96, 0xc6, 0xc5, 0xbf, 0xd4,
    0x82, 0xd3, 0x0d, 0xd3, 0x65, 0x4c, 0x72, 0x67, 0xe2, 0x37,
    0x6b, 0x3c, 0x8e, 0xa3, 0x36, 0x84, 0xe9, 0xaa, 0xac, 0x7d,
    0xf3, 0xac, 0xfc, 0x01, 0x50, 0x87, 0x88, 0xf6, 0xbf, 0x84,
    0xc3, 0xa0, 0x23, 0xe4, 0xe8, 0x01, 0x38, 0x39, 0x30, 0x8a,
    0xf3, 0xba, 0x92, 0x62, 0x37, 0xd7, 0x20, 0xd7, 0xf7, 0x41,
    0xff, 0xae, 0x81, 0x02, 0x29, 0x2a, 0x66, 0x8b, 0x20, 0xbe,
    0x61, 0x8d, 0xfb, 0x7c, 0x70, 0x14, 0xad, 0xf4, 0x94, 0x8c,
    0xee, 0x64, 0x3b, 0x9f, 0xe1, 0x6e, 0x68, 0x17, 0x07, 0xb8,
    0xfc, 0x99, 0xdc, 0xde, 0x69, 0x58, 0x8c, 0x97, 0x7d, 0xb3,
    0x2c, 0x9e, 0x90, 0x33, 0x2e, 0x7b, 0xbf, 0xf8, 0x6f, 0xf8,
    0x12, 0x64, 0xda, 0xc0, 0xfb, 0x30, 0xe6, 0xbf, 0x7b, 0x9a,
    0xde, 0xb5, 0xac, 0x9d, 0x6b, 0xcb, 0xe1, 0x0d, 0xf1, 0xbb,
    0xf3, 0x97, 0xc5, 0x08, 0xd3, 0x3e, 0xe3, 0xa4, 0xeb, 0x6f,
    0x6b, 0x62, 0x61, 0xc5, 0x0b, 0xa8, 0x02, 0xc2, 0xf1, 0xbe,
    0xbb, 0x93, 0x13, 0xa5, 0x8d, 0x7b, 0x5a, 0x6d, 0x1f, 0x28,
    0xbc, 0x35, 0xd8, 0xe8, 0xcf, 0x80, 0x8b, 0x4b, 0x02, 0x80,
    0x3b, 0xdc, 0x00, 0xce, 0x88, 0xb0, 0x62, 0x35, 0x7d, 0x51,
    0x7f, 0x5c, 0xb2, 0x23, 0x85, 0x47, 0x7e, 0x73, 0x88, 0x65,
    0xfd, 0x0d, 0x47, 0x33, 0xef, 0xb9, 0x75, 0x05, 0x86, 0x5d,
    0xd3, 0x98, 0xa6, 0x91, 0xe6, 0x8c, 0xe2, 0x71, 0x7a, 0x95,
    0xe0, 0x8c, 0x54, 0x4b, 0x68, 0x4d, 0x5a, 0xec, 0xad, 0xae,
    0x54, 0x4e, 0x3b, 0x0e, 0xcd, 0x70, 0xe6, 0x81, 0xbf, 0xf4,
    0x86, 0xab, 0xfe, 0xd8, 0xed, 0x69, 0xdd, 0x0f, 0x75, 0x8f,
    0x8e, 0xcd, 0x72, 0x40, 0x21, 0xee, 0x80, 0x6f, 0x9e, 0xa0,
    0x80, 0xf7, 0xf6, 0xa2, 0xf5, 0x04, 0x82, 0xea, 0xb6, 0xb1,
    0xa3, 0xfe, 0xa2, 0x2d, 0x83, 0xc7, 0x01, 0x4b, 0x27, 0x19,
    0x6a, 0x31, 0x04, 0x70, 0xce, 0x75, 0x22, 0x4b, 0x7a, 0x21,
    0x29, 0xfd, 0xe9, 0xcb, 0xbb, 0xca, 0x95, 0x0a, 0xd8, 0xcd,
    0x20, 0x2a, 0xb7, 0xbe, 0xdf, 0x2f, 0x0f, 0xfa, 0xf1, 0xc0,
    0x39, 0xf3, 0x74, 0x22, 0x05, 0x33, 0xca, 0x2a, 0x9c, 0x9f,
    0x06, 0x71, 0x90, 0x1e, 0x74, 0x4b, 0xbe, 0x9a, 0xc7, 0x1e,
    0x37, 0x9b, 0x96, 0x19, 0xfd, 0xa0, 0x61, 0x87, 0x93, 0xab,
    0x75, 0x79, 0xac, 0x2f, 0x83, 0xe1, 0x8c, 0x70, 0x54, 0x70,
    0x01, 0x93, 0xce, 0x76, 0x7a, 0x08, 0xe7, 0x75, 0xfb, 0x5e,
    0xa4, 0xcc, 0xd6, 0xeb, 0x90, 0xe2, 0x57, 0x07, 0x53, 0x88,
    0x8f, 0x7f, 0x29, 0x39, 0x80, 0xc4, 0x7f, 0x70, 0x6f, 0xff,
    0x44, 0x25, 0x2b, 0x9e, 0xa1, 0xbb, 0xda, 0x43, 0x53, 0x14,
    0xf8, 0x97, 0x08, 0xa4, 0xaf, 0xa0, 0xa5, 0x0c, 0xfa, 0xcc,
    0xba, 0xcd, 0x4f, 0xd3, 0x90, 0x28, 0x02, 0x25, 0xbe, 0xc6,
    0x35, 0x66, 0x99, 0xb0, 0x69, 0x46, 0xe5, 0xbf, 0x7e, 0x4f,
    0x53, 0x11, 0x1f, 0xa5, 0x2c, 0x9b, 0xd1, 0x70, 0x90, 0x34,
    0x66, 0xaa, 0x9f, 0xa8, 0x02, 0x3a, 0x05, 0x2b, 0x0a, 0xd0,
    0x72, 0x5d, 0x01, 0x7b, 0x02, 0xce, 0x18, 0xb9, 0x63, 0xd1,
    0x7d, 0xd2, 0x34, 0xa3, 0x2d, 0xaa, 0x78, 0xf0, 0x30, 0x6e,
    0x59, 0xe3, 0xf1, 0x1e, 0xf1, 0x33, 0x41, 0xde, 0xc4, 0x4e,
    0x88, 0x61, 0xc3, 0xb4, 0x6b, 0x21, 0x5d, 0xcc, 0x69, 0x44,
    0xf3, 0xb0, 0x84, 0x54, 0x2a, 0x23, 0x22, 0xa2, 0xc4, 0xba,
    0xad, 0x00, 0x57, 0x5b, 0xdf, 0xa0, 0xf7, 0x1c, 0x00, 0xc3,
    0x23, 0x93, 0xc0, 0x2f, 0x3b, 0x9d, 0x6e, 0x8c, 0x38, 0xa6,
    0x5e, 0xd8, 0x98, 0x7a, 0x6c, 0x90, 0xd5, 0x40, 0x3f, 0x8c,
    0xc3, 0xf0, 0x92, 0x66, 0xc4, 0xe5, 0xa8, 0x42, 0x25, 0x4c,
    0x56, 0x42, 0x37, 0x9a, 0xa4, 0x1d, 0xf5, 0xb0, 0xe3, 0x8a,
    0x9c, 0x57, 0x52, 0x63, 0xdc, 0xd9, 0xb0, 0xbf, 0xc3, 0xfc,
    0xfc, 0x6c, 0xab, 0x41, 0xae, 0xec, 0xc7, 0x40, 0x80, 0xb6,
    0x0b, 0x3c, 0xa9, 0xf5, 0x4f, 0x2d, 0xf6, 0x72, 0xe3, 0xba,
    0x13, 0x2c, 0x73, 0x61, 0x98, 0x66, 0x6f, 0x03, 0x88, 0x3b,
    0xe6, 0x95, 0x43, 0x33, 0x3b, 0xfe, 0xfd, 0x63, 0x8c, 0x00,
    0x8a, 0x67, 0x1c, 0x46, 0x0e, 0x0b, 0x51, 0x26, 0x79, 0x4f,
    0x7b, 0xb1, 0x36, 0x34, 0x52, 0x41, 0x7e, 0x74, 0xbb, 0x71,
    0x52, 0x8f, 0xcc, 0xf2, 0x99, 0x24, 0x3f, 0x18, 0xe6, 0xcf,
    0xdf, 0x6b, 0xfe, 0x77, 0xfa, 0xa8, 0x3f, 0xe3, 0x6b, 0xb7,
    0x32, 0x30, 0x8e, 0x16, 0x08, 0x59, 0x66, 0xdf, 0x95, 0x75,
    0x7d, 0xa3, 0x80, 0xf0, 0x0c, 0x1a, 0xa8, 0xe7, 0x87, 0x2f,
    0xe3, 0x39, 0x11, 0x82, 0x00, 0x3e, 0xe5, 0x71, 0x05, 0x7d,
    0x0c, 0x90, 0xae, 0xbc, 0xbf, 0xe0, 0x4b, 0x8f, 0x91, 0x85,
    0x1d, 0x0a, 0xa2, 0x36, 0x66, 0x18, 0x78, 0xd0, 0x0a, 0xa0,
    0xaf, 0x0f, 0x1c, 0x01, 0xdb, 0xb2, 0x21, 0x96, 0x25, 0xf7,
    0x9e, 0x3a, 0x9e, 0xc3, 0xe8, 0x92, 0x34, 0xaf, 0x7e, 0x3b,
    0x5f, 0xd9, 0x23, 0x97, 0x09, 0xf1, 0x87, 0x31, 0x3a, 0x94,
    0xc8, 0x9b, 0x52, 0xf4, 0x57, 0x54, 0x7b, 0x3e, 0x50, 0xd3,
    0x75, 0x2a, 0xba, 0x97, 0xd7, 0xec, 0x95, 0x6c, 0x35, 0x63,
    0xa4, 0xa1, 0x8f, 0xf5, 0xcc, 0xbe, 0x42, 0x65, 0x4e, 0x69,
    0x35, 0x55, 0xa5, 0x3e, 0xc4, 0xf0, 0xde, 0x60, 0x54, 0xdf,
    0xbb, 0x83, 0xad, 0xdf, 0xa5, 0x24, 0x8f, 0xbe, 0x0b, 0x16,
    0xfc, 0xf2, 0x64, 0xd5, 0x79, 0x68, 0xf3, 0x91, 0x81, 0x2a,
    0xd7, 0x1c, 0xc0, 0xdd, 0xe6, 0xb6, 0xb3, 0xa2, 0x4f, 0xc0,
    0x6d, 0x77, 0x02, 0xee, 0x43, 0xd6, 0x5e, 0x82, 0x66, 0x7f,
    0xb4, 0xe6, 0x5c, 0xff, 0x87, 0x1e, 0x1d, 0x6f, 0x1d, 0x96,
    0x6d, 0xbd, 0x90, 0x57, 0x65, 0xc2, 0x01, 0x35, 0xfa, 0x9a,
    0xc6, 0xe0, 0x4e, 0x2c, 0x4b, 0x16, 0xfa, 0x0d, 0x38, 0x87,
    0x39, 0x2c, 0x2b, 0x48, 0x14, 0x92, 0x3d, 0x83, 0x00, 0xa9,
    0x1a, 0x3d, 0x4d, 0x30, 0x23, 0x48, 0xcd, 0xd5, 0xcd, 0x01,
    0xb1, 0x45, 0x85, 0xcc, 0x66, 0x47, 0x1d, 0x63, 0x3d, 0x70,
    0xb8, 0x0c, 0xfd, 0xe3, 0xb2, 0x0f, 0x64, 0x6e, 0xb9, 0x2b,
    0xe5, 0xb0, 0x4d, 0x44, 0x4d, 0x66, 0x1a, 0xfa, 0x49, 0xbb,
    0xc3, 0xb8, 0xad, 0x64, 0x23, 0x7e, 0x71, 0x9f, 0x59, 0xec,
    0x25, 0xa8, 0x5e, 0x11, 0xd6, 0x6e, 0xc9, 0x09, 0xe7, 0xb9,
    0x6a, 0x63, 0x91, 0xaa, 0x5d, 0xd2, 0x8c, 0x91, 0xe8, 0x8d,
    0x35, 0x6d, 0x10, 0xf6, 0xfc, 0x6a, 0x3c, 0x77, 0x90, 0xf8,
    0x2a, 0x49, 0x13, 0x7f, 0xdb, 0xf5, 0x0c, 0xe9, 0xc8, 0x57,
    0xc6, 0xfd, 0x26, 0x8d, 0x79, 0xb5, 0xdd, 0x47, 0x74, 0x6e,
    0xe8, 0x8f, 0x50, 0xf5, 0xa7, 0x9e, 0xd1, 0x74, 0x10, 0xbb,
    0xf4, 0x8f, 0x8f, 0x0d, 0xcd, 0x1f, 0xf6, 0x59, 0xb8, 0x6c,
    0xd2, 0x37, 0x83, 0x28, 0xb2, 0x36, 0xc1, 0x39, 0x5b, 0xde,
    0x59, 0xee, 0x77, 0xa2, 0x6e, 0x67, 0xc6, 0xea, 0x1d, 0x2b,
    0x41, 0x8f, 0x6f, 0x96, 0x94, 0x1b, 0x5d, 0xab, 0x30, 0x53,
    0x1e, 0xf8, 0x17, 0x06, 0xea, 0xcc, 0x98, 0xa8, 0xdf, 0x81,
    0xe1, 0x80, 0xb7, 0xad, 0x69, 0xcb, 0x8f, 0x81, 0x1e, 0x76,
    0x75, 0x3c, 0x11, 0x9b, 0x38, 0x95, 0xa7, 0x87, 0x1f, 0xd9,
    0x76, 0x82, 0x21, 0x13, 0x25, 0x20, 0x42, 0xd3, 0x8c, 0xd9,
    0x1c, 0x64, 0xed, 0xe9, 0x55, 0xb5, 0x29, 0x98, 0x85, 0x7c,
    0x01, 0x94, 0xaa, 0xdd, 0x8c, 0x78, 0x08, 0x99, 0x99, 0x5a,
    0xf6, 0x61, 0x4c, 0xe0, 0x99, 0xf8, 0x15, 0x74, 0x2e, 0x0d,
    0x14, 0x89, 0x11, 0x84, 0xcd, 0x78, 0x0c, 0x6b, 0x48, 0xde,
    0xb4, 0xd6, 0x05, 0xbd, 0x99, 0x58, 0xb7, 0xe5, 0xc5, 0x7a,
    0x43, 0x18, 0x55, 0x33, 0x16, 0x2b, 0xfa, 0x27, 0xf5, 0xbb,
    0xaa, 0x52, 0xb5, 0x28, 0x5c, 0xfe, 0x61, 0x7f, 0x7a, 0x70,
    0xc2, 0x32, 0x4b, 0x05, 0x8d, 0x7b, 0x4d, 0x22, 0x57, 0x25,
    0x40, 0x46, 0x7c, 0xad, 0x2f, 0x8a, 0xc8, 0x16, 0xd6, 0xac,
    0x4e, 0xe3, 0xe3, 0x29, 0xe4, 0xe8, 0x00, 0x2b, 0xc9, 0xe3,
    0x3a, 0x6f, 0x66, 0xf1, 0x37, 0x37, 0x52, 0x88, 0x77, 0xf6,
    0xbd, 0x59, 0x5f, 0xf8, 0x11, 0x46, 0x7b, 0x12, 0x88, 0x2f,
    0x4b, 0x0d, 0x16, 0x89, 0x3e, 0x2a, 0x56, 0x58, 0xa8, 0x1c,
    0xee, 0x23, 0xd5, 0x66, 0x86, 0x5f, 0x59, 0x55, 0xac, 0x07,
    0xfd, 0xda, 0x6b, 0xf1, 0xc7, 0x01, 0x19, 0xdb, 0xff, 0x63,
    0x6f, 0x27, 0xdb, 0xa1, 0xc7, 0xe9, 0xe0, 0xdb, 0xe4, 0x9a,
    0xce, 0xf5, 0xac, 0x68, 0xab, 0x59, 0x0c, 0x83, 0xa3, 0x1c,
    0x2a, 0x86, 0x55, 0xe2, 0xaa, 0xa1, 0xb3, 0xed, 0xc2, 0x2d,
    0x43, 0xc5, 0x13, 0x68, 0xe4, 0x83, 0x3e, 0xd5, 0x7f, 0xf7,
    0xd5, 0xd0, 0x60, 0xd3, 0x70, 0x7f, 0x88, 0xaa, 0xca, 0x74,
    0xcc, 0x50, 0x8d, 0x55, 0x9c, 0xfe, 0x4a, 0xc6, 0xc9, 0x36,
    0xf7, 0x27, 0x26, 0x64, 0xd3, 0x6c, 0xdb, 0x16, 0x31, 0x81,
    0xe9, 0xce, 0x73, 0x60, 0x61, 0x9c, 0x0f, 0xb5, 0x6e, 0x68,
    0xbc, 0xb1, 0x9e, 0x9f, 0xcd, 0x6c, 0x27, 0x31, 0x2d, 0x40,
    0x36, 0xce, 0x91, 0xee, 0x47, 0xdc, 0xa0, 0x4f, 0xd7, 0x14,
    0x4f, 0x93, 0x00, 0xc4, 0x34, 0xca, 0xd4, 0x42, 0x21, 0x90,
    0xf6, 0x9d, 0xea, 0x45, 0x15, 0xfe, 0x2d, 0xd6, 0xab, 0xc2,
    0x36, 0x47, 0xc0, 0x5b, 0xd2, 0xae, 0x53, 0x33, 0xb0, 0x2d,
    0x29, 0xa3, 0x14, 0xda, 0xa4, 0x48, 0xc1, 0x57, 0x0c, 0xdc,
    0x72, 0x4a, 0xd0, 0xf5, 0x5b, 0x9a, 0x57, 0x1d, 0x06, 0xc8,
    0x0f, 0xc7, 0x5b, 0x70, 0xbb, 0x27, 0xf4, 0xe2, 0xf4, 0xf3,
    0x3c, 0xdc, 0xba, 0x43, 0xc4, 0x4e, 0xe2, 0x96, 0xd4, 0x6c,
    0x33, 0x3e, 0xbf, 0x85, 0xf7, 0x3c, 0x1d, 0x46, 0x59, 0x4e,
    0xa1, 0xa7, 0xa3, 0x76, 0x55, 0x8a, 0x72, 0x83, 0xd0, 0x45,
    0x86, 0x38, 0xa5, 0x4d, 0xc8, 0x62, 0xe4, 0x8a, 0xd5, 0x8e,
    0xb7, 0x4c, 0x6e, 0xaf, 0xa4, 0xbe, 0x88, 0x87, 0x77, 0xd1,
    0x7b, 0xb2, 0x1d, 0xe0, 0x1e, 0x53, 0x30, 0x31, 0x15, 0x6c,
    0x10, 0x81, 0x03, 0x55, 0xa7, 0x69, 0xb6, 0xa5, 0x48, 0xf4,
    0xb2, 0x3b, 0x76, 0x8b, 0x2e, 0x42, 0xa6, 0xaa, 0x7e, 0x66,
    0x57, 0xc2, 0x11, 0xc5, 0x2c, 0x7d, 0x96, 0xdf, 0xe3, 0x58,
    0x12, 0x98, 0x18, 0x0d, 0x87, 0xbd, 0x64, 0xbd, 0xfe, 0x6d,
    0xad, 0x6d, 0x1e, 0xf6, 0x34, 0x01, 0xb5, 0x56, 0xe8, 0x6a,
    0xb3, 0x8c, 0x70, 0x84, 0x36, 0x17, 0xd6, 0x4b, 0xaa, 0x57,
    0xab, 0xb3, 0x45, 0x30, 0x36, 0x10, 0xd4, 0xee, 0x8a, 0xc9,
    0x29, 0xd1, 0x92, 0x9b, 0xe2, 0x7c, 0x12, 0xd1, 0x29, 0x62,
    0x41, 0x69, 0xae, 0x3a, 0x50, 0xcc, 0x89, 0x50, 0x2e, 0xe6,
    0x07, 0xf8, 0x9c, 0x98, 0x80, 0xd5, 0xa3, 0xc8, 0x74, 0xfb,
    0xfc, 0x91, 0x16, 0x02, 0xdc, 0xf0, 0x42, 0x49, 0xbc, 0xc9,
    0x2f, 0x7f, 0x8d, 0x93, 0xf7, 0xf0, 0x74, 0xb7, 0xd1, 0x55,
    0xfc, 0x79, 0x03, 0x37, 0xfb, 0xf6, 0x7d, 0x2f, 0x2d, 0xf8,
    0x6b, 0xc5, 0xf9, 0x66, 0x38, 0xf5, 0xfd, 0x64, 0xc6, 0x08,
    0x99, 0xb3, 0x25, 0xad, 0xf4, 0xfd, 0x69, 0x2f, 0xf1, 0x18,
    0x46, 0xd6, 0x5c, 0x1a, 0x37, 0xcd, 0xee, 0xa3, 0xbf, 0x0f,
    0x57, 0x5c, 0xc3, 0x97, 0x94, 0x84, 0x89, 0xbe, 0x00, 0xf6,
    0x40, 0xe9, 0x5a, 0x52, 0xaf, 0x3a, 0x5b, 0xf4, 0x56, 0xb0,
    0x04, 0x49, 0xc6, 0x32, 0x8c, 0xa1, 0x0a, 0xd8, 0x88, 0xa1,
    0xc3, 0xb7, 0x8b, 0x96, 0xc3, 0x39, 0x51, 0x50, 0x83, 0xa6,
    0xf0, 0x6d, 0xe7, 0x6e, 0x20, 0xff, 0x9d, 0xac, 0x03, 0x57,
    0xbc, 0xcb, 0x6a, 0x19, 0xa7, 0xc5, 0xd2, 0x44, 0x4f, 0x17,
    0x1e, 0x9a, 0x8d, 0x97, 0x25, 0x55, 0x52, 0x49, 0xe2, 0x48,
    0xae, 0x4b, 0x3f, 0x94, 0x5a, 0xb2, 0x2d, 0x40, 0xd9, 0x85,
    0xef, 0x03, 0xa0, 0xd3, 0x66, 0x9a, 0x8f, 0x7b, 0xc0, 0x8d,
    0x54, 0x95, 0x42, 0x49, 0xeb, 0x15, 0x00, 0xf3, 0x6d, 0x6f,
    0x40, 0xf2, 0x8b, 0xc1, 0x50, 0xa6, 0x22, 0x3b, 0xd6, 0x88,
    0xa1, 0xf7, 0xb0, 0x1f, 0xcd, 0x20, 0x4e, 0x5b, 0xad, 0x66,
    0x4a, 0xda, 0x40, 0xee, 0x4c, 0x4c, 0x3e, 0xa7, 0x75, 0x51,
    0x90, 0xba, 0xee, 0x59, 0xbc, 0xe3, 0xcd, 0x4d, 0xb9, 0x57,
    0xb7, 0xf8, 0xc1, 0xb9, 0x8d, 0x0f, 0x58, 0x2c, 0x4c, 0x98,
    0xa6, 0x9c, 0xd9, 0x0e, 0x25, 0x4f, 0xea, 0x4c, 0x15, 0x0b,
    0x89, 0xe4, 0xac, 0xa1, 0x5a, 0xa1, 0xfd, 0x5b, 0xc6, 0xfe,
    0xf0, 0xf1, 0x4c, 0xa7, 0x60, 0xbc, 0xc3, 0xa5, 0x80, 0x00,
    0x3b, 0x3f, 0x22, 0x38, 0x60, 0x40, 0x76, 0x52, 0x83, 0x32,
    0xee, 0x20, 0x6a, 0xf9, 0x1e, 0x6b, 0x99, 0x52, 0xe7, 0x04,
    0xdc, 0x5a, 0x9d, 0x77, 0x8a, 0xdd, 0x9b, 0x53, 0x19, 0xff,
    0x69, 0x8c, 0xbc, 0xc6, 0xe0, 0x79, 0x0d, 0x3d, 0x3d, 0x54,
    0x5b, 0xe0, 0x47, 0x5b, 0x71, 0x05, 0x98, 0x8f, 0xbb, 0x65,
    0xe1, 0x31, 0x9a, 0xc8, 0x1e, 0x7a, 0x4a, 0xf8, 0xcb, 0x17,
    0xd1, 0x83, 0x58, 0xb1, 0xc0, 0xe4, 0xb1, 0x85, 0xca, 0xa5,
    0xf8, 0x0e, 0xd1, 0x0c, 0xe8, 0x71, 0xc3, 0xfa, 0xbf, 0x1d,
    0xd6, 0x98, 0x03, 0xed, 0x77, 0x3b, 0x55, 0xaf, 0x69, 0x72,
    0x6b, 0x42, 0x31, 0x98, 0x95, 0xd5, 0x79, 0xa5, 0x4c, 0x51,
    0xcf, 0x02, 0x65, 0x93, 0xf2, 0x71, 0xdc, 0xde, 0x9a, 0xa3,
    0x86, 0xa7, 0xea, 0xcf, 0xd7, 0xe5, 0x00, 0xde, 0x40, 0x02,
    0xcd, 0x6b, 0x46, 0x0b, 0xbb, 0xbf, 0x77, 0x5f, 0x9d, 0x7c,
    0xa4, 0x7f, 0x7c, 0x8a, 0xba, 0xd6, 0x99, 0xc5, 0xaa, 0x06,
    0x36, 0xe1, 0x7e, 0x9c, 0x6f, 0x28, 0xd4, 0x6e, 0x1d, 0x5b,
    0xdd, 0x01, 0x24, 0xbd, 0x6c, 0x5d, 0x87, 0x3c, 0xc1, 0xf6,
    0x93, 0x37, 0xe2, 0x3b, 0x70, 0xc4, 0xd8, 0x10, 0x0e, 0x44,
    0x37, 0x00, 0xe3, 0x07, 0xbd, 0x67, 0xd3, 0x9d, 0xe6, 0xe7,
    0x48, 0x1b, 0xe0, 0x79, 0xb3, 0x30, 0x91, 0x89, 0x0f, 0x89,
    0x77, 0xfa, 0x13, 0x85, 0xd0, 0x32, 0xbd, 0xc1, 0x9e, 0x52,
    0x04, 0x80, 0x54, 0xb1, 0x08, 0x39, 0x20, 0xda, 0x3e, 0xf1,
    0xd9, 0x15, 0x74, 0x55, 0x06, 0xfc, 0x4d, 0x85, 0xd4, 0x98,
    0x02, 0x64, 0x10, 0x86, 0xd7, 0xcd, 0x01, 0x0d, 0x85, 0xa0,
    0x78, 0xb0, 0x58, 0x99, 0x7b, 0xdf, 0xe4, 0x8c, 0x3f, 0xab,
    0xc0, 0xbc, 0xa5, 0x30, 0x28, 0xe1, 0x4e, 0x02, 0x98, 0xab,
    0x03, 0xf3, 0x21, 0xe7, 0xa7, 0xe7, 0xc3, 0x5f, 0x98, 0xc0,
    0x83, 0x02, 0xe8, 0x8a, 0x30, 0x75, 0x95, 0xcf, 0x77, 0x83,
    0xfb, 0x32, 0x5a, 0xf9, 0x13, 0xed, 0xdb, 0xda, 0xc3, 0x84,
    0x4b, 0x8f, 0x1a, 0xf0, 0xad, 0x8e, 0xcf, 0xe3, 0xa7, 0x2b,
    0xb5, 0x44, 0x75, 0xd6, 0xda, 0x33, 0x81, 0x22, 0xa7, 0x6a,
    0xbd, 0x21, 0x64, 0x85, 0xfa, 0x65, 0x8e, 0xc4, 0x58, 0xec,
    0xc4, 0x18, 0x90, 0xa3, 0xcc, 0x2e, 0xaa, 0xa2, 0x2e, 0x46,
    0x7a, 0x4a, 0x35, 0xbf, 0x58, 0x78, 0x2b, 0x1e, 0x72, 0xe5,
    0x80, 0xc9, 0xe0, 0x9e, 0x43, 0x01, 0xcc, 0xe1, 0x0c, 0x00,
    0xe9, 0xc1, 0xa5, 0x1a, 0x9b, 0x4e, 0x6e, 0x34, 0x32, 0xfd,
    0x86, 0xb7, 0xae, 0xc3, 0x6e, 0x69, 0x04, 0xf6, 0x6a, 0x92,
    0x78, 0xb1, 0x1f, 0x9d, 0x5e, 0x0c, 0xf9, 0xc4, 0x1a, 0xf6,
    0xb4, 0x8a, 0x63, 0xb5, 0x87, 0x5b, 0xfb, 0x50, 0xbf, 0xd5,
    0x17, 0x97, 0x8e, 0x55, 0x1c, 0xfe, 0x82, 0xf6, 0xa7, 0x9c,
    0x0b, 0xc9, 0x0a, 0xf6, 0x7f, 0x70, 0xd1, 0x00, 0xed, 0x1c,
    0x6c, 0x3a, 0x95, 0xed, 0x61, 0xa4, 0xd6, 0x57, 0xfb, 0x57,
    0xf8, 0x9b, 0x4c, 0xce, 0x50, 0x26, 0x5c, 0x19, 0xd2, 0xa7,
    0xd6, 0xe8, 0x3c, 0x29, 0x34, 0xfb, 0x26, 0x7f, 0xc5, 0x78,
    0xbf, 0xfe, 0xb6, 0x2a, 0x5a, 0x62, 0x8e, 0x31, 0x9b, 0x57,
    0xa4, 0xe7, 0x4d, 0x3d, 0x18, 0x05, 0xf0, 0x94, 0xbb, 0x04,
    0xfa, 0x0a, 0x92, 0xf4, 0xc6, 0x7f, 0x16, 0xa2, 0x31, 0xed,
    0xc1, 0xb4, 0x62, 0x54, 0x3a, 0x23, 0x12, 0x6a, 0x76, 0xcc,
    0x8c, 0x91, 0x89, 0x58, 0x8c, 0x20, 0x23, 0xd9, 0xaa, 0x0d,
    0x80, 0xbe, 0xb9, 0xb4, 0x40, 0x1e, 0xff, 0xa9, 0xf7, 0x71,
    0x0a, 0xa0, 0x0a, 0xdf, 0x11, 0x0b, 0x66, 0x3f, 0xf2, 0x4d,
    0x5d, 0x39, 0x7c, 0x77, 0xe1, 0xb1, 0x09, 0xa1, 0x6b, 0x2e,
    0x30, 0x43, 0x33, 0x80, 0x6e, 0x6a, 0x1d, 0x47, 0xd9, 0xd6,
    0xac, 0xdc, 0x3f, 0x16, 0xb1, 0x58, 0x11, 0x9f, 0x67, 0xd7,
    0x15, 0x45, 0xd8, 0xc3, 0x69, 0x24, 0x8d, 0xac, 0xff, 0xc3,
    0x43, 0xfd, 0x24, 0xaf, 0xf1, 0xc8, 0x3a, 0xc7, 0xd6, 0x1f,
    0x56, 0x26, 0x16, 0xe6, 0x30, 0xcd, 0x6e, 0x0a, 0x63, 0x2a,
    0x7b, 0x86, 0xd7, 0x65, 0x39, 0x45, 0x7c, 0xe6, 0xa0, 0xe6,
    0x38, 0xed, 0x54, 0x84, 0x00, 0x4d, 0x8e, 0xc2, 0xba, 0x56,
    0x9b, 0xf3, 0xe1, 0xe8, 0x7d, 0xfe, 0x47, 0xf0, 0x58, 0xe7,
    0x59, 0x60, 0x97, 0x2e, 0x57, 0x1a, 0x09, 0x1f, 0x8b, 0x2b,
    0x0b, 0x47, 0x75, 0xc0, 0xb3, 0x79, 0xce, 0x10, 0x47, 0x6d,
    0xfc, 0xcb, 0x22, 0x61, 0x5c, 0x39, 0xc4, 0x3f, 0xc5, 0xef,
    0xb8, 0xc8, 0x88, 0x52, 0xce, 0x90, 0x17, 0xf5, 0x3c, 0xa9,
    0x87, 0x6f, 0xcb, 0x2f, 0x11, 0x53, 0x65, 0x9b, 0x74, 0x21,
    0x3e, 0xdd, 0x7b, 0x1f, 0x19, 0x9f, 0x53, 0xe6, 0xab, 0xc0,
    0x56, 0xba, 0x80, 0x19, 0x5d, 0x3f, 0xc7, 0xe2, 0xfb, 0x8c,
    0xe2, 0x93, 0xe0, 0x31, 0xc9, 0x33, 0x31, 0x23, 0x31, 0xa1,
    0x36, 0x4c, 0x62, 0xd8, 0x0a, 0xfd, 0x85, 0x97, 0xae, 0xa9,
    0xe9, 0x58, 0x29, 0x17, 0x33, 0x09, 0x5a, 0x8e, 0xa3, 0x90,
    0x41, 0xd3, 0xfc, 0x24, 0x98, 0x61, 0x4d, 0x30, 0x1f, 0x76,
    0x8f, 0xfc, 0xd0, 0x96, 0x8b, 0x2e, 0x9b, 0x24, 0x73, 0x35,
    0x00, 0xb7, 0xf6, 0xe8, 0xba, 0xec, 0x98, 0x74, 0x41, 0xa4,
    0x47, 0x10, 0x0d, 0xbc, 0xba, 0xd1, 0xe7, 0xdb, 0x12, 0xcb,
    0x5f, 0x02, 0xb1, 0xa6, 0xa0, 0xd7, 0x28, 0x30, 0x3e, 0x0a,
    0x5c, 0x5f, 0xe6, 0x2f, 0x3c, 0xde, 0x46, 0x60, 0xaf, 0x07,
    0x5f, 0xed, 0x08, 0xc0, 0x06, 0x58, 0xba, 0xd7, 0x36, 0x5b,
    0xa0, 0x4a, 0xf7, 0xa1, 0x05, 0x9b, 0x00, 0xda, 0x49, 0xdc,
    0xbf, 0xea, 0xe1, 0x03, 0xda, 0x95, 0x95, 0xa0, 0xfa, 0x2e,
    0xf1, 0x60, 0x11, 0x47, 0xdd, 0xb3, 0xfb, 0x0b, 0xa2, 0x92,
    0xcf, 0x73, 0xbb, 0xce, 0x82, 0x71, 0xbc, 0xbd, 0x50, 0x64,
    0xf1, 0x96, 0x48, 0x48, 0x93, 0xf8, 0xdc, 0x1c, 0x18, 0x12,
    0xc6, 0x17, 0x6a, 0xa9, 0xc1, 0x4d, 0x6f, 0x76, 0xda, 0x2f,
    0x4e, 0x59, 0xdd, 0x8b, 0x1c, 0xa5, 0x30, 0xb6, 0xe9, 0x88,
    0x8f, 0x75, 0x0c, 0xcd, 0xd8, 0x61, 0xf4, 0x28, 0xc5, 0x9a,
    0xcd, 0x77, 0x0d, 0x36, 0x5f, 0x75, 0xa5, 0x0a, 0x77, 0x20,
    0x28, 0x5a, 0xac, 0x5f, 0xa1, 0x83, 0x67, 0x70, 0xb7, 0xd8,
    0x23, 0x48, 0x60, 0xa8, 0xd0, 0xaf, 0xee, 0x7a, 0xb8, 0x25,
    0xd7, 0x8f, 0x82, 0x8c, 0xd0, 0x81, 0x7a, 0x49, 0x69, 0xe4,
    0x22, 0x73, 0x29, 0x48, 0xc8, 0x09, 0x72, 0x16, 0xf8, 0x3d,
    0xff, 0x13, 0xac, 0x98, 0x03, 0x76, 0x33, 0xcb, 0x19, 0xb0,
    0x22, 0x5b, 0x1e, 0x16, 0x29, 0xb9, 0xcc, 0xa6, 0x92, 0xd8,
    0xed, 0x93, 0x0f, 0xbd, 0x10, 0x98, 0x53, 0x0a, 0x07, 0x7f,
    0xd6, 0x51, 0x76, 0xda, 0xdc, 0x0c, 0xeb, 0x2a, 0x95, 0xd0,
    0x3e, 0xa6, 0xc4, 0xc6, 0xd8, 0xfb, 0x1b, 0x2a, 0x7f, 0xf1,
    0x08, 0xbe, 0xd3, 0xed, 0x67, 0x63, 0x5f, 0x1d, 0x29, 0xdb,
    0x47, 0x03, 0x4a, 0xf4, 0x6b, 0xb4, 0x46, 0x02, 0x28, 0x4f,
    0x88, 0x9b, 0x46, 0x66, 0x40, 0x56, 0x34, 0x4c, 0xec, 0x8e,
    0x0b, 0x5d, 0x14, 0x94, 0x91, 0xfc, 0xdc, 0x0c, 0xdc, 0x5b,
    0x45, 0x12, 0x7e, 0xa1, 0xe9, 0x75, 0x38, 0xcb, 0xd3, 0x6b,
    0xd7, 0xa4, 0x24, 0x94, 0x78, 0x09, 0x7f, 0x77, 0xc8, 0x6d,
    0xe1, 0x82, 0x1c, 0x1c, 0x91, 0xc6, 0x38, 0x9e, 0x3b, 0x3d,
    0x31, 0xdd, 0x9e, 0x46, 0x58, 0x7a, 0x42, 0x16, 0x6f, 0xfd,
    0x7d, 0x8c, 0xf5, 0xf0, 0x9f, 0x92, 0x6e, 0xbe, 0x47, 0xa6,
    0x1e, 0x8e, 0x82, 0x15, 0x24, 0xc3, 0x1b, 0xb0, 0xd1, 0x68,
    0xf9, 0xd1, 0x7c, 0x60, 0x98, 0x86, 0xd9, 0x53, 0xa2, 0x38,
    0x62, 0xf4, 0x72, 0x71, 0xcb, 0xb9, 0x35, 0xef, 0xb9, 0x49,
    0x3a, 0x73, 0xb2, 0xd7, 0x0f, 0x90, 0xf5, 0x2c, 0x5b, 0xf5,
    0xfd, 0x39, 0x17, 0xf7, 0xe4, 0x69, 0x81, 0x0f, 0x6b, 0xe7,
    0x32, 0xd2, 0xdc, 0x5d, 0x40, 0xbf, 0x41, 0x95, 0x89, 0x81,
    0x29, 0x80, 0x40, 0xa3, 0xac, 0xd2, 0xc7, 0xf7, 0xe8, 0xd0,
    0x45, 0xed, 0x48, 0x43, 0x3a, 0xed, 0x8d, 0xef, 0x37, 0xe1,
    0x24, 0x9a, 0x67, 0x9a, 0x6b, 0x71, 0x4f, 0x9a, 0xb9, 0x2c,
    0x1b, 0x10, 0x48, 0xe2, 0x31, 0x1e, 0xbb, 0xf2, 0x4a, 0xad,
    0x04, 0xc7, 0xd7, 0xf2, 0xe8, 0x83, 0x5f, 0xe8, 0xa2, 0x81,
    0x95, 0xf9, 0x60, 0x51, 0x9c, 0x99, 0x76, 0x69, 0x76, 0x4e,
    0xbd, 0x44, 0x52, 0x36, 0xca, 0xd8, 0x6e, 0xf7, 0x1a, 0xa1,
    0x54, 0xdf, 0x90, 0x52, 0x94, 0xb6, 0x3a, 0xcb, 0x43, 0x56,
    0x11, 0xde, 0xa0, 0xe1, 0x45, 0x8a, 0x80, 0x2d, 0xaf, 0x1f,
    0x24, 0x3f, 0x80, 0x17, 0x1f, 0x28, 0xbb, 0xcc, 0x1a, 0xd2,
    0x2d, 0xa6, 0x9e, 0xe0, 0xdc, 0xf0, 0x98, 0x16, 0x58, 0x88,
    0xc6, 0xf1, 0x81, 0x71, 0x91, 0x8f, 0xa2, 0xab, 0xa5, 0xe6,
    0x68, 0x1f, 0xa5, 0x86, 0xb5, 0xd9, 0x05, 0xba, 0x50, 0x67,
    0x0b, 0x1e, 0xfe, 0x42, 0x50, 0xf8, 0x01, 0xf8, 0x38, 0x92,
    0x57, 0x86, 0x08, 0x47, 0xee, 0x23, 0x11, 0x60, 0x61, 0x1a,
    0x77, 0x3c, 0x1a, 0x8e, 0x08, 0xe3, 0xaf, 0x84, 0x04, 0x75,
    0x15, 0x47, 0x7a, 0x83, 0x8e, 0x92, 0x3e, 0xe8, 0xf0, 0xc2,
    0x81, 0x89, 0x3b, 0x73, 0x81, 0xe5, 0xe8, 0x97, 0x97, 0x63,
    0x64, 0xf3, 0xa9, 0x1b, 0x61, 0x65, 0x7f, 0x0e, 0x47, 0x6b,
    0x14, 0x57, 0x29, 0x8f, 0x91, 0x35, 0x43, 0x10, 0x12, 0x86,
    0x99, 0xec, 0xc8, 0x9e, 0x67, 0x90, 0x20, 0x21, 0x3c, 0x83,
    0xdb, 0x73, 0x4e, 0x8e, 0x7d, 0x86, 0xde, 0xb8, 0xd8, 0xfa,
    0x23, 0x1f, 0x5a, 0xe4, 0xc7, 0x0c, 0x1d, 0x5e, 0xd1, 0x10,
    0x58, 0xd5, 0x86, 0xfa, 0x40, 0x30, 0x0a, 0x78, 0x0a, 0xa5,
    0x56, 0xd5, 0xe6, 0x86, 0xd4, 0x14, 0x77, 0x32, 0xcd, 0x07,
    0xf9, 0xbe, 0x7a, 0xd8, 0xbc, 0x91, 0xe0, 0xda, 0x76, 0x6b,
    0x97, 0x10, 0xda, 0xea, 0x27, 0xa2, 0x67, 0x6d, 0x94, 0x27,
    0x6e, 0xea, 0xca, 0x56, 0x45, 0x32, 0x1d, 0x38, 0x12, 0x21,
    0x33, 0x2c, 0x3c, 0x5c, 0x33, 0xb0, 0x9e, 0x80, 0x0b, 0x4e,
    0xbb, 0x09, 0x5e, 0x56, 0x54, 0xb0, 0x9b, 0x7e, 0xb6, 0x00,
    0xe8, 0x63, 0x19, 0x85, 0xf1, 0x4d, 0x65, 0x9d, 0x1f, 0x8d,
    0x18, 0xcc, 0x63, 0xc6, 0xd9, 0xa6, 0xbc, 0xe7, 0x42, 0x55,
    0x12, 0xdc, 0x8c, 0x26, 0x2d, 0x8d, 0xc2, 0xe9, 0x3b, 0xbc,
    0xed, 0x06, 0x08, 0x31, 0xb0, 0xe0, 0x99, 0xe2, 0x86, 0x81,
    0x88, 0x4a, 0xac, 0x1f, 0x4a, 0xb2, 0x1e, 0x1e, 0x4c, 0xb2,
    0x9f, 0x27, 0xa0, 0xd9, 0x8a, 0x7e, 0xe7, 0xa3, 0xad, 0xeb,
    0x2c, 0xfd, 0x14, 0xc6, 0x4b, 0x26, 0xce, 0x38, 0xb9, 0x01,
    0x9e, 0xde, 0xc8, 0x7b, 0x82, 0x2f, 0xaa, 0x72, 0x80, 0xbe,
    0x3a, 0x35, 0x95, 0xc8, 0xf3, 0x7c, 0x36, 0x68, 0x02, 0xdc,
    0xa2, 0xda, 0xef, 0xd7, 0xf1, 0x3e, 0x81, 0xb3, 0x5d, 0x2f,
    0xcf, 0x7e, 0xe6, 0x9c, 0xa0, 0x32, 0x29, 0x8b, 0x52, 0x24,
    0xbd, 0x0d, 0x36, 0xdc, 0x1d, 0xcc, 0x6a, 0x0a, 0x74, 0x52,
    0x1b, 0x68, 0x4d, 0x15, 0x05, 0x47, 0xe1, 0x2f, 0x97, 0x45,
    0x52, 0x17, 0x4b, 0x2a, 0x3b, 0x74, 0xc5, 0x20, 0x35, 0x5c,
    0x37, 0xae, 0xe6, 0xa7, 0x24, 0x0f, 0x34, 0x70, 0xea, 0x7c,
    0x03, 0xa3, 0xde, 0x2d, 0x22, 0x55, 0x88, 0x01, 0x45, 0xf2,
    0x5f, 0x1f, 0xaf, 0x3b, 0xb1, 0xa6, 0x5d, 0xcd, 0x93, 0xfb,
    0xf8, 0x2f, 0x87, 0xcc, 0x26, 0xc5, 0x36, 0xde, 0x06, 0x9b,
    0xe9, 0xa7, 0x66, 0x7e, 0x8c, 0xcd, 0x99, 0x6b, 0x51, 0x1c,
    0xb0, 0xa0, 0xfa, 0xc7, 0x46, 0xfe, 0x65, 0xe4, 0x80, 0x5b,
    0x5f, 0x24, 0x3b, 0xa4, 0xe6, 0x81, 0x31, 0xe5, 0x87, 0x2c,
    0xa4, 0x83, 0xaf, 0x8b, 0x9f, 0x89, 0xb4, 0x3c, 0x7a, 0xbe,
    0x4c, 0xb3, 0xbf, 0x3d, 0xec, 0x78, 0xb0, 0x8a, 0xdd, 0xc8,
    0x43, 0x8c, 0x45, 0xa1, 0xa3, 0x3a, 0x82, 0x7d, 0x06, 0xdf,
    0x20, 0x27, 0x9b, 0x4e, 0x09, 0x90, 0x6a, 0x23, 0xbf, 0x1b,
    0x04, 0x1d, 0x50, 0xe2, 0xb4, 0xff, 0xe0, 0xd0, 0x9b, 0x40,
    0x2b, 0xc0, 0x52, 0xc1, 0x39, 0x29, 0x60, 0x83, 0x06, 0x9b,
    0x48, 0xb8, 0xa7, 0xe1, 0x2b, 0xfb, 0xf0, 0x2b, 0x82, 0xf1,
    0xda, 0xc9, 0x30, 0x47, 0x3f, 0xf5, 0xf9, 0xf7, 0x6c, 0xf0,
    0x0f, 0xe7, 0xb1, 0x4d, 0x46, 0x49, 0xf8, 0xb3, 0xe1, 0xfe,
    0x85, 0x61, 0xcc, 0xf7, 0xfa, 0xd2, 0xf1, 0xbc, 0xf0, 0x7f,
    0x3b, 0xe6, 0x45, 0xa2, 0x1b, 0x55, 0xf6, 0x0c, 0x02, 0x95,
    0xdc, 0x78, 0x94, 0xa0, 0xc4, 0x6a, 0x21, 0x7e, 0xa8, 0x5f,
    0xbd, 0xc3, 0xb3, 0x4d, 0x9b, 0x30, 0x31, 0x1d, 0x5b, 0x8b,
    0x45, 0x3c, 0x18, 0xe9, 0x61, 0xe8, 0x76, 0x3e, 0x91, 0xd2,
    0xfd, 0x1a, 0xd7, 0x30, 0x4d, 0xfe, 0xef, 0x7f, 0xc0, 0x7e,
    0x45, 0x43, 0xe9, 0xf9, 0x23, 0xfe, 0xd8, 0xef, 0xbc, 0xd6,
    0x99, 0x79, 0x54, 0xed, 0x7a, 0x8b, 0x39, 0xa6, 0xe7, 0x9d,
    0x3f, 0x9f, 0x35, 0xe1, 0xe4, 0xd5, 0x26, 0x31, 0x3a, 0x44,
    0x03, 0x79, 0xde, 0xdc, 0x29, 0x1e, 0x8e, 0x26, 0x41, 0xc6,
    0x60, 0xaa, 0xfd, 0xe1, 0x5e, 0xa6, 0xc0, 0x2f, 0x90, 0x1e,
    0x3b, 0xc1, 0xe6, 0xf6, 0xde, 0x60, 0x87, 0x57, 0x51, 0x11,
    0x6a, 0x8e, 0x9d, 0x70, 0x9d, 0x6d, 0x36, 0x21, 0x05, 0x55,
    0xc1, 0x56, 0x9b, 0xc9, 0x91, 0x50, 0x3e, 0xb4, 0xbd, 0x19,
    0x53, 0x44, 0x99, 0xc7, 0xb8, 0xce, 0xce, 0x86, 0x06, 0x5d,
    0x99, 0x85, 0x33, 0xd4, 0x16, 0x21, 0x4a, 0xe9, 0x7e, 0x2e,
    0xcc, 0x7e, 0x3f, 0xc1, 0x47, 0x3b, 0x32, 0xd0, 0x57, 0x1c,
    0xc2, 0x26, 0x67, 0xf0, 0xd9, 0xc4, 0x9e, 0xbb, 0x65, 0xa4,
    0xf7, 0xf7, 0x8d, 0x7d, 0x08, 0xd4, 0x9c, 0x1e, 0x0f, 0xb9,
    0xff, 0x24, 0x2f, 0xaf, 0xfa, 0x24, 0x26, 0xb7, 0xb1, 0x78,
    0xc1, 0xd1, 0xfe, 0x85, 0x55, 0xa0, 0x86, 0x77, 0xf6, 0xc2,
    0xe0, 0x12, 0xe4, 0x45, 0x85, 0xd0, 0xe7, 0x68, 0xf0, 0x31,
    0x4c, 0x9c, 0xb0, 0x5f, 0x89, 0xca, 0xfe, 0xc2, 0xf0, 0x1e,
    0xeb, 0xee, 0x75, 0x64, 0xea, 0x09, 0xd4, 0x1c, 0x72, 0x12,
    0xd4, 0x31, 0xf0, 0x89, 0x71, 0x74, 0x6e, 0x01, 0x32, 0xca,
    0x8a, 0x91, 0x0c, 0xdf, 0xd7, 0x05, 0xe9, 0x35, 0xed, 0x06,
    0x1a, 0x17, 0x5a, 0xf3, 0x65, 0xc5, 0xbd, 0x37, 0xf2, 0x53,
    0x49, 0x2f, 0xcd, 0xc6, 0x15, 0xb3, 0x36, 0x88, 0xd8, 0x7a,
    0x2f, 0xfa, 0x21, 0x7f, 0x55, 0x20, 0xc6, 0xf4, 0x23, 0x59,
    0x6b, 0x3c, 0xeb, 0xe5, 0xd3, 0x78, 0xdc, 0x31, 0xeb, 0x87,
    0x86, 0x3d, 0x7c, 0x10, 0x64, 0x66, 0xa4, 0xad, 0x07, 0xe1,
    0x93, 0x15, 0x07, 0x4c, 0xe4, 0xb4, 0x4a, 0x06, 0xca, 0x2a,
    0x50, 0xa2, 0x85, 0xc6, 0xa1, 0x19, 0x89, 0x7f, 0x8a, 0x05,
    0x00, 0x23, 0x72, 0x5f, 0x89, 0x74, 0x8e, 0x22, 0xa1, 0x5d,
    0x26, 0xf9, 0xfe, 0xdf, 0x6d, 0x98, 0x3a, 0xc4, 0x7c, 0x93,
    0xcf, 0xc4, 0xfe, 0xed, 0x98, 0xb0, 0x31, 0x4c, 0x81, 0x83,
    0x0d, 0x5d, 0x3d, 0x0c, 0x27, 0x4e, 0xca, 0xcf, 0x38, 0x0c,
    0x37, 0xb0, 0xf8, 0xc5, 0xc8, 0x52, 0x14, 0xec, 0x53, 0x80,
    0xb9, 0xd8, 0x8a, 0x05, 0x4e, 0x31, 0x3d, 0x67, 0x57, 0xf0,
    0x7a, 0xa2, 0xc5, 0xc9, 0x02, 0x25, 0x69, 0x83, 0xb9, 0x3e,
    0x1b, 0x04, 0xbf, 0xb2, 0xe6, 0x97, 0x7a, 0x6b, 0x8e, 0x37,
    0x77, 0x2e, 0x16, 0x8b, 0x33, 0xe1, 0xea, 0x2b, 0x30, 0x01,
    0x6e, 0xa0, 0x28, 0x14, 0x17, 0xe9, 0x98, 0xa8, 0x89, 0x72,
    0x68, 0x64, 0x81, 0x60, 0xa8, 0xf7, 0x72, 0xdf, 0x1a, 0xae,
    0xf5, 0xf0, 0x9f, 0x69, 0x35, 0xbc, 0x58, 0x27, 0x38, 0xd6,
    0x7f, 0x7a, 0xd4, 0xc4, 0xf1, 0xcf, 0xee, 0x59, 0x49, 0x31,
    0xda, 0xc1, 0x08, 0x46, 0x65, 0x68, 0xe9, 0x44, 0x18, 0x2b,
    0xf2, 0x2a, 0x13, 0x60, 0x07, 0xae, 0xe4, 0x96, 0xdb, 0x0a,
    0x6f, 0x52, 0x23, 0x9a, 0xcf, 0x9d, 0xa4, 0xc5, 0xc1, 0x74,
    0xa8, 0x0e, 0xe1, 0x5e, 0xfa, 0xa4, 0x06, 0x9c, 0x2e, 0x70,
    0x08, 0x22, 0x25, 0x4f, 0xc1, 0xf1, 0x13, 0x5a, 0x66, 0xa0,
    0x6c, 0x59, 0xa3, 0xfc, 0x03, 0x9c, 0x8a, 0x23, 0x01, 0x00,
    0xa9, 0x49, 0xf0, 0x22, 0xa3, 0x8f, 0x6c, 0xef, 0xcb, 0x69,
    0x06, 0x3a, 0x69, 0x99, 0x96, 0xd2, 0xa7, 0xa0, 0x0b, 0x7e,
    0x44, 0x7d, 0x04, 0xff, 0x7e, 0x9e, 0x1e, 0x77, 0xa0, 0x30,
    0xd1, 0xdf, 0x18, 0xe4, 0xd8, 0xa5, 0x64, 0xbe, 0x8c, 0x80,
    0x28, 0xe2, 0x98, 0x5e, 0xec, 0x9e, 0xb1, 0x0a, 0xb5, 0x25,
    0xaa, 0xb8, 0x0f, 0x78, 0x30, 0x48, 0x06, 0xe5, 0x76, 0xf9,
    0x24, 0x96, 0x87, 0x2a, 0x91, 0x89, 0xb6, 0xce, 0x04, 0xdf,
    0xfc, 0x13, 0x42, 0x19, 0xba, 0x14, 0x46, 0x20, 0x08, 0x47,
    0xe1, 0x82, 0x57, 0x51, 0x74, 0x3b, 0x5b, 0x23, 0x5c, 0xb2,
    0x85, 0x8c, 0xed, 0xe6, 0xda, 0x4d, 0x56, 0xe8, 0x61, 0x31,
    0xec, 0x97, 0x27, 0xeb, 0xf2, 0xa7, 0x7c, 0x13, 0x1b, 0xc5,
    0x44, 0xfe, 0x63, 0x4b, 0x2b, 0x33, 0x22, 0x23, 0x60, 0x86,
    0x7c, 0x3b, 0x57, 0xba, 0x16, 0xde, 0x47, 0x04, 0x3e, 0x2b,
    0xe5, 0xbd, 0x23, 0xa0, 0xab, 0xdf, 0x5d, 0x6e, 0x20, 0xb1,
    0x37, 0x44, 0xcb, 0xbd, 0x03, 0xa9, 0x5c, 0xe6, 0x92, 0x5e,
    0x2f, 0x6f, 0x95, 0xc6, 0x5b, 0x6d, 0xab, 0x39, 0xdd, 0x1e,
    0x34, 0xd5, 0x21, 0xca, 0x92, 0xee, 0x59, 0xf0, 0xb9, 0x65,
    0xe6, 0x81, 0x49, 0xf8, 0x11, 0xec, 0x45, 0x14, 0x6a, 0x19,
    0xb4, 0xce, 0xbf, 0x9e, 0xf7, 0x32, 0x8d, 0x99, 0x78, 0xc3,
    0x07, 0x3d, 0xfd, 0x18, 0x2d, 0x0e, 0x06, 0x2f, 0x27, 0x24,
    0x6f, 0x16, 0xd8, 0x01, 0x33, 0xc8, 0xbb, 0x7f, 0x7d, 0xfa,
    0x73, 0xf6, 0x7d, 0x54, 0xf2, 0xd4, 0x8a, 0x53, 0xe1, 0x62,
    0x45, 0xf4, 0x01, 0xa6, 0x31, 0x6b, 0x3a, 0x06, 0x56, 0xfd,
    0x79, 0x7f, 0x58, 0xd8, 0x47, 0x33, 0x53, 0xc5, 0x78, 0x70,
    0xce, 0x81, 0x7f, 0x66, 0xa1, 0x58, 0x7c, 0x5a, 0xdb, 0x4a,
    0xad, 0x29, 0xff, 0x93, 0x75, 0x95, 0x35, 0xa9, 0xd2, 0xb1,
    0xeb, 0xa0, 0x4f, 0x10, 0x0a, 0xc9, 0x38, 0x69, 0xc8, 0x8d,
    0x57, 0xef, 0x99, 0x0f, 0xa5, 0x69, 0x86, 0xa6, 0xfb, 0x2b,
    0x37, 0xe4, 0xc7, 0xab, 0x3e, 0xcd, 0x8f, 0x3f, 0x93, 0x8c,
    0x0b, 0xc4, 0x4d, 0x16, 0xe0, 0xb0, 0x94, 0x5a, 0x0d, 0x17,
    0xaf, 0x6e, 0x4b, 0x2e, 0x18, 0x29, 0x0e, 0xe0, 0xf5, 0x72,
    0x1a, 0x21, 0x37, 0xef, 0x7d, 0x6a, 0x39, 0xe9, 0xa8, 0xd7,
    0x96, 0xd6, 0xb3, 0x7d, 0x83, 0x0c, 0x13, 0x30, 0x49, 0x03,
    0xe8, 0x6b, 0xe6, 0x77, 0xe8, 0x69, 0x48, 0x56, 0x5f, 0x39,
    0x63, 0xbc, 0x86, 0xa8, 0x26, 0xa1, 0xbd, 0x4b, 0x24, 0xbd,
    0xdd, 0xe8, 0x02, 0x64, 0xcb, 0xae, 0x24, 0x17, 0x62, 0xbd,
    0x27, 0xa7, 0x22, 0x60, 0x51, 0x0c, 0x53, 0xff, 0x9d, 0x63,
    0x1b, 0xf9, 0xff, 0x76, 0x3b, 0x74, 0x05, 0x98, 0x46, 0x0b,
    0xe8, 0xcb, 0xd4, 0x0a, 0xcd, 0x91, 0xdb, 0x5b, 0x21, 0x4d,
    0xa1, 0x87, 0xbd, 0xb7, 0x58, 0xec, 0x28, 0x00, 0x92, 0xc2,
    0x98, 0xe4, 0x8c, 0x1f, 0x9d, 0xa4, 0x80, 0x83, 0x40, 0xb9,
    0x63, 0xfe, 0xc9, 0x18, 0x3f, 0xd6, 0xab, 0x34, 0x00, 0x2c,
    0x53, 0x40, 0x38, 0x0e, 0xb1, 0x69, 0xa8, 0xb8, 0xa9, 0x2e,
    0x9b, 0x7b, 0x89, 0x8d, 0xff, 0x86, 0x01, 0x51, 0x42, 0xde,
    0x04, 0xd6, 0x1d, 0xd1, 0x29, 0x8d, 0x42, 0x46, 0x5f, 0xd6,
    0x02, 0xde, 0x73, 0xee, 0x2d, 0xe9, 0x6e, 0xb0, 0x3f, 0xf0,
    0x47, 0x72, 0xfe, 0x45, 0xff, 0x05, 0x82, 0x2d, 0xc6, 0x4f,
    0xc9, 0xd3, 0xec, 0xf9, 0x5a, 0x22, 0x50, 0x6c, 0x4f, 0x1e,
    0xc8, 0x5f, 0xfc, 0x2c, 0x04, 0x4f, 0xdf, 0xce, 0xe4, 0x18,
    0xd2, 0xd7, 0x8b, 0x67, 0x83, 0x39, 0x96, 0x47, 0x5e, 0x5b,
    0xad, 0x7f, 0x5d, 0x42, 0x56, 0x97, 0x71, 0x39, 0x28, 0x44,
    0x9d, 0x35, 0xde, 0xde, 0x03, 0x20, 0x34, 0x44, 0xdb, 0xdf,
    0xfc, 0xff, 0x1e, 0x3d, 0x58, 0x5f, 0x7a, 0x8e, 0x90, 0xa1,
    0xd3, 0xeb, 0x0c, 0x23, 0x3f, 0x4e, 0x61, 0x77, 0x79, 0xb2,
    0xdc, 0xfb, 0x21, 0x46, 0x5c, 0x82, 0xb6, 0xf6, 0x34, 0x3c,
    0x3f, 0x45, 0x4b, 0x80, 0x9e, 0xa4, 0xe6, 0x02, 0x13, 0x38,
    0x40, 0x7e, 0x87, 0x92, 0x96, 0x51, 0x63, 0x87, 0xae, 0xc8,
    0x02, 0x6a, 0x70, 0xc8, 0xcd, 0xd0, 0xe2, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
    0x12, 0x1c, 0x22, 0x2b, 0x33, 0x38, 0x3f,
};
static const int sizeof_bench_dilithium_level5_sig =
    sizeof(bench_dilithium_level5_sig);
#endif

#endif /* !WOLFSSL_DILITHIUM_NO_VERIFY */


void bench_dilithiumKeySign(byte level)
{
    int    ret = 0;
    dilithium_key key;
    double start;
    int    i, count;
#if !defined(WOLFSSL_DILITHIUM_NO_SIGN) || !defined(WOLFSSL_DILITHIUM_NO_VERIFY)
    byte   sig[DILITHIUM_MAX_SIG_SIZE];
    byte   msg[512];
    word32 x = 0;
#endif
    const char**desc = bench_desc_words[lng_index];
    DECLARE_MULTI_VALUE_STATS_VARS()
    byte params = 0;

    if (level == 2) {
        params = 44;
    }
    else if (level == 3) {
        params = 65;
    }
    else if (level == 5) {
        params = 87;
    }

#if !defined(WOLFSSL_DILITHIUM_NO_SIGN) || !defined(WOLFSSL_DILITHIUM_NO_VERIFY)
    /* make dummy msg */
    for (i = 0; i < (int)sizeof(msg); i++) {
        msg[i] = (byte)i;
    }
#endif

    ret = wc_dilithium_init(&key);
    if (ret != 0) {
        printf("wc_dilithium_init failed %d\n", ret);
        return;
    }

    ret = wc_dilithium_set_level(&key, level);
    if (ret != 0) {
        printf("wc_dilithium_set_level() failed %d\n", ret);
    }

#ifndef WOLFSSL_DILITHIUM_NO_MAKE_KEY
    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < agreeTimes; i++) {
            ret = wc_dilithium_make_key(&key, GLOBAL_RNG);
            if (ret != 0) {
                printf("wc_dilithium_import_private_key failed %d\n", ret);
                return;
            }
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    if (ret == 0) {
        bench_stats_asym_finish("ML-DSA", params, desc[2], 0, count,
                                start, ret);
    #ifdef MULTI_VALUE_STATISTICS
        bench_multi_value_stats(max, min, sum, squareSum, runs);
    #endif
    }

#elif !defined WOLFSSL_DILITHIUM_NO_SIGN

#ifndef WOLFSSL_NO_ML_DSA_44
    if (level == 2) {
        ret = wc_dilithium_import_private(bench_dilithium_level2_key,
            sizeof_bench_dilithium_level2_key, &key);
    }
#endif
#ifndef WOLFSSL_NO_ML_DSA_65
    if (level == 3) {
        ret = wc_dilithium_import_private(bench_dilithium_level3_key,
            sizeof_bench_dilithium_level3_key, &key);
    }
#endif
#ifndef WOLFSSL_NO_ML_DSA_87
    if (level == 5) {
        ret = wc_dilithium_import_private(bench_dilithium_level5_key,
            sizeof_bench_dilithium_level5_key, &key);
    }
#endif
    if (ret != 0) {
        printf("Failed to load private key\n");
        return;
    }

#endif

#ifndef WOLFSSL_DILITHIUM_NO_SIGN
    if (level == 2) {
        x = DILITHIUM_LEVEL2_SIG_SIZE;
    }
    else if (level == 3) {
        x = DILITHIUM_LEVEL3_SIG_SIZE;
    }
    else {
        x = DILITHIUM_LEVEL5_SIG_SIZE;
    }

    RESET_MULTI_VALUE_STATS_VARS();

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < agreeTimes; i++) {
            if (ret == 0) {
                ret = wc_dilithium_sign_msg(msg, sizeof(msg), sig, &x, &key,
                                            GLOBAL_RNG);
                if (ret != 0) {
                    printf("wc_dilithium_sign_msg failed\n");
                }
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    if (ret == 0) {
        bench_stats_asym_finish("ML-DSA", params, desc[4], 0, count, start,
                                ret);
    #ifdef MULTI_VALUE_STATISTICS
        bench_multi_value_stats(max, min, sum, squareSum, runs);
    #endif
    }

#endif

#if !defined(WOLFSSL_DILITHIUM_NO_VERIFY) && \
    (defined(WOLFSSL_DILITHIUM_NO_SIGN) || \
     defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY))

#ifndef WOLFSSL_NO_ML_DSA_44
    if (level == 2) {
    #ifdef WOLFSSL_DILITHIUM_NO_SIGN
        x = sizeof_bench_dilithium_level2_sig;
        XMEMCPY(sig, bench_dilithium_level2_sig, x);
    #endif
        ret = wc_dilithium_import_public(bench_dilithium_level2_pubkey,
            sizeof_bench_dilithium_level2_pubkey, &key);
    }
#endif
#ifndef WOLFSSL_NO_ML_DSA_65
    if (level == 3) {
    #ifdef WOLFSSL_DILITHIUM_NO_SIGN
        x = sizeof_bench_dilithium_level3_sig;
        XMEMCPY(sig, bench_dilithium_level3_sig, x);
    #endif
        ret = wc_dilithium_import_public(bench_dilithium_level3_pubkey,
            sizeof_bench_dilithium_level3_pubkey, &key);
    }
#endif
#ifndef WOLFSSL_NO_ML_DSA_87
    if (level == 5) {
    #ifdef WOLFSSL_DILITHIUM_NO_SIGN
        x = sizeof_bench_dilithium_level5_sig;
        XMEMCPY(sig, bench_dilithium_level5_sig, x);
    #endif
        ret = wc_dilithium_import_public(bench_dilithium_level5_pubkey,
            sizeof_bench_dilithium_level5_pubkey, &key);
    }
#endif
    if (ret != 0) {
        printf("Failed to load public key\n");
        return;
    }

#endif

#ifndef WOLFSSL_DILITHIUM_NO_VERIFY
    RESET_MULTI_VALUE_STATS_VARS();

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < agreeTimes; i++) {
            if (ret == 0) {
                int verify = 0;
                ret = wc_dilithium_verify_msg(sig, x, msg, sizeof(msg),
                                              &verify, &key);

                if (ret != 0 || verify != 1) {
                    printf("wc_dilithium_verify_msg failed %d, verify %d\n",
                           ret, verify);
                    ret = -1;
                }
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    if (ret == 0) {
        bench_stats_asym_finish("ML-DSA", params, desc[5], 0, count, start,
                                ret);
    #ifdef MULTI_VALUE_STATISTICS
        bench_multi_value_stats(max, min, sum, squareSum, runs);
    #endif
    }
#endif

    wc_dilithium_free(&key);
}
#endif /* HAVE_DILITHIUM */

#ifdef HAVE_SPHINCS
void bench_sphincsKeySign(byte level, byte optim)
{
    int    ret = 0;
    sphincs_key key;
    double start;
    int    i, count;
    byte   sig[SPHINCS_MAX_SIG_SIZE];
    byte   msg[512];
    word32 x = 0;
    const char**desc = bench_desc_words[lng_index];
    DECLARE_MULTI_VALUE_STATS_VARS()

    ret = wc_sphincs_init(&key);
    if (ret != 0) {
        printf("wc_sphincs_init failed %d\n", ret);
        return;
    }

    ret = wc_sphincs_set_level_and_optim(&key, level, optim);
    if (ret != 0) {
        printf("wc_sphincs_set_level_and_optim() failed %d\n", ret);
    }

    if (ret == 0) {
        ret = -1;
        if ((level == 1) && (optim == FAST_VARIANT)) {
            ret = wc_sphincs_import_private_key(bench_sphincs_fast_level1_key,
                      sizeof_bench_sphincs_fast_level1_key, NULL, 0, &key);
        }
        else if ((level == 3) && (optim == FAST_VARIANT)) {
            ret = wc_sphincs_import_private_key(bench_sphincs_fast_level3_key,
                      sizeof_bench_sphincs_fast_level3_key, NULL, 0, &key);
        }
        else if ((level == 5) && (optim == FAST_VARIANT)) {
            ret = wc_sphincs_import_private_key(bench_sphincs_fast_level5_key,
                      sizeof_bench_sphincs_fast_level5_key, NULL, 0, &key);
        }
        else if ((level == 1) && (optim == SMALL_VARIANT)) {
            ret = wc_sphincs_import_private_key(
                      bench_sphincs_small_level1_key,
                      sizeof_bench_sphincs_small_level1_key, NULL, 0, &key);
        }
        else if ((level == 3) && (optim == SMALL_VARIANT)) {
            ret = wc_sphincs_import_private_key(
                      bench_sphincs_small_level3_key,
                      sizeof_bench_sphincs_small_level3_key, NULL, 0, &key);
        }
        else if ((level == 5) && (optim == SMALL_VARIANT)) {
            ret = wc_sphincs_import_private_key(
                      bench_sphincs_small_level5_key,
                      sizeof_bench_sphincs_small_level5_key, NULL, 0, &key);
        }

        if (ret != 0) {
            printf("wc_sphincs_import_private_key failed %d\n", ret);
        }
    }

    /* make dummy msg */
    for (i = 0; i < (int)sizeof(msg); i++) {
        msg[i] = (byte)i;
    }

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < agreeTimes; i++) {
            if (ret == 0) {
                if ((level == 1) && (optim == FAST_VARIANT)) {
                    x = SPHINCS_FAST_LEVEL1_SIG_SIZE;
                }
                else if ((level == 3) && (optim == FAST_VARIANT)) {
                    x = SPHINCS_FAST_LEVEL3_SIG_SIZE;
                }
                else if ((level == 5) && (optim == FAST_VARIANT)) {
                    x = SPHINCS_FAST_LEVEL5_SIG_SIZE;
                }
                else if ((level == 1) && (optim == SMALL_VARIANT)) {
                    x = SPHINCS_SMALL_LEVEL1_SIG_SIZE;
                }
                else if ((level == 3) && (optim == SMALL_VARIANT)) {
                    x = SPHINCS_SMALL_LEVEL3_SIG_SIZE;
                }
                else if ((level == 5) && (optim == SMALL_VARIANT)) {
                    x = SPHINCS_SMALL_LEVEL5_SIG_SIZE;
                }

                ret = wc_sphincs_sign_msg(msg, sizeof(msg), sig, &x, &key, GLOBAL_RNG);
                if (ret != 0) {
                    printf("wc_sphincs_sign_msg failed\n");
                }
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    if (ret == 0) {
        if (optim == FAST_VARIANT) {
            bench_stats_asym_finish("SPHINCS-FAST", level, desc[4], 0, count,
                                    start, ret);
        }
        else {
            bench_stats_asym_finish("SPHINCS-SMALL", level, desc[4], 0, count,
                                    start, ret);
        }
    #ifdef MULTI_VALUE_STATISTICS
        bench_multi_value_stats(max, min, sum, squareSum, runs);
    #endif
    }

    RESET_MULTI_VALUE_STATS_VARS();

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < agreeTimes; i++) {
            if (ret == 0) {
                int verify = 0;
                ret = wc_sphincs_verify_msg(sig, x, msg, sizeof(msg), &verify,
                                            &key);

                if (ret != 0 || verify != 1) {
                    printf("wc_sphincs_verify_msg failed %d, verify %d\n",
                           ret, verify);
                    ret = -1;
                }
            }
            RECORD_MULTI_VALUE_STATS();
        }
        count += i;
    } while (bench_stats_check(start)
#ifdef MULTI_VALUE_STATISTICS
       || runs < minimum_runs
#endif
       );

    if (ret == 0) {
        if (optim == FAST_VARIANT) {
            bench_stats_asym_finish("SPHINCS-FAST", level, desc[5], 0, count,
                                    start, ret);
        }
        else {
            bench_stats_asym_finish("SPHINCS-SMALL", level, desc[5], 0, count,
                                    start, ret);
        }
    #ifdef MULTI_VALUE_STATISTICS
        bench_multi_value_stats(max, min, sum, squareSum, runs);
    #endif
    }

    wc_sphincs_free(&key);
}
#endif /* HAVE_SPHINCS */

#if defined(_WIN32) && !defined(INTIME_RTOS)

    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>

    double current_time(int reset)
    {
        static int init = 0;
        static LARGE_INTEGER freq;

        LARGE_INTEGER count;

        (void)reset;

        if (!init) {
            QueryPerformanceFrequency(&freq);
            init = 1;
        }

        QueryPerformanceCounter(&count);

#ifdef BENCH_MICROSECOND
        return ((double)count.QuadPart * 1000000) / freq.QuadPart;
#else
        return (double)count.QuadPart / freq.QuadPart;
#endif
    }

#elif defined MICROCHIP_PIC32
    #if defined(WOLFSSL_MICROCHIP_PIC32MZ)
        #define CLOCK 80000000.0
    #else
        #define CLOCK 40000000.0
    #endif
    extern void WriteCoreTimer(word32 t);
    extern word32 ReadCoreTimer(void);
    double current_time(int reset)
    {
        unsigned int ns;

        if (reset) {
            WriteCoreTimer(0);
        }

        /* get timer in ns */
        ns = ReadCoreTimer();

        /* return seconds as a double */
        return ( ns / CLOCK * 2.0);
    }

#elif defined(WOLFSSL_IAR_ARM_TIME) || defined (WOLFSSL_MDK_ARM) || \
      defined(WOLFSSL_USER_CURRTIME) || defined(WOLFSSL_CURRTIME_REMAP)
    /* declared above at line 239 */
    /* extern   double current_time(int reset); */

#elif defined(FREERTOS)

    #ifdef PLATFORMIO
        #include <freertos/FreeRTOS.h>
        #include <freertos/task.h>
    #else
        #include "task.h"
    #endif

#if defined(WOLFSSL_ESPIDF)
    /* prototype definition */
    int construct_argv();
    extern char* __argv[22];

    /* current_time(reset)
     *
     * Benchmark passage of time, in fractional seconds.
     *   [reset] is non zero to adjust timer or counter to zero
     *
     * Use care when repeatedly calling calling. See implementation. */
    double current_time(int reset)
    {
        double ret;
    #if ESP_IDF_VERSION_MAJOR >= 4
        TickType_t tickCount; /* typically 32 bit, local FreeRTOS ticks */
    #else
        portTickType tickCount;
    #endif

    #if defined(__XTENSA__)
        (void)reset;

        if (reset) {
            /* TODO: Determine a mechanism for reset that does not interfere
             * with freeRTOS tick. Using this code for Xtensa appears to cause
             * RTOS tick timer to stick. See "last_tickCount unchanged".
            ESP_LOGW(TAG, "Current_time() reset!");
            portTICK_TYPE_ENTER_CRITICAL();
            {
                esp_cpu_set_cycle_count((esp_cpu_cycle_count_t)0);
                _esp_cpu_count_last = xthal_get_ccount();
                _esp_cpu_count_last = esp_cpu_get_cycle_count();
            }
            portTICK_TYPE_EXIT_CRITICAL();
            */
        }
    #else
        /* Only reset the CPU counter for RISC-V */
        if (reset) {
            ESP_LOGV(TAG, "current_time() reset!");
            /* TODO: why does Espressif esp_cpu_get_cycle_count() cause
             * unexpected rollovers in return values for Xtensa but not RISC-V?
             * See also esp_get_cycle_count_ex() */
            #ifdef __XTENSA__
                _esp_cpu_count_last = xthal_get_ccount();
            #else
                #if ESP_IDF_VERSION_MAJOR >= 5
                    esp_cpu_set_cycle_count((esp_cpu_cycle_count_t)0);
                    _esp_cpu_count_last = esp_cpu_get_cycle_count();
                #else
                    cpu_hal_set_cycle_count((uint32_t)0);
                    _esp_cpu_count_last = cpu_hal_get_cycle_count();
                #endif
            #endif
       }
    #endif

    /* tick count == ms, if configTICK_RATE_HZ is set to 1000 */
    tickCount = xTaskGetTickCount(); /* RTOS ticks, not CPU cycles!
      The count of ticks since vTaskStartScheduler was called,
      typiclly in app_startup.c */

    #ifdef DEBUG_WOLFSSL_BENCHMARK_TIMING
        ESP_LOGV(TAG, "tickCount = " TFMT, tickCount);
        if (tickCount == last_tickCount) {
            ESP_LOGW(TAG, "last_tickCount unchanged?" TFMT, tickCount);

        }
        if (tickCount < last_tickCount) {
            ESP_LOGW(TAG, "last_tickCount overflow?");
        }
    #endif

    if (reset) {
        #ifdef DEBUG_WOLFSSL_BENCHMARK_TIMING
            ESP_LOGW(TAG, "Assign last_tickCount = " TFMT, tickCount);
        #endif
        last_tickCount = tickCount;
    }
    else {
        #ifdef DEBUG_WOLFSSL_BENCHMARK_TIMING
            ESP_LOGV(TAG, "No Reset last_tickCount = " TFMT, tickCount);
        #endif
    }

    #if defined(configTICK_RATE_HZ) && defined(CONFIG_FREERTOS_HZ)
        ret = (double)tickCount / configTICK_RATE_HZ;
    #else
        ESP_LOGW(TAG, "Warning: configTICK_RATE_HZ not defined,"
                        "assuming 1000 Hz.");
        ret = (double)(tickCount / 1000.0);
    #endif /* configTICK_RATE_HZ */

        return ret;

    } /* current_time */
#else
    /* current_time(reset)
    *
    * Benchmark passage of time, in fractional seconds.
    *   [reset] is non zero to adjust timer or counter to zero
    *
    * Use care when repeatedly calling calling. See implementation. */
    double current_time(int reset)
    {
        portTickType tickCount = xTaskGetTickCount();
        /* if configTICK_RATE_HZ is available use if (default is 1000) */
    #ifdef configTICK_RATE_HZ
        return (double)tickCount / configTICK_RATE_HZ;
    #else
        return (double)tickCount / 1000;
    #endif
    }
#endif


#elif defined (WOLFSSL_TIRTOS)

    extern double current_time(int reset);

#elif defined(FREESCALE_MQX)

    double current_time(int reset)
    {
        TIME_STRUCT tv;
        _time_get(&tv);

        return (double)tv.SECONDS + (double)tv.MILLISECONDS / 1000;
    }

#elif (defined(WOLFSSL_MAX3266X_OLD) || defined(WOLFSSL_MAX3266X)) \
            && defined(MAX3266X_RTC)

    double current_time(int reset)
    {
        (void)reset;
        return wc_MXC_RTC_Time();
    }

#elif defined(FREESCALE_KSDK_BM)

    double current_time(int reset)
    {
        return (double)OSA_TimeGetMsec() / 1000;
    }

#elif defined(WOLFSSL_CMSIS_RTOS) || defined(WOLFSSL_CMSIS_RTOSv2)

    double current_time(int reset)
    {
        (void)reset;
        return (double)osKernelGetTickCount() / 1000.0;
    }

#elif defined(WOLFSSL_EMBOS)

    #include "RTOS.h"

    double current_time(int reset)
    {
        double time_now;
        double current_s = OS_GetTime() / 1000.0;
        double current_us = OS_GetTime_us() / MILLION_VALUE;
        time_now = (double)( current_s + current_us);

        (void) reset;

        return time_now;
    }
#elif defined(WOLFSSL_SGX)
    double current_time(int reset);

#elif defined(WOLFSSL_DEOS)
    double current_time(int reset)
    {
        const uint32_t systemTickTimeInHz
                         = 1000000 / systemTickInMicroseconds();

        const volatile uint32_t *systemTickPtr = systemTickPointer();

        (void)reset;

        return (double) *systemTickPtr/systemTickTimeInHz;
    }

#elif defined(MICRIUM)
    double current_time(int reset)
    {

#if (OS_VERSION < 50000)
        CPU_ERR err;
        (void)reset;
        return (double) CPU_TS_Get32()/CPU_TS_TmrFreqGet(&err);
#else
        RTOS_ERR  err;
        double ret = 0;
        OS_TICK tick = OSTimeGet(&err);
        OS_RATE_HZ rate = OSTimeTickRateHzGet(&err);
        (void)reset;

        if (RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE) {
            ret = ((double)tick)/rate;
        }
        return ret;
#endif
    }
#elif defined(WOLFSSL_ZEPHYR)

    #include <time.h>

    double current_time(int reset)
    {
        int64_t t;
        (void)reset;
     #if defined(CONFIG_ARCH_POSIX)
         k_cpu_idle();
     #endif
        t = k_uptime_get(); /* returns current uptime in milliseconds */
        return (double)(t / 1000);
    }

#elif defined(WOLFSSL_NETBURNER)
    #include <predef.h>
    #include <utils.h>
    #include <constants.h>

    double current_time(int reset)
    {
        DWORD ticks = TimeTick; /* ticks since system start */
        (void)reset;

        return (double) ticks/TICKS_PER_SECOND;
    }
#elif defined(WOLFSSL_RPIPICO)
    #include "pico/stdlib.h"

    double current_time(int reset)
    {
        (void)reset;

        return (double) time_us_64() / 1000000;
    }
#elif defined(THREADX)
    #include "tx_api.h"
    double current_time(int reset)
    {
        (void)reset;
        return (double) tx_time_get() / TX_TIMER_TICKS_PER_SECOND;
    }

#elif defined(WOLFSSL_XILINX)
    #ifdef XPAR_VERSAL_CIPS_0_PSPMC_0_PSV_CORTEXA72_0_TIMESTAMP_CLK_FREQ
        #define COUNTS_PER_SECOND    \
                XPAR_VERSAL_CIPS_0_PSPMC_0_PSV_CORTEXA72_0_TIMESTAMP_CLK_FREQ
    #else
        #define COUNTS_PER_SECOND     \
                XPAR_CPU_CORTEXA53_0_TIMESTAMP_CLK_FREQ
    #endif

    double current_time(int reset)
    {
        double timer;
        uint64_t cntPct = 0;
        asm volatile("mrs %0, CNTPCT_EL0" : "=r" (cntPct));

        /* Convert to milliseconds */
        timer = (double)(cntPct / (COUNTS_PER_SECOND / 1000));
        /* Convert to seconds.millisecond */
        timer /= 1000;
        return timer;
    }

#elif defined(LINUX_RUSAGE_UTIME)

    #include <sys/time.h>
    #include <sys/resource.h>

    static struct rusage base_rusage;
    static struct rusage cur_rusage;

    double current_time(int reset)
    {
        struct rusage rusage;

        (void)reset;

        LIBCALL_CHECK_RET(getrusage(RUSAGE_SELF, &rusage));

        if (reset)
            base_rusage = rusage;
        else
            cur_rusage = rusage;

        /* only consider user time, as system time is host-related overhead
         * outside wolfcrypt.
         */
        return (double)rusage.ru_utime.tv_sec +
            (double)rusage.ru_utime.tv_usec / MILLION_VALUE;
    }

    static void check_for_excessive_stime(const char *desc,
                                          const char *desc_extra)
    {
        double start_utime = (double)base_rusage.ru_utime.tv_sec +
            (double)base_rusage.ru_utime.tv_usec / MILLION_VALUE;
        double start_stime = (double)base_rusage.ru_stime.tv_sec +
            (double)base_rusage.ru_stime.tv_usec / MILLION_VALUE;
        double cur_utime = (double)cur_rusage.ru_utime.tv_sec +
            (double)cur_rusage.ru_utime.tv_usec / MILLION_VALUE;
        double cur_stime = (double)cur_rusage.ru_stime.tv_sec +
            (double)cur_rusage.ru_stime.tv_usec / MILLION_VALUE;
        double stime_utime_ratio =
            (cur_stime - start_stime) / (cur_utime - start_utime);
        if (stime_utime_ratio > .1)
            printf("%swarning, "
                   "excessive system time ratio for %s%s (" FLT_FMT_PREC "%%).\n",
                   err_prefix, desc, desc_extra,
                   FLT_FMT_PREC_ARGS(3, stime_utime_ratio * 100.0));
    }

#elif defined(WOLFSSL_LINUXKM)

    double current_time(int reset)
    {
        (void)reset;
        u64 ns = ktime_get_ns();
        return (double)ns / 1000000000.0;
    }

#elif defined(WOLFSSL_GAISLER_BCC)

    #include <bcc/bcc.h>
    double current_time(int reset)
    {
        (void)reset;
        uint32_t us = bcc_timer_get_us();
        return (double)us / 1000000.0;
    }

#else

    #include <time.h>
    #include <sys/time.h>

    double current_time(int reset)
    {
        struct timespec tv;

        (void)reset;

        LIBCALL_CHECK_RET(clock_gettime(CLOCK_REALTIME, &tv));

    #ifdef BENCH_MICROSECOND
        return (double)tv.tv_sec * 1000000 + (double)tv.tv_nsec / 1000;
    #else
        return (double)tv.tv_sec + (double)tv.tv_nsec / 1000000000;
    #endif
    }

#endif /* _WIN32 */

#if defined(HAVE_GET_CYCLES)

    #if defined(WOLFSSL_ESPIDF)
        /* Generic CPU cycle counter for either Xtensa or RISC-V */
        static WC_INLINE word64 esp_get_cpu_benchmark_cycles(void)
        {
            /* Reminder for long duration between calls with
             * multiple overflows will not be detected. */
            return esp_get_cycle_count_ex();
        }

    /* implement other architectures here */

    #else
        static WC_INLINE word64 get_intel_cycles(void)
        {
            unsigned int lo_c, hi_c;
            __asm__ __volatile__ (
                "cpuid\n\t"
                "rdtsc"
                    : "=a"(lo_c), "=d"(hi_c)   /* out */
                    : "a"(0)                   /* in */
                    : "%ebx", "%ecx");         /* clobber */
            return ((word64)lo_c) | (((word64)hi_c) << 32);
        }
    #endif

#endif /* HAVE_GET_CYCLES */

void benchmark_configure(word32 block_size)
{
    /* must be greater than 0 */
    if (block_size > 0) {
        numBlocks = (int)((word32)numBlocks * bench_size / block_size);
        bench_size = block_size;
    }
}

#ifndef NO_MAIN_DRIVER

#ifndef MAIN_NO_ARGS

#ifndef WOLFSSL_BENCHMARK_ALL
/* Display the algorithm string and keep to 80 characters per line.
 *
 * str   Algorithm string to print.
 * line  Length of line used so far.
 */
#ifndef BENCH_MAX_LINE
#define BENCH_MAX_LINE 80
#endif
static void print_alg(const char* str, int* line)
{
    const char* const ident = "             ";
    if (*line == 0) {
        printf("%s", ident);
        *line = (int)XSTRLEN(ident);
    }
    printf(" %s", str);
    *line += (int)XSTRLEN(str) + 1;
    if (*line > BENCH_MAX_LINE) {
        printf("\n");
        *line = 0;
    }
}
#endif /* WOLFSSL_BENCHMARK_ALL */

/* Display the usage options of the benchmark program. */
static void Usage(void)
{
    int e = 0;
#ifndef WOLFSSL_BENCHMARK_ALL
    int i;
    int line;
#endif

    printf("benchmark\n");
    printf("%s", bench_Usage_msg1[lng_index][e++]);    /* option -? */
    printf("%s", bench_Usage_msg1[lng_index][e++]);    /* English / Japanese */
    printf("%s", bench_Usage_msg1[lng_index][e++]);    /* option -csv */
    printf("%s", bench_Usage_msg1[lng_index][e++]);    /* option -base10 */
#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
    printf("%s", bench_Usage_msg1[lng_index][e++]);    /* option -no_aad */
    printf("%s", bench_Usage_msg1[lng_index][e++]);    /* option -aad_size */
    printf("%s", bench_Usage_msg1[lng_index][e++]);    /* option -all_aad */
#else
    e += 3;
#endif
    printf("%s", bench_Usage_msg1[lng_index][e++]);    /* option -dgst_full */
#ifndef NO_RSA
    printf("%s", bench_Usage_msg1[lng_index][e++]);    /* option -ras_sign */
    #ifdef WOLFSSL_KEY_GEN
    printf("%s", bench_Usage_msg1[lng_index][e]);    /* option -rsa-sz */
    #endif
    e++;
#else
    e += 2;
#endif
#if !defined(NO_DH) && defined(HAVE_FFDHE_2048)
    printf("%s", bench_Usage_msg1[lng_index][e]);    /* option -ffdhe2048 */
#endif
    e++;
#if !defined(NO_DH) && defined(HAVE_FFDHE_3072)
    printf("%s", bench_Usage_msg1[lng_index][e]);    /* option -ffdhe3072 */
#endif
    e++;
#if defined(HAVE_ECC) && !defined(NO_ECC256)
    printf("%s", bench_Usage_msg1[lng_index][e]);    /* option -p256 */
#endif
    e++;
#if defined(HAVE_ECC) && defined(HAVE_ECC384)
    printf("%s", bench_Usage_msg1[lng_index][e]);   /* option -p384 */
#endif
    e++;
#if defined(HAVE_ECC) && defined(HAVE_ECC521)
    printf("%s", bench_Usage_msg1[lng_index][e]);   /* option -p521 */
#endif
    e++;
#if defined(HAVE_ECC)
    printf("%s", bench_Usage_msg1[lng_index][e]);   /* option -ecc-all */
#endif
    e++;
#ifndef WOLFSSL_BENCHMARK_ALL
    printf("%s", bench_Usage_msg1[lng_index][e]);   /* option -<alg> */
    line = 0;
    for (i=0; bench_cipher_opt[i].str != NULL; i++)
        print_alg(bench_cipher_opt[i].str, &line);
    for (i=0; bench_digest_opt[i].str != NULL; i++)
        print_alg(bench_digest_opt[i].str, &line);
    for (i=0; bench_mac_opt[i].str != NULL; i++)
        print_alg(bench_mac_opt[i].str, &line);
    for (i=0; bench_kdf_opt[i].str != NULL; i++)
        print_alg(bench_kdf_opt[i].str, &line);
    for (i=0; bench_asym_opt[i].str != NULL; i++)
        print_alg(bench_asym_opt[i].str, &line);
    for (i=0; bench_other_opt[i].str != NULL; i++)
        print_alg(bench_other_opt[i].str, &line);
#if defined(WOLFSSL_HAVE_KYBER) || defined(HAVE_FALCON) || \
    defined(HAVE_DILITHIUM) || defined(HAVE_SPHINCS)
    for (i=0; bench_pq_asym_opt[i].str != NULL; i++)
        print_alg(bench_pq_asym_opt[i].str, &line);
#if defined(HAVE_SPHINCS)
    for (i=0; bench_pq_asym_opt2[i].str != NULL; i++)
        print_alg(bench_pq_asym_opt2[i].str, &line);
#endif /* HAVE_SPHINCS */
#endif
#if defined(BENCH_PQ_STATEFUL_HBS)
    for (i=0; bench_pq_hash_sig_opt[i].str != NULL; i++)
        print_alg(bench_pq_hash_sig_opt[i].str, &line);
#endif /* BENCH_PQ_STATEFUL_HBS */
    printf("\n");
#endif /* !WOLFSSL_BENCHMARK_ALL */
    e++;
    printf("%s", bench_Usage_msg1[lng_index][e++]); /* option -lng */
    printf("%s", bench_Usage_msg1[lng_index][e++]); /* option <num> */
    printf("%s", bench_Usage_msg1[lng_index][e++]); /* option -blocks <num> */
#ifdef WC_ENABLE_BENCH_THREADING
    printf("%s", bench_Usage_msg1[lng_index][e]);   /* option -threads <num> */
#endif
    e++;
#ifdef WC_BENCH_TRACK_STATS
    printf("%s", bench_Usage_msg1[lng_index][e]);   /* option -print */
#endif
    e++;
#ifndef NO_FILESYSTEM
    printf("%s", bench_Usage_msg1[lng_index][e]);   /* option -hash_input */
#endif
    e++;
#ifndef NO_FILESYSTEM
    printf("%s", bench_Usage_msg1[lng_index][e]);   /* option -cipher_input */
#endif
#ifdef MULTI_VALUE_STATISTICS
    e++;
    printf("%s", bench_Usage_msg1[lng_index][e]);   /* option -min_runs */
#endif
}

/* Match the command line argument with the string.
 *
 * arg  Command line argument.
 * str  String to check for.
 * return 1 if the command line argument matches the string, 0 otherwise.
 */
static int string_matches(const char* arg, const char* str)
{
    return XSTRCMP(arg, str) == 0;
}
#endif /* MAIN_NO_ARGS */

/*
** ----------------------------------------------------------------------------
** determine how the benchmarks are called, the function name varies:
** ----------------------------------------------------------------------------
*/
#if !defined(NO_MAIN_DRIVER) && !defined(NO_MAIN_FUNCTION)
    #if defined(WOLFSSL_ESPIDF) || defined(_WIN32_WCE)

        /* for some environments, we'll call a function wolf_benchmark_task: */
        int wolf_benchmark_task(void)

    #elif defined(MAIN_NO_ARGS)

        /* otherwise we'll use main() with no arguments as desired: */
        int main()

    #else

        /* else we'll be calling main with default arg parameters */
        int main(int argc, char** argv)

    #endif
{
    /* Code for main() or wolf_benchmark_task() */
    #ifdef WOLFSSL_ESPIDF
        int argc = construct_argv();
        char** argv = (char**)__argv;
    #elif defined(MAIN_NO_ARGS)
        int argc = 0;
        char** argv = NULL;
    #endif

    return wolfcrypt_benchmark_main(argc, argv);
}
#endif /* !NO_MAIN_DRIVER && !NO_MAIN_FUNCTION */

int wolfcrypt_benchmark_main(int argc, char** argv)
{
    int ret = 0;

#ifndef MAIN_NO_ARGS
    int optMatched;
    #ifndef WOLFSSL_BENCHMARK_ALL
        int i;
    #endif
#endif

    benchmark_static_init(1);

    printf("%s------------------------------------------------------------------------------\n",
           info_prefix);
    printf("%s wolfSSL version %s\n", info_prefix, LIBWOLFSSL_VERSION_STRING);
    printf("%s------------------------------------------------------------------------------\n",
           info_prefix);

#ifndef MAIN_NO_ARGS
    while (argc > 1) {
        if (string_matches(argv[1], "-?")) {
            if (--argc > 1) {
                lng_index = XATOI((++argv)[1]);
                if (lng_index<0 || lng_index>1) {
                    lng_index = 0;
                }
            }
            Usage();
            return 0;
        }
        else if (string_matches(argv[1], "-lng")) {
            argc--;
            argv++;
            if (argc > 1) {
                lng_index = XATOI(argv[1]);
                if (lng_index<0 || lng_index>1) {
                    printf("invalid number(%d) is specified. [<num> :0-1]\n",
                           lng_index);
                    lng_index = 0;
                }
            }
        }
        else if (string_matches(argv[1], "-base10"))
            base2 = 0;
#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
        else if (string_matches(argv[1], "-no_aad"))
            aes_aad_options = AAD_SIZE_ZERO;
        else if (string_matches(argv[1], "-all_aad"))
            aes_aad_options |= AAD_SIZE_ZERO | AAD_SIZE_DEFAULT;
        else if (string_matches(argv[1], "-aad_size")) {
            argc--;
            argv++;
            if (argc > 1) {
                aes_aad_size = (word32)XATOI(argv[1]);
                aes_aad_options |= AAD_SIZE_CUSTOM;
            }
        }
#endif
        else if (string_matches(argv[1], "-dgst_full"))
            digest_stream = 0;
#ifdef HAVE_CHACHA
        else if (string_matches(argv[1], "-enc_only"))
            encrypt_only = 1;
#endif
#ifndef NO_RSA
        else if (string_matches(argv[1], "-rsa_sign"))
            rsa_sign_verify = 1;
#endif
#if !defined(NO_DH) && defined(HAVE_FFDHE_2048)
        else if (string_matches(argv[1], "-ffdhe2048"))
            use_ffdhe = 2048;
#endif
#if !defined(NO_DH) && defined(HAVE_FFDHE_3072)
        else if (string_matches(argv[1], "-ffdhe3072"))
            use_ffdhe = 3072;
#endif
#if !defined(NO_DH) && defined(HAVE_FFDHE_4096)
        else if (string_matches(argv[1], "-ffdhe4096"))
            use_ffdhe = 4096;
#endif
#if defined(HAVE_ECC) && !defined(NO_ECC256)
        else if (string_matches(argv[1], "-p256"))
            bench_asym_algs |= BENCH_ECC_P256;
#endif
#if defined(HAVE_ECC) && defined(HAVE_ECC384)
        else if (string_matches(argv[1], "-p384"))
            bench_asym_algs |= BENCH_ECC_P384;
#endif
#if defined(HAVE_ECC) && defined(HAVE_ECC521)
        else if (string_matches(argv[1], "-p521"))
            bench_asym_algs |= BENCH_ECC_P521;
#endif
#ifdef BENCH_ASYM
        else if (string_matches(argv[1], "-csv")) {
            csv_format = 1;
        }
#endif

#ifdef WC_ENABLE_BENCH_THREADING
        else if (string_matches(argv[1], "-threads")) {
            argc--;
            argv++;
            if (argc > 1) {
                g_threadCount = XATOI(argv[1]);
                if (g_threadCount < 1 || lng_index > 128){
                    printf("invalid number(%d) is specified. [<num> :1-128]\n",
                        g_threadCount);
                    g_threadCount = 0;
                }
            }
        }
#endif
#ifdef WC_BENCH_TRACK_STATS
        else if (string_matches(argv[1], "-print")) {
            gPrintStats = 1;
        }
#endif
        else if (string_matches(argv[1], "-blocks")) {
            argc--;
            argv++;
            if (argc > 1)
                numBlocks = XATOI(argv[1]);
        }
#ifndef NO_FILESYSTEM
        else if (string_matches(argv[1], "-hash_input")) {
            argc--;
            argv++;
            if (argc > 1)
                hash_input = argv[1];
        }
        else if (string_matches(argv[1], "-cipher_input")) {
            argc--;
            argv++;
            if (argc > 1)
                cipher_input = argv[1];
        }
#endif
#ifdef MULTI_VALUE_STATISTICS
        else if (string_matches(argv[1], "-min_runs")) {
            argc--;
            argv++;
            if (argc > 1) {
                minimum_runs = XATOI(argv[1]);
            }
        }
#endif
        else if (argv[1][0] == '-') {
            optMatched = 0;
#ifndef WOLFSSL_BENCHMARK_ALL
            /* Check known algorithm choosing command line options. */
            /* Known cipher algorithms */
            for (i=0; !optMatched && bench_cipher_opt[i].str != NULL; i++) {
                if (string_matches(argv[1], bench_cipher_opt[i].str)) {
                    bench_cipher_algs |= bench_cipher_opt[i].val;
                    bench_all = 0;
                    optMatched = 1;
                }
            }
            /* Known digest algorithms */
            for (i=0; !optMatched && bench_digest_opt[i].str != NULL; i++) {
                if (string_matches(argv[1], bench_digest_opt[i].str)) {
                    bench_digest_algs |= bench_digest_opt[i].val;
                    bench_all = 0;
                    optMatched = 1;
                }
            }
            /* Known MAC algorithms */
            for (i=0; !optMatched && bench_mac_opt[i].str != NULL; i++) {
                if (string_matches(argv[1], bench_mac_opt[i].str)) {
                    bench_mac_algs |= bench_mac_opt[i].val;
                    bench_all = 0;
                    optMatched = 1;
                }
            }
            /* Known KDF algorithms */
            for (i=0; !optMatched && bench_kdf_opt[i].str != NULL; i++) {
                if (string_matches(argv[1], bench_kdf_opt[i].str)) {
                    bench_kdf_algs |= bench_kdf_opt[i].val;
                    bench_all = 0;
                    optMatched = 1;
                }
            }
            /* Known asymmetric algorithms */
            for (i=0; !optMatched && bench_asym_opt[i].str != NULL; i++) {
                if (string_matches(argv[1], bench_asym_opt[i].str)) {
                    bench_asym_algs |= bench_asym_opt[i].val;
                    bench_all = 0;
                    optMatched = 1;
                }
            }
        #if defined(WOLFSSL_HAVE_KYBER) || defined(HAVE_FALCON) || \
            defined(HAVE_DILITHIUM) || defined(HAVE_SPHINCS)
            /* Known asymmetric post-quantum algorithms */
            for (i=0; !optMatched && bench_pq_asym_opt[i].str != NULL; i++) {
                if (string_matches(argv[1], bench_pq_asym_opt[i].str)) {
                    bench_pq_asym_algs |= bench_pq_asym_opt[i].val;
                    bench_all = 0;
                    optMatched = 1;
                }
            }
        #ifdef HAVE_SPHINCS
            /* Both bench_pq_asym_opt and bench_pq_asym_opt2 are looking for
             * -pq, so we need to do a special case for -pq since optMatched
             * was set to 1 just above. */
            if ((bench_pq_asym_opt[0].str != NULL) &&
                string_matches(argv[1], bench_pq_asym_opt[0].str))
            {
                bench_pq_asym_algs2 |= bench_pq_asym_opt2[0].val;
                bench_all = 0;
                optMatched = 1;
            }
            for (i=1; !optMatched && bench_pq_asym_opt2[i].str != NULL; i++) {
                if (string_matches(argv[1], bench_pq_asym_opt2[i].str)) {
                    bench_pq_asym_algs2 |= bench_pq_asym_opt2[i].val;
                    bench_all = 0;
                    optMatched = 1;
                }
            }
        #endif
        #endif
            /* Other known cryptographic algorithms */
            for (i=0; !optMatched && bench_other_opt[i].str != NULL; i++) {
                if (string_matches(argv[1], bench_other_opt[i].str)) {
                    bench_other_algs |= bench_other_opt[i].val;
                    bench_all = 0;
                    optMatched = 1;
                }
            }

        #if defined(BENCH_PQ_STATEFUL_HBS)
            /* post-quantum stateful hash-based signatures */
            for (i=0; !optMatched && bench_pq_hash_sig_opt[i].str != NULL; i++) {
                if (string_matches(argv[1], bench_pq_hash_sig_opt[i].str)) {
                    bench_pq_hash_sig_algs |= bench_pq_hash_sig_opt[i].val;
                    bench_all = 0;
                    optMatched = 1;
                }
            }
        #endif /* BENCH_PQ_STATEFUL_HBS */
#endif
            if (!optMatched) {
                printf("Option not recognized: %s\n", argv[1]);
                Usage();
                return 1;
            }
        }
        else {
            /* parse for block size */
            benchmark_configure((word32)XATOI(argv[1]));
        }
        argc--;
        argv++;
    }
#endif /* MAIN_NO_ARGS */

#if defined(WOLFSSL_BENCHMARK_FIXED_CSV)
    /* when defined, we'll always output CSV regardless of params.
    ** this is typically convenient in embedded environments.
    */
    csv_format = 1;
#endif

#if defined(WC_ENABLE_BENCH_THREADING) && !defined(WOLFSSL_ASYNC_CRYPT)
    if (g_threadCount > 1) {
        ret = benchmark_test_threaded(NULL);
    }
    else
#endif
    {
    #if defined(CONFIG_IDF_TARGET_ESP32C2) || \
        defined(CONFIG_IDF_TARGET_ESP32C3) || \
        defined(CONFIG_IDF_TARGET_ESP32C6)
        {
        #ifdef WOLFSSL_BENCHMARK_TIMER_DEBUG
            if (esp_gptimer == NULL) {
                ESP_ERROR_CHECK(gptimer_new_timer(&esp_timer_config,
                                                  &esp_gptimer)     );
            }
            ESP_ERROR_CHECK(gptimer_enable(esp_gptimer));
            ESP_ERROR_CHECK(gptimer_start(esp_gptimer));
            ESP_LOGI(TAG, "Enable %s timer", CONFIG_IDF_TARGET);
        #endif /* WOLFSSL_BENCHMARK_TIMER_DEBUG */
        }
    #endif

    #ifdef HAVE_STACK_SIZE
        ret = StackSizeCheck(NULL, benchmark_test);
    #else
        ret = benchmark_test(NULL);
    #endif
    }

    #if defined(CONFIG_IDF_TARGET_ESP32C2) || \
        defined(CONFIG_IDF_TARGET_ESP32C3) || \
        defined(CONFIG_IDF_TARGET_ESP32C6)
        {
            #ifdef WOLFSSL_BENCHMARK_TIMER_DEBUG
                ESP_ERROR_CHECK(gptimer_stop(esp_gptimer));
                ESP_ERROR_CHECK(gptimer_disable(esp_gptimer));
            #endif /* WOLFSSL_BENCHMARK_TIMER_DEBUG */
        }
    #endif

    return ret;
}
#endif /* !NO_MAIN_DRIVER */

#else
    #if !defined(NO_MAIN_DRIVER) && !defined(NO_MAIN_FUNCTION)
        int main(void) { return 0; }
    #endif
#endif /* !NO_CRYPT_BENCHMARK */
