/* benchmark.c
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
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


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

/* Macro to disable benchmark */
#ifndef NO_CRYPT_BENCHMARK

#ifdef XMALLOC_USER
    #include <stdlib.h>  /* we're using malloc / free direct here */
#endif

#ifdef WOLFSSL_STATIC_MEMORY
    #include <wolfssl/wolfcrypt/memory.h>
    static WOLFSSL_HEAP_HINT* HEAP_HINT;
#else
    #define HEAP_HINT NULL
#endif /* WOLFSSL_STATIC_MEMORY */

#include <string.h>

#ifdef FREESCALE_MQX
    #include <mqx.h>
    #if MQX_USE_IO_OLD
        #include <fio.h>
    #else
        #include <nio.h>
    #endif
#elif defined(FREESCALE_KSDK_BM)
    #include "fsl_debug_console.h"
    #include "fsl_os_abstraction.h"
    #undef printf
    #define printf PRINTF
#else
    #include <stdio.h>
#endif

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/des3.h>
#include <wolfssl/wolfcrypt/arc4.h>
#include <wolfssl/wolfcrypt/hc128.h>
#include <wolfssl/wolfcrypt/rabbit.h>
#include <wolfssl/wolfcrypt/chacha.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/poly1305.h>
#include <wolfssl/wolfcrypt/camellia.h>
#include <wolfssl/wolfcrypt/md5.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/ripemd.h>
#include <wolfssl/wolfcrypt/cmac.h>
#ifndef NO_PWDBASED
    #include <wolfssl/wolfcrypt/pwdbased.h>
#endif
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifdef HAVE_IDEA
    #include <wolfssl/wolfcrypt/idea.h>
#endif
#ifdef HAVE_CURVE25519
    #include <wolfssl/wolfcrypt/curve25519.h>
#endif
#ifdef HAVE_ED25519
    #include <wolfssl/wolfcrypt/ed25519.h>
#endif

#include <wolfssl/wolfcrypt/dh.h>
#ifdef HAVE_NTRU
    #include "libntruencrypt/ntru_crypto.h"
#endif
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* only for stack size check */
#ifdef HAVE_STACK_SIZE
    #include <wolfssl/ssl.h>
    #include <wolfssl/test.h>
#endif

#ifdef WOLFSSL_ASYNC_CRYPT
    #include <wolfssl/wolfcrypt/async.h>
#endif

#ifdef HAVE_WNR
    const char* wnrConfigFile = "wnr-example.conf";
#endif

#if defined(WOLFSSL_MDK_ARM)
    extern FILE * wolfSSL_fopen(const char *fname, const char *mode);
    #define fopen wolfSSL_fopen
#endif

#if defined(__GNUC__) && defined(__x86_64__) && !defined(NO_ASM)
    #define HAVE_GET_CYCLES
    static INLINE word64 get_intel_cycles(void);
    static THREAD_LS_T word64 total_cycles;
    #define INIT_CYCLE_COUNTER
    #define BEGIN_INTEL_CYCLES total_cycles = get_intel_cycles();
    #define END_INTEL_CYCLES   total_cycles = get_intel_cycles() - total_cycles;
    #define SHOW_INTEL_CYCLES  printf(" Cycles per byte = %6.2f", \
                               (float)total_cycles / (count*BENCH_SIZE));
#elif defined(LINUX_CYCLE_COUNT)
    #include <linux/perf_event.h>
    #include <sys/syscall.h>
    #include <unistd.h>

    static THREAD_LS_T word64 begin_cycles;
    static THREAD_LS_T word64 total_cycles;
    static THREAD_LS_T int cycles = -1;
    static THREAD_LS_T struct perf_event_attr atr;

    #define INIT_CYCLE_COUNTER do { \
        atr.type   = PERF_TYPE_HARDWARE; \
        atr.config = PERF_COUNT_HW_CPU_CYCLES; \
        cycles = (int)syscall(__NR_perf_event_open, &atr, 0, -1, -1, 0); \
    } while (0);

    #define BEGIN_INTEL_CYCLES read(cycles, &begin_cycles, sizeof(begin_cycles));
    #define END_INTEL_CYCLES   do { \
        read(cycles, &total_cycles, sizeof(total_cycles)); \
        total_cycles = total_cycles - begin_cycles; \
    } while (0);

    #define SHOW_INTEL_CYCLES  printf(" Cycles per byte = %6.2f", \
                               (float)total_cycles / (count*BENCH_SIZE));

#else
    #define INIT_CYCLE_COUNTER
    #define BEGIN_INTEL_CYCLES
    #define END_INTEL_CYCLES
    #define SHOW_INTEL_CYCLES
#endif

/* let's use buffers, we have them */
#if !defined(USE_CERT_BUFFERS_1024) && !defined(USE_CERT_BUFFERS_2048)
    #define USE_CERT_BUFFERS_2048
#endif

#if defined(USE_CERT_BUFFERS_1024) || defined(USE_CERT_BUFFERS_2048) \
                                   || !defined(NO_DH)
    /* include test cert and key buffers for use with NO_FILESYSTEM */
    #include <wolfssl/certs_test.h>
#endif


#ifdef HAVE_BLAKE2
    #include <wolfssl/wolfcrypt/blake2.h>
    void bench_blake2(void);
#endif

#ifdef _MSC_VER
    /* 4996 warning to use MS extensions e.g., strcpy_s instead of strncpy */
    #pragma warning(disable: 4996)
#endif

#include "wolfcrypt/benchmark/benchmark.h"

void bench_des(int);
void bench_idea(void);
void bench_arc4(int);
void bench_hc128(void);
void bench_rabbit(void);
void bench_chacha(void);
void bench_chacha20_poly1305_aead(void);
void bench_aescbc(int);
void bench_aesgcm(int);
void bench_aesccm(void);
void bench_aesctr(void);
void bench_poly1305(void);
void bench_camellia(void);

void bench_md5(int);
void bench_sha(int);
void bench_sha224(int);
void bench_sha256(int);
void bench_sha384(int);
void bench_sha512(int);
void bench_ripemd(void);
void bench_cmac(void);
void bench_scrypt(void);

void bench_rsaKeyGen(int);
void bench_rsa(int);
void bench_dh(int);
#ifdef HAVE_ECC
void bench_eccMakeKey(int);
void bench_ecc(int);
    #ifdef HAVE_ECC_ENCRYPT
    void bench_eccEncrypt(void);
    #endif
#endif
#ifdef HAVE_CURVE25519
    void bench_curve25519KeyGen(void);
    #ifdef HAVE_CURVE25519_SHARED_SECRET
        void bench_curve25519KeyAgree(void);
    #endif /* HAVE_CURVE25519_SHARED_SECRET */
#endif /* HAVE_CURVE25519 */
#ifdef HAVE_ED25519
void bench_ed25519KeyGen(void);
void bench_ed25519KeySign(void);
#endif
#ifdef HAVE_NTRU
void bench_ntru(void);
void bench_ntruKeyGen(void);
#endif
#ifndef WC_NO_RNG
void bench_rng(void);
#endif /* WC_NO_RNG */

#ifdef WOLFSSL_CURRTIME_REMAP
    #define current_time WOLFSSL_CURRTIME_REMAP
#elif !defined(HAVE_STACK_SIZE)
    double current_time(int);
#endif

#if defined(DEBUG_WOLFSSL) && !defined(HAVE_VALGRIND) && \
        !defined(HAVE_STACK_SIZE)
    WOLFSSL_API int wolfSSL_Debugging_ON();
    WOLFSSL_API void wolfSSL_Debugging_OFF(void);
#endif

#if !defined(NO_RSA) || !defined(NO_DH) \
                        || defined(WOLFSSL_KEYGEN) || defined(HAVE_ECC) \
                        || defined(HAVE_CURVE25519) || defined(HAVE_ED25519)
    #define HAVE_LOCAL_RNG
    static THREAD_LS_T WC_RNG rng;
#endif



/* Asynchronous helper macros */
static THREAD_LS_T int devId = INVALID_DEVID;

#ifdef WOLFSSL_ASYNC_CRYPT
    static THREAD_LS_T WOLF_EVENT_QUEUE eventQueue;
    static THREAD_LS_T int asyncPending;

    #define BENCH_ASYNC_GET_DEV(obj)      (&(obj)->asyncDev)
    #define BENCH_ASYNC_GET_NAME(doAsync) (doAsync) ? "HW" : "SW"
    #define BENCH_ASYNC_IS_PEND()         (asyncPending > 0)
    #define BENCH_MAX_PENDING             (WOLF_ASYNC_MAX_PENDING)

#ifndef WC_NO_ASYNC_THREADING
    typedef struct ThreadData {
        pthread_t thread_id;
    } ThreadData;
    static ThreadData* g_threadData;
    static int g_threadCount;
#endif

    static INLINE int bench_async_begin(void) {
        /* init event queue */
        asyncPending = 0;
        return wolfEventQueue_Init(&eventQueue);
    }

    static INLINE void bench_async_end(void) {
        /* free event queue */
        wolfEventQueue_Free(&eventQueue);
    }

    static INLINE void bench_async_complete(int* ret, WC_ASYNC_DEV* asyncDev,
        int* times)
    {
        *ret = asyncDev->event.ret;
        if (*ret >= 0) {
            (*times)++;
            asyncDev->event.done = 0; /* reset done flag */
        }
    }

    static INLINE int bench_async_check(int* ret, WC_ASYNC_DEV* asyncDev,
        int callAgain, int* times, int limit)
    {
        int allowNext = 0;

        /* if algo doesn't require calling again then use this flow */
        if (!callAgain) {
            if (asyncDev->event.done) {
                /* operation completed */
                bench_async_complete(ret, asyncDev, times);
            }
        }
        /* if algo does require calling again then use this flow */
        else {
            if (asyncDev->event.done) {
                allowNext = 1;
            }
        }

        if (asyncDev->event.pending == 0 &&
                (*times + asyncPending) < limit) {
            allowNext = 1;
        }

        return allowNext;
    }

    static INLINE int bench_async_handle(int* ret, WC_ASYNC_DEV* asyncDev,
        int callAgain, int* times)
    {
        if (*ret == WC_PENDING_E) {
            *ret = wc_AsyncHandle(asyncDev, &eventQueue,
                callAgain ? WC_ASYNC_FLAG_CALL_AGAIN : WC_ASYNC_FLAG_NONE);
            if (*ret == 0)
                asyncPending++;
        }
        else if (*ret >= 0) {
            /* operation completed */
            bench_async_complete(ret, asyncDev, times);
        }

        return (*ret >= 0) ? 1 : 0;
    }

    static INLINE void bench_async_poll(void)
    {
        /* poll until there are events done */
        if (asyncPending > 0) {
            int ret, asyncDone = 0;
            do {
                ret = wolfAsync_EventQueuePoll(&eventQueue, NULL, NULL, 0,
                                       WOLF_POLL_FLAG_CHECK_HW, &asyncDone);
                if (ret != 0) {
                    printf("Async poll failed %d\n", ret);
                    return;
                }
            } while (asyncDone == 0);
            asyncPending -= asyncDone;
        }
    }

#else
    #define BENCH_MAX_PENDING             (1)
    #define BENCH_ASYNC_GET_NAME(doAsync) ""
    #define BENCH_ASYNC_GET_DEV(obj)      NULL
    #define BENCH_ASYNC_IS_PEND()         (0)

    #define bench_async_begin()
    #define bench_async_end()             (void)doAsync;

    static INLINE int bench_async_check(int* ret, void* asyncDev,
        int callAgain, int* times, int limit)
    {
        (void)ret;
        (void)asyncDev;
        (void)callAgain;
        (void)times;
        (void)limit;

        return 1;
    }

    static INLINE int bench_async_handle(int* ret, void* asyncDev,
        int callAgain, int* times)
    {
        (void)asyncDev;
        (void)callAgain;

        if (*ret >= 0) {
            /* operation completed */
            (*times)++;
            return 1;
        }
        return 0;
    }
    #define bench_async_poll()
#endif /* WOLFSSL_ASYNC_CRYPT */



/* maximum runtime for each benchmark */
#define BENCH_MIN_RUNTIME_SEC   1.0f


#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
    #define AES_AUTH_ADD_SZ 13
    #define AES_AUTH_TAG_SZ 16
    #define BENCH_CIPHER_ADD AES_AUTH_TAG_SZ
#endif
#ifndef BENCH_CIPHER_ADD
    #define BENCH_CIPHER_ADD 0
#endif


/* use kB instead of mB for embedded benchmarking */
#ifdef BENCH_EMBEDDED
    enum BenchmarkBounds {
        numBlocks  = 25, /* how many kB to test (en/de)cryption */
        scryptCnt  = 1,
        ntimes     = 2,
        genTimes   = BENCH_MAX_PENDING,
        agreeTimes = 2
    };
    static const char blockType[] = "kB";   /* used in printf output */
    #define BENCH_SIZE (1024ul)
#else
    enum BenchmarkBounds {
        numBlocks  = 5, /* how many megs to test (en/de)cryption */
        scryptCnt  = 10,
        ntimes     = 100,
        genTimes   = BENCH_MAX_PENDING, /* must be at least BENCH_MAX_PENDING */
        agreeTimes = 100
    };
    static const char blockType[] = "megs"; /* used in printf output */
    #define BENCH_SIZE (1024*1024ul)
#endif


/* globals for cipher tests */
#ifdef WOLFSSL_ASYNC_CRYPT
    static byte* bench_plain = NULL;
    static byte* bench_cipher = NULL;
#else
    static byte bench_plain[BENCH_SIZE];
    static byte bench_cipher[BENCH_SIZE];
#endif
static const XGEN_ALIGN byte bench_key_buf[] =
{
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    0xfe,0xde,0xba,0x98,0x76,0x54,0x32,0x10,
    0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67,
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
};

static const XGEN_ALIGN byte bench_iv_buf[] =
{
    0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef,
    0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
    0x11,0x21,0x31,0x41,0x51,0x61,0x71,0x81
};
static byte* bench_key = (byte*)bench_key_buf;
static byte* bench_iv = (byte*)bench_iv_buf;

#ifdef WOLFSSL_STATIC_MEMORY
    #ifdef BENCH_EMBEDDED
        static byte gBenchMemory[50000];
    #else
        static byte gBenchMemory[400000];
    #endif
#endif


/******************************************************************************/
/* Begin Stats Functions */
/******************************************************************************/
#if defined(WOLFSSL_ASYNC_CRYPT) && !defined(WC_NO_ASYNC_THREADING)
    typedef enum bench_stat_type {
        BENCH_STAT_ASYM,
        BENCH_STAT_SYM,
    } bench_stat_type_t;
    typedef struct bench_stats {
        struct bench_stats* next;
        struct bench_stats* prev;
        const char* algo;
        const char* desc;
        double perfsec;
        int strength;
        int doAsync;
        int finishCount;
        bench_stat_type_t type;
    } bench_stats_t;
    static bench_stats_t* bench_stats_head;
    static bench_stats_t* bench_stats_tail;
    static pthread_mutex_t bench_lock = PTHREAD_MUTEX_INITIALIZER;

    static bench_stats_t* bench_stats_add(bench_stat_type_t type,
        const char* algo, int strength, const char* desc, int doAsync,
        double perfsec)
    {
        bench_stats_t* stat;

        pthread_mutex_lock(&bench_lock);

        /* locate existing in list */
        for (stat = bench_stats_head; stat != NULL; stat = stat->next) {
            /* match based on algo, strength and desc */
            if (stat->algo == algo && stat->strength == strength && stat->desc == desc && stat->doAsync == doAsync) {
                break;
            }
        }

        if (stat == NULL) {
            /* allocate new and put on list */
            stat = (bench_stats_t*)XMALLOC(sizeof(bench_stats_t), NULL, DYNAMIC_TYPE_INFO);
            if (stat) {
                XMEMSET(stat, 0, sizeof(bench_stats_t));

                /* add to list */
                stat->next = NULL;
                if (bench_stats_tail == NULL)  {
                    bench_stats_head = stat;
                }
                else {
                    bench_stats_tail->next = stat;
                    stat->prev = bench_stats_tail;
                }
                bench_stats_tail = stat; /* add to the end either way */
            }
        }

        if (stat) {
            int isLast = 0;
            stat->type = type;
            stat->algo = algo;
            stat->strength = strength;
            stat->desc = desc;
            stat->doAsync = doAsync;
            stat->perfsec += perfsec;
            stat->finishCount++;

            if (stat->finishCount == g_threadCount) {
                isLast = 1;
            }

            pthread_mutex_unlock(&bench_lock);

            /* wait until remaining are complete */
            while (stat->finishCount < g_threadCount) {
                wc_AsyncThreadYield();
            }

            /* print final stat */
            if (isLast) {
                if (stat->type == BENCH_STAT_SYM) {
                    printf("%-8s%s %8.3f MB/s\n", stat->desc,
                        BENCH_ASYNC_GET_NAME(stat->doAsync), stat->perfsec);
                }
                else {
                    printf("%-5s %4d %-9s %s %.3f ops/sec\n",
                        stat->algo, stat->strength, stat->desc,
                        BENCH_ASYNC_GET_NAME(stat->doAsync), stat->perfsec);
                }
            }

            (void)blockType;
        }
        else {
            pthread_mutex_unlock(&bench_lock);
        }

        return stat;
    }
#endif /* WOLFSSL_ASYNC_CRYPT && !WC_NO_ASYNC_THREADING */

static INLINE void bench_stats_init(void)
{
#if defined(WOLFSSL_ASYNC_CRYPT) && !defined(WC_NO_ASYNC_THREADING)
    bench_stats_head = NULL;
    bench_stats_tail = NULL;
#endif
    INIT_CYCLE_COUNTER
}

static INLINE void bench_stats_start(int* count, double* start)
{
    *count = 0;
    *start = current_time(1);
    BEGIN_INTEL_CYCLES
}

static INLINE int bench_stats_sym_check(double start)
{
    return ((current_time(0) - start) < BENCH_MIN_RUNTIME_SEC);
}

static void bench_stats_sym_finish(const char* desc, int doAsync, int count, double start)
{
    double total, persec = 0;

    END_INTEL_CYCLES
    total = current_time(0) - start;

    if (count > 0)
        persec = 1 / total * count;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    printf("%-8s%s %5d %s took %5.3f seconds, %8.3f MB/s",
        desc, BENCH_ASYNC_GET_NAME(doAsync), count, blockType, total, persec);
    SHOW_INTEL_CYCLES
    printf("\n");
    (void)doAsync;

#if defined(WOLFSSL_ASYNC_CRYPT) && !defined(WC_NO_ASYNC_THREADING)
    /* Add to thread stats */
    bench_stats_add(BENCH_STAT_SYM, NULL, 0, desc, doAsync, persec);
#endif
}

/* declare here rather than creating a static function to avoid warning of not
 * used in the case of something like a leanpsk only build */
void bench_stats_asym_finish(const char* algo, int strength,
    const char* desc, int doAsync, int count, double start);

void bench_stats_asym_finish(const char* algo, int strength,
    const char* desc, int doAsync, int count, double start)
{
    double total, each = 0, opsSec, milliEach;

    total = current_time(0) - start;
    if (count > 0)
        each  = total / count; /* per second  */
    opsSec = count / total;    /* ops/per second */
    milliEach = each * 1000;   /* milliseconds */

    printf("%-5s %4d %-9s %s %6d ops took %5.3f sec, avg %5.3f ms,"
        " %.3f ops/sec\n", algo, strength, desc, BENCH_ASYNC_GET_NAME(doAsync),
        count, total, milliEach, opsSec);
    (void)doAsync;

#if defined(WOLFSSL_ASYNC_CRYPT) && !defined(WC_NO_ASYNC_THREADING)
    /* Add to thread stats */
    bench_stats_add(BENCH_STAT_ASYM, algo, strength, desc, doAsync, opsSec);
#endif
}

static INLINE void bench_stats_free(void)
{
#if defined(WOLFSSL_ASYNC_CRYPT) && !defined(WC_NO_ASYNC_THREADING)
    bench_stats_t* stat;
    for (stat = bench_stats_head; stat != NULL; ) {
        bench_stats_t* next = stat->next;
        XFREE(stat, NULL, DYNAMIC_TYPE_INFO);
        stat = next;
    }
    bench_stats_head = NULL;
    bench_stats_tail = NULL;
#endif
}
/******************************************************************************/
/* End Stats Functions */
/******************************************************************************/


static void* benchmarks_do(void* args)
{
#ifdef WOLFSSL_ASYNC_CRYPT
#ifndef WC_NO_ASYNC_THREADING
    ThreadData* threadData = (ThreadData*)args;

    if (wolfAsync_DevOpenThread(&devId, &threadData->thread_id) < 0)
#else
    if (wolfAsync_DevOpen(&devId) < 0)
#endif
    {
        printf("Async device open failed\nRunning without async\n");
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    (void)args;

#if defined(HAVE_LOCAL_RNG)
    {
        int rngRet;

#ifndef HAVE_FIPS
        rngRet = wc_InitRng_ex(&rng, HEAP_HINT, INVALID_DEVID);
#else
        rngRet = wc_InitRng(&rng);
#endif
        if (rngRet < 0) {
            printf("InitRNG failed\n");
        }
    }
#endif

#ifndef WC_NO_RNG
    bench_rng();
#endif /* WC_NO_RNG */
#ifndef NO_AES
#ifdef HAVE_AES_CBC
    #ifndef NO_SW_BENCH
        bench_aescbc(0);
    #endif
    #if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_AES)
        bench_aescbc(1);
    #endif
#endif
#ifdef HAVE_AESGCM
    #ifndef NO_SW_BENCH
        bench_aesgcm(0);
    #endif
    #if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_AES)
        bench_aesgcm(1);
    #endif
#endif
#ifdef WOLFSSL_AES_COUNTER
    bench_aesctr();
#endif
#ifdef HAVE_AESCCM
    bench_aesccm();
#endif
#endif /* !NO_AES */

#ifdef HAVE_CAMELLIA
    bench_camellia();
#endif
#ifndef NO_RC4
    #ifndef NO_SW_BENCH
        bench_arc4(0);
    #endif
    #if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_ARC4)
        bench_arc4(1);
    #endif
#endif
#ifdef HAVE_HC128
    bench_hc128();
#endif
#ifndef NO_RABBIT
    bench_rabbit();
#endif
#ifdef HAVE_CHACHA
    bench_chacha();
#endif
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    bench_chacha20_poly1305_aead();
#endif
#ifndef NO_DES3
    #ifndef NO_SW_BENCH
        bench_des(0);
    #endif
    #if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_3DES)
        bench_des(1);
    #endif
#endif
#ifdef HAVE_IDEA
    bench_idea();
#endif

#ifndef NO_MD5
    #ifndef NO_SW_BENCH
        bench_md5(0);
    #endif
    #if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_MD5)
        bench_md5(1);
    #endif
#endif
#ifdef HAVE_POLY1305
    bench_poly1305();
#endif
#ifndef NO_SHA
    #ifndef NO_SW_BENCH
        bench_sha(0);
    #endif
    #if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_SHA)
        bench_sha(1);
    #endif
#endif
#ifdef WOLFSSL_SHA224
    #ifndef NO_SW_BENCH
        bench_sha224(0);
    #endif
    #if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_SHA224)
        bench_sha224(1);
    #endif
#endif
#ifndef NO_SHA256
    #ifndef NO_SW_BENCH
        bench_sha256(0);
    #endif
    #if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_SHA256)
        bench_sha256(1);
    #endif
#endif
#ifdef WOLFSSL_SHA384
    #ifndef NO_SW_BENCH
        bench_sha384(0);
    #endif
    #if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_SHA384)
        bench_sha384(1);
    #endif
#endif
#ifdef WOLFSSL_SHA512
    #ifndef NO_SW_BENCH
        bench_sha512(0);
    #endif
    #if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_SHA512)
        bench_sha512(1);
    #endif
#endif
#ifdef WOLFSSL_RIPEMD
    bench_ripemd();
#endif
#ifdef HAVE_BLAKE2
    bench_blake2();
#endif
#ifdef WOLFSSL_CMAC
    bench_cmac();
#endif

#ifdef HAVE_SCRYPT
    bench_scrypt();
#endif

#ifndef NO_RSA
    #ifdef WOLFSSL_KEY_GEN
        #ifndef NO_SW_BENCH
            bench_rsaKeyGen(0);
        #endif
        #if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_RSA)
            /* async supported in simulator only */
            #ifdef WOLFSSL_ASYNC_CRYPT_TEST
                bench_rsaKeyGen(1);
            #endif
        #endif
    #endif
    #ifndef NO_SW_BENCH
        bench_rsa(0);
    #endif
    #if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_RSA)
        bench_rsa(1);
    #endif
#endif

#ifndef NO_DH
    #ifndef NO_SW_BENCH
        bench_dh(0);
    #endif
    #if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_DH)
        bench_dh(1);
    #endif
#endif

#ifdef HAVE_NTRU
    bench_ntru();
    bench_ntruKeyGen();
#endif

#ifdef HAVE_ECC
    #ifndef NO_SW_BENCH
        bench_eccMakeKey(0);
    #endif
    #if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_ECC)
        /* async supported in simulator only */
        #ifdef WOLFSSL_ASYNC_CRYPT_TEST
            bench_eccMakeKey(1);
        #endif
    #endif
    #ifndef NO_SW_BENCH
        bench_ecc(0);
    #endif
    #if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_ECC)
        bench_ecc(1);
    #endif
    #ifdef HAVE_ECC_ENCRYPT
        bench_eccEncrypt();
    #endif
#endif

#ifdef HAVE_CURVE25519
    bench_curve25519KeyGen();
    #ifdef HAVE_CURVE25519_SHARED_SECRET
        bench_curve25519KeyAgree();
    #endif
#endif

#ifdef HAVE_ED25519
    bench_ed25519KeyGen();
    bench_ed25519KeySign();
#endif

#if defined(HAVE_LOCAL_RNG)
    wc_FreeRng(&rng);
#endif

#ifdef WOLFSSL_ASYNC_CRYPT
    wolfAsync_DevClose(&devId);
#endif

    return NULL;
}


/* so embedded projects can pull in tests on their own */
#ifdef HAVE_STACK_SIZE
THREAD_RETURN WOLFSSL_THREAD benchmark_test(void* args)
#else
int benchmark_test(void *args)
#endif
{
    int ret = 0;

#ifdef WOLFSSL_STATIC_MEMORY
    ret = wc_LoadStaticMemory(&HEAP_HINT, gBenchMemory, sizeof(gBenchMemory),
                                                            WOLFMEM_GENERAL, 1);
    if (ret != 0) {
        printf("unable to load static memory %d\n", ret);
        EXIT_TEST(EXIT_FAILURE);
    }
#endif /* WOLFSSL_STATIC_MEMORY */

    (void)args;

    wolfCrypt_Init();

    bench_stats_init();

#if defined(DEBUG_WOLFSSL) && !defined(HAVE_VALGRIND)
    wolfSSL_Debugging_ON();
#endif

    printf("wolfCrypt Benchmark (min %.1f sec each)\n", BENCH_MIN_RUNTIME_SEC);

#ifdef HAVE_WNR
    ret = wc_InitNetRandom(wnrConfigFile, NULL, 5000);
    if (ret != 0) {
        printf("Whitewood netRandom config init failed %d\n", ret);
        EXIT_TEST(EXIT_FAILURE);
    }
#endif /* HAVE_WNR */

    /* setup bench plain, cipher, key and iv globals */
#ifdef WOLFSSL_ASYNC_CRYPT
    bench_plain = (byte*)XMALLOC(BENCH_SIZE+BENCH_CIPHER_ADD, HEAP_HINT, DYNAMIC_TYPE_WOLF_BIGINT);
    bench_cipher = (byte*)XMALLOC(BENCH_SIZE+BENCH_CIPHER_ADD, HEAP_HINT, DYNAMIC_TYPE_WOLF_BIGINT);
    bench_key = (byte*)XMALLOC(sizeof(bench_key_buf), HEAP_HINT, DYNAMIC_TYPE_WOLF_BIGINT);
    bench_iv = (byte*)XMALLOC(sizeof(bench_iv_buf), HEAP_HINT, DYNAMIC_TYPE_WOLF_BIGINT);
    if (bench_plain == NULL || bench_cipher == NULL || bench_key == NULL || bench_iv == NULL) {
        printf("Benchmark cipher buffer alloc failed!\n");
        EXIT_TEST(EXIT_FAILURE);
    }
    XMEMCPY(bench_key, bench_key_buf, sizeof(bench_key_buf));
    XMEMCPY(bench_iv, bench_iv_buf, sizeof(bench_iv_buf));
    XMEMSET(bench_plain, 0, BENCH_SIZE+BENCH_CIPHER_ADD);
    XMEMSET(bench_cipher, 0, BENCH_SIZE+BENCH_CIPHER_ADD);
#endif
    (void)bench_plain;
    (void)bench_cipher;
    (void)bench_key;
    (void)bench_iv;


#if defined(WOLFSSL_ASYNC_CRYPT) && !defined(WC_NO_ASYNC_THREADING)
{
    int i;
    int numCpus = wc_AsyncGetNumberOfCpus();

    printf("CPUs: %d\n", numCpus);

    g_threadData = (ThreadData*)XMALLOC(sizeof(ThreadData) * numCpus,
        HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (g_threadData == NULL) {
        printf("Thread data alloc failed!\n");
        EXIT_TEST(EXIT_FAILURE);
    }
    g_threadCount = numCpus;

    /* Create threads */
    for (i = 0; i < numCpus; i++) {
        ret = wc_AsyncThreadCreate(&g_threadData[i].thread_id,
            benchmarks_do, &g_threadData[i]);
        if (ret != 0) {
            printf("Error creating benchmark thread %d\n", ret);
            EXIT_TEST(EXIT_FAILURE);
        }
    }

    /* Start threads */
    for (i = 0; i < numCpus; i++) {
        wc_AsyncThreadJoin(&g_threadData[i].thread_id);
    }

    XFREE(g_threadData, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
}
#else
    benchmarks_do(NULL);
#endif

#ifdef WOLFSSL_ASYNC_CRYPT
    XFREE(bench_plain, HEAP_HINT, DYNAMIC_TYPE_WOLF_BIGINT);
    XFREE(bench_cipher, HEAP_HINT, DYNAMIC_TYPE_WOLF_BIGINT);
    XFREE(bench_key, HEAP_HINT, DYNAMIC_TYPE_WOLF_BIGINT);
    XFREE(bench_iv, HEAP_HINT, DYNAMIC_TYPE_WOLF_BIGINT);
#endif

#ifdef HAVE_WNR
    ret = wc_FreeNetRandom();
    if (ret < 0) {
        printf("Failed to free netRandom context %d\n", ret);
        EXIT_TEST(EXIT_FAILURE);
    }
#endif

    bench_stats_free();

	if (wolfCrypt_Cleanup() != 0) {
        printf("error with wolfCrypt_Cleanup\n");
    }

    EXIT_TEST(ret);
}


#ifndef WC_NO_RNG
void bench_rng(void)
{
    int    ret, i, count;
    double start;
    int    pos, len, remain;
    WC_RNG myrng;

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
            remain = (int)BENCH_SIZE;
            while (remain > 0) {
                len = remain;
                if (len > RNG_MAX_BLOCK_LEN)
                    len = RNG_MAX_BLOCK_LEN;
                ret = wc_RNG_GenerateBlock(&myrng, &bench_plain[pos], len);
                if (ret < 0)
                    goto exit_rng;

                remain -= len;
                pos += len;
            }
        }
        count += i;
    } while (bench_stats_sym_check(start));
exit_rng:
    bench_stats_sym_finish("RNG", 0, count, start);

    if (ret < 0) {
        printf("wc_RNG_GenerateBlock failed %d\n", ret);
    }

    wc_FreeRng(&myrng);
}
#endif /* WC_NO_RNG */


#ifndef NO_AES

#ifdef HAVE_AES_CBC
void bench_aescbc(int doAsync)
{
    int    ret, i, count = 0, times;
    Aes    enc[BENCH_MAX_PENDING];
    double start;

    bench_async_begin();

    /* clear for done cleanup */
    XMEMSET(enc, 0, sizeof(enc));

    /* init keys */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        if ((ret = wc_AesInit(&enc[i], HEAP_HINT,
                                doAsync ? devId : INVALID_DEVID)) != 0) {
            printf("AesInit failed, ret = %d\n", ret);
            goto exit;
        }

        ret = wc_AesSetKey(&enc[i], bench_key, 16, bench_iv, AES_ENCRYPTION);
        if (ret != 0) {
            printf("AesSetKey failed, ret = %d\n", ret);
            goto exit;
        }
    }

    bench_stats_start(&count, &start);
    do {
        for (times = 0; times < numBlocks || BENCH_ASYNC_IS_PEND(); ) {
            bench_async_poll();

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(&enc[i]), 0, &times, numBlocks)) {
                    ret = wc_AesCbcEncrypt(&enc[i], bench_plain, bench_cipher,
                        BENCH_SIZE);
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(&enc[i]), 0, &times)) {
                        goto exit_aes_enc;
                    }
                }
            } /* for i */
        } /* for times */
        count += times;
    } while (bench_stats_sym_check(start));
exit_aes_enc:
    bench_stats_sym_finish("AES-Enc", doAsync, count, start);

    if (ret < 0) {
        goto exit;
    }

#ifdef HAVE_AES_DECRYPT
    /* init keys */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        ret = wc_AesSetKey(&enc[i], bench_key, 16, bench_iv, AES_DECRYPTION);
        if (ret != 0) {
            printf("AesSetKey failed, ret = %d\n", ret);
            goto exit;
        }
    }

    bench_stats_start(&count, &start);
    do {
        for (times = 0; times < numBlocks || BENCH_ASYNC_IS_PEND(); ) {
            bench_async_poll();

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(&enc[i]), 0, &times, numBlocks)) {
                    ret = wc_AesCbcDecrypt(&enc[i], bench_plain, bench_cipher,
                        BENCH_SIZE);
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(&enc[i]), 0, &times)) {
                        goto exit_aes_dec;
                    }
                }
            } /* for i */
        } /* for times */
        count += times;
    } while (bench_stats_sym_check(start));
exit_aes_dec:
    bench_stats_sym_finish("AES-Dec", doAsync, count, start);

#endif /* HAVE_AES_DECRYPT */

exit:

    if (ret < 0) {
        printf("bench_aescbc failed: %d\n", ret);
    }

    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        wc_AesFree(&enc[i]);
    }

    bench_async_end();
}
#endif /* HAVE_AES_CBC */

#ifdef HAVE_AESGCM
void bench_aesgcm(int doAsync)
{
    int    ret, i, count = 0, times;
    Aes    enc[BENCH_MAX_PENDING];
    double start;

    DECLARE_VAR(bench_additional, byte, AES_AUTH_ADD_SZ, HEAP_HINT);
    DECLARE_VAR(bench_tag, byte, AES_AUTH_TAG_SZ, HEAP_HINT);

    bench_async_begin();

    /* clear for done cleanup */
    XMEMSET(enc, 0, sizeof(enc));
#ifdef WOLFSSL_ASYNC_CRYPT
    if (bench_additional)
#endif
    {   XMEMSET(bench_additional, 0, AES_AUTH_ADD_SZ); }
#ifdef WOLFSSL_ASYNC_CRYPT
    if (bench_tag)
#endif
    {   XMEMSET(bench_tag, 0, AES_AUTH_TAG_SZ); }

    /* init keys */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        if ((ret = wc_AesInit(&enc[i], HEAP_HINT,
                        doAsync ? devId : INVALID_DEVID)) != 0) {
            printf("AesInit failed, ret = %d\n", ret);
            goto exit;
        }

        ret = wc_AesGcmSetKey(&enc[i], bench_key, 16);
        if (ret != 0) {
            printf("AesGcmSetKey failed, ret = %d\n", ret);
            goto exit;
        }
    }

    /* GCM uses same routine in backend for both encrypt and decrypt */
    bench_stats_start(&count, &start);
    do {
        for (times = 0; times < numBlocks || BENCH_ASYNC_IS_PEND(); ) {
            bench_async_poll();

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(&enc[i]), 0, &times, numBlocks)) {
                    ret = wc_AesGcmEncrypt(&enc[i], bench_cipher,
                        bench_plain, BENCH_SIZE,
                        bench_iv, 12, bench_tag, AES_AUTH_TAG_SZ,
                        bench_additional, AES_AUTH_ADD_SZ);
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(&enc[i]), 0, &times)) {
                        goto exit_aes_gcm;
                    }
                }
            } /* for i */
        } /* for times */
        count += times;
    } while (bench_stats_sym_check(start));
exit_aes_gcm:
    bench_stats_sym_finish("AES-GCM", doAsync, count, start);

exit:

    if (ret < 0) {
        printf("bench_aesgcm failed: %d\n", ret);
    }

    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        wc_AesFree(&enc[i]);
    }

    FREE_VAR(bench_additional, HEAP_HINT);
    FREE_VAR(bench_tag, HEAP_HINT);

    bench_async_end();
}
#endif /* HAVE_AESGCM */


#ifdef WOLFSSL_AES_COUNTER
void bench_aesctr(void)
{
    Aes    enc;
    double start;
    int    i, count;

    wc_AesSetKeyDirect(&enc, bench_key, AES_BLOCK_SIZE, bench_iv, AES_ENCRYPTION);

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            wc_AesCtrEncrypt(&enc, bench_plain, bench_cipher, BENCH_SIZE);
        }
        count += i;
    } while (bench_stats_sym_check(start));
    bench_stats_sym_finish("AES-CTR", 0, count, start);
}
#endif /* WOLFSSL_AES_COUNTER */


#ifdef HAVE_AESCCM
void bench_aesccm(void)
{
    Aes    enc;
    double start;
    int    ret, i, count;

    DECLARE_VAR(bench_additional, byte, AES_AUTH_ADD_SZ, HEAP_HINT);
    DECLARE_VAR(bench_tag, byte, AES_AUTH_TAG_SZ, HEAP_HINT);

    if ((ret = wc_AesCcmSetKey(&enc, bench_key, 16)) != 0) {
        printf("wc_AesCcmSetKey failed, ret = %d\n", ret);
        return;
    }

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            wc_AesCcmEncrypt(&enc, bench_cipher, bench_plain, BENCH_SIZE,
                bench_iv, 12, bench_tag, AES_AUTH_TAG_SZ,
                bench_additional, AES_AUTH_ADD_SZ);
        }
        count += i;
    } while (bench_stats_sym_check(start));
    bench_stats_sym_finish("AES-CCM", 0, count, start);

    FREE_VAR(bench_additional, HEAP_HINT);
    FREE_VAR(bench_tag, HEAP_HINT);
}
#endif /* HAVE_AESCCM */
#endif /* !NO_AES */


#ifdef HAVE_POLY1305
void bench_poly1305()
{
    Poly1305 enc;
    byte     mac[16];
    double   start;
    int      ret, i, count;

    ret = wc_Poly1305SetKey(&enc, bench_key, 32);
    if (ret != 0) {
        printf("Poly1305SetKey failed, ret = %d\n", ret);
        return;
    }

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            ret = wc_Poly1305Update(&enc, bench_plain, BENCH_SIZE);
            if (ret != 0) {
                printf("Poly1305Update failed: %d\n", ret);
                break;
            }
        }
        wc_Poly1305Final(&enc, mac);
        count += i;
    } while (bench_stats_sym_check(start));
    bench_stats_sym_finish("POLY1305", 0, count, start);
}
#endif /* HAVE_POLY1305 */


#ifdef HAVE_CAMELLIA
void bench_camellia(void)
{
    Camellia cam;
    double   start;
    int      ret, i, count;

    ret = wc_CamelliaSetKey(&cam, bench_key, 16, bench_iv);
    if (ret != 0) {
        printf("CamelliaSetKey failed, ret = %d\n", ret);
        return;
    }

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            wc_CamelliaCbcEncrypt(&cam, bench_plain, bench_cipher,
                BENCH_SIZE);
        }
        count += i;
    } while (bench_stats_sym_check(start));
    bench_stats_sym_finish("Camellia", 0, count, start);
}
#endif


#ifndef NO_DES3
void bench_des(int doAsync)
{
    int    ret, i, count = 0, times;
    Des3   enc[BENCH_MAX_PENDING];
    double start;

    bench_async_begin();

    /* clear for done cleanup */
    XMEMSET(enc, 0, sizeof(enc));

    /* init keys */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        if ((ret = wc_Des3Init(&enc[i], HEAP_HINT,
                                doAsync ? devId : INVALID_DEVID)) != 0) {
            printf("Des3Init failed, ret = %d\n", ret);
            goto exit;
        }

        ret = wc_Des3_SetKey(&enc[i], bench_key, bench_iv, DES_ENCRYPTION);
        if (ret != 0) {
            printf("Des3_SetKey failed, ret = %d\n", ret);
            goto exit;
        }
    }

    bench_stats_start(&count, &start);
    do {
        for (times = 0; times < numBlocks || BENCH_ASYNC_IS_PEND(); ) {
            bench_async_poll();

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(&enc[i]), 0, &times, numBlocks)) {
                    ret = wc_Des3_CbcEncrypt(&enc[i], bench_plain, bench_cipher,
                        BENCH_SIZE);
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(&enc[i]), 0, &times)) {
                        goto exit_3des;
                    }
                }
            } /* for i */
        } /* for times */
        count += times;
    } while (bench_stats_sym_check(start));
exit_3des:
    bench_stats_sym_finish("3DES", doAsync, count, start);

exit:

    if (ret < 0) {
        printf("bench_des failed: %d\n", ret);
    }

    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        wc_Des3Free(&enc[i]);
    }

    bench_async_end();
}
#endif /* !NO_DES3 */


#ifdef HAVE_IDEA
void bench_idea(void)
{
    Idea   enc;
    double start;
    int    ret, i, count;

    ret = wc_IdeaSetKey(&enc, bench_key, IDEA_KEY_SIZE, bench_iv,
        IDEA_ENCRYPTION);
    if (ret != 0) {
        printf("Des3_SetKey failed, ret = %d\n", ret);
        return;
    }

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            wc_IdeaCbcEncrypt(&enc, bench_plain, bench_cipher, BENCH_SIZE);
        }
        count += i;
    } while (bench_stats_sym_check(start));
    bench_stats_sym_finish("IDEA", 0, count, start);
}
#endif /* HAVE_IDEA */


#ifndef NO_RC4
void bench_arc4(int doAsync)
{
    int    ret, i, count = 0, times;
    Arc4   enc[BENCH_MAX_PENDING];
    double start;

    bench_async_begin();

    /* clear for done cleanup */
    XMEMSET(enc, 0, sizeof(enc));

    /* init keys */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        if ((ret = wc_Arc4Init(&enc[i], HEAP_HINT,
                            doAsync ? devId : INVALID_DEVID)) != 0) {
            printf("Arc4Init failed, ret = %d\n", ret);
            goto exit;
        }

        ret = wc_Arc4SetKey(&enc[i], bench_key, 16);
        if (ret != 0) {
            printf("Arc4SetKey failed, ret = %d\n", ret);
            goto exit;
        }
    }

    bench_stats_start(&count, &start);
    do {
        for (times = 0; times < numBlocks || BENCH_ASYNC_IS_PEND(); ) {
            bench_async_poll();

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(&enc[i]), 0, &times, numBlocks)) {
                    ret = wc_Arc4Process(&enc[i], bench_cipher, bench_plain,
                        BENCH_SIZE);
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(&enc[i]), 0, &times)) {
                        goto exit_arc4;
                    }
                }
            } /* for i */
        } /* for times */
        count += times;
    } while (bench_stats_sym_check(start));
exit_arc4:
    bench_stats_sym_finish("ARC4", doAsync, count, start);

exit:

    if (ret < 0) {
        printf("bench_arc4 failed: %d\n", ret);
    }

    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        wc_Arc4Free(&enc[i]);
    }

    bench_async_end();
}
#endif /* !NO_RC4 */


#ifdef HAVE_HC128
void bench_hc128(void)
{
    HC128  enc;
    double start;
    int    i, count;

    wc_Hc128_SetKey(&enc, bench_key, bench_iv);

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            wc_Hc128_Process(&enc, bench_cipher, bench_plain, BENCH_SIZE);
        }
        count += i;
    } while (bench_stats_sym_check(start));
    bench_stats_sym_finish("HC128", 0, count, start);
}
#endif /* HAVE_HC128 */


#ifndef NO_RABBIT
void bench_rabbit(void)
{
    Rabbit enc;
    double start;
    int    i, count;

    wc_RabbitSetKey(&enc, bench_key, bench_iv);

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            wc_RabbitProcess(&enc, bench_cipher, bench_plain, BENCH_SIZE);
        }
        count += i;
    } while (bench_stats_sym_check(start));
    bench_stats_sym_finish("RABBIT", 0, count, start);
}
#endif /* NO_RABBIT */


#ifdef HAVE_CHACHA
void bench_chacha(void)
{
    ChaCha enc;
    double start;
    int    i, count;

    wc_Chacha_SetKey(&enc, bench_key, 16);

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            wc_Chacha_SetIV(&enc, bench_iv, 0);
            wc_Chacha_Process(&enc, bench_cipher, bench_plain, BENCH_SIZE);
        }
        count += i;
    } while (bench_stats_sym_check(start));
    bench_stats_sym_finish("CHACHA", 0, count, start);
}
#endif /* HAVE_CHACHA*/

#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
void bench_chacha20_poly1305_aead(void)
{
    double start;
    int    ret, i, count;

    byte authTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    XMEMSET(authTag, 0, sizeof(authTag));

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            ret = wc_ChaCha20Poly1305_Encrypt(bench_key, bench_iv, NULL, 0,
                bench_plain, BENCH_SIZE, bench_cipher, authTag);
            if (ret < 0) {
                printf("wc_ChaCha20Poly1305_Encrypt error: %d\n", ret);
                break;
            }
        }
        count += i;
    } while (bench_stats_sym_check(start));
    bench_stats_sym_finish("CHA-POLY", 0, count, start);
}
#endif /* HAVE_CHACHA && HAVE_POLY1305 */


#ifndef NO_MD5
void bench_md5(int doAsync)
{
    Md5    hash[BENCH_MAX_PENDING];
    double start;
    int    ret, i, count = 0, times;
    DECLARE_ARRAY(digest, byte, BENCH_MAX_PENDING, MD5_DIGEST_SIZE, HEAP_HINT);

    bench_async_begin();

    /* clear for done cleanup */
    XMEMSET(hash, 0, sizeof(hash));

    /* init keys */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        ret = wc_InitMd5_ex(&hash[i], HEAP_HINT,
                    doAsync ? devId : INVALID_DEVID);
        if (ret != 0) {
            printf("InitMd5_ex failed, ret = %d\n", ret);
            goto exit;
        }
    }

    bench_stats_start(&count, &start);
    do {
        for (times = 0; times < numBlocks || BENCH_ASYNC_IS_PEND(); ) {
            bench_async_poll();

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(&hash[i]), 0, &times, numBlocks)) {
                    ret = wc_Md5Update(&hash[i], bench_plain,
                        BENCH_SIZE);
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(&hash[i]), 0, &times)) {
                        goto exit_md5;
                    }
                }
            } /* for i */
        } /* for times */
        count += times;

        times = 0;
        do {
            bench_async_poll();

            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(&hash[i]), 0, &times, numBlocks)) {
                    ret = wc_Md5Final(&hash[i], digest[i]);
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(&hash[i]), 0, &times)) {
                        goto exit_md5;
                    }
                }
            } /* for i */
        } while (BENCH_ASYNC_IS_PEND());
    } while (bench_stats_sym_check(start));
exit_md5:
    bench_stats_sym_finish("MD5", doAsync, count, start);

exit:

    if (ret < 0) {
        printf("bench_md5 failed: %d\n", ret);
    }

#ifdef WOLFSSL_ASYNC_CRYPT
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        wc_Md5Free(&hash[i]);
    }
#endif

    FREE_ARRAY(digest, BENCH_MAX_PENDING, HEAP_HINT);

    bench_async_end();
}
#endif /* !NO_MD5 */


#ifndef NO_SHA
void bench_sha(int doAsync)
{
    Sha    hash[BENCH_MAX_PENDING];
    double start;
    int    ret, i, count = 0, times;
    DECLARE_ARRAY(digest, byte, BENCH_MAX_PENDING, SHA_DIGEST_SIZE, HEAP_HINT);

    bench_async_begin();

    /* clear for done cleanup */
    XMEMSET(hash, 0, sizeof(hash));

    /* init keys */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        ret = wc_InitSha_ex(&hash[i], HEAP_HINT,
            doAsync ? devId : INVALID_DEVID);
        if (ret != 0) {
            printf("InitSha failed, ret = %d\n", ret);
            goto exit;
        }
    }

    bench_stats_start(&count, &start);
    do {
        for (times = 0; times < numBlocks || BENCH_ASYNC_IS_PEND(); ) {
            bench_async_poll();

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(&hash[i]), 0, &times, numBlocks)) {
                    ret = wc_ShaUpdate(&hash[i], bench_plain,
                        BENCH_SIZE);
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(&hash[i]), 0, &times)) {
                        goto exit_sha;
                    }
                }
            } /* for i */
        } /* for times */
        count += times;

        times = 0;
        do {
            bench_async_poll();

            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(&hash[i]), 0, &times, numBlocks)) {
                    ret = wc_ShaFinal(&hash[i], digest[i]);
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(&hash[i]), 0, &times)) {
                        goto exit_sha;
                    }
                }
            } /* for i */
        } while (BENCH_ASYNC_IS_PEND());
    } while (bench_stats_sym_check(start));
exit_sha:
    bench_stats_sym_finish("SHA", doAsync, count, start);

exit:

    if (ret < 0) {
        printf("bench_sha failed: %d\n", ret);
    }

#ifdef WOLFSSL_ASYNC_CRYPT
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        wc_ShaFree(&hash[i]);
    }
#endif

    FREE_ARRAY(digest, BENCH_MAX_PENDING, HEAP_HINT);

    bench_async_end();
}
#endif /* NO_SHA */


#ifdef WOLFSSL_SHA224
void bench_sha224(int doAsync)
{
    Sha224 hash[BENCH_MAX_PENDING];
    double start;
    int    ret, i, count = 0, times;
    DECLARE_ARRAY(digest, byte, BENCH_MAX_PENDING, SHA224_DIGEST_SIZE, HEAP_HINT);

    bench_async_begin();

    /* clear for done cleanup */
    XMEMSET(hash, 0, sizeof(hash));

    /* init keys */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        ret = wc_InitSha224_ex(&hash[i], HEAP_HINT,
            doAsync ? devId : INVALID_DEVID);
        if (ret != 0) {
            printf("InitSha224_ex failed, ret = %d\n", ret);
            goto exit;
        }
    }

    bench_stats_start(&count, &start);
    do {
        for (times = 0; times < numBlocks || BENCH_ASYNC_IS_PEND(); ) {
            bench_async_poll();

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(&hash[i]), 0, &times, numBlocks)) {
                    ret = wc_Sha224Update(&hash[i], bench_plain,
                        BENCH_SIZE);
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(&hash[i]), 0, &times)) {
                        goto exit_sha224;
                    }
                }
            } /* for i */
        } /* for times */
        count += times;

        times = 0;
        do {
            bench_async_poll();
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(&hash[i]), 0, &times, numBlocks)) {
                    ret = wc_Sha224Final(&hash[i], digest[i]);
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(&hash[i]), 0, &times)) {
                        goto exit_sha224;
                    }
                }
            } /* for i */
        } while (BENCH_ASYNC_IS_PEND());
    } while (bench_stats_sym_check(start));
exit_sha224:
    bench_stats_sym_finish("SHA-224", doAsync, count, start);

exit:

    if (ret < 0) {
        printf("bench_sha224 failed: %d\n", ret);
    }

#ifdef WOLFSSL_ASYNC_CRYPT
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        wc_Sha224Free(&hash[i]);
    }
#endif

    FREE_ARRAY(digest, BENCH_MAX_PENDING, HEAP_HINT);

    bench_async_end();
}
#endif

#ifndef NO_SHA256
void bench_sha256(int doAsync)
{
    Sha256 hash[BENCH_MAX_PENDING];
    double start;
    int    ret, i, count = 0, times;
    DECLARE_ARRAY(digest, byte, BENCH_MAX_PENDING, SHA256_DIGEST_SIZE, HEAP_HINT);

    bench_async_begin();

    /* clear for done cleanup */
    XMEMSET(hash, 0, sizeof(hash));

    /* init keys */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        ret = wc_InitSha256_ex(&hash[i], HEAP_HINT,
            doAsync ? devId : INVALID_DEVID);
        if (ret != 0) {
            printf("InitSha256_ex failed, ret = %d\n", ret);
            goto exit;
        }
    }

    bench_stats_start(&count, &start);
    do {
        for (times = 0; times < numBlocks || BENCH_ASYNC_IS_PEND(); ) {
            bench_async_poll();

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(&hash[i]), 0, &times, numBlocks)) {
                    ret = wc_Sha256Update(&hash[i], bench_plain,
                        BENCH_SIZE);
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(&hash[i]), 0, &times)) {
                        goto exit_sha256;
                    }
                }
            } /* for i */
        } /* for times */
        count += times;

        times = 0;
        do {
            bench_async_poll();
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(&hash[i]), 0, &times, numBlocks)) {
                    ret = wc_Sha256Final(&hash[i], digest[i]);
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(&hash[i]), 0, &times)) {
                        goto exit_sha256;
                    }
                }
            } /* for i */
        } while (BENCH_ASYNC_IS_PEND());
    } while (bench_stats_sym_check(start));
exit_sha256:
    bench_stats_sym_finish("SHA-256", doAsync, count, start);

exit:

    if (ret < 0) {
        printf("bench_sha256 failed: %d\n", ret);
    }

#ifdef WOLFSSL_ASYNC_CRYPT
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        wc_Sha256Free(&hash[i]);
    }
#endif

    FREE_ARRAY(digest, BENCH_MAX_PENDING, HEAP_HINT);

    bench_async_end();
}
#endif

#ifdef WOLFSSL_SHA384
void bench_sha384(int doAsync)
{
    Sha384 hash[BENCH_MAX_PENDING];
    double start;
    int    ret, i, count = 0, times;
    DECLARE_ARRAY(digest, byte, BENCH_MAX_PENDING, SHA384_DIGEST_SIZE, HEAP_HINT);

    bench_async_begin();

    /* clear for done cleanup */
    XMEMSET(hash, 0, sizeof(hash));

    /* init keys */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        ret = wc_InitSha384_ex(&hash[i], HEAP_HINT,
            doAsync ? devId : INVALID_DEVID);
        if (ret != 0) {
            printf("InitSha384_ex failed, ret = %d\n", ret);
            goto exit;
        }
    }

    bench_stats_start(&count, &start);
    do {
        for (times = 0; times < numBlocks || BENCH_ASYNC_IS_PEND(); ) {
            bench_async_poll();

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(&hash[i]), 0, &times, numBlocks)) {
                    ret = wc_Sha384Update(&hash[i], bench_plain,
                        BENCH_SIZE);
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(&hash[i]), 0, &times)) {
                        goto exit_sha384;
                    }
                }
            } /* for i */
        } /* for times */
        count += times;

        times = 0;
        do {
            bench_async_poll();
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(&hash[i]), 0, &times, numBlocks)) {
                    ret = wc_Sha384Final(&hash[i], digest[i]);
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(&hash[i]), 0, &times)) {
                        goto exit_sha384;
                    }
                }
            } /* for i */
        } while (BENCH_ASYNC_IS_PEND());
    } while (bench_stats_sym_check(start));
exit_sha384:
    bench_stats_sym_finish("SHA-384", doAsync, count, start);

exit:

    if (ret < 0) {
        printf("bench_sha384 failed: %d\n", ret);
    }

#ifdef WOLFSSL_ASYNC_CRYPT
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        wc_Sha384Free(&hash[i]);
    }
#endif

    FREE_ARRAY(digest, BENCH_MAX_PENDING, HEAP_HINT);

    bench_async_end();
}
#endif

#ifdef WOLFSSL_SHA512
void bench_sha512(int doAsync)
{
    Sha512 hash[BENCH_MAX_PENDING];
    double start;
    int    ret, i, count = 0, times;
    DECLARE_ARRAY(digest, byte, BENCH_MAX_PENDING, SHA512_DIGEST_SIZE, HEAP_HINT);

    bench_async_begin();

    /* clear for done cleanup */
    XMEMSET(hash, 0, sizeof(hash));

    /* init keys */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        ret = wc_InitSha512_ex(&hash[i], HEAP_HINT,
            doAsync ? devId : INVALID_DEVID);
        if (ret != 0) {
            printf("InitSha512_ex failed, ret = %d\n", ret);
            goto exit;
        }
    }

    bench_stats_start(&count, &start);
    do {
        for (times = 0; times < numBlocks || BENCH_ASYNC_IS_PEND(); ) {
            bench_async_poll();

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(&hash[i]), 0, &times, numBlocks)) {
                    ret = wc_Sha512Update(&hash[i], bench_plain,
                        BENCH_SIZE);
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(&hash[i]), 0, &times)) {
                        goto exit_sha512;
                    }
                }
            } /* for i */
        } /* for times */
        count += times;

        times = 0;
        do {
            bench_async_poll();
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(&hash[i]), 0, &times, numBlocks)) {
                    ret = wc_Sha512Final(&hash[i], digest[i]);
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(&hash[i]), 0, &times)) {
                        goto exit_sha512;
                    }
                }
            } /* for i */
        } while (BENCH_ASYNC_IS_PEND());
    } while (bench_stats_sym_check(start));
exit_sha512:
    bench_stats_sym_finish("SHA-512", doAsync, count, start);

exit:

    if (ret < 0) {
        printf("bench_sha512 failed: %d\n", ret);
    }

#ifdef WOLFSSL_ASYNC_CRYPT
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        wc_Sha512Free(&hash[i]);
    }
#endif

    FREE_ARRAY(digest, BENCH_MAX_PENDING, HEAP_HINT);

    bench_async_end();
}
#endif

#ifdef WOLFSSL_RIPEMD
void bench_ripemd(void)
{
    RipeMd hash;
    byte   digest[RIPEMD_DIGEST_SIZE];
    double start;
    int    i, count;

    wc_InitRipeMd(&hash);

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            wc_RipeMdUpdate(&hash, bench_plain, BENCH_SIZE);
        }
        wc_RipeMdFinal(&hash, digest);
        count += i;
    } while (bench_stats_sym_check(start));
    bench_stats_sym_finish("RIPEMD", 0, count, start);
}
#endif


#ifdef HAVE_BLAKE2
void bench_blake2(void)
{
    Blake2b b2b;
    byte    digest[64];
    double  start;
    int     ret, i, count;

    ret = wc_InitBlake2b(&b2b, 64);
    if (ret != 0) {
        printf("InitBlake2b failed, ret = %d\n", ret);
        return;
    }

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < numBlocks; i++) {
            ret = wc_Blake2bUpdate(&b2b, bench_plain, BENCH_SIZE);
            if (ret != 0) {
                printf("Blake2bUpdate failed, ret = %d\n", ret);
                return;
            }
        }
        ret = wc_Blake2bFinal(&b2b, digest, 64);
        if (ret != 0) {
            printf("Blake2bFinal failed, ret = %d\n", ret);
            return;
        }
        count += i;
    } while (bench_stats_sym_check(start));
    bench_stats_sym_finish("BLAKE2b", 0, count, start);
}
#endif


#ifdef WOLFSSL_CMAC

void bench_cmac(void)
{
    Cmac    cmac;
    byte    digest[AES_BLOCK_SIZE];
    word32  digestSz = sizeof(digest);
    double  start;
    int     ret, i, count;

    bench_stats_start(&count, &start);
    do {
        ret = wc_InitCmac(&cmac, bench_key, 16, WC_CMAC_AES, NULL);
        if (ret != 0) {
            printf("InitCmac failed, ret = %d\n", ret);
            return;
        }

        for (i = 0; i < numBlocks; i++) {
            ret = wc_CmacUpdate(&cmac, bench_plain, BENCH_SIZE);
            if (ret != 0) {
                printf("CmacUpdate failed, ret = %d\n", ret);
                return;
            }
        }
        /* Note: final force zero's the Cmac struct */
        ret = wc_CmacFinal(&cmac, digest, &digestSz);
        if (ret != 0) {
            printf("CmacFinal failed, ret = %d\n", ret);
            return;
        }
        count += i;
    } while (bench_stats_sym_check(start));
    bench_stats_sym_finish("AES-CMAC", 0, count, start);
}

#endif /* WOLFSSL_CMAC */

#ifdef HAVE_SCRYPT

void bench_scrypt(void)
{
    byte   derived[64];
    double start;
    int    ret, i, count;

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < scryptCnt; i++) {
            ret = wc_scrypt(derived, (byte*)"pleaseletmein", 13,
                            (byte*)"SodiumChloride", 14, 14, 8, 1, sizeof(derived));
            if (ret != 0) {
                printf("scrypt failed, ret = %d\n", ret);
                goto exit;
            }
        }
        count += i;
    } while (bench_stats_sym_check(start));
exit:
    bench_stats_asym_finish("scrypt", 0, "", 0, count, start);
}

#endif /* HAVE_SCRYPT */

#ifndef NO_RSA

#if defined(WOLFSSL_KEY_GEN)
void bench_rsaKeyGen(int doAsync)
{
    RsaKey genKey[BENCH_MAX_PENDING];
    double start;
    int    ret, i, count = 0, times;
    int    k, keySz;
    const int  keySizes[2] = {1024, 2048};
    const long rsa_e_val = 65537;

    bench_async_begin();

    /* clear for done cleanup */
    XMEMSET(genKey, 0, sizeof(genKey));

    for (k = 0; k < (int)(sizeof(keySizes)/sizeof(int)); k++) {
        keySz = keySizes[k];

        bench_stats_start(&count, &start);
        do {
            /* while free pending slots in queue, submit ops */
            for (times = 0; times < genTimes || BENCH_ASYNC_IS_PEND(); ) {
                bench_async_poll();

                for (i = 0; i < BENCH_MAX_PENDING; i++) {
                    if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(&genKey[i]), 0, &times, genTimes)) {

                        wc_FreeRsaKey(&genKey[i]);
                        ret = wc_InitRsaKey_ex(&genKey[i], HEAP_HINT,
                            doAsync ? devId : INVALID_DEVID);
                        if (ret < 0) {
                            goto exit;
                        }

                        ret = wc_MakeRsaKey(&genKey[i], keySz, rsa_e_val, &rng);
                        if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(&genKey[i]), 0, &times)) {
                            goto exit;
                        }
                    }
                } /* for i */
            } /* for times */
            count += times;
        } while (bench_stats_sym_check(start));
    exit:
        bench_stats_asym_finish("RSA", keySz, "key gen", doAsync, count, start);

        if (ret < 0) {
            printf("bench_rsaKeyGen failed: %d\n", ret);
            break;
        }
    }

    /* cleanup */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        wc_FreeRsaKey(&genKey[i]);
    }

    bench_async_end();
}
#endif /* WOLFSSL_KEY_GEN */

#if !defined(USE_CERT_BUFFERS_1024) && !defined(USE_CERT_BUFFERS_2048)
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

#define RSA_BUF_SIZE 256  /* for up to 2048 bit */

void bench_rsa(int doAsync)
{
    int         ret, i, times, count = 0;
    size_t      bytes;
    word32      idx = 0;
    const byte* tmp;
    const char* messageStr = "Everyone gets Friday off.";
    const int   len = (int)XSTRLEN((char*)messageStr);
    double      start = 0.0f;
    RsaKey      rsaKey[BENCH_MAX_PENDING];
    int         rsaKeySz = RSA_BUF_SIZE * 8; /* used in printf */

    DECLARE_VAR_INIT(message, byte, len, messageStr, HEAP_HINT);
    DECLARE_ARRAY(enc, byte, BENCH_MAX_PENDING, RSA_BUF_SIZE, HEAP_HINT);
    DECLARE_ARRAY(out, byte, BENCH_MAX_PENDING, RSA_BUF_SIZE, HEAP_HINT);

#ifdef USE_CERT_BUFFERS_1024
    tmp = rsa_key_der_1024;
    bytes = sizeof_rsa_key_der_1024;
    rsaKeySz = 1024;
#elif defined(USE_CERT_BUFFERS_2048)
    tmp = rsa_key_der_2048;
    bytes = sizeof_rsa_key_der_2048;
#else
    #error "need a cert buffer size"
#endif /* USE_CERT_BUFFERS */

    bench_async_begin();

    /* clear for done cleanup */
    XMEMSET(rsaKey, 0, sizeof(rsaKey));

    /* init keys */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        /* setup an async context for each key */
        if ((ret = wc_InitRsaKey_ex(&rsaKey[i], HEAP_HINT,
                                        doAsync ? devId : INVALID_DEVID)) < 0) {
            goto exit;
        }

    #ifdef WC_RSA_BLINDING
        ret = wc_RsaSetRNG(&rsaKey[i], &rng);
        if (ret != 0)
            goto exit;
    #endif

        /* decode the private key */
        idx = 0;
        if ((ret = wc_RsaPrivateKeyDecode(tmp, &idx, &rsaKey[i],
                                                        (word32)bytes)) != 0) {
            printf("wc_RsaPrivateKeyDecode failed! %d\n", ret);
            goto exit;
        }
    }

    /* begin public RSA */
    bench_stats_start(&count, &start);
    do {
        for (times = 0; times < ntimes || BENCH_ASYNC_IS_PEND(); ) {
            bench_async_poll();

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(&rsaKey[i]), 1, &times, ntimes)) {
                    ret = wc_RsaPublicEncrypt(message, len, enc[i],
                                            RSA_BUF_SIZE, &rsaKey[i], &rng);
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(&rsaKey[i]), 1, &times)) {
                        goto exit_rsa_pub;
                    }
                }
            } /* for i */
        } /* for times */
        count += times;
    } while (bench_stats_sym_check(start));
exit_rsa_pub:
    bench_stats_asym_finish("RSA", rsaKeySz, "public", doAsync, count, start);

    if (ret < 0) {
        goto exit;
    }

#ifdef WOLFSSL_ASYNC_CRYPT
    /* Clear events */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        XMEMSET(&rsaKey[i].asyncDev.event, 0, sizeof(WOLF_EVENT));
    }
    asyncPending = 0;
#endif

    /* capture resulting encrypt length */
    idx = RSA_BUF_SIZE; /* fixed at 2048 bit */

    /* begin private async RSA */
    bench_stats_start(&count, &start);
    do {
        for (times = 0; times < ntimes || BENCH_ASYNC_IS_PEND(); ) {
            bench_async_poll();

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(&rsaKey[i]), 1, &times, ntimes)) {
                    ret = wc_RsaPrivateDecrypt(enc[i], idx, out[i],
                                                    RSA_BUF_SIZE, &rsaKey[i]);
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(&rsaKey[i]), 1, &times)) {
                        goto exit;
                    }
                }
            } /* for i */
        } /* for times */
        count += times;
    } while (bench_stats_sym_check(start));
exit:
    bench_stats_asym_finish("RSA", rsaKeySz, "private", doAsync, count, start);

    if (ret < 0) {
        printf("bench_rsa failed: %d\n", ret);
    }

    /* cleanup */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        wc_FreeRsaKey(&rsaKey[i]);
    }

    FREE_ARRAY(enc, BENCH_MAX_PENDING, HEAP_HINT);
    FREE_ARRAY(out, BENCH_MAX_PENDING, HEAP_HINT);
    FREE_VAR(message, HEAP_HINT);

    bench_async_end();
}

#endif /* !NO_RSA */


#ifndef NO_DH

#if !defined(USE_CERT_BUFFERS_1024) && !defined(USE_CERT_BUFFERS_2048)
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

#define BENCH_DH_KEY_SIZE  256 /* for 2048 bit */
#define BENCH_DH_PRIV_SIZE (BENCH_DH_KEY_SIZE/8)

void bench_dh(int doAsync)
{
    int    ret, i;
    int    count = 0, times;
    const byte* tmp = NULL;
    double start = 0.0f;
    DhKey  dhKey[BENCH_MAX_PENDING];
    int    dhKeySz = 2048; /* used in printf */
#ifndef NO_ASN
    size_t bytes;
    word32 idx;
#endif
    word32 pubSz[BENCH_MAX_PENDING];
    word32 privSz[BENCH_MAX_PENDING];
    word32 pubSz2;
    word32 privSz2;
    word32 agreeSz[BENCH_MAX_PENDING];

    DECLARE_ARRAY(pub, byte, BENCH_MAX_PENDING, BENCH_DH_KEY_SIZE, HEAP_HINT);
    DECLARE_VAR(pub2, byte, BENCH_DH_KEY_SIZE, HEAP_HINT);
    DECLARE_ARRAY(agree, byte, BENCH_MAX_PENDING, BENCH_DH_KEY_SIZE, HEAP_HINT);
    DECLARE_ARRAY(priv, byte, BENCH_MAX_PENDING, BENCH_DH_PRIV_SIZE, HEAP_HINT);
    DECLARE_VAR(priv2, byte, BENCH_DH_PRIV_SIZE, HEAP_HINT);

    (void)tmp;

#if defined(NO_ASN)
    dhKeySz = 1024;
    /* do nothing, but don't use default FILE */
#elif defined(USE_CERT_BUFFERS_1024)
    tmp = dh_key_der_1024;
    bytes = sizeof_dh_key_der_1024;
    dhKeySz = 1024;
#elif defined(USE_CERT_BUFFERS_2048)
    tmp = dh_key_der_2048;
    bytes = sizeof_dh_key_der_2048;
#else
    #error "need to define a cert buffer size"
#endif /* USE_CERT_BUFFERS */

    bench_async_begin();

    /* clear for done cleanup */
    XMEMSET(dhKey, 0, sizeof(dhKey));

    /* init keys */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        /* setup an async context for each key */
        ret = wc_InitDhKey_ex(&dhKey[i], HEAP_HINT,
                        doAsync ? devId : INVALID_DEVID);
        if (ret != 0)
            goto exit;

        /* setup key */
    #ifdef NO_ASN
        ret = wc_DhSetKey(&dhKey[i], dh_p, sizeof(dh_p), dh_g, sizeof(dh_g));
    #else
        idx = 0;
        ret = wc_DhKeyDecode(tmp, &idx, &dhKey[i], (word32)bytes);
    #endif
        if (ret != 0) {
            printf("DhKeyDecode failed %d, can't benchmark\n", ret);
            goto exit;
        }
    }

    /* Key Gen */
    bench_stats_start(&count, &start);
    do {
        /* while free pending slots in queue, submit ops */
        for (times = 0; times < genTimes || BENCH_ASYNC_IS_PEND(); ) {
            bench_async_poll();

            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(&dhKey[i]), 0, &times, genTimes)) {
                    privSz[i] = 0;
                    ret = wc_DhGenerateKeyPair(&dhKey[i], &rng, priv[i], &privSz[i],
                        pub[i], &pubSz[i]);
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(&dhKey[i]), 0, &times)) {
                        goto exit_dh_gen;
                    }
                }
            } /* for i */
        } /* for times */
        count += times;
    } while (bench_stats_sym_check(start));
exit_dh_gen:
    bench_stats_asym_finish("DH", dhKeySz, "key gen", doAsync, count, start);

    if (ret < 0) {
        goto exit;
    }

    /* Generate key to use as other public */
    ret = wc_DhGenerateKeyPair(&dhKey[0], &rng, priv2, &privSz2, pub2, &pubSz2);
#ifdef WOLFSSL_ASYNC_CRYPT
    ret = wc_AsyncWait(ret, &dhKey[0].asyncDev, WC_ASYNC_FLAG_NONE);

    /* Clear events */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        XMEMSET(&dhKey[i].asyncDev.event, 0, sizeof(WOLF_EVENT));
    }
    asyncPending = 0;
#endif

    /* Key Agree */
    bench_stats_start(&count, &start);
    do {
        for (times = 0; times < agreeTimes || BENCH_ASYNC_IS_PEND(); ) {
            bench_async_poll();

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(&dhKey[i]), 0, &times, agreeTimes)) {
                    ret = wc_DhAgree(&dhKey[i], agree[i], &agreeSz[i], priv[i], privSz[i],
                        pub2, pubSz2);
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(&dhKey[i]), 0, &times)) {
                        goto exit;
                    }
                }
            } /* for i */
        } /* for times */
        count += times;
    } while (bench_stats_sym_check(start));
exit:
    bench_stats_asym_finish("DH", dhKeySz, "key agree", doAsync, count, start);

    if (ret < 0) {
        printf("bench_dh failed: %d\n", ret);
    }

    /* cleanup */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        wc_FreeDhKey(&dhKey[i]);
    }

    FREE_ARRAY(pub, BENCH_MAX_PENDING, HEAP_HINT);
    FREE_VAR(pub2, HEAP_HINT);
    FREE_ARRAY(priv, BENCH_MAX_PENDING, HEAP_HINT);
    FREE_VAR(priv2, HEAP_HINT);
    FREE_ARRAY(agree, BENCH_MAX_PENDING, HEAP_HINT);

    bench_async_end();
}
#endif /* !NO_DH */

#ifdef HAVE_NTRU
byte GetEntropy(ENTROPY_CMD cmd, byte* out);

byte GetEntropy(ENTROPY_CMD cmd, byte* out)
{
    if (cmd == INIT)
        return 1; /* using local rng */

    if (out == NULL)
        return 0;

    if (cmd == GET_BYTE_OF_ENTROPY)
        return (wc_RNG_GenerateBlock(&rng, out, 1) == 0) ? 1 : 0;

    if (cmd == GET_NUM_BYTES_PER_BYTE_OF_ENTROPY) {
        *out = 1;
        return 1;
    }

    return 0;
}

void bench_ntru(void)
{
    int    i;
    double start;

    byte   public_key[1027];
    word16 public_key_len = sizeof(public_key);
    byte   private_key[1120];
    word16 private_key_len = sizeof(private_key);
    word16 ntruBits = 128;
    word16 type     = 0;
    word32 ret;

    byte ciphertext[1022];
    word16 ciphertext_len;
    byte plaintext[16];
    word16 plaintext_len;

    DRBG_HANDLE drbg;
    static byte const aes_key[] = {
        0xf3, 0xe9, 0x87, 0xbb, 0x18, 0x08, 0x3c, 0xaa,
        0x7b, 0x12, 0x49, 0x88, 0xaf, 0xb3, 0x22, 0xd8
    };

    static byte const wolfsslStr[] = {
        'w', 'o', 'l', 'f', 'S', 'S', 'L', ' ', 'N', 'T', 'R', 'U'
    };

    for (ntruBits = 128; ntruBits < 257; ntruBits += 64) {
        switch (ntruBits) {
            case 128:
                type = NTRU_EES439EP1;
                break;
            case 192:
                type = NTRU_EES593EP1;
                break;
            case 256:
                type = NTRU_EES743EP1;
                break;
        }

        ret = ntru_crypto_drbg_instantiate(ntruBits, wolfsslStr,
                sizeof(wolfsslStr), (ENTROPY_FN) GetEntropy, &drbg);
        if(ret != DRBG_OK) {
            printf("NTRU drbg instantiate failed\n");
            return;
        }

        /* set key sizes */
        ret = ntru_crypto_ntru_encrypt_keygen(drbg, type, &public_key_len,
                                                  NULL, &private_key_len, NULL);
        if (ret != NTRU_OK) {
            ntru_crypto_drbg_uninstantiate(drbg);
            printf("NTRU failed to get key lengths\n");
            return;
        }

        ret = ntru_crypto_ntru_encrypt_keygen(drbg, type, &public_key_len,
                                     public_key, &private_key_len,
                                     private_key);

        ntru_crypto_drbg_uninstantiate(drbg);

        if (ret != NTRU_OK) {
            printf("NTRU keygen failed\n");
            return;
        }

        ret = ntru_crypto_drbg_instantiate(ntruBits, NULL, 0,
                (ENTROPY_FN)GetEntropy, &drbg);
        if (ret != DRBG_OK) {
            printf("NTRU error occurred during DRBG instantiation\n");
            return;
        }

        ret = ntru_crypto_ntru_encrypt(drbg, public_key_len, public_key,
                sizeof(aes_key), aes_key, &ciphertext_len, NULL);

        if (ret != NTRU_OK) {
            printf("NTRU error occurred requesting the buffer size needed\n");
            return;
        }

        bench_stats_start(&i, &start);
        for (i = 0; i < ntimes; i++) {
            ret = ntru_crypto_ntru_encrypt(drbg, public_key_len, public_key,
                    sizeof(aes_key), aes_key, &ciphertext_len, ciphertext);
            if (ret != NTRU_OK) {
                printf("NTRU encrypt error\n");
                return;
            }
        }
        bench_stats_asym_finish("NTRU", ntruBits, "encryption", 0, i, start);

        ret = ntru_crypto_drbg_uninstantiate(drbg);
        if (ret != DRBG_OK) {
            printf("NTRU error occurred uninstantiating the DRBG\n");
            return;
        }

        ret = ntru_crypto_ntru_decrypt(private_key_len, private_key,
                ciphertext_len, ciphertext, &plaintext_len, NULL);

        if (ret != NTRU_OK) {
            printf("NTRU decrypt error occurred getting the buffer size needed\n");
            return;
        }

        plaintext_len = sizeof(plaintext);

        bench_stats_start(&i, &start);
        for (i = 0; i < ntimes; i++) {
            ret = ntru_crypto_ntru_decrypt(private_key_len, private_key,
                                      ciphertext_len, ciphertext,
                                      &plaintext_len, plaintext);

            if (ret != NTRU_OK) {
                printf("NTRU error occurred decrypting the key\n");
                return;
            }
        }
        bench_stats_asym_finish("NTRU", ntruBits, "decryption", 0, i, start);
    }

}

void bench_ntruKeyGen(void)
{
    double start;
    int    i;

    byte   public_key[1027];
    word16 public_key_len = sizeof(public_key);
    byte   private_key[1120];
    word16 private_key_len = sizeof(private_key);
    word16 ntruBits = 128;
    word16 type     = 0;
    word32 ret;

    DRBG_HANDLE drbg;
    static uint8_t const pers_str[] = {
                'w', 'o', 'l', 'f',  'S', 'S', 'L', ' ', 't', 'e', 's', 't'
    };

    for (ntruBits = 128; ntruBits < 257; ntruBits += 64) {
        ret = ntru_crypto_drbg_instantiate(ntruBits, pers_str,
                sizeof(pers_str), GetEntropy, &drbg);
        if (ret != DRBG_OK) {
            printf("NTRU drbg instantiate failed\n");
            return;
        }

        switch (ntruBits) {
            case 128:
                type = NTRU_EES439EP1;
                break;
            case 192:
                type = NTRU_EES593EP1;
                break;
            case 256:
                type = NTRU_EES743EP1;
                break;
        }

        /* set key sizes */
        ret = ntru_crypto_ntru_encrypt_keygen(drbg, type, &public_key_len,
                                                  NULL, &private_key_len, NULL);

        bench_stats_start(&i, &start);
        for (i = 0; i < genTimes; i++) {
            ret = ntru_crypto_ntru_encrypt_keygen(drbg, type, &public_key_len,
                                         public_key, &private_key_len,
                                         private_key);
        }
        bench_stats_asym_finish("NTRU", ntruBits, "key gen", 0, i, start);

        if (ret != NTRU_OK) {
            printf("keygen failed\n");
            return;
        }

        ret = ntru_crypto_drbg_uninstantiate(drbg);

        if (ret != NTRU_OK) {
            printf("NTRU drbg uninstantiate failed\n");
            return;
        }
    }
}
#endif

#ifdef HAVE_ECC
#define BENCH_ECC_SIZE  32

void bench_eccMakeKey(int doAsync)
{
    int ret, i, times, count;
    const int keySize = BENCH_ECC_SIZE;
    ecc_key genKey[BENCH_MAX_PENDING];
    double start;

    bench_async_begin();

    /* clear for done cleanup */
    XMEMSET(&genKey, 0, sizeof(genKey));

    /* ECC Make Key */
    bench_stats_start(&count, &start);
    do {
        /* while free pending slots in queue, submit ops */
        for (times = 0; times < genTimes || BENCH_ASYNC_IS_PEND(); ) {
            bench_async_poll();

            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(&genKey[i]), 0, &times, genTimes)) {

                    wc_ecc_free(&genKey[i]);
                    ret = wc_ecc_init_ex(&genKey[i], HEAP_HINT, doAsync ? devId : INVALID_DEVID);
                    if (ret < 0) {
                        goto exit;
                    }

                    ret = wc_ecc_make_key(&rng, keySize, &genKey[i]);
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(&genKey[i]), 0, &times)) {
                        goto exit;
                    }
                }
            } /* for i */
        } /* for times */
        count += times;
    } while (bench_stats_sym_check(start));
exit:
    bench_stats_asym_finish("ECC", keySize * 8, "key gen", doAsync, count, start);

    if (ret < 0) {
        printf("bench_eccMakeKey failed: %d\n", ret);
    }

    /* cleanup */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        wc_ecc_free(&genKey[i]);
    }

    bench_async_end();
}

void bench_ecc(int doAsync)
{
    int ret, i, times, count;
    const int keySize = BENCH_ECC_SIZE;
    ecc_key genKey[BENCH_MAX_PENDING];
#ifdef HAVE_ECC_DHE
    ecc_key genKey2[BENCH_MAX_PENDING];
#endif
#if !defined(NO_ASN) && defined(HAVE_ECC_SIGN)
#ifdef HAVE_ECC_VERIFY
    int    verify[BENCH_MAX_PENDING];
#endif
#endif
    word32 x[BENCH_MAX_PENDING];
    double start;

#ifdef HAVE_ECC_DHE
    DECLARE_ARRAY(shared, byte, BENCH_MAX_PENDING, BENCH_ECC_SIZE, HEAP_HINT);
#endif
#if !defined(NO_ASN) && defined(HAVE_ECC_SIGN)
    DECLARE_ARRAY(sig, byte, BENCH_MAX_PENDING, ECC_MAX_SIG_SIZE, HEAP_HINT);
#endif
    DECLARE_ARRAY(digest, byte, BENCH_MAX_PENDING, BENCH_ECC_SIZE, HEAP_HINT);

    bench_async_begin();

    /* clear for done cleanup */
    XMEMSET(&genKey, 0, sizeof(genKey));
#ifdef HAVE_ECC_DHE
    XMEMSET(&genKey2, 0, sizeof(genKey2));
#endif

    /* init keys */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        /* setup an context for each key */
        if ((ret = wc_ecc_init_ex(&genKey[i], HEAP_HINT,
                                    doAsync ? devId : INVALID_DEVID)) < 0) {
            goto exit;
        }
        ret = wc_ecc_make_key(&rng, keySize, &genKey[i]);
    #ifdef WOLFSSL_ASYNC_CRYPT
        ret = wc_AsyncWait(ret, &genKey[i].asyncDev, WC_ASYNC_FLAG_NONE);
    #endif
        if (ret < 0) {
            goto exit;
        }

    #ifdef HAVE_ECC_DHE
        if ((ret = wc_ecc_init_ex(&genKey2[i], HEAP_HINT, INVALID_DEVID)) < 0) {
            goto exit;
        }
        if ((ret = wc_ecc_make_key(&rng, keySize, &genKey2[i])) > 0) {
            goto exit;
        }
    #endif
    }

#ifdef HAVE_ECC_DHE
#ifdef WOLFSSL_ASYNC_CRYPT
    /* Clear events */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        XMEMSET(&genKey[i].asyncDev.event, 0, sizeof(WOLF_EVENT));
    }
    asyncPending = 0;
#endif

    /* ECC Shared Secret */
    bench_stats_start(&count, &start);
    do {
        for (times = 0; times < agreeTimes || BENCH_ASYNC_IS_PEND(); ) {
            bench_async_poll();

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(&genKey[i]), 1, &times, agreeTimes)) {
                    x[i] = keySize;
                    ret = wc_ecc_shared_secret(&genKey[i], &genKey2[i], shared[i], &x[i]);
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(&genKey[i]), 1, &times)) {
                        goto exit_ecdhe;
                    }
                }
            } /* for i */
        } /* for times */
        count += times;
    } while (bench_stats_sym_check(start));
exit_ecdhe:
    bench_stats_asym_finish("ECDHE", keySize * 8, "agree", doAsync, count, start);

    if (ret < 0) {
        goto exit;
    }
#endif /* HAVE_ECC_DHE */

#if !defined(NO_ASN) && defined(HAVE_ECC_SIGN)
#ifdef WOLFSSL_ASYNC_CRYPT
    /* Clear events */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        XMEMSET(&genKey[i].asyncDev.event, 0, sizeof(WOLF_EVENT));
    }
    asyncPending = 0;
#endif

    /* Init digest to sign */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        for (count = 0; count < keySize; count++) {
            digest[i][count] = (byte)count;
        }
    }

    /* ECC Sign */
    bench_stats_start(&count, &start);
    do {
        for (times = 0; times < agreeTimes || BENCH_ASYNC_IS_PEND(); ) {
            bench_async_poll();

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(&genKey[i]), 1, &times, agreeTimes)) {
                    if (genKey[i].state == 0)
                        x[i] = ECC_MAX_SIG_SIZE;
                    ret = wc_ecc_sign_hash(digest[i], keySize, sig[i], &x[i],
                                                            &rng, &genKey[i]);
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(&genKey[i]), 1, &times)) {
                        goto exit_ecdsa_sign;
                    }
                }
            } /* for i */
        } /* for times */
        count += times;
    } while (bench_stats_sym_check(start));
exit_ecdsa_sign:
    bench_stats_asym_finish("ECDSA", keySize * 8, "sign", doAsync, count, start);

    if (ret < 0) {
        goto exit;
    }

#ifdef HAVE_ECC_VERIFY
#ifdef WOLFSSL_ASYNC_CRYPT
    /* Clear events */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        XMEMSET(&genKey[i].asyncDev.event, 0, sizeof(WOLF_EVENT));
    }
    asyncPending = 0;
#endif

    /* ECC Verify */
    bench_stats_start(&count, &start);
    do {
        for (times = 0; times < agreeTimes || BENCH_ASYNC_IS_PEND(); ) {
            bench_async_poll();

            /* while free pending slots in queue, submit ops */
            for (i = 0; i < BENCH_MAX_PENDING; i++) {
                if (bench_async_check(&ret, BENCH_ASYNC_GET_DEV(&genKey[i]), 1, &times, agreeTimes)) {
                    if (genKey[i].state == 0)
                        verify[i] = 0;
                    ret = wc_ecc_verify_hash(sig[i], x[i], digest[i],
                                        keySize, &verify[i], &genKey[i]);
                    if (!bench_async_handle(&ret, BENCH_ASYNC_GET_DEV(&genKey[i]), 1, &times)) {
                        goto exit_ecdsa_verify;
                    }
                }
            } /* for i */
        } /* for times */
        count += times;
    } while (bench_stats_sym_check(start));
exit_ecdsa_verify:
    bench_stats_asym_finish("ECDSA", keySize * 8, "verify", doAsync, count, start);
#endif /* HAVE_ECC_VERIFY */
#endif /* !NO_ASN && HAVE_ECC_SIGN */

exit:

    if (ret < 0) {
        printf("bench_ecc failed: %d\n", ret);
    }

    /* cleanup */
    for (i = 0; i < BENCH_MAX_PENDING; i++) {
        wc_ecc_free(&genKey[i]);
    #ifdef HAVE_ECC_DHE
        wc_ecc_free(&genKey2[i]);
    #endif
    }

#ifdef HAVE_ECC_DHE
    FREE_ARRAY(shared, BENCH_MAX_PENDING, HEAP_HINT);
#endif
#if !defined(NO_ASN) && defined(HAVE_ECC_SIGN)
    FREE_ARRAY(sig, BENCH_MAX_PENDING, HEAP_HINT);
#endif
    FREE_ARRAY(digest, BENCH_MAX_PENDING, HEAP_HINT);

    bench_async_end();
}


#ifdef HAVE_ECC_ENCRYPT
void bench_eccEncrypt(void)
{
    ecc_key userA, userB;
    const int keySize = BENCH_ECC_SIZE;
    byte    msg[48];
    byte    out[80];
    word32  outSz   = sizeof(out);
    word32  bench_plainSz = BENCH_SIZE;
    int     ret, i, count;
    double start;

    ret = wc_ecc_init_ex(&userA, HEAP_HINT, devId);
    if (ret != 0) {
        printf("wc_ecc_encrypt make key A failed: %d\n", ret);
        return;
    }
    wc_ecc_init_ex(&userB, HEAP_HINT, devId);
    if (ret != 0) {
        printf("wc_ecc_encrypt make key B failed: %d\n", ret);
        wc_ecc_free(&userA);
        return;
    }

    ret = wc_ecc_make_key(&rng, keySize, &userA);
    if (ret != 0)
        goto exit;
    ret = wc_ecc_make_key(&rng, keySize, &userB);
    if (ret != 0)
        goto exit;

    for (i = 0; i < (int)sizeof(msg); i++)
        msg[i] = i;

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < ntimes; i++) {
            /* encrypt msg to B */
            ret = wc_ecc_encrypt(&userA, &userB, msg, sizeof(msg), out, &outSz, NULL);
            if (ret != 0) {
                printf("wc_ecc_encrypt failed! %d\n", ret);
                goto exit_enc;
            }
        }
        count += i;
    } while (bench_stats_sym_check(start));
exit_enc:
    bench_stats_asym_finish("ECC", keySize * 8, "encrypt", 0, count, start);

    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < ntimes; i++) {
            /* decrypt msg from A */
            ret = wc_ecc_decrypt(&userB, &userA, out, outSz, bench_plain, &bench_plainSz, NULL);
            if (ret != 0) {
                printf("wc_ecc_decrypt failed! %d\n", ret);
                goto exit_dec;
            }
        }
        count += i;
    } while (bench_stats_sym_check(start));
exit_dec:
    bench_stats_asym_finish("ECC", keySize * 8, "decrypt", 0, count, start);

exit:

    if (ret != 0) {
        printf("bench_eccEncrypt failed! %d\n", ret);
    }

    /* cleanup */
    wc_ecc_free(&userB);
    wc_ecc_free(&userA);
}
#endif
#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519
void bench_curve25519KeyGen(void)
{
    curve25519_key genKey;
    double start;
    int    ret, i, count;

    /* Key Gen */
    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < genTimes; i++) {
            ret = wc_curve25519_make_key(&rng, 32, &genKey);
            wc_curve25519_free(&genKey);
            if (ret != 0) {
                printf("wc_curve25519_make_key failed: %d\n", ret);
                break;
            }
        }
        count += i;
    } while (bench_stats_sym_check(start));
    bench_stats_asym_finish("CURVE", 25519, "key gen", 0, count, start);
}

#ifdef HAVE_CURVE25519_SHARED_SECRET
void bench_curve25519KeyAgree(void)
{
    curve25519_key genKey, genKey2;
    double start;
    int    ret, i, count;
    byte   shared[32];
    word32 x = 0;

    wc_curve25519_init(&genKey);
    wc_curve25519_init(&genKey2);

    ret = wc_curve25519_make_key(&rng, 32, &genKey);
    if (ret != 0) {
        printf("curve25519_make_key failed\n");
        return;
    }
    ret = wc_curve25519_make_key(&rng, 32, &genKey2);
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
        }
        count += i;
    } while (bench_stats_sym_check(start));
exit:
    bench_stats_asym_finish("CURVE", 25519, "key agree", 0, count, start);

    wc_curve25519_free(&genKey2);
    wc_curve25519_free(&genKey);
}
#endif /* HAVE_CURVE25519_SHARED_SECRET */
#endif /* HAVE_CURVE25519 */

#ifdef HAVE_ED25519
void bench_ed25519KeyGen(void)
{
    ed25519_key genKey;
    double start;
    int    i, count;

    /* Key Gen */
    bench_stats_start(&count, &start);
    do {
        for (i = 0; i < genTimes; i++) {
            wc_ed25519_init(&genKey);
            wc_ed25519_make_key(&rng, 32, &genKey);
            wc_ed25519_free(&genKey);
        }
        count += i;
    } while (bench_stats_sym_check(start));
    bench_stats_asym_finish("ED", 25519, "key gen", 0, count, start);
}


void bench_ed25519KeySign(void)
{
    int    ret;
    ed25519_key genKey;
#ifdef HAVE_ED25519_SIGN
    double start;
    int    i, count;
    byte   sig[ED25519_SIG_SIZE];
    byte   msg[512];
    word32 x = 0;
#endif

    wc_ed25519_init(&genKey);

    ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &genKey);
    if (ret != 0) {
        printf("ed25519_make_key failed\n");
        return;
    }

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
        }
        count += i;
    } while (bench_stats_sym_check(start));
exit_ed_sign:
    bench_stats_asym_finish("ED", 25519, "sign", 0, count, start);

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
        }
        count += i;
    } while (bench_stats_sym_check(start));
exit_ed_verify:
    bench_stats_asym_finish("ED", 25519, "verify", 0, count, start);
#endif /* HAVE_ED25519_VERIFY */
#endif /* HAVE_ED25519_SIGN */

    wc_ed25519_free(&genKey);
}
#endif /* HAVE_ED25519 */

#ifndef HAVE_STACK_SIZE
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

        return (double)count.QuadPart / freq.QuadPart;
    }

#elif defined MICROCHIP_PIC32
    #if defined(WOLFSSL_MICROCHIP_PIC32MZ)
        #define CLOCK 80000000.0
    #else
        #include <peripheral/timer.h>
        #define CLOCK 40000000.0
    #endif

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

#elif defined FREERTOS

    double current_time(int reset)
    {
        portTickType tickCount;

        (void) reset;

        /* tick count == ms, if configTICK_RATE_HZ is set to 1000 */
        tickCount = xTaskGetTickCount();
        return (double)tickCount / 1000;
    }

#elif defined (WOLFSSL_TIRTOS)

    extern double current_time(int reset);

#elif defined(FREESCALE_MQX)

    double current_time(int reset)
    {
        TIME_STRUCT tv;
        _time_get(&tv);

        return (double)tv.SECONDS + (double)tv.MILLISECONDS / 1000;
    }

#elif defined(FREESCALE_KSDK_BM)

    double current_time(int reset)
    {
        return (double)OSA_TimeGetMsec() / 1000;
    }

#elif defined(WOLFSSL_EMBOS)

    #include "RTOS.h"

    double current_time(int reset)
    {
        double time_now;
        double current_s = OS_GetTime() / 1000.0;
        double current_us = OS_GetTime_us() / 1000000.0;
        time_now = (double)( current_s + current_us);

        (void) reset;

        return time_now;
    }

#else

    #include <sys/time.h>

    double current_time(int reset)
    {
        struct timeval tv;

        (void)reset;

        gettimeofday(&tv, 0);

        return (double)tv.tv_sec + (double)tv.tv_usec / 1000000;
    }

#endif /* _WIN32 */
#endif /* !HAVE_STACK_SIZE */

#if defined(HAVE_GET_CYCLES)

static INLINE word64 get_intel_cycles(void)
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

#endif /* HAVE_GET_CYCLES */

#ifndef NO_MAIN_DRIVER

int main(int argc, char** argv)
{
    int ret = 0;

#ifdef HAVE_STACK_SIZE
    ret = StackSizeCheck(NULL, benchmark_test);
#else
    ret = benchmark_test(NULL);
#endif

    (void)argc;
    (void)argv;

    return ret;
}
#endif /* !NO_MAIN_DRIVER */

#else
    #ifndef NO_MAIN_DRIVER
        int main() { return 0; }
    #endif
#endif /* !NO_CRYPT_BENCHMARK */
