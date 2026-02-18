/* wolfentropy.c
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

/*

DESCRIPTION
This library contains implementation for the raw entropy source generator (TRNG)
Not to be confused for the DRBG implemented in random.c, this raw entropy is
designed to SEED a DRBG, not to be consumed directly for use cases requiring
random data. Use the DRBG outputs for consuming applications requesting random
data, use this implementation to seed and re-seed the DRBG.

*/

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef HAVE_ENTROPY_MEMUSE

#include <wolfssl/wolfcrypt/wolfentropy.h>

#include <wolfssl/wolfcrypt/sha3.h>
#if defined(__APPLE__) || defined(__MACH__)
    #include <mach/mach_time.h>
#endif

/* Define ENTROPY_MEMUSE_THREAD to force use of counter in a new thread.
 * Only do this when high resolution timer not otherwise available.
 */

/* Number of bytes that will hold the maximum entropy bits. */
#define MAX_ENTROPY_BYTES    (MAX_ENTROPY_BITS / 8)
/* Number of bits stored for one sample. */
#define ENTROPY_BITS_USED    8

/* Minimum entropy from a sample. */
#define ENTROPY_MIN          1
/* Number of extra samples to ensure full entropy. */
#define ENTROPY_EXTRA        64
/* Maximum number of bytes to sample to produce max entropy. */
#define MAX_NOISE_CNT        (MAX_ENTROPY_BITS * 8 + ENTROPY_EXTRA)

/* MemUse entropy global state initialized. */
static volatile int entropy_memuse_initialized = 0;
/* Global SHA-3 object used for conditioning entropy and creating noise. */
static wc_Sha3 entropyHash;
/* Reset the health tests. */
static void Entropy_HealthTest_Reset(void);

#ifdef CUSTOM_ENTROPY_TIMEHIRES
static WC_INLINE word64 Entropy_TimeHiRes(void)
{
    return CUSTOM_ENTROPY_TIMEHIRES();
}
#elif !defined(ENTROPY_MEMUSE_THREAD) && \
      (defined(__x86_64__) || defined(__i386__))
/* Get the high resolution time counter.
 *
 * @return  64-bit count of CPU cycles.
 */
static WC_INLINE word64 Entropy_TimeHiRes(void)
{
    unsigned int lo_c, hi_c;
    __asm__ __volatile__ (
        "rdtsc"
            : "=a"(lo_c), "=d"(hi_c)   /* out */
            : "a"(0)                   /* in */
            : "%ebx", "%ecx");         /* clobber */
    return ((word64)lo_c) | (((word64)hi_c) << 32);
}
#elif !defined(ENTROPY_MEMUSE_THREAD) && \
      (defined(__APPLE__) || defined(__MACH__))
/* Get the high resolution time counter.
 *
 * @return  64-bit time in nanoseconds.
 */
static WC_INLINE word64 Entropy_TimeHiRes(void)
{
    return clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW);
}
#elif !defined(ENTROPY_MEMUSE_THREAD) && defined(__aarch64__)
/* Get the high resolution time counter.
 *
 * @return  64-bit timer count.
 */
static WC_INLINE word64 Entropy_TimeHiRes(void)
{
    word64 cnt;
    __asm__ __volatile__ (
        "mrs %[cnt], cntvct_el0"
        : [cnt] "=r"(cnt)
        :
        :
    );
    return cnt;
}
#elif !defined(ENTROPY_MEMUSE_THREAD) && defined(__MICROBLAZE__)

#define LPD_SCNTR_BASE_ADDRESS 0xFF250000

/* Get the high resolution time counter.
 * Collect ticks from LPD_SCNTR
 * @return  64-bit tick count.
 */
static WC_INLINE word64 Entropy_TimeHiRes(void)
{
    word64 cnt;
    word32 *ptr;

    ptr = (word32*)LPD_SCNTR_BASE_ADDRESS;
    cnt = *(ptr+1);
    cnt = cnt << 32;
    cnt |= *ptr;

    return cnt;
}
#elif !defined(ENTROPY_MEMUSE_THREAD) && defined(_POSIX_C_SOURCE) && \
    (_POSIX_C_SOURCE >= 199309L)
/* Get the high resolution time counter.
 *
 * @return  64-bit time that is the nanoseconds of current time.
 */
static WC_INLINE word64 Entropy_TimeHiRes(void)
{
    struct timespec now;

    clock_gettime(CLOCK_REALTIME, &now);

    return now.tv_nsec;
}
#elif defined(_WIN32) /* USE_WINDOWS_API */
/* Get the high resolution time counter.
 *
 * @return  64-bit timer
 */
static WC_INLINE word64 Entropy_TimeHiRes(void)
{
    LARGE_INTEGER count;
    QueryPerformanceCounter(&count);
    return (word64)(count.QuadPart);
}
#elif !defined(ENTROPY_MEMUSE_THREAD) && defined(__arm__)
/* Get time counter from arch_sys_counter clocksource.
 *
 * @return  64-bit timer count.
 */
static WC_INLINE word64 Entropy_TimeHiRes(void)
{
    word32 lo, hi;
    __asm__ __volatile__ (
        "mrrc p15, 1, %[lo], %[hi], c14"
        : [lo] "=r"(lo), [hi] "=r"(hi)
    );
    return ((word64)hi << 32) | lo;
}
#elif defined(WOLFSSL_THREAD_NO_JOIN)

/* Start and stop thread that counts as a proxy for time counter. */
#define ENTROPY_MEMUSE_THREADED

/* Data for entropy thread. */
typedef struct ENTROPY_THREAD_DATA {
    /* Current counter - proxy for time. */
    word64 counter;
    /* Whether to stop thread. */
    int stop;
} ENTROPY_THREAD_DATA;

/* Track whether entropy thread has been started already. */
static int entropy_thread_started = 0;
/* Data for thread to update/observer. */
static volatile ENTROPY_THREAD_DATA entropy_thread_data = { 0, 0 };

/* Get the high resolution time counter. Counter incremented in thread.
 *
 * @return  64-bit counter.
 */
static WC_INLINE word64 Entropy_TimeHiRes(void)
{
    /* Return counter update in thread. */
    return entropy_thread_data.counter;
}

/* Thread that increments counter while not told to stop.
 *
 * @param [in,out] args  Entropy data including: counter and stop flag.
 * @return  NULL always.
 */
static THREAD_RETURN_NOJOIN WOLFSSL_THREAD_NO_JOIN
    Entropy_IncCounter(void* args)
{
    (void)args;

    /* Keep going until caller tells us to stop and exit. */
    while (!entropy_thread_data.stop) {
        /* Increment counter acting as high resolution timer. */
        entropy_thread_data.counter++;
    }

#ifdef WOLFSSL_DEBUG_ENTROPY_MEMUSE
    fprintf(stderr, "EXITING ENTROPY COUNTER THREAD\n");
#endif

    /* Exit from thread. */
    RETURN_FROM_THREAD_NOJOIN(0);
}

/* Start a thread that increments counter if not one already.
 *
 * Won't start a new thread if one already running.
 * Waits for thread to start by waiting for counter to have incremented.
 *
 * @return  0 on success.
 * @return  Negative on failure.
 */
static int Entropy_StartThread(void)
{
    int ret = 0;

    /* Only continue if we haven't started a thread. */
    if (!entropy_thread_started) {
        /* Get counter before starting thread. */
        word64 start_counter = entropy_thread_data.counter;

        /* In case of restarting thread, set stop indicator to false. */
        entropy_thread_data.stop = 0;

    #ifdef WOLFSSL_DEBUG_ENTROPY_MEMUSE
        fprintf(stderr, "STARTING ENTROPY COUNTER THREAD\n");
    #endif
        /* Create a thread that increments the counter in the data. */
        /* Thread resources to be disposed of. */
        ret = wolfSSL_NewThreadNoJoin(Entropy_IncCounter, NULL);
        if (ret == 0) {
            /* Wait for the counter to increase indicating thread started. */
            while (entropy_thread_data.counter == start_counter) {
                sched_yield();
            }
        }

        entropy_thread_started = (ret == 0);
    }

    return ret;
}

/* Tell thread to stop and wait for it to complete.
 *
 * Called by wolfCrypt_Cleanup().
 */
static void Entropy_StopThread(void)
{
    /* Only stop a thread if one is running. */
    if (entropy_thread_started) {
        /* Tell thread to stop. */
        entropy_thread_data.stop = 1;
        /* Stopped thread so no thread started anymore. */
        entropy_thread_started = 0;
    }
}
    /* end if defined(HAVE_PTHREAD) */

#else

#error "No high precision time available for MemUse Entropy."

#endif

#ifndef ENTROPY_NUM_WORDS_BITS
    /* Number of bits to count of 64-bit words in state. */
    #define ENTROPY_NUM_WORDS_BITS      14
#endif

/* Floor of 8 yields pool of 256x 64-bit word samples
 * 9  -> 512x 64-bit word samples
 * 10 -> 1,024x 64-bit word samples
 * 11 -> 2,048x 64-bit word samples
 * 12 -> 4,096x 64-bit word samples
 * 13 -> 8,192x 64-bit word samples
 * 14 -> 16,384x 64-bit word samples
 * 15 -> 32,768x 64-bit word samples
 * ... doubling every time up to a maximum of:
 * 30 -> 1,073,741,824x 64-bit word samples
 * 1 billion+ samples should be more then sufficient for any use-case
 */
#if ENTROPY_NUM_WORDS_BITS < 8
    #error "ENTROPY_NUM_WORDS_BITS must be 8 or more"
#elif ENTROPY_NUM_WORDS_BITS > 30
    #error "ENTROPY_NUM_WORDS_BITS must be less than 31"
#endif
/* Number of 64-bit words in state. */
#define ENTROPY_NUM_WORDS               (1 << ENTROPY_NUM_WORDS_BITS)

/* Size of one block of 64-bit words. */
#define ENTROPY_BLOCK_SZ                (ENTROPY_NUM_WORDS_BITS - 8)

#ifndef ENTROPY_NUM_UPDATES
    /* Number of times to update random blocks.
     * Less than 2^ENTROPY_BLOCK_SZ (default: 2^6 = 64).
     * Maximize value to maximize entropy per sample.
     * Limit value to ensure entropy is collected in a timely manner.
     */
    #define ENTROPY_NUM_UPDATES         18
    /* Upper round of log2(ENTROPY_NUM_UPDATES) */
    #define ENTROPY_NUM_UPDATES_BITS    5
#elif !defined(ENTROPY_NUM_UPDATES_BITS)
    #define ENTROPY_NUM_UPDATES_BITS     ENTROPY_BLOCK_SZ
#endif
#ifndef ENTROPY_NUM_UPDATES_BITS
    #error "ENTROPY_NUM_UPDATES_BITS must be defined - " \
           "upper(log2(ENTROPY_NUM_UPDATES))"
#endif
#if ENTROPY_NUM_UPDATES_BITS != 0
    /* Amount to shift offset to get better coverage of a block */
    #define ENTROPY_OFFSET_SHIFTING          \
        (ENTROPY_BLOCK_SZ / ENTROPY_NUM_UPDATES_BITS)
#else
    /* Amount to shift offset to get better coverage of a block */
    #define ENTROPY_OFFSET_SHIFTING          ENTROPY_BLOCK_SZ
#endif

#ifndef ENTROPY_NUM_64BIT_WORDS
    /* Number of 64-bit words to update - 32. */
    #define ENTROPY_NUM_64BIT_WORDS     WC_SHA3_256_DIGEST_SIZE
#elif ENTROPY_NUM_64BIT_WORDS > WC_SHA3_256_DIGEST_SIZE
    #error "ENTROPY_NUM_64BIT_WORDS must be <= SHA3-256 digest size in bytes"
#endif

#if ENTROPY_BLOCK_SZ < ENTROPY_NUM_UPDATES_BITS
#define EXTRA_ENTROPY_WORDS             ENTROPY_NUM_UPDATES
#else
#define EXTRA_ENTROPY_WORDS             0
#endif

/* State to update that is multiple cache lines long. */
static word64 entropy_state[ENTROPY_NUM_WORDS + EXTRA_ENTROPY_WORDS] = {0};

/* Using memory will take different amount of times depending on the CPU's
 * caches and business.
 */
static void Entropy_MemUse(void)
{
    int i;
    static byte d[WC_SHA3_256_DIGEST_SIZE];
    int j;

    for (j = 0; j < ENTROPY_NUM_UPDATES; j++) {
        /* Hash the first 32 64-bit words of state. */
        wc_Sha3_256_Update(&entropyHash, (byte*)entropy_state,
            sizeof(*entropy_state) * ENTROPY_NUM_64BIT_WORDS);
        /* Get pseudo-random indices. */
        wc_Sha3_256_Final(&entropyHash, d);

        for (i = 0; i < ENTROPY_NUM_64BIT_WORDS; i++) {
            /* Choose a 64-bit word from a pseudo-random block.*/
            int idx = ((int)d[i] << ENTROPY_BLOCK_SZ) +
                      (j << ENTROPY_OFFSET_SHIFTING);
            /* Update a pseudo-random 64-bit word with a pseudo-random value. */
            entropy_state[idx] += Entropy_TimeHiRes();
            /* Ensure part of state that is hashed is updated. */
            entropy_state[i] += entropy_state[idx];
        }
    }
}


/* Last time entropy sample was gathered. */
static word64 entropy_last_time = 0;

/* Get a sample of noise.
 *
 * Value is time taken to use memory.
 *
 * Called to test raw entropy.
 *
 * @return  64-bit value that is the noise.
 */
static word64 Entropy_GetSample(void)
{
    word64 now;
    word64 ret;

#ifdef HAVE_FIPS
    /* First sample must be disregard when in FIPS. */
    if (entropy_last_time == 0) {
        /* Get sample which triggers CAST in FIPS mode. */
        Entropy_MemUse();
        /* Start entropy time after CASTs. */
        entropy_last_time = Entropy_TimeHiRes();
    }
#endif

    /* Use memory such that it will take an unpredictable amount of time. */
    Entropy_MemUse();

    /* Get the time now to subtract from previous end time. */
    now = Entropy_TimeHiRes();
    /* Calculate time diff since last sampling. */
    ret = now - entropy_last_time;
    /* Store last time. */
    entropy_last_time = now;

    return ret;
}

/* Get as many samples of noise as required.
 *
 * One sample is one byte.
 *
 * @param [out] noise    Buffer to hold samples.
 * @param [in]  samples  Number of one byte samples to get.
 */
static void Entropy_GetNoise(unsigned char* noise, int samples)
{
    int i;

    /* Do it once to get things going. */
    Entropy_MemUse();

    /* Get as many samples as required. */
    for (i = 0; i < samples; i++) {
       noise[i] = (byte)Entropy_GetSample();
    }
}

/* Generate raw entropy for performing assessment.
 *
 * @param [out] raw  Buffer to hold raw entropy data.
 * @param [in]  cnt  Number of bytes of raw entropy to get.
 * @return  0 on success.
 * @return  Negative when creating a thread fails - when no high resolution
 * clock available.
 */
int wc_Entropy_GetRawEntropy(unsigned char* raw, int cnt)
{
    int ret = 0;

#ifdef ENTROPY_MEMUSE_THREADED
    /* Start the counter thread as a proxy for time counter. */
    ret = Entropy_StartThread();
    if (ret == 0)
#endif
    {
        Entropy_GetNoise(raw, cnt);
    }
#ifdef ENTROPY_MEMUSE_THREADED
    /* Stop the counter thread to avoid thrashing the system. */
    Entropy_StopThread();
#endif

    return ret;
}

#if ENTROPY_MIN == 1
/* SP800-90b 4.4.1 - Repetition Test
 * C = 1 + upper(-log2(alpha) / H)
 * When alpha = 2^-30 and H = 1,
 * C = 1 + upper(30 / 1) = 31
 */
#define REP_CUTOFF           31
#else
#error "Minimum entropy not defined to a recognized value."
#endif

/* Have valid previous sample for repetition test. */
static int rep_have_prev = 0;
/* Previous sample value. */
static byte rep_prev_noise;

static void Entropy_HealthTest_Repetition_Reset(void)
{
    /* No previous stored. */
    rep_have_prev = 0;
    /* Clear previous. */
    rep_prev_noise = 0;
}

/* Test sample value with repetition test.
 *
 * @param [in] noise  Sample to test.
 * @return  0 on success.
 * @return  ENTROPY_RT_E on failure.
 */
static int Entropy_HealthTest_Repetition(byte noise)
{
    int ret = 0;
    /* Number of times previous value has been seen continuously. */
    static int rep_cnt = 0;

    /* If we don't have a previous then store this one for next time. */
    if (!rep_have_prev) {
        rep_prev_noise = noise;
        rep_have_prev = 1;
        rep_cnt = 1;
    }
    /* Check whether this sample matches last. */
    else if (noise == rep_prev_noise) {
        /* Update count of repetitions. */
        rep_cnt++;
        /* Fail if we reach cutoff. */
        if (rep_cnt >= REP_CUTOFF) {
        #ifdef WOLFSSL_DEBUG_ENTROPY_MEMUSE
            fprintf(stderr, "REPETITION FAILED: %d\n", noise);
        #endif
            Entropy_HealthTest_Repetition_Reset();
            ret = ENTROPY_RT_E;
        }
    }
    else {
        /* Cache new previous and seen one so far. */
        rep_prev_noise = noise;
        rep_cnt = 1;
    }

    return ret;
}

/* SP800-90b 4.4.2 - Adaptive Proportion Test
 * Para 2
 *   ... The window size W is selected based on the alphabet size ... 512 if
 *   the noise source is not binary ...
 */
#define PROP_WINDOW_SIZE     512
#if ENTROPY_MIN == 1
/* SP800-90b 4.4.2 - Adaptive Proportion Test
 * Note 10
 * C = 1 + CRITBINOM(W, power(2,( -H)),1-alpha)
 * alpha = 2^-30 = POWER(2,-30), H = 1, W = 512
 * C = 1 + CRITBINOM(512, 0.5, 1-POWER(2,-30)) = 1 + 324 = 325
 */
#define PROP_CUTOFF          325
#else
#error "Minimum entropy not defined to a recognized value."
#endif

/* Total number of samples storef for Adaptive proportion test.
 * Need the next 512 samples to compare this this one.
 */
static word16 prop_total = 0;
/* Index of first sample. */
static word16 prop_first = 0;
/* Index to put next sample in. */
static word16 prop_last = 0;
/* Count of each value seen in queue. */
static word16 prop_cnt[1 << ENTROPY_BITS_USED] = { 0 };
/* Circular queue of samples. */
static word16 prop_samples[PROP_WINDOW_SIZE];

/* Resets the data for the Adaptive Proportion Test.
 */
static void Entropy_HealthTest_Proportion_Reset(void)
{
    /* Clear out samples. */
    XMEMSET(prop_samples, 0, sizeof(prop_samples));
    /* Clear out counts. */
    XMEMSET(prop_cnt, 0, sizeof(prop_cnt));
    /* Clear stored count. */
    prop_total = 0;
    /* Reset first and last index for samples. */
    prop_first = 0;
    prop_last = 0;
}

/* Add sample to Adaptive Proportion test.
 *
 * SP800-90b 4.4.2 - Adaptive Proportion Test
 *
 * Sample is accumulated into buffer until required successive values seen.
 *
 * @param [in] noise  Sample to test.
 * @return  0 on success.
 * @return  ENTROPY_APT_E on failure.
 */
static int Entropy_HealthTest_Proportion(byte noise)
{
    int ret = 0;

    /* Need minimum samples in queue to test with - keep adding while we have
     * less. */
    if (prop_total < PROP_CUTOFF - 1) {
        /* Store sample at last position in circular queue. */
        prop_samples[prop_last++] = noise;
        /* Update count of seen value based on new sample. */
        prop_cnt[noise]++;
        /* Update count of store values. */
        prop_total++;
    }
    else {
        /* We have at least a minimum set of samples in queue. */
        /* Store new sample at end of queue. */
        prop_samples[prop_last] = noise;
        /* Update last index now that we have added new sample to queue. */
        prop_last = (prop_last + 1) % PROP_WINDOW_SIZE;
        /* Added sample to queue - add count. */
        prop_cnt[noise]++;
        /* Update count of store values. */
        prop_total++;

        /* Check whether first value has too many repetitions in queue. */
        if (prop_cnt[noise] >= PROP_CUTOFF) {
        #ifdef WOLFSSL_DEBUG_ENTROPY_MEMUSE
            fprintf(stderr, "PROPORTION FAILED: %d %d\n", val, prop_cnt[noise]);
        #endif
            Entropy_HealthTest_Proportion_Reset();
            /* Error code returned. */
            ret = ENTROPY_APT_E;
        }
        else if (prop_total == PROP_WINDOW_SIZE) {
            /* Return to 511 samples in queue. */
            /* Get first value in queue - value to test. */
            byte val = (byte)prop_samples[prop_first];
            /* Update first index to remove first sample from the queue. */
            prop_first = (prop_first + 1) % PROP_WINDOW_SIZE;
            /* Removed first sample from queue - remove count. */
            prop_cnt[val]--;
            /* Update count of store values. */
            prop_total--;
        }
    }

    return ret;
}

/* SP800-90b 4.3 - Requirements for Health Tests
 * 1.4: The entropy source's startup tests shall run the continuous health
 * tests over at least 1024 consecutive samples.
 *
 * Adaptive Proportion Test requires a number of samples to compared too.
 */
#define ENTROPY_INITIAL_COUNT   (1024 + PROP_WINDOW_SIZE)

/* Perform startup health testing.
 *
 * Fill adaptive proportion test buffer and then do 1024 samples.
 * Perform repetition test on all samples expect last.
 *
 * Discards samples from health tests on failure.
 *
 * @return  0 on success.
 * @return  ENTROPY_RT_E or ENTROPY_APT_E on failure.
 */
static int Entropy_HealthTest_Startup(void)
{
    int ret = 0;
    byte initial[ENTROPY_INITIAL_COUNT];
    int i;

#ifdef WOLFSSL_DEBUG_ENTROPY_MEMUSE
    fprintf(stderr, "STARTUP HEALTH TEST\n");
#endif

    /* Reset cached values before testing. */
    Entropy_HealthTest_Reset();

    /* Fill initial sample buffer with noise. */
    Entropy_GetNoise(initial, ENTROPY_INITIAL_COUNT);
    /* Health check initial noise. */
    for (i = 0; (ret == 0) && (i < ENTROPY_INITIAL_COUNT); i++) {
        ret = Entropy_HealthTest_Repetition(initial[i]);
        if (ret == 0) {
            ret = Entropy_HealthTest_Proportion(initial[i]);
        }
    }

    if (ret != 0) {
        /* Failing test only resets its own data. */
        Entropy_HealthTest_Reset();
    }

    return ret;
}

/* Condition raw entropy noise using SHA-3-256.
 *
 * Put noise into a hash function: SHA-3-256.
 * Add the current time counter to help with uniqueness.
 *
 * @param [out]  output     Buffer to conditioned data.
 * @param [in]   len        Number of bytes to put into output buffer.
 * @param [in]   noise      Buffer with raw noise data.
 * @param [in]   noise_len  Length of noise data in bytes.
 * @return  0 on success.
 * @return  Negative on failure.
 */
static int Entropy_Condition(byte* output, word32 len, byte* noise,
    word32 noise_len)
{
    int ret;

    /* Add noise to initialized hash. */
    ret = wc_Sha3_256_Update(&entropyHash, noise, noise_len);
    if (ret == 0) {
        word64 now = Entropy_TimeHiRes();
        /* Add time now counter. */
        ret = wc_Sha3_256_Update(&entropyHash, (byte*)&now, sizeof(now));
    }
    if (ret == 0) {
        /* Finalize into output buffer. */
        if (len == WC_SHA3_256_DIGEST_SIZE) {
            ret = wc_Sha3_256_Final(&entropyHash, output);
        }
        else {
            byte hash[WC_SHA3_256_DIGEST_SIZE];

            ret = wc_Sha3_256_Final(&entropyHash, hash);
            if (ret == 0) {
                XMEMCPY(output, hash, len);
            }
        }
    }

    return ret;
}

/* Mutex to prevent multiple callers requesting entropy operations at the
 * same time.
 */
static wolfSSL_Mutex entropy_mutex WOLFSSL_MUTEX_INITIALIZER_CLAUSE(entropy_mutex);

/* Get entropy of specified strength.
 *
 * SP800-90b 2.3.1 - GetEntropy: An Interface to the Entropy Source
 *
 * In threaded environment, only one thread at a time can get entropy.
 *
 * @param [in]  bits     Number of entropy bits. 256 is max value.
 * @param [out] entropy  Buffer to hold entropy.
 * @param [in]  len      Length of data to put into buffer in bytes.
 * @return  0 on success.
 * @return  ENTROPY_RT_E or ENTROPY_APT_E on failure.
 * @return  BAD_MUTEX_E when unable to lock mutex.
 */
int wc_Entropy_Get(int bits, unsigned char* entropy, word32 len)
{
    int ret = 0;
    /* Noise length is the number of 8 byte samples required to get the bits of
     * entropy requested. */
    int noise_len = (bits + ENTROPY_EXTRA) / ENTROPY_MIN;
    static byte noise[MAX_NOISE_CNT];

#ifdef HAVE_FIPS
    /* FIPS KATs, e.g. EccPrimitiveZ_KnownAnswerTest(), call wc_Entropy_Get()
     * incidental to wc_InitRng(), without first calling Entropy_Init(), neither
     * directly, nor indirectly via wolfCrypt_Init().  This matters, because
     * KATs must be usable before wolfCrypt_Init() (indeed, in the library
     * embodiment, the HMAC KAT always runs before wolfCrypt_Init(), incidental
     * to fipsEntry()).  Without the InitSha3() under Entropy_Init(), the
     * SHA3_BLOCK function pointer is null when Sha3Update() is called by
     * Entropy_MemUse(), which ends badly.
     */
    if (!entropy_memuse_initialized) {
        ret = Entropy_Init();
    }
#endif

    /* Lock the mutex as collection uses globals. */
    if ((ret == 0) && (wc_LockMutex(&entropy_mutex) != 0)) {
        ret = BAD_MUTEX_E;
    }

#ifdef ENTROPY_MEMUSE_THREADED
    if (ret == 0) {
        /* Start the counter thread as a proxy for time counter. */
        ret = Entropy_StartThread();
    }
#endif

    /* Check we have had a startup health check pass. */
    if ((ret == 0) && ((prop_total == 0) || (!rep_have_prev))) {
        /* Try again as check failed. */
        ret = Entropy_HealthTest_Startup();
    }

    /* Keep putting data into buffer until full. */
    while ((ret == 0) && (len > 0)) {
        int i;
        word32 entropy_len = WC_SHA3_256_DIGEST_SIZE;

        /* Output 32 bytes at a time unless buffer has fewer bytes remaining. */
        if (len < entropy_len) {
            entropy_len = len;
        }

        /* Get raw entropy noise. */
        Entropy_GetNoise(noise, noise_len);
        /* Health check each noise value. */
        for (i = 0; (ret == 0) && (i < noise_len); i++) {
            ret = Entropy_HealthTest_Repetition(noise[i]);
            if (ret == 0) {
                ret = Entropy_HealthTest_Proportion(noise[i]);
            }
        }

        if (ret == 0) {
            /* Condition noise value down to 32-bytes or less. */
            ret = Entropy_Condition(entropy, entropy_len, noise, noise_len);
        }
        if (ret == 0) {
            /* Update buffer pointer and count of bytes left to generate. */
            entropy += entropy_len;
            len -= entropy_len;
        }
        if (ret == 0) {
            ret = WC_CHECK_FOR_INTR_SIGNALS();
        }
        if (ret == 0) {
            WC_RELAX_LONG_LOOP();
        }
    }

#ifdef ENTROPY_MEMUSE_THREADED
    /* Stop the counter thread to avoid thrashing the system. */
    Entropy_StopThread();
#endif

    if (ret != WC_NO_ERR_TRACE(BAD_MUTEX_E)) {
        /* Unlock mutex now we are done. */
        wc_UnLockMutex(&entropy_mutex);
    }

    return ret;
}

/* Performs on-demand testing.
 *
 * In threaded environment, locks out other threads from getting entropy.
 *
 * @return  0 on success.
 * @return  ENTROPY_RT_E or ENTROPY_APT_E on failure.
 * @return  BAD_MUTEX_E when unable to lock mutex.
 */
int wc_Entropy_OnDemandTest(void)
{
    int ret = 0;

    /* Lock the mutex as we don't want collecting to happen during testing. */
    if (wc_LockMutex(&entropy_mutex) != 0) {
        ret = BAD_MUTEX_E;
    }

    if (ret == 0) {
        /* Perform startup tests. */
        ret = Entropy_HealthTest_Startup();
    }

    if (ret != WC_NO_ERR_TRACE(BAD_MUTEX_E)) {
        /* Unlock mutex now we are done. */
        wc_UnLockMutex(&entropy_mutex);
    }
    return ret;
}

/* Initialize global state for MemUse Entropy and do startup health test.
 *
 * @return  0 on success.
 * @return  Negative on failure.
 */
int Entropy_Init(void)
{
    int ret = 0;

    /* Check whether initialization has succeeded before. */
    if (!entropy_memuse_initialized) {
    #if !defined(SINGLE_THREADED) && !defined(WOLFSSL_MUTEX_INITIALIZER)
        ret = wc_InitMutex(&entropy_mutex);
    #endif
        if (ret == 0)
            ret = wc_LockMutex(&entropy_mutex);

        if (entropy_memuse_initialized) {
            /* Short circuit return -- a competing thread initialized the state
             * while we were waiting.  Note, this is only threadsafe when
             * WOLFSSL_MUTEX_INITIALIZER is defined.
             */
            if (ret == 0)
                wc_UnLockMutex(&entropy_mutex);
            return 0;
        }

        if (ret == 0) {
            /* Initialize a SHA3-256 object for use in entropy operations. */
            ret = wc_InitSha3_256(&entropyHash, NULL, INVALID_DEVID);
        }
        /* Set globals initialized. */
        entropy_memuse_initialized = (ret == 0);
        if (ret == 0) {
        #ifdef ENTROPY_MEMUSE_THREADED
            /* Start the counter thread as a proxy for time counter. */
            ret = Entropy_StartThread();
            if (ret == 0)
        #endif
            {
                /* Do first startup test now. */
                ret = Entropy_HealthTest_Startup();
            }
        #ifdef ENTROPY_MEMUSE_THREADED
            /* Stop the counter thread to avoid thrashing the system. */
            Entropy_StopThread();
        #endif
        }

        if (ret != WC_NO_ERR_TRACE(BAD_MUTEX_E)) {
            wc_UnLockMutex(&entropy_mutex);
        }
    }

    return ret;
}

/* Finalize the data associated with the MemUse Entropy source.
 */
void Entropy_Final(void)
{
    /* Only finalize when initialized. */
    if (entropy_memuse_initialized) {
        /* Dispose of the SHA3-356 hash object. */
        wc_Sha3_256_Free(&entropyHash);
    #if !defined(SINGLE_THREADED) && !defined(WOLFSSL_MUTEX_INITIALIZER)
        wc_FreeMutex(&entropy_mutex);
    #endif
        /* Clear health test data. */
        Entropy_HealthTest_Reset();
        /* No longer initialized. */
        entropy_memuse_initialized = 0;
    }
}

/* Reset the data associated with the MemUse Entropy health tests.
 */
static void Entropy_HealthTest_Reset(void)
{
    Entropy_HealthTest_Repetition_Reset();
    Entropy_HealthTest_Proportion_Reset();
}

#endif /* HAVE_ENTROPY_MEMUSE */

