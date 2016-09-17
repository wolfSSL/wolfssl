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

#ifdef WOLFSSL_ASYNC_CRYPT
    #include <wolfssl/wolfcrypt/async.h>
#endif
#if defined(WOLFSSL_ASYNC_CRYPT) || defined(HAVE_ECC)
    static int devId = INVALID_DEVID;
#endif

#ifdef HAVE_WNR
    const char* wnrConfigFile = "wnr-example.conf";
#endif

#if defined(WOLFSSL_MDK_ARM)
    extern FILE * wolfSSL_fopen(const char *fname, const char *mode) ;
    #define fopen wolfSSL_fopen
#endif

#if defined(__GNUC__) && defined(__x86_64__) && !defined(NO_ASM)
    #define HAVE_GET_CYCLES
    static INLINE word64 get_intel_cycles(void);
    static word64 total_cycles;
    #define INIT_CYCLE_COUNTER
    #define BEGIN_INTEL_CYCLES total_cycles = get_intel_cycles();
    #define END_INTEL_CYCLES   total_cycles = get_intel_cycles() - total_cycles;
    #define SHOW_INTEL_CYCLES  printf(" Cycles per byte = %6.2f", \
                               (float)total_cycles / (numBlocks*sizeof(plain)));
#elif defined(LINUX_CYCLE_COUNT)
    #include <linux/perf_event.h>
    #include <sys/syscall.h>
    #include <unistd.h>

    #define HAVE_GET_CYCLES
    static word64 begin_cycles;
    static word64 total_cycles;
    static int cycles = -1;
    static struct perf_event_attr atr;

    #define INIT_CYCLE_COUNTER do { \
        atr.type   = PERF_TYPE_HARDWARE; \
        atr.config = PERF_COUNT_HW_CPU_CYCLES; \
        cycles = syscall(__NR_perf_event_open, &atr, 0, -1, -1, 0); \
    } while (0);

    #define BEGIN_INTEL_CYCLES read(cycles, &begin_cycles, sizeof(begin_cycles));
    #define END_INTEL_CYCLES   do { \
        read(cycles, &total_cycles, sizeof(total_cycles)); \
        total_cycles = total_cycles - begin_cycles; \
    } while (0);

    #define SHOW_INTEL_CYCLES  printf(" Cycles per byte = %6.2f", \
                               (float)total_cycles / (numBlocks*sizeof(plain)));

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

#ifdef USE_WOLFSSL_MEMORY
    #include "wolfssl/wolfcrypt/mem_track.h"
#endif

void bench_des(void);
void bench_idea(void);
void bench_arc4(void);
void bench_hc128(void);
void bench_rabbit(void);
void bench_chacha(void);
void bench_chacha20_poly1305_aead(void);
void bench_aes(int);
void bench_aesgcm(void);
void bench_aesccm(void);
void bench_aesctr(void);
void bench_poly1305(void);
void bench_camellia(void);

void bench_md5(void);
void bench_sha(void);
void bench_sha256(void);
void bench_sha384(void);
void bench_sha512(void);
void bench_ripemd(void);
void bench_cmac(void);

void bench_rsa(void);
#ifdef WOLFSSL_ASYNC_CRYPT
    void bench_rsa_async(void);
#endif
void bench_rsaKeyGen(void);
void bench_dh(void);
#ifdef HAVE_ECC
void bench_eccKeyGen(void);
void bench_eccKeyAgree(void);
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
void bench_rng(void);

double current_time(int);


#if defined(DEBUG_WOLFSSL) && !defined(HAVE_VALGRIND)
    WOLFSSL_API int wolfSSL_Debugging_ON();
#endif

#if !defined(NO_RSA) || !defined(NO_DH) \
                        || defined(WOLFSSL_KEYGEN) || defined(HAVE_ECC) \
                        || defined(HAVE_CURVE25519) || defined(HAVE_ED25519)
    #define HAVE_LOCAL_RNG
    static WC_RNG rng;
#endif

/* use kB instead of mB for embedded benchmarking */
#ifdef BENCH_EMBEDDED
    static byte plain [1024];
#else
    static byte plain [1024*1024];
#endif


/* use kB instead of mB for embedded benchmarking */
#ifdef BENCH_EMBEDDED
    static byte cipher[1024];
#else
    static byte cipher[1024*1024];
#endif


static const XGEN_ALIGN byte key[] =
{
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    0xfe,0xde,0xba,0x98,0x76,0x54,0x32,0x10,
    0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67,
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
};

static const XGEN_ALIGN byte iv[] =
{
    0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef,
    0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
    0x11,0x21,0x31,0x41,0x51,0x61,0x71,0x81
};


/* so embedded projects can pull in tests on their own */
#if !defined(NO_MAIN_DRIVER)

int main(int argc, char** argv)

{
    (void)argc;
    (void)argv;
#else
int benchmark_test(void *args)
{
    (void)args;
#endif

#ifdef WOLFSSL_STATIC_MEMORY
    #ifdef BENCH_EMBEDDED
        byte memory[50000];
    #else
        byte memory[400000];
    #endif

    if (wc_LoadStaticMemory(&HEAP_HINT, memory, sizeof(memory),
                                                WOLFMEM_GENERAL, 1) != 0) {
        printf("unable to load static memory");
        exit(EXIT_FAILURE);
    }
#endif

#if defined(USE_WOLFSSL_MEMORY) && defined(WOLFSSL_TRACK_MEMORY)
    InitMemoryTracker();
#endif

    wolfCrypt_Init();
    INIT_CYCLE_COUNTER

#if defined(DEBUG_WOLFSSL) && !defined(HAVE_VALGRIND)
    wolfSSL_Debugging_ON();
#endif

    (void)plain;
    (void)cipher;
    (void)key;
    (void)iv;

#ifdef WOLFSSL_ASYNC_CRYPT
    if (wolfAsync_DevOpen(&devId) != 0) {
        printf("Async device open failed\n");
        exit(-1);
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

#ifdef HAVE_WNR
    if (wc_InitNetRandom(wnrConfigFile, NULL, 5000) != 0) {
        printf("Whitewood netRandom config init failed\n");
        exit(-1);
    }
#endif /* HAVE_WNR */

#if defined(HAVE_LOCAL_RNG)
    {
        int rngRet = wc_InitRng(&rng);
        if (rngRet < 0) {
            printf("InitRNG failed\n");
            return rngRet;
        }
    }
#endif

    bench_rng();
#ifndef NO_AES
#ifdef HAVE_AES_CBC
    bench_aes(0);
    bench_aes(1);
#endif
#ifdef HAVE_AESGCM
    bench_aesgcm();
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
    bench_arc4();
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
    bench_des();
#endif
#ifdef HAVE_IDEA
    bench_idea();
#endif

    printf("\n");

#ifndef NO_MD5
    bench_md5();
#endif
#ifdef HAVE_POLY1305
    bench_poly1305();
#endif
#ifndef NO_SHA
    bench_sha();
#endif
#ifndef NO_SHA256
    bench_sha256();
#endif
#ifdef WOLFSSL_SHA384
    bench_sha384();
#endif
#ifdef WOLFSSL_SHA512
    bench_sha512();
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

    printf("\n");

#ifndef NO_RSA
    bench_rsa();
    #ifdef WOLFSSL_ASYNC_CRYPT
        bench_rsa_async();
    #endif
    #ifdef WOLFSSL_KEY_GEN
        bench_rsaKeyGen();
    #endif
#endif

#ifndef NO_DH
    bench_dh();
#endif

#ifdef HAVE_NTRU
    bench_ntru();
    bench_ntruKeyGen();
#endif

#ifdef HAVE_ECC
    bench_eccKeyGen();
    bench_eccKeyAgree();
    #ifdef HAVE_ECC_ENCRYPT
        bench_eccEncrypt();
    #endif
    #if defined(FP_ECC)
        wc_ecc_fp_free();
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

#ifdef HAVE_WNR
    if (wc_FreeNetRandom() < 0) {
        printf("Failed to free netRandom context\n");
        exit(-1);
    }
#endif

#if defined(USE_WOLFSSL_MEMORY) && defined(WOLFSSL_TRACK_MEMORY)
    ShowMemoryTracker();
#endif

    return 0;
}


#ifdef BENCH_EMBEDDED
enum BenchmarkBounds {
    numBlocks  = 25, /* how many kB to test (en/de)cryption */
    ntimes     = 1,
    genTimes   = 5,  /* public key iterations */
    agreeTimes = 5
};
static const char blockType[] = "kB";   /* used in printf output */
#else
enum BenchmarkBounds {
    numBlocks  = 50,  /* how many megs to test (en/de)cryption */
#ifdef WOLFSSL_ASYNC_CRYPT
    ntimes     = 1000,
    genTimes   = 1000,
    agreeTimes = 1000
#else
    ntimes     = 100,
    genTimes   = 100,
    agreeTimes = 100
#endif
};
static const char blockType[] = "megs"; /* used in printf output */
#endif

void bench_rng(void)
{
    int    ret, i;
    double start, total, persec;
    int pos, len, remain;
#ifndef HAVE_LOCAL_RNG
    WC_RNG rng;
#endif

#ifndef HAVE_LOCAL_RNG
    ret = wc_InitRng(&rng);
    if (ret < 0) {
        printf("InitRNG failed\n");
        return;
    }
#endif

    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++) {
        /* Split request to handle large RNG request */
        pos = 0;
        remain = (int)sizeof(plain);
        while (remain > 0) {
            len = remain;
            if (len > RNG_MAX_BLOCK_LEN)
                len = RNG_MAX_BLOCK_LEN;
            ret = wc_RNG_GenerateBlock(&rng, &plain[pos], len);
            if (ret < 0) {
                printf("wc_RNG_GenerateBlock failed %d\n", ret);
                break;
            }
            remain -= len;
            pos += len;
        }
    }

    END_INTEL_CYCLES
    total = current_time(0) - start;

    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif
    printf("RNG      %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                                  blockType, total, persec);
    SHOW_INTEL_CYCLES
    printf("\n");

#ifndef HAVE_LOCAL_RNG
    wc_FreeRng(&rng);
#endif
}


#ifndef NO_AES

#ifdef HAVE_AES_CBC
void bench_aes(int show)
{
    Aes    enc;
    double start, total, persec;
    int    i;
    int    ret;

#ifdef WOLFSSL_ASYNC_CRYPT
    if ((ret = wc_AesAsyncInit(&enc, devId)) != 0) {
        printf("wc_AesAsyncInit failed, ret = %d\n", ret);
        return;
    }
#endif

    ret = wc_AesSetKey(&enc, key, 16, iv, AES_ENCRYPTION);
    if (ret != 0) {
        printf("AesSetKey failed, ret = %d\n", ret);
        return;
    }
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_AesCbcEncrypt(&enc, plain, cipher, sizeof(plain));

    END_INTEL_CYCLES
    total = current_time(0) - start;

    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    if (show) {
        printf("AES enc  %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                                  blockType, total, persec);
        SHOW_INTEL_CYCLES
        printf("\n");
    }
#ifdef WOLFSSL_ASYNC_CRYPT
    wc_AesAsyncFree(&enc);
    if ((ret = wc_AesAsyncInit(&enc, devId)) != 0) {
        printf("wc_AesAsyncInit failed, ret = %d\n", ret);
        return;
    }
#endif

    ret = wc_AesSetKey(&enc, key, 16, iv, AES_DECRYPTION);
    if (ret != 0) {
        printf("AesSetKey failed, ret = %d\n", ret);
        return;
    }
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_AesCbcDecrypt(&enc, plain, cipher, sizeof(plain));

    END_INTEL_CYCLES
    total = current_time(0) - start;

    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    if (show) {
        printf("AES dec  %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                                  blockType, total, persec);
        SHOW_INTEL_CYCLES
        printf("\n");
    }
#ifdef WOLFSSL_ASYNC_CRYPT
    wc_AesAsyncFree(&enc);
#endif
}
#endif /* HAVE_AES_CBC */

#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
    static byte additional[13];
    static byte tag[16];
#endif


#ifdef HAVE_AESGCM
void bench_aesgcm(void)
{
    Aes    enc;
    double start, total, persec;
    int    i;

    wc_AesGcmSetKey(&enc, key, 16);
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_AesGcmEncrypt(&enc, cipher, plain, sizeof(plain), iv, 12,
                        tag, 16, additional, 13);

    END_INTEL_CYCLES
    total = current_time(0) - start;

    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    printf("AES-GCM  %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    printf("\n");

#if 0
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_AesGcmDecrypt(&enc, plain, cipher, sizeof(cipher), iv, 12,
                        tag, 16, additional, 13);

    END_INTEL_CYCLES
    total = current_time(0) - start;

    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    printf("AES-GCM Decrypt %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    printf("\n");
#endif
}
#endif /* HAVE_AESGCM */


#ifdef WOLFSSL_AES_COUNTER
void bench_aesctr(void)
{
    Aes    enc;
    double start, total, persec;
    int    i;

    wc_AesSetKeyDirect(&enc, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_AesCtrEncrypt(&enc, plain, cipher, sizeof(plain));

    END_INTEL_CYCLES
    total = current_time(0) - start;

    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    printf("AES-CTR  %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    printf("\n");
}
#endif /* WOLFSSL_AES_COUNTER */


#ifdef HAVE_AESCCM
void bench_aesccm(void)
{
    Aes    enc;
    double start, total, persec;
    int    i;

    wc_AesCcmSetKey(&enc, key, 16);
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_AesCcmEncrypt(&enc, cipher, plain, sizeof(plain), iv, 12,
                        tag, 16, additional, 13);

    END_INTEL_CYCLES
    total = current_time(0) - start;

    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    printf("AES-CCM  %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    printf("\n");
}
#endif /* HAVE_AESCCM */
#endif /* !NO_AES */


#ifdef HAVE_POLY1305
void bench_poly1305()
{
    Poly1305    enc;
    byte   mac[16];
    double start, total, persec;
    int    i;
    int    ret;


    ret = wc_Poly1305SetKey(&enc, key, 32);
    if (ret != 0) {
        printf("Poly1305SetKey failed, ret = %d\n", ret);
        return;
    }
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_Poly1305Update(&enc, plain, sizeof(plain));

    wc_Poly1305Final(&enc, mac);
    END_INTEL_CYCLES
    total = current_time(0) - start;

    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    printf("POLY1305 %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                                  blockType, total, persec);
    SHOW_INTEL_CYCLES
    printf("\n");
}
#endif /* HAVE_POLY1305 */


#ifdef HAVE_CAMELLIA
void bench_camellia(void)
{
    Camellia cam;
    double start, total, persec;
    int    i, ret;

    ret = wc_CamelliaSetKey(&cam, key, 16, iv);
    if (ret != 0) {
        printf("CamelliaSetKey failed, ret = %d\n", ret);
        return;
    }
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_CamelliaCbcEncrypt(&cam, plain, cipher, sizeof(plain));

    END_INTEL_CYCLES
    total = current_time(0) - start;

    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    printf("Camellia %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    printf("\n");
}
#endif


#ifndef NO_DES3
void bench_des(void)
{
    Des3   enc;
    double start, total, persec;
    int    i, ret;

#ifdef WOLFSSL_ASYNC_CRYPT
    if (wc_Des3AsyncInit(&enc, devId) != 0)
        printf("des3 async init failed\n");
#endif
    ret = wc_Des3_SetKey(&enc, key, iv, DES_ENCRYPTION);
    if (ret != 0) {
        printf("Des3_SetKey failed, ret = %d\n", ret);
        return;
    }
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_Des3_CbcEncrypt(&enc, plain, cipher, sizeof(plain));

    END_INTEL_CYCLES
    total = current_time(0) - start;

    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    printf("3DES     %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    printf("\n");
#ifdef WOLFSSL_ASYNC_CRYPT
    wc_Des3AsyncFree(&enc);
#endif
}
#endif


#ifdef HAVE_IDEA
void bench_idea(void)
{
    Idea   enc;
    double start, total, persec;
    int    i, ret;

    ret = wc_IdeaSetKey(&enc, key, IDEA_KEY_SIZE, iv, IDEA_ENCRYPTION);
    if (ret != 0) {
        printf("Des3_SetKey failed, ret = %d\n", ret);
        return;
    }
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_IdeaCbcEncrypt(&enc, plain, cipher, sizeof(plain));

    END_INTEL_CYCLES
    total = current_time(0) - start;

    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    printf("IDEA     %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    printf("\n");
}
#endif /* HAVE_IDEA */


#ifndef NO_RC4
void bench_arc4(void)
{
    Arc4   enc;
    double start, total, persec;
    int    i;

#ifdef WOLFSSL_ASYNC_CRYPT
    if (wc_Arc4AsyncInit(&enc, devId) != 0)
        printf("arc4 async init failed\n");
#endif

    wc_Arc4SetKey(&enc, key, 16);
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_Arc4Process(&enc, cipher, plain, sizeof(plain));

    END_INTEL_CYCLES
    total = current_time(0) - start;
    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    printf("ARC4     %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    printf("\n");
#ifdef WOLFSSL_ASYNC_CRYPT
    wc_Arc4AsyncFree(&enc);
#endif
}
#endif


#ifdef HAVE_HC128
void bench_hc128(void)
{
    HC128  enc;
    double start, total, persec;
    int    i;

    wc_Hc128_SetKey(&enc, key, iv);
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_Hc128_Process(&enc, cipher, plain, sizeof(plain));

    END_INTEL_CYCLES
    total = current_time(0) - start;
    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    printf("HC128    %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    printf("\n");
}
#endif /* HAVE_HC128 */


#ifndef NO_RABBIT
void bench_rabbit(void)
{
    Rabbit  enc;
    double start, total, persec;
    int    i;

    wc_RabbitSetKey(&enc, key, iv);
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_RabbitProcess(&enc, cipher, plain, sizeof(plain));

    END_INTEL_CYCLES
    total = current_time(0) - start;
    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    printf("RABBIT   %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    printf("\n");
}
#endif /* NO_RABBIT */


#ifdef HAVE_CHACHA
void bench_chacha(void)
{
    ChaCha enc;
    double start, total, persec;
    int    i;

    wc_Chacha_SetKey(&enc, key, 16);
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for (i = 0; i < numBlocks; i++) {
        wc_Chacha_SetIV(&enc, iv, 0);
        wc_Chacha_Process(&enc, cipher, plain, sizeof(plain));
    }

    END_INTEL_CYCLES
    total = current_time(0) - start;
    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    printf("CHACHA   %d %s took %5.3f seconds, %8.3f MB/s", numBlocks, blockType, total, persec);
    SHOW_INTEL_CYCLES
    printf("\n");

}
#endif /* HAVE_CHACHA*/

#if( defined( HAVE_CHACHA ) && defined( HAVE_POLY1305 ) )
void bench_chacha20_poly1305_aead(void)
{
    double start, total, persec;
    int    i;

    byte authTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    XMEMSET( authTag, 0, sizeof( authTag ) );

    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for (i = 0; i < numBlocks; i++)
    {
        wc_ChaCha20Poly1305_Encrypt(key, iv, NULL, 0, plain, sizeof(plain),
                                    cipher, authTag );
    }

    END_INTEL_CYCLES
    total = current_time(0) - start;
    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    printf("CHA-POLY %d %s took %5.3f seconds, %8.3f MB/s",
           numBlocks, blockType, total, persec);
    SHOW_INTEL_CYCLES
    printf("\n");

}
#endif /* HAVE_CHACHA && HAVE_POLY1305 */


#ifndef NO_MD5
void bench_md5(void)
{
    Md5    hash;
    byte   digest[MD5_DIGEST_SIZE];
    double start, total, persec;
    int    i;

    wc_InitMd5(&hash);
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_Md5Update(&hash, plain, sizeof(plain));

    wc_Md5Final(&hash, digest);

    END_INTEL_CYCLES
    total = current_time(0) - start;
    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    printf("MD5      %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    printf("\n");
}
#endif /* NO_MD5 */


#ifndef NO_SHA
void bench_sha(void)
{
    Sha    hash;
    byte   digest[SHA_DIGEST_SIZE];
    double start, total, persec;
    int    i, ret;

    ret = wc_InitSha(&hash);
    if (ret != 0) {
        printf("InitSha failed, ret = %d\n", ret);
        return;
    }
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_ShaUpdate(&hash, plain, sizeof(plain));

    wc_ShaFinal(&hash, digest);

    END_INTEL_CYCLES
    total = current_time(0) - start;
    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    printf("SHA      %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    printf("\n");
}
#endif /* NO_SHA */


#ifndef NO_SHA256
void bench_sha256(void)
{
    Sha256 hash;
    byte   digest[SHA256_DIGEST_SIZE];
    double start, total, persec;
    int    i, ret;

    ret = wc_InitSha256(&hash);
    if (ret != 0) {
        printf("InitSha256 failed, ret = %d\n", ret);
        return;
    }
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++) {
        ret = wc_Sha256Update(&hash, plain, sizeof(plain));
        if (ret != 0) {
            printf("Sha256Update failed, ret = %d\n", ret);
            return;
        }
    }

    ret = wc_Sha256Final(&hash, digest);
    if (ret != 0) {
        printf("Sha256Final failed, ret = %d\n", ret);
        return;
    }

    END_INTEL_CYCLES
    total = current_time(0) - start;
    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    printf("SHA-256  %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    printf("\n");
}
#endif

#ifdef WOLFSSL_SHA384
void bench_sha384(void)
{
    Sha384 hash;
    byte   digest[SHA384_DIGEST_SIZE];
    double start, total, persec;
    int    i, ret;

    ret = wc_InitSha384(&hash);
    if (ret != 0) {
        printf("InitSha384 failed, ret = %d\n", ret);
        return;
    }
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++) {
        ret = wc_Sha384Update(&hash, plain, sizeof(plain));
        if (ret != 0) {
            printf("Sha384Update failed, ret = %d\n", ret);
            return;
        }
    }

    ret = wc_Sha384Final(&hash, digest);
    if (ret != 0) {
        printf("Sha384Final failed, ret = %d\n", ret);
        return;
    }

    END_INTEL_CYCLES
    total = current_time(0) - start;
    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    printf("SHA-384  %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    printf("\n");
}
#endif

#ifdef WOLFSSL_SHA512
void bench_sha512(void)
{
    Sha512 hash;
    byte   digest[SHA512_DIGEST_SIZE];
    double start, total, persec;
    int    i, ret;

    ret = wc_InitSha512(&hash);
    if (ret != 0) {
        printf("InitSha512 failed, ret = %d\n", ret);
        return;
    }
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++) {
        ret = wc_Sha512Update(&hash, plain, sizeof(plain));
        if (ret != 0) {
            printf("Sha512Update failed, ret = %d\n", ret);
            return;
        }
    }

    ret = wc_Sha512Final(&hash, digest);
    if (ret != 0) {
        printf("Sha512Final failed, ret = %d\n", ret);
        return;
    }

    END_INTEL_CYCLES
    total = current_time(0) - start;
    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    printf("SHA-512  %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    printf("\n");
}
#endif

#ifdef WOLFSSL_RIPEMD
void bench_ripemd(void)
{
    RipeMd hash;
    byte   digest[RIPEMD_DIGEST_SIZE];
    double start, total, persec;
    int    i;

    wc_InitRipeMd(&hash);
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++)
        wc_RipeMdUpdate(&hash, plain, sizeof(plain));

    wc_RipeMdFinal(&hash, digest);

    END_INTEL_CYCLES
    total = current_time(0) - start;
    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    printf("RIPEMD   %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    printf("\n");
}
#endif


#ifdef HAVE_BLAKE2
void bench_blake2(void)
{
    Blake2b b2b;
    byte    digest[64];
    double  start, total, persec;
    int     i, ret;

    ret = wc_InitBlake2b(&b2b, 64);
    if (ret != 0) {
        printf("InitBlake2b failed, ret = %d\n", ret);
        return;
    }
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++) {
        ret = wc_Blake2bUpdate(&b2b, plain, sizeof(plain));
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

    END_INTEL_CYCLES
    total = current_time(0) - start;
    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    printf("BLAKE2b  %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    printf("\n");
}
#endif


#ifdef WOLFSSL_CMAC

void bench_cmac(void)
{
    Cmac    cmac;
    byte    digest[AES_BLOCK_SIZE];
    word32  digestSz = sizeof(digest);
    double  start, total, persec;
    int     i, ret;

    ret = wc_InitCmac(&cmac, key, 16, WC_CMAC_AES, NULL);
    if (ret != 0) {
        printf("InitCmac failed, ret = %d\n", ret);
        return;
    }
    start = current_time(1);
    BEGIN_INTEL_CYCLES

    for(i = 0; i < numBlocks; i++) {
        ret = wc_CmacUpdate(&cmac, plain, sizeof(plain));
        if (ret != 0) {
            printf("CmacUpdate failed, ret = %d\n", ret);
            return;
        }
    }

    ret = wc_CmacFinal(&cmac, digest, &digestSz);
    if (ret != 0) {
        printf("CmacFinal failed, ret = %d\n", ret);
        return;
    }

    END_INTEL_CYCLES
    total = current_time(0) - start;
    persec = 1 / total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    persec = persec / 1024;
#endif

    printf("AES-CMAC %d %s took %5.3f seconds, %8.3f MB/s", numBlocks,
                                              blockType, total, persec);
    SHOW_INTEL_CYCLES
    printf("\n");
}

#endif /* WOLFSSL_CMAC */


#ifndef NO_RSA


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

void bench_rsa(void)
{
    int    i;
    int    ret;
    size_t bytes;
    word32 idx = 0;
    const byte* tmp;

    const byte message[] = "Everyone gets Friday off.";
    byte      enc[256];  /* for up to 2048 bit */
    const int len = (int)strlen((char*)message);
    double    start, total, each, milliEach;

    RsaKey rsaKey;
    int    rsaKeySz = 2048; /* used in printf */

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

    if ((ret = wc_InitRsaKey(&rsaKey, HEAP_HINT)) < 0) {
        printf("InitRsaKey failed! %d\n", ret);
        return;
    }

    /* decode the private key */
    ret = wc_RsaPrivateKeyDecode(tmp, &idx, &rsaKey, (word32)bytes);

    start = current_time(1);

    for (i = 0; i < ntimes; i++) {
        ret = wc_RsaPublicEncrypt(message, len, enc, sizeof(enc),
                                                        &rsaKey, &rng);
        if (ret < 0) {
            break;
        }
    } /* for ntimes */

    total = current_time(0) - start;
    each  = total / ntimes;   /* per second   */
    milliEach = each * 1000; /* milliseconds */

    printf("RSA %d public          %6.3f milliseconds, avg over %d"
           " iterations\n", rsaKeySz, milliEach, ntimes);

    if (ret < 0) {
        printf("Rsa Public Encrypt failed! %d\n", ret);
        return;
    }

#ifdef WC_RSA_BLINDING
    wc_RsaSetRNG(&rsaKey, &rng);
#endif
    start = current_time(1);

    /* capture resulting encrypt length */
    idx = ret;

    for (i = 0; i < ntimes; i++) {
        byte  out[256];  /* for up to 2048 bit */

        ret = wc_RsaPrivateDecrypt(enc, idx, out, sizeof(out), &rsaKey);
        if (ret < 0 && ret != WC_PENDING_E) {
            break;
        }
    } /* for ntimes */

    total = current_time(0) - start;
    each  = total / ntimes;   /* per second   */
    milliEach = each * 1000; /* milliseconds */

    printf("RSA %d private         %6.3f milliseconds, avg over %d"
           " iterations\n", rsaKeySz, milliEach, ntimes);

    wc_FreeRsaKey(&rsaKey);
}


#ifdef WOLFSSL_ASYNC_CRYPT
void bench_rsa_async(void)
{
    int    i;
    int    ret;
    size_t bytes;
    word32 idx = 0;
    const byte* tmp;

    const byte message[] = "Everyone gets Friday off.";
    byte      enc[256];  /* for up to 2048 bit */
    const int len = (int)strlen((char*)message);
    double    start, total, each, milliEach;

    RsaKey rsaKey[WOLF_ASYNC_MAX_PENDING];
    int    rsaKeySz = 2048; /* used in printf */

    WOLF_EVENT events[WOLF_ASYNC_MAX_PENDING];
    WOLF_EVENT_QUEUE eventQueue;
    int evtNum, asyncDone, asyncPend;

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

    /* init event queue */
    ret = wolfEventQueue_Init(&eventQueue);
    if (ret != 0) {
        return;
    }

    /* clear for done cleanup */
    XMEMSET(&events, 0, sizeof(events));
    XMEMSET(&rsaKey, 0, sizeof(rsaKey));

    /* init events and keys */
    for (i = 0; i < WOLF_ASYNC_MAX_PENDING; i++) {
        /* setup an async context for each key */
        if ((ret = wc_InitRsaKey_ex(&rsaKey[i], HEAP_HINT, devId)) < 0) {
            goto done;
        }
    #ifdef WC_RSA_BLINDING
        wc_RsaSetRNG(&rsaKey[i], &rng);
    #endif
        if ((ret = wolfAsync_EventInit(&events[i],
                WOLF_EVENT_TYPE_ASYNC_WOLFCRYPT, &rsaKey[i].asyncDev)) != 0) {
            goto done;
        }
        events[i].pending = 0; /* Reset pending flag */

        /* decode the private key */
        idx = 0;
        if ((ret = wc_RsaPrivateKeyDecode(tmp, &idx, &rsaKey[i],
                                                        (word32)bytes)) != 0) {
            printf("wc_RsaPrivateKeyDecode failed! %d\n", ret);
            goto done;
        }
    }

    /* begin public async RSA */
    start = current_time(1);

    asyncPend = 0;
    for (i = 0; i < ntimes; ) {

        /* while free pending slots in queue, submit RSA operations */
        for (evtNum = 0; evtNum < WOLF_ASYNC_MAX_PENDING; evtNum++) {
            if (events[evtNum].done || (events[evtNum].pending == 0 &&
                                                    (i + asyncPend) < ntimes))
            {
                /* check for event error */
                if (events[evtNum].ret != WC_PENDING_E && events[evtNum].ret < 0) {
                    printf("wc_RsaPublicEncrypt: Async event error: %d\n", events[evtNum].ret);
                    goto done;
                }

                ret = wc_RsaPublicEncrypt(message, len, enc, sizeof(enc),
                                                        &rsaKey[evtNum], &rng);
                if (ret == WC_PENDING_E) {
                    ret = wc_RsaAsyncHandle(&rsaKey[evtNum], &eventQueue,
                                                            &events[evtNum]);
                    if (ret != 0) goto done;
                    asyncPend++;
                }
                else if (ret >= 0) {
                    /* operation completed */
                    i++;
                    asyncPend--;
                    events[evtNum].done = 0;
                }
                else {
                    printf("wc_RsaPublicEncrypt failed: %d\n", ret);
                    goto done;
                }
            }
        } /* for evtNum */

        /* poll until there are events done */
        if (asyncPend > 0) {
            do {
                ret = wolfAsync_EventQueuePoll(&eventQueue, NULL, NULL, 0,
                                        WOLF_POLL_FLAG_CHECK_HW, &asyncDone);
                if (ret != 0) goto done;
            } while (asyncDone == 0);
        }
    } /* for ntimes */

    total = current_time(0) - start;
    each  = total / ntimes;   /* per second   */
    milliEach = each * 1000; /* milliseconds */

    printf("RSA %d public async    %6.3f milliseconds, avg over %d"
           " iterations\n", rsaKeySz, milliEach, ntimes);

    if (ret < 0) {
        goto done;
    }


    /* begin private async RSA */
    start = current_time(1);

    /* capture resulting encrypt length */
    idx = sizeof(enc); /* fixed at 2048 bit */

    asyncPend = 0;
    for (i = 0; i < ntimes; ) {
        byte  out[256];  /* for up to 2048 bit */

        /* while free pending slots in queue, submit RSA operations */
        for (evtNum = 0; evtNum < WOLF_ASYNC_MAX_PENDING; evtNum++) {
            if (events[evtNum].done || (events[evtNum].pending == 0 &&
                                                    (i + asyncPend) < ntimes))
            {
                /* check for event error */
                if (events[evtNum].ret != WC_PENDING_E && events[evtNum].ret < 0) {
                    printf("wc_RsaPrivateDecrypt: Async event error: %d\n", events[evtNum].ret);
                    goto done;
                }

                ret = wc_RsaPrivateDecrypt(enc, idx, out, sizeof(out),
                                                            &rsaKey[evtNum]);
                if (ret == WC_PENDING_E) {
                    ret = wc_RsaAsyncHandle(&rsaKey[evtNum], &eventQueue,
                                                            &events[evtNum]);
                    if (ret != 0) goto done;
                    asyncPend++;
                }
                else if (ret >= 0) {
                    /* operation completed */
                    i++;
                    asyncPend--;
                    events[evtNum].done = 0;
                }
                else {
                    printf("wc_RsaPrivateDecrypt failed: %d\n", ret);
                    goto done;
                }
            }
        } /* for evtNum */

        /* poll until there are events done */
        if (asyncPend > 0) {
            do {
                ret = wolfAsync_EventQueuePoll(&eventQueue, NULL, NULL, 0,
                                        WOLF_POLL_FLAG_CHECK_HW, &asyncDone);
                if (ret != 0) goto done;
            } while (asyncDone == 0);
        }
    } /* for ntimes */

    total = current_time(0) - start;
    each  = total / ntimes;   /* per second   */
    milliEach = each * 1000; /* milliseconds */

    printf("RSA %d private async   %6.3f milliseconds, avg over %d"
           " iterations\n", rsaKeySz, milliEach, ntimes);

done:

    if (ret < 0) {
        printf("bench_rsa_async failed: %d\n", ret);
    }

    /* cleanup */
    for (i = 0; i < WOLF_ASYNC_MAX_PENDING; i++) {
        wc_FreeRsaKey(&rsaKey[i]);
    }

    /* free event queue */
    wolfEventQueue_Free(&eventQueue);
}
#endif /* WOLFSSL_ASYNC_CRYPT */

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

void bench_dh(void)
{
    int    i ;
    size_t bytes;
    word32 idx = 0, pubSz, privSz = 0, pubSz2, privSz2, agreeSz;
    const byte* tmp = NULL;

    byte   pub[256];    /* for 2048 bit */
    byte   pub2[256];   /* for 2048 bit */
    byte   agree[256];  /* for 2048 bit */
    byte   priv[32];    /* for 2048 bit */
    byte   priv2[32];   /* for 2048 bit */

    double start, total, each, milliEach;
    DhKey  dhKey;
    int    dhKeySz = 2048; /* used in printf */

    (void)idx;
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


    wc_InitDhKey(&dhKey);
#ifdef NO_ASN
    bytes = wc_DhSetKey(&dhKey, dh_p, sizeof(dh_p), dh_g, sizeof(dh_g));
#else
    bytes = wc_DhKeyDecode(tmp, &idx, &dhKey, (word32)bytes);
#endif
    if (bytes != 0) {
        printf("dhekydecode failed, can't benchmark\n");
        return;
    }

    start = current_time(1);

    for (i = 0; i < ntimes; i++)
        wc_DhGenerateKeyPair(&dhKey, &rng, priv, &privSz, pub, &pubSz);

    total = current_time(0) - start;
    each  = total / ntimes;   /* per second   */
    milliEach = each * 1000; /* milliseconds */

    printf("DH  %d key generation  %6.3f milliseconds, avg over %d"
           " iterations\n", dhKeySz, milliEach, ntimes);

    wc_DhGenerateKeyPair(&dhKey, &rng, priv2, &privSz2, pub2, &pubSz2);
    start = current_time(1);

    for (i = 0; i < ntimes; i++)
        wc_DhAgree(&dhKey, agree, &agreeSz, priv, privSz, pub2, pubSz2);

    total = current_time(0) - start;
    each  = total / ntimes;   /* per second   */
    milliEach = each * 1000; /* milliseconds */

    printf("DH  %d key agreement   %6.3f milliseconds, avg over %d"
           " iterations\n", dhKeySz, milliEach, ntimes);

    wc_FreeDhKey(&dhKey);
}
#endif

#if defined(WOLFSSL_KEY_GEN) && !defined(NO_RSA)
void bench_rsaKeyGen(void)
{
    RsaKey genKey;
    double start, total, each, milliEach;
    int    i;

    /* 1024 bit */
    start = current_time(1);

    for(i = 0; i < genTimes; i++) {
        wc_InitRsaKey(&genKey, HEAP_HINT);
        wc_MakeRsaKey(&genKey, 1024, 65537, &rng);
        wc_FreeRsaKey(&genKey);
    }

    total = current_time(0) - start;
    each  = total / genTimes;  /* per second  */
    milliEach = each * 1000;   /* milliseconds */
    printf("\n");
    printf("RSA 1024 key generation  %6.3f milliseconds, avg over %d"
           " iterations\n", milliEach, genTimes);

    /* 2048 bit */
    start = current_time(1);

    for(i = 0; i < genTimes; i++) {
        wc_InitRsaKey(&genKey, HEAP_HINT);
        wc_MakeRsaKey(&genKey, 2048, 65537, &rng);
        wc_FreeRsaKey(&genKey);
    }

    total = current_time(0) - start;
    each  = total / genTimes;  /* per second  */
    milliEach = each * 1000;   /* milliseconds */
    printf("RSA 2048 key generation  %6.3f milliseconds, avg over %d"
           " iterations\n", milliEach, genTimes);
}
#endif /* WOLFSSL_KEY_GEN */
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
    double start, total, each, milliEach;

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

    printf("\n");
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
        start = current_time(1);

        for (i = 0; i < ntimes; i++) {
            ret = ntru_crypto_ntru_encrypt(drbg, public_key_len, public_key,
                    sizeof(aes_key), aes_key, &ciphertext_len, ciphertext);
            if (ret != NTRU_OK) {
                printf("NTRU encrypt error\n");
                return;
            }
        }
        ret = ntru_crypto_drbg_uninstantiate(drbg);

        if (ret != DRBG_OK) {
            printf("NTRU error occurred uninstantiating the DRBG\n");
            return;
        }

        total = current_time(0) - start;
        each  = total / ntimes;   /* per second   */
        milliEach = each * 1000; /* milliseconds */

        printf("NTRU %d encryption took %6.3f milliseconds, avg over %d"
           " iterations\n", ntruBits, milliEach, ntimes);


        ret = ntru_crypto_ntru_decrypt(private_key_len, private_key,
                ciphertext_len, ciphertext, &plaintext_len, NULL);

        if (ret != NTRU_OK) {
            printf("NTRU decrypt error occurred getting the buffer size needed\n");
            return;
        }

        plaintext_len = sizeof(plaintext);
        start = current_time(1);

        for (i = 0; i < ntimes; i++) {
            ret = ntru_crypto_ntru_decrypt(private_key_len, private_key,
                                      ciphertext_len, ciphertext,
                                      &plaintext_len, plaintext);

            if (ret != NTRU_OK) {
                printf("NTRU error occurred decrypting the key\n");
                return;
            }
        }

        total = current_time(0) - start;
        each  = total / ntimes;   /* per second   */
        milliEach = each * 1000; /* milliseconds */

        printf("NTRU %d decryption took %6.3f milliseconds, avg over %d"
           " iterations\n", ntruBits, milliEach, ntimes);
    }

}

void bench_ntruKeyGen(void)
{
    double start, total, each, milliEach;
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
        start = current_time(1);

        for(i = 0; i < genTimes; i++) {
            ret = ntru_crypto_ntru_encrypt_keygen(drbg, type, &public_key_len,
                                         public_key, &private_key_len,
                                         private_key);
        }

        total = current_time(0) - start;

        if (ret != NTRU_OK) {
            printf("keygen failed\n");
            return;
        }

        ret = ntru_crypto_drbg_uninstantiate(drbg);

        if (ret != NTRU_OK) {
            printf("NTRU drbg uninstantiate failed\n");
            return;
        }

        each = total / genTimes;
        milliEach = each * 1000;

        printf("NTRU %d key generation  %6.3f milliseconds, avg over %d"
            " iterations\n", ntruBits, milliEach, genTimes);
    }
}
#endif

#ifdef HAVE_ECC
void bench_eccKeyGen(void)
{
    ecc_key genKey;
    double start, total, each, milliEach;
    int    i;

    /* 256 bit */
    start = current_time(1);

    for(i = 0; i < genTimes; i++) {
        wc_ecc_init_ex(&genKey, HEAP_HINT, devId);
        wc_ecc_make_key(&rng, 32, &genKey);
        wc_ecc_free(&genKey);
    }

    total = current_time(0) - start;
    each  = total / genTimes;  /* per second  */
    milliEach = each * 1000;   /* milliseconds */
    printf("\n");
    printf("ECC  256 key generation  %6.3f milliseconds, avg over %d"
           " iterations\n", milliEach, genTimes);
}


void bench_eccKeyAgree(void)
{
    ecc_key genKey, genKey2;
    double start, total, each, milliEach;
    int    i, ret;
    byte   shared[32];
#if !defined(NO_ASN) && !defined(NO_ECC_SIGN)
    byte   sig[64+16];  /* der encoding too */
#endif
    byte   digest[32];
    word32 x = 0;

    wc_ecc_init_ex(&genKey, HEAP_HINT, devId);
    wc_ecc_init_ex(&genKey2, HEAP_HINT, devId);

    ret = wc_ecc_make_key(&rng, 32, &genKey);
    if (ret != 0) {
        printf("ecc_make_key failed\n");
        return;
    }
    ret = wc_ecc_make_key(&rng, 32, &genKey2);
    if (ret != 0) {
        printf("ecc_make_key failed\n");
        return;
    }

    /* 256 bit */
    start = current_time(1);

    for(i = 0; i < agreeTimes; i++) {
        x = sizeof(shared);
        ret = wc_ecc_shared_secret(&genKey, &genKey2, shared, &x);
        if (ret != 0) {
            printf("ecc_shared_secret failed\n");
            return;
        }
    }

    total = current_time(0) - start;
    each  = total / agreeTimes;  /* per second  */
    milliEach = each * 1000;   /* milliseconds */
    printf("EC-DHE   key agreement   %6.3f milliseconds, avg over %d"
           " iterations\n", milliEach, agreeTimes);

    /* make dummy digest */
    for (i = 0; i < (int)sizeof(digest); i++)
        digest[i] = (byte)i;


#if !defined(NO_ASN) && !defined(NO_ECC_SIGN)
    start = current_time(1);

    for(i = 0; i < agreeTimes; i++) {
        x = sizeof(sig);
        ret = wc_ecc_sign_hash(digest, sizeof(digest), sig, &x, &rng, &genKey);
        if (ret != 0) {
            printf("ecc_sign_hash failed\n");
            return;
        }
    }

    total = current_time(0) - start;
    each  = total / agreeTimes;  /* per second  */
    milliEach = each * 1000;   /* milliseconds */
    printf("EC-DSA   sign   time     %6.3f milliseconds, avg over %d"
           " iterations\n", milliEach, agreeTimes);

    start = current_time(1);

    for(i = 0; i < agreeTimes; i++) {
        int verify = 0;
        ret = wc_ecc_verify_hash(sig, x, digest, sizeof(digest), &verify, &genKey);
        if (ret != 0) {
            printf("ecc_verify_hash failed\n");
            return;
        }
    }
#endif

    total = current_time(0) - start;
    each  = total / agreeTimes;  /* per second  */
    milliEach = each * 1000;     /* milliseconds */
    printf("EC-DSA   verify time     %6.3f milliseconds, avg over %d"
           " iterations\n", milliEach, agreeTimes);

    wc_ecc_free(&genKey2);
    wc_ecc_free(&genKey);
}
#ifdef HAVE_ECC_ENCRYPT
void bench_eccEncrypt(void)
{
    ecc_key userA, userB;
    byte    msg[48];
    byte    out[80];
    word32  outSz   = sizeof(out);
    word32  plainSz = sizeof(plain);
    int     ret, i;
    double start, total, each, milliEach;

    wc_ecc_init_ex(&userA, HEAP_HINT, devId);
    wc_ecc_init_ex(&userB, HEAP_HINT, devId);

    wc_ecc_make_key(&rng, 32, &userA);
    wc_ecc_make_key(&rng, 32, &userB);

    for (i = 0; i < (int)sizeof(msg); i++)
        msg[i] = i;

    start = current_time(1);

    for(i = 0; i < ntimes; i++) {
        /* encrypt msg to B */
        ret = wc_ecc_encrypt(&userA, &userB, msg, sizeof(msg), out, &outSz, NULL);
        if (ret != 0) {
            printf("wc_ecc_encrypt failed! %d\n", ret);
            return;
        }
    }

    total = current_time(0) - start;
    each  = total / ntimes;  /* per second  */
    milliEach = each * 1000;   /* milliseconds */
    printf("ECC      encrypt         %6.3f milliseconds, avg over %d"
           " iterations\n", milliEach, ntimes);

    start = current_time(1);

    for(i = 0; i < ntimes; i++) {
        /* decrypt msg from A */
        ret = wc_ecc_decrypt(&userB, &userA, out, outSz, plain, &plainSz, NULL);
        if (ret != 0) {
            printf("wc_ecc_decrypt failed! %d\n", ret);
            return;
        }
    }

    total = current_time(0) - start;
    each  = total / ntimes;  /* per second  */
    milliEach = each * 1000;   /* milliseconds */
    printf("ECC      decrypt         %6.3f milliseconds, avg over %d"
           " iterations\n", milliEach, ntimes);

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
    double start, total, each, milliEach;
    int    i;

    /* 256 bit */
    start = current_time(1);

    for(i = 0; i < genTimes; i++) {
        wc_curve25519_make_key(&rng, 32, &genKey);
        wc_curve25519_free(&genKey);
    }

    total = current_time(0) - start;
    each  = total / genTimes;  /* per second  */
    milliEach = each * 1000;   /* milliseconds */
    printf("\n");
    printf("CURVE25519 256 key generation %6.3f milliseconds, avg over %d"
           " iterations\n", milliEach, genTimes);
}

#ifdef HAVE_CURVE25519_SHARED_SECRET
void bench_curve25519KeyAgree(void)
{
    curve25519_key genKey, genKey2;
    double start, total, each, milliEach;
    int    i, ret;
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
        printf("curve25519_make_key failed\n");
        return;
    }

    /* 256 bit */
    start = current_time(1);

    for(i = 0; i < agreeTimes; i++) {
        x = sizeof(shared);
        ret = wc_curve25519_shared_secret(&genKey, &genKey2, shared, &x);
        if (ret != 0) {
            printf("curve25519_shared_secret failed\n");
            return;
        }
    }

    total = current_time(0) - start;
    each  = total / agreeTimes;  /* per second  */
    milliEach = each * 1000;   /* milliseconds */
    printf("CURVE25519 key agreement      %6.3f milliseconds, avg over %d"
           " iterations\n", milliEach, agreeTimes);

    wc_curve25519_free(&genKey2);
    wc_curve25519_free(&genKey);
}
#endif /* HAVE_CURVE25519_SHARED_SECRET */
#endif /* HAVE_CURVE25519 */

#ifdef HAVE_ED25519
void bench_ed25519KeyGen(void)
{
    ed25519_key genKey;
    double start, total, each, milliEach;
    int    i;

    /* 256 bit */
    start = current_time(1);

    for(i = 0; i < genTimes; i++) {
        wc_ed25519_init(&genKey);
        wc_ed25519_make_key(&rng, 32, &genKey);
        wc_ed25519_free(&genKey);
    }

    total = current_time(0) - start;
    each  = total / genTimes;  /* per second  */
    milliEach = each * 1000;   /* milliseconds */
    printf("\n");
    printf("ED25519  key generation  %6.3f milliseconds, avg over %d"
           " iterations\n", milliEach, genTimes);
}


void bench_ed25519KeySign(void)
{
    int    ret;
    ed25519_key genKey;
#ifdef HAVE_ED25519_SIGN
    double start, total, each, milliEach;
    int    i;
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

    start = current_time(1);

    for(i = 0; i < agreeTimes; i++) {
        x = sizeof(sig);
        ret = wc_ed25519_sign_msg(msg, sizeof(msg), sig, &x, &genKey);
        if (ret != 0) {
            printf("ed25519_sign_msg failed\n");
            return;
        }
    }

    total = current_time(0) - start;
    each  = total / agreeTimes;  /* per second  */
    milliEach = each * 1000;   /* milliseconds */
    printf("ED25519  sign   time     %6.3f milliseconds, avg over %d"
           " iterations\n", milliEach, agreeTimes);

#ifdef HAVE_ED25519_VERIFY
    start = current_time(1);

    for(i = 0; i < agreeTimes; i++) {
        int verify = 0;
        ret = wc_ed25519_verify_msg(sig, x, msg, sizeof(msg), &verify,
                                    &genKey);
        if (ret != 0 || verify != 1) {
            printf("ed25519_verify_msg failed\n");
            return;
        }
    }

    total = current_time(0) - start;
    each  = total / agreeTimes;  /* per second  */
    milliEach = each * 1000;     /* milliseconds */
    printf("ED25519  verify time     %6.3f milliseconds, avg over %d"
           " iterations\n", milliEach, agreeTimes);
#endif /* HAVE_ED25519_VERIFY */
#endif /* HAVE_ED25519_SIGN */

    wc_ed25519_free(&genKey);
}
#endif /* HAVE_ED25519 */


#ifdef _WIN32

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

#elif defined(WOLFSSL_IAR_ARM_TIME) || defined (WOLFSSL_MDK_ARM) || defined(WOLFSSL_USER_CURRTIME)
    extern   double current_time(int reset);

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

#ifdef HAVE_GET_CYCLES

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
#else
    #ifndef NO_MAIN_DRIVER
        int main() { return 0; }
    #endif
#endif /* !NO_CRYPT_BENCHMARK */
