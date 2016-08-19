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
#endif /* HAVE_CONFIG_H */

#include <wolfssl/wolfcrypt/settings.h>
#define UNEXPLAINED_ERROR printf("AN UNEXPLAINED ERROR HAS OCCURRED.\n ");


/* Macro to disable benchmark */
#ifndef NO_CRYPT_BENCHMARK



#ifdef FREESCALE_MQX
#include <mqx.h>
#if MQX_USE_IO_OLD
#include <fio.h>
#else
#include <nio.h>
#endif /* MQX_USE_IO_OLD */
#else
#include <stdio.h>
#endif /* FREESCALE_MQX */

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif /* HAVE_SIGNAL_H */

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
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef HAVE_ECC
#include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifdef HAVE_IDEA
#include <wolfssl/wolfcrypt/idea.h>
#endif
#ifdef HAVE_CURVE25519
#include <wolfssl/wolfcrypt/curve25519.h>
#endif /* HAVE_CURVE25519 */
#ifdef HAVE_ED25519
#include <wolfssl/wolfcrypt/ed25519.h>
#endif /* HAVE_ED25519 */

#include <wolfssl/wolfcrypt/dh.h>
#ifdef HAVE_CAVIUM
#include "cavium_sysdep.h"
#include "cavium_common.h"
#include "cavium_ioctl.h"
#endif /* HAVE_CAVIUM */
#ifdef HAVE_NTRU
#include "libntruencrypt/ntru_crypto.h"
#endif /* HAVE_NTRU */
#include <wolfssl/wolfcrypt/random.h>

#ifdef HAVE_WNR
const char* wnrConfigFile = "wnr-example.conf";
#endif /* HAVE_WNR */

#if defined(WOLFSSL_MDK_ARM)
extern FILE * wolfSSL_fopen(const char *fname, const char *mode) ;
#define fopen wolfSSL_fopen
#endif

#if defined(__GNUC__) && defined(__x86_64__) && !defined(NO_ASM)
#define HAVE_GET_CYCLES
static INLINE word64 get_intel_cycles(void);
#define BEGIN_INTEL_CYCLES result->cycles = get_intel_cycles();
#define END_INTEL_CYCLES   result->cycles = get_intel_cycles() - result->cycles;
#define SHOW_INTEL_CYCLES  printf(" Cycles per byte = %6.2f", \
        (float)result->cycles / (numBlocks*sizeof(plain)));
#else
#define BEGIN_INTEL_CYCLES
#define END_INTEL_CYCLES
#define SHOW_INTEL_CYCLES
#endif /* defined(__GNUC__) && defined(__x86_64__) && !defined(NO_ASM) */

/* let's use buffers, we have them */
#if !defined(USE_CERT_BUFFERS_1024) && !defined(USE_CERT_BUFFERS_2048)
#define USE_CERT_BUFFERS_2048
#endif

#if defined(USE_CERT_BUFFERS_1024) || defined(USE_CERT_BUFFERS_2048) \
    || !defined(NO_DH)
/* include test cert and key buffers for use with NO_FILESYSTEM */
#include <wolfssl/certs_test.h>
#endif /* defined(USE_CERT_BUFFERS_1024) || defined(USE_CERT_BUFFERS_2048) */


#include "benchmark.h"

#ifdef HAVE_BLAKE2
#include <wolfssl/wolfcrypt/blake2.h>
int bench_blake2(benchResult*, output_cb);
#endif /* HAVE_BLAKE2 */

#ifdef _MSC_VER
/* 4996 warning to use MS extensions e.g., strcpy_s instead of strncpy */
#pragma warning(disable: 4996)
#endif


#ifdef USE_WOLFSSL_MEMORY
#include "wolfssl/wolfcrypt/mem_track.h"
#endif /* USE_WOLFSSL_MEMORY */

void bench_loop       (bench_cb*, int, output_cb);
int  continuous_result(benchResult*);
int  run_benchmarks   (void);
void bench            (bench_cb, output_cb);
int  init_bench       (void);
#ifdef HAVE_SIGNAL_H
void signals          (int);
#endif /* HAVE_SIGNAL_H */

int  bench_des      (benchResult*, output_cb);
int  bench_idea     (benchResult*, output_cb);
int  bench_arc4     (benchResult*, output_cb);
int  bench_hc128    (benchResult*, output_cb);
int  bench_rabbit   (benchResult*, output_cb);
int  bench_chacha   (benchResult*, output_cb);
int  bench_chacha20_poly1305_aead(benchResult*, output_cb);
int  bench_aes      (benchResult*, output_cb);
int  bench_aesBase  (benchResult*, output_cb, int);
int  bench_aesenc   (benchResult*, output_cb);
int  bench_aesdec   (benchResult*, output_cb);
int  bench_aesgcm   (benchResult*, output_cb);
int  bench_aesccm   (benchResult*, output_cb);
int  bench_aesctr   (benchResult*, output_cb);
int  bench_poly1305 (benchResult*, output_cb);
int  bench_camellia (benchResult*, output_cb);

int  bench_md5      (benchResult*, output_cb);
int  bench_sha      (benchResult*, output_cb);
int  bench_sha256   (benchResult*, output_cb);
int  bench_sha384   (benchResult*, output_cb);
int  bench_sha512   (benchResult*, output_cb);
int  bench_ripemd   (benchResult*, output_cb);
int  bench_cmac     (benchResult*, output_cb);

int  bench_rsaBase  (benchResult*, output_cb, int);
int  bench_rsa      (benchResult*, output_cb);
int  bench_rsaEnc   (benchResult*, output_cb);
int  bench_rsaDec   (benchResult*, output_cb);
int  bench_rsaKeyGen(benchResult*, output_cb);
int  bench_dh       (benchResult*, output_cb);

#ifdef HAVE_ECC
int  bench_eccKeyGen    (benchResult*, output_cb);
int  bench_eccKeyAgree  (benchResult*, output_cb);
#ifdef HAVE_ECC_ENCRYPT
int  bench_eccEncrypt   (benchResult*, output_cb);
#endif /* HAVE_ECC_ENCRYPT */
#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519
int  bench_curve25519KeyGen(benchResult*, output_cb);
#ifdef HAVE_CURVE25519_SHARED_SECRET
int  bench_curve25519KeyAgree(benchResult*, output_cb);
#endif /* HAVE_CURVE25519_SHARED_SECRET */
#endif /* HAVE_CURVE25519 */
#ifdef HAVE_ED25519
int  bench_ed25519KeyGen(benchResult*, output_cb);
int  bench_ed25519KeySign(benchResult*, output_cb);
#endif /* HAVE_ED25519 */
#ifdef HAVE_NTRU
int  bench_ntru             (benchResult*, output_cb);
int  bench_ntruBits         (benchResult*, output_cb, word16, int);
int  bench_ntru128E         (benchResult*, output_cb);
int  bench_ntru192E         (benchResult*, output_cb);
int  bench_ntru256E         (benchResult*, output_cb);
int  bench_ntru128D         (benchResult*, output_cb);
int  bench_ntru192D         (benchResult*, output_cb);
int  bench_ntru256D         (benchResult*, output_cb);
int  bench_ntruKeyGen       (benchResult*, output_cb);
int  bench_ntruKeyGen128    (benchResult*, output_cb);
int  bench_ntruKeyGen192    (benchResult*, output_cb);
int  bench_ntruKeyGen256    (benchResult*, output_cb);
int  bench_ntruKeyGenBits   (benchResult*, output_cb, word16);
#endif /* HAVE_NTRU */
int  bench_rng      (benchResult*, output_cb);

double current_time(int);
int print_result    (benchResult*);
int init_result     (benchResult*, const char*, int);


#ifdef HAVE_CAVIUM

static int OpenNitroxDevice(int dma_mode,int dev_id)
{
    Csp1CoreAssignment core_assign;
    Uint32             device;

    if (CspInitialize(CAVIUM_DIRECT,CAVIUM_DEV_ID))
        return -1;
    if (Csp1GetDevType(&device))
        return -1;
    if (device != NPX_DEVICE) {
        if (ioctl(gpkpdev_hdlr[CAVIUM_DEV_ID], IOCTL_CSP1_GET_CORE_ASSIGNMENT,
                    (Uint32 *)&core_assign)!= 0)
            return -1;
    }
    CspShutdown(CAVIUM_DEV_ID);

    return CspInitialize(dma_mode, dev_id);
}

#endif /* HAVE_CAVIUM */

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

/**
 * Global variable for controlling loop.
 * Used to terminate the benchmark loop gracefully.
 */
volatile int isDone = 0;

static const XGEN_ALIGN byte key[] =
{
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    0xfe,0xde,0xba,0x98,0x76,0x54,0x32,0x10,
    0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67
};

static const XGEN_ALIGN byte iv[] =
{
    0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef,
    0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
    0x11,0x21,0x31,0x41,0x51,0x61,0x71,0x81
};

#ifdef BENCH_EMBEDDED
enum BenchmarkBounds {
    numBlocks = 25, /* how many kB to test (en/de)cryption */
    ntimes = 1,
    genTimes = 5,   /* public key iterations */
    agreeTimes = 5
};
static const char blockType[] = "kB";   /* used in printf output */
#else
enum BenchmarkBounds {
    numBlocks = 50,  /* how many megs to test (en/de)cryption */
    ntimes = 100,
    genTimes = 100,
    agreeTimes = 100
};
static const char blockType[] = "megs"; /* used in printf output */
#endif /* BENCH_EMBEDDED */

/**
 * Output's benchmark result to console. Used as a callback in the benchmark
 * functions. This allows multiple functions to be defined in order to customize
 * output of the bench results.  Determines which line to output based on the
 * printFormat enum.
 *
 * TODO: Rename to console_result or default_result
 *
 *      result: Pointer to a benchResult structure.
 */
int print_result(benchResult* result)
{

    switch(result->outputType){
        case mbPerSec:
            printf("%-10s%d %s took %5.3f seconds, %8.3f MB/s",result->name,
                numBlocks, blockType, result->total, result->rate);
            SHOW_INTEL_CYCLES
            printf("\n");
            break;
        case encryptMillisecond:
           printf("%-10s%d encryption took %6.3f milliseconds, avg over %d"
             " iterations\n", result->name, result->keySize, result->rate,
             ntimes);
           break;
        case decryptMillisecond:
           printf("%-10s%d decryption took %6.3f milliseconds, avg over %d"
             " iterations\n", result->name, result->keySize, result->rate,
             ntimes);
           break;
        case keyGen:
           printf("%-10s%d key generation  %6.3f milliseconds, avg over %d"
             " iterations\n", result->name, result->keySize,
              result->rate, ntimes);
           break;
        case keyAgree:
           printf("%-10s%d key agreement   %6.3f milliseconds, avg over %d"
             " iterations\n", result->name, result->keySize,
              result->rate, ntimes);
           break;
        case keyGenNoKeysz:
           printf("%-10skey generation %7.3f milliseconds, avg over %d"
             " iterations\n", result->name, result->rate, genTimes);
           break;
        case keyAgreeNoKeysz:
           printf("%-10skey agreement   %6.3f milliseconds, avg over %d"
              " iterations\n", result->name, result->rate, agreeTimes);
           break;
        case signTime:
            printf("%-10ssign   time     %6.3f milliseconds, avg over %d"
                " iterations\n", result->name, result->rate, agreeTimes);
            break;
        case verifyTime:
            printf("%-10sverify time     %6.3f milliseconds, avg over %d"
                " iterations\n", result->name, result->rate, agreeTimes);
            break;
        case encryptNoKeysz:
            printf("%-10sencrypt         %6.3f milliseconds, avg over %d"
                " iterations\n", result->name, result->rate, ntimes);
            break;
        case decryptNoKeysz:
            printf("%-10sdecrypt         %6.3f milliseconds, avg over %d"
              " iterations\n", result->name, result->rate, ntimes);
            break;
        default:
            fprintf(stderr,"The result->outputType is not valid.");
    }

    return 0;
}

/**
 * Initializes a result structure by setting its name and output type.
 *
 *       name: A string of length BENCH_NAME_SZ
 * outputType: An integer representing how to format the output.  Refer to
 *             the printFormat enumeration.
 */
int init_result(benchResult* result, const char* name, int outputType)
{
    if(result == NULL || name == NULL){
       fprintf(stderr, "Bad Function arg in init_result\n");
        return -1;
    } else {
        XSTRNCPY(result->name, name, BENCH_NAME_SZ);
        result->outputType = outputType;
        if(result->name != NULL){
            return 0;
        }else {
            fprintf(stderr, "init_result did not set properly.\n");
            return -1;
        }
    }
}

/**
 * Wrapper function for running a single benchmark.  Cleans up code.
 *
 *      bench_alg: A function pointer to a benchmark function.
 *      output_cb: A function pointer to a function for output.
 */
void bench(bench_cb bench_alg, output_cb output)
{
    int ret;

    benchResult result;
    XMEMSET(&result, 0, sizeof(benchResult));
    ret = bench_alg(&result, output);
    if(ret < 0)
    {
        /* There was an error */
        fprintf(stderr, "Error: %d.  %s\n", ret, wc_GetErrorString(ret));
    }
}

/**
 * Will perform a set of benchmarks continuously until an interupt or terminate
 * signal is passed.
 *
 *      bench_alg: Array of benchmark function pointers to run.
 *      output_cb: Function pointer for output.
 */
void bench_loop(bench_cb bench_alg[], int arrayLen, output_cb output)
{
    int i;
    while(!isDone)
    {
        for(i = 0; i < arrayLen; i++) {
            bench((*bench_alg[i]), output);
        }
    }
}

/**
 * Simple output function for printing just the algorithm name and the rate.
 * This is called when a benchmark is performed as a command line argument.
 *
 *      result: Pointer to a benchResult object that has been used in a
 *              benchmark function.
 */
int continuous_result(benchResult* result)
{
    switch(result->outputType)
    {
        case(decryptMillisecond):
            printf("%f - %s%dD\n", result->rate, result->name, result->keySize);
            break;
        case(encryptMillisecond):
            printf("%f - %s%dE\n", result->rate, result->name, result->keySize);
            break;
        default:
            printf("%f - %s\n", result->rate, result->name);
            break;
    }
    if (fflush(stdout) < 0) {
        return -1;
    }

    return 0;
}

#ifdef HAVE_SIGNAL_H
/**
 * Handles the SIGTERM and SIGINT signals. Only for Windows, Mac, Linux systems.
 *
 *      signum: The signal being passed. *
 */
void signals(int signum)
{
    if(signum == SIGTERM) {
        /* Clean up */
        fprintf(stderr, "Exiting...\n");
        isDone = 1;
    }
    else if (signum == SIGINT) {
        /* Interupt */
        fprintf(stderr, "Interuptting...\n");
        isDone = 1;
    }
}
#endif /* HAVE_SIGNAL_H */

/* so embedded projects can pull in tests on their own */
#if !defined(NO_MAIN_DRIVER)

/* Defines the amount of command line arguments to support. */
#define MAX_ARG_COUNT 6
/* Defines the max length of a single argument */
#define MAX_ARG_LENGTH 7

int main(int argc, char** argv)
{
    int argError;
    int i;
    int benchmark_i;
    bench_cb benchmarks[MAX_ARG_COUNT];
    (void)argc;
    (void)argv;
#if defined(HAVE_SIGNAL_H) || defined(_WIN32)
#ifdef _WIN32
    /* This handles interupts on Windows */
    signal(SIGTERM, signals);
    signal(SIGINT, signals);
#else
    /* This handles interupts on POSIX */
    struct sigaction action;
    XMEMSET(&action, 0, sizeof(struct sigaction));
    action.sa_handler = signals;
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT,  &action, NULL);
#endif /* _Win32 */
#endif /* HAVE_SIGNAL_H || _WIN32 */

    if (argc == 1) {
        if (init_bench() >= 0)
        {
            run_benchmarks();
        }
    } else {
        benchmark_i = 0;
        argError = 0;
        for (i = 1; i < argc; i++) {
            /* Display help */
            if (XSTRNCMP(argv[i], "-?", MAX_ARG_LENGTH) == 0) {
                argError = 1;
                printf("Run benchmark with the following options:\n");
                printf("\t-?\tList available commands.\n");
#ifdef HAVE_AESCCM
                printf("\t-ac\tBenchmark AES CCM\n");
#endif /* HAVE_AESCCM */
#ifdef HAVE_AESGCM
                printf("\t-ag\tBenchmark AES GCM\n");
#endif /* HAVE_AESGCM */
#ifdef HAVE_NTRU
                printf("\t-n128d\tBenchmark NTRU 128 Decrypt\n");
                printf("\t-n128e\tBenchmark NTRU 128 Encrypt\n");
#endif /* HAVE_NTRU */
#ifndef NO_RSA
                printf("\t-rd\tBenchmark RSA.\n");
#endif /* NO_RSA */
#ifndef NO_SHA256
                printf("\t-s256\tBenchmark SHA256.\n");
#endif
#ifdef WOLFSSL_SHA384
                printf("\t-s384\tBenchmark SHA384.\n");
#endif

                break;
            }
#ifdef HAVE_AESCCM
            /* Continuously benchmark AES CCM */
            else if (XSTRNCMP(argv[i], "-ac", MAX_ARG_LENGTH) == 0) {
                if(benchmark_i < 6) {
                    benchmarks[benchmark_i++] = bench_aesccm;
                }
            }
#endif /* HAVE_AESCCM */
#ifdef HAVE_AESGCM
            /* Add AES GCM to benchmarks */
            else if (XSTRNCMP(argv[i], "-ag", MAX_ARG_LENGTH) == 0) {
                if(benchmark_i < 6) {
                    benchmarks[benchmark_i++] = bench_aesgcm;
                }
            }
#endif /* HAVE_AESGCM */
#ifdef HAVE_NTRU
            else if (XSTRNCMP(argv[i], "-n128d", MAX_ARG_LENGTH) == 0) {
                if(benchmark_i < 6) {
                    benchmarks[benchmark_i++] = bench_ntru128D;
                }
            }
            else if (XSTRNCMP(argv[i], "-n128e", MAX_ARG_LENGTH) == 0) {
                if(benchmark_i < 6) {
                    benchmarks[benchmark_i++] = bench_ntru128E;
                }
            }
#endif /* HAVE_NTRU */
#ifndef NO_RSA
            /* Continuously benchmark RSA decrypt */
            else if (XSTRNCMP(argv[i], "-rd", MAX_ARG_LENGTH) == 0) {
                if(benchmark_i < 6) {
                    benchmarks[benchmark_i++] = bench_rsaDec;
                }
            }
#endif /* NO_RSA */
#ifndef NO_SHA256
            /* Continuously benchmark SHA 256 */
            else if (XSTRNCMP(argv[i], "-s256", MAX_ARG_LENGTH) == 0) {
                if(benchmark_i < 6) {
                    benchmarks[benchmark_i++] = bench_sha256;
                }
            }
#endif /* NO_SHA256 */
#ifdef WOLFSSL_SHA384
            /* Continously benchmark SHA 284 */
            else if (XSTRNCMP(argv[i], "-s384", MAX_ARG_LENGTH) == 0) {
                if(benchmark_i < 6) {
                    benchmarks[benchmark_i++] = bench_sha384;
                }
            }
#endif /* WOLFSSL_SHA384 */
            else {
                /* Print help for invalid command. */
                printf("\n\tOption(s) not recognized."
                       "  Use -? to view available options.\n\n");
                argError = 1;
            }
        }

        /* Perform benchmark only if there were no errors. */
        if(!argError && benchmark_i > 0 && init_bench() >= 0) {
            bench_loop(benchmarks, benchmark_i, continuous_result);
        }
    }
#else
int benchmark_test(void *args)
{
    (void)args;

    if (init_bench() >= 0) {
        run_benchmarks();
    }
#endif /* NO_MAIN_DRIVER */
    return 0;
}

/**
 * Initialize wolfCrypt to perform benchmarks.
 */
int init_bench()
{
#if defined(USE_WOLFSSL_MEMORY) && defined(WOLFSSL_TRACK_MEMORY)
    InitMemoryTracker();
#endif

    wolfCrypt_Init();

#if defined(DEBUG_WOLFSSL) && !defined(HAVE_VALGRIND)
    wolfSSL_Debugging_ON();
#endif

    (void)plain;
    (void)cipher;
    (void)key;
    (void)iv;

#ifdef HAVE_CAVIUM
    int ret = OpenNitroxDevice(CAVIUM_DIRECT, CAVIUM_DEV_ID);
    if (ret != 0) {
        printf("Cavium OpenNitroxDevice failed\n");
        exit(-1);
    }
#endif /* HAVE_CAVIUM */

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
    return 0;
}

/**
 * Runs all benchmarks.  This is the default operation of benchmark.
 */
int run_benchmarks()
{
    bench(bench_rng, print_result);
#ifndef NO_AES
#ifdef HAVE_AES_CBC
    /* Run bench_aes once to fill caches */
    bench(bench_aes, NULL);

    /* Run again but show these results */
    bench(bench_aes, print_result);
#endif /* HAVE_AES_CBC */
#ifdef HAVE_AESGCM
    bench(bench_aesgcm, print_result);
#endif /* HAVE_AESGCM */
#ifdef WOLFSSL_AES_COUNTER
    bench(bench_aesctr, print_result);
#endif /* WOLFSSL_AES_COUNTER */
#ifdef HAVE_AESCCM
    bench(bench_aesccm, print_result);
#endif /* HAVE_AESCCM */
#endif /* !NO_AES */

#ifdef HAVE_CAMELLIA
    bench(bench_camellia, print_result);
#endif /* HAVE_CAMELLIA */
#ifndef NO_RC4
    bench(bench_arc4, print_result);
#endif /* NO_RC4 */
#ifdef HAVE_HC128
    bench(bench_hc128, print_result);
#endif /* HAVE_HC128 */
#ifndef NO_RABBIT
    bench(bench_rabbit, print_result);
#endif
#ifdef HAVE_CHACHA
    bench(bench_chacha, print_result);
#endif
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    bench(bench_chacha20_poly1305_aead, print_result);
#endif
#ifndef NO_DES3
    bench(bench_des, print_result);
#endif
#ifdef HAVE_IDEA
    bench(bench_idea, print_result);
#endif

    printf("\n");

#ifndef NO_MD5
    bench(bench_md5,print_result);
#endif
#ifdef HAVE_POLY1305
    bench(bench_poly1305, print_result);
#endif
#ifndef NO_SHA
    bench(bench_sha, print_result);
#endif
#ifndef NO_SHA256
    bench(bench_sha256, print_result);
#endif
#ifdef WOLFSSL_SHA384
    bench(bench_sha384, print_result);
#endif
#ifdef WOLFSSL_SHA512
    bench(bench_sha512, print_result);
#endif
#ifdef WOLFSSL_RIPEMD
    bench(bench_ripemd, print_result);
#endif
#ifdef HAVE_BLAKE2
    bench(bench_blake2, print_result);
#endif
#ifdef WOLFSSL_CMAC
    bench(bench_cmac, print_result);
#endif

    printf("\n");

#ifndef NO_RSA
    bench(bench_rsa, print_result);
#endif

#ifndef NO_DH
    bench(bench_dh, print_result);
#endif

#if defined(WOLFSSL_KEY_GEN) && !defined(NO_RSA)
    bench(bench_rsaKeyGen, print_result);
#endif

#ifdef HAVE_NTRU
    printf("\n");
    bench(bench_ntru, print_result);
    bench(bench_ntruKeyGen, print_result);
#endif

#ifdef HAVE_ECC
    bench(bench_eccKeyGen, print_result);
    bench(bench_eccKeyAgree, print_result);
#ifdef HAVE_ECC_ENCRYPT
    bench(bench_eccEncrypt, print_result);
#endif
#if defined(FP_ECC)
    wc_ecc_fp_free();
#endif
#endif

#ifdef HAVE_CURVE25519
    bench(bench_curve25519KeyGen, print_result);
#ifdef HAVE_CURVE25519_SHARED_SECRET
    bench(bench_curve25519KeyAgree, print_result);
#endif
#endif

#ifdef HAVE_ED25519
    bench(bench_ed25519KeyGen, print_result);
    bench(bench_ed25519KeySign, print_result);
#endif

#if defined(HAVE_LOCAL_RNG)
    wc_FreeRng(&rng);
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

int bench_rng(benchResult* result, output_cb output)
{
    int    ret, i;
    double start;
    int pos, len, remain;
#ifndef HAVE_LOCAL_RNG
    WC_RNG rng;

    ret = wc_InitRng(&rng);
    if (ret < 0) {
        return  ret;
    }
#endif

    /* Start Time */
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
                return ret;
            }
            remain -= len;
            pos += len;
        }
    }

    END_INTEL_CYCLES
    /* Stop time */
    result->total = current_time(0) - start;

    /* Calculate results */
    result->rate = 1 / result->total * numBlocks;
#ifdef BENCH_EMBEDDED
    /* since using kB, convert to MB/s */
    result->rate = result->rate / 1024;
#endif

   init_result(result, "RNG", mbPerSec);
   if(output)
   {
       output(result);
   }

#ifndef HAVE_LOCAL_RNG
    wc_FreeRng(&rng);
#endif
    return 0;
}

#ifndef NO_AES

#ifdef HAVE_AES_CBC

    /**
     * Default AES benchmark.  Outputs both encrypt and decrypt results.
     * Wrapper around bench_aesBase.
     *
     *      result: Pointer to a result object.
     *      output: Function pointer to the output function to use.
     */
    int bench_aes(benchResult* result, output_cb output)
    {
        return bench_aesBase(result, output, outputBoth);
    }

    /**
     * Wrapper function for bench_aesBase to only output the encrypt results.
     *
     *         result: Pointer to the result object.
     *         output: Function pointer to output functoin.
     */
    int bench_aesenc(benchResult* result, output_cb output)
    {
        return bench_aesBase(result, output, outputEncrypt);
    }

    /**
     * Wrapper function for bench_aesBase to only output the decrypt results.
     *
     *         result: Pointer to the result object.
     *         output: Function pointer to output functoin.
     */
    int bench_aesdec(benchResult* result, output_cb output)
    {
        return bench_aesBase(result, output, outputDecrypt);
    }

    /**
     * Base AES benchmark function.  Use it in wrapper functions to control
     * what it outputs.
     *
     *         result: Pointer to the result object.
     *         output: Function pointer to output functoin.
     *     outputType: Use outputType enum to determine what part of function to
     *                 output.
     */
    int bench_aesBase(benchResult* result, output_cb output, int outputType)
    {
        Aes    enc;
        double start;
        int    i;
        int    ret;

#ifdef HAVE_CAVIUM
        ret = wc_AesInitCavium(&enc, CAVIUM_DEV_ID);
        if (ret < 0) {
            return ret;
        }
#endif
        ret = wc_AesSetKey(&enc, key, 16, iv, AES_ENCRYPTION);
        if (ret != 0) {
            return ret;
        }
        start = current_time(1);
        BEGIN_INTEL_CYCLES

        for(i = 0; i < numBlocks; i++)
            wc_AesCbcEncrypt(&enc, plain, cipher, sizeof(plain));

        END_INTEL_CYCLES

        result->total = current_time(0) - start;
        result->rate = 1 / result->total * numBlocks;
#ifdef BENCH_EMBEDDED
        /* since using kB, convert to MB/s */
        result->rate = result->rate / 1024;
#endif
        /* Only output if we want encrypt results or both */
        if(outputType == outputEncrypt || outputType == outputBoth) {
            init_result(result, "AES-ENC", mbPerSec);
            if (output) {
                output(result);
            }
        }
#ifdef HAVE_CAVIUM
        wc_AesFreeCavium(&enc);
        ret = wc_AesInitCavium(&enc, CAVIUM_DEV_ID);
        if (ret != 0) {
            return ret;
        }
#endif

        /* Only perform if we want decrypt results or both */
        if(outputType == outputDecrypt || outputType == outputBoth) {
            ret = wc_AesSetKey(&enc, key, 16, iv, AES_DECRYPTION);
            if (ret != 0) {
                return ret;
            }

            /* Start benching decrypt */
            start = current_time(1);
            BEGIN_INTEL_CYCLES

            for(i = 0; i < numBlocks; i++)
                wc_AesCbcDecrypt(&enc, plain, cipher, sizeof(plain));

            END_INTEL_CYCLES

            result->total = current_time(0) - start;
            result->rate = 1 / result->total * numBlocks;
#ifdef BENCH_EMBEDDED
                /* since using kB, convert to MB/s */
            result->rate = result->rate / 1024;
#endif
            init_result(result, "AES-DEC", mbPerSec);
            if(output) {
                output(result);
            }
#ifdef HAVE_CAVIUM
            wc_AesFreeCavium(&enc);
#endif
        }
        return 0;
    }
#endif /* HAVE_AES_CBC */

#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
    static byte additional[13];
    static byte tag[16];
#endif


#ifdef HAVE_AESGCM
    int bench_aesgcm(benchResult* result, output_cb output)
    {
        Aes    enc;
        double start;
        int    i;
        wc_AesGcmSetKey(&enc, key, 16);
        start = current_time(1);
        BEGIN_INTEL_CYCLES

        for(i = 0; i < numBlocks; i++)
            wc_AesGcmEncrypt(&enc, cipher, plain, sizeof(plain), iv, 12,
                    tag, 16, additional, 13);

        END_INTEL_CYCLES;
        /* Save */
        result->total = current_time(0) - start;
        result->rate = 1 / result->total * numBlocks;
#ifdef BENCH_EMBEDDED
        /* since using kB, convert to MB/s */
        result->rate = result->rate / 1024;
#endif

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

        printf("AES-GCM Decrypt %d %s took %5.3f seconds, %8.3f MB/s",
                numBlocks, blockType, total, persec);
        SHOW_INTEL_CYCLES
            printf("\n");
#endif
        init_result(result, "AES-GCM", mbPerSec);
        if(output) {
            output(result);
        }
        return 0;
    }
#endif /* HAVE_AESGCM */


#ifdef WOLFSSL_AES_COUNTER
    int bench_aesctr(benchResult* result, output_cb output)
    {
        Aes    enc;
        double start;
        int    i;
        wc_AesSetKeyDirect(&enc, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
        start = current_time(1);
        BEGIN_INTEL_CYCLES

        for(i = 0; i < numBlocks; i++)
            wc_AesCtrEncrypt(&enc, plain, cipher, sizeof(plain));

        END_INTEL_CYCLES
        result->total = current_time(0) - start;

        result->rate = 1 / result->total * numBlocks;
#ifdef BENCH_EMBEDDED
        /* since using kB, convert to MB/s */
        result->rate = result->rate / 1024;
#endif

        init_result(result, "AES-CTR", mbPerSec);
        if(output) {
            output(result);
        }

        return 0;
    }
#endif /* WOLFSSL_AES_COUNTER */


#ifdef HAVE_AESCCM
    int bench_aesccm(benchResult* result, output_cb output)
    {
        Aes    enc;
        double start;
        int    i;

        wc_AesCcmSetKey(&enc, key, 16);
        start = current_time(1);
        BEGIN_INTEL_CYCLES


        for(i = 0; i < numBlocks; i++)
            wc_AesCcmEncrypt(&enc, cipher, plain, sizeof(plain), iv, 12,
                    tag, 16, additional, 13);


        END_INTEL_CYCLES
            result->total = current_time(0) - start;

        result->rate = 1 / result->total * numBlocks;

#ifdef BENCH_EMBEDDED
        /* since using kB, convert to MB/s */
        result->rate = result->rate / 1024;
#endif

        init_result(result, "AES-CCM", mbPerSec);
        if(output) {
          output(result);
        }

        return 0;
    }
#endif /* HAVE_AESCCM */
#endif /* !NO_AES */


#ifdef HAVE_POLY1305
    int bench_poly1305(benchResult* result, output_cb output)
    {
        Poly1305    enc;
        byte   mac[16];
        double start;
        int    i;
        int    ret;

        ret = wc_Poly1305SetKey(&enc, key, 32);
        if (ret != 0) {
            return ret;
        }
        start = current_time(1);
        BEGIN_INTEL_CYCLES

        for(i = 0; i < numBlocks; i++)
            wc_Poly1305Update(&enc, plain, sizeof(plain));

        wc_Poly1305Final(&enc, mac);
        END_INTEL_CYCLES

        result->total = current_time(0) - start;
        result->rate = 1 / result->total * numBlocks;
#ifdef BENCH_EMBEDDED
        /* since using kB, convert to MB/s */
        result->rate = result->rate / 1024;
#endif
        init_result(result, "POLY1305", mbPerSec);
        if(output) {
            output(result);
        }

        return 0;
    }
#endif /* HAVE_POLY1305 */


#ifdef HAVE_CAMELLIA
    int bench_camellia(benchResult* result, output_cb output)
    {
        Camellia cam;
        double start;
        int    i, ret;

        ret = wc_CamelliaSetKey(&cam, key, 16, iv);
        if (ret != 0) {
            return ret;
        }
        start = current_time(1);
        BEGIN_INTEL_CYCLES

        for(i = 0; i < numBlocks; i++)
            wc_CamelliaCbcEncrypt(&cam, plain, cipher, sizeof(plain));

        END_INTEL_CYCLES
        result->total = current_time(0) - start;

        result->rate = 1 / result->total * numBlocks;
#ifdef BENCH_EMBEDDED
        /* since using kB, convert to MB/s */
        result->rate = result->rate / 1024;
#endif
        init_result(result, "Camellia", mbPerSec);
        if(output) {
          output(result);
        }

        return 0;
    }
#endif


#ifndef NO_DES3
    int bench_des(benchResult* result, output_cb output)
    {
        Des3   enc;
        double start;
        int    i, ret;

#ifdef HAVE_CAVIUM
        ret = wc_Des3_InitCavium(&enc, CAVIUM_DEV_ID);
        if (ret != 0)
        {
            return ret;
        }
#endif
        ret = wc_Des3_SetKey(&enc, key, iv, DES_ENCRYPTION);
        if (ret != 0) {
            return ret;
        }
        start = current_time(1);
        BEGIN_INTEL_CYCLES

        for(i = 0; i < numBlocks; i++)
            wc_Des3_CbcEncrypt(&enc, plain, cipher, sizeof(plain));

        END_INTEL_CYCLES
        result->total = current_time(0) - start;

        result->rate = 1 / result->total * numBlocks;
#ifdef BENCH_EMBEDDED
        /* since using kB, convert to MB/s */
        result->rate = result->rate / 1024;
#endif
        init_result(result, "3DES", mbPerSec);
        if(output) {
          output(result);
        }

#ifdef HAVE_CAVIUM
        wc_Des3_FreeCavium(&enc);
#endif
        return 0;
    }
#endif


#ifdef HAVE_IDEA
    int bench_idea(benchResult* result, output_cb output)
    {
        Idea   enc;
        double start;
        int    i, ret;

        ret = wc_IdeaSetKey(&enc, key, IDEA_KEY_SIZE, iv, IDEA_ENCRYPTION);
        if (ret != 0) {
            return ret;
        }
        start = current_time(1);
        BEGIN_INTEL_CYCLES

        for(i = 0; i < numBlocks; i++)
            wc_IdeaCbcEncrypt(&enc, plain, cipher, sizeof(plain));

        END_INTEL_CYCLES

        result->total = current_time(0) - start;
        result->rate = 1 / result->total * numBlocks;
#ifdef BENCH_EMBEDDED
        /* since using kB, convert to MB/s */
        result->rate = result->rate / 1024;
#endif
        init_result(result, "IDEA", mbPerSec);
        if(output) {
          output(result);
        }

        return 0;
    }
#endif /* HAVE_IDEA */


#ifndef NO_RC4
    int bench_arc4(benchResult* result, output_cb output)
    {
        Arc4   enc;
        double start;
        int    i;

#ifdef HAVE_CAVIUM
        if (wc_Arc4InitCavium(&enc, CAVIUM_DEV_ID) != 0)

#endif /* HAVE_CAVIUM */

        wc_Arc4SetKey(&enc, key, 16);
        start = current_time(1);
        BEGIN_INTEL_CYCLES

        for(i = 0; i < numBlocks; i++)
            wc_Arc4Process(&enc, cipher, plain, sizeof(plain));

        END_INTEL_CYCLES

        result->total = current_time(0) - start;
        result->rate = 1 / result->total * numBlocks;
#ifdef BENCH_EMBEDDED
        /* since using kB, convert to MB/s */
        result->rate = result->rate / 1024;
#endif /* BENCH_EMBEDDED */
        init_result(result, "ARC4", mbPerSec);
        if(output) {
          output(result);
        }
#ifdef HAVE_CAVIUM
        wc_Arc4FreeCavium(&enc);
#endif /* HAVE_CAVIUM */

        return 0;
    }
#endif /* NO_RC# */


#ifdef HAVE_HC128
    int bench_hc128(benchResult* result, output_cb output)
    {
        HC128  enc;
        double start;
        int    i;

        wc_Hc128_SetKey(&enc, key, iv);
        start = current_time(1);
        BEGIN_INTEL_CYCLES

        for(i = 0; i < numBlocks; i++)
            wc_Hc128_Process(&enc, cipher, plain, sizeof(plain));

        END_INTEL_CYCLES

        result->total = current_time(0) - start;
        result->rate = 1 / result->total * numBlocks;
#ifdef BENCH_EMBEDDED
        /* since using kB, convert to MB/s */
        result->rate = result->rate / 1024;
#endif

        init_result(result, "HC128", mbPerSec);
        if(output) {
          output(result);
        }

        return 0;
    }
#endif /* HAVE_HC128 */


#ifndef NO_RABBIT
    int bench_rabbit(benchResult* result, output_cb output)
    {
        Rabbit  enc;
        double start;
        int    i;

        wc_RabbitSetKey(&enc, key, iv);
        start = current_time(1);
        BEGIN_INTEL_CYCLES

        for(i = 0; i < numBlocks; i++)
            wc_RabbitProcess(&enc, cipher, plain, sizeof(plain));

        END_INTEL_CYCLES

        result->total = current_time(0) - start;
        result->rate = 1 / result->total * numBlocks;
#ifdef BENCH_EMBEDDED
        /* since using kB, convert to MB/s */
        result->rate = result->rate / 1024;
#endif /* BENCH_EMBEDDED */
        init_result(result, "RABBIT", mbPerSec);
        if(output) {
          output(result);
        }

        return 0;
    }
#endif /* NO_RABBIT */


#ifdef HAVE_CHACHA
    int bench_chacha(benchResult* result, output_cb output)
    {
        ChaCha enc;
        double start;
        int    i;

        wc_Chacha_SetKey(&enc, key, 16);
        start = current_time(1);
        BEGIN_INTEL_CYCLES

        for (i = 0; i < numBlocks; i++) {
            wc_Chacha_SetIV(&enc, iv, 0);
            wc_Chacha_Process(&enc, cipher, plain, sizeof(plain));
        }

        END_INTEL_CYCLES

        result->total = current_time(0) - start;
        result->rate = 1 / result->total * numBlocks;
#ifdef BENCH_EMBEDDED
        /* since using kB, convert to MB/s */
        result->rate = result->rate / 1024;
#endif /* BENCH_EMBEDDED */
        init_result(result, "CHACHA", mbPerSec);
        if(output) {
          output(result);
        }

        return 0;
    }
#endif /* HAVE_CHACHA*/

#if( defined( HAVE_CHACHA ) && defined( HAVE_POLY1305 ) )
    int bench_chacha20_poly1305_aead(benchResult* result, output_cb output)
    {
        double start;
        int    i;

        byte authTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
        XMEMSET( authTag, 0, sizeof( authTag ) );

        start = current_time(1);
        BEGIN_INTEL_CYCLES

        for (i = 0; i < numBlocks; i++) {
            wc_ChaCha20Poly1305_Encrypt(key, iv, NULL, 0, plain,
                    sizeof(plain), cipher, authTag);
        }

        END_INTEL_CYCLES

        result->total = current_time(0) - start;
        result->rate = 1 / result->total * numBlocks;

#ifdef BENCH_EMBEDDED
        /* since using kB, convert to MB/s */
        result->rate = result->rate / 1024;
#endif /* BENCH_EMBEDDED */
        init_result(result, "CHAPOLY", mbPerSec);
        if(output) {
          output(result);
        }

        return 0;
    }
#endif /* HAVE_CHACHA && HAVE_POLY1305 */


#ifndef NO_MD5
    int bench_md5(benchResult* result, output_cb output)
    {
        Md5    hash;
        byte   digest[MD5_DIGEST_SIZE];
        double start;
        int    i;

        wc_InitMd5(&hash);
        start = current_time(1);

        BEGIN_INTEL_CYCLES

        for(i = 0; i < numBlocks; i++)
            wc_Md5Update(&hash, plain, sizeof(plain));

        wc_Md5Final(&hash, digest);

        END_INTEL_CYCLES

        result->total = current_time(0) - start;
        result->rate = 1 / result->total * numBlocks;
#ifdef BENCH_EMBEDDED
        /* since using kB, convert to MB/s */
        result->rate = result->rate / 1024;
#endif
        init_result(result, "MD5", mbPerSec);
        if(output) {
          output(result);
        }

        return 0;
    }
#endif /* NO_MD5 */


#ifndef NO_SHA
    int bench_sha(benchResult* result, output_cb output)
    {
        Sha    hash;
        byte   digest[SHA_DIGEST_SIZE];
        double start;
        int    i, ret;

        ret = wc_InitSha(&hash);
        if (ret != 0) {
            return ret;
        }
        start = current_time(1);
        BEGIN_INTEL_CYCLES;

        for(i = 0; i < numBlocks; i++)
            wc_ShaUpdate(&hash, plain, sizeof(plain));

        wc_ShaFinal(&hash, digest);

        END_INTEL_CYCLES;

        result->total = current_time(0) - start;
        result->rate = 1 / result->total * numBlocks;
#ifdef BENCH_EMBEDDED
        /* since using kB, convert to MB/s */
        result->rate = result->rate / 1024;
#endif
        init_result(result, "SHA", mbPerSec);
        if(output) {
          output(result);
        }

        return 0;
    }
#endif /* NO_SHA */


#ifndef NO_SHA256
    int bench_sha256(benchResult* result, output_cb output)
    {
        Sha256 hash;
        byte   digest[SHA256_DIGEST_SIZE];
        double start;
        int    i, ret;

        ret = wc_InitSha256(&hash);
        if (ret != 0) {
            return ret;
        }
        start = current_time(1);
        BEGIN_INTEL_CYCLES;

        for(i = 0; i < numBlocks; i++) {
            ret = wc_Sha256Update(&hash, plain, sizeof(plain));
            if (ret != 0) {
                return ret;
            }
        }

        ret = wc_Sha256Final(&hash, digest);
        if (ret != 0) {
            return ret;
        }

        END_INTEL_CYCLES;
        result->total = current_time(0) - start;
        result->rate = 1 / result->total * numBlocks;
#ifdef BENCH_EMBEDDED
        /* since using kB, convert to MB/s */
        result->rate = result->rate / 1024;
#endif

        init_result(result, "SHA-256", mbPerSec);
        if(output) {
           output(result);
        }

        return 0;
    }
#endif

#ifdef WOLFSSL_SHA384
    int bench_sha384(benchResult* result, output_cb output)
    {
        Sha384 hash;
        byte   digest[SHA384_DIGEST_SIZE];
        double start;
        int    i, ret;

        ret = wc_InitSha384(&hash);
        if (ret != 0) {
            return ret;
        }
        start = current_time(1);
        BEGIN_INTEL_CYCLES;

        for(i = 0; i < numBlocks; i++) {
            ret = wc_Sha384Update(&hash, plain, sizeof(plain));
            if (ret != 0) {
                return ret;
            }
        }

        ret = wc_Sha384Final(&hash, digest);
        if (ret != 0) {
            return ret;
        }

        END_INTEL_CYCLES;

        result->total = current_time(0) - start;
        result->rate = 1 / result->total * numBlocks;
#ifdef BENCH_EMBEDDED
        /* since using kB, convert to MB/s */
        result->rate = result->rate / 1024;
#endif
        init_result(result, "SHA-384", mbPerSec);
        if(output) {
          output(result);
        }

        return 0;
    }
#endif

#ifdef WOLFSSL_SHA512
    int bench_sha512(benchResult* result, output_cb output)
    {
        Sha512 hash;
        byte   digest[SHA512_DIGEST_SIZE];
        double start;
        int    i, ret;

        ret = wc_InitSha512(&hash);
        if (ret != 0) {
            return ret;
        }
        start = current_time(1);
        BEGIN_INTEL_CYCLES

        for(i = 0; i < numBlocks; i++) {
            ret = wc_Sha512Update(&hash, plain, sizeof(plain));
            if (ret != 0) {
                return ret;
            }
        }

        ret = wc_Sha512Final(&hash, digest);
        if (ret != 0) {
            return ret;
        }

        END_INTEL_CYCLES
            result->total = current_time(0) - start;
        result->rate = 1 / result->total * numBlocks;
#ifdef BENCH_EMBEDDED
        /* since using kB, convert to MB/s */
        result->rate = result->rate / 1024;
#endif
        init_result(result, "SHA-512", mbPerSec);
        if(output) {
          output(result);
        }

        return 0;
    }
#endif

#ifdef WOLFSSL_RIPEMD
    int bench_ripemd(benchResult* result, output_cb output)
    {
        RipeMd hash;
        byte   digest[RIPEMD_DIGEST_SIZE];
        double start;
        int    i;

        wc_InitRipeMd(&hash);
        start = current_time(1);
        BEGIN_INTEL_CYCLES

            for(i = 0; i < numBlocks; i++)
                wc_RipeMdUpdate(&hash, plain, sizeof(plain));

        wc_RipeMdFinal(&hash, digest);

        END_INTEL_CYCLES
            result->total = current_time(0) - start;
        result->rate = 1 / result->total * numBlocks;
#ifdef BENCH_EMBEDDED
        /* since using kB, convert to MB/s */
        result->rate = result->rate / 1024;
#endif
        init_result(result, "RIPEMD", mbPerSec);
        if(output) {
          output(result);
        }

        return 0;
    }
#endif


#ifdef HAVE_BLAKE2
    int bench_blake2(benchResult* result, output_cb output)
    {
        Blake2b b2b;
        byte    digest[64];
        double  start;
        int     i, ret;

        ret = wc_InitBlake2b(&b2b, 64);
        if (ret != 0) {
            return ret;
        }
        start = current_time(1);
        BEGIN_INTEL_CYCLES

        for(i = 0; i < numBlocks; i++) {
            ret = wc_Blake2bUpdate(&b2b, plain, sizeof(plain));
            if (ret != 0) {
                return ret;
            }
        }

        ret = wc_Blake2bFinal(&b2b, digest, 64);
        if (ret != 0) {
            return ret;
        }

        END_INTEL_CYCLES
            result->total = current_time(0) - start;
        result->rate = 1 / result->total * numBlocks;
#ifdef BENCH_EMBEDDED
        /* since using kB, convert to MB/s */
        result->rate = result->rate / 1024;
#endif
        init_result(result, "BLAKE2b", mbPerSec);
        if(output) {
          output(result);
        }

        return 0;
    }
#endif


#ifdef WOLFSSL_CMAC
    int bench_cmac(benchResult* result, output_cb output)
    {
        Cmac    cmac;
        byte    digest[AES_BLOCK_SIZE];
        word32  digestSz = sizeof(digest);
        double  start;
        int     i, ret;

        ret = wc_InitCmac(&cmac, key, 16, WC_CMAC_AES, NULL);
        if (ret != 0) {
            return ret;
        }
        start = current_time(1);
        BEGIN_INTEL_CYCLES

        for(i = 0; i < numBlocks; i++) {
            ret = wc_CmacUpdate(&cmac, plain, sizeof(plain));
            if (ret != 0) {
                return ret;
            }
        }

        ret = wc_CmacFinal(&cmac, digest, &digestSz);
        if (ret != 0) {
            return ret;
        }

        END_INTEL_CYCLES
        result->total = current_time(0) - start;
        result->rate = 1 / result->total * numBlocks;
#ifdef BENCH_EMBEDDED
        /* since using kB, convert to MB/s */
        result->rate = result->rate / 1024;
#endif
        init_result(result, "AES-CMAC", mbPerSec);
        if(output) {
          output(result);
        }

        return 0;
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

    /**
     * Base function for RSA.  Call it with wrapper functions to control what
     * part of the benchmark actually outputs.
     */
    int bench_rsaBase(benchResult* result, output_cb output, int outputType)
    {
        int    i;
        int    ret, errorCode;
        size_t bytes;
        word32 idx = 0;
        const byte* tmp;

        byte      message[] = "Everyone gets Friday off.";
        byte      enc[256];  /* for up to 2048 bit */
        const int len = (int)strlen((char*)message);
        double    start, each;

        RsaKey rsaKey;
#ifdef USE_CERT_BUFFERS_1024
        tmp = rsa_key_der_1024;
        bytes = sizeof_rsa_key_der_1024;
        result->keySize = 1024; /* used in printf */
#elif defined(USE_CERT_BUFFERS_2048)
        tmp = rsa_key_der_2048;
        bytes = sizeof_rsa_key_der_2048;
        result->keySize = 2048; /* used in printf */
#else
#error "need a cert buffer size"
#endif /* USE_CERT_BUFFERS */


#ifdef HAVE_CAVIUM
        errorCode = wc_RsaInitCavium(&rsaKey, CAVIUM_DEV_ID);
        if (errorCode < 0)
            return errorCode;
#endif
        errorCode = wc_InitRsaKey(&rsaKey, 0);
        if (errorCode < 0)
            return errorCode;

        errorCode = wc_RsaPrivateKeyDecode(tmp, &idx, &rsaKey, (word32)bytes);
        if(errorCode < 0)
            return errorCode;

        start = current_time(1);

        for (i = 0; i < ntimes; i++)
            ret = wc_RsaPublicEncrypt(message,len,enc,sizeof(enc), &rsaKey,
                    &rng);

        result->total = current_time(0) - start;
        each  = result->total / ntimes;   /* per second   */
        result->rate = each * 1000; /* milliseconds */

        if (ret < 0) {
            return ret;
        }

        if(outputType == outputEncrypt || outputType == outputBoth)
        {
            init_result(result, "RSA", encryptMillisecond);
            if(output) {
                output(result);
            }
        }


        if(outputType == outputDecrypt || outputType == outputBoth)
        {

#ifdef WC_RSA_BLINDING
            wc_RsaSetRNG(&rsaKey, &rng);
#endif
            start = current_time(1);

            for (i = 0; i < ntimes; i++) {
                byte  out[256];  /* for up to 2048 bit */
                errorCode = wc_RsaPrivateDecrypt(enc, (word32)ret, out,
                        sizeof(out), &rsaKey);
            }

            result->total = current_time(0) - start;
            each  = result->total / ntimes;   /* per second   */
            result->rate = each * 1000; /* milliseconds */

            if(errorCode < 0) {
                return errorCode;
            }

            init_result(result, "RSA", decryptMillisecond);
            if(output) {
                output(result);
            }
        }

        wc_FreeRsaKey(&rsaKey);
#ifdef HAVE_CAVIUM
        wc_RsaFreeCavium(&rsaKey);
#endif
        return 0;
    }

    int bench_rsa(benchResult* result, output_cb output)
    {
        return bench_rsaBase(result, output, outputBoth);
    }

    int bench_rsaEnc(benchResult* result, output_cb output)
    {
        return bench_rsaBase(result, output, outputEncrypt);
    }

    int bench_rsaDec(benchResult* result, output_cb output)
    {
        return bench_rsaBase(result, output, outputDecrypt);
    }
#endif


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

    int bench_dh(benchResult* result, output_cb output)
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

        double start, each;
        DhKey  dhKey;
        result->keySize = 2048; /* used in printf */

        (void)idx;
        (void)tmp;


#if defined(NO_ASN)
        result->keySize = 1024;
        /* do nothing, but don't use default FILE */
#elif defined(USE_CERT_BUFFERS_1024)
        tmp = dh_key_der_1024;
        bytes = sizeof_dh_key_der_1024;
        result->keySize = 1024;
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
            return bytes;
        }

        start = current_time(1);

        for (i = 0; i < ntimes; i++)
            wc_DhGenerateKeyPair(&dhKey, &rng, priv, &privSz, pub, &pubSz);

        result->total = current_time(0) - start;
        each  = result->total / ntimes;   /* per second   */
        result->rate = each * 1000; /* milliseconds */

        init_result(result, "DH", keyGen);
        if(output) {
            output(result);
        }



        wc_DhGenerateKeyPair(&dhKey, &rng, priv2, &privSz2, pub2, &pubSz2);
        start = current_time(1);

        for (i = 0; i < ntimes; i++)
            wc_DhAgree(&dhKey, agree, &agreeSz, priv, privSz, pub2, pubSz2);

        result->total = current_time(0) - start;
        each  = result->total / ntimes;   /* per second   */
        result->rate = each * 1000; /* milliseconds */

        init_result(result, "DH", keyAgree);
        if(output) {
          output(result);
        }
        wc_FreeDhKey(&dhKey);

        return 0;
    }
#endif

#if defined(WOLFSSL_KEY_GEN) && !defined(NO_RSA)
    int bench_rsaKeyGen(benchResult* result, output_cb output)
    {
        RsaKey genKey;
        double start, each;
        int    i;

        /* 1024 bit */
        start = current_time(1);

        for(i = 0; i < genTimes; i++) {
            wc_InitRsaKey(&genKey, 0);
            wc_MakeRsaKey(&genKey, 1024, 65537, &rng);
            wc_FreeRsaKey(&genKey);
        }

        result->total = current_time(0) - start;
        each  = result->total / genTimes;  /* per second  */
        result->rate = each * 1000;   /* milliseconds */
        printf("\n");

        init_result(result, "RSA 1024", keyGenNoKeysz);
        if(output) {
            output(result);
        }

        /* 2048 bit */
        start = current_time(1);

        for(i = 0; i < genTimes; i++) {
            wc_InitRsaKey(&genKey, 0);
            wc_MakeRsaKey(&genKey, 2048, 65537, &rng);
            wc_FreeRsaKey(&genKey);
        }

        result->total = current_time(0) - start;
        each  = result->total / genTimes;  /* per second  */
        result->rate = each * 1000;   /* milliseconds */

        init_result(result, "RSA 2048", keyGenNoKeysz);
        if(output) {
            output(result);
        }

        return 0;
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

    /**
     * Wrapper function for bench_ntruBits.  This is for outputting both encrypt
     * and decrypt results.  Mainly used in run_benchmarks() and is the normal
     * output copies from original benchmark app.
     *
     *      result: Pointer to a benchResult object for storing the benchmark
     *              results.
     *      output: Function pointer to the output function to use for display.
     */
    int bench_ntru(benchResult* result, output_cb output)
    {
        int ret;
        word16 ntruBits;
        for(ntruBits = 128; ntruBits < 257; ntruBits += 64) {
            ret = bench_ntruBits(result, output, ntruBits, outputBoth);
            if(ret < 0) {
                return ret;
            }
        }

        return 0;
    }

    /**
     * Wrapper function for bench_ntruBits.  This is for outputting encrypt
     * results for 128 bits.  Use it to call from command line or to benchmark
     * a single aspect of NTRU.
     *
     *      result: Pointer to a benchResult object for storing the benchmark
     *              results.
     *      output: Function pointer to the output function to use for display.
     */
    int bench_ntru128E(benchResult* result, output_cb output)
    {
        return bench_ntruBits(result, output, 128, outputEncrypt);
    }

    /**
     * Wrapper function for bench_ntruBits.  This is for outputting decrypt
     * results for 128 bits.  Use it to call from command line or to benchmark
     * a single aspect of NTRU.
     *
     *      result: Pointer to a benchResult object for storing the benchmark
     *              results.
     *      output: Function pointer to the output function to use for display.
     */
    int bench_ntru128D(benchResult* result, output_cb output)
    {

        return bench_ntruBits(result, output, 128, outputDecrypt);
    }

    /**
     * Wrapper function for bench_ntruBits.  This is for outputting encrypt
     * results for 192 bits.  Use it to call from command line or to benchmark
     * a single aspect of NTRU.
     *
     *      result: Pointer to a benchResult object for storing the benchmark
     *              results.
     *      output: Function pointer to the output function to use for display.
     */
    int bench_ntru192E(benchResult* result, output_cb output)
    {
        return bench_ntruBits(result, output, 192, outputEncrypt);
    }

    /**
     * Wrapper function for bench_ntruBits.  This is for outputting decrypt
     * results for 192 bits.  Use it to call from command line or to benchmark
     * a single aspect of NTRU.
     *
     *      result: Pointer to a benchResult object for storing the benchmark
     *              results.
     *      output: Function pointer to the output function to use for display.
     */
    int bench_ntru192D(benchResult* result, output_cb output)
    {
        return bench_ntruBits(result, output, 192, outputDecrypt);
    }

    /**
     * Wrapper function for bench_ntruBits.  This is for outputting encrypt
     * results for 256 bits.  Use it to call from command line or to benchmark
     * a single aspect of NTRU.
     *
     *      result: Pointer to a benchResult object for storing the benchmark
     *              results.
     *      output: Function pointer to the output function to use for display.
     */
    int bench_ntru256E(benchResult* result, output_cb output)
    {
        return bench_ntruBits(result, output, 256, outputEncrypt);
    }

    /**
     * Wrapper function for bench_ntruBits.  This is for outputting decrypt
     * results for 256 bits.  Use it to call from command line or to benchmark
     * a single aspect of NTRU.
     *
     *      result: Pointer to a benchResult object for storing the benchmark
     *              results.
     *      output: Function pointer to the output function to use for display.
     */
    int bench_ntru256D(benchResult* result, output_cb output)
    {
        return bench_ntruBits(result, output, 256, outputDecrypt);
    }

    /**
     * Base NTRU benchmark function.  Use it in wrappers to call it with
     * different bits and whether to output encryption or decryption results.
     *
     *         result: Pointer to the result object.
     *         output: Function pointer to output functoin.
     *       ntruBits: The size in bits to run.
     *     outputType: Use outputType enum to determine what part of function to
     *                 output.
     */
    int bench_ntruBits(benchResult* result, output_cb output, word16 ntruBits,
                       int outputType)
    {
        int    i;
        double start, each;

        byte   public_key[1027];
        word16 public_key_len = sizeof(public_key);
        byte   private_key[1120];
        word16 private_key_len = sizeof(private_key);
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
        /* Set key size for result */
        result->keySize = ntruBits;

        ret = ntru_crypto_drbg_instantiate(ntruBits, wolfsslStr,
                sizeof(wolfsslStr), (ENTROPY_FN) GetEntropy, &drbg);
        if(ret != DRBG_OK) {
            printf("NTRU drbg instantiate failed\n");
            return ret;
        }

        /* set key sizes */
        ret = ntru_crypto_ntru_encrypt_keygen(drbg, type, &public_key_len,
                NULL, &private_key_len, NULL);
        if (ret != NTRU_OK) {
            ntru_crypto_drbg_uninstantiate(drbg);
            printf("NTRU failed to get key lengths\n");
            return ret;
        }

        ret = ntru_crypto_ntru_encrypt_keygen(drbg, type, &public_key_len,
                public_key, &private_key_len,
                private_key);

        ntru_crypto_drbg_uninstantiate(drbg);

        if (ret != NTRU_OK) {
            printf("NTRU keygen failed\n");
            return ret;
        }

        ret = ntru_crypto_drbg_instantiate(ntruBits, NULL, 0,
                (ENTROPY_FN)GetEntropy, &drbg);
        if (ret != DRBG_OK) {
            printf("NTRU error occurred during DRBG instantiation\n");
            return ret;
        }

        ret = ntru_crypto_ntru_encrypt(drbg, public_key_len, public_key,
                sizeof(aes_key), aes_key, &ciphertext_len, NULL);

        if (ret != NTRU_OK) {
            printf("NTRU error occurred requesting the buffer size"
                    " needed\n");
            return ret;
        }
        start = current_time(1);

        for (i = 0; i < ntimes; i++) {
            ret = ntru_crypto_ntru_encrypt(drbg, public_key_len, public_key,
                    sizeof(aes_key), aes_key, &ciphertext_len, ciphertext);
            if (ret != NTRU_OK) {
                printf("NTRU encrypt error\n");
                return ret;
            }
        }
        ret = ntru_crypto_drbg_uninstantiate(drbg);

        if (ret != DRBG_OK) {
            printf("NTRU error occurred uninstantiating the DRBG\n");
            return ret;
        }

        result->total = current_time(0) - start;
        each  = result->total / ntimes;   /* per second   */
        result->rate = each * 1000; /* milliseconds */

        if(outputType == outputEncrypt || outputType == outputBoth) {
            /* Only output encryption if results are wanted. */
            init_result(result, "NTRU", encryptMillisecond);
            if(output) {
                output(result);
            }
        }

        if(outputType == outputDecrypt || outputType == outputBoth)
        {
            /* Only decrypt if the results are wanted. */

            ret = ntru_crypto_ntru_decrypt(private_key_len, private_key,
                   ciphertext_len, ciphertext, &plaintext_len, NULL);

            if (ret != NTRU_OK) {
                printf("NTRU decrypt error occurred getting the buffer size"
                        " needed\n");
                return ret;
            }

            plaintext_len = sizeof(plaintext);
            start = current_time(1);

            for (i = 0; i < ntimes; i++) {
                ret = ntru_crypto_ntru_decrypt(private_key_len, private_key,
                        ciphertext_len, ciphertext,
                        &plaintext_len, plaintext);

                if (ret != NTRU_OK) {
                    printf("NTRU error occurred decrypting the key\n");
                    return ret;
                }
            }

            result->total = current_time(0) - start;
            each  = result->total / ntimes;   /* per second   */
            result->rate = each * 1000; /* milliseconds */

            init_result(result, "NTRU", decryptMillisecond);

            if(output) {
                output(result);
            }
        }

        return 0;
    }
    int bench_ntruKeyGen(benchResult* result, output_cb output)
    {
        word16 ntruBits;
        int ret;
        for(ntruBits = 128; ntruBits < 257; ntruBits += 64) {
            ret = bench_ntruKeyGenBits(result, output, ntruBits);
            if(ret < 0) {
                return ret;
            }
        }

        return 0;
    }
    int bench_ntruKeyGen128(benchResult* result, output_cb output)
    {
        word16 ntruBits = 128;
        return bench_ntruKeyGenBits(result, output, ntruBits);
    }
    int bench_ntruKeyGen192(benchResult* result, output_cb output)
    {
        word16 ntruBits = 192;
        return bench_ntruKeyGenBits(result, output, ntruBits);
    }
    int bench_ntruKeyGen256(benchResult* result, output_cb output)
    {
        word16 ntruBits = 256;
        return bench_ntruKeyGenBits(result, output, ntruBits);
    }
    int bench_ntruKeyGenBits(benchResult* result, output_cb output,
                             word16 ntruBits)
    {
        double start, each;
        int    i;

        byte   public_key[1027];
        word16 public_key_len = sizeof(public_key);
        byte   private_key[1120];
        word16 private_key_len = sizeof(private_key);
        word16 type     = 0;
        word32 ret;

        DRBG_HANDLE drbg;
        static uint8_t const pers_str[] = {
            'w', 'o', 'l', 'f',  'S', 'S', 'L', ' ', 't', 'e', 's', 't'
        };

        ret = ntru_crypto_drbg_instantiate(ntruBits, pers_str,
                sizeof(pers_str), GetEntropy, &drbg);
        if (ret != DRBG_OK) {
            printf("NTRU drbg instantiate failed\n");
            return ret;
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
        /* Set key size for result */
        result->keySize = ntruBits;
        /* set key sizes */
        ret = ntru_crypto_ntru_encrypt_keygen(drbg, type, &public_key_len,
                NULL, &private_key_len, NULL);
        start = current_time(1);

        for(i = 0; i < genTimes; i++) {
            ret = ntru_crypto_ntru_encrypt_keygen(drbg, type,
                    &public_key_len, public_key, &private_key_len,
                    private_key);
        }

        result->total = current_time(0) - start;

        if (ret != NTRU_OK) {
            printf("keygen failed\n");
            return ret;
        }

        ret = ntru_crypto_drbg_uninstantiate(drbg);

        if (ret != NTRU_OK) {
            printf("NTRU drbg uninstantiate failed\n");
            return ret;
        }

        each = result->total / genTimes;
        result->rate = each * 1000;

        init_result(result, "NTRU", keyGen);
        if(output) {
            output(result);
        }

        return 0;
    }
#endif

#ifdef HAVE_ECC
    int bench_eccKeyGen(benchResult* result, output_cb output)
    {
        ecc_key genKey;
        double start, each;
        int    i;

        /* 256 bit */
        start = current_time(1);

        for(i = 0; i < genTimes; i++) {
            wc_ecc_init(&genKey);
            wc_ecc_make_key(&rng, 32, &genKey);
            wc_ecc_free(&genKey);
        }

        result->total = current_time(0) - start;
        each  =  result->total / genTimes;  /* per second  */
        result->rate = each * 1000;   /* milliseconds */
        printf("\n");

        init_result(result, "ECC 256", keyGenNoKeysz);
        if(output) {
            output(result);
        }

        return 0;
    }


    int bench_eccKeyAgree(benchResult* result, output_cb output)
    {
        ecc_key genKey, genKey2;
        double start, each;
        int    i, ret;
        byte   shared[32];
#if !defined(NO_ASN) && !defined(NO_ECC_SIGN)
        byte   sig[64+16];  /* der encoding too */
#endif
        byte   digest[32];
        word32 x = 0;

        wc_ecc_init(&genKey);
        wc_ecc_init(&genKey2);

        ret = wc_ecc_make_key(&rng, 32, &genKey);
        if (ret != 0) {
            return ret;
        }
        ret = wc_ecc_make_key(&rng, 32, &genKey2);
        if (ret != 0) {
            return ret;
        }

        /* 256 bit */
        start = current_time(1);

        for(i = 0; i < agreeTimes; i++) {
            x = sizeof(shared);
            ret = wc_ecc_shared_secret(&genKey, &genKey2, shared, &x);
            if (ret != 0) {
                return ret;
            }
        }

        result->total = current_time(0) - start;
        each  = result->total / agreeTimes;  /* per second  */
        result->rate = each * 1000;   /* milliseconds */

        init_result(result, "EC-DHE", keyAgreeNoKeysz);
        if(output) {
            output(result);
        }

        /* make dummy digest */
        for (i = 0; i < (int)sizeof(digest); i++)
            digest[i] = (byte)i;


#if !defined(NO_ASN) && !defined(NO_ECC_SIGN)
        start = current_time(1);

        for(i = 0; i < agreeTimes; i++) {
            x = sizeof(sig);
            ret = wc_ecc_sign_hash(digest, sizeof(digest), sig, &x, &rng,
                    &genKey);
            if (ret != 0) {
                return ret;
            }
        }

        result->total = current_time(0) - start;
        each  = result->total / agreeTimes;  /* per second  */
        result->rate = each * 1000;   /* milliseconds */

        init_result(result, "EC-DSA", signTime);
        if(output) {
            output(result);
        }

        start = current_time(1);

        for(i = 0; i < agreeTimes; i++) {
            int verify = 0;
            ret = wc_ecc_verify_hash(sig, x, digest, sizeof(digest), &verify,
                    &genKey);
            if (ret != 0) {
                return ret;
            }
        }
#endif

        result->total = current_time(0) - start;
        each  = result->total / agreeTimes;  /* per second  */
        result->rate = each * 1000;     /* milliseconds */

        init_result(result, "EC-DSA", verifyTime);
        if(output) {
            output(result);
        }

        wc_ecc_free(&genKey2);
        wc_ecc_free(&genKey);

        return 0;
    }
#ifdef HAVE_ECC_ENCRYPT
    int bench_eccEncrypt(benchResult* result, output_cb output)
    {
        ecc_key userA, userB;
        byte    msg[48];
        byte    out[80];
        word32  outSz   = sizeof(out);
        word32  plainSz = sizeof(plain);
        int     ret, i;
        double start, each;

        wc_ecc_init(&userA);
        wc_ecc_init(&userB);

        wc_ecc_make_key(&rng, 32, &userA);
        wc_ecc_make_key(&rng, 32, &userB);

        for (i = 0; i < (int)sizeof(msg); i++)
            msg[i] = i;

        start = current_time(1);

        for(i = 0; i < ntimes; i++) {
            /* encrypt msg to B */
            ret = wc_ecc_encrypt(&userA, &userB, msg, sizeof(msg), out, &outSz,
                    NULL);
            if (ret != 0) {
                return ret;
            }
        }

        result->total = current_time(0) - start;
        each  = result->total / ntimes;  /* per second  */
        result->rate = each * 1000;   /* milliseconds */

        init_result(result, "ECC", encryptNoKeysz);
        if(output) {
            output(result);
        }

        start = current_time(1);

        for(i = 0; i < ntimes; i++) {
            /* decrypt msg from A */
            ret = wc_ecc_decrypt(&userB, &userA, out, outSz, plain, &plainSz,
                    NULL);
            if (ret != 0) {
                return ret;
            }
        }

        result->total = current_time(0) - start;
        each  = result->total / ntimes;  /* per second  */
        result->rate = each * 1000;   /* milliseconds */

        init_result(result, "ECC", decryptNoKeysz);
        if(output) {
            output(result);
        }

        /* cleanup */
        wc_ecc_free(&userB);
        wc_ecc_free(&userA);

        return 0;
    }
#endif
#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519
    int bench_curve25519KeyGen(benchResult* result, output_cb output)
    {
        curve25519_key genKey;
        double start, each;
        int    i;

        /* 256 bit */
        start = current_time(1);

        for(i = 0; i < genTimes; i++) {
            wc_curve25519_make_key(&rng, 32, &genKey);
            wc_curve25519_free(&genKey);
        }

        result->total = current_time(0) - start;
        each  = result->total / genTimes;  /* per second  */
        result->rate = each * 1000;   /* milliseconds */
        printf("\n");

        init_result(result, "CURVE255", keyGenNoKeysz);
        if(output) {
            output(result);
        }

        return 0;
    }

#ifdef HAVE_CURVE25519_SHARED_SECRET
    int bench_curve25519KeyAgree(benchResult* result, output_cb output)
    {
        curve25519_key genKey, genKey2;
        double start, each;
        int    i, ret;
        byte   shared[32];
        word32 x = 0;

        wc_curve25519_init(&genKey);
        wc_curve25519_init(&genKey2);

        ret = wc_curve25519_make_key(&rng, 32, &genKey);
        if (ret != 0) {
            return ret;
        }
        ret = wc_curve25519_make_key(&rng, 32, &genKey2);
        if (ret != 0) {
            return ret;
        }

        /* 256 bit */
        start = current_time(1);

        for(i = 0; i < agreeTimes; i++) {
            x = sizeof(shared);
            ret = wc_curve25519_shared_secret(&genKey, &genKey2, shared, &x);
            if (ret != 0) {
                return ret;
            }
        }

        result->total = current_time(0) - start;
        each  = result->total / agreeTimes;  /* per second  */
        result->rate = each * 1000;   /* milliseconds */

        init_result(result, "CURVE255", keyAgreeNoKeysz);
        if(output) {
            output(result);
        }

        wc_curve25519_free(&genKey2);
        wc_curve25519_free(&genKey);

        return 0;
    }
#endif /* HAVE_CURVE25519_SHARED_SECRET */
#endif /* HAVE_CURVE25519 */

#ifdef HAVE_ED25519
    int bench_ed25519KeyGen(benchResult* result, output_cb output)
    {
        ed25519_key genKey;
        double start, each;
        int    i;

        /* 256 bit */
        start = current_time(1);

        for(i = 0; i < genTimes; i++) {
            wc_ed25519_init(&genKey);
            wc_ed25519_make_key(&rng, 32, &genKey);
            wc_ed25519_free(&genKey);
        }

        result->total = current_time(0) - start;
        each  = result->total / genTimes;  /* per second  */
        result->rate = each * 1000;   /* milliseconds */
        printf("\n");

        init_result(result, "ED25519", keyGenNoKeysz);
        if(output) {
            output(result);
        }

        return 0;
    }


    int bench_ed25519KeySign(benchResult* result, output_cb output)
    {
        int    ret;
        ed25519_key genKey;
#ifdef HAVE_ED25519_SIGN
        double start, each;
        int    i;
        byte   sig[ED25519_SIG_SIZE];
        byte   msg[512];
        word32 x = 0;
#endif

        wc_ed25519_init(&genKey);

        ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &genKey);
        if (ret != 0) {
            return ret;
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
                return ret;
            }
        }

        result->total = current_time(0) - start;
        each  = result->total / agreeTimes;  /* per second  */
        result->rate = each * 1000;   /* milliseconds */

        init_result(result, "ED25519", signTime);
        if(output) {
            output(result);
        }

#ifdef HAVE_ED25519_VERIFY
        start = current_time(1);

        for(i = 0; i < agreeTimes; i++) {
            int verify = 0;
            ret = wc_ed25519_verify_msg(sig, x, msg, sizeof(msg), &verify,
                    &genKey);
            if (ret != 0 || verify != 1) {
                return ret;
            }
        }

        result->total = current_time(0) - start;
        each  = result->total / agreeTimes;  /* per second  */
        result->rate = each * 1000;     /* milliseconds */

        init_result(result, "ED25519", verifyTime);
        if(output) {
            output(result);
        }

#endif /* HAVE_ED25519_VERIFY */
#endif /* HAVE_ED25519_SIGN */

        wc_ed25519_free(&genKey);

        return 0;
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

#elif defined(WOLFSSL_IAR_ARM_TIME) || defined (WOLFSSL_MDK_ARM) ||\
defined(WOLFSSL_USER_CURRTIME)
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

