/* clu_benchmark.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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

#include <wolfclu/wolfclu/clu_header_main.h>


#define DES3_BLOCK_SIZE 24

#ifdef HAVE_BLAKE2

#endif /* HAVE_BLAKE2 */

/*
 * benchmarking funciton
 */
int wolfCLU_benchmark(int timer, int* option)
{
    int i              =   0;       /* A looping variable */

    int     loop       =   1;       /* benchmarking loop */
    int64_t blocks     =   0;       /* blocks used during benchmarking */
#ifndef NO_AES
    Aes aes;                        /* aes declaration */
#endif

#ifndef NO_DES3
    Des3 des3;                      /* 3des declaration */
#endif

    WC_RNG rng;                     /* random number generator */

    double          stop = 0.0;     /* stop breaks loop */
    double          start;          /* start time */
    double          currTime;       /* current time*/


    ALIGN16 byte*   plain;          /* plain text */
    ALIGN16 byte*   cipher;         /* cipher */
    ALIGN16 byte*   key;            /* key for testing */
    ALIGN16 byte*   iv;             /* iv for initial encoding */

    byte*           digest;         /* message digest */

    wc_InitRng(&rng);

    /* @fragile:
     * this function assumes that it perfectly knows the order and length of
     * the option array in clu_src/benchmark/clu_bench_setup.c. Looping over a
     * switch on an enum would be much more robust.
     */

    i = 0;
#ifndef NO_AES
    /* aes test */
    if (option[i] == 1) {
        plain = XMALLOC(AES_BLOCK_SIZE, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (plain == NULL) {
            return MEMORY_E;
        }
        cipher = XMALLOC(AES_BLOCK_SIZE, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (cipher == NULL) {
            wolfCLU_freeBins(plain, NULL, NULL, NULL, NULL);
            return MEMORY_E;
        }
        key = XMALLOC(AES_BLOCK_SIZE, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (key == NULL) {
            wolfCLU_freeBins(plain, cipher, NULL, NULL, NULL);
            return MEMORY_E;
        }
        iv = XMALLOC(AES_BLOCK_SIZE, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (iv == NULL) {
            wolfCLU_freeBins(plain, cipher, key, NULL, NULL);
            return MEMORY_E;
        }

        wc_RNG_GenerateBlock(&rng, plain, AES_BLOCK_SIZE);
        wc_RNG_GenerateBlock(&rng, cipher, AES_BLOCK_SIZE);
        wc_RNG_GenerateBlock(&rng, key, AES_BLOCK_SIZE);
        wc_RNG_GenerateBlock(&rng, iv, AES_BLOCK_SIZE);
        start = wolfCLU_getTime();

        wc_AesSetKey(&aes, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);

        while (loop) {
            wc_AesCbcEncrypt(&aes, cipher, plain, AES_BLOCK_SIZE);
            blocks++;
            currTime = wolfCLU_getTime();
            stop = currTime - start;
            /* if stop >= timer, loop = 0 */
            loop = (stop >= timer) ? 0 : 1;
        }
        printf("\n");
        printf("AES-CBC ");
        wolfCLU_stats(start, AES_BLOCK_SIZE, blocks);
        XMEMSET(plain, 0, AES_BLOCK_SIZE);
        XMEMSET(cipher, 0, AES_BLOCK_SIZE);
        XMEMSET(key, 0, AES_BLOCK_SIZE);
        XMEMSET(iv, 0, AES_BLOCK_SIZE);
        wolfCLU_freeBins(plain, cipher, key, iv, NULL);
        blocks = 0;
        loop = 1;
    }
    i++;
#endif
#ifdef WOLFSSL_AES_COUNTER
    /* aes-ctr test */
    if (option[i] == 1) {
        plain = XMALLOC(AES_BLOCK_SIZE, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (plain == NULL) {
            return MEMORY_E;
        }
        cipher = XMALLOC(AES_BLOCK_SIZE, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (cipher == NULL) {
            wolfCLU_freeBins(plain, NULL, NULL, NULL, NULL);
            return MEMORY_E;
        }
        key = XMALLOC(AES_BLOCK_SIZE, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (key == NULL) {
            wolfCLU_freeBins(plain, cipher, NULL, NULL, NULL);
            return MEMORY_E;
        }
        iv = XMALLOC(AES_BLOCK_SIZE, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (iv == NULL) {
            wolfCLU_freeBins(plain, cipher, key, NULL, NULL);
            return MEMORY_E;
        }

        wc_RNG_GenerateBlock(&rng, plain, AES_BLOCK_SIZE);
        wc_RNG_GenerateBlock(&rng, cipher, AES_BLOCK_SIZE);
        wc_RNG_GenerateBlock(&rng, key, AES_BLOCK_SIZE);
        wc_RNG_GenerateBlock(&rng, iv, AES_BLOCK_SIZE);
        start = wolfCLU_getTime();

        wc_AesSetKeyDirect(&aes, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
        while (loop) {
            wc_AesCtrEncrypt(&aes, cipher, plain, AES_BLOCK_SIZE);
            blocks++;
            currTime = wolfCLU_getTime();
            stop = currTime - start;
            /* if stop >= timer, loop = 0 */
            loop = (stop >= timer) ? 0 : 1;
        }
        printf("AES-CTR ");
        wolfCLU_stats(start, AES_BLOCK_SIZE, blocks);
        XMEMSET(plain, 0, AES_BLOCK_SIZE);
        XMEMSET(cipher, 0, AES_BLOCK_SIZE);
        XMEMSET(key, 0, AES_BLOCK_SIZE);
        XMEMSET(iv, 0, AES_BLOCK_SIZE);
        wolfCLU_freeBins(plain, cipher, key, iv, NULL);
        blocks = 0;
        loop = 1;
    }
    i++;
#endif
#ifndef NO_DES3
    /* 3des test */
    if (option[i] == 1) {
        plain = XMALLOC(DES3_BLOCK_SIZE, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (plain == NULL) {
            return MEMORY_E;
        }
        cipher = XMALLOC(DES3_BLOCK_SIZE, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (cipher == NULL) {
            wolfCLU_freeBins(plain, NULL, NULL, NULL, NULL);
            return MEMORY_E;
        }
        key = XMALLOC(DES3_BLOCK_SIZE, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (key == NULL) {
            wolfCLU_freeBins(plain, cipher, NULL, NULL, NULL);
            return MEMORY_E;
        }
        iv = XMALLOC(DES3_BLOCK_SIZE, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (iv == NULL) {
            wolfCLU_freeBins(plain, cipher, key, NULL, NULL);
            return MEMORY_E;
        }

        wc_RNG_GenerateBlock(&rng, plain, DES3_BLOCK_SIZE);
        wc_RNG_GenerateBlock(&rng, cipher, DES3_BLOCK_SIZE);
        wc_RNG_GenerateBlock(&rng, key, DES3_BLOCK_SIZE);
        wc_RNG_GenerateBlock(&rng, iv, DES3_BLOCK_SIZE);

        start = wolfCLU_getTime();

        wc_Des3_SetKey(&des3, key, iv, DES_ENCRYPTION);
        while (loop) {
            wc_Des3_CbcEncrypt(&des3, cipher, plain, DES3_BLOCK_SIZE);
            blocks++;
            currTime = wolfCLU_getTime();
            stop = currTime - start;
            /* if stop >= timer, loop = 0 */
            loop = (stop >= timer) ? 0 : 1;
        }
        printf("3DES ");
        wolfCLU_stats(start, DES3_BLOCK_SIZE, blocks);
        XMEMSET(plain, 0, DES3_BLOCK_SIZE);
        XMEMSET(cipher, 0, DES3_BLOCK_SIZE);
        XMEMSET(key, 0, DES3_BLOCK_SIZE);
        XMEMSET(iv, 0, DES3_BLOCK_SIZE);
        wolfCLU_freeBins(plain, cipher, key, iv, NULL);
        blocks = 0;
        loop = 1;
    }
    i++;
#endif
#ifdef HAVE_CAMELLIA
    #define CAM_SZ CAMELLIA_BLOCK_SIZE
    /* camellia test */
    if (option[i] == 1) {
        Camellia camellia;

        plain = XMALLOC(CAM_SZ, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (plain == NULL) {
            return MEMORY_E;
        }
        cipher = XMALLOC(CAM_SZ, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (cipher == NULL) {
            wolfCLU_freeBins(plain, NULL, NULL, NULL, NULL);
            return MEMORY_E;
        }
        key = XMALLOC(CAM_SZ, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (key == NULL) {
            wolfCLU_freeBins(plain, cipher, NULL, NULL, NULL);
            return MEMORY_E;
        }
        iv = XMALLOC(CAM_SZ, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (iv == NULL) {
            wolfCLU_freeBins(plain, cipher, key, NULL, NULL);
            return MEMORY_E;
        }

        wc_RNG_GenerateBlock(&rng, plain, CAMELLIA_BLOCK_SIZE);
        wc_RNG_GenerateBlock(&rng, cipher, CAMELLIA_BLOCK_SIZE);
        wc_RNG_GenerateBlock(&rng, key, CAMELLIA_BLOCK_SIZE);
        wc_RNG_GenerateBlock(&rng, iv, CAMELLIA_BLOCK_SIZE);

        start = wolfCLU_getTime();

        wc_CamelliaSetKey(&camellia, key, CAMELLIA_BLOCK_SIZE, iv);
        while (loop) {
            wc_CamelliaCbcEncrypt(&camellia, cipher, plain, CAMELLIA_BLOCK_SIZE);
            blocks++;
            currTime = wolfCLU_getTime();
            stop = currTime - start;
            /* if stop >= timer, loop = 0 */
            loop = (stop >= timer) ? 0 : 1;
        }
        printf("Camellia ");
        wolfCLU_stats(start, CAMELLIA_BLOCK_SIZE, blocks);
        XMEMSET(plain, 0, CAMELLIA_BLOCK_SIZE);
        XMEMSET(cipher, 0, CAMELLIA_BLOCK_SIZE);
        XMEMSET(key, 0, CAMELLIA_BLOCK_SIZE);
        XMEMSET(iv, 0, CAMELLIA_BLOCK_SIZE);
        wolfCLU_freeBins(plain, cipher, key, iv, NULL);
        blocks = 0;
        loop = 1;
    }
    i++;
#endif
#ifndef NO_MD5
    /* md5 test */
    if (option[i] == 1) {
        wc_Md5 md5;

        digest = XMALLOC(WC_MD5_DIGEST_SIZE, HEAP_HINT,
                         DYNAMIC_TYPE_TMP_BUFFER);
        if (digest == NULL)
            return MEMORY_E;
        plain = XMALLOC(BYTE_UNIT, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (plain == NULL) {
            wolfCLU_freeBins(digest, NULL, NULL, NULL, NULL);
            return MEMORY_E;
        }
        wc_RNG_GenerateBlock(&rng, plain, BYTE_UNIT);

        wc_InitMd5(&md5);
        start = wolfCLU_getTime();

        while (loop) {
            wc_Md5Update(&md5, plain, BYTE_UNIT);
            blocks++;
            currTime = wolfCLU_getTime();
            stop = currTime - start;
            /* if stop >= timer, loop = 0 */
            loop = (stop >= timer) ? 0 : 1;
        }
        wc_Md5Final(&md5, digest);
        printf("MD5 ");
        wolfCLU_stats(start, BYTE_UNIT, blocks);
        XMEMSET(plain, 0, BYTE_UNIT);
        XMEMSET(digest, 0, WC_MD5_DIGEST_SIZE);
        wolfCLU_freeBins(digest, plain, NULL, NULL, NULL);
        blocks = 0;
        loop = 1;
    }
    i++;
#endif
#ifndef NO_SHA
    /* sha test */
    if (option[i] == 1) {
        wc_Sha sha;

        digest = XMALLOC(WC_SHA_DIGEST_SIZE, HEAP_HINT,
                         DYNAMIC_TYPE_TMP_BUFFER);
        if (digest == NULL)
            return MEMORY_E;
        plain = XMALLOC(BYTE_UNIT, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (plain == NULL) {
            wolfCLU_freeBins(digest, NULL, NULL, NULL, NULL);
            return MEMORY_E;
        }
        wc_RNG_GenerateBlock(&rng, plain, BYTE_UNIT);

        wc_InitSha(&sha);
        start = wolfCLU_getTime();

        while (loop) {
            wc_ShaUpdate(&sha, plain, BYTE_UNIT);
            blocks++;
            currTime = wolfCLU_getTime();
            stop = currTime - start;
            /* if stop >= timer, loop = 0 */
            loop = (stop >= timer) ? 0 : 1;
        }
        wc_ShaFinal(&sha, digest);
        printf("Sha ");
        wolfCLU_stats(start, BYTE_UNIT, blocks);
        XMEMSET(plain, 0, BYTE_UNIT);
        XMEMSET(digest, 0, WC_SHA_DIGEST_SIZE);
        wolfCLU_freeBins(plain, digest, NULL, NULL, NULL);
        blocks = 0;
        loop = 1;
    }
    i++;
#endif
#ifndef NO_SHA256
    #define SHA256_SZ WC_SHA256_DIGEST_SIZE
    /* sha256 test */
    if (option[i] == 1) {
        wc_Sha256 sha256;

        digest = XMALLOC(SHA256_SZ, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (digest == NULL)
            return MEMORY_E;
        plain = XMALLOC(BYTE_UNIT, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (plain == NULL) {
            wolfCLU_freeBins(digest, NULL, NULL, NULL, NULL);
            return MEMORY_E;
        }

        wc_RNG_GenerateBlock(&rng, plain, BYTE_UNIT);

        wc_InitSha256(&sha256);
        start = wolfCLU_getTime();

        while (loop) {
            wc_Sha256Update(&sha256, plain, BYTE_UNIT);
            blocks++;
            currTime = wolfCLU_getTime();
            stop = currTime - start;
            /* if stop >= timer, loop = 0 */
            loop = (stop >= timer) ? 0 : 1;
        }
        wc_Sha256Final(&sha256, digest);
        printf("Sha256 ");
        wolfCLU_stats(start, BYTE_UNIT, blocks);
        XMEMSET(plain, 0, BYTE_UNIT);
        XMEMSET(digest, 0, WC_SHA256_DIGEST_SIZE);
        wolfCLU_freeBins(plain, digest, NULL, NULL, NULL);
        /* resets used for debug, uncomment if needed */
        blocks = 0;
        loop = 1;
    }
    i++;
#endif
#ifdef WOLFSSL_SHA384
    #define SHA384_SZ WC_SHA384_DIGEST_SIZE
    /* sha384 test */
    if (option[i] == 1) {
        wc_Sha384 sha384;

        digest = XMALLOC(SHA384_SZ, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (digest == NULL)
            return MEMORY_E;
        plain = XMALLOC(BYTE_UNIT, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (plain == NULL) {
            wolfCLU_freeBins(digest, NULL, NULL, NULL, NULL);
            return MEMORY_E;
        }

        wc_RNG_GenerateBlock(&rng, plain, BYTE_UNIT);

        wc_InitSha384(&sha384);
        start = wolfCLU_getTime();

        while (loop) {
            wc_Sha384Update(&sha384, plain, BYTE_UNIT);
            blocks++;
            currTime = wolfCLU_getTime();
            stop = currTime - start;
            /* if stop >= timer, loop = 0 */
            loop = (stop >= timer) ? 0 : 1;
        }
        wc_Sha384Final(&sha384, digest);
        printf("Sha384 ");
        wolfCLU_stats(start, BYTE_UNIT, blocks);
        XMEMSET(plain, 0, BYTE_UNIT);
        XMEMSET(digest, 0, WC_SHA384_DIGEST_SIZE);
        wolfCLU_freeBins(plain, digest, NULL, NULL, NULL);
        blocks = 0;
        loop = 1;
    }
    i++;
#endif
#ifdef WOLFSSL_SHA512
    #define SHA512_SZ WC_SHA512_DIGEST_SIZE
    /* sha512 test */
    if (option[i] == 1) {
        wc_Sha512 sha512;

        digest = XMALLOC(SHA512_SZ, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (digest == NULL)
            return MEMORY_E;
        plain = XMALLOC(BYTE_UNIT, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (plain == NULL) {
            wolfCLU_freeBins(digest, NULL, NULL, NULL, NULL);
            return MEMORY_E;
        }

        wc_RNG_GenerateBlock(&rng, plain, BYTE_UNIT);

        wc_InitSha512(&sha512);
        start = wolfCLU_getTime();

        while (loop) {
            wc_Sha512Update(&sha512, plain, BYTE_UNIT);
            blocks++;
            currTime = wolfCLU_getTime();
            stop = currTime - start;
            /* if stop >= timer, loop = 0 */
            loop = (stop >= timer) ? 0 : 1;
        }
        wc_Sha512Final(&sha512, digest);
        printf("Sha512 ");
        wolfCLU_stats(start, BYTE_UNIT, blocks);
        XMEMSET(plain, 0, BYTE_UNIT);
        XMEMSET(digest, 0, WC_SHA512_DIGEST_SIZE);
        wolfCLU_freeBins(plain, digest, NULL, NULL, NULL);
        blocks = 0;
        loop = 1;
    }
    i++;
#endif
#ifdef HAVE_BLAKE2
    /* blake2b test */
    if (option[i] == 1) {
        Blake2b  b2b;

        digest = XMALLOC(BLAKE2B_OUTBYTES, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (digest == NULL)
            return MEMORY_E;
        plain = XMALLOC(BYTE_UNIT, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (plain == NULL) {
            wolfCLU_freeBins(digest, NULL, NULL, NULL, NULL);
            return MEMORY_E;
        }

        wc_RNG_GenerateBlock(&rng, plain, BYTE_UNIT);

        wc_InitBlake2b(&b2b, BLAKE2B_OUTBYTES);
        start = wolfCLU_getTime();

        while (loop) {
            wc_Blake2bUpdate(&b2b, plain, BYTE_UNIT);
            blocks++;
            currTime = wolfCLU_getTime();
            stop = currTime - start;
            /* if stop >= timer, loop = 0 */
            loop = (stop >= timer) ? 0 : 1;
        }
        wc_Blake2bFinal(&b2b, digest, BLAKE2B_OUTBYTES);
        printf("Blake2b ");
        wolfCLU_stats(start, BYTE_UNIT, blocks);
        XMEMSET(plain, 0, BYTE_UNIT);
        XMEMSET(digest, 0, BLAKE2B_OUTBYTES);
        wolfCLU_freeBins(digest, plain, NULL, NULL, NULL);
    }
#endif
    wc_FreeRng(&rng);
    (void)blocks;
    (void)loop;
    return WOLFCLU_SUCCESS;
}
