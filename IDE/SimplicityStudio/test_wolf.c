/* test_wolf.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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

/* Example for running wolfCrypt test and benchmark from
 * SiLabs Simplicity Studio's CLI example */

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfcrypt/test/test.h>
#include <wolfcrypt/benchmark/benchmark.h>
#include <stdio.h>

#include "sl_cli.h"
#include "sl_cli_instances.h"
#include "sl_cli_arguments.h"
#include "sl_cli_handles.h"

#ifndef NO_CRYPT_TEST
typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;

static func_args args = { 0 };
#endif

void wolf_test(sl_cli_command_arg_t *arguments)
{
    int ret;
#ifndef NO_CRYPT_TEST
    wolfCrypt_Init();

    printf("\nCrypt Test\n");
    wolfcrypt_test(&args);
    ret = args.return_code;
    printf("Crypt Test: Return code %d\n", ret);

    wolfCrypt_Cleanup();
#else
    ret = NOT_COMPILED_IN;
#endif
    (void)arguments;
    (void)ret;
}

void wolf_bench(sl_cli_command_arg_t *arguments)
{
    int ret;
#ifndef NO_CRYPT_BENCHMARK
    wolfCrypt_Init();

    printf("\nBenchmark Test\n");
    benchmark_test(&args);
    ret = args.return_code;
    printf("Benchmark Test: Return code %d\n", ret);

    wolfCrypt_Cleanup();
#else
    ret = NOT_COMPILED_IN;
#endif
    (void)arguments;
    (void)ret;
}

/* ecc key gen, sign and verify examples */
#define TEST_ECC_KEYSZ    32
#define TEST_DATA_SIZE    128
#define TEST_KEYGEN_TRIES 100
#define TEST_ECDSA_TRIES  100

void wolf_ecc_test(sl_cli_command_arg_t *arguments)
{
    int ret = 0, i, j;
    byte data[TEST_DATA_SIZE];
    word32 dataLen = (word32)sizeof(data);
    byte sig[ECC_MAX_SIG_SIZE];
    word32 sigLen;
    WC_RNG rng;
    ecc_key eccKey;

    memset(&rng, 0, sizeof(rng));
    memset(&eccKey, 0, sizeof(eccKey));

    wolfSSL_Debugging_ON();

    wolfCrypt_Init();

    /* test data */
    for (i=0; i<(int)dataLen; i++) {
        data[i] = (byte)i;
    }

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        goto exit;
    }

    for (i=0; i<TEST_KEYGEN_TRIES; i++) {
        ret = wc_ecc_init_ex(&eccKey, NULL, 0);
        if (ret == 0) {
#if (_SILICON_LABS_SECURITY_FEATURE == _SILICON_LABS_SECURITY_FEATURE_VAULT)
            /* Load ecc_key with vault's public key.
             * When only the public area of a key is loaded silabs_ecc.c
             * (silabs_ecc_sign_hash) will use the vault key to sign */
            ret = silabs_ecc_load_vault(&eccKey);
#else
            ret = wc_ecc_make_key(&rng, TEST_ECC_KEYSZ, &eccKey);
#endif
        }

        for (j=0; j<TEST_ECDSA_TRIES; j++) {
            if (ret == 0) {
                /* generate signature using ecc key */
                sigLen = (word32)sizeof(sig);

                ret = wc_SignatureGenerate(
                    WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_ECC,
                    data, dataLen,
                    sig, &sigLen,
                    &eccKey, (word32)sizeof(eccKey),
                    &rng);
            }
            if (ret == 0) {
                ret = wc_SignatureVerify(
                    WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_ECC,
                    data, dataLen,
                    sig, sigLen,
                    &eccKey, (word32)sizeof(eccKey));
            }

            if (ret == 0) {
                fprintf(stderr, "Verification Passed %d %d\n", i, j);
            }
            else {
                fprintf(stderr, "Verification failed!! (ret %d) %d %d\n",
                    ret, i, j);
                break;
            }
        } /* sign/verify tries */

        wc_ecc_free(&eccKey);
        if (ret != 0)
            break;
    } /* key gen tries */

exit:
    wc_FreeRng(&rng);

    wolfCrypt_Cleanup();

    (void)arguments;
}
