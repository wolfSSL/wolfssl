/* clu_bench_setup.c
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

int wolfCLU_benchSetup(int argc, char** argv)
{
    int     ret     =   0;          /* return variable */
    int     time    =   3;          /* timer variable */
    int     i, j    =   0;          /* second loop variable */
    const char* algs[]  = {         /* list of acceptable algorithms */
#ifndef NO_AES
        "aes-cbc",
#endif
#ifdef WOLFSSL_AES_COUNTER
        "aes-ctr",
#endif
#ifndef NO_DES3
        "3des",
#endif
#ifdef HAVE_CAMELLIA
        "camellia",
#endif
#ifndef NO_MD5
        "md5",
#endif
#ifndef NO_SHA
        "sha",
#endif
#ifndef NO_SHA256
        "sha256",
#endif
#ifdef WOLFSSL_SHA384
        "sha384",
#endif
#ifdef WOLFSSL_SHA512
        "sha512",
#endif
#ifdef HAVE_BLAKE2
        "blake2b",
#endif
        NULL /* terminal argument (also stops us from having an empty list) */
    };
    size_t algsSz = sizeof(algs) / sizeof(algs[0]) - 1; /* -1 to ignore NULL */

    /* acceptable options */
    int option[sizeof(algs) / sizeof(algs[0])] = {0};

    /* acceptable option check */
    int optionCheck = 0;

    ret = wolfCLU_checkForArg("-help", 5, argc, argv);
    if (ret > 0) {
            wolfCLU_benchHelp();
            return 0;
    }

    ret = wolfCLU_checkForArg("-time", 5, argc, argv);
    if (ret > 0) {
        /* time for each test in seconds */
        time = XATOI(argv[ret+1]);
        if (time < 1 || time > 10) {
            printf("Invalid time, must be between 1-10. Using default"
                                            " of three seconds.\n");
            time = 3;
        }
    }

    ret = wolfCLU_checkForArg("-all", 4, argc, argv);
    if (ret > 0) {
        /* perform all available tests */
        for (j = 0; j < (int)algsSz; j++) {
            option[j] = 1;
            optionCheck = 1;
        }
    }

    /* pull as many of the algorithms out of the argv as posible */
    for (i = 0; i < (int)algsSz; ++i) {
        ret = wolfCLU_checkForArg(algs[i], (int)XSTRLEN(algs[i]), argc, argv);
        if (ret > 0) {
            option[i] = 1;
            optionCheck = 1;
        }
    }

    if (optionCheck != 1) {
        wolfCLU_help();
        ret = 0;
    }
    else {
        /* benchmarking function */
        printf("\nTesting for %d second(s)\n", time);
        ret = wolfCLU_benchmark(time, option);
    }
    return ret;
}
