/* clu_alg_hash.c
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
#include <wolfclu/wolfclu/clu_log.h>
#include <wolfclu/wolfclu/clu_optargs.h>

#define MAX_BUFSIZE 8192

int wolfCLU_algHashSetup(int argc, char** argv, int algorithm)
{
#ifndef WOLFCLU_NO_FILESYSTEM
    WOLFSSL_BIO *bioIn  = NULL;
    WOLFSSL_BIO *bioOut = NULL;
    int     ret         = 0;    /* return variable */
    int     size        = 0;    /* message digest size */
    char*   alg;                /* algorithm being used */

    switch (algorithm) {
        case WOLFCLU_MD5:
        #ifndef NO_MD5
            alg = (char*)"md5";
            size = WC_MD5_DIGEST_SIZE;
            break;
        #endif

        case WOLFCLU_CERT_SHA256:
        #ifndef NO_SHA256
            alg = (char*)"sha256";
            size = WC_SHA256_DIGEST_SIZE;
            break;
        #endif

        case WOLFCLU_CERT_SHA384:
        #ifdef WOLFSSL_SHA384
            alg = (char*)"sha384";
            size = WC_SHA384_DIGEST_SIZE;
            break;
        #endif

        case WOLFCLU_CERT_SHA512:
        #ifdef WOLFSSL_SHA512
            alg = (char*)"sha512";
            size = WC_SHA512_DIGEST_SIZE;
            break;
        #endif

        default:
            wolfCLU_LogError("Please reconfigure wolfSSL with support for that algorithm");
            return NOT_COMPILED_IN;

    }

    /* was a file input provided? if so read from file */
    if (argc >= 3) {
        bioIn = wolfSSL_BIO_new_file(argv[2], "rb");
        if (bioIn == NULL) {
            wolfCLU_LogError("unable to open file %s", argv[2]);
            return USER_INPUT_ERROR;
        }
    }

    /* hashing function */
    ret = wolfCLU_hash(bioIn, bioOut, alg, size);
    wolfSSL_BIO_free(bioIn);

    return ret;
#else
    (void)argc;
    (void)argv;
    (void)algorithm;
    WOLFCLU_LOG(WOLFCLU_E0, "No filesystem support");
    return WOLFCLU_FATAL_ERROR;
#endif
}

