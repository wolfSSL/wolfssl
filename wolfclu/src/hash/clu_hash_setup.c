/* clu_hash_setup.c
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

/*
 * hash argument function
 * return WOLFCLU_SUCCESS on success
 */
int wolfCLU_hashSetup(int argc, char** argv)
{
#ifndef WOLFCLU_NO_FILESYSTEM
    WOLFSSL_BIO *bioIn = NULL;
    WOLFSSL_BIO *bioOut = NULL;

    int     ret        =   WOLFCLU_SUCCESS;
    int     i          =   0;   /* loop variable */
    const char* algs[]  =   {   /* list of acceptable algorithms */
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
#ifndef NO_CODING
    #ifdef WOLFSSL_BASE64_ENCODE
        "base64enc",
    #endif
        "base64dec",
#endif
        NULL /* terminal element (also stops the array from being 0-size */
    };
    size_t algsSz = sizeof(algs) / sizeof(algs[0]) - 1; /* -1 to ignore NULL */

    char*   alg;                /* algorithm being used */
    int     algCheck=   0;      /* acceptable algorithm check */
    int     inCheck =   0;      /* input check */
    int     size    =   0;      /* message digest size */

#ifdef HAVE_BLAKE2
    size = BLAKE2B_OUTBYTES;
#endif

    /* help checking */
    ret = wolfCLU_checkForArg("-help", 5, argc, argv);
    if (ret > 0) {
        wolfCLU_hashHelp();
        return WOLFCLU_SUCCESS;
    }

    for (i = 0; i < (int)algsSz; ++i) {
        /* checks for acceptable algorithms */
        if (XSTRNCMP(argv[2], algs[i], XSTRLEN(algs[i])) == 0) {
            alg = argv[2];
            algCheck = 1;
        }
    }

    if (algCheck == 0) {
        wolfCLU_LogError("Invalid algorithm");
        return WOLFCLU_FATAL_ERROR;
    }

    /* returns location of the arg in question if present */
    ret = wolfCLU_checkForArg("-in", 3, argc, argv);
    if (ret > 0) {
        bioIn = wolfSSL_BIO_new_file(argv[ret+1], "rb");
        if (bioIn == NULL) {
            wolfCLU_LogError("unable to open file %s", argv[ret+1]);
            return USER_INPUT_ERROR;
        }
        inCheck = 1;
    }

    ret = wolfCLU_checkForArg("-out", 4, argc, argv);
    if (ret > 0) {
        bioOut = wolfSSL_BIO_new_file(argv[ret+1], "wb");
        if (bioOut == NULL) {
            wolfCLU_LogError("unable to open output file %s",
                    argv[ret+1]);
            return USER_INPUT_ERROR;
        }
    }

    ret = wolfCLU_checkForArg("-size", 5, argc, argv);
    if (ret > 0) {
        /* size of output */
#ifndef HAVE_BLAKE2
        wolfCLU_LogError("%s: -size is only valid when blake2 is enabled.",
                argv[0]);
#else
        size = XATOI(argv[ret+1]);
        if (size <= 0 || size > 64) {
            wolfCLU_LogError("Invalid size, Must be between 1-64. Using default.");
            size = BLAKE2B_OUTBYTES;
        }
#endif
    }

    if (inCheck == 0) {
        wolfCLU_LogError("Must have input as either a file or standard I/O");
        return WOLFCLU_FATAL_ERROR;
    }

    /* sets default size of algorithm */
#ifndef NO_MD5
    if (XSTRNCMP(alg, "md5", 3) == 0)
        size = WC_MD5_DIGEST_SIZE;
#endif

#ifndef NO_SHA
    if (XSTRNCMP(alg, "sha", 3) == 0)
        size = WC_SHA_DIGEST_SIZE;
#endif

#ifndef NO_SHA256
    if (XSTRNCMP(alg, "sha256", 6) == 0)
        size = WC_SHA256_DIGEST_SIZE;
#endif

#ifdef WOLFSSL_SHA384
    if (XSTRNCMP(alg, "sha384", 6) == 0)
        size = WC_SHA384_DIGEST_SIZE;
#endif

#ifdef WOLFSSL_SHA512
    if (XSTRNCMP(alg, "sha512", 6) == 0)
        size = WC_SHA512_DIGEST_SIZE;
#endif

    /* hashing function */
    ret = wolfCLU_hash(bioIn, bioOut, alg, size);
    wolfSSL_BIO_free(bioIn);
    wolfSSL_BIO_free(bioOut);

    return ret;
#else
    (void)argc;
    (void)argv;
    WOLFCLU_LOG(WOLFCLU_E0, "No filesystem support");
    return WOLFCLU_FATAL_ERROR;
#endif
}
