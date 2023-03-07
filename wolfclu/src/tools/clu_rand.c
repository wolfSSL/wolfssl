/* clu_rand.c
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

static const struct option rand_options[] = {
    {"-out",    required_argument, 0, WOLFCLU_OUTFILE},
    {"-base64", no_argument,       0, WOLFCLU_BASE64 },

    {0, 0, 0, 0} /* terminal element */
};

static void wolfCLU_RandHelp(void)
{
    WOLFCLU_LOG(WOLFCLU_L0, "wolfssl rand <num bytes>");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-out the file to output data to (default to stdout)");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-base64 output the results in base64 encoding");
}


int wolfCLU_Rand(int argc, char** argv)
{
#ifndef WC_NO_RNG
    int ret       = WOLFCLU_SUCCESS;
    int useBase64 = 0;
    int size      = 0;
    int option;
    int longIndex = 1;
    WOLFSSL_BIO *bioOut = NULL;
    byte *buf = NULL;

    /* last parameter is the rand bytes output size */
    if (XSTRNCMP("-h", argv[argc-1], 2) == 0) {
        wolfCLU_RandHelp();
        return WOLFCLU_SUCCESS;
    }
    else {
        size = XATOI(argv[argc-1]);
        if (size <= 0) {
            wolfCLU_LogError("Unable to convert %s to a number",
                    argv[argc-1]);
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at indent 0 */
    while ((option = wolfCLU_GetOpt(argc, argv, "",
                   rand_options, &longIndex )) != -1) {
        switch (option) {
            case WOLFCLU_BASE64:
                useBase64 = 1;
                break;

            case WOLFCLU_OUTFILE:
#ifdef WOLFCLU_NO_FILESYSTEM
                WOLFCLU_LOG(WOLFCLU_E0, "No filesystem support. Unable to open input file");
                ret = WOLFCLU_FATAL_ERROR;
#else
                bioOut = wolfSSL_BIO_new_file(optarg, "wb");
                if (bioOut == NULL) {
                    wolfCLU_LogError("Unable to open output file %s",
                            optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
#endif
                break;

            case WOLFCLU_HELP:
                wolfCLU_RandHelp();
                return WOLFCLU_SUCCESS;

            case ':':
            case '?':
                break;

            default:
                /* do nothing. */
                (void)ret;
        }
    }


    if (ret == WOLFCLU_SUCCESS) {
        buf = (byte*)XMALLOC(size, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (buf == NULL) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        WC_RNG rng;
        if (wc_InitRng(&rng) != 0) {
            wolfCLU_LogError("Unable to initialize RNG");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            if (wc_RNG_GenerateBlock(&rng, buf, size) != 0) {
                wolfCLU_LogError("Unable to generate RNG block");
                ret = WOLFCLU_FATAL_ERROR;
            }
            wc_FreeRng(&rng);
        }
    }

    /* setup output bio to stdout if not set */
    if (ret == WOLFCLU_SUCCESS && bioOut == NULL) {
        bioOut = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
        if (bioOut == NULL) {
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            if (wolfSSL_BIO_set_fp(bioOut, stdout, BIO_NOCLOSE)
                    != WOLFSSL_SUCCESS) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    /* check and convert to base64 */
    if (ret == WOLFCLU_SUCCESS && useBase64) {
        byte *base64 = NULL;
        word32 base64Sz;

        if (Base64_Encode(buf, size, NULL, &base64Sz) != LENGTH_ONLY_E) {
            wolfCLU_LogError("Error getting size for base64");
            ret = WOLFCLU_FATAL_ERROR;
        }

        base64 = (byte*)XMALLOC(base64Sz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (base64 == NULL) {
            wolfCLU_LogError("Error malloc'ing for base64");
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (Base64_Encode(buf, size, base64, &base64Sz) != 0) {
            wolfCLU_LogError("Error base64 encoding");
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (ret == WOLFCLU_SUCCESS) {
            wolfCLU_ForceZero(buf, size);
            XFREE(buf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            buf  = base64;
            size = base64Sz;
        }
        else {
            XFREE(base64, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }

    /* write out the results */
    if (ret == WOLFCLU_SUCCESS) {
        if (wolfSSL_BIO_write(bioOut, buf, size) != size) {
            wolfCLU_LogError("Error writing out RNG data");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (buf != NULL) {
        wolfCLU_ForceZero(buf, size);
        XFREE(buf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    wolfSSL_BIO_free(bioOut);

    return ret;
#else
    wolfCLU_LogError("Recompile wolfSSL with RNG support");
    return WOLFCLU_FATAL_ERROR;
#endif
}

