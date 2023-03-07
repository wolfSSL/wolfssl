/* clu_ecparam.c
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
#include <wolfclu/wolfclu/genkey/clu_genkey.h>
#include <wolfclu/wolfclu/x509/clu_cert.h>    /* PER_FORM/DER_FORM */
#include <wolfclu/wolfclu/clu_optargs.h>

#ifndef MAX_TERM_WIDTH
#define MAX_TERM_WIDTH 80
#endif

static const struct option ecparam_options[] = {
    {"-in",        required_argument, 0, WOLFCLU_INFILE    },
    {"-out",       required_argument, 0, WOLFCLU_OUTFILE   },
    {"-inform",    required_argument, 0, WOLFCLU_INFORM    },
    {"-outform",   required_argument, 0, WOLFCLU_OUTFORM   },
    {"-genkey",    no_argument,       0, WOLFCLU_GEN_KEY    },
    {"-name",      required_argument, 0, WOLFCLU_CURVE_NAME },
    {"-text",      no_argument,       0, WOLFCLU_TEXT_OUT },

    {0, 0, 0, 0} /* terminal element */
};


static void wolfCLU_ecparamNamesPrint(void)
{
#if defined(HAVE_FIPS) && \
    defined(HAVE_FIPS_VERSION) && FIPS_VERSION_LT(4,0)
    const int maxId = ECC_BRAINPOOLP512R1;
#else
    const int maxId = ECC_CURVE_MAX;
#endif
    int id;

    WOLFCLU_LOG(WOLFCLU_L0, "\tname options:");
    for (id = 0; id < maxId; id++) {
        const char* name = wc_ecc_get_name(id);
        if (name != NULL && XSTRNCMP(name, "SAKKE", 5) != 0) {
            WOLFCLU_LOG(WOLFCLU_L0, "\t\t%s", wc_ecc_get_name(id));
        }
    }
}

static void wolfCLU_ecparamHelp(void)
{
    WOLFCLU_LOG(WOLFCLU_L0, "./wolfssl ecparam");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-genkey create new key");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-out output file");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-name curve name i.e. secp384r1");
    wolfCLU_ecparamNamesPrint();
}


/* return WOLFCLU_SUCCESS on success */
int wolfCLU_ecparam(int argc, char** argv)
{
    char* name = NULL;
    char* out  = NULL;    /* default output file name */
    int   ret        = WOLFCLU_SUCCESS;
    int   longIndex  = 1;
    int   genKey     = 0;
    int   textOut    = 0;
    int   outForm    = PEM_FORM;
    int   inForm     = PEM_FORM;
    int   i, option;
    WC_RNG rng;
    WOLFSSL_BIO* in = NULL;
    WOLFSSL_BIO* bioOut = NULL;
    WOLFSSL_EC_KEY* key = NULL;

    if (wolfCLU_checkForArg("-h", 2, argc, argv) > 0) {
        wolfCLU_ecparamHelp();
        return WOLFCLU_SUCCESS;
    }

    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at indent 0 */
    while ((option = wolfCLU_GetOpt(argc, argv, "",
                   ecparam_options, &longIndex )) != -1) {

        switch (option) {
            case WOLFCLU_OUTFILE:
                out = optarg;
                break;

            case WOLFCLU_INFILE:
#ifdef WOLFCLU_NO_FILESYSTEM
            WOLFCLU_LOG(WOLFCLU_E0, "No filesystem support. Unable to open input file");
            ret = WOLFCLU_FATAL_ERROR;
#else
                in = wolfSSL_BIO_new_file(optarg, "rb");
                if (in == NULL) {
                    wolfCLU_LogError("Error opening file %s", optarg);
                    ret = USER_INPUT_ERROR;
                }
#endif
                break;

            case WOLFCLU_OUTFORM:
                outForm = wolfCLU_checkOutform(optarg);
                if (outForm < 0) {
                    wolfCLU_LogError("bad outform");
                    ret = USER_INPUT_ERROR;
                }
                break;

            case WOLFCLU_INFORM:
                inForm = wolfCLU_checkInform(optarg);
                if (inForm < 0) {
                    wolfCLU_LogError("bad inform");
                    ret = USER_INPUT_ERROR;
                }
                break;

            case WOLFCLU_GEN_KEY:
                genKey = 1;
                break;

            case WOLFCLU_TEXT_OUT:
                textOut = 1;
                break;

            case WOLFCLU_CURVE_NAME:
                if (name != NULL) {
                    XFREE(name, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                }
                name = (char*)XMALLOC(ECC_MAXNAME, HEAP_HINT,
                        DYNAMIC_TYPE_TMP_BUFFER);
                if (name == NULL) {
                    ret = MEMORY_E;
                    break;
                }
                XSTRNCPY(name, optarg, ECC_MAXNAME);

                /* convert name to upper case */
                for (i = 0; i < (int)XSTRLEN(name); i++)
                    (void)toupper(name[i]);

                #if 0
                /* way to get the key size if needed in the future */
                keySz = wc_ecc_get_curve_size_from_name(name);
                #endif

                break;

            case ':':
            case '?':
                break;

            default:
                /* do nothing. */
                (void)ret;
        }
    }

    if (wc_InitRng(&rng) != 0) {
        ret = WOLFCLU_FAILURE;
    }

    if (ret == WOLFCLU_SUCCESS && in != NULL) {
        WOLFSSL_EVP_PKEY* pkey = NULL;
        if (inForm == PEM_FORM) {
            pkey = wolfSSL_PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
        }
        else {
            pkey = wolfSSL_d2i_PrivateKey_bio(in, NULL);
        }
        if (pkey == NULL) {
            wolfCLU_LogError("Error reading key from file");
            ret = USER_INPUT_ERROR;
        }

        if (ret == WOLFCLU_SUCCESS) {
            key = wolfSSL_EVP_PKEY_get1_EC_KEY(pkey);
        }
        wolfSSL_EVP_PKEY_free(pkey);
    }

    if (ret == WOLFCLU_SUCCESS && genKey) {
        key = wolfCLU_GenKeyECC(name);
        if (key == NULL) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS && key == NULL) {
        wolfCLU_LogError("Unable to parse or create key information");
        ret = WOLFCLU_FATAL_ERROR;
    }

    /* print out the key */
    if (ret == WOLFCLU_SUCCESS && out != NULL) {
#ifdef WOLFCLU_NO_FILESYSTEM
        WOLFCLU_LOG(WOLFCLU_E0, "No filesystem support. Unable to open input file");
        ret = WOLFCLU_FATAL_ERROR;
#else
        bioOut = wolfSSL_BIO_new_file(out, "wb");
        if (bioOut == NULL) {
            ret = WOLFCLU_FATAL_ERROR;
        }
#endif
    }

    if (ret == WOLFCLU_SUCCESS && out == NULL) {
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

    if (ret == WOLFCLU_SUCCESS && key != NULL && textOut) {
        const char* idName = NULL;
        char txt[MAX_TERM_WIDTH];
        const WOLFSSL_EC_GROUP* group;

        group = wolfSSL_EC_KEY_get0_group(key);
        if (group != NULL) {
            idName = wc_ecc_get_name(wc_ecc_get_curve_id(group->curve_idx));
            if (idName != NULL) {
                XSNPRINTF(txt, MAX_TERM_WIDTH, "Curve Name : %s\n",
                        idName);
                wolfSSL_BIO_write(bioOut, txt, (int)XSTRLEN(txt));
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS && key != NULL) {
        wolfCLU_EcparamPrintOID(bioOut, key, outForm);
    }

    if (ret == WOLFCLU_SUCCESS && key != NULL && genKey) {
        if (outForm == PEM_FORM) {
            if (wolfSSL_PEM_write_bio_ECPrivateKey(bioOut, key,
                    NULL, NULL, 0, NULL, NULL) != WOLFSSL_SUCCESS) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        else {
            byte* der = NULL;
            int   derSz;

            derSz = wolfSSL_i2d_ECPrivateKey(key, &der);
            if (derSz > 0) {
                if (wolfSSL_BIO_write(bioOut, der, derSz)
                        != derSz) {
                    wolfCLU_LogError("issue writing out data");
                    ret = WOLFCLU_FATAL_ERROR;
                }
            }

            if (der != NULL) {
                /* der was created by wolfSSL library so we assume
                 * that XMALLOC was used and call XFREE here */
                XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            }
        }
    }


    if (name != NULL) {
        XFREE(name, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }

    wolfSSL_EC_KEY_free(key);
    wolfSSL_BIO_free(bioOut);
    wolfSSL_BIO_free(in);
    wc_FreeRng(&rng);
    return ret;
}

