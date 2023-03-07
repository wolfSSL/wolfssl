/* clu_rsa.c
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
#include <wolfclu/wolfclu/pkey/clu_pkey.h>
#include <wolfclu/wolfclu/x509/clu_cert.h>
#include <wolfclu/wolfclu/x509/clu_parse.h>

#ifndef WOLFCLU_NO_FILESYSTEM

static const struct option rsa_options[] = {
    {"-in",        required_argument, 0, WOLFCLU_INFILE    },
    {"-inform",    required_argument, 0, WOLFCLU_INFORM    },
    {"-out",       required_argument, 0, WOLFCLU_OUTFILE   },
    {"-outform",   required_argument, 0, WOLFCLU_OUTFORM   },
    {"-passin",    required_argument, 0, WOLFCLU_PASSWORD  },
    {"-noout",     no_argument,       0, WOLFCLU_NOOUT     },
    {"-modulus",   no_argument,       0, WOLFCLU_MODULUS   },
    {"-RSAPublicKey_in", no_argument, 0, WOLFCLU_RSAPUBIN  },
    {"-help",      no_argument,       0, WOLFCLU_HELP      },
    {"-h",         no_argument,       0, WOLFCLU_HELP      },

    {0, 0, 0, 0} /* terminal element */
};


static void wolfCLU_RSAHelp(void)
{
    WOLFCLU_LOG(WOLFCLU_L0, "./wolfssl rsa");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-in file input for key to read");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-inform PEM or DER input format");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-out file to write result to (defaults to stdout)");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-outform PEM or DER output format");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-passin password for PEM encrypted files");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-noout do not print the key out when set");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-modulus print out the RSA modulus (n value)");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-RSAPublicKey_in expecting a public key input");
}
#endif /* WOLFCLU_NO_FILESYSTEM */

int wolfCLU_RSA(int argc, char** argv)
{
#ifndef WOLFCLU_NO_FILESYSTEM
    char *pass = NULL;
    char password[MAX_PASSWORD_SIZE];
    int passwordSz = MAX_PASSWORD_SIZE;
    int ret     = WOLFCLU_SUCCESS;
    int inForm  = PEM_FORM;
    int outForm = PEM_FORM;
    int printModulus = 0;
    int pubOnly = 0;
    int noOut = 0;
    int option;
    int longIndex = 1;
    WOLFSSL_BIO *bioIn  = NULL;
    WOLFSSL_BIO *bioOut = NULL;
    WOLFSSL_RSA *rsa = NULL;

    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at indent 0 */
    while ((option = wolfCLU_GetOpt(argc, argv, "",
                   rsa_options, &longIndex )) != -1) {
        switch (option) {
            case WOLFCLU_INFILE:
                bioIn = wolfSSL_BIO_new_file(optarg, "rb");
                if (bioIn == NULL) {
                    wolfCLU_LogError("unable to open key file %s",
                            optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_OUTFILE:
                bioOut = wolfSSL_BIO_new_file(optarg, "wb");
                if (bioOut == NULL) {
                    wolfCLU_LogError("unable to open out file %s",
                            optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_INFORM:
                inForm = wolfCLU_checkInform(optarg);
                break;

            case WOLFCLU_OUTFORM:
                outForm = wolfCLU_checkInform(optarg);
                break;

            case WOLFCLU_PASSWORD:
                passwordSz = MAX_PASSWORD_SIZE;
                ret = wolfCLU_GetPassword(password, &passwordSz, optarg);
                pass = password;
                break;

            case WOLFCLU_MODULUS:
                printModulus = 1;
                break;

            case WOLFCLU_RSAPUBIN:
                pubOnly = 1;
                break;

            case WOLFCLU_NOOUT:
                noOut = 1;
                break;

            case WOLFCLU_HELP:
                wolfCLU_RSAHelp();
                return WOLFCLU_SUCCESS;

            case ':':
            case '?':
                break;

            default:
                /* do nothing. */
                (void)ret;
        }
    }

    /* read in the RSA key */
    if (ret == WOLFCLU_SUCCESS && bioIn != NULL) {
        if (inForm == PEM_FORM) {
            if (pubOnly) {
                rsa = wolfSSL_PEM_read_bio_RSA_PUBKEY(bioIn, NULL, NULL, pass);
            }
            else {
                rsa = wolfSSL_PEM_read_bio_RSAPrivateKey(bioIn, NULL, NULL, pass);
            }
        }
        else {
            if (pubOnly) {
                unsigned char *der;
                const unsigned char **pp;
                long derSz;

                derSz = wolfSSL_BIO_get_len(bioIn);
                der = (unsigned char*)XMALLOC(derSz, HEAP_HINT,
                        DYNAMIC_TYPE_PUBLIC_KEY);
                if (der == NULL) {
                    ret = WOLFCLU_FATAL_ERROR;
                }
                else {
                    if (wolfSSL_BIO_read(bioIn, der, (int)derSz) != derSz) {
                        ret = WOLFCLU_FATAL_ERROR;
                    }

                    if (ret == WOLFCLU_SUCCESS) {
                        pp = (const unsigned char**)&der;
                        rsa = wolfSSL_d2i_RSAPublicKey(NULL, pp, derSz);
                    }
                    XFREE(der, HEAP_HINT, DYNAMIC_TYPE_PUBLICKEY);
                }
            }
            else {
                rsa = wolfSSL_d2i_RSAPrivateKey_bio(bioIn, NULL);
            }
        }

        if (rsa == NULL) {
            wolfCLU_LogError("error reading key from file");
            ret = USER_INPUT_ERROR;
        }
    }

    /* print to stdout if no -out was used */
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

    /* print out the key */
    if (ret == WOLFCLU_SUCCESS && noOut == 0) {
        unsigned char *der = NULL;
        unsigned char *pt; /* use pt with i2d to handle potential pointer
                              increment */
        int derSz = 0;
        int pemType;
        int heapType;

        if (pubOnly) {
            heapType = DYNAMIC_TYPE_PUBLIC_KEY;
            pemType  = PUBLICKEY_TYPE;

            derSz = wolfSSL_i2d_RSAPublicKey(rsa, NULL);
            if (derSz < 0) {
                ret = WOLFCLU_FATAL_ERROR;
            }

            if (ret == WOLFCLU_SUCCESS) {
                der = (unsigned char*)XMALLOC(derSz, HEAP_HINT, heapType);
                if (der == NULL) {
                    ret = WOLFCLU_FATAL_ERROR;
                }
            }

            if (ret == WOLFCLU_SUCCESS) {
                pt    = der;
                derSz = wolfSSL_i2d_RSAPublicKey(rsa, &pt);
            }
        }
        else {
            heapType = DYNAMIC_TYPE_PRIVATE_KEY;
            pemType  = RSA_TYPE;

            derSz = wolfSSL_i2d_RSAPrivateKey(rsa, NULL);
            if (derSz < 0) {
                ret = WOLFCLU_FATAL_ERROR;
            }

            if (ret == WOLFCLU_SUCCESS) {
                der = (unsigned char*)XMALLOC(derSz, HEAP_HINT, heapType);
                if (der == NULL) {
                    ret = WOLFCLU_FATAL_ERROR;
                }
            }

            if (ret == WOLFCLU_SUCCESS) {
                pt    = der;
                derSz = wolfSSL_i2d_RSAPrivateKey(rsa, &pt);
            }
        }

        if (outForm == PEM_FORM) {
            ret = wolfCLU_printDer(bioOut, der, derSz, pemType, heapType);
        }
        else {
            wolfSSL_BIO_write(bioOut, der, derSz);
        }

        if (der != NULL) {
            wolfCLU_ForceZero(der, derSz);
            XFREE(der, HEAP_HINT, heapType);
        }
    }

    /* print out the modulus */
    if (ret == WOLFCLU_SUCCESS && printModulus == 1) {
        const WOLFSSL_BIGNUM *n = NULL;
        char *hex;

        wolfSSL_RSA_get0_key(rsa, &n, NULL, NULL);
        hex = wolfSSL_BN_bn2hex(n);
        if (hex != NULL) {
            if (wolfSSL_BIO_write(bioOut, "Modulus=", (int)XSTRLEN("Modulus="))
                    <= 0) {
                ret = WOLFCLU_FATAL_ERROR;
            }

            if (ret == WOLFCLU_SUCCESS &&
                    wolfSSL_BIO_write(bioOut, hex, (int)XSTRLEN(hex)) <= 0) {
                ret = WOLFCLU_FATAL_ERROR;
            }
            XFREE(hex, NULL, DYNAMIC_TYPE_OPENSSL);
        }
    }

    wolfSSL_BIO_free(bioIn);
    wolfSSL_BIO_free(bioOut);
    wolfSSL_RSA_free(rsa);

    return ret;
#else
    (void)argc;
    (void)argv;
    WOLFCLU_LOG(WOLFCLU_E0, "No filesystem support");
    return WOLFCLU_FATAL_ERROR;
#endif
}

