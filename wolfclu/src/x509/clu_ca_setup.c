/* clu_ca_setup.c
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
#include <wolfclu/wolfclu/x509/clu_request.h>
#include <wolfclu/wolfclu/x509/clu_cert.h>
#include <wolfclu/wolfclu/x509/clu_x509_sign.h>
#include <wolfclu/wolfclu/certgen/clu_certgen.h>

#ifndef WOLFCLU_NO_FILESYSTEM

static const struct option ca_options[] = {
    {"-in",        required_argument, 0, WOLFCLU_INFILE    },
    {"-out",       required_argument, 0, WOLFCLU_OUTFILE   },
    {"-keyfile",   required_argument, 0, WOLFCLU_KEY       },
    {"-cert",      required_argument, 0, WOLFCLU_CAFILE    },
    {"-extensions",required_argument, 0, WOLFCLU_EXTENSIONS},
    {"-md",        required_argument, 0, WOLFCLU_MD        },
    {"-inform",    required_argument, 0, WOLFCLU_INFORM    },
    {"-config",    required_argument, 0, WOLFCLU_CONFIG },
    {"-days",      required_argument, 0, WOLFCLU_DAYS },
    {"-selfsign",  no_argument, 0, WOLFCLU_SELFSIGN },
    {"-h",         no_argument, 0, WOLFCLU_HELP },
    {"-help",      no_argument, 0, WOLFCLU_HELP },

    {0, 0, 0, 0} /* terminal element */
};

static void wolfCLU_CAHelp(void)
{
    WOLFCLU_LOG(WOLFCLU_L0, "./wolfssl ca");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-in CSR file input");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-out file to output to");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-keyfile file to read private key from");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-cert file to read CA from");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-extensions section in config file to parse extensions from");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-md type of hash i.e sha256");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-inform type PEM/DER of CSR input");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-config file to read configuration from");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-days number of days for certificate to be valid");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-selfsign sign with key associated with cert");
}
#endif

/* return WOLFCLU_SUCCESS on success */
int wolfCLU_CASetup(int argc, char** argv)
{
#ifndef WOLFCLU_NO_FILESYSTEM
    WOLFCLU_CERT_SIGN* signer = NULL;
    WOLFSSL_BIO *keyIn  = NULL;
    WOLFSSL_BIO *reqIn  = NULL;
    WOLFSSL_X509 *x509  = NULL;
    WOLFSSL_X509 *ca    = NULL;
    WOLFSSL_EVP_PKEY* pkey = NULL;
    enum wc_HashType hashType = WC_HASH_TYPE_NONE;

    int   ret = WOLFCLU_SUCCESS;
    char* out = NULL;
    char* config = NULL;
    char* ext = NULL;

    int inForm  = PEM_FORM;
    int option;
    int longIndex = 1;
    int days = 0;
    int selfSigned = 0;

    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at indent 0 */
    while ((option = wolfCLU_GetOpt(argc, argv, "", ca_options,
                    &longIndex )) != -1) {

        switch (option) {
            case WOLFCLU_INFILE:
                reqIn = wolfSSL_BIO_new_file(optarg, "rb");
                if (reqIn == NULL) {
                    wolfCLU_LogError("Unable to open CSR file %s",
                            optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_SELFSIGN:
                selfSigned = 1;
                break;

            case WOLFCLU_KEY:
                keyIn = wolfSSL_BIO_new_file(optarg, "rb");
                if (keyIn == NULL) {
                    wolfCLU_LogError("Unable to open private key file %s",
                            optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_CAFILE:
                ca = wolfSSL_X509_load_certificate_file(optarg,
                        WOLFSSL_FILETYPE_PEM);
                if (ca == NULL) {
                    wolfCLU_LogError("Unable to open ca file %s",
                            optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_MD:
                hashType = wolfCLU_StringToHashType(optarg);
                if (hashType == WC_HASH_TYPE_NONE) {
                    wolfCLU_LogError("Invalid digest name");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_OUTFILE:
                out = optarg;
                break;

            case WOLFCLU_INFORM:
                inForm = wolfCLU_checkInform(optarg);
                break;

            case WOLFCLU_CONFIG:
                config = optarg;
                break;

            case WOLFCLU_DAYS:
                days = XATOI(optarg);
                break;

            case WOLFCLU_EXTENSIONS:
                ext = optarg;
                break;

            case WOLFCLU_HELP:
                wolfCLU_CAHelp();
                return WOLFCLU_SUCCESS;

            case ':':
            case '?':
                wolfCLU_LogError("Unexpected argument");
                ret = WOLFCLU_FATAL_ERROR;
                wolfCLU_CAHelp();
                break;

            default:
                /* do nothing. */
                (void)ret;
        }
    }

    if (reqIn == NULL) {
        wolfCLU_LogError("Expecting CSR input");
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS && config != NULL) {
        signer = wolfCLU_readSignConfig(config, (char*)"ca");
    }
    else {
        signer = wolfCLU_CertSignNew();
    }
    if (signer == NULL) {
        wolfCLU_LogError("Unable to create a signer struct");
        ret = WOLFCLU_FATAL_ERROR;
    }

    /* override hash type if -md was passed in */
    if (ret == WOLFCLU_SUCCESS && hashType != WC_HASH_TYPE_NONE) {
        wolfCLU_CertSignSetHash(signer, hashType);
    }

    if (ret == WOLFCLU_SUCCESS && keyIn != NULL) {
        pkey = wolfSSL_PEM_read_bio_PrivateKey(keyIn, NULL, NULL, NULL);
        if (pkey == NULL) {
            wolfCLU_LogError("Error reading key from file");
            ret = USER_INPUT_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS && out != NULL) {
        ret = wolfCLU_CertSignAppendOut(signer, out);
    }

    if (ret == WOLFCLU_SUCCESS && days > 0) {
        wolfCLU_CertSignSetDate(signer, days);
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (inForm == PEM_FORM) {
            wolfSSL_PEM_read_bio_X509_REQ(reqIn, &x509, NULL, NULL);
        }
        else {
            wolfSSL_d2i_X509_REQ_bio(reqIn, &x509);
        }
        if (x509 == NULL) {
            wolfCLU_LogError("Issue creating structure to use");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS && (pkey != NULL || ca != NULL)) {
        if (selfSigned) {
            wolfCLU_CertSignSetCA(signer, x509, pkey,
                    wolfCLU_GetTypeFromPKEY(pkey));
        }
        else {
            wolfCLU_CertSignSetCA(signer, ca, pkey,
                    wolfCLU_GetTypeFromPKEY(pkey));
        }
    }

    /* default to version 3 which supports extensions */
    if (ret == WOLFCLU_SUCCESS &&
           wolfSSL_X509_set_version(x509, WOLFSSL_X509_V3) != WOLFSSL_SUCCESS) {
        wolfCLU_LogError("Unable to set version 3 for cert");
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS && ext != NULL) {
        wolfCLU_CertSignSetExt(signer, ext);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfCLU_CertSign(signer, x509);
    }

    wolfSSL_BIO_free(reqIn);
    wolfSSL_BIO_free(keyIn);
    if (!selfSigned) {
        wolfSSL_X509_free(x509);
    }

    /* check for success on signer free since random data is output */
    if (wolfCLU_CertSignFree(signer) != WOLFCLU_SUCCESS) {
        ret = WOLFCLU_FATAL_ERROR;
    }
    return ret;
#else
    (void)argc;
    (void)argv;
    WOLFCLU_LOG(WOLFCLU_E0, "No filesystem support");
    return WOLFCLU_FATAL_ERROR;
#endif
}
