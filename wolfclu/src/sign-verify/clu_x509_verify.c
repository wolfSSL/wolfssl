/* clu_x509_verify.c
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
#include <wolfclu/wolfclu/sign-verify/clu_verify.h>
#include <wolfclu/wolfclu/x509/clu_cert.h>

#ifndef WOLFCLU_NO_FILESYSTEM

static const struct option verify_options[] = {
    {"-CAfile",        required_argument, 0, WOLFCLU_CAFILE        },
    {"-crl_check",     no_argument,       0, WOLFCLU_CHECK_CRL     },
    {"-partial_chain", no_argument,       0, WOLFCLU_PARTIAL_CHAIN },
    {"-help",          no_argument,       0, WOLFCLU_HELP          },
    {"-h",             no_argument,       0, WOLFCLU_HELP          },

    {0, 0, 0, 0} /* terminal element */
};


static void wolfCLU_x509VerifyHelp(void)
{
    WOLFCLU_LOG(WOLFCLU_L0, "./wolfssl verify -CAfile <ca file name> "
            "[-crl_check] [-partial_chain] <cert to verify>");
}
#endif

int wolfCLU_x509Verify(int argc, char** argv)
{
#ifndef WOLFCLU_NO_FILESYSTEM
    int ret    = WOLFCLU_SUCCESS;
    int inForm = PEM_FORM;
    int crlCheck     = 0;
    int partialChain = 0;
    int longIndex    = 1;
    int option;
    char* caCert     = NULL;
    char* verifyCert = NULL;
    WOLFSSL_X509_STORE*  store = NULL;
    WOLFSSL_X509_LOOKUP* lookup = NULL;

    /* last parameter is the certificate to verify */
    if (XSTRNCMP("-h", argv[argc-1], 2) == 0) {
        wolfCLU_x509VerifyHelp();
        return WOLFCLU_SUCCESS;
    }
    else {
        verifyCert = argv[argc-1];
        if (verifyCert == NULL) {
            wolfCLU_LogError("Unable to open certificate file %s",
                             argv[argc-1]);
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        WOLFCLU_LOG(WOLFCLU_L0, "verifying certificate file %s", verifyCert);

        opterr = 0; /* do not display unrecognized options */
        optind = 0; /* start at indent 0 */
        while ((option = wolfCLU_GetOpt(argc - 1, argv, "",
                       verify_options, &longIndex )) != -1) {
            switch (option) {
                case WOLFCLU_CHECK_CRL:
                #ifndef HAVE_CRL
                    wolfCLU_LogError("recompile wolfSSL with CRL");
                    ret = WOLFCLU_FATAL_ERROR;
                #endif
                    crlCheck = 1;
                    break;

                case WOLFCLU_CAFILE:
                    WOLFCLU_LOG(WOLFCLU_L0, "using CA file %s", optarg);
                    caCert = optarg;
                    break;

                case WOLFCLU_PARTIAL_CHAIN:
                    partialChain = 1;
                    break;

                case WOLFCLU_INFORM:
                    inForm = wolfCLU_checkInform(optarg);
                    break;

                case WOLFCLU_HELP:
                    wolfCLU_x509VerifyHelp();
                    return WOLFCLU_SUCCESS;

                case ':':
                case '?':
                    break;

                default:
                    /* do nothing. */
                    (void)ret;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        store = wolfSSL_X509_STORE_new();
        if (store == NULL) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (inForm != PEM_FORM) {
            wolfCLU_LogError("Only handling PEM CA files");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        lookup = wolfSSL_X509_STORE_add_lookup(store,
                wolfSSL_X509_LOOKUP_file());
        if (lookup == NULL) {
            wolfCLU_LogError("Failed to setup lookup");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* Confirm CA file is root CA unless partialChain enabled */
    if (ret == WOLFCLU_SUCCESS){
        if (!partialChain && caCert != NULL){
            int error;

            error = wolfSSL_CertManagerVerify(store->cm, caCert,
                    WOLFSSL_FILETYPE_PEM);

            if (error != ASN_SELF_SIGNED_E) {
                wolfCLU_LogError("CA file is not root CA");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                /*
                 * We're expecting these errors, since root certs are
                 * self-signed so remove them from the error queue.
                 */
                if (wolfSSL_ERR_peek_error() == -ASN_NO_SIGNER_E) {
                    wolfSSL_ERR_get_error();
                    if (wolfSSL_ERR_peek_error() == -ASN_SELF_SIGNED_E) {
                        wolfSSL_ERR_get_error();
                    }
                }
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS && caCert != NULL) {
        if (wolfSSL_X509_LOOKUP_load_file(lookup, caCert, X509_FILETYPE_PEM)
                != WOLFSSL_SUCCESS) {
            wolfCLU_LogError("Failed to load CA file");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }


#ifdef HAVE_CRL
    if (ret == WOLFCLU_SUCCESS) {
        if (crlCheck) {
            if (wolfSSL_CertManagerEnableCRL(store->cm, WOLFSSL_CRL_CHECKALL)
                    != WOLFSSL_SUCCESS) {
                wolfCLU_LogError("Failed to enable CRL use");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        else {
            if (wolfSSL_CertManagerDisableCRL(store->cm) != WOLFSSL_SUCCESS) {
                wolfCLU_LogError("Failed to disable CRL use");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }
#endif

    if (ret == WOLFCLU_SUCCESS) {
        int err;

        err = wolfSSL_CertManagerVerify(store->cm, verifyCert,
                WOLFSSL_FILETYPE_PEM);
        if (err == ASN_NO_PEM_HEADER) {
            /* most likely the file was DER if PEM header not found */
            err = wolfSSL_CertManagerVerify(store->cm, verifyCert,
                    WOLFSSL_FILETYPE_ASN1);
        }
        if (err != WOLFSSL_SUCCESS) {
            wolfCLU_LogError("Verification Failed\nErr (%d): %s",
                             err, wolfSSL_ERR_reason_error_string(err));
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            WOLFCLU_LOG(WOLFCLU_L0, "OK");
        }
    }

    wolfSSL_X509_STORE_free(store);
    (void)crlCheck;
    return ret;
#else
    (void)argc;
    (void)argv;
    WOLFCLU_LOG(WOLFCLU_E0, "No filesystem support");
    return WOLFCLU_FATAL_ERROR;
#endif
}
