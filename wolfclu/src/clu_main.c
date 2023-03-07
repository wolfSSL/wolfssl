/* clu_main.c
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
#include <wolfclu/wolfclu/x509/clu_cert.h>
#include <wolfclu/wolfclu/clu_optargs.h>
#include <wolfclu/wolfclu/clu_error_codes.h>
#include <wolfclu/wolfclu/x509/clu_request.h>
#include <wolfclu/wolfclu/genkey/clu_genkey.h>
#include <wolfclu/wolfclu/pkey/clu_pkey.h>
#include <wolfclu/wolfclu/sign-verify/clu_sign_verify_setup.h>
#include <wolfclu/wolfclu/sign-verify/clu_verify.h>

#ifdef _WIN32
char* optarg;
int   optind;
int   opterr;
#endif


/* enumerate optionals beyond ascii range to dis-allow use of alias IE we
 * do not want "-e" to work for encrypt, user must use "encrypt"
 */

static const struct option mode_options[] = {
    {"ca",        no_argument,       0, WOLFCLU_CA          },
    {"encrypt",   required_argument, 0, WOLFCLU_ENCRYPT     },
    {"decrypt",   required_argument, 0, WOLFCLU_DECRYPT     },
    {"enc",       no_argument,       0, WOLFCLU_CRYPT       },
    {"bench",     no_argument,       0, WOLFCLU_BENCHMARK   },
    {"hash",      required_argument, 0, WOLFCLU_HASH        },
    {"md5",       no_argument,       0, WOLFCLU_MD5         },
    {"sha256",    no_argument,       0, WOLFCLU_CERT_SHA256 },
    {"sha384",    no_argument,       0, WOLFCLU_CERT_SHA384 },
    {"sha512",    no_argument,       0, WOLFCLU_CERT_SHA512 },
    {"x509",      no_argument,       0, WOLFCLU_X509        },
    {"req",       no_argument,       0, WOLFCLU_REQUEST     },
    {"genkey",    required_argument, 0, WOLFCLU_GEN_KEY     },
    {"ecparam",   no_argument,       0, WOLFCLU_ECPARAM     },
    {"pkey",      no_argument,       0, WOLFCLU_PKEY        },
    {"rsa",       no_argument,       0, WOLFCLU_RSA         },
    {"ecc",       no_argument,       0, WOLFCLU_ECC         },
    {"ed25519",   no_argument,       0, WOLFCLU_ED25519     },
    {"dgst",      no_argument,       0, WOLFCLU_DGST        },
    {"verify",    no_argument,       0, WOLFCLU_VERIFY      },
    {"pkcs12",    no_argument,       0, WOLFCLU_PKCS12      },
    {"crl",       no_argument,       0, WOLFCLU_CRL         },
    {"s_client",  no_argument,       0, WOLFCLU_CLIENT      },
    {"rand",      no_argument,       0, WOLFCLU_RAND        },
    {"dsaparam",  no_argument,       0, WOLFCLU_DSA         },
    {"dhparam",   no_argument,       0, WOLFCLU_DH          },
    {"help",      no_argument,       0, WOLFCLU_HELP        },
    {"h",         no_argument,       0, WOLFCLU_HELP        },
    {"v",         no_argument,       0, 'v'       },
    {"version",   no_argument,       0, 'v'       },

    {0, 0, 0, 0} /* terminal element */
};


/**
 * Takes in the second string passed into the function and compares it to known
 * modes. When a match is found the modes value is returned, otherwise a
 * negative value is returned.
 */
static int getMode(char* arg)
{
    int ret = WOLFCLU_FATAL_ERROR, i = 0;

    if (arg != NULL) {
        int argSz = (int)XSTRLEN(arg);
        const struct option* current;

        current = &mode_options[i];
        while (current->name != NULL) {
            if ((int)XSTRLEN(current->name) == argSz &&
                    XSTRNCMP(arg, current->name, argSz) == 0) {
                ret = current->val;
                break;
            }
            i = i + 1;
            current = &mode_options[i];
        }
    }
    return ret;
}

#ifdef HAVE_FIPS
static void myFipsCb(int ok, int err, const char* hash)
{
    printf("in my Fips callback, ok = %d, err = %d\n", ok, err);
    printf("message = %s\n", wc_GetErrorString(err));
    printf("hash = %s\n", hash);

    if (err == IN_CORE_FIPS_E) {
        printf("In core integrity hash check failure, copy above hash\n");
        printf("into verifyCore[] in fips_test.c and rebuild\n");
    }
}
#endif

int main(int argc, char** argv)
{
    int     flag = 0;
    int     ret = WOLFCLU_SUCCESS;
    int     longIndex = 0;
#ifdef HAVE_FIPS
    WC_RNG rng;

    wolfCrypt_SetCb_fips(myFipsCb);

    #ifdef WC_RNG_SEED_CB
        wc_SetSeed_Cb(wc_GenerateSeed);
    #endif

    ret = wc_InitRng(&rng);

    if (ret != 0) {
        wolfCLU_LogError("Err %d, update the FIPS hash\n", ret);
        return ret;
    }

    wc_FreeRng(&rng);
#endif

    if (argc == 1) {
        WOLFCLU_LOG(WOLFCLU_L0, "Main Help.");
        wolfCLU_help();
    }

#ifdef HAVE_FIPS
    if (wolfCrypt_GetStatus_fips() == IN_CORE_FIPS_E) {
        WOLFCLU_LOG(WOLFCLU_L0, "Linked to a FIPS version of wolfSSL that has failed the in core"
               "integrity check. ALL FIPS crypto will report ERRORS when used."
               "To resolve please recompile wolfSSL with the correct integrity"
               "hash. If the issue continues, contact fips @ wolfssl.com");
    }
#endif

#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
#endif
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        wolfCLU_LogError("wolfSSL initialization failed!");
        return -1;
    }

    optind = 0;

    /* retain old version of modes where '-' is used. i.e -x509, -req */
    if (argc > 1 && argv[1] != NULL && argv[1][0] == '-') {
        argv[1] = argv[1] + 1;
        flag = getMode(argv[1]);

        /* if -rsa was used then it is the older sign/verify version of rsa */
        if (flag == WOLFCLU_RSA) flag = WOLFCLU_RSALEGACY;
    }
   /* If the first string does not have a '-' in front of it then try to
     * get the mode to use i.e. x509, req, version ... this is for
     * compatibility with the behavior of the OpenSSL command line utility
     */
    else {
        flag = wolfCLU_GetOpt(argc, argv,"", mode_options, &longIndex);
    }

    switch (flag) {
        case 0:
            wolfCLU_LogError("No mode provided.");
            ret = 0;
            break;

        case WOLFCLU_CRYPT:
            /* generic 'enc' used, default to encrypt unless -d was used */
            ret = wolfCLU_checkForArg("-d", 2, argc, argv);
            if (ret > 0) {
                ret = wolfCLU_setup(argc, argv, 'd');
            }
            else {
                ret = wolfCLU_setup(argc, argv, 'e');
            }
            break;

        case WOLFCLU_ENCRYPT:
            ret = wolfCLU_setup(argc, argv, 'e');
            break;

        case WOLFCLU_DECRYPT:
            ret = wolfCLU_setup(argc, argv, 'd');
            break;

        case WOLFCLU_CA:
            ret = wolfCLU_CASetup(argc, argv);
            break;

        case WOLFCLU_BENCHMARK:
            ret = wolfCLU_benchSetup(argc, argv);
            break;

        case WOLFCLU_HASH:
            ret = wolfCLU_hashSetup(argc, argv);
            break;

        case WOLFCLU_MD5:
            ret = wolfCLU_algHashSetup(argc, argv, WOLFCLU_MD5);
            break;

        case WOLFCLU_CERT_SHA256:
            ret = wolfCLU_algHashSetup(argc, argv, WOLFCLU_CERT_SHA256);
            break;

        case WOLFCLU_CERT_SHA384:
            ret = wolfCLU_algHashSetup(argc, argv, WOLFCLU_CERT_SHA384);
            break;

        case WOLFCLU_CERT_SHA512:
            ret = wolfCLU_algHashSetup(argc, argv, WOLFCLU_CERT_SHA512);
            break;

        case WOLFCLU_X509:
            ret = wolfCLU_certSetup(argc, argv);
            break;

        case WOLFCLU_REQUEST:
            ret = wolfCLU_requestSetup(argc, argv);
            break;

        case WOLFCLU_GEN_KEY:
            ret = wolfCLU_genKeySetup(argc, argv);
            break;

        case WOLFCLU_ECPARAM:
            ret = wolfCLU_ecparam(argc, argv);
            break;

        case WOLFCLU_PKEY:
            ret = wolfCLU_pKeySetup(argc, argv);
            break;

        case WOLFCLU_DGST:
            ret = wolfCLU_dgst_setup(argc, argv);
            break;

        case WOLFCLU_VERIFY:
            ret = wolfCLU_x509Verify(argc, argv);
            break;

        case WOLFCLU_CRL:
            ret = wolfCLU_CRLVerify(argc, argv);
            break;

        case WOLFCLU_RSA:
            ret = wolfCLU_RSA(argc, argv);
            break;

        case WOLFCLU_RSALEGACY:
        case WOLFCLU_ECC:
        case WOLFCLU_ED25519:
            ret = wolfCLU_sign_verify_setup(argc, argv);
            break;

        case WOLFCLU_PKCS12:
            ret = wolfCLU_PKCS12(argc, argv);
            break;

        case WOLFCLU_CLIENT:
            ret = wolfCLU_Client(argc, argv);
            break;

        case WOLFCLU_RAND:
            ret = wolfCLU_Rand(argc, argv);
            break;

        case WOLFCLU_DSA:
            ret = wolfCLU_DsaParamSetup(argc, argv);
            break;

        case WOLFCLU_DH:
            ret = wolfCLU_DhParamSetup(argc, argv);
            break;

        case WOLFCLU_HELP:
            /* only print for -help if no mode has been declared */
            WOLFCLU_LOG(WOLFCLU_L0, "Main help menu:");
            wolfCLU_help();
            break;

        case WOLFCLU_VERBOSE:
            wolfCLU_verboseHelp();
            break;

        case 'v':
            ret = wolfCLU_version();
            break;

        default:
            wolfCLU_LogError("Unknown mode");
            wolfCLU_help();
            ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret <= 0) {
        wolfCLU_LogError("Error returned: %d.", ret);
        ret = WOLFCLU_FATAL_ERROR;
    }
    wolfSSL_Cleanup();

    /* main function we want to return 0 on success so that the executable
     * returns the expected 0 on success */
    return (ret == WOLFCLU_SUCCESS)? 0 : ret;
}

#ifdef FREERTOS

#ifndef MAX_COMMAND_ARGS
#define MAX_COMMAND_ARGS 30
#endif

#ifndef HAL_CONSOLE_UART
#define HAL_CONSOLE_UART huart4
#endif
extern UART_HandleTypeDef HAL_CONSOLE_UART;

/* When building on FreeRTOS, clu_entry() acts as the entry function and
 * parses the UART-transmitted command. Be sure to rename the main function
 * above, to clu_main() so the right function is called below */
int clu_entry(const void* argument)
{

    HAL_StatusTypeDef halRet;
    byte buffer[50];

    char* command;
    char* token;

    char* argv[MAX_COMMAND_ARGS];
    int argc = 1;

    int i = 0;
    int ret;

    WOLFCLU_LOG(WOLFCLU_L0, "Please enter a wolfCLU command (wolfssl -h for help)");

    /* Recieve the command from the UART console */
    do {
        halRet = HAL_UART_Receive(&HAL_CONSOLE_UART, buffer, sizeof(buffer), 100);
    } while (halRet != HAL_OK || buffer[0] == '\n' || buffer[0] == '\r');

    WOLFCLU_LOG(WOLFCLU_L0, "Command received.");

    command = (char*)buffer;

    /* Determine the number of supplied arguments */
    for (i = 0; command[i] != '\0' && i < XSTRLEN(command); i++) {
        if (command[i]==' ') {
            argc++;
        }
    }

    i = 0;
    token = strtok(command, " ");

    /* split the command string to correspond to separate argv[i] */
    while (token != NULL && i <= MAX_COMMAND_ARGS) {
        argv[i] = XMALLOC(XSTRLEN(token)+1, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        XMEMSET(argv[i], 0, XSTRLEN(token)+1);
        XSTRNCPY(argv[i], token, XSTRLEN(token));
        i++;
        if (i==(argc-1)) {
            token = strtok(NULL, "\r");
        }
        else {
            token = strtok(NULL, " ");
        }
    }

    ret = clu_main(argc, argv);

    /* free malloc'd argv[i] args */
    for (i = 0; i < argc; i++) {
        XFREE(argv[i], HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return ret;
}
#endif
