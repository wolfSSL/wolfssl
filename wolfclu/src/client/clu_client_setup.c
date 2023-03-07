/* clu_client_setup.c
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
#include <wolfclu/wolfclu/x509/clu_parse.h>
#include <wolfclu/wolfclu/x509/clu_cert.h>
#include <wolfclu/wolfclu/client.h>

#ifndef WOLFCLU_NO_FILESYSTEM

static const struct option client_options[] = {
    {"-connect",             required_argument, 0, WOLFCLU_CONNECT            },
    {"-starttls",            required_argument, 0, WOLFCLU_STARTTLS           },
    {"-CAfile",              required_argument, 0, WOLFCLU_CAFILE             },
    {"-verify_return_error", no_argument,       0, WOLFCLU_VERIFY_RETURN_ERROR},
    {"-help",                no_argument,       0, WOLFCLU_HELP               },
    {"-h",                   no_argument,       0, WOLFCLU_HELP               },

    {0, 0, 0, 0} /* terminal element */
};


static void wolfCLU_ClientHelp(void)
{
    WOLFCLU_LOG(WOLFCLU_L0, "./wolfssl s_client");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-connect <ip>:<port>");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-connect <[ipv6]>:<port>");
    WOLFCLU_LOG(WOLFCLU_L0, "\t\ti.e:");
    WOLFCLU_LOG(WOLFCLU_L0, "\t\t-connect '[::1]:11111'");
    WOLFCLU_LOG(WOLFCLU_L0, "\t\t-connect '[fe80::63:57c0:9b88:77ca%%en0]:11111'");
    WOLFCLU_LOG(WOLFCLU_L0, "\t\t-connect '[2001:4860:4860::8888]:443'");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-starttls <proto, i.e. smtp>");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-CAfile <ca file name>");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-verify_return_error close connection on verification error");
}

static const char hostFlag[]       = "-h";
static const char ipv6Flag[]       = "-6";
static const char portFlag[]       = "-p";
static const char noVerifyFlag[]   = "-d";
static const char caFileFlag[]     = "-A";
static const char noClientCert[]   = "-x";
static const char startTLSFlag[]   = "-M";
static const char disableCRLFlag[] = "-C";

int myoptind = 0;
char* myoptarg = NULL;

#define MAX_CLIENT_ARGS 15

/* return WOLFCLU_SUCCESS on success */
static int _addClientArg(const char** args, const char* in, int* idx)
{
    int ret = WOLFCLU_SUCCESS;

    if (*idx >= MAX_CLIENT_ARGS) {
        wolfCLU_LogError("Too many client args for array");
        ret = WOLFCLU_FATAL_ERROR;
    }
    else {
        args[*idx] = in;
        *idx = *idx + 1;
    }
    return ret;
}
#endif /* !WOLFCLU_NO_FILESYSTEM */

int wolfCLU_Client(int argc, char** argv)
{
#ifndef WOLFCLU_NO_FILESYSTEM
    func_args args;
    int ret     = WOLFCLU_SUCCESS;
    int longIndex = 1;
    int option;
    char* host = NULL;
    int   idx  = 0;
    /* Don't verify peer by default (same as OpenSSL). */
    int   verify = 0;
    char* ipv6 = NULL;

    int    clientArgc = 0;
    const char* clientArgv[MAX_CLIENT_ARGS];

    /* burn one argv for executable name spot */
    ret = _addClientArg(clientArgv, "wolfclu", &clientArgc);

    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at indent 0 */
    while ((option = wolfCLU_GetOpt(argc, argv, "", client_options,
                    &longIndex )) != -1) {
        switch (option) {
            case WOLFCLU_CONNECT:
                /* check for [] ipv6 address */
                ipv6 = XSTRSTR(optarg, "[");
                if (ipv6 != NULL) {
                    int strSz;

                    strSz = (int)XSTRLEN(ipv6);
                    for (idx = 0; idx < strSz; idx++) {
                        if (ipv6[idx] == ']') {
                            break;
                        }
                    }

                    if (idx == strSz) {
                        WOLFCLU_LOG(WOLFCLU_E0,
                                "No right bracket found for ipv6");
                        ret = WOLFCLU_FATAL_ERROR;
                    }

                    /* current idx is at ']' string is expected to have
                     * ']:<port>' format, check there is space left for it */
                    if (ret == WOLFCLU_SUCCESS && idx + 2 >= strSz) {
                        WOLFCLU_LOG(WOLFCLU_E0,
                                "No spaces left in string for port number");
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                    idx++; /* increment idx to ':' for getting port next */

                    if (ret == WOLFCLU_SUCCESS) {
                        ret = _addClientArg(clientArgv, ipv6Flag, &clientArgc);
                    }
                }

                if (XSTRSTR(optarg, ":") == NULL) {
                    wolfCLU_LogError("connect string does not have ':'");
                    ret = WOLFCLU_FATAL_ERROR;
                }

                /* expecting ipv4 address if ipv6 not found */
                if (ret == WOLFCLU_SUCCESS && ipv6 == NULL) {
                    idx = (int)strcspn(optarg, ":");
                }

                if (ret == WOLFCLU_SUCCESS) {
                    host = (char*)XMALLOC(idx + 1, HEAP_HINT,
                            DYNAMIC_TYPE_TMP_BUFFER);
                    if (host == NULL) {
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                    else {
                        if (ipv6) {
                            /* remove the '[' and ']' characters */
                            if (idx <= 2) {
                                ret = WOLFCLU_FATAL_ERROR;
                                XMEMSET(host, 0, idx);
                            }
                            else {
                                XMEMCPY(host, optarg + 1, idx - 2);
                                host[idx - 2] = '\0';
                            }
                        }
                        else {
                            XMEMCPY(host, optarg, idx);
                            host[idx] = '\0';
                        }
                        if (ret == WOLFCLU_SUCCESS) {
                            ret = _addClientArg(clientArgv, hostFlag, &clientArgc);
                            if (ret == WOLFCLU_SUCCESS) {
                                ret = _addClientArg(clientArgv, host, &clientArgc);
                            }
                        }
                    }
                }

                if (ret == WOLFCLU_SUCCESS) {
                    ret = _addClientArg(clientArgv, portFlag, &clientArgc);
                    if (ret == WOLFCLU_SUCCESS) {
                        ret = _addClientArg(clientArgv, optarg + idx + 1,
                                &clientArgc);
                    }
                }
                break;

            case WOLFCLU_STARTTLS:
                if (ret == WOLFCLU_SUCCESS) {
                    ret = _addClientArg(clientArgv, startTLSFlag, &clientArgc);
                    if (ret == WOLFCLU_SUCCESS) {
                        ret = _addClientArg(clientArgv, optarg, &clientArgc);
                    }
                }
                break;

            case WOLFCLU_CAFILE:
                if (ret == WOLFCLU_SUCCESS) {
                    ret = _addClientArg(clientArgv, caFileFlag, &clientArgc);
                    if (ret == WOLFCLU_SUCCESS) {
                        ret = _addClientArg(clientArgv, optarg, &clientArgc);
                    }
                }
                break;

            case WOLFCLU_VERIFY_RETURN_ERROR:
                if (ret == WOLFCLU_SUCCESS) {
                    verify = 1;
                }
                break;

            case WOLFCLU_HELP:
                wolfCLU_ClientHelp();
                return WOLFCLU_SUCCESS;

            case ':':
            case '?':
                break;

            default:
                /* do nothing. */
                (void)ret;
        }
    }

    if (ret == WOLFCLU_SUCCESS && !verify) {
        ret = _addClientArg(clientArgv, noVerifyFlag, &clientArgc);

        WOLFCLU_LOG(WOLFCLU_L0, "\nWarning: -verify_return_error not specified."
            " Defaulting to NOT verifying peer.");
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = _addClientArg(clientArgv, noClientCert, &clientArgc);
    }

    /* add TLS downgrade support i.e -v d to arguments */
    if (ret == WOLFCLU_SUCCESS) {
        ret = _addClientArg(clientArgv, "-v", &clientArgc);
    }
    if (ret == WOLFCLU_SUCCESS) {
        ret = _addClientArg(clientArgv, "d", &clientArgc);
    }

    /* No CRL support, yet. Disable CRL check. */
    if (ret == WOLFCLU_SUCCESS) {
        ret = _addClientArg(clientArgv, disableCRLFlag, &clientArgc);
    }

    if (ret == WOLFCLU_SUCCESS) {
        args.argv = (char**)clientArgv;
        args.argc = clientArgc;

        client_test(&args);

        if (args.return_code != 0) {
            wolfCLU_LogError("s_client failed (%d).", args.return_code);
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (host != NULL) {
        XFREE(host, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return ret;
#else
    (void)argc;
    (void)argv;
    WOLFCLU_LOG(WOLFCLU_E0, "No filesystem support");
    return WOLFCLU_FATAL_ERROR;
#endif
}


