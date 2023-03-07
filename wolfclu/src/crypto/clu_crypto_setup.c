/* clu_crypto_setup.c
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

#ifndef WOLFCLU_NO_FILESYSTEM

static const struct option crypt_options[] = {
    {"-sha",       no_argument,       0, WOLFCLU_CERT_SHA   },
    {"-sha224",    no_argument,       0, WOLFCLU_CERT_SHA224},
    {"-sha256",    no_argument,       0, WOLFCLU_CERT_SHA256},
    {"-sha384",    no_argument,       0, WOLFCLU_CERT_SHA384},
    {"-sha512",    no_argument,       0, WOLFCLU_CERT_SHA512},

    {"-in",        required_argument, 0, WOLFCLU_INFILE    },
    {"-out",       required_argument, 0, WOLFCLU_OUTFILE   },
    {"-pwd",       required_argument, 0, WOLFCLU_PASSWORD  },
    {"-key",       required_argument, 0, WOLFCLU_KEY       },
    {"-iv",        required_argument, 0, WOLFCLU_IV        },
    {"-inkey",     required_argument, 0, WOLFCLU_INKEY     },
    {"-output",    required_argument, 0, WOLFCLU_OUTPUT    },
    {"-pbkdf2",    no_argument,       0, WOLFCLU_PBKDF2    },
    {"-md",        required_argument, 0, WOLFCLU_MD        },
    {"-d",         no_argument,       0, WOLFCLU_DECRYPT   },
    {"-p",         no_argument,       0, WOLFCLU_DEBUG     },
    {"-k",         required_argument, 0, WOLFCLU_PASSWORD  },
    {"-base64",    no_argument,       0, WOLFCLU_BASE64    },
    {"-nosalt",    no_argument,       0, WOLFCLU_NOSALT    },
    {"-pass",      required_argument, 0, WOLFCLU_PASSWORD_SOURCE  },
    {0, 0, 0, 0} /* terminal element */
};
#endif

/* returns WOLFCLU_SUCCESS on success */
int wolfCLU_setup(int argc, char** argv, char action)
{
#ifndef WOLFCLU_NO_FILESYSTEM
    int      ret        =   0;  /* return variable */
    char     outNameEnc[256];     /* default outFile for encrypt */
    char     outNameDec[256];     /* default outfile for decrypt */
    char     inName[256];       /* name of the in File if not provided */

    int      alg;               /* algorithm from name */
    char*    mode = NULL;       /* mode from name */
    char*    out  = NULL;       /* default output file name */
    char*    in = inName;       /* default in data */
    byte*    pwdKey = NULL;     /* password for generating pwdKey */
    byte*    key = NULL;        /* user set key NOT PWDBASED */
    byte*    iv = NULL;         /* iv for initial encryption */


    int      passwordSz =   0;
    int      noSalt     =   0;
    int      isBase64   =   0;
    int      keySize    =   0;  /* keysize from name */
    int      block      =   0;  /* block size based on algorithm */
    int      pwdKeyChk  =   0;  /* if a pwdKey has been provided */
    int      ivCheck    =   0;  /* if the user sets the IV explicitly */
    int      keyCheck   =   0;  /* if ivCheck is 1 this should be set also */
    int      inCheck    =   0;  /* if input has been provided */
    int      outCheck   =   0;  /* if output has been provided */
    int      encCheck   =   0;  /* if user is encrypting data */
    int      decCheck   =   0;  /* if user is decrypting data */
    int      inputHex   =   0;  /* if user is encrypting hexidecimal data */
    int      keyType    =   0;  /* tells Decrypt which key it will be using
                                 * 1 = password based key, 2 = user set key
                                 */
    int      verbose   =   0;  /* flag to print out key/iv/salt */
    int      pbkVersion =   1;
    const WOLFSSL_EVP_MD* hashType = wolfSSL_EVP_sha256();

    const WOLFSSL_EVP_CIPHER* cphr = NULL;
    word32   ivSize     =   0;  /* IV if provided should be 2*block since
                                 * reading a hex string passed in */
    word32   numBits    =   0;  /* number of bits in argument from the user */
    int      option;
    int      longIndex = 1;

    if (action == 'e')
        encCheck = 1;
    if (action == 'd')
        decCheck = 1;

    ret = wolfCLU_checkForArg("-h", 2, argc, argv);
    if (ret > 0) {
        if (encCheck == 1) {
            wolfCLU_encryptHelp();
            return WOLFCLU_SUCCESS;
        }
        else {
            wolfCLU_decryptHelp();
            return WOLFCLU_SUCCESS;
        }
    }

    /* gets blocksize, algorithm, mode, and key size from name argument */
    block = wolfCLU_getAlgo(argc, argv, &alg, &mode, &keySize);
    if (block < 0) {
        wolfCLU_LogError("unable to find algorithm to use");
        return WOLFCLU_FATAL_ERROR;
    }

    /* initialize memory buffers */
    pwdKey = (byte*)XMALLOC(keySize + block, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (pwdKey == NULL)
        return MEMORY_E;
    XMEMSET(pwdKey, 0, keySize + block);

    iv = (byte*)XMALLOC(block, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (iv == NULL) {
        wolfCLU_freeBins(pwdKey, NULL, NULL, NULL, NULL);
        return MEMORY_E;
    }
    XMEMSET(iv, 0, block);

    key = (byte*)XMALLOC(keySize, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (key == NULL) {
        wolfCLU_freeBins(pwdKey, iv, NULL, NULL, NULL);
        return MEMORY_E;
    }
    XMEMSET(key, 0, keySize);

    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at indent 0 */
    while ((option = wolfCLU_GetOpt(argc, argv, "",
                   crypt_options, &longIndex )) != -1) {

        switch (option) {
        case WOLFCLU_PASSWORD_SOURCE:
            passwordSz = keySize;
            ret = wolfCLU_GetPassword((char*)pwdKey, &passwordSz, optarg);
            pwdKeyChk = 1;
            keyType   = 1;
            break;

        case WOLFCLU_PASSWORD:
            if (optarg == NULL) {
                return WOLFCLU_FATAL_ERROR;
            }
            else {
                XSTRLCPY((char*)pwdKey, optarg, keySize);
                pwdKeyChk = 1;
                keyType   = 1;
            }
            break;

        case WOLFCLU_PBKDF2:
            pbkVersion = 2;
            break;

        case WOLFCLU_BASE64:
            isBase64 = 1;
            break;

        case WOLFCLU_NOSALT:
            noSalt = 1;
            break;

        case WOLFCLU_KEY: /* Key if used must be in hex */
            break;

        case WOLFCLU_IV:  /* IV if used must be in hex */
            {
                char* ivString;
                if (optarg == NULL) {
                    return WOLFCLU_FATAL_ERROR;
                }
                else {
                    ivString = (char*)XMALLOC(XSTRLEN(optarg), HEAP_HINT,
                        DYNAMIC_TYPE_TMP_BUFFER);
                    if (ivString == NULL) {
                        wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
                        return MEMORY_E;
                    }

                    XSTRLCPY(ivString, optarg, XSTRLEN(optarg));
                    ret = wolfCLU_hexToBin(ivString, &iv, &ivSize,
                                       NULL, NULL, NULL,
                                       NULL, NULL, NULL,
                                       NULL, NULL, NULL);
                    XFREE(ivString, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                    if (ret != WOLFCLU_SUCCESS) {
                        WOLFCLU_LOG(WOLFCLU_E0,
                            "failed during conversion of IV, ret = %d", ret);
                        wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
                        return WOLFCLU_FATAL_ERROR;
                    }
                    ivCheck = 1;
                }
            }
            break;

        case WOLFCLU_SIGN:
            break;

        case WOLFCLU_VERIFY: /* Verify results, used with -iv and -key */
            /* using hexidecimal format */
            inputHex = 1;
            break;

        case WOLFCLU_INFORM:
        case WOLFCLU_OUTFORM:
        case WOLFCLU_OUTPUT:
        case WOLFCLU_NOOUT:
        case WOLFCLU_TEXT_OUT:
        case WOLFCLU_SILENT:
        case WOLFCLU_PUBIN:
        case WOLFCLU_PUBOUT:
        case WOLFCLU_PUBKEY:


            /* The cases above have their arguments converted to lower case */
            if (optarg) wolfCLU_convertToLower(optarg, (int)XSTRLEN(optarg));
            /* The cases below won't have their argument's molested */
            FALL_THROUGH;

        case WOLFCLU_INFILE:
            in = optarg;
            inCheck = 1;
            break;

        case WOLFCLU_OUTFILE:
            out = optarg;
            outCheck = 1;
            break;

        case WOLFCLU_INKEY:
            if (optarg == NULL) {
                wolfCLU_LogError("no key passed in..");
                wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
                return WOLFCLU_FATAL_ERROR;
            }

            /* 2 characters = 1 byte. 1 byte = 8 bits
             */
            numBits = (word32)(XSTRLEN(optarg) * 4);
            /* Key for encryption */
            if ((int)numBits != keySize) {
                WOLFCLU_LOG(WOLFCLU_L0,
                        "Length of key provided was: %d.", numBits);
                WOLFCLU_LOG(WOLFCLU_L0,
                        "Length of key expected was: %d.", keySize);
                WOLFCLU_LOG(WOLFCLU_E0,
                        "Invalid Key. Must match algorithm key size.");
                wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
                return WOLFCLU_FATAL_ERROR;
            }
            else {
                char* keyString;

                keyString = (char*)XMALLOC(XSTRLEN(optarg), HEAP_HINT,
                        DYNAMIC_TYPE_TMP_BUFFER);
                if (keyString == NULL) {
                    wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
                    return MEMORY_E;
                }

                XSTRLCPY(keyString, optarg, XSTRLEN(optarg));
                ret = wolfCLU_hexToBin(keyString, &key, &numBits,
                                       NULL, NULL, NULL,
                                       NULL, NULL, NULL,
                                       NULL, NULL, NULL);
                XFREE(keyString, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                if (ret != WOLFCLU_SUCCESS) {
                    WOLFCLU_LOG(WOLFCLU_E0,
                            "failed during conversion of Key, ret = %d", ret);
                    wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
                    return WOLFCLU_FATAL_ERROR;
                }
                keyCheck = 1;
                keyType = 2;
            }
            break;

        case WOLFCLU_SIGFILE:
            break;

        case WOLFCLU_DECRYPT:
            encCheck = 0;
            decCheck = 1;
            break;

        case WOLFCLU_DEBUG:
            verbose = 1;
            break;

        case WOLFCLU_MD:
            hashType = wolfSSL_EVP_get_digestbyname(optarg);
            if (hashType == NULL) {
                wolfCLU_LogError("Invalid digest name");
                return WOLFCLU_FATAL_ERROR;
            }
            break;

        case ':':
        case '?':
            break;

        default:
            /* do nothing. */
            (void)ret;
        }
    }

    if (pwdKeyChk == 0 && keyCheck == 0) {
        if (decCheck == 1) {
            WOLFCLU_LOG(WOLFCLU_L0, "\nDECRYPT ERROR:");
            wolfCLU_LogError("no key or passphrase set");
            WOLFCLU_LOG(WOLFCLU_L0,
                    "Please type \"wolfssl -decrypt -help\" for decryption"
                                                            " usage \n");
            return WOLFCLU_FATAL_ERROR;
        }
        /* if no pwdKey is provided */
        else {
            WOLFCLU_LOG(WOLFCLU_L0,
                    "No -pwd flag set, please enter a password to use for"
                    " encrypting.");
            ret = wolfCLU_GetStdinPassword(pwdKey, (word32*)&keySize);
            pwdKeyChk = 1;
        }
    }

    if (inCheck == 0 && encCheck == 1) {
        ret = 0;
        while (ret == 0) {
            WOLFCLU_LOG(WOLFCLU_L0,
                    "-in flag was not set, please enter a string or"
                   "file name to be encrypted: ");
            ret = (int) scanf("%s", inName);
        }
        in = inName;
        WOLFCLU_LOG(WOLFCLU_L0, "Encrypting :\"%s\"", inName);
        inCheck = 1;
    }

    if (encCheck == 1 && decCheck == 1) {
        WOLFCLU_LOG(WOLFCLU_E0,
                "Encrypt and decrypt simultaneously is invalid");
        wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
        return WOLFCLU_FATAL_ERROR;
    }

    if (inCheck == 0 && decCheck == 1) {
        wolfCLU_LogError("File/string to decrypt needed");
        wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
        return WOLFCLU_FATAL_ERROR;
    }

    if (ivCheck == 1) {
        if (keyCheck == 0) {
            WOLFCLU_LOG(WOLFCLU_E0,
                    "-iv was explicitly set, but no -key was set. User"
                    " needs to provide a non-password based key when setting"
                    " the -iv flag.");
            wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
            return WOLFCLU_FATAL_ERROR;
        }
    }

    if (pwdKeyChk == 1 && keyCheck == 1) {
        XMEMSET(pwdKey, 0, keySize + block);
    }

    /* encryption function call */
    cphr = wolfCLU_CipherTypeFromAlgo(alg);
    if (encCheck == 1) {
        /* if EVP type found then call generic EVP function */
        if (cphr != NULL) {
            ret = wolfCLU_evp_crypto(cphr, mode, pwdKey, key, (keySize+7)/8, in,
                  out, NULL, iv, 0, 1, pbkVersion, hashType, verbose, isBase64,
                  noSalt);
        }
        else {
            if (outCheck == 0) {
                ret = 0;
                while (ret == 0) {
                    WOLFCLU_LOG(WOLFCLU_L0,
                            "Please enter a name for the output file: ");
                    ret = (int) scanf("%s", outNameEnc);
                    out = (ret > 0) ? outNameEnc : '\0';
                }
            }
            ret = wolfCLU_encrypt(alg, mode, pwdKey, key, keySize, in, out,
                iv, block, ivCheck, inputHex);
        }
    }
    /* decryption function call */
    else if (decCheck == 1) {
        /* if EVP type found then call generic EVP function */
        if (cphr != NULL) {
            ret = wolfCLU_evp_crypto(cphr, mode, pwdKey, key, (keySize+7)/8, in,
                    out, NULL, iv, 0, 0, pbkVersion, hashType, verbose,
                    isBase64, noSalt);
        }
        else {
            if (outCheck == 0) {
                ret = 0;
                while (ret == 0) {
                    WOLFCLU_LOG(WOLFCLU_L0,
                            "Please enter a name for the output file: ");
                    ret = (int) scanf("%s", outNameDec);
                    out = (ret > 0) ? outNameDec : '\0';
                }
            }
            ret = wolfCLU_decrypt(alg, mode, pwdKey, key, keySize, in, out,
                iv, block, keyType);
        }
    }
    else {
        wolfCLU_help();
    }
    /* clear and free data */
    XMEMSET(key, 0, keySize);
    XMEMSET(pwdKey, 0, keySize + block);
    XMEMSET(iv, 0, block);
    wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);

    if (mode != NULL)
        XFREE(mode, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
#else
    (void)argc;
    (void)argv;
    (void)action;
    WOLFCLU_LOG(WOLFCLU_E0, "No filesystem support");
    return WOLFCLU_FATAL_ERROR;
#endif
}
