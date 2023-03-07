/* clu_sign_verify_setup.c
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
#include <wolfclu/wolfclu/sign-verify/clu_sign.h>
#include <wolfclu/wolfclu/sign-verify/clu_verify.h>
#include <wolfclu/wolfclu/sign-verify/clu_sign_verify_setup.h>

int wolfCLU_sign_verify_setup(int argc, char** argv)
{
#ifndef WOLFCLU_NO_FILESYSTEM
    int     ret  = WOLFCLU_SUCCESS;
    char*   in   = NULL; /* input variable */
    char*   out  = NULL; /* output variable */
    char*   priv = NULL; /* private key variable */
    char*   sig  = NULL;

    int     algCheck;           /* acceptable algorithm check */
    int     inCheck     = 0;    /* input check */
    int     signCheck   = 0;
    int     verifyCheck = 0;
    int     pubInCheck  = 0;

    /* checkForArg doesn't look for "-" here, as it would have been
     * removed in clu_main.c if present */
    if (wolfCLU_checkForArg("rsa", 3, argc, argv) > 0) {
        algCheck = RSA_SIG_VER;
    }
    else if (wolfCLU_checkForArg("ed25519", 7, argc, argv) > 0) {
        algCheck = ED25519_SIG_VER;
    }
    else if (wolfCLU_checkForArg("ecc", 3, argc, argv) > 0) {
        algCheck = ECC_SIG_VER;
    }
    else {
        return WOLFCLU_FATAL_ERROR;
    }

    ret = wolfCLU_checkForArg("-sign", 5, argc, argv);
    if (ret > 0) {
        /* output file */
        signCheck = 1;
    }

    ret = wolfCLU_checkForArg("-verify", 7, argc, argv);
    if (ret > 0) {
        /* output file */
        verifyCheck = 1;
    }

    /* help checking */
    ret = wolfCLU_checkForArg("-help", 5, argc, argv);
    if (ret > 0) {
        if (signCheck == 1) {
            wolfCLU_signHelp(algCheck);
        }
        else if (verifyCheck == 1) {
            wolfCLU_verifyHelp(algCheck);
        }
        else {
            wolfCLU_signHelp(algCheck);
            wolfCLU_verifyHelp(algCheck);
        }
        return 0;
    }

    ret = wolfCLU_checkForArg("-inkey", 6, argc, argv);
    if (ret > 0) {
        priv = XMALLOC(XSTRLEN(argv[ret+1]) + 1, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (priv == NULL) {
            return MEMORY_E;
        }
        else if (access(argv[ret+1], F_OK) == -1) {
            wolfCLU_LogError("Inkey file %s did not exist. Please check your options.",
                    argv[ret+1]);
            XFREE(priv, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            return MEMORY_E;
        }

        XSTRLCPY(priv, &argv[ret+1][0], XSTRLEN(argv[ret+1])+1);
        priv[XSTRLEN(argv[ret+1])] = '\0';
    }
    else {
        WOLFCLU_LOG(WOLFCLU_L0, "Please specify an -inkey <key> option when "
               "signing or verifying.");
        wolfCLU_signHelp(algCheck);
        wolfCLU_verifyHelp(algCheck);
        return ret;
    }

    ret = wolfCLU_checkForArg("-pubin", 6, argc, argv);
    if (ret > 0) {
        /* output file */
        pubInCheck = 1;
    }

    ret = wolfCLU_checkForArg("-in", 3, argc, argv);
    if (ret > 0) {
        /* input file/text */
        in = XMALLOC(XSTRLEN(argv[ret+1]) + 1, HEAP_HINT,
                     DYNAMIC_TYPE_TMP_BUFFER);
        if (in == NULL) {
            if (priv)
                XFREE(priv, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            return MEMORY_E;
        }
        else if (access(argv[ret+1], F_OK) == -1) {
            wolfCLU_LogError("In file did not exist. Please check your options.");
            XFREE(in, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            if (priv)
                XFREE(priv, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            return MEMORY_E;
        }

        XSTRLCPY(in, &argv[ret+1][0], XSTRLEN(argv[ret+1])+1);
        in[XSTRLEN(argv[ret+1])] = '\0';
        inCheck = 1;
    }

    ret = wolfCLU_checkForArg("-sigfile", 8, argc, argv);
    if (ret > 0) {
        sig = XMALLOC(XSTRLEN(argv[ret+1]) + 1, HEAP_HINT,
                      DYNAMIC_TYPE_TMP_BUFFER);
        if (sig == NULL) {
            if (priv)
                XFREE(priv, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            if (in)
                XFREE(in, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            return MEMORY_E;
        }
        else if (access(argv[ret+1], F_OK) == -1) {
            wolfCLU_LogError("Signature file did not exist. Please check your options.");
            if (priv)
                XFREE(priv, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            if (in)
                XFREE(in, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(sig, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            return MEMORY_E;
        }

        XSTRLCPY(sig, &argv[ret+1][0], XSTRLEN(argv[ret+1])+1);
        sig[XSTRLEN(argv[ret+1])] = '\0';
    }
    else if (verifyCheck == 1) {
        wolfCLU_LogError("Please specify -sigfile <sig> when verifying.");
        wolfCLU_verifyHelp(algCheck);
        if (priv)
            XFREE(priv, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (in)
            XFREE(in, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (sig)
            XFREE(sig, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    ret = wolfCLU_checkForArg("-out", 4, argc, argv);
    if (ret > 0) {
        /* output file */
        out = argv[ret+1];
    }
    else {
        if (algCheck == RSA_SIG_VER) {
            WOLFCLU_LOG(WOLFCLU_L0, "Please specify an output file when "
                   "signing or verifing with RSA.");
            wolfCLU_signHelp(algCheck);
            wolfCLU_verifyHelp(algCheck);
            if (priv)
                XFREE(priv, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            if (in)
                XFREE(in, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            if (sig)
                XFREE(sig, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            return ret;
        }
        else if (algCheck == ECC_SIG_VER && verifyCheck == 0) {
            WOLFCLU_LOG(WOLFCLU_L0, "Please specify an output file when "
                   "signing with ECC.");
            wolfCLU_signHelp(algCheck);
            if (priv)
                XFREE(priv, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            if (in)
                XFREE(in, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            if (sig)
                XFREE(sig, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            return ret;
        }
        else {
            /* No out needed for ECC verifying */
            /* ED25519 exceptions will need to be added at a later date */
        }
    }

    if (inCheck == 0) {
        if (algCheck == RSA_SIG_VER && verifyCheck == 1) {
            /* ignore no -in. RSA verify doesn't check original message */
        }
        else {
            wolfCLU_LogError("Must have input as either a file or standard I/O");
            if (priv)
                XFREE(priv, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            if (in)
                XFREE(in, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            if (sig)
                XFREE(sig, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            return WOLFCLU_FATAL_ERROR;
        }
    }

    if (signCheck == 1) {
        ret = wolfCLU_sign_data(in, out, priv, algCheck);
    }
    else if (verifyCheck == 1) {
        ret = wolfCLU_verify_signature(sig, in, out, priv, algCheck, pubInCheck);
    }

    if (priv)
        XFREE(priv, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (in)
        XFREE(in, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (sig)
        XFREE(sig, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
#else
    (void)argc;
    (void)argv;
    WOLFCLU_LOG(WOLFCLU_E0, "No filesystem support");
    return WOLFCLU_FATAL_ERROR;
#endif
}
