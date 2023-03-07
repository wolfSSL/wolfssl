/* clu_decrypt.c
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
#include <wolfclu/wolfclu/genkey/clu_genkey.h>

#ifndef WOLFCLU_NO_FILESYSTEM

#ifndef MAX_LEN
    static const int MAX_LEN = 1024;
#endif

/* Used for algorithms that do not have an EVP type
 * return WOLFCLU_SUCCESS on success
 */
int wolfCLU_decrypt(int alg, char* mode, byte* pwdKey, byte* key, int size,
        char* in, char* out, byte* iv, int block, int keyType)
{
#ifdef HAVE_CAMELLIA
    Camellia camellia;                  /* camellia declaration */
#endif

    XFILE  inFile;                      /* input file */
    XFILE  outFile;                     /* output file */

    WC_RNG     rng;                     /* random number generator */
    byte*   input  = NULL;              /* input buffer */
    byte*   output = NULL;              /* output buffer */
    byte    salt[SALT_SIZE] = {0};      /* salt variable */

    int     currLoopFlag = 1;           /* flag to track the loop */
    int     lastLoopFlag = 0;           /* flag for last loop */
    int     ret          = 0;           /* return variable */
    int     keyVerify    = 0;           /* verify the key is set */
    int     i            = 0;           /* loop variable */
    int     pad          = 0;           /* the length to pad */
    int     length;                     /* length of message */
    int     tempMax = MAX_LEN;              /* equal to MAX_LEN until feof */
    int     saltAndIvSize = SALT_SIZE + block; /* size of salt and iv together */

    /* opens input file */
    inFile = XFOPEN(in, "rb");
    if (inFile == NULL) {
        wolfCLU_LogError("Input file does not exist.");
        return DECRYPT_ERROR;
    }
    /* opens output file */

    if ((outFile = XFOPEN(out, "wb")) == NULL) {
        wolfCLU_LogError("Error creating output file.");
        XFCLOSE(inFile);
        return DECRYPT_ERROR;
    }

    /* find end of file for length */
    XFSEEK(inFile, 0, SEEK_END);
    length = (int)XFTELL(inFile);
    XFSEEK(inFile, 0, SEEK_SET);

    /* if there is a remainder,
     * round up else no round
     */
    if (length % MAX_LEN > 0) {
        lastLoopFlag = (length/MAX_LEN) + 1;
    }
    else {
        lastLoopFlag =  length/MAX_LEN;
    }

    input = (byte*) XMALLOC(MAX_LEN, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (input == NULL) {
        ret = MEMORY_E;
    }

    if (ret == 0) {
        output = (byte*) XMALLOC(MAX_LEN, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (output == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        ret = wc_InitRng(&rng);
    }

    /* read in salt and iv */
    if (ret == 0 &&
            (int)XFREAD(salt, 1, SALT_SIZE, inFile) != SALT_SIZE) {
        wolfCLU_LogError("Error reading salt.");
        ret = FREAD_ERROR;
    }

    if (ret == 0 && (int)XFREAD(iv, 1, block, inFile) != block) {
        wolfCLU_LogError("Error reading salt.");
        ret = FREAD_ERROR;
    }
    /* replicates old pwdKey if pwdKeys match */
    if (ret == 0 && keyType == 1) {
        if (wc_PBKDF2(key, pwdKey, (int) XSTRLEN((const char*)pwdKey),
                      salt, SALT_SIZE, CLU_4K_TYPE, size,
                      CLU_SHA256) != 0) {
            wolfCLU_LogError("pwdKey set error.");
            ret = ENCRYPT_ERROR;
        }
    }
    else if (ret == 0 && keyType == 2) {
        for (i = 0; i < size; i++) {

            /* ensure key is set */
            if (key[i] == 0 || key[i] == '\0') {
                continue;
            }
            else {
                keyVerify++;
            }
        }
        if (keyVerify == 0) {
            wolfCLU_LogError("the key is all zero's or not set.");
            ret = ENCRYPT_ERROR;
        }
    }

    /* reads from inFile and writes whatever
     * is there to the input buffer
     */
    while (length > 0 && ret == 0) {
        /* Read in 1kB */
        if (ret == 0 &&
                (ret = (int)XFREAD(input, 1, MAX_LEN, inFile)) != MAX_LEN) {
            if (feof(inFile)) {
                tempMax = ret;
                ret = 0; /* success */
            }
            else {
                wolfCLU_LogError("Input file does not exist.");
                ret = FREAD_ERROR;
            }
        }

#ifdef HAVE_CAMELLIA
        if (ret == 0 &&
                (alg == WOLFCLU_CAMELLIA128CBC ||
                 alg == WOLFCLU_CAMELLIA192CBC ||
                 alg == WOLFCLU_CAMELLIA256CBC)) {
            ret = wc_CamelliaSetKey(&camellia, key, block, iv);
            if (ret == 0) {
                wc_CamelliaCbcDecrypt(&camellia, output, input, tempMax);
            }
        }
#endif
        if (ret == 0 && currLoopFlag == lastLoopFlag) {
            break;
        }

        /* writes output to the outFile */
        if (ret == 0 && output != NULL)
            XFWRITE(output, 1, tempMax, outFile);

        if (ret == 0) {
            currLoopFlag++;
            length -= tempMax;
        }
    }

    /* check padding */
    if (ret == 0) {
        if (output != NULL && salt[0] != 0) {
            /* reduces length based on number of padded elements  */
            pad = output[tempMax-1];
            /* adjust length for padded bytes and salt size */
            length -= pad + saltAndIvSize;
            if (length < 0) {
                wolfCLU_LogError("bad length %d found", length);
                ret = -1;
            }
            /* reset tempMax for smaller decryption */
            XFWRITE(output, 1, length, outFile);
        }
        else {
            if (output != NULL)
                XFWRITE(output, 1, tempMax, outFile);
        }
    }

    /* closes the opened files and frees memory */
    wolfCLU_freeBins(input, output, NULL, NULL, NULL);
    XMEMSET(key, 0, size);
    /* Use the wolfssl wc_FreeRng to free rng */
    wc_FreeRng(&rng);
    XFCLOSE(inFile);
    XFCLOSE(outFile);

    (void)mode;
    (void)alg;
    return (ret == 0)? WOLFCLU_SUCCESS : ret;
}

#endif /* !WOLFCLU_NO_FILESYSTEM */
