/* clu_genkey.h
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

#ifndef CLU_GENKEY_H
#define CLU_GENKEY_H

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#ifdef HAVE_ED25519
    #include <wolfssl/wolfcrypt/ed25519.h>
#endif
#ifndef NO_RSA
    #include <wolfssl/wolfcrypt/rsa.h>
#endif
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif

#define SALT_SIZE       8

enum {
    ECPARAM,
    PRIV_ONLY,
    PUB_ONLY,
    PRIV_ONLY_FILE,
    PUB_ONLY_FILE,
    PRIV_AND_PUB
};

/* handles incoming arguments for certificate generation */
int wolfCLU_genKeySetup(int argc, char** argv);

#ifdef HAVE_ED25519
/* Generate an ED25519 key */
int wolfCLU_genKey_ED25519(WC_RNG* rng, char* fOutNm, int directive,
                                                                    int format);
#endif


/**
 * generates an ECC key
 *
 * @param rng       random number generator
 * @param fName     name of the file to write to
 * @param directive which key to output, public or private, maybe both
 * @param fmt       output format (PEM/DER)
 * @param name      curve name for the ECC key
 *
 * return   WOLFCLU_SUCCESS on success
 */
int wolfCLU_GenAndOutput_ECC(WC_RNG* rng, char* fName, int directive, int fmt,
        char* name);

/**
 * generates an RSA key
 *
 * @param rng       random number generator
 * @param fName     name of the file to write to
 * @param directive which key to output, public or private, maybe both
 * @param fmt       output format (PEM/DER)
 * @param keySz     size of the RSA key
 * @param exp       RSA public exponent
 *
 * return   WOLFCLU_SUCCESS on success
 */
int wolfCLU_genKey_RSA(WC_RNG* rng, char* fName, int directive, int fmt,
                       int keySz, long exp);

/* generates key based on password provided
 *
 * @param rng the random number generator
 * @param pwdKey the password based key as provided by the user
 * @param size size as determined by wolfCLU_GetAlgo
 * @param salt the buffer to store the resulting salt after it's generated
 * @param pad a flag to let us know if there are padded bytes or not
 */
int wolfCLU_genKey_PWDBASED(WC_RNG* rng, byte* pwdKey, int size, byte* salt,
                                                                       int pad);

void wolfCLU_EcparamPrintOID(WOLFSSL_BIO* out, WOLFSSL_EC_KEY* key,
        int fmt);

WOLFSSL_EC_KEY* wolfCLU_GenKeyECC(char* name);

int wolfCLU_KeyDerToPem(const byte* der, int derSz, byte** out, int pemType,
        int heapType);
#endif /* CLU_GENKEY_H */
