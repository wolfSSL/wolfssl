/* clu_pkey.h
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

#ifndef CLU_PKEY_H
#define CLU_PKEY_H

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

/* handles incoming arguments for certificate generation */
int wolfCLU_pKeySetup(int argc, char** argv);

/* print out the private key from pkey into bio */
int wolfCLU_pKeyPEMtoPriKey(WOLFSSL_BIO* bio, WOLFSSL_EVP_PKEY* pkey);

/* print out the encrypted private key from pkey into bio */
int wolfCLU_pKeyPEMtoPriKeyEnc(WOLFSSL_BIO* bio, WOLFSSL_EVP_PKEY* pkey,
        int encAlgId, byte* password, word32 passwordSz);

int wolfCLU_RSA(int argc, char** argv);

int wolfCLU_pKeytoPubKey(WOLFSSL_EVP_PKEY* pkey, unsigned char** out);
int wolfCLU_pKeytoPriKey(WOLFSSL_EVP_PKEY* pkey, unsigned char** out);
#endif /* CLU_PKEY_H */

