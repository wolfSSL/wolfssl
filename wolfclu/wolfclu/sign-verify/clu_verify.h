/* clu_verify.h
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
    #include <wolfssl/wolfcrypt/asn_public.h>
#endif

int wolfCLU_x509Verify(int argc, char** argv);
int wolfCLU_CRLVerify(int argc, char** argv);

int wolfCLU_verify_signature(char* , char*, char*, char*, int, int);

int wolfCLU_verify_signature_rsa(byte* , char*, int, char*, int);
int wolfCLU_verify_signature_ecc(byte*, int, byte*, int, char*, int);
int wolfCLU_verify_signature_ed25519(byte*, int, byte*, int, char*, int);
