/* pkcs7.h
 *
 * Copyright (C) 2006-2013 wolfSSL Inc.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful, 
 * * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


#ifdef HAVE_PKCS7

#ifndef CTAO_CRYPT_PKCS7_H
#define CTAO_CRYPT_PKCS7_H

#include <cyassl/ctaocrypt/types.h>
#include <cyassl/ctaocrypt/asn.h>
#include <cyassl/ctaocrypt/asn_public.h>
#include <cyassl/ctaocrypt/random.h>
#include <cyassl/ctaocrypt/des3.h>

#ifdef __cplusplus
    extern "C" {
#endif

enum PKCS7_TYPES {
    PKCS7                     = 650,   /* 1.2.840.113549.1.7 */ 
    DATA                      = 651,   /* 1.2.840.113549.1.7.1 */
    SIGNED_DATA               = 652,   /* 1.2.840.113549.1.7.2 */
    ENVELOPED_DATA            = 653,   /* 1.2.840.113549.1.7.3 */
    SIGNED_AND_ENVELOPED_DATA = 654,   /* 1.2.840.113549.1.7.4 */
    DIGESTED_DATA             = 655,   /* 1.2.840.113549.1.7.5 */
    ENCRYPTED_DATA            = 656    /* 1.2.840.113549.1.7.6 */
};

enum Pkcs7_Misc {
    MAX_ENCRYPTED_KEY_SZ = 512,        /* max enc. key size, RSA <= 4096 */
    MAX_CONTENT_KEY_LEN  = DES3_KEYLEN,
    MAX_RECIP_SZ         = MAX_VERSION_SZ +
                           MAX_SEQ_SZ + ASN_NAME_MAX + MAX_SN_SZ +
                           MAX_SEQ_SZ + MAX_ALGO_SZ + 1 + MAX_ENCRYPTED_KEY_SZ
};

CYASSL_API int Pkcs7_encrypt(const byte* certs, word32 certSz, byte* data,
                             word32 dataSz, int cipher, byte* out,
                             word32* outSz, word32 flags);

CYASSL_LOCAL int SetContentType(int pkcs7TypeOID, byte* output);
CYASSL_LOCAL int CreateRecipientInfo(const byte* cert, word32 certSz,
                                     int keyEncAlgo, int blockKeySz,
                                     RNG* rng, byte* contentKeyPlain,
                                     byte* contentKeyEnc,
                                     int* keyEncSz, byte* out, word32 outSz);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* CTAO_CRYPT_PKCS7_H */

#endif /* HAVE_PKCS7 */

