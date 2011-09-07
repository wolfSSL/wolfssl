/* asn_public.h
 *
 * Copyright (C) 2006-2011 Sawtooth Consulting Ltd.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


#ifndef CTAO_CRYPT_ASN_PUBLIC_H
#define CTAO_CRYPT_ASN_PUBLIC_H

#include <cyassl/ctaocrypt/types.h>
#ifdef CYASSL_CERT_GEN
    #include <cyassl/ctaocrypt/rsa.h>
#endif


#ifdef __cplusplus
    extern "C" {
#endif


/* Certificate file Type */
enum CertType {
    CERT_TYPE       = 0, 
    PRIVATEKEY_TYPE,
    CA_TYPE
};

#ifdef CYASSL_CERT_GEN

enum Ctc_Misc {
    CTC_NAME_SIZE       = 64,
    CTC_SERIAL_SIZE     =  8
};

typedef struct CertName {
    char country[CTC_NAME_SIZE];
    char state[CTC_NAME_SIZE];
    char locality[CTC_NAME_SIZE];
    char sur[CTC_NAME_SIZE];
    char org[CTC_NAME_SIZE];
    char unit[CTC_NAME_SIZE];
    char commonName[CTC_NAME_SIZE];
    char email[CTC_NAME_SIZE];  /* !!!! email has to be last !!!! */
} CertName;


/* for user to fill for certificate generation */
typedef struct Cert {
    int      version;                   /* x509 version  */
    byte     serial[CTC_SERIAL_SIZE];   /* serial number */
    int      sigType;                   /* signature algo type */
    CertName issuer;                    /* issuer info */
    int      daysValid;                 /* validity days */
    int      selfSigned;                /* self signed flag */
    CertName subject;                   /* subject info */
    int      isCA;                      /* is this going to be a CA */
    /* internal use only */
    int      bodySz;                    /* pre sign total size */
    int      keyType;                   /* public key type of subject */
} Cert;




/* Initialize and Set Certficate defaults:
   version    = 3 (0x2)
   serial     = 0 (Will be randomly generated)
   sigType    = MD5_WITH_RSA
   issuer     = blank
   daysValid  = 500
   selfSigned = 1 (true) use subject as issuer
   subject    = blank
   isCA       = 0 (false)
   keyType    = RSA_KEY (default)
*/
CYASSL_API void InitCert(Cert*);
CYASSL_API int  MakeCert(Cert*, byte* derBuffer, word32 derSz, RsaKey*, RNG*);
CYASSL_API int  SignCert(Cert*, byte* derBuffer, word32 derSz, RsaKey*, RNG*);
CYASSL_API int  MakeSelfCert(Cert*, byte* derBuffer, word32 derSz, RsaKey*,
                             RNG*);
CYASSL_API int  SetIssuer(Cert*, const char*);
CYASSL_API int  SetSubject(Cert*, const char*);
CYASSL_API int  SetIssuerBuffer(Cert*, const byte*, int);
CYASSL_API int  SetSubjectBuffer(Cert*, const byte*, int);

    #ifdef HAVE_NTRU
        CYASSL_API int  MakeNtruCert(Cert*, byte* derBuffer, word32 derSz,
                                     const byte* ntruKey, word16 keySz, RNG*);
    #endif

#endif /* CYASSL_CERT_GEN */


#if defined(CYASSL_KEY_GEN) || defined(CYASSL_CERT_GEN)
    CYASSL_API int DerToPem(const byte* der, word32 derSz, byte* output,
                            word32 outputSz, int type);
#endif


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* CTAO_CRYPT_ASN_PUBLIC_H */

