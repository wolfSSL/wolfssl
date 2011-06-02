/* ctc_asn_public.h
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

#include "ctc_types.h"

#ifdef __cplusplus
    extern "C" {
#endif

/* forward declarations */
typedef struct DecodedCert DecodedCert;
typedef struct Cert        Cert;
typedef struct Signer      Signer;
#ifndef CTC_RSA_KEY_DEFINED
    typedef struct RsaKey      RsaKey;
#endif
#ifndef CTC_RNG_DEFINED
    typedef struct RNG         RNG;
#endif

CYASSL_API void InitDecodedCert(DecodedCert*, byte*, void*);
CYASSL_API void FreeDecodedCert(DecodedCert*);
CYASSL_API int  ParseCert(DecodedCert*, word32, int type, int verify,
                          Signer* signer);

#if defined(CYASSL_KEY_GEN) || defined(CYASSL_CERT_GEN)
CYASSL_API int DerToPem(const byte* der, word32 derSz, byte* output,
                        word32 outputSz, int type);
#endif

/* Initialize and Set Certficate defaults:
   version    = 3 (0x2)
   serial     = 0 (Will be randomly generated)
   sigType    = MD5_WITH_RSA
   issuer     = blank
   daysValid  = 500
   selfSigned = 1 (true) use subject as issuer
   subject    = blank
   keyType    = RSA_KEY (default)
*/
CYASSL_API void InitCert(Cert*);
CYASSL_API int  MakeCert(Cert*, byte* derBuffer, word32 derSz, RsaKey*, RNG*);
CYASSL_API int  SignCert(Cert*, byte* derBuffer, word32 derSz, RsaKey*, RNG*);
CYASSL_API int  MakeSelfCert(Cert*, byte* derBuffer, word32 derSz, RsaKey*,
                             RNG*);
CYASSL_API int  SetIssuer(Cert*, const char*);
#ifdef HAVE_NTRU
CYASSL_API int  MakeNtruCert(Cert*, byte* derBuffer, word32 derSz,
                             const byte* ntruKey, word16 keySz, RNG*);
#endif


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* CTAO_CRYPT_ASN_PUBLIC_H */

