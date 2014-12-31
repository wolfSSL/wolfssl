/* asn_public.h
 *
 * Copyright (C) 2006-2014 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */


#ifndef CTAO_CRYPT_ASN_PUBLIC_H
#define CTAO_CRYPT_ASN_PUBLIC_H

#include <cyassl/ctaocrypt/types.h>
#include <cyassl/ctaocrypt/ecc.h>
#ifdef CYASSL_CERT_GEN
    #include <cyassl/ctaocrypt/rsa.h>
#endif

#include <wolfssl/wolfcrypt/asn_public.h>

#ifndef HAVE_FIPS
	#ifdef WOLFSSL_CERT_GEN
	#define InitCert wc_InitCert
	#define MakeCert wc_MakeCert
	
    #ifdef WOLFSSL_CERT_REQ
	    #define MakeCertReq wc_MakeCertReq
	#endif
	
    #define SignCert     wc_SignCert
	#define MakeSelfCert wc_MakeSelfCert
	#define SetIssuer    wc_SetIssuer
	#define SetSubject   wc_SetSubject
	
    #ifdef WOLFSSL_ALT_NAMES
	    #define SetAltNames wc_SetAltNames
	#endif
	
    #define SetIssuerBuffer   wc_SetIssuerBuffer
	#define SetSubjectBuffer  wc_SetSubjectBuffer
	#define SetAltNamesBuffer wc_SetAltNamesBuffer
	#define SetDatesBuffer    wc_SetDatesBuffer
	
	    #ifdef HAVE_NTRU
	        #define MakeNtruCert wc_MakeNtruCert
	    #endif
	
	#endif /* WOLFSSL_CERT_GEN */
	
    #if defined(WOLFSSL_KEY_GEN) || defined(WOLFSSL_CERT_GEN)
	    #define DerToPem wc_DerToPem
	#endif
	
	#ifdef HAVE_ECC
	    /* private key helpers */
	    #define EccPrivateKeyDecode wc_EccPrivateKeyDecode
	    #define EccKeyToDer         wc_EccKeyToDer
	#endif
	
	/* DER encode signature */
	#define EncodeSignature wc_EncodeSignature
	#define GetCTC_HashOID  wc_GetCTC_HashOID
#else
	#define WOLFSSL_CERT_GEN  CYASSL_CERTGEN
	#define WOLFSSL_CERT_REQ  CYASSL_CERT_REQ
	#define WOLFSSL_ALT_NAMES CYASSL_ALT_NAMES
	
	#ifdef WOLFSSL_CERT_GEN
	#define wc_InitCert InitCert
	#define wc_MakeCert MakeCert
	
    #ifdef WOLFSSL_CERT_REQ
	    #define wc_MakeCertReq MakeCertReq
	#endif
	
    #define wc_SignCert     SignCert
	#define wc_MakeSelfCert MakeSelfCert
	#define wc_SetIssuer    SetIssuer
	#define wc_SetSubject   SetSubject
	
    #ifdef WOLFSSL_ALT_NAMES
	    #define wc_SetAltNames SetAltNames
	#endif
	
    #define wc_SetIssuerBuffer   SetIssuerBuffer
	#define wc_SetSubjectBuffer  SetSubjectBuffer
	#define wc_SetAltNamesBuffer SetAltNamesBuffer
	#define wc_SetDatesBuffer    SetDatesBuffer
	
	    #ifdef HAVE_NTRU
	        #define wc_MakeNtruCert MakeNtruCert
	    #endif
	
	#endif /* WOLFSSL_CERT_GEN */
	
    #if defined(WOLFSSL_KEY_GEN) || defined(WOLFSSL_CERT_GEN)
	    #define wc_DerToPem DerToPem
	#endif
	
	#ifdef HAVE_ECC
	    /* private key helpers */
	    #define wc_EccPrivateKeyDecode EccPrivateKeyDecode
	    #define wc_EccKeyToDer         EccKeyToDer
	#endif
	
	/* DER encode signature */
	#define wc_EncodeSignature EncodeSignature
	#define wc_GetCTC_HashOID  GetCTC_HashOID
#endif /* HAVE_FIPS */
#endif /* CTA_CRYPT_ASN_PUBLIC_H */

