/* ocsp.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
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



/* wolfSSL OCSP API */

#ifndef WOLFSSL_OCSP_H
#define WOLFSSL_OCSP_H

#ifdef HAVE_OCSP

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>

#ifdef __cplusplus
    extern "C" {
#endif

struct buffer;
typedef struct WOLFSSL_OCSP WOLFSSL_OCSP;

WOLFSSL_LOCAL int  InitOCSP(WOLFSSL_OCSP*, WOLFSSL_CERT_MANAGER*);
WOLFSSL_LOCAL void FreeOCSP(WOLFSSL_OCSP*, int dynamic);

WOLFSSL_LOCAL int  CheckCertOCSP(WOLFSSL_OCSP*, DecodedCert*,
                                            struct buffer* responseBuffer);
WOLFSSL_LOCAL int  CheckOcspRequest(WOLFSSL_OCSP* ocsp,
                   OcspRequest* ocspRequest, struct buffer* responseBuffer);

#ifdef __cplusplus
    }  /* extern "C" */
#endif


#endif /* HAVE_OCSP */
#endif /* WOLFSSL_OCSP_H */


