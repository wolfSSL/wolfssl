/* ocsp.h
 *
 * Copyright (C) 2015 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */


#ifndef WOLFSSL_OCSP_H_
#define WOLFSSL_OCSP_H_

#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/evp.h>

#ifdef __cplusplus
    extern "C" {
#endif

#ifdef HAVE_STUNNEL
	#define X509_get1_ocsp                   wolfSSL_X509_get1_ocsp
	#define OCSP_CERTID_free                 wolfSSL_OCSP_CERTID_free
	#define OCSP_cert_to_id                  wolfSSL_OCSP_cert_to_id
    #define OCSP_REQUEST_free                wolfSSL_OCSP_REQUEST_free

    #define OPENSSL_STRING           WOLFSSL_STRING
    #define sk_OPENSSL_STRING_value  wolfSSL_sk_WOLFSSL_STRING_value
    #define sk_OPENSSL_STRING_num    wolfSSL_sk_WOLFSSL_STRING_num

    typedef WOLFSSL_OCSP_CERTID        OCSP_CERTID;
    typedef char*                      WOLFSSL_STRING;
    typedef WOLFSSL_OCSP_RESPONSE      OCSP_RESPONSE;


	WOLFSSL_API WOLFSSL_STRING *wolfSSL_X509_get1_ocsp(WOLFSSL_X509*);
	WOLFSSL_API void wolfSSL_OCSP_CERTID_free(WOLFSSL_OCSP_CERTID* cert);
	WOLFSSL_API
    WOLFSSL_OCSP_CERTID* wolfSSL_OCSP_cert_to_id(const WOLFSSL_EVP_MD*,
	            WOLFSSL_X509*, WOLFSSL_X509*);

    WOLFSSL_API
    int wolfSSL_sk_WOLFSSL_STRING_num(const STACK_OF(WOLFSSL_STRING)*);
    WOLFSSL_API WOLFSSL_STRING wolfSSL_sk_WOLFSSL_STRING_value(
            const STACK_OF(WOLFSSL_STRING)*, int);


	WOLFSSL_API void wolfSSL_OCSP_REQUEST_free(WOLFSSL_OCSP_REQUEST*);
#endif /* HAVE_STUNNEL */

#ifdef __cplusplus
    } /* extern "C" */
#endif


#endif /* WOLFSSL_EVP_H_ */
