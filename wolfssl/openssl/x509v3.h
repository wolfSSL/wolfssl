/* x508v3.h
 *
 * Copyright (C) 2006-2017 wolfSSL Inc.
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

/* x509v3.h for openSSL */

#ifndef WOLFSSL_x509v3_H_
#define WOLFSSL_x509v3_H_

#include <wolfssl/openssl/conf.h>
#include <wolfssl/openssl/bio.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* Forward reference */
struct WOLFSSL_v3_ext_method;

typedef STACK_OF(CONF_VALUE) *(*X509V3_EXT_I2V) (struct WOLFSSL_v3_ext_method *method, 
                                      void *ext, STACK_OF(CONF_VALUE) *extlist);
typedef char *(*X509V3_EXT_I2S)(struct WOLFSSL_v3_ext_method *method, void *ext);
typedef int (*X509V3_EXT_I2R) (struct WOLFSSL_v3_ext_method *method, void *ext,
                                                          BIO *out, int indent);

struct WOLFSSL_v3_ext_method {
    int ext_nid;
    int ext_flags;
    void *usr_data;
    X509V3_EXT_I2V i2v;
    X509V3_EXT_I2S i2s;
    X509V3_EXT_I2R i2r;
};

struct WOLFSSL_ACCESS_DESCRIPTION {
    ASN1_OBJECT *method;
    GENERAL_NAME *location;
};

typedef struct WOLFSSL_AUTHORITY_KEYID AUTHORITY_KEYID;
typedef struct WOLFSSL_BASIC_CONSTRAINTS BASIC_CONSTRAINTS;
typedef struct WOLFSSL_ACCESS_DESCRIPTION ACCESS_DESCRIPTION;
typedef STACK_OF(WOLFSSL_ACCESS_DESCRIPTION) AUTHORITY_INFO_ACCESS;
typedef struct WOLFSSL_v3_ext_method WOLFSSL_v3_ext_method;
typedef struct WOLFSSL_v3_ext_method X509V3_EXT_METHOD;


WOLFSSL_API void wolfSSL_BASIC_CONSTRAINTS_free(WOLFSSL_BASIC_CONSTRAINTS *bc);
WOLFSSL_API void wolfSSL_AUTHORITY_KEYID_free(WOLFSSL_AUTHORITY_KEYID *id);
WOLFSSL_API const WOLFSSL_v3_ext_method* wolfSSL_X509V3_EXT_get(WOLFSSL_X509_EXTENSION* ex);
WOLFSSL_API void* wolfSSL_X509V3_EXT_d2i(WOLFSSL_X509_EXTENSION* ex);

#define BASIC_CONSTRAINTS_free    wolfSSL_BASIC_CONSTRAINTS_free
#define AUTHORITY_KEYID_free      wolfSSL_AUTHORITY_KEYID_free
#define SSL_CTX_get_cert_store(x) wolfSSL_CTX_get_cert_store ((WOLFSSL_CTX*) (x))
#define ASN1_INTEGER              WOLFSSL_ASN1_INTEGER
#define ASN1_OCTET_STRING         WOLFSSL_ASN1_STRING
#define X509V3_EXT_get            wolfSSL_X509V3_EXT_get
#define X509V3_EXT_d2i            wolfSSL_X509V3_EXT_d2i

#ifdef  __cplusplus
}
#endif

#endif
