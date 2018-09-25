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

struct WOLFSSL_AUTHORITY_KEYID {
    WOLFSSL_ASN1_STRING *keyid;
    GENERAL_NAME *issuer;
    WOLFSSL_ASN1_INTEGER *serial;
};

#define ASN1_INTEGER        WOLFSSL_ASN1_INTEGER
#define ASN1_OCTET_STRING   WOLFSSL_ASN1_STRING

/* currently stub function, may need to add more later */
struct WOLFSSL_v3_ext_method {
    int ext_nid;
    int ext_flags;
    void *usr_data;         
};

struct WOLFSSL_ACCESS_DESCRIPTION {
    ASN1_OBJECT *method;
    GENERAL_NAME *location;
};

typedef WOLFSSL_AUTHORITY_KEYID AUTHORITY_KEYID;
typedef WOLFSSL_ACCESS_DESCRIPTION ACCESS_DESCRIPTION;
typedef STACK_OF(WOLFSSL_ACCESS_DESCRIPTION) AUTHORITY_INFO_ACCESS;
typedef WOLFSSL_v3_ext_method X509V3_EXT_METHOD;
