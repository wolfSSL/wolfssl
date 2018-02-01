/* asn1.h
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

/* asn1.h for openssl */

#ifndef WOLFSSL_ASN1_H_
#define WOLFSSL_ASN1_H_

#include <wolfssl/openssl/ssl.h>

#define ASN1_STRING_new      wolfSSL_ASN1_STRING_type_new
#define ASN1_STRING_type_new wolfSSL_ASN1_STRING_type_new
#define ASN1_STRING_set      wolfSSL_ASN1_STRING_set
#define ASN1_STRING_free     wolfSSL_ASN1_STRING_free

#define V_ASN1_OCTET_STRING  0x04 /* tag for ASN1_OCTET_STRING */
#endif /* WOLFSSL_ASN1_H_ */
