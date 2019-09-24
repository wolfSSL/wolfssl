/* asn1.h
 *
 * Copyright (C) 2006-2019 wolfSSL Inc.
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

#define ASN1_STRING_new      wolfSSL_ASN1_STRING_new
#define ASN1_STRING_type_new wolfSSL_ASN1_STRING_type_new
#define ASN1_STRING_type     wolfSSL_ASN1_STRING_type
#define ASN1_STRING_set      wolfSSL_ASN1_STRING_set
#define ASN1_STRING_free     wolfSSL_ASN1_STRING_free

#define V_ASN1_INTEGER                   0x02
#define V_ASN1_OCTET_STRING              0x04 /* tag for ASN1_OCTET_STRING */
#define V_ASN1_NEG                       0x100
#define V_ASN1_NEG_INTEGER               (2 | V_ASN1_NEG)
#define V_ASN1_NEG_ENUMERATED            (10 | V_ASN1_NEG)

/* Type for ASN1_print_ex */
# define ASN1_STRFLGS_ESC_2253           1
# define ASN1_STRFLGS_ESC_CTRL           2
# define ASN1_STRFLGS_ESC_MSB            4
# define ASN1_STRFLGS_ESC_QUOTE          8
# define ASN1_STRFLGS_UTF8_CONVERT       0x10
# define ASN1_STRFLGS_IGNORE_TYPE        0x20
# define ASN1_STRFLGS_SHOW_TYPE          0x40
# define ASN1_STRFLGS_DUMP_ALL           0x80
# define ASN1_STRFLGS_DUMP_UNKNOWN       0x100
# define ASN1_STRFLGS_DUMP_DER           0x200
# define ASN1_STRFLGS_RFC2253            (ASN1_STRFLGS_ESC_2253 | \
                                          ASN1_STRFLGS_ESC_CTRL | \
                                          ASN1_STRFLGS_ESC_MSB | \
                                          ASN1_STRFLGS_UTF8_CONVERT | \
                                          ASN1_STRFLGS_DUMP_UNKNOWN | \
                                          ASN1_STRFLGS_DUMP_DER)

#define MBSTRING_UTF8                    0x1000
#define MBSTRING_ASC                     0x1001
#define MBSTRING_BMP                     0x1002
#define MBSTRING_UNIV                    0x1004

#define ASN1_UTCTIME_print              wolfSSL_ASN1_UTCTIME_print
#define ASN1_TIME_check                 wolfSSL_ASN1_TIME_check
#define ASN1_TIME_diff                  wolfSSL_ASN1_TIME_diff
#define ASN1_TIME_set                   wolfSSL_ASN1_TIME_set

#define V_ASN1_UTCTIME                  23
#define V_ASN1_GENERALIZEDTIME          24

#define ASN1_STRING_FLAG_BITS_LEFT       0x008
#define ASN1_STRING_FLAG_NDEF            0x010
#define ASN1_STRING_FLAG_CONT            0x020
#define ASN1_STRING_FLAG_MSTRING         0x040
#define ASN1_STRING_FLAG_EMBED           0x080


WOLFSSL_API WOLFSSL_ASN1_INTEGER *wolfSSL_BN_to_ASN1_INTEGER(
    const WOLFSSL_BIGNUM*, WOLFSSL_ASN1_INTEGER*);
#define BN_to_ASN1_INTEGER wolfSSL_BN_to_ASN1_INTEGER


#endif /* WOLFSSL_ASN1_H_ */
