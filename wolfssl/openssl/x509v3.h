/* x509v3.h
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

/* x509v3.h for openSSL */

#ifndef WOLFSSL_x509v3_H
#define WOLFSSL_x509v3_H

#include <wolfssl/openssl/conf.h>
#include <wolfssl/openssl/bio.h>

#ifdef __cplusplus
    extern "C" {
#endif

struct WOLFSSL_ACCESS_DESCRIPTION {
    WOLFSSL_ASN1_OBJECT *method;
    WOLFSSL_GENERAL_NAME *location;
};

typedef struct WOLFSSL_ACCESS_DESCRIPTION ACCESS_DESCRIPTION;

#ifdef  __cplusplus
}
#endif

#endif
