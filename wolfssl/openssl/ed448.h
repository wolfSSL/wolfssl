/* ed448.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

/* ed448.h */

#ifndef WOLFSSL_ED448_H_
#define WOLFSSL_ED448_H_

#include <wolfssl/openssl/compat_types.h>

#ifdef __cplusplus
extern "C" {
#endif

WOLFSSL_API
int wolfSSL_ED448_generate_key(unsigned char *priv, unsigned int *privSz,
                               unsigned char *pub, unsigned int *pubSz);
WOLFSSL_API
int wolfSSL_ED448_sign(const unsigned char *msg, unsigned int msgSz,
                       const unsigned char *priv, unsigned int privSz,
                       unsigned char *sig, unsigned int *sigSz);
WOLFSSL_API
int wolfSSL_ED448_verify(const unsigned char *msg, unsigned int msgSz,
                         const unsigned char *pub, unsigned int pubSz,
                         const unsigned char *sig, unsigned int sigSz);

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
#ifndef WC_ED448KEY_TYPE_DEFINED
    typedef struct ed448_key ed448_key;
    #define WC_ED448KEY_TYPE_DEFINED
#endif
/* Not OpenSSL API's, but these two constructors are leveraged within
 * wolfSSL's compat layer for Ed448 object creation/deletion simplicity */
WOLFSSL_API
ed448_key* wolfSSL_ED448_new(void* heap, int devId);

WOLFSSL_API
void wolfSSL_ED448_free(ed448_key* key);
#endif

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* header */
