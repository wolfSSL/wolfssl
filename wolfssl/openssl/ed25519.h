/* ed25519.h
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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

/* ed25519.h */

#ifndef WOLFSSL_ED25519_H_
#define WOLFSSL_ED25519_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WOLFSSL_ED25519_TYPE_DEFINED /* guard on redeclaration */
typedef struct WOLFSSL_ED25519   WOLFSSL_ED25519;
#define WOLFSSL_ED25519_TYPE_DEFINED
#endif

typedef struct WOLFSSL_ED25519 {
    WOLFSSL_BIGNUM* p; /* public key */
    WOLFSSL_BIGNUM* k; /* private key */
    void* internal;
    /* bits */
    byte inSet:1;     /* internal set from external ? */
    byte exSet:1;     /* external set from internal ? */
} WOLFSSL_ED25519;

WOLFSSL_API
WOLFSSL_ED25519* wolfSSL_ED25519_new(void);

WOLFSSL_API
void wolfSSL_ED25519_free(WOLFSSL_ED25519 *key);

WOLFSSL_API
int wolfSSL_ED25519_generate_key(unsigned char *priv, unsigned int *privSz,
                                 unsigned char *pub, unsigned int *pubSz);
WOLFSSL_API
int wolfSSL_ED25519_sign(const unsigned char *msg, unsigned int msgSz,
                         const unsigned char *priv, unsigned int privSz,
                         unsigned char *sig, unsigned int *sigSz);
WOLFSSL_API
int wolfSSL_ED25519_verify(const unsigned char *msg, unsigned int msgSz,
                           const unsigned char *pub, unsigned int pubSz,
                           const unsigned char *sig, unsigned int sigSz);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* header */
