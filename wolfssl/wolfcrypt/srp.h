/* srp.h
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
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

#ifdef WOLFCRYPT_HAVE_SRP

#ifndef WOLFCRYPT_SRP_H
#define WOLFCRYPT_SRP_H

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/integer.h>

#ifdef __cplusplus
    extern "C" {
#endif

enum {
    SRP_CLIENT_SIDE  = 0,
    SRP_SERVER_SIDE  = 1,
#ifndef NO_SHA
    SRP_TYPE_SHA     = 1,
#endif
#ifndef NO_SHA256
    SRP_TYPE_SHA256  = 2,
#endif
#ifdef WOLFSSL_SHA384
    SRP_TYPE_SHA384  = 3,
#endif
#ifdef WOLFSSL_SHA512
    SRP_TYPE_SHA512  = 4,
#endif

/* Select the largest available hash for the buffer size. */
#if defined(WOLFSSL_SHA512)
    SRP_MAX_DIGEST_SIZE = SHA512_DIGEST_SIZE,
#elif defined(WOLFSSL_SHA384)
    SRP_MAX_DIGEST_SIZE = SHA384_DIGEST_SIZE,
#elif !defined(NO_SHA256)
    SRP_MAX_DIGEST_SIZE = SHA256_DIGEST_SIZE,
#elif !defined(NO_SHA)
    SRP_MAX_DIGEST_SIZE = SHA_DIGEST_SIZE,
#else
    #error "You have to have some kind of SHA hash if you want to use SRP."
#endif
};

typedef struct {
    byte type;
    union {
        #ifndef NO_SHA
            Sha sha;
        #endif
        #ifndef NO_SHA256
            Sha256 sha256;
        #endif
        #ifdef WOLFSSL_SHA384
            Sha384 sha384;
        #endif
        #ifdef WOLFSSL_SHA512
            Sha512 sha512;
        #endif
    } data;
} SrpHash;

typedef struct {
    byte   side; /**< SRP_CLIENT_SIDE or SRP_SERVER_SIDE */
    byte   type; /**< Hash type, one of SRP_TYPE_SHA[|256|384|512] */
    byte*  user;                   /**< Username, login.                      */
    word32 userSz;                 /**< Username length.                      */
    byte*  salt;                   /**< Small salt.                           */
    word32 saltSz;                 /**< Salt length.                          */
    mp_int N;                      /**< Modulus. N = 2q+1, [q, N] are primes. */
    mp_int g;                      /**< Generator. A generator modulo N.      */
    byte   k[SRP_MAX_DIGEST_SIZE]; /**< Multiplier parameeter. H(N, g)        */
    mp_int auth;                   /**< Priv key. H(salt, H(user, ":", pswd)) */
    mp_int priv;                   /**< Private ephemeral value.              */
    mp_int pub;                    /**< Public ephemeral value.               */
    mp_int peer;                   /**< Peer's public ephemeral value.        */
    mp_int u;                      /**< Random scrambling parameeter.         */
    SrpHash client_proof;          /**< Client proof. Sent to Server.         */
    SrpHash server_proof;          /**< Server proof. Sent to Client.         */
    mp_int s;                      /**< Session key.                          */
} Srp;

WOLFSSL_API int wc_SrpInit(Srp* srp, byte type, byte side);

WOLFSSL_API void wc_SrpTerm(Srp* srp);

WOLFSSL_API int wc_SrpSetUsername(Srp* srp, const byte* username, word32 size);

WOLFSSL_API int wc_SrpSetParams(Srp* srp, const byte* N,    word32 nSz,
                                          const byte* g,    word32 gSz,
                                          const byte* salt, word32 saltSz);

WOLFSSL_API int wc_SrpSetPassword(Srp* srp, const byte* password, word32 size);

WOLFSSL_API int wc_SrpSetVerifier(Srp* srp, const byte* verifier, word32 size);

WOLFSSL_API int wc_SrpGetVerifier(Srp* srp, byte* verifier, word32* size);

WOLFSSL_API int wc_SrpSetPrivate(Srp* srp, const byte* private, word32 size);

WOLFSSL_API int wc_SrpGenPublic(Srp* srp, byte* public, word32* size);

WOLFSSL_API int wc_SrpComputeKey(Srp* srp, byte* peersKey, word32 peersKeySz);

#ifdef __cplusplus
   } /* extern "C" */
#endif

#endif /* WOLFCRYPT_SRP_H */
#endif /* WOLFCRYPT_HAVE_SRP */
