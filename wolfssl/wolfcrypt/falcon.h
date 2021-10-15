/* falcon.h
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

/*!
    \file wolfssl/wolfcrypt/falcon.h
*/

/* Interfaces for Falcon NIST Level 1 (AKA Falcon512) and Falcon NIST Level 5
 * (AKA Falcon1024). */

#ifndef WOLF_CRYPT_FALCON_H
#define WOLF_CRYPT_FALCON_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef HAVE_LIBOQS

#include <oqs/oqs.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* Macros Definitions */ 

#define FALCON_LEVEL1_KEY_SIZE     OQS_SIG_falcon_512_length_secret_key
#define FALCON_LEVEL1_SIG_SIZE     OQS_SIG_falcon_512_length_signature
#define FALCON_LEVEL1_PUB_KEY_SIZE OQS_SIG_falcon_512_length_public_key
#define FALCON_LEVEL1_PRV_KEY_SIZE (FALCON_LEVEL1_PUB_KEY_SIZE+FALCON_LEVEL1_KEY_SIZE)

#define FALCON_LEVEL5_KEY_SIZE     OQS_SIG_falcon_1024_length_secret_key
#define FALCON_LEVEL5_SIG_SIZE     OQS_SIG_falcon_1024_length_signature
#define FALCON_LEVEL5_PUB_KEY_SIZE OQS_SIG_falcon_1024_length_public_key
#define FALCON_LEVEL5_PRV_KEY_SIZE (FALCON_LEVEL5_PUB_KEY_SIZE+FALCON_LEVEL5_KEY_SIZE)

/* Structs */

struct falcon_level1_key {
    bool pubKeySet;
    bool prvKeySet;
    byte p[FALCON_LEVEL1_PUB_KEY_SIZE];
    byte k[FALCON_LEVEL1_PRV_KEY_SIZE];
    void *heap;
};

struct falcon_level5_key {
    bool pubKeySet;
    bool prvKeySet;
    byte p[FALCON_LEVEL5_PUB_KEY_SIZE];
    byte k[FALCON_LEVEL5_PRV_KEY_SIZE];
    void *heap;
};

#ifndef WC_FALCONKEY_TYPE_DEFINED
    typedef struct falcon_level1_key falcon_level1_key;
    typedef struct falcon_level5_key falcon_level5_key;
    #define WC_FALCONKEY_TYPE_DEFINED
#endif

/***********************************/
/* Falcon Level 1 APIs [Falcon512] */
/***********************************/

/* ANTH TODO */
#if 0
WOLFSSL_API
int wc_falcon_level1_make_public(falcon_level1_key* key, unsigned char* pubKey,
                                 word32 pubKeySz);
WOLFSSL_API
int wc_falcon_level1_make_key(WC_RNG* rng, int keysize, falcon_level1_key* key);
WOLFSSL_API
#endif

int wc_falcon_level1_sign_msg(const byte* in, word32 inLen, byte* out,
                              word32 *outLen,  falcon_level1_key* key);
WOLFSSL_API
int wc_falcon_level1_verify_msg(const byte* sig, word32 sigLen, const byte* msg,
                                word32 msgLen, int* stat,
                                falcon_level1_key* key);

WOLFSSL_API
int wc_falcon_level1_init(falcon_level1_key* key);
WOLFSSL_API
void wc_falcon_level1_free(falcon_level1_key* key);

WOLFSSL_API
int wc_falcon_level1_import_public(const byte* in, word32 inLen,
                                   falcon_level1_key* key);
WOLFSSL_API
int wc_falcon_level1_import_private_only(const byte* priv, word32 privSz,
                                         falcon_level1_key* key);
WOLFSSL_API
int wc_falcon_level1_import_private_key(const byte* priv, word32 privSz,
                                        const byte* pub, word32 pubSz,
                                        falcon_level1_key* key);

WOLFSSL_API
int wc_falcon_level1_export_public(falcon_level1_key*, byte* out,
                                   word32* outLen);
WOLFSSL_API
int wc_falcon_level1_export_private_only(falcon_level1_key* key, byte* out,
                                         word32* outLen);
WOLFSSL_API
int wc_falcon_level1_export_private(falcon_level1_key* key, byte* out,
                                    word32* outLen);
WOLFSSL_API
int wc_falcon_level1_export_key(falcon_level1_key* key, byte* priv,
                                word32 *privSz, byte* pub, word32 *pubSz);

WOLFSSL_API
int wc_falcon_level1_check_key(falcon_level1_key* key);

WOLFSSL_API
int wc_falcon_level1_size(falcon_level1_key* key);
WOLFSSL_API
int wc_falcon_level1_priv_size(falcon_level1_key* key);
WOLFSSL_API
int wc_falcon_level1_pub_size(falcon_level1_key* key);
WOLFSSL_API
int wc_falcon_level1_sig_size(falcon_level1_key* key);

/************************************/
/* Falcon Level 5 APIs [Falcon1024] */
/************************************/

/* ANTH TODO */
#if 0
WOLFSSL_API
int wc_falcon_level5_make_public(falcon_level5_key* key, unsigned char* pubKey,
                                 word32 pubKeySz);
WOLFSSL_API
int wc_falcon_level5_make_key(WC_RNG* rng, int keysize, falcon_level5_key* key);
#endif

WOLFSSL_API
int wc_falcon_level5_sign_msg(const byte* in, word32 inLen, byte* out,
                              word32 *outLen, falcon_level5_key* key);
WOLFSSL_API
int wc_falcon_level5_verify_msg(const byte* sig, word32 sigLen, const byte* msg,
                        word32 msgLen, int* stat, falcon_level5_key* key);

WOLFSSL_API
int wc_falcon_level5_init(falcon_level5_key* key);
WOLFSSL_API
void wc_falcon_level5_free(falcon_level5_key* key);

WOLFSSL_API
int wc_falcon_level5_import_public(const byte* in, word32 inLen,
                                   falcon_level5_key* key);
WOLFSSL_API
int wc_falcon_level5_import_private_only(const byte* priv, word32 privSz,
                                         falcon_level5_key* key);
WOLFSSL_API
int wc_falcon_level5_import_private_key(const byte* priv, word32 privSz,
                                        const byte* pub, word32 pubSz,
                                        falcon_level5_key* key);

WOLFSSL_API
int wc_falcon_level5_export_public(falcon_level5_key*, byte* out,
                                   word32* outLen);
WOLFSSL_API
int wc_falcon_level5_export_private_only(falcon_level5_key* key, byte* out,
                                         word32* outLen);
WOLFSSL_API
int wc_falcon_level5_export_private(falcon_level5_key* key, byte* out,
                                    word32* outLen);
WOLFSSL_API
int wc_falcon_level5_export_key(falcon_level5_key* key, byte* priv,
                                word32 *privSz, byte* pub, word32 *pubSz);

WOLFSSL_API
int wc_falcon_level5_check_key(falcon_level5_key* key);

WOLFSSL_API
int wc_falcon_level5_size(falcon_level5_key* key);
WOLFSSL_API
int wc_falcon_level5_priv_size(falcon_level5_key* key);
WOLFSSL_API
int wc_falcon_level5_pub_size(falcon_level5_key* key);
WOLFSSL_API
int wc_falcon_level5_sig_size(falcon_level5_key* key);

#ifdef __cplusplus
    }    /* extern "C" */
#endif

#endif /* HAVE_LIBOQS */
#endif /* WOLF_CRYPT_FALCON_H */
