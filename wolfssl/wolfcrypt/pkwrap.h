/* pk_wrap.h
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
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

#ifndef _PK_WRAP_H_
#define _PK_WRAP_H_

#ifndef NO_PK_WRAPPER

#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>

typedef enum {
    WOLFSSL_PK_NONE = 0,
    WOLFSSL_PK_RSA,
    WOLFSSL_PK_RSASSA_PSS,
    WOLFSSL_PK_ECKEY,
    WOLFSSL_PK_ECKEY_DH,
    WOLFSSL_PK_ECDSA,
} wc_pk_type_t;

typedef struct wc_pk_context {
    void* heap;
    int devId;
    union {
    #ifndef NO_RSA
        RsaKey rsa;
    #endif
    #ifdef HAVE_ECC
        ecc_key  ecc;
    #endif
        void* ptr;
    } key;
    int type;  /* wc_pk_type_t */
    int keyBits;
    byte* der;
    word32 derLen;
} wc_pk_context;


WOLFSSL_API wc_pk_context* wc_pk_new_ex(void* heap, int devId);
WOLFSSL_API wc_pk_context* wc_pk_new(void);

WOLFSSL_API wc_pk_type_t wc_pk_get_type(const wc_pk_context *pk);
WOLFSSL_API word32 wc_pk_get_bitlen(const wc_pk_context *pk);

WOLFSSL_API void* wc_pk_get_key(const wc_pk_context *pk);

WOLFSSL_API int wc_pk_get_key_der(const wc_pk_context *pk, byte* der, word32* derLen);

WOLFSSL_API void wc_pk_key_free(wc_pk_context *pk);

WOLFSSL_API int wc_pk_create_key(wc_pk_context *pk, wc_pk_type_t pk_type, 
    int keySz, int curve_id);

WOLFSSL_API int wc_pk_load_key(wc_pk_context *pk,
                     const byte *der, word32 derlen);

WOLFSSL_API int wc_pk_parse_key(wc_pk_context *pk,
                    const byte *key, word32 keylen,
                    const byte *pwd, word32 pwdlen);

WOLFSSL_API int wc_pk_sign(wc_pk_context *pk,
               int hashType, int mgf,
               const byte* pucHash,
               word32 uiHashLen,
               byte* pucSig,
               word32* pxSigLen,
               WC_RNG* pRng);

WOLFSSL_API int wc_pk_verify(wc_pk_context *pk,
                 int hashType, int mgf,
                 const byte* pucHash,
                 word32 uiHashLen,
                 const byte* pucSig,
                 word32 ulSigLen);

WOLFSSL_API void wc_pk_free(wc_pk_context *pk);

#endif /* NO_PK_WRAPPER */

#endif /* _PK_WRAP_H_ */
