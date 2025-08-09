/* renesas-fspsm-crypt.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
#ifndef __RENESAS_FSPSM_CRYPT_H__
#define __RENESAS_FSPSM_CRYPT_H__

#include <wolfssl/wolfcrypt/port/Renesas/renesas-fspsm-types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WOLFSSL_FSPSM_ILLEGAL_CIPHERSUITE     -1

typedef void* FSPSM_W_KEYVAR;

/* flags Crypt Only */
struct FSPSM_key_flg_ST {
    uint8_t aes256_installedkey_set:1;
    uint8_t aes128_installedkey_set:1;
    uint8_t rsapri2048_installedkey_set:1;
    uint8_t rsapub2048_installedkey_set:1;
    uint8_t rsapri1024_installedkey_set:1;
    uint8_t rsapub1024_installedkey_set:1;
    uint8_t message_type:1;/*message 0, hashed 1*/
};

typedef struct FSPSM_ST_Internal FSPSM_ST_Internal;

typedef struct FSPSM_tag_ST {
    /* unique number for each session */
    int devId;

    /* installed key handling */
    /* aes */
    FSPSM_W_KEYVAR   wrapped_key_aes256;
    FSPSM_W_KEYVAR   wrapped_key_aes128;

   #if defined(WOLFSSL_RENESAS_FSPSM_CRYPTONLY)
    /* rsa */
    FSPSM_W_KEYVAR   wrapped_key_rsapri2048;
    FSPSM_W_KEYVAR   wrapped_key_rsapub2048;
    FSPSM_W_KEYVAR   wrapped_key_rsapri1024;
    FSPSM_W_KEYVAR   wrapped_key_rsapub1024;
   #endif

   #if defined(WOLFSSL_RENESAS_RSIP)
    uint8_t hash_type;
   #endif

    /* key status flags */
    /* flags shows status if wrapped keys are installed */
    union {
        uint8_t chr;
        struct FSPSM_key_flg_ST bits;
    } keyflgs_crypt;

    FSPSM_ST_Internal* internal;

} FSPSM_ST;

struct WOLFSSL;
struct WOLFSSL_CTX;
struct ecc_key;
struct wc_CryptoInfo;
struct Aes;


#if defined(WOLFSSL_RENESAS_FSPSM_TLS) && \
        !defined(WOLFSSL_RENESAS_FSPSM_CRYPT_ONLY)
/* user API */
WOLFSSL_API void FSPSM_INFORM_FUNC(
    uint8_t*     encrypted_provisioning_key,
    uint8_t*     iv,
    uint8_t*     encrypted_user_tls_key,
    uint32_t    encrypted_user_tls_key_type);

WOLFSSL_API void FSPSM_CALLBACK_FUNC(struct WOLFSSL_CTX* ctx);
WOLFSSL_API int  FSPSM_CALLBACK_CTX_FUNC(struct WOLFSSL* ssl, void* user_ctx);
WOLFSSL_API void FSPSM_INFORM_CERT_SIGN(const uint8_t *sign);

#endif  /* WOLFSSL_RENESAS_FSPSM_TLS &&
         * !WOLFSSL_RENESAS_FSPSM_CRYPT_ONLY */

#endif  /* __RENESAS_FSPSM_CRYPT_H__ */
