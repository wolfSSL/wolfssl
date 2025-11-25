/* psoc6_crypto.h
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

#ifndef _PSOC6_CRYPTO_PORT_H_
#define _PSOC6_CRYPTO_PORT_H_

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h> /* for MATH_INT_T */
#include <wolfssl/wolfcrypt/wc_port.h>

#if defined(WOLFSSL_PSOC6_CRYPTO)

#include "cy_pdl.h"

/* Enable SHA-1 hardware acceleration if SHA-1 is enabled in wolfSSL */
#if !defined(NO_SHA)
    #define PSOC6_HASH_SHA1
#endif

/* Enable SHA-2 family hardware acceleration if any SHA-2 variant is enabled */
#if !defined(NO_SHA256) || defined(WOLFSSL_SHA224) || \
    defined(WOLFSSL_SHA384) || defined(WOLFSSL_SHA512)
    #define PSOC6_HASH_SHA2
#endif

/* Enable SHA-3 hardware acceleration if SHA-3 is enabled in wolfSSL */
#if defined(WOLFSSL_SHA3)
    #define PSOC6_HASH_SHA3
#endif

/* Enable AES support for PSOC6. */
#ifndef NO_AES
    #define PSOC6_CRYPTO_AES
#endif /* !NO_AES */

typedef enum {
    WC_PSOC6_SHA1       = 0,
    WC_PSOC6_SHA224     = 1,
    WC_PSOC6_SHA256     = 2,
    WC_PSOC6_SHA384     = 3,
    WC_PSOC6_SHA512     = 4,
    WC_PSOC6_SHA512_224 = 5,
    WC_PSOC6_SHA512_256 = 6
} wc_psoc6_hash_sha1_sha2_t;

#if defined(PSOC6_HASH_SHA1) || defined(PSOC6_HASH_SHA2)
int wc_Psoc6_Sha1_Sha2_Init(void* sha, wc_psoc6_hash_sha1_sha2_t hash_mode,
                            int init_hash);
#endif /* PSOC6_HASH_SHA1 || PSOC6_HASH_SHA2 */

#if defined(PSOC6_HASH_SHA1) || defined(PSOC6_HASH_SHA2) ||                    \
    defined(PSOC6_HASH_SHA3)
int wc_Psoc6_Sha_Free(void);
#endif /* PSOC6_HASH_SHA1 || PSOC6_HASH_SHA2 || PSOC6_HASH_SHA3 */

#if defined(WOLFSSL_SHA3) && defined(PSOC6_HASH_SHA3)

int wc_Psoc6_Sha3_Init(void* sha3);
int wc_Psoc6_Sha3_Update(void* sha3, const byte* data, word32 len, byte p);
int wc_Psoc6_Sha3_Final(void* sha3, byte padChar, byte* hash, byte p, word32 l);
int wc_Psoc6_Shake_SqueezeBlocks(void* shake, byte* out, word32 blockCnt);
#endif /* WOLFSSL_SHA3 && PSOC6_HASH_SHA3 */

/* AES functions */
#if defined(PSOC6_CRYPTO_AES)
struct Aes; /* Forward declaration */

int wc_Psoc6_Aes_SetKey(struct Aes* aes, const byte* userKey, word32 keylen,
                        const byte* iv, int dir);
void wc_Psoc6_Aes_Free(struct Aes* aes);
int wc_Psoc6_Aes_Encrypt(struct Aes* aes, const byte* in, byte* out);
#ifdef HAVE_AES_DECRYPT
int wc_Psoc6_Aes_Decrypt(struct Aes* aes, const byte* in, byte* out);
#endif /* HAVE_AES_DECRYPT */

#ifdef WOLFSSL_AES_DIRECT
int wc_Psoc6_Aes_EncryptDirect(struct Aes* aes, byte* out, const byte* in);
#ifdef HAVE_AES_DECRYPT
int wc_Psoc6_Aes_DecryptDirect(struct Aes* aes, byte* out, const byte* in);
#endif /* HAVE_AES_DECRYPT */
#endif /* WOLFSSL_AES_DIRECT */

#ifdef HAVE_AES_ECB
int wc_Psoc6_Aes_EcbEncrypt(struct Aes* aes, byte* out, const byte* in,
                            word32 sz);
#ifdef HAVE_AES_DECRYPT
int wc_Psoc6_Aes_EcbDecrypt(struct Aes* aes, byte* out, const byte* in,
                            word32 sz);
#endif /* HAVE_AES_DECRYPT */
#endif /* HAVE_AES_ECB */

#ifdef HAVE_AES_CBC
int wc_Psoc6_Aes_CbcEncrypt(struct Aes* aes, byte* out, const byte* in,
                            word32 sz);
#ifdef HAVE_AES_DECRYPT
int wc_Psoc6_Aes_CbcDecrypt(struct Aes* aes, byte* out, const byte* in,
                            word32 sz);
#endif /* HAVE_AES_DECRYPT */
#endif /* HAVE_AES_CBC */

#ifdef WOLFSSL_AES_CFB
int wc_Psoc6_Aes_CfbEncrypt(struct Aes* aes, byte* out, const byte* in,
                            word32 sz);
#ifdef HAVE_AES_DECRYPT
int wc_Psoc6_Aes_CfbDecrypt(struct Aes* aes, byte* out, const byte* in,
                            word32 sz);
#endif /* HAVE_AES_DECRYPT */
#endif /* WOLFSSL_AES_CFB */

#ifdef HAVE_AESGCM
int wc_Psoc6_Aes_Gcm_SetKey(struct Aes* aes, const byte* key, word32 len);
int wc_Psoc6_Aes_GcmEncrypt(struct Aes* aes, byte* out, const byte* in,
                            word32 sz, const byte* iv, word32 ivSz,
                            byte* authTag, word32 authTagSz, const byte* authIn,
                            word32 authInSz);
#ifdef HAVE_AES_DECRYPT
int wc_Psoc6_Aes_GcmDecrypt(struct Aes* aes, byte* out, const byte* in,
                            word32 sz, const byte* iv, word32 ivSz,
                            const byte* authTag, word32 authTagSz,
                            const byte* authIn, word32 authInSz);
#endif /* HAVE_AES_DECRYPT */
#endif /* HAVE_AESGCM */
#endif /* NO_AES */

#ifdef HAVE_ECC

/* Forward declaration of ecc_key structure.
 * Only pointers to struct ecc_key are used in this header,
 * so the forward declaration is sufficient.
 * The full definition is in wolfssl/wolfcrypt/ecc.h.
 */
struct ecc_key;

int psoc6_ecc_verify_hash_ex(MATH_INT_T* r, MATH_INT_T* s, const byte* hash,
                             word32 hashlen, int* verif_res,
                             struct ecc_key* key);
#endif /* HAVE_ECC */

#define PSOC6_CRYPTO_BASE ((CRYPTO_Type*)CRYPTO_BASE)

/* Crypto HW engine initialization */
int psoc6_crypto_port_init(void);

#endif /* WOLFSSL_PSOC6_CRYPTO */

#endif /* _PSOC6_CRYPTO_PORT_H_ */
