/* signature.h
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

/*!
    \file wolfssl/wolfcrypt/signature.h
*/


#ifndef WOLF_CRYPT_SIGNATURE_H
#define WOLF_CRYPT_SIGNATURE_H

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/random.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* Minimum hash strength accepted by the wc_SignatureVerify/Generate
 * convenience APIs. Default is SHA-256 to keep MD5 and SHA-1 (both with
 * known collision attacks) out of new code. Define WC_SIG_MIN_HASH_TYPE
 * to a weaker wc_HashType (e.g. WC_HASH_TYPE_SHA) to opt back into legacy
 * behavior. The lower-level wc_SignatureVerifyHash/wc_SignatureGenerateHash
 * APIs are unaffected. */
#ifndef WC_SIG_MIN_HASH_TYPE
    #define WC_SIG_MIN_HASH_TYPE WC_HASH_TYPE_SHA256
#endif

enum wc_SignatureType {
    WC_SIGNATURE_TYPE_NONE = 0,
    WC_SIGNATURE_TYPE_ECC = 1,
    WC_SIGNATURE_TYPE_RSA = 2,
    WC_SIGNATURE_TYPE_RSA_W_ENC = 3 /* Adds DER header via wc_EncodeSignature */
};

WOLFSSL_API int wc_SignatureGetSize(enum wc_SignatureType sig_type,
    const void* key, word32 key_len);

WOLFSSL_API int wc_SignatureVerifyHash(
    enum wc_HashType hash_type, enum wc_SignatureType sig_type,
    const byte* hash_data, word32 hash_len,
    const byte* sig, word32 sig_len,
    void* key, word32 key_len);

WOLFSSL_API int wc_SignatureVerify(
    enum wc_HashType hash_type, enum wc_SignatureType sig_type,
    const byte* data, word32 data_len,
    const byte* sig, word32 sig_len,
    void* key, word32 key_len);

WOLFSSL_API int wc_SignatureGenerateHash(
    enum wc_HashType hash_type, enum wc_SignatureType sig_type,
    const byte* hash_data, word32 hash_len,
    byte* sig, word32 *sig_len,
    void* key, word32 key_len, WC_RNG* rng);
WOLFSSL_API int wc_SignatureGenerateHash_ex(
    enum wc_HashType hash_type, enum wc_SignatureType sig_type,
    const byte* hash_data, word32 hash_len,
    byte* sig, word32 *sig_len,
    void* key, word32 key_len, WC_RNG* rng, int verify);
WOLFSSL_API int wc_SignatureGenerate(
    enum wc_HashType hash_type, enum wc_SignatureType sig_type,
    const byte* data, word32 data_len,
    byte* sig, word32 *sig_len,
    void* key, word32 key_len,
    WC_RNG* rng);
WOLFSSL_API int wc_SignatureGenerate_ex(
    enum wc_HashType hash_type, enum wc_SignatureType sig_type,
    const byte* data, word32 data_len,
    byte* sig, word32 *sig_len,
    void* key, word32 key_len,
    WC_RNG* rng, int verify);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLF_CRYPT_SIGNATURE_H */
