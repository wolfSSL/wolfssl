/* hpke.h
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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
    \file wolfssl/wolfcrypt/hpke.h
*/

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/ecc.h>

#ifdef __cplusplus
    extern "C" {
#endif

#if defined(HAVE_HPKE) && defined(HAVE_ECC)

/* KEM enum */
enum {
    DHKEM_P256_HKDF_SHA256 = 0x0010,
    DHKEM_P384_HKDF_SHA384 = 0x0011,
    DHKEM_P521_HKDF_SHA512 = 0x0012,
    DHKEM_X25519_HKDF_SHA256 = 0x0020,
    DHKEM_X448_HKDF_SHA512 = 0x0021,
};

/* KDF enum */
enum {
    HKDF_SHA256 = 0x0001,
    HKDF_SHA384 = 0x0002,
    HKDF_SHA512 = 0x0003,
};

/* AEAD enum */
enum {
    HPKE_AES_128_GCM = 0x0001,
    HPKE_AES_256_GCM = 0x0002,
};

#define HPKE_Nh_MAX 64
#define HPKE_Nk_MAX 32
#define HPKE_Nn_MAX 12
#define HPKE_Nt_MAX 16
#define HPKE_Ndh_MAX 66
#define HPKE_Npk_MAX 133
#define HPKE_Nsecret_MAX 64
#define KEM_SUITE_ID_LEN 5
#define HPKE_SUITE_ID_LEN 10

#ifndef MAX_HPKE_LABEL_SZ
#define MAX_HPKE_LABEL_SZ 512
#endif

typedef struct {
    int kem;
    int kdf;
    int aead;
    int Nh;
    int Nk;
    int Nn;
    int Nt;
    int Ndh;
    int Npk;
    int Nsecret;
    int kdf_digest;
    int curve_id;
    void* heap;
    ecc_key receiver_key[1];
    byte kem_suite_id[5];
    byte hpke_suite_id[10];
    byte receiver_key_set:1;
} Hpke;

typedef struct {
    int seq;
    byte key[HPKE_Nk_MAX];
    byte base_nonce[HPKE_Nn_MAX];
    byte exporter_secret[HPKE_Nsecret_MAX];
} HpkeBaseContext;

WOLFSSL_API int wc_HpkeInit(Hpke* hpke, int kem, int kdf, int aead, void* heap);
WOLFSSL_API int wc_HpkeGenerateKeyPair(Hpke* hpke, ecc_key* keypair);
WOLFSSL_API int wc_HpkeSerializePublicKey(ecc_key* key, byte* out, word32* outSz);
WOLFSSL_API int wc_HpkeDeserializePublicKey(Hpke* hpke, ecc_key* key, const byte* in, word32 inSz);
WOLFSSL_API int wc_HpkeSealBase(Hpke* hpke, byte* info, word32 infoSz,
    byte* aad, word32 aadSz, byte* plaintext, word32 ptSz, byte* ciphertext,
    byte* pubKey, word32* pubKeySz);
WOLFSSL_API int wc_HpkeOpenBase(Hpke* hpke, const byte* pubKey, word32 pubKeySz,
    byte* info, word32 infoSz, byte* aad, word32 aadSz,
    byte* ciphertext, word32 ctSz, byte* plaintext);
WOLFSSL_API void wc_HpkeFree(Hpke* hpke);

#endif /* HAVE_HPKE && HAVE_ECC */

#ifdef __cplusplus
    }    /* extern "C" */
#endif
