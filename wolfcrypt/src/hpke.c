/* hpke.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(HAVE_HPKE) && defined(HAVE_ECC) && defined(HAVE_AESGCM)

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hpke.h>

static const char* KEM_STR = "KEM";
static const int KEM_STR_LEN = 3;

static const char* HPKE_STR = "HPKE";
static const int HPKE_STR_LEN = 4;

static const char* HPKE_VERSION_STR = "HPKE-v1";
static const int HPKE_VERSION_STR_LEN = 7;

static const char* EAE_PRK_LABEL_STR = "eae_prk";
static const int EAE_PRK_LABEL_STR_LEN = 7;

static const char* SHARED_SECRET_LABEL_STR = "sharedSecret";
static const int SHARED_SECRET_LABEL_STR_LEN = 13;

static const char* PSK_ID_HASH_LABEL_STR = "psk_id_hash";
static const int PSK_ID_HASH_LABEL_STR_LEN = 11;

static const char* INFO_HASH_LABEL_STR = "info_hash";
static const int INFO_HASH_LABEL_STR_LEN = 9;

static const char* SECRET_LABEL_STR = "secret";
static const int SECRET_LABEL_STR_LEN = 6;

static const char* KEY_LABEL_STR = "key";
static const int KEY_LABEL_STR_LEN = 3;

static const char* BASE_NONCE_LABEL_STR = "base_nonce";
static const int BASE_NONCE_LABEL_STR_LEN = 10;

static const char* EXP_LABEL_STR = "exp";
static const int EXP_LABEL_STR_LEN = 3;

static int I2OSP(int n, int w, byte* out)
{
    int i;

    if (w <= 0 || w > 32) {
        return MP_VAL;
    }

    /* make sure the byte string is cleared */
    XMEMSET( out, 0, w );

    /* we're only concerned with up to integer max */
    if ((n > 256 && w < 2) ||
        (n > 65536 && w < 3) ||
        (n > 16777216 && w < 4)) {
        return MP_VAL;
    }

    for (i = 0; i < w && n > 0; i++) {
        out[w - ( i + 1 )] = n % 256;
        n = n >> 8;
    }

    return 0;
}

int wc_HpkeInit(Hpke* hpke, int kem, int kdf, int aead, void* heap)
{
    int ret;

    if (hpke == NULL || kem == 0 || kdf == 0 || aead == 0) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(hpke, 0, sizeof(*hpke));
    hpke->kem = kem;
    hpke->kdf = kdf;
    hpke->aead = aead;
    hpke->heap = heap;

    XMEMCPY(hpke->kem_suite_id, KEM_STR, KEM_STR_LEN);

    ret = I2OSP(kem, 2, hpke->kem_suite_id + KEM_STR_LEN);

    XMEMCPY(hpke->hpke_suite_id, HPKE_STR, HPKE_STR_LEN);

    if (ret == 0) {
      ret = I2OSP(kem, 2, hpke->hpke_suite_id + HPKE_STR_LEN);
    }
    if (ret == 0) {
      ret = I2OSP(kdf, 2, hpke->hpke_suite_id + HPKE_STR_LEN + 2);
    }
    if (ret == 0) {
      ret = I2OSP(aead, 2, hpke->hpke_suite_id + HPKE_STR_LEN + 2 + 2);
    }
    if (ret != 0)
        return ret;

    switch (kem)
    {
        case DHKEM_P256_HKDF_SHA256:
            hpke->Nsecret = 32;
            hpke->Nh = 32;
            hpke->Ndh = 32;
            hpke->Npk = 65;
            hpke->curve_id = ECC_SECP256R1;
            break;

        case DHKEM_P384_HKDF_SHA384:
            hpke->Nsecret = 48;
            hpke->Nh = 48;
            hpke->Ndh = 48;
            hpke->Npk = 97;
            hpke->curve_id = ECC_SECP384R1;
            break;

        case DHKEM_P521_HKDF_SHA512:
            hpke->Nsecret = 64;
            hpke->Nh = 64;
            hpke->Ndh = 66;
            hpke->Npk = 133;
            hpke->curve_id = ECC_SECP521R1;
            break;

        /* TODO: Add X25519 and X448 */
        case DHKEM_X25519_HKDF_SHA256:
            hpke->Nsecret = 32;
            hpke->Nh = 32;
            hpke->Ndh = 32;
            hpke->Npk = 32;
            /* hpke->curve_id = ECC_X25519; */
            break;

        case DHKEM_X448_HKDF_SHA512:
            hpke->Nsecret = 64;
            hpke->Nh = 64;
            hpke->Ndh = 64;
            hpke->Npk = 56;
            /* hpke->curve_id = ECC_X448; */
            break;

        default:
            ret = BAD_FUNC_ARG;
            break;
    }

    switch (kdf)
    {
        case HKDF_SHA256:
            hpke->kdf_digest = WC_SHA256;
            break;

        case HKDF_SHA384:
            hpke->kdf_digest = WC_SHA384;
            break;

        case HKDF_SHA512:
            hpke->kdf_digest = WC_SHA512;
            break;

        default:
            ret = BAD_FUNC_ARG;
            break;
    }

    switch (aead)
    {
        case HPKE_AES_128_GCM:
            hpke->Nk = 16;
            hpke->Nn = 12;
            hpke->Nt = 16;
            break;

        case HPKE_AES_256_GCM:
            hpke->Nk = 32;
            hpke->Nn = 12;
            hpke->Nt = 16;
            break;

        default:
            ret = BAD_FUNC_ARG;
            break;
    }

    return 0;
}

int wc_HpkeSerializePublicKey(ecc_key* key, byte* out, word32* outSz)
{
    int ret;
    word32 qxLen;
    word32 qyLen;

    if (key == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }
    if (outSz != NULL && *outSz < (word32)key->dp->size * 2 + 1) {
        return BUFFER_E;
    }

    /* first byte indicates uncompressed public key */
    out[0] = 0x04;
    qxLen = qyLen = key->dp->size;

    ret = wc_ecc_export_public_raw(key,
        out + 1, &qxLen,
        out + 1 + qxLen, &qyLen);
    if (outSz) {
        *outSz = (word32)key->dp->size * 2 + 1;
    }

    return ret;
}

int wc_HpkeDeserializePublicKey(Hpke* hpke, ecc_key* key, const byte* in,
    word32 inSz)
{
    int ret;

    if (hpke == NULL || key == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }

    if (inSz < (word32)hpke->Npk) {
        return BUFFER_E;
    }

    /* import +1 to skip the leading x.963 byte */
    ret = wc_ecc_init(key);
    if (ret == 0) {
        ret = wc_ecc_import_unsigned(key,
            in + 1,
            in + 1 + (hpke->Npk / 2),
            NULL,
            hpke->curve_id);
    }

    return ret;
}

int wc_HpkeGenerateKeyPair(Hpke* hpke, ecc_key* keypair)
{
    int ret;
#ifdef WOLFSSL_SMALL_STACK
    WC_RNG* rng;
#else
    WC_RNG rng[1];
#endif

    if (hpke == NULL || keypair == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    /* allocate after we know hpke is good */
    rng = (WC_RNG*)XMALLOC(sizeof(WC_RNG), hpke->heap, DYNAMIC_TYPE_RNG);
    if (rng == NULL) {
        return MEMORY_E;
    }
#endif

    ret = wc_InitRng(rng);
    if (ret == 0) {
        ret = wc_ecc_init(keypair);
    }

    if (ret == 0) {
        hpke->receiver_key_set = 1;

        switch (hpke->kem)
        {
            case DHKEM_P256_HKDF_SHA256:
                ret = wc_ecc_make_key_ex(rng, 32, keypair, ECC_SECP256R1);
                break;
            case DHKEM_P384_HKDF_SHA384:
                ret = wc_ecc_make_key_ex(rng, 48, keypair, ECC_SECP384R1);
                break;
            case DHKEM_P521_HKDF_SHA512:
                ret = wc_ecc_make_key_ex(rng, 66, keypair, ECC_SECP521R1);
                break;
            case DHKEM_X25519_HKDF_SHA256:
                /* TODO: Add X25519 */
                break;
            case DHKEM_X448_HKDF_SHA512:
                /* TODO: Add X448 */
                break;
            default:
                ret = BAD_FUNC_ARG;
                break;
        }
    }

    wc_FreeRng(rng);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(rng, hpke->heap, DYNAMIC_TYPE_RNG);
#endif

    return ret;
}

static int wc_HpkeLabeledExtract(Hpke* hpke, byte* suite_id, word32 suite_id_len,
    byte* salt, word32 salt_len, byte* label, word32 label_len,
    byte* ikm, word32 ikm_len, byte* out)
{
    int ret;
    byte* labeled_ikm_p;
#ifndef WOLFSSL_SMALL_STACK
    byte labeled_ikm[MAX_HPKE_LABEL_SZ];
#else
    byte* labeled_ikm;
#endif

    if (hpke == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    labeled_ikm = (byte*)XMALLOC(MAX_HPKE_LABEL_SZ, hpke->heap,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (labeled_ikm == NULL) {
        return MEMORY_E;
    }
#endif

    /* concat the labeled_ikm */
    /* version */
    XMEMCPY(labeled_ikm, HPKE_VERSION_STR, HPKE_VERSION_STR_LEN);
    labeled_ikm_p = labeled_ikm + HPKE_VERSION_STR_LEN;

    /* suite_id */
    XMEMCPY(labeled_ikm_p, suite_id, suite_id_len);
    labeled_ikm_p += suite_id_len;

    /* label */
    XMEMCPY(labeled_ikm_p, label, label_len);
    labeled_ikm_p += label_len;

    /* ikm */
    XMEMCPY(labeled_ikm_p, ikm, ikm_len);
    labeled_ikm_p += ikm_len;

    /* call extract */
    ret = wc_HKDF_Extract(hpke->kdf_digest, salt, salt_len, labeled_ikm,
        (word32)(size_t)(labeled_ikm_p - labeled_ikm), out);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(labeled_ikm, hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

static int wc_HpkeLabeledExpand(Hpke* hpke, byte* suite_id, word32 suite_id_len,
    byte* prk, word32 prk_len, byte* label, word32 label_len, byte* info,
    word32 infoSz, word32 L, byte* out)
{
    int ret;
    byte* labeled_info_p;
#ifndef WOLFSSL_SMALL_STACK
    byte labeled_info[MAX_HPKE_LABEL_SZ];
#else
    byte* labeled_info;
#endif

    if (hpke == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    labeled_info = (byte*)XMALLOC(MAX_HPKE_LABEL_SZ, hpke->heap,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (labeled_info == NULL) {
        return MEMORY_E;
    }
#endif

    /* copy length */
    ret = I2OSP(L, 2, labeled_info);
    labeled_info_p = labeled_info + 2;

    if (ret == 0) {
        /* version */
        XMEMCPY(labeled_info_p, HPKE_VERSION_STR, HPKE_VERSION_STR_LEN);
        labeled_info_p += HPKE_VERSION_STR_LEN;

        /* suite_id */
        XMEMCPY(labeled_info_p, suite_id, suite_id_len);
        labeled_info_p += suite_id_len;

        /* label */
        XMEMCPY(labeled_info_p, label, label_len);
        labeled_info_p += label_len;

        /* info */
        XMEMCPY(labeled_info_p, info, infoSz);
        labeled_info_p += infoSz;

        /* call expand */
        ret = wc_HKDF_Expand(hpke->kdf_digest,
            prk, prk_len,
            labeled_info, (word32)(size_t)(labeled_info_p - labeled_info),
            out, L);
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(labeled_info, hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

static int wc_HpkeContextComputeNonce(Hpke* hpke, HpkeBaseContext* context, byte* out)
{
    int ret;
    byte seq_bytes[HPKE_Nn_MAX];

    /* convert the sequence into a byte string with the same length as the
     * nonce */
    ret = I2OSP(context->seq, hpke->Nn, seq_bytes);
    if (ret == 0) {
        int i;
        for (i = 0; i < hpke->Nn; i++) {
            out[i] = (context->base_nonce[i] ^ seq_bytes[i]);
        }
    }

    return ret;
}

static int wc_HpkeExtractAndExpand( Hpke* hpke, byte* dh, word32 dh_len,
    byte* kemContext, word32 kem_context_length, byte* sharedSecret)
{
    int ret;
    /* max length is the largest hmac digest possible */
#ifndef WOLFSSL_SMALL_STACK
    byte eae_prk[WC_MAX_DIGEST_SIZE];
#else
    byte* eae_prk;
#endif

    if (hpke == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    eae_prk = (byte*)XMALLOC(WC_MAX_DIGEST_SIZE, hpke->heap,
        DYNAMIC_TYPE_DIGEST);
    if (eae_prk == NULL) {
        return MEMORY_E;
    }
#endif

    /* extract */
    ret = wc_HpkeLabeledExtract(hpke, hpke->kem_suite_id,
        sizeof( hpke->kem_suite_id ), NULL, 0, (byte*)EAE_PRK_LABEL_STR,
        EAE_PRK_LABEL_STR_LEN, dh, dh_len, eae_prk);

    /* expand */
    if ( ret == 0 )
        ret = wc_HpkeLabeledExpand(hpke, hpke->kem_suite_id,
            sizeof( hpke->kem_suite_id ), eae_prk, hpke->Nh,
            (byte*)SHARED_SECRET_LABEL_STR, SHARED_SECRET_LABEL_STR_LEN,
            kemContext, kem_context_length, hpke->Nsecret, sharedSecret);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(eae_prk, hpke->heap, DYNAMIC_TYPE_DIGEST);
#endif

    return ret;
}

static int wc_HpkeKeyScheduleBase(Hpke* hpke, HpkeBaseContext* context,
    byte* sharedSecret, byte* info, word32 infoSz)
{
    int ret;
#ifndef WOLFSSL_SMALL_STACK
    /* 1 for mode and WC_MAX_DIGEST_SIZE times 2 for psk_id_hash and info_hash */
    byte key_schedule_context[1 + 2 * WC_MAX_DIGEST_SIZE];
    /* maximum size of secret is largest hash of extract */
    byte secret[WC_MAX_DIGEST_SIZE];
#else
    byte* key_schedule_context = NULL;
    byte* secret = NULL;
#endif

    if (hpke == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    key_schedule_context = (byte*)XMALLOC((1 + 2 * WC_MAX_DIGEST_SIZE),
        hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
    secret = (byte*)XMALLOC(WC_MAX_DIGEST_SIZE, hpke->heap,
        DYNAMIC_TYPE_DIGEST);
    if (key_schedule_context == NULL || secret == NULL) {
        XFREE(key_schedule_context, hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(secret, hpke->heap, DYNAMIC_TYPE_DIGEST);
        return MEMORY_E;
    }
#endif

    /* set the sequence to 0 */
    context->seq = 0;

    /* 0 for mode */
    key_schedule_context[0] = 0;

    /* extract psk_id, which for base is null */
    ret = wc_HpkeLabeledExtract(hpke, hpke->hpke_suite_id,
        sizeof( hpke->hpke_suite_id ), NULL, 0, (byte*)PSK_ID_HASH_LABEL_STR,
        PSK_ID_HASH_LABEL_STR_LEN, NULL, 0, key_schedule_context + 1);

    /* extract info */
    if (ret == 0) {
        ret = wc_HpkeLabeledExtract(hpke, hpke->hpke_suite_id,
            sizeof( hpke->hpke_suite_id ), NULL, 0, (byte*)INFO_HASH_LABEL_STR,
            INFO_HASH_LABEL_STR_LEN, info, infoSz,
            key_schedule_context + 1 + hpke->Nh);
    }

    /* extract secret */
    if (ret == 0) {
        ret = wc_HpkeLabeledExtract(hpke, hpke->hpke_suite_id,
            sizeof( hpke->hpke_suite_id ), sharedSecret, hpke->Nsecret,
            (byte*)SECRET_LABEL_STR, SECRET_LABEL_STR_LEN, NULL, 0, secret);
    }

    /* expand key */
    if (ret == 0)
        ret = wc_HpkeLabeledExpand(hpke, hpke->hpke_suite_id,
            sizeof( hpke->hpke_suite_id ), secret, hpke->Nh,
            (byte*)KEY_LABEL_STR, KEY_LABEL_STR_LEN, key_schedule_context,
            1 + 2 * hpke->Nh, hpke->Nk, context->key);

    /* expand nonce */
    if (ret == 0) {
        ret = wc_HpkeLabeledExpand(hpke, hpke->hpke_suite_id,
            sizeof( hpke->hpke_suite_id ), secret, hpke->Nh,
            (byte*)BASE_NONCE_LABEL_STR, BASE_NONCE_LABEL_STR_LEN,
            key_schedule_context, 1 + 2 * hpke->Nh, hpke->Nn,
            context->base_nonce);
    }

    /* expand exporter_secret */
    if (ret == 0) {
        ret = wc_HpkeLabeledExpand(hpke, hpke->hpke_suite_id,
            sizeof( hpke->hpke_suite_id ), secret, hpke->Nh,
            (byte*)EXP_LABEL_STR, EXP_LABEL_STR_LEN, key_schedule_context,
            1 + 2 * hpke->Nh, hpke->Nh, context->exporter_secret);
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(key_schedule_context, hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(secret, hpke->heap, DYNAMIC_TYPE_DIGEST);
#endif

    return ret;
}

static int wc_HpkeEncap(Hpke* hpke, byte* sharedSecret, byte* pubKey, word32* pubKeySz)
{
    int ret;
    word32 dh_len;
#ifndef WOLFSSL_SMALL_STACK
    ecc_key ephemeralKey[1];
    byte dh[HPKE_Ndh_MAX];
    byte kemContext[HPKE_Npk_MAX * 2];
#else
    ecc_key* ephemeralKey = NULL;
    byte* dh = NULL;
    byte* kemContext = NULL;
#endif

    if (hpke == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    ephemeralKey = (ecc_key*)XMALLOC(sizeof(ecc_key), hpke->heap,
        DYNAMIC_TYPE_ECC);
    dh = (byte*)XMALLOC(hpke->Ndh, hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
    kemContext = (byte*)XMALLOC(hpke->Npk * 2, hpke->heap,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (ephemeralKey == NULL || dh == NULL || kemContext == NULL) {
        XFREE(ephemeralKey, hpke->heap, DYNAMIC_TYPE_ECC);
        XFREE(dh, hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(kemContext, hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
#endif

    /* generate keypair */
    ret = wc_HpkeGenerateKeyPair(hpke, ephemeralKey);
    if (ret == 0) {
        /* generate dh */
        ephemeralKey->rng = wc_rng_new(NULL, 0, hpke->heap);
        dh_len = hpke->Ndh;
        ret = wc_ecc_shared_secret(ephemeralKey, hpke->receiver_key,
            dh, &dh_len);
        wc_rng_free(ephemeralKey->rng);

        /* serialize ephemeralKey */
        if (ret == 0) {
            ret = wc_HpkeSerializePublicKey(ephemeralKey, pubKey, pubKeySz);
        }

        /* free ephemeralKey */
        wc_ecc_free(ephemeralKey);
    }

    if (ret == 0) {
        /* copy pubKey into kemContext */
        XMEMCPY(kemContext, pubKey, hpke->Npk);

        /* serialize pkR into kemContext */
        ret = wc_HpkeSerializePublicKey(hpke->receiver_key,
            kemContext + hpke->Npk, NULL);
    }

    /* compute the shared secret */
    if (ret == 0) {
        ret = wc_HpkeExtractAndExpand(hpke, dh, dh_len, kemContext,
            hpke->Npk * 2, sharedSecret);
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(ephemeralKey, hpke->heap, DYNAMIC_TYPE_ECC);
    XFREE(dh, hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(kemContext, hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

static int wc_HpkeSetupBaseSender(Hpke* hpke, HpkeBaseContext* context,
    byte* info, word32 infoSz, byte* pubKey, word32* pubKeySz)
{
    int ret;
#ifndef WOLFSSL_SMALL_STACK
    byte sharedSecret[HPKE_Nsecret_MAX];
#else
    byte* sharedSecret;
#endif

    if (hpke == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    sharedSecret = (byte*)XMALLOC(hpke->Nsecret, hpke->heap,
        DYNAMIC_TYPE_TMP_BUFFER);
#endif

    /* encap */
    ret = wc_HpkeEncap(hpke, sharedSecret, pubKey, pubKeySz);

    /* schedule */
    if (ret == 0) {
        ret = wc_HpkeKeyScheduleBase(hpke, context, sharedSecret, info,
            infoSz);
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(sharedSecret, hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

static int wc_HpkeContextSealBase(Hpke* hpke, HpkeBaseContext* context,
    byte* aad, word32 aadSz, byte* plaintext, word32 ptSz, byte* out)
{
    int ret;
    byte nonce[HPKE_Nn_MAX];
#ifndef WOLFSSL_SMALL_STACK
    Aes aes_key[1];
#else
    Aes* aes_key;
#endif

    if (hpke == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    aes_key = (Aes*)XMALLOC(sizeof(Aes), hpke->heap, DYNAMIC_TYPE_AES);
    if (aes_key == NULL) {
        return MEMORY_E;
    }
#endif

    ret = wc_HpkeContextComputeNonce(hpke, context, nonce);

    /* TODO: Support additional algorithms (like ChaCha20) */
    if (ret == 0) {
        ret = wc_AesGcmSetKey(aes_key, context->key, hpke->Nk);
    }
    if (ret == 0) {
        ret = wc_AesGcmEncrypt(aes_key, out, plaintext, ptSz, nonce, hpke->Nn,
            out + ptSz, hpke->Nt, aad, aadSz);
    }
    if (ret == 0) {
        context->seq++;
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(aes_key, hpke->heap, DYNAMIC_TYPE_AES);
#endif

    return ret;
}

int wc_HpkeSealBase(Hpke* hpke, byte* info, word32 infoSz, byte* aad,
    word32 aadSz, byte* plaintext, word32 ptSz, byte* ciphertext, byte* pubKey,
    word32* pubKeySz)
{
    int ret;
#ifdef WOLFSSL_SMALL_STACK
    HpkeBaseContext* context;
#else
    HpkeBaseContext context[1];
#endif

    /* check that all the buffers are non NULL or optional with 0 length */
    if (hpke == NULL || hpke->receiver_key_set == 0 ||
        (info == NULL && infoSz != 0) || (aad == NULL && aadSz != 0) ||
        plaintext == NULL || ciphertext == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    context = (HpkeBaseContext*)XMALLOC(sizeof(HpkeBaseContext), hpke->heap,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (context == NULL) {
        return MEMORY_E;
    }
#endif

    /* setup the context and pubKey */
    ret = wc_HpkeSetupBaseSender(hpke, context, info, infoSz, pubKey, pubKeySz);

    /* run seal using the context */
    if (ret == 0) {
        ret = wc_HpkeContextSealBase(hpke, context, aad, aadSz, plaintext,
            ptSz, ciphertext);
        }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(context, hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

static int wc_HpkeDecap(Hpke* hpke, const byte* pubKey, word32 pubKeySz,
    byte* sharedSecret)
{
    int ret;
    word32 dh_len;
#ifndef WOLFSSL_SMALL_STACK
    ecc_key ephemeralKey[1];
    byte dh[HPKE_Ndh_MAX];
    byte kemContext[HPKE_Npk_MAX * 2];
#else
    ecc_key* ephemeralKey = NULL;
    byte* dh = NULL;
    byte* kemContext = NULL;
#endif

    if (hpke == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    ephemeralKey = (ecc_key*)XMALLOC(sizeof(ecc_key), hpke->heap,
        DYNAMIC_TYPE_ECC);
    dh = (byte*)XMALLOC(hpke->Ndh, hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
    kemContext = (byte*)XMALLOC(hpke->Npk * 2, hpke->heap,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (ephemeralKey == NULL || dh == NULL || kemContext == NULL) {
        XFREE(ephemeralKey, hpke->heap, DYNAMIC_TYPE_ECC);
        XFREE(dh, hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(kemContext, hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
#endif

    /* deserialize ephemeralKey from pubKey */
    ret = wc_HpkeDeserializePublicKey(hpke, ephemeralKey, pubKey, pubKeySz);
    if (ret == 0) {
        /* generate dh */
        hpke->receiver_key->rng = wc_rng_new(NULL, 0, hpke->heap);
        dh_len = hpke->Ndh;
        ret = wc_ecc_shared_secret(hpke->receiver_key, ephemeralKey,
            dh, &dh_len);
        wc_rng_free(hpke->receiver_key->rng);

        wc_ecc_free(ephemeralKey);
    }

    if (ret == 0) {
        /* copy pubKey into kemContext */
        XMEMCPY(kemContext, pubKey, hpke->Npk);

        /* serialize pkR into kemContext */
        ret = wc_HpkeSerializePublicKey(hpke->receiver_key,
            kemContext + hpke->Npk, NULL);
    }

    /* compute the shared secret */
    if (ret == 0) {
        ret = wc_HpkeExtractAndExpand(hpke, dh, dh_len, kemContext,
            hpke->Npk * 2, sharedSecret);
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(ephemeralKey, hpke->heap, DYNAMIC_TYPE_ECC);
    XFREE(dh, hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(kemContext, hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

static int wc_HpkeSetupBaseReceiver(Hpke* hpke, HpkeBaseContext* context,
    const byte* pubKey, word32 pubKeySz, byte* info, word32 infoSz)
{
    int ret;
#ifndef WOLFSSL_SMALL_STACK
    byte sharedSecret[HPKE_Nsecret_MAX];
#else
    byte* sharedSecret;
#endif

#ifdef WOLFSSL_SMALL_STACK
    sharedSecret = (byte*)XMALLOC(hpke->Nsecret, hpke->heap,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (sharedSecret == NULL) {
        return MEMORY_E;
    }
#endif

    /* decap */
    ret = wc_HpkeDecap(hpke, pubKey, pubKeySz, sharedSecret);

    /* schedule */
    if (ret == 0) {
        ret = wc_HpkeKeyScheduleBase(hpke, context, sharedSecret, info,
            infoSz);
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(sharedSecret, hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

static int wc_HpkeContextOpenBase(Hpke* hpke, HpkeBaseContext* context,
    byte* aad, word32 aadSz, byte* ciphertext, word32 ctSz, byte* out)
{
    int ret;
    byte nonce[HPKE_Nn_MAX];
#ifndef WOLFSSL_SMALL_STACK
    Aes aes_key[1];
#else
    Aes* aes_key;
#endif

    if (hpke == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    aes_key = (Aes*)XMALLOC(sizeof(Aes), hpke->heap, DYNAMIC_TYPE_AES);
    if (aes_key == NULL) {
        return MEMORY_E;
    }
#endif

    ret = wc_HpkeContextComputeNonce(hpke, context, nonce);

    /* TODO: Support additional algorithms (like ChaCha20) */
    if (ret == 0) {
        ret = wc_AesGcmSetKey(aes_key, context->key, hpke->Nk);
    }
    if (ret == 0) {
        ret = wc_AesGcmDecrypt(aes_key, out, ciphertext, ctSz, nonce,
            hpke->Nn, ciphertext + ctSz, hpke->Nt, aad, aadSz);
    }
    if (ret == 0) {
        context->seq++;
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(aes_key, hpke->heap, DYNAMIC_TYPE_AES);
#endif

    return ret;
}

int wc_HpkeOpenBase(Hpke* hpke, const byte* pubKey, word32 pubKeySz,
    byte* info, word32 infoSz, byte* aad, word32 aadSz, byte* ciphertext,
    word32 ctSz, byte* plaintext)
{
    int ret;
#ifndef WOLFSSL_SMALL_STACK
    HpkeBaseContext context[1];
#else
    HpkeBaseContext* context;
#endif

    /* check that all the buffer are non NULL or optional with 0 length */
    if (hpke == NULL || pubKey == NULL || pubKeySz == 0 ||
        (info == NULL && infoSz != 0) || (aad == NULL && aadSz != 0) ||
        plaintext == NULL || ciphertext == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    context = (HpkeBaseContext*)XMALLOC(sizeof(HpkeBaseContext), hpke->heap,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (context == NULL) {
        return MEMORY_E;
    }
#endif

    /* setup receiver */
    ret = wc_HpkeSetupBaseReceiver(hpke, context, pubKey, pubKeySz, info, infoSz);
    if (ret == 0) {
        /* open the ciphertext */
        ret = wc_HpkeContextOpenBase(hpke, context, aad, aadSz, ciphertext,
            ctSz, plaintext);
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(context, hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

void wc_HpkeFree(Hpke* hpke)
{
    if (hpke && hpke->receiver_key_set) {
        wc_ecc_free(hpke->receiver_key);
        hpke->receiver_key_set = 0;
    }
}

#endif /* HAVE_HPKE && HAVE_ECC && HAVE_AESGCM */
