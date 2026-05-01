/* falcon.c
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

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

/* Based on ed448.c and Reworked for Falcon by Anthony Hu. */

#if defined(HAVE_FALCON)

#include <wolfssl/wolfcrypt/asn.h>

/* HAVE_FALCON implies HAVE_LIBOQS (enforced in settings.h and falcon.h). */
#include <oqs/oqs.h>

#include <wolfssl/wolfcrypt/falcon.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* Sign the message using the falcon private key.
 *
 *  in          [in]      Message to sign.
 *  inLen       [in]      Length of the message in bytes.
 *  out         [in]      Buffer to write signature into.
 *  outLen      [in/out]  On in, size of buffer.
 *                        On out, the length of the signature in bytes.
 *  key         [in]      Falcon key to use when signing
 *  returns BAD_FUNC_ARG when a parameter is NULL or public key not set,
 *          BUFFER_E when outLen is less than FALCON_LEVEL1_SIG_SIZE,
 *          0 otherwise.
 */
int wc_falcon_sign_msg(const byte* in, word32 inLen,
                              byte* out, word32 *outLen,
                              falcon_key* key, WC_RNG* rng)
{
    int ret = 0;
#ifdef HAVE_LIBOQS
    OQS_SIG *oqssig = NULL;
    size_t localOutLen = 0;
#endif

    /* sanity check on arguments */
    if ((in == NULL) || (out == NULL) || (outLen == NULL) || (key == NULL)) {
        return  BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    #ifndef WOLF_CRYPTO_CB_FIND
    if (key->devId != INVALID_DEVID)
    #endif
    {
        ret = wc_CryptoCb_PqcSign(in, inLen, out, outLen, NULL, 0,
                WC_HASH_TYPE_NONE, rng, WC_PQC_SIG_TYPE_FALCON, key);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return ret;
        /* fall-through when unavailable */
        ret = 0;
    }
#endif

#ifdef HAVE_LIBOQS
    if ((ret == 0) && (!key->prvKeySet)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        if (key->level == 1) {
            oqssig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
        }
        else if (key->level == 5) {
            oqssig = OQS_SIG_new(OQS_SIG_alg_falcon_1024);
        }

        if (oqssig == NULL) {
            ret = SIG_TYPE_E;
        }
    }

    /* check and set up out length */
    if (ret == 0) {
        if ((key->level == 1) && (*outLen < FALCON_LEVEL1_SIG_SIZE)) {
            *outLen = FALCON_LEVEL1_SIG_SIZE;
            ret = BUFFER_E;
        }
        else if ((key->level == 5) && (*outLen < FALCON_LEVEL5_SIG_SIZE)) {
            *outLen = FALCON_LEVEL5_SIG_SIZE;
            ret = BUFFER_E;
        }
        localOutLen = *outLen;
    }

    if (ret == 0) {
        ret = wolfSSL_liboqsRngMutexLock(rng);
        if (ret == 0) {
            if (OQS_SIG_sign(oqssig, out, &localOutLen, in, inLen, key->k)
                == OQS_ERROR) {
                ret = BAD_FUNC_ARG;
            }
        }
        if (ret == 0) {
            *outLen = (word32)localOutLen;
        }
        wolfSSL_liboqsRngMutexUnlock();
    }

    if (oqssig != NULL) {
        OQS_SIG_free(oqssig);
    }
#else
    ret = NOT_COMPILED_IN;
#endif
    return ret;
}

/* Verify the message using the falcon public key.
 *
 *  sig         [in]  Signature to verify.
 *  sigLen      [in]  Size of signature in bytes.
 *  msg         [in]  Message to verify.
 *  msgLen      [in]  Length of the message in bytes.
 *  res         [out] *res is set to 1 on successful verification.
 *  key         [in]  Falcon key to use to verify.
 *  returns BAD_FUNC_ARG when a parameter is NULL or contextLen is zero when and
 *          BUFFER_E when sigLen is less than FALCON_LEVEL1_SIG_SIZE,
 *          0 otherwise.
 */
int wc_falcon_verify_msg(const byte* sig, word32 sigLen, const byte* msg,
                        word32 msgLen, int* res, falcon_key* key)
{
    int ret = 0;
#ifdef HAVE_LIBOQS
    OQS_SIG *oqssig = NULL;
#endif

    if (key == NULL || sig == NULL || msg == NULL || res == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    #ifndef WOLF_CRYPTO_CB_FIND
    if (key->devId != INVALID_DEVID)
    #endif
    {
        ret = wc_CryptoCb_PqcVerify(sig, sigLen, msg, msgLen, NULL, 0,
                WC_HASH_TYPE_NONE, res, WC_PQC_SIG_TYPE_FALCON, key);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return ret;
        /* fall-through when unavailable */
        ret = 0;
    }
#endif

#ifdef HAVE_LIBOQS
    if ((ret == 0) && (!key->pubKeySet)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        if (key->level == 1) {
            oqssig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
        }
        else if (key->level == 5) {
            oqssig = OQS_SIG_new(OQS_SIG_alg_falcon_1024);
        }

        if (oqssig == NULL) {
            ret = SIG_TYPE_E;
        }
    }

    if ((ret == 0) &&
        (OQS_SIG_verify(oqssig, msg, msgLen, sig, sigLen, key->p)
         == OQS_ERROR)) {
         ret = SIG_VERIFY_E;
    }

    if (ret == 0) {
        *res = 1;
    }

    if (oqssig != NULL) {
        OQS_SIG_free(oqssig);
    }
#else
    ret = NOT_COMPILED_IN;
#endif

    return ret;
}

/* Initialize the falcon private/public key.
 *
 * key  [in]  Falcon key.
 * returns BAD_FUNC_ARG when key is NULL
 */
int wc_falcon_init(falcon_key* key)
{
    return wc_falcon_init_ex(key, NULL, INVALID_DEVID);
}

/* Initialize the falcon private/public key.
 *
 * key  [in]  Falcon key.
 * heap [in]  Heap hint.
 * devId[in]  Device ID.
 * returns BAD_FUNC_ARG when key is NULL
 */
int wc_falcon_init_ex(falcon_key* key, void* heap, int devId)
{
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    ForceZero(key, sizeof(*key));

#ifdef WOLF_CRYPTO_CB
    key->devCtx = NULL;
    key->devId = devId;
#endif
#ifdef WOLF_PRIVATE_KEY_ID
    key->idLen = 0;
    key->labelLen = 0;
#endif

    (void) heap;
    (void) devId;

    return 0;
}

#ifdef WOLF_PRIVATE_KEY_ID
int wc_falcon_init_id(falcon_key* key, const unsigned char* id, int len,
                         void* heap, int devId)
{
    int ret = 0;

    if (key == NULL)
        ret = BAD_FUNC_ARG;
    if (ret == 0 && (len < 0 || len > FALCON_MAX_ID_LEN))
        ret = BUFFER_E;

    if (ret == 0)
        ret = wc_falcon_init_ex(key, heap, devId);
    if (ret == 0 && id != NULL && len != 0) {
        XMEMCPY(key->id, id, (size_t)len);
        key->idLen = len;
    }

    /* Set the maximum level here */
    wc_falcon_set_level(key, 5);

    return ret;
}

int wc_falcon_init_label(falcon_key* key, const char* label, void* heap,
                            int devId)
{
    int ret = 0;
    int labelLen = 0;

    if (key == NULL || label == NULL)
        ret = BAD_FUNC_ARG;
    if (ret == 0) {
        labelLen = (int)XSTRLEN(label);
        if (labelLen == 0 || labelLen > FALCON_MAX_LABEL_LEN)
            ret = BUFFER_E;
    }

    if (ret == 0)
        ret = wc_falcon_init_ex(key, heap, devId);
    if (ret == 0) {
        XMEMCPY(key->label, label, (size_t)labelLen);
        key->labelLen = labelLen;
    }

    /* Set the maximum level here */
    wc_falcon_set_level(key, 5);

    return ret;
}
#endif

/* Set the level of the falcon private/public key.
 *
 * key   [out]  Falcon key.
 * level [in]   Either 1 or 5.
 * returns BAD_FUNC_ARG when key is NULL or level is not 1 and not 5.
 */
int wc_falcon_set_level(falcon_key* key, byte level)
{
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    if (level != 1 && level != 5) {
        return BAD_FUNC_ARG;
    }

    key->level = level;
    key->pubKeySet = 0;
    key->prvKeySet = 0;
    return 0;
}

/* Get the level of the falcon private/public key.
 *
 * key   [in]  Falcon key.
 * level [out] The level.
 * returns BAD_FUNC_ARG when key is NULL or level has not been set.
 */
int wc_falcon_get_level(falcon_key* key, byte* level)
{
    if (key == NULL || level == NULL) {
        return BAD_FUNC_ARG;
    }

    if (key->level != 1 && key->level != 5) {
        return BAD_FUNC_ARG;
    }

    *level = key->level;
    return 0;
}

/* Clears the falcon key data
 *
 * key  [in]  Falcon key.
 */
void wc_falcon_free(falcon_key* key)
{
    if (key != NULL) {
        ForceZero(key, sizeof(*key));
    }
}

/* Export the falcon public key.
 *
 * key     [in]      Falcon public key.
 * out     [in]      Array to hold public key.
 * outLen  [in/out]  On in, the number of bytes in array.
 *                   On out, the number bytes put into array.
 * returns BAD_FUNC_ARG when a parameter is NULL,
 *         BUFFER_E when outLen is less than FALCON_LEVEL1_PUB_KEY_SIZE,
 *         0 otherwise.
 */
int wc_falcon_export_public(falcon_key* key,
                            byte* out, word32* outLen)
{
    /* sanity check on arguments */
    if ((key == NULL) || (out == NULL) || (outLen == NULL)) {
        return BAD_FUNC_ARG;
    }

    if ((key->level != 1) && (key->level != 5)) {
        return BAD_FUNC_ARG;
    }

    if (!key->pubKeySet) {
        return BAD_FUNC_ARG;
    }

    /* check and set up out length */
    if ((key->level == 1) && (*outLen < FALCON_LEVEL1_PUB_KEY_SIZE)) {
        *outLen = FALCON_LEVEL1_PUB_KEY_SIZE;
        return BUFFER_E;
    }
    else if ((key->level == 5) && (*outLen < FALCON_LEVEL5_PUB_KEY_SIZE)) {
        *outLen = FALCON_LEVEL5_PUB_KEY_SIZE;
        return BUFFER_E;
    }

    if (key->level == 1) {
        *outLen = FALCON_LEVEL1_PUB_KEY_SIZE;
        XMEMCPY(out, key->p, FALCON_LEVEL1_PUB_KEY_SIZE);
    }
    else if (key->level == 5) {
        *outLen = FALCON_LEVEL5_PUB_KEY_SIZE;
        XMEMCPY(out, key->p, FALCON_LEVEL5_PUB_KEY_SIZE);
    }

    return 0;
}

/* Import a falcon public key from a byte array.
 * Public key encoded in big-endian.
 *
 * in      [in]  Array holding public key.
 * inLen   [in]  Number of bytes of data in array.
 * key     [in]  Falcon public key.
 * returns BAD_FUNC_ARG when a parameter is NULL or key format is not supported,
 *         0 otherwise.
 */
int wc_falcon_import_public(const byte* in, word32 inLen,
                                   falcon_key* key)
{
    /* sanity check on arguments */
    if ((in == NULL) || (key == NULL)) {
        return BAD_FUNC_ARG;
    }

    if ((key->level != 1) && (key->level != 5)) {
        return BAD_FUNC_ARG;
    }

    if ((key->level == 1) && (inLen != FALCON_LEVEL1_PUB_KEY_SIZE)) {
        return BAD_FUNC_ARG;
    }
    else if ((key->level == 5) && (inLen != FALCON_LEVEL5_PUB_KEY_SIZE)) {
        return BAD_FUNC_ARG;
    }

    XMEMCPY(key->p, in, inLen);
    key->pubKeySet = 1;

    return 0;
}

/* Import a raw Falcon private key.
 *
 * Accepts either the raw secret key (FALCON_LEVELx_KEY_SIZE) or the legacy
 * concat(priv, pub) layout (FALCON_LEVELx_PRV_KEY_SIZE) produced by older
 * wolfSSL releases. In the concat case, the trailing public-key bytes are
 * imported as well so verify works on round-tripped keys.
 *
 * priv    [in]  Raw private-key bytes.
 * privSz  [in]  Length of priv in bytes.
 * key     [in]  Falcon key. key->level must already be set.
 * returns BAD_FUNC_ARG when a parameter is NULL or privSz doesn't match
 *         either accepted size, 0 otherwise.
 *
 * This is the raw-bytes import. To decode a DER/PKCS8 Falcon private key,
 * use wc_Falcon_PrivateKeyDecode instead.
 */
int wc_falcon_import_private_only(const byte* priv, word32 privSz,
                                 falcon_key* key)
{
    word32 keySz;
    word32 concatSz;

    if ((priv == NULL) || (key == NULL)) {
        return BAD_FUNC_ARG;
    }

    if (key->level == 1) {
        keySz = FALCON_LEVEL1_KEY_SIZE;
        concatSz = FALCON_LEVEL1_PRV_KEY_SIZE;
    }
    else if (key->level == 5) {
        keySz = FALCON_LEVEL5_KEY_SIZE;
        concatSz = FALCON_LEVEL5_PRV_KEY_SIZE;
    }
    else {
        return BAD_FUNC_ARG;
    }

    if ((privSz != keySz) && (privSz != concatSz)) {
        return BAD_FUNC_ARG;
    }

    XMEMCPY(key->k, priv, keySz);
    key->prvKeySet = 1;

    /* Legacy concat layout carries the public key after the private key. */
    if (privSz == concatSz) {
        XMEMCPY(key->p, priv + keySz, concatSz - keySz);
        key->pubKeySet = 1;
    }

    return 0;
}

/* Import a raw Falcon private (and optionally public) key.
 *
 * If pub is NULL (and pubSz is 0), only the private key is imported. The
 * private buffer may be in the legacy concat(priv,pub) layout, in which case
 * the public part is recovered from it.
 *
 * priv    [in]  Raw private-key bytes (FALCON_LEVELx_KEY_SIZE or the legacy
 *               FALCON_LEVELx_PRV_KEY_SIZE concat layout).
 * privSz  [in]  Length of priv in bytes.
 * pub     [in]  Raw public-key bytes (FALCON_LEVELx_PUB_KEY_SIZE), or NULL.
 * pubSz   [in]  Length of pub in bytes (0 if pub is NULL).
 * key     [in]  Falcon key. key->level must already be set.
 * returns BAD_FUNC_ARG when a required parameter is NULL or a length doesn't
 *         match an expected size, 0 otherwise.
 *
 * This is the raw-bytes import. To decode a DER/PKCS8 Falcon private key,
 * use wc_Falcon_PrivateKeyDecode instead.
 */
int wc_falcon_import_private_key(const byte* priv, word32 privSz,
                                        const byte* pub, word32 pubSz,
                                        falcon_key* key)
{
    int ret;

    if ((priv == NULL) || (key == NULL)) {
        return BAD_FUNC_ARG;
    }
    if ((pub == NULL) && (pubSz != 0)) {
        return BAD_FUNC_ARG;
    }

    ret = wc_falcon_import_private_only(priv, privSz, key);
    if ((ret == 0) && (pub != NULL)) {
        ret = wc_falcon_import_public(pub, pubSz, key);
    }
    return ret;
}

/* Export the falcon private key.
 *
 * key     [in]      Falcon private key.
 * out     [in]      Array to hold private key.
 * outLen  [in/out]  On in, the number of bytes in array.
 *                   On out, the number bytes put into array.
 * returns BAD_FUNC_ARG when a parameter is NULL,
 *         BUFFER_E when outLen is less than FALCON_LEVEL1_KEY_SIZE,
 *         0 otherwise.
 */
int wc_falcon_export_private_only(falcon_key* key, byte* out, word32* outLen)
{
    /* sanity checks on arguments */
    if ((key == NULL) || (out == NULL) || (outLen == NULL)) {
        return BAD_FUNC_ARG;
    }

    if ((key->level != 1) && (key->level != 5)) {
        return BAD_FUNC_ARG;
    }

    /* check and set up out length */
    if ((key->level == 1) && (*outLen < FALCON_LEVEL1_KEY_SIZE)) {
        *outLen = FALCON_LEVEL1_KEY_SIZE;
        return BUFFER_E;
    }
    else if ((key->level == 5) && (*outLen < FALCON_LEVEL5_KEY_SIZE)) {
        *outLen = FALCON_LEVEL5_KEY_SIZE;
        return BUFFER_E;
    }

    if (key->level == 1) {
        *outLen = FALCON_LEVEL1_KEY_SIZE;
    }
    else if (key->level == 5) {
        *outLen = FALCON_LEVEL5_KEY_SIZE;
    }

    XMEMCPY(out, key->k, *outLen);

    return 0;
}

/* Export the falcon private and public key.
 *
 * key     [in]      Falcon private/public key.
 * out     [in]      Array to hold private and public key.
 * outLen  [in/out]  On in, the number of bytes in array.
 *                   On out, the number bytes put into array.
 * returns BAD_FUNC_ARG when a parameter is NULL,
 *         BUFFER_E when outLen is less than FALCON_LEVEL1_PRV_KEY_SIZE,
 *         0 otherwise.
 */
int wc_falcon_export_private(falcon_key* key, byte* out, word32* outLen)
{
    /* sanity checks on arguments */
    if ((key == NULL) || (out == NULL) || (outLen == NULL)) {
        return BAD_FUNC_ARG;
    }

    if ((key->level != 1) && (key->level != 5)) {
        return BAD_FUNC_ARG;
    }

    if ((key->level == 1) && (*outLen < FALCON_LEVEL1_PRV_KEY_SIZE)) {
        *outLen = FALCON_LEVEL1_PRV_KEY_SIZE;
        return BUFFER_E;
    }
    else if ((key->level == 5) && (*outLen < FALCON_LEVEL5_PRV_KEY_SIZE)) {
        *outLen = FALCON_LEVEL5_PRV_KEY_SIZE;
        return BUFFER_E;
    }


    if (key->level == 1) {
        *outLen = FALCON_LEVEL1_PRV_KEY_SIZE;
        XMEMCPY(out, key->k, FALCON_LEVEL1_KEY_SIZE);
        XMEMCPY(out + FALCON_LEVEL1_KEY_SIZE, key->p,
                FALCON_LEVEL1_PUB_KEY_SIZE);
    }
    else if (key->level == 5) {
        *outLen = FALCON_LEVEL5_PRV_KEY_SIZE;
        XMEMCPY(out, key->k, FALCON_LEVEL5_KEY_SIZE);
        XMEMCPY(out + FALCON_LEVEL5_KEY_SIZE, key->p,
                FALCON_LEVEL5_PUB_KEY_SIZE);
    }

    return 0;
}

/* Export the falcon private and public key.
 *
 * key     [in]      Falcon private/public key.
 * priv    [in]      Array to hold private key.
 * privSz  [in/out]  On in, the number of bytes in private key array.
 * pub     [in]      Array to hold  public key.
 * pubSz   [in/out]  On in, the number of bytes in public key array.
 *                   On out, the number bytes put into array.
 * returns BAD_FUNC_ARG when a parameter is NULL,
 *         BUFFER_E when privSz is less than FALCON_LEVEL1_PRV_KEY_SIZE or pubSz is less
 *         than FALCON_LEVEL1_PUB_KEY_SIZE,
 *         0 otherwise.
 */
int wc_falcon_export_key(falcon_key* key, byte* priv, word32 *privSz,
                        byte* pub, word32 *pubSz)
{
    int ret = 0;

    /* export private part */
    ret = wc_falcon_export_private(key, priv, privSz);
    if (ret == 0) {
        /* export public part */
        ret = wc_falcon_export_public(key, pub, pubSz);
    }

    return ret;
}

/* Check the public key of the falcon key matches the private key.
 *
 * key     [in]      Falcon private/public key.
 * returns BAD_FUNC_ARG when key is NULL,
 *         PUBLIC_KEY_E when the public key is not set or doesn't match,
 *         other -ve value on hash failure,
 *         0 otherwise.
 */
int wc_falcon_check_key(falcon_key* key)
{
    int ret = 0;

    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    /* The public key is also decoded and stored within the private key buffer
     * behind the private key. Hence, we can compare both stored public keys. */
    if (key->level == 1) {
        ret = XMEMCMP(key->p, key->k + FALCON_LEVEL1_KEY_SIZE,
                      FALCON_LEVEL1_PUB_KEY_SIZE);
    }
    else if (key->level == 5) {
        ret = XMEMCMP(key->p, key->k + FALCON_LEVEL5_KEY_SIZE,
                      FALCON_LEVEL5_PUB_KEY_SIZE);
    }

    if (ret != 0) {
        ret = PUBLIC_KEY_E;
    }

    return ret;
}

/* Returns the size of a falcon private key.
 *
 * key     [in]      Falcon private/public key.
 * returns BAD_FUNC_ARG when key is NULL,
 *         FALCON_LEVEL1_KEY_SIZE otherwise.
 */
int wc_falcon_size(falcon_key* key)
{
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    if (key->level == 1) {
        return FALCON_LEVEL1_KEY_SIZE;
    }
    else if (key->level == 5) {
        return FALCON_LEVEL5_KEY_SIZE;
    }

    return BAD_FUNC_ARG;
}

/* Returns the size of a falcon private plus public key.
 *
 * key     [in]      Falcon private/public key.
 * returns BAD_FUNC_ARG when key is NULL,
 *         FALCON_LEVEL1_PRV_KEY_SIZE otherwise.
 */
int wc_falcon_priv_size(falcon_key* key)
{
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    if (key->level == 1) {
        return FALCON_LEVEL1_PRV_KEY_SIZE;
    }
    else if (key->level == 5) {
        return FALCON_LEVEL5_PRV_KEY_SIZE;
    }

    return BAD_FUNC_ARG;
}

/* Returns the size of a falcon public key.
 *
 * key     [in]      Falcon private/public key.
 * returns BAD_FUNC_ARG when key is NULL,
 *         FALCON_LEVEL1_PUB_KEY_SIZE otherwise.
 */
int wc_falcon_pub_size(falcon_key* key)
{
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    if (key->level == 1) {
        return FALCON_LEVEL1_PUB_KEY_SIZE;
    }
    else if (key->level == 5) {
        return FALCON_LEVEL5_PUB_KEY_SIZE;
    }

    return BAD_FUNC_ARG;
}

/* Returns the size of a falcon signature.
 *
 * key     [in]      Falcon private/public key.
 * returns BAD_FUNC_ARG when key is NULL,
 *         FALCON_LEVEL1_SIG_SIZE otherwise.
 */
int wc_falcon_sig_size(falcon_key* key)
{
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    if (key->level == 1) {
        return FALCON_LEVEL1_SIG_SIZE;
    }
    else if (key->level == 5) {
        return FALCON_LEVEL5_SIG_SIZE;
    }

    return BAD_FUNC_ARG;
}

int wc_Falcon_PrivateKeyDecode(const byte* input, word32* inOutIdx,
                                     falcon_key* key, word32 inSz)
{
    int ret = 0;
    byte* privKey = NULL;
    byte* pubKey = NULL;
    word32 privKeyLen = FALCON_MAX_PRV_KEY_SIZE;
    word32 pubKeyLen = FALCON_MAX_PUB_KEY_SIZE;
    int keytype = 0;

    if (input == NULL || inOutIdx == NULL || key == NULL || inSz == 0) {
        return BAD_FUNC_ARG;
    }

    if (key->level == 1) {
        keytype = FALCON_LEVEL1k;
    }
    else if (key->level == 5) {
        keytype = FALCON_LEVEL5k;
    }
    else {
        return BAD_FUNC_ARG;
    }

    privKey = (byte*)XMALLOC(FALCON_MAX_PRV_KEY_SIZE, NULL,
                             DYNAMIC_TYPE_TMP_BUFFER);
    if (privKey == NULL)
        return MEMORY_E;
    pubKey = (byte*)XMALLOC(FALCON_MAX_PUB_KEY_SIZE, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (pubKey == NULL) {
        XFREE(privKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }

    ret = DecodeAsymKey(input, inOutIdx, inSz, privKey, &privKeyLen,
                        pubKey, &pubKeyLen, keytype);
    if (ret == 0) {
        /* PKCS8 may carry only the private key; pass NULL/0 in that case
         * so import_private_key can recover the public part from the legacy
         * concat layout (or leave pubKeySet = 0 for a strict raw private). */
        if (pubKeyLen == 0) {
            ret = wc_falcon_import_private_key(privKey, privKeyLen,
                                               NULL, 0, key);
        }
        else {
            ret = wc_falcon_import_private_key(privKey, privKeyLen,
                                               pubKey, pubKeyLen, key);
        }
    }

    XFREE(privKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(pubKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

int wc_Falcon_PublicKeyDecode(const byte* input, word32* inOutIdx,
                                    falcon_key* key, word32 inSz)
{
    int ret = 0;
    WC_DECLARE_VAR(pubKey, byte, FALCON_MAX_PUB_KEY_SIZE, NULL);
    word32 pubKeyLen = FALCON_MAX_PUB_KEY_SIZE;
    int keytype = 0;

    if (input == NULL || inOutIdx == NULL || key == NULL || inSz == 0) {
        return BAD_FUNC_ARG;
    }

    ret = wc_falcon_import_public(input, inSz, key);
    if (ret == 0) {
        return 0;
    }

    if (key->level == 1) {
        keytype = FALCON_LEVEL1k;
    }
    else if (key->level == 5) {
        keytype = FALCON_LEVEL5k;
    }
    else {
        return BAD_FUNC_ARG;
    }

    WC_ALLOC_VAR_EX(pubKey, byte, FALCON_MAX_PUB_KEY_SIZE, NULL,
                    DYNAMIC_TYPE_TMP_BUFFER, return MEMORY_E);

    ret = DecodeAsymKeyPublic(input, inOutIdx, inSz, pubKey, &pubKeyLen,
                              keytype);
    if (ret == 0) {
        ret = wc_falcon_import_public(pubKey, pubKeyLen, key);
    }

    WC_FREE_VAR_EX(pubKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

#ifdef WC_ENABLE_ASYM_KEY_EXPORT
/* Encode the public part of an Falcon key in DER.
 *
 * Pass NULL for output to get the size of the encoding.
 *
 * @param [in]  key       Falcon key object.
 * @param [out] output    Buffer to put encoded data in.
 * @param [in]  outLen    Size of buffer in bytes.
 * @param [in]  withAlg   Whether to use SubjectPublicKeyInfo format.
 * @return  Size of encoded data in bytes on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
int wc_Falcon_PublicKeyToDer(falcon_key* key, byte* output, word32 inLen,
                             int withAlg)
{
    int    ret;
    WC_DECLARE_VAR(pubKey, byte, FALCON_MAX_PUB_KEY_SIZE, NULL);
    word32 pubKeyLen = FALCON_MAX_PUB_KEY_SIZE;
    int    keytype = 0;

    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    if (key->level == 1) {
        keytype = FALCON_LEVEL1k;
    }
    else if (key->level == 5) {
        keytype = FALCON_LEVEL5k;
    }
    else {
        return BAD_FUNC_ARG;
    }

    WC_ALLOC_VAR_EX(pubKey, byte, FALCON_MAX_PUB_KEY_SIZE, NULL,
                    DYNAMIC_TYPE_TMP_BUFFER, return MEMORY_E);

    ret = wc_falcon_export_public(key, pubKey, &pubKeyLen);
    if (ret == 0) {
        ret = SetAsymKeyDerPublic(pubKey, pubKeyLen, output, inLen, keytype,
                                  withAlg);
    }

    WC_FREE_VAR_EX(pubKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}
#endif

int wc_Falcon_KeyToDer(falcon_key* key, byte* output, word32 inLen)
{
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    if (key->level == 1) {
        return SetAsymKeyDer(key->k, FALCON_LEVEL1_KEY_SIZE, key->p,
                             FALCON_LEVEL1_PUB_KEY_SIZE, output, inLen,
                             FALCON_LEVEL1k);
    }
    else if (key->level == 5) {
        return SetAsymKeyDer(key->k, FALCON_LEVEL5_KEY_SIZE, key->p,
                             FALCON_LEVEL5_PUB_KEY_SIZE, output, inLen,
                             FALCON_LEVEL5k);
    }

    return BAD_FUNC_ARG;
}

int wc_Falcon_PrivateKeyToDer(falcon_key* key, byte* output, word32 inLen)
{
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    if (key->level == 1) {
        return SetAsymKeyDer(key->k, FALCON_LEVEL1_KEY_SIZE, NULL, 0, output,
                             inLen, FALCON_LEVEL1k);
    }
    else if (key->level == 5) {
        return SetAsymKeyDer(key->k, FALCON_LEVEL5_KEY_SIZE, NULL, 0, output,
                             inLen, FALCON_LEVEL5k);
    }

    return BAD_FUNC_ARG;
}
#endif /* HAVE_FALCON */
