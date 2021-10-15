/* falcon.c
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

/* Based on ed448.c and Reworked for Falcon by Anthony Hu. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* in case user set HAVE_LIBOQS there */
#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_LIBOQS

#include <oqs/oqs.h>


#include <wolfssl/wolfcrypt/falcon.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* ANTH TODO: Level 1 and Level 5 are just copy/paste and then search/replace
 *            so we should make them into templates or macros or a python script
 *            or some other thing that allows us to maintain it easier. 
 */

/***********************************/
/* Falcon Level 1 APIs [Falcon512] */
/***********************************/

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
                              falcon_key* key)
{
    int ret = 0;
    OQS_SIG *oqssig = NULL;

    /* sanity check on arguments */
    if ((in == NULL) || (out == NULL) || (outLen == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }

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
    }

    if ((ret == 0) &&
        (OQS_SIG_sign(oqssig, out, (size_t *)outLen, in, inLen, key->k)
         == OQS_ERROR)) {
        /* ANTH TODO: better return value! */
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        if (key->level == 1) {
            *outLen = FALCON_LEVEL1_SIG_SIZE;
        }
        else if (key->level == 5) {
            *outLen = FALCON_LEVEL5_SIG_SIZE;
        }
    }

    if (oqssig != NULL) {
        OQS_SIG_free(oqssig);
    }

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
    OQS_SIG *oqssig = NULL;

    if (key == NULL || sig == NULL || msg == NULL || res == NULL) {
        ret = BAD_FUNC_ARG;
    }

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

    return ret;
}

/* Initialize the falcon level 1 private/public key.
 *
 * key  [in]  Falcon key.
 * returns BAD_FUNC_ARG when key is NULL
 */
int wc_falcon_level1_init(falcon_key* key)
{
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    ForceZero(key, sizeof(key));
    key->level = 1;
    return 0;
}

/* Initialize the falcon level 5 private/public key.
 *
 * key  [in]  Falcon key.
 * returns BAD_FUNC_ARG when key is NULL
 */
int wc_falcon_level5_init(falcon_key* key)
{
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    ForceZero(key, sizeof(key));
    key->level = 5;
    return 0;
}

/* Clears the falcon key data
 *
 * key  [in]  Falcon key.
 */
void wc_falcon_free(falcon_key* key)
{
    if (key != NULL) {
        ForceZero(key, sizeof(key));
    }
}

/* Export the falcon public key.
 *
 * key     [in]      Falcon public key.
 * out     [in]      Array to hold public key.
 * outLen  [in/out]  On in, the number of bytes in array.
 *                   On out, the number bytes put into array.
 * returns BAD_FUNC_ARG when a parameter is NULL,
 *         ECC_BAD_ARG_E when outLen is less than FALCON_LEVEL1_PUB_KEY_SIZE,
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

/* Import a falcon private key from a byte array.
 *
 * priv    [in]  Array holding private key.
 * privSz  [in]  Number of bytes of data in array.
 * key     [in]  Falcon private key.
 * returns BAD_FUNC_ARG when a parameter is NULL or privSz is less than
 *         FALCON_LEVEL1_KEY_SIZE,
 *         0 otherwise.
 */
int wc_falcon_import_private_only(const byte* priv, word32 privSz,
                                 falcon_key* key)
{

    /* sanity check on arguments */
    if ((priv == NULL) || (key == NULL)) {
        return BAD_FUNC_ARG;
    }

    if ((key->level != 1) && (key->level != 5)) {
        return BAD_FUNC_ARG;
    }

    /* key size check */
    if ((key->level == 1) && (privSz != FALCON_LEVEL1_KEY_SIZE)) {
        return BAD_FUNC_ARG;
    }
    else if ((key->level == 5) && (privSz != FALCON_LEVEL5_KEY_SIZE)) {
        return BAD_FUNC_ARG;
    }

    XMEMCPY(key->k, priv, privSz);
    key->prvKeySet = 1;

    return 0;
}

/* Import a falcon private and public keys from byte array(s).
 *
 * priv    [in]  Array holding private key or private+public keys
 * privSz  [in]  Number of bytes of data in private key array.
 * pub     [in]  Array holding public key (or NULL).
 * pubSz   [in]  Number of bytes of data in public key array (or 0).
 * key     [in]  Falcon private/public key.
 * returns BAD_FUNC_ARG when a required parameter is NULL or an invalid
 *         combination of keys/lengths is supplied, 0 otherwise.
 */
int wc_falcon_import_private_key(const byte* priv, word32 privSz,
                                        const byte* pub, word32 pubSz,
                                        falcon_key* key)
{
    int ret = 0;

    /* sanity check on arguments */
    if (priv == NULL || key == NULL) {
        return BAD_FUNC_ARG;
    }

    if ((key->level != 1) && (key->level != 5)) {
        return BAD_FUNC_ARG;
    }

    /* key size check */
    if ((key->level == 1) && (privSz != FALCON_LEVEL1_KEY_SIZE) &&
        (privSz != FALCON_LEVEL1_PRV_KEY_SIZE)) {
        return BAD_FUNC_ARG;
    }
    else if ((key->level == 5) && (privSz != FALCON_LEVEL5_KEY_SIZE) &&
             (privSz != FALCON_LEVEL5_PRV_KEY_SIZE)) {
        return BAD_FUNC_ARG;
    }

    if (pub == NULL) {
        if (pubSz != 0) {
            return BAD_FUNC_ARG;
        }

        if ((privSz != FALCON_LEVEL1_PRV_KEY_SIZE) &&
            (privSz != FALCON_LEVEL5_PRV_KEY_SIZE)) {
            return BAD_FUNC_ARG;
        }

        if (key->level == 1) {
            pub = priv + FALCON_LEVEL1_KEY_SIZE;
            pubSz = FALCON_LEVEL1_PUB_KEY_SIZE;
        }
        else if (key->level == 5) {
            pub = priv + FALCON_LEVEL5_KEY_SIZE;
            pubSz = FALCON_LEVEL5_PUB_KEY_SIZE;
        }
    }
    else if ((pubSz != FALCON_LEVEL1_PUB_KEY_SIZE) &&
             (pubSz != FALCON_LEVEL5_PUB_KEY_SIZE)) {
        return BAD_FUNC_ARG;
    }

    /* import public key */
    ret = wc_falcon_import_public(pub, pubSz, key);

    if (ret == 0) {
        /* make the private key (priv + pub) */
        if (key->level == 1) {
            XMEMCPY(key->k, priv, FALCON_LEVEL1_KEY_SIZE);
        }
        else if (key->level == 5) {
            XMEMCPY(key->k, priv, FALCON_LEVEL5_KEY_SIZE);
        }
        key->prvKeySet = 1;
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
 *         ECC_BAD_ARG_E when outLen is less than FALCON_LEVEL1_KEY_SIZE,
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
        XMEMCPY(out, key->k, FALCON_LEVEL1_PRV_KEY_SIZE);
        XMEMCPY(out + FALCON_LEVEL1_PRV_KEY_SIZE, key->p,
                FALCON_LEVEL1_PUB_KEY_SIZE);
    }
    else if (key->level == 5) {
        *outLen = FALCON_LEVEL5_PRV_KEY_SIZE;
        XMEMCPY(out, key->k, FALCON_LEVEL5_PRV_KEY_SIZE);
        XMEMCPY(out + FALCON_LEVEL5_PRV_KEY_SIZE, key->p,
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
    /* ANTH TODO: Sign and verify some random message. */
    int ret = 0;
    (void)key;
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
#endif /* HAVE_LIBOQS */
