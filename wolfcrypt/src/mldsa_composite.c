/* mldsa_composite.c
 */

/* Based on dilithium.c and Reworked for Composite by Dr. Pala.
 */

/* Possible Composite options:
 *
 * HAVE_MLDSA_COMPOSITE                                       Default: OFF
 *   Enables the code in this file to be compiled.
 * WOLFSSL_NO_MLDSA44_P256                                    Default: OFF
 *   Does not compile in parameter set ML-DSA-44 and any code specific to that
 *   parameter set.
 * WOLFSSL_NO_MLDSA44_X25519                                  Default: OFF
 *   Does not compile in parameter set ML-DSA-44 and any code specific to that
 *   parameter set.
 * WOLFSSL_MLDSA_COMPOSITE_VERIFY_ONLY                        Default: OFF
 *   Compiles in only the verification and public key operations.
 * WOLFSSL_MLDSA_COMPOSITE_ASSIGN_KEY                         Default: OFF
 *   Key data is assigned into Composite key rather than copied.
 *   Life of key data passed in is tightly coupled to life of Compsite key.
 *   Cannot be used when make key is enabled.
 *
 * WOLFSSL_MLDSA_COMPOSITE_NO_ASN1                            Default: OFF
 *   Disables any ASN.1 encoding or decoding code.
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* in case user set HAVE_PQC there */
#include <wolfssl/wolfcrypt/settings.h>

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_ASN1
#include <wolfssl/wolfcrypt/asn.h>
#endif

#if defined(HAVE_MLDSA_COMPOSITE)
#include <wolfssl/wolfcrypt/mldsa_composite.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifdef WOLFSSL_WC_MLDSA_COMPOSITE


/******************************************************************************
 * Encode/Decode operations
 ******************************************************************************/

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_MAKE_KEY
int wc_mldsa_composite_make_key(mldsa_composite_key* key, WC_RNG* rng)
{
    int ret;
  
    if (!key || !rng) {
        return BAD_FUNC_ARG;
    }

    ret = wc_dilithium_make_key(key->mldsa_key, rng);
    if (ret == 0) ret = wc_ecc_make_key(rng, 256, key->alt_key.ecc);

    return ret;
}
#endif /* !WOLFSSL_MLDSA_COMPOSITE_NO_MAKE_KEY */

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_VERIFY
WOLFSSL_API
int mldsa_composite_verify_msg(mldsa_composite_key* key, const byte* msg,
    word32 msgLen, const byte* sig, word32 sigLen, int* res)
{
    return wc_mldsa_composite_verify_msg_ex(key, msg, msgLen, sig, sigLen, res, NULL, 0);
}

WOLFSSL_API
int mldsa_composite_verify_msg_ex(mldsa_composite_key* key, const byte* msg,
    word32 msgLen, const byte* sig, word32 sigLen, int* res, const byte* context, byte contextLen)
{
    int ret = 0;

    return NOT_COMPILED_IN;
}
#endif /* WOLFSSL_MLDSA_COMPOSITE_NO_VERIFY */


#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_SIGN
int wc_mldsa_composite_sign_msg(const byte* in, word32 inLen, byte* out,
    word32 *outLen, mldsa_composite_key* key, WC_RNG* rng) {

    return wc_mldsa_composite_sign_msg_ex(in, inLen, out, outLen, key, rng, NULL, 0);
}

WOLFSSL_API
int wc_mldsa_composite_sign_msg_ex(const byte* in, word32 inLen, byte* out,
    word32 *outLen, mldsa_composite_key* key, WC_RNG* rng, const byte* context, byte contextLen)
{
    int ret = 0;
    byte rnd[DILITHIUM_RND_SZ];

    /* Must have a random number generator. */
    if (rng == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Step 7: Generate random seed. */
        ret = wc_RNG_GenerateBlock(rng, rnd, DILITHIUM_RND_SZ);
    }
    if (ret == 0) {
        /* TODO:
         * 
         * Generate the ASN1 SEQUENCE for the signature
         * 
         * 1. Generate a new ASN1 SEQUENCE
         * 2. For Each of the Component Key, do
         *    2.a) Generate a new BIT STRING
         *    2.b) Generate the component's signature
         *    2.c) Add the BIT STRING to the sequence
         * 3. Save the DER representation of the sequence as the signature
         */
        ret = wc_MlDsaKey_Sign(in, inLen, outLen, in, inLen, rng);
    }

    return ret;
    }

#endif /* !WOLFSSL_MLDSA_COMPOSITE_NO_SIGN */

int wc_mldsa_composite_init(mldsa_composite_key* key)
{
    return wc_mldsa_composite_init_ex(key, NULL, INVALID_DEVID);
}

/* Initialize the MlDsaComposite private/public key.
 *
 * key  [in]  MlDsaComposite key.
 * heap [in]  Heap hint.
 * devId[in]  Device ID.
 * returns BAD_FUNC_ARG when key is NULL
 */
int wc_mldsa_composite_init_ex(mldsa_composite_key* key, void* heap, int devId)
{
    int ret = 0;

    (void)devId;

    /* Validate parameters. */
    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }

    /* Init the MLDSA Key */
    ret = wc_dilithium_init_ex(key->mldsa_key, heap, devId);
    if (ret) return ret;

    /* Sets the traditional pointer to NULL */
    key->alt_key.ecc = NULL;

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

    return ret;
}

#ifdef WOLF_PRIVATE_KEY_ID
int wc_mldsa_composite_init_id(mldsa_composite_key* key, const unsigned char* id, int len,
    void* heap, int devId)
{
    int ret = 0;

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && ((len < 0) || (len > MLDSA_COMPOSITE_MAX_ID_LEN))) {
        ret = BUFFER_E;
    }

    if (ret == 0) {
        ret = wc_dilithium_init_ex(key, heap, devId);
    }
    if ((ret == 0) && (id != NULL) && (len != 0)) {
        XMEMCPY(key->id, id, (size_t)len);
        key->idLen = len;
    }

    return ret;
}

int wc_mldsa_composite_init_label(mldsa_composite_key* key, const char* label, void* heap,
    int devId)
{
    int ret = 0;
    int labelLen = 0;

    if ((key == NULL) || (label == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        labelLen = (int)XSTRLEN(label);
        if ((labelLen == 0) || (labelLen > MLDSA_COMPOISTE_MAX_LABEL_LEN)) {
            ret = BUFFER_E;
        }
    }

    if (ret == 0) {
        ret = wc_mldsa_composite_init_ex(key, heap, devId);
    }
    if (ret == 0) {
        XMEMCPY(key->label, label, (size_t)labelLen);
        key->labelLen = labelLen;
    }

    // /* Set the maximum level here */
    // wc_dilithium_set_level(key, WC_ML_DSA_87);


    return ret;
}
#endif

/* Set the level of the MlDsaComposite private/public key.
 *
 * key   [out]  MlDsaComposite key.
 * level [in]   One of WC_MLDSA_COMPOSITE_TYPE_* values.
 * returns BAD_FUNC_ARG when key is NULL or level is a bad values.
 */
int wc_mldsa_composite_set_type(mldsa_composite_key* key, byte type)
{
    int ret = 0;

    /* Validate parameters. */
    if (key == NULL || type <= 0) {
        ret = BAD_FUNC_ARG;
    }

 
    if (ret == 0) {

        /* Sets the combination type */
        key->params.type = type;

        /* Set level according to the type of composite */
        switch (type) {
            case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_ED25519:
            case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_P256: {
                /* Set the algorithm level for the ML-DSA key */
                ret = wc_MlDsa_set_level(key->mldsa_key, WC_ML_DSA_44);
            } break;

            default: {
                /* All valid combinations should be captured */
                ret = BAD_FUNC_ARG;
            }
        }
    }

    return ret;
}

/* Get the level of the MlDsaComposite private/public key.
 *
 * key   [in]  MlDsaComposite key.
 * level [out] The level.
 * returns BAD_FUNC_ARG when key is NULL or level has not been set.
 */
int wc_mldsa_composite_get_level(mldsa_composite_key* key, byte* type)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (type == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    /* Only recognized combinations are returned */
    if ((ret == 0) && 
        (key->params.type != WC_MLDSA_COMPOSITE_TYPE_MLDSA44_ED25519) &&
        (key->params.type != WC_MLDSA_COMPOSITE_TYPE_MLDSA44_P256)) {
        /* Not Recognized as a valid composite sig */
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Return level. */
        *type = key->params.type;
    }

    return ret;
}

/* Clears the MlDsaComposite key data
 *
 * key  [in]  MlDsaComposite key.
 */
void wc_mldsa_composite_free(mldsa_composite_key* key)
{
    if (key != NULL) {

#ifdef WOLFSSL_WC_MLDSA_COMPOSITE

        /* Free the ML-DSA key*/
        if (key->mldsa_key) wc_MlDsaCompositeKey_Free(key->mldsa_key);
        ForceZero(key->mldsa_key, sizeof(*key->mldsa_key));

        /* Free the classic component */
        switch (key->params.type) {
            case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_ED25519: {
                wc_ed25519_free(key->alt_key.ed25519);
                ForceZero(key->alt_key.ecc, sizeof(*key->alt_key.ed25519));
            } break;
            case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_P256: {
                wc_ecc_free(key->alt_key.ecc);
                ForceZero(key->alt_key.ecc, sizeof(*key->alt_key.ecc));
            }
            default: {
                /* Error */
                
            }
        }
#endif /* WOLFSSL_WC_MLDSA_COMPOSITE*/

        /* Ensure all private data is zeroized. */
        ForceZero(key, sizeof(*key));
    }
}

#ifdef WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY
/* Returns the size of a MlDsaComposite private key.
 *
 * @param [in] key  Dilithium private/public key.
 * @return  Private key size on success for set level.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
int wc_mldsa_composite_size(mldsa_composite_key* key)
{
    int ret = BAD_FUNC_ARG;

    if (key != NULL) {
        if (key->params.type == WC_MLDSA_COMPOSITE_TYPE_MLDSA44_ED25519) {
            ret = MLDSA44_ED25519_KEY_SIZE;
        } else if (key->params.type == WC_MLDSA_COMPOSITE_TYPE_MLDSA44_P256) {
            ret = MLDSA44_P256_KEY_SIZE;
        }
    }

    return ret;
}

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
/* Returns the size of a MlDsaComposite private plus public key.
 *
 * @param [in] key  MlDsaComposite private/public key.
 * @return  Private key size on success for set level.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
int wc_mldsa_composite_priv_size(mldsa_composite_key* key) {

    int ret = BAD_FUNC_ARG;

    if (key != NULL) {
        if (key->params.type == WC_MLDSA_COMPOSITE_TYPE_MLDSA44_ED25519) {
            ret = MLDSA44_ED25519_PRV_KEY_SIZE;
        } else if (key->params.type == WC_MLDSA_COMPOSITE_TYPE_MLDSA44_P256) {
            ret = MLDSA44_P256_PRV_KEY_SIZE;
        }
    }

    return ret;
}

/* Returns the size of a MlDsaComposite private plus public key.
 *
 * @param [in]  key  MlDsaComposite private/public key.
 * @param [out] len  Private key size for set level.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
int wc_MlDsaCompositeKey_GetPrivLen(MlDsaCompositeKey* key, int* len)
{
    int ret = 0;

    *len = wc_mldsa_composite_priv_size(key);
    if (*len < 0) {
        ret = *len;
    }

    return ret;
}
#endif /* WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY */
#endif /* WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY */

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
/* Returns the size of a MlDsaComposite public key.
 *
 * @param [in] key  MlDsaComposite private/public key.
 * @return  Public key size on success for set level.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
int wc_mldsa_composite_pub_size(mldsa_composite_key* key)
{
    int ret = BAD_FUNC_ARG;

    if (key != NULL) {
        if (key->params.type == WC_MLDSA_COMPOSITE_TYPE_MLDSA44_ED25519) {
            ret = MLDSA44_ED25519_PUB_KEY_SIZE;
        } else if (key->params.type == WC_MLDSA_COMPOSITE_TYPE_MLDSA44_P256) {
            ret = MLDSA44_P256_PUB_KEY_SIZE;
        }
    }

    return ret;
}

/* Returns the size of a MlDsaComposite public key.
 *
 * @param [in]  key  MlDsaComposite private/public key.
 * @param [out] len  Public key size for set level.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
int wc_MlDsaComposite_GetPubLen(mldsa_composite_key* key, int* len)
{
    int ret = 0;

    *len = wc_mldsa_composite_pub_size(key);
    if (*len < 0) {
        ret = *len;
    }

    return ret;
}
#endif

#if !defined(WOLFSSL_MLDSA_COMPOSITE_NO_SIGN) || !defined(WOLFSSL_MLDSA_COMPOSITE_NO_VERIFY)
/* Returns the size of a MlDsaComposite signature.
 *
 * @param [in] key  MlDsaComposite private/public key.
 * @return  Signature size on success for set level.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
int wc_mldsa_composite_sig_size(mldsa_composite_key* key)
{
    int ret = BAD_FUNC_ARG;

    if (key != NULL) {
        if (key->params.type == WC_MLDSA_COMPOSITE_TYPE_MLDSA44_ED25519) {
            ret = MLDSA44_ED25519_SIG_SIZE;
        } else if (key->params.type == WC_MLDSA_COMPOSITE_TYPE_MLDSA44_P256) {
            ret = MLDSA44_P256_SIG_SIZE;
        }
    }

    return ret;
}

/* Returns the size of a MlDsaComposite signature.
 *
 * @param [in]  key  MlDsaComposite private/public key.
 * @param [out] len  Signature size for set level.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
int wc_MlDsaComposite_GetSigLen(mldsa_composite_key* key, int* len)
{
    int ret = 0;

    *len = wc_mldsa_composite_sig_size(key);
    if (*len < 0) {
        ret = *len;
    }

    return ret;
}
#endif

#ifdef WOLFSSL_MLDSA_COMPOSITE_CHECK_KEY
int wc_mldsa_composite_check_key(mldsa_composite_key* key)
{
    int ret = 0;
    
    ret = wc_mldsa_composite_check_key(key->mldsa_key);

    switch(key->params.type) {

#if defined(HAVE_ED25519)
        case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_ED25519: {
            ret = wc_ecc_check_key(key->alt_key.ecc);
        } break;
#endif

#if defined(HAVE_ECC)
        case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_P256: {
            ret = wc_ed25519_check_key(key->alt_key.ed25519);
        } break;
#endif

        default: {
            ret = ALGO_ID_E;
        }
    }

    return ret;
}
#endif /* WOLFSSL_MLDSA_COMPOSITE_CHECK_KEY */

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
/* Import a MlDsaComposite public key from a byte array.
 *
 * Public key encoded in big-endian.
 *
 * @param [in]      in     Array holding public key.
 * @param [in]      inLen  Number of bytes of data in array.
 * @param [in]      type   ML-DSA Composite Type (WC_MLDSA_COMPOSITE_TYPE_*)
 * @param [in, out] key    MlDsaComposite public key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when in or key is NULL or key format is not supported.
 */
int wc_mldsa_composite_import_public(const byte* in, word32 inLen, mldsa_composite_key* key, word32 type)
{
    int ret = 0;

    /* Validate parameters. */
    if ((in == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Copy the private key data in or copy pointer. */
    #ifndef WOLFSSL_MLDSA_COMPOSITE_ASSIGN_KEY
        XMEMCPY(key->p, in, inLen);
    #else
        key->p = in;
    #endif

        /* Unpacks The SEQUENCE */
        /*
         * TODO:
         *
         * 1. Start the ASN1 parser, open a SEQUENCE
         * 2. Extract the contents of each OCTET STRING
         * 3. Checks the Key Type against the expected one (type)
         * 4. Import the extracted contents into the public key
        */

        /* Public key is set. */
        key->pubKeySet = 1;
    }

    return ret;
}

/* Export the MlDsaComposite public key.
 *
 * @param [in]      key     MlDsaComposite public key.
 * @param [out]     out     Array to hold public key.
 * @param [in, out] outLen  On in, the number of bytes in array.
 *                          On out, the number bytes put into array.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  BUFFER_E when outLen is less than DILITHIUM_LEVEL2_PUB_KEY_SIZE.
 */
int wc_mldsa_composite_export_public(mldsa_composite_key* key, byte* out, word32* outLen)
{
    int ret = 0;
    word32 inLen;

    /* Validate parameters */
    if ((key == NULL) || (out == NULL) || (outLen == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        /* Get length passed in for checking. */
        inLen = *outLen;
        *outLen = wc_mldsa_composite_pub_size(key);
        if (inLen < *outLen) {
            ret = BUFFER_E;
        } else {
            /* Level not set. */
            ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0) {

        /* TODO: 
         * =====
         * 
         * 1. Generate a new ASN1 SEQUENCE
         * 2. For Each Component in the key
         *    2.a) Generate a BIT STRING
         *    2.b) Export the Component in the BIT STRING
         *    2.c) Add the BIT STRING to the SEQUENCE
         * 3. Export the DER encoded sequence 
        */

        word32 tmpLen = *outLen;
        /* Exports the ML-DSA key first */
        ret = wc_MlDsaKey_ExportPubRaw(key->mldsa_key, out, &tmpLen);
        if (ret == 0) {
            *outLen = tmpLen;
            int pubLenX = 32, pubLenY = 32;
            ret = wc_ecc_export_public_raw(key, out, &pubLenX, out + 32, &pubLenY);
        }
    }

    return ret;
}
#endif /* WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY */


#ifdef WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY
/* Import a mldsa_composite private key from a byte array.
 *
 * @param [in]      priv    Array holding private key.
 * @param [in]      privSz  Number of bytes of data in array.
 * @param [in, out] key     mldsa_composite private key.
 * @param [in]      type    WC_MLDSA_COMPOSITEKEY_TYPE_* values
 * @return  0 otherwise.
 * @return  BAD_FUNC_ARG when a parameter is NULL or privSz is less than size
 *          required for level,
 */
int wc_mldsa_composite_import_private(const byte* priv, word32 privSz,
    mldsa_composite_key* key, wc_MlDsaCompositeType type)
{
    int ret = 0;

    /* Validate parameters. */
    if ((priv == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    /* Unpacks The SEQUENCE */
    /*
        * TODO:
        *
        * 1. Start the ASN1 parser, open a SEQUENCE
        * 2. Extract the contents of each OCTET STRING
        * 3. Checks the Key Type against the expected one (type)
        * 4. Import the extracted contents into the private key
    */

    if (ret == 0) {
        ret = wc_MlDsaKey_import_private(priv, privSz, key);
        /* Private key is set. */
        
    }

    return ret;
}

/* Export the mldsa_composite private key.
 *
 * @param [in]      key     mldsa_composite private key.
 * @param [out]     out     Array to hold private key.
 * @param [in, out] outLen  On in, the number of bytes in array.
 *                          On out, the number bytes put into array.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  BUFFER_E when outLen is less than DILITHIUM_LEVEL2_KEY_SIZE.
 */
int wc_mldsa_composite_export_private(mldsa_composite_key* key, byte* out,
    word32* outLen)
{
    int ret = 0;
    word32 inLen;

    /* Validate parameters. */
    if ((key == NULL) || (out == NULL) || (outLen == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    /* Check private key available. */
    if ((ret == 0) && (!key->prvKeySet)) {
        ret = BAD_FUNC_ARG;
    }

    /* Check array length. */
    if ((ret == 0) && (inLen < *outLen)) {
        ret = BUFFER_E;
    }

    // if (ret == 0) {
    //     /* Copy private key out key. */
    //     XMEMCPY(out, key->k, *outLen);
    // }

    return ret;
}

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
int wc_mldsa_composite_import_key(const byte* priv, word32 privSz,
    const byte* pub, word32 pubSz, mldsa_composite_key* key)
{
    int ret = 0;

    /* Validate parameters. */
    if ((priv == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if ((pub == NULL) && (pubSz != 0)) {
        ret = BAD_FUNC_ARG;
    }

    if ((ret == 0) && (pub != NULL)) {
        /* Import public key. */
        ret = wc_dilithium_import_public(pub, pubSz, key);
    }
    if (ret == 0) {
        ret = dilithium_set_priv_key(priv, privSz, key);
    }

    return ret;
}
#endif /* WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY */

int wc_mldsa_composite_export_key(mldsa_composite_key* key, byte* priv, word32 *privSz,
    byte* pub, word32 *pubSz)
{
    int ret;

    /* Export private key only. */
    ret = wc_mldsa_composite_export_private(key, priv, privSz);
    if (ret == 0) {
        /* Export public key. */
        ret = wc_mldsa_composite_export_public(key, pub, pubSz);
    }

    return ret;
}
#endif /* WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY */
#endif /* WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY */

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_ASN1
#if defined(WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY)
int wc_MlDsaComposite_PrivateKeyDecode(const byte* input, word32* inOutIdx,
    mldsa_composite_key* key, word32 inSz)
{
    int ret = 0;
    const byte* privKey = NULL;
    const byte* pubKey = NULL;
    word32 privKeyLen = 0;
    word32 pubKeyLen = 0;
    int keytype = 0;

    /* Validate parameters. */
    if ((input == NULL) || (inOutIdx == NULL) || (key == NULL) || (inSz == 0)) {
        ret = BAD_FUNC_ARG;
    }

    keytype = MLDSA44_ED25519k;

    if (ret == 0) {
        /* Decode the asymmetric key and get out private and public key data. */
        ret = DecodeAsymKey_Assign(input, inOutIdx, inSz, &privKey, &privKeyLen,
            &pubKey, &pubKeyLen, keytype);
    }
    if ((ret == 0) && (pubKey == NULL) && (pubKeyLen == 0)) {
        // /* Check if the public key is included in the private key. */
        // if ((key->level == WC_ML_DSA_44) &&
        //     (privKeyLen == DILITHIUM_LEVEL2_PRV_KEY_SIZE)) {
        //     pubKey = privKey + DILITHIUM_LEVEL2_KEY_SIZE;
        //     pubKeyLen = DILITHIUM_LEVEL2_PUB_KEY_SIZE;
        //     privKeyLen -= DILITHIUM_LEVEL2_PUB_KEY_SIZE;
        // }
        // else if ((key->level == WC_ML_DSA_65) &&
        //          (privKeyLen == DILITHIUM_LEVEL3_PRV_KEY_SIZE)) {
        //     pubKey = privKey + DILITHIUM_LEVEL3_KEY_SIZE;
        //     pubKeyLen = DILITHIUM_LEVEL3_PUB_KEY_SIZE;
        //     privKeyLen -= DILITHIUM_LEVEL3_PUB_KEY_SIZE;
        // }
        // else if ((key->level == WC_ML_DSA_87) &&
        //          (privKeyLen == DILITHIUM_LEVEL5_PRV_KEY_SIZE)) {
        //     pubKey = privKey + DILITHIUM_LEVEL5_KEY_SIZE;
        //     pubKeyLen = DILITHIUM_LEVEL5_PUB_KEY_SIZE;
        //     privKeyLen -= DILITHIUM_LEVEL5_PUB_KEY_SIZE;
        // }
    }

    if (ret == 0) {
        /* Check whether public key data was found. */
#if defined(WOLFSSL_DILITHIUM_PUBLIC_KEY)
        if (pubKeyLen == 0)
#endif
        {
            /* No public key data, only import private key data. */
            ret = wc_dilithium_import_private(privKey, privKeyLen, key);
        }
#if defined(WOLFSSL_DILITHIUM_PUBLIC_KEY)
        else {
            /* Import private and public key data. */
            ret = wc_dilithium_import_key(privKey, privKeyLen, pubKey,
                pubKeyLen, key);
        }
#endif
    }

    (void)pubKey;
    (void)pubKeyLen;

    return ret;
}

#endif /* WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY */

#endif /* WOLFSSL_MLDSA_COMPOSITE_NO_ASN1 */

static int mldsa_composite_get_der_length(const byte* input, word32* inOutIdx,
    int *length, word32 inSz)
{
    int ret = 0;
    word32 idx = *inOutIdx;
    word32 len = 0;

    if (idx >= inSz) {
        ret = ASN_PARSE_E;
    }
    else if (input[idx] < 0x80) {
        len = input[idx];
        idx++;
    }
    else if ((input[idx] == 0x80) || (input[idx] >= 0x83)) {
        ret = ASN_PARSE_E;
    }
    else if (input[idx] == 0x81) {
        if (idx + 1 >= inSz) {
            ret = ASN_PARSE_E;
        }
        else if (input[idx + 1] < 0x80) {
            ret = ASN_PARSE_E;
        }
        else {
            len = input[idx + 1];
            idx += 2;
        }
    }
    else if (input[idx] == 0x82) {
        if (idx + 2 >= inSz) {
            ret = ASN_PARSE_E;
        }
        else {
            len = ((word16)input[idx + 1] << 8) + input[idx + 2];
            idx += 3;
            if (len < 0x100) {
                ret = ASN_PARSE_E;
            }
        }
    }

    if ((ret == 0) && ((idx + len) > inSz)) {
        ret = ASN_PARSE_E;
    }

    *length = (int)len;
    *inOutIdx = idx;
    return ret;
}

static int mldsa_composite_check_type(const byte* input, word32* inOutIdx, byte type,
    word32 inSz)
{
    int ret = 0;
    word32 idx = *inOutIdx;

    if (idx >= inSz) {
        ret = ASN_PARSE_E;
    }
    else if (input[idx] != type){
        ret = ASN_PARSE_E;
    }
    else {
        idx++;
    }

    *inOutIdx = idx;
    return ret;
}

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
int wc_MlDsaComposite_PublicKeyDecode(const byte* input, word32* inOutIdx,
    mldsa_composite_key* key, word32 inSz)
{
    int ret = 0;
    const byte* pubKey;
    word32 pubKeyLen = 0;

    /* Validate parameters. */
    if ((input == NULL) || (inOutIdx == NULL) || (key == NULL) || (inSz == 0)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Try to import the key directly. */
        ret = wc_mldsa_composite_import_public(input, inSz, key, key->params.type);
        if (ret != 0) {
        #if !defined(WOLFSSL_MLDSA_COMPOSITE_NO_ASN1)
            int keytype = 0;
        #else
            int length;
            unsigned char* oid;
            int oidLen;
            word32 idx = 0;
        #endif

            /* Start again. */
            ret = 0;

    #if !defined(WOLFSSL_MLDSA_COMPOSITE_NO_ASN1)
            // /* Get OID sum for level. */
            // if (key->level == WC_ML_DSA_44) {
            //     keytype = DILITHIUM_LEVEL2k;
            // }
            // else if (key->level == WC_ML_DSA_65) {
            //     keytype = DILITHIUM_LEVEL3k;
            // }
            // else if (key->level == WC_ML_DSA_87) {
            //     keytype = DILITHIUM_LEVEL5k;
            // }
            // else {
            //     /* Level not set. */
            //     ret = BAD_FUNC_ARG;
            // }
            if (ret == 0) {
                /* Decode the asymmetric key and get out public key data. */
                ret = DecodeAsymKeyPublic_Assign(input, inOutIdx, inSz, &pubKey,
                    &pubKeyLen, keytype);
            }
    #else
            /* Get OID sum for level. */
        #ifndef WOLFSSL_NO_ML_DSA_44
            if (key->level == WC_ML_DSA_44) {
                oid = dilithium_oid_44;
                oidLen = (int)sizeof(dilithium_oid_44);
            }
            else
        #endif
        #ifndef WOLFSSL_NO_ML_DSA_65
            if (key->level == WC_ML_DSA_65) {
                oid = dilithium_oid_65;
                oidLen = (int)sizeof(dilithium_oid_65);
            }
            else
        #endif
        #ifndef WOLFSSL_NO_ML_DSA_87
            if (key->level == WC_ML_DSA_87) {
                oid = dilithium_oid_87;
                oidLen = (int)sizeof(dilithium_oid_87);
            }
            else
        #endif
            {
                /* Level not set. */
                ret = BAD_FUNC_ARG;
            }
            if (ret == 0) {
                ret = dilithium_check_type(input, &idx, 0x30, inSz);
            }
            if (ret == 0) {
                ret = dilitihium_get_der_length(input, &idx, &length, inSz);
            }
            if (ret == 0) {
                ret = dilithium_check_type(input, &idx, 0x30, inSz);
            }
            if (ret == 0) {
                ret = dilitihium_get_der_length(input, &idx, &length, inSz);
            }
            if (ret == 0) {
                ret = dilithium_check_type(input, &idx, 0x06, inSz);
            }
            if (ret == 0) {
                ret = dilitihium_get_der_length(input, &idx, &length, inSz);
            }
            if (ret == 0) {
                if ((length != oidLen) ||
                        (XMEMCMP(input + idx, oid, oidLen) != 0)) {
                    ret = ASN_PARSE_E;
                }
                idx += oidLen;
            }
            if (ret == 0) {
                ret = dilithium_check_type(input, &idx, 0x03, inSz);
            }
            if (ret == 0) {
                ret = dilitihium_get_der_length(input, &idx, &length, inSz);
            }
            if (ret == 0) {
                if (input[idx] != 0) {
                    ret = ASN_PARSE_E;
                }
                idx++;
                length--;
            }
            if (ret == 0) {
                /* This is the raw point data compressed or uncompressed. */
                pubKeyLen = (word32)length;
                pubKey = input + idx;
            }
    #endif
            if (ret == 0) {
                /* Import public key data. */
                ret = wc_dilithium_import_public(pubKey, pubKeyLen, key);
            }
        }
    }
    return ret;
}

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_ASN1

#ifdef WC_ENABLE_ASYM_KEY_EXPORT
int wc_MlDsaComposite_PublicKeyToDer(mldsa_composite_key* key, byte* output, word32 len,
    int withAlg)
{
    int ret = 0;
    int keytype = 0;
    int pubKeyLen = 0;

    /* Validate parameters. */
    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    /* Check we have a public key to encode. */
    if ((ret == 0) && (!key->pubKeySet)) {
        ret = BAD_FUNC_ARG;
    }

    // if (ret == 0) {
    //     /* Get OID and length for level. */
    //     if (key->level == WC_ML_DSA_44) {
    //         keytype = DILITHIUM_LEVEL2k;
    //         pubKeyLen = DILITHIUM_LEVEL2_PUB_KEY_SIZE;
    //     }
    //     else if (key->level == WC_ML_DSA_65) {
    //         keytype = DILITHIUM_LEVEL3k;
    //         pubKeyLen = DILITHIUM_LEVEL3_PUB_KEY_SIZE;
    //     }
    //     else if (key->level == WC_ML_DSA_87) {
    //         keytype = DILITHIUM_LEVEL5k;
    //         pubKeyLen = DILITHIUM_LEVEL5_PUB_KEY_SIZE;
    //     }
    //     else {
    //         /* Level not set. */
    //         ret = BAD_FUNC_ARG;
    //     }
    // }

    if (ret == 0) {
        ret = SetAsymKeyDerPublic(key->p, pubKeyLen, output, len, keytype,
            withAlg);
    }

    return ret;
}
#endif /* WC_ENABLE_ASYM_KEY_EXPORT */

#endif /* !WOLFSSL_MLDSA_COMPOSITE_NO_ASN1 */

#endif /* WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY */

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_ASN1

#ifdef WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY


int wc_MlDsaComposite_PrivateKeyToDer(mldsa_composite_key* key, byte* output, word32 len)
{
    int ret = BAD_FUNC_ARG;

    // /* Validate parameters and check private key set. */
    // if ((key != NULL) && key->prvKeySet) {
    //     /* Create DER for level. */
    //     if (key->level == WC_ML_DSA_44) {
    //         ret = SetAsymKeyDer(key->k, DILITHIUM_LEVEL2_KEY_SIZE, NULL, 0,
    //             output, len, DILITHIUM_LEVEL2k);
    //     }
    //     else if (key->level == WC_ML_DSA_65) {
    //         ret = SetAsymKeyDer(key->k, DILITHIUM_LEVEL3_KEY_SIZE, NULL, 0,
    //             output, len, DILITHIUM_LEVEL3k);
    //     }
    //     else if (key->level == WC_ML_DSA_87) {
    //         ret = SetAsymKeyDer(key->k, DILITHIUM_LEVEL5_KEY_SIZE, NULL, 0,
    //             output, len, DILITHIUM_LEVEL5k);
    //     }
    // }

    return ret;
}

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY

int wcMlDsaComposite_KeyToDer(mldsa_composite_key* key, byte* output, word32 len)
{
    int ret = BAD_FUNC_ARG;

    // /* Validate parameters and check public and private key set. */
    // if ((key != NULL) && key->prvKeySet && key->pubKeySet) {
    //     /* Create DER for level. */
    //     if (key->level == WC_ML_DSA_44) {
    //         ret = SetAsymKeyDer(key->k, DILITHIUM_LEVEL2_KEY_SIZE, key->p,
    //             DILITHIUM_LEVEL2_PUB_KEY_SIZE, output, len, DILITHIUM_LEVEL2k);
    //     }
    //     else if (key->level == WC_ML_DSA_65) {
    //         ret = SetAsymKeyDer(key->k, DILITHIUM_LEVEL3_KEY_SIZE, key->p,
    //             DILITHIUM_LEVEL3_PUB_KEY_SIZE, output, len, DILITHIUM_LEVEL3k);
    //     }
    //     else if (key->level == WC_ML_DSA_87) {
    //         ret = SetAsymKeyDer(key->k, DILITHIUM_LEVEL5_KEY_SIZE, key->p,
    //             DILITHIUM_LEVEL5_PUB_KEY_SIZE, output, len, DILITHIUM_LEVEL5k);
    //     }
    // }

    return ret;
}
#endif /* WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY */
#endif /* WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY */

#endif /* !WOLFSSL_MLDSA_COMPOSITE_NO_ASN1 */


#endif /* HAVE_MLDSA_COMPOSITE */
