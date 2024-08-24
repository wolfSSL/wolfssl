/* mldsa_composite.h
 */

/*!
    \file wolfssl/wolfcrypt/mldsa_composite.h
*/

/* Interfaces for Composite Signatures */

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

/* in case user set HAVE_ECC there */
#include <wolfssl/wolfcrypt/settings.h>

#ifndef WOLF_CRYPT_MLDSA_COMPOSITE_H
#define WOLF_CRYPT_MLDSA_COMPOSITE_H

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/asn.h>

#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif

#if defined(HAVE_MLDSA_COMPOSITE)

#include <wolfssl/wolfcrypt/dilithium.h>

#if defined(HAVE_ECC)
#include <wolfssl/wolfcrypt/ecc.h>
#endif

#if defined(HAVE_ED25519)
#include <wolfssl/wolfcrypt/ed25519.h>
#endif

#if defined(HAVE_ED448)
#include <wolfssl/wolfcrypt/ed448.h>
#endif

#ifndef NO_RSA
#include <wolfssl/wolfcrypt/rsa.h>
#endif

#if defined(WOLFSSL_MLDSA_COMPOSITE_NO_MAKE_KEY) && \
        defined(WOLFSSL_MLDSA_COMPOSITE_NO_SIGN) && \
        !defined(WOLFSSL_MLDSA_COMPOSITE_NO_VERIFY) && \
        !defined(WOLFSSL_MLDSA_COMPOSITE_VERIFY_ONLY)
    #define WOLFSSL_MLDSA_COMPOSITE_VERIFY_ONLY
#endif
#ifdef WOLFSSL_MLDSA_COMPOSITE_VERIFY_ONLY
    #ifndef WOLFSSL_MLDSA_COMPOSITE_NO_MAKE_KEY
        #define WOLFSSL_MLDSA_COMPOSITE_NO_MAKE_KEY
    #endif
    #ifndef WOLFSSL_MLDSA_COMPOSITE_NO_SIGN
        #define WOLFSSL_MLDSA_COMPOSITE_NO_SIGN
    #endif
#endif

#if !defined(WOLFSSL_MLDSA_COMPOSITE_NO_MAKE_KEY) || \
        !defined(WOLFSSL_MLDSA_COMPOSITE_NO_VERIFY)
    #define WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
#endif
#if !defined(WOLFSSL_MLDSA_COMPOSITE_NO_MAKE_KEY) || \
        !defined(WOLFSSL_MLDSA_COMPOSITE_NO_SIGN)
    #define WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY
#endif

#if defined(WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY) && \
        defined(WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY) && \
        !defined(WOLFSSL_MLDSA_COMPOSITE_NO_CHECK_KEY) && \
        !defined(WOLFSSL_MLDSA_COMPOSITE_CHECK_KEY)
    #define WOLFSSL_MLDSA_COMPOSITE_CHECK_KEY
#endif

#ifdef __cplusplus
    extern "C" {
#endif

/* Macros Definitions */

#ifdef WOLFSSL_WC_MLDSA_COMPOSITE

#define WF_MLDSA44_P256             1
#define WF_MLDSA44_ED25519          2

#define MLDSA_COMPOSITE_MAX_SEQUENCE_DER_SIZE    50

// TODO: Fix how to get the right values
#define ECC_KEY_SIZE                64
#define ECC_SIG_SIZE                32

#define MLDSA44_P256_KEY_SIZE       DILITHIUM_ML_DSA_44_KEY_SIZE + ECC_KEY_SIZE + MLDSA_COMPOSITE_MAX_SEQUENCE_DER_SIZE
#define MLDSA44_P256_SIG_SIZE       DILITHIUM_ML_DSA_44_KEY_SIZE + ECC_SIG_SIZE + MLDSA_COMPOSITE_MAX_SEQUENCE_DER_SIZE
#define MLDSA44_P256_PUB_KEY_SIZE   DILITHIUM_ML_DSA_44_PUB_KEY_SIZE + ECC_KEY_SIZE + MLDSA_COMPOSITE_MAX_SEQUENCE_DER_SIZE
#define MLDSA44_P256_PRV_KEY_SIZE   \
    (MLDSA44_P256_PUB_KEY_SIZE + MLDSA44_P256_KEY_SIZE)

#define MLDSA44_ED25519_KEY_SIZE       DILITHIUM_ML_DSA_44_KEY_SIZE + ED25519_KEY_SIZE + MLDSA_COMPOSITE_MAX_SEQUENCE_DER_SIZE
#define MLDSA44_ED25519_SIG_SIZE       DILITHIUM_ML_DSA_44_KEY_SIZE + ED25519_SIG_SIZE + MLDSA_COMPOSITE_MAX_SEQUENCE_DER_SIZE
#define MLDSA44_ED25519_PUB_KEY_SIZE   DILITHIUM_ML_DSA_44_PUB_KEY_SIZE + ED25519_PUB_KEY_SIZE + MLDSA_COMPOSITE_MAX_SEQUENCE_DER_SIZE
#define MLDSA44_ED25519_PRV_KEY_SIZE   \
    (MLDSA44_ED25519_PUB_KEY_SIZE + MLDSA44_ED25519_KEY_SIZE)

#define MLDSA_COMPOSITE_MAX_KEY_SIZE     DILITHIUM_LEVEL5_KEY_SIZE + P256_KEY_SIZE + MLDSA_COMPOSITE_MAX_SEQUENCE_DER_SIZE
#define MLDSA_COMPOSITE_MAX_SIG_SIZE     DILITHIUM_LEVEL5_SIG_SIZE + P256_SIG_SIZE + MLDSA_COMPOSITE_MAX_SEQUENCE_DER_SIZE
#define MLDSA_COMPOSITE_MAX_PUB_KEY_SIZE DILITHIUM_LEVEL5_PUB_KEY_SIZE + P256_PUB_KEY_SIZE + MLDSA_COMPOSITE_MAX_SEQUENCE_DER_SIZE
#define MLDSA_COMPOSITE_MAX_PRV_KEY_SIZE DILITHIUM_LEVEL5_PRV_KEY_SIZE + P256_PRV_KEY_SIZE + MLDSA_COMPOSITE_MAX_SEQUENCE_DER_SIZE

#ifdef WOLF_PRIVATE_KEY_ID
#define MLDSA_COMPOSITE_MAX_ID_LEN    32
#define MLDSA_COMPOSITE_MAX_LABEL_LEN 32
#endif

#endif /* WOLFSSL_WC_MLDSA_COMPOSITE */

/* Structs */

#ifdef WOLFSSL_WC_MLDSA_COMPOSITE

enum wc_MlDsaCompositeType {
    WC_MLDSA_COMPOSITE_TYPE_MLDSA44_P256         = 1,
    WC_MLDSA_COMPOSITE_TYPE_MLDSA44_ED25519      = 2,
};

typedef enum wc_MlDsaCompositeType wc_MlDsaCompositeType;

typedef struct wc_mldsa_composite_key_params {
    enum wc_PkType type;
    union {        
        struct {
            word16 bits;
            enum wc_HashType mask_gen_param;
            enum wc_HashType digest_alg_param;
            int salt_len;
        } rsapss;

        struct {
            word16 bits;    
        } rsa_oaep;
        
        struct {
            ecc_curve_id curve_id;
        } ecdsa;

        struct {
            // No Params
        } ed25519;

        struct {
            byte level;
        } dilithium;

        struct {
            byte level;
        } falcon;

    } values;
} wc_MlDsaCompositeKeyParams;


#endif

struct mldsa_composite_key {

    void * p;
        /* Pointer to Raw Encoding */
    
    byte pubKeySet;
    byte prvKeySet;
        /* Track key contents */

#ifdef WOLF_CRYPTO_CB
    int devId; /* should use wc_CryptoCb_DefaultDevID() */
    void devCtx;
#endif /* WOLF_CRYPTO_CB */

#ifdef WOLF_PRIVATE_KEY_ID
    byte * id;
    int idLen;

    byte * label;
    int labelLen;
#endif /* WOLF_PRIVATE_KEY_ID */
    struct {
        wc_MlDsaCompositeType type; /* WC_MLDSA_COMPOSITE_TYPE */
        wc_MlDsaCompositeKeyParams keyParams[2];
        const enum wc_HashType hash;
    } params;
    MlDsaKey * mldsa_key;
    union {
        RsaKey * rsa_oaep; /* RSAOAEPk, RSAPSSk */
        ecc_key * ecc; /* ECDSAk */
        ed25519_key * ed25519; /* ED25519k */
    } alt_key;
};

#ifndef WC_MLDSA_COMPOSITEKEY_TYPE_DEFINED
    typedef struct mldsa_composite_key mldsa_composite_key;
    #define mldsa_composite_key MlDsaCompositeKey
    #define WC_MLDSA_COMPOSITEKEY_TYPE_DEFINED
    const mldsa_composite_key mldsacomposite_params[] = {
        { MLDSA44_ED25519k, SHA256, { { DILITHIUM_LEVEL2k, 2 }, { } }, NULL, { NULL } },
        { MLDSA44_P256k, SHA256, { { DILITHIUM_LEVEL2k, 2 }, { ECC_SECP256R1 } }, NULL, { NULL } },
    };
#endif


#define MlDsaCompositeKey mldsa_composite_key

/* Functions */

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_MAKE_KEY
/* Make a key from a random seed.
 *
 * @param [in, out] key  Dilithium key.
 * @param [in]      rng  Random number generator.
 * @return  0 on success.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
WOLFSSL_API int wc_mldsa_composite_make_key(mldsa_composite_key* key, WC_RNG* rng);
#endif /* ! WOLFSSL_MLDSA_COMPOSITE_NO_MAKE_KEY */

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_VERIFY

/* Verify signature of message using public key.
 * @param [in]      sig     Signature to verify message.
 * @param [in]      sigLen  Length of message in bytes.
 * @param [in]      msg     Message to verify.
 * @param [in]      msgLen  Length of message in bytes.
 * @param [out]     res     Result of verification.
 * @param [in, out] key     ML-DSA composite key.
 * @return  0 on success.
 * @return  SIG_VERIFY_E when hint is malformed.
 * @return  BUFFER_E when the length of the signature does not match
 *          parameters.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
WOLFSSL_API int wc_mldsa_composite_verify_msg(const byte* sig, word32 sigLen, const byte* msg,
    word32 msgLen, int* res, mldsa_composite_key* key);

/* Verify signature of message using public key and context.
 * @param [in]      sig     Signature to verify message.
 * @param [in]      sigLen  Length of message in bytes.
 * @param [in]      msg     Message to verify.
 * @param [in]      msgLen  Length of message in bytes.
 * @param [out]     res     Result of verification.
 * @param [in, out] key     ML-DSA composite key.
 * @param [in]      context  Extra signing data.
 * @param [in]      contextLen  Length of extra signing data
 * @return  0 on success.
 * @return  SIG_VERIFY_E when hint is malformed.
 * @return  BUFFER_E when the length of the signature does not match
 *          parameters.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
WOLFSSL_API int wc_mldsa_composite_verify_msg_ex(const byte* sig, word32 sigLen, const byte* msg,
    word32 msgLen, int* res, mldsa_composite_key* key, const byte* context, byte contextLen);

#endif /* !WOLFSSL_MLDSA_COMPOSITE_NO_VERIFY */

#ifndef WOLFSSL_DILITHIUM_VERIFY_ONLY
/* Sign a message with the key and a random number generator.
 *
 * @param [in]      in      Message data to sign
 * @param [in]      inLen   Length of the data to sign in bytes.
 * @param [out]     out     Buffer to hold signature.
 * @param [in, out] outLen  On in, length of buffer in bytes.
 *                          On out, the length of the signature in bytes.
 * @param [in]      key     ML-DSA composite key.
 * @param [in, out] rng     Random number generator.
 * @return  0 on success.
 * @return  BUFFER_E when the signature buffer is too small.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
WOLFSSL_API int wc_mldsa_composite_sign_msg(const byte* in, word32 inLen, byte* out,
    word32 *outLen, mldsa_composite_key* key, WC_RNG* rng);

/* Sign a message with the key and a random number generator.
 *
 * @param [in]      in      Message data to sign
 * @param [in]      inLen   Length of the data to sign in bytes.
 * @param [out]     out     Buffer to hold signature.
 * @param [in, out] outLen  On in, length of buffer in bytes.
 *                          On out, the length of the signature in bytes.
 * @param [in]      key     ML-DSA composite key.
 * @param [in, out] rng     Random number generator.
 * @param [in]      context  Extra signing data.
 * @param [in]      contextLen  Length of extra signing data
 * @return  0 on success.
 * @return  BUFFER_E when the signature buffer is too small.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
WOLFSSL_API int wc_mldsa_composite_sign_msg_ex(const byte* in, word32 inLen, byte* out,
    word32 *outLen, mldsa_composite_key* key, WC_RNG* rng,
    const byte* context, byte contextLen);

#endif

/* Initialize the MlDsaComposite private/public key.
 *
 * @param [in, out] key     ML-DSA composite key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL
 */
WOLFSSL_API int wc_mldsa_composite_init(mldsa_composite_key* key);

/* Initialize the MlDsaComposite private/public key.
 *
 * @param [in, out] key     ML-DSA composite key.
 * @param [in]      heap    Heap hint.
 * @param [in]      devId   Device ID.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL
 */
WOLFSSL_API int wc_mldsa_composite_init_ex(mldsa_composite_key* key, void* heap, int devId);

#ifdef WOLF_PRIVATE_KEY_ID
WOLFSSL_API
int wc_mldsa_composite_init_id(mldsa_composite_key* key, const unsigned char* id, int len,
    void* heap, int devId);
WOLFSSL_API
int wc_mldsa_composite_init_label(mldsa_composite_key* key, const char* label, void* heap,
    int devId);
#endif

/* Set the level of the MlDsaComposite private/public key.
 *
 * key   [out]  MlDsaComposite key.
 * level [in]   One of WC_MLDSA_COMPOSITE_TYPE_* values.
 * returns BAD_FUNC_ARG when key is NULL or level is a bad values.
 */
WOLFSSL_API int wc_mldsa_composite_set_type(mldsa_composite_key* key, byte type);

/* Get the level of the MlDsaComposite private/public key.
 *
 * key   [in]  MlDsaComposite key.
 * level [out] The level.
 * returns BAD_FUNC_ARG when key is NULL or level has not been set.
 */
WOLFSSL_API int wc_mldsa_composite_get_level(mldsa_composite_key* key, byte* type);

/* Clears the MlDsaComposite key data
 *
 * key  [in]  MlDsaComposite key.
 */
WOLFSSL_API void wc_mldsa_composite_free(mldsa_composite_key* key);

#ifdef WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY
/* Returns the size of a MlDsaComposite private key.
 *
 * @param [in] key  Dilithium private/public key.
 * @return  Private key size on success for set level.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
WOLFSSL_API int wc_mldsa_composite_size(mldsa_composite_key* key);
#endif

#if defined(WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY) && \
    defined(WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY)
/* Returns the size of a MlDsaComposite private plus public key.
 *
 * @param [in] key  MlDsaComposite private/public key.
 * @return  Private key size on success for set level.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
WOLFSSL_API int wc_mldsa_composite_priv_size(mldsa_composite_key* key);
#endif

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
/* Returns the size of a MlDsaComposite public key.
 *
 * @param [in] key  MlDsaComposite private/public key.
 * @return  Public key size on success for set level.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
WOLFSSL_API int wc_mldsa_composite_pub_size(mldsa_composite_key* key);
#endif

/* Returns the size of a MlDsaComposite public key.
 *
 * @param [in]  key  MlDsaComposite private/public key.
 * @param [out] len  Public key size for set level.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
WOLFSSL_API int wc_MlDsaCompositeKey_GetPubLen(MlDsaCompositeKey* key, int* len);

#if !defined(WOLFSSL_MLDSA_COMPOSITE_NO_SIGN) || !defined(WOLFSSL_MLDSA_COMPOSITE_NO_VERIFY)
/* Returns the size of a MlDsaComposite signature.
 *
 * @param [in] key  MlDsaComposite private/public key.
 * @return  Signature size on success for set level.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
WOLFSSL_API int wc_mldsa_composite_sig_size(mldsa_composite_key* key);
#endif

/* Returns the size of a MlDsaComposite signature.
 *
 * @param [in]  key  MlDsaComposite private/public key.
 * @param [out] len  Signature size for set level.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
WOLFSSL_API int wc_MlDsaCompositeKey_GetSigLen(MlDsaCompositeKey* key, int* len);

#ifdef WOLFSSL_MLDSA_COMPOSITE_CHECK_KEY
/* Check the public key of the MlDsaComposite key matches the private key.
 *
 * @param [in] key  MlDsaComposite private/public key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL or no private key available,
 * @return  PUBLIC_KEY_E when the public key is not set or doesn't match,
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
WOLFSSL_API int wc_mldsa_composite_check_key(mldsa_composite_key* key);
#endif

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
WOLFSSL_API int wc_mldsa_composite_import_public(const byte* in, word32 inLen,
    mldsa_composite_key* key, word32 type);

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
WOLFSSL_API int wc_mldsa_composite_export_public(mldsa_composite_key* key, byte* out, word32* outLen);
#endif /* WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY */

#ifdef WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY
/* Import a mldsa_composite private key from a byte array.
 *
 * @param [in]      priv    Array holding private key.
 * @param [in]      privSz  Number of bytes of data in array.
 * @param [in, out] key     mldsa_composite private key.
 * @return  0 otherwise.
 * @return  BAD_FUNC_ARG when a parameter is NULL or privSz is less than size
 *          required for level,
 */
WOLFSSL_API int wc_mldsa_composite_import_private(const byte* priv, word32 privSz,
    mldsa_composite_key* key, wc_MlDsaCompositeType type);

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
WOLFSSL_API int wc_mldsa_composite_export_private(mldsa_composite_key* key, byte* out, word32* outLen);

/* Define for import private only */
#define wc_mldsa_composite_import_private_only    wc_mldsa_composite_import_private

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
/* Import a mldsa_composite private and public keys from byte array(s).
 *
 * @param [in] priv    Array holding private key or private+public keys
 * @param [in] privSz  Number of bytes of data in private key array.
 * @param [in] pub     Array holding public key (or NULL).
 * @param [in] pubSz   Number of bytes of data in public key array (or 0).
 * @param [in] key     mldsa_composite private/public key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a required parameter is NULL an invalid
 *          combination of keys/lengths is supplied.
 */
WOLFSSL_API int wc_mldsa_composite_import_key(const byte* priv, word32 privSz,
    const byte* pub, word32 pubSz, mldsa_composite_key* key);

/* Export the mldsa_composite private and public key.
 *
 * @param [in]      key     mldsa_composite private/public key.
 * @param [out]     priv    Array to hold private key.
 * @param [in, out] privSz  On in, the number of bytes in private key array.
 *                          On out, the number bytes put into private key.
 * @param [out]     pub     Array to hold  public key.
 * @param [in, out] pubSz   On in, the number of bytes in public key array.
 *                          On out, the number bytes put into public key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a key, priv, privSz, pub or pubSz is NULL.
 * @return  BUFFER_E when privSz or pubSz is less than required size.
 */
WOLFSSL_API int wc_mldsa_composite_export_key(mldsa_composite_key* key, byte* priv, word32 *privSz,
    byte* pub, word32 *pubSz);

#endif /* WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY */
#endif /* WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY */

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_ASN1
#if defined(WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY)
/* Decode the DER encoded mldsa_composite key.
 *
 * @param [in]      input     Array holding DER encoded data.
 * @param [in, out] inOutIdx  On in, index into array of start of DER encoding.
 *                            On out, index into array after DER encoding.
 * @param [in, out] key       mldsa_composite key to store key.
 * @param [in]      inSz      Total size of data in array.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when input, inOutIdx or key is NULL or inSz is 0.
 * @return  BAD_FUNC_ARG when level not set.
 * @return  Other negative on parse error.
 */
WOLFSSL_API int wc_MlDsaComposite_PrivateKeyDecode(const byte* input,
    word32* inOutIdx, mldsa_composite_key* key, word32 inSz);
#endif /* WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY */
#endif /* WOLFSSL_MLDSA_COMPOSITE_NO_ASN1 */

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
/* Decode the DER encoded mldsa_composite public key.
 *
 * @param [in]      input     Array holding DER encoded data.
 * @param [in, out] inOutIdx  On in, index into array of start of DER encoding.
 *                            On out, index into array after DER encoding.
 * @param [in, out] key       mldsa_composite key to store key.
 * @param [in]      inSz      Total size of data in array.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when input, inOutIdx or key is NULL or inSz is 0.
 * @return  BAD_FUNC_ARG when level not set.
 * @return  Other negative on parse error.
 */
WOLFSSL_API int wc_MlDsaComposite_PublicKeyDecode(const byte* input,
    word32* inOutIdx, mldsa_composite_key* key, word32 inSz);
#endif /* WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY */

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_ASN1
#ifdef WC_ENABLE_ASYM_KEY_EXPORT
/* Encode the public part of a mldsa_composite key in DER.
 *
 * Pass NULL for output to get the size of the encoding.
 *
 * @param [in]  key      mldsa_composite key object.
 * @param [out] output   Buffer to put encoded data in.
 * @param [in]  len      Size of buffer in bytes.
 * @param [in]  withAlg  Whether to use SubjectPublicKeyInfo format.
 * @return  Size of encoded data in bytes on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
WOLFSSL_API int wc_MlDsaComposite_PublicKeyToDer(mldsa_composite_key* key, byte* output,
    word32 inLen, int withAlg);
#endif /* WC_ENABLE_ASYM_KEY_EXPORT */

#ifdef WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY
/* Encode the private data of a mldsa_composite key in DER.
 *
 * Pass NULL for output to get the size of the encoding.
 *
 * @param [in]  key     mldsa_composite key object.
 * @param [out] output  Buffer to put encoded data in.
 * @param [in]  len     Size of buffer in bytes.
 * @return  Size of encoded data in bytes on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
WOLFSSL_API int wc_MlDsaComposite_PrivateKeyToDer(mldsa_composite_key* key, byte* output,
    word32 inLen);

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
/* Encode the private and public data of a mldsa_composite key in DER.
 *
 * Pass NULL for output to get the size of the encoding.
 *
 * @param [in]  key     mldsa_composite key object.
 * @param [out] output  Buffer to put encoded data in.
 * @param [in]  len     Size of buffer in bytes.
 * @return  Size of encoded data in bytes on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
WOLFSSL_API int wc_MlDsaComposite_KeyToDer(mldsa_composite_key* key, byte* output,
    word32 inLen);
#endif /* WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY */
#endif /* WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY */
#endif /* !WOLFSSL_MLDSA_COMPOSITE_NO_ASN1 */

#define MlDsaCompositeKey  dilithium_key


#define wc_MlDsaCompositeKey_Init(key, heap, devId)                      \
    wc_mldsa_composite_init_ex(key, heap, devId)
#define wc_MlDsaCompositeKey_SetParams(key, id)                          \
    wc_mldsa_composite_set_level(key, id)
#define wc_MlDsaCompositeKey_GetParams(key, id)                          \
    wc_mldsa_composite_get_level(key, id)
#define wc_MlDsaCompositeKey_MakeKey(key, rng)                           \
    wc_mldsa_composite_make_key(key, rng)
#define wc_MlDsaCompositeKey_Sign(key, sig, sigSz, msg, msgSz, rng)      \
    wc_mldsa_composite_sign_msg(msg, msgSz, sig, sigSz, key, rng)
#define wc_MlDsaCompositeKey_Free(key)                                   \
    wc_mldsa_composite_free(key)
#define wc_MlDsaCompositeKey_ExportPubRaw(key, out, outLen)              \
    wc_mldsa_composite_export_public(key, out, outLen)
#define wc_MlDsaCompositeKey_ImportPubRaw(key, in, inLen)                \
    wc_mldsa_composite_import_public(out, outLen, key)
#define wc_MlDsaCompositeKey_Verify(key, sig, sigSz, msg, msgSz, res)    \
    wc_mldsa_composite_verify_msg(sig, sigSz, msg, msgSz, res, key)

int wc_MlDsaCompositeKey_GetPrivLen(MlDsaCompositeKey* key, int* len);

#ifdef __cplusplus
    }    /* extern "C" */
#endif

#endif /* HAVE_MLDSA_COMPOSITE */
#endif /* WOLF_CRYPT_MLDSA_COMPOSITE_H */
