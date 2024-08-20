/* mldsa_composite.h
 */

/*!
    \file wolfssl/wolfcrypt/mldsa_composite.h
*/

/* Interfaces for Composite Signatures */

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

#define MLDSA44_P256_KEY_SIZE       DILITHIUM_ML_DSA_44_KEY_SIZE + P256_KEY_SIZE
#define MLDSA44_P256_SIG_SIZE       DILITHIUM_ML_DSA_44_KEY_SIZE + P256_SIG_SIZE
#define MLDSA44_P256_PUB_KEY_SIZE   1312 + P256_PUB_KEY_SIZE
#define MLDSA44_P256_PRV_KEY_SIZE   \
    (MLDSA44_P256_PUB_KEY_SIZE + MLDSA44_P256_KEY_SIZE)

#define MLDSA44_ED25519_KEY_SIZE       DILITHIUM_ML_DSA_44_KEY_SIZE + ED25519_KEY_SIZE
#define MLDSA44_ED25519_SIG_SIZE       DILITHIUM_ML_DSA_44_KEY_SIZE + ED25519_SIG_SIZE
#define MLDSA44_ED25519_PUB_KEY_SIZE   DILITHIUM_ML_DSA_44_KEY_SIZE + ED25519_PUB_KEY_SIZE
#define MLDSA44_ED25519_PRV_KEY_SIZE   \
    (MLDSA44_ED25519_PUB_KEY_SIZE + MLDSA44_ED25519_KEY_SIZE)

#define MLDSA_COMPOSITE_MAX_KEY_SIZE     DILITHIUM_LEVEL5_KEY_SIZE + P256_KEY_SIZE
#define MLDSA_COMPOSITE_MAX_SIG_SIZE     DILITHIUM_LEVEL5_SIG_SIZE + P256_SIG_SIZE
#define MLDSA_COMPOSITE_MAX_PUB_KEY_SIZE DILITHIUM_LEVEL5_PUB_KEY_SIZE + P256_PUB_KEY_SIZE
#define MLDSA_COMPOSITE_MAX_PRV_KEY_SIZE DILITHIUM_LEVEL5_PRV_KEY_SIZE + P256_PRV_KEY_SIZE

#ifdef WOLF_PRIVATE_KEY_ID
#define MLDSA_COMPOSITE_MAX_ID_LEN    32
#define MLDSA_COMPOSITE_MAX_LABEL_LEN 32
#endif

#endif /* WOLFSSL_WC_MLDSA_COMPOSITE */

/* Structs */

#ifdef WOLFSSL_WC_MLDSA_COMPOSITE

typedef struct wc_composite_key_params {
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
} wc_CompositeKeyParams;


#endif

struct mldsa_composite_key {
    const enum wc_PkType algo; /* RSAPSSk */
    const enum wc_HashType hashParam; /* hSHA256 */
    wc_CompositeKeyParams params[2];
    dilithium_key * mldsa_key;
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

#ifndef WOLFSSL_DILITHIUM_VERIFY_ONLY
WOLFSSL_API
int wc_mldsa_composite_make_key(mldsa_composite_key* key, WC_RNG* rng);
WOLFSSL_API
int wc_mldsa_composite_make_key_from_seed(mldsa_composite_key* key, const byte* seed);

WOLFSSL_API
int wc_mldsa_composite_sign_msg(const byte* in, word32 inLen, byte* out,
    word32 *outLen, mldsa_composite_key* key, WC_RNG* rng);
WOLFSSL_API
int wc_mldsa_composite_sign_msg_with_seed(const byte* in, word32 inLen, byte* out,
    word32 *outLen, mldsa_composite_key* key, byte* seed);
#endif
WOLFSSL_API
int wc_mldsa_composite_verify_msg(const byte* sig, word32 sigLen, const byte* msg,
    word32 msgLen, int* res, mldsa_composite_key* key);

WOLFSSL_API
int wc_mldsa_composite_init(mldsa_composite_key* key);

WOLFSSL_API
int wc_mldsa_composite_init_ex(mldsa_composite_key* key, void* heap, int devId);

#ifdef WOLF_PRIVATE_KEY_ID
WOLFSSL_API
int wc_mldsa_composite_init_id(mldsa_composite_key* key, const unsigned char* id, int len,
    void* heap, int devId);
WOLFSSL_API
int wc_mldsa_composite_init_label(mldsa_composite_key* key, const char* label, void* heap,
    int devId);
#endif

WOLFSSL_API
int wc_mldsa_composite_set_level(mldsa_composite_key* key, byte level);
WOLFSSL_API
int wc_mldsa_composite_get_level(mldsa_composite_key* key, byte* level);
WOLFSSL_API
void wc_mldsa_composite_free(mldsa_composite_key* key);

#ifdef WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY
WOLFSSL_API
int wc_mldsa_composite_size(mldsa_composite_key* key);
#endif
#if defined(WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY) && \
    defined(WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY)
WOLFSSL_API
int wc_mldsa_composite_priv_size(mldsa_composite_key* key);
#endif
#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
WOLFSSL_API
int wc_mldsa_composite_pub_size(mldsa_composite_key* key);
#endif
#if !defined(WOLFSSL_MLDSA_COMPOSITE_NO_SIGN) || !defined(WOLFSSL_MLDSA_COMPOSITE_NO_VERIFY)
WOLFSSL_API
int wc_mldsa_composite_sig_size(mldsa_composite_key* key);
#endif

#ifdef WOLFSSL_MLDSA_COMPOSITE_CHECK_KEY
WOLFSSL_API
int wc_mldsa_composite_check_key(mldsa_composite_key* key);
#endif

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
WOLFSSL_API
int wc_mldsa_composite_import_public(const byte* in, word32 inLen,
    mldsa_composite_key* key);
#endif
#ifdef WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY
WOLFSSL_API
int wc_mldsa_composite_import_private(const byte* priv, word32 privSz,
    mldsa_composite_key* key);
#define wc_mldsa_composite_import_private_only    wc_mldsa_composite_import_private
WOLFSSL_API
int wc_mldsa_composite_import_key(const byte* priv, word32 privSz,
    const byte* pub, word32 pubSz, mldsa_composite_key* key);
#endif

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
WOLFSSL_API
int wc_mldsa_composite_export_public(mldsa_composite_key* key, byte* out, word32* outLen);
#endif
#ifdef WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY
WOLFSSL_API
int wc_mldsa_composite_export_private(mldsa_composite_key* key, byte* out, word32* outLen);
#endif
#ifdef WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY
WOLFSSL_API
int wc_mldsa_composite_export_key(mldsa_composite_key* key, byte* priv, word32 *privSz,
    byte* pub, word32 *pubSz);
#endif

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_ASN1
#if defined(WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY)
WOLFSSL_API int wc_MlDsaComposite_PrivateKeyDecode(const byte* input,
    word32* inOutIdx, mldsa_composite_key* key, word32 inSz);
#endif
#endif /* WOLFSSL_MLDSA_COMPOSITE_NO_ASN1 */
#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
WOLFSSL_API int wc_MlDsaComposite_PublicKeyDecode(const byte* input,
    word32* inOutIdx, mldsa_composite_key* key, word32 inSz);
#endif

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_ASN1
#ifdef WC_ENABLE_ASYM_KEY_EXPORT
WOLFSSL_API int wc_MlDsaComposite_PublicKeyToDer(mldsa_composite_key* key, byte* output,
    word32 inLen, int withAlg);
#endif
#if defined(WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY)
WOLFSSL_API int wc_MlDsaComposite_KeyToDer(mldsa_composite_key* key, byte* output,
    word32 inLen);
#endif
#ifdef WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY
WOLFSSL_API int wc_MlDsaComposite_PrivateKeyToDer(mldsa_composite_key* key, byte* output,
    word32 inLen);
#endif
#endif /* WOLFSSL_MLDSA_COMPOSITE_NO_ASN1 */

#define WC_MLDSA44_P256         1
#define WC_MLDSA44_ED25519      2

int wc_MlDsaCompositeKey_GetPrivLen(MlDsaCompositeKey* key, int* len);
int wc_MlDsaCompositeKey_GetPubLen(MlDsaCompositeKey* key, int* len);
int wc_MlDsaCompositeKey_GetSigLen(MlDsaCompositeKey* key, int* len);

#ifdef __cplusplus
    }    /* extern "C" */
#endif

#endif /* HAVE_MLDSA_COMPOSITE */
#endif /* WOLF_CRYPT_MLDSA_COMPOSITE_H */
