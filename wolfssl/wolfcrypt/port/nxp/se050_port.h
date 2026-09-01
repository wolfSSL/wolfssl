/* se050_port.h
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

#ifndef _SE050_PORT_H_
#define _SE050_PORT_H_

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/visibility.h>
#include <wolfssl/wolfcrypt/types.h> /* for MATH_INT_T */

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wundef"
#pragma GCC diagnostic ignored "-Wredundant-decls"
#endif

#include "fsl_sss_se05x_types.h"
#include "fsl_sss_se05x_apis.h"
#include "se05x_APDU.h"

#if (SSS_HAVE_SSS > 1)
#include "fsl_sss_api.h"
#endif

#if defined(WOLFSSL_SE050) && defined(WOLFSSL_SE050_HASH)
    /* NXP SE050 - Disable SHA512 224/256 support */
    #ifndef WOLFSSL_NOSHA512_224
    #define WOLFSSL_NOSHA512_224
    #endif
    #ifndef WOLFSSL_NOSHA512_256
    #define WOLFSSL_NOSHA512_256
    #endif
#endif

#undef  WOLFSSL_NO_HASH_RAW
#define WOLFSSL_NO_HASH_RAW

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

#ifdef __cplusplus
    extern "C" {
#endif

/* Default key ID's */
#ifndef SE050_KEYSTOREID_AES
#define SE050_KEYSTOREID_AES     55
#endif
#ifndef SE050_KEYSTOREID_ED25519
#define SE050_KEYSTOREID_ED25519 58
#endif
#ifndef SE050_KEYSTOREID_CURVE25519
#define SE050_KEYSTOREID_CURVE25519 59
#endif
#ifndef SE050_KEYSTOREID_ECC
#define SE050_KEYSTOREID_ECC     60
#endif
#ifndef SE050_KEYSTOREID_RSA
#define SE050_KEYSTOREID_RSA     61
#endif
#ifndef SE050_KEYSTOREID_GENERIC
#define SE050_KEYSTOREID_GENERIC 62
#endif

/* old public API was renamed to add wc_ */
#define se050_ecc_insert_private_key wc_se050_ecc_insert_private_key

enum {
    SSS_BLOCK_SIZE   = 512,
    SSS_MAX_ECC_BITS = 521
};

enum SE050KeyType {
    SE050_ANY_KEY,
    SE050_AES_KEY,
    SE050_ECC_KEY,
    SE050_RSA_KEY,
    SE050_ED25519_KEY,
    SE050_CURVE25519_KEY
};

/* SE05x secure object permissions. Attaching any policy makes the applet
 * default-deny all permissions that are not explicitly granted. A value of
 * zero preserves the applet default policy by attaching no policy. */
#define WC_SE050_POLICY_ALLOW_DELETE        0x00000001U
#define WC_SE050_POLICY_ALLOW_WRITE         0x00000002U
#define WC_SE050_POLICY_ALLOW_READ          0x00000004U
#define WC_SE050_POLICY_ALLOW_SIGN          0x00000008U
#define WC_SE050_POLICY_ALLOW_VERIFY        0x00000010U
#define WC_SE050_POLICY_ALLOW_ENCRYPT       0x00000020U
#define WC_SE050_POLICY_ALLOW_DECRYPT       0x00000040U
#define WC_SE050_POLICY_ALLOW_KA            0x00000080U
#define WC_SE050_POLICY_ALLOW_KD            0x00000100U
#define WC_SE050_POLICY_ALLOW_GEN           0x00000200U
#define WC_SE050_POLICY_ALLOW_IMPORT_EXPORT 0x00000400U
#define WC_SE050_POLICY_ALLOW_ATTEST        0x00000800U
#define WC_SE050_POLICY_REQUIRE_SM          0x00001000U

/* Platform SCP03 uses one 128-bit ENC, MAC and data-encryption key. */
typedef struct wc_se050_scp03_keys {
    byte enc[16];
    byte mac[16];
    byte dek[16];
} wc_se050_scp03_keys;

#ifndef WC_SE050_ATTEST_VALUE_MAX
#define WC_SE050_ATTEST_VALUE_MAX 1024U
#endif

#ifndef WOLFSSL_SE050_NO_ATTEST
/* Result of an attested object read. The public object value is returned in
 * the same DER form as sss_key_store_get_key(). cipherType, objectType and
 * curveId describe the object and are used by the host verifier to recover
 * the exact applet response value. */
typedef struct wc_se050_attst_result {
    byte value[WC_SE050_ATTEST_VALUE_MAX];
    word32 valueSz;
    byte freshness[16];
    byte origin;
    word32 authObjId;
    word32 policyFlags;
    word32 cipherType;
    word32 objectType;
    word32 curveId;
    enum wc_HashType hashAlgo;
    sss_se05x_attst_data_t raw;
} wc_se050_attst_result;
#endif


#ifdef WOLFSSL_SE050_HASH
typedef struct {
    void*  heap;
    byte*  msg;
    word32 used;
    word32 len;
} SE050_HASH_Context;
#endif

/* Public Functions */
WOLFSSL_API int wc_se050_set_config(sss_session_t *pSession,
    sss_key_store_t *pHostKeyStore, sss_key_store_t *pKeyStore);
/** Return the configured SSS session and keystores. Output pointers may be
 * NULL. Direct middleware use must be bracketed by wc_se050_lock/unlock. */
WOLFSSL_API int wc_se050_get_config(sss_session_t **pSession,
    sss_key_store_t **pHostKeyStore, sss_key_store_t **pKeyStore);
/** Return the SSS session currently used by the wolfCrypt SE05x port. */
WOLFSSL_API sss_session_t* wc_se050_get_session(void);
/** Return the low-level SE05x session, or NULL when none is configured. */
WOLFSSL_API pSe05xSession_t wc_se050_get_se05x_session(void);
/** Acquire/release the shared wolfCrypt hardware transport lock. */
WOLFSSL_API int wc_se050_lock(void);
WOLFSSL_API void wc_se050_unlock(void);
#ifdef WOLFSSL_SE050_INIT
WOLFSSL_API int wc_se050_init(const char* portName);
/** Close a session opened by wc_se050_init() or wc_se050_init_ex(). */
WOLFSSL_API int wc_se050_close(void);
#if defined(SSS_HAVE_HOSTCRYPTO_ANY) && SSS_HAVE_HOSTCRYPTO_ANY && \
    defined(SSS_HAVE_SCP_SCP03_SSS) && SSS_HAVE_SCP_SCP03_SSS && \
    defined(SSS_HAVE_SE05X_AUTH_PLATFSCP03) && \
        SSS_HAVE_SE05X_AUTH_PLATFSCP03
/** Open Platform SCP03 using caller-supplied 128-bit ENC/MAC/DEK keys. */
WOLFSSL_API int wc_se050_init_ex(const char* portName,
    const wc_se050_scp03_keys* keys);
#endif
#endif

#ifdef HAVE_HKDF
/** Deterministically derive the Platform SCP03 ENC, MAC and DEK keys from a
 * seed. No SE05x session is required, so this can be called before
 * wolfCrypt_Init() to recover keys after a power cycle. */
WOLFSSL_API int wc_se050_scp03_derive_keys_seed(const byte* seed,
    word32 seedSz, wc_se050_scp03_keys* derivedOut);
#endif

#if defined(WOLFSSL_SE050_SCP03_ROTATE) && \
    defined(WOLFSSL_SE050_INIT) && \
    defined(SSS_HAVE_HOSTCRYPTO_ANY) && SSS_HAVE_HOSTCRYPTO_ANY && \
    defined(SSS_HAVE_SCP_SCP03_SSS) && SSS_HAVE_SCP_SCP03_SSS && \
    defined(SSS_HAVE_SE05X_AUTH_PLATFSCP03) && \
        SSS_HAVE_SE05X_AUTH_PLATFSCP03
/** Destructively replace the Platform SCP03 key set using secured PUT KEY.
 * The port temporarily authenticates to the Security Domain, then returns
 * with a fresh IoT applet session authenticated by newKeys. */
WOLFSSL_API int wc_se050_scp03_rotate_keys(
    const wc_se050_scp03_keys* newKeys, byte keyVersion);
#ifdef HAVE_HKDF
/** Derive three keys with the documented HKDF-SHA256 construction and rotate.
 * Persist the seed before calling. derivedOut may be NULL. */
WOLFSSL_API int wc_se050_scp03_rotate_keys_seed(const byte* seed,
    word32 seedSz, byte keyVersion, wc_se050_scp03_keys* derivedOut);
#endif
#endif
WOLFSSL_API int wc_se050_erase_object(word32 keyId);

WOLFSSL_API int wc_se050_ecc_insert_public_key(word32 keyId,
    const byte* eccDer, word32 eccDerSize);
WOLFSSL_API int wc_se050_ecc_insert_private_key(word32 keyId,
    const byte* eccDer, word32 eccDerSize);
/** Insert an ECC public/private key with a flag-based immutable policy. */
WOLFSSL_API int wc_se050_ecc_insert_public_key_ex(word32 keyId,
    const byte* eccDer, word32 eccDerSize, word32 policyFlags,
    word32 authObjId);
WOLFSSL_API int wc_se050_ecc_insert_private_key_ex(word32 keyId,
    const byte* eccDer, word32 eccDerSize, word32 policyFlags,
    word32 authObjId);
WOLFSSL_API int wc_se050_ecc_insert_public_key_policy(word32 keyId,
    const byte* eccDer, word32 eccDerSize, const sss_policy_t* policy);
WOLFSSL_API int wc_se050_ecc_insert_private_key_policy(word32 keyId,
    const byte* eccDer, word32 eccDerSize, const sss_policy_t* policy);
#ifdef HAVE_ECC
/** Generate a persistent ECC key pair at a caller-selected, unused ID with a
 * flag-based immutable policy. keySize is in bytes. */
WOLFSSL_API int wc_se050_ecc_generate_key_ex(word32 keyId, int keySize,
    int curveId, word32 policyFlags, word32 authObjId);
/** Generate a persistent ECC key pair with a raw middleware policy. */
WOLFSSL_API int wc_se050_ecc_generate_key_policy(word32 keyId, int keySize,
    int curveId, const sss_policy_t* policy);
#endif

WOLFSSL_API int wc_se050_rsa_insert_public_key(word32 keyId,
    const byte* rsaDer, word32 rsaDerSize);
WOLFSSL_API int wc_se050_rsa_insert_private_key(word32 keyId,
    const byte* rsaDer, word32 rsaDerSize);
/** Insert an RSA public/private key with a flag-based immutable policy. */
WOLFSSL_API int wc_se050_rsa_insert_public_key_ex(word32 keyId,
    const byte* rsaDer, word32 rsaDerSize, word32 policyFlags,
    word32 authObjId);
WOLFSSL_API int wc_se050_rsa_insert_private_key_ex(word32 keyId,
    const byte* rsaDer, word32 rsaDerSize, word32 policyFlags,
    word32 authObjId);
WOLFSSL_API int wc_se050_rsa_insert_public_key_policy(word32 keyId,
    const byte* rsaDer, word32 rsaDerSize, const sss_policy_t* policy);
WOLFSSL_API int wc_se050_rsa_insert_private_key_policy(word32 keyId,
    const byte* rsaDer, word32 rsaDerSize, const sss_policy_t* policy);
#if !defined(NO_RSA) && !defined(WOLFSSL_SE050_NO_RSA)
/** Generate a persistent RSA key pair at a caller-selected, unused ID with a
 * flag-based immutable policy. size is in bits and e must be 65537. */
WOLFSSL_API int wc_se050_rsa_generate_key_ex(word32 keyId, int size, long e,
    word32 policyFlags, word32 authObjId);
/** Generate a persistent RSA key pair with a raw middleware policy. */
WOLFSSL_API int wc_se050_rsa_generate_key_policy(word32 keyId, int size,
    long e, const sss_policy_t* policy);
#endif

WOLFSSL_API int wc_se050_insert_binary_object(word32 keyId,
    const byte* object, word32 objectSz);
/** Insert a binary object with a flag-based immutable policy. */
WOLFSSL_API int wc_se050_insert_binary_object_ex(word32 keyId,
    const byte* object, word32 objectSz, word32 policyFlags,
    word32 authObjId);
WOLFSSL_API int wc_se050_insert_binary_object_policy(word32 keyId,
    const byte* object, word32 objectSz, const sss_policy_t* policy);
WOLFSSL_API int wc_se050_get_binary_object(word32 keyId,
    byte* out, word32* outSz);
/** Read raw object attributes, including policy records and origin. */
WOLFSSL_API int wc_se050_get_object_attributes(word32 keyId, byte* attr,
    word32* attrSz);

#ifndef WOLFSSL_SE050_NO_ATTEST
/** Read and attest an object. Freshness must be 16 bytes or NULL. */
WOLFSSL_API int wc_se050_attest_object(word32 keyId, word32 attestKeyId,
    enum wc_HashType hashAlgo, const byte* random, word32 randomSz,
    wc_se050_attst_result* result);
/** Verify all returned attestation components with an ECC/RSA public key and
 * require the independently retained 16-byte freshness challenge. */
WOLFSSL_API int wc_se050_verify_attestation(
    const wc_se050_attst_result* result, const byte* attestPubDer,
    word32 attestPubDerSz, const byte* expectedRandom,
    word32 expectedRandomSz, int* res);
/** Attest a key, verify the signature, and compare its public-key DER. */
WOLFSSL_API int wc_se050_validate_provisioned_key(word32 keyId,
    word32 attestKeyId, const byte* expectedPubDer, word32 expectedPubDerSz,
    const byte* attestPubDer, word32 attestPubDerSz, int* res);
#endif

/* Private Functions */
WOLFSSL_LOCAL word32 se050_allocate_key(int keyType);
#if !defined(WC_NO_RNG) && !defined(WOLFSSL_SE050_NO_TRNG)
WOLFSSL_LOCAL int se050_get_random_number(uint32_t count, uint8_t* rand_out);
#endif

#ifdef WOLFSSL_SE050_HASH
WOLFSSL_LOCAL int se050_hash_init(SE050_HASH_Context* se050Ctx, void* heap);
WOLFSSL_LOCAL int se050_hash_update(SE050_HASH_Context* se050Ctx,
    const byte* data, word32 len);
WOLFSSL_LOCAL int se050_hash_final(SE050_HASH_Context* se050Ctx, byte* hash,
    size_t digestLen, sss_algorithm_t algo);
WOLFSSL_LOCAL int se050_hash_copy(SE050_HASH_Context* src,
    SE050_HASH_Context* dst);
WOLFSSL_LOCAL void se050_hash_free(SE050_HASH_Context* se050Ctx);
#endif

#if defined(WOLFSSL_SE050_CRYPT) && !defined(NO_AES)
struct Aes;
WOLFSSL_LOCAL int se050_aes_free_key_store_object(struct Aes* aes);
WOLFSSL_LOCAL int se050_aes_set_key(struct Aes* aes, const byte* key,
    word32 len, const byte* iv, int dir);
WOLFSSL_LOCAL int se050_aes_crypt(struct Aes* aes, const byte* in, byte* out,
    word32 sz, int dir, sss_algorithm_t algorithm);
WOLFSSL_LOCAL void se050_aes_free(struct Aes* aes);
#endif

struct WC_RNG;
struct ecc_key;

#ifdef HAVE_ECC
WOLFSSL_LOCAL int se050_ecc_use_key_id(struct ecc_key* key, word32 keyId);
WOLFSSL_LOCAL int se050_ecc_get_key_id(struct ecc_key* key, word32* keyId);
WOLFSSL_LOCAL int se050_ecc_sign_hash_ex(const byte* in, word32 inLen,
    MATH_INT_T* r, MATH_INT_T* s, byte* out, word32 *outLen, struct ecc_key* key);

WOLFSSL_LOCAL int se050_ecc_verify_hash_ex(const byte* hash, word32 hashlen,
    MATH_INT_T* r, MATH_INT_T* s, struct ecc_key* key, int* res);

WOLFSSL_LOCAL int se050_ecc_create_key(struct ecc_key* key, int curve_id,
    int keySize);
WOLFSSL_LOCAL int se050_ecc_shared_secret(struct ecc_key* private_key,
    struct ecc_key* public_key, byte* out, word32* outlen);
WOLFSSL_LOCAL void se050_ecc_free_key(struct ecc_key* key);
#endif /* HAVE_ECC */

#ifndef NO_RSA
struct RsaKey;
WOLFSSL_LOCAL int se050_rsa_use_key_id(struct RsaKey* key, word32 keyId);
WOLFSSL_LOCAL int se050_rsa_get_key_id(struct RsaKey* key, word32* keyId);
WOLFSSL_LOCAL int se050_rsa_create_key(struct RsaKey* key, int size, long e);
WOLFSSL_LOCAL void se050_rsa_free_key(struct RsaKey* key);
WOLFSSL_LOCAL int se050_rsa_sign(const byte* in, word32 inLen, byte* out,
    word32 outLen, struct RsaKey* key, int rsa_type, byte pad_value,
    int pad_type, enum wc_HashType hash, int mgf, byte* label, word32 labelSz,
    int keySz);
WOLFSSL_LOCAL int se050_rsa_verify(const byte* in, word32 inLen, byte* out,
    word32 outLen, struct RsaKey* key, int rsa_type, byte pad_value,
    int pad_type, enum wc_HashType hash, int mgf, byte* label, word32 labelSz);
WOLFSSL_LOCAL int se050_rsa_public_encrypt(const byte* in, word32 inLen,
    byte* out, word32 outLen, struct RsaKey* key, int rsa_type, byte pad_value,
    int pad_type, enum wc_HashType hash, int mgf, byte* label,
    word32 labelSz, int keySz);
WOLFSSL_LOCAL int se050_rsa_private_decrypt(const byte* in, word32 inLen,
    byte* out, word32 outLen, struct RsaKey* key, int rsa_type, byte pad_value,
    int pad_type, enum wc_HashType hash, int mgf, byte* label, word32 labelSz);
#endif

#ifdef HAVE_ED25519
struct ed25519_key;
WOLFSSL_LOCAL int se050_ed25519_create_key(struct ed25519_key* key);
WOLFSSL_LOCAL void se050_ed25519_free_key(struct ed25519_key* key);
WOLFSSL_LOCAL int se050_ed25519_sign_msg(const byte* in, word32 inLen,
    byte* out, word32 *outLen, struct ed25519_key* key);
WOLFSSL_LOCAL int se050_ed25519_verify_msg(const byte* signature,
    word32 signatureLen, const byte* msg, word32 msgLen,
    struct ed25519_key* key, int* res);
#endif /* HAVE_ED25519 */

#ifdef HAVE_CURVE25519
struct curve25519_key;
struct ECPoint;
WOLFSSL_LOCAL int se050_curve25519_create_key(struct curve25519_key* key,
    int keySize);
WOLFSSL_LOCAL int se050_curve25519_shared_secret(
    struct curve25519_key* private_key, struct curve25519_key* public_key,
    struct ECPoint* out);
WOLFSSL_LOCAL void se050_curve25519_free_key(struct curve25519_key* key);
#endif /* HAVE_CURVE25519 */

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* _SE050_PORT_H_ */
