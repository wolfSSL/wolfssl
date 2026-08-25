/* silabs_shim.h
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

/* Host compile-test stand-in for the slice of the Silicon Labs SE Manager that
 * the wolfcrypt/src/port/silabs/ sources reference. Compiled ONLY under
 * WOLFSSL_SILABS_HOST_TEST. It lets the port's dispatch, field access and
 * compile-time guards be built on a host with no Simplicity SDK installed, so
 * CI catches breakage in this port.
 *
 * Every stub returns SL_STATUS_NOT_SUPPORTED and performs NO crypto, which the
 * port maps to CRYPTOCB_UNAVAILABLE so wolfCrypt falls back to software. That
 * makes the host build a compile gate that also exercises every engine's
 * decline-and-fall-back path -- AES, hash, ECC and TRNG correctness is
 * validated on EFR32 hardware against the wolfcrypt test known-answer
 * vectors, never through these stubs. On target this header is NOT used:
 * the real SE Manager headers are included instead, supplied via the
 * application include path.
 *
 * The declarations here intentionally mirror the real SE Manager signatures
 * from Simplicity SDK platform/security/sl_component/se_manager/inc/. Keep this
 * in sync with the SE Manager calls in the port (add a stub here when the port
 * starts calling a new sl_se_* function).
 *
 * The device is modeled as Series 2 Config 5 (EFR32xG25) with Secure Vault
 * High, which is the configuration the port targets.
 */

#ifndef _WOLFPORT_SILABS_SHIM_H_
#define _WOLFPORT_SILABS_SHIM_H_

#ifdef WOLFSSL_SILABS_HOST_TEST

#include <stdint.h>
#include <stddef.h>

/* ---- Device identity (normally from em_device.h) ---- */
#ifndef SEMAILBOX_PRESENT
    #define SEMAILBOX_PRESENT 1
#endif
#define _SILICON_LABS_32B_SERIES                2
#define _SILICON_LABS_32B_SERIES_2              1
#define _SILICON_LABS_32B_SERIES_2_CONFIG       5
#define _SILICON_LABS_32B_SERIES_2_CONFIG_5     1
#define _SILICON_LABS_SECURITY_FEATURE_SE       0
#define _SILICON_LABS_SECURITY_FEATURE_VAULT    1
#define _SILICON_LABS_SECURITY_FEATURE_ROT      2
#define _SILICON_LABS_SECURITY_FEATURE_BASE     3
/* The shim models Secure Vault High by default. Define
 * WOLFSSL_SILABS_HOST_TEST_VAULT_MID to model a Vault Mid part instead, which
 * compile-tests that every Vault-only path (SHA-384/512, P-384/P-521,
 * ChaCha20-Poly1305, the SE KDFs and wrapped keys) drops out cleanly. */
#ifdef WOLFSSL_SILABS_HOST_TEST_VAULT_MID
    #define _SILICON_LABS_SECURITY_FEATURE _SILICON_LABS_SECURITY_FEATURE_SE
#else
    #define _SILICON_LABS_SECURITY_FEATURE _SILICON_LABS_SECURITY_FEATURE_VAULT
#endif

/* ---- Status codes (sl_status.h) ---- */
typedef uint32_t sl_status_t;
#define SL_STATUS_OK                    ((sl_status_t)0x0000)
#define SL_STATUS_FAIL                  ((sl_status_t)0x0001)
#define SL_STATUS_INVALID_PARAMETER     ((sl_status_t)0x0021)
#define SL_STATUS_NOT_SUPPORTED         ((sl_status_t)0x000F)
#define SL_STATUS_INVALID_SIGNATURE     ((sl_status_t)0x002C)

/* ---- Command context (sl_se_manager_types.h) ---- */
typedef struct {
    uint32_t opaque[4];
} sl_se_command_context_t;
#define SL_SE_COMMAND_CONTEXT_INIT { { 0, 0, 0, 0 } }

/* ---- Key descriptor (sl_se_manager_types.h) ---- */
typedef uint32_t sl_se_key_type_t;
typedef uint32_t sl_se_storage_method_t;

#define SL_SE_KEY_STORAGE_EXTERNAL_PLAINTEXT    ((sl_se_storage_method_t)0)
#define SL_SE_KEY_STORAGE_EXTERNAL_WRAPPED      ((sl_se_storage_method_t)1)
#define SL_SE_KEY_STORAGE_INTERNAL_VOLATILE     ((sl_se_storage_method_t)2)
#define SL_SE_KEY_STORAGE_INTERNAL_IMMUTABLE    ((sl_se_storage_method_t)3)

#define SL_SE_KEY_TYPE_SYMMETRIC        0x00000000
#define SL_SE_KEY_TYPE_AES_128          0x00000010
#define SL_SE_KEY_TYPE_AES_192          0x00000018
#define SL_SE_KEY_TYPE_AES_256          0x00000020
#define SL_SE_KEY_TYPE_ECC_P192         0x08000018
#define SL_SE_KEY_TYPE_ECC_P224         0x0800001C
#define SL_SE_KEY_TYPE_ECC_P256         0x08000020
#ifndef WOLFSSL_SILABS_HOST_TEST_VAULT_MID
    #define SL_SE_KEY_TYPE_ECC_P384     0x08000030
    #define SL_SE_KEY_TYPE_ECC_P521     0x08000042
#endif
#define SL_SE_KEY_TYPE_ECC_X25519       0x0b000020
#ifndef WOLFSSL_SILABS_HOST_TEST_VAULT_MID
    #define SL_SE_KEY_TYPE_ECC_X448     0x0b000038
#endif
#define SL_SE_KEY_TYPE_ECC_ED25519      0x0c000020
/* Secure Vault High only. */
#ifndef WOLFSSL_SILABS_HOST_TEST_VAULT_MID
    #define SL_SE_KEY_TYPE_CHACHA20     0x00000020
    #define SL_SE_KEY_TYPE_ECC_ED448    0x0c000038
#endif

#define SL_SE_KEY_FLAG_ASYMMETRIC_BUFFER_HAS_PRIVATE_KEY  (1UL << 12)
#define SL_SE_KEY_FLAG_ASYMMETRIC_BUFFER_HAS_PUBLIC_KEY   (1UL << 13)
#define SL_SE_KEY_FLAG_ASYMMETRIC_SIGNING_ONLY            (1UL << 14)
#define SL_SE_KEY_FLAG_NON_EXPORTABLE                     (1UL << 24)
#define SL_SE_KEY_FLAG_IS_DEVICE_GENERATED                (1UL << 25)

typedef struct {
    sl_se_key_type_t type;
    uint32_t         flags;
    uint32_t         size;
    struct {
        sl_se_storage_method_t method;
        union {
            struct {
                uint8_t* pointer;   /* matches sl_se_buffer_t in the SDK */
                uint32_t size;
            } buffer;
            uint32_t slot;
        } location;
    } storage;
} sl_se_key_descriptor_t;

/* ---- Key slots and wrapped-key sizing (sl_se_manager_defines.h) ---- */
#define SL_SE_KEY_SLOT_VOLATILE_0                   0x00
#define SL_SE_KEY_SLOT_VOLATILE_1                   0x01
#define SL_SE_KEY_SLOT_VOLATILE_2                   0x02
#define SL_SE_KEY_SLOT_VOLATILE_3                   0x03
#define SL_SE_KEY_SLOT_TRUSTZONE_ROOT_KEY           0xF7
#define SL_SE_KEY_SLOT_APPLICATION_SECURE_DEBUG_KEY 0xF8
#define SL_SE_KEY_SLOT_APPLICATION_AES_128_KEY      0xFA
#define SL_SE_KEY_SLOT_APPLICATION_SECURE_BOOT_KEY  0xFC
#define SL_SE_KEY_SLOT_APPLICATION_ATTESTATION_KEY  0xFE
#define SL_SE_KEY_SLOT_SE_ATTESTATION_KEY           0xFF

#define SLI_SE_WRAPPED_KEY_OVERHEAD  (12 + 16)

/* ---- Internal (built-in) keys (sl_se_manager_internal_keys.h) ---- */
#define SL_SE_APPLICATION_ATTESTATION_KEY { 0, 0, 0, { 0, { { NULL, 0 } } } }

/* ---- Cipher (sl_se_manager_cipher.h) ---- */
typedef enum {
    SL_SE_DECRYPT = 0,
    SL_SE_ENCRYPT = 1
} sl_se_cipher_operation_t;

/* ---- Hash (sl_se_manager_hash.h) ---- */
typedef enum {
    SL_SE_HASH_NONE = 0,
    SL_SE_HASH_SHA1,
    SL_SE_HASH_SHA224,
    SL_SE_HASH_SHA256,
    SL_SE_HASH_SHA384,
    SL_SE_HASH_SHA512
} sl_se_hash_type_t;

#define SLI_SE_SHIM_HASH_CTX(bits, blocksz)  \
    struct {                                 \
        uint32_t hash_type;                  \
        uint64_t total;                      \
        uint32_t state[(bits) / 32];         \
        uint8_t  buffer[blocksz];            \
    }

typedef SLI_SE_SHIM_HASH_CTX(160, 64)  sl_se_sha1_multipart_context_t;
typedef SLI_SE_SHIM_HASH_CTX(256, 64)  sl_se_sha224_multipart_context_t;
typedef SLI_SE_SHIM_HASH_CTX(256, 64)  sl_se_sha256_multipart_context_t;
typedef SLI_SE_SHIM_HASH_CTX(512, 128) sl_se_sha384_multipart_context_t;
typedef SLI_SE_SHIM_HASH_CTX(512, 128) sl_se_sha512_multipart_context_t;

/* Selects the SDK v4+ multipart hash interface in silabs_hash.h, matching the
 * SE major version two used by Series 2 Config 5. The SDK defines these PRF
 * identifiers as aliases of the hash enum. */
#define SL_SE_PRF_HMAC_SHA1     SL_SE_HASH_SHA1
#define SL_SE_PRF_HMAC_SHA224   SL_SE_HASH_SHA224
#define SL_SE_PRF_HMAC_SHA256   SL_SE_HASH_SHA256
#define SL_SE_PRF_HMAC_SHA384   SL_SE_HASH_SHA384
#define SL_SE_PRF_HMAC_SHA512   SL_SE_HASH_SHA512
typedef sl_se_hash_type_t sl_se_pbkdf2_prf_type_t;

/* ---- CMAC / CTR (sl_se_manager_cipher.h, sl_se_manager_config.h) ---- */
#define SL_SE_AES_BLOCK_SIZE                (16u)
#ifndef SLI_SE_AES_CTR_NUM_BLOCKS_BUFFERED
    #define SLI_SE_AES_CTR_NUM_BLOCKS_BUFFERED 1
#endif

typedef struct {
    uint8_t state[16];
    uint8_t data_in[16];
    uint8_t data_out[16];
    size_t  length;
} sl_se_cmac_multipart_context_t;

/* ---- Function stubs ---- */
static inline sl_status_t sl_se_init(void)
    { return SL_STATUS_OK; }
static inline sl_status_t sl_se_deinit(void)
    { return SL_STATUS_OK; }
static inline sl_status_t sl_se_init_command_context(
        sl_se_command_context_t* c)
    { (void)c; return SL_STATUS_OK; }

static inline sl_status_t sl_se_get_random(sl_se_command_context_t* c,
        void* out, uint32_t n)
    { (void)c; (void)out; (void)n; return SL_STATUS_NOT_SUPPORTED; }

static inline sl_status_t sl_se_aes_crypt_ecb(sl_se_command_context_t* c,
        const sl_se_key_descriptor_t* k, sl_se_cipher_operation_t op,
        size_t len, const unsigned char* in, unsigned char* out)
    { (void)c; (void)k; (void)op; (void)len; (void)in; (void)out;
      return SL_STATUS_NOT_SUPPORTED; }

static inline sl_status_t sl_se_aes_crypt_cbc(sl_se_command_context_t* c,
        const sl_se_key_descriptor_t* k, sl_se_cipher_operation_t op,
        size_t len, unsigned char* iv, const unsigned char* in,
        unsigned char* out)
    { (void)c; (void)k; (void)op; (void)len; (void)iv; (void)in; (void)out;
      return SL_STATUS_NOT_SUPPORTED; }

static inline sl_status_t sl_se_gcm_crypt_and_tag(
        sl_se_command_context_t* c, const sl_se_key_descriptor_t* k,
        sl_se_cipher_operation_t op, size_t len, const unsigned char* iv,
        size_t ivLen, const unsigned char* add, size_t addLen,
        const unsigned char* in, unsigned char* out, size_t tagLen,
        unsigned char* tag)
    { (void)c; (void)k; (void)op; (void)len; (void)iv; (void)ivLen;
      (void)add; (void)addLen; (void)in; (void)out; (void)tagLen; (void)tag;
      return SL_STATUS_NOT_SUPPORTED; }

static inline sl_status_t sl_se_gcm_auth_decrypt(
        sl_se_command_context_t* c, const sl_se_key_descriptor_t* k,
        size_t len, const unsigned char* iv, size_t ivLen,
        const unsigned char* add, size_t addLen, const unsigned char* in,
        unsigned char* out, size_t tagLen, const unsigned char* tag)
    { (void)c; (void)k; (void)len; (void)iv; (void)ivLen; (void)add;
      (void)addLen; (void)in; (void)out; (void)tagLen; (void)tag;
      return SL_STATUS_NOT_SUPPORTED; }

static inline sl_status_t sl_se_ccm_encrypt_and_tag(
        sl_se_command_context_t* c, const sl_se_key_descriptor_t* k,
        size_t len, const unsigned char* iv, size_t ivLen,
        const unsigned char* add, size_t addLen, const unsigned char* in,
        unsigned char* out, unsigned char* tag, size_t tagLen)
    { (void)c; (void)k; (void)len; (void)iv; (void)ivLen; (void)add;
      (void)addLen; (void)in; (void)out; (void)tag; (void)tagLen;
      return SL_STATUS_NOT_SUPPORTED; }

static inline sl_status_t sl_se_ccm_auth_decrypt(
        sl_se_command_context_t* c, const sl_se_key_descriptor_t* k,
        size_t len, const unsigned char* iv, size_t ivLen,
        const unsigned char* add, size_t addLen, const unsigned char* in,
        unsigned char* out, const unsigned char* tag, size_t tagLen)
    { (void)c; (void)k; (void)len; (void)iv; (void)ivLen; (void)add;
      (void)addLen; (void)in; (void)out; (void)tag; (void)tagLen;
      return SL_STATUS_NOT_SUPPORTED; }

static inline sl_status_t sl_se_hash_multipart_starts(void* hashCtx,
        sl_se_command_context_t* c, sl_se_hash_type_t type)
    { (void)hashCtx; (void)c; (void)type; return SL_STATUS_NOT_SUPPORTED; }
static inline sl_status_t sl_se_hash_multipart_update(void* hashCtx,
        sl_se_command_context_t* c, const uint8_t* in, size_t len)
    { (void)hashCtx; (void)c; (void)in; (void)len;
      return SL_STATUS_NOT_SUPPORTED; }
static inline sl_status_t sl_se_hash_multipart_finish(void* hashCtx,
        sl_se_command_context_t* c, uint8_t* digest, size_t len)
    { (void)hashCtx; (void)c; (void)digest; (void)len;
      return SL_STATUS_NOT_SUPPORTED; }

static inline sl_status_t sl_se_validate_key(
        const sl_se_key_descriptor_t* k)
    { (void)k; return SL_STATUS_NOT_SUPPORTED; }
static inline sl_status_t sl_se_get_storage_size(
        const sl_se_key_descriptor_t* k, uint32_t* sz)
    { (void)k; (void)sz; return SL_STATUS_NOT_SUPPORTED; }
static inline sl_status_t sl_se_generate_key(sl_se_command_context_t* c,
        const sl_se_key_descriptor_t* k)
    { (void)c; (void)k; return SL_STATUS_NOT_SUPPORTED; }
static inline sl_status_t sl_se_export_public_key(
        sl_se_command_context_t* c, const sl_se_key_descriptor_t* k,
        const sl_se_key_descriptor_t* pub)
    { (void)c; (void)k; (void)pub; return SL_STATUS_NOT_SUPPORTED; }

static inline sl_status_t sl_se_ecc_sign(sl_se_command_context_t* c,
        const sl_se_key_descriptor_t* k, sl_se_hash_type_t hashAlg,
        int hashedMessage, const unsigned char* msg, size_t msgLen,
        unsigned char* sig, size_t sigLen)
    { (void)c; (void)k; (void)hashAlg; (void)hashedMessage; (void)msg;
      (void)msgLen; (void)sig; (void)sigLen; return SL_STATUS_NOT_SUPPORTED; }

static inline sl_status_t sl_se_ecc_verify(sl_se_command_context_t* c,
        const sl_se_key_descriptor_t* k, sl_se_hash_type_t hashAlg,
        int hashedMessage, const unsigned char* msg, size_t msgLen,
        const unsigned char* sig, size_t sigLen)
    { (void)c; (void)k; (void)hashAlg; (void)hashedMessage; (void)msg;
      (void)msgLen; (void)sig; (void)sigLen; return SL_STATUS_NOT_SUPPORTED; }

static inline sl_status_t sl_se_ecdh_compute_shared_secret(
        sl_se_command_context_t* c, const sl_se_key_descriptor_t* priv,
        const sl_se_key_descriptor_t* pub, const sl_se_key_descriptor_t* out)
    { (void)c; (void)priv; (void)pub; (void)out;
      return SL_STATUS_NOT_SUPPORTED; }

static inline sl_status_t sl_se_aes_crypt_ctr(sl_se_command_context_t* c,
        const sl_se_key_descriptor_t* k, size_t len, uint32_t* ncOff,
        unsigned char* nonceCounter, unsigned char* streamBlock,
        const unsigned char* in, unsigned char* out)
    { (void)c; (void)k; (void)len; (void)ncOff; (void)nonceCounter;
      (void)streamBlock; (void)in; (void)out; return SL_STATUS_NOT_SUPPORTED; }

static inline sl_status_t sl_se_cmac(sl_se_command_context_t* c,
        const sl_se_key_descriptor_t* k, const unsigned char* in,
        size_t inLen, unsigned char* out)
    { (void)c; (void)k; (void)in; (void)inLen; (void)out;
      return SL_STATUS_NOT_SUPPORTED; }
static inline sl_status_t sl_se_cmac_multipart_starts(
        sl_se_cmac_multipart_context_t* m, sl_se_command_context_t* c,
        const sl_se_key_descriptor_t* k)
    { (void)m; (void)c; (void)k; return SL_STATUS_NOT_SUPPORTED; }
static inline sl_status_t sl_se_cmac_multipart_update(
        sl_se_cmac_multipart_context_t* m, sl_se_command_context_t* c,
        const sl_se_key_descriptor_t* k, const uint8_t* in, size_t inLen)
    { (void)m; (void)c; (void)k; (void)in; (void)inLen;
      return SL_STATUS_NOT_SUPPORTED; }
static inline sl_status_t sl_se_cmac_multipart_finish(
        sl_se_cmac_multipart_context_t* m, sl_se_command_context_t* c,
        const sl_se_key_descriptor_t* k, uint8_t* out)
    { (void)m; (void)c; (void)k; (void)out; return SL_STATUS_NOT_SUPPORTED; }

static inline sl_status_t sl_se_hmac(sl_se_command_context_t* c,
        const sl_se_key_descriptor_t* k, sl_se_hash_type_t hashType,
        const uint8_t* msg, size_t msgLen, uint8_t* out, size_t outLen)
    { (void)c; (void)k; (void)hashType; (void)msg; (void)msgLen; (void)out;
      (void)outLen; return SL_STATUS_NOT_SUPPORTED; }
static inline sl_status_t sl_se_hmac_multipart_starts(
        sl_se_command_context_t* c, const sl_se_key_descriptor_t* k,
        sl_se_hash_type_t hashType, const uint8_t* msg, size_t msgLen,
        uint8_t* stateOut, size_t stateOutLen)
    { (void)c; (void)k; (void)hashType; (void)msg; (void)msgLen;
      (void)stateOut; (void)stateOutLen; return SL_STATUS_NOT_SUPPORTED; }
static inline sl_status_t sl_se_hmac_multipart_update(
        sl_se_command_context_t* c, sl_se_hash_type_t hashType,
        const uint8_t* msg, size_t msgLen, uint8_t* state, size_t stateLen)
    { (void)c; (void)hashType; (void)msg; (void)msgLen; (void)state;
      (void)stateLen; return SL_STATUS_NOT_SUPPORTED; }
static inline sl_status_t sl_se_hmac_multipart_finish(
        sl_se_command_context_t* c, const sl_se_key_descriptor_t* k,
        sl_se_hash_type_t hashType, const uint8_t* msg, size_t msgLen,
        uint8_t* state, size_t stateLen, uint8_t* out, size_t outLen)
    { (void)c; (void)k; (void)hashType; (void)msg; (void)msgLen; (void)state;
      (void)stateLen; (void)out; (void)outLen; return SL_STATUS_NOT_SUPPORTED; }

static inline sl_status_t sl_se_chacha20_poly1305_encrypt_and_tag(
        sl_se_command_context_t* c, const sl_se_key_descriptor_t* k,
        size_t len, const unsigned char* nonce, const unsigned char* add,
        size_t addLen, const unsigned char* in, unsigned char* out,
        unsigned char* tag)
    { (void)c; (void)k; (void)len; (void)nonce; (void)add; (void)addLen;
      (void)in; (void)out; (void)tag; return SL_STATUS_NOT_SUPPORTED; }
static inline sl_status_t sl_se_chacha20_poly1305_auth_decrypt(
        sl_se_command_context_t* c, const sl_se_key_descriptor_t* k,
        size_t len, const unsigned char* nonce, const unsigned char* add,
        size_t addLen, const unsigned char* in, unsigned char* out,
        const unsigned char* tag)
    { (void)c; (void)k; (void)len; (void)nonce; (void)add; (void)addLen;
      (void)in; (void)out; (void)tag; return SL_STATUS_NOT_SUPPORTED; }

static inline sl_status_t sl_se_derive_key_hkdf(sl_se_command_context_t* c,
        const sl_se_key_descriptor_t* inKey, sl_se_hash_type_t hashType,
        const unsigned char* salt, size_t saltLen, const unsigned char* info,
        size_t infoLen, sl_se_key_descriptor_t* outKey)
    { (void)c; (void)inKey; (void)hashType; (void)salt; (void)saltLen;
      (void)info; (void)infoLen; (void)outKey; return SL_STATUS_NOT_SUPPORTED; }
static inline sl_status_t sl_se_derive_key_pbkdf2(sl_se_command_context_t* c,
        const sl_se_key_descriptor_t* inKey, sl_se_pbkdf2_prf_type_t prf,
        const unsigned char* salt, size_t saltLen, uint32_t iterations,
        sl_se_key_descriptor_t* outKey)
    { (void)c; (void)inKey; (void)prf; (void)salt; (void)saltLen;
      (void)iterations; (void)outKey; return SL_STATUS_NOT_SUPPORTED; }

static inline sl_status_t sl_se_import_key(sl_se_command_context_t* c,
        const sl_se_key_descriptor_t* in, const sl_se_key_descriptor_t* out)
    { (void)c; (void)in; (void)out; return SL_STATUS_NOT_SUPPORTED; }
static inline sl_status_t sl_se_export_key(sl_se_command_context_t* c,
        const sl_se_key_descriptor_t* in, const sl_se_key_descriptor_t* out)
    { (void)c; (void)in; (void)out; return SL_STATUS_NOT_SUPPORTED; }

#endif /* WOLFSSL_SILABS_HOST_TEST */

#endif /* _WOLFPORT_SILABS_SHIM_H_ */
