/* stsafe.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/port/st/stsafe.h>
#include <wolfssl/wolfcrypt/logging.h>
#ifndef NO_ASN
    #include <wolfssl/wolfcrypt/asn.h>
#endif

#ifndef STSAFE_INTERFACE_PRINTF
    #define STSAFE_INTERFACE_PRINTF(...) WC_DO_NOTHING
#endif

/* Combined STSAFE macro - set in stsafe.h when either A100/A120 is defined */
#ifdef WOLFSSL_STSAFE

/* ========================================================================== */
/* Internal Implementation (when NOT using external stsafe_interface.h)       */
/* ========================================================================== */

/* When WOLFSSL_STSAFE_INTERFACE_EXTERNAL is defined, all internal
 * implementation is skipped and the customer provides their own
 * stsafe_interface.h with custom implementations. This maintains
 * backwards compatibility with older integration approaches. */
#ifndef WOLFSSL_STSAFE_INTERFACE_EXTERNAL

/* ========================================================================== */
/* SDK-Specific Includes                                                      */
/* ========================================================================== */

#ifdef WOLFSSL_STSAFEA120
    /* STSELib includes for A120 */
    #include "stselib.h"
#else /* WOLFSSL_STSAFEA100 */
    /* Legacy STSAFE-A1xx SDK includes */
    #include <stsafe_a_types.h>
    #include <stsafe_a_configuration.h>
    #include <stsafe_a_basic.h>
    #include <stsafe_a_tools.h>
    #include <stsafe_a_administrative.h>
    #include <stsafe_a_general_purpose.h>
    #include <stsafe_a_private_public_key.h>
    #include <stsafe_a_data_partition.h>
#endif

/* ========================================================================== */
/* Global State                                                               */
/* ========================================================================== */

#ifdef WOLFSSL_STSAFEA120
    /* STSELib handler */
    static stse_Handler_t g_stse_handler;
    static int g_stse_initialized = 0;
#else /* WOLFSSL_STSAFEA100 */
    /* Legacy SDK handle */
    static void* g_stsafe_handle = NULL;

    /* Host MAC and Cipher Keys for secure communication */
    /* NOTE: These are example keys
     * - real implementations should store securely */
    #ifndef STSAFE_HOST_KEY_MAC
    static const uint8_t g_host_mac_key[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
    };
    #endif
    #ifndef STSAFE_HOST_KEY_CIPHER
    static const uint8_t g_host_cipher_key[16] = {
        0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44,
        0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88
    };
    #endif
#endif

/* Current curve mode for signing operations */
static stsafe_curve_id_t g_stsafe_curve_mode = STSAFE_DEFAULT_CURVE;


/* ========================================================================== */
/* Internal Helper Functions                                                  */
/* ========================================================================== */

/**
 * \brief Helper macros to store/retrieve slot number in devCtx
 * \details Slot number is stored directly in devCtx as void* to avoid
 *          dynamic memory allocation. Slot values are small (0, 1, 0xFF)
 *          so safe to cast to/from void*.
 */
#define STSAFE_SLOT_TO_DEVCXT(slot) ((void*)(uintptr_t)(slot))
#define STSAFE_DEVCXT_TO_SLOT(devCtx) ((stsafe_slot_t)(uintptr_t)(devCtx))


/**
 * \brief Get key size in bytes for a given curve
 */
static int stsafe_get_key_size(stsafe_curve_id_t curve_id)
{
    switch (curve_id) {
        case STSAFE_ECC_CURVE_P256:
    #if defined(HAVE_ECC_BRAINPOOL) && defined(STSE_CONF_ECC_BRAINPOOL_P_256)
        case STSAFE_ECC_CURVE_BP256:
    #endif
            return 32;
        case STSAFE_ECC_CURVE_P384:
    #if defined(HAVE_ECC_BRAINPOOL) && defined(STSE_CONF_ECC_BRAINPOOL_P_384)
        case STSAFE_ECC_CURVE_BP384:
    #endif
            return 48;
        default:
            break;
    }
    return 0;
}

/**
 * \brief Convert wolfSSL ECC curve ID to STSAFE curve ID
 */
static stsafe_curve_id_t stsafe_get_ecc_curve_id(int ecc_curve)
{
    switch (ecc_curve) {
        case ECC_SECP256R1:
            return STSAFE_ECC_CURVE_P256;
        case ECC_SECP384R1:
            return STSAFE_ECC_CURVE_P384;
    #if defined(HAVE_ECC_BRAINPOOL) && defined(STSE_CONF_ECC_BRAINPOOL_P_256)
        case ECC_BRAINPOOLP256R1:
            return STSAFE_ECC_CURVE_BP256;
    #endif
    #if defined(HAVE_ECC_BRAINPOOL) && defined(STSE_CONF_ECC_BRAINPOOL_P_384)
        case ECC_BRAINPOOLP384R1:
            return STSAFE_ECC_CURVE_BP384;
    #endif
        default:
            break;
    }
    return STSAFE_DEFAULT_CURVE;
}

/**
 * \brief Convert STSAFE curve ID to wolfSSL ECC curve ID
 */
#if !defined(WOLFCRYPT_ONLY) && defined(HAVE_PK_CALLBACKS)
static int stsafe_get_ecc_curve(stsafe_curve_id_t curve_id)
{
    switch (curve_id) {
        case STSAFE_ECC_CURVE_P256:
            return ECC_SECP256R1;
        case STSAFE_ECC_CURVE_P384:
            return ECC_SECP384R1;
    #if defined(HAVE_ECC_BRAINPOOL) && defined(STSE_CONF_ECC_BRAINPOOL_P_256)
        case STSAFE_ECC_CURVE_BP256:
            return ECC_BRAINPOOLP256R1;
    #endif
    #if defined(HAVE_ECC_BRAINPOOL) && defined(STSE_CONF_ECC_BRAINPOOL_P_384)
        case STSAFE_ECC_CURVE_BP384:
            return ECC_BRAINPOOLP384R1;
    #endif
        default:
            break;
    }
    return ECC_SECP256R1;
}
#endif

/**
 * \brief Get current curve mode for signing
 */
static stsafe_curve_id_t stsafe_get_curve_mode(void)
{
    return g_stsafe_curve_mode;
}

/**
 * \brief Set current curve mode for signing
 */
static int stsafe_set_curve_mode(stsafe_curve_id_t curve_id)
{
    g_stsafe_curve_mode = curve_id;
    return 0;
}

/* Unused function workaround for some compilers */
#ifdef __GNUC__
__attribute__((unused))
#endif
static void stsafe_unused_funcs(void)
{
#if !defined(WOLFCRYPT_ONLY) && defined(HAVE_PK_CALLBACKS)
    (void)stsafe_get_ecc_curve;
#endif
    (void)stsafe_set_curve_mode;
}

/* ========================================================================== */
/* Internal Interface Functions - SDK Specific Implementations               */
/* ========================================================================== */

#ifdef WOLFSSL_STSAFEA120
/* -------------------------------------------------------------------------- */
/* STSELib (A120) Implementation                                              */
/* -------------------------------------------------------------------------- */

/**
 * \brief Initialize STSAFE-A120 device using STSELib
 */
int stsafe_interface_init(void)
{
    int rc = 0;
    stse_ReturnCode_t ret;

    if (g_stse_initialized) {
        return 0; /* Already initialized */
    }

    /* Set default handler values */
    ret = stse_set_default_handler_value(&g_stse_handler);
    if (ret != STSE_OK) {
        STSAFE_INTERFACE_PRINTF("stse_set_default_handler_value error: %d\n",
            ret);
        rc = -1;
    }

    if (rc == 0) {
        /* Configure for STSAFE-A120 on I2C bus 1 */
        g_stse_handler.device_type = STSAFE_A120;
    #ifdef STSAFE_I2C_BUS
        g_stse_handler.io.busID = STSAFE_I2C_BUS;
    #else
        g_stse_handler.io.busID = 1;
    #endif
        g_stse_handler.io.BusSpeed = 400; /* 400 kHz */

        /* Initialize STSELib - this sets up I2C communication */
        ret = stse_init(&g_stse_handler);
        if (ret != STSE_OK) {
            STSAFE_INTERFACE_PRINTF("stse_init error: %d\n", ret);
            rc = -1;
        }
    }

    if (rc == 0) {
        g_stse_initialized = 1;
    #ifdef USE_STSAFE_VERBOSE
        WOLFSSL_MSG("STSAFE-A120 (STSELib) initialized");
    #endif
    }

    return rc;
}

/**
 * \brief Generate ECC key pair on STSAFE-A120
 * \details Uses dedicated key slot (slot 1) for persistent keys.
 *          For ephemeral ECDHE keys, use stsafe_create_ecdhe_key() instead.
 */
static int stsafe_create_key(stsafe_slot_t* pSlot, stsafe_curve_id_t curve_id,
                             uint8_t* pPubKeyRaw)
{
    int rc = STSAFE_A_OK;
    stse_ReturnCode_t ret;
    stsafe_slot_t slot = STSAFE_KEY_SLOT_1; /* Use dedicated key slot for persistent keys */

    if (pPubKeyRaw == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Generate key pair - public key is X||Y concatenated
     * Note: stse_generate_ecc_key_pair expects stse_ecc_key_type_t,
     * but stsafe_curve_id_t values match stse_ecc_key_type_t enum values */
    ret = stse_generate_ecc_key_pair(&g_stse_handler, slot,
        (stse_ecc_key_type_t)curve_id,
        STSAFE_PERSISTENT_KEY_USAGE_LIMIT,
        pPubKeyRaw);
    if (ret != STSE_OK) {
        STSAFE_INTERFACE_PRINTF("stse_generate_ecc_key_pair error: %d\n", ret);
        rc = (int)ret;
    }

    if (rc == STSAFE_A_OK && pSlot != NULL) {
        *pSlot = slot;
    }

    return rc;
}

/**
 * \brief Generate ECDHE ephemeral key pair on STSAFE-A120
 * \details Uses stse_generate_ECDHE_key_pair() which generates truly
 *          ephemeral keys (not stored in slots). The private key remains
 *          in STSE internal memory for use with shared secret computation.
 *          Public key is returned in X||Y format (same as stse_generate_ecc_key_pair).
 */
static int stsafe_create_ecdhe_key(stsafe_curve_id_t curve_id,
                                    uint8_t* pPubKeyRaw)
{
    int rc = STSAFE_A_OK;
    stse_ReturnCode_t ret;

    if (pPubKeyRaw == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Generate ECDHE ephemeral key pair - public key returned as X||Y */
    ret = stse_generate_ECDHE_key_pair(&g_stse_handler,
        (stse_ecc_key_type_t)curve_id, pPubKeyRaw);
    if (ret != STSE_OK) {
        STSAFE_INTERFACE_PRINTF("stse_generate_ECDHE_key_pair error: %d\n", ret);
        rc = (int)ret;
    }

    return rc;
}

/**
 * \brief ECDSA sign using STSAFE-A120
 */
static int stsafe_sign(stsafe_slot_t slot, stsafe_curve_id_t curve_id,
                       uint8_t* pHash, uint8_t* pSigRS)
{
    int rc = STSAFE_A_OK;
    stse_ReturnCode_t ret;
    int key_sz = stsafe_get_key_size(curve_id);

    if (pHash == NULL || pSigRS == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Sign hash - output is R || S concatenated */
    ret = stse_ecc_generate_signature(&g_stse_handler, slot, curve_id,
        pHash, (uint16_t)key_sz, pSigRS);
    if (ret != STSE_OK) {
        STSAFE_INTERFACE_PRINTF("stse_ecc_generate_signature error: %d\n", ret);
        rc = (int)ret;
    }

    return rc;
}

/**
 * \brief ECDSA verify using STSAFE-A120
 */
static int stsafe_verify(stsafe_curve_id_t curve_id, uint8_t* pHash,
                         uint8_t* pSigRS, uint8_t* pPubKeyX, uint8_t* pPubKeyY,
                         int32_t* pResult)
{
    int rc = STSAFE_A_OK;
    stse_ReturnCode_t ret;
    int key_sz = stsafe_get_key_size(curve_id);
    uint8_t pubKey[STSAFE_MAX_PUBKEY_RAW_LEN];
    uint8_t validity = 0;

    if (pHash == NULL || pSigRS == NULL || pPubKeyX == NULL ||
        pPubKeyY == NULL || pResult == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Combine X and Y into single buffer (X||Y) */
    XMEMCPY(pubKey, pPubKeyX, key_sz);
    XMEMCPY(pubKey + key_sz, pPubKeyY, key_sz);

    /* Verify signature - pMessage is the hash, pSignature is R||S */
    ret = stse_ecc_verify_signature(&g_stse_handler, curve_id,
        pubKey,     /* public key X||Y */
        pSigRS,     /* signature R||S */
        pHash,      /* message (hash) */
        (uint16_t)key_sz,  /* message length */
        0,          /* eddsa_variant (0 for non-EdDSA) */
        &validity);
    if (ret != STSE_OK) {
        STSAFE_INTERFACE_PRINTF("stse_ecc_verify_signature error: %d\n", ret);
        *pResult = 0;
        rc = (int)ret;
    }

    if (rc == STSAFE_A_OK) {
        *pResult = (validity != 0) ? 1 : 0;
    }

    return rc;
}

/**
 * \brief ECDH shared secret using STSAFE-A120
 */
static int stsafe_shared_secret(stsafe_slot_t slot, stsafe_curve_id_t curve_id,
                                uint8_t* pPubKeyX, uint8_t* pPubKeyY,
                                uint8_t* pSharedSecret,
                                int32_t* pSharedSecretLen)
{
    int rc = STSAFE_A_OK;
    stse_ReturnCode_t ret;
    int key_sz = stsafe_get_key_size(curve_id);
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    uint8_t* peerPubKey = NULL;
#else
    uint8_t peerPubKey[STSAFE_MAX_PUBKEY_RAW_LEN];
#endif

    if (pPubKeyX == NULL || pPubKeyY == NULL || pSharedSecret == NULL ||
        pSharedSecretLen == NULL) {
        return BAD_FUNC_ARG;
    }

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    peerPubKey = (uint8_t*)XMALLOC(STSAFE_MAX_PUBKEY_RAW_LEN, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (peerPubKey == NULL) {
        return MEMORY_E;
    }
#endif

    /* Combine peer X and Y (X||Y format) */
    XMEMCPY(peerPubKey, pPubKeyX, key_sz);
    XMEMCPY(peerPubKey + key_sz, pPubKeyY, key_sz);

    /* Compute shared secret
     * Note: stse_ecc_establish_shared_secret expects stse_ecc_key_type_t.
     * For STSAFE-A120, stsafe_curve_id_t values match stse_ecc_key_type_t enum values:
     *   STSAFE_ECC_CURVE_P256 (0) = STSE_ECC_KT_NIST_P_256 (0)
     *   STSAFE_ECC_CURVE_P384 (1) = STSE_ECC_KT_NIST_P_384 (1) */
    ret = stse_ecc_establish_shared_secret(&g_stse_handler, slot,
        (stse_ecc_key_type_t)curve_id, peerPubKey, pSharedSecret);
    if (ret != STSE_OK) {
        STSAFE_INTERFACE_PRINTF("stse_ecc_establish_shared_secret error: %d (slot: %d, curve_id: %d)\n",
            ret, slot, curve_id);
        rc = (int)ret;
    }

    if (rc == STSAFE_A_OK) {
        *pSharedSecretLen = (int32_t)key_sz;
    }

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    XFREE(peerPubKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return rc;
}

/**
 * \brief ECDHE shared secret using STSAFE-A120
 * \details Computes shared secret using the ephemeral ECDHE private key
 *          that was generated by stsafe_create_ecdhe_key(). The ephemeral
 *          private key is stored internally in the STSE device.
 */
static int stsafe_shared_secret_ecdhe(stsafe_curve_id_t curve_id,
                                       uint8_t* pPubKeyX, uint8_t* pPubKeyY,
                                       uint8_t* pSharedSecret,
                                       int32_t* pSharedSecretLen)
{
    int rc = STSAFE_A_OK;
    stse_ReturnCode_t ret;
    int key_sz = stsafe_get_key_size(curve_id);
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    uint8_t* peerPubKey = NULL;
#else
    uint8_t peerPubKey[STSAFE_MAX_PUBKEY_RAW_LEN];
#endif

    if (pPubKeyX == NULL || pPubKeyY == NULL || pSharedSecret == NULL ||
        pSharedSecretLen == NULL || key_sz == 0) {
        return BAD_FUNC_ARG;
    }

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    peerPubKey = (uint8_t*)XMALLOC(STSAFE_MAX_PUBKEY_RAW_LEN, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (peerPubKey == NULL) {
        return MEMORY_E;
    }
#endif

    /* Combine peer X and Y (X||Y format) */
    XMEMCPY(peerPubKey, pPubKeyX, key_sz);
    XMEMCPY(peerPubKey + key_sz, pPubKeyY, key_sz);

    /* Compute shared secret using ephemeral slot (0xFF)
     * The ephemeral private key was generated by stse_generate_ECDHE_key_pair() */
    ret = stse_ecc_establish_shared_secret(&g_stse_handler,
        STSAFE_KEY_SLOT_EPHEMERAL, (stse_ecc_key_type_t)curve_id, peerPubKey, pSharedSecret);
    if (ret != STSE_OK) {
        STSAFE_INTERFACE_PRINTF("stse_ecc_establish_shared_secret (ECDHE) error: %d\n",
            ret);
        rc = (int)ret;
    }

    if (rc == STSAFE_A_OK) {
        *pSharedSecretLen = (int32_t)key_sz;
    }

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    XFREE(peerPubKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return rc;
}

/**
 * \brief Read device certificate from STSAFE-A120
 */
static int stsafe_read_certificate(uint8_t** ppCert, uint32_t* pCertLen)
{
#ifdef WOLFSSL_NO_MALLOC
    /* Certificate reading requires dynamic allocation */
    (void)ppCert;
    (void)pCertLen;
    return NOT_COMPILED_IN;
#else
    int rc = STSAFE_A_OK;
    stse_ReturnCode_t ret;
    uint16_t certLen = 0;
    uint8_t certZone = 0; /* Certificate zone 0 */

    /* First, get certificate size */
    ret = stse_get_device_certificate_size(&g_stse_handler, certZone, &certLen);
    if (ret != STSE_OK || certLen == 0) {
        STSAFE_INTERFACE_PRINTF("stse_get_device_certificate_size error: %d\n",
            ret);
        rc = (int)ret;
    }

    /* Allocate buffer */
    if (rc == STSAFE_A_OK) {
        *ppCert = (uint8_t*)XMALLOC(certLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (*ppCert == NULL) {
            rc = MEMORY_E;
        }
    }

    /* Read certificate */
    if (rc == STSAFE_A_OK) {
        ret = stse_get_device_certificate(&g_stse_handler, certZone, certLen,
            *ppCert);
        if (ret != STSE_OK) {
            XFREE(*ppCert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            *ppCert = NULL;
            STSAFE_INTERFACE_PRINTF("stse_get_device_certificate error: %d\n",
                ret);
            rc = (int)ret;
        }
    }

    if (rc == STSAFE_A_OK) {
        *pCertLen = certLen;
    }

    return rc;
#endif /* WOLFSSL_NO_MALLOC */
}

#if !defined(WC_NO_RNG) && defined(USE_STSAFE_RNG_SEED)
/**
 * \brief Get random bytes from STSAFE-A120
 */
static int stsafe_get_random(uint8_t* pRandom, uint32_t size)
{
    int rc;
    stse_ReturnCode_t ret;
    uint16_t len = (size > 0xFFFF) ? 0xFFFF : (uint16_t)size;

    ret = stse_generate_random(&g_stse_handler, pRandom, len);
    if (ret != STSE_OK) {
        rc = -1;
    }
    else {
        rc = (int)len;
    }

    return rc;
}
#endif

#else /* WOLFSSL_STSAFEA100 */
/* -------------------------------------------------------------------------- */
/* Legacy STSAFE-A1xx SDK (A100/A110) Implementation                          */
/* -------------------------------------------------------------------------- */

/**
 * \brief Set host keys for secure communication
 */
static void stsafe_set_host_keys(void* handle)
{
    StSafeA_SetHostMacKey(handle, g_host_mac_key);
    StSafeA_SetHostCipherKey(handle, g_host_cipher_key);
}

/**
 * \brief Check and initialize host keys
 */
static int stsafe_check_host_keys(void* handle)
{
    uint8_t status_code;
    StSafeA_HostKeySlotBuffer* pHostKeySlot;

    status_code = StSafeA_HostKeySlotQuery(handle, &pHostKeySlot,
        STSAFE_A_NO_MAC);

    if (status_code == STSAFE_A_OK && !pHostKeySlot->HostKeyPresenceFlag) {
        /* Host keys not set, initialize them */
        uint8_t hostKeys[32];
        XMEMCPY(hostKeys, g_host_mac_key, 16);
        XMEMCPY(hostKeys + 16, g_host_cipher_key, 16);

        status_code = StSafeA_PutAttribute(handle, STSAFE_A_HOST_KEY_SLOT_TAG,
            hostKeys, sizeof(hostKeys), STSAFE_A_NO_MAC);
    }

    return status_code;
}

/**
 * \brief Initialize STSAFE-A100/A110 device
 */
int stsafe_interface_init(void)
{
    int rc = 0;
    uint8_t status_code;
    const uint8_t echo_data[3] = {0x01, 0x02, 0x03};
    StSafeA_EchoBuffer* echo_resp = NULL;

    if (g_stsafe_handle != NULL) {
        return 0; /* Already initialized */
    }

    /* Create handle */
    status_code = StSafeA_CreateHandle(&g_stsafe_handle, STSAFE_I2C_ADDR);
    if (status_code != STSAFE_A_OK) {
        STSAFE_INTERFACE_PRINTF("StSafeA_CreateHandle error: %d\n",
            status_code);
        rc = -1;
    }

    /* Echo test to verify communication */
    if (rc == 0) {
        status_code = StSafeA_Echo(g_stsafe_handle, (uint8_t*)echo_data, 3,
            &echo_resp, STSAFE_A_NO_MAC);
        if (status_code != STSAFE_A_OK ||
            XMEMCMP(echo_data, echo_resp->Data, 3) != 0) {
            STSAFE_INTERFACE_PRINTF("StSafeA_Echo error: %d\n", status_code);
            rc = -1;
        }
        XFREE(echo_resp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    /* Check/initialize host keys */
    if (rc == 0) {
        status_code = stsafe_check_host_keys(g_stsafe_handle);
        if (status_code != STSAFE_A_OK) {
            STSAFE_INTERFACE_PRINTF("stsafe_check_host_keys error: %d\n",
                status_code);
            rc = -1;
        }
    }

#ifdef USE_STSAFE_VERBOSE
    if (rc == 0) {
        WOLFSSL_MSG("STSAFE-A100/A110 initialized");
    }
#endif

    return rc;
}

/**
 * \brief Generate ECC key pair on STSAFE-A100/A110
 */
static int stsafe_create_key(stsafe_slot_t* pSlot, stsafe_curve_id_t curve_id,
                             uint8_t* pPubKeyRaw)
{
    int rc;
    uint8_t status_code;
    int key_sz = stsafe_get_key_size(curve_id);
    stsafe_slot_t slot = STSAFE_KEY_SLOT_1;
    StSafeA_CoordinateBuffer* pubX = NULL;
    StSafeA_CoordinateBuffer* pubY = NULL;
    uint8_t* pointRepId = NULL;

    stsafe_set_host_keys(g_stsafe_handle);

    status_code = StSafeA_GenerateKeyPair(g_stsafe_handle, slot, 0xFFFF, 1,
        (StSafeA_KeyUsageAuthorizationFlags)(
            STSAFE_A_COMMAND_RESPONSE_SIGNATURE |
            STSAFE_A_MESSAGE_DIGEST_SIGNATURE |
            STSAFE_A_KEY_ESTABLISHMENT),
        curve_id, &pointRepId, &pubX, &pubY, STSAFE_A_HOST_C_MAC);

    if (status_code == STSAFE_A_OK && pointRepId != NULL &&
        *pointRepId == STSAFE_A_POINT_REPRESENTATION_ID) {
        XMEMCPY(pPubKeyRaw, pubX->Data, pubX->Length);
        XMEMCPY(pPubKeyRaw + key_sz, pubY->Data, pubY->Length);
        rc = STSAFE_A_OK;
    }
    else {
        rc = (int)(uint8_t)-1;
    }

    /* Free SDK-allocated buffers */
    XFREE(pubX, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(pubY, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (rc == STSAFE_A_OK && pSlot != NULL) {
        *pSlot = slot;
    }

    return rc;
}

/**
 * \brief ECDSA sign using STSAFE-A100/A110
 */
static int stsafe_sign(stsafe_slot_t slot, stsafe_curve_id_t curve_id,
                       uint8_t* pHash, uint8_t* pSigRS)
{
    int rc;
    uint8_t status_code;
    int key_sz = stsafe_get_key_size(curve_id);
    StSafeA_SignatureBuffer* signature = NULL;
    StSafeA_HashTypes hashType;
    size_t r_length, s_length;

    hashType = (curve_id == STSAFE_ECC_CURVE_P384 ||
                curve_id == STSAFE_ECC_CURVE_BP384) ?
                STSAFE_HASH_SHA384 : STSAFE_HASH_SHA256;

    status_code = StSafeA_GenerateSignature(g_stsafe_handle, slot, pHash,
        hashType, &signature, STSAFE_A_NO_MAC);

    if (status_code == STSAFE_A_OK && signature != NULL) {
        /* Parse signature - format is: len(2) || R || len(2) || S */
        r_length = ((uint16_t)signature->Data[0] << 8) | signature->Data[1];

        /* Bounds check: r_length must be valid and fit within signature buffer */
        if (r_length > key_sz || r_length == 0 ||
            (size_t)(2 + r_length + 2) > signature->Length) {
            rc = ASN_PARSE_E;
        }
        else {
            s_length = ((uint16_t)signature->Data[2 + r_length] << 8) |
                       signature->Data[3 + r_length];

            /* Bounds check: s_length must be valid and fit within signature buffer */
            if (s_length > key_sz || s_length == 0 ||
                (size_t)(4 + r_length + s_length) > signature->Length) {
                rc = ASN_PARSE_E;
            }
            else {
                /* Copy R and S to output (zero-padded) */
                XMEMSET(pSigRS, 0, key_sz * 2);
                XMEMCPY(pSigRS + (key_sz - r_length), &signature->Data[2], r_length);
                XMEMCPY(pSigRS + key_sz + (key_sz - s_length),
                        &signature->Data[4 + r_length], s_length);
                rc = STSAFE_A_OK;
            }
        }
    }
    else {
        rc = (int)status_code;
    }

    /* Free SDK-allocated buffer */
    XFREE(signature, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return rc;
}

/**
 * \brief ECDSA verify using STSAFE-A100/A110
 */
static int stsafe_verify(stsafe_curve_id_t curve_id, uint8_t* pHash,
                         uint8_t* pSigRS, uint8_t* pPubKeyX, uint8_t* pPubKeyY,
                         int32_t* pResult)
{
    int rc = (int)(uint8_t)-1;
    uint8_t status_code;
    int key_sz = stsafe_get_key_size(curve_id);
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    StSafeA_CoordinateBuffer* X = NULL;
    StSafeA_CoordinateBuffer* Y = NULL;
    StSafeA_SignatureBuffer* R = NULL;
    StSafeA_SignatureBuffer* S = NULL;
    StSafeA_SignatureBuffer* Hash = NULL;
#else
    /* Stack buffers: 2 bytes for Length + STSAFE_MAX_KEY_LEN for Data */
    byte R_buf[2 + STSAFE_MAX_KEY_LEN];
    byte S_buf[2 + STSAFE_MAX_KEY_LEN];
    byte Hash_buf[2 + STSAFE_MAX_KEY_LEN];
    byte X_buf[2 + STSAFE_MAX_KEY_LEN];
    byte Y_buf[2 + STSAFE_MAX_KEY_LEN];
    StSafeA_SignatureBuffer* R = (StSafeA_SignatureBuffer*)R_buf;
    StSafeA_SignatureBuffer* S = (StSafeA_SignatureBuffer*)S_buf;
    StSafeA_SignatureBuffer* Hash = (StSafeA_SignatureBuffer*)Hash_buf;
    StSafeA_CoordinateBuffer* X = (StSafeA_CoordinateBuffer*)X_buf;
    StSafeA_CoordinateBuffer* Y = (StSafeA_CoordinateBuffer*)Y_buf;
#endif
    StSafeA_VerifySignatureBuffer* Verif = NULL;

    *pResult = 0;

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    /* Allocate buffers */
    R = (StSafeA_SignatureBuffer*)XMALLOC(key_sz + 2, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    S = (StSafeA_SignatureBuffer*)XMALLOC(key_sz + 2, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    Hash = (StSafeA_SignatureBuffer*)XMALLOC(key_sz + 2, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    X = (StSafeA_CoordinateBuffer*)XMALLOC(key_sz + 2, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    Y = (StSafeA_CoordinateBuffer*)XMALLOC(key_sz + 2, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);

    if (X == NULL || Y == NULL || R == NULL || S == NULL || Hash == NULL) {
        XFREE(R, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(S, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(Hash, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(X, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(Y, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
#endif

    R->Length = key_sz;
    S->Length = key_sz;
    Hash->Length = key_sz;
    X->Length = key_sz;
    Y->Length = key_sz;

    XMEMCPY(R->Data, pSigRS, key_sz);
    XMEMCPY(S->Data, pSigRS + key_sz, key_sz);
    XMEMCPY(Hash->Data, pHash, key_sz);
    XMEMCPY(X->Data, pPubKeyX, key_sz);
    XMEMCPY(Y->Data, pPubKeyY, key_sz);

    status_code = StSafeA_VerifyMessageSignature(g_stsafe_handle,
        curve_id, X, Y, R, S, Hash, &Verif, STSAFE_A_NO_MAC);

    if (status_code == STSAFE_A_OK && Verif != NULL) {
        *pResult = Verif->SignatureValidity ? 1 : 0;
        if (Verif->SignatureValidity) {
            rc = STSAFE_A_OK;
        }
    }
#ifndef WOLFSSL_NO_MALLOC
    /* Free SDK-allocated buffer */
    XFREE(Verif, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    XFREE(R, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(S, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(Hash, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(X, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(Y, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return rc;
}

/**
 * \brief ECDH shared secret using STSAFE-A100/A110
 */
static int stsafe_shared_secret(stsafe_slot_t slot, stsafe_curve_id_t curve_id,
                                uint8_t* pPubKeyX, uint8_t* pPubKeyY,
                                uint8_t* pSharedSecret,
                                int32_t* pSharedSecretLen)
{
    int rc = (int)(uint8_t)-1;
    uint8_t status_code;
    int key_sz = stsafe_get_key_size(curve_id);
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    StSafeA_CoordinateBuffer* peerX = NULL;
    StSafeA_CoordinateBuffer* peerY = NULL;
#else
    /* Stack buffers: 2 bytes for Length + STSAFE_MAX_KEY_LEN for Data */
    byte peerX_buf[2 + STSAFE_MAX_KEY_LEN];
    byte peerY_buf[2 + STSAFE_MAX_KEY_LEN];
    StSafeA_CoordinateBuffer* peerX = (StSafeA_CoordinateBuffer*)peerX_buf;
    StSafeA_CoordinateBuffer* peerY = (StSafeA_CoordinateBuffer*)peerY_buf;
#endif
    StSafeA_SharedSecretBuffer* sharedSecret = NULL;

    stsafe_set_host_keys(g_stsafe_handle);

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    peerX = (StSafeA_CoordinateBuffer*)XMALLOC(key_sz + 2, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    peerY = (StSafeA_CoordinateBuffer*)XMALLOC(key_sz + 2, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);

    if (peerX == NULL || peerY == NULL) {
        XFREE(peerX, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(peerY, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
#endif

    peerX->Length = key_sz;
    peerY->Length = key_sz;
    XMEMCPY(peerX->Data, pPubKeyX, key_sz);
    XMEMCPY(peerY->Data, pPubKeyY, key_sz);

    status_code = StSafeA_EstablishKey(g_stsafe_handle, slot,
        peerX, peerY, &sharedSecret, STSAFE_A_HOST_C_MAC);

    if (status_code == STSAFE_A_OK && sharedSecret != NULL) {
        *pSharedSecretLen = sharedSecret->SharedSecret.Length;
        XMEMCPY(pSharedSecret, sharedSecret->SharedSecret.Data,
                sharedSecret->SharedSecret.Length);
        rc = STSAFE_A_OK;
    }
#ifndef WOLFSSL_NO_MALLOC
    /* Free SDK-allocated buffer */
    XFREE(sharedSecret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    XFREE(peerX, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(peerY, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return rc;
}

/**
 * \brief Read device certificate from STSAFE-A100/A110
 */
static int stsafe_read_certificate(uint8_t** ppCert, uint32_t* pCertLen)
{
#ifdef WOLFSSL_NO_MALLOC
    /* Certificate reading requires dynamic allocation */
    (void)ppCert;
    (void)pCertLen;
    return NOT_COMPILED_IN;
#else
    int rc = STSAFE_A_OK;
    uint8_t status_code;
    StSafeA_ReadBuffer* readBuf = NULL;
    struct stsafe_a* stsafe_a = (struct stsafe_a*)g_stsafe_handle;
    uint8_t step;
    uint16_t i;

    *pCertLen = 0;

    /* Read first 4 bytes to determine certificate length */
    status_code = StSafeA_Read(g_stsafe_handle, 0, 0, STSAFE_A_ALWAYS,
        0, 0, 4, &readBuf, STSAFE_A_NO_MAC);

    if (status_code == STSAFE_A_OK && readBuf->Length == 4) {
        /* Parse ASN.1 DER certificate header */
        /* 0x30 = ASN_SEQUENCE | ASN_CONSTRUCTED (certificate is a SEQUENCE) */
        if (readBuf->Data[0] == (ASN_SEQUENCE | ASN_CONSTRUCTED)) {
            /* Parse ASN.1 length encoding */
            switch (readBuf->Data[1]) {
                case (ASN_LONG_LENGTH | 0x01):  /* Length encoded in 1 byte */
                    *pCertLen = readBuf->Data[2] + 3;
                    break;
                case (ASN_LONG_LENGTH | 0x02):  /* Length encoded in 2 bytes */
                    *pCertLen = ((uint16_t)readBuf->Data[2] << 8) +
                                       readBuf->Data[3] + 4;
                    break;
                default:
                    /* Short form: length < 128, encoded directly */
                    if (readBuf->Data[1] < ASN_LONG_LENGTH) {
                        *pCertLen = readBuf->Data[1] + 2;
                    }
                    break;
            }
        }
    }
    else {
        rc = (int)status_code;
    }
    XFREE(readBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    readBuf = NULL;

    if (rc == STSAFE_A_OK && *pCertLen > 0) {
        *ppCert = (uint8_t*)XMALLOC(*pCertLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (*ppCert == NULL) {
            rc = (int)(uint8_t)-1;
        }
    }

    if (rc == STSAFE_A_OK && *pCertLen > 0) {
        /* STSAFE-A100/A110 maximum read size is 225 bytes per command.
         * When CRC is supported, 2 bytes are used for CRC, leaving 223 bytes
         * for data. Without CRC, we can read up to 225 bytes, but use 223
         * for consistency and to leave room for protocol overhead. */
        step = 223 - (stsafe_a->CrcSupport ? 2 : 0);

        for (i = 0; rc == STSAFE_A_OK && i < *pCertLen / step; i++) {
            status_code = StSafeA_Read(g_stsafe_handle, 0, 0,
                STSAFE_A_ALWAYS, 0, i * step, step, &readBuf,
                STSAFE_A_NO_MAC);
            if (status_code == STSAFE_A_OK) {
                XMEMCPY(*ppCert + (i * step), readBuf->Data, readBuf->Length);
            }
            else {
                rc = (int)status_code;
            }
            XFREE(readBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            readBuf = NULL;
        }

        if (rc == STSAFE_A_OK && (*pCertLen % step)) {
            status_code = StSafeA_Read(g_stsafe_handle, 0, 0,
                STSAFE_A_ALWAYS, 0, i * step, *pCertLen % step,
                &readBuf, STSAFE_A_NO_MAC);
            if (status_code == STSAFE_A_OK) {
                XMEMCPY(*ppCert + (i * step), readBuf->Data, readBuf->Length);
            }
            else {
                rc = (int)status_code;
            }
            XFREE(readBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            readBuf = NULL;
        }
    }

    return rc;
#endif /* WOLFSSL_NO_MALLOC */
}

#if !defined(WC_NO_RNG) && defined(USE_STSAFE_RNG_SEED)
/**
 * \brief Get random bytes from STSAFE-A100/A110
 */
static int stsafe_get_random(uint8_t* pRandom, uint32_t size)
{
    int rc;
    uint8_t status_code;
    StSafeA_GenerateRandomBuffer* rndBuf = NULL;
    uint8_t reqSize = (size > 255) ? 255 : (uint8_t)size;

    status_code = StSafeA_GenerateRandom(g_stsafe_handle, STSAFE_A_EPHEMERAL,
        reqSize, &rndBuf, STSAFE_A_NO_MAC);

    if (status_code == STSAFE_A_OK && rndBuf != NULL) {
        rc = (int)rndBuf->Length;
        XMEMCPY(pRandom, rndBuf->Data, rndBuf->Length);
    }
    else {
        rc = -1;
    }

    XFREE(rndBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return rc;
}
#endif

#endif /* WOLFSSL_STSAFEA120 */

#endif /* !WOLFSSL_STSAFE_INTERFACE_EXTERNAL */


/* ========================================================================== */
/* Public API Functions                                                       */
/* ========================================================================== */

/**
 * \brief Load device certificate from STSAFE
 */
int SSL_STSAFE_LoadDeviceCertificate(byte** pRawCertificate,
    word32* pRawCertificateLen)
{
    int err = 0;

    if (pRawCertificate == NULL || pRawCertificateLen == NULL) {
        err = BAD_FUNC_ARG;
    }

#ifdef USE_STSAFE_VERBOSE
    if (err == 0) {
        WOLFSSL_MSG("SSL_STSAFE_LoadDeviceCertificate");
    }
#endif

    if (err == 0) {
        err = stsafe_read_certificate(pRawCertificate, pRawCertificateLen);
        if (err != STSAFE_A_OK) {
            err = WC_HW_E;
        }
    }

    return err;
}


/* ========================================================================== */
/* PK Callbacks                                                               */
/* ========================================================================== */

#if !defined(WOLFCRYPT_ONLY) && defined(HAVE_PK_CALLBACKS)

/**
 * \brief Key Gen Callback (used by TLS server for ECDHE)
 */
int SSL_STSAFE_CreateKeyCb(WOLFSSL* ssl, ecc_key* key, word32 keySz,
    int ecc_curve, void* ctx)
{
    int err = 0;
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    byte* pubKeyRaw = NULL;
#else
    byte pubKeyRaw[STSAFE_MAX_PUBKEY_RAW_LEN];
#endif
    stsafe_slot_t slot;
    stsafe_curve_id_t curve_id;

    (void)ssl;
    (void)ctx;

#ifdef USE_STSAFE_VERBOSE
    WOLFSSL_MSG("CreateKeyCb: STSAFE (ECDHE)");
#endif

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    pubKeyRaw = (byte*)XMALLOC(STSAFE_MAX_PUBKEY_RAW_LEN, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (pubKeyRaw == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == 0) {
        curve_id = stsafe_get_ecc_curve_id(ecc_curve);

#ifdef WOLFSSL_STSAFEA120
        /* Use ECDHE ephemeral key generation for A120 */
        err = stsafe_create_ecdhe_key(curve_id, pubKeyRaw);
        if (err != STSAFE_A_OK) {
            STSAFE_INTERFACE_PRINTF("stsafe_create_ecdhe_key error: %d\n", err);
            err = WC_HW_E;
        }
        /* For ECDHE, slot is not used (ephemeral key stored internally) */
        slot = STSAFE_KEY_SLOT_EPHEMERAL;
#else
        /* Legacy A100/A110 uses slot-based key generation */
        err = stsafe_create_key(&slot, curve_id, pubKeyRaw);
        if (err != STSAFE_A_OK) {
            STSAFE_INTERFACE_PRINTF("stsafe_create_key error: %d\n", err);
            err = WC_HW_E;
        }
#endif
    }

    if (err == 0) {
        err = wc_ecc_import_unsigned(key, pubKeyRaw, &pubKeyRaw[keySz],
            NULL, ecc_curve);
    }

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    XFREE(pubKeyRaw, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    (void)slot; /* May be unused for A120 ECDHE */

    return err;
}

/**
 * \brief Verify Peer Cert Callback
 */
int SSL_STSAFE_VerifyPeerCertCb(WOLFSSL* ssl,
                                const unsigned char* sig, unsigned int sigSz,
                                const unsigned char* hash, unsigned int hashSz,
                                const unsigned char* keyDer, unsigned int keySz,
                                int* result, void* ctx)
{
    int err = 0;
    int eccKeyInit = 0;
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    byte* sigRS = NULL;
    byte* pubKeyX = NULL;
    byte* pubKeyY = NULL;
#else
    byte sigRS[STSAFE_MAX_SIG_LEN];
    byte pubKeyX[STSAFE_MAX_PUBKEY_RAW_LEN/2];
    byte pubKeyY[STSAFE_MAX_PUBKEY_RAW_LEN/2];
#endif
    byte* r = NULL;
    byte* s = NULL;
    word32 r_len = STSAFE_MAX_SIG_LEN/2, s_len = STSAFE_MAX_SIG_LEN/2;
    word32 pubKeyX_len = STSAFE_MAX_PUBKEY_RAW_LEN/2;
    word32 pubKeyY_len = STSAFE_MAX_PUBKEY_RAW_LEN/2;
    ecc_key eccKey;
    word32 inOutIdx = 0;
    stsafe_curve_id_t curve_id = STSAFE_ECC_CURVE_P256;
    int ecc_curve;
    int key_sz = 0;

    (void)ssl;
    (void)ctx;
    (void)hashSz;

#ifdef USE_STSAFE_VERBOSE
    WOLFSSL_MSG("VerifyPeerCertCB: STSAFE");
#endif

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    sigRS = (byte*)XMALLOC(STSAFE_MAX_SIG_LEN, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    pubKeyX = (byte*)XMALLOC(STSAFE_MAX_PUBKEY_RAW_LEN/2, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    pubKeyY = (byte*)XMALLOC(STSAFE_MAX_PUBKEY_RAW_LEN/2, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (sigRS == NULL || pubKeyX == NULL || pubKeyY == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == 0) {
        err = wc_ecc_init(&eccKey);
        if (err == 0) {
            eccKeyInit = 1;
        }
    }

    if (err == 0) {
        err = wc_EccPublicKeyDecode(keyDer, &inOutIdx, &eccKey, keySz);
    }
    if (err == 0) {
        err = wc_ecc_export_public_raw(&eccKey, pubKeyX, &pubKeyX_len,
            pubKeyY, &pubKeyY_len);
    }
    if (err == 0) {
        ecc_curve = eccKey.dp->id;
        curve_id = stsafe_get_ecc_curve_id(ecc_curve);
        key_sz = stsafe_get_key_size(curve_id);
        if (key_sz <= 0 || key_sz > STSAFE_MAX_KEY_LEN) {
            err = BAD_FUNC_ARG;
        }
    }
    if (err == 0) {
        XMEMSET(sigRS, 0, STSAFE_MAX_SIG_LEN);
        r = &sigRS[0];
        s = &sigRS[key_sz];
        err = wc_ecc_sig_to_rs(sig, sigSz, r, &r_len, s, &s_len);
    }
    if (err == 0) {
        if ((int)r_len > key_sz || (int)s_len > key_sz) {
            err = BAD_FUNC_ARG;
        }
    }
    if (err == 0) {
        /* Zero-pad R and S */
        XMEMMOVE(&sigRS[key_sz - r_len], r, r_len);
        XMEMSET(&sigRS[0], 0, key_sz - r_len);
        XMEMMOVE(&sigRS[key_sz + (key_sz - s_len)], s, s_len);
        XMEMSET(&sigRS[key_sz], 0, key_sz - s_len);

        err = stsafe_verify(curve_id, (uint8_t*)hash, sigRS,
            pubKeyX, pubKeyY, (int32_t*)result);
        if (err != STSAFE_A_OK) {
            STSAFE_INTERFACE_PRINTF("stsafe_verify error: %d\n", err);
            err = WC_HW_E;
        }
    }

    if (eccKeyInit) {
        wc_ecc_free(&eccKey);
    }

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    XFREE(sigRS, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(pubKeyX, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(pubKeyY, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return err;
}

/**
 * \brief Sign Certificate Callback
 */
int SSL_STSAFE_SignCertificateCb(WOLFSSL* ssl, const byte* in,
                                 word32 inSz, byte* out, word32* outSz,
                                 const byte* key, word32 keySz, void* ctx)
{
    int err = 0;
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    byte* digest = NULL;
    byte* sigRS = NULL;
#else
    byte digest[STSAFE_MAX_KEY_LEN];
    byte sigRS[STSAFE_MAX_SIG_LEN];
#endif
    byte* r;
    byte* s;
    stsafe_curve_id_t curve_id;
    int key_sz;

    (void)ssl;
    (void)ctx;
    (void)key;
    (void)keySz;

#ifdef USE_STSAFE_VERBOSE
    WOLFSSL_MSG("SignCertificateCb: STSAFE");
#endif

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    digest = (byte*)XMALLOC(STSAFE_MAX_KEY_LEN, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    sigRS = (byte*)XMALLOC(STSAFE_MAX_SIG_LEN, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (digest == NULL || sigRS == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == 0) {
        curve_id = stsafe_get_curve_mode();
        key_sz = stsafe_get_key_size(curve_id);

        if ((int)inSz > key_sz)
            inSz = key_sz;

        XMEMSET(digest, 0, STSAFE_MAX_KEY_LEN);
        XMEMCPY(&digest[key_sz - inSz], in, inSz);

        XMEMSET(sigRS, 0, STSAFE_MAX_SIG_LEN);
        err = stsafe_sign(STSAFE_KEY_SLOT_0, curve_id, digest, sigRS);
        if (err != STSAFE_A_OK) {
            STSAFE_INTERFACE_PRINTF("stsafe_sign error: %d\n", err);
            err = WC_HW_E;
        }
    }

    if (err == 0) {
        r = &sigRS[0];
        s = &sigRS[key_sz];
        err = wc_ecc_rs_raw_to_sig(r, key_sz, s, key_sz, out, outSz);
        if (err != 0) {
            WOLFSSL_MSG("Error converting RS to Signature");
        }
    }

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    XFREE(digest, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(sigRS, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return err;
}

/**
 * \brief Shared Secret Callback (ECDHE)
 */
int SSL_STSAFE_SharedSecretCb(WOLFSSL* ssl, ecc_key* otherKey,
                              unsigned char* pubKeyDer, unsigned int* pubKeySz,
                              unsigned char* out, unsigned int* outlen,
                              int side, void* ctx)
{
    int err = 0;
    int tmpKeyInit = 0;
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    byte* otherKeyX = NULL;
    byte* otherKeyY = NULL;
    byte* pubKeyRaw = NULL;
#else
    byte otherKeyX[STSAFE_MAX_KEY_LEN];
    byte otherKeyY[STSAFE_MAX_KEY_LEN];
    byte pubKeyRaw[STSAFE_MAX_PUBKEY_RAW_LEN];
#endif
    word32 otherKeyX_len = STSAFE_MAX_KEY_LEN;
    word32 otherKeyY_len = STSAFE_MAX_KEY_LEN;
    stsafe_slot_t slot = STSAFE_KEY_SLOT_0;
    stsafe_curve_id_t curve_id;
    ecc_key tmpKey;
    int ecc_curve;
    int key_sz;

    (void)ssl;
    (void)ctx;

#ifdef USE_STSAFE_VERBOSE
    WOLFSSL_MSG("SharedSecretCb: STSAFE (ECDHE)");
#endif

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    otherKeyX = (byte*)XMALLOC(STSAFE_MAX_KEY_LEN, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    otherKeyY = (byte*)XMALLOC(STSAFE_MAX_KEY_LEN, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    pubKeyRaw = (byte*)XMALLOC(STSAFE_MAX_PUBKEY_RAW_LEN, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (otherKeyX == NULL || otherKeyY == NULL || pubKeyRaw == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == 0) {
        err = wc_ecc_init(&tmpKey);
        if (err == 0) {
            tmpKeyInit = 1;
        }
    }

    if (err == 0) {
        ecc_curve = otherKey->dp->id;
        curve_id = stsafe_get_ecc_curve_id(ecc_curve);
        key_sz = stsafe_get_key_size(curve_id);

        if (side == WOLFSSL_CLIENT_END) {
            err = wc_ecc_export_public_raw(otherKey, otherKeyX, &otherKeyX_len,
                otherKeyY, &otherKeyY_len);

            if (err == 0) {
#ifdef WOLFSSL_STSAFEA120
                /* Use ECDHE ephemeral key generation for A120 */
                err = stsafe_create_ecdhe_key(curve_id, pubKeyRaw);
                if (err != STSAFE_A_OK) {
                    STSAFE_INTERFACE_PRINTF("stsafe_create_ecdhe_key error: %d\n",
                        err);
                    err = WC_HW_E;
                }
                slot = STSAFE_KEY_SLOT_EPHEMERAL;
#else
                /* Legacy A100/A110 uses slot-based key generation */
                err = stsafe_create_key(&slot, curve_id, pubKeyRaw);
                if (err != STSAFE_A_OK) {
                    STSAFE_INTERFACE_PRINTF("stsafe_create_key error: %d\n",
                        err);
                    err = WC_HW_E;
                }
#endif
            }

            if (err == 0) {
                err = wc_ecc_import_unsigned(&tmpKey, pubKeyRaw,
                    &pubKeyRaw[key_sz], NULL, ecc_curve);
            }
            if (err == 0) {
                err = wc_ecc_export_x963(&tmpKey, pubKeyDer, pubKeySz);
            }
        }
        else if (side == WOLFSSL_SERVER_END) {
            err = wc_ecc_import_x963_ex(pubKeyDer, *pubKeySz, &tmpKey,
                ecc_curve);
            if (err == 0) {
                err = wc_ecc_export_public_raw(&tmpKey, otherKeyX,
                    &otherKeyX_len, otherKeyY, &otherKeyY_len);
            }
        }
        else {
            err = BAD_FUNC_ARG;
        }
    }

    if (err == 0) {
#ifdef WOLFSSL_STSAFEA120
        /* Use ECDHE shared secret computation for A120 */
        err = stsafe_shared_secret_ecdhe(curve_id, otherKeyX, otherKeyY,
            out, (int32_t*)outlen);
        if (err != STSAFE_A_OK) {
            STSAFE_INTERFACE_PRINTF("stsafe_shared_secret_ecdhe error: %d\n", err);
            err = WC_HW_E;
        }
#else
        /* Legacy A100/A110 uses slot-based shared secret */
        err = stsafe_shared_secret(slot, curve_id, otherKeyX, otherKeyY,
            out, (int32_t*)outlen);
        if (err != STSAFE_A_OK) {
            STSAFE_INTERFACE_PRINTF("stsafe_shared_secret error: %d\n", err);
            err = WC_HW_E;
        }
#endif
    }

    if (tmpKeyInit) {
        wc_ecc_free(&tmpKey);
    }

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    XFREE(otherKeyX, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(otherKeyY, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(pubKeyRaw, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return err;
}

/**
 * \brief Setup PK callbacks for STSAFE
 */
int SSL_STSAFE_SetupPkCallbacks(WOLFSSL_CTX* ctx)
{
    wolfSSL_CTX_SetEccKeyGenCb(ctx, SSL_STSAFE_CreateKeyCb);
    wolfSSL_CTX_SetEccSignCb(ctx, SSL_STSAFE_SignCertificateCb);
    wolfSSL_CTX_SetEccVerifyCb(ctx, SSL_STSAFE_VerifyPeerCertCb);
    wolfSSL_CTX_SetEccSharedSecretCb(ctx, SSL_STSAFE_SharedSecretCb);
    wolfSSL_CTX_SetDevId(ctx, 0);
    return 0;
}

/**
 * \brief Setup PK callback context
 */
int SSL_STSAFE_SetupPkCallbackCtx(WOLFSSL* ssl, void* user_ctx)
{
    wolfSSL_SetEccKeyGenCtx(ssl, user_ctx);
    wolfSSL_SetEccSharedSecretCtx(ssl, user_ctx);
    wolfSSL_SetEccSignCtx(ssl, user_ctx);
    wolfSSL_SetEccVerifyCtx(ssl, user_ctx);
    return 0;
}

#endif /* HAVE_PK_CALLBACKS */


/* ========================================================================== */
/* Crypto Callbacks                                                           */
/* ========================================================================== */

#ifdef WOLF_CRYPTO_CB

int wolfSSL_STSAFE_CryptoDevCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    int rc = CRYPTOCB_UNAVAILABLE;
    wolfSTSAFE_CryptoCb_Ctx* stsCtx = (wolfSTSAFE_CryptoCb_Ctx*)ctx;

    if (info == NULL || ctx == NULL) {
        rc = BAD_FUNC_ARG;
    }

    (void)devId;
    (void)stsCtx;

    if (rc != BAD_FUNC_ARG && info->algo_type == WC_ALGO_TYPE_SEED) {
    #if !defined(WC_NO_RNG) && defined(USE_STSAFE_RNG_SEED)
        rc = 0;
        while (rc == 0 && info->seed.sz > 0) {
            int len = stsafe_get_random(info->seed.seed, info->seed.sz);
            if (len < 0) {
                rc = len;
            }
            else {
                info->seed.seed += len;
                info->seed.sz -= len;
            }
        }
    #else
        rc = CRYPTOCB_UNAVAILABLE;
    #endif
    }
#ifdef HAVE_ECC
    else if (rc != BAD_FUNC_ARG && info->algo_type == WC_ALGO_TYPE_PK) {
    #ifdef USE_STSAFE_VERBOSE
        STSAFE_INTERFACE_PRINTF("STSAFE Pk: Type %d\n", info->pk.type);
    #endif

        if (info->pk.type == WC_PK_TYPE_EC_KEYGEN) {
        #if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
            byte* pubKeyRaw = NULL;
        #else
            byte pubKeyRaw[STSAFE_MAX_PUBKEY_RAW_LEN];
        #endif
            stsafe_slot_t slot;
            stsafe_curve_id_t curve_id;
            int ecc_curve, key_sz;

            WOLFSSL_MSG("STSAFE: ECC KeyGen");

            rc = 0;
        #if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
            pubKeyRaw = (byte*)XMALLOC(STSAFE_MAX_PUBKEY_RAW_LEN, NULL,
                DYNAMIC_TYPE_TMP_BUFFER);
            if (pubKeyRaw == NULL) {
                rc = MEMORY_E;
            }
        #endif

            if (rc == 0) {
                ecc_curve = info->pk.eckg.curveId;
                curve_id = stsafe_get_ecc_curve_id(ecc_curve);
                key_sz = stsafe_get_key_size(curve_id);

                /* For A120, generate keys in slot 1 (persistent slot) by default for ECDSA signing.
                 * For ECDH operations, ephemeral keys will be generated on-demand in the ECDH callback
                 * if needed (see WC_PK_TYPE_ECDH handling below). */
#ifdef WOLFSSL_STSAFEA120
                stse_ReturnCode_t ret;
                slot = STSAFE_KEY_SLOT_1;  /* Use persistent slot for ECDSA signing */
                ret = stse_generate_ecc_key_pair(&g_stse_handler, slot,
                    (stse_ecc_key_type_t)curve_id,
                    STSAFE_PERSISTENT_KEY_USAGE_LIMIT,
                    pubKeyRaw);
                if (ret != STSE_OK) {
                    STSAFE_INTERFACE_PRINTF("stse_generate_ecc_key_pair (slot 1) error: %d\n", ret);
                    rc = WC_HW_E;
                } else {
                    rc = STSAFE_A_OK;
                }
#else
                /* Legacy A100/A110 uses slot-based key generation */
                rc = stsafe_create_key(&slot, curve_id, pubKeyRaw);
                if (rc != STSAFE_A_OK) {
                    STSAFE_INTERFACE_PRINTF("stsafe_create_key error: %d\n",
                        rc);
                    rc = WC_HW_E;
                }
#endif
            }

            if (rc == 0) {
                /* Store slot number directly in devCtx (no dynamic allocation) */
                info->pk.eckg.key->devCtx = STSAFE_SLOT_TO_DEVCXT(slot);
            }

            if (rc == 0) {
                /* Import public key - preserve devCtx */
                void* saved_devCtx = info->pk.eckg.key->devCtx;
                rc = wc_ecc_import_unsigned(info->pk.eckg.key, pubKeyRaw,
                    &pubKeyRaw[key_sz], NULL, ecc_curve);
                /* Restore devCtx in case import cleared it */
                if (saved_devCtx != NULL && info->pk.eckg.key->devCtx != saved_devCtx) {
                    info->pk.eckg.key->devCtx = saved_devCtx;
                }
            }

        #if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
            XFREE(pubKeyRaw, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
        }
        else if (info->pk.type == WC_PK_TYPE_ECDSA_SIGN) {
        #if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
            byte* digest = NULL;
            byte* sigRS = NULL;
        #else
            byte digest[STSAFE_MAX_KEY_LEN];
            byte sigRS[STSAFE_MAX_SIG_LEN];
        #endif
            byte* r;
            byte* s;
            stsafe_curve_id_t curve_id;
            int ecc_curve;
            word32 inSz = info->pk.eccsign.inlen;
            int key_sz;

            WOLFSSL_MSG("STSAFE: ECC Sign");

            rc = 0;
        #if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
            digest = (byte*)XMALLOC(STSAFE_MAX_KEY_LEN, NULL,
                DYNAMIC_TYPE_TMP_BUFFER);
            sigRS = (byte*)XMALLOC(STSAFE_MAX_SIG_LEN, NULL,
                DYNAMIC_TYPE_TMP_BUFFER);
            if (digest == NULL || sigRS == NULL) {
                rc = MEMORY_E;
            }
        #endif

            if (rc == 0) {
                /* Get curve from signing key */
                if (info->pk.eccsign.key != NULL &&
                    info->pk.eccsign.key->dp != NULL) {
                    ecc_curve = info->pk.eccsign.key->dp->id;
                    curve_id = stsafe_get_ecc_curve_id(ecc_curve);
                } else {
                    curve_id = stsafe_get_curve_mode();
                }
                key_sz = stsafe_get_key_size(curve_id);

                if ((int)inSz > key_sz)
                    inSz = key_sz;

                XMEMSET(digest, 0, STSAFE_MAX_KEY_LEN);
                XMEMCPY(&digest[key_sz - inSz], info->pk.eccsign.in, inSz);

                XMEMSET(sigRS, 0, STSAFE_MAX_SIG_LEN);
                /* Retrieve slot from devCtx if available, otherwise use default */
                stsafe_slot_t slot = STSAFE_KEY_SLOT_1; /* Default fallback */
                if (info->pk.eccsign.key != NULL && info->pk.eccsign.key->devCtx != NULL) {
                    slot = STSAFE_DEVCXT_TO_SLOT(info->pk.eccsign.key->devCtx);
                    STSAFE_INTERFACE_PRINTF("STSAFE: Using slot %d from devCtx for signing\n", slot);
                } else {
                    WOLFSSL_MSG("STSAFE: Warning: devCtx not found, using default slot 1");
                }
                rc = stsafe_sign(slot, curve_id, digest, sigRS);
                if (rc != STSAFE_A_OK) {
                    STSAFE_INTERFACE_PRINTF("stsafe_sign error: %d\n", rc);
                    rc = WC_HW_E;
                }
            }

            if (rc == 0) {
                r = &sigRS[0];
                s = &sigRS[key_sz];
                rc = wc_ecc_rs_raw_to_sig(r, key_sz, s, key_sz,
                    info->pk.eccsign.out, info->pk.eccsign.outlen);
                if (rc != 0) {
                    WOLFSSL_MSG("Error converting RS to Signature");
                }
            }

        #if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
            XFREE(digest, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(sigRS, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
        }
        else if (info->pk.type == WC_PK_TYPE_ECDSA_VERIFY) {
        #if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
            byte* sigRS = NULL;
            byte* pubKeyX = NULL;
            byte* pubKeyY = NULL;
        #else
            byte sigRS[STSAFE_MAX_SIG_LEN];
            byte pubKeyX[STSAFE_MAX_PUBKEY_RAW_LEN/2];
            byte pubKeyY[STSAFE_MAX_PUBKEY_RAW_LEN/2];
        #endif
            byte* r = NULL;
            byte* s = NULL;
            word32 r_len = STSAFE_MAX_SIG_LEN/2, s_len = STSAFE_MAX_SIG_LEN/2;
            word32 pubKeyX_len = STSAFE_MAX_PUBKEY_RAW_LEN/2;
            word32 pubKeyY_len = STSAFE_MAX_PUBKEY_RAW_LEN/2;
            stsafe_curve_id_t curve_id;
            int ecc_curve, key_sz;

            WOLFSSL_MSG("STSAFE: ECC Verify");

            rc = 0;
            if (info->pk.eccverify.key == NULL ||
                info->pk.eccverify.key->dp == NULL) {
                rc = BAD_FUNC_ARG;
            }

        #if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
            if (rc == 0) {
                sigRS = (byte*)XMALLOC(STSAFE_MAX_SIG_LEN, NULL,
                    DYNAMIC_TYPE_TMP_BUFFER);
                pubKeyX = (byte*)XMALLOC(STSAFE_MAX_PUBKEY_RAW_LEN/2, NULL,
                    DYNAMIC_TYPE_TMP_BUFFER);
                pubKeyY = (byte*)XMALLOC(STSAFE_MAX_PUBKEY_RAW_LEN/2, NULL,
                    DYNAMIC_TYPE_TMP_BUFFER);
                if (sigRS == NULL || pubKeyX == NULL || pubKeyY == NULL) {
                    rc = MEMORY_E;
                }
            }
        #endif

            if (rc == 0) {
                ecc_curve = info->pk.eccverify.key->dp->id;
                curve_id = stsafe_get_ecc_curve_id(ecc_curve);
                key_sz = stsafe_get_key_size(curve_id);
                if (key_sz <= 0 || key_sz > STSAFE_MAX_KEY_LEN) {
                    rc = BAD_FUNC_ARG;
                }
            }

            if (rc == 0) {
                rc = wc_ecc_export_public_raw(info->pk.eccverify.key,
                    pubKeyX, &pubKeyX_len, pubKeyY, &pubKeyY_len);
            }
            if (rc == 0) {
                XMEMSET(sigRS, 0, STSAFE_MAX_SIG_LEN);
                r = &sigRS[0];
                s = &sigRS[key_sz];
                rc = wc_ecc_sig_to_rs(info->pk.eccverify.sig,
                    info->pk.eccverify.siglen, r, &r_len, s, &s_len);
            }
            if (rc == 0) {
                if ((int)r_len > key_sz || (int)s_len > key_sz) {
                    rc = BAD_FUNC_ARG;
                }
            }
            if (rc == 0) {
                XMEMMOVE(&sigRS[key_sz - r_len], r, r_len);
                XMEMSET(&sigRS[0], 0, key_sz - r_len);
                XMEMMOVE(&sigRS[key_sz + (key_sz - s_len)], s, s_len);
                XMEMSET(&sigRS[key_sz], 0, key_sz - s_len);

                rc = stsafe_verify(curve_id, (uint8_t*)info->pk.eccverify.hash,
                    sigRS, pubKeyX, pubKeyY, (int32_t*)info->pk.eccverify.res);
                if (rc != STSAFE_A_OK) {
                    STSAFE_INTERFACE_PRINTF("stsafe_verify error: %d\n", rc);
                    rc = WC_HW_E;
                }
            }

        #if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
            XFREE(sigRS, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(pubKeyX, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(pubKeyY, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
        }
        else if (info->pk.type == WC_PK_TYPE_ECDH) {
        #if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
            byte* otherKeyX = NULL;
            byte* otherKeyY = NULL;
        #else
            byte otherKeyX[STSAFE_MAX_KEY_LEN];
            byte otherKeyY[STSAFE_MAX_KEY_LEN];
        #endif
            word32 otherKeyX_len = STSAFE_MAX_KEY_LEN;
            word32 otherKeyY_len = STSAFE_MAX_KEY_LEN;
            stsafe_curve_id_t curve_id;
            int ecc_curve;

            WOLFSSL_MSG("STSAFE: ECDH");

            rc = 0;
            if (info->pk.ecdh.public_key == NULL) {
                rc = BAD_FUNC_ARG;
            }

        #if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
            if (rc == 0) {
                otherKeyX = (byte*)XMALLOC(STSAFE_MAX_KEY_LEN, NULL,
                    DYNAMIC_TYPE_TMP_BUFFER);
                otherKeyY = (byte*)XMALLOC(STSAFE_MAX_KEY_LEN, NULL,
                    DYNAMIC_TYPE_TMP_BUFFER);
                if (otherKeyX == NULL || otherKeyY == NULL) {
                    rc = MEMORY_E;
                }
            }
        #endif

            if (rc == 0) {
                /* Get curve from private_key (hardware key), not public_key (peer key) */
                if (info->pk.ecdh.private_key != NULL &&
                    info->pk.ecdh.private_key->dp != NULL) {
                    ecc_curve = info->pk.ecdh.private_key->dp->id;
                } else if (info->pk.ecdh.public_key != NULL &&
                           info->pk.ecdh.public_key->dp != NULL) {
                    /* Fallback to public_key if private_key not available */
                    ecc_curve = info->pk.ecdh.public_key->dp->id;
                } else {
                    rc = BAD_FUNC_ARG;
                }
                if (rc == 0) {
                    curve_id = stsafe_get_ecc_curve_id(ecc_curve);
                    /* Note: STSAFE_ECC_CURVE_P256 is 0, so we can't use STSAFE_DEFAULT_CURVE check.
                     * Instead, verify the curve_id is valid by checking it's one of the supported curves */
                    if (curve_id != STSAFE_ECC_CURVE_P256 && curve_id != STSAFE_ECC_CURVE_P384
                    #if defined(HAVE_ECC_BRAINPOOL) && defined(STSE_CONF_ECC_BRAINPOOL_P_256)
                        && curve_id != STSAFE_ECC_CURVE_BP256
                    #endif
                    #if defined(HAVE_ECC_BRAINPOOL) && defined(STSE_CONF_ECC_BRAINPOOL_P_384)
                        && curve_id != STSAFE_ECC_CURVE_BP384
                    #endif
                    ) {
                        rc = BAD_FUNC_ARG;
                    }
                }

                if (rc == 0) {
                    rc = wc_ecc_export_public_raw(info->pk.ecdh.public_key,
                        otherKeyX, &otherKeyX_len, otherKeyY, &otherKeyY_len);
                }
            }
            if (rc == 0) {
                *info->pk.ecdh.outlen = 0;

                /* Check if private key is software but public key is hardware.
                 * In this case, we can't use hardware for computation since the
                 * private key is not in a slot. Return CRYPTOCB_UNAVAILABLE to
                 * let software handle it (but software path may also fail if
                 * public key export fails). */
                if (info->pk.ecdh.private_key == NULL ||
                    info->pk.ecdh.private_key->devId == INVALID_DEVID) {
                    if (info->pk.ecdh.public_key != NULL &&
                        info->pk.ecdh.public_key->devId != INVALID_DEVID) {
                        WOLFSSL_MSG("STSAFE: Private key is software, public key is hardware - cannot use hardware");
                        rc = CRYPTOCB_UNAVAILABLE;
                    }
                }

                if (rc == 0) {
                    /* For ECDH operations, use ephemeral slot (0xFF).
                     * Keys are generated in slot 1 by default (for ECDSA signing).
                     * If the key is in slot 1, generate a new ephemeral key for ECDH.
                     * If the key is already in the ephemeral slot, use it directly. */
                    stsafe_slot_t slot;
                    stsafe_slot_t original_slot = STSAFE_KEY_SLOT_1;
                    int need_ephemeral_key = 0;

                    if (info->pk.ecdh.private_key != NULL &&
                        info->pk.ecdh.private_key->devCtx != NULL) {
                        original_slot = STSAFE_DEVCXT_TO_SLOT(info->pk.ecdh.private_key->devCtx);

                        /* If key is in slot 1 (for ECDSA), we need to generate ephemeral key for ECDH */
                        if (original_slot == STSAFE_KEY_SLOT_1) {
                            need_ephemeral_key = 1;
                        }
                    }

                    if (need_ephemeral_key) {
#ifdef WOLFSSL_STSAFEA120
                        /* Key is in slot 1 (for ECDSA), but ECDH requires ephemeral slot.
                         * Generate ephemeral key pair for ECDH. Note: This will overwrite any
                         * existing key in ephemeral slot, so for bidirectional ECDH, both keys
                         * should be generated in ephemeral slot from the start. */
                        stse_ReturnCode_t ret;
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
                        byte* ephemeralPubKey = NULL;
#else
                        byte ephemeralPubKey[STSAFE_MAX_PUBKEY_RAW_LEN];
#endif
                        int key_sz = stsafe_get_key_size(curve_id);
                        slot = STSAFE_KEY_SLOT_EPHEMERAL;

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
                        ephemeralPubKey = (byte*)XMALLOC(STSAFE_MAX_PUBKEY_RAW_LEN, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
                        if (ephemeralPubKey == NULL) {
                            rc = MEMORY_E;
                        }
#endif

                        if (rc == 0) {
                            ret = stse_generate_ecc_key_pair(&g_stse_handler, slot,
                                (stse_ecc_key_type_t)curve_id,
                                STSAFE_EPHEMERAL_KEY_USAGE_LIMIT,
                                ephemeralPubKey);
                            if (ret != STSE_OK) {
                                STSAFE_INTERFACE_PRINTF("stse_generate_ecc_key_pair (ephemeral for ECDH) error: %d\n", ret);
                                rc = (int)ret;
                            } else {
                                WOLFSSL_MSG("STSAFE: Generated ephemeral key for ECDH");
                                /* Update devCtx to reflect ephemeral slot for this key */
                                if (info->pk.ecdh.private_key != NULL) {
                                    info->pk.ecdh.private_key->devCtx = STSAFE_SLOT_TO_DEVCXT(slot);
                                }
                                /* Update the public key in the key structure to match the new ephemeral key */
                                if (info->pk.ecdh.private_key != NULL && rc == 0) {
                                    void* saved_devCtx = info->pk.ecdh.private_key->devCtx;
                                    rc = wc_ecc_import_unsigned(info->pk.ecdh.private_key,
                                        ephemeralPubKey, &ephemeralPubKey[key_sz],
                                        NULL, ecc_curve);
                                    /* Restore devCtx in case import cleared it */
                                    if (saved_devCtx != NULL && info->pk.ecdh.private_key->devCtx != saved_devCtx) {
                                        info->pk.ecdh.private_key->devCtx = saved_devCtx;
                                    }
                                }
                            }
                        }
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
                        XFREE(ephemeralPubKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
#else /* WOLFSSL_STSAFEA100 */
                        /* For A100/A110, ephemeral key generation in ECDH callback
                         * is not supported. Keys must be generated in ephemeral slot
                         * from the start for ECDH operations. */
                        WOLFSSL_MSG("STSAFE: ECDH requires ephemeral slot - key must be generated in ephemeral slot");
                        rc = WC_HW_E;
#endif
                    } else {
                        /* Key is already in ephemeral slot, use it */
                        slot = STSAFE_KEY_SLOT_EPHEMERAL;
                    }

                    if (rc == 0) {
                        STSAFE_INTERFACE_PRINTF("STSAFE: Computing shared secret with ephemeral slot %d, curve_id %d\n",
                            slot, curve_id);
                        rc = stsafe_shared_secret(slot, curve_id,
                            otherKeyX, otherKeyY,
                            info->pk.ecdh.out, (int32_t*)info->pk.ecdh.outlen);
                        if (rc != STSAFE_A_OK) {
                            WOLFSSL_MSG("STSAFE: stsafe_shared_secret failed");
                            STSAFE_INTERFACE_PRINTF("stsafe_shared_secret error: %d (slot: %d, curve_id: %d)\n",
                                rc, slot, curve_id);
                            rc = WC_HW_E;
                        }
                    }
                }
            }

        #if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
            XFREE(otherKeyX, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(otherKeyY, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
        }
    }
#endif /* HAVE_ECC */

    if (rc != 0 && rc != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
        WOLFSSL_MSG("STSAFE: CryptoCb failed");
    #ifdef USE_STSAFE_VERBOSE
        STSAFE_INTERFACE_PRINTF("STSAFE: CryptoCb failed %d\n", rc);
    #endif
        rc = WC_HW_E;
    }

    return rc;
}

#endif /* WOLF_CRYPTO_CB */

#endif /* WOLFSSL_STSAFE */
