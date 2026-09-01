/* se050_port.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <stdint.h>

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_SE050

#include <wolfssl/wolfcrypt/types.h> /* for MATH_INT_T */
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/curve25519.h>

#ifdef HAVE_HKDF
    #include <wolfssl/wolfcrypt/hmac.h>
#endif

#ifndef WOLFSSL_SE050_NO_ATTEST
    #include <wolfssl/wolfcrypt/hash.h>
    #include <wolfssl/wolfcrypt/signature.h>
#endif

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/port/nxp/se050_port.h>

#ifdef WOLFSSL_SE050_INIT
    #ifndef SE050_DEFAULT_PORT
    #define SE050_DEFAULT_PORT "/dev/i2c-1"
    #endif

    #include "ex_sss_boot.h"
    #if defined(SSS_HAVE_SE05X_AUTH_PLATFSCP03) && \
        SSS_HAVE_SE05X_AUTH_PLATFSCP03
        #include "ex_sss_auth.h"
    #endif
#endif

#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
    struct ecc_key;
    #ifndef SE050_ECC_DER_MAX
    #define SE050_ECC_DER_MAX 256
    #endif
#endif
#if !defined(NO_RSA) && (!defined(WOLFSSL_SE050_NO_RSA) || \
        !defined(WOLFSSL_SE050_NO_ATTEST))
    #include <wolfssl/wolfcrypt/rsa.h>
    struct RsaKey;
#endif
#include <wolfssl/wolfcrypt/asn.h>

#ifndef SE050_KEYID_START
#define SE050_KEYID_START 100
#endif

/* enable for debugging */
/* #define SE050_DEBUG*/
/* enable to factory erase chip */
/* #define WOLFSSL_SE050_FACTORY_RESET */

/* Global variables */
static sss_session_t *cfg_se050_i2c_pi;
static sss_key_store_t *gHostKeyStore;
static sss_key_store_t *gKeyStore;
#ifdef WOLFSSL_SE050_INIT
static ex_sss_boot_ctx_t gBootCtx;
#endif

#if defined(WOLFSSL_SE050_INIT) && \
    defined(SSS_HAVE_HOSTCRYPTO_ANY) && SSS_HAVE_HOSTCRYPTO_ANY && \
    defined(SSS_HAVE_SCP_SCP03_SSS) && SSS_HAVE_SCP_SCP03_SSS && \
    defined(SSS_HAVE_SE05X_AUTH_PLATFSCP03) && \
        SSS_HAVE_SE05X_AUTH_PLATFSCP03
    #define SE050_RUNTIME_SCP03
#endif

int wc_se050_set_config(sss_session_t *pSession, sss_key_store_t *pHostKeyStore,
    sss_key_store_t *pKeyStore)
{
    int ret;

    if ((pSession == NULL) || (pKeyStore == NULL)) {
        return BAD_FUNC_ARG;
    }
    ret = wolfSSL_CryptHwMutexInit();
    if (ret != 0) {
        return ret;
    }

    WOLFSSL_MSG("Setting SE050 session configuration");

    cfg_se050_i2c_pi = pSession;
    gHostKeyStore = pHostKeyStore;
    gKeyStore = pKeyStore;

    return 0;
}

int wc_se050_get_config(sss_session_t **pSession,
    sss_key_store_t **pHostKeyStore, sss_key_store_t **pKeyStore)
{
    if ((cfg_se050_i2c_pi == NULL) || (gKeyStore == NULL)) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }

    if (pSession != NULL) {
        *pSession = cfg_se050_i2c_pi;
    }
    if (pHostKeyStore != NULL) {
        *pHostKeyStore = gHostKeyStore;
    }
    if (pKeyStore != NULL) {
        *pKeyStore = gKeyStore;
    }

    return 0;
}

sss_session_t* wc_se050_get_session(void)
{
    return cfg_se050_i2c_pi;
}

pSe05xSession_t wc_se050_get_se05x_session(void)
{
#if SSS_HAVE_APPLET_SE05X_IOT
    if ((cfg_se050_i2c_pi != NULL) &&
            (cfg_se050_i2c_pi->subsystem == kType_SSS_SE_SE05x)) {
        return &((sss_se05x_session_t*)cfg_se050_i2c_pi)->s_ctx;
    }
#endif
    return NULL;
}

int wc_se050_lock(void)
{
    return wolfSSL_CryptHwMutexLock();
}

void wc_se050_unlock(void)
{
    wolfSSL_CryptHwMutexUnLock();
}

enum se050_policy_object_type {
    SE050_POLICY_OBJECT_ASYM,
    SE050_POLICY_OBJECT_FILE
};

#define SE050_POLICY_MAX_ENTRIES 3U

typedef struct se050_policy_set {
    sss_policy_u entries[SE050_POLICY_MAX_ENTRIES];
    sss_policy_t policy;
} se050_policy_set;

#define SE050_POLICY_COMMON_FLAGS (WC_SE050_POLICY_ALLOW_DELETE | \
    WC_SE050_POLICY_ALLOW_WRITE | WC_SE050_POLICY_ALLOW_READ | \
    WC_SE050_POLICY_REQUIRE_SM)
#define SE050_POLICY_ASYM_FLAGS (SE050_POLICY_COMMON_FLAGS | \
    WC_SE050_POLICY_ALLOW_SIGN | WC_SE050_POLICY_ALLOW_VERIFY | \
    WC_SE050_POLICY_ALLOW_ENCRYPT | WC_SE050_POLICY_ALLOW_DECRYPT | \
    WC_SE050_POLICY_ALLOW_KA | WC_SE050_POLICY_ALLOW_KD | \
    WC_SE050_POLICY_ALLOW_GEN | WC_SE050_POLICY_ALLOW_IMPORT_EXPORT | \
    WC_SE050_POLICY_ALLOW_ATTEST)

static int se050_build_policy_set(
    enum se050_policy_object_type objectType, word32 flags,
    word32 authObjId, se050_policy_set* policySet)
{
    sss_policy_u* objectPolicy;
    sss_policy_u* commonPolicy;
    word32 allowedFlags;
    word32 count = 0U;

    if (policySet == NULL) {
        return BAD_FUNC_ARG;
    }

    allowedFlags = (objectType == SE050_POLICY_OBJECT_ASYM) ?
        SE050_POLICY_ASYM_FLAGS : SE050_POLICY_COMMON_FLAGS;
    if ((flags & ~allowedFlags) != 0U) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(policySet, 0, sizeof(*policySet));
    if (flags == 0U) {
        return 0;
    }

    objectPolicy = &policySet->entries[count++];
    objectPolicy->auth_obj_id = authObjId;
    if (objectType == SE050_POLICY_OBJECT_ASYM) {
        objectPolicy->type = KPolicy_Asym_Key;
        objectPolicy->policy.asymmkey.can_Sign =
            (flags & WC_SE050_POLICY_ALLOW_SIGN) != 0U;
        objectPolicy->policy.asymmkey.can_Verify =
            (flags & WC_SE050_POLICY_ALLOW_VERIFY) != 0U;
        objectPolicy->policy.asymmkey.can_Encrypt =
            (flags & WC_SE050_POLICY_ALLOW_ENCRYPT) != 0U;
        objectPolicy->policy.asymmkey.can_Decrypt =
            (flags & WC_SE050_POLICY_ALLOW_DECRYPT) != 0U;
        objectPolicy->policy.asymmkey.can_KA =
            (flags & WC_SE050_POLICY_ALLOW_KA) != 0U;
        objectPolicy->policy.asymmkey.can_Gen =
            (flags & WC_SE050_POLICY_ALLOW_GEN) != 0U;
        objectPolicy->policy.asymmkey.can_Import_Export =
            (flags & WC_SE050_POLICY_ALLOW_IMPORT_EXPORT) != 0U;
        objectPolicy->policy.asymmkey.can_Attest =
            (flags & WC_SE050_POLICY_ALLOW_ATTEST) != 0U;
    #if !defined(SSS_HAVE_SE05X_VER_GTE_07_02) || \
        !SSS_HAVE_SE05X_VER_GTE_07_02
        objectPolicy->policy.asymmkey.can_Read =
            (flags & WC_SE050_POLICY_ALLOW_READ) != 0U;
        objectPolicy->policy.asymmkey.can_Write =
            (flags & WC_SE050_POLICY_ALLOW_WRITE) != 0U;
        objectPolicy->policy.asymmkey.can_KD =
            (flags & WC_SE050_POLICY_ALLOW_KD) != 0U;
    #else
        if ((flags & WC_SE050_POLICY_ALLOW_KD) != 0U) {
            sss_policy_u* derivePolicy = &policySet->entries[count++];

            derivePolicy->type = KPolicy_Sym_Key;
            derivePolicy->auth_obj_id = authObjId;
            derivePolicy->policy.symmkey.can_HKDF = 1;
        }
    #endif
    }
    else {
        objectPolicy->type = KPolicy_File;
        objectPolicy->policy.file.can_Read =
            (flags & WC_SE050_POLICY_ALLOW_READ) != 0U;
        objectPolicy->policy.file.can_Write =
            (flags & WC_SE050_POLICY_ALLOW_WRITE) != 0U;
    }

    commonPolicy = &policySet->entries[count++];
    commonPolicy->type = KPolicy_Common;
    commonPolicy->auth_obj_id = authObjId;
    commonPolicy->policy.common.can_Delete =
        (flags & WC_SE050_POLICY_ALLOW_DELETE) != 0U;
    commonPolicy->policy.common.req_Sm =
        (flags & WC_SE050_POLICY_REQUIRE_SM) != 0U;
#if defined(SSS_HAVE_SE05X_VER_GTE_07_02) && \
    SSS_HAVE_SE05X_VER_GTE_07_02
    if (objectType == SE050_POLICY_OBJECT_ASYM) {
        commonPolicy->policy.common.can_Read =
            (flags & WC_SE050_POLICY_ALLOW_READ) != 0U;
        commonPolicy->policy.common.can_Write =
            (flags & WC_SE050_POLICY_ALLOW_WRITE) != 0U;
    }
#endif

    policySet->policy.nPolicies = count;
    for (count = 0U; count < policySet->policy.nPolicies; count++) {
        policySet->policy.policies[count] = &policySet->entries[count];
    }

    return 0;
}

/* Called only while the shared transport mutex is held. */
static sss_status_t se050_require_new_object(word32 keyId)
{
    pSe05xSession_t session = wc_se050_get_se05x_session();
    SE05x_Result_t exists = kSE05x_Result_NA;
    smStatus_t status;

    if (session == NULL) {
        return kStatus_SSS_Fail;
    }
    status = Se05x_API_CheckObjectExists(session, keyId, &exists);
    if ((status != SM_OK) || (exists != kSE05x_Result_FAILURE)) {
        return kStatus_SSS_Fail;
    }
    return kStatus_SSS_Success;
}

#ifdef WOLFSSL_SE050_INIT
static int se050_boot_context_is_open(void)
{
    return (cfg_se050_i2c_pi != NULL) ||
        (gBootCtx.session.subsystem != kType_SSS_SubSystem_NONE);
}

static sss_key_store_t* se050_boot_host_key_store(void)
{
#if defined(SSS_HAVE_HOSTCRYPTO_ANY) && SSS_HAVE_HOSTCRYPTO_ANY
    if (gBootCtx.host_ks.session != NULL) {
        return &gBootCtx.host_ks;
    }
#endif
    return NULL;
}

#ifdef SE050_RUNTIME_SCP03
static int se050_set_scp03_static_keys(const wc_se050_scp03_keys* keys)
{
    NXSCP03_StaticCtx_t* staticCtx;
    sss_status_t status;

    if (keys == NULL) {
        return BAD_FUNC_ARG;
    }

    staticCtx = gBootCtx.se05x_open_ctx.auth.ctx.scp03.pStatic_ctx;
    if ((staticCtx == NULL) || (staticCtx->Enc.keyStore == NULL) ||
            (staticCtx->Mac.keyStore == NULL) ||
            (staticCtx->Dek.keyStore == NULL)) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }

    status = sss_host_key_store_set_key(&gBootCtx.host_ks, &staticCtx->Enc,
        keys->enc, sizeof(keys->enc), sizeof(keys->enc) * 8U, NULL, 0);
    if (status == kStatus_SSS_Success) {
        status = sss_host_key_store_set_key(&gBootCtx.host_ks,
            &staticCtx->Mac, keys->mac, sizeof(keys->mac),
            sizeof(keys->mac) * 8U, NULL, 0);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_host_key_store_set_key(&gBootCtx.host_ks,
            &staticCtx->Dek, keys->dek, sizeof(keys->dek),
            sizeof(keys->dek) * 8U, NULL, 0);
    }
    if (status != kStatus_SSS_Success) {
        return WC_HW_E;
    }

    staticCtx->key_len = (int)sizeof(keys->enc);
    return 0;
}

#ifdef WOLFSSL_SE050_SCP03_ROTATE
static int se050_set_scp03_dek(const byte* dek, word32 dekSz)
{
    NXSCP03_StaticCtx_t* staticCtx;
    sss_status_t status;

    if ((dek == NULL) ||
            (dekSz != sizeof(((wc_se050_scp03_keys*)0)->dek))) {
        return BAD_FUNC_ARG;
    }
    staticCtx = gBootCtx.se05x_open_ctx.auth.ctx.scp03.pStatic_ctx;
    if ((staticCtx == NULL) || (staticCtx->Dek.keyStore == NULL)) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }
    status = sss_host_key_store_set_key(&gBootCtx.host_ks, &staticCtx->Dek,
        dek, dekSz, dekSz * 8U, NULL, 0);
    return (status == kStatus_SSS_Success) ? 0 : WC_HW_E;
}
#endif

static sss_status_t se050_open_scp03(const char* portName,
    const wc_se050_scp03_keys* keys, int skipSelectApplet)
{
    SE_Connect_Ctx_t* connectCtx = &gBootCtx.se05x_open_ctx;
    sss_status_t status;
    int ret;

    status = ex_sss_se05x_prepare_host(&gBootCtx.host_session,
        &gBootCtx.host_ks, connectCtx, &gBootCtx.ex_se05x_auth,
        kSSS_AuthType_SCP03);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    /* PUT KEY is a Security Domain operation. NXP's reference rotation
     * application opens SCP03 with applet selection skipped, which makes the
     * transport select the SSD before INITIALIZE UPDATE. Normal wolfCrypt
     * operations must continue to select the IoT applet. */
    connectCtx->skip_select_applet = (skipSelectApplet != 0);

#if defined(SMCOM_JRCP_V1)
    if (ex_sss_boot_isSocketPortName(portName)) {
        connectCtx->connType = kType_SE_Conn_Type_JRCP_V1;
        connectCtx->portName = portName;
    }
#endif
#if defined(SMCOM_JRCP_V2)
    if (ex_sss_boot_isSocketPortName(portName)) {
        connectCtx->connType = kType_SE_Conn_Type_JRCP_V2;
        connectCtx->portName = portName;
    }
#endif
#if defined(RJCT_VCOM)
    if (ex_sss_boot_isSerialPortName(portName)) {
        connectCtx->connType = kType_SE_Conn_Type_VCOM;
        connectCtx->portName = portName;
    }
#endif
#if defined(SCI2C)
    #error "SCI2C is not a valid SE05x connection for runtime SCP03 keys"
#endif
#if defined(T1oI2C)
    connectCtx->connType = kType_SE_Conn_Type_T1oI2C;
    connectCtx->portName = portName;
#endif
#if defined(SMCOM_PCSC)
    connectCtx->connType = kType_SE_Conn_Type_PCSC;
    connectCtx->portName = portName;
#endif
#if defined(SMCOM_PN7150)
    connectCtx->connType = kType_SE_Conn_Type_NFC;
    connectCtx->portName = NULL;
#endif
#if !defined(SMCOM_JRCP_V1) && !defined(SMCOM_JRCP_V2) && \
    !defined(RJCT_VCOM) && !defined(T1oI2C) && !defined(SMCOM_PCSC) && \
    !defined(SMCOM_PN7150)
    /* wolfSSL's --with-se050 build consumes an already-configured
     * middleware and therefore does not inherit its private transport
     * define. T=1 over I2C is the port's documented/default transport. */
    connectCtx->connType = kType_SE_Conn_Type_T1oI2C;
    connectCtx->portName = portName;
#endif

    ret = se050_set_scp03_static_keys(keys);
    if (ret != 0) {
        return kStatus_SSS_Fail;
    }

    return sss_session_open(&gBootCtx.session, kType_SSS_SE_SE05x, 0,
        kSSS_ConnectionType_Encrypted, connectCtx);
}
#endif /* SE050_RUNTIME_SCP03 */

int wc_se050_init(const char* portName)
{
    int ret;
    sss_status_t status;

    if (se050_boot_context_is_open()) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }
    if (portName == NULL) {
        portName = SE050_DEFAULT_PORT;
    }

    XMEMSET(&gBootCtx, 0, sizeof(gBootCtx));
    status = ex_sss_boot_open(&gBootCtx, portName);
    if (status == kStatus_SSS_Success) {
        status = ex_sss_key_store_and_object_init(&gBootCtx);
    }
    if (status == kStatus_SSS_Success) {
#if defined(WOLFSSL_SE050_SCP03_ROTATE) && defined(SE050_RUNTIME_SCP03)
        if (gBootCtx.se05x_open_ctx.auth.authType == kSSS_AuthType_SCP03) {
            byte defaultDek[] = EX_SSS_AUTH_SE05X_KEY_DEK;

            ret = se050_set_scp03_dek(defaultDek,
                (word32)sizeof(defaultDek));
            ForceZero(defaultDek, sizeof(defaultDek));
            if (ret != 0) {
                ex_sss_session_close(&gBootCtx);
                XMEMSET(&gBootCtx, 0, sizeof(gBootCtx));
                return ret;
            }
        }
#endif
        ret = wc_se050_set_config(&gBootCtx.session,
            se050_boot_host_key_store(), &gBootCtx.ks);
        if (ret != 0) {
            ex_sss_session_close(&gBootCtx);
            XMEMSET(&gBootCtx, 0, sizeof(gBootCtx));
        }

    #ifdef WOLFSSL_SE050_FACTORY_RESET
        if (ret == 0) {
            ex_sss_boot_factory_reset(&gBootCtx);
        }
    #endif
    }
    else {
        ex_sss_session_close(&gBootCtx);
        XMEMSET(&gBootCtx, 0, sizeof(gBootCtx));
        WOLFSSL_MSG("Failed to open SE050 context");
        ret = WC_HW_E;
    }
    return ret;
}

#ifdef SE050_RUNTIME_SCP03
static int se050_init_scp03_mode(const char* portName,
    const wc_se050_scp03_keys* keys, int skipSelectApplet)
{
    sss_status_t status;
    int ret;

    if (keys == NULL) {
        return BAD_FUNC_ARG;
    }
    if (se050_boot_context_is_open()) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }
    if (portName == NULL) {
        portName = SE050_DEFAULT_PORT;
    }

    XMEMSET(&gBootCtx, 0, sizeof(gBootCtx));
    status = se050_open_scp03(portName, keys, skipSelectApplet);
    if (status == kStatus_SSS_Success) {
        status = ex_sss_key_store_and_object_init(&gBootCtx);
    }
    if (status == kStatus_SSS_Success) {
        ret = wc_se050_set_config(&gBootCtx.session,
            se050_boot_host_key_store(), &gBootCtx.ks);
        if (ret != 0) {
            ex_sss_session_close(&gBootCtx);
            XMEMSET(&gBootCtx, 0, sizeof(gBootCtx));
        }
    }
    else {
        ex_sss_session_close(&gBootCtx);
        XMEMSET(&gBootCtx, 0, sizeof(gBootCtx));
        WOLFSSL_MSG("Failed to open SE050 runtime SCP03 context");
        ret = WC_HW_E;
    }
    return ret;
}

int wc_se050_init_ex(const char* portName, const wc_se050_scp03_keys* keys)
{
    return se050_init_scp03_mode(portName, keys, 0);
}
#endif

int wc_se050_close(void)
{
    int ret;

    if (cfg_se050_i2c_pi != &gBootCtx.session) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }
    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }
    ex_sss_session_close(&gBootCtx);
    cfg_se050_i2c_pi = NULL;
    gHostKeyStore = NULL;
    gKeyStore = NULL;
    XMEMSET(&gBootCtx, 0, sizeof(gBootCtx));
    wolfSSL_CryptHwMutexUnLock();
    return 0;
}
#endif

#ifdef HAVE_HKDF
int wc_se050_scp03_derive_keys_seed(const byte* seed, word32 seedSz,
    wc_se050_scp03_keys* derivedOut)
{
    static const byte encInfo[] = "SE050 SCP03 ENC";
    static const byte macInfo[] = "SE050 SCP03 MAC";
    static const byte dekInfo[] = "SE050 SCP03 DEK";
    int ret;

    if ((seed == NULL) || (seedSz == 0U) || (derivedOut == NULL)) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(derivedOut, 0, sizeof(*derivedOut));
    ret = wc_HKDF(WC_SHA256, seed, seedSz, NULL, 0, encInfo,
        (word32)sizeof(encInfo) - 1U, derivedOut->enc,
        sizeof(derivedOut->enc));
    if (ret == 0) {
        ret = wc_HKDF(WC_SHA256, seed, seedSz, NULL, 0, macInfo,
            (word32)sizeof(macInfo) - 1U, derivedOut->mac,
            sizeof(derivedOut->mac));
    }
    if (ret == 0) {
        ret = wc_HKDF(WC_SHA256, seed, seedSz, NULL, 0, dekInfo,
            (word32)sizeof(dekInfo) - 1U, derivedOut->dek,
            sizeof(derivedOut->dek));
    }
    if (ret != 0) {
        ForceZero(derivedOut, sizeof(*derivedOut));
    }
    return ret;
}
#endif /* HAVE_HKDF */

#if defined(WOLFSSL_SE050_SCP03_ROTATE) && \
    defined(SE050_RUNTIME_SCP03)
#define SE050_SCP03_KEY_SZ       16U
#define SE050_SCP03_KCV_SZ       3U
#define SE050_SCP03_KEY_BLOCK_SZ 23U
#define SE050_SCP03_PUT_KEY_SZ \
    (1U + (3U * SE050_SCP03_KEY_BLOCK_SZ))
#define SE050_SCP03_CMD_CAPACITY \
    (SE050_SCP03_PUT_KEY_SZ + AES_BLOCK_SIZE)

static int se050_scp03_get_static_key(sss_object_t* object, byte* key,
    size_t keySz)
{
    size_t outSz = keySz;
    size_t outBits = keySz * 8U;
    sss_status_t status;

    if ((object == NULL) || (object->keyStore == NULL) || (key == NULL)) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }
    status = sss_host_key_store_get_key(&gBootCtx.host_ks, object, key,
        &outSz, &outBits);
    if ((status != kStatus_SSS_Success) || (outSz != keySz)) {
        ForceZero(key, keySz);
        return WC_HW_E;
    }
    return 0;
}

static int se050_scp03_get_static_keys(wc_se050_scp03_keys* keys)
{
    NXSCP03_StaticCtx_t* staticCtx;
    int ret;

    if (keys == NULL) {
        return BAD_FUNC_ARG;
    }
    staticCtx = gBootCtx.se05x_open_ctx.auth.ctx.scp03.pStatic_ctx;
    if (staticCtx == NULL) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }
    ret = se050_scp03_get_static_key(&staticCtx->Enc, keys->enc,
        sizeof(keys->enc));
    if (ret == 0) {
        ret = se050_scp03_get_static_key(&staticCtx->Mac, keys->mac,
            sizeof(keys->mac));
    }
    if (ret == 0) {
        ret = se050_scp03_get_static_key(&staticCtx->Dek, keys->dek,
            sizeof(keys->dek));
    }
    if (ret != 0) {
        ForceZero(keys, sizeof(*keys));
    }
    return ret;
}

static int se050_scp03_encrypt_block(const byte* key, const byte* in,
    byte* out)
{
    Aes aes;
    int ret;
    /* in/out point into byte-packed APDU command buffers and are not
     * guaranteed to be 4-byte aligned. HW-accelerated AES backends (e.g.
     * STM32_CRYPTO) cast these pointers to uint32_t* internally, so an
     * unaligned buffer here faults. Stage through aligned local buffers. */
    ALIGN16 byte alignedIn[SE050_SCP03_KEY_SZ];
    ALIGN16 byte alignedOut[SE050_SCP03_KEY_SZ];

    XMEMSET(&aes, 0, sizeof(aes));
#if defined(WOLFSSL_SE050_CRYPT) && defined(HAVE_AESGCM)
    /* SCP03 static keys are host secrets. Never route DEK wrapping or KCV
     * generation back through the secure element. */
    aes.useSWCrypt = 1;
#endif
    XMEMCPY(alignedIn, in, sizeof(alignedIn));
    ret = wc_AesSetKey(&aes, key, SE050_SCP03_KEY_SZ, NULL, AES_ENCRYPTION);
    if (ret == 0) {
        ret = wc_AesEncryptDirect(&aes, alignedOut, alignedIn);
        if (ret == 0) {
            XMEMCPY(out, alignedOut, sizeof(alignedOut));
        }
    }
    ForceZero(alignedIn, sizeof(alignedIn));
    ForceZero(alignedOut, sizeof(alignedOut));
    wc_AesFree(&aes);
    return ret;
}

static int se050_scp03_make_key_block(const byte* newKey,
    const byte* currentDek, byte* block, byte* kcv)
{
    byte checkInput[SE050_SCP03_KEY_SZ];
    int ret;

    block[0] = 0x88; /* GlobalPlatform AES key type. */
    block[1] = SE050_SCP03_KEY_SZ + 1U;
    block[2] = SE050_SCP03_KEY_SZ;
    ret = se050_scp03_encrypt_block(currentDek, newKey, &block[3]);
    if (ret == 0) {
        XMEMSET(checkInput, 1, sizeof(checkInput));
        ret = se050_scp03_encrypt_block(newKey, checkInput, kcv);
    }
    if (ret == 0) {
        block[3U + SE050_SCP03_KEY_SZ] = SE050_SCP03_KCV_SZ;
        XMEMCPY(&block[4U + SE050_SCP03_KEY_SZ], kcv,
            SE050_SCP03_KCV_SZ);
    }
    ForceZero(checkInput, sizeof(checkInput));
    return ret;
}

static int se050_scp03_put_keys(const wc_se050_scp03_keys* newKeys,
    byte keyVersion, int* keysChanged)
{
    byte cmd[SE050_SCP03_CMD_CAPACITY];
    byte expected[1U + (3U * SE050_SCP03_KCV_SZ)];
    byte response[64];
    byte currentDek[SE050_SCP03_KEY_SZ];
    size_t responseSz = sizeof(response);
    size_t currentDekSz = sizeof(currentDek);
    size_t currentDekBits = sizeof(currentDek) * 8U;
    NXSCP03_StaticCtx_t* staticCtx;
    sss_se05x_session_t* session;
    tlvHeader_t header = {{0x80, 0xD8, 0, 0x81}};
    sss_status_t status;
    smStatus_t smStatus;
    word32 i;
    int ret;

    if ((newKeys == NULL) || (keysChanged == NULL)) {
        return BAD_FUNC_ARG;
    }
    *keysChanged = 0;
    if ((cfg_se050_i2c_pi != &gBootCtx.session) ||
            (gBootCtx.session.subsystem != kType_SSS_SE_SE05x) ||
            (gBootCtx.se05x_open_ctx.auth.authType != kSSS_AuthType_SCP03) ||
            (gBootCtx.se05x_open_ctx.skip_select_applet != 1)) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }

    staticCtx = gBootCtx.se05x_open_ctx.auth.ctx.scp03.pStatic_ctx;
    if ((staticCtx == NULL) || (staticCtx->Dek.keyStore == NULL)) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }

    status = sss_host_key_store_get_key(&gBootCtx.host_ks,
        &staticCtx->Dek, currentDek, &currentDekSz, &currentDekBits);
    if ((status != kStatus_SSS_Success) ||
            (currentDekSz != sizeof(currentDek))) {
        ForceZero(currentDek, sizeof(currentDek));
        return WC_HW_E;
    }

    cmd[0] = keyVersion;
    expected[0] = keyVersion;
    for (i = 0; i < 3U; i++) {
        const byte* key = (i == 0U) ? newKeys->enc :
            ((i == 1U) ? newKeys->mac : newKeys->dek);
        byte kcv[SE050_SCP03_KEY_SZ];

        ret = se050_scp03_make_key_block(key, currentDek,
            &cmd[1U + (i * SE050_SCP03_KEY_BLOCK_SZ)], kcv);
        if (ret != 0) {
            ForceZero(kcv, sizeof(kcv));
            ForceZero(currentDek, sizeof(currentDek));
            ForceZero(cmd, sizeof(cmd));
            return ret;
        }
        XMEMCPY(&expected[1U + (i * SE050_SCP03_KCV_SZ)], kcv,
            SE050_SCP03_KCV_SZ);
        ForceZero(kcv, sizeof(kcv));
    }
    ForceZero(currentDek, sizeof(currentDek));

    header.hdr[2] = keyVersion;
    session = (sss_se05x_session_t*)&gBootCtx.session;
    ret = wc_se050_lock();
    if (ret == 0) {
        smStatus = DoAPDUTxRx_s_Case4(&session->s_ctx, &header, cmd,
            SE050_SCP03_PUT_KEY_SZ, response, &responseSz);
        wc_se050_unlock();
    }
    else {
        smStatus = SM_NOT_OK;
    }
    ForceZero(cmd, sizeof(cmd));

    if ((ret != 0) || (smStatus != SM_OK) || (responseSz < 2U) ||
            ((((word32)response[responseSz - 2U] << 8) |
               response[responseSz - 1U]) != SM_OK)) {
        ForceZero(expected, sizeof(expected));
        ForceZero(response, sizeof(response));
        return WC_HW_E;
    }
    /* A successful status means the Security Domain has committed the key
     * set, even if the response below is malformed or its KCV echo does not
     * match. The caller must reconnect with newKeys in that case. */
    *keysChanged = 1;
    if (responseSz < (sizeof(expected) + 2U)) {
        ForceZero(expected, sizeof(expected));
        ForceZero(response, sizeof(response));
        return WC_HW_E;
    }
    if (ConstantCompare(response, expected, sizeof(expected)) != 0) {
        ForceZero(expected, sizeof(expected));
        ForceZero(response, sizeof(response));
        return AES_GCM_AUTH_E;
    }
    ForceZero(expected, sizeof(expected));
    ForceZero(response, sizeof(response));

    return 0;
}

int wc_se050_scp03_rotate_keys(const wc_se050_scp03_keys* newKeys,
    byte keyVersion)
{
    wc_se050_scp03_keys currentKeys;
    const wc_se050_scp03_keys* reopenKeys;
    const char* portName;
    int keysChanged = 0;
    int closeRet;
    int reopenRet;
    int ret;

    if (newKeys == NULL) {
        return BAD_FUNC_ARG;
    }
    if ((cfg_se050_i2c_pi != &gBootCtx.session) ||
            (gBootCtx.session.subsystem != kType_SSS_SE_SE05x) ||
            (gBootCtx.se05x_open_ctx.auth.authType != kSSS_AuthType_SCP03) ||
            (gBootCtx.se05x_open_ctx.skip_select_applet != 0)) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }

    portName = gBootCtx.se05x_open_ctx.portName;
    ret = se050_scp03_get_static_keys(&currentKeys);
    if (ret != 0) {
        return ret;
    }

    /* Platform SCP03 protects both the IoT applet and its Security Domain,
     * but PUT KEY is accepted only by the latter. Reopen against the SSD for
     * the update, then always return to a fresh IoT applet session. */
    ret = wc_se050_close();
    if (ret == 0) {
        ret = se050_init_scp03_mode(portName, &currentKeys, 1);
    }
    if (ret == 0) {
        ret = se050_scp03_put_keys(newKeys, keyVersion, &keysChanged);
        closeRet = wc_se050_close();
        if (closeRet != 0) {
            ret = closeRet;
        }
    }

    if (gBootCtx.session.subsystem == kType_SSS_SubSystem_NONE) {
        reopenKeys = (keysChanged != 0) ? newKeys : &currentKeys;
        reopenRet = se050_init_scp03_mode(portName, reopenKeys, 0);
        if (reopenRet != 0) {
            ret = reopenRet;
        }
    }
    ForceZero(&currentKeys, sizeof(currentKeys));
    return ret;
}

#ifdef HAVE_HKDF
int wc_se050_scp03_rotate_keys_seed(const byte* seed, word32 seedSz,
    byte keyVersion, wc_se050_scp03_keys* derivedOut)
{
    wc_se050_scp03_keys keys;
    int ret;

    ret = wc_se050_scp03_derive_keys_seed(seed, seedSz, &keys);
    if ((ret == 0) && (derivedOut != NULL)) {
        XMEMCPY(derivedOut, &keys, sizeof(keys));
    }
    if (ret == 0) {
        ret = wc_se050_scp03_rotate_keys(&keys, keyVersion);
    }
    ForceZero(&keys, sizeof(keys));
    return ret;
}
#endif /* HAVE_HKDF */
#endif /* WOLFSSL_SE050_SCP03_ROTATE && SE050_RUNTIME_SCP03 */

/**
 * Erase and free an object stored in SE050.
 *
 * keyId  ID of object to erase
 *
 * Returns 0 on success, negative on error.
 */
int wc_se050_erase_object(word32 id)
{
    int ret = 0;
    sss_object_t    object;
    sss_key_store_t host_keystore;
    sss_status_t    status = kStatus_SSS_Success;

#ifdef SE050_DEBUG
    printf("wc_se050_erase_object: id %d\n", id);
#endif

    if (cfg_se050_i2c_pi == NULL) {
        return BAD_FUNC_ARG;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore,
                                        SE050_KEYSTOREID_GENERIC);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&object, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_get_handle(&object, id);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_erase_key(&host_keystore, &object);
        sss_key_object_free(&object);
    }
    wolfSSL_CryptHwMutexUnLock();

    if (status != kStatus_SSS_Success) {
        ret = WC_HW_E;
    }

    return ret;
}

word32 se050_allocate_key(int keyType)
{
    word32 keyId = 0;
    static word32 keyId_allocator = SE050_KEYID_START;
    switch (keyType) {
        case SE050_AES_KEY:
        case SE050_ECC_KEY:
        case SE050_RSA_KEY:
        case SE050_ED25519_KEY:
        case SE050_CURVE25519_KEY:
        case SE050_ANY_KEY:
            keyId = keyId_allocator++;
            break;
    }
#ifdef SE050_DEBUG
    printf("se050_allocate_key: keyId %d\n", keyId);
#endif
    return keyId;
}

#if !defined(WC_NO_RNG) && !defined(WOLFSSL_SE050_NO_TRNG)
int se050_get_random_number(uint32_t count, uint8_t* rand_out)
{
    int ret = 0;
    sss_status_t status;
    sss_rng_context_t rng;

#ifdef SE050_DEBUG
    printf("se050_get_random_number: %p (%d)\n", rand_out, count);
#endif

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }
    status = sss_rng_context_init(&rng, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_rng_get_random(&rng, rand_out, count);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_rng_context_free(&rng);
    }
    if (status != kStatus_SSS_Success) {
        ret = RNG_FAILURE_E;
    }

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}
#endif /* !WC_NO_RNG && !WOLFSSL_SE050_NO_TRNG */

#ifdef WOLFSSL_SE050_HASH

/* Used for sha/sha224/sha384/sha512 */
int se050_hash_init(SE050_HASH_Context* se050Ctx, void* heap)
{
    se050Ctx->heap = heap;
    se050Ctx->len  = 0;
    se050Ctx->used = 0;
    se050Ctx->msg  = NULL;
    return 0;
}

int se050_hash_copy(SE050_HASH_Context* src, SE050_HASH_Context* dst)
{
    if (src == NULL || dst == NULL || (src->used != dst->used)) {
        return BAD_FUNC_ARG;
    }

    if (src->used > 0) {
        /* dst->msg points to same buffer as src->msg, needs to be allocated
         * and dep copied over instead of plain pointer copy */
        dst->msg = (byte*)XMALLOC(src->used, dst->heap,
                                  DYNAMIC_TYPE_TMP_BUFFER);
        if (dst->msg == NULL) {
            PRINTF("Tried to allocate %d bytes\n", dst->used);
            return MEMORY_E;
        }
        XMEMSET(dst->msg, 0, dst->used);
        XMEMCPY(dst->msg, src->msg, src->used);
        dst->used = src->used;
        dst->len = src->used;
    } else {
        dst->msg = NULL;
        dst->len = 0;
        dst->used = 0;
    }

    return 0;
}

int se050_hash_update(SE050_HASH_Context* se050Ctx, const byte* data, word32 len)
{
    byte* tmp = NULL;
    word32 usedSz = 0;

    if (se050Ctx == NULL || (len > 0 && data == NULL) || (len == 0) ||
        !WC_SAFE_SUM_WORD32(se050Ctx->used, len, usedSz)) {
        return BAD_FUNC_ARG;
    }

    if (se050Ctx->len < usedSz) {
        if (se050Ctx->msg == NULL) {
            se050Ctx->msg = (byte*)XMALLOC(usedSz,
                se050Ctx->heap, DYNAMIC_TYPE_TMP_BUFFER);
            if (se050Ctx->msg == NULL) {
                return MEMORY_E;
            }
            XMEMSET(se050Ctx->msg, 0, usedSz);
        }
        else {
            tmp = (byte*)XMALLOC(usedSz, se050Ctx->heap,
                                 DYNAMIC_TYPE_TMP_BUFFER);
            if (tmp == NULL) {
                return MEMORY_E;
            }
            XMEMSET(tmp, 0, usedSz);
            XMEMCPY(tmp, se050Ctx->msg, se050Ctx->used);
            XFREE(se050Ctx->msg, se050Ctx->heap, DYNAMIC_TYPE_TMP_BUFFER);
            se050Ctx->msg = tmp;
        }
        se050Ctx->len = usedSz;
    }

    XMEMCPY(se050Ctx->msg + se050Ctx->used, data, len);
    se050Ctx->used += len;

    return 0;
}

int se050_hash_final(SE050_HASH_Context* se050Ctx, byte* hash, size_t digestLen,
    sss_algorithm_t algo)
{
    int          ret;
    sss_status_t status;
    sss_digest_t digest_ctx;
    const byte*  data = se050Ctx->msg;
    int          size = (se050Ctx->used) / SSS_BLOCK_SIZE;
    int          leftover = (se050Ctx->used) % SSS_BLOCK_SIZE;
    const byte*  blocks = data;

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    status = sss_digest_context_init(&digest_ctx, cfg_se050_i2c_pi, algo,
        kMode_SSS_Digest);
    if (status == kStatus_SSS_Success) {
        status = sss_digest_init(&digest_ctx);
    }
    if (status == kStatus_SSS_Success) {
        /* used to send chunks of size 512 */
        while (status == kStatus_SSS_Success && size--) {
            status = sss_digest_update(&digest_ctx, blocks, SSS_BLOCK_SIZE);
            blocks += SSS_BLOCK_SIZE;
        }
        if (status == kStatus_SSS_Success && leftover) {
            status = sss_digest_update(&digest_ctx, blocks, leftover);
        }
        if (status == kStatus_SSS_Success) {
            status = sss_digest_finish(&digest_ctx, hash, &digestLen);
        }
        sss_digest_context_free(&digest_ctx);
    }

    if (status == kStatus_SSS_Success) {
        /* reset state */
        XFREE(se050Ctx->msg, se050Ctx->heap, DYNAMIC_TYPE_TMP_BUFFER);
        ret = se050_hash_init(se050Ctx, se050Ctx->heap);
    } else {
        ret = WC_HW_E;
    }

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

void se050_hash_free(SE050_HASH_Context* se050Ctx)
{
    XFREE(se050Ctx->msg, se050Ctx->heap, DYNAMIC_TYPE_TMP_BUFFER);
    se050Ctx->msg = NULL;
    se050Ctx->len  = 0;
    se050Ctx->used = 0;
}

#endif /* WOLFSSL_SE050_HASH */

#if defined(WOLFSSL_SE050_CRYPT) && !defined(NO_AES)

int se050_aes_set_key(Aes* aes, const byte* key, word32 keylen,
                                        const byte* iv, int dir)
{
    int ret = 0;
    sss_status_t status;
    sss_object_t newKey;
    sss_key_store_t host_keystore;
    word32 keyId;
    int keyCreated = 0;

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    (void)dir;
    (void)iv;

    aes->rounds = keylen/4 + 6;

    /* free existing key in slot first before storing new one */
    ret = wc_se050_erase_object(aes->keyId);
    if (ret != 0) {
        wolfSSL_CryptHwMutexUnLock();
        return ret;
    }
    aes->keyIdSet = 0;

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore, SE050_KEYSTOREID_AES);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&newKey, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        keyId = se050_allocate_key(SE050_AES_KEY);
        status = sss_key_object_allocate_handle(&newKey, keyId,
            kSSS_KeyPart_Default, kSSS_CipherType_AES, keylen,
            kKeyObject_Mode_Transient);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_set_key(&host_keystore, &newKey, key, keylen,
                                    keylen * 8, NULL, 0);
    }

    if (status == kStatus_SSS_Success) {
        keyCreated = 1;
        aes->keyId = keyId;
        aes->keyIdSet = 1;
        ret = 0;
    }
    else {
        if (keyCreated) {
            sss_key_store_erase_key(&host_keystore, &newKey);
            sss_key_object_free(&newKey);
        }
        ret = WC_HW_E;
    }

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

int se050_aes_crypt(Aes* aes, const byte* in, byte* out, word32 sz, int dir,
    sss_algorithm_t algorithm)
{
    int             ret = 0;
    sss_status_t    status;
    sss_object_t    keyObject;
    sss_key_store_t host_keystore;

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }
    if (aes->keyIdSet == 0) {
        return BAD_FUNC_ARG;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore, SE050_KEYSTOREID_AES);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&keyObject, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_get_handle(&keyObject, aes->keyId);
    }

    /* The first call to this function needs an initialization call,
        * subsequent calls just need to call update */
    if (status == kStatus_SSS_Success && aes->ctxInitDone == 0) {
        sss_mode_t      mode;

        XMEMSET(&mode, 0, sizeof(mode));
        if (dir == AES_DECRYPTION)
            mode = kMode_SSS_Decrypt;
        else if (dir == AES_ENCRYPTION)
            mode = kMode_SSS_Encrypt;

        if (status == kStatus_SSS_Success) {
            status = sss_symmetric_context_init(&aes->aes_ctx,
                cfg_se050_i2c_pi, &keyObject, algorithm, mode);
        }
        if (status == kStatus_SSS_Success) {
            aes->ctxInitDone = 1;
            status = sss_cipher_init(&aes->aes_ctx, (uint8_t*)aes->reg,
                sizeof(aes->reg));
        }
    }
    if (status == kStatus_SSS_Success) {
        size_t outSz = (size_t)sz;
        status = sss_cipher_update(&aes->aes_ctx, in, sz, out, &outSz);
    }

    ret = (status == kStatus_SSS_Success) ? 0 : WC_HW_E;

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

void se050_aes_free(Aes* aes)
{
    if (aes == NULL) {
        return;
    }

    if (aes->ctxInitDone) {
        sss_symmetric_context_free(&aes->aes_ctx);

        /* sets back to zero to indicate that a free has been called */
        aes->ctxInitDone = 0;
    }

    aes->keyId = 0;
    aes->keyIdSet = 0;
}

#endif /* WOLFSSL_SE050_CRYPT && !NO_AES */

/**
 * Get size of a SE05X secure object at specified object ID.
 *
 * keystore  SE050 keystore associated with object
 * keyId     SE050 key ID in which object is stored
 *
 * Size returned depends on object type:
 *   ECC key: curve size
 *   RSA/AES/DES/HMAC key: key size
 *   Binary file: file size
 *
 * Return size or negative on error
 */
static int se050_get_object_size(sss_key_store_t* keystore, word32 keyId)
{
    uint16_t size = 0;
    smStatus_t status = SM_NOT_OK;
    sss_se05x_key_store_t* se05x_keystore = NULL;

    if (keystore == NULL) {
        return BAD_FUNC_ARG;
    }

    se05x_keystore = (sss_se05x_key_store_t*)keystore;
    status = Se05x_API_ReadSize(&se05x_keystore->session->s_ctx,
                                keyId, &size);
    if (status != SM_OK) {
        return WC_HW_E;
    }

    return (int)size;
}

/**
 * Insert binary object into SE050 as persistent object.
 *
 * keyId       SE050 key ID to store object in
 * object      binary object data
 * objectSz    size of binary object, bytes
 *
 * Returns 0 on success, negative on error
 */
static int se050_insert_binary_object(word32 keyId, const byte* object,
    word32 objectSz, const sss_policy_t* policy, int requireNew)
{
    int             ret = 0;
    sss_object_t    newObj;
    sss_key_store_t host_keystore;
    sss_status_t    status = kStatus_SSS_Success;

    if ((cfg_se050_i2c_pi == NULL) || (object == NULL) || (objectSz == 0U)) {
        return BAD_FUNC_ARG;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    /* Avoid key ID conflicts with temporary key storage */
    if (keyId >= SE050_KEYID_START) {
        wolfSSL_CryptHwMutexUnLock();
        return BAD_FUNC_ARG;
    }

    if (requireNew) {
        status = se050_require_new_object(keyId);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_context_init(&host_keystore,
            cfg_se050_i2c_pi);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&newObj, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_allocate_handle(&newObj, keyId,
            kSSS_KeyPart_Default, kSSS_CipherType_Binary, objectSz,
            kKeyObject_Mode_Persistent);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_set_key(&host_keystore, &newObj, object,
            objectSz, (objectSz * 8), (void*)policy, 0);
    }
    wolfSSL_CryptHwMutexUnLock();

    if (status != kStatus_SSS_Success) {
        ret = WC_HW_E;
    }

    return ret;
}

int wc_se050_insert_binary_object_policy(word32 keyId, const byte* object,
    word32 objectSz, const sss_policy_t* policy)
{
    return se050_insert_binary_object(keyId, object, objectSz, policy, 0);
}

int wc_se050_insert_binary_object_ex(word32 keyId, const byte* object,
    word32 objectSz, word32 policyFlags, word32 authObjId)
{
    int ret;
    const sss_policy_t* policy = NULL;
    se050_policy_set policySet;

    ret = se050_build_policy_set(SE050_POLICY_OBJECT_FILE, policyFlags,
        authObjId, &policySet);
    if (ret != 0) {
        return ret;
    }
    if (policyFlags != 0U) {
        policy = &policySet.policy;
    }
    return se050_insert_binary_object(keyId, object, objectSz, policy, 1);
}

int wc_se050_insert_binary_object(word32 keyId, const byte* object,
    word32 objectSz)
{
    return wc_se050_insert_binary_object_policy(keyId, object, objectSz,
        NULL);
}

/**
 * Get binary object from SE050 from specified key ID.
 *
 * keyId  SE050 key ID to get binary object from
 * out    output buffer to place binary object
 * outSz  size of output buffer on input, size of written object on output
 *
 * Returns 0 on success, LENGTH_ONLY_E if out is NULL with outSz set to
 * required buffer size, and other negative on error.
 */
int wc_se050_get_binary_object(word32 keyId, byte* out, word32* outSz)
{
    int             ret = 0;
    sss_object_t    object;
    sss_key_store_t host_keystore;
    sss_status_t    status = kStatus_SSS_Success;
    size_t outBitSz = 0;

    /* If out is NULL, outSz set to required size and LENGTH_ONLY_E returned */
    if (outSz == NULL) {
        return BAD_FUNC_ARG;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&object, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        ret = se050_get_object_size(&host_keystore, keyId);
        if (ret < 0) {
            status = kStatus_SSS_Fail;
        }
        else {
            if (out == NULL) {
                *outSz = ret;
                wolfSSL_CryptHwMutexUnLock();
                return WC_NO_ERR_TRACE(LENGTH_ONLY_E);
            }
            if ((word32)ret > *outSz) {
                WOLFSSL_MSG("Output buffer not large enough for object");
                wolfSSL_CryptHwMutexUnLock();
                return BAD_LENGTH_E;
            }
            ret = 0;
        }
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_get_handle(&object, keyId);
    }
    if (status == kStatus_SSS_Success) {
        outBitSz = (*outSz) * 8;
        status = sss_key_store_get_key(&host_keystore, &object, out,
                                       (size_t*)outSz, &outBitSz);
    }
    wolfSSL_CryptHwMutexUnLock();

    if (status != kStatus_SSS_Success) {
        ret = WC_HW_E;
    }

    return ret;
}

int wc_se050_get_object_attributes(word32 keyId, byte* attr, word32* attrSz)
{
#if defined(SSS_HAVE_SE05X_VER_GTE_07_02) && \
    SSS_HAVE_SE05X_VER_GTE_07_02
    pSe05xSession_t session;
    smStatus_t status;
    size_t size;

    if ((attr == NULL) || (attrSz == NULL) || (*attrSz == 0U)) {
        return BAD_FUNC_ARG;
    }
    if (cfg_se050_i2c_pi == NULL) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }
    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    session = wc_se050_get_se05x_session();
    if (session == NULL) {
        wolfSSL_CryptHwMutexUnLock();
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }

    size = *attrSz;
    status = Se05x_API_ReadObjectAttributes(session, keyId, attr, &size);
    *attrSz = (word32)size;
    wolfSSL_CryptHwMutexUnLock();

    return (status == SM_OK) ? 0 : WC_HW_E;
#else
    (void)keyId;
    (void)attr;
    (void)attrSz;
    return WC_NO_ERR_TRACE(NOT_COMPILED_IN);
#endif
}

#ifndef WOLFSSL_SE050_NO_ATTEST

#define SE050_ATTEST_RANDOM_SIZE 16U
#define SE050_ATTR_FIXED_SIZE    14U
#define SE050_ATTR_POLICY_MIN    8U
#define SE050_TLV_OVERHEAD       4U

static word32 se050_get_u32(const byte* in)
{
    return ((word32)in[0] << 24) | ((word32)in[1] << 16) |
        ((word32)in[2] << 8) | (word32)in[3];
}

static int se050_attest_algorithm(enum wc_HashType hashAlgo,
    word32 cipherType, sss_algorithm_t* algorithm)
{
    int isRsa;

    if (algorithm == NULL) {
        return BAD_FUNC_ARG;
    }

    isRsa = (cipherType == (word32)kSSS_CipherType_RSA) ||
        (cipherType == (word32)kSSS_CipherType_RSA_CRT);

    if (hashAlgo == WC_HASH_TYPE_SHA) {
        *algorithm = isRsa ? kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA1 :
            kAlgorithm_SSS_ECDSA_SHA1;
    }
    else if (hashAlgo == WC_HASH_TYPE_SHA224) {
        *algorithm = isRsa ? kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA224 :
            kAlgorithm_SSS_ECDSA_SHA224;
    }
    else if (hashAlgo == WC_HASH_TYPE_SHA256) {
        *algorithm = isRsa ? kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256 :
            kAlgorithm_SSS_ECDSA_SHA256;
    }
    else if (hashAlgo == WC_HASH_TYPE_SHA384) {
        *algorithm = isRsa ? kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA384 :
            kAlgorithm_SSS_ECDSA_SHA384;
    }
    else if (hashAlgo == WC_HASH_TYPE_SHA512) {
        *algorithm = isRsa ? kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA512 :
            kAlgorithm_SSS_ECDSA_SHA512;
    }
    else {
        return BAD_FUNC_ARG;
    }

    if (!isRsa &&
            (cipherType != (word32)kSSS_CipherType_EC_NIST_P) &&
            (cipherType != (word32)kSSS_CipherType_EC_NIST_K) &&
            (cipherType != (word32)kSSS_CipherType_EC_BRAINPOOL)) {
        return BAD_FUNC_ARG;
    }

    return 0;
}

static void se050_parse_attested_attributes(const byte* attr, word32 attrSz,
    wc_se050_attst_result* result)
{
    word32 i;
    word32 authId = 0U;
    word32 header;
    word32 flags = 0U;
    word32 entryLen;
    int haveAuthId = 0;

    if ((attr == NULL) || (result == NULL) ||
            (attrSz < (SE050_ATTR_FIXED_SIZE + 1U))) {
        return;
    }

    i = SE050_ATTR_FIXED_SIZE;
    while ((i < attrSz) && (attr[i] >= SE050_ATTR_POLICY_MIN)) {
        entryLen = attr[i];
        if ((entryLen > (attrSz - i - 1U)) || (entryLen < 8U)) {
            return;
        }
        if (!haveAuthId) {
            authId = se050_get_u32(attr + i + 1U);
            haveAuthId = 1;
        }
        header = se050_get_u32(attr + i + 5U);
        if ((header & 0x00040000U) != 0U)
            flags |= WC_SE050_POLICY_ALLOW_DELETE;
        if ((header & 0x00100000U) != 0U)
            flags |= WC_SE050_POLICY_ALLOW_WRITE;
        if ((header & 0x00200000U) != 0U)
            flags |= WC_SE050_POLICY_ALLOW_READ;
        if ((header & 0x10000000U) != 0U)
            flags |= WC_SE050_POLICY_ALLOW_SIGN;
        if ((header & 0x08000000U) != 0U)
            flags |= WC_SE050_POLICY_ALLOW_VERIFY;
        if ((header & 0x02000000U) != 0U)
            flags |= WC_SE050_POLICY_ALLOW_ENCRYPT;
        if ((header & 0x01000000U) != 0U)
            flags |= WC_SE050_POLICY_ALLOW_DECRYPT;
        if ((header & 0x04000000U) != 0U)
            flags |= WC_SE050_POLICY_ALLOW_KA;
        if ((header & 0x00800000U) != 0U)
            flags |= WC_SE050_POLICY_ALLOW_KD;
        if ((header & 0x00080000U) != 0U)
            flags |= WC_SE050_POLICY_ALLOW_GEN;
        if ((header & 0x00001000U) != 0U)
            flags |= WC_SE050_POLICY_ALLOW_IMPORT_EXPORT;
        if ((header & 0x00008000U) != 0U)
            flags |= WC_SE050_POLICY_ALLOW_ATTEST;
        if ((header & 0x00020000U) != 0U)
            flags |= WC_SE050_POLICY_REQUIRE_SM;
        i += entryLen + 1U;
    }

    if (i < attrSz) {
        result->origin = attr[i];
    }
    result->authObjId = authId;
    result->policyFlags = flags;
}

int wc_se050_attest_object(word32 keyId, word32 attestKeyId,
    enum wc_HashType hashAlgo, const byte* random, word32 randomSz,
    wc_se050_attst_result* result)
{
    int ret = 0;
    int i;
    byte generatedRandom[SE050_ATTEST_RANDOM_SIZE];
    const byte* freshness = random;
    word32 freshnessSz = randomSz;
    size_t valueSz;
    size_t valueBitSz = 0;
    sss_algorithm_t algorithm = kAlgorithm_None;
    sss_key_store_t keyStore;
    sss_object_t object;
    sss_object_t attestObject;
    sss_se05x_object_t* seObject;
    sss_se05x_object_t* seAttestObject;
    sss_status_t status = kStatus_SSS_Fail;

    if ((result == NULL) || (keyId == attestKeyId) ||
            ((random == NULL) && (randomSz != 0U)) ||
            ((random != NULL) && (randomSz != SE050_ATTEST_RANDOM_SIZE))) {
        return BAD_FUNC_ARG;
    }
    if (cfg_se050_i2c_pi == NULL) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }

    if (freshness == NULL) {
    #if !defined(WC_NO_RNG) && !defined(WOLFSSL_SE050_NO_TRNG)
        ret = se050_get_random_number((word32)sizeof(generatedRandom),
            generatedRandom);
        if (ret != 0) {
            return ret;
        }
        freshness = generatedRandom;
        freshnessSz = (word32)sizeof(generatedRandom);
    #else
        return WC_NO_ERR_TRACE(NOT_COMPILED_IN);
    #endif
    }

    XMEMSET(result, 0, sizeof(*result));
    result->hashAlgo = hashAlgo;
    XMEMCPY(result->freshness, freshness, SE050_ATTEST_RANDOM_SIZE);
    for (i = 0; i < SE05X_MAX_ATTST_DATA; i++) {
        result->raw.data[i].attributeLen =
            sizeof(result->raw.data[i].attribute);
        result->raw.data[i].chipIdLen = sizeof(result->raw.data[i].chipId);
        result->raw.data[i].signatureLen =
            sizeof(result->raw.data[i].signature);
        result->raw.data[i].timeStampLen =
            sizeof(result->raw.data[i].timeStamp);
    #if SSS_HAVE_SE05X_VER_GTE_07_02
        result->raw.data[i].cmdLen = sizeof(result->raw.data[i].cmd);
        result->raw.data[i].objSizeLen =
            sizeof(result->raw.data[i].objSize);
    #else
        result->raw.data[i].outrandomLen =
            sizeof(result->raw.data[i].outrandom);
    #endif
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    status = sss_key_store_context_init(&keyStore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success)
        status = sss_key_object_init(&object, &keyStore);
    if (status == kStatus_SSS_Success)
        status = sss_key_object_get_handle(&object, keyId);
    if (status == kStatus_SSS_Success)
        status = sss_key_object_init(&attestObject, &keyStore);
    if (status == kStatus_SSS_Success)
        status = sss_key_object_get_handle(&attestObject, attestKeyId);

    seObject = (sss_se05x_object_t*)&object;
    seAttestObject = (sss_se05x_object_t*)&attestObject;
    if (status == kStatus_SSS_Success) {
        ret = se050_attest_algorithm(hashAlgo, seAttestObject->cipherType,
            &algorithm);
        if (ret != 0)
            status = kStatus_SSS_Fail;
    }
    if (status == kStatus_SSS_Success) {
        result->cipherType = seObject->cipherType;
        result->objectType = seObject->objectType;
        result->curveId = seObject->curve_id;
        valueSz = sizeof(result->value);
        status = sss_se05x_key_store_get_key_attst(
            (sss_se05x_key_store_t*)&keyStore, seObject, result->value,
            &valueSz, &valueBitSz, seAttestObject, algorithm,
            (byte*)freshness, freshnessSz, &result->raw);
        if (status == kStatus_SSS_Success) {
            result->valueSz = (word32)valueSz;
        }
    }
    wolfSSL_CryptHwMutexUnLock();

    ForceZero(generatedRandom, sizeof(generatedRandom));
    if (status != kStatus_SSS_Success) {
        return (ret != 0) ? ret : WC_HW_E;
    }
    if ((result->raw.valid_number == 0U) ||
            (result->raw.valid_number > SE05X_MAX_ATTST_DATA)) {
        return WC_HW_E;
    }

    se050_parse_attested_attributes(result->raw.data[0].attribute,
        (word32)result->raw.data[0].attributeLen, result);
    return 0;
}

static int se050_attested_component(const wc_se050_attst_result* result,
    word32 componentIndex, byte* component, word32* componentSz)
{
    int ret;

    if ((result == NULL) || (component == NULL) || (componentSz == NULL) ||
            (componentIndex >= result->raw.valid_number)) {
        return BAD_FUNC_ARG;
    }

    if ((result->cipherType == (word32)kSSS_CipherType_RSA) ||
            (result->cipherType == (word32)kSSS_CipherType_RSA_CRT)) {
    #ifndef NO_RSA
        RsaKey key;
        word32 idx = 0;
        byte exponent[8];
        word32 exponentSz = sizeof(exponent);
        word32 modulusSz = *componentSz;

        ret = wc_InitRsaKey(&key, NULL);
        if (ret == 0)
            ret = wc_RsaPublicKeyDecode(result->value, &idx, &key,
                result->valueSz);
        if (ret == 0) {
            ret = wc_RsaFlattenPublicKey(&key, exponent, &exponentSz,
                component, &modulusSz);
        }
        if (ret == 0) {
            if (componentIndex == 0U) {
                *componentSz = modulusSz;
            }
            else if (*componentSz >= exponentSz) {
                XMEMCPY(component, exponent, exponentSz);
                *componentSz = exponentSz;
            }
            else {
                ret = BUFFER_E;
            }
        }
        wc_FreeRsaKey(&key);
        ForceZero(exponent, sizeof(exponent));
        return ret;
    #else
        return WC_NO_ERR_TRACE(NOT_COMPILED_IN);
    #endif
    }

    if ((result->cipherType == (word32)kSSS_CipherType_EC_NIST_P) ||
            (result->cipherType == (word32)kSSS_CipherType_EC_NIST_K) ||
            (result->cipherType == (word32)kSSS_CipherType_EC_BRAINPOOL)) {
    #ifdef HAVE_ECC
        ecc_key key;
        word32 idx = 0;

        ret = wc_ecc_init(&key);
        if (ret == 0)
            ret = wc_EccPublicKeyDecode(result->value, &idx, &key,
                result->valueSz);
        if (ret == 0)
            ret = wc_ecc_export_x963(&key, component, componentSz);
        wc_ecc_free(&key);
        return ret;
    #else
        return WC_NO_ERR_TRACE(NOT_COMPILED_IN);
    #endif
    }

    if ((result->cipherType ==
            (word32)kSSS_CipherType_EC_MONTGOMERY) ||
            (result->cipherType ==
            (word32)kSSS_CipherType_EC_TWISTED_ED)) {
        word32 i;
        word32 rawSz = 32U;

        /* Plug & Trust prepends SubjectPublicKeyInfo DER and reverses these
         * little-endian applet values after attestation. The signature is
         * over the original applet bytes, so strip DER and undo that reverse. */
        if ((result->cipherType ==
                (word32)kSSS_CipherType_EC_MONTGOMERY) &&
                (result->valueSz > 56U)) {
            rawSz = 56U; /* X448 */
        }
        if ((result->valueSz < rawSz) || (*componentSz < rawSz)) {
            return BUFFER_E;
        }
        for (i = 0U; i < rawSz; i++) {
            component[i] = result->value[result->valueSz - 1U - i];
        }
        *componentSz = rawSz;
        return 0;
    }

    if (*componentSz < result->valueSz) {
        return BUFFER_E;
    }
    XMEMCPY(component, result->value, result->valueSz);
    *componentSz = result->valueSz;
    return 0;
}

static int se050_attest_append(byte* out, word32 outSz, word32* offset,
    const byte* in, word32 inSz)
{
    if ((out == NULL) || (offset == NULL) ||
            ((in == NULL) && (inSz != 0U)) || (*offset > outSz) ||
            (inSz > (outSz - *offset))) {
        return BUFFER_E;
    }
    if (inSz != 0U) {
        XMEMCPY(out + *offset, in, inSz);
        *offset += inSz;
    }
    return 0;
}

#if SSS_HAVE_SE05X_VER_GTE_07_02
static int se050_attest_append_tlv(byte* out, word32 outSz, word32* offset,
    byte tag, const byte* value, word32 valueSz)
{
    byte header[SE050_TLV_OVERHEAD];
    int ret;

    if (valueSz > 0xFFFFU) {
        return BAD_LENGTH_E;
    }
    header[0] = tag;
    header[1] = 0x82;
    header[2] = (byte)(valueSz >> 8);
    header[3] = (byte)valueSz;
    ret = se050_attest_append(out, outSz, offset, header, sizeof(header));
    if (ret == 0)
        ret = se050_attest_append(out, outSz, offset, value, valueSz);
    return ret;
}
#endif

static int se050_build_attestation_data(const wc_se050_attst_result* result,
    word32 componentIndex, byte* component, word32 componentSz,
    byte* signedData, word32 signedDataSz, word32* used)
{
#ifdef NO_HASH_WRAPPER
    (void)result;
    (void)componentIndex;
    (void)component;
    (void)componentSz;
    (void)signedData;
    (void)signedDataSz;
    (void)used;
    return WC_NO_ERR_TRACE(NOT_COMPILED_IN);
#else
    int ret = 0;
    word32 offset = 0;
    const sss_se05x_attst_comp_data_t* data;

    if ((result == NULL) || (signedData == NULL) || (used == NULL) ||
            (componentIndex >= result->raw.valid_number)) {
        return BAD_FUNC_ARG;
    }
    data = &result->raw.data[componentIndex];
    if ((data->attributeLen > sizeof(data->attribute)) ||
            (data->chipIdLen > sizeof(data->chipId)) ||
            (data->timeStampLen > sizeof(data->timeStamp)) ||
            (data->signatureLen > sizeof(data->signature))) {
        return BAD_LENGTH_E;
    }
#if SSS_HAVE_SE05X_VER_GTE_07_02
    if ((data->cmdLen > sizeof(data->cmd)) ||
            (data->objSizeLen > sizeof(data->objSize))) {
        return BAD_LENGTH_E;
    }
#else
    if (data->outrandomLen > sizeof(data->outrandom)) {
        return BAD_LENGTH_E;
    }
#endif

#if SSS_HAVE_SE05X_VER_GTE_07_02
    {
        int digestSz;
        byte commandDigest[WC_MAX_DIGEST_SIZE];

        digestSz = wc_HashGetDigestSize(result->hashAlgo);
        if ((digestSz <= 0) || (data->cmdLen > UINT32_MAX)) {
            return BAD_FUNC_ARG;
        }
        ret = wc_Hash(result->hashAlgo, data->cmd, (word32)data->cmdLen,
            commandDigest, (word32)digestSz);
        if (ret == 0)
            ret = se050_attest_append(signedData, signedDataSz, &offset,
                commandDigest, (word32)digestSz);
        if ((ret == 0) && (componentSz != 0U))
            ret = se050_attest_append_tlv(signedData, signedDataSz, &offset,
                (byte)kSE05x_TAG_1, component, componentSz);
        if (ret == 0)
            ret = se050_attest_append_tlv(signedData, signedDataSz, &offset,
                (byte)kSE05x_TAG_2, data->chipId, (word32)data->chipIdLen);
        if (ret == 0)
            ret = se050_attest_append_tlv(signedData, signedDataSz, &offset,
                (byte)kSE05x_TAG_3, data->attribute,
                (word32)data->attributeLen);
        if (ret == 0)
            ret = se050_attest_append_tlv(signedData, signedDataSz, &offset,
                (byte)kSE05x_TAG_4, data->objSize,
                (word32)data->objSizeLen);
        if (ret == 0)
            ret = se050_attest_append_tlv(signedData, signedDataSz, &offset,
                (byte)kSE05x_TAG_TIMESTAMP, data->timeStamp.ts,
                (word32)data->timeStampLen);
        ForceZero(commandDigest, sizeof(commandDigest));
    }
#else
    ret = se050_attest_append(signedData, signedDataSz, &offset, component,
        componentSz);
    if (ret == 0)
        ret = se050_attest_append(signedData, signedDataSz, &offset,
            data->attribute, (word32)data->attributeLen);
    if (ret == 0)
        ret = se050_attest_append(signedData, signedDataSz, &offset,
            data->timeStamp.ts, (word32)data->timeStampLen);
    if (ret == 0)
        ret = se050_attest_append(signedData, signedDataSz, &offset,
            data->outrandom, (word32)data->outrandomLen);
    if (ret == 0)
        ret = se050_attest_append(signedData, signedDataSz, &offset,
            data->chipId, (word32)data->chipIdLen);
#endif

    if (ret == 0)
        *used = offset;
    return ret;
#endif
}

static int se050_verify_attestation_freshness(
    const sss_se05x_attst_comp_data_t* data, const byte* expectedRandom,
    word32 expectedRandomSz)
{
    if ((data == NULL) || (expectedRandom == NULL) ||
            (expectedRandomSz != SE050_ATTEST_RANDOM_SIZE)) {
        return BAD_FUNC_ARG;
    }

#if defined(SSS_HAVE_SE05X_VER_GTE_07_02) && \
    SSS_HAVE_SE05X_VER_GTE_07_02
    {
        word32 offset = 7U;
        word32 commandDataSz;
        int found = 0;

        if ((data->cmdLen < offset) || (data->cmdLen > sizeof(data->cmd)) ||
                (data->cmd[0] != (byte)kSE05x_CLA) ||
                (data->cmd[1] !=
                    (byte)kSE05x_INS_READ_With_Attestation) ||
                (data->cmd[4] != 0U)) {
            return BAD_LENGTH_E;
        }
        commandDataSz = ((word32)data->cmd[5] << 8) | data->cmd[6];
        if (commandDataSz != ((word32)data->cmdLen - offset)) {
            return BAD_LENGTH_E;
        }

        while (offset < data->cmdLen) {
            byte tag;
            byte lengthByte;
            word32 valueSz;

            tag = data->cmd[offset++];
            if (offset >= data->cmdLen) {
                return BAD_LENGTH_E;
            }
            lengthByte = data->cmd[offset++];
            if (lengthByte <= 0x7FU) {
                valueSz = lengthByte;
            }
            else if (lengthByte == 0x81U) {
                if (offset >= data->cmdLen) {
                    return BAD_LENGTH_E;
                }
                valueSz = data->cmd[offset++];
            }
            else if (lengthByte == 0x82U) {
                if (((word32)data->cmdLen - offset) < 2U) {
                    return BAD_LENGTH_E;
                }
                valueSz = ((word32)data->cmd[offset] << 8) |
                    data->cmd[offset + 1U];
                offset += 2U;
            }
            else {
                return BAD_LENGTH_E;
            }
            if (valueSz > ((word32)data->cmdLen - offset)) {
                return BAD_LENGTH_E;
            }
            if (tag == (byte)kSE05x_TAG_7) {
                if (found || (valueSz != expectedRandomSz)) {
                    return BAD_LENGTH_E;
                }
                if (ConstantCompare(data->cmd + offset, expectedRandom,
                        expectedRandomSz) != 0) {
                    return WC_NO_ERR_TRACE(SIG_VERIFY_E);
                }
                found = 1;
            }
            offset += valueSz;
        }
        return found ? 0 : BAD_LENGTH_E;
    }
#else
    if (data->outrandomLen != expectedRandomSz) {
        return BAD_LENGTH_E;
    }
    if (ConstantCompare(data->outrandom, expectedRandom,
            expectedRandomSz) != 0) {
        return WC_NO_ERR_TRACE(SIG_VERIFY_E);
    }
    return 0;
#endif
}

int wc_se050_verify_attestation(const wc_se050_attst_result* result,
    const byte* attestPubDer, word32 attestPubDerSz,
    const byte* expectedRandom, word32 expectedRandomSz, int* res)
{
#if defined(NO_HASH_WRAPPER) || defined(NO_ASN)
    (void)result;
    (void)attestPubDer;
    (void)attestPubDerSz;
    (void)expectedRandom;
    (void)expectedRandomSz;
    if (res != NULL)
        *res = 0;
    return WC_NO_ERR_TRACE(NOT_COMPILED_IN);
#else
    int ret = 0;
    int keyDecoded = 0;
    int sigType = WC_SIGNATURE_TYPE_NONE;
    word32 i;
    word32 idx;
    word32 componentSz;
    word32 signedDataSz;
    word32 signedDataUsed;
    byte* component = NULL;
    byte* signedData = NULL;
#if defined(HAVE_ECC) && defined(HAVE_ECC_VERIFY)
    int eccInit = 0;
    ecc_key eccKey;
#endif
#ifndef NO_RSA
    int rsaInit = 0;
    RsaKey rsaKey;
#endif
    void* verifyKey = NULL;
    word32 verifyKeySz = 0;

    if ((result == NULL) || (attestPubDer == NULL) ||
            (attestPubDerSz == 0U) || (expectedRandom == NULL) ||
            (expectedRandomSz != SE050_ATTEST_RANDOM_SIZE) ||
            (res == NULL) ||
            (result->raw.valid_number == 0U) ||
            (result->raw.valid_number > SE05X_MAX_ATTST_DATA)) {
        return BAD_FUNC_ARG;
    }
    *res = 0;
    if (ConstantCompare(result->freshness, expectedRandom,
            expectedRandomSz) != 0) {
        return 0;
    }

#if defined(HAVE_ECC) && defined(HAVE_ECC_VERIFY)
    XMEMSET(&eccKey, 0, sizeof(eccKey));
#endif
#ifndef NO_RSA
    XMEMSET(&rsaKey, 0, sizeof(rsaKey));
#endif
#if defined(HAVE_ECC) && defined(HAVE_ECC_VERIFY)
    ret = wc_ecc_init(&eccKey);
    if (ret == 0) {
        eccInit = 1;
        idx = 0;
        ret = wc_EccPublicKeyDecode(attestPubDer, &idx, &eccKey,
            attestPubDerSz);
        if (ret == 0) {
            keyDecoded = 1;
            sigType = WC_SIGNATURE_TYPE_ECC;
            verifyKey = &eccKey;
            verifyKeySz = sizeof(eccKey);
        }
    }
#endif
#ifndef NO_RSA
    if (!keyDecoded) {
        ret = wc_InitRsaKey(&rsaKey, NULL);
        if (ret == 0) {
            rsaInit = 1;
            idx = 0;
            ret = wc_RsaPublicKeyDecode(attestPubDer, &idx, &rsaKey,
                attestPubDerSz);
            if (ret == 0) {
                keyDecoded = 1;
                sigType = WC_SIGNATURE_TYPE_RSA_W_ENC;
                verifyKey = &rsaKey;
                verifyKeySz = sizeof(rsaKey);
            }
        }
    }
#endif
    if (!keyDecoded) {
        goto cleanup;
    }

    component = (byte*)XMALLOC(WC_SE050_ATTEST_VALUE_MAX, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    signedDataSz = WC_SE050_ATTEST_VALUE_MAX + MAX_POLICY_BUFFER_SIZE +
        WC_MAX_DIGEST_SIZE + 128U;
    signedData = (byte*)XMALLOC(signedDataSz, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if ((component == NULL) || (signedData == NULL)) {
        ret = MEMORY_E;
        goto cleanup;
    }

    ret = 0;
    for (i = 0; (i < result->raw.valid_number) && (ret == 0); i++) {
        ret = se050_verify_attestation_freshness(&result->raw.data[i],
            expectedRandom, expectedRandomSz);
        if (ret == WC_NO_ERR_TRACE(SIG_VERIFY_E)) {
            ret = 0;
            goto cleanup;
        }
        componentSz = WC_SE050_ATTEST_VALUE_MAX;
        if (ret == 0) {
            ret = se050_attested_component(result, i, component,
                &componentSz);
        }
        if (ret == 0) {
            ret = se050_build_attestation_data(result, i, component,
                componentSz, signedData, signedDataSz, &signedDataUsed);
        }
        if (ret == 0) {
            if ((result->raw.data[i].signatureLen == 0U) ||
                    (result->raw.data[i].signatureLen >
                    sizeof(result->raw.data[i].signature))) {
                ret = BAD_LENGTH_E;
                break;
            }
            ret = wc_SignatureVerify(result->hashAlgo,
                (enum wc_SignatureType)sigType, signedData, signedDataUsed,
                result->raw.data[i].signature,
                (word32)result->raw.data[i].signatureLen, verifyKey,
                verifyKeySz);
            if (ret == WC_NO_ERR_TRACE(SIG_VERIFY_E)) {
                ret = 0;
                goto cleanup;
            }
        }
    }
    if (ret == 0)
        *res = 1;

cleanup:
    if (component != NULL) {
        ForceZero(component, WC_SE050_ATTEST_VALUE_MAX);
        XFREE(component, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (signedData != NULL) {
        ForceZero(signedData, signedDataSz);
        XFREE(signedData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#if defined(HAVE_ECC) && defined(HAVE_ECC_VERIFY)
    if (eccInit)
        wc_ecc_free(&eccKey);
#endif
#ifndef NO_RSA
    if (rsaInit)
        wc_FreeRsaKey(&rsaKey);
#endif
    return ret;
#endif
}

int wc_se050_validate_provisioned_key(word32 keyId, word32 attestKeyId,
    const byte* expectedPubDer, word32 expectedPubDerSz,
    const byte* attestPubDer, word32 attestPubDerSz, int* res)
{
    int ret;
    int verified = 0;
    wc_se050_attst_result result;

    if ((expectedPubDer == NULL) || (expectedPubDerSz == 0U) ||
            (attestPubDer == NULL) || (attestPubDerSz == 0U) ||
            (res == NULL)) {
        return BAD_FUNC_ARG;
    }
    *res = 0;

    ret = wc_se050_attest_object(keyId, attestKeyId, WC_HASH_TYPE_SHA256,
        NULL, 0, &result);
    if (ret == 0)
        ret = wc_se050_verify_attestation(&result, attestPubDer,
            attestPubDerSz, result.freshness,
            (word32)sizeof(result.freshness), &verified);
    if ((ret == 0) && verified && (result.valueSz == expectedPubDerSz) &&
            (XMEMCMP(result.value, expectedPubDer, expectedPubDerSz) == 0)) {
        *res = 1;
    }
    ForceZero(&result, sizeof(result));
    return ret;
}

#endif /* !WOLFSSL_SE050_NO_ATTEST */

#if !defined(NO_RSA) && !defined(WOLFSSL_SE050_NO_RSA)

/**
 * Use specified SE050 key ID with this RsaKey struct.
 * Should be called by wc_RsaUseKeyId() for using pre-populated
 * SE050 keys.
 *
 * key   Pointer to initialized RsaKey structure
 * keyId SE050 key ID containing RSA key object
 *
 * Return 0 on success, negative on error.
 */
int se050_rsa_use_key_id(struct RsaKey* key, word32 keyId)
{
    int ret = 0;
    sss_object_t    keyObject;
    sss_key_store_t host_keystore;
    sss_status_t    status = kStatus_SSS_Success;
    uint8_t*        derBuf = NULL;
    size_t          derSz = 0;
    size_t          derSzBits = 0;
    word32          idx = 0;

#ifdef SE050_DEBUG
    printf("se050_rsa_use_key_id: key %p, keyId %d\n", key, keyId);
#endif
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore, SE050_KEYSTOREID_RSA);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&keyObject, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_get_handle(&keyObject, keyId);
    }
    if (status == kStatus_SSS_Success) {
        ret = se050_get_object_size(&host_keystore, keyObject.keyId);
        if (ret <= 0) {
            status = kStatus_SSS_Fail;
        }
        else {
            /* double derSz to allow for ASN.1 encoding space */
            derSz = ((size_t)ret) * 2;
            ret = 0;
            derBuf = (uint8_t*)XMALLOC(derSz, key->heap,
                                       DYNAMIC_TYPE_TMP_BUFFER);
            if (derBuf == NULL) {
                WOLFSSL_MSG("Error calling malloc for RSA DER buffer");
                status = kStatus_SSS_Fail;
            }
        }
    }
    if (status == kStatus_SSS_Success) {
        derSzBits = derSz * 8;
        XMEMSET(derBuf, 0, derSz);
        status = sss_key_store_get_key(&host_keystore, &keyObject,
            derBuf, &derSz, &derSzBits);
        (void)derSzBits; /* not used */
    }
    if (status == kStatus_SSS_Success) {
        /* Populate RsaKey with general key info, for wolfCrypt to use */
        ret = wc_RsaPublicKeyDecode(derBuf, &idx, key, (word32)derSz);
        if (ret != 0) {
            status = kStatus_SSS_Fail;
        }
    }
    XFREE(derBuf, key->heap, DYNAMIC_TYPE_TMP_BUFFER);

    if (status == kStatus_SSS_Success) {
        key->keyId = keyId;
        key->keyIdSet = 1;
        key->type = RSA_PRIVATE;
        ret = 0;
    }
    else if (ret == 0) {
        ret = WC_HW_E;
    }

    sss_key_object_free(&keyObject);

    wolfSSL_CryptHwMutexUnLock();

#ifdef SE050_DEBUG
    printf("se050_rsa_use_key_id: ret %d\n", ret);
#endif

    return ret;
}

/**
 * Get SE050 key ID associated with this RsaKey struct.
 * Should be called by wc_RsaGetKeyId() for the application to get
 * what key ID wolfCrypt picked for this RsaKey struct when generating
 * a key inside the SE050.
 *
 * key   Pointer to initialized RsaKey structure
 * keyId [OUT] SE050 key ID associated with this key structure
 *
 * Return 0 on success, negative on error.
 */
int se050_rsa_get_key_id(struct RsaKey* key, word32* keyId)
{
    int ret = 0;

    if (key == NULL || keyId == NULL) {
        return BAD_FUNC_ARG;
    }

    if (key->keyIdSet == 1) {
        *keyId = key->keyId;

    } else {
        WOLFSSL_MSG("SE050 key ID not set for RsaKey struct");
        ret = WC_HW_E;
    }

    return ret;
}

/**
 * Create RSA key pair inside SE050.
 *
 * key   RsaKey structure to store generated key information in
 * size  RSA key size to generate in bytes
 * e     RSA exponent, must be 65537 for SE050 compatibility
 *
 * Returns 0 on success, negative on error.
 */
int se050_rsa_create_key(struct RsaKey* key, int size, long e)
{
    int             ret = 0;
    word32          keyId = 0;
    int             keyCreated = 0;
    sss_status_t    status = kStatus_SSS_Success;
    sss_object_t    keyPair;
    sss_key_store_t host_keystore;
    uint8_t*        derBuf = NULL;
    size_t          derSz = 0;
    size_t          derSzBits = 0;
    word32          idx = 0;

#ifdef SE050_DEBUG
    printf("se050_rsa_create_key: key %p, size %d, e %ld\n", key, size, e);
#endif

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }

    if (e != 65537) {
        WOLFSSL_MSG("SE050 RSA key create only supports exponent of 65537");
        return WC_HW_E;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore, SE050_KEYSTOREID_RSA);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&keyPair, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        keyId = se050_allocate_key(SE050_RSA_KEY);
        status = sss_key_object_allocate_handle(&keyPair, keyId,
            kSSS_KeyPart_Pair, kSSS_CipherType_RSA, (size / 8),
            kKeyObject_Mode_Persistent);
    }
    if (status == kStatus_SSS_Success) {
        /* Try to delete existing key first. Ignore return since will fail
         * if no key exists */
        sss_key_store_erase_key(&host_keystore, &keyPair);

        keyCreated = 1;
        status = sss_key_store_generate_key(&host_keystore, &keyPair,
            size, NULL);
    }
    if (status == kStatus_SSS_Success) {
        ret = se050_get_object_size(&host_keystore, keyPair.keyId);
        if (ret <= 0) {
            status = kStatus_SSS_Fail;
        }
        else {
            /* double derSz to allow for ASN.1 encoding space */
            derSz = ((size_t)ret) * 2;
            ret = 0;
            derBuf = (uint8_t*)XMALLOC(derSz, key->heap,
                                       DYNAMIC_TYPE_TMP_BUFFER);
            if (derBuf == NULL) {
                WOLFSSL_MSG("Error calling malloc for RSA DER buffer");
                status = kStatus_SSS_Fail;
            }
        }
    }
    if (status == kStatus_SSS_Success) {
        derSzBits = derSz * 8;
        XMEMSET(derBuf, 0, derSz);
        status = sss_key_store_get_key(&host_keystore, &keyPair,
            derBuf, &derSz, &derSzBits);
        (void)derSzBits; /* not used */
    }
    if (status == kStatus_SSS_Success) {
        ret = wc_RsaPublicKeyDecode(derBuf, &idx, key, (word32)derSz);
        if (ret != 0) {
            status = kStatus_SSS_Fail;
        }
    }
    XFREE(derBuf, key->heap, DYNAMIC_TYPE_TMP_BUFFER);

    if (status == kStatus_SSS_Success) {
        key->keyId = keyId;
        key->keyIdSet = 1;
        key->type = RSA_PRIVATE;
        ret = 0;
    }
    else {
        if (keyCreated) {
            sss_key_store_erase_key(&host_keystore, &keyPair);
            sss_key_object_free(&keyPair);
        }
        if (ret == 0) {
            ret = WC_HW_E;
        }
    }

    wolfSSL_CryptHwMutexUnLock();

#ifdef SE050_DEBUG
    printf("se050_rsa_create_key: key %p, ret %d, keyId %d\n",
           key, ret, key->keyId);
#endif

    return ret;
}

static int se050_rsa_generate_key(word32 keyId, int size, long e,
    const sss_policy_t* policy)
{
    sss_status_t status = kStatus_SSS_Success;
    sss_object_t keyPair;
    sss_key_store_t host_keystore;
    int keyObjectInit = 0;

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }
    if ((keyId >= SE050_KEYID_START) || (size <= 0) ||
            ((size & 7) != 0) || (e != 65537)) {
        return BAD_FUNC_ARG;
    }
    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    status = se050_require_new_object(keyId);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_context_init(&host_keystore,
            cfg_se050_i2c_pi);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore,
            SE050_KEYSTOREID_RSA);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&keyPair, &host_keystore);
        if (status == kStatus_SSS_Success) {
            keyObjectInit = 1;
        }
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_allocate_handle(&keyPair, keyId,
            kSSS_KeyPart_Pair, kSSS_CipherType_RSA, (size / 8),
            kKeyObject_Mode_Persistent);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_generate_key(&host_keystore, &keyPair,
            size, (void*)policy);
    }

    if (keyObjectInit) {
        sss_key_object_free(&keyPair);
    }
    wolfSSL_CryptHwMutexUnLock();
    return (status == kStatus_SSS_Success) ? 0 : WC_HW_E;
}

int wc_se050_rsa_generate_key_policy(word32 keyId, int size, long e,
    const sss_policy_t* policy)
{
    return se050_rsa_generate_key(keyId, size, e, policy);
}

int wc_se050_rsa_generate_key_ex(word32 keyId, int size, long e,
    word32 policyFlags, word32 authObjId)
{
    const sss_policy_t* policy = NULL;
    se050_policy_set policySet;
    int ret;

    ret = se050_build_policy_set(SE050_POLICY_OBJECT_ASYM, policyFlags,
        authObjId, &policySet);
    if (ret != 0) {
        return ret;
    }
    if (policyFlags != 0U) {
        policy = &policySet.policy;
    }
    return se050_rsa_generate_key(keyId, size, e, policy);
}

static int se050_rsa_insert_key(word32 keyId, const byte* rsaDer,
    word32 rsaDerSize, int keyType, const sss_policy_t* policy,
    int requireNew)
{
    int             ret = 0;
    int             keySize;
    word32          idx = 0;
    sss_object_t    newKey;
    sss_key_store_t host_keystore;
    sss_status_t    status = kStatus_SSS_Success;
    struct RsaKey   key;
    sss_key_part_t  keyPart = kSSS_KeyPart_Pair;

    if ((cfg_se050_i2c_pi == NULL) || (rsaDer == NULL) ||
            (rsaDerSize == 0U)) {
        return BAD_FUNC_ARG;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    /* Avoid key ID conflicts with temporary key storage */
    if (keyId >= SE050_KEYID_START) {
        wolfSSL_CryptHwMutexUnLock();
        return BAD_FUNC_ARG;
    }

    if (requireNew) {
        status = se050_require_new_object(keyId);
    }

    ret = wc_InitRsaKey(&key, NULL);
    if (ret != 0) {
        status = kStatus_SSS_Fail;
    }
    else {
        if (keyType == RSA_PUBLIC) {
            keyPart = kSSS_KeyPart_Public;
            ret = wc_RsaPublicKeyDecode(rsaDer, &idx, &key, rsaDerSize);
        }
        else if (keyType == RSA_PRIVATE) {
            keyPart = kSSS_KeyPart_Pair;
            ret = wc_RsaPrivateKeyDecode(rsaDer, &idx, &key, rsaDerSize);
        }
        else {
            ret = BAD_FUNC_ARG;
        }

        if (ret != 0) {
            status = kStatus_SSS_Fail;
        }
    }

    if (status == kStatus_SSS_Success) {
        keySize = wc_RsaEncryptSize(&key);
        if (keySize < 0) {
            status = kStatus_SSS_Fail;
        }
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&newKey, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_allocate_handle(&newKey, keyId,
            keyPart, kSSS_CipherType_RSA, keySize,
            kKeyObject_Mode_Persistent);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_set_key(&host_keystore, &newKey, rsaDer,
            rsaDerSize, (keySize * 8), (void*)policy, 0);
    }
    wolfSSL_CryptHwMutexUnLock();

    wc_FreeRsaKey(&key);
    if (status != kStatus_SSS_Success) {
        if (ret == 0) {
            ret = WC_HW_E;
        }
    }

    return ret;
}

/**
 * Insert DER encoded RSA private key into SE050 as a persistent key.
 *
 * keyId       SE050 key ID to store key into
 * rsaDer      DER encoded RSA private key
 * rsaDerSize  size of DER buffer, bytes
 *
 * Returns 0 on success, negative on error
 */
int wc_se050_rsa_insert_private_key(word32 keyId, const byte* rsaDer,
                                    word32 rsaDerSize)
{
    return se050_rsa_insert_key(keyId, rsaDer, rsaDerSize, RSA_PRIVATE,
        NULL, 0);
}

/**
 * Insert DER encoded RSA public key into SE050 as a persistent key.
 *
 * keyId       SE050 key ID to store key into
 * rsaDer      DER encoded RSA public key
 * rsaDerSize  size of DER buffer, bytes
 *
 * Returns 0 on success, negative on error
 */
int wc_se050_rsa_insert_public_key(word32 keyId, const byte* rsaDer,
                                   word32 rsaDerSize)
{
    return se050_rsa_insert_key(keyId, rsaDer, rsaDerSize, RSA_PUBLIC,
        NULL, 0);
}

int wc_se050_rsa_insert_private_key_policy(word32 keyId, const byte* rsaDer,
    word32 rsaDerSize, const sss_policy_t* policy)
{
    return se050_rsa_insert_key(keyId, rsaDer, rsaDerSize, RSA_PRIVATE,
        policy, 0);
}

int wc_se050_rsa_insert_public_key_policy(word32 keyId, const byte* rsaDer,
    word32 rsaDerSize, const sss_policy_t* policy)
{
    return se050_rsa_insert_key(keyId, rsaDer, rsaDerSize, RSA_PUBLIC,
        policy, 0);
}

static int se050_rsa_insert_key_ex(word32 keyId, const byte* rsaDer,
    word32 rsaDerSize, int keyType, word32 policyFlags, word32 authObjId)
{
    int ret;
    const sss_policy_t* policy = NULL;
    se050_policy_set policySet;

    ret = se050_build_policy_set(SE050_POLICY_OBJECT_ASYM, policyFlags,
        authObjId, &policySet);
    if (ret != 0) {
        return ret;
    }
    if (policyFlags != 0U) {
        policy = &policySet.policy;
    }
    return se050_rsa_insert_key(keyId, rsaDer, rsaDerSize, keyType, policy,
        1);
}

int wc_se050_rsa_insert_private_key_ex(word32 keyId, const byte* rsaDer,
    word32 rsaDerSize, word32 policyFlags, word32 authObjId)
{
    return se050_rsa_insert_key_ex(keyId, rsaDer, rsaDerSize, RSA_PRIVATE,
        policyFlags, authObjId);
}

int wc_se050_rsa_insert_public_key_ex(word32 keyId, const byte* rsaDer,
    word32 rsaDerSize, word32 policyFlags, word32 authObjId)
{
    return se050_rsa_insert_key_ex(keyId, rsaDer, rsaDerSize, RSA_PUBLIC,
        policyFlags, authObjId);
}

/**
 * Free an RSA key object from the SE050. Erases key from persistent storage
 * if it was allocated by wolfSSL (not pre-provisioned).
 *
 * key  Pointer to initialized RsaKey structure
 */
void se050_rsa_free_key(struct RsaKey* key)
{
    sss_status_t    status = kStatus_SSS_Success;
    sss_object_t    keyObject;
    sss_key_store_t host_keystore;

#ifdef SE050_DEBUG
    printf("se050_rsa_free_key: key %p, keyId %d\n", key, key->keyId);
#endif

    if (cfg_se050_i2c_pi == NULL) {
        return;
    }
    if (key->keyIdSet == 0) {
        return;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return;
    }

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore, SE050_KEYSTOREID_RSA);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&keyObject, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_get_handle(&keyObject, key->keyId);
    }

    if (status == kStatus_SSS_Success) {
        /* Erase key from SE050 persistent storage if it was allocated
         * by wolfSSL (not a pre-provisioned key). Without this, persistent
         * key objects leak on the SE050 and can exhaust secure storage. */
        if (key->keyId >= SE050_KEYID_START) {
            sss_key_store_erase_key(&host_keystore, &keyObject);
        }
        sss_key_object_free(&keyObject);
        key->keyId = 0;
        key->keyIdSet = 0;
    }
    wolfSSL_CryptHwMutexUnLock();
}

/**
 * Get SSS algorithm type for RSA signature operations.
 *
 * padType  padding type
 * hash     hash function
 * mgf      mask generation function (for PSS)
 *
 * Returns algorithm type or kAlgorithm_None if none supported found
 */
static sss_algorithm_t se050_get_rsa_signature_type(int padType,
        enum wc_HashType hash, int mgf)
{
    sss_algorithm_t alg = kAlgorithm_None;

    switch (padType) {
        case WC_RSA_PKCSV15_PAD:
            if (hash == WC_HASH_TYPE_NONE) {
                alg = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_NO_HASH;
            } else if (hash == WC_HASH_TYPE_SHA) {
                alg = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA1;
            } else if (hash == WC_HASH_TYPE_SHA224) {
                alg = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA224;
            } else if (hash == WC_HASH_TYPE_SHA256) {
                alg = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256;
            } else if (hash == WC_HASH_TYPE_SHA384) {
                alg = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA384;
            } else if (hash == WC_HASH_TYPE_SHA512) {
                alg = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA512;
            }
            break;
        case WC_RSA_OAEP_PAD:
            if (hash == WC_HASH_TYPE_SHA) {
                alg = kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA1;
            } else if (hash == WC_HASH_TYPE_SHA224) {
                alg = kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA224;
            } else if (hash == WC_HASH_TYPE_SHA256) {
                alg = kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA256;
            } else if (hash == WC_HASH_TYPE_SHA384) {
                alg = kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA384;
            } else if (hash == WC_HASH_TYPE_SHA512) {
                alg = kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA512;
            }
            break;
        case WC_RSA_PSS_PAD:
            if (mgf == WC_MGF1SHA1) {
                alg = kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA1;
            } else if (mgf == WC_MGF1SHA224) {
                alg = kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA224;
            } else if (mgf == WC_MGF1SHA256) {
                alg = kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA256;
            } else if (mgf == WC_MGF1SHA384) {
                alg = kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA384;
            } else if (mgf == WC_MGF1SHA512) {
                alg = kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA512;
            }
            break;
        case WC_RSA_NO_PAD:
            alg = kAlgorithm_SSS_RSASSA_NO_PADDING;
            break;
        default:
            break;
    }

    return alg;
}

static sss_algorithm_t se050_get_rsa_encrypt_type(int padType,
        enum wc_HashType hash)
{
    sss_algorithm_t alg = kAlgorithm_None;
    (void)hash;

    switch (padType) {
        case WC_RSA_PKCSV15_PAD:
            alg = kAlgorithm_SSS_RSAES_PKCS1_V1_5;
            break;
        case WC_RSA_OAEP_PAD:
            /* lower level Se05x API translation maps OAEP-SHA1 alg type to
             * kSE05x_RSAEncryptionAlgo_PKCS1_OAEP (generic) */
            alg = kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA1;
            break;
        case WC_RSA_NO_PAD:
            alg = kAlgorithm_SSS_RSASSA_NO_PADDING;
            break;
        default:
            break;
    }

    return alg;
}

/**
 * RSA sign operation.
 *
 * in        input data to be signed
 * inLen     length of input data, bytes
 * out       output buffer containing signature
 * outLen    length of output buffer, bytes
 * key       pointer to initialized/populated RsaKey structure
 * rsa_type  type of RSA: must be RSA_PRIVATE_ENCRYPT
 * pad_value should be RSA_BLOCK_TYPE_1 for signing
 * pad_type  type of padding: WC_RSA_PKCSV15_PAD, WC_RSA_OAEP_PAD,
 *           WC_RSA_NO_PAD, WC_RSA_PSS_PAD
 * hash      type of hash algorithm, found in wolfssl/wolfcrypt/hash.h
 * mgf       type of mask generation function to use
 * label     optional label, not supported by SE050, must be NULL
 * labelSz   size of label, not supported by SE050, must be 0
 * keySz     size of RSA key, bytes
 *
 * Return size of signature on success, negative on error.
 */
int se050_rsa_sign(const byte* in, word32 inLen, byte* out,
                   word32 outLen, struct RsaKey* key, int rsa_type,
                   byte pad_value, int pad_type, enum wc_HashType hash,
                   int mgf, byte* label, word32 labelSz, int keySz)
{
    int ret = 0;
    int keyCreated = 0;
    word32 keyId;
    size_t sigSz;
    sss_object_t     newKey;
    sss_status_t     status;
    sss_key_store_t  host_keystore;
    sss_algorithm_t  algorithm = kAlgorithm_None;
    sss_asymmetric_t ctx_asymm;
    byte* derBuf = NULL;
    int derSz = 0;
    int derBufSz = 0;

    /* SE050 does not support optional label */
    (void)label;
    (void)labelSz;

#ifdef SE050_DEBUG
    printf("se050_rsa_sign: key %p, in %p (%d), out %p (%d), "
            "key %p, type %d, pad_value = %d, pad_type = %d, mgf = %d\n",
            key, in, inLen, out, outLen, key, rsa_type, pad_value,
            pad_type, mgf);
#endif

    if (in == NULL || out == NULL || key == NULL ||
        rsa_type != RSA_PRIVATE_ENCRYPT || pad_value != RSA_BLOCK_TYPE_1) {
        return BAD_FUNC_ARG;
    }

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }

#ifdef WOLFSSL_SE050_ONLY_KEY_ID
    /* under ONLY_KEY_ID only SE050-resident keys reach this
     * hardware path. Never auto-import a software key (keyIdSet == 0). */
    if (key->keyIdSet == 0) {
        return NOT_COMPILED_IN;
    }
#endif

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    algorithm = se050_get_rsa_signature_type(pad_type, hash, mgf);
    if (algorithm == kAlgorithm_None) {
        WOLFSSL_MSG("Unsupported padding/hash/mgf combination for SE050");
        wolfSSL_CryptHwMutexUnLock();
        return BAD_FUNC_ARG;
    }
#ifdef SE050_DEBUG
    printf("se050_rsa_sign: algorithm = %d, keySz = %d, keyIdSet = %d\n",
            algorithm, keySz, key->keyIdSet);
#endif

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
#ifdef SE050_DEBUG
    printf("se050_rsa_sign: sss_key_store_context_init status = %d\n", status);
#endif
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore, SE050_KEYSTOREID_RSA);
#ifdef SE050_DEBUG
        printf("se050_rsa_sign: sss_key_store_allocate status = %d\n", status);
#endif
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&newKey, &host_keystore);
#ifdef SE050_DEBUG
        printf("se050_rsa_sign: sss_key_object_init status = %d\n", status);
#endif
    }
    if (status == kStatus_SSS_Success) {
        keyId = key->keyId;
        if (key->keyIdSet == 0) {
            /* key was not generated in SE050, export RsaKey to DER
             * and use that to store into SE050 keystore */
            derSz = wc_RsaKeyToDer(key, NULL, 0);
#ifdef SE050_DEBUG
            printf("se050_rsa_sign: wc_RsaKeyToDer size query = %d\n", derSz);
#endif
            if (derSz < 0) {
                status = kStatus_SSS_Fail;
                ret = derSz;
            }
            else {
                derBuf = (byte*)XMALLOC(derSz, key->heap,
                                        DYNAMIC_TYPE_TMP_BUFFER);
                if (derBuf == NULL) {
                    WOLFSSL_MSG("malloc failed when converting RsaKey to DER");
                    status = kStatus_SSS_Fail;
                    ret = MEMORY_E;
                }
                else {
                    derBufSz = derSz;
                }
            }
            if (status == kStatus_SSS_Success) {
                derSz = wc_RsaKeyToDer(key, derBuf, derSz);
#ifdef SE050_DEBUG
                printf("se050_rsa_sign: wc_RsaKeyToDer export = %d\n", derSz);
#endif
                if (derSz < 0) {
                    status = kStatus_SSS_Fail;
                    ret = derSz;
                }
            }
            if (status == kStatus_SSS_Success) {
                keyId = se050_allocate_key(SE050_RSA_KEY);
                status = sss_key_object_allocate_handle(&newKey, keyId,
                    kSSS_KeyPart_Pair, kSSS_CipherType_RSA, keySz,
                    kKeyObject_Mode_Persistent);
#ifdef SE050_DEBUG
                printf("se050_rsa_sign: sss_key_object_allocate_handle "
                        "status = %d, keyId = %d\n", status, keyId);
#endif
            }
            if (status == kStatus_SSS_Success) {
                /* Try to delete existing key first, ignore return since will
                 * fail if no key exists yet */
                status = sss_key_store_erase_key(&host_keystore, &newKey);
#ifdef SE050_DEBUG
                printf("se050_rsa_sign: sss_key_store_erase_key "
                        "status = %d\n", status);
#endif
                /* Reset status - erase failing is expected if key doesn't
                 * exist yet */
                status = kStatus_SSS_Success;

                keyCreated = 1;
                status = sss_key_store_set_key(&host_keystore, &newKey, derBuf,
                                               derSz, (keySz * 8), NULL, 0);
#ifdef SE050_DEBUG
                printf("se050_rsa_sign: sss_key_store_set_key "
                        "status = %d, derSz = %d, keyBits = %d\n",
                        status, derSz, (keySz * 8));
#endif
            }

            if ((derBuf != NULL) && (derBufSz > 0)) {
                /* Private key encoding sent to the SE. Wipe the whole
                 * allocation: a failed encode leaves derSz negative having
                 * possibly already written to the buffer. */
                ForceZero(derBuf, (word32)derBufSz);
            }
            XFREE(derBuf, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        }
        else {
            status = sss_key_object_get_handle(&newKey, keyId);
#ifdef SE050_DEBUG
            printf("se050_rsa_sign: sss_key_object_get_handle "
                    "status = %d, keyId = %d\n", status, keyId);
#endif
        }
    }

    if (status == kStatus_SSS_Success) {
        status = sss_asymmetric_context_init(&ctx_asymm, cfg_se050_i2c_pi,
                                            &newKey, algorithm, kMode_SSS_Sign);
#ifdef SE050_DEBUG
        printf("se050_rsa_sign: sss_asymmetric_context_init "
                "status = %d, algorithm = %d\n", status, algorithm);
#endif
        if (status == kStatus_SSS_Success) {
            sigSz = outLen;
            status = sss_asymmetric_sign_digest(&ctx_asymm, (uint8_t*)in,
                                                inLen, out, &sigSz);
#ifdef SE050_DEBUG
            printf("se050_rsa_sign: sss_asymmetric_sign_digest "
                    "status = %d, inLen = %d, sigSz = %d\n",
                    status, inLen, (int)sigSz);
#endif
        }
        sss_asymmetric_context_free(&ctx_asymm);
    }

    if (status == kStatus_SSS_Success) {
        key->keyId = keyId;
        key->keyIdSet = 1;
        ret = sigSz;
    }
    else {
        if (keyCreated) {
            sss_key_store_erase_key(&host_keystore, &newKey);
            sss_key_object_free(&newKey);
        }
        if (ret == 0) {
            ret = WC_HW_E;
        }
    }

    wolfSSL_CryptHwMutexUnLock();

#ifdef SE050_DEBUG
    printf("se050_rsa_sign: ret %d, outLen %d\n", ret, outLen);
#endif

    return ret;
}

/**
 * RSA verify operation.
 *
 * in        input signature to be verified
 * inLen     length of sig, bytes
 * out       output buffer containing decoded data
 * outLen    length of output buffer, bytes
 * key       pointer to initialized/populated RsaKey structure
 * rsa_type  type of RSA: must be RSA_PUBLIC_DECRYPT
 * pad_value should be RSA_BLOCK_TYPE_1 for sign/verify
 * pad_type  type of padding: WC_RSA_PKCSV15_PAD, WC_RSA_OAEP_PAD,
 *           WC_RSA_NO_PAD, WC_RSA_PSS_PAD
 * hash      type of hash algorithm, found in wolfssl/wolfcrypt/hash.h
 * mgf       type of mask generation function to use
 * label     optional label, not supported by SE050, must be NULL
 * labelSz   size of label, not supported by SE050, must be 0
 *
 * Returns size of decoded data on success, negative on error.
 */
int se050_rsa_verify(const byte* in, word32 inLen, byte* out, word32 outLen,
                     struct RsaKey* key, int rsa_type, byte pad_value,
                     int pad_type, enum wc_HashType hash, int mgf, byte* label,
                     word32 labelSz)
{
    int ret = 0;
    word32 keyId;
    int keySz;
    int keyCreated = 0;
    size_t decLen  = 0;
    sss_status_t     status;
    sss_object_t     newKey;
    sss_key_store_t  host_keystore;
    sss_asymmetric_t ctx_asymm = {0};
    sss_se05x_asymmetric_t* se050_ctx_asymm = NULL;
    sss_algorithm_t  algorithm = kAlgorithm_None;
    smStatus_t       smStatus = SM_NOT_OK;
    byte* pad    = NULL;
    byte* derBuf = NULL;
    byte* decBuf = NULL;
    int derSz = 0;

#ifdef SE050_DEBUG
    printf("se050_rsa_pkcs1v15_verify: key %p, in %p (%d), out %p (%d)\n",
            key, in, inLen, out, outLen);
#endif

    if (in == NULL || out == NULL || key == NULL ||
        rsa_type != RSA_PUBLIC_DECRYPT || pad_value != RSA_BLOCK_TYPE_1) {
        return BAD_FUNC_ARG;
    }

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }

#ifdef WOLFSSL_SE050_ONLY_KEY_ID
    /* Under ONLY_KEY_ID only SE050-resident keys reach this
     * hardware path. Never auto-import a software key (keyIdSet == 0). */
    if (key->keyIdSet == 0) {
        return NOT_COMPILED_IN;
    }
#endif

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    algorithm = se050_get_rsa_signature_type(pad_type, hash, mgf);
    if (algorithm == kAlgorithm_None) {
        WOLFSSL_MSG("Unsupported padding/hash/mgf combination for SE050");
        wolfSSL_CryptHwMutexUnLock();
        return BAD_FUNC_ARG;
    }

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore, SE050_KEYSTOREID_RSA);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&newKey, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        keySz = wc_RsaEncryptSize(key);
        if (keySz < 0) {
            WOLFSSL_MSG("Failed to get RSA key size from struct");
            status = kStatus_SSS_Fail;
        }
    }
    if (status == kStatus_SSS_Success) {
        keyId = key->keyId;
        if (key->keyIdSet == 0) {
            /* key was not generated in SE050, export RsaKey to DER
             * and use that to store into SE050 keystore */
            derSz = wc_RsaKeyToPublicDer(key, NULL, 0);
            if (derSz < 0) {
                status = kStatus_SSS_Fail;
                ret = derSz;
            }
            else {
                derBuf = (byte*)XMALLOC(derSz, key->heap,
                                        DYNAMIC_TYPE_TMP_BUFFER);
                if (derBuf == NULL) {
                    WOLFSSL_MSG("malloc failed when converting RsaKey to DER");
                    status = kStatus_SSS_Fail;
                    ret = MEMORY_E;
                }
            }
            if (status == kStatus_SSS_Success) {
                derSz = wc_RsaKeyToPublicDer(key, derBuf, derSz);
                if (derSz < 0) {
                    status = kStatus_SSS_Fail;
                    ret = derSz;
                }
            }
            if (status == kStatus_SSS_Success) {
                keyId = se050_allocate_key(SE050_RSA_KEY);
                status = sss_key_object_allocate_handle(&newKey, keyId,
                    kSSS_KeyPart_Public, kSSS_CipherType_RSA, keySz,
                    kKeyObject_Mode_Transient);
            }
            if (status == kStatus_SSS_Success) {
                /* Try to delete existing key first, ignore return since will
                 * fail if no key exists yet */
                sss_key_store_erase_key(&host_keystore, &newKey);

                keyCreated = 1;
                status = sss_key_store_set_key(&host_keystore, &newKey, derBuf,
                                               derSz, (keySz * 8), NULL, 0);
            }

            XFREE(derBuf, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        }
        else {
            status = sss_key_object_get_handle(&newKey, keyId);
        }
    }

    if (status == kStatus_SSS_Success) {
        status = sss_asymmetric_context_init(&ctx_asymm, cfg_se050_i2c_pi,
                                    &newKey, algorithm, kMode_SSS_Verify);
        if (status == kStatus_SSS_Success) {
            /* The raw RSA public operation always produces keySz bytes, but
             * callers such as PKCS#7 signature verify pass an out buffer
             * sized for the unpadded payload only. Decrypt into a
             * keySz-sized scratch buffer, then unpad and copy the payload
             * to out. */
            decBuf = (byte*)XMALLOC((size_t)keySz, key->heap,
                                    DYNAMIC_TYPE_TMP_BUFFER);
            if (decBuf == NULL) {
                status = kStatus_SSS_Fail;
                ret = MEMORY_E;
            }
        }
        if (status == kStatus_SSS_Success) {
            /* Use lower Se05x API instead of sss_asymmetric_verify_digest()
             * since we need to return decoded data not just verify result */
            decLen = (size_t)keySz;
            se050_ctx_asymm = (sss_se05x_asymmetric_t*)&ctx_asymm;
            smStatus = Se05x_API_RSAEncrypt(&se050_ctx_asymm->session->s_ctx,
                                            se050_ctx_asymm->keyObject->keyId,
                                            kSE05x_RSAEncryptionAlgo_NO_PAD,
                                            in, inLen, decBuf, &decLen);
            if (smStatus == SM_OK) {
                /* find end of padding, pad points to start of actual data */
                ret = wc_RsaUnPad_ex(decBuf, decLen, &pad, pad_value,
                        pad_type, hash, mgf,
                        label, labelSz, RSA_PSS_SALT_LEN_DEFAULT, (keySz * 8),
                        key->heap);
                if (ret >= 0) {
                    if ((word32)ret > outLen) {
                        WOLFSSL_MSG("Output buffer too small for RSA verify");
                        ret = RSA_BUFFER_E;
                        status = kStatus_SSS_Fail;
                    }
                    else {
                        XMEMCPY(out, pad, ret);
                    }
                }
                else {
                    WOLFSSL_MSG("Error in wc_RsaUnPad_ex for RSA verify");
                    status = kStatus_SSS_Fail;
                }
            }
            else {
                WOLFSSL_MSG("Se05x_API_RSAEncrypt failed");
                status = kStatus_SSS_Fail;
            }
        }
        XFREE(decBuf, key->heap, DYNAMIC_TYPE_TMP_BUFFER);

        sss_asymmetric_context_free(&ctx_asymm);
    }

    if (status == kStatus_SSS_Success) {
        if (keyCreated) {
            /* We uploaded only the public part of the key for this verify.
             * Don't persist keyIdSet=1 -- a later sign on the same RsaKey
             * would reuse this binding and fail because the SE050 object has
             * no private material. Erase the transient object so the next
             * SE050 op (sign or verify) re-uploads from whatever the host
             * RsaKey currently holds. */
            sss_key_store_erase_key(&host_keystore, &newKey);
            sss_key_object_free(&newKey);
        }
        else {
            /* Pre-existing keyIdSet=1 binding (e.g. wc_RsaUseKeyId or prior
             * sign that uploaded a keypair). Preserve it. */
            key->keyId = keyId;
            key->keyIdSet = 1;
        }
    }
    else {
        if (keyCreated) {
            sss_key_store_erase_key(&host_keystore, &newKey);
            sss_key_object_free(&newKey);
        }
        if (ret == 0) {
            ret = WC_HW_E;
        }
    }

    wolfSSL_CryptHwMutexUnLock();

#ifdef SE050_DEBUG
    printf("se050_rsa_verify: key %p, ret %d\n", key, ret);
#endif

    return ret;
}

/**
 * RSA public encrypt operation.
 *
 * in        input data to be encrypted
 * inLen     length of input data, bytes
 * out       output buffer containing encrypted data
 * outLen    length of output buffer, bytes
 * key       pointer to initialized/populated RsaKey structure
 * rsa_type  type of RSA: must be RSA_PUBLIC_ENCRYPT
 * pad_value should be RSA_BLOCK_TYPE_2 for encrypting
 * pad_type  type of padding: WC_RSA_PKCSV15_PAD, WC_RSA_OAEP_PAD,
 *           WC_RSA_NO_PAD, WC_RSA_PSS_PAD
 * hash      type of hash algorithm, found in wolfssl/wolfcrypt/hash.h
 * mgf       type of mask generation function to use
 * label     optional label, not supported by SE050, must be NULL
 * labelSz   size of label, not supported by SE050, must be 0
 * keySz     size of RSA key, bytes
 *
 * Returns size of encrypted data on success, negative on error.
 */
int se050_rsa_public_encrypt(const byte* in, word32 inLen, byte* out,
                             word32 outLen, struct RsaKey* key, int rsa_type,
                             byte pad_value, int pad_type,
                             enum wc_HashType hash, int mgf, byte* label,
                             word32 labelSz, int keySz)
{
    int ret = 0;
    int keyCreated = 0;
    word32 keyId;
    size_t encSz;
    sss_object_t     newKey;
    sss_status_t     status;
    sss_key_store_t  host_keystore;
    sss_algorithm_t  algorithm = kAlgorithm_None;
    sss_asymmetric_t ctx_asymm;
    byte* derBuf = NULL;
    int derSz = 0;

    /* SE050 does not support optional label */
    (void)label;
    (void)labelSz;
    (void)mgf;

#ifdef SE050_DEBUG
    printf("se050_rsa_public_encrypt: key %p, in %p (%d), out %p (%d), "
            "key %p\n", key, in, inLen, out, outLen, key);
#endif

    if (in == NULL || out == NULL || key == NULL ||
        rsa_type != RSA_PUBLIC_ENCRYPT || pad_value != RSA_BLOCK_TYPE_2) {
        return BAD_FUNC_ARG;
    }

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }

#ifdef WOLFSSL_SE050_ONLY_KEY_ID
    /* Under ONLY_KEY_ID only SE050-resident keys reach this
     * hardware path. Never auto-import a software key (keyIdSet == 0). */
    if (key->keyIdSet == 0) {
        return NOT_COMPILED_IN;
    }
#endif

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    algorithm = se050_get_rsa_encrypt_type(pad_type, hash);
    if (algorithm == kAlgorithm_None) {
        WOLFSSL_MSG("Unsupported padding/hash/mgf combination for SE050");
        wolfSSL_CryptHwMutexUnLock();
        return BAD_FUNC_ARG;
    }

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore, SE050_KEYSTOREID_RSA);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&newKey, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        keyId = key->keyId;
        if (key->keyIdSet == 0) {
            /* key was not generated in SE050, export RsaKey to DER
             * and use that to store into SE050 keystore */
            derSz = wc_RsaKeyToPublicDer(key, NULL, 0);
            if (derSz < 0) {
                status = kStatus_SSS_Fail;
                ret = derSz;
            }
            else {
                derBuf = (byte*)XMALLOC(derSz, key->heap,
                                        DYNAMIC_TYPE_TMP_BUFFER);
                if (derBuf == NULL) {
                    WOLFSSL_MSG("malloc failed when converting RsaKey to DER");
                    status = kStatus_SSS_Fail;
                    ret = MEMORY_E;
                }
            }
            if (status == kStatus_SSS_Success) {
                derSz = wc_RsaKeyToPublicDer(key, derBuf, derSz);
                if (derSz < 0) {
                    status = kStatus_SSS_Fail;
                    ret = derSz;
                }
            }
            if (status == kStatus_SSS_Success) {
                keyId = se050_allocate_key(SE050_RSA_KEY);
                status = sss_key_object_allocate_handle(&newKey, keyId,
                    kSSS_KeyPart_Public, kSSS_CipherType_RSA, keySz,
                    kKeyObject_Mode_Persistent);
            }
            if (status == kStatus_SSS_Success) {
                /* Try to delete existing key first, ignore return since will
                 * fail if no key exists yet */
                sss_key_store_erase_key(&host_keystore, &newKey);

                keyCreated = 1;
                status = sss_key_store_set_key(&host_keystore, &newKey, derBuf,
                                               derSz, (keySz * 8), NULL, 0);
            }
        }
        else {
            status = sss_key_object_get_handle(&newKey, keyId);
        }

        XFREE(derBuf, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }

    if (status == kStatus_SSS_Success) {
        status = sss_asymmetric_context_init(&ctx_asymm, cfg_se050_i2c_pi,
                    &newKey, algorithm, kMode_SSS_Encrypt);
        if (status == kStatus_SSS_Success) {
            encSz = outLen;
            status = sss_asymmetric_encrypt(&ctx_asymm, (uint8_t*)in, inLen,
                                            out, &encSz);
        }
        sss_asymmetric_context_free(&ctx_asymm);
    }

    if (status == kStatus_SSS_Success) {
        if (keyCreated) {
            /* Public-key encrypt imported a temporary public object only.
             * Do not bind that SE050 object to the caller's RsaKey or later
             * private-key operations will try to reuse a public handle. */
            sss_key_store_erase_key(&host_keystore, &newKey);
            sss_key_object_free(&newKey);
        }
        else {
            key->keyId = keyId;
            key->keyIdSet = 1;
        }
        ret = encSz;
    }
    else {
        if (keyCreated) {
            sss_key_store_erase_key(&host_keystore, &newKey);
            sss_key_object_free(&newKey);
        }
        if (ret == 0) {
            ret = WC_HW_E;
        }
    }

    wolfSSL_CryptHwMutexUnLock();

#ifdef SE050_DEBUG
    printf("se050_rsa_public_encrypt: ret %d, outLen %d\n", ret, outLen);
#endif

    return ret;
}

/**
 * RSA public decrypt operation.
 *
 * in        input data to be decrypted
 * inLen     length of input data, bytes
 * out       output buffer containing decrypted data
 * outLen    length of output buffer, bytes
 * key       pointer to initialized/populated RsaKey structure
 * rsa_type  type of RSA: must be RSA_PRIVATE_DECRYPT
 * pad_value should be RSA_BLOCK_TYPE_2 for encrypting
 * pad_type  type of padding: WC_RSA_PKCSV15_PAD, WC_RSA_OAEP_PAD,
 *           WC_RSA_NO_PAD, WC_RSA_PSS_PAD
 * hash      type of hash algorithm, found in wolfssl/wolfcrypt/hash.h
 * mgf       type of mask generation function to use
 * label     optional label, not supported by SE050, must be NULL
 * labelSz   size of label, not supported by SE050, must be 0
 *
 * Returns size of decrypted data on success, negative on error.
 */
int se050_rsa_private_decrypt(const byte* in, word32 inLen, byte* out,
                             word32 outLen, struct RsaKey* key, int rsa_type,
                             byte pad_value, int pad_type,
                             enum wc_HashType hash, int mgf, byte* label,
                             word32 labelSz)
{
    int ret = 0;
    int keyCreated = 0;
    word32 keyId;
    int keySz;
    size_t decSz;
    sss_object_t     newKey;
    sss_status_t     status;
    sss_key_store_t  host_keystore;
    sss_algorithm_t  algorithm = kAlgorithm_None;
    sss_asymmetric_t ctx_asymm;
    byte* derBuf = NULL;
    int derSz = 0;
    int derBufSz = 0;

    /* SE050 does not support optional label */
    (void)label;
    (void)labelSz;
    (void)mgf;

#ifdef SE050_DEBUG
    printf("se050_rsa_public_decrypt: key %p, in %p (%d), out %p (%d), "
            "key %p\n", key, in, inLen, out, outLen, key);
#endif

    if (in == NULL || out == NULL || key == NULL ||
        rsa_type != RSA_PRIVATE_DECRYPT || pad_value != RSA_BLOCK_TYPE_2) {
        return BAD_FUNC_ARG;
    }

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }

#ifdef WOLFSSL_SE050_ONLY_KEY_ID
    /* Under ONLY_KEY_ID only SE050-resident keys reach this
     * hardware path. Never auto-import a software key (keyIdSet == 0). */
    if (key->keyIdSet == 0) {
        return NOT_COMPILED_IN;
    }
#endif

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    algorithm = se050_get_rsa_encrypt_type(pad_type, hash);
    if (algorithm == kAlgorithm_None) {
        WOLFSSL_MSG("Unsupported padding/hash/mgf combination for SE050");
        wolfSSL_CryptHwMutexUnLock();
        return BAD_FUNC_ARG;
    }

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore, SE050_KEYSTOREID_RSA);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&newKey, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        keySz = wc_RsaEncryptSize(key);
        if (keySz < 0) {
            WOLFSSL_MSG("Failed to get RSA key size from struct");
            status = kStatus_SSS_Fail;
        }
    }
    if (status == kStatus_SSS_Success) {
        keyId = key->keyId;
        if (key->keyIdSet == 0) {
            /* key was not generated in SE050, export RsaKey to DER
             * and use that to store into SE050 keystore */
            derSz = wc_RsaKeyToDer(key, NULL, 0);
            if (derSz < 0) {
                status = kStatus_SSS_Fail;
                ret = derSz;
            }
            else {
                derBuf = (byte*)XMALLOC(derSz, key->heap,
                                        DYNAMIC_TYPE_TMP_BUFFER);
                if (derBuf == NULL) {
                    WOLFSSL_MSG("malloc failed when converting RsaKey to DER");
                    status = kStatus_SSS_Fail;
                    ret = MEMORY_E;
                }
                else {
                    derBufSz = derSz;
                }
            }
            if (status == kStatus_SSS_Success) {
                derSz = wc_RsaKeyToDer(key, derBuf, derSz);
                if (derSz < 0) {
                    status = kStatus_SSS_Fail;
                    ret = derSz;
                }
            }
            if (status == kStatus_SSS_Success) {
                keyId = se050_allocate_key(SE050_RSA_KEY);
                status = sss_key_object_allocate_handle(&newKey, keyId,
                    kSSS_KeyPart_Pair, kSSS_CipherType_RSA, keySz,
                    kKeyObject_Mode_Persistent);
            }
            if (status == kStatus_SSS_Success) {
                /* Try to delete existing key first, ignore return since will
                 * fail if no key exists yet */
                sss_key_store_erase_key(&host_keystore, &newKey);

                keyCreated = 1;
                status = sss_key_store_set_key(&host_keystore, &newKey, derBuf,
                                               derSz, (keySz * 8), NULL, 0);
            }
        }
        else {
            status = sss_key_object_get_handle(&newKey, keyId);
        }

        if ((derBuf != NULL) && (derBufSz > 0)) {
            /* Private key encoding sent to the SE. Wipe the whole allocation:
             * a failed encode leaves derSz negative having possibly already
             * written to the buffer. */
            ForceZero(derBuf, (word32)derBufSz);
        }
        XFREE(derBuf, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }

    if (status == kStatus_SSS_Success) {
        status = sss_asymmetric_context_init(&ctx_asymm, cfg_se050_i2c_pi,
                    &newKey, algorithm, kMode_SSS_Decrypt);
        if (status == kStatus_SSS_Success) {
            decSz = outLen;
            status = sss_asymmetric_decrypt(&ctx_asymm, (uint8_t*)in, inLen,
                                            out, &decSz);
        }
        sss_asymmetric_context_free(&ctx_asymm);
    }

    if (status == kStatus_SSS_Success) {
        key->keyId = keyId;
        key->keyIdSet = 1;
        ret = decSz;
    }
    else {
        if (keyCreated) {
            sss_key_store_erase_key(&host_keystore, &newKey);
            sss_key_object_free(&newKey);
        }
        if (ret == 0) {
            ret = WC_HW_E;
        }
    }

    wolfSSL_CryptHwMutexUnLock();

#ifdef SE050_DEBUG
    printf("se050_rsa_public_decrypt: ret %d, outLen %d\n", ret, outLen);
#endif

    return ret;
}

#endif /* NO_RSA */

#ifdef HAVE_ECC

static int se050_map_curve(int curve_id, int keySize,
    int* keySizeBits, sss_cipher_type_t* pcurve_type)
{
    int ret = 0;
    sss_cipher_type_t curve_type = kSSS_CipherType_NONE;

    *keySizeBits = keySize * 8; /* set default */
    switch (curve_id) {
        case ECC_SECP160K1:
        case ECC_SECP192K1:
        case ECC_SECP224K1:
        case ECC_SECP256K1:
        #ifdef HAVE_ECC_KOBLITZ
            curve_type = kSSS_CipherType_EC_NIST_K;
        #else
            ret = ECC_CURVE_OID_E;
        #endif
            break;
        case ECC_BRAINPOOLP160R1:
        case ECC_BRAINPOOLP192R1:
        case ECC_BRAINPOOLP224R1:
        case ECC_BRAINPOOLP256R1:
        case ECC_BRAINPOOLP320R1:
        case ECC_BRAINPOOLP384R1:
        case ECC_BRAINPOOLP512R1:
        #ifdef HAVE_ECC_BRAINPOOL
            curve_type = kSSS_CipherType_EC_BRAINPOOL;
        #else
            ret = ECC_CURVE_OID_E;
        #endif
            break;
        case ECC_CURVE_DEF:
        case ECC_SECP160R1:
        case ECC_SECP192R1:
        case ECC_SECP224R1:
        case ECC_SECP256R1:
        case ECC_SECP384R1:
            curve_type = kSSS_CipherType_EC_NIST_P;
            break;
        case ECC_SECP521R1:
            curve_type = kSSS_CipherType_EC_NIST_P;
            *keySizeBits = 521;
            break;
        case ECC_PRIME239V1:
        case ECC_PRIME192V2:
        case ECC_PRIME192V3:
        default:
            ret = ECC_CURVE_OID_E;
            break;
    }
    if (pcurve_type)
        *pcurve_type = curve_type;
    return ret;
}

static int se050_ecc_generate_key(word32 keyId, int keySize, int curveId,
    const sss_policy_t* policy)
{
    sss_status_t status = kStatus_SSS_Success;
    sss_object_t keyPair;
    sss_key_store_t host_keystore;
    sss_cipher_type_t curveType;
    int keyObjectInit = 0;
    int keySizeBits;
    int ret;

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }
    if ((keyId >= SE050_KEYID_START) || (keySize <= 0)) {
        return BAD_FUNC_ARG;
    }
    ret = se050_map_curve(curveId, keySize, &keySizeBits, &curveType);
    if (ret != 0) {
        return ret;
    }
    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    status = se050_require_new_object(keyId);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_context_init(&host_keystore,
            cfg_se050_i2c_pi);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore,
            SE050_KEYSTOREID_ECC);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&keyPair, &host_keystore);
        if (status == kStatus_SSS_Success) {
            keyObjectInit = 1;
        }
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_allocate_handle(&keyPair, keyId,
            kSSS_KeyPart_Pair, curveType, keySize,
            kKeyObject_Mode_Persistent);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_generate_key(&host_keystore, &keyPair,
            keySizeBits, (void*)policy);
    }

    if (keyObjectInit) {
        sss_key_object_free(&keyPair);
    }
    wolfSSL_CryptHwMutexUnLock();
    return (status == kStatus_SSS_Success) ? 0 : WC_HW_E;
}

int wc_se050_ecc_generate_key_policy(word32 keyId, int keySize, int curveId,
    const sss_policy_t* policy)
{
    return se050_ecc_generate_key(keyId, keySize, curveId, policy);
}

int wc_se050_ecc_generate_key_ex(word32 keyId, int keySize, int curveId,
    word32 policyFlags, word32 authObjId)
{
    const sss_policy_t* policy = NULL;
    se050_policy_set policySet;
    int ret;

    ret = se050_build_policy_set(SE050_POLICY_OBJECT_ASYM, policyFlags,
        authObjId, &policySet);
    if (ret != 0) {
        return ret;
    }
    if (policyFlags != 0U) {
        policy = &policySet.policy;
    }
    return se050_ecc_generate_key(keyId, keySize, curveId, policy);
}

static sss_algorithm_t se050_map_hash_alg(int hashLen)
{
    sss_algorithm_t algorithm = kAlgorithm_None;
    if (hashLen == 20) {
        algorithm = kAlgorithm_SSS_SHA1;
    } else if (hashLen == 28) {
        algorithm = kAlgorithm_SSS_SHA224;
    } else if (hashLen == 32) {
        algorithm = kAlgorithm_SSS_SHA256;
    } else if (hashLen == 48) {
        algorithm = kAlgorithm_SSS_SHA384;
    } else if (hashLen == 64 || hashLen == 66) {
        /* ECC P-521 can pass key size 66, use SHA-512 */
        algorithm = kAlgorithm_SSS_SHA512;
    }
    return algorithm;
}

static int se050_ecc_insert_key(word32 keyId, const byte* eccDer,
    word32 eccDerSize, int keyType, const sss_policy_t* policy,
    int requireNew)
{
    int               ret = 0;
    struct ecc_key    key;
    sss_object_t      newKey;
    sss_key_store_t   host_keystore;
    sss_status_t      status = kStatus_SSS_Success;
    int               keySizeBits = 0;
    int               keySize = 0;
    word32            idx = 0;
    sss_cipher_type_t curveType = kSSS_CipherType_NONE;
    sss_key_part_t    keyPart = kSSS_KeyPart_Pair;

    if ((cfg_se050_i2c_pi == NULL) || (eccDer == NULL) ||
            (eccDerSize == 0U)) {
        return BAD_FUNC_ARG;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    /* Avoid key ID conflicts with temporary key storage */
    if (keyId >= SE050_KEYID_START) {
        wolfSSL_CryptHwMutexUnLock();
        return BAD_FUNC_ARG;
    }

    if (requireNew) {
        status = se050_require_new_object(keyId);
    }

    ret = wc_ecc_init(&key);
    if (ret != 0) {
        status = kStatus_SSS_Fail;
    } else {
        if (keyType == ECC_PUBLICKEY) {
            keyPart = kSSS_KeyPart_Public;
            ret = wc_EccPublicKeyDecode(eccDer, &idx, &key, eccDerSize);
        }
        else if (keyType == ECC_PRIVATEKEY) {
            keyPart = kSSS_KeyPart_Pair;
            ret = wc_EccPrivateKeyDecode(eccDer, &idx, &key, eccDerSize);
        }
        else {
            ret = BAD_FUNC_ARG;
        }

        if (ret != 0) {
            status = kStatus_SSS_Fail;
        }
    }

    if (status == kStatus_SSS_Success) {
        keySize = key.dp->size;
        ret = se050_map_curve(key.dp->id, keySize, &keySizeBits, &curveType);
        if (ret != 0) {
            status = kStatus_SSS_Fail;
        }
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&newKey, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_allocate_handle(&newKey, keyId,
            keyPart, curveType, MAX_ECC_BYTES,
            kKeyObject_Mode_Persistent);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_set_key(&host_keystore, &newKey, eccDer,
            eccDerSize, keySizeBits, (void*)policy, 0);
    }
    wolfSSL_CryptHwMutexUnLock();

    wc_ecc_free(&key);
    if (status != kStatus_SSS_Success) {
        if (ret == 0)
            ret = WC_HW_E;
    }

    return ret;
}

/**
 * Insert ECC public key into SE050 at specified key ID.
 *
 * keyId       SE050 key ID to place public key into
 * eccDer      DER encoded ECC public key
 * eccDerSize  Size of eccDer, bytes
 *
 * Return 0 on success, negative on error.
 */
int wc_se050_ecc_insert_public_key(word32 keyId, const byte* eccDer,
                                   word32 eccDerSize)
{
    return se050_ecc_insert_key(keyId, eccDer, eccDerSize, ECC_PUBLICKEY,
        NULL, 0);
}

/**
 * Insert ECC private key into SE050 at specified key ID.
 *
 * keyId       SE050 key ID to place private key into
 * eccDer      DER encoded ECC private key
 * eccDerSize  Size of eccDer, bytes
 *
 * Return 0 on success, negative on error.
 */
int wc_se050_ecc_insert_private_key(word32 keyId, const byte* eccDer,
                                    word32 eccDerSize)
{
    return se050_ecc_insert_key(keyId, eccDer, eccDerSize, ECC_PRIVATEKEY,
        NULL, 0);
}

int wc_se050_ecc_insert_public_key_policy(word32 keyId, const byte* eccDer,
    word32 eccDerSize, const sss_policy_t* policy)
{
    return se050_ecc_insert_key(keyId, eccDer, eccDerSize, ECC_PUBLICKEY,
        policy, 0);
}

int wc_se050_ecc_insert_private_key_policy(word32 keyId, const byte* eccDer,
    word32 eccDerSize, const sss_policy_t* policy)
{
    return se050_ecc_insert_key(keyId, eccDer, eccDerSize, ECC_PRIVATEKEY,
        policy, 0);
}

static int se050_ecc_insert_key_ex(word32 keyId, const byte* eccDer,
    word32 eccDerSize, int keyType, word32 policyFlags, word32 authObjId)
{
    int ret;
    const sss_policy_t* policy = NULL;
    se050_policy_set policySet;

    ret = se050_build_policy_set(SE050_POLICY_OBJECT_ASYM, policyFlags,
        authObjId, &policySet);
    if (ret != 0) {
        return ret;
    }
    if (policyFlags != 0U) {
        policy = &policySet.policy;
    }
    return se050_ecc_insert_key(keyId, eccDer, eccDerSize, keyType, policy,
        1);
}

int wc_se050_ecc_insert_public_key_ex(word32 keyId, const byte* eccDer,
    word32 eccDerSize, word32 policyFlags, word32 authObjId)
{
    return se050_ecc_insert_key_ex(keyId, eccDer, eccDerSize, ECC_PUBLICKEY,
        policyFlags, authObjId);
}

int wc_se050_ecc_insert_private_key_ex(word32 keyId, const byte* eccDer,
    word32 eccDerSize, word32 policyFlags, word32 authObjId)
{
    return se050_ecc_insert_key_ex(keyId, eccDer, eccDerSize, ECC_PRIVATEKEY,
        policyFlags, authObjId);
}

int se050_ecc_sign_hash_ex(const byte* in, word32 inLen, MATH_INT_T* r, MATH_INT_T* s,
                           byte* out, word32 *outLen, struct ecc_key* key)
{
    int                 ret = 0;
    sss_status_t        status;
    sss_asymmetric_t    ctx_asymm;
    sss_key_store_t     host_keystore;
    sss_object_t        newKey;
    sss_algorithm_t     algorithm;
    int                 keySize;
    int                 keySizeBits;
    int                 keyCreated = 0;
    word32              keyId;
    sss_cipher_type_t   curveType;

    byte sigBuf[ECC_MAX_SIG_SIZE];
    size_t sigSz = sizeof(sigBuf);
    word32 rLen = 0;
    word32 sLen = 0;
#ifndef WC_ALLOW_ECC_ZERO_HASH
    byte hashIsZero = 0;
    word32 zIdx;
#endif

#ifdef SE050_DEBUG
    printf("se050_ecc_sign_hash_ex: key %p, in %p (%d), out %p (%d), "
            "keyId %d\n", key, in, inLen, out, *outLen, key->keyId);
#endif

    if (in == NULL || r == NULL || s == NULL || out == NULL ||
        outLen == NULL || key == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SE050_ONLY_KEY_ID
    /* Under ONLY_KEY_ID only SE050-resident keys reach this
     * hardware path. Never auto-import a software key (keyIdSet == 0). */
    if (key->keyIdSet == 0) {
        return NOT_COMPILED_IN;
    }
#endif

#ifndef WC_ALLOW_ECC_ZERO_HASH
    /* SE050 hardware does not reject all-zero digests; mirror the
     * software path's check so behavior is consistent. */
    for (zIdx = 0; zIdx < inLen; zIdx++)
        hashIsZero |= in[zIdx];
    if (hashIsZero == 0)
        return ECC_BAD_ARG_E;
#endif

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }

    keySize = key->dp->size;
    ret = se050_map_curve(key->dp->id, keySize, &keySizeBits, &curveType);
    if (ret != 0) {
        return ret;
    }

    /* truncate if digest is larger than key size */
    if (inLen > (word32)keySize) {
        inLen = (word32)keySize;
    }

    /* For P-521, if inLen is 66, truncate down to 64 for SHA-512 */
    if ((keySize == 66) && (inLen == 66)) {
        inLen = 64;
    }

    algorithm = se050_map_hash_alg(inLen);
    if (algorithm == kAlgorithm_None) {
        WOLFSSL_MSG("SE050 ECDSA sign only supports SHA-1/224/256/384/512 digest sizes");
        return BAD_LENGTH_E;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore, SE050_KEYSTOREID_ECC);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&newKey, &host_keystore);
    }
    /* this is run when a key was not generated and was instead passed in */
    if (status == kStatus_SSS_Success) {
        keyId = key->keyId;
        if (key->keyIdSet == 0) {
            byte derBuf[SE050_ECC_DER_MAX];
            word32 derSz;

            ret = wc_EccKeyToDer(key, derBuf, (word32)sizeof(derBuf));
            if (ret >= 0) {
                derSz = ret;
                ret = 0;
            }
            else {
                status = kStatus_SSS_Fail;
            }
            if (status == kStatus_SSS_Success) {
                keyId = se050_allocate_key(SE050_ECC_KEY);
                status = sss_key_object_allocate_handle(&newKey, keyId,
                    kSSS_KeyPart_Pair, curveType, keySize,
                    kKeyObject_Mode_Persistent);
            }
            if (status == kStatus_SSS_Success) {
                /* Try to delete existing key first, ignore return since will
                 * fail if no key exists yet */
                sss_key_store_erase_key(&host_keystore, &newKey);

                keyCreated = 1;
                status = sss_key_store_set_key(&host_keystore, &newKey, derBuf,
                                                derSz, keySizeBits, NULL, 0);
            }
            /* Private scalar encoding sent to the SE. */
            ForceZero(derBuf, sizeof(derBuf));
        }
        else {
            status = sss_key_object_get_handle(&newKey, keyId);
        }
    }

    if (status == kStatus_SSS_Success) {

        status = sss_asymmetric_context_init(&ctx_asymm, cfg_se050_i2c_pi,
            &newKey, algorithm, kMode_SSS_Sign);
        if (status == kStatus_SSS_Success) {

            status = sss_asymmetric_sign_digest(&ctx_asymm, (uint8_t*)in, inLen,
                sigBuf, &sigSz);
            if (status == kStatus_SSS_Success) {

                /* SE050 returns ASN.1 encoded signature */
                rLen = keySize;
                sLen = keySize;

                ret = DecodeECC_DSA_Sig_Bin(sigBuf, (word32)sigSz,
                    out,         &rLen,
                    out+keySize, &sLen);

                if (ret != 0) {
                    status = kStatus_SSS_Fail;
                } else {
                    /* In case rLen is smaller than keySize, move S up */
                    XMEMCPY(out + rLen, out + keySize, sLen);
                }
            }
        }
        sss_asymmetric_context_free(&ctx_asymm);
    }

    if (status == kStatus_SSS_Success) {
        /* Load R and S into mp_int */
        ret = mp_read_unsigned_bin(r, out, rLen);
        if (ret == MP_OKAY) {
            ret = mp_read_unsigned_bin(s, out + rLen, sLen);
        }
        if (ret != MP_OKAY) {
            status = kStatus_SSS_Fail;
        }
        ret = 0;
    }

    if (status == kStatus_SSS_Success) {
        key->keyId = keyId;
        key->keyIdSet = 1;
        ret = 0;
    }
    else {
        if (keyCreated) {
            sss_key_store_erase_key(&host_keystore, &newKey);
            sss_key_object_free(&newKey);
        }
        if (ret == 0)
            ret = WC_HW_E;
    }

    wolfSSL_CryptHwMutexUnLock();

#ifdef SE050_DEBUG
    printf("se050_ecc_sign_hash_ex: ret %d, outLen %d\n", ret, *outLen);
#endif

    (void)outLen; /* caller sets outLen */

    return ret;
}

int se050_ecc_verify_hash_ex(const byte* hash, word32 hashLen, MATH_INT_T* r,
                             MATH_INT_T* s, struct ecc_key* key, int* res)
{
    int                 ret = 0;
    sss_status_t        status;
    sss_asymmetric_t    ctx_asymm;
    sss_object_t        newKey;
    sss_key_store_t     host_keystore;
    sss_algorithm_t     algorithm;
    int                 keyId;
    int                 keySize;
    int                 keySizeBits;
    sss_cipher_type_t   curveType;
    int                 keyCreated = 0;

    byte rBuf[ECC_MAX_CRYPTO_HW_SIZE];
    byte sBuf[ECC_MAX_CRYPTO_HW_SIZE];
    byte sigBuf[ECC_MAX_SIG_SIZE];
    word32 rBufSz = (word32)sizeof(rBuf);
    word32 sBufSz = (word32)sizeof(sBuf);
    word32 sigSz  = (word32)sizeof(sigBuf);

#ifdef SE050_DEBUG
    printf("se050_ecc_verify_hash_ex: key %p, hash %p (%d)\n",
        key, hash, hashLen);
#endif

    *res = 0;

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }

#ifdef WOLFSSL_SE050_ONLY_KEY_ID
    /* Under ONLY_KEY_ID only SE050-resident keys reach this
     * hardware path. Never auto-import a software key (keyIdSet == 0). */
    if (key->keyIdSet == 0) {
        return NOT_COMPILED_IN;
    }
#endif

    keySize = key->dp->size;
    ret = se050_map_curve(key->dp->id, keySize, &keySizeBits, &curveType);
    if (ret != 0) {
        return ret;
    }

    /* truncate hash if larger than key size */
    if (hashLen > (word32)keySize) {
        hashLen = (word32)keySize;
    }

    /* For P-521, if inLen is 66, truncate down to 64 for SHA-512 */
    if ((keySize == 66) && (hashLen == 66)) {
        hashLen = 64;
    }

    algorithm = se050_map_hash_alg(hashLen);
    if (algorithm == kAlgorithm_None) {
        WOLFSSL_MSG("SE050 ECDSA verify only supports SHA-1/224/256/384/512 digest sizes");
        return BAD_LENGTH_E;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore, SE050_KEYSTOREID_ECC);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&newKey, &host_keystore);
    }

    /* this is run when a key was not generated and was instead passed in */
    if (status == kStatus_SSS_Success) {
        keyId = key->keyId;
        if (key->keyIdSet == 0) {
            byte derBuf[SE050_ECC_DER_MAX];
            word32 derSz;

            ret = wc_EccPublicKeyToDer(key, derBuf, (word32)sizeof(derBuf), 1);
            if (ret >= 0) {
                derSz = ret;
                ret = 0;
            }
            else {
                status = kStatus_SSS_Fail;
            }
            if (status == kStatus_SSS_Success) {
                keyId = se050_allocate_key(SE050_ECC_KEY);
                status = sss_key_object_allocate_handle(&newKey, keyId,
                    kSSS_KeyPart_Public, curveType, keySize,
                    kKeyObject_Mode_Persistent);
            }
            if (status == kStatus_SSS_Success) {
                /* Try to delete existing key first, ignore return since will
                 * fail if no key exists yet */
                sss_key_store_erase_key(&host_keystore, &newKey);

                keyCreated = 1;
                status = sss_key_store_set_key(&host_keystore, &newKey, derBuf,
                                                derSz, keySizeBits, NULL, 0);
            }
        }
        else {
            status = sss_key_object_get_handle(&newKey, keyId);
        }
    }

    if (status == kStatus_SSS_Success) {
        status = sss_asymmetric_context_init(&ctx_asymm, cfg_se050_i2c_pi,
                                    &newKey, algorithm, kMode_SSS_Verify);

        if (status == kStatus_SSS_Success) {
            /* SE050 expects ASN.1 encoded signature */
            XMEMSET(rBuf, 0, sizeof(rBuf));
            XMEMSET(sBuf, 0, sizeof(sBuf));

            rBufSz = mp_unsigned_bin_size(r);
            sBufSz = mp_unsigned_bin_size(s);

            if (rBufSz > sizeof(rBuf) || sBufSz > sizeof(sBuf)) {
                WOLFSSL_MSG("Internal R/S buffers too small for signature");
                ret = BUFFER_E;
            }

            if (ret == 0) {
                ret = mp_to_unsigned_bin(r, rBuf);
                if (ret == MP_OKAY) {
                    ret = mp_to_unsigned_bin(s, sBuf);
                }
            }

            if (ret == 0) {
                ret = StoreECC_DSA_Sig_Bin(sigBuf, &sigSz, rBuf, rBufSz,
                                           sBuf, sBufSz);
            }

            if (ret == 0) {
                status = sss_asymmetric_verify_digest(&ctx_asymm,
                    (uint8_t*)hash, hashLen, sigBuf, sigSz);
            }
            else {
                status = kStatus_SSS_Fail;
            }
        }
        sss_asymmetric_context_free(&ctx_asymm);
    }

    if (status == kStatus_SSS_Success) {
        key->keyId = keyId;
        key->keyIdSet = 1;
        *res = 1;
        ret = 0;
    }
    else {
        if (keyCreated) {
            sss_key_store_erase_key(&host_keystore, &newKey);
            sss_key_object_free(&newKey);
        }
        if (ret == 0)
            ret = WC_HW_E;
    }

    wolfSSL_CryptHwMutexUnLock();

#ifdef SE050_DEBUG
    printf("se050_ecc_verify_hash_ex: key %p, ret %d, res %d\n",
        key, ret, *res);
#endif

    return ret;
}


void se050_ecc_free_key(struct ecc_key* key)
{
    sss_status_t    status = kStatus_SSS_Success;
    sss_object_t    keyObject;
    sss_key_store_t host_keystore;

#ifdef SE050_DEBUG
    printf("se050_ecc_free_key: key %p, keyId %d\n", key, key->keyId);
#endif

    if (cfg_se050_i2c_pi == NULL) {
        return;
    }
    if (key->keyIdSet == 0) {
        return;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return;
    }

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore, SE050_KEYSTOREID_ECC);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&keyObject, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_get_handle(&keyObject, key->keyId);
    }

    if (status == kStatus_SSS_Success) {
        /* Erase key from SE050 persistent storage if it was allocated
         * by wolfSSL (not a pre-provisioned key). Without this, persistent
         * key objects leak on the SE050 and can exhaust secure storage. */
        if (key->keyId >= SE050_KEYID_START) {
            sss_key_store_erase_key(&host_keystore, &keyObject);
        }
        sss_key_object_free(&keyObject);
        key->keyId = 0;
        key->keyIdSet = 0;
    }
    wolfSSL_CryptHwMutexUnLock();
}

/**
 * Use specified SE050 key ID with this ecc_key struct.
 * Should be called by wc_ecc_use_key_id() for using pre-populated
 * SE050 keys.
 *
 * key   Pointer to initialized ecc_key structure
 * keyId SE050 key ID containing ECC key object
 *
 * Return 0 on success, negative on error.
 */
int se050_ecc_use_key_id(struct ecc_key* key, word32 keyId)
{
    int ret = 0;
    sss_object_t    keyObject;
    sss_key_store_t host_keystore;
    sss_status_t    status = kStatus_SSS_Success;
    uint8_t         derBuf[SE050_ECC_DER_MAX];
    size_t          derSz = sizeof(derBuf);
    size_t          derSzBits = 0;
    word32          idx = 0;

#ifdef SE050_DEBUG
    printf("se050_ecc_use_key_id: key %p, keyId %d\n", key, keyId);
#endif
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore, SE050_KEYSTOREID_ECC);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&keyObject, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_get_handle(&keyObject, keyId);
    }
    if (status == kStatus_SSS_Success) {
        derSzBits = derSz * 8;
        status = sss_key_store_get_key(&host_keystore, &keyObject,
            derBuf, &derSz, &derSzBits);
        (void)derSzBits; /* not used */
    }
    if (status == kStatus_SSS_Success) {
        ret = wc_EccPublicKeyDecode(derBuf, &idx, key, (word32)derSz);
        if (ret != 0) {
            status = kStatus_SSS_Fail;
        }
    }
    if (status == kStatus_SSS_Success) {
        key->keyId = keyId;
        key->keyIdSet = 1;
        ret = 0;
    }
    else if (ret == 0) {
        ret = WC_HW_E;
    }

    sss_key_object_free(&keyObject);

    wolfSSL_CryptHwMutexUnLock();

#ifdef SE050_DEBUG
    printf("se050_ecc_use_key_id: ret %d\n", ret);
#endif

    return ret;
}

/**
 * Get SE050 key ID associated with this ecc_key struct.
 * Should be called by wc_ecc_get_key_id() for the application to get
 * what key ID wolfCrypt picked for this ecc_key struct when generating
 * a key inside the SE050.
 *
 * key   Pointer to initialized ecc_key structure
 * keyId [OUT] SE050 key ID associated with this key structure
 *
 * Return 0 on success, negative on error.
 */
int se050_ecc_get_key_id(struct ecc_key* key, word32* keyId)
{
    int ret = 0;

    if (key == NULL || keyId == NULL) {
        return BAD_FUNC_ARG;
    }

    if (key->keyIdSet == 1) {
        *keyId = key->keyId;

    } else {
        WOLFSSL_MSG("SE050 key ID not set for ecc_key struct");
        ret = WC_HW_E;
    }

    return ret;
}

int se050_ecc_create_key(struct ecc_key* key, int curve_id, int keySize)
{
    int               ret = 0;
    sss_status_t      status = kStatus_SSS_Success;
    sss_object_t      keyPair;
    sss_key_store_t   host_keystore;
    uint8_t           derBuf[SE050_ECC_DER_MAX];
    size_t            derSz = sizeof(derBuf);
    word32            keyId = 0;
    int               keySizeBits;
    sss_cipher_type_t curveType;
    int               keyCreated = 0;

#ifdef SE050_DEBUG
    printf("se050_ecc_create_key: key %p, curve %d, keySize %d\n",
        key, curve_id, keySize);
#endif

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }

    ret = se050_map_curve(curve_id, keySize, &keySizeBits, &curveType);
    if (ret != 0) {
        return ret;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore, SE050_KEYSTOREID_ECC);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&keyPair, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        keyId = se050_allocate_key(SE050_ECC_KEY);
        /* Using Transient key type here does not work with SE050 */
        status = sss_key_object_allocate_handle(&keyPair, keyId,
            kSSS_KeyPart_Pair, curveType, keySize,
            kKeyObject_Mode_Persistent);
    }
    if (status == kStatus_SSS_Success) {
        /* Try to delete existing key first. Ignore return since will fail
         * if no key exists */
        sss_key_store_erase_key(&host_keystore, &keyPair);

        keyCreated = 1;
        status = sss_key_store_generate_key(&host_keystore, &keyPair,
            keySizeBits, NULL);
    }
    if (status == kStatus_SSS_Success) {
        size_t derSzBits = derSz * 8;
        status = sss_key_store_get_key(&host_keystore, &keyPair,
            derBuf, &derSz, &derSzBits);
        (void)derSzBits; /* not used */
    }
    if (status == kStatus_SSS_Success) {
        word32 idx = 0;
        ret = wc_EccPublicKeyDecode(derBuf, &idx, key, (word32)derSz);
        if (ret != 0) {
            status = kStatus_SSS_Fail;
        }
    }
    if (status == kStatus_SSS_Success) {
        key->keyId = keyId;
        key->keyIdSet = 1;
        ret = 0;
    }
    else {
        if (keyCreated) {
            sss_key_store_erase_key(&host_keystore, &keyPair);
            sss_key_object_free(&keyPair);
        }
        if (ret == 0)
            ret = WC_HW_E;
    }

    wolfSSL_CryptHwMutexUnLock();

#ifdef SE050_DEBUG
    printf("se050_ecc_create_key: key %p, ret %d, status %d, keyId %d\n",
        key, ret, status, key->keyId);
#endif

    return ret;
}


int se050_ecc_shared_secret(ecc_key* private_key, ecc_key* public_key,
    byte* out, word32* outlen)
{
    int                 ret;
    sss_status_t        status = kStatus_SSS_Success;
    sss_key_store_t     host_keystore;
    sss_object_t        ref_private_key;
    sss_object_t        ref_public_key;
    int                 keySize;
    int                 keySizeBits;
    sss_cipher_type_t   curveType;
#if !(defined(SSS_HAVE_SE05X_VER_GTE_07_02) && SSS_HAVE_SE05X_VER_GTE_07_02)
    sss_object_t        deriveKey;
    sss_derive_key_t    ctx_derive_key;
    word32              keyId = 0;
    int                 keyCreated = 0;
    int                 deriveKeyCreated = 0;
#endif

#ifdef SE050_DEBUG
    printf("se050_ecc_shared_secret: priv %p, pub %p, out %p (%d)\n",
        private_key, public_key, out, *outlen);
#endif

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }
    if (private_key == NULL || public_key == NULL ||
        private_key->keyIdSet == 0) {
        return BAD_FUNC_ARG;
    }

    keySize = private_key->dp->size;
    ret = se050_map_curve(private_key->dp->id, keySize, &keySizeBits,
                          &curveType);
    if (ret != 0) {
        return ret;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore, SE050_KEYSTOREID_ECC);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&ref_private_key, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_get_handle(&ref_private_key,
                                           private_key->keyId);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&ref_public_key, &host_keystore);
    }
#if !(defined(SSS_HAVE_SE05X_VER_GTE_07_02) && SSS_HAVE_SE05X_VER_GTE_07_02)
    if (status == kStatus_SSS_Success) {
        keyId = public_key->keyId;
        if (public_key->keyIdSet == 0) {
            byte derBuf[SE050_ECC_DER_MAX];
            word32 derSz;
#ifdef WOLFSSL_SE050_ONLY_KEY_ID
            /* The peer's public key is uploaded for this derivation only and
             * erased afterwards, so it must not occupy SE050 flash. */
            sss_key_object_mode_t pubKeyMode = kKeyObject_Mode_Transient;
#else
            sss_key_object_mode_t pubKeyMode = kKeyObject_Mode_Persistent;
#endif

            ret = wc_EccPublicKeyToDer(public_key, derBuf,
                (word32)sizeof(derBuf), 1);
            if (ret >= 0) {
                derSz = ret;
                ret = 0;
            }
            else {
                status = kStatus_SSS_Fail;
            }
            if (status == kStatus_SSS_Success) {
                keyId = se050_allocate_key(SE050_ECC_KEY);
                status = sss_key_object_allocate_handle(&ref_public_key,
                    keyId, kSSS_KeyPart_Public, curveType, keySize,
                    pubKeyMode);
            }
            if (status == kStatus_SSS_Success) {
                /* Try to delete existing key first, ignore return since will
                 * fail if no key exists yet */
                sss_key_store_erase_key(&host_keystore, &ref_public_key);
                status = sss_key_store_set_key(&host_keystore, &ref_public_key,
                    derBuf, derSz, keySizeBits, NULL, 0);
                keyCreated = 1;
            }
        }
        else {
            status = sss_key_object_get_handle(&ref_public_key, keyId);
        }
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&deriveKey, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        word32 keyIdAes = se050_allocate_key(SE050_AES_KEY);
        status = sss_key_object_allocate_handle(&deriveKey,
            keyIdAes,
            kSSS_KeyPart_Default,
            /* The applet denies ReadObject on a symmetric key object no
             * matter what policy is attached, so the derive target must
             * be a Binary object, which ReadObject allows by default */
            kSSS_CipherType_Binary,
            keySize,
            kKeyObject_Mode_Transient);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_derive_key_context_init(&ctx_derive_key, cfg_se050_i2c_pi,
                                    &ref_private_key, kAlgorithm_SSS_ECDH,
                                    kMode_SSS_ComputeSharedSecret);
        if (status == kStatus_SSS_Success) {
            /* Try to delete existing key first, ignore return since will
             * fail if no key exists yet */
            sss_key_store_erase_key(&host_keystore, &deriveKey);
            status = sss_derive_key_dh(&ctx_derive_key, &ref_public_key,
                &deriveKey);
        }
        if (status == kStatus_SSS_Success) {
            size_t outlenSz = (size_t)*outlen;
            size_t outlenSzBits = outlenSz * 8;
            deriveKeyCreated = 1;
            /* derived key export */
            status = sss_key_store_get_key(&host_keystore, &deriveKey,
                out, &outlenSz, &outlenSzBits);
            *outlen = (word32)outlenSz;
            (void)outlenSzBits; /* not used */
        }

        sss_derive_key_context_free(&ctx_derive_key);
    }
    if (deriveKeyCreated) {
        sss_key_store_erase_key(&host_keystore, &deriveKey);
        sss_key_object_free(&deriveKey);
    }
#else
    /* The direct APDU carries the peer public point in the command, so
     * the peer key is never uploaded to the SE050 on this path; a
     * reference object is only needed when the peer public key is
     * already SE050-resident. */
    if (status == kStatus_SSS_Success && public_key->keyIdSet != 0) {
        status = sss_key_object_get_handle(&ref_public_key,
            public_key->keyId);
    }
    if (status == kStatus_SSS_Success) {
        /* Middleware built for applet >= 7.2 derives into an SE05x
         * resident object, but the applet refuses to export a symmetric
         * key object regardless of the policy attached at its creation
         * (verified on SE051 applet 7.2.0 hardware), so a derived secret
         * stored in an object can never be read back. Use the direct
         * APDU that returns the shared secret in the response instead,
         * as the middleware itself does whenever the derived key lives
         * in a host keystore. */
        byte peerPoint[SE050_ECC_DER_MAX];
        word32 peerPointSz = (word32)sizeof(peerPoint);
        smStatus_t sm;

        if (public_key->keyIdSet == 0) {
            ret = wc_ecc_export_x963(public_key, peerPoint, &peerPointSz);
            if (ret != 0) {
                status = kStatus_SSS_Fail;
            }
        }
        else {
            /* Peer public key is SE050-resident: read the DER encoding
             * back and use the trailing uncompressed point */
            size_t derSz = sizeof(peerPoint);
            size_t derSzBits = derSz * 8;
            word32 pointSz = (word32)(1 + 2 * keySize);
            status = sss_key_store_get_key(&host_keystore, &ref_public_key,
                peerPoint, &derSz, &derSzBits);
            if (status == kStatus_SSS_Success && derSz >= pointSz &&
                    peerPoint[derSz - pointSz] == 0x04) {
                XMEMMOVE(peerPoint, peerPoint + derSz - pointSz, pointSz);
                peerPointSz = pointSz;
            }
            else {
                status = kStatus_SSS_Fail;
            }
        }
        if (status == kStatus_SSS_Success) {
            size_t outSz = (size_t)*outlen;
            sm = Se05x_API_ECDHGenerateSharedSecret(
                &((sss_se05x_session_t*)cfg_se050_i2c_pi)->s_ctx,
                private_key->keyId, peerPoint, peerPointSz, out, &outSz);
            /* a NIST curve shared secret is always exactly keySize
             * bytes; anything else indicates a malformed response */
            if (sm == SM_OK && outSz == (size_t)keySize) {
                *outlen = (word32)outSz;
            }
            else {
                status = kStatus_SSS_Fail;
            }
        }
    }
#endif

    if (status == kStatus_SSS_Success) {
#if !(defined(SSS_HAVE_SE05X_VER_GTE_07_02) && SSS_HAVE_SE05X_VER_GTE_07_02)
#ifdef WOLFSSL_SE050_ONLY_KEY_ID
        if (keyCreated) {
            /* The peer's public key was uploaded for this derivation only. */
            sss_key_store_erase_key(&host_keystore, &ref_public_key);
            sss_key_object_free(&ref_public_key);
        }
        else
#endif
        {
            public_key->keyId = keyId;
            public_key->keyIdSet = 1;
        }
#endif /* !SSS_HAVE_SE05X_VER_GTE_07_02 */
        ret = 0;
    }
    else {
#if !(defined(SSS_HAVE_SE05X_VER_GTE_07_02) && SSS_HAVE_SE05X_VER_GTE_07_02)
        if (keyCreated) {
            sss_key_store_erase_key(&host_keystore, &ref_public_key);
            sss_key_object_free(&ref_public_key);
        }
#endif
        if (ret == 0) {
            ret = WC_HW_E;
        }
    }

    wolfSSL_CryptHwMutexUnLock();

#ifdef SE050_DEBUG
    printf("se050_ecc_shared_secret: ret %d, status %d, outlen %d\n", ret,
            status, *outlen);
#endif

    return ret;
}
#endif /* HAVE_ECC */

#ifdef HAVE_ED25519

int se050_ed25519_create_key(ed25519_key* key)
{
    int             ret = 0;
    sss_status_t    status;
    sss_key_store_t host_keystore;
    sss_object_t    newKey;
    word32          keyId;
    int             keySize = ED25519_KEY_SIZE;
    int             keyCreated = 0;

#ifdef SE050_DEBUG
    printf("se050_ed25519_create_key: %p\n", key);
#endif

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore, SE050_KEYSTOREID_ED25519);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&newKey, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        keyId = se050_allocate_key(SE050_ED25519_KEY);
        status = sss_key_object_allocate_handle(&newKey, keyId,
            kSSS_KeyPart_Pair, kSSS_CipherType_EC_TWISTED_ED, keySize,
            kKeyObject_Mode_Transient);
    }
    if (status == kStatus_SSS_Success) {
        keyCreated = 1;
        status = sss_key_store_generate_key(&host_keystore, &newKey,
            keySize * 8, NULL);
    }

    if (status == kStatus_SSS_Success) {
        key->keyId = keyId;
        key->keyIdSet = 1;
        ret = 0;
    }
    else {
        if (keyCreated) {
            sss_key_store_erase_key(&host_keystore, &newKey);
            sss_key_object_free(&newKey);
        }
        ret = WC_HW_E;
    }

    wolfSSL_CryptHwMutexUnLock();

#ifdef SE050_DEBUG
    printf("se050_ed25519_create_key: ret %d, keyId %ld\n", ret, key->keyId);
#endif

    return ret;
}

void se050_ed25519_free_key(ed25519_key* key)
{
    sss_status_t status;
    sss_object_t newKey;
    sss_key_store_t host_keystore;

#ifdef SE050_DEBUG
    printf("se050_ed25519_free_key: %p, id %ld\n", key, key->keyId);
#endif

    if (cfg_se050_i2c_pi == NULL) {
        return;
    }
    if (key->keyIdSet == 0) {
        return;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return;
    }

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);

    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore, SE050_KEYSTOREID_ED25519);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&newKey, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_get_handle(&newKey, key->keyId);
    }
    if (status == kStatus_SSS_Success) {
        if (key->keyId >= SE050_KEYID_START) {
            sss_key_store_erase_key(&host_keystore, &newKey);
        }
        sss_key_object_free(&newKey);
        key->keyId = 0;
        key->keyIdSet = 0;
    }
    wolfSSL_CryptHwMutexUnLock();
}

int se050_ed25519_sign_msg(const byte* in, word32 inLen, byte* out,
                         word32 *outLen, ed25519_key* key)
{
    int                 ret = 0;
    sss_status_t        status = kStatus_SSS_Success;
    sss_asymmetric_t    ctx_asymm;
    sss_key_store_t     host_keystore;
    sss_object_t        newKey;
    int                 keySize = ED25519_KEY_SIZE;
    int                 keyCreated = 0;
    word32              keyId;

#ifdef SE050_DEBUG
    printf("se050_ed25519_sign_msg: key %p, in %p (%d), out %p (%d), "
            "keyId %ld\n", key, in, inLen, out, *outLen, key->keyId);
#endif

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }

#ifdef WOLFSSL_SE050_ONLY_KEY_ID
    /* Under ONLY_KEY_ID only SE050-resident keys reach this
     * hardware path. Never auto-import a software key (keyIdSet == 0). */
    if (key->keyIdSet == 0) {
        return NOT_COMPILED_IN;
    }
#endif

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore, SE050_KEYSTOREID_ED25519);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&newKey, &host_keystore);
    }
    /* this is run when a key was not generated and was instead passed in */
    if (status == kStatus_SSS_Success) {
        keyId = key->keyId;
        if (key->keyIdSet == 0) {
            byte derBuf[SE050_ECC_DER_MAX];
            word32 derSz;

            ret = wc_Ed25519KeyToDer(key, derBuf, (word32)sizeof(derBuf));
            if (ret >= 0) {
                derSz = ret;
                ret = 0;
            }
            else {
                status = kStatus_SSS_Fail;
            }
            if (status == kStatus_SSS_Success) {
                keyId = se050_allocate_key(SE050_ED25519_KEY);
                status = sss_key_object_allocate_handle(&newKey, keyId,
                    kSSS_KeyPart_Pair, kSSS_CipherType_EC_TWISTED_ED, keySize,
                    kKeyObject_Mode_Transient);
            }
            if (status == kStatus_SSS_Success) {
                keyCreated = 1;
                status = sss_key_store_set_key(&host_keystore, &newKey, derBuf,
                                                derSz, keySize * 8, NULL, 0);
            }
            ForceZero(derBuf, sizeof(derBuf));
        }
        else {
            status = sss_key_object_get_handle(&newKey, keyId);
        }
    }
    if (status == kStatus_SSS_Success) {
        status = sss_asymmetric_context_init(&ctx_asymm, cfg_se050_i2c_pi,
                            &newKey, kAlgorithm_SSS_SHA512, kMode_SSS_Sign);
        if (status == kStatus_SSS_Success) {
            size_t outlenSz = (size_t)*outLen;
            status = sss_se05x_asymmetric_sign(
                    (sss_se05x_asymmetric_t *)&ctx_asymm,
                    (uint8_t *)in, inLen, out, &outlenSz);
            *outLen = (word32)outlenSz;
        }

        sss_asymmetric_context_free(&ctx_asymm);
    }

    if (status != kStatus_SSS_Success) {
        if (keyCreated) {
            sss_key_store_erase_key(&host_keystore, &newKey);
            sss_key_object_free(&newKey);
        }
        ret = WC_HW_E;
    } else {
        key->keyId = keyId;
        key->keyIdSet = 1;
    }

    wolfSSL_CryptHwMutexUnLock();

#ifdef SE050_DEBUG
    printf("se050_ed25519_sign_msg: ret %d, outLen %d\n", ret, *outLen);
#endif

    return ret;
}

int se050_ed25519_verify_msg(const byte* signature, word32 signatureLen,
    const byte* msg, word32 msgLen, struct ed25519_key* key, int* res)
{
    int                 ret = 0;
    sss_status_t        status = kStatus_SSS_Success;
    sss_asymmetric_t    ctx_asymm;
    sss_object_t        newKey;
    sss_key_store_t     host_keystore;
    word32              keyId;
    int                 keySize = ED25519_KEY_SIZE;
    int                 keyCreated = 0;

#ifdef SE050_DEBUG
    printf("se050_ed25519_verify_msg: key %p, sig %p (%d), msg %p (%d)\n",
        key, signature, signatureLen, msg, msgLen);
#endif

    if (signature == NULL || msg == NULL || key == NULL || res == NULL) {
        return BAD_FUNC_ARG;
    }

    *res = 0;

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }

#ifdef WOLFSSL_SE050_ONLY_KEY_ID
    /* Under ONLY_KEY_ID only SE050-resident keys reach this
     * hardware path. Never auto-import a software key (keyIdSet == 0). */
    if (key->keyIdSet == 0) {
        return NOT_COMPILED_IN;
    }
#endif

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore,
                                        SE050_KEYSTOREID_ED25519);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&newKey, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        keyId = key->keyId;
        if (key->keyIdSet == 0) {
            byte derBuf[ED25519_PUB_KEY_SIZE + 12]; /* seq + algo + bitstring */
            word32 derSz = 0;

            ret = wc_Ed25519PublicKeyToDer(key, derBuf,
                                           (word32)sizeof(derBuf), 1);
            if (ret >= 0) {
                derSz = ret;
                ret = 0;
            }
            else {
                status = kStatus_SSS_Fail;
            }
            if (status == kStatus_SSS_Success) {
                keyId = se050_allocate_key(SE050_ED25519_KEY);
                status = sss_key_object_allocate_handle(&newKey, keyId,
                    kSSS_KeyPart_Public, kSSS_CipherType_EC_TWISTED_ED, keySize,
                    kKeyObject_Mode_Transient);
            }
            if (status == kStatus_SSS_Success) {
                keyCreated = 1;
                status = sss_key_store_set_key(&host_keystore, &newKey, derBuf,
                                                derSz, keySize * 8, NULL, 0);
            }
        }
        else {
            status = sss_key_object_get_handle(&newKey, keyId);
        }
    }

    if (status == kStatus_SSS_Success) {
        status = sss_asymmetric_context_init(&ctx_asymm, cfg_se050_i2c_pi,
                    &newKey, kAlgorithm_SSS_SHA512, kMode_SSS_Verify);
        if (status == kStatus_SSS_Success) {
            status = sss_se05x_asymmetric_verify(
                    (sss_se05x_asymmetric_t*)&ctx_asymm, (uint8_t*)msg, msgLen,
                    (uint8_t*)signature, (size_t)signatureLen);
        }
        sss_asymmetric_context_free(&ctx_asymm);
    }

    if (status == kStatus_SSS_Success) {
        if (keyCreated) {
            /* We uploaded only the public part of the key for this verify.
             * Don't persist keyIdSet=1 -- a later sign on the same ed25519_key
             * would reuse this binding and fail because the SE050 object has
             * no private material. Erase the transient object so the next
             * SE050 op re-uploads. Mirrors the fix in se050_rsa_verify. */
            sss_key_store_erase_key(&host_keystore, &newKey);
            sss_key_object_free(&newKey);
        }
        else {
            /* Pre-existing keyIdSet=1 binding (from prior sign that uploaded
             * a keypair, or explicit caller setup). Preserve it. */
            key->keyId = keyId;
            key->keyIdSet = 1;
        }
        *res = 1;
        ret = 0;
    }
    else {
        if (keyCreated) {
            sss_key_store_erase_key(&host_keystore, &newKey);
            sss_key_object_free(&newKey);
        }
        if (ret == 0)
            ret = WC_HW_E;
    }

    wolfSSL_CryptHwMutexUnLock();

#ifdef SE050_DEBUG
    printf("se050_ed25519_verify_msg: ret %d, res %d\n", ret, *res);
#endif

    return ret;
}

#endif /* HAVE_ED25519 */


#ifdef HAVE_CURVE25519

int se050_curve25519_create_key(curve25519_key* key, int keySize)
{
    int             ret;
    sss_status_t    status = kStatus_SSS_Success;
    sss_object_t    keyPair;
    sss_key_store_t host_keystore;
    uint8_t         derBuf[SE050_ECC_DER_MAX];
    size_t          derSz = sizeof(derBuf);
    word32          keyId;
    int             keyCreated = 0;

#ifdef SE050_DEBUG
    printf("se050_curve25519_create_key: key %p, keySize %d\n",
        key, keySize);
#endif

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }
    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore,
            SE050_KEYSTOREID_CURVE25519);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&keyPair, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        keyId = se050_allocate_key(SE050_CURVE25519_KEY);
        status = sss_key_object_allocate_handle(&keyPair, keyId,
            kSSS_KeyPart_Pair, kSSS_CipherType_EC_MONTGOMERY, keySize,
            kKeyObject_Mode_None);
    }
    if (status == kStatus_SSS_Success) {
        keyCreated = 1;
        status = sss_key_store_generate_key(&host_keystore, &keyPair,
            keySize * 8, NULL);
    }
    if (status == kStatus_SSS_Success) {
        size_t derSzBits = derSz * 8;
        status = sss_key_store_get_key(&host_keystore, &keyPair,
            derBuf, &derSz, &derSzBits);
        (void)derSzBits; /* not used */
    }
    if (status == kStatus_SSS_Success) {
        word32 idx = 0;
        byte   pubKey[CURVE25519_KEYSIZE];
        word32 pubKeyLen = (word32)sizeof(pubKey);

        ret = DecodeAsymKeyPublic(derBuf, &idx, (word32)derSz,
            pubKey, &pubKeyLen, X25519k);
        if (ret == 0) {
            ret = wc_curve25519_import_public_ex(pubKey, pubKeyLen, key,
                EC25519_LITTLE_ENDIAN);
        }
        if (ret != 0) {
            status = kStatus_SSS_Fail;
        }
    }

    if (status == kStatus_SSS_Success) {
        key->keyId = keyId;
        key->keyIdSet = 1;
        ret = 0;
    }
    else {
        if (keyCreated) {
            sss_key_store_erase_key(&host_keystore, &keyPair);
            sss_key_object_free(&keyPair);
        }
        ret = WC_HW_E;
    }
    wolfSSL_CryptHwMutexUnLock();

#ifdef SE050_DEBUG
    printf("se050_curve25519_create_key: key %p, ret %d, keyId %ld\n",
        key, ret, key->keyId);
#endif

    return ret;
}

int se050_curve25519_shared_secret(curve25519_key* private_key,
    curve25519_key* public_key, ECPoint* out)
{
    int               ret = 0;
    sss_status_t      status = kStatus_SSS_Success;
    sss_key_store_t   host_keystore;
    sss_object_t      ref_private_key;
    sss_object_t      ref_public_key;
#if !(defined(SSS_HAVE_SE05X_VER_GTE_07_02) && SSS_HAVE_SE05X_VER_GTE_07_02)
    int               keySize = CURVE25519_KEYSIZE;
    sss_object_t      deriveKey;
    sss_derive_key_t  ctx_derive_key;
    word32            keyId;
    int               keyCreated = 0;
    int               deriveKeyCreated = 0;
#endif

#ifdef SE050_DEBUG
    printf("se050_curve25519_shared_secret: priv %p, pub %p, out %p (%d)\n",
        private_key, public_key, out, out->pointSz);
#endif

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }

    if (private_key == NULL || public_key == NULL ||
        private_key->keyIdSet == 0) {
        return BAD_FUNC_ARG;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore,
            SE050_KEYSTOREID_CURVE25519);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&ref_private_key, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_get_handle(&ref_private_key,
                                           private_key->keyId);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&ref_public_key, &host_keystore);
    }
#if !(defined(SSS_HAVE_SE05X_VER_GTE_07_02) && SSS_HAVE_SE05X_VER_GTE_07_02)
    if (status == kStatus_SSS_Success) {
        keyId = public_key->keyId;
        if (public_key->keyIdSet == 0) {
            byte   derBuf[CURVE25519_PUB_KEY_SIZE + 12]; /* seq + algo + bitstring */
            word32 derSz;
            byte   pubKey[CURVE25519_PUB_KEY_SIZE];
            word32 pubKeyLen = (word32)sizeof(pubKey);

            ret = wc_curve25519_export_public_ex(public_key, pubKey, &pubKeyLen,
                EC25519_LITTLE_ENDIAN);
            if (ret == 0) {
                ret = SetAsymKeyDerPublic(pubKey, pubKeyLen, derBuf,
                    (word32)sizeof(derBuf), X25519k, 1);
                if (ret >= 0) {
                    derSz = ret;
                    ret = 0;
                }
            }
            if (ret != 0) {
                status = kStatus_SSS_Fail;
            }
            if (status == kStatus_SSS_Success) {
                keyId = se050_allocate_key(SE050_CURVE25519_KEY);
                status = sss_key_object_allocate_handle(&ref_public_key,
                    keyId, kSSS_KeyPart_Public, kSSS_CipherType_EC_MONTGOMERY,
                    keySize, kKeyObject_Mode_Transient);
            }
            if (status == kStatus_SSS_Success) {
                keyCreated = 1;
                status = sss_key_store_set_key(&host_keystore, &ref_public_key,
                    derBuf, derSz, keySize * 8, NULL, 0);
            }
        }
        else {
            status = sss_key_object_get_handle(&ref_public_key, keyId);
        }
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&deriveKey, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        word32 keyIdAes = se050_allocate_key(SE050_AES_KEY);
        status = sss_key_object_allocate_handle(&deriveKey,
            keyIdAes,
            kSSS_KeyPart_Default,
            /* The applet denies ReadObject on a symmetric key object no
             * matter what policy is attached, so the derive target must
             * be a Binary object, which ReadObject allows by default */
            kSSS_CipherType_Binary,
            keySize,
            kKeyObject_Mode_Transient);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_derive_key_context_init(&ctx_derive_key, cfg_se050_i2c_pi,
                                    &ref_private_key, kAlgorithm_SSS_ECDH,
                                    kMode_SSS_ComputeSharedSecret);
        if (status == kStatus_SSS_Success) {
            /* Try to delete existing key first, ignore return since will
             * fail if no key exists yet */
            sss_key_store_erase_key(&host_keystore, &deriveKey);
            status = sss_derive_key_dh(&ctx_derive_key, &ref_public_key,
                &deriveKey);
        }
        if (status == kStatus_SSS_Success) {
            size_t outlenSz = sizeof(out->point);
            size_t outlenSzBits = outlenSz * 8;
            deriveKeyCreated = 1;
            /* derived key export */
            status = sss_key_store_get_key(&host_keystore, &deriveKey,
                out->point, &outlenSz, &outlenSzBits);
            out->pointSz = (word32)outlenSz;
            (void)outlenSzBits; /* not used */
        }

        sss_derive_key_context_free(&ctx_derive_key);
    }
    if (deriveKeyCreated) {
        sss_key_store_erase_key(&host_keystore, &deriveKey);
        sss_key_object_free(&deriveKey);
    }
#else
    /* The direct APDU carries the peer public point in the command, so
     * the peer key is never uploaded to the SE050 on this path; a
     * reference object is only needed when the peer public key is
     * already SE050-resident. */
    if (status == kStatus_SSS_Success && public_key->keyIdSet != 0) {
        status = sss_key_object_get_handle(&ref_public_key,
            public_key->keyId);
    }
    if (status == kStatus_SSS_Success) {
        /* Middleware built for applet >= 7.2 derives into an SE05x
         * resident object, but the applet refuses to export a symmetric
         * key object regardless of the policy attached at its creation
         * (verified on SE051 applet 7.2.0 hardware), so a derived secret
         * stored in an object can never be read back. Use the direct
         * APDU that returns the shared secret in the response instead,
         * as the middleware itself does whenever the derived key lives
         * in a host keystore. The applet speaks big endian for
         * Montgomery keys, so the peer point and the returned secret are
         * both byte swapped, matching sss_se05x_derive_key_dh. */
        byte peerPoint[CURVE25519_KEYSIZE];
        word32 peerPointSz = (word32)sizeof(peerPoint);
        smStatus_t sm;
        int i;
        byte swp;

        if (public_key->keyIdSet == 0) {
            ret = wc_curve25519_export_public_ex(public_key, peerPoint,
                &peerPointSz, EC25519_LITTLE_ENDIAN);
            if (ret != 0) {
                status = kStatus_SSS_Fail;
            }
        }
        else {
            /* Peer public key is SE050-resident: read the DER encoding
             * back; the raw little endian point is the trailing bytes */
            byte derBuf[CURVE25519_PUB_KEY_SIZE + 12];
            size_t derSz = sizeof(derBuf);
            size_t derSzBits = derSz * 8;
            status = sss_key_store_get_key(&host_keystore, &ref_public_key,
                derBuf, &derSz, &derSzBits);
            if (status == kStatus_SSS_Success &&
                    derSz >= CURVE25519_KEYSIZE) {
                XMEMCPY(peerPoint, derBuf + derSz - CURVE25519_KEYSIZE,
                    CURVE25519_KEYSIZE);
                peerPointSz = CURVE25519_KEYSIZE;
            }
            else {
                status = kStatus_SSS_Fail;
            }
        }
        if (status == kStatus_SSS_Success) {
            size_t outSz = sizeof(out->point);
            for (i = 0; i < CURVE25519_KEYSIZE / 2; i++) {
                swp = peerPoint[i];
                peerPoint[i] = peerPoint[CURVE25519_KEYSIZE - 1 - i];
                peerPoint[CURVE25519_KEYSIZE - 1 - i] = swp;
            }
            sm = Se05x_API_ECDHGenerateSharedSecret(
                &((sss_se05x_session_t*)cfg_se050_i2c_pi)->s_ctx,
                private_key->keyId, peerPoint, peerPointSz,
                out->point, &outSz);
            if (sm == SM_OK && outSz == CURVE25519_KEYSIZE) {
                for (i = 0; i < CURVE25519_KEYSIZE / 2; i++) {
                    swp = out->point[i];
                    out->point[i] = out->point[CURVE25519_KEYSIZE - 1 - i];
                    out->point[CURVE25519_KEYSIZE - 1 - i] = swp;
                }
                out->pointSz = (word32)outSz;
            }
            else {
                status = kStatus_SSS_Fail;
            }
        }
    }
#endif

    if (status == kStatus_SSS_Success) {
#if !(defined(SSS_HAVE_SE05X_VER_GTE_07_02) && SSS_HAVE_SE05X_VER_GTE_07_02)
#ifdef WOLFSSL_SE050_ONLY_KEY_ID
        if (keyCreated) {
            /* The peer's public key was uploaded for this derivation only.*/
            sss_key_store_erase_key(&host_keystore, &ref_public_key);
            sss_key_object_free(&ref_public_key);
        }
        else
#endif
        {
            public_key->keyId = keyId;
            public_key->keyIdSet = 1;
        }
#endif /* !SSS_HAVE_SE05X_VER_GTE_07_02 */
        ret = 0;
    }
    else {
#if !(defined(SSS_HAVE_SE05X_VER_GTE_07_02) && SSS_HAVE_SE05X_VER_GTE_07_02)
        if (keyCreated) {
            sss_key_store_erase_key(&host_keystore, &ref_public_key);
            sss_key_object_free(&ref_public_key);
        }
#endif
        if (ret == 0)
            ret = WC_HW_E;
    }

    wolfSSL_CryptHwMutexUnLock();

#ifdef SE050_DEBUG
    printf("se050_curve25519_shared_secret: ret %d, outlen %d\n",
        ret, out->pointSz);
#endif

    return ret;
}

void se050_curve25519_free_key(struct curve25519_key* key)
{
    sss_status_t status;
    sss_object_t newKey;
    sss_key_store_t host_keystore;

#ifdef SE050_DEBUG
    printf("se050_curve25519_free_key: %p, id %ld\n", key, key->keyId);
#endif

    if (cfg_se050_i2c_pi == NULL || key->keyIdSet == 0) {
        return;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return;
    }

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);

    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore,
            SE050_KEYSTOREID_CURVE25519);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&newKey, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_get_handle(&newKey, key->keyId);
    }
    if (status == kStatus_SSS_Success) {
        if (key->keyId >= SE050_KEYID_START) {
            sss_key_store_erase_key(&host_keystore, &newKey);
        }
        sss_key_object_free(&newKey);
        key->keyId = 0;
        key->keyIdSet = 0;
    }
    wolfSSL_CryptHwMutexUnLock();
}
#endif /* HAVE_CURVE25519 */

#endif /* WOLFSSL_SE050 */
