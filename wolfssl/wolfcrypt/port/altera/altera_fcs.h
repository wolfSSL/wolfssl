/* altera_fcs.h
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

#ifndef WOLF_CRYPT_PORT_ALTERA_FCS_H
#define WOLF_CRYPT_PORT_ALTERA_FCS_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_ALTERA_FCS

#include <wolfssl/wolfcrypt/cryptocb.h>

/* These backends deliberately decline operations the SDM cannot service. The
 * corresponding software implementations must therefore remain available. */
#if defined(WOLFSSL_ALTERA_FCS_HASH) && \
    defined(WOLF_CRYPTO_CB_ONLY_SHA256)
    #error "Altera FCS hash requires software SHA-256 fallback"
#endif
#if defined(WOLFSSL_ALTERA_FCS_AES) && defined(WOLF_CRYPTO_CB_ONLY_AES)
    #error "Altera FCS AES requires software AES fallback"
#endif
#if defined(WOLFSSL_ALTERA_FCS_ECC) && defined(WOLF_CRYPTO_CB_ONLY_ECC)
    #error "Altera FCS ECC requires software ECC fallback"
#endif
#if defined(WOLFSSL_ALTERA_FCS_ECC) && \
    defined(NO_ECC_CHECK_PUBKEY_ORDER)
    #error "Altera FCS ECC requires public key order validation"
#endif

/* ECC is an optional part of the combined FCS build. Raw point and signature
 * conversion require both key import and export. */
#if defined(WOLFSSL_ALTERA_FCS_ECC) && \
    defined(HAVE_ECC_KEY_IMPORT) && defined(HAVE_ECC_KEY_EXPORT) && \
    !defined(NO_ASN)
    #define WC_ALTERA_FCS_HAVE_ECC
#endif

#ifdef __cplusplus
    extern "C" {
#endif

/* Default devId for the SDM. Callers opt in explicitly: registering on
 * INVALID_DEVID would route every hash in the process through one chip-wide
 * hardware session. */
#ifndef WOLFSSL_ALTERA_FCS_DEVID
    #define WOLFSSL_ALTERA_FCS_DEVID 0x4143
#endif

/* Largest single SDM transaction (FCS_CRYPTO_BLOCK_SZ in the kernel driver). */
#define WC_ALTERA_FCS_MAX_XFER (4 * 1024 * 1024)

/* Requests below these configurable thresholds remain in software. */
#ifndef WOLFSSL_ALTERA_FCS_HASH_MIN
    #define WOLFSSL_ALTERA_FCS_HASH_MIN 4096
#endif
#ifndef WOLFSSL_ALTERA_FCS_AES_MIN
    #define WOLFSSL_ALTERA_FCS_AES_MIN 4096
#endif

/* Context id tagging every request this port makes. */
#ifndef WOLFSSL_ALTERA_FCS_CTX_ID
    #define WOLFSSL_ALTERA_FCS_CTX_ID 0x574F4C46
#endif

/* First key id handed out. Must be non-zero, the device rejects id 0. */
#ifndef WOLFSSL_ALTERA_FCS_KEY_ID_BASE
    #define WOLFSSL_ALTERA_FCS_KEY_ID_BASE 0x57420001
#endif

WOLFSSL_LOCAL int  wc_AlteraFcs_Init(void);
WOLFSSL_LOCAL int  wc_AlteraFcs_Cleanup(void);
WOLFSSL_LOCAL int  wc_AlteraFcs_SessionAcquire(void** sessionId);
WOLFSSL_LOCAL void wc_AlteraFcs_SessionRelease(void);
WOLFSSL_LOCAL int  wc_AlteraFcs_MapError(int fcsRet);
WOLFSSL_LOCAL int  wc_AlteraFcs_KeyIdNew(word32* keyId);
WOLFSSL_LOCAL int  wc_AlteraFcs_RemoveServiceKey(word32 keyId);
WOLFSSL_LOCAL int  wc_AlteraFcs_OrphanKey(word32 keyId);
WOLFSSL_LOCAL void wc_AlteraFcs_DiscardServiceKey(word32 keyId);
WOLFSSL_LOCAL int  wc_AlteraFcs_ResourceAcquire(void);
WOLFSSL_LOCAL void wc_AlteraFcs_ResourceAdd(void);
WOLFSSL_LOCAL void wc_AlteraFcs_ResourceRemove(void);
WOLFSSL_LOCAL void wc_AlteraFcsCryptoCb_UnRegisterPending(void);
WOLFSSL_LOCAL int  wc_AlteraFcsCryptoCb_UnRegisterDeviceEx(int devId);
WOLFSSL_LOCAL int  wc_AlteraFcs_UnregisterPending(void);
WOLFSSL_LOCAL int  wc_AlteraFcs_RegisterActive(void);
WOLFSSL_LOCAL void wc_AlteraFcs_StateAtForkPrepare(void);
WOLFSSL_LOCAL void wc_AlteraFcs_StateAtForkParent(void);
WOLFSSL_LOCAL void wc_AlteraFcs_StateAtForkChild(void);
WOLFSSL_LOCAL void wc_AlteraFcs_StateForkChildReset(void);
WOLFSSL_API int  wc_AlteraFcs_AlgoEnabled(word32 algoMask);
/* Non-zero when the process can open the shared SDM service session. */
WOLFSSL_API int  wc_AlteraFcs_HardwareAvailable(void);
WOLFSSL_API void wc_AlteraFcs_TestHwReset(void);
WOLFSSL_API word32 wc_AlteraFcs_TestHwGet(void);

#define WC_ALTERA_FCS_TEST_HW_RNG          0x01
#define WC_ALTERA_FCS_TEST_HW_HASH         0x02
#define WC_ALTERA_FCS_TEST_HW_AES          0x04
#define WC_ALTERA_FCS_TEST_HW_AES_RESIDENT 0x08
WOLFSSL_LOCAL void wc_AlteraFcs_TestHwMark(word32 operation);

/* Which algorithm classes the callback accepts. Signing and key exchange are
 * the operations that gain key isolation; hashing and AES with a plaintext key
 * do not, and both are slower on the device than in software, so a deployment
 * can register a subset. */
#define WC_ALTERA_FCS_ALGO_RNG  0x01
#define WC_ALTERA_FCS_ALGO_HASH 0x02
#define WC_ALTERA_FCS_ALGO_AES  0x04
#define WC_ALTERA_FCS_ALGO_ECC  0x08
#ifdef WOLFSSL_ALTERA_FCS_RNG
    #define WC_ALTERA_FCS_HAVE_RNG_MASK WC_ALTERA_FCS_ALGO_RNG
#else
    #define WC_ALTERA_FCS_HAVE_RNG_MASK 0
#endif
#ifdef WOLFSSL_ALTERA_FCS_HASH
    #define WC_ALTERA_FCS_HAVE_HASH_MASK WC_ALTERA_FCS_ALGO_HASH
#else
    #define WC_ALTERA_FCS_HAVE_HASH_MASK 0
#endif
#ifdef WOLFSSL_ALTERA_FCS_AES
    #define WC_ALTERA_FCS_HAVE_AES_MASK WC_ALTERA_FCS_ALGO_AES
#else
    #define WC_ALTERA_FCS_HAVE_AES_MASK 0
#endif
#ifdef WC_ALTERA_FCS_HAVE_ECC
    #define WC_ALTERA_FCS_HAVE_ECC_MASK WC_ALTERA_FCS_ALGO_ECC
#else
    #define WC_ALTERA_FCS_HAVE_ECC_MASK 0
#endif
#define WC_ALTERA_FCS_ALGO_ALL (WC_ALTERA_FCS_HAVE_RNG_MASK | \
                                WC_ALTERA_FCS_HAVE_HASH_MASK | \
                                WC_ALTERA_FCS_HAVE_AES_MASK | \
                                WC_ALTERA_FCS_HAVE_ECC_MASK)

/* Mask used by the automatic registration in wolfCrypt_Init(). Deployments
 * that only want the operations gaining key isolation can build with
 * WOLFSSL_ALTERA_FCS_AUTO_MASK set to, say, ECC | RNG so TLS keeps its
 * transcript hashing and record ciphers on the faster software paths. */
#ifndef WOLFSSL_ALTERA_FCS_AUTO_MASK
    #define WOLFSSL_ALTERA_FCS_AUTO_MASK WC_ALTERA_FCS_ALGO_ALL
#endif

/* The SDM uses WOLFSSL_ALTERA_FCS_DEVID exclusively. The mask is fixed once
 * registered because live contexts may hold state owned by the port. */
WOLFSSL_API int  wc_AlteraFcsCryptoCb_RegisterDevice(int devId);
WOLFSSL_API int  wc_AlteraFcsCryptoCb_RegisterDeviceMask(int devId,
                                                         word32 algoMask);
WOLFSSL_API void wc_AlteraFcsCryptoCb_UnRegisterDevice(int devId);

#ifdef WOLFSSL_ALTERA_FCS_RNG
WOLFSSL_LOCAL int wc_AlteraFcs_Rng(wc_CryptoInfo* info);
#endif

#ifdef WOLFSSL_ALTERA_FCS_HASH
WOLFSSL_LOCAL int wc_AlteraFcs_Hash(wc_CryptoInfo* info);
#endif

#ifdef WOLFSSL_ALTERA_FCS_AES
WOLFSSL_LOCAL int wc_AlteraFcs_Aes(wc_CryptoInfo* info);
/* Device resident AES. The key is generated inside the SDM and never appears in
 * HPS memory, unlike wc_AesSetKey which stores a plaintext key the port can only
 * import. Created explicitly because an SDM key object commits to its usage at
 * creation. CBC and CTR are then offloaded by handle with no software fallback,
 * so callers that depend on key isolation should assert IsDeviceKey. */
WOLFSSL_API int wc_AlteraFcsAes_MakeKey(Aes* aes, int keyBits);
WOLFSSL_API int wc_AlteraFcsAes_IsDeviceKey(const Aes* aes);
#endif

#ifdef WC_ALTERA_FCS_HAVE_ECC
WOLFSSL_LOCAL int wc_AlteraFcs_Ecc(wc_CryptoInfo* info);
/* Non-zero when the private key lives inside the SDM rather than in HPS
 * memory. Callers that depend on key isolation should assert this. */
WOLFSSL_API  int wc_AlteraFcsEcc_IsDeviceKey(const ecc_key* key);
/* Device resident keys are created explicitly rather than through
 * wc_ecc_make_key_ex, because an SDM key object must commit to Sign/Verify or
 * Exchange usage at creation and the two are mutually exclusive. Sign and ECDH
 * are then offloaded automatically for keys made this way. */
#if defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY)
WOLFSSL_API  int wc_AlteraFcsEcc_MakeSigningKey(ecc_key* key, int curveId);
#endif
#ifdef HAVE_ECC_DHE
WOLFSSL_API  int wc_AlteraFcsEcc_MakeExchangeKey(ecc_key* key, int curveId);
#endif
#endif

#ifdef WOLFSSL_ALTERA_FCS_HMAC
/* MAC verification under a key the HPS cannot read. Not a crypto callback: the
 * device only verifies, returning a verdict rather than a tag, while wolfSSL's
 * HMAC API generates one, so there is no matching entry point to hook. The SDM
 * supports matched key/digest sizes: 256/SHA-256, 384/SHA-384, and
 * 512/SHA-512. */
WOLFSSL_API int wc_AlteraFcs_HmacMakeKey(int keyBits, word32* keyId);
WOLFSSL_API int wc_AlteraFcs_HmacImportKey(const byte* key, int keyBits,
                                           word32* keyId);
WOLFSSL_API int wc_AlteraFcs_HmacRemoveKey(word32 keyId);
WOLFSSL_API int wc_AlteraFcs_HmacVerify(word32 keyId, int hashType,
                                        const byte* data, word32 dataSz,
                                        const byte* mac, word32 macSz,
                                        int* isValid);
#endif

#ifdef __cplusplus
    }
#endif

#endif /* WOLFSSL_ALTERA_FCS */
#endif /* WOLF_CRYPT_PORT_ALTERA_FCS_H */
