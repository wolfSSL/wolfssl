/* silabs_cryptocb.h
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

#ifndef _SILABS_CRYPTOCB_H_
#define _SILABS_CRYPTOCB_H_

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_SILABS_CRYPTOCB

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#ifndef NO_AES
    #include <wolfssl/wolfcrypt/aes.h>
#endif
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif

/* Pulled in for _SILICON_LABS_SECURITY_FEATURE, which gates the wrapped-key
 * API below. The sibling silabs headers include it the same way. */
#ifdef WOLFSSL_SILABS_HOST_TEST
    #include <wolfssl/wolfcrypt/port/silabs/silabs_shim.h>
#else
    #include <em_device.h>
#endif

/* Declare the wrapped-key API on exactly the parts that compile it: Secure
 * Vault High. Deriving the declaration from the same hardware capability as
 * the definition means a Vault Mid build fails at the call site with an
 * undeclared function, instead of compiling against a prototype and then
 * failing at link time with no explanation. WOLFSSL_SILABS_NO_VAULT_KEYS
 * remains available to suppress the API on a Vault High part. */
#if defined(_SILICON_LABS_SECURITY_FEATURE) && \
    (_SILICON_LABS_SECURITY_FEATURE == _SILICON_LABS_SECURITY_FEATURE_VAULT) \
    && !defined(WOLFSSL_SILABS_NO_VAULT_KEYS)
    #define WOLFSSL_SILABS_WRAPPED_KEYS_API
#endif

#ifdef __cplusplus
    extern "C" {
#endif

/* Register / unregister the Silicon Labs Secure Element device. wolfCrypt_Init
 * registers it automatically at WOLFSSL_SILABS_DEVID; call these only to use a
 * different device id or to tear the device down early. Both return 0 on
 * success and a negative wolfCrypt error otherwise. */
WOLFSSL_API int wc_SilabsCryptoCb_RegisterDevice(int devId);
WOLFSSL_API int wc_SilabsCryptoCb_UnRegisterDevice(int devId);

/* ---- Secure Vault key management ----------------------------------------
 *
 * A wrapped key is encrypted to a device-unique key: the SE can use it, the
 * application never sees the key material. A built-in key lives in an SE slot
 * and is named rather than supplied. Both bind to an ordinary Aes or ecc_key,
 * after which the normal wolfCrypt calls run on the SE against that key.
 *
 * The descriptor references the caller's wrapped buffer without copying it, so
 * that buffer must outlive the Aes / ecc_key bound to it.
 *
 * Wrapped keys need Secure Vault High; the built-in slots do not. All return 0
 * on success and a negative wolfCrypt error otherwise. */

/* Bound only to be used by the cipher engine; without it a bind would erase
 * the software key and then dispatch would decline, leaving nothing usable. */
#if !defined(NO_AES) && defined(WOLFSSL_SILABS_WRAPPED_KEYS_API) && \
    defined(WOLFSSL_SILABS_CRYPTOCB_CIPHER)
/* Size of the wrapped blob for an AES key of keyBits bits. */
WOLFSSL_API int wc_SilabsSe_AesGetWrappedKeySize(int keyBits, word32* outSz);
/* Generate an AES key inside the SE, returning only its wrapped form. */
WOLFSSL_API int wc_SilabsSe_AesGenerateWrappedKey(int keyBits, byte* out,
    word32* outSz);
/* Bind a wrapped AES key to an Aes. */
WOLFSSL_API int wc_SilabsSe_AesUseWrappedKey(Aes* aes, const byte* wrapped,
    word32 wrappedSz, int keyBits);
#endif
#if !defined(NO_AES) && defined(WOLFSSL_SILABS_CRYPTOCB_CIPHER)
/* Bind an SE built-in AES slot (for example
 * SL_SE_KEY_SLOT_APPLICATION_AES_128_KEY) to an Aes. */
WOLFSSL_API int wc_SilabsSe_AesUseBuiltInKey(Aes* aes, int slot, int keyBits);
#endif

/* As above: these are only usable when the ECC engine is compiled in. */
#if defined(HAVE_ECC) && defined(WOLFSSL_SILABS_CRYPTOCB_ECC)
#if defined(WOLFSSL_SILABS_WRAPPED_KEYS_API)
WOLFSSL_API int wc_SilabsSe_EccGetWrappedKeySize(int curveId, word32* outSz);
/* Generate an ECC key inside the SE. wrapped receives the private key in
 * wrapped form; pubOut, when not NULL, receives the public point as X||Y. */
WOLFSSL_API int wc_SilabsSe_EccGenerateWrappedKey(int curveId, byte* wrapped,
    word32* wrappedSz, byte* pubOut, word32* pubOutSz);
WOLFSSL_API int wc_SilabsSe_EccUseWrappedKey(ecc_key* key, const byte* wrapped,
    word32 wrappedSz, int curveId);
#endif
/* Bind an SE built-in ECC slot (for example
 * SL_SE_KEY_SLOT_APPLICATION_ATTESTATION_KEY) to an ecc_key. */
WOLFSSL_API int wc_SilabsSe_EccUseBuiltInKey(ecc_key* key, int slot,
    int curveId);
#endif /* HAVE_ECC && WOLFSSL_SILABS_CRYPTOCB_ECC */

/* Engine entry points. Each runs the whole operation and returns 0 when the SE
 * handled it, CRYPTOCB_UNAVAILABLE to fall back to software, or a negative
 * wolfCrypt error. */
#ifdef WOLFSSL_SILABS_CRYPTOCB_TRNG
WOLFSSL_LOCAL int wc_SilabsRng(wc_CryptoInfo* info);
#endif
#ifdef WOLFSSL_SILABS_CRYPTOCB_HASH
WOLFSSL_LOCAL int wc_SilabsHash(wc_CryptoInfo* info);
#endif
#ifdef WOLFSSL_SILABS_CRYPTOCB_CIPHER
WOLFSSL_LOCAL int wc_SilabsCipher(wc_CryptoInfo* info);
#endif
#if defined(WOLFSSL_SILABS_CRYPTOCB_CMAC) && defined(WOLFSSL_CMAC) && \
    !defined(NO_AES)
WOLFSSL_LOCAL int wc_SilabsCmac(wc_CryptoInfo* info);
#endif
#if defined(WOLFSSL_SILABS_CRYPTOCB_ECC) && defined(HAVE_ECC)
WOLFSSL_LOCAL int wc_SilabsPk(wc_CryptoInfo* info);
#endif
#ifdef WOLFSSL_SILABS_CRYPTOCB_KDF
WOLFSSL_LOCAL int wc_SilabsKdf(wc_CryptoInfo* info);
#endif

/* Map an SE status to a wolfCrypt error. */
WOLFSSL_LOCAL int silabs_cb_status(int slStatus);

/* Map a wolfCrypt hash type to an SE hash type, or SL_SE_HASH_NONE when the
 * SE cannot do it. */
WOLFSSL_LOCAL int silabs_cb_hash_type(int wcHashType, int* digestSz);

#ifdef __cplusplus
    }
#endif

#endif /* WOLFSSL_SILABS_CRYPTOCB */

#endif /* _SILABS_CRYPTOCB_H_ */
