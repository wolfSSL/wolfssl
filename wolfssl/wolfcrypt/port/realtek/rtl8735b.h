/* rtl8735b.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* RealTek AmebaPro2 (RTL8735B) HUK (Hardware Unique Key) crypto-callback port.
 *
 * Binds keys to the silicon HUK via the AmebaPro2 HAL crypto engine: a 256-bit
 * "seed" is run through the HAL HKDF key-ladder against the HUK to land a
 * device-bound working key in a secure key-storage slot; AES (GCM/ECB/CBC/CTR)
 * then runs from that slot without the key ever entering software. ECDSA sign
 * binds a HUK-wrapped private scalar. The port is a pure crypto-callback device:
 * it adds no wolfSSL core API or struct fields -- AES reads its seed from the
 * standard aes->devKey, and ECDSA reads a wc_Rtl8735b_EccKey (below) the caller
 * attaches via the standard ecc_key->devCtx. Only a 32-byte seed is HUK-bound:
 * a 16/24-byte AES key falls back to ordinary software AES (the bytes become the
 * literal key, no device binding, no error), so AES-128/192 are not HUK-bound.
 *
 * The HW ECDSA P-256 engine (hal_ecdsa) is also used as a general sign/verify
 * offload, independent of the HUK: an ecc_key with devId = WC_HUK_DEVID and no
 * devCtx routes wc_ecc_sign_hash through the engine using the key's own scalar,
 * and wc_ecc_verify_hash through the engine using the key's own public point
 * (no HUK context needed for verify). This lets a standard wolfCrypt benchmark
 * exercise the HW engine just by setting WC_USE_DEVID = WC_HUK_DEVID.
 */

#ifndef _WOLFPORT_RTL8735B_H_
#define _WOLFPORT_RTL8735B_H_

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_RTL8735B_HUK

/* Transparent HUK crypto flows through the crypto-callback framework. */
#if !defined(WOLF_CRYPTO_CB)
    #error "WOLFSSL_RTL8735B_HUK requires WOLF_CRYPTO_CB (crypto callback dispatch)"
#endif

/* Crypto-callback device id for transparent HUK crypto. Must not collide with
 * the STM32 DHUK device ids (807 SAES, 808 DHUK, 809 DHUK-wrapped) if both ports
 * are enabled in one build. Override before include if it collides. */
#ifndef WC_HUK_DEVID
    #define WC_HUK_DEVID                    810
#endif

/* Secure key-storage slot indices for the key ladder (KEY_STG_* values from
 * rtl8735b_crypto_ctrl.h, NOT the hkdf_key_storage_e enum in rtl8735b_hkdf.h):
 * the HUK source is HUK1 (0xC); slots 0..7 are general. The PRK and the derived
 * working key each take a general slot -- the working-key slot is the one
 * AES/HMAC *_sk_init reference. All overridable from user_settings. */
#ifndef WC_RTL8735B_HUK_SK_IDX
    #define WC_RTL8735B_HUK_SK_IDX        0xC /* KEY_STG_HUK1 */
#endif
#ifndef WC_RTL8735B_HKDF_PRK_IDX
    #define WC_RTL8735B_HKDF_PRK_IDX      3   /* KEY_STG_IDX3 */
#endif
#ifndef WC_RTL8735B_DERIVED_WB_IDX
    #define WC_RTL8735B_DERIVED_WB_IDX    4   /* KEY_STG_IDX4 */
#endif

/* crypto_sel for hal_hkdf_hmac_sha256_secure_init: HKDF_CRYPTO_HW_SEL_EN. */
#ifndef WC_RTL8735B_HKDF_CRYPTO_SEL
    #define WC_RTL8735B_HKDF_CRYPTO_SEL   0
#endif

/* Secure-key HMAC-SHA256 config selectors (rtl8735b crypto key-storage roles,
 * passed to hal_crypto_hmac_sha2_256_get_sk_cfg): source the HMAC key from the
 * secure slot (KEY_STG_SKTYPE_LD_SK) and emit the digest to the output buffer
 * with no slot write-back (KEY_STG_WBTYPE_WB_ONLY_BUF). The key slot used is
 * WC_RTL8735B_DERIVED_WB_IDX (the HUK-derived working key). All overridable. */
#ifndef WC_RTL8735B_HMAC_SK_OP
    #define WC_RTL8735B_HMAC_SK_OP        1   /* KEY_STG_SKTYPE_LD_SK */
#endif
#ifndef WC_RTL8735B_HMAC_WB_OP
    #define WC_RTL8735B_HMAC_WB_OP        0   /* KEY_STG_WBTYPE_WB_ONLY_BUF */
#endif
#ifndef WC_RTL8735B_HMAC_WB_IDX
    #define WC_RTL8735B_HMAC_WB_IDX       0   /* unused when WB_ONLY_BUF */
#endif

/* HUK HMAC-SHA256 is one-shot: wc_HmacUpdate chunks are buffered on the heap and
 * the MAC runs at wc_HmacFinal, so heap use grows with the total message. It is
 * intended for bounded/short HUK MAC / KDF inputs. WC_RTL8735B_HMAC_MAX_MSG caps
 * the buffered length: past it, accumulation returns BUFFER_E. The default 64 KB
 * bounds runaway growth while clearing typical benchmark/KDF use; set to 0 for
 * unbounded, or raise it if you MAC larger messages under the HUK.
 * IMPORTANT: the HMAC key buffer (the HUK seed, passed to wc_HmacSetKey) is
 * borrowed via hmac->keyRaw and re-read at wc_HmacFinal / wc_HmacFree, so it must
 * stay valid and unmodified through all Update/Final/Free calls on the Hmac. */
#ifndef WC_RTL8735B_HMAC_MAX_MSG
    #define WC_RTL8735B_HMAC_MAX_MSG      65536
#endif

/* Max wrapped-scalar blob the HUK ECDSA sign path will unwrap (a multiple of 16
 * covering up to P-521: 66 padded to 80, plus headroom). */
#ifndef WC_RTL8735B_MAX_WRAPPED
    #define WC_RTL8735B_MAX_WRAPPED       96
#endif

/* Bounded spin waiting for the HW ECDSA finish IRQ -- only a safety bound so a
 * wedged engine returns WC_HW_E instead of hanging. An ITERATION count, not a
 * wall-clock timeout (so it scales with CPU clock / optimization, intentionally
 * generous). Default sized for the RTL8735B "KM4" Cortex-M33 at 500 MHz (a P-256
 * sign/verify finishes in a few ms). Tune for a different part/toolchain. */
#ifndef WC_RTL8735B_ECDSA_SPIN
    #define WC_RTL8735B_ECDSA_SPIN        2000000L
#endif

/* Hook called once per ECDSA wait-loop iteration. The wait runs while the global
 * crypto mutex is held, so on an RTOS a busy spin blocks other crypto threads;
 * define this to a cooperative yield (e.g. taskYIELD() on FreeRTOS, k_yield() on
 * Zephyr) so the core is released while the engine finishes. Default: no-op. */
#ifndef WC_RTL8735B_ECDSA_YIELD
    #define WC_RTL8735B_ECDSA_YIELD()     do {} while (0)
#endif

/* HUK-bound ECC private key context for the ECDSA sign path. Instead of a new
 * wolfSSL core API, the caller attaches one of these to a WC_HUK_DEVID ecc_key
 * via the standard crypto-callback context pointer (key->devCtx) before signing:
 *
 *     wc_Rtl8735b_EccKey hk = { seed, 32, wrapped, plainLen, plainLen,
 *                               0, 0, iv, 12, tag, 16 };
 *     wc_ecc_init_ex(&key, NULL, WC_HUK_DEVID);
 *     wc_ecc_set_curve(&key, plainLen, curveId);
 *     key.devCtx = &hk;
 *     wc_ecc_sign_hash(...);   (unwraps + signs under the HUK)
 *
 * The pointed-at buffers must stay valid for the key's lifetime (borrowed, not
 * copied). seed is the 256-bit HKDF input. The private scalar is AUTHENTICATED-
 * wrapped with AES-GCM under the HUK-derived key: wrapped is the ciphertext
 * (wrappedLen == plainLen, no block padding, <= WC_RTL8735B_MAX_WRAPPED), iv the
 * 12-byte nonce, tag the 16-byte auth tag; plainLen is the scalar size (32 for
 * P-256). GCM means a tampered, corrupted, or wrong-device blob fails at unwrap
 * (AES_GCM_AUTH_E) instead of silently yielding a garbage scalar. Requires
 * HAVE_AESGCM.
 *
 * By default the sign runs in software after the HUK GCM-unwrap. Set useHwEngine
 * to route the sign through the HW ECDSA engine (hal_ecdsa, P-256 only). With
 * otpPrkSel != 0 the private scalar is sourced from OTP via hal_ecdsa_select_prk
 * and never enters software -- seed/wrapped/iv/tag/plainLen are then unused and
 * may be zero/NULL. (The HW-engine INPUT/HUK-wrapped path is validated on
 * silicon; the OTP-resident path is implemented but unexercised.) */
typedef struct wc_Rtl8735b_EccKey {
    const byte* seed;
    word32      seedSz;
    const byte* wrapped;     /* AES-GCM ciphertext of the scalar (== plainLen) */
    word32      wrappedLen;
    word32      plainLen;
    /* --- HW ECDSA engine extensions (appended; zero keeps legacy behavior) --- */
    byte        useHwEngine; /* 1: sign via the HW ECDSA engine (hal_ecdsa) */
    byte        otpPrkSel;   /* HW private-key source: 0 = unwrapped INPUT scalar,
                              * 1 = ECDSA_OTP_PRK_1, 2 = ECDSA_OTP_PRK_2 (scalar
                              * never in software; seed/wrapped may be NULL) */
    /* --- AES-GCM wrap parameters (authenticated unwrap) --- */
    const byte* iv;          /* 12-byte GCM nonce for the wrapped scalar */
    word32      ivSz;
    const byte* tag;         /* 16-byte GCM auth tag */
    word32      tagSz;
} wc_Rtl8735b_EccKey;

#ifdef __cplusplus
    extern "C" {
#endif

/* Register / unregister the AmebaPro2 HUK device. After registering at
 * WC_HUK_DEVID, set an object's devId to it at init (e.g.
 * wc_AesInit(&aes, NULL, WC_HUK_DEVID)) to route transparently to the HUK
 * crypto engine. Both return 0 on success; unregister returns a mutex-lock
 * error if it could not scrub the derivation cache / TRNG-init state (the device
 * is still unregistered in that case). */
WOLFSSL_API int wc_Rtl8735b_HukRegister(int devId);
WOLFSSL_API int wc_Rtl8735b_HukUnRegister(int devId);

#ifdef WOLFSSL_RTL8735B_HOST_TEST
/* Host-only KAT of the port's silicon-independent helpers (BE/LE word conversion,
 * CTR counter increment, HMAC accumulator growth/overflow/cap, bounce alignment).
 * A build/CI aid for the --enable-rtl8735b compile-test -- NOT shipped production
 * API. Returns 0 on success, negative on the first failing check. */
WOLFSSL_API int wc_Rtl8735b_HukSelfTest(void);
#endif

#ifdef __cplusplus
    }
#endif

#endif /* WOLFSSL_RTL8735B_HUK */

#endif /* _WOLFPORT_RTL8735B_H_ */
