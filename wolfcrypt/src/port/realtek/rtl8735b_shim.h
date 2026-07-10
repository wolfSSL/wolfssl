/* rtl8735b_shim.h
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

/* Host compile-test stand-in for the slice of the RealTek AmebaPro2 HAL that
 * wolfcrypt/src/port/realtek/rtl8735b.c references. Compiled ONLY under
 * WOLFSSL_RTL8735B_HOST_TEST (set by --enable-rtl8735b). It lets the
 * crypto-callback dispatch, field access, and compile-time guards be exercised
 * on a host without the customer SDK. Every stub returns a success sentinel; it
 * performs NO real crypto -- so the host build is a compile gate, plus the
 * silicon-independent helper KATs in wc_Rtl8735b_HukSelfTest() (which need no
 * HAL crypto). Cipher / GCM / ECDSA correctness is validated on RTL8735B
 * hardware, never through these stubs. On target this header is NOT used -- the
 * real HAL headers (hal_crypto.h, hal_hkdf.h) are included instead, supplied via
 * the application/board include path.
 *
 * The prototypes here intentionally mirror the real HAL signatures from
 * nuwa_hal_realtek (rtl8735b branch),
 * ameba/amebapro2/source/fwlib/rtl8735b/include/. Keep this in sync with the
 * HAL calls in rtl8735b.c (add a stub here when the port starts calling a new
 * HAL function under host test).
 */

#ifndef _WOLFPORT_RTL8735B_SHIM_H_
#define _WOLFPORT_RTL8735B_SHIM_H_

#ifdef WOLFSSL_RTL8735B_HOST_TEST

/* HAL scalar types (the real HAL pulls these from its basic_types header). */
#ifndef _RTL8735B_TYPES_SHIMMED_
    #define _RTL8735B_TYPES_SHIMMED_
    typedef unsigned char  u8;
    typedef unsigned int   u32;
#endif

/* hal_status_t / success sentinel. */
typedef int hal_status_t;
#ifndef HAL_OK
    #define HAL_OK 0
#endif

/* ---- Engine + AES secure-key ops (hal_crypto.h) ---- */
static inline int hal_crypto_engine_init(void) { return 0; }
static inline int hal_crypto_aes_gcm_sk_init(u8 key_num, const u32 keylen)
    { (void)key_num; (void)keylen; return 0; }
static inline int hal_crypto_aes_gcm_encrypt(const u8* msg, const u32 msglen,
        const u8* iv, const u8* aad, const u32 aadlen, u8* pResult, u8* pTag)
    { (void)msg; (void)msglen; (void)iv; (void)aad; (void)aadlen;
      (void)pResult; (void)pTag; return 0; }
static inline int hal_crypto_aes_gcm_decrypt(const u8* msg, const u32 msglen,
        const u8* iv, const u8* aad, const u32 aadlen, u8* pResult, u8* pTag)
    { (void)msg; (void)msglen; (void)iv; (void)aad; (void)aadlen;
      (void)pResult; (void)pTag; return 0; }
static inline int hal_crypto_aes_ecb_sk_init(u8 key_num, const u32 keylen)
    { (void)key_num; (void)keylen; return 0; }
static inline int hal_crypto_aes_ecb_encrypt(const u8* msg, const u32 msglen,
        const u8* iv, const u32 ivlen, u8* pResult)
    { (void)msg; (void)msglen; (void)iv; (void)ivlen; (void)pResult; return 0; }
static inline int hal_crypto_aes_ecb_decrypt(const u8* msg, const u32 msglen,
        const u8* iv, const u32 ivlen, u8* pResult)
    { (void)msg; (void)msglen; (void)iv; (void)ivlen; (void)pResult; return 0; }

/* ---- Secure-key HMAC-SHA256 (hal_crypto.h) ---- */
#if !defined(NO_HMAC) && !defined(NO_SHA256)
static inline u32 hal_crypto_hmac_sha2_256_get_sk_cfg(const u8 sk_op,
        const u8 sk_idx, const u8 wb_op, const u8 wb_idx)
    { (void)sk_op; (void)sk_idx; (void)wb_op; (void)wb_idx; return 0; }
static inline int hal_crypto_hmac_sha2_256_sk_init(const u8* key,
        const u32 sk_cfg)
    { (void)key; (void)sk_cfg; return 0; }
static inline int hal_crypto_hmac_sha2_256_update(const u8* message,
        const u32 msglen)
    { (void)message; (void)msglen; return 0; }
static inline int hal_crypto_hmac_sha2_256_sk_final(u8* pDigest)
    { (void)pDigest; return 0; }
#endif /* !NO_HMAC && !NO_SHA256 */

/* ---- HKDF secure key-ladder (hal_hkdf.h) ---- */
static inline hal_status_t hal_hkdf_hmac_sha256_secure_init(const u8 crypto_sel)
    { (void)crypto_sel; return HAL_OK; }
static inline hal_status_t hal_hkdf_extract_secure_all(const u8 sk_idx,
        const u8 wb_idx, const u8* msg_buf)
    { (void)sk_idx; (void)wb_idx; (void)msg_buf; return HAL_OK; }
static inline hal_status_t hal_hkdf_expand_secure_all(const u8 sk_idx,
        const u8 wb_idx, const u8* nonce)
    { (void)sk_idx; (void)wb_idx; (void)nonce; return HAL_OK; }

/* ---- Secure TRNG (hal_trng_sec.h) ---- */
#ifndef WC_NO_RNG
static inline hal_status_t hal_trng_sec_init(void) { return HAL_OK; }
static inline u32 hal_trng_sec_get_rand(void) { return 0x5A5A5A5Au; }
#endif /* WC_NO_RNG */

/* ---- HW ECDSA engine (hal_ecdsa.h) ---- */
#if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN)
typedef int HAL_Status;
typedef unsigned char ecdsa_curve_t;
typedef unsigned char ecdsa_mode_t;
typedef unsigned char ecdsa_basic_func_t;
typedef unsigned char ecdsa_bit_num_t;
typedef unsigned char ecdsa_sel_prk_t;
#ifndef ECDSA_P256
    #define ECDSA_P256       0x1
#endif
#ifndef ECDSA_SIGN
    #define ECDSA_SIGN       0x1
#endif
#ifndef ECDSA_VERI
    #define ECDSA_VERI       0x0
#endif
#ifndef ECDSA_NONE
    #define ECDSA_NONE       0x5
#endif
#ifndef ECDSA_256_BIT
    #define ECDSA_256_BIT    0x0
#endif
#ifndef ECDSA_INPUT_PRK
    #define ECDSA_INPUT_PRK  0x0
    #define ECDSA_OTP_PRK_1  0x1
    #define ECDSA_OTP_PRK_2  0x2
#endif
typedef struct hal_ecdsa_adapter_s { int dummy; } hal_ecdsa_adapter_t;
typedef struct hal_ecdsa_curve_table_s {
    u32* ppoint_x;
    u32* ppoint_y;
    u32* pa_adr;
    u32* pprime;
    u32* porder_n;
} hal_ecdsa_curve_table_t;
typedef void (*ecdsa_irq_user_cb_t)(void*);
static inline HAL_Status hal_ecdsa_init(hal_ecdsa_adapter_t* a)
    { (void)a; return 0; }
static inline HAL_Status hal_ecdsa_deinit(hal_ecdsa_adapter_t* a)
    { (void)a; return 0; }
static inline u32 hal_ecdsa_get_err_sta(hal_ecdsa_adapter_t* a)
    { (void)a; return 0; }
static inline void hal_ecdsa_cb_handler(hal_ecdsa_adapter_t* a,
        ecdsa_irq_user_cb_t cb, void* arg) { (void)a; (void)cb; (void)arg; }
static inline void hal_ecdsa_set_curve(hal_ecdsa_adapter_t* a, ecdsa_curve_t c,
        hal_ecdsa_curve_table_t* t, ecdsa_bit_num_t b)
    { (void)a; (void)c; (void)t; (void)b; }
static inline void hal_ecdsa_set_mode(hal_ecdsa_adapter_t* a, ecdsa_mode_t m,
        ecdsa_basic_func_t f) { (void)a; (void)m; (void)f; }
static inline void hal_ecdsa_select_prk(hal_ecdsa_adapter_t* a,
        ecdsa_sel_prk_t s) { (void)a; (void)s; }
static inline void hal_ecdsa_signature(hal_ecdsa_adapter_t* a, u32* pk, u32* k)
    { (void)a; (void)pk; (void)k; }
static inline void hal_ecdsa_hash(hal_ecdsa_adapter_t* a, u32* h)
    { (void)a; (void)h; }
static inline void hal_ecdsa_get_rs(hal_ecdsa_adapter_t* a, u32* r, u32* s)
    { (void)a; (void)r; (void)s; }
#ifdef HAVE_ECC_VERIFY
typedef struct hal_ecdsa_veri_input_s {
    u32* ppub_key_x;
    u32* ppub_key_y;
    u32* pr_adr;
    u32* ps_adr;
} hal_ecdsa_veri_input_t;
static inline void hal_ecdsa_verify(hal_ecdsa_adapter_t* a,
        hal_ecdsa_veri_input_t* in) { (void)a; (void)in; }
static inline u32 hal_ecdsa_get_veri_result(hal_ecdsa_adapter_t* a)
    { (void)a; return 0; }
static inline u32 hal_ecdsa_get_veri_err_sta(hal_ecdsa_adapter_t* a)
    { (void)a; return 0; }
#endif /* HAVE_ECC_VERIFY */
#endif /* HAVE_ECC && HAVE_ECC_SIGN */

#endif /* WOLFSSL_RTL8735B_HOST_TEST */

#endif /* _WOLFPORT_RTL8735B_SHIM_H_ */
