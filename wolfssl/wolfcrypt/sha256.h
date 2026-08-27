/* sha256.h
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

/*!
    \file wolfssl/wolfcrypt/sha256.h
*/



#ifndef WOLF_CRYPT_SHA256_H
#define WOLF_CRYPT_SHA256_H

#include <wolfssl/wolfcrypt/types.h>

#ifndef NO_SHA256

#if FIPS_VERSION3_GE(2,0,0)
    #include <wolfssl/wolfcrypt/fips.h>
#endif /* HAVE_FIPS_VERSION >= 2 */

#ifdef FREESCALE_LTC_SHA
    #include "fsl_ltc.h"
#endif

#if defined(WOLFSSL_IMXRT1170_CAAM)
    #include "fsl_device_registers.h"
    #include "fsl_caam.h"
#endif

#ifdef WOLFSSL_IMXRT_DCP
    #include "fsl_dcp.h"
#endif

#if defined(WOLFSSL_PSOC6_CRYPTO)
    #include <wolfssl/wolfcrypt/port/cypress/psoc6_crypto.h>

    #include "cy_crypto_core_sha.h"
    #include "cy_device_headers.h"
    #include "cy_crypto_common.h"
    #include "cy_crypto_core.h"
#endif

#ifndef WC_HAVE_SHA2_NO_SMALL_STACK
    #define WC_HAVE_SHA2_NO_SMALL_STACK
#endif

#ifdef __cplusplus
    extern "C" {
#endif

#if FIPS_VERSION3_GE(6,0,0)
    extern const unsigned int wolfCrypt_FIPS_sha256_ro_sanity[2];
    WOLFSSL_LOCAL int wolfCrypt_FIPS_SHA256_sanity(void);
#endif

/* avoid redefinition of structs */
#if !defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2))

#ifdef WOLFSSL_MICROCHIP_PIC32MZ
    #include <wolfssl/wolfcrypt/port/pic32/pic32mz-crypt.h>
#endif
#ifdef STM32_HASH
    #include <wolfssl/wolfcrypt/port/st/stm32.h>
#endif
#ifdef WOLFSSL_ASYNC_CRYPT
    #include <wolfssl/wolfcrypt/async.h>
#endif
#if defined(WOLFSSL_DEVCRYPTO) && defined(WOLFSSL_DEVCRYPTO_HASH)
    #include <wolfssl/wolfcrypt/port/devcrypto/wc_devcrypto.h>
#endif
#if defined(WOLFSSL_ESP32_CRYPT)
    #include "wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h"
#endif
#if defined(WOLFSSL_CRYPTOCELL)
    #include <wolfssl/wolfcrypt/port/arm/cryptoCell.h>
#endif
#if defined(WOLFSSL_SILABS_SE_ACCEL)
    #include <wolfssl/wolfcrypt/port/silabs/silabs_hash.h>
#endif
#if defined(WOLFSSL_KCAPI_HASH)
    #include "wolfssl/wolfcrypt/port/kcapi/kcapi_hash.h"
#endif

#if defined(WOLFSSL_HAVE_PSA) && !defined(WOLFSSL_PSA_NO_HASH)
#include <psa/crypto.h>
#undef  WOLFSSL_NO_HASH_RAW
#define WOLFSSL_NO_HASH_RAW
#endif

/* no raw hash access when software transform is stripped */
#if defined(WOLF_CRYPTO_CB_ONLY_SHA256)
#undef  WOLFSSL_NO_HASH_RAW
#define WOLFSSL_NO_HASH_RAW
#endif

#define SHA256_NOINLINE WC_NO_INLINE

#if !defined(NO_OLD_SHA_NAMES)
    #define SHA256             WC_SHA256
#endif

#ifndef NO_OLD_WC_NAMES
    #define Sha256             wc_Sha256
    #define SHA256_BLOCK_SIZE  WC_SHA256_BLOCK_SIZE
    #define SHA256_DIGEST_SIZE WC_SHA256_DIGEST_SIZE
    #define SHA256_PAD_SIZE    WC_SHA256_PAD_SIZE
#endif

/* in bytes */
#define WC_SHA256              WC_HASH_TYPE_SHA256
#define WC_SHA256_BLOCK_SIZE   64
#define WC_SHA256_DIGEST_SIZE  32
#define WC_SHA256_PAD_SIZE     56


#ifdef WOLFSSL_TI_HASH
    #include "wolfssl/wolfcrypt/port/ti/ti-hash.h"
#elif defined(WOLFSSL_IMX6_CAAM) && !defined(WOLFSSL_QNX_CAAM)
    #include "wolfssl/wolfcrypt/port/caam/wolfcaam_sha.h"
#elif defined(WOLFSSL_AFALG_HASH)
    #include "wolfssl/wolfcrypt/port/af_alg/afalg_hash.h"
#elif (defined(WOLFSSL_RENESAS_TSIP_TLS) || \
       defined(WOLFSSL_RENESAS_TSIP_CRYPTONLY)) && \
   !defined(NO_WOLFSSL_RENESAS_TSIP_CRYPT_HASH)
    #include "wolfssl/wolfcrypt/port/Renesas/renesas_tsip_types.h"
#elif (defined(WOLFSSL_RENESAS_SCEPROTECT) || \
       defined(WOLFSSL_RENESAS_RSIP))    && \
     !defined(NO_WOLFSSL_RENESAS_FSPSM_HASH)
    #include "wolfssl/wolfcrypt/port/Renesas/renesas_fspsm_internal.h"
#elif defined(WOLFSSL_RENESAS_RX64_HASH)
    #include "wolfssl/wolfcrypt/port/Renesas/renesas-rx64-hw-crypt.h"
#else

#if defined(WOLFSSL_MAX3266X) || defined(WOLFSSL_MAX3266X_OLD)
    #include "wolfssl/wolfcrypt/port/maxim/max3266x.h"
#endif

#if defined(WOLFSSL_SE050) && defined(WOLFSSL_SE050_HASH)
    #include "wolfssl/wolfcrypt/port/nxp/se050_port.h"
#endif

#ifdef WOLFSSL_MAXQ10XX_CRYPTO
    #include <wolfssl/wolfcrypt/port/maxim/maxq10xx.h>
#endif

#ifdef HAVE_ARIA
    #include "mcapi.h"
    #include "mcapi_error.h"
#endif


/* wc_Sha256 digest */
struct wc_Sha256 {
#ifdef FREESCALE_LTC_SHA
    ltc_hash_ctx_t ctx;
#elif defined(WOLFSSL_SE050) && defined(WOLFSSL_SE050_HASH)
    SE050_HASH_Context se050Ctx;
#elif defined(STM32_HASH_SHA2)
    STM32_HASH_Context stmCtx;
#elif defined(WOLFSSL_SILABS_SE_ACCEL)
    wc_silabs_sha_t silabsCtx;
#elif defined(WOLFSSL_IMXRT_DCP)
    dcp_handle_t handle;
    dcp_hash_ctx_t ctx;
#elif defined(PSOC6_HASH_SHA2)
    cy_stc_crypto_sha_state_t hash_state;
    cy_stc_crypto_v2_sha256_buffers_t sha_buffers;
#elif defined(WOLFSSL_HAVE_PSA) && !defined(WOLFSSL_PSA_NO_HASH)
    psa_hash_operation_t psa_ctx;
#else
#ifdef WC_64BIT_CPU
    /* alignment on digest and buffer speeds up ARMv8 crypto operations */
    ALIGN16 word32  digest[WC_SHA256_DIGEST_SIZE / sizeof(word32)];
    ALIGN16 word32  buffer[WC_SHA256_BLOCK_SIZE  / sizeof(word32)];
#else
    word32  digest[WC_SHA256_DIGEST_SIZE / sizeof(word32)];
    word32  buffer[WC_SHA256_BLOCK_SIZE  / sizeof(word32)];
#endif
    word32  buffLen;   /* in bytes          */
    word32  loLen;     /* length in bytes   */
    word32  hiLen;     /* length in bytes   */

#endif
    void*   heap;
#ifdef WOLFSSL_PIC32MZ_HASH
    hashUpdCache cache; /* cache for updates */
#endif
#ifdef WOLFSSL_ASYNC_CRYPT
    WC_ASYNC_DEV asyncDev;
#endif /* WOLFSSL_ASYNC_CRYPT */
#if defined(WOLFSSL_SMALL_STACK_CACHE) && !defined(WC_SHA2_NO_SMALL_STACK)
    word32* W;
#endif /* !FREESCALE_LTC_SHA && !STM32_HASH_SHA2 */
#ifdef WOLFSSL_DEVCRYPTO_HASH
    WC_CRYPTODEV ctx;
#endif
#if defined(WOLFSSL_DEVCRYPTO_HASH) || defined(WOLFSSL_HASH_KEEP)
    byte*  msg;
    word32 used;
    word32 len;
#endif
#if defined(WOLFSSL_ESP32_CRYPT) && \
   !defined(NO_WOLFSSL_ESP32_CRYPT_HASH) && \
  (!defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA256) || \
   !defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA224))
    WC_ESP32SHA ctx;
#endif
#ifdef WOLFSSL_MAXQ10XX_CRYPTO
    maxq_sha256_t maxq_ctx;
#endif
#ifdef WOLFSSL_CRYPTOCELL
    CRYS_HASHUserContext_t ctx;
#endif
#ifdef WOLFSSL_KCAPI_HASH
    wolfssl_KCAPI_Hash kcapi;
#endif
#ifdef WOLF_CRYPTO_CB
    int    devId;
    void*  devCtx; /* generic crypto callback context */
#endif
#ifdef WOLFSSL_IMXRT1170_CAAM
    caam_hash_ctx_t ctx;
    caam_handle_t hndl;
#endif
#ifdef HAVE_ARIA
    MC_HSESSION hSession;
#endif
#ifdef WOLFSSL_HASH_FLAGS
    word32 flags; /* enum wc_HashFlags in hash.h */
#endif
};

#ifndef WC_SHA256_TYPE_DEFINED
    typedef struct wc_Sha256 wc_Sha256;
    #define WC_SHA256_TYPE_DEFINED
#endif

#endif

#endif /* HAVE_FIPS */

WOLFSSL_API int wc_InitSha256(wc_Sha256* sha);
WOLFSSL_API int wc_InitSha256_ex(wc_Sha256* sha, void* heap, int devId);
WOLFSSL_API int wc_Sha256Update(wc_Sha256* sha, const byte* data, word32 len);

#if !defined(WOLFSSL_KCAPI_HASH) && !defined(WOLFSSL_AFALG_HASH) && \
    !defined(WOLF_CRYPTO_CB_ONLY_SHA256)
WOLFSSL_API int wc_Sha256FinalRaw(wc_Sha256* sha256, byte* hash);
#endif
WOLFSSL_API int wc_Sha256Final(wc_Sha256* sha256, byte* hash);
WOLFSSL_API void wc_Sha256Free(wc_Sha256* sha256);
#if (defined(OPENSSL_EXTRA) || defined(HAVE_CURL)) && \
    !defined(WOLFSSL_KCAPI_HASH) && !defined(WOLFSSL_AFALG_HASH) && \
    !defined(WOLF_CRYPTO_CB_ONLY_SHA256)
WOLFSSL_API int wc_Sha256Transform(wc_Sha256* sha, const unsigned char* data);
#endif
#if defined(WOLFSSL_HAVE_LMS) && !defined(WOLFSSL_LMS_FULL_HASH)
WOLFSSL_API int wc_Sha256HashBlock(wc_Sha256* sha, const unsigned char* data,
    unsigned char* hash);
#endif

/* Multi-buffer SHA-256: compress several independent message blocks at once,
 * one per 32-bit lane of a vector register.  LMS and XMSS drive these
 * directly, the way ML-KEM and SLH-DSA drive the multi-way Keccak in sha3.h -
 * there is no wrapper API, so the caller owns the interleaved state, the
 * CPUID check and the vector-register save.
 *
 * state is lane-interleaved: word i of message m is state[i * cnt + m], which
 * is what the round code needs in a register.  data is 'cnt' consecutive
 * 64-byte blocks.  The compressed block is added into state, so a caller
 * starts it from the SHA-256 initial value or from a shared prefix's chaining
 * value and calls once per block.
 *
 * Two widths are built.  Which is usable is a property of the CPU, so the
 * lane count is decided at run time and WC_SHA256_N_WAY_MAX_CNT is only for
 * sizing buffers.  Measured per compressed block on a Zen 5: sixteen-way
 * AVX-512 7.3 ns, eight-way AVX2 25.5 ns, single-stream SHA-NI 23.5 ns - so
 * callers take sixteen lanes wherever AVX-512 is present, but eight only
 * where SHA-NI is absent.  (The AVX2 eight-way is now level with SHA-NI
 * rather than clearly behind it, so that last rule is closer than it used to
 * be; it still goes the same way.)
 *
 * The condition must stay in step with the guards the generator puts around
 * these in sha256_asm.S.
 */
#if defined(WOLFSSL_X86_64_BUILD) && defined(USE_INTEL_SPEEDUP) && \
    !defined(NO_AVX2_SUPPORT) && !defined(WOLFSSL_NO_SHA256_N_WAY) && \
    (defined(WOLFSSL_HAVE_LMS) || defined(WOLFSSL_HAVE_XMSS) || \
     defined(WOLFSSL_HAVE_SLHDSA))

#define WC_SHA256_N_WAY
/* Widest batch this build can run. */
#ifdef NO_AVX512_SUPPORT
    #define WC_SHA256_N_WAY_MAX_CNT   8
#else
    #define WC_SHA256_N_WAY_MAX_CNT   16
#endif
/* Bytes of message data the widest batch consumes per block index. */
#define WC_SHA256_N_WAY_MAX_BLK_SZ  \
    (WC_SHA256_N_WAY_MAX_CNT * WC_SHA256_BLOCK_SIZE)

WOLFSSL_LOCAL void Transform_Sha256_x8_AVX2(word32* state, const byte* data);
#ifndef NO_AVX512_SUPPORT
WOLFSSL_LOCAL void Transform_Sha256_x16_AVX512(word32* state,
    const byte* data);
#ifndef NO_AVX512BW_SUPPORT
/* The same kernel, byte-swapping the message with vpshufb instead of the
 * rotate-and-merge pair the AVX-512F-only form uses - two instructions
 * saved on each of the sixteen loads, about 1%.  Call it only after
 * IS_INTEL_AVX512_BW(); the plain form is what runs otherwise. */
WOLFSSL_LOCAL void Transform_Sha256_x16_AVX512_BW(word32* state,
    const byte* data);
#endif

/* LM-OTS kernels: these fill the lanes themselves and leave the compressed
 * state lane-interleaved in the caller's buffer, so a chain runs without ever
 * de-interleaving - the same shape as SLH-DSA's SHAKE x4 chain, where the
 * state persists across the loop and the hashes are read out only at the end.
 *
 * One sets the lanes up in the first place, one reuses the buffer they leave;
 * what differs between call sites is passed in rather than made into more
 * functions.
 *
 * st    - WC_SHA256_N_WAY_MAX_CNT * 8 words, lane-interleaved, in and out.
 * tmpl  - the LM-OTS block as sixteen host-order words: the fields that do
 *         not vary between lanes.
 * idx0  - chain index of lane 0; lane l takes idx0 + l.
 * idxv  - per-lane chain index.
 * jv    - per-lane iteration index.
 */
WOLFSSL_LOCAL void Transform_Sha256_x16_LmsInit_AVX512(word32* st,
    const word32* tmpl, word32 idx0);
WOLFSSL_LOCAL void Transform_Sha256_x16_LmsStep_AVX512(word32* st,
    const word32* tmpl, const word32* idxv, const word32* jv);
/* Key generation runs every chain of a group the same length with every lane
 * at the same iteration, so the whole loop goes in here: 'max' iterations
 * without the state leaving registers between them. */
WOLFSSL_LOCAL void Transform_Sha256_x16_LmsChain_AVX512(word32* st,
    const word32* tmpl, const word32* idxv, word32 max);
#ifdef WOLFSSL_LMS_SHA256_192
/* The same three for a 24-byte hash: the message is eight bytes shorter, so
 * tmp ends in W11 and the digest is six words rather than eight. */
WOLFSSL_LOCAL void Transform_Sha256_x16_Lms192Init_AVX512(word32* st,
    const word32* tmpl, word32 idx0);
WOLFSSL_LOCAL void Transform_Sha256_x16_Lms192Step_AVX512(word32* st,
    const word32* tmpl, const word32* idxv, const word32* jv);
WOLFSSL_LOCAL void Transform_Sha256_x16_Lms192Chain_AVX512(word32* st,
    const word32* tmpl, const word32* idxv, word32 max);
#endif
#endif

#if defined(WOLFSSL_HAVE_XMSS) && !defined(NO_AVX512_SUPPORT)
/* XMSS with SHA-256 and n = 32, sixteen chains at a time.
 *
 * PRF hashes padding || SEED || ADRS.  Padding and SEED are one whole block
 * and do not change within a WOTS+ operation, so the caller absorbs them once
 * and every PRF here is the single block that holds ADRS.
 *
 * F hashes padding || KEY || (tmp ^ BM), all of which this code already holds
 * lane-interleaved - so a chain runs PRF, PRF, F without any of the three
 * touching a byte buffer.
 *
 * out   - WC_SHA256_N_WAY_MAX_CNT * 8 words, lane-interleaved.
 * mid   - the eight-word state left by padding || SEED.
 * adrs  - ADRS as eight host-order words: the fields alike in every lane,
 *         including the key-and-mask word that selects KEY or BM.
 * chainv, hashv - per-lane chain and hash address.
 * st    - the chain value, lane-interleaved, in and out.
 * key, bm - lane-interleaved, as PRF left them.
 */
WOLFSSL_LOCAL void Transform_Sha256_x16_XmssPrf_AVX512(word32* out,
    const word32* mid, const word32* adrs, const word32* chainv,
    const word32* hashv);
WOLFSSL_LOCAL void Transform_Sha256_x16_XmssF_AVX512(word32* st,
    const word32* key, const word32* bm);
/* The 24-byte parameter sets pad with four bytes, not a whole hash, so the
 * blocks fall differently: PRF's 60-byte message spills into a second block
 * and has no whole block of prefix to absorb once, while F's 52-byte message
 * fits in one.  Both start from the initial value.
 *
 * pfx - the four padding bytes and SEED as seven words.
 */
WOLFSSL_LOCAL void Transform_Sha256_x16_Xmss192Prf_AVX512(word32* out,
    const word32* pfx, const word32* adrs, const word32* chainv,
    const word32* hashv);
WOLFSSL_LOCAL void Transform_Sha256_x16_Xmss192F_AVX512(word32* st,
    const word32* key, const word32* bm);
#endif

#endif /* multi-buffer SHA-256 */
#if defined(WOLFSSL_HASH_KEEP)
WOLFSSL_API int wc_Sha256_Grow(wc_Sha256* sha256, const byte* in, int inSz);
#endif
WOLFSSL_API int wc_Sha256GetHash(wc_Sha256* sha256, byte* hash);
WOLFSSL_API int wc_Sha256Copy(wc_Sha256* src, wc_Sha256* dst);

#ifdef WOLFSSL_PIC32MZ_HASH
WOLFSSL_API void wc_Sha256SizeSet(wc_Sha256* sha256, word32 len);
#endif

#ifdef WOLFSSL_HASH_FLAGS
    WOLFSSL_API int wc_Sha256SetFlags(wc_Sha256* sha256, word32 flags);
    WOLFSSL_API int wc_Sha256GetFlags(wc_Sha256* sha256, word32* flags);
#endif

#ifdef WOLFSSL_SHA224
/* avoid redefinition of structs */
#if !defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2))

#if !defined(NO_OLD_SHA_NAMES)
    #define SHA224             WC_SHA224
#endif

#ifndef NO_OLD_WC_NAMES
    #define Sha224             wc_Sha224
    #define SHA224_BLOCK_SIZE  WC_SHA224_BLOCK_SIZE
    #define SHA224_DIGEST_SIZE WC_SHA224_DIGEST_SIZE
    #define SHA224_PAD_SIZE    WC_SHA224_PAD_SIZE
#endif

/* in bytes */
#define WC_SHA224             WC_HASH_TYPE_SHA224
#define WC_SHA224_BLOCK_SIZE  WC_SHA256_BLOCK_SIZE
#define WC_SHA224_DIGEST_SIZE 28
#define WC_SHA224_PAD_SIZE    WC_SHA256_PAD_SIZE


#ifndef WC_SHA224_TYPE_DEFINED
    typedef struct wc_Sha256 wc_Sha224;
    #define WC_SHA224_TYPE_DEFINED
#endif
#endif /* HAVE_FIPS */

WOLFSSL_API int wc_InitSha224(wc_Sha224* sha224);
WOLFSSL_API int wc_InitSha224_ex(wc_Sha224* sha224, void* heap, int devId);
WOLFSSL_API int wc_Sha224Update(wc_Sha224* sha224, const byte* data, word32 len);
WOLFSSL_API int wc_Sha224Final(wc_Sha224* sha224, byte* hash);
WOLFSSL_API void wc_Sha224Free(wc_Sha224* sha224);

#if defined(WOLFSSL_HASH_KEEP)
WOLFSSL_API int wc_Sha224_Grow(wc_Sha224* sha224, const byte* in, int inSz);
#endif
WOLFSSL_API int wc_Sha224GetHash(wc_Sha224* sha224, byte* hash);
WOLFSSL_API int wc_Sha224Copy(wc_Sha224* src, wc_Sha224* dst);

#ifdef WOLFSSL_HASH_FLAGS
    WOLFSSL_API int wc_Sha224SetFlags(wc_Sha224* sha224, word32 flags);
    WOLFSSL_API int wc_Sha224GetFlags(wc_Sha224* sha224, word32* flags);
#endif

#endif /* WOLFSSL_SHA224 */

#if defined(WOLFSSL_ARMASM)
void Transform_Sha256_Len_base(wc_Sha256* sha256, const byte* data, word32 len);
void Transform_Sha256_Len_neon(wc_Sha256* sha256, const byte* data, word32 len);
void Transform_Sha256_Len_crypto(wc_Sha256* sha256, const byte* data,
    word32 len);
#endif

#if defined(WOLFSSL_RISCV_ASM)
void Transform_Sha256_Len_riscv(wc_Sha256* sha256, const byte* data,
    word32 len);
void Transform_Sha256_Len_riscv_crypto(wc_Sha256* sha256, const byte* data,
    word32 len);
void Transform_Sha256_Len_riscv_vector(wc_Sha256* sha256, const byte* data,
    word32 len);
#endif

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* NO_SHA256 */
#endif /* WOLF_CRYPT_SHA256_H */
