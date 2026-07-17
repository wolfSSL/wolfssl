/* sha3.h
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


#ifndef WOLF_CRYPT_SHA3_H
#define WOLF_CRYPT_SHA3_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_SHA3

#ifdef HAVE_FIPS
    /* for fips @wc_fips */
    #include <wolfssl/wolfcrypt/fips.h>
#endif

#ifdef __cplusplus
    extern "C" {
#endif

#if FIPS_VERSION3_GE(6,0,0)
    extern const unsigned int wolfCrypt_FIPS_sha3_ro_sanity[2];
    WOLFSSL_LOCAL int wolfCrypt_FIPS_SHA3_sanity(void);
#endif

#ifdef WOLFSSL_ASYNC_CRYPT
    #include <wolfssl/wolfcrypt/async.h>
#endif

#ifdef STM32_HASH
    #include <wolfssl/wolfcrypt/port/st/stm32.h>
#endif

/* in bytes */
/* Digest and block sizes are macros (like the other hash headers, e.g.
 * sha256.h) rather than enum values so they are visible to the preprocessor -
 * e.g. the WC_MIN_DIGEST_SIZE selection in hash.h evaluates them in #if. */
#define WC_SHA3_224_DIGEST_SIZE  28
#define WC_SHA3_256_DIGEST_SIZE  32
#define WC_SHA3_384_DIGEST_SIZE  48
#define WC_SHA3_512_DIGEST_SIZE  64

#if !defined(HAVE_SELFTEST) || \
    defined(HAVE_SELFTEST_VERSION) && (HAVE_SELFTEST_VERSION >= 2)
/* These values are used for HMAC, not SHA-3 directly.
 * They come from from FIPS PUB 202. */
#define WC_SHA3_128_BLOCK_SIZE   168
#define WC_SHA3_224_BLOCK_SIZE   144
#define WC_SHA3_256_BLOCK_SIZE   136
#define WC_SHA3_384_BLOCK_SIZE   104
#define WC_SHA3_512_BLOCK_SIZE   72
#else
/* For SELFTEST version < 2, define WC_SHA3_128_BLOCK_SIZE
 * for Kyber/Dilithium */
#define WC_SHA3_128_BLOCK_SIZE   168
#endif

enum {
    /* SHAKE-128 */
    WC_SHA3_128_COUNT        = 21,

    WC_SHA3_224              = WC_HASH_TYPE_SHA3_224,
    WC_SHA3_224_COUNT        = 18,

    WC_SHA3_256              = WC_HASH_TYPE_SHA3_256,
    WC_SHA3_256_COUNT        = 17,

    WC_SHA3_384              = WC_HASH_TYPE_SHA3_384,
    WC_SHA3_384_COUNT        = 13,

    WC_SHA3_512              = WC_HASH_TYPE_SHA3_512,
    WC_SHA3_512_COUNT        =  9,

    #ifdef WOLFSSL_SHAKE128
        WC_SHAKE128          = WC_HASH_TYPE_SHAKE128,
    #endif
    #ifdef WOLFSSL_SHAKE256
        WC_SHAKE256          = WC_HASH_TYPE_SHAKE256,
    #endif

    WOLF_ENUM_DUMMY_LAST_ELEMENT(WC_SHA3)
};

#ifndef NO_OLD_WC_NAMES
    #define SHA3_224             WC_SHA3_224
    #define SHA3_224_DIGEST_SIZE WC_SHA3_224_DIGEST_SIZE
    #define SHA3_256             WC_SHA3_256
    #define SHA3_256_DIGEST_SIZE WC_SHA3_256_DIGEST_SIZE
    #define SHA3_384             WC_SHA3_384
    #define SHA3_384_DIGEST_SIZE WC_SHA3_384_DIGEST_SIZE
    #define SHA3_512             WC_SHA3_512
    #define SHA3_512_DIGEST_SIZE WC_SHA3_512_DIGEST_SIZE
    #define Sha3 wc_Sha3
    #ifdef WOLFSSL_SHAKE128
        #define SHAKE128             WC_SHAKE128
    #endif
    #ifdef WOLFSSL_SHAKE256
        #define SHAKE256             WC_SHAKE256
    #endif
#endif



#ifdef WOLFSSL_XILINX_CRYPT
    #include "wolfssl/wolfcrypt/port/xilinx/xil-sha3.h"
#elif defined(WOLFSSL_AFALG_XILINX_SHA3)
    #include <wolfssl/wolfcrypt/port/af_alg/afalg_hash.h>
#else

#if defined(WOLFSSL_PSOC6_CRYPTO)
    #include <wolfssl/wolfcrypt/port/cypress/psoc6_crypto.h>

    #include "cy_crypto_core_sha.h"
    #include "cy_device_headers.h"
    #include "cy_crypto_common.h"
    #include "cy_crypto_core.h"
#endif

/* Sha3 digest */
struct wc_Sha3 {
#if defined(PSOC6_HASH_SHA3)
    cy_stc_crypto_sha_state_t hash_state;
    cy_stc_crypto_v2_sha3_buffers_t sha_buffers;
    bool init_done;
#else
    /* State data that is processed for each block. */
    word64 s[25];
    /* Unprocessed message data. */
    byte   t[200];
    /* Index into unprocessed data to place next message byte. */
    byte   i;

    void*  heap;

#ifdef WOLF_CRYPTO_CB
    int    devId;
    void*  devCtx;
    int    hashType;
#endif

#ifdef WC_C_DYNAMIC_FALLBACK
    void (*sha3_block)(word64 *s);
    void (*sha3_block_n)(word64 *s, const byte* data, word32 n,
        word64 c);
#endif

#ifdef WOLFSSL_ASYNC_CRYPT
    WC_ASYNC_DEV asyncDev;
#endif /* WOLFSSL_ASYNC_CRYPT */
#ifdef WOLFSSL_HASH_FLAGS
    word32 flags; /* enum wc_HashFlags in hash.h */
#endif
#if defined(STM32_HASH_SHA3)
    STM32_HASH_Context stmCtx;
#endif
#endif
};

#ifndef WC_SHA3_TYPE_DEFINED
    typedef struct wc_Sha3 wc_Sha3;
    #define WC_SHA3_TYPE_DEFINED
#endif

#endif

#if defined(WOLFSSL_SHAKE128) || defined(WOLFSSL_SHAKE256)
    #ifndef WC_SHAKE_TYPE_DEFINED
        typedef wc_Sha3 wc_Shake;
        #define WC_SHAKE_TYPE_DEFINED
    #endif
#endif

WOLFSSL_API int wc_InitSha3_224(wc_Sha3* sha3, void* heap, int devId);
WOLFSSL_API int wc_Sha3_224_Update(wc_Sha3* sha3, const byte* data, word32 len);
WOLFSSL_API int wc_Sha3_224_Final(wc_Sha3* sha3, byte* hash);
WOLFSSL_API void wc_Sha3_224_Free(wc_Sha3* sha3);
WOLFSSL_API int wc_Sha3_224_GetHash(wc_Sha3* sha3, byte* hash);
WOLFSSL_API int wc_Sha3_224_Copy(wc_Sha3* src, wc_Sha3* dst);

WOLFSSL_API int wc_InitSha3_256(wc_Sha3* sha3, void* heap, int devId);
WOLFSSL_API int wc_Sha3_256_Update(wc_Sha3* sha3, const byte* data, word32 len);
WOLFSSL_API int wc_Sha3_256_Final(wc_Sha3* sha3, byte* hash);
WOLFSSL_API void wc_Sha3_256_Free(wc_Sha3* sha3);
WOLFSSL_API int wc_Sha3_256_GetHash(wc_Sha3* sha3, byte* hash);
WOLFSSL_API int wc_Sha3_256_Copy(wc_Sha3* src, wc_Sha3* dst);

WOLFSSL_API int wc_InitSha3_384(wc_Sha3* sha3, void* heap, int devId);
WOLFSSL_API int wc_Sha3_384_Update(wc_Sha3* sha3, const byte* data, word32 len);
WOLFSSL_API int wc_Sha3_384_Final(wc_Sha3* sha3, byte* hash);
WOLFSSL_API void wc_Sha3_384_Free(wc_Sha3* sha3);
WOLFSSL_API int wc_Sha3_384_GetHash(wc_Sha3* sha3, byte* hash);
WOLFSSL_API int wc_Sha3_384_Copy(wc_Sha3* src, wc_Sha3* dst);

WOLFSSL_API int wc_InitSha3_512(wc_Sha3* sha3, void* heap, int devId);
WOLFSSL_API int wc_Sha3_512_Update(wc_Sha3* sha3, const byte* data, word32 len);
WOLFSSL_API int wc_Sha3_512_Final(wc_Sha3* sha3, byte* hash);
WOLFSSL_API void wc_Sha3_512_Free(wc_Sha3* sha3);
WOLFSSL_API int wc_Sha3_512_GetHash(wc_Sha3* sha3, byte* hash);
WOLFSSL_API int wc_Sha3_512_Copy(wc_Sha3* src, wc_Sha3* dst);

#ifdef WOLFSSL_SHAKE128
WOLFSSL_API int wc_InitShake128(wc_Shake* shake, void* heap, int devId);
WOLFSSL_API int wc_Shake128_Update(wc_Shake* shake, const byte* data, word32 len);
WOLFSSL_API int wc_Shake128_Final(wc_Shake* shake, byte* hash, word32 hashLen);
WOLFSSL_API int wc_Shake128_Absorb(wc_Shake* shake, const byte* data,
    word32 len);
WOLFSSL_API int wc_Shake128_SqueezeBlocks(wc_Shake* shake, byte* out,
    word32 blockCnt);
WOLFSSL_API void wc_Shake128_Free(wc_Shake* shake);
WOLFSSL_API int wc_Shake128_Copy(wc_Shake* src, wc_Sha3* dst);
#endif

#ifdef WOLFSSL_SHAKE256
WOLFSSL_API int wc_InitShake256(wc_Shake* shake, void* heap, int devId);
WOLFSSL_API int wc_Shake256_Update(wc_Shake* shake, const byte* data, word32 len);
WOLFSSL_API int wc_Shake256_Final(wc_Shake* shake, byte* hash, word32 hashLen);
WOLFSSL_API int wc_Shake256_Absorb(wc_Shake* shake, const byte* data,
    word32 len);
WOLFSSL_API int wc_Shake256_SqueezeBlocks(wc_Shake* shake, byte* out,
    word32 blockCnt);
WOLFSSL_API void wc_Shake256_Free(wc_Shake* shake);
WOLFSSL_API int wc_Shake256_Copy(wc_Shake* src, wc_Sha3* dst);
#endif

#ifdef WOLFSSL_HASH_FLAGS
    WOLFSSL_API int wc_Sha3_SetFlags(wc_Sha3* sha3, word32 flags);
    WOLFSSL_API int wc_Sha3_GetFlags(wc_Sha3* sha3, word32* flags);
#endif

#if defined(WOLFSSL_KMAC) || defined(WOLFSSL_CSHAKE)
/* KMAC (KECCAK Message Authentication Code) and its cSHAKE substrate,
 * NIST SP 800-185. KMAC is built on cSHAKE, so enabling KMAC (WOLFSSL_KMAC)
 * also enables cSHAKE; cSHAKE may be enabled on its own with WOLFSSL_CSHAKE.
 * Both are built on the SHAKE XOF - the 128-bit variants require SHAKE128 and
 * the 256-bit variants require SHAKE256. */
#if defined(WOLFSSL_KMAC) && !defined(WOLFSSL_CSHAKE)
    #define WOLFSSL_CSHAKE
#endif

/* KMAC and cSHAKE use the software KECCAK sponge directly (Sha3Update/
 * Sha3Final), which is not available on pure-hardware SHA-3 ports. PSOC6
 * offers hardware SHAKE but no software KECCAK, so they cannot be built there;
 * fail early with a clear message rather than an obscure link error. */
#if defined(PSOC6_HASH_SHA3)
    #error "WOLFSSL_KMAC/WOLFSSL_CSHAKE not supported with PSOC6 hardware SHA-3"
#endif

/* cSHAKE variants follow the enabled SHAKE variants. */
#if defined(WOLFSSL_SHAKE128) && !defined(WOLFSSL_CSHAKE128)
    #define WOLFSSL_CSHAKE128
#endif
#if defined(WOLFSSL_SHAKE256) && !defined(WOLFSSL_CSHAKE256)
    #define WOLFSSL_CSHAKE256
#endif
#if !defined(WOLFSSL_CSHAKE128) && !defined(WOLFSSL_CSHAKE256)
    #error "WOLFSSL_KMAC/WOLFSSL_CSHAKE requires SHAKE128 and/or SHAKE256"
#endif

/* KMAC variants follow the enabled cSHAKE variants. */
#ifdef WOLFSSL_KMAC
    #if defined(WOLFSSL_CSHAKE128) && !defined(WOLFSSL_KMAC128)
        #define WOLFSSL_KMAC128
    #endif
    #if defined(WOLFSSL_CSHAKE256) && !defined(WOLFSSL_KMAC256)
        #define WOLFSSL_KMAC256
    #endif
#endif

/* cSHAKE state - a SHAKE (KECCAK) sponge, the block rate, and the pad byte
 * (0x04 when customized, 0x1f when it reduces to plain SHAKE). */
struct wc_Cshake {
    wc_Shake shake;
    byte     count;
    byte     pad;
};

#ifndef WC_CSHAKE_TYPE_DEFINED
    typedef struct wc_Cshake wc_Cshake;
    #define WC_CSHAKE_TYPE_DEFINED
#endif

#ifdef WOLFSSL_KMAC
/* KMAC state - wraps a SHAKE (KECCAK) sponge plus the block rate. */
struct wc_Kmac {
    wc_Shake shake;
    /* Number of 64-bit words in a KECCAK block (rate / 8) - selects the
     * KMAC128 (SHAKE128) or KMAC256 (SHAKE256) variant. */
    byte     count;
};

#ifndef WC_KMAC_TYPE_DEFINED
    typedef struct wc_Kmac wc_Kmac;
    #define WC_KMAC_TYPE_DEFINED
#endif
#endif /* WOLFSSL_KMAC */

#ifdef WOLFSSL_KMAC128
WOLFSSL_API int wc_InitKmac128(wc_Kmac* kmac, const byte* key, word32 keyLen,
    const byte* custom, word32 customLen, void* heap, int devId);
WOLFSSL_API int wc_Kmac128_Update(wc_Kmac* kmac, const byte* in, word32 inLen);
WOLFSSL_API int wc_Kmac128_Final(wc_Kmac* kmac, byte* out, word32 outLen);
WOLFSSL_API int wc_Kmac128_FinalXof(wc_Kmac* kmac, byte* out, word32 outLen);
WOLFSSL_API int wc_Kmac128_Copy(wc_Kmac* src, wc_Kmac* dst);
WOLFSSL_API void wc_Kmac128_Free(wc_Kmac* kmac);
WOLFSSL_API int wc_Kmac128Hash(const byte* key, word32 keyLen,
    const byte* custom, word32 customLen, const byte* in, word32 inLen,
    byte* out, word32 outLen);
WOLFSSL_API int wc_Kmac128HashXof(const byte* key, word32 keyLen,
    const byte* custom, word32 customLen, const byte* in, word32 inLen,
    byte* out, word32 outLen);
#endif

#ifdef WOLFSSL_KMAC256
WOLFSSL_API int wc_InitKmac256(wc_Kmac* kmac, const byte* key, word32 keyLen,
    const byte* custom, word32 customLen, void* heap, int devId);
WOLFSSL_API int wc_Kmac256_Update(wc_Kmac* kmac, const byte* in, word32 inLen);
WOLFSSL_API int wc_Kmac256_Final(wc_Kmac* kmac, byte* out, word32 outLen);
WOLFSSL_API int wc_Kmac256_FinalXof(wc_Kmac* kmac, byte* out, word32 outLen);
WOLFSSL_API int wc_Kmac256_Copy(wc_Kmac* src, wc_Kmac* dst);
WOLFSSL_API void wc_Kmac256_Free(wc_Kmac* kmac);
WOLFSSL_API int wc_Kmac256Hash(const byte* key, word32 keyLen,
    const byte* custom, word32 customLen, const byte* in, word32 inLen,
    byte* out, word32 outLen);
WOLFSSL_API int wc_Kmac256HashXof(const byte* key, word32 keyLen,
    const byte* custom, word32 customLen, const byte* in, word32 inLen,
    byte* out, word32 outLen);
#endif

#ifdef WOLFSSL_CSHAKE128
WOLFSSL_API int wc_InitCshake128(wc_Cshake* cshake, const byte* name,
    word32 nameLen, const byte* custom, word32 customLen, void* heap,
    int devId);
WOLFSSL_API int wc_Cshake128_Update(wc_Cshake* cshake, const byte* in,
    word32 inLen);
WOLFSSL_API int wc_Cshake128_Final(wc_Cshake* cshake, byte* out, word32 outLen);
WOLFSSL_API int wc_Cshake128_Copy(wc_Cshake* src, wc_Cshake* dst);
WOLFSSL_API void wc_Cshake128_Free(wc_Cshake* cshake);
WOLFSSL_API int wc_Cshake128(const byte* name, word32 nameLen,
    const byte* custom, word32 customLen, const byte* in, word32 inLen,
    byte* out, word32 outLen);
#endif

#ifdef WOLFSSL_CSHAKE256
WOLFSSL_API int wc_InitCshake256(wc_Cshake* cshake, const byte* name,
    word32 nameLen, const byte* custom, word32 customLen, void* heap,
    int devId);
WOLFSSL_API int wc_Cshake256_Update(wc_Cshake* cshake, const byte* in,
    word32 inLen);
WOLFSSL_API int wc_Cshake256_Final(wc_Cshake* cshake, byte* out, word32 outLen);
WOLFSSL_API int wc_Cshake256_Copy(wc_Cshake* src, wc_Cshake* dst);
WOLFSSL_API void wc_Cshake256_Free(wc_Cshake* cshake);
WOLFSSL_API int wc_Cshake256(const byte* name, word32 nameLen,
    const byte* custom, word32 customLen, const byte* in, word32 inLen,
    byte* out, word32 outLen);
#endif
#endif /* WOLFSSL_KMAC || WOLFSSL_CSHAKE */

WOLFSSL_LOCAL void BlockSha3(word64 *s);

#ifdef WC_SHA3_NO_ASM
    /* asm speedups disabled */
    #if defined(USE_INTEL_SPEEDUP) && \
        !(defined(WC_MLKEM_NO_ASM) && defined(WC_SLHDSA_NO_ASM))
        /* native ML-KEM and SLH-DSA use this directly. */
        WOLFSSL_LOCAL void sha3_blocksx4_avx2(word64* s);
    #endif
#elif defined(USE_INTEL_SPEEDUP)
    WOLFSSL_LOCAL void sha3_block_n_bmi2(word64* s, const byte* data, word32 n,
        word64 c);
    WOLFSSL_LOCAL void sha3_block_bmi2(word64* s);
    WOLFSSL_LOCAL void sha3_block_n_avx2(word64* s, const byte* data, word32 n,
        word64 c);
    WOLFSSL_LOCAL void sha3_block_avx2(word64* s);
    WOLFSSL_LOCAL void sha3_blocksx4_avx2(word64* s);
    WOLFSSL_LOCAL void sha3_blocksx4_out_avx2(word64* s, byte* out,
        word32 len);
    WOLFSSL_LOCAL void sha3_blocksx8_out_avx512(word64* s, byte* out,
        word32 len);

    WOLFSSL_LOCAL void sha3_128_blocksx4_seed_avx2(word64* s, byte* seed);
    WOLFSSL_LOCAL void sha3_256_blocksx4_seed_avx2(word64* s, byte* seed);

    WOLFSSL_LOCAL void sha3_256_blocksx4_seed_64_avx2(word64* s, byte* seed);
#elif defined(__aarch64__) && defined(WOLFSSL_ARMASM)
    #ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        WOLFSSL_LOCAL void BlockSha3_crypto(word64 *s);
    #endif
    WOLFSSL_LOCAL void BlockSha3_base(word64 *s);
#elif defined(WOLFSSL_PPC64_ASM)
    #ifdef WOLFSSL_PPC64_ASM_POWER8
        WOLFSSL_LOCAL void BlockSha3_power8(word64 *s);
    #endif
    WOLFSSL_LOCAL void BlockSha3_base(word64 *s);
#endif

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_SHA3 */
#endif /* WOLF_CRYPT_SHA3_H */

