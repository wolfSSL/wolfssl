/* mpfs_athena.c
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

/* SHA-2, AES, the NRBG and DRBG, ECDSA, ECDH and RSA on the PolarFire SoC
 * Athena F5200 through the crypto callback; see mpfs_athena.h and README.md. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* wolfSSL's and CAL's uint128_t collide; nothing here uses word128. Local
 * only: in CFLAGS it would change the whole build. */
#ifndef NO_INT128
    #define NO_INT128
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_MPFS_ATHENA) && defined(WOLF_CRYPTO_CB)

#include <wolfssl/wolfcrypt/port/microchip/mpfs_athena.h>

/* One published CAL defines these, the other stops without them. */
#ifndef CALCONFIGH
    #define CALCONFIGH "config_user.h"
#endif
#ifndef INC_STDINT_H
    #define INC_STDINT_H
#endif
#include "calini.h"
#include "hash.h"
#include "sym.h"
#ifdef WOLFSSL_CMAC
    #include "mac.h"
#endif
#if (!defined(WC_NO_RNG) && !defined(WC_MPFS_ATHENA_NO_RNG)) || \
    (defined(HAVE_ECC) && !defined(WC_MPFS_ATHENA_NO_ECC)) || \
    (!defined(NO_RSA) && !defined(WC_MPFS_ATHENA_NO_RSA))
    #include "pk.h"
#endif
#if !defined(WC_NO_RNG) && !defined(WC_MPFS_ATHENA_NO_RNG)
    #include "nrbg.h"
    #include "drbg.h"
#endif
#if defined(HAVE_ECC) && !defined(WC_MPFS_ATHENA_NO_ECC)
    #include "pkx.h"
#endif

#include <wolfssl/wolfcrypt/aes.h>
#ifdef WOLFSSL_CMAC
    #include <wolfssl/wolfcrypt/cmac.h>
#endif
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/random.h>
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
    #include <wolfssl/wolfcrypt/asn.h>
#endif
#ifndef NO_RSA
    #include <wolfssl/wolfcrypt/rsa.h>
#endif
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* One published CAL needs this symbol to link; WC_MPFS_ATHENA_NO_BASE_ADDR
 * when the platform supplies it. */
#ifndef WC_MPFS_ATHENA_NO_BASE_ADDR
word32 g_user_crypto_base_addr = (word32)WC_MPFS_ATHENA_BASE_ADDR;
#endif

#define WC_MPFS_REG32(a)        (*(volatile word32*)(size_t)(a))
#define WC_MPFS_SUBBLK_CLOCK_CR WC_MPFS_REG32(WC_MPFS_ATHENA_SYSREG_BASE + 0x84)
#define WC_MPFS_SOFT_RESET_CR   WC_MPFS_REG32(WC_MPFS_ATHENA_SYSREG_BASE + 0x88)
#define WC_MPFS_PERIPH_ATHENA   (1UL << 28)

#define WC_MPFS_ATHENA_CR       WC_MPFS_REG32(WC_MPFS_ATHENA_REG_BASE + 0x00)
#define WC_MPFS_ATHENA_STALL_CR WC_MPFS_REG32(WC_MPFS_ATHENA_REG_BASE + 0x04)
#define WC_MPFS_ATHENA_RESET      0x01u
#define WC_MPFS_ATHENA_RINGOSCON  0x08u
#define WC_MPFS_ATHENA_STALL_EN   0x10u

/* A CAL update must not be able to overflow the opaque context quietly. */
typedef char wc_mpfs_athena_ctx_sz_check[
    ((int)(WC_MPFS_ATHENA_CTX_WORDS * sizeof(word32)) >=
        (int)sizeof(SATRESCONTEXT)) ? 1 : -1];

/* Raw SATR of the last failed CAL call; diagnostic only. */
static int mpfsAthenaCalRc;

/* Callback entries served: a passing digest alone does not prove offload. */
static word32 mpfsAthenaCbCalls;

/* One-shot: resetting the core after CALIni() kills AES. */
static int mpfsAthenaReady;

word32 wc_MpfsAthena_GetCbCount(void)
{
    return mpfsAthenaCbCalls;
}

/* Under the engine mutex, so it cannot tear against an offload. */
static void wc_MpfsAthenaCountCall(void)
{
    if (wolfSSL_CryptHwMutexLock() == 0) {
        mpfsAthenaCbCalls++;
        wolfSSL_CryptHwMutexUnLock();
    }
}

/* Ungate, un-reset, then CALIni(), once: a reset after CALIni() leaves AES
 * silently dead. Stall seed from rdcycle, as mcycle traps in S-mode. */
static int wc_MpfsAthenaHwInit(void)
{
    SATR rc;
#ifndef WC_MPFS_ATHENA_NO_HW_INIT
    word64 cyc;
#endif

#ifndef WC_MPFS_ATHENA_NO_HW_INIT
    WC_MPFS_SUBBLK_CLOCK_CR |= (word32)WC_MPFS_PERIPH_ATHENA;
    WC_MPFS_SOFT_RESET_CR &= ~(word32)WC_MPFS_PERIPH_ATHENA;
#ifdef __riscv
    __asm__ volatile("rdcycle %0" : "=r"(cyc));
#else
    cyc = 0;
#endif
    WC_MPFS_ATHENA_STALL_CR = (word32)(cyc ^ (cyc >> 32));
    WC_MPFS_ATHENA_CR = WC_MPFS_ATHENA_RESET | WC_MPFS_ATHENA_RINGOSCON;
    WC_MPFS_ATHENA_CR = WC_MPFS_ATHENA_RINGOSCON | WC_MPFS_ATHENA_STALL_EN;
#endif

    rc = CALIni();
    if (rc != SATR_SUCCESS) {
        mpfsAthenaCalRc = (int)rc;
        WOLFSSL_MSG("MPFS Athena: CALIni failed");
        return WC_HW_E;
    }
    return 0;
}

int wc_MpfsAthena_Init(void)
{
    int ret;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }

    if (!mpfsAthenaReady) {
        ret = wc_MpfsAthenaHwInit();
        if (ret == 0) {
            mpfsAthenaReady = 1;
        }
    }

    wolfSSL_CryptHwMutexUnLock();
    return ret;
}

/* Records a failed CAL result and releases the engine mutex. Every CAL
 * transaction runs under it: CAL has one resource handle. */
static SATR wc_MpfsAthenaUnlock(SATR rc)
{
    if (rc != SATR_SUCCESS) {
        mpfsAthenaCalRc = (int)rc;
    }
    wolfSSL_CryptHwMutexUnLock();
    return rc;
}

#if !defined(NO_SHA256) && !defined(WC_MPFS_ATHENA_NO_SHA256)
    #define WC_MPFS_ATHENA_SHA256
#endif
#if defined(WOLFSSL_SHA512) && !defined(WC_MPFS_ATHENA_NO_SHA512)
    #define WC_MPFS_ATHENA_SHA512
#endif
/* Objects of these types are a struct wc_Sha512. */
#if defined(WOLFSSL_SHA384) || defined(WC_MPFS_ATHENA_SHA512)
    #define WC_MPFS_ATHENA_SHA512_FAMILY
#endif
#if defined(WC_MPFS_ATHENA_SHA256) || defined(WC_MPFS_ATHENA_SHA512_FAMILY)
    #define WC_MPFS_ATHENA_HASH
#endif

/* CUSTOM_RAND_GENERATE_BLOCK replaces wolfCrypt's DRBG and its seed whole. */
#if !defined(WC_NO_RNG) && defined(HAVE_HASHDRBG) && \
    !defined(CUSTOM_RAND_GENERATE_BLOCK) && !defined(WC_MPFS_ATHENA_NO_RNG)
    #define WC_MPFS_ATHENA_RNG
#elif defined(WC_MPFS_ATHENA_RNG_DRBG)
    #error "WC_MPFS_ATHENA_RNG_DRBG needs the RNG offload and HAVE_HASHDRBG"
#endif

#if defined(HAVE_ECC) && !defined(WC_MPFS_ATHENA_NO_ECC) && \
    !defined(NO_ECC_SECP)
    #define WC_MPFS_ATHENA_ECC
    /* The same curve gates ecc.c applies to its own tables. */
    #if (defined(HAVE_ECC192) || defined(HAVE_ALL_CURVES)) && \
        ECC_MIN_KEY_SZ <= 192
        #define WC_MPFS_ATHENA_P192
    #endif
    #if (defined(HAVE_ECC224) || defined(HAVE_ALL_CURVES)) && \
        ECC_MIN_KEY_SZ <= 224
        #define WC_MPFS_ATHENA_P224
    #endif
    #if (!defined(NO_ECC256) || defined(HAVE_ALL_CURVES)) && \
        ECC_MIN_KEY_SZ <= 256
        #define WC_MPFS_ATHENA_P256
    #endif
    #if (defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)) && \
        ECC_MIN_KEY_SZ <= 384
        #define WC_MPFS_ATHENA_P384
    #endif
    #if (defined(HAVE_ECC521) || defined(HAVE_ALL_CURVES)) && \
        ECC_MIN_KEY_SZ <= 521
        #define WC_MPFS_ATHENA_P521
    #endif
    #if !defined(WC_MPFS_ATHENA_P192) && !defined(WC_MPFS_ATHENA_P224) && \
        !defined(WC_MPFS_ATHENA_P256) && !defined(WC_MPFS_ATHENA_P384) && \
        !defined(WC_MPFS_ATHENA_P521)
        #undef WC_MPFS_ATHENA_ECC
    #endif
    #ifdef BIG_ENDIAN_ORDER
        #error "WOLFSSL_MPFS_ATHENA ECC operands assume a little-endian core"
    #endif
#endif

#if !defined(NO_RSA) && !defined(WC_MPFS_ATHENA_NO_RSA)
    #define WC_MPFS_ATHENA_RSA
    #ifdef BIG_ENDIAN_ORDER
        #error "WOLFSSL_MPFS_ATHENA RSA operands assume a little-endian core"
    #endif
#endif

#ifndef NO_AES
    #if defined(HAVE_AES_CBC) && !defined(WC_MPFS_ATHENA_NO_CBC)
        #define WC_MPFS_ATHENA_CBC
    #endif
    #if defined(HAVE_AESGCM) && !defined(WC_MPFS_ATHENA_NO_GCM)
        #define WC_MPFS_ATHENA_GCM
    #endif
    #if defined(HAVE_AES_KEYWRAP) && !defined(WC_MPFS_ATHENA_NO_KEYWRAP)
        #define WC_MPFS_ATHENA_KEYWRAP
    #endif
    #if defined(WOLFSSL_CMAC) && !defined(WC_MPFS_ATHENA_NO_CMAC)
        #define WC_MPFS_ATHENA_CMAC
    #endif
    #if defined(WOLFSSL_AES_COUNTER) || defined(HAVE_AES_ECB) || \
        defined(WC_MPFS_ATHENA_CBC) || defined(WC_MPFS_ATHENA_GCM) || \
        defined(WC_MPFS_ATHENA_KEYWRAP)
        #define WC_MPFS_ATHENA_CIPHER
    #endif
#endif /* !NO_AES */

#ifdef WC_MPFS_ATHENA_HASH
/* SHA-512's, the largest digest the engine produces. */
#define WC_MPFS_ATHENA_MAX_DIGEST_SZ 64

static int wc_MpfsAthenaShaIni(word32* calCtx, SATHASHTYPE type)
{
    int ret = wolfSSL_CryptHwMutexLock();

    if (ret == 0 && wc_MpfsAthenaUnlock(CALHashCtxIni(
            (SATRESCONTEXTPTR)calCtx, type)) != SATR_SUCCESS) {
        ret = WC_HW_E;
    }
    return ret;
}

/* inSz must be whole blocks unless last is set, when any length works and the
 * engine pads. The state lives in calCtx, so contexts interleave. */
static int wc_MpfsAthenaSha(word32* calCtx, const byte* in, word32 inSz,
    byte* digest, int last)
{
    int ret = wolfSSL_CryptHwMutexLock();

    if (ret == 0 && wc_MpfsAthenaUnlock(CALHashCtx((SATRESHANDLE)0,
            (SATRESCONTEXTPTR)calCtx, in, (SATUINT32_t)inSz, digest,
            last ? SAT_TRUE : SAT_FALSE)) != SATR_SUCCESS) {
        ret = WC_HW_E;
    }
    return ret;
}
#endif /* WC_MPFS_ATHENA_HASH */

#ifdef WC_MPFS_ATHENA_CIPHER
#define MPFS_ATHENA_ROUND_UP(x, n) (((x) + (n) - 1) & ~(word32)((n) - 1))

/* The engine type for a key of keylen bytes, or SATSYMTYPE_NULL. */
static SATSYMTYPE wc_MpfsAthenaAesType(word32 keylen)
{
    switch (keylen) {
        case AES_128_KEY_SIZE:
            return SATSYMTYPE_AES128;
        case AES_192_KEY_SIZE:
            return SATSYMTYPE_AES192;
        case AES_256_KEY_SIZE:
            return SATSYMTYPE_AES256;
        default:
            return SATSYMTYPE_NULL;
    }
}

static SATSYMTYPE wc_MpfsAthenaAesArgs(const Aes* aes, const void* in,
    const void* out)
{
    if (aes == NULL || in == NULL || out == NULL) {
        return SATSYMTYPE_NULL;
    }
    return wc_MpfsAthenaAesType((word32)aes->keylen);
}

/* Completes the transfer the previous call started. It polls with no check
 * that one is pending, so it must follow only calls that start one. */
static SATR wc_MpfsAthenaSymWait(void)
{
    SATR rc = CALSymTrfRes(SAT_TRUE);

    return (rc == SATR_NOPEND) ? SATR_SUCCESS : rc;
}
#endif /* WC_MPFS_ATHENA_CIPHER */

#if !defined(NO_AES) && (defined(WOLFSSL_AES_COUNTER) || \
    defined(HAVE_AES_ECB) || defined(WC_MPFS_ATHENA_CBC))
/* One ECB, CBC or CTR transfer of whole blocks. iv, when given, is the
 * engine's working copy and is advanced in place. */
static int wc_MpfsAthenaSymRun(SATSYMTYPE type, const word32* key,
    SATSYMMODE mode, byte* iv, const byte* in, byte* out, word32 sz, int enc)
{
    SATBOOL ivSet = (iv != NULL) ? SAT_TRUE : SAT_FALSE;
    SATR rc;
    int ret = wolfSSL_CryptHwMutexLock();

    if (ret != 0) {
        return ret;
    }
    if (enc) {
        rc = CALSymEncrypt(type, (const SATUINT32_t*)key, mode, iv, ivSet, in,
            out, (SATUINT32_t)sz);
    }
    else {
        rc = CALSymDecrypt(type, (const SATUINT32_t*)key, mode, iv, ivSet, in,
            out, (SATUINT32_t)sz);
    }
    if (rc == SATR_SUCCESS) {
        rc = wc_MpfsAthenaSymWait();
    }
    return (wc_MpfsAthenaUnlock(rc) == SATR_SUCCESS) ? 0 : WC_HW_E;
}
#endif

#ifdef WC_MPFS_ATHENA_HASH

/* Hangs on the hash object's devCtx, owned by the free and copy events. part[]
 * holds a SHA-512 block, two SHA-256 blocks, so chunks are whole for both. */

typedef struct MpfsAthenaShaCtx {
    word32 calCtx[WC_MPFS_ATHENA_CTX_WORDS]; /* opaque SATRESCONTEXT */
    byte   part[WC_MPFS_ATHENA_BLOCK_SZ];    /* short of a block, held over */
    word32 partLen;
    word32 digestSz;
} MpfsAthenaShaCtx;

#if defined(WOLFSSL_NO_MALLOC) || defined(WOLFSSL_STATIC_MEMORY)
    #define WC_MPFS_ATHENA_SHA_POOL
#endif

#ifdef WC_MPFS_ATHENA_SHA_POOL
/* No heap on the first targets, so contexts come from a fixed pool; hashing
 * falls back to software once it is empty. */
static MpfsAthenaShaCtx mpfsAthenaShaPool[WC_MPFS_ATHENA_HASH_SLOTS];
static byte mpfsAthenaShaPoolUsed[WC_MPFS_ATHENA_HASH_SLOTS];
#endif

/* NULL when none is free; only ever a reason to decline a first call. */
static MpfsAthenaShaCtx* wc_MpfsAthenaShaNew(void* heap)
{
#ifdef WC_MPFS_ATHENA_SHA_POOL
    MpfsAthenaShaCtx* ctx = NULL;
    int i;

    (void)heap;

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return NULL;
    }
    for (i = 0; i < WC_MPFS_ATHENA_HASH_SLOTS; i++) {
        if (mpfsAthenaShaPoolUsed[i] == 0) {
            mpfsAthenaShaPoolUsed[i] = 1;
            ctx = &mpfsAthenaShaPool[i];
            break;
        }
    }
    wolfSSL_CryptHwMutexUnLock();

    if (ctx != NULL) {
        XMEMSET(ctx, 0, sizeof(*ctx));
    }
    return ctx;
#else
    MpfsAthenaShaCtx* ctx = (MpfsAthenaShaCtx*)XMALLOC(sizeof(*ctx), heap,
        DYNAMIC_TYPE_TMP_BUFFER);

    if (ctx != NULL) {
        XMEMSET(ctx, 0, sizeof(*ctx));
    }
    return ctx;
#endif
}

/* Holds message bytes and running state, so it is zeroed, not just freed. */
static void wc_MpfsAthenaShaFree(MpfsAthenaShaCtx* ctx, void* heap)
{
#ifdef WC_MPFS_ATHENA_SHA_POOL
    int i;

    (void)heap;

    if (ctx == NULL) {
        return;
    }
    ForceZero(ctx, sizeof(*ctx));
    /* Cannot fail once registration succeeded; clearing the flag unlocked
     * would race wc_MpfsAthenaShaNew(). */
    if (wolfSSL_CryptHwMutexLock() != 0) {
        WOLFSSL_MSG("MPFS Athena: hardware mutex failed; hash slot retained");
        return;
    }
    for (i = 0; i < WC_MPFS_ATHENA_HASH_SLOTS; i++) {
        if (&mpfsAthenaShaPool[i] == ctx) {
            mpfsAthenaShaPoolUsed[i] = 0;
            break;
        }
    }
    wolfSSL_CryptHwMutexUnLock();
#else
    if (ctx == NULL) {
        return;
    }
    ForceZero(ctx, sizeof(*ctx));
    XFREE(ctx, heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
}

/* Push whole blocks; retain any short tail for the next call or the final. */
static int wc_MpfsAthenaShaFeed(MpfsAthenaShaCtx* ctx, const byte* in,
    word32 inSz)
{
    word32 take;
    int ret;

    if (ctx->partLen > 0) {
        take = WC_MPFS_ATHENA_BLOCK_SZ - ctx->partLen;
        if (take > inSz) {
            take = inSz;
        }
        XMEMCPY(&ctx->part[ctx->partLen], in, take);
        ctx->partLen += take;
        in += take;
        inSz -= take;
        if (ctx->partLen < WC_MPFS_ATHENA_BLOCK_SZ) {
            return 0;               /* still short of a block */
        }
        ret = wc_MpfsAthenaSha(ctx->calCtx, ctx->part,
            WC_MPFS_ATHENA_BLOCK_SZ, NULL, 0);
        if (ret != 0) {
            return ret;
        }
        ctx->partLen = 0;
    }

    take = inSz - (inSz % WC_MPFS_ATHENA_BLOCK_SZ);
    if (take > 0) {
        /* straight from the caller's buffer, no copy */
        ret = wc_MpfsAthenaSha(ctx->calCtx, in, take, NULL, 0);
        if (ret != 0) {
            return ret;
        }
        in += take;
        inSz -= take;
    }

    if (inSz > 0) {
        XMEMCPY(ctx->part, in, inSz);
        ctx->partLen = inSz;
    }
    return 0;
}

/* The variant comes from the IV still in digest[]: every SHA-512 family update
 * arrives as WC_HASH_TYPE_SHA512, and the IV is valid until software feeds. */
typedef struct MpfsAthenaShaObj {
    void**      devCtx;
    void*       heap;
    SATHASHTYPE type;
    word32      digestSz;   /* 0 when the variant is not served here */
    int         fed;        /* software has already absorbed input */
} MpfsAthenaShaObj;

#ifdef WC_MPFS_ATHENA_SHA256
static void wc_MpfsAthenaSha256Obj(wc_Sha256* sha, MpfsAthenaShaObj* obj)
{
    obj->devCtx = &sha->devCtx;
    obj->heap = sha->heap;
    obj->fed = (sha->buffLen != 0 || sha->loLen != 0 || sha->hiLen != 0);
    if (sha->digest[0] == 0x6A09E667UL) {
        obj->type = SATHASHTYPE_SHA256;
        obj->digestSz = WC_SHA256_DIGEST_SIZE;
    }
#ifdef WOLFSSL_SHA224
    else if (sha->digest[0] == 0xC1059ED8UL) {
        obj->type = SATHASHTYPE_SHA224;
        obj->digestSz = WC_SHA224_DIGEST_SIZE;
    }
#endif
}
#endif /* WC_MPFS_ATHENA_SHA256 */

#ifdef WC_MPFS_ATHENA_SHA512_FAMILY
static void wc_MpfsAthenaSha512Obj(wc_Sha512* sha, MpfsAthenaShaObj* obj)
{
    obj->devCtx = &sha->devCtx;
    obj->heap = sha->heap;
    obj->fed = (sha->buffLen != 0 || sha->loLen != 0 || sha->hiLen != 0);
#ifdef WOLFSSL_SHA384
    if (sha->digest[0] == W64LIT(0xcbbb9d5dc1059ed8)) {
        obj->type = SATHASHTYPE_SHA384;
        obj->digestSz = WC_SHA384_DIGEST_SIZE;
    }
#endif
#ifdef WC_MPFS_ATHENA_SHA512
    if (sha->digest[0] == W64LIT(0x6a09e667f3bcc908)) {
        obj->type = SATHASHTYPE_SHA512;
        obj->digestSz = WC_SHA512_DIGEST_SIZE;
    }
  #ifndef WOLFSSL_NOSHA512_224
    if (sha->digest[0] == W64LIT(0x8c3d37c819544da2)) {
        obj->type = SATHASHTYPE_SHA512_224;
        obj->digestSz = WC_SHA512_224_DIGEST_SIZE;
    }
  #endif
  #ifndef WOLFSSL_NOSHA512_256
    if (sha->digest[0] == W64LIT(0x22312194fc2bf72c)) {
        obj->type = SATHASHTYPE_SHA512_256;
        obj->digestSz = WC_SHA512_256_DIGEST_SIZE;
    }
  #endif
#endif /* WC_MPFS_ATHENA_SHA512 */
}
#endif /* WC_MPFS_ATHENA_SHA512_FAMILY */

/* The object a hash, free or copy event refers to, viewed by its family. */
static int wc_MpfsAthenaShaObjOf(int hashType, void* sha, MpfsAthenaShaObj* obj)
{
    XMEMSET(obj, 0, sizeof(*obj));
    if (sha == NULL) {
        return BAD_FUNC_ARG;
    }
    switch (hashType) {
#ifdef WC_MPFS_ATHENA_SHA256
    #ifdef WOLFSSL_SHA224
        case WC_HASH_TYPE_SHA224:
    #endif
        case WC_HASH_TYPE_SHA256:
            wc_MpfsAthenaSha256Obj((wc_Sha256*)sha, obj);
            return 0;
#endif
#ifdef WC_MPFS_ATHENA_SHA512_FAMILY
    #ifdef WOLFSSL_SHA384
        case WC_HASH_TYPE_SHA384:
    #endif
    #ifdef WC_MPFS_ATHENA_SHA512
        case WC_HASH_TYPE_SHA512:
        #ifndef WOLFSSL_NOSHA512_224
        case WC_HASH_TYPE_SHA512_224:
        #endif
        #ifndef WOLFSSL_NOSHA512_256
        case WC_HASH_TYPE_SHA512_256:
        #endif
    #endif
            wc_MpfsAthenaSha512Obj((wc_Sha512*)sha, obj);
            return 0;
#endif
        default:
            return BAD_FUNC_ARG;
    }
}

/* info->hash is a union only with HAVE_ANONYMOUS_INLINE_AGGREGATES, so the
 * member is chosen by type rather than read through any one of them. */
static void* wc_MpfsAthenaShaOfEvent(const wc_CryptoInfo* info)
{
    switch (info->hash.type) {
#ifdef WC_MPFS_ATHENA_SHA256
    #ifdef WOLFSSL_SHA224
        case WC_HASH_TYPE_SHA224:
            return info->hash.sha224;
    #endif
        case WC_HASH_TYPE_SHA256:
            return info->hash.sha256;
#endif
#ifdef WOLFSSL_SHA384
        case WC_HASH_TYPE_SHA384:
            return info->hash.sha384;
#endif
#ifdef WOLFSSL_SHA512
        case WC_HASH_TYPE_SHA512:
    #ifndef WOLFSSL_NOSHA512_224
        case WC_HASH_TYPE_SHA512_224:
    #endif
    #ifndef WOLFSSL_NOSHA512_256
        case WC_HASH_TYPE_SHA512_256:
    #endif
            return info->hash.sha512;
#endif
        default:
            return NULL;
    }
}

/* Final into a whole SHA-512 digest and copy out only this variant's length:
 * the caller's buffer may be as short as a SHA-224 digest. */
static int wc_MpfsAthenaShaFinal(MpfsAthenaShaCtx* ctx, const byte* in,
    word32 inSz, byte* digest)
{
    word64 out[WC_MPFS_ATHENA_MAX_DIGEST_SZ / sizeof(word64)];
    int ret;

    ret = wc_MpfsAthenaSha(ctx->calCtx, in, inSz, (byte*)out, 1);
    if (ret == 0) {
        XMEMCPY(digest, out, ctx->digestSz);
    }
    ForceZero(out, sizeof(out));
    return ret;
}

/* Update and final. Declining is safe only before data reaches the engine;
 * after that a software fallback would be wrong, so failures are WC_HW_E. */
static int wc_MpfsAthenaShaDev(wc_CryptoInfo* info)
{
    MpfsAthenaShaObj obj;
    MpfsAthenaShaCtx* ctx;
    int ret;

    if (wc_MpfsAthenaShaObjOf(info->hash.type, wc_MpfsAthenaShaOfEvent(info),
            &obj) != 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    ctx = (MpfsAthenaShaCtx*)*obj.devCtx;

    /* The empty message, on a borrowed context; software state is untouched,
     * so declining stays correct if the engine refuses it. */
    if (ctx == NULL && info->hash.digest != NULL &&
            (info->hash.in == NULL || info->hash.inSz == 0) && !obj.fed) {
        if (obj.digestSz == 0) {
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
        ret = WC_HW_E;
        ctx = wc_MpfsAthenaShaNew(obj.heap);
        if (ctx != NULL) {
            ctx->digestSz = obj.digestSz;
            ret = wc_MpfsAthenaShaIni(ctx->calCtx, obj.type);
            if (ret == 0) {
                ret = wc_MpfsAthenaShaFinal(ctx, NULL, 0, info->hash.digest);
            }
            wc_MpfsAthenaShaFree(ctx, obj.heap);
        }
        if (ret != 0) {
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
        wc_MpfsAthenaCountCall();
        return 0;
    }

    if (ctx == NULL) {
        /* Adopt only an unfed object, so one decline sticks: otherwise the
         * next call would look like a first call and hash only the rest. */
        if (obj.fed || obj.digestSz == 0) {
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
        /* The only point at which declining cannot produce a wrong answer. */
        ctx = wc_MpfsAthenaShaNew(obj.heap);
        if (ctx == NULL) {
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
        ctx->digestSz = obj.digestSz;
        ret = wc_MpfsAthenaShaIni(ctx->calCtx, obj.type);
        if (ret != 0) {
            wc_MpfsAthenaShaFree(ctx, obj.heap);
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
        *obj.devCtx = ctx;
    }

    if (info->hash.in != NULL && info->hash.inSz > 0) {
        ret = wc_MpfsAthenaShaFeed(ctx, info->hash.in, info->hash.inSz);
        if (ret != 0) {
            wc_MpfsAthenaShaFree(ctx, obj.heap);
            *obj.devCtx = NULL;
            return ret;
        }
    }

    wc_MpfsAthenaCountCall();

    if (info->hash.digest != NULL) {
        /* Send whatever is left, any length including zero, and let the engine
         * pad. There is no software finalisation. */
        ret = wc_MpfsAthenaShaFinal(ctx, ctx->part, ctx->partLen,
            info->hash.digest);
        wc_MpfsAthenaShaFree(ctx, obj.heap);
        *obj.devCtx = NULL;
        if (ret != 0) {
            return ret;
        }
    }

    return 0;
}

/* Releases the engine context, then declines so the wolfCrypt Free() still
 * zeroes the object and frees its small-stack cache. */
static int wc_MpfsAthenaShaFreeDev(wc_CryptoInfo* info)
{
    MpfsAthenaShaObj obj;

    if (wc_MpfsAthenaShaObjOf(info->free.type, info->free.obj, &obj) == 0 &&
            *obj.devCtx != NULL) {
        wc_MpfsAthenaShaFree((MpfsAthenaShaCtx*)*obj.devCtx, obj.heap);
        *obj.devCtx = NULL;
    }
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}

/* Taking a copy means reproducing every fix-up wc_Sha256Copy() and
 * wc_Sha512Copy() make; declining would alias dst's engine context on src's. */

/* SATRESCONTEXT holds no pointers or handles, so a byte copy is a valid second
 * context. NULL only when none is free. */
static MpfsAthenaShaCtx* wc_MpfsAthenaShaDup(const MpfsAthenaShaCtx* src,
    void* heap)
{
    MpfsAthenaShaCtx* dst = wc_MpfsAthenaShaNew(heap);

    if (dst != NULL) {
        XMEMCPY(dst, src, sizeof(*dst));
    }
    return dst;
}

#ifdef WC_MPFS_ATHENA_SHA256
static int wc_MpfsAthenaSha256CopyDev(int type, wc_Sha256* src, wc_Sha256* dst)
{
    MpfsAthenaShaCtx* dstCtx;

#ifdef WOLFSSL_SHA224
    if (type == WC_HASH_TYPE_SHA224) {
        wc_Sha224Free(dst);
    }
    else
#endif
    {
        (void)type;
        wc_Sha256Free(dst);
    }
    XMEMCPY(dst, src, sizeof(wc_Sha256));

    /* Re-own what the copy above aliased onto the source, as wc_Sha256Copy()
     * and wc_Sha224Copy() do. */
#if defined(WOLFSSL_SMALL_STACK_CACHE) && !defined(WC_SHA2_NO_SMALL_STACK)
    dst->W = (word32*)XMALLOC(WC_SHA256_TSCRATCH_SIZE, dst->heap,
        DYNAMIC_TYPE_DIGEST);
    if (dst->W == NULL) {
        /* msg still aliases the source here, so it is dropped, not freed. */
        ForceZero(dst, sizeof(wc_Sha256));
        return MEMORY_E;
    }
#endif
#ifdef WOLFSSL_HASH_FLAGS
    dst->flags |= WC_HASH_FLAG_ISCOPY;
#endif
#ifdef WOLFSSL_HASH_KEEP
    if (src->msg != NULL) {
        dst->msg = (byte*)XMALLOC(src->len, dst->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (dst->msg == NULL) {
#if defined(WOLFSSL_SMALL_STACK_CACHE) && !defined(WC_SHA2_NO_SMALL_STACK)
            XFREE(dst->W, dst->heap, DYNAMIC_TYPE_DIGEST);
#endif
            ForceZero(dst, sizeof(wc_Sha256));
            return MEMORY_E;
        }
        XMEMCPY(dst->msg, src->msg, src->len);
    }
#endif

    dstCtx = wc_MpfsAthenaShaDup((MpfsAthenaShaCtx*)src->devCtx, dst->heap);
    if (dstCtx == NULL) {
        /* The wolfCrypt Copy() hands a failure straight back to its caller
         * without freeing dst, so this handler owns what it allocated above. */
#if defined(WOLFSSL_SMALL_STACK_CACHE) && !defined(WC_SHA2_NO_SMALL_STACK)
        XFREE(dst->W, dst->heap, DYNAMIC_TYPE_DIGEST);
#endif
#ifdef WOLFSSL_HASH_KEEP
        if (dst->msg != NULL) {
            ForceZero(dst->msg, src->len);
        }
        XFREE(dst->msg, dst->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        ForceZero(dst, sizeof(wc_Sha256));
        return MEMORY_E;
    }
    dst->devCtx = dstCtx;
    return 0;
}
#endif /* WC_MPFS_ATHENA_SHA256 */

#ifdef WC_MPFS_ATHENA_SHA512_FAMILY
static int wc_MpfsAthenaSha512CopyDev(int type, wc_Sha512* src, wc_Sha512* dst)
{
    MpfsAthenaShaCtx* dstCtx;

#ifdef WOLFSSL_SHA384
    if (type == WC_HASH_TYPE_SHA384) {
        wc_Sha384Free(dst);
    }
    else
#endif
    {
        (void)type;
#ifdef WC_MPFS_ATHENA_SHA512
        wc_Sha512Free(dst);
#endif
    }
    XMEMCPY(dst, src, sizeof(wc_Sha512));

    /* Re-own what the copy aliased onto the source, as wc_Sha512Copy() does;
     * W carries a second block-sized buffer. */
#if defined(WOLFSSL_SMALL_STACK_CACHE) && !defined(WC_SHA2_NO_SMALL_STACK)
  #ifdef WC_SHA512_TSCRATCH_SIZE
    dst->W = (word64*)XMALLOC(WC_SHA512_TSCRATCH_SIZE + WC_SHA512_BLOCK_SIZE,
        dst->heap, DYNAMIC_TYPE_DIGEST);
  #else /* old FIPS */
    dst->W = (word64*)XMALLOC((sizeof(word64) * 16) + WC_SHA512_BLOCK_SIZE,
        dst->heap, DYNAMIC_TYPE_DIGEST);
  #endif
    if (dst->W == NULL) {
        /* msg still aliases the source here, so it is dropped, not freed. */
        ForceZero(dst, sizeof(wc_Sha512));
        return MEMORY_E;
    }
#endif
#ifdef WOLFSSL_HASH_FLAGS
    dst->flags |= WC_HASH_FLAG_ISCOPY;
#endif
#ifdef WOLFSSL_HASH_KEEP
    if (src->msg != NULL) {
        dst->msg = (byte*)XMALLOC(src->len, dst->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (dst->msg == NULL) {
            /* Release what this handler already took before dropping the
             * pointers; zeroing dst alone would leak the W buffer above. */
#if defined(WOLFSSL_SMALL_STACK_CACHE) && !defined(WC_SHA2_NO_SMALL_STACK)
            XFREE(dst->W, dst->heap, DYNAMIC_TYPE_DIGEST);
#endif
            ForceZero(dst, sizeof(wc_Sha512));
            return MEMORY_E;
        }
        XMEMCPY(dst->msg, src->msg, src->len);
    }
#endif

    dstCtx = wc_MpfsAthenaShaDup((MpfsAthenaShaCtx*)src->devCtx, dst->heap);
    if (dstCtx == NULL) {
        /* The wolfCrypt Copy() returns a failure without freeing dst, so
         * this handler releases what it allocated. */
#if defined(WOLFSSL_SMALL_STACK_CACHE) && !defined(WC_SHA2_NO_SMALL_STACK)
        XFREE(dst->W, dst->heap, DYNAMIC_TYPE_DIGEST);
#endif
#ifdef WOLFSSL_HASH_KEEP
        if (dst->msg != NULL) {
            ForceZero(dst->msg, src->len);
        }
        XFREE(dst->msg, dst->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        ForceZero(dst, sizeof(wc_Sha512));
        return MEMORY_E;
    }
    dst->devCtx = dstCtx;
    return 0;
}
#endif /* WC_MPFS_ATHENA_SHA512_FAMILY */

static int wc_MpfsAthenaShaCopyDev(wc_CryptoInfo* info)
{
    MpfsAthenaShaObj srcObj;

    if (info->copy.dst == NULL ||
            wc_MpfsAthenaShaObjOf(info->copy.type, info->copy.src,
                &srcObj) != 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    /* Nothing in the engine yet, so the ordinary copy is correct. The common
     * case, and the only one in which declining is safe. */
    if (*srcObj.devCtx == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    switch (info->copy.type) {
#ifdef WC_MPFS_ATHENA_SHA256
    #ifdef WOLFSSL_SHA224
        case WC_HASH_TYPE_SHA224:
    #endif
        case WC_HASH_TYPE_SHA256:
            return wc_MpfsAthenaSha256CopyDev(info->copy.type,
                (wc_Sha256*)info->copy.src, (wc_Sha256*)info->copy.dst);
#endif
#ifdef WC_MPFS_ATHENA_SHA512_FAMILY
        default:
            return wc_MpfsAthenaSha512CopyDev(info->copy.type,
                (wc_Sha512*)info->copy.src, (wc_Sha512*)info->copy.dst);
#else
        default:
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
#endif
    }
}

#endif /* WC_MPFS_ATHENA_HASH */

#if defined(WOLFSSL_AES_COUNTER) && !defined(NO_AES)
/* Big-endian add over the whole counter block, the increment wolfCrypt's own
 * CTR does. */
static void wc_MpfsAthenaCtrAdd(byte* ctr, word32 blocks)
{
    word32 carry = blocks;
    int i;

    for (i = WC_AES_BLOCK_SIZE - 1; i >= 0 && carry != 0; i--) {
        word32 sum = (word32)ctr[i] + (carry & 0xFFU);
        ctr[i] = (byte)sum;
        carry = (carry >> 8) + (sum >> 8);
    }
}

/* AES-CTR both ways, keeping wolfCrypt's keystream state (aes->tmp, left,
 * reg) consistent with the output written so far, even on failure. */
static int wc_MpfsAthenaAesCtrDev(wc_CryptoInfo* info)
{
    Aes* aes = info->cipher.aesctr.aes;
    const byte* in = info->cipher.aesctr.in;
    byte* out = info->cipher.aesctr.out;
    word32 sz = info->cipher.aesctr.sz;
    byte ctr[WC_AES_BLOCK_SIZE];
    SATSYMTYPE type;
    word32 whole;
    word32 processed;
    int ret;

    type = wc_MpfsAthenaAesArgs(aes, in, out);
    if (type == SATSYMTYPE_NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (sz == 0) {
        return 0;
    }

    /* Keystream left from a previous partial block: aes->reg is already past
     * it, so software could not resume from here. */
    if (aes->left > 0) {
        processed = (aes->left < sz) ? aes->left : sz;
        xorbufout(out, in, (byte*)aes->tmp + WC_AES_BLOCK_SIZE - aes->left,
            processed);
        out += processed;
        in += processed;
        aes->left -= processed;
        sz -= processed;
    }

    /* The engine carries only the low 32 bits of the counter: stop each
     * transfer at that wrap and advance all 128 bits here. */
    whole = sz - (sz % WC_AES_BLOCK_SIZE);
    while (whole > 0) {
        word32 run = whole;
        word32 low = ((word32)((byte*)aes->reg)[12] << 24) |
                     ((word32)((byte*)aes->reg)[13] << 16) |
                     ((word32)((byte*)aes->reg)[14] << 8) |
                      (word32)((byte*)aes->reg)[15];
        word32 toWrap = ~low + 1U;  /* blocks left before the low word wraps */

        if (toWrap != 0 && run / WC_AES_BLOCK_SIZE > toWrap) {
            run = toWrap * WC_AES_BLOCK_SIZE;
        }
        XMEMCPY(ctr, aes->reg, WC_AES_BLOCK_SIZE);
        ret = wc_MpfsAthenaSymRun(type, aes->devKey, SATSYMMODE_CTR, ctr, in,
            out, run, 1);
        if (ret != 0) {
            return ret;
        }
        wc_MpfsAthenaCtrAdd((byte*)aes->reg, run / WC_AES_BLOCK_SIZE);
        in += run;
        out += run;
        sz -= run;
        whole -= run;
    }

    if (sz > 0) {
        /* One keystream block, its tail left where wolfCrypt keeps its own,
         * built locally so a failure leaves aes->tmp intact. */
        byte ks[WC_AES_BLOCK_SIZE];

        XMEMSET(ks, 0, sizeof(ks));
        XMEMCPY(ctr, aes->reg, WC_AES_BLOCK_SIZE);
        ret = wc_MpfsAthenaSymRun(type, aes->devKey, SATSYMMODE_CTR, ctr, ks,
            ks, WC_AES_BLOCK_SIZE, 1);
        if (ret != 0) {
            ForceZero(ks, sizeof(ks));
            return ret;
        }
        wc_MpfsAthenaCtrAdd((byte*)aes->reg, 1U);
        xorbufout(out, in, ks, sz);
        XMEMCPY(aes->tmp, ks, WC_AES_BLOCK_SIZE);
        aes->left = WC_AES_BLOCK_SIZE - sz;
        ForceZero(ks, sizeof(ks));
    }

    wc_MpfsAthenaCountCall();
    return 0;
}
#endif /* WOLFSSL_AES_COUNTER && !NO_AES */

#if defined(HAVE_AES_ECB) && !defined(NO_AES)
/* AES-ECB, which also carries AES-XTS: _AesXtsHelper() issues one bulk ECB
 * call per XTS call. */
static int wc_MpfsAthenaAesEcbDev(wc_CryptoInfo* info)
{
    Aes* aes = info->cipher.aesecb.aes;
    const byte* in = info->cipher.aesecb.in;
    byte* out = info->cipher.aesecb.out;
    word32 sz = info->cipher.aesecb.sz;
    SATSYMTYPE type;
    int ret;

    type = wc_MpfsAthenaAesArgs(aes, in, out);
    if (type == SATSYMTYPE_NULL || (sz % WC_AES_BLOCK_SIZE) != 0 ||
            sz < WC_MPFS_ATHENA_AES_MIN_SZ || sz == 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    ret = wc_MpfsAthenaSymRun(type, aes->devKey, SATSYMMODE_ECB, NULL, in, out,
        sz, info->cipher.enc);
    if (ret != 0) {
        return ret;
    }

    wc_MpfsAthenaCountCall();
    return 0;
}
#endif /* HAVE_AES_ECB && !NO_AES */

#ifdef WC_MPFS_ATHENA_CBC
/* Advances aes->reg to the last ciphertext block, saved first on a decrypt
 * since one in place overwrites it. */
static int wc_MpfsAthenaAesCbcDev(wc_CryptoInfo* info)
{
    Aes* aes = info->cipher.aescbc.aes;
    const byte* in = info->cipher.aescbc.in;
    byte* out = info->cipher.aescbc.out;
    word32 sz = info->cipher.aescbc.sz;
    byte iv[WC_AES_BLOCK_SIZE];
    byte next[WC_AES_BLOCK_SIZE];
    SATSYMTYPE type;
    int ret;

    type = wc_MpfsAthenaAesArgs(aes, in, out);
    /* A partial block is left to software, which rejects or ignores it. */
    if (type == SATSYMTYPE_NULL || sz == 0 || (sz % WC_AES_BLOCK_SIZE) != 0 ||
            sz < WC_MPFS_ATHENA_AES_MIN_SZ) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    XMEMCPY(iv, aes->reg, WC_AES_BLOCK_SIZE);
    if (!info->cipher.enc) {
        XMEMCPY(next, in + sz - WC_AES_BLOCK_SIZE, WC_AES_BLOCK_SIZE);
    }
    ret = wc_MpfsAthenaSymRun(type, aes->devKey, SATSYMMODE_CBC, iv, in, out,
        sz, info->cipher.enc);
    if (ret != 0) {
        return ret;
    }
    if (info->cipher.enc) {
        XMEMCPY(aes->reg, out + sz - WC_AES_BLOCK_SIZE, WC_AES_BLOCK_SIZE);
    }
    else {
        XMEMCPY(aes->reg, next, WC_AES_BLOCK_SIZE);
    }

    wc_MpfsAthenaCountCall();
    return 0;
}
#endif /* WC_MPFS_ATHENA_CBC */

#ifdef WC_MPFS_ATHENA_GCM
/* CAL reads AAD and input and writes output in whole blocks, so other lengths
 * go through a padded copy: on the stack when short, as a TLS AAD is. */
#define MPFS_ATHENA_GCM_STACK_SZ 64

/* One-shot GCM with a 96-bit IV, both directions. Declines when nothing was
 * transferred, so software can redo the call from untouched inputs. */
static int wc_MpfsAthenaAesGcm(SATSYMTYPE type, const word32* key,
    const byte* iv, const byte* in, byte* out, word32 sz, const byte* aad,
    word32 aadSz, byte* tag, word32 tagSz, int enc, void* heap)
{
    byte j0[WC_AES_BLOCK_SIZE];
    byte aadBuf[MPFS_ATHENA_GCM_STACK_SZ];
    byte dataBuf[2 * MPFS_ATHENA_GCM_STACK_SZ];
    byte* bounce = NULL;
    byte* calIn = (byte*)(wc_ptr_t)in;
    byte* calOut = out;
    byte* calAad = (byte*)(wc_ptr_t)aad;
    word32 szPad = MPFS_ATHENA_ROUND_UP(sz, WC_AES_BLOCK_SIZE);
    word32 aadPad = MPFS_ATHENA_ROUND_UP(aadSz, WC_AES_BLOCK_SIZE);
    word32 bounceSz = 0;
    int started = 0;
    SATR rc = SATR_FAIL;
    int ret;

    /* Keeps 2 * szPad + aadPad below 2^32. */
    if (sz > 0x3FFFFFF0U || aadSz > 0x3FFFFFF0U) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (szPad != sz && szPad > MPFS_ATHENA_GCM_STACK_SZ) {
        bounceSz += 2 * szPad;
    }
    if (aadPad != aadSz && aadPad > MPFS_ATHENA_GCM_STACK_SZ) {
        bounceSz += aadPad;
    }
    if (bounceSz != 0) {
        bounce = (byte*)XMALLOC(bounceSz, heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (bounce == NULL) {
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
        XMEMSET(bounce, 0, bounceSz);
    }
    if (szPad != sz) {
        calIn = (szPad > MPFS_ATHENA_GCM_STACK_SZ) ? bounce : dataBuf;
        calOut = calIn + szPad;
        XMEMSET(calIn + sz, 0, szPad - sz);
        XMEMCPY(calIn, in, sz);
    }
    if (aadPad != aadSz) {
        calAad = (aadPad > MPFS_ATHENA_GCM_STACK_SZ) ?
            bounce + bounceSz - aadPad : aadBuf;
        XMEMSET(calAad + aadSz, 0, aadPad - aadSz);
        XMEMCPY(calAad, aad, aadSz);
    }
    /* J0 = IV || 0x00000001; CAL rewrites it, so it is a local copy. */
    XMEMSET(j0, 0, sizeof(j0));
    XMEMCPY(j0, iv, GCM_NONCE_MID_SZ);
    j0[WC_AES_BLOCK_SIZE - 1] = 1;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        if (enc) {
            rc = CALSymEncAuth(type, (const SATUINT32_t*)key, SATSYMMODE_GCM,
                j0, calIn, calOut, (SATUINT32_t)sz, calAad,
                (SATUINT32_t)aadSz, tag, (SATUINT32_t)tagSz);
        }
        else {
            rc = CALSymDecVerify(type, (const SATUINT32_t*)key,
                SATSYMMODE_GCM, j0, calIn, calOut, (SATUINT32_t)sz, calAad,
                (SATUINT32_t)aadSz, tag, (SATUINT32_t)tagSz);
        }
        started = (rc == SATR_SUCCESS);
        if (started) {
            rc = wc_MpfsAthenaSymWait();
        }
        rc = wc_MpfsAthenaUnlock(rc);
    }

    if (calOut != out) {
        if (rc == SATR_SUCCESS) {
            XMEMCPY(out, calOut, sz);
        }
        ForceZero(calIn, 2 * szPad);
    }
    if (bounce != NULL) {
        ForceZero(bounce, bounceSz);
        XFREE(bounce, heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (ret != 0) {
        return ret;
    }
    if (rc == SATR_SUCCESS) {
        return 0;
    }
    if (!enc && rc == SATR_VERIFYFAIL) {
        return AES_GCM_AUTH_E;
    }
    if (!started) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    return WC_HW_E;
}

/* The encrypt and decrypt events carry the same fields. */
#define MPFS_ATHENA_GCM_ARGS(f)                     \
    aes = info->cipher.f.aes;                       \
    in = info->cipher.f.in;                         \
    out = info->cipher.f.out;                       \
    sz = info->cipher.f.sz;                         \
    iv = info->cipher.f.iv;                         \
    ivSz = info->cipher.f.ivSz;                     \
    aad = info->cipher.f.authIn;                    \
    aadSz = info->cipher.f.authInSz;                \
    tagSz = info->cipher.f.authTagSz

static int wc_MpfsAthenaAesGcmDev(wc_CryptoInfo* info)
{
    byte tag[WC_AES_BLOCK_SIZE];
    Aes* aes;
    const byte* in;
    byte* out;
    word32 sz;
    const byte* iv;
    word32 ivSz;
    const byte* aad;
    word32 aadSz;
    word32 tagSz;
    SATSYMTYPE type;
    int enc = info->cipher.enc;
    int ret;

    if (enc) {
        MPFS_ATHENA_GCM_ARGS(aesgcm_enc);
    }
    else {
        MPFS_ATHENA_GCM_ARGS(aesgcm_dec);
    }

    if (aes == NULL || iv == NULL || ivSz != GCM_NONCE_MID_SZ ||
            tagSz == 0 || tagSz > sizeof(tag)) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
#if WC_MPFS_ATHENA_GCM_MIN_SZ > 0
    if (sz < WC_MPFS_ATHENA_GCM_MIN_SZ) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
#endif
    type = wc_MpfsAthenaAesType((word32)aes->keylen);
    if (type == SATSYMTYPE_NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    if (!enc) {
        XMEMCPY(tag, info->cipher.aesgcm_dec.authTag, tagSz);
    }
    ret = wc_MpfsAthenaAesGcm(type, aes->devKey, iv, in, out, sz, aad, aadSz,
        tag, tagSz, enc, aes->heap);
    if (ret == WC_NO_ERR_TRACE(AES_GCM_AUTH_E) && sz > 0) {
        ForceZero(out, sz);
    }
    if (ret == 0) {
        if (enc) {
            XMEMCPY(info->cipher.aesgcm_enc.authTag, tag, tagSz);
        }
        wc_MpfsAthenaCountCall();
    }
    return ret;
}
#endif /* WC_MPFS_ATHENA_GCM */

#ifdef WC_MPFS_ATHENA_KEYWRAP
/* CAL's limits: 2..501 semiblocks (RFC 3394), 1..501 bytes (RFC 5649). */
#define MPFS_ATHENA_KW_MAX_BLOCKS 501U
#define MPFS_ATHENA_KWP_MAX_SZ    501U

/* RFC 3394 both ways and RFC 5649 wrap. CAL's bWrap is inverted, its length
 * is the plaintext's, and an unwrap writes the IV ahead of the key. */
static int wc_MpfsAthenaAesKeyWrapDev(wc_CryptoInfo* info)
{
    Aes* aes = info->cipher.aeskeywrap.aes;
    const byte* in = info->cipher.aeskeywrap.in;
    word32 inSz = info->cipher.aeskeywrap.inSz;
    byte* out = info->cipher.aeskeywrap.out;
    int pad = info->cipher.aeskeywrap.pad;
    int enc = info->cipher.enc;
    word32 resSz;
    word32 calSz;
    word32 len;
    SATSYMTYPE type;
    int started;
    SATR rc;
    int ret;

    if (aes == NULL || in == NULL || out == NULL ||
            info->cipher.aeskeywrap.iv != NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    type = wc_MpfsAthenaAesType((word32)aes->keylen);
    if (type == SATSYMTYPE_NULL ||
            (((wc_ptr_t)in | (wc_ptr_t)out) % sizeof(word32)) != 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (pad) {
        if (!enc || inSz == 0 || inSz > MPFS_ATHENA_KWP_MAX_SZ ||
                (inSz % sizeof(word32)) != 0) {
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
        len = inSz;
        resSz = MPFS_ATHENA_ROUND_UP(inSz, KEYWRAP_BLOCK_SIZE) +
            KEYWRAP_BLOCK_SIZE;
        calSz = resSz;
    }
    else {
        if ((inSz % KEYWRAP_BLOCK_SIZE) != 0) {
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
        len = inSz / KEYWRAP_BLOCK_SIZE - (enc ? 0U : 1U);
        if (len < 2U || len > MPFS_ATHENA_KW_MAX_BLOCKS) {
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
        resSz = enc ? inSz + KEYWRAP_BLOCK_SIZE : inSz - KEYWRAP_BLOCK_SIZE;
        calSz = enc ? resSz : inSz;
    }
    if (calSz > info->cipher.aeskeywrap.outSz ||
            ((wc_ptr_t)out < (wc_ptr_t)in + inSz &&
             (wc_ptr_t)in < (wc_ptr_t)out + calSz)) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }
    if (pad) {
        rc = CALSymKwp(type, (const SATUINT32_t*)aes->devKey,
            (const SATUINT32_t*)(const void*)in, (SATUINT32_t*)(void*)out,
            (SATUINT32_t)len, SAT_FALSE);
    }
    else {
        rc = CALSymKw(type, (const SATUINT32_t*)aes->devKey,
            (const SATUINT32_t*)(const void*)in, (SATUINT32_t*)(void*)out,
            (SATUINT32_t)len, enc ? SAT_FALSE : SAT_TRUE);
    }
    started = (rc == SATR_SUCCESS);
    if (started) {
        rc = wc_MpfsAthenaSymWait();
    }
    rc = wc_MpfsAthenaUnlock(rc);

    if (rc == SATR_SUCCESS) {
        if (!enc) {
            XMEMMOVE(out, out + KEYWRAP_BLOCK_SIZE, resSz);
            ForceZero(out + resSz, KEYWRAP_BLOCK_SIZE);
        }
        info->cipher.aeskeywrap.outResSz = resSz;
        wc_MpfsAthenaCountCall();
        return 0;
    }
    if (!enc) {
        ForceZero(out, calSz);
        if (rc == SATR_MSBICV1 || rc == SATR_MSBICV2 ||
                rc == SATR_VERIFYFAIL) {
            return BAD_KEYWRAP_IV_E;
        }
    }
    if (!started) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    return WC_HW_E;
}
#endif /* WC_MPFS_ATHENA_KEYWRAP */

#ifdef WC_MPFS_ATHENA_CMAC
/* One-shot wc_AesCmacGenerate_ex() only: CALMAC takes the whole message, so
 * the streaming events decline to software. */
static int wc_MpfsAthenaCmacDev(wc_CryptoInfo* info)
{
    word32 key[AES_256_KEY_SIZE / sizeof(word32)];
    byte mac[WC_AES_BLOCK_SIZE];
    word32 keySz = info->cmac.keySz;
    SATMACTYPE type;
    SATR rc;
    int ret;

    if (info->cmac.type != WC_CMAC_AES || info->cmac.key == NULL ||
            info->cmac.out == NULL || info->cmac.outSz == NULL ||
            (info->cmac.in == NULL && info->cmac.inSz != 0) ||
            *info->cmac.outSz < WC_CMAC_TAG_MIN_SZ ||
            *info->cmac.outSz > WC_AES_BLOCK_SIZE) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    switch (keySz) {
        case AES_128_KEY_SIZE:
            type = SATMACTYPE_AESCMAC128;
            break;
        case AES_192_KEY_SIZE:
            type = SATMACTYPE_AESCMAC192;
            break;
        case AES_256_KEY_SIZE:
            type = SATMACTYPE_AESCMAC256;
            break;
        default:
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    /* CAL reads the key as words; the caller's buffer may not be aligned. */
    XMEMCPY(key, info->cmac.key, keySz);
    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        ForceZero(key, sizeof(key));
        return ret;
    }
    rc = wc_MpfsAthenaUnlock(CALMAC(type, (const SATUINT32_t*)key,
        (SATUINT32_t)keySz, info->cmac.in, (SATUINT32_t)info->cmac.inSz, mac));
    ForceZero(key, sizeof(key));

    if (rc != SATR_SUCCESS) {
        /* Nothing of the caller's was written; software can redo it. */
        ForceZero(mac, sizeof(mac));
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    XMEMCPY(info->cmac.out, mac, *info->cmac.outSz);
    ForceZero(mac, sizeof(mac));
    wc_MpfsAthenaCountCall();
    return 0;
}
#endif /* WC_MPFS_ATHENA_CMAC */

#if (defined(WC_MPFS_ATHENA_RNG) && defined(WC_MPFS_ATHENA_RNG_DRBG)) || \
    defined(WC_MPFS_ATHENA_ECC) || defined(WC_MPFS_ATHENA_RSA)
/* As wc_MpfsAthenaSymWait(), for DRBG generate and public-key transfers. */
static SATR wc_MpfsAthenaPkWait(void)
{
    SATR rc = CALPKTrfRes(SAT_TRUE);

    return (rc == SATR_NOPEND) ? SATR_SUCCESS : rc;
}
#endif

#if (defined(WC_MPFS_ATHENA_ECC) && \
     (defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_DHE))) || \
    (defined(WC_MPFS_ATHENA_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY))
/* Wipes the private operands the engine keeps; synchronous, so not waited on
 * afterwards. */
static SATR wc_MpfsAthenaPkPurge(SATR rc)
{
    SATR purge = CALPurge52(SAT_TRUE);

    return (rc == SATR_SUCCESS) ? purge : rc;
}
#endif

#ifdef WC_MPFS_ATHENA_RNG

/* Words of entropy taken from the NRBG per CAL call. */
#define WC_MPFS_ATHENA_NRBG_WORDS 8

/* Raw NRBG output to seed wolfCrypt's DRBG. A failed health test is an error,
 * not a decline: another seed source would hide a broken entropy source. */
static int wc_MpfsAthenaNrbg(byte* out, word32 sz)
{
    word32 buf[WC_MPFS_ATHENA_NRBG_WORDS];
    word32 take;
    SATR rc = SATR_SUCCESS;
    int ret;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }
    while (sz > 0 && rc == SATR_SUCCESS) {
        if (CALNRBGHealthStatus() != 0) {
            rc = SATR_FAIL;
            break;
        }
        /* Synchronous: a CALPKTrfRes() after it waits forever. */
        rc = CALNRBGGetEntropy((SATUINT32_t*)buf,
            WC_MPFS_ATHENA_NRBG_WORDS, SAT_FALSE);
        if (rc == SATR_SUCCESS) {
            take = (sz < sizeof(buf)) ? sz : (word32)sizeof(buf);
            XMEMCPY(out, buf, take);
            out += take;
            sz -= take;
        }
    }
    rc = wc_MpfsAthenaUnlock(rc);
    ForceZero(buf, sizeof(buf));
    return (rc == SATR_SUCCESS) ? 0 : WC_HW_E;
}

/* The NRBG for wc_GenerateSeed(), which random.c calls directly, so every RNG
 * is seeded from it whatever its devId. */
int wc_MpfsAthena_GenerateSeed(byte* output, word32 sz)
{
    int ret;

    if (output == NULL) {
        return BAD_FUNC_ARG;
    }
    if (sz == 0) {
        return 0;
    }
    ret = wc_MpfsAthena_Init();
    if (ret == 0) {
        ret = wc_MpfsAthenaNrbg(output, sz);
    }
    if (ret == 0) {
        wc_MpfsAthenaCountCall();
    }
    return ret;
}

#ifdef WC_MPFS_ATHENA_RNG_DRBG
/* 128-bit blocks per generate call, the most Microchip's own example asks
 * for at once. */
#define WC_MPFS_ATHENA_DRBG_BLOCKS 8

static int mpfsAthenaDrbgReady;

/* The engine's one DRBG, instantiated on first use, replaces wolfCrypt's for
 * output. Failures decline, so wolfCrypt's DRBG fills the whole buffer. */
static int wc_MpfsAthenaRngDev(wc_CryptoInfo* info)
{
    word32 buf[WC_MPFS_ATHENA_DRBG_BLOCKS * 4];
    word32 nonce[4];
    byte* out = info->rng.out;
    word32 sz = info->rng.sz;
    word32 blocks;
    word32 take;
    SATR rc = SATR_SUCCESS;
    int ret;

    if (out == NULL || sz == 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }
    if (!mpfsAthenaDrbgReady) {
        if (CALNRBGHealthStatus() != 0) {
            rc = SATR_FAIL;
        }
        /* Neither starts a PKX transfer, so neither is waited on. */
        if (rc == SATR_SUCCESS) {
            rc = CALNRBGGetEntropy((SATUINT32_t*)nonce, 4, SAT_FALSE);
        }
        if (rc == SATR_SUCCESS) {
            rc = CALDRBGInstantiate((const SATUINT32_t*)nonce, 4, NULL, 0,
                SATSYMKEYSIZE_AES256, CALDRBGENTROPYFACTOR,
                WC_MPFS_ATHENA_DRBG_RESEED, SAT_FALSE);
        }
        ForceZero(nonce, sizeof(nonce));
        if (rc == SATR_SUCCESS) {
            mpfsAthenaDrbgReady = 1;
        }
    }
    while (rc == SATR_SUCCESS && sz > 0) {
        blocks = (sz / WC_AES_BLOCK_SIZE) +
            (((sz % WC_AES_BLOCK_SIZE) != 0U) ? 1U : 0U);
        if (blocks > WC_MPFS_ATHENA_DRBG_BLOCKS) {
            blocks = WC_MPFS_ATHENA_DRBG_BLOCKS;
        }
        rc = CALDRBGGenerate(NULL, 0, SAT_FALSE, (SATUINT32_t*)buf, blocks);
        if (rc == SATR_SUCCESS) {
            rc = wc_MpfsAthenaPkWait();
        }
        if (rc == SATR_SUCCESS) {
            take = (sz < blocks * WC_AES_BLOCK_SIZE) ? sz :
                blocks * WC_AES_BLOCK_SIZE;
            XMEMCPY(out, buf, take);
            out += take;
            sz -= take;
        }
    }
    rc = wc_MpfsAthenaUnlock(rc);
    ForceZero(buf, sizeof(buf));

    if (rc != SATR_SUCCESS) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    wc_MpfsAthenaCountCall();
    return 0;
}
#endif /* WC_MPFS_ATHENA_RNG_DRBG */
#endif /* WC_MPFS_ATHENA_RNG */

#ifdef WC_MPFS_ATHENA_ECC
#define WC_MPFS_ATHENA_ECC_WORDS ((MAX_ECC_BYTES + 3) / 4)

/* The curve's operands, filled from key->dp on first use. The field prime is
 * CAL's own: it is in the engine's ROM, addressed by mod. */
typedef struct MpfsAthenaCurve {
    word32             bits;   /* of the order */
    const SATUINT32_t* mod;
    word32             bytes;
    word32             words;
    byte               n[MAX_ECC_BYTES];   /* the order, big-endian */
    word32             nOp[WC_MPFS_ATHENA_ECC_WORDS];
    word32             nMu[WC_MPFS_ATHENA_ECC_WORDS + 1];
    word32             gx[WC_MPFS_ATHENA_ECC_WORDS];
    word32             gy[WC_MPFS_ATHENA_ECC_WORDS];
    word32             b[WC_MPFS_ATHENA_ECC_WORDS];
    byte               ready;
} MpfsAthenaCurve;

static const struct {
    int                id;
    word32             bits;
    const SATUINT32_t* mod;
} mpfsAthenaCurveIds[] = {
#ifdef WC_MPFS_ATHENA_P192
    { ECC_SECP192R1, 192, P192_MOD },
#endif
#ifdef WC_MPFS_ATHENA_P224
    { ECC_SECP224R1, 224, P224_MOD },
#endif
#ifdef WC_MPFS_ATHENA_P256
    { ECC_SECP256R1, 256, P256_MOD },
#endif
#ifdef WC_MPFS_ATHENA_P384
    { ECC_SECP384R1, 384, P384_MOD },
#endif
#ifdef WC_MPFS_ATHENA_P521
    { ECC_SECP521R1, 521, P521_MOD },
#endif
};
static MpfsAthenaCurve mpfsAthenaCurves[XELEM_CNT(mpfsAthenaCurveIds)];

/* Operand scratch for one operation, zeroed after use. */
typedef struct MpfsAthenaEccOps {
    word32 e[WC_MPFS_ATHENA_ECC_WORDS];
    word32 k[WC_MPFS_ATHENA_ECC_WORDS];
    word32 d[WC_MPFS_ATHENA_ECC_WORDS];
    word32 x[WC_MPFS_ATHENA_ECC_WORDS];
    word32 y[WC_MPFS_ATHENA_ECC_WORDS];
    word32 r[WC_MPFS_ATHENA_ECC_WORDS];
    word32 s[WC_MPFS_ATHENA_ECC_WORDS];
    byte   be[2][(WC_MPFS_ATHENA_ECC_WORDS * 4) + 1];
} MpfsAthenaEccOps;

/* CAL operands are little-endian words, least significant first: on this
 * core, the big-endian value with its bytes reversed. */
static void wc_MpfsAthenaOpFromBe(word32* op, const byte* be, word32 beLen)
{
    byte* o = (byte*)op;
    word32 i;

    XMEMSET(op, 0, WC_MPFS_ATHENA_ECC_WORDS * sizeof(word32));
    for (i = 0; i < beLen; i++) {
        o[i] = be[beLen - 1 - i];
    }
}

/* A hex string from ecc.c's curve table as a CAL operand of sz bytes. */
static int wc_MpfsAthenaHexOp(const char* hex, word32* op, word32 sz)
{
    byte be[MAX_ECC_BYTES];
    word32 len = (word32)XSTRLEN(hex);
    word32 i;
    signed char v;

    if (len > 2 * sz) {
        return BAD_FUNC_ARG;
    }
    XMEMSET(be, 0, sizeof(be));
    for (i = 0; i < len; i++) {
        v = HexCharToByte(hex[len - 1 - i]);
        if (v < 0) {
            return BAD_FUNC_ARG;
        }
        be[sz - 1 - i / 2] |= (byte)(v << (4 * (i & 1)));
    }
    wc_MpfsAthenaOpFromBe(op, be, sz);
    return 0;
}

/* NULL for a custom curve or one without a prime in the engine's ROM. The
 * order's Barrett constant comes from the engine. */
static const MpfsAthenaCurve* wc_MpfsAthenaCurveOf(const ecc_key* key)
{
    MpfsAthenaCurve* c = NULL;
    SATR rc = SATR_SUCCESS;
    word32 i;

    if (key == NULL || key->dp == NULL || key->idx == ECC_CUSTOM_IDX ||
            key->dp->size > MAX_ECC_BYTES) {
        return NULL;
    }
    for (i = 0; i < XELEM_CNT(mpfsAthenaCurveIds); i++) {
        if (mpfsAthenaCurveIds[i].id == key->dp->id) {
            c = &mpfsAthenaCurves[i];
            break;
        }
    }
    if (c == NULL || wolfSSL_CryptHwMutexLock() != 0) {
        return NULL;
    }
    if (!c->ready) {
        c->bits = mpfsAthenaCurveIds[i].bits;
        c->mod = mpfsAthenaCurveIds[i].mod;
        c->bytes = (word32)key->dp->size;
        c->words = (c->bytes + 3) / 4;
        if (wc_MpfsAthenaHexOp(key->dp->order, c->nOp, c->bytes) != 0 ||
                wc_MpfsAthenaHexOp(key->dp->Gx, c->gx, c->bytes) != 0 ||
                wc_MpfsAthenaHexOp(key->dp->Gy, c->gy, c->bytes) != 0 ||
                wc_MpfsAthenaHexOp(key->dp->Bf, c->b, c->bytes) != 0) {
            rc = SATR_BADPARAM;
        }
        if (rc == SATR_SUCCESS) {
            for (i = 0; i < c->bytes; i++) {
                c->n[i] = ((const byte*)c->nOp)[c->bytes - 1 - i];
            }
            rc = CALPreCompute((const SATUINT32_t*)c->nOp,
                (SATUINT32_t*)c->nMu, (SATUINT32_t)c->words);
        }
        if (rc == SATR_SUCCESS) {
            rc = wc_MpfsAthenaPkWait();
        }
        c->ready = (rc == SATR_SUCCESS);
    }
    return (wc_MpfsAthenaUnlock(rc) == SATR_SUCCESS) ? c : NULL;
}

#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
/* Unlike every other operand, the ECDSA digest is taken as a big-endian byte
 * string the length of the operand, the form the engine's own hash produces. */
static void wc_MpfsAthenaOpFromHash(word32* op, const byte* be, word32 beLen,
    word32 words)
{
    XMEMSET(op, 0, WC_MPFS_ATHENA_ECC_WORDS * sizeof(word32));
    XMEMCPY((byte*)op + (words * sizeof(word32)) - beLen, be, beLen);
}
#endif

#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_DHE)
static void wc_MpfsAthenaOpToBe(byte* be, word32 beLen, const word32* op)
{
    const byte* o = (const byte*)op;
    word32 i;

    for (i = 0; i < beLen; i++) {
        be[i] = o[beLen - 1 - i];
    }
}
#endif

/* 1 when a < b, both len big-endian bytes, in constant time: it tests secret
 * nonce candidates. */
static int wc_MpfsAthenaBeLess(const byte* a, const byte* b, word32 len)
{
    word32 borrow = 0;
    word32 i = len;

    while (i > 0) {
        i--;
        borrow = ((word32)a[i] - (word32)b[i] - borrow) >> 31;
    }
    return (int)borrow;
}

#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
/* a -= b, both len big-endian bytes; the caller knows a >= b. */
static void wc_MpfsAthenaBeSub(byte* a, const byte* b, word32 len)
{
    word32 borrow = 0;
    word32 t;
    word32 i = len;

    while (i > 0) {
        i--;
        t = (word32)a[i] - (word32)b[i] - borrow;
        a[i] = (byte)t;
        borrow = t >> 31;
    }
}
#endif

static int wc_MpfsAthenaBeIsZero(const byte* a, word32 len)
{
    byte acc = 0;
    word32 i;

    for (i = 0; i < len; i++) {
        acc |= a[i];
    }
    return acc == 0;
}

#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_DHE)
/* A secret scalar in [1, n-1] by FIPS 186-4 B.5.2 testing candidates; the
 * bound keeps a broken RNG from looping forever. */
static int wc_MpfsAthenaEccScalar(WC_RNG* rng, const MpfsAthenaCurve* c,
    byte* out)
{
    int ret;
    int tries;
    int bad;
    byte top = (byte)((c->bits % 8) ? (1U << (c->bits % 8)) - 1U : 0xFFU);

    for (tries = 0; tries < 64; tries++) {
        ret = wc_RNG_GenerateBlock(rng, out, c->bytes);
        if (ret != 0) {
            return ret;
        }
        out[0] &= top;
        bad = wc_MpfsAthenaBeIsZero(out, c->bytes) |
              (wc_MpfsAthenaBeLess(out, c->n, c->bytes) ^ 1);
        if (!bad) {
            return 0;
        }
    }
    ForceZero(out, c->bytes);
    return RNG_FAILURE_E;
}
#endif

#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
/* The digest's leftmost order-length bytes, reduced once mod n. A digest that
 * needs bit truncation (wider than 521 bits on P-521) is declined. */
static int wc_MpfsAthenaEccHash(const MpfsAthenaCurve* c, const byte* in,
    word32 inLen, byte* e)
{
    if (inLen > c->bytes ||
            (inLen == c->bytes && (c->bits % 8) != 0)) {
        if ((c->bits % 8) != 0) {
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
        inLen = c->bytes;
    }
    XMEMSET(e, 0, c->bytes);
    XMEMCPY(e + c->bytes - inLen, in, inLen);
    if (!wc_MpfsAthenaBeLess(e, c->n, c->bytes)) {
        wc_MpfsAthenaBeSub(e, c->n, c->bytes);
    }
    return 0;
}
#endif

#ifdef WOLFSSL_SMALL_STACK
static MpfsAthenaEccOps* wc_MpfsAthenaEccOpsNew(void* heap)
{
    return (MpfsAthenaEccOps*)XMALLOC(sizeof(MpfsAthenaEccOps), heap,
        DYNAMIC_TYPE_TMP_BUFFER);
}
#endif

static void wc_MpfsAthenaEccOpsFree(MpfsAthenaEccOps* op, void* heap)
{
    ForceZero(op, sizeof(*op));
#ifdef WOLFSSL_SMALL_STACK
    XFREE(op, heap, DYNAMIC_TYPE_TMP_BUFFER);
#else
    (void)heap;
#endif
}

#if defined(HAVE_ECC_VERIFY) || defined(HAVE_ECC_DHE)
/* A public point as operands; only an affine point (z == 1) is taken. */
static int wc_MpfsAthenaEccPoint(const MpfsAthenaCurve* c, ecc_point* pt,
    MpfsAthenaEccOps* op)
{
    if (mp_cmp_d(pt->z, 1) != MP_EQ ||
            mp_to_unsigned_bin_len(pt->x, op->be[0],
                (int)c->bytes) != MP_OKAY ||
            mp_to_unsigned_bin_len(pt->y, op->be[1],
                (int)c->bytes) != MP_OKAY) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    wc_MpfsAthenaOpFromBe(op->x, op->be[0], c->bytes);
    wc_MpfsAthenaOpFromBe(op->y, op->be[1], c->bytes);
    return 0;
}
#endif

#ifdef HAVE_ECC_SIGN
static int wc_MpfsAthenaEccSignDev(wc_CryptoInfo* info)
{
    ecc_key* key = info->pk.eccsign.key;
    const MpfsAthenaCurve* c = wc_MpfsAthenaCurveOf(key);
#ifndef WOLFSSL_SMALL_STACK
    MpfsAthenaEccOps opBuf;
#endif
    MpfsAthenaEccOps* op;
    int started;
    int tries;
    SATR rc;
    int ret;

    /* An all-zero digest is software's to reject or allow
     * (WC_ALLOW_ECC_ZERO_HASH); its check runs only after this callback. */
    if (c == NULL || info->pk.eccsign.rng == NULL ||
            (key->type != ECC_PRIVATEKEY && key->type != ECC_PRIVATEKEY_ONLY) ||
            wc_MpfsAthenaBeIsZero(info->pk.eccsign.in,
                info->pk.eccsign.inlen)) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
#ifdef NO_ASN
    /* The raw r || s form; software reports the size it needs. */
    if (*info->pk.eccsign.outlen < 2U * c->bytes) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
#endif
    /* A caller-set or RFC 6979 nonce is software's to produce. */
#if defined(WOLFSSL_ECDSA_SET_K) || defined(WOLFSSL_ECDSA_SET_K_ONE_LOOP) || \
    defined(WOLFSSL_ECDSA_DETERMINISTIC_K) || \
    defined(WOLFSSL_ECDSA_DETERMINISTIC_K_VARIANT)
  #ifndef WOLFSSL_NO_MALLOC
    if (key->sign_k != NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
  #else
    if (key->sign_k_set) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
  #endif
#endif
#if defined(WOLFSSL_ECDSA_DETERMINISTIC_K) || \
    defined(WOLFSSL_ECDSA_DETERMINISTIC_K_VARIANT)
    if (key->deterministic) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
#endif

#ifdef WOLFSSL_SMALL_STACK
    op = wc_MpfsAthenaEccOpsNew(key->heap);
    if (op == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
#else
    op = &opBuf;
#endif

    ret = wc_MpfsAthenaEccHash(c, info->pk.eccsign.in, info->pk.eccsign.inlen,
        op->be[0]);
    if (ret == 0) {
        wc_MpfsAthenaOpFromHash(op->e, op->be[0], c->bytes, c->words);
        if (mp_to_unsigned_bin_len(wc_ecc_key_get_priv(key), op->be[0],
                (int)c->bytes) != MP_OKAY) {
            ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
    }
    if (ret == 0) {
        wc_MpfsAthenaOpFromBe(op->d, op->be[0], c->bytes);
    }

    /* A zero r or s needs a fresh nonce. It is drawn unlocked: the RNG's own
     * hashing comes back through this port and takes the same mutex. */
    started = 0;
    rc = SATR_SIGNFAIL;
    for (tries = 0; ret == 0 && rc == SATR_SIGNFAIL && tries < 4; tries++) {
        ret = wc_MpfsAthenaEccScalar(info->pk.eccsign.rng, c, op->be[1]);
        if (ret != 0) {
            break;
        }
        wc_MpfsAthenaOpFromBe(op->k, op->be[1], c->bytes);
        ret = wolfSSL_CryptHwMutexLock();
        if (ret != 0) {
            break;
        }
        rc = CALECDSASignCM((const SATUINT32_t*)op->e,
            (const SATUINT32_t*)c->gx, (const SATUINT32_t*)c->gy,
            (const SATUINT32_t*)op->k, (const SATUINT32_t*)op->d,
            (const SATUINT32_t*)c->b, c->mod, NULL,
            (const SATUINT32_t*)c->nOp, (const SATUINT32_t*)c->nMu,
            (SATUINT32_t)c->words, (SATUINT32_t*)op->r, (SATUINT32_t*)op->s);
        if (rc == SATR_SUCCESS) {
            started = 1;
            rc = wc_MpfsAthenaPkPurge(wc_MpfsAthenaPkWait());
        }
        rc = wc_MpfsAthenaUnlock(rc);
    }
    if (ret != 0) {
        wc_MpfsAthenaEccOpsFree(op, key->heap);
        return ret;
    }
    if (rc == SATR_SIGNFAIL) {
        ret = WC_HW_E;
    }
    if (ret == 0 && rc == SATR_SUCCESS) {
    #ifndef NO_ASN
        wc_MpfsAthenaOpToBe(op->be[0], c->bytes, op->r);
        wc_MpfsAthenaOpToBe(op->be[1], c->bytes, op->s);
        ret = StoreECC_DSA_Sig_Bin(info->pk.eccsign.out,
            info->pk.eccsign.outlen, op->be[0], c->bytes, op->be[1],
            c->bytes);
    #else
        /* Without ASN.1, wolfCrypt's signature is r || s. */
        wc_MpfsAthenaOpToBe(info->pk.eccsign.out, c->bytes, op->r);
        wc_MpfsAthenaOpToBe(info->pk.eccsign.out + c->bytes, c->bytes,
            op->s);
        *info->pk.eccsign.outlen = 2U * c->bytes;
    #endif
        if (ret == 0) {
            wc_MpfsAthenaCountCall();
        }
    }
    else if (ret == 0) {
        ret = started ? WC_HW_E : WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    wc_MpfsAthenaEccOpsFree(op, key->heap);
    return ret;
}
#endif /* HAVE_ECC_SIGN */

#ifdef HAVE_ECC_VERIFY
/* Inputs software would judge differently (zero digest, malformed signature,
 * r or s out of range) are declined, so its result and error code stand. */
static int wc_MpfsAthenaEccVerifyDev(wc_CryptoInfo* info)
{
    ecc_key* key = info->pk.eccverify.key;
    const MpfsAthenaCurve* c = wc_MpfsAthenaCurveOf(key);
#ifndef WOLFSSL_SMALL_STACK
    MpfsAthenaEccOps opBuf;
#endif
    MpfsAthenaEccOps* op;
    word32 rLen;
    word32 sLen;
    int started = 0;
    SATR rc;
    int ret;

    if (c == NULL || info->pk.eccverify.res == NULL ||
            (key->type != ECC_PUBLICKEY && key->type != ECC_PRIVATEKEY) ||
            wc_MpfsAthenaBeIsZero(info->pk.eccverify.hash,
                info->pk.eccverify.hashlen)) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

#ifdef WOLFSSL_SMALL_STACK
    op = wc_MpfsAthenaEccOpsNew(key->heap);
    if (op == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
#else
    op = &opBuf;
#endif

#ifndef NO_ASN
    rLen = sLen = sizeof(op->be[0]);
    ret = DecodeECC_DSA_Sig_Bin(info->pk.eccverify.sig,
        info->pk.eccverify.siglen, op->be[0], &rLen, op->be[1], &sLen);
    if (ret != 0 || rLen > c->bytes || sLen > c->bytes) {
        ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
#else
    /* Without ASN.1, wolfCrypt's signature is r || s. */
    rLen = sLen = c->bytes;
    ret = 0;
    if (info->pk.eccverify.siglen != 2U * c->bytes) {
        ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    else {
        XMEMCPY(op->be[0], info->pk.eccverify.sig, c->bytes);
        XMEMCPY(op->be[1], info->pk.eccverify.sig + c->bytes, c->bytes);
    }
#endif
    if (ret == 0) {
        /* Right-align r and s to the order's length. */
        XMEMMOVE(op->be[0] + c->bytes - rLen, op->be[0], rLen);
        XMEMSET(op->be[0], 0, c->bytes - rLen);
        XMEMMOVE(op->be[1] + c->bytes - sLen, op->be[1], sLen);
        XMEMSET(op->be[1], 0, c->bytes - sLen);
        if (wc_MpfsAthenaBeIsZero(op->be[0], c->bytes) ||
                wc_MpfsAthenaBeIsZero(op->be[1], c->bytes) ||
                !wc_MpfsAthenaBeLess(op->be[0], c->n, c->bytes) ||
                !wc_MpfsAthenaBeLess(op->be[1], c->n, c->bytes)) {
            ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
    }
    if (ret == 0) {
        wc_MpfsAthenaOpFromBe(op->r, op->be[0], c->bytes);
        wc_MpfsAthenaOpFromBe(op->s, op->be[1], c->bytes);
        ret = wc_MpfsAthenaEccHash(c, info->pk.eccverify.hash,
            info->pk.eccverify.hashlen, op->be[0]);
    }
    if (ret == 0) {
        wc_MpfsAthenaOpFromHash(op->e, op->be[0], c->bytes, c->words);
        ret = wc_MpfsAthenaEccPoint(c, &key->pubkey, op);
    }
    if (ret == 0) {
        ret = wolfSSL_CryptHwMutexLock();
    }
    if (ret != 0) {
        wc_MpfsAthenaEccOpsFree(op, key->heap);
        return ret;
    }

    rc = CALECDSAVerify((const SATUINT32_t*)op->e,
        (const SATUINT32_t*)c->gx, (const SATUINT32_t*)c->gy,
        (const SATUINT32_t*)op->x, (const SATUINT32_t*)op->y,
        (const SATUINT32_t*)op->r, (const SATUINT32_t*)op->s,
        (const SATUINT32_t*)c->b, c->mod, NULL,
        (const SATUINT32_t*)c->nOp, (const SATUINT32_t*)c->nMu,
        (SATUINT32_t)c->words, 0);
    if (rc == SATR_SUCCESS) {
        started = 1;
        rc = wc_MpfsAthenaPkWait();
    }
    rc = wc_MpfsAthenaUnlock(rc);
    wc_MpfsAthenaEccOpsFree(op, key->heap);

    if (rc == SATR_SUCCESS) {
        *info->pk.eccverify.res = 1;
    }
    else if (started && rc == SATR_VERIFYFAIL) {
        *info->pk.eccverify.res = 0;
    }
    else {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    wc_MpfsAthenaCountCall();
    return 0;
}
#endif /* HAVE_ECC_VERIFY */

#ifdef HAVE_ECC_DHE
/* The peer point is validated, then multiplied by the private scalar on the
 * countermeasure path; x is the secret. */
static int wc_MpfsAthenaEcdhDev(wc_CryptoInfo* info)
{
    ecc_key* priv = info->pk.ecdh.private_key;
    ecc_key* pub = info->pk.ecdh.public_key;
    const MpfsAthenaCurve* c = wc_MpfsAthenaCurveOf(priv);
#ifndef WOLFSSL_SMALL_STACK
    MpfsAthenaEccOps opBuf;
#endif
    MpfsAthenaEccOps* op;
    int started = 0;
    SATR rc;
    int ret;

    if (c == NULL || pub == NULL || wc_MpfsAthenaCurveOf(pub) != c ||
            info->pk.ecdh.out == NULL || info->pk.ecdh.outlen == NULL ||
            *info->pk.ecdh.outlen < c->bytes ||
            (priv->type != ECC_PRIVATEKEY &&
             priv->type != ECC_PRIVATEKEY_ONLY) ||
            (pub->type != ECC_PUBLICKEY && pub->type != ECC_PRIVATEKEY)) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

#ifdef WOLFSSL_SMALL_STACK
    op = wc_MpfsAthenaEccOpsNew(priv->heap);
    if (op == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
#else
    op = &opBuf;
#endif

    ret = wc_MpfsAthenaEccPoint(c, &pub->pubkey, op);
    if (ret == 0 && mp_to_unsigned_bin_len(wc_ecc_key_get_priv(priv),
            op->be[0], (int)c->bytes) != MP_OKAY) {
        ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (ret == 0) {
        wc_MpfsAthenaOpFromBe(op->d, op->be[0], c->bytes);
        ret = wolfSSL_CryptHwMutexLock();
    }
    if (ret != 0) {
        wc_MpfsAthenaEccOpsFree(op, priv->heap);
        return ret;
    }

    rc = CALECPtValidate((const SATUINT32_t*)op->x, (const SATUINT32_t*)op->y,
        (const SATUINT32_t*)c->b, c->mod, NULL, (SATUINT32_t)c->words);
    if (rc == SATR_SUCCESS) {
        rc = wc_MpfsAthenaPkWait();
        if (rc != SATR_SUCCESS) {
            /* Never multiply a point off the curve by a private scalar. */
            ret = IS_POINT_E;
        }
    }
    if (rc == SATR_SUCCESS) {
        rc = CALECMultCM((const SATUINT32_t*)op->d, (const SATUINT32_t*)op->x,
            (const SATUINT32_t*)op->y, (const SATUINT32_t*)c->b, c->mod, NULL,
            (const SATUINT32_t*)c->nOp, (SATUINT32_t)c->words, 0,
            (SATUINT32_t*)op->r, (SATUINT32_t*)op->s);
        if (rc == SATR_SUCCESS) {
            started = 1;
            rc = wc_MpfsAthenaPkWait();
        }
    }
    if (started) {
        rc = wc_MpfsAthenaPkPurge(rc);
    }
    rc = wc_MpfsAthenaUnlock(rc);

    if (ret == 0 && rc == SATR_SUCCESS) {
        wc_MpfsAthenaOpToBe(info->pk.ecdh.out, c->bytes, op->r);
        *info->pk.ecdh.outlen = c->bytes;
        wc_MpfsAthenaCountCall();
    }
    else if (ret == 0) {
        ret = started ? WC_HW_E : WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    wc_MpfsAthenaEccOpsFree(op, priv->heap);
    return ret;
}

#ifndef WOLFSSL_ECC_BLIND_K
/* A fresh scalar from the caller's RNG and its point from the engine. With
 * WOLFSSL_ECC_BLIND_K software keeps the scalar blinded, so it keeps keygen. */
static int wc_MpfsAthenaEccKeyGenDev(wc_CryptoInfo* info)
{
    ecc_key* key = info->pk.eckg.key;
    const MpfsAthenaCurve* c = wc_MpfsAthenaCurveOf(key);
#ifndef WOLFSSL_SMALL_STACK
    MpfsAthenaEccOps opBuf;
#endif
    MpfsAthenaEccOps* op;
    int started = 0;
    SATR rc;
    int ret;

    if (c == NULL || info->pk.eckg.rng == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

#ifdef WOLFSSL_SMALL_STACK
    op = wc_MpfsAthenaEccOpsNew(key->heap);
    if (op == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
#else
    op = &opBuf;
#endif

    ret = wc_MpfsAthenaEccScalar(info->pk.eckg.rng, c, op->be[0]);
    if (ret == 0) {
        wc_MpfsAthenaOpFromBe(op->d, op->be[0], c->bytes);
        ret = wolfSSL_CryptHwMutexLock();
    }
    if (ret != 0) {
        wc_MpfsAthenaEccOpsFree(op, key->heap);
        return ret;
    }

    rc = CALECMultCM((const SATUINT32_t*)op->d, (const SATUINT32_t*)c->gx,
        (const SATUINT32_t*)c->gy, (const SATUINT32_t*)c->b, c->mod, NULL,
        (const SATUINT32_t*)c->nOp, (SATUINT32_t)c->words, 0,
        (SATUINT32_t*)op->x, (SATUINT32_t*)op->y);
    if (rc == SATR_SUCCESS) {
        started = 1;
        rc = wc_MpfsAthenaPkWait();
    }
    if (started) {
        rc = wc_MpfsAthenaPkPurge(rc);
    }
    rc = wc_MpfsAthenaUnlock(rc);

    if (rc == SATR_SUCCESS) {
        ret = mp_read_unsigned_bin(key->k, op->be[0], c->bytes);
        if (ret == MP_OKAY) {
            wc_MpfsAthenaOpToBe(op->be[1], c->bytes, op->x);
            ret = mp_read_unsigned_bin(key->pubkey.x, op->be[1], c->bytes);
        }
        if (ret == MP_OKAY) {
            wc_MpfsAthenaOpToBe(op->be[1], c->bytes, op->y);
            ret = mp_read_unsigned_bin(key->pubkey.y, op->be[1], c->bytes);
        }
        if (ret == MP_OKAY) {
            ret = mp_set(key->pubkey.z, 1);
        }
        if (ret == MP_OKAY) {
            key->type = ECC_PRIVATEKEY;
            wc_MpfsAthenaCountCall();
        }
        else {
            mp_forcezero(key->k);
        }
    }
    else {
        ret = started ? WC_HW_E : WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    wc_MpfsAthenaEccOpsFree(op, key->heap);
    return ret;
}
#endif /* !WOLFSSL_ECC_BLIND_K */
#endif /* HAVE_ECC_DHE */
#endif /* WC_MPFS_ATHENA_ECC */

#ifdef WC_MPFS_ATHENA_RSA
/* The longest public exponent served, in words; others go to software. */
#define WC_MPFS_ATHENA_RSA_WORDS (WC_MPFS_ATHENA_RSA_MAX_BITS / 32)
#define WC_MPFS_ATHENA_RSA_E_WORDS 8

/* Operand scratch for one operation, zeroed after use. */
typedef struct MpfsAthenaRsaOps {
    word32 x[WC_MPFS_ATHENA_RSA_WORDS];
    word32 n[WC_MPFS_ATHENA_RSA_WORDS];
    word32 nMu[WC_MPFS_ATHENA_RSA_WORDS + 1];
    word32 r[WC_MPFS_ATHENA_RSA_WORDS];
    word32 e[WC_MPFS_ATHENA_RSA_E_WORDS];
#ifndef WOLFSSL_RSA_PUBLIC_ONLY
    word32 p[WC_MPFS_ATHENA_RSA_WORDS / 2];
    word32 q[WC_MPFS_ATHENA_RSA_WORDS / 2];
    word32 dP[WC_MPFS_ATHENA_RSA_WORDS / 2];
    word32 dQ[WC_MPFS_ATHENA_RSA_WORDS / 2];
    word32 u[WC_MPFS_ATHENA_RSA_WORDS / 2];
#endif
    byte   be[WC_MPFS_ATHENA_RSA_WORDS * 4];
} MpfsAthenaRsaOps;

/* A big-endian value as a CAL operand of words words: least significant word
 * first, which on this little-endian core is the byte string reversed. */
static void wc_MpfsAthenaRsaLoadBe(word32* op, word32 words, const byte* be,
    word32 beLen)
{
    byte* o = (byte*)op;
    word32 i;

    XMEMSET(op, 0, words * sizeof(word32));
    for (i = 0; i < beLen; i++) {
        o[i] = be[beLen - 1 - i];
    }
}

/* Always the full width, so the work on a private component does not depend
 * on its leading zeros. CRYPTOCB_UNAVAILABLE when it does not fit. */
static int wc_MpfsAthenaRsaLoadMp(mp_int* a, word32* op, word32 words,
    byte* be)
{
    if (mp_to_unsigned_bin_len(a, be, (int)(words * 4U)) != MP_OKAY) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    wc_MpfsAthenaRsaLoadBe(op, words, be, words * 4U);
    return 0;
}

/* The raw RSA primitive; padding and input range checks stay in software. The
 * private operation uses CRT on the countermeasure path, as blinding is not. */
static int wc_MpfsAthenaRsaDev(wc_CryptoInfo* info)
{
    RsaKey* key = info->pk.rsa.key;
    const byte* in = info->pk.rsa.in;
    word32 inLen = info->pk.rsa.inLen;
    int type = info->pk.rsa.type;
    int priv = (type == RSA_PRIVATE_ENCRYPT || type == RSA_PRIVATE_DECRYPT);
#ifndef WOLFSSL_SMALL_STACK
    MpfsAthenaRsaOps opBuf;
#endif
    MpfsAthenaRsaOps* op;
    word32 nBytes;
    word32 words;
    word32 eWords;
    word32 i;
    int started = 0;
    SATR rc;
    int ret;

    if (key == NULL || in == NULL || info->pk.rsa.out == NULL ||
            info->pk.rsa.outLen == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
#ifdef WOLF_CRYPTO_CB_RSA_PAD
    if (info->pk.rsa.padding != NULL &&
            info->pk.rsa.padding->pad_type != WC_RSA_NO_PAD) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
#endif
    nBytes = (word32)mp_unsigned_bin_size(&key->n);
    words = (nBytes + 3U) / 4U;
    eWords = ((word32)mp_unsigned_bin_size(&key->e) + 3U) / 4U;
    if (nBytes == 0 || words > WC_MPFS_ATHENA_RSA_WORDS || inLen != nBytes ||
            *info->pk.rsa.outLen < nBytes || eWords == 0 ||
            eWords > WC_MPFS_ATHENA_RSA_E_WORDS) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
#ifndef WC_MPFS_ATHENA_RSA_PUBLIC
    if (!priv) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
#endif
#ifdef WOLFSSL_RSA_PUBLIC_ONLY
    if (priv) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
#else
    /* CAL's CRT takes p, q and the rest at half the modulus length. */
    if (priv && (key->type != RSA_PRIVATE || mp_iszero(&key->p) ||
            mp_iszero(&key->q) || mp_iszero(&key->dP) ||
            mp_iszero(&key->dQ) || mp_iszero(&key->u) || (words % 2U) != 0)) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
#endif

#ifdef WOLFSSL_SMALL_STACK
    op = (MpfsAthenaRsaOps*)XMALLOC(sizeof(MpfsAthenaRsaOps), key->heap,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (op == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
#else
    op = &opBuf;
#endif

    /* 1 < x < n - 1, compared as big-endian: x <= 1 is all zero but the last
     * byte, which is 0 or 1; x >= n - 1 is x + 1 >= n. */
    ret = wc_MpfsAthenaRsaLoadMp(&key->n, op->n, words, op->be);
    if (ret == 0) {
        byte small = 0;
        for (i = 0; i + 1 < inLen; i++) {
            small |= in[i];
        }
        if (small == 0 && in[inLen - 1] <= 1) {
            ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
    }
    if (ret == 0 && mp_to_unsigned_bin_len(&key->n, op->be,
            (int)nBytes) != MP_OKAY) {
        ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (ret == 0) {
        /* op->be holds n; make it n - 1 and require x < n - 1. */
        i = nBytes;
        while (i > 0) {
            i--;
            if (op->be[i] != 0) {
                op->be[i]--;
                break;
            }
            op->be[i] = 0xFF;
        }
        i = 0;
        while (i < nBytes && in[i] == op->be[i]) {
            i++;
        }
        if (i == nBytes || in[i] > op->be[i]) {
            ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
    }
    if (ret == 0) {
        wc_MpfsAthenaRsaLoadBe(op->x, words, in, inLen);
        ret = wc_MpfsAthenaRsaLoadMp(&key->e, op->e, eWords, op->be);
    }
#ifndef WOLFSSL_RSA_PUBLIC_ONLY
    if (ret == 0 && priv) {
        ret = wc_MpfsAthenaRsaLoadMp(&key->p, op->p, words / 2U, op->be);
        if (ret == 0) {
            ret = wc_MpfsAthenaRsaLoadMp(&key->q, op->q, words / 2U, op->be);
        }
        if (ret == 0) {
            ret = wc_MpfsAthenaRsaLoadMp(&key->dP, op->dP, words / 2U,
                op->be);
        }
        if (ret == 0) {
            ret = wc_MpfsAthenaRsaLoadMp(&key->dQ, op->dQ, words / 2U,
                op->be);
        }
        if (ret == 0) {
            ret = wc_MpfsAthenaRsaLoadMp(&key->u, op->u, words / 2U, op->be);
        }
    }
#endif
    if (ret == 0) {
        ret = wolfSSL_CryptHwMutexLock();
    }
    if (ret != 0) {
        ForceZero(op, sizeof(*op));
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(op, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
        return ret;
    }

    rc = CALPreCompute((const SATUINT32_t*)op->n, (SATUINT32_t*)op->nMu,
        (SATUINT32_t)words);
    if (rc == SATR_SUCCESS) {
        rc = wc_MpfsAthenaPkWait();
    }
    if (rc == SATR_SUCCESS && !priv) {
        rc = CALExpo((const SATUINT32_t*)op->x, (const SATUINT32_t*)op->e,
            (const SATUINT32_t*)op->n, (const SATUINT32_t*)op->nMu,
            (SATUINT32_t)eWords, (SATUINT32_t)words, (SATUINT32_t*)op->r);
        if (rc == SATR_SUCCESS) {
            started = 1;
            rc = wc_MpfsAthenaPkWait();
        }
    }
#ifndef WOLFSSL_RSA_PUBLIC_ONLY
    else if (rc == SATR_SUCCESS) {
        rc = CALRSACRTCM((const SATUINT32_t*)op->x,
            (const SATUINT32_t*)op->u, (const SATUINT32_t*)op->dP,
            (const SATUINT32_t*)op->dQ, (const SATUINT32_t*)op->e,
            (const SATUINT32_t*)op->p, (const SATUINT32_t*)op->q,
            (const SATUINT32_t*)op->n, (const SATUINT32_t*)op->nMu,
            (SATUINT32_t)(words / 2U), (SATUINT32_t)eWords,
            (SATUINT32_t*)op->r);
        if (rc == SATR_SUCCESS) {
            started = 1;
            rc = wc_MpfsAthenaPkPurge(wc_MpfsAthenaPkWait());
        }
    }
#endif
    if (rc != SATR_SUCCESS) {
        mpfsAthenaCalRc = (int)rc;
    }
    wolfSSL_CryptHwMutexUnLock();

    if (rc == SATR_SUCCESS) {
        byte* o = (byte*)op->r;
        for (i = 0; i < nBytes; i++) {
            info->pk.rsa.out[i] = o[nBytes - 1 - i];
        }
        *info->pk.rsa.outLen = nBytes;
        wc_MpfsAthenaCountCall();
    }
    else {
        ret = started ? WC_HW_E : WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    ForceZero(op, sizeof(*op));
#ifdef WOLFSSL_SMALL_STACK
    XFREE(op, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return ret;
}
#endif /* WC_MPFS_ATHENA_RSA */

int wc_MpfsAthena_CryptoDevCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    (void)devId;
    (void)ctx;

    if (info == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    switch (info->algo_type) {
#ifdef WC_MPFS_ATHENA_HASH
        case WC_ALGO_TYPE_HASH:
            /* A declined SHA-384 call retried as SHA-512 is still hashed as
             * SHA-384: the variant comes from the object's IV. */
            return wc_MpfsAthenaShaDev(info);
#endif

#ifdef WC_MPFS_ATHENA_CIPHER
        case WC_ALGO_TYPE_CIPHER:
#if defined(WOLFSSL_AES_COUNTER)
            if (info->cipher.type == WC_CIPHER_AES_CTR) {
                return wc_MpfsAthenaAesCtrDev(info);
            }
#endif
#if defined(HAVE_AES_ECB)
            if (info->cipher.type == WC_CIPHER_AES_ECB) {
                return wc_MpfsAthenaAesEcbDev(info);
            }
#endif
#ifdef WC_MPFS_ATHENA_CBC
            if (info->cipher.type == WC_CIPHER_AES_CBC) {
                return wc_MpfsAthenaAesCbcDev(info);
            }
#endif
#ifdef WC_MPFS_ATHENA_GCM
            if (info->cipher.type == WC_CIPHER_AES_GCM) {
                return wc_MpfsAthenaAesGcmDev(info);
            }
#endif
#ifdef WC_MPFS_ATHENA_KEYWRAP
            if (info->cipher.type == WC_CIPHER_AES_KEYWRAP) {
                return wc_MpfsAthenaAesKeyWrapDev(info);
            }
#endif
            break;
#endif

#ifdef WC_MPFS_ATHENA_CMAC
        case WC_ALGO_TYPE_CMAC:
            return wc_MpfsAthenaCmacDev(info);
#endif

#if defined(WC_MPFS_ATHENA_ECC) || defined(WC_MPFS_ATHENA_RSA)
        case WC_ALGO_TYPE_PK:
    #ifdef WC_MPFS_ATHENA_RSA
            if (info->pk.type == WC_PK_TYPE_RSA) {
                return wc_MpfsAthenaRsaDev(info);
            }
    #endif
    #if defined(WC_MPFS_ATHENA_ECC) && defined(HAVE_ECC_SIGN)
            if (info->pk.type == WC_PK_TYPE_ECDSA_SIGN) {
                return wc_MpfsAthenaEccSignDev(info);
            }
    #endif
    #if defined(WC_MPFS_ATHENA_ECC) && defined(HAVE_ECC_VERIFY)
            if (info->pk.type == WC_PK_TYPE_ECDSA_VERIFY) {
                return wc_MpfsAthenaEccVerifyDev(info);
            }
    #endif
    #if defined(WC_MPFS_ATHENA_ECC) && defined(HAVE_ECC_DHE)
            if (info->pk.type == WC_PK_TYPE_ECDH) {
                return wc_MpfsAthenaEcdhDev(info);
            }
        #ifndef WOLFSSL_ECC_BLIND_K
            if (info->pk.type == WC_PK_TYPE_EC_KEYGEN) {
                return wc_MpfsAthenaEccKeyGenDev(info);
            }
        #endif
    #endif
            break;
#endif

#ifdef WC_MPFS_ATHENA_RNG_DRBG
        case WC_ALGO_TYPE_RNG:
            return wc_MpfsAthenaRngDev(info);
#endif

#ifdef WC_MPFS_ATHENA_HASH
        case WC_ALGO_TYPE_FREE:
            if (info->free.algo == WC_ALGO_TYPE_HASH) {
                return wc_MpfsAthenaShaFreeDev(info);
            }
            break;

        case WC_ALGO_TYPE_COPY:
            if (info->copy.algo == WC_ALGO_TYPE_HASH) {
                return wc_MpfsAthenaShaCopyDev(info);
            }
            break;
#endif

        default:
            break;
    }

    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}

int wc_MpfsAthena_RegisterDevice(int devId)
{
    int ret;

    ret = wc_MpfsAthena_Init();
    if (ret != 0) {
        return ret;
    }

    /* No wc_CryptoCb_Init() here: it clears the whole device table, and
     * wolfCrypt_Init() already runs it. */
    ret = wc_CryptoCb_RegisterDevice(devId, wc_MpfsAthena_CryptoDevCb, NULL);
    if (ret == WC_NO_ERR_TRACE(ALREADY_E)) {
        /* Already registered is success: wolfcrypt_test() and benchmark()
         * both register. */
        return 0;
    }
    if (ret != 0) {
        if (ret == WC_NO_ERR_TRACE(BUFFER_E)) {
            WOLFSSL_MSG("MPFS Athena: no free crypto callback device slot; "
                        "call wolfCrypt_Init() before registering");
        }
        return ret;
    }

    return 0;
}

void wc_MpfsAthena_UnRegisterDevice(int devId)
{
    wc_CryptoCb_UnRegisterDevice(devId);
}

/* Known-answer tests, opt-in. The engine call count they check is what tells
 * a live engine from a silent software fallback. */
#ifdef WC_MPFS_ATHENA_SELFTEST

/* Driven through the public API, so the whole dispatch chain is covered. Run
 * it at init: a concurrent offload would add to the count it checks. */

#if !defined(NO_AES) && (defined(WOLFSSL_AES_COUNTER) || \
    defined(HAVE_AES_ECB) || defined(WC_MPFS_ATHENA_CBC) || \
    defined(WC_MPFS_ATHENA_GCM) || defined(WC_MPFS_ATHENA_KEYWRAP) || \
    (defined(WC_MPFS_ATHENA_CMAC) && defined(WOLFSSL_AES_DIRECT)))
    #define WC_MPFS_ATHENA_KAT_AES
#endif
#if defined(WC_MPFS_ATHENA_RSA) && (WC_MPFS_ATHENA_RSA_MAX_BITS >= 2048)
    #define WC_MPFS_ATHENA_KAT_RSA
#endif
#if defined(WC_MPFS_ATHENA_HASH) || defined(WC_MPFS_ATHENA_KAT_AES) || \
    defined(WC_MPFS_ATHENA_RNG) || defined(WC_MPFS_ATHENA_ECC) || \
    defined(WC_MPFS_ATHENA_KAT_RSA)
    #define WC_MPFS_ATHENA_KAT_ANY
#endif

static const char* mpfsAthenaFailWhat;

const char* wc_MpfsAthena_SelfTestDesc(void)
{
    return (mpfsAthenaFailWhat != NULL) ? mpfsAthenaFailWhat : "ok";
}

#ifdef WC_MPFS_ATHENA_KAT_ANY
/* Self-test only, which runs before other threads drive the engine, so one
 * static buffer is enough. */
static char mpfsAthenaFailBuf[80];

static void wc_MpfsAthenaKatFail(const char* alg, const char* step,
    const char* what)
{
    const char* parts[5];
    word32 n = 0;
    int i;

    parts[0] = alg;
    parts[1] = " ";
    parts[2] = step;
    parts[3] = ": ";
    parts[4] = what;
    for (i = 0; i < 5; i++) {
        while (*parts[i] != '\0' && n < sizeof(mpfsAthenaFailBuf) - 1) {
            mpfsAthenaFailBuf[n++] = *parts[i]++;
        }
    }
    mpfsAthenaFailBuf[n] = '\0';
    mpfsAthenaFailWhat = mpfsAthenaFailBuf;
}

/* served: 1 the step must have reached the engine since calls was taken, 0 it
 * must not have, -1 either. got is compared with want unless it is NULL. */
static int wc_MpfsAthenaKatCheck(const char* alg, const char* step, int ret,
    int served, word32 calls, const byte* got, const byte* want, word32 sz)
{
    const char* what = NULL;

    if (ret != 0) {
        what = "failed";
    }
    else if (served >= 0 && (mpfsAthenaCbCalls != calls) != served) {
        what = served ? "never reached the engine" : "reached the engine";
        ret = WC_HW_E;
    }
    else if (got != NULL && XMEMCMP(got, want, sz) != 0) {
        what = "known-answer mismatch";
        ret = WC_HW_E;
    }
    if (what != NULL) {
        wc_MpfsAthenaKatFail(alg, step, what);
    }
    return ret;
}

#if defined(WC_MPFS_ATHENA_HASH) || defined(WC_MPFS_ATHENA_KAT_AES) || \
    defined(WC_MPFS_ATHENA_ECC) || defined(WC_MPFS_ATHENA_KAT_RSA)
static void wc_MpfsAthenaKatSeq(byte* out, word32 sz, byte start)
{
    word32 i;

    for (i = 0; i < sz; i++) {
        out[i] = (byte)(start + i);
    }
}
#endif
#endif /* WC_MPFS_ATHENA_KAT_ANY */

#ifdef WC_MPFS_ATHENA_HASH
/* Per variant: the digests of 0x00..0xFF, of its first 100 bytes (what
 * GetHash() must return mid-stream) and of the empty message. */
#if defined(WC_MPFS_ATHENA_SHA256) && defined(WOLFSSL_SHA224)
static const byte mpfsAthenaKatSha224[84] = {
    0x88, 0x70, 0x2e, 0x63, 0x23, 0x78, 0x24, 0xc4, 0xeb, 0x0d, 0x0f, 0xcf,
    0xe4, 0x14, 0x69, 0xa4, 0x62, 0x49, 0x3e, 0x8b, 0xeb, 0x2a, 0x75, 0xbb,
    0xe5, 0x98, 0x17, 0x34, 0x6e, 0x08, 0x21, 0x5b, 0x54, 0x70, 0xdd, 0xeb,
    0x67, 0xe4, 0x4a, 0x49, 0x4e, 0x52, 0xe2, 0x59, 0xa9, 0xc2, 0xc4, 0xfb,
    0xed, 0x4a, 0xf5, 0xdc, 0x6d, 0xb3, 0xe9, 0x2a, 0xd1, 0x4a, 0x02, 0x8c,
    0x2a, 0x3a, 0x2b, 0xc9, 0x47, 0x61, 0x02, 0xbb, 0x28, 0x82, 0x34, 0xc4,
    0x15, 0xa2, 0xb0, 0x1f, 0x82, 0x8e, 0xa6, 0x2a, 0xc5, 0xb3, 0xe4, 0x2f
};
#endif
#ifdef WC_MPFS_ATHENA_SHA256
static const byte mpfsAthenaKatSha256[96] = {
    0x40, 0xaf, 0xf2, 0xe9, 0xd2, 0xd8, 0x92, 0x2e, 0x47, 0xaf, 0xd4, 0x64,
    0x8e, 0x69, 0x67, 0x49, 0x71, 0x58, 0x78, 0x5f, 0xbd, 0x1d, 0xa8, 0x70,
    0xe7, 0x11, 0x02, 0x66, 0xbf, 0x94, 0x48, 0x80, 0xbc, 0xe0, 0xaf, 0xf1,
    0x9c, 0xf5, 0xaa, 0x6a, 0x74, 0x69, 0xa3, 0x0d, 0x61, 0xd0, 0x4e, 0x43,
    0x76, 0xe4, 0xbb, 0xf6, 0x38, 0x10, 0x52, 0xee, 0x9e, 0x7f, 0x33, 0x92,
    0x5c, 0x95, 0x4d, 0x52, 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4,
    0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};
#endif
#ifdef WOLFSSL_SHA384
static const byte mpfsAthenaKatSha384[144] = {
    0xff, 0xda, 0xeb, 0xff, 0x65, 0xed, 0x05, 0xcf, 0x40, 0x0f, 0x02, 0x21,
    0xc4, 0xcc, 0xfb, 0x4b, 0x21, 0x04, 0xfb, 0x6a, 0x51, 0xf8, 0x7e, 0x40,
    0xbe, 0x6c, 0x43, 0x09, 0x38, 0x6b, 0xfd, 0xec, 0x28, 0x92, 0xe9, 0x17,
    0x9b, 0x34, 0x63, 0x23, 0x31, 0xa5, 0x95, 0x92, 0x73, 0x7d, 0xb5, 0xc5,
    0x3d, 0x20, 0xe3, 0x3b, 0xa4, 0xd5, 0x2a, 0x8c, 0x37, 0x48, 0x78, 0xf1,
    0xa6, 0x24, 0xa9, 0x07, 0x13, 0x22, 0x64, 0xd0, 0xc8, 0x31, 0xc6, 0x4f,
    0xc5, 0x1e, 0xd8, 0xe1, 0xcd, 0xb7, 0x5d, 0x11, 0xc3, 0xfc, 0x78, 0xd4,
    0xc3, 0xcf, 0xbf, 0x99, 0xd7, 0xf0, 0xbe, 0xa9, 0x82, 0x9b, 0x72, 0x5c,
    0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e,
    0xb1, 0xb1, 0xe3, 0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43,
    0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf,
    0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b
};
#endif
#ifdef WC_MPFS_ATHENA_SHA512
static const byte mpfsAthenaKatSha512[192] = {
    0x1e, 0x7b, 0x80, 0xbc, 0x8e, 0xdc, 0x55, 0x2c, 0x8f, 0xee, 0xb2, 0x78,
    0x0e, 0x11, 0x14, 0x77, 0xe5, 0xbc, 0x70, 0x46, 0x5f, 0xac, 0x1a, 0x77,
    0xb2, 0x9b, 0x35, 0x98, 0x0c, 0x3f, 0x0c, 0xe4, 0xa0, 0x36, 0xa6, 0xc9,
    0x46, 0x20, 0x36, 0x82, 0x4b, 0xd5, 0x68, 0x01, 0xe6, 0x2a, 0xf7, 0xe9,
    0xfe, 0xba, 0x5c, 0x22, 0xed, 0x8a, 0x5a, 0xf8, 0x77, 0xbf, 0x7d, 0xe1,
    0x17, 0xdc, 0xac, 0x6d, 0xaf, 0x21, 0x6a, 0x71, 0x22, 0xd2, 0x9d, 0x6a,
    0x7d, 0xc7, 0xb8, 0x9c, 0x8b, 0x41, 0xc1, 0x11, 0xe7, 0xc9, 0xa0, 0x07,
    0x81, 0xd4, 0xa8, 0x67, 0xa1, 0xd7, 0x51, 0x10, 0xb4, 0x8a, 0x5a, 0x9c,
    0x92, 0xa1, 0x5d, 0x1d, 0xc2, 0xae, 0xab, 0xb5, 0x3b, 0x83, 0xbc, 0xff,
    0xc5, 0x0f, 0x44, 0xcf, 0xdc, 0xae, 0x29, 0xdc, 0x99, 0x84, 0xc8, 0xc8,
    0x4f, 0xeb, 0xd0, 0x18, 0x93, 0x22, 0xbe, 0x25, 0xcf, 0x83, 0xe1, 0x35,
    0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
    0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21,
    0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
    0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd,
    0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e
};
#endif
#if defined(WC_MPFS_ATHENA_SHA512) && !defined(WOLFSSL_NOSHA512_224)
static const byte mpfsAthenaKatSha512_224[84] = {
    0xf8, 0xb6, 0xe6, 0x39, 0x8b, 0x49, 0xc8, 0x76, 0x78, 0xa1, 0xa3, 0x23,
    0x5c, 0x07, 0x8d, 0x8d, 0xb9, 0x3f, 0xf5, 0x02, 0x71, 0xd6, 0xea, 0x36,
    0x64, 0x7f, 0x7f, 0x00, 0xb8, 0xab, 0xe8, 0x55, 0x9d, 0x49, 0x21, 0x71,
    0x2a, 0x44, 0x81, 0x5b, 0x8c, 0x4e, 0xac, 0xbe, 0x2b, 0x8d, 0x6e, 0x93,
    0xdf, 0x96, 0x60, 0x25, 0x34, 0xce, 0xf8, 0x52, 0x6e, 0xd0, 0xdd, 0x02,
    0x80, 0x6f, 0xa8, 0x9e, 0x25, 0xde, 0x06, 0x0c, 0x19, 0xd3, 0xac, 0x86,
    0xca, 0xbb, 0x87, 0xd6, 0xa0, 0xdd, 0xd0, 0x5c, 0x33, 0x3b, 0x84, 0xf4
};
#endif
#if defined(WC_MPFS_ATHENA_SHA512) && !defined(WOLFSSL_NOSHA512_256)
static const byte mpfsAthenaKatSha512_256[96] = {
    0x08, 0x37, 0xa1, 0x1d, 0x99, 0x4d, 0x5a, 0xa8, 0x60, 0xd0, 0x69, 0x17,
    0xa8, 0xa0, 0xf6, 0x3e, 0x31, 0x11, 0xb9, 0x56, 0x33, 0xde, 0xeb, 0x15,
    0xee, 0xd9, 0x94, 0x93, 0x76, 0xf3, 0x7d, 0x36, 0x1e, 0x68, 0x71, 0x79,
    0x9b, 0xdf, 0x2b, 0x39, 0x37, 0xf8, 0x45, 0x8d, 0x12, 0x4c, 0x4a, 0xe5,
    0x5a, 0xe5, 0xb4, 0x29, 0x8e, 0xf6, 0xa8, 0x3b, 0x87, 0x63, 0x07, 0x0f,
    0x4e, 0x2a, 0x0f, 0x3f, 0xc6, 0x72, 0xb8, 0xd1, 0xef, 0x56, 0xed, 0x28,
    0xab, 0x87, 0xc3, 0x62, 0x2c, 0x51, 0x14, 0x06, 0x9b, 0xdd, 0x3a, 0xd7,
    0xb8, 0xf9, 0x73, 0x74, 0x98, 0xd0, 0xc0, 0x1e, 0xce, 0xf0, 0x96, 0x7a
};
#endif

/* Each type through its own API: the generic wc_Hash*() one would link every
 * hash type. */
#ifdef WC_MPFS_ATHENA_SHA256
typedef struct MpfsAthenaKatSha256Fn {
    int  (*init)(wc_Sha256* sha, void* heap, int devId);
    int  (*update)(wc_Sha256* sha, const byte* in, word32 sz);
    int  (*final)(wc_Sha256* sha, byte* out);
    int  (*getHash)(wc_Sha256* sha, byte* out);
    void (*release)(wc_Sha256* sha);
} MpfsAthenaKatSha256Fn;
#ifdef WOLFSSL_SHA224
static const MpfsAthenaKatSha256Fn mpfsAthenaKatSha224Fn = {
    wc_InitSha224_ex, wc_Sha224Update, wc_Sha224Final, wc_Sha224GetHash,
    wc_Sha224Free
};
#endif
static const MpfsAthenaKatSha256Fn mpfsAthenaKatSha256Fn = {
    wc_InitSha256_ex, wc_Sha256Update, wc_Sha256Final, wc_Sha256GetHash,
    wc_Sha256Free
};
#endif /* WC_MPFS_ATHENA_SHA256 */

#ifdef WC_MPFS_ATHENA_SHA512_FAMILY
typedef struct MpfsAthenaKatSha512Fn {
    int  (*init)(wc_Sha512* sha, void* heap, int devId);
    int  (*update)(wc_Sha512* sha, const byte* in, word32 sz);
    int  (*final)(wc_Sha512* sha, byte* out);
    int  (*getHash)(wc_Sha512* sha, byte* out);
    void (*release)(wc_Sha512* sha);
} MpfsAthenaKatSha512Fn;
#ifdef WOLFSSL_SHA384
static const MpfsAthenaKatSha512Fn mpfsAthenaKatSha384Fn = {
    wc_InitSha384_ex, wc_Sha384Update, wc_Sha384Final, wc_Sha384GetHash,
    wc_Sha384Free
};
#endif
#ifdef WC_MPFS_ATHENA_SHA512
static const MpfsAthenaKatSha512Fn mpfsAthenaKatSha512Fn = {
    wc_InitSha512_ex, wc_Sha512Update, wc_Sha512Final, wc_Sha512GetHash,
    wc_Sha512Free
};
#ifndef WOLFSSL_NOSHA512_224
static const MpfsAthenaKatSha512Fn mpfsAthenaKatSha512_224Fn = {
    wc_InitSha512_224_ex, wc_Sha512_224Update, wc_Sha512_224Final,
    wc_Sha512_224GetHash, wc_Sha512_224Free
};
#endif
#ifndef WOLFSSL_NOSHA512_256
static const MpfsAthenaKatSha512Fn mpfsAthenaKatSha512_256Fn = {
    wc_InitSha512_256_ex, wc_Sha512_256Update, wc_Sha512_256Final,
    wc_Sha512_256GetHash, wc_Sha512_256Free
};
#endif
#endif /* WC_MPFS_ATHENA_SHA512 */
#endif /* WC_MPFS_ATHENA_SHA512_FAMILY */

typedef union MpfsAthenaKatHashObj {
#ifdef WC_MPFS_ATHENA_SHA256
    wc_Sha256 s256;
#endif
#ifdef WC_MPFS_ATHENA_SHA512_FAMILY
    wc_Sha512 s512;
#endif
} MpfsAthenaKatHashObj;

typedef struct MpfsAthenaKatSha {
    const char* name;
    const byte* exp;
    word32      sz;
    const void* fn;     /* MpfsAthenaKatSha512Fn when wide, else ...256Fn */
    int         wide;
} MpfsAthenaKatSha;

static const MpfsAthenaKatSha mpfsAthenaKatShas[] = {
#if defined(WC_MPFS_ATHENA_SHA256) && defined(WOLFSSL_SHA224)
    { "SHA-224", mpfsAthenaKatSha224, WC_SHA224_DIGEST_SIZE,
      &mpfsAthenaKatSha224Fn, 0 },
#endif
#ifdef WC_MPFS_ATHENA_SHA256
    { "SHA-256", mpfsAthenaKatSha256, WC_SHA256_DIGEST_SIZE,
      &mpfsAthenaKatSha256Fn, 0 },
#endif
#ifdef WOLFSSL_SHA384
    { "SHA-384", mpfsAthenaKatSha384, WC_SHA384_DIGEST_SIZE,
      &mpfsAthenaKatSha384Fn, 1 },
#endif
#ifdef WC_MPFS_ATHENA_SHA512
    { "SHA-512", mpfsAthenaKatSha512, WC_SHA512_DIGEST_SIZE,
      &mpfsAthenaKatSha512Fn, 1 },
#endif
#if defined(WC_MPFS_ATHENA_SHA512) && !defined(WOLFSSL_NOSHA512_224)
    { "SHA-512/224", mpfsAthenaKatSha512_224, WC_SHA512_224_DIGEST_SIZE,
      &mpfsAthenaKatSha512_224Fn, 1 },
#endif
#if defined(WC_MPFS_ATHENA_SHA512) && !defined(WOLFSSL_NOSHA512_256)
    { "SHA-512/256", mpfsAthenaKatSha512_256, WC_SHA512_256_DIGEST_SIZE,
      &mpfsAthenaKatSha512_256Fn, 1 },
#endif
};

enum {
    MPFS_ATHENA_KAT_INIT,
    MPFS_ATHENA_KAT_UPDATE,
    MPFS_ATHENA_KAT_FINAL,
    MPFS_ATHENA_KAT_GETHASH,
    MPFS_ATHENA_KAT_FREE
};

static int wc_MpfsAthenaKatHashOp(const MpfsAthenaKatSha* kat, int op,
    MpfsAthenaKatHashObj* o, const byte* in, word32 sz, byte* out)
{
#ifdef WC_MPFS_ATHENA_SHA512_FAMILY
    if (kat->wide) {
        const MpfsAthenaKatSha512Fn* f = (const MpfsAthenaKatSha512Fn*)kat->fn;
        switch (op) {
            case MPFS_ATHENA_KAT_INIT:
                return f->init(&o->s512, NULL, WC_MPFS_ATHENA_DEVID);
            case MPFS_ATHENA_KAT_UPDATE:
                return f->update(&o->s512, in, sz);
            case MPFS_ATHENA_KAT_FINAL:
                return f->final(&o->s512, out);
            case MPFS_ATHENA_KAT_GETHASH:
                return f->getHash(&o->s512, out);
            default:
                f->release(&o->s512);
                return 0;
        }
    }
#endif
#ifdef WC_MPFS_ATHENA_SHA256
    if (!kat->wide) {
        const MpfsAthenaKatSha256Fn* f = (const MpfsAthenaKatSha256Fn*)kat->fn;
        switch (op) {
            case MPFS_ATHENA_KAT_INIT:
                return f->init(&o->s256, NULL, WC_MPFS_ATHENA_DEVID);
            case MPFS_ATHENA_KAT_UPDATE:
                return f->update(&o->s256, in, sz);
            case MPFS_ATHENA_KAT_FINAL:
                return f->final(&o->s256, out);
            case MPFS_ATHENA_KAT_GETHASH:
                return f->getHash(&o->s256, out);
            default:
                f->release(&o->s256);
                return 0;
        }
    }
#endif
    (void)op;
    (void)o;
    (void)in;
    (void)sz;
    (void)out;
    return BAD_FUNC_ARG;
}

/* buf holds 0x00..0xFF, then room for a digest. 100 + 100 + 56 buffers,
 * flushes on full twice and leaves the final carrying zero bytes. */
static int wc_MpfsAthenaKatSha(const MpfsAthenaKatSha* kat, const byte* buf,
    byte* digest)
{
    MpfsAthenaKatHashObj o;
    word32 calls;
    int ret;

    calls = mpfsAthenaCbCalls;
    ret = wc_MpfsAthenaKatHashOp(kat, MPFS_ATHENA_KAT_INIT, &o, NULL, 0,
        NULL);
    if (ret == 0) {
        ret = wc_MpfsAthenaKatHashOp(kat, MPFS_ATHENA_KAT_UPDATE, &o, buf,
            100, NULL);
        if (ret == 0) {
            ret = wc_MpfsAthenaKatHashOp(kat, MPFS_ATHENA_KAT_UPDATE, &o,
                buf + 100, 100, NULL);
        }
        if (ret == 0) {
            ret = wc_MpfsAthenaKatHashOp(kat, MPFS_ATHENA_KAT_UPDATE, &o,
                buf + 200, 56, NULL);
        }
        if (ret == 0) {
            ret = wc_MpfsAthenaKatHashOp(kat, MPFS_ATHENA_KAT_FINAL, &o, NULL,
                0, digest);
        }
        (void)wc_MpfsAthenaKatHashOp(kat, MPFS_ATHENA_KAT_FREE, &o, NULL, 0,
            NULL);
    }
    ret = wc_MpfsAthenaKatCheck(kat->name, "digest", ret, 1, calls, digest,
        kat->exp, kat->sz);

    /* The empty message, which the engine takes as a zero-length final. */
    if (ret == 0) {
        calls = mpfsAthenaCbCalls;
        ret = wc_MpfsAthenaKatHashOp(kat, MPFS_ATHENA_KAT_INIT, &o, NULL, 0,
            NULL);
        if (ret == 0) {
            ret = wc_MpfsAthenaKatHashOp(kat, MPFS_ATHENA_KAT_FINAL, &o, NULL,
                0, digest);
            (void)wc_MpfsAthenaKatHashOp(kat, MPFS_ATHENA_KAT_FREE, &o, NULL,
                0, NULL);
        }
        ret = wc_MpfsAthenaKatCheck(kat->name, "empty message", ret, 1, calls,
            digest, kat->exp + 2 * kat->sz, kat->sz);
    }

    /* GetHash() is copy-then-final: the copy must fork the live engine
     * context and leave the original able to finish the full digest. */
    if (ret == 0) {
        ret = wc_MpfsAthenaKatHashOp(kat, MPFS_ATHENA_KAT_INIT, &o, NULL, 0,
            NULL);
        if (ret == 0) {
            ret = wc_MpfsAthenaKatHashOp(kat, MPFS_ATHENA_KAT_UPDATE, &o, buf,
                100, NULL);
            if (ret == 0) {
                ret = wc_MpfsAthenaKatHashOp(kat, MPFS_ATHENA_KAT_GETHASH, &o,
                    NULL, 0, digest);
            }
            ret = wc_MpfsAthenaKatCheck(kat->name, "mid-stream GetHash", ret,
                -1, 0, digest, kat->exp + kat->sz, kat->sz);
            if (ret == 0) {
                ret = wc_MpfsAthenaKatHashOp(kat, MPFS_ATHENA_KAT_UPDATE, &o,
                    buf + 100, 156, NULL);
                if (ret == 0) {
                    ret = wc_MpfsAthenaKatHashOp(kat, MPFS_ATHENA_KAT_FINAL,
                        &o, NULL, 0, digest);
                }
                ret = wc_MpfsAthenaKatCheck(kat->name, "digest after a copy",
                    ret, -1, 0, digest, kat->exp, kat->sz);
            }
            (void)wc_MpfsAthenaKatHashOp(kat, MPFS_ATHENA_KAT_FREE, &o, NULL,
                0, NULL);
        }
        else {
            wc_MpfsAthenaKatFail(kat->name, "copy", "init failed");
        }
    }
    return ret;
}
#endif /* WC_MPFS_ATHENA_HASH */

#ifdef WC_MPFS_ATHENA_KAT_AES
/* Per key size: key 0x00.., IV or counter 0x00..0x0F, input 0x00.., with the
 * output of each mode at these offsets. */
#define MPFS_ATHENA_KAT_ECB   0     /* 32 bytes */
#define MPFS_ATHENA_KAT_CTR   32    /* 32 bytes */
#define MPFS_ATHENA_KAT_CBC   64    /* 64 bytes */
#define MPFS_ATHENA_KAT_GCM   128   /* 40, IV 0x00..0x0B, AAD 0x00..0x13; tag */
#define MPFS_ATHENA_KAT_GMAC  184   /* the tag of that AAD alone */
#define MPFS_ATHENA_KAT_KW    200   /* RFC 3394 wrap of 0x0011..FF0001..0F */
#define MPFS_ATHENA_KAT_CMAC  240   /* of 16 bytes */
#ifdef WOLFSSL_AES_128
static const byte mpfsAthenaKatAes128[256] = {
    0x0a, 0x94, 0x0b, 0xb5, 0x41, 0x6e, 0xf0, 0x45, 0xf1, 0xc3, 0x94, 0x58,
    0xc6, 0x53, 0xea, 0x5a, 0x07, 0xfe, 0xef, 0x74, 0xe1, 0xd5, 0x03, 0x6e,
    0x90, 0x0e, 0xee, 0x11, 0x8e, 0x94, 0x92, 0x93, 0x0a, 0x95, 0x09, 0xb6,
    0x45, 0x6b, 0xf6, 0x42, 0xf9, 0xca, 0x9e, 0x53, 0xca, 0x5e, 0xe4, 0x55,
    0x12, 0x72, 0xfe, 0x87, 0x72, 0x0d, 0x64, 0x81, 0x82, 0xc3, 0xe7, 0x14,
    0x57, 0xb9, 0x11, 0xc3, 0xc6, 0xa1, 0x3b, 0x37, 0x87, 0x8f, 0x5b, 0x82,
    0x6f, 0x4f, 0x81, 0x62, 0xa1, 0xc8, 0xd8, 0x79, 0x35, 0xd9, 0xdc, 0xdb,
    0x82, 0x9f, 0xec, 0x33, 0x52, 0xe7, 0xbf, 0x10, 0xb8, 0x4b, 0xe4, 0xa5,
    0x7b, 0x30, 0x46, 0x46, 0x05, 0xf0, 0x2a, 0x09, 0x4c, 0x0a, 0xf7, 0xad,
    0x98, 0x4f, 0x61, 0xfc, 0xd8, 0x84, 0x34, 0xa5, 0x59, 0x1d, 0xbc, 0x8f,
    0xd9, 0x63, 0x08, 0x12, 0xd3, 0xa2, 0x7b, 0x87, 0x93, 0x6d, 0xa5, 0xcd,
    0x62, 0x1e, 0xf1, 0x53, 0x43, 0xdb, 0x6b, 0x81, 0x3a, 0xae, 0x7e, 0x07,
    0xa3, 0x37, 0x08, 0xf5, 0x47, 0xf8, 0xeb, 0xe1, 0xfe, 0x38, 0xeb, 0x36,
    0x08, 0x59, 0xbc, 0x73, 0xa5, 0x85, 0xf9, 0xd4, 0xd0, 0xa5, 0x91, 0xc4,
    0xc4, 0x38, 0x6d, 0x85, 0x29, 0xf1, 0x67, 0x08, 0xe7, 0x58, 0x08, 0x00,
    0xce, 0x77, 0x72, 0xee, 0xf9, 0x48, 0x09, 0x97, 0x7f, 0xa6, 0x8b, 0xdb,
    0x06, 0x40, 0xdc, 0xf3, 0x1c, 0xa6, 0xb8, 0x9d, 0x11, 0x82, 0x68, 0x40,
    0x77, 0x4d, 0x99, 0x3f, 0xf9, 0xc2, 0xfa, 0x02, 0xcc, 0xa3, 0xce, 0xa0,
    0xe9, 0x3b, 0x1e, 0x1c, 0xf9, 0x63, 0x61, 0xf9, 0x3e, 0xa6, 0xdc, 0x2f,
    0x34, 0x51, 0x94, 0xe7, 0xb3, 0x0f, 0x96, 0x4c, 0x79, 0xf9, 0xe6, 0x1d,
    0x7b, 0xcf, 0xbb, 0xca, 0x7a, 0x2e, 0xa6, 0x8b, 0x96, 0x6f, 0xc5, 0x39,
    0x9f, 0x74, 0x80, 0x9e
};
#endif
#ifdef WOLFSSL_AES_192
static const byte mpfsAthenaKatAes192[256] = {
    0x00, 0x60, 0xbf, 0xfe, 0x46, 0x83, 0x4b, 0xb8, 0xda, 0x5c, 0xf9, 0xa6,
    0x1f, 0xf2, 0x20, 0xae, 0x93, 0xae, 0x3b, 0x7f, 0x9f, 0xc2, 0xe8, 0x15,
    0x9d, 0x05, 0xa6, 0xa9, 0xf5, 0xe2, 0x4f, 0x2d, 0x00, 0x61, 0xbd, 0xfd,
    0x42, 0x86, 0x4d, 0xbf, 0xd2, 0x55, 0xf3, 0xad, 0x13, 0xff, 0x2e, 0xa1,
    0x39, 0xe6, 0x71, 0xfb, 0xb5, 0x60, 0xd0, 0xa8, 0xbd, 0x4d, 0x8e, 0x92,
    0x0e, 0x99, 0x5b, 0xea, 0x91, 0x62, 0x51, 0x82, 0x1c, 0x73, 0xa5, 0x22,
    0xc3, 0x96, 0xd6, 0x27, 0x38, 0x01, 0x96, 0x07, 0x18, 0x17, 0xdb, 0x15,
    0x0e, 0x77, 0x1c, 0x58, 0x9e, 0xd0, 0x80, 0x49, 0x3d, 0xe7, 0x33, 0x8b,
    0xb4, 0x1e, 0xee, 0x4c, 0x09, 0x68, 0x4a, 0xda, 0xa2, 0x42, 0x90, 0x64,
    0x90, 0x87, 0xa0, 0x27, 0x59, 0x41, 0x35, 0x85, 0xdc, 0xa6, 0x20, 0xc7,
    0x09, 0xdb, 0x9c, 0xb7, 0x74, 0x70, 0x72, 0x88, 0xe6, 0xf8, 0x20, 0x98,
    0x9d, 0xbc, 0xcf, 0x09, 0xd8, 0x3a, 0xd6, 0x89, 0xf3, 0xa4, 0xd2, 0x7f,
    0x1e, 0x8e, 0x21, 0x18, 0x2c, 0xb4, 0x40, 0xa9, 0x67, 0x46, 0x71, 0x23,
    0xd1, 0x8b, 0x3f, 0x43, 0xf7, 0x55, 0xd5, 0x52, 0x3e, 0x79, 0x2b, 0x2c,
    0xfc, 0x19, 0x04, 0x3a, 0xd0, 0x44, 0x99, 0x5d, 0x7b, 0x26, 0xd4, 0x64,
    0x40, 0xd4, 0x1f, 0x0f, 0xe7, 0xc8, 0x42, 0xe1, 0x18, 0xef, 0x68, 0xd5,
    0x5e, 0x8d, 0x68, 0x0b, 0x90, 0x64, 0xc2, 0xad, 0x08, 0x86, 0x1e, 0x00,
    0x0a, 0xab, 0xfa, 0x44, 0x79, 0xc7, 0x19, 0x1f, 0x9d, 0xc5, 0x1c, 0xca,
    0x37, 0xc5, 0x0f, 0x16, 0xcc, 0x14, 0x44, 0x1c, 0x6e, 0xa4, 0x98, 0x0c,
    0xfc, 0xe0, 0xf4, 0x1d, 0x92, 0x85, 0x75, 0x8c, 0x6f, 0x74, 0xac, 0x6d,
    0xf8, 0x1b, 0xde, 0x00, 0x69, 0xa6, 0xe3, 0x89, 0x57, 0x3b, 0xf0, 0x4e,
    0x7c, 0xde, 0x68, 0x8c
};
#endif
#ifdef WOLFSSL_AES_256
static const byte mpfsAthenaKatAes256[256] = {
    0x5a, 0x6e, 0x04, 0x57, 0x08, 0xfb, 0x71, 0x96, 0xf0, 0x2e, 0x55, 0x3d,
    0x02, 0xc3, 0xa6, 0x92, 0xe9, 0xc3, 0xef, 0x8a, 0xb2, 0x34, 0x53, 0xe6,
    0xf0, 0x74, 0x9c, 0xd6, 0x36, 0xe7, 0xa8, 0x8e, 0x5a, 0x6f, 0x06, 0x54,
    0x0c, 0xfe, 0x77, 0x91, 0xf8, 0x27, 0x5f, 0x36, 0x0e, 0xce, 0xa8, 0x9d,
    0x70, 0xe2, 0x02, 0xc6, 0xd7, 0x90, 0x4e, 0x4a, 0x4d, 0x0f, 0xe1, 0x4a,
    0x6e, 0xf8, 0x3e, 0xd0, 0xf2, 0x90, 0x00, 0xb6, 0x2a, 0x49, 0x9f, 0xd0,
    0xa9, 0xf3, 0x9a, 0x6a, 0xdd, 0x2e, 0x77, 0x80, 0x95, 0x43, 0xb8, 0x6f,
    0xc0, 0x46, 0xfa, 0x88, 0x3a, 0x94, 0x46, 0xb8, 0x2e, 0x47, 0xd1, 0x2d,
    0xa1, 0x44, 0xfc, 0x25, 0x5a, 0xad, 0x45, 0xbf, 0x68, 0x1d, 0x3a, 0x37,
    0x73, 0xa3, 0x25, 0xc2, 0x93, 0x68, 0x8f, 0x47, 0xda, 0xdb, 0xc9, 0xa6,
    0xe1, 0xad, 0xca, 0xae, 0x6a, 0x1e, 0x3b, 0xd7, 0x47, 0x03, 0xd4, 0x18,
    0xc1, 0xe0, 0xc4, 0x1c, 0x85, 0x48, 0x9d, 0x80, 0xbd, 0xe4, 0x76, 0x62,
    0x93, 0xc7, 0x95, 0x27, 0xe4, 0x6e, 0x49, 0x6b, 0x20, 0x7e, 0xff, 0x9e,
    0x01, 0x74, 0x1e, 0xad, 0x21, 0x31, 0x8c, 0xdf, 0x8b, 0xe4, 0x34, 0xbf,
    0x5b, 0xbe, 0x34, 0x37, 0xf9, 0x88, 0x88, 0x45, 0x7b, 0xeb, 0x56, 0x85,
    0x77, 0xbd, 0xfc, 0x8f, 0x7f, 0xa7, 0xad, 0xf4, 0x07, 0x2a, 0x73, 0xa7,
    0x1e, 0xff, 0x0a, 0x32, 0xb5, 0x9c, 0xe3, 0x64, 0x28, 0xc9, 0xf4, 0x04,
    0xc4, 0xb8, 0x10, 0xf4, 0xcb, 0xcc, 0xb3, 0x5c, 0xfb, 0x87, 0xf8, 0x26,
    0x3f, 0x57, 0x86, 0xe2, 0xd8, 0x0e, 0xd3, 0x26, 0xcb, 0xc7, 0xf0, 0xe7,
    0x1a, 0x99, 0xf4, 0x3b, 0xfb, 0x98, 0x8b, 0x9b, 0x7a, 0x02, 0xdd, 0x21,
    0x59, 0xee, 0x3f, 0x3b, 0x5f, 0x83, 0xe2, 0x90, 0xca, 0xe2, 0x6d, 0xad,
    0x29, 0xbb, 0xa3, 0x2d
};
#endif

#if defined(WOLFSSL_AES_COUNTER) && defined(WOLFSSL_AES_256)
/* AES-256-CTR of 0x00..0x2F, counter 0x00..0x0B ff ff ff fe: the third block
 * is past the low word's wrap, which the engine does not carry on its own. */
static const byte mpfsAthenaKatAesCtrWrap[48] = {
    0x8b, 0x65, 0xb1, 0x2c, 0xf3, 0xb6, 0x96, 0x55, 0xb3, 0xa0, 0x70, 0x5f,
    0x80, 0xd8, 0x41, 0x6b, 0x8d, 0x43, 0xf8, 0x94, 0x09, 0x22, 0xf4, 0x11,
    0xae, 0x57, 0x8a, 0x36, 0x01, 0x98, 0x60, 0x5b, 0xfa, 0x87, 0x6a, 0xdc,
    0xe3, 0xea, 0xe5, 0x81, 0xf1, 0xdf, 0x7e, 0xb2, 0xd3, 0x26, 0x39, 0xae
};
#endif

#if defined(WC_MPFS_ATHENA_KEYWRAP) && defined(WOLFSSL_AES_KEYWRAP_PADDING) && \
    defined(WOLFSSL_AES_192)
/* RFC 5649 section 6, first example: the 192-bit KEK, the 20-byte key and its
 * 32-byte wrap. */
static const byte mpfsAthenaKatKwp[76] = {
    0x58, 0x40, 0xdf, 0x6e, 0x29, 0xb0, 0x2a, 0xf1, 0xab, 0x49, 0x3b, 0x70,
    0x5b, 0xf1, 0x6e, 0xa1, 0xae, 0x83, 0x38, 0xf4, 0xdc, 0xc1, 0x76, 0xa8,
    0xc3, 0x7b, 0x7e, 0x64, 0x92, 0x58, 0x43, 0x40, 0xbe, 0xd1, 0x22, 0x07,
    0x80, 0x89, 0x41, 0x15, 0x50, 0x68, 0xf7, 0x38, 0x13, 0x8b, 0xde, 0xaa,
    0x9b, 0x8f, 0xa7, 0xfc, 0x61, 0xf9, 0x77, 0x42, 0xe7, 0x22, 0x48, 0xee,
    0x5a, 0xe6, 0xae, 0x53, 0x60, 0xd1, 0xae, 0x6a, 0x5f, 0x54, 0xf3, 0x73,
    0xfa, 0x54, 0x3b, 0x6a
};
#endif

typedef struct MpfsAthenaKatAes {
    const char* name;
    const byte* exp;
    word32      keySz;
} MpfsAthenaKatAes;

static const MpfsAthenaKatAes mpfsAthenaKatAess[] = {
#ifdef WOLFSSL_AES_128
    { "AES-128", mpfsAthenaKatAes128, 16 },
#endif
#ifdef WOLFSSL_AES_192
    { "AES-192", mpfsAthenaKatAes192, 24 },
#endif
#ifdef WOLFSSL_AES_256
    { "AES-256", mpfsAthenaKatAes256, 32 },
#endif
};

/* An ECB call of at least WC_MPFS_ATHENA_AES_MIN_SZ, or the engine declines;
 * 16, not WC_AES_BLOCK_SIZE, which the preprocessor reads as 0. */
#if WC_MPFS_ATHENA_AES_MIN_SZ > 32
    #define WC_MPFS_ATHENA_KAT_ECB_SZ \
        (((WC_MPFS_ATHENA_AES_MIN_SZ + 15) / 16) * 16)
#else
    #define WC_MPFS_ATHENA_KAT_ECB_SZ 32
#endif
/* The AES KAT's input and its output area are this size each. */
#if WC_MPFS_ATHENA_KAT_ECB_SZ > 128
    #define WC_MPFS_ATHENA_KAT_AES_SZ WC_MPFS_ATHENA_KAT_ECB_SZ
#else
    #define WC_MPFS_ATHENA_KAT_AES_SZ 128
#endif

#ifdef WOLFSSL_AES_COUNTER
/* sz bytes as two calls split at split: the engine advances the counter in
 * aes->reg, and a partial block leaves keystream in aes->tmp. */
static int wc_MpfsAthenaKatCtr(Aes* aes, const byte* key, word32 keySz,
    const byte* ctr, const byte* in, byte* out, word32 sz, word32 split)
{
    int ret;

    ret = wc_AesSetKey(aes, key, keySz, ctr, AES_ENCRYPTION);
    if (ret == 0) {
        ret = wc_AesCtrEncrypt(aes, out, in, split);
    }
    if (ret == 0 && split < sz) {
        ret = wc_AesCtrEncrypt(aes, out + split, in + split, sz - split);
    }
    return ret;
}
#endif

/* buf is two word-aligned WC_MPFS_ATHENA_KAT_AES_SZ areas: the input
 * 0x00.., and the output; key wrap declines unaligned buffers. */
static int wc_MpfsAthenaKatAes(const MpfsAthenaKatAes* kat, byte* buf)
{
    Aes aes;
    byte key[32];
    byte iv[WC_AES_BLOCK_SIZE];
    byte* in = buf;
    byte* out = buf + WC_MPFS_ATHENA_KAT_AES_SZ;
    const char* name = kat->name;
    word32 calls = 0;
    int ret;
    int i;

    wc_MpfsAthenaKatSeq(key, sizeof(key), 0);
    wc_MpfsAthenaKatSeq(iv, sizeof(iv), 0);
    wc_MpfsAthenaKatSeq(in, WC_MPFS_ATHENA_KAT_AES_SZ, 0);
    (void)out;
    (void)calls;
    (void)i;

    ret = wc_AesInit(&aes, NULL, WC_MPFS_ATHENA_DEVID);
    if (ret != 0) {
        wc_MpfsAthenaKatFail(name, "init", "failed");
        ForceZero(key, sizeof(key));
        return ret;
    }

#ifdef HAVE_AES_ECB
    /* Distinct buffers, then in place, which is what XTS sends. */
    ret = wc_AesSetKey(&aes, key, kat->keySz, NULL, AES_ENCRYPTION);
    if (ret == 0) {
        calls = mpfsAthenaCbCalls;
        ret = wc_AesEcbEncrypt(&aes, out, in, WC_MPFS_ATHENA_KAT_ECB_SZ);
    }
    ret = wc_MpfsAthenaKatCheck(name, "ECB encrypt", ret, 1, calls, out,
        kat->exp + MPFS_ATHENA_KAT_ECB, 32);
#ifdef HAVE_AES_DECRYPT
    if (ret == 0) {
        ret = wc_AesSetKey(&aes, key, kat->keySz, NULL, AES_DECRYPTION);
        calls = mpfsAthenaCbCalls;
        if (ret == 0) {
            ret = wc_AesEcbDecrypt(&aes, out, out, WC_MPFS_ATHENA_KAT_ECB_SZ);
        }
        ret = wc_MpfsAthenaKatCheck(name, "ECB in-place decrypt", ret, 1,
            calls, out, in, WC_MPFS_ATHENA_KAT_ECB_SZ);
    }
#endif
    if (ret == 0) {
        ret = wc_AesSetKey(&aes, key, kat->keySz, NULL, AES_ENCRYPTION);
        XMEMCPY(out, in, WC_MPFS_ATHENA_KAT_ECB_SZ);
        calls = mpfsAthenaCbCalls;
        if (ret == 0) {
            ret = wc_AesEcbEncrypt(&aes, out, out, WC_MPFS_ATHENA_KAT_ECB_SZ);
        }
        ret = wc_MpfsAthenaKatCheck(name, "ECB in-place encrypt", ret, 1,
            calls, out, kat->exp + MPFS_ATHENA_KAT_ECB, 32);
    }
#if WC_MPFS_ATHENA_AES_MIN_SZ > 16
    /* One block is below the minimum: software serves it on this context. */
    if (ret == 0) {
        calls = mpfsAthenaCbCalls;
        ret = wc_AesEcbEncrypt(&aes, out, in, WC_AES_BLOCK_SIZE);
        ret = wc_MpfsAthenaKatCheck(name, "ECB one block", ret, 0, calls, out,
            kat->exp + MPFS_ATHENA_KAT_ECB, WC_AES_BLOCK_SIZE);
    }
#endif
#endif /* HAVE_AES_ECB */

#ifdef WOLFSSL_AES_COUNTER
    /* One call; 16 + 16, which must carry the counter; 20 + 12, where the
     * second call is served from the keystream left over, with no engine. */
    if (ret == 0) {
        calls = mpfsAthenaCbCalls;
        ret = wc_MpfsAthenaKatCtr(&aes, key, kat->keySz, iv, in, out, 32, 32);
        ret = wc_MpfsAthenaKatCheck(name, "CTR", ret, 1, calls, out,
            kat->exp + MPFS_ATHENA_KAT_CTR, 32);
    }
    if (ret == 0) {
        XMEMSET(out, 0, 32);
        ret = wc_MpfsAthenaKatCtr(&aes, key, kat->keySz, iv, in, out, 32, 16);
        ret = wc_MpfsAthenaKatCheck(name, "CTR 16 + 16", ret, -1, 0, out,
            kat->exp + MPFS_ATHENA_KAT_CTR, 32);
    }
    if (ret == 0) {
        XMEMSET(out, 0, 32);
        ret = wc_MpfsAthenaKatCtr(&aes, key, kat->keySz, iv, in, out, 32, 20);
        ret = wc_MpfsAthenaKatCheck(name, "CTR 20 + 12", ret, -1, 0, out,
            kat->exp + MPFS_ATHENA_KAT_CTR, 32);
    }
#ifdef WOLFSSL_AES_256
    if (ret == 0 && kat->keySz == 32) {
        byte ctr[WC_AES_BLOCK_SIZE];

        XMEMCPY(ctr, iv, sizeof(ctr));
        ctr[12] = 0xff; ctr[13] = 0xff; ctr[14] = 0xff; ctr[15] = 0xfe;
        ret = wc_MpfsAthenaKatCtr(&aes, key, kat->keySz, ctr, in, out, 48, 48);
        ret = wc_MpfsAthenaKatCheck(name, "CTR past 32 bits", ret, -1, 0,
            out, mpfsAthenaKatAesCtrWrap, sizeof(mpfsAthenaKatAesCtrWrap));
    }
#endif
#endif /* WOLFSSL_AES_COUNTER */

#ifdef WC_MPFS_ATHENA_CBC
    /* Two 32-byte calls in place must equal one run: the chaining value is
     * kept in aes->reg, and the in-place decrypt must save it first. */
    if (ret == 0) {
        ret = wc_AesSetKey(&aes, key, kat->keySz, iv, AES_ENCRYPTION);
        XMEMCPY(out, in, 64);
        calls = mpfsAthenaCbCalls;
        if (ret == 0) {
            ret = wc_AesCbcEncrypt(&aes, out, out, 32);
        }
        if (ret == 0) {
            ret = wc_AesCbcEncrypt(&aes, out + 32, out + 32, 32);
        }
        ret = wc_MpfsAthenaKatCheck(name, "CBC encrypt", ret,
            (WC_MPFS_ATHENA_AES_MIN_SZ <= 32) ? 1 : -1, calls, out,
            kat->exp + MPFS_ATHENA_KAT_CBC, 64);
    }
#ifdef HAVE_AES_DECRYPT
    if (ret == 0) {
        ret = wc_AesSetKey(&aes, key, kat->keySz, iv, AES_DECRYPTION);
        calls = mpfsAthenaCbCalls;
        if (ret == 0) {
            ret = wc_AesCbcDecrypt(&aes, out, out, 32);
        }
        if (ret == 0) {
            ret = wc_AesCbcDecrypt(&aes, out + 32, out + 32, 32);
        }
        ret = wc_MpfsAthenaKatCheck(name, "CBC in-place decrypt", ret,
            (WC_MPFS_ATHENA_AES_MIN_SZ <= 32) ? 1 : -1, calls, out, in, 64);
    }
#endif
#endif /* WC_MPFS_ATHENA_CBC */

#ifdef WC_MPFS_ATHENA_GCM
    /* A partial final block and a partial AAD block; the tag lands after the
     * ciphertext and the decrypt at out + 64. */
    if (ret == 0) {
        ret = wc_AesGcmSetKey(&aes, key, kat->keySz);
        calls = mpfsAthenaCbCalls;
        if (ret == 0) {
            ret = wc_AesGcmEncrypt(&aes, out, in, 40, iv, GCM_NONCE_MID_SZ,
                out + 40, WC_AES_BLOCK_SIZE, in, 20);
        }
        ret = wc_MpfsAthenaKatCheck(name, "GCM encrypt", ret,
            (WC_MPFS_ATHENA_GCM_MIN_SZ <= 40) ? 1 : -1, calls, out,
            kat->exp + MPFS_ATHENA_KAT_GCM, 56);
    }
#ifdef HAVE_AES_DECRYPT
    if (ret == 0) {
        calls = mpfsAthenaCbCalls;
        ret = wc_AesGcmDecrypt(&aes, out + 64, out, 40, iv, GCM_NONCE_MID_SZ,
            out + 40, WC_AES_BLOCK_SIZE, in, 20);
        ret = wc_MpfsAthenaKatCheck(name, "GCM decrypt", ret,
            (WC_MPFS_ATHENA_GCM_MIN_SZ <= 40) ? 1 : -1, calls, out + 64, in,
            40);
    }
#endif
    if (ret == 0) {
        calls = mpfsAthenaCbCalls;
        ret = wc_AesGcmEncrypt(&aes, NULL, NULL, 0, iv, GCM_NONCE_MID_SZ,
            out + 112, WC_AES_BLOCK_SIZE, in, 20);
        ret = wc_MpfsAthenaKatCheck(name, "GMAC", ret,
            (WC_MPFS_ATHENA_GCM_MIN_SZ == 0) ? 1 : -1, calls, out + 112,
            kat->exp + MPFS_ATHENA_KAT_GMAC, WC_AES_BLOCK_SIZE);
    }
#ifdef HAVE_AES_DECRYPT
    if (ret == 0) {
        ret = wc_AesGcmDecrypt(&aes, NULL, NULL, 0, iv, GCM_NONCE_MID_SZ,
            out + 112, WC_AES_BLOCK_SIZE, in, 20);
        ret = wc_MpfsAthenaKatCheck(name, "GMAC verify", ret, -1, 0, NULL,
            NULL, 0);
    }
    /* A corrupted tag must fail authentication and release no plaintext. */
    if (ret == 0) {
        out[40] ^= 0x01;
        XMEMSET(out + 64, 0xA5, 40);
        ret = wc_AesGcmDecrypt(&aes, out + 64, out, 40, iv, GCM_NONCE_MID_SZ,
            out + 40, WC_AES_BLOCK_SIZE, in, 20);
        ret = wc_MpfsAthenaKatCheck(name, "GCM bad tag",
            (ret == WC_NO_ERR_TRACE(AES_GCM_AUTH_E)) ? 0 : WC_HW_E, -1, 0,
            NULL, NULL, 0);
        for (i = 64; ret == 0 && i < 104; i++) {
            if (out[i] != 0) {
                wc_MpfsAthenaKatFail(name, "GCM bad tag", "plaintext released");
                ret = WC_HW_E;
            }
        }
    }
#endif
#endif /* WC_MPFS_ATHENA_GCM */

#ifdef WC_MPFS_ATHENA_KEYWRAP
    /* The key at out, its wrap at out + 32, the unwrap at out + 72: an unwrap
     * writes the initial value first, so it needs the whole 40 bytes. */
    if (ret == 0) {
        for (i = 0; i < 16; i++) {
            out[i] = (byte)(i * 0x11);
        }
        wc_MpfsAthenaKatSeq(out + 16, 16, 0);
        ret = wc_AesSetKey(&aes, key, kat->keySz, NULL, AES_ENCRYPTION);
        calls = mpfsAthenaCbCalls;
        if (ret == 0) {
            ret = wc_AesKeyWrap_ex(&aes, out, 32, out + 32, 40, NULL);
            ret = (ret == 40) ? 0 : ((ret < 0) ? ret : WC_HW_E);
        }
        ret = wc_MpfsAthenaKatCheck(name, "key wrap", ret, 1, calls, out + 32,
            kat->exp + MPFS_ATHENA_KAT_KW, 40);
    }
#ifdef HAVE_AES_DECRYPT
    if (ret == 0) {
        ret = wc_AesSetKey(&aes, key, kat->keySz, NULL, AES_DECRYPTION);
        calls = mpfsAthenaCbCalls;
        if (ret == 0) {
            ret = wc_AesKeyUnWrap_ex(&aes, out + 32, 40, out + 72, 40, NULL);
            ret = (ret == 32) ? 0 : ((ret < 0) ? ret : WC_HW_E);
        }
        ret = wc_MpfsAthenaKatCheck(name, "key unwrap", ret, 1, calls,
            out + 72, out, 32);
    }
    if (ret == 0) {
        out[32] ^= 0x01;
        ret = wc_AesKeyUnWrap_ex(&aes, out + 32, 40, out + 72, 40, NULL);
        ret = wc_MpfsAthenaKatCheck(name, "key unwrap bad wrap",
            (ret == WC_NO_ERR_TRACE(BAD_KEYWRAP_IV_E)) ? 0 : WC_HW_E, -1, 0,
            NULL, NULL, 0);
    }
#endif
#if defined(WOLFSSL_AES_KEYWRAP_PADDING) && defined(WOLFSSL_AES_192)
    if (ret == 0 && kat->keySz == 24) {
        ret = wc_AesSetKey(&aes, mpfsAthenaKatKwp, 24, NULL, AES_ENCRYPTION);
        XMEMCPY(out, mpfsAthenaKatKwp + 24, 20);
        calls = mpfsAthenaCbCalls;
        if (ret == 0) {
            ret = wc_AesKeyWrap_Pad_ex(&aes, out, 20, out + 32, 40, NULL);
            ret = (ret == 32) ? 0 : ((ret < 0) ? ret : WC_HW_E);
        }
        ret = wc_MpfsAthenaKatCheck(name, "key wrap with padding", ret, 1,
            calls, out + 32, mpfsAthenaKatKwp + 44, 32);
    }
#endif
#endif /* WC_MPFS_ATHENA_KEYWRAP */

    wc_AesFree(&aes);
    ForceZero(key, sizeof(key));
    return ret;
}

#if defined(WC_MPFS_ATHENA_CMAC) && defined(WOLFSSL_AES_DIRECT)
/* Apart from the AES KAT so its Aes and this Cmac are not both on the stack. */
static int wc_MpfsAthenaKatCmac(const MpfsAthenaKatAes* kat, byte* buf)
{
    Cmac cmac;
    byte key[32];
    byte tag[WC_AES_BLOCK_SIZE];
    word32 tagSz = sizeof(tag);
    word32 calls;
    int ret;

    wc_MpfsAthenaKatSeq(key, sizeof(key), 0);
    wc_MpfsAthenaKatSeq(buf, 16, 0);
    calls = mpfsAthenaCbCalls;
    ret = wc_AesCmacGenerate_ex(&cmac, tag, &tagSz, buf, 16, key, kat->keySz,
        NULL, WC_MPFS_ATHENA_DEVID);
    if (ret == 0 && tagSz != sizeof(tag)) {
        ret = WC_HW_E;
    }
    ForceZero(key, sizeof(key));
    return wc_MpfsAthenaKatCheck(kat->name, "CMAC", ret, 1, calls, tag,
        kat->exp + MPFS_ATHENA_KAT_CMAC, sizeof(tag));
}
#endif
#endif /* WC_MPFS_ATHENA_KAT_AES */

#ifdef WC_MPFS_ATHENA_RNG
/* No known answer for an entropy source: the NRBG and, with
 * WC_MPFS_ATHENA_RNG_DRBG, the generate path must be served and not repeat. */
static int wc_MpfsAthenaKatRng(byte* buf)
{
    WC_RNG rng;
    word32 calls;
    int ret;

    calls = mpfsAthenaCbCalls;
    ret = wc_MpfsAthena_GenerateSeed(buf, 32);
    if (ret == 0) {
        ret = wc_MpfsAthena_GenerateSeed(buf + 32, 32);
    }
    ret = wc_MpfsAthenaKatCheck("RNG", "NRBG", ret, 1, calls, NULL, NULL, 0);
    if (ret == 0 && XMEMCMP(buf, buf + 32, 32) == 0) {
        wc_MpfsAthenaKatFail("RNG", "NRBG", "repeated output");
        ret = WC_HW_E;
    }
    if (ret == 0) {
        ret = wc_InitRng_ex(&rng, NULL, WC_MPFS_ATHENA_DEVID);
        ret = wc_MpfsAthenaKatCheck("RNG", "init", ret, -1, 0, NULL, NULL, 0);
        if (ret == 0) {
            calls = mpfsAthenaCbCalls;
            ret = wc_RNG_GenerateBlock(&rng, buf, 32);
            if (ret == 0) {
                ret = wc_RNG_GenerateBlock(&rng, buf + 32, 32);
            }
        #ifdef WC_MPFS_ATHENA_RNG_DRBG
            ret = wc_MpfsAthenaKatCheck("RNG", "generate", ret, 1, calls,
                NULL, NULL, 0);
        #else
            ret = wc_MpfsAthenaKatCheck("RNG", "generate", ret, -1, calls,
                NULL, NULL, 0);
        #endif
            if (ret == 0 && XMEMCMP(buf, buf + 32, 32) == 0) {
                wc_MpfsAthenaKatFail("RNG", "generate", "repeated output");
                ret = WC_HW_E;
            }
            wc_FreeRng(&rng);
        }
    }
    ForceZero(buf, 64);
    return ret;
}
#endif /* WC_MPFS_ATHENA_RNG */

#ifdef WC_MPFS_ATHENA_ECC
/* Per curve: Qx, Qy of d = 0x01.. (P-521 0x00..), a peer's x, y, their ECDH
 * secret, and r, s of an independent signature of the hash 0x80... */
#ifdef WC_MPFS_ATHENA_P192
static const byte mpfsAthenaKatP192[168] = {
    0x9c, 0x35, 0xbc, 0xc7, 0x63, 0x4b, 0x6d, 0x6c, 0x76, 0xb1, 0x1a, 0x89,
    0x8e, 0x83, 0xea, 0xc5, 0x9b, 0x88, 0x8b, 0x1a, 0x13, 0x71, 0xfe, 0xd0,
    0xc1, 0x8c, 0x00, 0x1d, 0x66, 0x44, 0x6d, 0x9c, 0x20, 0x4b, 0x40, 0xf4,
    0x52, 0xd6, 0xa7, 0xbc, 0x39, 0x46, 0x65, 0xbf, 0x08, 0x97, 0x34, 0xc7,
    0xbc, 0x64, 0x78, 0xa7, 0xa9, 0x73, 0xb0, 0x9c, 0x13, 0x2f, 0xb4, 0x97,
    0x55, 0xfc, 0xec, 0xf9, 0x36, 0xab, 0x34, 0x28, 0x38, 0x65, 0x25, 0x0b,
    0xd3, 0xcd, 0xa3, 0x94, 0x36, 0x0c, 0x94, 0x0f, 0x54, 0x87, 0x93, 0x1e,
    0x99, 0x7b, 0xe2, 0x1b, 0x70, 0xa0, 0x44, 0x17, 0x5c, 0xa4, 0x1d, 0xb1,
    0x9c, 0x53, 0x84, 0x61, 0xe6, 0xef, 0x29, 0x13, 0xca, 0x43, 0x2b, 0x7a,
    0x5a, 0x19, 0xf2, 0xd2, 0x12, 0xc7, 0xe7, 0x14, 0x1c, 0x10, 0x71, 0x2c,
    0x48, 0xe2, 0x64, 0x55, 0x7e, 0xec, 0x26, 0x90, 0x55, 0xb0, 0x73, 0x05,
    0x47, 0x02, 0x47, 0x61, 0x04, 0xaf, 0x9d, 0xdc, 0xb8, 0x15, 0x5d, 0x4e,
    0x0f, 0x3e, 0xb4, 0x12, 0x8a, 0x5c, 0x4a, 0xac, 0xb7, 0xd0, 0x82, 0x66,
    0x5c, 0xa2, 0x5e, 0xc1, 0xfd, 0xc6, 0x63, 0x5e, 0x88, 0x19, 0xe6, 0x03
};
#endif
#ifdef WC_MPFS_ATHENA_P224
static const byte mpfsAthenaKatP224[196] = {
    0x62, 0x7b, 0x7c, 0x0b, 0x3a, 0x2f, 0xb7, 0xa4, 0x78, 0xac, 0x56, 0x70,
    0xe9, 0x97, 0x31, 0x94, 0xa5, 0xfd, 0xa0, 0xbc, 0x07, 0x91, 0xb0, 0x75,
    0x06, 0xa7, 0x3d, 0xdd, 0x99, 0x11, 0x3b, 0x3f, 0xde, 0xa7, 0x1b, 0xbf,
    0xf9, 0x92, 0x13, 0x30, 0xd9, 0xce, 0x98, 0x01, 0x55, 0xee, 0xbd, 0x62,
    0x0c, 0x46, 0xbe, 0x92, 0x7c, 0x21, 0x45, 0x43, 0x2b, 0x65, 0xc2, 0xec,
    0x94, 0x77, 0x1c, 0x0c, 0x34, 0x8f, 0xcc, 0xa1, 0x3d, 0xf3, 0xf2, 0x39,
    0x60, 0xcd, 0xa7, 0xe9, 0x57, 0x80, 0xc0, 0xce, 0x5a, 0x3c, 0x55, 0x23,
    0xb2, 0x7d, 0xa8, 0x0a, 0x0c, 0x6e, 0x4c, 0xce, 0xa7, 0x1d, 0xaa, 0x27,
    0x05, 0x4f, 0x16, 0x17, 0x12, 0x4d, 0x69, 0x95, 0xfc, 0x94, 0xa5, 0x95,
    0xbd, 0xd8, 0xa1, 0x34, 0x3c, 0xb8, 0x49, 0xd1, 0x1c, 0xa9, 0x9e, 0x7c,
    0x04, 0x5b, 0x71, 0xa4, 0x2f, 0x57, 0xec, 0xf2, 0x54, 0x9f, 0x41, 0x30,
    0x7b, 0x79, 0x0f, 0xce, 0x3e, 0x3a, 0x18, 0xf5, 0xe4, 0x7c, 0x53, 0x43,
    0xd0, 0xbd, 0xaf, 0x51, 0x27, 0xde, 0x30, 0xd1, 0x25, 0x3c, 0x2b, 0x78,
    0x58, 0xe2, 0x01, 0x0d, 0xfc, 0xca, 0x0e, 0x92, 0x25, 0xa2, 0x70, 0xb0,
    0x7b, 0xbf, 0xa5, 0x84, 0x1f, 0xdf, 0xc8, 0xc3, 0xf9, 0xae, 0xd6, 0x82,
    0xbd, 0xa2, 0xf2, 0xc2, 0x92, 0x75, 0x3d, 0x94, 0xcb, 0xc2, 0x35, 0xc2,
    0xf6, 0xbd, 0x6f, 0x09
};
#endif
#ifdef WC_MPFS_ATHENA_P256
static const byte mpfsAthenaKatP256[224] = {
    0x51, 0x5c, 0x3d, 0x6e, 0xb9, 0xe3, 0x96, 0xb9, 0x04, 0xd3, 0xfe, 0xca,
    0x7f, 0x54, 0xfd, 0xcd, 0x0c, 0xc1, 0xe9, 0x97, 0xbf, 0x37, 0x5d, 0xca,
    0x51, 0x5a, 0xd0, 0xa6, 0xc3, 0xb4, 0x03, 0x5f, 0x45, 0x36, 0xbe, 0x3a,
    0x50, 0xf3, 0x18, 0xfb, 0xf9, 0xa5, 0x47, 0x59, 0x02, 0xa2, 0x21, 0x50,
    0x2b, 0xef, 0x0d, 0x57, 0xe0, 0x8c, 0x53, 0xb2, 0xcc, 0x0a, 0x56, 0xf1,
    0x7d, 0x9f, 0x93, 0x54, 0x68, 0xec, 0x7c, 0xf0, 0x8c, 0xd4, 0x10, 0x6e,
    0x43, 0xb1, 0x4d, 0xe8, 0x95, 0x42, 0x65, 0x22, 0xbd, 0x0a, 0x45, 0x15,
    0x0c, 0x02, 0x7e, 0x45, 0xc7, 0x95, 0x34, 0x34, 0xd7, 0x47, 0xe7, 0xba,
    0xe3, 0xaf, 0x39, 0xa8, 0x8e, 0xbb, 0xee, 0x86, 0x79, 0xbb, 0x61, 0xe7,
    0x84, 0x5c, 0x3a, 0x89, 0xcb, 0x9b, 0x5a, 0x32, 0x37, 0xc3, 0xfd, 0xb0,
    0xb0, 0x58, 0x7d, 0xba, 0xf4, 0x15, 0x11, 0x8d, 0xec, 0x55, 0x9d, 0x31,
    0xe5, 0x4c, 0x6c, 0x29, 0x23, 0x83, 0xfe, 0xf2, 0x1c, 0xd1, 0x74, 0x7c,
    0x33, 0x1f, 0xfc, 0x66, 0x54, 0x8e, 0x52, 0xb5, 0x6d, 0x35, 0x88, 0xd0,
    0x6c, 0x99, 0x26, 0x82, 0x85, 0x53, 0x75, 0x03, 0xc2, 0x4a, 0xaf, 0xe1,
    0x5d, 0xf9, 0x45, 0x24, 0x96, 0xb3, 0x32, 0x47, 0x3b, 0xd5, 0xd4, 0xec,
    0xae, 0xf2, 0xc6, 0x67, 0xce, 0xa6, 0x90, 0x46, 0xd3, 0x7d, 0xfa, 0x36,
    0xde, 0x1b, 0xc2, 0xe2, 0x2b, 0xc9, 0xbd, 0x2a, 0xbe, 0x9a, 0xc9, 0x4f,
    0x72, 0x38, 0xff, 0x14, 0x5e, 0x94, 0x8b, 0x6b, 0xe4, 0x3f, 0x11, 0x8c,
    0x6b, 0x78, 0xcc, 0xa2, 0x20, 0x44, 0x77, 0x1b
};
#endif
#ifdef WC_MPFS_ATHENA_P384
static const byte mpfsAthenaKatP384[336] = {
    0xc7, 0x6f, 0x22, 0x83, 0xdd, 0xa9, 0x5c, 0xd4, 0x9b, 0x0e, 0xd9, 0xe7,
    0x33, 0xd2, 0x90, 0x44, 0x74, 0xe3, 0x72, 0x16, 0xf1, 0x24, 0xe1, 0x3d,
    0x2c, 0x9a, 0xb4, 0xcf, 0x01, 0x02, 0x1c, 0x49, 0xad, 0x9c, 0xab, 0xb3,
    0xd0, 0xb9, 0x74, 0x99, 0xae, 0xf2, 0xf0, 0xab, 0x31, 0x3f, 0xa0, 0x28,
    0x26, 0xbc, 0x1f, 0x83, 0x45, 0x1b, 0x5c, 0x89, 0x62, 0xa7, 0x5c, 0xaf,
    0xf7, 0x35, 0x88, 0xd4, 0x40, 0x0a, 0x62, 0x96, 0x43, 0x61, 0x54, 0xfb,
    0x34, 0x3c, 0x39, 0x3e, 0x91, 0x04, 0x8a, 0x6c, 0x7b, 0xcb, 0xad, 0xc8,
    0x3c, 0xd8, 0xa5, 0xf2, 0x6f, 0xea, 0xe8, 0x83, 0x15, 0x6f, 0x92, 0xa1,
    0x0f, 0x3b, 0x4e, 0x71, 0x29, 0x2f, 0x2d, 0xe3, 0xa7, 0xc7, 0xbe, 0xfb,
    0x78, 0x50, 0x08, 0x41, 0x78, 0x58, 0xf3, 0xcf, 0xfe, 0x81, 0x92, 0x34,
    0x5e, 0x11, 0x73, 0x5f, 0x4e, 0x75, 0xed, 0x8a, 0x20, 0x21, 0x8b, 0xdd,
    0xfd, 0x9c, 0x66, 0x56, 0x94, 0x3b, 0x2d, 0xb8, 0xca, 0xbf, 0x2e, 0x40,
    0xb3, 0x34, 0x8b, 0xbb, 0xec, 0xff, 0x8a, 0x7b, 0x14, 0x4d, 0x73, 0x25,
    0x9b, 0x20, 0x01, 0x8e, 0x9f, 0x44, 0xf4, 0xda, 0xc2, 0x5b, 0xe0, 0x06,
    0x93, 0x44, 0xc0, 0xc7, 0x0e, 0xf4, 0xba, 0x5d, 0x83, 0x00, 0x80, 0xa5,
    0x2f, 0x8a, 0x05, 0xa4, 0x23, 0xb6, 0xe8, 0x3b, 0x93, 0xe8, 0x92, 0x3e,
    0xd2, 0x78, 0x92, 0x2c, 0x13, 0x8f, 0x35, 0x41, 0xe2, 0x4e, 0x81, 0xa4,
    0xa1, 0xba, 0x00, 0xb9, 0x97, 0x33, 0xb2, 0x86, 0xa2, 0x90, 0x53, 0x2a,
    0x2b, 0xee, 0x9b, 0x9b, 0xc0, 0x66, 0x54, 0x9b, 0xf5, 0x7a, 0xf9, 0x35,
    0x02, 0x03, 0x25, 0x0e, 0xd2, 0xbf, 0xf9, 0x80, 0x29, 0xbf, 0xe2, 0x06,
    0x1a, 0x44, 0x0b, 0x59, 0x54, 0x73, 0x97, 0x80, 0xdf, 0x94, 0xce, 0xbe,
    0x6d, 0x00, 0x9f, 0xf9, 0x77, 0xb4, 0xbc, 0xce, 0x67, 0x3e, 0xd7, 0xcc,
    0x77, 0x35, 0x7e, 0x11, 0x42, 0xa1, 0xa0, 0x20, 0x6e, 0xda, 0x4a, 0x17,
    0xa0, 0x50, 0x89, 0x62, 0x63, 0xda, 0xf3, 0xc9, 0x17, 0x88, 0x1b, 0xe1,
    0x98, 0x2f, 0x23, 0x8d, 0x29, 0x64, 0x4a, 0x2d, 0xc6, 0x01, 0xec, 0x39,
    0x15, 0x1a, 0x9c, 0x6d, 0xc6, 0x35, 0x3e, 0x84, 0x62, 0x40, 0x00, 0x1b,
    0x39, 0x54, 0x49, 0x64, 0x57, 0xfa, 0x39, 0x32, 0xf5, 0x3c, 0x22, 0xe0,
    0x24, 0x43, 0x47, 0x74, 0x2e, 0x6e, 0x6a, 0x32, 0xe0, 0x4f, 0xca, 0x35
};
#endif
#ifdef WC_MPFS_ATHENA_P521
static const byte mpfsAthenaKatP521[462] = {
    0x01, 0x26, 0xf7, 0xe6, 0xa6, 0xdf, 0x70, 0x87, 0xc9, 0x4b, 0x0c, 0x1b,
    0x0b, 0x19, 0x4a, 0x85, 0x66, 0x9e, 0xe8, 0x10, 0xfd, 0xa2, 0xea, 0xe1,
    0x2c, 0xa6, 0x41, 0x60, 0xde, 0xd6, 0xb2, 0x6c, 0x46, 0x47, 0x5e, 0xbe,
    0xdc, 0xce, 0xae, 0x40, 0x11, 0xda, 0x8e, 0xdd, 0x5c, 0x63, 0x94, 0xe0,
    0xb0, 0xbd, 0x42, 0x09, 0xa1, 0x52, 0x27, 0xf2, 0x57, 0x46, 0x56, 0x25,
    0x68, 0x54, 0xa7, 0xeb, 0x6e, 0x46, 0x01, 0xb9, 0xa2, 0x48, 0xcd, 0x40,
    0x17, 0xdd, 0xd4, 0xc2, 0xf6, 0xcc, 0x27, 0xcf, 0x0a, 0x30, 0x7a, 0x18,
    0x38, 0xee, 0x92, 0x37, 0x91, 0x3d, 0x8a, 0x50, 0x17, 0x60, 0xb7, 0xa6,
    0x38, 0xc9, 0x57, 0x3b, 0x9a, 0x0a, 0x08, 0xce, 0xd3, 0x0b, 0xef, 0xa7,
    0xa3, 0xc0, 0x93, 0x8b, 0xba, 0xaa, 0x77, 0x0a, 0x7b, 0xc3, 0x7d, 0xd1,
    0x75, 0x95, 0x7c, 0xb3, 0xa4, 0x5e, 0xbd, 0xe3, 0xc9, 0x82, 0x6e, 0xeb,
    0x01, 0x7a, 0x40, 0xfc, 0x56, 0x0b, 0x1a, 0x88, 0xed, 0x96, 0x1a, 0xbb,
    0xcd, 0x82, 0x4f, 0xc5, 0xbf, 0xca, 0xc3, 0xe1, 0xab, 0xaa, 0xa8, 0x1e,
    0xb3, 0x15, 0x0b, 0x98, 0x3b, 0x13, 0x44, 0x6b, 0x9f, 0xc1, 0xa0, 0x2e,
    0xb3, 0x2d, 0x1e, 0x9b, 0x4a, 0x7a, 0x6d, 0xa9, 0xc0, 0x72, 0x94, 0x78,
    0x89, 0x6a, 0x3e, 0xdc, 0x15, 0x68, 0x3d, 0x8b, 0x72, 0x4d, 0x20, 0x84,
    0x49, 0x4c, 0xc7, 0xe5, 0x42, 0x82, 0x01, 0x40, 0x74, 0x90, 0x91, 0xc3,
    0x32, 0x43, 0x33, 0x2b, 0x84, 0xbb, 0x7b, 0x92, 0xc8, 0x96, 0x28, 0xa2,
    0x59, 0xa8, 0x44, 0x0e, 0x3c, 0x11, 0xc2, 0xc8, 0x23, 0x0d, 0xc4, 0x15,
    0xb8, 0xff, 0x9d, 0x18, 0x67, 0x1d, 0x42, 0xae, 0x82, 0x06, 0x04, 0xe1,
    0x44, 0xf8, 0x0f, 0x65, 0xc8, 0x99, 0x5b, 0x22, 0xf0, 0x0b, 0x17, 0x63,
    0x1a, 0x2e, 0x27, 0xbf, 0x37, 0x72, 0x22, 0x08, 0x69, 0xc5, 0x63, 0x8e,
    0x00, 0xa0, 0x2a, 0xc3, 0x04, 0x13, 0x70, 0x17, 0x35, 0x8c, 0xfa, 0x6a,
    0x53, 0xba, 0x05, 0x7d, 0x2c, 0x37, 0xc1, 0x58, 0x2b, 0x91, 0xe6, 0xdb,
    0xfe, 0x20, 0x26, 0xd9, 0xc3, 0xb6, 0xda, 0x02, 0xdd, 0x1b, 0xa9, 0x32,
    0x99, 0xea, 0x00, 0x82, 0x05, 0x07, 0x8e, 0x8e, 0x0e, 0xff, 0xc2, 0x64,
    0x51, 0xea, 0xbb, 0x25, 0xb3, 0xf1, 0xbe, 0xb0, 0x70, 0x17, 0xdc, 0x80,
    0x63, 0x64, 0xb6, 0x0e, 0x76, 0xf7, 0x01, 0x54, 0x1e, 0x0d, 0x24, 0x05,
    0xe8, 0x7e, 0xe3, 0x2d, 0x5f, 0x63, 0xa6, 0xeb, 0x7c, 0x61, 0xd0, 0x41,
    0xba, 0x16, 0xef, 0x36, 0xdd, 0x13, 0x12, 0x59, 0xfe, 0x23, 0x77, 0xaf,
    0xf4, 0x94, 0x0d, 0xc6, 0x58, 0xeb, 0x92, 0x9a, 0x46, 0x6c, 0x48, 0xea,
    0x40, 0x04, 0x36, 0x77, 0x2c, 0xc5, 0x2d, 0x20, 0x4f, 0x52, 0x5d, 0x00,
    0xe8, 0x69, 0x6e, 0xc7, 0xc5, 0x53, 0x5b, 0xec, 0xee, 0xf2, 0xfa, 0x30,
    0x00, 0x35, 0x47, 0x0b, 0x90, 0x0b, 0x0d, 0x6e, 0xa0, 0xd7, 0x44, 0xa7,
    0xc2, 0x32, 0x9f, 0xae, 0xfa, 0x16, 0x16, 0xa8, 0x8a, 0x0c, 0xc8, 0x86,
    0x90, 0x6d, 0xcc, 0x8e, 0xbf, 0x1d, 0x2d, 0x84, 0xf9, 0x92, 0x00, 0x6b,
    0x33, 0x54, 0x71, 0xb8, 0xcf, 0x46, 0x0f, 0x14, 0x0f, 0x71, 0xb4, 0xad,
    0x3f, 0x73, 0x80, 0x1a, 0xbe, 0xd9, 0xf1, 0xef, 0x33, 0xfa, 0x2a, 0x5f,
    0x41, 0xa3, 0x9d, 0x8f, 0x9e, 0x02
};
#endif

typedef struct MpfsAthenaKatEcc {
    const char* name;
    const byte* v;
    int         curveId;
    word32      sz;
    word32      hashSz;
    byte        dStart;
} MpfsAthenaKatEcc;

static const MpfsAthenaKatEcc mpfsAthenaKatEccs[] = {
#ifdef WC_MPFS_ATHENA_P192
    { "P-192", mpfsAthenaKatP192, ECC_SECP192R1, 24, 32, 0x01 },
#endif
#ifdef WC_MPFS_ATHENA_P224
    { "P-224", mpfsAthenaKatP224, ECC_SECP224R1, 28, 28, 0x01 },
#endif
#ifdef WC_MPFS_ATHENA_P256
    { "P-256", mpfsAthenaKatP256, ECC_SECP256R1, 32, 32, 0x01 },
#endif
#ifdef WC_MPFS_ATHENA_P384
    { "P-384", mpfsAthenaKatP384, ECC_SECP384R1, 48, 48, 0x01 },
#endif
#ifdef WC_MPFS_ATHENA_P521
    { "P-521", mpfsAthenaKatP521, ECC_SECP521R1, 66, 64, 0x00 },
#endif
};

/* buf takes d at 0 and the hash at 96. Known answers, so an operand in the
 * wrong word or byte order fails rather than agreeing with itself. */
static int wc_MpfsAthenaKatEccOne(const MpfsAthenaKatEcc* kat, WC_RNG* rng,
    byte* buf)
{
    ecc_key key;
    ecc_key peer;
    byte out[ECC_MAX_SIG_SIZE];
    const byte* v = kat->v;
    const byte* hash = buf + 96;
    word32 sz = kat->sz;
    word32 outSz = 0;
    word32 calls = 0;
    int res;
    int ret;

    (void)hash;
    (void)rng;
    (void)outSz;
    (void)res;
    (void)calls;

    wc_MpfsAthenaKatSeq(buf, sz, kat->dStart);
    wc_MpfsAthenaKatSeq(buf + 96, kat->hashSz, 0x80);
    ret = wc_ecc_init_ex(&key, NULL, WC_MPFS_ATHENA_DEVID);
    if (ret != 0) {
        wc_MpfsAthenaKatFail(kat->name, "init", "failed");
        return ret;
    }
    ret = wc_ecc_init_ex(&peer, NULL, WC_MPFS_ATHENA_DEVID);
    if (ret != 0) {
        wc_MpfsAthenaKatFail(kat->name, "init", "failed");
        wc_ecc_free(&key);
        return ret;
    }
    ret = wc_ecc_import_unsigned(&key, v, v + sz, buf, kat->curveId);
    if (ret == 0) {
        ret = wc_ecc_import_unsigned(&peer, v + 2 * sz, v + 3 * sz, NULL,
            kat->curveId);
    }
    ret = wc_MpfsAthenaKatCheck(kat->name, "key import", ret, -1, 0, NULL,
        NULL, 0);

#ifdef HAVE_ECC_VERIFY
    /* The fixed signature, then the same with its last byte changed. */
    if (ret == 0) {
    #ifndef NO_ASN
        outSz = sizeof(out);
        ret = wc_ecc_rs_raw_to_sig(v + 5 * sz, sz, v + 6 * sz, sz, out,
            &outSz);
    #else
        outSz = 2 * sz;
        XMEMCPY(out, v + 5 * sz, outSz);
    #endif
        calls = mpfsAthenaCbCalls;
        res = 0;
        if (ret == 0) {
            ret = wc_ecc_verify_hash(out, outSz, hash, kat->hashSz, &res,
                &key);
        }
        if (ret == 0 && res != 1) {
            ret = WC_HW_E;
        }
        ret = wc_MpfsAthenaKatCheck(kat->name, "verify", ret, 1, calls, NULL,
            NULL, 0);
    }
    if (ret == 0) {
        out[outSz - 1] ^= 0x01;
        calls = mpfsAthenaCbCalls;
        res = 1;
        ret = wc_ecc_verify_hash(out, outSz, hash, kat->hashSz, &res, &key);
        if (ret == 0 && res != 0) {
            ret = WC_HW_E;
        }
        ret = wc_MpfsAthenaKatCheck(kat->name, "bad signature", ret, 1, calls,
            NULL, NULL, 0);
    }
#endif

#ifdef HAVE_ECC_DHE
    if (ret == 0) {
        outSz = sizeof(out);
        calls = mpfsAthenaCbCalls;
        ret = wc_ecc_shared_secret(&key, &peer, out, &outSz);
        if (ret == 0 && outSz != sz) {
            ret = WC_HW_E;
        }
        ret = wc_MpfsAthenaKatCheck(kat->name, "ECDH", ret, 1, calls, out,
            v + 4 * sz, sz);
    }
#endif

#if defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY)
    /* A fresh signature under the fixed key must verify. */
    if (ret == 0) {
        outSz = sizeof(out);
        calls = mpfsAthenaCbCalls;
        ret = wc_ecc_sign_hash(hash, kat->hashSz, out, &outSz, rng, &key);
        ret = wc_MpfsAthenaKatCheck(kat->name, "sign", ret, 1, calls, NULL,
            NULL, 0);
    }
    if (ret == 0) {
        res = 0;
        ret = wc_ecc_verify_hash(out, outSz, hash, kat->hashSz, &res, &key);
        if (ret == 0 && res != 1) {
            ret = WC_HW_E;
        }
        ret = wc_MpfsAthenaKatCheck(kat->name, "verify own signature", ret,
            -1, 0, NULL, NULL, 0);
    }
#endif

#if defined(HAVE_ECC_DHE) && !defined(WOLFSSL_ECC_BLIND_K) && \
    defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY)
    /* Keygen, then a sign and verify under the new key. */
    if (ret == 0) {
        wc_ecc_free(&peer);
        ret = wc_ecc_init_ex(&peer, NULL, WC_MPFS_ATHENA_DEVID);
        calls = mpfsAthenaCbCalls;
        if (ret == 0) {
            ret = wc_ecc_make_key_ex(rng, (int)sz, &peer, kat->curveId);
        }
        ret = wc_MpfsAthenaKatCheck(kat->name, "keygen", ret, 1, calls, NULL,
            NULL, 0);
    }
    if (ret == 0) {
        ret = wc_ecc_check_key(&peer);
        ret = wc_MpfsAthenaKatCheck(kat->name, "generated key check", ret, -1,
            0, NULL, NULL, 0);
    }
    if (ret == 0) {
        outSz = sizeof(out);
        ret = wc_ecc_sign_hash(hash, kat->hashSz, out, &outSz, rng, &peer);
        if (ret == 0) {
            res = 0;
            ret = wc_ecc_verify_hash(out, outSz, hash, kat->hashSz, &res,
                &peer);
        }
        if (ret == 0 && res != 1) {
            ret = WC_HW_E;
        }
        ret = wc_MpfsAthenaKatCheck(kat->name, "generated key signature",
            ret, -1, 0, NULL, NULL, 0);
    }
#endif

    wc_ecc_free(&peer);
    wc_ecc_free(&key);
    ForceZero(out, sizeof(out));
    ForceZero(buf, sz);
    return ret;
}

static int wc_MpfsAthenaKatEcc(byte* buf)
{
    WC_RNG rng;
    word32 i;
    int ret;

    /* In software: an engine-tagged RNG offloads its own SHA-256, which would
     * satisfy the call count of a step that stayed in software. */
    ret = wc_InitRng_ex(&rng, NULL, INVALID_DEVID);
    if (ret != 0) {
        wc_MpfsAthenaKatFail("ECC", "RNG init", "failed");
        return ret;
    }
    for (i = 0; ret == 0 && i < sizeof(mpfsAthenaKatEccs) /
            sizeof(mpfsAthenaKatEccs[0]); i++) {
        ret = wc_MpfsAthenaKatEccOne(&mpfsAthenaKatEccs[i], &rng, buf);
    }
    wc_FreeRng(&rng);
    return ret;
}
#endif /* WC_MPFS_ATHENA_ECC */

#ifdef WC_MPFS_ATHENA_KAT_RSA
/* An RSA-2048 key, and the raw public-key encryption of the message
 * 0x00..0xFF, from an independent implementation. u is q^-1 mod p. */
static const byte mpfsAthenaKatRsaN[256] = {
    0xe4, 0x15, 0x7b, 0xf1, 0xea, 0xfc, 0xc9, 0xaa, 0x8b, 0x3f, 0x2a, 0x48,
    0x89, 0x89, 0x7e, 0x4a, 0x47, 0x58, 0x4f, 0xaa, 0xad, 0x0d, 0x6d, 0x07,
    0x7d, 0x3c, 0x35, 0x75, 0x96, 0xd9, 0x13, 0xc7, 0x56, 0xf1, 0x9e, 0x79,
    0xd1, 0x8f, 0x97, 0x06, 0x16, 0x3e, 0x69, 0x8e, 0xf3, 0x7b, 0x09, 0xc8,
    0xce, 0x3f, 0xbc, 0x4d, 0x42, 0x4a, 0xd9, 0x89, 0xa7, 0x63, 0xaa, 0x1d,
    0x69, 0xe8, 0x48, 0xfc, 0xd2, 0x00, 0xef, 0xd5, 0x3b, 0x60, 0x92, 0x74,
    0x99, 0x3a, 0x94, 0xea, 0x31, 0x49, 0xd5, 0x52, 0x58, 0xa4, 0x32, 0x05,
    0xfd, 0x4b, 0x9e, 0x17, 0xa4, 0x27, 0x97, 0x7b, 0x24, 0x63, 0x37, 0x57,
    0xa1, 0xbb, 0xc4, 0x46, 0xca, 0x45, 0xe9, 0xbf, 0xcd, 0x98, 0x92, 0xef,
    0x19, 0xbe, 0xc6, 0x9a, 0xdb, 0x57, 0x1a, 0x45, 0xbf, 0x0b, 0xfa, 0xe1,
    0x0f, 0x85, 0xf2, 0x9b, 0x81, 0x5b, 0x97, 0xa3, 0x66, 0x53, 0x40, 0x6f,
    0x93, 0xd6, 0x01, 0x48, 0xb7, 0xe3, 0x93, 0x26, 0xe6, 0xa0, 0x7f, 0x6e,
    0xad, 0xbd, 0xdd, 0x77, 0x98, 0x86, 0x0e, 0xd9, 0x59, 0x21, 0xe8, 0x5b,
    0x10, 0xcb, 0x0e, 0x8f, 0x9c, 0xc2, 0xb3, 0x2b, 0xbd, 0xe8, 0xb6, 0xad,
    0x4c, 0x4d, 0x28, 0x6e, 0xeb, 0xf1, 0x02, 0x5b, 0x51, 0xc0, 0xcf, 0x78,
    0x56, 0xdd, 0xfd, 0x6e, 0x5c, 0x4d, 0x78, 0xb7, 0x5a, 0xd4, 0x7f, 0x38,
    0xf8, 0x85, 0x95, 0xcb, 0xb7, 0x6a, 0x7b, 0x30, 0xcf, 0x9d, 0x15, 0x56,
    0x1a, 0xd2, 0x64, 0xdb, 0x68, 0x83, 0x85, 0x14, 0xef, 0x83, 0xfb, 0x0c,
    0x19, 0xed, 0xf1, 0x46, 0x30, 0x11, 0x5a, 0x95, 0xef, 0x37, 0x82, 0x8e,
    0xe5, 0x66, 0x65, 0xd2, 0x7f, 0x54, 0x50, 0x62, 0x56, 0xf8, 0xee, 0xcf,
    0x18, 0x95, 0x89, 0x69, 0x40, 0x16, 0xbc, 0xf0, 0xc7, 0xc4, 0x33, 0x5e,
    0x45, 0x6e, 0xb7, 0x87
};
static const byte mpfsAthenaKatRsaE[3] = {
    0x01, 0x00, 0x01
};
#ifndef WOLFSSL_RSA_PUBLIC_ONLY
static const byte mpfsAthenaKatRsaD[256] = {
    0x0f, 0xcd, 0xc1, 0x49, 0xd0, 0xeb, 0x75, 0x19, 0xc1, 0x0e, 0x3e, 0x62,
    0xca, 0x4c, 0xe1, 0x98, 0x49, 0xfb, 0x3f, 0x81, 0xe6, 0xfd, 0xc0, 0x29,
    0x3d, 0xaf, 0x37, 0x51, 0x0f, 0x83, 0xb9, 0x10, 0x1d, 0xe1, 0x1e, 0x06,
    0xf8, 0xd3, 0x47, 0x36, 0x9f, 0xc1, 0xf1, 0x54, 0x7b, 0x60, 0x72, 0x1c,
    0x1c, 0xd6, 0x63, 0xb8, 0xc2, 0xb8, 0x26, 0xfc, 0x97, 0xc1, 0x9b, 0x1e,
    0xf0, 0xa0, 0xac, 0xb5, 0xff, 0xe3, 0x1a, 0xbb, 0x1e, 0xa3, 0x21, 0x62,
    0xbc, 0xdf, 0x47, 0x44, 0x36, 0xe8, 0x13, 0xc4, 0xe1, 0xe9, 0x76, 0xa1,
    0xdd, 0x9c, 0x28, 0xb7, 0x20, 0xa3, 0xb1, 0xa6, 0x51, 0xae, 0x22, 0x3e,
    0x8b, 0x31, 0x54, 0x77, 0x47, 0x3a, 0xb2, 0xe8, 0x9c, 0x59, 0x4f, 0x0d,
    0x0c, 0x2e, 0xa0, 0xda, 0x48, 0x0a, 0x70, 0x02, 0x97, 0x2b, 0x40, 0x55,
    0xe9, 0xda, 0x71, 0x25, 0xff, 0x3f, 0x96, 0x71, 0x15, 0x7a, 0xeb, 0x1e,
    0x74, 0x6a, 0x38, 0x0a, 0x53, 0x67, 0x87, 0x85, 0x61, 0x8a, 0x5d, 0x00,
    0x6b, 0x56, 0x35, 0x3c, 0xc9, 0xd1, 0xc1, 0x6f, 0x26, 0x0f, 0x77, 0xa3,
    0x7b, 0xa0, 0xbd, 0xf3, 0xda, 0x8a, 0x97, 0xd8, 0x5e, 0xeb, 0xd7, 0x4c,
    0x0d, 0x6a, 0x9f, 0xc0, 0xe2, 0xb9, 0x5b, 0x1d, 0xba, 0x56, 0x11, 0xa3,
    0x3a, 0x62, 0xce, 0xac, 0x04, 0xfc, 0xdb, 0x85, 0x49, 0xa4, 0xbf, 0x00,
    0x94, 0xd4, 0x5f, 0x7d, 0x9a, 0x86, 0xfa, 0x3d, 0xfd, 0xcf, 0x34, 0xc0,
    0x04, 0x74, 0xff, 0x7c, 0xc4, 0x8d, 0xb8, 0x62, 0x68, 0x38, 0xe5, 0xcf,
    0x3a, 0xeb, 0x54, 0xf5, 0xc5, 0x48, 0x60, 0x30, 0x93, 0xc9, 0xa0, 0xcd,
    0x44, 0x95, 0xab, 0x15, 0xdc, 0xd1, 0xc1, 0xe9, 0xde, 0x3f, 0x08, 0xc8,
    0x78, 0x81, 0x2e, 0xcd, 0xd9, 0xd9, 0xc8, 0x71, 0x4c, 0xe7, 0x57, 0x6c,
    0xb1, 0x57, 0x17, 0x61
};
static const byte mpfsAthenaKatRsaP[128] = {
    0xfa, 0x7c, 0xbf, 0x15, 0x13, 0xe9, 0x9e, 0x95, 0x5f, 0x39, 0xd6, 0xd7,
    0x7a, 0xdf, 0x01, 0xaf, 0x14, 0x44, 0xb7, 0xf5, 0x48, 0xd0, 0x0a, 0x4e,
    0x79, 0xd5, 0xf8, 0x82, 0x82, 0x91, 0x52, 0xda, 0x8b, 0xd5, 0x55, 0x9d,
    0xe7, 0xb0, 0x20, 0xa1, 0x02, 0x6f, 0x85, 0xb8, 0xd6, 0xd7, 0xb2, 0xbc,
    0x15, 0x99, 0x00, 0x86, 0xa0, 0xfe, 0xf5, 0xf8, 0xe6, 0x6f, 0x6c, 0x84,
    0x3f, 0x42, 0xc9, 0x25, 0x2d, 0x8e, 0xd6, 0x52, 0xa2, 0x64, 0xe4, 0x39,
    0xd3, 0x46, 0x00, 0xa9, 0xa3, 0x3d, 0xce, 0x32, 0x11, 0x62, 0xbf, 0x8c,
    0x4e, 0x51, 0x61, 0x42, 0xa9, 0xf4, 0xe4, 0x40, 0x38, 0x7d, 0xa7, 0x95,
    0xa3, 0xb5, 0x44, 0x8e, 0xea, 0x57, 0xb6, 0xd9, 0x2c, 0xfe, 0x76, 0x1c,
    0x79, 0x77, 0x5a, 0x9c, 0xd4, 0xd2, 0xf3, 0x36, 0x66, 0xfc, 0xe0, 0x34,
    0xb8, 0xa1, 0x74, 0xed, 0xf8, 0xd0, 0xb0, 0x51
};
static const byte mpfsAthenaKatRsaQ[128] = {
    0xe9, 0x1a, 0x84, 0x35, 0x26, 0x31, 0x40, 0x1c, 0xa1, 0x56, 0xc1, 0x63,
    0x99, 0x8c, 0x04, 0x54, 0x12, 0xa5, 0x07, 0xcc, 0xaa, 0xc8, 0x61, 0xbc,
    0x74, 0x5f, 0xda, 0xb5, 0x3f, 0xe8, 0x59, 0xdc, 0xd6, 0xd5, 0xe4, 0x3c,
    0x8e, 0x8e, 0x60, 0x7f, 0x5d, 0xd7, 0x41, 0x6f, 0x6a, 0xd4, 0xfe, 0x44,
    0x8e, 0xde, 0x94, 0x12, 0x59, 0xb2, 0x18, 0x44, 0xb7, 0x0b, 0x49, 0xcf,
    0x42, 0x03, 0xe4, 0x1e, 0x10, 0x06, 0xaf, 0x20, 0x1e, 0xf7, 0xad, 0x92,
    0xb0, 0xf4, 0x8f, 0xc8, 0xde, 0x5a, 0x04, 0x8c, 0xcf, 0xe9, 0xa3, 0xde,
    0xd9, 0x7f, 0xd5, 0x41, 0x6b, 0x51, 0x82, 0xac, 0x34, 0x3a, 0x7c, 0xa8,
    0x76, 0xae, 0x3c, 0xef, 0x45, 0x96, 0xca, 0xbc, 0xaa, 0xcf, 0x3e, 0x5c,
    0x2e, 0x4c, 0x22, 0x2d, 0x58, 0x04, 0xb2, 0x8d, 0xb0, 0x23, 0x08, 0xed,
    0x97, 0xec, 0x19, 0x08, 0x21, 0x8f, 0x0c, 0x57
};
static const byte mpfsAthenaKatRsaDP[128] = {
    0xc1, 0x08, 0xab, 0x95, 0x09, 0xc0, 0x6a, 0xe6, 0xbf, 0xf8, 0xe9, 0xd9,
    0x2b, 0x26, 0x7a, 0xbc, 0xba, 0xc8, 0xee, 0x5f, 0x47, 0x9a, 0x93, 0xa6,
    0xc0, 0x7b, 0xa5, 0xc4, 0xa5, 0xec, 0x6a, 0x46, 0x63, 0xa6, 0xa7, 0x11,
    0x46, 0x40, 0x54, 0x14, 0xe0, 0xb4, 0xa2, 0xff, 0xbc, 0x09, 0x84, 0x03,
    0x30, 0x3d, 0xb5, 0xcb, 0x0a, 0x7d, 0x11, 0x7f, 0x9b, 0xcd, 0xd8, 0x79,
    0xdd, 0xea, 0x90, 0xea, 0x66, 0xbe, 0x81, 0xea, 0x32, 0x9d, 0xbf, 0xc7,
    0xd4, 0x4a, 0x49, 0x2e, 0x71, 0xcf, 0xaa, 0x7c, 0xa9, 0x2b, 0x49, 0x64,
    0x4d, 0xe2, 0xa7, 0x2a, 0x61, 0xa1, 0x88, 0xd8, 0xf8, 0xef, 0xd4, 0xdb,
    0x1b, 0xcb, 0x10, 0xa7, 0x76, 0x6e, 0xdc, 0x49, 0x67, 0x44, 0x3e, 0x2f,
    0x59, 0x68, 0x22, 0x5b, 0x64, 0x23, 0xa1, 0x2c, 0x96, 0x97, 0x60, 0x0d,
    0x21, 0x0f, 0xc3, 0xf5, 0xb4, 0x5e, 0xd6, 0xd1
};
static const byte mpfsAthenaKatRsaDQ[128] = {
    0x2e, 0x71, 0xec, 0x19, 0xb2, 0xec, 0x69, 0x3b, 0xcb, 0x21, 0xc0, 0x12,
    0x9a, 0x4b, 0x7d, 0xa9, 0x4a, 0xb5, 0xbb, 0x22, 0x1a, 0x7d, 0x26, 0x8c,
    0x28, 0x1b, 0xd9, 0x35, 0xf7, 0xef, 0xd1, 0xc7, 0xe0, 0xbe, 0x69, 0x65,
    0x6f, 0x7a, 0x0a, 0xdc, 0x15, 0xd4, 0x87, 0xe3, 0x2d, 0x44, 0x17, 0x0d,
    0x8d, 0xf1, 0xe7, 0x4a, 0xe8, 0xb8, 0x45, 0x81, 0x9b, 0x7f, 0x12, 0x4b,
    0xcb, 0x79, 0x7f, 0x00, 0x46, 0x6d, 0x2e, 0x83, 0x95, 0xe7, 0xff, 0x9b,
    0x94, 0xca, 0x85, 0xc3, 0x9e, 0x1a, 0x0d, 0x82, 0x09, 0x03, 0x22, 0x75,
    0x8a, 0x9c, 0x9f, 0xdf, 0x13, 0x05, 0x00, 0xa6, 0x53, 0x19, 0xbc, 0x30,
    0xcc, 0xc4, 0xd6, 0xbb, 0x4e, 0x00, 0x47, 0x90, 0xe3, 0xef, 0xbb, 0x1b,
    0x1e, 0xd6, 0x68, 0x90, 0xe4, 0x52, 0xbb, 0x48, 0xe3, 0xe9, 0x77, 0x23,
    0xef, 0xfb, 0x48, 0xd9, 0x87, 0xe6, 0x3a, 0xad
};
static const byte mpfsAthenaKatRsaU[128] = {
    0xdf, 0x5c, 0xec, 0xed, 0x48, 0xdc, 0x64, 0x13, 0xe1, 0x6a, 0x74, 0x93,
    0x43, 0x63, 0x8a, 0x66, 0x72, 0x5b, 0x44, 0xd0, 0xbb, 0x44, 0x29, 0x5c,
    0xc7, 0xd5, 0xd8, 0x20, 0xf1, 0xbe, 0x28, 0xe2, 0xbf, 0xd3, 0x06, 0xbb,
    0x83, 0x86, 0xb7, 0xbf, 0xc0, 0x27, 0x8d, 0xc6, 0x03, 0x81, 0xa3, 0xab,
    0x05, 0x45, 0xb6, 0x04, 0x1f, 0xfe, 0x26, 0x7f, 0xae, 0x96, 0xf5, 0x42,
    0xd1, 0x45, 0xd7, 0x4a, 0xa7, 0xd3, 0x2b, 0x78, 0x64, 0xc9, 0xf4, 0xcc,
    0x3f, 0x11, 0x3e, 0xfd, 0x0c, 0xf1, 0x45, 0xfe, 0x9b, 0x29, 0x40, 0x23,
    0x1d, 0xa8, 0x25, 0xa9, 0xee, 0xc8, 0x6a, 0xbb, 0x1a, 0x30, 0x53, 0x24,
    0x38, 0x20, 0xa4, 0x48, 0xcf, 0x84, 0xc5, 0xe5, 0x99, 0x52, 0xe2, 0xf2,
    0xd5, 0x53, 0x8c, 0x3d, 0x93, 0x7a, 0x03, 0xed, 0x84, 0x08, 0xb2, 0xc9,
    0xa8, 0x5f, 0x08, 0x86, 0x56, 0x38, 0x0f, 0xde
};
#endif
static const byte mpfsAthenaKatRsaCt[256] = {
    0x72, 0xa5, 0x7e, 0x81, 0x20, 0xdd, 0x7c, 0x06, 0xb9, 0xef, 0x0e, 0xff,
    0xc9, 0x32, 0x60, 0x66, 0x01, 0x5c, 0xf8, 0xd5, 0xc1, 0x39, 0x9a, 0x8b,
    0x63, 0x1c, 0xe5, 0x09, 0xde, 0x7a, 0x94, 0xe2, 0xbf, 0xcc, 0x76, 0x99,
    0x55, 0xa5, 0xad, 0x75, 0x92, 0x53, 0x12, 0x75, 0xf4, 0x21, 0x29, 0xe0,
    0x9e, 0x9a, 0x99, 0xdd, 0x02, 0x6d, 0x12, 0x48, 0xbc, 0x06, 0x37, 0x39,
    0xf2, 0x9d, 0x10, 0x8b, 0x2d, 0x15, 0x71, 0x80, 0xfc, 0x32, 0xc7, 0x36,
    0xbf, 0x04, 0xe5, 0x35, 0x39, 0x35, 0x54, 0x8d, 0xed, 0x64, 0xb4, 0xbd,
    0x1b, 0xd2, 0x20, 0xda, 0x97, 0xd9, 0x6b, 0x44, 0x6c, 0x54, 0x2e, 0x89,
    0x1c, 0xe6, 0x3c, 0xf2, 0x5f, 0x72, 0x87, 0x7f, 0x4c, 0xd1, 0x8c, 0x0e,
    0xe9, 0xcf, 0xcb, 0xc0, 0x78, 0x62, 0xfa, 0x22, 0xe6, 0xa8, 0x16, 0x39,
    0x17, 0x6c, 0x5f, 0xed, 0x4b, 0xd1, 0x93, 0x62, 0xd4, 0x1a, 0xa1, 0xb5,
    0x25, 0x72, 0x08, 0x55, 0x21, 0x82, 0x46, 0x85, 0x23, 0xe7, 0xe7, 0xf1,
    0x65, 0x9d, 0x25, 0x4d, 0x13, 0x8b, 0x34, 0x53, 0x99, 0x86, 0xc5, 0x2e,
    0x5f, 0x9c, 0x20, 0xa0, 0xe5, 0x0b, 0x50, 0xc6, 0x66, 0xe9, 0xe1, 0x3a,
    0x1a, 0x79, 0x93, 0xb2, 0xb9, 0xc2, 0x64, 0xd2, 0x0a, 0xe4, 0x3e, 0xe3,
    0x44, 0xf1, 0x1b, 0x8c, 0x1c, 0xa0, 0xa1, 0x4f, 0xc0, 0x91, 0x22, 0xd5,
    0xdd, 0x83, 0x1f, 0xa0, 0x7a, 0xd1, 0x1c, 0x1e, 0xba, 0xf0, 0xdd, 0xd4,
    0xbd, 0x8c, 0xa9, 0xd7, 0x75, 0x73, 0xa7, 0xa0, 0x75, 0xfb, 0x5f, 0x71,
    0x4a, 0xe4, 0x5b, 0xc2, 0xf0, 0xda, 0x05, 0x44, 0x5a, 0x37, 0x69, 0x2d,
    0x16, 0x8c, 0x9b, 0xda, 0xd8, 0x88, 0xd9, 0x68, 0x55, 0xc9, 0x04, 0xda,
    0x76, 0x67, 0x83, 0x74, 0xfb, 0x1c, 0xcf, 0xe0, 0x6d, 0xf6, 0xc5, 0x65,
    0xcb, 0xe2, 0xbd, 0x70
};

/* The public operation must stay in software unless WC_MPFS_ATHENA_RSA_PUBLIC
 * is defined. buf takes the message; the RNG is in software as for ECC. */
static int wc_MpfsAthenaKatRsa(byte* buf)
{
    RsaKey key;
    WC_RNG rng;
    byte out[256];
    word32 outSz;
    word32 calls;
    int ret;

    ret = wc_InitRng_ex(&rng, NULL, INVALID_DEVID);
    if (ret != 0) {
        wc_MpfsAthenaKatFail("RSA-2048", "RNG init", "failed");
        return ret;
    }
    ret = wc_InitRsaKey_ex(&key, NULL, WC_MPFS_ATHENA_DEVID);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_MpfsAthenaKatFail("RSA-2048", "key init", "failed");
        return ret;
    }
#ifndef WOLFSSL_RSA_PUBLIC_ONLY
    ret = wc_RsaPrivateKeyDecodeRaw(mpfsAthenaKatRsaN,
        sizeof(mpfsAthenaKatRsaN), mpfsAthenaKatRsaE,
        sizeof(mpfsAthenaKatRsaE), mpfsAthenaKatRsaD,
        sizeof(mpfsAthenaKatRsaD), mpfsAthenaKatRsaU,
        sizeof(mpfsAthenaKatRsaU), mpfsAthenaKatRsaP,
        sizeof(mpfsAthenaKatRsaP), mpfsAthenaKatRsaQ,
        sizeof(mpfsAthenaKatRsaQ), mpfsAthenaKatRsaDP,
        sizeof(mpfsAthenaKatRsaDP), mpfsAthenaKatRsaDQ,
        sizeof(mpfsAthenaKatRsaDQ), &key);
#else
    ret = wc_RsaPublicKeyDecodeRaw(mpfsAthenaKatRsaN,
        sizeof(mpfsAthenaKatRsaN), mpfsAthenaKatRsaE,
        sizeof(mpfsAthenaKatRsaE), &key);
#endif
    ret = wc_MpfsAthenaKatCheck("RSA-2048", "key import", ret, -1, 0, NULL,
        NULL, 0);
    wc_MpfsAthenaKatSeq(buf, 256, 0);

    if (ret == 0) {
        outSz = sizeof(out);
        calls = mpfsAthenaCbCalls;
        ret = wc_RsaFunction(buf, 256, out, &outSz, RSA_PUBLIC_ENCRYPT, &key,
            &rng);
        if (ret == 0 && outSz != sizeof(out)) {
            ret = WC_HW_E;
        }
    #ifdef WC_MPFS_ATHENA_RSA_PUBLIC
        ret = wc_MpfsAthenaKatCheck("RSA-2048", "public", ret, 1, calls, out,
            mpfsAthenaKatRsaCt, sizeof(out));
    #else
        ret = wc_MpfsAthenaKatCheck("RSA-2048", "public", ret, 0, calls, out,
            mpfsAthenaKatRsaCt, sizeof(out));
    #endif
    }
#ifndef WOLFSSL_RSA_PUBLIC_ONLY
    if (ret == 0) {
        outSz = sizeof(out);
        calls = mpfsAthenaCbCalls;
        ret = wc_RsaFunction(mpfsAthenaKatRsaCt, sizeof(mpfsAthenaKatRsaCt),
            out, &outSz, RSA_PRIVATE_DECRYPT, &key, &rng);
        if (ret == 0 && outSz != sizeof(out)) {
            ret = WC_HW_E;
        }
        ret = wc_MpfsAthenaKatCheck("RSA-2048", "private", ret, 1, calls, out,
            buf, sizeof(out));
    }
#endif
    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);
    ForceZero(out, sizeof(out));
    return ret;
}
#endif /* WC_MPFS_ATHENA_KAT_RSA */

/* The message 0x00..0xFF and a digest, a literal 64 because the enum
 * WC_SHA512_DIGEST_SIZE reads as 0 here; the AES KAT may need more. */
#ifdef WC_MPFS_ATHENA_HASH
    #define WC_MPFS_ATHENA_KAT_MSG_SZ (256 + 64)
#else
    #define WC_MPFS_ATHENA_KAT_MSG_SZ 256
#endif
#if defined(WC_MPFS_ATHENA_KAT_AES) && \
        (2 * WC_MPFS_ATHENA_KAT_AES_SZ) > WC_MPFS_ATHENA_KAT_MSG_SZ
    #define WC_MPFS_ATHENA_KAT_BUF_SZ (2 * WC_MPFS_ATHENA_KAT_AES_SZ)
#else
    #define WC_MPFS_ATHENA_KAT_BUF_SZ WC_MPFS_ATHENA_KAT_MSG_SZ
#endif

int wc_MpfsAthena_SelfTest(void)
{
#ifdef WOLFSSL_SMALL_STACK
    word32* bufW;
#else
    word32 bufW[WC_MPFS_ATHENA_KAT_BUF_SZ / sizeof(word32)];
#endif
    byte* buf;
    word32 i;
    int ret = 0;

    mpfsAthenaFailWhat = NULL;
#ifdef WOLFSSL_SMALL_STACK
    bufW = (word32*)XMALLOC(WC_MPFS_ATHENA_KAT_BUF_SZ, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (bufW == NULL) {
        mpfsAthenaFailWhat = "self-test buffer";
        return MEMORY_E;
    }
#endif
    buf = (byte*)bufW;

#ifdef WC_MPFS_ATHENA_HASH
    wc_MpfsAthenaKatSeq(buf, 256, 0);
    for (i = 0; ret == 0 &&
            i < sizeof(mpfsAthenaKatShas) / sizeof(mpfsAthenaKatShas[0]);
            i++) {
        ret = wc_MpfsAthenaKatSha(&mpfsAthenaKatShas[i], buf, buf + 256);
    }
#endif
#ifdef WC_MPFS_ATHENA_KAT_AES
    for (i = 0; ret == 0 &&
            i < sizeof(mpfsAthenaKatAess) / sizeof(mpfsAthenaKatAess[0]);
            i++) {
        ret = wc_MpfsAthenaKatAes(&mpfsAthenaKatAess[i], buf);
    #if defined(WC_MPFS_ATHENA_CMAC) && defined(WOLFSSL_AES_DIRECT)
        if (ret == 0) {
            ret = wc_MpfsAthenaKatCmac(&mpfsAthenaKatAess[i], buf);
        }
    #endif
    }
#endif
#ifdef WC_MPFS_ATHENA_RNG
    if (ret == 0) {
        ret = wc_MpfsAthenaKatRng(buf);
    }
#endif
#ifdef WC_MPFS_ATHENA_ECC
    if (ret == 0) {
        ret = wc_MpfsAthenaKatEcc(buf);
    }
#endif
#ifdef WC_MPFS_ATHENA_KAT_RSA
    if (ret == 0) {
        ret = wc_MpfsAthenaKatRsa(buf);
    }
#endif
    (void)buf;
    (void)i;

#ifdef WOLFSSL_SMALL_STACK
    XFREE(bufW, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    if (ret != 0) {
        WOLFSSL_MSG_EX("MPFS Athena self-test: %s (rc %d, engine calls %u)",
            wc_MpfsAthena_SelfTestDesc(), ret,
            (unsigned int)mpfsAthenaCbCalls);
    }
    return ret;
}

#else /* WC_MPFS_ATHENA_SELFTEST */

const char* wc_MpfsAthena_SelfTestDesc(void)
{
    return "self-test not compiled in";
}

int wc_MpfsAthena_SelfTest(void)
{
    return NOT_COMPILED_IN;
}

#endif /* WC_MPFS_ATHENA_SELFTEST */
#endif /* WOLFSSL_MPFS_ATHENA && WOLF_CRYPTO_CB */
