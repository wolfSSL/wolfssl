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

/* SHA-384 and AES-256-CTR on the PolarFire SoC Athena F5200, through the
 * wolfCrypt crypto callback. See wolfssl/wolfcrypt/port/microchip/mpfs_athena.h
 * and the README in this directory. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* wolfSSL's types.h and CAL's caltypes.h both define uint128_t, differently --
 * the only name they collide on. Dropping wolfSSL's 128-bit typedefs here moves
 * no struct (SP_WORD_SIZE keys off HAVE___UINT128_T) and nothing here uses
 * word128. Must stay local: in CFLAGS it would change the whole build. */
#ifndef NO_INT128
    #define NO_INT128
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_MPFS_ATHENA) && defined(WOLF_CRYPTO_CB)

#include <wolfssl/wolfcrypt/port/microchip/mpfs_athena.h>

/* Guarded, not simply set: the hart-software-services calpolicy.h defines both
 * already, the polarfire-soc-bare-metal-examples copy defines neither and stops
 * with "CALCONFIGH not defined". CAL is referenced, never vendored. */
#ifndef CALCONFIGH
    #define CALCONFIGH "config_user.h"
#endif
#ifndef INC_STDINT_H
    #define INC_STDINT_H
#endif
#include "calini.h"
#include "hash.h"
#include "sym.h"

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* One published CAL builds PKX0_BASE from this and will not link without it;
 * the other compiles the address in and never references it. Define
 * WC_MPFS_ATHENA_NO_BASE_ADDR when the platform supplies its own. */
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

/* Callback entries served. The self-test needs it: with registration failed,
 * software computes the right answer and a digest-only KAT still passes. */
static word32 mpfsAthenaCbCalls;

/* One-shot: resetting the core after CALIni() kills AES, so there is no
 * teardown counterpart. */
static int mpfsAthenaReady;

word32 wc_MpfsAthena_GetCbCount(void)
{
    return mpfsAthenaCbCalls;
}

/* Taken under the same mutex as the CAL transactions, so the count cannot tear
 * against a concurrent offload. A lock failure only loses a count. */
static void wc_MpfsAthenaCountCall(void)
{
    if (wolfSSL_CryptHwMutexLock() == 0) {
        mpfsAthenaCbCalls++;
        wolfSSL_CryptHwMutexUnLock();
    }
}

/* Ungate, un-reset, then CALIni() - in that order, once per image. Asserting
 * RESET after CALIni() leaves AES silently dead (CALSymEncrypt() returns
 * SATR_SUCCESS and writes nothing) while hashing still works, and only another
 * CALIni() recovers. Stall seed from rdcycle: mcycle traps in S-mode. */
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

    /* Once only: CALIni() must follow the un-reset and nothing may reset the
     * core after it. */
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

/* Non-DMA entry points only: the shipped archive is built USE_X52EXEC_DMA 0, so
 * CALHashDMA() and aesf5200dma() return success without moving data.
 *
 * Every CAL transaction below runs under the wolfCrypt hardware mutex. CAL is
 * configured with one resource handle (MAXRESHANDLES 1) and the engine is a
 * single block, so two hash contexts, or a hash and a cipher, would otherwise
 * corrupt each other mid-operation. The AES pair is locked as a unit because
 * CALSymEncrypt() only starts the transfer that CALSymTrfRes() waits for. */

#ifdef WOLFSSL_SHA384
static int wc_MpfsAthenaShaIni(word32* calCtx)
{
    SATR rc;
    int ret;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }
    rc = CALHashCtxIni((SATRESCONTEXTPTR)calCtx, SATHASHTYPE_SHA384);
    if (rc != SATR_SUCCESS) {
        mpfsAthenaCalRc = (int)rc;
    }
    wolfSSL_CryptHwMutexUnLock();

    if (rc != SATR_SUCCESS) {
        return WC_HW_E;
    }
    return 0;
}

/* inSz must be whole blocks unless last is set: a short non-final chunk is
 * rejected with SATR_BADHASHLEN (30). With last, any inSz including 0 works and
 * the engine pads. Handle 0 is valid; state lives in calCtx, so contexts
 * interleave. */
static int wc_MpfsAthenaSha(word32* calCtx, const byte* in, word32 inSz,
    byte* digest, int last)
{
    SATR rc;
    int ret;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }
    rc = CALHashCtx((SATRESHANDLE)0, (SATRESCONTEXTPTR)calCtx, in,
        (SATUINT32_t)inSz, digest, last ? SAT_TRUE : SAT_FALSE);
    if (rc != SATR_SUCCESS) {
        mpfsAthenaCalRc = (int)rc;
    }
    wolfSSL_CryptHwMutexUnLock();

    if (rc != SATR_SUCCESS) {
        return WC_HW_E;
    }
    return 0;
}

#endif /* WOLFSSL_SHA384 */

#if defined(WOLFSSL_AES_COUNTER) && !defined(NO_AES)
/* sz must be whole blocks. ctr is advanced in place, so consecutive calls
 * continue one keystream. CTR is symmetric: one routine, both directions. */
static int wc_MpfsAthenaAesCtr(const word32* key, byte* ctr, const byte* in,
    byte* out, word32 sz)
{
    SATR rc;
    int ret;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }
    rc = CALSymEncrypt(SATSYMTYPE_AES256, (const SATUINT32_t*)key,
        SATSYMMODE_CTR, ctr, SAT_TRUE, in, out, (SATUINT32_t)sz);
    if (rc == SATR_SUCCESS) {
        /* CALSymEncrypt() only starts the transfer. Without this wait the
         * output buffer is never written while both calls report success. */
        rc = CALSymTrfRes(SAT_TRUE);
    }
    if (rc != SATR_SUCCESS) {
        mpfsAthenaCalRc = (int)rc;
    }
    wolfSSL_CryptHwMutexUnLock();

    if (rc != SATR_SUCCESS) {
        return WC_HW_E;
    }
    return 0;
}
#endif /* WOLFSSL_AES_COUNTER && !NO_AES */

#ifdef WOLFSSL_SHA384

/* Hangs on wc_Sha384's devCtx; the callback's free and copy events own its
 * lifetime, so an abandoned context strands nothing. */

typedef struct MpfsAthenaShaCtx {
    word32 calCtx[WC_MPFS_ATHENA_CTX_WORDS]; /* opaque SATRESCONTEXT */
    byte   part[WC_MPFS_ATHENA_BLOCK_SZ];    /* short of a block, held over */
    word32 partLen;
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
    if (wolfSSL_CryptHwMutexLock() != 0) {
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

/* The engine is asked for the empty message first and this is the fallback if
 * it refuses a zero-length final, as the Renesas RX64 and MAX3266X ports do. */
static const byte mpfsAthenaSha384Empty[WC_SHA384_DIGEST_SIZE] = {
    0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38,
    0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
    0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43,
    0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
    0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb,
    0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b
};

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

/* Update, final, and the one-shot carrying both. Declining is only safe before
 * any data reaches the engine; past that wolfCrypt's own state is incomplete
 * and a software fallback would be silently wrong, so failures are WC_HW_E. */
static int wc_MpfsAthenaShaDev(wc_CryptoInfo* info)
{
    wc_Sha384* sha384 = info->hash.sha384;
    MpfsAthenaShaCtx* ctx;
    int ret;

    if (sha384 == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    ctx = (MpfsAthenaShaCtx*)sha384->devCtx;

    /* The empty message: no context yet, a final call, and nothing to add.
     * Borrows an engine context rather than putting one on the stack. The
     * software-state test below applies here too: a zero-length final on a
     * context software has already fed is not the empty message. */
    if (ctx == NULL && info->hash.digest != NULL &&
            (info->hash.in == NULL || info->hash.inSz == 0) &&
            sha384->buffLen == 0 && sha384->loLen == 0 && sha384->hiLen == 0) {
        ret = WC_HW_E;
        ctx = wc_MpfsAthenaShaNew(sha384->heap);
        if (ctx != NULL) {
            ret = wc_MpfsAthenaShaIni(ctx->calCtx);
            if (ret == 0) {
                ret = wc_MpfsAthenaSha(ctx->calCtx, NULL, 0,
                    info->hash.digest, 1);
            }
            wc_MpfsAthenaShaFree(ctx, sha384->heap);
        }
        if (ret != 0) {
            XMEMCPY(info->hash.digest, mpfsAthenaSha384Empty,
                WC_SHA384_DIGEST_SIZE);
        }
        wc_MpfsAthenaCountCall();
        return 0;
    }

    if (ctx == NULL) {
        /* Adopt only a context software has not already fed. A declined call
         * leaves devCtx NULL, so the next one would look like a first call and
         * hash only the remainder. wolfCrypt's lengths stay zero while the
         * engine serves, so this makes one decline stick. */
        if (sha384->buffLen != 0 || sha384->loLen != 0 || sha384->hiLen != 0) {
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
        /* The only point at which declining cannot produce a wrong answer. */
        ctx = wc_MpfsAthenaShaNew(sha384->heap);
        if (ctx == NULL) {
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
        ret = wc_MpfsAthenaShaIni(ctx->calCtx);
        if (ret != 0) {
            wc_MpfsAthenaShaFree(ctx, sha384->heap);
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
        sha384->devCtx = ctx;
    }

    if (info->hash.in != NULL && info->hash.inSz > 0) {
        ret = wc_MpfsAthenaShaFeed(ctx, info->hash.in, info->hash.inSz);
        if (ret != 0) {
            wc_MpfsAthenaShaFree(ctx, sha384->heap);
            sha384->devCtx = NULL;
            return ret;
        }
    }

    wc_MpfsAthenaCountCall();

    if (info->hash.digest != NULL) {
        /* Send whatever is left, any length including zero, and let the engine
         * pad. There is no software finalisation. */
        ret = wc_MpfsAthenaSha(ctx->calCtx, ctx->part, ctx->partLen,
            info->hash.digest, 1);
        wc_MpfsAthenaShaFree(ctx, sha384->heap);
        sha384->devCtx = NULL;
        if (ret != 0) {
            return ret;
        }
    }

    return 0;
}

/* Release the engine context, then decline so wc_Sha384Free() goes on to its
 * own ForceZero of the object and its small-stack-cache free: returning 0 here
 * makes it return early and skip both. devCtx is already NULL by then, so
 * nothing is released twice. */
static int wc_MpfsAthenaShaFreeDev(wc_CryptoInfo* info)
{
    wc_Sha384* sha384 = (wc_Sha384*)info->free.obj;

    if (sha384 != NULL && sha384->devCtx != NULL) {
        wc_MpfsAthenaShaFree((MpfsAthenaShaCtx*)sha384->devCtx, sha384->heap);
        sha384->devCtx = NULL;
    }
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}

/* wc_Sha384Copy() returns as soon as this returns 0, so taking the copy means
 * taking all of it. Declining would alias dst->devCtx onto src's: two contexts
 * on one engine context, released by whichever finalises first. */
static int wc_MpfsAthenaShaCopyDev(wc_CryptoInfo* info)
{
    wc_Sha384* src = (wc_Sha384*)info->copy.src;
    wc_Sha384* dst = (wc_Sha384*)info->copy.dst;
    MpfsAthenaShaCtx* srcCtx;
    MpfsAthenaShaCtx* dstCtx;

    if (src == NULL || dst == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    /* Nothing in the engine yet, so the ordinary copy is correct. The common
     * case, and the only one in which declining is safe. */
    if (src->devCtx == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    wc_Sha384Free(dst);
    XMEMCPY(dst, src, sizeof(wc_Sha384));

    /* Re-own what the copy above aliased onto the source. Kept in step with
     * wc_Sha384Copy(), which this handler stands in for: W is scratch for
     * _Transform_Sha512() and wc_Sha512Transform() and is allocated rather than
     * copied, and its size carries that second buffer. */
#if defined(WOLFSSL_SMALL_STACK_CACHE) && !defined(WC_SHA2_NO_SMALL_STACK)
    dst->W = (word64*)XMALLOC((sizeof(word64) * 16) + WC_SHA384_BLOCK_SIZE,
        dst->heap, DYNAMIC_TYPE_DIGEST);
    if (dst->W == NULL) {
        XMEMSET(dst, 0, sizeof(wc_Sha384));
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
            XMEMSET(dst, 0, sizeof(wc_Sha384));
            return MEMORY_E;
        }
        XMEMCPY(dst->msg, src->msg, src->len);
    }
#endif

    /* SATRESCONTEXT is a flat run of PODs with no pointers and no engine
     * handle, so a byte copy is a valid second context and the two interleave
     * freely from here. */
    srcCtx = (MpfsAthenaShaCtx*)src->devCtx;
    dstCtx = wc_MpfsAthenaShaNew(dst->heap);
    if (dstCtx == NULL) {
        /* dst keeps the buffers this handler allocated; wc_Sha384Free() on it
         * releases them, so only the stale engine pointer has to go. */
        dst->devCtx = NULL;
        return MEMORY_E;
    }
    XMEMCPY(dstCtx, srcCtx, sizeof(*dstCtx));
    dst->devCtx = dstCtx;

    return 0;
}

#endif /* WOLFSSL_SHA384 */

#if defined(WOLFSSL_AES_COUNTER) && !defined(NO_AES)
/* AES-256-CTR, one path for both directions (info->cipher.enc unread).
 * Keystream state is wolfCrypt's own: aes->tmp holds one front-aligned block,
 * aes->left counts its unconsumed tail, aes->reg is already past it. Every
 * bail-out is above the first engine call, or the counter desynchronises. */
static int wc_MpfsAthenaAesCtrDev(wc_CryptoInfo* info)
{
    Aes* aes = info->cipher.aesctr.aes;
    const byte* in = info->cipher.aesctr.in;
    byte* out = info->cipher.aesctr.out;
    word32 sz = info->cipher.aesctr.sz;
    word32 whole;
    word32 processed;
    int ret;

    if (aes == NULL || in == NULL || out == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    /* AES-256 only. The engine does 128 and 192 as well, but only 256 has been
     * run on silicon and an untested path is worse than none. */
    if (aes->keylen != 32) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    /* wc_AesCtrEncrypt() returns above the callback when sz is 0. */
    if (sz == 0) {
        return 0;
    }

    /* Keystream wolfCrypt is still holding from a previous partial block.
     * Consumed here rather than declined: aes->reg is already past that block,
     * so the engine resumes at the right counter, and declining would have
     * nothing to fall back to in a WOLF_CRYPTO_CB_ONLY_AES build. */
    if (aes->left > 0) {
        processed = (aes->left < sz) ? aes->left : sz;
        xorbufout(out, in, (byte*)aes->tmp + WC_AES_BLOCK_SIZE - aes->left,
            processed);
        out += processed;
        in += processed;
        aes->left -= processed;
        sz -= processed;
    }

    whole = sz - (sz % WC_AES_BLOCK_SIZE);
    if (whole > 0) {
        ret = wc_MpfsAthenaAesCtr(aes->devKey, (byte*)aes->reg, in, out, whole);
        if (ret != 0) {
            return ret;
        }
        in += whole;
        out += whole;
        sz -= whole;
    }

    if (sz > 0) {
        /* Take one keystream block and leave the unused tail where wolfCrypt
         * keeps its own, so the next call continues the stream whichever path
         * serves it. Run on a local block, not in place on aes->tmp: on a
         * failure return the Aes state then stays self-consistent. */
        byte ks[WC_AES_BLOCK_SIZE];

        XMEMSET(ks, 0, sizeof(ks));
        ret = wc_MpfsAthenaAesCtr(aes->devKey, (byte*)aes->reg, ks, ks,
            WC_AES_BLOCK_SIZE);
        if (ret != 0) {
            ForceZero(ks, sizeof(ks));
            return ret;
        }
        xorbufout(out, in, ks, sz);
        XMEMCPY(aes->tmp, ks, WC_AES_BLOCK_SIZE);
        aes->left = WC_AES_BLOCK_SIZE - sz;
        ForceZero(ks, sizeof(ks));
    }

    wc_MpfsAthenaCountCall();
    return 0;
}
#endif /* WOLFSSL_AES_COUNTER && !NO_AES */

int wc_MpfsAthena_CryptoDevCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    (void)devId;
    (void)ctx;

    if (info == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    switch (info->algo_type) {
#ifdef WOLFSSL_SHA384
        case WC_ALGO_TYPE_HASH:
            /* SHA-384 only. A decline is retried as WC_HASH_TYPE_SHA512 over
             * the same object, so that must keep declining; adding SHA-512 here
             * needs WOLF_CRYPTO_CB_NO_SHA512_FALLBACK or it would report a
             * SHA-512 of SHA-384 state as a SHA-384 digest. */
            if (info->hash.type == WC_HASH_TYPE_SHA384) {
                return wc_MpfsAthenaShaDev(info);
            }
            break;
#endif

#if defined(WOLFSSL_AES_COUNTER) && !defined(NO_AES)
        case WC_ALGO_TYPE_CIPHER:
            if (info->cipher.type == WC_CIPHER_AES_CTR) {
                return wc_MpfsAthenaAesCtrDev(info);
            }
            break;
#endif

#ifdef WOLFSSL_SHA384
        case WC_ALGO_TYPE_FREE:
            /* WC_HASH_TYPE_SHA512 here is wc_Sha512Free()'s object, which this
             * port never owns. */
            if (info->free.algo == WC_ALGO_TYPE_HASH &&
                    info->free.type == WC_HASH_TYPE_SHA384) {
                return wc_MpfsAthenaShaFreeDev(info);
            }
            break;

        case WC_ALGO_TYPE_COPY:
            if (info->copy.algo == WC_ALGO_TYPE_HASH &&
                    info->copy.type == WC_HASH_TYPE_SHA384) {
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

    /* Deliberately no wc_CryptoCb_Init() here: it clears the whole device
     * table, so a port calling it would unregister every other device.
     * wolfCrypt_Init() already does it. A caller that skips wolfCrypt_Init()
     * leaves the table reading as full and lands on the BUFFER_E below. */
    ret = wc_CryptoCb_RegisterDevice(devId, wc_MpfsAthena_CryptoDevCb, NULL);
    if (ret == WC_NO_ERR_TRACE(ALREADY_E)) {
        /* Idempotent: the device is registered, which is what the caller asked
         * for. Both wolfcrypt_test() and benchmark() register, so a harness
         * that runs either twice, or an application that registered first,
         * would otherwise fail on the second call. */
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

/* Known-answer tests. Compiled by default: the callback count they check is
 * the only thing that tells a live engine from a silent software fallback.
 * WC_MPFS_ATHENA_NO_SELFTEST drops them where size matters more. */
#ifndef WC_MPFS_ATHENA_NO_SELFTEST

/* Driven through the public API so the whole dispatch chain is covered, with
 * the callback count part of the pass condition. Run it at init, before other
 * threads drive the engine: a concurrent offload would add to the count this
 * checks. */

static const char* mpfsAthenaFailWhat;

const char* wc_MpfsAthena_SelfTestDesc(void)
{
    return (mpfsAthenaFailWhat != NULL) ? mpfsAthenaFailWhat : "ok";
}

#ifdef WOLFSSL_SHA384
/* SHA-384 of the 256 bytes 0x00..0xFF. */
static const byte mpfsAthenaKatSha384[WC_SHA384_DIGEST_SIZE] = {
    0xff, 0xda, 0xeb, 0xff, 0x65, 0xed, 0x05, 0xcf,
    0x40, 0x0f, 0x02, 0x21, 0xc4, 0xcc, 0xfb, 0x4b,
    0x21, 0x04, 0xfb, 0x6a, 0x51, 0xf8, 0x7e, 0x40,
    0xbe, 0x6c, 0x43, 0x09, 0x38, 0x6b, 0xfd, 0xec,
    0x28, 0x92, 0xe9, 0x17, 0x9b, 0x34, 0x63, 0x23,
    0x31, 0xa5, 0x95, 0x92, 0x73, 0x7d, 0xb5, 0xc5
};

/* SHA-384 of the first 100 of those bytes: what wc_Sha384GetHash() must return
 * mid-stream, which is the copy handler's job. */
static const byte mpfsAthenaKatSha384Part[WC_SHA384_DIGEST_SIZE] = {
    0x3d, 0x20, 0xe3, 0x3b, 0xa4, 0xd5, 0x2a, 0x8c,
    0x37, 0x48, 0x78, 0xf1, 0xa6, 0x24, 0xa9, 0x07,
    0x13, 0x22, 0x64, 0xd0, 0xc8, 0x31, 0xc6, 0x4f,
    0xc5, 0x1e, 0xd8, 0xe1, 0xcd, 0xb7, 0x5d, 0x11,
    0xc3, 0xfc, 0x78, 0xd4, 0xc3, 0xcf, 0xbf, 0x99,
    0xd7, 0xf0, 0xbe, 0xa9, 0x82, 0x9b, 0x72, 0x5c
};
#endif

#if defined(WOLFSSL_AES_COUNTER) && !defined(NO_AES)
/* AES-256-CTR of 0x00..0x1F under key 0x00..0x1F, counter 0x00..0x0F. */
static const byte mpfsAthenaKatAesCtr[32] = {
    0x5a, 0x6f, 0x06, 0x54, 0x0c, 0xfe, 0x77, 0x91,
    0xf8, 0x27, 0x5f, 0x36, 0x0e, 0xce, 0xa8, 0x9d,
    0x70, 0xe2, 0x02, 0xc6, 0xd7, 0x90, 0x4e, 0x4a,
    0x4d, 0x0f, 0xe1, 0x4a, 0x6e, 0xf8, 0x3e, 0xd0
};
#endif

#ifdef WOLFSSL_SHA384
/* 100 + 100 + 56 is chosen: it buffers, flushes on full twice, carries state
 * across three calls, and leaves the final carrying zero bytes. */
static int wc_MpfsAthenaKatSha384(byte* buf, byte* digest)
{
    wc_Sha384 sha;
    int ret;

    mpfsAthenaCbCalls = 0;

    ret = wc_InitSha384_ex(&sha, NULL, WC_MPFS_ATHENA_DEVID);
    if (ret != 0) {
        mpfsAthenaFailWhat = "SHA-384 init";
        return ret;
    }
    ret = wc_Sha384Update(&sha, buf, 100);
    if (ret == 0) {
        ret = wc_Sha384Update(&sha, buf + 100, 100);
    }
    if (ret == 0) {
        ret = wc_Sha384Update(&sha, buf + 200, 56);
    }
    if (ret != 0) {
        mpfsAthenaFailWhat = "SHA-384 update";
    }
    if (ret == 0) {
        ret = wc_Sha384Final(&sha, digest);
        if (ret != 0) {
            mpfsAthenaFailWhat = "SHA-384 final";
        }
    }
    wc_Sha384Free(&sha);
    if (ret != 0) {
        return ret;
    }

    if (mpfsAthenaCbCalls == 0) {
        mpfsAthenaFailWhat = "SHA-384 never reached the engine (software)";
        return WC_HW_E;
    }
    if (XMEMCMP(digest, mpfsAthenaKatSha384, WC_SHA384_DIGEST_SIZE) != 0) {
        mpfsAthenaFailWhat = "SHA-384 digest mismatch";
        return WC_HW_E;
    }

    /* The empty message, which the engine takes as a zero-length final. */
    ret = wc_InitSha384_ex(&sha, NULL, WC_MPFS_ATHENA_DEVID);
    if (ret == 0) {
        ret = wc_Sha384Final(&sha, digest);
        wc_Sha384Free(&sha);
    }
    if (ret != 0) {
        mpfsAthenaFailWhat = "SHA-384 empty message";
        return ret;
    }
    if (XMEMCMP(digest, mpfsAthenaSha384Empty, WC_SHA384_DIGEST_SIZE) != 0) {
        mpfsAthenaFailWhat = "SHA-384 empty message mismatch";
        return WC_HW_E;
    }

    /* wc_Sha384GetHash() is copy-then-final, so this is the copy handler: it
     * has to fork a live engine context and leave the original usable. Both
     * digests are checked, because a copy that aliased the source would still
     * produce a plausible first answer and then corrupt the second. */
    ret = wc_InitSha384_ex(&sha, NULL, WC_MPFS_ATHENA_DEVID);
    if (ret == 0) {
        ret = wc_Sha384Update(&sha, buf, 100);
    }
    if (ret == 0) {
        ret = wc_Sha384GetHash(&sha, digest);
    }
    if (ret == 0 && XMEMCMP(digest, mpfsAthenaKatSha384Part,
            WC_SHA384_DIGEST_SIZE) != 0) {
        mpfsAthenaFailWhat = "SHA-384 mid-stream GetHash mismatch";
        ret = WC_HW_E;
    }
    if (ret == 0) {
        ret = wc_Sha384Update(&sha, buf + 100, 156);
    }
    if (ret == 0) {
        ret = wc_Sha384Final(&sha, digest);
    }
    wc_Sha384Free(&sha);
    if (ret != 0) {
        if (mpfsAthenaFailWhat == NULL) {
            mpfsAthenaFailWhat = "SHA-384 copy";
        }
        return ret;
    }
    if (XMEMCMP(digest, mpfsAthenaKatSha384, WC_SHA384_DIGEST_SIZE) != 0) {
        mpfsAthenaFailWhat = "SHA-384 digest wrong after a copy";
        return WC_HW_E;
    }
    return 0;
}
#endif /* WOLFSSL_SHA384 */

#if defined(WOLFSSL_AES_COUNTER) && !defined(NO_AES)
/* One pass of AES-256-CTR split at the given boundary, on a fresh context. */
static int wc_MpfsAthenaKatAesRun(const byte* key, const byte* ctr,
    const byte* in, byte* out, word32 split)
{
    Aes aes;
    int ret;

    ret = wc_AesInit(&aes, NULL, WC_MPFS_ATHENA_DEVID);
    if (ret != 0) {
        return ret;
    }
    ret = wc_AesSetKey(&aes, key, 32, ctr, AES_ENCRYPTION);
    if (ret == 0) {
        ret = wc_AesCtrEncrypt(&aes, out, in, split);
    }
    if (ret == 0 && split < 32) {
        ret = wc_AesCtrEncrypt(&aes, out + split, in + split, 32 - split);
    }
    wc_AesFree(&aes);
    return ret;
}

static int wc_MpfsAthenaKatAesCtr(const byte* in)
{
    byte key[32];
    byte ctr[WC_AES_BLOCK_SIZE];
    byte out[32];
    int ret;
    int i;

    for (i = 0; i < (int)sizeof(key); i++) {
        key[i] = (byte)i;
    }
    for (i = 0; i < (int)sizeof(ctr); i++) {
        ctr[i] = (byte)i;
    }

    /* One 32-byte call: two whole blocks in a single engine transfer. */
    mpfsAthenaCbCalls = 0;
    ret = wc_MpfsAthenaKatAesRun(key, ctr, in, out, 32);
    if (ret == 0 && mpfsAthenaCbCalls == 0) {
        mpfsAthenaFailWhat = "AES-256-CTR never reached the engine (software)";
        ret = WC_HW_E;
    }
    if (ret == 0 && XMEMCMP(out, mpfsAthenaKatAesCtr, sizeof(out)) != 0) {
        mpfsAthenaFailWhat = "AES-256-CTR known-answer mismatch";
        ret = WC_HW_E;
    }

    /* 16 + 16: the engine advances the counter in aes->reg in place, so two
     * calls must equal one. The image decrypt path calls CTR once per chunk and
     * depends on exactly this. */
    if (ret == 0) {
        XMEMSET(out, 0, sizeof(out));
        ret = wc_MpfsAthenaKatAesRun(key, ctr, in, out, 16);
        if (ret == 0 &&
                XMEMCMP(out, mpfsAthenaKatAesCtr, sizeof(out)) != 0) {
            mpfsAthenaFailWhat = "AES-256-CTR counter does not carry";
            ret = WC_HW_E;
        }
    }

    /* 20 + 12: the first call leaves 12 bytes of keystream in aes->tmp, and the
     * second is served entirely from that drain with no engine call - so this
     * phase covers both halves of the aes->tmp/aes->left contract. */
    if (ret == 0) {
        XMEMSET(out, 0, sizeof(out));
        ret = wc_MpfsAthenaKatAesRun(key, ctr, in, out, 20);
        if (ret == 0 &&
                XMEMCMP(out, mpfsAthenaKatAesCtr, sizeof(out)) != 0) {
            mpfsAthenaFailWhat = "AES-256-CTR partial block mismatch";
            ret = WC_HW_E;
        }
    }

    if (ret != 0 && mpfsAthenaFailWhat == NULL) {
        mpfsAthenaFailWhat = "AES-256-CTR";
    }
    ForceZero(key, sizeof(key));
    return ret;
}
#endif /* WOLFSSL_AES_COUNTER && !NO_AES */

/* 256 message bytes, plus room for a digest after them when SHA-384 is in the
 * build. WC_SHA384_DIGEST_SIZE only exists under WOLFSSL_SHA384, so an AES-only
 * build must not name it. */
#ifdef WOLFSSL_SHA384
    #define WC_MPFS_ATHENA_KAT_BUF_SZ (256 + WC_SHA384_DIGEST_SIZE)
#else
    #define WC_MPFS_ATHENA_KAT_BUF_SZ (256)
#endif

int wc_MpfsAthena_SelfTest(void)
{
#ifdef WOLFSSL_SMALL_STACK
    byte* buf;
#else
    byte buf[WC_MPFS_ATHENA_KAT_BUF_SZ];
#endif
    int ret;
    int i;

    mpfsAthenaFailWhat = NULL;
    mpfsAthenaCalRc = 0;

#ifdef WOLFSSL_SMALL_STACK
    buf = (byte*)XMALLOC(WC_MPFS_ATHENA_KAT_BUF_SZ, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL) {
        mpfsAthenaFailWhat = "self-test buffer";
        return MEMORY_E;
    }
#endif

    for (i = 0; i < 256; i++) {
        buf[i] = (byte)i;
    }

    ret = 0;
#ifdef WOLFSSL_SHA384
    ret = wc_MpfsAthenaKatSha384(buf, buf + 256);
#endif
#if defined(WOLFSSL_AES_COUNTER) && !defined(NO_AES)
    if (ret == 0) {
        ret = wc_MpfsAthenaKatAesCtr(buf);
    }
#endif

#ifdef WOLFSSL_SMALL_STACK
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    if (ret != 0) {
        WOLFSSL_MSG_EX("MPFS Athena self-test: %s (rc %d, CAL rc %d, "
            "engine calls %u)", wc_MpfsAthena_SelfTestDesc(), ret,
            mpfsAthenaCalRc, (unsigned int)mpfsAthenaCbCalls);
    }
    return ret;
}


#else /* WC_MPFS_ATHENA_NO_SELFTEST */

const char* wc_MpfsAthena_SelfTestDesc(void)
{
    return "self-test not compiled in";
}

int wc_MpfsAthena_SelfTest(void)
{
    return NOT_COMPILED_IN;
}

#endif /* WC_MPFS_ATHENA_NO_SELFTEST */
#endif /* WOLFSSL_MPFS_ATHENA && WOLF_CRYPTO_CB */
