/* els_pkc_port.c
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

/* wolfCrypt crypto callback port for the NXP EdgeLock subsystem. ELS has
 * global busy state, so every command and its wait run under one lock. */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef WOLFSSL_ELS_PKC

/* Name the missing Kconfig option rather than fail on mcuxClEls.h. */
#if defined(__ZEPHYR__) && !defined(CONFIG_MCUX_ELS_PKC)
    #error "WOLFSSL_ELS_PKC requires the NXP els_pkc module (CONFIG_MCUX_ELS_PKC=y)"
#endif

#include <wolfssl/wolfcrypt/port/nxp/els_pkc_port.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#include <mcuxClEls.h>
#include <mcuxCsslFlowProtection.h>

/* per-SoC bring-up helper; els_pkc provides one for each supported platform */
#include <mcux_els.h>

#ifdef WOLFSSL_ZEPHYR
    #include <zephyr/kernel.h>
    #include <zephyr/irq.h>
#endif

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

static wolfSSL_Mutex elsLock;
/* Read from the crypto-callback path, written by init/cleanup. Volatile so a
 * compiler cannot cache the flag across the mutex operations that order them. */
static volatile int elsLockInit = 0;
static volatile int elsRegistered = 0;
/* Set only once the peripheral is actually up. */
static volatile int elsReady = 0;

#ifdef WOLFSSL_ZEPHYR
static void ElsDropStaleDone(void);
#else
    #define ElsDropStaleDone() WC_DO_NOTHING
#endif

static int ElsLock(void)
{
    /* The mutex exists before the peripheral is enabled, so test elsReady
     * too. */
    if (!elsLockInit || !elsReady) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }
    if (wc_LockMutex(&elsLock) != 0) {
        return WC_NO_ERR_TRACE(BAD_MUTEX_E);
    }
    /* Cleanup may have run while this caller waited for the mutex. */
    if (!elsReady) {
        (void)wc_UnLockMutex(&elsLock);
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }
    ElsDropStaleDone();
    return 0;
}

static void ElsUnlock(void)
{
    if (elsLockInit) {
        (void)wc_UnLockMutex(&elsLock);
    }
}

/* mcuxClEls_WaitForOperation() spins with no timeout, so sleep on the
 * completion interrupt where a kernel is available. */

#ifndef WOLFSSL_ELS_PKC_TIMEOUT_MS
    #define WOLFSSL_ELS_PKC_TIMEOUT_MS 1000
#endif

/* Spin this long before blocking, since a short operation finishes sooner
 * than a thread switch. Zero never spins. */
#ifndef WOLFSSL_ELS_PKC_SPIN_US
    #define WOLFSSL_ELS_PKC_SPIN_US 128
#endif

#ifdef WOLFSSL_ZEPHYR

static struct k_sem elsDone;
static volatile int elsIrqReady = 0;

static void ElsIsr(const void* arg)
{
    mcuxClEls_InterruptOptionRst_t rst;

    (void)arg;

    /* acknowledge at the peripheral before releasing the waiter, so a fast
     * follow-up operation cannot see a stale flag */
    rst.word.value = 0u;
    rst.bits.elsint = MCUXCLELS_ELS_RESET_CLEAR;
    (void)mcuxClEls_ResetIntFlags(rst);

    k_sem_give(&elsDone);
}

/* Arm the completion interrupt. Called once from wc_ElsPkc_Init(). */
static int ElsIrqInit(void)
{
    mcuxClEls_InterruptOptionEn_t en;
    mcuxClEls_InterruptOptionRst_t rst;

    if (elsIrqReady) {
        return 0;
    }

    k_sem_init(&elsDone, 0, 1);

    IRQ_CONNECT(ELS_IRQn, WOLFSSL_ELS_PKC_IRQ_PRIO, ElsIsr, NULL, 0);
    irq_enable(ELS_IRQn);

    /* The enable at bring-up was polled, so its completion is still latched. */
    rst.word.value = 0u;
    rst.bits.elsint = MCUXCLELS_ELS_RESET_CLEAR;
    (void)mcuxClEls_ResetIntFlags(rst);

    en.word.value = 0u;
    en.bits.elsint = MCUXCLELS_ELS_INTERRUPT_ENABLE;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEls_SetIntEnableFlags(en));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_SetIntEnableFlags) != t) ||
        (MCUXCLELS_STATUS_OK != r)) {
        irq_disable(ELS_IRQn);
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    elsIrqReady = 1;

    return 0;
}

/* Sleeping needs the armed interrupt and a thread to put to sleep. */
static int ElsCanSleep(void)
{
    return elsIrqReady && !k_is_in_isr();
}

/* Take the completion semaphore without blocking, for as long as the spin
 * budget allows. Returns whether it was taken. */
static int ElsSpinForDone(void)
{
#if WOLFSSL_ELS_PKC_SPIN_US > 0
    uint32_t start = k_cycle_get_32();
    uint32_t budget = k_us_to_cyc_ceil32(WOLFSSL_ELS_PKC_SPIN_US);

    do {
        if (k_sem_take(&elsDone, K_NO_WAIT) == 0) {
            return 1;
        }
    } while ((k_cycle_get_32() - start) < budget);
#endif

    return 0;
}

/* A completion nobody waited for, from bring-up or a polled wait, must not end
 * the next command's wait early. Caller holds the lock. */
static void ElsDropStaleDone(void)
{
    if (elsIrqReady) {
        k_sem_reset(&elsDone);
    }
}

/* Under the lock, so no caller is left asleep on a disabled interrupt. */
static void ElsIrqDisarm(void)
{
    if (elsIrqReady) {
        irq_disable(ELS_IRQn);
        elsIrqReady = 0;
    }
}

#else
    #define ElsIrqDisarm() WC_DO_NOTHING
#endif /* WOLFSSL_ZEPHYR */

#if defined(WOLFSSL_ELS_PKC_ALLOW_CANCEL) && defined(WOLFSSL_ZEPHYR)
/* Abandon the pending operation. A tamper event unless the ITRC has been
 * retargeted; see WOLFSSL_ELS_PKC_ALLOW_CANCEL. */
static void ElsCancel(void)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t,
        mcuxClEls_Reset_Async(MCUXCLELS_RESET_CANCEL));
    (void)r;
    (void)t;
    MCUX_CSSL_FP_FUNCTION_CALL_END();
}
#endif

/* Must be called with the lock held, and always paired with the _Async that
 * preceded it. */
static int ElsWait(void)
{
    int ret;
#ifdef WOLFSSL_ZEPHYR
    int timedOut = 0;
#ifdef WOLFSSL_ELS_PKC_ALLOW_CANCEL
    int cancelled = 0;
#endif

    if (ElsCanSleep()) {
        if (!ElsSpinForDone() &&
            k_sem_take(&elsDone, K_MSEC(WOLFSSL_ELS_PKC_TIMEOUT_MS)) != 0) {
            timedOut = 1;
            WOLFSSL_MSG("els_pkc: completion interrupt late");
#ifdef WOLFSSL_ELS_PKC_ALLOW_CANCEL
            /* The reset is itself async; wait for it so the next caller does
             * not get CANNOT_INTERRUPT. */
            ElsCancel();
            cancelled = 1;
#endif
        }
    }
#endif

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(res, tok,
        mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != tok) ||
        (MCUXCLELS_STATUS_OK != res)) {
        ret = WC_NO_ERR_TRACE(WC_HW_E);
    }
    else {
        ret = 0;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

#ifdef WOLFSSL_ZEPHYR
    /* The interrupt for this operation lands eventually. Drop it, or it would
     * satisfy the next wait before that operation had finished. */
    if (timedOut) {
        k_sem_reset(&elsDone);
    }
#ifdef WOLFSSL_ELS_PKC_ALLOW_CANCEL
    /* A cancelled operation produced no result, whatever the wait reported. */
    if (cancelled) {
        ret = WC_NO_ERR_TRACE(WC_HW_E);
    }
#endif
#endif

    return ret;
}

/* els_pkc ships this helper for every platform it supports, so the port stays
 * SoC-agnostic. */
static int ElsEnable(void)
{
    if (ELS_PowerDownWakeupInit(ELS) != 0) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }

    return 0;
}

/* State lives in the caller's object and the lock is held per call, since
 * TLS 1.3 keeps several transcript hashes open at once. ELS never pads. */

#if !defined(NO_SHA256) || defined(WOLFSSL_SHA384) || defined(WOLFSSL_SHA512)

#define ELS_SHA256_BLOCK MCUXCLELS_HASH_BLOCK_SIZE_SHA_256
#define ELS_SHA256_STATE MCUXCLELS_HASH_STATE_SIZE_SHA_256

/* SHA-384 and SHA-512 share the engine's block and state size, differing in
 * the mode selector, the digest truncation and a 128-bit length field. */
#if defined(WOLFSSL_SHA384) || defined(WOLFSSL_SHA512)
    #define ELS_HASH_SHA512
    #define ELS_HASH_MAX_BLOCK MCUXCLELS_HASH_BLOCK_SIZE_SHA_512
#else
    #define ELS_HASH_MAX_BLOCK ELS_SHA256_BLOCK
#endif

/* State uses the object's own digest[] and buffer[], so a struct copy
 * duplicates it and nothing needs freeing. */

/* Equalities, not bounds: a mismatch would overrun the caller's object. */
#ifndef NO_SHA256
wc_static_assert(WC_SHA256_DIGEST_SIZE == ELS_SHA256_STATE);
wc_static_assert(WC_SHA256_BLOCK_SIZE == ELS_SHA256_BLOCK);
#endif
#ifdef ELS_HASH_SHA512
wc_static_assert(WC_SHA512_DIGEST_SIZE == MCUXCLELS_HASH_STATE_SIZE_SHA_512);
wc_static_assert(WC_SHA512_BLOCK_SIZE == MCUXCLELS_HASH_BLOCK_SIZE_SHA_512);
#endif

/* The fields above exist only in the software arm of the #ifdef chain in
 * sha256.h and sha512.h; another SHA-2 port replaces them with its own. */
#if defined(FREESCALE_LTC_SHA) || defined(STM32_HASH_SHA2) || \
    defined(WOLFSSL_SILABS_SE_ACCEL) || defined(WOLFSSL_IMXRT_DCP) || \
    defined(PSOC6_HASH_SHA2) || \
    (defined(WOLFSSL_SE050) && defined(WOLFSSL_SE050_HASH)) || \
    (defined(WOLFSSL_HAVE_PSA) && !defined(WOLFSSL_PSA_NO_HASH)) || \
    defined(WOLFSSL_TI_HASH) || defined(WOLFSSL_AFALG_HASH) || \
    (defined(WOLFSSL_IMX6_CAAM) && !defined(WOLFSSL_QNX_CAAM)) || \
    ((defined(WOLFSSL_RENESAS_TSIP_TLS) || \
      defined(WOLFSSL_RENESAS_TSIP_CRYPTONLY)) && \
     !defined(NO_WOLFSSL_RENESAS_TSIP_CRYPT_HASH)) || \
    ((defined(WOLFSSL_RENESAS_SCEPROTECT) || defined(WOLFSSL_RENESAS_RSIP)) && \
     !defined(NO_WOLFSSL_RENESAS_FSPSM_HASH)) || \
    defined(WOLFSSL_RENESAS_RX64_HASH)
    #error "WOLFSSL_ELS_PKC hash offload conflicts with another SHA-2 port"
#endif

/* Parked in devCtx as a tagged scalar rather than a pointer, so that a struct
 * copy carries it and a free has nothing to release. */
#define ELS_HASH_OWNED   ((wc_ptr_t)0x1)
#define ELS_HASH_STARTED ((wc_ptr_t)0x2)  /* the engine has absorbed a block */
#define ELS_HASH_FAILED  ((wc_ptr_t)0x4)  /* a block never reached it */

/* FIPS 180-4 initial values, in the host-order form of digest[]. */
#ifndef NO_SHA256
static const word32 elsSha256Iv[8] = {
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
};
#endif
#ifdef WOLFSSL_SHA384
static const word64 elsSha384Iv[8] = {
    W64LIT(0xcbbb9d5dc1059ed8), W64LIT(0x629a292a367cd507),
    W64LIT(0x9159015a3070dd17), W64LIT(0x152fecd8f70e5939),
    W64LIT(0x67332667ffc00b31), W64LIT(0x8eb44a8768581511),
    W64LIT(0xdb0c2e0d64f98fa7), W64LIT(0x47b5481dbefa4fa4)
};
#endif
#ifdef WOLFSSL_SHA512
static const word64 elsSha512Iv[8] = {
    W64LIT(0x6a09e667f3bcc908), W64LIT(0xbb67ae8584caa73b),
    W64LIT(0x3c6ef372fe94f82b), W64LIT(0xa54ff53a5f1d36f1),
    W64LIT(0x510e527fade682d1), W64LIT(0x9b05688c2b3e6c1f),
    W64LIT(0x1f83d9abfb41bd6b), W64LIT(0x5be0cd19137e2179)
};
#endif

/* The caller's object, bound at the dispatch site so the offload below does
 * not care which of the three hashes it is driving. */
typedef struct ElsHashObj {
    void**  devCtx;
    byte*   state;     /* the object's digest[] */
    byte*   buf;       /* the object's buffer[] */
    word32* buffered;  /* the object's buffLen  */
    void*   lo;        /* the object's loLen    */
    void*   hi;        /* the object's hiLen    */
    const void* iv;    /* the software initial state, restored at Final */
    word32  stateSz;
    word32  blockSz;
    word32  lenSz;     /* width of the length field the padding ends with */
    byte    mode;      /* MCUXCLELS_HASH_MODE_* */
    byte    wide;      /* loLen/hiLen are word64, not word32 */
} ElsHashObj;

static word64 ElsHashTotal(const ElsHashObj* o)
{
    if (o->wide) {
        return *(const word64*)o->lo;
    }

    return ((word64)*(const word32*)o->hi << 32) |
           (word64)*(const word32*)o->lo;
}

static void ElsHashTotalSet(const ElsHashObj* o, word64 total)
{
    if (o->wide) {
        *(word64*)o->lo = total;
    }
    else {
        *(word32*)o->lo = (word32)total;
        *(word32*)o->hi = (word32)(total >> 32);
    }
}

#ifndef NO_SHA256
static void ElsHashBindSha256(ElsHashObj* o, wc_Sha256* sha)
{
    o->devCtx   = &sha->devCtx;
    o->state    = (byte*)sha->digest;
    o->buf      = (byte*)sha->buffer;
    o->buffered = &sha->buffLen;
    o->lo       = &sha->loLen;
    o->hi       = &sha->hiLen;
    o->iv       = elsSha256Iv;
    o->stateSz  = (word32)ELS_SHA256_STATE;
    o->blockSz  = (word32)ELS_SHA256_BLOCK;
    o->lenSz    = WC_SHA256_BLOCK_SIZE - WC_SHA256_PAD_SIZE;
    o->mode     = MCUXCLELS_HASH_MODE_SHA_256;
    o->wide     = 0;
}
#endif

#ifdef ELS_HASH_SHA512
static void ElsHashBindSha512(ElsHashObj* o, wc_Sha512* sha, byte mode)
{
    o->devCtx   = &sha->devCtx;
    o->state    = (byte*)sha->digest;
    o->buf      = (byte*)sha->buffer;
    o->buffered = &sha->buffLen;
    o->lo       = &sha->loLen;
    o->hi       = &sha->hiLen;
#if defined(WOLFSSL_SHA384) && defined(WOLFSSL_SHA512)
    o->iv       = (mode == MCUXCLELS_HASH_MODE_SHA_384) ? (const void*)elsSha384Iv
                                                        : (const void*)elsSha512Iv;
#elif defined(WOLFSSL_SHA384)
    o->iv       = elsSha384Iv;
#else
    o->iv       = elsSha512Iv;
#endif
    o->stateSz  = (word32)MCUXCLELS_HASH_STATE_SIZE_SHA_512;
    o->blockSz  = (word32)MCUXCLELS_HASH_BLOCK_SIZE_SHA_512;
    o->lenSz    = WC_SHA512_BLOCK_SIZE - WC_SHA512_PAD_SIZE;
    o->mode     = mode;
    o->wide     = 1;
}
#endif

/* Feed whole blocks to the engine, carrying the running state in and out.
 * Caller must hold the lock. len must be a multiple of the block size. */
static int ElsHashBlocks(const ElsHashObj* o, const byte* in, word32 len)
{
    mcuxClEls_HashOption_t opt;
    wc_ptr_t st = (wc_ptr_t)*o->devCtx;
    int ret;

    if (len == 0) {
        return 0;
    }

    opt.word.value = 0u;
    opt.bits.hashmd = o->mode;
    opt.bits.hashoe = MCUXCLELS_HASH_OUTPUT_ENABLE;
    if (st & ELS_HASH_STARTED) {
        opt.bits.hashini = MCUXCLELS_HASH_INIT_DISABLE;
        opt.bits.hashld  = MCUXCLELS_HASH_LOAD_ENABLE;
    }
    else {
        opt.bits.hashini = MCUXCLELS_HASH_INIT_ENABLE;
        opt.bits.hashld  = MCUXCLELS_HASH_LOAD_DISABLE;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t,
        mcuxClEls_Hash_Async(opt, in, len, o->state));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Hash_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    *o->devCtx = (void*)(st | ELS_HASH_STARTED);

    ret = ElsWait();

    return ret;
}

/* Absorb into the caller's object, taking it over on the first call. */
static int ElsHashUpdate(ElsHashObj* o, const byte* in, word32 inSz)
{
    word32 take, whole;
    int ret;

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    if (*o->devCtx == NULL) {
        /* Only a pristine object: the engine starts from the standard IV, and
         * SHA-512/224 and SHA-512/256 arrive as WC_HASH_TYPE_SHA512. */
        if (*o->buffered != 0 || ElsHashTotal(o) != 0 ||
            XMEMCMP(o->state, o->iv, o->stateSz) != 0) {
            ElsUnlock();
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
        *o->devCtx = (void*)ELS_HASH_OWNED;
    }
    else if ((wc_ptr_t)*o->devCtx & ELS_HASH_FAILED) {
        ElsUnlock();
        return WC_NO_ERR_TRACE(WC_HW_E);
    }

    ElsHashTotalSet(o, ElsHashTotal(o) + inSz);

    /* Hold the last block back so Final absorbs it with the padding. */
    if (*o->buffered > 0) {
        take = o->blockSz - *o->buffered;
        if (take > inSz) {
            take = inSz;
        }
        XMEMCPY(o->buf + *o->buffered, in, take);
        *o->buffered += take;
        in += take;
        inSz -= take;

        if (*o->buffered == o->blockSz && inSz > 0) {
            ret = ElsHashBlocks(o, o->buf, o->blockSz);
            if (ret != 0) {
                goto out;
            }
            *o->buffered = 0;
        }
    }

    /* whole blocks straight from the caller's buffer, less the last one */
    if (inSz > o->blockSz) {
        whole = ((inSz - 1u) / o->blockSz) * o->blockSz;
        ret = ElsHashBlocks(o, in, whole);
        if (ret != 0) {
            goto out;
        }
        in += whole;
        inSz -= whole;
    }

    /* keep whatever is left for next time */
    if (inSz > 0) {
        XMEMCPY(o->buf + *o->buffered, in, inSz);
        *o->buffered += inSz;
    }

out:
    if (ret != 0) {
        /* the length now counts bytes the engine never saw, so anything this
         * object produces from here is wrong */
        *o->devCtx = (void*)((wc_ptr_t)*o->devCtx | ELS_HASH_FAILED);
    }
    ElsUnlock();

    return ret;
}

/* Pad, absorb the tail, and take the digest from the running state. */
/* Drop the message state of an object that will produce no digest. */
static void ElsHashAbandon(ElsHashObj* o)
{
    ForceZero(o->state, o->stateSz);
    ForceZero(o->buf, o->blockSz);
    *o->buffered = 0;
    ElsHashTotalSet(o, 0);
    *o->devCtx = (void*)((wc_ptr_t)*o->devCtx | ELS_HASH_FAILED);
}

static int ElsHashFinal(ElsHashObj* o, byte* digest, word32 digestSz)
{
    ALIGN32 byte tail[2u * ELS_HASH_MAX_BLOCK];
    word32 buffered, tailSz;
    word64 bitLen;
    int ret;
    int i;

    if (*o->devCtx == NULL) {
        /* never taken over, so software holds the whole message */
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    ret = ElsLock();
    if (ret != 0) {
        ElsHashAbandon(o);
        return ret;
    }

    if ((wc_ptr_t)*o->devCtx & ELS_HASH_FAILED) {
        ElsUnlock();
        ElsHashAbandon(o);
        return WC_NO_ERR_TRACE(WC_HW_E);
    }

    /* residual, then 0x80, zeros, and a big-endian bit count of lenSz bytes. A
     * second block is needed when the remainder leaves no room for it. */
    buffered = *o->buffered;
    XMEMSET(tail, 0, sizeof(tail));
    if (buffered > 0) {
        XMEMCPY(tail, o->buf, buffered);
    }
    tail[buffered] = 0x80;
    tailSz = (buffered + 1u + o->lenSz > o->blockSz)
                 ? (2u * o->blockSz) : o->blockSz;

    bitLen = ElsHashTotal(o) * 8u;
    for (i = 0; i < 8; i++) {
        tail[tailSz - 1u - (word32)i] = (byte)(bitLen >> (8 * i));
    }

    ret = ElsHashBlocks(o, tail, tailSz);
    if (ret == 0) {
        /* after the padded tail the running state is the digest, truncated
         * for the modes whose output is shorter than the state */
        XMEMCPY(digest, o->state, digestSz);
    }

    /* Re-init as software's Final does, which the callback return skips. */
    XMEMCPY(o->state, o->iv, o->stateSz);
    *o->devCtx   = NULL;
    *o->buffered = 0;
    ElsHashTotalSet(o, 0);

    ElsUnlock();
    ForceZero(tail, sizeof(tail));

    return ret;
}

#endif /* !NO_SHA256 || WOLFSSL_SHA384 || WOLFSSL_SHA512 */

int wc_ElsPkc_CryptoCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    int ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
#if !defined(NO_SHA256) || defined(WOLFSSL_SHA384) || defined(WOLFSSL_SHA512)
    ElsHashObj hobj;
#endif

    (void)devId;
    (void)ctx;

    if (info == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }

    switch (info->algo_type) {


#if !defined(NO_SHA256) || defined(WOLFSSL_SHA384) || defined(WOLFSSL_SHA512)
        case WC_ALGO_TYPE_HASH:
            /* update passes (data, len, NULL) and final passes (NULL, 0,
             * digest), never both. */
            switch (info->hash.type) {
    #if !defined(NO_SHA256)
                case WC_HASH_TYPE_SHA256:
                    if (info->hash.sha256 == NULL) {
                        break;
                    }
                    ElsHashBindSha256(&hobj, info->hash.sha256);
                    if (info->hash.digest != NULL) {
                        ret = ElsHashFinal(&hobj, info->hash.digest,
                                           WC_SHA256_DIGEST_SIZE);
                    }
                    else if (info->hash.in != NULL) {
                        ret = ElsHashUpdate(&hobj, info->hash.in,
                                            info->hash.inSz);
                    }
                    else {
                        /* update of zero bytes with no buffer */
                        ret = 0;
                    }
                    break;
    #endif
    #ifdef WOLFSSL_SHA384
                case WC_HASH_TYPE_SHA384:
                    if (info->hash.sha384 == NULL) {
                        break;
                    }
                    ElsHashBindSha512(&hobj, info->hash.sha384,
                                      MCUXCLELS_HASH_MODE_SHA_384);
                    if (info->hash.digest != NULL) {
                        ret = ElsHashFinal(&hobj, info->hash.digest,
                                           WC_SHA384_DIGEST_SIZE);
                    }
                    else if (info->hash.in != NULL) {
                        ret = ElsHashUpdate(&hobj, info->hash.in,
                                            info->hash.inSz);
                    }
                    else {
                        ret = 0;
                    }
                    break;
    #endif
    #ifdef WOLFSSL_SHA512
                case WC_HASH_TYPE_SHA512:
                    if (info->hash.sha512 == NULL) {
                        break;
                    }
                    ElsHashBindSha512(&hobj, info->hash.sha512,
                                      MCUXCLELS_HASH_MODE_SHA_512);
                    if (info->hash.digest != NULL) {
                        ret = ElsHashFinal(&hobj, info->hash.digest,
                                           WC_SHA512_DIGEST_SIZE);
                    }
                    else if (info->hash.in != NULL) {
                        ret = ElsHashUpdate(&hobj, info->hash.in,
                                            info->hash.inSz);
                    }
                    else {
                        ret = 0;
                    }
                    break;
    #endif
                default:
                    break;
            }
            break;
#endif

        default:
            /* Anything not claimed above falls back to software. */
            break;
    }

    return ret;
}

int wc_ElsPkc_Init(void)
{
    int ret;

    /* Not safe against itself; call from one boot-time context. */
    if (!elsLockInit) {
        if (wc_InitMutex(&elsLock) != 0) {
            return WC_NO_ERR_TRACE(BAD_MUTEX_E);
        }
        elsLockInit = 1;
    }

    /* Bring the subsystem out of reset and enable it. Without this the first
     * offload would drive a disabled peripheral. Safe to repeat. */
    ret = ElsEnable();
    if (ret != 0) {
        WOLFSSL_MSG("els_pkc: enable failed");
        return ret;
    }
    elsReady = 1;

#ifdef WOLFSSL_ZEPHYR
    /* after ElsEnable(): the peripheral must be clocked and out of reset
     * before its interrupt configuration will stick */
    ret = ElsIrqInit();
    if (ret != 0) {
        WOLFSSL_MSG("els_pkc: interrupt setup failed, falling back to polling");
        /* not fatal - ElsWait() polls when the IRQ is not armed */
    }
#endif

    /* Always register: wolfCrypt_Cleanup() clears the device table. ALREADY_E
     * is ours only when this port registered and has not been cleaned up. */
    ret = wc_CryptoCb_RegisterDevice(WOLFSSL_ELS_PKC_DEVID,
                                     wc_ElsPkc_CryptoCb, NULL);
    if (ret == WC_NO_ERR_TRACE(ALREADY_E) && elsRegistered) {
        ret = 0;
    }
    if (ret != 0) {
        WOLFSSL_MSG("els_pkc: RegisterDevice failed");
        /* ElsLock() keys off this: a failed init must leave the port shut, or
         * the direct entry points would drive a device that never came up. */
        elsReady = 0;
        return ret;
    }

    elsRegistered = 1;

    return 0;
}

int wc_ElsPkc_Cleanup(void)
{
    /* Unregister, then take the lock so an in-flight operation finishes
     * first. */
    if (elsRegistered) {
        wc_CryptoCb_UnRegisterDevice(WOLFSSL_ELS_PKC_DEVID);
        elsRegistered = 0;
    }

    if (elsLockInit) {
        /* Close the gate under the lock. The mutex outlives cleanup, since a
         * blocked caller still has to unlock it. */
        if (wc_LockMutex(&elsLock) == 0) {
            elsReady = 0;
            ElsIrqDisarm();
            (void)wc_UnLockMutex(&elsLock);
        }
        else {
            elsReady = 0;
            ElsIrqDisarm();
        }
    }

    return 0;
}

#endif /* WOLFSSL_ELS_PKC */
