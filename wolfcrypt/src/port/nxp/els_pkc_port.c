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

/* The AES modes ELS drives with its block-cipher command. GCM and CMAC are
 * separate commands, so they are not in here. */
#if !defined(NO_AES) && (defined(HAVE_AES_CBC) || defined(WOLFSSL_AES_COUNTER) || \
                         defined(HAVE_AES_ECB) || defined(WOLFSSL_AES_DIRECT))
    #define ELS_HAVE_AES_BLOCK_CIPHER
#endif

/* Each of these checks a slot reference first, because a permission
 * violation resets the SoC. */
#if defined(ELS_HAVE_AES_BLOCK_CIPHER) || \
    (!defined(NO_AES) && (defined(HAVE_AESGCM) || defined(WOLFSSL_CMAC)))
    #define ELS_HAVE_SLOT_KEYS
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

/* Public bound, so a caller can range-check a slot without the NXP headers. */
wc_static_assert((WC_ELSPKC_MAX_SLOT + 1) == MCUXCLELS_KEY_SLOTS);

#define ELS_REF_FLAGS_KNOWN (WC_ELSPKC_REF_FLAG_BIND | \
                             WC_ELSPKC_REF_FLAG_EXPORTABLE | \
                             WC_ELSPKC_REF_FLAG_PERSISTENT)

int wc_ElsPkc_MakeKeyRef(const wc_ElsPkc_KeyRef* ref, byte* out, word32* outSz)
{
    if (ref == NULL || outSz == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    if (out == NULL) {
        *outSz = WC_ELSPKC_KEYREF_SZ;
        return WC_NO_ERR_TRACE(LENGTH_ONLY_E);
    }
    if (*outSz < WC_ELSPKC_KEYREF_SZ) {
        return WC_NO_ERR_TRACE(BUFFER_E);
    }
    if (ref->keyClass == WC_ELSPKC_KEY_NONE ||
        ref->keyClass > WC_ELSPKC_KEY_MAX ||
        ref->slot > WC_ELSPKC_MAX_SLOT ||
        (ref->flags & ~ELS_REF_FLAGS_KNOWN) != 0) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }

    XMEMSET(out, 0, WC_ELSPKC_KEYREF_SZ);
    out[0] = WC_ELSPKC_KEYREF_MAGIC_0;
    out[1] = WC_ELSPKC_KEYREF_MAGIC_1;
    out[2] = WC_ELSPKC_KEYREF_VER;
    out[3] = ref->keyClass;
    out[4] = ref->slot;
    out[5] = ref->flags;
    /* out[6..7] stay zero - reserved */
    if (ref->flags & WC_ELSPKC_REF_FLAG_BIND) {
        XMEMCPY(out + 8, ref->bind, WC_ELSPKC_BIND_SZ);
    }

    *outSz = WC_ELSPKC_KEYREF_SZ;

    return 0;
}

int wc_ElsPkc_ParseKeyRef(const byte* in, word32 inSz, wc_ElsPkc_KeyRef* ref)
{
    int i;

    if (in == NULL || ref == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    /* wolfPSA stores the reference followed by the public point, so a longer
     * blob is expected - only the prefix belongs to us. */
    if (inSz < WC_ELSPKC_KEYREF_SZ) {
        return WC_NO_ERR_TRACE(BUFFER_E);
    }
    if (in[0] != WC_ELSPKC_KEYREF_MAGIC_0 ||
        in[1] != WC_ELSPKC_KEYREF_MAGIC_1) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }
    if (in[2] != WC_ELSPKC_KEYREF_VER) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }
    if (in[3] == WC_ELSPKC_KEY_NONE || in[3] > WC_ELSPKC_KEY_MAX) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }
    if (in[4] > WC_ELSPKC_MAX_SLOT) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }
    if ((in[5] & ~ELS_REF_FLAGS_KNOWN) != 0 || in[6] != 0 || in[7] != 0) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }

    if (!(in[5] & WC_ELSPKC_REF_FLAG_BIND)) {
        for (i = 0; i < WC_ELSPKC_BIND_SZ; i++) {
            if (in[8 + i] != 0) {
                return WC_NO_ERR_TRACE(BAD_STATE_E);
            }
        }
    }

    XMEMSET(ref, 0, sizeof(*ref));
    ref->keyClass = in[3];
    ref->slot     = in[4];
    ref->flags    = in[5];
    if (ref->flags & WC_ELSPKC_REF_FLAG_BIND) {
        XMEMCPY(ref->bind, in + 8, WC_ELSPKC_BIND_SZ);
    }

    return 0;
}

/* Slot validation, reached from every path that can name a slot. */
#ifdef ELS_HAVE_SLOT_KEYS

/* The ELS permission bit each class stands for. */
static word32 ElsClassUsageBit(byte keyClass)
{
    switch (keyClass) {
        case WC_ELSPKC_KEY_ECC_SIGN: return MCUXCLELS_KEYPROPERTY_VALUE_ECSGN;
        case WC_ELSPKC_KEY_ECC_DH:   return MCUXCLELS_KEYPROPERTY_VALUE_ECDH;
        case WC_ELSPKC_KEY_ECC_SEED: return MCUXCLELS_KEYPROPERTY_VALUE_KGSRC;
        case WC_ELSPKC_KEY_AES:      return MCUXCLELS_KEYPROPERTY_VALUE_AES;
        case WC_ELSPKC_KEY_HMAC:     return MCUXCLELS_KEYPROPERTY_VALUE_HMAC;
        case WC_ELSPKC_KEY_CMAC:     return MCUXCLELS_KEYPROPERTY_VALUE_CMAC;
        case WC_ELSPKC_KEY_KWK:      return MCUXCLELS_KEYPROPERTY_VALUE_KWK;
        case WC_ELSPKC_KEY_CKDF:     return MCUXCLELS_KEYPROPERTY_VALUE_CKDF;
        case WC_ELSPKC_KEY_HKDF:     return MCUXCLELS_KEYPROPERTY_VALUE_HKDF;
        default:                     return 0;
    }
}

/* Check the slot is occupied and carries the usage bit; a permission
 * violation resets the SoC. Caller holds the lock. */
static int ElsCheckSlot(const wc_ElsPkc_KeyRef* ref, byte expectClass)
{
    mcuxClEls_KeyProp_t prop;
    word32 need;

    if (ref->keyClass != expectClass) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }
    need = ElsClassUsageBit(ref->keyClass);
    if (need == 0) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t,
        mcuxClEls_GetKeyProperties((mcuxClEls_KeyIndex_t)ref->slot, &prop));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_GetKeyProperties) != t) ||
        (MCUXCLELS_STATUS_OK != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* An empty slot reads as all-zero properties, which fails the usage test
     * below anyway - but check it explicitly so the error says what is wrong. */
    if ((prop.word.value & MCUXCLELS_KEYPROPERTY_VALUE_ACTIVE) == 0) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }
    if ((prop.word.value & need) == 0) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }

    return 0;
}

#endif /* ELS_HAVE_SLOT_KEYS */

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

/* ELS knows only 128- and 256-bit keys and only whole blocks. AES-192 and any
 * trailing partial block are declined so software handles them. */

#ifndef NO_AES

int wc_ElsPkc_AesUseSlot(Aes* aes, const wc_ElsPkc_KeyRef* ref,
                         void* heap, int devId)
{
    byte   blob[WC_ELSPKC_KEYREF_SZ];
    word32 blobSz = sizeof(blob);
    int    ret;

    if (aes == NULL || ref == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    /* A CMAC key gets its own reference on the Cmac object. */
    if (ref->keyClass != WC_ELSPKC_KEY_AES) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }

    ret = wc_ElsPkc_MakeKeyRef(ref, blob, &blobSz);
    if (ret == 0) {
        /* keyInstalled stays clear: the key is in the slot. */
        ret = wc_AesInit_Id(aes, blob, (int)blobSz, heap, devId);
    }

    ForceZero(blob, sizeof(blob));

    return ret;
}

#if defined(ELS_HAVE_AES_BLOCK_CIPHER) || defined(HAVE_AESGCM)
static int ElsAesKeyOk(const Aes* aes)
{
    return (aes->keylen == 16 || aes->keylen == 32);
}

/* CRYPTOCB_UNAVAILABLE means no reference. A parse failure is an error only
 * when no key is held in memory to use instead. */
static int ElsAesRef(const Aes* aes, wc_ElsPkc_KeyRef* ref)
{
    int ret;

    if (aes == NULL || aes->idLen <= 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    ret = wc_ElsPkc_ParseKeyRef(aes->id, (word32)aes->idLen, ref);
    if (ret != 0 && aes->keylen != 0) {
        ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    return ret;
}
#endif

/* Caller holds the lock. keyIdx is read only for an internal-key opt. */
#ifdef ELS_HAVE_AES_BLOCK_CIPHER

static int ElsCipherRun(mcuxClEls_CipherOption_t opt,
                        mcuxClEls_KeyIndex_t keyIdx, Aes* aes,
                        const byte* in, word32 sz, byte* out, int useIv)
{
    int extKey = (opt.bits.extkey == MCUXCLELS_CIPHER_EXTERNAL_KEY);

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEls_Cipher_Async(
        opt, keyIdx,
        extKey ? (const uint8_t*)aes->devKey : NULL,
        extKey ? (size_t)aes->keylen : 0u,
        in, sz, useIv ? (uint8_t*)aes->reg : NULL, out));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cipher_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return ElsWait();
}

static int ElsAesCipher(Aes* aes, byte* out, const byte* in, word32 sz,
                        int mode, int encrypt, int useIv)
{
    mcuxClEls_CipherOption_t opt;
    wc_ElsPkc_KeyRef ref;
    byte lastCipher[MCUXCLELS_CIPHER_BLOCK_SIZE_AES];
    int slotted = 0;
    int issued = 0;
    int ret;

    if (aes == NULL || out == NULL || in == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }

    XMEMSET(&ref, 0, sizeof(ref));
    ret = ElsAesRef(aes, &ref);
    if (ret == 0) {
        slotted = 1;
    }
    else if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
        return ret;
    }

    /* Whole blocks only. keylen matters only for a key held in memory: a slot
     * key carries its size in its property word and aes->keylen is 0. */
    if (sz == 0) {
        /* Software would fail a slot key with MISSING_KEY. */
        return slotted ? 0 : WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (!slotted && !ElsAesKeyOk(aes)) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if ((sz % MCUXCLELS_CIPHER_BLOCK_SIZE_AES) != 0) {
        /* A slot key has no software copy to finish the tail with. */
        return slotted ? WC_NO_ERR_TRACE(BAD_LENGTH_E)
                       : WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
#ifdef WOLFSSL_AES_COUNTER
    /* aes->reg is already past the unconsumed keystream left in aes->tmp. */
    if (mode == MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_CTR && aes->left != 0) {
        return slotted ? WC_NO_ERR_TRACE(BAD_LENGTH_E)
                       : WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
#endif

    opt.word.value = 0u;
    opt.bits.cphmde = (uint32_t)mode;
    opt.bits.dcrpt  = encrypt ? MCUXCLELS_CIPHER_ENCRYPT
                              : MCUXCLELS_CIPHER_DECRYPT;
    opt.bits.extkey = slotted ? MCUXCLELS_CIPHER_INTERNAL_KEY
                              : MCUXCLELS_CIPHER_EXTERNAL_KEY;
    if (useIv && mode == MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_CTR) {
        /* cphsoe writes the counter back. Not for CBC, where it made ELS treat
         * pIV as a state blob. */
        opt.bits.cphsie = MCUXCLELS_CIPHER_STATE_IN_ENABLE;
        opt.bits.cphsoe = MCUXCLELS_CIPHER_STATE_OUT_ENABLE;
    }

    /* CBC decrypt chains on the last ciphertext block, which is the input -
     * save it now because an in-place call is about to overwrite it. */
    if (mode == MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_CBC && !encrypt) {
        XMEMCPY(lastCipher, in + sz - MCUXCLELS_CIPHER_BLOCK_SIZE_AES,
                MCUXCLELS_CIPHER_BLOCK_SIZE_AES);
    }

    ret = ElsLock();
    if (ret == 0) {
        /* Prove the slot holds an active AES key: the class check alone would
         * pass a hand-built reference against, say, a wrapping key. */
        if (slotted) {
            ret = ElsCheckSlot(&ref, WC_ELSPKC_KEY_AES);
        }
        if (ret == 0) {
            issued = 1;
            ret = ElsCipherRun(opt, (mcuxClEls_KeyIndex_t)ref.slot, aes,
                               in, sz, out, useIv);
        }
        ElsUnlock();
    }

    /* The engine may have written plaintext before it failed. */
    if (ret != 0 && issued &&
        (!encrypt || mode == MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_CTR)) {
        ForceZero(out, sz);
    }

    if (ret == 0) {
        /* This part does not write pIV back for CBC; the next IV is the last
         * ciphertext block. */
        if (mode == MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_CBC) {
            if (encrypt) {
                XMEMCPY(aes->reg, out + sz - MCUXCLELS_CIPHER_BLOCK_SIZE_AES,
                        MCUXCLELS_CIPHER_BLOCK_SIZE_AES);
            }
            else {
                XMEMCPY(aes->reg, lastCipher,
                        MCUXCLELS_CIPHER_BLOCK_SIZE_AES);
            }
        }
    }

    ForceZero(lastCipher, sizeof(lastCipher));

    return ret;
}

#endif /* ELS_HAVE_AES_BLOCK_CIPHER */

/* Every stage takes whole blocks; the true AAD and data lengths reach the
 * hardware only in Finalize. */

#ifdef HAVE_AESGCM

#define ELS_GCM_BLOCK MCUXCLELS_AEAD_IV_BLOCK_SIZE

/* An internal key is named by keyIdx and the memory pair is then ignored. */
static const uint8_t* ElsGcmKeyPtr(mcuxClEls_AeadOption_t opt, const Aes* aes)
{
    return (opt.bits.extkey == MCUXCLELS_AEAD_EXTERN_KEY)
           ? (const uint8_t*)aes->devKey : NULL;
}

static size_t ElsGcmKeyLen(mcuxClEls_AeadOption_t opt, const Aes* aes)
{
    return (opt.bits.extkey == MCUXCLELS_AEAD_EXTERN_KEY)
           ? (size_t)aes->keylen : 0u;
}

/* Each stage below is its own function so the flow-protection macro pair stays
 * within one scope, matching the rest of this port. Caller holds the lock. */

static int ElsGcmInit(mcuxClEls_AeadOption_t opt, mcuxClEls_KeyIndex_t keyIdx,
                      const Aes* aes, const byte* j0, byte* aeadCtx)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEls_Aead_Init_Async(
        opt, keyIdx, ElsGcmKeyPtr(opt, aes), ElsGcmKeyLen(opt, aes),
        j0, (size_t)ELS_GCM_BLOCK, aeadCtx));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Aead_Init_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return ElsWait();
}

static int ElsGcmAadChunk(mcuxClEls_AeadOption_t opt,
                          mcuxClEls_KeyIndex_t keyIdx, const Aes* aes,
                          const byte* aad, word32 len, byte* aeadCtx)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEls_Aead_UpdateAad_Async(
        opt, keyIdx, ElsGcmKeyPtr(opt, aes), ElsGcmKeyLen(opt, aes),
        aad, (size_t)len, aeadCtx));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Aead_UpdateAad_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return ElsWait();
}

static int ElsGcmDataChunk(mcuxClEls_AeadOption_t opt,
                           mcuxClEls_KeyIndex_t keyIdx, const Aes* aes,
                           const byte* in, word32 len, byte* out,
                           byte* aeadCtx)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEls_Aead_UpdateData_Async(
        opt, keyIdx, ElsGcmKeyPtr(opt, aes), ElsGcmKeyLen(opt, aes),
        in, (size_t)len, out, aeadCtx));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Aead_UpdateData_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return ElsWait();
}

static int ElsGcmFinal(mcuxClEls_AeadOption_t opt, mcuxClEls_KeyIndex_t keyIdx,
                       const Aes* aes, word32 aadSz, word32 dataSz,
                       byte* tag, byte* aeadCtx)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEls_Aead_Finalize_Async(
        opt, keyIdx, ElsGcmKeyPtr(opt, aes), ElsGcmKeyLen(opt, aes),
        (size_t)aadSz, (size_t)dataSz, tag, aeadCtx));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Aead_Finalize_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return ElsWait();
}

/* AAD is fed as whole blocks; Finalize's aadLength says how much of the
 * zero-padded last block was real. */
static int ElsGcmAad(mcuxClEls_AeadOption_t opt, mcuxClEls_KeyIndex_t keyIdx,
                     const Aes* aes, const byte* aad, word32 aadSz,
                     byte* aeadCtx)
{
    ALIGN32 byte block[ELS_GCM_BLOCK];
    word32 full = aadSz & ~(word32)(ELS_GCM_BLOCK - 1u);
    word32 tail = aadSz - full;
    int ret = 0;

    if (full > 0u) {
        ret = ElsGcmAadChunk(opt, keyIdx, aes, aad, full, aeadCtx);
    }

    if (ret == 0 && tail > 0u) {
        XMEMSET(block, 0, sizeof(block));
        XMEMCPY(block, aad + full, tail);
        ret = ElsGcmAadChunk(opt, keyIdx, aes, block, ELS_GCM_BLOCK, aeadCtx);
        ForceZero(block, sizeof(block));
    }

    return ret;
}

static int ElsAesGcm(Aes* aes, byte* out, const byte* in, word32 sz,
                     const byte* iv, word32 ivSz,
                     byte* authTag, word32 authTagSz,
                     const byte* authIn, word32 authInSz, int encrypt)
{
    mcuxClEls_AeadOption_t opt;
    mcuxClEls_AeadOption_t stageOpt;
    wc_ElsPkc_KeyRef ref;
    ALIGN32 byte aeadCtx[MCUXCLELS_AEAD_CONTEXT_SIZE];
    ALIGN32 byte j0[ELS_GCM_BLOCK];
    ALIGN32 byte inBlock[ELS_GCM_BLOCK];
    ALIGN32 byte outBlock[ELS_GCM_BLOCK];
    byte   tag[MCUXCLELS_AEAD_TAG_SIZE];
    word32 full, tail;
    int    slotted = 0;
    int ret;

    if (aes == NULL || iv == NULL || authTag == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    if ((sz > 0 && (in == NULL || out == NULL)) ||
        (authInSz > 0 && authIn == NULL)) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }

    XMEMSET(&ref, 0, sizeof(ref));
    ret = ElsAesRef(aes, &ref);
    if (ret == 0) {
        slotted = 1;
    }
    else if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
        return ret;
    }
    /* Only a 12-byte IV maps onto Aead_Init's J0. A short tag is a prefix of
     * the full one; AES-192 has no ELS key size. */
    if (!slotted && !ElsAesKeyOk(aes)) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (ivSz != GCM_NONCE_MID_SZ || authTagSz == 0 ||
        authTagSz > MCUXCLELS_AEAD_TAG_SIZE) {
        return slotted ? WC_NO_ERR_TRACE(BAD_FUNC_ARG)
                       : WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    /* For a 96-bit IV, J0 is IV || 0x00000001 (SP 800-38D, 7.1). */
    XMEMSET(j0, 0, sizeof(j0));
    XMEMCPY(j0, iv, ivSz);
    j0[ELS_GCM_BLOCK - 1] = 0x01;

    opt.word.value   = 0u;
    opt.bits.dcrpt   = encrypt ? MCUXCLELS_AEAD_ENCRYPT
                               : MCUXCLELS_AEAD_DECRYPT;
    opt.bits.extkey  = slotted ? MCUXCLELS_AEAD_INTERN_KEY
                               : MCUXCLELS_AEAD_EXTERN_KEY;
    opt.bits.acpsie  = MCUXCLELS_AEAD_STATE_IN_ENABLE;
    opt.bits.lastinit = MCUXCLELS_AEAD_LASTINIT_FALSE;

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    /* Prove the slot before the four-stage sequence starts, so a bad reference
     * fails before any context is built. */
    if (slotted) {
        ret = ElsCheckSlot(&ref, WC_ELSPKC_KEY_AES);
        if (ret != 0) {
            ElsUnlock();
            return ret;
        }
    }

    /* Init builds the context rather than continuing one, so it must not be
     * told to read a state in - aeadCtx holds nothing yet. */
    stageOpt = opt;
    stageOpt.bits.acpsie = MCUXCLELS_AEAD_STATE_IN_DISABLE;
    ret = ElsGcmInit(stageOpt, (mcuxClEls_KeyIndex_t)ref.slot, aes, j0,
                     aeadCtx);

    if (ret == 0 && authInSz > 0) {
        ret = ElsGcmAad(opt, (mcuxClEls_KeyIndex_t)ref.slot, aes, authIn,
                        authInSz, aeadCtx);
    }

    if (ret == 0 && sz > 0) {
        full = sz & ~(word32)(ELS_GCM_BLOCK - 1u);
        tail = sz - full;

        if (full > 0) {
            ret = ElsGcmDataChunk(opt, (mcuxClEls_KeyIndex_t)ref.slot, aes,
                                  in, full, out, aeadCtx);
        }
        if (ret == 0 && tail > 0) {
            /* msgendw carries the real byte count of the final block while
             * the block itself still arrives zero-padded. */
            stageOpt = opt;
            stageOpt.bits.msgendw = (uint32_t)tail;

            XMEMSET(inBlock, 0, sizeof(inBlock));
            XMEMCPY(inBlock, in + full, tail);
            ret = ElsGcmDataChunk(stageOpt, (mcuxClEls_KeyIndex_t)ref.slot,
                                  aes, inBlock, ELS_GCM_BLOCK, outBlock,
                                  aeadCtx);
            if (ret == 0) {
                XMEMCPY(out + full, outBlock, tail);
            }
        }
    }

    if (ret == 0) {
        ret = ElsGcmFinal(opt, (mcuxClEls_KeyIndex_t)ref.slot, aes, authInSz,
                          sz, tag, aeadCtx);
    }

    ElsUnlock();

    if (ret == 0) {
        if (encrypt) {
            XMEMCPY(authTag, tag, authTagSz);
        }
        else if (wc_ConstantCompare(tag, authTag, (int)authTagSz) != 0) {
            ret = WC_NO_ERR_TRACE(AES_GCM_AUTH_E);
        }
    }
    /* No unverified plaintext is left behind, whichever stage failed. */
    if (ret != 0 && !encrypt && sz > 0) {
        ForceZero(out, sz);
    }

    ForceZero(tag, sizeof(tag));
    ForceZero(j0, sizeof(j0));
    ForceZero(inBlock, sizeof(inBlock));
    ForceZero(outBlock, sizeof(outBlock));
    ForceZero(aeadCtx, sizeof(aeadCtx));

    return ret;
}

#endif /* HAVE_AESGCM */

#endif /* !NO_AES */

/* Serving WC_ALGO_TYPE_SEED as well as _RNG means wolfCrypt's own Hash-DRBG is
 * seeded from the hardware, not just the direct generate path. */

#ifndef WC_NO_RNG

/* Issue one DRBG request. Caller holds the lock, and len must already satisfy
 * the engine's contract. */
static int ElsRandomRun(byte* out, word32 len)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t,
        mcuxClEls_Rng_DrbgRequest_Async(out, (size_t)len));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Rng_DrbgRequest_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return ElsWait();
}

static int ElsRandom(byte* out, word32 sz)
{
    /* The DRBG takes whole words of at least four bytes, so the tail comes
     * from a scratch word. */
    ALIGN32 byte tail[MCUXCLELS_RNG_DRBG_TEST_EXTRACT_OUTPUT_MIN_SIZE];
    word32 whole;
    word32 rest;
    int ret;

    if (out == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    if (sz == 0) {
        return 0;
    }

    whole = sz & ~(word32)(sizeof(tail) - 1u);
    rest  = sz - whole;

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    /* One request is capped; the caller's size is not. */
    while (ret == 0 && whole > 0) {
        word32 chunk = whole;
        if (chunk > MCUXCLELS_RNG_DRBG_TEST_EXTRACT_OUTPUT_MAX_SIZE) {
            chunk = MCUXCLELS_RNG_DRBG_TEST_EXTRACT_OUTPUT_MAX_SIZE;
        }
        ret = ElsRandomRun(out, chunk);
        out   += chunk;
        whole -= chunk;
    }
    if (ret == 0 && rest > 0) {
        ret = ElsRandomRun(tail, (word32)sizeof(tail));
        if (ret == 0) {
            XMEMCPY(out, tail, rest);
        }
    }

    ElsUnlock();

    ForceZero(tail, sizeof(tail));

    return ret;
}

int wc_ElsPkc_GenerateSeed(byte* output, word32 sz)
{
    return ElsRandom(output, sz);
}

#endif /* !WC_NO_RNG */

/* pMac is [in, out] and carries the intermediate state, so it lives in the
 * caller's Cmac and the lock is held per call. */

#if defined(WOLFSSL_CMAC) && !defined(NO_AES)

#define ELS_CMAC_BLOCK MCUXCLELS_CIPHER_BLOCK_SIZE_AES
#define ELS_CMAC_STATE MCUXCLELS_CMAC_OUT_SIZE

/* Offload state lives in the object: digest[] the state, buffer[] the
 * residual block, k1||k2 a plaintext key. */
wc_static_assert(ELS_CMAC_STATE == WC_AES_BLOCK_SIZE);
wc_static_assert(ELS_CMAC_BLOCK == WC_AES_BLOCK_SIZE);

/* Parked in devCtx, tagged like the hash's. The slot index needs a byte; the
 * rest are flags. */
#define ELS_CMAC_OWNED     ((wc_ptr_t)0x01)
#define ELS_CMAC_STARTED   ((wc_ptr_t)0x02)
#define ELS_CMAC_SLOTTED   ((wc_ptr_t)0x04)
#define ELS_CMAC_KEY256    ((wc_ptr_t)0x08)
#define ELS_CMAC_FAILED    ((wc_ptr_t)0x10)  /* a block never reached it */
#define ELS_CMAC_SLOT_SHIFT 8
#define ELS_CMAC_SLOT(st)  ((byte)(((st) >> ELS_CMAC_SLOT_SHIFT) & 0xFFu))

/* Feed one chunk. Caller holds the lock. */
static int ElsCmacChunk(Cmac* cmac, const byte* in, word32 len, int final)
{
    mcuxClEls_CmacOption_t opt;
    wc_ElsPkc_KeyRef ref;
    wc_ptr_t st = (wc_ptr_t)cmac->devCtx;
    byte key[2 * WC_AES_BLOCK_SIZE];
    size_t keySz = 0;
    int ret;

    /* The slot may have been deleted or reprovisioned since init. */
    if (st & ELS_CMAC_SLOTTED) {
        XMEMSET(&ref, 0, sizeof(ref));
        ref.keyClass = WC_ELSPKC_KEY_CMAC;
        ref.slot     = ELS_CMAC_SLOT(st);
        ret = ElsCheckSlot(&ref, WC_ELSPKC_KEY_CMAC);
        if (ret != 0) {
            return ret;
        }
    }

    opt.word.value = 0u;
    opt.bits.extkey = (st & ELS_CMAC_SLOTTED)
                          ? MCUXCLELS_CMAC_EXTERNAL_KEY_DISABLE
                          : MCUXCLELS_CMAC_EXTERNAL_KEY_ENABLE;
    opt.bits.initialize = (st & ELS_CMAC_STARTED)
                              ? MCUXCLELS_CMAC_INITIALIZE_DISABLE
                              : MCUXCLELS_CMAC_INITIALIZE_ENABLE;
    opt.bits.finalize = final ? MCUXCLELS_CMAC_FINALIZE_ENABLE
                              : MCUXCLELS_CMAC_FINALIZE_DISABLE;

    if (!(st & ELS_CMAC_SLOTTED)) {
        /* k1 and k2 are separate members, so the engine's contiguous key is
         * assembled here rather than assumed of the struct layout. */
        XMEMCPY(key, cmac->k1, WC_AES_BLOCK_SIZE);
        if (st & ELS_CMAC_KEY256) {
            XMEMCPY(key + WC_AES_BLOCK_SIZE, cmac->k2, WC_AES_BLOCK_SIZE);
            keySz = sizeof(key);
        }
        else {
            keySz = WC_AES_BLOCK_SIZE;
        }
    }

    /* As in the cipher path, the unused half of the key pair is passed as
     * nothing rather than as an empty key[]. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEls_Cmac_Async(
        opt, (mcuxClEls_KeyIndex_t)ELS_CMAC_SLOT(st),
        (st & ELS_CMAC_SLOTTED) ? NULL : key, keySz,
        in, (size_t)len, cmac->digest));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cmac_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        ForceZero(key, sizeof(key));
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    cmac->devCtx = (void*)(st | ELS_CMAC_STARTED);

    ret = ElsWait();
    ForceZero(key, sizeof(key));

    return ret;
}

/* Read the slot reference a Cmac carries, if it carries one at all. */
static int ElsCmacRef(const Cmac* cmac, wc_ElsPkc_KeyRef* ref)
{
    if (cmac == NULL || cmac->idLen <= 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    return wc_ElsPkc_ParseKeyRef(cmac->id, (word32)cmac->idLen, ref);
}

/* key == NULL means the key is in the store and the Cmac names the slot. */
static int ElsCmacInit(Cmac* cmac, const byte* key, word32 keySz)
{
    wc_ElsPkc_KeyRef ref;
    wc_ptr_t st = ELS_CMAC_OWNED;
    int ret;

    if (cmac == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }

    XMEMSET(&ref, 0, sizeof(ref));
    if (key == NULL) {
        ret = ElsCmacRef(cmac, &ref);
        if (ret != 0) {
            return ret;
        }
        st |= ELS_CMAC_SLOTTED |
              ((wc_ptr_t)ref.slot << ELS_CMAC_SLOT_SHIFT);
    }
    else if (keySz != WC_AES_BLOCK_SIZE && keySz != 2 * WC_AES_BLOCK_SIZE) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    else if (keySz == 2 * WC_AES_BLOCK_SIZE) {
        st |= ELS_CMAC_KEY256;
    }

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    /* Validate the slot before claiming the object, so a bad reference leaves
     * the Cmac to software untouched. */
    if (st & ELS_CMAC_SLOTTED) {
        ret = ElsCheckSlot(&ref, WC_ELSPKC_KEY_CMAC);
        if (ret != 0) {
            ElsUnlock();
            return ret;
        }
    }
    else {
        XMEMCPY(cmac->k1, key, WC_AES_BLOCK_SIZE);
        if (keySz == 2 * WC_AES_BLOCK_SIZE) {
            XMEMCPY(cmac->k2, key + WC_AES_BLOCK_SIZE, WC_AES_BLOCK_SIZE);
        }
    }

    cmac->bufferSz = 0;
    cmac->devCtx   = (void*)st;
    /* _InitCmac_common() returns before wc_AesInit() once the callback takes
     * the init, so wc_CmacFree() would otherwise free an all-zero Aes. */
    cmac->aes.devId = INVALID_DEVID;

    ElsUnlock();

    return 0;
}

int wc_ElsPkc_CmacUseSlot(Cmac* cmac, const wc_ElsPkc_KeyRef* ref,
                          void* heap, int devId)
{
    byte   blob[WC_ELSPKC_KEYREF_SZ];
    word32 blobSz = sizeof(blob);
    int    ret;

    if (cmac == NULL || ref == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    /* ucmac is its own permission; a uaes slot is not automatically usable
     * here, and a reference for one is not a reference for the other. */
    if (ref->keyClass != WC_ELSPKC_KEY_CMAC) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }

    ret = wc_ElsPkc_MakeKeyRef(ref, blob, &blobSz);
    if (ret == 0) {
        /* No key and no size: both live in the slot, and passing NULL is what
         * tells the callback this is a key store init. */
        ret = wc_InitCmac_Id(cmac, NULL, 0, WC_CMAC_AES, NULL,
                             blob, (int)blobSz, heap, devId);
    }

    ForceZero(blob, sizeof(blob));

    return ret;
}

static int ElsCmacUpdate(Cmac* cmac, const byte* in, word32 inSz)
{
    word32 take, whole;
    int ret;

    if (cmac == NULL || cmac->devCtx == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    /* A zero-length update is legal and absorbs nothing; in may be NULL. */
    if (inSz == 0) {
        return 0;
    }
    if (in == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }

    ret = ElsLock();
    if (ret != 0) {
        ForceZero(cmac->k1, WC_AES_BLOCK_SIZE);
        ForceZero(cmac->k2, WC_AES_BLOCK_SIZE);
        cmac->devCtx = (void*)((wc_ptr_t)cmac->devCtx | ELS_CMAC_FAILED);
        return ret;
    }

    if ((wc_ptr_t)cmac->devCtx & ELS_CMAC_FAILED) {
        ElsUnlock();
        return WC_NO_ERR_TRACE(WC_HW_E);
    }

    /* The final chunk uses a different subkey, so hold the last block back. */
    if (cmac->bufferSz > 0) {
        take = ELS_CMAC_BLOCK - cmac->bufferSz;
        if (take > inSz) {
            take = inSz;
        }
        XMEMCPY(cmac->buffer + cmac->bufferSz, in, take);
        cmac->bufferSz += take;
        in += take;
        inSz -= take;

        if (cmac->bufferSz == ELS_CMAC_BLOCK && inSz > 0) {
            ret = ElsCmacChunk(cmac, cmac->buffer, ELS_CMAC_BLOCK, 0);
            if (ret != 0) {
                goto out;
            }
            cmac->bufferSz = 0;
        }
    }

    if (inSz > ELS_CMAC_BLOCK) {
        whole = ((inSz - 1u) / ELS_CMAC_BLOCK) * ELS_CMAC_BLOCK;
        ret = ElsCmacChunk(cmac, in, whole, 0);
        if (ret != 0) {
            goto out;
        }
        in += whole;
        inSz -= whole;
    }

    if (inSz > 0) {
        XMEMCPY(cmac->buffer + cmac->bufferSz, in, inSz);
        cmac->bufferSz += inSz;
    }

out:
    if (ret != 0) {
        /* buffer[] and digest[] now describe a message the engine only partly
         * absorbed, so nothing this object produces afterwards is a MAC */
        cmac->devCtx = (void*)((wc_ptr_t)cmac->devCtx | ELS_CMAC_FAILED);
        ForceZero(cmac->k1, WC_AES_BLOCK_SIZE);
        ForceZero(cmac->k2, WC_AES_BLOCK_SIZE);
    }
    ElsUnlock();

    return ret;
}

static int ElsCmacFinal(Cmac* cmac, byte* out, word32* outSz)
{
    word32 buffered;
    int ret;

    if (cmac == NULL || cmac->devCtx == NULL || out == NULL || outSz == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    /* Any length in [WC_CMAC_TAG_MIN_SZ, WC_CMAC_TAG_MAX_SZ]; the message is
     * absorbed, so no software state remains. */
    if (*outSz < WC_CMAC_TAG_MIN_SZ || *outSz > ELS_CMAC_STATE) {
        return WC_NO_ERR_TRACE(BUFFER_E);
    }

    ret = ElsLock();
    if (ret != 0) {
        /* The key is gone, so a retried Final must not compute a MAC. */
        ForceZero(cmac->k1, WC_AES_BLOCK_SIZE);
        ForceZero(cmac->k2, WC_AES_BLOCK_SIZE);
        cmac->devCtx = (void*)((wc_ptr_t)cmac->devCtx | ELS_CMAC_FAILED);
        return ret;
    }

    if ((wc_ptr_t)cmac->devCtx & ELS_CMAC_FAILED) {
        ElsUnlock();
        return WC_NO_ERR_TRACE(WC_HW_E);
    }

    /* ELS takes the length before padding but the block padded per
     * SP 800-38B. */
    buffered = cmac->bufferSz;
    if (buffered < ELS_CMAC_BLOCK) {
        cmac->buffer[buffered] = 0x80;
        if (buffered + 1u < ELS_CMAC_BLOCK) {
            XMEMSET(cmac->buffer + buffered + 1u, 0,
                    ELS_CMAC_BLOCK - buffered - 1u);
        }
    }

    ret = ElsCmacChunk(cmac, cmac->buffer, buffered, 1);
    if (ret == 0) {
        XMEMCPY(out, cmac->digest, *outSz);
    }

    /* The key is not needed again, and wc_CmacFinalNoFree() leaves the object
     * to the caller. */
    ForceZero(cmac->k1, WC_AES_BLOCK_SIZE);
    ForceZero(cmac->k2, WC_AES_BLOCK_SIZE);
    cmac->bufferSz = 0;
    cmac->devCtx   = NULL;

    ElsUnlock();

    return ret;
}

#endif /* WOLFSSL_CMAC && !NO_AES */

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
#if defined(WOLFSSL_CMAC) && !defined(NO_AES)
        case WC_ALGO_TYPE_CMAC:
            if (info->cmac.type != WC_CMAC_AES || info->cmac.cmac == NULL) {
                break;
            }
            /* A key store init carries no key and looks like a zero-length
             * update; devCtx and the software key schedule tell them apart. */
            if (info->cmac.in == NULL && info->cmac.out == NULL &&
                info->cmac.cmac->bufferSz == 0 &&
                (info->cmac.key != NULL ||
                 (info->cmac.cmac->devCtx == NULL &&
                  info->cmac.cmac->aes.keylen == 0))) {
                ret = ElsCmacInit(info->cmac.cmac, info->cmac.key,
                                  info->cmac.keySz);
            }
            else if (info->cmac.out == NULL &&
                     info->cmac.cmac->devCtx != NULL) {
                /* A zero-length update is legal, and an owned object has no
                 * software key schedule to fall back on. */
                ret = ElsCmacUpdate(info->cmac.cmac, info->cmac.in,
                                    info->cmac.inSz);
            }
            else if (info->cmac.out != NULL && info->cmac.key == NULL &&
                     info->cmac.in == NULL) {
                ret = ElsCmacFinal(info->cmac.cmac, info->cmac.out,
                                   info->cmac.outSz);
            }
            /* the one-shot form (key + in + out together) is left to software:
             * it would need init/update/final stitched here for no gain */
            break;
#endif

#ifndef WC_NO_RNG
        case WC_ALGO_TYPE_RNG:
            ret = ElsRandom(info->rng.out, info->rng.sz);
            break;

        case WC_ALGO_TYPE_SEED:
            ret = ElsRandom(info->seed.seed, info->seed.sz);
            break;
#endif

#ifndef NO_AES
        case WC_ALGO_TYPE_CIPHER:
            switch (info->cipher.type) {
    #ifdef HAVE_AESGCM
                case WC_CIPHER_AES_GCM:
                    if (info->cipher.enc) {
                        ret = ElsAesGcm(info->cipher.aesgcm_enc.aes,
                                info->cipher.aesgcm_enc.out,
                                info->cipher.aesgcm_enc.in,
                                info->cipher.aesgcm_enc.sz,
                                info->cipher.aesgcm_enc.iv,
                                info->cipher.aesgcm_enc.ivSz,
                                info->cipher.aesgcm_enc.authTag,
                                info->cipher.aesgcm_enc.authTagSz,
                                info->cipher.aesgcm_enc.authIn,
                                info->cipher.aesgcm_enc.authInSz, 1);
                    }
                    else {
                        /* the decrypt struct keeps authTag const; the port
                         * only ever compares against it */
                        ret = ElsAesGcm(info->cipher.aesgcm_dec.aes,
                                info->cipher.aesgcm_dec.out,
                                info->cipher.aesgcm_dec.in,
                                info->cipher.aesgcm_dec.sz,
                                info->cipher.aesgcm_dec.iv,
                                info->cipher.aesgcm_dec.ivSz,
                                (byte*)info->cipher.aesgcm_dec.authTag,
                                info->cipher.aesgcm_dec.authTagSz,
                                info->cipher.aesgcm_dec.authIn,
                                info->cipher.aesgcm_dec.authInSz, 0);
                    }
                    break;
    #endif
    #ifdef HAVE_AES_CBC
                case WC_CIPHER_AES_CBC:
                    ret = ElsAesCipher(info->cipher.aescbc.aes,
                            info->cipher.aescbc.out, info->cipher.aescbc.in,
                            info->cipher.aescbc.sz,
                            MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_CBC,
                            info->cipher.enc, 1);
                    break;
    #endif
    #ifdef WOLFSSL_AES_COUNTER
                case WC_CIPHER_AES_CTR:
                    /* CTR keystream is symmetric, so the hardware always runs
                     * the "encrypt" direction regardless of the caller's. */
                    ret = ElsAesCipher(info->cipher.aesctr.aes,
                            info->cipher.aesctr.out, info->cipher.aesctr.in,
                            info->cipher.aesctr.sz,
                            MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_CTR, 1, 1);
                    break;
    #endif
    #if defined(HAVE_AES_ECB) || defined(WOLFSSL_AES_DIRECT)
                case WC_CIPHER_AES_ECB:
                    ret = ElsAesCipher(info->cipher.aesecb.aes,
                            info->cipher.aesecb.out, info->cipher.aesecb.in,
                            info->cipher.aesecb.sz,
                            MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_ECB,
                            info->cipher.enc, 0);
                    break;
    #endif
                default:
                    break;
            }
            break;
#endif /* !NO_AES */

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
