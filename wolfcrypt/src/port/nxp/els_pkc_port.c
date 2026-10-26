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
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/asn.h>
#endif

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
    (!defined(NO_AES) && (defined(HAVE_AESGCM) || defined(WOLFSSL_CMAC))) || \
    defined(HAVE_ECC) || defined(WOLF_CRYPTO_CB_KEYSTORE)
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

#define ELS_REF_FLAGS_KNOWN (WC_ELSPKC_REF_FLAG_EXPORTABLE | \
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
    /* out[6..15] stay zero - reserved */

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

    for (i = 0; i < WC_ELSPKC_BIND_SZ; i++) {
        if (in[8 + i] != 0) {
            return WC_NO_ERR_TRACE(BAD_STATE_E);
        }
    }

    XMEMSET(ref, 0, sizeof(*ref));
    ref->keyClass = in[3];
    ref->slot     = in[4];
    ref->flags    = in[5];

    return 0;
}

/* Slot validation, reached from every path that can name a slot. */
#ifdef ELS_HAVE_SLOT_KEYS

/* Read a slot's properties. Caller holds the lock. */
static int ElsKsProps(byte slot, mcuxClEls_KeyProp_t* prop)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t,
        mcuxClEls_GetKeyProperties((mcuxClEls_KeyIndex_t)slot, prop));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_GetKeyProperties) != t) ||
        (MCUXCLELS_STATUS_OK != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return 0;
}

/* A key over 128 bits, which every ECC class is, is named by its first slot. */
static int ElsSlotBaseOk(const mcuxClEls_KeyProp_t* prop, byte keyClass)
{
    if (keyClass == WC_ELSPKC_KEY_ECC_SIGN ||
        keyClass == WC_ELSPKC_KEY_ECC_DH ||
        keyClass == WC_ELSPKC_KEY_ECC_SEED ||
        (prop->word.value & 0x3u) != MCUXCLELS_KEYPROPERTY_VALUE_KEY_SIZE_128) {
        return (prop->word.value & MCUXCLELS_KEYPROPERTY_VALUE_BASE_SLOT) != 0;
    }

    return 1;
}

#if (defined(HAVE_ECC) && defined(HAVE_ECC_KEY_IMPORT)) || \
    defined(WOLF_CRYPTO_CB_KEYSTORE)
/* A new key needs a free general purpose slot. Caller holds the lock. */
static int ElsSlotFree(byte slot)
{
    mcuxClEls_KeyProp_t cur;
    int ret = ElsKsProps(slot, &cur);

    if (ret == 0 &&
        ((cur.word.value & MCUXCLELS_KEYPROPERTY_VALUE_ACTIVE) ||
         (cur.word.value &
          MCUXCLELS_KEYPROPERTY_VALUE_GENERAL_PURPOSE_SLOT) == 0)) {
        ret = WC_NO_ERR_TRACE(BAD_STATE_E);
    }

    return ret;
}

/* Both slots of a 256-bit key. Caller holds the lock. */
static int ElsSlotPairFree(byte slot)
{
    int ret;

    if (slot >= WC_ELSPKC_MAX_SLOT) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    ret = ElsSlotFree(slot);
    if (ret == 0) {
        ret = ElsSlotFree((byte)(slot + 1u));
    }

    return ret;
}

static int ElsSlotDeleteRun(byte slot)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t,
        mcuxClEls_KeyDelete_Async((mcuxClEls_KeyIndex_t)slot));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_KeyDelete_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return ElsWait();
}
#endif

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

/* Whether a slot carries the permission a reference's class stands for. */
static int ElsSlotHasClass(const mcuxClEls_KeyProp_t* prop, byte keyClass)
{
    word32 need = ElsClassUsageBit(keyClass);

    if (keyClass == WC_ELSPKC_KEY_KWK) {
        need |= MCUXCLELS_KEYPROPERTY_VALUE_KUOK;
    }

    return need != 0 && (prop->word.value & need) != 0;
}

/* An active key of the class, named by its first slot. */
static int ElsSlotHolds(const mcuxClEls_KeyProp_t* prop, byte keyClass)
{
    return (prop->word.value & MCUXCLELS_KEYPROPERTY_VALUE_ACTIVE) != 0 &&
           ElsSlotHasClass(prop, keyClass) && ElsSlotBaseOk(prop, keyClass);
}

/* Check the slot holds a key of the class; a permission violation resets the
 * SoC. Caller holds the lock. */
static int ElsCheckSlot(const wc_ElsPkc_KeyRef* ref, byte expectClass)
{
    mcuxClEls_KeyProp_t prop;
    int ret;

    if (ref->keyClass != expectClass) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }

    ret = ElsKsProps(ref->slot, &prop);
    if (ret == 0 && !ElsSlotHolds(&prop, ref->keyClass)) {
        ret = WC_NO_ERR_TRACE(BAD_STATE_E);
    }

    return ret;
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

/* P-256 only: the key property word has no bit for RSA or the Ed curves. ELS
 * speaks raw X9.62 (X||Y, R||S) where the callback boundary is DER. */

#ifdef HAVE_ECC

#define ELS_ECC_COORD_SZ 32                          /* P-256 */
#define ELS_ECC_PUB_SZ   MCUXCLELS_ECC_PUBLICKEY_SIZE /* X||Y   */
#define ELS_ECC_SIG_SZ   MCUXCLELS_ECC_SIGNATURE_SIZE /* R||S   */

#if (defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)) && \
    !defined(WC_ALLOW_ECC_ZERO_HASH)
/* Software rejects an all-zero digest below the callback; decline it. */
static int ElsEccDigestIsZero(const byte* d, word32 len)
{
    byte acc = 0;
    word32 i;

    for (i = 0; i < len; i++) {
        acc |= d[i];
    }

    return acc == 0;
}
#endif

#ifdef HAVE_ECC_VERIFY
/* DecodeECC_DSA_Sig_Bin() drops leading zero bytes; the engine wants
 * fixed-width big-endian. */
static int ElsPadSigComponent(byte* buf, word32 len, word32 width)
{
    if (len > width) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (len < width) {
        XMEMMOVE(buf + (width - len), buf, len);
        XMEMSET(buf, 0, width - len);
    }

    return 0;
}

/* Software takes r and s as positive INTEGERs in a SEQUENCE that fills the
 * buffer; DecodeECC_DSA_Sig_Bin() checks neither. */
static int ElsEccSigDerOk(const byte* sig, word32 sigLen)
{
    word32 idx = 0;
    int len;
    int i;
    byte tag;

    if (GetSequence(sig, &idx, &len, sigLen) < 0) {
        return 0;
    }
#ifndef NO_STRICT_ECDSA_LEN
    if (idx + (word32)len != sigLen) {
        return 0;
    }
#endif
    for (i = 0; i < 2; i++) {
        if (GetASNTag(sig, &idx, &tag, sigLen) < 0 || tag != ASN_INTEGER ||
            GetLength(sig, &idx, &len, sigLen) <= 0 ||
            (sig[idx] & 0x80) != 0) {
            return 0;
        }
        idx += (word32)len;
    }

    return 1;
}

static const byte elsP256Order[ELS_ECC_COORD_SZ] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
};

/* Range-check a padded R||S with the codes wc_ecc_check_r_s_range uses. */
static int ElsEccSigRange(const byte* sig, const byte* order, word32 len)
{
    byte rAcc = 0, sAcc = 0;
    word32 i;

    for (i = 0; i < len; i++) {
        rAcc |= sig[i];
        sAcc |= sig[len + i];
    }
    if (rAcc == 0 || sAcc == 0) {
        return WC_NO_ERR_TRACE(MP_ZERO_E);
    }
    if (XMEMCMP(sig, order, len) >= 0 ||
        XMEMCMP(sig + len, order, len) >= 0) {
        return WC_NO_ERR_TRACE(MP_VAL);
    }

    return 0;
}
#endif /* HAVE_ECC_VERIFY */

/* Read the slot reference an ecc_key carries, if it carries one at all. */
static int ElsEccRef(const ecc_key* key, wc_ElsPkc_KeyRef* ref)
{
    if (key == NULL || key->idLen <= 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    return wc_ElsPkc_ParseKeyRef(key->id, (word32)key->idLen, ref);
}

#ifdef HAVE_ECC_SIGN
/* 1 when the caller asked for RFC 6979 or a set k; neither engine takes one. */
static int ElsEccCustomNonce(const ecc_key* key)
{
#if defined(WOLFSSL_ECDSA_DETERMINISTIC_K) || \
    defined(WOLFSSL_ECDSA_DETERMINISTIC_K_VARIANT)
    if (key->deterministic) {
        return 1;
    }
#endif
#if defined(WOLFSSL_ECDSA_SET_K) || defined(WOLFSSL_ECDSA_SET_K_ONE_LOOP)
    #ifndef WOLFSSL_NO_MALLOC
    if (key->sign_k != NULL) {
        return 1;
    }
    #else
    if (key->sign_k_set) {
        return 1;
    }
    #endif
#endif
    (void)key;

    return 0;
}
#endif /* HAVE_ECC_SIGN */

/* P-256 is the only curve with a slot to reference. */
static int ElsEccCurveOk(const ecc_key* key)
{
    return (key != NULL && key->dp != NULL &&
            key->dp->id == ECC_SECP256R1);
}

#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
/* ELS takes a fixed 32-byte digest; a 256-bit order makes the ECDSA
 * conversion a plain truncate-or-zero-extend (FIPS 186-4 6.4). */
static void ElsEccDigest(const byte* in, word32 inlen, byte* out)
{
    if (inlen >= ELS_ECC_COORD_SZ) {
        XMEMCPY(out, in, ELS_ECC_COORD_SZ);
    }
    else {
        XMEMSET(out, 0, ELS_ECC_COORD_SZ - inlen);
        XMEMCPY(out + ELS_ECC_COORD_SZ - inlen, in, inlen);
    }
}
#endif /* HAVE_ECC_SIGN || HAVE_ECC_VERIFY */

#ifdef HAVE_ECC_SIGN
/* A key that arrived as a bare id has no curve, and an ELS ECC reference names
 * a slot the hardware only ever fills with P-256. */
static int ElsEccPinCurve(ecc_key* key)
{
    if (key->dp != NULL) {
        return 0;
    }

    return wc_ecc_set_curve(key, ELS_ECC_COORD_SZ, ECC_SECP256R1);
}
#endif /* HAVE_ECC_SIGN */

int wc_ElsPkc_EccUseSlot(ecc_key* key, const wc_ElsPkc_KeyRef* ref,
                         void* heap, int devId)
{
    byte   blob[WC_ELSPKC_KEYREF_SZ];
    word32 blobSz = sizeof(blob);
    int    ret;

    if (key == NULL || ref == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    if (ref->keyClass != WC_ELSPKC_KEY_ECC_SIGN &&
        ref->keyClass != WC_ELSPKC_KEY_ECC_DH) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }

    ret = wc_ElsPkc_MakeKeyRef(ref, blob, &blobSz);
    if (ret == 0) {
        ret = wc_ecc_init_id(key, blob, (int)blobSz, heap, devId);
    }
    if (ret == 0) {
        /* Pin the curve now. Without it the first operation would have to
         * infer P-256 from a key whose private part it can never see. */
        ret = wc_ecc_set_curve(key, ELS_ECC_COORD_SZ, ECC_SECP256R1);
        if (ret != 0) {
            wc_ecc_free(key);
        }
    }

    ForceZero(blob, sizeof(blob));

    return ret;
}

/* Generate a key in the empty slot the reference names, or from the ukgsrc
 * seed already there. Only now is the public point available. */
#ifdef HAVE_ECC_KEY_IMPORT
static int ElsEccKeyGenRun(ecc_key* key, int seeded)
{
    mcuxClEls_EccKeyGenOption_t opt;
    mcuxClEls_KeyProp_t         prop;
    mcuxClEls_KeyProp_t         cur;
    wc_ElsPkc_KeyRef            ref;
    ALIGN32 byte pub[ELS_ECC_PUB_SZ];
    int ret;

    ret = ElsEccRef(key, &ref);
    if (ret != 0) {
        return ret;
    }
    /* Under WOLF_CRYPTO_CB_KEYGEN_SW_FALLBACK a decline would have software
     * fill a slot key. */
    if (!ElsEccCurveOk(key) ||
        (ref.keyClass != WC_ELSPKC_KEY_ECC_SIGN &&
         ref.keyClass != WC_ELSPKC_KEY_ECC_DH)) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }

    /* kgtypedh sets the rest; a property word ELS disagrees with is a tamper
     * event. */
    prop.word.value = 0u;
    prop.bits.upprot_priv = MCUXCLELS_KEYPROPERTY_PRIVILEGED_FALSE;
    prop.bits.upprot_sec  = MCUXCLELS_KEYPROPERTY_SECURE_FALSE;
    if (ref.flags & WC_ELSPKC_REF_FLAG_EXPORTABLE) {
        prop.bits.wrpok = MCUXCLELS_KEYPROPERTY_WRAP_TRUE;
    }
    /* WC_ELSPKC_REF_FLAG_PERSISTENT is ignored; retention is per slot. */

    opt.word.value  = 0u;
    opt.bits.kgsrc  = seeded ? MCUXCLELS_ECC_OUTPUTKEY_DETERMINISTIC
                             : MCUXCLELS_ECC_OUTPUTKEY_RANDOM;
    opt.bits.kgtypedh = (ref.keyClass == WC_ELSPKC_KEY_ECC_DH)
                        ? MCUXCLELS_ECC_OUTPUTKEY_KEYEXCHANGE
                        : MCUXCLELS_ECC_OUTPUTKEY_SIGN;
    opt.bits.kgsign = MCUXCLELS_ECC_PUBLICKEY_SIGN_DISABLE;
    opt.bits.kgsign_rnd = MCUXCLELS_ECC_NO_RANDOM_DATA;
    opt.bits.skip_pbk = MCUXCLELS_ECC_GEN_PUBLIC_KEY;

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    /* A seed becomes the scalar, so must be 256 bits. */
    if (seeded) {
        ret = ElsKsProps(ref.slot, &cur);
        if (ret == 0 &&
            ((cur.word.value & MCUXCLELS_KEYPROPERTY_VALUE_ACTIVE) == 0 ||
             (cur.word.value & MCUXCLELS_KEYPROPERTY_VALUE_KGSRC) == 0 ||
             (cur.word.value & 0x3u) !=
                 MCUXCLELS_KEYPROPERTY_VALUE_KEY_SIZE_256 ||
             !ElsSlotBaseOk(&cur, WC_ELSPKC_KEY_ECC_SEED))) {
            ret = WC_NO_ERR_TRACE(BAD_STATE_E);
        }
    }
    else {
        ret = ElsSlotPairFree(ref.slot);
    }
    if (ret != 0) {
        ElsUnlock();
        return ret;
    }
    if (seeded) {
        prop.bits.upprot_priv = cur.bits.upprot_priv;
        prop.bits.upprot_sec  = cur.bits.upprot_sec;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEls_EccKeyGen_Async(
        opt, 0u, (mcuxClEls_KeyIndex_t)ref.slot, prop, NULL, pub));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_EccKeyGen_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        ElsUnlock();
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    ret = ElsWait();

    ElsUnlock();

    if (ret == 0) {
        ret = wc_ecc_import_unsigned(key, pub, pub + ELS_ECC_COORD_SZ,
                                     NULL, ECC_SECP256R1);
        /* Give the pair back, or a retry would find it occupied. */
        if (ret != 0 && !seeded && ElsLock() == 0) {
            (void)ElsSlotDeleteRun(ref.slot);
            ElsUnlock();
        }
    }

    ForceZero(pub, sizeof(pub));

    return ret;
}

#ifdef HAVE_ECC_DHE
static int ElsEccKeyGen(ecc_key* key)
{
    return ElsEccKeyGenRun(key, 0);
}
#endif

int wc_ElsPkc_EccKeyGenFromSeed(ecc_key* key, const wc_ElsPkc_KeyRef* seed,
                                byte keyClass, void* heap, int devId)
{
    wc_ElsPkc_KeyRef ref;
    int ret;

    if (key == NULL || seed == NULL ||
        seed->keyClass != WC_ELSPKC_KEY_ECC_SEED ||
        (keyClass != WC_ELSPKC_KEY_ECC_SIGN &&
         keyClass != WC_ELSPKC_KEY_ECC_DH)) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }

    /* The same slots, named by what they will hold once this returns. The
     * engine sets a seeded key's properties itself, wrpok included. */
    ref = *seed;
    ref.keyClass = keyClass;
    ref.flags &= (byte)~WC_ELSPKC_REF_FLAG_EXPORTABLE;
    ret = wc_ElsPkc_EccUseSlot(key, &ref, heap, devId);
    if (ret == 0) {
        ret = ElsEccKeyGenRun(key, 1);
        if (ret == WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
            ret = WC_NO_ERR_TRACE(BAD_FUNC_ARG);
        }
        if (ret != 0) {
            wc_ecc_free(key);
        }
    }
    ForceZero(&ref, sizeof(ref));

    return ret;
}
#elif defined(HAVE_ECC_DHE)
/* Without the import the public point cannot be loaded into the key. */
static int ElsEccKeyGen(ecc_key* key)
{
    wc_ElsPkc_KeyRef ref;
    int ret = ElsEccRef(key, &ref);

    return (ret == 0) ? WC_NO_ERR_TRACE(NOT_COMPILED_IN) : ret;
}
#endif /* HAVE_ECC_KEY_IMPORT */

#ifdef HAVE_ECC_SIGN
/* Issue the sign command. Caller holds the lock and has validated the slot.
 * Split out so the flow-protection macro pair stays within one scope. */
static int ElsEccSignRun(mcuxClEls_EccSignOption_t opt, byte slot,
                         const byte* hash, byte* sig)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEls_EccSign_Async(
        opt, (mcuxClEls_KeyIndex_t)slot, hash, NULL, 0u, sig));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_EccSign_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return ElsWait();
}

/* The check-key self-test passes anyNonce to ignore the key's nonce mode. */
static int ElsEccSign(const byte* in, word32 inlen, byte* out, word32* outlen,
                      ecc_key* key, int anyNonce)
{
    mcuxClEls_EccSignOption_t opt;
    wc_ElsPkc_KeyRef ref;
    ALIGN32 byte hash[ELS_ECC_COORD_SZ];
    ALIGN32 byte sig[ELS_ECC_SIG_SZ];
    int ret;

    if (in == NULL || out == NULL || outlen == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    ret = ElsEccRef(key, &ref);
    if (ret != 0) {
        return ret;
    }
    /* Past this point a decline would sign with ecc_key's zero scalar. */
    if (ref.keyClass != WC_ELSPKC_KEY_ECC_SIGN) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }
    ret = ElsEccPinCurve(key);
    if (ret != 0) {
        return ret;
    }
    if (!ElsEccCurveOk(key) || (!anyNonce && ElsEccCustomNonce(key))) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }

    ElsEccDigest(in, inlen, hash);

    opt.word.value    = 0u;
    opt.bits.echashchl = MCUXCLELS_ECC_HASHED;
    opt.bits.signrtf   = MCUXCLELS_ECC_NO_RTF;

    ret = ElsLock();
    if (ret != 0) {
        goto out;
    }

    ret = ElsCheckSlot(&ref, WC_ELSPKC_KEY_ECC_SIGN);
    if (ret == 0) {
        ret = ElsEccSignRun(opt, ref.slot, hash, sig);
    }

    ElsUnlock();

    if (ret == 0) {
        /* ELS returns raw R||S; the callback boundary is DER. */
        ret = StoreECC_DSA_Sig_Bin(out, outlen,
                                   sig, ELS_ECC_COORD_SZ,
                                   sig + ELS_ECC_COORD_SZ, ELS_ECC_COORD_SZ);
    }

out:
    ForceZero(hash, sizeof(hash));
    ForceZero(sig, sizeof(sig));

    return ret;
}

#endif /* HAVE_ECC_SIGN */

#ifdef HAVE_ECC_VERIFY
/* Verification needs no slot - the public key is ordinary wolfCrypt material,
 * so this accelerates any P-256 verify, vaulted key or not. */
static int ElsEccVerify(const byte* sig, word32 siglen, const byte* digest,
                        word32 hashlen, int* res, ecc_key* key)
{
    mcuxClEls_EccVerifyOption_t opt;
    ALIGN32 byte sigAndPub[ELS_ECC_SIG_SZ + ELS_ECC_PUB_SZ];
    ALIGN32 byte hash[ELS_ECC_COORD_SZ];
    ALIGN32 byte rCalc[ELS_ECC_COORD_SZ];
    word32 rLen = ELS_ECC_COORD_SZ, sLen = ELS_ECC_COORD_SZ;
    int    ret;

    if (sig == NULL || digest == NULL || res == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    if (!ElsEccCurveOk(key) || !ElsEccSigDerOk(sig, siglen) ||
        (key->type != ECC_PUBLICKEY && key->type != ECC_PRIVATEKEY)) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    *res = 0;

    /* DER in, raw R||S out, both fixed 32-byte components. */
    ret = DecodeECC_DSA_Sig_Bin(sig, siglen, sigAndPub, &rLen,
                                sigAndPub + ELS_ECC_COORD_SZ, &sLen);
    if (ret != 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    ret = ElsPadSigComponent(sigAndPub, rLen, ELS_ECC_COORD_SZ);
    if (ret == 0) {
        ret = ElsPadSigComponent(sigAndPub + ELS_ECC_COORD_SZ, sLen,
                                 ELS_ECC_COORD_SZ);
    }
    if (ret != 0) {
        return ret;
    }
    /* wolfCrypt range-checks r and s only on its software path. */
    ret = ElsEccSigRange(sigAndPub, elsP256Order, ELS_ECC_COORD_SZ);
    if (ret != 0) {
        return ret;
    }

    /* ELS takes the point as X||Y. */
    if (mp_to_unsigned_bin_len(key->pubkey.x, sigAndPub + ELS_ECC_SIG_SZ,
                               ELS_ECC_COORD_SZ) != MP_OKAY ||
        mp_to_unsigned_bin_len(key->pubkey.y,
                               sigAndPub + ELS_ECC_SIG_SZ + ELS_ECC_COORD_SZ,
                               ELS_ECC_COORD_SZ) != MP_OKAY) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    ElsEccDigest(digest, hashlen, hash);

    opt.word.value     = 0u;
    opt.bits.echashchl = MCUXCLELS_ECC_HASHED;

    ret = ElsLock();
    if (ret != 0) {
        goto out;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEls_EccVerify_Async(
        opt, hash, NULL, 0u, sigAndPub, rCalc));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_EccVerify_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        ElsUnlock();
        ret = WC_NO_ERR_TRACE(WC_HW_E);
        goto out;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    ret = ElsWait();

    ElsUnlock();

    if (ret == 0) {
        /* ELS reports a bad signature only through the R comparison. */
        *res = (wc_ConstantCompare(rCalc, sigAndPub, ELS_ECC_COORD_SZ) == 0);
    }

out:
    ForceZero(hash, sizeof(hash));
    ForceZero(rCalc, sizeof(rCalc));

    return ret;
}

#endif /* HAVE_ECC_VERIFY */

#ifdef HAVE_ECC_CHECK_KEY
#if defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY)
static const byte elsEccPctDigest[ELS_ECC_COORD_SZ] = {
    0x45, 0x4c, 0x53, 0x2d, 0x50, 0x43, 0x54, 0x2d,
    0x45, 0x4c, 0x53, 0x2d, 0x50, 0x43, 0x54, 0x2d,
    0x45, 0x4c, 0x53, 0x2d, 0x50, 0x43, 0x54, 0x2d,
    0x45, 0x4c, 0x53, 0x2d, 0x50, 0x43, 0x54, 0x2d
};

/* Sign in the slot and verify against key->pubkey. */
static int ElsEccPairwiseTest(ecc_key* key)
{
    byte   der[ECC_MAX_SIG_SIZE];
    word32 derSz = sizeof(der);
    int    res = 0;
    int    ret;

    ret = ElsEccSign(elsEccPctDigest, sizeof(elsEccPctDigest), der, &derSz,
                     key, 1);
    if (ret == 0) {
        ret = ElsEccVerify(der, derSz, elsEccPctDigest,
                           sizeof(elsEccPctDigest), &res, key);
    }
    /* A decline would let wc_ecc_check_key() skip the pairing in software. */
    if ((ret == 0 && res != 1) ||
        ret == WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
        ret = WC_NO_ERR_TRACE(ECC_PRIV_KEY_E);
    }

    return ret;
}
#endif

/* wc_ecc_check_key() for a slot key, whose ecc_key holds no scalar. */
static int ElsEccCheckKey(ecc_key* key, int checkPriv)
{
    wc_ElsPkc_KeyRef ref;
    int havePub;
    int ret;

    ret = ElsEccRef(key, &ref);
    if (ret != 0) {
        return ret;
    }
    if ((ref.keyClass != WC_ELSPKC_KEY_ECC_SIGN &&
         ref.keyClass != WC_ELSPKC_KEY_ECC_DH) || !ElsEccCurveOk(key)) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }

    /* P-256 has cofactor 1, so a point on the curve also has order n. */
    havePub = (key->type == ECC_PUBLICKEY || key->type == ECC_PRIVATEKEY);
    if (!havePub && !checkPriv) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (havePub) {
        ret = wc_ecc_point_is_on_curve(&key->pubkey, key->idx);
    }
    if (ret != 0 || !checkPriv) {
        return ret;
    }

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }
    ret = ElsCheckSlot(&ref, ref.keyClass);
    ElsUnlock();

#if defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY)
    /* A key agreement slot cannot sign, so only the slot check covers it. */
    if (ret == 0 && havePub && ref.keyClass == WC_ELSPKC_KEY_ECC_SIGN) {
        ret = ElsEccPairwiseTest(key);
    }
#endif

    return ret;
}
#endif /* HAVE_ECC_CHECK_KEY */

#endif /* HAVE_ECC */

/* The PKC workarea is a fixed hardware region at PKC_RAM_ADDR shared with
 * ELS, so PKC work runs under the ELS lock. */

#if !defined(NO_RSA) || defined(HAVE_CURVE25519) || \
    (defined(HAVE_ECC) && \
     (defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)))
#define ELS_PKC_HAVE_SESSION

#include <mcuxClSession.h>
#include <mcuxClPkc_Types.h>   /* MCUXCLPKC_PACKARGS4, used by the ECC
                                * domain-parameter packing macro */
#include <mcuxClRandom.h>
#include <mcuxClRandomModes.h>
#include <mcux_pkc.h>
#if defined(HAVE_ECC) || defined(HAVE_CURVE25519)
    /* Shared by the ECDSA and Montgomery-curve paths, either of which
     * can be built without the other. */
    #include <mcuxClEcc.h>
#endif
#ifndef NO_RSA
    #include <mcuxClRsa.h>
#endif

/* Fixed PKC RAM window on rw61x, mirrored from the vendor platform header so a
 * build that does not export ip_platform.h still gets the right region. */
#ifndef WOLFSSL_ELS_PKC_RAM_ADDR
    #define WOLFSSL_ELS_PKC_RAM_ADDR 0x5015A000u
#endif
#ifndef WOLFSSL_ELS_PKC_RAM_SIZE
    #define WOLFSSL_ELS_PKC_RAM_SIZE 0x2000u
#endif

/* CLNS CPU workarea, sized for RSA-4096. */
#ifndef WOLFSSL_ELS_PKC_CPU_WA_SZ
    #define WOLFSSL_ELS_PKC_CPU_WA_SZ 1024
#endif

static uint32_t elsPkcCpuWa[(WOLFSSL_ELS_PKC_CPU_WA_SZ + 3u) / 4u];
static uint32_t elsPkcRngCtx[64];
/* The vendor publishes the context size per mode; a bigger SDK context would
 * otherwise overflow this .bss object silently. */
wc_static_assert(sizeof(elsPkcRngCtx) >=
                 MCUXCLRANDOMMODES_CTR_DRBG_AES256_CONTEXT_SIZE);

/* The 128-bit ELS DRBG is too weak for RSA-4096 and orders over 32 bytes,
 * which take the 256-bit DRG.3 instead. Caller holds the lock. */
static int ElsPkcRandomInit(mcuxClSession_Descriptor_t* sess, int need256)
{
    mcuxClRandom_Mode_t mode = need256
                                   ? mcuxClRandomModes_Mode_CtrDrbg_AES256_DRG3
                                   : mcuxClRandomModes_Mode_ELS_Drbg;

    if (need256) {
        XMEMSET(elsPkcRngCtx, 0, sizeof(elsPkcRngCtx));
    }

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(rr, rt, mcuxClRandom_init(sess,
        need256 ? (mcuxClRandom_Context_t)elsPkcRngCtx : NULL, mode));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_init) != rt) ||
        (MCUXCLRANDOM_STATUS_OK != rr)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return 0;
}

/* Point the session at a DRBG that ElsPkcRandomInit() has set up. */
static int ElsPkcRandomUse(mcuxClSession_Descriptor_t* sess, int need256)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(sr, st, mcuxClSession_setRandom(sess,
        need256 ? mcuxClRandomModes_Mode_CtrDrbg_AES256_DRG3
                : mcuxClRandomModes_Mode_ELS_Drbg,
        need256 ? (mcuxClRandom_Context_t)elsPkcRngCtx : NULL));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_setRandom) != st) ||
        (MCUXCLSESSION_STATUS_OK != sr)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return 0;
}

static void ElsPkcRandomUninit(mcuxClSession_Descriptor_t* sess, int need256)
{
    if (ElsPkcRandomUse(sess, need256) != 0) {
        return;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ur, ut, mcuxClRandom_uninit(sess));
    (void)ur;
    (void)ut;
    MCUX_CSSL_FP_FUNCTION_CALL_END();
}

static int ElsPkcRandomNcInit(mcuxClSession_Descriptor_t* sess)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(pr, pt, mcuxClRandom_ncInit(sess));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncInit) != pt) ||
        (MCUXCLRANDOM_STATUS_OK != pr)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return 0;
}

static int ElsPkcSessionInit(mcuxClSession_Descriptor_t* sess)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(sr, st, mcuxClSession_init(
        sess, elsPkcCpuWa, WOLFSSL_ELS_PKC_CPU_WA_SZ,
        (uint32_t*)WOLFSSL_ELS_PKC_RAM_ADDR, WOLFSSL_ELS_PKC_RAM_SIZE));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_init) != st) ||
        (MCUXCLSESSION_STATUS_OK != sr)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return 0;
}

/* Writing the PKC window faults the bus unless the PKC is clocked. Caller
 * holds the lock. */
static void ElsCleanupSession(void)
{
    ForceZero(elsPkcRngCtx, sizeof(elsPkcRngCtx));
    ForceZero(elsPkcCpuWa, sizeof(elsPkcCpuWa));
    ForceZero((void*)(wc_ptr_t)WOLFSSL_ELS_PKC_RAM_ADDR,
              WOLFSSL_ELS_PKC_RAM_SIZE);
}

/* CLNS wipes the work areas, including key material left in the shared PKC
 * window. Best effort. */
static void ElsPkcSessionWipe(mcuxClSession_Descriptor_t* sess)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(cr, ct, mcuxClSession_cleanup(sess));
    (void)cr;
    (void)ct;
    MCUX_CSSL_FP_FUNCTION_CALL_END();
}

static void ElsPkcSessionEnd(mcuxClSession_Descriptor_t* sess)
{
    ElsPkcSessionWipe(sess);

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(dr, dt, mcuxClSession_destroy(sess));
    (void)dr;
    (void)dt;
    MCUX_CSSL_FP_FUNCTION_CALL_END();
}

/* One session serves every PKC operation, so the 256-bit DRBG is instantiated
 * once. Caller holds the lock. */
static mcuxClSession_Descriptor_t elsPkcSess;
static byte elsPkcSessUp;
static byte elsPkcRng256Up;
static uint32_t elsPkcCpuUsed;
static uint32_t elsPkcPkcUsed;

static void ElsPkcSessionDown(void)
{
    if (!elsPkcSessUp) {
        return;
    }
    if (elsPkcRng256Up) {
        ElsPkcRandomUninit(&elsPkcSess, 1);
    }
    ElsPkcRandomUninit(&elsPkcSess, 0);
    ElsPkcSessionEnd(&elsPkcSess);
    ForceZero(elsPkcRngCtx, sizeof(elsPkcRngCtx));
    elsPkcSessUp   = 0;
    elsPkcRng256Up = 0;
    /* The error exits that keep work area claimed also leave the PKC set up. */
    (void)PKC_PowerDownWakeupInit(PKC);
}

static int ElsPkcSessionOpen(mcuxClSession_Descriptor_t** sess, int need256)
{
    int ret;

    if (!elsPkcSessUp) {
        ret = ElsPkcSessionInit(&elsPkcSess);
        if (ret != 0) {
            return ret;
        }
        /* mcuxClRandom_uninit() reads the mode that a failed init never set. */
        ret = ElsPkcRandomInit(&elsPkcSess, 0);
        if (ret != 0) {
            ElsPkcSessionEnd(&elsPkcSess);
            return ret;
        }
        elsPkcSessUp = 1;
        ret = ElsPkcRandomNcInit(&elsPkcSess);
        if (ret != 0) {
            ElsPkcSessionDown();
            return ret;
        }
    }
    if (need256 && !elsPkcRng256Up) {
        ret = ElsPkcRandomInit(&elsPkcSess, 1);
        if (ret != 0) {
            ElsPkcSessionDown();
            return ret;
        }
        elsPkcRng256Up = 1;
    }
    ret = ElsPkcRandomUse(&elsPkcSess, need256);
    if (ret != 0) {
        ElsPkcSessionDown();
        return ret;
    }

    elsPkcCpuUsed = elsPkcSess.cpuWa.used;
    elsPkcPkcUsed = elsPkcSess.pkcWa.used;
    *sess = &elsPkcSess;

    return 0;
}

/* Some CLNS error exits keep their work area claimed, so the session starts
 * over after any operation that leaves more claimed than it found. */
static void ElsPkcSessionClose(mcuxClSession_Descriptor_t* sess, int failed)
{
    if (failed || sess->cpuWa.used != elsPkcCpuUsed ||
        sess->pkcWa.used != elsPkcPkcUsed) {
        ElsPkcSessionDown();
    }
    else {
        ElsPkcSessionWipe(sess);
    }
}

/* ELS_PowerDownWakeupInit() leaves the PKC alone. */
static int ElsPkcEnable(void)
{
    if (PKC_PowerDownWakeupInit(PKC) != kStatus_Success) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    /* A session that a failed cleanup left open would not survive the reset. */
    ForceZero(&elsPkcSess, sizeof(elsPkcSess));
    ForceZero(elsPkcRngCtx, sizeof(elsPkcRngCtx));
    elsPkcSessUp   = 0;
    elsPkcRng256Up = 0;

    return 0;
}

#ifndef NO_RSA

/* Export an mp_int as a fixed-width big-endian string, which is the only form
 * the vendor key entries accept. */
static int ElsPkcMpToBin(mp_int* a, byte* out, word32 len)
{
    if (mp_unsigned_bin_size(a) > (int)len) {
        return WC_NO_ERR_TRACE(BUFFER_E);
    }

    return mp_to_unsigned_bin_len(a, out, (int)len);
}

/* RSAVP1: the raw public operation, out = in^e mod n. */
static int ElsPkcRsaPublic(mcuxClSession_Descriptor_t* sess,
                           mcuxClRsa_Key* k, const byte* in, word32 modLen,
                           byte* out)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClRsa_verify(
        sess, k, NULL, 0u, (mcuxCl_Buffer_t)(uintptr_t)in,
        (mcuxClRsa_SignVerifyMode)&mcuxClRsa_Mode_Verify_NoVerify,
        0u, 0u, out));
    /* RSAVP1 reports VERIFYPRIMITIVE_OK; the padded modes report VERIFY_OK. */
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_verify) != t) ||
        ((MCUXCLRSA_STATUS_VERIFYPRIMITIVE_OK != r) &&
         (MCUXCLRSA_STATUS_VERIFY_OK != r))) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    (void)modLen;

    return 0;
}

/* RSASP1: the raw private operation, out = in^d mod n (by CRT when possible). */
static int ElsPkcRsaPrivate(mcuxClSession_Descriptor_t* sess,
                            mcuxClRsa_Key* k, const byte* in, word32 modLen,
                            byte* out)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClRsa_sign(
        sess, k, in, modLen,
        (mcuxClRsa_SignVerifyMode)&mcuxClRsa_Mode_Sign_NoEncode,
        0u, 0u, out));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_sign) != t) ||
        (MCUXCLRSA_STATUS_SIGN_OK != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return 0;
}

#if !defined(NO_RSA_BOUNDS_CHECK) && \
    (defined(WOLF_CRYPTO_CB_ONLY_RSA) || defined(WOLFSSL_NO_RSA_SW))
/* RsaFunctionCheckIn() is compiled out in this build: 1 < c < n - 1. */
static int ElsPkcRsaCheckIn(const byte* in, word32 len, RsaKey* key)
{
    byte*  nm1;
    word32 i;
    int    ret;

    nm1 = (byte*)XMALLOC(len, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (nm1 == NULL) {
        return WC_NO_ERR_TRACE(MEMORY_E);
    }
    ret = ElsPkcMpToBin(&key->n, nm1, len);
    if (ret == 0) {
        for (i = len; i > 0 && nm1[i - 1] == 0; i--) {
            nm1[i - 1] = 0xff;
        }
        if (i == 0) {
            ret = WC_NO_ERR_TRACE(RSA_OUT_OF_RANGE_E);
        }
        else {
            nm1[i - 1]--;
        }
    }
    if (ret == 0 && XMEMCMP(in, nm1, len) >= 0) {
        ret = WC_NO_ERR_TRACE(RSA_OUT_OF_RANGE_E);
    }
    if (ret == 0) {
        for (i = 0; i < len - 1 && in[i] == 0; i++) {
        }
        if (i == len - 1 && in[i] <= 1) {
            ret = WC_NO_ERR_TRACE(RSA_OUT_OF_RANGE_E);
        }
    }

    XFREE(nm1, key->heap, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}
#endif

/* RSA at the raw primitive, beneath padding: NoVerify and NoEncode. */
/* Mirror rsa.h's conditions for the p/q and dP/dQ/u members. */
#if !defined(WOLFSSL_RSA_PUBLIC_ONLY) && \
    (defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA) || \
     !defined(RSA_LOW_MEM))
    #define ELS_PKC_RSA_HAVE_CRT
#endif

#ifdef ELS_PKC_RSA_HAVE_CRT
static int ElsPkcRsaCrtFits(const mp_int* a, word32 half)
{
    int sz = mp_unsigned_bin_size((mp_int*)a);

    return sz > 0 && sz <= (int)half;
}

/* CLNS takes a CRT key's modulus length as bits(p) + bits(q). */
static int ElsPkcRsaHaveCrt(const RsaKey* key, word32 half)
{
    return ElsPkcRsaCrtFits(&key->p, half) &&
           ElsPkcRsaCrtFits(&key->q, half) &&
           ElsPkcRsaCrtFits(&key->dP, half) &&
           ElsPkcRsaCrtFits(&key->dQ, half) &&
           ElsPkcRsaCrtFits(&key->u, half) &&
           mp_count_bits((mp_int*)&key->p) + mp_count_bits((mp_int*)&key->q) ==
               mp_count_bits((mp_int*)&key->n);
}
#endif

static int ElsPkcRsaFunction(const byte* in, word32 inLen, byte* out,
                             word32* outLen, int type, RsaKey* key)
{
    mcuxClSession_Descriptor_t* sess = NULL;
    mcuxClRsa_Key      rsaKey;
    mcuxClRsa_KeyEntry_t e1, e4;
#ifdef ELS_PKC_RSA_HAVE_CRT
    mcuxClRsa_KeyEntry_t e2, e3, e5;   /* the CRT-only entries */
#endif
    byte*  buf = NULL;
    word32 modLen;
    int    isPrivate;
    int    ret;

    if (in == NULL || out == NULL || outLen == NULL || key == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    if (type != RSA_PUBLIC_ENCRYPT && type != RSA_PUBLIC_DECRYPT &&
        type != RSA_PRIVATE_ENCRYPT && type != RSA_PRIVATE_DECRYPT) {
        return WC_NO_ERR_TRACE(RSA_WRONG_TYPE_E);
    }

    modLen = (word32)mp_unsigned_bin_size(&key->n);
    /* The engine covers 512..4096-bit moduli in multiples of 8 bits. Anything
     * else, including a modulus wolfCrypt would accept, goes to software. */
    if (modLen < 64 || modLen > 512 || inLen != modLen ||
        (word32)mp_count_bits(&key->n) != modLen * 8u || mp_iseven(&key->n)) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (*outLen < modLen) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    isPrivate = (type == RSA_PRIVATE_DECRYPT || type == RSA_PRIVATE_ENCRYPT);
#ifdef WOLFSSL_RSA_PUBLIC_ONLY
    /* RsaKey carries no private members at all in this build. */
    if (isPrivate) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
#else
    if (isPrivate && (key->type != RSA_PRIVATE || mp_iszero(&key->d))) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
#endif
#ifndef NO_RSA_BOUNDS_CHECK
    if (type == RSA_PRIVATE_DECRYPT || type == RSA_PUBLIC_DECRYPT) {
    #if !defined(WOLF_CRYPTO_CB_ONLY_RSA) && !defined(WOLFSSL_NO_RSA_SW)
        /* Software bounds the input only for its own padded callers. */
        if (RsaFunctionCheckIn(in, inLen, key, 1) != 0) {
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
    #else
        ret = ElsPkcRsaCheckIn(in, modLen, key);
        if (ret != 0) {
            return ret;
        }
    #endif
    }
#endif

    /* One scratch block holds every key entry, sized for the CRT case: five
     * entries of at most half a modulus each, plus the modulus itself. */
    buf = (byte*)XMALLOC(modLen * 4u, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL) {
        return WC_NO_ERR_TRACE(MEMORY_E);
    }
    XMEMSET(buf, 0, modLen * 4u);
    XMEMSET(&rsaKey, 0, sizeof(rsaKey));

    if (!isPrivate) {
        /* public: N and E */
        e1.pKeyEntryData = buf;
        e1.keyEntryLength = modLen;
        ret = ElsPkcMpToBin(&key->n, e1.pKeyEntryData, modLen);

        if (ret == 0) {
            word32 eLen = (word32)mp_unsigned_bin_size(&key->e);
            /* The scratch block leaves one modulus length for the exponent. */
            if (eLen == 0 || eLen > modLen) {
                ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
            }
            else {
                e4.pKeyEntryData = buf + modLen;
                e4.keyEntryLength = eLen;
                ret = ElsPkcMpToBin(&key->e, e4.pKeyEntryData, eLen);
            }
        }
        rsaKey.keytype = MCUXCLRSA_KEY_PUBLIC;
        rsaKey.pMod1 = &e1;
        rsaKey.pExp1 = &e4;
    }
#ifndef WOLFSSL_RSA_PUBLIC_ONLY
    else {
#ifdef ELS_PKC_RSA_HAVE_CRT
        word32 half = (modLen + 1u) / 2u;

        if (ElsPkcRsaHaveCrt(key, half)) {
            e1.pKeyEntryData = buf;              e1.keyEntryLength = half;
            e2.pKeyEntryData = buf + half;       e2.keyEntryLength = half;
            e3.pKeyEntryData = buf + 2u * half;  e3.keyEntryLength = half;
            e4.pKeyEntryData = buf + 3u * half;  e4.keyEntryLength = half;
            e5.pKeyEntryData = buf + 4u * half;  e5.keyEntryLength = half;

            ret = ElsPkcMpToBin(&key->p, e1.pKeyEntryData, half);
            if (ret == 0) ret = ElsPkcMpToBin(&key->q,  e2.pKeyEntryData, half);
            if (ret == 0) ret = ElsPkcMpToBin(&key->u,  e3.pKeyEntryData, half);
            if (ret == 0) ret = ElsPkcMpToBin(&key->dP, e4.pKeyEntryData, half);
            if (ret == 0) ret = ElsPkcMpToBin(&key->dQ, e5.pKeyEntryData, half);

            rsaKey.keytype = MCUXCLRSA_KEY_PRIVATECRT;
            rsaKey.pMod1 = &e1;
            rsaKey.pMod2 = &e2;
            rsaKey.pQInv = &e3;
            rsaKey.pExp1 = &e4;
            rsaKey.pExp2 = &e5;
        }
        else
#endif /* ELS_PKC_RSA_HAVE_CRT */
        {
            e1.pKeyEntryData = buf;           e1.keyEntryLength = modLen;
            e4.pKeyEntryData = buf + modLen;  e4.keyEntryLength = modLen;

            ret = ElsPkcMpToBin(&key->n, e1.pKeyEntryData, modLen);
            if (ret == 0) ret = ElsPkcMpToBin(&key->d, e4.pKeyEntryData, modLen);

            rsaKey.keytype = MCUXCLRSA_KEY_PRIVATEPLAIN;
            rsaKey.pMod1 = &e1;
            rsaKey.pExp1 = &e4;
        }
    }
#endif /* !WOLFSSL_RSA_PUBLIC_ONLY */

    if (ret == 0) {
        ret = ElsLock();
    }
    if (ret == 0) {
        /* Only the private operation blinds from the DRBG. */
        ret = ElsPkcSessionOpen(&sess, isPrivate && modLen >= 512u);
        if (ret == 0) {
            ret = isPrivate
                ? ElsPkcRsaPrivate(sess, &rsaKey, in, modLen, out)
                : ElsPkcRsaPublic(sess, &rsaKey, in, modLen, out);
            ElsPkcSessionClose(sess, ret == WC_NO_ERR_TRACE(WC_HW_E));
        }
        ElsUnlock();
    }

    if (ret == 0) {
        *outLen = modLen;
    }

    ForceZero(buf, modLen * 4u);
    XFREE(buf, key->heap, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

#endif /* !NO_RSA */

#endif /* ELS_PKC_HAVE_SESSION */

/* Only the shared secret is claimed; key generation stays in software. */

#ifdef HAVE_CURVE25519

#include <mcuxClKey.h>

#define ELS_X25519_KEY_SZ MCUXCLECC_MONTDH_CURVE25519_SIZE_PRIVATEKEY

/* Wrap a raw key buffer in a vendor key descriptor. Caller holds the lock. */
static int ElsPkcKeyInit(mcuxClSession_Descriptor_t* sess,
                         mcuxClKey_Handle_t h, mcuxClKey_Type_t type,
                         byte* data)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClKey_init(
        sess, h, type, data, ELS_X25519_KEY_SZ));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != t) ||
        (MCUXCLKEY_STATUS_OK != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return 0;
}

/* The agreement itself, kept in its own scope so the flow-protection macro
 * pair - which expands to a do/while - stays balanced. */
static int ElsPkcMontDhRun(mcuxClSession_Descriptor_t* sess,
                           mcuxClKey_Handle_t priv, mcuxClKey_Handle_t pub,
                           byte* ss, uint32_t* len)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEcc_MontDH_KeyAgreement(
        sess, priv, pub, ss, len));
    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_MontDH_KeyAgreement) != t) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    /* The engine's RFC 7748 all-zero check. CLNS reports a detected fault the
     * same way, so one also lands here. */
    if (MCUXCLECC_STATUS_ERROR_SMALL_SUBGROUP == r) {
        return WC_NO_ERR_TRACE(ECC_OUT_OF_RANGE_E);
    }
    if (MCUXCLECC_STATUS_OK != r) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return 0;
}

static int ElsPkcMontDh(mcuxClSession_Descriptor_t* sess,
                        const byte* priv, const byte* pub, byte* out,
                        word32* outLen)
{
    uint32_t privDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    uint32_t pubDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    ALIGN32 byte privBuf[ELS_X25519_KEY_SZ];
    ALIGN32 byte pubBuf[ELS_X25519_KEY_SZ];
    ALIGN32 byte ss[ELS_X25519_KEY_SZ];
    uint32_t len = 0u;
    int ret = 0;

    XMEMCPY(privBuf, priv, ELS_X25519_KEY_SZ);
    XMEMCPY(pubBuf, pub, ELS_X25519_KEY_SZ);

    ret = ElsPkcKeyInit(sess, (mcuxClKey_Handle_t)privDesc,
                        mcuxClKey_Type_Ecc_MontDH_Curve25519_PrivateKey,
                        privBuf);
    if (ret == 0) {
        ret = ElsPkcKeyInit(sess, (mcuxClKey_Handle_t)pubDesc,
                            mcuxClKey_Type_Ecc_MontDH_Curve25519_PublicKey,
                            pubBuf);
    }

    if (ret == 0) {
        ret = ElsPkcMontDhRun(sess, (mcuxClKey_Handle_t)privDesc,
                              (mcuxClKey_Handle_t)pubDesc, ss, &len);
    }

    if (ret == 0) {
        if (len != ELS_X25519_KEY_SZ || *outLen < len) {
            ret = WC_NO_ERR_TRACE(BUFFER_E);
        }
        else {
            XMEMCPY(out, ss, len);
            *outLen = len;
        }
    }

    ForceZero(privBuf, sizeof(privBuf));
    ForceZero(ss, sizeof(ss));

    return ret;
}

static int ElsPkcX25519(curve25519_key* privKey, curve25519_key* pubKey,
                        byte* out, word32* outLen, int endian)
{
    mcuxClSession_Descriptor_t* sess = NULL;
    byte priv[ELS_X25519_KEY_SZ];
    byte pub[ELS_X25519_KEY_SZ];
    word32 privSz = sizeof(priv);
    word32 pubSz  = sizeof(pub);
    int ret;

    if (privKey == NULL || pubKey == NULL || out == NULL || outLen == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    /* The engine is little-endian; decline the legacy big-endian request. */
    if (endian != EC25519_LITTLE_ENDIAN) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

#ifdef HAVE_CURVE25519_KEY_EXPORT
    ret = wc_curve25519_export_private_raw_ex(privKey, priv, &privSz,
                                              EC25519_LITTLE_ENDIAN);
    if (ret == 0) {
        ret = wc_curve25519_export_public_ex(pubKey, pub, &pubSz,
                                             EC25519_LITTLE_ENDIAN);
    }
#else
    ret = WC_NO_ERR_TRACE(NOT_COMPILED_IN);
#endif
    if (ret != 0 || privSz != ELS_X25519_KEY_SZ ||
        pubSz != ELS_X25519_KEY_SZ) {
        ForceZero(priv, sizeof(priv));
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    ret = ElsLock();
    if (ret == 0) {
        ret = ElsPkcSessionOpen(&sess, 0);
        if (ret == 0) {
            ret = ElsPkcMontDh(sess, priv, pub, out, outLen);
            ElsPkcSessionClose(sess, ret == WC_NO_ERR_TRACE(WC_HW_E));
        }
        ElsUnlock();
    }

    ForceZero(priv, sizeof(priv));

    return ret;
}

#endif /* HAVE_CURVE25519 */

/* Every curve, and P-256 for a key without a slot. Domain parameters are
 * converted into shared scratch under the lock. */

#if defined(HAVE_ECC) && \
    (defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY))

#define ELS_PKC_ECC_MAX_P MCUXCLECC_WEIERECC_MAX_SIZE_PRIMEP
#define ELS_PKC_ECC_MAX_N MCUXCLECC_WEIERECC_MAX_SIZE_BASEPOINTORDER

/* Curve constants for the operation in flight, kept for the next one on the
 * same built-in curve. Caller holds the lock. */
static struct {
    ALIGN32 byte a[ELS_PKC_ECC_MAX_P];
    ALIGN32 byte b[ELS_PKC_ECC_MAX_P];
    ALIGN32 byte p[ELS_PKC_ECC_MAX_P];
    ALIGN32 byte g[2 * ELS_PKC_ECC_MAX_P];
    ALIGN32 byte n[ELS_PKC_ECC_MAX_N];
    const ecc_set_type* set;
} elsPkcCurve;

/* wolfCrypt stores curve constants as hex text; the engine wants fixed-width
 * big-endian octets with leading zeros. */
static int ElsPkcHexToBin(const char* hex, byte* out, word32 len)
{
    mp_int t;
    int ret;

    if (hex == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    ret = mp_init(&t);
    if (ret != 0) {
        return ret;
    }
    ret = mp_read_radix(&t, hex, MP_RADIX_HEX);
    if (ret == 0) {
        ret = mp_to_unsigned_bin_len(&t, out, (int)len);
    }
    mp_clear(&t);

    return ret;
}

/* Marshal a wolfCrypt curve into the engine's parameter block. */
static int ElsPkcLoadCurve(const ecc_key* key, mcuxClEcc_DomainParam_t* dp,
                           word32* lenPOut)
{
    const ecc_set_type* set;
    word32 lenP;
    int ret;

    if (key == NULL || key->dp == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    set  = key->dp;
    lenP = (word32)set->size;
    /* lenP sizes writes into buffers dimensioned by both constants - the order
     * is carried at the prime's width - so it has to respect the smaller. */
    if (lenP == 0 || lenP > ELS_PKC_ECC_MAX_P || lenP > ELS_PKC_ECC_MAX_N) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    if (elsPkcCurve.set == set) {
        goto loaded;
    }
    elsPkcCurve.set = NULL;

    ret = ElsPkcHexToBin(set->Af, elsPkcCurve.a, lenP);
    if (ret == 0) ret = ElsPkcHexToBin(set->Bf,    elsPkcCurve.b, lenP);
    if (ret == 0) ret = ElsPkcHexToBin(set->prime, elsPkcCurve.p, lenP);
    if (ret == 0) ret = ElsPkcHexToBin(set->Gx,    elsPkcCurve.g, lenP);
    if (ret == 0) ret = ElsPkcHexToBin(set->Gy,    elsPkcCurve.g + lenP, lenP);
    /* The order is carried at the prime's width; secp160r1/r2, whose order is
     * a byte longer, fail here and stay in software. */
    if (ret == 0) ret = ElsPkcHexToBin(set->order, elsPkcCurve.n, lenP);
    if (ret != 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    /* Both leading bytes must be nonzero per the engine's contract. */
    if (elsPkcCurve.p[0] == 0 || elsPkcCurve.n[0] == 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    /* Only wolfCrypt's own table entries outlive the call. */
    elsPkcCurve.set = (wc_ecc_get_curve_params(key->idx) == set) ? set : NULL;

loaded:
    dp->pA = elsPkcCurve.a;
    dp->pB = elsPkcCurve.b;
    dp->pP = elsPkcCurve.p;
    dp->pG = elsPkcCurve.g;
    dp->pN = elsPkcCurve.n;
    dp->misc = mcuxClEcc_DomainParam_misc_Pack(lenP, lenP);

    *lenPOut = lenP;

    return 0;
}

#ifdef HAVE_ECC_SIGN

static int ElsPkcEccSignRun(mcuxClSession_Descriptor_t* sess,
                            mcuxClEcc_Sign_Param_t* prm)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEcc_Sign(sess, prm));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_Sign) != t) ||
        (MCUXCLECC_STATUS_OK != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return 0;
}

static int ElsPkcEccSign(const byte* in, word32 inlen, byte* out,
                         word32* outlen, ecc_key* key)
{
    mcuxClSession_Descriptor_t* sess = NULL;
    mcuxClEcc_Sign_Param_t prm;
    ALIGN32 byte priv[ELS_PKC_ECC_MAX_N];
    ALIGN32 byte sig[2 * ELS_PKC_ECC_MAX_N];
    ALIGN32 byte hash[ELS_PKC_ECC_MAX_N];
    word32 lenP = 0, privSz;
    int ret;

    if (in == NULL || out == NULL || outlen == NULL || key == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    /* The digest is copied into a fixed buffer, which bounds this more tightly
     * than the eight-bit byteLenHash field does. */
    if (inlen == 0 || inlen > 255 || inlen > sizeof(hash) ||
        ElsEccCustomNonce(key)) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    ret = ElsPkcLoadCurve(key, &prm.curveParam, &lenP);

    if (ret == 0) {
        privSz = lenP;
#ifdef HAVE_ECC_KEY_EXPORT
        ret = wc_ecc_export_private_only(key, priv, &privSz);
#else
        ret = WC_NO_ERR_TRACE(NOT_COMPILED_IN);
#endif
        if (ret != 0 || privSz != lenP) {
            ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
    }

    if (ret == 0) {
        XMEMCPY(hash, in, inlen);

        prm.pHash       = hash;
        prm.pPrivateKey = priv;
        prm.pSignature  = sig;
        prm.optLen      = mcuxClEcc_Sign_Param_optLen_Pack(inlen);
        prm.pMode       = &mcuxClEcc_ECDSA_ProtocolDescriptor;

        ret = ElsPkcSessionOpen(&sess, lenP > 32u);
        if (ret == 0) {
            ret = ElsPkcEccSignRun(sess, &prm);
            ElsPkcSessionClose(sess, ret == WC_NO_ERR_TRACE(WC_HW_E));
        }
    }

    ElsUnlock();

    if (ret == 0) {
        /* raw R||S out of the engine, DER at the callback boundary */
        ret = StoreECC_DSA_Sig_Bin(out, outlen, sig, lenP, sig + lenP, lenP);
    }

    ForceZero(priv, sizeof(priv));
    ForceZero(hash, sizeof(hash));
    ForceZero(sig, sizeof(sig));

    return ret;
}

#endif /* HAVE_ECC_SIGN */

#ifdef HAVE_ECC_VERIFY

#ifdef WOLFSSL_CUSTOM_CURVES
static int ElsPkcPointMultRun(mcuxClSession_Descriptor_t* sess,
                              mcuxClEcc_PointMult_Param_t* prm)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEcc_PointMult(sess, prm));
    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_PointMult) != t) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    if (MCUXCLECC_STATUS_INVALID_PARAMS == r) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (MCUXCLECC_STATUS_OK != r) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return 0;
}

/* Keyed on the whole domain, since every explicit-parameter curve reports
 * ECC_CURVE_CUSTOM. */
static struct {
    ALIGN32 byte precG[2 * ELS_PKC_ECC_MAX_P];
    byte   dom[5 * ELS_PKC_ECC_MAX_P];  /* p || a || b || G */
    word32 lenP;
    byte   valid;
} elsPkcPrecG;

static void ElsPkcPrecGDomain(const mcuxClEcc_DomainParam_t* dp, word32 lenP,
                              byte* dom)
{
    XMEMCPY(dom, dp->pP, lenP);
    XMEMCPY(dom + lenP, dp->pA, lenP);
    XMEMCPY(dom + 2u * lenP, dp->pB, lenP);
    XMEMCPY(dom + 3u * lenP, dp->pG, 2u * lenP);
}
#endif /* WOLFSSL_CUSTOM_CURVES */

/* PrecG = (2^(byteLenN*4))*G for input verification, under the same guards
 * as ecc.c. A custom curve's is computed. */
typedef struct ElsPkcPrecGEntry {
    int         curveId;
    word32      lenP;
    const byte* precG;
} ElsPkcPrecGEntry;

/* The curve gates of ecc.c's table, which ecc.c keeps private. */
#if (defined(HAVE_ECC112) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 112
    #define ELS_PKC_ECC112
#endif
#if (defined(HAVE_ECC128) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 128
    #define ELS_PKC_ECC128
#endif
#if (defined(HAVE_ECC160) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 160
    #define ELS_PKC_ECC160
#endif
#if (defined(HAVE_ECC192) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 192
    #define ELS_PKC_ECC192
#endif
#if (defined(HAVE_ECC224) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 224
    #define ELS_PKC_ECC224
#endif
#if (defined(HAVE_ECC239) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 239
    #define ELS_PKC_ECC239
#endif
#if (!defined(NO_ECC256) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 256
    #define ELS_PKC_ECC256
#endif
#if (defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 384
    #define ELS_PKC_ECC384
#endif
#if (defined(HAVE_ECC512) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 512
    #define ELS_PKC_ECC512
#endif
#if (defined(HAVE_ECC521) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 521
    #define ELS_PKC_ECC521
#endif

#if defined(ELS_PKC_ECC112) && \
    !defined(NO_ECC_SECP)
static const byte elsPkcPrecGSecp112r1[2 * 14] = {  /* SECP112R1 */
    0xAB, 0x76, 0x6C, 0xBE, 0x5F, 0x14, 0xE7, 0xC7, 0xB4, 0x67, 0x81, 0x12,
    0x7E, 0x03, 0x84, 0xE6, 0xB1, 0xDB, 0x60, 0x93, 0x50, 0x82, 0xDD, 0xAA,
    0x2F, 0x64, 0x1B, 0x51
};
#endif

#if defined(ELS_PKC_ECC128) && \
    !defined(NO_ECC_SECP)
static const byte elsPkcPrecGSecp128r1[2 * 16] = {  /* SECP128R1 */
    0x8A, 0xB9, 0x90, 0x7E, 0x91, 0x28, 0x33, 0xFC, 0x5B, 0x10, 0xF2, 0x01,
    0x40, 0xA6, 0x3E, 0xF0, 0xFA, 0x2F, 0xC2, 0x33, 0x76, 0x21, 0xCE, 0x72,
    0x40, 0x13, 0xDF, 0x3B, 0x6F, 0x3D, 0xCF, 0x65
};
#endif

#if defined(ELS_PKC_ECC160) && \
    defined(HAVE_ECC_BRAINPOOL)
static const byte elsPkcPrecGBrainpoolp160r1[2 * 20] = {  /* BRAINPOOLP160R1 */
    0x8E, 0x63, 0xBD, 0x39, 0x39, 0xFC, 0x8E, 0x94, 0xBB, 0x51, 0x87, 0x25,
    0xD3, 0xB8, 0x21, 0x0C, 0xB1, 0x9B, 0xD5, 0xA1, 0x4D, 0x1E, 0x97, 0x7B,
    0x17, 0xA6, 0x83, 0x90, 0x8E, 0x13, 0x88, 0x36, 0xAF, 0x10, 0x15, 0xA3,
    0x68, 0xDE, 0x44, 0x48
};
#endif

#if defined(ELS_PKC_ECC192) && \
    !defined(NO_ECC_SECP)
static const byte elsPkcPrecGSecp192r1[2 * 24] = {  /* SECP192R1 */
    0x51, 0xA5, 0x81, 0xD9, 0x18, 0x4A, 0xC7, 0x37, 0x47, 0x30, 0xD4, 0xF4,
    0x80, 0xD1, 0x09, 0x0B, 0xB1, 0x99, 0x63, 0xD8, 0xC0, 0xA1, 0xE3, 0x40,
    0x5B, 0xD8, 0x1E, 0xE2, 0xE0, 0xBB, 0x9F, 0x6E, 0x7C, 0xDF, 0xCE, 0xA0,
    0x2F, 0x68, 0x3F, 0x16, 0xEC, 0xC5, 0x67, 0x31, 0xE6, 0x99, 0x12, 0xA5
};
#endif

#if defined(ELS_PKC_ECC192) && \
    defined(HAVE_ECC_SECPR2)
static const byte elsPkcPrecGPrime192v2[2 * 24] = {  /* PRIME192V2 */
    0x0F, 0x81, 0x09, 0x2A, 0xE6, 0x45, 0x5D, 0xB7, 0x6E, 0xC5, 0x18, 0xDC,
    0x04, 0xA6, 0x25, 0x99, 0x88, 0xF9, 0xAE, 0x41, 0xB7, 0xCF, 0x44, 0xC4,
    0xEC, 0xDA, 0xA4, 0x7C, 0x25, 0x27, 0x26, 0x27, 0x1C, 0x40, 0x4C, 0x1B,
    0x55, 0x9C, 0x79, 0x71, 0x13, 0x73, 0xED, 0x13, 0x86, 0xA2, 0x33, 0xD7
};
#endif

#if defined(ELS_PKC_ECC192) && \
    defined(HAVE_ECC_SECPR3)
static const byte elsPkcPrecGPrime192v3[2 * 24] = {  /* PRIME192V3 */
    0x58, 0x27, 0x5C, 0x4B, 0xC2, 0x74, 0xE9, 0x83, 0x6A, 0xCE, 0x2E, 0xDD,
    0xE4, 0x4B, 0xF4, 0x94, 0xBE, 0x8F, 0x86, 0x61, 0x7E, 0x22, 0x02, 0x71,
    0xA0, 0xD8, 0x9C, 0x98, 0x1D, 0x5C, 0x7F, 0xE2, 0xA4, 0x37, 0xAD, 0xB4,
    0xCA, 0x6A, 0x8A, 0x43, 0x42, 0xCC, 0x4D, 0x4C, 0x07, 0x9C, 0xBD, 0x07
};
#endif

#if defined(ELS_PKC_ECC192) && \
    defined(HAVE_ECC_BRAINPOOL)
static const byte elsPkcPrecGBrainpoolp192r1[2 * 24] = {  /* BRAINPOOLP192R1 */
    0x77, 0x3D, 0x02, 0x97, 0x1E, 0x97, 0x2E, 0x92, 0x08, 0x6B, 0x6F, 0x1D,
    0xB5, 0xB5, 0x55, 0x27, 0xB4, 0x00, 0x6C, 0xD5, 0x6E, 0x55, 0x38, 0x4C,
    0x80, 0x7F, 0x61, 0x5C, 0x01, 0xCE, 0x04, 0x88, 0xA3, 0xD9, 0x34, 0x6E,
    0x66, 0x34, 0xC2, 0xCE, 0x32, 0x82, 0x8E, 0x3D, 0x30, 0x14, 0x23, 0x4C
};
#endif

#if defined(ELS_PKC_ECC224) && \
    !defined(NO_ECC_SECP)
static const byte elsPkcPrecGSecp224r1[2 * 28] = {  /* SECP224R1 */
    0x04, 0x99, 0xAA, 0x8A, 0x5F, 0x8E, 0xBE, 0xEF, 0xEC, 0x27, 0xA4, 0xE1,
    0x3A, 0x0B, 0x91, 0xFB, 0x29, 0x91, 0xFA, 0xB0, 0xA0, 0x06, 0x41, 0x96,
    0x6C, 0xAB, 0x26, 0xE3, 0x69, 0x16, 0xF6, 0xD4, 0x33, 0x8C, 0x5B, 0x81,
    0xD7, 0x7A, 0xAE, 0x82, 0xF7, 0x06, 0x84, 0xD9, 0x29, 0x61, 0x0D, 0x54,
    0x50, 0x75, 0x10, 0x40, 0x77, 0x66, 0xAF, 0x5D
};
#endif

#if defined(ELS_PKC_ECC224) && \
    defined(HAVE_ECC_BRAINPOOL)
static const byte elsPkcPrecGBrainpoolp224r1[2 * 28] = {  /* BRAINPOOLP224R1 */
    0xB3, 0xCD, 0xA5, 0xBC, 0x06, 0x99, 0xB4, 0xA5, 0xD7, 0xC8, 0x4B, 0x0E,
    0xEE, 0x59, 0x10, 0x79, 0x61, 0x9F, 0x1D, 0x35, 0x79, 0x4A, 0xDD, 0x48,
    0x18, 0x67, 0x1C, 0xAC, 0xBC, 0x2D, 0xC0, 0x34, 0xFE, 0xF3, 0x2E, 0x40,
    0xD6, 0xD7, 0x50, 0xA1, 0x3B, 0x07, 0xA6, 0x8C, 0x4D, 0x88, 0xB7, 0x67,
    0x6E, 0x60, 0x80, 0xC1, 0xBB, 0x4A, 0x54, 0x47
};
#endif

#if defined(ELS_PKC_ECC239) && \
    !defined(NO_ECC_SECP)
static const byte elsPkcPrecGPrime239v1[2 * 30] = {  /* PRIME239V1 */
    0x35, 0xFE, 0x64, 0x2B, 0x09, 0x5F, 0x1E, 0x6F, 0x16, 0x04, 0xB1, 0x6F,
    0x77, 0x69, 0x34, 0x3A, 0xEC, 0x0F, 0xEE, 0x90, 0x4B, 0xCB, 0xE7, 0x45,
    0xC8, 0xDE, 0x0B, 0xDF, 0xE2, 0x69, 0x02, 0xA1, 0x73, 0x21, 0xBF, 0x3F,
    0x1A, 0xA0, 0xE4, 0xF1, 0x9B, 0xBA, 0x3B, 0xE4, 0xB2, 0xC6, 0xE0, 0x69,
    0xF5, 0x47, 0x9F, 0x56, 0xA9, 0xE7, 0x67, 0x9F, 0xD8, 0xC7, 0xE7, 0x08
};
#endif

#if defined(ELS_PKC_ECC239) && \
    defined(HAVE_ECC_SECPR2)
static const byte elsPkcPrecGPrime239v2[2 * 30] = {  /* PRIME239V2 */
    0x2C, 0xCE, 0xC8, 0x07, 0x91, 0xF3, 0x58, 0x99, 0x5E, 0x55, 0x43, 0x3E,
    0xCC, 0x2F, 0x82, 0xDF, 0x31, 0x9C, 0x29, 0x01, 0x4A, 0x0C, 0x27, 0x27,
    0x74, 0x9F, 0xB5, 0xB4, 0xB0, 0x5C, 0x34, 0x95, 0xBC, 0x6F, 0xA7, 0x7E,
    0xBC, 0x6A, 0x5F, 0x16, 0x02, 0x27, 0xB5, 0xD2, 0x35, 0xFB, 0x51, 0x68,
    0x1A, 0x74, 0x1D, 0xBF, 0xBE, 0xC2, 0x37, 0x43, 0xBE, 0x34, 0x3B, 0x70
};
#endif

#if defined(ELS_PKC_ECC239) && \
    defined(HAVE_ECC_SECPR3)
static const byte elsPkcPrecGPrime239v3[2 * 30] = {  /* PRIME239V3 */
    0x09, 0x69, 0x0E, 0xBA, 0xDD, 0xAE, 0xC9, 0x1E, 0xF0, 0x96, 0xA4, 0x9C,
    0x6D, 0x77, 0xD3, 0x2D, 0x5C, 0x81, 0x03, 0x5A, 0xC2, 0x8D, 0xEB, 0x75,
    0xD1, 0x22, 0xB3, 0x09, 0x86, 0x7E, 0x11, 0x6C, 0xDA, 0x12, 0xDE, 0x47,
    0xAA, 0x2C, 0x94, 0x5E, 0x29, 0xB2, 0x3B, 0x05, 0xCF, 0x19, 0xAC, 0xC2,
    0x3D, 0x82, 0xBF, 0xAC, 0x51, 0x06, 0x9D, 0x97, 0xB7, 0x0F, 0xDD, 0xF4
};
#endif

#if defined(ELS_PKC_ECC256) && \
    !defined(NO_ECC_SECP)
static const byte elsPkcPrecGSecp256r1[2 * 32] = {  /* SECP256R1 */
    0x44, 0x7D, 0x73, 0x9B, 0xEE, 0xDB, 0x5E, 0x67, 0xFB, 0x98, 0x2F, 0xD5,
    0x88, 0xC6, 0x76, 0x6E, 0xFC, 0x35, 0xFF, 0x7D, 0xC2, 0x97, 0xEA, 0xC3,
    0x57, 0xC8, 0x4F, 0xC9, 0xD7, 0x89, 0xBD, 0x85, 0x2D, 0x48, 0x25, 0xAB,
    0x83, 0x41, 0x31, 0xEE, 0xE1, 0x2E, 0x9D, 0x95, 0x3A, 0x4A, 0xAF, 0xF7,
    0x3D, 0x34, 0x9B, 0x95, 0xA7, 0xFA, 0xE5, 0x00, 0x0C, 0x7E, 0x33, 0xC9,
    0x72, 0xE2, 0x5B, 0x32
};
#endif

#if defined(ELS_PKC_ECC256) && \
    defined(HAVE_ECC_BRAINPOOL)
static const byte elsPkcPrecGBrainpoolp256r1[2 * 32] = {  /* BRAINPOOLP256R1 */
    0x4A, 0x14, 0xC0, 0x30, 0x3B, 0x85, 0x6C, 0x94, 0xB4, 0x43, 0x85, 0x11,
    0x7F, 0x87, 0xED, 0x9D, 0x12, 0x00, 0xCA, 0x9B, 0x11, 0x00, 0x65, 0x90,
    0xEB, 0x6B, 0x65, 0x1C, 0xF5, 0x84, 0x72, 0xC9, 0x7B, 0x81, 0xE4, 0x70,
    0xDA, 0xE2, 0xD5, 0xEF, 0xE6, 0x38, 0x73, 0x49, 0x8B, 0x47, 0xCC, 0x5E,
    0xD5, 0x44, 0xA0, 0x68, 0xCD, 0x73, 0x21, 0x17, 0x52, 0x9C, 0x5C, 0xD6,
    0x28, 0xF8, 0x52, 0xD1
};
#endif

#if (defined(WOLFSSL_SM2))
static const byte elsPkcPrecGSm2p256v1[2 * 32] = {  /* SM2P256V1 */
    0xB6, 0x92, 0xE5, 0xB5, 0x74, 0xD5, 0x5D, 0xA9, 0x3D, 0xB7, 0xB2, 0x48,
    0x88, 0xC2, 0x1F, 0x3A, 0x2B, 0x23, 0x08, 0xF6, 0x48, 0x4E, 0x1B, 0x38,
    0xEA, 0xE3, 0xD9, 0xA9, 0xD1, 0x3A, 0x42, 0xED, 0xA1, 0x75, 0x05, 0x1B,
    0x0F, 0x3F, 0xB6, 0x13, 0x5A, 0x92, 0x4F, 0x85, 0x54, 0x49, 0x26, 0xF9,
    0xDB, 0x61, 0xAC, 0x17, 0x73, 0x43, 0x8E, 0x6D, 0xD1, 0x86, 0x46, 0x9D,
    0xE2, 0x95, 0xE5, 0xAB
};
#endif

#if defined(ELS_PKC_ECC384) && \
    !defined(NO_ECC_SECP)
static const byte elsPkcPrecGSecp384r1[2 * 48] = {  /* SECP384R1 */
    0xC1, 0x9E, 0x0B, 0x4C, 0x80, 0x01, 0x19, 0xC4, 0x40, 0xF7, 0xF9, 0xE7,
    0x06, 0x42, 0x12, 0x79, 0xB4, 0x2A, 0x31, 0xAF, 0x8A, 0x3E, 0x29, 0x7D,
    0xDB, 0x29, 0x87, 0x89, 0x4D, 0x10, 0xDD, 0xEA, 0xBA, 0x06, 0x54, 0x58,
    0xA4, 0xF5, 0x2D, 0x78, 0xA6, 0x28, 0xB0, 0x9A, 0xAA, 0x03, 0xBD, 0x53,
    0x16, 0xF3, 0xFD, 0xBF, 0x03, 0x56, 0xB3, 0x01, 0xE5, 0xA0, 0x19, 0x1D,
    0x1F, 0x5B, 0x77, 0xF6, 0x57, 0x7A, 0x30, 0xEA, 0xE3, 0x56, 0x7A, 0xF9,
    0xC1, 0xC7, 0xCA, 0xD1, 0x35, 0xF6, 0xEB, 0xF2, 0xAF, 0x68, 0xAA, 0x6D,
    0xE6, 0x39, 0xD8, 0x58, 0x82, 0x2D, 0x0F, 0xC5, 0xE6, 0xC8, 0x8C, 0x41
};
#endif

#if defined(ELS_PKC_ECC384) && \
    defined(HAVE_ECC_BRAINPOOL)
static const byte elsPkcPrecGBrainpoolp384r1[2 * 48] = {  /* BRAINPOOLP384R1 */
    0x23, 0x69, 0xDB, 0xB6, 0x39, 0x7C, 0x99, 0xF1, 0x89, 0x74, 0xB5, 0x68,
    0x8E, 0x81, 0xAF, 0x98, 0xDF, 0x4D, 0xDA, 0xCC, 0xBB, 0x1F, 0xDC, 0x04,
    0xE1, 0x8A, 0x5D, 0x2D, 0x02, 0xC7, 0xF7, 0x27, 0x02, 0xA3, 0x53, 0xBC,
    0x53, 0x45, 0xA9, 0x46, 0x6B, 0xF5, 0x50, 0xB0, 0x4D, 0x99, 0x4B, 0x04,
    0x6F, 0x47, 0xB1, 0x1D, 0xAA, 0x3B, 0x12, 0x4F, 0x93, 0xB0, 0x87, 0x75,
    0x92, 0x5F, 0xF0, 0xA8, 0x12, 0x73, 0x68, 0xF1, 0x07, 0x42, 0xFA, 0x8F,
    0xCD, 0x41, 0xCA, 0xE9, 0x33, 0x34, 0xCE, 0x66, 0x43, 0xF1, 0x43, 0xE6,
    0x50, 0x0C, 0xB2, 0xC1, 0x0E, 0xE1, 0x88, 0xBB, 0x14, 0x50, 0x4C, 0x85
};
#endif

#if defined(ELS_PKC_ECC512) && \
    defined(HAVE_ECC_BRAINPOOL)
static const byte elsPkcPrecGBrainpoolp512r1[2 * 64] = {  /* BRAINPOOLP512R1 */
    0x7B, 0x59, 0x13, 0xF7, 0x66, 0xC4, 0xED, 0x95, 0xD5, 0x26, 0x2C, 0xE1,
    0xB8, 0xF1, 0xB2, 0xAF, 0xC0, 0x56, 0xFD, 0x65, 0x8F, 0x28, 0x48, 0x70,
    0x79, 0xA8, 0x3D, 0x9B, 0x94, 0x5E, 0x84, 0x60, 0x1B, 0xAE, 0x0F, 0x47,
    0xAC, 0xA3, 0xB9, 0x4E, 0x97, 0x50, 0x2F, 0x33, 0x73, 0x0A, 0x37, 0x21,
    0x9D, 0x18, 0x9C, 0x54, 0x08, 0xAC, 0x7D, 0xA5, 0xCA, 0x44, 0x81, 0x27,
    0xEF, 0x66, 0xEF, 0xB5, 0x3B, 0x4D, 0x8E, 0x45, 0x4F, 0xFC, 0x59, 0x3A,
    0x37, 0x27, 0xEA, 0x1E, 0xEA, 0x20, 0xB7, 0x08, 0xC2, 0x1F, 0xCA, 0x91,
    0x61, 0x30, 0x6A, 0xF0, 0xE4, 0x66, 0x56, 0xA7, 0x5F, 0xC4, 0x50, 0xA8,
    0xFB, 0x4E, 0xDB, 0x0D, 0xBC, 0x57, 0x88, 0x77, 0x24, 0xEC, 0x6F, 0x84,
    0x4E, 0xB4, 0x96, 0xC3, 0x3E, 0x94, 0x70, 0xF8, 0xDA, 0x00, 0x92, 0xC9,
    0xD6, 0x10, 0x45, 0x3C, 0xC2, 0xF4, 0x58, 0x72
};
#endif

#if defined(ELS_PKC_ECC521) && \
    !defined(NO_ECC_SECP)
static const byte elsPkcPrecGSecp521r1[2 * 66] = {  /* SECP521R1 */
    0x00, 0x8E, 0x81, 0x8D, 0x28, 0xF3, 0x81, 0xD8, 0xB2, 0x05, 0xED, 0xFF,
    0x69, 0x61, 0x3B, 0x96, 0x2E, 0x0C, 0x77, 0xD2, 0x23, 0xEF, 0x25, 0xCC,
    0x1C, 0x99, 0xD9, 0xA6, 0x2E, 0x4F, 0x25, 0x72, 0xC1, 0x61, 0x7A, 0xD0,
    0xF5, 0xE9, 0xA8, 0x6B, 0x71, 0x04, 0xE8, 0x97, 0x00, 0xD4, 0xDA, 0x71,
    0x3C, 0xB4, 0x08, 0xF3, 0xDE, 0x44, 0x65, 0xF8, 0x6A, 0xC4, 0xEE, 0x31,
    0xE7, 0x1A, 0x28, 0x64, 0x92, 0xAD, 0x01, 0x3E, 0xFD, 0xBC, 0x85, 0x6E,
    0x8F, 0x68, 0xBF, 0x44, 0xD4, 0xE1, 0x9F, 0xC7, 0xC3, 0x26, 0xFE, 0x48,
    0xA1, 0x6F, 0x78, 0x55, 0xC8, 0x08, 0x66, 0x23, 0x71, 0x96, 0xBF, 0x8F,
    0x72, 0xEA, 0x0D, 0xCB, 0x42, 0x22, 0x85, 0xDC, 0x03, 0x70, 0x68, 0x9F,
    0xBE, 0x72, 0x6F, 0x8C, 0xE0, 0x45, 0xA4, 0x03, 0x8B, 0x64, 0x0F, 0x2B,
    0x67, 0x17, 0x76, 0x0F, 0x72, 0x12, 0x31, 0xCF, 0x8C, 0xDF, 0x1F, 0x60
};
#endif

static const ElsPkcPrecGEntry elsPkcPrecGTable[] = {
#if defined(ELS_PKC_ECC112) && \
    !defined(NO_ECC_SECP)
    { ECC_SECP112R1, 14, elsPkcPrecGSecp112r1 },
#endif
#if defined(ELS_PKC_ECC128) && \
    !defined(NO_ECC_SECP)
    { ECC_SECP128R1, 16, elsPkcPrecGSecp128r1 },
#endif
#if defined(ELS_PKC_ECC160) && \
    defined(HAVE_ECC_BRAINPOOL)
    { ECC_BRAINPOOLP160R1, 20, elsPkcPrecGBrainpoolp160r1 },
#endif
#if defined(ELS_PKC_ECC192) && \
    !defined(NO_ECC_SECP)
    { ECC_SECP192R1, 24, elsPkcPrecGSecp192r1 },
#endif
#if defined(ELS_PKC_ECC192) && \
    defined(HAVE_ECC_SECPR2)
    { ECC_PRIME192V2, 24, elsPkcPrecGPrime192v2 },
#endif
#if defined(ELS_PKC_ECC192) && \
    defined(HAVE_ECC_SECPR3)
    { ECC_PRIME192V3, 24, elsPkcPrecGPrime192v3 },
#endif
#if defined(ELS_PKC_ECC192) && \
    defined(HAVE_ECC_BRAINPOOL)
    { ECC_BRAINPOOLP192R1, 24, elsPkcPrecGBrainpoolp192r1 },
#endif
#if defined(ELS_PKC_ECC224) && \
    !defined(NO_ECC_SECP)
    { ECC_SECP224R1, 28, elsPkcPrecGSecp224r1 },
#endif
#if defined(ELS_PKC_ECC224) && \
    defined(HAVE_ECC_BRAINPOOL)
    { ECC_BRAINPOOLP224R1, 28, elsPkcPrecGBrainpoolp224r1 },
#endif
#if defined(ELS_PKC_ECC239) && \
    !defined(NO_ECC_SECP)
    { ECC_PRIME239V1, 30, elsPkcPrecGPrime239v1 },
#endif
#if defined(ELS_PKC_ECC239) && \
    defined(HAVE_ECC_SECPR2)
    { ECC_PRIME239V2, 30, elsPkcPrecGPrime239v2 },
#endif
#if defined(ELS_PKC_ECC239) && \
    defined(HAVE_ECC_SECPR3)
    { ECC_PRIME239V3, 30, elsPkcPrecGPrime239v3 },
#endif
#if defined(ELS_PKC_ECC256) && \
    !defined(NO_ECC_SECP)
    { ECC_SECP256R1, 32, elsPkcPrecGSecp256r1 },
#endif
#if defined(ELS_PKC_ECC256) && \
    defined(HAVE_ECC_BRAINPOOL)
    { ECC_BRAINPOOLP256R1, 32, elsPkcPrecGBrainpoolp256r1 },
#endif
#if (defined(WOLFSSL_SM2))
    { ECC_SM2P256V1, 32, elsPkcPrecGSm2p256v1 },
#endif
#if defined(ELS_PKC_ECC384) && \
    !defined(NO_ECC_SECP)
    { ECC_SECP384R1, 48, elsPkcPrecGSecp384r1 },
#endif
#if defined(ELS_PKC_ECC384) && \
    defined(HAVE_ECC_BRAINPOOL)
    { ECC_BRAINPOOLP384R1, 48, elsPkcPrecGBrainpoolp384r1 },
#endif
#if defined(ELS_PKC_ECC512) && \
    defined(HAVE_ECC_BRAINPOOL)
    { ECC_BRAINPOOLP512R1, 64, elsPkcPrecGBrainpoolp512r1 },
#endif
#if defined(ELS_PKC_ECC521) && \
    !defined(NO_ECC_SECP)
    { ECC_SECP521R1, 66, elsPkcPrecGSecp521r1 },
#endif
    { ECC_CURVE_INVALID, 0, NULL }  /* terminator, and keeps it non-empty */
};

/* Point at the value for this curve, deriving it only for a curve the table
 * does not carry. Caller holds the lock and has loaded the curve. */
static int ElsPkcPrecGet(mcuxClSession_Descriptor_t* sess,
                         const mcuxClEcc_DomainParam_t* dp, int curveId,
                         word32 lenP, const byte** precG)
{
    int i;
#ifdef WOLFSSL_CUSTOM_CURVES
    mcuxClEcc_PointMult_Param_t prm;
    ALIGN32 byte scalar[ELS_PKC_ECC_MAX_N];
    byte dom[5 * ELS_PKC_ECC_MAX_P];
    int ret;
#endif

    for (i = 0; elsPkcPrecGTable[i].precG != NULL; i++) {
        if (elsPkcPrecGTable[i].curveId == curveId &&
            elsPkcPrecGTable[i].lenP == lenP) {
            *precG = elsPkcPrecGTable[i].precG;
            return 0;
        }
    }

#ifdef WOLFSSL_CUSTOM_CURVES
    ElsPkcPrecGDomain(dp, lenP, dom);
    if (elsPkcPrecG.valid && elsPkcPrecG.lenP == lenP &&
        XMEMCMP(elsPkcPrecG.dom, dom, 5u * lenP) == 0) {
        *precG = elsPkcPrecG.precG;
        return 0;
    }
    elsPkcPrecG.valid = 0;
    /* The exponent byteLenN*4 is half the order's bit width, so the single set
     * bit lands halfway through the scalar. Even byte lengths only. */
    if ((lenP & 1u) != 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    XMEMSET(scalar, 0, sizeof(scalar));
    scalar[lenP / 2u - 1u] = 0x01;

    prm.curveParam = *dp;
    prm.pScalar    = scalar;
    prm.pPoint     = dp->pG;
    prm.pResult    = elsPkcPrecG.precG;
    prm.optLen     = 0u;

    ret = ElsPkcPointMultRun(sess, &prm);
    if (ret == 0) {
        XMEMCPY(elsPkcPrecG.dom, dom, 5u * lenP);
        elsPkcPrecG.lenP  = lenP;
        elsPkcPrecG.valid = 1;
        *precG = elsPkcPrecG.precG;
    }

    return ret;
#else
    (void)sess;
    (void)dp;

    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
#endif
}

static int ElsPkcEccVerifyRun(mcuxClSession_Descriptor_t* sess,
                              mcuxClEcc_Verify_Param_t* prm, int* res)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEcc_Verify(sess, prm));
    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_Verify) != t) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    /* The PKC reports a bad signature through INVALID_SIGNATURE. */
    if (MCUXCLECC_STATUS_OK == r) {
        *res = 1;
    }
    else if (MCUXCLECC_STATUS_INVALID_SIGNATURE == r) {
        *res = 0;
    }
    /* An off-curve public key; software gives its own answer for one. */
    else if (MCUXCLECC_STATUS_INVALID_PARAMS == r) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    else {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return 0;
}

static int ElsPkcEccVerify(const byte* sigDer, word32 sigLen,
                           const byte* digest, word32 hashLen, int* res,
                           ecc_key* key)
{
    mcuxClSession_Descriptor_t* sess = NULL;
    mcuxClEcc_Verify_Param_t prm;
    ALIGN32 byte sig[2 * ELS_PKC_ECC_MAX_N];
    ALIGN32 byte hash[ELS_PKC_ECC_MAX_N];
    ALIGN32 byte pub[2 * ELS_PKC_ECC_MAX_P];
    ALIGN32 byte rOut[ELS_PKC_ECC_MAX_N];
    byte   x963[1 + 2 * ELS_PKC_ECC_MAX_P];
    const byte* precG = NULL;
    word32 x963Sz = sizeof(x963);
    word32 lenP = 0, rLen, sLen;
    int    ret;

    if (sigDer == NULL || digest == NULL || res == NULL || key == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    /* As in the signer: the fixed buffer bounds this more tightly than the
     * eight-bit byteLenHash field does. */
    if (hashLen == 0 || hashLen > 255 || hashLen > sizeof(hash) ||
        !ElsEccSigDerOk(sigDer, sigLen)) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    *res = 0;

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    ret = ElsPkcLoadCurve(key, &prm.curveParam, &lenP);

    if (ret == 0) {
        rLen = lenP;
        sLen = lenP;
        if (DecodeECC_DSA_Sig_Bin(sigDer, sigLen, sig, &rLen,
                                  sig + lenP, &sLen) != 0) {
            ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
        if (ret == 0) {
            ret = ElsPadSigComponent(sig, rLen, lenP);
        }
        if (ret == 0) {
            ret = ElsPadSigComponent(sig + lenP, sLen, lenP);
        }
        if (ret == 0) {
            ret = ElsEccSigRange(sig, elsPkcCurve.n, lenP);
        }
    }

    if (ret == 0) {
#ifdef HAVE_ECC_KEY_EXPORT
        ret = wc_ecc_export_x963_ex(key, x963, &x963Sz, 0);
#else
        ret = WC_NO_ERR_TRACE(NOT_COMPILED_IN);
#endif
        if (ret != 0 || x963Sz != (1u + 2u * lenP) || x963[0] != 0x04) {
            ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
        else {
            XMEMCPY(pub, x963 + 1, 2u * lenP);
        }
    }

    if (ret == 0) {
        XMEMCPY(hash, digest, hashLen);
        /* Verify consumes no nonce, so it never needs the 256-bit DRBG. */
        ret = ElsPkcSessionOpen(&sess, 0);
        if (ret == 0) {
            ret = ElsPkcPrecGet(sess, &prm.curveParam, key->dp->id, lenP,
                                &precG);
            if (ret == 0) {
                prm.pPrecG     = precG;
                prm.pHash      = hash;
                prm.pSignature = sig;
                prm.pPublicKey = pub;
                prm.pOutputR   = rOut;
                prm.optLen     = mcuxClEcc_Verify_Param_optLen_Pack(hashLen);

                ret = ElsPkcEccVerifyRun(sess, &prm, res);
            }
            ElsPkcSessionClose(sess, ret == WC_NO_ERR_TRACE(WC_HW_E));
        }
    }

    ElsUnlock();

    ForceZero(hash, sizeof(hash));
    ForceZero(rOut, sizeof(rOut));

    return ret;
}

#endif /* HAVE_ECC_VERIFY */
#endif /* HAVE_ECC && (HAVE_ECC_SIGN || HAVE_ECC_VERIFY) */

/* These calls name two slots rather than one, and a permission mistake resets
 * the SoC, so both references are validated against the hardware first. */

#ifdef WOLF_CRYPTO_CB_KEYSTORE

/* The container is the key plus an 8-byte property/padding prefix, all inside
 * an RFC 3394 wrap that adds its own 8-byte integrity block. */
#define ELS_KS_BLOB_SZ(keySz) ((word32)(keySz) + 16u)

/* ELS derives with a fixed-width label/context block. */
#define ELS_KS_DERIV_SZ MCUXCLELS_CKDF_DERIVATIONDATA_SIZE

/* A slot holds 128 bits; a 256-bit key spans the pair. */
#define ELS_KS_KEY_128_SZ 16u
#define ELS_KS_KEY_256_SZ 32u

/* NXP_DIE_INT_MK_SK, the die unique key the ROM leaves in slots 0 and 1. */
#define ELS_DIE_INT_MK_SLOT 0
#define ELS_DIE_INT_MK_PROPS (MCUXCLELS_KEYPROPERTY_VALUE_ACTIVE | \
                              MCUXCLELS_KEYPROPERTY_VALUE_CKDF | \
                              MCUXCLELS_KEYPROPERTY_VALUE_DUK)

/* SP800-108 derivation data for NXP_DIE_KEK_SK, published by NXP. */
static const byte elsDieKekDeriv[ELS_KS_DERIV_SZ] = {
    0x94, 0xbe, 0x03, 0xac, 0x8b, 0x59, 0x32, 0x45, 0x11, 0x7f, 0xf8, 0x3f
};

/* Map a stored key's ELS properties onto the facility's vocabulary. */
static word32 ElsKsTypeFromProp(const mcuxClEls_KeyProp_t* prop)
{
    if (prop->word.value & MCUXCLELS_KEYPROPERTY_VALUE_ECSGN) {
        return WC_KEYSTORE_KEY_ECC_SIGN;
    }
    if (prop->word.value & MCUXCLELS_KEYPROPERTY_VALUE_ECDH) {
        return WC_KEYSTORE_KEY_ECC_DH;
    }
    if (prop->word.value & MCUXCLELS_KEYPROPERTY_VALUE_HMAC) {
        return WC_KEYSTORE_KEY_HMAC;
    }
    if (prop->word.value & MCUXCLELS_KEYPROPERTY_VALUE_CMAC) {
        return WC_KEYSTORE_KEY_CMAC;
    }
    if (prop->word.value & MCUXCLELS_KEYPROPERTY_VALUE_AES) {
        return WC_KEYSTORE_KEY_AES;
    }
    /* A slot that also wraps is reported by what it computes. */
    if (prop->word.value & (MCUXCLELS_KEYPROPERTY_VALUE_KWK |
                            MCUXCLELS_KEYPROPERTY_VALUE_KUOK)) {
        return WC_KEYSTORE_KEY_WRAP;
    }
    if (prop->word.value & (MCUXCLELS_KEYPROPERTY_VALUE_CKDF |
                            MCUXCLELS_KEYPROPERTY_VALUE_HKDF |
                            MCUXCLELS_KEYPROPERTY_VALUE_KGSRC)) {
        return WC_KEYSTORE_KEY_DERIVE;
    }

    return WC_KEYSTORE_KEY_NONE;
}

/* The facility's key type for a reference's class. */
static word32 ElsKsTypeFromClass(byte keyClass)
{
    switch (keyClass) {
        case WC_ELSPKC_KEY_ECC_SIGN: return WC_KEYSTORE_KEY_ECC_SIGN;
        case WC_ELSPKC_KEY_ECC_DH:   return WC_KEYSTORE_KEY_ECC_DH;
        case WC_ELSPKC_KEY_AES:      return WC_KEYSTORE_KEY_AES;
        case WC_ELSPKC_KEY_HMAC:     return WC_KEYSTORE_KEY_HMAC;
        case WC_ELSPKC_KEY_CMAC:     return WC_KEYSTORE_KEY_CMAC;
        case WC_ELSPKC_KEY_KWK:      return WC_KEYSTORE_KEY_WRAP;
        case WC_ELSPKC_KEY_CKDF:     /* fall through */
        case WC_ELSPKC_KEY_HKDF:     /* fall through */
        case WC_ELSPKC_KEY_ECC_SEED: return WC_KEYSTORE_KEY_DERIVE;
        default:                     return WC_KEYSTORE_KEY_NONE;
    }
}

/* Check the caller's stated keyType against what the target reference names.
 * WC_KEYSTORE_KEY_NONE is unspecified, not a claim to disagree with. */
static int ElsKsCheckType(word32 keyType, byte keyClass)
{
    if (keyType == WC_KEYSTORE_KEY_NONE) {
        return 0;
    }
    if (keyType != ElsKsTypeFromClass(keyClass)) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }

    return 0;
}

/* Key size in bits, from the two-bit size field. */
static word32 ElsKsBitsFromProp(const mcuxClEls_KeyProp_t* prop)
{
    /* The 512-bit encoding only exists on parts with an internal public-key
     * store; elsewhere the field holds 128 or 256 and nothing else. */
    switch (prop->word.value & 0x3u) {
        case MCUXCLELS_KEYPROPERTY_VALUE_KEY_SIZE_128:
            return 128;
        case MCUXCLELS_KEYPROPERTY_VALUE_KEY_SIZE_256:
            return 256;
#ifdef MCUXCL_FEATURE_ELS_PUK_INTERNAL
        case MCUXCLELS_KEYPROPERTY_VALUE_KEY_SIZE_512:
            return 512;
#endif
        default:
            return 0;
    }
}

/* Find room for a new key: only the active bit is a safe test, and a
 * 256-bit key needs a pair. Advisory. */
int wc_ElsPkc_ReserveSlot(byte keyClass, word32 keySz, wc_ElsPkc_KeyRef* ref)
{
    mcuxClEls_KeyProp_t prop;
    int isEcc;
    int need;
    int run = 0;
    int slot;
    int ret;

    if (ref == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    if (ElsClassUsageBit(keyClass) == 0) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    isEcc = (keyClass == WC_ELSPKC_KEY_ECC_SIGN ||
             keyClass == WC_ELSPKC_KEY_ECC_DH ||
             keyClass == WC_ELSPKC_KEY_ECC_SEED);
    if ((keySz != 0 && keySz != ELS_KS_KEY_128_SZ &&
         keySz != ELS_KS_KEY_256_SZ) ||
        (isEcc && keySz == ELS_KS_KEY_128_SZ)) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    /* ECC keys and seeds are 256 bits, so always a pair; every other class
     * follows the size, which is why the caller has to state it. */
    need = (isEcc || keySz == ELS_KS_KEY_256_SZ) ? 2 : 1;

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    for (slot = 0; slot <= WC_ELSPKC_MAX_SLOT; slot++) {
        ret = ElsKsProps((byte)slot, &prop);
        if (ret != 0) {
            break;
        }
        if (prop.word.value & MCUXCLELS_KEYPROPERTY_VALUE_ACTIVE) {
            run = 0;
            continue;
        }
        /* Slots 0 and 1 are retention and slot 2 is hardware-out. */
        if ((prop.word.value &
             MCUXCLELS_KEYPROPERTY_VALUE_GENERAL_PURPOSE_SLOT) == 0) {
            run = 0;
            continue;
        }
        if (++run == need) {
            XMEMSET(ref, 0, sizeof(*ref));
            ref->keyClass = keyClass;
            ref->slot     = (byte)(slot - (need - 1));
            ElsUnlock();
            return 0;
        }
    }

    ElsUnlock();

    return (ret == 0) ? WC_NO_ERR_TRACE(MEMORY_E) : ret;
}

/* Parse a reference and, when it must already exist, confirm the slot carries
 * the permission its class claims. */
static int ElsKsRef(const byte* ref, word32 refSz, byte expectClass,
                    int mustExist, wc_ElsPkc_KeyRef* out)
{
    int ret = wc_ElsPkc_ParseKeyRef(ref, refSz, out);

    if (ret != 0) {
        return ret;
    }
    if (out->keyClass != expectClass) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }

    return mustExist ? ElsCheckSlot(out, expectClass) : 0;
}

/* ukwk both wraps and unwraps, ukuok only unwraps, so an export needs more
 * than an import does - the point of an unwrap-only key. */
static int ElsKsWrapRef(const byte* ref, word32 refSz, int needWrap,
                        wc_ElsPkc_KeyRef* out)
{
    mcuxClEls_KeyProp_t prop;
    int ret = wc_ElsPkc_ParseKeyRef(ref, refSz, out);

    if (ret == 0 && out->keyClass != WC_ELSPKC_KEY_KWK) {
        ret = WC_NO_ERR_TRACE(BAD_STATE_E);
    }
    if (ret == 0) {
        ret = ElsKsProps(out->slot, &prop);
    }
    if (ret == 0 && (!ElsSlotHolds(&prop, WC_ELSPKC_KEY_KWK) ||
            (needWrap &&
             (prop.word.value & MCUXCLELS_KEYPROPERTY_VALUE_KWK) == 0))) {
        ret = WC_NO_ERR_TRACE(BAD_STATE_E);
    }

    return ret;
}

static int ElsKsImportRun(const byte* blob, word32 blobSz, byte wrapSlot,
                          byte targetSlot)
{
    mcuxClEls_KeyImportOption_t opt;

    opt.word.value = 0u;
    opt.bits.kfmt  = MCUXCLELS_KEYIMPORT_KFMT_RFC3394;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEls_KeyImport_Async(
        opt, blob, (size_t)blobSz, (mcuxClEls_KeyIndex_t)wrapSlot,
        (mcuxClEls_KeyIndex_t)targetSlot));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_KeyImport_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return ElsWait();
}

static int ElsKsExportRun(byte wrapSlot, byte keySlot, byte* out)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEls_KeyExport_Async(
        (mcuxClEls_KeyIndex_t)wrapSlot, (mcuxClEls_KeyIndex_t)keySlot, out));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_KeyExport_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return ElsWait();
}

static int ElsKsDeriveRun(byte srcSlot, byte targetSlot,
                          mcuxClEls_KeyProp_t prop, const byte* deriv)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEls_Ckdf_Sp800108_Async(
        (mcuxClEls_KeyIndex_t)srcSlot, (mcuxClEls_KeyIndex_t)targetSlot,
        prop, deriv));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Ckdf_Sp800108_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return ElsWait();
}

/* Check the imported key carries the target class's permission. Caller holds
 * the lock. */
static int ElsKsImportCheck(const wc_ElsPkc_KeyRef* target)
{
    mcuxClEls_KeyProp_t prop;
    int ret;

    ret = ElsKsProps(target->slot, &prop);
    if (ret == 0 && !ElsSlotHolds(&prop, target->keyClass)) {
        ret = WC_NO_ERR_TRACE(BAD_STATE_E);
    }

    return ret;
}

static int ElsKsImport(wc_CryptoInfo* info)
{
    wc_ElsPkc_KeyRef target, wrap;
    int ret;

    if (info->keystore.op.importWrapped.blob == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    /* Only this container shape. A bare RFC 3394 blob has no property word,
     * so ELS would have nothing to set the imported key's permissions from. */
    if (info->keystore.op.importWrapped.format != WC_KEYWRAP_FORMAT_VENDOR) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (info->keystore.op.importWrapped.blobSz != ELS_KS_BLOB_SZ(16) &&
        info->keystore.op.importWrapped.blobSz != ELS_KS_BLOB_SZ(32)) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    /* The target need not exist yet - that is the point of an import - so its
     * reference is parsed but not checked against the hardware. */
    ret = wc_ElsPkc_ParseKeyRef(info->keystore.op.importWrapped.keyRef,
                                info->keystore.op.importWrapped.keyRefSz,
                                &target);
    if (ret == 0) {
        /* The container's property word sets the type; this catches a blob
         * aimed at a reference of another class before the unwrap. */
        ret = ElsKsCheckType(info->keystore.op.importWrapped.keyType,
                             target.keyClass);
    }
    /* Every ECC key is 256 bits. */
    if (ret == 0 && (target.keyClass == WC_ELSPKC_KEY_ECC_SIGN ||
                     target.keyClass == WC_ELSPKC_KEY_ECC_DH ||
                     target.keyClass == WC_ELSPKC_KEY_ECC_SEED) &&
        info->keystore.op.importWrapped.blobSz !=
            ELS_KS_BLOB_SZ(ELS_KS_KEY_256_SZ)) {
        ret = WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    /* attrs is unused; the property word inside the container decides. */
    if (ret == 0) {
        ret = ElsKsWrapRef(info->keystore.op.importWrapped.wrapKeyRef,
                           info->keystore.op.importWrapped.wrapKeyRefSz,
                           0, &wrap);
    }
    /* The container size gives the slot count. */
    if (ret == 0) {
        ret = (info->keystore.op.importWrapped.blobSz ==
               ELS_KS_BLOB_SZ(ELS_KS_KEY_256_SZ))
              ? ElsSlotPairFree(target.slot) : ElsSlotFree(target.slot);
    }
    if (ret == 0) {
        ret = ElsKsImportRun(info->keystore.op.importWrapped.blob,
                             info->keystore.op.importWrapped.blobSz,
                             wrap.slot, target.slot);
    }
    /* The container set the permissions; remove a key that disagrees. */
    if (ret == 0) {
        ret = ElsKsImportCheck(&target);
        if (ret != 0) {
            (void)ElsSlotDeleteRun(target.slot);
        }
    }

    ElsUnlock();

    return ret;
}

static int ElsKsExport(wc_CryptoInfo* info)
{
    wc_ElsPkc_KeyRef key, wrap;
    mcuxClEls_KeyProp_t prop;
    word32 need = 0;
    int ret;

    if (info->keystore.op.exportWrapped.blobSz == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    if (info->keystore.op.exportWrapped.format != WC_KEYWRAP_FORMAT_VENDOR) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    ret = wc_ElsPkc_ParseKeyRef(info->keystore.op.exportWrapped.keyRef,
                                info->keystore.op.exportWrapped.keyRefSz,
                                &key);
    if (ret == 0) {
        ret = ElsKsProps(key.slot, &prop);
    }
    if (ret == 0) {
        word32 bits = ElsKsBitsFromProp(&prop);

        if (!ElsSlotHolds(&prop, key.keyClass)) {
            ret = WC_NO_ERR_TRACE(BAD_STATE_E);
        }
        /* wrpok is set at creation and cannot be added later, so a key that
         * was not made exportable simply cannot leave. */
        else if ((prop.word.value & MCUXCLELS_KEYPROPERTY_VALUE_WRPOK) == 0) {
            ret = WC_NO_ERR_TRACE(BAD_STATE_E);
        }
        else if (bits != 128 && bits != 256) {
            ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
        else {
            need = ELS_KS_BLOB_SZ(bits / 8u);

            /* Size query: wc_KeyStore_ExportWrapped() defines this as
             * success. */
            if (info->keystore.op.exportWrapped.blob == NULL) {
                *info->keystore.op.exportWrapped.blobSz = need;
                ElsUnlock();
                return 0;
            }
            if (*info->keystore.op.exportWrapped.blobSz < need) {
                ret = WC_NO_ERR_TRACE(BUFFER_E);
            }
        }
    }

    if (ret == 0) {
        ret = ElsKsWrapRef(info->keystore.op.exportWrapped.wrapKeyRef,
                           info->keystore.op.exportWrapped.wrapKeyRefSz,
                           1, &wrap);
    }
    if (ret == 0 && wrap.slot == key.slot) {
        ret = WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    if (ret == 0) {
        ret = ElsKsExportRun(wrap.slot, key.slot,
                             info->keystore.op.exportWrapped.blob);
    }

    ElsUnlock();

    if (ret == 0) {
        *info->keystore.op.exportWrapped.blobSz = need;
    }

    return ret;
}

static int ElsKsDerive(wc_CryptoInfo* info)
{
    wc_ElsPkc_KeyRef target, src;
    mcuxClEls_KeyProp_t prop, srcProp;
    word32 keySz;
    int ret;

    if (info->keystore.op.derive.deriv == NULL ||
        info->keystore.op.derive.derivSz != ELS_KS_DERIV_SZ) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    /* The engine runs the SP800-108 CMAC KDF and nothing else. */
    if (info->keystore.op.derive.kdfType != WC_KDF_TYPE_NONE) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    /* The only two sizes an ELS slot key can have. Zero takes the smaller,
     * which is what the engine's zero-valued property word already encodes. */
    keySz = info->keystore.op.derive.keySz;
    if (keySz == 0) {
        keySz = ELS_KS_KEY_128_SZ;
    }
    if (keySz != ELS_KS_KEY_128_SZ && keySz != ELS_KS_KEY_256_SZ) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    /* The source must already be a derivation key; the target is where the
     * result lands and does not exist yet. */
    ret = ElsKsRef(info->keystore.op.derive.srcKeyRef,
                   info->keystore.op.derive.srcKeyRefSz,
                   WC_ELSPKC_KEY_CKDF, 1, &src);
    if (ret == 0) {
        ret = wc_ElsPkc_ParseKeyRef(info->keystore.op.derive.keyRef,
                                    info->keystore.op.derive.keyRefSz,
                                    &target);
    }
    if (ret == 0) {
        ret = ElsKsCheckType(info->keystore.op.derive.keyType,
                             target.keyClass);
    }
    if (ret == 0 && info->keystore.op.derive.keySz == 0 &&
        target.keyClass == WC_ELSPKC_KEY_ECC_SEED) {
        keySz = ELS_KS_KEY_256_SZ;
    }
    /* An ECC key pair only comes out of key generation, and a seed is 256
     * bits. */
    if (ret == 0 && (target.keyClass == WC_ELSPKC_KEY_ECC_SIGN ||
                     target.keyClass == WC_ELSPKC_KEY_ECC_DH ||
                     (target.keyClass == WC_ELSPKC_KEY_ECC_SEED &&
                      keySz != ELS_KS_KEY_256_SZ))) {
        ret = WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    if (ret == 0) {
        ret = (keySz == ELS_KS_KEY_256_SZ) ? ElsSlotPairFree(target.slot)
                                           : ElsSlotFree(target.slot);
    }
    if (ret == 0) {
        ret = ElsKsProps(src.slot, &srcProp);
    }
    if (ret == 0 && target.keyClass == WC_ELSPKC_KEY_KWK &&
        !(info->keystore.op.derive.attrs & WC_KEYSTORE_ATTR_UNWRAP_ONLY) &&
        (src.slot != ELS_DIE_INT_MK_SLOT ||
         (srcProp.word.value & MCUXCLELS_KEYPROPERTY_VALUE_DUK) == 0)) {
        /* A key that can wrap may only descend from the die unique key; from
         * any other parent the engine trips the tamper controller. */
        ret = WC_NO_ERR_TRACE(BAD_STATE_E);
    }
    if (ret == 0) {
        /* The derived key's permissions come from the target reference's
         * class, which keyType has just been checked against. */
        prop.word.value = 0u;
        if (keySz == ELS_KS_KEY_256_SZ) {
            prop.bits.ksize = MCUXCLELS_KEYPROPERTY_KEY_SIZE_256;
        }
        /* The protection bits feed the derivation, and NXP's recipes (EdgeLock
         * 2GO included) copy them from the parent. */
        prop.bits.upprot_priv = srcProp.bits.upprot_priv;
        prop.bits.upprot_sec  = srcProp.bits.upprot_sec;
        prop.word.value |= ElsClassUsageBit(target.keyClass);
        if (info->keystore.op.derive.attrs & WC_KEYSTORE_ATTR_EXPORTABLE) {
            prop.bits.wrpok = MCUXCLELS_KEYPROPERTY_WRAP_TRUE;
        }
        if (target.keyClass == WC_ELSPKC_KEY_KWK &&
            (info->keystore.op.derive.attrs & WC_KEYSTORE_ATTR_UNWRAP_ONLY)) {
            /* An unwrap-only wrapping key: it can bring keys in and never
             * take them out. */
            prop.word.value &= ~MCUXCLELS_KEYPROPERTY_VALUE_KWK;
            prop.word.value |= MCUXCLELS_KEYPROPERTY_VALUE_KUOK;
        }

        ret = ElsKsDeriveRun(src.slot, target.slot, prop,
                             info->keystore.op.derive.deriv);
    }

    ElsUnlock();

    return ret;
}

int wc_ElsPkc_DeriveDieKek(wc_ElsPkc_KeyRef* ref)
{
    mcuxClEls_KeyProp_t prop, src;
    int ret;

    if (ref == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }

    ret = wc_ElsPkc_ReserveSlot(WC_ELSPKC_KEY_KWK, ELS_KS_KEY_256_SZ, ref);

    if (ret == 0) {
        ret = ElsLock();
    }
    if (ret != 0) {
        /* ReserveSlot has already filled ref, so scrub it rather than return
         * a well-formed reference to a slot nothing was derived into. */
        XMEMSET(ref, 0, sizeof(*ref));
        return ret;
    }

    /* ReserveSlot dropped the lock, so the pair may have been taken since. */
    ret = ElsSlotPairFree(ref->slot);

    /* The ROM's recipe exactly; the engine refuses properties the parent
     * cannot confer. */
    if (ret == 0) {
        ret = ElsKsProps(ELS_DIE_INT_MK_SLOT, &src);
    }
    /* Deriving from an unfit parent resets the SoC instead of failing. */
    if (ret == 0 &&
        (src.word.value & ELS_DIE_INT_MK_PROPS) != ELS_DIE_INT_MK_PROPS) {
        ret = WC_NO_ERR_TRACE(BAD_STATE_E);
    }
    if (ret == 0) {
        prop.word.value = 0u;
        prop.bits.upprot_priv = src.bits.upprot_priv;
        prop.bits.upprot_sec  = src.bits.upprot_sec;
        prop.bits.ksize       = MCUXCLELS_KEYPROPERTY_KEY_SIZE_256;
        prop.word.value |= MCUXCLELS_KEYPROPERTY_VALUE_KWK;

        ret = ElsKsDeriveRun(ELS_DIE_INT_MK_SLOT, ref->slot, prop,
                             elsDieKekDeriv);
    }

    ElsUnlock();

    if (ret != 0) {
        XMEMSET(ref, 0, sizeof(*ref));
    }

    return ret;
}

static int ElsKsDelete(wc_CryptoInfo* info)
{
    wc_ElsPkc_KeyRef key;
    int ret = ElsLock();

    if (ret != 0) {
        return ret;
    }

    ret = wc_ElsPkc_ParseKeyRef(info->keystore.op.deleteKey.keyRef,
                                info->keystore.op.deleteKey.keyRefSz, &key);
    if (ret == 0) {
        mcuxClEls_KeyProp_t prop;

        ret = ElsKsProps(key.slot, &prop);
        /* Retention and hardware-out slots hold the ROM's keys. */
        if (ret == 0 && (prop.word.value &
                MCUXCLELS_KEYPROPERTY_VALUE_GENERAL_PURPOSE_SLOT) == 0) {
            ret = WC_NO_ERR_TRACE(BAD_FUNC_ARG);
        }
        if (ret == 0) {
            /* Deleting an empty slot is a caller mistake, and this part does
             * not return errors for those. Nothing is destroyed either way. */
            if ((prop.word.value & MCUXCLELS_KEYPROPERTY_VALUE_ACTIVE) == 0) {
                ElsUnlock();
                return 0;
            }
            if (!ElsSlotBaseOk(&prop, key.keyClass)) {
                ret = WC_NO_ERR_TRACE(BAD_FUNC_ARG);
            }
            /* A stale reference must not delete a key that reused its slot. */
            else if (!ElsSlotHasClass(&prop, key.keyClass)) {
                ret = WC_NO_ERR_TRACE(BAD_STATE_E);
            }
            else {
                ret = ElsSlotDeleteRun(key.slot);
            }
        }
    }

    ElsUnlock();

    return ret;
}

static int ElsKsGetInfo(wc_CryptoInfo* info)
{
    wc_ElsPkc_KeyRef key;
    mcuxClEls_KeyProp_t prop;
    int ret = ElsLock();

    if (ret != 0) {
        return ret;
    }

    ret = wc_ElsPkc_ParseKeyRef(info->keystore.op.getInfo.keyRef,
                                info->keystore.op.getInfo.keyRefSz, &key);
    if (ret == 0) {
        ret = ElsKsProps(key.slot, &prop);
    }

    ElsUnlock();

    if (ret == 0) {
        if (!ElsSlotHolds(&prop, key.keyClass)) {
            return WC_NO_ERR_TRACE(BAD_STATE_E);
        }
        if (info->keystore.op.getInfo.keyType != NULL) {
            *info->keystore.op.getInfo.keyType = ElsKsTypeFromProp(&prop);
        }
        if (info->keystore.op.getInfo.keyBits != NULL) {
            *info->keystore.op.getInfo.keyBits = ElsKsBitsFromProp(&prop);
        }
        if (info->keystore.op.getInfo.attrs != NULL) {
            word32 a = 0;

            if (prop.word.value & MCUXCLELS_KEYPROPERTY_VALUE_WRPOK) {
                a |= WC_KEYSTORE_ATTR_EXPORTABLE;
            }
            if ((prop.word.value & MCUXCLELS_KEYPROPERTY_VALUE_KUOK) &&
                !(prop.word.value & MCUXCLELS_KEYPROPERTY_VALUE_KWK)) {
                a |= WC_KEYSTORE_ATTR_UNWRAP_ONLY;
            }
            if (prop.word.value & MCUXCLELS_KEYPROPERTY_VALUE_RETENTION_SLOT) {
                a |= WC_KEYSTORE_ATTR_PERSISTENT;
            }
            *info->keystore.op.getInfo.attrs = a;
        }
    }

    return ret;
}

#endif /* WOLF_CRYPTO_CB_KEYSTORE */

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

#if defined(HAVE_ECC) || !defined(NO_RSA) || defined(HAVE_CURVE25519)
        case WC_ALGO_TYPE_PK:
            switch (info->pk.type) {
    #ifdef HAVE_CURVE25519
                case WC_PK_TYPE_CURVE25519:
                    ret = ElsPkcX25519(info->pk.curve25519.private_key,
                            info->pk.curve25519.public_key,
                            info->pk.curve25519.out,
                            info->pk.curve25519.outlen,
                            info->pk.curve25519.endian);
                    break;
    #endif
    #ifndef NO_RSA
                case WC_PK_TYPE_RSA:
                    ret = ElsPkcRsaFunction(info->pk.rsa.in,
                            info->pk.rsa.inLen, info->pk.rsa.out,
                            info->pk.rsa.outLen, info->pk.rsa.type,
                            info->pk.rsa.key);
                    break;
    #endif
    /* info->pk.eckg itself is declared under HAVE_ECC_DHE. */
    #if defined(HAVE_ECC) && defined(HAVE_ECC_DHE)
                case WC_PK_TYPE_EC_KEYGEN:
                    ret = ElsEccKeyGen(info->pk.eckg.key);
                    break;
    #endif
    #if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN)
                case WC_PK_TYPE_ECDSA_SIGN:
        #ifndef WC_ALLOW_ECC_ZERO_HASH
                    if (ElsEccDigestIsZero(info->pk.eccsign.in,
                                           info->pk.eccsign.inlen)) {
                        break;
                    }
        #endif
                    /* ELS first; it declines anything but a P-256 slot key. */
                    ret = ElsEccSign(info->pk.eccsign.in,
                            info->pk.eccsign.inlen, info->pk.eccsign.out,
                            info->pk.eccsign.outlen, info->pk.eccsign.key,
                            0);
                    if (ret == WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
                        ret = ElsPkcEccSign(info->pk.eccsign.in,
                                info->pk.eccsign.inlen, info->pk.eccsign.out,
                                info->pk.eccsign.outlen, info->pk.eccsign.key);
                    }
                    break;
    #endif
    #if defined(HAVE_ECC) && defined(HAVE_ECC_VERIFY)
                case WC_PK_TYPE_ECDSA_VERIFY:
        #ifndef WC_ALLOW_ECC_ZERO_HASH
                    if (ElsEccDigestIsZero(info->pk.eccverify.hash,
                                           info->pk.eccverify.hashlen)) {
                        break;
                    }
        #endif
                    ret = ElsEccVerify(info->pk.eccverify.sig,
                            info->pk.eccverify.siglen,
                            info->pk.eccverify.hash,
                            info->pk.eccverify.hashlen,
                            info->pk.eccverify.res,
                            info->pk.eccverify.key);
                    if (ret == WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
                        ret = ElsPkcEccVerify(info->pk.eccverify.sig,
                                info->pk.eccverify.siglen,
                                info->pk.eccverify.hash,
                                info->pk.eccverify.hashlen,
                                info->pk.eccverify.res,
                                info->pk.eccverify.key);
                    }
                    break;
    #endif
    #if defined(HAVE_ECC) && defined(HAVE_ECC_CHECK_KEY)
                case WC_PK_TYPE_EC_CHECK_PUB_KEY:
                    ret = ElsEccCheckKey(info->pk.ecc_check_pub.key,
                                         info->pk.ecc_check_pub.checkPriv);
                    break;
    #endif
                /* No WC_PK_TYPE_ECDH: ELS leaves the agreed secret in a slot. */
                default:
                    break;
            }
            break;
#endif /* HAVE_ECC || !NO_RSA || HAVE_CURVE25519 */

#ifdef WOLF_CRYPTO_CB_KEYSTORE
        case WC_ALGO_TYPE_KEYSTORE:
            switch (info->keystore.type) {
                /* No plaintext path in either direction: a key enters only as
                 * an unwrapped blob or a derivation, and leaves only wrapped. */
                case WC_KEYSTORE_IMPORT_PLAIN:
                case WC_KEYSTORE_EXPORT_PLAIN:
                    break;
                case WC_KEYSTORE_IMPORT_WRAPPED:
                    ret = ElsKsImport(info);
                    break;
                case WC_KEYSTORE_EXPORT_WRAPPED:
                    ret = ElsKsExport(info);
                    break;
                case WC_KEYSTORE_DERIVE:
                    ret = ElsKsDerive(info);
                    break;
                case WC_KEYSTORE_DELETE:
                    ret = ElsKsDelete(info);
                    break;
                case WC_KEYSTORE_GET_INFO:
                    ret = ElsKsGetInfo(info);
                    break;
                default:
                    break;
            }
            break;
#endif /* WOLF_CRYPTO_CB_KEYSTORE */

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
#ifdef ELS_PKC_HAVE_SESSION
    /* A PKC reset under a live port would wedge an operation in flight. */
    if (ret == 0 && !elsReady) {
        ret = ElsPkcEnable();
    }
#endif
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
#ifdef ELS_PKC_HAVE_SESSION
            if (elsReady) {
                ElsPkcSessionDown();
                ElsCleanupSession();
            }
#endif
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
