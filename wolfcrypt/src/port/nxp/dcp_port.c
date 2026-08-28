/* dcp_port.c
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


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_IMXRT_DCP
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#if defined(__DCACHE_PRESENT) && (__DCACHE_PRESENT == 1U) && defined(DCP_USE_DCACHE) && (DCP_USE_DCACHE == 1U)
#error "DCACHE not supported by this driver. Please undefine DCP_USE_DCACHE."
#endif

#ifndef DCP_USE_OTP_KEY
#define DCP_USE_OTP_KEY 0 /* Set to 1 to select OTP key for AES encryption/decryption. */
#endif

#include "fsl_dcp.h"

#ifndef SINGLE_THREADED
#define dcp_lock_init() wolfSSL_CryptHwMutexInit()
#define dcp_lock() wolfSSL_CryptHwMutexLock()
#define dcp_unlock() wolfSSL_CryptHwMutexUnLock()
#else
/* Single-threaded: no mutex, the lock calls evaluate to success (0) so
 * the "if (dcp_lock() != 0)" checks compile out as constants. unlock is
 * statement-only, hence (void)0 to keep -Wunused-value quiet. */
#define dcp_lock_init() 0
#define dcp_lock()      0
#define dcp_unlock()    ((void)0)
#endif

#if DCP_USE_OTP_KEY
typedef enum _dcp_otp_key_select
{
    kDCP_OTPMKKeyLow  = 1U, /* Use [127:0] from snvs key as dcp key */
    kDCP_OTPMKKeyHigh = 2U, /* Use [255:128] from snvs key as dcp key */
    kDCP_OCOTPKeyLow  = 3U, /* Use [127:0] from ocotp key as dcp key */
    kDCP_OCOTPKeyHigh = 4U  /* Use [255:128] from ocotp key as dcp key */
} dcp_otp_key_select;
#endif

#if DCP_USE_OTP_KEY
static status_t DCP_OTPKeySelect(dcp_otp_key_select keySelect)
{
    status_t retval = kStatus_Success;
    if (keySelect == kDCP_OTPMKKeyLow)
    {
        IOMUXC_GPR->GPR3 &= ~(1 << IOMUXC_GPR_GPR3_DCP_KEY_SEL_SHIFT);
        IOMUXC_GPR->GPR10 &= ~(1 << IOMUXC_GPR_GPR10_DCPKEY_OCOTP_OR_KEYMUX_SHIFT);
    }

    else if (keySelect == kDCP_OTPMKKeyHigh)
    {
        IOMUXC_GPR->GPR3 |= (1 << IOMUXC_GPR_GPR3_DCP_KEY_SEL_SHIFT);
        IOMUXC_GPR->GPR10 &= ~(1 << IOMUXC_GPR_GPR10_DCPKEY_OCOTP_OR_KEYMUX_SHIFT);
    }

    else if (keySelect == kDCP_OCOTPKeyLow)
    {
        IOMUXC_GPR->GPR3 &= ~(1 << IOMUXC_GPR_GPR3_DCP_KEY_SEL_SHIFT);
        IOMUXC_GPR->GPR10 |= (1 << IOMUXC_GPR_GPR10_DCPKEY_OCOTP_OR_KEYMUX_SHIFT);
    }

    else if (keySelect == kDCP_OCOTPKeyHigh)
    {
        IOMUXC_GPR->GPR3 |= (1 << IOMUXC_GPR_GPR3_DCP_KEY_SEL_SHIFT);
        IOMUXC_GPR->GPR10 |= (1 << IOMUXC_GPR_GPR10_DCPKEY_OCOTP_OR_KEYMUX_SHIFT);
    }

    else
    {
        retval = kStatus_InvalidArgument;
    }
    return retval;
}
#endif

static const int dcp_channels[4] = {
    kDCP_Channel0,
    kDCP_Channel1,
    kDCP_Channel2,
    kDCP_Channel3
};

#ifndef SINGLE_THREADED
/* Channel table. dcp_status[i] is the publication flag for entry i: it
 * is the LAST field written when reserving and when releasing, so an
 * entry is only ever visible as claimable once dcp_owner[i] already
 * agrees. dcp_free_unlocked() relies on that ordering to release
 * without the lock, so both arrays are volatile to stop the compiler
 * reordering or caching the paired accesses. */
static volatile int dcp_status[4] = {0, 0, 0, 0};
/* Context that reserved each channel: a release only takes effect from
 * the recorded owner, so a stale or uninitialized handle.channel value
 * (a struct never zeroed before init, a freed struct reused) cannot
 * free a channel another live context holds. This table is also what
 * lets the port answer "does this context already hold a channel?"
 * without reading the caller's struct, which init is allowed to
 * receive uninitialized. */
static void* volatile dcp_owner[4] = {NULL, NULL, NULL, NULL};
#endif

/* Reserve a channel for owner.
 * Returns the channel on success, 0 if the pool is exhausted (callers
 * map it to WC_HW_WAIT_E, "Hardware waiting on resource", the same code
 * the CAAM and Atmel ports return for an exhausted slot pool), or -1 if
 * the lock is unusable, which is a hard WC_HW_E rather than a transient
 * shortage. */
static int dcp_get_channel(void* owner)
{
#ifdef SINGLE_THREADED
    (void)owner;
    return dcp_channels[0];
#else
    int i;
    int ret = 0;

    if (dcp_lock() != 0)
        return -1;
    /* A context owns at most one channel. If this one already holds a
     * reservation - a live context being re-initialized, or the
     * destination of a copy - hand back the same channel instead of
     * taking a second. Looking the owner up here, in the port's own
     * table, is what lets the callers avoid reading a handle.channel
     * that may never have been initialized. */
    for (i = 0; i < 4; i++) {
        if (dcp_status[i] != 0 && dcp_owner[i] == owner) {
            ret = dcp_channels[i];
            break;
        }
    }
    if (ret == 0) {
        for (i = 0; i < 4; i++) {
            if (dcp_status[i] == 0) {
                /* Owner first, status last: dcp_status[i] publishes the
                 * entry, so it must never be set while dcp_owner[i]
                 * still names somebody else. */
                dcp_owner[i] = owner;
                dcp_status[i] = 1;
                ret = dcp_channels[i];
                break;
            }
        }
    }
    dcp_unlock();
    return ret;
#endif
}

static int dcp_key_slot(int ch)
{
#if DCP_USE_OTP_KEY
    (void)ch;
    return kDCP_OtpKey;
#elif defined(SINGLE_THREADED)
    (void)ch;
    return 0;
#else
    int i;
    int ret = -1;

    if (dcp_lock() != 0)
        return ret;
    for (i = 0; i < 4; i++) {
        if (ch == dcp_channels[i]) {
            ret = i;
            break;
        }
    }
    dcp_unlock();
    return ret;
#endif
}


int wc_dcp_init(void)
{
    dcp_config_t dcpConfig;

    if (dcp_lock_init() != 0)
        return WC_HW_E;
    if (dcp_lock() != 0)
        return WC_HW_E;
    DCP_GetDefaultConfig(&dcpConfig);

    /* Reset and initialize DCP */
    DCP_Init(DCP, &dcpConfig);
#if DCP_USE_OTP_KEY
    /* Set OTP key type in IOMUX registers before initializing DCP. */
    /* Software reset of DCP must be issued after changing the OTP key type. */
    DCP_OTPKeySelect(kDCP_OTPMKKeyLow);
#endif
    /* Release mutex */
    dcp_unlock();
    return 0;
}

/* Release a channel without taking the DCP lock.
 *
 * A failed dcp_lock() does not prove the critical section is empty:
 * wolfSSL_CryptHwMutexLock() can fail before it ever reaches
 * wc_LockMutex(), because on every port without a static mutex
 * initializer it first runs the lazy wolfSSL_CryptHwMutexInit(). One
 * thread can lose that init race, or hit an allocation failure in it,
 * and be told the lock is unavailable while another thread is inside
 * the critical section. So this must be correct against a concurrent
 * locked allocator, not merely against nobody.
 *
 * It is, because it only ever publishes a consistent entry: the owner
 * is cleared while dcp_status[i] still marks the entry busy, so no
 * allocator can claim it yet, and the single store that frees the
 * entry is the last thing that happens. An allocator that claims the
 * entry afterwards owns both fields outright and nothing here writes
 * to them again. The reverse order would let an allocator claim the
 * channel between the two stores and then have its fresh owner
 * overwritten with NULL, leaving the channel busy but ownerless -
 * unreleasable, and lost for the lifetime of the process. */
static void dcp_free_unlocked(void* owner, int ch)
{
#ifndef SINGLE_THREADED
    int i;

    for (i = 0; i < 4; i++) {
        if (ch == dcp_channels[i] && dcp_owner[i] == owner) {
            dcp_owner[i] = NULL;
            dcp_status[i] = 0;
            break;
        }
    }
#else
    (void)owner;
    (void)ch;
#endif
}

/* Total: always releases, so callers may drop their handle record
 * unconditionally. A lock failure falls back to the unlocked release,
 * which is ordered to be safe against a concurrent locked allocator
 * (see dcp_free_unlocked), instead of orphaning the reservation - with
 * only four channels, refusing to release on a lock failure would leak
 * one permanently. */
static void dcp_free(void* owner, int ch)
{
    int locked;

    locked = (dcp_lock() == 0);
    dcp_free_unlocked(owner, ch);
    if (locked)
        dcp_unlock();
}

/*
 * The DCP SDK's opaque hash context embeds a pointer to the
 * dcp_handle_t passed to DCP_HASH_Init; all engine scheduling goes
 * through that pointer, so a copied context must be rebound to its own
 * handle. The internal layout is not exported by fsl_dcp.h, so locate
 * the pointer word by binding a scratch context to a probe handle and
 * scanning for the word holding the probe address. DCP_HASH_Init is a
 * pure software state setup and touches neither the DCP peripheral nor
 * shared port state. Returns DCP_HASH_CTX_SIZE if the layout no longer
 * matches, so the copy fails instead of binding a wrong word.
 */
#if !defined(NO_SHA256) || !defined(NO_SHA)
static word32 dcp_hash_handle_word(void)
{
    dcp_hash_ctx_t bound;
    dcp_handle_t probe;
    word32 i;

    XMEMSET(&bound, 0, sizeof(bound));
    XMEMSET(&probe, 0, sizeof(probe));
    if (DCP_HASH_Init(DCP, &probe, &bound, kDCP_Sha256) != kStatus_Success)
        return DCP_HASH_CTX_SIZE;
    for (i = 0; i < DCP_HASH_CTX_SIZE; i++) {
        if (bound.x[i] == (word32)&probe)
            return i;
    }
    return DCP_HASH_CTX_SIZE;
}
#endif


#ifndef NO_AES
int DCPAesInit(Aes *aes)
{
    int ch;
    int keyslot;
    if (!aes)
        return BAD_FUNC_ARG;
    ch = dcp_get_channel(aes);
    if (ch < 0)
        return WC_HW_E;
    if (ch == 0)
        return WC_HW_WAIT_E;
    /* dcp_key_slot() fails with -1 if its lock acquisition fails;
     * never keep a channel with an invalid key slot. */
    keyslot = dcp_key_slot(ch);
    if (keyslot < 0) {
        dcp_free(aes, ch);
        return WC_HW_E;
    }
    XMEMSET(&aes->handle, 0, sizeof(aes->handle));
    aes->handle.channel = (dcp_channel_t)ch;
    aes->handle.keySlot = (dcp_key_slot_t)keyslot;
    aes->handle.swapConfig = kDCP_NoSwap;
    return 0;
}

static unsigned char  aes_key_aligned[16] __attribute__((aligned(0x10)));

void DCPAesFree(Aes *aes)
{
    /* The shared key scratch buffer is zeroed under the DCP lock; if
     * the lock is unavailable, skip the zeroing rather than race
     * another thread on the buffer. */
    if (dcp_lock() == 0) {
        ForceZero(aes_key_aligned, sizeof(aes_key_aligned));
        dcp_unlock();
    }
    dcp_free(aes, aes->handle.channel);
    aes->handle.channel = 0;
}


int  DCPAesSetKey(Aes* aes, const byte* key, word32 len, const byte* iv,
                          int dir)
{

#if DCP_USE_OTP_KEY
#warning Please update cipherAes128 variables to match expected AES ciphertext for your OTP key.
#endif
    status_t status;
    if (!aes || !key)
        return BAD_FUNC_ARG;

    if (len != 16)
        return BAD_FUNC_ARG;
    if (aes->handle.channel == 0) {
        if (DCPAesInit(aes) != 0)
            return WC_HW_E;
    }
    if (dcp_lock() != 0)
        return WC_HW_E;
    XMEMCPY(aes_key_aligned, key, 16);
    status = DCP_AES_SetKey(DCP, &aes->handle, aes_key_aligned, 16);
    ForceZero(aes_key_aligned, sizeof(aes_key_aligned));
    if (status != kStatus_Success)
        status = WC_HW_E;
    else {
        if (iv)
            XMEMCPY(aes->reg, iv, 16);
        else
            XMEMSET(aes->reg, 0, 16);
    }
    dcp_unlock();
    return status;
}

int  DCPAesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret;
    if (sz % 16)
        return BAD_FUNC_ARG;
    if (dcp_lock() != 0)
        return WC_HW_E;
    ret = DCP_AES_EncryptCbc(DCP, &aes->handle, in, out, sz, (const byte *)aes->reg);
    if (ret)
        ret = WC_HW_E;
    else
        XMEMCPY(aes->reg, out + sz - WC_AES_BLOCK_SIZE, WC_AES_BLOCK_SIZE);
    dcp_unlock();
    return ret;
}

int  DCPAesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret;
    if (sz % 16)
        return BAD_FUNC_ARG;
    /* Snapshot last ciphertext block before decrypt; in-place decryption
     * (in == out) overwrites the input with plaintext. */
    XMEMCPY(aes->tmp, in + sz - WC_AES_BLOCK_SIZE, WC_AES_BLOCK_SIZE);
    if (dcp_lock() != 0)
        return WC_HW_E;
    ret = DCP_AES_DecryptCbc(DCP, &aes->handle, in, out, sz, (const byte *)aes->reg);
    if (ret)
        ret = WC_HW_E;
    else
        XMEMCPY(aes->reg, aes->tmp, WC_AES_BLOCK_SIZE);
    dcp_unlock();
    return ret;
}

int  DCPAesEcbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret;
    if (sz % 16)
        return BAD_FUNC_ARG;
    if (dcp_lock() != 0)
        return WC_HW_E;
    ret = DCP_AES_EncryptEcb(DCP, &aes->handle, in, out, sz);
    if (ret)
        ret = WC_HW_E;
    dcp_unlock();
    return ret;
}

int  DCPAesEcbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret;
    if (sz % 16)
        return BAD_FUNC_ARG;
    if (dcp_lock() != 0)
        return WC_HW_E;
    ret = DCP_AES_DecryptEcb(DCP, &aes->handle, in, out, sz);
    if (ret)
        ret = WC_HW_E;
    dcp_unlock();
    return ret;
}

#endif

#ifndef NO_SHA256
int wc_InitSha256_ex(wc_Sha256* sha256, void* heap, int devId)
{
    int ret;
    int ch;
    int keyslot;
    if (sha256 == NULL)
        return BAD_FUNC_ARG;
    /* Nothing in the supplied struct is read here: init accepts raw
     * stack or XMALLOC storage, so handle.channel is indeterminate
     * until the XMEMSET below. dcp_get_channel() hands back the
     * reservation this pointer already holds, if any, so
     * re-initializing a live context still cannot leak its channel. */
    ch = dcp_get_channel(sha256);
    if (ch < 0)
        return WC_HW_E;
    if (ch == 0)
        return WC_HW_WAIT_E;
    /* dcp_key_slot() fails with -1 if its lock acquisition fails;
     * never keep a channel with an invalid key slot. */
    keyslot = dcp_key_slot(ch);
    if (keyslot < 0) {
        dcp_free(sha256, ch);
        return WC_HW_E;
    }
    if (dcp_lock() != 0) {
        dcp_free_unlocked(sha256, ch);
        return WC_HW_E;
    }
    (void)devId;
    XMEMSET(sha256, 0, sizeof(wc_Sha256));
    sha256->handle.channel    = (dcp_channel_t)ch;
    sha256->handle.keySlot    = (dcp_key_slot_t)keyslot;
    sha256->handle.swapConfig = kDCP_NoSwap;
    ret = DCP_HASH_Init(DCP, &sha256->handle, &sha256->ctx, kDCP_Sha256);
    if (ret != kStatus_Success)
        ret = WC_HW_E;
    dcp_unlock();
    if (ret == WC_HW_E) {
        /* The channel is reserved before the SDK init; release it on
         * failure (after dropping the lock: dcp_free takes it itself)
         * so repeated failures cannot exhaust the channels, and leave
         * the context explicitly uninitialized. */
        dcp_free(sha256, ch);
        sha256->handle.channel = 0;
    }
    return ret;
}

void DCPSha256Free(wc_Sha256* sha256)
{
    if (sha256) {
        dcp_free(sha256, sha256->handle.channel);
        /* Drop the channel record: the context no longer owns a
         * channel, and the value must not outlive the reservation. */
        sha256->handle.channel = 0;
    }
}

int wc_Sha256Update(wc_Sha256* sha256, const byte* data, word32 len)
{
    int ret;
    if (sha256 == NULL || (data == NULL && len != 0)) {
        return BAD_FUNC_ARG;
    }
    if (dcp_lock() != 0)
        return WC_HW_E;
    ret = DCP_HASH_Update(DCP, &sha256->ctx, data, len);
    if (ret != kStatus_Success)
        ret = WC_HW_E;
    dcp_unlock();
    return ret;
}

int wc_Sha256GetHash(wc_Sha256* sha256, byte* hash)
{
    int ret;
    size_t outlen = WC_SHA256_DIGEST_SIZE;
    dcp_hash_ctx_t saved_ctx;
    if (sha256 == NULL || hash == NULL)
        return BAD_FUNC_ARG;
    if (dcp_lock() != 0)
        return WC_HW_E;
    XMEMCPY(&saved_ctx, &sha256->ctx, sizeof(dcp_hash_ctx_t));
    XMEMSET(hash, 0, WC_SHA256_DIGEST_SIZE);
    ret = DCP_HASH_Finish(DCP, &sha256->ctx, hash, &outlen);
    if ((ret != kStatus_Success) || (outlen != SHA256_DIGEST_SIZE))
        ret = WC_HW_E;
    else
        XMEMCPY(&sha256->ctx, &saved_ctx, sizeof(dcp_hash_ctx_t));
    dcp_unlock();
    return ret;
}

int wc_Sha256Final(wc_Sha256* sha256, byte* hash)
{
    int ret;
    size_t outlen = WC_SHA256_DIGEST_SIZE;
    if (dcp_lock() != 0)
        return WC_HW_E;
    ret = DCP_HASH_Finish(DCP, &sha256->ctx, hash, &outlen);
    if ((ret != kStatus_Success) || (outlen != SHA256_DIGEST_SIZE))
        ret = WC_HW_E;
    else {
        ret = DCP_HASH_Init(DCP, &sha256->handle, &sha256->ctx, kDCP_Sha256);
        if (ret != kStatus_Success)
            ret = WC_HW_E;
    }
    dcp_unlock();
    return ret;
}

#ifdef WOLFSSL_HASH_FLAGS
int wc_Sha256SetFlags(wc_Sha256* sha256, word32 flags)
{
    if (sha256) {
        sha256->flags = flags;
    }
    return 0;
}
int wc_Sha256GetFlags(wc_Sha256* sha256, word32* flags)
{
    if (sha256 && flags) {
        *flags = sha256->flags;
    }
    return 0;
}
#endif /* WOLFSSL_HASH_FLAGS */

int wc_Sha256Copy(wc_Sha256* src, wc_Sha256* dst)
{
    int ch;
    int keyslot;
    word32 handleWord;

    if (src == NULL || dst == NULL)
        return BAD_FUNC_ARG;
    if (src == dst)
        return 0;
    handleWord = dcp_hash_handle_word();
    if (handleWord >= DCP_HASH_CTX_SIZE)
        return WC_HW_E;
    /* The copy overwrites dst's hash state, not its channel
     * reservation: dcp_get_channel() returns the channel dst already
     * owns, and only reserves a new one when dst holds none. Releasing
     * first and re-reserving would let another context take the
     * channel in between, so a copy into a perfectly live dst - what
     * wc_HmacUpdate() does on every call under WOLFSSL_HMAC_COPY_HASH -
     * could fail for want of a channel it already had. It also avoids
     * reading dst->handle, which need not be initialized here. */
    ch = dcp_get_channel(dst);
    if (ch < 0)
        return WC_HW_E;
    if (ch == 0)
        return WC_HW_WAIT_E;
    /* dcp_key_slot() fails with -1 if its lock acquisition fails;
     * never keep a channel with an invalid key slot. */
    keyslot = dcp_key_slot(ch);
    if (keyslot < 0) {
        dcp_free(dst, ch);
        return WC_HW_E;
    }
    if (dcp_lock() != 0) {
        dcp_free_unlocked(dst, ch);
        return WC_HW_E;
    }
    dst->handle.channel    = (dcp_channel_t)ch;
    dst->handle.keySlot    = (dcp_key_slot_t)keyslot;
    dst->handle.swapConfig = kDCP_NoSwap;
    XMEMCPY(&dst->ctx, &src->ctx, sizeof(dcp_hash_ctx_t));
    /* Rebind the copied context to its own handle: the SDK stages the
     * running hash per channel, so a copy sharing the source channel
     * would corrupt both digests. */
    dst->ctx.x[handleWord] = (word32)&dst->handle;
    dst->heap = src->heap;
#ifdef WOLFSSL_HASH_FLAGS
    dst->flags = src->flags;
    dst->flags |= WC_HASH_FLAG_ISCOPY;
#endif
    dcp_unlock();
    return 0;
}
#endif /* !NO_SHA256 */


#ifndef NO_SHA

int wc_InitSha_ex(wc_Sha* sha, void* heap, int devId)
{
    int ret;
    int ch;
    int keyslot;
    if (sha == NULL)
        return BAD_FUNC_ARG;
    /* Nothing in the supplied struct is read here: init accepts raw
     * stack or XMALLOC storage, so handle.channel is indeterminate
     * until the XMEMSET below. dcp_get_channel() hands back the
     * reservation this pointer already holds, if any, so
     * re-initializing a live context still cannot leak its channel. */
    ch = dcp_get_channel(sha);
    if (ch < 0)
        return WC_HW_E;
    if (ch == 0)
        return WC_HW_WAIT_E;
    /* dcp_key_slot() fails with -1 if its lock acquisition fails;
     * never keep a channel with an invalid key slot. */
    keyslot = dcp_key_slot(ch);
    if (keyslot < 0) {
        dcp_free(sha, ch);
        return WC_HW_E;
    }
    if (dcp_lock() != 0) {
        dcp_free_unlocked(sha, ch);
        return WC_HW_E;
    }
    (void)devId;
    XMEMSET(sha, 0, sizeof(wc_Sha));
    sha->handle.channel    = (dcp_channel_t)ch;
    sha->handle.keySlot    = (dcp_key_slot_t)keyslot;
    sha->handle.swapConfig = kDCP_NoSwap;
    ret = DCP_HASH_Init(DCP, &sha->handle, &sha->ctx, kDCP_Sha1);
    if (ret != kStatus_Success)
        ret = WC_HW_E;
    dcp_unlock();
    if (ret == WC_HW_E) {
        /* The channel is reserved before the SDK init; release it on
         * failure (after dropping the lock: dcp_free takes it itself)
         * so repeated failures cannot exhaust the channels, and leave
         * the context explicitly uninitialized. */
        dcp_free(sha, ch);
        sha->handle.channel = 0;
    }
    return ret;
}

void DCPShaFree(wc_Sha* sha)
{
    if (sha) {
        dcp_free(sha, sha->handle.channel);
        /* Drop the channel record: the context no longer owns a
         * channel, and the value must not outlive the reservation. */
        sha->handle.channel = 0;
    }
}

int wc_ShaUpdate(wc_Sha* sha, const byte* data, word32 len)
{
    int ret;
    if (sha == NULL || (data == NULL && len != 0)) {
        return BAD_FUNC_ARG;
    }
    if (dcp_lock() != 0)
        return WC_HW_E;
    ret = DCP_HASH_Update(DCP, &sha->ctx, data, len);
    if (ret != kStatus_Success)
        ret = WC_HW_E;
    dcp_unlock();
    return ret;
}


int wc_ShaGetHash(wc_Sha* sha, byte* hash)
{
    int ret;
    size_t outlen = WC_SHA_DIGEST_SIZE;
    dcp_hash_ctx_t saved_ctx;
    if (sha == NULL || hash == NULL)
        return BAD_FUNC_ARG;
    if (dcp_lock() != 0)
        return WC_HW_E;
    XMEMCPY(&saved_ctx, &sha->ctx, sizeof(dcp_hash_ctx_t));
    XMEMSET(hash, 0, WC_SHA_DIGEST_SIZE);
    ret = DCP_HASH_Finish(DCP, &sha->ctx, hash, &outlen);
    if ((ret != kStatus_Success) || (outlen != WC_SHA_DIGEST_SIZE))
        ret = WC_HW_E;
    else
        XMEMCPY(&sha->ctx, &saved_ctx, sizeof(dcp_hash_ctx_t));
    dcp_unlock();
    return ret;
}

int wc_ShaFinal(wc_Sha* sha, byte* hash)
{
    int ret;
    size_t outlen = WC_SHA_DIGEST_SIZE;
    if (dcp_lock() != 0)
        return WC_HW_E;
    ret = DCP_HASH_Finish(DCP, &sha->ctx, hash, &outlen);
    if ((ret != kStatus_Success) || (outlen != SHA_DIGEST_SIZE)) {
        ret = WC_HW_E;
    } else {
        ret = DCP_HASH_Init(DCP, &sha->handle, &sha->ctx, kDCP_Sha1);
        if (ret != kStatus_Success)
            ret = WC_HW_E;
    }
    dcp_unlock();
    return ret;
}

#ifdef WOLFSSL_HASH_FLAGS
int wc_ShaSetFlags(wc_Sha* sha, word32 flags)
{
    if (sha) {
        sha->flags = flags;
    }
    return 0;
}
int wc_ShaGetFlags(wc_Sha* sha, word32* flags)
{
    if (sha && flags) {
        *flags = sha->flags;
    }
    return 0;
}
#endif /* WOLFSSL_HASH_FLAGS */

int wc_ShaCopy(wc_Sha* src, wc_Sha* dst)
{
    int ch;
    int keyslot;
    word32 handleWord;

    if (src == NULL || dst == NULL)
        return BAD_FUNC_ARG;
    if (src == dst)
        return 0;
    handleWord = dcp_hash_handle_word();
    if (handleWord >= DCP_HASH_CTX_SIZE)
        return WC_HW_E;
    /* The copy overwrites dst's hash state, not its channel
     * reservation: dcp_get_channel() returns the channel dst already
     * owns, and only reserves a new one when dst holds none. Releasing
     * first and re-reserving would let another context take the
     * channel in between, so a copy into a perfectly live dst - what
     * wc_HmacUpdate() does on every call under WOLFSSL_HMAC_COPY_HASH -
     * could fail for want of a channel it already had. It also avoids
     * reading dst->handle, which need not be initialized here. */
    ch = dcp_get_channel(dst);
    if (ch < 0)
        return WC_HW_E;
    if (ch == 0)
        return WC_HW_WAIT_E;
    /* dcp_key_slot() fails with -1 if its lock acquisition fails;
     * never keep a channel with an invalid key slot. */
    keyslot = dcp_key_slot(ch);
    if (keyslot < 0) {
        dcp_free(dst, ch);
        return WC_HW_E;
    }
    if (dcp_lock() != 0) {
        dcp_free_unlocked(dst, ch);
        return WC_HW_E;
    }
    dst->handle.channel    = (dcp_channel_t)ch;
    dst->handle.keySlot    = (dcp_key_slot_t)keyslot;
    dst->handle.swapConfig = kDCP_NoSwap;
    XMEMCPY(&dst->ctx, &src->ctx, sizeof(dcp_hash_ctx_t));
    /* Rebind the copied context to its own handle: the SDK stages the
     * running hash per channel, so a copy sharing the source channel
     * would corrupt both digests. */
    dst->ctx.x[handleWord] = (word32)&dst->handle;
    dst->heap = src->heap;
#ifdef WOLFSSL_HASH_FLAGS
    dst->flags = src->flags;
    dst->flags |= WC_HASH_FLAG_ISCOPY;
#endif
    dcp_unlock();
    return 0;
}
#endif /* !NO_SHA */

#endif /* WOLFSSL_IMXRT_DCP */
