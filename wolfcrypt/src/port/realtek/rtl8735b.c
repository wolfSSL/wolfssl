/* rtl8735b.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_RTL8735B_HUK

#include <wolfssl/wolfcrypt/port/realtek/rtl8735b.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif
#ifndef NO_AES
    #include <wolfssl/wolfcrypt/aes.h>
#endif
#if !defined(NO_HMAC) && !defined(NO_SHA256)
    #include <wolfssl/wolfcrypt/hmac.h>
#endif
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* Vendor HAL surface: the real SDK headers on target, the host-test shim under
 * --enable-rtl8735b (see rtl8735b_shim.h). The on-target include path is
 * supplied by the application / board CMake (see this port's README). */
#ifdef WOLFSSL_RTL8735B_HOST_TEST
    #include "rtl8735b_shim.h"
#else
    #include "hal_crypto.h"
    #include "hal_hkdf.h"
    #ifndef WC_NO_RNG
        #include "hal_trng_sec.h"
    #endif
    #if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN)
        #include "hal_ecdsa.h"
    #endif
#endif

#ifdef WOLF_CRYPTO_CB

/* HUK-derived working key is always a 256-bit key. */
#define WC_RTL8735B_KEYLEN 32

/* The HAL crypto engine DMAs its buffers on 32-byte (cache line) boundaries.
 * Unaligned caller buffers are bounced through an aligned heap temp: over-
 * allocate by 31 and round the usable pointer up; keep the raw pointer for XFREE. */
#define WC_RTL8735B_IS_ALIGNED32(p) ((((wc_ptr_t)(p)) & 31u) == 0)
#define WC_RTL8735B_ALIGN_UP32(p) \
    ((byte*)((((wc_ptr_t)(p)) + 31u) & ~(wc_ptr_t)31u))
/* Largest length we will bounce: leaves headroom so (sz + 31) cannot wrap.
 * Anything larger is rejected (defensive; not reachable in device RAM). */
#define WC_RTL8735B_BOUNCE_MAX  (0xFFFFFFFFUL - 32u)

#if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN)
/* HW ECDSA engine is wired for 256-bit curves (P-256); big ints cross the HAL as
 * little-endian 32-bit word arrays. Used by the ECDSA paths and result state. */
#define WC_RTL8735B_ECC_BYTES   32
#define WC_RTL8735B_ECC_WORDS   (WC_RTL8735B_ECC_BYTES / 4)
#endif

/* --- bounce-buffer helpers (HAL DMA needs 32-byte alignment) --- */

/* Stage an unaligned input on a 32-byte-aligned heap temp. *aligned <- aligned
 * pointer (src if already aligned, NULL for sz==0); *allocp <- buffer to free
 * (NULL if none). Caller bounds sz to WC_RTL8735B_BOUNCE_MAX. 0 or MEMORY_E. */
static int Rtl8735b_BounceIn(const byte* src, word32 sz, const byte** aligned,
    byte** allocp)
{
    byte* b;
    *allocp = NULL;
    if (sz == 0 || WC_RTL8735B_IS_ALIGNED32(src)) {
        *aligned = src;
        return 0;
    }
    b = (byte*)XMALLOC(sz + 31, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (b == NULL) {
        return MEMORY_E;
    }
    *allocp  = b;
    *aligned = WC_RTL8735B_ALIGN_UP32(b);
    XMEMCPY((byte*)*aligned, src, sz);
    return 0;
}

/* Allocate a 32-byte-aligned output bounce of sz bytes. *aligned <- usable
 * pointer, *allocp <- buffer to free. Caller bounds sz. 0 or MEMORY_E. */
static int Rtl8735b_BounceOut(word32 sz, byte** aligned, byte** allocp)
{
    byte* b = (byte*)XMALLOC(sz + 31, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (b == NULL) {
        return MEMORY_E;
    }
    *allocp  = b;
    *aligned = WC_RTL8735B_ALIGN_UP32(b);
    return 0;
}

/* Release a bounce: scrub the aligned (plaintext) view, then free the raw
 * allocation. No-op when alloc is NULL. */
static void Rtl8735b_BounceFree(byte* alloc, byte* aligned, word32 sz)
{
    if (alloc != NULL) {
        if (sz > 0) {
            ForceZero(aligned, sz);
        }
        XFREE(alloc, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
}

/* --- module state: file-scope globals, each touched only with the crypto mutex
 * held (every HW path locks first), so safe across concurrent objects. --- */

/* Derivation cache: the seed whose working key currently resides in the derived
 * slot WC_RTL8735B_DERIVED_WB_IDX. Single slot, so interleaving distinct seeds
 * misses every call and gains nothing (still correct -- re-derived under the
 * mutex). Seed is HKDF input, not secret, but scrubbed on unregister. Define
 * WC_RTL8735B_NO_DERIVE_CACHE to disable. */
#ifndef WC_RTL8735B_NO_DERIVE_CACHE
static byte huk_seedCache[WC_RTL8735B_KEYLEN];
static int  huk_haveCache = 0;
#endif

#if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN)
/* HW ECDSA finish-IRQ completion state. The op runs under the crypto mutex, so
 * these are safe; the ISR fills them and sets huk_ecdsaDone last. Only the flag
 * is volatile (the sync point); results are read after the flag is seen set and
 * after hal_ecdsa_deinit() (a compiler barrier), so they need not be -- which
 * also avoids volatile-discarding casts at the HAL/XMEMCPY boundary. */
static volatile int    huk_ecdsaDone;
static volatile word32 huk_ecdsaErr;
static word32          huk_ecdsaR[WC_RTL8735B_ECC_WORDS];
static word32          huk_ecdsaS[WC_RTL8735B_ECC_WORDS];
#ifdef HAVE_ECC_VERIFY
static volatile word32 huk_veriResult;
#endif
/* The finish-IRQ callback is registered with the address of this adapter; it is
 * file-scope (not a stack local) so a late IRQ arriving after a spin-timeout
 * return dereferences valid memory, not a dead stack frame. Mutex-serialized, so
 * one shared instance is safe across the sign/verify paths. */
static hal_ecdsa_adapter_t huk_ecdsaAdapter;
#endif

#ifndef WC_NO_RNG
/* Lazily-initialized secure TRNG (a peripheral distinct from the AES/HKDF engine). */
static int huk_trngInit = 0;
#endif

static int Rtl8735bHuk_Init(void* ctx)
{
    (void)ctx;
    /* One-time crypto engine bring-up. Idempotent on the HAL side. */
    if (hal_crypto_engine_init() != 0) {
        return WC_HW_E;
    }
    return 0;
}

/* Run the HUK key-ladder on the per-operation seed (the 32-byte HKDF input the
 * Aes carries in devKey): HUK (secure key slot) -> HKDF-Extract(secure) -> PRK
 * slot -> HKDF-Expand(secure) -> device-bound working key in the derived slot.
 * The working key never enters software; on return it resides in
 * WC_RTL8735B_DERIVED_WB_IDX, ready for an AES *_sk_init that references that
 * slot. The seed is passed by argument (not held in a global), so concurrent
 * Aes objects never race; the caller holds the crypto mutex across derive + op.
 *
 * The HUK is the built-in secure key at slot WC_RTL8735B_HUK_SK_IDX (HUK1); the
 * engine reads it internally. We deliberately do NOT lock the derived slot: each
 * operation re-derives the working key into it, and a locked key-storage slot
 * silently rejects that re-derivation (it would keep a stale key, so a different
 * seed would yield the wrong result). The slot is overwritten on the next
 * derive; nothing reads it back into software. */
static int Rtl8735bHuk_DeriveSlotKey(const byte* seed)
{
    XALIGNED(32) byte seedA[WC_RTL8735B_KEYLEN];

    if (seed == NULL) {
        return BAD_FUNC_ARG;
    }
#ifndef WC_RTL8735B_NO_DERIVE_CACHE
    /* If the derived slot already holds the working key for this exact seed,
     * skip the (two secure HMAC-SHA256 ops) HKDF ladder and reuse the slot. */
    if (huk_haveCache &&
            ConstantCompare(huk_seedCache, seed, WC_RTL8735B_KEYLEN) == 0) {
        return 0;
    }
    /* A fresh derive is starting; invalidate the cache until it succeeds so a
     * mid-ladder failure never leaves the cache claiming a stale slot. */
    huk_haveCache = 0;
#endif
    /* HKDF reads the seed via DMA -- pass it a 32-byte-aligned copy. */
    XMEMCPY(seedA, seed, WC_RTL8735B_KEYLEN);

    /* Init the secure HKDF HMAC-SHA256 engine (sets isHWCrypto_Init); required
     * before any *_secure_all call or extract returns HW_NOT_INIT. */
    if (hal_hkdf_hmac_sha256_secure_init((u8)WC_RTL8735B_HKDF_CRYPTO_SEL)
            != HAL_OK) {
        return WC_HW_E;
    }
    /* HKDF-Extract: PRK = HMAC(HUK, seed), into the PRK slot. */
    if (hal_hkdf_extract_secure_all((u8)WC_RTL8735B_HUK_SK_IDX,
            (u8)WC_RTL8735B_HKDF_PRK_IDX, seedA) != HAL_OK) {
        return WC_HW_E;
    }
    /* HKDF-Expand: OKM = working key, into the derived working-key slot. */
    if (hal_hkdf_expand_secure_all((u8)WC_RTL8735B_HKDF_PRK_IDX,
            (u8)WC_RTL8735B_DERIVED_WB_IDX, seedA) != HAL_OK) {
        return WC_HW_E;
    }
#ifndef WC_RTL8735B_NO_DERIVE_CACHE
    /* Slot now holds the working key for this seed; remember it. */
    XMEMCPY(huk_seedCache, seed, WC_RTL8735B_KEYLEN);
    huk_haveCache = 1;
#endif
    return 0;
}

#ifndef NO_AES

#ifdef HAVE_AESGCM
/* Full AES-GCM (encrypt or decrypt-verify) under a HUK-derived slot key. The HAL
 * assumes a 96-bit (12-byte) IV (standard J0); an unsupported IV length is a hard
 * BAD_FUNC_ARG. Do NOT return NOT_COMPILED_IN here -- the crypto-cb layer rewrites
 * it to CRYPTOCB_UNAVAILABLE, forcing an unwanted software GCM that would key off
 * the seed, not the device-bound key. */
static int Rtl8735bHuk_Gcm(int enc, const byte* seed, const byte* in,
    word32 sz, byte* out, const byte* iv, word32 ivSz, const byte* aad,
    word32 aadSz, byte* tag, word32 tagSz)
{
    int   ret;
    /* 16-byte aligned IV block: the HAL reads a full block, so the 4 bytes past
     * the 12-byte nonce must be zero and stable across calls. */
    XALIGNED(32) byte ivA[WC_AES_BLOCK_SIZE]   = { 0 };
    XALIGNED(32) byte hwTag[WC_AES_BLOCK_SIZE] = { 0 };
    const byte* inA  = in;       /* aligned views; bounced below if needed */
    const byte* aadA = aad;
    byte*       outA = out;
    byte* inBounce  = NULL;
    byte* outBounce = NULL;
    byte* aadBounce = NULL;

    /* Validate args before any copy/bounce/dereference: the crypto-callback
     * wrapper does not, so a bad caller would otherwise crash inside the HAL. */
    if (seed == NULL || iv == NULL) {
        return BAD_FUNC_ARG;
    }
    if (sz > 0 && (in == NULL || out == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (aadSz > 0 && aad == NULL) {
        return BAD_FUNC_ARG;
    }
    if (ivSz != GCM_NONCE_MID_SZ) {
        /* 12-byte IV only; hard error, NOT NOT_COMPILED_IN (see header). */
        return BAD_FUNC_ARG;
    }
    if (tag == NULL || tagSz == 0 || tagSz > WC_AES_BLOCK_SIZE) {
        return BAD_FUNC_ARG;
    }
    if (sz > WC_RTL8735B_BOUNCE_MAX || aadSz > WC_RTL8735B_BOUNCE_MAX) {
        return BAD_FUNC_ARG;   /* guard the (sz/aadSz + 31) bounce allocation */
    }

    /* Bounce any unaligned DMA buffer through a 32-byte-aligned temporary. iv
     * and tag are small and always staged on aligned stack buffers; in/out/aad
     * may be large, so are only copied when actually unaligned. */
    XMEMCPY(ivA, iv, GCM_NONCE_MID_SZ);
    ret = Rtl8735b_BounceIn(aad, aadSz, &aadA, &aadBounce);
    if (ret != 0) {
        goto cleanup;
    }
    ret = Rtl8735b_BounceIn(in, sz, &inA, &inBounce);
    if (ret != 0) {
        goto cleanup;
    }
    if (sz > 0 && !WC_RTL8735B_IS_ALIGNED32(out)) {
        ret = Rtl8735b_BounceOut(sz, &outA, &outBounce);
        if (ret != 0) {
            goto cleanup;
        }
    }
    if (sz == 0) {
        /* GMAC (empty payload): the caller's in/out may be NULL. Point the HAL at
         * a valid aligned buffer -- zero data bytes are processed, only the tag is
         * produced over the AAD. */
        inA  = ivA;
        outA = ivA;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        goto cleanup;
    }
    ret = Rtl8735bHuk_DeriveSlotKey(seed);
    if (ret != 0) {
        goto unlock;
    }
    if (hal_crypto_aes_gcm_sk_init((byte)WC_RTL8735B_DERIVED_WB_IDX,
            WC_RTL8735B_KEYLEN) != 0) {
        ret = WC_HW_E;
        goto unlock;
    }
    if (enc) {
        if (hal_crypto_aes_gcm_encrypt(inA, sz, ivA, aadA, aadSz, outA, hwTag)
                != 0) {
            ret = WC_HW_E;
            goto unlock;
        }
        XMEMCPY(tag, hwTag, tagSz);
        ret = 0;
    }
    else {
        if (hal_crypto_aes_gcm_decrypt(inA, sz, ivA, aadA, aadSz, outA, hwTag)
                != 0) {
            ret = WC_HW_E;
            goto unlock;
        }
        if (ConstantCompare(hwTag, tag, (int)tagSz) != 0) {
            if (outA != NULL && sz != 0) {
                ForceZero(outA, sz);
            }
            /* When out was bounced, outA is the heap bounce; also clear the
             * caller's out so the zero-on-auth-fail contract holds for the
             * unaligned (incl. in-place) case. */
            if (outBounce != NULL && sz != 0) {
                ForceZero(out, sz);
            }
            ret = AES_GCM_AUTH_E;
        }
        else {
            ret = 0;
        }
    }
    if (ret == 0 && outBounce != NULL) {
        XMEMCPY(out, outA, sz);
    }

unlock:
    ForceZero(hwTag, sizeof(hwTag));
    wolfSSL_CryptHwMutexUnLock();
cleanup:
    /* Scrub + free each bounce (the aligned views hold plaintext / AAD). */
    Rtl8735b_BounceFree(inBounce, (byte*)inA, sz);
    Rtl8735b_BounceFree(outBounce, outA, sz);
    Rtl8735b_BounceFree(aadBounce, (byte*)aadA, aadSz);
    return ret;
}
#endif /* HAVE_AESGCM */

#if defined(HAVE_AES_ECB) || defined(WOLFSSL_AES_DIRECT) || \
    defined(WOLF_CRYPTO_CB_ONLY_AES)
/* AES-ECB under a HUK-derived slot key. sz must be a multiple of the block.
 * Unaligned caller in/out are bounced through 32-byte-aligned temporaries (the
 * HAL DMAs its buffers on cache-line boundaries), so callers need not align.
 * Guarded to match its only call site (the WC_CIPHER_AES_ECB dispatch case);
 * CBC/CTR drive hal_crypto_aes_ecb_* directly, not this helper. */
static int Rtl8735bHuk_Ecb(int enc, const byte* seed, const byte* in,
    word32 sz, byte* out)
{
    int         ret = 0;
    const byte* inA  = in;
    byte*       outA = out;
    byte* inBounce  = NULL;
    byte* outBounce = NULL;

    if (seed == NULL || in == NULL || out == NULL ||
            sz == 0 || (sz % WC_AES_BLOCK_SIZE) != 0) {
        return BAD_FUNC_ARG;
    }
    if (sz > WC_RTL8735B_BOUNCE_MAX) {
        return BAD_FUNC_ARG;   /* guard the (sz + 31) bounce allocation */
    }
    ret = Rtl8735b_BounceIn(in, sz, &inA, &inBounce);
    if (ret != 0) {
        return ret;
    }
    if (!WC_RTL8735B_IS_ALIGNED32(out)) {
        ret = Rtl8735b_BounceOut(sz, &outA, &outBounce);
        if (ret != 0) {
            goto cleanup;
        }
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        goto cleanup;
    }
    ret = Rtl8735bHuk_DeriveSlotKey(seed);
    if (ret != 0) {
        goto unlock;
    }
    if (hal_crypto_aes_ecb_sk_init((byte)WC_RTL8735B_DERIVED_WB_IDX,
            WC_RTL8735B_KEYLEN) != 0) {
        ret = WC_HW_E;
        goto unlock;
    }
    if (enc) {
        ret = hal_crypto_aes_ecb_encrypt(inA, sz, NULL, 0, outA);
    }
    else {
        ret = hal_crypto_aes_ecb_decrypt(inA, sz, NULL, 0, outA);
    }
    if (ret != 0) {
        ret = WC_HW_E;
    }
    else if (outBounce != NULL) {
        XMEMCPY(out, outA, sz);
    }

unlock:
    wolfSSL_CryptHwMutexUnLock();
cleanup:
    Rtl8735b_BounceFree(inBounce, (byte*)inA, sz);   /* scrub + free (plaintext) */
    Rtl8735b_BounceFree(outBounce, outA, sz);
    return ret;
}
#endif /* HAVE_AES_ECB || WOLFSSL_AES_DIRECT || WOLF_CRYPTO_CB_ONLY_AES */

#ifdef HAVE_AES_CBC
/* AES-CBC under a HUK-derived slot key. The HAL has no CBC secure-key variant
 * (only ECB/GCM expose *_sk_init), so chain in software over single-block
 * ECB-sk operations -- the key still never leaves hardware. iv is the 16-byte
 * chaining block (aes->reg); on success it is advanced to the last ciphertext
 * block for the next call. Handles in == out (in-place) for both directions. */
static int Rtl8735bHuk_Cbc(int enc, const byte* seed, const byte* in,
    word32 sz, byte* out, byte* iv)
{
    int    ret;
    word32 off;
    XALIGNED(32) byte prev[WC_AES_BLOCK_SIZE];
    XALIGNED(32) byte blk[WC_AES_BLOCK_SIZE];
    XALIGNED(32) byte cur[WC_AES_BLOCK_SIZE];

    if (seed == NULL || in == NULL || out == NULL || iv == NULL ||
            sz == 0 || (sz % WC_AES_BLOCK_SIZE) != 0) {
        return BAD_FUNC_ARG;
    }
    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }
    ret = Rtl8735bHuk_DeriveSlotKey(seed);
    if (ret != 0) {
        goto out;
    }
    if (hal_crypto_aes_ecb_sk_init((byte)WC_RTL8735B_DERIVED_WB_IDX,
            WC_RTL8735B_KEYLEN) != 0) {
        ret = WC_HW_E;
        goto out;
    }

    XMEMCPY(prev, iv, WC_AES_BLOCK_SIZE);
    for (off = 0; off < sz; off += WC_AES_BLOCK_SIZE) {
        if (enc) {
            /* C_i = ECB_enc(P_i XOR C_{i-1}). The HAL DMAs its output on a
             * 32-byte boundary, so encrypt into the aligned temp cur, then copy
             * to the (possibly unaligned) out+off. Reads in+off before writing
             * out+off, so in-place (out == in) is safe. */
            xorbufout(blk, in + off, prev, WC_AES_BLOCK_SIZE);
            ret = hal_crypto_aes_ecb_encrypt(blk, WC_AES_BLOCK_SIZE, NULL, 0,
                                             cur);
            if (ret != 0) {
                ret = WC_HW_E;
                goto out;
            }
            XMEMCPY(out + off, cur, WC_AES_BLOCK_SIZE);
            XMEMCPY(prev, cur, WC_AES_BLOCK_SIZE);
        }
        else {
            /* P_i = ECB_dec(C_i) XOR C_{i-1}. Save C_i first: writing out+off
             * below would clobber it when out == in, and it is the next call's
             * chaining value. */
            XMEMCPY(cur, in + off, WC_AES_BLOCK_SIZE);
            ret = hal_crypto_aes_ecb_decrypt(cur, WC_AES_BLOCK_SIZE, NULL, 0,
                                             blk);
            if (ret != 0) {
                ret = WC_HW_E;
                goto out;
            }
            xorbufout(out + off, blk, prev, WC_AES_BLOCK_SIZE);
            XMEMCPY(prev, cur, WC_AES_BLOCK_SIZE);
        }
    }
    /* Advance the chaining IV to the last ciphertext block (prev holds it for
     * both directions); only on full success. */
    XMEMCPY(iv, prev, WC_AES_BLOCK_SIZE);
    ret = 0;

out:
    ForceZero(prev, sizeof(prev));
    ForceZero(blk, sizeof(blk));
    ForceZero(cur, sizeof(cur));
    wolfSSL_CryptHwMutexUnLock();
    return ret;
}
#endif /* HAVE_AES_CBC */

#ifdef WOLFSSL_AES_COUNTER
/* Increment the 16-byte big-endian counter in place. */
static void Rtl8735bHuk_IncCtr(byte* ctr)
{
    int i;
    for (i = WC_AES_BLOCK_SIZE - 1; i >= 0; i--) {
        if (++ctr[i] != 0) {
            break;
        }
    }
}

/* AES-CTR under a HUK-derived slot key. The HAL has no CTR secure-key variant,
 * so generate the keystream by ECB-sk encrypting the counter and XOR it with the
 * data -- the key never leaves hardware. Maintains the wolfCrypt CTR state:
 * aes->reg (counter), aes->tmp (current keystream block) and aes->left (unused
 * keystream bytes at the tail of aes->tmp) so partial blocks continue across
 * calls exactly as the software path does. The counter is staged on an aligned
 * stack buffer, so caller in/out alignment does not matter (only XORed here). */
static int Rtl8735bHuk_Ctr(Aes* aes, const byte* seed, const byte* in,
    word32 sz, byte* out)
{
    int    ret;
    word32 processed;
    XALIGNED(32) byte ctr[WC_AES_BLOCK_SIZE] = { 0 };
    XALIGNED(32) byte ks[WC_AES_BLOCK_SIZE]  = { 0 };

    if (aes == NULL || seed == NULL ||
            (sz != 0 && (in == NULL || out == NULL))) {
        return BAD_FUNC_ARG;   /* seed check for parity with Gcm/Ecb/Cbc */
    }

    /* If the whole request is covered by leftover keystream, no HW is needed:
     * consume it and return without touching the lock. */
    if (aes->left >= sz) {
        if (sz > 0) {
            xorbufout(out, in,
                      (byte*)aes->tmp + WC_AES_BLOCK_SIZE - aes->left, sz);
            aes->left -= sz;
        }
        return 0;
    }

    /* HW is needed -- take the lock before mutating any state, so a lock failure
     * leaves the CTR state and output untouched. */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }

    /* Derive/init the HW key first: a failure here must leave the output and CTR
     * state untouched, so the leftover-keystream consumption (below) only runs
     * once the hardware is ready. */
    ret = Rtl8735bHuk_DeriveSlotKey(seed);
    if (ret != 0) {
        goto out;
    }
    if (hal_crypto_aes_ecb_sk_init((byte)WC_RTL8735B_DERIVED_WB_IDX,
            WC_RTL8735B_KEYLEN) != 0) {
        ret = WC_HW_E;
        goto out;
    }

    /* Now consume any leftover keystream (all of it, since left < sz here). */
    processed = aes->left;
    if (processed > 0) {
        xorbufout(out, in,
                  (byte*)aes->tmp + WC_AES_BLOCK_SIZE - aes->left, processed);
        out += processed;
        in  += processed;
        aes->left = 0;
        sz  -= processed;
    }

    XMEMCPY(ctr, aes->reg, WC_AES_BLOCK_SIZE);
    while (sz >= WC_AES_BLOCK_SIZE) {
        ret = hal_crypto_aes_ecb_encrypt(ctr, WC_AES_BLOCK_SIZE, NULL, 0, ks);
        if (ret != 0) {
            ret = WC_HW_E;
            goto out;
        }
        xorbufout(out, in, ks, WC_AES_BLOCK_SIZE);
        Rtl8735bHuk_IncCtr(ctr);
        out += WC_AES_BLOCK_SIZE;
        in  += WC_AES_BLOCK_SIZE;
        sz  -= WC_AES_BLOCK_SIZE;
    }
    if (sz > 0) {
        /* Final partial block: keep the unused keystream for the next call. */
        ret = hal_crypto_aes_ecb_encrypt(ctr, WC_AES_BLOCK_SIZE, NULL, 0, ks);
        if (ret != 0) {
            ret = WC_HW_E;
            goto out;
        }
        XMEMCPY(aes->tmp, ks, WC_AES_BLOCK_SIZE);
        xorbufout(out, in, ks, sz);
        Rtl8735bHuk_IncCtr(ctr);
        aes->left = WC_AES_BLOCK_SIZE - sz;
    }
    XMEMCPY(aes->reg, ctr, WC_AES_BLOCK_SIZE);
    ret = 0;

out:
    ForceZero(ks, sizeof(ks));
    ForceZero(ctr, sizeof(ctr));
    wolfSSL_CryptHwMutexUnLock();
    return ret;
}
#endif /* WOLFSSL_AES_COUNTER */

/* The 256-bit seed an Aes carries in devKey (set via the normal key API) is the
 * per-operation HKDF input. Point *seed at it, or return CRYPTOCB_UNAVAILABLE if
 * this is not a 256-bit seed key (so non-HUK keys fall back to software). */
static int Rtl8735bHuk_AesSeed(Aes* aes, const byte** seed)
{
    if (aes == NULL || aes->keylen != WC_RTL8735B_KEYLEN) {
        return CRYPTOCB_UNAVAILABLE;
    }
    *seed = (const byte*)aes->devKey;
    return 0;
}

static int Rtl8735bHuk_Cipher(struct wc_CryptoInfo* info)
{
    int ret;
    const byte* seed = NULL;

    switch (info->cipher.type) {
#if defined(HAVE_AES_ECB) || defined(WOLFSSL_AES_DIRECT) || \
    defined(WOLF_CRYPTO_CB_ONLY_AES)
    case WC_CIPHER_AES_ECB:
        ret = Rtl8735bHuk_AesSeed(info->cipher.aesecb.aes, &seed);
        if (ret != 0) {
            return ret;
        }
        return Rtl8735bHuk_Ecb(info->cipher.enc, seed, info->cipher.aesecb.in,
                                info->cipher.aesecb.sz, info->cipher.aesecb.out);
#endif
#if defined(HAVE_AES_CBC)
    case WC_CIPHER_AES_CBC:
        ret = Rtl8735bHuk_AesSeed(info->cipher.aescbc.aes, &seed);
        if (ret != 0) {
            return ret;
        }
        /* Rtl8735bHuk_Cbc advances aes->reg (the chaining IV) itself, correctly
         * for in-place and both directions. */
        return Rtl8735bHuk_Cbc(info->cipher.enc, seed, info->cipher.aescbc.in,
                                info->cipher.aescbc.sz, info->cipher.aescbc.out,
                                (byte*)info->cipher.aescbc.aes->reg);
#endif
#ifdef WOLFSSL_AES_COUNTER
    case WC_CIPHER_AES_CTR:
        ret = Rtl8735bHuk_AesSeed(info->cipher.aesctr.aes, &seed);
        if (ret != 0) {
            return ret;
        }
        return Rtl8735bHuk_Ctr(info->cipher.aesctr.aes, seed,
                                info->cipher.aesctr.in, info->cipher.aesctr.sz,
                                info->cipher.aesctr.out);
#endif
#ifdef HAVE_AESGCM
    case WC_CIPHER_AES_GCM:
        if (info->cipher.enc) {
            ret = Rtl8735bHuk_AesSeed(info->cipher.aesgcm_enc.aes, &seed);
            if (ret != 0) {
                return ret;
            }
            return Rtl8735bHuk_Gcm(1, seed,
                                    info->cipher.aesgcm_enc.in,
                                    info->cipher.aesgcm_enc.sz,
                                    info->cipher.aesgcm_enc.out,
                                    info->cipher.aesgcm_enc.iv,
                                    info->cipher.aesgcm_enc.ivSz,
                                    info->cipher.aesgcm_enc.authIn,
                                    info->cipher.aesgcm_enc.authInSz,
                                    info->cipher.aesgcm_enc.authTag,
                                    info->cipher.aesgcm_enc.authTagSz);
        }
        else {
            ret = Rtl8735bHuk_AesSeed(info->cipher.aesgcm_dec.aes, &seed);
            if (ret != 0) {
                return ret;
            }
            return Rtl8735bHuk_Gcm(0, seed,
                                    info->cipher.aesgcm_dec.in,
                                    info->cipher.aesgcm_dec.sz,
                                    info->cipher.aesgcm_dec.out,
                                    info->cipher.aesgcm_dec.iv,
                                    info->cipher.aesgcm_dec.ivSz,
                                    info->cipher.aesgcm_dec.authIn,
                                    info->cipher.aesgcm_dec.authInSz,
                                    /* authTag is const (input-only on decrypt);
                                     * Rtl8735bHuk_Gcm reads it via ConstantCompare
                                     * and never writes it on the decrypt (enc==0)
                                     * path, so dropping const here is safe. */
                                    (byte*)info->cipher.aesgcm_dec.authTag,
                                    info->cipher.aesgcm_dec.authTagSz);
        }
#endif
    default:
        return CRYPTOCB_UNAVAILABLE;
    }
}
#endif /* !NO_AES */

#if !defined(NO_HMAC) && !defined(NO_SHA256)
/* HUK-bound HMAC-SHA256 over a secure-key slot. wc_HmacUpdate is incremental but
 * the HAL sk_init->update->sk_final state cannot span those calls under one mutex
 * hold, so the message is accumulated into a heap buffer and MAC'd one-shot at
 * final (suits short HUK MAC / KDF use). The buffer hangs off the inner SHA-256
 * devCtx, NOT hmac->devCtx: the latter has no cryptocb copy/free op and
 * wc_HmacCopy aliases it (-> double free); the SHA-256 devCtx fires
 * WC_ALGO_TYPE_COPY/FREE so the buffer is deep-copied and freed once. Needs
 * WOLF_CRYPTO_CB_COPY + WOLF_CRYPTO_CB_FREE. */
#if !defined(WOLF_CRYPTO_CB_COPY) || !defined(WOLF_CRYPTO_CB_FREE)
    #error "RTL8735B HUK HMAC needs WOLF_CRYPTO_CB_COPY and WOLF_CRYPTO_CB_FREE"
#endif
typedef struct Rtl8735bHmacCtx {
    byte*  buf;
    word32 len;
    word32 cap;
} Rtl8735bHmacCtx;

/* Free the accumulation buffer + ctx hung off a SHA-256 context's devCtx (the
 * WC_ALGO_TYPE_FREE handler, and the one-shot free after Final). No-op if none. */
static void Rtl8735bHuk_HmacFreeSha(wc_Sha256* sha)
{
    Rtl8735bHmacCtx* ctx;
    if (sha == NULL) {
        return;
    }
    ctx = (Rtl8735bHmacCtx*)sha->devCtx;
    if (ctx != NULL) {
        if (ctx->buf != NULL) {
            ForceZero(ctx->buf, ctx->cap);   /* cleartext message material */
            XFREE(ctx->buf, sha->heap, DYNAMIC_TYPE_HMAC);
        }
        XFREE(ctx, sha->heap, DYNAMIC_TYPE_HMAC);
        sha->devCtx = NULL;
    }
}

/* Deep-copy the accumulation buffer from src's SHA-256 devCtx to dst's (the
 * WC_ALGO_TYPE_COPY handler). wc_Sha256Copy has already shallow-copied
 * dst->devCtx = src->devCtx (an alias); replace it with an owned copy. */
static int Rtl8735bHuk_HmacCopySha(wc_Sha256* src, wc_Sha256* dst)
{
    Rtl8735bHmacCtx* s;
    Rtl8735bHmacCtx* d;

    if (src == NULL || dst == NULL) {
        return BAD_FUNC_ARG;
    }
    /* wc_Sha256Copy returns as soon as this handler returns 0, skipping the struct
     * copy that carries devId/heap (wc_HmacCopy has zeroed dst->hash). Carry them
     * over so a later copy/free of dst routes back here (else free misroutes and
     * leaks); set heap before the XMALLOCs. */
    dst->devId = src->devId;
    dst->heap  = src->heap;
    s = (Rtl8735bHmacCtx*)src->devCtx;
    if (s == NULL) {
        dst->devCtx = NULL;              /* nothing accumulated on src */
        return 0;
    }
    d = (Rtl8735bHmacCtx*)XMALLOC(sizeof(Rtl8735bHmacCtx), dst->heap,
                                  DYNAMIC_TYPE_HMAC);
    if (d == NULL) {
        dst->devCtx = NULL;              /* drop the alias; do not free src's */
        return MEMORY_E;
    }
    d->len = s->len;
    d->cap = s->len;                     /* copy exactly what is used */
    d->buf = NULL;
    if (s->len > 0) {
        d->buf = (byte*)XMALLOC(s->len, dst->heap, DYNAMIC_TYPE_HMAC);
        if (d->buf == NULL) {
            XFREE(d, dst->heap, DYNAMIC_TYPE_HMAC);
            dst->devCtx = NULL;
            return MEMORY_E;
        }
        XMEMCPY(d->buf, s->buf, s->len);
    }
    dst->devCtx = d;
    return 0;
}

/* Append a message chunk to the accumulation buffer (grown geometric), stored on
 * the inner SHA-256 devCtx. On allocation failure the partial buffer is released
 * by the SHA-256 free op (WC_ALGO_TYPE_FREE) at wc_HmacFree. */
static int Rtl8735bHuk_HmacAccumulate(Hmac* hmac, const byte* in, word32 inSz)
{
    wc_Sha256* sha = &hmac->hash.sha256;
    Rtl8735bHmacCtx* ctx;
    byte*  nb;
    word32 need;
    word32 newCap;
    word32 dbl;

    if (inSz == 0) {
        return 0;
    }
    if (in == NULL) {
        return BAD_FUNC_ARG;
    }
    ctx = (Rtl8735bHmacCtx*)sha->devCtx;
    if (ctx == NULL) {
        /* DYNAMIC_TYPE_HMAC, not _TMP_BUFFER: this context + its growing buffer
         * live across Update calls until Final/Free, not within one call. */
        ctx = (Rtl8735bHmacCtx*)XMALLOC(sizeof(Rtl8735bHmacCtx), sha->heap,
                                         DYNAMIC_TYPE_HMAC);
        if (ctx == NULL) {
            return MEMORY_E;
        }
        ctx->buf = NULL;
        ctx->len = 0;
        ctx->cap = 0;
        sha->devCtx = ctx;
    }
    need = ctx->len + inSz;
    if (need < ctx->len) {              /* word32 overflow */
        return BUFFER_E;
    }
#ifdef WC_RTL8735B_HMAC_MAX_MSG
    /* Optional misuse guard: HUK HMAC buffers the whole message, so cap it. */
    if (WC_RTL8735B_HMAC_MAX_MSG != 0 &&
            need > (word32)WC_RTL8735B_HMAC_MAX_MSG) {
        return BUFFER_E;
    }
#endif
    if (need > ctx->cap) {
        newCap = (ctx->cap == 0) ? inSz : ctx->cap;
        while (newCap < need) {
            dbl = newCap << 1;
            if (dbl < newCap) {         /* overflow -> clamp to exact need */
                newCap = need;
                break;
            }
            newCap = dbl;
        }
        nb = (byte*)XREALLOC(ctx->buf, newCap, sha->heap,
                             DYNAMIC_TYPE_HMAC);
        if (nb == NULL) {
            return MEMORY_E;
        }
        ctx->buf = nb;
        ctx->cap = newCap;
    }
    XMEMCPY(ctx->buf + ctx->len, in, inSz);
    ctx->len += inSz;
    return 0;
}

/* Free the accumulation buffer for an Hmac (one-shot free after Final). The
 * WC_ALGO_TYPE_FREE op at wc_HmacFree also frees it via Rtl8735bHuk_HmacFreeSha. */
static void Rtl8735bHuk_HmacFreeCtx(Hmac* hmac)
{
    Rtl8735bHuk_HmacFreeSha(&hmac->hash.sha256);
}

/* Compute HMAC-SHA256(message) under the HUK-derived slot key. The slot key is
 * loaded by sk_cfg (LD_SK from WC_RTL8735B_DERIVED_WB_IDX); the key passed to
 * sk_init is unused in that mode but a valid aligned buffer is supplied so the
 * HAL never dereferences NULL. */
static int Rtl8735bHuk_Hmac(const byte* seed, const byte* msg, word32 msgSz,
    byte* digest)
{
    int    ret;
    u32    skCfg;
    const byte* msgA = msg;
    byte*  msgBounce = NULL;
    XALIGNED(32) byte dummyKey[WC_RTL8735B_KEYLEN] = { 0 };
    XALIGNED(32) byte digA[WC_SHA256_DIGEST_SIZE]   = { 0 };

    if (seed == NULL || digest == NULL) {
        return BAD_FUNC_ARG;
    }
    if (msgSz > 0 && msg == NULL) {
        return BAD_FUNC_ARG;
    }
    if (msgSz > WC_RTL8735B_BOUNCE_MAX) {
        return BAD_FUNC_ARG;   /* guard the (msgSz + 31) bounce allocation */
    }
    /* The HAL DMAs the message; the accumulation buffer is not guaranteed
     * 32-byte aligned, so stage an unaligned one on an aligned temp. */
    ret = Rtl8735b_BounceIn(msg, msgSz, &msgA, &msgBounce);
    if (ret != 0) {
        return ret;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        goto cleanup;
    }
    ret = Rtl8735bHuk_DeriveSlotKey(seed);
    if (ret != 0) {
        goto unlock;
    }
    skCfg = (u32)hal_crypto_hmac_sha2_256_get_sk_cfg(
                (u8)WC_RTL8735B_HMAC_SK_OP, (u8)WC_RTL8735B_DERIVED_WB_IDX,
                (u8)WC_RTL8735B_HMAC_WB_OP, (u8)WC_RTL8735B_HMAC_WB_IDX);
    if (hal_crypto_hmac_sha2_256_sk_init(dummyKey, skCfg) != 0) {
        ret = WC_HW_E;
        goto unlock;
    }
    if (msgSz > 0) {
        if (hal_crypto_hmac_sha2_256_update(msgA, msgSz) != 0) {
            ret = WC_HW_E;
            goto unlock;
        }
    }
    if (hal_crypto_hmac_sha2_256_sk_final(digA) != 0) {
        ret = WC_HW_E;
        goto unlock;
    }
    XMEMCPY(digest, digA, WC_SHA256_DIGEST_SIZE);
    ret = 0;

unlock:
    ForceZero(digA, sizeof(digA));
    wolfSSL_CryptHwMutexUnLock();
cleanup:
    Rtl8735b_BounceFree(msgBounce, (byte*)msgA, msgSz);   /* scrub + free message */
    return ret;
}

/* Route an HMAC request to the HUK backend. Handles only HMAC-SHA256 keyed by a
 * 32-byte HUK seed (the seed is the wc_HmacSetKey key, read from hmac->keyRaw);
 * anything else returns CRYPTOCB_UNAVAILABLE for software fallback. Update calls
 * (digest == NULL) accumulate; the final call (digest != NULL) produces the MAC
 * and frees the buffer. The HmacFree cleanup callback also arrives as a final
 * call with a throwaway digest; computing into it is harmless. */
static int Rtl8735bHuk_HmacCb(struct wc_CryptoInfo* info)
{
    Hmac*       hmac = info->hmac.hmac;
    const byte* seed;
    const byte* msg   = NULL;
    word32      msgSz = 0;
    Rtl8735bHmacCtx* ctx;
    int ret;

    if (hmac == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (info->hmac.macType != WC_SHA256 ||
            hmac->keyLen != WC_RTL8735B_KEYLEN || hmac->keyRaw == NULL) {
        /* Not our op. If this is a final/cleanup call (digest != NULL) and an
         * accumulation buffer is still attached -- e.g. an Hmac re-keyed to a
         * non-32-byte key after some Update calls, or wc_HmacFree -- free it
         * here so it cannot leak; the guard would short-circuit any later
         * free path too. HmacFreeCtx is a no-op when devCtx is NULL. */
        if (info->hmac.digest != NULL) {
            Rtl8735bHuk_HmacFreeCtx(hmac);
        }
        return CRYPTOCB_UNAVAILABLE;
    }
    seed = hmac->keyRaw;

    if (info->hmac.digest == NULL) {
        return Rtl8735bHuk_HmacAccumulate(hmac, info->hmac.in,
                                           info->hmac.inSz);
    }
    ctx = (Rtl8735bHmacCtx*)hmac->hash.sha256.devCtx;
    if (ctx != NULL) {
        msg   = ctx->buf;
        msgSz = ctx->len;
    }
    ret = Rtl8735bHuk_Hmac(seed, msg, msgSz, info->hmac.digest);
    Rtl8735bHuk_HmacFreeCtx(hmac);
    return ret;
}
#endif /* !NO_HMAC && !NO_SHA256 */

#if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN)
/* The HUK-wrapped ECDSA scalar is AES-GCM decrypt-verified at unwrap
 * (Rtl8735bHuk_UnwrapScalar reuses Rtl8735bHuk_Gcm), so the ECDSA sign path
 * requires AES-GCM. */
#ifndef HAVE_AESGCM
    #error "RTL8735B HUK ECDSA needs HAVE_AESGCM (GCM-authenticated scalar unwrap)"
#endif

/* Big integers cross the HAL as little-endian 32-bit word arrays (word[0] =
 * least-significant limb), matching the SDK mbedTLS _alt bridge. ECC sizing
 * (WC_RTL8735B_ECC_BYTES/_WORDS) is defined near the top of this file. */

/* Scratch buffers for one HW ECDSA sign (~0.25KB). Heap-allocated under
 * WOLFSSL_SMALL_STACK (see Rtl8735bHuk_EccSignHw), on the stack otherwise. */
typedef struct Rtl8735bEccSignTmp {
    word32 hashW[WC_RTL8735B_ECC_WORDS];
    word32 kW[WC_RTL8735B_ECC_WORDS];
    word32 scW[WC_RTL8735B_ECC_WORDS];
    word32 rW[WC_RTL8735B_ECC_WORDS];
    word32 sW[WC_RTL8735B_ECC_WORDS];
    byte   be[WC_RTL8735B_ECC_BYTES];
    byte   rBe[WC_RTL8735B_ECC_BYTES];
    byte   sBe[WC_RTL8735B_ECC_BYTES];
} Rtl8735bEccSignTmp;

#ifdef HAVE_ECC_VERIFY
/* Scratch buffers for one HW ECDSA verify (heap-allocated under
 * WOLFSSL_SMALL_STACK, see Rtl8735bHuk_EccVerifyHw). */
typedef struct Rtl8735bEccVeriTmp {
    word32 qxW[WC_RTL8735B_ECC_WORDS];
    word32 qyW[WC_RTL8735B_ECC_WORDS];
    word32 rW[WC_RTL8735B_ECC_WORDS];
    word32 sW[WC_RTL8735B_ECC_WORDS];
    word32 hashW[WC_RTL8735B_ECC_WORDS];
    byte   qxBe[WC_RTL8735B_ECC_BYTES];
    byte   qyBe[WC_RTL8735B_ECC_BYTES];
    byte   rBe[WC_RTL8735B_ECC_BYTES];
    byte   sBe[WC_RTL8735B_ECC_BYTES];
    byte   hashBe[WC_RTL8735B_ECC_BYTES];
    byte   rDec[WC_RTL8735B_ECC_BYTES];  /* raw r from wc_ecc_sig_to_rs */
    byte   sDec[WC_RTL8735B_ECC_BYTES];  /* raw s from wc_ecc_sig_to_rs */
} Rtl8735bEccVeriTmp;
#endif

/* 32 big-endian bytes -> WC_RTL8735B_ECC_WORDS little-endian words. */
static void Rtl8735b_BeToLeWords(const byte* be, word32* w)
{
    int j;
    const byte* p;
    for (j = 0; j < WC_RTL8735B_ECC_WORDS; j++) {
        p = be + (WC_RTL8735B_ECC_BYTES - 4 * (j + 1));
        w[j] = ((word32)p[0] << 24) | ((word32)p[1] << 16) |
               ((word32)p[2] <<  8) |  (word32)p[3];
    }
}

/* Little-endian words -> 32 big-endian bytes (inverse of Rtl8735b_BeToLeWords). */
static void Rtl8735b_LeWordsToBe(const word32* w, byte* be)
{
    int j;
    byte* p;
    for (j = 0; j < WC_RTL8735B_ECC_WORDS; j++) {
        p = be + (WC_RTL8735B_ECC_BYTES - 4 * (j + 1));
        p[0] = (byte)(w[j] >> 24);
        p[1] = (byte)(w[j] >> 16);
        p[2] = (byte)(w[j] >>  8);
        p[3] = (byte)(w[j]);
    }
}

/* The HW ECDSA completion state (huk_ecdsaDone/Err/R/S/veriResult) is defined
 * near the top of this file with the other module state. */

/* ECDSA finish-interrupt callback (registered via hal_ecdsa_cb_handler): read
 * the error status and r,s, then flag completion. Mirrors the RealTek example. */
static void Rtl8735bHuk_EcdsaIrqCb(void* data)
{
    hal_ecdsa_adapter_t* a = (hal_ecdsa_adapter_t*)data;
    huk_ecdsaErr = (word32)hal_ecdsa_get_err_sta(a);
    hal_ecdsa_get_rs(a, (u32*)huk_ecdsaR, (u32*)huk_ecdsaS);
    huk_ecdsaDone = 1;
}

#ifdef HAVE_ECC_VERIFY
/* ECDSA verify finish-interrupt callback: read the verify error status and the
 * pass result (ECDSA_BIT_VERIFY_PASS -> non-zero == verified), then flag done. */
static void Rtl8735bHuk_EcdsaVeriIrqCb(void* data)
{
    hal_ecdsa_adapter_t* a = (hal_ecdsa_adapter_t*)data;
    huk_ecdsaErr   = (word32)hal_ecdsa_get_veri_err_sta(a);
    huk_veriResult = (word32)hal_ecdsa_get_veri_result(a);
    huk_ecdsaDone  = 1;
}
#endif

/* Right-align the message hash into a 32-byte big-endian block (leftmost 256
 * bits of the digest), zero-padded on the left. Caller converts to LE words. */
static void Rtl8735b_PadHashBe(const byte* hash, word32 hashlen, byte* be32)
{
    if (hashlen >= WC_RTL8735B_ECC_BYTES) {
        XMEMCPY(be32, hash, WC_RTL8735B_ECC_BYTES);
    }
    else {
        XMEMSET(be32, 0, WC_RTL8735B_ECC_BYTES);
        XMEMCPY(be32 + (WC_RTL8735B_ECC_BYTES - hashlen), hash, hashlen);
    }
}

/* Busy-wait for the ECDSA finish IRQ (sets huk_ecdsaDone), bounded by
 * WC_RTL8735B_ECDSA_SPIN; WC_RTL8735B_ECDSA_YIELD is an optional RTOS yield. */
static void Rtl8735b_EcdsaSpin(void)
{
    long spin;
    for (spin = 0; spin < WC_RTL8735B_ECDSA_SPIN && huk_ecdsaDone == 0; spin++) {
        WC_RTL8735B_ECDSA_YIELD();
    }
}

/* Generate a per-signature nonce k in [1, n-1] from the RNG, as LE words. The
 * curve order n comes from the wolfCrypt curve params (dp->order). */
static int Rtl8735b_GenK(WC_RNG* rng, const ecc_set_type* dp, word32* kW)
{
    byte   be[WC_RTL8735B_ECC_BYTES];
#ifdef WOLFSSL_SMALL_STACK
    mp_int* k;
    mp_int* n;
#else
    mp_int  k[1];   /* mp_int can be multi-KB with fastmath; heap on small stack */
    mp_int  n[1];
#endif
    int    ret;
    int    i;
    int    ok = 0;

    if (rng == NULL || dp == NULL) {
        return BAD_FUNC_ARG;
    }
#ifdef WOLFSSL_SMALL_STACK
    k = (mp_int*)XMALLOC(sizeof(mp_int) * 2, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (k == NULL) {
        return MEMORY_E;
    }
    n = k + 1;
#endif
    ret = mp_init_multi(k, n, NULL, NULL, NULL, NULL);
    if (ret != 0) {
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(k, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
        return ret;
    }
    ret = mp_read_radix(n, dp->order, MP_RADIX_HEX);
    for (i = 0; ret == 0 && ok == 0 && i < 16; i++) {
        ret = wc_RNG_GenerateBlock(rng, be, WC_RTL8735B_ECC_BYTES);
        if (ret != 0) {
            break;
        }
        ret = mp_read_unsigned_bin(k, be, WC_RTL8735B_ECC_BYTES);
        if (ret != 0) {
            break;
        }
        if (!mp_iszero(k) && mp_cmp(k, n) == MP_LT) {
            ok = 1;
        }
    }
    if (ret == 0 && ok == 0) {
        ret = RNG_FAILURE_E;
    }
    if (ret == 0) {
        ret = mp_to_unsigned_bin_len(k, be, WC_RTL8735B_ECC_BYTES);
        if (ret == 0) {
            Rtl8735b_BeToLeWords(be, kW);
        }
    }
    ForceZero(be, sizeof(be));
    mp_forcezero(k);
    mp_clear(n);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(k, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return ret;
}

/* Sign info->pk.eccsign over the HW ECDSA engine (P-256). The private scalar is
 * either the unwrapped INPUT scalar (otpPrkSel == 0) or sourced from OTP via
 * select_prk (otpPrkSel != 0, scalar never in software). On success the DER
 * signature is written to info->pk.eccsign.out/outlen.
 *
 * Follows the RealTek hal_ecdsa reference flow: set_curve(ECDSA_P256, NULL) uses
 * the engine's built-in P-256 constants (no curve table needed); load the
 * private key + nonce via hal_ecdsa_signature, then hal_ecdsa_hash marks the
 * hash ready, which STARTS the engine; completion arrives via the finish IRQ
 * (hal_ecdsa_cb_handler -> Rtl8735bHuk_EcdsaIrqCb). Big integers cross the HAL
 * as little-endian 32-bit word arrays. This is the opt-in useHwEngine path; the
 * default software sign delegates to wc_ecc_sign_hash. */
static int Rtl8735bHuk_EccSignHw(struct wc_CryptoInfo* info,
    const wc_Rtl8735b_EccKey* hk, const byte* scalar, word32 scalarSz)
{
    ecc_key* key = info->pk.eccsign.key;
#ifdef WOLFSSL_SMALL_STACK
    Rtl8735bEccSignTmp* t;
#else
    Rtl8735bEccSignTmp  t[1];
#endif
    int    ret;
    int    useOtp = (hk != NULL && hk->otpPrkSel != 0);

    /* The HW engine here is wired for P-256 (secp256r1). PkSign only routes P-256
     * here; this is a defensive hard error (not CRYPTOCB_UNAVAILABLE, which would
     * make the core retry a software sign on the keyless HUK device key). */
    if (key->dp == NULL || key->dp->size != WC_RTL8735B_ECC_BYTES ||
            key->dp->id != ECC_SECP256R1) {
        return BAD_FUNC_ARG;
    }
#ifdef WOLFSSL_SMALL_STACK
    t = (Rtl8735bEccSignTmp*)XMALLOC(sizeof(*t), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (t == NULL) {
        return MEMORY_E;
    }
#endif
    XMEMSET(t, 0, sizeof(*t));

    Rtl8735b_PadHashBe(info->pk.eccsign.in, info->pk.eccsign.inlen, t->be);
    Rtl8735b_BeToLeWords(t->be, t->hashW);

    ret = Rtl8735b_GenK(info->pk.eccsign.rng, key->dp, t->kW);
    if (ret != 0) {
        goto done;
    }
    if (!useOtp) {
        if (scalar == NULL || scalarSz == 0 ||
                scalarSz > WC_RTL8735B_ECC_BYTES) {
            ret = BAD_FUNC_ARG;
            goto done;
        }
        XMEMSET(t->be, 0, sizeof(t->be));
        XMEMCPY(t->be + (WC_RTL8735B_ECC_BYTES - scalarSz), scalar, scalarSz);
        Rtl8735b_BeToLeWords(t->be, t->scW);
    }

    XMEMSET(&huk_ecdsaAdapter, 0, sizeof(huk_ecdsaAdapter));
    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        goto done;
    }
    if (hal_ecdsa_init(&huk_ecdsaAdapter) != 0) {
        ret = WC_HW_E;
        goto unlock;
    }
    huk_ecdsaDone = 0;
    huk_ecdsaErr  = 0;
    hal_ecdsa_cb_handler(&huk_ecdsaAdapter,
                         (ecdsa_irq_user_cb_t)Rtl8735bHuk_EcdsaIrqCb, &huk_ecdsaAdapter);
    /* P-256: NULL curve table -> the engine uses its built-in constants. */
    hal_ecdsa_set_curve(&huk_ecdsaAdapter, ECDSA_P256, NULL, ECDSA_256_BIT);
    hal_ecdsa_set_mode(&huk_ecdsaAdapter, ECDSA_SIGN, ECDSA_NONE);
    if (useOtp) {
        hal_ecdsa_select_prk(&huk_ecdsaAdapter, (ecdsa_sel_prk_t)hk->otpPrkSel);
    }
    /* Load priv + nonce, then mark the hash ready -- that starts the engine.
     * The HAL word pointers are the vendor u32 type (not necessarily wolfCrypt's
     * word32 on this ABI), so cast the 32-bit word arrays at the boundary. */
    hal_ecdsa_signature(&huk_ecdsaAdapter, (u32*)(useOtp ? NULL : t->scW), (u32*)t->kW);
    hal_ecdsa_hash(&huk_ecdsaAdapter, (u32*)t->hashW);

    /* Wait for the finish IRQ (the callback reads err + r,s and sets the flag). */
    Rtl8735b_EcdsaSpin();
    hal_ecdsa_deinit(&huk_ecdsaAdapter);

    if (huk_ecdsaDone == 0) {
        ret = WC_HW_E;
    }
    else if (huk_ecdsaErr != 0) {
        ret = WC_HW_E;
    }
    else {
        XMEMCPY(t->rW, huk_ecdsaR, sizeof(t->rW));
        XMEMCPY(t->sW, huk_ecdsaS, sizeof(t->sW));
        ret = 0;
    }
unlock:
    wolfSSL_CryptHwMutexUnLock();
    if (ret == 0) {
        Rtl8735b_LeWordsToBe(t->rW, t->rBe);
        Rtl8735b_LeWordsToBe(t->sW, t->sBe);
        ret = wc_ecc_rs_raw_to_sig(t->rBe, WC_RTL8735B_ECC_BYTES,
                                   t->sBe, WC_RTL8735B_ECC_BYTES,
                                   info->pk.eccsign.out, info->pk.eccsign.outlen);
    }
done:
    ForceZero(t, sizeof(*t));   /* scrub nonce + scalar (and the rest) */
#ifdef WOLFSSL_SMALL_STACK
    XFREE(t, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return ret;
}

#ifdef HAVE_ECC_VERIFY
/* Verify an ECDSA P-256 signature over the HW engine (general offload; any
 * P-256 public key, no HUK context needed). Sets *res = 1 if the signature
 * verifies, 0 otherwise. Same engine flow as sign: load inputs (here the public
 * key + r + s via hal_ecdsa_verify), then hal_ecdsa_hash marks the hash ready to
 * start; completion via the verify finish IRQ (ECDSA_BIT_VERIFY_PASS). */
static int Rtl8735bHuk_EccVerifyHw(struct wc_CryptoInfo* info)
{
    ecc_key* key = info->pk.eccverify.key;
    hal_ecdsa_veri_input_t vin;
#ifdef WOLFSSL_SMALL_STACK
    Rtl8735bEccVeriTmp* t;
#else
    Rtl8735bEccVeriTmp  t[1];
#endif
    word32 qxLen, qyLen, rLen, sLen;
    int    ret;

    if (key == NULL || info->pk.eccverify.res == NULL || key->dp == NULL ||
            key->dp->id != ECC_SECP256R1) {
        return CRYPTOCB_UNAVAILABLE;     /* non-P256 -> software verify */
    }
    *info->pk.eccverify.res = 0;
#ifdef WOLFSSL_SMALL_STACK
    t = (Rtl8735bEccVeriTmp*)XMALLOC(sizeof(*t), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (t == NULL) {
        return MEMORY_E;
    }
#endif
    XMEMSET(t, 0, sizeof(*t));

    qxLen = WC_RTL8735B_ECC_BYTES;
    qyLen = WC_RTL8735B_ECC_BYTES;
    ret = wc_ecc_export_public_raw(key, t->qxBe, &qxLen, t->qyBe, &qyLen);
    if (ret != 0 || qxLen != WC_RTL8735B_ECC_BYTES ||
            qyLen != WC_RTL8735B_ECC_BYTES) {
        ret = CRYPTOCB_UNAVAILABLE;      /* fall back to software verify */
        goto done;
    }
    Rtl8735b_BeToLeWords(t->qxBe, t->qxW);
    Rtl8735b_BeToLeWords(t->qyBe, t->qyW);

    /* DER signature -> raw r,s -> right-aligned 32 bytes -> LE words. Decode
     * into dedicated rDec/sDec scratch (never the public-key or hash buffers),
     * then zero-extend into rBe/sBe. */
    rLen = WC_RTL8735B_ECC_BYTES;
    sLen = WC_RTL8735B_ECC_BYTES;
    ret = wc_ecc_sig_to_rs(info->pk.eccverify.sig, info->pk.eccverify.siglen,
                           t->rDec, &rLen, t->sDec, &sLen);
    if (ret != 0 || rLen > WC_RTL8735B_ECC_BYTES ||
            sLen > WC_RTL8735B_ECC_BYTES) {
        ret = CRYPTOCB_UNAVAILABLE;
        goto done;
    }
    XMEMCPY(t->rBe + (WC_RTL8735B_ECC_BYTES - rLen), t->rDec, rLen);
    Rtl8735b_BeToLeWords(t->rBe, t->rW);
    XMEMCPY(t->sBe + (WC_RTL8735B_ECC_BYTES - sLen), t->sDec, sLen);
    Rtl8735b_BeToLeWords(t->sBe, t->sW);

    Rtl8735b_PadHashBe(info->pk.eccverify.hash, info->pk.eccverify.hashlen,
                       t->hashBe);
    Rtl8735b_BeToLeWords(t->hashBe, t->hashW);

    XMEMSET(&huk_ecdsaAdapter, 0, sizeof(huk_ecdsaAdapter));
    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        goto done;
    }
    if (hal_ecdsa_init(&huk_ecdsaAdapter) != 0) {
        ret = WC_HW_E;
        goto unlock;
    }
    huk_ecdsaDone  = 0;
    huk_ecdsaErr   = 0;
    huk_veriResult = 0;
    hal_ecdsa_cb_handler(&huk_ecdsaAdapter,
                         (ecdsa_irq_user_cb_t)Rtl8735bHuk_EcdsaVeriIrqCb,
                         &huk_ecdsaAdapter);
    hal_ecdsa_set_curve(&huk_ecdsaAdapter, ECDSA_P256, NULL, ECDSA_256_BIT);
    hal_ecdsa_set_mode(&huk_ecdsaAdapter, ECDSA_VERI, ECDSA_NONE);
    vin.ppub_key_x = (u32*)t->qxW;
    vin.ppub_key_y = (u32*)t->qyW;
    vin.pr_adr     = (u32*)t->rW;
    vin.ps_adr     = (u32*)t->sW;
    hal_ecdsa_verify(&huk_ecdsaAdapter, &vin);          /* load pubkey + r + s */
    hal_ecdsa_hash(&huk_ecdsaAdapter, (u32*)t->hashW);  /* mark hash ready -> start */

    Rtl8735b_EcdsaSpin();
    hal_ecdsa_deinit(&huk_ecdsaAdapter);

    if (huk_ecdsaDone == 0) {
        ret = WC_HW_E;
    }
    else {
        /* A completed verify is success (ret 0); *res reflects pass/fail. A bad
         * signature is not an error -- it just yields res = 0. */
        *info->pk.eccverify.res =
            (huk_ecdsaErr == 0 && huk_veriResult != 0) ? 1 : 0;
        ret = 0;
    }
unlock:
    wolfSSL_CryptHwMutexUnLock();
done:
    ForceZero(t, sizeof(*t));   /* one scrub convention with the sign path */
#ifdef WOLFSSL_SMALL_STACK
    XFREE(t, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return ret;
}
#endif /* HAVE_ECC_VERIFY */

/* Unwrap the HUK-wrapped private scalar (hk->plainLen bytes). AES-GCM decrypt-
 * verify under the HUK-derived key (reusing the GCM path): a tampered/wrong blob
 * fails here with AES_GCM_AUTH_E, not silently as a garbage scalar downstream. */
static int Rtl8735bHuk_UnwrapScalar(const wc_Rtl8735b_EccKey* hk,
    byte* scalar, word32 scalarSz)
{
    (void)scalarSz;   /* out length is hk->plainLen (GCM: ciphertext == plaintext) */
    return Rtl8735bHuk_Gcm(0, hk->seed, hk->wrapped, hk->plainLen, scalar,
                           hk->iv, hk->ivSz, NULL, 0, (byte*)hk->tag, hk->tagSz);
}

/* Route an ECDSA sign request to the HUK backend (wc_Rtl8735b_EccKey via
 * key->devCtx). Modes: 1 OTP-resident (scalar stays in OTP); 2 GCM-unwrap the
 * wrapped scalar then HW sign; 3 GCM-unwrap then software sign. The unwrap is
 * AES-GCM-authenticated (needs HAVE_AESGCM). A plain ecc_key with no devCtx is a
 * general HW offload. The wrapped blob unwraps only on its origin HUK. */
static int Rtl8735bHuk_PkSign(struct wc_CryptoInfo* info)
{
    ecc_key* key = info->pk.eccsign.key;
    const wc_Rtl8735b_EccKey* hk;
    ecc_key* tmp = NULL;
    int      ret;
    int      curveId;
    word32   scalarSz;
#ifdef WOLFSSL_SMALL_STACK
    byte*    scalar = NULL;
#else
    byte     scalar[MAX_ECC_BYTES];
#endif

    if (key == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }
#ifdef WOLFSSL_SMALL_STACK
    scalar = (byte*)XMALLOC(MAX_ECC_BYTES, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (scalar == NULL) {
        return MEMORY_E;
    }
#endif

    /* General HW offload: a plain ecc_key (no HUK devCtx) signed via the HW
     * engine with its own scalar. P-256 with a usable private key only. */
    if (key->devCtx == NULL) {
        if (key->dp == NULL || key->dp->id != ECC_SECP256R1 ||
                (key->type != ECC_PRIVATEKEY &&
                 key->type != ECC_PRIVATEKEY_ONLY)) {
            ret = CRYPTOCB_UNAVAILABLE;
            goto cleanup;
        }
        scalarSz = MAX_ECC_BYTES;
        ret = wc_ecc_export_private_only(key, scalar, &scalarSz);
        if (ret != 0) {
            ret = CRYPTOCB_UNAVAILABLE; /* fall back to software */
            goto cleanup;
        }
        /* HW failure (e.g. finish-IRQ timeout) is surfaced verbatim, not masked
         * by a silent software fall-through (which would hide engine faults). */
        ret = Rtl8735bHuk_EccSignHw(info, NULL, scalar, scalarSz);
        goto cleanup;
    }
    hk = (const wc_Rtl8735b_EccKey*)key->devCtx;

    /* Mode 1: OTP-resident scalar -- no seed/wrapped blob needed. */
    if (hk->useHwEngine && hk->otpPrkSel != 0) {
        ret = Rtl8735bHuk_EccSignHw(info, hk, NULL, 0);
        goto cleanup;
    }

    /* Modes 2/3 need the seed + GCM-wrapped scalar (ciphertext + iv + tag). */
    if (hk->seed == NULL || hk->seedSz != WC_RTL8735B_KEYLEN ||
            hk->wrapped == NULL || hk->iv == NULL || hk->tag == NULL) {
        ret = CRYPTOCB_UNAVAILABLE;
        goto cleanup;
    }
    if (hk->plainLen == 0 ||
            hk->wrappedLen != hk->plainLen ||   /* GCM: ciphertext == plaintext */
            hk->plainLen > WC_RTL8735B_MAX_WRAPPED ||
            hk->plainLen > (word32)MAX_ECC_BYTES) {
        ret = BAD_FUNC_ARG;
        goto cleanup;
    }
    /* The caller must set the curve (wc_ecc_set_curve): a wrapped 32-byte scalar
     * is not necessarily P-256 (e.g. secp256k1), so do NOT assume it -- signing
     * under the wrong curve would silently produce a bad signature. */
    if (key->dp == NULL) {
        ret = BAD_FUNC_ARG;
        goto cleanup;
    }
    curveId  = key->dp->id;
    scalarSz = hk->plainLen;

    ret = Rtl8735bHuk_UnwrapScalar(hk, scalar, scalarSz);
    if (ret != 0) {
        goto cleanup;
    }

    /* Mode 2: HW-engine sign for P-256; other curves fall through to the software
     * sign below with the same unwrapped scalar (CRYPTOCB_UNAVAILABLE here would
     * make the core retry a software sign on the keyless HUK device key). */
    if (hk->useHwEngine && key->dp->id == ECC_SECP256R1) {
        ret = Rtl8735bHuk_EccSignHw(info, hk, scalar, scalarSz);
        goto cleanup;
    }

    /* Mode 3: software sign. The temp key uses INVALID_DEVID so the inner sign
     * does not re-enter this callback. */
    tmp = (ecc_key*)XMALLOC(sizeof(ecc_key), NULL, DYNAMIC_TYPE_ECC);
    if (tmp == NULL) {
        ret = MEMORY_E;
        goto cleanup;
    }
    ret = wc_ecc_init_ex(tmp, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_ecc_import_private_key_ex(scalar, scalarSz, NULL, 0, tmp,
                                           curveId);
        if (ret == 0) {
            ret = wc_ecc_sign_hash(info->pk.eccsign.in, info->pk.eccsign.inlen,
                                   info->pk.eccsign.out, info->pk.eccsign.outlen,
                                   info->pk.eccsign.rng, tmp);
        }
        wc_ecc_free(tmp);
    }

cleanup:
#ifdef WOLFSSL_SMALL_STACK
    if (scalar != NULL) {
        ForceZero(scalar, MAX_ECC_BYTES);
        XFREE(scalar, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#else
    ForceZero(scalar, sizeof(scalar));
#endif
    if (tmp != NULL) {
        XFREE(tmp, NULL, DYNAMIC_TYPE_ECC);
    }
    return ret;
}
#endif /* HAVE_ECC && HAVE_ECC_SIGN */

#ifndef WC_NO_RNG
/* huk_trngInit (secure-TRNG lazy-init flag) is defined near the top of this file
 * with the other module state. */

/* Fill a caller buffer with entropy from the secure (self-tested) TRNG. Exposed
 * as the crypto-callback SEED source so an app that inits its RNG with
 * WC_HUK_DEVID (wc_InitRng_ex(&rng, NULL, WC_HUK_DEVID)) gets HW-seeded entropy
 * without wiring CUSTOM_RAND_GENERATE_SEED. */
static int Rtl8735b_Seed(byte* seed, word32 sz)
{
    int    ret;
    word32 i;
    word32 n;
    u32    r;

    if (seed == NULL) {
        return BAD_FUNC_ARG;
    }
    if (sz == 0) {
        return 0;
    }
    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }
    if (!huk_trngInit) {
        if (hal_trng_sec_init() != HAL_OK) {
            wolfSSL_CryptHwMutexUnLock();
            return WC_HW_E;
        }
        huk_trngInit = 1;
    }
    /* Fill from the secure TRNG a 32-bit word at a time (hal_trng_sec_get_rand). */
    for (i = 0; i < sz; ) {
        r = hal_trng_sec_get_rand();
        n = (sz - i) < 4u ? (sz - i) : 4u;
        XMEMCPY(seed + i, &r, n);
        i += n;
    }
    ret = 0;
    wolfSSL_CryptHwMutexUnLock();
    return ret;
}
#endif /* WC_NO_RNG */

/* The crypto-callback device entry point (registered by
 * wc_Rtl8735b_HukRegister). Returns CRYPTOCB_UNAVAILABLE for anything it does
 * not handle so the caller falls back to software.
 *
 * cmsis_os.h (AmebaPro2 FreeRTOS) does "#define free vPortFree", which collides
 * with the wc_CryptoInfo ".free" union member used below. Drop the macro for
 * this one function (preprocessor-only, no push_macro), then restore it after so
 * XFREE keeps mapping to vPortFree. On a host build (no such macro) both #ifdef
 * blocks are skipped. */
#ifdef free
    #undef free
    #define RTL8735B_FREE_WAS_MACRO
#endif
static int Rtl8735b_CryptoDevCb(int devId, struct wc_CryptoInfo* info,
    void* ctx)
{
    (void)devId;
    (void)ctx;
    if (info == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }

    switch (info->algo_type) {
#ifndef NO_AES
        case WC_ALGO_TYPE_CIPHER:
            return Rtl8735bHuk_Cipher(info);
#endif
#if !defined(NO_HMAC) && !defined(NO_SHA256)
        case WC_ALGO_TYPE_HMAC:
            return Rtl8735bHuk_HmacCb(info);
        /* Manage the HMAC accumulation buffer stored on the inner SHA-256 devCtx:
         * deep-copy on wc_HmacCopy, free on wc_HmacFree. NULL devCtx -> no-op, so
         * this is safe for any non-HUK SHA-256 object routed here too. */
        case WC_ALGO_TYPE_COPY:
            if (info->copy.algo == WC_ALGO_TYPE_HASH &&
                    info->copy.type == WC_HASH_TYPE_SHA256) {
                return Rtl8735bHuk_HmacCopySha((wc_Sha256*)info->copy.src,
                                               (wc_Sha256*)info->copy.dst);
            }
            return CRYPTOCB_UNAVAILABLE;
        case WC_ALGO_TYPE_FREE:
            /* ".free" resolves to the member: the SDK's free macro is dropped for
             * this function (see the #undef above its definition). */
            if (info->free.algo == WC_ALGO_TYPE_HASH &&
                    info->free.type == WC_HASH_TYPE_SHA256) {
                Rtl8735bHuk_HmacFreeSha((wc_Sha256*)info->free.obj);
                return 0;
            }
            return CRYPTOCB_UNAVAILABLE;
#endif
#if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN)
        case WC_ALGO_TYPE_PK:
            if (info->pk.type == WC_PK_TYPE_ECDSA_SIGN) {
                return Rtl8735bHuk_PkSign(info);
            }
        #ifdef HAVE_ECC_VERIFY
            if (info->pk.type == WC_PK_TYPE_ECDSA_VERIFY) {
                return Rtl8735bHuk_EccVerifyHw(info);
            }
        #endif
            return CRYPTOCB_UNAVAILABLE;
#endif
#ifndef WC_NO_RNG
        case WC_ALGO_TYPE_SEED:
            return Rtl8735b_Seed(info->seed.seed, info->seed.sz);
#endif
        default:
            return CRYPTOCB_UNAVAILABLE;
    }
}
#ifdef RTL8735B_FREE_WAS_MACRO
    #define free vPortFree   /* restore the cmsis_os.h macro for XFREE below */
    #undef RTL8735B_FREE_WAS_MACRO
#endif

/* Register the AmebaPro2 HUK device at devId (e.g. WC_HUK_DEVID). After this,
 * objects whose devId is set to it at init route transparently to the HUK
 * crypto engine. */
int wc_Rtl8735b_HukRegister(int devId)
{
    int ret = Rtl8735bHuk_Init(NULL);
    if (ret != 0) {
        return ret;
    }
    return wc_CryptoCb_RegisterDevice(devId, Rtl8735b_CryptoDevCb, NULL);
}

int wc_Rtl8735b_HukUnRegister(int devId)
{
    int ret;
    wc_CryptoCb_UnRegisterDevice(devId);
    /* Scrub the mutex-guarded globals. Take the mutex so this cannot race an
     * in-flight op (in practice a shutdown call, nothing in flight); a lock
     * failure is surfaced so the caller knows the scrub did not run. */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
#ifndef WC_RTL8735B_NO_DERIVE_CACHE
        ForceZero(huk_seedCache, sizeof(huk_seedCache));   /* next op re-derives */
        huk_haveCache = 0;
#endif
#ifndef WC_NO_RNG
        huk_trngInit = 0;   /* re-arm TRNG init for a later re-register */
#endif
        wolfSSL_CryptHwMutexUnLock();
    }
    return ret;
}

#ifdef WOLFSSL_RTL8735B_HOST_TEST
/* Host self-test for the silicon-independent helpers (no HAL crypto needed):
 * BE<->LE word conversion, the AES-CTR counter increment, the HMAC accumulator
 * growth/overflow/cap logic, and the bounce-buffer alignment helpers. The
 * --enable-rtl8735b build is a compile + these-KATs gate; the cipher / GCM /
 * ECDSA crypto correctness is validated on RTL8735B hardware, not here. Returns
 * 0 on success, or a negative code identifying the first failing check. */
int wc_Rtl8735b_HukSelfTest(void)
{
#if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN)
    static const byte kBe[WC_RTL8735B_ECC_BYTES] = {
        0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b, 0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b, 0x1c,0x1d,0x1e,0x1f
    };
    word32 w[WC_RTL8735B_ECC_WORDS];
    byte   be2[WC_RTL8735B_ECC_BYTES];
#endif
#ifdef WOLFSSL_AES_COUNTER
    byte ctr[WC_AES_BLOCK_SIZE];
    int  i;
#endif
#if !defined(NO_HMAC) && !defined(NO_SHA256)
    Hmac             hmac;
    Rtl8735bHmacCtx* hctx;
    Rtl8735bHmacCtx* dctx;
    wc_Sha256        shaDst;
    byte             chunk[5];
#endif
    const byte* al;
    byte*       alloc;
    byte        aligned[64];
    byte*       ap;

#if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN)
    /* BE->LE limb layout: word[0] is the least-significant limb (last 4 BE
     * bytes), word[N-1] the most-significant (first 4 BE bytes). */
    Rtl8735b_BeToLeWords(kBe, w);
    if (w[0] != 0x1c1d1e1fUL ||
            w[WC_RTL8735B_ECC_WORDS - 1] != 0x00010203UL) {
        return -1;
    }
    Rtl8735b_LeWordsToBe(w, be2);       /* round-trip back to big-endian */
    if (XMEMCMP(kBe, be2, sizeof(kBe)) != 0) {
        return -2;
    }
#endif

#ifdef WOLFSSL_AES_COUNTER
    /* All-ones -> all-zero full rollover. */
    for (i = 0; i < WC_AES_BLOCK_SIZE; i++) {
        ctr[i] = 0xFF;
    }
    Rtl8735bHuk_IncCtr(ctr);
    for (i = 0; i < WC_AES_BLOCK_SIZE; i++) {
        if (ctr[i] != 0x00) {
            return -3;
        }
    }
    /* Low-byte carry: 0x..00FF -> 0x..0100. */
    XMEMSET(ctr, 0, sizeof(ctr));
    ctr[WC_AES_BLOCK_SIZE - 1] = 0xFF;
    Rtl8735bHuk_IncCtr(ctr);
    if (ctr[WC_AES_BLOCK_SIZE - 1] != 0x00 ||
            ctr[WC_AES_BLOCK_SIZE - 2] != 0x01) {
        return -4;
    }
#endif

#if !defined(NO_HMAC) && !defined(NO_SHA256)
    /* Accumulator: growth, overflow guard, and the MAX_MSG cap. */
    XMEMSET(&hmac, 0, sizeof(hmac));
    chunk[0] = 0xAA; chunk[1] = 0xBB; chunk[2] = 0xCC;
    chunk[3] = 0xDD; chunk[4] = 0xEE;
    if (Rtl8735bHuk_HmacAccumulate(&hmac, chunk, 3) != 0) {
        return -5;
    }
    if (Rtl8735bHuk_HmacAccumulate(&hmac, chunk + 3, 2) != 0) {
        return -6;
    }
    hctx = (Rtl8735bHmacCtx*)hmac.hash.sha256.devCtx;
    if (hctx == NULL || hctx->len != 5 ||
            XMEMCMP(hctx->buf, chunk, 5) != 0) {
        Rtl8735bHuk_HmacFreeCtx(&hmac);
        return -7;
    }
    /* word32 overflow guard: need = len + inSz wraps below len -> BUFFER_E.
     * (Returns before touching the buffer, so the tiny chunk pointer is safe.) */
    if (Rtl8735bHuk_HmacAccumulate(&hmac, chunk, 0xFFFFFFFFUL) != BUFFER_E) {
        Rtl8735bHuk_HmacFreeCtx(&hmac);
        return -8;
    }
#if WC_RTL8735B_HMAC_MAX_MSG != 0
    /* Cap: need beyond WC_RTL8735B_HMAC_MAX_MSG -> BUFFER_E (returns pre-alloc). */
    if (Rtl8735bHuk_HmacAccumulate(&hmac, chunk,
            (word32)WC_RTL8735B_HMAC_MAX_MSG) != BUFFER_E) {
        Rtl8735bHuk_HmacFreeCtx(&hmac);
        return -9;
    }
#endif
    /* Copy op (the wc_HmacCopy fix): dst must own a distinct buffer with the same
     * contents -- not an alias (double free) -- and carry src's devId + heap so
     * dst's later copy/free routes back here. src still has len==5. */
    hmac.hash.sha256.devId = WC_HUK_DEVID;     /* sentinel: must survive the copy */
    XMEMSET(&shaDst, 0, sizeof(shaDst));
    shaDst.devCtx = hmac.hash.sha256.devCtx;   /* mimic wc_Sha256Copy's shallow alias */
    if (Rtl8735bHuk_HmacCopySha(&hmac.hash.sha256, &shaDst) != 0) {
        Rtl8735bHuk_HmacFreeCtx(&hmac);
        return -20;
    }
    dctx = (Rtl8735bHmacCtx*)shaDst.devCtx;
    hctx = (Rtl8735bHmacCtx*)hmac.hash.sha256.devCtx;
    if (dctx == NULL || dctx == hctx || dctx->buf == hctx->buf ||
            dctx->len != 5 || XMEMCMP(dctx->buf, chunk, 5) != 0 ||
            shaDst.devId != WC_HUK_DEVID ||        /* devId carried over */
            shaDst.heap  != hmac.hash.sha256.heap) /* heap carried over */ {
        Rtl8735bHuk_HmacFreeSha(&shaDst);
        Rtl8735bHuk_HmacFreeCtx(&hmac);
        return -21;
    }
    Rtl8735bHuk_HmacFreeSha(&shaDst);          /* free the copy independently */
    Rtl8735bHuk_HmacFreeCtx(&hmac);            /* ... then the original: no double free */
    if (hmac.hash.sha256.devCtx != NULL || shaDst.devCtx != NULL) {
        return -22;
    }
#endif

    /* Bounce helpers: aligned fast-path, unaligned bounce, sz==0, and out. */
    ap = WC_RTL8735B_ALIGN_UP32(aligned);   /* a known 32-byte-aligned pointer */
    if (Rtl8735b_BounceIn(ap, 16, &al, &alloc) != 0 ||
            alloc != NULL || al != ap) {
        return -11;                          /* already aligned -> no alloc */
    }
    if (Rtl8735b_BounceIn(ap + 1, 16, &al, &alloc) != 0 || alloc == NULL ||
            !WC_RTL8735B_IS_ALIGNED32(al) || XMEMCMP(al, ap + 1, 16) != 0) {
        Rtl8735b_BounceFree(alloc, (byte*)al, 16);
        return -12;                          /* unaligned -> aligned copy */
    }
    Rtl8735b_BounceFree(alloc, (byte*)al, 16);
    if (Rtl8735b_BounceIn(ap, 0, &al, &alloc) != 0 || alloc != NULL) {
        return -13;                          /* sz==0 -> no alloc */
    }
    if (Rtl8735b_BounceOut(16, &ap, &alloc) != 0 || alloc == NULL ||
            !WC_RTL8735B_IS_ALIGNED32(ap)) {
        Rtl8735b_BounceFree(alloc, ap, 16);
        return -14;
    }
    Rtl8735b_BounceFree(alloc, ap, 16);

    return 0;
}
#endif /* WOLFSSL_RTL8735B_HOST_TEST */

#endif /* WOLF_CRYPTO_CB */

#endif /* WOLFSSL_RTL8735B_HUK */
