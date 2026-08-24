/* rng_bank.h
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
    \file wolfssl/wolfcrypt/rng_bank.h
*/

/* This facility allocates and manages a bank of persistent RNGs with thread
 * safety and provisions for automatic affinity.  It is typically used in kernel
 * applications.
 */

#ifndef WOLF_CRYPT_RNG_BANK_H
#define WOLF_CRYPT_RNG_BANK_H

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>

#ifdef WC_RNG_BANK_SUPPORT

#ifdef WC_NO_RNG
    #error WC_RNG_BANK_SUPPORT requires RNG support.
#endif

#define WC_RNG_BANK_FLAG_NONE                     0
#define WC_RNG_BANK_FLAG_INITED               (1<<0)
#define WC_RNG_BANK_FLAG_CAN_FAIL_OVER_INST   (1<<1)
#define WC_RNG_BANK_FLAG_CAN_WAIT             (1<<2)
#define WC_RNG_BANK_FLAG_NO_VECTOR_OPS        (1<<3)
#define WC_RNG_BANK_FLAG_PREFER_AFFINITY_INST (1<<4)
#define WC_RNG_BANK_FLAG_AFFINITY_LOCK        (1<<5)
/* WC_RNG_BANK_FLAG_SEED_UNCREDITED applies only to wc_rng_bank_seed(): the
 * supplied seed material is mixed into each instance without entropy credit
 * (wc_RNG_DRBG_Reseed_Uncredited()), leaving the reseed schedule governed
 * solely by the module's own seed source. */
#define WC_RNG_BANK_FLAG_SEED_UNCREDITED      (1<<6)

#define WC_RNG_BANK_INST_LOCK_FREE                0
#define WC_RNG_BANK_INST_LOCK_HELD            (1<<0)
#define WC_RNG_BANK_INST_LOCK_AFFINITY_LOCKED (1<<1)
#define WC_RNG_BANK_INST_LOCK_VEC_OPS_INH     (1<<2)

/* ---- Legacy FIPS boundary compatibility --------------------------------
 *
 * Pre-v7 FIPS boundaries do not export the DRBG accessor and reseed
 * scheduling services that wolfcrypt/src/random.c supplies as of FIPS v7
 * (wc_RNG_GetStatus(), wc_RNG_DRBG_Present(), wc_RNG_DRBG_GetReseedCtr(),
 * wc_RNG_DRBG_ScheduleReseed(), wc_RNG_DRBG_Reseed_Uncredited(), and
 * wc_RNG_DRBG_Reseed_Now()).  Supply source-compatible static fallbacks
 * here, implemented via the public DRBG struct definitions in the legacy
 * random.h.  These fallbacks are the historic direct-access mechanism, now
 * confined to frozen pre-v7 boundaries, which cannot gain new services;
 * wherever the in-boundary services exist, they are used instead.
 */
#if defined(HAVE_FIPS) && FIPS_VERSION3_LT(7,0,0)

#include <wolfssl/wolfcrypt/error-crypt.h>

#ifndef WC_DRBG_RESEED_CTR_TYPE_DEFINED
#define WC_DRBG_RESEED_CTR_TYPE_DEFINED
    #ifdef WORD64_AVAILABLE
    typedef word64 wc_drbg_reseed_ctr_t;
    #else
    typedef word32 wc_drbg_reseed_ctr_t;
    #endif
#endif

#if FIPS_VERSION3_LT(5,2,4) || FIPS_VERSION3_EQ(6,0,0)
    /* WC_DRBG_OK predates these FIPS random.h editions. */
    #define WC_DRBG_OK 1
#endif

/* Helpers to access reseedCtr / null-check the active DRBG.  The shape of
 * struct WC_RNG and the DRBG_*_internal types varies by which DRBGs are
 * compiled in; random.h gates the SHA-256 side on !NO_SHA256 and the SHA-512
 * side on WOLFSSL_DRBG_SHA512, so all three live combinations are handled
 * separately here. */
#if defined(WOLFSSL_DRBG_SHA512) && !defined(NO_SHA256)
    /* Both DRBGs compiled in: dispatch on the runtime drbgType. */
    #define WC_RNG_BANK_RESEED_CTR(rng_ptr) \
        (((rng_ptr)->drbgType == WC_DRBG_SHA512) \
            ? ((struct DRBG_SHA512_internal *)(rng_ptr)->drbg512)->reseedCtr \
            : ((struct DRBG_internal *)(rng_ptr)->drbg)->reseedCtr)
    #define WC_RNG_BANK_SET_RESEED_CTR(rng_ptr, val) \
        do { \
            if ((rng_ptr)->drbgType == WC_DRBG_SHA512) \
                ((struct DRBG_SHA512_internal *)(rng_ptr)->drbg512)->reseedCtr \
                    = (val); \
            else \
                ((struct DRBG_internal *)(rng_ptr)->drbg)->reseedCtr = (val); \
        } while (0)
    #define WC_RNG_BANK_DRBG_NULL(rng_ptr) \
        ((rng_ptr)->drbg == NULL && (rng_ptr)->drbg512 == NULL)
#elif defined(WOLFSSL_DRBG_SHA512)
    /* SHA-512 DRBG only (NO_SHA256 defined); the SHA-256 struct and
     * rng->drbg field do not exist in this build. */
    #define WC_RNG_BANK_RESEED_CTR(rng_ptr) \
        (((struct DRBG_SHA512_internal *)(rng_ptr)->drbg512)->reseedCtr)
    #define WC_RNG_BANK_SET_RESEED_CTR(rng_ptr, val) \
        do { \
            ((struct DRBG_SHA512_internal *)(rng_ptr)->drbg512)->reseedCtr \
                = (val); \
        } while (0)
    #define WC_RNG_BANK_DRBG_NULL(rng_ptr) \
        ((rng_ptr)->drbg512 == NULL)
#else
    /* SHA-256 DRBG only (the historical default). */
    #define WC_RNG_BANK_RESEED_CTR(rng_ptr) \
        (((struct DRBG_internal *)(rng_ptr)->drbg)->reseedCtr)
    #define WC_RNG_BANK_SET_RESEED_CTR(rng_ptr, val) \
        do { \
            ((struct DRBG_internal *)(rng_ptr)->drbg)->reseedCtr = (val); \
        } while (0)
    #define WC_RNG_BANK_DRBG_NULL(rng_ptr) \
        ((rng_ptr)->drbg == NULL)
#endif

/* WC_RNG_BANK_SET_RESEED_CTR drives reseedCtr up to WC_RESEED_INTERVAL to
 * force a reseed.  The SHA-256 DRBG's reseedCtr is 32-bit when
 * WORD64_AVAILABLE is undefined (random.h), so a reseed interval above 2^32
 * would truncate to 0 and silently defeat the forced reseed (SP 800-90A Rev1
 * sec 9.3).  Fail the build rather than mis-reseed.  This is a compile-time
 * assert rather than a preprocessor #if because WC_RESEED_INTERVAL may be
 * defined with a (word64) cast (settings.h kernel path) that the preprocessor
 * cannot evaluate; the outer #if uses only defined() so the 64-bit path skips
 * it without expanding that cast. */
#if defined(WC_RESEED_INTERVAL) && !defined(WORD64_AVAILABLE)
    wc_static_assert((WC_RESEED_INTERVAL) <= 0xFFFFFFFFUL);
#endif

WC_MAYBE_UNUSED static WC_INLINE int wc_RNG_GetStatus(const WC_RNG* rng)
{
    if (rng == NULL)
        return BAD_FUNC_ARG;
    return (int)rng->status;
}

WC_MAYBE_UNUSED static WC_INLINE int wc_RNG_DRBG_Present(const WC_RNG* rng)
{
    return (rng != NULL) && (! WC_RNG_BANK_DRBG_NULL(rng));
}

WC_MAYBE_UNUSED static WC_INLINE int wc_RNG_DRBG_GetReseedCtr(
    const WC_RNG* rng, wc_drbg_reseed_ctr_t* reseedCtr)
{
    if ((rng == NULL) || (reseedCtr == NULL))
        return BAD_FUNC_ARG;
    if (WC_RNG_BANK_DRBG_NULL(rng))
        *reseedCtr = 0;
    else
        *reseedCtr = (wc_drbg_reseed_ctr_t)WC_RNG_BANK_RESEED_CTR(rng);
    return 0;
}

WC_MAYBE_UNUSED static WC_INLINE int wc_RNG_DRBG_ScheduleReseed(WC_RNG* rng)
{
    if (rng == NULL)
        return BAD_FUNC_ARG;
    if (! WC_RNG_BANK_DRBG_NULL(rng))
        WC_RNG_BANK_SET_RESEED_CTR(rng, WC_RESEED_INTERVAL);
    return 0;
}

WC_MAYBE_UNUSED static WC_INLINE int wc_RNG_DRBG_Reseed_Uncredited(
    WC_RNG* rng, const byte* seed, word32 seedSz)
{
    wc_drbg_reseed_ctr_t saved_ctr;
    int ret;

    if ((rng == NULL) || (seed == NULL))
        return BAD_FUNC_ARG;
    if (WC_RNG_BANK_DRBG_NULL(rng)) {
        /* defer to wc_RNG_DRBG_Reseed()'s RDRAND-config handling. */
        return wc_RNG_DRBG_Reseed(rng, seed, seedSz);
    }
    saved_ctr = (wc_drbg_reseed_ctr_t)WC_RNG_BANK_RESEED_CTR(rng);
    ret = wc_RNG_DRBG_Reseed(rng, seed, seedSz);
    /* wc_RNG_DRBG_Reseed() only resets the counter on success, so the
     * unconditional restore is exact either way. */
    WC_RNG_BANK_SET_RESEED_CTR(rng, saved_ctr);
    return ret;
}

WC_MAYBE_UNUSED static WC_INLINE int wc_RNG_DRBG_Reseed_Now(
    WC_RNG* rng, const byte* nonce, word32 nonceSz)
{
    wc_drbg_reseed_ctr_t saved_ctr;
    int ret;
    byte scratch[4];

    if (rng == NULL)
        return BAD_FUNC_ARG;
    if ((nonce == NULL) && (nonceSz > 0))
        return BAD_FUNC_ARG;
    if (wc_RNG_GetStatus(rng) != WC_DRBG_OK)
        return RNG_FAILURE_E;
    if (WC_RNG_BANK_DRBG_NULL(rng)) {
        /* No DRBG instantiated -- nothing to reseed (RDRAND et al.). */
        return 0;
    }

    saved_ctr = (wc_drbg_reseed_ctr_t)WC_RNG_BANK_RESEED_CTR(rng);
    WC_RNG_BANK_SET_RESEED_CTR(rng, WC_RESEED_INTERVAL);

    /* The legacy boundary has no direct reseed-from-source service; a
     * minimal generate at the forced counter performs the module's own
     * PollAndReSeed() in-boundary.  This consumes 4 bytes of output, so on
     * success the fresh reseed counter is 2 rather than 1.  scratch holds
     * only discarded output bytes; XMEMSET suffices for it here. */
    ret = wc_RNG_GenerateBlock(rng, scratch, (word32)sizeof(scratch));
    XMEMSET(scratch, 0, sizeof(scratch));

    if ((ret == 0) && (nonce != NULL) && (nonceSz > 0)) {
        /* On the legacy boundary, nonce incorporation is a separate
         * (uncredited) transition following the reseed, rather than part of
         * the same reseed derivation. */
        ret = wc_RNG_DRBG_Reseed_Uncredited(rng, nonce, nonceSz);
    }

    if ((ret != 0) &&
        ((wc_drbg_reseed_ctr_t)WC_RNG_BANK_RESEED_CTR(rng) >=
         (wc_drbg_reseed_ctr_t)WC_RESEED_INTERVAL))
    {
        /* The reseed did not occur -- restore the counter, leaving it
         * unmodified as the contract requires. */
        WC_RNG_BANK_SET_RESEED_CTR(rng, saved_ctr);
    }

    return ret;
}

#endif /* HAVE_FIPS && FIPS_VERSION3_LT(7,0,0) */

typedef int (*wc_affinity_lock_fn_t)(void *arg);
typedef int (*wc_affinity_get_id_fn_t)(void *arg, int *id);
typedef int (*wc_affinity_unlock_fn_t)(void *arg);

struct wc_rng_bank;

struct wc_rng_bank_inst {
#ifdef WOLFSSL_NO_ATOMICS
    int lock;
#else
    wolfSSL_Atomic_Int lock;
#endif
    struct wc_rng_bank *bank;
    WC_RNG rng;
};

#if defined(WOLFSSL_NO_MALLOC) && defined(NO_WOLFSSL_MEMORY) && \
    !defined(WC_RNG_BANK_STATIC)
    #define WC_RNG_BANK_STATIC
#endif

#ifndef WC_RNG_BANK_STATIC_SIZE
    #define WC_RNG_BANK_STATIC_SIZE 4
#endif

struct wc_rng_bank {
    wolfSSL_Ref refcount;
    void *heap;
    word32 flags;
    wc_affinity_lock_fn_t affinity_lock_cb;
    wc_affinity_get_id_fn_t affinity_get_id_cb;
    wc_affinity_unlock_fn_t affinity_unlock_cb;
    void *cb_arg; /* if mutable, caller is responsible for thread safety. */
    int n_rngs;
#ifdef WC_RNG_BANK_STATIC
    struct wc_rng_bank_inst rngs[WC_RNG_BANK_STATIC_SIZE];
#else
    struct wc_rng_bank_inst *rngs; /* typically one per CPU ID, plus a few */
#endif
};

#ifndef WC_RNG_BANK_STATIC
WOLFSSL_API int wc_rng_bank_new(
    struct wc_rng_bank **ctx,
    int n_rngs,
    word32 flags,
    int timeout_secs,
    void *heap,
    int devId);
#endif

WOLFSSL_API int wc_rng_bank_init(
    struct wc_rng_bank *ctx,
    int n_rngs,
    word32 flags,
    int timeout_secs,
    void *heap,
    int devId);

WOLFSSL_API int wc_rng_bank_set_affinity_handlers(
    struct wc_rng_bank *ctx,
    wc_affinity_lock_fn_t affinity_lock_cb,
    wc_affinity_get_id_fn_t affinity_get_id_cb,
    wc_affinity_unlock_fn_t affinity_unlock_cb,
    void *cb_arg);

WOLFSSL_API int wc_rng_bank_fini(struct wc_rng_bank *ctx);

#ifndef WC_RNG_BANK_STATIC
WOLFSSL_API int wc_rng_bank_free(struct wc_rng_bank **ctx);
#endif

#ifdef WC_RNG_BANK_NO_DEFAULT_SUPPORT
#undef WC_RNG_BANK_DEFAULT_SUPPORT
#else /* !WC_RNG_BANK_NO_DEFAULT_SUPPORT */
#ifndef WC_RNG_BANK_DEFAULT_SUPPORT
#define WC_RNG_BANK_DEFAULT_SUPPORT
#endif
WOLFSSL_API int wc_rng_bank_default_set(struct wc_rng_bank *bank);
WOLFSSL_API int wc_rng_bank_default_checkout(struct wc_rng_bank **bank);
WOLFSSL_API int wc_rng_bank_default_checkin(struct wc_rng_bank **bank);
WOLFSSL_API int wc_rng_bank_default_clear(struct wc_rng_bank *bank);
#endif /* !WC_RNG_BANK_NO_DEFAULT_SUPPORT */

WOLFSSL_API int wc_rng_bank_checkout(
    struct wc_rng_bank *bank,
    struct wc_rng_bank_inst **rng_inst,
    int preferred_inst_offset,
    int timeout_secs,
    word32 flags);

WOLFSSL_LOCAL int wc_local_rng_bank_checkout_for_bankref(
    struct wc_rng_bank *bank,
    struct wc_rng_bank_inst **rng_inst);

WOLFSSL_API int wc_rng_bank_checkin(
    struct wc_rng_bank *bank,
    struct wc_rng_bank_inst **rng_inst);

WOLFSSL_API int wc_rng_bank_inst_checkin(
    struct wc_rng_bank_inst **rng_inst);

WOLFSSL_API int wc_rng_bank_inst_reinit(
    struct wc_rng_bank *bank,
    struct wc_rng_bank_inst *rng_inst,
    int timeout_secs,
    word32 flags);

WOLFSSL_API int wc_rng_bank_seed(struct wc_rng_bank *bank,
                                 const byte* seed, word32 seedSz,
                                 int timeout_secs,
                                 word32 flags);

WOLFSSL_API int wc_rng_bank_reseed(struct wc_rng_bank *bank,
                                   int timeout_secs,
                                   word32 flags);

#if defined(WC_DRBG_BANKREF) && !defined(WC_HAVE_RNG_BANKREF)
    /* forward compat for FIPS v5.2.4 random.h */
    #define WC_HAVE_RNG_BANKREF
#endif

#ifdef WC_HAVE_RNG_BANKREF
WOLFSSL_API int wc_InitRng_BankRef(struct wc_rng_bank *bank, WC_RNG *rng);

WOLFSSL_API int wc_BankRef_Release(WC_RNG *rng);

#if !defined(WC_RNG_BANK_STATIC) && !defined(WC_NO_CONSTRUCTORS)
WOLFSSL_API int wc_rng_new_bankref(struct wc_rng_bank *bank, WC_RNG **rng);
/* note, free with wc_rng_free(). */
#endif
#endif /* WC_HAVE_RNG_BANKREF */

#define WC_RNG_BANK_INST_TO_RNG(rng_inst) (&(rng_inst)->rng)

#endif /* WC_RNG_BANK_SUPPORT */

#endif /* WOLF_CRYPT_RNG_BANK_H */
