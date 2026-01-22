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

#define WC_RNG_BANK_INST_LOCK_FREE                0
#define WC_RNG_BANK_INST_LOCK_HELD            (1<<0)
#define WC_RNG_BANK_INST_LOCK_AFFINITY_LOCKED (1<<1)
#define WC_RNG_BANK_INST_LOCK_VEC_OPS_INH     (1<<2)

typedef int (*wc_affinity_lock_fn_t)(void *arg);
typedef int (*wc_affinity_get_id_fn_t)(void *arg, int *id);
typedef int (*wc_affinity_unlock_fn_t)(void *arg);

struct wc_rng_bank_inst {
#ifdef WOLFSSL_NO_ATOMICS
    int lock;
#else
    wolfSSL_Atomic_Int lock;
#endif
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

#ifdef WC_DRBG_BANKREF
WOLFSSL_API int wc_InitRng_BankRef(struct wc_rng_bank *bank, WC_RNG *rng);

WOLFSSL_API int wc_BankRef_Release(WC_RNG *rng);

#ifndef WC_RNG_BANK_STATIC
WOLFSSL_API int wc_rng_new_bankref(struct wc_rng_bank *bank, WC_RNG **rng);
#endif
#endif /* WC_DRBG_BANKREF */

#define WC_RNG_BANK_INST_TO_RNG(rng_inst) (&(rng_inst)->rng)

#endif /* WC_RNG_BANK_SUPPORT */

#endif /* WOLF_CRYPT_RNG_BANK_H */
