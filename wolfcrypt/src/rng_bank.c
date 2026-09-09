/* rng_bank.c
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

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef WC_RNG_BANK_SUPPORT

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rng_bank.h>

/* DRBG status and reseed-counter access, and reseed forcing, are via the
 * wc_RNG_GetStatus() / wc_RNG_DRBG_*() services in wolfcrypt/src/random.c
 * (FIPS v7+ and non-FIPS builds).  For pre-v7 FIPS boundaries, which lack
 * those services, rng_bank.h supplies source-compatible static fallbacks.
 */

/* To disable retry looping in wc_rng_bank_init(), pass timeout_secs=0, and to
 * retry indefinitely, pass negative timeout_secs -- the flags arg here is only
 * used to initialize the flags in the new bank.
 */
WOLFSSL_API int wc_rng_bank_init_nonce(
    struct wc_rng_bank *ctx,
    int n_rngs,
    word32 flags,
    int timeout_secs,
    void *heap,
    int devId,
    const byte *nonce,
    word32 nonceSz)
{
    int i;
    int ret;
    int need_reenable_vec = 0;
#ifdef WC_RNG_HAVE_RBGC
    WC_RNG root;
    int root_inited = 0;
#endif

    if ((ctx == NULL) || (n_rngs <= 0))
        return BAD_FUNC_ARG;

    XMEMSET(ctx, 0, sizeof(*ctx));

    wolfSSL_RefInit(&ctx->refcount, &ret);
    if (ret != 0)
        return ret;

#ifdef WC_RNG_HAVE_NEXT_SEED
    wolfSSL_Atomic_Int_Init(&ctx->inst_op_gate, 0);
#endif
    ctx->flags = flags | WC_RNG_BANK_FLAG_INITED;
    ctx->heap = heap;
    ctx->first_failover_inst = -1;

#ifdef WC_RNG_BANK_STATIC
    if (n_rngs > WC_RNG_BANK_STATIC_SIZE)
        ret = BAD_LENGTH_E;
#else
    ctx->rngs = (struct wc_rng_bank_inst *)
        XMALLOC(sizeof(*ctx->rngs) * (size_t)n_rngs,
                heap, DYNAMIC_TYPE_RNG);
    if (! ctx->rngs)
        ret = MEMORY_E;
#endif

#ifdef WC_RNG_HAVE_RBGC
    if ((ret == 0) && (flags & WC_RNG_BANK_FLAG_INIT_RBGC)) {
        ret = wc_InitRngNonce_ex(&root, nonce, nonceSz, heap, devId);
        if (ret == 0)
            root_inited = 1;
    }
#else
    (void)nonce;
    (void)nonceSz;
#endif

    if (ret == 0) {
        XMEMSET(ctx->rngs, 0, sizeof(*ctx->rngs) * (size_t)n_rngs);
        ctx->n_rngs = n_rngs;

        for (i = 0; i < n_rngs; ++i) {
            /* The nonce is the address of the instance, so it has to be taken
             * from a pointer to it, not from the instance itself. */
            struct wc_rng_bank_inst *rng_inst = ctx->rngs + i;
#ifdef WC_VERBOSE_RNG
            int nretries = 0;
#endif
            time_t ts1 = XTIME(0);
            rng_inst->bank = ctx;
            for (;;) {
                time_t ts2;
                if (flags & WC_RNG_BANK_FLAG_NO_VECTOR_OPS)
                    need_reenable_vec = (DISABLE_VECTOR_REGISTERS() == 0);

#ifdef WC_RNG_HAVE_RBGC
                if (flags & WC_RNG_BANK_FLAG_INIT_RBGC) {
                    ret = wc_InitRngNonceRBGC(
                        WC_RNG_BANK_INST_TO_RNG(rng_inst),
                        &root,
                        (byte *)&rng_inst, sizeof(byte *)
#if !defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0)
                        , WC_RNG_INIT_FLAGS_LOCK_REQUIRED
#else
                        , WC_RNG_INIT_FLAGS_NONE
#endif
                        );
                }
                else
#endif
                {
#ifdef WC_RNG_INIT_FLAGS_LOCK_REQUIRED
                    ret = wc_InitRngNonce_ex2(
                        WC_RNG_BANK_INST_TO_RNG(rng_inst),
                        (byte *)&rng_inst, sizeof(byte *), heap, devId,
                        WC_RNG_INIT_FLAGS_LOCK_REQUIRED);
#else
                    ret = wc_InitRngNonce_ex(
                        WC_RNG_BANK_INST_TO_RNG(rng_inst),
                        (byte *)&rng_inst, sizeof(byte *), heap, devId);
#endif
                }
                if (need_reenable_vec)
                    REENABLE_VECTOR_REGISTERS();
                /* if we're allowed to sleep, relax the loop between each inner
                 * iteration even on success, assuring relaxation of the outer
                 * iterations.
                 */
                WC_RELAX_LONG_LOOP();
                if (ret == 0)
                    break;

                /* Several plausible error codes are non-retryable -- fail early
                 * for these.
                 */
                switch (ret) {
                case WC_NO_ERR_TRACE(BAD_MUTEX_E):
                case WC_NO_ERR_TRACE(BAD_FUNC_ARG):
                case WC_NO_ERR_TRACE(MEMORY_E):
                case WC_NO_ERR_TRACE(NOT_COMPILED_IN):
                case WC_NO_ERR_TRACE(MISSING_RNG_E):
                case WC_NO_ERR_TRACE(BUFFER_E):
                case WC_NO_ERR_TRACE(OPEN_RAN_E):
                case WC_NO_ERR_TRACE(FIPS_NOT_ALLOWED_E):
                case WC_NO_ERR_TRACE(DRBG_KAT_FIPS_E):
                case WC_NO_ERR_TRACE(DRBG_CONT_FIPS_E):
                    goto out;
                }

                if (timeout_secs == 0) {
                    break; /* Retry disabled -- return the real error, not
                            * WC_TIMEOUT_E. */
                }

                /* Allow interrupt only if we're stuck spinning retries -- i.e.,
                 * don't allow an untimely user signal to derail an
                 * initialization that is proceeding expeditiously.
                 */
                ret = WC_CHECK_FOR_INTR_SIGNALS();
                if (ret == WC_NO_ERR_TRACE(INTERRUPTED_E))
                    break;
                ts2 = XTIME(0);
                if ((timeout_secs > 0) && (ts2 - ts1 > timeout_secs)) {
                    ret = WC_TIMEOUT_E;
                    break;
                }
#ifdef WC_VERBOSE_RNG
                ++nretries;
#endif
            }
            if (ret != 0) {
#ifdef WC_VERBOSE_RNG
                WOLFSSL_DEBUG_PRINTF(
                    "ERROR: wc_InitRng returned %d after %d retries.\n", ret,
                    nretries);
#endif
                break;
            }
        }
    }

out:

    if (ret != 0)
        (void)wc_rng_bank_fini(ctx);

#ifdef WC_RNG_HAVE_RBGC
    if (root_inited)
        wc_FreeRng(&root);
#endif

    return ret;
}

WOLFSSL_API int wc_rng_bank_init(
    struct wc_rng_bank *ctx,
    int n_rngs,
    word32 flags,
    int timeout_secs,
    void *heap,
    int devId)
{

    return wc_rng_bank_init_nonce(ctx, n_rngs, flags, timeout_secs, heap, devId, NULL, 0);
}

WOLFSSL_API int wc_rng_bank_first_failover_inst_set(
    struct wc_rng_bank *ctx,
    int first_failover_inst)
{
    if ((ctx == NULL) ||
        (first_failover_inst < 0) ||
        (first_failover_inst >= ctx->n_rngs))
    {
        return BAD_FUNC_ARG;
    }
    ctx->first_failover_inst = first_failover_inst;
    return 0;
}

#ifndef WC_RNG_BANK_STATIC
WOLFSSL_API int wc_rng_bank_new(
    struct wc_rng_bank **ctx,
    int n_rngs,
    word32 flags,
    int timeout_secs,
    void *heap,
    int devId)
{
    int ret;

    if ((ctx == NULL) || (n_rngs <= 0))
        return BAD_FUNC_ARG;

    *ctx = (struct wc_rng_bank *)XMALLOC(sizeof(struct wc_rng_bank), heap, DYNAMIC_TYPE_RNG);
    if (*ctx == NULL)
        return MEMORY_E;

    ret = wc_rng_bank_init(*ctx, n_rngs, flags, timeout_secs, heap, devId);

    if (ret != 0) {
        XFREE(*ctx, heap, DYNAMIC_TYPE_RNG);
        *ctx = NULL;
    }

    return ret;
}
#endif /* !WC_RNG_BANK_STATIC */

WOLFSSL_API int wc_rng_bank_set_affinity_handlers(
    struct wc_rng_bank *ctx,
    wc_affinity_lock_fn_t affinity_lock_cb,
    wc_affinity_get_id_fn_t affinity_get_id_cb,
    wc_affinity_unlock_fn_t affinity_unlock_cb,
    void *cb_arg)
{
    if ((ctx == NULL) ||
        (! (ctx->flags & WC_RNG_BANK_FLAG_INITED)))
    {
        return BAD_FUNC_ARG;
    }
    if ((affinity_lock_cb == NULL) ^ (affinity_unlock_cb == NULL))
        return BAD_FUNC_ARG;
    if (wolfSSL_RefCur(ctx->refcount) != 1)
        return BUSY_E;
    ctx->affinity_lock_cb = affinity_lock_cb;
    ctx->affinity_get_id_cb = affinity_get_id_cb;
    ctx->affinity_unlock_cb = affinity_unlock_cb;
    ctx->cb_arg = cb_arg;
    return 0;
}

WOLFSSL_API int wc_rng_bank_fini(struct wc_rng_bank *ctx) {
    int i;
    int ret;
    WC_ATOMIC_INT_ARG new_refcount;

    if (ctx == NULL)
        return BAD_FUNC_ARG;

    if (ctx->flags == WC_RNG_BANK_FLAG_NONE)
        return 0;

    if (! (ctx->flags & WC_RNG_BANK_FLAG_INITED))
        return BAD_FUNC_ARG;

    if (wolfSSL_RefCur(ctx->refcount) > 1)
        return BUSY_E;
    else if (wolfSSL_RefCur(ctx->refcount) < 1)
        return BAD_STATE_E;

    wolfSSL_RefDec_IfEquals(&ctx->refcount, 1, &new_refcount, &ret);
    if (ret != 0) {
#ifdef WC_VERBOSE_RNG
        WOLFSSL_DEBUG_PRINTF(
            "WARNING: wc_rng_bank_fini() called with refcount %d.", new_refcount);
#endif
        if (new_refcount > 1)
            return BUSY_E;
        else
            return ret;
    }

#ifndef WC_RNG_BANK_STATIC
    if (ctx->rngs)
#endif
    {
        for (i = 0; i < ctx->n_rngs; ++i) {
            WC_RNG_lock_arg_t fini_lock_state = 0;
            (void)wc_rng_bank_inst_lock_read(&ctx->rngs[i],
                                   &fini_lock_state);
            if (fini_lock_state & WC_RNG_LOCK_HELD) {
                /* Held is the disqualifier; a bare sticky
                 * WC_RNG_LOCK_REQUIRED is the at-rest state of a marked
                 * free instance and is expected here.
                 *
                 * better to leak than to crash. */
#ifdef WC_VERBOSE_RNG
                WOLFSSL_DEBUG_PRINTF(
                    "BUG: wc_rng_bank_fini() called with RNG #%d still "
                    "locked.\n", i);
#endif
                wolfSSL_RefInc2(&ctx->refcount, &new_refcount, &ret);
                /* Always return BAD_STATE_E here -- a locked rng with a zero
                 * refcount on the bank is always a corruption.
                 */
                (void)new_refcount;
                (void)ret;
                return BAD_STATE_E;
            }
        }

        if (ctx->free_hook != NULL) {
            /* teardown is committed: fire the free hook (one-shot). */
            wc_rng_bank_free_hook_cb_t free_hook = ctx->free_hook;
            ctx->free_hook = NULL;
            (void)free_hook(ctx, ctx->free_hook_arg);
            ctx->free_hook_arg = NULL;
        }

        for (i = 0; i < ctx->n_rngs; ++i) {
            /* Lease-taking teardown: wc_FreeRng() on a _LOCK_REQUIRED
             * instance is (correctly) refused without the lease, so take
             * it -- structurally uncontended at refcount zero with the
             * held-check above passed.  The latch dies held in dying
             * memory, per the uncleared-on-free contract. */
            if ((wc_rng_bank_inst_lock_get(&ctx->rngs[i], 0) != 0) &&
                (wc_rng_bank_inst_lock_get_conditional(&ctx->rngs[i],
                     WC_RNG_LOCK_ENTROPY_INVALIDATED, 0) != 0))
            {
                /* can't happen absent corruption; leak, don't crash. */
#ifdef WC_VERBOSE_RNG
                WOLFSSL_DEBUG_PRINTF(
                    "BUG: wc_rng_bank_fini() couldn't take the teardown "
                    "lease on RNG #%d.\n", i);
#endif
                ret = BAD_STATE_E;
                continue;
            }
            wc_FreeRng(&ctx->rngs[i].rng);
        }
        if (ret == WC_NO_ERR_TRACE(BAD_STATE_E))
            return ret;

#ifndef WC_RNG_BANK_STATIC
        XFREE(ctx->rngs, ctx->heap, DYNAMIC_TYPE_RNG);
        ctx->rngs = NULL;
#endif
        ctx->n_rngs = 0;
    }

    wolfSSL_RefFree(&ctx->refcount);

    ctx->flags = WC_RNG_BANK_FLAG_NONE;
    ctx->cb_arg = NULL;

    return 0;
}

#ifndef WC_RNG_BANK_STATIC
WOLFSSL_API int wc_rng_bank_free(struct wc_rng_bank **ctx) {
    int ret;
    void *heap;

    if (ctx == NULL)
        return BAD_FUNC_ARG;

    if (*ctx == NULL)
        return 0;

    heap = (*ctx)->heap;

    ret = wc_rng_bank_fini(*ctx);

    if (ret == 0) {
        XFREE(*ctx, heap, DYNAMIC_TYPE_RNG);
        *ctx = NULL;
    }

    return ret;
}
#endif /* !WC_RNG_BANK_STATIC */

#ifdef WC_RNG_BANK_DEFAULT_SUPPORT

/* The default_rng_bank facility is used by the Linux kernel module as a global
 * resource for wc_rng_bank_checkout(),
 * wc_local_rng_bank_checkout_for_bankref(), and wc_InitRng_BankRef(), and can
 * be similarly used by any application, to cache DRBG seeding at application
 * startup.
 */

static struct wc_rng_bank * volatile default_rng_bank;

WOLFSSL_API int wc_rng_bank_default_set(struct wc_rng_bank *bank) {
    int ret;
    struct wc_rng_bank *cur_default_rng_bank = NULL;
    WC_ATOMIC_INT_ARG new_refcount;

    if (bank == NULL)
        return BAD_FUNC_ARG;

    if (! (bank->flags & WC_RNG_BANK_FLAG_INITED))
        return BAD_STATE_E;

    wolfSSL_RefInc_IfAtLeast(&bank->refcount, 1, &new_refcount, &ret);
    if (ret != 0) {
#ifdef WC_VERBOSE_RNG
        WOLFSSL_DEBUG_PRINTF(
        "BUG: wc_rng_bank_default_set() with refcount %d.\n", new_refcount);
#else
        (void)new_refcount;
#endif
        return ret;
    }
    if (wolfSSL_Atomic_Ptr_CompareExchange((void * volatile *)&default_rng_bank, (void **)&cur_default_rng_bank, bank)) {
        bank->flags |= WC_RNG_BANK_FLAG_DEFAULT_BANK;
        return 0;
    }
    else {
        wolfSSL_RefDec2(&bank->refcount, &new_refcount, &ret);
#ifdef WC_VERBOSE_RNG
        if (new_refcount <= 0)
            WOLFSSL_DEBUG_PRINTF(
            "BUG: wc_rng_bank_default_set() cleanup popped refcount to %d.\n", new_refcount);
#else
        (void)new_refcount;
#endif
        return BUSY_E;
    }
}

/* Note wc_rng_bank_default_checkout() must not be called before
 * wc_rng_bank_default_set() returns, or after wc_rng_bank_default_clear() is
 * called -- it is the caller's responsibility to assure this.
 */
WOLFSSL_API int wc_rng_bank_default_checkout(struct wc_rng_bank **bank) {
    int ret;
    struct wc_rng_bank *cur_default_rng_bank = default_rng_bank;
    WC_ATOMIC_INT_ARG new_refcount;

    if (bank == NULL)
        return BAD_FUNC_ARG;
    if (cur_default_rng_bank == NULL)
        return NO_DEFAULT_FOUND_E;
    else if (! (cur_default_rng_bank->flags & WC_RNG_BANK_FLAG_INITED))
        return BAD_STATE_E;

    if (cur_default_rng_bank->flags & WC_RNG_BANK_FLAG_NO_CHECKOUT_REFCOUNTING) {
        /* read-only validity test: >= 2 means inited and still registered
         * as the default (wc_rng_bank_default_set()'s standing ref). */
        if (wolfSSL_RefCur(cur_default_rng_bank->refcount) < 2)
            return BAD_STATE_E;
        ret = 0;
    }
    else {
        wolfSSL_RefInc_IfAtLeast(&cur_default_rng_bank->refcount, 2,
                                 &new_refcount, &ret);
        if (ret != 0)
            return ret;
    }

    *bank = cur_default_rng_bank;

    return ret;
}

WOLFSSL_API int wc_rng_bank_default_checkin(struct wc_rng_bank **bank) {
    int ret;
    WC_ATOMIC_INT_ARG new_refcount;
    if ((bank == NULL) || (*bank == NULL))
        return BAD_FUNC_ARG;
    if ((*bank)->flags & WC_RNG_BANK_FLAG_NO_CHECKOUT_REFCOUNTING) {
        *bank = NULL;
        return 0;
    }
    wolfSSL_RefDec2(&(*bank)->refcount, &new_refcount, &ret);
#ifdef WC_VERBOSE_RNG
    if (new_refcount <= 0)
        WOLFSSL_DEBUG_PRINTF(
        "BUG: wc_rng_bank_default_checkin() popped refcount to %d.\n", new_refcount);
#else
    (void)new_refcount;
#endif
    *bank = NULL;
    return ret;
}

/* Note, wc_rng_bank_default_clear() should only be called at module or
 * application shutdown to avoid races with wc_rng_bank_default_checkout(), and
 * must be called before wc_rng_bank_fini() on a bank previously passed to
 * wc_rng_bank_default_set().
 */
WOLFSSL_API int wc_rng_bank_default_clear(struct wc_rng_bank *bank) {
    if (bank == NULL)
        return BAD_FUNC_ARG;
    if (bank != default_rng_bank)
        return BAD_FUNC_ARG;
    if (wolfSSL_Atomic_Ptr_CompareExchange((void * volatile *)&default_rng_bank, (void **)&bank, NULL)) {
        int ret;
        WC_ATOMIC_INT_ARG new_refcount;
        bank->flags &= ~WC_RNG_BANK_FLAG_DEFAULT_BANK;
        wolfSSL_RefDec2(&bank->refcount, &new_refcount, &ret);
#ifdef WC_VERBOSE_RNG
        /* wc_rng_bank_fini() is the sole responsibility of the context that
         * called wc_rng_bank_default_set() for this wc_rng_bank.
         */
        if (new_refcount < 1)
            WOLFSSL_DEBUG_PRINTF(
                "BUG: wc_rng_bank_default_clear() popped refcount to %d.\n", new_refcount);
        if (! (bank->flags & WC_RNG_BANK_FLAG_INITED))
            WOLFSSL_DEBUG_PRINTF(
                "BUG: wc_rng_bank_default_clear() bank is already uninited.\n");
#else
        (void)new_refcount;
#endif
        return ret;
    }
    else
        return BUSY_E;
}

#endif /* WC_RNG_BANK_DEFAULT_SUPPORT */

/* wc_rng_bank_checkout() uses atomic operations to get exclusive ownership of a
 * DRBG without delay.  It expects to be called in uninterruptible context,
 * though works fine in any context.  When _PREFER_AFFINITY_INST, it starts by
 * trying the DRBG matching the local DRBG (usually the current CPU ID, returned
 * by bank->affinity_get_id_cb()), and if that doesn't immediately succeed, and
 * _CAN_FAIL_OVER_INST, it iterates upward until one succeeds.  The first
 * attempt will always succeed, even under intense load, unless there is or has
 * recently been a reseed or mix-in operation competing with generators.
 */
WOLFSSL_API int wc_rng_bank_checkout(
    struct wc_rng_bank *bank,
    struct wc_rng_bank_inst **rng_inst,
    int preferred_inst_offset,
    int timeout_secs,
    word32 flags)
{
    WC_RNG_lock_arg_t lock_extra_bits = 0;
    int ret = 0;
    time_t ts1, ts2;
    int n_rngs_tried = 0;
    int diverted_unusable = 0;
    WC_ATOMIC_INT_ARG new_refcount;
#ifdef WC_RNG_HAVE_NEXT_SEED
    WC_ATOMIC_INT_ARG NextSeedCurrent = 0;
    int recovered_claim = 0;
#endif
    int maybe_recovery_claim = 0;


    if (rng_inst == NULL)
        return BAD_FUNC_ARG;

    if (bank == NULL) {
#ifdef WC_RNG_BANK_DEFAULT_SUPPORT
        ret = wc_rng_bank_default_checkout(&bank);
        if (ret != 0)
            return ret;
        /* wc_rng_bank_default_checkout() increments bank->refcount, which we
         * carry through below (no matching wc_rng_bank_default_checkin()).
         */
#else
        return BAD_FUNC_ARG;
#endif
    }
    else {
        if ((! (bank->flags & WC_RNG_BANK_FLAG_INITED)) ||
            (wolfSSL_RefCur(bank->refcount) < 1))
        {
            return BAD_STATE_E;
        }

        /* Increment bank->refcount here speculatively to mitigate races with
         * bank deallocation.  With _NO_CHECKOUT_REFCOUNTING the container
         * guarantees liveness and the RefCur test above suffices.
         */
        if (! (bank->flags & WC_RNG_BANK_FLAG_NO_CHECKOUT_REFCOUNTING)) {
            wolfSSL_RefInc_IfAtLeast(&bank->refcount, 1, &new_refcount, &ret);
            if (ret != 0) {
#ifdef WC_VERBOSE_RNG
                WOLFSSL_DEBUG_PRINTF(
                    "wc_rng_bank_checkout() called with refcount %d.\n",
                    new_refcount);
#endif
                return ret;
            }
        }
    }

    if (flags & WC_RNG_BANK_FLAG_FOR_RECOVERY) {
        if (flags & WC_RNG_BANK_FLAG_PREDICTION_RESISTANCE) {
            ret = BAD_FUNC_ARG;
            goto out;
        }
    }
    else {
        if (((flags | bank->flags) & WC_RNG_BANK_FLAG_PREDICTION_RESISTANCE) &&
            (((! (flags & WC_RNG_BANK_FLAG_CAN_WAIT))) ||
             (flags & WC_RNG_BANK_FLAG_SEED_UNCREDITED)))
        {
            ret = BAD_FUNC_ARG;
            goto out;
        }
    }

    if ((flags & WC_RNG_BANK_FLAG_FOR_RECOVERY) &&
        (flags & (WC_RNG_BANK_FLAG_CAN_FAIL_OVER_INST |
                  WC_RNG_BANK_FLAG_PREFER_AFFINITY_INST |
                  WC_RNG_BANK_FLAG_ERROR_ON_RNG_FAILED)))
    {
        /* Recovery targets one explicit instance -- selection-altering flags
         * contradict it. */
        ret = BAD_FUNC_ARG;
        goto out;
    }

    if (! (flags & WC_RNG_BANK_FLAG_FOR_RECOVERY))
        flags |= bank->flags & (WC_RNG_BANK_FLAG_AFFINITY_LOCK | WC_RNG_BANK_FLAG_PREFER_AFFINITY_INST);

    if ((flags & WC_RNG_BANK_FLAG_PREFER_AFFINITY_INST) &&
        (bank->affinity_get_id_cb == NULL))
    {
#ifdef WC_VERBOSE_RNG
        WOLFSSL_DEBUG_PRINTF(
            "BUG: wc_rng_bank_checkout() called with _PREFER_AFFINITY_INST but "
            "no _get_id_cb.\n");
#endif
        ret = BAD_FUNC_ARG;
        goto out;
    }

    if ((timeout_secs > 0) && (flags & WC_RNG_BANK_FLAG_CAN_WAIT))
        ts1 = XTIME(0);
    else
        ts1 = 0; /* mollify -Wmaybe-uninitialized... */

    for (; ret == 0;) {

        if (flags & WC_RNG_BANK_FLAG_AFFINITY_LOCK) {
            if ((bank->affinity_lock_cb == NULL) ||
                (bank->affinity_unlock_cb == NULL))
            {
#ifdef WC_VERBOSE_RNG
                WOLFSSL_DEBUG_PRINTF(
                    "BUG: wc_rng_bank_checkout() called with _AFFINITY_LOCK but "
                    "missing _lock_cb.\n");
#endif
                ret = BAD_FUNC_ARG;
                break;
            }
            ret = bank->affinity_lock_cb(bank->cb_arg);
            if (ret == 0)
                lock_extra_bits |= WC_RNG_BANK_INST_LOCK_AFFINITY_LOCKED;
            else if (ret == WC_NO_ERR_TRACE(INTERRUPTED_E))
                break;
            else {
                /* need to, and can, continue regardless of the error code from
                 * bank->affinity_lock_cb. */
                ret = 0;
            }
        }

        if (flags & WC_RNG_BANK_FLAG_PREFER_AFFINITY_INST) {
            preferred_inst_offset = -1;
            ret = bank->affinity_get_id_cb(bank->cb_arg, &preferred_inst_offset);
            if (ret != 0) {
#ifdef WC_VERBOSE_RNG
                WOLFSSL_DEBUG_PRINTF(
                    "BUG: bank->affinity_get_id_cb() returned err %d.\n", ret);
#endif
                break;
            }
        }

        if (preferred_inst_offset < 0) {
            ret = BAD_INDEX_E;
            break;
        }

        if (preferred_inst_offset >= bank->n_rngs) {
            /* An affinity id can legitimately exceed n_rngs, there may be
             * more CPUs than instances.  Wrap into range when the caller
             * allows failover; otherwise the index is unusable.
             */
            if (flags & WC_RNG_BANK_FLAG_CAN_FAIL_OVER_INST) {
                preferred_inst_offset %= bank->n_rngs;
            }
            else {
                ret = BAD_INDEX_E;
                break;
            }
        }

#ifdef WC_RNG_HAVE_NEXT_SEED
        recovered_claim = 0;
#endif
        maybe_recovery_claim = 0;
        if ((wc_rng_bank_inst_lock_get(&bank->rngs[preferred_inst_offset],
                               lock_extra_bits) == 0)
            ||
            /* recovery-intent checkouts claim quarantined
             * (_ENTROPY_INVALIDATED) instances too -- the claimant is about
             * to recover them; ordinary consumers stay refused... */
            ((flags & WC_RNG_BANK_FLAG_FOR_RECOVERY) &&
             (wc_rng_bank_inst_lock_get_conditional(
                  &bank->rngs[preferred_inst_offset],
                  WC_RNG_LOCK_ENTROPY_INVALIDATED,
                  lock_extra_bits) == 0))
#ifdef WC_RNG_HAVE_NEXT_SEED
            ||
            /* ...UNLESS recovery is pure computation: when the quarantined
             * instance's banked next seed reads READY, any claimant
             * completes the recovery -- the invalidation purge guarantees
             * a READY bank is post-event, and a recovered_claim forces the
             * consume-at-checkout leg below (independent of bank consume
             * policy), performing the credited reseed from banked material
             * before the instance is handed out.  Without this admission,
             * the quarantine stands in front of the only machinery that
             * can lift it, and no bank instance ever recovers (observed as
             * system-wide checkout timeouts after a live
             * state-invalidation event). */
            ((wc_RNG_DRBG_NextSeedCurrent(
                  WC_RNG_BANK_INST_TO_RNG(&bank->rngs[preferred_inst_offset]),
                  &NextSeedCurrent) == 0) &&
             (NextSeedCurrent == WC_DRBG_NEXT_SEED_READY) &&
             (wc_rng_bank_inst_lock_get_conditional(
                  &bank->rngs[preferred_inst_offset],
                  WC_RNG_LOCK_ENTROPY_INVALIDATED,
                  lock_extra_bits) == 0) &&
             ((recovered_claim = 1) != 0))
#endif /* WC_RNG_HAVE_NEXT_SEED */
            ||
            /* last resort, by caller declaration: admit to the quarantined
             * instance anyway, transferring the recovery obligation to the
             * caller (checkout will return NEEDS_RECOVERY_E with the lease
             * held -- see WC_RNG_BANK_FLAG_MAYBE_FOR_RECOVERY). */
            ((flags & WC_RNG_BANK_FLAG_MAYBE_FOR_RECOVERY) &&
             (wc_rng_bank_inst_lock_get_conditional(
                  &bank->rngs[preferred_inst_offset],
                  WC_RNG_LOCK_ENTROPY_INVALIDATED,
                  lock_extra_bits) == 0) &&
             ((maybe_recovery_claim = 1) != 0))
            )
        {
            int inst_unusable;
            wc_drbg_reseed_ctr_t cur_reseed_ctr = 0;

            *rng_inst = &bank->rngs[preferred_inst_offset];

#ifdef WC_RNG_HAVE_NEXT_SEED
            if ((recovered_claim != 0) ||
                (((flags | bank->flags) & WC_RNG_BANK_FLAG_CONSUME_NEXT_SEED) &&
                 (! (flags & WC_RNG_BANK_FLAG_FOR_RECOVERY)) &&
                 (! ((flags | bank->flags) & WC_RNG_BANK_FLAG_PREDICTION_RESISTANCE))))
            {
                /* Consume a ready banked next seed, if any, BEFORE the
                 * usability evaluation below, so that evaluation judges the
                 * post-consume state: a reseed-due instance with a ready
                 * bank is cured here rather than diverted from or warned
                 * about.  The return value is deliberately ignored --
                 * every outcome is fully represented in instance state and
                 * is handled uniformly below:
                 *
                 *   consumed:        reseed counter reset; no longer due;
                 *   not ready / no DRBG:  nothing changed;
                 *   status-gated (instance already out of service): the
                 *       bank is left intact and the instance diverts or
                 *       errors below per flags;
                 *   hard reseed failure: the instance is now out of
                 *       service, and diverts (failover finds another
                 *       instance), errors (_ERROR_ON_RNG_FAILED ->
                 *       BAD_STATE_E via the out: mapping), or is handed
                 *       out under incumbent bare-targeted semantics --
                 *       identically to any other out-of-service instance.
                 */
                if (wc_RNG_DRBG_NextSeedNow(
                        WC_RNG_BANK_INST_TO_RNG(*rng_inst)) == 0)
                {
#ifndef WC_RNG_HAVE_LOCK
                    /* consumption is a credited reseed; mirror the
                     * in-boundary clear (see wc_rng_bank_reseed_range()). */
                    (void)wc_rng_bank_inst_lock_clear_invalidated(*rng_inst);
#endif
                }
            }
#endif /* WC_RNG_HAVE_NEXT_SEED */

            /* Two scenarios where we put an instance back and move on, both of
             * them only when the caller allows failover and instances remain:
             *
             * (1) It's not in service (a module-side failure marked it
             * WC_DRBG_FAILED, or an earlier wc_rng_bank_inst_reinit() failed
             * and left it WC_DRBG_NOT_INIT), or
             *
             * (2) It's due for reseed and the caller can't wait.
             *
             * rng.status, not a missing DRBG, is the out-of-service test.
             * With HAVE_INTEL_RDRAND on an RDRAND-capable CPU, _InitRng()
             * bypasses DRBG instantiation entirely and returns a usable
             * instance with no DRBG and status WC_DRBG_OK; treating that as
             * out of service would divert away from every instance in the
             * bank.  wc_RNG_DRBG_GetReseedCtr() reports a counter of 0 for
             * such instances -- never due for reseed -- so no separate
             * DRBG-presence test is needed here.
             */
            inst_unusable =
                (wc_RNG_GetStatus(WC_RNG_BANK_INST_TO_RNG(*rng_inst)) !=
                 WC_DRBG_OK);

            /* Divert (release and move on / retry) when:
             *
             * (a) the instance is out of service and the caller demanded
             *     the WC_RNG_BANK_FLAG_ERROR_ON_RNG_FAILED guarantee --
             *     unconditionally, in both targeted and failover modes,
             *     with the wait/timeout machinery below bounding the
             *     retries and the out: mapping converting the resulting
             *     BUSY_E/WC_TIMEOUT_E to BAD_STATE_E; or
             *
             * (b) the incumbent best-effort failover divert: instances
             *     remain untried this lap, and the instance is out of
             *     service or is due for reseed for a caller that can't
             *     wait.  (The lap disarm is the anti-livelock provision;
             *     with (a) in force, the guarantee supersedes it.)
             */
            if ((inst_unusable &&
                 (flags & WC_RNG_BANK_FLAG_ERROR_ON_RNG_FAILED)) ||
                ((flags & WC_RNG_BANK_FLAG_CAN_FAIL_OVER_INST) &&
                 (n_rngs_tried < bank->n_rngs) &&
                 (inst_unusable ||
                  ((! (flags & WC_RNG_BANK_FLAG_CAN_WAIT)) &&
                   (wc_RNG_DRBG_GetReseedCtr(
                       WC_RNG_BANK_INST_TO_RNG(*rng_inst),
                       &cur_reseed_ctr) == 0) &&
                   (cur_reseed_ctr >= WC_RESEED_INTERVAL)
            #ifdef WC_RNG_HAVE_NEXT_SEED
                   && (wc_RNG_DRBG_NextSeedCurrent(WC_RNG_BANK_INST_TO_RNG(*rng_inst), &NextSeedCurrent) == 0)
                   && (NextSeedCurrent != WC_DRBG_NEXT_SEED_READY)
            #endif
                      ))))
            {
                if (inst_unusable)
                    diverted_unusable = 1;
                (void)wc_rng_bank_inst_lock_put(*rng_inst);
                *rng_inst = NULL;
            }
            else {
#ifdef WC_VERBOSE_RNG
                if ((! (bank->flags & WC_RNG_BANK_FLAG_QUIET)) &&
                    (! (flags & (WC_RNG_BANK_FLAG_CAN_WAIT |
                                 WC_RNG_BANK_FLAG_FOR_RECOVERY |
                                 WC_RNG_BANK_FLAG_MAYBE_FOR_RECOVERY))) &&
                    (wc_RNG_DRBG_GetReseedCtr(
                        WC_RNG_BANK_INST_TO_RNG(*rng_inst),
                        &cur_reseed_ctr) == 0) &&
                    (cur_reseed_ctr >= WC_RESEED_INTERVAL))
                {
                    /* With WC_RNG_HAVE_NEXT_SEED, this reports only a
                     * genuinely-due instance: a consumable banked seed
                     * would already have cured it above. */
                    WOLFSSL_DEBUG_PRINTF(
                        "WARNING: wc_rng_bank_checkout() returning RNG ID %d, "
                        "currently marked for reseed, to !_CAN_WAIT caller.\n",
                        preferred_inst_offset);
                }

                /* Note that a caller can still encounter a PollAndReSeed() via
                 * wc_RNG_GenerateBlock() if a call bumps reseedCtr up to
                 * WC_RESEED_INTERVAL.  In kernel mode, the default interval is
                 * the SP 800-90A max of 2.81E+14, which is unlikely to be
                 * reached in practice.
                 */
#endif

                if (((flags | bank->flags) & WC_RNG_BANK_FLAG_PREDICTION_RESISTANCE) &&
                    (! (flags & WC_RNG_BANK_FLAG_FOR_RECOVERY)))
                {
                    ret = wc_RNG_DRBG_Reseed_Now(WC_RNG_BANK_INST_TO_RNG(*rng_inst),
                                                 NULL, 0);
                    if (ret != 0) {
                        (void)wc_rng_bank_inst_lock_put(*rng_inst);
                        *rng_inst = NULL;
                        goto out;
                    }
                }

#ifdef WOLFSSL_USE_SAVE_VECTOR_REGISTERS
                if ((flags | bank->flags) & WC_RNG_BANK_FLAG_NO_VECTOR_OPS) {
                    ret = DISABLE_VECTOR_REGISTERS();
                    if (ret == 0)
                        ret = wc_rng_bank_inst_lock_add_extra(*rng_inst,
                            WC_RNG_BANK_INST_LOCK_VEC_OPS_INH);
                    else if (ret == WC_NO_ERR_TRACE(WC_ACCEL_INHIBIT_E))
                        ret = 0;
                    else {
                        (void)wc_rng_bank_inst_lock_put(*rng_inst);
                        *rng_inst = NULL;
                        break;
                    }
                }
#endif /* WOLFSSL_USE_SAVE_VECTOR_REGISTERS */

                if (maybe_recovery_claim) {
                    WC_RNG_lock_arg_t claimed_lock_state = 0;
                    if ((wc_rng_bank_inst_lock_read(*rng_inst,
                                                    &claimed_lock_state) == 0)
                        && (claimed_lock_state &
                            WC_RNG_LOCK_ENTROPY_INVALIDATED))
                    {
#ifdef WC_RNG_HAVE_NEXT_SEED
                        /* material may have raced in since the admission
                         * scan: a successful banked consume cures the
                         * instance and downgrades this to an ordinary
                         * checkout. */
                        if (wc_RNG_DRBG_NextSeedNow(
                                WC_RNG_BANK_INST_TO_RNG(*rng_inst)) != 0)
#endif
                        {
                            /* The robust-mutex (EOWNERDEAD) pattern: an
                             * error return WITH the acquisition complete
                             * and persistent.  As with pthread robust
                             * mutexes, "this resource needs consistency
                             * recovery" is only safely reportable to a
                             * caller that already holds it -- reporting
                             * without the lease races the diagnosis
                             * against concurrent state changes, and
                             * leasing without the report invites blind
                             * use of unrecovered state.  The caller owns
                             * the lease: recover (credited reseed clears
                             * the quarantine) or check in.
                             *
                             * NOT via out: -- that's the failure path,
                             * which unwinds refcount and affinity state.
                             * This return holds everything the success
                             * return below holds. */
                            return NEEDS_RECOVERY_E;
                        }
                    }
                }

                return 0; /* Short-circuit return, holding onto bank refcount,
                           * RNG lock, affinity locks, and (if applicable)
                           * vector register inhibition.
                           */
            }
        }

        if (flags & WC_RNG_BANK_FLAG_CAN_FAIL_OVER_INST) {
            if ((n_rngs_tried >= bank->n_rngs) &&
                ((! (flags & WC_RNG_BANK_FLAG_CAN_WAIT)) ||
                 (timeout_secs == 0)))
            {
                ret = BUSY_E;
                break; /* jump to cleanup. */
            }
            /* There's no longer any consistent connection between the CPU ID
             * and the instance -- no point getting an affinity lock.
             */
            flags &= ~(word32)WC_RNG_BANK_FLAG_AFFINITY_LOCK;
            flags &= ~(word32)WC_RNG_BANK_FLAG_PREFER_AFFINITY_INST;

            if ((n_rngs_tried == 0) && (bank->first_failover_inst >= 0))
                preferred_inst_offset = bank->first_failover_inst;
            else {
                ++preferred_inst_offset;
                if (preferred_inst_offset >= bank->n_rngs)
                    preferred_inst_offset = 0;
            }
            ++n_rngs_tried;
        }
        else {
            if ((! (flags & WC_RNG_BANK_FLAG_CAN_WAIT)) ||
                (timeout_secs == 0))
            {
                ret = BUSY_E;
                break; /* jump to cleanup. */
            }
        }

        if (lock_extra_bits & WC_RNG_BANK_INST_LOCK_AFFINITY_LOCKED) {
            (void)bank->affinity_unlock_cb(bank->cb_arg);
            lock_extra_bits &= ~WC_RNG_BANK_INST_LOCK_AFFINITY_LOCKED;
        }

        if ((flags & WC_RNG_BANK_FLAG_CAN_WAIT) && (timeout_secs != 0)) {
            ret = WC_CHECK_FOR_INTR_SIGNALS();
            if (ret == WC_NO_ERR_TRACE(INTERRUPTED_E))
                break;

            if (timeout_secs > 0) {
                ts2 = XTIME(0);
                if (ts2 - ts1 >= timeout_secs) {
                    ret = WC_TIMEOUT_E;
                    break;
                }
            }

            WC_RELAX_LONG_LOOP();
        }
    }

out:

    if (ret == 0)
        ret = RNG_FAILURE_E;

    /* Under the WC_RNG_BANK_FLAG_ERROR_ON_RNG_FAILED guarantee, a lap or
     * wait that diverted from an out-of-service instance reports
     * BAD_STATE_E -- distinguishing bank degradation from mere contention
     * (BUSY_E) or slow contention (WC_TIMEOUT_E). */
    if (diverted_unusable &&
        (flags & WC_RNG_BANK_FLAG_ERROR_ON_RNG_FAILED) &&
        ((ret == WC_NO_ERR_TRACE(BUSY_E)) ||
         (ret == WC_NO_ERR_TRACE(WC_TIMEOUT_E))))
    {
        ret = BAD_STATE_E;
    }

    if (lock_extra_bits & WC_RNG_BANK_INST_LOCK_AFFINITY_LOCKED)
        (void)bank->affinity_unlock_cb(bank->cb_arg);

    /* Decrement the speculative refcount increment.  This also covers the
     * refcount increment in wc_rng_bank_default_checkout() if that's how it was
     * incremented.  With _NO_CHECKOUT_REFCOUNTING neither increment
     * happened.
     */
    if (! (bank->flags & WC_RNG_BANK_FLAG_NO_CHECKOUT_REFCOUNTING)) {
        int refdec_err;
        wolfSSL_RefDec2(&bank->refcount, &new_refcount, &refdec_err);
#ifdef WC_VERBOSE_RNG
        if (refdec_err != 0)
            WOLFSSL_DEBUG_PRINTF(
                "WARNING: wc_rng_bank_checkout() cleanup wolfSSL_RefDec2 returned %d.", refdec_err);
        else if (new_refcount <= 0)
            WOLFSSL_DEBUG_PRINTF(
                "WARNING: wc_rng_bank_checkout() bank refcount after wolfSSL_RefDec2() is %d.", new_refcount);
#else
        (void)new_refcount;
        (void)refdec_err;
#endif
    }

    return ret;
}

WOLFSSL_API int wc_rng_bank_register_free_hook(struct wc_rng_bank *bank,
    wc_rng_bank_free_hook_cb_t free_hook, void *arg)
{
    if (bank == NULL)
        return BAD_FUNC_ARG;
    bank->free_hook = free_hook;
    bank->free_hook_arg = arg;
    return 0;
}

#ifdef WC_RNG_BANK_HAVE_DAEMON_SUPPORT

WOLFSSL_API int wc_rng_bank_daemon_reserve(struct wc_rng_bank *bank, WC_ATOMIC_UINT_ARG magic) {
    int ret;
    WC_ATOMIC_INT_ARG new_refcount;

    if ((bank == NULL) || (magic == WC_RNG_BANK_DAEMON_MAGIC_FREE))
        return BAD_FUNC_ARG;

    if (bank->daemon != NULL)
        return BUSY_E;

    {
        WC_ATOMIC_UINT_ARG expected = WC_RNG_BANK_DAEMON_MAGIC_FREE;
        if (! wolfSSL_Atomic_Uint_CompareExchange(&bank->daemon_magic, &expected,
                                                 magic))
            return BUSY_E;
    }

    wolfSSL_RefInc_IfAtLeast(&bank->refcount, 1, &new_refcount, &ret);
    if (ret != 0) {
#ifdef WC_VERBOSE_RNG
        WOLFSSL_DEBUG_PRINTF(
            "wc_rng_bank_daemon_reserve() called with refcount %d.\n",
            new_refcount);
#endif
        WOLFSSL_ATOMIC_STORE(bank->daemon_magic, WC_RNG_BANK_DAEMON_MAGIC_FREE);
        return ret;
    }

    return 0;
}

WOLFSSL_API int wc_rng_bank_daemon_register(struct wc_rng_bank *bank, void *daemon, WC_ATOMIC_UINT_ARG magic) {
    if ((bank == NULL) || (daemon == NULL) || (magic == WC_RNG_BANK_DAEMON_MAGIC_FREE))
        return BAD_FUNC_ARG;

    if (bank->daemon != NULL)
        return ALREADY_E;

    if (WOLFSSL_ATOMIC_LOAD(bank->daemon_magic) != magic)
        return WRONG_TYPE_OBJECT_E;

    bank->daemon = daemon;

    return 0;
}

WOLFSSL_API int wc_rng_bank_daemon_unregister(struct wc_rng_bank *bank, void **daemon, WC_ATOMIC_UINT_ARG magic) {
    if ((bank == NULL) || (daemon == NULL) || (magic == WC_RNG_BANK_DAEMON_MAGIC_FREE))
        return BAD_FUNC_ARG;

    if (WOLFSSL_ATOMIC_LOAD(bank->daemon_magic) != magic)
        return WRONG_TYPE_OBJECT_E;

    if (bank->daemon == NULL)
        return ALREADY_E;

    *daemon = bank->daemon;
    bank->daemon = NULL;

    return 0;
}

WOLFSSL_API int wc_rng_bank_daemon_release(struct wc_rng_bank *bank, WC_ATOMIC_UINT_ARG magic) {
    int ret;
    WC_ATOMIC_INT_ARG new_refcount;

    if ((bank == NULL) || (magic == WC_RNG_BANK_DAEMON_MAGIC_FREE))
        return BAD_FUNC_ARG;

    if (WOLFSSL_ATOMIC_LOAD(bank->daemon_magic) != magic)
        return WRONG_TYPE_OBJECT_E;

    if (bank->daemon != NULL)
        return BUSY_E;

    wolfSSL_RefDec2(&bank->refcount, &new_refcount, &ret);
#ifdef WC_VERBOSE_RNG
    /* wc_rng_bank_fini() is the sole responsibility of the context that
     * called wc_rng_bank_daemon_reserve() for this wc_rng_bank.
     */
    if (new_refcount < 1)
        WOLFSSL_DEBUG_PRINTF(
        "wc_rng_bank_daemon_release() popped refcount to %d.\n", new_refcount);
    if (! (bank->flags & WC_RNG_BANK_FLAG_INITED))
        WOLFSSL_DEBUG_PRINTF(
            "BUG: wc_rng_bank_daemon_release() bank is already uninited.\n");
#else
    (void)new_refcount;
#endif

    WOLFSSL_ATOMIC_STORE(bank->daemon_magic, WC_RNG_BANK_DAEMON_MAGIC_FREE);

    return 0;
}

WOLFSSL_API int wc_rng_bank_daemon_root_set(struct wc_rng_bank *bank,
                                            WC_RNG *daemon_root)
{
    if (bank == NULL)
        return BAD_FUNC_ARG;
    bank->daemon_root = daemon_root;
    return 0;
}

WOLFSSL_API WC_RNG *wc_rng_bank_daemon_root_get(struct wc_rng_bank *bank)
{
    if (bank == NULL)
        return NULL;
    return bank->daemon_root;
}

#endif /* WC_RNG_BANK_HAVE_DAEMON_SUPPORT */

#ifdef WC_HAVE_RNG_BANKREF
/* wc_local_rng_bank_checkout_for_bankref() is the shim to the real WC_RNG when
 * wc_RNG_GenerateBlock() is called on a bankref WC_RNG.  It's called from
 * kernel atomic contexts, where waiting for a busy instance is the hazard, not
 * the fix.  Thus we pass timeout_secs = 0.
 *
 * _CAN_WAIT is not in contradiction with that.  _CAN_WAIT allows selection of
 * instances that would otherwise be skipped because due for reseed, so the
 * generate absorbs the reseed inline instead of skipping instances, while
 * timeout_secs = 0 inhibits waiting when no instances are available.
 *
 * _CAN_FAIL_OVER_INST tells wc_rng_bank_checkout() to sweep every instance --
 * BUSY_E is reachable only when all of them are held at once, which is
 * impossible by construction when the bank has at least as many instances as
 * there can be concurrent callers.  That sizing is the caller's contract: the
 * linuxkm module allocates nr_cpu_ids + 4.  An undersized bank does not fail
 * unsafely, but it does make this return BUSY_E to callers of the public API
 * that have no reason to expect it, so when WC_VERBOSE_RNG, we print a warning
 * if it occurs.
 */
WOLFSSL_LOCAL int wc_local_rng_bank_checkout_for_bankref(
    struct wc_rng_bank *bank,
    struct wc_rng_bank_inst **rng_inst)
{
    int ret;

    if (bank == NULL)
        return BAD_FUNC_ARG;

    ret = wc_rng_bank_checkout(
        bank, rng_inst, 0, 0,
        WC_RNG_BANK_FLAG_CAN_FAIL_OVER_INST |
        WC_RNG_BANK_FLAG_CAN_WAIT |
        ((bank->affinity_get_id_cb != NULL) ? WC_RNG_BANK_FLAG_PREFER_AFFINITY_INST : 0) |
        ((bank->affinity_lock_cb != NULL) ? WC_RNG_BANK_FLAG_AFFINITY_LOCK : 0));

#ifdef WC_VERBOSE_RNG
    if ((ret == WC_NO_ERR_TRACE(BUSY_E)) &&
        (! (bank->flags & WC_RNG_BANK_FLAG_QUIET)))
    {
        WOLFSSL_DEBUG_PRINTF(
            "WARNING: all %d rng_bank instances busy; size the bank to at "
            "least the peak number of concurrent callers.\n", bank->n_rngs);
    }
#endif

    return ret;
}
#endif /* WC_HAVE_RNG_BANKREF */

/* rng_inst_matches_bank() returns 1 if rng_inst is one of this bank's live
 * instances, else an error.  The INITED and refcount gates catch calls on a
 * torn-down bank (wc_rng_bank_fini() clears the flags and zeroes n_rngs); the
 * n_rngs and NULL checks are additional checks for the same case, to
 * catch data corruption opportunistically.  The range check's upper bound is
 * n_rngs - 1, not WC_RNG_BANK_STATIC_SIZE - 1: on a live bank sized below
 * WC_RNG_BANK_STATIC_SIZE, that bound is the only thing rejecting a pointer
 * to a trailing slot that was never instantiated.
 */
static WC_INLINE int rng_inst_matches_bank(
    struct wc_rng_bank *bank,
    struct wc_rng_bank_inst *rng_inst)
{
    if ((bank == NULL) || (rng_inst == NULL))
        return BAD_FUNC_ARG;
    if (! (bank->flags & WC_RNG_BANK_FLAG_INITED))
        return BAD_STATE_E;
    /* a live lease implies a per-checkout ref -- unless the bank runs
     * _NO_CHECKOUT_REFCOUNTING, where only the standing baseline holds. */
    if (wolfSSL_RefCur(bank->refcount) <
        ((bank->flags & WC_RNG_BANK_FLAG_NO_CHECKOUT_REFCOUNTING) ? 1 : 2))
        return BAD_STATE_E;

    if (bank->n_rngs <= 0)
        return BAD_FUNC_ARG;

#ifndef WC_RNG_BANK_STATIC
    /* Not testable in the static build, rngs is an array, never NULL. */
    if (bank->rngs == NULL)
        return BAD_FUNC_ARG;
#endif

    /* Compare integer addresses: the negative tests deliberately supply
     * fabricated pointers, for which pointer relationals and subtraction
     * are undefined (C11 6.5.8p5 / 6.5.6p9).  Integer comparisons are
     * defined for any value. */
    if (((wc_ptr_t)rng_inst < (wc_ptr_t)&bank->rngs[0]) ||
        ((wc_ptr_t)rng_inst > (wc_ptr_t)&bank->rngs[bank->n_rngs - 1]))
    {
        return BAD_FUNC_ARG;
    }

    /* Reject a pointer into the middle of an instance. */
    if ((((wc_ptr_t)rng_inst - (wc_ptr_t)&bank->rngs[0]) %
         sizeof(*rng_inst)) != 0)
    {
        return BAD_FUNC_ARG;
    }

    return 1;
}

WOLFSSL_API int wc_rng_bank_get_inst_id(struct wc_rng_bank_inst *rng_inst) {
    int ret;
    if (rng_inst == NULL)
        return BAD_FUNC_ARG;
    ret = rng_inst_matches_bank(rng_inst->bank, rng_inst);
    if (ret < 0)
        return ret;
    return (int)(((wc_ptr_t)rng_inst - (wc_ptr_t)&rng_inst->bank->rngs[0]) /
                 sizeof(*rng_inst));
}

WOLFSSL_API int wc_rng_bank_checkin(
    struct wc_rng_bank *bank,
    struct wc_rng_bank_inst **rng_inst)
{
    WC_RNG_lock_arg_t lockval;
    int ret;

    if ((rng_inst == NULL) || (*rng_inst == NULL))
        return BAD_FUNC_ARG;

#ifdef WC_RNG_BANK_DEFAULT_SUPPORT
    if (bank == NULL)
        bank = (*rng_inst)->bank;
#endif

    ret = rng_inst_matches_bank(bank, *rng_inst);
    if (ret < 0) {
        /* Nothing can be released here: the instance the caller actually holds
         * can't be identified from a pointer that isn't in this bank, so its
         * lock and the bank refcount stay held and wc_rng_bank_fini() will
         * report BUSY_E/BAD_STATE_E until the caller checks in correctly.
         *
         * We can't warn for this misuse because random_bank_test() exercises
         * the functionality.
         */
#ifdef WC_RNG_BANK_LOCK_DEBUG
        WOLFSSL_DEBUG_PRINTF(
            "BUG: wc_rng_bank_checkin() with an instance that is not in this "
            "bank; caller's lock and bank refcount (if any) remain held.\n");
#endif
        return ret;
    }

    ret = wc_rng_bank_inst_lock_read(*rng_inst, &lockval);
    if (ret < 0)
        return ret;

    ret = wc_rng_bank_inst_lock_put(*rng_inst);
    if (ret != 0) {
#ifdef WC_RNG_BANK_LOCK_DEBUG
        WOLFSSL_DEBUG_PRINTF(
            "wc_rng_bank_checkin(): wc_rng_bank_inst_lock_put() returned code %d "
            "(lock state 0x%x).\n", ret, lockval);
#endif
        if (ret == WC_NO_ERR_TRACE(OBJECT_NOT_LOCKED_E))
            return ret;
        /* else NEEDS_RECOVERY_E -- proceed with check-in. */
    }

    *rng_inst = NULL;

    if (lockval & WC_RNG_BANK_INST_LOCK_VEC_OPS_INH)
        REENABLE_VECTOR_REGISTERS();

    if (lockval & WC_RNG_BANK_INST_LOCK_AFFINITY_LOCKED)
        (void)bank->affinity_unlock_cb(bank->cb_arg);

    if (! (bank->flags & WC_RNG_BANK_FLAG_NO_CHECKOUT_REFCOUNTING)) {
        WC_ATOMIC_INT_ARG new_refcount;
        int refdec_err;
        wolfSSL_RefDec2(&bank->refcount, &new_refcount, &refdec_err);
#ifdef WC_VERBOSE_RNG
        if (refdec_err != 0)
            WOLFSSL_DEBUG_PRINTF(
                "WARNING: wc_rng_bank_checkin() wolfSSL_RefDec2 returned %d.", refdec_err);
        else if (new_refcount <= 0)
            WOLFSSL_DEBUG_PRINTF(
                "WARNING: wc_rng_bank_checkin() bank refcount after wolfSSL_RefDec2() is %d.", new_refcount);
#else
        (void)new_refcount;
        (void)refdec_err;
#endif
    }

    return ret;
}

WOLFSSL_API int wc_rng_bank_inst_checkin(
    struct wc_rng_bank_inst **rng_inst)
{
    if ((rng_inst == NULL) || (*rng_inst == NULL))
        return BAD_FUNC_ARG;
    return wc_rng_bank_checkin((*rng_inst)->bank, rng_inst);
}

#ifdef WC_RNG_HAVE_NEXT_SEED

#define WC_RNG_BANK_INST_OP_DAEMON ((WC_ATOMIC_INT_ARG)1)
#define WC_RNG_BANK_INST_OP_REINIT ((WC_ATOMIC_INT_ARG)2)

static int wc_rng_bank_next_seed_generate_local(
    struct wc_rng_bank *bank,
    int inst_offset,
    word32 n,
    WC_RNG *root)
{
    int ret;
    WC_ATOMIC_INT_ARG expected = 0;

    if (bank == NULL)
        return BAD_FUNC_ARG;
    if (! (bank->flags & WC_RNG_BANK_FLAG_INITED))
        return BAD_FUNC_ARG;
    if (inst_offset < 0)
        return BAD_FUNC_ARG;
    if (inst_offset >= bank->n_rngs)
        return BAD_FUNC_ARG;

#ifndef WC_RNG_HAVE_RBGC
    if (root != NULL)
        return NOT_COMPILED_IN;
#endif

    if (! wolfSSL_Atomic_Int_CompareExchange(&bank->inst_op_gate, &expected,
                                             WC_RNG_BANK_INST_OP_DAEMON))
    {
        /* A whole-instance operation (reinit) is in progress somewhere in
         * the bank -- skip this turn. */
        return BUSY_E;
    }

#ifdef WC_RNG_HAVE_RBGC
    if (root != NULL) {
        ret = wc_RNG_DRBG_NextSeedGenerate_RBGC(
            WC_RNG_BANK_INST_TO_RNG(&bank->rngs[inst_offset]), root, n);
    }
    else
#endif
    {
        ret = wc_RNG_DRBG_NextSeedGenerate(
            WC_RNG_BANK_INST_TO_RNG(&bank->rngs[inst_offset]), n);
    }

    WOLFSSL_ATOMIC_STORE(bank->inst_op_gate, 0);

    return ret;
}

WOLFSSL_API int wc_rng_bank_next_seed_generate_rbgc(
    struct wc_rng_bank *bank,
    int inst_offset,
    word32 n,
    WC_RNG *root)
{
    if (root == NULL)
        return BAD_FUNC_ARG;
    return wc_rng_bank_next_seed_generate_local(bank, inst_offset, n, root);
}

WOLFSSL_API int wc_rng_bank_next_seed_generate(
    struct wc_rng_bank *bank,
    int inst_offset,
    word32 n)
{
    return wc_rng_bank_next_seed_generate_local(bank, inst_offset, n, NULL);
}

#endif /* WC_RNG_HAVE_NEXT_SEED */

/* note the rng_inst passed to wc_rng_bank_inst_reinit() must have been obtained
 * via wc_rng_bank_checkout() to assure that the caller holds the proper locks.
 */
WOLFSSL_API int wc_rng_bank_inst_reinit(
    struct wc_rng_bank *bank,
    struct wc_rng_bank_inst *rng_inst,
    int timeout_secs,
    word32 flags)
{
    int ret;
    time_t ts1 = 0;
    int devId;
    WC_RNG_lock_arg_t cur_lock = 0;
#ifdef WC_RNG_DEBUG_STATS
    struct wc_rng_debug_stats_snapshot s;
    int stats_snap_ret;
#endif

    if (rng_inst == NULL)
        return BAD_FUNC_ARG;

    if (bank == NULL)
        bank = rng_inst->bank;

    ret = rng_inst_matches_bank(bank, rng_inst);
    if (ret < 0)
        return ret;

    /* No DRBG-NULL rejection here.  wc_FreeRng() below nulls the DRBG, so an
     * instance left that way by an earlier failed reinit needs another attempt.
     * Note that with HAVE_INTEL_RDRAND on an RDRAND-capable CPU, a NULL DRBG is
     * the normal in-service state.  wc_FreeRng() null-checks each member, so
     * it is a safe no-op when called on an already-freed instance.
     */
    if ((timeout_secs > 0) && (flags & WC_RNG_BANK_FLAG_CAN_WAIT))
        ts1 = XTIME(0);

#if defined(WOLFSSL_ASYNC_CRYPT) || defined(WOLF_CRYPTO_CB)
    devId = rng_inst->rng.devId;
#else
    devId = INVALID_DEVID;
#endif

#ifdef WC_RNG_HAVE_NEXT_SEED
    /* Exclude the entropy daemon's lockless banking for the duration of the
     * free/reinstantiate cycle.  Non-blocking on both sides: if the daemon
     * holds the gate, skip this reinit attempt (the instance stays out of
     * service and a later checkout retries); if reinit holds it, the daemon
     * skips its turn. */
    {
        WC_ATOMIC_INT_ARG expected = 0;
        if (! wolfSSL_Atomic_Int_CompareExchange(&bank->inst_op_gate,
                                                 &expected,
                                                 WC_RNG_BANK_INST_OP_REINIT))
        {
            return BUSY_E;
        }
    }
#endif

    /* Pre-read the held latch's annotation bits -- an owner-context read
     * of a live object (the constructor itself never reads its target).
     * The reinit is declared _LOCK_INITIALLY, so the instance is
     * invariantly locked across the free/reinstantiate cycle, and the
     * annotations (including a sticky WC_RNG_LOCK_REQUIRED, when the
     * instance carries one) are re-asserted below on success. */
    ret = wc_rng_bank_inst_lock_read(rng_inst, &cur_lock);
    if (ret < 0)
        return ret;

#ifdef WC_RNG_DEBUG_STATS
    stats_snap_ret =
        wc_rng_debug_stats_snap(&s, WC_RNG_BANK_INST_TO_RNG(rng_inst));
#endif

    wc_FreeRng(&rng_inst->rng);

    for (;;) {
#ifdef WC_RNG_INIT_FLAGS_LOCK_REQUIRED
        ret = wc_InitRngNonce_ex2(WC_RNG_BANK_INST_TO_RNG(rng_inst),
                                  (byte *)&rng_inst, sizeof(byte *),
                                  bank->heap, devId,
                                  WC_RNG_INIT_FLAGS_LOCK_REQUIRED |
                                  WC_RNG_INIT_FLAGS_LOCK_INITIALLY);
#else
        ret = wc_InitRngNonce_ex(WC_RNG_BANK_INST_TO_RNG(rng_inst),
                                  (byte *)&rng_inst, sizeof(byte *),
                                  bank->heap, devId);
#endif

        if (ret == 0) {
            if (cur_lock != 0) {
                ret = wc_rng_bank_inst_lock_set_extra(rng_inst, cur_lock);
            }
#ifdef WC_RNG_DEBUG_STATS
            if (stats_snap_ret == 0)
                wc_rng_debug_stats_restore(
                    &s, WC_RNG_BANK_INST_TO_RNG(rng_inst));
#endif
            break;
        }

        /* Relax between iterations exactly as wc_rng_bank_init() does.  The
         * caller may hold the affinity lock taken by wc_rng_bank_checkout(),
         * so this must not sleep in atomic context; WC_RELAX_LONG_LOOP()
         * degrades to a cpu_relax() there.
         */
        WC_RELAX_LONG_LOOP();

        /* Several plausible error codes are non-retryable -- fail early for
         * these rather than reattempting until the timeout.  Same list as
         * wc_rng_bank_init().
         */
        switch (ret) {
        case WC_NO_ERR_TRACE(BAD_MUTEX_E):
        case WC_NO_ERR_TRACE(BAD_FUNC_ARG):
        case WC_NO_ERR_TRACE(MEMORY_E):
        case WC_NO_ERR_TRACE(NOT_COMPILED_IN):
        case WC_NO_ERR_TRACE(MISSING_RNG_E):
        case WC_NO_ERR_TRACE(BUFFER_E):
        case WC_NO_ERR_TRACE(OPEN_RAN_E):
        case WC_NO_ERR_TRACE(FIPS_NOT_ALLOWED_E):
        case WC_NO_ERR_TRACE(DRBG_KAT_FIPS_E):
        case WC_NO_ERR_TRACE(DRBG_CONT_FIPS_E):
#ifdef WC_VERBOSE_RNG
            if (! (bank->flags & WC_RNG_BANK_FLAG_QUIET))
                WOLFSSL_DEBUG_PRINTF(
                    "WARNING: wc_rng_bank_inst_reinit() non-retryable err "
                    "%d.\n", ret);
#endif
            goto out;
        }

        if ((! (flags & WC_RNG_BANK_FLAG_CAN_WAIT)) || (timeout_secs == 0)) {
#ifdef WC_VERBOSE_RNG
            if (! (bank->flags & WC_RNG_BANK_FLAG_QUIET))
                WOLFSSL_DEBUG_PRINTF(
                    "WARNING: wc_rng_bank_inst_reinit() returning err %d.\n",
                    ret);
#endif
            break;
        }

        /* Allow interrupt only once we are stuck spinning retries.  Without
         * this, a negative timeout_secs (retry indefinitely) has no break at
         * all other than success.
         */
        {
            int intr = WC_CHECK_FOR_INTR_SIGNALS();
            if (intr == WC_NO_ERR_TRACE(INTERRUPTED_E)) {
                ret = intr;
                break;
            }
        }

        if (timeout_secs > 0) {
            time_t ts2 = XTIME(0);
            if (ts2 - ts1 >= timeout_secs) {
#ifdef WC_VERBOSE_RNG
                if (! (bank->flags & WC_RNG_BANK_FLAG_QUIET))
                    WOLFSSL_DEBUG_PRINTF(
                        "WARNING: wc_rng_bank_inst_reinit() timed out, "
                        "err %d.\n", ret);
#endif
                break;
            }
        }
    }

out:

    /* Leave a failed instance explicitly out of service rather than relying
     * on whichever status _InitRng() happened to leave behind (some of its
     * platform-specific failure paths return with status WC_DRBG_OK).
     * wc_FreeRng() deterministically leaves status WC_DRBG_NOT_INIT -- out of
     * service under every status-gate in this facility -- and is idempotent
     * on the failed-init carcass, so the marking happens entirely through
     * the module's own service interface.  wc_rng_bank_checkout() diverts
     * away from such an instance when the caller allows failover, and the
     * seed/reseed walks refuse it.
     */
    if (ret != 0)
        (void)wc_FreeRng(WC_RNG_BANK_INST_TO_RNG(rng_inst));

#ifdef WC_RNG_HAVE_NEXT_SEED
    WOLFSSL_ATOMIC_STORE(bank->inst_op_gate, 0);
#endif

    return ret;
}

WOLFSSL_API int wc_rng_bank_recover_inst(
    struct wc_rng_bank *bank,
    int inst_offset,
    int timeout_secs,
    word32 flags)
{
    struct wc_rng_bank_inst *rng_inst = NULL;
    int ret;
    int checkin_ret;

    if ((bank == NULL) ||
        (flags & ~(word32)(WC_RNG_BANK_FLAG_CAN_WAIT |
                           WC_RNG_BANK_FLAG_AFFINITY_LOCK)))
    {
        return BAD_FUNC_ARG;
    }

    ret = wc_rng_bank_checkout(bank, &rng_inst, inst_offset, timeout_secs,
                               flags | WC_RNG_BANK_FLAG_FOR_RECOVERY);
    if (ret != 0)
        return ret;

    if (wc_RNG_GetStatus(WC_RNG_BANK_INST_TO_RNG(rng_inst)) != WC_DRBG_OK) {
        /* Out of service -- recover it.  A BUSY_E from the whole-instance-
         * operation gate is retryable on a later patrol turn. */
        ret = wc_rng_bank_inst_reinit(bank, rng_inst, timeout_secs, flags);
    }
    /* else: healthy -- a stale lockless status observation; no-op. */

    checkin_ret = wc_rng_bank_checkin(bank, &rng_inst);
    if ((checkin_ret != 0) && (ret == 0))
        ret = checkin_ret;

    return ret;
}

#ifdef WC_RNG_HAVE_RBGC
/* Unified mechanics for wc_rng_bank_spawn() and wc_rng_bank_spawn_new():
 * check out -> wc_InitRngNonceRBGC[_New]() -> check in, following the
 * exactly-one-destination convention of random.c's SpawnRngRBGC().  All
 * RBGC semantics (depth-one enforcement, leaf tagging, strength
 * accounting, root reseed-counter debit) are the spawn APIs' own; the
 * bank contributes instance selection, the lease, and (optionally, via
 * WC_RNG_BANK_FLAG_CONSUME_NEXT_SEED) a banked reseed of the root before
 * the spawn draw. */
static int rng_bank_spawn(
    struct wc_rng_bank *bank,
    WC_RNG *leaf_stack,
    WC_RNG **leaf_heap,
    byte *nonce,
    word32 nonceSz,
    int preferred_inst_offset,
    int timeout_secs,
    word32 flags)
{
    struct wc_rng_bank_inst *rng_inst = NULL;
    int ret;
    int checkin_ret;

    if ((leaf_stack == NULL) == (leaf_heap == NULL))
        return BAD_FUNC_ARG;

    if (flags & (WC_RNG_BANK_FLAG_SEED_UNCREDITED |
                 WC_RNG_BANK_FLAG_FOR_RECOVERY))
        return BAD_FUNC_ARG;

    /* bank == NULL resolves to the default bank inside
     * wc_rng_bank_checkout(), which carries the default-bank refcount
     * through the lease; the one-arg wc_rng_bank_inst_checkin() releases
     * the whole arrangement without requiring a bank pointer here.
     * WC_RNG_BANK_FLAG_ERROR_ON_RNG_FAILED makes the checkout itself
     * guarantee an in-service instance (or an error with no lease), so no
     * status gate is needed here. */
    ret = wc_rng_bank_checkout(bank, &rng_inst, preferred_inst_offset,
                               timeout_secs,
                               flags | WC_RNG_BANK_FLAG_ERROR_ON_RNG_FAILED);
    if (ret != 0)
        return ret;

    {
        word32 child_init_flags = WC_RNG_INIT_FLAGS_NONE;
        if (flags & WC_RNG_BANK_FLAG_SPAWN_RECOVER_AND_PROMOTE)
            child_init_flags |= WC_RNG_INIT_FLAGS_RECOVER_AND_PROMOTE_FROM_NEXT_SEED;
    if (leaf_stack != NULL) {
        ret = wc_InitRngNonceRBGC(leaf_stack,
                                  WC_RNG_BANK_INST_TO_RNG(rng_inst),
                                  nonce, nonceSz,
                                  child_init_flags
                                 );
    }
    else {
#ifndef WC_NO_CONSTRUCTORS
        ret = wc_InitRngNonceRBGC_New(leaf_heap,
                                      WC_RNG_BANK_INST_TO_RNG(rng_inst),
                                      nonce, nonceSz,
                                      child_init_flags);
#else
        /* Unreachable: wc_rng_bank_spawn_new() is absent under
         * WC_NO_CONSTRUCTORS, so leaf_heap is always null here. */
        ret = BAD_FUNC_ARG;
#endif
    }
    }

    checkin_ret = wc_rng_bank_inst_checkin(&rng_inst);
    if ((checkin_ret != 0) && (ret == 0)) {
        /* The leaf came up but the lease release failed: surface the
         * check-in error and don't hand back a leaf the caller would
         * reasonably pair with a healthy bank. */
        if (leaf_stack != NULL) {
            (void)wc_FreeRng(leaf_stack);
        }
#ifndef WC_NO_CONSTRUCTORS
        else {
            wc_rng_free(*leaf_heap);
            *leaf_heap = NULL;
        }
#endif
        ret = checkin_ret;
    }

    return ret;
}

WOLFSSL_API int wc_rng_bank_spawn(
    struct wc_rng_bank *bank,
    WC_RNG *leaf_rng,
    byte *nonce,
    word32 nonceSz,
    int preferred_inst_offset,
    int timeout_secs,
    word32 flags)
{
    return rng_bank_spawn(bank, leaf_rng, NULL, nonce, nonceSz,
                          preferred_inst_offset, timeout_secs, flags);
}

#ifndef WC_NO_CONSTRUCTORS
WOLFSSL_API int wc_rng_bank_spawn_new(
    struct wc_rng_bank *bank,
    WC_RNG **leaf_rng,
    byte *nonce,
    word32 nonceSz,
    int preferred_inst_offset,
    int timeout_secs,
    word32 flags)
{
    return rng_bank_spawn(bank, NULL, leaf_rng, nonce, nonceSz,
                          preferred_inst_offset, timeout_secs, flags);
}
#endif /* !WC_NO_CONSTRUCTORS */
#endif /* WC_RNG_HAVE_RBGC */

WOLFSSL_API int wc_rng_bank_seed_range(struct wc_rng_bank *bank,
                                       int first_inst, int last_inst,
                                       const byte* seed, word32 seedSz,
                                       int timeout_secs,
                                       word32 flags)
{
    int ret = 0;
    int n;
#ifdef WC_RNG_BANK_DEFAULT_SUPPORT
    int bank_is_default = 0;
#endif

    /* wc_rng_bank_seed() must walk every instance by explicit index -- forbid
     * flags that would let wc_rng_bank_checkout() pick a different instance
     * than requested.  Same restriction applies in wc_rng_bank_reseed().
     */
    if (flags & (WC_RNG_BANK_FLAG_CAN_FAIL_OVER_INST |
                 WC_RNG_BANK_FLAG_PREFER_AFFINITY_INST |
                 WC_RNG_BANK_FLAG_CONSUME_NEXT_SEED |
                 WC_RNG_BANK_FLAG_FOR_RECOVERY))
        return BAD_FUNC_ARG;

    if (first_inst < 0)
        return BAD_INDEX_E;

    if (bank == NULL) {
#ifdef WC_RNG_BANK_DEFAULT_SUPPORT
        if (seedSz == 0) {
            if (default_rng_bank == NULL)
                return NO_DEFAULT_FOUND_E;
            else
                return 0;
        }
        ret = wc_rng_bank_default_checkout(&bank);
        if (ret != 0)
            return ret;
        bank_is_default = 1;
#else
        return BAD_FUNC_ARG;
#endif
    }
    else {
        if (! (bank->flags & WC_RNG_BANK_FLAG_INITED))
            return BAD_STATE_E;
        if (seedSz == 0)
            return 0;
    }

    if (first_inst >= bank->n_rngs) {
        ret = BAD_INDEX_E;
        goto out;
    }
    if (last_inst < 0)
        last_inst = bank->n_rngs - 1;
    else if (last_inst >= bank->n_rngs) {
        ret = BAD_INDEX_E;
        goto out;
    }
    else if (last_inst < first_inst) {
        ret = BAD_INDEX_E;
        goto out;
    }

    /* This iteration counts down, whereas the iteration in get_drbg() counts
     * up, to assure they can't possibly phase-lock to each other.
     */
    for (n = last_inst; n >= first_inst; --n) {
        struct wc_rng_bank_inst *drbg;
        ret = wc_rng_bank_checkout(bank, &drbg, n, timeout_secs,
                                   flags & ~(word32)
                                       (WC_RNG_BANK_FLAG_SEED_UNCREDITED |
                                        WC_RNG_BANK_FLAG_CONSUME_NEXT_SEED));
        if (ret != 0) {
#ifdef WC_VERBOSE_RNG
            if (! (bank->flags & WC_RNG_BANK_FLAG_QUIET))
                WOLFSSL_DEBUG_PRINTF(
                    "WARNING: wc_rng_bank_seed(): wc_rng_bank_checkout() for "
                    "inst#%d returned err %d.\n", n, ret);
#endif
            break;
        }
        /* Note that a NULL DRBG doesn't necessarily indicate failure:
         * _InitRng() bypasses DRBG instantiation when the CPU has RDRAND
         * (HAVE_INTEL_RDRAND), leaving a usable instance with drbg NULL and
         * status WC_DRBG_OK.  wc_RNG_DRBG_Reseed() gracefully handles that case
         * itself (random.c returns success for a NULL DRBG under RDRAND), so
         * let it through rather than calling it an error.
         */
        else if (wc_RNG_GetStatus(WC_RNG_BANK_INST_TO_RNG(drbg)) !=
                 WC_DRBG_OK)
        {
#ifdef WC_VERBOSE_RNG
            if (! (bank->flags & WC_RNG_BANK_FLAG_QUIET))
                WOLFSSL_DEBUG_PRINTF(
                    "WARNING: wc_rng_bank_seed(): inst#%d is out of service "
                    "(status %d).\n", n,
                    wc_RNG_GetStatus(WC_RNG_BANK_INST_TO_RNG(drbg)));
#endif
            ret = BAD_STATE_E;
        }
        else if ((ret = ((flags & WC_RNG_BANK_FLAG_SEED_UNCREDITED)
                         ? wc_RNG_DRBG_Reseed_Uncredited(
                               WC_RNG_BANK_INST_TO_RNG(drbg), seed, seedSz)
                         : wc_RNG_DRBG_Reseed(
                               WC_RNG_BANK_INST_TO_RNG(drbg), seed, seedSz)))
                 != 0)
        {
#ifdef WC_VERBOSE_RNG
            WOLFSSL_DEBUG_PRINTF(
                "WARNING: wc_rng_bank_seed(): Hash_DRBG_Reseed() for inst#%d "
                "returned %d\n", n, ret);
#endif
        }

        (void)wc_rng_bank_checkin(bank, &drbg);

        if (ret != 0)
            break;
    }

out:

#ifdef WC_RNG_BANK_DEFAULT_SUPPORT
    if (bank_is_default)
        (void)wc_rng_bank_default_checkin(&bank);
#endif

    return ret;
}

WOLFSSL_API int wc_rng_bank_seed(struct wc_rng_bank *bank,
                                 const byte* seed, word32 seedSz,
                                 int timeout_secs,
                                 word32 flags)
{
    return wc_rng_bank_seed_range(bank, 0, -1, seed, seedSz, timeout_secs,
                                  flags);
}

WOLFSSL_API int wc_rng_bank_reseed_range(struct wc_rng_bank *bank,
                                         int first_inst, int last_inst,
                                         int timeout_secs,
                                         word32 flags)
{
    int n;
    int ret;
    time_t ts1 = 0;
#ifdef WC_RNG_BANK_DEFAULT_SUPPORT
    int bank_is_default = 0;
#endif

    /* wc_rng_bank_reseed() must walk every instance by explicit index -- forbid
     * flags that would let wc_rng_bank_checkout() pick a different instance
     * than requested.  Same restriction applies in wc_rng_bank_seed().
     * WC_RNG_BANK_FLAG_SEED_UNCREDITED applies only to wc_rng_bank_seed() --
     * a bank reseed is always from the module's own seed source, and always
     * credited.
     */
    if (flags & (WC_RNG_BANK_FLAG_CAN_FAIL_OVER_INST |
                 WC_RNG_BANK_FLAG_PREFER_AFFINITY_INST |
                 WC_RNG_BANK_FLAG_SEED_UNCREDITED |
                 WC_RNG_BANK_FLAG_CONSUME_NEXT_SEED |
                 WC_RNG_BANK_FLAG_FOR_RECOVERY))
        return BAD_FUNC_ARG;

    if (first_inst < 0)
        return BAD_INDEX_E;

    if (bank == NULL) {
#ifdef WC_RNG_BANK_DEFAULT_SUPPORT
        ret = wc_rng_bank_default_checkout(&bank);
        if (ret != 0)
            return ret;
        bank_is_default = 1;
#else
        return BAD_FUNC_ARG;
#endif
    }
    else {
        if (! (bank->flags & WC_RNG_BANK_FLAG_INITED))
            return BAD_STATE_E;
    }

    if (first_inst >= bank->n_rngs) {
        ret = BAD_INDEX_E;
        goto out;
    }
    if (last_inst < 0)
        last_inst = bank->n_rngs - 1;
    else if (last_inst >= bank->n_rngs) {
        ret = BAD_INDEX_E;
        goto out;
    }
    else if (last_inst < first_inst) {
        ret = BAD_INDEX_E;
        goto out;
    }

    if ((timeout_secs > 0) && (flags & WC_RNG_BANK_FLAG_CAN_WAIT))
        ts1 = XTIME(0);

    for (n = last_inst; n >= first_inst; --n) {
        struct wc_rng_bank_inst *drbg;

        ret = wc_rng_bank_checkout(bank, &drbg, n, timeout_secs,
                                   flags | WC_RNG_BANK_FLAG_FOR_RECOVERY);
        if (ret != 0)
            goto out;

        if (wc_RNG_GetStatus(WC_RNG_BANK_INST_TO_RNG(drbg)) != WC_DRBG_OK) {
#ifdef WC_VERBOSE_RNG
            WOLFSSL_DEBUG_PRINTF(
                "WARNING: wc_rng_bank_reseed(): inst#%d is out of service "
                "(status %d).\n", n,
                wc_RNG_GetStatus(WC_RNG_BANK_INST_TO_RNG(drbg)));
#endif
            (void)wc_rng_bank_checkin(bank, &drbg);
            ret = BAD_STATE_E;
            goto out;
        }

        /* An in-service instance can still have no DRBG: _InitRng() bypasses
         * DRBG instantiation when the CPU has RDRAND (HAVE_INTEL_RDRAND).
         * There is nothing to reseed in that case; skip, do not fail.
         */
        if (! wc_RNG_DRBG_Present(WC_RNG_BANK_INST_TO_RNG(drbg))) {
            (void)wc_rng_bank_checkin(bank, &drbg);
            continue;
        }

        if (flags & WC_RNG_BANK_FLAG_CAN_WAIT) {
            for (;;) {
                time_t ts2;
                ret = wc_RNG_DRBG_Reseed_Now(WC_RNG_BANK_INST_TO_RNG(drbg),
                                             NULL, 0);
                if (ret == 0) {
#ifndef WC_RNG_HAVE_LOCK
                    /* the pre-lock boundary can't see the inst-side latch:
                     * mirror the in-boundary clear-on-credited-reseed. */
                    (void)wc_rng_bank_inst_lock_clear_invalidated(drbg);
#endif
                    break;
                }
                if ((timeout_secs == 0) ||
                    (! (flags & WC_RNG_BANK_FLAG_CAN_WAIT)))
                {
                    break;
                }
                if (timeout_secs > 0) {
                    ts2 = XTIME(0);
                    if (ts2 - ts1 > timeout_secs) {
#ifdef WC_VERBOSE_RNG
                        WOLFSSL_DEBUG_PRINTF(
                            "ERROR: timeout trying wc_RNG_DRBG_Reseed_Now() "
                            "for DRBG #%d, err %d.", n, ret);
#endif
                        ret = WC_TIMEOUT_E;
                        break;
                    }
                }
                ret = WC_CHECK_FOR_INTR_SIGNALS();
                if (ret == WC_NO_ERR_TRACE(INTERRUPTED_E))
                    break;
                WC_RELAX_LONG_LOOP();
            }
            if (ret != 0) {
                /* Preserve the pre-existing contract: a failed forced reseed
                 * leaves the instance due for reseed, so the next generate
                 * operation retries it in-boundary. */
                (void)wc_RNG_DRBG_ScheduleReseed(WC_RNG_BANK_INST_TO_RNG(drbg));
            }
#ifdef WC_VERBOSE_RNG
            if ((ret != 0) && (ret != WC_NO_ERR_TRACE(WC_TIMEOUT_E)))
                WOLFSSL_DEBUG_PRINTF(
                    "ERROR: wc_rng_bank_reseed() wc_RNG_DRBG_Reseed_Now() "
                    "for DRBG #%d returned %d.", n, ret);
#endif
            (void)wc_rng_bank_checkin(bank, &drbg);
            if ((ret == WC_NO_ERR_TRACE(WC_TIMEOUT_E)) ||
                (ret == WC_NO_ERR_TRACE(INTERRUPTED_E)))
            {
                goto out;
            }
            ret = WC_CHECK_FOR_INTR_SIGNALS();
            if (ret == WC_NO_ERR_TRACE(INTERRUPTED_E))
                goto out;
            WC_RELAX_LONG_LOOP();
        }
        else {
            /* Cannot gather entropy without waiting -- mark the instance due
             * for reseed and let the next entropy-capable generate operation
             * perform it in-boundary. */
            (void)wc_RNG_DRBG_ScheduleReseed(WC_RNG_BANK_INST_TO_RNG(drbg));
            (void)wc_rng_bank_checkin(bank, &drbg);
        }
    }

    ret = 0;

out:

#ifdef WC_RNG_BANK_DEFAULT_SUPPORT
    if (bank_is_default)
        (void)wc_rng_bank_default_checkin(&bank);
#endif

    return ret;
}

WOLFSSL_API int wc_rng_bank_reseed(struct wc_rng_bank *bank,
                                   int timeout_secs,
                                   word32 flags)
{
    return wc_rng_bank_reseed_range(bank, 0, -1, timeout_secs, flags);
}

WOLFSSL_API int wc_rng_bank_invalidate_entropy(struct wc_rng_bank *bank,
                                               word32 flags)
{
    int n;
    int ret = 0;
#ifdef WC_RNG_BANK_DEFAULT_SUPPORT
    int bank_is_default = 0;
#endif

    if (flags != 0)
        return BAD_FUNC_ARG;

    if (bank == NULL) {
#ifdef WC_RNG_BANK_DEFAULT_SUPPORT
        ret = wc_rng_bank_default_checkout(&bank);
        if (ret != 0)
            return ret;
        bank_is_default = 1;
#else
        return BAD_FUNC_ARG;
#endif
    }
    else {
        if (! (bank->flags & WC_RNG_BANK_FLAG_INITED))
            return BAD_STATE_E;
    }

    /* Best-effort-complete: an error on one instance must not leave the
     * rest un-flagged.  First error wins the return. */
    for (n = 0; n < bank->n_rngs; n++) {
        int this_ret = wc_rng_bank_inst_invalidate_entropy(&bank->rngs[n]);
        if ((this_ret != 0) && (ret == 0))
            ret = this_ret;
    }

#ifdef WC_RNG_BANK_DEFAULT_SUPPORT
    if (bank_is_default)
        (void)wc_rng_bank_default_checkin(&bank);
#endif

    return ret;
}

#ifdef WC_HAVE_RNG_BANKREF

static int wc_InitRng_BankRef_local(struct wc_rng_bank *bank, WC_RNG **rng) {
    int ret;
    WC_ATOMIC_INT_ARG new_refcount;

    if (rng == NULL)
        return BAD_FUNC_ARG;

    if (bank == NULL) {
#ifdef WC_RNG_BANK_DEFAULT_SUPPORT
        ret = wc_rng_bank_default_checkout(&bank);
        if (ret != 0)
            return ret;
        /* wc_rng_bank_default_checkout() increments bank->refcount, which we
         * carry through below (no matching wc_rng_bank_default_checkin()).
         */
#else
        return BAD_FUNC_ARG;
#endif
    }
    else {
        if (! (bank->flags & WC_RNG_BANK_FLAG_INITED))
            return BAD_STATE_E;
        wolfSSL_RefInc_IfAtLeast(&bank->refcount, 1, &new_refcount, &ret);
        (void)new_refcount;
        if (ret != 0)
            return ret;
    }

#if !defined(WC_RNG_BANK_STATIC) && !defined(WC_NO_CONSTRUCTORS)
    if (*rng == NULL) {
        *rng = (WC_RNG*)XMALLOC(sizeof(WC_RNG), bank->heap, DYNAMIC_TYPE_RNG);
        if (*rng == NULL) {
            ret = MEMORY_E;
            goto out;
        }
    }
#endif

    XMEMSET(*rng, 0, sizeof(**rng));
    (*rng)->heap = bank->heap;
    (*rng)->status = WC_DRBG_BANKREF;
    (*rng)->bankref = bank;

    ret = 0;

#if !defined(WC_RNG_BANK_STATIC) && !defined(WC_NO_CONSTRUCTORS)
out:
#endif

    if (ret != 0) {
        int refdec_err;
        wolfSSL_RefDec2(&bank->refcount, &new_refcount, &refdec_err);
        (void)new_refcount;
        (void)refdec_err;
    }

    return ret;
}

WOLFSSL_API int wc_InitRng_BankRef(struct wc_rng_bank *bank, WC_RNG *rng)
{
    if (rng == NULL)
        return BAD_FUNC_ARG;
    return wc_InitRng_BankRef_local(bank, &rng);
}

WOLFSSL_API int wc_BankRef_Release(WC_RNG *rng)
{
    int isZero = 0;
    int ret = 0;
    if (rng == NULL)
        return BAD_FUNC_ARG;
    if (rng->bankref == NULL)
        return BAD_FUNC_ARG;
    wolfSSL_RefDec(&rng->bankref->refcount, &isZero, &ret);
#ifdef WC_VERBOSE_RNG
    if (isZero)
        WOLFSSL_DEBUG_PRINTF(
            "BUG: wc_BankRef_Release() popped refcount to zero.\n");
#else
    (void)isZero;
#endif
    rng->heap = NULL;
    rng->status = WC_DRBG_NOT_INIT;
    rng->bankref = NULL;
    return ret;
}

#if !defined(WC_RNG_BANK_STATIC) && !defined(WC_NO_CONSTRUCTORS)
WOLFSSL_API int wc_rng_new_bankref(struct wc_rng_bank *bank, WC_RNG **rng) {
    if (rng == NULL)
        return BAD_FUNC_ARG;
    *rng = NULL;
    return wc_InitRng_BankRef_local(bank, rng);
}
#endif /* !WC_RNG_BANK_STATIC && !WC_NO_CONSTRUCTORS */

#endif /* WC_HAVE_RNG_BANKREF */

#ifdef WC_RNG_DEBUG_STATS

WOLFSSL_API int wc_rng_bank_debug_stats_snap(struct wc_rng_debug_stats_snapshot *s,
                                             struct wc_rng_bank *bank)
{
    int i;
    int ret;

    if ((s == NULL) || (bank == NULL))
        return BAD_FUNC_ARG;

    XMEMSET(s, 0, sizeof(*s));

    for (i = 0; i < bank->n_rngs; ++i) {
        WC_RNG *rng = WC_RNG_BANK_INST_TO_RNG(&bank->rngs[i]);
        ret = wc_rng_debug_stats_sum(s, rng);
        if (ret != 0)
            break;
    }

    return ret;
}

#endif /* WC_RNG_DEBUG_STATS */

#endif /* WC_RNG_BANK_SUPPORT */
