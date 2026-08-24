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
WOLFSSL_API int wc_rng_bank_init(
    struct wc_rng_bank *ctx,
    int n_rngs,
    word32 flags,
    int timeout_secs,
    void *heap,
    int devId)
{
    int i;
    int ret;
    int need_reenable_vec = 0;

    if ((ctx == NULL) || (n_rngs <= 0))
        return BAD_FUNC_ARG;

    XMEMSET(ctx, 0, sizeof(*ctx));

    wolfSSL_RefInit(&ctx->refcount, &ret);
    if (ret != 0)
        return ret;

    ctx->flags = flags | WC_RNG_BANK_FLAG_INITED;
    ctx->heap = heap;

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
                ret = wc_InitRngNonce_ex(
                        WC_RNG_BANK_INST_TO_RNG(rng_inst),
                        (byte *)&rng_inst, sizeof(byte *), heap, devId);

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

    return ret;
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
            if (ctx->rngs[i].lock != 0) {
                /* better to leak than to crash. */
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

        for (i = 0; i < ctx->n_rngs; ++i) {
            wc_FreeRng(&ctx->rngs[i].rng);
        }

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
    if (wolfSSL_Atomic_Ptr_CompareExchange((void * volatile *)&default_rng_bank, (void **)&cur_default_rng_bank, bank))
        return 0;
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

    wolfSSL_RefInc_IfAtLeast(&cur_default_rng_bank->refcount, 2, &new_refcount, &ret);
    if (ret != 0)
        return ret;

    *bank = cur_default_rng_bank;

    return ret;
}

WOLFSSL_API int wc_rng_bank_default_checkin(struct wc_rng_bank **bank) {
    int ret;
    WC_ATOMIC_INT_ARG new_refcount;
    if ((bank == NULL) || (*bank == NULL))
        return BAD_FUNC_ARG;
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
    if ((bank != default_rng_bank) || (bank == NULL))
        return BAD_FUNC_ARG;
    if (wolfSSL_Atomic_Ptr_CompareExchange((void * volatile *)&default_rng_bank, (void **)&bank, NULL)) {
        int ret;
        WC_ATOMIC_INT_ARG new_refcount;
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
    int new_lock_value = WC_RNG_BANK_INST_LOCK_HELD;
    int ret = 0;
    time_t ts1, ts2;
    int n_rngs_tried = 0;
    WC_ATOMIC_INT_ARG new_refcount;

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
         * bank deallocation.
         */
        wolfSSL_RefInc_IfAtLeast(&bank->refcount, 1, &new_refcount, &ret);
        if (ret != 0) {
#ifdef WC_VERBOSE_RNG
            WOLFSSL_DEBUG_PRINTF(
                "wc_rng_bank_checkout() called with refcount %d.\n", new_refcount);
#endif
            return ret;
        }
    }

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
        int expected = 0;

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
                new_lock_value |= WC_RNG_BANK_INST_LOCK_AFFINITY_LOCKED;
            else if (ret == WC_NO_ERR_TRACE(INTERRUPTED_E))
                break;
            else {
                /* need to, and can, continue regardless of other error codes from
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

        if (wolfSSL_Atomic_Int_CompareExchange(
                &bank->rngs[preferred_inst_offset].lock,
                &expected,
                new_lock_value))
        {
            wc_drbg_reseed_ctr_t cur_reseed_ctr = 0;

            *rng_inst = &bank->rngs[preferred_inst_offset];

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
            if ((flags & WC_RNG_BANK_FLAG_CAN_FAIL_OVER_INST) &&
                (n_rngs_tried < bank->n_rngs) &&
                ((wc_RNG_GetStatus(WC_RNG_BANK_INST_TO_RNG(*rng_inst)) !=
                  WC_DRBG_OK) ||
                 ((! (flags & WC_RNG_BANK_FLAG_CAN_WAIT)) &&
                  (wc_RNG_DRBG_GetReseedCtr(
                      WC_RNG_BANK_INST_TO_RNG(*rng_inst),
                      &cur_reseed_ctr) == 0) &&
                  (cur_reseed_ctr >= WC_RESEED_INTERVAL))))
            {
                WOLFSSL_ATOMIC_STORE((*rng_inst)->lock, WC_RNG_BANK_INST_LOCK_FREE);
                *rng_inst = NULL;
            }
            else {
#ifdef WC_VERBOSE_RNG
                if ((! (flags & WC_RNG_BANK_FLAG_CAN_WAIT)) &&
                    (wc_RNG_DRBG_GetReseedCtr(
                        WC_RNG_BANK_INST_TO_RNG(*rng_inst),
                        &cur_reseed_ctr) == 0) &&
                    (cur_reseed_ctr >= WC_RESEED_INTERVAL))
                {
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

#ifdef WOLFSSL_USE_SAVE_VECTOR_REGISTERS
                if ((flags | bank->flags) & WC_RNG_BANK_FLAG_NO_VECTOR_OPS) {
                    ret = DISABLE_VECTOR_REGISTERS();
                    if (ret == 0)
                        WOLFSSL_ATOMIC_STORE((*rng_inst)->lock, new_lock_value |
                                             WC_RNG_BANK_INST_LOCK_VEC_OPS_INH);
                    else if (ret == WC_NO_ERR_TRACE(WC_ACCEL_INHIBIT_E))
                        ret = 0;
                    else {
                        WOLFSSL_ATOMIC_STORE((*rng_inst)->lock, WC_RNG_BANK_INST_LOCK_FREE);
                        *rng_inst = NULL;
                        break;
                    }
                }
#endif /* WOLFSSL_USE_SAVE_VECTOR_REGISTERS */

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

            ++preferred_inst_offset;
            if (preferred_inst_offset >= bank->n_rngs)
                preferred_inst_offset = 0;
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

        if (new_lock_value & WC_RNG_BANK_INST_LOCK_AFFINITY_LOCKED) {
            (void)bank->affinity_unlock_cb(bank->cb_arg);
            new_lock_value &= ~WC_RNG_BANK_INST_LOCK_AFFINITY_LOCKED;
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

    if (new_lock_value & WC_RNG_BANK_INST_LOCK_AFFINITY_LOCKED)
        (void)bank->affinity_unlock_cb(bank->cb_arg);

    /* Decrement the speculative refcount increment.  This also covers the
     * refcount increment in wc_rng_bank_default_checkout() if that's how it was
     * incremented.
     */
    {
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
    if (ret == WC_NO_ERR_TRACE(BUSY_E)) {
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
    if (wolfSSL_RefCur(bank->refcount) < 2)
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

WOLFSSL_API int wc_rng_bank_checkin(
    struct wc_rng_bank *bank,
    struct wc_rng_bank_inst **rng_inst)
{
    int lockval;
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
         * We can't normally warn for this misuse because random_bank_test()
         * exercises the functionality.
         */
#ifdef WC_RNG_BANK_LOCK_DEBUG
        WOLFSSL_DEBUG_PRINTF(
            "BUG: wc_rng_bank_checkin() with an instance that is not in this "
            "bank; caller's lock and bank refcount remain held.\n");
#endif
        return ret;
    }

    lockval = (int)WOLFSSL_ATOMIC_LOAD((*rng_inst)->lock);

    /* Opportunistically check for lock misuse/corruption.
     *
     * An instance must be checked in exactly once, by the caller that checked
     * it out. A duplicate or cross-thread check-in double-releases the affinity
     * lock (double migrate_enable() in linuxkm) and double-decrements the bank
     * refcount.  In normal builds we detect sequential misuse -- duplicate or
     * stale checkins ordered after the release -- with a cheap check that the
     * lock has WC_RNG_BANK_INST_LOCK_HELD.  In WC_RNG_BANK_LOCK_DEBUG builds,
     * the release is the more expensive compare-and-exchange, which catches
     * both sequential misuses and concurrent duplicates (short of ABA reuse of
     * the slot within the race window).
     */
    if (! (lockval & WC_RNG_BANK_INST_LOCK_HELD)) {
#ifdef WC_RNG_BANK_LOCK_DEBUG
        WOLFSSL_DEBUG_PRINTF(
            "BUG: wc_rng_bank_checkin() on an instance that is not checked "
            "out (lock %d).\n", lockval);
#endif
        return BAD_STATE_E;
    }

#ifdef WC_RNG_BANK_LOCK_DEBUG
    {
        int expected = lockval;
        if (! wolfSSL_Atomic_Int_CompareExchange(
                  &(*rng_inst)->lock, &expected,
                  WC_RNG_BANK_INST_LOCK_FREE))
        {
            WOLFSSL_DEBUG_PRINTF(
                "BUG: wc_rng_bank_checkin() lock changed under it "
                "(%d -> %d).\n", lockval, expected);
            return BAD_STATE_E;
        }
    }
#else /* !WC_RNG_BANK_LOCK_DEBUG */
    WOLFSSL_ATOMIC_STORE((*rng_inst)->lock, WC_RNG_BANK_INST_LOCK_FREE);
#endif /* !WC_RNG_BANK_LOCK_DEBUG */

    *rng_inst = NULL;

    if (lockval & WC_RNG_BANK_INST_LOCK_VEC_OPS_INH)
        REENABLE_VECTOR_REGISTERS();

    if (lockval & WC_RNG_BANK_INST_LOCK_AFFINITY_LOCKED)
        ret = bank->affinity_unlock_cb(bank->cb_arg);
    else
        ret = 0;

    {
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

    wc_FreeRng(&rng_inst->rng);

    for (;;) {
        ret = wc_InitRngNonce_ex(WC_RNG_BANK_INST_TO_RNG(rng_inst),
                                 (byte *)&rng_inst, sizeof(byte *),
                                 bank->heap, devId);

        /* Relax between iterations exactly as wc_rng_bank_init() does.  The
         * caller may hold the affinity lock taken by wc_rng_bank_checkout(),
         * so this must not sleep in atomic context; WC_RELAX_LONG_LOOP()
         * degrades to a cpu_relax() there.
         */
        WC_RELAX_LONG_LOOP();

        if (ret == 0)
            break;

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
            WOLFSSL_DEBUG_PRINTF(
                "WARNING: wc_rng_bank_inst_reinit() non-retryable err %d.\n",
                ret);
#endif
            goto out;
        }

        if ((! (flags & WC_RNG_BANK_FLAG_CAN_WAIT)) || (timeout_secs == 0)) {
#ifdef WC_VERBOSE_RNG
            WOLFSSL_DEBUG_PRINTF(
                "WARNING: wc_rng_bank_inst_reinit() returning err %d.\n", ret);
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
                WOLFSSL_DEBUG_PRINTF(
                    "WARNING: wc_rng_bank_inst_reinit() timed out, err %d.\n",
                    ret);
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

    return ret;
}

WOLFSSL_API int wc_rng_bank_seed(struct wc_rng_bank *bank,
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
                 WC_RNG_BANK_FLAG_PREFER_AFFINITY_INST))
        return BAD_FUNC_ARG;

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

    /* This iteration counts down, whereas the iteration in get_drbg() counts
     * up, to assure they can't possibly phase-lock to each other.
     */
    for (n = bank->n_rngs - 1; n >= 0; --n) {
        struct wc_rng_bank_inst *drbg;
        ret = wc_rng_bank_checkout(bank, &drbg, n, timeout_secs,
                                   flags & ~(word32)
                                       WC_RNG_BANK_FLAG_SEED_UNCREDITED);
        if (ret != 0) {
#ifdef WC_VERBOSE_RNG
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
                 WC_RNG_BANK_FLAG_SEED_UNCREDITED))
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

    if ((timeout_secs > 0) && (flags & WC_RNG_BANK_FLAG_CAN_WAIT))
        ts1 = XTIME(0);

    for (n = bank->n_rngs - 1; n >= 0; --n) {
        struct wc_rng_bank_inst *drbg;

        ret = wc_rng_bank_checkout(bank, &drbg, n, timeout_secs, flags);
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
                if (ret == 0)
                    break;
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
                            "ERROR: timeout after attempted reseed by "
                            "wc_RNG_GenerateBlock() for DRBG #%d, err %d.", n, ret);
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

#endif /* WC_RNG_BANK_SUPPORT */
