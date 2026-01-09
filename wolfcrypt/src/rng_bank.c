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
        return BAD_LENGTH_E;
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
#ifdef WC_VERBOSE_RNG
            int nretries = 0;
#endif
            time_t ts1 = XTIME(0);
            for (;;) {
                time_t ts2;

                if (flags & WC_RNG_BANK_FLAG_NO_VECTOR_OPS)
                    need_reenable_vec = (DISABLE_VECTOR_REGISTERS() == 0);
                ret = wc_InitRngNonce_ex(
                    WC_RNG_BANK_INST_TO_RNG(ctx->rngs + i),
                    (byte *)&ctx->rngs[i], sizeof(byte *), heap, devId);

                if (need_reenable_vec)
                    REENABLE_VECTOR_REGISTERS();
                /* if we're allowed to sleep, relax the loop between each inner
                 * iteration even on success, assuring relaxation of the outer
                 * iterations.
                 */
                WC_RELAX_LONG_LOOP();
                if (ret == 0)
                    break;
                /* Allow interrupt only if we're stuck spinning retries -- i.e.,
                 * don't allow an untimely user signal to derail an
                 * initialization that is proceeding expeditiously.
                 */
                ret = WC_CHECK_FOR_INTR_SIGNALS();
                if (ret == WC_NO_ERR_TRACE(INTERRUPTED_E))
                    break;
                ts2 = XTIME(0);
                if (ts2 - ts1 > timeout_secs) {
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

    if (ctx == NULL)
        return BAD_FUNC_ARG;

    if (ctx->flags == WC_RNG_BANK_FLAG_NONE)
        return 0;

    if (! (ctx->flags & WC_RNG_BANK_FLAG_INITED))
        return BAD_FUNC_ARG;

    if (wolfSSL_RefCur(ctx->refcount) > 1)
        return BUSY_E;

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
                return BUSY_E;
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

    if ((bank == NULL) ||
        (! (bank->flags & WC_RNG_BANK_FLAG_INITED)) ||
        (rng_inst == NULL))
    {
        return BAD_FUNC_ARG;
    }

    if ((flags & WC_RNG_BANK_FLAG_PREFER_AFFINITY_INST) &&
        (bank->affinity_get_id_cb == NULL))
    {
#ifdef WC_VERBOSE_RNG
        WOLFSSL_DEBUG_PRINTF(
            "BUG: wc_rng_bank_checkout() called with _PREFER_AFFINITY_INST but "
            "no _get_id_cb.\n");
#endif
        return BAD_FUNC_ARG;
    }

    if (flags & WC_RNG_BANK_FLAG_AFFINITY_LOCK) {
        if ((bank->affinity_lock_cb == NULL) ||
            (bank->affinity_unlock_cb == NULL))
        {
#ifdef WC_VERBOSE_RNG
            WOLFSSL_DEBUG_PRINTF(
                "BUG: wc_rng_bank_checkout() called with _AFFINITY_LOCK but "
                "missing _lock_cb.\n");
#endif
            return BAD_FUNC_ARG;
        }
        ret = bank->affinity_lock_cb(bank->cb_arg);
        if (ret == 0)
            new_lock_value |= WC_RNG_BANK_INST_LOCK_AFFINITY_LOCKED;
        else if (ret != WC_NO_ERR_TRACE(ALREADY_E))
            return ret;
    }

    if (flags & WC_RNG_BANK_FLAG_PREFER_AFFINITY_INST) {
        preferred_inst_offset = -1;
        ret = bank->affinity_get_id_cb(bank->cb_arg, &preferred_inst_offset);
        if (ret != 0) {
#ifdef WC_VERBOSE_RNG
            WOLFSSL_DEBUG_PRINTF(
                "BUG: bank->affinity_get_id_cb() returned err %d.\n", ret);
#endif
        }
        else if (((preferred_inst_offset < 0) ||
                  (preferred_inst_offset >= bank->n_rngs)))
        {
            ret = BAD_INDEX_E;
        }
    }
    else {
        if ((preferred_inst_offset < 0) ||
            (preferred_inst_offset >= bank->n_rngs))
        {
            ret = BAD_INDEX_E;
        }
    }

    if ((timeout_secs > 0) && (flags & WC_RNG_BANK_FLAG_CAN_WAIT))
        ts1 = XTIME(0);
    else
        ts1 = 0; /* mollify -Wmaybe-uninitialized... */

    for (; ret == 0;) {
        int expected = 0;

        if (wolfSSL_Atomic_Int_CompareExchange(
                &bank->rngs[preferred_inst_offset].lock,
                &expected,
                new_lock_value))
        {
            *rng_inst = &bank->rngs[preferred_inst_offset];

            if ((! (flags & WC_RNG_BANK_FLAG_CAN_WAIT)) &&
                (((struct DRBG_internal *)(*rng_inst)->rng.drbg)->reseedCtr >=
                 WC_RESEED_INTERVAL) &&
                (flags & WC_RNG_BANK_FLAG_CAN_FAIL_OVER_INST) &&
                (n_rngs_tried < bank->n_rngs))
            {
                WOLFSSL_ATOMIC_STORE((*rng_inst)->lock, WC_RNG_BANK_INST_LOCK_FREE);
            }
            else {
#ifdef WC_VERBOSE_RNG
                if ((! (flags & WC_RNG_BANK_FLAG_CAN_WAIT)) &&
                    (((struct DRBG_internal *)(*rng_inst)->rng.drbg)->reseedCtr >=
                     WC_RESEED_INTERVAL))
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

                if ((flags | bank->flags) & WC_RNG_BANK_FLAG_NO_VECTOR_OPS) {
                    if (DISABLE_VECTOR_REGISTERS() == 0)
                        WOLFSSL_ATOMIC_STORE((*rng_inst)->lock, new_lock_value |
                                             WC_RNG_BANK_INST_LOCK_VEC_OPS_INH);
                }

                return 0; /* Short-circuit return, holding onto RNG and affinity
                           * locks and vector register inhibition.
                           */
            }
        }

        if (flags & WC_RNG_BANK_FLAG_CAN_FAIL_OVER_INST) {
            if ((! (flags & WC_RNG_BANK_FLAG_CAN_WAIT)) &&
                (n_rngs_tried >= bank->n_rngs))
            {
                ret = BUSY_E;
                break; /* jump to cleanup. */
            }
            ++preferred_inst_offset;
            if (preferred_inst_offset >= bank->n_rngs)
                preferred_inst_offset = 0;
            ++n_rngs_tried;
        }
        else {
            if (! (flags & WC_RNG_BANK_FLAG_CAN_WAIT)) {
                ret = BUSY_E;
                break; /* jump to cleanup. */
            }
        }

        if (flags & WC_RNG_BANK_FLAG_AFFINITY_LOCK)
            (void)bank->affinity_unlock_cb(bank->cb_arg);

        ret = WC_CHECK_FOR_INTR_SIGNALS();
        if (ret == WC_NO_ERR_TRACE(INTERRUPTED_E))
            return ret; /* immediate return -- no locks held */

        if (timeout_secs > 0) {
            ts2 = XTIME(0);
            if (ts2 - ts1 >= timeout_secs)
                return WC_TIMEOUT_E; /* immediate return -- no locks held */
        }
        WC_RELAX_LONG_LOOP();

        if (flags & WC_RNG_BANK_FLAG_AFFINITY_LOCK) {
            ret = bank->affinity_lock_cb(bank->cb_arg);
            if (ret)
                return ret; /* immediate return -- no locks held */
        }

        /* Note that we may have been migrated at this point, but it doesn't
         * matter -- we only reach this point if we have to retry/iterate.
         */
    }

    if (flags & WC_RNG_BANK_FLAG_AFFINITY_LOCK)
        (void)bank->affinity_unlock_cb(bank->cb_arg);

    return ret;
}

#ifdef WC_DRBG_BANKREF
WOLFSSL_LOCAL int wc_local_rng_bank_checkout_for_bankref(
    struct wc_rng_bank *bank,
    struct wc_rng_bank_inst **rng_inst)
{
    return wc_rng_bank_checkout(
        bank, rng_inst, 0, 0,
        WC_RNG_BANK_FLAG_CAN_FAIL_OVER_INST |
        WC_RNG_BANK_FLAG_CAN_WAIT |
        ((bank->affinity_get_id_cb != NULL) ? WC_RNG_BANK_FLAG_PREFER_AFFINITY_INST : 0) |
        ((bank->affinity_lock_cb != NULL) ? WC_RNG_BANK_FLAG_AFFINITY_LOCK : 0));
}
#endif /* WC_DRBG_BANKREF */

WOLFSSL_API int wc_rng_bank_checkin(
    struct wc_rng_bank *bank,
    struct wc_rng_bank_inst **rng_inst)
{
    int lockval;

    if ((bank == NULL) || (rng_inst == NULL) || (*rng_inst == NULL))
        return BAD_FUNC_ARG;

    lockval = (int)WOLFSSL_ATOMIC_LOAD((*rng_inst)->lock);

    WOLFSSL_ATOMIC_STORE((*rng_inst)->lock, WC_RNG_BANK_INST_LOCK_FREE);

    *rng_inst = NULL;

    if (lockval & WC_RNG_BANK_INST_LOCK_VEC_OPS_INH)
        REENABLE_VECTOR_REGISTERS();

    if (lockval & WC_RNG_BANK_INST_LOCK_AFFINITY_LOCKED)
        return bank->affinity_unlock_cb(bank->cb_arg);
    else
        return 0;
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

    if ((rng_inst == NULL) ||
        (rng_inst->rng.drbg == NULL))
    {
        return BAD_FUNC_ARG;
    }

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
        if (ret == 0)
            break;
        if (! (flags & WC_RNG_BANK_FLAG_CAN_WAIT)) {
#ifdef WC_VERBOSE_RNG
            WOLFSSL_DEBUG_PRINTF(
                "WARNING: wc_rng_bank_inst_reinit() returning err %d.\n", ret);
#endif
            break;
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

    return ret;
}

WOLFSSL_API int wc_rng_bank_seed(struct wc_rng_bank *bank,
                                 const byte* seed, word32 seedSz,
                                 int timeout_secs,
                                 word32 flags)
{
    int ret = 0;
    int n;

    if ((bank == NULL) ||
        (! (bank->flags & WC_RNG_BANK_FLAG_INITED)))
    {
        return BAD_FUNC_ARG;
    }

    if (seedSz == 0)
        return 0;

    /* this iteration counts down, whereas the iteration in get_drbg() counts
     * up, to assure they can't possibly phase-lock to each other.
     */
    for (n = bank->n_rngs - 1; n >= 0; --n) {
        struct wc_rng_bank_inst *drbg;
        ret = wc_rng_bank_checkout(bank, &drbg, n, timeout_secs, flags);
        if (ret != 0) {
#ifdef WC_VERBOSE_RNG
            WOLFSSL_DEBUG_PRINTF(
                "WARNING: wc_rng_bank_seed(): wc_rng_bank_checkout() for "
                "inst#%d returned err %d.\n", n, ret);
#endif
            break;
        }
        else if (drbg->rng.drbg == NULL) {
#ifdef WC_VERBOSE_RNG
            WOLFSSL_DEBUG_PRINTF(
                "WARNING: wc_rng_bank_seed(): inst#%d has null .drbg.\n", n);
#endif
            ret = BAD_STATE_E;
        }
        else if ((ret = wc_RNG_DRBG_Reseed(WC_RNG_BANK_INST_TO_RNG(drbg), seed,
                                         seedSz)) != 0)
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

    return ret;
}

WOLFSSL_API int wc_rng_bank_reseed(struct wc_rng_bank *bank,
                                   int timeout_secs,
                                   word32 flags)
{
    int n;
    int ret;
    time_t ts1 = 0;

    if (! bank)
        return BAD_FUNC_ARG;

    if (flags & (WC_RNG_BANK_FLAG_CAN_FAIL_OVER_INST |
                 WC_RNG_BANK_FLAG_PREFER_AFFINITY_INST))
        return BAD_FUNC_ARG;

    if ((timeout_secs > 0) && (flags & WC_RNG_BANK_FLAG_CAN_WAIT))
        ts1 = XTIME(0);

    for (n = bank->n_rngs - 1; n >= 0; --n) {
        struct wc_rng_bank_inst *drbg;

        ret = wc_rng_bank_checkout(bank, &drbg, n, timeout_secs, flags);
        if (ret != 0)
            return ret;

        ((struct DRBG_internal *)drbg->rng.drbg)->reseedCtr =
            WC_RESEED_INTERVAL;

        if (flags & WC_RNG_BANK_FLAG_CAN_WAIT) {
            byte scratch[4];
            for (;;) {
                time_t ts2;
                ret = wc_RNG_GenerateBlock(WC_RNG_BANK_INST_TO_RNG(drbg), scratch,
                                           (word32)sizeof(scratch));
                if (ret == 0)
                    break;
                if ((timeout_secs <= 0) ||
                    (! (flags & WC_RNG_BANK_FLAG_CAN_WAIT)))
                {
                    break;
                }
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
#ifdef WC_VERBOSE_RNG
            if ((ret != 0) && (ret != WC_NO_ERR_TRACE(WC_TIMEOUT_E)))
                WOLFSSL_DEBUG_PRINTF(
                    "ERROR: wc_crng_reseed() wc_RNG_GenerateBlock() "
                    "for DRBG #%d returned %d.", n, ret);
#endif
            wc_rng_bank_checkin(bank, &drbg);
            if (ret == WC_NO_ERR_TRACE(WC_TIMEOUT_E))
                return ret;
            ret = WC_CHECK_FOR_INTR_SIGNALS();
            if (ret == WC_NO_ERR_TRACE(INTERRUPTED_E))
                return ret;
            WC_RELAX_LONG_LOOP();
        }
        else {
            wc_rng_bank_checkin(bank, &drbg);
        }
    }

    return 0;
}

#ifdef WC_DRBG_BANKREF

WOLFSSL_API int wc_InitRng_BankRef(struct wc_rng_bank *bank, WC_RNG *rng)
{
    int ret;

    if ((bank == NULL) ||
        (! (bank->flags & WC_RNG_BANK_FLAG_INITED)) ||
        (rng == NULL))
    {
        return BAD_FUNC_ARG;
    }

    XMEMSET(rng, 0, sizeof(*rng));

    wolfSSL_RefInc(&bank->refcount, &ret);

    if (ret != 0)
        return ret;

    rng->heap = bank->heap;
    rng->status = WC_DRBG_BANKREF;
    rng->bankref = bank;

    return 0;
}

WOLFSSL_API int wc_BankRef_Release(WC_RNG *rng)
{
    int isZero = 0;
    int ret = 0;
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

#ifndef WC_RNG_BANK_STATIC
WOLFSSL_API int wc_rng_new_bankref(struct wc_rng_bank *bank, WC_RNG **rng) {
    int ret;

    if ((bank == NULL) ||
        (! (bank->flags & WC_RNG_BANK_FLAG_INITED)) ||
        (rng == NULL))
    {
        return BAD_FUNC_ARG;
    }

    *rng = (WC_RNG*)XMALLOC(sizeof(WC_RNG), bank->heap, DYNAMIC_TYPE_RNG);
    if (*rng == NULL) {
        return MEMORY_E;
    }

    ret = wc_InitRng_BankRef(bank, *rng);
    if (ret != 0) {
        XFREE(*rng, bank->heap, DYNAMIC_TYPE_RNG);
        *rng = NULL;
    }

    return ret;
}
#endif /* !WC_RNG_BANK_STATIC */

#endif /* WC_DRBG_BANKREF */

#endif /* WC_RNG_BANK_SUPPORT */
