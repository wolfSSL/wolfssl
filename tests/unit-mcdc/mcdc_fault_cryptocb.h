/* mcdc_fault_cryptocb.h
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

/*
 * mcdc_fault_cryptocb.h -- make one crypto operation fail, on demand.
 *
 * PURPOSE
 * -------
 * The protocol engine is written defensively around every crypto call:
 *
 *     ret = wc_ecc_verify_hash(sig, sigSz, hash, hashSz, &verify, key);
 *     if (ret != 0 || verify != 1)
 *         return VERIFY_SIGN_ERROR;
 *
 * A correct build cannot make the first operand true. The maths works, so the
 * error arm is dead code to every ordinary test, and the operand stays
 * unpaired no matter how many handshakes are run. The other injectors in this
 * directory reach that arm by redirecting a symbol with a #define, which
 * requires a white-box that #includes the .c under test.
 *
 * WOLF_CRYPTO_CB reaches the same arm from the outside, and it is the
 * supported way to do it: a registered device sees every dispatched operation
 * before the software implementation does, and whatever it returns is what the
 * caller gets. Returning CRYPTOCB_UNAVAILABLE means "not mine", and the
 * software path runs as usual. So a device that answers CRYPTOCB_UNAVAILABLE
 * to everything except one selected operation, which it fails, turns any
 * ordinary black-box test into a fault-injection vector -- no #define, no
 * white-box, and the library is exercised exactly as a real offload device
 * would exercise it.
 *
 * WHAT IT DOES NOT DO
 * -------------------
 * Only operations that are actually dispatched through the callback can be
 * failed, and dispatch happens only when the key or context carries a devId
 * other than INVALID_DEVID. Handing the devId to the object under test is the
 * caller's job -- wolfSSL_CTX_SetDevId() for a whole CTX, or the per-key
 * wc_*_init_ex(). An operation on a default-devId key runs in software and
 * never reaches this device, which is the correct behaviour and is also the
 * usual reason a vector that "should" have failed did not.
 *
 * USE
 * ---
 *     mcdc_cb_reset();
 *     mcdc_cb_fail_pk(WC_PK_TYPE_ECDSA_VERIFY, SIG_VERIFY_E);
 *     wolfSSL_CTX_SetDevId(ctx, MCDC_CB_DEVID);
 *     ... run the handshake, which now fails at the signature check ...
 *     ExpectIntEQ(mcdc_cb_hits(), 1);
 *     mcdc_cb_reset();
 *
 * mcdc_cb_after(n) lets the first n matching operations through to software
 * before failing the next one, for the handshakes that verify more than one
 * signature and where only the second one is the interesting guard.
 */

#ifndef MCDC_FAULT_CRYPTOCB_H
#define MCDC_FAULT_CRYPTOCB_H

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLF_CRYPTO_CB

#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* Any value that is not INVALID_DEVID. Kept away from the small integers the
 * async and PKCS#11 tests use so a stray registration cannot collide. */
#define MCDC_CB_DEVID 1729

typedef struct McdcCbState {
    int algoType;   /* WC_ALGO_TYPE_* to fail, or -1 for "any"           */
    int pkType;     /* WC_PK_TYPE_*  to fail, or -1 for "any"            */
    int failCode;   /* what the device returns for a matching operation  */
    int after;      /* let this many matches through before failing      */
    int setRes;     /* for a verify op answered 0: what to write to *res  */
    int matched;    /* matching operations seen, whether failed or not   */
    int failed;     /* matching operations actually failed               */
    int seen;       /* every operation the device was offered            */
    int armed;      /* zero disarms without unregistering the device     */
} McdcCbState;

static McdcCbState mcdc_cb_state;

static WC_INLINE void mcdc_cb_reset(void)
{
    XMEMSET(&mcdc_cb_state, 0, sizeof(mcdc_cb_state));
    mcdc_cb_state.algoType = -1;
    mcdc_cb_state.pkType   = -1;
    mcdc_cb_state.failCode = WC_HW_E;
    mcdc_cb_state.setRes   = -1;
}

/* Answer a public-key operation: WC_PK_TYPE_ECDSA_VERIFY, _RSA,
 * _ED25519_VERIFY, _ED448_VERIFY, _ECDH and so on. A negative code is a device
 * that refuses; a code of 0 is a device that claims the operation succeeded
 * without doing it, which is how the "succeeded but the answer is no" arm of a
 * verify guard is reached. */
static WC_INLINE void mcdc_cb_answer_pk(int pkType, int code)
{
    mcdc_cb_reset();
    mcdc_cb_state.algoType = WC_ALGO_TYPE_PK;
    mcdc_cb_state.pkType   = pkType;
    mcdc_cb_state.failCode = code;
    mcdc_cb_state.setRes   = -1;   /* leave *res as the caller left it */
    mcdc_cb_state.armed    = 1;
}

static WC_INLINE void mcdc_cb_fail_pk(int pkType, int failCode)
{
    mcdc_cb_answer_pk(pkType, failCode);
}

/* Verify entry points differ in whether they zero *res before dispatching:
 * wc_ed448_verify_msg does, wc_ecc_verify_hash and wc_ed25519_verify_msg do
 * not. Setting the verdict from inside the device removes the difference, so a
 * vector means the same thing whichever algorithm it names. Pass -1 to leave
 * *res untouched. */
static WC_INLINE void mcdc_cb_verdict(int res)
{
    mcdc_cb_state.setRes = res;
}

/* Fail a whole class: WC_ALGO_TYPE_HASH, _CIPHER, _RNG, _HMAC, _KDF, _SEED. */
static WC_INLINE void mcdc_cb_fail_algo(int algoType, int failCode)
{
    mcdc_cb_reset();
    mcdc_cb_state.algoType = algoType;
    mcdc_cb_state.failCode = failCode;
    mcdc_cb_state.armed    = 1;
}

/* Let the first n matching operations run in software, then fail the next. */
static WC_INLINE void mcdc_cb_after(int n)
{
    mcdc_cb_state.after = n;
}

static WC_INLINE void mcdc_cb_disarm(void)
{
    mcdc_cb_state.armed = 0;
}

static WC_INLINE int mcdc_cb_hits(void)    { return mcdc_cb_state.failed;  }
static WC_INLINE int mcdc_cb_matched(void) { return mcdc_cb_state.matched; }
static WC_INLINE int mcdc_cb_seen(void)    { return mcdc_cb_state.seen;    }

static WC_INLINE int mcdc_cb_callback(int devId, wc_CryptoInfo* info, void* ctx)
{
    McdcCbState* st = (McdcCbState*)ctx;

    (void)devId;

    if (st == NULL || info == NULL)
        return CRYPTOCB_UNAVAILABLE;

    st->seen++;

    if (!st->armed)
        return CRYPTOCB_UNAVAILABLE;

    if (st->algoType >= 0 && info->algo_type != st->algoType)
        return CRYPTOCB_UNAVAILABLE;

    /* info->pk.type is only meaningful for WC_ALGO_TYPE_PK; reading it for a
     * hash or cipher would be reading the wrong union arm. */
    if (st->pkType >= 0) {
        if (info->algo_type != WC_ALGO_TYPE_PK)
            return CRYPTOCB_UNAVAILABLE;
        if (info->pk.type != st->pkType)
            return CRYPTOCB_UNAVAILABLE;
    }

    st->matched++;

    if (st->matched <= st->after)
        return CRYPTOCB_UNAVAILABLE;   /* software runs this one */

    /* A device that answers a verify has to report the verdict somewhere; the
     * caller reads *res, not the return value. Only touched when the vector
     * asked for it, and only for the three verify types that carry a res. */
    if (st->setRes >= 0 && info->algo_type == WC_ALGO_TYPE_PK) {
        int* res = NULL;

        switch (info->pk.type) {
        #ifdef HAVE_ECC
            case WC_PK_TYPE_ECDSA_VERIFY:  res = info->pk.eccverify.res;   break;
        #endif
        #ifdef HAVE_ED25519
            case WC_PK_TYPE_ED25519_VERIFY:
                res = info->pk.ed25519verify.res;
                break;
        #endif
        #ifdef HAVE_ED448
            case WC_PK_TYPE_ED448_VERIFY:  res = info->pk.ed448verify.res; break;
        #endif
            default: break;
        }
        if (res != NULL)
            *res = st->setRes;
    }

    st->failed++;
    return st->failCode;
}

/* Registration is global and idempotent; the state is reset separately so a
 * vector can re-arm without re-registering. */
static WC_INLINE int mcdc_cb_install(void)
{
    mcdc_cb_reset();
    return wc_CryptoCb_RegisterDevice(MCDC_CB_DEVID, mcdc_cb_callback,
                                      &mcdc_cb_state);
}

static WC_INLINE void mcdc_cb_uninstall(void)
{
    wc_CryptoCb_UnRegisterDevice(MCDC_CB_DEVID);
    mcdc_cb_reset();
}

#endif /* WOLF_CRYPTO_CB */
#endif /* MCDC_FAULT_CRYPTOCB_H */
