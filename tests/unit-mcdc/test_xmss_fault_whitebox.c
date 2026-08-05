/* test_xmss_fault_whitebox.c
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
 * MC/DC white-box supplement for wolfcrypt/src/wc_xmss.c's public-API guard
 * chains: NULL/argument checks and the `(ret == 0) && <key->state check>`
 * decisions that gate MakeKey/Reload/Sign/Verify/Get*Len/Import/Export.
 *
 * None of these decisions need a real XMSS keypair. Every guard chain here
 * is closed with the SMALLEST built-in parameter set (XMSS-SHA2_10_256,
 * height 10 - available under every campaign variant since
 * WOLFSSL_XMSS_MIN_HEIGHT defaults to 10) purely for its XmssParams fields
 * (sig_len/pk_len/sk_len); wc_XmssKey_SetParamStr() never generates keys, so
 * it costs nothing. key->state is then poked directly (this file #includes
 * wc_xmss.c, so XmssKey's fields are in scope) to walk every enum value a
 * guard compares against, without a single real MakeKey/Sign/Verify.
 *
 * Two "false" (guard-passes) rows genuinely cannot be reached without
 * calling the real public function and letting it proceed - MakeKey's
 * write_private_key check and Reload's write/read check are only false
 * when a real callback is installed, and the code that follows immediately
 * allocates key->sk before doing anything else. For those two rows, this
 * file arms mcdc_fault_alloc.h's fail-index at 1 right before the call: the
 * write/read guard is still evaluated and recorded (false, callbacks are
 * genuinely set), but the very next heap allocation - key->sk in
 * wc_xmsskey_alloc_sk(), the first thing the guard-passing path does -
 * fails immediately (MEMORY_E), so no real keygen ever runs.
 *
 * Sign's and Verify's write/read-callback and state-chain "guard passes"
 * rows are closed the same way but without needing the allocator at all:
 * Sign's read_private_key callback is invoked (by the target itself)
 * BEFORE any signing math, so a callback stub that unconditionally returns
 * WC_XMSS_RC_READ_FAIL forces an immediate, deterministic IO_FAILED_E.
 * Verify's real tree-hash walk only starts after a sigLen == params->sig_len
 * check; passing a deliberately mismatched sigLen (line 1972, already
 * covered elsewhere) reaches the state-chain decision under test and then
 * bails via BUFFER_E before any hashing.
 *
 * This #includes wc_xmss.c directly (like the sibling wc_xmss_impl.c
 * white-box) so key->state and the other private fields are reachable.
 *
 * Invocation: no arguments; runs the full sweep (the campaign's
 * run_whitebox harness invokes the binary with none).
 */

#include <wolfcrypt/src/wc_xmss.c>

#include "mcdc_fault_alloc.h"

#include <wolfssl/wolfcrypt/random.h>
#include <stdio.h>
#include <string.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if !defined(WOLFSSL_HAVE_XMSS)

int main(void)
{
    printf("wc_xmss.c fault white-box: WOLFSSL_HAVE_XMSS absent, "
        "nothing to do\n");
    return 0;
}

#else

/* Smallest built-in parameter set (single tree, height 10): only ever used
 * for its XmssParams fields, never for a real keygen/sign/verify. */
#define WB_PARM_STR "XMSS-SHA2_10_256"

/* Zeroize, Init, and SetParamStr a fresh key (state ends at PARMSET). */
static int wb_make_parmset_key(XmssKey* key)
{
    int ret;

    XMEMSET(key, 0, sizeof(*key));
    ret = wc_XmssKey_Init(key, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_XmssKey_SetParamStr(key, WB_PARM_STR);
    }
    if (ret != 0) {
        WB_NOTE("wb_make_parmset_key: Init/SetParamStr unavailable");
        wb_fail = 1;
    }
    return ret;
}

#ifndef WOLFSSL_XMSS_VERIFY_ONLY
/* Never actually invoked in the rows that use it (the alloc-fault bailout
 * runs first); present only so the write-callback guard sees non-NULL. */
static enum wc_XmssRc wb_write_cb_dummy(const byte* priv, word32 privSz,
    void* context)
{
    (void)priv; (void)privSz; (void)context;
    return WC_XMSS_RC_SAVED_TO_NV_MEMORY;
}

/* Deterministic, allocation-free bailout: forces wc_xmsskey_signupdate() /
 * wc_XmssKey_Reload() to fail at the very first thing they do with the
 * secret key, before any real WOTS+/tree-hash math runs. */
static enum wc_XmssRc wb_read_cb_fail(byte* priv, word32 privSz,
    void* context)
{
    (void)priv; (void)privSz; (void)context;
    return WC_XMSS_RC_READ_FAIL;
}

/********************************************
 * 1205: wc_XmssKey_MakeKey()'s
 *   "if ((ret == 0) && (key->state != WC_XMSS_STATE_PARMSET))"
 * 1229: same function's
 *   "if ((ret == 0) && (key->write_private_key == NULL))"
 ********************************************/
static void wb_makekey_state_chain(void)
{
    XmssKey key;
    WC_RNG  rng; /* never dereferenced: every row bails before RNG use */
    int     ret;

    XMEMSET(&rng, 0, sizeof(rng));

    /* 1205 cond0 false: the argument guard above already set ret, so the
     * state check short-circuits without dereferencing key. */
    ret = wc_XmssKey_MakeKey(NULL, &rng);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("MakeKey key==NULL did not report BAD_FUNC_ARG");
        wb_fail = 1;
    }

    /* 1205 true: wrong state. */
    if (wb_make_parmset_key(&key) == 0) {
        key.state = WC_XMSS_STATE_INITED;
        ret = wc_XmssKey_MakeKey(&key, &rng);
        if (ret != WC_NO_ERR_TRACE(BAD_STATE_E)) {
            WB_NOTE("MakeKey bad-state row did not report BAD_STATE_E");
            wb_fail = 1;
        }
        wc_XmssKey_Free(&key);
    }

    /* 1205 false (PARMSET) + 1229 true: no write callback set. */
    if (wb_make_parmset_key(&key) == 0) {
        ret = wc_XmssKey_MakeKey(&key, &rng);
        if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
            WB_NOTE("MakeKey missing-write-cb row did not report "
                "BAD_FUNC_ARG");
            wb_fail = 1;
        }
        wc_XmssKey_Free(&key);
    }

    /* 1205 false + 1229 false: write callback set. key->sk's allocation is
     * the guard-passing path's first action; fault it so real keygen never
     * starts. */
    if (wb_make_parmset_key(&key) == 0) {
        ret = wc_XmssKey_SetWriteCb(&key, wb_write_cb_dummy);
        if (ret != 0) {
            WB_NOTE("SetWriteCb failed; MakeKey alloc-guard row skipped");
            wb_fail = 1;
        }
        else {
            mcdc_fa_arm(1);
            ret = wc_XmssKey_MakeKey(&key, &rng);
            mcdc_fa_disarm();
            if (ret != WC_NO_ERR_TRACE(MEMORY_E)) {
                WB_NOTE("MakeKey write-cb-set row did not fault at the sk "
                    "allocation as expected");
                wb_fail = 1;
            }
        }
        wc_XmssKey_Free(&key);
    }
}

/********************************************
 * 1343: wc_XmssKey_Reload()'s
 *   "if ((ret == 0) && (key->state != WC_XMSS_STATE_PARMSET))"
 * 1358-1359: same function's
 *   "if ((ret == 0) && ((key->write_private_key == NULL) ||
 *                       (key->read_private_key == NULL)))"
 ********************************************/
static void wb_reload_state_chain(void)
{
    XmssKey key;
    int     ret;

    /* 1343 cond0 false: the argument guard above already set ret. */
    ret = wc_XmssKey_Reload(NULL);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("Reload key==NULL did not report BAD_FUNC_ARG");
        wb_fail = 1;
    }

    /* 1343 true: wrong state. */
    if (wb_make_parmset_key(&key) == 0) {
        key.state = WC_XMSS_STATE_INITED;
        ret = wc_XmssKey_Reload(&key);
        if (ret != WC_NO_ERR_TRACE(BAD_STATE_E)) {
            WB_NOTE("Reload bad-state row did not report BAD_STATE_E");
            wb_fail = 1;
        }
        wc_XmssKey_Free(&key);
    }

    /* 1343 false (PARMSET) + 1358 true: read cb set, write cb NULL. */
    if (wb_make_parmset_key(&key) == 0) {
        ret = wc_XmssKey_SetReadCb(&key, wb_read_cb_fail);
        if (ret != 0) { WB_NOTE("SetReadCb failed"); wb_fail = 1; }
        ret = wc_XmssKey_Reload(&key);
        if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
            WB_NOTE("Reload write-cb-NULL row did not report BAD_FUNC_ARG");
            wb_fail = 1;
        }
        wc_XmssKey_Free(&key);
    }

    /* 1343 false + 1358 true: write cb set, read cb NULL (the OR's other
     * operand). */
    if (wb_make_parmset_key(&key) == 0) {
        ret = wc_XmssKey_SetWriteCb(&key, wb_write_cb_dummy);
        if (ret != 0) { WB_NOTE("SetWriteCb failed"); wb_fail = 1; }
        ret = wc_XmssKey_Reload(&key);
        if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
            WB_NOTE("Reload read-cb-NULL row did not report BAD_FUNC_ARG");
            wb_fail = 1;
        }
        wc_XmssKey_Free(&key);
    }

    /* 1343 false + 1358 false: both callbacks set. Same alloc-fault
     * bailout as MakeKey - key->sk's allocation runs before either callback
     * is invoked. */
    if (wb_make_parmset_key(&key) == 0) {
        ret = wc_XmssKey_SetWriteCb(&key, wb_write_cb_dummy);
        if (ret == 0) {
            ret = wc_XmssKey_SetReadCb(&key, wb_read_cb_fail);
        }
        if (ret != 0) {
            WB_NOTE("Reload cb setup failed; alloc-guard row skipped");
            wb_fail = 1;
        }
        else {
            mcdc_fa_arm(1);
            ret = wc_XmssKey_Reload(&key);
            mcdc_fa_disarm();
            if (ret != WC_NO_ERR_TRACE(MEMORY_E)) {
                WB_NOTE("Reload both-cb-set row did not fault at the sk "
                    "allocation as expected");
                wb_fail = 1;
            }
        }
        wc_XmssKey_Free(&key);
    }
}

/********************************************
 * 1410: wc_XmssKey_GetPrivLen()'s "if ((key == NULL) || (len == NULL))"
 * 1414-1415: same function's
 *   "if ((ret == 0) && ((key->state != WC_XMSS_STATE_OK) &&
 *                       (key->state != WC_XMSS_STATE_PARMSET)))"
 * Pure arithmetic past the guard - no crypto, safe for any state value.
 ********************************************/
static void wb_get_priv_len_state_chain(void)
{
    XmssKey key;
    word32  len;
    int     ret;

    ret = wc_XmssKey_GetPrivLen(NULL, &len);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("GetPrivLen key==NULL did not report BAD_FUNC_ARG");
        wb_fail = 1;
    }

    if (wb_make_parmset_key(&key) != 0) {
        return;
    }

    ret = wc_XmssKey_GetPrivLen(&key, NULL);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("GetPrivLen len==NULL did not report BAD_FUNC_ARG");
        wb_fail = 1;
    }

    /* state == PARMSET: state!=OK true, state!=PARMSET false -> decision
     * false (masks nothing further; this is the "!=PARMSET" operand's
     * false row). */
    len = 0;
    ret = wc_XmssKey_GetPrivLen(&key, &len);
    if (ret != 0 || len == 0) {
        WB_NOTE("GetPrivLen state==PARMSET row failed");
        wb_fail = 1;
    }

    /* state == OK: state!=OK false (masks state!=PARMSET) -> decision
     * false. */
    key.state = WC_XMSS_STATE_OK;
    len = 0;
    ret = wc_XmssKey_GetPrivLen(&key, &len);
    if (ret != 0 || len == 0) {
        WB_NOTE("GetPrivLen state==OK row failed");
        wb_fail = 1;
    }

    /* state == BAD: neither OK nor PARMSET -> both operands true ->
     * decision true. */
    key.state = WC_XMSS_STATE_BAD;
    ret = wc_XmssKey_GetPrivLen(&key, &len);
    if (ret != WC_NO_ERR_TRACE(BAD_STATE_E)) {
        WB_NOTE("GetPrivLen state==BAD did not report BAD_STATE_E");
        wb_fail = 1;
    }

    wc_XmssKey_Free(&key);
}

/********************************************
 * 1458: wc_XmssKey_Sign()'s
 *   "if ((ret == 0) && (key->state == WC_XMSS_STATE_NOSIGS))"
 * 1462: same function's
 *   "if ((ret == 0) && (key->state != WC_XMSS_STATE_OK))"
 * 1489-1490: same function's
 *   "if ((ret == 0) && ((key->write_private_key == NULL) ||
 *                       (key->read_private_key == NULL)))"
 *
 * The state==OK "guard passes" row for 1462 is blocked immediately after by
 * an undersized sigLen (line 1469, already covered) - BUFFER_E before any
 * crypto. The write/read "guard passes" row for 1489-1490 is blocked
 * instead by wb_read_cb_fail(), invoked by wc_xmsskey_signupdate() before
 * any signing math - IO_FAILED_E.
 ********************************************/
static void wb_sign_state_chain(void)
{
    XmssKey key;
    byte    sigBuf[4096];
    word32  sigLen;
    static const byte msg[] = "xmss fault whitebox sign message";
    int     ret;

    /* 1458 cond0 false: the argument guard above already set ret. */
    sigLen = 0;
    ret = wc_XmssKey_Sign(NULL, sigBuf, &sigLen, msg, (int)sizeof(msg));
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("Sign key==NULL did not report BAD_FUNC_ARG");
        wb_fail = 1;
    }

    /* 1458 true: signatures exhausted. */
    if (wb_make_parmset_key(&key) == 0) {
        key.state = WC_XMSS_STATE_NOSIGS;
        sigLen = 0;
        ret = wc_XmssKey_Sign(&key, sigBuf, &sigLen, msg, (int)sizeof(msg));
        if (ret != WC_NO_ERR_TRACE(BAD_STATE_E)) {
            WB_NOTE("Sign state==NOSIGS did not report BAD_STATE_E");
            wb_fail = 1;
        }
        wc_XmssKey_Free(&key);
    }

    /* 1458 false (PARMSET != NOSIGS) + 1462 true (PARMSET != OK). */
    if (wb_make_parmset_key(&key) == 0) {
        sigLen = 0;
        ret = wc_XmssKey_Sign(&key, sigBuf, &sigLen, msg, (int)sizeof(msg));
        if (ret != WC_NO_ERR_TRACE(BAD_STATE_E)) {
            WB_NOTE("Sign state==PARMSET did not report BAD_STATE_E");
            wb_fail = 1;
        }
        wc_XmssKey_Free(&key);
    }

    /* 1458 false + 1462 false (state == OK): blocked by an undersized
     * sigLen before any crypto. */
    if (wb_make_parmset_key(&key) == 0) {
        key.state = WC_XMSS_STATE_OK;
        sigLen = 0; /* always fails the sigLen check, any parameter set */
        ret = wc_XmssKey_Sign(&key, sigBuf, &sigLen, msg, (int)sizeof(msg));
        if (ret != WC_NO_ERR_TRACE(BUFFER_E)) {
            WB_NOTE("Sign state==OK row did not hit the sigLen guard");
            wb_fail = 1;
        }
        wc_XmssKey_Free(&key);
    }

    /* 1489-1490 true (write NULL, read set): callbacks set BEFORE forcing
     * state to OK (SetReadCb/SetWriteCb refuse an already-OK key). */
    if (wb_make_parmset_key(&key) == 0) {
        ret = wc_XmssKey_SetReadCb(&key, wb_read_cb_fail);
        if (ret != 0) { WB_NOTE("SetReadCb failed"); wb_fail = 1; }
        key.state = WC_XMSS_STATE_OK;
        sigLen = (word32)sizeof(sigBuf);
        ret = wc_XmssKey_Sign(&key, sigBuf, &sigLen, msg, (int)sizeof(msg));
        if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
            WB_NOTE("Sign write-cb-NULL row did not report BAD_FUNC_ARG");
            wb_fail = 1;
        }
        wc_XmssKey_Free(&key);
    }

    /* 1489-1490 true (write set, read NULL): the OR's other operand. */
    if (wb_make_parmset_key(&key) == 0) {
        ret = wc_XmssKey_SetWriteCb(&key, wb_write_cb_dummy);
        if (ret != 0) { WB_NOTE("SetWriteCb failed"); wb_fail = 1; }
        key.state = WC_XMSS_STATE_OK;
        sigLen = (word32)sizeof(sigBuf);
        ret = wc_XmssKey_Sign(&key, sigBuf, &sigLen, msg, (int)sizeof(msg));
        if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
            WB_NOTE("Sign read-cb-NULL row did not report BAD_FUNC_ARG");
            wb_fail = 1;
        }
        wc_XmssKey_Free(&key);
    }

    /* 1489-1490 false: both callbacks set. wb_read_cb_fail() bails the
     * moment wc_xmsskey_signupdate() calls it, before any real WOTS+/
     * tree-hash math. */
    if (wb_make_parmset_key(&key) == 0) {
        ret = wc_XmssKey_SetWriteCb(&key, wb_write_cb_dummy);
        if (ret == 0) {
            ret = wc_XmssKey_SetReadCb(&key, wb_read_cb_fail);
        }
        if (ret != 0) {
            WB_NOTE("Sign cb setup failed; both-cb-set row skipped");
            wb_fail = 1;
        }
        else {
            key.state = WC_XMSS_STATE_OK;
            sigLen = (word32)sizeof(sigBuf);
            ret = wc_XmssKey_Sign(&key, sigBuf, &sigLen, msg,
                (int)sizeof(msg));
            if (ret != WC_NO_ERR_TRACE(IO_FAILED_E)) {
                WB_NOTE("Sign both-cb-set row did not fault via "
                    "read_private_key as expected");
                wb_fail = 1;
            }
        }
        wc_XmssKey_Free(&key);
    }
}

#else /* WOLFSSL_XMSS_VERIFY_ONLY: MakeKey/Reload/GetPrivLen/Sign and their
       * write/read callbacks are not compiled in. */
static void wb_makekey_state_chain(void)
{
    WB_NOTE("WOLFSSL_XMSS_VERIFY_ONLY: MakeKey not compiled in; "
        "wb_makekey_state_chain skipped");
}
static void wb_reload_state_chain(void)
{
    WB_NOTE("WOLFSSL_XMSS_VERIFY_ONLY: Reload not compiled in; "
        "wb_reload_state_chain skipped");
}
static void wb_get_priv_len_state_chain(void)
{
    WB_NOTE("WOLFSSL_XMSS_VERIFY_ONLY: GetPrivLen not compiled in; "
        "wb_get_priv_len_state_chain skipped");
}
static void wb_sign_state_chain(void)
{
    WB_NOTE("WOLFSSL_XMSS_VERIFY_ONLY: Sign not compiled in; "
        "wb_sign_state_chain skipped");
}
#endif /* !WOLFSSL_XMSS_VERIFY_ONLY */

/********************************************
 * 1962-1963: wc_XmssKey_Verify()'s
 *   "if ((ret == 0) && (key->state != WC_XMSS_STATE_OK) &&
 *                      (key->state != WC_XMSS_STATE_VERIFYONLY))"
 * Compiled in every variant (including VERIFY_ONLY). The two "guard
 * passes" rows (state OK / VERIFYONLY) are blocked immediately after by a
 * deliberately mismatched sigLen (line 1972, already covered) - BUFFER_E
 * before the real tree-hash walk.
 ********************************************/
static void wb_verify_state_chain(void)
{
    XmssKey key;
    byte    sig[8]; /* never dereferenced: bails at the sigLen check */
    static const byte msg[] = "xmss fault whitebox verify message";
    int     ret;

    ret = wc_XmssKey_Verify(NULL, sig, (word32)sizeof(sig), msg,
        (int)sizeof(msg));
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("Verify key==NULL did not report BAD_FUNC_ARG");
        wb_fail = 1;
    }

    if (wb_make_parmset_key(&key) != 0) {
        return;
    }

    /* state == BAD: neither OK nor VERIFYONLY -> decision true. */
    key.state = WC_XMSS_STATE_BAD;
    ret = wc_XmssKey_Verify(&key, sig, (word32)sizeof(sig), msg,
        (int)sizeof(msg));
    if (ret != WC_NO_ERR_TRACE(BAD_STATE_E)) {
        WB_NOTE("Verify state==BAD did not report BAD_STATE_E");
        wb_fail = 1;
    }

    /* state == OK: state!=OK false -> decision false (masks state!=
     * VERIFYONLY); blocked by the sigLen mismatch immediately after. */
    key.state = WC_XMSS_STATE_OK;
    ret = wc_XmssKey_Verify(&key, sig, (word32)sizeof(sig), msg,
        (int)sizeof(msg));
    if (ret != WC_NO_ERR_TRACE(BUFFER_E)) {
        WB_NOTE("Verify state==OK row did not hit the sigLen guard");
        wb_fail = 1;
    }

    /* state == VERIFYONLY: state!=OK true, state!=VERIFYONLY false ->
     * decision false. */
    key.state = WC_XMSS_STATE_VERIFYONLY;
    ret = wc_XmssKey_Verify(&key, sig, (word32)sizeof(sig), msg,
        (int)sizeof(msg));
    if (ret != WC_NO_ERR_TRACE(BUFFER_E)) {
        WB_NOTE("Verify state==VERIFYONLY row did not hit the sigLen "
            "guard");
        wb_fail = 1;
    }

    wc_XmssKey_Free(&key);
}

/********************************************
 * 1912: wc_XmssKey_GetSigLen()'s "if ((key == NULL) || ...)" - only the
 * key==NULL operand is an open gap (the others are covered elsewhere).
 * 1916-1918: same function's
 *   "if ((ret == 0) && (key->state != WC_XMSS_STATE_OK) &&
 *                      (key->state != WC_XMSS_STATE_PARMSET) &&
 *                      (key->state != WC_XMSS_STATE_VERIFYONLY))"
 * Pure arithmetic past the guard - safe for any state, every variant.
 ********************************************/
static void wb_get_sig_len_state_chain(void)
{
    XmssKey key;
    word32  len;
    int     ret;

    ret = wc_XmssKey_GetSigLen(NULL, &len);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("GetSigLen key==NULL did not report BAD_FUNC_ARG");
        wb_fail = 1;
    }

    if (wb_make_parmset_key(&key) != 0) {
        return;
    }

    /* state == BAD: all three "!=" operands true -> decision true. */
    key.state = WC_XMSS_STATE_BAD;
    ret = wc_XmssKey_GetSigLen(&key, &len);
    if (ret != WC_NO_ERR_TRACE(BAD_STATE_E)) {
        WB_NOTE("GetSigLen state==BAD did not report BAD_STATE_E");
        wb_fail = 1;
    }

    /* state == OK: first "!=" operand false -> decision false. */
    key.state = WC_XMSS_STATE_OK;
    len = 0;
    ret = wc_XmssKey_GetSigLen(&key, &len);
    if (ret != 0 || len == 0) {
        WB_NOTE("GetSigLen state==OK row failed");
        wb_fail = 1;
    }

    /* state == PARMSET: second "!=" operand false (first true). */
    key.state = WC_XMSS_STATE_PARMSET;
    len = 0;
    ret = wc_XmssKey_GetSigLen(&key, &len);
    if (ret != 0 || len == 0) {
        WB_NOTE("GetSigLen state==PARMSET row failed");
        wb_fail = 1;
    }

    /* state == VERIFYONLY: third "!=" operand false (first two true). */
    key.state = WC_XMSS_STATE_VERIFYONLY;
    len = 0;
    ret = wc_XmssKey_GetSigLen(&key, &len);
    if (ret != 0 || len == 0) {
        WB_NOTE("GetSigLen state==VERIFYONLY row failed");
        wb_fail = 1;
    }

    wc_XmssKey_Free(&key);
}

/********************************************
 * 1000: wc_XmssKey_GetParamStr()'s "if ((key == NULL) || (str == NULL))"
 * 1003-1006: same function's
 *   "if (key->state != PARMSET && != OK && != VERIFYONLY && != NOSIGS)"
 * Table lookup only past the guard - no crypto, every variant.
 ********************************************/
static void wb_get_param_str_state_chain(void)
{
    XmssKey     key;
    const char* str;
    int         ret;

    ret = wc_XmssKey_GetParamStr(NULL, &str);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("GetParamStr key==NULL did not report BAD_FUNC_ARG");
        wb_fail = 1;
    }

    if (wb_make_parmset_key(&key) != 0) {
        return;
    }

    str = NULL;
    ret = wc_XmssKey_GetParamStr(&key, NULL);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("GetParamStr str==NULL did not report BAD_FUNC_ARG");
        wb_fail = 1;
    }

    /* state == BAD: none of the four listed states -> all four operands
     * true -> decision true. */
    key.state = WC_XMSS_STATE_BAD;
    str = NULL;
    ret = wc_XmssKey_GetParamStr(&key, &str);
    if (ret != WC_NO_ERR_TRACE(BAD_STATE_E)) {
        WB_NOTE("GetParamStr state==BAD did not report BAD_STATE_E");
        wb_fail = 1;
    }

    /* state == PARMSET: first operand false -> decision false. */
    key.state = WC_XMSS_STATE_PARMSET;
    str = NULL;
    ret = wc_XmssKey_GetParamStr(&key, &str);
    if (ret != 0 || str == NULL) {
        WB_NOTE("GetParamStr state==PARMSET row failed");
        wb_fail = 1;
    }

    /* state == OK: second operand false (first true). */
    key.state = WC_XMSS_STATE_OK;
    str = NULL;
    ret = wc_XmssKey_GetParamStr(&key, &str);
    if (ret != 0 || str == NULL) {
        WB_NOTE("GetParamStr state==OK row failed");
        wb_fail = 1;
    }

    /* state == VERIFYONLY: third operand false (first two true). */
    key.state = WC_XMSS_STATE_VERIFYONLY;
    str = NULL;
    ret = wc_XmssKey_GetParamStr(&key, &str);
    if (ret != 0 || str == NULL) {
        WB_NOTE("GetParamStr state==VERIFYONLY row failed");
        wb_fail = 1;
    }

    /* state == NOSIGS: fourth operand false (first three true). */
    key.state = WC_XMSS_STATE_NOSIGS;
    str = NULL;
    ret = wc_XmssKey_GetParamStr(&key, &str);
    if (ret != 0 || str == NULL) {
        WB_NOTE("GetParamStr state==NOSIGS row failed");
        wb_fail = 1;
    }

    wc_XmssKey_Free(&key);
}

/********************************************
 * 1580: wc_XmssKey_GetPubLen()'s
 *   "if ((key == NULL) || (key->params == NULL) || (len == NULL))" -
 * only the first two operands are open gaps (the third is covered
 * elsewhere). key->params == NULL happens naturally right after Init,
 * before SetParamStr.
 ********************************************/
static void wb_get_pub_len_guard(void)
{
    XmssKey key;
    word32  len;
    int     ret;

    ret = wc_XmssKey_GetPubLen(NULL, &len);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("GetPubLen key==NULL did not report BAD_FUNC_ARG");
        wb_fail = 1;
    }

    XMEMSET(&key, 0, sizeof(key));
    ret = wc_XmssKey_Init(&key, NULL, INVALID_DEVID);
    if (ret != 0) {
        WB_NOTE("wc_XmssKey_Init failed; GetPubLen rows skipped");
        wb_fail = 1;
        return;
    }

    /* key->params == NULL (fresh Init, no SetParamStr yet). */
    ret = wc_XmssKey_GetPubLen(&key, &len);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("GetPubLen params==NULL did not report BAD_FUNC_ARG");
        wb_fail = 1;
    }

    /* All-false baseline: real params. */
    ret = wc_XmssKey_SetParamStr(&key, WB_PARM_STR);
    if (ret != 0) {
        WB_NOTE("SetParamStr unavailable; GetPubLen baseline skipped");
        wb_fail = 1;
    }
    else {
        len = 0;
        ret = wc_XmssKey_GetPubLen(&key, &len);
        if (ret != 0 || len == 0) {
            WB_NOTE("GetPubLen baseline row failed");
            wb_fail = 1;
        }
    }

    wc_XmssKey_Free(&key);
}

/********************************************
 * 1611: wc_XmssKey_ExportPub_ex()'s
 *   "if ((keyDst == NULL) || (keySrc == NULL))"
 * Struct copy only - no crypto.
 ********************************************/
static void wb_export_pub_guard(void)
{
    XmssKey src;
    XmssKey dst;
    int     ret;

    if (wb_make_parmset_key(&src) != 0) {
        return;
    }

    ret = wc_XmssKey_ExportPub_ex(NULL, &src, NULL, INVALID_DEVID);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("ExportPub_ex keyDst==NULL did not report BAD_FUNC_ARG");
        wb_fail = 1;
    }

    ret = wc_XmssKey_ExportPub_ex(&dst, NULL, NULL, INVALID_DEVID);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("ExportPub_ex keySrc==NULL did not report BAD_FUNC_ARG");
        wb_fail = 1;
    }

    ret = wc_XmssKey_ExportPub_ex(&dst, &src, NULL, INVALID_DEVID);
    if (ret != 0) {
        WB_NOTE("ExportPub_ex valid-args row failed");
        wb_fail = 1;
    }

    wc_XmssKey_Free(&src);
    wc_XmssKey_Free(&dst);
}

/********************************************
 * 1665: wc_XmssKey_ExportPubRaw()'s
 *   "if ((key == NULL) || (out == NULL) || (outLen == NULL))"
 * 1674: same function's "if ((ret == 0) && (*outLen < pubLen))"
 * Buffer-size arithmetic and a memcpy - no crypto.
 ********************************************/
static void wb_export_pub_raw_guard(void)
{
    XmssKey key;
    byte    buf[512];
    word32  outLen;
    int     ret;

    if (wb_make_parmset_key(&key) != 0) {
        return;
    }

    outLen = (word32)sizeof(buf);
    ret = wc_XmssKey_ExportPubRaw(NULL, buf, &outLen);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("ExportPubRaw key==NULL did not report BAD_FUNC_ARG");
        wb_fail = 1;
    }

    ret = wc_XmssKey_ExportPubRaw(&key, NULL, &outLen);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("ExportPubRaw out==NULL did not report BAD_FUNC_ARG");
        wb_fail = 1;
    }

    ret = wc_XmssKey_ExportPubRaw(&key, buf, NULL);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("ExportPubRaw outLen==NULL did not report BAD_FUNC_ARG");
        wb_fail = 1;
    }

    /* 1674 false: buffer big enough. */
    outLen = (word32)sizeof(buf);
    ret = wc_XmssKey_ExportPubRaw(&key, buf, &outLen);
    if (ret != 0) {
        WB_NOTE("ExportPubRaw baseline row failed");
        wb_fail = 1;
    }

    /* 1674 true: buffer too small. */
    outLen = 1;
    ret = wc_XmssKey_ExportPubRaw(&key, buf, &outLen);
    if (ret != WC_NO_ERR_TRACE(BUFFER_E)) {
        WB_NOTE("ExportPubRaw undersized-outLen did not report BUFFER_E");
        wb_fail = 1;
    }

    wc_XmssKey_Free(&key);
}

/********************************************
 * 1860: wc_XmssKey_ImportPubRaw()'s "if ((key == NULL) || (in == NULL))"
 * 1864: same function's
 *   "if ((ret == 0) && (key->state != WC_XMSS_STATE_PARMSET))"
 * 1875: same function's "if ((ret == 0) && (inLen != pubLen))"
 * Struct copy only - no crypto.
 ********************************************/
static void wb_import_pub_raw_guard(void)
{
    XmssKey src;
    XmssKey dst;
    XmssKey freshKey;
    byte    buf[512];
    word32  outLen;
    int     ret;

    if (wb_make_parmset_key(&src) != 0) {
        return;
    }
    outLen = (word32)sizeof(buf);
    ret = wc_XmssKey_ExportPubRaw(&src, buf, &outLen);
    if (ret != 0) {
        WB_NOTE("ExportPubRaw prep failed; ImportPubRaw rows skipped");
        wb_fail = 1;
        wc_XmssKey_Free(&src);
        return;
    }

    ret = wc_XmssKey_ImportPubRaw(NULL, buf, outLen);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("ImportPubRaw key==NULL did not report BAD_FUNC_ARG");
        wb_fail = 1;
    }

    if (wb_make_parmset_key(&dst) == 0) {
        ret = wc_XmssKey_ImportPubRaw(&dst, NULL, outLen);
        if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
            WB_NOTE("ImportPubRaw in==NULL did not report BAD_FUNC_ARG");
            wb_fail = 1;
        }

        /* 1864 true: fresh (INITED, not PARMSET) key. */
        XMEMSET(&freshKey, 0, sizeof(freshKey));
        ret = wc_XmssKey_Init(&freshKey, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wc_XmssKey_ImportPubRaw(&freshKey, buf, outLen);
        }
        if (ret != WC_NO_ERR_TRACE(BAD_STATE_E)) {
            WB_NOTE("ImportPubRaw state==INITED did not report "
                "BAD_STATE_E");
            wb_fail = 1;
        }
        wc_XmssKey_Free(&freshKey);

        /* 1864 false (PARMSET) + 1875 true: wrong inLen. */
        ret = wc_XmssKey_ImportPubRaw(&dst, buf, outLen - 1U);
        if (ret != WC_NO_ERR_TRACE(BUFFER_E)) {
            WB_NOTE("ImportPubRaw wrong inLen did not report BUFFER_E");
            wb_fail = 1;
        }

        /* 1864 false + 1875 false: baseline success. */
        ret = wc_XmssKey_ImportPubRaw(&dst, buf, outLen);
        if (ret != 0) {
            WB_NOTE("ImportPubRaw baseline row failed");
            wb_fail = 1;
        }
        wc_XmssKey_Free(&dst);
    }

    wc_XmssKey_Free(&src);
}

#ifdef WOLF_PRIVATE_KEY_ID
/********************************************
 * 874: wc_XmssKey_InitId()'s
 *   "if (ret == 0 && (len < 0 || len > XMSS_MAX_ID_LEN))"
 * 878: same function's
 *   "if (ret == 0 && id != NULL && len != 0)"
 * 903: wc_XmssKey_InitLabel()'s "if (key == NULL || label == NULL)"
 * 907: same function's
 *   "if (labelLen == 0 || labelLen > XMSS_MAX_LABEL_LEN)"
 * WOLF_PRIVATE_KEY_ID is auto-enabled by settings.h whenever
 * HAVE_PK_CALLBACKS is set (true for every campaign variant here), so this
 * is not a dead gate in practice.
 ********************************************/
static void wb_init_id_label(void)
{
    XmssKey key;
    byte    id[4] = { 1, 2, 3, 4 };
    char    bigLabel[XMSS_MAX_LABEL_LEN + 2];
    int     ret;

    /* 874 baseline (len == 0, within range) + 878 false (len == 0). */
    XMEMSET(&key, 0, sizeof(key));
    ret = wc_XmssKey_InitId(&key, id, 0, NULL, INVALID_DEVID);
    if (ret != 0 || key.idLen != 0) {
        WB_NOTE("InitId len==0 baseline failed");
        wb_fail = 1;
    }

    /* 874 true: len < 0. */
    XMEMSET(&key, 0, sizeof(key));
    ret = wc_XmssKey_InitId(&key, id, -1, NULL, INVALID_DEVID);
    if (ret != WC_NO_ERR_TRACE(BUFFER_E)) {
        WB_NOTE("InitId len<0 did not report BUFFER_E");
        wb_fail = 1;
    }

    /* 874 true: len > XMSS_MAX_ID_LEN. */
    XMEMSET(&key, 0, sizeof(key));
    ret = wc_XmssKey_InitId(&key, id, XMSS_MAX_ID_LEN + 1, NULL,
        INVALID_DEVID);
    if (ret != WC_NO_ERR_TRACE(BUFFER_E)) {
        WB_NOTE("InitId len>MAX did not report BUFFER_E");
        wb_fail = 1;
    }

    /* 874 false-masking row: key == NULL (ret != 0 entering the check). */
    ret = wc_XmssKey_InitId(NULL, id, -1, NULL, INVALID_DEVID);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("InitId key==NULL did not report BAD_FUNC_ARG");
        wb_fail = 1;
    }

    /* 878 true (all operands true): valid id, non-zero len. */
    XMEMSET(&key, 0, sizeof(key));
    ret = wc_XmssKey_InitId(&key, id, (int)sizeof(id), NULL, INVALID_DEVID);
    if (ret != 0 || key.idLen != (int)sizeof(id)) {
        WB_NOTE("InitId valid id/len row failed");
        wb_fail = 1;
    }

    /* 878 false: id == NULL (len != 0 held true). */
    XMEMSET(&key, 0, sizeof(key));
    ret = wc_XmssKey_InitId(&key, NULL, 4, NULL, INVALID_DEVID);
    if (ret != 0 || key.idLen != 0) {
        WB_NOTE("InitId id==NULL row unexpectedly copied an id");
        wb_fail = 1;
    }

    /* 903 true: key == NULL. */
    ret = wc_XmssKey_InitLabel(NULL, "label", NULL, INVALID_DEVID);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("InitLabel key==NULL did not report BAD_FUNC_ARG");
        wb_fail = 1;
    }

    /* 903 true: label == NULL (key != NULL). */
    XMEMSET(&key, 0, sizeof(key));
    ret = wc_XmssKey_InitLabel(&key, NULL, NULL, INVALID_DEVID);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("InitLabel label==NULL did not report BAD_FUNC_ARG");
        wb_fail = 1;
    }

    /* 903 false baseline + 907 false: valid, in-range label. */
    XMEMSET(&key, 0, sizeof(key));
    ret = wc_XmssKey_InitLabel(&key, "label", NULL, INVALID_DEVID);
    if (ret != 0) {
        WB_NOTE("InitLabel valid-label baseline failed");
        wb_fail = 1;
    }

    /* 907 true: empty label. */
    XMEMSET(&key, 0, sizeof(key));
    ret = wc_XmssKey_InitLabel(&key, "", NULL, INVALID_DEVID);
    if (ret != WC_NO_ERR_TRACE(BUFFER_E)) {
        WB_NOTE("InitLabel empty label did not report BUFFER_E");
        wb_fail = 1;
    }

    /* 907 true: label longer than XMSS_MAX_LABEL_LEN. */
    XMEMSET(bigLabel, 'a', sizeof(bigLabel) - 1U);
    bigLabel[sizeof(bigLabel) - 1U] = '\0';
    XMEMSET(&key, 0, sizeof(key));
    ret = wc_XmssKey_InitLabel(&key, bigLabel, NULL, INVALID_DEVID);
    if (ret != WC_NO_ERR_TRACE(BUFFER_E)) {
        WB_NOTE("InitLabel oversized label did not report BUFFER_E");
        wb_fail = 1;
    }
}
#else
static void wb_init_id_label(void)
{
    WB_NOTE("WOLF_PRIVATE_KEY_ID not compiled in; wb_init_id_label "
        "skipped");
}
#endif /* WOLF_PRIVATE_KEY_ID */

#ifndef WOLFSSL_XMSS_VERIFY_ONLY
/********************************************
 * 1117: wc_XmssKey_SetReadCb()'s "if ((key == NULL) || (read_cb == NULL))"
 ********************************************/
static void wb_set_read_cb_guard(void)
{
    XmssKey key;
    int     ret;

    ret = wc_XmssKey_SetReadCb(NULL, wb_read_cb_fail);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("SetReadCb key==NULL did not report BAD_FUNC_ARG");
        wb_fail = 1;
    }

    if (wb_make_parmset_key(&key) != 0) {
        return;
    }

    ret = wc_XmssKey_SetReadCb(&key, NULL);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("SetReadCb read_cb==NULL did not report BAD_FUNC_ARG");
        wb_fail = 1;
    }

    ret = wc_XmssKey_SetReadCb(&key, wb_read_cb_fail);
    if (ret != 0) {
        WB_NOTE("SetReadCb valid-args row failed");
        wb_fail = 1;
    }

    wc_XmssKey_Free(&key);
}
#else
static void wb_set_read_cb_guard(void)
{
    WB_NOTE("WOLFSSL_XMSS_VERIFY_ONLY: SetReadCb not compiled in; "
        "wb_set_read_cb_guard skipped");
}
#endif /* !WOLFSSL_XMSS_VERIFY_ONLY */

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("wc_xmss.c fault white-box\n");

    mcdc_fa_install();

    wb_init_id_label();
    wb_get_param_str_state_chain();
    wb_set_read_cb_guard();
    wb_makekey_state_chain();
    wb_reload_state_chain();
    wb_get_priv_len_state_chain();
    wb_sign_state_chain();
    wb_get_pub_len_guard();
    wb_export_pub_guard();
    wb_export_pub_raw_guard();
    wb_import_pub_raw_guard();
    wb_get_sig_len_state_chain();
    wb_verify_state_chain();

    mcdc_fa_disarm();
    mcdc_fa_restore();

    printf("done (%s)\n", wb_fail ? "with failures" : "ok");
    return 0;
}

#endif /* WOLFSSL_HAVE_XMSS */
