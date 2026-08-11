/* test_mldsa_hash_fault_whitebox.c
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
 * MC/DC hash-fault white-box supplement for wolfcrypt/src/wc_mldsa.c.
 *
 * test_mldsa_fault_whitebox.c already faults the ALLOCATOR. That lever stops
 * at the outer `if (ret == 0)` that follows wc_mldsa.c's single bulk working
 * buffer: an allocation failure returns MEMORY_E before any of the sampling /
 * expand / sign / verify loops is entered, so the FALSE half of their
 * `(ret == 0)` operands stays undriven. Those loops take `ret` from one place
 * only -- SHAKE:
 *
 *     mldsa_shake256()    wc_Shake256_Update / _Final
 *     mldsa_squeeze256()  wc_Shake256_Absorb / _SqueezeBlocks
 *     mldsa_sample_in_ball()  wc_Shake256_SqueezeBlocks, per exhausted block
 *
 * mcdc_fault_hash.h macro-interposes those for THIS translation unit only and
 * mcdc_fh_arm(n) makes the n-th call -- and every later one -- return
 * BAD_FUNC_ARG. Sweeping n across sign / verify / keygen therefore drives
 *
 *     for (r = 0; (ret == 0) && (r < l); r++)              expand-mask
 *     for (i = N - tau; (ret == 0) && (i < N); i++)        sample-in-ball
 *     while ((ret == 0) && (j > i))                        sample-in-ball
 *     for (; (ret == 0) && valid && (r < params->k); r++)  small-mem sign
 *     if ((ret == 0) && valid)                             small-mem sign
 *     for (r = 0; (ret == 0) && (r < params->k); r++)      small-mem verify
 *     for (s = 0; (ret == 0) && (s < params->l); s++)      small-mem verify
 *
 * false, against the ordinary (T,T) rows the same binary produces disarmed.
 *
 * A NOTE ON PAIRING (HARD RULE 1): for `(ret == 0) && X` an armed row alone is
 * not a pair when X is false in the ordinary row -- both vectors then have the
 * same FALSE outcome. Every site above is a loop header or is followed by work
 * that runs in the ordinary case, so the disarmed run supplies a genuine (T,T).
 * Where that is NOT true the operand is a documented residual instead; see the
 * list at the bottom of this comment.
 *
 * ARGUMENT ROWS (no injector needed)
 * ----------------------------------
 *   - `if ((ret == 0) && (!key->prvKeySet))`: needs a key that has parameters
 *     and a PUBLIC key but no private key. Every API test signs with a full
 *     key, so only the FALSE side is ever produced.
 *   - `if ((ret == 0) && (id != NULL) && (len != 0))` in wc_MlDsaKey_InitId:
 *     needs the id == NULL / len == 0 call, which no test makes because the
 *     entry point exists to attach an id.
 *   - `if ((ret == 0) && ((int)hashLen != wc_HashGetDigestSize(hashAlg)))` in
 *     the static mldsa_verify_ctx_hash(): the FALSE side of the first operand
 *     needs key == NULL, which the public wrapper rejects before calling. The
 *     static helper is in scope here and is called directly.
 *
 * DOCUMENTED RESIDUALS (mirrored in campaign/db/exclusions.json):
 *   - `for (; (ret == 0) && valid && (r < params->k); r++)` and
 *     `if ((ret == 0) && valid)`: `valid` is assigned 1 unconditionally and is
 *     only ever assigned 0 inside `#ifdef WOLFSSL_MLDSA_SIGN_CHECK_Y`,
 *     `#ifdef WOLFSSL_MLDSA_SIGN_CHECK_W0` and `#ifdef WC_MLDSA_FAULT_HARDEN`.
 *     None of the three is set by any variant of this module, so in every
 *     compiled build the operand is the constant 1.
 *   - `if ((oid != NULL) && (*oidLen <= MLDSA_HASH_OID_LEN - 2))` and
 *     `if ((oid != NULL) && (*oidLen <= MLDSA_HASH_OID_LEN))`: *oidLen comes
 *     from the hash-OID table the same branch selected, whose entries are all
 *     at most MLDSA_HASH_OID_LEN - 2 bytes long, so the bound holds for every
 *     value the first operand admits.
 *
 * VARIANT COVERAGE (HARD RULE 2): every row is behind the feature guard of the
 * entry point it drives, with an #else skip stub, and main() always returns 0.
 * Determinism (HARD RULE 3): fixed seeds, fixed message, and a sweep bounded by
 * a vector COUNT -- there is no wall clock anywhere in this file.
 */

#include "mcdc_fault_hash.h"

/* wc_mldsa.c is #included AFTER the interposers are installed. */
#include <wolfcrypt/src/wc_mldsa.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if !defined(WOLFSSL_HAVE_MLDSA)

int main(void)
{
    printf("wc_mldsa.c hash-fault white-box: MLDSA off, nothing to do\n");
    return 0;
}

#else

/* ML-DSA-44: smallest parameter set, so keygen/sign stay cheap under coverage
 * instrumentation. */
#define WB_LEVEL WC_ML_DSA_44

/* Sweep shape. The residual loops all sit in the sign/verify sampling core,
 * which is thousands of SHAKE calls deep, so a dense head plus a bounded
 * number of strided points is what reaches them without an unbounded run.
 * Every bound here is a VECTOR COUNT; nothing in this file reads a clock. */
#define WB_DENSE          64
#define WB_POINTS_SIGN    64
#define WB_POINTS_VERIFY  64
#define WB_POINTS_KEYGEN  32

static byte s_keySeed[MLDSA_SEED_SZ];
static byte s_sigSeed[MLDSA_RND_SZ];
static byte s_msg[32];
static byte s_sig[8192];

static long wb_next(long n, long k, long budget)
{
    long stride;

    if (n < (long)WB_DENSE)
        return n + 1;
    stride = k / budget;
    if (stride < 1)
        stride = 1;
    return n + stride;
}

static int wb_build_key(wc_MlDsaKey* key)
{
    int ret = wc_MlDsaKey_Init(key, NULL, INVALID_DEVID);

    if (ret == 0) {
        ret = wc_MlDsaKey_SetParams(key, WB_LEVEL);
    }
#ifndef WOLFSSL_MLDSA_NO_MAKE_KEY
    if (ret == 0) {
        ret = wc_MlDsaKey_MakeKeyFromSeed(key, s_keySeed);
    }
#else
    ret = NOT_COMPILED_IN;
#endif
    return ret;
}

#if !defined(WOLFSSL_MLDSA_NO_MAKE_KEY) && !defined(WOLFSSL_MLDSA_NO_SIGN)

static void wb_sweep_sign(wc_MlDsaKey* key)
{
    word32 sigLen = (word32)sizeof(s_sig);
    long   k, n, points = 0;

    mcdc_fh_disarm();
    if (wc_MlDsaKey_SignCtxWithSeed(key, NULL, 0, s_sig, &sigLen, s_msg,
            (word32)sizeof(s_msg), s_sigSeed) != 0) {
        WB_NOTE("baseline sign failed; sign sweep skipped");
        wb_fail = 1;
        return;
    }
    k = mcdc_fh_seen();
    printf("  [wb] sign K=%ld\n", k);

    for (n = 1; n <= k; n = wb_next(n, k, WB_POINTS_SIGN)) {
        byte   s2[sizeof(s_sig)];
        word32 l2 = (word32)sizeof(s2);
        mcdc_fh_arm(n);
        (void)wc_MlDsaKey_SignCtxWithSeed(key, NULL, 0, s2, &l2, s_msg,
            (word32)sizeof(s_msg), s_sigSeed);
        mcdc_fh_disarm();
        points++;
    }
    printf("  [wb] sign sweep: %ld points\n", points);
}

#else

static void wb_sweep_sign(wc_MlDsaKey* key)
{
    (void)key;
    WB_NOTE("signing not compiled in this variant; sign sweep skipped");
}

#endif

#ifndef WOLFSSL_MLDSA_NO_VERIFY

static void wb_sweep_verify(wc_MlDsaKey* key, word32 sigLen)
{
    long k, n, points = 0;
    int  res = 0;

    if (sigLen == 0) {
        return;
    }

    mcdc_fh_disarm();
    (void)wc_MlDsaKey_VerifyCtx(key, s_sig, sigLen, NULL, 0, s_msg,
        (word32)sizeof(s_msg), &res);
    k = mcdc_fh_seen();
    printf("  [wb] verify K=%ld\n", k);

    for (n = 1; n <= k; n = wb_next(n, k, WB_POINTS_VERIFY)) {
        res = 0;
        mcdc_fh_arm(n);
        (void)wc_MlDsaKey_VerifyCtx(key, s_sig, sigLen, NULL, 0, s_msg,
            (word32)sizeof(s_msg), &res);
        mcdc_fh_disarm();
        points++;
    }
    printf("  [wb] verify sweep: %ld points\n", points);
}

#else

static void wb_sweep_verify(wc_MlDsaKey* key, word32 sigLen)
{
    (void)key; (void)sigLen;
    WB_NOTE("verify not compiled in this variant; verify sweep skipped");
}

#endif

#ifndef WOLFSSL_MLDSA_NO_MAKE_KEY

static void wb_sweep_makekey(void)
{
    long k, n, points = 0;

    mcdc_fh_disarm();
    {
        wc_MlDsaKey key;
        XMEMSET(&key, 0, sizeof(key));
        if (wb_build_key(&key) != 0) {
            wc_MlDsaKey_Free(&key);
            WB_NOTE("baseline keygen failed; keygen sweep skipped");
            return;
        }
        k = mcdc_fh_seen();
        wc_MlDsaKey_Free(&key);
    }
    printf("  [wb] keygen K=%ld\n", k);

    for (n = 1; n <= k; n = wb_next(n, k, WB_POINTS_KEYGEN)) {
        wc_MlDsaKey key;
        XMEMSET(&key, 0, sizeof(key));
        if (wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID) == 0 &&
                wc_MlDsaKey_SetParams(&key, WB_LEVEL) == 0) {
            mcdc_fh_arm(n);
            (void)wc_MlDsaKey_MakeKeyFromSeed(&key, s_keySeed);
            mcdc_fh_disarm();
            points++;
        }
        wc_MlDsaKey_Free(&key);
    }
    printf("  [wb] keygen sweep: %ld points\n", points);
}

#else

static void wb_sweep_makekey(void)
{
    WB_NOTE("keygen not compiled in this variant; keygen sweep skipped");
}

#endif

/* ------------------------------------------------------------------------- *
 * Argument rows.
 * ------------------------------------------------------------------------- */

/* `if ((ret == 0) && (!key->prvKeySet))`: a key with parameters and a public
 * key but no private key. Only the entry point's own validation runs, so
 * nothing downstream ever sees the half-populated key. */
#if !defined(WOLFSSL_MLDSA_NO_SIGN) && defined(WOLFSSL_MLDSA_PUBLIC_KEY)
static void wb_sign_no_private(void)
{
    wc_MlDsaKey key;
    byte   sig[64];
    byte   hash[32];
    word32 sigLen = (word32)sizeof(sig);

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(hash, 0x5b, sizeof(hash));

    if (wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID) != 0) {
        return;
    }
    if (wc_MlDsaKey_SetParams(&key, WB_LEVEL) == 0) {
        /* prvKeySet is left 0 by Init/SetParams. */
        if (wc_MlDsaKey_SignCtxHashWithSeed(&key, NULL, 0, sig, &sigLen, hash,
                (word32)sizeof(hash), (int)WC_HASH_TYPE_SHA256,
                s_sigSeed) == 0) {
            WB_NOTE("SignCtxHashWithSeed accepted a key with no private key");
            wb_fail = 1;
        }
    }
    wc_MlDsaKey_Free(&key);

    /* The partner row: the SAME entry point on a key that DOES have a private
     * key, so the operand is false with the decision reaching its other
     * outcome. Nothing else in the campaign calls the seeded pre-hash signer,
     * so without this the operand above has no vector to pair against. */
#ifndef WOLFSSL_MLDSA_NO_MAKE_KEY
    XMEMSET(&key, 0, sizeof(key));
    if (wb_build_key(&key) == 0) {
        byte   sig2[8192];
        word32 sig2Len = (word32)sizeof(sig2);

        if (wc_MlDsaKey_SignCtxHashWithSeed(&key, NULL, 0, sig2, &sig2Len,
                hash, (word32)sizeof(hash), (int)WC_HASH_TYPE_SHA256,
                s_sigSeed) != 0) {
            WB_NOTE("seeded pre-hash sign failed on a full key");
        }
    }
    wc_MlDsaKey_Free(&key);
#endif

    WB_NOTE("sign-without-private-key rows exercised");
}
#else
static void wb_sign_no_private(void)
{
    WB_NOTE("pre-hash signing not compiled in this variant; row skipped");
}
#endif

/* `if ((ret == 0) && (id != NULL) && (len != 0))` in wc_MlDsaKey_InitId. */
#ifdef WOLF_PRIVATE_KEY_ID
static void wb_init_id_rows(void)
{
    wc_MlDsaKey key;
    byte        id[4];

    XMEMSET(id, 0x21, sizeof(id));

    /* (T,T,T) -- also the ordinary caller's row. */
    XMEMSET(&key, 0, sizeof(key));
    (void)wc_MlDsaKey_InitId(&key, id, (int)sizeof(id), NULL, INVALID_DEVID);
    wc_MlDsaKey_Free(&key);

    /* (T,F,-): no id supplied. */
    XMEMSET(&key, 0, sizeof(key));
    (void)wc_MlDsaKey_InitId(&key, NULL, 0, NULL, INVALID_DEVID);
    wc_MlDsaKey_Free(&key);

    /* (T,T,F): id supplied but an empty one. */
    XMEMSET(&key, 0, sizeof(key));
    (void)wc_MlDsaKey_InitId(&key, id, 0, NULL, INVALID_DEVID);
    wc_MlDsaKey_Free(&key);

    WB_NOTE("InitId id/len argument rows exercised");
}
#else
static void wb_init_id_rows(void)
{
    WB_NOTE("WOLF_PRIVATE_KEY_ID not set; InitId rows skipped");
}
#endif

/* mldsa_verify_ctx_hash()'s `if ((ret == 0) && (hashLen != digestSize))`: the
 * first operand's FALSE side needs key == NULL, which every public wrapper
 * rejects first. The helper is file-static, so it is called directly. Both
 * arguments after the key are only read once ret is still 0, so the NULL key
 * short-circuits before any dereference. */
#ifndef WOLFSSL_MLDSA_NO_VERIFY
static void wb_verify_ctx_hash_null(void)
{
    byte hash[32];
    byte sig[64];
    int  res = 0;

    XMEMSET(hash, 0x33, sizeof(hash));
    XMEMSET(sig, 0x44, sizeof(sig));

    if (mldsa_verify_ctx_hash(NULL, NULL, 0, (int)WC_HASH_TYPE_SHA256, hash,
            (word32)sizeof(hash), sig, (word32)sizeof(sig), &res) == 0) {
        WB_NOTE("mldsa_verify_ctx_hash accepted a NULL key");
        wb_fail = 1;
    }

    /* The partner row: a real key with a hash length that does NOT match the
     * algorithm's digest size, so the decision is TRUE. A row that is FALSE in
     * both vectors proves nothing about the first operand. */
#ifndef WOLFSSL_MLDSA_NO_MAKE_KEY
    {
        wc_MlDsaKey key;

        XMEMSET(&key, 0, sizeof(key));
        if (wb_build_key(&key) == 0) {
            res = 0;
            if (mldsa_verify_ctx_hash(&key, NULL, 0, (int)WC_HASH_TYPE_SHA256,
                    hash, (word32)sizeof(hash) - 1, sig, (word32)sizeof(sig),
                    &res) == 0) {
                WB_NOTE("mldsa_verify_ctx_hash accepted a short digest");
                wb_fail = 1;
            }
        }
        wc_MlDsaKey_Free(&key);
    }
#endif

    WB_NOTE("mldsa_verify_ctx_hash key/hashLen rows exercised");
}
#else
static void wb_verify_ctx_hash_null(void)
{
    WB_NOTE("verify not compiled in this variant; NULL-key row skipped");
}
#endif

int main(void)
{
    wc_MlDsaKey key;
    word32      sigLen = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("wc_mldsa.c hash-fault white-box supplement\n");

    XMEMSET(s_keySeed, 0xA5, sizeof(s_keySeed));
    XMEMSET(s_sigSeed, 0x5A, sizeof(s_sigSeed));
    XMEMSET(s_msg, 0x42, sizeof(s_msg));
    XMEMSET(s_sig, 0, sizeof(s_sig));
    XMEMSET(&key, 0, sizeof(key));

    mcdc_fh_disarm();
    if (wb_build_key(&key) != 0) {
        WB_NOTE("key setup unavailable in this variant; sweeps skipped");
    }
    else {
#if !defined(WOLFSSL_MLDSA_NO_SIGN)
        sigLen = (word32)sizeof(s_sig);
        if (wc_MlDsaKey_SignCtxWithSeed(&key, NULL, 0, s_sig, &sigLen, s_msg,
                (word32)sizeof(s_msg), s_sigSeed) != 0) {
            sigLen = 0;
        }
#endif
        wb_sweep_sign(&key);
        wb_sweep_verify(&key, sigLen);
    }
    wc_MlDsaKey_Free(&key);

    wb_sweep_makekey();
    wb_sign_no_private();
    wb_init_id_rows();
    wb_verify_ctx_hash_null();

    mcdc_fh_disarm();
    printf("done (%s)\n", wb_fail ? "with failures" : "ok");
    /* A non-zero exit makes the campaign discard this binary's coverage. */
    return 0;
}

#endif /* WOLFSSL_HAVE_MLDSA */
