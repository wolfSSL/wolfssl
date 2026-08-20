/* test_dsa_fault_whitebox.c
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
 * MC/DC fault-injection white-box supplement for wolfcrypt/src/dsa.c.
 *
 * dsa.c's dominant uncovered class is the FALSE half of allocation success
 * chains that only diverge when an EARLIER heap allocation fails, e.g.
 *
 *   wc_MakeDsaParameters:  if (((tmp=XMALLOC(..))==NULL) || ((tmp2=XMALLOC..)==NULL))
 *                          if ((err not MP_INIT_E) && (err not MEMORY_E)) mp_clear(tmp);
 *   wc_DsaSign_ex:         if ((k==NULL)||(kInv==NULL)||...||(buffer==NULL))
 *                          if ((ret not MP_INIT_E) && (ret not MEMORY_E)) mp_forcezero(k);
 *   wc_DsaVerify_ex:       if ((w==NULL)||(u1==NULL)||...||(s==NULL))
 *                          if (ret not MP_INIT_E && ret not MEMORY_E) mp_clear(s);
 *
 * In normal execution every XMALLOC succeeds, so these decisions never take the
 * failure branch. This white-box installs the generic heap-fault injector
 * (mcdc_fault_alloc.h) and sweeps the fail-index across each entry point's
 * allocation sites: for each index exactly one earlier XMALLOC returns NULL,
 * so exactly one operand of the NULL-guard and one MEMORY_E cleanup-guard half
 * are driven per call.
 *
 * These allocation sites only exist under WOLFSSL_SMALL_STACK (the mp_int/byte
 * temporaries are otherwise on the stack), so this supplement is only
 * productive in the small_stack variant; under the other variants it still
 * builds and runs (the sweep simply finds no heap sites to fault and the
 * targets run to completion), which is why it is safe to wire as a normal
 * whitebox entry that every variant compiles.
 *
 * It #includes dsa.c directly (like the other unit-mcdc white-boxes) to reach
 * the file-static CheckDsaLN / _DsaImportParamsRaw and the SMALL_STACK cleanup.
 *
 * Crash-safety: every armed call either returns MEMORY_E before building any
 * mp_int, or fails a deeper allocation whose error the target's own cleanup
 * absorbs (that cleanup is exactly what is under test). The key/params inputs
 * are prepared while DISARMED, and the harness never dereferences a value a
 * faulted call returned. Runs clean under -fsanitize=address.
 *
 * SECOND LEVER -- BIG-INTEGER FAULTS (mcdc_fault_mp.h)
 * ----------------------------------------------------
 * The heap sweep above cannot reach the OTHER half of dsa.c's residuals, the
 * long mp_* success chains:
 *
 *   if (err == MP_OKAY && !mp_iszero(tmp2))            (wc_DsaCheckPubKey)
 *   the init/memory error-code pair guards ...          (MakeDsaParameters)
 *   the same pair on the Sign / Verify cleanup path
 *   if (mp_read_unsigned_bin(r, ..) != MP_OKAY || ..)  (Verify parse)
 *
 * On a healthy machine no mp_* call ever fails, so the `mp_xxx(..) != MP_OKAY`
 * operands are never TRUE and the `err == MP_OKAY` operands are never FALSE --
 * and where the mp_int scratch lives on the stack there is no allocation to
 * fault either. mcdc_fault_mp.h macro-interposes the value-returning mp_* API
 * for this translation unit only (installed before dsa.c is #included), and
 * mcdc_fm_arm(n) makes the n-th mp_* call -- and every later one -- return
 * MP_VAL. Sweeping n therefore drives BOTH operands of each guard from a
 * single pass over each entry point. Predicates (mp_iszero/mp_cmp/...) and
 * teardown (mp_clear/mp_forcezero) are NOT interposed, so cleanup keeps
 * working and every armed call stays crash-safe.
 *
 * Invocation:
 *   ./test_dsa_fault_whitebox            baseline: unarmed valid ops only
 *   ./test_dsa_fault_whitebox sweep      baseline + the fault-index sweeps
 * (Two modes so the injector's contribution can be measured as a delta; the
 * campaign's run_whitebox harness runs it with no args -- pass "sweep" there by
 * default via argv, see the modules.json entry note.)
 */

/* Installed BEFORE dsa.c so its mp_* calls resolve to the fault wrappers --
 * the only lever that can drive dsa.c's `mp_xxx(...) != MP_OKAY` operands TRUE
 * and, downstream of them, its success-code and init-error-code operands
 * FALSE. See the file header. */
#include "mcdc_fault_mp.h"

/* ---- narrow, opt-in mp_init_multi fault -------------------------------
 * mcdc_fault_mp.h leaves mp_init/mp_init_multi alone by default (its
 * MCDC_FM_WITH_INIT block), because dsa.c has three call sites that assign
 * the init result straight into `err` and then run a cleanup that clears
 * objects a failed init never constructed (:147 is safe -- it returns
 * immediately -- but wc_MakeDsaKey :281 and wc_MakeDsaParameters :423 would
 * mp_clear() an uninitialised stack/heap mp_int and segfault).
 *
 * The two entry points below are the exception: wc_DsaSign_ex (:843/:845) and
 * wc_DsaVerify_ex (:1195) MAP a failed init to MP_INIT_E and every one of
 * their cleanup guards test ret against the init and memory error codes
 * precisely so the clear is skipped. Those guards' MP_INIT_E halves are
 * therefore only reachable by failing THEIR init, and doing so is crash-safe.
 *
 * So instead of turning MCDC_FM_WITH_INIT on globally (which would arm the
 * three unsafe sites too), this TU installs its own counter-based interposer
 * and arms it only around Sign / Verify. Same monotone semantics as the
 * shared levers: wb_fmi_arm(n) fails the n-th mp_init_multi and every later
 * one, so exactly one init position is exercised per armed call. */
static long wb_fmi_count   = 0;
static long wb_fmi_fail_at = 0;

static int wb_fm_init_multi(mp_int* a, mp_int* b, mp_int* c, mp_int* d,
                            mp_int* e, mp_int* f)
{
    wb_fmi_count++;
    if ((wb_fmi_fail_at != 0) && (wb_fmi_count >= wb_fmi_fail_at))
        return MP_VAL;
    return mp_init_multi(a, b, c, d, e, f);
}

static void wb_fmi_arm(long n)   { wb_fmi_count = 0; wb_fmi_fail_at = n; }
static void wb_fmi_disarm(void)  { wb_fmi_count = 0; wb_fmi_fail_at = 0; }
static long wb_fmi_seen(void)    { return wb_fmi_count; }

#undef  mp_init_multi
#define mp_init_multi(a, b, c, d, e, f) \
    wb_fm_init_multi((a), (b), (c), (d), (e), (f))

/* ---- narrow, opt-in MEMORY_E fault on mp_prime_is_prime_ex ------------
 * wc_MakeDsaParameters' tmp2 cleanup guard
 *
 *     if ((err not MP_INIT_E) && (err not MEMORY_E)) mp_clear(tmp2);
 *
 * can only take its `err not MEMORY_E` FALSE half with tmp2 ALLOCATED, and the
 * only MEMORY_E the function assigns itself (the tmp/tmp2 XMALLOC guard at
 * :426) is a short-circuit `||`: when it fires, tmp2 is NULL by construction
 * and the guard is never reached. So that half needs a MEMORY_E arriving from
 * DEEPER, after both allocations succeeded.
 *
 * mp_prime_is_prime_ex() at :466 is such a source in the product: the sp_int
 * implementation propagates wc_RNG_GenerateBlock()'s error code VERBATIM out
 * of its Miller-Rabin base draw (wolfcrypt/src/sp_int.c, the `err =
 * wc_RNG_GenerateBlock(rng, (byte*)b->dp, baseSz); if (err != MP_OKAY) break;`
 * in sp_prime_is_prime_ex), and wc_RNG_GenerateBlock returns MEMORY_E when its
 * own WOLFSSL_SMALL_STACK scratch allocation fails. Injecting MEMORY_E here is
 * therefore the same value the real code path produces, just without having to
 * guess which of the several hundred allocations inside a 1024-bit parameter
 * generation is the DRBG's (an index-walk that far in is neither cheap nor
 * stable across builds).
 *
 * One-shot, and armed only around a dedicated wc_MakeDsaParameters call, so
 * nothing else in the file sees it. dsa.c has exactly one direct call site. */
static int wb_pip_mem = 0;

static int wb_fm_prime_is_prime_ex(const mp_int* a, int t, int* result,
                                   WC_RNG* rng)
{
    if (wb_pip_mem) {
        wb_pip_mem = 0;
        return MEMORY_E;
    }
    return mp_prime_is_prime_ex(MCDC_FM_MI(a), t, result, rng);
}

#undef  mp_prime_is_prime_ex
#define mp_prime_is_prime_ex(a, t, r, g) \
    wb_fm_prime_is_prime_ex((a), (t), (r), (g))

#include <wolfcrypt/src/dsa.c>

#include "mcdc_fault_alloc.h"
#include <time.h>

#include <wolfssl/wolfcrypt/random.h>
#include <stdio.h>
#include <string.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(NO_DSA) || !defined(WOLFSSL_KEY_GEN)

int main(void)
{
    printf("dsa.c fault white-box: NO_DSA or !WOLFSSL_KEY_GEN, nothing to do\n");
    return 0;
}

#else

/* [mod = L=1024, N=160], from CAVP KeyPair (same vector as tests/api). */
static const char* kP =
    "d38311e2cd388c3ed698e82fdf88eb92b5a9a483dc88005d"
    "4b725ef341eabb47cf8a7a8a41e792a156b7ce97206c4f9c"
    "5ce6fc5ae7912102b6b502e59050b5b21ce263dddb2044b6"
    "52236f4d42ab4b5d6aa73189cef1ace778d7845a5c1c1c71"
    "47123188f8dc551054ee162b634d60f097f719076640e209"
    "80a0093113a8bd73";
static const char* kQ = "96c5390a8b612c0e422bb2b0ea194a3ec935a281";
static const char* kG =
    "06b7861abbd35cc89e79c52f68d20875389b127361ca66822"
    "138ce4991d2b862259d6b4548a6495b195aa0e0b6137ca37e"
    "b23b94074d3c3d300042bdf15762812b6333ef7b07ceba786"
    "07610fcc9ee68491dbc1e34cd12615474e52b18bc934fb00c"
    "61d39e7da8902291c4434a4e2224c3f4fd9f93cd6f4f17fc0"
    "76341a7e7d9";

/* Build a fully populated (params + x/y) DSA key. Must be called DISARMED. */
/* The sweeps below are already capped deterministically by WB_MP_MAX. The wall
 * clock is a second, load-dependent truncation on top of that: if it fires
 * first, the sweep is shorter on a busy machine than on an idle one and the
 * same source measures differently run to run (proved on wc_lms_impl.c,
 * 2026-08-11). Keep it as a backstop against TEST_TIMEOUT, but make it say so,
 * so a load-dependent result is never mistaken for a stable one. */
static int wb_mp_backstop = 0;

static int wb_mp_over(int elapsed)
{
    if (elapsed && !wb_mp_backstop) {
        wb_mp_backstop = 1;
        printf("  [wb] WALL-CLOCK BACKSTOP truncated the sweep before "
               "WB_MP_MAX -- coverage is load-dependent for this run\n");
    }
    return elapsed;
}

/* kQ with its last hex digit changed (1 -> 3). Still > 1 and still 160 bits,
 * so wc_DsaCheckPubKey's p/q/g/y range guards all pass, but it no longer
 * divides p-1 -- the ONE input shape that makes (p-1) mod q non-zero at
 * dsa.c:161. */
static const char* kQnotDivisor =
    "96c5390a8b612c0e422bb2b0ea194a3ec935a283";

static int build_key(DsaKey* key, WC_RNG* rng)
{
    int ret = wc_InitDsaKey(key);
    if (ret == 0)
        ret = wc_DsaImportParamsRaw(key, kP, kQ, kG);
    if (ret == 0)
        ret = wc_MakeDsaKey(rng, key);
    return ret;
}

/* --------------------------------------------------------------------------
 * CRAFTED-INPUT VECTORS
 * --------------------------------------------------------------------------
 * The fault levers below can only break a success chain; they cannot produce
 * an input that is well-formed enough to reach a validation guard yet wrong in
 * exactly the way that guard tests. dsa.c's remaining residuals are mostly of
 * that second kind -- "q does not divide p-1", "q is negative", "r came out
 * zero", "the caller passed x=NULL but y!=NULL" -- so each one below is a
 * hand-built argument/key/signature that makes exactly one operand flip while
 * its neighbours stay at the value the all-false baseline already recorded.
 *
 * Everything here runs DISARMED (both injectors) and every destructive edit is
 * confined to a scratch DsaKey built for that vector alone; the shared `key`
 * used by the sweeps is never mutated.
 * ------------------------------------------------------------------------ */
static void wb_crafted(WC_RNG* rng, DsaKey* key, const byte* digest,
                       word32 digestSz)
{
    byte  bufA[256], bufB[256];
    word32 szA, szB, szC;
    int   ret;

    mcdc_fa_disarm();
    mcdc_fm_disarm();
    wb_fmi_disarm();

    /* ---- CheckDsaLN (file-static; every public caller pre-computes the
     * (L,N) pair from a real key, so only these direct calls can drive the
     * modLen==2048 arm's two divLen operands independently). 204 idx0/idx1. */
    (void)CheckDsaLN(2048, 224);   /* (T,-)  -> ret 0            */
    (void)CheckDsaLN(2048, 256);   /* (F,T)  -> ret 0            */
    (void)CheckDsaLN(2048, 160);   /* (F,F)  -> ret -1           */

#ifndef NO_DSA_PUBKEY_CHECK
    /* ---- wc_DsaCheckPubKey with a q that does NOT divide p-1: the only way
     * to reach 161 with err==MP_OKAY AND a non-zero remainder, i.e. the (T,T)
     * vector both of that decision's operands need (the mp sweep supplies the
     * (F,-) half, the good key supplies (T,F)). */
    {
        DsaKey bad;
        XMEMSET(&bad, 0, sizeof(bad));
        if (wc_InitDsaKey(&bad) == 0) {
            if ((mp_read_radix(&bad.p, kP, MP_RADIX_HEX) == MP_OKAY) &&
                (mp_read_radix(&bad.q, kQnotDivisor, MP_RADIX_HEX)
                     == MP_OKAY) &&
                (mp_read_radix(&bad.g, kG, MP_RADIX_HEX) == MP_OKAY) &&
                /* y only has to satisfy 1 < y < p to get past the range
                 * guards; g qualifies and saves a second constant. */
                (mp_read_radix(&bad.y, kG, MP_RADIX_HEX) == MP_OKAY)) {
                ret = wc_DsaCheckPubKey(&bad);
                if (ret == 0)
                    WB_NOTE("UNEXPECTED: q-not-divisor key accepted");
            }
            wc_FreeDsaKey(&bad);
        }
    }
#endif

    /* ---- wc_MakeDsaParameters reached with err != MP_OKAY. 518's `err !=
     * MP_OKAY` operand is only FALSE-able from a successful run (the baseline
     * call) and TRUE-able from a failed one; nothing in the normal campaign
     * ever fails it, and the heap sweep cannot (see the MakeDsaParameters note
     * further down). One armed mp step is enough and stops before the
     * expensive prime search: index 1 is mp_read_unsigned_bin at :426, index 2
     * is mp_rand_prime at :430. mp_init_multi at :423 has already run in both
     * cases, so every mp_int the cleanup clears is constructed. */
    {
        long n;
        for (n = 1; n <= 2; n++) {
            DsaKey pk;
            XMEMSET(&pk, 0, sizeof(pk));
            if (wc_InitDsaKey(&pk) == 0) {
                mcdc_fm_arm(n);
                (void)wc_MakeDsaParameters(rng, 1024, &pk);
                mcdc_fm_disarm();
                wc_FreeDsaKey(&pk);
            }
        }
    }

    /* ---- KEY-GENERATION MP_INIT_E cleanup halves: wc_MakeDsaKey 332 idx1
     * and wc_MakeDsaParameters 520 idx0 / 526 idx0 / 537 idx1.
     *
     * These were dead until wolfcrypt commit 1e8807b13. Neither key-generation
     * entry point mapped a failed mp_init_multi() to MP_INIT_E -- mp_init_multi
     * reports the BACKEND's code (MP_MEM from the heap backends) -- so
     * wc_MakeDsaParameters' "err not MP_INIT_E" guards could never fire and
     * wc_MakeDsaKey had no guard at all and ran mp_clear(tmpQ) on never-
     * initialised storage (the SIGSEGV recorded in DEATHNOTE.md). Both sites
     * now use the idiom wc_DsaSign_ex/wc_DsaVerify_ex already used, so failing
     * THEIR mp_init_multi is the way into these halves and is crash-safe: the
     * guards exist precisely to skip the clears.
     *
     * Each entry point performs exactly one mp_init_multi and it is the first
     * one of the call (nothing ahead of it initialises an mp_int), so index 1
     * selects it in both cases. The accepting halves of the same guards come
     * from the unarmed key/parameter generation in main(). */
    {
        DsaKey ik;
        XMEMSET(&ik, 0, sizeof(ik));
        if (wc_InitDsaKey(&ik) == 0) {
            if (wc_DsaImportParamsRaw(&ik, kP, kQ, kG) == 0) {
                wb_fmi_arm(1);
                ret = wc_MakeDsaKey(rng, &ik);
                wb_fmi_disarm();
                if (ret != WC_NO_ERR_TRACE(MP_INIT_E))
                    printf("  [wb] MakeDsaKey init fault returned %d, not "
                           "MP_INIT_E: 332 idx1 NOT driven\n", ret);
            }
            wc_FreeDsaKey(&ik);
        }
    }
    {
        DsaKey pk;
        XMEMSET(&pk, 0, sizeof(pk));
        if (wc_InitDsaKey(&pk) == 0) {
            wb_fmi_arm(1);
            ret = wc_MakeDsaParameters(rng, 1024, &pk);
            wb_fmi_disarm();
            if (ret != WC_NO_ERR_TRACE(MP_INIT_E))
                printf("  [wb] MakeDsaParameters init fault returned %d, not "
                       "MP_INIT_E: 520/526/537 NOT driven\n", ret);
            wc_FreeDsaKey(&pk);
        }
    }

    /* ---- wc_MakeDsaParameters 526 idx1 (`err not MEMORY_E` FALSE with tmp2
     * allocated). The function's OWN MEMORY_E (:426) is a short-circuit `||`
     * over the tmp/tmp2 XMALLOCs, so whenever it fires tmp2 is NULL and the
     * `if (tmp2 != NULL)` gate above 526 skips the guard entirely -- that path
     * closes 520 idx1 (tmp allocated, tmp2 not) and can never close 526 idx1.
     * The vector needs a MEMORY_E raised AFTER both allocations succeeded;
     * mp_prime_is_prime_ex is such a source in the product (see the
     * wb_fm_prime_is_prime_ex note). One-shot, fires on dsa.c's single direct
     * call site at :466. */
    {
        DsaKey pk;
        XMEMSET(&pk, 0, sizeof(pk));
        if (wc_InitDsaKey(&pk) == 0) {
            wb_pip_mem = 1;
            ret = wc_MakeDsaParameters(rng, 1024, &pk);
            wb_pip_mem = 0;
            if (ret != WC_NO_ERR_TRACE(MEMORY_E))
                printf("  [wb] MakeDsaParameters MEMORY_E fault returned %d: "
                       "526 idx1 NOT driven\n", ret);
            wc_FreeDsaKey(&pk);
        }
    }

    /* ---- _DsaImportParamsRaw with trusted == 0: the (T,T) vector of
     * `err == MP_OKAY && !trusted` at :540. wc_DsaImportParamsRaw (used
     * everywhere else, including by the sweeps) hard-codes trusted = 1, so
     * only the ...RawCheck entry point can drive it. Runs one 1024-bit
     * Miller-Rabin pass; deterministic given a fixed p. */
    {
        DsaKey ck;
        XMEMSET(&ck, 0, sizeof(ck));
        if (wc_InitDsaKey(&ck) == 0) {
            (void)wc_DsaImportParamsRawCheck(&ck, kP, kQ, kG, 0, rng);
            wc_FreeDsaKey(&ck);
        }
    }

    /* ---- wc_DsaExportParamsRaw / wc_DsaExportKeyRaw argument shapes.
     * MC/DC is judged per BINARY, so each decision's whole vector set has to
     * be present here even when the tests/api lane already covers some rows:
     *   658 idx2 : (T,T,T) all-NULL length query  vs (T,T,F) g non-NULL
     *   733 idx1 : (T,T) all-NULL length query    vs (T,F) y non-NULL
     *   739 idx0 : (T,-) from that x-NULL call    vs (F,F) a real export
     * The (T,T,F)/(T,F) rows are the ones no ordinary caller produces. */
    szA = szB = szC = (word32)sizeof(bufA);
    (void)wc_DsaExportParamsRaw(key, NULL, &szA, NULL, &szB, NULL, &szC);
    szA = szB = szC = (word32)sizeof(bufA);
    (void)wc_DsaExportParamsRaw(key, NULL, &szA, NULL, &szB, bufA, &szC);

    szA = szB = (word32)sizeof(bufA);
    (void)wc_DsaExportKeyRaw(key, NULL, &szA, NULL, &szB);
    szA = szB = (word32)sizeof(bufA);
    (void)wc_DsaExportKeyRaw(key, NULL, &szA, bufB, &szB);
    szA = szB = (word32)sizeof(bufA);
    (void)wc_DsaExportKeyRaw(key, bufA, &szA, bufB, &szB);

    /* ---- wc_DsaSign_ex with a NEGATIVE q: 887's `mp_isneg(qMinus1)` operand
     * is unreachable from any non-negative q (q-1 is then zero or positive,
     * and q==0 exits earlier at the halfSz==0 guard because
     * mp_unsigned_bin_size(0) is 0). Negating q keeps |q| 20 bytes so halfSz
     * stays 20 and execution reaches 887 with q-1 = -(q+1): non-zero AND
     * negative, i.e. the (F,T) vector.
     *
     * Whether a math backend represents negatives at all is a build property
     * (sp_int only carries a sign field under WOLFSSL_SP_INT_NEGATIVE), so the
     * negation is checked at run time and the vector skipped when the backend
     * saturates at zero -- a build-determined, not load-determined, choice. */
    {
        DsaKey nk;
        mp_int  zero[1];
        mp_int  neg[1];
        XMEMSET(&nk, 0, sizeof(nk));
        XMEMSET(zero, 0, sizeof(zero));
        XMEMSET(neg, 0, sizeof(neg));
        if (wc_InitDsaKey(&nk) == 0) {
            if ((wc_DsaImportParamsRaw(&nk, kP, kQ, kG) == 0) &&
                (mp_init_multi(zero, neg, NULL, NULL, NULL, NULL) == MP_OKAY)) {
                /* distinct destination: aliasing the result over an input of
                 * mp_sub is not guaranteed across the three math backends. */
                int e1 = mp_set(zero, 0);
                int e2 = (e1 == MP_OKAY) ? mp_sub(zero, &nk.q, neg) : e1;
                if ((e2 == MP_OKAY) && mp_isneg(neg) && !mp_iszero(neg) &&
                    (mp_copy(neg, &nk.q) == MP_OKAY) && mp_isneg(&nk.q)) {
                    byte sigN[DSA_MAX_HALF_SIZE * 2];
                    XMEMSET(sigN, 0, sizeof(sigN));
                    (void)wc_DsaSign_ex(digest, digestSz, sigN, &nk, rng);
                }
                else {
                    /* Expected for every WOLFSSL_SP_INT_NEGATIVE-less build:
                     * sp_int.h then #defines sp_isneg(a) to the constant (0),
                     * so 906's second operand cannot be TRUE there at all --
                     * which is exactly why the module carries an
                     * `sp_negative` variant (-DWOLFSSL_SP_INT_NEGATIVE), the
                     * one build in which this vector is productive. */
                    printf("  [wb] no negative mp_int (set=%d sub=%d neg=%d "
                           "zero=%d): 906 idx1 needs the sp_negative "
                           "variant\n",
                           e1, e2, (int)mp_isneg(neg), (int)mp_iszero(neg));
                }
                mp_clear(neg);
                mp_clear(zero);
            }
            wc_FreeDsaKey(&nk);
        }
    }

    /* ---- wc_DsaSign_ex zero-r / zero-s: 1050's two operands. wc_DsaSign_ex
     * does NOT validate the key (only wc_DsaVerify_ex does), so a params-only
     * key -- x and y still zero from wc_InitDsaKey -- is accepted:
     *   x == 0 and an all-zero digest  => H == 0, s = (H + x.r)/k == 0 with r
     *                                     non-zero              -> (F,T)
     *   g == 0                          => r = 0^k mod p mod q == 0 -> (T,-)
     * Both are the same scratch key, edited in place between the two calls. */
    {
        DsaKey zk;
        XMEMSET(&zk, 0, sizeof(zk));
        if (wc_InitDsaKey(&zk) == 0) {
            if (wc_DsaImportParamsRaw(&zk, kP, kQ, kG) == 0) {
                byte zdig[WC_SHA_DIGEST_SIZE];
                byte sigZ[DSA_MAX_HALF_SIZE * 2];
                XMEMSET(zdig, 0, sizeof(zdig));
                XMEMSET(sigZ, 0, sizeof(sigZ));
                (void)wc_DsaSign_ex(zdig, sizeof(zdig), sigZ, &zk, rng);
                if (mp_set(&zk.g, 0) == MP_OKAY) {
                    XMEMSET(sigZ, 0, sizeof(sigZ));
                    (void)wc_DsaSign_ex(digest, digestSz, sigZ, &zk, rng);
                }
            }
            wc_FreeDsaKey(&zk);
        }
    }

    /* ---- wc_DsaVerify_ex signature sanity check at 1214: four operands, each
     * needing one crafted 2*qSz signature that trips exactly it while the
     * earlier ones stay FALSE. The good key's q is 160 bits, so 0xff.. is
     * >= q and 0x00..01 is a valid non-zero value below it. The valid-
     * signature call in the baseline supplies the all-FALSE row. */
    {
        int    qSz = mp_unsigned_bin_size(&key->q);
        if ((qSz > 0) && ((size_t)(2 * qSz) <= sizeof(bufA))) {
            int    a = 0;
            int    v;
            /* [0]=r zero, [1]=s zero, [2]=r >= q, [3]=s >= q */
            for (v = 0; v < 4; v++) {
                XMEMSET(bufA, 0, (size_t)(2 * qSz));
                /* default both halves to a valid non-zero value < q */
                bufA[qSz - 1]     = 0x01;
                bufA[2 * qSz - 1] = 0x01;
                switch (v) {
                    case 0: bufA[qSz - 1] = 0x00; break;
                    case 1: bufA[2 * qSz - 1] = 0x00; break;
                    case 2: XMEMSET(bufA, 0xff, (size_t)qSz); break;
                    default: XMEMSET(bufA + qSz, 0xff, (size_t)qSz); break;
                }
                (void)wc_DsaVerify_ex(digest, digestSz, bufA, key, &a);
            }
        }
    }

    /* ---- MP_INIT_E cleanup halves (Sign 1068/1074/1080/1086/1092/1099,
     * Verify 1274/1279/1284/1289/1294/1299). See the wb_fm_init_multi note:
     * these two entry points map a failed mp_init_multi to MP_INIT_E and their
     * cleanups deliberately skip the clear in that case, so failing THEIR init
     * is both the only way in and crash-safe.
     *
     * Sign's init is the first one it performs, so index 1. Verify's is the
     * LAST one it performs (wc_DsaCheckPubKey runs first and does its own), so
     * the index is measured with a disarmed call instead of hard-coded -- that
     * keeps the vector correct under NO_DSA_PUBKEY_CHECK too. */
    {
        byte sigI[DSA_MAX_HALF_SIZE * 2];
        int  a = 0;
        long inits;

        XMEMSET(sigI, 0, sizeof(sigI));
        wb_fmi_arm(1);
        (void)wc_DsaSign_ex(digest, digestSz, sigI, key, rng);
        wb_fmi_disarm();

        /* count, disarmed, then re-run failing the last init seen */
        wb_fmi_arm(0);
        (void)wc_DsaVerify_ex(digest, digestSz, sigI, key, &a);
        inits = wb_fmi_seen();
        wb_fmi_disarm();
        if (inits > 0) {
            wb_fmi_arm(inits);
            (void)wc_DsaVerify_ex(digest, digestSz, sigI, key, &a);
            wb_fmi_disarm();
        }
    }

    /* ---- wc_MakeDsaParameters tmp/tmp2 heap guard at 415 (WOLFSSL_SMALL_STACK
     * only). A plain fail-index sweep cannot reach it: buf is allocation #1 but
     * the wc_RNG_GenerateBlock at :400 sits between buf and tmp and performs a
     * build-dependent number of allocations of its own, so every index in that
     * band returns the RNG's error and masks the MEMORY_E under test.
     *
     * Self-calibrate instead of guessing the offset: walk the index upward and
     * watch the RETURN CODE. Below tmp the call dies inside the RNG with some
     * other error; the first index that yields MEMORY_E past index 1 is tmp
     * (415 idx0 TRUE), and the next one is tmp2 (415 idx0 FALSE, idx1 TRUE,
     * and -- since tmp is then non-NULL -- the only vector that reaches 501
     * with err set to the memory error, closing 501 idx1). Every armed call
     * aborts before
     * mp_rand_prime, so the walk is cheap.
     *
     * Bounded by a vector COUNT, never by a clock: a fixed six-vector window
     * around the measured offset, so two sweeps of an unchanged tree fire the
     * same calls in the same order. */
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC) && \
    !defined(MCDC_FA_UNAVAILABLE)
    {
        /* The RETURN CODE says which allocation was hit, so the offset does
         * not have to be predicted: anything faulted inside
         * wc_RNG_GenerateBlock surfaces as the RNG's own failure code, while
         * only buf (#1), tmp and tmp2 yield MEMORY_E. Starting at #2 (past
         * buf), the first MEMORY_E is tmp -- 415 idx0 TRUE -- and the second is
         * tmp2 -- 415 idx0 FALSE + idx1 TRUE, and the only vector that reaches
         * 501 with err set to the memory error, since tmp is non-NULL only there.
         *
         * Every armed call in the walk aborts before mp_rand_prime, so the
         * whole thing is cheap. Bound is a fixed vector COUNT (never a clock):
         * at most WB_MDP_CAP calls, stopping as soon as the pair is seen. */
        /* Each armed call gets its OWN WC_RNG, built while disarmed. Faulting
         * an allocation inside wc_RNG_GenerateBlock leaves the Hash_DRBG in
         * its permanent DRBG_FAILED state, so a shared generator would answer
         * RNG_FAILURE_E to every later index and the walk would never get past
         * the RNG band (observed: every index 2..96 returning -199). */
#define WB_MDP_CAP 96
        int n, hits = 0;

        for (n = 2; (n <= WB_MDP_CAP) && (hits < 2); n++) {
            DsaKey pk;
            WC_RNG lrng;
            int    r2;
            XMEMSET(&pk, 0, sizeof(pk));
            XMEMSET(&lrng, 0, sizeof(lrng));
            if (wc_InitRng(&lrng) != 0)
                break;
            if (wc_InitDsaKey(&pk) != 0) {
                wc_FreeRng(&lrng);
                break;
            }
            mcdc_fa_arm(n);
            r2 = wc_MakeDsaParameters(&lrng, 1024, &pk);
            mcdc_fa_disarm();
            wc_FreeDsaKey(&pk);
            wc_FreeRng(&lrng);
            if (r2 == WC_NO_ERR_TRACE(MEMORY_E))
                hits++;
            else if (hits > 0)
                break;      /* walked past the adjacent tmp/tmp2 pair */
        }
        printf("  [wb] MakeDsaParameters heap walk: %d/2 MEMORY_E positions"
               " in %d vectors\n", hits, n - 2);
    }
#endif

    /* ---- wc_DsaVerify_ex 1274 idx1 (the memory-error operand FALSE). See
     * mcdc_fa_arm_only() note in mcdc_fault_alloc.h: s is the LAST of the six
     * temporaries, so a monotone fail-from-n can never leave s non-NULL while
     * ret is MEMORY_E, and `if (s)` gates the decision. A one-shot fault on
     * verify's FIRST temporary (w) gives exactly that vector.
     *
     * Verify's own allocations start after wc_DsaCheckPubKey's, so the offset
     * is measured rather than assumed: arm past any plausible count, run the
     * pubkey check alone, and read the counter. That count is RNG-free and
     * therefore identical on every run of the same build. */
#if defined(WOLFSSL_SMALL_STACK) && !defined(MCDC_FA_UNAVAILABLE)
    {
        unsigned long checkAllocs = 0;
        int a = 0;
        int i;
#ifndef NO_DSA_PUBKEY_CHECK
        mcdc_fa_arm(1000000);
        (void)wc_DsaCheckPubKey(key);
        checkAllocs = mcdc_fa_count;
        mcdc_fa_disarm();
#endif
        /* w u1 u2 v r are all "not s"; failing any one of them reaches 1274
         * with s allocated. Six vectors bracket the boundary by one. */
        for (i = 0; i < 6; i++) {
            mcdc_fa_arm_only((int)checkAllocs + 1 + i);
            (void)wc_DsaVerify_ex(digest, digestSz, bufB, key, &a);
            mcdc_fa_disarm();
        }
    }
#endif

    WB_NOTE("crafted-input vectors done");
    (void)ret;
}

int main(int argc, char** argv)
{
    /* Default action is the fault sweep so the campaign's run_whitebox harness
     * (which runs this binary with NO arguments) gets full coverage. Pass
     * "baseline" to run only the unarmed valid ops (used to measure the
     * injector's contribution as a delta), or "probe" to print the
     * per-entry-point allocation counts used to size each sweep. */
    int      do_sweep = !(argc > 1 && strcmp(argv[1], "baseline") == 0);
    WC_RNG   rng;
    DsaKey   key;
    byte     digest[WC_SHA_DIGEST_SIZE];
    byte     sig[256];
    int      answer = 0;
    int      n;
    int      ret;

    /* Unbuffered: if an armed call ever crashes, the notes printed so far
     * must survive to say WHICH sweep it died in. */
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("dsa.c fault white-box (%s)\n",
           (argc > 1 && strcmp(argv[1], "baseline") == 0) ? "baseline" : "sweep");

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(digest, 0x2b, sizeof(digest));
    XMEMSET(sig, 0, sizeof(sig));

    if (wc_InitRng(&rng) != 0) {
        printf("  wc_InitRng failed; skipping\n");
        return 0;
    }

    mcdc_fa_install();

    /* ---- baseline: unarmed valid operations (all-false NULL guards, the
     *      err==MP_OKAY true chains, and MP_OKAY cleanup halves). ---- */
    ret = build_key(&key, &rng);
    if (ret != 0) {
        printf("  build_key failed (%d); skipping\n", ret);
        mcdc_fa_restore();
        wc_FreeRng(&rng);
        return 0;
    }
    (void)wc_DsaSign_ex(digest, sizeof(digest), sig, &key, &rng);
    (void)wc_DsaVerify_ex(digest, sizeof(digest), sig, &key, &answer);

#ifndef MCDC_FA_UNAVAILABLE
    if (argc > 1 && strcmp(argv[1], "probe") == 0) {
        /* Diagnostic: count the allocations each entry point performs, WITHOUT
         * failing any (arm a huge index so the counter advances but never
         * trips). Use these counts to choose each sweep's K -- see the header
         * and the campaign fan-out recipe. Exits without sweeping. */
        int a = 0;
        byte s2[256]; XMEMSET(s2, 0, sizeof(s2));
        mcdc_fa_arm(1000000);
        (void)wc_DsaSign_ex(digest, sizeof(digest), s2, &key, &rng);
        printf("  PROBE sign allocs     = %lu\n", mcdc_fa_count);
        mcdc_fa_arm(1000000);
        (void)wc_DsaVerify_ex(digest, sizeof(digest), sig, &key, &a);
        printf("  PROBE verify allocs   = %lu\n", mcdc_fa_count);
#ifndef NO_DSA_PUBKEY_CHECK
        mcdc_fa_arm(1000000);
        (void)wc_DsaCheckPubKey(&key);
        printf("  PROBE checkpub allocs = %lu\n", mcdc_fa_count);
#endif
        mcdc_fa_disarm();
        mcdc_fa_restore();
        wc_FreeDsaKey(&key);
        wc_FreeRng(&rng);
        return 0;
    }
#endif
#ifndef NO_DSA_PUBKEY_CHECK
    (void)wc_DsaCheckPubKey(&key);
#endif
    {
        /* one real parameter generation for baseline body coverage */
        DsaKey pk;
        if (wc_InitDsaKey(&pk) == 0) {
            (void)wc_MakeDsaParameters(&rng, 1024, &pk);
            wc_FreeDsaKey(&pk);
        }
    }

    /* Crafted-input vectors: independent of the injectors (they run disarmed),
     * so they belong to BOTH modes -- the "baseline" mode still has to compile
     * and execute them or the delta measurement would attribute their wins to
     * the fault levers. */
    wb_crafted(&rng, &key, digest, (word32)sizeof(digest));

    if (do_sweep) {
        /* --- wc_DsaSign_ex: 6-7 XMALLOCs up front (k,kInv,r,s,H,[b],buffer),
         * ALL before any mp op, so fail-index n selects exactly the n-th temp
         * (nothing allocates ahead of them). Drives the 816 NULL-guard operands
         * (n=1..7) and the 1048..1079 MEMORY_E cleanup halves (n=2..7). Sign
         * does not mutate the key, so the key is reused. K=40 over-sweeps into
         * the deeper mp allocations (harmless, closes nothing new). --- */
        for (n = 1; n <= 40; n++) {
            byte sig2[256];
            XMEMSET(sig2, 0, sizeof(sig2));
            mcdc_fa_arm(n);
            (void)wc_DsaSign_ex(digest, sizeof(digest), sig2, &key, &rng);
            mcdc_fa_disarm();
        }

        /* --- wc_DsaVerify_ex: begins with wc_DsaCheckPubKey (deterministic
         * ~777 exptmod-scratch allocations for this fixed key -- no RNG, so the
         * count is stable), THEN its own w,u1,u2,v,r,s XMALLOCs. The pubkey
         * check shifts verify's temps to indices ~778..783, so a naive small
         * sweep never reaches them. K=820 covers past that window: low indices
         * fault the pubkey check, the ~778..783 band faults verify's own temps
         * -> the 1154 NULL-guard operands and 1249..1269 MEMORY_E cleanup
         * halves. sig holds the valid baseline signature. --- */
        for (n = 1; n <= 820; n++) {
            int a = 0;
            mcdc_fa_arm(n);
            (void)wc_DsaVerify_ex(digest, sizeof(digest), sig, &key, &a);
            mcdc_fa_disarm();
        }

#ifndef NO_DSA_PUBKEY_CHECK
        /* --- wc_DsaCheckPubKey standalone: same ~777-deep allocation space;
         * sweep it fully to drive the 137/140 MEMORY_E returns and, where a
         * deeper mp step's scratch fails, the 161 err!=MP_OKAY half. --- */
        for (n = 1; n <= 800; n++) {
            mcdc_fa_arm(n);
            (void)wc_DsaCheckPubKey(&key);
            mcdc_fa_disarm();
        }
#endif

        /* --- wc_MakeDsaParameters: NOT swept. Its buf(#1) is faultable but
         * that guard is single-condition (not MC/DC). Its tmp/tmp2 XMALLOCs
         * (line 403) sit AFTER the first wc_RNG_GenerateBlock (line 388), which
         * under WOLFSSL_SMALL_STACK performs a large, RNG-state-dependent
         * number of heap allocations; every fail-index that would reach tmp
         * instead lands in an RNG allocation and returns RNG_FAILURE_E, masking
         * the tmp/tmp2 MEMORY_E. The 403/489/495/506 residuals are therefore
         * not closable with a pass-through fault allocator (they would need a
         * non-allocating RNG mock or WOLFSSL_SP_NO_MALLOC) and stay justified.
         * A token n=1 confirms the buf guard is reachable. --- */
        {
            DsaKey pk;
            if (wc_InitDsaKey(&pk) == 0) {
                mcdc_fa_arm(1);
                (void)wc_MakeDsaParameters(&rng, 1024, &pk);
                mcdc_fa_disarm();
                wc_FreeDsaKey(&pk);
            }
        }
        WB_NOTE("fault-index sweeps over Sign / Verify / CheckPubKey done");

        /* ---- big-integer fault sweeps (mcdc_fault_mp.h) ----------------
         * Each entry point is run once DISARMED (the all-true baseline row
         * for every guard, in THIS binary, and the sweep length K), then the
         * fail index is swept over [1..K]. Inputs are always prepared while
         * disarmed and none of these entry points mutates the key, so every
         * armed call starts from the same known-good state. */
        {
            time_t t0 = time(NULL);
            long   k, i;
            int    a = 0;

#define WB_MP_MAX      400
#define WB_MP_DEADLINE 120
#define WB_MP_EXPIRED() wb_mp_over(difftime(time(NULL), t0) > (double)WB_MP_DEADLINE)
#define WB_MP_SWEEP(lbl, ...)                                            \
    do {                                                                  \
        mcdc_fm_disarm();                                                 \
        { __VA_ARGS__; }                                                  \
        k = mcdc_fm_seen();                                               \
        if (k > WB_MP_MAX)                                                \
            k = WB_MP_MAX;                                                \
        for (i = 1; (i <= k) && !WB_MP_EXPIRED(); i++) {                  \
            mcdc_fm_arm(i);                                               \
            { __VA_ARGS__; }                                              \
            mcdc_fm_disarm();                                             \
        }                                                                 \
        printf("  [wb] mp sweep %s: K=%ld\n", (lbl), k);                  \
    } while (0)

            {
                byte sig2[256];
                XMEMSET(sig2, 0, sizeof(sig2));
                WB_MP_SWEEP("DsaSign_ex",
                    (void)wc_DsaSign_ex(digest, sizeof(digest), sig2, &key,
                        &rng));
            }
            WB_MP_SWEEP("DsaVerify_ex",
                (void)wc_DsaVerify_ex(digest, sizeof(digest), sig, &key, &a));
#ifndef NO_DSA_PUBKEY_CHECK
            WB_MP_SWEEP("DsaCheckPubKey", (void)wc_DsaCheckPubKey(&key));
#endif
            /* Import parses p/q/g through mp_read_radix; a fresh key each
             * time because import populates it. */
            {
                DsaKey ik;
                WB_MP_SWEEP("DsaImportParamsRaw",
                    if (wc_InitDsaKey(&ik) == 0) {
                        (void)wc_DsaImportParamsRaw(&ik, kP, kQ, kG);
                        wc_FreeDsaKey(&ik);
                    });
            }
            /* Key generation from valid parameters: mp_rand_prime-free, so
             * the sweep lands squarely in the exptmod/mod chain. */
            {
                DsaKey mk;
                WB_MP_SWEEP("MakeDsaKey",
                    if (wc_InitDsaKey(&mk) == 0) {
                        if (wc_DsaImportParamsRaw(&mk, kP, kQ, kG) == 0)
                            (void)wc_MakeDsaKey(&rng, &mk);
                        wc_FreeDsaKey(&mk);
                    });
            }
            mcdc_fm_disarm();
            WB_NOTE("big-integer fault sweeps done");
        }
    }

    mcdc_fa_disarm();
    mcdc_fa_restore();
    mcdc_fm_disarm();
    wc_FreeDsaKey(&key);
    wc_FreeRng(&rng);

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    (void)wb_fail;
    return 0;
}

#endif /* !NO_DSA && WOLFSSL_KEY_GEN */
