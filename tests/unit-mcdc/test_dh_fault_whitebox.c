/* test_dh_fault_whitebox.c
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
 * MC/DC white-box supplement for wolfcrypt/src/dh.c.
 *
 * dh.c's dominant uncovered class is NOT allocator-failure (unlike hpke.c/
 * dsa.c): every math backend call here (mp_init/mp_copy/mp_sub_d/mp_set on a
 * file-static, full-capacity sp_int) is a cross-TU call into sp_int.c, and
 * mcdc_fault_alloc.h's XMALLOC hook only reaches allocations made BY dh.c
 * itself (see its header comment) - it cannot fail an sp_int.c internal
 * allocation, and under this suite's math backend (WOLFSSL_SP_MATH_ALL,
 * SP_INT_BITS=4096, fixed-size sp_int, no heap growth) most of those calls
 * cannot fail at all except on a NULL argument that can never be NULL here.
 * This file therefore does not use mcdc_fault_alloc.h; instead it drives the
 * "ret == 0 && <call>" / "<call> == NULL" chains with three techniques,
 * each verified against a standalone reproduction before use here:
 *
 *   (a) NULL/argument-guard rows: direct calls with one pointer NULL at a
 *       time (ordinary black-box testing of an OR-guard).
 *   (b) size-capacity rows: sp_int is a fixed SP_INT_DIGITS-digit struct
 *       (SP_INT_BITS=4096 here); mp_read_unsigned_bin()/sp_exptmod() reject
 *       inputs that do not fit *by construction* (sp_read_unsigned_bin: inSz
 *       > a->size*SP_WORD_SIZEOF; sp_exptmod_ex: m->used*2 >= SP_INT_DIGITS).
 *       Passing an oversized buffer (here: 2000 zero bytes, always over the
 *       ~1024-1032 byte capacity regardless of 32/64-bit sp_int digits) or a
 *       modulus bigger than SP_INT_BITS deterministically fails that call
 *       with no allocator involved, and cascades ret != 0 through every
 *       later "ret == 0 && ..." guard in the same function.
 *   (c) crafted-value rows: several decisions (agree/z must not be 0 or 1;
 *       a candidate prime must actually be composite; a public key must not
 *       be merely in-range but a genuine subgroup member) are only reached
 *       by choosing DEGENERATE-but-otherwise-valid inputs (private exponent
 *       0 or 1, p-2 as a "pub", a same-size-but-content-flipped named prime)
 *       rather than by injecting any fault.
 *
 * Two rows are targeted via q == 0: wc_InitDhKey() leaves key->q correctly
 * initialized-but-zero, and wc_DhSetKey_ex()/wc_DhSetCheckKey() only touch
 * key->q when a non-NULL q buffer is passed, so building a key with a real,
 * SP-dispatch-sized p/g and q intentionally left at 0 skips the subgroup
 * membership check in _ffc_validate_public_key() (partial=0's deep check is
 * itself gated on q != 0) while keeping the range check active - this makes
 * arbitrary small crafted "otherPub" values (3, p-2, ...) pass the upfront
 * wc_DhCheckPubKey_ex() that wc_DhAgree_Sync() always performs, so the SP
 * dispatch / generic exptmod code beneath it is actually reached.
 *
 * This #includes dh.c directly so wc_DhGenerateKeyPair_Sync (a file-static
 * helper - its own NULL guard is otherwise unreachable, see below) and the
 * dh_ffdhe*_p/g byte tables are in scope.
 *
 * Crash-safety: every crafted call uses a real (mp_init'd) DhKey and either
 * a correctly-sized scratch buffer or the fixed 2000-byte all-zero
 * "oversized" buffer, whose LENGTH argument (never its dereferenced past-end
 * content) is what trips the size guard - no OOB read ever happens.
 *
 * STRUCTURALLY UNSATISFIABLE (recorded in the exclusion record).
 * Three dh.c conditions are not driven here because no input produces the
 * missing vector:
 *
 *   2205:0  `if (0` -- the WOLFSSL_HAVE_SP_DH dispatch is written as
 *           `if (0 || bits == 2048 || bits == 3072 || bits == 4096)` so each
 *           #if-selected arm can be added or removed without touching the
 *           punctuation. clang records the literal 0 as condition 0 (the
 *           MC/DC record carries four conditions, one per leaf) and a
 *           literal 0 is false in every evaluation, so it has no
 *           independence pair. Conditions 1..3 are covered by
 *           test_agree_sp_dispatch().
 *
 *   2222:0  `if (ret == 0 && mp_read_unsigned_bin(y, otherPub, pubSz) !=
 *           MP_OKAY)` sits directly inside `if (ret == 0) {` (dh.c:2220),
 *           with only a declaration and the mp_init(y) whose failure that
 *           outer guard already filtered in between. The operand is true at
 *           every evaluation; the trailing operand is covered by the
 *           DhAgree/ffdhe2048 mp_* sweep.
 *
 *   3018:3  `qCmp != NULL` in wc_DhCmpNamedKey(). Every goodName case of the
 *           switch assigns qCmp from the matching dh_ffdhe*_q table inside
 *           #ifdef HAVE_FFDHE_Q, which configs/dh/user_settings.base.h
 *           defines for all six variants; goodName == 0 skips the whole
 *           expression. The operand is true wherever it is evaluated.
 *
 * Invocation: ./test_dh_fault_whitebox (no args; always returns 0).
 */

/* Installed BEFORE dh.c so its mp_* calls resolve to the fault wrappers.
 * dh.c's residual class is the long big-integer success chain
 *
 *     if (ret == 0 && mp_copy(&key->p, p) != MP_OKAY) ...
 *     if (ret == 0 && mp_read_unsigned_bin(y, otherPub, pubSz) != MP_OKAY) ...
 *     } while (ret == 0 && mp_cmp_d(tmp, 1) == MP_EQ);
 *
 * where BOTH operands are uncovered: on a healthy machine no mp_* call ever
 * fails, so `mp_xxx(..) != MP_OKAY` is never TRUE and, with nothing upstream
 * failing, `ret == 0` is never FALSE. The mp_int scratch here mostly lives on
 * the stack, so the heap-fault lever has nothing to fault either.
 * mcdc_fault_mp.h interposes the value-returning mp_* API for this TU only;
 * mcdc_fm_arm(n) makes the n-th mp_* call (and every later one) return MP_VAL,
 * so one sweep drives both operands of every guard in the chain. Predicates
 * (mp_iszero/mp_cmp/mp_count_bits) and teardown (mp_clear/mp_forcezero) are
 * NOT interposed, so cleanup keeps working and armed calls stay crash-safe. */
#include "mcdc_fault_mp.h"

/* EXPERIMENT (2026-08-11 flake hunt): dh.c:3359 `(ret == 0) && (primeCheckCount)`
 * was the last non-deterministic condition suite-wide -- covered in 2 of 3
 * sweeps of an unchanged tree. primeCheckCount counts rejected prime
 * candidates, so it is a direct function of the random draws. */
#include "mcdc_seed_rng.h"

#define WB_DH_SEED 0xd4f00d01UL

/* ---- call-site-exact levers ---------------------------------------------
 * mcdc_fault_mp.h arms by GLOBAL call index, which three dh.c decisions are
 * out of reach of:
 *
 *   2771  `if (ret == 0 && mp_init(&key->g) != MP_OKAY)` - mp_init is opt-in
 *         in that header (MCDC_FM_WITH_INIT) and deliberately left off,
 *         because faulting initialisation is not crash-safe for every caller.
 *         It is safe HERE: _DhSetKey's cleanup clears keyG only when the
 *         mp_read_unsigned_bin that follows this init succeeded, so a faulted
 *         run leaves nothing half-constructed. Keyed on the mp_init ordinal
 *         within one _DhSetKey call (1 = &key->p at 2676, 2 = &key->g).
 *
 *   3365  `if ((ret == 0) && (mp_set(&dh->g, 1) != MP_OKAY))` - mp_set has
 *         exactly ONE call site in dh.c, so "fail every mp_set" is already
 *         call-site exact; a global index is not, because the index of this
 *         call inside wc_DhGenerateParams moves with the random draws.
 *
 *   3374  `} while (ret == 0 && mp_cmp_d(tmp, 1) == MP_EQ);` - both operands
 *         need the (TRUE,TRUE) row, which is mp_exptmod SUCCEEDING with a
 *         result of 1, not failing. That is the outcome the loop exists for:
 *         g^tmp2 mod p == 1 whenever the candidate g lands in a subgroup
 *         whose order divides tmp2. It is a legitimate value of this
 *         exptmod - just drawn with probability ~1/q, so it cannot be
 *         reached by choosing inputs. Mode 2 substitutes it once, and the
 *         next iteration computes the real result so the loop terminates.
 *
 * All three chain to mcdc_fault_mp.h's own wrappers, so its index sweeps
 * still see every call, and all three are armed only while that lever is
 * disarmed. Defined here, BEFORE the #undef/#define pairs below, so the
 * bodies still reach the real entry points. */
static int wb_lv_init_n    = 0;  /* mp_init calls seen since the counter reset */
static int wb_lv_init_fail = 0;  /* fail the n-th mp_init; 0 = off */
static int wb_lv_set_fail  = 0;  /* fail mp_set (one call site in dh.c) */
static int wb_lv_exp_mode  = 0;  /* mp_exptmod: 1 = fail once, 2 = yield 1 once */

MCDC_FM_MAYBE_UNUSED static int wb_mp_init(mp_int* a)
{
    wb_lv_init_n++;
    if ((wb_lv_init_fail != 0) && (wb_lv_init_n == wb_lv_init_fail))
        return MP_VAL;
    return mp_init(a);
}

MCDC_FM_MAYBE_UNUSED static int wb_mp_set(mp_int* a, mp_digit d)
{
    if (wb_lv_set_fail)
        return MP_VAL;
    return mcdc_fm_set(a, d);
}

MCDC_FM_MAYBE_UNUSED static int wb_mp_exptmod(const mp_int* b, const mp_int* e,
    const mp_int* m, mp_int* r)
{
    int mode = wb_lv_exp_mode;
    int ret;

    if (mode == 1) {
        wb_lv_exp_mode = 0;
        return MP_VAL;
    }
    ret = mcdc_fm_exptmod(b, e, m, r);
    if ((mode == 2) && (ret == MP_OKAY)) {
        wb_lv_exp_mode = 0;
        /* mcdc_fm_set, not mp_set: the substitution stays visible to the
         * index lever's counter. That lever is disarmed whenever this one
         * is armed, so the extra tick changes nothing. */
        ret = mcdc_fm_set(r, 1);
    }
    return ret;
}

#undef  mp_init
#define mp_init(a)             wb_mp_init((a))
#undef  mp_set
#define mp_set(a, d)           wb_mp_set((a), (d))
#undef  mp_exptmod
#define mp_exptmod(a, b, c, d) wb_mp_exptmod((a), (b), (c), (d))

#include <wolfcrypt/src/dh.c>

#define MCDC_SR_IMPL
#include "mcdc_seed_rng.h"

#include <wolfssl/wolfcrypt/random.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)
#define WB_CHECK(cond, msg) \
    do { if (!(cond)) { wb_fail++; WB_NOTE("FAIL: " msg); } } while (0)

#if defined(NO_DH)

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("dh.c fault white-box: NO_DH, nothing to do\n");
    return 0;
}

#else

/* Buffer whose full length, used as an mp_read_unsigned_bin() byte count, is
 * always over an sp_int's fixed digit capacity here (SP_INT_BITS=4096 ->
 * ~1024-1032 bytes depending on 32/64-bit sp_int digits) - content is never
 * read past the point the size guard rejects it, so all-zero is fine. */
#define OVERSIZED_LEN 2000
static byte oversized[OVERSIZED_LEN];

/* ---- wc_DhGenerateKeyPair_Sync NULL guard, dh.c:1458-1459 -----------------
 * if (key==NULL || rng==NULL || priv==NULL || privSz==NULL || pub==NULL ||
 *     pubSz==NULL)
 * The public wc_DhGenerateKeyPair() (dh.c:2012) repeats this exact check
 * before ever calling the static Sync helper, so none of its 6 operands can
 * be driven NULL through the public entry - call the file-static helper
 * directly (in scope via the #include above) instead. */
static void test_generate_keypair_null_guards(void)
{
    WC_RNG rng;
    DhKey key;
    byte priv[300], pub[300];
    word32 privSz, pubSz;

    wc_InitRng(&rng);
    wc_InitDhKey(&key);
    wc_DhSetNamedKey(&key, WC_FFDHE_2048);

    privSz = sizeof(priv); pubSz = sizeof(pub);
    WB_CHECK(wc_DhGenerateKeyPair_Sync(&key, &rng, priv, &privSz, pub, &pubSz)
              == 0, "genkeypair_sync baseline should succeed");

    privSz = sizeof(priv); pubSz = sizeof(pub);
    WB_CHECK(wc_DhGenerateKeyPair_Sync(NULL, &rng, priv, &privSz, pub, &pubSz)
              == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "key==NULL");
    WB_CHECK(wc_DhGenerateKeyPair_Sync(&key, NULL, priv, &privSz, pub, &pubSz)
              == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "rng==NULL");
    WB_CHECK(wc_DhGenerateKeyPair_Sync(&key, &rng, NULL, &privSz, pub, &pubSz)
              == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "priv==NULL");
    WB_CHECK(wc_DhGenerateKeyPair_Sync(&key, &rng, priv, NULL, pub, &pubSz)
              == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "privSz==NULL");
    WB_CHECK(wc_DhGenerateKeyPair_Sync(&key, &rng, priv, &privSz, NULL, &pubSz)
              == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pub==NULL");
    WB_CHECK(wc_DhGenerateKeyPair_Sync(&key, &rng, priv, &privSz, pub, NULL)
              == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pubSz==NULL");

    wc_FreeDhKey(&key);
    wc_FreeRng(&rng);
}

/* ---- GeneratePublicDh, dh.c:1405/1408 -------------------------------------
 * if (ret == 0 && mp_exptmod(&key->g, x, &key->p, y) != MP_OKAY)   (1405)
 * if (ret == 0 && mp_to_unsigned_bin(y, pub) != MP_OKAY)           (1408)
 * Only reached with !WOLFSSL_HAVE_SP_DH-matching p (else the sp_DhExp_*
 * dispatch above returns first): a p whose bit count is not 2048/3072/4096
 * takes this generic path in every variant. 1408's mp_to_unsigned_bin(y,pub)
 * call is given the exact size it needs (never truncated) and only checks
 * for NULL - its failure arm is unreachable (), so
 * only 1408's ret==0 operand is exercised here (via the same cascade as
 * 1405's). */
static void test_generate_public_cascade(void)
{
    DhKey key;
    byte priv[1] = { 0x05 };
    byte pub[900];
    word32 pubSz;
    int ret;

    /* baseline: real 2048-bit p/g (not SP-dispatch-sized without
     * WOLFSSL_HAVE_SP_DH; harmless extra SP dispatch when it is defined -
     * either way ret==0 and mp_exptmod/mp_to_unsigned_bin succeed). */
    wc_InitDhKey(&key);
    wc_DhSetKey_ex(&key, dh_ffdhe2048_p, sizeof(dh_ffdhe2048_p),
                   dh_ffdhe2048_g, sizeof(dh_ffdhe2048_g), NULL, 0);
    pubSz = sizeof(pub);
    ret = wc_DhGeneratePublic(&key, priv, sizeof(priv), pub, &pubSz);
    WB_CHECK(ret == 0, "GeneratePublicDh baseline should succeed");

    /* 1405:0 / 1408:0 - oversized priv fails the mp_read_unsigned_bin(x,...)
     * at dh.c:1402, so ret != 0 entering both later guards. */
    pubSz = sizeof(pub);
    ret = wc_DhGeneratePublic(&key, oversized, OVERSIZED_LEN, pub, &pubSz);
    WB_CHECK(ret != 0, "GeneratePublicDh oversized priv should fail early");
    wc_FreeDhKey(&key);

    /* 1405:1 - a modulus bigger than SP_INT_BITS makes sp_exptmod_ex's own
     * "m->used*2 >= SP_INT_DIGITS" guard fail deterministically (verified:
     * MP_EXPTMOD_E), with ret==0 still true entering the check. Self-built
     * odd 6144-bit-ish value (no HAVE_FFDHE_6144 table in this suite's
     * base config) - trusted=1 skips the (irrelevant) primality check. */
    {
        byte bigp[768];
        byte g[1] = { 0x02 };
        WC_RNG rng;
        XMEMSET(bigp, 0xFF, sizeof(bigp));
        bigp[sizeof(bigp) - 1] |= 0x01;
        wc_InitRng(&rng);
        wc_InitDhKey(&key);
        wc_DhSetCheckKey(&key, bigp, sizeof(bigp), g, sizeof(g), NULL, 0, 1,
                          &rng);
        pubSz = sizeof(pub);
        ret = wc_DhGeneratePublic(&key, priv, sizeof(priv), pub, &pubSz);
        WB_CHECK(ret == WC_NO_ERR_TRACE(MP_EXPTMOD_E),
                 "GeneratePublicDh over-capacity modulus should fail exptmod");
        wc_FreeDhKey(&key);
        wc_FreeRng(&rng);
    }
}

/* ---- _ffc_validate_public_key cascade, dh.c:1600/1612/1617/1620/1628/1636/
 * 1675, and its OR-decision cousin in _ffc_pairwise_consistency_test,
 * dh.c:1920-1921 -------------------------------------------------------
 * All of "ret==0 && ..." at 1600/1612/1617/1620/1628/1636/1675 read as one
 * long forward chain inside a single call to wc_DhCheckPubKey_ex(); an
 * oversized pub fails the very first mp_read_unsigned_bin (dh.c:1596),
 * cascading ret != 0 (operand 0 = FALSE) through every one of them in this
 * one call. 1675's *second* operand (mp_cmp_d(y,1) != MP_EQ, TRUE side) is
 * a distinct case: a value in the valid [2,p-2] range that is NOT a
 * subgroup member. For an FFDHE group (safe prime p, g=2, order-q
 * subgroup), y = p-2 = -g mod p has full order 2q, so y^q mod p == p-1, not
 * 1 - in range but fails subgroup membership (verified: MP_CMP_E). */
static void test_validate_and_pairwise(void)
{
    DhKey key;
    WC_RNG rng;
    byte priv[300], pub[300];
    word32 privSz, pubSz;
    int ret;

    wc_InitRng(&rng);
    wc_InitDhKey(&key);
    wc_DhSetNamedKey(&key, WC_FFDHE_2048); /* real q populated */

    privSz = sizeof(priv); pubSz = sizeof(pub);
    ret = wc_DhGenerateKeyPair_Sync(&key, &rng, priv, &privSz, pub, &pubSz);
    WB_CHECK(ret == 0, "genkeypair for validate/pairwise setup");

    /* baseline: genuine subgroup member -> every "ret==0 && ..." operand's
     * TRUE-continuing side, and the final 1675 FALSE side. */
    ret = wc_DhCheckPubKey_ex(&key, pub, pubSz, NULL, 0);
    WB_CHECK(ret == 0, "validate baseline pub should pass");

    /* 1600:0/1612:0/1617:0/1620:0/1628:0/1636:0/1675:0 - oversized pub
     * cascade (dh.c:1596 mp_read_unsigned_bin fails first). */
    ret = wc_DhCheckPubKey_ex(&key, oversized, OVERSIZED_LEN, NULL, 0);
    WB_CHECK(ret != 0, "validate oversized pub should fail early");

    /* 1653:0/1 - `if (ret == 0 && mp_cmp_d(y, 2) == MP_LT)`. Both operands
     * need the (TRUE,TRUE) row, i.e. a pub that reads back below the
     * SP 800-56Ar3 lower bound; a one-byte 0x01 is the smallest such value
     * that still parses. The oversized cascade above is the FALSE row for
     * operand 0, in this same binary. */
    {
        byte one[1] = { 0x01 };
        ret = wc_DhCheckPubKey_ex(&key, one, sizeof(one), NULL, 0);
        WB_CHECK(ret == WC_NO_ERR_TRACE(MP_CMP_E),
                 "a pub of 1 should fail the y >= 2 bound");
    }

    /* 1675:1 - p-2 trick: in-range, non-subgroup-member. */
    {
        mp_int p, y;
        byte fakepub[300];
        word32 fakeSz;
        mp_init(&p);
        mp_init(&y);
        mp_copy(&key.p, &p);
        mp_sub_d(&p, 2, &y);
        fakeSz = (word32)mp_unsigned_bin_size(&y);
        mp_to_unsigned_bin(&y, fakepub);
        ret = wc_DhCheckPubKey_ex(&key, fakepub, fakeSz, NULL, 0);
        WB_CHECK(ret == WC_NO_ERR_TRACE(MP_CMP_E), "p-2 pub should fail subgroup check");
        mp_clear(&p);
        mp_clear(&y);
    }

    /* 1920:0/1:1 - _ffc_pairwise_consistency_test's OR decision,
     * "mp_read_unsigned_bin(publicKey,...) != MP_OKAY ||
     *  mp_read_unsigned_bin(privateKey,...) != MP_OKAY", via
     * wc_DhCheckKeyPair(). Baseline (both reads succeed) already covered
     * above by construction; here: oversized pub (operand 0 TRUE, short-
     * circuits) and valid pub + oversized priv (operand 0 FALSE, operand 1
     * TRUE) give the independence pair for each operand. */
    ret = wc_DhCheckKeyPair(&key, pub, pubSz, priv, privSz);
    WB_CHECK(ret == 0, "pairwise baseline should pass");
    ret = wc_DhCheckKeyPair(&key, oversized, OVERSIZED_LEN, priv, privSz);
    WB_CHECK(ret != 0, "pairwise oversized pub should fail (operand 0)");
    ret = wc_DhCheckKeyPair(&key, pub, pubSz, oversized, OVERSIZED_LEN);
    WB_CHECK(ret != 0, "pairwise oversized priv should fail (operand 1)");

    wc_FreeDhKey(&key);
    wc_FreeRng(&rng);
}

/* ---- _DhSetKey named-table short-circuit and primality chain,
 * dh.c:2641/2649/2706/2710 ---------------------------------------------
 * if ((pSz == sizeof(dh_ffdhe3072_p)) && (XMEMCMP(...) == 0))   (2641, idx1)
 * if ((pSz == sizeof(dh_ffdhe4096_p)) && (XMEMCMP(...) == 0))   (2649, idx1)
 * if (ret == 0 && isPrime == 0)                                 (2706, idx0)
 * if (ret == 0 && mp_init(&key->g) != MP_OKAY)                  (2710, idx0)
 * A same-size-but-flipped-byte copy of a named table matches the size
 * operand but not the content one (2641:1/2649:1's XMEMCMP==0 FALSE side),
 * falling through to a real (untrusted) primality test on the corrupted
 * candidate; a single flipped byte makes it composite with overwhelming
 * probability, giving isPrime==0 (2706's TRUE row) which sets ret=
 * DH_CHECK_PUB_E and cascades ret!=0 into 2710 (its FALSE row). mp_init()
 * on &key->g itself cannot fail here. */
static void test_setkey_primality(void)
{
    WC_RNG rng;
    DhKey key;
    int ret;

    wc_InitRng(&rng);

    {
        byte p3[sizeof(dh_ffdhe3072_p)];
        XMEMCPY(p3, dh_ffdhe3072_p, sizeof(p3));
        p3[sizeof(p3) / 2] ^= 0xFF; /* same size, wrong content, likely composite */
        wc_InitDhKey(&key);
        ret = wc_DhSetCheckKey(&key, p3, sizeof(p3), dh_ffdhe3072_g,
                                sizeof(dh_ffdhe3072_g), NULL, 0, 0, &rng);
        WB_CHECK(ret == WC_NO_ERR_TRACE(DH_CHECK_PUB_E),
                 "corrupted same-size ffdhe3072 candidate should be rejected");
        wc_FreeDhKey(&key);
    }
    {
        byte p4[sizeof(dh_ffdhe4096_p)];
        XMEMCPY(p4, dh_ffdhe4096_p, sizeof(p4));
        p4[sizeof(p4) / 2] ^= 0xFF;
        wc_InitDhKey(&key);
        ret = wc_DhSetCheckKey(&key, p4, sizeof(p4), dh_ffdhe4096_g,
                                sizeof(dh_ffdhe4096_g), NULL, 0, 0, &rng);
        WB_CHECK(ret == WC_NO_ERR_TRACE(DH_CHECK_PUB_E),
                 "corrupted same-size ffdhe4096 candidate should be rejected");
        wc_FreeDhKey(&key);
    }

    wc_FreeRng(&rng);
}

/* ---- wc_DhImportKeyPair, dh.c:2494/2544 -----------------------------------
 * havePub = ((pub != NULL) && (pubSz > 0));                       (2494:1)
 * if (havePriv == 0 && havePub == 0)                       (2544:0, 2544:1)
 * Masking MC/DC needs (A=havePriv==0,B=havePub==0): (T,T), (F,T), (T,F).
 * priv-only success gives (F,T); pub-only success gives (T,F); an oversized
 * priv with no pub forces the priv read to fail (havePriv -> 0) while pub
 * was never provided (havePub stays 0) giving (T,T) -> MEMORY_E. The
 * pub-only call also supplies pub!=NULL,pubSz==0 to drive 2494:1. */
static void test_import_export_keypair(void)
{
    DhKey key;
    byte priv[1] = { 0x05 };
    byte pub[1] = { 0x03 };
    int ret;

    wc_InitDhKey(&key);
    ret = wc_DhImportKeyPair(&key, priv, sizeof(priv), pub, 0); /* priv-only */
    WB_CHECK(ret == 0, "priv-only import should succeed");
    wc_FreeDhKey(&key);

    wc_InitDhKey(&key);
    ret = wc_DhImportKeyPair(&key, priv, 0, pub, sizeof(pub)); /* pub-only */
    WB_CHECK(ret == 0, "pub-only import should succeed");
    wc_FreeDhKey(&key);

    wc_InitDhKey(&key);
    ret = wc_DhImportKeyPair(&key, oversized, OVERSIZED_LEN, pub, 0);
    WB_CHECK(ret == WC_NO_ERR_TRACE(MEMORY_E), "oversized priv, no pub should give MEMORY_E");
    wc_FreeDhKey(&key);
}

/* ---- wc_DhCmpNamedKey, dh.c:2957 ------------------------------------------
 * cmp = (pSz==pCmpSz) && (gSz==gCmpSz) && (noQ || ...) &&
 *       (XMEMCMP(p,...)==0) && (XMEMCMP(g,...)==0);
 * idx2 (the noQ||... term) is already covered elsewhere; noQ=1 here keeps
 * it trivially TRUE throughout so idx0/1/3/4 are isolated. */
static void test_cmp_named_key(void)
{
    byte p[sizeof(dh_ffdhe2048_p)];
    byte g[sizeof(dh_ffdhe2048_g)];

    XMEMCPY(p, dh_ffdhe2048_p, sizeof(p));
    XMEMCPY(g, dh_ffdhe2048_g, sizeof(g));

    WB_CHECK(wc_DhCmpNamedKey(WC_FFDHE_2048, 1, p, sizeof(p), g, sizeof(g),
                                NULL, 0) == 1, "cmp baseline should match");
    WB_CHECK(wc_DhCmpNamedKey(WC_FFDHE_2048, 1, p, sizeof(p) - 1, g,
                                sizeof(g), NULL, 0) == 0, "pSz mismatch (idx0)");
    WB_CHECK(wc_DhCmpNamedKey(WC_FFDHE_2048, 1, p, sizeof(p), g,
                                sizeof(g) + 1, NULL, 0) == 0,
             "gSz mismatch (idx1)");
    {
        byte pBad[sizeof(dh_ffdhe2048_p)];
        XMEMCPY(pBad, p, sizeof(pBad));
        pBad[10] ^= 0xFF;
        WB_CHECK(wc_DhCmpNamedKey(WC_FFDHE_2048, 1, pBad, sizeof(pBad), g,
                                    sizeof(g), NULL, 0) == 0,
                 "p content mismatch (idx3)");
    }
    {
        byte gBad[sizeof(dh_ffdhe2048_g)];
        XMEMCPY(gBad, g, sizeof(gBad));
        gBad[0] ^= 0xFF;
        WB_CHECK(wc_DhCmpNamedKey(WC_FFDHE_2048, 1, p, sizeof(p), gBad,
                                    sizeof(gBad), NULL, 0) == 0,
                 "g content mismatch (idx4)");
    }
}

/* ---- wc_DhKeyCopy, dh.c:2444 (WOLFSSL_DH_EXTRA) ---------------------------
 * if (!src || !dst || src == dst) */
static void test_dhkeycopy_null_guards(void)
{
    DhKey src, dst;

    wc_InitDhKey(&src);
    wc_InitDhKey(&dst);
    wc_DhSetNamedKey(&src, WC_FFDHE_2048);

    WB_CHECK(wc_DhKeyCopy(&src, &dst) == 0, "keycopy baseline should succeed");
    WB_CHECK(wc_DhKeyCopy(NULL, &dst) == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "src==NULL");
    WB_CHECK(wc_DhKeyCopy(&src, NULL) == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "dst==NULL");
    WB_CHECK(wc_DhKeyCopy(&src, &src) == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "src==dst");

    wc_FreeDhKey(&src);
    wc_FreeDhKey(&dst);
}

/* ---- wc_DhCheckPubValue, dh.c:1776 ---------------------------------------
 * if (prime == NULL || pub == NULL) -> BAD_FUNC_ARG
 * Both operands need their TRUE row against an all-false row in this same
 * binary; every in-tree caller of wc_DhCheckPubValue() hands it two buffers
 * it has already produced, so the API-level tests only ever build the
 * all-false row. The guard short-circuits before either pointer is read. */
static void test_check_pub_value_null_guards(void)
{
    static const byte prime[4] = { 0xFF, 0xFF, 0xFF, 0xFB };
    static const byte pub[4]   = { 0x00, 0x00, 0x00, 0x02 };

    /* idx0 TRUE: prime absent. */
    WB_CHECK(wc_DhCheckPubValue(NULL, (word32)sizeof(prime), pub,
                                (word32)sizeof(pub))
             == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "prime==NULL");

    /* idx0 FALSE, idx1 TRUE: pub absent. */
    WB_CHECK(wc_DhCheckPubValue(prime, (word32)sizeof(prime), NULL,
                                (word32)sizeof(pub))
             == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pub==NULL");

    /* all-false baseline: pub == 2 is neither 0/1 nor prime/prime-1. */
    WB_CHECK(wc_DhCheckPubValue(prime, (word32)sizeof(prime), pub,
                                (word32)sizeof(pub)) == 0,
             "valid prime/pub baseline");
}

/* ---- wc_DhExportParamsRaw, dh.c:3391/3400 ---------------------------------
 * if (p==NULL && q==NULL && g==NULL) ... LENGTH_ONLY_E          (3391)
 * if (p==NULL || q==NULL || g==NULL) ... BAD_FUNC_ARG           (3400)
 * 3391:1/2 need q's and g's independent effect (idx0/p already covered
 * elsewhere); 3400:0/2 need p's and g's independent effect (idx1/q already
 * covered elsewhere). */
static void test_export_params_null_guards(void)
{
    DhKey key;
    byte p[300], q[300], g[300];
    word32 pSz, qSz, gSz;
    int ret;

    wc_InitDhKey(&key);
    wc_DhSetNamedKey(&key, WC_FFDHE_2048);

    pSz = sizeof(p); qSz = sizeof(q); gSz = sizeof(g);
    ret = wc_DhExportParamsRaw(&key, NULL, &pSz, NULL, &qSz, NULL, &gSz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(LENGTH_ONLY_E),
             "all-NULL should give LENGTH_ONLY_E");

    /* 3391:1 - q non-NULL breaks the all-NULL chain (idx1 FALSE) */
    pSz = sizeof(p); qSz = sizeof(q); gSz = sizeof(g);
    ret = wc_DhExportParamsRaw(&key, NULL, &pSz, q, &qSz, NULL, &gSz);
    WB_CHECK(ret != WC_NO_ERR_TRACE(LENGTH_ONLY_E), "p=NULL,q=valid,g=NULL");

    /* 3391:2 - g non-NULL breaks the all-NULL chain (idx2 FALSE) */
    pSz = sizeof(p); qSz = sizeof(q); gSz = sizeof(g);
    ret = wc_DhExportParamsRaw(&key, NULL, &pSz, NULL, &qSz, g, &gSz);
    WB_CHECK(ret != WC_NO_ERR_TRACE(LENGTH_ONLY_E), "p=NULL,q=NULL,g=valid");

    /* 3400:0 - p==NULL (with q,g valid) trips the OR (idx0 TRUE) */
    pSz = sizeof(p); qSz = sizeof(q); gSz = sizeof(g);
    ret = wc_DhExportParamsRaw(&key, NULL, &pSz, q, &qSz, g, &gSz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "p=NULL,q=valid,g=valid");

    /* 3400:2 - g==NULL (with p,q valid) trips the OR (idx2 TRUE) */
    pSz = sizeof(p); qSz = sizeof(q); gSz = sizeof(g);
    ret = wc_DhExportParamsRaw(&key, p, &pSz, q, &qSz, NULL, &gSz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "p=valid,q=valid,g=NULL");

    /* baseline: all valid, decision FALSE both places */
    pSz = sizeof(p); qSz = sizeof(q); gSz = sizeof(g);
    ret = wc_DhExportParamsRaw(&key, p, &pSz, q, &qSz, g, &gSz);
    WB_CHECK(ret == 0, "export all-valid should succeed");

    wc_FreeDhKey(&key);
}

#ifdef WOLFSSL_HAVE_SP_DH
/* ---- wc_DhAgree_Sync SP-DH dispatch, dh.c:2159/2204/2210 ------------------
 * if (0 || count==2048 || count==3072 || count==4096)                (2159)
 * if ((ret==0) && ((*agreeSz==0)||((*agreeSz==1)&&(agree[0]==1))))   (2204)
 * if ((ret==0) && ct)                                                (2210)
 *
 * Uses a "relaxed" key: real named-group p/g (so the SP dispatch triggers)
 * but key->q intentionally left at 0 (wc_DhSetKey_ex only touches key->q
 * when a q buffer is passed; wc_InitDhKey already left it validly
 * initialized to zero) - this skips the deep subgroup check in the upfront
 * wc_DhCheckPubKey_ex() that wc_DhAgree_Sync() always performs, so a tiny
 * crafted otherPub (value 3) is accepted and the SP dispatch code actually
 * runs on it.
 *
 * 2159: FFDHE_2048/3072/4096 each drive one of the OR's TRUE arms; the
 * ~4080-bit key built in test_agree_generic() (count_bits none of
 * 2048/3072/4096) drives the all-FALSE row (shared with the generic-path
 * decisions there).
 *
 * 2204: priv=0 makes agree = otherPub^0 mod p == 1, i.e. *agreeSz==1 &&
 * agree[0]==1 (idx1 FALSE via *agreeSz==1 not 0, idx2/idx3 TRUE) -
 * deterministic, no allocator or degenerate-modulus trick needed (verified:
 * sp_DhExp_2048 returns outLen=1,byte=1 for base^0). priv=1,otherPub=3 gives
 * agree = 3^1 mod p == 3, i.e. *agreeSz==1 but agree[0]!=1 (idx3's FALSE
 * pairing). An oversized priv (privSz>256 for a 2048-bit exponent) fails
 * sp_DhExp_2048's own "expLen > 256" guard before agree is touched, giving
 * ret != 0 (idx0's FALSE side) and cascading into 2210 (idx0's FALSE side,
 * ct's TRUE/FALSE independence already covered by ordinary agree/agree_ct
 * use elsewhere). *agreeSz==0 (idx1 TRUE) needs a shared secret of exactly
 * zero: sp_DhExp_2048 writes 256 bytes and then strips leading zero bytes
 * from the length, so an all-zero result reports *outLen == 0. Over a prime
 * p that cannot happen for a peer key the SP 800-56A range check admits, but
 * the modulus is only required to be odd and 2048 bits - it is never tested
 * for primality when the key is set as trusted. p = m*m for an odd 1024-bit
 * m is odd and exactly 2048 bits, y = m is in [2, p-2] (and q left at 0
 * skips the subgroup check), and y^x mod p == 0 for every x >= 2. */
static void test_agree_sp_dispatch(void)
{
    DhKey key2048, key3072, key4096;
    byte otherPub[1] = { 0x03 };
    byte priv0[1] = { 0x00 };
    byte priv1[1] = { 0x01 };
    byte agree[600];
    word32 agreeSz;
    int ret;

    wc_InitDhKey(&key2048);
    wc_DhSetKey_ex(&key2048, dh_ffdhe2048_p, sizeof(dh_ffdhe2048_p),
                   dh_ffdhe2048_g, sizeof(dh_ffdhe2048_g), NULL, 0);
    WB_CHECK(mp_iszero(&key2048.q) == MP_YES, "relaxed key has q==0");

    /* 2159 idx1 TRUE: count_bits==2048 dispatch */
    agreeSz = sizeof(agree);
    ret = wc_DhAgree(&key2048, agree, &agreeSz, priv1, sizeof(priv1),
                      otherPub, sizeof(otherPub));
    WB_CHECK(ret == 0 && agreeSz == 1 && agree[0] == 3,
             "2048 dispatch priv=1 otherPub=3 -> agree=3 (2204 idx3 FALSE)");

    /* 2204 idx1 FALSE / idx2,idx3 TRUE: priv=0 -> agree=1 -> MP_VAL guard */
    agreeSz = sizeof(agree);
    ret = wc_DhAgree(&key2048, agree, &agreeSz, priv0, sizeof(priv0),
                      otherPub, sizeof(otherPub));
    WB_CHECK(ret == WC_NO_ERR_TRACE(MP_VAL), "2204 priv=0 degenerate agree should hit MP_VAL");

    /* 2204 idx0 FALSE / 2210 idx0 FALSE: oversized priv fails inside
     * sp_DhExp_2048 (expLen > 256) before the agree-value check runs. */
    agreeSz = sizeof(agree);
    ret = wc_DhAgree(&key2048, agree, &agreeSz, oversized, OVERSIZED_LEN,
                      otherPub, sizeof(otherPub));
    WB_CHECK(ret != 0, "2204/2210 oversized priv should fail dispatch");
    agreeSz = sizeof(agree);
    ret = wc_DhAgree_ct(&key2048, agree, &agreeSz, oversized, OVERSIZED_LEN,
                         otherPub, sizeof(otherPub));
    WB_CHECK(ret != 0, "2210 (ct path) oversized priv should fail dispatch");
    wc_FreeDhKey(&key2048);

    /* 2159 idx2 TRUE: count_bits==3072 dispatch */
    wc_InitDhKey(&key3072);
    wc_DhSetKey_ex(&key3072, dh_ffdhe3072_p, sizeof(dh_ffdhe3072_p),
                   dh_ffdhe3072_g, sizeof(dh_ffdhe3072_g), NULL, 0);
    agreeSz = sizeof(agree);
    ret = wc_DhAgree(&key3072, agree, &agreeSz, priv1, sizeof(priv1),
                      otherPub, sizeof(otherPub));
    WB_CHECK(ret == 0 && agreeSz == 1 && agree[0] == 3, "3072 dispatch");
    wc_FreeDhKey(&key3072);

    /* 2159 idx3 TRUE: count_bits==4096 dispatch (only meaningful with
     * WOLFSSL_SP_4096; harmless if that dispatch arm is compiled out - the
     * generic path below still succeeds). */
    wc_InitDhKey(&key4096);
    wc_DhSetKey_ex(&key4096, dh_ffdhe4096_p, sizeof(dh_ffdhe4096_p),
                   dh_ffdhe4096_g, sizeof(dh_ffdhe4096_g), NULL, 0);
    agreeSz = sizeof(agree);
    ret = wc_DhAgree(&key4096, agree, &agreeSz, priv1, sizeof(priv1),
                      otherPub, sizeof(otherPub));
    WB_CHECK(ret == 0, "4096 dispatch/generic should succeed");
    wc_FreeDhKey(&key4096);

    /* 2250:1 TRUE - the zero shared secret described in the block comment. */
    {
        DhKey  keySq;
        mp_int m, psq;
        byte   mbuf[128];        /* 1024 bits, all ones: odd, top bit set */
        byte   pbuf[256];
        byte   g2[1]    = { 0x02 };
        byte   priv2[1] = { 0x02 };
        word32 pSz2;

        XMEMSET(mbuf, 0xFF, sizeof(mbuf));
        if ((mp_init(&m) == MP_OKAY) && (mp_init(&psq) == MP_OKAY)) {
            if ((mp_read_unsigned_bin(&m, mbuf, (word32)sizeof(mbuf))
                     == MP_OKAY) &&
                (mp_sqr(&m, &psq) == MP_OKAY)) {
                pSz2 = (word32)mp_unsigned_bin_size(&psq);
                WB_CHECK(pSz2 == sizeof(pbuf), "m*m should be 256 bytes");
                if ((pSz2 == sizeof(pbuf)) &&
                    (mp_to_unsigned_bin(&psq, pbuf) == MP_OKAY) &&
                    (wc_InitDhKey(&keySq) == 0)) {
                    /* trusted=1: p is deliberately composite, so the
                     * primality test must not run. */
                    ret = wc_DhSetCheckKey(&keySq, pbuf, pSz2, g2,
                              (word32)sizeof(g2), NULL, 0, 1, NULL);
                    WB_CHECK(ret == 0, "m*m modulus should be settable");
                    agreeSz = sizeof(agree);
                    ret = wc_DhAgree(&keySq, agree, &agreeSz, priv2,
                              (word32)sizeof(priv2), mbuf,
                              (word32)sizeof(mbuf));
                    WB_CHECK(ret == WC_NO_ERR_TRACE(MP_VAL),
                             "y=m against p=m*m gives a zero-length secret");
                    wc_FreeDhKey(&keySq);
                }
            }
            mp_clear(&psq);
            mp_clear(&m);
        }
    }
}
#endif /* WOLFSSL_HAVE_SP_DH */

/* ---- wc_DhAgree_Sync generic exptmod path, dh.c:2258/2290 -----------------
 * if (ret==0 && mp_read_unsigned_bin(y,otherPub,pubSz) != MP_OKAY)   (2258)
 * if (ret==0 && (mp_cmp_d(z,1) == MP_EQ))                            (2290)
 *
 * Reached only when the p size does not match any WOLFSSL_HAVE_SP_DH
 * dispatch arm (or that macro is undefined): a ~4080-bit modulus (real
 * dh_ffdhe4096_p with its top 2 bytes zeroed, still odd - last byte
 * untouched) is never 2048/3072/4096 bits, so every variant takes this
 * path. q left at 0 as in test_agree_sp_dispatch() so a small crafted
 * otherPub passes the upfront check. This key also shares dh.c:2159's
 * all-FALSE row (none of the OR's count_bits arms match).
 *
 * 2258:0/2290:0 - oversized priv fails mp_read_unsigned_bin(x,priv,privSz)
 * at dh.c:2251, cascading ret!=0. 2290:1 - priv=0 gives z = otherPub^0 mod p
 * == 1 -> MP_VAL (verified). 2258:1 (this exact otherPub read failing) is
 * effectively unreachable in the 5 non-WC_DH_NONBLOCK variants: the
 * identical otherPub bytes/size were already read successfully moments
 * earlier by the mandatory upfront wc_DhCheckPubKey_ex() validation (same
 * sp_int capacity, so a repeat read cannot newly fail) - not attempted. */
static void test_agree_generic(void)
{
    DhKey key;
    WC_RNG rng;
    byte bigp[sizeof(dh_ffdhe4096_p)];
    byte g[1] = { 0x02 };
    byte otherPub[1] = { 0x03 };
    byte priv7[1] = { 0x07 };
    byte priv0[1] = { 0x00 };
    byte agree[600];
    word32 agreeSz;
    int ret;

    XMEMCPY(bigp, dh_ffdhe4096_p, sizeof(bigp));
    bigp[0] = 0x00;
    bigp[1] = 0x00; /* ~4080 bits: not 2048/3072/4096, still < SP_INT_BITS */

    wc_InitRng(&rng);
    wc_InitDhKey(&key);
    /* trusted=1: this is no longer the real ffdhe4096 prime (content
     * changed), so an untrusted primality re-check would (correctly) reject
     * it - irrelevant to what this test targets, so skip it. */
    wc_DhSetCheckKey(&key, bigp, sizeof(bigp), g, sizeof(g), NULL, 0, 1, &rng);
    WB_CHECK(mp_count_bits(&key.p) != 2048 && mp_count_bits(&key.p) != 3072 &&
              mp_count_bits(&key.p) != 4096,
             "custom modulus avoids every SP dispatch size");

    /* baseline: real agree, generic path, z != 1 */
    agreeSz = sizeof(agree);
    ret = wc_DhAgree(&key, agree, &agreeSz, priv7, sizeof(priv7), otherPub,
                      sizeof(otherPub));
    WB_CHECK(ret == 0, "generic path baseline should succeed");

    /* 2258:0 / 2290:0 - oversized priv fails the x read at dh.c:2251 */
    agreeSz = sizeof(agree);
    ret = wc_DhAgree(&key, agree, &agreeSz, oversized, OVERSIZED_LEN,
                      otherPub, sizeof(otherPub));
    WB_CHECK(ret != 0, "generic path oversized priv should fail early");

    /* 2290:1 - priv=0 -> z = otherPub^0 mod p == 1 -> MP_VAL. Under
     * WOLFSSL_VALIDATE_FFC_IMPORT, wc_DhAgree_Sync additionally calls
     * wc_DhCheckPrivKey() up front, which itself rejects priv==0 (its own
     * "priv should not be 0" check) with DH_CHECK_PRIV_E before this line
     * is ever reached - expected in that one variant, not a regression. */
    agreeSz = sizeof(agree);
    ret = wc_DhAgree(&key, agree, &agreeSz, priv0, sizeof(priv0), otherPub,
                      sizeof(otherPub));
    WB_CHECK(ret == WC_NO_ERR_TRACE(MP_VAL) || ret == WC_NO_ERR_TRACE(DH_CHECK_PRIV_E),
             "generic path priv=0 degenerate z should hit MP_VAL (or be "
             "pre-rejected by VALIDATE_FFC_IMPORT's priv!=0 check)");

    wc_FreeDhKey(&key);
    wc_FreeRng(&rng);
}

#ifdef WC_DH_NONBLOCK
/* ---- wc_DhAgree_Sync non-blocking cache, dh.c:2070/2085/2098/2116 ---------
 * if (key->nb==NULL || ct || !key->nb->pubKeyValidated)              (2070)
 * if (key->nb != NULL && !ct)                                 (2085, 2098)
 * if (!dispatched && mp_count_bits(&key->p) == 4096)                 (2116)
 *
 * Attaching a DhNb and driving a real non-blocking agree to completion
 * naturally exercises the pubKeyValidated cache lifecycle the code
 * documents: first call validates (pubKeyValidated 0->1, 2070/2085/2098
 * all TRUE); every WOULDBLOCK continuation re-enters with
 * pubKeyValidated==1 and ct==0, skipping re-validation (2070/2085/2098 all
 * FALSE); completion resets the cache to 0. A separate wc_DhAgree_ct() call
 * on the same nb-attached key drives ct==1 (the independent operand in
 * 2070/2085/2098 the cache-loop alone cannot vary while nb!=NULL is held
 * fixed). A 2048-bit key dispatches (and completes, ~10k cheap chunked
 * calls, verified) at the first count_bits check, leaving "dispatched"
 * TRUE before the 4096 check runs (2116 idx1 FALSE); a 4096-bit key hits
 * that check directly (2116 idx1 TRUE) - completion isn't needed for that
 * row, so only a couple of calls are made. */
static void test_agree_nonblock(void)
{
    DhKey key;
    DhNb nb;
    WC_RNG rng;
    byte priv[600], pub[600], agree[600]; /* big enough for a 4096-bit key */
    word32 privSz, pubSz, agreeSz;
    int ret, n;

    wc_InitRng(&rng);

    /* 2070/2085/2098 cache lifecycle + ct operand, on a 2048-bit key. */
    XMEMSET(&nb, 0, sizeof(nb));
    wc_InitDhKey(&key);
    wc_DhSetNamedKey(&key, WC_FFDHE_2048);
    wc_DhSetNonBlock(&key, &nb);

    privSz = sizeof(priv); pubSz = sizeof(pub);
    ret = wc_DhGenerateKeyPair_Sync(&key, &rng, priv, &privSz, pub, &pubSz);
    WB_CHECK(ret == 0, "nb setup keypair should succeed");

    agreeSz = sizeof(agree);
    for (n = 0; n < 20000; n++) {
        ret = wc_DhAgree(&key, agree, &agreeSz, priv, privSz, pub, pubSz);
        if (ret != WC_NO_ERR_TRACE(MP_WOULDBLOCK))
            break;
    }
    WB_CHECK(ret == 0, "nb agree loop should complete (2070/2085/2098 cache "
              "lifecycle)");
    WB_CHECK(nb.pubKeyValidated == 0, "cache reset after completed op");

    agreeSz = sizeof(agree);
    ret = wc_DhAgree_ct(&key, agree, &agreeSz, priv, privSz, pub, pubSz);
    WB_CHECK(ret == 0, "ct=1 on nb-attached key (ct operand TRUE)");

    wc_DhSetNonBlock(&key, NULL);
    wc_FreeDhKey(&key);

    /* 2116 idx1 TRUE: count_bits==4096 dispatch (one call is enough). */
    XMEMSET(&nb, 0, sizeof(nb));
    wc_InitDhKey(&key);
    wc_DhSetNamedKey(&key, WC_FFDHE_4096);
    wc_DhSetNonBlock(&key, &nb);
    privSz = sizeof(priv); pubSz = sizeof(pub);
    ret = wc_DhGenerateKeyPair_Sync(&key, &rng, priv, &privSz, pub, &pubSz);
    WB_CHECK(ret == 0, "nb 4096 setup keypair should succeed");
    agreeSz = sizeof(agree);
    ret = wc_DhAgree(&key, agree, &agreeSz, priv, privSz, pub, pubSz);
    WB_CHECK(ret == 0 || ret == WC_NO_ERR_TRACE(MP_WOULDBLOCK),
             "nb 4096 dispatch should run (WOULDBLOCK is fine, just probing "
             "the branch)");
    wc_DhSetNonBlock(&key, NULL);
    wc_FreeDhKey(&key);

    /* 2162 idx1 FALSE with idx0 TRUE: a prime that is none of the three SP
     * sizes leaves "dispatched" clear all the way through the chain, which
     * is the only way the 4096 test is reached and false. The only source of
     * a non-SP-size prime here is a generated one. */
#ifndef WOLFSSL_NO_DH_GEN_PARAMS
    XMEMSET(&nb, 0, sizeof(nb));
    wc_InitDhKey(&key);
    mcdc_sr_arm(WB_DH_SEED);
    ret = wc_DhGenerateParams(&rng, 1024, &key);
    mcdc_sr_disarm();
    WB_CHECK(ret == 0, "nb non-SP-size params should generate");
    if (ret == 0) {
        wc_DhSetNonBlock(&key, &nb);
        privSz = sizeof(priv); pubSz = sizeof(pub);
        ret = wc_DhGenerateKeyPair_Sync(&key, &rng, priv, &privSz, pub,
                &pubSz);
        WB_CHECK(ret == 0, "nb non-SP-size keypair should succeed");
        agreeSz = sizeof(agree);
        for (n = 0; n < 20000; n++) {
            ret = wc_DhAgree(&key, agree, &agreeSz, priv, privSz, pub, pubSz);
            if (ret != WC_NO_ERR_TRACE(MP_WOULDBLOCK))
                break;
        }
        WB_CHECK(ret == 0, "nb non-SP-size agree should fall through to the "
                  "generic path");
        wc_DhSetNonBlock(&key, NULL);
    }
    wc_FreeDhKey(&key);
#endif /* !WOLFSSL_NO_DH_GEN_PARAMS */

    wc_FreeRng(&rng);
}
#endif /* WC_DH_NONBLOCK */

/* ---- wc_DhGenerateParams, dh.c:3293/3299 ----------------------------------
 * if ((ret==0) && (primeCheckCount))                                 (3293)
 * if ((ret==0) && (mp_set(&dh->g, 1) != MP_OKAY))                    (3299)
 * modSz=1024 is the smallest built-in (L,N) pair (groupSz=20) so the safe-
 * prime search here runs in well under a second (verified); finding a
 * 1024-bit prime candidate p=q*rnd+1 essentially never succeeds on the
 * very first trial, so primeCheckCount ends up > 0 (3293 TRUE) as an
 * ordinary side effect of a real run, not anything crafted. rng==NULL
 * fails the very first guard (dh.c:3145), cascading ret != 0 all the way to
 * 3299 (its idx0 FALSE side) cheaply, without running the search at all.
 * The rows this function cannot produce -- the mp_set guard actually
 * failing, and the g-search do-while actually repeating -- are driven by
 * test_generate_params_levers() below, in this same binary. */
#ifndef WOLFSSL_NO_DH_GEN_PARAMS
static void test_generate_params(void)
{
    WC_RNG rng;
    DhKey dh;
    int ret;

    wc_InitRng(&rng);

    wc_InitDhKey(&dh);
    ret = wc_DhGenerateParams(NULL, 1024, &dh);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "rng==NULL should fail immediately (3299 "
              "idx0 FALSE cascade)");
    wc_FreeDhKey(&dh);

    wc_InitDhKey(&dh);
    mcdc_sr_arm(WB_DH_SEED);
    ret = wc_DhGenerateParams(&rng, 1024, &dh);
    mcdc_sr_disarm();
    WB_CHECK(ret == 0, "modSz=1024 real generation should succeed");
    wc_FreeDhKey(&dh);

    wc_FreeRng(&rng);
}
#endif /* !WOLFSSL_NO_DH_GEN_PARAMS */

/* ---- _DhSetKey init guard, dh.c:2771 --------------------------------------
 * if (ret == 0 && mp_init(&key->g) != MP_OKAY)
 * Both operands need the (TRUE,TRUE) row -- the init failing -- which no
 * input produces: key->g is a fixed-capacity sp_int and mp_init on it cannot
 * fail. The FALSE row for operand 0 is supplied by test_setkey_primality()'s
 * composite candidate (a non-zero ret on arrival here) and the
 * (TRUE,FALSE) row by every successful set, both in this binary. See the
 * call-site-lever note at the top of this file for why faulting mp_init is
 * crash-safe at exactly this site. */
static void test_setkey_init_fault(void)
{
    DhKey key;
    int ret;

    if (wc_InitDhKey(&key) != 0)
        return;

    /* mp_init ordinal 1 is &key->p (dh.c:2676), ordinal 2 is &key->g. The
     * named-table short-circuit skips the primality test for this p, and
     * nothing between the two inits calls mp_init from dh.c. */
    wb_lv_init_n = 0;
    wb_lv_init_fail = 2;
    ret = wc_DhSetKey_ex(&key, dh_ffdhe2048_p, sizeof(dh_ffdhe2048_p),
                         dh_ffdhe2048_g, sizeof(dh_ffdhe2048_g), NULL, 0);
    wb_lv_init_fail = 0;
    WB_CHECK(ret == WC_NO_ERR_TRACE(MP_INIT_E),
             "faulted mp_init(&key->g) should give MP_INIT_E");
    wc_FreeDhKey(&key);
}

#ifndef WOLFSSL_NO_DH_GEN_PARAMS
/* ---- wc_DhGenerateParams tail guards, dh.c:3365/3374 ----------------------
 * if ((ret == 0) && (mp_set(&dh->g, 1) != MP_OKAY))                   (3365)
 * } while (ret == 0 && mp_cmp_d(tmp, 1) == MP_EQ);                    (3374)
 * Four vectors, all four rows in this binary; see the call-site-lever note
 * at the top of this file for why each row needs its own lever. Every run
 * is under the seeded RNG so the generated parameters are reproducible. */
static void test_generate_params_levers(void)
{
    WC_RNG rng;
    DhKey dh;
    int ret;

    if (wc_InitRng(&rng) != 0)
        return;

    /* 3365 (FALSE,-): fail the first interposed mp_* call of the function
     * (the mp_read_unsigned_bin of the random multiplier), which cascades
     * ret != 0 all the way down without running the prime search. */
    if (wc_InitDhKey(&dh) == 0) {
        mcdc_sr_arm(WB_DH_SEED);
        mcdc_fm_arm(1);
        ret = wc_DhGenerateParams(&rng, 1024, &dh);
        mcdc_fm_disarm();
        mcdc_sr_disarm();
        WB_CHECK(ret != 0, "faulted first mp_* should fail DhGenerateParams");
        wc_FreeDhKey(&dh);
    }

    /* 3365 (TRUE,TRUE): mp_set's single dh.c call site. */
    if (wc_InitDhKey(&dh) == 0) {
        mcdc_sr_arm(WB_DH_SEED);
        wb_lv_set_fail = 1;
        ret = wc_DhGenerateParams(&rng, 1024, &dh);
        wb_lv_set_fail = 0;
        mcdc_sr_disarm();
        WB_CHECK(ret == WC_NO_ERR_TRACE(MP_ZERO_E),
                 "faulted mp_set should give MP_ZERO_E");
        wc_FreeDhKey(&dh);
    }

    /* 3374 (TRUE,TRUE): one substituted g^tmp2 == 1, so the generator
     * search repeats; the next iteration computes the real value and the
     * loop terminates with a usable generator. */
    if (wc_InitDhKey(&dh) == 0) {
        mcdc_sr_arm(WB_DH_SEED);
        wb_lv_exp_mode = 2;
        ret = wc_DhGenerateParams(&rng, 1024, &dh);
        wb_lv_exp_mode = 0;
        mcdc_sr_disarm();
        WB_CHECK(ret == 0,
                 "generator search should retry past a g of order dividing tmp2");
        wc_FreeDhKey(&dh);
    }

    /* 3374 (FALSE,-): mp_exptmod failing inside the loop body. Its only
     * call site in this function is the one at dh.c:3372. */
    if (wc_InitDhKey(&dh) == 0) {
        mcdc_sr_arm(WB_DH_SEED);
        wb_lv_exp_mode = 1;
        ret = wc_DhGenerateParams(&rng, 1024, &dh);
        wb_lv_exp_mode = 0;
        mcdc_sr_disarm();
        WB_CHECK(ret == WC_NO_ERR_TRACE(MP_EXPTMOD_E),
                 "faulted mp_exptmod should give MP_EXPTMOD_E");
        wc_FreeDhKey(&dh);
    }

    wc_FreeRng(&rng);
}

/* ---- big-integer fault sweeps (mcdc_fault_mp.h) -------------------------
 * Each entry point is run once DISARMED -- that is the all-true baseline row
 * for every guard, in THIS binary (both halves in the same binary), and it
 * also measures the sweep length K -- and then the fail index is swept over
 * [1..K]. All inputs are built while disarmed; none of the swept calls
 * mutates the shared key, and the ones that do (SetKey / GenerateParams) get
 * a fresh key per iteration. Bounded by a VECTOR COUNT only: a wall-clock
 * budget makes coverage a function of machine load, so the same source
 * measures differently run to run (proved on wc_lms_impl.c, 2026-08-11). */
#define WB_MP_MAX       400

#ifndef WB_MAX_VECTORS
    #define WB_MAX_VECTORS 20000
#endif

static long wb_mp_vectors = 0;

static int wb_mp_expired(void)
{
    return (++wb_mp_vectors > (long)WB_MAX_VECTORS);
}

/* Sweep the fail index over the FIRST `cap` mp_* calls of the entry point. */
#define WB_MP_SWEEP(lbl, cap, ...)                                       \
    do {                                                                  \
        long k_, i_;                                                      \
        mcdc_fm_disarm();                                                 \
        { __VA_ARGS__; }                                                  \
        k_ = mcdc_fm_seen();                                              \
        if (k_ > (long)(cap))                                             \
            k_ = (long)(cap);                                             \
        for (i_ = 1; (i_ <= k_) && !wb_mp_expired(); i_++) {              \
            mcdc_fm_arm(i_);                                              \
            { __VA_ARGS__; }                                              \
            mcdc_fm_disarm();                                             \
        }                                                                 \
        printf("  [wb] mp sweep %s: K=%ld\n", (lbl), k_);                 \
    } while (0)

/* Sweep the fail index over the LAST `tail` mp_* calls of the entry point.
 * wc_DhGenerateParams() spends the whole prefix in the prime search, so a
 * head sweep never reaches the g-derivation chain at the end of it, which is
 * where that function's residual guards live. */
#define WB_MP_SWEEP_TAIL(lbl, tail, ...)                                 \
    do {                                                                  \
        long k_, i_, first_;                                              \
        mcdc_fm_disarm();                                                 \
        { __VA_ARGS__; }                                                  \
        k_ = mcdc_fm_seen();                                              \
        first_ = k_ - (long)(tail) + 1;                                   \
        if (first_ < 1)                                                   \
            first_ = 1;                                                   \
        for (i_ = first_; (i_ <= k_) && !wb_mp_expired(); i_++) {         \
            mcdc_fm_arm(i_);                                              \
            { __VA_ARGS__; }                                              \
            mcdc_fm_disarm();                                             \
        }                                                                 \
        printf("  [wb] mp tail sweep %s: K=%ld first=%ld\n", (lbl), k_,   \
               first_);                                                   \
    } while (0)

static void test_mp_fault_sweeps(void)
{
    WC_RNG rng;
    DhKey  dh;
    byte   priv[512];
    byte   pub[512];
    byte   agree[512];
    byte   p[512];
    byte   g[512];
    byte   q[512];
    word32 privSz = (word32)sizeof(priv);
    word32 pubSz  = (word32)sizeof(pub);
    word32 agreeSz;
    word32 pSz = (word32)sizeof(p);
    word32 gSz = (word32)sizeof(g);
    word32 qSz = (word32)sizeof(q);

    mcdc_fm_disarm();

    XMEMSET(priv, 0, sizeof(priv));
    XMEMSET(pub, 0, sizeof(pub));
    XMEMSET(agree, 0, sizeof(agree));

    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("wc_InitRng failed; mp fault sweeps skipped");
        return;
    }
    if (wc_InitDhKey(&dh) != 0) {
        WB_NOTE("wc_InitDhKey failed; mp fault sweeps skipped");
        wc_FreeRng(&rng);
        return;
    }
    /* One real 1024-bit parameter set, generated DISARMED, is the fixture for
     * every sweep below. */
    if (wc_DhGenerateParams(&rng, 1024, &dh) != 0) {
        WB_NOTE("wc_DhGenerateParams failed; mp fault sweeps skipped");
        wc_FreeDhKey(&dh);
        wc_FreeRng(&rng);
        return;
    }
    if (wc_DhGenerateKeyPair(&dh, &rng, priv, &privSz, pub, &pubSz) != 0) {
        WB_NOTE("wc_DhGenerateKeyPair failed; mp fault sweeps skipped");
        wc_FreeDhKey(&dh);
        wc_FreeRng(&rng);
        return;
    }
    (void)wc_DhExportParamsRaw(&dh, p, &pSz, q, &qSz, g, &gSz);

    {
        byte   pv2[512];
        byte   pb2[512];
        word32 s1, s2;
        s1 = (word32)sizeof(pv2); s2 = (word32)sizeof(pb2);
        WB_MP_SWEEP("DhGenerateKeyPair", 200,
            s1 = (word32)sizeof(pv2); s2 = (word32)sizeof(pb2);
            (void)wc_DhGenerateKeyPair(&dh, &rng, pv2, &s1, pb2, &s2));
    }

    WB_MP_SWEEP("DhGeneratePublic", 200,
        {
            byte   pb2[512];
            word32 s2 = (word32)sizeof(pb2);
            (void)wc_DhGeneratePublic(&dh, priv, privSz, pb2, &s2);
        });

    WB_MP_SWEEP("DhCheckPubKey", 200,
        (void)wc_DhCheckPubKey(&dh, pub, pubSz));

    WB_MP_SWEEP("DhCheckPubKey_ex", 200,
        (void)wc_DhCheckPubKey_ex(&dh, pub, pubSz, p, pSz));

    WB_MP_SWEEP("DhCheckPrivKey", 200,
        (void)wc_DhCheckPrivKey(&dh, priv, privSz));

    WB_MP_SWEEP("DhCheckKeyPair", 200,
        (void)wc_DhCheckKeyPair(&dh, pub, pubSz, priv, privSz));

    WB_MP_SWEEP("DhAgree", 200,
        {
            agreeSz = (word32)sizeof(agree);
            (void)wc_DhAgree(&dh, agree, &agreeSz, priv, privSz, pub, pubSz);
        });

    WB_MP_SWEEP("DhSetKey", 200,
        {
            DhKey k2;
            if (wc_InitDhKey(&k2) == 0) {
                (void)wc_DhSetKey(&k2, p, pSz, g, gSz);
                wc_FreeDhKey(&k2);
            }
        });

    WB_MP_SWEEP("DhExportParamsRaw", 200,
        {
            byte   pp[512], gg[512], qq[512];
            word32 a1 = (word32)sizeof(pp), a2 = (word32)sizeof(qq),
                   a3 = (word32)sizeof(gg);
            (void)wc_DhExportParamsRaw(&dh, pp, &a1, qq, &a2, gg, &a3);
        });

    WB_MP_SWEEP("DhSetCheckKey", 200,
        {
            DhKey k2;
            if (wc_InitDhKey(&k2) == 0) {
                (void)wc_DhSetCheckKey(&k2, p, pSz, g, gSz, q, qSz, 0, &rng);
                wc_FreeDhKey(&k2);
            }
        });

    /* GenerateParams spends its whole prefix in the prime search; the
     * residuals it owns (3365/3374) are in the g-derivation chain that runs
     * after it, so this sweep arms the TAIL of the call sequence. The seeded
     * RNG makes the sequence, and therefore the index range, reproducible. */
    WB_MP_SWEEP_TAIL("DhGenerateParams", 150,
        {
            DhKey k2;
            if (wc_InitDhKey(&k2) == 0) {
                mcdc_sr_arm(WB_DH_SEED);
                (void)wc_DhGenerateParams(&rng, 1024, &k2);
                mcdc_sr_disarm();
                wc_FreeDhKey(&k2);
            }
        });

    /* The 1024-bit fixture never takes the WOLFSSL_HAVE_SP_DH dispatch, whose
     * own mp_* chain (2222) only runs for an SP-supported prime size. Repeat
     * the agree / public-key sweeps against a named FFDHE-2048 group. */
    {
        DhKey  k2;
        byte   pv2[512];
        byte   pb2[512];
        byte   ag2[512];
        word32 s1 = (word32)sizeof(pv2);
        word32 s2 = (word32)sizeof(pb2);
        word32 s3;

        if (wc_InitDhKey(&k2) == 0) {
            if ((wc_DhSetNamedKey(&k2, WC_FFDHE_2048) == 0) &&
                (wc_DhGenerateKeyPair(&k2, &rng, pv2, &s1, pb2, &s2) == 0)) {
                WB_MP_SWEEP("DhAgree/ffdhe2048", 200,
                    {
                        s3 = (word32)sizeof(ag2);
                        (void)wc_DhAgree(&k2, ag2, &s3, pv2, s1, pb2, s2);
                    });
                WB_MP_SWEEP("DhCheckPubKey/ffdhe2048", 200,
                    (void)wc_DhCheckPubKey(&k2, pb2, s2));
            }
            wc_FreeDhKey(&k2);
        }
    }

    mcdc_fm_disarm();
    wc_FreeDhKey(&dh);
    wc_FreeRng(&rng);
    WB_NOTE("big-integer fault sweeps done");
}
#endif /* !WOLFSSL_NO_DH_GEN_PARAMS */

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("dh.c fault white-box\n");

    XMEMSET(oversized, 0, sizeof(oversized));

    test_generate_keypair_null_guards();
    test_generate_public_cascade();
    test_validate_and_pairwise();
    test_setkey_primality();
    test_import_export_keypair();
    test_cmp_named_key();
    test_dhkeycopy_null_guards();
    test_check_pub_value_null_guards();
    test_export_params_null_guards();
#ifdef WOLFSSL_HAVE_SP_DH
    test_agree_sp_dispatch();
#else
    WB_NOTE("WOLFSSL_HAVE_SP_DH not built; SP dispatch decisions "
            "(2159/2204/2210) skipped");
#endif
    test_agree_generic();
#ifdef WC_DH_NONBLOCK
    test_agree_nonblock();
#else
    WB_NOTE("WC_DH_NONBLOCK not built; nb cache decisions "
            "(2070/2085/2098/2116) skipped");
#endif
#ifndef WOLFSSL_NO_DH_GEN_PARAMS
    test_generate_params();
#else
    WB_NOTE("WOLFSSL_NO_DH_GEN_PARAMS built; parameter generation decisions "
            "(3293/3299) skipped");
#endif
    test_setkey_init_fault();
#ifndef WOLFSSL_NO_DH_GEN_PARAMS
    test_generate_params_levers();
    test_mp_fault_sweeps();
#endif

    printf("done (%s)\n", wb_fail ? "FAILURES" : "ok");
    return 0;
}

#endif /* !NO_DH */
