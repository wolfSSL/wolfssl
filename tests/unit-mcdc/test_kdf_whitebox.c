/* test_kdf_whitebox.c
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
 * MC/DC supplement for wolfcrypt/src/kdf.c.
 *
 * Four residual classes that tests/api/test_kdf.c cannot close on its own,
 * driven here with BOTH halves of every independence pair in ONE binary
 * (llvm-cov derives MC/DC per binary, so a rejection on its own proves
 * nothing):
 *
 *   1. wc_Tls13_HKDF_Extract_ex()  (~line 354)
 *          if (prk == NULL || (ikm == NULL && ikmLen > 0))
 *      A public entry point, but the campaign's group tests only ever call it
 *      with a valid prk and a present ikm, so none of the three operands gets
 *      a pair. All four call shapes are memory-safe: the guard short-circuits
 *      before either pointer is read, and the accepted "ikm == NULL &&
 *      ikmLen == 0" shape is the RFC 5869 zero-IKM case the function itself
 *      substitutes a zeroed local buffer for.
 *
 *   2. wc_PRF()  (~line 152, WOLFSSL_SMALL_STACK only)
 *          if (current == NULL || hmac == NULL)
 *      The two scratch buffers come from back-to-back XMALLOC()s that never
 *      fail in a normal run. mcdc_fault_alloc.h fails the n-th and every later
 *      allocation, which maps one-to-one onto the two operands:
 *          arm(1) -> current == NULL (and hmac == NULL) -> idx0 T
 *          arm(2) -> current != NULL, hmac == NULL      -> idx0 F, idx1 T
 *          unarmed                                       -> idx0 F, idx1 F
 *      The guard XFREEs whatever it got (XFREE(NULL) is a no-op) and returns
 *      MEMORY_E before anything dereferences the scratch, so every armed call
 *      is crash-safe.
 *
 *   3. wc_KDA_KDF_onestep()  (~line 1421, WOLFSSL_SMALL_STACK only)
 *          if (ret == 0 && outIdx < derivedSecretSz)
 *      The "ret == 0" operand needs a failed derivation iteration that still
 *      leaves outIdx short of the requested length. Faulting the first
 *      allocation inside wc_KDA_KDF_iteration() (its WC_ALLOC_VAR_EX of the
 *      wc_HashAlg scratch) makes iteration 1 return MEMORY_E, the loop breaks
 *      with outIdx still 0, and the tail guard is evaluated with (F,T).
 *
 *   4. wc_PRF() (~line 90), wc_PRF_TLSv1() (~line 239) and wc_PRF_TLS()
 *      (~line 303): the (ptr == NULL && ptrLen != 0) chains added by
 *      "Crypto layer: Add missing input validation", plus the
 *      "labLen > MAX_PRF_LABSEED" operand the same commit split out of the
 *      old "labLen + seedLen > MAX_PRF_LABSEED" bound (~line 250 / ~324).
 *      Every caller in tests/api and in the library hands these functions
 *      buffers it has already produced, so only the all-false row is ever
 *      built there. See the block comment above wb_prf_arg_guard() for why
 *      each fall-through row is memory-safe.
 *
 * Not chased in THIS file, and no longer residual: the "ret == 0 && kPad"
 * pairs in wc_SSH_KDF (~804/~855), the "(ret == 0) && ..." loop/tail guards in
 * wc_srtp_kdf_derive_key (~947/~959) and the "ret == 0 && fixedInfoSz > 0"
 * guard in wc_KDA_KDF_iteration (~1354) all require a *hash or AES transform*
 * to fail mid-operation on valid buffers, which no allocation-failure
 * injection reaches. tests/unit-mcdc/mcdc_fault_hash.h provides that lever by
 * macro interposition, but it must be included BEFORE the involved .c, which
 * this file cannot do. They are closed in the sibling translation unit
 * tests/unit-mcdc/test_kdf_hash_fault_whitebox.c instead.
 *
 * Build: compiled by the campaign's white-box step with the same MC/DC CFLAGS
 * as the instrumented library, then linked against that variant's
 * libwolfssl.a with kdf.o removed. Not part of the wolfSSL build.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <wolfcrypt/src/kdf.c>

#include "mcdc_fault_alloc.h"

#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/hash.h>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)
#define WB_EXPECT(cond, msg) \
    do { if (!(cond)) { WB_NOTE("FAIL: " msg); wb_fail = 1; } } while (0)

/* --------------------------------------------------------------------------
 * 1. wc_Tls13_HKDF_Extract_ex(): prk / ikm / ikmLen argument guard.
 * ----------------------------------------------------------------------- */
#if defined(HAVE_HKDF) && !defined(NO_HMAC) && !defined(NO_SHA256)
static void wb_tls13_hkdf_extract_guard(void)
{
    byte prk[WC_SHA256_DIGEST_SIZE];
    byte salt[WC_SHA256_DIGEST_SIZE];
    byte ikm[32];
    int  ret;

    XMEMSET(prk,  0, sizeof(prk));
    XMEMSET(salt, 0x5a, sizeof(salt));
    XMEMSET(ikm,  0x3c, sizeof(ikm));

    /* idx0 true: prk == NULL. */
    ret = wc_Tls13_HKDF_Extract_ex(NULL, salt, (word32)sizeof(salt),
        ikm, (word32)sizeof(ikm), WC_SHA256, NULL, INVALID_DEVID);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("HKDF_Extract prk==NULL not rejected");
        wb_fail = 1;
    }

    /* idx0 false, idx1 true, idx2 true: ikm absent but a length claimed. */
    ret = wc_Tls13_HKDF_Extract_ex(prk, salt, (word32)sizeof(salt),
        NULL, (word32)sizeof(ikm), WC_SHA256, NULL, INVALID_DEVID);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("HKDF_Extract ikm==NULL/ikmLen>0 not rejected");
        wb_fail = 1;
    }

    /* idx0 false, idx1 true, idx2 FALSE: the accepted zero-IKM shape. */
    ret = wc_Tls13_HKDF_Extract_ex(prk, salt, (word32)sizeof(salt),
        NULL, 0, WC_SHA256, NULL, INVALID_DEVID);
    if (ret != 0) {
        WB_NOTE("HKDF_Extract zero-length IKM unexpectedly failed");
        wb_fail = 1;
    }

    /* All-false baseline in the same binary: a real extract. */
    ret = wc_Tls13_HKDF_Extract_ex(prk, salt, (word32)sizeof(salt),
        ikm, (word32)sizeof(ikm), WC_SHA256, NULL, INVALID_DEVID);
    if (ret != 0) {
        WB_NOTE("HKDF_Extract valid call failed");
        wb_fail = 1;
    }

    WB_NOTE("wc_Tls13_HKDF_Extract_ex prk/ikm/ikmLen pairs exercised");
}
#else
static void wb_tls13_hkdf_extract_guard(void)
{ WB_NOTE("HAVE_HKDF/HMAC/SHA256 off; HKDF_Extract guard skipped"); }
#endif

/* --------------------------------------------------------------------------
 * 2. wc_PRF(): current / hmac scratch-allocation guard (small-stack only).
 * ----------------------------------------------------------------------- */
#if defined(WOLFSSL_HAVE_PRF) && !defined(NO_HMAC) && !defined(NO_SHA256) && \
    defined(WOLFSSL_SMALL_STACK) && !defined(MCDC_FA_UNAVAILABLE)
static void wb_prf_alloc_guard(void)
{
    byte result[48];
    byte secret[32];
    byte seed[32];
    int  ret;

    XMEMSET(result, 0, sizeof(result));
    XMEMSET(secret, 0x11, sizeof(secret));
    XMEMSET(seed,   0x22, sizeof(seed));

    mcdc_fa_install();

    /* idx0 true: the "current" XMALLOC fails (so does "hmac"). */
    mcdc_fa_arm(1);
    (void)wc_PRF(result, (word32)sizeof(result), secret, (word32)sizeof(secret),
        seed, (word32)sizeof(seed), sha256_mac, NULL, INVALID_DEVID);
    mcdc_fa_disarm();

    /* idx0 false, idx1 true: "current" succeeds, "hmac" fails. */
    mcdc_fa_arm(2);
    (void)wc_PRF(result, (word32)sizeof(result), secret, (word32)sizeof(secret),
        seed, (word32)sizeof(seed), sha256_mac, NULL, INVALID_DEVID);
    mcdc_fa_disarm();

    /* All-false baseline, unarmed, in the same binary. */
    ret = wc_PRF(result, (word32)sizeof(result), secret, (word32)sizeof(secret),
        seed, (word32)sizeof(seed), sha256_mac, NULL, INVALID_DEVID);
    if (ret != 0) {
        WB_NOTE("wc_PRF unarmed baseline failed");
        wb_fail = 1;
    }

    mcdc_fa_restore();
    WB_NOTE("wc_PRF current/hmac XMALLOC guard pairs exercised");
}
#else
static void wb_prf_alloc_guard(void)
{ WB_NOTE("not WOLFSSL_SMALL_STACK PRF (or no injector); wc_PRF alloc guard "
          "skipped"); }
#endif

/* --------------------------------------------------------------------------
 * 3. wc_KDA_KDF_onestep(): "ret == 0" half of the partial-block tail guard.
 * ----------------------------------------------------------------------- */
#if defined(WC_KDF_NIST_SP_800_56C) && !defined(NO_SHA256) && \
    defined(WOLFSSL_SMALL_STACK) && !defined(MCDC_FA_UNAVAILABLE)
static void wb_kda_kdf_onestep_errprop(void)
{
    byte z[32];
    byte fixedInfo[8];
    byte out[WC_SHA256_DIGEST_SIZE + 5];   /* not a whole number of blocks */
    int  ret;

    XMEMSET(z, 0x77, sizeof(z));
    XMEMSET(fixedInfo, 0x88, sizeof(fixedInfo));
    XMEMSET(out, 0, sizeof(out));

    mcdc_fa_install();

    /* Faults the wc_HashAlg scratch allocation of the FIRST iteration: the
     * loop breaks with ret != 0 and outIdx still 0, so the tail guard sees
     * (F, T). Armed around this one call; nothing else here allocates. */
    mcdc_fa_arm(1);
    (void)wc_KDA_KDF_onestep(z, (word32)sizeof(z), fixedInfo,
        (word32)sizeof(fixedInfo), (word32)sizeof(out), WC_HASH_TYPE_SHA256,
        out, (word32)sizeof(out));
    mcdc_fa_disarm();

    /* All-true baseline, unarmed: ret == 0 and a genuine partial tail block. */
    ret = wc_KDA_KDF_onestep(z, (word32)sizeof(z), fixedInfo,
        (word32)sizeof(fixedInfo), (word32)sizeof(out), WC_HASH_TYPE_SHA256,
        out, (word32)sizeof(out));
    if (ret != 0) {
        WB_NOTE("wc_KDA_KDF_onestep unarmed baseline failed");
        wb_fail = 1;
    }

    mcdc_fa_restore();
    WB_NOTE("wc_KDA_KDF_onestep tail-guard ret==0 pair exercised");
}
#else
static void wb_kda_kdf_onestep_errprop(void)
{ WB_NOTE("WC_KDF_NIST_SP_800_56C/small-stack off; KDA tail guard skipped"); }
#endif

/* --------------------------------------------------------------------------
 * 4. wc_PRF() / wc_PRF_TLSv1() / wc_PRF_TLS(): the pointer/length argument
 *    guards, plus the labLen bound they made reachable.
 * ----------------------------------------------------------------------- */
#if defined(WOLFSSL_HAVE_PRF) && !defined(NO_HMAC) && !defined(NO_SHA256)

/* Every operand of these guards is one half of an (x == NULL && xLen != 0)
 * pair, so each pair needs three rows in this binary:
 *   (T,T) x absent with a length claimed      -> decision TRUE
 *   (T,F) x absent with a zero length          -> decision FALSE
 *   (F,-) x present                            -> decision FALSE
 * The (T,F) rows fall THROUGH the guard, so each one is chosen so the
 * function still cannot dereference the absent pointer:
 *   - result/digest absent with a zero length: wc_PRF() computes times == 0
 *     from resLen == 0 and returns BAD_FUNC_ARG before the first XMALLOC.
 *   - secret absent with a zero length: paired with labLen > MAX_PRF_LABSEED
 *     so the size check (kdf.c:250 / :324) returns BUFFER_E before
 *     "md5_half = secret" / before wc_PRF() is called. That same row is the
 *     TRUE half of the labLen bound, which is otherwise unreachable.
 *   - label/seed absent with a zero length: the "if (labLen != 0)" /
 *     "if (seedLen != 0)" copies that the same upstream commit added are
 *     skipped, which is exactly the shape the guard is there to admit.
 */

/* Past MAX_PRF_LABSEED, so kdf.c:250:1 / :324:0 is the operand that trips. */
#define WB_PRF_LAB_BIG (MAX_PRF_LABSEED + 72)

static void wb_prf_arg_guard(void)
{
    byte dig[32];
    byte sec[32];
    byte seed[32];
    byte lab[WB_PRF_LAB_BIG];
    const word32 digLen  = (word32)sizeof(dig);
    const word32 secLen  = (word32)sizeof(sec);
    const word32 seedLen = (word32)sizeof(seed);
    const word32 labLen  = 16;
    const word32 labBig  = (word32)sizeof(lab);
    int ret;

    XMEMSET(dig,  0, sizeof(dig));
    XMEMSET(sec,  0x11, sizeof(sec));
    XMEMSET(seed, 0x22, sizeof(seed));
    XMEMSET(lab,  0x33, sizeof(lab));

    /* ---- wc_PRF(), kdf.c:90 ---- */

    ret = wc_PRF(NULL, digLen, sec, secLen, seed, seedLen, sha256_mac, NULL,
        INVALID_DEVID);
    WB_EXPECT(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "PRF result==NULL");

    ret = wc_PRF(NULL, 0, sec, secLen, seed, seedLen, sha256_mac, NULL,
        INVALID_DEVID);
    WB_EXPECT(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
        "PRF result==NULL/resLen==0");

    ret = wc_PRF(dig, digLen, NULL, secLen, seed, seedLen, sha256_mac, NULL,
        INVALID_DEVID);
    WB_EXPECT(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "PRF secret==NULL");

    ret = wc_PRF(dig, 0, NULL, 0, seed, seedLen, sha256_mac, NULL,
        INVALID_DEVID);
    WB_EXPECT(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
        "PRF secret==NULL/secLen==0");

    ret = wc_PRF(dig, digLen, sec, secLen, NULL, seedLen, sha256_mac, NULL,
        INVALID_DEVID);
    WB_EXPECT(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "PRF seed==NULL");

    ret = wc_PRF(dig, 0, sec, secLen, NULL, 0, sha256_mac, NULL,
        INVALID_DEVID);
    WB_EXPECT(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
        "PRF seed==NULL/seedLen==0");

    /* All-false row, same binary. */
    ret = wc_PRF(dig, digLen, sec, secLen, seed, seedLen, sha256_mac, NULL,
        INVALID_DEVID);
    WB_EXPECT(ret == 0, "PRF all-valid baseline");

    /* ---- wc_PRF_TLSv1(), kdf.c:239 and the :249 labLen bound ---- */

    ret = wc_PRF_TLSv1(NULL, digLen, sec, secLen, lab, labLen, seed, seedLen,
        NULL, INVALID_DEVID);
    WB_EXPECT(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "TLSv1 digest==NULL");

    ret = wc_PRF_TLSv1(NULL, 0, sec, secLen, lab, labLen, seed, seedLen,
        NULL, INVALID_DEVID);
    WB_EXPECT(ret != 0, "TLSv1 digest==NULL/digLen==0 falls through");

    ret = wc_PRF_TLSv1(dig, digLen, NULL, secLen, lab, labLen, seed, seedLen,
        NULL, INVALID_DEVID);
    WB_EXPECT(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "TLSv1 secret==NULL");

    /* secLen == 0 falls through the guard; labBig then trips :249:1. */
    ret = wc_PRF_TLSv1(dig, digLen, NULL, 0, lab, labBig, seed, seedLen,
        NULL, INVALID_DEVID);
    WB_EXPECT(ret == WC_NO_ERR_TRACE(BUFFER_E), "TLSv1 labLen>MAX_PRF_LABSEED");

    ret = wc_PRF_TLSv1(dig, digLen, sec, secLen, NULL, labLen, seed, seedLen,
        NULL, INVALID_DEVID);
    WB_EXPECT(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "TLSv1 label==NULL");

    ret = wc_PRF_TLSv1(dig, digLen, sec, secLen, NULL, 0, seed, seedLen,
        NULL, INVALID_DEVID);
#if !defined(NO_MD5) && !defined(NO_SHA)
    WB_EXPECT(ret == 0, "TLSv1 label==NULL/labLen==0 accepted");
#endif

    ret = wc_PRF_TLSv1(dig, digLen, sec, secLen, lab, labLen, NULL, seedLen,
        NULL, INVALID_DEVID);
    WB_EXPECT(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "TLSv1 seed==NULL");

    ret = wc_PRF_TLSv1(dig, digLen, sec, secLen, lab, labLen, NULL, 0,
        NULL, INVALID_DEVID);
#if !defined(NO_MD5) && !defined(NO_SHA)
    WB_EXPECT(ret == 0, "TLSv1 seed==NULL/seedLen==0 accepted");
#endif

    ret = wc_PRF_TLSv1(dig, digLen, sec, secLen, lab, labLen, seed, seedLen,
        NULL, INVALID_DEVID);
#if !defined(NO_MD5) && !defined(NO_SHA)
    WB_EXPECT(ret == 0, "TLSv1 all-valid baseline");
#endif

    /* ---- wc_PRF_TLS(), kdf.c:303 and the :324 labLen bound ---- */

    ret = wc_PRF_TLS(NULL, digLen, sec, secLen, lab, labLen, seed, seedLen,
        1, sha256_mac, NULL, INVALID_DEVID);
    WB_EXPECT(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "TLS digest==NULL");

    ret = wc_PRF_TLS(NULL, 0, sec, secLen, lab, labLen, seed, seedLen,
        1, sha256_mac, NULL, INVALID_DEVID);
    WB_EXPECT(ret != 0, "TLS digest==NULL/digLen==0 falls through");

    ret = wc_PRF_TLS(dig, digLen, NULL, secLen, lab, labLen, seed, seedLen,
        1, sha256_mac, NULL, INVALID_DEVID);
    WB_EXPECT(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "TLS secret==NULL");

    /* secLen == 0 falls through the guard; labBig then trips :324:0. */
    ret = wc_PRF_TLS(dig, digLen, NULL, 0, lab, labBig, seed, seedLen,
        1, sha256_mac, NULL, INVALID_DEVID);
    WB_EXPECT(ret == WC_NO_ERR_TRACE(BUFFER_E), "TLS labLen>MAX_PRF_LABSEED");

    ret = wc_PRF_TLS(dig, digLen, sec, secLen, NULL, labLen, seed, seedLen,
        1, sha256_mac, NULL, INVALID_DEVID);
    WB_EXPECT(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "TLS label==NULL");

    ret = wc_PRF_TLS(dig, digLen, sec, secLen, NULL, 0, seed, seedLen,
        1, sha256_mac, NULL, INVALID_DEVID);
    WB_EXPECT(ret == 0, "TLS label==NULL/labLen==0 accepted");

    ret = wc_PRF_TLS(dig, digLen, sec, secLen, lab, labLen, NULL, seedLen,
        1, sha256_mac, NULL, INVALID_DEVID);
    WB_EXPECT(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "TLS seed==NULL");

    ret = wc_PRF_TLS(dig, digLen, sec, secLen, lab, labLen, NULL, 0,
        1, sha256_mac, NULL, INVALID_DEVID);
    WB_EXPECT(ret == 0, "TLS seed==NULL/seedLen==0 accepted");

    ret = wc_PRF_TLS(dig, digLen, sec, secLen, lab, labLen, seed, seedLen,
        1, sha256_mac, NULL, INVALID_DEVID);
    WB_EXPECT(ret == 0, "TLS all-valid baseline");

    WB_NOTE("wc_PRF/wc_PRF_TLSv1/wc_PRF_TLS argument-guard pairs exercised");
}
#else
static void wb_prf_arg_guard(void)
{ WB_NOTE("WOLFSSL_HAVE_PRF/HMAC/SHA256 off; PRF argument guards skipped"); }
#endif

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("kdf.c white-box MC/DC supplement\n");

    wb_tls13_hkdf_extract_guard();
    wb_prf_alloc_guard();
    wb_kda_kdf_onestep_errprop();
    wb_prf_arg_guard();

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Always 0: a nonzero exit discards this variant's whole coverage. */
    (void)wb_fail;
    return 0;
}
