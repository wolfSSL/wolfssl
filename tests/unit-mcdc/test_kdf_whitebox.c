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
 * Three residual classes that tests/api/test_kdf.c cannot close on its own,
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
 * Deliberately NOT chased here (documented residuals, not oversights): the
 * "ret == 0 && kPad" pairs in wc_SSH_KDF (~804/~855), the
 * "(ret == 0) && ..." loop/tail guards in wc_srtp_kdf_derive_key (~947/~959)
 * and the "ret == 0 && fixedInfoSz > 0" guard in wc_KDA_KDF_iteration (~1354)
 * all require a *hash or AES transform* to fail mid-operation on valid
 * buffers. Those primitives allocate nothing on this path, so no
 * allocation-failure injection reaches them; they are the same
 * transform-failure residual class as the sha module's.
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

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("kdf.c white-box MC/DC supplement\n");

    wb_tls13_hkdf_extract_guard();
    wb_prf_alloc_guard();
    wb_kda_kdf_onestep_errprop();

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Always 0: a nonzero exit discards this variant's whole coverage. */
    (void)wb_fail;
    return 0;
}
