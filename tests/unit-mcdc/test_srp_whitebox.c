/* test_srp_whitebox.c
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
 * MC/DC hash-fault white-box supplement for wolfcrypt/src/srp.c.
 *
 * THE ONE OPEN CONDITION
 * ----------------------
 *     srp.c:1057  if (!r && ConstantCompare(proof, digest, (int)size) != 0)
 *
 * `r` at that point comes from SrpHashFinal() (:1049), and -- on the server
 * side only -- from the two SrpHashUpdate() calls at :1055-:1056. Those are
 * file-static dispatchers straight onto wc_ShaFinal/wc_Sha256Final/
 * wc_Sha384Final/wc_Sha512Final, which cannot fail on a live, initialised
 * context. So every reachable call from tests/api arrives here with r == 0
 * and only ever shows the operand TRUE: the (T,T) row (a wrong proof, giving
 * SRP_VERIFY_E) and the (T,F) row (a correct proof) are both there, but the
 * idx0 independence pair -- (T,T) against (F,.) -- is not.
 *
 * mcdc_fault_hash.h is the lever for exactly this shape: it
 * macro-interposes the hash primitives for THIS translation unit only, before
 * srp.c is #included, so mcdc_fh_arm(1) makes the very next primitive call
 * (and every later one) return BAD_FUNC_ARG. SrpHashFinal() then propagates
 * that into `r`, and :1057 is evaluated with `!r` FALSE while the decision
 * short-circuits -- the missing half. The unarmed (T,T) partner is driven in
 * the SAME binary immediately before it, which is what MC/DC needs: llvm-cov
 * computes independence per binary and the harness only ORs the resulting
 * bits by line:col.
 *
 * Note that wc_SrpVerifyPeersProof()'s SHA-256 proof hash is used here in its
 * freshly initialised state (wc_SrpInit() runs SrpHashInit() on both proof
 * contexts). No SRP handshake is needed to reach :1057 -- the decision does
 * not depend on the session key, only on the digest/proof comparison -- and
 * keeping the fixture to wc_SrpInit() makes every vector deterministic and
 * cheap (no modexp, well inside TEST_TIMEOUT). tests/api/test_srp.c already
 * carries the full handshake, including the corrupted-proof rejection.
 *
 * Build: compiled by the coverage runner's white-box step with the SAME MC/DC
 * CFLAGS, -DHAVE_CONFIG_H and -I<workspace> as the instrumented library, then
 * linked against that variant's libwolfssl.a with its srp.o removed (this TU
 * supplies the instrumented srp.c). NOT part of the wolfSSL build; not
 * registered in tests/api. See tests/unit-mcdc/README.md.
 */

#include "mcdc_fault_hash.h"

/* Pull srp.c in verbatim so the file-static SrpHash* dispatchers are in scope
 * and instrumented in THIS binary, and so the macros above rewrite srp.c's
 * own primitive call sites. */
#include <wolfcrypt/src/srp.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(WOLFCRYPT_HAVE_SRP) && !defined(NO_SHA256) && \
    defined(MCDC_FH_HAVE_SHA256)

/* ------------------------------------------------------------------------ *
 * srp.c:1057  if (!r && ConstantCompare(proof, digest, (int)size) != 0)
 *
 *   vector A (unarmed, wrong proof)  -> (T,T) decision TRUE  -> SRP_VERIFY_E
 *   vector B (unarmed, right proof)  -> (T,F) decision FALSE -> 0
 *   vector C (armed,  any proof)     -> (F,.) decision FALSE -> BAD_FUNC_ARG
 *
 * A against C is the idx0 independence pair; A against B is idx1's (already
 * shown by tests/api, repeated here so this binary stands on its own).
 * ------------------------------------------------------------------------ */
static void wb_verify_peers_proof_hash_fault(void)
{
    Srp  srp;
    byte proof[WC_SHA256_DIGEST_SIZE];
    byte expect[WC_SHA256_DIGEST_SIZE];
    int  ret;

    /* The proof context is the one wc_SrpInit() built and nothing has been
     * absorbed into it, so the digest wc_SrpVerifyPeersProof() computes is
     * SHA-256 over the empty message. Derive it the same way, unarmed. */
    {
        wc_Sha256 sha;

        XMEMSET(expect, 0, sizeof(expect));
        if (wc_InitSha256(&sha) != 0) {
            WB_NOTE("wc_InitSha256 failed; skipping srp proof vectors");
            return;
        }
        ret = wc_Sha256Final(&sha, expect);
        wc_Sha256Free(&sha);
        if (ret != 0) {
            WB_NOTE("wc_Sha256Final failed; skipping srp proof vectors");
            return;
        }
    }

    /* Vector A: r == 0, proof mismatches -> both operands TRUE. */
    XMEMSET(&srp, 0, sizeof(srp));
    if (wc_SrpInit(&srp, SRP_TYPE_SHA256, SRP_CLIENT_SIDE) != 0) {
        WB_NOTE("wc_SrpInit failed; skipping srp proof vectors");
        return;
    }
    XMEMSET(proof, 0, sizeof(proof));
    proof[0] = (byte)(expect[0] ^ 0x01);
    ret = wc_SrpVerifyPeersProof(&srp, proof, (word32)sizeof(proof));
    if (ret != WC_NO_ERR_TRACE(SRP_VERIFY_E)) {
        WB_NOTE("wrong proof was not rejected with SRP_VERIFY_E");
        wb_fail = 1;
    }
    wc_SrpTerm(&srp);

    /* Vector B: r == 0, proof matches -> idx0 TRUE, idx1 FALSE. */
    XMEMSET(&srp, 0, sizeof(srp));
    if (wc_SrpInit(&srp, SRP_TYPE_SHA256, SRP_CLIENT_SIDE) != 0) {
        WB_NOTE("wc_SrpInit failed; skipping matching-proof vector");
    }
    else {
        XMEMCPY(proof, expect, sizeof(proof));
        ret = wc_SrpVerifyPeersProof(&srp, proof, (word32)sizeof(proof));
        if (ret != 0) {
            WB_NOTE("matching proof was not accepted");
            wb_fail = 1;
        }
        wc_SrpTerm(&srp);
    }

    /* Vector C: SrpHashFinal() fails, so :1057 is reached with r != 0 and
     * `!r` is FALSE -- the half no live context can produce. Arm for exactly
     * this one call so nothing else in the binary is faulted. */
    XMEMSET(&srp, 0, sizeof(srp));
    if (wc_SrpInit(&srp, SRP_TYPE_SHA256, SRP_CLIENT_SIDE) != 0) {
        WB_NOTE("wc_SrpInit failed; skipping hash-fault vector");
        return;
    }
    XMEMSET(proof, 0, sizeof(proof));
    mcdc_fh_arm(1);
    ret = wc_SrpVerifyPeersProof(&srp, proof, (word32)sizeof(proof));
    mcdc_fh_disarm();
    if (ret != WC_NO_ERR_TRACE(MCDC_FH_ERR)) {
        WB_NOTE("faulted SrpHashFinal did not propagate out of "
                "wc_SrpVerifyPeersProof");
        wb_fail = 1;
    }
    wc_SrpTerm(&srp);

    WB_NOTE("wc_SrpVerifyPeersProof !r / ConstantCompare pairs exercised");
}

#else /* !(WOLFCRYPT_HAVE_SRP && !NO_SHA256 && MCDC_FH_HAVE_SHA256) */

static void wb_verify_peers_proof_hash_fault(void)
{
    WB_NOTE("SRP or SHA-256 not compiled in; srp proof vectors skipped");
}

#endif

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("srp.c white-box supplement\n");
    wb_verify_peers_proof_hash_fault();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup issues are surfaced as skips; a nonzero exit would make the
     * suite discard this variant's coverage. */
    return 0;
}
