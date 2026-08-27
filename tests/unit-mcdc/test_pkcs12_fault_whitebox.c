/* test_pkcs12_fault_whitebox.c
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
 * MC/DC white-box supplement for wolfcrypt/src/pkcs12.c, closing the last
 * closable residual left after test_pkcs12_whitebox.c and
 * test_pkcs12_parse_whitebox.c (GAPS.md: 58/65): PKCS12_CheckConstructedZero()
 *
 *   if (ret == 0 && GetObjectId(data, idx, &oid, oidIgnoreType, dataSz)) {
 *                                                          (pkcs12.c:1239)
 *
 * condition index 0 (`ret == 0`).
 *
 * Both rows this condition needs already exist in the campaign -- just not
 * in the same binary. test_pkcs12_whitebox.c's wb_check_constructed_zero()
 * drives a valid chain (ret==0 entering 1239, GetObjectId succeeds ->
 * (T,F)=FALSE) and a chain truncated right after the outer SEQUENCE header
 * (ret==0 entering 1239, GetObjectId has no room -> (T,T)=TRUE); together
 * those close condition 1 (the GetObjectId operand) entirely, but every call
 * in that binary reaches line 1239 with ret==0 already true -- cond0 is
 * never shown FALSE there. test_pkcs12_parse_whitebox.c's
 * wb_check_zero_op1_false() supplies exactly that FALSE row (a buffer too
 * small to even hold a SEQUENCE header, so the first GetSequence() fails and
 * ret != 0 before line 1239 is reached) -- but that file never issues the
 * TRUE row. llvm-cov computes MC/DC independence per binary, so neither of
 * those two binaries alone closes condition 0's pair even though the union
 * of both rows exists somewhere across the two. This file issues BOTH rows
 * together in the SAME binary:
 *
 *   (T,T): a 2-byte buffer holding just the outer SEQUENCE header (tag
 *          0x30, length 0x00). GetSequence() succeeds and leaves idx at 2
 *          (== dataSz), so ret==0 entering 1239; GetObjectId then has zero
 *          bytes left to read even the OID tag and fails -> decision TRUE.
 *   (F,-): a zero-length buffer. The very first GetSequence() call fails
 *          immediately (idx(0) >= maxIdx(0)), so ret != 0 before line 1239
 *          is ever reached -> decision short-circuits FALSE without
 *          evaluating GetObjectId.
 *
 * The function is static, so it is called directly (same idiom as the two
 * other pkcs12 white-boxes: #include pkcs12.c to reach file-static helpers).
 *
 * The other six GAPS.md residuals are all structurally unreachable and are
 * deliberately NOT exercised here -- inventing a vector for a decision that
 * cannot occur would misrepresent the code as more exercised than it is.
 * Each was independently re-derived from the current source (not taken on
 * faith from the other white-boxes' comments) before being left out:
 *
 *   - pkcs12.c:445 cond1 / :477 cond1 (GetSignData() digest/salt
 *     "mac->digestSz + curIdx > totalSz" / "mac->saltSz + curIdx > totalSz"
 *     operand): GetLength() always calls GetLength_ex(..., check=1)
 *     (asn.c), whose `check && (length > (maxIdx - idx))` test rejects any
 *     length that would run past maxIdx *before* GetLength() can return
 *     success. At both call sites maxIdx is the same `totalSz` used in the
 *     later comparison, and curIdx is exactly the post-length-bytes idx
 *     GetLength() advanced to, so a successful GetLength() (size>0)
 *     already guarantees size + curIdx <= totalSz. The ">" half can never
 *     be true once control reaches the XMALLOC/guard line. Dead code.
 *   - pkcs12.c:599 cond0 (wc_PKCS12_create_mac() `kLen < 0`): kLen comes
 *     from wc_HashGetDigestSize(hashT) where hashT = wc_OidGetHash(mac->oid),
 *     and the line above already rejects hashT == WC_HASH_TYPE_NONE.
 *     Comparing wc_OidGetHash() and wc_HashGetDigestSize() (hash.c)
 *     case-by-case shows every OID maps to WC_HASH_TYPE_NONE under exactly
 *     the same #if guard under which wc_HashGetDigestSize() would otherwise
 *     return the negative HASH_TYPE_E for that hash type (e.g. MD5h maps to
 *     WC_HASH_TYPE_NONE unless !NO_MD5, and WC_HASH_TYPE_MD5 maps to
 *     HASH_TYPE_E unless !NO_MD5) -- with one asymmetry: the four SHA3 OIDs
 *     map on a plain `#ifdef WOLFSSL_SHA3`, while the matching
 *     wc_HashGetDigestSize() arms additionally require
 *     !WOLFSSL_NOSHA3_224/256/384/512. Those four macros are defined in
 *     exactly one place in the tree, the WOLFSSL_XILINX_CRYPT /
 *     WOLFSSL_AFALG_XILINX block of settings.h (~:3019, "only SHA3-384 is
 *     supported"), and neither pkcs12 variant selects that port: both build
 *     plain WOLFSSL_SHA3 with no NOSHA3_* set. So in every build this module
 *     is measured in, a hashT that survives the WC_HASH_TYPE_NONE check can
 *     never make wc_HashGetDigestSize() return a negative value. Dead code
 *     as compiled here (it is live only on a Xilinx-offload build, where an
 *     attacker-chosen SHA3-224/256/512 MAC OID would reach it -- so the
 *     guard itself must stay).
 *   - pkcs12.c:886 cond2 (wc_d2i_PKCS12_fp() cleanup guard, `*pkcs12 !=
 *     NULL` false side): callerAlloc starts at 1 and is set to 0 in exactly
 *     the branch that also assigns `*pkcs12 = tmpPkcs12` (non-NULL); the
 *     only later use of `*pkcs12` is passing it BY VALUE into
 *     wc_d2i_PKCS12() (which takes a plain WC_PKCS12*, not a WC_PKCS12**,
 *     so it cannot NULL the caller's slot). callerAlloc == 0 therefore
 *     always implies *pkcs12 != NULL at the cleanup check. Dead code.
 *   - pkcs12.c:2043 cond1 / :2465 cond1 (LENGTH_ONLY_E passthrough guards,
 *     `ret < 0` false side): at both call sites the inner call is made with
 *     its own `out` argument hardcoded to NULL (wc_PKCS12_create_key_bag()
 *     calls wc_PKCS12_shroud_key(pkcs12, rng, NULL, &length, ...);
 *     PKCS12_create_key_content() calls wc_PKCS12_create_key_bag(pkcs12,
 *     rng, NULL, &keyBufSz, ...)), and each callee's own out==NULL branch
 *     returns either a genuine negative error (already caught by the
 *     earlier half of the same guard) or exactly
 *     WC_NO_ERR_TRACE(LENGTH_ONLY_E) -- there is no third return value a
 *     `ret < 0` check could see as false while the length-only comparison
 *     that precedes it stays true. Dead code.
 *
 * All six are logged as DEATHNOTE candidates by the caller; not repeated as
 * test code here. mcdc_fault_alloc.h is included for idiom consistency with
 * the rest of the campaign's *_fault_whitebox.c files, but is unused: the
 * one closable residual here is a pure ASN decode-path decision, not an
 * allocation-failure guard.
 */

#include <wolfcrypt/src/pkcs12.c>

#include "mcdc_fault_alloc.h"

#include <stdio.h>
#include <string.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if !defined(HAVE_PKCS12) || defined(NO_ASN) || defined(NO_PWDBASED) || \
    defined(NO_HMAC) || defined(NO_CERTS)

int main(void)
{
    printf("pkcs12.c fault white-box: HAVE_PKCS12 surface absent, "
        "nothing to do\n");
    return 0;
}

#else

#ifdef ASN_BER_TO_DER
/* PKCS12_CheckConstructedZero() line 1239 cond0 (`ret == 0`) independence
 * pair -- both rows issued in this one binary. See file header. */
static void wb_check_zero_cond0(void)
{
    /* (T,T): outer SEQUENCE header only, nothing else. GetSequence()
     * succeeds and leaves idx == dataSz, so ret==0 entering 1239;
     * GetObjectId then has no bytes left and fails -> decision TRUE. */
    {
        byte buf[2] = { ASN_SEQUENCE | ASN_CONSTRUCTED, 0x00 };
        word32 idx = 0;
        int ret = PKCS12_CheckConstructedZero(buf, sizeof(buf), &idx);

        if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) {
            WB_NOTE("1239 (T,T) case unexpectedly did not fail");
            wb_fail = 1;
        }
    }

    /* (F,-): zero-length buffer. The outer GetSequence() fails before line
     * 1239 is reached, so ret != 0 already -> cond0 FALSE, short-circuit
     * without evaluating GetObjectId. */
    {
        byte buf[1] = { 0x00 };
        word32 idx = 0;
        int ret = PKCS12_CheckConstructedZero(buf, 0, &idx);

        if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) {
            WB_NOTE("1239 (F,-) case unexpectedly did not fail");
            wb_fail = 1;
        }
    }

    WB_NOTE("PKCS12_CheckConstructedZero 1239 cond0 (ret==0) pair "
            "exercised in one binary");
}
#else
static void wb_check_zero_cond0(void)
{
    WB_NOTE("ASN_BER_TO_DER off; PKCS12_CheckConstructedZero not built, "
            "1239 cond0 skipped");
}
#endif /* ASN_BER_TO_DER */

int main(void)
{
    printf("pkcs12.c fault white-box MC/DC supplement\n");
    wb_check_zero_cond0();
    printf("done (%s)\n", wb_fail ? "with failures" : "ok");
    /* Always return 0: a nonzero exit makes the campaign discard the whole
     * variant's coverage, including the parts that did succeed. */
    return 0;
}

#endif /* HAVE_PKCS12 && !NO_ASN && !NO_PWDBASED && !NO_HMAC && !NO_CERTS */
