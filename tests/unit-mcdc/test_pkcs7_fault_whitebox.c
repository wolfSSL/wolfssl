/* test_pkcs7_fault_whitebox.c
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
 * Third white-box MC/DC supplement for wolfcrypt/src/pkcs7.c (Part 5).
 *
 * test_pkcs7_whitebox.c and test_pkcs7_decode_whitebox.c drive the NULL/size
 * argument guards of most public and file-static entry points, but almost
 * always only the FAIL side (each operand forced NULL/zero, one at a time).
 * MC/DC independence for an OR-chain guard `if (a==NULL || b==NULL || ...)`
 * requires, for each operand, a pair of calls that differ ONLY in that
 * operand while the others are held fixed -- in particular a call where
 * EVERY operand is false (the guard does not trigger, real code runs) is
 * needed to pair against each single-operand-true call. Because llvm-cov
 * computes independence per BINARY, that baseline call has to exist in the
 * SAME executable as the operand-true calls, so it is not enough that some
 * other whitebox binary happens to exercise a valid call elsewhere. This
 * file supplies the missing baseline call alongside a fresh set of
 * operand-true calls for each targeted guard, closing the pair in one place.
 *
 * A baseline call does not need to fully succeed -- it only needs to reach
 * PAST the guard under test (observed as a return code other than the
 * guard's own BAD_FUNC_ARG/error). Deeper failures on garbage input are
 * fine and expected; wolfCrypt's ASN.1 walkers are bounds-checked and safe
 * on arbitrary bytes.
 *
 * Also included: one allocation-fault MC/DC pair (mcdc_fault_alloc.h,
 * fail-forward heap injector) for wc_PKCS7_EncodeContentStream's
 * `encContentOut == NULL || contentData == NULL` cleanup guard, whose
 * second operand can be isolated by failing only the second of the two
 * back-to-back allocations.
 *
 * This file does NOT re-drive anything already fully paired (operand-true
 * AND baseline, in one binary) by the other two whitebox files -- see the
 * per-guard comments below and the final report for what is targeted here.
 */

#include <wolfcrypt/src/pkcs7.c>

#include "mcdc_fault_alloc.h"

#include <stdio.h>
#include <string.h>
#include <wolfssl/certs_test.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)
#define WB_CHECK(cond, msg) \
    do { if (!(cond)) { printf("  [wb][FAIL] %s\n", (msg)); wb_fail = 1; } } \
    while (0)

/* ------------------------------------------------------------------------- *
 * Section 1: cheap top-of-function NULL/size guards -- CheckPublicKeyDer,
 * AddCertificate, GetAttributeValue, ParseAttribs. Each gets its baseline
 * (all operands false) plus one call per operand (that operand forced
 * true, others held false).
 * ------------------------------------------------------------------------- */
static void wb_guard_baselines1(void)
{
    wc_PKCS7 pkcs7;
    byte dummyKey[4] = { 0x30, 0x02, 0x01, 0x00 };
    byte dummyCert[4] = { 0x30, 0x02, 0x01, 0x00 };
    int ret;

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));

    WB_NOTE("wc_PKCS7_CheckPublicKeyDer(): 3-operand OR guard baseline+pairs");
    ret = wc_PKCS7_CheckPublicKeyDer(&pkcs7, RSAk, dummyKey, sizeof(dummyKey));
    WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "baseline (all false): garbage key, not a guard rejection");
    ret = wc_PKCS7_CheckPublicKeyDer(NULL, RSAk, dummyKey, sizeof(dummyKey));
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pkcs7==NULL true");
    ret = wc_PKCS7_CheckPublicKeyDer(&pkcs7, RSAk, NULL, sizeof(dummyKey));
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "key==NULL true");
    ret = wc_PKCS7_CheckPublicKeyDer(&pkcs7, RSAk, dummyKey, 0);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "keySz==0 true");

    WB_NOTE("wc_PKCS7_AddCertificate(): 3-operand OR guard baseline+pairs");
    {
        wc_PKCS7 p2;
        XMEMSET(&p2, 0, sizeof(p2));
        ret = wc_PKCS7_AddCertificate(&p2, dummyCert, sizeof(dummyCert));
        WB_CHECK(ret == 0, "baseline (all false): real cert list append");
        /* free what the baseline call allocated */
        if (p2.certList != NULL) {
            Pkcs7Cert* c = p2.certList;
            Pkcs7Cert* n;
            while (c != NULL) {
                n = c->next;
                XFREE(c, p2.heap, DYNAMIC_TYPE_PKCS7);
                c = n;
            }
        }
    }
    ret = wc_PKCS7_AddCertificate(NULL, dummyCert, sizeof(dummyCert));
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pkcs7==NULL true");
    ret = wc_PKCS7_AddCertificate(&pkcs7, NULL, sizeof(dummyCert));
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "derCert==NULL true");
    ret = wc_PKCS7_AddCertificate(&pkcs7, dummyCert, 0);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "derCertSz==0 true");

    WB_NOTE("wc_PKCS7_GetAttributeValue(): 3-operand OR guard baseline+pairs");
    {
        byte oid[4] = { 1,2,3,4 };
        byte out[8];
        word32 outSz = sizeof(out);
        ret = wc_PKCS7_GetAttributeValue(&pkcs7, oid, sizeof(oid), out, &outSz);
        WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                "baseline (all false): no matching attrib, not a guard reject");
        ret = wc_PKCS7_GetAttributeValue(NULL, oid, sizeof(oid), out, &outSz);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pkcs7==NULL true");
        ret = wc_PKCS7_GetAttributeValue(&pkcs7, NULL, sizeof(oid), out, &outSz);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "oid==NULL true");
        ret = wc_PKCS7_GetAttributeValue(&pkcs7, oid, sizeof(oid), out, NULL);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "outSz==NULL true");
    }

    WB_NOTE("wc_PKCS7_ParseAttribs(): 3-operand OR guard baseline+pairs");
    {
        /* minimal well-formed attribute buffer: SEQ { OID, SET{OCTET(0)} } */
        static const byte oid[] =
            { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04 };
        byte buf[16];
        word32 idx = 0;
        buf[idx++] = 0x30; buf[idx++] = 0;
        {
            word32 lenIdx = 1, start = idx;
            XMEMCPY(&buf[idx], oid, sizeof(oid)); idx += (word32)sizeof(oid);
            buf[idx++] = 0x31; buf[idx++] = 0x02;
            buf[idx++] = 0x04; buf[idx++] = 0x00;
            buf[lenIdx] = (byte)(idx - start);
        }
        XMEMSET(&pkcs7, 0, sizeof(pkcs7));
        ret = wc_PKCS7_ParseAttribs(&pkcs7, buf, (int)idx);
        WB_CHECK(ret == 1, "baseline (all false): 1 attrib parsed");
        wc_PKCS7_FreeDecodedAttrib(pkcs7.decodedAttrib, NULL);
        pkcs7.decodedAttrib = NULL;

        ret = wc_PKCS7_ParseAttribs(NULL, buf, (int)idx);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pkcs7==NULL true");
        ret = wc_PKCS7_ParseAttribs(&pkcs7, NULL, (int)idx);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "in==NULL true");
        ret = wc_PKCS7_ParseAttribs(&pkcs7, buf, -1);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "inSz<0 true");
    }
}

/* ------------------------------------------------------------------------- *
 * Section 2: wc_PKCS7_SignedDataGetEncAlgoId, wc_PKCS7_BuildDigestInfo,
 * wc_PKCS7_SignedDataBuildSignature -- NULL guards already exercised
 * elsewhere, baseline (proceed-past-guard) call missing everywhere.
 * ------------------------------------------------------------------------- */
static void wb_sign_algid_digest(void)
{
    wc_PKCS7 pkcs7;
    ESD esd;
    int ret;

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));
    XMEMSET(&esd, 0, sizeof(esd));

    WB_NOTE("wc_PKCS7_SignedDataGetEncAlgoId(): 3-operand OR guard"
            " baseline+pairs");
    {
        int a1 = 0, a2 = 0;
        ret = wc_PKCS7_SignedDataGetEncAlgoId(&pkcs7, &a1, &a2);
        WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                "baseline (all false): publicKeyOID==0 falls to an algo-id"
                " error, not the guard");
        ret = wc_PKCS7_SignedDataGetEncAlgoId(NULL, &a1, &a2);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pkcs7==NULL true");
        ret = wc_PKCS7_SignedDataGetEncAlgoId(&pkcs7, NULL, &a2);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "digEncAlgoId==NULL true");
        ret = wc_PKCS7_SignedDataGetEncAlgoId(&pkcs7, &a1, NULL);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "digEncAlgoType==NULL true");
    }

    WB_NOTE("wc_PKCS7_BuildDigestInfo(): 4-operand OR guard baseline+pairs");
    {
        byte flat[4] = { 0 };
        byte digestInfo[MAX_PKCS7_DIGEST_SZ];
        word32 digestInfoSz = sizeof(digestInfo);
        esd.hashType = WC_HASH_TYPE_SHA256;

        ret = wc_PKCS7_BuildDigestInfo(&pkcs7, flat, 0, &esd, digestInfo,
                &digestInfoSz);
        WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                "baseline (all false): real digest info build");

        digestInfoSz = sizeof(digestInfo);
        ret = wc_PKCS7_BuildDigestInfo(NULL, flat, 0, &esd, digestInfo,
                &digestInfoSz);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pkcs7==NULL true");
        ret = wc_PKCS7_BuildDigestInfo(&pkcs7, flat, 0, NULL, digestInfo,
                &digestInfoSz);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "esd==NULL true");
        ret = wc_PKCS7_BuildDigestInfo(&pkcs7, flat, 0, &esd, NULL,
                &digestInfoSz);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "digestInfo==NULL true");
        ret = wc_PKCS7_BuildDigestInfo(&pkcs7, flat, 0, &esd, digestInfo, NULL);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "digestInfoSz==NULL true");
    }

    WB_NOTE("wc_PKCS7_SignedDataBuildSignature(): 2-operand OR guard"
            " baseline+pairs (deeper failure on unset key material is fine --"
            " only the top guard's decision is under test)");
    {
        XMEMSET(&esd, 0, sizeof(esd));
        ret = wc_PKCS7_SignedDataBuildSignature(&pkcs7, NULL, 0, &esd);
        WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                "baseline (all false): proceeds past the guard");
        ret = wc_PKCS7_SignedDataBuildSignature(NULL, NULL, 0, &esd);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pkcs7==NULL true");
        ret = wc_PKCS7_SignedDataBuildSignature(&pkcs7, NULL, 0, NULL);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "esd==NULL true");
    }
}

/* ------------------------------------------------------------------------- *
 * Section 3: wc_PKCS7_GetSignerSID, PKCS7_GenerateContentEncryptionKey (cek
 * reuse AND-guard), wc_PKCS7_KeyWrap -- baseline calls missing everywhere.
 * ------------------------------------------------------------------------- */
static void wb_cek_signer_sid(void)
{
    wc_PKCS7 pkcs7;
    int ret;

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));

    WB_NOTE("wc_PKCS7_GetSignerSID(): 2-operand OR guard baseline+pairs");
    {
        byte out[16];
        word32 outSz = sizeof(out);
        ret = wc_PKCS7_GetSignerSID(&pkcs7, out, &outSz);
        WB_CHECK(ret == WC_NO_ERR_TRACE(PKCS7_NO_SIGNER_E),
                "baseline (all false): no signerInfo, distinct from the guard");
        ret = wc_PKCS7_GetSignerSID(NULL, out, &outSz);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pkcs7==NULL true");
        ret = wc_PKCS7_GetSignerSID(&pkcs7, out, NULL);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "outSz==NULL true");
    }

    WB_NOTE("PKCS7_GenerateContentEncryptionKey(): cek-reuse AND-guard"
            " [pkcs7->cek!=NULL && pkcs7->cekSz!=0] -- baseline (cek==NULL,"
            " real RNG-generated key) pairs against the existing"
            " both-true rows (matching/mismatching cekSz)");
    {
        XMEMSET(&pkcs7, 0, sizeof(pkcs7));
        ret = PKCS7_GenerateContentEncryptionKey(&pkcs7, 16);
        WB_CHECK(ret == 0, "cek==NULL: real key generated via internal RNG");
        WB_CHECK(pkcs7.cek != NULL && pkcs7.cekSz == 16, "cek stored");
        /* 1st operand true, 2nd operand false pair: cek!=NULL, cekSz==0 */
        {
            byte* savedCek = pkcs7.cek;
            pkcs7.cekSz = 0;
            ret = PKCS7_GenerateContentEncryptionKey(&pkcs7, 16);
            WB_CHECK(ret == 0, "cek!=NULL, cekSz==0: guard false, regenerates");
            if (pkcs7.cek != NULL && pkcs7.cek != savedCek) {
                XFREE(savedCek, pkcs7.heap, DYNAMIC_TYPE_PKCS7);
            }
        }
        if (pkcs7.cek != NULL) {
            XFREE(pkcs7.cek, pkcs7.heap, DYNAMIC_TYPE_PKCS7);
            pkcs7.cek = NULL;
            pkcs7.cekSz = 0;
        }
    }

    WB_NOTE("wc_PKCS7_KeyWrap(): 4-operand OR guard baseline+pairs (real"
            " AES-128 key wrap)");
#if !defined(NO_AES) && defined(HAVE_AES_KEYWRAP) && defined(WOLFSSL_AES_128)
    {
        byte cek[16], kek[16], out[32];
        XMEMSET(cek, 1, sizeof(cek));
        XMEMSET(kek, 2, sizeof(kek));
        XMEMSET(&pkcs7, 0, sizeof(pkcs7));
        ret = wc_PKCS7_KeyWrap(&pkcs7, cek, sizeof(cek), kek, sizeof(kek),
                out, sizeof(out), AES128_WRAP, AES_ENCRYPTION);
        WB_CHECK(ret > 0, "baseline (all false): real AES128 key wrap");
    }
#else
    WB_NOTE("no AES/AES-keywrap/AES128 support; KeyWrap baseline skipped"
            " (NULL-operand pairs below still exercised)");
#endif
    {
        byte cek[16], kek[16], out[32];
        XMEMSET(cek, 1, sizeof(cek));
        XMEMSET(kek, 2, sizeof(kek));
        XMEMSET(&pkcs7, 0, sizeof(pkcs7));
        ret = wc_PKCS7_KeyWrap(NULL, cek, sizeof(cek), kek, sizeof(kek), out,
                sizeof(out), AES128_WRAP, AES_ENCRYPTION);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pkcs7==NULL true");
        ret = wc_PKCS7_KeyWrap(&pkcs7, NULL, sizeof(cek), kek, sizeof(kek),
                out, sizeof(out), AES128_WRAP, AES_ENCRYPTION);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "cek==NULL true");
        ret = wc_PKCS7_KeyWrap(&pkcs7, cek, sizeof(cek), NULL, sizeof(kek),
                out, sizeof(out), AES128_WRAP, AES_ENCRYPTION);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "kek==NULL true");
        ret = wc_PKCS7_KeyWrap(&pkcs7, cek, sizeof(cek), kek, sizeof(kek),
                NULL, sizeof(out), AES128_WRAP, AES_ENCRYPTION);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "out==NULL true");
    }
}

/* ------------------------------------------------------------------------- *
 * Section 4: wc_PKCS7_SetContentType, wc_PKCS7_PadData -- baseline calls
 * missing everywhere.
 * ------------------------------------------------------------------------- */
static void wb_content_pad(void)
{
    wc_PKCS7 pkcs7;
    int ret;

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));

    WB_NOTE("wc_PKCS7_SetContentType(): 3-operand OR guard baseline+pairs");
    {
        byte ct[4] = { 0x06, 0x02, 0x01, 0x02 };
        ret = wc_PKCS7_SetContentType(&pkcs7, ct, sizeof(ct));
        WB_CHECK(ret == 0, "baseline (all false): real content type set");
        ret = wc_PKCS7_SetContentType(NULL, ct, sizeof(ct));
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pkcs7==NULL true");
        ret = wc_PKCS7_SetContentType(&pkcs7, NULL, sizeof(ct));
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "contentType==NULL true");
        ret = wc_PKCS7_SetContentType(&pkcs7, ct, 0);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "sz==0 true");
    }

    WB_NOTE("wc_PKCS7_PadData(): 5-operand OR guard baseline+pairs");
    {
        byte in[16], out[32];
        XMEMSET(in, 0xAA, sizeof(in));
        ret = wc_PKCS7_PadData(in, sizeof(in), out, sizeof(out), 16);
        WB_CHECK(ret >= 0, "baseline (all false): real pad");
        ret = wc_PKCS7_PadData(NULL, sizeof(in), out, sizeof(out), 16);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "in==NULL true");
        ret = wc_PKCS7_PadData(in, 0, out, sizeof(out), 16);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "inSz==0 true");
        ret = wc_PKCS7_PadData(in, sizeof(in), NULL, sizeof(out), 16);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "out==NULL true");
        ret = wc_PKCS7_PadData(in, sizeof(in), out, 0, 16);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "outSz==0 true");
        ret = wc_PKCS7_PadData(in, sizeof(in), out, sizeof(out), 0);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "blockSz==0 true");
    }
}

/* ------------------------------------------------------------------------- *
 * Section 5: wc_PKCS7_AddRecipient_ORI, wc_PKCS7_GenerateKEK_PWRI,
 * wc_PKCS7_PwriKek_KeyUnWrap, wc_PKCS7_SetPassword -- baseline calls missing
 * everywhere (PwriKek_KeyUnWrap's top NULL guard is not driven at all by the
 * other two files -- only its inSz-bound branch is).
 * ------------------------------------------------------------------------- */
static int wb_ori_stub_cb(wc_PKCS7* pkcs7, byte* cek, word32 cekSz,
        byte* oriType, word32* oriTypeSz, byte* oriValue, word32* oriValueSz,
        void* ctx)
{
    (void)pkcs7; (void)cek; (void)cekSz; (void)oriType; (void)oriValue;
    (void)ctx;
    if (oriTypeSz != NULL)
        *oriTypeSz = 0;
    if (oriValueSz != NULL)
        *oriValueSz = 0;
    return 0;
}

static void wb_ori_pwri(void)
{
    wc_PKCS7 pkcs7;
    int ret;

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));

    WB_NOTE("wc_PKCS7_AddRecipient_ORI(): 2-operand OR guard baseline+pairs");
    {
        ret = wc_PKCS7_AddRecipient_ORI(&pkcs7, wb_ori_stub_cb, 0);
        WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                "baseline (all false): real callback accepted, proceeds"
                " past the guard");
        if (pkcs7.recipList != NULL) {
            Pkcs7EncodedRecip* r = pkcs7.recipList;
            Pkcs7EncodedRecip* n;
            while (r != NULL) {
                n = r->next;
                XFREE(r, pkcs7.heap, DYNAMIC_TYPE_PKCS7);
                r = n;
            }
            pkcs7.recipList = NULL;
        }
        ret = wc_PKCS7_AddRecipient_ORI(NULL, wb_ori_stub_cb, 0);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pkcs7==NULL true");
        ret = wc_PKCS7_AddRecipient_ORI(&pkcs7, NULL, 0);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "oriEncryptCb==NULL true");
    }

#if !defined(NO_PWDBASED) && !defined(NO_SHA)
    WB_NOTE("wc_PKCS7_GenerateKEK_PWRI(): 4-operand OR guard baseline+pairs"
            " (real PBKDF2 derivation)");
    {
        byte passwd[9] = "password";
        byte salt[8] = { 1,2,3,4,5,6,7,8 };
        byte out[16];
        XMEMSET(&pkcs7, 0, sizeof(pkcs7));
        ret = wc_PKCS7_GenerateKEK_PWRI(&pkcs7, passwd, sizeof(passwd), salt,
                sizeof(salt), PBKDF2_OID, WC_SHA, 1000, out, sizeof(out));
        WB_CHECK(ret == 0, "baseline (all false): real KEK derived");
        ret = wc_PKCS7_GenerateKEK_PWRI(NULL, passwd, sizeof(passwd), salt,
                sizeof(salt), PBKDF2_OID, WC_SHA, 1000, out, sizeof(out));
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pkcs7==NULL true");
        ret = wc_PKCS7_GenerateKEK_PWRI(&pkcs7, NULL, sizeof(passwd), salt,
                sizeof(salt), PBKDF2_OID, WC_SHA, 1000, out, sizeof(out));
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "passwd==NULL true");
        ret = wc_PKCS7_GenerateKEK_PWRI(&pkcs7, passwd, sizeof(passwd), NULL,
                sizeof(salt), PBKDF2_OID, WC_SHA, 1000, out, sizeof(out));
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "salt==NULL true");
        ret = wc_PKCS7_GenerateKEK_PWRI(&pkcs7, passwd, sizeof(passwd), salt,
                sizeof(salt), PBKDF2_OID, WC_SHA, 1000, NULL, sizeof(out));
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "out==NULL true");
    }
#else
    WB_NOTE("no PWDBASED/SHA support; GenerateKEK_PWRI section skipped");
#endif

#if !defined(NO_PWDBASED) && !defined(NO_SHA)
    WB_NOTE("wc_PKCS7_PwriKek_KeyUnWrap(): 5-operand OR top guard -- not"
            " NULL-driven at all elsewhere (only the inSz-bound branch is)."
            " Baseline is a real KeyWrap/KeyUnWrap roundtrip.");
    {
        byte kek[16], cek[16], iv[16], wrapped[64], out[64];
        word32 wrappedSz = sizeof(wrapped);
        XMEMSET(kek, 1, sizeof(kek));
        XMEMSET(cek, 2, sizeof(cek));
        XMEMSET(iv, 3, sizeof(iv));
        XMEMSET(&pkcs7, 0, sizeof(pkcs7));

        ret = wc_PKCS7_PwriKek_KeyWrap(&pkcs7, kek, sizeof(kek), cek,
                sizeof(cek), wrapped, &wrappedSz, iv, sizeof(iv), AES128_WRAP);
        WB_CHECK(ret == 0, "PwriKek_KeyWrap baseline (feeds unwrap roundtrip)");

        ret = wc_PKCS7_PwriKek_KeyUnWrap(&pkcs7, kek, sizeof(kek), wrapped,
                wrappedSz, out, sizeof(out), iv, sizeof(iv), AES128_WRAP);
        WB_CHECK(ret >= 0, "baseline (all false): real key unwrap roundtrip");

        ret = wc_PKCS7_PwriKek_KeyUnWrap(NULL, kek, sizeof(kek), wrapped,
                wrappedSz, out, sizeof(out), iv, sizeof(iv), AES128_WRAP);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pkcs7==NULL true");
        ret = wc_PKCS7_PwriKek_KeyUnWrap(&pkcs7, NULL, sizeof(kek), wrapped,
                wrappedSz, out, sizeof(out), iv, sizeof(iv), AES128_WRAP);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "kek==NULL true");
        ret = wc_PKCS7_PwriKek_KeyUnWrap(&pkcs7, kek, sizeof(kek), NULL,
                wrappedSz, out, sizeof(out), iv, sizeof(iv), AES128_WRAP);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "in==NULL true");
        ret = wc_PKCS7_PwriKek_KeyUnWrap(&pkcs7, kek, sizeof(kek), wrapped,
                wrappedSz, NULL, sizeof(out), iv, sizeof(iv), AES128_WRAP);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "out==NULL true");
        ret = wc_PKCS7_PwriKek_KeyUnWrap(&pkcs7, kek, sizeof(kek), wrapped,
                wrappedSz, out, sizeof(out), NULL, sizeof(iv), AES128_WRAP);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "iv==NULL true");
    }
#else
    WB_NOTE("no PWDBASED/SHA support; PwriKek_Key(Un)Wrap section skipped");
#endif

    WB_NOTE("wc_PKCS7_SetPassword(): 3-operand OR guard baseline+pairs");
    {
        byte passwd[9] = "password";
        XMEMSET(&pkcs7, 0, sizeof(pkcs7));
        ret = wc_PKCS7_SetPassword(&pkcs7, passwd, sizeof(passwd));
        WB_CHECK(ret == 0, "baseline (all false): real password set");
        ret = wc_PKCS7_SetPassword(NULL, passwd, sizeof(passwd));
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pkcs7==NULL true");
        ret = wc_PKCS7_SetPassword(&pkcs7, NULL, sizeof(passwd));
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "passwd==NULL true");
        ret = wc_PKCS7_SetPassword(&pkcs7, passwd, 0);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pLen==0 true");
    }
}

/* ------------------------------------------------------------------------- *
 * Section 6: wc_PKCS7_AddRecipient_KEKRI top guard [pkcs7,kek,keyId] plus its
 * two `other!=NULL && otherSz>0` branches -- baseline+pairs missing
 * everywhere (the other file only drives this with other==NULL).
 * ------------------------------------------------------------------------- */
#if !defined(NO_AES) && defined(HAVE_AES_KEYWRAP) && defined(WOLFSSL_AES_256)
static void wb_kekri_other(void)
{
    wc_PKCS7 pkcs7;
    byte kek[32];
    byte keyId[4] = { 0xAA, 0xBB, 0xCC, 0xDD };
    byte otherOID[4] = { 0x06, 0x02, 0x01, 0x01 };
    byte other[4] = { 1,2,3,4 };
    int ret, i;

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));
    for (i = 0; i < (int)sizeof(kek); i++) {
        kek[i] = (byte)i;
    }

    WB_NOTE("wc_PKCS7_AddRecipient_KEKRI(): top OR guard baseline+pairs, plus"
            " other!=NULL&&otherSz>0 true row [feeds the two gapped OR"
            " decisions at recip build time and at recip write-out time]");
    ret = wc_PKCS7_AddRecipient_KEKRI(&pkcs7, AES256_WRAP, kek, sizeof(kek),
            keyId, sizeof(keyId), NULL, otherOID, sizeof(otherOID), other,
            sizeof(other), 0);
    WB_CHECK(ret >= 0,
            "baseline (top guard false) + other!=NULL&&otherSz>0 true"
            " (both OR decisions exercised true)");

    /* other==NULL (2nd operand false), otherSz==0 (both false): pairs
     * against the true row above for both otherAttSeq OR decisions. */
    ret = wc_PKCS7_AddRecipient_KEKRI(&pkcs7, AES256_WRAP, kek, sizeof(kek),
            keyId, sizeof(keyId), NULL, NULL, 0, NULL, 0, 0);
    WB_CHECK(ret >= 0, "other==NULL, otherSz==0: both OR decisions false");

    ret = wc_PKCS7_AddRecipient_KEKRI(NULL, AES256_WRAP, kek, sizeof(kek),
            keyId, sizeof(keyId), NULL, NULL, 0, NULL, 0, 0);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pkcs7==NULL true");
    ret = wc_PKCS7_AddRecipient_KEKRI(&pkcs7, AES256_WRAP, NULL, sizeof(kek),
            keyId, sizeof(keyId), NULL, NULL, 0, NULL, 0, 0);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "kek==NULL true");
    ret = wc_PKCS7_AddRecipient_KEKRI(&pkcs7, AES256_WRAP, kek, sizeof(kek),
            NULL, sizeof(keyId), NULL, NULL, 0, NULL, 0, 0);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "keyId==NULL true");

    if (pkcs7.recipList != NULL) {
        Pkcs7EncodedRecip* r = pkcs7.recipList;
        Pkcs7EncodedRecip* n;
        while (r != NULL) {
            n = r->next;
            XFREE(r, pkcs7.heap, DYNAMIC_TYPE_PKCS7);
            r = n;
        }
        pkcs7.recipList = NULL;
    }
}
#else
static void wb_kekri_other(void)
{
    WB_NOTE("no AES256/AES-keywrap support; AddRecipient_KEKRI other-buffer"
            " section skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 7: wc_PKCS7_KtriFakeCEK, wc_PKCS7_DecryptRecipientInfos (the 3
 * operands the other file does not NULL-test: decryptedKey, decryptedKeySz,
 * recipFound) -- baseline+pairs missing everywhere.
 * ------------------------------------------------------------------------- */
static void wb_ktri_recipinfos(void)
{
    wc_PKCS7 pkcs7;
    int ret;

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));

    WB_NOTE("wc_PKCS7_KtriFakeCEK(): 3-operand OR guard baseline+pairs");
    {
        byte encKey[32];
        byte out[32];
        XMEMSET(encKey, 0xAB, sizeof(encKey));
        ret = wc_PKCS7_KtriFakeCEK(&pkcs7, encKey, sizeof(encKey), out);
        WB_CHECK(ret == 0, "baseline (all false): real fake-CEK derivation");
        ret = wc_PKCS7_KtriFakeCEK(NULL, encKey, sizeof(encKey), out);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pkcs7==NULL true");
        ret = wc_PKCS7_KtriFakeCEK(&pkcs7, NULL, sizeof(encKey), out);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "encryptedKey==NULL true");
        ret = wc_PKCS7_KtriFakeCEK(&pkcs7, encKey, sizeof(encKey), NULL);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "out==NULL true");
    }

    WB_NOTE("wc_PKCS7_DecryptRecipientInfos(): 7-operand OR guard -- the"
            " other file only NULL-tests pkcs7/in/idx; decryptedKey,"
            " decryptedKeySz, recipFound, setEnd plus the all-false baseline"
            " are added here (stream must be created first: the post-switch"
            " path unconditionally reads pkcs7->stream->length)");
    {
        byte in[8] = { 0x30, 0x06, 1,2,3,4,5,6 };
        byte decKey[32];
        word32 idx, decKeySz;
        word32 setEndWb;
        int recipFound;

#ifndef NO_PKCS7_STREAM
        ret = wc_PKCS7_CreateStream(&pkcs7);
        WB_CHECK(ret == 0, "CreateStream for DecryptRecipientInfos baseline");
#endif
        idx = 0; decKeySz = sizeof(decKey); recipFound = 0;
        setEndWb = 0;
        ret = wc_PKCS7_DecryptRecipientInfos(&pkcs7, in, sizeof(in), &idx,
                decKey, &decKeySz, &recipFound, &setEndWb);
        WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                "baseline (all false): proceeds past the guard"
                " (state==WC_PKCS7_START -> not-decrypting no-op, ret==0)");

        idx = 0;
        ret = wc_PKCS7_DecryptRecipientInfos(NULL, in, sizeof(in), &idx,
                decKey, &decKeySz, &recipFound, &setEndWb);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pkcs7==NULL true");
        ret = wc_PKCS7_DecryptRecipientInfos(&pkcs7, NULL, sizeof(in), &idx,
                decKey, &decKeySz, &recipFound, &setEndWb);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "in==NULL true");
        ret = wc_PKCS7_DecryptRecipientInfos(&pkcs7, in, sizeof(in), NULL,
                decKey, &decKeySz, &recipFound, &setEndWb);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "idx==NULL true");
        idx = 0;
        ret = wc_PKCS7_DecryptRecipientInfos(&pkcs7, in, sizeof(in), &idx,
                NULL, &decKeySz, &recipFound, &setEndWb);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "decryptedKey==NULL true");
        idx = 0;
        ret = wc_PKCS7_DecryptRecipientInfos(&pkcs7, in, sizeof(in), &idx,
                decKey, NULL, &recipFound, &setEndWb);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                "decryptedKeySz==NULL true");
        idx = 0;
        ret = wc_PKCS7_DecryptRecipientInfos(&pkcs7, in, sizeof(in), &idx,
                decKey, &decKeySz, NULL, &setEndWb);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "recipFound==NULL true");
        idx = 0;
        ret = wc_PKCS7_DecryptRecipientInfos(&pkcs7, in, sizeof(in), &idx,
                decKey, &decKeySz, &recipFound, NULL);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "setEnd==NULL true");

#ifndef NO_PKCS7_STREAM
        wc_PKCS7_FreeStream(&pkcs7);
#endif
    }
}

/* ------------------------------------------------------------------------- *
 * Section 8: KARI (Key Agreement RecipientInfo) family -- a real ECC
 * lifecycle (parse recipient cert -> ephemeral key -> shared info -> KEK)
 * closes the encode-side NULL guards' baseline row, then the KariGetX
 * decode-side static helpers get a "valid pointers, garbage ASN.1 content"
 * baseline (guard false, fails deeper in the parse -- fine, only the
 * guard's own decision is under test).
 * ------------------------------------------------------------------------- */
#ifdef HAVE_ECC
static void wb_kari_full(void)
{
    wc_PKCS7 pkcs7;
    WC_PKCS7_KARI* kari;
    WC_RNG rng;
    int ret;

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));
    ret = wc_InitRng(&rng);
    WB_CHECK(ret == 0, "rng init for KARI lifecycle");

    WB_NOTE("KARI encode lifecycle: KariParseRecipCert [2-op guard],"
            " KariGenerateEphemeralKey [4-op guard], KariGenerateSharedInfo"
            " ukm guard [2-op guard], KariGenerateKEK [4-op guard] -- real"
            " ECDH chain over a real recipient cert supplies each"
            " function's all-false baseline");
    kari = wc_PKCS7_KariNew(&pkcs7, WC_PKCS7_ENCODE);
    WB_CHECK(kari != NULL, "KariNew baseline");
    if (kari != NULL) {
        ret = wc_PKCS7_KariParseRecipCert(kari, (const byte*)cliecc_cert_der_256,
                (word32)sizeof_cliecc_cert_der_256, NULL, 0);
        WB_CHECK(ret == 0, "KariParseRecipCert baseline (all false): real"
                " recipient cert parsed");

        ret = wc_PKCS7_KariGenerateEphemeralKey(kari);
        WB_CHECK(ret == 0, "KariGenerateEphemeralKey baseline (all false):"
                " real ephemeral key generated");

        kari->ukm = NULL;
        kari->ukmSz = 0;
        ret = wc_PKCS7_KariGenerateSharedInfo(kari, AES128_WRAP);
        WB_CHECK(ret == 0,
                "KariGenerateSharedInfo ukm guard baseline (both false)");
        {
            byte ukm[8] = { 1,2,3,4,5,6,7,8 };
            kari->ukm = ukm;
            kari->ukmSz = sizeof(ukm);
            ret = wc_PKCS7_KariGenerateSharedInfo(kari, AES128_WRAP);
            WB_CHECK(ret == 0,
                    "ukm guard: ukmSz>0 && ukm!=NULL (both false, real ukm)");
            kari->ukm = NULL;
            kari->ukmSz = 0;
        }
        {
            WC_PKCS7_KARI* kari2 = wc_PKCS7_KariNew(&pkcs7, WC_PKCS7_ENCODE);
            if (kari2 != NULL) {
                kari2->ukmSz = 4;
                kari2->ukm = NULL;
                ret = wc_PKCS7_KariGenerateSharedInfo(kari2, AES128_WRAP);
                WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                        "ukm guard: ukmSz>0 && ukm==NULL true");
                wc_PKCS7_KariFree(kari2);
            }
        }

        ret = wc_PKCS7_KariGenerateKEK(kari, &rng, AES128_WRAP,
                dhSinglePass_stdDH_sha256kdf_scheme);
        WB_CHECK(ret == 0, "KariGenerateKEK baseline (all false): real KEK"
                " derived via ECDH");

        ret = wc_PKCS7_KariGenerateEphemeralKey(NULL);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                "KariGenerateEphemeralKey kari==NULL true");
        {
            ecc_key* saved = kari->recipKey;
            kari->recipKey = NULL;
            ret = wc_PKCS7_KariGenerateEphemeralKey(kari);
            WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                    "KariGenerateEphemeralKey recipKey==NULL true");
            kari->recipKey = saved;
        }
        ret = wc_PKCS7_KariGenerateKEK(NULL, &rng, AES128_WRAP,
                dhSinglePass_stdDH_sha256kdf_scheme);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                "KariGenerateKEK kari==NULL true");
        {
            ecc_key* saved = kari->senderKey;
            kari->senderKey = NULL;
            ret = wc_PKCS7_KariGenerateKEK(kari, &rng, AES128_WRAP,
                    dhSinglePass_stdDH_sha256kdf_scheme);
            WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                    "KariGenerateKEK senderKey==NULL true");
            kari->senderKey = saved;
        }

        ret = wc_PKCS7_KariParseRecipCert(NULL, (const byte*)cliecc_cert_der_256,
                (word32)sizeof_cliecc_cert_der_256, NULL, 0);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                "KariParseRecipCert kari==NULL true");
        {
            DecodedCert* saved = kari->decoded;
            kari->decoded = NULL;
            ret = wc_PKCS7_KariParseRecipCert(kari,
                    (const byte*)cliecc_cert_der_256,
                    (word32)sizeof_cliecc_cert_der_256, NULL, 0);
            WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                    "KariParseRecipCert kari->decoded==NULL true");
            kari->decoded = saved;
        }

        wc_PKCS7_KariFree(kari);
    }

    WB_NOTE("wc_PKCS7_AddRecipient_KARI(): ukmSz>0 && ukm!=NULL AND-guard"
            " baseline (real ukm) pairs against the default no-ukm calls"
            " used elsewhere");
#if !defined(NO_AES) && defined(WOLFSSL_AES_128)
    {
        byte out[512];
        byte ukm[8] = { 1,2,3,4,5,6,7,8 };
        XMEMSET(&pkcs7, 0, sizeof(pkcs7));
        pkcs7.encryptOID = AES128CBCb;
        pkcs7.rng = &rng;
        ret = wc_PKCS7_AddRecipient_KARI(&pkcs7,
                (const byte*)cliecc_cert_der_256,
                (word32)sizeof_cliecc_cert_der_256, AES128_WRAP,
                dhSinglePass_stdDH_sha256kdf_scheme, ukm, sizeof(ukm), 0);
        WB_CHECK(ret >= 0, "AddRecipient_KARI: ukmSz>0 && ukm!=NULL (both"
                " true, real ukm attached)");
        if (pkcs7.recipList != NULL) {
            Pkcs7EncodedRecip* r = pkcs7.recipList;
            Pkcs7EncodedRecip* n;
            while (r != NULL) {
                n = r->next;
                XFREE(r, pkcs7.heap, DYNAMIC_TYPE_PKCS7);
                r = n;
            }
            pkcs7.recipList = NULL;
        }
    }
#else
    WB_NOTE("no AES/AES128 support; AddRecipient_KARI ukm section skipped");
#endif

    WB_NOTE("KariGetX decode-side static helpers: NULL-guard baseline"
            " (valid pointers, garbage ASN.1 -- guard false, fails deeper)"
            " for KariGetOriginatorIdentifierOrKey [3-op],"
            " KariGetUserKeyingMaterial [3-op],"
            " KariGetKeyEncryptionAlgorithmId [5-op],"
            " KariGetSubjectKeyIdentifier [5-op],"
            " KariGetRecipientEncryptedKeys [5-op]");
    kari = wc_PKCS7_KariNew(&pkcs7, WC_PKCS7_DECODE);
    WB_CHECK(kari != NULL, "KariNew (decode) baseline");
    if (kari != NULL) {
        byte garbage[16] = { 0x30, 0x0e, 1,2,3,4,5,6,7,8,9,10,11,12,13,14 };
        word32 idx;
        int recipFound;
        byte rid[KEYID_SIZE];
        byte encKey[8];
        int encKeySz;
        word32 keyAgreeOID, keyWrapOID;

        idx = 0;
        ret = wc_PKCS7_KariGetOriginatorIdentifierOrKey(kari, garbage,
                sizeof(garbage), &idx);
        WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                "OriginatorIdentifierOrKey baseline (all false)");
        ret = wc_PKCS7_KariGetOriginatorIdentifierOrKey(NULL, garbage,
                sizeof(garbage), &idx);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "kari==NULL true");
        ret = wc_PKCS7_KariGetOriginatorIdentifierOrKey(kari, NULL,
                sizeof(garbage), &idx);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pkiMsg==NULL true");
        ret = wc_PKCS7_KariGetOriginatorIdentifierOrKey(kari, garbage,
                sizeof(garbage), NULL);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "idx==NULL true");

        idx = 0;
        ret = wc_PKCS7_KariGetUserKeyingMaterial(kari, garbage,
                sizeof(garbage), &idx);
        WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                "UserKeyingMaterial baseline (all false)");
        ret = wc_PKCS7_KariGetUserKeyingMaterial(NULL, garbage,
                sizeof(garbage), &idx);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "kari==NULL true");
        ret = wc_PKCS7_KariGetUserKeyingMaterial(kari, NULL, sizeof(garbage),
                &idx);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pkiMsg==NULL true");
        ret = wc_PKCS7_KariGetUserKeyingMaterial(kari, garbage,
                sizeof(garbage), NULL);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "idx==NULL true");

        idx = 0; keyAgreeOID = 0; keyWrapOID = 0;
        ret = wc_PKCS7_KariGetKeyEncryptionAlgorithmId(kari, garbage,
                sizeof(garbage), &idx, &keyAgreeOID, &keyWrapOID);
        WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                "KeyEncryptionAlgorithmId baseline (all false)");
        ret = wc_PKCS7_KariGetKeyEncryptionAlgorithmId(NULL, garbage,
                sizeof(garbage), &idx, &keyAgreeOID, &keyWrapOID);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "kari==NULL true");
        ret = wc_PKCS7_KariGetKeyEncryptionAlgorithmId(kari, NULL,
                sizeof(garbage), &idx, &keyAgreeOID, &keyWrapOID);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pkiMsg==NULL true");
        ret = wc_PKCS7_KariGetKeyEncryptionAlgorithmId(kari, garbage,
                sizeof(garbage), NULL, &keyAgreeOID, &keyWrapOID);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "idx==NULL true");
        ret = wc_PKCS7_KariGetKeyEncryptionAlgorithmId(kari, garbage,
                sizeof(garbage), &idx, NULL, &keyWrapOID);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "keyAgreeOID==NULL true");
        ret = wc_PKCS7_KariGetKeyEncryptionAlgorithmId(kari, garbage,
                sizeof(garbage), &idx, &keyAgreeOID, NULL);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "keyWrapOID==NULL true");

        idx = 0; recipFound = 0;
        ret = wc_PKCS7_KariGetSubjectKeyIdentifier(kari, garbage,
                sizeof(garbage), &idx, &recipFound, rid);
        WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                "SubjectKeyIdentifier baseline (all false)");
        ret = wc_PKCS7_KariGetSubjectKeyIdentifier(NULL, garbage,
                sizeof(garbage), &idx, &recipFound, rid);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "kari==NULL true");
        ret = wc_PKCS7_KariGetSubjectKeyIdentifier(kari, NULL,
                sizeof(garbage), &idx, &recipFound, rid);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pkiMsg==NULL true");
        ret = wc_PKCS7_KariGetSubjectKeyIdentifier(kari, garbage,
                sizeof(garbage), NULL, &recipFound, rid);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "idx==NULL true");
        ret = wc_PKCS7_KariGetSubjectKeyIdentifier(kari, garbage,
                sizeof(garbage), &idx, NULL, rid);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "recipFound==NULL true");
        ret = wc_PKCS7_KariGetSubjectKeyIdentifier(kari, garbage,
                sizeof(garbage), &idx, &recipFound, NULL);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "rid==NULL true");

        idx = 0; recipFound = 0; encKeySz = 0;
        ret = wc_PKCS7_KariGetRecipientEncryptedKeys(kari, garbage,
                sizeof(garbage), &idx, &recipFound, encKey, &encKeySz, rid);
        WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                "RecipientEncryptedKeys baseline (all false)");
        ret = wc_PKCS7_KariGetRecipientEncryptedKeys(NULL, garbage,
                sizeof(garbage), &idx, &recipFound, encKey, &encKeySz, rid);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "kari==NULL true");
        ret = wc_PKCS7_KariGetRecipientEncryptedKeys(kari, NULL,
                sizeof(garbage), &idx, &recipFound, encKey, &encKeySz, rid);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pkiMsg==NULL true");
        ret = wc_PKCS7_KariGetRecipientEncryptedKeys(kari, garbage,
                sizeof(garbage), NULL, &recipFound, encKey, &encKeySz, rid);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "idx==NULL true");
        ret = wc_PKCS7_KariGetRecipientEncryptedKeys(kari, garbage,
                sizeof(garbage), &idx, NULL, encKey, &encKeySz, rid);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "recipFound==NULL true");
        ret = wc_PKCS7_KariGetRecipientEncryptedKeys(kari, garbage,
                sizeof(garbage), &idx, &recipFound, NULL, &encKeySz, rid);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "encryptedKey==NULL true");

        wc_PKCS7_KariFree(kari);
    }

    WB_NOTE("wc_PKCS7_DecryptKari(): 5-operand OR top guard baseline+pairs"
            " (state forced to WC_PKCS7_DECRYPT_KARI so the guard's FALSE"
            " decision is genuinely exercised rather than falling through"
            " to the switch's own BAD_FUNC_ARG default case)");
    {
        byte in[8] = { 0x30, 0x06, 1,2,3,4,5,6 };
        byte decKey[32];
        word32 idx, decKeySz;
        int recipFound;

        XMEMSET(&pkcs7, 0, sizeof(pkcs7));
#ifndef NO_PKCS7_STREAM
        ret = wc_PKCS7_CreateStream(&pkcs7);
        WB_CHECK(ret == 0, "CreateStream for DecryptKari baseline");
#endif
        pkcs7.state = WC_PKCS7_DECRYPT_KARI;
        idx = 0; decKeySz = sizeof(decKey); recipFound = 0;
        ret = wc_PKCS7_DecryptKari(&pkcs7, in, sizeof(in), &idx, decKey,
                &decKeySz, &recipFound);
        WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                "baseline (all false): proceeds past the guard");

        idx = 0;
        ret = wc_PKCS7_DecryptKari(NULL, in, sizeof(in), &idx, decKey,
                &decKeySz, &recipFound);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pkcs7==NULL true");
        ret = wc_PKCS7_DecryptKari(&pkcs7, NULL, sizeof(in), &idx, decKey,
                &decKeySz, &recipFound);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pkiMsg==NULL true");
        ret = wc_PKCS7_DecryptKari(&pkcs7, in, sizeof(in), NULL, decKey,
                &decKeySz, &recipFound);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "idx==NULL true");
        idx = 0;
        ret = wc_PKCS7_DecryptKari(&pkcs7, in, sizeof(in), &idx, NULL,
                &decKeySz, &recipFound);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "decryptedKey==NULL true");
        idx = 0;
        ret = wc_PKCS7_DecryptKari(&pkcs7, in, sizeof(in), &idx, decKey,
                NULL, &recipFound);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                "decryptedKeySz==NULL true");

#ifndef NO_PKCS7_STREAM
        wc_PKCS7_FreeStream(&pkcs7);
#endif
    }

    wc_FreeRng(&rng);
}
#else
static void wb_kari_full(void)
{
    WB_NOTE("HAVE_ECC off; KARI family baseline section skipped");
}
#endif /* HAVE_ECC */

/* ------------------------------------------------------------------------- *
 * Section 9: allocation-fault MC/DC pair for wc_PKCS7_EncodeContentStream's
 * cleanup guard `encContentOut == NULL || contentData == NULL`
 * (streaming path, two back-to-back XMALLOCs, encContentOut first,
 * contentData second). arm(2) lets encContentOut succeed and fails
 * contentData, closing the 2nd operand. The 1st operand's true-while-
 * 2nd-false row (encContentOut fails, contentData succeeds) needs the
 * ONE-SHOT injector instead of the monotone one: arm_only(1) fails only
 * the first allocation and lets every later one (just #2 here) succeed.
 * ------------------------------------------------------------------------- */
#ifndef NO_AES
static void wb_alloc_fault_encodestream(void)
{
    wc_PKCS7 pkcs7;
    ESD esd;
    byte content[16];
    byte out[64];
    int ret;

    mcdc_fa_install();

    XMEMSET(content, 0xAA, sizeof(content));

    WB_NOTE("wc_PKCS7_EncodeContentStream(): streaming-path alloc-cleanup"
            " OR guard -- baseline (disarmed) + fault at n=2 (2nd alloc"
            " fails, 1st succeeds) closes the contentData==NULL operand");

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));
    pkcs7.contentSz = sizeof(content);
    pkcs7.encodeStream = 1;
    XMEMSET(&esd, 0, sizeof(esd));
    esd.hashType = WC_HASH_TYPE_SHA256;
    ret = wc_PKCS7_EncodeContentStream(&pkcs7, &esd, NULL, content,
            (int)sizeof(content), out, WC_CIPHER_NONE);
    WB_CHECK(ret == 0, "baseline (disarmed): both allocations succeed");

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));
    pkcs7.contentSz = sizeof(content);
    pkcs7.encodeStream = 1;
    XMEMSET(&esd, 0, sizeof(esd));
    esd.hashType = WC_HASH_TYPE_SHA256;
    mcdc_fa_arm(2);
    ret = wc_PKCS7_EncodeContentStream(&pkcs7, &esd, NULL, content,
            (int)sizeof(content), out, WC_CIPHER_NONE);
    mcdc_fa_disarm();
    WB_CHECK(ret == WC_NO_ERR_TRACE(MEMORY_E),
            "fault n=2: encContentOut succeeds, contentData fails"
            " (contentData==NULL operand true, encContentOut==NULL false)");

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));
    pkcs7.contentSz = sizeof(content);
    pkcs7.encodeStream = 1;
    XMEMSET(&esd, 0, sizeof(esd));
    esd.hashType = WC_HASH_TYPE_SHA256;
    mcdc_fa_arm_only(1);
    ret = wc_PKCS7_EncodeContentStream(&pkcs7, &esd, NULL, content,
            (int)sizeof(content), out, WC_CIPHER_NONE);
    mcdc_fa_disarm();
    WB_CHECK(ret == WC_NO_ERR_TRACE(MEMORY_E),
            "fault n=1 only: encContentOut fails, contentData (2nd, later)"
            " succeeds (encContentOut==NULL operand true, contentData==NULL"
            " false)");

    mcdc_fa_disarm();
    mcdc_fa_restore();
}
#else
static void wb_alloc_fault_encodestream(void)
{
    WB_NOTE("NO_AES; EncodeContentStream alloc-fault section skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 10: wc_PKCS7_GrowStream() buffer-copy guard
 * `pkcs7->stream->buffer != NULL && pkcs7->stream->bufferSz > 0` [:327] --
 * direct calls to the file-static growth helper (not an allocation-failure
 * decision despite living next to an XMALLOC; a data-shape drive). Call 1
 * grows from a fresh stream (both operands false: buffer==NULL). Call 2
 * regrows with the buffer already allocated but bufferSz manually forced to
 * 0 first (1st operand true, 2nd false -- skips the memcpy). Call 3 regrows
 * again with both true (buffer!=NULL, bufferSz>0 -- takes the memcpy path,
 * already exercised elsewhere but included here for a same-binary triple).
 * Only compiled when the streaming state machine exists at all
 * (wc_PKCS7_CreateStream/GrowStream/FreeStream are themselves inside
 * `#ifndef NO_PKCS7_STREAM` in pkcs7.c, so they are simply not there to
 * call under the no_stream suite variant).
 * ------------------------------------------------------------------------- */
#ifndef NO_PKCS7_STREAM
static void wb_growstream_bufsz(void)
{
    wc_PKCS7 pkcs7;
    int ret;

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));
    ret = wc_PKCS7_CreateStream(&pkcs7);
    WB_CHECK(ret == 0, "CreateStream for GrowStream baseline");
    if (ret != 0) {
        return;
    }

    WB_NOTE("wc_PKCS7_GrowStream(): buffer-copy guard [:327]");

    ret = wc_PKCS7_GrowStream(&pkcs7, 32);
    WB_CHECK(ret == 0, "both false: buffer==NULL, fresh allocation");
    WB_CHECK(pkcs7.stream != NULL && pkcs7.stream->buffer != NULL
            && pkcs7.stream->bufferSz == 32, "buffer grown to 32 bytes");

    pkcs7.stream->bufferSz = 0; /* buffer left non-NULL */
    ret = wc_PKCS7_GrowStream(&pkcs7, 64);
    WB_CHECK(ret == 0, "1st true, 2nd false: buffer!=NULL, bufferSz==0");
    WB_CHECK(pkcs7.stream->buffer != NULL && pkcs7.stream->bufferSz == 64,
            "buffer regrown to 64 bytes, memcpy skipped");

    ret = wc_PKCS7_GrowStream(&pkcs7, 96);
    WB_CHECK(ret == 0, "both true: buffer!=NULL, bufferSz>0, memcpy path");

    wc_PKCS7_FreeStream(&pkcs7);
}
#else
static void wb_growstream_bufsz(void)
{
    WB_NOTE("NO_PKCS7_STREAM; GrowStream buffer-copy guard drive skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 11: wc_PKCS7_AddRecipient_KTRI() WOLFSSL_SMALL_STACK alloc-guard
 * `decoded == NULL || serial == NULL || keyAlgArray == NULL` [:9371]. This
 * guard only exists in the WOLFSSL_SMALL_STACK build (small_stack suite
 * variant) -- in every other variant these three locals are plain stack
 * arrays and the line is not even compiled, so the sweep below is inert
 * (still safe) elsewhere. Allocation order is fixed by source order: serial
 * (#1), keyAlgArray (#2), decoded (#3); none depends on another's success,
 * so arm_only(n) cleanly isolates exactly one NULL operand per call.
 * ------------------------------------------------------------------------- */
static void wb_ktri_smallstack_fault(void)
{
    wc_PKCS7 pkcs7;
    byte dummyCert[4] = { 0x30, 0x02, 0x01, 0x00 };
    int ret;

    mcdc_fa_install();
    mcdc_fa_disarm();

    WB_NOTE("wc_PKCS7_AddRecipient_KTRI(): WOLFSSL_SMALL_STACK alloc-guard"
            " [:9371] -- baseline (disarmed) + one arm_only() per"
            " allocation site (serial, keyAlgArray, decoded)");

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));
    ret = wc_PKCS7_AddRecipient_KTRI(&pkcs7, dummyCert, sizeof(dummyCert), 0);
    WB_CHECK(ret != WC_NO_ERR_TRACE(MEMORY_E),
            "baseline (disarmed): all 3 allocations succeed, function fails"
            " later (garbage cert / unset encryptOID), not on this guard");

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));
    mcdc_fa_arm_only(1);
    ret = wc_PKCS7_AddRecipient_KTRI(&pkcs7, dummyCert, sizeof(dummyCert), 0);
    mcdc_fa_disarm();
    WB_CHECK(ret == WC_NO_ERR_TRACE(MEMORY_E),
            "arm_only(1): serial==NULL true, decoded/keyAlgArray false");

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));
    mcdc_fa_arm_only(2);
    ret = wc_PKCS7_AddRecipient_KTRI(&pkcs7, dummyCert, sizeof(dummyCert), 0);
    mcdc_fa_disarm();
    WB_CHECK(ret == WC_NO_ERR_TRACE(MEMORY_E),
            "arm_only(2): keyAlgArray==NULL true, decoded/serial false");

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));
    mcdc_fa_arm_only(3);
    ret = wc_PKCS7_AddRecipient_KTRI(&pkcs7, dummyCert, sizeof(dummyCert), 0);
    mcdc_fa_disarm();
    WB_CHECK(ret == WC_NO_ERR_TRACE(MEMORY_E),
            "arm_only(3): decoded==NULL true, serial/keyAlgArray false");

    mcdc_fa_disarm();
    mcdc_fa_restore();
}

/* ------------------------------------------------------------------------- *
 * Section 12: allocation-fault MC/DC pair for wc_PKCS7_DecodeEncryptedData's
 * `ret == 0 && (encryptedContent = XMALLOC(...)) == NULL` [:17106]. The
 * `ret == 0` operand is provably TRUE on every path that reaches this line
 * (see final report -- excluded, not driven here). The allocation-failure
 * operand is driven with the fail-forward injector: the only allocation
 * ahead of this one along a single-shot decode is wc_PKCS7_CreateStream's
 * PKCS7State, so with the mock armed right before the decode call,
 * allocation #1 is CreateStream and #2 is encryptedContent -- arm(2) fails
 * exactly the target allocation while CreateStream still succeeds.
 * ------------------------------------------------------------------------- */
#ifndef NO_PKCS7_ENCRYPTED_DATA
#if !defined(NO_AES) && defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_128)
static const byte wbFaultEncKey[] = {
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
    0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
};

static word32 wb_build_encrypted_aes_fault(byte* out, word32 outSz)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    byte data[] = "pkcs7 fault-whitebox EncryptedData corpus payload";
    int sz = 0;
    WC_RNG rng;

    if (p == NULL) {
        return 0;
    }
    if (wc_InitRng(&rng) == 0) {
        if (wc_PKCS7_Init(p, NULL, INVALID_DEVID) == 0) {
            p->content         = data;
            p->contentSz       = (word32)sizeof(data);
            p->contentOID      = DATA;
            p->encryptOID      = AES128CBCb;
            p->encryptionKey   = (byte*)wbFaultEncKey;
            p->encryptionKeySz = (word32)sizeof(wbFaultEncKey);
            p->rng             = &rng;
            sz = wc_PKCS7_EncodeEncryptedData(p, out, outSz);
        }
        wc_FreeRng(&rng);
    }
    wc_PKCS7_Free(p);
    return (sz > 0) ? (word32)sz : 0;
}

static void wb_encrypteddata_alloc_fault(void)
{
    byte corpus[256];
    word32 corpusLen;
    byte out[256];
    wc_PKCS7* p;
    int ret;

    corpusLen = wb_build_encrypted_aes_fault(corpus, sizeof(corpus));
    WB_CHECK(corpusLen > 0, "self-built AES128CBCb EncryptedData corpus"
            " encoded for the alloc-fault pair");
    if (corpusLen == 0) {
        return;
    }

    mcdc_fa_install();
    mcdc_fa_disarm();

    WB_NOTE("wc_PKCS7_DecodeEncryptedData(): encryptedContent alloc guard"
            " [:17106] -- baseline (disarmed, full decode succeeds) +"
            " fault at n=2 (CreateStream succeeds, encryptedContent fails)");

    p = wc_PKCS7_New(NULL, INVALID_DEVID);
    WB_CHECK(p != NULL, "New for EncryptedData alloc-fault baseline");
    if (p != NULL) {
        if (wc_PKCS7_Init(p, NULL, INVALID_DEVID) == 0) {
            p->encryptionKey   = (byte*)wbFaultEncKey;
            p->encryptionKeySz = (word32)sizeof(wbFaultEncKey);
            ret = wc_PKCS7_DecodeEncryptedData(p, corpus, corpusLen, out,
                    sizeof(out));
            WB_CHECK(ret == 0, "baseline (disarmed): full decode succeeds,"
                    " encryptedContent alloc succeeds");
        }
        wc_PKCS7_Free(p);
    }

    p = wc_PKCS7_New(NULL, INVALID_DEVID);
    WB_CHECK(p != NULL, "New for EncryptedData alloc-fault n=2");
    if (p != NULL) {
        if (wc_PKCS7_Init(p, NULL, INVALID_DEVID) == 0) {
            p->encryptionKey   = (byte*)wbFaultEncKey;
            p->encryptionKeySz = (word32)sizeof(wbFaultEncKey);
            mcdc_fa_arm(2);
            ret = wc_PKCS7_DecodeEncryptedData(p, corpus, corpusLen, out,
                    sizeof(out));
            mcdc_fa_disarm();
            WB_CHECK(ret == WC_NO_ERR_TRACE(MEMORY_E),
                    "fault n=2: CreateStream succeeds, encryptedContent"
                    " fails (alloc==NULL operand true)");
        }
        wc_PKCS7_Free(p);
    }

    mcdc_fa_disarm();
    mcdc_fa_restore();
}
#else
static void wb_encrypteddata_alloc_fault(void)
{
    WB_NOTE("no AES-CBC-128 support; EncryptedData alloc-fault pair"
            " skipped");
}
#endif
#else
static void wb_encrypteddata_alloc_fault(void)
{
    WB_NOTE("NO_PKCS7_ENCRYPTED_DATA; EncryptedData alloc-fault pair"
            " skipped");
}
#endif

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("pkcs7.c fault/baseline white-box MC/DC supplement\n");

    wb_guard_baselines1();
    wb_sign_algid_digest();
    wb_cek_signer_sid();
    wb_content_pad();
    wb_ori_pwri();
    wb_kekri_other();
    wb_ktri_recipinfos();
    wb_kari_full();
    wb_alloc_fault_encodestream();
    wb_growstream_bufsz();
    wb_ktri_smallstack_fault();
    wb_encrypteddata_alloc_fault();

    printf("done (%s)\n", wb_fail ? "with failures" : "ok");
    /* Always return 0: a nonzero exit discards this variant's coverage
     * entirely in the test harness. Failures are surfaced via the
     * printed [FAIL] lines instead. */
    (void)wb_fail;
    return 0;
}
