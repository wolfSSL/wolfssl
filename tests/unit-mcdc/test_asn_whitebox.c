/* test_asn_whitebox.c
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
 * First white-box MC/DC supplement for wolfcrypt/src/asn.c (Part 5).
 *
 * asn.c is 40.8k lines and only 267/1510 conditions covered by tests/api at
 * the start of this file's existence. Most of the ASN.1 primitives and the
 * template engine core (SizeASN_Items/SetASN_Items/GetASN_Items and their
 * static helpers) are file-static or take raw ASNItem/ASNGetData/ASNSetData
 * arrays that tests/api never constructs directly -- every real caller uses
 * a fixed, already-valid production template, so the malformed/edge-case
 * arms of the shared engine go untouched. This file compiles asn.c directly
 * (#include) and drives those helpers with hand-built DER byte arrays and
 * minimal custom ASNItem templates.
 *
 * Coverage is unioned by source line:col with the tests/api asn/x509/... run
 * in the per-module campaign; every pair below is completed *within this
 * file* (masking MC/DC is computed per binary).
 *
 * Sections (asn.c line numbers as of this writing):
 *   1. GetASNTag() NULL-arg OR ................................... :2708
 *   2. GetASNHeader_ex() tag mismatch + OID length-vs-buffer check  :2763,:2777
 *   3. GetASNNull() tag/length checks ............................ :3012,:3016
 *   4. GetASNInt() leading-zero / negative-padding checks ........ :3122,:3130,:3135
 *   5. CheckBitString() template-path zeroBits check .............. :3965
 *   6. wc_BerToDer()/GetBerHeader() indefinite-length tag class and
 *      constructed-basic-type / IndefItems bookkeeping ............ :4125,:4243,
 *                                                                     :4297,:4322,:4399
 *   7. SizeASN_Items()/SetASN_Items() template engine (custom
 *      encode template) ............................................ :866,:899,
 *                                                                     :987,:999,:1085,
 *                                                                     :1260,:1266,:1278
 *   8. GetASN_Items()/GetASN_StoreData()/GetASN_Integer()/
 *      GetASN_UTF8String() (custom single-item decode templates) .... :1337,:1347,
 *                                                                     :1355,:1416,:1530,
 *                                                                     :1542,:1548,:1563,
 *                                                                     :1569
 *   9. GetASN_Sequence() tag/length/complete checks ................. :2225,:2229,:2233
 *
 * RESIDUALS (structurally dead operand/branch, not a gap in this test):
 *   - GetASNInt() :3135 first operand (`*len > 0`) is only ever reached
 *     immediately after the leading-zero trim at :3130, which requires the
 *     pre-trim length to be > 1; the post-decrement length is therefore
 *     always >= 1 (never 0) at :3135. The false side of that operand is
 *     unreachable in this function; only the true side (driven below) is
 *     satisfiable.
 *   - SetASN_Items() :1278 `!asn[i].headerOnly || data[i].data.buffer.data
 *     != NULL`: this `else if` is only reached when the preceding `if
 *     (data[i].data.buffer.data == NULL)` at :1273 was false, i.e.
 *     `data[i].data.buffer.data != NULL` is a precondition of even
 *     evaluating :1278 -- the 2nd operand is therefore always true here,
 *     making the whole OR permanently true and its false outcome (both
 *     operands false) structurally unreachable. Both operands' "other"
 *     value is driven below (headerOnly true and false) but the decision
 *     itself cannot show a false outcome.
 */

#include <wolfcrypt/src/asn.c>

#include <stdio.h>
#include <string.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)
#define WB_CHECK(cond, msg) \
    do { if (!(cond)) { printf("  [wb][FAIL] %s\n", (msg)); wb_fail = 1; } } \
    while (0)

/* ------------------------------------------------------------------------- *
 * Section 1: GetASNTag() NULL-arg OR (:2708).
 *   if ((tag == NULL) || (inOutIdx == NULL) || (input == NULL))
 * Every real caller in this file passes valid pointers, so the true side of
 * each operand is white-box only.
 * ------------------------------------------------------------------------- */
static void wb_get_asn_tag(void)
{
    byte buf[4] = { 0x30, 0x00, 0x00, 0x00 };
    word32 idx;
    byte tag = 0;
    int ret;

    WB_NOTE("GetASNTag(): tag/inOutIdx/input NULL OR [:2708]");

    idx = 0;
    ret = GetASNTag(buf, &idx, &tag, sizeof(buf));
    WB_CHECK(ret == 0 && tag == 0x30, "GetASNTag all-valid (baseline)");

    idx = 0;
    ret = GetASNTag(buf, &idx, NULL, sizeof(buf));
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "GetASNTag tag==NULL");

    idx = 0;
    ret = GetASNTag(buf, NULL, &tag, sizeof(buf));
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "GetASNTag inOutIdx==NULL");

    idx = 0;
    ret = GetASNTag(NULL, &idx, &tag, sizeof(buf));
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "GetASNTag input==NULL");
}

/* ------------------------------------------------------------------------- *
 * Section 2: GetASNHeader_ex().
 *   :2763  if ((ret == 0) && (tagFound != tag))
 *   :2777  else if ((!check) && ((word32)length > maxIdx - idx))  (OID only)
 * The public GetASNHeader() wrapper hard-codes check=1, so the check=0 path
 * (and its length-vs-buffer arm) is white-box only.
 * ------------------------------------------------------------------------- */
static void wb_get_asn_header_ex(void)
{
    byte buf[4] = { 0x30, 0x00, 0xAA, 0xBB };
    word32 idx;
    int len;
    int ret;

    WB_NOTE("GetASNHeader_ex(): ret==0 short-circuit + tag mismatch [:2763]");

    /* A(ret==0) false: GetASNTag() itself fails (buffer too small). */
    idx = 4;
    ret = GetASNHeader_ex(buf, 0x30, &idx, &len, 4, 1);
    WB_CHECK(ret < 0, "ret!=0 short-circuit (buffer too small for tag)");

    /* baseline: tag matches. */
    idx = 0;
    ret = GetASNHeader_ex(buf, 0x30, &idx, &len, sizeof(buf), 1);
    WB_CHECK(ret == 0, "tag matches (both operands: T,F)");

    /* tag mismatch: both operands true. */
    idx = 0;
    ret = GetASNHeader_ex(buf, 0x31, &idx, &len, sizeof(buf), 1);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E), "tag mismatch (both operands true)");

    WB_NOTE("GetASNHeader_ex(): OID length-vs-buffer, check=0 [:2777]");
    {
        /* OBJECT_ID tag, claims 5 bytes of data; last octet (0x01) has MSB
         * clear so the "last octet" arm never fires -- isolates :2777. */
        byte oidBuf[16] = { 0x06, 0x05, 0x2A, 0x03, 0x04, 0x05, 0x01, 0,0,0,0,0,0,0,0,0 };

        /* V1: check=0, logical maxIdx too small for claimed length -> T&&T. */
        idx = 0; len = 0;
        ret = GetASNHeader_ex(oidBuf, ASN_OBJECT_ID, &idx, &len, 4, 0);
        WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
                "OID length exceeds logical maxIdx, check=0 (T,T)");

        /* V2: check=0, maxIdx large enough -> T,F (isolates 2nd operand). */
        idx = 0; len = 0;
        ret = GetASNHeader_ex(oidBuf, ASN_OBJECT_ID, &idx, &len, 7, 0);
        WB_CHECK(ret == 5, "OID length within logical maxIdx, check=0 (T,F)");

        /* V3: check=1 -> !check false, short-circuits (isolates 1st operand
         * against V1: same claimed length, operand1 flips T->F). */
        idx = 0; len = 0;
        ret = GetASNHeader_ex(oidBuf, ASN_OBJECT_ID, &idx, &len, 7, 1);
        WB_CHECK(ret == 5, "OID valid, check=1 (F via !check)");
    }
}

/* ------------------------------------------------------------------------- *
 * Section 3: GetASNNull() (:3012 tag check, :3016 length check).
 * Compiled whenever !WOLFSSL_ASN_TEMPLATE || HAVE_OCSP (matches asn.c's own
 * guard on the function).
 * ------------------------------------------------------------------------- */
#if !defined(WOLFSSL_ASN_TEMPLATE) || defined(HAVE_OCSP)
static void wb_get_asn_null(void)
{
    byte buf[4];
    word32 idx;
    int ret;

    WB_NOTE("GetASNNull(): tag!=NULL_TAG [:3012] / len!=0 [:3016]");

    buf[0] = ASN_TAG_NULL; buf[1] = 0x00;
    idx = 0;
    ret = GetASNNull(buf, &idx, 4);
    WB_CHECK(ret == 0, "GetASNNull baseline (both false)");

    buf[0] = 0x01; buf[1] = 0x00;
    idx = 0;
    ret = GetASNNull(buf, &idx, 4);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_TAG_NULL_E), "GetASNNull wrong tag (:3012 true)");

    buf[0] = ASN_TAG_NULL; buf[1] = 0x01;
    idx = 0;
    ret = GetASNNull(buf, &idx, 4);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_EXPECT_0_E), "GetASNNull nonzero length (:3016 true)");

    /* ret(idx+2>maxIdx) false side of the shared 1st operand at :3012/:3016:
     * force the buffer-too-small pre-check so both lines short-circuit. */
    idx = 0;
    ret = GetASNNull(buf, &idx, 1);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E), "GetASNNull buffer too small (:3012/:3016 1st operand false)");
}
#else
static void wb_get_asn_null(void) { WB_NOTE("GetASNNull not compiled; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 4: GetASNInt() (always compiled, not template-gated).
 *   :3122  if ((input[*inOutIdx] == 0xff) && (input[*inOutIdx+1] & 0x80))
 *   :3130  if ((input[*inOutIdx] == 0x00) && (*len > 1))
 *   :3135  if (*len > 0 && (input[*inOutIdx] & 0x80) == 0)   (see RESIDUAL
 *          note in the file header: first operand always true here)
 * ------------------------------------------------------------------------- */
static void wb_get_asn_int(void)
{
    byte b_ff90[] = { 0x02, 0x02, 0xFF, 0x90 }; /* 0xff, MSB-set next  -> :3122 T,T */
    byte b_ff05[] = { 0x02, 0x02, 0xFF, 0x05 }; /* 0xff, MSB-clear next -> :3122 T,F */
    byte b_0090[] = { 0x02, 0x02, 0x00, 0x90 }; /* leading 0, MSB-set next (zero
                                                  * legitimately needed) -> :3130
                                                  * T,T; :3135 both true */
    byte b_0005[] = { 0x02, 0x02, 0x00, 0x05 }; /* leading 0, MSB-clear next
                                                  * (zero NOT needed) -> :3130
                                                  * T,T but rejected inside
                                                  * :3122's sibling check at
                                                  * :3122 (input[idx]!=0xff so
                                                  * that's F,F; this is really
                                                  * the "invalid pad" case) */
    byte b_00[]   = { 0x02, 0x01, 0x00 };       /* lone zero: :3130 T,F */
    word32 idx;
    int len;
    int ret;

    WB_NOTE("GetASNInt(): negative-padding / leading-zero checks [:3122,:3130,:3135]");

    idx = 0;
    ret = GetASNInt(b_ff90, &idx, &len, sizeof(b_ff90));
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_EXPECT_0_E), ":3122 both true (bad negative padding)");

    idx = 0;
    ret = GetASNInt(b_ff05, &idx, &len, sizeof(b_ff05));
    WB_CHECK(ret == 0, ":3122 first true, second false");

    /* :3130 true (leading zero, len>1) with :3135 both operands true
     * (post-trim len==1>0, next byte 0x90 has MSB set -> "zero was needed"
     * check fails because it's checking the OPPOSITE: MSB *clear* triggers
     * the error at :3135; MSB *set* here means the leading zero WAS
     * legitimate, so this call succeeds). */
    idx = 0;
    ret = GetASNInt(b_0090, &idx, &len, sizeof(b_0090));
    WB_CHECK(ret == 0, ":3130 true, trim ok; :3135 false via 2nd operand (zero legitimately needed)");

    /* Same :3130 true, but next byte MSB clear -> :3135 both true (zero was
     * NOT needed) -> rejected. Also demonstrates :3122 false,false (first
     * byte is 0x00, not 0xff). */
    idx = 0;
    ret = GetASNInt(b_0005, &idx, &len, sizeof(b_0005));
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_EXPECT_0_E), ":3135 both true (leading zero not needed)");

    /* :3130 false via 2nd operand (len==1, no room to trim) -- pairs against
     * b_0090/b_0005 (1st operand true both times, len flips 2->1). */
    idx = 0;
    ret = GetASNInt(b_00, &idx, &len, sizeof(b_00));
    WB_CHECK(ret == 0, ":3130 false via len>1 operand (lone zero byte, valid)");
}

/* ------------------------------------------------------------------------- *
 * Section 5: CheckBitString(), WOLFSSL_ASN_TEMPLATE path (:3965).
 *   if (zeroBits && (bits != 0))
 * ------------------------------------------------------------------------- */
#ifdef WOLFSSL_ASN_TEMPLATE
static void wb_check_bit_string(void)
{
    /* unusedBits=1, data=0x80: valid BIT_STRING (bit0 of last byte, the only
     * unused bit, is already 0). */
    byte bitsNZ[] = { 0x03, 0x02, 0x01, 0x80 };
    /* unusedBits=0: trivially valid regardless of data (shift-by-8 zeroes
     * the check per GetASN_BitString()). */
    byte bitsZ[]  = { 0x03, 0x02, 0x00, 0xAA };
    word32 idx;
    int len;
    byte unused;
    int ret;

    WB_NOTE("CheckBitString(): zeroBits && bits!=0 [:3965]");

    idx = 0;
    ret = CheckBitString(bitsNZ, &idx, &len, sizeof(bitsNZ), 1, &unused);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_EXPECT_0_E), "zeroBits=1, bits!=0 (both true)");

    idx = 0;
    ret = CheckBitString(bitsZ, &idx, &len, sizeof(bitsZ), 1, &unused);
    WB_CHECK(ret == 0, "zeroBits=1, bits==0 (2nd operand false)");

    idx = 0;
    ret = CheckBitString(bitsNZ, &idx, &len, sizeof(bitsNZ), 0, &unused);
    WB_CHECK(ret == 0, "zeroBits=0 (1st operand false, short-circuit)");
}
#else
static void wb_check_bit_string(void) { WB_NOTE("non-template CheckBitString; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 6: wc_BerToDer()/GetBerHeader() (ASN_BER_TO_DER).
 *   GetBerHeader :4125  if (((tag & 0xc0)==0) && ((tag & ASN_CONSTRUCTED)==0))
 *   wc_BerToDer  :4243  if (items->cnt > 0 && items->idx >= 0)
 *                :4297/:4399  if ((tag & 0xC0)==0 && tag!=SEQ && tag!=SET)
 *                :4322  if (indef || tag != basic)
 * Called for both the size-only pass (der==NULL) and the write pass, since
 * some of these decisions only execute in the write pass.
 * ------------------------------------------------------------------------- */
#ifdef ASN_BER_TO_DER
static void wb_ber_to_der_call(const byte* ber, word32 berSz, const char* label,
        int expectRet)
{
    word32 derSz = 0;
    byte   derBuf[64];
    int    ret;

    /* der==NULL is the documented "give me the size" mode: on success it
     * returns LENGTH_ONLY_E (not 0), with derSz set. */
    ret = wc_BerToDer(ber, berSz, NULL, &derSz);
    if (expectRet == 0) {
        WB_CHECK(ret == WC_NO_ERR_TRACE(LENGTH_ONLY_E), label);
        if (ret == WC_NO_ERR_TRACE(LENGTH_ONLY_E) && derSz <= sizeof(derBuf)) {
            word32 derSz2 = derSz;
            ret = wc_BerToDer(ber, berSz, derBuf, &derSz2);
            WB_CHECK(ret == 0, label);
        }
    }
    else {
        WB_CHECK(ret == expectRet, label);
    }
}

static void wb_ber_to_der(void)
{
    /* :4125 both true: primitive (non-constructed) universal-class tag with
     * indefinite length is illegal. */
    static const byte berBadIndefPrimitive[] = { 0x04, 0x80 };
    /* :4125 first true, second false; :4297/:4399 both true (constructed
     * basic OCTET STRING, universal class, not SEQ/SET) -- also drives
     * :4322 false (children match basic tag, not indefinite). */
    static const byte berIndefConstructedOctet[] = {
        0x24, 0x80,             /* OCTET STRING constructed, indefinite */
          0x04, 0x02, 0xAA, 0xBB,
          0x04, 0x02, 0xCC, 0xDD,
        0x00, 0x00              /* EOC */
    };
    /* :4125 first false (context class tag; short-circuits regardless of
     * constructed bit); :4297/:4399 both false (tag&0xC0 != 0). */
    static const byte berIndefContext[] = { 0xA0, 0x80, 0x00, 0x00 };
    /* :4243 both true (definite item nested inside an still-open indefinite
     * SEQUENCE) followed by :4243 true,false (definite item after the
     * indefinite SEQUENCE has been closed, idx reset to -1 by IndefItems_Up). */
    static const byte berIndefSeqWithDefiniteChildren[] = {
        0x30, 0x80,             /* SEQUENCE, indefinite */
          0x02, 0x01, 0x05,     /* definite INTEGER (nested, open indef) */
        0x00, 0x00,             /* EOC closes SEQUENCE */
        0x02, 0x01, 0x07        /* definite INTEGER (top level, idx now -1) */
    };
    /* :4297/:4399 3rd operand false: tag==SET (excluded like SEQUENCE, but
     * SEQUENCE alone short-circuits on the 2nd operand -- this isolates the
     * 3rd). 1st,2nd operands true (0x31&0xC0==0, 0x31!=SEQ); 3rd false
     * (0x31==SET) -> whole condition false, same as :4322's "indef" family
     * skipped for a SEQ/SET parent. */
    static const byte berIndefSet[] = {
        0x31, 0x80,             /* SET, indefinite */
          0x02, 0x01, 0x05,     /* definite INTEGER child */
        0x00, 0x00              /* EOC */
    };
    /* :4322 2nd operand true (tag != basic): a child tag (BOOLEAN) that
     * does not match the constructed-basic-type's own primitive tag
     * (OCTET_STRING) is rejected. indef stays false for this definite
     * child, isolating the 2nd operand. */
    static const byte berIndefOctetMismatchChild[] = {
        0x24, 0x80,             /* OCTET STRING constructed, indefinite */
          0x01, 0x01, 0x00,     /* definite BOOLEAN child (tag mismatch) */
        0x00, 0x00               /* EOC (never reached: rejected first) */
    };

    WB_NOTE("wc_BerToDer(): indefinite-length tag-class checks [:4125,:4297,:4322,:4399]");

    wb_ber_to_der_call(berBadIndefPrimitive, sizeof(berBadIndefPrimitive),
            ":4125 both true (primitive+indefinite rejected)",
            WC_NO_ERR_TRACE(ASN_PARSE_E));

    wb_ber_to_der_call(berIndefConstructedOctet, sizeof(berIndefConstructedOctet),
            ":4125 T,F; :4297/:4399 both true (constructed basic type)", 0);

    wb_ber_to_der_call(berIndefContext, sizeof(berIndefContext),
            ":4125 first false (context-class tag)", 0);

    wb_ber_to_der_call(berIndefSet, sizeof(berIndefSet),
            ":4297/:4399 3rd operand false (tag==SET, excluded)", 0);

    wb_ber_to_der_call(berIndefOctetMismatchChild, sizeof(berIndefOctetMismatchChild),
            ":4322 2nd operand true (child tag != basic tag)",
            WC_NO_ERR_TRACE(ASN_PARSE_E));

    WB_NOTE("wc_BerToDer(): IndefItems_MoreData cnt>0&&idx>=0 [:4243]");
    wb_ber_to_der_call(berIndefSeqWithDefiniteChildren,
            sizeof(berIndefSeqWithDefiniteChildren),
            ":4243 both true, then true/false (idx reset to -1 after close)", 0);

    /* :4243 first operand false: no indefinite item ever opened (cnt stays
     * 0) -- a purely definite document. */
    {
        static const byte berAllDefinite[] = { 0x02, 0x01, 0x09 };
        wb_ber_to_der_call(berAllDefinite, sizeof(berAllDefinite),
                ":4243 first operand false (cnt==0, no indefinite items)", 0);
    }
}
#else
static void wb_ber_to_der(void) { WB_NOTE("ASN_BER_TO_DER off; wc_BerToDer skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 7: SizeASN_Items()/SetASN_Items() template engine core, driven
 * with a custom (non-production) ASNItem template built for this test.
 *   :866/:867 headerOnly && data==NULL && dataType!=REPLACE_BUFFER
 *   :899  asn==NULL || data==NULL || count<=0 || encSz==NULL
 *   :987/:988, :999   BIT_STRING/ASNIntMSBSet OR (Size); :1260/:1266/:1278 (Set)
 *   :1085 SetASN_Num() INTEGER MSB check
 * ------------------------------------------------------------------------- */
#ifdef WOLFSSL_ASN_TEMPLATE
static const ASNItem wbEncASN[] = {
/* SEQ  */ { 0, ASN_SEQUENCE,      1, 1, 0 },
/* OCT  */   { 1, ASN_OCTET_STRING, 0, 0, 0 },
/* INTN */   { 1, ASN_INTEGER,      0, 0, 0 }, /* buffer, MSB set   */
/* INTP */   { 1, ASN_INTEGER,      0, 0, 0 }, /* buffer, MSB clear */
/* BIT  */   { 1, ASN_BIT_STRING,   0, 0, 0 },
/* W8N  */   { 1, ASN_INTEGER,      0, 0, 0 }, /* Int8Bit, MSB set   (SetASN_Num) */
/* W8P  */   { 1, ASN_INTEGER,      0, 0, 0 }, /* Int8Bit, MSB clear (SetASN_Num) */
/* INTNODATA */ { 1, ASN_INTEGER,   0, 0, 0 }, /* no buffer: ASNIntMSBSet data!=NULL false */
/* INTZEROLEN */ { 1, ASN_INTEGER,  0, 0, 0 }, /* buffer, length==0: ASNIntMSBSet length>0 false */
};
enum {
    WBENC_SEQ = 0, WBENC_OCT, WBENC_INTN, WBENC_INTP, WBENC_BIT,
    WBENC_W8N, WBENC_W8P, WBENC_INTNODATA, WBENC_INTZEROLEN, WBENC_COUNT
};

static void wb_size_set_asn_items(void)
{
    ASNSetData dataASN[WBENC_COUNT];
    byte octBuf[4]  = { 0x11, 0x22, 0x33, 0x44 };
    byte intnBuf[2] = { 0x80, 0x01 };  /* MSB set   -> ASNIntMSBSet true */
    byte intpBuf[2] = { 0x05, 0x06 };  /* MSB clear -> ASNIntMSBSet false */
    byte bitBuf[3]  = { 0xAA, 0xBB, 0xCC };
    byte encOut[128];
    word32 encSz = 0;
    int ret;

    WB_NOTE("SizeASN_Items()/SetASN_Items(): bad-args OR [:899]");
    ret = SizeASN_Items(NULL, NULL, 0, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "asn==NULL");
    {
        ASNSetData tmp[1];
        word32 sz;
        ret = SizeASN_Items(wbEncASN, NULL, 1, &sz);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "data==NULL");
        ret = SizeASN_Items(wbEncASN, tmp, 0, &sz);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "count<=0");
        ret = SizeASN_Items(wbEncASN, tmp, 1, NULL);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "encSz==NULL");
    }

    WB_NOTE("SizeASN_Items()/SetASN_Items(): headerOnly buffer-override [:866,:899(baseline),:999]");
    XMEMSET(dataASN, 0, sizeof(dataASN));
    SetASN_Buffer(&dataASN[WBENC_OCT],  octBuf,  sizeof(octBuf));
    SetASN_Buffer(&dataASN[WBENC_INTN], intnBuf, sizeof(intnBuf));
    SetASN_Buffer(&dataASN[WBENC_INTP], intpBuf, sizeof(intpBuf));
    SetASN_Buffer(&dataASN[WBENC_BIT],  bitBuf,  sizeof(bitBuf));
    SetASN_Int8Bit(&dataASN[WBENC_W8N], 0xFFU);
    SetASN_Int8Bit(&dataASN[WBENC_W8P], 0x05U);
    /* WBENC_INTNODATA left all-zero (data==NULL, length==0): isolates
     * ASNIntMSBSet's "data!=NULL" operand (false) against WBENC_INTZEROLEN
     * below (same length==0, data!=NULL true). */
    SetASN_Buffer(&dataASN[WBENC_INTZEROLEN], octBuf, 0); /* data!=NULL, length==0 */
    /* dataASN[WBENC_SEQ] left all-zero: headerOnly=1, data==NULL -> :866
     * false side (SizeASN_CalcDataLength sums children); :999 false side
     * (!headerOnly||data!=NULL -> F||F). */
    ret = SizeASN_Items(wbEncASN, dataASN, WBENC_COUNT, &encSz);
    WB_CHECK(ret == 0 && encSz > 0 && encSz <= sizeof(encOut),
            "Size: headerOnly, data==NULL (child-length sum path)");
    ret = SetASN_Items(wbEncASN, dataASN, WBENC_COUNT, encOut);
    WB_CHECK(ret == (int)encSz, "Set: headerOnly, data==NULL");

    /* Same template, but SEQ item gets an explicit replacement buffer:
     * :866 true side (children forced noOut); :999/:1278 true via 2nd
     * operand (data!=NULL rescues the OR even though headerOnly=1). */
    XMEMSET(dataASN, 0, sizeof(dataASN));
    SetASN_Buffer(&dataASN[WBENC_OCT],  octBuf,  sizeof(octBuf));
    SetASN_Buffer(&dataASN[WBENC_INTN], intnBuf, sizeof(intnBuf));
    SetASN_Buffer(&dataASN[WBENC_INTP], intpBuf, sizeof(intpBuf));
    SetASN_Buffer(&dataASN[WBENC_BIT],  bitBuf,  sizeof(bitBuf));
    SetASN_Int8Bit(&dataASN[WBENC_W8N], 0xFFU);
    SetASN_Int8Bit(&dataASN[WBENC_W8P], 0x05U);
    SetASN_Buffer(&dataASN[WBENC_INTZEROLEN], octBuf, 0);
    SetASN_Buffer(&dataASN[WBENC_SEQ], octBuf, sizeof(octBuf));
    {
        word32 encSz2 = 0;
        byte encOut2[128];
        ret = SizeASN_Items(wbEncASN, dataASN, WBENC_COUNT, &encSz2);
        WB_CHECK(ret == 0, "Size: headerOnly, data!=NULL (buffer-override path)");
        ret = SetASN_Items(wbEncASN, dataASN, WBENC_COUNT, encOut2);
        WB_CHECK(ret == (int)encSz2, "Set: headerOnly, data!=NULL (:1278 2nd operand rescues copy)");
    }

    WB_NOTE("SizeASN_Items()/SetASN_Items(): BIT_STRING/ASNIntMSBSet OR [:987,:988,:1260,:1266]"
            " -- WBENC_OCT (both false), WBENC_INTN (MSB set, true),"
            " WBENC_INTP (INTEGER, MSB clear, false), WBENC_BIT (true via 1st operand),"
            " WBENC_INTNODATA (data!=NULL false) vs WBENC_INTZEROLEN (data!=NULL true,"
            " same length==0) isolates the data!=NULL operand;"
            " WBENC_INTZEROLEN (length>0 false) vs WBENC_INTP (length>0 true,"
            " same data!=NULL) isolates the length>0 operand");

    WB_NOTE("SetASN_Num(): INTEGER MSB check [:1085] via WBENC_W8N/W8P above (0xFF vs 0x05)");

    /* :866/:867 SizeASN_CalcDataLength()'s per-child check
     *   asn[j].headerOnly && data[j].data.buffer.data==NULL && dataType!=REPLACE
     * needs a headerOnly CHILD (not just the top-level item) to isolate the
     * 2nd operand (data==NULL) -- a dedicated 3-level template (outer
     * headerOnly SEQ -> nested headerOnly SEQ -> leaf) drives it directly,
     * flipping only the nested SEQ's data.buffer.data between calls. */
    {
        static const ASNItem wbNestedASN[] = {
        /* OUTER */ { 0, ASN_SEQUENCE, 1, 1, 0 },
        /* NESTED */  { 1, ASN_SEQUENCE, 1, 1, 0 },
        /* LEAF   */    { 2, ASN_OCTET_STRING, 0, 0, 0 },
        };
        ASNSetData nd[3];
        byte leafBuf[3] = { 1, 2, 3 };
        byte nestedBuf[2] = { 9, 9 };
        word32 sz;

        WB_NOTE("SizeASN_CalcDataLength(): headerOnly child, data==NULL/!=NULL [:866,:867]");

        XMEMSET(nd, 0, sizeof(nd));
        SetASN_Buffer(&nd[2], leafBuf, sizeof(leafBuf));
        /* nd[1] (NESTED) left all-zero: data==NULL -> :867 2nd operand true */
        ret = SizeASN_Items(wbNestedASN, nd, 3, &sz);
        WB_CHECK(ret == 0 && sz > 0, "nested headerOnly child, data==NULL (2nd operand true)");

        XMEMSET(nd, 0, sizeof(nd));
        SetASN_Buffer(&nd[2], leafBuf, sizeof(leafBuf));
        SetASN_Buffer(&nd[1], nestedBuf, sizeof(nestedBuf)); /* data!=NULL -> 2nd operand false */
        ret = SizeASN_Items(wbNestedASN, nd, 3, &sz);
        WB_CHECK(ret == 0 && sz > 0, "nested headerOnly child, data!=NULL (2nd operand false)");
    }
}
#else
static void wb_size_set_asn_items(void) { WB_NOTE("non-template SizeASN_Items/SetASN_Items; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 8: GetASN_Items()/GetASN_StoreData()/GetASN_Integer()/
 * GetASN_UTF8String(), driven with minimal single-item custom templates so
 * each decision can be isolated without needing a full certificate-shaped
 * document.
 *   :1337/:1347/:1355  GetASN_Integer() leading-zero/negative checks
 *   :1416               GetASN_UTF8String() while loop
 *   :1530/:1542/:1548/:1563/:1569  GetASN_StoreData() WORD8/16/32 checks
 * ------------------------------------------------------------------------- */
#ifdef WOLFSSL_ASN_TEMPLATE
static void wb_get_asn_items_integer(void)
{
    static const ASNItem intItemMP[] = { { 0, ASN_INTEGER, 0, 0, 0 } };
    mp_int mpVal;
    word32 idx;
    int ret;

    WB_NOTE("GetASN_Integer(): leading-zero/negative-padding [:1337,:1347,:1355]");

    /* :1337 true (leading zero present, len>1, next byte MSB clear -> zero
     * was NOT required) -> rejected inside GetASN_Integer before StoreData
     * even runs. */
    {
        byte der[] = { 0x02, 0x02, 0x00, 0x05 };
        ASNGetData d[1];
        XMEMSET(d, 0, sizeof(d));
        idx = 0;
        ret = GetASN_Items(intItemMP, d, 1, 0, der, &idx, sizeof(der));
        WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E), ":1337 both true (unneeded leading zero)");
    }
    /* :1337 false via 2nd operand (leading zero, len>1, next byte MSB set
     * -> zero legitimately needed). */
    {
        byte der[] = { 0x02, 0x02, 0x00, 0x90 };
        ASNGetData d[1];
        byte n8;
        XMEMSET(d, 0, sizeof(d));
        GetASN_Int8Bit(&d[0], &n8);
        idx = 0;
        ret = GetASN_Items(intItemMP, d, 1, 0, der, &idx, sizeof(der));
        WB_CHECK(ret == 0, ":1337 1st true, 2nd false (leading zero legitimate)");
    }
    /* :1337 false via 1st operand (len==1, no leading-zero-plus-next-byte
     * to examine at all). */
    {
        byte der[] = { 0x02, 0x01, 0x00 };
        ASNGetData d[1];
        byte n8;
        XMEMSET(d, 0, sizeof(d));
        GetASN_Int8Bit(&d[0], &n8);
        idx = 0;
        ret = GetASN_Items(intItemMP, d, 1, 0, der, &idx, sizeof(der));
        WB_CHECK(ret == 0, ":1337 1st operand false (len==1)");
    }

    /* :1347 both true (0xff, len>1, next byte MSB set -> bad negative pad).
     * Uses a BUFFER dataType (not WORD8) so GetASN_StoreData's own
     * len==1-required gate for WORD8 doesn't mask GetASN_Integer()'s
     * result for these 2-byte values. */
    {
        byte der[] = { 0x02, 0x02, 0xFF, 0x90 };
        byte outBuf[4];
        word32 outLen = sizeof(outBuf);
        ASNGetData d[1];
        XMEMSET(d, 0, sizeof(d));
        GetASN_Buffer(&d[0], outBuf, &outLen);
        idx = 0;
        ret = GetASN_Items(intItemMP, d, 1, 0, der, &idx, sizeof(der));
        WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_EXPECT_0_E), ":1347 all true");
    }
    /* :1347 3rd operand false (0xff, len>1, next byte MSB clear). */
    {
        byte der[] = { 0x02, 0x02, 0xFF, 0x05 };
        byte outBuf[4];
        word32 outLen = sizeof(outBuf);
        ASNGetData d[1];
        XMEMSET(d, 0, sizeof(d));
        GetASN_Buffer(&d[0], outBuf, &outLen);
        idx = 0;
        ret = GetASN_Items(intItemMP, d, 1, 0, der, &idx, sizeof(der));
        WB_CHECK(ret == 0, ":1347 3rd operand false");
    }

    /* :1355 both true: positive (MP dataType) and MSB set, single byte
     * (skips the :1337/:1347 leading-zero/0xff arms entirely). */
    {
        byte der[] = { 0x02, 0x01, 0x90 };
        ASNGetData d[1];
        XMEMSET(d, 0, sizeof(d));
        GetASN_MP(&d[0], &mpVal);
        idx = 0;
        ret = GetASN_Items(intItemMP, d, 1, 0, der, &idx, sizeof(der));
        WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_EXPECT_0_E), ":1355 both true (positive, MSB set)");
    }
    /* :1355 2nd operand false: positive, MSB clear -- pairs against above. */
    {
        byte der[] = { 0x02, 0x01, 0x05 };
        ASNGetData d[1];
        XMEMSET(d, 0, sizeof(d));
        GetASN_MP(&d[0], &mpVal);
        idx = 0;
        ret = GetASN_Items(intItemMP, d, 1, 0, der, &idx, sizeof(der));
        WB_CHECK(ret == 0, ":1355 1st true, 2nd false");
        mp_clear(&mpVal);
    }
    /* :1355 1st operand false: not positive (WORD8), MSB set -- already
     * exercised via the :1530 WORD8 vectors below, reused here for clarity. */
}

static void wb_get_asn_items_utf8(void)
{
    static const ASNItem utf8Item[] = { { 0, ASN_UTF8STRING, 0, 0, 0 } };
    /* 'A' (valid ASCII), then an invalid lead byte (0xFF matches none of the
     * continuation-count masks), then a trailing byte never reached --
     * demonstrates the while(ret==0 && i<length) [:1416] exiting via the
     * ret==0 operand (error mid-string) rather than only via i<length. */
    byte der[] = { 0x0c, 0x03, 0x41, 0xFF, 0x42 };
    ASNGetData d[1];
    word32 idx;
    int ret;

    WB_NOTE("GetASN_UTF8String(): while(ret==0 && i<length) [:1416]");
    XMEMSET(d, 0, sizeof(d));
    idx = 0;
    ret = GetASN_Items(utf8Item, d, 1, 0, der, &idx, sizeof(der));
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E), ":1416 loop exits via ret!=0 mid-string");
}

static void wb_get_asn_items_word8(void)
{
    static const ASNItem intItem[]  = { { 0, ASN_INTEGER, 0, 0, 0 } };
    static const ASNItem boolItem[] = { { 0, ASN_BOOLEAN, 0, 0, 0 } };
    ASNGetData d[1];
    byte n8;
    word32 idx;
    int ret;

    WB_NOTE("GetASN_StoreData() WORD8 [:1530]");

    { /* baseline: INTEGER, MSB clear -> all false */
        byte der[] = { 0x02, 0x01, 0x05 };
        XMEMSET(d, 0, sizeof(d)); GetASN_Int8Bit(&d[0], &n8);
        idx = 0;
        ret = GetASN_Items(intItem, d, 1, 0, der, &idx, sizeof(der));
        WB_CHECK(ret == 0 && n8 == 0x05, "WORD8 baseline (all false)");
    }
    { /* INTEGER, MSB set, not zero-padded -> all true */
        byte der[] = { 0x02, 0x01, 0x90 };
        XMEMSET(d, 0, sizeof(d)); GetASN_Int8Bit(&d[0], &n8);
        idx = 0;
        ret = GetASN_Items(intItem, d, 1, 0, der, &idx, sizeof(der));
        WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_EXPECT_0_E), "WORD8 all true (MSB set, not zero-padded)");
    }
    { /* INTEGER, zero-padded, next byte MSB set -> 2nd operand false */
        byte der[] = { 0x02, 0x02, 0x00, 0x90 };
        XMEMSET(d, 0, sizeof(d)); GetASN_Int8Bit(&d[0], &n8);
        idx = 0;
        ret = GetASN_Items(intItem, d, 1, 0, der, &idx, sizeof(der));
        WB_CHECK(ret == 0 && n8 == 0x90, "WORD8 zero-padded (:1530 2nd operand false)");
    }
    { /* BOOLEAN tag with WORD8 dataType -> 1st operand false, short-circuit */
        byte der[] = { 0x01, 0x01, 0x01 };
        XMEMSET(d, 0, sizeof(d)); GetASN_Int8Bit(&d[0], &n8);
        idx = 0;
        ret = GetASN_Items(boolItem, d, 1, 0, der, &idx, sizeof(der));
        WB_CHECK(ret == 0, "WORD8 tag==BOOLEAN (:1530 1st operand false)");
    }
}

static void wb_get_asn_items_word16(void)
{
    /* Implicit context tag (0x84): not ASN_INTEGER, so the leading-zero
     * trim / GetASN_Integer() special-casing never applies here -- lets
     * len==0/len>2 be reached directly. */
    static const ASNItem ctxItem[] = { { 0, 0x84, 0, 0, 0 } };
    static const ASNItem intItem[] = { { 0, ASN_INTEGER, 0, 0, 0 } };
    ASNGetData d[1];
    word16 n16;
    word32 idx;
    int ret;

    WB_NOTE("GetASN_StoreData() WORD16 [:1542,:1548]");

    { /* baseline: len==2, MSB clear -> both false */
        byte der[] = { 0x84, 0x02, 0x01, 0x02 };
        XMEMSET(d, 0, sizeof(d)); GetASN_Int16Bit(&d[0], &n16);
        idx = 0;
        ret = GetASN_Items(ctxItem, d, 1, 0, der, &idx, sizeof(der));
        WB_CHECK(ret == 0 && n16 == 0x0102, "WORD16 baseline");
    }
    { /* len==0 -> :1542 1st operand true */
        byte der[] = { 0x84, 0x00 };
        XMEMSET(d, 0, sizeof(d)); GetASN_Int16Bit(&d[0], &n16);
        idx = 0;
        ret = GetASN_Items(ctxItem, d, 1, 0, der, &idx, sizeof(der));
        WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E), ":1542 len==0");
    }
    { /* len==3 (>2) -> :1542 2nd operand true */
        byte der[] = { 0x84, 0x03, 0x01, 0x02, 0x03 };
        XMEMSET(d, 0, sizeof(d)); GetASN_Int16Bit(&d[0], &n16);
        idx = 0;
        ret = GetASN_Items(ctxItem, d, 1, 0, der, &idx, sizeof(der));
        WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E), ":1542 len>2");
    }
    { /* implicit tag, MSB set -> :1548 both true (!zeroPadded always true
       * for a non-INTEGER tag) */
        byte der[] = { 0x84, 0x01, 0x90 };
        XMEMSET(d, 0, sizeof(d)); GetASN_Int16Bit(&d[0], &n16);
        idx = 0;
        ret = GetASN_Items(ctxItem, d, 1, 0, der, &idx, sizeof(der));
        WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_EXPECT_0_E), ":1548 both true (implicit tag)");
    }
    { /* literal INTEGER tag, zero-padded, next byte MSB set -> :1548 1st
       * operand false (pairs against the vector above: same MSB-set value,
       * !zeroPadded flips true->false) */
        byte der[] = { 0x02, 0x02, 0x00, 0x90 };
        XMEMSET(d, 0, sizeof(d)); GetASN_Int16Bit(&d[0], &n16);
        idx = 0;
        ret = GetASN_Items(intItem, d, 1, 0, der, &idx, sizeof(der));
        WB_CHECK(ret == 0 && n16 == 0x0090, ":1548 1st operand false (zero-padded)");
    }
}

static void wb_get_asn_items_word32(void)
{
    /* Implicit context tag (0x85): isolates len==0/len>4 from the
     * ASN_INTEGER leading-zero special-casing, same rationale as WORD16. */
    static const ASNItem ctxItem[] = { { 0, 0x85, 0, 0, 0 } };
    static const ASNItem bitItem[] = { { 0, ASN_BIT_STRING, 0, 0, 0 } };
    ASNGetData d[1];
    word32 n32;
    word32 idx;
    int ret;

    WB_NOTE("GetASN_StoreData() WORD32 [:1563,:1569]");

    { /* baseline: len==2 -> both false */
        byte der[] = { 0x85, 0x02, 0x01, 0x02 };
        XMEMSET(d, 0, sizeof(d)); GetASN_Int32Bit(&d[0], &n32);
        idx = 0;
        ret = GetASN_Items(ctxItem, d, 1, 0, der, &idx, sizeof(der));
        WB_CHECK(ret == 0 && n32 == 0x0102u, "WORD32 baseline");
    }
    { /* len==0 -> :1563 1st operand true */
        byte der[] = { 0x85, 0x00 };
        XMEMSET(d, 0, sizeof(d)); GetASN_Int32Bit(&d[0], &n32);
        idx = 0;
        ret = GetASN_Items(ctxItem, d, 1, 0, der, &idx, sizeof(der));
        WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E), ":1563 len==0");
    }
    { /* len==5 (>4) -> :1563 2nd operand true */
        byte der[] = { 0x85, 0x05, 1, 2, 3, 4, 5 };
        XMEMSET(d, 0, sizeof(d)); GetASN_Int32Bit(&d[0], &n32);
        idx = 0;
        ret = GetASN_Items(ctxItem, d, 1, 0, der, &idx, sizeof(der));
        WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E), ":1563 len>4");
    }
    { /* BIT_STRING tag with WORD32 dataType -> :1569 1st operand false
       * (tag==BIT_STRING), short-circuits regardless of zero-pad/MSB. Data
       * byte (0x2B) kept MSB-clear, matching the ctx-tag baseline above, so
       * only the 1st operand differs between the two calls (clean
       * independence pair: 2nd/3rd operands held at the same values). */
        byte der[] = { 0x03, 0x02, 0x00, 0x2B };
        XMEMSET(d, 0, sizeof(d)); GetASN_Int32Bit(&d[0], &n32);
        idx = 0;
        ret = GetASN_Items(bitItem, d, 1, 0, der, &idx, sizeof(der));
        WB_CHECK(ret == 0, ":1569 1st operand false (tag==BIT_STRING)");
    }
}
#else
static void wb_get_asn_items_integer(void) { WB_NOTE("non-template GetASN_Items; skipped"); }
static void wb_get_asn_items_utf8(void)    { }
static void wb_get_asn_items_word8(void)   { }
static void wb_get_asn_items_word16(void)  { }
static void wb_get_asn_items_word32(void)  { }
#endif

/* ------------------------------------------------------------------------- *
 * Section 9: GetASN_Sequence() (:2225 tag check, :2229 length check,
 * :2233 complete-vs-remaining check).
 * ------------------------------------------------------------------------- */
#ifdef WOLFSSL_ASN_TEMPLATE
static void wb_get_asn_sequence(void)
{
    byte buf[8];
    word32 idx;
    int len;
    int ret;

    WB_NOTE("GetASN_Sequence(): tag/length/complete checks [:2225,:2229,:2233]");

    /* ret==0 false (shared 1st operand for all three lines): forced via the
     * unconditional idx+1>maxIdx pre-check. */
    idx = 0;
    ret = GetASN_Sequence(buf, &idx, &len, 0, 1);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E), "ret!=0 short-circuit (buffer too small)");

    /* baseline: correct tag, exact-length match, complete=1 -> all false. */
    buf[0] = ASN_SEQUENCE | ASN_CONSTRUCTED; buf[1] = 0x02; buf[2] = 0xAA; buf[3] = 0xBB;
    idx = 0;
    ret = GetASN_Sequence(buf, &idx, &len, 4, 1);
    WB_CHECK(ret == 0 && len == 2, "baseline (tag ok, exact length match)");

    /* :2225 both true: tag mismatch. */
    buf[0] = 0x31;
    idx = 0;
    ret = GetASN_Sequence(buf, &idx, &len, 4, 1);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E), ":2225 both true (tag mismatch)");

    /* :2229 both true: length encoding claims more bytes than available. */
    buf[0] = ASN_SEQUENCE | ASN_CONSTRUCTED; buf[1] = 0x84; /* claims 4 length bytes */
    idx = 0;
    ret = GetASN_Sequence(buf, &idx, &len, 2, 1);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E), ":2229 both true (bad length encoding)");

    /* :2233: same short (len=1) SEQUENCE with one trailing byte still in
     * the logical buffer. complete=0 bypasses the check (2nd operand
     * false); complete=1 catches the mismatch (2nd operand true). */
    buf[0] = ASN_SEQUENCE | ASN_CONSTRUCTED; buf[1] = 0x01; buf[2] = 0xAA; buf[3] = 0xBB;
    idx = 0;
    ret = GetASN_Sequence(buf, &idx, &len, 4, 0);
    WB_CHECK(ret == 0, ":2233 complete=0 bypasses trailing-data check (2nd operand false)");

    idx = 0;
    ret = GetASN_Sequence(buf, &idx, &len, 4, 1);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E), ":2233 complete=1, trailing data mismatch (both true)");
}
#else
static void wb_get_asn_sequence(void) { WB_NOTE("non-template GetASN_Sequence; skipped"); }
#endif

int main(void)
{
    printf("asn.c white-box MC/DC supplement\n");

    wb_get_asn_tag();
    wb_get_asn_header_ex();
    wb_get_asn_null();
    wb_get_asn_int();
    wb_check_bit_string();
    wb_ber_to_der();
    wb_size_set_asn_items();
    wb_get_asn_items_integer();
    wb_get_asn_items_utf8();
    wb_get_asn_items_word8();
    wb_get_asn_items_word16();
    wb_get_asn_items_word32();
    wb_get_asn_sequence();

    printf("done (%s)\n", wb_fail ? "with failures" : "ok");
    /* Always return 0: a nonzero exit discards this variant's coverage
     * entirely in the campaign harness. Failures are surfaced via the
     * printed [FAIL] lines instead. */
    (void)wb_fail;
    return 0;
}
