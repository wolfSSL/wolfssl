/* test_coding.c
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

#include <tests/unit.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <tests/api/api.h>
#include <tests/api/test_coding.h>

/*
 * MC/DC DecisionCoverage for wolfcrypt/src/coding.c (Base64 / Base16).
 *
 * Base64_SkipNewline() is WOLFSSL_LOCAL (hidden visibility): it is NOT called
 * directly here (that would break the shared shared-lib CI), it is exercised
 * only indirectly via Base64_Decode() on inputs containing embedded
 * whitespace / CR / LF, in test_wc_Base64_DecodeWhitespaceCoverage below.
 */

/* Exercises the argument-check OR, the padding logic, the bad-character and
 * short-output-buffer branches of Base64_Decode() (constant-time path) and
 * Base64_Decode_nonCT() (table path). */
int test_wc_Base64_DecodeDecisionCoverage(void)
{
    EXPECT_DECLS;
#if !defined(NO_CODING) && defined(WOLFSSL_BASE64_DECODE)
    /* "TWFu" -> "Man" */
    const byte good[]  = { 'T', 'W', 'F', 'u' };
    byte out[8];
    word32 outLen;

    /* --- argument-check decision: (in==NULL && inLen>0) || out==NULL ||
     *     outLen==NULL --- independence pair for each operand */
    /* in==NULL, inLen>0  -> true  (BAD_FUNC_ARG) */
    outLen = (word32)sizeof(out);
    ExpectIntEQ(Base64_Decode(NULL, 4, out, &outLen),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* in!=NULL, inLen>0  -> the (in==NULL && inLen>0) sub-term is false */
    outLen = (word32)sizeof(out);
    ExpectIntEQ(Base64_Decode(good, (word32)sizeof(good), out, &outLen), 0);
    /* in==NULL, inLen==0 -> (in==NULL && inLen>0) false; other operands false */
    outLen = (word32)sizeof(out);
    ExpectIntEQ(Base64_Decode(NULL, 0, out, &outLen), 0);
    /* out==NULL alone -> true */
    outLen = (word32)sizeof(out);
    ExpectIntEQ(Base64_Decode(good, (word32)sizeof(good), NULL, &outLen),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* outLen==NULL alone -> true */
    ExpectIntEQ(Base64_Decode(good, (word32)sizeof(good), out, NULL),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* --- valid decode, verify result --- */
    outLen = (word32)sizeof(out);
    ExpectIntEQ(Base64_Decode(good, (word32)sizeof(good), out, &outLen), 0);
    ExpectIntEQ(outLen, 3);
    ExpectIntEQ(XMEMCMP(out, "Man", 3), 0);

    /* --- padding decisions --- */
    /* pad3 && pad4 : "TQ==" -> "M" (1 byte) */
    {
        const byte p2[] = { 'T', 'Q', '=', '=' };
        outLen = (word32)sizeof(out);
        ExpectIntEQ(Base64_Decode(p2, (word32)sizeof(p2), out, &outLen), 0);
        ExpectIntEQ(outLen, 1);
        ExpectIntEQ(out[0], 'M');
    }
    /* !pad3 && pad4 : "TWE=" -> "Ma" (2 bytes) */
    {
        const byte p1[] = { 'T', 'W', 'E', '=' };
        outLen = (word32)sizeof(out);
        ExpectIntEQ(Base64_Decode(p1, (word32)sizeof(p1), out, &outLen), 0);
        ExpectIntEQ(outLen, 2);
        ExpectIntEQ(XMEMCMP(out, "Ma", 2), 0);
    }
    /* pad3 && !pad4 : illegal -> ASN_INPUT_E */
    {
        const byte bad[] = { 'T', 'W', '=', 'u' };
        outLen = (word32)sizeof(out);
        ExpectIntEQ(Base64_Decode(bad, (word32)sizeof(bad), out, &outLen),
                    WC_NO_ERR_TRACE(ASN_INPUT_E));
    }

    /* --- bad character (not in alphabet) -> ASN_INPUT_E --- */
    {
        const byte bad[] = { 'T', '@', 'F', 'u' };
        outLen = (word32)sizeof(out);
        ExpectIntEQ(Base64_Decode(bad, (word32)sizeof(bad), out, &outLen),
                    WC_NO_ERR_TRACE(ASN_INPUT_E));
    }

    /* --- output buffer too small -> BUFFER_E --- */
    outLen = 1;
    ExpectIntEQ(Base64_Decode(good, (word32)sizeof(good), out, &outLen),
                WC_NO_ERR_TRACE(BUFFER_E));

    /* --- trailing non-whitespace after a full quantum -> ASN_INPUT_E --- */
    {
        const byte tr[] = { 'T', 'W', 'F', 'u', '!' };
        outLen = (word32)sizeof(out);
        ExpectIntEQ(Base64_Decode(tr, (word32)sizeof(tr), out, &outLen),
                    WC_NO_ERR_TRACE(ASN_INPUT_E));
    }

    /* --- table (non constant-time) decode path --- */
    outLen = (word32)sizeof(out);
    ExpectIntEQ(Base64_Decode_nonCT(good, (word32)sizeof(good), out, &outLen),
                0);
    ExpectIntEQ(outLen, 3);
    ExpectIntEQ(XMEMCMP(out, "Man", 3), 0);
#endif
    return EXPECT_RESULT();
}

/* Drives Base64_SkipNewline() (indirectly) through Base64_Decode(): embedded
 * spaces, LF, CR LF, and the "not enough buffer" / bad-EOL branches. */
int test_wc_Base64_DecodeWhitespaceCoverage(void)
{
    EXPECT_DECLS;
#if !defined(NO_CODING) && defined(WOLFSSL_BASE64_DECODE)
    byte out[16];
    word32 outLen;

    /* LF between quanta: "TWFu\nTWFu" -> "ManMan" */
    {
        const byte in[] = { 'T','W','F','u','\n','T','W','F','u' };
        outLen = (word32)sizeof(out);
        ExpectIntEQ(Base64_Decode(in, (word32)sizeof(in), out, &outLen), 0);
        ExpectIntEQ(outLen, 6);
        ExpectIntEQ(XMEMCMP(out, "ManMan", 6), 0);
    }
    /* CR LF sequence between quanta */
    {
        const byte in[] = { 'T','W','F','u','\r','\n','T','W','F','u' };
        outLen = (word32)sizeof(out);
        ExpectIntEQ(Base64_Decode(in, (word32)sizeof(in), out, &outLen), 0);
        ExpectIntEQ(outLen, 6);
        ExpectIntEQ(XMEMCMP(out, "ManMan", 6), 0);
    }
    /* embedded spaces (skipped as whitespace) */
    {
        const byte in[] = { 'T','W','F','u',' ',' ','T','W','F','u' };
        outLen = (word32)sizeof(out);
        ExpectIntEQ(Base64_Decode(in, (word32)sizeof(in), out, &outLen), 0);
        ExpectIntEQ(outLen, 6);
    }
    /* CR not followed by LF -> bad end of line -> ASN_INPUT_E */
    {
        const byte in[] = { 'T','W','F','u','\r','x','T','u' };
        outLen = (word32)sizeof(out);
        ExpectIntEQ(Base64_Decode(in, (word32)sizeof(in), out, &outLen),
                    WC_NO_ERR_TRACE(ASN_INPUT_E));
    }
    /* trailing whitespace after final quantum is tolerated */
    {
        const byte in[] = { 'T','W','F','u','\n' };
        outLen = (word32)sizeof(out);
        ExpectIntEQ(Base64_Decode(in, (word32)sizeof(in), out, &outLen), 0);
        ExpectIntEQ(outLen, 3);
    }
#endif
    return EXPECT_RESULT();
}

/* Base64_Encode / Base64_EncodeEsc / Base64_Encode_NoNl:
 * arg checks, length-only (out==NULL) path, buffer-too-small, escape logic. */
int test_wc_Base64_EncodeDecisionCoverage(void)
{
    EXPECT_DECLS;
#if !defined(NO_CODING) && defined(WOLFSSL_BASE64_ENCODE)
    const byte in[]   = { 'M', 'a', 'n' };
    byte out[64];
    word32 outLen;

    /* in==NULL && inLen>0 -> BAD_FUNC_ARG */
    outLen = (word32)sizeof(out);
    ExpectIntEQ(Base64_Encode(NULL, 3, out, &outLen),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* outLen==NULL -> BAD_FUNC_ARG */
    ExpectIntEQ(Base64_Encode(in, (word32)sizeof(in), out, NULL),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* out==NULL -> length-only query returns LENGTH_ONLY_E and sets outLen */
    outLen = 0;
    ExpectIntEQ(Base64_Encode(in, (word32)sizeof(in), NULL, &outLen),
                WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    ExpectIntGT(outLen, 0);

    /* output buffer too small -> BAD_FUNC_ARG */
    outLen = 2;
    ExpectIntEQ(Base64_Encode(in, (word32)sizeof(in), out, &outLen),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* valid encode with trailing newline (WC_STD_ENC) */
    outLen = (word32)sizeof(out);
    ExpectIntEQ(Base64_Encode(in, (word32)sizeof(in), out, &outLen), 0);
    ExpectIntGT(outLen, 0);

    /* valid encode without newline (WC_NO_NL_ENC) -> "TWFu" */
    outLen = (word32)sizeof(out);
    ExpectIntEQ(Base64_Encode_NoNl(in, (word32)sizeof(in), out, &outLen), 0);
    ExpectIntEQ(outLen, 4);
    ExpectIntEQ(XMEMCMP(out, "TWFu", 4), 0);

    /* escaped-newline encode (WC_ESC_NL_ENC): a payload long enough to force a
     * line break drives the CEscape() '\n' -> "%0A" and '+' / '=' escapes. */
    {
        byte big[80];
        byte enc[512];
        word32 i;
        for (i = 0; i < (word32)sizeof(big); i++)
            big[i] = (byte)(0xF8 + (i & 0x7)); /* yields '+' and '/' indices */
        outLen = (word32)sizeof(enc);
        ExpectIntEQ(Base64_EncodeEsc(big, (word32)sizeof(big), enc, &outLen), 0);
        ExpectIntGT(outLen, 0);
    }
#endif
    return EXPECT_RESULT();
}

/* Base16_Encode / Base16_Decode: arg checks, single-byte decode, odd-length,
 * bad-character, short-buffer, and a round-trip. */
int test_wc_Base16DecisionCoverage(void)
{
    EXPECT_DECLS;
#if !defined(NO_CODING) && defined(WOLFSSL_BASE16)
    const byte raw[] = { 0x0A, 0xB3, 0xFF };
    byte hex[8];
    byte back[8];
    word32 hexLen;
    word32 backLen;

    /* --- Base16_Encode arg checks --- */
    hexLen = (word32)sizeof(hex);
    ExpectIntEQ(Base16_Encode(NULL, 3, hex, &hexLen),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    hexLen = (word32)sizeof(hex);
    ExpectIntEQ(Base16_Encode(raw, 3, NULL, &hexLen),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(Base16_Encode(raw, 3, hex, NULL),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* output too small (*outLen < 2*inLen) -> BAD_FUNC_ARG */
    hexLen = 2;
    ExpectIntEQ(Base16_Encode(raw, 3, hex, &hexLen),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* --- valid encode (buffer has room, so a NUL is appended and counted) --- */
    hexLen = (word32)sizeof(hex);
    ExpectIntEQ(Base16_Encode(raw, (word32)sizeof(raw), hex, &hexLen), 0);
    ExpectIntEQ(hexLen, 7); /* 6 hex chars + appended NUL terminator */
    ExpectIntEQ(XMEMCMP(hex, "0AB3FF", 6), 0);

    /* --- Base16_Decode arg checks --- */
    backLen = (word32)sizeof(back);
    ExpectIntEQ(Base16_Decode(NULL, 6, back, &backLen),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    backLen = (word32)sizeof(back);
    ExpectIntEQ(Base16_Decode(hex, 6, NULL, &backLen),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(Base16_Decode(hex, 6, back, NULL),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* odd length (>1) -> BAD_FUNC_ARG */
    backLen = (word32)sizeof(back);
    ExpectIntEQ(Base16_Decode(hex, 3, back, &backLen),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* output too small -> BUFFER_E */
    backLen = 1;
    ExpectIntEQ(Base16_Decode(hex, 6, back, &backLen),
                WC_NO_ERR_TRACE(BUFFER_E));

    /* single-byte decode path: "A" -> 0x0A */
    {
        const byte one[] = { 'A' };
        backLen = (word32)sizeof(back);
        ExpectIntEQ(Base16_Decode(one, 1, back, &backLen), 0);
        ExpectIntEQ(backLen, 1);
        ExpectIntEQ(back[0], 0x0A);
    }

    /* bad character -> ASN_INPUT_E ('G' is out of the hex alphabet) */
    {
        const byte bad[] = { 'G', 'G' };
        backLen = (word32)sizeof(back);
        ExpectIntEQ(Base16_Decode(bad, 2, back, &backLen),
                    WC_NO_ERR_TRACE(ASN_INPUT_E));
    }

    /* --- round-trip decode of the earlier encode --- */
    backLen = (word32)sizeof(back);
    ExpectIntEQ(Base16_Decode(hex, 6, back, &backLen), 0);
    ExpectIntEQ(backLen, 3);
    ExpectIntEQ(XMEMCMP(back, raw, 3), 0);
#endif
    return EXPECT_RESULT();
}
