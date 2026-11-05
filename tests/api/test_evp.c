/* test_evp.c
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

#include <wolfssl/wolfcrypt/error-crypt.h>

#include <wolfssl/openssl/evp.h>
#include <tests/api/test_evp.h>

/* Test functions for base64 encode/decode */
int test_wolfSSL_EVP_ENCODE_CTX_new(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && \
( defined(WOLFSSL_BASE64_ENCODE) || defined(WOLFSSL_BASE64_DECODE))
    EVP_ENCODE_CTX* ctx = NULL;

    ExpectNotNull(ctx = EVP_ENCODE_CTX_new());
    ExpectIntEQ(ctx->remaining,0);
    ExpectIntEQ(ctx->data[0],0);
    ExpectIntEQ(ctx->data[sizeof(ctx->data) -1],0);
    EVP_ENCODE_CTX_free(ctx);
#endif /* OPENSSL_EXTRA && (WOLFSSL_BASE64_ENCODE || WOLFSSL_BASE64_DECODE) */
    return EXPECT_RESULT();
}
int test_wolfSSL_EVP_ENCODE_CTX_free(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && \
( defined(WOLFSSL_BASE64_ENCODE) || defined(WOLFSSL_BASE64_DECODE))
    EVP_ENCODE_CTX* ctx = NULL;

    ExpectNotNull(ctx = EVP_ENCODE_CTX_new());
    EVP_ENCODE_CTX_free(ctx);
#endif /* OPENSSL_EXTRA && (WOLFSSL_BASE64_ENCODE || WOLFSSL_BASE64_DECODE) */
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_EncodeInit(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_BASE64_ENCODE)
    EVP_ENCODE_CTX* ctx = NULL;

    ExpectNotNull(ctx = EVP_ENCODE_CTX_new());
    ExpectIntEQ(ctx->remaining, 0);
    ExpectIntEQ(ctx->data[0], 0);
    ExpectIntEQ(ctx->data[sizeof(ctx->data) -1], 0);

    if (ctx != NULL) {
        /* make ctx dirty */
        ctx->remaining = 10;
        XMEMSET(ctx->data, 0x77, sizeof(ctx->data));
    }

    EVP_EncodeInit(ctx);

    ExpectIntEQ(ctx->remaining, 0);
    ExpectIntEQ(ctx->data[0], 0);
    ExpectIntEQ(ctx->data[sizeof(ctx->data) -1], 0);

    EVP_ENCODE_CTX_free(ctx);
#endif /* OPENSSL_EXTRA && WOLFSSL_BASE64_ENCODE*/
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_EncodeUpdate(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_BASE64_ENCODE)
    int outl;
    int total;

    const unsigned char plain0[] = {"Th"};
    const unsigned char plain1[] = {"This is a base64 encodeing test."};
    const unsigned char plain2[] = {"This is additional data."};

    const unsigned char encBlock0[] = {"VGg="};
    const unsigned char enc0[]   = {"VGg=\n"};
    /* expected encoded result for the first output 64 chars plus trailing LF*/
    const unsigned char enc1[]   = {
        "VGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVpbmcgdGVzdC5UaGlzIGlzIGFkZGl0aW9u\n"
    };

    const unsigned char enc2[]   = {
        "VGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVpbmcgdGVzdC5UaGlzIGlzIGFkZGl0aW9u\n"
        "YWwgZGF0YS4=\n"
    };

    unsigned char encOutBuff[300];

    EVP_ENCODE_CTX* ctx = NULL;

    ExpectNotNull(ctx = EVP_ENCODE_CTX_new());

    EVP_EncodeInit(ctx);

    /* illegal parameter test */
    ExpectIntEQ(
        EVP_EncodeUpdate(
            NULL,            /* pass NULL as ctx */
            encOutBuff,
            &outl,
            plain1,
            sizeof(plain1)-1),
        0                    /* expected result code 0: fail */
    );

    ExpectIntEQ(
        EVP_EncodeUpdate(
            ctx,
            NULL,           /* pass NULL as out buff */
            &outl,
            plain1,
            sizeof(plain1)-1),
        0                    /* expected result code 0: fail */
    );

    ExpectIntEQ(
        EVP_EncodeUpdate(
            ctx,
            encOutBuff,
            NULL,            /* pass NULL as outl */
            plain1,
            sizeof(plain1)-1),
        0                    /* expected result code 0: fail */
    );

    ExpectIntEQ(
        EVP_EncodeUpdate(
            ctx,
            encOutBuff,
            &outl,
            NULL,            /* pass NULL as in */
            sizeof(plain1)-1),
        0                    /* expected result code 0: fail */
    );

    ExpectIntEQ(EVP_EncodeBlock(NULL, NULL, 0), -1);

    /* meaningless parameter test */

    ExpectIntEQ(
        EVP_EncodeUpdate(
            ctx,
            encOutBuff,
            &outl,
            plain1,
            0),              /* pass zero input */
        1                    /* expected result code 1: success */
    );

    /* very small data encoding test */

    EVP_EncodeInit(ctx);

    ExpectIntEQ(
        EVP_EncodeUpdate(
            ctx,
            encOutBuff,
            &outl,
            plain0,
            sizeof(plain0)-1),
        1                    /* expected result code 1: success */
    );
    ExpectIntEQ(outl,0);

    if (EXPECT_SUCCESS()) {
        EVP_EncodeFinal(
            ctx,
            encOutBuff + outl,
            &outl);
    }

    ExpectIntEQ( outl, sizeof(enc0)-1);
    ExpectIntEQ(
        XSTRNCMP(
            (const char*)encOutBuff,
            (const char*)enc0,sizeof(enc0) ),
    0);

    XMEMSET( encOutBuff,0, sizeof(encOutBuff));
    ExpectIntEQ(EVP_EncodeBlock(encOutBuff, plain0, sizeof(plain0)-1),
                sizeof(encBlock0)-1);
    ExpectStrEQ(encOutBuff, encBlock0);

    /* oversized length must be rejected, not read past the input buffer */
    XMEMSET( encOutBuff,0, sizeof(encOutBuff));
    ExpectIntEQ(EVP_EncodeBlock(encOutBuff, plain0, 0x7FFFFFFF), -1);

    /* oversized length must be rejected by EVP_EncodeUpdate as well, rather
     * than reading far past the caller's input buffer */
    EVP_EncodeInit(ctx);
    outl = 1;
    XMEMSET( encOutBuff,0, sizeof(encOutBuff));
    ExpectIntEQ(
        EVP_EncodeUpdate(
            ctx,
            encOutBuff,
            &outl,
            plain0,
            0x7FFFFFFF),
        0);
    ExpectIntEQ(outl, 0);

    /* pass small size( < 48bytes ) input, then make sure they are not
     * encoded  and just stored in ctx
     */

    EVP_EncodeInit(ctx);

    total = 0;
    outl = 0;
    XMEMSET( encOutBuff,0, sizeof(encOutBuff));

    ExpectIntEQ(
    EVP_EncodeUpdate(
        ctx,
        encOutBuff,         /* buffer for output */
        &outl,              /* size of output */
        plain1,             /* input */
        sizeof(plain1)-1),  /* size of input */
        1);                 /* expected result code 1:success */

    total += outl;

    ExpectIntEQ(outl, 0);  /* no output expected */
    ExpectIntEQ(ctx->remaining, sizeof(plain1) -1);
    ExpectTrue(
        XSTRNCMP((const char*)(ctx->data),
                 (const char*)plain1,
                 ctx->remaining) ==0 );
    ExpectTrue(encOutBuff[0] == 0);

    /* call wolfSSL_EVP_EncodeUpdate again to make it encode
     * the stored data and the new input together
     */
    ExpectIntEQ(
    EVP_EncodeUpdate(
        ctx,
        encOutBuff + outl,  /* buffer for output */
        &outl,              /* size of output */
        plain2,             /* additional input */
        sizeof(plain2) -1), /* size of additional input */
        1);                 /* expected result code 1:success */

    total += outl;

    ExpectIntNE(outl, 0);   /* some output is expected this time*/
    ExpectIntEQ(outl, BASE64_ENCODE_RESULT_BLOCK_SIZE +1); /* 64 bytes and LF */
    ExpectIntEQ(
        XSTRNCMP((const char*)encOutBuff,(const char*)enc1,sizeof(enc1) ),0);

    /* call wolfSSL_EVP_EncodeFinal to flush all the unprocessed input */
    EVP_EncodeFinal(
        ctx,
        encOutBuff + outl,
        &outl);

    total += outl;

    ExpectIntNE(total,0);
    ExpectIntNE(outl,0);
    ExpectIntEQ(XSTRNCMP(
        (const char*)encOutBuff,(const char*)enc2,sizeof(enc2) ),0);

    /* test with illeagal parameters */
    outl = 1;
    EVP_EncodeFinal(NULL, encOutBuff + outl, &outl);
    ExpectIntEQ(outl, 0);
    outl = 1;
    EVP_EncodeFinal(ctx, NULL, &outl);
    ExpectIntEQ(outl, 0);
    EVP_EncodeFinal(ctx, encOutBuff + outl, NULL);
    EVP_EncodeFinal(NULL, NULL, NULL);

    EVP_ENCODE_CTX_free(ctx);
#endif /* OPENSSL_EXTRA && WOLFSSL_BASE64_ENCODE*/
    return EXPECT_RESULT();
}
int test_wolfSSL_EVP_EncodeFinal(void)
{
    int res = TEST_SKIPPED;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_BASE64_ENCODE)
    /* tests for wolfSSL_EVP_EncodeFinal are included in
     * test_wolfSSL_EVP_EncodeUpdate
     */
    res = TEST_SUCCESS;
#endif /* OPENSSL_EXTRA && WOLFSSL_BASE64_ENCODE*/
    return res;
}


int test_wolfSSL_EVP_DecodeInit(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_BASE64_DECODE)
    EVP_ENCODE_CTX* ctx = NULL;

    ExpectNotNull( ctx = EVP_ENCODE_CTX_new());
    ExpectIntEQ( ctx->remaining,0);
    ExpectIntEQ( ctx->data[0],0);
    ExpectIntEQ( ctx->data[sizeof(ctx->data) -1],0);

    if (ctx != NULL) {
        /* make ctx dirty */
        ctx->remaining = 10;
        XMEMSET( ctx->data, 0x77, sizeof(ctx->data));
    }

    EVP_DecodeInit(ctx);

    ExpectIntEQ( ctx->remaining,0);
    ExpectIntEQ( ctx->data[0],0);
    ExpectIntEQ( ctx->data[sizeof(ctx->data) -1],0);

    EVP_ENCODE_CTX_free(ctx);
#endif /* OPENSSL && WOLFSSL_BASE_DECODE */
    return EXPECT_RESULT();
}
int test_wolfSSL_EVP_DecodeUpdate(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_BASE64_DECODE)
    int outl;
    unsigned char decOutBuff[300];

    EVP_ENCODE_CTX* ctx = NULL;

    static const unsigned char enc1[]   =
            {"VGhpcyBpcyBhIGJhc2U2NCBkZWNvZGluZyB0ZXN0Lg==\n"};
/*    const unsigned char plain1[] =
    {"This is a base64 decoding test."} */

    ExpectNotNull(ctx = EVP_ENCODE_CTX_new());

    EVP_DecodeInit(ctx);

    /* illegal parameter tests */

    /* pass NULL as ctx */
    ExpectIntEQ(
        EVP_DecodeUpdate(
            NULL,            /* pass NULL as ctx */
            decOutBuff,
            &outl,
            enc1,
            sizeof(enc1)-1),
        -1                    /* expected result code -1: fail */
    );
    ExpectIntEQ( outl, 0);

    /* pass NULL as output */
    ExpectIntEQ(
        EVP_DecodeUpdate(
            ctx,
            NULL,           /* pass NULL as out buff */
            &outl,
            enc1,
            sizeof(enc1)-1),
        -1                    /* expected result code -1: fail */
    );
    ExpectIntEQ( outl, 0);

    /* pass NULL as outl */
    ExpectIntEQ(
        EVP_DecodeUpdate(
            ctx,
            decOutBuff,
            NULL,            /* pass NULL as outl */
            enc1,
            sizeof(enc1)-1),
        -1                   /* expected result code -1: fail */
    );

    /* pass NULL as input */
    ExpectIntEQ(
        EVP_DecodeUpdate(
            ctx,
            decOutBuff,
            &outl,
            NULL,            /* pass NULL as in */
            sizeof(enc1)-1),
        -1                    /* expected result code -1: fail */
    );
    ExpectIntEQ( outl, 0);

    /* pass negative length */
    ExpectIntEQ(
        EVP_DecodeUpdate(
            ctx,
            decOutBuff,
            &outl,
            enc1,
            -1),             /* negative inl */
        -1                    /* expected result code -1: fail */
    );
    ExpectIntEQ( outl, 0);

    ExpectIntEQ(EVP_DecodeBlock(NULL, NULL, 0), -1);

    /* pass zero length input */

    ExpectIntEQ(
        EVP_DecodeUpdate(
            ctx,
            decOutBuff,
            &outl,
            enc1,
            0),              /* pass zero as input len */
        1                    /* expected result code 1: success */
    );

    /* decode correct base64 string */

    {
        static const unsigned char enc2[]   =
        {"VGhpcyBpcyBhIGJhc2U2NCBkZWNvZGluZyB0ZXN0Lg==\n"};
        static const unsigned char plain2[] =
        {"This is a base64 decoding test."};

        EVP_EncodeInit(ctx);

        ExpectIntEQ(
            EVP_DecodeUpdate(
                ctx,
                decOutBuff,
                &outl,
                enc2,
                sizeof(enc2)-1),
            0                    /* expected result code 0: success */
            );

        ExpectIntEQ(outl,sizeof(plain2) -1);

        ExpectIntEQ(
            EVP_DecodeFinal(
                ctx,
                decOutBuff + outl,
                &outl),
            1                    /* expected result code 1: success */
            );
        ExpectIntEQ(outl, 0);   /* expected DecodeFinal output no data */

        ExpectIntEQ(XSTRNCMP( (const char*)plain2,(const char*)decOutBuff,
                              sizeof(plain2) -1 ),0);
        ExpectIntEQ(EVP_DecodeBlock(decOutBuff, enc2, sizeof(enc2)),
                    sizeof(plain2)-1);
        ExpectIntEQ(XSTRNCMP( (const char*)plain2,(const char*)decOutBuff,
                              sizeof(plain2) -1 ),0);
    }

    /* decode correct base64 string which does not have '\n' in its last*/

    {
        static const unsigned char enc3[]   =
        {"VGhpcyBpcyBhIGJhc2U2NCBkZWNvZGluZyB0ZXN0Lg=="}; /* 44 chars */
        static const unsigned char plain3[] =
        {"This is a base64 decoding test."}; /* 31 chars */

        EVP_EncodeInit(ctx);

        ExpectIntEQ(
            EVP_DecodeUpdate(
                ctx,
                decOutBuff,
                &outl,
                enc3,
                sizeof(enc3)-1),
            0                    /* expected result code 0: success */
            );

        ExpectIntEQ(outl,sizeof(plain3)-1);   /* 31 chars should be output */

        ExpectIntEQ(XSTRNCMP( (const char*)plain3,(const char*)decOutBuff,
                              sizeof(plain3) -1 ),0);

        ExpectIntEQ(
            EVP_DecodeFinal(
                ctx,
                decOutBuff + outl,
                &outl),
            1                    /* expected result code 1: success */
            );

        ExpectIntEQ(outl,0 );

        ExpectIntEQ(EVP_DecodeBlock(decOutBuff, enc3, sizeof(enc3)-1),
                    sizeof(plain3)-1);
        ExpectIntEQ(XSTRNCMP( (const char*)plain3,(const char*)decOutBuff,
                              sizeof(plain3) -1 ),0);
    }

    /* decode string which has a padding char ('=') in the illegal position*/

    {
        static const unsigned char enc4[]   =
            {"VGhpcyBpcyBhIGJhc2U2N=CBkZWNvZGluZyB0ZXN0Lg==\n"};

        EVP_EncodeInit(ctx);

        ExpectIntEQ(
            EVP_DecodeUpdate(
                ctx,
                decOutBuff,
                &outl,
                enc4,
                sizeof(enc4)-1),
            -1                    /* expected result code -1: error */
            );
        ExpectIntEQ(outl,0);
        ExpectIntEQ(EVP_DecodeBlock(decOutBuff, enc4, sizeof(enc4)-1), -1);
    }

    /* small data decode test */

    {
        static const unsigned char enc00[]   = {"VG"};
        static const unsigned char enc01[]   = {"g=\n"};
        static const unsigned char plain4[]  = {"Th"};

        EVP_EncodeInit(ctx);

        ExpectIntEQ(
            EVP_DecodeUpdate(
                ctx,
                decOutBuff,
                &outl,
                enc00,
                sizeof(enc00)-1),
            1                    /* expected result code 1: success */
            );
        ExpectIntEQ(outl,0);

        ExpectIntEQ(
            EVP_DecodeUpdate(
                ctx,
                decOutBuff + outl,
                &outl,
                enc01,
                sizeof(enc01)-1),
            0                    /* expected result code 0: success */
            );

        ExpectIntEQ(outl,sizeof(plain4)-1);

        /* test with illegal parameters */
        ExpectIntEQ(EVP_DecodeFinal(NULL,decOutBuff + outl,&outl), -1);
        ExpectIntEQ(EVP_DecodeFinal(ctx,NULL,&outl), -1);
        ExpectIntEQ(EVP_DecodeFinal(ctx,decOutBuff + outl, NULL), -1);
        ExpectIntEQ(EVP_DecodeFinal(NULL,NULL, NULL), -1);

        if (EXPECT_SUCCESS()) {
            EVP_DecodeFinal(
                ctx,
                decOutBuff + outl,
                &outl);
        }

        ExpectIntEQ( outl, 0);
        ExpectIntEQ(
            XSTRNCMP(
                (const char*)decOutBuff,
                (const char*)plain4,sizeof(plain4)-1 ),
            0);
    }

    /* decode input holding a NUL byte at the start of a 4 byte group, followed
     * by more data than the context buffer can hold */

    {
        unsigned char enc5[64];

        XMEMSET(enc5, 'A', sizeof(enc5));
        enc5[0] = '\0';

        EVP_DecodeInit(ctx);

        ExpectIntEQ(
            EVP_DecodeUpdate(
                ctx,
                decOutBuff,
                &outl,
                enc5,
                (int)sizeof(enc5)),
            1                    /* expected result code 1: success */
            );
        ExpectIntEQ(outl, 0);
        /* Before the fix all 64 input bytes were buffered into the 48 byte
         * ctx->data. The NUL byte ends the input, so nothing may be buffered
         * at all. */
        ExpectIntEQ(ctx->remaining, 0);
    }

    EVP_ENCODE_CTX_free(ctx);
#endif /* OPENSSL && WOLFSSL_BASE_DECODE */
    return EXPECT_RESULT();
}
/* A chunk whose last base64 group is left incomplete by trailing whitespace
 * takes the streaming rollback in Base64_Decode_impl(): the bulk decoder is
 * reached - it needs four bytes or more - walks into the group, runs out of
 * input part way through it, and hands the whole group back for the next call
 * to finish. Getting that wrong loses or duplicates decoded bytes, and a
 * single call decode cannot show it, because there is no resume point for it
 * to get wrong. Each case holds one, two or three base64 characters back,
 * alone and after a group the same call does decode, and the resumed stream
 * has to produce the plaintext with nothing missing or repeated. */
int test_wolfSSL_EVP_DecodeUpdate_partial_group(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_BASE64_DECODE)
    /* "abcdefghi" encodes to twelve characters with no padding, so a split
     * can fall anywhere in it without the padding rules coming into it. */
    static const char plain[] = "abcdefghi";
    static const struct {
        const char* chunk1;     /* ends mid group, with the whitespace */
        const char* chunk2;     /* the rest of the encoding */
        int         firstOutl;  /* bytes the first call can already produce */
        int         held;       /* base64 characters left in the context */
    } cases[] = {
        /* Held back on their own: nothing is decodable yet. */
        { "Y\n\n\n",     "WJjZGVmZ2hp", 0, 1 },
        { "YW\n\n",      "JjZGVmZ2hp",  0, 2 },
        { "YWJ\n",       "jZGVmZ2hp",   0, 3 },
        /* The same, after one whole group the call does decode. */
        { "YWJjZ\n\n\n", "GVmZ2hp",     3, 1 },
        { "YWJjZG\n\n",  "VmZ2hp",      3, 2 },
        { "YWJjZGV\n",   "mZ2hp",       3, 3 }
    };
    size_t c;

    for (c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        EVP_ENCODE_CTX* ctx = NULL;
        unsigned char   out[64];
        int             used = 0;
        int             outl = 0;

        XMEMSET(out, 0, sizeof(out));
        ExpectNotNull(ctx = EVP_ENCODE_CTX_new());
        EVP_DecodeInit(ctx);

        /* Four bytes or more, so it is the bulk decoder that runs and not the
         * block at a time path above it. */
        ExpectIntGE((int)XSTRLEN(cases[c].chunk1), 4);

        /* 0 and 1 both report success; 0 only asks the caller to finalize. */
        ExpectIntGE(EVP_DecodeUpdate(ctx, out, &outl,
            (const unsigned char*)cases[c].chunk1,
            (int)XSTRLEN(cases[c].chunk1)), 0);
        ExpectIntEQ(outl, cases[c].firstOutl);
        ExpectIntEQ(ctx->remaining, cases[c].held);
        used = outl;

        outl = 0;
        ExpectIntGE(EVP_DecodeUpdate(ctx, out + used, &outl,
            (const unsigned char*)cases[c].chunk2,
            (int)XSTRLEN(cases[c].chunk2)), 0);
        used += outl;

        /* Nothing held over: the two chunks are a whole number of groups. */
        ExpectIntEQ(ctx->remaining, 0);
        ExpectIntEQ(used, (int)XSTRLEN(plain));
        ExpectIntEQ(XMEMCMP(out, plain, XSTRLEN(plain)), 0);

        EVP_ENCODE_CTX_free(ctx);
        ctx = NULL;
    }
#endif
    return EXPECT_RESULT();
}

/* A chunk holding nothing but whitespace, arriving while characters are
 * already buffered, must leave those characters alone. The leftover-store path
 * used to clear ctx->data on entry while leaving ctx->remaining counting the
 * characters it had just zeroed, so the next call decoded a group starting
 * with NULs - which Base64_Decode() reads as the end of its input. The group
 * before the whitespace was then dropped and success still reported, so only
 * checking the decoded output catches it: ctx->remaining was right all along.
 * The buffered bytes are checked directly for that reason.
 *
 * Each whitespace chunk here carries at most one line ending. A chunk with two
 * or more of them is a separate, pre-existing defect (F-14258): the copy loop
 * below takes whatever Base64_SkipNewline() stops on, and that call only skips
 * one line ending, so the second is stored into ctx->data as though it were a
 * base64 character. Measured, with "YW" buffered: "\n\n" leaves
 * ctx->data[2] = 0x0a and the next call fails. Those inputs are left out so
 * this test fails only for the defect it is about. */
int test_wolfSSL_EVP_DecodeUpdate_whitespace_chunk(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_BASE64_DECODE)
    static const struct {
        const char* chunk1;  /* leaves 1-3 characters buffered */
        const char* ws;      /* a chunk with nothing but whitespace in it */
        const char* chunk3;  /* the rest of the encoding */
        const char* plain;   /* what the whole stream has to decode to */
        int         held;    /* characters buffered after chunk1 */
    } cases[] = {
        { "Y",   "\n",     "WJjZGVmZ2hp", "abcdefghi", 1 },
        { "YW",  "\n",     "JjZGVmZ2hp",  "abcdefghi", 2 },
        { "YWJ", "\n",     "jZGVmZ2hp",   "abcdefghi", 3 },
        { "YW",  "\r\n",   "JjZGVmZ2hp",  "abcdefghi", 2 },
        /* Four bytes, so the bulk decoder is handed the whitespace as well. */
        { "YW",  " \r\n ", "JjZGVmZ2hp",  "abcdefghi", 2 },
        { "YW",  "  ",     "JjZGVmZ2hp",  "abcdefghi", 2 },
        /* The padded case as reported. */
        { "VG",  "\n",     "g=",          "Th",        2 }
    };
    size_t c;

    for (c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        EVP_ENCODE_CTX* ctx = NULL;
        unsigned char   out[64];
        int             plainLen = (int)XSTRLEN(cases[c].plain);
        int             used = 0;
        int             outl = 0;

        XMEMSET(out, 0, sizeof(out));
        ExpectNotNull(ctx = EVP_ENCODE_CTX_new());
        EVP_DecodeInit(ctx);

        /* Buffer a partial group. */
        ExpectIntGE(EVP_DecodeUpdate(ctx, out, &outl,
            (const unsigned char*)cases[c].chunk1,
            (int)XSTRLEN(cases[c].chunk1)), 0);
        ExpectIntEQ(outl, 0);
        ExpectIntEQ(ctx->remaining, cases[c].held);
        ExpectIntEQ(XMEMCMP(ctx->data, cases[c].chunk1,
            (size_t)cases[c].held), 0);

        /* The whitespace call must not disturb what is buffered. */
        outl = 0;
        ExpectIntGE(EVP_DecodeUpdate(ctx, out, &outl,
            (const unsigned char*)cases[c].ws,
            (int)XSTRLEN(cases[c].ws)), 0);
        ExpectIntEQ(outl, 0);
        ExpectIntEQ(ctx->remaining, cases[c].held);
        ExpectIntEQ(XMEMCMP(ctx->data, cases[c].chunk1,
            (size_t)cases[c].held), 0);

        /* Finish the stream: nothing may be missing or repeated. */
        outl = 0;
        ExpectIntGE(EVP_DecodeUpdate(ctx, out + used, &outl,
            (const unsigned char*)cases[c].chunk3,
            (int)XSTRLEN(cases[c].chunk3)), 0);
        used += outl;
        outl = 0;
        ExpectIntGE(EVP_DecodeFinal(ctx, out + used, &outl), 0);
        used += outl;

        ExpectIntEQ(used, plainLen);
        ExpectIntEQ(XMEMCMP(out, cases[c].plain, (size_t)plainLen), 0);

        EVP_ENCODE_CTX_free(ctx);
        ctx = NULL;
    }
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_DecodeFinal(void)
{
    int res = TEST_SKIPPED;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_BASE64_DECODE)
    /* tests for wolfSSL_EVP_DecodeFinal are included in
     * test_wolfSSL_EVP_DecodeUpdate
     */
    res = TEST_SUCCESS;
#endif /* OPENSSL && WOLFSSL_BASE_DECODE */
    return res;
}


/*
 * EVP_EncodeUpdate() across chunk boundaries.
 *
 * The encoder works in 48-byte blocks, one output line each, and holds back a
 * partial block in the ctx for the next call. The result must not depend on how
 * the caller splits the input, so each size below is fed in every chunking and
 * compared against the same data encoded in a single call.
 */
int test_wolfSSL_EVP_EncodeUpdate_chunked(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_BASE64_ENCODE)
    static const int totals[] = { 1, 47, 48, 49, 95, 96, 97, 144, 145, 200 };
    byte   in[256];
    byte   whole[512];
    byte   piece[512];
    int    wholeLen = 0;
    size_t t;
    int    i;

    for (i = 0; i < (int)sizeof(in); i++) {
        in[i] = (byte)(i * 7 + 3);
    }

    for (t = 0; t < sizeof(totals) / sizeof(totals[0]); t++) {
        int total = totals[t];
        int chunk;

        /* Reference: the whole input in one call. */
        {
            EVP_ENCODE_CTX* ctx = NULL;
            int outl = 0;

            ExpectNotNull(ctx = EVP_ENCODE_CTX_new());
            EVP_EncodeInit(ctx);
            ExpectIntEQ(EVP_EncodeUpdate(ctx, whole, &outl, in, total), 1);
            wholeLen = outl;
            outl = 0;
            EVP_EncodeFinal(ctx, whole + wholeLen, &outl);
            wholeLen += outl;
            EVP_ENCODE_CTX_free(ctx);
            ExpectIntGT(wholeLen, 0);
        }

        /* Every chunk size has to reproduce it exactly. */
        for (chunk = 1; chunk <= total; chunk++) {
            EVP_ENCODE_CTX* ctx = NULL;
            int used = 0;
            int off  = 0;

            XMEMSET(piece, 0xEE, sizeof(piece));
            ExpectNotNull(ctx = EVP_ENCODE_CTX_new());
            EVP_EncodeInit(ctx);

            while (off < total) {
                int n = chunk;
                int outl = 0;

                if (n > total - off) {
                    n = total - off;
                }
                ExpectIntEQ(EVP_EncodeUpdate(ctx, piece + used, &outl,
                    in + off, n), 1);
                used += outl;
                off  += n;
            }
            {
                int outl = 0;
                EVP_EncodeFinal(ctx, piece + used, &outl);
                used += outl;
            }
            EVP_ENCODE_CTX_free(ctx);

            ExpectIntEQ(used, wholeLen);
            ExpectIntEQ(XMEMCMP(piece, whole, (size_t)wholeLen), 0);
        }
    }
#endif
    return EXPECT_RESULT();
}
