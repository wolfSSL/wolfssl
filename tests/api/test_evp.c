/* test_evp.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

    EVP_ENCODE_CTX_free(ctx);
#endif /* OPENSSL && WOLFSSL_BASE_DECODE */
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

