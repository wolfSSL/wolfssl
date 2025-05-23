/* test_tls.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <tests/utils.h>
#include <tests/api/test_tls.h>


int test_tls12_unexpected_ccs(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(WOLFSSL_NO_TLS12)
    const byte ccs[] = {
        0x14, /* ccs type */
        0x03, 0x03, /* version */
        0x00, 0x01, /* length */
        0x01, /* ccs value */
    };
    const byte badccs[] = {
        0x14, /* ccs type */
        0x03, 0x03, /* version */
        0x00, 0x01, /* length */
        0x99, /* wrong ccs value */
    };
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    /* ccs in the wrong place */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    /* inject SH */
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0,
            (const char*)ccs, sizeof(ccs)), 0);
    ExpectIntEQ(test_memio_setup(&test_ctx, NULL, &ctx_s, NULL, &ssl_s,
                    NULL, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(wolfSSL_accept(ssl_s), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
            OUT_OF_ORDER_E);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
    ctx_s = NULL;
    ssl_s = NULL;

    /* malformed ccs */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0,
            (const char*)badccs, sizeof(badccs)), 0);
    ExpectIntEQ(test_memio_setup(&test_ctx, NULL, &ctx_s, NULL, &ssl_s,
                    NULL, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(wolfSSL_accept(ssl_s), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
            LENGTH_ERROR);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

int test_tls13_unexpected_ccs(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_TLS13)
    const byte ccs[] = {
        0x14, /* ccs type */
        0x03, 0x03, /* version */
        0x00, 0x01, /* length */
        0x01, /* ccs value */
    };
    const byte badccs[] = {
        0x14, /* ccs type */
        0x03, 0x03, /* version */
        0x00, 0x01, /* length */
        0x99, /* wrong ccs value */
    };
    const byte unexpectedAlert[] = {
        0x15, /* alert type */
        0x03, 0x03, /* version */
        0x00, 0x02, /* length */
        0x02, /* level: fatal */
        0x0a /* protocol version */
    };
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    /* ccs can't appear before a CH */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0,
            (const char*)ccs, sizeof(ccs)), 0);
    ExpectIntEQ(test_memio_setup(&test_ctx, NULL, &ctx_s, NULL, &ssl_s,
                    NULL, wolfTLSv1_3_server_method), 0);
    ExpectIntEQ(wolfSSL_accept(ssl_s), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
            UNKNOWN_RECORD_TYPE);
    ExpectIntEQ(test_ctx.c_len, sizeof(unexpectedAlert));
    ExpectBufEQ(test_ctx.c_buff, unexpectedAlert, sizeof(unexpectedAlert));
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
    ctx_s = NULL;
    ssl_s = NULL;

    /* malformed ccs */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0,
            (const char*)badccs, sizeof(badccs)), 0);
    ExpectIntEQ(test_memio_setup(&test_ctx, NULL, &ctx_s, NULL, &ssl_s,
                    NULL, wolfTLSv1_3_server_method), 0);
    ExpectIntEQ(wolfSSL_accept(ssl_s), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
            UNKNOWN_RECORD_TYPE);
    ExpectIntEQ(test_ctx.c_len, sizeof(unexpectedAlert));
    ExpectBufEQ(test_ctx.c_buff, unexpectedAlert, sizeof(unexpectedAlert));
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}
