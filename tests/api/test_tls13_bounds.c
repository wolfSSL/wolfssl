/* test_tls13_bounds.c
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

/* MC/DC vectors for src/tls13.c's protocol-version and length/boundary
 * decisions (ISO 26262 Part 7, Track B).
 *
 * Every test here drives a real handshake through the tests/utils.c memio
 * transport and mutates one field of one flight, so no WOLFSSL_LOCAL symbol is
 * referenced and the file links in a shared build.  Each vector is written to
 * complete an independence PAIR with the ordinary handshakes the tls13 group
 * already runs: for a decision "A && B" the ordinary handshake supplies the
 * (A=1, B=0, D=0) row, so the vector here has to supply either (A=1, B=1, D=1)
 * or (A=0, D=0) -- a rejection on its own proves nothing.
 */

#include <tests/unit.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>
#include <tests/api/api.h>
#include <tests/utils.h>
#include <tests/api/test_tls13_bounds.h>

#if defined(WOLFSSL_TLS13) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    !defined(WOLFSSL_NO_TLS12)

#define TLS13B_CH_BUF_SZ    4096
#define TLS13B_REC_HDR_SZ   5
#define TLS13B_HS_HDR_SZ    4
/* record header (5) + handshake header (4) = offset of legacy_version */
#define TLS13B_LEGACY_OFF   (TLS13B_REC_HDR_SZ + TLS13B_HS_HDR_SZ)

/* Copy the first complete TLS record out of a memio direction buffer.
 *
 * dir 0 is the server's inbox (client -> server), dir 1 the client's inbox.
 * A single memio "message" can hold several concatenated records (the server
 * writes ServerHello + CCS + the first encrypted flight in one go), so the
 * record is sliced out using its own 2-byte length field rather than the
 * message size.
 *
 * Returns 0 on success. */
static int test_tls13b_take_record(struct test_memio_ctx* ctx, int dir,
    byte* out, int out_cap, int* out_sz)
{
    const char* msg = NULL;
    int msg_sz = 0;
    int rec_sz;

    if (test_memio_get_message(ctx, dir, &msg, &msg_sz, 0) != 0)
        return -1;
    if (msg_sz < TLS13B_REC_HDR_SZ)
        return -1;
    rec_sz = TLS13B_REC_HDR_SZ +
        (((int)(byte)msg[3] << 8) | (int)(byte)msg[4]);
    if (rec_sz > msg_sz || rec_sz > out_cap)
        return -1;

    XMEMCPY(out, msg, (size_t)rec_sz);
    *out_sz = rec_sz;
    return 0;
}

/* Overwrite the legacy_version of the handshake message carried by a
 * plaintext handshake record. hs_type guards against patching the wrong
 * message. Returns 0 on success. */
static int test_tls13b_set_legacy_version(byte* rec, int rec_sz, byte hs_type,
    byte major, byte minor)
{
    if (rec_sz < TLS13B_LEGACY_OFF + 2)
        return -1;
    if (rec[0] != handshake)
        return -1;
    if (rec[TLS13B_REC_HDR_SZ] != hs_type)
        return -1;

    rec[TLS13B_LEGACY_OFF]     = major;
    rec[TLS13B_LEGACY_OFF + 1] = minor;
    return 0;
}

/* Drive a TLS 1.3 client far enough to emit its ClientHello, rewrite the
 * ClientHello's legacy_version to major.minor, replay it to a TLS 1.3-only
 * server and require the given error.
 *
 * All three callers land in DoTls13ClientHello()'s legacy-version block
 * (tls13.c ~7620-7665). */
static int test_tls13b_ch_legacy_version(byte major, byte minor, int expErr)
{
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    byte ch[TLS13B_CH_BUF_SZ];
    int ch_sz = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    /* Client emits the ClientHello and then blocks on the reply. */
    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);

    ExpectIntEQ(test_tls13b_take_record(&test_ctx, 0, ch, (int)sizeof(ch),
        &ch_sz), 0);
    ExpectIntEQ(test_tls13b_set_legacy_version(ch, ch_sz, client_hello,
        major, minor), 0);

    test_memio_clear_buffer(&test_ctx, 0);
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (const char*)ch,
            ch_sz), 0);
    }

    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        expErr);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
    return EXPECT_RESULT();
}

/* Run a TLS 1.3 handshake up to the server's first flight, rewrite the
 * ServerHello's legacy_version to major.minor, feed the client that single
 * record and require the given error.
 *
 * Lands in DoTls13ServerHello()'s downgrade block (tls13.c ~5432-5470). */
static int test_tls13b_sh_legacy_version(byte major, byte minor, int expErr)
{
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    byte sh[TLS13B_CH_BUF_SZ];
    int sh_sz = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);
    wolfSSL_set_verify(ssl_c, WOLFSSL_VERIFY_NONE, NULL);

    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);
    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);

    ExpectIntEQ(test_tls13b_take_record(&test_ctx, 1, sh, (int)sizeof(sh),
        &sh_sz), 0);
    ExpectIntEQ(test_tls13b_set_legacy_version(sh, sh_sz, server_hello,
        major, minor), 0);

    /* Drop the rest of the server flight: only the tampered ServerHello is
     * replayed, so the client cannot get past the version check. */
    test_memio_clear_buffer(&test_ctx, 1);
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(test_memio_inject_message(&test_ctx, 1, (const char*)sh,
            sh_sz), 0);
    }

    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        expErr);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
    return EXPECT_RESULT();
}
#endif /* guards */

/* tls13.c:7645 - "args->pv.major == SSLv3_MAJOR && args->pv.minor >=
 * TLSv1_3_MINOR". A legacy_version of 0x0304 makes BOTH operands true, which
 * is the decision-true row RFC 8446 4.2.1 lets a server abort on. It is the
 * accepting partner for cond 0 (paired with the 0x0403 vector below) and for
 * cond 1 (paired with every ordinary ClientHello, whose 0x0303 makes cond 1
 * false). */
int test_tls13_ch_legacy_version_is_tls13(void)
{
#if defined(WOLFSSL_TLS13) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    !defined(WOLFSSL_NO_TLS12) && \
    !defined(WOLFSSL_ALLOW_BAD_TLS_LEGACY_VERSION)
    return test_tls13b_ch_legacy_version(SSLv3_MAJOR, TLSv1_3_MINOR,
        WC_NO_ERR_TRACE(VERSION_ERROR));
#else
    return TEST_SKIPPED;
#endif
}

/* tls13.c:7645 cond 0 false row, and tls13.c:7652 cond 0 true row.
 * A legacy_version major of 4 is > SSLv3_MAJOR, so :7645 short-circuits false
 * on its first operand and :7652's first operand is true on its own. The
 * server has downgrade disabled, so the forced downgrade is refused with
 * VERSION_ERROR. */
int test_tls13_ch_legacy_version_major_above_ssl3(void)
{
#if defined(WOLFSSL_TLS13) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    !defined(WOLFSSL_NO_TLS12)
    return test_tls13b_ch_legacy_version(SSLv3_MAJOR + 1, TLSv1_2_MINOR,
        WC_NO_ERR_TRACE(VERSION_ERROR));
#else
    return TEST_SKIPPED;
#endif
}

/* tls13.c:7660 cond 1 true row - "args->pv.minor < TLSv1_2_MINOR" in the
 * else-if that catches a pre-TLS1.2 legacy_version. 0x0301 (TLS 1.0) falls
 * through :7645 and :7652 and makes this operand true; the ordinary
 * ClientHello's 0x0303 is the false row. */
int test_tls13_ch_legacy_version_below_tls12(void)
{
#if defined(WOLFSSL_TLS13) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    !defined(WOLFSSL_NO_TLS12)
    return test_tls13b_ch_legacy_version(SSLv3_MAJOR, TLSv1_MINOR,
        WC_NO_ERR_TRACE(VERSION_ERROR));
#else
    return TEST_SKIPPED;
#endif
}

/* tls13.c:5436 - "args->pv.major == ssl->version.major && args->pv.minor <
 * TLSv1_2_MINOR" in DoTls13ServerHello(). A ServerHello legacy_version of
 * 0x0302 makes both operands true (the decision-true row that cond 0 and
 * cond 1 both need); the client has downgrade disabled so it then fails
 * :5466 cond 1 ("args->pv.minor != tls12minor"), whose false row every
 * ordinary handshake supplies. */
int test_tls13_sh_legacy_version_below_tls12(void)
{
#if defined(WOLFSSL_TLS13) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    !defined(WOLFSSL_NO_TLS12)
    return test_tls13b_sh_legacy_version(SSLv3_MAJOR, TLSv1_1_MINOR,
        WC_NO_ERR_TRACE(VERSION_ERROR));
#else
    return TEST_SKIPPED;
#endif
}

/* tls13.c:5436 cond 0 false row and :5466 cond 0 true row. A ServerHello
 * legacy_version major of 4 differs from the client's, so :5436
 * short-circuits false without evaluating its second operand and :5466's
 * first operand is true on its own. */
int test_tls13_sh_legacy_version_major_mismatch(void)
{
#if defined(WOLFSSL_TLS13) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    !defined(WOLFSSL_NO_TLS12)
    return test_tls13b_sh_legacy_version(SSLv3_MAJOR + 1, TLSv1_2_MINOR,
        WC_NO_ERR_TRACE(VERSION_ERROR));
#else
    return TEST_SKIPPED;
#endif
}
