/* test_compress.c
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

/* After <tests/unit.h>: that header establishes wolfSSL's feature-test
 * macros, and a libc header pulled in ahead of it fixes glibc's exposure
 * before they are seen -- under -std=c89 that leaves POSIX types the rest of
 * the suite needs undeclared. Every other file in tests/api/ starts with
 * <tests/unit.h> for the same reason. INT_MAX is used below. */
#include <limits.h>

#ifdef HAVE_LIBZ
    #include <wolfssl/wolfcrypt/compress.h>
#endif
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/internal.h>
#include <tests/api/api.h>
#include <tests/api/test_compress.h>

/* TLS level zlib compression (wolfSSL_set_compression()) needs the record
 * layer, so the memio harness on top of HAVE_LIBZ. */
#if defined(HAVE_LIBZ) && defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES)
    #define TEST_TLS_COMPRESSION_ANY
#endif
/* Compression itself only exists up to TLS 1.2; 1.3 removed it.  The 1.3
 * test below deliberately stays outside this guard: a 1.3 only build is where
 * the "compression stays off" behaviour matters most. */
#if defined(TEST_TLS_COMPRESSION_ANY) && !defined(WOLFSSL_NO_TLS12)
    #define TEST_TLS_COMPRESSION
#endif

/*
 * MC/DC decision coverage for the zlib wrapper (wolfcrypt/src/compress.c).
 * compress_test() in testwolfcrypt exercises the round trips; this drives the
 * argument guards, each operand flipped independently:
 *   - "out == NULL || in == NULL" in wc_Compress_ex, wc_DeCompress_ex and
 *     wc_DeCompressDynamic;
 *   - "inSz == 0 || inSz > INT_MAX/2" in wc_DeCompressDynamic, the cap that
 *     keeps the buffer doubling from overflowing.
 */
int test_wc_CompressDecisionCoverage(void)
{
    EXPECT_DECLS;
#ifdef HAVE_LIBZ
    static const byte sample[] =
        "wolfSSL compress decision coverage sample text, repeated enough to "
        "actually compress: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    byte  packed[512];
    byte  plain[512];
    byte* dynOut = NULL;
    int   packedSz;

    XMEMSET(packed, 0, sizeof(packed));
    XMEMSET(plain, 0, sizeof(plain));

    /* wc_Compress_ex "out == NULL || in == NULL" */
    ExpectIntEQ(wc_Compress_ex(NULL, sizeof(packed), sample, sizeof(sample),
        0, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Compress_ex(packed, sizeof(packed), NULL, sizeof(sample),
        0, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* both operands false: a real compression, whose output feeds the
     * decompression guards below. */
    ExpectIntGT(packedSz = wc_Compress(packed, sizeof(packed), sample,
        sizeof(sample), 0), 0);

    /* wc_DeCompress_ex "out == NULL || in == NULL" */
    ExpectIntEQ(wc_DeCompress_ex(NULL, sizeof(plain), packed, sizeof(packed),
        0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DeCompress_ex(plain, sizeof(plain), NULL, sizeof(packed),
        0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    if (EXPECT_SUCCESS() && packedSz > 0) {
        ExpectIntEQ(wc_DeCompress(plain, sizeof(plain), packed,
            (word32)packedSz), (int)sizeof(sample));
        ExpectIntEQ(XMEMCMP(plain, sample, sizeof(sample)), 0);
    }

    /* wc_DeCompressDynamic "out == NULL || in == NULL" */
    ExpectIntEQ(wc_DeCompressDynamic(NULL, 1, DYNAMIC_TYPE_TMP_BUFFER, packed,
        (word32)packedSz, 0, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DeCompressDynamic(&dynOut, 1, DYNAMIC_TYPE_TMP_BUFFER, NULL,
        (word32)packedSz, 0, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* wc_DeCompressDynamic "inSz == 0 || inSz > INT_MAX/2", one operand true
     * per call, then both false on the working round trip. */
    ExpectIntEQ(wc_DeCompressDynamic(&dynOut, 1, DYNAMIC_TYPE_TMP_BUFFER,
        packed, 0, 0, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DeCompressDynamic(&dynOut, 1, DYNAMIC_TYPE_TMP_BUFFER,
        packed, (word32)(INT_MAX / 2) + 1, 0, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    if (EXPECT_SUCCESS() && packedSz > 0) {
        ExpectIntEQ(wc_DeCompressDynamic(&dynOut, 4, DYNAMIC_TYPE_TMP_BUFFER,
            packed, (word32)packedSz, 0, NULL),
            (int)sizeof(sample));
        ExpectNotNull(dynOut);
        if (dynOut != NULL) {
            ExpectIntEQ(XMEMCMP(dynOut, sample, sizeof(sample)), 0);
            XFREE(dynOut, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            dynOut = NULL;
        }
    }
#endif /* HAVE_LIBZ */
    return EXPECT_RESULT();
}

#ifdef TEST_TLS_COMPRESSION_ANY
static int test_tls_compression_ssl_ready(WOLFSSL* ssl)
{
    EXPECT_DECLS;
    ExpectIntEQ(wolfSSL_set_compression(ssl), WOLFSSL_SUCCESS);
    return EXPECT_RESULT();
}
#endif /* TEST_TLS_COMPRESSION_ANY */

#ifdef TEST_TLS_COMPRESSION

/* Payload big enough to fill a record.  Made of one repeated byte so the
 * compressed record on the wire is a tiny fraction of the plaintext - that
 * ratio is what the decompression side has to survive. */
#define TEST_TLS_COMP_PAYLOAD_SZ MAX_RECORD_SIZE

static void test_tls_compression_setup(test_ssl_memio_ctx* testCtx)
{
    XMEMSET(testCtx, 0, sizeof(*testCtx));
    testCtx->c_cb.method = wolfTLSv1_2_client_method;
    testCtx->s_cb.method = wolfTLSv1_2_server_method;
    testCtx->c_cb.ssl_ready = test_tls_compression_ssl_ready;
    testCtx->s_cb.ssl_ready = test_tls_compression_ssl_ready;
}

/* Deterministic filler that deflate cannot shrink, so myCompress() returns
 * more bytes than it was given and the record has to be sized for it. */
static void test_tls_compression_fill_random(byte* buf, word32 sz)
{
    word32 state = 0x12345678;
    word32 i;

    for (i = 0; i < sz; i++) {
        state = (state * 1103515245U) + 12345U;
        buf[i] = (byte)(state >> 16);
    }
}
#endif /* TEST_TLS_COMPRESSION */

/*
 * A full sized, highly compressible record round trip with TLS compression
 * negotiated.  The record on the wire is a tiny fraction of the 16384 byte
 * plaintext, so the receiver expands the fragment far past the size of the
 * record it arrived in.  That expansion used to be written back over the
 * input buffer, which GetInputData() only grows to hold the wire record, so a
 * single record overflowed the input buffer allocation.
 *
 * Also covers the ClientHello compression_methods list: RFC 5246 7.4.1.2
 * requires CompressionMethod.null to always be offered, and a wolfSSL server
 * rejects a list without it, so a client that offered zlib on its own could
 * not complete a handshake at all.
 */
int test_wolfSSL_tls_compression(void)
{
    EXPECT_DECLS;
#ifdef TEST_TLS_COMPRESSION
    test_ssl_memio_ctx testCtx;
    byte* payload = NULL;
    byte* readBuf = NULL;
    int   wireSz = 0;

    test_tls_compression_setup(&testCtx);

    ExpectNotNull(payload = (byte*)XMALLOC(TEST_TLS_COMP_PAYLOAD_SZ, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectNotNull(readBuf = (byte*)XMALLOC(TEST_TLS_COMP_PAYLOAD_SZ, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    if (payload != NULL)
        XMEMSET(payload, 'A', TEST_TLS_COMP_PAYLOAD_SZ);
    if (readBuf != NULL)
        XMEMSET(readBuf, 0, TEST_TLS_COMP_PAYLOAD_SZ);

    ExpectIntEQ(test_ssl_memio_setup(&testCtx), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_memio_do_handshake(&testCtx, 10, NULL), TEST_SUCCESS);

    /* zlib has to be what was actually negotiated, otherwise the rest of this
     * test would pass on a plain uncompressed connection. */
    ExpectIntEQ(testCtx.c_ssl->options.usingCompression, 1);
    ExpectIntEQ(testCtx.s_ssl->options.usingCompression, 1);

    /* client -> server, the direction the overflow was reachable in */
    if (EXPECT_SUCCESS())
        testCtx.s_len = 0;
    ExpectIntEQ(wolfSSL_write(testCtx.c_ssl, payload, TEST_TLS_COMP_PAYLOAD_SZ),
        TEST_TLS_COMP_PAYLOAD_SZ);
    if (EXPECT_SUCCESS())
        wireSz = testCtx.s_len;
    /* the record really did compress: the server's input buffer is grown to
     * the wire size, so this is the size the plaintext gets expanded past */
    ExpectIntLT(wireSz, TEST_TLS_COMP_PAYLOAD_SZ / 4);
    ExpectIntEQ(wolfSSL_read(testCtx.s_ssl, readBuf, TEST_TLS_COMP_PAYLOAD_SZ),
        TEST_TLS_COMP_PAYLOAD_SZ);
    ExpectIntEQ(XMEMCMP(readBuf, payload, TEST_TLS_COMP_PAYLOAD_SZ), 0);

    /* second record on the same connection: zlib streams are stateful, so a
     * follow up record exercises the continued stream, not just the first
     * block, and confirms the send side plaintext accounting stayed right. */
    if (readBuf != NULL)
        XMEMSET(readBuf, 0, TEST_TLS_COMP_PAYLOAD_SZ);
    ExpectIntEQ(wolfSSL_write(testCtx.c_ssl, payload, TEST_TLS_COMP_PAYLOAD_SZ),
        TEST_TLS_COMP_PAYLOAD_SZ);
    ExpectIntEQ(wolfSSL_read(testCtx.s_ssl, readBuf, TEST_TLS_COMP_PAYLOAD_SZ),
        TEST_TLS_COMP_PAYLOAD_SZ);
    ExpectIntEQ(XMEMCMP(readBuf, payload, TEST_TLS_COMP_PAYLOAD_SZ), 0);

    /* server -> client, so both compression streams get exercised */
    if (readBuf != NULL)
        XMEMSET(readBuf, 0, TEST_TLS_COMP_PAYLOAD_SZ);
    ExpectIntEQ(wolfSSL_write(testCtx.s_ssl, payload, TEST_TLS_COMP_PAYLOAD_SZ),
        TEST_TLS_COMP_PAYLOAD_SZ);
    ExpectIntEQ(wolfSSL_read(testCtx.c_ssl, readBuf, TEST_TLS_COMP_PAYLOAD_SZ),
        TEST_TLS_COMP_PAYLOAD_SZ);
    ExpectIntEQ(XMEMCMP(readBuf, payload, TEST_TLS_COMP_PAYLOAD_SZ), 0);

    /* Incompressible payload: deflate returns more bytes than it was given,
     * so the record has to have been sized with room for the expansion. */
    if (payload != NULL)
        test_tls_compression_fill_random(payload, TEST_TLS_COMP_PAYLOAD_SZ);
    if (readBuf != NULL)
        XMEMSET(readBuf, 0, TEST_TLS_COMP_PAYLOAD_SZ);
    if (EXPECT_SUCCESS())
        testCtx.s_len = 0;
    ExpectIntEQ(wolfSSL_write(testCtx.c_ssl, payload, TEST_TLS_COMP_PAYLOAD_SZ),
        TEST_TLS_COMP_PAYLOAD_SZ);
    /* it really did fail to compress, otherwise this proves nothing */
    ExpectIntGT(testCtx.s_len, TEST_TLS_COMP_PAYLOAD_SZ);
    ExpectIntEQ(wolfSSL_read(testCtx.s_ssl, readBuf, TEST_TLS_COMP_PAYLOAD_SZ),
        TEST_TLS_COMP_PAYLOAD_SZ);
    ExpectIntEQ(XMEMCMP(readBuf, payload, TEST_TLS_COMP_PAYLOAD_SZ), 0);

    XFREE(readBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(payload, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    test_ssl_memio_cleanup(&testCtx);
#endif /* TEST_TLS_COMPRESSION */
    return EXPECT_RESULT();
}

/*
 * A write larger than one record makes SendData() loop.  The loop cursor and
 * the WANT_WRITE resume point are both measured in plaintext bytes, but
 * SendData() overwrites its length variable with the compressed length, so
 * advancing by it resent most of the payload instead of moving past it.
 */
int test_wolfSSL_tls_compression_multi_record(void)
{
    EXPECT_DECLS;
#ifdef TEST_TLS_COMPRESSION
    test_ssl_memio_ctx testCtx;
    byte*  payload = NULL;
    byte*  readBuf = NULL;
    word32 payloadSz = 3 * TEST_TLS_COMP_PAYLOAD_SZ;
    word32 got = 0;
    int    ret;

    test_tls_compression_setup(&testCtx);

    ExpectNotNull(payload = (byte*)XMALLOC(payloadSz, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectNotNull(readBuf = (byte*)XMALLOC(payloadSz, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    if (payload != NULL) {
        /* distinct bytes throughout, so a resent or skipped span shows up as
         * a content mismatch rather than matching by accident */
        test_tls_compression_fill_random(payload, payloadSz);
    }
    if (readBuf != NULL)
        XMEMSET(readBuf, 0, payloadSz);

    ExpectIntEQ(test_ssl_memio_setup(&testCtx), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_memio_do_handshake(&testCtx, 10, NULL), TEST_SUCCESS);
    ExpectIntEQ(testCtx.c_ssl->options.usingCompression, 1);

    ExpectIntEQ(wolfSSL_write(testCtx.c_ssl, payload, (int)payloadSz),
        (int)payloadSz);

    /* one record per read, so drain until the whole payload is back */
    while (EXPECT_SUCCESS() && got < payloadSz) {
        ret = wolfSSL_read(testCtx.s_ssl, readBuf + got,
                           (int)(payloadSz - got));
        ExpectIntGT(ret, 0);
        if (ret <= 0)
            break;
        got += (word32)ret;
    }
    ExpectIntEQ(got, payloadSz);
    ExpectIntEQ(XMEMCMP(readBuf, payload, payloadSz), 0);

    XFREE(readBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(payload, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    test_ssl_memio_cleanup(&testCtx);
#endif /* TEST_TLS_COMPRESSION */
    return EXPECT_RESULT();
}

/*
 * Pin the compression_methods list a ClientHello actually puts on the wire.
 * A wolfSSL to wolfSSL handshake cannot catch a wrong length byte or entry
 * order, because both ends share the bug; a strict third party peer would
 * reject it with illegal_parameter.
 */
int test_wolfSSL_tls_compression_client_hello(void)
{
    EXPECT_DECLS;
#ifdef TEST_TLS_COMPRESSION
    test_ssl_memio_ctx testCtx;
    word32 idx = 0;
    word32 sessionSz;
    word32 suitesSz;

    test_tls_compression_setup(&testCtx);
    ExpectIntEQ(test_ssl_memio_setup(&testCtx), TEST_SUCCESS);

    /* one connect call writes the ClientHello and stops on WANT_READ, so the
     * server has not consumed it from the buffer yet */
    ExpectIntNE(wolfSSL_connect(testCtx.c_ssl), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(testCtx.c_ssl, -1),
        WOLFSSL_ERROR_WANT_READ);
    ExpectIntGT(testCtx.s_len, 0);

    if (EXPECT_SUCCESS()) {
        /* record header, handshake header, version, random */
        idx = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ + VERSION_SZ + RAN_LEN;
        ExpectIntGT(testCtx.s_len, (int)idx);
    }
    if (EXPECT_SUCCESS()) {
        sessionSz = testCtx.s_buff[idx];
        idx += ENUM_LEN + sessionSz;
        ExpectIntGT(testCtx.s_len, (int)(idx + OPAQUE16_LEN));
    }
    if (EXPECT_SUCCESS()) {
        suitesSz = ((word32)testCtx.s_buff[idx] << 8) |
                    (word32)testCtx.s_buff[idx + 1];
        idx += OPAQUE16_LEN + suitesSz;
        ExpectIntGT(testCtx.s_len, (int)(idx + 2));
    }
    /* two methods, zlib first, then the null RFC 5246 7.4.1.2 requires */
    ExpectIntEQ(testCtx.s_buff[idx], COMP_LEN + ENUM_LEN);
    ExpectIntEQ(testCtx.s_buff[idx + 1], ZLIB_COMPRESSION);
    ExpectIntEQ(testCtx.s_buff[idx + 2], NO_COMPRESSION);

    test_ssl_memio_cleanup(&testCtx);
#endif /* TEST_TLS_COMPRESSION */
    return EXPECT_RESULT();
}

/*
 * TLS 1.3 removed record layer compression (RFC 8446 5.2) and a 1.3 capable
 * ClientHello must carry legacy_compression_methods of exactly null, so a
 * connection that asks for compression and then lands on 1.3 has to complete
 * with compression off rather than compress records the peer will not
 * decompress.
 */
int test_wolfSSL_tls13_compression_off(void)
{
    EXPECT_DECLS;
#if defined(TEST_TLS_COMPRESSION_ANY) && defined(WOLFSSL_TLS13)
    test_ssl_memio_ctx testCtx;
    char msg[] = "compression is not a TLS 1.3 thing";
    char readBuf[64];

    XMEMSET(&testCtx, 0, sizeof(testCtx));
    XMEMSET(readBuf, 0, sizeof(readBuf));
    testCtx.c_cb.method = wolfTLSv1_3_client_method;
    testCtx.s_cb.method = wolfTLSv1_3_server_method;
    testCtx.c_cb.ssl_ready = test_tls_compression_ssl_ready;
    testCtx.s_cb.ssl_ready = test_tls_compression_ssl_ready;

    ExpectIntEQ(test_ssl_memio_setup(&testCtx), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_memio_do_handshake(&testCtx, 10, NULL), TEST_SUCCESS);

    ExpectIntEQ(testCtx.c_ssl->options.usingCompression, 0);
    ExpectIntEQ(testCtx.s_ssl->options.usingCompression, 0);

    ExpectIntEQ(wolfSSL_write(testCtx.c_ssl, msg, (int)XSTRLEN(msg)),
        (int)XSTRLEN(msg));
    ExpectIntEQ(wolfSSL_read(testCtx.s_ssl, readBuf, (int)sizeof(readBuf)),
        (int)XSTRLEN(msg));
    ExpectIntEQ(XMEMCMP(readBuf, msg, XSTRLEN(msg)), 0);

    test_ssl_memio_cleanup(&testCtx);
#endif /* TEST_TLS_COMPRESSION_ANY && WOLFSSL_TLS13 */
    return EXPECT_RESULT();
}

/*
 * Decompressing a record must not write into the record it was handed.  A
 * legal fragment expanding to a full 2^14 byte plaintext is fed to
 * DoApplicationData() in an exact sized allocation, so an in place expansion
 * runs straight off the end of it.
 *
 * The exactly-at-the-limit size also pins the one byte of headroom the
 * decompression buffer carries: myDeCompress() reports a full output buffer
 * as an oversized record, so a buffer sized at the limit would reject this
 * legitimate record.
 *
 * The connection is freshly handshaked so the receive stream is at its start
 * and accepts the standalone zlib stream wc_Compress() produces.
 */
int test_wolfSSL_tls_decompression_no_writeback(void)
{
    EXPECT_DECLS;
#ifdef TEST_TLS_COMPRESSION
    test_ssl_memio_ctx testCtx;
    byte*  plain = NULL;
    byte*  packed = NULL;
    byte*  packedCopy = NULL;
    word32 plainSz = MAX_RECORD_SIZE;
    word32 idx = 0;
    int    packedSz = 0;

    test_tls_compression_setup(&testCtx);

    ExpectNotNull(plain = (byte*)XMALLOC(plainSz, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectNotNull(packedCopy = (byte*)XMALLOC(plainSz, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    if (plain != NULL)
        XMEMSET(plain, 'A', plainSz);
    ExpectIntGT(packedSz = wc_Compress(packedCopy, plainSz, plain, plainSz, 0),
        0);

    if (EXPECT_SUCCESS()) {
        ExpectNotNull(packed = (byte*)XMALLOC((word32)packedSz, NULL,
            DYNAMIC_TYPE_TMP_BUFFER));
    }
    if (packed != NULL)
        XMEMCPY(packed, packedCopy, (word32)packedSz);

    ExpectIntEQ(test_ssl_memio_setup(&testCtx), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_memio_do_handshake(&testCtx, 10, NULL), TEST_SUCCESS);
    ExpectIntEQ(testCtx.s_ssl->options.usingCompression, 1);

    if (EXPECT_SUCCESS())
        testCtx.s_ssl->curSize = (word16)packedSz;
    ExpectIntEQ(DoApplicationData(testCtx.s_ssl, packed, &idx, NO_SNIFF), 0);
    /* the whole plaintext came back, and the record was left untouched */
    ExpectIntEQ(testCtx.s_ssl->buffers.clearOutputBuffer.length, plainSz);
    ExpectIntEQ(XMEMCMP(testCtx.s_ssl->buffers.clearOutputBuffer.buffer, plain,
        plainSz), 0);
    ExpectIntEQ(XMEMCMP(packed, packedCopy, (word32)packedSz), 0);
    ExpectIntEQ(idx, (word32)packedSz);

    XFREE(packed, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(packedCopy, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(plain, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    test_ssl_memio_cleanup(&testCtx);
#endif /* TEST_TLS_COMPRESSION */
    return EXPECT_RESULT();
}

/*
 * A compressed fragment that expands past the RFC 5246 6.2.2 limit of 2^14
 * bytes must be rejected, not silently truncated, and must not be written
 * back over the record it arrived in.
 *
 * The record is handed straight to DoApplicationData() because a conforming
 * wolfSSL peer never emits one: the fragment is built to decompress to more
 * than a legal TLSPlaintext.  The connection is freshly handshaked so the
 * receive stream is at its start and accepts the standalone zlib stream that
 * wc_Compress() produces.
 */
int test_wolfSSL_tls_decompression_limit(void)
{
    EXPECT_DECLS;
#ifdef TEST_TLS_COMPRESSION
    test_ssl_memio_ctx testCtx;
    WOLFSSL_ALERT_HISTORY alertHistory;
    byte*  oversize = NULL;
    byte*  packed = NULL;
    byte*  packedCopy = NULL;
    byte   readBuf[16];
    word32 oversizeSz = MAX_RECORD_SIZE + 1;
    word32 idx = 0;
    int    packedSz = 0;

    test_tls_compression_setup(&testCtx);

    /* Compress one byte more than a record may decompress to.  wc_Compress()
     * needs an output buffer larger than its input, so size it that way and
     * only the returned length is handed to the record layer. */
    ExpectNotNull(oversize = (byte*)XMALLOC(oversizeSz, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectNotNull(packedCopy = (byte*)XMALLOC(oversizeSz, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    if (oversize != NULL)
        XMEMSET(oversize, 'A', oversizeSz);
    ExpectIntGT(packedSz = wc_Compress(packedCopy, oversizeSz, oversize,
        oversizeSz, 0), 0);

    /* Exact sized allocation: the compressed record is all the input buffer
     * the record layer is entitled to write to, so an expansion written back
     * over it lands outside this allocation. */
    if (EXPECT_SUCCESS()) {
        ExpectNotNull(packed = (byte*)XMALLOC((word32)packedSz, NULL,
            DYNAMIC_TYPE_TMP_BUFFER));
    }
    if (packed != NULL)
        XMEMCPY(packed, packedCopy, (word32)packedSz);

    ExpectIntEQ(test_ssl_memio_setup(&testCtx), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_memio_do_handshake(&testCtx, 10, NULL), TEST_SUCCESS);
    ExpectIntEQ(testCtx.s_ssl->options.usingCompression, 1);

    if (EXPECT_SUCCESS()) {
        testCtx.s_ssl->curSize = (word16)packedSz;
        testCtx.c_len = 0;
    }
    ExpectIntEQ(DoApplicationData(testCtx.s_ssl, packed, &idx, NO_SNIFF),
        WC_NO_ERR_TRACE(ZLIB_DECOMPRESS_ERROR));
    /* the record it was handed is left exactly as it was */
    ExpectIntEQ(XMEMCMP(packed, packedCopy, (word32)packedSz), 0);
    /* and the peer is told why, per RFC 5246 7.2.2 */
    ExpectIntGT(testCtx.c_len, 0);
    ExpectIntEQ(wolfSSL_read(testCtx.c_ssl, readBuf, (int)sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_alert_history(testCtx.c_ssl, &alertHistory),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(alertHistory.last_rx.code, decompression_failure);
    ExpectIntEQ(alertHistory.last_rx.level, alert_fatal);

    XFREE(packed, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(packedCopy, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(oversize, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    test_ssl_memio_cleanup(&testCtx);
#endif /* TEST_TLS_COMPRESSION */
    return EXPECT_RESULT();
}

/*
 * The decompression buffer only grows, so the size handed to myDeCompress()
 * has to be the fragment limit in force now rather than the allocation a
 * larger limit left behind.  A record is decompressed at the default limit to
 * size the buffer, the limit is then lowered the way
 * WOLFSSL_ALLOW_MAX_FRAGMENT_ADJUST does, and a record expanding past the new
 * limit must be rejected even though the old allocation would still hold it.
 */
int test_wolfSSL_tls_decompression_lowered_limit(void)
{
    EXPECT_DECLS;
#if defined(TEST_TLS_COMPRESSION) && defined(HAVE_MAX_FRAGMENT)
    test_ssl_memio_ctx testCtx;
    WOLFSSL_ALERT_HISTORY alertHistory;
    byte*  payload = NULL;
    byte*  readBuf = NULL;
    word32 payloadSz = 2048;
    word16 loweredFrag = 1024;

    test_tls_compression_setup(&testCtx);

    ExpectNotNull(payload = (byte*)XMALLOC(payloadSz, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectNotNull(readBuf = (byte*)XMALLOC(payloadSz, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    if (payload != NULL)
        XMEMSET(payload, 'A', payloadSz);
    if (readBuf != NULL)
        XMEMSET(readBuf, 0, payloadSz);

    ExpectIntEQ(test_ssl_memio_setup(&testCtx), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_memio_do_handshake(&testCtx, 10, NULL), TEST_SUCCESS);
    ExpectIntEQ(testCtx.s_ssl->options.usingCompression, 1);

    /* first record sizes the buffer against the default fragment limit */
    ExpectIntEQ(wolfSSL_write(testCtx.c_ssl, payload, (int)payloadSz),
        (int)payloadSz);
    ExpectIntEQ(wolfSSL_read(testCtx.s_ssl, readBuf, (int)payloadSz),
        (int)payloadSz);
    ExpectIntEQ(XMEMCMP(readBuf, payload, payloadSz), 0);
    ExpectIntGT(testCtx.s_ssl->buffers.decompBuffer.length, loweredFrag);

    /* the receiver drops its limit below what the peer keeps sending */
    if (EXPECT_SUCCESS()) {
        testCtx.s_ssl->max_fragment = loweredFrag;
        testCtx.c_len = 0;
    }

    /* same record as above, now over the limit and no longer acceptable */
    ExpectIntEQ(wolfSSL_write(testCtx.c_ssl, payload, (int)payloadSz),
        (int)payloadSz);
    ExpectIntLT(wolfSSL_read(testCtx.s_ssl, readBuf, (int)payloadSz), 0);

    /* and the peer is told why, per RFC 5246 7.2.2 */
    ExpectIntGT(testCtx.c_len, 0);
    ExpectIntEQ(wolfSSL_read(testCtx.c_ssl, readBuf, (int)payloadSz), -1);
    ExpectIntEQ(wolfSSL_get_alert_history(testCtx.c_ssl, &alertHistory),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(alertHistory.last_rx.code, decompression_failure);
    ExpectIntEQ(alertHistory.last_rx.level, alert_fatal);

    XFREE(readBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(payload, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    test_ssl_memio_cleanup(&testCtx);
#endif /* TEST_TLS_COMPRESSION && HAVE_MAX_FRAGMENT */
    return EXPECT_RESULT();
}

/*
 * wolfSSL_GetOutputSize() tells an application how many transport bytes its
 * write will produce, so it has to carry the same allowance for deflate
 * expanding an incompressible fragment that SendData() sizes the record with.
 */
int test_wolfSSL_tls_compression_output_size(void)
{
    EXPECT_DECLS;
#ifdef TEST_TLS_COMPRESSION
    test_ssl_memio_ctx testCtx;
    byte* payload = NULL;
    byte* readBuf = NULL;
    int   maxOut = 0;
    int   reported = 0;

    test_tls_compression_setup(&testCtx);

    ExpectNotNull(payload = (byte*)XMALLOC(TEST_TLS_COMP_PAYLOAD_SZ, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectNotNull(readBuf = (byte*)XMALLOC(TEST_TLS_COMP_PAYLOAD_SZ, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    if (readBuf != NULL)
        XMEMSET(readBuf, 0, TEST_TLS_COMP_PAYLOAD_SZ);

    ExpectIntEQ(test_ssl_memio_setup(&testCtx), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_memio_do_handshake(&testCtx, 10, NULL), TEST_SUCCESS);
    ExpectIntEQ(testCtx.c_ssl->options.usingCompression, 1);

    ExpectIntGT(maxOut = wolfSSL_GetMaxOutputSize(testCtx.c_ssl), 0);
    ExpectIntLE(maxOut, TEST_TLS_COMP_PAYLOAD_SZ);
    ExpectIntGT(reported = wolfSSL_GetOutputSize(testCtx.c_ssl, maxOut), 0);

    /* a full fragment deflate cannot shrink, so the record on the wire ends
     * up carrying more bytes than the plaintext it was built from */
    if (EXPECT_SUCCESS()) {
        test_tls_compression_fill_random(payload, (word32)maxOut);
        testCtx.s_len = 0;
    }
    ExpectIntEQ(wolfSSL_write(testCtx.c_ssl, payload, maxOut), maxOut);

    /* sizing from the plaintext length alone, which is all this reported
     * before the allowance, would have come up short */
    ExpectIntGT(testCtx.s_len, reported - MAX_COMP_EXTRA);
    ExpectIntLE(testCtx.s_len, reported);

    ExpectIntEQ(wolfSSL_read(testCtx.s_ssl, readBuf, maxOut), maxOut);
    ExpectIntEQ(XMEMCMP(readBuf, payload, (word32)maxOut), 0);

    XFREE(readBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(payload, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    test_ssl_memio_cleanup(&testCtx);
#endif /* TEST_TLS_COMPRESSION */
    return EXPECT_RESULT();
}

/*
 * Compression cannot work over DTLS: zlib keeps one deflate stream running
 * across records, so a datagram that is lost, duplicated or reordered leaves
 * the peer's inflate state desynced for the rest of the connection.  The
 * transport is known when the WOLFSSL object is created, so the request is
 * reported rather than silently dropped the way a TLS 1.3 one is.
 */
int test_wolfSSL_dtls_compression_off(void)
{
    EXPECT_DECLS;
#if defined(HAVE_LIBZ) && defined(WOLFSSL_DTLS) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL*     ssl = NULL;

    ExpectIntEQ(wolfSSL_set_compression(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_set_compression(ssl), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(ssl->options.usingCompression, 0);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif /* HAVE_LIBZ && WOLFSSL_DTLS && !WOLFSSL_NO_TLS12 &&
        * !NO_WOLFSSL_CLIENT */
    return EXPECT_RESULT();
}
