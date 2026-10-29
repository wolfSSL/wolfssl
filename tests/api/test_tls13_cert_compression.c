/* test_tls13_cert_compression.c
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

#ifdef NO_INLINE
#include <wolfssl/wolfcrypt/misc.h>
#else
#define WOLFSSL_MISC_INCLUDED
#include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>
#include <wolfssl/wolfcrypt/compress.h>
#include <tests/api/api.h>
#include <tests/utils.h>
#include <tests/api/test_tls13_cert_compression.h>

#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_CERT_COMPRESSION) &&             \
    defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) &&                              \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)
#define TEST_TLS13_CERT_COMPRESSION
#endif

#ifdef TEST_TLS13_CERT_COMPRESSION
static const word16 certCompZlibOnly[] = { WC_ZLIB };

/* Rename the compress_certificate extension in the ClientHello sitting in the
 * server's input buffer to a GREASE type (RFC 8701) so the server ignores it
 * and sends a plain Certificate.
 * returns 1 when the extension was found and renamed, 0 otherwise. */
static int test_cert_compression_hide_ext(struct test_memio_ctx *ctx)
{
    /* compress_certificate(27) extension as the client writes it when its
     * list is set to just zlib: type, extension length, list length, alg id. */
    static const byte certCompZlibExt[] = { 0x00, 0x1b, 0x00, 0x03,
                                            0x02, 0x00, 0x01 };
    int i;

    for (i = 0; i + (int)sizeof(certCompZlibExt) <= ctx->s_len; i++) {
        if (XMEMCMP(ctx->s_buff + i, certCompZlibExt,
                    sizeof(certCompZlibExt)) == 0) {
            ctx->s_buff[i] = 0x0a;
            ctx->s_buff[i + 1] = 0x0a;
            return 1;
        }
    }
    return 0;
}

/* Run the client's first flight and the server's reply, and report how many
 * bytes the server's flight (ServerHello .. Finished) took on the wire.
 * hideExt  when set the server never sees the compress_certificate extension,
 *          so it sends an uncompressed Certificate. */
static int test_cert_compression_server_flight_sz(int hideExt, int *flightSz)
{
    EXPECT_DECLS;
    struct test_memio_ctx testContext;
    WOLFSSL_CTX *clientContext = NULL;
    WOLFSSL_CTX *serverContext = NULL;
    WOLFSSL *clientSSL = NULL;
    WOLFSSL *serverSSL = NULL;

    XMEMSET(&testContext, 0, sizeof(testContext));
    ExpectIntEQ(test_memio_setup(&testContext, &clientContext, &serverContext,
                                 &clientSSL, &serverSSL,
                                 wolfTLSv1_3_client_method,
                                 wolfTLSv1_3_server_method),
                0);
    ExpectIntEQ(
        wolfSSL_set_cert_compression_algs(clientSSL, certCompZlibOnly,
                                          (int)XELEM_CNT(certCompZlibOnly)),
        WOLFSSL_SUCCESS);

    /* ClientHello */
    ExpectIntEQ(wolfSSL_connect(clientSSL), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(clientSSL, WOLFSSL_FATAL_ERROR),
                WOLFSSL_ERROR_WANT_READ);
    if (hideExt) {
        ExpectIntEQ(test_cert_compression_hide_ext(&testContext), 1);
    }

    /* ServerHello .. Finished, then the server waits on the client */
    ExpectIntEQ(wolfSSL_accept(serverSSL), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(serverSSL, WOLFSSL_FATAL_ERROR),
                WOLFSSL_ERROR_WANT_READ);
    *flightSz = testContext.c_len;

    wolfSSL_free(clientSSL);
    wolfSSL_free(serverSSL);
    wolfSSL_CTX_free(clientContext);
    wolfSSL_CTX_free(serverContext);
    return EXPECT_RESULT();
}

/* Send a message each way over an established connection. */
static int test_cert_compression_exchange(WOLFSSL *clientSSL,
                                          WOLFSSL *serverSSL)
{
    EXPECT_DECLS;
    static const char msg[] = "cert compression round trip";
    char reply[sizeof(msg)];

    XMEMSET(reply, 0, sizeof(reply));
    ExpectIntEQ(wolfSSL_write(clientSSL, msg, (int)sizeof(msg)),
                (int)sizeof(msg));
    ExpectIntEQ(wolfSSL_read(serverSSL, reply, (int)sizeof(reply)),
                (int)sizeof(msg));
    ExpectIntEQ(XMEMCMP(reply, msg, sizeof(msg)), 0);

    XMEMSET(reply, 0, sizeof(reply));
    ExpectIntEQ(wolfSSL_write(serverSSL, msg, (int)sizeof(msg)),
                (int)sizeof(msg));
    ExpectIntEQ(wolfSSL_read(clientSSL, reply, (int)sizeof(reply)),
                (int)sizeof(msg));
    ExpectIntEQ(XMEMCMP(reply, msg, sizeof(msg)), 0);
    return EXPECT_RESULT();
}

#ifdef HAVE_MAX_FRAGMENT
/* --- WANT_WRITE resumption harness -----------------------------------------
 *
 * test_memio's own simulate_want_write is all-or-nothing, so a counting send
 * callback is layered over test_memio_write_cb instead: write number cc_ww_at
 * fails with WANT_WRITE once and every other write goes through. Sweeping
 * cc_ww_at across the whole flight interrupts each record in turn, including
 * the ones in the middle of a fragmented CompressedCertificate. */
static int cc_ww_at = -1;
static int cc_ww_n = 0;

static int test_cert_compression_send_cb(WOLFSSL *ssl, char *buf, int sz,
                                         void *ctx)
{
    if (cc_ww_n++ == cc_ww_at)
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    return test_memio_write_cb(ssl, buf, sz, ctx);
}

/* Compressed size of the certificates an SSL object would send. */
static int test_cert_compression_chain_comp_sz(WOLFSSL *ssl, word32 *compSz)
{
    EXPECT_DECLS;
    wc_CompressionData cd;
    byte *raw = NULL;
    word32 rawSz = 0;
    word32 leafSz = 0;

    XMEMSET(&cd, 0, sizeof(cd));
    *compSz = 0;
    ExpectNotNull(ssl->buffers.certificate);
    if (EXPECT_SUCCESS()) {
        leafSz = ssl->buffers.certificate->length;
        rawSz = leafSz;
        if (ssl->buffers.certChain != NULL)
            rawSz += ssl->buffers.certChain->length;
    }
    ExpectNotNull(raw = (byte *)XMALLOC(rawSz, NULL, DYNAMIC_TYPE_TMP_BUFFER));
    if (EXPECT_SUCCESS()) {
        XMEMCPY(raw, ssl->buffers.certificate->buffer, leafSz);
        if (ssl->buffers.certChain != NULL) {
            XMEMCPY(raw + leafSz, ssl->buffers.certChain->buffer,
                    ssl->buffers.certChain->length);
        }
    }
    ExpectIntEQ(wc_CompressionData_InitComp(&cd, raw, rawSz, WC_ZLIB), 0);
    ExpectIntEQ(wc_CompressionData_Compress(&cd), 0);
    if (EXPECT_SUCCESS())
        *compSz = cd.compressedSz;
    wc_CompressionData_Free(&cd);
    XFREE(raw, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return EXPECT_RESULT();
}

/* One handshake with write number 'at' of 'side' (0 server, 1 client)
 * interrupted by WANT_WRITE. The server presents a chain and, for mutual
 * auth, the client does too; max_fragment_length 2^9 makes the compressed
 * certificates span several records so the fragOffset != 0 path runs.
 * writes  set to the number of writes 'side' made, so the caller knows when
 *         the sweep has covered the whole flight. */
static int test_cert_compression_frag_round(method_provider cm,
                                            method_provider sm, int mutual,
                                            int side, int at, int *writes)
{
    EXPECT_DECLS;
    struct test_memio_ctx testContext;
    WOLFSSL_CTX *clientContext = NULL;
    WOLFSSL_CTX *serverContext = NULL;
    WOLFSSL *clientSSL = NULL;
    WOLFSSL *serverSSL = NULL;
    word32 compSz = 0;

    XMEMSET(&testContext, 0, sizeof(testContext));
    ExpectIntEQ(test_memio_setup(&testContext, &clientContext, &serverContext,
                                 &clientSSL, &serverSSL, cm, sm),
                0);
    ExpectIntEQ(wolfSSL_use_certificate_chain_file(serverSSL, svrCertFile),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(test_cert_compression_chain_comp_sz(serverSSL, &compSz),
                TEST_SUCCESS);
    /* the compressed chain must not fit one 2^9 record, or the
     * fragmentation path is never reached */
    ExpectIntGT(compSz, 512);
    if (mutual) {
        ExpectIntEQ(
            wolfSSL_CTX_load_verify_locations(serverContext, cliCertFile, NULL),
            WOLFSSL_SUCCESS);
        wolfSSL_set_verify(
            serverSSL,
            WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        ExpectIntEQ(wolfSSL_use_certificate_chain_file(clientSSL, cliCertFile),
                    WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_use_PrivateKey_file(clientSSL, cliKeyFile,
                                                WOLFSSL_FILETYPE_PEM),
                    WOLFSSL_SUCCESS);
    }
    ExpectIntEQ(wolfSSL_UseMaxFragment(clientSSL, WOLFSSL_MFL_2_9),
                WOLFSSL_SUCCESS);
    wolfSSL_SSLSetIOSend(side == 0 ? serverSSL : clientSSL,
                         test_cert_compression_send_cb);

    cc_ww_at = at;
    cc_ww_n = 0;
    ExpectIntEQ(test_memio_do_handshake(clientSSL, serverSSL, 64, NULL), 0);
    *writes = cc_ww_n;
    cc_ww_at = -1;
    /* nothing left over from the compressed send on either side */
    ExpectNull(serverSSL == NULL ? NULL : serverSSL->compressedCert);
    ExpectNull(clientSSL == NULL ? NULL : clientSSL->compressedCert);
    ExpectIntEQ(test_cert_compression_exchange(clientSSL, serverSSL),
                TEST_SUCCESS);

    wolfSSL_free(clientSSL);
    wolfSSL_free(serverSSL);
    wolfSSL_CTX_free(clientContext);
    wolfSSL_CTX_free(serverContext);
    return EXPECT_RESULT();
}

/* Sweep a WANT_WRITE over every write 'side' makes during the handshake,
 * starting with one uninterrupted run to learn how many writes there are. */
static int test_cert_compression_frag_sweep(method_provider cm,
                                            method_provider sm, int mutual,
                                            int side)
{
    EXPECT_DECLS;
    int writes = 0;
    int n = 0;
    int at;

    ExpectIntEQ(
        test_cert_compression_frag_round(cm, sm, mutual, side, -1, &writes),
        TEST_SUCCESS);
    for (at = 0; at < writes && EXPECT_SUCCESS(); at++) {
        ExpectIntEQ(
            test_cert_compression_frag_round(cm, sm, mutual, side, at, &n),
            TEST_SUCCESS);
    }
    return EXPECT_RESULT();
}
#endif /* HAVE_MAX_FRAGMENT */
#endif /* TEST_TLS13_CERT_COMPRESSION */

/* Full TLS 1.3 handshakes with RFC 8879 certificate compression:
 *   - server auth: the server's Certificate goes out as a
 *     CompressedCertificate and the client decompresses and verifies it;
 *   - mutual auth: the CertificateRequest carries the extension so the
 *     client's Certificate is compressed too and the server verifies it;
 *   - the server's flight is smaller when the client offers compression than
 *     when the server never sees the offer, proving compression was used. */
int test_tls13_cert_compression_roundTrip(void)
{
    EXPECT_DECLS;
#ifdef TEST_TLS13_CERT_COMPRESSION
    struct test_memio_ctx testContext;
    WOLFSSL_CTX *clientContext = NULL;
    WOLFSSL_CTX *serverContext = NULL;
    WOLFSSL *clientSSL = NULL;
    WOLFSSL *serverSSL = NULL;
    int compressedSz = 0;
    int uncompressedSz = 0;

    /* --- server auth, default alg list --- */
    XMEMSET(&testContext, 0, sizeof(testContext));
    ExpectIntEQ(test_memio_setup(&testContext, &clientContext, &serverContext,
                                 &clientSSL, &serverSSL,
                                 wolfTLSv1_3_client_method,
                                 wolfTLSv1_3_server_method),
                0);
    ExpectIntEQ(test_memio_do_handshake(clientSSL, serverSSL, 10, NULL), 0);
    ExpectIntEQ(test_cert_compression_exchange(clientSSL, serverSSL),
                TEST_SUCCESS);

    wolfSSL_free(clientSSL);
    clientSSL = NULL;
    wolfSSL_free(serverSSL);
    serverSSL = NULL;
    wolfSSL_CTX_free(clientContext);
    clientContext = NULL;
    wolfSSL_CTX_free(serverContext);
    serverContext = NULL;

    /* --- mutual auth, both certificates compressed --- */
    XMEMSET(&testContext, 0, sizeof(testContext));
    ExpectIntEQ(test_memio_setup(&testContext, &clientContext, &serverContext,
                                 &clientSSL, &serverSSL,
                                 wolfTLSv1_3_client_method,
                                 wolfTLSv1_3_server_method),
                0);
    /* client-cert.pem is self signed so it is its own CA */
    ExpectIntEQ(
        wolfSSL_CTX_load_verify_locations(serverContext, cliCertFile, NULL),
        WOLFSSL_SUCCESS);
    wolfSSL_set_verify(
        serverSSL, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        NULL);
    ExpectIntEQ(wolfSSL_use_certificate_file(clientSSL, cliCertFile,
                                             WOLFSSL_FILETYPE_PEM),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_use_PrivateKey_file(clientSSL, cliKeyFile,
                                            WOLFSSL_FILETYPE_PEM),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(clientSSL, serverSSL, 10, NULL), 0);
    ExpectIntEQ(test_cert_compression_exchange(clientSSL, serverSSL),
                TEST_SUCCESS);

    wolfSSL_free(clientSSL);
    clientSSL = NULL;
    wolfSSL_free(serverSSL);
    serverSSL = NULL;
    wolfSSL_CTX_free(clientContext);
    clientContext = NULL;
    wolfSSL_CTX_free(serverContext);
    serverContext = NULL;

    /* --- compression actually shrank the server's flight --- */
    ExpectIntEQ(test_cert_compression_server_flight_sz(0, &compressedSz),
                TEST_SUCCESS);
    ExpectIntEQ(test_cert_compression_server_flight_sz(1, &uncompressedSz),
                TEST_SUCCESS);
    ExpectIntGT(compressedSz, 0);
    ExpectIntLT(compressedSz, uncompressedSz);
#endif /* TEST_TLS13_CERT_COMPRESSION */
    return EXPECT_RESULT();
}

int test_tls13_cert_compression_turnoff(void)
{
    EXPECT_DECLS;
#ifdef TEST_TLS13_CERT_COMPRESSION
    struct test_memio_ctx testContext;
    WOLFSSL_CTX *clientContext = NULL;
    WOLFSSL_CTX *serverContext = NULL;
    WOLFSSL *clientSSL = NULL;
    WOLFSSL *serverSSL = NULL;

    /* --- server auth, default alg list --- */
    XMEMSET(&testContext, 0, sizeof(testContext));
    ExpectIntEQ(test_memio_setup(&testContext, &clientContext, &serverContext,
                                 &clientSSL, &serverSSL,
                                 wolfTLSv1_3_client_method,
                                 wolfTLSv1_3_server_method),
                0);

    /* turn off cert compression */
    ExpectIntEQ(wolfSSL_set_cert_compression_algs(clientSSL, NULL, 0),
                WOLFSSL_SUCCESS);

    /* ClientHello */
    ExpectIntEQ(wolfSSL_connect(clientSSL), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(clientSSL, WOLFSSL_FATAL_ERROR),
                WOLFSSL_ERROR_WANT_READ);

    /* check if clientSSL has the compress_certificate extension */
    ExpectNull(TLSX_Find(clientSSL->extensions, TLSX_CERT_COMPRESSION));

    wolfSSL_free(clientSSL);
    clientSSL = NULL;
    wolfSSL_free(serverSSL);
    serverSSL = NULL;
    wolfSSL_CTX_free(clientContext);
    clientContext = NULL;
    wolfSSL_CTX_free(serverContext);
    serverContext = NULL;

    /* --- turned off on the CTX: inherited by objects created from it, even
     * when the CTX also holds an alg list --- */
    XMEMSET(&testContext, 0, sizeof(testContext));
    ExpectIntEQ(test_memio_setup(&testContext, &clientContext, &serverContext,
                                 NULL, NULL, wolfTLSv1_3_client_method,
                                 wolfTLSv1_3_server_method),
                0);
    ExpectIntEQ(
        wolfSSL_CTX_set_cert_compression_algs(clientContext, certCompZlibOnly,
                                              (int)XELEM_CNT(certCompZlibOnly)),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_set_cert_compression_algs(clientContext, NULL, 0),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_setup(&testContext, &clientContext, &serverContext,
                                 &clientSSL, &serverSSL,
                                 wolfTLSv1_3_client_method,
                                 wolfTLSv1_3_server_method),
                0);

    ExpectIntEQ(wolfSSL_connect(clientSSL), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(clientSSL, WOLFSSL_FATAL_ERROR),
                WOLFSSL_ERROR_WANT_READ);
    ExpectNull(TLSX_Find(clientSSL->extensions, TLSX_CERT_COMPRESSION));

    wolfSSL_free(clientSSL);
    clientSSL = NULL;
    wolfSSL_free(serverSSL);
    serverSSL = NULL;

    /* --- re-enabled on the CTX after turning it off --- */
    XMEMSET(&testContext, 0, sizeof(testContext));
    ExpectIntEQ(
        wolfSSL_CTX_set_cert_compression_algs(clientContext, certCompZlibOnly,
                                              (int)XELEM_CNT(certCompZlibOnly)),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_setup(&testContext, &clientContext, &serverContext,
                                 &clientSSL, &serverSSL,
                                 wolfTLSv1_3_client_method,
                                 wolfTLSv1_3_server_method),
                0);

    ExpectIntEQ(wolfSSL_connect(clientSSL), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(clientSSL, WOLFSSL_FATAL_ERROR),
                WOLFSSL_ERROR_WANT_READ);
    ExpectNotNull(TLSX_Find(clientSSL->extensions, TLSX_CERT_COMPRESSION));

    wolfSSL_free(clientSSL);
    clientSSL = NULL;
    wolfSSL_free(serverSSL);
    serverSSL = NULL;

    /* --- re-enabled on the SSL after turning it off --- */
    XMEMSET(&testContext, 0, sizeof(testContext));
    ExpectIntEQ(test_memio_setup(&testContext, &clientContext, &serverContext,
                                 &clientSSL, NULL, wolfTLSv1_3_client_method,
                                 wolfTLSv1_3_server_method),
                0);
    ExpectIntEQ(wolfSSL_set_cert_compression_algs(clientSSL, NULL, 0),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(
        wolfSSL_set_cert_compression_algs(clientSSL, certCompZlibOnly,
                                          (int)XELEM_CNT(certCompZlibOnly)),
        WOLFSSL_SUCCESS);

    ExpectIntEQ(wolfSSL_connect(clientSSL), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(clientSSL, WOLFSSL_FATAL_ERROR),
                WOLFSSL_ERROR_WANT_READ);
    ExpectNotNull(TLSX_Find(clientSSL->extensions, TLSX_CERT_COMPRESSION));

    wolfSSL_free(clientSSL);
    wolfSSL_free(serverSSL);
    wolfSSL_CTX_free(clientContext);
    wolfSSL_CTX_free(serverContext);
#endif /* TEST_TLS13_CERT_COMPRESSION */
    return EXPECT_RESULT();
}

/* RFC 8879 CompressedCertificate larger than one record: max_fragment_length
 * 2^9 with a certificate chain on each side, and a WANT_WRITE injected at
 * every write of the sender so each fragment boundary is resumed from. */
int test_tls13_cert_compression_fragment(void)
{
    EXPECT_DECLS;
#if defined(TEST_TLS13_CERT_COMPRESSION) && defined(HAVE_MAX_FRAGMENT)
    /* server's compressed Certificate */
    ExpectIntEQ(test_cert_compression_frag_sweep(
                    wolfTLSv1_3_client_method, wolfTLSv1_3_server_method, 0, 0),
                TEST_SUCCESS);
    /* client's compressed Certificate */
    ExpectIntEQ(test_cert_compression_frag_sweep(
                    wolfTLSv1_3_client_method, wolfTLSv1_3_server_method, 1, 1),
                TEST_SUCCESS);
#endif
    return EXPECT_RESULT();
}

/* The DTLS 1.3 path hands the whole CompressedCertificate to
 * Dtls13HandshakeSend, which does its own fragmentation. Run it once plainly,
 * then with max_fragment_length and a WANT_WRITE sweep on each side. */
int test_tls13_cert_compression_dtls13(void)
{
    EXPECT_DECLS;
#if defined(TEST_TLS13_CERT_COMPRESSION) && defined(WOLFSSL_DTLS13)
    struct test_memio_ctx testContext;
    WOLFSSL_CTX *clientContext = NULL;
    WOLFSSL_CTX *serverContext = NULL;
    WOLFSSL *clientSSL = NULL;
    WOLFSSL *serverSSL = NULL;

    XMEMSET(&testContext, 0, sizeof(testContext));
    ExpectIntEQ(test_memio_setup(&testContext, &clientContext, &serverContext,
                                 &clientSSL, &serverSSL,
                                 wolfDTLSv1_3_client_method,
                                 wolfDTLSv1_3_server_method),
                0);
    ExpectIntEQ(
        wolfSSL_CTX_load_verify_locations(serverContext, cliCertFile, NULL),
        WOLFSSL_SUCCESS);
    wolfSSL_set_verify(
        serverSSL, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        NULL);
    ExpectIntEQ(wolfSSL_use_certificate_file(clientSSL, cliCertFile,
                                             WOLFSSL_FILETYPE_PEM),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_use_PrivateKey_file(clientSSL, cliKeyFile,
                                            WOLFSSL_FILETYPE_PEM),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(clientSSL, serverSSL, 10, NULL), 0);
    ExpectNull(serverSSL == NULL ? NULL : serverSSL->compressedCert);
    ExpectNull(clientSSL == NULL ? NULL : clientSSL->compressedCert);
    ExpectIntEQ(test_cert_compression_exchange(clientSSL, serverSSL),
                TEST_SUCCESS);

    wolfSSL_free(clientSSL);
    wolfSSL_free(serverSSL);
    wolfSSL_CTX_free(clientContext);
    wolfSSL_CTX_free(serverContext);

#ifdef HAVE_MAX_FRAGMENT
    ExpectIntEQ(test_cert_compression_frag_sweep(wolfDTLSv1_3_client_method,
                                                 wolfDTLSv1_3_server_method, 0,
                                                 0),
                TEST_SUCCESS);
    ExpectIntEQ(test_cert_compression_frag_sweep(wolfDTLSv1_3_client_method,
                                                 wolfDTLSv1_3_server_method, 1,
                                                 1),
                TEST_SUCCESS);
#endif
#endif
    return EXPECT_RESULT();
}

#if defined(TEST_TLS13_CERT_COMPRESSION) && defined(WOLFSSL_POST_HANDSHAKE_AUTH)
/* Replace the algorithm list of the server's compress_certificate extension
 * with an ID nobody implements, so the client falls back to a plain
 * Certificate. Used to get an uncompressed baseline for the same flight. */
static int test_cert_compression_poison_offer(WOLFSSL *ssl)
{
    TLSX *ext;

    for (ext = ssl->extensions; ext != NULL; ext = ext->next) {
        if (ext->type == TLSX_CERT_COMPRESSION && ext->data != NULL) {
            byte *data = (byte *)ext->data;
            /* <list len><alg id 16 bit> */
            data[1] = 0xff;
            data[2] = 0xfe;
            return 1;
        }
    }
    return 0;
}

/* Post-handshake auth: report the size of the client's reply to the
 * server's CertificateRequest (CompressedCertificate or Certificate,
 * CertificateVerify, Finished) and check the server accepted it. */
static int test_cert_compression_pha_flight_sz(int poison, int *flightSz)
{
    EXPECT_DECLS;
    struct test_memio_ctx testContext;
    WOLFSSL_CTX *clientContext = NULL;
    WOLFSSL_CTX *serverContext = NULL;
    WOLFSSL *clientSSL = NULL;
    WOLFSSL *serverSSL = NULL;
#ifdef KEEP_PEER_CERT
    WOLFSSL_X509 *peer = NULL;
#endif
    char buf[16];

    XMEMSET(&testContext, 0, sizeof(testContext));
    /* The client's certificate goes on the CTX: one set on the SSL is
     * unloaded at the end of the handshake, before the request arrives. The
     * pre-made CTX makes test_memio_setup skip its CA load and IO setup. */
    ExpectNotNull(clientContext = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectIntEQ(
        wolfSSL_CTX_load_verify_locations(clientContext, caCertFile, NULL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(clientContext, cliCertFile,
                                                 WOLFSSL_FILETYPE_PEM),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(clientContext, cliKeyFile,
                                                WOLFSSL_FILETYPE_PEM),
                WOLFSSL_SUCCESS);
    wolfSSL_SetIORecv(clientContext, test_memio_read_cb);
    wolfSSL_SetIOSend(clientContext, test_memio_write_cb);
    ExpectIntEQ(test_memio_setup(&testContext, &clientContext, &serverContext,
                                 &clientSSL, &serverSSL,
                                 wolfTLSv1_3_client_method,
                                 wolfTLSv1_3_server_method),
                0);
    ExpectIntEQ(
        wolfSSL_CTX_load_verify_locations(serverContext, cliCertFile, NULL),
        WOLFSSL_SUCCESS);
    wolfSSL_set_verify(
        serverSSL, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_POST_HANDSHAKE, NULL);
    ExpectIntEQ(wolfSSL_allow_post_handshake_auth(clientSSL), 0);
    ExpectIntEQ(test_memio_do_handshake(clientSSL, serverSSL, 10, NULL), 0);
#ifdef KEEP_PEER_CERT
    ExpectNull(wolfSSL_get_peer_certificate(serverSSL));
#endif

    if (poison && EXPECT_SUCCESS()) {
        /* The server only adds compress_certificate when it sends a
         * CertificateRequest, so add it now to have an offer to poison. The
         * request reuses the existing entry. */
        ExpectIntEQ(TLSX_UseCertCompression(serverSSL, serverSSL->heap), 0);
        ExpectIntEQ(test_cert_compression_poison_offer(serverSSL), 1);
    }

    /* OPENSSL_COMPATIBLE_DEFAULTS turns on message grouping, which would
     * hold the CertificateRequest until the server's next write. */
    ExpectIntEQ(wolfSSL_clear_group_messages(serverSSL), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_request_certificate(serverSSL), WOLFSSL_SUCCESS);
    testContext.s_len = 0;
    /* client reads the CertificateRequest and answers it */
    ExpectIntEQ(wolfSSL_read(clientSSL, buf, sizeof(buf)), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(clientSSL, WOLFSSL_FATAL_ERROR),
                WOLFSSL_ERROR_WANT_READ);
    *flightSz = testContext.s_len;
    ExpectNull(clientSSL == NULL ? NULL : clientSSL->compressedCert);
    /* server reads and verifies the answer */
    ExpectIntEQ(wolfSSL_read(serverSSL, buf, sizeof(buf)), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(serverSSL, WOLFSSL_FATAL_ERROR),
                WOLFSSL_ERROR_WANT_READ);
#ifdef KEEP_PEER_CERT
    /* a reference the caller frees when OPENSSL_EXTRA is defined */
    ExpectNotNull(peer = wolfSSL_get_peer_certificate(serverSSL));
    wolfSSL_X509_free(peer);
#endif
    ExpectIntEQ(test_cert_compression_exchange(clientSSL, serverSSL),
                TEST_SUCCESS);

    wolfSSL_free(clientSSL);
    wolfSSL_free(serverSSL);
    wolfSSL_CTX_free(clientContext);
    wolfSSL_CTX_free(serverContext);
    return EXPECT_RESULT();
}
#endif

/* Post-handshake auth: the CertificateRequest the server sends after the
 * handshake carries compress_certificate, so the client answers with a
 * CompressedCertificate. It is smaller than the plain Certificate the client
 * sends when the offer is changed to an unknown algorithm. */
int test_tls13_cert_compression_pha(void)
{
    EXPECT_DECLS;
#if defined(TEST_TLS13_CERT_COMPRESSION) && defined(WOLFSSL_POST_HANDSHAKE_AUTH)
    int compressedSz = 0;
    int uncompressedSz = 0;

    ExpectIntEQ(test_cert_compression_pha_flight_sz(0, &compressedSz),
                TEST_SUCCESS);
    ExpectIntEQ(test_cert_compression_pha_flight_sz(1, &uncompressedSz),
                TEST_SUCCESS);
    ExpectIntGT(compressedSz, 0);
    ExpectIntLT(compressedSz, uncompressedSz);
#endif
    return EXPECT_RESULT();
}

#ifdef TEST_TLS13_CERT_COMPRESSION
/* Payload for a CompressedCertificate that decompresses cleanly, so every
 * rejection below comes from the field under test. Its content is never
 * parsed as a Certificate. It has to be compressible: the compressor gives
 * up when the output would not be smaller than the input. */
static byte cc_payload[64];

/* Build alg(2) | uncompressed_length(3) | compressed_length(3) | body. */
static word32 test_cert_compression_build(byte *out, word16 alg,
                                          word32 uncompSz, word32 compSz,
                                          const byte *body, word32 bodySz)
{
    c16toa(alg, out);
    c32to24(uncompSz, out + OPAQUE16_LEN);
    c32to24(compSz, out + OPAQUE16_LEN + OPAQUE24_LEN);
    XMEMCPY(out + COMP_CERT_HEADER_SZ, body, bodySz);
    return COMP_CERT_HEADER_SZ + bodySz;
}

/* Feed one CompressedCertificate body to a fresh client and check the error
 * it returns, that nothing is leaked in ssl->compressedCert and, when
 * expAlert >= 0, that a fatal alert with that description was sent. */
static int test_cert_compression_reject(byte *msg, word32 msgSz, int expErr,
                                        int expAlert, int noRequest)
{
    EXPECT_DECLS;
    struct test_memio_ctx testContext;
    WOLFSSL_CTX *clientContext = NULL;
    WOLFSSL_CTX *serverContext = NULL;
    WOLFSSL *clientSSL = NULL;
    WOLFSSL *serverSSL = NULL;
    word32 idx = 0;

    XMEMSET(&testContext, 0, sizeof(testContext));
    ExpectIntEQ(test_memio_setup(&testContext, &clientContext, &serverContext,
                                 &clientSSL, &serverSSL,
                                 wolfTLSv1_3_client_method,
                                 wolfTLSv1_3_server_method),
                0);
    if (!noRequest) {
        ExpectIntEQ(TLSX_UseCertCompression(clientSSL, clientSSL->heap), 0);
    }
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(DoTls13CompressedCertificate(clientSSL, msg, &idx, msgSz),
                    expErr);
        ExpectIntEQ(idx, 0);
        ExpectNull(clientSSL->compressedCert);
    }
    if (expAlert >= 0) {
        /* level and description are the last two bytes of the record */
        ExpectIntGE(testContext.s_len, RECORD_HEADER_SZ + ALERT_SIZE);
        if (EXPECT_SUCCESS()) {
            ExpectIntEQ(testContext.s_buff[0], alert);
            ExpectIntEQ(testContext.s_buff[testContext.s_len - 2], alert_fatal);
            ExpectIntEQ(testContext.s_buff[testContext.s_len - 1], expAlert);
        }
    }
    else {
        ExpectIntEQ(testContext.s_len, 0);
    }

    wolfSSL_free(clientSSL);
    wolfSSL_free(serverSSL);
    wolfSSL_CTX_free(clientContext);
    wolfSSL_CTX_free(serverContext);
    return EXPECT_RESULT();
}
#endif /* TEST_TLS13_CERT_COMPRESSION */

/* Each field of a CompressedCertificate that DoTls13CompressedCertificate
 * checks, broken one at a time. The message is encrypted on the wire, so it
 * is handed to the parser directly rather than edited in the memio buffer. */
int test_tls13_cert_compression_malformed(void)
{
    EXPECT_DECLS;
#ifdef TEST_TLS13_CERT_COMPRESSION
    wc_CompressionData cd;
    byte msg[COMP_CERT_HEADER_SZ + 64];
    byte body[64];
    word32 compSz = 0;
    word32 uncompSz = (word32)sizeof(cc_payload);
    word32 msgSz;

    XMEMSET(&cd, 0, sizeof(cd));
    ExpectIntEQ(wc_CompressionData_InitComp(&cd, cc_payload, uncompSz, WC_ZLIB),
                0);
    ExpectIntEQ(wc_CompressionData_Compress(&cd), 0);
    ExpectIntLE(cd.compressedSz, sizeof(body));
    if (EXPECT_SUCCESS()) {
        compSz = cd.compressedSz;
        XMEMCPY(body, cd.data, compSz);
    }
    wc_CompressionData_Free(&cd);

    /* shorter than the fixed header */
    msgSz = test_cert_compression_build(msg, WC_ZLIB, uncompSz, compSz, body,
                                        compSz);
    ExpectIntEQ(test_cert_compression_reject(msg, COMP_CERT_HEADER_SZ - 1,
                                             BUFFER_ERROR, -1, 0),
                TEST_SUCCESS);

    /* compressed_length larger / smaller than the bytes that follow */
    msgSz = test_cert_compression_build(msg, WC_ZLIB, uncompSz, compSz + 1,
                                        body, compSz);
    ExpectIntEQ(test_cert_compression_reject(msg, msgSz, BUFFER_ERROR, -1, 0),
                TEST_SUCCESS);
    msgSz = test_cert_compression_build(msg, WC_ZLIB, uncompSz, compSz - 1,
                                        body, compSz);
    ExpectIntEQ(test_cert_compression_reject(msg, msgSz, BUFFER_ERROR, -1, 0),
                TEST_SUCCESS);

    /* compressed_length of 0 */
    msgSz = test_cert_compression_build(msg, WC_ZLIB, uncompSz, 0, body, 0);
    ExpectIntEQ(test_cert_compression_reject(msg, msgSz, BUFFER_ERROR, -1, 0),
                TEST_SUCCESS);

    /* algorithm IDs that were never offered: brotli, zstd, unassigned */
    msgSz = test_cert_compression_build(msg, 2, uncompSz, compSz, body, compSz);
    ExpectIntEQ(test_cert_compression_reject(msg, msgSz, DECOMPRESS_E,
                                             illegal_parameter, 0),
                TEST_SUCCESS);
    msgSz = test_cert_compression_build(msg, 3, uncompSz, compSz, body, compSz);
    ExpectIntEQ(test_cert_compression_reject(msg, msgSz, DECOMPRESS_E,
                                             illegal_parameter, 0),
                TEST_SUCCESS);
    msgSz = test_cert_compression_build(msg, 0xffff, uncompSz, compSz, body,
                                        compSz);
    ExpectIntEQ(test_cert_compression_reject(msg, msgSz, DECOMPRESS_E,
                                         illegal_parameter, 0),TEST_SUCCESS);
    /* 0 is "no compression", which is not a valid algorithm to receive */
    msgSz = test_cert_compression_build(msg, WC_NO_COMPRESSION, uncompSz,
                                        compSz, body, compSz);
    ExpectIntEQ(test_cert_compression_reject(msg, msgSz, DECOMPRESS_E,
                                        illegal_parameter, 0), TEST_SUCCESS);

    /* uncompressed_length of 0 and above MAX_CERTIFICATE_SZ + room */
    msgSz = test_cert_compression_build(msg, WC_ZLIB, 0, compSz, body, compSz);
    ExpectIntEQ(test_cert_compression_reject(msg, msgSz, DECOMPRESS_E,
                                             bad_certificate, 0),
                TEST_SUCCESS);
    if (MAX_CERTIFICATE_SZ < 0xffffff) {
        msgSz = test_cert_compression_build(
            msg, WC_ZLIB, MAX_CERTIFICATE_SZ + 300, compSz, body, compSz);
        ExpectIntEQ(test_cert_compression_reject(msg, msgSz, DECOMPRESS_E,
                                                 bad_certificate, 0),
                    TEST_SUCCESS);
    }

    /* uncompressed_length one short of / one past the real output */
    msgSz = test_cert_compression_build(msg, WC_ZLIB, uncompSz - 1, compSz,
                                        body, compSz);
    ExpectIntEQ(test_cert_compression_reject(msg, msgSz, DECOMPRESS_E,
                                             bad_certificate, 0),
                TEST_SUCCESS);
    msgSz = test_cert_compression_build(msg, WC_ZLIB, uncompSz + 1, compSz,
                                        body, compSz);
    ExpectIntEQ(test_cert_compression_reject(msg, msgSz, DECOMPRESS_E,
                                             bad_certificate, 0),
                TEST_SUCCESS);

    /* corrupt zlib stream: bad header byte, bad adler32, truncated stream */
    msgSz = test_cert_compression_build(msg, WC_ZLIB, uncompSz, compSz, body,
                                        compSz);
    msg[COMP_CERT_HEADER_SZ] ^= 0xff;
    ExpectIntEQ(test_cert_compression_reject(msg, msgSz, DECOMPRESS_E,
                                             bad_certificate, 0),
                TEST_SUCCESS);
    msgSz = test_cert_compression_build(msg, WC_ZLIB, uncompSz, compSz, body,
                                        compSz);
    msg[msgSz - 1] ^= 0x01;
    ExpectIntEQ(test_cert_compression_reject(msg, msgSz, DECOMPRESS_E,
                                             bad_certificate, 0),
                TEST_SUCCESS);
    msgSz = test_cert_compression_build(msg, WC_ZLIB, uncompSz, compSz - 4,
                                        body, compSz - 4);
    ExpectIntEQ(test_cert_compression_reject(msg, msgSz, DECOMPRESS_E,
                                             bad_certificate, 0),
                TEST_SUCCESS);

    /* check that unrequested compressed cert is not processed */
    msgSz = test_cert_compression_build(msg, WC_ZLIB, uncompSz, compSz, body,
                                        compSz);
    ExpectIntEQ(test_cert_compression_reject(msg, msgSz, DECOMPRESS_E,
                                             illegal_parameter, 1),
                TEST_SUCCESS);
#endif
    return EXPECT_RESULT();
}


#if defined(TEST_TLS13_CERT_COMPRESSION) && defined(USE_WOLFSSL_MEMORY) &&     \
    !defined(WOLFSSL_STATIC_MEMORY) && !defined(WOLFSSL_DEBUG_MEMORY) &&       \
    defined(HAVE_LIBZ) && !defined(WOLFSSL_TRACK_MEMORY)
/* An allocator that fails every request of at least CC_FAIL_MIN_SZ bytes
 * while armed. zlib gets its memory through XMALLOC and its deflate state is
 * made of 64KB blocks, far above anything the handshake itself allocates, so
 * only the compression fails. */
#define CC_FAIL_MIN_SZ (32 * 1024)
static int cc_fail_armed = 0;
static int cc_fail_hits = 0;

static void *test_cert_compression_fail_malloc(size_t size)
{
    if (cc_fail_armed && size >= CC_FAIL_MIN_SZ) {
        cc_fail_hits++;
        return NULL;
    }
    return malloc(size);
}

static void test_cert_compression_fail_free(void *ptr)
{
    free(ptr);
}

static void *test_cert_compression_fail_realloc(void *ptr, size_t size)
{
    if (cc_fail_armed && size >= CC_FAIL_MIN_SZ) {
        cc_fail_hits++;
        return NULL;
    }
    return realloc(ptr, size);
}

#if defined(HAVE_OCSP) && defined(HAVE_CERTIFICATE_STATUS_REQUEST) &&          \
    !defined(NO_RSA) && !defined(NO_SHA)
#define TEST_CERT_COMPRESSION_STAPLE
/* Good OCSP response for certs/ocsp/server1-cert.pem, handed to the server by
 * its OCSP IO callback so it has something to staple. */
static byte cc_staple_resp[4096];
static int cc_staple_respSz = 0;
static int cc_staple_calls = 0;

static int test_cert_compression_staple_io_cb(void *ioCtx, const char *url,
                                              int urlSz, unsigned char *req,
                                              int reqSz,
                                              unsigned char **respBuf)
{
    (void)ioCtx;
    (void)url;
    (void)urlSz;
    (void)req;
    (void)reqSz;

    cc_staple_calls++;
    /* static buffer: the free callback registered with this one is NULL */
    *respBuf = cc_staple_resp;
    return cc_staple_respSz;
}

/* TLS 1.3 handshake where the server staples an OCSP response to its leaf
 * CertificateEntry and the client offers zlib and requires the staple.
 * failAlloc  when set, compression cannot allocate while the server writes
 *            its flight, so the staple has to go out in the plain Certificate.
 * flightSz   set to the size of the server's flight (ServerHello .. Finished).
 */
static int test_cert_compression_staple_round(int failAlloc, int *flightSz)
{
    EXPECT_DECLS;
    struct test_memio_ctx testContext;
    WOLFSSL_CTX *clientContext = NULL;
    WOLFSSL_CTX *serverContext = NULL;
    WOLFSSL *clientSSL = NULL;
    WOLFSSL *serverSSL = NULL;
    wolfSSL_Malloc_cb prevMalloc = NULL;
    wolfSSL_Free_cb prevFree = NULL;
    wolfSSL_Realloc_cb prevRealloc = NULL;

    cc_staple_calls = 0;
    *flightSz = 0;

    /* The CTXs are configured before any SSL is made from them, since each
     * SSL latches the certificate at wolfSSL_new(). */
    XMEMSET(&testContext, 0, sizeof(testContext));
    ExpectIntEQ(test_memio_setup(&testContext, &clientContext, &serverContext,
                                 NULL, NULL, wolfTLSv1_3_client_method,
                                 wolfTLSv1_3_server_method),
                0);

    /* server1 is the certificate the response answers for, sent with its
     * intermediate so the client can build a path to the root */
    ExpectIntEQ(wolfSSL_CTX_use_certificate_chain_file(
                    serverContext, "./certs/ocsp/server1-chain-noroot.pem"),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(serverContext,
                                                "./certs/ocsp/server1-key.pem",
                                                WOLFSSL_FILETYPE_PEM),
                WOLFSSL_SUCCESS);
    /* the server verifies the response before stapling it */
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(
                    serverContext, "./certs/ocsp/root-ca-cert.pem", NULL),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(
        wolfSSL_CTX_load_verify_locations(
            serverContext, "./certs/ocsp/intermediate1-ca-cert.pem", NULL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(serverContext), WOLFSSL_SUCCESS);
    /* server1 carries no AuthInfo, so point the lookup at a dummy responder */
    ExpectIntEQ(
        wolfSSL_CTX_SetOCSP_OverrideURL(serverContext, "http://dummy.test"),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(
        wolfSSL_CTX_EnableOCSP(serverContext, WOLFSSL_OCSP_NO_NONCE |
                                                  WOLFSSL_OCSP_URL_OVERRIDE),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_Cb(serverContext,
                                       test_cert_compression_staple_io_cb, NULL,
                                       NULL),
                WOLFSSL_SUCCESS);

    /* the client needs the intermediate too, to verify the responder
     * certificate inside the stapled response */
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(
                    clientContext, "./certs/ocsp/root-ca-cert.pem", NULL),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(
        wolfSSL_CTX_load_verify_locations(
            clientContext, "./certs/ocsp/intermediate1-ca-cert.pem", NULL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(clientContext), WOLFSSL_SUCCESS);
    /* a Certificate that lost the staple fails the handshake */
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPMustStaple(clientContext),
                WOLFSSL_SUCCESS);

    ExpectIntEQ(test_memio_setup(&testContext, &clientContext, &serverContext,
                                 &clientSSL, &serverSSL,
                                 wolfTLSv1_3_client_method,
                                 wolfTLSv1_3_server_method),
                0);
    wolfSSL_set_verify(clientSSL, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_UseOCSPStapling(clientSSL, WOLFSSL_CSR_OCSP, 0),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(
        wolfSSL_set_cert_compression_algs(clientSSL, certCompZlibOnly,
                                          (int)XELEM_CNT(certCompZlibOnly)),
        WOLFSSL_SUCCESS);

    /* ClientHello */
    ExpectIntEQ(wolfSSL_connect(clientSSL), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(clientSSL, WOLFSSL_FATAL_ERROR),
                WOLFSSL_ERROR_WANT_READ);

    /* ServerHello .. Finished */
    if (failAlloc) {
        ExpectIntEQ(wolfSSL_GetAllocators(&prevMalloc, &prevFree, &prevRealloc),
                    0);
        ExpectIntEQ(wolfSSL_SetAllocators(test_cert_compression_fail_malloc,
                                          test_cert_compression_fail_free,
                                          test_cert_compression_fail_realloc),
                    0);
        cc_fail_hits = 0;
        cc_fail_armed = 1;
    }
    ExpectIntEQ(wolfSSL_accept(serverSSL), WOLFSSL_FATAL_ERROR);
    if (failAlloc) {
        cc_fail_armed = 0;
        (void)wolfSSL_SetAllocators(prevMalloc, prevFree, prevRealloc);
        /* compression was attempted and failed */
        ExpectIntGT(cc_fail_hits, 0);
    }
    ExpectIntEQ(wolfSSL_get_error(serverSSL, WOLFSSL_FATAL_ERROR),
                WOLFSSL_ERROR_WANT_READ);
    *flightSz = testContext.c_len;
    /* the server fetched a response to staple */
    ExpectIntGT(cc_staple_calls, 0);
    ExpectNull(serverSSL == NULL ? NULL : serverSSL->compressedCert);

    /* the client accepts the Certificate only with the staple in it */
    ExpectIntEQ(test_memio_do_handshake(clientSSL, serverSSL, 10, NULL), 0);
    ExpectIntEQ(test_cert_compression_exchange(clientSSL, serverSSL),
                TEST_SUCCESS);

    wolfSSL_free(clientSSL);
    wolfSSL_free(serverSSL);
    wolfSSL_CTX_free(clientContext);
    wolfSSL_CTX_free(serverContext);
    return EXPECT_RESULT();
}
#endif /* HAVE_OCSP && HAVE_CERTIFICATE_STATUS_REQUEST && ... */
#endif

/* When the Certificate cannot be compressed the server falls back to sending
 * a plain Certificate and the handshake still completes. With OCSP stapling
 * the fallback Certificate must still carry the staple. */
int test_tls13_comp_cert_fallback(void)
{
    EXPECT_DECLS;
#if defined(TEST_TLS13_CERT_COMPRESSION) && defined(USE_WOLFSSL_MEMORY) &&     \
    !defined(WOLFSSL_STATIC_MEMORY) && !defined(WOLFSSL_DEBUG_MEMORY) &&       \
    defined(HAVE_LIBZ) && !defined(WOLFSSL_TRACK_MEMORY)
    struct test_memio_ctx testContext;
    WOLFSSL_CTX *clientContext = NULL;
    WOLFSSL_CTX *serverContext = NULL;
    WOLFSSL *clientSSL = NULL;
    WOLFSSL *serverSSL = NULL;
    wolfSSL_Malloc_cb prevMalloc = NULL;
    wolfSSL_Free_cb prevFree = NULL;
    wolfSSL_Realloc_cb prevRealloc = NULL;
    int plainSz = 0;
    int compressedSz = 0;
    word16 algs[] = { WC_ZLIB };
#ifdef TEST_CERT_COMPRESSION_STAPLE
    XFILE f = XBADFILE;
#endif

    /* reference sizes of the server flight with a plain and a compressed
     * Certificate */
    ExpectIntEQ(test_cert_compression_server_flight_sz(1, &plainSz),
                TEST_SUCCESS);
    ExpectIntEQ(test_cert_compression_server_flight_sz(0, &compressedSz),
                TEST_SUCCESS);
    ExpectIntLT(compressedSz, plainSz);

    XMEMSET(&testContext, 0, sizeof(testContext));
    ExpectIntEQ(test_memio_setup(&testContext, &clientContext, &serverContext,
                                 &clientSSL, &serverSSL,
                                 wolfTLSv1_3_client_method,
                                 wolfTLSv1_3_server_method),
                0);

    /* this test is zlib specific and must negotiate with zlib */
    ExpectIntEQ(wolfSSL_set_cert_compression_algs(clientSSL, algs, 1),
                WOLFSSL_SUCCESS);

    /* ClientHello */
    ExpectIntEQ(wolfSSL_connect(clientSSL), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(clientSSL, WOLFSSL_FATAL_ERROR),
                WOLFSSL_ERROR_WANT_READ);

    /* ServerHello .. Finished with compression unable to allocate */
    ExpectIntEQ(wolfSSL_GetAllocators(&prevMalloc, &prevFree, &prevRealloc), 0);
    ExpectIntEQ(wolfSSL_SetAllocators(test_cert_compression_fail_malloc,
                                      test_cert_compression_fail_free,
                                      test_cert_compression_fail_realloc),
                0);
    cc_fail_hits = 0;
    cc_fail_armed = 1;
    ExpectIntEQ(wolfSSL_accept(serverSSL), WOLFSSL_FATAL_ERROR);
    cc_fail_armed = 0;
    (void)wolfSSL_SetAllocators(prevMalloc, prevFree, prevRealloc);
    ExpectIntEQ(wolfSSL_get_error(serverSSL, WOLFSSL_FATAL_ERROR),
                WOLFSSL_ERROR_WANT_READ);

    /* compression was attempted and failed, and a plain Certificate went
     * out in its place */
    ExpectIntGT(cc_fail_hits, 0);
    ExpectIntEQ(testContext.c_len, plainSz);
    ExpectNull(serverSSL == NULL ? NULL : serverSSL->compressedCert);

    ExpectIntEQ(test_memio_do_handshake(clientSSL, serverSSL, 10, NULL), 0);
    ExpectIntEQ(test_cert_compression_exchange(clientSSL, serverSSL),
                TEST_SUCCESS);

    wolfSSL_free(clientSSL);
    wolfSSL_free(serverSSL);
    wolfSSL_CTX_free(clientContext);
    wolfSSL_CTX_free(serverContext);

#ifdef TEST_CERT_COMPRESSION_STAPLE
    /* --- OCSP stapling: the status_request extension in the leaf
     * CertificateEntry survives the fallback to a plain Certificate --- */
    ExpectTrue((f = XFOPEN("./certs/ocsp/test-leaf-response.der", "rb")) !=
               XBADFILE);
    if (f != XBADFILE) {
        cc_staple_respSz =
            (int)XFREAD(cc_staple_resp, 1, sizeof(cc_staple_resp), f);
        XFCLOSE(f);
    }
    ExpectIntGT(cc_staple_respSz, 0);
    ExpectIntLT(cc_staple_respSz, (int)sizeof(cc_staple_resp));

    compressedSz = 0;
    plainSz = 0;
    ExpectIntEQ(test_cert_compression_staple_round(0, &compressedSz),
                TEST_SUCCESS);
    ExpectIntEQ(test_cert_compression_staple_round(1, &plainSz), TEST_SUCCESS);
    /* the first flight was compressed and the second was not */
    ExpectIntGT(compressedSz, 0);
    ExpectIntLT(compressedSz, plainSz);
#endif
#endif
    return EXPECT_RESULT();
}
