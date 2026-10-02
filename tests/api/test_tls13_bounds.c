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
/* --- WANT_WRITE resumption harness -----------------------------------------
 *
 * SendTls13Certificate() only fragments (and only takes its ssl->fragOffset
 * resume path) when a send is interrupted part way through a multi-record
 * Certificate. test_memio's own simulate_want_write is all-or-nothing from the
 * start of the flight, so instead a counting send callback is layered over
 * test_memio_write_cb: write number tls13b_ww_at fails with WANT_WRITE once,
 * every other write goes through. Sweeping tls13b_ww_at across the whole
 * flight interrupts each record in turn, and the handshake is still required
 * to complete, so the resume paths are exercised without a rejection vector.
 */
static int tls13b_ww_at = -1;
static int tls13b_ww_n = 0;

static int test_tls13b_send_cb(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    if (tls13b_ww_n++ == tls13b_ww_at)
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    return test_memio_write_cb(ssl, buf, sz, ctx);
}

/* Build a memio pair whose server presents a certificate CHAIN (the default
 * test_memio_setup loads the leaf only, which leaves certChainSz == 0 and the
 * whole chain-walk block in SendTls13Certificate unreachable).
 *
 * The pre-made ctx_s makes test_memio_setup_ex skip its own certificate load
 * AND its IO callback installation, so both are done here. */
static int test_tls13b_setup_chain(struct test_memio_ctx* tc,
    WOLFSSL_CTX** ctx_c, WOLFSSL_CTX** ctx_s, WOLFSSL** ssl_c, WOLFSSL** ssl_s,
    int wantWriteSide)
{
    *ctx_s = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (*ctx_s == NULL)
        return -1;
    if (wolfSSL_CTX_use_PrivateKey_file(*ctx_s, svrKeyFile, CERT_FILETYPE)
            != WOLFSSL_SUCCESS)
        return -1;
    if (wolfSSL_CTX_use_certificate_chain_file(*ctx_s, svrCertFile)
            != WOLFSSL_SUCCESS)
        return -1;
    if (wolfSSL_CTX_load_verify_locations(*ctx_s, caCertFile, 0)
            != WOLFSSL_SUCCESS)
        return -1;
    wolfSSL_SetIORecv(*ctx_s, test_memio_read_cb);
    wolfSSL_SetIOSend(*ctx_s, wantWriteSide == 0 ? test_tls13b_send_cb
                                                 : test_memio_write_cb);

    if (test_memio_setup_ex(tc, ctx_c, ctx_s, ssl_c, ssl_s,
            wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
            NULL, 0, NULL, 0, NULL, 0) != 0)
        return -1;

    /* Per-SSL, not per-CTX: wolfSSL_new() has already copied ctx_c's
     * callbacks into ssl_c by this point, so setting it on the CTX would be
     * a no-op for this connection. */
    if (wantWriteSide == 1)
        wolfSSL_SSLSetIOSend(*ssl_c, test_tls13b_send_cb);
    return 0;
}

/* One handshake with the server's write number 'at' interrupted by
 * WANT_WRITE. Small max_fragment_length forces the Certificate across several
 * records so at least one 'at' lands inside it. */
static int test_tls13b_server_frag_round(int at)
{
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    tls13b_ww_at = at;
    tls13b_ww_n = 0;

    ExpectIntEQ(test_tls13b_setup_chain(&test_ctx, &ctx_c, &ctx_s, &ssl_c,
        &ssl_s, 0), 0);
#ifdef HAVE_MAX_FRAGMENT
    ExpectIntEQ(wolfSSL_UseMaxFragment(ssl_c, WOLFSSL_MFL_2_9),
        WOLFSSL_SUCCESS);
#endif
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 64, NULL), 0);

    tls13b_ww_at = -1;
    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
    return EXPECT_RESULT();
}

/* Same, with the client holding a certificate chain and the interrupt on the
 * client's writes, so the client-side resume path in wolfSSL_connect_TLSv13()
 * runs too. */
static int test_tls13b_client_frag_round(int at)
{
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    tls13b_ww_at = at;
    tls13b_ww_n = 0;

    ExpectIntEQ(test_tls13b_setup_chain(&test_ctx, &ctx_c, &ctx_s, &ssl_c,
        &ssl_s, 1), 0);
    /* Ask for the client's certificate so the client also fragments one.
     * client-cert.pem is its own issuer, so it has to be added to the
     * server's store for the verify to succeed. */
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_s, cliCertFile, 0),
        WOLFSSL_SUCCESS);
    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_use_certificate_chain_file(ssl_c, cliCertFile),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_use_PrivateKey_file(ssl_c, cliKeyFile, CERT_FILETYPE),
        WOLFSSL_SUCCESS);
#ifdef HAVE_MAX_FRAGMENT
    ExpectIntEQ(wolfSSL_UseMaxFragment(ssl_c, WOLFSSL_MFL_2_9),
        WOLFSSL_SUCCESS);
#endif
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 64, NULL), 0);

    tls13b_ww_at = -1;
    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
    return EXPECT_RESULT();
}
/* Rewrite a ServerHello record so it carries a present-but-EMPTY extensions
 * block. That is the only shape that reaches DoTls13ServerHello()'s
 * post-negotiation code with args->totalExtSz == 0: a ServerHello with no
 * extensions FIELD at all returns earlier, at the truncated-length branch.
 * Returns the new record length. */
static int test_tls13b_sh_empty_exts(byte* rec, int rec_sz)
{
    int off, sessIdSz, bodySz;

    if (rec_sz < TLS13B_LEGACY_OFF + 2 + RAN_LEN + 1)
        return -1;
    if (rec[0] != handshake || rec[TLS13B_REC_HDR_SZ] != server_hello)
        return -1;

    off = TLS13B_LEGACY_OFF + OPAQUE16_LEN + RAN_LEN;
    sessIdSz = rec[off];
    off += 1 + sessIdSz;
    off += OPAQUE16_LEN + OPAQUE8_LEN;      /* cipher suite + compression */
    if (off + OPAQUE16_LEN > rec_sz)
        return -1;

    rec[off] = 0;
    rec[off + 1] = 0;
    off += OPAQUE16_LEN;

    bodySz = off - (TLS13B_REC_HDR_SZ + TLS13B_HS_HDR_SZ);
    rec[6] = (byte)(bodySz >> 16);
    rec[7] = (byte)(bodySz >> 8);
    rec[8] = (byte)bodySz;
    rec[3] = (byte)((off - TLS13B_REC_HDR_SZ) >> 8);
    rec[4] = (byte)(off - TLS13B_REC_HDR_SZ);
    return off;
}

/* Find the first extension of the given type in a ClientHello record and
 * return the offset of its body, or -1. */
static int test_tls13b_ch_find_ext(const byte* rec, int rec_sz, word16 type,
    int* bodySz)
{
    int off, sessIdSz, suiteSz, compSz, extEnd;
    int extTotal;

    if (rec_sz < TLS13B_LEGACY_OFF + 2 + RAN_LEN + 1)
        return -1;
    if (rec[0] != handshake || rec[TLS13B_REC_HDR_SZ] != client_hello)
        return -1;

    off = TLS13B_LEGACY_OFF + OPAQUE16_LEN + RAN_LEN;
    sessIdSz = rec[off];
    off += 1 + sessIdSz;
    if (off + OPAQUE16_LEN > rec_sz)
        return -1;
    suiteSz = ((int)rec[off] << 8) | rec[off + 1];
    off += OPAQUE16_LEN + suiteSz;
    if (off + 1 > rec_sz)
        return -1;
    compSz = rec[off];
    off += 1 + compSz;
    if (off + OPAQUE16_LEN > rec_sz)
        return -1;
    extTotal = ((int)rec[off] << 8) | rec[off + 1];
    off += OPAQUE16_LEN;
    extEnd = off + extTotal;
    if (extEnd > rec_sz)
        return -1;

    while (off + 4 <= extEnd) {
        word16 t = (word16)(((word16)rec[off] << 8) | rec[off + 1]);
        int l = ((int)rec[off + 2] << 8) | rec[off + 3];
        if (off + 4 + l > extEnd)
            return -1;
        if (t == type) {
            *bodySz = l;
            return off + 4;
        }
        off += 4 + l;
    }
    return -1;
}

#endif /* guards */

#if defined(WOLFSSL_TLS13) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    (!defined(NO_RSA) || defined(HAVE_ECC) || defined(HAVE_ED25519) || \
     defined(HAVE_ED448))

/* A mutually authenticated TLS 1.3 handshake with a chosen key type on both
 * ends. DoTls13CertificateVerify()'s peer-key / peerSigAlgo dispatch has one
 * arm per algorithm and the group only ever ran the RSA one, so each arm's
 * operands sat on a single row. */
/* The ECC, Ed25519 and Ed448 client certificates in certs/ are self-signed,
 * so cliCa is the client certificate itself rather than a separate CA. */
static int test_tls13b_mutual_auth_round(const char* srvCa,
    const char* srvCert, const char* srvKey,
    const char* cliCa, const char* cliCert, const char* cliKey)
{
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectNotNull(ctx_c = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_c, srvCa, 0),
        WOLFSSL_SUCCESS);
    ExpectNotNull(ctx_s = wolfSSL_CTX_new(wolfTLSv1_3_server_method()));
    ExpectIntEQ(wolfSSL_CTX_use_certificate_chain_file(ctx_s, srvCert),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx_s, srvKey, CERT_FILETYPE),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_s, cliCa, 0),
        WOLFSSL_SUCCESS);
    if (EXPECT_SUCCESS()) {
        wolfSSL_CTX_set_verify(ctx_s, WOLFSSL_VERIFY_PEER |
            WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        /* Pre-made CTXs make test_memio_setup_ex skip its own IO callback
         * install as well as its cert load. */
        wolfSSL_SetIORecv(ctx_c, test_memio_read_cb);
        wolfSSL_SetIOSend(ctx_c, test_memio_write_cb);
        wolfSSL_SetIORecv(ctx_s, test_memio_read_cb);
        wolfSSL_SetIOSend(ctx_s, test_memio_write_cb);
    }

    ExpectIntEQ(test_memio_setup_ex(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
        NULL, 0, NULL, 0, NULL, 0), 0);
    ExpectIntEQ(wolfSSL_use_certificate_chain_file(ssl_c, cliCert),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_use_PrivateKey_file(ssl_c, cliKey, CERT_FILETYPE),
        WOLFSSL_SUCCESS);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 16, NULL), 0);

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

/* Interrupt every write of the server's flight in turn with WANT_WRITE while
 * it sends a fragmented Certificate built from a real chain.
 *
 * Drives SendTls13Certificate()'s resume block: :10019 (certChainSz > 0 &&
 * fragOffset >= certSz + extSz[0]), :10061 cond 1 (the fragment loop leaving
 * with length still > 0 because SendBuffered() answered WANT_WRITE, which is
 * the row an uninterrupted send can never produce), :10143, :10156, :10187 and
 * :9655, plus wolfSSL_accept_TLSv13()'s :16693 buffered-fragment resume.
 * Every round must still complete the handshake, so each vector has its
 * accepting partner in the same run. */
int test_tls13_server_cert_fragment_want_write(void)
{
#if defined(WOLFSSL_TLS13) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    !defined(WOLFSSL_NO_TLS12)
    EXPECT_DECLS;
    int at;

    for (at = 0; at < 16 && EXPECT_SUCCESS(); at++)
        ExpectIntEQ(test_tls13b_server_frag_round(at), TEST_SUCCESS);

    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

/* Client-side counterpart: the client sends its own fragmented Certificate
 * and its writes are interrupted in turn, which drives
 * wolfSSL_connect_TLSv13()'s :15347 buffered-fragment resume. */
int test_tls13_client_cert_fragment_want_write(void)
{
#if defined(WOLFSSL_TLS13) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    !defined(WOLFSSL_NO_TLS12)
    EXPECT_DECLS;
    int at;

    for (at = 0; at < 12 && EXPECT_SUCCESS(); at++)
        ExpectIntEQ(test_tls13b_client_frag_round(at), TEST_SUCCESS);

    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

/* tls13.c:5719 cond 0 - "args->totalExtSz > 0" in DoTls13ServerHello().
 * Every ordinary ServerHello supplies the (both operands true, decision true)
 * row; this vector supplies the missing (cond 0 false) row by handing a
 * downgrade-capable client a ServerHello whose extensions block is present but
 * empty. The client then takes the !foundVersion downgrade path and arrives at
 * :5719 with totalExtSz == 0. The handshake cannot complete (no key_share), so
 * only the failure is asserted. */
int test_tls13_sh_empty_extensions_block(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    byte sh[TLS13B_CH_BUF_SZ];
    int sh_sz = 0;
    int new_sz = -1;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    /* SSLv23 client: downgrade enabled, which the !foundVersion branch needs. */
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfSSLv23_client_method, wolfTLSv1_3_server_method), 0);
    wolfSSL_set_verify(ssl_c, WOLFSSL_VERIFY_NONE, NULL);

    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);

    ExpectIntEQ(test_tls13b_take_record(&test_ctx, 1, sh, (int)sizeof(sh),
        &sh_sz), 0);
    if (EXPECT_SUCCESS())
        new_sz = test_tls13b_sh_empty_exts(sh, sh_sz);
    ExpectIntGT(new_sz, 0);

    test_memio_clear_buffer(&test_ctx, 1);
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(test_memio_inject_message(&test_ctx, 1, (const char*)sh,
            new_sz), 0);
    }
    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* tls13.c:7425 cond 1 - "!IsAtLeastTLSv1_3(ssl->version)" in
 * DoTls13SupportedVersions(). Ordinary handshakes give the (foundVersion set,
 * version still 1.3, decision false) row. This vector rewrites the single
 * version in the ClientHello's supported_versions extension from 0x0304 to
 * 0x0303 - same length, so no other field moves - and hands it to a
 * downgrade-capable server, which negotiates TLS 1.2 and makes the operand
 * true with foundVersion still set. */
int test_tls13_ch_supported_versions_tls12_only(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    byte ch[TLS13B_CH_BUF_SZ];
    int ch_sz = 0;
    int svOff = -1, svSz = 0, i;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfSSLv23_server_method), 0);
    wolfSSL_set_verify(ssl_c, WOLFSSL_VERIFY_NONE, NULL);

    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_tls13b_take_record(&test_ctx, 0, ch, (int)sizeof(ch),
        &ch_sz), 0);
    if (EXPECT_SUCCESS())
        svOff = test_tls13b_ch_find_ext(ch, ch_sz, TLSX_SUPPORTED_VERSIONS,
            &svSz);
    ExpectIntGT(svOff, 0);
    /* body is: 1-byte list length, then <major,minor> pairs */
    ExpectIntGE(svSz, 3);
    if (EXPECT_SUCCESS()) {
        for (i = svOff + 1; i + 1 < svOff + svSz; i += 2) {
            if (ch[i] == SSLv3_MAJOR && ch[i + 1] == TLSv1_3_MINOR)
                ch[i + 1] = TLSv1_2_MINOR;
        }
    }

    test_memio_clear_buffer(&test_ctx, 0);
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (const char*)ch,
            ch_sz), 0);
    }
    /* The server downgrades; the TLS 1.3-only client cannot follow, so the
     * handshake must not complete. */
    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* A complete Encrypted ClientHello handshake in the tls13 group. The group's
 * existing tests never build an ECHConfig, so every ssl->ctx->echConfigs and
 * echX operand in DoTls13ClientHello(), DoTls13HandShakeMsgType() and
 * SendTls13ClientHello() sits on its "no ECH" row only. This supplies the
 * accepting row for all of them; the ordinary handshakes supply the other. */
int test_tls13_ech_accepted_handshake(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && defined(HAVE_ECH) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(HAVE_SNI) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    static const char pubName[] = "ech-public-name.com";
    static const char privName[] = "ech-private-name.com";
    byte configs[512];
    word32 configsLen = (word32)sizeof(configs);

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);
    wolfSSL_set_verify(ssl_c, WOLFSSL_VERIFY_NONE, NULL);

    /* The handshake reads ssl->ctx->echConfigs, so generating on the CTX
     * after wolfSSL_new() is still in time for this connection. */
    ExpectIntEQ(wolfSSL_CTX_GenerateEchConfig(ctx_s, pubName, 0, 0, 0),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_GetEchConfigs(ctx_s, configs, &configsLen),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_SetEchConfigs(ssl_c, configs, configsLen),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseSNI(ssl_c, WOLFSSL_SNI_HOST_NAME, privName,
        (word16)XSTRLEN(privName)), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseSNI(ssl_s, WOLFSSL_SNI_HOST_NAME, privName,
        (word16)XSTRLEN(privName)), WOLFSSL_SUCCESS);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 16, NULL), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* Same handshake with the ECHConfig's public key corrupted, so the server
 * cannot open the outer ClientHello and answers with retry_configs. That is
 * the ECH-rejected arm of the same decisions - notably EchCheckAcceptance()
 * and the acceptance-confirmation compare in DoTls13HandShakeMsgType(). */
int test_tls13_ech_rejected_handshake(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && defined(HAVE_ECH) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(HAVE_SNI) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    static const char pubName[] = "ech-public-name.com";
    static const char privName[] = "ech-private-name.com";
    byte configs[512];
    word32 configsLen = (word32)sizeof(configs);
    word16 idx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);
    wolfSSL_set_verify(ssl_c, WOLFSSL_VERIFY_NONE, NULL);

    ExpectIntEQ(wolfSSL_CTX_GenerateEchConfig(ctx_s, pubName, 0, 0, 0),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_GetEchConfigs(ctx_s, configs, &configsLen),
        WOLFSSL_SUCCESS);
    if (EXPECT_SUCCESS()) {
        /* skip list length, version, length, config id, kem id and public
         * key length to land on the first byte of the public key */
        idx = OPAQUE16_LEN + OPAQUE16_LEN + OPAQUE16_LEN + OPAQUE8_LEN +
            OPAQUE16_LEN + OPAQUE16_LEN;
        ExpectIntLT((word32)idx, configsLen);
        if (EXPECT_SUCCESS())
            configs[idx] ^= 0xFF;
    }
    ExpectIntEQ(wolfSSL_SetEchConfigs(ssl_c, configs, configsLen),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseSNI(ssl_c, WOLFSSL_SNI_HOST_NAME, privName,
        (word16)XSTRLEN(privName)), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseSNI(ssl_s, WOLFSSL_SNI_HOST_NAME, pubName,
        (word16)XSTRLEN(pubName)), WOLFSSL_SUCCESS);

    /* The server cannot open the outer ClientHello, so it completes the
     * handshake against the public name and returns retry_configs; RFC 9849
     * 6.1.7 then makes the client abort with ECH_REQUIRED_E. Both sides run
     * their full ECH code paths first, which is the point of the vector. */
    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WC_NO_ERR_TRACE(ECH_REQUIRED_E));

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* ECDSA on both ends: drives DoTls13CertificateVerify()'s
 * peerEccDsaKey / ecc_dsa_sa_algo arms. */
int test_tls13_mutual_auth_ecdsa(void)
{
#if defined(WOLFSSL_TLS13) && defined(HAVE_ECC) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM)
    return test_tls13b_mutual_auth_round(caEccCertFile, eccCertFile,
        eccKeyFile, cliEccCertFile, cliEccCertFile, cliEccKeyFile);
#else
    return TEST_SKIPPED;
#endif
}

/* Ed25519 on both ends: drives the peerEd25519Key / ed25519_sa_algo arms. */
int test_tls13_mutual_auth_ed25519(void)
{
#if defined(WOLFSSL_TLS13) && defined(HAVE_ED25519) && \
    defined(HAVE_ED25519_SIGN) && defined(HAVE_ED25519_VERIFY) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_ED25519_CLIENT_AUTH) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM)
    return test_tls13b_mutual_auth_round(caEdCertFile, edCertFile,
        edKeyFile, cliEdCertFile, cliEdCertFile, cliEdKeyFile);
#else
    return TEST_SKIPPED;
#endif
}

/* Ed448 on both ends: drives the peerEd448Key / ed448_sa_algo arms. */
int test_tls13_mutual_auth_ed448(void)
{
#if defined(WOLFSSL_TLS13) && defined(HAVE_ED448) && \
    defined(HAVE_ED448_SIGN) && defined(HAVE_ED448_VERIFY) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_ED448_CLIENT_AUTH) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM)
    return test_tls13b_mutual_auth_round(caEd448CertFile, ed448CertFile,
        ed448KeyFile, cliEd448CertFile, cliEd448CertFile, cliEd448KeyFile);
#else
    return TEST_SKIPPED;
#endif
}

/* RSA on both ends, mutually authenticated. The group already runs one-sided
 * RSA handshakes; this adds the client-authenticating rows for the RSA arm of
 * the same dispatch. */
int test_tls13_mutual_auth_rsa(void)
{
#if defined(WOLFSSL_TLS13) && !defined(NO_RSA) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM)
    return test_tls13b_mutual_auth_round(caCertFile, svrCertFile,
        svrKeyFile, cliCertFile, cliCertFile, cliKeyFile);
#else
    return TEST_SKIPPED;
#endif
}
