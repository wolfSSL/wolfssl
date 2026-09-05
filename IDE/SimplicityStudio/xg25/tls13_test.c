/* tls13_test.c
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

/* TLS 1.3 handshake and record layer over an in-memory transport, run on the
 * device with every crypto operation routed to the Secure Element.
 *
 * The wolfCrypt test proves the callbacks against known answer vectors one
 * call at a time. This drives them the way a real connection does: a full
 * TLS 1.3 handshake (ECDHE key share, ECDSA certificate and CertificateVerify,
 * the HKDF key schedule and a running SHA-256 transcript hash), then
 * application data through the AES-GCM record layer.
 *
 * That combination is what catches problems the vector tests cannot. Handshake
 * and record buffers are cursors into a larger buffer, so they land on
 * arbitrary byte offsets rather than the aligned stack arrays the vector tests
 * hand over -- if an engine needs an aligned or DMA-reachable buffer, this is
 * where it shows. The record layer also reuses one Aes object across thousands
 * of chained operations, so any state the port fails to carry between calls
 * surfaces as a decrypt failure rather than passing by luck on a single shot.
 *
 * Client and server both run here, in one thread, wired together through two
 * byte queues. Modeled on examples/tls13/tls13_memio.c, with the file-based
 * certificates replaced by the compiled-in test buffers and both endpoints
 * given the Secure Element devId.
 */

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_XG25_TLS13

#include <stdio.h>

#include <wolfssl/ssl.h>
#include <wolfssl/certs_test.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/port/silabs/silabs_settings.h>

/* Holds one handshake flight. The server's is the larger: certificate,
 * CertificateVerify and Finished together stay under 2 KB with a P-256
 * chain. */
#define XG25_TLS_BUF_SZ 4096

/* Handshake needs a few round trips; the cap only stops a stalled loop. */
#define XG25_TLS_MAX_ITERS 32

typedef struct membuf {
    unsigned char data[XG25_TLS_BUF_SZ];
    int len;
} membuf;

static int mem_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    membuf* mb = (membuf*)ctx;
    int n;

    (void)ssl;
    if (mb->len == 0) {
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
    n = (sz < mb->len) ? sz : mb->len;
    XMEMCPY(buf, mb->data, (size_t)n);
    XMEMMOVE(mb->data, mb->data + n, (size_t)(mb->len - n));
    mb->len -= n;
    return n;
}

static int mem_send(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    membuf* mb = (membuf*)ctx;

    (void)ssl;
    if (sz < 0 || mb->len > XG25_TLS_BUF_SZ - sz) {
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    }
    XMEMCPY(mb->data + mb->len, buf, (size_t)sz);
    mb->len += sz;
    return sz;
}

/* Application data round trip at a deliberately awkward length and offset.
 * Every record is sealed and opened by the Secure Element, and the payload is
 * read back byte for byte, so a record layer that corrupts data fails here
 * even though the handshake succeeded. */
static int xg25_tls13_echo(WOLFSSL* c, WOLFSSL* s, int payloadSz, int offset)
{
    static unsigned char out[512];
    static unsigned char in[512];
    int i;
    int ret;

    if (offset + payloadSz > (int)sizeof(out)) {
        return BAD_FUNC_ARG;
    }

    for (i = 0; i < payloadSz; i++) {
        out[offset + i] = (unsigned char)(i * 7 + payloadSz);
    }

    ret = wolfSSL_write(c, out + offset, payloadSz);
    if (ret != payloadSz) {
        printf("  write failed: %d (err %d)\n", ret, wolfSSL_get_error(c, ret));
        return -1;
    }

    XMEMSET(in, 0, sizeof(in));
    ret = wolfSSL_read(s, in + offset, payloadSz);
    if (ret != payloadSz) {
        printf("  read failed: %d (err %d)\n", ret, wolfSSL_get_error(s, ret));
        return -1;
    }

    if (XMEMCMP(out + offset, in + offset, (size_t)payloadSz) != 0) {
        printf("  payload mismatch at %d bytes, offset %d\n",
            payloadSz, offset);
        return -1;
    }

    return 0;
}

static int xg25_tls13_one(const char* suite)
{
    /* Static rather than automatic: two 4 KB queues plus the peer objects
     * would otherwise sit on a small-stack build's stack. */
    static membuf c2s;  /* client writes, server reads */
    static membuf s2c;  /* server writes, client reads */
    /* Odd lengths and offsets on purpose: unaligned starts and partial final
     * blocks are what an engine with an alignment or block assumption trips
     * over. */
    static const int sizes[]   = { 1, 15, 16, 17, 31, 63, 127, 128, 255 };
    static const int offsets[] = { 0,  1,  2,  3,  1,  2,   3,   1,   2 };
    WOLFSSL_CTX* cctx = NULL;
    WOLFSSL_CTX* sctx = NULL;
    WOLFSSL* c = NULL;
    WOLFSSL* s = NULL;
    int cdone = 0, sdone = 0;
    int cret = WOLFSSL_FATAL_ERROR;
    int sret = WOLFSSL_FATAL_ERROR;
    int ret = -1;
    int i;

    XMEMSET(&c2s, 0, sizeof(c2s));
    XMEMSET(&s2c, 0, sizeof(s2c));

    cctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    sctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (cctx == NULL || sctx == NULL) {
        printf("  CTX_new failed\n");
        goto done;
    }

    /* A single-suite list means a completed handshake proves that suite was
     * the one used. */
    if (wolfSSL_CTX_set_cipher_list(cctx, suite) != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_set_cipher_list(sctx, suite) != WOLFSSL_SUCCESS) {
        printf("  %s: not built in, skipped\n", suite);
        ret = 0;
        goto done;
    }

    /* The whole point: every private key operation, key schedule step,
     * transcript hash and record seal below goes to the Secure Element. */
    if (wolfSSL_CTX_SetDevId(cctx, WOLFSSL_SILABS_DEVID) != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_SetDevId(sctx, WOLFSSL_SILABS_DEVID) != WOLFSSL_SUCCESS) {
        printf("  CTX_SetDevId failed\n");
        goto done;
    }

    /* P-256 server certificate and its issuing CA, from the compiled-in test
     * buffers. Test credentials only - never ship these. */
    if (wolfSSL_CTX_use_certificate_buffer(sctx, serv_ecc_der_256,
            (long)sizeof_serv_ecc_der_256, WOLFSSL_FILETYPE_ASN1)
                != WOLFSSL_SUCCESS) {
        printf("  server cert load failed\n");
        goto done;
    }
    if (wolfSSL_CTX_use_PrivateKey_buffer(sctx, ecc_key_der_256,
            (long)sizeof_ecc_key_der_256, WOLFSSL_FILETYPE_ASN1)
                != WOLFSSL_SUCCESS) {
        printf("  server key load failed\n");
        goto done;
    }
    ret = wolfSSL_CTX_load_verify_buffer(cctx, ca_ecc_cert_der_256,
            (long)sizeof_ca_ecc_cert_der_256, WOLFSSL_FILETYPE_ASN1);
    if (ret != WOLFSSL_SUCCESS) {
        printf("  CA load failed: %d\n", ret);
        ret = -1;
        goto done;
    }
    ret = -1;

    /* Peer verification stays on: the client must actually validate the
     * server's chain, which drives ECDSA verify through the SE. */
    wolfSSL_CTX_set_verify(cctx, WOLFSSL_VERIFY_PEER, NULL);

    wolfSSL_CTX_SetIORecv(cctx, mem_recv);
    wolfSSL_CTX_SetIOSend(cctx, mem_send);
    wolfSSL_CTX_SetIORecv(sctx, mem_recv);
    wolfSSL_CTX_SetIOSend(sctx, mem_send);

    c = wolfSSL_new(cctx);
    s = wolfSSL_new(sctx);
    if (c == NULL || s == NULL) {
        printf("  SSL_new failed\n");
        goto done;
    }

    wolfSSL_SetIOReadCtx(c, &s2c);
    wolfSSL_SetIOWriteCtx(c, &c2s);
    wolfSSL_SetIOReadCtx(s, &c2s);
    wolfSSL_SetIOWriteCtx(s, &s2c);

    for (i = 0; i < XG25_TLS_MAX_ITERS && !(cdone && sdone); i++) {
        if (!cdone) {
            cret = wolfSSL_connect(c);
            if (cret == WOLFSSL_SUCCESS) {
                cdone = 1;
            }
        }
        if (!sdone) {
            sret = wolfSSL_accept(s);
            if (sret == WOLFSSL_SUCCESS) {
                sdone = 1;
            }
        }
    }

    if (!cdone || !sdone) {
        printf("  handshake FAILED (client err %d, server err %d)\n",
            wolfSSL_get_error(c, cret), wolfSSL_get_error(s, sret));
        goto done;
    }
    if (XSTRCMP(wolfSSL_get_version(c), "TLSv1.3") != 0) {
        printf("  negotiated %s, expected TLSv1.3\n", wolfSSL_get_version(c));
        goto done;
    }

    printf("  handshake OK: %s %s\n",
        wolfSSL_get_version(c), wolfSSL_get_cipher(c));

    for (i = 0; i < (int)(sizeof(sizes) / sizeof(sizes[0])); i++) {
        if (xg25_tls13_echo(c, s, sizes[i], offsets[i]) != 0) {
            goto done;
        }
    }
    printf("  record layer OK: %d payloads, 1 to %d bytes\n",
        (int)(sizeof(sizes) / sizeof(sizes[0])),
        sizes[(sizeof(sizes) / sizeof(sizes[0])) - 1]);

    ret = 0;

done:
    wolfSSL_free(c);
    wolfSSL_free(s);
    wolfSSL_CTX_free(cctx);
    wolfSSL_CTX_free(sctx);
    return ret;
}

int xg25_tls13_test(void)
{
    /* Both TLS 1.3 suites, because they exercise different engines. The
     * SHA-256 suite drives the key schedule and transcript hash through the
     * Secure Element; the SHA-384 suite runs those in software unless
     * software, so running both covers the offloaded and the fallback hash
     * path. */
    static const char* suites[] = {
        "TLS13-AES128-GCM-SHA256",
        "TLS13-AES256-GCM-SHA384"
    };
    int i;
    int ret;

    for (i = 0; i < (int)(sizeof(suites) / sizeof(suites[0])); i++) {
        printf("  [%s]\n", suites[i]);
        ret = xg25_tls13_one(suites[i]);
        if (ret != 0) {
            return ret;
        }
    }

    return 0;
}

#endif /* WOLFSSL_XG25_TLS13 */
