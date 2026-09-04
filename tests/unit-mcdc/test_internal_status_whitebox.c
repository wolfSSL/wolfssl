/* test_internal_status_whitebox.c -- MC/DC white-box driver for the
 * certificate-status and send-path error decisions in src/internal.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* Three more error-classification clusters, none of which needs a peer.
 *
 * CsrDoStatusVerifyCb lets an application override the library's OCSP verdict.
 * Its decisions compare the library's result against the callback's, and the
 * interesting combinations are precisely the disagreements: the callback
 * forcing an error on a good status, and the callback clearing an error on a
 * bad one. No in-tree test installs a callback that disagrees, so those arms
 * have never been taken. A mock callback returning a chosen value against a
 * chosen incoming result sweeps the whole matrix.
 *
 * DoCertificateStatus parses a CertificateStatus message off the wire. Its
 * length guards compare the declared status length against the record size,
 * and a conforming peer always makes them agree -- so the mismatch arms need
 * bytes a real peer never sends. Crafted input, no fixture.
 *
 * SendData's opening guards ask whether the connection is resuming from a
 * blocked write. A test that writes successfully never sets ssl->error to
 * WANT_WRITE first, so that operand is constant; setting it directly pairs it.
 *
 * Rules, as for the sibling drivers:
 *   - options.h FIRST, or the smoke build compiles this with the feature
 *     macros undefined and it silently becomes a no-op that still exits 0.
 *   - main() ALWAYS returns 0; a non-zero exit discards the whole variant.
 */

#include <wolfssl/options.h>

#include <src/internal.c>

#include <stdio.h>
#include <string.h>

#if !defined(WOLFCRYPT_ONLY) && !defined(NO_TLS) && !defined(NO_CERTS)

static int g_checks;

static int wb_send_sink(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl; (void)buf; (void)ctx;
    return sz;              /* swallow output, report it fully written */
}

/* ------------------------------------------------- CsrDoStatusVerifyCb */

#if !defined(NO_WOLFSSL_SERVER) && \
    (defined(HAVE_CERTIFICATE_STATUS_REQUEST) || \
     defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2))

static int g_verRet;    /* what the mock callback returns */

static int wb_status_verify_cb(WOLFSSL* ssl, int err, byte* resp,
                               word32 respSz, word32 idx, void* arg)
{
    (void)ssl; (void)err; (void)resp; (void)respSz; (void)idx; (void)arg;
    return g_verRet;
}

static void wb_csr_status_verify(WOLFSSL* ssl, WOLFSSL_CTX* ctx)
{
    /* The library's verdict, and the callback's, swept against each other.
     * (0, <0) is "callback forces an error"; (<0, 0) is "callback overrides
     * the error"; >0 is the invalid-return arm. */
    static const int kLibRet[] = { 0, -1, ASN_NO_SIGNER_E };
    static const int kCbRet[]  = { 0, -1, 1, 42 };
    byte input[32];
    size_t a, b;
    int installed;

    XMEMSET(input, 0, sizeof(input));

    for (installed = 0; installed < 2; installed++) {
        for (a = 0; a < sizeof(kLibRet) / sizeof(kLibRet[0]); a++) {
            for (b = 0; b < sizeof(kCbRet) / sizeof(kCbRet[0]); b++) {
                XMEMSET(ssl, 0, sizeof(*ssl));
                ssl->ctx = ctx;
                /* the `callback != NULL` operand: a build that never
                 * installs one keeps it false forever */
                ctx->ocspStatusVerifyCb = installed ? wb_status_verify_cb
                                                    : NULL;
                ctx->ocspStatusVerifyCbArg = NULL;
                g_verRet = kCbRet[b];
                (void)CsrDoStatusVerifyCb(ssl, input, (word32)sizeof(input),
                                          0, kLibRet[a]);
                g_checks++;
            }
        }
    }
    ctx->ocspStatusVerifyCb = NULL;
}
#endif

/* ------------------------------------------------- DoCertificateStatus */

static void wb_do_certificate_status(WOLFSSL* ssl, WOLFSSL_CTX* ctx)
{
    /* A CertificateStatus body is: status_type(1) status_length(3) data.
     * The guards compare `size` against those fields, so the vectors are
     * (declared length, actual size) pairs that agree and disagree. */
    static const struct { byte type; word32 declared; word32 size;
                          const char* what; } rows[] = {
        { 1, 4,  4 + 1 + 3, "consistent, type ocsp" },
        { 2, 4,  4 + 1 + 3, "consistent, type ocsp_multi" },
        { 0, 4,  4 + 1 + 3, "consistent, type none" },
        { 9, 4,  4 + 1 + 3, "consistent, unknown type" },
        { 1, 4,  3,         "size below the fixed header" },
        { 1, 0,  1 + 3,     "zero-length status" },
        { 1, 64, 1 + 3 + 4, "declared longer than the record" },
        { 1, 1,  1 + 3 + 4, "declared shorter than the record" },
    };
    byte input[128];
    size_t i;

    for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        word32 idx = 0;

        XMEMSET(ssl, 0, sizeof(*ssl));
        ssl->ctx = ctx;
        ssl->version.major = SSLv3_MAJOR;
        ssl->version.minor = TLSv1_2_MINOR;
        ssl->options.side = WOLFSSL_CLIENT_END;
        ssl->CBIOSend = wb_send_sink;

        XMEMSET(input, 0, sizeof(input));
        input[0] = rows[i].type;
        c32to24(rows[i].declared, input + 1);

        (void)DoCertificateStatus(ssl, input, &idx, rows[i].size);
        g_checks++;
    }
}

/* ------------------------------------------------------------- SendData */

static void wb_send_data(WOLFSSL* ssl, WOLFSSL_CTX* ctx)
{
    /* The opening guard asks whether ssl->error holds a blocked-write code
     * (or, under async, a pending-crypto one), i.e. whether this call resumes
     * a write that could not complete. A test that writes successfully never
     * leaves that state behind, so the operand is constant. The
     * oversized-length guard above it returns before any IO happens at all. */
    static const int kErrors[] = { 0, WANT_WRITE, WC_PENDING_E, SOCKET_ERROR_E };
    static const char payload[] = "hello";
    size_t i;

    for (i = 0; i < sizeof(kErrors) / sizeof(kErrors[0]); i++) {
        XMEMSET(ssl, 0, sizeof(*ssl));
        ssl->ctx = ctx;
        ssl->version.major = SSLv3_MAJOR;
        ssl->version.minor = TLSv1_2_MINOR;
        ssl->options.side = WOLFSSL_CLIENT_END;
        ssl->CBIOSend = wb_send_sink;
        ssl->error = kErrors[i];
        (void)SendData(ssl, payload, sizeof(payload) - 1);
        g_checks++;
    }

    /* `sz > INT_MAX`: a length no caller passes, and the only guard that
     * returns before the connection state is even consulted. */
    XMEMSET(ssl, 0, sizeof(*ssl));
    ssl->ctx = ctx;
    ssl->CBIOSend = wb_send_sink;
    (void)SendData(ssl, payload, (size_t)INT_MAX + 1);
    g_checks++;
}

/* ---------------------------------------------------------------- main */

int main(void)
{
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        printf("internal status white-box: wolfSSL_Init failed\n");
        goto done;
    }
    ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (ctx == NULL) {
        printf("internal status white-box: CTX_new failed\n");
        goto done;
    }
    ssl = (WOLFSSL*)XMALLOC(sizeof(WOLFSSL), NULL, DYNAMIC_TYPE_SSL);
    if (ssl == NULL) {
        printf("internal status white-box: out of memory\n");
        goto done;
    }

#if !defined(NO_WOLFSSL_SERVER) && \
    (defined(HAVE_CERTIFICATE_STATUS_REQUEST) || \
     defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2))
    wb_csr_status_verify(ssl, ctx);
#endif
    wb_do_certificate_status(ssl, ctx);
    wb_send_data(ssl, ctx);

    printf("internal status white-box: %d vectors driven\n", g_checks);

done:
    XFREE(ssl, NULL, DYNAMIC_TYPE_SSL);
    if (ctx != NULL)
        wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return 0;   /* always 0: a non-zero exit discards the variant */
}

#else

int main(void)
{
    printf("internal status white-box: skipped (TLS/certs not built)\n");
    return 0;
}

#endif
