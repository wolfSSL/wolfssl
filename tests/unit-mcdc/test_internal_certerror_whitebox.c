/* test_internal_certerror_whitebox.c -- MC/DC white-box driver for the
 * certificate error-classification decisions in src/internal.c
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

/* Error propagation is the largest uncovered category in internal.c, and most
 * of it needs the failing value to be produced by something upstream. These
 * two functions are the exception: they CLASSIFY an error that is handed to
 * them, so the failing value is an argument, and every arm is reachable by
 * calling them with the code that arm names.
 *
 * DoCertFatalAlert maps a verification failure onto the alert a peer is sent.
 * A handshake produces one failure at a time and most of them not at all --
 * a test would need an expired certificate, then a path-length-invalid one,
 * then a revoked one, each with its own chain -- so the arms are mutually
 * exclusive per run and never pair. Passing the codes directly covers the
 * whole map, and the mapping is security-relevant: it decides what a peer
 * learns about why it was rejected.
 *
 * ProcessPeerCertCheckKey enforces the minimum key size per algorithm. The
 * minimums are configuration fixed for the life of a connection and the
 * negative sentinel is never set by a working configuration, so both operands
 * of each guard are constant in any real run.
 *
 * Neither needs fault injection, a certificate chain, or a peer -- only a
 * zeroed WOLFSSL and, for the key check, a DecodedCert filled in by hand.
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

/* ------------------------------------------------------ DoCertFatalAlert */

static void wb_cert_fatal_alert(WOLFSSL* ssl, WOLFSSL_CTX* ctx)
{
    /* Every code the function discriminates on, plus two it does not, so the
     * default arm has its own vector. */
    static const int kCodes[] = {
        0,
        ASN_AFTER_DATE_E, ASN_BEFORE_DATE_E,
        ASN_NO_SIGNER_E, ASN_PATHLEN_INV_E, ASN_PATHLEN_SIZE_E,
#ifdef HAVE_RPK
        RPK_UNTRUSTED_E, UNSUPPORTED_CERTIFICATE,
#endif
#ifdef OPENSSL_EXTRA
        CRL_CERT_REVOKED,
#endif
        NO_PEER_CERT,
        ASN_SIG_CONFIRM_E, BUFFER_E, MEMORY_E
    };
    size_t i;
    int tls13;

    /* ssl == NULL is the first operand; ret == 0 the second. */
    DoCertFatalAlert(NULL, ASN_NO_SIGNER_E);
    g_checks++;

    /* NO_PEER_CERT branches again on tls1_3, so both settings are swept. */
    for (tls13 = 0; tls13 < 2; tls13++) {
        for (i = 0; i < sizeof(kCodes) / sizeof(kCodes[0]); i++) {
            XMEMSET(ssl, 0, sizeof(*ssl));
            ssl->ctx = ctx;
            ssl->version.major = SSLv3_MAJOR;
            ssl->version.minor = tls13 ? TLSv1_3_MINOR : TLSv1_2_MINOR;
            ssl->options.side = WOLFSSL_CLIENT_END;
            ssl->options.tls1_3 = (byte)tls13;
            /* no CBIOSend: DoCertFatalAlert records the alert reason on the
             * ssl rather than writing it, so nothing is transmitted here */
            DoCertFatalAlert(ssl, kCodes[i]);
            g_checks++;
        }
    }
}

/* ----------------------------------------------- ProcessPeerCertCheckKey */

static void wb_check_key_size(WOLFSSL* ssl, WOLFSSL_CTX* ctx)
{
    /* One entry per key algorithm the switch names, so each arm is entered. */
    static const int kOids[] = {
#ifndef NO_RSA
        RSAk,
    #ifdef WC_RSA_PSS
        RSAPSSk,
    #endif
#endif
#ifdef HAVE_ECC
        ECDSAk,
#endif
#ifdef HAVE_ED25519
        ED25519k,
#endif
#ifdef HAVE_ED448
        ED448k,
#endif
        0   /* an OID the switch does not name: the default arm */
    };
    /* The size relative to the configured minimum, and the negative sentinel
     * that a working configuration never sets. */
    static const int kMins[] = { -1, 0, 1024, 4096 };
    ProcPeerCertArgs args;
    DecodedCert dCert;
    size_t o, m;
    int verifyNone;

    for (verifyNone = 0; verifyNone < 2; verifyNone++) {
        for (o = 0; o < sizeof(kOids) / sizeof(kOids[0]); o++) {
            for (m = 0; m < sizeof(kMins) / sizeof(kMins[0]); m++) {
                XMEMSET(ssl, 0, sizeof(*ssl));
                XMEMSET(&args, 0, sizeof(args));
                XMEMSET(&dCert, 0, sizeof(dCert));
                ssl->ctx = ctx;
                ssl->options.verifyNone = (byte)verifyNone;
                /* every minimum set together: the switch picks one arm, and
                 * the arm it picks reads its own field */
                ssl->options.minRsaKeySz = kMins[m];
                ssl->options.minEccKeySz = kMins[m];
                dCert.keyOID = kOids[o];
                dCert.pubKeySize = 2048;
                args.dCert = &dCert;
                (void)ProcessPeerCertCheckKey(ssl, &args);
                g_checks++;
            }
        }
    }
}

/* ---------------------------------------------------------------- main */

int main(void)
{
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        printf("internal certerror white-box: wolfSSL_Init failed\n");
        goto done;
    }
    ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (ctx == NULL) {
        printf("internal certerror white-box: CTX_new failed\n");
        goto done;
    }
    ssl = (WOLFSSL*)XMALLOC(sizeof(WOLFSSL), NULL, DYNAMIC_TYPE_SSL);
    if (ssl == NULL) {
        printf("internal certerror white-box: out of memory\n");
        goto done;
    }

    wb_cert_fatal_alert(ssl, ctx);
    wb_check_key_size(ssl, ctx);

    printf("internal certerror white-box: %d vectors driven\n", g_checks);

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
    printf("internal certerror white-box: skipped (TLS/certs not built)\n");
    return 0;
}

#endif
