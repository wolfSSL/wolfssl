/* test_internal_revocation_whitebox.c -- MC/DC white-box driver for the leaf
 * revocation-check decisions in src/internal.c, using faked revocation
 * back ends
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

/* FAKING THE REVOCATION BACK ENDS.
 *
 * ProcessPeerCertLeafRevocation decides what a revocation answer MEANS. Its
 * guards discriminate between specific codes -- an explicit assertion that the
 * certificate is revoked, a responder that does not know it, a responder that
 * could not be reached, a certificate naming no responder, a lookup still in
 * flight, and the CRL equivalents. The difference between them is the
 * difference between failing a handshake and continuing it, which makes these
 * among the most security-relevant decisions in the file.
 *
 * They are unreachable from any test that owns only certificates: producing
 * the codes for real needs a responder that answers "unknown", then one that
 * times out, then one taken offline, then a certificate with no AIA extension
 * -- four separate deployments, one per vector.
 *
 * Since this translation unit #includes internal.c, the revocation entry
 * points it CALLS but does not DEFINE can be redirected to fakes with a
 * #define ahead of the include -- the idiom mcdc_fault_hash.h already uses for
 * wolfcrypt primitives. CheckCertOCSP_ex, CheckCertCRL and OcspNoUrlPolicy
 * live in ocsp.c and crl.c, so redirecting them rewrites only this driver's
 * copy of internal.c and leaves the library untouched.
 *
 * The answers are only half the input: the guards below them also read
 * ocspEnabled, crlEnabled, crlCheckAll, tls1_3, totalCerts and whether the
 * decoded certificate has a CA. Those are swept one at a time from both
 * saturated ends, crossed with the codes -- an earlier version of this driver
 * pinned them and left every guard that reads them constant.
 *
 * Rules, as for the sibling drivers:
 *   - options.h FIRST, or the smoke build compiles this with the feature
 *     macros undefined and it silently becomes a no-op that still exits 0.
 *   - main() ALWAYS returns 0; a non-zero exit discards the whole variant.
 */

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>
#include <wolfssl/ocsp.h>
#include <wolfssl/crl.h>

#include <stdio.h>
#include <string.h>

#if !defined(WOLFCRYPT_ONLY) && !defined(NO_TLS) && !defined(NO_CERTS) && \
    (defined(HAVE_OCSP) || defined(HAVE_CRL))

/* ---- the fakes, and the code each is told to return ---------------------- */

static int g_ocspRet;       /* what the OCSP back end answers */
static int g_crlRet;        /* what the CRL back end answers  */
static int g_noUrlRet;      /* what the no-URL policy answers */
static int g_ocspCalls;
static int g_crlCalls;

#ifdef HAVE_OCSP
static int mcdc_CheckCertOCSP_ex(WOLFSSL_OCSP* ocsp, DecodedCert* cert,
                                 WOLFSSL* ssl)
{
    (void)ocsp; (void)cert; (void)ssl;
    g_ocspCalls++;
    return g_ocspRet;
}
static int mcdc_OcspNoUrlPolicy(WOLFSSL_CERT_MANAGER* cm)
{
    (void)cm;
    return g_noUrlRet;
}
#endif

#ifdef HAVE_CRL
static int mcdc_CheckCertCRL(WOLFSSL_CRL* crl, DecodedCert* cert)
{
    (void)crl; (void)cert;
    g_crlCalls++;
    return g_crlRet;
}
/* The chain walk uses a different entry point, and it dereferences the Signer
 * chain it is handed. Faking it as well keeps the chain vectors from walking
 * a hand-built Signer, and makes the chain answer selectable like the leaf
 * answer. */
static int mcdc_CheckCertCRL_ex(WOLFSSL_CRL* crl, byte* issuerHash,
        byte* serial, int serialSz, byte* serialHash, const byte* extCrlInfo,
        int extCrlInfoSz, void* issuerName)
{
    (void)crl; (void)issuerHash; (void)serial; (void)serialSz;
    (void)serialHash; (void)extCrlInfo; (void)extCrlInfoSz; (void)issuerName;
    g_crlCalls++;
    return g_crlRet;
}
#endif

/* Redirect internal.c's calls to the fakes. These are defined in ocsp.c and
 * crl.c, not here, so nothing is redefined -- only this driver's view of what
 * internal.c calls. */
#ifdef HAVE_OCSP
    #define CheckCertOCSP_ex(a, b, c)  mcdc_CheckCertOCSP_ex((a), (b), (c))
    #define OcspNoUrlPolicy(a)         mcdc_OcspNoUrlPolicy((a))
#endif
#ifdef HAVE_CRL
    #define CheckCertCRL(a, b)         mcdc_CheckCertCRL((a), (b))
    #define CheckCertCRL_ex(a, b, c, d, e, f, g, h) \
        mcdc_CheckCertCRL_ex((a), (b), (c), (d), (e), (f), (g), (h))
#endif

#include <src/internal.c>

static int g_checks;

int main(void)
{
    /* Every code the decisions discriminate on, plus success and one they do
     * not name, so the default arm has a vector too. */
    static const int kCodes[] = {
        0,
#ifdef HAVE_OCSP
        OCSP_CERT_REVOKED, OCSP_CERT_UNKNOWN, OCSP_LOOKUP_FAIL, OCSP_NO_URL,
    #ifdef WOLFSSL_NONBLOCK_OCSP
        OCSP_WANT_READ,
    #endif
#endif
#ifdef HAVE_CRL
        CRL_MISSING, CRL_CERT_REVOKED,
#endif
        ASN_NO_SIGNER_E
    };
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    WOLFSSL_CERT_MANAGER* cm = NULL;
    ProcPeerCertArgs args;
    DecodedCert dCert;
    Signer caSigner;
    size_t a, b;
    int side, statusReq, mustStaple, flagBase, which, k;

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        printf("internal revocation white-box: wolfSSL_Init failed\n");
        goto done;
    }
    ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (ctx == NULL) {
        printf("internal revocation white-box: CTX_new failed\n");
        goto done;
    }
    ssl = (WOLFSSL*)XMALLOC(sizeof(WOLFSSL), NULL, DYNAMIC_TYPE_SSL);
    if (ssl == NULL) {
        printf("internal revocation white-box: out of memory\n");
        goto done;
    }
    cm = ctx->cm;
    if (cm == NULL) {
        printf("internal revocation white-box: no cert manager\n");
        goto done;
    }

    for (side = 0; side < 2; side++) {
    for (statusReq = 0; statusReq < 2; statusReq++) {
    for (mustStaple = 0; mustStaple < 2; mustStaple++) {
    for (flagBase = 0; flagBase < 2; flagBase++) {
        /* which == -1 is the saturated baseline; 0..5 flip exactly one flag,
         * which is the independence pair for the operand that reads it. */
        for (which = -1; which < 6; which++) {
            for (a = 0; a < sizeof(kCodes) / sizeof(kCodes[0]); a++) {
                for (b = 0; b < sizeof(kCodes) / sizeof(kCodes[0]); b++) {
                    int pRet = 0;
                    int f[6];

                    for (k = 0; k < 6; k++)
                        f[k] = flagBase;
                    if (which >= 0)
                        f[which] = !flagBase;

                    XMEMSET(ssl, 0, sizeof(*ssl));
                    XMEMSET(&args, 0, sizeof(args));
                    XMEMSET(&dCert, 0, sizeof(dCert));
                    XMEMSET(&caSigner, 0, sizeof(caSigner));
                    ssl->ctx = ctx;
                    ssl->version.major = SSLv3_MAJOR;
                    ssl->version.minor = f[3] ? TLSv1_3_MINOR : TLSv1_2_MINOR;
                    ssl->options.side = side ? WOLFSSL_SERVER_END
                                             : WOLFSSL_CLIENT_END;
                    ssl->options.handShakeDone = (byte)side;
                    ssl->options.tls1_3 = (byte)f[3];
                    ssl->status_request = (byte)statusReq;
                    args.dCert = &dCert;
                    /* totalCerts == 1 is one operand of the chain check */
                    args.totalCerts = f[4] ? 1 : 2;
                    /* a decoded cert with and without a CA of its own */
                    /* a real zeroed Signer, not a cast of some other
                     * struct: the callee walks Signer fields. */
                    dCert.ca = f[5] ? &caSigner : NULL;

#ifdef HAVE_OCSP
                    cm->ocspEnabled = (byte)f[0];
                    cm->ocspMustStaple = (byte)mustStaple;
#endif
#ifdef HAVE_CRL
                    cm->crlEnabled = (byte)f[1];
                    cm->crlCheckAll = (byte)f[2];
#endif
                    g_ocspRet = kCodes[a];
                    g_crlRet = kCodes[b];
                    g_noUrlRet = kCodes[b];

                    (void)ProcessPeerCertLeafRevocation(ssl, &args, &pRet);
                    g_checks++;
                }
            }
        }
    }
    }
    }
    }

    printf("internal revocation white-box: %d vectors driven "
           "(%d ocsp, %d crl back-end calls)\n",
           g_checks, g_ocspCalls, g_crlCalls);

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
    printf("internal revocation white-box: skipped (needs OCSP or CRL)\n");
    return 0;
}

#endif
