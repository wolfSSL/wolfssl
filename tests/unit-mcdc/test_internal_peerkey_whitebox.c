/* test_internal_peerkey_whitebox.c -- MC/DC white-box driver for the
 * file-static peer-key and peer-certificate guards in src/internal.c
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

/* WHY A WHITE-BOX.
 *
 * These are the "no peer key" and "nothing decoded" guards of internal.c.
 * Every one of them is file-static, and every one of them is a rejection that
 * only fires for a peer key or a decoded certificate that the handshake code
 * would already have refused upstream:
 *
 *   EcMakeKey        -- the three `!peerKey || !peerKeyPresent || !peerKey->dp`
 *                       guards, one per curve family. The caller only reaches
 *                       EcMakeKey after the peer's key has been imported, so
 *                       on every API-driven call all of these are false.
 *   SetCurveId       -- `key == NULL || key->dp == NULL` on a key the server
 *                       key-exchange builder just created itself.
 *   RpkIsTrusted     -- the spki/spkiSz operands, pinned by a caller that has
 *                       already length-checked the SubjectPublicKeyInfo.
 *   CopyDecodedPubKey / CopyDecodedSig -- `publicKey != NULL && pubKeySize`
 *                       and `signature != NULL && sigLength`, pinned true by
 *                       any certificate that parsed at all.
 *   ProcessPeerCertParse -- its argument guard, pinned false by its one caller.
 *   ProcessCSR_ex    -- `csr && !csr->ssl`, where the back-pointer is set on
 *                       the first pass and never seen unset again.
 *
 * SHORT-CIRCUIT IS THE WHOLE GAME: one call per uncovered operand, everything
 * else in that call valid, plus one all-valid call as the shared partner.
 *
 * WHERE THE ALL-VALID PARTNER IS BUILT RATHER THAN BORROWED. For the EcMakeKey
 * guards the false partner has to actually generate a key, so the fixture
 * carries a real WC_RNG and a real ECC/X25519 peer key and lets the function
 * run to completion, freeing the ephemeral key afterwards with FreeKey(). Two
 * of the three EcMakeKey arms (X25519 on TLS 1.2, and the static-ECDH arm) are
 * not exercised by any suite the campaign negotiates, so borrowing their
 * partner from the handshake runs would silently pair nothing.
 *
 * Rules, as for the sibling drivers:
 *   - options.h FIRST, or the smoke build compiles this with the feature
 *     macros undefined and it silently becomes a no-op that still exits 0.
 *   - main() ALWAYS returns 0; a non-zero exit discards the whole variant.
 *   - Each target carries the SAME preprocessor guard that encloses it in
 *     internal.c.
 */

#include <wolfssl/options.h>

#include <src/internal.c>

#include <stdio.h>
#include <string.h>

#if !defined(WOLFCRYPT_ONLY) && !defined(NO_TLS) && !defined(WOLFSSL_NO_TLS12)

static int g_calls;

typedef struct WbFix {
    WOLFSSL*              ssl;
    WOLFSSL_CTX*          ctx;
    WOLFSSL_CERT_MANAGER* cm;
    WC_RNG                rng;
    int                   rngOk;
} WbFix;

static void wb_reset(WbFix* f)
{
    XMEMSET(f->ssl, 0, sizeof(*f->ssl));
    XMEMSET(f->ctx, 0, sizeof(*f->ctx));
    XMEMSET(f->cm, 0, sizeof(*f->cm));
    f->ssl->ctx = f->ctx;
    f->ssl->ctx->cm = f->cm;
    f->ssl->heap = NULL;
    f->ssl->devId = INVALID_DEVID;
    f->ssl->version.major = SSLv3_MAJOR;
    f->ssl->version.minor = TLSv1_2_MINOR;
    if (f->rngOk)
        f->ssl->rng = &f->rng;
}

/* ------------------------------------------------------------------ EcMakeKey
 *
 * Three guards, one per curve family, all of the same shape: reject when the
 * peer key is absent, not marked present, or carries no domain parameters.
 * Each arm is selected by a "present" flag or by ssl->specs, so the driver
 * enters exactly one arm per call and every rejecting vector returns
 * NO_PEER_KEY without allocating anything. */
#if !defined(NO_WOLFSSL_CLIENT) && \
    (defined(HAVE_ECC) || defined(HAVE_CURVE25519) || defined(HAVE_CURVE448))

#ifdef HAVE_CURVE25519
static void wb_ecmakekey_x25519(WbFix* f)
{
    curve25519_key blank;
    curve25519_key peer;
    int            peerInit = 0;

    XMEMSET(&blank, 0, sizeof(blank));   /* never inited: dp stays NULL */

    /* operand 0: the "present" flag is set but there is no key object */
    wb_reset(f);
    f->ssl->peerX25519KeyPresent = 1;
    f->ssl->peerX25519Key = NULL;
    (void)EcMakeKey(f->ssl);
    g_calls++;

    /* operand 1: a key object with no domain parameters */
    f->ssl->peerX25519Key = &blank;
    (void)EcMakeKey(f->ssl);
    g_calls++;

    /* the shared false partner: a real peer key, so the function allocates an
     * ephemeral key and generates it. Needs the fixture RNG. */
    if (f->rngOk && wc_curve25519_init(&peer) == 0) {
        peerInit = 1;
        if (wc_curve25519_make_key(&f->rng, CURVE25519_KEYSIZE, &peer) == 0) {
            f->ssl->peerX25519Key = &peer;
            (void)EcMakeKey(f->ssl);
            g_calls++;
            FreeKey(f->ssl, (int)f->ssl->hsType, (void**)&f->ssl->hsKey);
        }
    }

    f->ssl->peerX25519Key = NULL;
    f->ssl->peerX25519KeyPresent = 0;
    if (peerInit)
        wc_curve25519_free(&peer);
}
#endif /* HAVE_CURVE25519 */

#ifdef HAVE_ECC
static void wb_ecmakekey_ecc(WbFix* f)
{
    ecc_key blank;
    ecc_key peer;
    int     peerInit = 0;
    int     havePeer = 0;

    XMEMSET(&blank, 0, sizeof(blank));   /* never inited: dp stays NULL */

    if (f->rngOk && wc_ecc_init(&peer) == 0) {
        peerInit = 1;
        havePeer = (wc_ecc_make_key(&f->rng, 32, &peer) == 0);
    }

    /* ---- static-ECDH arm: `!peerEccDsaKey || !peerEccDsaKeyPresent` ---- */

    /* operand 0 */
    wb_reset(f);
    f->ssl->specs.kea = ecc_diffie_hellman_kea;
    f->ssl->specs.static_ecdh = 1;
    f->ssl->eccTempKeySz = 32;
    f->ssl->peerEccDsaKey = NULL;
    f->ssl->peerEccDsaKeyPresent = 1;
    (void)EcMakeKey(f->ssl);
    g_calls++;

    /* operand 1: a key object that is not marked present */
    f->ssl->peerEccDsaKey = &blank;
    f->ssl->peerEccDsaKeyPresent = 0;
    (void)EcMakeKey(f->ssl);
    g_calls++;

    /* false partner: a real fixed-ECDH peer key. EccMakeKey() sizes the
     * ephemeral key from ssl->peerEccKey, so that one is populated too. */
    if (havePeer) {
        f->ssl->peerEccDsaKey = &peer;
        f->ssl->peerEccDsaKeyPresent = 1;
        f->ssl->peerEccKey = &peer;
        f->ssl->peerEccKeyPresent = 1;
        (void)EcMakeKey(f->ssl);
        g_calls++;
        FreeKey(f->ssl, (int)f->ssl->hsType, (void**)&f->ssl->hsKey);
    }

    /* ---- ephemeral arm: `!peerEccKey || !peerEccKeyPresent || !dp` ---- */

    /* operand 0 */
    wb_reset(f);
    f->ssl->specs.kea = ecc_diffie_hellman_kea;
    f->ssl->specs.static_ecdh = 0;
    f->ssl->eccTempKeySz = 32;
    f->ssl->peerEccKey = NULL;
    f->ssl->peerEccKeyPresent = 1;
    (void)EcMakeKey(f->ssl);
    g_calls++;

    /* operand 1: present flag clear */
    f->ssl->peerEccKey = &blank;
    f->ssl->peerEccKeyPresent = 0;
    (void)EcMakeKey(f->ssl);
    g_calls++;

    /* operand 2: present, but no domain parameters on the key */
    f->ssl->peerEccKeyPresent = 1;
    (void)EcMakeKey(f->ssl);
    g_calls++;

    /* false partner for all three */
    if (havePeer) {
        f->ssl->peerEccKey = &peer;
        f->ssl->peerEccKeyPresent = 1;
        (void)EcMakeKey(f->ssl);
        g_calls++;
        FreeKey(f->ssl, (int)f->ssl->hsType, (void**)&f->ssl->hsKey);
    }

    f->ssl->peerEccKey = NULL;
    f->ssl->peerEccKeyPresent = 0;
    f->ssl->peerEccDsaKey = NULL;
    f->ssl->peerEccDsaKeyPresent = 0;
    if (peerInit)
        wc_ecc_free(&peer);
}
#endif /* HAVE_ECC */
#endif /* !NO_WOLFSSL_CLIENT && (HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448) */

/* ----------------------------------------------------------------- SetCurveId
 *
 * `if (key == NULL || key->dp == NULL)`. The caller hands it a key it has just
 * generated, so neither operand ever flips. */
#if !defined(NO_WOLFSSL_SERVER) && defined(HAVE_ECC)
static void wb_set_curve_id(WbFix* f)
{
    ecc_key blank;
    ecc_key key;
    int     keyInit = 0;

    (void)f;
    XMEMSET(&blank, 0, sizeof(blank));

    /* operand 0 */
    (void)SetCurveId(NULL);
    g_calls++;

    /* operand 1: a key with no domain parameters */
    (void)SetCurveId(&blank);
    g_calls++;

    /* false partner: a key with a curve set, which reaches GetCurveByOID */
    if (f->rngOk && wc_ecc_init(&key) == 0) {
        keyInit = 1;
        if (wc_ecc_make_key(&f->rng, 32, &key) == 0) {
            (void)SetCurveId(&key);
            g_calls++;
        }
    }
    if (keyInit)
        wc_ecc_free(&key);
}
#endif /* !NO_WOLFSSL_SERVER && HAVE_ECC */

/* --------------------------------------------------------------- RpkIsTrusted
 *
 * `if ((cfg->expectedRpkCnt > 0) && (spki != NULL) && (spkiSz > 0))`. The
 * caller has already parsed a SubjectPublicKeyInfo, so operands 1 and 2 are
 * pinned true; only the pin count ever varies. */
#if defined(HAVE_RPK) && !defined(NO_SHA256) && !defined(NO_CERTS)
static void wb_rpk_is_trusted(WbFix* f)
{
    byte spki[64];

    XMEMSET(spki, 0x5A, sizeof(spki));

    wb_reset(f);
    f->ssl->options.rpkConfig.expectedRpkCnt = 1;
    XMEMSET(f->ssl->options.rpkConfig.expectedRpk[0], 0,
            WC_SHA256_DIGEST_SIZE);

    /* operand 1: pins configured, but nothing presented */
    (void)RpkIsTrusted(f->ssl, NULL, (word32)sizeof(spki));
    g_calls++;

    /* operand 2: something presented, but of zero length */
    (void)RpkIsTrusted(f->ssl, spki, 0);
    g_calls++;

    /* the shared true partner: all three operands true, so the SPKI is
     * hashed and compared against the pin (which will not match). */
    (void)RpkIsTrusted(f->ssl, spki, (word32)sizeof(spki));
    g_calls++;
}
#endif /* HAVE_RPK && !NO_SHA256 && !NO_CERTS */

/* -------------------------------------- CopyDecodedPubKey / CopyDecodedSig
 *
 * `dCert->publicKey != NULL && dCert->pubKeySize != 0` and
 * `dCert->signature != NULL && dCert->sigLength != 0`. A certificate that
 * parsed has both, so both decisions are pinned true and neither operand can
 * be shown independent. The DecodedCert here is a driver-owned shell: only the
 * four fields these two functions read are populated. */
#if !defined(NO_CERTS) && (defined(KEEP_PEER_CERT) || defined(SESSION_CERTS) || \
    defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL))
static void wb_copy_decoded(WbFix* f)
{
    WOLFSSL_X509* x509;
    DecodedCert*  dCert;
    byte          pub[32];
    byte          sig[32];

    (void)f;

    x509 = (WOLFSSL_X509*)XMALLOC(sizeof(*x509), NULL, DYNAMIC_TYPE_X509);
    dCert = (DecodedCert*)XMALLOC(sizeof(*dCert), NULL, DYNAMIC_TYPE_DCERT);
    if (x509 == NULL || dCert == NULL) {
        XFREE(x509, NULL, DYNAMIC_TYPE_X509);
        XFREE(dCert, NULL, DYNAMIC_TYPE_DCERT);
        return;
    }
    XMEMSET(pub, 0x11, sizeof(pub));
    XMEMSET(sig, 0x22, sizeof(sig));

    /* ---- CopyDecodedPubKey ---- */

    /* operand 0 false: no public key on the decoded cert */
    XMEMSET(x509, 0, sizeof(*x509));
    XMEMSET(dCert, 0, sizeof(*dCert));
    dCert->publicKey = NULL;
    dCert->pubKeySize = sizeof(pub);
    (void)CopyDecodedPubKey(x509, dCert, 0);
    g_calls++;

    /* operand 1 false: a public key pointer of zero length */
    XMEMSET(x509, 0, sizeof(*x509));
    XMEMSET(dCert, 0, sizeof(*dCert));
    dCert->publicKey = pub;
    dCert->pubKeySize = 0;
    (void)CopyDecodedPubKey(x509, dCert, 0);
    g_calls++;

    /* the shared true partner: both present, so the key is copied into the
     * X509. The copy is the only thing this driver has to give back. */
    XMEMSET(x509, 0, sizeof(*x509));
    XMEMSET(dCert, 0, sizeof(*dCert));
    dCert->publicKey = pub;
    dCert->pubKeySize = (word32)sizeof(pub);
    dCert->keyOID = ECDSAk;
    (void)CopyDecodedPubKey(x509, dCert, 0);
    g_calls++;
    XFREE(x509->pubKey.buffer, x509->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    x509->pubKey.buffer = NULL;

    /* ---- CopyDecodedSig: only the length operand is open ---- */

    XMEMSET(x509, 0, sizeof(*x509));
    XMEMSET(dCert, 0, sizeof(*dCert));
    dCert->signature = sig;
    dCert->sigLength = 0;
    (void)CopyDecodedSig(x509, dCert);
    g_calls++;

    XMEMSET(x509, 0, sizeof(*x509));
    XMEMSET(dCert, 0, sizeof(*dCert));
    dCert->signature = sig;
    dCert->sigLength = (word32)sizeof(sig);
    dCert->signatureOID = CTC_SHA256wECDSA;
    (void)CopyDecodedSig(x509, dCert);
    g_calls++;
    XFREE(x509->sig.buffer, x509->heap, DYNAMIC_TYPE_SIGNATURE);
    x509->sig.buffer = NULL;

    XFREE(dCert, NULL, DYNAMIC_TYPE_DCERT);
    XFREE(x509, NULL, DYNAMIC_TYPE_X509);
}
#endif /* !NO_CERTS && (KEEP_PEER_CERT || SESSION_CERTS || OPENSSL_EXTRA...) */

/* ------------------------------------------------------- ProcessPeerCertParse
 *
 * `if (ssl == NULL || args == NULL || args->dCert == NULL)`. The one caller
 * owns all three, so no operand flips there. Each rejecting vector returns
 * BAD_FUNC_ARG before touching the certificate buffer.
 *
 * MC/DC's independence pair has to be demonstrated inside ONE binary's own
 * execution trace -- llvm-cov computes the covered/not-covered bit per
 * condition from a single profile, and the campaign's union is a logical OR
 * of those already-computed bits across binaries, not a merge of raw traces.
 * So an "accepting" vector recorded by the real handshake corpus can never
 * pair with a "rejecting" vector recorded by this driver; the false partner
 * has to be produced HERE. It is: a one-entry cert list carrying four
 * unparsable bytes, so ParseCertRelative() fails cleanly (ASN_PARSE_E) after
 * the guard instead of returning success -- the guard itself is all this
 * driver needs to exercise, not a real chain. */
#if !defined(NO_CERTS) && \
    (!defined(NO_WOLFSSL_CLIENT) || !defined(WOLFSSL_NO_CLIENT_AUTH))
static void wb_process_peer_cert_parse(WbFix* f)
{
    ProcPeerCertArgs args;
    DecodedCert      dCert;
    buffer           certs[1];
    byte             junk[4];
    byte*            subjectHash = NULL;
    int              alreadySigner = 0;

    wb_reset(f);
    XMEMSET(&args, 0, sizeof(args));
    XMEMSET(&dCert, 0, sizeof(dCert));
    args.dCert = &dCert;
    args.certIdx = 0;
    args.count = 0;

    /* operand 0 */
    (void)ProcessPeerCertParse(NULL, &args, CERT_TYPE, VERIFY, &subjectHash,
                               &alreadySigner);
    g_calls++;

    /* operand 1 */
    (void)ProcessPeerCertParse(f->ssl, NULL, CERT_TYPE, VERIFY, &subjectHash,
                               &alreadySigner);
    g_calls++;

#ifndef WOLFSSL_SMALL_CERT_VERIFY
    /* operand 2 -- compiled only when the decoded-cert operand is part of the
     * decision. Under WOLFSSL_SMALL_CERT_VERIFY it is not, and calling with a
     * NULL dCert would run on into the parser instead of being rejected. */
    args.dCert = NULL;
    (void)ProcessPeerCertParse(f->ssl, &args, CERT_TYPE, VERIFY, &subjectHash,
                               &alreadySigner);
    g_calls++;
    args.dCert = &dCert;
#endif

    /* the shared false partner: ssl, args and dCert all valid, so the guard
     * is false for every operand and the function runs on into the parser. */
    XMEMSET(junk, 0, sizeof(junk));
    certs[0].buffer = junk;
    certs[0].length = (word32)sizeof(junk);
    XMEMSET(&dCert, 0, sizeof(dCert));
    args.dCert = &dCert;
    args.dCertInit = 0;
    args.certs = certs;
    args.count = 1;
    args.certIdx = 0;
    (void)ProcessPeerCertParse(f->ssl, &args, CERT_TYPE, VERIFY, &subjectHash,
                               &alreadySigner);
    g_calls++;
    if (args.dCertInit)
        FreeDecodedCert(args.dCert);
}
#endif /* !NO_CERTS && (!NO_WOLFSSL_CLIENT || !WOLFSSL_NO_CLIENT_AUTH) */

/* --------------------------------------------------------------- ProcessCSR_ex
 *
 * `if (csr && !csr->ssl)`. The status-request extension is created with a NULL
 * back-pointer and filled in here on the first pass, so by the time any test
 * observes it the operand is pinned. All three vectors leave through the
 * BUFFER_ERROR exit below (neither status_request nor status_request_v2 is
 * set), so nothing is decoded and nothing is allocated. */
#if !defined(NO_CERTS) && defined(HAVE_CERTIFICATE_STATUS_REQUEST) && \
    !defined(WOLFSSL_NO_TLS12) && \
    (!defined(NO_WOLFSSL_CLIENT) || !defined(WOLFSSL_NO_CLIENT_AUTH))
static void wb_process_csr(WbFix* f)
{
    TLSX                      ext;
    CertificateStatusRequest* csr;
    byte                      input[32];
    word32                    idx;

    csr = (CertificateStatusRequest*)XMALLOC(sizeof(*csr), NULL,
                                             DYNAMIC_TYPE_TLSX);
    if (csr == NULL)
        return;
    XMEMSET(input, 0, sizeof(input));

    wb_reset(f);
    XMEMSET(&ext, 0, sizeof(ext));
    ext.type = TLSX_STATUS_REQUEST;
    ext.next = NULL;
    f->ssl->extensions = &ext;
    f->ssl->status_request = 0;
#ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2
    f->ssl->status_request_v2 = 0;
#endif

    /* operand 0 false: the extension carries no request object */
    ext.data = NULL;
    idx = 0;
    (void)ProcessCSR_ex(f->ssl, input, &idx, 0, 0);
    g_calls++;

    /* operands 0 and 1 true: a request whose back-pointer is not yet set */
    XMEMSET(csr, 0, sizeof(*csr));
    csr->ssl = NULL;
    ext.data = csr;
    idx = 0;
    (void)ProcessCSR_ex(f->ssl, input, &idx, 0, 0);
    g_calls++;

    /* operand 1 false: the back-pointer is already set */
    csr->ssl = f->ssl;
    idx = 0;
    (void)ProcessCSR_ex(f->ssl, input, &idx, 0, 0);
    g_calls++;

    f->ssl->extensions = NULL;
    XFREE(csr, NULL, DYNAMIC_TYPE_TLSX);
}
#endif /* !NO_CERTS && HAVE_CERTIFICATE_STATUS_REQUEST && !WOLFSSL_NO_TLS12 */

/* ---------------------------------------------------------------------- main */

int main(void)
{
    WbFix f;

    XMEMSET(&f, 0, sizeof(f));

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        printf("internal peer-key white-box: wolfSSL_Init failed\n");
        return 0;
    }

    f.ssl = (WOLFSSL*)XMALLOC(sizeof(WOLFSSL), NULL, DYNAMIC_TYPE_SSL);
    f.ctx = (WOLFSSL_CTX*)XMALLOC(sizeof(WOLFSSL_CTX), NULL, DYNAMIC_TYPE_CTX);
    f.cm  = (WOLFSSL_CERT_MANAGER*)XMALLOC(sizeof(WOLFSSL_CERT_MANAGER), NULL,
                                           DYNAMIC_TYPE_CERT_MANAGER);
    if (f.ssl == NULL || f.ctx == NULL || f.cm == NULL) {
        printf("internal peer-key white-box: out of memory\n");
        goto done;
    }

    /* A real RNG: the all-valid partner for the EcMakeKey guards has to
     * generate an ephemeral key, and there is no other way to reach the
     * false side of those decisions from inside this TU. */
    f.rngOk = (wc_InitRng(&f.rng) == 0);
    if (!f.rngOk)
        printf("internal peer-key white-box: no RNG, key-gen partners skipped\n");

#if !defined(NO_WOLFSSL_CLIENT) && \
    (defined(HAVE_ECC) || defined(HAVE_CURVE25519) || defined(HAVE_CURVE448))
#ifdef HAVE_CURVE25519
    wb_ecmakekey_x25519(&f);
#endif
#ifdef HAVE_ECC
    wb_ecmakekey_ecc(&f);
#endif
#endif
#if !defined(NO_WOLFSSL_SERVER) && defined(HAVE_ECC)
    wb_set_curve_id(&f);
#endif
#if defined(HAVE_RPK) && !defined(NO_SHA256) && !defined(NO_CERTS)
    wb_rpk_is_trusted(&f);
#endif
#if !defined(NO_CERTS) && (defined(KEEP_PEER_CERT) || defined(SESSION_CERTS) || \
    defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL))
    wb_copy_decoded(&f);
#endif
#if !defined(NO_CERTS) && \
    (!defined(NO_WOLFSSL_CLIENT) || !defined(WOLFSSL_NO_CLIENT_AUTH))
    wb_process_peer_cert_parse(&f);
#endif
#if !defined(NO_CERTS) && defined(HAVE_CERTIFICATE_STATUS_REQUEST) && \
    !defined(WOLFSSL_NO_TLS12) && \
    (!defined(NO_WOLFSSL_CLIENT) || !defined(WOLFSSL_NO_CLIENT_AUTH))
    wb_process_csr(&f);
#endif

    printf("internal peer-key white-box: %d static-guard calls\n", g_calls);

    if (f.rngOk)
        wc_FreeRng(&f.rng);

done:
    XFREE(f.cm, NULL, DYNAMIC_TYPE_CERT_MANAGER);
    XFREE(f.ctx, NULL, DYNAMIC_TYPE_CTX);
    XFREE(f.ssl, NULL, DYNAMIC_TYPE_SSL);
    wolfSSL_Cleanup();
    return 0;   /* always 0: a non-zero exit discards the variant */
}

#else

int main(void)
{
    printf("internal peer-key white-box: skipped (TLS 1.2 not built)\n");
    return 0;
}

#endif
