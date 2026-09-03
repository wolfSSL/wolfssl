/* test_internal_nullguard_whitebox.c -- MC/DC white-box driver for the
 * file-static NULL guards in src/internal.c
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

/* WHY A WHITE-BOX, AND WHY THESE FUNCTIONS.
 *
 * Every decision closed here is a defensive NULL/emptiness guard at the head
 * of a FILE-STATIC function. Two facts make them unreachable from tests/api:
 *
 *   1. The function has internal linkage, so no test can call it with a
 *      crafted argument; the only entry is through its one caller.
 *   2. That caller never passes NULL. The guard exists for a future caller,
 *      for a partially-constructed WOLFSSL, or for an out-of-memory path -- so
 *      on every call the API can produce, the decision is taken false and the
 *      operand never changes value. MC/DC needs the operand to flip AND the
 *      outcome to follow; reaching the line is not the same as pairing it, and
 *      running more handshakes only produces more of the same vector.
 *
 * SHORT-CIRCUIT IS THE WHOLE GAME. For `if (a == NULL || b == NULL)` a NULL in
 * slot a pairs ONLY operand a -- b is never evaluated. So each uncovered
 * operand gets its OWN call, with every other argument valid, and one
 * all-valid call serves as the shared false partner for all of them.
 *
 * THE FIXTURE. A zeroed WOLFSSL from XMALLOC, plus a zeroed WOLFSSL_CTX and a
 * zeroed WOLFSSL_CERT_MANAGER that the driver owns outright. The fake CTX is
 * the point: several of these guards test ssl->ctx->cm and ssl->ctx->cm->
 * ocsp_stapling, which on a real CTX are non-NULL and cannot be made NULL
 * without corrupting a live object. Owning the CTX means the guard's operands
 * are ordinary driver variables. Nothing here is constructed with wolfSSL_new
 * -- it returns NULL for a server CTX with no certificate, which is what
 * silently turned an earlier white-box in this campaign into a no-op that
 * still exited 0.
 *
 * Rules, as for the sibling drivers:
 *   - options.h FIRST, or the smoke build compiles this with the feature
 *     macros undefined and it silently becomes a no-op that still exits 0.
 *   - main() ALWAYS returns 0; a non-zero exit discards the whole variant.
 *   - Each target is wrapped in the SAME preprocessor guard that encloses it
 *     in internal.c, so this TU tracks the file across configurations instead
 *     of failing to link under a narrower one.
 */

#include <wolfssl/options.h>

#include <src/internal.c>

#include <stdio.h>
#include <string.h>

#if !defined(WOLFCRYPT_ONLY) && !defined(NO_TLS) && !defined(WOLFSSL_NO_TLS12)

static int g_calls;

/* The driver-owned object graph. Everything is zeroed and none of it is
 * constructed, so any field a guard reads is a plain driver variable. */
typedef struct WbFix {
    WOLFSSL*              ssl;
    WOLFSSL_CTX*          ctx;
    WOLFSSL_CERT_MANAGER* cm;
    WOLFSSL_SESSION*      session;
    Arrays*               arrays;
    Suites*               suites;
} WbFix;

/* Put the WOLFSSL back to "zeroed, attached to the fake CTX". Called before
 * every target so one target's leftovers cannot mask another's operand. */
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
}

/* ------------------------------------------------- SupportedHashSigAlgo
 *
 * `if (ssl == NULL || hashSigAlgo == NULL)` and, after WOLFSSL_SUITES(ssl),
 * `if (suites == NULL || suites->hashSigAlgoSz == 0)`. Four operands, four
 * one-at-a-time vectors plus the all-valid partner that walks the table.
 * WOLFSSL_SUITES() falls back to ssl->ctx->suites, which is why the fake CTX
 * matters: only an owned CTX can present a NULL suites pointer. */
#if !defined(NO_TLS) && (!defined(NO_WOLFSSL_SERVER) || !defined(NO_CERTS))
static void wb_supported_hash_sig_algo(WbFix* f)
{
    static const byte kAlgo[HELLO_EXT_SIGALGO_SZ] = { sha256_mac, rsa_sa_algo };

    wb_reset(f);

    /* operand 0 of the argument guard: ssl NULL, second argument valid */
    (void)SupportedHashSigAlgo(NULL, kAlgo);
    g_calls++;

    /* operand 1: ssl valid, hashSigAlgo NULL */
    (void)SupportedHashSigAlgo(f->ssl, NULL);
    g_calls++;

    /* operand 0 of the suites guard: both arguments valid, no suites object
     * anywhere -- ssl->suites NULL and the owned ctx->suites NULL too. */
    f->ssl->suites = NULL;
    f->ctx->suites = NULL;
    (void)SupportedHashSigAlgo(f->ssl, kAlgo);
    g_calls++;

    /* operand 1 of the suites guard: a suites object that is present but
     * carries no sig algos. */
    XMEMSET(f->suites, 0, sizeof(*f->suites));
    f->ssl->suites = f->suites;
    f->suites->hashSigAlgoSz = 0;
    (void)SupportedHashSigAlgo(f->ssl, kAlgo);
    g_calls++;

    /* the shared false partner: a populated table that matches on the first
     * entry, so both guards are false and the function returns 1. */
    f->suites->hashSigAlgoSz = HELLO_EXT_SIGALGO_SZ;
    XMEMCPY(f->suites->hashSigAlgo, kAlgo, HELLO_EXT_SIGALGO_SZ);
    (void)SupportedHashSigAlgo(f->ssl, kAlgo);
    g_calls++;

    f->ssl->suites = NULL;
}
#endif /* !NO_TLS && (!NO_WOLFSSL_SERVER || !NO_CERTS) */

/* ---------------------------------------------------------- GetCtxOcspLock
 *
 * `if (ssl->ctx->cm == NULL || ssl->ctx->cm->ocsp_stapling == NULL)`. On a
 * real CTX both are non-NULL for the whole life of the object, so neither
 * operand can flip from the API. Both are fields of driver-owned structs
 * here. */
#if (defined(HAVE_CERTIFICATE_STATUS_REQUEST) || \
     defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)) && !defined(WOLFSSL_NO_TLS12)
#ifndef NO_WOLFSSL_SERVER
static void wb_get_ctx_ocsp_lock(WbFix* f)
{
    WOLFSSL_OCSP* ocsp;

    ocsp = (WOLFSSL_OCSP*)XMALLOC(sizeof(*ocsp), NULL, DYNAMIC_TYPE_OCSP);
    if (ocsp == NULL)
        return;
    XMEMSET(ocsp, 0, sizeof(*ocsp));

    /* operand 0: no cert manager on the CTX at all */
    wb_reset(f);
    f->ctx->cm = NULL;
    (void)GetCtxOcspLock(f->ssl);
    g_calls++;

    /* operand 1: a cert manager, but no stapling responder on it */
    wb_reset(f);
    f->cm->ocsp_stapling = NULL;
    (void)GetCtxOcspLock(f->ssl);
    g_calls++;

    /* false partner: both present, the lock address is returned */
    f->cm->ocsp_stapling = ocsp;
    (void)GetCtxOcspLock(f->ssl);
    g_calls++;

    f->cm->ocsp_stapling = NULL;
    XFREE(ocsp, NULL, DYNAMIC_TYPE_OCSP);
}

/* --------------------------------- BuildCertificateStatusWithStatusCB
 *
 * `if (ocsp == NULL || ocsp->statusCb == NULL)` where ocsp is
 * SSL_CM(ssl)->ocsp_stapling. The false partner is safe to run because the
 * callback is ours: returning NOACK makes the function return 0 without
 * building a record. */
static int wb_status_cb(WOLFSSL* ssl, void* arg)
{
    (void)ssl;
    (void)arg;
    return WOLFSSL_OCSP_STATUS_CB_NOACK;
}

static void wb_build_cert_status_cb(WbFix* f)
{
    WOLFSSL_OCSP* ocsp;

    ocsp = (WOLFSSL_OCSP*)XMALLOC(sizeof(*ocsp), NULL, DYNAMIC_TYPE_OCSP);
    if (ocsp == NULL)
        return;
    XMEMSET(ocsp, 0, sizeof(*ocsp));

    /* operand 0: the CM has no stapling responder */
    wb_reset(f);
    f->cm->ocsp_stapling = NULL;
    (void)BuildCertificateStatusWithStatusCB(f->ssl, WOLFSSL_CSR2_OCSP);
    g_calls++;

    /* operand 1: a responder with no status callback registered */
    ocsp->statusCb = NULL;
    f->cm->ocsp_stapling = ocsp;
    (void)BuildCertificateStatusWithStatusCB(f->ssl, WOLFSSL_CSR2_OCSP);
    g_calls++;

    /* false partner: a callback that declines, so nothing is built */
    ocsp->statusCb = wb_status_cb;
    (void)BuildCertificateStatusWithStatusCB(f->ssl, WOLFSSL_CSR2_OCSP);
    g_calls++;

    f->cm->ocsp_stapling = NULL;
    XFREE(ocsp, NULL, DYNAMIC_TYPE_OCSP);
}
#endif /* !NO_WOLFSSL_SERVER */
#endif /* (HAVE_CERTIFICATE_STATUS_REQUEST || ..._V2) && !WOLFSSL_NO_TLS12 */

/* ------------------------------------------ InvalidateSessionOnFatalAlert
 *
 * `if (ssl == NULL || ssl->ctx == NULL || ssl->session == NULL)`. The caller
 * in DoAlert always has all three, so operands 0 and 2 never flip. The false
 * partner stops at the next guard (handshake not done, not resuming), so no
 * session is actually evicted and the fake CTX is never handed to the cache. */
#ifndef NO_SESSION_CACHE
static void wb_invalidate_session(WbFix* f)
{
    /* operand 0 */
    InvalidateSessionOnFatalAlert(NULL);
    g_calls++;

    /* operand 2: ssl and ctx present, no session attached */
    wb_reset(f);
    f->ssl->session = NULL;
    InvalidateSessionOnFatalAlert(f->ssl);
    g_calls++;

    /* false partner: all three present. handShakeDone and resuming are both
     * clear, so the function returns at the very next guard and the session
     * object is only ever compared against NULL. */
    XMEMSET(f->session, 0, sizeof(*f->session));
    f->ssl->session = f->session;
    InvalidateSessionOnFatalAlert(f->ssl);
    g_calls++;

    f->ssl->session = NULL;
}
#endif /* !NO_SESSION_CACHE */

/* ------------------------------------------------------- dtlsRecordIsNewest
 *
 * `if (e == NULL || !w64Equal(ssl->keys.curEpoch64, e->epochNumber))` on the
 * DTLS 1.3 path. A live connection always has a decrypt epoch installed whose
 * number matches the current one, so both operands sit at false. All three
 * vectors below stop inside the function: with a zeroed epoch table
 * Dtls13GetEpoch() finds nothing and the function returns 0. */
#if defined(WOLFSSL_DTLS) && defined(WOLFSSL_DTLS_CID) && \
    defined(WOLFSSL_DTLS13)
static void wb_dtls_record_is_newest(WbFix* f)
{
    Dtls13Epoch epoch;

    /* DTLS 1.3, and curEpoch64 == dtls13PeerEpoch (both zero) so the first
     * guard falls through to the one under test. */
    wb_reset(f);
    f->ssl->options.dtls = 1;
    f->ssl->version.major = DTLS_MAJOR;
    f->ssl->version.minor = DTLSv1_3_MINOR;
    w64Zero(&f->ssl->keys.curEpoch64);
    w64Zero(&f->ssl->dtls13PeerEpoch);

    /* operand 0: no decrypt epoch installed */
    f->ssl->dtls13DecryptEpoch = NULL;
    (void)dtlsRecordIsNewest(f->ssl);
    g_calls++;

    /* operand 1: an epoch is installed but it is not the current one */
    XMEMSET(&epoch, 0, sizeof(epoch));
    epoch.epochNumber = w64From32(0, 1);
    f->ssl->dtls13DecryptEpoch = &epoch;
    (void)dtlsRecordIsNewest(f->ssl);
    g_calls++;

    /* false partner: the installed epoch IS the current one */
    epoch.epochNumber = w64From32(0, 0);
    epoch.nextPeerSeqNumber = w64From32(0, 0);
    (void)dtlsRecordIsNewest(f->ssl);
    g_calls++;

    f->ssl->dtls13DecryptEpoch = NULL;
}
#endif /* WOLFSSL_DTLS && WOLFSSL_DTLS_CID && WOLFSSL_DTLS13 */

/* ---------------------------------------------- FreeCachedHandshakeMessages
 *
 * `if ((ssl->hsHashes != NULL) && (ssl->hsHashes->messages != NULL))`. The
 * caller only reaches this after a handshake hash object exists, so operand 0
 * is pinned true. The vector with no hashes at all supplies its pair. */
#if !defined(WOLFSSL_NO_CLIENT_AUTH) && \
           ((defined(WOLFSSL_SM2) && defined(WOLFSSL_SM3)) || \
            (defined(HAVE_ED25519) && !defined(NO_ED25519_CLIENT_AUTH)) || \
            (defined(HAVE_ED448) && !defined(NO_ED448_CLIENT_AUTH)))
static void wb_free_cached_handshake_messages(WbFix* f)
{
    HS_Hashes hashes;
    byte*     msgs;

    /* operand 0 false: no handshake hash object */
    wb_reset(f);
    f->ssl->hsHashes = NULL;
    FreeCachedHandshakeMessages(f->ssl, 0);
    g_calls++;

    /* operand 0 true, decision true: a hash object holding a cached message
     * buffer, which the function zeroes and frees. */
    msgs = (byte*)XMALLOC(32, NULL, DYNAMIC_TYPE_HASHES);
    if (msgs == NULL)
        return;
    XMEMSET(msgs, 0xA5, 32);
    XMEMSET(&hashes, 0, sizeof(hashes));
    hashes.messages = msgs;
    hashes.length = 32;
    f->ssl->hsHashes = &hashes;
    FreeCachedHandshakeMessages(f->ssl, 0);
    g_calls++;

    /* the function nulls hashes.messages after freeing it; nothing to clean */
    f->ssl->hsHashes = NULL;
}
#endif

/* ----------------------------------------------------------- ParseCipherList
 *
 * `if (suites == NULL || list == NULL)`. Both callers (SetCipherList_ex and
 * friends) validate before calling, so neither operand flips. */
static void wb_parse_cipher_list(WbFix* f)
{
    ProtocolVersion pv;

    pv.major = SSLv3_MAJOR;
    pv.minor = TLSv1_2_MINOR;

    /* operand 0 */
    (void)ParseCipherList(NULL, "DEFAULT", pv, 0, WOLFSSL_CLIENT_END);
    g_calls++;

    /* operand 1 */
    XMEMSET(f->suites, 0, sizeof(*f->suites));
    (void)ParseCipherList(f->suites, NULL, pv, 0, WOLFSSL_CLIENT_END);
    g_calls++;

    /* false partner: "DEFAULT" takes the wolfSSL-default early return, which
     * fills the caller-owned Suites and returns 1 without parsing a list. */
    (void)ParseCipherList(f->suites, "DEFAULT", pv, 0, WOLFSSL_CLIENT_END);
    g_calls++;
}

/* ---------------------------------------------------------- SendHandshakeMsg
 *
 * `if (ssl == NULL || input == NULL)`. Both operands are pinned false by every
 * caller. The false partner has to be produced HERE, in this same binary: the
 * MC/DC union is taken per condition across variants, not per vector, so a
 * rejecting call in this driver and an accepting call in unit.test never form
 * a pair. It is produced without transmitting anything -- buildingMsg is set
 * so the pre-loop hash is skipped, and fragOffset is already at the end of the
 * input so the fragment loop body never runs. The function falls straight
 * through to its epilogue and returns 0. */
static void wb_send_handshake_msg(WbFix* f)
{
    byte input[64];

    XMEMSET(input, 0, sizeof(input));

    /* operand 0 */
    (void)SendHandshakeMsg(NULL, input, (word32)sizeof(input), client_hello,
                           "white-box");
    g_calls++;

    /* operand 1 */
    wb_reset(f);
    (void)SendHandshakeMsg(f->ssl, NULL, 0, client_hello, "white-box");
    g_calls++;

    /* the false partner: valid ssl, valid input, nothing left to fragment */
    wb_reset(f);
    f->ssl->options.buildingMsg = 1;
    f->ssl->fragOffset = (word32)sizeof(input);
    (void)SendHandshakeMsg(f->ssl, input, (word32)sizeof(input), client_hello,
                           "white-box");
    g_calls++;
}

/* -------------------------------------------------------- DecodePrivateKey_ex
 *
 * `if (key == NULL || key->buffer == NULL)`. The caller passes ssl->buffers.key
 * which is validated long before, so the guard only fires for a connection
 * with no private key -- a state the API refuses to build. Both rejecting
 * vectors take the "private key missing" exit.
 *
 * The false partner has to be produced by THIS binary: llvm-cov computes the
 * covered bit per condition from one profile, and the campaign's union is a
 * logical OR of those bits across binaries, not a merge of raw traces, so an
 * accepting call recorded by the real handshake corpus can never pair with a
 * rejecting call recorded here. It is supplied by a DerBuffer that is present
 * but holds unparsable bytes and a keyType restricted to RSA, so
 * DecodePrivateKey_ex takes exactly one decode attempt (wc_RsaPrivateKeyDecode
 * on garbage, which fails cleanly) and returns without allocating anything
 * that survives -- every algorithm block after the RSA one unconditionally
 * frees whatever AllocKey produced before checking whether keyType selects it,
 * so hsKey is back to freed/NULL by the time the function returns. */
#if !defined(NO_CERTS)
static void wb_decode_private_key(WbFix* f)
{
    DerBuffer der;
    byte      junk[4];
    word32    hsType = 0;
    void*     hsKey = NULL;
    word32    sigLen = 0;

    /* operand 0: no DerBuffer at all */
    wb_reset(f);
    (void)DecodePrivateKey_ex(f->ssl, rsa_sa_algo, NULL, &hsType, &hsKey,
                              INVALID_DEVID, 0, 0, 0, &sigLen);
    g_calls++;

    /* operand 1: a DerBuffer that carries no bytes */
    XMEMSET(&der, 0, sizeof(der));
    der.buffer = NULL;
    der.length = 0;
    (void)DecodePrivateKey_ex(f->ssl, rsa_sa_algo, &der, &hsType, &hsKey,
                              INVALID_DEVID, 0, 0, 0, &sigLen);
    g_calls++;

#ifndef NO_RSA
    /* the shared false partner: a DerBuffer that is present and non-empty,
     * so both operands are false and the function proceeds to decode. */
    XMEMSET(junk, 0, sizeof(junk));
    der.buffer = junk;
    der.length = (word32)sizeof(junk);
    hsType = 0;
    hsKey = NULL;
    sigLen = 0;
    (void)DecodePrivateKey_ex(f->ssl, rsa_sa_algo, &der, &hsType, &hsKey,
                              INVALID_DEVID, 0, 0, 0, &sigLen);
    g_calls++;
    if (hsKey != NULL)
        FreeKey(f->ssl, (int)hsType, &hsKey);
#endif
}
#endif /* !NO_CERTS */

/* ------------------------------------------------------------ GetRealSessionID
 *
 * `else if (!IsAtLeastTLSv1_3(ssl->version) && ssl->arrays != NULL)`. A
 * TLS 1.2 server holding a ticket always has ssl->arrays, so operand 1 never
 * flips; the vector without arrays falls through to the session's own ID. */
#if !defined(NO_WOLFSSL_SERVER) && defined(HAVE_SESSION_TICKET) && \
    defined(WOLFSSL_TICKET_HAVE_ID)
static void wb_get_real_session_id(WbFix* f)
{
    const byte* id = NULL;
    byte        idSz = 0;

    /* TLS 1.2 and no alternate session ID, so the else-if is the decision
     * actually evaluated. */
    wb_reset(f);
    XMEMSET(f->session, 0, sizeof(*f->session));
    f->ssl->session = f->session;
    f->session->haveAltSessionID = 0;

    /* operand 1 false: no arrays, the session's own ID is used */
    f->ssl->arrays = NULL;
    GetRealSessionID(f->ssl, &id, &idSz);
    g_calls++;

    /* operand 1 true: arrays present, its session ID is used */
    XMEMSET(f->arrays, 0, sizeof(*f->arrays));
    f->arrays->sessionIDSz = ID_LEN;
    f->ssl->arrays = f->arrays;
    GetRealSessionID(f->ssl, &id, &idSz);
    g_calls++;

    f->ssl->arrays = NULL;
    f->ssl->session = NULL;
    (void)id;
    (void)idSz;
}
#endif /* !NO_WOLFSSL_SERVER && HAVE_SESSION_TICKET && WOLFSSL_TICKET_HAVE_ID */

/* ---------------------------------------------------------------------- main */

int main(void)
{
    WbFix f;

    XMEMSET(&f, 0, sizeof(f));

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        printf("internal null-guard white-box: wolfSSL_Init failed\n");
        return 0;
    }

    f.ssl     = (WOLFSSL*)XMALLOC(sizeof(WOLFSSL), NULL, DYNAMIC_TYPE_SSL);
    f.ctx     = (WOLFSSL_CTX*)XMALLOC(sizeof(WOLFSSL_CTX), NULL,
                                      DYNAMIC_TYPE_CTX);
    f.cm      = (WOLFSSL_CERT_MANAGER*)XMALLOC(sizeof(WOLFSSL_CERT_MANAGER),
                                      NULL, DYNAMIC_TYPE_CERT_MANAGER);
    f.session = (WOLFSSL_SESSION*)XMALLOC(sizeof(WOLFSSL_SESSION), NULL,
                                      DYNAMIC_TYPE_SESSION);
    f.arrays  = (Arrays*)XMALLOC(sizeof(Arrays), NULL, DYNAMIC_TYPE_ARRAYS);
    f.suites  = (Suites*)XMALLOC(sizeof(Suites), NULL, DYNAMIC_TYPE_SUITES);

    if (f.ssl == NULL || f.ctx == NULL || f.cm == NULL || f.session == NULL ||
            f.arrays == NULL || f.suites == NULL) {
        printf("internal null-guard white-box: out of memory\n");
        goto done;
    }

#if !defined(NO_TLS) && (!defined(NO_WOLFSSL_SERVER) || !defined(NO_CERTS))
    wb_supported_hash_sig_algo(&f);
#endif
#if (defined(HAVE_CERTIFICATE_STATUS_REQUEST) || \
     defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)) && !defined(WOLFSSL_NO_TLS12)
#ifndef NO_WOLFSSL_SERVER
    wb_get_ctx_ocsp_lock(&f);
    wb_build_cert_status_cb(&f);
#endif
#endif
#ifndef NO_SESSION_CACHE
    wb_invalidate_session(&f);
#endif
#if defined(WOLFSSL_DTLS) && defined(WOLFSSL_DTLS_CID) && \
    defined(WOLFSSL_DTLS13)
    wb_dtls_record_is_newest(&f);
#endif
#if !defined(WOLFSSL_NO_CLIENT_AUTH) && \
           ((defined(WOLFSSL_SM2) && defined(WOLFSSL_SM3)) || \
            (defined(HAVE_ED25519) && !defined(NO_ED25519_CLIENT_AUTH)) || \
            (defined(HAVE_ED448) && !defined(NO_ED448_CLIENT_AUTH)))
    wb_free_cached_handshake_messages(&f);
#endif
    wb_parse_cipher_list(&f);
    wb_send_handshake_msg(&f);
#if !defined(NO_CERTS)
    wb_decode_private_key(&f);
#endif
#if !defined(NO_WOLFSSL_SERVER) && defined(HAVE_SESSION_TICKET) && \
    defined(WOLFSSL_TICKET_HAVE_ID)
    wb_get_real_session_id(&f);
#endif

    printf("internal null-guard white-box: %d static-guard calls\n", g_calls);

done:
    /* XFREE, not the wolfSSL_*_free family: nothing here was constructed. */
    XFREE(f.suites, NULL, DYNAMIC_TYPE_SUITES);
    XFREE(f.arrays, NULL, DYNAMIC_TYPE_ARRAYS);
    XFREE(f.session, NULL, DYNAMIC_TYPE_SESSION);
    XFREE(f.cm, NULL, DYNAMIC_TYPE_CERT_MANAGER);
    XFREE(f.ctx, NULL, DYNAMIC_TYPE_CTX);
    XFREE(f.ssl, NULL, DYNAMIC_TYPE_SSL);
    wolfSSL_Cleanup();
    return 0;   /* always 0: a non-zero exit discards the variant */
}

#else

int main(void)
{
    printf("internal null-guard white-box: skipped (TLS 1.2 not built)\n");
    return 0;
}

#endif
