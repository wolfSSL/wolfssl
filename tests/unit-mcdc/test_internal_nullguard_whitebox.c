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
 *   - Each target is wrapped in the SAME preprocessor guard that encloses it
 *     in internal.c, so this TU tracks the file across configurations instead
 *     of failing to link under a narrower one.
 */

#include <wolfssl/options.h>

#include <src/internal.c>
#include "mcdc_fault_alloc.h"

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

/* Protocol classifiers also see legacy version numbers supplied by callers. */
static int wb_protocol_classifiers(WbFix* f)
{
    int failed = 0;

    wb_reset(f);
    if (!IsTLS(f->ssl) || !IsTLS_ex(f->ssl->version) ||
            !IsAtLeastTLSv1_2(f->ssl))
        failed = 1;
    f->ssl->version.minor = SSLv3_MINOR;
    if (IsTLS(f->ssl) || IsTLS_ex(f->ssl->version) ||
            IsAtLeastTLSv1_2(f->ssl))
        failed = 1;
#ifdef WOLFSSL_DTLS
    f->ssl->version.major = DTLS_MAJOR;
    f->ssl->version.minor = DTLS_MINOR;
    if (!IsTLS(f->ssl) || !IsTLS_ex(f->ssl->version) ||
            IsAtLeastTLSv1_2(f->ssl))
        failed = 1;
    f->ssl->version.minor = DTLSv1_2_MINOR;
    if (!IsAtLeastTLSv1_2(f->ssl))
        failed = 1;
#endif
    wb_reset(f);
    return failed;
}

/* A finished fatal-alert path must never report a retriable error. */
static int wb_fatal_alert_errors(WbFix* f)
{
    static const int retryErrors[] = {
        0, WANT_READ, WANT_WRITE, WOLFSSL_ERROR_WANT_READ,
        WOLFSSL_ERROR_WANT_WRITE, ZERO_RETURN
    };
    size_t i;
    int failed = 0;

    wb_reset(f);
    f->ssl->error = WANT_READ;
    if (HandshakeEndedByFatalAlert(f->ssl) != 0 || f->ssl->error != WANT_READ)
        failed = 1;

    f->ssl->options.fatalAlert = 1;
    for (i = 0; i < XELEM_CNT(retryErrors); i++) {
        f->ssl->error = retryErrors[i];
        if (HandshakeEndedByFatalAlert(f->ssl) != 1 ||
                f->ssl->error != SOCKET_PEER_CLOSED_E)
            failed = 1;
    }
    f->ssl->error = SOCKET_ERROR_E;
    if (HandshakeEndedByFatalAlert(f->ssl) != 1 ||
            f->ssl->error != SOCKET_ERROR_E)
        failed = 1;
    wb_reset(f);
    return failed;
}

#if !defined(NO_RSA) && defined(WC_RSA_PSS) && !defined(NO_SHA256) && \
    !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
static int wb_rsa_pss_scheme_encoding(void)
{
    byte encoded[4] = {0};
    byte hash = 0;
    byte sig = 0;
    word16 len = 0;

    AddSuiteHashSigAlgo(encoded, sha_mac, rsa_pss_pss_algo, 0, &len);
    AddSuiteHashSigAlgo(encoded, sha512_mac + 1, rsa_pss_pss_algo, 0, &len);
    if (len != 0)
        return 1;
    AddSuiteHashSigAlgo(encoded, sha256_mac, rsa_pss_pss_algo, 0, &len);
    if (len != 2 || encoded[0] != rsa_pss_sa_algo ||
            encoded[1] != pss_sha256)
        return 1;
    DecodeSigAlg(encoded, &hash, &sig);
    if (hash != sha256_mac || sig != rsa_pss_pss_algo)
        return 1;

    /* Decode an assigned later scheme when its optional support is absent. */
#ifndef HAVE_ECC_BRAINPOOL
    encoded[1] = ECDSA_BRAINPOOLP256R1TLS13_SHA256_MINOR;
    DecodeSigAlg(encoded, &hash, &sig);
    if (sig == rsa_pss_pss_algo)
        return 1;
#endif
    return 0;
}

static int wb_rsa_pss_constraints(WbFix* f)
{
    static const struct {
        byte hash;
        byte mgf;
        word16 saltLen;
        int result;
    } cases[] = {
        {0, 0, 0, 0},
        {WC_HASH_TYPE_SHA256, WC_MGF1SHA256, WC_SHA256_DIGEST_SIZE, 0},
        {WC_HASH_TYPE_SHA384, WC_MGF1SHA256, 0, INVALID_PARAMETER},
        {WC_HASH_TYPE_SHA256, WC_MGF1SHA384, 0, INVALID_PARAMETER},
        {WC_HASH_TYPE_SHA256, WC_MGF1SHA256, WC_SHA256_DIGEST_SIZE + 1,
            INVALID_PARAMETER},
    };
    size_t i;
    int failed = 0;

    wb_reset(f);
    f->ssl->peerRsaPss = 1;
    for (i = 0; i < XELEM_CNT(cases); i++) {
        f->ssl->peerRsaPssHash = cases[i].hash;
        f->ssl->peerRsaPssMgf = cases[i].mgf;
        f->ssl->peerRsaPssSaltLen = cases[i].saltLen;
        if (CheckPeerRsaSigAlgo(f->ssl, rsa_pss_pss_algo, sha256_mac) !=
                cases[i].result)
            failed = 1;
    }
    wb_reset(f);
    return failed;
}
#endif

#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
static int wb_handshake_hash_copy(WbFix* f)
{
    static const byte record[RECORD_HEADER_SZ + 1] = {0};
    HS_Hashes* copy = NULL;
    int failed = 0;

    wb_reset(f);
    if (HashOutput(f->ssl, record, sizeof(record), 0) != BAD_FUNC_ARG)
        failed = 1;
    if (InitHandshakeHashes(f->ssl) != 0)
        return 1;
    if (HashOutput(f->ssl, NULL, sizeof(record), 0) != BAD_FUNC_ARG)
        failed = 1;
    if (HashOutput(f->ssl, record, sizeof(record), 0) != 0)
        failed = 1;

    if (InitHandshakeHashesAndCopy(NULL, f->ssl->hsHashes, &copy) !=
            BAD_FUNC_ARG)
        failed = 1;
    if (InitHandshakeHashesAndCopy(f->ssl, NULL, &copy) != BAD_FUNC_ARG)
        failed = 1;
    if (InitHandshakeHashesAndCopy(f->ssl, f->ssl->hsHashes, NULL) !=
            BAD_FUNC_ARG)
        failed = 1;
    if (InitHandshakeHashesAndCopy(f->ssl, f->ssl->hsHashes, &copy) != 0 ||
            copy == NULL || copy == f->ssl->hsHashes)
        failed = 1;
#if !defined(WOLFSSL_NO_CLIENT_AUTH) && \
    ((defined(WOLFSSL_SM2) && defined(WOLFSSL_SM3)) || \
     (defined(HAVE_ED25519) && !defined(NO_ED25519_CLIENT_AUTH)) || \
     (defined(HAVE_ED448) && !defined(NO_ED448_CLIENT_AUTH)))
    f->ssl->options.cacheMessages = 1;
    if (HashOutput(f->ssl, record, sizeof(record), 0) != 0 ||
            InitHandshakeHashesAndCopy(f->ssl, f->ssl->hsHashes, &copy) != 0 ||
            copy == NULL || copy->messages == NULL ||
            copy->messages == f->ssl->hsHashes->messages ||
            copy->length != 1 || copy->messages[0] != record[RECORD_HEADER_SZ])
        failed = 1;
#endif
    if (copy != f->ssl->hsHashes)
        Free_HS_Hashes(copy, f->ssl->heap);
    Free_HS_Hashes(f->ssl->hsHashes, f->ssl->heap);
    wb_reset(f);
    return failed;
}
#endif

#ifdef WOLFSSL_DTLS
static int wb_dtls_message_list(void)
{
    DtlsMsg first, middle, last, absent;
    DtlsMsg* head;
    int failed = 0;

    XMEMSET(&first, 0, sizeof(first));
    XMEMSET(&middle, 0, sizeof(middle));
    XMEMSET(&last, 0, sizeof(last));
    XMEMSET(&absent, 0, sizeof(absent));
    first.seq = 2;
    middle.seq = 4;
    last.seq = 6;
    absent.seq = 8;

    head = DtlsMsgInsert(NULL, &last);
    head = DtlsMsgInsert(head, &first);
    head = DtlsMsgInsert(head, &middle);
    if (head != &first || first.next != &middle || middle.next != &last)
        failed = 1;

    head = DtlsMsgListUnlink(head, &absent);
    if (head != &first || first.next != &middle || middle.next != &last)
        failed = 1;
    head = DtlsMsgListUnlink(head, &middle);
    if (head != &first || first.next != &last || middle.next != NULL)
        failed = 1;
    head = DtlsMsgListUnlink(head, &first);
    if (head != &last || first.next != NULL)
        failed = 1;
    if (DtlsMsgListUnlink(head, &last) != NULL)
        failed = 1;
    return failed;
}

static int wb_dtls_prev_sequence_limit(WbFix* f)
{
    int failed = 0;

    wb_reset(f);
    f->ssl->keys.dtls_prev_sequence_number_hi = 0xfffe;
    f->ssl->keys.dtls_prev_sequence_number_lo = 0xffffffffU;
    if (DtlsSEQAtMax(f->ssl, PREV_ORDER))
        failed = 1;
    f->ssl->keys.dtls_prev_sequence_number_hi = 0xffff;
    if (!DtlsSEQAtMax(f->ssl, PREV_ORDER))
        failed = 1;
    f->ssl->keys.dtls_prev_sequence_number_lo = 0xfffffffeU;
    if (DtlsSEQAtMax(f->ssl, PREV_ORDER))
        failed = 1;
    wb_reset(f);
    return failed;
}
#endif

#if !defined(NO_DH) && defined(HAVE_FFDHE_2048) && \
    (!defined(NO_CERTS) || !defined(NO_PSK)) && !defined(WOLFSSL_ASYNC_CRYPT) && \
    !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
static int wb_dh_key_exchange(WbFix* f)
{
    DhKey key;
    WC_RNG rng;
    byte prime[256], priv[256], pub[256], secret[256];
    word32 privSz = sizeof(priv), pubSz = sizeof(pub);
    word32 secretSz = sizeof(secret);
    int failed = 0;

    wb_reset(f);
    if (wc_InitDhKey(&key) != 0)
        return 1;
    if (wc_InitRng(&rng) != 0) {
        wc_FreeDhKey(&key);
        return 1;
    }
    f->ssl->rng = &rng;
    if (wc_DhSetNamedKey(&key, WC_FFDHE_2048) != 0 ||
            mp_unsigned_bin_size(&key.p) != sizeof(prime) ||
            mp_to_unsigned_bin(&key.p, prime) != MP_OKAY) {
        failed = 1;
        goto done;
    }

    if (DhGenKeyPair(NULL, &key, priv, &privSz, pub, &pubSz) != BAD_FUNC_ARG)
        failed = 1;
    if (DhGenKeyPair(f->ssl, NULL, priv, &privSz, pub, &pubSz) != BAD_FUNC_ARG)
        failed = 1;
    if (DhGenKeyPair(f->ssl, &key, priv, &privSz, pub, &pubSz) != 0) {
        failed = 1;
        goto done;
    }

    if (DhAgree(f->ssl, &key, priv, privSz, pub, pubSz, secret, &secretSz,
            prime, sizeof(prime)) != 0 || secretSz == 0)
        failed = 1;
    secretSz = sizeof(secret);
    if (DhAgree(f->ssl, &key, priv, privSz, pub, pubSz, secret, &secretSz,
            prime, 0) != 0 || secretSz == 0)
        failed = 1;
    if (DhAgree(f->ssl, NULL, priv, privSz, pub, pubSz, secret, &secretSz,
            prime, sizeof(prime)) != BAD_FUNC_ARG)
        failed = 1;
    if (DhAgree(f->ssl, &key, priv, privSz, pub, pubSz, secret, NULL,
            prime, sizeof(prime)) != BAD_FUNC_ARG)
        failed = 1;
    secretSz = 1;
    if (DhAgree(f->ssl, &key, priv, privSz, pub, pubSz, secret, &secretSz,
            prime, sizeof(prime)) != BUFFER_E)
        failed = 1;

done:
    ForceZero(priv, sizeof(priv));
    ForceZero(secret, sizeof(secret));
    wc_FreeRng(&rng);
    wc_FreeDhKey(&key);
    wb_reset(f);
    return failed;
}
#endif

#if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY) && \
    !defined(NO_ECC256) && !defined(WOLFSSL_ASYNC_CRYPT) && \
    !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
static int wb_ecc_verify_digest_limits(WbFix* f)
{
    ecc_key key;
    WC_RNG rng;
    byte digest[WC_MAX_DIGEST_SIZE + 1];
    byte sig[ECC_MAX_SIG_SIZE];
    word32 sigSz = sizeof(sig);
    int failed = 0;

    wb_reset(f);
    if (wc_ecc_init(&key) != 0)
        return 1;
    if (wc_InitRng(&rng) != 0) {
        wc_ecc_free(&key);
        return 1;
    }
    XMEMSET(digest, 0x24, sizeof(digest));
    if (wc_ecc_make_key_ex(&rng, 32, &key, ECC_SECP256R1) != 0 ||
            wc_ecc_sign_hash(digest, 32, sig, &sigSz, &rng, &key) != 0) {
        failed = 1;
        goto done;
    }
    if (EccVerify(f->ssl, sig, sigSz, digest, sizeof(digest), &key, NULL) !=
            BAD_LENGTH_E)
        failed = 1;
    if (EccVerify(f->ssl, sig, sigSz, digest, 0, &key, NULL) != BAD_LENGTH_E)
        failed = 1;
    if (EccVerify(f->ssl, sig, sigSz, digest, 32, &key, NULL) != 0)
        failed = 1;

done:
    wc_FreeRng(&rng);
    wc_ecc_free(&key);
    wb_reset(f);
    return failed;
}
#endif

#if defined(HAVE_ECC) && \
    (defined(HAVE_CURVE25519) || defined(HAVE_CURVE448)) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(HAVE_FIPS) && \
    !defined(HAVE_SELFTEST)
static int wb_curve_key_cleanup(void)
{
    static const int keyTypes[] = {
        DYNAMIC_TYPE_ECC,
#ifdef HAVE_CURVE25519
        DYNAMIC_TYPE_CURVE25519,
#endif
#ifdef HAVE_CURVE448
        DYNAMIC_TYPE_CURVE448,
#endif
    };
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    size_t i;
    int pass, withPeer;
    int failed = 0;

    if (ctx == NULL)
        return 1;
    for (pass = 0; pass < 2; pass++) {
        for (i = 0; i < XELEM_CNT(keyTypes); i++) {
            for (withPeer = 0; withPeer <= (i != 0); withPeer++) {
                int type = keyTypes[i];
                WOLFSSL* ssl = wolfSSL_new(ctx);
                int ret;

                if (ssl == NULL) {
                    failed = 1;
                    continue;
                }
                ret = AllocKey(ssl, type, (void**)&ssl->eccTempKey);
                if (ret == 0)
                    ssl->eccTempKeyPresent = (byte)type;
#ifdef HAVE_CURVE25519
                if (ret == 0 && withPeer && type == DYNAMIC_TYPE_CURVE25519) {
                    ret = AllocKey(ssl, type, (void**)&ssl->peerX25519Key);
                    ssl->peerX25519KeyPresent = (ret == 0);
                }
#endif
#ifdef HAVE_CURVE448
                if (ret == 0 && withPeer && type == DYNAMIC_TYPE_CURVE448) {
                    ret = AllocKey(ssl, type, (void**)&ssl->peerX448Key);
                    ssl->peerX448KeyPresent = (ret == 0);
                }
#endif
                if (ret == 0 && withPeer) {
                    /* A peer key also identifies the type of an owned
                     * temporary key when only the peer flag remains. */
                    ssl->eccTempKeyPresent = 0;
                }
                if (pass == 0)
                    FreeSSL_EccPeerKeys(ssl);
                else
                    FreeHandshakeResources(ssl);
                if (ret != 0 || ssl->eccTempKey != NULL ||
                        ssl->eccTempKeyPresent)
                    failed = 1;
#ifdef HAVE_CURVE25519
                if (ssl->peerX25519Key != NULL || ssl->peerX25519KeyPresent)
                    failed = 1;
#endif
#ifdef HAVE_CURVE448
                if (ssl->peerX448Key != NULL || ssl->peerX448KeyPresent)
                    failed = 1;
#endif
                wolfSSL_free(ssl);
            }
        }
    }
    wolfSSL_CTX_free(ctx);
    return failed;
}
#endif

#if !defined(NO_CERTS) && !defined(WOLFSSL_SESSION_EXPORT)
static int wb_suite_credentials(WbFix* f)
{
    DerBuffer cert, key;
    byte fixture = 0;
    int failed = 0;

    wb_reset(f);
    XMEMSET(&cert, 0, sizeof(cert));
    XMEMSET(&key, 0, sizeof(key));
    f->ssl->options.side = WOLFSSL_SERVER_END;

    if (InitSSL_Suites(f->ssl) != NO_PRIVATE_KEY)
        failed = 1;
    f->ssl->buffers.certificate = &cert;
    if (InitSSL_Suites(f->ssl) != NO_PRIVATE_KEY)
        failed = 1;

    cert.buffer = &fixture;
    if (InitSSL_Suites(f->ssl) != NO_PRIVATE_KEY)
        failed = 1;
    f->ssl->buffers.key = &key;
    if (InitSSL_Suites(f->ssl) != NO_PRIVATE_KEY)
        failed = 1;

    key.buffer = &fixture;
    if (InitSSL_Suites(f->ssl) != WOLFSSL_SUCCESS)
        failed = 1;

    f->ssl->buffers.certificate = NULL;
    f->ssl->buffers.key = NULL;
#ifdef HAVE_ANON
    f->ssl->options.useAnon = 1;
    if (InitSSL_Suites(f->ssl) != WOLFSSL_SUCCESS)
        failed = 1;
    f->ssl->options.useAnon = 0;
#endif
#ifndef NO_PSK
    f->ssl->options.havePSK = 1;
    if (InitSSL_Suites(f->ssl) != WOLFSSL_SUCCESS)
        failed = 1;
#endif
    wb_reset(f);
    return failed;
}
#endif

#if !defined(NO_CERTS) && (defined(HAVE_SNI) || defined(WOLFSSL_CERT_SETUP_CB))
static int wb_context_credential_ownership(WbFix* f)
{
    DerBuffer cert, chain, key;
    int failed = 0;

    XMEMSET(&cert, 0, sizeof(cert));
    XMEMSET(&chain, 0, sizeof(chain));
    XMEMSET(&key, 0, sizeof(key));
    wb_reset(f);
    f->ssl->buffers.certificate = f->ctx->certificate = &cert;
    f->ssl->buffers.certChain = f->ctx->certChain = &chain;
    f->ssl->buffers.key = f->ctx->privateKey = &key;
    f->ssl->buffers.certChainCnt = f->ctx->certChainCnt = 1;
    if (CheckSSL_CTX_CertsAndKeys(f->ssl) != 0)
        failed = 1;

    f->ctx->certificate = NULL;
    if (CheckSSL_CTX_CertsAndKeys(f->ssl) != BAD_STATE_E)
        failed = 1;
    f->ssl->buffers.weOwnCert = 1;
    if (CheckSSL_CTX_CertsAndKeys(f->ssl) != 0)
        failed = 1;

    f->ctx->certChain = NULL;
    if (CheckSSL_CTX_CertsAndKeys(f->ssl) != BAD_STATE_E)
        failed = 1;
    f->ctx->certChain = &chain;
    f->ctx->certChainCnt = 2;
    if (CheckSSL_CTX_CertsAndKeys(f->ssl) != BAD_STATE_E)
        failed = 1;
    f->ssl->buffers.weOwnCertChain = 1;
    if (CheckSSL_CTX_CertsAndKeys(f->ssl) != 0)
        failed = 1;

    f->ctx->privateKey = NULL;
    if (CheckSSL_CTX_CertsAndKeys(f->ssl) != BAD_STATE_E)
        failed = 1;
    f->ssl->buffers.weOwnKey = 1;
    if (CheckSSL_CTX_CertsAndKeys(f->ssl) != 0)
        failed = 1;

    wb_reset(f);
    return failed;
}
#endif

/* AllocateSuites can copy the CTX list or start with an empty local list. */
static int wb_allocate_suites(WbFix* f)
{
    int failed = 0;
    int fixture;

    for (fixture = 0; fixture < 3; fixture++) {
        int ret;

        wb_reset(f);
        XMEMSET(f->suites, 0, sizeof(*f->suites));
        f->suites->suites[0] = ECC_BYTE;
        f->suites->suiteSz = 2;
        if (fixture == 0)
            f->ssl->ctx = NULL;
        if (fixture == 2)
            f->ctx->suites = f->suites;

        ret = AllocateSuites(f->ssl);
        if (ret != 0 || f->ssl->suites == NULL ||
                f->ssl->suites->suiteSz != (fixture == 2 ? 2 : 0) ||
                f->ssl->suites->suites[0] != (fixture == 2 ? ECC_BYTE : 0))
            failed = 1;
        XFREE(f->ssl->suites, NULL, DYNAMIC_TYPE_SUITES);
    }
    wb_reset(f);
    return failed;
}

#if !defined(NO_RSA) && !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
static int wb_key_lifecycle(WbFix* f)
{
    void* key = NULL;
    void* original;
    int failed = 0;

    wb_reset(f);
    if (AllocKey(NULL, DYNAMIC_TYPE_RSA, &key) != BAD_FUNC_ARG ||
            AllocKey(f->ssl, DYNAMIC_TYPE_RSA, NULL) != BAD_FUNC_ARG)
        failed = 1;

    if (AllocKey(f->ssl, DYNAMIC_TYPE_RSA, &key) != 0 || key == NULL)
        return 1;
    original = key;
    if (AllocKey(f->ssl, DYNAMIC_TYPE_RSA, &key) != BAD_STATE_E ||
            key != original)
        failed = 1;

    FreeKey(NULL, DYNAMIC_TYPE_RSA, &key);
    FreeKey(f->ssl, DYNAMIC_TYPE_RSA, NULL);
    if (key != original)
        failed = 1;
    FreeKey(f->ssl, DYNAMIC_TYPE_RSA, &key);
    if (key != NULL)
        failed = 1;
    FreeKey(f->ssl, DYNAMIC_TYPE_RSA, &key);
    return failed;
}
#endif

#if !defined(NO_DH) && !defined(MCDC_FA_UNAVAILABLE) && \
    !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
static int wb_copy_dh_params(WbFix* f)
{
    byte prime = 23;
    byte generator = 2;
    byte* oldPrime;
    byte* oldGenerator;
    int ret, failed = 0;
    int nth;

    wb_reset(f);
    f->ctx->serverDH_P.buffer = &prime;
    f->ctx->serverDH_P.length = 1;
    f->ctx->serverDH_G.buffer = &generator;
    f->ctx->serverDH_G.length = 1;

    ret = CopySSL_CTX_DhParams(f->ssl, f->ctx);
    oldPrime = f->ssl->buffers.serverDH_P.buffer;
    oldGenerator = f->ssl->buffers.serverDH_G.buffer;
    if (ret != 0 || !f->ssl->buffers.weOwnDH || oldPrime == NULL ||
            oldGenerator == NULL || oldPrime == &prime ||
            oldGenerator == &generator || *oldPrime != prime ||
            *oldGenerator != generator) {
        failed = 1;
        goto cleanup;
    }

    prime = 47;
    generator = 5;
    for (nth = 1; nth <= 2; nth++) {
        mcdc_fa_install();
        mcdc_fa_arm_only(nth);
        ret = CopySSL_CTX_DhParams(f->ssl, f->ctx);
        mcdc_fa_restore();
        if (ret != MEMORY_E || !f->ssl->buffers.weOwnDH ||
                f->ssl->buffers.serverDH_P.buffer != oldPrime ||
                f->ssl->buffers.serverDH_G.buffer != oldGenerator ||
                *oldPrime != 23 || *oldGenerator != 2) {
            failed = 1;
            goto cleanup;
        }
    }

    /* A context with only one parameter must leave the owned copy intact. */
    f->ctx->serverDH_P.buffer = NULL;
    ret = CopySSL_CTX_DhParams(f->ssl, f->ctx);
    if (ret != 0 || f->ssl->buffers.serverDH_P.buffer != oldPrime ||
            f->ssl->buffers.serverDH_G.buffer != oldGenerator)
        failed = 1;

    f->ctx->serverDH_P.buffer = &prime;
    f->ctx->serverDH_G.buffer = NULL;
    ret = CopySSL_CTX_DhParams(f->ssl, f->ctx);
    if (ret != 0 || f->ssl->buffers.serverDH_P.buffer != oldPrime ||
            f->ssl->buffers.serverDH_G.buffer != oldGenerator)
        failed = 1;

    f->ctx->serverDH_G.buffer = &generator;
    ret = CopySSL_CTX_DhParams(f->ssl, f->ctx);
    if (ret != 0 || !f->ssl->buffers.weOwnDH ||
            f->ssl->buffers.serverDH_P.length != 1 ||
            f->ssl->buffers.serverDH_G.length != 1 ||
            f->ssl->buffers.serverDH_P.buffer == NULL ||
            f->ssl->buffers.serverDH_G.buffer == NULL ||
            *f->ssl->buffers.serverDH_P.buffer != prime ||
            *f->ssl->buffers.serverDH_G.buffer != generator)
        failed = 1;

cleanup:
    if (f->ssl->buffers.weOwnDH) {
        XFREE(f->ssl->buffers.serverDH_P.buffer, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
        XFREE(f->ssl->buffers.serverDH_G.buffer, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    }
    wb_reset(f);
    return !failed;
}
#endif

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
 * `if (ctx->cm == NULL || ctx->cm->ocsp_stapling == NULL)`, for the SSL's
 * CTX. On a real CTX both are non-NULL for the whole life of the object, so
 * neither operand can flip from the API. Both are fields of driver-owned
 * structs here. */
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
    (void)GetCtxOcspLock(f->ssl->ctx);
    g_calls++;

    /* operand 1: a cert manager, but no stapling responder on it */
    wb_reset(f);
    f->cm->ocsp_stapling = NULL;
    (void)GetCtxOcspLock(f->ssl->ctx);
    g_calls++;

    /* false partner: both present, the lock address is returned */
    f->cm->ocsp_stapling = ocsp;
    (void)GetCtxOcspLock(f->ssl->ctx);
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

#if !defined(NO_WOLFSSL_CLIENT) && !defined(WOLFSSL_ASYNC_CRYPT) && \
    (!defined(NO_DH) || !defined(NO_RSA)) && !defined(MCDC_FA_UNAVAILABLE) && \
    !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
#if !defined(NO_DH) && !defined(NO_PSK)
static unsigned int wb_psk_not_called(WOLFSSL* ssl, const char* hint,
    char* identity, unsigned int identityCapacity, unsigned char* key,
    unsigned int keyCapacity)
{
    (void)ssl;
    (void)hint;
    (void)identity;
    (void)identityCapacity;
    (void)key;
    (void)keyCapacity;
    return 0;
}
#endif

static int wb_send_key_exchange(WOLFSSL* ssl)
{
    ssl->options.buildingMsg = 0;
    return SendClientKeyExchange(ssl);
}

static int wb_missing_exchange_keys(WbFix* f)
{
    int failed = 0;
    int ret;

    wb_reset(f);
    f->ssl->arrays = f->arrays;
#ifdef WOLFSSL_ASYNC_IO
    f->ssl->async = (struct WOLFSSL_ASYNC*)XMALLOC(sizeof(*f->ssl->async),
        NULL, DYNAMIC_TYPE_ASYNC);
    if (f->ssl->async == NULL)
        return 1;
    XMEMSET(f->ssl->async, 0, sizeof(*f->ssl->async));
#endif

#ifndef NO_RSA
    {
        RsaKey* rsa = NULL;

        f->ssl->specs.kea = rsa_kea;
        if (wb_send_key_exchange(f->ssl) != NO_PEER_KEY)
            failed = 1;

        if (AllocKey(f->ssl, DYNAMIC_TYPE_RSA, (void**)&rsa) != 0) {
        #ifdef WOLFSSL_ASYNC_IO
            FreeAsyncCtx(f->ssl, 1);
        #endif
            return 1;
        }
        f->ssl->peerRsaKey = rsa;
        if (wb_send_key_exchange(f->ssl) != NO_PEER_KEY)
            failed = 1;

        /* An allocation error after the guard is the positive partner. The
         * RSA key object never reaches an encryption operation. */
        f->ssl->peerRsaKeyPresent = 1;
        mcdc_fa_install();
        mcdc_fa_arm_only(1);
        ret = wb_send_key_exchange(f->ssl);
        mcdc_fa_restore();
        if (ret != MEMORY_E)
            failed = 1;
        FreePeerCertKeys(f->ssl);
    }
#endif
#ifndef NO_DH
    {
        static const byte exchanges[] = {
            diffie_hellman_kea,
        #ifndef NO_PSK
            dhe_psk_kea,
        #endif
        };
        byte unread = 0;
        size_t i;
        int omitted;

        /* These buffers are borrowed by the fixture. Allocation stops the
         * accepting case before their data would be read. */
        for (i = 0; i < sizeof(exchanges) / sizeof(exchanges[0]); i++) {
            for (omitted = 0; omitted <= 3; omitted++) {
                f->ssl->specs.kea = exchanges[i];
                f->ssl->buffers.serverDH_P.buffer =
                    omitted == 0 ? NULL : &unread;
                f->ssl->buffers.serverDH_G.buffer =
                    omitted == 1 ? NULL : &unread;
                f->ssl->buffers.serverDH_Pub.buffer =
                    omitted == 2 ? NULL : &unread;
            #ifndef NO_PSK
                f->ssl->options.client_psk_cb = wb_psk_not_called;
            #endif
                mcdc_fa_install();
                mcdc_fa_arm_only(1);
                ret = wb_send_key_exchange(f->ssl);
                mcdc_fa_restore();
                if (ret != (omitted == 3 ? MEMORY_E : NO_PEER_KEY))
                    failed = 1;
            }
        }
        f->ssl->buffers.serverDH_P.buffer = NULL;
        f->ssl->buffers.serverDH_G.buffer = NULL;
        f->ssl->buffers.serverDH_Pub.buffer = NULL;
    }
#endif
#ifdef WOLFSSL_ASYNC_IO
    FreeAsyncCtx(f->ssl, 1);
#endif
    return failed;
}
#endif

/* ---------------------------------------------------------------------- main */

int main(void)
{
    WbFix f;
    int failed = 0;

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

#if !defined(NO_DH) && !defined(MCDC_FA_UNAVAILABLE) && \
    !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
    if (!wb_copy_dh_params(&f)) {
        puts("internal null-guard white-box: DH parameter copy failed");
        failed = 1;
    }
#endif

    if (wb_protocol_classifiers(&f)) {
        puts("internal null-guard white-box: protocol classification failed");
        failed = 1;
    }
    if (wb_fatal_alert_errors(&f)) {
        puts("internal null-guard white-box: fatal alert error check failed");
        failed = 1;
    }
#if !defined(NO_RSA) && defined(WC_RSA_PSS) && !defined(NO_SHA256) && \
    !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
    if (wb_rsa_pss_scheme_encoding() || wb_rsa_pss_constraints(&f)) {
        puts("internal null-guard white-box: RSA-PSS constraint check failed");
        failed = 1;
    }
#endif
#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
    if (wb_handshake_hash_copy(&f)) {
        puts("internal null-guard white-box: handshake hash copy failed");
        failed = 1;
    }
#endif
#ifdef WOLFSSL_DTLS
    if (wb_dtls_message_list() || wb_dtls_prev_sequence_limit(&f)) {
        puts("internal null-guard white-box: DTLS message bookkeeping failed");
        failed = 1;
    }
#endif
#if !defined(NO_DH) && defined(HAVE_FFDHE_2048) && \
    (!defined(NO_CERTS) || !defined(NO_PSK)) && !defined(WOLFSSL_ASYNC_CRYPT) && \
    !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
    if (wb_dh_key_exchange(&f)) {
        puts("internal null-guard white-box: DH key exchange check failed");
        failed = 1;
    }
#endif
#if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY) && \
    !defined(NO_ECC256) && !defined(WOLFSSL_ASYNC_CRYPT) && \
    !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
    if (wb_ecc_verify_digest_limits(&f)) {
        puts("internal null-guard white-box: ECC digest limit check failed");
        failed = 1;
    }
#endif
#if defined(HAVE_ECC) && \
    (defined(HAVE_CURVE25519) || defined(HAVE_CURVE448)) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(HAVE_FIPS) && \
    !defined(HAVE_SELFTEST)
    if (wb_curve_key_cleanup()) {
        puts("internal null-guard white-box: curve key cleanup failed");
        failed = 1;
    }
#endif
#if !defined(NO_CERTS) && !defined(WOLFSSL_SESSION_EXPORT)
    if (wb_suite_credentials(&f)) {
        puts("internal null-guard white-box: suite credential check failed");
        failed = 1;
    }
#endif
#if !defined(NO_CERTS) && (defined(HAVE_SNI) || defined(WOLFSSL_CERT_SETUP_CB))
    if (wb_context_credential_ownership(&f)) {
        puts("internal null-guard white-box: context ownership check failed");
        failed = 1;
    }
#endif
    if (wb_allocate_suites(&f)) {
        puts("internal null-guard white-box: suite allocation failed");
        failed = 1;
    }
#if !defined(NO_RSA) && !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
    if (wb_key_lifecycle(&f)) {
        puts("internal null-guard white-box: key lifecycle check failed");
        failed = 1;
    }
#endif

#if !defined(NO_WOLFSSL_CLIENT) && !defined(WOLFSSL_ASYNC_CRYPT) && \
    (!defined(NO_DH) || !defined(NO_RSA)) && !defined(MCDC_FA_UNAVAILABLE) && \
    !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
    if (wb_missing_exchange_keys(&f)) {
        puts("internal null-guard white-box: unexpected exchange key result");
        failed = 1;
    }
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
    return failed;
}

#else

int main(void)
{
    printf("internal null-guard white-box: skipped (TLS 1.2 not built)\n");
    return 0;
}

#endif
