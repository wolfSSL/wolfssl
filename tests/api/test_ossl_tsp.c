/* test_ossl_tsp.c
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

#include <tests/api/api.h>
#include <tests/api/test_ossl_tsp.h>

#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_TSP) && \
    defined(HAVE_PKCS7) && !defined(NO_RSA) && !defined(NO_SHA256) && \
    !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER)
    #define TEST_OSSL_TSP
    #include <wolfssl/openssl/ts.h>
    #include <wolfssl/openssl/x509.h>
    #include <wolfssl/openssl/x509v3.h>
    #include <wolfssl/openssl/evp.h>
    #include <wolfssl/openssl/pkcs7.h>
    #include <wolfssl/wolfcrypt/tsp.h>
    #include <wolfssl/wolfcrypt/pkcs7.h>
    #include <wolfssl/wolfcrypt/random.h>
    #include <wolfssl/wolfcrypt/sha256.h>
#endif

#ifdef TEST_OSSL_TSP

/* Hash of message - content is not checked against an algorithm. */
static const byte tsOsslHash[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
#ifdef WOLFSSL_TSP_RESPONDER
/* 1.3.6.1.4.1.999.1 - test TSA policy. */
static const byte tsOsslPolicy[] = {
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x87, 0x67, 0x01
};
#endif /* WOLFSSL_TSP_RESPONDER */
/* Nonce with top bit set to check INTEGER encoding. */
static const byte tsOsslNonce[] = {
    0xc3, 0x5a, 0x10, 0x42, 0x77, 0x08, 0x99, 0x01
};
#ifdef WOLFSSL_TSP_RESPONDER
/* Serial number of test time-stamp. */
static const byte tsOsslSerial[] = { 0x9a, 0x33 };
/* Time of test time-stamp. */
static const byte tsOsslGenTime[] = "20260605120000Z";
#endif /* WOLFSSL_TSP_RESPONDER */

/* Options controlling the test TimeStampResp built by
 * test_tsp_create_resp_ex(). */
typedef struct TsRespOpts {
    int  withNonce;   /* Include the nonce in the TSTInfo. */
    int  withMicros;  /* Include a microseconds accuracy. */
    int  ordering;    /* Set the ordering flag of the TSTInfo. */
    int  noAccuracy;  /* Omit the accuracy from the TSTInfo. */
    byte status;      /* PKIStatus to put on the response. */
} TsRespOpts;

#ifdef WOLFSSL_TSP_RESPONDER
/* Create a TimeStampResp with a token signed by the test TSA. */
static int test_tsp_create_resp_ex(byte* out, word32* outSz,
    const TsRespOpts* opts)
{
    EXPECT_DECLS;
    wc_PKCS7* pkcs7 = NULL;
    WC_RNG rng;
    TspTstInfo tst;
    TspResponse resp;
    byte token[3072];
    word32 tokenSz = (word32)sizeof(token);

    ExpectIntEQ(wc_InitRng(&rng), 0);

    ExpectIntEQ(wc_TspTstInfo_Init(&tst), 0);
    tst.policy = tsOsslPolicy;
    tst.policySz = (word32)sizeof(tsOsslPolicy);
    tst.imprint.hashAlgOID = SHA256h;
    XMEMCPY(tst.imprint.hash, tsOsslHash, sizeof(tsOsslHash));
    tst.imprint.hashSz = (word32)sizeof(tsOsslHash);
    tst.serial = tsOsslSerial;
    tst.serialSz = (word32)sizeof(tsOsslSerial);
    tst.genTime = tsOsslGenTime;
    tst.genTimeSz = (word32)sizeof(tsOsslGenTime) - 1;
    if (!opts->noAccuracy) {
        tst.accuracy.seconds = 1;
        tst.accuracy.millis = 500;
        if (opts->withMicros) {
            tst.accuracy.micros = 250;
        }
    }
    tst.ordering = (byte)(opts->ordering != 0);
    if (opts->withNonce) {
        tst.nonce = tsOsslNonce;
        tst.nonceSz = (word32)sizeof(tsOsslNonce);
    }

    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, (byte*)tsa_cert_der_2048,
        sizeof_tsa_cert_der_2048), 0);
    if (EXPECT_SUCCESS()) {
        pkcs7->rng = &rng;
        pkcs7->hashOID = SHA256h;
        pkcs7->encryptOID = RSAk;
        pkcs7->privateKey = (byte*)tsa_key_der_2048;
        pkcs7->privateKeySz = sizeof_tsa_key_der_2048;
    }
    ExpectIntEQ(wc_TspTstInfo_SignWithPkcs7(&tst, pkcs7, token, &tokenSz), 0);
    wc_PKCS7_Free(pkcs7);

    ExpectIntEQ(wc_TspResponse_Init(&resp), 0);
    resp.status = opts->status;
    resp.token = token;
    resp.tokenSz = tokenSz;
    ExpectIntEQ(wc_TspResponse_Encode(&resp, out, outSz), 0);

    wc_FreeRng(&rng);
    return EXPECT_RESULT();
}

/* Create a granted TimeStampResp with a token signed by the test TSA. */
static int test_tsp_create_resp(byte* out, word32* outSz, int withNonce)
{
    TsRespOpts opts;
    XMEMSET(&opts, 0, sizeof(opts));
    opts.withNonce = withNonce;
    opts.status = WC_TSP_PKISTATUS_GRANTED;
    return test_tsp_create_resp_ex(out, outSz, &opts);
}

/* Create a granted TimeStampResp whose token is signed by an intermediate-
 * issued TSA certificate. The token carries both the signer and the
 * intermediate CA so a verifier holding only the root can build the chain. */
static int test_tsp_create_resp_chain(byte* out, word32* outSz)
{
    EXPECT_DECLS;
    wc_PKCS7* pkcs7 = NULL;
    WC_RNG rng;
    TspTstInfo tst;
    TspResponse resp;
    byte token[4096];
    word32 tokenSz = (word32)sizeof(token);

    ExpectIntEQ(wc_InitRng(&rng), 0);

    ExpectIntEQ(wc_TspTstInfo_Init(&tst), 0);
    tst.policy = tsOsslPolicy;
    tst.policySz = (word32)sizeof(tsOsslPolicy);
    tst.imprint.hashAlgOID = SHA256h;
    XMEMCPY(tst.imprint.hash, tsOsslHash, sizeof(tsOsslHash));
    tst.imprint.hashSz = (word32)sizeof(tsOsslHash);
    tst.serial = tsOsslSerial;
    tst.serialSz = (word32)sizeof(tsOsslSerial);
    tst.genTime = tsOsslGenTime;
    tst.genTimeSz = (word32)sizeof(tsOsslGenTime) - 1;
    tst.nonce = tsOsslNonce;
    tst.nonceSz = (word32)sizeof(tsOsslNonce);

    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, testDevId));
    /* The signer is the intermediate-issued TSA leaf. */
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, (byte*)tsa_chain_cert_der_2048,
        sizeof_tsa_chain_cert_der_2048), 0);
    /* Carry the intermediate CA in the token for chain building. */
    ExpectIntEQ(wc_PKCS7_AddCertificate(pkcs7, (byte*)ca_int_cert_der_2048,
        sizeof_ca_int_cert_der_2048), 0);
    if (EXPECT_SUCCESS()) {
        pkcs7->rng = &rng;
        pkcs7->hashOID = SHA256h;
        pkcs7->encryptOID = RSAk;
        pkcs7->privateKey = (byte*)tsa_chain_key_der_2048;
        pkcs7->privateKeySz = sizeof_tsa_chain_key_der_2048;
    }
    ExpectIntEQ(wc_TspTstInfo_SignWithPkcs7(&tst, pkcs7, token, &tokenSz), 0);
    wc_PKCS7_Free(pkcs7);

    ExpectIntEQ(wc_TspResponse_Init(&resp), 0);
    resp.status = WC_TSP_PKISTATUS_GRANTED;
    resp.token = token;
    resp.tokenSz = tokenSz;
    ExpectIntEQ(wc_TspResponse_Encode(&resp, out, outSz), 0);

    wc_FreeRng(&rng);
    return EXPECT_RESULT();
}

/* Attach a trust store holding the test TSA certificate to a verification
 * context so the token signer can be anchored - without a store the verifier
 * fails closed. Each context owns its store, so a fresh store is built per
 * call. Returns TEST_SUCCESS on success. */
static int test_tsp_trust_ctx(WOLFSSL_TS_VERIFY_CTX* ctx)
{
    EXPECT_DECLS;
    WOLFSSL_X509_STORE* store = NULL;
    WOLFSSL_X509* caX509 = NULL;
    const unsigned char* cp = tsa_cert_der_2048;

    ExpectNotNull(caX509 = wolfSSL_d2i_X509(NULL, &cp,
        sizeof_tsa_cert_der_2048));
    ExpectNotNull(store = wolfSSL_X509_STORE_new());
    ExpectIntEQ(wolfSSL_X509_STORE_add_cert(store, caX509), 1);
    wolfSSL_X509_free(caX509);
    if (EXPECT_SUCCESS()) {
        ExpectNotNull(TS_VERIFY_CTX_set_store(ctx, store));
    }
    else {
        wolfSSL_X509_STORE_free(store);
    }
    return EXPECT_RESULT();
}

/* Serial number callback for the TS_RESP_CTX - returns a fixed serial. The
 * response creation takes ownership of the returned ASN1_INTEGER. */
static WOLFSSL_ASN1_INTEGER* test_tsp_serial_cb(WOLFSSL_TS_RESP_CTX* ctx,
    void* data)
{
    WOLFSSL_ASN1_INTEGER* serial = wolfSSL_ASN1_INTEGER_new();

    (void)ctx;
    (void)data;
    if (serial != NULL) {
        wolfSSL_ASN1_INTEGER_set(serial, 0x1234);
    }
    return serial;
}

/* Serial callback returning a positive INTEGER whose top byte has the high
 * bit set. Its DER encoding carries a leading 0x00 pad which the responder
 * must strip before encoding the TSTInfo serial. */
static WOLFSSL_ASN1_INTEGER* test_tsp_serial_cb_highbit(
    WOLFSSL_TS_RESP_CTX* ctx, void* data)
{
    WOLFSSL_ASN1_INTEGER* serial = wolfSSL_ASN1_INTEGER_new();

    (void)ctx;
    (void)data;
    if (serial != NULL) {
        /* 0x80 has the high bit set - encodes as INTEGER 00 80. */
        wolfSSL_ASN1_INTEGER_set(serial, 0x80);
    }
    return serial;
}

/* Serial callback returning a negative INTEGER - a serial number must be a
 * non-negative number, so creating a response with this must fail. */
static WOLFSSL_ASN1_INTEGER* test_tsp_serial_cb_neg(WOLFSSL_TS_RESP_CTX* ctx,
    void* data)
{
    WOLFSSL_ASN1_INTEGER* serial = wolfSSL_ASN1_INTEGER_new();

    (void)ctx;
    (void)data;
    if (serial != NULL) {
        serial->data[0] = ASN_INTEGER;
        serial->data[1] = 0x01;
        serial->data[2] = 0x05;
        serial->length = 3;
        serial->negative = 1;
        serial->type = WOLFSSL_V_ASN1_NEG_INTEGER;
    }
    return serial;
}

/* Time callback for the TS_RESP_CTX - returns a fixed time. */
static int test_tsp_time_cb(WOLFSSL_TS_RESP_CTX* ctx, void* data, long* sec,
    long* usec)
{
    (void)ctx;
    (void)data;
    /* 2026-06-04 12:00:00 UTC. */
    *sec = 1780920000L;
    if (usec != NULL)
        *usec = 0;
    return 1;
}
#endif /* WOLFSSL_TSP_RESPONDER */

/* Create a TS_REQ matching the test time-stamps. */
static WOLFSSL_TS_REQ* test_tsp_create_req(void)
{
    EXPECT_DECLS;
    WOLFSSL_TS_REQ* req = NULL;
    WOLFSSL_TS_MSG_IMPRINT* imprint = NULL;
    WOLFSSL_X509_ALGOR* algo = NULL;
    WOLFSSL_ASN1_INTEGER* nonce = NULL;

    ExpectNotNull(req = TS_REQ_new());
    ExpectIntEQ(TS_REQ_set_version(req, 1), 1);

    /* Hash algorithm and message hash. */
    ExpectNotNull(imprint = TS_MSG_IMPRINT_new());
    ExpectNotNull(algo = X509_ALGOR_new());
    if (EXPECT_SUCCESS()) {
        ASN1_OBJECT_free(algo->algorithm);
        algo->algorithm = OBJ_nid2obj(NID_sha256);
    }
    ExpectIntEQ(TS_MSG_IMPRINT_set_algo(imprint, algo), 1);
    ExpectIntEQ(TS_MSG_IMPRINT_set_msg(imprint, (unsigned char*)tsOsslHash,
        (int)sizeof(tsOsslHash)), 1);
    ExpectIntEQ(TS_REQ_set_msg_imprint(req, imprint), 1);

    /* Nonce. */
    ExpectNotNull(nonce = ASN1_INTEGER_new());
    if (EXPECT_SUCCESS()) {
        word32 i;
        nonce->data[0] = ASN_INTEGER;
        nonce->data[1] = (unsigned char)sizeof(tsOsslNonce);
        for (i = 0; i < (word32)sizeof(tsOsslNonce); i++)
            nonce->data[2 + i] = tsOsslNonce[i];
        nonce->length = 2 + (int)sizeof(tsOsslNonce);
    }
    ExpectIntEQ(TS_REQ_set_nonce(req, nonce), 1);
    ExpectIntEQ(TS_REQ_set_cert_req(req, 1), 1);

    ASN1_INTEGER_free(nonce);
    X509_ALGOR_free(algo);
    TS_MSG_IMPRINT_free(imprint);

    if (!EXPECT_SUCCESS()) {
        TS_REQ_free(req);
        req = NULL;
    }
    return req;
}

#endif /* TEST_OSSL_TSP */

int test_wolfSSL_TS_REQ(void)
{
    EXPECT_DECLS;
#ifdef TEST_OSSL_TSP
    WOLFSSL_TS_REQ* req = NULL;
    WOLFSSL_TS_REQ* reqDec = NULL;
    WOLFSSL_TS_MSG_IMPRINT* imprint = NULL;
    unsigned char* der = NULL;
    unsigned char buf[256];
    unsigned char* p;
    const unsigned char* cp;
    int derSz = 0;
    TspRequest wcReq;

    ExpectNotNull(req = test_tsp_create_req());

    /* Get length of encoding only. */
    ExpectIntGT(derSz = i2d_TS_REQ(req, NULL), 0);
    /* Allocating encode. */
    ExpectIntEQ(i2d_TS_REQ(req, &der), derSz);
    ExpectNotNull(der);
    /* Encode into buffer - pointer moved on. */
    p = buf;
    ExpectIntEQ(i2d_TS_REQ(req, &p), derSz);
    if (EXPECT_SUCCESS()) {
        ExpectPtrEq(p, buf + derSz);
        ExpectBufEQ(buf, der, derSz);
    }

    /* Check the encoding decodes at the wc level. */
    ExpectIntEQ(wc_TspRequest_Decode(&wcReq, buf, (word32)derSz), 0);
    ExpectIntEQ(wcReq.version, 1);
    ExpectIntEQ(wcReq.imprint.hashAlgOID, SHA256h);
    ExpectIntEQ(wcReq.certReq, 1);
    ExpectIntEQ(wcReq.nonceSz, (word32)sizeof(tsOsslNonce));
    ExpectBufEQ(wcReq.nonce, tsOsslNonce, (int)sizeof(tsOsslNonce));

    /* Decode and check fields. */
    cp = buf;
    ExpectNotNull(reqDec = d2i_TS_REQ(NULL, &cp, derSz));
    if (EXPECT_SUCCESS()) {
        ExpectPtrEq(cp, buf + derSz);
    }
    ExpectIntEQ(TS_REQ_get_version(reqDec), 1);
    ExpectIntEQ(TS_REQ_get_cert_req(reqDec), 1);
    ExpectNotNull(TS_REQ_get_nonce(reqDec));
    ExpectNull(TS_REQ_get_policy_id(reqDec));
    ExpectNotNull(imprint = TS_REQ_get_msg_imprint(reqDec));
    if (EXPECT_SUCCESS()) {
        WOLFSSL_X509_ALGOR* algo = NULL;
        WOLFSSL_ASN1_STRING* msg = NULL;

        ExpectNotNull(algo = TS_MSG_IMPRINT_get_algo(imprint));
        if (algo != NULL) {
            ExpectIntEQ(OBJ_obj2nid(algo->algorithm), NID_sha256);
        }
        ExpectNotNull(msg = TS_MSG_IMPRINT_get_msg(imprint));
        ExpectIntEQ(ASN1_STRING_length(msg), (int)sizeof(tsOsslHash));
        if (msg != NULL) {
            ExpectBufEQ(ASN1_STRING_data(msg), tsOsslHash,
                (int)sizeof(tsOsslHash));
        }
    }

    /* Decoding into an existing object frees and replaces it. The return is
     * not assigned back to reqDec: d2i updates it through the &reqDec argument
     * on success and leaves it pointing at the still-owned old object on
     * failure - assigning a NULL return would orphan that object (a leak the
     * memory-failure tests detect). */
    cp = buf;
    ExpectNotNull(d2i_TS_REQ(&reqDec, &cp, derSz));
    ExpectIntEQ(TS_REQ_get_version(reqDec), 1);

    /* Bad arguments. */
    ExpectIntEQ(i2d_TS_REQ(NULL, NULL), -1);
    cp = buf;
    ExpectNull(d2i_TS_REQ(NULL, &cp, 2));
    ExpectNull(d2i_TS_REQ(NULL, NULL, derSz));

    /* Setting fields onto themselves does no work. */
    ExpectIntEQ(TS_REQ_set_msg_imprint(req, TS_REQ_get_msg_imprint(req)), 1);
    ExpectIntEQ(TS_MSG_IMPRINT_set_algo(TS_REQ_get_msg_imprint(req),
        TS_MSG_IMPRINT_get_algo(TS_REQ_get_msg_imprint(req))), 1);

    /* set_nonce rejects a malformed ASN1_INTEGER (no DER value bytes). */
    {
        WOLFSSL_ASN1_INTEGER* badNonce = NULL;
        ExpectNotNull(badNonce = ASN1_INTEGER_new());
        ExpectIntEQ(TS_REQ_set_nonce(req, badNonce), 0);
        ASN1_INTEGER_free(badNonce);
    }
    /* i2d of a request with no message imprint fails to encode. */
    {
        WOLFSSL_TS_REQ* emptyReq = NULL;
        ExpectNotNull(emptyReq = TS_REQ_new());
        ExpectIntEQ(i2d_TS_REQ(emptyReq, NULL), -1);
        TS_REQ_free(emptyReq);
    }
    /* A well-framed SEQUENCE that is not a valid TimeStampReq fails to
     * decode (passes the outer length check but not wc_TspRequest_Decode). */
    {
        static const byte badReq[] = { 0x30, 0x03, 0x02, 0x01, 0x01 };
        const unsigned char* bp = badReq;
        ExpectNull(d2i_TS_REQ(NULL, &bp, (long)sizeof(badReq)));
    }
    /* set_algo rejects an algorithm OID that is not a known hash. */
    {
        WOLFSSL_TS_MSG_IMPRINT* mi = NULL;
        WOLFSSL_X509_ALGOR* algo = NULL;
        ExpectNotNull(mi = TS_MSG_IMPRINT_new());
        ExpectNotNull(algo = X509_ALGOR_new());
        if (EXPECT_SUCCESS()) {
            ASN1_OBJECT_free(algo->algorithm);
            algo->algorithm = OBJ_nid2obj(NID_commonName);
        }
        ExpectNotNull(algo->algorithm);
        ExpectIntEQ(TS_MSG_IMPRINT_set_algo(mi, algo), 0);
        X509_ALGOR_free(algo);
        TS_MSG_IMPRINT_free(mi);
    }
    /* set_nonce rejects a nonce value longer than the maximum. */
    {
        WOLFSSL_ASN1_INTEGER bigNonce;
        unsigned char nbuf[2 + MAX_TS_NONCE_SZ + 1];
        XMEMSET(&bigNonce, 0, sizeof(bigNonce));
        nbuf[0] = 0x02;                                 /* INTEGER */
        nbuf[1] = (unsigned char)(MAX_TS_NONCE_SZ + 1); /* > max, no pad */
        XMEMSET(nbuf + 2, 0x55, MAX_TS_NONCE_SZ + 1);
        bigNonce.data = nbuf;
        bigNonce.length = 2 + MAX_TS_NONCE_SZ + 1;
        ExpectIntEQ(TS_REQ_set_nonce(req, &bigNonce), 0);
    }

    XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
    TS_REQ_free(reqDec);
    TS_REQ_free(req);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_TS_REQ_long_nonce(void)
{
    EXPECT_DECLS;
#ifdef TEST_OSSL_TSP
    WOLFSSL_TS_REQ* reqDec = NULL;
    const WOLFSSL_ASN1_INTEGER* nonce = NULL;
    TspRequest req;
    byte longNonce[MAX_TS_NONCE_SZ];
    byte enc[384];
    word32 encSz = (word32)sizeof(enc);
    byte buf[384];
    unsigned char* p;
    const unsigned char* cp;
    word32 i;

    /* A maximum length nonce - longer than an embedded ASN1_INTEGER. */
    for (i = 0; i < (word32)sizeof(longNonce); i++)
        longNonce[i] = (byte)(i + 1);

    ExpectIntEQ(wc_TspRequest_Init(&req), 0);
    req.imprint.hashAlgOID = SHA256h;
    XMEMCPY(req.imprint.hash, tsOsslHash, sizeof(tsOsslHash));
    req.imprint.hashSz = (word32)sizeof(tsOsslHash);
    XMEMCPY(req.nonce, longNonce, sizeof(longNonce));
    req.nonceSz = (word32)sizeof(longNonce);
    ExpectIntEQ(wc_TspRequest_Encode(&req, enc, &encSz), 0);

    /* Decode and check the nonce round trips. */
    cp = enc;
    ExpectNotNull(reqDec = d2i_TS_REQ(NULL, &cp, (long)encSz));
    ExpectNotNull(nonce = TS_REQ_get_nonce(reqDec));
    if (EXPECT_SUCCESS()) {
        /* Type, one length byte then the number. */
        ExpectIntEQ(nonce->length, 2 + (int)sizeof(longNonce));
        ExpectBufEQ(nonce->data + 2, longNonce, (int)sizeof(longNonce));
    }
    p = buf;
    ExpectIntEQ(i2d_TS_REQ(reqDec, &p), (int)encSz);
    ExpectBufEQ(buf, enc, (int)encSz);

    /* A negative nonce is rejected - the magnitude must not be used as if
     * unsigned. */
    {
        WOLFSSL_TS_REQ* req2 = NULL;
        WOLFSSL_ASN1_INTEGER* neg = NULL;

        ExpectNotNull(req2 = TS_REQ_new());
        ExpectNotNull(neg = ASN1_INTEGER_new());
        if (EXPECT_SUCCESS()) {
            neg->data[0] = ASN_INTEGER;
            neg->data[1] = 0x01;
            neg->data[2] = 0x05;
            neg->length = 3;
            neg->negative = 1;
            neg->type = WOLFSSL_V_ASN1_NEG_INTEGER;
        }
        ExpectIntEQ(TS_REQ_set_nonce(req2, neg), 0);
        /* The same magnitude as a positive nonce is accepted. */
        if (EXPECT_SUCCESS()) {
            neg->negative = 0;
            neg->type = WOLFSSL_V_ASN1_INTEGER;
        }
        ExpectIntEQ(TS_REQ_set_nonce(req2, neg), 1);
        /* A malformed length encoding is rejected. */
        if (EXPECT_SUCCESS()) {
            neg->data[1] = 0x82;   /* long form: two length bytes follow... */
            neg->length = 3;       /* ...but the encoding is truncated. */
        }
        ExpectIntEQ(TS_REQ_set_nonce(req2, neg), 0);

        ASN1_INTEGER_free(neg);
        TS_REQ_free(req2);
    }

    TS_REQ_free(reqDec);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_TS_RESP(void)
{
    EXPECT_DECLS;
#if defined(TEST_OSSL_TSP) && defined(WOLFSSL_TSP_RESPONDER)
    WOLFSSL_TS_RESP* resp = NULL;
    WOLFSSL_TS_TST_INFO* tstInfo = NULL;
    WOLFSSL_TS_TST_INFO* tstInfoDec = NULL;
    WOLFSSL_TS_MSG_IMPRINT* imprint = NULL;
    WOLFSSL_TS_ACCURACY* accuracy = NULL;
    const WOLFSSL_ASN1_INTEGER* num = NULL;
    const WOLFSSL_ASN1_GENERALIZEDTIME* genTime = NULL;
    byte respDer[4096];
    word32 respDerSz = (word32)sizeof(respDer);
    unsigned char* der = NULL;
    const unsigned char* cp;
    int derSz = 0;

    ExpectIntEQ(test_tsp_create_resp(respDer, &respDerSz, 1), TEST_SUCCESS);

    /* Decode the response. */
    cp = respDer;
    ExpectNotNull(resp = d2i_TS_RESP(NULL, &cp, (long)respDerSz));
    /* Granted - no failure information or status string. */
    ExpectIntEQ(ASN1_INTEGER_get(TS_STATUS_INFO_get0_status(
        TS_RESP_get_status_info(resp))), TS_STATUS_GRANTED);
    ExpectNull(TS_STATUS_INFO_get0_failure_info(
        TS_RESP_get_status_info(resp)));
    ExpectNull(TS_STATUS_INFO_get0_text(TS_RESP_get_status_info(resp)));

    /* Rejection with a PKIFreeText of two strings - first one exposed. */
    {
        static const byte rejDer[] = {
            0x30, 0x12, 0x30, 0x10,
            0x02, 0x01, 0x02,
            0x30, 0x0b,
            0x0c, 0x03, 'a', 'b', 'c',
            0x0c, 0x04, 'd', 'e', 'f', 'g'
        };
        WOLFSSL_TS_RESP* rej = NULL;
        const WOLF_STACK_OF(WOLFSSL_ASN1_STRING)* text = NULL;
        WOLFSSL_ASN1_STRING* str = NULL;

        cp = rejDer;
        ExpectNotNull(rej = d2i_TS_RESP(NULL, &cp, (long)sizeof(rejDer)));
        ExpectIntEQ(ASN1_INTEGER_get(TS_STATUS_INFO_get0_status(
            TS_RESP_get_status_info(rej))), TS_STATUS_REJECTION);
        ExpectNotNull(text = TS_STATUS_INFO_get0_text(
            TS_RESP_get_status_info(rej)));
        ExpectIntEQ(sk_ASN1_UTF8STRING_num(text), 1);
        ExpectNotNull(str = (WOLFSSL_ASN1_STRING*)sk_ASN1_UTF8STRING_value(
            text, 0));
        if (EXPECT_SUCCESS()) {
            ExpectIntEQ(ASN1_STRING_length(str), 3);
            ExpectBufEQ(ASN1_STRING_data(str), "abc", 3);
        }
        TS_RESP_free(rej);
    }

    /* Encode is the same. */
    ExpectIntEQ(derSz = i2d_TS_RESP(resp, &der), (int)respDerSz);
    if (EXPECT_SUCCESS()) {
        ExpectBufEQ(der, respDer, derSz);
    }
    XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
    der = NULL;
    /* i2d length-only (NULL) and into a caller buffer (pointer advances). */
    {
        unsigned char* wbuf = NULL;
        unsigned char* q;
        ExpectIntEQ(i2d_TS_RESP(resp, NULL), (int)respDerSz);
        ExpectNotNull(wbuf = (unsigned char*)XMALLOC((size_t)respDerSz, NULL,
            DYNAMIC_TYPE_OPENSSL));
        if (wbuf != NULL) {
            q = wbuf;
            ExpectIntEQ(i2d_TS_RESP(resp, &q), (int)respDerSz);
            ExpectPtrEq(q, wbuf + respDerSz);
            ExpectBufEQ(wbuf, respDer, (int)respDerSz);
        }
        XFREE(wbuf, NULL, DYNAMIC_TYPE_OPENSSL);
    }

    /* Check the TSTInfo of the token. */
    ExpectNotNull(tstInfo = TS_RESP_get_tst_info(resp));
    ExpectIntEQ(TS_TST_INFO_get_version(tstInfo), 1);
    ExpectNotNull(TS_TST_INFO_get_policy_id(tstInfo));
    ExpectIntEQ(TS_TST_INFO_get_ordering(tstInfo), 0);
    /* Serial number. */
    ExpectNotNull(num = TS_TST_INFO_get_serial(tstInfo));
    if (EXPECT_SUCCESS()) {
        /* Top bit of first byte set - 0x00 pad keeps the INTEGER positive. */
        ExpectIntEQ(num->length, 3 + (int)sizeof(tsOsslSerial));
        ExpectIntEQ(num->data[2], 0x00);
        ExpectBufEQ(num->data + 3, tsOsslSerial, (int)sizeof(tsOsslSerial));
    }
    /* Time of time-stamp. */
    ExpectNotNull(genTime = TS_TST_INFO_get_time(tstInfo));
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(genTime->length, (int)sizeof(tsOsslGenTime) - 1);
        ExpectBufEQ(genTime->data, tsOsslGenTime,
            (int)sizeof(tsOsslGenTime) - 1);
    }
    /* Accuracy. */
    ExpectNotNull(accuracy = TS_TST_INFO_get_accuracy(tstInfo));
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(ASN1_INTEGER_get(TS_ACCURACY_get_seconds(accuracy)), 1);
        ExpectIntEQ(ASN1_INTEGER_get(TS_ACCURACY_get_millis(accuracy)), 500);
        ExpectNull(TS_ACCURACY_get_micros(accuracy));
    }
    /* Nonce. */
    ExpectNotNull(num = TS_TST_INFO_get_nonce(tstInfo));
    if (EXPECT_SUCCESS()) {
        /* Top bit of first byte set - 0x00 pad keeps the INTEGER positive. */
        ExpectIntEQ(num->length, 3 + (int)sizeof(tsOsslNonce));
        ExpectIntEQ(num->data[2], 0x00);
        ExpectBufEQ(num->data + 3, tsOsslNonce, (int)sizeof(tsOsslNonce));
    }
    /* Message imprint. */
    ExpectNotNull(imprint = TS_TST_INFO_get_msg_imprint(tstInfo));
    if (EXPECT_SUCCESS()) {
        WOLFSSL_X509_ALGOR* algo = NULL;
        WOLFSSL_ASN1_STRING* msg = NULL;

        ExpectNotNull(algo = TS_MSG_IMPRINT_get_algo(imprint));
        if (algo != NULL) {
            ExpectIntEQ(OBJ_obj2nid(algo->algorithm), NID_sha256);
        }
        ExpectNotNull(msg = TS_MSG_IMPRINT_get_msg(imprint));
        if (msg != NULL) {
            ExpectBufEQ(ASN1_STRING_data(msg), tsOsslHash,
                (int)sizeof(tsOsslHash));
        }
    }

    /* Encode and decode the TSTInfo. */
    ExpectIntGT(derSz = i2d_TS_TST_INFO(tstInfo, &der), 0);
    cp = der;
    ExpectNotNull(tstInfoDec = d2i_TS_TST_INFO(NULL, &cp, derSz));
    ExpectIntEQ(TS_TST_INFO_get_version(tstInfoDec), 1);
    /* i2d length-only (NULL) and into a caller buffer (pointer advances). */
    {
        unsigned char* wbuf = NULL;
        unsigned char* q;
        ExpectIntEQ(i2d_TS_TST_INFO(tstInfo, NULL), derSz);
        ExpectNotNull(wbuf = (unsigned char*)XMALLOC((size_t)derSz, NULL,
            DYNAMIC_TYPE_OPENSSL));
        if (wbuf != NULL) {
            q = wbuf;
            ExpectIntEQ(i2d_TS_TST_INFO(tstInfo, &q), derSz);
            ExpectPtrEq(q, wbuf + derSz);
        }
        XFREE(wbuf, NULL, DYNAMIC_TYPE_OPENSSL);
    }
    /* Decoding into an existing TSTInfo frees and replaces it. The return is
     * not assigned back - d2i updates tstInfoDec through the &tstInfoDec
     * argument and leaves it valid on failure (see d2i_TS_REQ above). */
    cp = der;
    ExpectNotNull(d2i_TS_TST_INFO(&tstInfoDec, &cp, derSz));
    ExpectIntEQ(TS_TST_INFO_get_version(tstInfoDec), 1);
    XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);

    /* Decoding into an existing response frees and replaces it (tstInfo and
     * the other views above reference resp and must not be used afterward).
     * The return is not assigned back - d2i updates resp through &resp and
     * leaves it valid on failure (see d2i_TS_REQ above). */
    cp = respDer;
    ExpectNotNull(d2i_TS_RESP(&resp, &cp, (long)respDerSz));

    TS_TST_INFO_free(tstInfoDec);
    TS_RESP_free(resp);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_TS_RESP_verify_response(void)
{
    EXPECT_DECLS;
#if defined(TEST_OSSL_TSP) && defined(WOLFSSL_TSP_RESPONDER)
    WOLFSSL_TS_REQ* req = NULL;
    WOLFSSL_TS_RESP* resp = NULL;
    WOLFSSL_TS_VERIFY_CTX* ctx = NULL;
    WOLFSSL_X509_STORE* store = NULL;
    byte respDer[4096];
    word32 respDerSz = (word32)sizeof(respDer);
    const unsigned char* cp;
    unsigned char* imprint = NULL;

    ExpectIntEQ(test_tsp_create_resp(respDer, &respDerSz, 1), TEST_SUCCESS);
    cp = respDer;
    ExpectNotNull(resp = d2i_TS_RESP(NULL, &cp, (long)respDerSz));

    /* Verification context out of the request sent. */
    ExpectNotNull(req = test_tsp_create_req());
    ExpectNotNull(ctx = TS_REQ_to_TS_VERIFY_CTX(req, NULL));
    /* No trust store set - the signer cannot be anchored so verification
     * fails closed even though the token's signature is valid. */
    ExpectIntEQ(TS_RESP_verify_response(ctx, resp), 0);

    /* An empty store - the signer's certificate is not trusted - fails. */
    ExpectNotNull(store = wolfSSL_X509_STORE_new());
    ExpectNotNull(TS_VERIFY_CTX_set_store(ctx, store));
    store = NULL;
    ExpectIntEQ(TS_RESP_verify_response(ctx, resp), 0);

    /* Trust the signer's certificate - verification succeeds. */
    ExpectIntEQ(test_tsp_trust_ctx(ctx), TEST_SUCCESS);
    ExpectIntEQ(TS_RESP_verify_response(ctx, resp), 1);

    /* Check a different message imprint fails. The trusted store stays set so
     * the imprint check - not the signer check - is what rejects it. */
    ExpectNotNull(imprint = (unsigned char*)XMALLOC(sizeof(tsOsslHash), NULL,
        DYNAMIC_TYPE_OPENSSL));
    if (EXPECT_SUCCESS()) {
        XMEMCPY(imprint, tsOsslHash, sizeof(tsOsslHash));
        imprint[0] ^= 0x80;
        ExpectNotNull(TS_VERIFY_CTX_set_imprint(ctx, imprint,
            (long)sizeof(tsOsslHash)));
        imprint = NULL;
        ExpectIntEQ(TS_RESP_verify_response(ctx, resp), 0);
    }

    /* Data check enabled but no data BIO set - verification fails. */
    TS_VERIFY_CTX_add_flags(ctx, TS_VFY_DATA);
    ExpectIntEQ(TS_RESP_verify_response(ctx, resp), 0);

    TS_VERIFY_CTX_free(ctx);
    ctx = NULL;

    /* Check a response without a nonce fails the nonce check. */
    respDerSz = (word32)sizeof(respDer);
    ExpectIntEQ(test_tsp_create_resp(respDer, &respDerSz, 0), TEST_SUCCESS);
    TS_RESP_free(resp);
    resp = NULL;
    cp = respDer;
    ExpectNotNull(resp = d2i_TS_RESP(NULL, &cp, (long)respDerSz));
    ExpectNotNull(ctx = TS_REQ_to_TS_VERIFY_CTX(req, NULL));
    /* Trust the signer so the nonce check - not the signer check - rejects. */
    ExpectIntEQ(test_tsp_trust_ctx(ctx), TEST_SUCCESS);
    ExpectIntEQ(TS_RESP_verify_response(ctx, resp), 0);
    TS_VERIFY_CTX_free(ctx);
    ctx = NULL;
    TS_RESP_free(resp);
    resp = NULL;

    /* A granted response with no time-stamp token fails verification. */
    {
        static const byte grantedNoTokenDer[] = {
            0x30, 0x05,             /* TimeStampResp */
            0x30, 0x03,             /* PKIStatusInfo */
            0x02, 0x01, 0x00        /* status granted (0) - no token */
        };
        cp = grantedNoTokenDer;
        ExpectNotNull(resp = d2i_TS_RESP(NULL, &cp,
            (long)sizeof(grantedNoTokenDer)));
        ExpectNotNull(ctx = TS_REQ_to_TS_VERIFY_CTX(req, NULL));
        ExpectIntEQ(TS_RESP_verify_response(ctx, resp), 0);
    }
    TS_VERIFY_CTX_free(ctx);
    ctx = NULL;
    TS_RESP_free(resp);
    resp = NULL;

    /* A granted response whose token signature is corrupt fails to verify -
     * exercises the wc_TspTstInfo_VerifyWithPKCS7 failure path. The flipped byte
     * is well inside the trailing RSA signature so the response framing still
     * decodes but the signature does not verify. */
    respDerSz = (word32)sizeof(respDer);
    ExpectIntEQ(test_tsp_create_resp(respDer, &respDerSz, 1), TEST_SUCCESS);
    if (EXPECT_SUCCESS()) {
        respDer[respDerSz - 16] ^= 0xFF;
    }
    cp = respDer;
    ExpectNotNull(resp = d2i_TS_RESP(NULL, &cp, (long)respDerSz));
    ExpectNotNull(ctx = TS_REQ_to_TS_VERIFY_CTX(req, NULL));
    ExpectIntEQ(TS_RESP_verify_response(ctx, resp), 0);

    TS_VERIFY_CTX_free(ctx);
    TS_RESP_free(resp);
    TS_REQ_free(req);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_TS_RESP_verify_response_chain(void)
{
    EXPECT_DECLS;
#if defined(TEST_OSSL_TSP) && defined(WOLFSSL_TSP_RESPONDER)
    WOLFSSL_TS_REQ* req = NULL;
    WOLFSSL_TS_RESP* resp = NULL;
    WOLFSSL_TS_VERIFY_CTX* ctx = NULL;
    WOLFSSL_X509_STORE* store = NULL;
    WOLFSSL_X509* rootX509 = NULL;
    byte respDer[4096];
    word32 respDerSz = (word32)sizeof(respDer);
    const unsigned char* cp;

    /* A response whose token is signed by an intermediate-issued TSA and
     * carries the intermediate certificate. */
    ExpectIntEQ(test_tsp_create_resp_chain(respDer, &respDerSz), TEST_SUCCESS);
    cp = respDer;
    ExpectNotNull(resp = d2i_TS_RESP(NULL, &cp, (long)respDerSz));

    ExpectNotNull(req = test_tsp_create_req());
    ExpectNotNull(ctx = TS_REQ_to_TS_VERIFY_CTX(req, NULL));

    /* Trusting only the intermediate-issued leaf's root is enough: the token
     * carries the intermediate, so the signer chains leaf -> intermediate ->
     * root and verifies. */
    cp = ca_cert_der_2048;
    ExpectNotNull(rootX509 = wolfSSL_d2i_X509(NULL, &cp,
        sizeof_ca_cert_der_2048));
    ExpectNotNull(store = wolfSSL_X509_STORE_new());
    ExpectIntEQ(wolfSSL_X509_STORE_add_cert(store, rootX509), 1);
    wolfSSL_X509_free(rootX509);
    rootX509 = NULL;
    /* set_store takes ownership, but a failed Expect above short-circuits it -
     * free the store in that case so an allocation-failure path does not leak
     * the store. */
    if (EXPECT_SUCCESS()) {
        ExpectNotNull(TS_VERIFY_CTX_set_store(ctx, store));
    }
    else {
        wolfSSL_X509_STORE_free(store);
    }
    store = NULL;
    ExpectIntEQ(TS_RESP_verify_response(ctx, resp), 1);

    /* An empty store does not trust the chain - verification fails. */
    ExpectNotNull(store = wolfSSL_X509_STORE_new());
    ExpectNotNull(TS_VERIFY_CTX_set_store(ctx, store));
    store = NULL;
    ExpectIntEQ(TS_RESP_verify_response(ctx, resp), 0);

    TS_VERIFY_CTX_free(ctx);
    TS_RESP_free(resp);
    TS_REQ_free(req);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspResponse_VerifyWithCm(void)
{
    EXPECT_DECLS;
#if defined(TEST_OSSL_TSP) && defined(WOLFSSL_TSP_RESPONDER)
    TspResponse resp;
    TspTstInfo tst;
    WOLFSSL_CERT_MANAGER* cm = NULL;
    WOLFSSL_CERT_MANAGER* emptyCm = NULL;
    byte respDer[4096];
    word32 respDerSz = (word32)sizeof(respDer);

    /* A response whose token is signed by the intermediate-issued TSA. */
    ExpectIntEQ(test_tsp_create_resp_chain(respDer, &respDerSz), TEST_SUCCESS);
    ExpectIntEQ(wc_TspResponse_Decode(&resp, respDer, respDerSz), 0);

    /* A manager trusting the root and holding the intermediate CA - the
     * signer (issued by the intermediate) chains to the trusted root. */
    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectIntEQ(wolfSSL_CertManagerLoadCABuffer(cm, ca_cert_der_2048,
        (long)sizeof_ca_cert_der_2048, WOLFSSL_FILETYPE_ASN1),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CertManagerLoadCABuffer(cm, ca_int_cert_der_2048,
        (long)sizeof_ca_int_cert_der_2048, WOLFSSL_FILETYPE_ASN1),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wc_TspResponse_VerifyWithCm(&resp, cm, &tst), 0);

    /* Bad arguments. */
    ExpectIntEQ(wc_TspResponse_VerifyWithCm(NULL, cm, &tst),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspResponse_VerifyWithCm(&resp, NULL, &tst),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* An empty manager does not trust the signer. */
    ExpectNotNull(emptyCm = wolfSSL_CertManagerNew());
    ExpectIntEQ(wc_TspResponse_VerifyWithCm(&resp, emptyCm, &tst),
        WC_NO_ERR_TRACE(TSP_VERIFY_E));

    /* The TSTInfo is optional. */
    ExpectIntEQ(wc_TspResponse_VerifyWithCm(&resp, cm, NULL), 0);

    wolfSSL_CertManagerFree(cm);
    wolfSSL_CertManagerFree(emptyCm);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_TS_RESP_verify_data(void)
{
    EXPECT_DECLS;
#if defined(TEST_OSSL_TSP) && defined(WOLFSSL_TSP_RESPONDER)
    WOLFSSL_TS_RESP* resp = NULL;
    WOLFSSL_TS_VERIFY_CTX* ctx = NULL;
    WOLFSSL_BIO* bio = NULL;
    wc_PKCS7* pkcs7 = NULL;
    WC_RNG rng;
    TspTstInfo tst;
    TspResponse wcResp;
    byte token[3072];
    word32 tokenSz = (word32)sizeof(token);
    byte respDer[4096];
    word32 respDerSz = (word32)sizeof(respDer);
    static const byte data[] = "wolfSSL RFC 3161 time-stamp data";
    byte dataHash[WC_SHA256_DIGEST_SIZE];
    const unsigned char* cp;

    ExpectIntEQ(wc_InitRng(&rng), 0);
    /* The hash of the data is the token's message imprint. */
    ExpectIntEQ(wc_Sha256Hash(data, (word32)sizeof(data) - 1, dataHash), 0);

    /* Build a granted response over the hash of the data. */
    ExpectIntEQ(wc_TspTstInfo_Init(&tst), 0);
    tst.policy = tsOsslPolicy;
    tst.policySz = (word32)sizeof(tsOsslPolicy);
    tst.imprint.hashAlgOID = SHA256h;
    XMEMCPY(tst.imprint.hash, dataHash, sizeof(dataHash));
    tst.imprint.hashSz = (word32)sizeof(dataHash);
    tst.serial = tsOsslSerial;
    tst.serialSz = (word32)sizeof(tsOsslSerial);
    tst.genTime = tsOsslGenTime;
    tst.genTimeSz = (word32)sizeof(tsOsslGenTime) - 1;

    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, (byte*)tsa_cert_der_2048,
        sizeof_tsa_cert_der_2048), 0);
    if (EXPECT_SUCCESS()) {
        pkcs7->rng = &rng;
        pkcs7->hashOID = SHA256h;
        pkcs7->encryptOID = RSAk;
        pkcs7->privateKey = (byte*)tsa_key_der_2048;
        pkcs7->privateKeySz = sizeof_tsa_key_der_2048;
    }
    ExpectIntEQ(wc_TspTstInfo_SignWithPkcs7(&tst, pkcs7, token, &tokenSz), 0);
    wc_PKCS7_Free(pkcs7);

    ExpectIntEQ(wc_TspResponse_Init(&wcResp), 0);
    wcResp.status = WC_TSP_PKISTATUS_GRANTED;
    wcResp.token = token;
    wcResp.tokenSz = tokenSz;
    ExpectIntEQ(wc_TspResponse_Encode(&wcResp, respDer, &respDerSz), 0);
    cp = respDer;
    ExpectNotNull(resp = d2i_TS_RESP(NULL, &cp, (long)respDerSz));

    /* Verify against the data - the library hashes it and checks the imprint,
     * so the caller does not pre-compute the hash. */
    ExpectNotNull(ctx = TS_VERIFY_CTX_new());
    ExpectIntEQ(TS_VERIFY_CTX_set_flags(ctx, TS_VFY_DATA | TS_VFY_SIGNER),
        TS_VFY_DATA | TS_VFY_SIGNER);
    ExpectIntEQ(test_tsp_trust_ctx(ctx), TEST_SUCCESS);
    ExpectNotNull(bio = BIO_new_mem_buf(data, (int)sizeof(data) - 1));
    ExpectNotNull(TS_VERIFY_CTX_set_data(ctx, bio));
    bio = NULL;  /* The context owns the BIO now. */
    ExpectIntEQ(TS_RESP_verify_response(ctx, resp), 1);

    /* Different data does not hash to the imprint - verification fails. */
    ExpectNotNull(bio = BIO_new_mem_buf("not the time-stamped data", 25));
    ExpectNotNull(TS_VERIFY_CTX_set_data(ctx, bio));
    bio = NULL;
    ExpectIntEQ(TS_RESP_verify_response(ctx, resp), 0);

    /* TS_VFY_DATA with no data set fails - clearing returns NULL. */
    ExpectNull(TS_VERIFY_CTX_set_data(ctx, NULL));
    ExpectIntEQ(TS_RESP_verify_response(ctx, resp), 0);

    TS_VERIFY_CTX_free(ctx);
    TS_RESP_free(resp);
    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_TS_TST_INFO_get_tsa(void)
{
    EXPECT_DECLS;
#if defined(TEST_OSSL_TSP) && defined(WOLFSSL_TSP_RESPONDER)
    TspTstInfo tst;
    WOLFSSL_TS_TST_INFO* tstInfo = NULL;
    WOLFSSL_GENERAL_NAME* gn = NULL;
    byte der[512];
    word32 derSz = (word32)sizeof(der);
    const unsigned char* cp;
    /* GeneralName dNSName [2] "tsa.wolfssl.com". */
    static const byte tsaName[] = {
        0x82, 0x0f, 't', 's', 'a', '.', 'w', 'o', 'l', 'f', 's', 's', 'l',
        '.', 'c', 'o', 'm'
    };

    /* Build a TSTInfo carrying a dNSName TSA name and encode it. */
    ExpectIntEQ(wc_TspTstInfo_Init(&tst), 0);
    tst.policy = tsOsslPolicy;
    tst.policySz = (word32)sizeof(tsOsslPolicy);
    tst.imprint.hashAlgOID = SHA256h;
    XMEMCPY(tst.imprint.hash, tsOsslHash, sizeof(tsOsslHash));
    tst.imprint.hashSz = (word32)sizeof(tsOsslHash);
    tst.serial = tsOsslSerial;
    tst.serialSz = (word32)sizeof(tsOsslSerial);
    tst.genTime = tsOsslGenTime;
    tst.genTimeSz = (word32)sizeof(tsOsslGenTime) - 1;
    tst.tsa = tsaName;
    tst.tsaSz = (word32)sizeof(tsaName);
    ExpectIntEQ(wc_TspTstInfo_Encode(&tst, der, &derSz), 0);

    cp = der;
    ExpectNotNull(tstInfo = d2i_TS_TST_INFO(NULL, &cp, (long)derSz));

    /* get_tsa builds the GeneralName - a dNSName with the expected value. */
    ExpectNotNull(gn = TS_TST_INFO_get_tsa(tstInfo));
    if (gn != NULL) {
        ExpectIntEQ(gn->type, GEN_DNS);
        ExpectIntEQ(ASN1_STRING_length(gn->d.dNSName),
            (int)sizeof(tsaName) - 2);
        ExpectIntEQ(XMEMCMP(ASN1_STRING_data(gn->d.dNSName), tsaName + 2,
            sizeof(tsaName) - 2), 0);
    }
    /* A second get returns the same cached object. */
    ExpectPtrEq(TS_TST_INFO_get_tsa(tstInfo), gn);

    /* NULL argument returns NULL. */
    ExpectNull(TS_TST_INFO_get_tsa(NULL));

    TS_TST_INFO_free(tstInfo);
    tstInfo = NULL;

    /* A directoryName [4] form is returned as a GEN_DIRNAME. The name is
     * RDNSequence { RDN { commonName "ts" } }. */
    {
        static const byte dirName[] = {
            0xa4, 0x0f, 0x30, 0x0d, 0x31, 0x0b, 0x30, 0x09,
            0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x02, 't', 's'
        };

        derSz = (word32)sizeof(der);
        tst.tsa = dirName;
        tst.tsaSz = (word32)sizeof(dirName);
        ExpectIntEQ(wc_TspTstInfo_Encode(&tst, der, &derSz), 0);
        cp = der;
        ExpectNotNull(tstInfo = d2i_TS_TST_INFO(NULL, &cp, (long)derSz));
        ExpectNotNull(gn = TS_TST_INFO_get_tsa(tstInfo));
        if (gn != NULL) {
            ExpectIntEQ(gn->type, GEN_DIRNAME);
        }
        TS_TST_INFO_free(tstInfo);
        tstInfo = NULL;
    }

    /* An unsupported GeneralName form - iPAddress [7] - returns NULL. */
    {
        static const byte ipName[] = {
            0x87, 0x04, 0x7f, 0x00, 0x00, 0x01
        };

        derSz = (word32)sizeof(der);
        tst.tsa = ipName;
        tst.tsaSz = (word32)sizeof(ipName);
        ExpectIntEQ(wc_TspTstInfo_Encode(&tst, der, &derSz), 0);
        cp = der;
        ExpectNotNull(tstInfo = d2i_TS_TST_INFO(NULL, &cp, (long)derSz));
        ExpectNull(TS_TST_INFO_get_tsa(tstInfo));
        TS_TST_INFO_free(tstInfo);
    }
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_TS_RESP_CTX(void)
{
    EXPECT_DECLS;
#if defined(TEST_OSSL_TSP) && defined(WOLFSSL_TSP_RESPONDER)
    WOLFSSL_TS_RESP_CTX* ctx = NULL;
    WOLFSSL_X509* signer = NULL;
    WOLFSSL_EVP_PKEY* key = NULL;
    WOLFSSL_ASN1_OBJECT* policy = NULL;
    WOLFSSL_TS_REQ* req = NULL;
    WOLFSSL_BIO* reqBio = NULL;
    WOLFSSL_TS_RESP* resp = NULL;
    WOLFSSL_TS_TST_INFO* tstInfo = NULL;
    WOLFSSL_TS_MSG_IMPRINT* imprint = NULL;
    unsigned char* reqDer = NULL;
    int reqDerSz = 0;
    const unsigned char* cp;
    /* 1.3.6.1.4.1.999.1 - the test TSA policy as an OID object. */
    static const byte policyObj[] = {
        0x2b, 0x06, 0x01, 0x04, 0x01, 0x87, 0x67, 0x01
    };

    /* Load the TSA signer certificate and key. */
    cp = tsa_cert_der_2048;
    ExpectNotNull(signer = wolfSSL_d2i_X509(NULL, &cp, sizeof_tsa_cert_der_2048));
    cp = tsa_key_der_2048;
    ExpectNotNull(key = wolfSSL_d2i_PrivateKey(EVP_PKEY_RSA, NULL, &cp,
        (long)sizeof_tsa_key_der_2048));

    /* Build the responder context. */
    ExpectNotNull(ctx = TS_RESP_CTX_new());
    ExpectIntEQ(TS_RESP_CTX_set_signer_cert(ctx, signer), 1);
    ExpectIntEQ(TS_RESP_CTX_set_signer_key(ctx, key), 1);
    ExpectIntEQ(TS_RESP_CTX_set_signer_digest(ctx, EVP_sha256()), 1);
    if (EXPECT_SUCCESS()) {
        const unsigned char* pp = policyObj;
        policy = wolfSSL_c2i_ASN1_OBJECT(NULL, &pp, (long)sizeof(policyObj));
    }
    ExpectNotNull(policy);
    ExpectIntEQ(TS_RESP_CTX_set_def_policy(ctx, policy), 1);
    ExpectIntEQ(TS_RESP_CTX_set_serial_cb(ctx, test_tsp_serial_cb, NULL), 1);
    ExpectIntEQ(TS_RESP_CTX_set_accuracy(ctx, 1, 0, 0), 1);

    /* A request from a client. */
    ExpectNotNull(req = test_tsp_create_req());
    ExpectIntGT(reqDerSz = i2d_TS_REQ(req, &reqDer), 0);
    ExpectNotNull(reqBio = BIO_new_mem_buf(reqDer, reqDerSz));

    /* Create the response. */
    ExpectNotNull(resp = TS_RESP_create_response(ctx, reqBio));

    /* The response is granted and the TSTInfo echoes the request imprint. */
    ExpectNotNull(tstInfo = TS_RESP_get_tst_info(resp));
    ExpectIntEQ(TS_TST_INFO_get_version(tstInfo), 1);
    ExpectNotNull(imprint = TS_TST_INFO_get_msg_imprint(tstInfo));
    if (imprint != NULL) {
        ExpectBufEQ(ASN1_STRING_data(TS_MSG_IMPRINT_get_msg(imprint)),
            tsOsslHash, (int)sizeof(tsOsslHash));
    }

    TS_RESP_free(resp);
    resp = NULL;
    BIO_free(reqBio);
    reqBio = NULL;

    /* Re-create with a time callback and the ordering flag set. */
    ExpectIntEQ(TS_RESP_CTX_set_time_cb(ctx, test_tsp_time_cb, NULL), 1);
    ExpectIntEQ(TS_RESP_CTX_add_flags(ctx, TS_ORDERING), 1);
    ExpectNotNull(reqBio = BIO_new_mem_buf(reqDer, reqDerSz));
    ExpectNotNull(resp = TS_RESP_create_response(ctx, reqBio));
    ExpectNotNull(tstInfo = TS_RESP_get_tst_info(resp));
    ExpectIntEQ(TS_TST_INFO_get_ordering(tstInfo), 1);

    /* Bad arguments - create with NULL, and each setter rejects a NULL ctx. */
    ExpectNull(TS_RESP_create_response(NULL, reqBio));
    ExpectNull(TS_RESP_create_response(ctx, NULL));
    ExpectIntEQ(TS_RESP_CTX_set_signer_cert(NULL, signer), 0);
    ExpectIntEQ(TS_RESP_CTX_set_signer_cert(ctx, NULL), 0);
    ExpectIntEQ(TS_RESP_CTX_set_signer_key(NULL, key), 0);
    ExpectIntEQ(TS_RESP_CTX_set_signer_key(ctx, NULL), 0);
    ExpectIntEQ(TS_RESP_CTX_set_signer_digest(NULL, EVP_sha256()), 0);
    ExpectIntEQ(TS_RESP_CTX_set_signer_digest(ctx, NULL), 0);
    ExpectIntEQ(TS_RESP_CTX_set_def_policy(NULL, policy), 0);
    ExpectIntEQ(TS_RESP_CTX_set_def_policy(ctx, NULL), 0);
    ExpectIntEQ(TS_RESP_CTX_set_serial_cb(NULL, test_tsp_serial_cb, NULL), 0);
    ExpectIntEQ(TS_RESP_CTX_set_time_cb(NULL, test_tsp_time_cb, NULL), 0);
    ExpectIntEQ(TS_RESP_CTX_set_accuracy(NULL, 1, 0, 0), 0);
    ExpectIntEQ(TS_RESP_CTX_add_flags(NULL, TS_ORDERING), 0);

    /* A context missing the serial callback cannot create a response. */
    {
        WOLFSSL_TS_RESP_CTX* ctx2 = NULL;
        WOLFSSL_BIO* bio2 = NULL;

        ExpectNotNull(ctx2 = TS_RESP_CTX_new());
        ExpectIntEQ(TS_RESP_CTX_set_signer_cert(ctx2, signer), 1);
        ExpectIntEQ(TS_RESP_CTX_set_signer_key(ctx2, key), 1);
        ExpectIntEQ(TS_RESP_CTX_set_def_policy(ctx2, policy), 1);
        ExpectNotNull(bio2 = BIO_new_mem_buf(reqDer, reqDerSz));
        ExpectNull(TS_RESP_create_response(ctx2, bio2));
        BIO_free(bio2);
        TS_RESP_CTX_free(ctx2);
    }

    /* A malformed request does not decode - no response is created. */
    {
        static const byte badReq[] = { 0x30, 0x03, 0x02, 0x01, 0x01 };
        WOLFSSL_BIO* badBio = NULL;

        ExpectNotNull(badBio = BIO_new_mem_buf(badReq, (int)sizeof(badReq)));
        ExpectNull(TS_RESP_create_response(ctx, badBio));
        BIO_free(badBio);
    }

    /* A serial callback returning a negative INTEGER is rejected - no response
     * is created. */
    {
        WOLFSSL_BIO* negBio = NULL;

        ExpectIntEQ(TS_RESP_CTX_set_serial_cb(ctx, test_tsp_serial_cb_neg,
            NULL), 1);
        ExpectNotNull(negBio = BIO_new_mem_buf(reqDer, reqDerSz));
        ExpectNull(TS_RESP_create_response(ctx, negBio));
        BIO_free(negBio);
        /* Restore the valid serial callback. */
        ExpectIntEQ(TS_RESP_CTX_set_serial_cb(ctx, test_tsp_serial_cb, NULL), 1);
    }

    /* A serial whose top byte has the high bit set is encoded successfully -
     * the responder strips the leading 0x00 pad from the DER content. */
    {
        WOLFSSL_BIO* hbBio = NULL;
        WOLFSSL_TS_RESP* hbResp = NULL;
        WOLFSSL_TS_TST_INFO* hbTst = NULL;
        const WOLFSSL_ASN1_INTEGER* hbSerial = NULL;

        ExpectIntEQ(TS_RESP_CTX_set_serial_cb(ctx, test_tsp_serial_cb_highbit,
            NULL), 1);
        ExpectNotNull(hbBio = BIO_new_mem_buf(reqDer, reqDerSz));
        ExpectNotNull(hbResp = TS_RESP_create_response(ctx, hbBio));
        ExpectNotNull(hbTst = TS_RESP_get_tst_info(hbResp));
        ExpectNotNull(hbSerial = TS_TST_INFO_get_serial(hbTst));
        if (EXPECT_SUCCESS()) {
            /* A positive high-bit value keeps a 0x00 pad in the ASN1_INTEGER
             * view: INTEGER, length 2, 0x00 pad, 0x80. */
            ExpectIntEQ(hbSerial->length, 4);
            ExpectIntEQ(hbSerial->data[0], ASN_INTEGER);
            ExpectIntEQ(hbSerial->data[2], 0x00);
            ExpectIntEQ(hbSerial->data[3], 0x80);
        }
        BIO_free(hbBio);
        TS_RESP_free(hbResp);
        /* Restore the valid serial callback. */
        ExpectIntEQ(TS_RESP_CTX_set_serial_cb(ctx, test_tsp_serial_cb, NULL), 1);
    }

    TS_RESP_free(resp);
    BIO_free(reqBio);
    XFREE(reqDer, NULL, DYNAMIC_TYPE_OPENSSL);
    TS_REQ_free(req);
    ASN1_OBJECT_free(policy);
    TS_RESP_CTX_free(ctx);
    wolfSSL_EVP_PKEY_free(key);
    wolfSSL_X509_free(signer);

    /* An ECDSA signer is also supported. */
#ifdef HAVE_ECC
    {
        WOLFSSL_TS_RESP_CTX* eccCtx = NULL;
        WOLFSSL_X509* eccSigner = NULL;
        WOLFSSL_EVP_PKEY* eccKey = NULL;
        WOLFSSL_ASN1_OBJECT* eccPolicy = NULL;
        WOLFSSL_TS_REQ* eccReq = NULL;
        WOLFSSL_BIO* eccBio = NULL;
        WOLFSSL_TS_RESP* eccResp = NULL;
        unsigned char* eccReqDer = NULL;
        int eccReqDerSz = 0;

        cp = tsa_ecc_cert_der_256;
        ExpectNotNull(eccSigner = wolfSSL_d2i_X509(NULL, &cp,
            sizeof_tsa_ecc_cert_der_256));
        cp = tsa_ecc_key_der_256;
        ExpectNotNull(eccKey = wolfSSL_d2i_PrivateKey(EVP_PKEY_EC, NULL, &cp,
            (long)sizeof_tsa_ecc_key_der_256));

        ExpectNotNull(eccCtx = TS_RESP_CTX_new());
        ExpectIntEQ(TS_RESP_CTX_set_signer_cert(eccCtx, eccSigner), 1);
        ExpectIntEQ(TS_RESP_CTX_set_signer_key(eccCtx, eccKey), 1);
        if (EXPECT_SUCCESS()) {
            const unsigned char* pp = policyObj;
            eccPolicy = wolfSSL_c2i_ASN1_OBJECT(NULL, &pp,
                (long)sizeof(policyObj));
        }
        ExpectIntEQ(TS_RESP_CTX_set_def_policy(eccCtx, eccPolicy), 1);
        ExpectIntEQ(TS_RESP_CTX_set_serial_cb(eccCtx, test_tsp_serial_cb,
            NULL), 1);

        ExpectNotNull(eccReq = test_tsp_create_req());
        ExpectIntGT(eccReqDerSz = i2d_TS_REQ(eccReq, &eccReqDer), 0);
        ExpectNotNull(eccBio = BIO_new_mem_buf(eccReqDer, eccReqDerSz));
        ExpectNotNull(eccResp = TS_RESP_create_response(eccCtx, eccBio));

        TS_RESP_free(eccResp);
        BIO_free(eccBio);
        XFREE(eccReqDer, NULL, DYNAMIC_TYPE_OPENSSL);
        TS_REQ_free(eccReq);
        ASN1_OBJECT_free(eccPolicy);
        TS_RESP_CTX_free(eccCtx);
        wolfSSL_EVP_PKEY_free(eccKey);
        wolfSSL_X509_free(eccSigner);
    }
#endif /* HAVE_ECC */
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_TS_RESP_verify_token(void)
{
    EXPECT_DECLS;
#if defined(TEST_OSSL_TSP) && defined(OPENSSL_ALL) && \
    defined(WOLFSSL_TSP_RESPONDER)
    WOLFSSL_TS_REQ* req = NULL;
    WOLFSSL_TS_VERIFY_CTX* ctx = NULL;
    WOLFSSL_PKCS7* token = NULL;
    TspResponse wcResp;
    byte respDer[4096];
    word32 respDerSz = (word32)sizeof(respDer);
    const unsigned char* cp;

    ExpectIntEQ(test_tsp_create_resp(respDer, &respDerSz, 1), TEST_SUCCESS);
    /* Get the time-stamp token out of the response. d2i_PKCS7 returns the
     * extended WOLFSSL_PKCS7 object that TS_RESP_verify_token requires. */
    ExpectIntEQ(wc_TspResponse_Decode(&wcResp, respDer, respDerSz), 0);
    cp = wcResp.token;
    ExpectNotNull(token = (WOLFSSL_PKCS7*)d2i_PKCS7(NULL, &cp,
        (int)wcResp.tokenSz));

    /* Verification context out of the request sent. */
    ExpectNotNull(req = test_tsp_create_req());
    ExpectNotNull(ctx = TS_REQ_to_TS_VERIFY_CTX(req, NULL));

    /* Bad arguments. */
    ExpectIntEQ(TS_RESP_verify_token(NULL, token), 0);
    ExpectIntEQ(TS_RESP_verify_token(ctx, NULL), 0);

    /* Trust the signer's certificate so verification can be anchored. */
    ExpectIntEQ(test_tsp_trust_ctx(ctx), TEST_SUCCESS);
    ExpectIntEQ(TS_RESP_verify_token(ctx, token), 1);

    /* Data check enabled but no data BIO set - verification fails. */
    TS_VERIFY_CTX_add_flags(ctx, TS_VFY_DATA);
    ExpectIntEQ(TS_RESP_verify_token(ctx, token), 0);

    TS_VERIFY_CTX_free(ctx);
    TS_REQ_free(req);
    PKCS7_free((PKCS7*)token);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_TS_REQ_policy_id(void)
{
    EXPECT_DECLS;
#ifdef TEST_OSSL_TSP
    WOLFSSL_TS_REQ* req = NULL;
    WOLFSSL_TS_REQ* reqDec = NULL;
    WOLFSSL_ASN1_OBJECT* policy = NULL;
    unsigned char buf[256];
    unsigned char* p;
    const unsigned char* cp;
    int derSz = 0;

    ExpectNotNull(req = test_tsp_create_req());
    /* No policy set on a fresh request. */
    ExpectNull(TS_REQ_get_policy_id(req));

    ExpectNotNull(policy = OBJ_nid2obj(NID_sha256));

    /* Bad arguments. */
    ExpectIntEQ(TS_REQ_set_policy_id(NULL, policy), 0);
    ExpectIntEQ(TS_REQ_set_policy_id(req, NULL), 0);
    /* A policy OID content longer than MAX_OID_SZ is rejected. The bytes do
     * not start with an OBJECT IDENTIFIER tag, so they are taken as content. */
    {
        WOLFSSL_ASN1_OBJECT bigPolicy;
        unsigned char bigOid[MAX_OID_SZ + 1];
        XMEMSET(&bigPolicy, 0, sizeof(bigPolicy));
        XMEMSET(bigOid, 0x2a, sizeof(bigOid));
        bigPolicy.obj = bigOid;
        bigPolicy.objSz = (unsigned int)sizeof(bigOid);
        ExpectIntEQ(TS_REQ_set_policy_id(req, &bigPolicy), 0);
    }
    /* An empty policy OID is rejected - a zero-length content or a full-DER
     * OBJECT IDENTIFIER with no content ({0x06,0x00}) both yield no policy. */
    {
        WOLFSSL_ASN1_OBJECT emptyPolicy;
        unsigned char emptyOid[2] = { ASN_OBJECT_ID, 0x00 };
        XMEMSET(&emptyPolicy, 0, sizeof(emptyPolicy));
        emptyPolicy.obj = emptyOid;
        emptyPolicy.objSz = 0;
        ExpectIntEQ(TS_REQ_set_policy_id(req, &emptyPolicy), 0);
        emptyPolicy.objSz = (unsigned int)sizeof(emptyOid);
        ExpectIntEQ(TS_REQ_set_policy_id(req, &emptyPolicy), 0);
    }

    /* Set the policy and read it back. */
    ExpectIntEQ(TS_REQ_set_policy_id(req, policy), 1);
    ExpectIntEQ(OBJ_obj2nid(TS_REQ_get_policy_id(req)), NID_sha256);

    /* The policy is encoded and round trips through decode. */
    ExpectIntGT(derSz = i2d_TS_REQ(req, NULL), 0);
    p = buf;
    ExpectIntEQ(i2d_TS_REQ(req, &p), derSz);
    cp = buf;
    ExpectNotNull(reqDec = d2i_TS_REQ(NULL, &cp, derSz));
    ExpectIntEQ(OBJ_obj2nid(TS_REQ_get_policy_id(reqDec)), NID_sha256);

    ASN1_OBJECT_free(policy);
    TS_REQ_free(reqDec);
    TS_REQ_free(req);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_TS_VERIFY_CTX(void)
{
    EXPECT_DECLS;
#ifdef TEST_OSSL_TSP
    WOLFSSL_TS_VERIFY_CTX* ctx = NULL;

    ExpectNotNull(ctx = TS_VERIFY_CTX_new());

    /* set_flags returns the new flag set; add_flags ORs more in. */
    ExpectIntEQ(TS_VERIFY_CTX_set_flags(ctx, TS_VFY_VERSION), TS_VFY_VERSION);
    ExpectIntEQ(TS_VERIFY_CTX_add_flags(ctx, TS_VFY_NONCE),
        TS_VFY_VERSION | TS_VFY_NONCE);
    /* set_flags replaces - not ORs - the flags. */
    ExpectIntEQ(TS_VERIFY_CTX_set_flags(ctx, TS_VFY_IMPRINT), TS_VFY_IMPRINT);

    /* Bad arguments. */
    ExpectIntEQ(TS_VERIFY_CTX_set_flags(NULL, TS_VFY_VERSION), 0);
    ExpectIntEQ(TS_VERIFY_CTX_add_flags(NULL, TS_VFY_VERSION), 0);
    ExpectNull(TS_VERIFY_CTX_set_store(NULL, NULL));
    ExpectNull(TS_VERIFY_CTX_set_imprint(NULL, NULL, 0));
    ExpectNull(TS_REQ_to_TS_VERIFY_CTX(NULL, NULL));
    ExpectIntEQ(TS_RESP_verify_response(NULL, NULL), 0);

    TS_VERIFY_CTX_free(ctx);
    /* Freeing NULL is safe. */
    TS_VERIFY_CTX_free(NULL);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_TS_STATUS_INFO_failure_info(void)
{
    EXPECT_DECLS;
#if defined(TEST_OSSL_TSP) && defined(WOLFSSL_TSP_RESPONDER)
    WOLFSSL_TS_RESP* resp = NULL;
    const WOLFSSL_ASN1_BIT_STRING* failInfo = NULL;
    TspResponse wcResp;
    byte respDer[64];
    word32 respDerSz = (word32)sizeof(respDer);
    const unsigned char* cp;
    /* BAD_ALG (top bit) plus SYSTEM_FAILURE (bit 25) - spans four bytes so
     * the trailing non-zero byte is kept. */
    static const byte expFailInfo[] = { 0x80, 0x00, 0x00, 0x40 };

    /* Build a rejection response with failure information. */
    ExpectIntEQ(wc_TspResponse_Init(&wcResp), 0);
    wcResp.status = WC_TSP_PKISTATUS_REJECTION;
    wcResp.failInfo = WC_TSP_FAIL_BAD_ALG | WC_TSP_FAIL_SYSTEM_FAILURE;
    ExpectIntEQ(wc_TspResponse_Encode(&wcResp, respDer, &respDerSz), 0);

    cp = respDer;
    ExpectNotNull(resp = d2i_TS_RESP(NULL, &cp, (long)respDerSz));
    ExpectIntEQ(ASN1_INTEGER_get(TS_STATUS_INFO_get0_status(
        TS_RESP_get_status_info(resp))), TS_STATUS_REJECTION);

    /* Failure information is exposed as a BIT STRING. */
    ExpectNotNull(failInfo = TS_STATUS_INFO_get0_failure_info(
        TS_RESP_get_status_info(resp)));
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(failInfo->length, (int)sizeof(expFailInfo));
        ExpectBufEQ(failInfo->data, expFailInfo, (int)sizeof(expFailInfo));
    }

    TS_RESP_free(resp);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_TS_RESP_accuracy_ordering(void)
{
    EXPECT_DECLS;
#if defined(TEST_OSSL_TSP) && defined(WOLFSSL_TSP_RESPONDER)
    WOLFSSL_TS_RESP* resp = NULL;
    WOLFSSL_TS_TST_INFO* tstInfo = NULL;
    WOLFSSL_TS_ACCURACY* accuracy = NULL;
    TsRespOpts opts;
    byte respDer[4096];
    word32 respDerSz = (word32)sizeof(respDer);
    const unsigned char* cp;

    /* A token with a microseconds accuracy and the ordering flag set. */
    XMEMSET(&opts, 0, sizeof(opts));
    opts.status = WC_TSP_PKISTATUS_GRANTED;
    opts.withMicros = 1;
    opts.ordering = 1;
    ExpectIntEQ(test_tsp_create_resp_ex(respDer, &respDerSz, &opts),
        TEST_SUCCESS);

    cp = respDer;
    ExpectNotNull(resp = d2i_TS_RESP(NULL, &cp, (long)respDerSz));
    ExpectNotNull(tstInfo = TS_RESP_get_tst_info(resp));

    /* Ordering flag is reported as set. */
    ExpectIntEQ(TS_TST_INFO_get_ordering(tstInfo), 1);

    /* Microseconds accuracy is present alongside seconds and milliseconds. */
    ExpectNotNull(accuracy = TS_TST_INFO_get_accuracy(tstInfo));
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(ASN1_INTEGER_get(TS_ACCURACY_get_seconds(accuracy)), 1);
        ExpectIntEQ(ASN1_INTEGER_get(TS_ACCURACY_get_millis(accuracy)), 500);
        ExpectNotNull(TS_ACCURACY_get_micros(accuracy));
        ExpectIntEQ(ASN1_INTEGER_get(TS_ACCURACY_get_micros(accuracy)), 250);
    }

    TS_RESP_free(resp);
    resp = NULL;

    /* A token with no accuracy at all - the accuracy is optional and
     * TS_TST_INFO_get_accuracy reports it absent. */
    respDerSz = (word32)sizeof(respDer);
    XMEMSET(&opts, 0, sizeof(opts));
    opts.status = WC_TSP_PKISTATUS_GRANTED;
    opts.noAccuracy = 1;
    ExpectIntEQ(test_tsp_create_resp_ex(respDer, &respDerSz, &opts),
        TEST_SUCCESS);
    cp = respDer;
    ExpectNotNull(resp = d2i_TS_RESP(NULL, &cp, (long)respDerSz));
    ExpectNotNull(tstInfo = TS_RESP_get_tst_info(resp));
    ExpectNull(TS_TST_INFO_get_accuracy(tstInfo));

    TS_RESP_free(resp);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_TS_RESP_verify_status(void)
{
    EXPECT_DECLS;
#if defined(TEST_OSSL_TSP) && defined(WOLFSSL_TSP_RESPONDER)
    WOLFSSL_TS_REQ* req = NULL;
    WOLFSSL_TS_RESP* resp = NULL;
    WOLFSSL_TS_VERIFY_CTX* ctx = NULL;
    TsRespOpts opts;
    byte respDer[4096];
    word32 respDerSz = (word32)sizeof(respDer);
    const unsigned char* cp;

    ExpectNotNull(req = test_tsp_create_req());

    /* "Granted with mods" is an accepted status. */
    XMEMSET(&opts, 0, sizeof(opts));
    opts.status = WC_TSP_PKISTATUS_GRANTED_WITH_MODS;
    opts.withNonce = 1;
    ExpectIntEQ(test_tsp_create_resp_ex(respDer, &respDerSz, &opts),
        TEST_SUCCESS);
    cp = respDer;
    ExpectNotNull(resp = d2i_TS_RESP(NULL, &cp, (long)respDerSz));
    ExpectNotNull(ctx = TS_REQ_to_TS_VERIFY_CTX(req, NULL));
    ExpectIntEQ(test_tsp_trust_ctx(ctx), TEST_SUCCESS);
    ExpectIntEQ(TS_RESP_verify_response(ctx, resp), 1);
    TS_VERIFY_CTX_free(ctx);
    ctx = NULL;
    TS_RESP_free(resp);
    resp = NULL;

    /* A rejection is not granted - verification fails on status. */
    respDerSz = (word32)sizeof(respDer);
    XMEMSET(&opts, 0, sizeof(opts));
    opts.status = WC_TSP_PKISTATUS_REJECTION;
    opts.withNonce = 1;
    ExpectIntEQ(test_tsp_create_resp_ex(respDer, &respDerSz, &opts),
        TEST_SUCCESS);
    cp = respDer;
    ExpectNotNull(resp = d2i_TS_RESP(NULL, &cp, (long)respDerSz));
    ExpectNotNull(ctx = TS_REQ_to_TS_VERIFY_CTX(req, NULL));
    ExpectIntEQ(TS_RESP_verify_response(ctx, resp), 0);

    TS_VERIFY_CTX_free(ctx);
    TS_RESP_free(resp);
    TS_REQ_free(req);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_TS_RESP_verify_policy(void)
{
    EXPECT_DECLS;
#if defined(TEST_OSSL_TSP) && defined(WOLFSSL_TSP_RESPONDER)
    WOLFSSL_TS_REQ* req = NULL;
    WOLFSSL_TS_RESP* resp = NULL;
    WOLFSSL_TS_VERIFY_CTX* ctx = NULL;
    WOLFSSL_ASN1_OBJECT* otherPolicy = NULL;
    WOLFSSL_ASN1_OBJECT policy;
    byte respDer[4096];
    word32 respDerSz = (word32)sizeof(respDer);
    const unsigned char* cp;

    /* An ASN1_OBJECT referencing the raw OID content of the test policy. */
    XMEMSET(&policy, 0, sizeof(policy));
    policy.obj = tsOsslPolicy;
    policy.objSz = (unsigned int)sizeof(tsOsslPolicy);

    /* A granted response carrying the test TSA policy. */
    ExpectIntEQ(test_tsp_create_resp(respDer, &respDerSz, 1), TEST_SUCCESS);
    cp = respDer;
    ExpectNotNull(resp = d2i_TS_RESP(NULL, &cp, (long)respDerSz));

    /* Request with the matching policy - context carries it and the
     * TS_VFY_POLICY check passes. */
    ExpectNotNull(req = test_tsp_create_req());
    ExpectIntEQ(TS_REQ_set_policy_id(req, &policy), 1);
    ExpectNotNull(ctx = TS_REQ_to_TS_VERIFY_CTX(req, NULL));
    ExpectIntEQ(test_tsp_trust_ctx(ctx), TEST_SUCCESS);
    ExpectIntEQ(TS_RESP_verify_response(ctx, resp), 1);
    TS_VERIFY_CTX_free(ctx);
    ctx = NULL;

    /* A different policy on the request fails the policy check. The signer is
     * trusted so the policy check - not the signer check - rejects it. */
    ExpectNotNull(otherPolicy = OBJ_nid2obj(NID_sha256));
    ExpectIntEQ(TS_REQ_set_policy_id(req, otherPolicy), 1);
    ExpectNotNull(ctx = TS_REQ_to_TS_VERIFY_CTX(req, NULL));
    ExpectIntEQ(test_tsp_trust_ctx(ctx), TEST_SUCCESS);
    ExpectIntEQ(TS_RESP_verify_response(ctx, resp), 0);

    ASN1_OBJECT_free(otherPolicy);
    TS_VERIFY_CTX_free(ctx);
    TS_RESP_free(resp);
    TS_REQ_free(req);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_TS_VERIFY_CTX_cleanup(void)
{
    EXPECT_DECLS;
#if defined(TEST_OSSL_TSP) && defined(WOLFSSL_TSP_RESPONDER)
    WOLFSSL_TS_REQ* req = NULL;
    WOLFSSL_TS_RESP* resp = NULL;
    WOLFSSL_TS_VERIFY_CTX* ctx = NULL;
    WOLFSSL_X509_STORE* store = NULL;
    WOLFSSL_X509* caX509 = NULL;
    byte respDer[4096];
    word32 respDerSz = (word32)sizeof(respDer);
    const unsigned char* cp;

    ExpectIntEQ(test_tsp_create_resp(respDer, &respDerSz, 1), TEST_SUCCESS);
    cp = respDer;
    ExpectNotNull(resp = d2i_TS_RESP(NULL, &cp, (long)respDerSz));

    /* A fully populated context - imprint, nonce, policy and a store. */
    ExpectNotNull(req = test_tsp_create_req());
    ExpectNotNull(ctx = TS_REQ_to_TS_VERIFY_CTX(req, NULL));
    cp = tsa_cert_der_2048;
    ExpectNotNull(caX509 = wolfSSL_d2i_X509(NULL, &cp,
        sizeof_tsa_cert_der_2048));
    ExpectNotNull(store = wolfSSL_X509_STORE_new());
    ExpectIntEQ(wolfSSL_X509_STORE_add_cert(store, caX509), 1);
    wolfSSL_X509_free(caX509);
    caX509 = NULL;
    /* set_store takes ownership, but a failed Expect above short-circuits it -
     * free the store in that case so an allocation-failure path does not leak
     * the store. */
    if (EXPECT_SUCCESS()) {
        ExpectNotNull(TS_VERIFY_CTX_set_store(ctx, store));
    }
    else {
        wolfSSL_X509_STORE_free(store);
    }
    store = NULL;
    ExpectIntEQ(TS_RESP_verify_response(ctx, resp), 1);

    /* Cleanup frees the owned store, imprint and nonce and resets state. */
    TS_VERIFY_CTX_cleanup(ctx);

    /* The context can be filled and used again - exercises the reuse of an
     * existing context by TS_REQ_to_TS_VERIFY_CTX. Cleanup dropped the store,
     * so trust the signer again. */
    ExpectPtrEq(TS_REQ_to_TS_VERIFY_CTX(req, ctx), ctx);
    ExpectIntEQ(test_tsp_trust_ctx(ctx), TEST_SUCCESS);
    ExpectIntEQ(TS_RESP_verify_response(ctx, resp), 1);

    TS_VERIFY_CTX_free(ctx);
    /* Cleaning up NULL is safe. */
    TS_VERIFY_CTX_cleanup(NULL);

    TS_RESP_free(resp);
    TS_REQ_free(req);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_TS_bad_args(void)
{
    EXPECT_DECLS;
#ifdef TEST_OSSL_TSP
    /* Scalar getters return 0 on NULL. */
    ExpectIntEQ(TS_REQ_get_version(NULL), 0);
    ExpectIntEQ(TS_REQ_get_cert_req(NULL), 0);
    ExpectIntEQ(TS_TST_INFO_get_version(NULL), 0);
    ExpectIntEQ(TS_TST_INFO_get_ordering(NULL), 0);

    /* Pointer getters return NULL on NULL. */
    ExpectNull(TS_REQ_get_msg_imprint(NULL));
    ExpectNull(TS_REQ_get_policy_id(NULL));
    ExpectNull(TS_REQ_get_nonce(NULL));
    ExpectNull(TS_MSG_IMPRINT_get_algo(NULL));
    ExpectNull(TS_MSG_IMPRINT_get_msg(NULL));
    ExpectNull(TS_TST_INFO_get_policy_id(NULL));
    ExpectNull(TS_TST_INFO_get_msg_imprint(NULL));
    ExpectNull(TS_TST_INFO_get_serial(NULL));
    ExpectNull(TS_TST_INFO_get_time(NULL));
    ExpectNull(TS_TST_INFO_get_accuracy(NULL));
    ExpectNull(TS_TST_INFO_get_nonce(NULL));
    ExpectNull(TS_ACCURACY_get_seconds(NULL));
    ExpectNull(TS_ACCURACY_get_millis(NULL));
    ExpectNull(TS_ACCURACY_get_micros(NULL));
    ExpectNull(TS_STATUS_INFO_get0_status(NULL));
    ExpectNull(TS_STATUS_INFO_get0_failure_info(NULL));
    ExpectNull(TS_STATUS_INFO_get0_text(NULL));
    ExpectNull(TS_RESP_get_status_info(NULL));
    ExpectNull(TS_RESP_get_tst_info(NULL));

    /* Setters return 0 on NULL. */
    ExpectIntEQ(TS_REQ_set_version(NULL, 1), 0);
    ExpectIntEQ(TS_REQ_set_cert_req(NULL, 1), 0);
    ExpectIntEQ(TS_REQ_set_msg_imprint(NULL, NULL), 0);
    ExpectIntEQ(TS_REQ_set_nonce(NULL, NULL), 0);
    ExpectIntEQ(TS_MSG_IMPRINT_set_algo(NULL, NULL), 0);
    ExpectIntEQ(TS_MSG_IMPRINT_set_msg(NULL, NULL, 0), 0);

    /* Encoders return -1 and decoders return NULL on NULL. */
    ExpectIntEQ(i2d_TS_RESP(NULL, NULL), -1);
    ExpectIntEQ(i2d_TS_TST_INFO(NULL, NULL), -1);
    ExpectNull(d2i_TS_RESP(NULL, NULL, 0));
    ExpectNull(d2i_TS_TST_INFO(NULL, NULL, 0));

    /* Well-framed SEQUENCEs that are not valid TSTInfo / TimeStampResp pass
     * the outer length check but fail the wc decode. */
    {
        /* SEQUENCE { INTEGER 1 } - not a TSTInfo. */
        static const byte badTst[] = { 0x30, 0x03, 0x02, 0x01, 0x01 };
        /* SEQUENCE { INTEGER 0 } - PKIStatusInfo must be a SEQUENCE. */
        static const byte badResp[] = { 0x30, 0x03, 0x02, 0x01, 0x00 };
        const unsigned char* cp;

        cp = badTst;
        ExpectNull(d2i_TS_TST_INFO(NULL, &cp, (long)sizeof(badTst)));
        cp = badResp;
        ExpectNull(d2i_TS_RESP(NULL, &cp, (long)sizeof(badResp)));

        /* A non-positive length has no item to decode. */
        cp = badTst;
        ExpectNull(d2i_TS_REQ(NULL, &cp, 0));
        cp = badTst;
        ExpectNull(d2i_TS_TST_INFO(NULL, &cp, -1));
        cp = badResp;
        ExpectNull(d2i_TS_RESP(NULL, &cp, 0));
    }

    /* Setters reject invalid sub-objects even when the parent is valid. */
    {
        WOLFSSL_TS_MSG_IMPRINT* mi = NULL;
        WOLFSSL_X509_ALGOR* algo = NULL;
        WOLFSSL_TS_REQ* req = NULL;
        WOLFSSL_ASN1_OBJECT policy;
        byte hash[WC_TSP_MAX_HASH_SZ + 1];

        XMEMSET(hash, 0, sizeof(hash));

        /* set_msg rejects NULL data, a non-positive length and an oversize
         * hash. */
        ExpectNotNull(mi = TS_MSG_IMPRINT_new());
        ExpectIntEQ(TS_MSG_IMPRINT_set_msg(mi, NULL, sizeof(hash)), 0);
        ExpectIntEQ(TS_MSG_IMPRINT_set_msg(mi, hash, 0), 0);
        ExpectIntEQ(TS_MSG_IMPRINT_set_msg(mi, hash, WC_TSP_MAX_HASH_SZ + 1), 0);
        /* set_algo rejects an algorithm carrying no OID. */
        ExpectNotNull(algo = X509_ALGOR_new());   /* algo->algorithm is NULL */
        ExpectIntEQ(TS_MSG_IMPRINT_set_algo(mi, algo), 0);
        X509_ALGOR_free(algo);
        TS_MSG_IMPRINT_free(mi);

        /* Request setters reject NULL sub-objects on an otherwise valid
         * request, and a policy object with no OID content. */
        ExpectNotNull(req = TS_REQ_new());
        ExpectIntEQ(TS_REQ_set_msg_imprint(req, NULL), 0);
        ExpectIntEQ(TS_REQ_set_nonce(req, NULL), 0);
        XMEMSET(&policy, 0, sizeof(policy));      /* policy.obj is NULL */
        ExpectIntEQ(TS_REQ_set_policy_id(req, &policy), 0);
        TS_REQ_free(req);

        /* A request with no message imprint cannot make a verify context. */
        ExpectNotNull(req = TS_REQ_new());
        ExpectNull(TS_REQ_to_TS_VERIFY_CTX(req, NULL));
        TS_REQ_free(req);
    }

    /* Freeing a NULL object is a safe no-op. */
    TS_MSG_IMPRINT_free(NULL);
    TS_REQ_free(NULL);
    TS_TST_INFO_free(NULL);
    TS_RESP_free(NULL);
#ifdef WOLFSSL_TSP_RESPONDER
    TS_RESP_CTX_free(NULL);
#endif
#endif
    return EXPECT_RESULT();
}

/* A getter builds an OpenSSL view from the embedded wc data and caches it on
 * the parent; a second get returns the same cached object; changing the wc
 * data with a setter discards the cached view so the next get rebuilds it. */
int test_wolfSSL_TS_view_cache(void)
{
    EXPECT_DECLS;
#ifdef TEST_OSSL_TSP
    WOLFSSL_TS_MSG_IMPRINT* mi = NULL;
    WOLFSSL_X509_ALGOR* algo = NULL;
    WOLFSSL_X509_ALGOR* gotAlgo = NULL;
    WOLFSSL_ASN1_STRING* gotMsg = NULL;
    WOLFSSL_TS_REQ* req = NULL;
    WOLFSSL_ASN1_INTEGER* nonce = NULL;
    byte hash[32];

    XMEMSET(hash, 0x5a, sizeof(hash));

    /* Build an imprint with an algorithm and message hash. */
    ExpectNotNull(mi = TS_MSG_IMPRINT_new());
    ExpectNotNull(algo = X509_ALGOR_new());
    if (EXPECT_SUCCESS()) {
        ASN1_OBJECT_free(algo->algorithm);
        algo->algorithm = OBJ_nid2obj(NID_sha256);
    }
    ExpectIntEQ(TS_MSG_IMPRINT_set_algo(mi, algo), 1);
    ExpectIntEQ(TS_MSG_IMPRINT_set_msg(mi, hash, (int)sizeof(hash)), 1);

    /* First get builds and caches the view; a second get returns the same
     * cached pointer rather than rebuilding. */
    ExpectNotNull(gotAlgo = TS_MSG_IMPRINT_get_algo(mi));
    ExpectPtrEq(TS_MSG_IMPRINT_get_algo(mi), gotAlgo);
    ExpectNotNull(gotMsg = TS_MSG_IMPRINT_get_msg(mi));
    ExpectPtrEq(TS_MSG_IMPRINT_get_msg(mi), gotMsg);

    /* Setting a new value discards the stale cached views. The next get
     * rebuilds a fresh object. */
    ExpectIntEQ(TS_MSG_IMPRINT_set_algo(mi, algo), 1);
    ExpectIntEQ(TS_MSG_IMPRINT_set_msg(mi, hash, (int)sizeof(hash)), 1);
    ExpectNotNull(TS_MSG_IMPRINT_get_algo(mi));
    ExpectNotNull(TS_MSG_IMPRINT_get_msg(mi));

    X509_ALGOR_free(algo);
    TS_MSG_IMPRINT_free(mi);

    /* The request's nonce view is likewise cached and invalidated on set. */
    ExpectNotNull(req = TS_REQ_new());
    ExpectNotNull(nonce = ASN1_INTEGER_new());
    if (EXPECT_SUCCESS()) {
        nonce->data[0] = ASN_INTEGER;
        nonce->data[1] = 4;
        nonce->data[2] = 0x12;
        nonce->data[3] = 0x34;
        nonce->data[4] = 0x56;
        nonce->data[5] = 0x78;
        nonce->length = 6;
    }
    ExpectIntEQ(TS_REQ_set_nonce(req, nonce), 1);
    ExpectNotNull(TS_REQ_get_nonce(req));         /* build the cached view */
    ExpectIntEQ(TS_REQ_set_nonce(req, nonce), 1); /* discards the stale view */
    ExpectNotNull(TS_REQ_get_nonce(req));         /* rebuilt */

    ASN1_INTEGER_free(nonce);
    TS_REQ_free(req);
#endif
    return EXPECT_RESULT();
}
