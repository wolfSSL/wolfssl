/* test_tsp.c
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
#include <tests/api/test_tsp.h>

#ifdef WOLFSSL_TSP
    #include <wolfssl/wolfcrypt/tsp.h>
    #include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef HAVE_PKCS7
    #include <wolfssl/wolfcrypt/asn.h>
    #include <wolfssl/wolfcrypt/pkcs7.h>
    #include <wolfssl/wolfcrypt/random.h>
#endif
#endif

#ifdef WOLFSSL_TSP

#ifdef WOLFSSL_TSP_REQUESTER
/* Hash of message - content is not checked against an algorithm. */
static const byte tsHashedMsg[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

/* Set a message imprint to SHA-256 and the test hash. */
static void test_tsp_set_hash(TspMessageImprint* mi)
{
    mi->hashAlgOID = SHA256h;
    XMEMCPY(mi->hash, tsHashedMsg, sizeof(tsHashedMsg));
    mi->hashSz = (word32)sizeof(tsHashedMsg);
}
/* 1.3.6.1.4.1.999.1 - test TSA policy. */
static const byte tsPolicy[] = {
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x87, 0x67, 0x01
};
/* Nonce with top bit set to check INTEGER encoding. */
static const byte tsNonce[] = {
    0xc3, 0x5a, 0x10, 0x42, 0x77, 0x08, 0x99, 0x01
};
#endif /* WOLFSSL_TSP_REQUESTER */
#ifndef NO_SHA256
#if defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
/* Serial number with top bit set to check INTEGER encoding. */
static const byte tsSerial[] = { 0x9a, 0x33 };
/* Time of test time-stamp. */
static const byte tsGenTime[] = "20260604120000Z";
/* Name of TSA: dNSName GeneralName. */
static const byte tsTsaName[] = { 0x82, 0x03, 't', 's', 'a' };
#endif /* WOLFSSL_TSP_REQUESTER && WOLFSSL_TSP_RESPONDER */
#ifdef WOLFSSL_TSP_REQUESTER
/* DER encoding of minimal TimeStampReq: version 1 and SHA-256 message
 * imprint of tsHashedMsg. */
static const byte tsMinReqDer[] = {
    0x30, 0x36,                                       /* TimeStampReq */
    0x02, 0x01, 0x01,                                 /* version 1 */
    0x30, 0x31,                                       /* messageImprint */
    0x30, 0x0d,                                       /* hashAlgorithm */
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,   /* sha256 */
    0x04, 0x02, 0x01,
    0x05, 0x00,                                       /* NULL */
    0x04, 0x20,                                       /* hashedMessage */
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
#endif /* WOLFSSL_TSP_REQUESTER */
#endif

#endif /* WOLFSSL_TSP */

int test_wc_TspRequest_Init(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(WOLFSSL_TSP_REQUESTER)
    TspRequest req;

    ExpectIntEQ(wc_TspRequest_Init(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    XMEMSET(&req, 0xa5, sizeof(TspRequest));
    ExpectIntEQ(wc_TspRequest_Init(&req), 0);
    ExpectIntEQ(req.version, WC_TSP_VERSION);
    ExpectIntEQ(req.imprint.hashSz, 0);
    ExpectIntEQ(req.policySz, 0);
    ExpectIntEQ(req.nonceSz, 0);
    ExpectIntEQ(req.certReq, 0);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspRequest_SetHashType(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && !defined(NO_SHA256) && \
    defined(WOLFSSL_TSP_REQUESTER)
    TspRequest req;

    ExpectIntEQ(wc_TspRequest_Init(&req), 0);

    /* Bad argument. */
    ExpectIntEQ(wc_TspRequest_SetHashType(NULL, WC_HASH_TYPE_SHA256),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Hash type that is not a usable algorithm. */
    ExpectIntEQ(wc_TspRequest_SetHashType(&req, WC_HASH_TYPE_NONE),
        WC_NO_ERR_TRACE(HASH_TYPE_E));

    /* SHA-256 sets the algorithm OID and the digest size. */
    ExpectIntEQ(wc_TspRequest_SetHashType(&req, WC_HASH_TYPE_SHA256), 0);
    ExpectIntEQ(req.imprint.hashAlgOID, SHA256h);
    ExpectIntEQ(req.imprint.hashSz, WC_SHA256_DIGEST_SIZE);

#ifdef WOLFSSL_SHA384
    /* A different algorithm sets a different OID and size. */
    ExpectIntEQ(wc_TspRequest_SetHashType(&req, WC_HASH_TYPE_SHA384), 0);
    ExpectIntEQ(req.imprint.hashAlgOID, SHA384h);
    ExpectIntEQ(req.imprint.hashSz, WC_SHA384_DIGEST_SIZE);
#endif
#endif
    return EXPECT_RESULT();
}

int test_wc_TspRequest_GetHashType(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && !defined(NO_SHA256) && \
    defined(WOLFSSL_TSP_REQUESTER)
    TspRequest req;
    enum wc_HashType hashType = WC_HASH_TYPE_NONE;

    ExpectIntEQ(wc_TspRequest_Init(&req), 0);
    ExpectIntEQ(wc_TspRequest_SetHashType(&req, WC_HASH_TYPE_SHA256), 0);

    /* Bad arguments. */
    ExpectIntEQ(wc_TspRequest_GetHashType(NULL, &hashType),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspRequest_GetHashType(&req, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Round trips with the algorithm that was set. */
    ExpectIntEQ(wc_TspRequest_GetHashType(&req, &hashType), 0);
    ExpectIntEQ(hashType, WC_HASH_TYPE_SHA256);

#ifdef WOLFSSL_SHA384
    ExpectIntEQ(wc_TspRequest_SetHashType(&req, WC_HASH_TYPE_SHA384), 0);
    ExpectIntEQ(wc_TspRequest_GetHashType(&req, &hashType), 0);
    ExpectIntEQ(hashType, WC_HASH_TYPE_SHA384);
#endif

    /* An OID that is not a known hash algorithm. */
    req.imprint.hashAlgOID = 1;
    ExpectIntEQ(wc_TspRequest_GetHashType(&req, &hashType),
        WC_NO_ERR_TRACE(HASH_TYPE_E));
#endif
    return EXPECT_RESULT();
}

int test_wc_TspRequest_GetSetHash(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && !defined(NO_SHA256) && \
    defined(WOLFSSL_TSP_REQUESTER)
    TspRequest req;
    byte hash[WC_SHA256_DIGEST_SIZE];
    byte out[WC_SHA256_DIGEST_SIZE];
    word32 outSz;

    XMEMSET(hash, 0x5a, sizeof(hash));
    ExpectIntEQ(wc_TspRequest_Init(&req), 0);

    /* Set: bad arguments. */
    ExpectIntEQ(wc_TspRequest_SetHash(NULL, hash, (word32)sizeof(hash)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspRequest_SetHash(&req, NULL, (word32)sizeof(hash)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspRequest_SetHash(&req, hash, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Hash too big for the message imprint. */
    ExpectIntEQ(wc_TspRequest_SetHash(&req, hash, WC_TSP_MAX_HASH_SZ + 1),
        WC_NO_ERR_TRACE(BUFFER_E));

    /* Set the hash and length. */
    ExpectIntEQ(wc_TspRequest_SetHash(&req, hash, (word32)sizeof(hash)), 0);
    ExpectIntEQ(req.imprint.hashSz, (word32)sizeof(hash));

    /* Get: bad arguments. */
    outSz = (word32)sizeof(out);
    ExpectIntEQ(wc_TspRequest_GetHash(NULL, out, &outSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspRequest_GetHash(&req, NULL, &outSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspRequest_GetHash(&req, out, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Buffer too small. */
    outSz = (word32)sizeof(hash) - 1;
    ExpectIntEQ(wc_TspRequest_GetHash(&req, out, &outSz),
        WC_NO_ERR_TRACE(BUFFER_E));

    /* Get the hash back - round trips. */
    outSz = (word32)sizeof(out);
    ExpectIntEQ(wc_TspRequest_GetHash(&req, out, &outSz), 0);
    ExpectIntEQ(outSz, (word32)sizeof(hash));
    ExpectBufEQ(out, hash, (int)sizeof(hash));
#endif
    return EXPECT_RESULT();
}

int test_wc_TspRequest_GetSetNonce(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && \
    defined(WOLFSSL_TSP_REQUESTER)
    TspRequest req;
    static const byte nonce[] = { 0x12, 0x34, 0x56, 0x78 };
    static const byte padded[] = { 0x00, 0x00, 0x12, 0x34 };
    static const byte zeros[] = { 0x00, 0x00, 0x00 };
    byte out[16];
    word32 outSz;

    ExpectIntEQ(wc_TspRequest_Init(&req), 0);

    /* Set: bad arguments. */
    ExpectIntEQ(wc_TspRequest_SetNonce(NULL, nonce, (word32)sizeof(nonce)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspRequest_SetNonce(&req, NULL, (word32)sizeof(nonce)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspRequest_SetNonce(&req, nonce, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Nonce too big for the field. */
    ExpectIntEQ(wc_TspRequest_SetNonce(&req, nonce, MAX_TS_NONCE_SZ + 1),
        WC_NO_ERR_TRACE(BUFFER_E));

    /* No leading zeros - kept as-is and round trips. */
    ExpectIntEQ(wc_TspRequest_SetNonce(&req, nonce, (word32)sizeof(nonce)), 0);
    ExpectIntEQ(req.nonceSz, (word32)sizeof(nonce));
    outSz = (word32)sizeof(out);
    ExpectIntEQ(wc_TspRequest_GetNonce(&req, out, &outSz), 0);
    ExpectIntEQ(outSz, (word32)sizeof(nonce));
    ExpectBufEQ(out, nonce, (int)sizeof(nonce));

    /* Leading zero bytes are stripped. */
    ExpectIntEQ(wc_TspRequest_SetNonce(&req, padded, (word32)sizeof(padded)),
        0);
    ExpectIntEQ(req.nonceSz, 2);
    outSz = (word32)sizeof(out);
    ExpectIntEQ(wc_TspRequest_GetNonce(&req, out, &outSz), 0);
    ExpectIntEQ(outSz, 2);
    ExpectIntEQ(out[0], 0x12);
    ExpectIntEQ(out[1], 0x34);

    /* All zeros becomes a single zero byte. */
    ExpectIntEQ(wc_TspRequest_SetNonce(&req, zeros, (word32)sizeof(zeros)), 0);
    ExpectIntEQ(req.nonceSz, 1);
    outSz = (word32)sizeof(out);
    ExpectIntEQ(wc_TspRequest_GetNonce(&req, out, &outSz), 0);
    ExpectIntEQ(outSz, 1);
    ExpectIntEQ(out[0], 0x00);

    /* Get: bad arguments. */
    outSz = (word32)sizeof(out);
    ExpectIntEQ(wc_TspRequest_GetNonce(NULL, out, &outSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspRequest_GetNonce(&req, NULL, &outSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspRequest_GetNonce(&req, out, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Buffer too small for the 1-byte nonce. */
    outSz = 0;
    ExpectIntEQ(wc_TspRequest_GetNonce(&req, out, &outSz),
        WC_NO_ERR_TRACE(BUFFER_E));
#endif
    return EXPECT_RESULT();
}

int test_wc_TspGenerateNonce(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER)
    WC_RNG rng;
    TspRequest req;

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_TspRequest_Init(&req), 0);

    /* Bad arguments. */
    ExpectIntEQ(wc_TspRequest_GenerateNonce(NULL, &rng, 8),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspRequest_GenerateNonce(&req, NULL, 8),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspRequest_GenerateNonce(&req, &rng, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspRequest_GenerateNonce(&req, &rng,
        MAX_TS_NONCE_SZ + 1), WC_NO_ERR_TRACE(BUFFER_E));

    /* Generates a minimal positive INTEGER nonce of the requested size. */
    ExpectIntEQ(wc_TspRequest_GenerateNonce(&req, &rng, 8), 0);
    ExpectIntEQ(req.nonceSz, 8);
    ExpectIntLT(req.nonce[0], 0x80);  /* positive - top bit clear */
    ExpectIntGT(req.nonce[0], 0x00);  /* minimal - non-zero leading byte */

    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspRequest_GetSetPolicy(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(WOLFSSL_TSP_REQUESTER)
    TspRequest req;
    /* 1.3.6.1.4.1.999.1 - OBJECT IDENTIFIER content. */
    static const byte policy[] = {
        0x2b, 0x06, 0x01, 0x04, 0x01, 0x87, 0x67, 0x01
    };
    byte big[MAX_OID_SZ + 1];
    byte out[MAX_OID_SZ];
    word32 outSz;

    XMEMSET(big, 0, sizeof(big));

    ExpectIntEQ(wc_TspRequest_Init(&req), 0);

    /* Set: bad arguments. */
    ExpectIntEQ(wc_TspRequest_SetPolicy(NULL, policy, (word32)sizeof(policy)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspRequest_SetPolicy(&req, NULL, (word32)sizeof(policy)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspRequest_SetPolicy(&req, policy, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Policy too big for the field. */
    ExpectIntEQ(wc_TspRequest_SetPolicy(&req, big, (word32)sizeof(big)),
        WC_NO_ERR_TRACE(BUFFER_E));

    /* Set and get round trips - content kept as-is, no stripping. */
    ExpectIntEQ(wc_TspRequest_SetPolicy(&req, policy, (word32)sizeof(policy)),
        0);
    ExpectIntEQ(req.policySz, (word32)sizeof(policy));
    outSz = (word32)sizeof(out);
    ExpectIntEQ(wc_TspRequest_GetPolicy(&req, out, &outSz), 0);
    ExpectIntEQ(outSz, (word32)sizeof(policy));
    ExpectBufEQ(out, policy, (int)sizeof(policy));

    /* Get: bad arguments. */
    outSz = (word32)sizeof(out);
    ExpectIntEQ(wc_TspRequest_GetPolicy(NULL, out, &outSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspRequest_GetPolicy(&req, NULL, &outSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspRequest_GetPolicy(&req, out, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Buffer too small for the policy. */
    outSz = (word32)sizeof(policy) - 1;
    ExpectIntEQ(wc_TspRequest_GetPolicy(&req, out, &outSz),
        WC_NO_ERR_TRACE(BUFFER_E));
#endif
    return EXPECT_RESULT();
}

int test_wc_TspRequest_GetSetCertReq(void)
{
    EXPECT_DECLS;
    /* The requester both sets and gets certReq - runs in a requester build. */
#if defined(WOLFSSL_TSP) && defined(WOLFSSL_TSP_REQUESTER)
    TspRequest req;

    ExpectIntEQ(wc_TspRequest_Init(&req), 0);

    /* Defaults to not requesting the TSA certificate. */
    ExpectIntEQ(wc_TspRequest_GetCertReq(&req), 0);

    /* Set requests the certificate and round trips through the getter. */
    wc_TspRequest_SetCertReq(&req, 1);
    ExpectIntEQ(wc_TspRequest_GetCertReq(&req), 1);

    /* Any non-zero value is normalized to 1. */
    wc_TspRequest_SetCertReq(&req, 5);
    ExpectIntEQ(wc_TspRequest_GetCertReq(&req), 1);
    ExpectIntEQ(req.certReq, 1);

    /* Clear the request. */
    wc_TspRequest_SetCertReq(&req, 0);
    ExpectIntEQ(wc_TspRequest_GetCertReq(&req), 0);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspRequest_Encode(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && !defined(NO_SHA256) && \
    defined(WOLFSSL_TSP_REQUESTER)
    TspRequest req;
    byte enc[256];
    word32 encSz;
    word32 sz;

    ExpectIntEQ(wc_TspRequest_Init(&req), 0);
    test_tsp_set_hash(&req.imprint);

    /* Bad arguments. */
    encSz = (word32)sizeof(enc);
    ExpectIntEQ(wc_TspRequest_Encode(NULL, enc, &encSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspRequest_Encode(&req, enc, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Message imprint required. */
    req.imprint.hashSz = 0;
    ExpectIntEQ(wc_TspRequest_Encode(&req, enc, &encSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Hash too long. */
    req.imprint.hashSz = WC_TSP_MAX_HASH_SZ + 1;
    ExpectIntEQ(wc_TspRequest_Encode(&req, enc, &encSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    req.imprint.hashSz = (word32)sizeof(tsHashedMsg);
    /* Policy too long. */
    req.policySz = MAX_OID_SZ + 1;
    ExpectIntEQ(wc_TspRequest_Encode(&req, enc, &encSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    req.policySz = 0;
    /* Unknown hash algorithm. */
    req.imprint.hashAlgOID = 1;
    ExpectIntEQ(wc_TspRequest_Encode(&req, enc, &encSz),
        WC_NO_ERR_TRACE(ASN_UNKNOWN_OID_E));
    req.imprint.hashAlgOID = SHA256h;
    /* Nonce with a leading zero byte - not allowed. */
    {
        static const byte paddedNonce[] = { 0x00, 0x13 };

        XMEMCPY(req.nonce, paddedNonce, sizeof(paddedNonce));
        req.nonceSz = (word32)sizeof(paddedNonce);
        ExpectIntEQ(wc_TspRequest_Encode(&req, enc, &encSz),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* Nonce too long - not allowed. */
        req.nonceSz = MAX_TS_NONCE_SZ + 1;
        ExpectIntEQ(wc_TspRequest_Encode(&req, enc, &encSz),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        req.nonceSz = 0;
    }

    /* Get length of encoding only. */
    encSz = 0;
    ExpectIntEQ(wc_TspRequest_Encode(&req, NULL, &encSz), 0);
    ExpectIntEQ(encSz, (word32)sizeof(tsMinReqDer));
    /* Buffer too small. */
    sz = encSz - 1;
    ExpectIntEQ(wc_TspRequest_Encode(&req, enc, &sz),
        WC_NO_ERR_TRACE(BUFFER_E));
    /* Check minimal encoding against expected DER. */
    sz = (word32)sizeof(enc);
    ExpectIntEQ(wc_TspRequest_Encode(&req, enc, &sz), 0);
    ExpectIntEQ(sz, (word32)sizeof(tsMinReqDer));
    ExpectBufEQ(enc, tsMinReqDer, (int)sizeof(tsMinReqDer));

    /* All optional fields included. */
    XMEMCPY(req.policy, tsPolicy, sizeof(tsPolicy));
    req.policySz = (word32)sizeof(tsPolicy);
    XMEMCPY(req.nonce, tsNonce, sizeof(tsNonce));
    req.nonceSz = (word32)sizeof(tsNonce);
    req.certReq = 1;
    sz = (word32)sizeof(enc);
    ExpectIntEQ(wc_TspRequest_Encode(&req, enc, &sz), 0);
    ExpectIntGT(sz, (word32)sizeof(tsMinReqDer));
#endif
    return EXPECT_RESULT();
}

int test_wc_TspRequest_Decode(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && !defined(NO_SHA256) && \
    defined(WOLFSSL_TSP_REQUESTER)
    /* Minimal TimeStampReq without NULL hash algorithm parameters. */
    static const byte noNullDer[] = {
        0x30, 0x34,
        0x02, 0x01, 0x01,
        0x30, 0x2f,
        0x30, 0x0b,
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x04, 0x20,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    TspRequest req;
    TspRequest reqDec;
    byte enc[256];
    word32 sz;

    /* Bad arguments. */
    ExpectIntEQ(wc_TspRequest_Decode(NULL, tsMinReqDer,
        (word32)sizeof(tsMinReqDer)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspRequest_Decode(&reqDec, NULL,
        (word32)sizeof(tsMinReqDer)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspRequest_Decode(&reqDec, tsMinReqDer, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Minimal request. */
    ExpectIntEQ(wc_TspRequest_Decode(&reqDec, tsMinReqDer,
        (word32)sizeof(tsMinReqDer)), 0);
    ExpectIntEQ(reqDec.version, WC_TSP_VERSION);
    ExpectIntEQ(reqDec.imprint.hashAlgOID, SHA256h);
    ExpectIntEQ(reqDec.imprint.hashSz, (word32)sizeof(tsHashedMsg));
    ExpectBufEQ(reqDec.imprint.hash, tsHashedMsg,
        (int)sizeof(tsHashedMsg));
    ExpectIntEQ(reqDec.policySz, 0);
    ExpectIntEQ(reqDec.nonceSz, 0);
    ExpectIntEQ(reqDec.certReq, 0);

    /* Hash algorithm parameters not present. */
    ExpectIntEQ(wc_TspRequest_Decode(&reqDec, noNullDer,
        (word32)sizeof(noNullDer)), 0);
    ExpectIntEQ(reqDec.imprint.hashAlgOID, SHA256h);

    /* Truncated encoding. */
    ExpectIntLT(wc_TspRequest_Decode(&reqDec, tsMinReqDer,
        (word32)sizeof(tsMinReqDer) - 1), 0);
    /* Trailing data not allowed. */
    XMEMCPY(enc, tsMinReqDer, sizeof(tsMinReqDer));
    enc[sizeof(tsMinReqDer)] = 0x00;
    ExpectIntLT(wc_TspRequest_Decode(&reqDec, enc,
        (word32)sizeof(tsMinReqDer) + 1), 0);

    /* Request with extensions is not supported. */
    {
        static const byte extsReqDer[] = {
            0x30, 0x45,                                     /* TimeStampReq */
            0x02, 0x01, 0x01,                               /* version 1 */
            0x30, 0x31,                                     /* messageImprint */
            0x30, 0x0d,                                     /* hashAlgorithm */
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, /* sha256 */
            0x04, 0x02, 0x01,
            0x05, 0x00,                                     /* NULL */
            0x04, 0x20,                                     /* hashedMessage */
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            0xa0, 0x0d,                                     /* extensions */
            0x30, 0x0b, 0x06, 0x02, 0x2a, 0x03,             /* OID 1.2.3 */
            0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05        /* value */
        };

        ExpectIntEQ(wc_TspRequest_Decode(&reqDec, extsReqDer,
            (word32)sizeof(extsReqDer)), WC_NO_ERR_TRACE(ASN_PARSE_E));
    }

    /* Request with an empty hash is invalid. */
    {
        static const byte emptyHashDer[] = {
            0x30, 0x16,                                     /* TimeStampReq */
            0x02, 0x01, 0x01,                               /* version 1 */
            0x30, 0x11,                                     /* messageImprint */
            0x30, 0x0d,                                     /* hashAlgorithm */
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, /* sha256 */
            0x04, 0x02, 0x01,
            0x05, 0x00,                                     /* NULL */
            0x04, 0x00                                      /* hashedMessage */
        };

        ExpectIntEQ(wc_TspRequest_Decode(&reqDec, emptyHashDer,
            (word32)sizeof(emptyHashDer)), WC_NO_ERR_TRACE(ASN_PARSE_E));
    }

    /* Request with an unsupported version is rejected - RFC 3161, 2.4.1. */
    {
        /* tsMinReqDer with the version INTEGER changed from 1 to 2. */
        XMEMCPY(enc, tsMinReqDer, sizeof(tsMinReqDer));
        enc[4] = 0x02;                                  /* version = 2 */
        ExpectIntEQ(wc_TspRequest_Decode(&reqDec, enc,
            (word32)sizeof(tsMinReqDer)), WC_NO_ERR_TRACE(ASN_VERSION_E));
        enc[4] = 0x00;                                  /* version = 0 */
        ExpectIntEQ(wc_TspRequest_Decode(&reqDec, enc,
            (word32)sizeof(tsMinReqDer)), WC_NO_ERR_TRACE(ASN_VERSION_E));
    }

    /* Nonce of zero is one zero byte. */
    {
        static const byte zeroNonce[] = { 0x00 };

        ExpectIntEQ(wc_TspRequest_Init(&req), 0);
        test_tsp_set_hash(&req.imprint);
        XMEMCPY(req.nonce, zeroNonce, sizeof(zeroNonce));
        req.nonceSz = (word32)sizeof(zeroNonce);
        sz = (word32)sizeof(enc);
        ExpectIntEQ(wc_TspRequest_Encode(&req, enc, &sz), 0);
        ExpectIntEQ(wc_TspRequest_Decode(&reqDec, enc, sz), 0);
        ExpectIntEQ(reqDec.nonceSz, 1);
        if (EXPECT_SUCCESS()) {
            ExpectIntEQ(reqDec.nonce[0], 0x00);
        }
    }

    /* Round trip all optional fields. */
    ExpectIntEQ(wc_TspRequest_Init(&req), 0);
    test_tsp_set_hash(&req.imprint);
    XMEMCPY(req.policy, tsPolicy, sizeof(tsPolicy));
    req.policySz = (word32)sizeof(tsPolicy);
    XMEMCPY(req.nonce, tsNonce, sizeof(tsNonce));
    req.nonceSz = (word32)sizeof(tsNonce);
    req.certReq = 1;
    sz = (word32)sizeof(enc);
    ExpectIntEQ(wc_TspRequest_Encode(&req, enc, &sz), 0);
    ExpectIntEQ(wc_TspRequest_Decode(&reqDec, enc, sz), 0);
    ExpectIntEQ(reqDec.policySz, (word32)sizeof(tsPolicy));
    ExpectBufEQ(reqDec.policy, tsPolicy, (int)sizeof(tsPolicy));
    ExpectIntEQ(reqDec.nonceSz, (word32)sizeof(tsNonce));
    ExpectBufEQ(reqDec.nonce, tsNonce, (int)sizeof(tsNonce));
    ExpectIntEQ(reqDec.certReq, 1);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_Init(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(WOLFSSL_TSP_RESPONDER)
    TspTstInfo tst;

    ExpectIntEQ(wc_TspTstInfo_Init(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    XMEMSET(&tst, 0xa5, sizeof(TspTstInfo));
    ExpectIntEQ(wc_TspTstInfo_Init(&tst), 0);
    ExpectIntEQ(tst.version, WC_TSP_VERSION);
    ExpectNull(tst.policy);
    ExpectNull(tst.serial);
    ExpectNull(tst.genTime);
    ExpectIntEQ(tst.accuracy.seconds, 0);
    ExpectIntEQ(tst.ordering, 0);
    ExpectNull(tst.nonce);
    ExpectNull(tst.tsa);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_GetSetSerial(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    TspTstInfo tst;
    static const byte serial[] = { 0x9a, 0x33, 0x10 };
    static const byte padded[] = { 0x00, 0x00, 0x9a, 0x33 };
    static const byte zeros[] = { 0x00, 0x00, 0x00 };
    const byte* out = NULL;
    word32 outSz = 0;

    ExpectIntEQ(wc_TspTstInfo_Init(&tst), 0);

    /* No serial on a freshly initialized TSTInfo - Get reports it absent. */
    out = serial;
    outSz = 99;
    ExpectIntEQ(wc_TspTstInfo_GetSerial(&tst, &out, &outSz), 0);
    ExpectNull(out);
    ExpectIntEQ(outSz, 0);

    /* Set: bad arguments. */
    ExpectIntEQ(wc_TspTstInfo_SetSerial(NULL, serial, (word32)sizeof(serial)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_SetSerial(&tst, NULL, (word32)sizeof(serial)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_SetSerial(&tst, serial, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* No leading zeros - referenced as-is and round trips. */
    ExpectIntEQ(wc_TspTstInfo_SetSerial(&tst, serial, (word32)sizeof(serial)),
        0);
    ExpectIntEQ(wc_TspTstInfo_GetSerial(&tst, &out, &outSz), 0);
    ExpectPtrEq(out, serial);
    ExpectIntEQ(outSz, (word32)sizeof(serial));

    /* Leading zero bytes are stripped - references past them. */
    ExpectIntEQ(wc_TspTstInfo_SetSerial(&tst, padded, (word32)sizeof(padded)),
        0);
    ExpectIntEQ(wc_TspTstInfo_GetSerial(&tst, &out, &outSz), 0);
    ExpectPtrEq(out, padded + 2);
    ExpectIntEQ(outSz, 2);
    ExpectIntEQ(out[0], 0x9a);
    ExpectIntEQ(out[1], 0x33);

    /* All zeros becomes a single zero byte. */
    ExpectIntEQ(wc_TspTstInfo_SetSerial(&tst, zeros, (word32)sizeof(zeros)), 0);
    ExpectIntEQ(wc_TspTstInfo_GetSerial(&tst, &out, &outSz), 0);
    ExpectPtrEq(out, zeros + 2);
    ExpectIntEQ(outSz, 1);
    ExpectIntEQ(out[0], 0x00);

    /* Get: bad arguments. */
    ExpectIntEQ(wc_TspTstInfo_GetSerial(NULL, &out, &outSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_GetSerial(&tst, NULL, &outSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_GetSerial(&tst, &out, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_TSP) && !defined(NO_SHA256) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
/* Fill a TSTInfo with the required fields. */
static void test_tsp_set_tstinfo(TspTstInfo* tst)
{
    (void)wc_TspTstInfo_Init(tst);
    tst->policy = tsPolicy;
    tst->policySz = (word32)sizeof(tsPolicy);
    test_tsp_set_hash(&tst->imprint);
    tst->serial = tsSerial;
    tst->serialSz = (word32)sizeof(tsSerial);
    tst->genTime = tsGenTime;
    tst->genTimeSz = (word32)sizeof(tsGenTime) - 1;
}
#endif

int test_wc_TspTstInfo_Getters(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && !defined(NO_SHA256) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    TspTstInfo tst;
    const byte* out = NULL;
    word32 outSz = 0;
    word32 hashOID = 0;
    word32 seconds = 0;
    word16 millis = 0;
    word16 micros = 0;

    test_tsp_set_tstinfo(&tst);
    tst.accuracy.seconds = 1;
    tst.accuracy.millis = 500;
    tst.accuracy.micros = 250;
    tst.nonce = tsNonce;
    tst.nonceSz = (word32)sizeof(tsNonce);
    tst.tsa = tsTsaName;
    tst.tsaSz = (word32)sizeof(tsTsaName);

    /* Policy. */
    ExpectIntEQ(wc_TspTstInfo_GetPolicy(&tst, &out, &outSz), 0);
    ExpectPtrEq(out, tsPolicy);
    ExpectIntEQ(outSz, (word32)sizeof(tsPolicy));
    /* Message imprint. */
    ExpectIntEQ(wc_TspTstInfo_GetMsgImprint(&tst, &hashOID, &out, &outSz), 0);
    ExpectIntEQ(hashOID, SHA256h);
    ExpectIntEQ(outSz, (word32)sizeof(tsHashedMsg));
    ExpectBufEQ(out, tsHashedMsg, (int)sizeof(tsHashedMsg));
    /* All message imprint outputs are optional. */
    ExpectIntEQ(wc_TspTstInfo_GetMsgImprint(&tst, NULL, NULL, NULL), 0);
    /* Time of the time-stamp. */
    ExpectIntEQ(wc_TspTstInfo_GetGenTime(&tst, &out, &outSz), 0);
    ExpectPtrEq(out, tsGenTime);
    ExpectIntEQ(outSz, (word32)sizeof(tsGenTime) - 1);
    /* Accuracy. */
    ExpectIntEQ(wc_TspTstInfo_GetAccuracy(&tst, &seconds, &millis, &micros), 0);
    ExpectIntEQ(seconds, 1);
    ExpectIntEQ(millis, 500);
    ExpectIntEQ(micros, 250);
    /* All accuracy outputs are optional. */
    ExpectIntEQ(wc_TspTstInfo_GetAccuracy(&tst, NULL, NULL, NULL), 0);
    /* Nonce. */
    ExpectIntEQ(wc_TspTstInfo_GetNonce(&tst, &out, &outSz), 0);
    ExpectPtrEq(out, tsNonce);
    ExpectIntEQ(outSz, (word32)sizeof(tsNonce));
    /* TSA name. */
    ExpectIntEQ(wc_TspTstInfo_GetTsa(&tst, &out, &outSz), 0);
    ExpectPtrEq(out, tsTsaName);
    ExpectIntEQ(outSz, (word32)sizeof(tsTsaName));

    /* On a freshly initialized TSTInfo the optional fields are absent - the
     * getters succeed and report empty values, not an error. */
    ExpectIntEQ(wc_TspTstInfo_Init(&tst), 0);
    out = tsPolicy;
    outSz = 99;
    ExpectIntEQ(wc_TspTstInfo_GetPolicy(&tst, &out, &outSz), 0);
    ExpectNull(out);
    ExpectIntEQ(outSz, 0);
    out = tsGenTime;
    outSz = 99;
    ExpectIntEQ(wc_TspTstInfo_GetGenTime(&tst, &out, &outSz), 0);
    ExpectNull(out);
    ExpectIntEQ(outSz, 0);
    out = tsNonce;
    outSz = 99;
    ExpectIntEQ(wc_TspTstInfo_GetNonce(&tst, &out, &outSz), 0);
    ExpectNull(out);
    ExpectIntEQ(outSz, 0);
    out = tsTsaName;
    outSz = 99;
    ExpectIntEQ(wc_TspTstInfo_GetTsa(&tst, &out, &outSz), 0);
    ExpectNull(out);
    ExpectIntEQ(outSz, 0);
    hashOID = 99;
    outSz = 99;
    ExpectIntEQ(wc_TspTstInfo_GetMsgImprint(&tst, &hashOID, &out, &outSz), 0);
    ExpectIntEQ(hashOID, 0);
    ExpectIntEQ(outSz, 0);
    seconds = 99;
    millis = 99;
    micros = 99;
    ExpectIntEQ(wc_TspTstInfo_GetAccuracy(&tst, &seconds, &millis, &micros), 0);
    ExpectIntEQ(seconds, 0);
    ExpectIntEQ(millis, 0);
    ExpectIntEQ(micros, 0);

    /* Bad arguments. */
    ExpectIntEQ(wc_TspTstInfo_GetPolicy(NULL, &out, &outSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_GetPolicy(&tst, NULL, &outSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_GetPolicy(&tst, &out, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_GetMsgImprint(NULL, &hashOID, &out, &outSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_GetGenTime(NULL, &out, &outSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_GetGenTime(&tst, NULL, &outSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_GetGenTime(&tst, &out, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_GetAccuracy(NULL, &seconds, &millis, &micros),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_GetNonce(NULL, &out, &outSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_GetNonce(&tst, NULL, &outSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_GetNonce(&tst, &out, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_GetTsa(NULL, &out, &outSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_GetTsa(&tst, NULL, &outSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_GetTsa(&tst, &out, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_Setters(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    TspTstInfo tst;
    /* 1.3.6.1.4.1.999.1 - OBJECT IDENTIFIER content. */
    static const byte policy[] = {
        0x2b, 0x06, 0x01, 0x04, 0x01, 0x87, 0x67, 0x01
    };
    static const byte hash[] = { 0xde, 0xad, 0xbe, 0xef };
    static const byte genTime[] = "20260610120000Z";
    static const byte nonce[] = { 0x12, 0x34 };
    /* Name of TSA: dNSName GeneralName. */
    static const byte tsa[] = { 0x82, 0x03, 't', 's', 'a' };
    static const byte padded[] = { 0x00, 0x00, 0x12, 0x34 };
    byte bigHash[WC_TSP_MAX_HASH_SZ + 1];
    const byte* out = NULL;
    word32 outSz = 0;
    word32 hashOID = 0;
    word32 seconds = 0;
    word16 millis = 0;
    word16 micros = 0;

    XMEMSET(bigHash, 0, sizeof(bigHash));
    ExpectIntEQ(wc_TspTstInfo_Init(&tst), 0);

    /* Policy - referenced, round trips through the getter. */
    ExpectIntEQ(wc_TspTstInfo_SetPolicy(NULL, policy, (word32)sizeof(policy)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_SetPolicy(&tst, NULL, (word32)sizeof(policy)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_SetPolicy(&tst, policy, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_SetPolicy(&tst, policy, (word32)sizeof(policy)),
        0);
    ExpectIntEQ(wc_TspTstInfo_GetPolicy(&tst, &out, &outSz), 0);
    ExpectPtrEq(out, policy);
    ExpectIntEQ(outSz, (word32)sizeof(policy));

    /* Message imprint - copied, too big rejected, round trips. */
    ExpectIntEQ(wc_TspTstInfo_SetMsgImprint(NULL, SHA256h, hash,
        (word32)sizeof(hash)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_SetMsgImprint(&tst, SHA256h, NULL,
        (word32)sizeof(hash)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_SetMsgImprint(&tst, SHA256h, hash, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_SetMsgImprint(&tst, SHA256h, bigHash,
        (word32)sizeof(bigHash)), WC_NO_ERR_TRACE(BUFFER_E));
    ExpectIntEQ(wc_TspTstInfo_SetMsgImprint(&tst, SHA256h, hash,
        (word32)sizeof(hash)), 0);
    ExpectIntEQ(wc_TspTstInfo_GetMsgImprint(&tst, &hashOID, &out, &outSz), 0);
    ExpectIntEQ(hashOID, SHA256h);
    ExpectIntEQ(outSz, (word32)sizeof(hash));
    ExpectBufEQ(out, hash, (int)sizeof(hash));

    /* Time of the time-stamp - referenced, round trips. */
    ExpectIntEQ(wc_TspTstInfo_SetGenTime(NULL, genTime,
        (word32)sizeof(genTime) - 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_SetGenTime(&tst, NULL,
        (word32)sizeof(genTime) - 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_SetGenTime(&tst, genTime, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_SetGenTime(&tst, genTime,
        (word32)sizeof(genTime) - 1), 0);
    ExpectIntEQ(wc_TspTstInfo_GetGenTime(&tst, &out, &outSz), 0);
    ExpectPtrEq(out, genTime);
    ExpectIntEQ(outSz, (word32)sizeof(genTime) - 1);

    /* Accuracy - values round trip. */
    ExpectIntEQ(wc_TspTstInfo_SetAccuracy(NULL, 1, 500, 250),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_SetAccuracy(&tst, 1, 500, 250), 0);
    ExpectIntEQ(wc_TspTstInfo_GetAccuracy(&tst, &seconds, &millis, &micros), 0);
    ExpectIntEQ(seconds, 1);
    ExpectIntEQ(millis, 500);
    ExpectIntEQ(micros, 250);

    /* Nonce - referenced, leading zeros stripped, round trips. */
    ExpectIntEQ(wc_TspTstInfo_SetNonce(NULL, nonce, (word32)sizeof(nonce)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_SetNonce(&tst, NULL, (word32)sizeof(nonce)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_SetNonce(&tst, nonce, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_SetNonce(&tst, nonce, (word32)sizeof(nonce)), 0);
    ExpectIntEQ(wc_TspTstInfo_GetNonce(&tst, &out, &outSz), 0);
    ExpectPtrEq(out, nonce);
    ExpectIntEQ(outSz, (word32)sizeof(nonce));
    ExpectIntEQ(wc_TspTstInfo_SetNonce(&tst, padded, (word32)sizeof(padded)),
        0);
    ExpectIntEQ(wc_TspTstInfo_GetNonce(&tst, &out, &outSz), 0);
    ExpectPtrEq(out, padded + 2);
    ExpectIntEQ(outSz, 2);

    /* TSA name - referenced, round trips. */
    ExpectIntEQ(wc_TspTstInfo_SetTsa(NULL, tsa, (word32)sizeof(tsa)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_SetTsa(&tst, NULL, (word32)sizeof(tsa)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_SetTsa(&tst, tsa, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_SetTsa(&tst, tsa, (word32)sizeof(tsa)), 0);
    ExpectIntEQ(wc_TspTstInfo_GetTsa(&tst, &out, &outSz), 0);
    ExpectPtrEq(out, tsa);
    ExpectIntEQ(outSz, (word32)sizeof(tsa));
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_Encode(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && !defined(NO_SHA256) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    TspTstInfo tst;
    TspTstInfo tstDec;
    byte enc[256];
    word32 encSz;
    word32 sz;

    test_tsp_set_tstinfo(&tst);

    /* Bad arguments. */
    encSz = (word32)sizeof(enc);
    ExpectIntEQ(wc_TspTstInfo_Encode(NULL, enc, &encSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_Encode(&tst, enc, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Required fields. */
    tst.policy = NULL;
    ExpectIntEQ(wc_TspTstInfo_Encode(&tst, enc, &encSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    tst.policy = tsPolicy;
    /* Empty policy - not allowed. */
    tst.policySz = 0;
    ExpectIntEQ(wc_TspTstInfo_Encode(&tst, enc, &encSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    tst.policySz = (word32)sizeof(tsPolicy);
    /* Empty genTime - not allowed. */
    tst.genTimeSz = 0;
    ExpectIntEQ(wc_TspTstInfo_Encode(&tst, enc, &encSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* genTime must end in Z. */
    tst.genTime = (const byte*)"20260604120000";
    tst.genTimeSz = 14;
    ExpectIntEQ(wc_TspTstInfo_Encode(&tst, enc, &encSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* genTime fraction of seconds must not have a trailing zero. */
    tst.genTime = (const byte*)"20260604120000.50Z";
    tst.genTimeSz = 18;
    ExpectIntEQ(wc_TspTstInfo_Encode(&tst, enc, &encSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* genTime fraction of seconds must not be empty. */
    tst.genTime = (const byte*)"20260604120000.Z";
    tst.genTimeSz = 16;
    ExpectIntEQ(wc_TspTstInfo_Encode(&tst, enc, &encSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* genTime with a fraction of seconds is valid. */
    tst.genTime = (const byte*)"20260604120000.5Z";
    tst.genTimeSz = 17;
    ExpectIntEQ(wc_TspTstInfo_Encode(&tst, enc, &encSz), 0);
    encSz = (word32)sizeof(enc);
    tst.genTime = tsGenTime;
    tst.genTimeSz = (word32)sizeof(tsGenTime) - 1;
    /* Empty TSA name - not allowed. */
    tst.tsa = tsTsaName;
    tst.tsaSz = 0;
    ExpectIntEQ(wc_TspTstInfo_Encode(&tst, enc, &encSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    tst.tsa = NULL;
    tst.imprint.hashSz = 0;
    ExpectIntEQ(wc_TspTstInfo_Encode(&tst, enc, &encSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Hash too long. */
    tst.imprint.hashSz = WC_TSP_MAX_HASH_SZ + 1;
    ExpectIntEQ(wc_TspTstInfo_Encode(&tst, enc, &encSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    tst.imprint.hashSz = (word32)sizeof(tsHashedMsg);
    tst.serial = NULL;
    ExpectIntEQ(wc_TspTstInfo_Encode(&tst, enc, &encSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    tst.serial = tsSerial;
    /* Serial number and nonce with a leading zero byte - not allowed. */
    {
        static const byte paddedNum[] = { 0x00, 0x13 };

        tst.serial = paddedNum;
        tst.serialSz = (word32)sizeof(paddedNum);
        ExpectIntEQ(wc_TspTstInfo_Encode(&tst, enc, &encSz),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* Empty serial number - not allowed. */
        tst.serialSz = 0;
        ExpectIntEQ(wc_TspTstInfo_Encode(&tst, enc, &encSz),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        tst.serial = tsSerial;
        tst.serialSz = (word32)sizeof(tsSerial);
        tst.nonce = paddedNum;
        tst.nonceSz = (word32)sizeof(paddedNum);
        ExpectIntEQ(wc_TspTstInfo_Encode(&tst, enc, &encSz),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        tst.nonce = NULL;
        tst.nonceSz = 0;
    }
    /* Accuracy range. */
    tst.accuracy.millis = 1000;
    ExpectIntEQ(wc_TspTstInfo_Encode(&tst, enc, &encSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    tst.accuracy.millis = 0;
    tst.accuracy.micros = 1000;
    ExpectIntEQ(wc_TspTstInfo_Encode(&tst, enc, &encSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    tst.accuracy.micros = 0;
    /* Unknown hash algorithm. */
    tst.imprint.hashAlgOID = 1;
    ExpectIntEQ(wc_TspTstInfo_Encode(&tst, enc, &encSz),
        WC_NO_ERR_TRACE(ASN_UNKNOWN_OID_E));
    tst.imprint.hashAlgOID = SHA256h;

    /* Get length of encoding only. */
    encSz = 0;
    ExpectIntEQ(wc_TspTstInfo_Encode(&tst, NULL, &encSz), 0);
    ExpectIntGT(encSz, 0);
    /* Buffer too small. */
    sz = encSz - 1;
    ExpectIntEQ(wc_TspTstInfo_Encode(&tst, enc, &sz),
        WC_NO_ERR_TRACE(BUFFER_E));
    /* Minimal TSTInfo round trip. */
    sz = (word32)sizeof(enc);
    ExpectIntEQ(wc_TspTstInfo_Encode(&tst, enc, &sz), 0);
    ExpectIntEQ(sz, encSz);
    ExpectIntEQ(wc_TspTstInfo_Decode(&tstDec, enc, sz), 0);
    ExpectIntEQ(tstDec.accuracy.seconds, 0);
    ExpectIntEQ(tstDec.accuracy.millis, 0);
    ExpectIntEQ(tstDec.accuracy.micros, 0);
    ExpectIntEQ(tstDec.ordering, 0);
    ExpectNull(tstDec.nonce);
    ExpectNull(tstDec.tsa);

    /* Accuracy values that need 2 bytes and a leading zero byte. */
    tst.accuracy.seconds = 70000;
    tst.accuracy.millis = 128;
    tst.accuracy.micros = 999;
    /* All optional fields included. */
    tst.ordering = 1;
    tst.nonce = tsNonce;
    tst.nonceSz = (word32)sizeof(tsNonce);
    tst.tsa = tsTsaName;
    tst.tsaSz = (word32)sizeof(tsTsaName);
    sz = (word32)sizeof(enc);
    ExpectIntEQ(wc_TspTstInfo_Encode(&tst, enc, &sz), 0);
    ExpectIntEQ(wc_TspTstInfo_Decode(&tstDec, enc, sz), 0);
    ExpectIntEQ(tstDec.accuracy.seconds, 70000);
    ExpectIntEQ(tstDec.accuracy.millis, 128);
    ExpectIntEQ(tstDec.accuracy.micros, 999);
    ExpectIntEQ(tstDec.ordering, 1);

    /* Accuracy with only seconds. */
    tst.accuracy.seconds = 1;
    tst.accuracy.millis = 0;
    tst.accuracy.micros = 0;
    sz = (word32)sizeof(enc);
    ExpectIntEQ(wc_TspTstInfo_Encode(&tst, enc, &sz), 0);
    ExpectIntEQ(wc_TspTstInfo_Decode(&tstDec, enc, sz), 0);
    ExpectIntEQ(tstDec.accuracy.seconds, 1);
    ExpectIntEQ(tstDec.accuracy.millis, 0);
    ExpectIntEQ(tstDec.accuracy.micros, 0);

    /* Accuracy with only millis. */
    tst.accuracy.seconds = 0;
    tst.accuracy.millis = 500;
    tst.accuracy.micros = 0;
    sz = (word32)sizeof(enc);
    ExpectIntEQ(wc_TspTstInfo_Encode(&tst, enc, &sz), 0);
    ExpectIntEQ(wc_TspTstInfo_Decode(&tstDec, enc, sz), 0);
    ExpectIntEQ(tstDec.accuracy.seconds, 0);
    ExpectIntEQ(tstDec.accuracy.millis, 500);
    ExpectIntEQ(tstDec.accuracy.micros, 0);

    /* Accuracy seconds needing a zero byte to be positive. */
    tst.accuracy.seconds = 200;
    tst.accuracy.millis = 0;
    sz = (word32)sizeof(enc);
    ExpectIntEQ(wc_TspTstInfo_Encode(&tst, enc, &sz), 0);
    ExpectIntEQ(wc_TspTstInfo_Decode(&tstDec, enc, sz), 0);
    ExpectIntEQ(tstDec.accuracy.seconds, 200);
    /* Accuracy seconds of the maximum encoding length. */
    tst.accuracy.seconds = 0x80000000UL;
    sz = (word32)sizeof(enc);
    ExpectIntEQ(wc_TspTstInfo_Encode(&tst, enc, &sz), 0);
    ExpectIntEQ(wc_TspTstInfo_Decode(&tstDec, enc, sz), 0);
    ExpectIntEQ(tstDec.accuracy.seconds, 0x80000000UL);

#if !defined(NO_ASN_TIME) && !defined(USER_TIME) && !defined(TIME_OVERRIDES)
    /* Use current time when genTime not set. */
    tst.genTime = NULL;
    tst.genTimeSz = 0;
    sz = (word32)sizeof(enc);
    ExpectIntEQ(wc_TspTstInfo_Encode(&tst, enc, &sz), 0);
    ExpectIntEQ(wc_TspTstInfo_Decode(&tstDec, enc, sz), 0);
    ExpectIntGE(tstDec.genTimeSz, 15);
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(tstDec.genTime[tstDec.genTimeSz - 1], 'Z');
    }
#endif
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_Decode(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && !defined(NO_SHA256) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    TspTstInfo tst;
    TspTstInfo tstDec;
    byte enc[256];
    word32 sz;

    test_tsp_set_tstinfo(&tst);
    sz = (word32)sizeof(enc);
    ExpectIntEQ(wc_TspTstInfo_Encode(&tst, enc, &sz), 0);

    /* Bad arguments. */
    ExpectIntEQ(wc_TspTstInfo_Decode(NULL, enc, sz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_Decode(&tstDec, NULL, sz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_Decode(&tstDec, enc, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Truncated encoding. */
    ExpectIntLT(wc_TspTstInfo_Decode(&tstDec, enc, sz - 1), 0);
    /* Trailing data not allowed. */
    enc[sz] = 0x00;
    ExpectIntLT(wc_TspTstInfo_Decode(&tstDec, enc, sz + 1), 0);

    /* TSTInfo with extensions is not supported. */
    {
        static const byte extsTstDer[] = {
            0x30, 0x62,                                     /* TSTInfo */
            0x02, 0x01, 0x01,                               /* version 1 */
            0x06, 0x08,                                     /* policy */
            0x2b, 0x06, 0x01, 0x04, 0x01, 0x87, 0x67, 0x01,
            0x30, 0x31,                                     /* messageImprint */
            0x30, 0x0d,                                     /* hashAlgorithm */
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, /* sha256 */
            0x04, 0x02, 0x01,
            0x05, 0x00,                                     /* NULL */
            0x04, 0x20,                                     /* hashedMessage */
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            0x02, 0x02, 0x9a, 0x33,                         /* serialNumber */
            0x18, 0x0f,                                     /* genTime */
            '2', '0', '2', '6', '0', '6', '0', '4',
            '1', '2', '0', '0', '0', '0', 'Z',
            0xa1, 0x0b,                                     /* extensions */
            0x30, 0x09, 0x06, 0x02, 0x2a, 0x03,             /* OID 1.2.3 */
            0x04, 0x03, 0x01, 0x02, 0x03                    /* value */
        };

        ExpectIntEQ(wc_TspTstInfo_Decode(&tstDec, extsTstDer,
            (word32)sizeof(extsTstDer)), WC_NO_ERR_TRACE(ASN_PARSE_E));
    }

    /* Accuracy millis and micros must be 1..999 when present. */
    {
        static const byte accTstDer[] = {
            0x30, 0x5b,                                     /* TSTInfo */
            0x02, 0x01, 0x01,                               /* version 1 */
            0x06, 0x08,                                     /* policy */
            0x2b, 0x06, 0x01, 0x04, 0x01, 0x87, 0x67, 0x01,
            0x30, 0x31,                                     /* messageImprint */
            0x30, 0x0d,                                     /* hashAlgorithm */
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, /* sha256 */
            0x04, 0x02, 0x01,
            0x05, 0x00,                                     /* NULL */
            0x04, 0x20,                                     /* hashedMessage */
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            0x02, 0x02, 0x9a, 0x33,                         /* serialNumber */
            0x18, 0x0f,                                     /* genTime */
            '2', '0', '2', '6', '0', '6', '0', '4',
            '1', '2', '0', '0', '0', '0', 'Z',
            0x30, 0x04,                                     /* accuracy */
            0x80, 0x02, 0x03, 0xe7                          /* millis 999 */
        };
        byte accEnc[sizeof(accTstDer)];

        XMEMCPY(accEnc, accTstDer, sizeof(accTstDer));
        /* Maximum millis value decodes. */
        ExpectIntEQ(wc_TspTstInfo_Decode(&tstDec, accEnc,
            (word32)sizeof(accEnc)), 0);
        ExpectIntEQ(tstDec.accuracy.millis, 999);
        /* millis of 1000 - out of range. */
        accEnc[sizeof(accEnc) - 1] = 0xe8;
        ExpectIntEQ(wc_TspTstInfo_Decode(&tstDec, accEnc,
            (word32)sizeof(accEnc)), WC_NO_ERR_TRACE(ASN_PARSE_E));
        /* micros of 1000 - out of range. */
        accEnc[sizeof(accEnc) - 4] = 0x81;
        ExpectIntEQ(wc_TspTstInfo_Decode(&tstDec, accEnc,
            (word32)sizeof(accEnc)), WC_NO_ERR_TRACE(ASN_PARSE_E));
        /* micros of zero - out of range. */
        accEnc[sizeof(accEnc) - 2] = 0x00;
        accEnc[sizeof(accEnc) - 1] = 0x00;
        ExpectIntEQ(wc_TspTstInfo_Decode(&tstDec, accEnc,
            (word32)sizeof(accEnc)), WC_NO_ERR_TRACE(ASN_PARSE_E));
        /* genTime not ending in Z - invalid. */
        XMEMCPY(accEnc, accTstDer, sizeof(accTstDer));
        accEnc[sizeof(accEnc) - 7] = '0';
        ExpectIntEQ(wc_TspTstInfo_Decode(&tstDec, accEnc,
            (word32)sizeof(accEnc)), WC_NO_ERR_TRACE(ASN_PARSE_E));
    }

    /* Check decoded fields. */
    ExpectIntEQ(wc_TspTstInfo_Decode(&tstDec, enc, sz), 0);
    ExpectIntEQ(tstDec.version, WC_TSP_VERSION);
    ExpectIntEQ(tstDec.policySz, (word32)sizeof(tsPolicy));
    ExpectBufEQ(tstDec.policy, tsPolicy, (int)sizeof(tsPolicy));
    ExpectIntEQ(tstDec.imprint.hashAlgOID, SHA256h);
    ExpectIntEQ(tstDec.imprint.hashSz, (word32)sizeof(tsHashedMsg));
    ExpectBufEQ(tstDec.imprint.hash, tsHashedMsg,
        (int)sizeof(tsHashedMsg));
    ExpectIntEQ(tstDec.serialSz, (word32)sizeof(tsSerial));
    ExpectBufEQ(tstDec.serial, tsSerial, (int)sizeof(tsSerial));
    ExpectIntEQ(tstDec.genTimeSz, (word32)sizeof(tsGenTime) - 1);
    ExpectBufEQ(tstDec.genTime, tsGenTime, (int)sizeof(tsGenTime) - 1);

    /* Round trip the tsa field. */
    tst.tsa = tsTsaName;
    tst.tsaSz = (word32)sizeof(tsTsaName);
    sz = (word32)sizeof(enc);
    ExpectIntEQ(wc_TspTstInfo_Encode(&tst, enc, &sz), 0);
    ExpectIntEQ(wc_TspTstInfo_Decode(&tstDec, enc, sz), 0);
    ExpectIntEQ(tstDec.tsaSz, (word32)sizeof(tsTsaName));
    ExpectBufEQ(tstDec.tsa, tsTsaName, (int)sizeof(tsTsaName));
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_CheckGenTime(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && !defined(NO_SHA256) && !defined(NO_ASN_TIME) && \
    !defined(USER_TIME) && !defined(TIME_OVERRIDES) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    TspTstInfo tst;
    TspTstInfo tstDec;
    byte enc[256];
    word32 sz = (word32)sizeof(enc);

    /* TSTInfo with the current time. */
    test_tsp_set_tstinfo(&tst);
    tst.genTime = NULL;
    tst.genTimeSz = 0;
    ExpectIntEQ(wc_TspTstInfo_Encode(&tst, enc, &sz), 0);
    ExpectIntEQ(wc_TspTstInfo_Decode(&tstDec, enc, sz), 0);

    /* Bad arguments. */
    ExpectIntEQ(wc_TspTstInfo_CheckGenTime(NULL, 10),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_CheckGenTime(&tst, 10),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* The current time is within tolerance. */
    ExpectIntEQ(wc_TspTstInfo_CheckGenTime(&tstDec, 10), 0);

    /* A time in the past is not. */
    tst.genTime = (const byte*)"19700101000000Z";
    tst.genTimeSz = 15;
    ExpectIntEQ(wc_TspTstInfo_CheckGenTime(&tst, 60),
        WC_NO_ERR_TRACE(TSP_VERIFY_E));
    /* A time in the future is not. */
    tst.genTime = (const byte*)"20990101000000Z";
    ExpectIntEQ(wc_TspTstInfo_CheckGenTime(&tst, 60),
        WC_NO_ERR_TRACE(TSP_VERIFY_E));
    /* An invalid time string. */
    tst.genTimeSz = 14;
    ExpectIntEQ(wc_TspTstInfo_CheckGenTime(&tst, 60),
        WC_NO_ERR_TRACE(ASN_PARSE_E));
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_GetSetGenTimeAsTime(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && !defined(NO_ASN_TIME) && \
    defined(WOLFSSL_TSP_VERIFIER) && defined(WOLFSSL_TSP_RESPONDER)
    TspTstInfo tst;
    byte buf[ASN_GENERALIZED_TIME_SIZE];
    const byte* out = NULL;
    word32 outSz = 0;
    time_t t = 0;

    ExpectIntEQ(wc_TspTstInfo_Init(&tst), 0);

    /* Set: bad arguments. */
    ExpectIntEQ(wc_TspTstInfo_SetGenTimeAsTime(NULL, 0, buf,
        (word32)sizeof(buf)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_SetGenTimeAsTime(&tst, 0, NULL,
        (word32)sizeof(buf)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Buffer too small for the GeneralizedTime string. */
    ExpectIntEQ(wc_TspTstInfo_SetGenTimeAsTime(&tst, 0, buf,
        ASN_GENERALIZED_TIME_SIZE - 1), WC_NO_ERR_TRACE(BUFFER_E));

    /* The Unix epoch formats as a known GeneralizedTime and references buf. */
    ExpectIntEQ(wc_TspTstInfo_SetGenTimeAsTime(&tst, 0, buf,
        (word32)sizeof(buf)), 0);
    ExpectIntEQ(wc_TspTstInfo_GetGenTime(&tst, &out, &outSz), 0);
    ExpectPtrEq(out, buf);
    ExpectIntEQ(outSz, 15);
    ExpectBufEQ(out, "19700101000000Z", 15);
    /* Get round trips back to the time_t. */
    ExpectIntEQ(wc_TspTstInfo_GetGenTimeAsTime(&tst, &t), 0);
    ExpectIntEQ((long)t, 0);

    /* A later time round trips through set then get. */
    ExpectIntEQ(wc_TspTstInfo_SetGenTimeAsTime(&tst, (time_t)1700000000, buf,
        (word32)sizeof(buf)), 0);
    ExpectIntEQ(wc_TspTstInfo_GetGenTimeAsTime(&tst, &t), 0);
    ExpectIntEQ((long)t, 1700000000L);

    /* Get ignores a fraction of a second. */
    tst.genTime = (const byte*)"19700101000000.5Z";
    tst.genTimeSz = 17;
    ExpectIntEQ(wc_TspTstInfo_GetGenTimeAsTime(&tst, &t), 0);
    ExpectIntEQ((long)t, 0);

    /* Get: bad arguments. */
    ExpectIntEQ(wc_TspTstInfo_GetGenTimeAsTime(NULL, &t),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_GetGenTimeAsTime(&tst, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Get: an invalid time string. */
    tst.genTime = (const byte*)"19700101000000";
    tst.genTimeSz = 14;
    ExpectIntEQ(wc_TspTstInfo_GetGenTimeAsTime(&tst, &t),
        WC_NO_ERR_TRACE(ASN_PARSE_E));
    /* Get: out-of-range fields are rejected, not used to index a table.
     * A month of 00 or 13-99 would otherwise read outside the month table. */
    tst.genTime = (const byte*)"19700001000000Z"; /* month 00 */
    tst.genTimeSz = 15;
    ExpectIntEQ(wc_TspTstInfo_GetGenTimeAsTime(&tst, &t),
        WC_NO_ERR_TRACE(ASN_PARSE_E));
    tst.genTime = (const byte*)"19701301000000Z"; /* month 13 */
    tst.genTimeSz = 15;
    ExpectIntEQ(wc_TspTstInfo_GetGenTimeAsTime(&tst, &t),
        WC_NO_ERR_TRACE(ASN_PARSE_E));
    tst.genTime = (const byte*)"19709901000000Z"; /* month 99 */
    tst.genTimeSz = 15;
    ExpectIntEQ(wc_TspTstInfo_GetGenTimeAsTime(&tst, &t),
        WC_NO_ERR_TRACE(ASN_PARSE_E));
    tst.genTime = (const byte*)"19700100000000Z"; /* day 00 */
    tst.genTimeSz = 15;
    ExpectIntEQ(wc_TspTstInfo_GetGenTimeAsTime(&tst, &t),
        WC_NO_ERR_TRACE(ASN_PARSE_E));
    tst.genTime = (const byte*)"19700101240000Z"; /* hour 24 */
    tst.genTimeSz = 15;
    ExpectIntEQ(wc_TspTstInfo_GetGenTimeAsTime(&tst, &t),
        WC_NO_ERR_TRACE(ASN_PARSE_E));
    tst.genTime = (const byte*)"19700101006000Z"; /* minute 60 */
    tst.genTimeSz = 15;
    ExpectIntEQ(wc_TspTstInfo_GetGenTimeAsTime(&tst, &t),
        WC_NO_ERR_TRACE(ASN_PARSE_E));
    tst.genTime = (const byte*)"19700101000061Z"; /* second 61 */
    tst.genTimeSz = 15;
    ExpectIntEQ(wc_TspTstInfo_GetGenTimeAsTime(&tst, &t),
        WC_NO_ERR_TRACE(ASN_PARSE_E));
    /* A leap second (60) is accepted. */
    tst.genTime = (const byte*)"19700101000060Z";
    tst.genTimeSz = 15;
    ExpectIntEQ(wc_TspTstInfo_GetGenTimeAsTime(&tst, &t), 0);
    /* Get: no time present. */
    tst.genTime = NULL;
    tst.genTimeSz = 0;
    ExpectIntEQ(wc_TspTstInfo_GetGenTimeAsTime(&tst, &t),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    return EXPECT_RESULT();
}

int test_wc_TspResponse_Init(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && \
    defined(WOLFSSL_TSP_RESPONDER)
    TspResponse resp;

    ExpectIntEQ(wc_TspResponse_Init(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Setting the status of a NULL response is rejected. */
    ExpectIntEQ(wc_TspResponse_SetStatus(NULL, WC_TSP_PKISTATUS_GRANTED, NULL,
        0, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    XMEMSET(&resp, 0xa5, sizeof(TspResponse));
    ExpectIntEQ(wc_TspResponse_Init(&resp), 0);
    ExpectIntEQ(resp.status, WC_TSP_PKISTATUS_GRANTED);
    ExpectNull(resp.statusString);
    ExpectIntEQ(resp.failInfo, 0);
    ExpectNull(resp.token);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspGetSetStatus(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    static const char statusText[] = "rejected by policy";
    TspResponse resp;
    word32 status = 0;
    const byte* str = NULL;
    word32 strSz = 0;
    word32 failInfo = 0;

    ExpectIntEQ(wc_TspResponse_Init(&resp), 0);

    /* Bad arguments - NULL response. */
    ExpectIntEQ(wc_TspResponse_GetStatus(NULL, &status, &str, &strSz,
        &failInfo), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspResponse_SetStatus(NULL, WC_TSP_PKISTATUS_GRANTED, NULL,
        0, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Set status, string and failure information - string is assigned. */
    ExpectIntEQ(wc_TspResponse_SetStatus(&resp, WC_TSP_PKISTATUS_REJECTION,
        (const byte*)statusText, (word32)XSTRLEN(statusText),
        WC_TSP_FAIL_BAD_ALG | WC_TSP_FAIL_SYSTEM_FAILURE), 0);
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(resp.status, WC_TSP_PKISTATUS_REJECTION);
        ExpectPtrEq(resp.statusString, statusText);
        ExpectIntEQ(resp.statusStringSz, (word32)XSTRLEN(statusText));
        ExpectIntEQ(resp.failInfo,
            WC_TSP_FAIL_BAD_ALG | WC_TSP_FAIL_SYSTEM_FAILURE);
    }

    /* Get returns each value asked for. */
    ExpectIntEQ(wc_TspResponse_GetStatus(&resp, &status, &str, &strSz,
        &failInfo), 0);
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(status, WC_TSP_PKISTATUS_REJECTION);
        ExpectPtrEq(str, statusText);
        ExpectIntEQ(strSz, (word32)XSTRLEN(statusText));
        ExpectIntEQ(failInfo, WC_TSP_FAIL_BAD_ALG | WC_TSP_FAIL_SYSTEM_FAILURE);
    }

    /* All outputs are optional - NULLs retrieve nothing. */
    ExpectIntEQ(wc_TspResponse_GetStatus(&resp, NULL, NULL, NULL, NULL), 0);

    /* A NULL string clears the string and its length. */
    ExpectIntEQ(wc_TspResponse_SetStatus(&resp, WC_TSP_PKISTATUS_GRANTED, NULL,
        5, 0), 0);
    str = (const byte*)statusText;
    strSz = 99;
    ExpectIntEQ(wc_TspResponse_GetStatus(&resp, &status, &str, &strSz,
        &failInfo), 0);
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(status, WC_TSP_PKISTATUS_GRANTED);
        ExpectNull(str);
        ExpectIntEQ(strSz, 0);
        ExpectIntEQ(failInfo, 0);
    }
#endif
    return EXPECT_RESULT();
}

int test_wc_TspStrings(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_TSP
    /* Each PKIStatus has a description. */
    ExpectStrEQ(wc_TspStatus_ToString(WC_TSP_PKISTATUS_GRANTED), "granted");
    ExpectStrEQ(wc_TspStatus_ToString(WC_TSP_PKISTATUS_REJECTION), "rejection");
    ExpectNotNull(wc_TspStatus_ToString(WC_TSP_PKISTATUS_GRANTED_WITH_MODS));
    ExpectNotNull(wc_TspStatus_ToString(WC_TSP_PKISTATUS_WAITING));
    ExpectNotNull(wc_TspStatus_ToString(WC_TSP_PKISTATUS_REVOCATION_WARNING));
    ExpectNotNull(wc_TspStatus_ToString(
        WC_TSP_PKISTATUS_REVOCATION_NOTIFICATION));
    /* An unknown status still returns a string. */
    ExpectStrEQ(wc_TspStatus_ToString(99), "unknown status");

    /* Each PKIFailureInfo flag has a description. */
    ExpectStrEQ(wc_TspFailInfo_ToString(WC_TSP_FAIL_SYSTEM_FAILURE),
        "the request cannot be handled due to system failure");
    ExpectNotNull(wc_TspFailInfo_ToString(WC_TSP_FAIL_BAD_ALG));
    ExpectNotNull(wc_TspFailInfo_ToString(WC_TSP_FAIL_BAD_REQUEST));
    ExpectNotNull(wc_TspFailInfo_ToString(WC_TSP_FAIL_BAD_DATA_FORMAT));
    ExpectNotNull(wc_TspFailInfo_ToString(WC_TSP_FAIL_TIME_NOT_AVAILABLE));
    ExpectNotNull(wc_TspFailInfo_ToString(WC_TSP_FAIL_UNACCEPTED_POLICY));
    ExpectNotNull(wc_TspFailInfo_ToString(WC_TSP_FAIL_UNACCEPTED_EXTENSION));
    ExpectNotNull(wc_TspFailInfo_ToString(WC_TSP_FAIL_ADD_INFO_NOT_AVAILABLE));
    /* An unknown or empty failure information still returns a string. */
    ExpectStrEQ(wc_TspFailInfo_ToString(0), "unknown failure information");
#endif
    return EXPECT_RESULT();
}

int test_wc_TspResponse_Encode(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    /* All failure information flags. RFC 3161, 2.4.2. */
    static const word32 failInfoFlags[] = {
        WC_TSP_FAIL_BAD_ALG,
        WC_TSP_FAIL_BAD_REQUEST,
        WC_TSP_FAIL_BAD_DATA_FORMAT,
        WC_TSP_FAIL_TIME_NOT_AVAILABLE,
        WC_TSP_FAIL_UNACCEPTED_POLICY,
        WC_TSP_FAIL_UNACCEPTED_EXTENSION,
        WC_TSP_FAIL_ADD_INFO_NOT_AVAILABLE,
        WC_TSP_FAIL_SYSTEM_FAILURE
    };
    /* Stand-in for a token - decoded as opaque DER. */
    static const byte token[] = { 0x30, 0x03, 0x02, 0x01, 0x05 };
    static const char statusText[] = "rejected by policy";
    TspResponse resp;
    TspResponse respDec;
    byte enc[256];
    word32 encSz;
    word32 sz;
    word32 i;

    ExpectIntEQ(wc_TspResponse_Init(&resp), 0);

    /* Bad arguments. */
    encSz = (word32)sizeof(enc);
    ExpectIntEQ(wc_TspResponse_Encode(NULL, enc, &encSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspResponse_Encode(&resp, enc, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Smallest response. */
    encSz = 0;
    ExpectIntEQ(wc_TspResponse_Encode(&resp, NULL, &encSz), 0);
    ExpectIntGT(encSz, 0);
    /* Buffer too small. */
    sz = encSz - 1;
    ExpectIntEQ(wc_TspResponse_Encode(&resp, enc, &sz),
        WC_NO_ERR_TRACE(BUFFER_E));
    sz = (word32)sizeof(enc);
    ExpectIntEQ(wc_TspResponse_Encode(&resp, enc, &sz), 0);
    ExpectIntEQ(sz, encSz);
    ExpectIntEQ(wc_TspResponse_Decode(&respDec, enc, sz), 0);
    ExpectIntEQ(respDec.status, WC_TSP_PKISTATUS_GRANTED);
    ExpectNull(respDec.statusString);
    ExpectIntEQ(respDec.failInfo, 0);
    ExpectNull(respDec.token);

    /* Rejection with status string and each failure information flag. */
    resp.status = WC_TSP_PKISTATUS_REJECTION;
    resp.statusString = (const byte*)statusText;
    resp.statusStringSz = (word32)XSTRLEN(statusText);
    for (i = 0; i < (word32)(sizeof(failInfoFlags) / sizeof(*failInfoFlags));
            i++) {
        resp.failInfo = failInfoFlags[i];
        sz = (word32)sizeof(enc);
        ExpectIntEQ(wc_TspResponse_Encode(&resp, enc, &sz), 0);
        ExpectIntEQ(wc_TspResponse_Decode(&respDec, enc, sz), 0);
        ExpectIntEQ(respDec.status, WC_TSP_PKISTATUS_REJECTION);
        ExpectIntEQ(respDec.failInfo, failInfoFlags[i]);
        ExpectIntEQ(respDec.statusStringSz, (word32)XSTRLEN(statusText));
        ExpectBufEQ(respDec.statusString, statusText,
            (int)XSTRLEN(statusText));
    }
    /* Multiple failure information flags. */
    resp.failInfo = WC_TSP_FAIL_BAD_ALG | WC_TSP_FAIL_BAD_REQUEST;
    sz = (word32)sizeof(enc);
    ExpectIntEQ(wc_TspResponse_Encode(&resp, enc, &sz), 0);
    ExpectIntEQ(wc_TspResponse_Decode(&respDec, enc, sz), 0);
    ExpectIntEQ(respDec.failInfo,
        WC_TSP_FAIL_BAD_ALG | WC_TSP_FAIL_BAD_REQUEST);

    /* Granted with a token. */
    ExpectIntEQ(wc_TspResponse_Init(&resp), 0);
    resp.token = token;
    resp.tokenSz = (word32)sizeof(token);
    sz = (word32)sizeof(enc);
    ExpectIntEQ(wc_TspResponse_Encode(&resp, enc, &sz), 0);
    ExpectIntEQ(wc_TspResponse_Decode(&respDec, enc, sz), 0);
    ExpectIntEQ(respDec.status, WC_TSP_PKISTATUS_GRANTED);
    ExpectIntEQ(respDec.tokenSz, (word32)sizeof(token));
    ExpectBufEQ(respDec.token, token, (int)sizeof(token));
#endif
    return EXPECT_RESULT();
}

int test_wc_TspResponse_Decode(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(WOLFSSL_TSP_VERIFIER)
    /* Rejection with failure information of badRequest - OpenSSL style BIT
     * STRING with unused bits. */
    static const byte failInfoDer[] = {
        0x30, 0x09, 0x30, 0x07,
        0x02, 0x01, 0x02,
        0x03, 0x02, 0x05, 0x20
    };
    /* Rejection with a PKIFreeText holding two strings. */
    static const byte twoStrDer[] = {
        0x30, 0x12, 0x30, 0x10,
        0x02, 0x01, 0x02,
        0x30, 0x0b,
        0x0c, 0x03, 'a', 'b', 'c',
        0x0c, 0x04, 'd', 'e', 'f', 'g'
    };
    /* Invalid: PKIFreeText must have at least one string. */
    static const byte emptyStrDer[] = {
        0x30, 0x07, 0x30, 0x05,
        0x02, 0x01, 0x02,
        0x30, 0x00
    };
    /* Failure information with more bits than recognized - invalid. */
    static const byte longFailDer[] = {
        0x30, 0x0d, 0x30, 0x0b,
        0x02, 0x01, 0x02,
        0x03, 0x06, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80
    };
    /* Present but empty failInfo BIT STRING - only the unused bits byte. */
    static const byte emptyFailDer[] = {
        0x30, 0x08, 0x30, 0x06,
        0x02, 0x01, 0x02,
        0x03, 0x01, 0x00
    };
    TspResponse respDec;
    byte enc[32];
    word32 status = 0;

    /* Bad arguments. */
    ExpectIntEQ(wc_TspResponse_Decode(NULL, failInfoDer,
        (word32)sizeof(failInfoDer)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Getting the status of a NULL response is rejected. */
    ExpectIntEQ(wc_TspResponse_GetStatus(NULL, &status, NULL, NULL, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspResponse_Decode(&respDec, NULL,
        (word32)sizeof(failInfoDer)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspResponse_Decode(&respDec, failInfoDer, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Failure information with unused bits in BIT STRING. */
    ExpectIntEQ(wc_TspResponse_Decode(&respDec, failInfoDer,
        (word32)sizeof(failInfoDer)), 0);
    ExpectIntEQ(respDec.status, WC_TSP_PKISTATUS_REJECTION);
    ExpectIntEQ(respDec.failInfo, WC_TSP_FAIL_BAD_REQUEST);
    ExpectNull(respDec.statusString);
    ExpectNull(respDec.token);

    /* First string of PKIFreeText returned. */
    ExpectIntEQ(wc_TspResponse_Decode(&respDec, twoStrDer,
        (word32)sizeof(twoStrDer)), 0);
    ExpectIntEQ(respDec.statusStringSz, 3);
    ExpectBufEQ(respDec.statusString, "abc", 3);

    /* Empty PKIFreeText invalid. */
    ExpectIntLT(wc_TspResponse_Decode(&respDec, emptyStrDer,
        (word32)sizeof(emptyStrDer)), 0);

    /* Failure information bits past 31 are not supported. */
    ExpectIntEQ(wc_TspResponse_Decode(&respDec, longFailDer,
        (word32)sizeof(longFailDer)), WC_NO_ERR_TRACE(ASN_PARSE_E));

    /* Present but empty failInfo BIT STRING (only the unused bits byte) has no
     * data bytes and is rejected - the shift over the encoded length is never
     * reached, so it cannot shift a word32 by 32. */
    ExpectIntEQ(wc_TspResponse_Decode(&respDec, emptyFailDer,
        (word32)sizeof(emptyFailDer)), WC_NO_ERR_TRACE(ASN_PARSE_E));

    /* Truncated encoding. */
    ExpectIntLT(wc_TspResponse_Decode(&respDec, failInfoDer,
        (word32)sizeof(failInfoDer) - 1), 0);
    /* Trailing data not allowed. */
    XMEMCPY(enc, failInfoDer, sizeof(failInfoDer));
    enc[sizeof(failInfoDer)] = 0x00;
    ExpectIntLT(wc_TspResponse_Decode(&respDec, enc,
        (word32)sizeof(failInfoDer) + 1), 0);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_CheckRequest(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    /* Nonce with extra leading zero byte. */
    static const byte paddedNonce[] = {
        0x00, 0xc3, 0x5a, 0x10, 0x42, 0x77, 0x08, 0x99, 0x01
    };
    static const byte otherNonce[] = { 0x01, 0x02 };
    /* Nonce of zero in different number of bytes. */
    static const byte zeroNonce1[] = { 0x00 };
    static const byte zeroNonce2[] = { 0x00, 0x00 };
    TspTstInfo tst;
    TspRequest req;

    /* Matching request and TSTInfo - no encoding required for check. */
    ExpectIntEQ(wc_TspRequest_Init(&req), 0);
    test_tsp_set_hash(&req.imprint);
    XMEMCPY(req.policy, tsPolicy, sizeof(tsPolicy));
    req.policySz = (word32)sizeof(tsPolicy);
    XMEMCPY(req.nonce, tsNonce, sizeof(tsNonce));
    req.nonceSz = (word32)sizeof(tsNonce);
    ExpectIntEQ(wc_TspTstInfo_Init(&tst), 0);
    tst.policy = tsPolicy;
    tst.policySz = (word32)sizeof(tsPolicy);
    test_tsp_set_hash(&tst.imprint);
    tst.nonce = tsNonce;
    tst.nonceSz = (word32)sizeof(tsNonce);

    /* Bad arguments. */
    ExpectIntEQ(wc_TspTstInfo_CheckRequest(NULL, &req),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_CheckRequest(&tst, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_TspTstInfo_CheckRequest(&tst, &req), 0);

    /* Only version 1 supported. */
    tst.version = 2;
    ExpectIntEQ(wc_TspTstInfo_CheckRequest(&tst, &req),
        WC_NO_ERR_TRACE(ASN_VERSION_E));
    tst.version = WC_TSP_VERSION;

    /* Hash algorithm different. */
    tst.imprint.hashAlgOID = SHA256h + 1;
    ExpectIntEQ(wc_TspTstInfo_CheckRequest(&tst, &req),
        WC_NO_ERR_TRACE(TSP_VERIFY_E));
    tst.imprint.hashAlgOID = SHA256h;
    /* Hash length different. */
    tst.imprint.hashSz--;
    ExpectIntEQ(wc_TspTstInfo_CheckRequest(&tst, &req),
        WC_NO_ERR_TRACE(TSP_VERIFY_E));
    tst.imprint.hashSz++;
    /* Hash different. */
    tst.imprint.hash[0] ^= 0x80;
    ExpectIntEQ(wc_TspTstInfo_CheckRequest(&tst, &req),
        WC_NO_ERR_TRACE(TSP_VERIFY_E));
    tst.imprint.hash[0] ^= 0x80;

    /* Nonce in request must be in TSTInfo. */
    tst.nonce = NULL;
    tst.nonceSz = 0;
    ExpectIntEQ(wc_TspTstInfo_CheckRequest(&tst, &req),
        WC_NO_ERR_TRACE(TSP_VERIFY_E));
    /* Nonces compared exactly - same number with leading zero byte does not
     * match. */
    tst.nonce = paddedNonce;
    tst.nonceSz = (word32)sizeof(paddedNonce);
    ExpectIntEQ(wc_TspTstInfo_CheckRequest(&tst, &req),
        WC_NO_ERR_TRACE(TSP_VERIFY_E));
    /* Request's nonce with leading zero byte. */
    XMEMCPY(req.nonce, paddedNonce, sizeof(paddedNonce));
    req.nonceSz = (word32)sizeof(paddedNonce);
    tst.nonce = tsNonce;
    tst.nonceSz = (word32)sizeof(tsNonce);
    ExpectIntEQ(wc_TspTstInfo_CheckRequest(&tst, &req),
        WC_NO_ERR_TRACE(TSP_VERIFY_E));
    /* Nonce of zero with different lengths. */
    XMEMCPY(req.nonce, zeroNonce2, sizeof(zeroNonce2));
    req.nonceSz = (word32)sizeof(zeroNonce2);
    tst.nonce = zeroNonce1;
    tst.nonceSz = (word32)sizeof(zeroNonce1);
    ExpectIntEQ(wc_TspTstInfo_CheckRequest(&tst, &req),
        WC_NO_ERR_TRACE(TSP_VERIFY_E));
    XMEMCPY(req.nonce, tsNonce, sizeof(tsNonce));
    req.nonceSz = (word32)sizeof(tsNonce);
    /* Nonce different. */
    tst.nonce = otherNonce;
    tst.nonceSz = (word32)sizeof(otherNonce);
    ExpectIntEQ(wc_TspTstInfo_CheckRequest(&tst, &req),
        WC_NO_ERR_TRACE(TSP_VERIFY_E));
    tst.nonce = tsNonce;
    tst.nonceSz = (word32)sizeof(tsNonce);
    /* Nonce in TSTInfo and not request is allowed. */
    req.nonceSz = 0;
    ExpectIntEQ(wc_TspTstInfo_CheckRequest(&tst, &req), 0);
    XMEMCPY(req.nonce, tsNonce, sizeof(tsNonce));
    req.nonceSz = (word32)sizeof(tsNonce);

    /* Policy in request must be in TSTInfo. */
    tst.policy = NULL;
    tst.policySz = 0;
    ExpectIntEQ(wc_TspTstInfo_CheckRequest(&tst, &req),
        WC_NO_ERR_TRACE(TSP_VERIFY_E));
    /* Policy different. */
    tst.policy = tsNonce;
    tst.policySz = (word32)sizeof(tsNonce);
    ExpectIntEQ(wc_TspTstInfo_CheckRequest(&tst, &req),
        WC_NO_ERR_TRACE(TSP_VERIFY_E));
    tst.policy = tsPolicy;
    tst.policySz = (word32)sizeof(tsPolicy);
    /* Policy not checked when not requested. */
    req.policySz = 0;
    ExpectIntEQ(wc_TspTstInfo_CheckRequest(&tst, &req), 0);
#endif
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER) && \
    (!defined(NO_RSA) || defined(HAVE_ECC))
/* Create a PKCS7 object ready to sign with the certificate and key using the
 * given encryption algorithm. */
static int test_tsp_new_signer_ex(wc_PKCS7** pkcs7, WC_RNG* rng,
    const byte* cert, word32 certSz, const byte* key, word32 keySz,
    int encryptOID)
{
    EXPECT_DECLS;

    ExpectNotNull(*pkcs7 = wc_PKCS7_New(NULL, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(*pkcs7, (byte*)cert, certSz), 0);
    if (EXPECT_SUCCESS()) {
        (*pkcs7)->rng = rng;
        (*pkcs7)->hashOID = SHA256h;
        (*pkcs7)->encryptOID = encryptOID;
        (*pkcs7)->privateKey = (byte*)key;
        (*pkcs7)->privateKeySz = keySz;
    }

    return EXPECT_RESULT();
}

#ifndef NO_RSA
/* Create a PKCS7 object ready to sign with the RSA certificate and key. */
static int test_tsp_new_signer(wc_PKCS7** pkcs7, WC_RNG* rng, const byte* cert,
    word32 certSz, const byte* key, word32 keySz)
{
    return test_tsp_new_signer_ex(pkcs7, rng, cert, certSz, key, keySz, RSAk);
}

/* Create a PKCS7 object ready to sign as the TSA. */
static int test_tsp_new_tsa_signer(wc_PKCS7** pkcs7, WC_RNG* rng)
{
    return test_tsp_new_signer(pkcs7, rng, tsa_cert_der_2048,
        sizeof_tsa_cert_der_2048, tsa_key_der_2048, sizeof_tsa_key_der_2048);
}
#endif /* !NO_RSA */

/* Build a standard time-stamp token signed with the given certificate and key.
 * Encapsulates the signing PKCS7 so verify tests need only their own object. */
static int test_tsp_make_token(byte* token, word32* tokenSz, const byte* cert,
    word32 certSz, const byte* key, word32 keySz, int encryptOID, WC_RNG* rng)
{
    EXPECT_DECLS;
    wc_PKCS7* pkcs7 = NULL;
    TspTstInfo tst;

    test_tsp_set_tstinfo(&tst);
    tst.nonce = tsNonce;
    tst.nonceSz = (word32)sizeof(tsNonce);

    ExpectIntEQ(test_tsp_new_signer_ex(&pkcs7, rng, cert, certSz, key, keySz,
        encryptOID), TEST_SUCCESS);
    ExpectIntEQ(wc_TspTstInfo_SignWithPkcs7(&tst, pkcs7, token, tokenSz), 0);
    wc_PKCS7_Free(pkcs7);

    return EXPECT_RESULT();
}
#endif

int test_wc_TspTstInfo_SignWithPkcs7(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    wc_PKCS7* pkcs7 = NULL;
    WC_RNG rng;
    TspTstInfo tst;
    byte token[3072];
    word32 tokenSz;

    ExpectIntEQ(wc_InitRng(&rng), 0);
    test_tsp_set_tstinfo(&tst);
    tst.nonce = tsNonce;
    tst.nonceSz = (word32)sizeof(tsNonce);
    ExpectIntEQ(test_tsp_new_tsa_signer(&pkcs7, &rng), TEST_SUCCESS);

    /* Bad arguments. */
    tokenSz = (word32)sizeof(token);
    ExpectIntEQ(wc_TspTstInfo_SignWithPkcs7(&tst, NULL, token, &tokenSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_SignWithPkcs7(NULL, pkcs7, token, &tokenSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_SignWithPkcs7(&tst, pkcs7, NULL, &tokenSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_SignWithPkcs7(&tst, pkcs7, token, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;

    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_SignWithPkcs7_create(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    wc_PKCS7* pkcs7 = NULL;
    WC_RNG rng;
    TspTstInfo tstDec;
    byte token[3072];
    word32 tokenSz;

    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* Create a token and check the TSTInfo it holds. */
    tokenSz = (word32)sizeof(token);
    ExpectIntEQ(test_tsp_make_token(token, &tokenSz, tsa_cert_der_2048,
        sizeof_tsa_cert_der_2048, tsa_key_der_2048, sizeof_tsa_key_der_2048,
        RSAk, &rng), TEST_SUCCESS);
    ExpectIntGT(tokenSz, 0);

    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    ExpectIntEQ(wc_TspTstInfo_VerifyWithPKCS7(pkcs7, token, tokenSz, &tstDec), 0);
    ExpectIntEQ(tstDec.version, WC_TSP_VERSION);
    ExpectBufEQ(tstDec.imprint.hash, tsHashedMsg,
        (int)sizeof(tsHashedMsg));
    ExpectIntEQ(tstDec.nonceSz, (word32)sizeof(tsNonce));
    ExpectBufEQ(tstDec.nonce, tsNonce, (int)sizeof(tsNonce));
    wc_PKCS7_Free(pkcs7);

    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_SignWithPkcs7_signer_required(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    wc_PKCS7* pkcs7 = NULL;
    TspTstInfo tst;
    byte token[3072];
    word32 tokenSz;

    test_tsp_set_tstinfo(&tst);
    tst.nonce = tsNonce;
    tst.nonceSz = (word32)sizeof(tsNonce);

    /* Signer's certificate required. */
    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    tokenSz = (word32)sizeof(token);
    ExpectIntEQ(wc_TspTstInfo_SignWithPkcs7(&tst, pkcs7, token, &tokenSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    wc_PKCS7_Free(pkcs7);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_SignWithPkcs7_hash_and_buffer(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    wc_PKCS7* pkcs7 = NULL;
    WC_RNG rng;
    TspTstInfo tst;
    byte token[3072];
    word32 tokenSz;

    ExpectIntEQ(wc_InitRng(&rng), 0);
    test_tsp_set_tstinfo(&tst);
    tst.nonce = tsNonce;
    tst.nonceSz = (word32)sizeof(tsNonce);

    /* Hash algorithm of PKCS7 object must be usable. */
    ExpectIntEQ(test_tsp_new_tsa_signer(&pkcs7, &rng), TEST_SUCCESS);
    if (EXPECT_SUCCESS()) {
        pkcs7->hashOID = 0;
    }
    tokenSz = (word32)sizeof(token);
    ExpectIntEQ(wc_TspTstInfo_SignWithPkcs7(&tst, pkcs7, token, &tokenSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Output buffer too small - PKCS7 object fields are put back. */
    if (EXPECT_SUCCESS()) {
        pkcs7->hashOID = SHA256h;
    }
    tokenSz = 16;
    ExpectIntLT(wc_TspTstInfo_SignWithPkcs7(&tst, pkcs7, token, &tokenSz), 0);
    if (EXPECT_SUCCESS()) {
        ExpectNull(pkcs7->content);
        ExpectIntEQ(pkcs7->contentSz, 0);
        ExpectNull(pkcs7->signedAttribs);
        ExpectIntEQ(pkcs7->signedAttribsSz, 0);
    }
    wc_PKCS7_Free(pkcs7);

    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_Sign(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    WC_RNG rng;
    TspTstInfo tst;
    TspTstInfo tstDec;
    TspResponse resp;
    byte token[3072];
    word32 tokenSz;

    ExpectIntEQ(wc_InitRng(&rng), 0);
    test_tsp_set_tstinfo(&tst);

    /* Bad arguments. */
    tokenSz = (word32)sizeof(token);
    ExpectIntEQ(wc_TspTstInfo_Sign(NULL, tsa_cert_der_2048,
        sizeof_tsa_cert_der_2048, tsa_key_der_2048, sizeof_tsa_key_der_2048,
        WC_PK_TYPE_RSA, WC_HASH_TYPE_SHA256, &rng, token, &tokenSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_Sign(&tst, NULL,
        sizeof_tsa_cert_der_2048, tsa_key_der_2048, sizeof_tsa_key_der_2048,
        WC_PK_TYPE_RSA, WC_HASH_TYPE_SHA256, &rng, token, &tokenSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_Sign(&tst, tsa_cert_der_2048, 0,
        tsa_key_der_2048, sizeof_tsa_key_der_2048, WC_PK_TYPE_RSA,
        WC_HASH_TYPE_SHA256, &rng, token, &tokenSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_Sign(&tst, tsa_cert_der_2048,
        sizeof_tsa_cert_der_2048, NULL, sizeof_tsa_key_der_2048,
        WC_PK_TYPE_RSA, WC_HASH_TYPE_SHA256, &rng, token, &tokenSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_Sign(&tst, tsa_cert_der_2048,
        sizeof_tsa_cert_der_2048, tsa_key_der_2048, 0, WC_PK_TYPE_RSA,
        WC_HASH_TYPE_SHA256, &rng, token, &tokenSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_Sign(&tst, tsa_cert_der_2048,
        sizeof_tsa_cert_der_2048, tsa_key_der_2048, sizeof_tsa_key_der_2048,
        WC_PK_TYPE_RSA, WC_HASH_TYPE_SHA256, NULL, token, &tokenSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_Sign(&tst, tsa_cert_der_2048,
        sizeof_tsa_cert_der_2048, tsa_key_der_2048, sizeof_tsa_key_der_2048,
        WC_PK_TYPE_RSA, WC_HASH_TYPE_SHA256, &rng, NULL, &tokenSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_Sign(&tst, tsa_cert_der_2048,
        sizeof_tsa_cert_der_2048, tsa_key_der_2048, sizeof_tsa_key_der_2048,
        WC_PK_TYPE_RSA, WC_HASH_TYPE_SHA256, &rng, token, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Unsupported key type. */
    ExpectIntEQ(wc_TspTstInfo_Sign(&tst, tsa_cert_der_2048,
        sizeof_tsa_cert_der_2048, tsa_key_der_2048, sizeof_tsa_key_der_2048,
        WC_PK_TYPE_DH, WC_HASH_TYPE_SHA256, &rng, token, &tokenSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Hash algorithm not available. */
    ExpectIntEQ(wc_TspTstInfo_Sign(&tst, tsa_cert_der_2048,
        sizeof_tsa_cert_der_2048, tsa_key_der_2048, sizeof_tsa_key_der_2048,
        WC_PK_TYPE_RSA, WC_HASH_TYPE_NONE, &rng, token, &tokenSz),
        WC_NO_ERR_TRACE(HASH_TYPE_E));

    /* Create an RSA-signed token and verify it against the TSA certificate. */
    tokenSz = (word32)sizeof(token);
    ExpectIntEQ(wc_TspTstInfo_Sign(&tst, tsa_cert_der_2048,
        sizeof_tsa_cert_der_2048, tsa_key_der_2048, sizeof_tsa_key_der_2048,
        WC_PK_TYPE_RSA, WC_HASH_TYPE_SHA256, &rng, token, &tokenSz), 0);
    ExpectIntGT(tokenSz, 0);
    ExpectIntEQ(wc_TspResponse_Init(&resp), 0);
    resp.status = WC_TSP_PKISTATUS_GRANTED;
    resp.token = token;
    resp.tokenSz = tokenSz;
    ExpectIntEQ(wc_TspResponse_Verify(&resp, tsa_cert_der_2048,
        sizeof_tsa_cert_der_2048, &tstDec), 0);
    ExpectIntEQ(tstDec.version, WC_TSP_VERSION);

#ifdef HAVE_ECC
    /* Create an ECDSA-signed token and verify it. */
    tokenSz = (word32)sizeof(token);
    ExpectIntEQ(wc_TspTstInfo_Sign(&tst, tsa_ecc_cert_der_256,
        sizeof_tsa_ecc_cert_der_256, tsa_ecc_key_der_256,
        sizeof_tsa_ecc_key_der_256, WC_PK_TYPE_ECDSA_SIGN,
        WC_HASH_TYPE_SHA256, &rng, token, &tokenSz), 0);
    ExpectIntEQ(wc_TspResponse_Init(&resp), 0);
    resp.status = WC_TSP_PKISTATUS_GRANTED;
    resp.token = token;
    resp.tokenSz = tokenSz;
    ExpectIntEQ(wc_TspResponse_Verify(&resp, tsa_ecc_cert_der_256,
        sizeof_tsa_ecc_cert_der_256, &tstDec), 0);
    ExpectIntEQ(tstDec.version, WC_TSP_VERSION);
#endif

    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
/* Custom user attribute OID 1.2.5555 with a UTF8String value. */
static const byte tspCustomOid[] = { 0x06, 0x03, 0x2a, 0xab, 0x33 };
static const byte tspCustomValue[] = { 0x0c, 0x02, 'h', 'i' };

/* Sign a standard TSTInfo token that also carries the custom user attribute.
 * Encapsulates the signing PKCS7 so verify tests need only their own object. */
static int test_tsp_make_attrib_token(byte* token, word32* tokenSz, WC_RNG* rng)
{
    EXPECT_DECLS;
    PKCS7Attrib attrib;
    wc_PKCS7* pkcs7 = NULL;
    TspTstInfo tst;

    XMEMSET(&attrib, 0, sizeof(attrib));
    attrib.oid = tspCustomOid;
    attrib.oidSz = (word32)sizeof(tspCustomOid);
    attrib.value = tspCustomValue;
    attrib.valueSz = (word32)sizeof(tspCustomValue);

    test_tsp_set_tstinfo(&tst);

    ExpectIntEQ(test_tsp_new_tsa_signer(&pkcs7, rng), TEST_SUCCESS);
    if (EXPECT_SUCCESS()) {
        pkcs7->signedAttribs = &attrib;
        pkcs7->signedAttribsSz = 1;
    }
    ExpectIntEQ(wc_TspTstInfo_SignWithPkcs7(&tst, pkcs7, token, tokenSz), 0);
    wc_PKCS7_Free(pkcs7);

    return EXPECT_RESULT();
}

#ifdef WOLFSSL_SHA384
/* Sign a standard TSTInfo token with SHA-384 so the hash algorithm is encoded
 * in the SigningCertificateV2 attribute.  Encapsulates the signing PKCS7. */
static int test_tsp_make_sha384_token(byte* token, word32* tokenSz, WC_RNG* rng)
{
    EXPECT_DECLS;
    wc_PKCS7* pkcs7 = NULL;
    TspTstInfo tst;

    test_tsp_set_tstinfo(&tst);

    ExpectIntEQ(test_tsp_new_tsa_signer(&pkcs7, rng), TEST_SUCCESS);
    if (EXPECT_SUCCESS()) {
        pkcs7->hashOID = SHA384h;
    }
    ExpectIntEQ(wc_TspTstInfo_SignWithPkcs7(&tst, pkcs7, token, tokenSz), 0);
    wc_PKCS7_Free(pkcs7);

    return EXPECT_RESULT();
}
#endif
#endif

int test_wc_TspTstInfo_SignWithPkcs7_attribs(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    PKCS7Attrib attrib;
    wc_PKCS7* pkcs7 = NULL;
    WC_RNG rng;
    TspTstInfo tst;
    byte token[3072];
    word32 tokenSz = (word32)sizeof(token);

    XMEMSET(&attrib, 0, sizeof(attrib));
    attrib.oid = tspCustomOid;
    attrib.oidSz = (word32)sizeof(tspCustomOid);
    attrib.value = tspCustomValue;
    attrib.valueSz = (word32)sizeof(tspCustomValue);

    ExpectIntEQ(wc_InitRng(&rng), 0);
    test_tsp_set_tstinfo(&tst);

    /* Create a token with a user's signed attribute as well. */
    ExpectIntEQ(test_tsp_new_tsa_signer(&pkcs7, &rng), TEST_SUCCESS);
    if (EXPECT_SUCCESS()) {
        pkcs7->signedAttribs = &attrib;
        pkcs7->signedAttribsSz = 1;
    }
    ExpectIntEQ(wc_TspTstInfo_SignWithPkcs7(&tst, pkcs7, token, &tokenSz), 0);
    /* PKCS7 object's signed attributes are put back. */
    if (EXPECT_SUCCESS()) {
        ExpectPtrEq(pkcs7->signedAttribs, &attrib);
        ExpectIntEQ(pkcs7->signedAttribsSz, 1);
    }
    wc_PKCS7_Free(pkcs7);

    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_SignWithPkcs7_attribs_verify(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    /* id-aa-signingCertificateV2: 1.2.840.113549.1.9.16.2.47. */
    static const byte signCertV2Oid[] = {
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x2f
    };
    wc_PKCS7* pkcs7 = NULL;
    WC_RNG rng;
    byte token[3072];
    word32 tokenSz = (word32)sizeof(token);
    byte attrValue[128];
    word32 attrValueSz;

    ExpectIntEQ(wc_InitRng(&rng), 0);

    ExpectIntEQ(test_tsp_make_attrib_token(token, &tokenSz, &rng),
        TEST_SUCCESS);

    /* Both the user's attribute and SigningCertificateV2 are in token. */
    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    ExpectIntEQ(wc_TspTstInfo_VerifyWithPKCS7(pkcs7, token, tokenSz, NULL), 0);
    attrValueSz = (word32)sizeof(attrValue);
    ExpectIntEQ(wc_PKCS7_GetAttributeValue(pkcs7, tspCustomOid + 2,
        (word32)sizeof(tspCustomOid) - 2, attrValue, &attrValueSz),
        (int)sizeof(tspCustomValue));
    ExpectBufEQ(attrValue, tspCustomValue, (int)sizeof(tspCustomValue));
    attrValueSz = (word32)sizeof(attrValue);
    ExpectIntGT(wc_PKCS7_GetAttributeValue(pkcs7, signCertV2Oid,
        (word32)sizeof(signCertV2Oid), attrValue, &attrValueSz), 0);
    wc_PKCS7_Free(pkcs7);

    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_SignWithPkcs7_attribs_sha384(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
#ifdef WOLFSSL_SHA384
    wc_PKCS7* pkcs7 = NULL;
    WC_RNG rng;
    byte token[3072];
    word32 tokenSz = (word32)sizeof(token);

    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* Not SHA-256: hash algorithm encoded in SigningCertificateV2. */
    ExpectIntEQ(test_tsp_make_sha384_token(token, &tokenSz, &rng),
        TEST_SUCCESS);

    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    ExpectIntEQ(wc_TspTstInfo_VerifyWithPKCS7(pkcs7, token, tokenSz, NULL), 0);
    wc_PKCS7_Free(pkcs7);

    wc_FreeRng(&rng);
#endif
#endif
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
/* Encode a CMS SignedData with DATA content - not a time-stamp token.
 * Encapsulates the signing PKCS7 so verify tests need only their own object. */
static int test_tsp_make_data_token(byte* token, word32* tokenSz, WC_RNG* rng)
{
    EXPECT_DECLS;
    wc_PKCS7* pkcs7 = NULL;
    byte data[] = { 0x01, 0x02, 0x03, 0x04 };
    int sz = 0;

    ExpectIntEQ(test_tsp_new_tsa_signer(&pkcs7, rng), TEST_SUCCESS);
    if (EXPECT_SUCCESS()) {
        pkcs7->content = data;
        pkcs7->contentSz = (word32)sizeof(data);
        pkcs7->contentOID = DATA;
    }
    ExpectIntGT(sz = wc_PKCS7_EncodeSignedData(pkcs7, token, *tokenSz), 0);
    if (EXPECT_SUCCESS()) {
        *tokenSz = (word32)sz;
    }
    wc_PKCS7_Free(pkcs7);

    return EXPECT_RESULT();
}

/* Build a standard time-stamp token that does not include any certificates.
 * Encapsulates the signing PKCS7 so verify tests need only their own object. */
static int test_tsp_make_nocerts_token(byte* token, word32* tokenSz,
    WC_RNG* rng)
{
    EXPECT_DECLS;
    wc_PKCS7* pkcs7 = NULL;
    TspTstInfo tst;

    test_tsp_set_tstinfo(&tst);

    ExpectIntEQ(test_tsp_new_tsa_signer(&pkcs7, rng), TEST_SUCCESS);
    if (EXPECT_SUCCESS()) {
        /* Do not include certificates in the token. */
        pkcs7->noCerts = 1;
    }
    ExpectIntEQ(wc_TspTstInfo_SignWithPkcs7(&tst, pkcs7, token, tokenSz), 0);
    wc_PKCS7_Free(pkcs7);

    return EXPECT_RESULT();
}
#endif

int test_wc_TspTstInfo_VerifyWithPKCS7(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    wc_PKCS7* pkcs7 = NULL;
    WC_RNG rng;
    TspTstInfo tstDec;
    byte token[3072];
    word32 tokenSz = (word32)sizeof(token);

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(test_tsp_make_token(token, &tokenSz, tsa_cert_der_2048,
        sizeof_tsa_cert_der_2048, tsa_key_der_2048, sizeof_tsa_key_der_2048,
        RSAk, &rng), TEST_SUCCESS);

    /* Bad arguments. */
    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    ExpectIntEQ(wc_TspTstInfo_VerifyWithPKCS7(NULL, token, tokenSz, &tstDec),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_VerifyWithPKCS7(pkcs7, NULL, tokenSz, &tstDec),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_VerifyWithPKCS7(pkcs7, token, 0, &tstDec),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* TSTInfo object is optional. */
    ExpectIntEQ(wc_TspTstInfo_VerifyWithPKCS7(pkcs7, token, tokenSz, NULL), 0);
    wc_PKCS7_Free(pkcs7);

    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_VerifyWithPKCS7_modified(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    wc_PKCS7* pkcs7 = NULL;
    WC_RNG rng;
    TspTstInfo tstDec;
    byte token[3072];
    word32 tokenSz = (word32)sizeof(token);

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(test_tsp_make_token(token, &tokenSz, tsa_cert_der_2048,
        sizeof_tsa_cert_der_2048, tsa_key_der_2048, sizeof_tsa_key_der_2048,
        RSAk, &rng), TEST_SUCCESS);

    /* Modified token does not verify. */
    token[tokenSz - 5] ^= 0x80;
    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    ExpectIntLT(wc_TspTstInfo_VerifyWithPKCS7(pkcs7, token, tokenSz, &tstDec), 0);
    token[tokenSz - 5] ^= 0x80;
    wc_PKCS7_Free(pkcs7);

    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_VerifyWithPKCS7_no_signer(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    /* Token without a SignerInfo does not verify. */
    static const byte noSignerToken[] = {
        0x30, 0x25,                                     /* ContentInfo */
        0x06, 0x09,                                     /* signedData */
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
        0xa0, 0x18,                                     /* content */
        0x30, 0x16,                                     /* SignedData */
        0x02, 0x01, 0x03,                               /* version 3 */
        0x31, 0x00,                                     /* digestAlgs */
        0x30, 0x0d,                                     /* encapContent */
        0x06, 0x0b,                                     /* id-ct-TSTInfo */
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04,
        0x31, 0x00                                      /* signerInfos */
    };
    wc_PKCS7* pkcs7 = NULL;
    TspTstInfo tstDec;
    byte noSigner[sizeof(noSignerToken)];

    XMEMCPY(noSigner, noSignerToken, sizeof(noSignerToken));
    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    ExpectIntEQ(wc_TspTstInfo_VerifyWithPKCS7(pkcs7, noSigner,
        (word32)sizeof(noSigner), &tstDec),
        WC_NO_ERR_TRACE(TSP_VERIFY_E));
    wc_PKCS7_Free(pkcs7);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_VerifyWithPKCS7_not_tst(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    wc_PKCS7* pkcs7 = NULL;
    WC_RNG rng;
    TspTstInfo tstDec;
    byte token[3072];
    word32 tokenSz = (word32)sizeof(token);

    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* CMS SignedData that is not a time-stamp token. */
    ExpectIntEQ(test_tsp_make_data_token(token, &tokenSz, &rng), TEST_SUCCESS);
    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    ExpectIntEQ(wc_TspTstInfo_VerifyWithPKCS7(pkcs7, token, tokenSz, &tstDec),
        WC_NO_ERR_TRACE(PKCS7_OID_E));
    wc_PKCS7_Free(pkcs7);

    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_VerifyWithPKCS7_bad_eku(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    wc_PKCS7* pkcs7 = NULL;
    WC_RNG rng;
    TspTstInfo tstDec;
    byte token[3072];
    word32 tokenSz = (word32)sizeof(token);

    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* Token signed with a certificate not for time-stamping. */
    ExpectIntEQ(test_tsp_make_token(token, &tokenSz, client_cert_der_2048,
        sizeof_client_cert_der_2048, client_key_der_2048,
        sizeof_client_key_der_2048, RSAk, &rng), TEST_SUCCESS);
    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    ExpectIntEQ(wc_TspTstInfo_VerifyWithPKCS7(pkcs7, token, tokenSz, &tstDec),
        WC_NO_ERR_TRACE(EXTKEYUSAGE_E));
    wc_PKCS7_Free(pkcs7);

    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_VerifyWithPKCS7_bad_ku(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    wc_PKCS7* pkcs7 = NULL;
    WC_RNG rng;
    TspTstInfo tstDec;
    byte token[3072];
    word32 tokenSz = (word32)sizeof(token);

    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* Token signed with a time-stamping certificate with a key usage that
     * is not signing. */
    ExpectIntEQ(test_tsp_make_token(token, &tokenSz, tsa_bad_ku_cert_der_2048,
        sizeof_tsa_bad_ku_cert_der_2048, tsa_key_der_2048,
        sizeof_tsa_key_der_2048, RSAk, &rng), TEST_SUCCESS);
    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    ExpectIntEQ(wc_TspTstInfo_VerifyWithPKCS7(pkcs7, token, tokenSz, &tstDec),
        WC_NO_ERR_TRACE(KEYUSAGE_E));
    wc_PKCS7_Free(pkcs7);

    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_VerifyWithPKCS7_extra_eku(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    wc_PKCS7* pkcs7 = NULL;
    WC_RNG rng;
    TspTstInfo tstDec;
    byte token[3072];
    word32 tokenSz = (word32)sizeof(token);

    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* Token signed with a time-stamping certificate that has an extra
     * extended key usage - the extra purpose is an unrecognized OID so the
     * time-stamping bit is still the only one set, but it is not the sole
     * KeyPurposeId, so verification must reject it. */
    ExpectIntEQ(test_tsp_make_token(token, &tokenSz, tsa_extra_eku_cert_der_2048,
        sizeof_tsa_extra_eku_cert_der_2048, tsa_key_der_2048,
        sizeof_tsa_key_der_2048, RSAk, &rng), TEST_SUCCESS);
    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    ExpectIntEQ(wc_TspTstInfo_VerifyWithPKCS7(pkcs7, token, tokenSz, &tstDec),
        WC_NO_ERR_TRACE(EXTKEYUSAGE_E));
    wc_PKCS7_Free(pkcs7);

    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_VerifyWithPKCS7_nocerts(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    wc_PKCS7* pkcs7 = NULL;
    WC_RNG rng;
    TspTstInfo tstDec;
    byte token[3072];
    word32 tokenSz = (word32)sizeof(token);

    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* Token without certificates - certReq was FALSE in the request. */
    ExpectIntEQ(test_tsp_make_nocerts_token(token, &tokenSz, &rng),
        TEST_SUCCESS);
    /* Cannot verify without the TSA's certificate. */
    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    ExpectIntLT(wc_TspTstInfo_VerifyWithPKCS7(pkcs7, token, tokenSz, &tstDec), 0);
    wc_PKCS7_Free(pkcs7);

    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_VerifyWithPKCS7_nocerts_supplied(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    wc_PKCS7* pkcs7 = NULL;
    WC_RNG rng;
    TspTstInfo tstDec;
    byte token[3072];
    word32 tokenSz = (word32)sizeof(token);

    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* Token without certificates - certReq was FALSE in the request. */
    ExpectIntEQ(test_tsp_make_nocerts_token(token, &tokenSz, &rng),
        TEST_SUCCESS);
    /* Verifies when the TSA's certificate is supplied. */
    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, (byte*)tsa_cert_der_2048,
        sizeof_tsa_cert_der_2048), 0);
    ExpectIntEQ(wc_TspTstInfo_VerifyWithPKCS7(pkcs7, token, tokenSz, &tstDec), 0);
    wc_PKCS7_Free(pkcs7);

    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

/* Standard verify gate for the TspResponse_Verify split. */
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
/* Build a token that includes the TSA's certificate and wrap it in a granted
 * response. The signing PKCS7 is created and freed in the helper. */
static int test_tsp_make_granted_resp(TspResponse* resp, byte* token,
    word32* tokenSz, WC_RNG* rng)
{
    EXPECT_DECLS;

    ExpectIntEQ(test_tsp_make_token(token, tokenSz, tsa_cert_der_2048,
        sizeof_tsa_cert_der_2048, tsa_key_der_2048, sizeof_tsa_key_der_2048,
        RSAk, rng), TEST_SUCCESS);
    ExpectIntEQ(wc_TspResponse_Init(resp), 0);
    if (EXPECT_SUCCESS()) {
        resp->status = WC_TSP_PKISTATUS_GRANTED;
        resp->token = token;
        resp->tokenSz = *tokenSz;
    }

    return EXPECT_RESULT();
}
#endif

int test_wc_TspResponse_Verify(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    WC_RNG rng;
    TspTstInfo tstDec;
    TspResponse resp;
    byte token[3072];
    word32 tokenSz = (word32)sizeof(token);

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(test_tsp_make_granted_resp(&resp, token, &tokenSz, &rng),
        TEST_SUCCESS);

    /* Bad arguments. */
    ExpectIntEQ(wc_TspResponse_Verify(NULL, NULL, 0, &tstDec),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Verifies with the certificate in the token - no certificate needed.
     * The returned TSTInfo references the response's token, which is still
     * available after the call. */
    ExpectIntEQ(wc_TspResponse_Verify(&resp, NULL, 0, &tstDec), 0);
    ExpectIntEQ(tstDec.version, 1);
    ExpectIntEQ(tstDec.genTimeSz, (word32)sizeof(tsGenTime) - 1);
    ExpectBufEQ(tstDec.genTime, tsGenTime, (int)sizeof(tsGenTime) - 1);
    ExpectIntEQ(tstDec.serialSz, (word32)sizeof(tsSerial));
    ExpectBufEQ(tstDec.serial, tsSerial, (int)sizeof(tsSerial));
    /* The TSTInfo object is optional. */
    ExpectIntEQ(wc_TspResponse_Verify(&resp, NULL, 0, NULL), 0);

    /* The signer matches the trusted TSA certificate. */
    ExpectIntEQ(wc_TspResponse_Verify(&resp, tsa_cert_der_2048,
        sizeof_tsa_cert_der_2048, &tstDec), 0);

    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspResponse_Verify_wrong_cert(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    WC_RNG rng;
    TspTstInfo tstDec;
    TspResponse resp;
    byte token[3072];
    word32 tokenSz = (word32)sizeof(token);

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(test_tsp_make_granted_resp(&resp, token, &tokenSz, &rng),
        TEST_SUCCESS);

    /* A different trusted certificate is not the signer - the token is signed
     * by the TSA but not the one trusted. This certificate is a different
     * length to the signer's. */
    ExpectIntEQ(wc_TspResponse_Verify(&resp, client_cert_der_2048,
        sizeof_client_cert_der_2048, &tstDec),
        WC_NO_ERR_TRACE(TSP_VERIFY_E));
    /* A certificate of the same length as the signer's but with a different
     * public key - the trust check is a byte comparison, not just length. */
    {
        byte badCert[sizeof_tsa_cert_der_2048];

        XMEMCPY(badCert, tsa_cert_der_2048, sizeof(badCert));
        /* Corrupt a byte of the public key. */
        badCert[500] ^= 0xff;
        ExpectIntEQ(wc_TspResponse_Verify(&resp, badCert,
            (word32)sizeof(badCert), &tstDec), WC_NO_ERR_TRACE(TSP_VERIFY_E));
    }

    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspResponse_Verify_status(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    WC_RNG rng;
    TspTstInfo tstDec;
    TspResponse resp;
    byte token[3072];
    word32 tokenSz = (word32)sizeof(token);

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(test_tsp_make_granted_resp(&resp, token, &tokenSz, &rng),
        TEST_SUCCESS);

    /* A response that was not granted has no token to trust. */
    resp.status = WC_TSP_PKISTATUS_REJECTION;
    ExpectIntEQ(wc_TspResponse_Verify(&resp, NULL, 0, &tstDec),
        WC_NO_ERR_TRACE(TSP_VERIFY_E));
    resp.status = WC_TSP_PKISTATUS_GRANTED_WITH_MODS;
    ExpectIntEQ(wc_TspResponse_Verify(&resp, NULL, 0, &tstDec), 0);

    /* A granted response with no token does not verify. */
    resp.status = WC_TSP_PKISTATUS_GRANTED;
    resp.token = NULL;
    resp.tokenSz = 0;
    ExpectIntEQ(wc_TspResponse_Verify(&resp, NULL, 0, &tstDec),
        WC_NO_ERR_TRACE(TSP_VERIFY_E));

    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspResponse_Verify_modified(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    WC_RNG rng;
    TspTstInfo tstDec;
    TspResponse resp;
    byte token[3072];
    word32 tokenSz = (word32)sizeof(token);

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(test_tsp_make_granted_resp(&resp, token, &tokenSz, &rng),
        TEST_SUCCESS);

    /* A modified token does not verify. */
    if (EXPECT_SUCCESS()) {
        token[tokenSz - 5] ^= 0x80;
    }
    ExpectIntLT(wc_TspResponse_Verify(&resp, NULL, 0, &tstDec), 0);

    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspResponse_Verify_nocerts(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    WC_RNG rng;
    TspTstInfo tstDec;
    TspResponse resp;
    byte token[3072];
    word32 tokenSz = (word32)sizeof(token);

    ExpectIntEQ(wc_InitRng(&rng), 0);
    /* Token without certificates - certReq was FALSE in the request. */
    ExpectIntEQ(test_tsp_make_nocerts_token(token, &tokenSz, &rng),
        TEST_SUCCESS);
    ExpectIntEQ(wc_TspResponse_Init(&resp), 0);
    resp.status = WC_TSP_PKISTATUS_GRANTED;
    resp.token = token;
    resp.tokenSz = tokenSz;

    /* Cannot verify without the TSA's certificate. */
    ExpectIntLT(wc_TspResponse_Verify(&resp, NULL, 0, &tstDec), 0);
    /* Verifies when the TSA's certificate is supplied. */
    ExpectIntEQ(wc_TspResponse_Verify(&resp, tsa_cert_der_2048,
        sizeof_tsa_cert_der_2048, &tstDec), 0);

    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspResponse_VerifyData(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    wc_PKCS7* pkcs7 = NULL;
    WC_RNG rng;
    TspTstInfo tst;
    TspTstInfo tstDec;
    TspResponse resp;
    byte token[3072];
    word32 tokenSz = (word32)sizeof(token);
    static const byte data[] = "wolfSSL RFC 3161 time-stamp data";
    byte dataHash[WC_SHA256_DIGEST_SIZE];

    ExpectIntEQ(wc_InitRng(&rng), 0);
    /* The hash of the data is the token's message imprint. */
    ExpectIntEQ(wc_Sha256Hash(data, (word32)sizeof(data) - 1, dataHash), 0);

    test_tsp_set_tstinfo(&tst);
    tst.imprint.hashAlgOID = SHA256h;
    XMEMCPY(tst.imprint.hash, dataHash, sizeof(dataHash));
    tst.imprint.hashSz = (word32)sizeof(dataHash);

    /* A token signed by the TSA over the hash of the data. */
    ExpectIntEQ(test_tsp_new_tsa_signer(&pkcs7, &rng), TEST_SUCCESS);
    ExpectIntEQ(wc_TspTstInfo_SignWithPkcs7(&tst, pkcs7, token, &tokenSz), 0);
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;

    ExpectIntEQ(wc_TspResponse_Init(&resp), 0);
    resp.status = WC_TSP_PKISTATUS_GRANTED;
    resp.token = token;
    resp.tokenSz = tokenSz;

    /* Bad arguments. */
    ExpectIntEQ(wc_TspResponse_VerifyData(NULL, NULL, 0, data,
        (word32)sizeof(data) - 1, &tstDec), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspResponse_VerifyData(&resp, NULL, 0, NULL, 0, &tstDec),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Verifies the token and that it is over the data - no hashing by the
     * caller. */
    ExpectIntEQ(wc_TspResponse_VerifyData(&resp, NULL, 0, data,
        (word32)sizeof(data) - 1, &tstDec), 0);
    ExpectIntEQ(tstDec.imprint.hashSz, (word32)sizeof(dataHash));
    /* The TSTInfo object is optional. */
    ExpectIntEQ(wc_TspResponse_VerifyData(&resp, NULL, 0, data,
        (word32)sizeof(data) - 1, NULL), 0);

    /* Different data does not match the message imprint. */
    ExpectIntEQ(wc_TspResponse_VerifyData(&resp, NULL, 0,
        (const byte*)"different data", 14, &tstDec),
        WC_NO_ERR_TRACE(TSP_VERIFY_E));

    /* wc_TspTstInfo_VerifyData directly - bad args and match/mismatch. */
    ExpectIntEQ(wc_TspTstInfo_VerifyData(NULL, data, (word32)sizeof(data) - 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_VerifyData(&tstDec, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_VerifyData(&tstDec, data,
        (word32)sizeof(data) - 1), 0);
    ExpectIntEQ(wc_TspTstInfo_VerifyData(&tstDec, (const byte*)"x", 1),
        WC_NO_ERR_TRACE(TSP_VERIFY_E));
    /* An unknown imprint hash algorithm cannot be used to hash the data. */
    {
        TspTstInfo tstBad = tstDec;

        tstBad.imprint.hashAlgOID = 0;     /* not a known hash OID */
        ExpectIntEQ(wc_TspTstInfo_VerifyData(&tstBad, data,
            (word32)sizeof(data) - 1), WC_NO_ERR_TRACE(HASH_TYPE_E));
        /* An imprint length that doesn't match the algorithm's digest. */
        tstBad = tstDec;
        tstBad.imprint.hashSz = 16;        /* SHA-256 is 32 bytes */
        ExpectIntEQ(wc_TspTstInfo_VerifyData(&tstBad, data,
            (word32)sizeof(data) - 1), WC_NO_ERR_TRACE(TSP_VERIFY_E));
    }

    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_SetFromRequest(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    WC_RNG rng;
    TspRequest req;
    TspRequest reqDec;
    TspTstInfo tst;
    TspResponse resp;
    TspResponse respDec;
    TspTstInfo tstDec;
    byte reqDer[256];
    word32 reqDerSz = (word32)sizeof(reqDer);
    byte token[3072];
    word32 tokenSz = (word32)sizeof(token);
    byte respDer[3072];
    word32 respDerSz = (word32)sizeof(respDer);

    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* Requester: build and encode a request with an imprint and a nonce. */
    ExpectIntEQ(wc_TspRequest_Init(&req), 0);
    test_tsp_set_hash(&req.imprint);
    XMEMCPY(req.nonce, tsNonce, sizeof(tsNonce));
    req.nonceSz = (word32)sizeof(tsNonce);
    ExpectIntEQ(wc_TspRequest_Encode(&req, reqDer, &reqDerSz), 0);

    /* TSA: decode the request. */
    ExpectIntEQ(wc_TspRequest_Decode(&reqDec, reqDer, reqDerSz), 0);

    ExpectIntEQ(wc_TspTstInfo_Init(&tst), 0);

    /* Bad arguments. */
    ExpectIntEQ(wc_TspTstInfo_SetFromRequest(NULL, &reqDec, tsPolicy,
        (word32)sizeof(tsPolicy), tsSerial, (word32)sizeof(tsSerial), tsGenTime,
        (word32)sizeof(tsGenTime) - 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_SetFromRequest(&tst, NULL, tsPolicy,
        (word32)sizeof(tsPolicy), tsSerial, (word32)sizeof(tsSerial), tsGenTime,
        (word32)sizeof(tsGenTime) - 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_SetFromRequest(&tst, &reqDec, NULL, 0, tsSerial,
        (word32)sizeof(tsSerial), tsGenTime, (word32)sizeof(tsGenTime) - 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_SetFromRequest(&tst, &reqDec, tsPolicy,
        (word32)sizeof(tsPolicy), NULL, 0, tsGenTime,
        (word32)sizeof(tsGenTime) - 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Set the TSTInfo from the request and the TSA's values - the request's
     * message imprint and nonce are echoed. */
    ExpectIntEQ(wc_TspTstInfo_SetFromRequest(&tst, &reqDec, tsPolicy,
        (word32)sizeof(tsPolicy), tsSerial, (word32)sizeof(tsSerial), tsGenTime,
        (word32)sizeof(tsGenTime) - 1), 0);
    ExpectIntEQ(tst.imprint.hashSz, (word32)sizeof(tsHashedMsg));
    ExpectBufEQ(tst.imprint.hash, tsHashedMsg, (int)sizeof(tsHashedMsg));
    ExpectIntEQ(tst.nonceSz, (word32)sizeof(tsNonce));
    ExpectIntEQ(tst.policySz, (word32)sizeof(tsPolicy));
    ExpectIntEQ(tst.serialSz, (word32)sizeof(tsSerial));
    ExpectIntEQ(tst.genTimeSz, (word32)sizeof(tsGenTime) - 1);

    /* Sign the TSTInfo and wrap it in a granted response. */
    ExpectIntEQ(wc_TspTstInfo_Sign(&tst, tsa_cert_der_2048,
        sizeof_tsa_cert_der_2048, tsa_key_der_2048, sizeof_tsa_key_der_2048,
        WC_PK_TYPE_RSA, WC_HASH_TYPE_SHA256, &rng, token, &tokenSz), 0);
    ExpectIntEQ(wc_TspResponse_Init(&resp), 0);
    resp.status = WC_TSP_PKISTATUS_GRANTED;
    resp.token = token;
    resp.tokenSz = tokenSz;
    ExpectIntEQ(wc_TspResponse_Encode(&resp, respDer, &respDerSz), 0);

    /* The response verifies and echoes the request's imprint and nonce. */
    ExpectIntEQ(wc_TspResponse_Decode(&respDec, respDer, respDerSz), 0);
    ExpectIntEQ(respDec.status, WC_TSP_PKISTATUS_GRANTED);
    ExpectIntEQ(wc_TspResponse_Verify(&respDec, tsa_cert_der_2048,
        sizeof_tsa_cert_der_2048, &tstDec), 0);
    ExpectBufEQ(tstDec.imprint.hash, tsHashedMsg, (int)sizeof(tsHashedMsg));
    ExpectIntEQ(tstDec.nonceSz, (word32)sizeof(tsNonce));
    ExpectBufEQ(tstDec.nonce, tsNonce, (int)sizeof(tsNonce));
    ExpectIntEQ(tstDec.serialSz, (word32)sizeof(tsSerial));
    ExpectBufEQ(tstDec.serial, tsSerial, (int)sizeof(tsSerial));

    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
/* Create a time-stamp token like CMS SignedData with the given signed
 * attributes - no SigningCertificateV2 added. */
static int test_tsp_token_with_attribs(WC_RNG* rng, PKCS7Attrib* attribs,
    word32 attribsSz, byte* out, word32* outSz)
{
    EXPECT_DECLS;
    /* id-ct-TSTInfo: 1.2.840.113549.1.9.16.1.4. */
    static const byte tstInfoOid[] = {
        0x06, 0x0b,
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04
    };
    wc_PKCS7* pkcs7 = NULL;
    TspTstInfo tst;
    byte tstDer[256];
    word32 tstDerSz = (word32)sizeof(tstDer);
    int sz = 0;

    test_tsp_set_tstinfo(&tst);
    ExpectIntEQ(wc_TspTstInfo_Encode(&tst, tstDer, &tstDerSz), 0);

    ExpectIntEQ(test_tsp_new_tsa_signer(&pkcs7, rng), TEST_SUCCESS);
    ExpectIntEQ(wc_PKCS7_SetContentType(pkcs7, (byte*)tstInfoOid,
        (word32)sizeof(tstInfoOid)), 0);
    if (EXPECT_SUCCESS()) {
        pkcs7->content = tstDer;
        pkcs7->contentSz = tstDerSz;
        pkcs7->signedAttribs = attribs;
        pkcs7->signedAttribsSz = attribsSz;
    }
    ExpectIntGT(sz = wc_PKCS7_EncodeSignedData(pkcs7, out, *outSz), 0);
    if (EXPECT_SUCCESS()) {
        *outSz = (word32)sz;
    }
    wc_PKCS7_Free(pkcs7);

    return EXPECT_RESULT();
}
#endif

int test_wc_TspTstInfo_VerifyWithPKCS7_ess_no_attrib(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    wc_PKCS7* pkcs7 = NULL;
    WC_RNG rng;
    byte token[3072];
    word32 tokenSz;

    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* Signing certificate attribute must be present. */
    tokenSz = (word32)sizeof(token);
    ExpectIntEQ(test_tsp_token_with_attribs(&rng, NULL, 0, token, &tokenSz),
        TEST_SUCCESS);
    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    ExpectIntEQ(wc_TspTstInfo_VerifyWithPKCS7(pkcs7, token, tokenSz, NULL),
        WC_NO_ERR_TRACE(TSP_VERIFY_E));
    wc_PKCS7_Free(pkcs7);

    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_VerifyWithPKCS7_ess_bad_hash(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    /* id-aa-signingCertificateV2: 1.2.840.113549.1.9.16.2.47. */
    static const byte signCertV2Oid[] = {
        0x06, 0x0b,
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x2f
    };
    /* SigningCertificateV2 with a certHash that matches no certificate. */
    static const byte badSignCertV2[] = {
        0x30, 0x26, 0x30, 0x24, 0x30, 0x22, 0x04, 0x20,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    PKCS7Attrib attrib;
    wc_PKCS7* pkcs7 = NULL;
    WC_RNG rng;
    byte token[3072];
    word32 tokenSz;

    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* Signing certificate attribute must match the signer's certificate. */
    XMEMSET(&attrib, 0, sizeof(attrib));
    attrib.oid = signCertV2Oid;
    attrib.oidSz = (word32)sizeof(signCertV2Oid);
    attrib.value = badSignCertV2;
    attrib.valueSz = (word32)sizeof(badSignCertV2);
    tokenSz = (word32)sizeof(token);
    ExpectIntEQ(test_tsp_token_with_attribs(&rng, &attrib, 1, token, &tokenSz),
        TEST_SUCCESS);
    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    ExpectIntEQ(wc_TspTstInfo_VerifyWithPKCS7(pkcs7, token, tokenSz, NULL),
        WC_NO_ERR_TRACE(TSP_VERIFY_E));
    wc_PKCS7_Free(pkcs7);

    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_VerifyWithPKCS7_ess_bad_alg(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    /* id-aa-signingCertificateV2: 1.2.840.113549.1.9.16.2.47. */
    static const byte signCertV2Oid[] = {
        0x06, 0x0b,
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x2f
    };
    /* SigningCertificateV2 with a hash algorithm - 1.2.3.4 - that is not a
     * hash. */
    static const byte badAlgSignCertV2[] = {
        0x30, 0x0e, 0x30, 0x0c, 0x30, 0x0a,
        0x30, 0x05, 0x06, 0x03, 0x2a, 0x03, 0x04,
        0x04, 0x01, 0x00
    };
    PKCS7Attrib attrib;
    wc_PKCS7* pkcs7 = NULL;
    WC_RNG rng;
    byte token[3072];
    word32 tokenSz;

    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* Signing certificate attribute's hash algorithm must be available. */
    XMEMSET(&attrib, 0, sizeof(attrib));
    attrib.oid = signCertV2Oid;
    attrib.oidSz = (word32)sizeof(signCertV2Oid);
    attrib.value = badAlgSignCertV2;
    attrib.valueSz = (word32)sizeof(badAlgSignCertV2);
    tokenSz = (word32)sizeof(token);
    ExpectIntEQ(test_tsp_token_with_attribs(&rng, &attrib, 1, token, &tokenSz),
        TEST_SUCCESS);
    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    ExpectIntEQ(wc_TspTstInfo_VerifyWithPKCS7(pkcs7, token, tokenSz, NULL),
        WC_NO_ERR_TRACE(HASH_TYPE_E));
    wc_PKCS7_Free(pkcs7);

    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_VerifyWithPKCS7_ess_v1(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
#ifndef NO_SHA
    /* id-aa-signingCertificate: 1.2.840.113549.1.9.16.2.12. */
    static const byte signCertOid[] = {
        0x06, 0x0b,
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x0c
    };
    byte signCertV1[8 + WC_SHA_DIGEST_SIZE];
    PKCS7Attrib attrib;
    wc_PKCS7* pkcs7 = NULL;
    WC_RNG rng;
    byte token[3072];
    word32 tokenSz;

    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* SigningCertificate of ESS - RFC 2634 - with SHA-1 hash accepted. */
    signCertV1[0] = 0x30;
    signCertV1[1] = 0x1a;
    signCertV1[2] = 0x30;
    signCertV1[3] = 0x18;
    signCertV1[4] = 0x30;
    signCertV1[5] = 0x16;
    signCertV1[6] = 0x04;
    signCertV1[7] = 0x14;
    ExpectIntEQ(wc_ShaHash(tsa_cert_der_2048, sizeof_tsa_cert_der_2048,
        signCertV1 + 8), 0);
    XMEMSET(&attrib, 0, sizeof(attrib));
    attrib.oid = signCertOid;
    attrib.oidSz = (word32)sizeof(signCertOid);
    attrib.value = signCertV1;
    attrib.valueSz = (word32)sizeof(signCertV1);
    tokenSz = (word32)sizeof(token);
    ExpectIntEQ(test_tsp_token_with_attribs(&rng, &attrib, 1, token, &tokenSz),
        TEST_SUCCESS);
    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
#if WC_TSP_MIN_HASH_STRENGTH_BITS > 80
    /* SHA-1 of ESS SigningCertificate is below the minimum strength. */
    ExpectIntEQ(wc_TspTstInfo_VerifyWithPKCS7(pkcs7, token, tokenSz, NULL),
        WC_NO_ERR_TRACE(HASH_TYPE_E));
#else
    ExpectIntEQ(wc_TspTstInfo_VerifyWithPKCS7(pkcs7, token, tokenSz, NULL), 0);
#endif
    wc_PKCS7_Free(pkcs7);

    wc_FreeRng(&rng);
#endif
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_VerifyWithPKCS7_ecc(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && defined(HAVE_ECC) && \
    defined(USE_CERT_BUFFERS_256) && !defined(NO_SHA256) && \
    !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    wc_PKCS7* pkcs7 = NULL;
    WC_RNG rng;
    TspTstInfo tstDec;
    byte token[3072];
    word32 tokenSz = (word32)sizeof(token);

    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* Sign the token with the ECC TSA. */
    ExpectIntEQ(test_tsp_make_token(token, &tokenSz, tsa_ecc_cert_der_256,
        sizeof_tsa_ecc_cert_der_256, tsa_ecc_key_der_256,
        sizeof_tsa_ecc_key_der_256, ECDSAk, &rng), TEST_SUCCESS);

    /* Verify the ECDSA signed token. */
    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    ExpectIntEQ(wc_TspTstInfo_VerifyWithPKCS7(pkcs7, token, tokenSz, &tstDec), 0);
    ExpectIntEQ(tstDec.version, WC_TSP_VERSION);
    ExpectBufEQ(tstDec.imprint.hash, tsHashedMsg,
        (int)sizeof(tsHashedMsg));
    wc_PKCS7_Free(pkcs7);

    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_CheckTsaName(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    /* Name of TSA: dNSName GeneralName. */
    static const byte tsaName[] = { 0x82, 0x03, 't', 's', 'a' };
    /* A different name of the same length. */
    static const byte otherName[] = { 0x82, 0x03, 't', 's', 'b' };
    TspTstInfo tst;

    ExpectIntEQ(wc_TspTstInfo_Init(&tst), 0);

    /* Bad arguments. */
    ExpectIntEQ(wc_TspTstInfo_CheckTsaName(NULL, tsaName,
        (word32)sizeof(tsaName)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_CheckTsaName(&tst, NULL, (word32)sizeof(tsaName)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_TspTstInfo_CheckTsaName(&tst, tsaName, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* TSA name must be present when expected. */
    ExpectIntEQ(wc_TspTstInfo_CheckTsaName(&tst, tsaName,
        (word32)sizeof(tsaName)), WC_NO_ERR_TRACE(TSP_VERIFY_E));

    /* TSA name is the expected name. */
    tst.tsa = tsaName;
    tst.tsaSz = (word32)sizeof(tsaName);
    ExpectIntEQ(wc_TspTstInfo_CheckTsaName(&tst, tsaName,
        (word32)sizeof(tsaName)), 0);
    /* Expected name of a different length. */
    ExpectIntEQ(wc_TspTstInfo_CheckTsaName(&tst, tsaName,
        (word32)sizeof(tsaName) - 1), WC_NO_ERR_TRACE(TSP_VERIFY_E));
    /* Expected name with different data. */
    ExpectIntEQ(wc_TspTstInfo_CheckTsaName(&tst, otherName,
        (word32)sizeof(otherName)), WC_NO_ERR_TRACE(TSP_VERIFY_E));
#endif
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
/* Build a token whose TSTInfo carries the given TSA name. The signing PKCS7
 * is created and freed here so the verifying caller news only its own. */
static int test_tsp_make_tsa_name_token(WC_RNG* rng, const byte* tsa,
    word32 tsaSz, byte* token, word32* tokenSz)
{
    EXPECT_DECLS;
    wc_PKCS7* pkcs7 = NULL;
    TspTstInfo tst;

    test_tsp_set_tstinfo(&tst);
    tst.tsa = tsa;
    tst.tsaSz = tsaSz;

    ExpectIntEQ(test_tsp_new_tsa_signer(&pkcs7, rng), TEST_SUCCESS);
    ExpectIntEQ(wc_TspTstInfo_SignWithPkcs7(&tst, pkcs7, token, tokenSz), 0);
    wc_PKCS7_Free(pkcs7);

    return EXPECT_RESULT();
}

/* Create and verify a token with a TSA name in the TSTInfo. */
static int test_tsp_tsa_name(WC_RNG* rng, const byte* tsa, word32 tsaSz,
    int expRet)
{
    EXPECT_DECLS;
    wc_PKCS7* pkcs7 = NULL;
    TspTstInfo tstDec;
    byte token[3072];
    word32 tokenSz = (word32)sizeof(token);

    ExpectIntEQ(test_tsp_make_tsa_name_token(rng, tsa, tsaSz, token, &tokenSz),
        TEST_SUCCESS);

    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    ExpectIntEQ(wc_TspTstInfo_VerifyWithPKCS7(pkcs7, token, tokenSz, &tstDec),
        expRet);
    if (expRet == 0) {
        /* TSA name decoded is the expected name. */
        ExpectIntEQ(wc_TspTstInfo_CheckTsaName(&tstDec, tsa, tsaSz), 0);
    }
    wc_PKCS7_Free(pkcs7);

    return EXPECT_RESULT();
}

#if !defined(IGNORE_NAME_CONSTRAINTS) || defined(WOLFSSL_CERT_EXT)
/* Make a directoryName GeneralName with the subject of the certificate. */
static int test_tsp_cert_dirname(const byte* certDer, word32 certDerSz,
    byte* out, word32* outSz)
{
    EXPECT_DECLS;
    DecodedCert cert;
    word32 idx = 0;
    word32 nameLen = 0;

    wc_InitDecodedCert(&cert, certDer, certDerSz, NULL);
    ExpectIntEQ(wc_ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL), 0);
    if (EXPECT_SUCCESS()) {
        nameLen = (word32)cert.subjectRawLen;
    }
    ExpectNotNull(cert.subjectRaw);
    ExpectIntLE(2 + 3 + 3 + nameLen, *outSz);
    if (EXPECT_SUCCESS()) {
        word32 seqLen = 2 + nameLen + ((nameLen >= 128) ? 1 : 0);

        /* directoryName [4] of GeneralName - explicitly tagged Name. */
        out[idx++] = ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | ASN_DIR_TYPE;
        if (seqLen >= 128) {
            out[idx++] = 0x81;
        }
        out[idx++] = (byte)seqLen;
        out[idx++] = ASN_SEQUENCE | ASN_CONSTRUCTED;
        if (nameLen >= 128) {
            out[idx++] = 0x81;
        }
        out[idx++] = (byte)nameLen;
        XMEMCPY(out + idx, cert.subjectRaw, nameLen);
        *outSz = idx + nameLen;
    }
    wc_FreeDecodedCert(&cert);

    return EXPECT_RESULT();
}
#endif
#endif

int test_wc_TspTstInfo_VerifyWithPKCS7_tsa_name(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    /* dNSName of the TSA's certificate. */
    static const byte goodDns[] = {
        0x82, 0x0f,
        't', 's', 'a', '.', 'w', 'o', 'l', 'f', 's', 's', 'l', '.', 'c',
        'o', 'm'
    };
    WC_RNG rng;

    ExpectIntEQ(wc_InitRng(&rng), 0);
    /* TSA name in subject alternative names of certificate. */
    ExpectIntEQ(test_tsp_tsa_name(&rng, goodDns, (word32)sizeof(goodDns), 0),
        TEST_SUCCESS);
    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_VerifyWithPKCS7_tsa_name_mismatch(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    /* dNSName not of the TSA's certificate. */
    static const byte badDns[] = {
        0x82, 0x0f,
        't', 's', 'b', '.', 'w', 'o', 'l', 'f', 's', 's', 'l', '.', 'c',
        'o', 'm'
    };
    WC_RNG rng;

    ExpectIntEQ(wc_InitRng(&rng), 0);
    /* TSA name not in subject alternative names of certificate. */
    ExpectIntEQ(test_tsp_tsa_name(&rng, badDns, (word32)sizeof(badDns),
        WC_NO_ERR_TRACE(TSP_VERIFY_E)), TEST_SUCCESS);
    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_VerifyWithPKCS7_tsa_name_unsupported(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    /* otherName - form of GeneralName not supported. */
    static const byte otherName[] = { 0xa0, 0x02, 0x05, 0x00 };
    WC_RNG rng;

    ExpectIntEQ(wc_InitRng(&rng), 0);
    /* Form of GeneralName not supported. */
    ExpectIntEQ(test_tsp_tsa_name(&rng, otherName, (word32)sizeof(otherName),
        WC_NO_ERR_TRACE(TSP_VERIFY_E)), TEST_SUCCESS);
    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_VerifyWithPKCS7_tsa_name_bad_enc(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER)
    /* dNSName with a length longer than the data. */
    static const byte badLen[] = { 0x82, 0x05, 't' };
#if !defined(IGNORE_NAME_CONSTRAINTS) || defined(WOLFSSL_CERT_EXT)
    /* directoryName that does not hold a SEQUENCE. */
    static const byte badDirName[] = { 0xa4, 0x02, 0x31, 0x00 };
#endif
    WC_RNG rng;

    ExpectIntEQ(wc_InitRng(&rng), 0);
    /* Invalid GeneralName encoding. */
    ExpectIntEQ(test_tsp_tsa_name(&rng, badLen, (word32)sizeof(badLen),
        WC_NO_ERR_TRACE(ASN_PARSE_E)), TEST_SUCCESS);
#if !defined(IGNORE_NAME_CONSTRAINTS) || defined(WOLFSSL_CERT_EXT)
    /* directoryName must hold a Name. */
    ExpectIntEQ(test_tsp_tsa_name(&rng, badDirName, (word32)sizeof(badDirName),
        WC_NO_ERR_TRACE(ASN_PARSE_E)), TEST_SUCCESS);
#endif
    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_TspTstInfo_VerifyWithPKCS7_tsa_name_dirname(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    defined(WOLFSSL_TSP_REQUESTER) && defined(WOLFSSL_TSP_RESPONDER) && \
    (!defined(IGNORE_NAME_CONSTRAINTS) || defined(WOLFSSL_CERT_EXT))
    byte dirName[256];
    word32 dirNameSz;
    WC_RNG rng;

    ExpectIntEQ(wc_InitRng(&rng), 0);
    /* TSA name is subject name of certificate. */
    dirNameSz = (word32)sizeof(dirName);
    ExpectIntEQ(test_tsp_cert_dirname(tsa_cert_der_2048,
        sizeof_tsa_cert_der_2048, dirName, &dirNameSz), TEST_SUCCESS);
    ExpectIntEQ(test_tsp_tsa_name(&rng, dirName, dirNameSz, 0), TEST_SUCCESS);
    /* TSA name is subject name of another certificate. */
    dirNameSz = (word32)sizeof(dirName);
    ExpectIntEQ(test_tsp_cert_dirname(client_cert_der_2048,
        sizeof_client_cert_der_2048, dirName, &dirNameSz), TEST_SUCCESS);
    ExpectIntEQ(test_tsp_tsa_name(&rng, dirName, dirNameSz,
        WC_NO_ERR_TRACE(TSP_VERIFY_E)), TEST_SUCCESS);
    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}
