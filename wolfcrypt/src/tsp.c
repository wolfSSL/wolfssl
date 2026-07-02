/* tsp.c
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

/*
 * DESCRIPTION
 * This library provides the application interface to the Time-Stamp Protocol
 * (TSP): TimeStampReq, TSTInfo and TimeStampResp setup and accessors, and
 * verification helpers for a response. RFC 3161.
 *
 * The encoding and decoding of TSP messages, and creation and verification of
 * time-stamp tokens (which use ASN.1 template machinery private to asn.c), are
 * in asn_tsp.c.
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if defined(WOLFSSL_TSP) && defined(WOLFSSL_ASN_TEMPLATE) && !defined(NO_ASN)

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/tsp.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/random.h>
#ifdef HAVE_PKCS7
    #include <wolfssl/wolfcrypt/pkcs7.h>
#endif

#ifdef WOLFSSL_TSP_REQUESTER
/* Initialize a TimeStampReq.
 *
 * @param [out] req  TimeStampReq object.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when req is NULL.
 */
int wc_TspRequest_Init(TspRequest* req)
{
    /* Validate parameter. */
    if (req == NULL) {
        return BAD_FUNC_ARG;
    }

    /* All fields empty - optional fields not encoded. */
    XMEMSET(req, 0, sizeof(TspRequest));
    /* Only version 1 defined. */
    req->version = WC_TSP_VERSION;

    return 0;
}
#endif /* WOLFSSL_TSP_REQUESTER */

#if defined(WOLFSSL_TSP_REQUESTER) || defined(WOLFSSL_TSP_VERIFIER)
/* Get the message imprint hash type of a TimeStampReq.
 *
 * Maps the message imprint hash algorithm OID to a hash type. The OID may be
 * one not recognized as a hash algorithm - e.g. after decoding a request from
 * an unknown source.
 *
 * @param [in]  req       TimeStampReq object.
 * @param [out] hashType  Hash algorithm of the message imprint.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when req or hashType is NULL.
 * @return  HASH_TYPE_E when the hash algorithm is not a recognized hash.
 */
int wc_TspRequest_GetHashType(const TspRequest* req, enum wc_HashType* hashType)
{
    int ret = 0;

    /* Validate parameters. */
    if ((req == NULL) || (hashType == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Map the OID sum to a hash type - NONE when not a known hash. */
        *hashType = wc_OidGetHash((int)req->imprint.hashAlgOID);
        if (*hashType == WC_HASH_TYPE_NONE) {
            ret = HASH_TYPE_E;
        }
    }

    return ret;
}
#endif /* WOLFSSL_TSP_REQUESTER || WOLFSSL_TSP_VERIFIER */

#ifdef WOLFSSL_TSP_REQUESTER
/* Set the message imprint hash algorithm of a TimeStampReq.
 *
 * Sets the hash algorithm OID and hash size from the hash type. The caller
 * fills req->imprint.hash with the digest of the data to be time-stamped.
 *
 * @param [in, out] req       TimeStampReq object.
 * @param [in]      hashType  Hash algorithm to use - e.g. WC_HASH_TYPE_SHA256.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when req is NULL.
 * @return  HASH_TYPE_E when the hash algorithm is not available.
 * @return  BUFFER_E when the digest is too big for the message imprint.
 */
int wc_TspRequest_SetHashType(TspRequest* req, enum wc_HashType hashType)
{
    int ret = 0;
    int oid = 0;
    int digestSz = 0;

    /* Validate parameter. */
    if (req == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Map the hash type to its OID sum - negative when not available. */
        oid = wc_HashGetOID(hashType);
        if (oid <= 0) {
            ret = HASH_TYPE_E;
        }
    }
    if (ret == 0) {
        /* The digest size is the length of the message imprint hash. */
        digestSz = wc_HashGetDigestSize(hashType);
        if (digestSz <= 0) {
            ret = HASH_TYPE_E;
        }
        else if (digestSz > (int)sizeof(req->imprint.hash)) {
            ret = BUFFER_E;
        }
    }
    if (ret == 0) {
        req->imprint.hashAlgOID = (word32)oid;
        req->imprint.hashSz = (word32)digestSz;
    }

    return ret;
}
#endif /* WOLFSSL_TSP_REQUESTER */

#if defined(WOLFSSL_TSP_REQUESTER) || defined(WOLFSSL_TSP_VERIFIER)
/* Get the message imprint hash of a TimeStampReq.
 *
 * Copies the hash into the caller's buffer.
 *
 * @param [in]      req     TimeStampReq object.
 * @param [out]     hash    Buffer to hold the hash.
 * @param [in, out] hashSz  On in, length of buffer in bytes.
 *                          On out, length of the hash in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when req, hash or hashSz is NULL.
 * @return  BUFFER_E when the buffer is too small for the hash.
 */
int wc_TspRequest_GetHash(const TspRequest* req, byte* hash, word32* hashSz)
{
    int ret = 0;

    /* Validate parameters. */
    if ((req == NULL) || (hash == NULL) || (hashSz == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else if (*hashSz < req->imprint.hashSz) {
        ret = BUFFER_E;
    }

    if (ret == 0) {
        XMEMCPY(hash, req->imprint.hash, req->imprint.hashSz);
        *hashSz = req->imprint.hashSz;
    }

    return ret;
}
#endif /* WOLFSSL_TSP_REQUESTER || WOLFSSL_TSP_VERIFIER */

#ifdef WOLFSSL_TSP_REQUESTER
/* Set the message imprint hash of a TimeStampReq.
 *
 * Copies the hash and its length into the message imprint. The hash algorithm
 * is set separately - see wc_TspRequest_SetHashType().
 *
 * @param [in, out] req     TimeStampReq object.
 * @param [in]      hash    Hash of the data to be time-stamped.
 * @param [in]      hashSz  Length of hash in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when req or hash is NULL or hashSz is 0.
 * @return  BUFFER_E when hashSz is too big for the message imprint.
 */
int wc_TspRequest_SetHash(TspRequest* req, const byte* hash, word32 hashSz)
{
    int ret = 0;

    /* Validate parameters. */
    if ((req == NULL) || (hash == NULL) || (hashSz == 0)) {
        ret = BAD_FUNC_ARG;
    }
    else if (hashSz > sizeof(req->imprint.hash)) {
        ret = BUFFER_E;
    }

    if (ret == 0) {
        XMEMCPY(req->imprint.hash, hash, hashSz);
        req->imprint.hashSz = hashSz;
    }

    return ret;
}
#endif /* WOLFSSL_TSP_REQUESTER */

#if defined(WOLFSSL_TSP_REQUESTER) || defined(WOLFSSL_TSP_VERIFIER)
/* Get the nonce of a TimeStampReq.
 *
 * Copies the nonce into the caller's buffer. A length of 0 means no nonce is
 * set.
 *
 * @param [in]      req      TimeStampReq object.
 * @param [out]     nonce    Buffer to hold the nonce.
 * @param [in, out] nonceSz  On in, length of buffer in bytes.
 *                           On out, length of the nonce in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when req, nonce or nonceSz is NULL.
 * @return  BUFFER_E when the buffer is too small for the nonce.
 */
int wc_TspRequest_GetNonce(const TspRequest* req, byte* nonce, word32* nonceSz)
{
    int ret = 0;

    /* Validate parameters. */
    if ((req == NULL) || (nonce == NULL) || (nonceSz == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else if (*nonceSz < req->nonceSz) {
        ret = BUFFER_E;
    }

    if (ret == 0) {
        XMEMCPY(nonce, req->nonce, req->nonceSz);
        *nonceSz = req->nonceSz;
    }

    return ret;
}
#endif /* WOLFSSL_TSP_REQUESTER || WOLFSSL_TSP_VERIFIER */

#ifdef WOLFSSL_TSP_REQUESTER
/* Set the nonce of a TimeStampReq.
 *
 * The nonce is a big-endian number that must not have a leading zero byte to
 * encode. Leading zero bytes are stripped, keeping at least one byte so an
 * all-zero nonce becomes the number zero.
 *
 * @param [in, out] req      TimeStampReq object.
 * @param [in]      nonce    Nonce as a big-endian number.
 * @param [in]      nonceSz  Length of nonce in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when req or nonce is NULL or nonceSz is 0.
 * @return  BUFFER_E when nonceSz is too big for the nonce field.
 */
int wc_TspRequest_SetNonce(TspRequest* req, const byte* nonce, word32 nonceSz)
{
    int ret = 0;

    /* Validate parameters. */
    if ((req == NULL) || (nonce == NULL) || (nonceSz == 0)) {
        ret = BAD_FUNC_ARG;
    }
    else if (nonceSz > sizeof(req->nonce)) {
        ret = BUFFER_E;
    }

    if (ret == 0) {
        /* Strip leading zeros. */
        while ((nonceSz > 1) && (nonce[0] == 0x00)) {
            nonce++;
            nonceSz--;
        }
        XMEMCPY(req->nonce, nonce, nonceSz);
        req->nonceSz = nonceSz;
    }

    return ret;
}

#ifndef WC_NO_RNG
/* Generate a random nonce for a TimeStampReq.
 *
 * A convenience over generating random bytes and calling
 * wc_TspRequest_SetNonce(). The nonce is a minimal positive INTEGER: the top
 * bit of the first byte is cleared so it is positive and the first byte is
 * made non-zero so there is no leading zero byte to strip.
 *
 * @param [in, out] req  TimeStampReq object.
 * @param [in]      rng  Random number generator.
 * @param [in]      sz   Length of nonce to generate in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when req or rng is NULL or sz is 0.
 * @return  BUFFER_E when sz is too big for the nonce field.
 * @return  Other negative value on random number generation failure.
 */
int wc_TspRequest_GenerateNonce(TspRequest* req, WC_RNG* rng, word32 sz)
{
    int ret = 0;

    /* Validate parameters. */
    if ((req == NULL) || (rng == NULL) || (sz == 0)) {
        ret = BAD_FUNC_ARG;
    }
    else if (sz > sizeof(req->nonce)) {
        ret = BUFFER_E;
    }

    if (ret == 0) {
        ret = wc_RNG_GenerateBlock(rng, req->nonce, sz);
    }
    if (ret == 0) {
        /* Make a minimal positive INTEGER: clear the sign bit and ensure a
         * non-zero leading byte so there is no leading zero to strip. */
        req->nonce[0] &= 0x7F;
        if (req->nonce[0] == 0x00) {
            req->nonce[0] = 0x01;
        }
        req->nonceSz = sz;
    }

    return ret;
}
#endif /* WC_NO_RNG */
#endif /* WOLFSSL_TSP_REQUESTER */

#if defined(WOLFSSL_TSP_REQUESTER) || defined(WOLFSSL_TSP_VERIFIER)
/* Get the TSA policy of a TimeStampReq.
 *
 * Copies the policy into the caller's buffer. A length of 0 means no policy is
 * set.
 *
 * @param [in]      req       TimeStampReq object.
 * @param [out]     policy    Buffer to hold the policy.
 * @param [in, out] policySz  On in, length of buffer in bytes.
 *                            On out, length of the policy in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when req, policy or policySz is NULL.
 * @return  BUFFER_E when the buffer is too small for the policy.
 */
int wc_TspRequest_GetPolicy(const TspRequest* req, byte* policy,
    word32* policySz)
{
    int ret = 0;

    /* Validate parameters. */
    if ((req == NULL) || (policy == NULL) || (policySz == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else if (*policySz < req->policySz) {
        ret = BUFFER_E;
    }

    if (ret == 0) {
        XMEMCPY(policy, req->policy, req->policySz);
        *policySz = req->policySz;
    }

    return ret;
}
#endif /* WOLFSSL_TSP_REQUESTER || WOLFSSL_TSP_VERIFIER */

#ifdef WOLFSSL_TSP_REQUESTER
/* Set the TSA policy of a TimeStampReq.
 *
 * The policy is the content of an OBJECT IDENTIFIER - the bytes after the type
 * and length. It is copied into the request.
 *
 * @param [in, out] req       TimeStampReq object.
 * @param [in]      policy    Policy as OBJECT IDENTIFIER content.
 * @param [in]      policySz  Length of policy in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when req or policy is NULL or policySz is 0.
 * @return  BUFFER_E when policySz is too big for the policy field.
 */
int wc_TspRequest_SetPolicy(TspRequest* req, const byte* policy,
    word32 policySz)
{
    int ret = 0;

    /* Validate parameters. */
    if ((req == NULL) || (policy == NULL) || (policySz == 0)) {
        ret = BAD_FUNC_ARG;
    }
    else if (policySz > sizeof(req->policy)) {
        ret = BUFFER_E;
    }

    if (ret == 0) {
        XMEMCPY(req->policy, policy, policySz);
        req->policySz = policySz;
    }

    return ret;
}
#endif /* WOLFSSL_TSP_REQUESTER */

#ifdef WOLFSSL_TSP_RESPONDER
/* Initialize a TSTInfo.
 *
 * @param [out] tstInfo  TSTInfo object.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when tstInfo is NULL.
 */
int wc_TspTstInfo_Init(TspTstInfo* tstInfo)
{
    /* Validate parameter. */
    if (tstInfo == NULL) {
        return BAD_FUNC_ARG;
    }

    /* All fields empty - optional fields not encoded. */
    XMEMSET(tstInfo, 0, sizeof(TspTstInfo));
    /* Only version 1 defined. */
    tstInfo->version = WC_TSP_VERSION;

    return 0;
}
#endif /* WOLFSSL_TSP_RESPONDER */

#if defined(WOLFSSL_TSP_RESPONDER) || defined(WOLFSSL_TSP_VERIFIER)
/* Get the serial number of a TSTInfo.
 *
 * Returns a reference to the serial number - it is not copied and is valid
 * while the TSTInfo references it.
 *
 * @param [in]  tstInfo   TSTInfo object.
 * @param [out] serial    Serial number as a big-endian number.
 * @param [out] serialSz  Length of serial number in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when tstInfo, serial or serialSz is NULL.
 */
int wc_TspTstInfo_GetSerial(const TspTstInfo* tstInfo, const byte** serial,
    word32* serialSz)
{
    /* Validate parameters. */
    if ((tstInfo == NULL) || (serial == NULL) || (serialSz == NULL)) {
        return BAD_FUNC_ARG;
    }

    *serial = tstInfo->serial;
    *serialSz = tstInfo->serialSz;

    return 0;
}
#endif /* WOLFSSL_TSP_RESPONDER || WOLFSSL_TSP_VERIFIER */

#ifdef WOLFSSL_TSP_RESPONDER
/* Set the serial number of a TSTInfo.
 *
 * The serial number is a big-endian number that is referenced - it is not
 * copied and must remain available while the TSTInfo is used. Leading zero
 * bytes are stripped, keeping at least one byte, so the serial number has no
 * leading zero byte and encodes - an all-zero serial number becomes zero.
 *
 * @param [in, out] tstInfo   TSTInfo object.
 * @param [in]      serial    Serial number as a big-endian number.
 * @param [in]      serialSz  Length of serial number in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when tstInfo or serial is NULL or serialSz is 0.
 */
int wc_TspTstInfo_SetSerial(TspTstInfo* tstInfo, const byte* serial,
    word32 serialSz)
{
    /* Validate parameters. */
    if ((tstInfo == NULL) || (serial == NULL) || (serialSz == 0)) {
        return BAD_FUNC_ARG;
    }

    /* Strip leading zero bytes - keep at least one byte. */
    while ((serialSz > 1) && (serial[0] == 0x00)) {
        serial++;
        serialSz--;
    }
    tstInfo->serial = serial;
    tstInfo->serialSz = serialSz;

    return 0;
}
#endif /* WOLFSSL_TSP_RESPONDER */

#if defined(WOLFSSL_TSP_RESPONDER) || defined(WOLFSSL_TSP_VERIFIER)
/* Get the TSA policy of a TSTInfo.
 *
 * Returns a reference to the policy - it is not copied and is valid while the
 * TSTInfo references it. A length of 0 means no policy is present.
 *
 * @param [in]  tstInfo   TSTInfo object.
 * @param [out] policy    Policy as OBJECT IDENTIFIER content.
 * @param [out] policySz  Length of policy in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when tstInfo, policy or policySz is NULL.
 */
int wc_TspTstInfo_GetPolicy(const TspTstInfo* tstInfo, const byte** policy,
    word32* policySz)
{
    /* Validate parameters. */
    if ((tstInfo == NULL) || (policy == NULL) || (policySz == NULL)) {
        return BAD_FUNC_ARG;
    }

    *policy = tstInfo->policy;
    *policySz = tstInfo->policySz;

    return 0;
}
#endif /* WOLFSSL_TSP_RESPONDER || WOLFSSL_TSP_VERIFIER */

#ifdef WOLFSSL_TSP_RESPONDER
/* Set the TSA policy of a TSTInfo.
 *
 * The policy is the content of an OBJECT IDENTIFIER - it is referenced, not
 * copied, and must remain available while the TSTInfo is used.
 *
 * @param [in, out] tstInfo   TSTInfo object.
 * @param [in]      policy    Policy as OBJECT IDENTIFIER content.
 * @param [in]      policySz  Length of policy in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when tstInfo or policy is NULL or policySz is 0.
 */
int wc_TspTstInfo_SetPolicy(TspTstInfo* tstInfo, const byte* policy,
    word32 policySz)
{
    /* Validate parameters. */
    if ((tstInfo == NULL) || (policy == NULL) || (policySz == 0)) {
        return BAD_FUNC_ARG;
    }

    tstInfo->policy = policy;
    tstInfo->policySz = policySz;

    return 0;
}
#endif /* WOLFSSL_TSP_RESPONDER */

#if defined(WOLFSSL_TSP_RESPONDER) || defined(WOLFSSL_TSP_VERIFIER)
/* Get the message imprint of a TSTInfo.
 *
 * The hash is the digest of the time-stamped data. Each output is optional -
 * pass NULL to not retrieve it. The hash references the TSTInfo.
 *
 * @param [in]  tstInfo  TSTInfo object.
 * @param [out] hashOID  Hash algorithm OID sum. May be NULL.
 * @param [out] hash     Hash of the time-stamped data. May be NULL.
 * @param [out] hashSz   Length of hash in bytes. May be NULL.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when tstInfo is NULL.
 */
int wc_TspTstInfo_GetMsgImprint(const TspTstInfo* tstInfo, word32* hashOID,
    const byte** hash, word32* hashSz)
{
    /* Validate parameter. */
    if (tstInfo == NULL) {
        return BAD_FUNC_ARG;
    }

    if (hashOID != NULL) {
        *hashOID = tstInfo->imprint.hashAlgOID;
    }
    if (hash != NULL) {
        *hash = tstInfo->imprint.hash;
    }
    if (hashSz != NULL) {
        *hashSz = tstInfo->imprint.hashSz;
    }

    return 0;
}
#endif /* WOLFSSL_TSP_RESPONDER || WOLFSSL_TSP_VERIFIER */

#ifdef WOLFSSL_TSP_RESPONDER
/* Set the message imprint of a TSTInfo.
 *
 * The hash is the digest of the data being time-stamped - it is copied into
 * the TSTInfo. The hash and algorithm are typically those of the request.
 *
 * @param [in, out] tstInfo  TSTInfo object.
 * @param [in]      hashOID  Hash algorithm OID sum: SHA256h, etc.
 * @param [in]      hash     Hash of the data to time-stamp.
 * @param [in]      hashSz   Length of hash in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when tstInfo or hash is NULL or hashSz is 0.
 * @return  BUFFER_E when hashSz is too big for the message imprint.
 */
int wc_TspTstInfo_SetMsgImprint(TspTstInfo* tstInfo, word32 hashOID,
    const byte* hash, word32 hashSz)
{
    /* Validate parameters. */
    if ((tstInfo == NULL) || (hash == NULL) || (hashSz == 0)) {
        return BAD_FUNC_ARG;
    }
    if (hashSz > sizeof(tstInfo->imprint.hash)) {
        return BUFFER_E;
    }

    tstInfo->imprint.hashAlgOID = hashOID;
    XMEMCPY(tstInfo->imprint.hash, hash, hashSz);
    tstInfo->imprint.hashSz = hashSz;

    return 0;
}
#endif /* WOLFSSL_TSP_RESPONDER */

#if defined(WOLFSSL_TSP_RESPONDER) || defined(WOLFSSL_TSP_VERIFIER)
/* Get the time of the time-stamp of a TSTInfo.
 *
 * Returns a reference to the genTime as a GeneralizedTime string of RFC 3161:
 * "YYYYMMDDhhmmss[.s...]Z" - not copied and valid while the TSTInfo references
 * it.
 *
 * @param [in]  tstInfo    TSTInfo object.
 * @param [out] genTime    Time as a GeneralizedTime string.
 * @param [out] genTimeSz  Length of string in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when tstInfo, genTime or genTimeSz is NULL.
 */
int wc_TspTstInfo_GetGenTime(const TspTstInfo* tstInfo, const byte** genTime,
    word32* genTimeSz)
{
    /* Validate parameters. */
    if ((tstInfo == NULL) || (genTime == NULL) || (genTimeSz == NULL)) {
        return BAD_FUNC_ARG;
    }

    *genTime = tstInfo->genTime;
    *genTimeSz = tstInfo->genTimeSz;

    return 0;
}
#endif /* WOLFSSL_TSP_RESPONDER || WOLFSSL_TSP_VERIFIER */

#ifdef WOLFSSL_TSP_RESPONDER
/* Set the time of the time-stamp of a TSTInfo.
 *
 * The genTime is a GeneralizedTime string of RFC 3161 - it is referenced, not
 * copied, and must remain available while the TSTInfo is used. The syntax is
 * checked on encode. Leave unset to use the current time on encode.
 *
 * @param [in, out] tstInfo    TSTInfo object.
 * @param [in]      genTime    Time as a GeneralizedTime string.
 * @param [in]      genTimeSz  Length of string in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when tstInfo or genTime is NULL or genTimeSz is 0.
 */
int wc_TspTstInfo_SetGenTime(TspTstInfo* tstInfo, const byte* genTime,
    word32 genTimeSz)
{
    /* Validate parameters. */
    if ((tstInfo == NULL) || (genTime == NULL) || (genTimeSz == 0)) {
        return BAD_FUNC_ARG;
    }

    tstInfo->genTime = genTime;
    tstInfo->genTimeSz = genTimeSz;

    return 0;
}
#endif /* WOLFSSL_TSP_RESPONDER */

#ifndef NO_ASN_TIME
#if defined(WOLFSSL_TSP_RESPONDER) || defined(WOLFSSL_TSP_VERIFIER)
/* Convert a broken-down UTC time to seconds since the Unix epoch.
 *
 * Computed directly rather than with mktime() - mktime() interprets the
 * fields as local time and may overflow a 32-bit time_t in 2038.
 *
 * @param [in] year  Year including century. e.g. 2026.
 * @param [in] mon   Month of year. 1-12.
 * @param [in] day   Day of month. 1-31.
 * @param [in] hour  Hour of day. 0-23.
 * @param [in] min   Minute of hour. 0-59.
 * @param [in] sec   Second of minute. 0-60.
 * @return  Seconds since 00:00:00 UTC, 1 January 1970.
 */
static time_t TspGenTimeToUnix(int year, int mon, int day, int hour, int min,
    int sec)
{
    /* Cumulative days before each month in a non-leap year. */
    static const int monthDays[12] = {
        0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
    };
    /* Years contributing a leap day - exclude this year before March. */
    int y = year - ((mon <= 2) ? 1 : 0);
    int leapDays = y / 4 - y / 100 + y / 400 -
                   (1969 / 4 - 1969 / 100 + 1969 / 400);

    return (time_t)(((((time_t)(year - 1970) * 365 + leapDays +
        monthDays[mon - 1] + day - 1) * 24 + hour) * 60 + min) * 60 + sec);
}

/* Get the time of the time-stamp of a TSTInfo as a time_t.
 *
 * Parses the genTime GeneralizedTime string of RFC 3161 - any fraction of a
 * second is ignored. The time is UTC.
 *
 * Not available when there is no time support - NO_ASN_TIME.
 *
 * @param [in]  tstInfo  TSTInfo object.
 * @param [out] t        Time of the time-stamp as seconds since the Unix
 *                       epoch.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when tstInfo, its genTime or t is NULL.
 * @return  ASN_PARSE_E when the genTime string is not valid.
 */
int wc_TspTstInfo_GetGenTimeAsTime(const TspTstInfo* tstInfo, time_t* t)
{
    int ret = 0;
    const byte* g;

    /* Validate parameters. */
    if ((tstInfo == NULL) || (tstInfo->genTime == NULL) || (t == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    /* The genTime must be a valid GeneralizedTime to convert. */
    if (ret == 0) {
        ret = TspCheckGenTimeSyntax(tstInfo->genTime, tstInfo->genTimeSz);
    }
    if (ret == 0) {
        /* Date and time digits checked by TspCheckGenTimeSyntax. */
        g = tstInfo->genTime;
        *t = TspGenTimeToUnix(
            (g[0] - '0') * 1000 + (g[1] - '0') * 100 + (g[2] - '0') * 10 +
                (g[3] - '0'),
            (g[4] - '0') * 10 + (g[5] - '0'),
            (g[6] - '0') * 10 + (g[7] - '0'),
            (g[8] - '0') * 10 + (g[9] - '0'),
            (g[10] - '0') * 10 + (g[11] - '0'),
            (g[12] - '0') * 10 + (g[13] - '0'));
    }

    return ret;
}
#endif /* WOLFSSL_TSP_RESPONDER || WOLFSSL_TSP_VERIFIER */

#ifdef WOLFSSL_TSP_RESPONDER
/* Set the time of the time-stamp of a TSTInfo from a time_t.
 *
 * Formats the time as a GeneralizedTime string of RFC 3161 into the caller's
 * buffer and references it - the buffer must remain available while the
 * TSTInfo is used and be at least ASN_GENERALIZED_TIME_SIZE bytes. The time
 * is treated as UTC.
 *
 * Not available when there is no time support - NO_ASN_TIME.
 *
 * @param [in, out] tstInfo  TSTInfo object.
 * @param [in]      t        Time of the time-stamp as seconds since the Unix
 *                           epoch.
 * @param [out]     buf      Buffer to hold the formatted GeneralizedTime.
 * @param [in]      bufSz    Length of buffer in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when tstInfo or buf is NULL.
 * @return  BUFFER_E when bufSz is too small for the GeneralizedTime string.
 * @return  ASN_TIME_E when the time could not be converted.
 */
int wc_TspTstInfo_SetGenTimeAsTime(TspTstInfo* tstInfo, time_t t, byte* buf,
    word32 bufSz)
{
    int ret = 0;
    int n = 0;
    struct tm* ts = NULL;
#ifdef NEED_TMP_TIME
    struct tm tmpTimeStorage;
    struct tm* tmpTime = &tmpTimeStorage;
#else
    struct tm* tmpTime = NULL;
#endif
    /* Needed in case XGMTIME does not use the tmpTime argument. */
    (void)tmpTime;

    /* Validate parameters. */
    if ((tstInfo == NULL) || (buf == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Buffer must hold "YYYYMMDDhhmmssZ" and a NUL from formatting. */
    else if (bufSz < ASN_GENERALIZED_TIME_SIZE) {
        ret = BUFFER_E;
    }

    if (ret == 0) {
        /* Break the time down as UTC. */
        ts = (struct tm*)XGMTIME(&t, tmpTime);
        if ((ts == NULL) || ValidateGmtime(ts)) {
            ret = ASN_TIME_E;
        }
    }
    if (ret == 0) {
        /* Format as a GeneralizedTime string of RFC 3161. */
        n = XSNPRINTF((char*)buf, bufSz, "%04d%02d%02d%02d%02d%02dZ",
                ts->tm_year + 1900, ts->tm_mon + 1, ts->tm_mday, ts->tm_hour,
                ts->tm_min, ts->tm_sec);
        /* Negative on error; >= bufSz when the time was truncated (e.g. a
         * year beyond 9999 needs more than the 15 expected characters). */
        if ((n < 0) || (n >= (int)bufSz)) {
            ret = ASN_TIME_E;
        }
    }
    if (ret == 0) {
        tstInfo->genTime = buf;
        /* Content length excludes the NUL terminator. */
        tstInfo->genTimeSz = ASN_GENERALIZED_TIME_SIZE - 1;
    }

    return ret;
}
#endif /* WOLFSSL_TSP_RESPONDER */
#endif /* !NO_ASN_TIME */

#if defined(WOLFSSL_TSP_RESPONDER) || defined(WOLFSSL_TSP_VERIFIER)
/* Get the accuracy of the time of a TSTInfo.
 *
 * The accuracy is the seconds, milliseconds and microseconds the genTime may
 * be off by. Each output is optional - pass NULL to not retrieve it. A value
 * of 0 means that part of the accuracy is not present.
 *
 * @param [in]  tstInfo  TSTInfo object.
 * @param [out] seconds  Accuracy in seconds. May be NULL.
 * @param [out] millis   Accuracy in milliseconds. May be NULL.
 * @param [out] micros   Accuracy in microseconds. May be NULL.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when tstInfo is NULL.
 */
int wc_TspTstInfo_GetAccuracy(const TspTstInfo* tstInfo, word32* seconds,
    word16* millis, word16* micros)
{
    /* Validate parameter. */
    if (tstInfo == NULL) {
        return BAD_FUNC_ARG;
    }

    if (seconds != NULL) {
        *seconds = tstInfo->accuracy.seconds;
    }
    if (millis != NULL) {
        *millis = tstInfo->accuracy.millis;
    }
    if (micros != NULL) {
        *micros = tstInfo->accuracy.micros;
    }

    return 0;
}
#endif /* WOLFSSL_TSP_RESPONDER || WOLFSSL_TSP_VERIFIER */

#ifdef WOLFSSL_TSP_RESPONDER
/* Set the accuracy of the time of a TSTInfo.
 *
 * The accuracy is how far the genTime may be off. A value of 0 for a part
 * means it is not present. Milliseconds and microseconds must be 1..999 -
 * checked on encode.
 *
 * @param [in, out] tstInfo  TSTInfo object.
 * @param [in]      seconds  Accuracy in seconds.
 * @param [in]      millis   Accuracy in milliseconds.
 * @param [in]      micros   Accuracy in microseconds.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when tstInfo is NULL.
 */
int wc_TspTstInfo_SetAccuracy(TspTstInfo* tstInfo, word32 seconds,
    word16 millis, word16 micros)
{
    /* Validate parameter. */
    if (tstInfo == NULL) {
        return BAD_FUNC_ARG;
    }

    tstInfo->accuracy.seconds = seconds;
    tstInfo->accuracy.millis = millis;
    tstInfo->accuracy.micros = micros;

    return 0;
}
#endif /* WOLFSSL_TSP_RESPONDER */

#if defined(WOLFSSL_TSP_RESPONDER) || defined(WOLFSSL_TSP_VERIFIER)
/* Get the nonce of a TSTInfo.
 *
 * Returns a reference to the nonce - it is not copied and is valid while the
 * TSTInfo references it. A length of 0 means no nonce is present.
 *
 * @param [in]  tstInfo  TSTInfo object.
 * @param [out] nonce    Nonce as a big-endian number.
 * @param [out] nonceSz  Length of nonce in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when tstInfo, nonce or nonceSz is NULL.
 */
int wc_TspTstInfo_GetNonce(const TspTstInfo* tstInfo, const byte** nonce,
    word32* nonceSz)
{
    /* Validate parameters. */
    if ((tstInfo == NULL) || (nonce == NULL) || (nonceSz == NULL)) {
        return BAD_FUNC_ARG;
    }

    *nonce = tstInfo->nonce;
    *nonceSz = tstInfo->nonceSz;

    return 0;
}
#endif /* WOLFSSL_TSP_RESPONDER || WOLFSSL_TSP_VERIFIER */

#ifdef WOLFSSL_TSP_RESPONDER
/* Set the nonce of a TSTInfo.
 *
 * The nonce is referenced, not copied, and must remain available while the
 * TSTInfo is used. It must match the request's nonce. Leading zero bytes are
 * stripped, keeping at least one byte, so it has no leading zero byte and
 * encodes - the request's decoded nonce is already in this form.
 *
 * @param [in, out] tstInfo  TSTInfo object.
 * @param [in]      nonce    Nonce as a big-endian number.
 * @param [in]      nonceSz  Length of nonce in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when tstInfo or nonce is NULL or nonceSz is 0.
 */
int wc_TspTstInfo_SetNonce(TspTstInfo* tstInfo, const byte* nonce,
    word32 nonceSz)
{
    /* Validate parameters. */
    if ((tstInfo == NULL) || (nonce == NULL) || (nonceSz == 0)) {
        return BAD_FUNC_ARG;
    }

    /* Strip leading zero bytes - keep at least one byte. */
    while ((nonceSz > 1) && (nonce[0] == 0x00)) {
        nonce++;
        nonceSz--;
    }
    tstInfo->nonce = nonce;
    tstInfo->nonceSz = nonceSz;

    return 0;
}
#endif /* WOLFSSL_TSP_RESPONDER */

#if defined(WOLFSSL_TSP_RESPONDER) || defined(WOLFSSL_TSP_VERIFIER)
/* Get the TSA name of a TSTInfo.
 *
 * Returns a reference to the tsa - the DER encoding of a GeneralName - it is
 * not copied and is valid while the TSTInfo references it. A length of 0
 * means no TSA name is present.
 *
 * @param [in]  tstInfo  TSTInfo object.
 * @param [out] tsa      TSA name as the DER encoding of a GeneralName.
 * @param [out] tsaSz    Length of TSA name in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when tstInfo, tsa or tsaSz is NULL.
 */
int wc_TspTstInfo_GetTsa(const TspTstInfo* tstInfo, const byte** tsa,
    word32* tsaSz)
{
    /* Validate parameters. */
    if ((tstInfo == NULL) || (tsa == NULL) || (tsaSz == NULL)) {
        return BAD_FUNC_ARG;
    }

    *tsa = tstInfo->tsa;
    *tsaSz = tstInfo->tsaSz;

    return 0;
}
#endif /* WOLFSSL_TSP_RESPONDER || WOLFSSL_TSP_VERIFIER */

#ifdef WOLFSSL_TSP_RESPONDER
/* Set the TSA name of a TSTInfo.
 *
 * The tsa is the DER encoding of a GeneralName - it is referenced, not
 * copied, and must remain available while the TSTInfo is used.
 *
 * @param [in, out] tstInfo  TSTInfo object.
 * @param [in]      tsa      TSA name as the DER encoding of a GeneralName.
 * @param [in]      tsaSz    Length of TSA name in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when tstInfo or tsa is NULL or tsaSz is 0.
 */
int wc_TspTstInfo_SetTsa(TspTstInfo* tstInfo, const byte* tsa, word32 tsaSz)
{
    /* Validate parameters. */
    if ((tstInfo == NULL) || (tsa == NULL) || (tsaSz == 0)) {
        return BAD_FUNC_ARG;
    }

    tstInfo->tsa = tsa;
    tstInfo->tsaSz = tsaSz;

    return 0;
}

/* Set the values of a TSTInfo to respond to a request.
 *
 * A convenience for a TSA building a response: echoes the request's message
 * imprint (copied) and nonce (referenced), and sets the TSA's policy, serial
 * number and time. The TSTInfo should be initialized with
 * wc_TspTstInfo_Init() first. The request, policy, serial and genTime buffers
 * are referenced - not copied (except the imprint) - and must remain available
 * while the TSTInfo is used.
 *
 * @param [in, out] tstInfo    TSTInfo object to set.
 * @param [in]      req        Decoded request being time-stamped.
 * @param [in]      policy     TSA policy as OBJECT IDENTIFIER content.
 * @param [in]      policySz   Length of policy in bytes.
 * @param [in]      serial     Serial number of the time-stamp - big-endian.
 *                             Leading zero bytes are stripped.
 * @param [in]      serialSz   Length of serial in bytes.
 * @param [in]      genTime    Time of the time-stamp as a GeneralizedTime
 *                             string. NULL to use the current time on encode.
 * @param [in]      genTimeSz  Length of genTime in bytes - 0 when NULL.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when tstInfo, req, policy or serial is NULL or
 *          policySz or serialSz is 0.
 */
int wc_TspTstInfo_SetFromRequest(TspTstInfo* tstInfo, const TspRequest* req,
    const byte* policy, word32 policySz, const byte* serial, word32 serialSz,
    const byte* genTime, word32 genTimeSz)
{
    int ret = 0;

    /* Validate parameters - genTime is optional. */
    if ((tstInfo == NULL) || (req == NULL) || (policy == NULL) ||
            (policySz == 0) || (serial == NULL) || (serialSz == 0)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Set the serial through the setter so a leading zero pad byte of a
         * positive value with the high bit set is stripped. */
        ret = wc_TspTstInfo_SetSerial(tstInfo, serial, serialSz);
    }
    if (ret == 0) {
        tstInfo->policy = policy;
        tstInfo->policySz = policySz;
        /* Echo the requester's message imprint - copies the embedded hash. */
        tstInfo->imprint = req->imprint;
        /* NULL genTime uses the current time when encoding. */
        tstInfo->genTime = genTime;
        tstInfo->genTimeSz = genTimeSz;
        /* Echo the nonce when the request has one. */
        if (req->nonceSz != 0) {
            tstInfo->nonce = req->nonce;
            tstInfo->nonceSz = req->nonceSz;
        }
    }

    return ret;
}
#endif /* WOLFSSL_TSP_RESPONDER */

#if !defined(NO_ASN_TIME) && !defined(USER_TIME) && !defined(TIME_OVERRIDES)
#ifdef WOLFSSL_TSP_VERIFIER
/* Check the genTime of a TSTInfo is close enough to the current time.
 *
 * RFC 3161, 2.4.2: the requester verifies the genTime is within an
 * acceptable period of the local trusted time. GeneralizedTime strings of
 * the same form compare as times - the bounds of the acceptable period are
 * formatted and compared as strings. Any fraction of a second in the
 * genTime is ignored.
 *
 * Not available when there is no real time clock - NO_ASN_TIME, USER_TIME
 * or TIME_OVERRIDES.
 *
 * @param [in] tstInfo    Decoded TSTInfo object from response.
 * @param [in] tolerance  Acceptable time around the current time in
 *                        seconds.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when tstInfo or its genTime is NULL.
 * @return  ASN_PARSE_E when the genTime string is not valid.
 * @return  ASN_TIME_E when getting the current time failed.
 * @return  TSP_VERIFY_E when the genTime is outside the acceptable period.
 */
int wc_TspTstInfo_CheckGenTime(const TspTstInfo* tstInfo, word32 tolerance)
{
    int ret = 0;
    time_t now;
    time_t bound;
    byte lo[ASN_GENERALIZED_TIME_SIZE];
    byte hi[ASN_GENERALIZED_TIME_SIZE];

    WOLFSSL_ENTER("wc_TspTstInfo_CheckGenTime");

    /* Validate parameters. */
    if ((tstInfo == NULL) || (tstInfo->genTime == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    /* The genTime must be a valid time to compare. */
    if (ret == 0) {
        ret = TspCheckGenTimeSyntax(tstInfo->genTime, tstInfo->genTimeSz);
    }
    if (ret == 0) {
        /* Format the bounds of the acceptable period. */
        now = wc_Time(0);
        bound = now - (time_t)tolerance;
        if (GetFormattedTime_ex(&bound, lo, sizeof(lo),
                ASN_GENERALIZED_TIME) <= 0) {
            ret = ASN_TIME_E;
        }
        bound = now + (time_t)tolerance;
        if ((ret == 0) && (GetFormattedTime_ex(&bound, hi, sizeof(hi),
                ASN_GENERALIZED_TIME) <= 0)) {
            ret = ASN_TIME_E;
        }
    }
    /* Compare the date and time digits - fraction of a second ignored. */
    if ((ret == 0) && ((XMEMCMP(tstInfo->genTime, lo, 14) < 0) ||
            (XMEMCMP(tstInfo->genTime, hi, 14) > 0))) {
        WOLFSSL_MSG("TSP genTime is outside the acceptable period");
        ret = TSP_VERIFY_E;
    }

    WOLFSSL_LEAVE("wc_TspTstInfo_CheckGenTime", ret);
    return ret;
}
#endif /* WOLFSSL_TSP_VERIFIER */
#endif /* !NO_ASN_TIME && !USER_TIME && !TIME_OVERRIDES */

#ifdef WOLFSSL_TSP_VERIFIER
/* Check the TSTInfo of a response against the request sent.
 *
 * Checks the version, that the message imprint is the same and, when in the
 * request, that the nonce and policy are matched. RFC 3161, 2.4.2.
 *
 * The genTime and the token's signature are not validated here.
 *
 * @param [in] tstInfo  Decoded TSTInfo object from response.
 * @param [in] req      TimeStampReq object sent.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when tstInfo or req is NULL.
 * @return  ASN_VERSION_E when the version is not supported.
 * @return  TSP_VERIFY_E when a field of the TSTInfo does not match the
 *          request.
 */
int wc_TspTstInfo_CheckRequest(const TspTstInfo* tstInfo, const TspRequest* req)
{
    int ret = 0;

    WOLFSSL_ENTER("wc_TspTstInfo_CheckRequest");

    /* Validate parameters. */
    if ((tstInfo == NULL) || (req == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    /* Only version 1 defined. */
    if ((ret == 0) && (tstInfo->version != WC_TSP_VERSION)) {
        ret = ASN_VERSION_E;
    }
    /* Message imprint must be the same as the request - same hash
     * algorithm ... */
    if ((ret == 0) &&
            (tstInfo->imprint.hashAlgOID != req->imprint.hashAlgOID)) {
        ret = TSP_VERIFY_E;
    }
    /* ... and same hash of data. */
    if ((ret == 0) &&
            ((tstInfo->imprint.hashSz != req->imprint.hashSz) ||
             (XMEMCMP(tstInfo->imprint.hash, req->imprint.hash,
                  req->imprint.hashSz) != 0))) {
        ret = TSP_VERIFY_E;
    }
    /* Nonce must be returned when in request - compared exactly. */
    if ((ret == 0) && (req->nonceSz != 0) &&
            ((tstInfo->nonce == NULL) ||
             (tstInfo->nonceSz != req->nonceSz) ||
             (XMEMCMP(tstInfo->nonce, req->nonce, req->nonceSz) != 0))) {
        ret = TSP_VERIFY_E;
    }
    /* Policy must match when requested. */
    if ((ret == 0) && (req->policySz != 0) &&
            ((tstInfo->policy == NULL) ||
             (tstInfo->policySz != req->policySz) ||
             (XMEMCMP(tstInfo->policy, req->policy, req->policySz) != 0))) {
        ret = TSP_VERIFY_E;
    }

    WOLFSSL_LEAVE("wc_TspTstInfo_CheckRequest", ret);
    return ret;
}
#endif /* WOLFSSL_TSP_VERIFIER */

#ifdef WOLFSSL_TSP_VERIFIER
/* Check the TSA name of a TSTInfo is the expected name.
 *
 * The TSA name must be present and be the same encoding as the expected
 * name - the DER encodings of the GeneralNames are compared exactly.
 *
 * @param [in] tstInfo  Decoded TSTInfo object from response.
 * @param [in] tsa      Expected name: DER encoding of GeneralName.
 * @param [in] tsaSz    Length of expected name in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when tstInfo or tsa is NULL or tsaSz is 0.
 * @return  TSP_VERIFY_E when the TSA name is not present or does not match
 *          the expected name.
 */
int wc_TspTstInfo_CheckTsaName(const TspTstInfo* tstInfo, const byte* tsa,
    word32 tsaSz)
{
    int ret = 0;

    WOLFSSL_ENTER("wc_TspTstInfo_CheckTsaName");

    /* Validate parameters. */
    if ((tstInfo == NULL) || (tsa == NULL) || (tsaSz == 0)) {
        ret = BAD_FUNC_ARG;
    }

    /* TSA name must be present and exactly the expected encoding. */
    if ((ret == 0) && ((tstInfo->tsa == NULL) || (tstInfo->tsaSz != tsaSz) ||
            (XMEMCMP(tstInfo->tsa, tsa, tsaSz) != 0))) {
        WOLFSSL_MSG("TSP TSA name is not the expected name");
        ret = TSP_VERIFY_E;
    }

    WOLFSSL_LEAVE("wc_TspTstInfo_CheckTsaName", ret);
    return ret;
}

/* Verify the message imprint of a TSTInfo against the original data.
 *
 * Hashes the data with the TSTInfo's message imprint hash algorithm and
 * compares the result to the imprint hash - confirming the time-stamp is over
 * the given data. The caller does not need to hash the data first.
 *
 * @param [in] tstInfo  TSTInfo object.
 * @param [in] data     Data that was time-stamped.
 * @param [in] dataSz   Length of data in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when tstInfo or data is NULL.
 * @return  HASH_TYPE_E when the imprint's hash algorithm is not supported.
 * @return  TSP_VERIFY_E when the hash of the data does not match the imprint.
 * @return  Other negative value on hashing failure.
 */
int wc_TspTstInfo_VerifyData(const TspTstInfo* tstInfo, const byte* data,
    word32 dataSz)
{
    int ret = 0;
    enum wc_HashType hashType = WC_HASH_TYPE_NONE;
    int digestSz = 0;
    byte digest[WC_MAX_DIGEST_SIZE];

    WOLFSSL_ENTER("wc_TspTstInfo_VerifyData");

    /* Validate parameters. */
    if ((tstInfo == NULL) || (data == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Determine the hash algorithm of the message imprint. */
        hashType = wc_OidGetHash((int)tstInfo->imprint.hashAlgOID);
        digestSz = wc_HashGetDigestSize(hashType);
        if (digestSz <= 0) {
            ret = HASH_TYPE_E;
        }
    }
    /* The imprint length must match the algorithm's digest size. */
    if ((ret == 0) && (tstInfo->imprint.hashSz != (word32)digestSz)) {
        ret = TSP_VERIFY_E;
    }
    if (ret == 0) {
        /* Hash the data and compare to the message imprint. */
        ret = wc_Hash(hashType, data, dataSz, digest, (word32)digestSz);
    }
    if ((ret == 0) && (XMEMCMP(digest, tstInfo->imprint.hash,
            (word32)digestSz) != 0)) {
        WOLFSSL_MSG("TSP data does not match the message imprint");
        ret = TSP_VERIFY_E;
    }

    WOLFSSL_LEAVE("wc_TspTstInfo_VerifyData", ret);
    return ret;
}
#endif /* WOLFSSL_TSP_VERIFIER */

#ifdef HAVE_PKCS7

/* id-ct-TSTInfo: 1.2.840.113549.1.9.16.1.4. RFC 3161 - the content type of
 * a time-stamp token. Used by wc_TspTstInfo_SignWithPkcs7() and
 * wc_TspTstInfo_VerifyWithPKCS7(). */
static const byte tspTstInfoOid[] = {
    ASN_OBJECT_ID, 0x0b,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04
};

#ifdef WOLFSSL_TSP_RESPONDER
/* Create a TimeStampToken signed with the TSA's certificate and private key.
 *
 * Convenience wrapper around wc_TspTstInfo_SignWithPkcs7() that creates and
 * disposes of the PKCS7 object. The TSA's certificate is included in the
 * token.
 *
 * @param [in]      tstInfo   TSTInfo object to encode and sign.
 * @param [in]      cert      DER encoded certificate of the TSA.
 * @param [in]      certSz    Length of certificate in bytes.
 * @param [in]      key       DER encoded private key of the TSA.
 * @param [in]      keySz     Length of private key in bytes.
 * @param [in]      keyType   Type of the private key - WC_PK_TYPE_RSA or
 *                            WC_PK_TYPE_ECDSA_SIGN.
 * @param [in]      hashType  Hash algorithm for the signature - e.g.
 *                            WC_HASH_TYPE_SHA256.
 * @param [in]      rng       Random number generator.
 * @param [out]     out       Buffer to hold encoding.
 * @param [in, out] outSz     On in, length of buffer in bytes.
 *                            On out, length of encoding in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a pointer argument is NULL, a length is 0 or the
 *          key type is not supported.
 * @return  HASH_TYPE_E when the hash algorithm is not available.
 * @return  BUFFER_E when the encoding is longer than outSz.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
int wc_TspTstInfo_Sign(const TspTstInfo* tstInfo,
    const byte* cert, word32 certSz, const byte* key, word32 keySz,
    enum wc_PkType keyType, enum wc_HashType hashType, WC_RNG* rng,
    byte* out, word32* outSz)
{
    int ret = 0;
#ifdef WOLFSSL_NO_MALLOC
    /* No dynamic memory - the PKCS7 object is on the stack. */
    wc_PKCS7 pkcs7Obj;
    wc_PKCS7* pkcs7 = &pkcs7Obj;
#else
    wc_PKCS7* pkcs7 = NULL;
#endif
    int hashOID = 0;
    int encryptOID = 0;

    WOLFSSL_ENTER("wc_TspTstInfo_Sign");

#ifdef WOLFSSL_NO_MALLOC
    /* Zero the stack object up front - an early error returns through the
     * unconditional wc_PKCS7_Free below, which must see isDynamic 0 and all
     * pointers NULL so it does not free the stack object or wild pointers. */
    XMEMSET(pkcs7, 0, sizeof(pkcs7Obj));
#endif

    /* Validate parameters. */
    if ((tstInfo == NULL) || (cert == NULL) || (certSz == 0) ||
            (key == NULL) || (keySz == 0) || (rng == NULL) ||
            (out == NULL) || (outSz == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    /* Map the key type to the signature algorithm OID. */
    if (ret == 0) {
        if (keyType == WC_PK_TYPE_RSA) {
            encryptOID = RSAk;
        }
    #ifdef HAVE_ECC
        else if (keyType == WC_PK_TYPE_ECDSA_SIGN) {
            encryptOID = ECDSAk;
        }
    #endif
        else {
            WOLFSSL_MSG("TSP key type not supported");
            ret = BAD_FUNC_ARG;
        }
    }
    /* Map the hash type to its OID sum. */
    if (ret == 0) {
        hashOID = wc_HashGetOID(hashType);
        if (hashOID <= 0) {
            ret = HASH_TYPE_E;
        }
    }

    if (ret == 0) {
#ifdef WOLFSSL_NO_MALLOC
        ret = wc_PKCS7_Init(pkcs7, NULL, INVALID_DEVID);
#else
        pkcs7 = wc_PKCS7_New(NULL, INVALID_DEVID);
        if (pkcs7 == NULL) {
            ret = MEMORY_E;
        }
#endif
    }
    if (ret == 0) {
        ret = wc_PKCS7_InitWithCert(pkcs7, (byte*)cert, certSz);
    }
    if (ret == 0) {
        /* Configure the signer and sign the TSTInfo. */
        pkcs7->rng = rng;
        pkcs7->hashOID = hashOID;
        pkcs7->encryptOID = encryptOID;
        pkcs7->privateKey = (byte*)key;
        pkcs7->privateKeySz = keySz;

        ret = wc_TspTstInfo_SignWithPkcs7(tstInfo, pkcs7, out, outSz);
    }

    wc_PKCS7_Free(pkcs7);
    WOLFSSL_LEAVE("wc_TspTstInfo_Sign", ret);
    return ret;
}

/* Maximum size of an encoded SigningCertificateV2: 4 headers of 4 bytes and
 * a hash algorithm of 15 bytes. */
#define TSP_MAX_SIGN_CERT_V2_SZ  (4 * 4 + 15 + WC_MAX_DIGEST_SIZE)

#ifdef WOLFSSL_NO_MALLOC
/* Maximum size of an encoded TSTInfo when no dynamic memory. */
#ifndef WC_TSP_MAX_TSTINFO_SZ
    #define WC_TSP_MAX_TSTINFO_SZ      512
#endif
/* Maximum number of signed attributes, including SigningCertificateV2, when
 * no dynamic memory. */
#ifndef WC_TSP_MAX_SIGNED_ATTRIBS
    #define WC_TSP_MAX_SIGNED_ATTRIBS  4
#endif
#endif

/* Create a TimeStampToken - CMS SignedData with TSTInfo content.
 *
 * The PKCS7 object must be initialized with the certificate and private key
 * of the TSA, and the hash algorithm and RNG set. A SigningCertificateV2
 * signed attribute is added as required by RFC 3161, 2.4.2.
 *
 * The TSA's certificate is included in the token. When the request did not
 * set certReq the certificates must not be included - RFC 3161, 2.4.1 -
 * set the PKCS7 object's noCerts field.
 *
 * @param [in]      tstInfo  TSTInfo object to encode and sign.
 * @param [in]      pkcs7    PKCS7 object with signer configured.
 * @param [out]     out      Buffer to hold encoding.
 * @param [in, out] outSz    On in, length of buffer in bytes.
 *                           On out, length of encoding in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when pkcs7, tstInfo, out or outSz is NULL or the
 *          signer's certificate is not set or, when no dynamic memory, there
 *          are more signed attributes than WC_TSP_MAX_SIGNED_ATTRIBS.
 * @return  BUFFER_E when no dynamic memory and the encoded TSTInfo is longer
 *          than WC_TSP_MAX_TSTINFO_SZ.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
int wc_TspTstInfo_SignWithPkcs7(const TspTstInfo* tstInfo, wc_PKCS7* pkcs7,
    byte* out, word32* outSz)
{
    int ret = 0;
#ifdef WOLFSSL_NO_MALLOC
    byte tstDer[WC_TSP_MAX_TSTINFO_SZ];
    PKCS7Attrib attribs[WC_TSP_MAX_SIGNED_ATTRIBS];
#else
    byte* tstDer = NULL;
    PKCS7Attrib* attribs = NULL;
#endif
    word32 tstDerSz = 0;
    WC_DECLARE_VAR(signCert, byte, TSP_MAX_SIGN_CERT_V2_SZ, pkcs7->heap);
    word32 signCertSz = TSP_MAX_SIGN_CERT_V2_SZ;
    word32 cnt = 0;

    WOLFSSL_ENTER("wc_TspTstInfo_SignWithPkcs7");

    /* Validate parameters. */
    if ((pkcs7 == NULL) || (tstInfo == NULL) || (out == NULL) ||
            (outSz == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* The signer's certificate is hashed into a signed attribute. */
    if ((ret == 0) && ((pkcs7->singleCert == NULL) ||
            (pkcs7->singleCertSz == 0))) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        WC_ALLOC_VAR_EX(signCert, byte, TSP_MAX_SIGN_CERT_V2_SZ, pkcs7->heap,
            DYNAMIC_TYPE_TMP_BUFFER, ret = MEMORY_E);
    }

    /* Encode TSTInfo as the content. */
#ifdef WOLFSSL_NO_MALLOC
    if (ret == 0) {
        /* Fixed size buffer on the stack. */
        tstDerSz = (word32)sizeof(tstDer);
    }
#else
    if (ret == 0) {
        /* Get the length of the encoding to allocate. */
        ret = wc_TspTstInfo_Encode(tstInfo, NULL, &tstDerSz);
    }
    if (ret == 0) {
        tstDer = (byte*)XMALLOC(tstDerSz, pkcs7->heap,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (tstDer == NULL) {
            ret = MEMORY_E;
        }
    }
#endif
    if (ret == 0) {
        ret = wc_TspTstInfo_Encode(tstInfo, tstDer, &tstDerSz);
    }
    /* Hash of signer's certificate in signed attribute. */
    if (ret == 0) {
        ret = TspEncodeSigningCertV2(pkcs7->hashOID, pkcs7->singleCert,
            pkcs7->singleCertSz, signCert, &signCertSz, pkcs7->heap);
    }
    /* Add SigningCertificateV2 to user's signed attributes. */
    if (ret == 0) {
        cnt = pkcs7->signedAttribsSz;
#ifdef WOLFSSL_NO_MALLOC
        /* Check fixed size array is big enough for one more. */
        if (cnt + 1 > WC_TSP_MAX_SIGNED_ATTRIBS) {
            ret = BAD_FUNC_ARG;
        }
#else
        /* Allocate array for user's attributes and one more. */
        attribs = (PKCS7Attrib*)XMALLOC((cnt + 1) * sizeof(PKCS7Attrib),
            pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (attribs == NULL) {
            ret = MEMORY_E;
        }
#endif
    }
    if (ret == 0) {
        /* Copy in user's attributes and append SigningCertificateV2. */
        if (cnt > 0) {
            XMEMCPY(attribs, pkcs7->signedAttribs,
                cnt * sizeof(PKCS7Attrib));
        }
        attribs[cnt].oid = tspSigningCertV2Oid;
        attribs[cnt].oidSz = (word32)sizeof(tspSigningCertV2Oid);
        attribs[cnt].value = signCert;
        attribs[cnt].valueSz = signCertSz;
    }
    if (ret == 0) {
        /* Sign TSTInfo keeping original PKCS7 object fields. */
        byte* content = pkcs7->content;
        word32 contentSz = pkcs7->contentSz;
        int contentOID = pkcs7->contentOID;
        byte contentType[MAX_OID_SZ];
        word32 contentTypeSz = pkcs7->contentTypeSz;
        PKCS7Attrib* signedAttribs = pkcs7->signedAttribs;
        word32 signedAttribsSz = pkcs7->signedAttribsSz;

        XMEMCPY(contentType, pkcs7->contentType, MAX_OID_SZ);

        /* TSTInfo encoding is the content to be signed. */
        pkcs7->content = tstDer;
        pkcs7->contentSz = tstDerSz;
        pkcs7->contentOID = TSTINFO_DATA;
        pkcs7->signedAttribs = attribs;
        pkcs7->signedAttribsSz = cnt + 1;

        /* Content type written and put in signed attributes. */
        ret = wc_PKCS7_SetContentType(pkcs7, (byte*)tspTstInfoOid,
            (word32)sizeof(tspTstInfoOid));
        if (ret == 0) {
            /* Encode CMS SignedData - returns length of encoding. */
            ret = wc_PKCS7_EncodeSignedData(pkcs7, out, *outSz);
        }

        /* Restore caller's PKCS7 object fields. */
        pkcs7->content = content;
        pkcs7->contentSz = contentSz;
        pkcs7->contentOID = contentOID;
        pkcs7->signedAttribs = signedAttribs;
        pkcs7->signedAttribsSz = signedAttribsSz;
        XMEMCPY(pkcs7->contentType, contentType, MAX_OID_SZ);
        pkcs7->contentTypeSz = contentTypeSz;

        if (ret > 0) {
            /* Return the length of the encoding. */
            *outSz = (word32)ret;
            ret = 0;
        }
        else if (ret == 0) {
            /* Zero length encoding is not valid. */
            ret = BAD_STATE_E;
        }
    }

#ifndef WOLFSSL_NO_MALLOC
    XFREE(attribs, (pkcs7 != NULL) ? pkcs7->heap : NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(tstDer, (pkcs7 != NULL) ? pkcs7->heap : NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
#endif
    WC_FREE_VAR_EX(signCert, (pkcs7 != NULL) ? pkcs7->heap : NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    WOLFSSL_LEAVE("wc_TspTstInfo_SignWithPkcs7", ret);
    return ret;
}

#endif /* WOLFSSL_TSP_RESPONDER */

#ifdef WOLFSSL_TSP_VERIFIER

/* Check a hash algorithm meets the minimum security strength.
 *
 * The collision resistance of a hash is half the digest length in bits -
 * digest size in bytes * 4. With WC_TSP_MIN_HASH_STRENGTH_BITS of 0 any
 * available hash algorithm is acceptable.
 *
 * This is a strength check, not an availability check: with the default
 * WC_TSP_MIN_HASH_STRENGTH_BITS of 0 it returns 0 for an unavailable OID.
 * Callers that go on to use the algorithm independently reject an unavailable
 * hash via wc_HashGetDigestSize() - see TspCheckSigningCertAttr() and
 * wc_TspTstInfo_VerifyData().
 *
 * Not static - also used by TspCheckSigningCertAttr() in asn_tsp.c (declared
 * in tsp.h).
 *
 * @param [in] hashOID  Hash algorithm OID sum.
 * @return  0 when strong enough.
 * @return  HASH_TYPE_E when not available or below
 *          WC_TSP_MIN_HASH_STRENGTH_BITS.
 */
int Tsp_CheckHashStrength(word32 hashOID)
{
    int ret = 0;
#if WC_TSP_MIN_HASH_STRENGTH_BITS > 0
    int digestSz = wc_HashGetDigestSize(wc_OidGetHash((int)hashOID));

    if ((digestSz <= 0) ||
            ((digestSz * 4) < WC_TSP_MIN_HASH_STRENGTH_BITS)) {
        WOLFSSL_MSG("TSP hash algorithm below minimum security strength");
        ret = HASH_TYPE_E;
    }
#else
    (void)hashOID;
#endif
    return ret;
}

/* Check the TSA name corresponds to a subject name of the signer's
 * certificate.
 *
 * RFC 3161, 2.4.2: the tsa field, when present, must correspond to one of
 * the subject names included in the certificate that is to be used to
 * verify the token.
 *
 * A directoryName is checked against the subject name and other supported
 * GeneralName forms against the subject alternative names.
 *
 * @param [in] dCert  Decoded certificate of signer.
 * @param [in] tsa    DER encoding of GeneralName.
 * @param [in] tsaSz  Length of GeneralName in bytes.
 * @return  0 on success.
 * @return  TSP_VERIFY_E when the name does not match the certificate or the
 *          form of name is not supported.
 * @return  ASN_PARSE_E when the encoding is invalid.
 */
static int Tsp_CheckTsaName(DecodedCert* dCert, const byte* tsa, word32 tsaSz)
{
    int ret = 0;
    word32 idx = 0;
    byte tag = 0;
    int len = 0;

    /* Get header of the one GeneralName. */
    if ((GetASNTag(tsa, &idx, &tag, tsaSz) < 0) ||
            (GetLength(tsa, &idx, &len, tsaSz) < 0) ||
            (idx + (word32)len != tsaSz)) {
        ret = ASN_PARSE_E;
    }
    /* directoryName [4] - explicitly tagged Name. */
    else if (tag == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED |
            ASN_DIR_TYPE)) {
    #if !defined(IGNORE_NAME_CONSTRAINTS) || defined(WOLFSSL_CERT_EXT)
        byte nameTag = 0;
        int nameLen = 0;

        /* Step into the Name to compare contents of SEQUENCE. */
        if ((GetASNTag(tsa, &idx, &nameTag, tsaSz) < 0) ||
                (nameTag != (ASN_SEQUENCE | ASN_CONSTRUCTED)) ||
                (GetLength(tsa, &idx, &nameLen, tsaSz) < 0) ||
                (idx + (word32)nameLen != tsaSz)) {
            ret = ASN_PARSE_E;
        }
        /* Compare with the subject name of the signer's certificate. */
        else if ((dCert->subjectRaw == NULL) ||
                (nameLen != dCert->subjectRawLen) ||
                (XMEMCMP(tsa + idx, dCert->subjectRaw,
                    (size_t)nameLen) != 0)) {
            WOLFSSL_MSG("TSP TSA name doesn't match signer's subject");
            ret = TSP_VERIFY_E;
        }
    #else
        /* No raw subject name to compare against. */
        WOLFSSL_MSG("TSP TSA name check requires raw subject name");
        ret = TSP_VERIFY_E;
    #endif
    }
    /* Name forms of the subject alternative names extension. */
    else if ((tag == (ASN_CONTEXT_SPECIFIC | ASN_RFC822_TYPE)) ||
             (tag == (ASN_CONTEXT_SPECIFIC | ASN_DNS_TYPE)) ||
             (tag == (ASN_CONTEXT_SPECIFIC | ASN_URI_TYPE))) {
        const DNS_entry* entry;
        int type = (int)(tag & ~ASN_CONTEXT_SPECIFIC);

        /* Compare against each subject alternative name of the form. */
        ret = TSP_VERIFY_E;
        for (entry = dCert->altNames; entry != NULL; entry = entry->next) {
            if ((entry->type == type) && (entry->len == len) &&
                    (XMEMCMP(entry->name, tsa + idx, (size_t)len) == 0)) {
                ret = 0;
                break;
            }
        }
        if (ret != 0) {
            WOLFSSL_MSG("TSP TSA name not in signer's alternative names");
        }
    }
    else {
        /* Other forms of GeneralName are not supported. */
        WOLFSSL_MSG("TSP TSA name form not supported");
        ret = TSP_VERIFY_E;
    }

    return ret;
}

/* Check the signer's certificate is valid for time-stamping.
 *
 * RFC 3161, 2.3: the TSA's certificate must have an extended key usage of
 * id-kp-timeStamping only and the extension must be critical. The key
 * usage, when present, must only be for signing.
 *
 * The TSA name of the TSTInfo, when present, must correspond to a subject
 * name of the certificate. RFC 3161, 2.4.2.
 *
 * @param [in] cert    DER encoded certificate of signer.
 * @param [in] certSz  Length of certificate in bytes.
 * @param [in] tsa     DER encoding of GeneralName from TSTInfo. May be NULL.
 * @param [in] tsaSz   Length of GeneralName in bytes.
 * @param [in] heap    Dynamic memory allocation hint.
 * @return  0 on success.
 * @return  EXTKEYUSAGE_E when the extended key usage is not critical or not
 *          time-stamping only.
 * @return  KEYUSAGE_E when the key usage is not for signing only.
 * @return  TSP_VERIFY_E when the TSA name does not match the certificate.
 * @return  ASN_PARSE_E when an encoding is invalid.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int Tsp_CheckSignerCert(const byte* cert, word32 certSz,
    const byte* tsa, word32 tsaSz, void* heap)
{
    int ret = 0;
    WC_DECLARE_VAR(dCert, DecodedCert, 1, heap);

    WC_ALLOC_VAR_EX(dCert, DecodedCert, 1, heap, DYNAMIC_TYPE_DCERT,
        return MEMORY_E);

    /* Parse certificate for extensions and names - no chain verify. */
    InitDecodedCert(dCert, cert, certSz, heap);
    ret = ParseCertRelative(dCert, CERT_TYPE, NO_VERIFY, NULL, NULL);
    if (ret == 0) {
        /* Extended key usage must be critical and time-stamping only - the
         * OID count catches an extra purpose whose OID is not recognized and
         * so leaves no extra bit set in extExtKeyUsage. */
        if ((!dCert->extExtKeyUsageSet) ||
                (dCert->extExtKeyUsage != EXTKEYUSE_TIMESTAMP) ||
                (dCert->extExtKeyUsageOidCnt != 1) ||
                (!dCert->extExtKeyUsageCrit)) {
            WOLFSSL_MSG("TSP signer's cert not for time-stamping only");
            ret = EXTKEYUSAGE_E;
        }
    }
    if (ret == 0) {
        /* Key usage, when present, must be for signing only. */
        if (dCert->extKeyUsageSet &&
                (((dCert->extKeyUsage & (word16)~(KEYUSE_DIGITAL_SIG |
                    KEYUSE_CONTENT_COMMIT)) != 0) ||
                 ((dCert->extKeyUsage & (KEYUSE_DIGITAL_SIG |
                    KEYUSE_CONTENT_COMMIT)) == 0))) {
            WOLFSSL_MSG("TSP signer's cert key usage not signing only");
            ret = KEYUSAGE_E;
        }
    }
    /* TSA name, when present, must correspond to the certificate. */
    if ((ret == 0) && (tsa != NULL)) {
        ret = Tsp_CheckTsaName(dCert, tsa, tsaSz);
    }
    FreeDecodedCert(dCert);

    WC_FREE_VAR_EX(dCert, heap, DYNAMIC_TYPE_DCERT);
    return ret;
}

/* Verify a TimeStampToken and decode the TSTInfo content.
 *
 * The PKCS7 object must be initialized. The signature of the CMS SignedData
 * is verified with the certificates in the token. When the token does not
 * include certificates - certReq was not set in the request - initialize
 * the PKCS7 object with the TSA's certificate. Trust in the TSA's
 * certificate must be established by the caller.
 *
 * The signer's certificate must be valid for time-stamping only -
 * RFC 3161, 2.3 - and be the certificate identified by the signing
 * certificate attribute - RFC 3161, 2.4.2. Only the certHash of the first
 * ESSCertID(v2) of the attribute is checked - any issuerSerial and further
 * certificate identifiers are not used. The TSA name of the TSTInfo, when
 * present, must correspond to a subject name of the signer's certificate -
 * RFC 3161, 2.4.2.
 *
 * Pointers in tstInfo reference the content of the PKCS7 object - the
 * PKCS7 object and the token buffer must remain available while tstInfo is
 * in use.
 *
 * @param [in]      pkcs7    Initialized PKCS7 object.
 * @param [in, out] token    Buffer holding DER encoding of token.
 * @param [in]      tokenSz  Length of data in buffer in bytes.
 * @param [out]     tstInfo  TSTInfo object to fill. May be NULL.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when pkcs7 or token is NULL or tokenSz is 0.
 * @return  PKCS7_OID_E when the content is not a TSTInfo.
 * @return  EXTKEYUSAGE_E when the signer's extended key usage is not
 *          critical or not time-stamping only.
 * @return  KEYUSAGE_E when the signer's key usage is not for signing only.
 * @return  TSP_VERIFY_E when the token does not have exactly one
 *          SignerInfo, no signing certificate attribute is found or it does
 *          not match the signer's certificate or the TSA name does not
 *          match the signer's certificate.
 * @return  HASH_TYPE_E when the signing certificate attribute's hash
 *          algorithm is not available or a hash algorithm is below
 *          WC_TSP_MIN_HASH_STRENGTH_BITS.
 * @return  ASN_PARSE_E when an encoding is invalid.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
int wc_TspTstInfo_VerifyWithPKCS7(wc_PKCS7* pkcs7, byte* token, word32 tokenSz,
    TspTstInfo* tstInfo)
{
    int ret = 0;
    TspTstInfo tstDec;

    WOLFSSL_ENTER("wc_TspTstInfo_VerifyWithPKCS7");

    /* Validate parameters. */
    if ((pkcs7 == NULL) || (token == NULL) || (tokenSz == 0)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Token must have a single SignerInfo. */
        ret = TspCheckOneSignerInfo(token, tokenSz, pkcs7->heap);
    }
    if (ret == 0) {
        /* Verify signature of CMS SignedData. */
        ret = wc_PKCS7_VerifySignedData(pkcs7, token, tokenSz);
    }
    /* Content type must be id-ct-TSTInfo. */
    if ((ret == 0) && ((pkcs7->contentTypeSz != sizeof(tspTstInfoOid)) ||
            (XMEMCMP(pkcs7->contentType, tspTstInfoOid,
                 sizeof(tspTstInfoOid)) != 0))) {
        ret = PKCS7_OID_E;
    }
    /* The digest algorithm of the signature must meet the minimum
     * strength. */
    if (ret == 0) {
        ret = Tsp_CheckHashStrength((word32)pkcs7->hashOID);
    }
    if (ret == 0) {
        /* Decode the content as a TSTInfo - TSA name needed for checks. */
        ret = wc_TspTstInfo_Decode(&tstDec, pkcs7->content, pkcs7->contentSz);
    }
    /* The hash algorithm of the imprint must meet the minimum strength. */
    if (ret == 0) {
        ret = Tsp_CheckHashStrength(tstDec.imprint.hashAlgOID);
    }
    /* Check the signer's certificate is valid for time-stamping. */
    if (ret == 0) {
        if (pkcs7->verifyCert == NULL) {
            /* No certificate to check - must be in token. */
            ret = TSP_VERIFY_E;
        }
        else {
            ret = Tsp_CheckSignerCert(pkcs7->verifyCert, pkcs7->verifyCertSz,
                tstDec.tsa, tstDec.tsaSz, pkcs7->heap);
        }
    }
    /* Check the signing certificate attribute matches the signer. */
    if (ret == 0) {
        ret = TspCheckSigningCertAttr(pkcs7);
    }
    /* Return the decoded TSTInfo when requested. */
    if ((ret == 0) && (tstInfo != NULL)) {
        *tstInfo = tstDec;
    }

    WOLFSSL_LEAVE("wc_TspTstInfo_VerifyWithPKCS7", ret);
    return ret;
}

#endif /* WOLFSSL_TSP_VERIFIER */
#endif /* HAVE_PKCS7 */

#ifdef WOLFSSL_TSP_RESPONDER
/* Initialize a TimeStampResp.
 *
 * @param [out] resp  TimeStampResp object.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when resp is NULL.
 */
int wc_TspResponse_Init(TspResponse* resp)
{
    /* Validate parameter. */
    if (resp == NULL) {
        return BAD_FUNC_ARG;
    }

    /* All fields empty - status of 0 is granted. */
    XMEMSET(resp, 0, sizeof(TspResponse));

    return 0;
}
#endif /* WOLFSSL_TSP_RESPONDER */

#if defined(WOLFSSL_TSP_RESPONDER) || defined(WOLFSSL_TSP_VERIFIER)
/* Get the status information of a TimeStampResp.
 *
 * Each output is optional - pass NULL to not retrieve a value. The status
 * string references into the response and is valid while the response is.
 *
 * @param [in]  resp      TimeStampResp object.
 * @param [out] status    PKIStatus value. See TspPkiStatus. May be NULL.
 * @param [out] str       Status string - UTF-8, no NUL terminator. NULL when
 *                        no status string present. May be NULL.
 * @param [out] strSz     Length of status string in bytes. May be NULL.
 * @param [out] failInfo  Failure information: WC_TSP_FAIL_* flags, 0 when not
 *                        present. May be NULL.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when resp is NULL.
 */
int wc_TspResponse_GetStatus(const TspResponse* resp, word32* status,
    const byte** str, word32* strSz, word32* failInfo)
{
    /* Validate parameter. */
    if (resp == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Return each value the caller asked for. */
    if (status != NULL) {
        *status = resp->status;
    }
    if (str != NULL) {
        *str = resp->statusString;
    }
    if (strSz != NULL) {
        *strSz = resp->statusStringSz;
    }
    if (failInfo != NULL) {
        *failInfo = resp->failInfo;
    }

    return 0;
}
#endif /* WOLFSSL_TSP_RESPONDER || WOLFSSL_TSP_VERIFIER */

#ifdef WOLFSSL_TSP_RESPONDER
/* Set the status information of a TimeStampResp.
 *
 * The status string is assigned - it is not copied and must remain available
 * while the response is used. Pass NULL to have no status string.
 *
 * @param [in, out] resp      TimeStampResp object.
 * @param [in]      status    PKIStatus value. See TspPkiStatus.
 * @param [in]      str       Status string - UTF-8, no NUL terminator. May be
 *                            NULL.
 * @param [in]      strSz     Length of status string in bytes.
 * @param [in]      failInfo  Failure information: WC_TSP_FAIL_* flags, 0 when
 *                            none.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when resp is NULL.
 */
int wc_TspResponse_SetStatus(TspResponse* resp, word32 status, const byte* str,
    word32 strSz, word32 failInfo)
{
    /* Validate parameter. */
    if (resp == NULL) {
        return BAD_FUNC_ARG;
    }

    resp->status = (byte)status;
    /* The status string is assigned, not copied. */
    resp->statusString = str;
    resp->statusStringSz = (str != NULL) ? strSz : 0;
    resp->failInfo = failInfo;

    return 0;
}
#endif /* WOLFSSL_TSP_RESPONDER */

/* Get a human-readable string for a PKIStatus value.
 *
 * @param [in] status  PKIStatus value. See TspPkiStatus.
 * @return  Description of the status - a constant string, not to be freed.
 */
const char* wc_TspStatus_ToString(word32 status)
{
    switch (status) {
        case WC_TSP_PKISTATUS_GRANTED:
            return "granted";
        case WC_TSP_PKISTATUS_GRANTED_WITH_MODS:
            return "granted with modifications";
        case WC_TSP_PKISTATUS_REJECTION:
            return "rejection";
        case WC_TSP_PKISTATUS_WAITING:
            return "waiting";
        case WC_TSP_PKISTATUS_REVOCATION_WARNING:
            return "revocation warning";
        case WC_TSP_PKISTATUS_REVOCATION_NOTIFICATION:
            return "revocation notification";
        default:
            return "unknown status";
    }
}

/* Get a human-readable string for a PKIFailureInfo flag.
 *
 * Expects a single WC_TSP_FAIL_* flag - the failure information of a response
 * has at most one.
 *
 * @param [in] failInfo  Failure information: a WC_TSP_FAIL_* flag.
 * @return  Description of the failure - a constant string, not to be freed.
 */
const char* wc_TspFailInfo_ToString(word32 failInfo)
{
    switch (failInfo) {
        case WC_TSP_FAIL_BAD_ALG:
            return "unrecognized or unsupported algorithm";
        case WC_TSP_FAIL_BAD_REQUEST:
            return "transaction not permitted or supported";
        case WC_TSP_FAIL_BAD_DATA_FORMAT:
            return "data submitted has the wrong format";
        case WC_TSP_FAIL_TIME_NOT_AVAILABLE:
            return "the TSA's time source is not available";
        case WC_TSP_FAIL_UNACCEPTED_POLICY:
            return "the requested TSA policy is not supported";
        case WC_TSP_FAIL_UNACCEPTED_EXTENSION:
            return "the requested extension is not supported";
        case WC_TSP_FAIL_ADD_INFO_NOT_AVAILABLE:
            return "the additional information is not available";
        case WC_TSP_FAIL_SYSTEM_FAILURE:
            return "the request cannot be handled due to system failure";
        default:
            return "unknown failure information";
    }
}

#ifdef HAVE_PKCS7
#ifdef WOLFSSL_TSP_VERIFIER
/* Verify a signer's certificate chains to a trusted CA in a manager.
 *
 * @param [in] cert    DER encoded signer certificate.
 * @param [in] certSz  Length of certificate in bytes.
 * @param [in] cm      WOLFSSL_CERT_MANAGER with the trusted CAs - a void
 *                     pointer to avoid an SSL layer dependency in wolfCrypt.
 * @param [in] heap    Dynamic memory allocation hint.
 * @return  0 when the certificate chains to a trusted CA.
 * @return  TSP_VERIFY_E when it does not.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int Tsp_VerifyCertChain(const byte* cert, word32 certSz, void* cm,
    void* heap)
{
    int ret;
    WC_DECLARE_VAR(dCert, DecodedCert, 1, heap);

    WC_ALLOC_VAR_EX(dCert, DecodedCert, 1, heap, DYNAMIC_TYPE_DCERT,
        return MEMORY_E);

    /* Parse and verify the certificate chains to a trusted CA in the
     * manager. The manager must hold the trust anchor and any intermediate
     * CAs needed - certificates carried in the token are not trust anchors. */
    InitDecodedCert(dCert, cert, certSz, heap);
    ret = ParseCertRelative(dCert, CERT_TYPE, VERIFY, cm, NULL);
    FreeDecodedCert(dCert);

    WC_FREE_VAR_EX(dCert, heap, DYNAMIC_TYPE_DCERT);

    if (ret != 0) {
        WOLFSSL_MSG("TSP signer's certificate is not trusted by the manager");
        ret = TSP_VERIFY_E;
    }
    return ret;
}

/* Verify the time-stamp token of a TimeStampResp, establishing trust in the
 * signer by either pinning a certificate or chaining to a certificate
 * manager. Used by wc_TspResponse_Verify() and wc_TspResponse_VerifyWithCm().
 *
 * @param [in]  resp     TimeStampResp object with a token to verify.
 * @param [in]  cert     DER encoded trusted TSA certificate to pin, or NULL.
 * @param [in]  certSz   Length of certificate in bytes.
 * @param [in]  cm       Certificate manager to chain against, or NULL.
 * @param [out] tstInfo  TSTInfo object to fill. May be NULL.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when resp is NULL.
 * @return  TSP_VERIFY_E on a verification failure.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int TspResponse_Verify(TspResponse* resp, const byte* cert,
    word32 certSz, void* cm, TspTstInfo* tstInfo)
{
    int ret = 0;
#ifdef WOLFSSL_NO_MALLOC
    /* No dynamic memory - the PKCS7 object is on the stack. */
    wc_PKCS7 pkcs7Obj;
    wc_PKCS7* pkcs7 = &pkcs7Obj;
#else
    wc_PKCS7* pkcs7 = NULL;
#endif

#ifdef WOLFSSL_NO_MALLOC
    /* Zero the stack object up front - an early error returns through the
     * unconditional wc_PKCS7_Free below, which must see isDynamic 0 and all
     * pointers NULL so it does not free the stack object or wild pointers. */
    XMEMSET(pkcs7, 0, sizeof(pkcs7Obj));
#endif

    /* Validate parameter. */
    if (resp == NULL) {
        ret = BAD_FUNC_ARG;
    }
    /* The time-stamp must have been granted. */
    if ((ret == 0) && (resp->status != WC_TSP_PKISTATUS_GRANTED) &&
            (resp->status != WC_TSP_PKISTATUS_GRANTED_WITH_MODS)) {
        WOLFSSL_MSG("TSP response status is not granted");
        ret = TSP_VERIFY_E;
    }
    /* A granted response has a token to verify. */
    if ((ret == 0) && ((resp->token == NULL) || (resp->tokenSz == 0))) {
        WOLFSSL_MSG("TSP response has no time-stamp token");
        ret = TSP_VERIFY_E;
    }

    if (ret == 0) {
#ifdef WOLFSSL_NO_MALLOC
        ret = wc_PKCS7_Init(pkcs7, NULL, INVALID_DEVID);
#else
        pkcs7 = wc_PKCS7_New(NULL, INVALID_DEVID);
        if (pkcs7 == NULL) {
            ret = MEMORY_E;
        }
#endif
    }
    if (ret == 0) {
        /* Initialize with the TSA's certificate - NULL when in the token. */
        ret = wc_PKCS7_InitWithCert(pkcs7, (byte*)cert, certSz);
    }
    if (ret == 0) {
        /* The token references the response - not modified by verify. */
        ret = wc_TspTstInfo_VerifyWithPKCS7(pkcs7, (byte*)resp->token,
            resp->tokenSz, tstInfo);
    }
    /* Establish trust in the signer. The token's signature was verified
     * against the certificate in the token; trust pins that certificate to a
     * known one or chains it to a trusted CA in the manager. */
    if ((ret == 0) && (cm != NULL)) {
        /* Chain the signer's certificate to a trusted CA. */
        ret = Tsp_VerifyCertChain(pkcs7->verifyCert, pkcs7->verifyCertSz,
            cm, pkcs7->heap);
    }
    else if ((ret == 0) && (cert != NULL) &&
            ((pkcs7->verifyCertSz != certSz) ||
             (pkcs7->verifyCert == NULL) ||
             (XMEMCMP(pkcs7->verifyCert, cert, certSz) != 0))) {
        /* Pin: the signer must be the given trusted certificate. */
        WOLFSSL_MSG("TSP signer is not the trusted TSA");
        ret = TSP_VERIFY_E;
    }
    /* tstInfo references pkcs7->content, which wc_PKCS7_Free releases - the
     * verify may copy the eContent into PKCS7-owned memory. Re-point the
     * references into the caller's token, which holds the same TSTInfo DER,
     * so tstInfo stays valid after this function returns. */
    if ((ret == 0) && (tstInfo != NULL) && (pkcs7->contentSz > 0)) {
        const byte* c = pkcs7->content;
        word32 off;
        word32 matchOff = 0;
        int matches = 0;

        /* The content must appear exactly once in the response token so the
         * references can be rebased unambiguously. Zero matches means the
         * content is not contiguous in the token (e.g. a constructed OCTET
         * STRING); more than one means a duplicated byte sequence that could
         * rebase the references to the wrong - though in-bounds - location.
         * Both are rejected rather than hand back possibly-wrong references. */
        for (off = 0; off + pkcs7->contentSz <= resp->tokenSz; off++) {
            if (XMEMCMP(resp->token + off, c, pkcs7->contentSz) == 0) {
                matchOff = off;
                if (++matches > 1) {
                    break;
                }
            }
        }
        if (matches != 1) {
            WOLFSSL_MSG("TSP token content not found uniquely in response");
            ret = TSP_VERIFY_E;
        }
        else {
            const byte* tok = resp->token + matchOff;
            if (tstInfo->policy != NULL)
                tstInfo->policy  = tok + (tstInfo->policy  - c);
            if (tstInfo->serial != NULL)
                tstInfo->serial  = tok + (tstInfo->serial  - c);
            if (tstInfo->genTime != NULL)
                tstInfo->genTime = tok + (tstInfo->genTime - c);
            if (tstInfo->nonce != NULL)
                tstInfo->nonce   = tok + (tstInfo->nonce   - c);
            if (tstInfo->tsa != NULL)
                tstInfo->tsa     = tok + (tstInfo->tsa     - c);
        }
    }

    /* On any error tstInfo may hold references into pkcs7->content, which
     * wc_PKCS7_Free is about to release - clear them so a caller that ignores
     * the return value is not handed dangling pointers. */
    if ((ret != 0) && (tstInfo != NULL)) {
        XMEMSET(tstInfo, 0, sizeof(*tstInfo));
    }

    wc_PKCS7_Free(pkcs7);
    return ret;
}

/* Verify the time-stamp token of a TimeStampResp with the TSA's certificate.
 *
 * Convenience wrapper around wc_TspTstInfo_VerifyWithPKCS7() that creates and
 * disposes of the PKCS7 object. The time-stamp must have been granted and the
 * response must have a token. The token's signature is verified and the
 * signer's certificate checked - see wc_TspTstInfo_VerifyWithPKCS7().
 *
 * When a certificate is given it is the trusted TSA - the signer of the token
 * must be that certificate. This establishes trust by pinning the TSA's
 * certificate. The certificate is also used to verify the signature when the
 * token does not include the signer's certificate - certReq was not set in
 * the request. When the certificate is NULL the token must include the
 * signer's certificate and no trust is established - the caller must trust
 * the signer by other means.
 *
 * Pointers in tstInfo reference the token of the response - the response and
 * its token buffer must remain available while tstInfo is in use.
 *
 * @param [in]  resp     TimeStampResp object with a token to verify.
 * @param [in]  cert     DER encoded certificate of the trusted TSA. May be
 *                       NULL when the token includes the signer's certificate
 *                       and trust is established by other means.
 * @param [in]  certSz   Length of certificate in bytes.
 * @param [out] tstInfo  TSTInfo object to fill. May be NULL.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when resp is NULL.
 * @return  TSP_VERIFY_E when the response was not granted, has no token, the
 *          token does not verify - see wc_TspTstInfo_VerifyWithPKCS7() - or the
 *          signer is not the trusted TSA certificate.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
int wc_TspResponse_Verify(TspResponse* resp, const byte* cert, word32 certSz,
    TspTstInfo* tstInfo)
{
    int ret;

    WOLFSSL_ENTER("wc_TspResponse_Verify");

    /* Pin the signer to the given certificate - no certificate manager. */
    ret = TspResponse_Verify(resp, cert, certSz, NULL, tstInfo);

    WOLFSSL_LEAVE("wc_TspResponse_Verify", ret);
    return ret;
}

/* Verify the time-stamp token of a TimeStampResp, trusting the signer via a
 * certificate manager.
 *
 * Convenience wrapper around wc_TspTstInfo_VerifyWithPKCS7() that creates and
 * disposes of the PKCS7 object. The time-stamp must have been granted and the
 * response must have a token. The token's signature is verified and the
 * signer's certificate checked - see wc_TspTstInfo_VerifyWithPKCS7() - then
 * the signer's certificate is verified to chain to a trusted CA in the
 * manager.
 *
 * The token must include the signer's certificate - the certificate manager
 * must hold the trust anchor and any intermediate CAs needed to build the
 * chain. Certificates carried in the token are used to verify the token's
 * signature but are not trusted as CAs - load intermediate CAs into the
 * manager to support a signer issued by an intermediate.
 *
 * Pointers in tstInfo reference the token of the response - the response and
 * its token buffer must remain available while tstInfo is in use.
 *
 * @param [in]  resp     TimeStampResp object with a token to verify.
 * @param [in]  cm       WOLFSSL_CERT_MANAGER with the trusted CAs - passed as
 *                       a void pointer to avoid an SSL layer dependency.
 * @param [out] tstInfo  TSTInfo object to fill. May be NULL.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when resp or cm is NULL.
 * @return  TSP_VERIFY_E when the response was not granted, has no token, the
 *          token does not verify or the signer does not chain to a trusted CA.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
int wc_TspResponse_VerifyWithCm(TspResponse* resp, void* cm,
    TspTstInfo* tstInfo)
{
    int ret;

    WOLFSSL_ENTER("wc_TspResponse_VerifyWithCm");

    /* A certificate manager is required to establish trust. */
    if (cm == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Chain the signer's certificate to a trusted CA in the manager. */
    ret = TspResponse_Verify(resp, NULL, 0, cm, tstInfo);

    WOLFSSL_LEAVE("wc_TspResponse_VerifyWithCm", ret);
    return ret;
}

/* Verify the time-stamp token of a TimeStampResp and that it is over the data.
 *
 * Convenience over wc_TspResponse_Verify() that also confirms the time-stamp
 * is over the given data - hashing the data with the token's message imprint
 * algorithm and comparing to the imprint. The caller does not hash the data.
 *
 * @param [in]  resp     TimeStampResp object with a token to verify.
 * @param [in]  cert     DER encoded certificate of the trusted TSA. May be
 *                       NULL - see wc_TspResponse_Verify().
 * @param [in]  certSz   Length of certificate in bytes.
 * @param [in]  data     Data that was time-stamped.
 * @param [in]  dataSz   Length of data in bytes.
 * @param [out] tstInfo  TSTInfo object to fill. May be NULL.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when resp or data is NULL.
 * @return  TSP_VERIFY_E when the token does not verify or the data does not
 *          match the message imprint.
 * @return  HASH_TYPE_E when the imprint's hash algorithm is not supported.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
int wc_TspResponse_VerifyData(TspResponse* resp, const byte* cert,
    word32 certSz, const byte* data, word32 dataSz, TspTstInfo* tstInfo)
{
    int ret;
    TspTstInfo tstLocal;

    WOLFSSL_ENTER("wc_TspResponse_VerifyData");

    /* Validate parameter - resp is checked by wc_TspResponse_Verify(). */
    if (data == NULL) {
        return BAD_FUNC_ARG;
    }
    /* A TSTInfo is needed for the data check - use a local when not wanted. */
    if (tstInfo == NULL) {
        tstInfo = &tstLocal;
    }

    /* Verify the response and its token. */
    ret = wc_TspResponse_Verify(resp, cert, certSz, tstInfo);
    /* Confirm the time-stamp is over the given data. */
    if (ret == 0) {
        ret = wc_TspTstInfo_VerifyData(tstInfo, data, dataSz);
    }

    WOLFSSL_LEAVE("wc_TspResponse_VerifyData", ret);
    return ret;
}

#endif /* WOLFSSL_TSP_VERIFIER */
#endif /* HAVE_PKCS7 */

#endif /* WOLFSSL_TSP && WOLFSSL_ASN_TEMPLATE && !NO_ASN */
