/* tsp.h
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

/*!
    \file wolfssl/wolfcrypt/tsp.h

    Time-Stamp Protocol (TSP) message encoding and decoding. RFC 3161.
*/

#ifndef WOLF_CRYPT_TSP_H
#define WOLF_CRYPT_TSP_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_TSP

#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/asn.h>
#ifdef HAVE_PKCS7
    #include <wolfssl/wolfcrypt/pkcs7.h>
#endif

#ifdef __cplusplus
    extern "C" {
#endif

/* Version of TimeStampReq and TSTInfo supported. RFC 3161, 2.4.1 and 2.4.2. */
#define WC_TSP_VERSION              1

/* PKIStatus values. RFC 3161, 2.4.2. */
enum TspPkiStatus {
    WC_TSP_PKISTATUS_GRANTED                 = 0,
    WC_TSP_PKISTATUS_GRANTED_WITH_MODS       = 1,
    WC_TSP_PKISTATUS_REJECTION               = 2,
    WC_TSP_PKISTATUS_WAITING                 = 3,
    WC_TSP_PKISTATUS_REVOCATION_WARNING      = 4,
    WC_TSP_PKISTATUS_REVOCATION_NOTIFICATION = 5
};

/* PKIFailureInfo flags. RFC 3161, 2.4.2.
 * The value is the BIT STRING's data as a big-endian number left-aligned to
 * 32 bits - named bit n is bit (31 - n) of the value. */
#define WC_TSP_FAIL_BAD_ALG                 0x80000000UL /* bit 0  */
#define WC_TSP_FAIL_BAD_REQUEST             0x20000000UL /* bit 2  */
#define WC_TSP_FAIL_BAD_DATA_FORMAT         0x04000000UL /* bit 5  */
#define WC_TSP_FAIL_TIME_NOT_AVAILABLE      0x00020000UL /* bit 14 */
#define WC_TSP_FAIL_UNACCEPTED_POLICY       0x00010000UL /* bit 15 */
#define WC_TSP_FAIL_UNACCEPTED_EXTENSION    0x00008000UL /* bit 16 */
#define WC_TSP_FAIL_ADD_INFO_NOT_AVAILABLE  0x00004000UL /* bit 17 */
#define WC_TSP_FAIL_SYSTEM_FAILURE          0x00000040UL /* bit 25 */

/* Maximum length of the hash in a MessageImprint: SHA-512 is the longest
 * hash supported. */
#define WC_TSP_MAX_HASH_SZ          64

/* Maximum length of a nonce in a TimeStampReq: OpenSSL sends 8 bytes. */
#ifndef MAX_TS_NONCE_SZ
    #define MAX_TS_NONCE_SZ         32
#endif

/* Minimum security strength in bits of the hash algorithms accepted when
 * verifying a token - the collision resistance of a hash is half the
 * digest length in bits. 0 means any available hash algorithm is accepted.
 * e.g. 128 requires SHA-256 or longer. */
#ifndef WC_TSP_MIN_HASH_STRENGTH_BITS
    #define WC_TSP_MIN_HASH_STRENGTH_BITS   0
#endif

/* MessageImprint. RFC 3161, 2.4.1.
 * Hash algorithm and hash of the data to be time-stamped. */
typedef struct TspMessageImprint {
    /* Hash algorithm OID sum: SHA256h, SHA384h, etc. On decode, checked
     * against the known hash algorithm OIDs - an OID not known is accepted
     * and the caller checks the sum is one it supports. */
    word32      hashAlgOID;
    /* Hash of message - copied into on decode. */
    byte        hash[WC_TSP_MAX_HASH_SZ];
    /* Length of hash in bytes. */
    word32      hashSz;
} TspMessageImprint;

/* Accuracy of time in TSTInfo. RFC 3161, 2.4.2.
 * A value of 0 in a field means not present. */
typedef struct TspAccuracy {
    /* Accuracy in seconds. */
    word32      seconds;
    /* Accuracy in milliseconds: 1..999. */
    word16      millis;
    /* Accuracy in microseconds: 1..999. */
    word16      micros;
} TspAccuracy;

/* TimeStampReq. RFC 3161, 2.4.1.
 * Extensions are not supported - decode fails when present. */
typedef struct TspRequest {
    /* Version: must be 1. Set on decode - always 1 on encode. */
    byte        version;
    /* Hash algorithm and hash of data to be time-stamped. */
    TspMessageImprint imprint;
    /* Optional TSA policy ID: content of OBJECT IDENTIFIER - copied into on
     * decode. Not present when policySz is 0. */
    byte        policy[MAX_OID_SZ];
    word32      policySz;
    /* Optional nonce: big-endian number - must not have a leading zero
     * byte, checked on encode. Copied into on decode. Not present when
     * nonceSz is 0. */
    byte        nonce[MAX_TS_NONCE_SZ];
    word32      nonceSz;
    /* Request TSA certificate to be included in response when true. */
    byte        certReq;
} TspRequest;

/* TSTInfo. RFC 3161, 2.4.2.
 * Content of the time-stamp token signed by the TSA.
 * On decode, pointers reference into the message buffer - the buffer must
 * remain available while the structure is in use.
 * Extensions are not supported - decode fails when present. */
typedef struct TspTstInfo {
    /* Version: must be 1. Set on decode - always 1 on encode. */
    byte        version;
    /* TSA policy ID: content of OBJECT IDENTIFIER. */
    const byte* policy;
    word32      policySz;
    /* Hash algorithm and hash of data time-stamped. */
    TspMessageImprint imprint;
    /* Serial number of time-stamp: big-endian number, up to 160 bits -
     * must not have a leading zero byte, checked on encode. */
    const byte* serial;
    word32      serialSz;
    /* Time of time-stamp as a GeneralizedTime string of RFC 3161:
     * "YYYYMMDDhhmmss[.s...]Z" - syntax checked on encode and decode.
     * When NULL on encode, the current time is used (requires a real time
     * clock - not available with NO_ASN_TIME). */
    const byte* genTime;
    word32      genTimeSz;
    /* Optional accuracy of time. */
    TspAccuracy accuracy;
    /* Time-stamps from TSA are strictly ordered when true. */
    byte        ordering;
    /* Optional nonce: big-endian number, must match request's nonce
     * exactly - must not have a leading zero byte, checked on encode. NULL
     * when not present. */
    const byte* nonce;
    word32      nonceSz;
    /* Optional name of TSA: DER encoding of GeneralName. NULL when not
     * present. */
    const byte* tsa;
    word32      tsaSz;
} TspTstInfo;

/* TimeStampResp. RFC 3161, 2.4.2.
 * PKIStatusInfo and optional TimeStampToken.
 * On decode, pointers reference into the message buffer - the buffer must
 * remain available while the structure is in use. */
typedef struct TspResponse {
    /* PKIStatus value. See TspPkiStatus. */
    byte        status;
    /* Optional status text, UTF-8 encoded, no NUL terminator.
     * On encode, placed in a PKIFreeText with one UTF8String.
     * On decode, references the first UTF8String of the PKIFreeText. */
    const byte* statusString;
    word32      statusStringSz;
    /* Optional failure information: WC_TSP_FAIL_* flags. 0 when not
     * present. */
    word32      failInfo;
    /* Optional time-stamp token: DER encoding of ContentInfo containing
     * CMS SignedData with TSTInfo content. NULL when not present. */
    const byte* token;
    word32      tokenSz;
} TspResponse;


/* TimeStampReq encoding, decoding and operations. */
#ifdef WOLFSSL_TSP_REQUESTER
WOLFSSL_API int wc_TspRequest_Init(TspRequest* req);
#endif /* WOLFSSL_TSP_REQUESTER */
#ifdef WOLFSSL_TSP_REQUESTER
WOLFSSL_API int wc_TspRequest_SetHashType(TspRequest* req,
    enum wc_HashType hashType);
#endif /* WOLFSSL_TSP_REQUESTER */
#if defined(WOLFSSL_TSP_REQUESTER) || defined(WOLFSSL_TSP_VERIFIER)
WOLFSSL_API int wc_TspRequest_GetHashType(const TspRequest* req,
    enum wc_HashType* hashType);
#endif /* WOLFSSL_TSP_REQUESTER || WOLFSSL_TSP_VERIFIER */
#if defined(WOLFSSL_TSP_REQUESTER) || defined(WOLFSSL_TSP_VERIFIER)
WOLFSSL_API int wc_TspRequest_GetHash(const TspRequest* req, byte* hash,
    word32* hashSz);
#endif /* WOLFSSL_TSP_REQUESTER || WOLFSSL_TSP_VERIFIER */
#ifdef WOLFSSL_TSP_REQUESTER
WOLFSSL_API int wc_TspRequest_SetHash(TspRequest* req, const byte* hash,
    word32 hashSz);
#endif /* WOLFSSL_TSP_REQUESTER */
#if defined(WOLFSSL_TSP_REQUESTER) || defined(WOLFSSL_TSP_VERIFIER)
WOLFSSL_API int wc_TspRequest_GetNonce(const TspRequest* req, byte* nonce,
    word32* nonceSz);
#endif /* WOLFSSL_TSP_REQUESTER || WOLFSSL_TSP_VERIFIER */
#ifdef WOLFSSL_TSP_REQUESTER
WOLFSSL_API int wc_TspRequest_SetNonce(TspRequest* req, const byte* nonce,
    word32 nonceSz);
#endif /* WOLFSSL_TSP_REQUESTER */
#if defined(WOLFSSL_TSP_REQUESTER) && !defined(WC_NO_RNG)
WOLFSSL_API int wc_TspRequest_GenerateNonce(TspRequest* req, WC_RNG* rng,
    word32 sz);
#endif /* WOLFSSL_TSP_REQUESTER && !WC_NO_RNG */
#if defined(WOLFSSL_TSP_REQUESTER) || defined(WOLFSSL_TSP_VERIFIER)
WOLFSSL_API int wc_TspRequest_GetPolicy(const TspRequest* req, byte* policy,
    word32* policySz);
#endif /* WOLFSSL_TSP_REQUESTER || WOLFSSL_TSP_VERIFIER */
#ifdef WOLFSSL_TSP_REQUESTER
WOLFSSL_API int wc_TspRequest_SetPolicy(TspRequest* req, const byte* policy,
    word32 policySz);
#endif /* WOLFSSL_TSP_REQUESTER */
/* The requester sets certReq and reads it back; the responder reads it from a
 * received request. */
#if defined(WOLFSSL_TSP_REQUESTER) || defined(WOLFSSL_TSP_RESPONDER)
/* Get the certReq flag of a TimeStampReq.
 *
 * A non-zero value means the requester asked for the TSA certificate to be
 * included in the response.
 *
 * @param [in] req  TimeStampReq object.
 * @return  Non-zero when the TSA certificate is requested, 0 otherwise.
 */
#define wc_TspRequest_GetCertReq(req)       ((req)->certReq)
#endif /* WOLFSSL_TSP_REQUESTER || WOLFSSL_TSP_RESPONDER */
#ifdef WOLFSSL_TSP_REQUESTER
/* Set the certReq flag of a TimeStampReq.
 *
 * A non-zero value requests the TSA certificate to be included in the
 * response. Any non-zero value is normalized to 1.
 *
 * @param [in, out] req  TimeStampReq object.
 * @param [in]      val  Non-zero to request the TSA certificate, 0 otherwise.
 */
#define wc_TspRequest_SetCertReq(req, val)  \
    ((req)->certReq = (byte)((val) != 0))
#endif /* WOLFSSL_TSP_REQUESTER */
#ifdef WOLFSSL_TSP_REQUESTER
WOLFSSL_API int wc_TspRequest_Encode(const TspRequest* req, byte* out,
    word32* outSz);
#endif /* WOLFSSL_TSP_REQUESTER */
WOLFSSL_API int wc_TspRequest_Decode(TspRequest* req, const byte* input,
    word32 inSz);

/* TSTInfo encoding, decoding and operations. */
#ifdef WOLFSSL_TSP_RESPONDER
WOLFSSL_API int wc_TspTstInfo_Init(TspTstInfo* tstInfo);
#endif /* WOLFSSL_TSP_RESPONDER */
#if defined(WOLFSSL_TSP_RESPONDER) || defined(WOLFSSL_TSP_VERIFIER)
WOLFSSL_API int wc_TspTstInfo_GetSerial(const TspTstInfo* tstInfo,
    const byte** serial, word32* serialSz);
#endif /* WOLFSSL_TSP_RESPONDER || WOLFSSL_TSP_VERIFIER */
#ifdef WOLFSSL_TSP_RESPONDER
WOLFSSL_API int wc_TspTstInfo_SetSerial(TspTstInfo* tstInfo,
    const byte* serial, word32 serialSz);
#endif /* WOLFSSL_TSP_RESPONDER */
#if defined(WOLFSSL_TSP_RESPONDER) || defined(WOLFSSL_TSP_VERIFIER)
WOLFSSL_API int wc_TspTstInfo_GetPolicy(const TspTstInfo* tstInfo,
    const byte** policy, word32* policySz);
#endif /* WOLFSSL_TSP_RESPONDER || WOLFSSL_TSP_VERIFIER */
#ifdef WOLFSSL_TSP_RESPONDER
WOLFSSL_API int wc_TspTstInfo_SetPolicy(TspTstInfo* tstInfo,
    const byte* policy, word32 policySz);
#endif /* WOLFSSL_TSP_RESPONDER */
#if defined(WOLFSSL_TSP_RESPONDER) || defined(WOLFSSL_TSP_VERIFIER)
WOLFSSL_API int wc_TspTstInfo_GetMsgImprint(const TspTstInfo* tstInfo,
    word32* hashOID, const byte** hash, word32* hashSz);
#endif /* WOLFSSL_TSP_RESPONDER || WOLFSSL_TSP_VERIFIER */
#ifdef WOLFSSL_TSP_RESPONDER
WOLFSSL_API int wc_TspTstInfo_SetMsgImprint(TspTstInfo* tstInfo,
    word32 hashOID, const byte* hash, word32 hashSz);
#endif /* WOLFSSL_TSP_RESPONDER */
#if defined(WOLFSSL_TSP_RESPONDER) || defined(WOLFSSL_TSP_VERIFIER)
WOLFSSL_API int wc_TspTstInfo_GetGenTime(const TspTstInfo* tstInfo,
    const byte** genTime, word32* genTimeSz);
#endif /* WOLFSSL_TSP_RESPONDER || WOLFSSL_TSP_VERIFIER */
#ifdef WOLFSSL_TSP_RESPONDER
WOLFSSL_API int wc_TspTstInfo_SetGenTime(TspTstInfo* tstInfo,
    const byte* genTime, word32 genTimeSz);
#endif /* WOLFSSL_TSP_RESPONDER */
#ifndef NO_ASN_TIME
#if defined(WOLFSSL_TSP_RESPONDER) || defined(WOLFSSL_TSP_VERIFIER)
WOLFSSL_API int wc_TspTstInfo_GetGenTimeAsTime(const TspTstInfo* tstInfo,
    time_t* t);
#endif /* WOLFSSL_TSP_RESPONDER || WOLFSSL_TSP_VERIFIER */
#ifdef WOLFSSL_TSP_RESPONDER
WOLFSSL_API int wc_TspTstInfo_SetGenTimeAsTime(TspTstInfo* tstInfo, time_t t,
    byte* buf, word32 bufSz);
#endif /* WOLFSSL_TSP_RESPONDER */
#endif /* !NO_ASN_TIME */
#if defined(WOLFSSL_TSP_RESPONDER) || defined(WOLFSSL_TSP_VERIFIER)
WOLFSSL_API int wc_TspTstInfo_GetAccuracy(const TspTstInfo* tstInfo,
    word32* seconds, word16* millis, word16* micros);
#endif /* WOLFSSL_TSP_RESPONDER || WOLFSSL_TSP_VERIFIER */
#ifdef WOLFSSL_TSP_RESPONDER
WOLFSSL_API int wc_TspTstInfo_SetAccuracy(TspTstInfo* tstInfo,
    word32 seconds, word16 millis, word16 micros);
#endif /* WOLFSSL_TSP_RESPONDER */
#if defined(WOLFSSL_TSP_RESPONDER) || defined(WOLFSSL_TSP_VERIFIER)
WOLFSSL_API int wc_TspTstInfo_GetNonce(const TspTstInfo* tstInfo,
    const byte** nonce, word32* nonceSz);
#endif /* WOLFSSL_TSP_RESPONDER || WOLFSSL_TSP_VERIFIER */
#ifdef WOLFSSL_TSP_RESPONDER
WOLFSSL_API int wc_TspTstInfo_SetNonce(TspTstInfo* tstInfo,
    const byte* nonce, word32 nonceSz);
#endif /* WOLFSSL_TSP_RESPONDER */
#if defined(WOLFSSL_TSP_RESPONDER) || defined(WOLFSSL_TSP_VERIFIER)
WOLFSSL_API int wc_TspTstInfo_GetTsa(const TspTstInfo* tstInfo,
    const byte** tsa, word32* tsaSz);
#endif /* WOLFSSL_TSP_RESPONDER || WOLFSSL_TSP_VERIFIER */
#ifdef WOLFSSL_TSP_RESPONDER
WOLFSSL_API int wc_TspTstInfo_SetTsa(TspTstInfo* tstInfo, const byte* tsa,
    word32 tsaSz);
#endif /* WOLFSSL_TSP_RESPONDER */
/* Set the TSTInfo's values to respond to a request - echoes the request's
 * imprint and nonce and sets the TSA's policy, serial and time. */
#ifdef WOLFSSL_TSP_RESPONDER
WOLFSSL_API int wc_TspTstInfo_SetFromRequest(TspTstInfo* tstInfo,
    const TspRequest* req, const byte* policy, word32 policySz,
    const byte* serial, word32 serialSz, const byte* genTime,
    word32 genTimeSz);
#endif /* WOLFSSL_TSP_RESPONDER */
#ifdef WOLFSSL_TSP_RESPONDER
WOLFSSL_API int wc_TspTstInfo_Encode(const TspTstInfo* tstInfo, byte* out,
    word32* outSz);
#endif /* WOLFSSL_TSP_RESPONDER */
#ifdef WOLFSSL_TSP_VERIFIER
WOLFSSL_API int wc_TspTstInfo_Decode(TspTstInfo* tstInfo, const byte* input,
    word32 inSz);
#endif /* WOLFSSL_TSP_VERIFIER */
#if !defined(NO_ASN_TIME) && !defined(USER_TIME) && !defined(TIME_OVERRIDES)
#ifdef WOLFSSL_TSP_VERIFIER
WOLFSSL_API int wc_TspTstInfo_CheckGenTime(const TspTstInfo* tstInfo,
    word32 tolerance);
#endif /* WOLFSSL_TSP_VERIFIER */
#endif
/* Check TSTInfo from a response against the request sent. */
#ifdef WOLFSSL_TSP_VERIFIER
WOLFSSL_API int wc_TspTstInfo_CheckRequest(const TspTstInfo* tstInfo,
    const TspRequest* req);
#endif /* WOLFSSL_TSP_VERIFIER */
/* Check the TSA name of a TSTInfo is the expected name. */
#ifdef WOLFSSL_TSP_VERIFIER
WOLFSSL_API int wc_TspTstInfo_CheckTsaName(const TspTstInfo* tstInfo,
    const byte* tsa, word32 tsaSz);
#endif /* WOLFSSL_TSP_VERIFIER */
/* Verify the message imprint of a TSTInfo against the original data. */
#ifdef WOLFSSL_TSP_VERIFIER
WOLFSSL_API int wc_TspTstInfo_VerifyData(const TspTstInfo* tstInfo,
    const byte* data, word32 dataSz);
#endif /* WOLFSSL_TSP_VERIFIER */
#ifdef HAVE_PKCS7
/* Internal: id-aa-signingCertificateV2 attribute OID. Defined in asn_tsp.c;
 * used by token creation (tsp.c) and the signing-certificate check
 * (asn_tsp.c). */
extern const byte tspSigningCertV2Oid[13];
/* TimeStampToken creation (responder) using CMS SignedData. */
#ifdef WOLFSSL_TSP_RESPONDER
/* Create a token with the TSA's certificate and key - manages the PKCS7
 * object. */
WOLFSSL_API int wc_TspTstInfo_Sign(const TspTstInfo* tstInfo,
    const byte* cert, word32 certSz, const byte* key, word32 keySz,
    enum wc_PkType keyType, enum wc_HashType hashType, WC_RNG* rng,
    byte* out, word32* outSz);
WOLFSSL_API int wc_TspTstInfo_SignWithPkcs7(const TspTstInfo* tstInfo,
    wc_PKCS7* pkcs7, byte* out, word32* outSz);
/* Internal: encode a SigningCertificateV2 signed attribute - asn_tsp.c. */
WOLFSSL_LOCAL int TspEncodeSigningCertV2(int hashOID, const byte* cert,
    word32 certSz, byte* out, word32* outSz, void* heap);
#endif /* WOLFSSL_TSP_RESPONDER */
/* TimeStampToken verification (requester) using CMS SignedData. */
#ifdef WOLFSSL_TSP_VERIFIER
WOLFSSL_API int wc_TspTstInfo_VerifyWithPKCS7(wc_PKCS7* pkcs7, byte* token,
    word32 tokenSz, TspTstInfo* tstInfo);
/* Internal helper in tsp.c, also used by TspCheckSigningCertAttr (asn_tsp.c). */
WOLFSSL_LOCAL int Tsp_CheckHashStrength(word32 hashOID);
/* Internal helpers in asn_tsp.c used by wc_TspTstInfo_VerifyWithPKCS7 (tsp.c). */
WOLFSSL_LOCAL int TspCheckOneSignerInfo(const byte* token, word32 tokenSz,
    void* heap);
WOLFSSL_LOCAL int TspCheckSigningCertAttr(wc_PKCS7* pkcs7);
#endif /* WOLFSSL_TSP_VERIFIER */
#endif /* HAVE_PKCS7 */

/* TimeStampResp encoding, decoding and operations. */
#ifdef WOLFSSL_TSP_RESPONDER
WOLFSSL_API int wc_TspResponse_Init(TspResponse* resp);
#endif /* WOLFSSL_TSP_RESPONDER */
#ifdef WOLFSSL_TSP_RESPONDER
WOLFSSL_API int wc_TspResponse_Encode(const TspResponse* resp, byte* out,
    word32* outSz);
#endif /* WOLFSSL_TSP_RESPONDER */
#ifdef WOLFSSL_TSP_VERIFIER
WOLFSSL_API int wc_TspResponse_Decode(TspResponse* resp, const byte* input,
    word32 inSz);
#endif /* WOLFSSL_TSP_VERIFIER */
/* Get and set the status information of a TimeStampResp. */
#if defined(WOLFSSL_TSP_RESPONDER) || defined(WOLFSSL_TSP_VERIFIER)
WOLFSSL_API int wc_TspResponse_GetStatus(const TspResponse* resp,
    word32* status, const byte** str, word32* strSz, word32* failInfo);
#endif /* WOLFSSL_TSP_RESPONDER || WOLFSSL_TSP_VERIFIER */
#ifdef WOLFSSL_TSP_RESPONDER
WOLFSSL_API int wc_TspResponse_SetStatus(TspResponse* resp, word32 status,
    const byte* str, word32 strSz, word32 failInfo);
#endif /* WOLFSSL_TSP_RESPONDER */
/* Human-readable strings for a PKIStatus and a PKIFailureInfo flag. */
WOLFSSL_API const char* wc_TspStatus_ToString(word32 status);
WOLFSSL_API const char* wc_TspFailInfo_ToString(word32 failInfo);
#ifdef HAVE_PKCS7
/* Verify a response's token with the TSA's certificate - manages the PKCS7
 * object. */
#ifdef WOLFSSL_TSP_VERIFIER
WOLFSSL_API int wc_TspResponse_Verify(TspResponse* resp, const byte* cert,
    word32 certSz, TspTstInfo* tstInfo);
#endif /* WOLFSSL_TSP_VERIFIER */
/* Verify a response's token, trusting the signer via a certificate manager
 * (WOLFSSL_CERT_MANAGER, passed as void* to avoid an SSL layer dependency). */
#ifdef WOLFSSL_TSP_VERIFIER
WOLFSSL_API int wc_TspResponse_VerifyWithCm(TspResponse* resp, void* cm,
    TspTstInfo* tstInfo);
#endif /* WOLFSSL_TSP_VERIFIER */
/* Verify a response's token and that it is over the given data. */
#ifdef WOLFSSL_TSP_VERIFIER
WOLFSSL_API int wc_TspResponse_VerifyData(TspResponse* resp, const byte* cert,
    word32 certSz, const byte* data, word32 dataSz, TspTstInfo* tstInfo);
#endif /* WOLFSSL_TSP_VERIFIER */
#endif /* HAVE_PKCS7 */

/* Internal: validate a genTime is a GeneralizedTime of RFC 3161. Shared by
 * the message encoding/decoding (asn_tsp.c) and wc_TspTstInfo_CheckGenTime
 * (tsp.c). */
WOLFSSL_LOCAL int TspCheckGenTimeSyntax(const byte* t, word32 sz);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_TSP */
#endif /* WOLF_CRYPT_TSP_H */
