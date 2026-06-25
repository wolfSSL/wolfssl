/* asn_tsp.c
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
 * This library provides encoding and decoding of Time-Stamp Protocol (TSP)
 * messages: TimeStampReq, TimeStampResp and TSTInfo. RFC 3161.
 *
 * The TimeStampToken in a TimeStampResp is a CMS SignedData (RFC 5652) with
 * content type id-ct-TSTInfo. Creation and verification of tokens is
 * implemented using PKCS#7 APIs when available.
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if !defined(WOLFSSL_ASN_TSP_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning asn_tsp.c does not need to be compiled separately from asn.c
    #endif
#else

#if defined(WOLFSSL_TSP) && defined(WOLFSSL_ASN_TEMPLATE) && !defined(NO_ASN)

#include <wolfssl/wolfcrypt/tsp.h>
#ifdef HAVE_PKCS7
    #include <wolfssl/wolfcrypt/pkcs7.h>
    #include <wolfssl/wolfcrypt/hash.h>
#endif

/* ASN template for TimeStampReq.
 * RFC 3161, 2.4.1 - Request Format
 *
 * Extensions are not supported - decoding a message with an extensions
 * element fails as it matches no item.
 */
static const ASNItem tspReqASN[] = {
/* SEQ         */ { 0, ASN_SEQUENCE, 1, 1, 0 },
                                              /* version */
/* VER         */     { 1, ASN_INTEGER, 0, 0, 0 },
                                              /* messageImprint */
/* MI_SEQ      */     { 1, ASN_SEQUENCE, 1, 1, 0 },
                                              /* hashAlgorithm */
/* MI_ALG_SEQ  */         { 2, ASN_SEQUENCE, 1, 1, 0 },
/* MI_ALG_OID  */             { 3, ASN_OBJECT_ID, 0, 0, 0 },
/* MI_ALG_NULL */             { 3, ASN_TAG_NULL, 0, 0, 1 },
                                              /* hashedMessage */
/* MI_MSG      */         { 2, ASN_OCTET_STRING, 0, 0, 0 },
                                              /* reqPolicy */
/* POLICY      */     { 1, ASN_OBJECT_ID, 0, 0, 1 },
                                              /* nonce */
/* NONCE       */     { 1, ASN_INTEGER, 0, 0, 1 },
                                              /* certReq */
/* CERTREQ     */     { 1, ASN_BOOLEAN, 0, 0, 1 },
};
/* Named indices for tspReqASN. */
enum {
    TSPREQASN_IDX_SEQ = 0,
    TSPREQASN_IDX_VER,
    TSPREQASN_IDX_MI_SEQ,
    TSPREQASN_IDX_MI_ALG_SEQ,
    TSPREQASN_IDX_MI_ALG_OID,
    TSPREQASN_IDX_MI_ALG_NULL,
    TSPREQASN_IDX_MI_MSG,
    TSPREQASN_IDX_POLICY,
    TSPREQASN_IDX_NONCE,
    TSPREQASN_IDX_CERTREQ
};
/* Number of items in ASN.1 template for TimeStampReq. */
#define tspReqASN_Length (sizeof(tspReqASN) / sizeof(ASNItem))

/* Check a number is encodable as given - no leading zero byte.
 *
 * The number is encoded as the content of an INTEGER - the encoder prepends
 * a zero byte to keep the number positive when needed. A number with a
 * leading zero byte would not round trip: the decoder returns the minimal
 * form and comparisons against it are exact.
 *
 * Zero is one zero byte - other leading zero bytes are redundant.
 *
 * @param [in] data  Big-endian number to check.
 * @param [in] sz    Length of number in bytes.
 * @return  0 when the number is encodable.
 * @return  BAD_FUNC_ARG when the number is empty or has a leading zero byte.
 */
#define TspCheckNum(data, sz)                                       \
    ((((sz) == 0) || (((sz) > 1) && ((data)[0] == 0x00))) ?         \
        BAD_FUNC_ARG : 0)

#ifdef WOLFSSL_TSP_REQUESTER
/* Encode a TimeStampReq.
 *
 * @param [in]      req    TimeStampReq object to encode.
 * @param [out]     out    Buffer to hold encoding. May be NULL to get length.
 * @param [in, out] outSz  On in, length of buffer in bytes.
 *                         On out, length of encoding in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when req or outSz is NULL, the message imprint hash
 *          is not set, a field is too long for its array or the nonce has a
 *          leading zero byte.
 * @return  BUFFER_E when out is not NULL and encoding is longer than outSz.
 * @return  ASN_UNKNOWN_OID_E when the hash algorithm is not recognized.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
int wc_TspRequest_Encode(const TspRequest* req, byte* out, word32* outSz)
{
    DECL_ASNSETDATA(dataASN, tspReqASN_Length);
    int ret = 0;
    word32 sz = 0;

    WOLFSSL_ENTER("wc_TspRequest_Encode");

    /* Validate parameters. */
    if ((req == NULL) || (outSz == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* The message imprint is the only required field. */
    if ((ret == 0) && ((req->imprint.hashSz == 0) ||
            (req->imprint.hashSz > sizeof(req->imprint.hash)))) {
        ret = BAD_FUNC_ARG;
    }
    /* Policy, when set, must fit. */
    if ((ret == 0) && (req->policySz > sizeof(req->policy))) {
        ret = BAD_FUNC_ARG;
    }
    /* Nonce, when set, must fit and be encodable as given. */
    if ((ret == 0) && (req->nonceSz != 0)) {
        if (req->nonceSz > sizeof(req->nonce)) {
            ret = BAD_FUNC_ARG;
        }
        else {
            ret = TspCheckNum(req->nonce, req->nonceSz);
        }
    }

    CALLOC_ASNSETDATA(dataASN, tspReqASN_Length, ret, NULL);

    if (ret == 0) {
        /* Version is 1 - only version defined. */
        SetASN_Int8Bit(&dataASN[TSPREQASN_IDX_VER], WC_TSP_VERSION);
        /* messageImprint - hash algorithm with NULL parameters and hash. */
        SetASN_OID(&dataASN[TSPREQASN_IDX_MI_ALG_OID],
            (int)req->imprint.hashAlgOID, oidHashType);
        /* No encoding available for an unknown OID sum. */
        if (dataASN[TSPREQASN_IDX_MI_ALG_OID].data.buffer.data == NULL) {
            ret = ASN_UNKNOWN_OID_E;
        }
    }
    if (ret == 0) {
        /* Hash of the data to be time-stamped. */
        SetASN_Buffer(&dataASN[TSPREQASN_IDX_MI_MSG], req->imprint.hash,
            req->imprint.hashSz);
        /* reqPolicy is optional. */
        if (req->policySz != 0) {
            SetASN_Buffer(&dataASN[TSPREQASN_IDX_POLICY], req->policy,
                req->policySz);
        }
        else {
            SetASNItem_NoOutNode_ex(dataASN, tspReqASN, 0,
                TSPREQASN_IDX_POLICY, tspReqASN_Length);
        }
        /* nonce is optional. */
        if (req->nonceSz != 0) {
            SetASN_Buffer(&dataASN[TSPREQASN_IDX_NONCE], req->nonce,
                req->nonceSz);
        }
        else {
            SetASNItem_NoOutNode_ex(dataASN, tspReqASN, 0,
                TSPREQASN_IDX_NONCE, tspReqASN_Length);
        }
        /* certReq defaults to FALSE - only encode when TRUE. */
        if (req->certReq) {
            SetASN_Boolean(&dataASN[TSPREQASN_IDX_CERTREQ], 1);
        }
        else {
            SetASNItem_NoOutNode_ex(dataASN, tspReqASN, 0,
                TSPREQASN_IDX_CERTREQ, tspReqASN_Length);
        }
        /* Calculate size of encoding. */
        ret = SizeASN_Items(tspReqASN, dataASN, tspReqASN_Length, &sz);
    }
    /* Write out encoding when buffer supplied. */
    if ((ret == 0) && (out != NULL)) {
        /* Check buffer is big enough to hold encoding. */
        if (sz > *outSz) {
            ret = BUFFER_E;
        }
        /* Length written must be the length calculated. */
        else if (SetASN_Items(tspReqASN, dataASN, tspReqASN_Length, out) !=
                (int)sz) {
            ret = ASN_PARSE_E;
        }
    }
    if (ret == 0) {
        /* Return the length of the encoding. */
        *outSz = sz;
    }

    FREE_ASNSETDATA(dataASN, NULL);
    WOLFSSL_LEAVE("wc_TspRequest_Encode", ret);
    return ret;
}

#endif /* WOLFSSL_TSP_REQUESTER */
/* Decode a TimeStampReq.
 *
 * All fields are copied - input is not referenced after return.
 *
 * @param [out] req    TimeStampReq object to fill.
 * @param [in]  input  Buffer holding DER encoding.
 * @param [in]  inSz   Length of data in buffer in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when req or input is NULL or inSz is 0.
 * @return  ASN_PARSE_E when the encoding is invalid, the hash is empty or
 *          extensions are present.
 * @return  ASN_VERSION_E when the version is not supported.
 * @return  ASN_UNKNOWN_OID_E when the hash algorithm OID check fails.
 * @return  BUFFER_E when the hash is longer than WC_TSP_MAX_HASH_SZ bytes,
 *          the policy is longer than MAX_OID_SZ bytes or the nonce is
 *          longer than MAX_TS_NONCE_SZ bytes.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
int wc_TspRequest_Decode(TspRequest* req, const byte* input, word32 inSz)
{
    DECL_ASNGETDATA(dataASN, tspReqASN_Length);
    int ret = 0;
    word32 idx = 0;

    WOLFSSL_ENTER("wc_TspRequest_Decode");

    /* Validate parameters. */
    if ((req == NULL) || (input == NULL) || (inSz == 0)) {
        ret = BAD_FUNC_ARG;
    }

    CALLOC_ASNGETDATA(dataASN, tspReqASN_Length, ret, NULL);

    if (ret == 0) {
        /* All fields empty - optional fields left empty when not present. */
        XMEMSET(req, 0, sizeof(TspRequest));

        /* Version is small - 1 is the only defined value. */
        GetASN_Int8Bit(&dataASN[TSPREQASN_IDX_VER], &req->version);
        /* Any policy accepted - copied into fixed size array. Caller
         * checks it is one it supports. */
        req->policySz = (word32)sizeof(req->policy);
        GetASN_Buffer(&dataASN[TSPREQASN_IDX_POLICY], req->policy,
            &req->policySz);
        /* Hash algorithm OID checked against known hash OIDs - caller
         * checks it is usable. */
        GetASN_OID(&dataASN[TSPREQASN_IDX_MI_ALG_OID], oidHashType);
        /* Hash copied into fixed size array - length checked. */
        req->imprint.hashSz = (word32)sizeof(req->imprint.hash);
        GetASN_Buffer(&dataASN[TSPREQASN_IDX_MI_MSG], req->imprint.hash,
            &req->imprint.hashSz);
        /* Nonce copied into fixed size array - length checked. */
        req->nonceSz = (word32)sizeof(req->nonce);
        GetASN_Buffer(&dataASN[TSPREQASN_IDX_NONCE], req->nonce,
            &req->nonceSz);
        /* certReq defaults to FALSE when not present. */
        GetASN_Boolean(&dataASN[TSPREQASN_IDX_CERTREQ], &req->certReq);
        /* Decode TimeStampReq. */
        ret = GetASN_Items(tspReqASN, dataASN, tspReqASN_Length, 1, input,
            &idx, inSz);
    }
    /* Check all data used - input is one complete message. */
    if ((ret == 0) && (idx != inSz)) {
        ret = ASN_PARSE_E;
    }
    /* Only version 1 defined - RFC 3161, 2.4.1. */
    if ((ret == 0) && (req->version != WC_TSP_VERSION)) {
        ret = ASN_VERSION_E;
    }
    /* Hash must not be empty. */
    if ((ret == 0) && (req->imprint.hashSz == 0)) {
        ret = ASN_PARSE_E;
    }
    if (ret == 0) {
        /* messageImprint hash algorithm - hash already copied. */
        req->imprint.hashAlgOID =
            dataASN[TSPREQASN_IDX_MI_ALG_OID].data.oid.sum;
        /* Optional fields already copied - length set to zero when not
         * present. */
        if (dataASN[TSPREQASN_IDX_POLICY].tag == 0) {
            req->policySz = 0;
        }
        if (dataASN[TSPREQASN_IDX_NONCE].tag == 0) {
            req->nonceSz = 0;
        }
    }

    FREE_ASNGETDATA(dataASN, NULL);
    WOLFSSL_LEAVE("wc_TspRequest_Decode", ret);
    return ret;
}


/* Check a genTime is a valid GeneralizedTime of RFC 3161.
 *
 * RFC 3161, 2.4.2: "YYYYMMDDhhmmss[.s...]Z" - the seconds are always
 * represented, the fraction of seconds has no trailing zeros and is not
 * empty, and the time is Zulu with nothing following.
 *
 * The date and time fields are range-checked so the values are usable as a
 * calendar time (e.g. a month outside 1..12 would index out of bounds when
 * converting to a time_t).
 *
 * @param [in] t   genTime string.
 * @param [in] sz  Length of string in bytes.
 * @return  0 when the string is valid.
 * @return  ASN_PARSE_E when the string is not valid.
 */
WOLFSSL_LOCAL int TspCheckGenTimeSyntax(const byte* t, word32 sz)
{
    int ret = 0;
    word32 i = 0;

    /* Shortest form: "YYYYMMDDhhmmssZ". */
    if (sz < 15) {
        ret = ASN_PARSE_E;
    }
    /* Date and time are digits. */
    for (i = 0; (ret == 0) && (i < 14); i++) {
        if ((t[i] < '0') || (t[i] > '9')) {
            ret = ASN_PARSE_E;
        }
    }
    /* Date and time fields must be in range. The month in particular is used
     * to index a table when converting to a time_t, so an out-of-range value
     * must not be accepted. */
    if (ret == 0) {
        int mon  = (t[4]  - '0') * 10 + (t[5]  - '0');
        int day  = (t[6]  - '0') * 10 + (t[7]  - '0');
        int hour = (t[8]  - '0') * 10 + (t[9]  - '0');
        int min  = (t[10] - '0') * 10 + (t[11] - '0');
        int sec  = (t[12] - '0') * 10 + (t[13] - '0');
        if ((mon < 1) || (mon > 12) || (day < 1) || (day > 31) ||
                (hour > 23) || (min > 59) || (sec > 60)) {
            ret = ASN_PARSE_E;
        }
    }
    /* Optional fraction of seconds. */
    if ((ret == 0) && (t[i] == '.')) {
        /* Step over the digits of the fraction. */
        for (i++; (i < sz - 1) && (t[i] >= '0') && (t[i] <= '9'); i++);
        /* At least one digit and no trailing zero. RFC 3161, 2.4.2. */
        if ((i == 15) || (t[i - 1] == '0')) {
            ret = ASN_PARSE_E;
        }
    }
    /* Must be Zulu time and nothing after. */
    if ((ret == 0) && ((i != sz - 1) || (t[i] != 'Z'))) {
        ret = ASN_PARSE_E;
    }

    return ret;
}

/* ASN template for TSTInfo.
 * RFC 3161, 2.4.2 - Response Format
 *
 * Extensions are not supported - decoding a message with an extensions
 * element fails as it matches no item.
 */
static const ASNItem tspTstInfoASN[] = {
/* SEQ         */ { 0, ASN_SEQUENCE, 1, 1, 0 },
                                              /* version */
/* VER         */     { 1, ASN_INTEGER, 0, 0, 0 },
                                              /* policy */
/* POLICY      */     { 1, ASN_OBJECT_ID, 0, 0, 0 },
                                              /* messageImprint */
/* MI_SEQ      */     { 1, ASN_SEQUENCE, 1, 1, 0 },
                                              /* hashAlgorithm */
/* MI_ALG_SEQ  */         { 2, ASN_SEQUENCE, 1, 1, 0 },
/* MI_ALG_OID  */             { 3, ASN_OBJECT_ID, 0, 0, 0 },
/* MI_ALG_NULL */             { 3, ASN_TAG_NULL, 0, 0, 1 },
                                              /* hashedMessage */
/* MI_MSG      */         { 2, ASN_OCTET_STRING, 0, 0, 0 },
                                              /* serialNumber */
/* SERIAL      */     { 1, ASN_INTEGER, 0, 0, 0 },
                                              /* genTime */
/* GENTIME     */     { 1, ASN_GENERALIZED_TIME, 0, 0, 0 },
                                              /* accuracy */
/* ACC_SEQ     */     { 1, ASN_SEQUENCE, 1, 1, 1 },
                                              /* seconds */
/* ACC_SEC     */         { 2, ASN_INTEGER, 0, 0, 1 },
                                              /* millis */
/* ACC_MILLIS  */         { 2, ASN_CONTEXT_SPECIFIC | 0, 0, 0, 1 },
                                              /* micros */
/* ACC_MICROS  */         { 2, ASN_CONTEXT_SPECIFIC | 1, 0, 0, 1 },
                                              /* ordering */
/* ORDERING    */     { 1, ASN_BOOLEAN, 0, 0, 1 },
                                              /* nonce */
/* NONCE       */     { 1, ASN_INTEGER, 0, 0, 1 },
                                              /* tsa */
/* TSA         */     { 1, ASN_CONTEXT_SPECIFIC | 0, 1, 0, 1 },
};
/* Named indices for tspTstInfoASN. */
enum {
    TSPTSTINFOASN_IDX_SEQ = 0,
    TSPTSTINFOASN_IDX_VER,
    TSPTSTINFOASN_IDX_POLICY,
    TSPTSTINFOASN_IDX_MI_SEQ,
    TSPTSTINFOASN_IDX_MI_ALG_SEQ,
    TSPTSTINFOASN_IDX_MI_ALG_OID,
    TSPTSTINFOASN_IDX_MI_ALG_NULL,
    TSPTSTINFOASN_IDX_MI_MSG,
    TSPTSTINFOASN_IDX_SERIAL,
    TSPTSTINFOASN_IDX_GENTIME,
    TSPTSTINFOASN_IDX_ACC_SEQ,
    TSPTSTINFOASN_IDX_ACC_SEC,
    TSPTSTINFOASN_IDX_ACC_MILLIS,
    TSPTSTINFOASN_IDX_ACC_MICROS,
    TSPTSTINFOASN_IDX_ORDERING,
    TSPTSTINFOASN_IDX_NONCE,
    TSPTSTINFOASN_IDX_TSA
};
/* Number of items in ASN.1 template for TSTInfo. */
#define tspTstInfoASN_Length (sizeof(tspTstInfoASN) / sizeof(ASNItem))

#ifdef WOLFSSL_TSP_RESPONDER
/* Encode a TSTInfo.
 *
 * When genTime is NULL, the current time is used. Not available when there
 * is no real time clock - NO_ASN_TIME, USER_TIME or TIME_OVERRIDES.
 *
 * @param [in]      tstInfo  TSTInfo object to encode.
 * @param [out]     out      Buffer to hold encoding. May be NULL to get
 *                           length.
 * @param [in, out] outSz    On in, length of buffer in bytes.
 *                           On out, length of encoding in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when tstInfo or outSz is NULL, a required field of
 *          tstInfo is not set or empty, the hash is too long, the genTime
 *          is not a valid GeneralizedTime, the tsa is empty, the serial
 *          number or nonce is empty or has a leading zero byte or accuracy
 *          millis or micros is out of range.
 * @return  BUFFER_E when out is not NULL and encoding is longer than outSz.
 * @return  ASN_UNKNOWN_OID_E when the hash algorithm is not recognized.
 * @return  ASN_TIME_E when getting the current time failed.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
int wc_TspTstInfo_Encode(const TspTstInfo* tstInfo, byte* out, word32* outSz)
{
    DECL_ASNSETDATA(dataASN, tspTstInfoASN_Length);
    int ret = 0;
    word32 sz = 0;
#if !defined(NO_ASN_TIME) && !defined(USER_TIME) && !defined(TIME_OVERRIDES)
    byte timeBuf[ASN_GENERALIZED_TIME_SIZE];
#endif

    WOLFSSL_ENTER("wc_TspTstInfo_Encode");

    /* Validate parameters. */
    if ((tstInfo == NULL) || (outSz == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Policy, message imprint and serial number are required fields. */
    if ((ret == 0) && ((tstInfo->policy == NULL) ||
            (tstInfo->policySz == 0) ||
            (tstInfo->imprint.hashSz == 0) ||
            (tstInfo->imprint.hashSz > sizeof(tstInfo->imprint.hash)) ||
            (tstInfo->serial == NULL))) {
        ret = BAD_FUNC_ARG;
    }
    /* genTime, when set, must be a valid GeneralizedTime of RFC 3161. */
    if ((ret == 0) && (tstInfo->genTime != NULL) &&
            (TspCheckGenTimeSyntax(tstInfo->genTime, tstInfo->genTimeSz)
                != 0)) {
        ret = BAD_FUNC_ARG;
    }
    /* TSA name, when set, must not be empty. */
    if ((ret == 0) && (tstInfo->tsa != NULL) && (tstInfo->tsaSz == 0)) {
        ret = BAD_FUNC_ARG;
    }
    /* Serial number must be encodable as given. */
    if (ret == 0) {
        ret = TspCheckNum(tstInfo->serial, tstInfo->serialSz);
    }
    /* Nonce, when set, must be encodable as given. */
    if ((ret == 0) && (tstInfo->nonce != NULL)) {
        ret = TspCheckNum(tstInfo->nonce, tstInfo->nonceSz);
    }
    /* Accuracy millis and micros must be 1..999 when set. */
    if ((ret == 0) && ((tstInfo->accuracy.millis > 999) ||
            (tstInfo->accuracy.micros > 999))) {
        ret = BAD_FUNC_ARG;
    }

    CALLOC_ASNSETDATA(dataASN, tspTstInfoASN_Length, ret, NULL);

    if (ret == 0) {
        /* Version is 1 - only version defined. */
        SetASN_Int8Bit(&dataASN[TSPTSTINFOASN_IDX_VER], WC_TSP_VERSION);
        /* TSA policy. */
        SetASN_Buffer(&dataASN[TSPTSTINFOASN_IDX_POLICY], tstInfo->policy,
            tstInfo->policySz);
        /* messageImprint - hash algorithm with NULL parameters and hash. */
        SetASN_OID(&dataASN[TSPTSTINFOASN_IDX_MI_ALG_OID],
            (int)tstInfo->imprint.hashAlgOID, oidHashType);
        /* No encoding available for an unknown OID sum. */
        if (dataASN[TSPTSTINFOASN_IDX_MI_ALG_OID].data.buffer.data == NULL) {
            ret = ASN_UNKNOWN_OID_E;
        }
    }
    if (ret == 0) {
        /* Hash of the data time-stamped. */
        SetASN_Buffer(&dataASN[TSPTSTINFOASN_IDX_MI_MSG],
            tstInfo->imprint.hash, tstInfo->imprint.hashSz);
        /* serialNumber. */
        SetASN_Buffer(&dataASN[TSPTSTINFOASN_IDX_SERIAL], tstInfo->serial,
            tstInfo->serialSz);
        /* genTime - use current time when not provided. */
        if (tstInfo->genTime != NULL) {
            SetASN_Buffer(&dataASN[TSPTSTINFOASN_IDX_GENTIME],
                tstInfo->genTime, tstInfo->genTimeSz);
        }
        else {
        #if !defined(NO_ASN_TIME) && !defined(USER_TIME) && \
            !defined(TIME_OVERRIDES)
            /* Format the current time as a GeneralizedTime string. */
            time_t now = wc_Time(0);
            int len = GetFormattedTime_ex(&now, timeBuf, sizeof(timeBuf),
                ASN_GENERALIZED_TIME);
            if (len <= 0) {
                ret = ASN_TIME_E;
            }
            else {
                SetASN_Buffer(&dataASN[TSPTSTINFOASN_IDX_GENTIME], timeBuf,
                    (word32)len);
            }
        #else
            /* No clock available - caller must provide the time. */
            ret = BAD_FUNC_ARG;
        #endif
        }
    }
    if (ret == 0) {
        /* accuracy is optional - not encoded when all fields are zero. */
        if ((tstInfo->accuracy.seconds == 0) &&
                (tstInfo->accuracy.millis == 0) &&
                (tstInfo->accuracy.micros == 0)) {
            SetASNItem_NoOutNode(dataASN, tspTstInfoASN,
                TSPTSTINFOASN_IDX_ACC_SEQ, tspTstInfoASN_Length);
        }
        else {
            /* Each field is optional - not encoded when zero. */
            /* INTEGER - leading zero added by encoder when needed. */
            if (tstInfo->accuracy.seconds != 0) {
                SetASN_Int32Bit(&dataASN[TSPTSTINFOASN_IDX_ACC_SEC],
                    tstInfo->accuracy.seconds);
            }
            else {
                SetASNItem_NoOutNode_ex(dataASN, tspTstInfoASN, 0,
                    TSPTSTINFOASN_IDX_ACC_SEC, tspTstInfoASN_Length);
            }
            /* Implicitly tagged INTEGERs. */
            if (tstInfo->accuracy.millis != 0) {
                SetASN_Int32BitInt(&dataASN[TSPTSTINFOASN_IDX_ACC_MILLIS],
                    tstInfo->accuracy.millis);
            }
            else {
                SetASNItem_NoOutNode_ex(dataASN, tspTstInfoASN, 0,
                    TSPTSTINFOASN_IDX_ACC_MILLIS, tspTstInfoASN_Length);
            }
            if (tstInfo->accuracy.micros != 0) {
                SetASN_Int32BitInt(&dataASN[TSPTSTINFOASN_IDX_ACC_MICROS],
                    tstInfo->accuracy.micros);
            }
            else {
                SetASNItem_NoOutNode_ex(dataASN, tspTstInfoASN, 0,
                    TSPTSTINFOASN_IDX_ACC_MICROS, tspTstInfoASN_Length);
            }
        }
        /* ordering defaults to FALSE - only encode when TRUE. */
        if (tstInfo->ordering) {
            SetASN_Boolean(&dataASN[TSPTSTINFOASN_IDX_ORDERING], 1);
        }
        else {
            SetASNItem_NoOutNode_ex(dataASN, tspTstInfoASN, 0,
                TSPTSTINFOASN_IDX_ORDERING, tspTstInfoASN_Length);
        }
        /* nonce is optional. */
        if (tstInfo->nonce != NULL) {
            SetASN_Buffer(&dataASN[TSPTSTINFOASN_IDX_NONCE], tstInfo->nonce,
                tstInfo->nonceSz);
        }
        else {
            SetASNItem_NoOutNode_ex(dataASN, tspTstInfoASN, 0,
                TSPTSTINFOASN_IDX_NONCE, tspTstInfoASN_Length);
        }
        /* tsa is optional. */
        if (tstInfo->tsa != NULL) {
            SetASN_Buffer(&dataASN[TSPTSTINFOASN_IDX_TSA], tstInfo->tsa,
                tstInfo->tsaSz);
        }
        else {
            SetASNItem_NoOutNode_ex(dataASN, tspTstInfoASN, 0,
                TSPTSTINFOASN_IDX_TSA, tspTstInfoASN_Length);
        }
        /* Calculate size of encoding. */
        ret = SizeASN_Items(tspTstInfoASN, dataASN, tspTstInfoASN_Length,
            &sz);
    }
    /* Write out encoding when buffer supplied. */
    if ((ret == 0) && (out != NULL)) {
        /* Check buffer is big enough to hold encoding. */
        if (sz > *outSz) {
            ret = BUFFER_E;
        }
        /* Length written must be the length calculated. */
        else if (SetASN_Items(tspTstInfoASN, dataASN, tspTstInfoASN_Length,
                out) != (int)sz) {
            ret = ASN_PARSE_E;
        }
    }
    if (ret == 0) {
        /* Return the length of the encoding. */
        *outSz = sz;
    }

    FREE_ASNSETDATA(dataASN, NULL);
    WOLFSSL_LEAVE("wc_TspTstInfo_Encode", ret);
    return ret;
}

#endif /* WOLFSSL_TSP_RESPONDER */

#ifdef WOLFSSL_TSP_VERIFIER
/* Decode a TSTInfo.
 *
 * Pointers in tstInfo reference into input - the buffer must remain
 * available while tstInfo is in use. The message imprint hash is copied.
 *
 * @param [out] tstInfo  TSTInfo object to fill.
 * @param [in]  input    Buffer holding DER encoding.
 * @param [in]  inSz     Length of data in buffer in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when tstInfo or input is NULL or inSz is 0.
 * @return  ASN_PARSE_E when the encoding is invalid, the hash is empty,
 *          accuracy millis or micros is out of range, the genTime is not a
 *          valid GeneralizedTime or extensions are present.
 * @return  ASN_UNKNOWN_OID_E when the hash algorithm OID check fails.
 * @return  BUFFER_E when the hash is longer than WC_TSP_MAX_HASH_SZ bytes.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
int wc_TspTstInfo_Decode(TspTstInfo* tstInfo, const byte* input, word32 inSz)
{
    DECL_ASNGETDATA(dataASN, tspTstInfoASN_Length);
    int ret = 0;
    word32 idx = 0;

    WOLFSSL_ENTER("wc_TspTstInfo_Decode");

    /* Validate parameters. */
    if ((tstInfo == NULL) || (input == NULL) || (inSz == 0)) {
        ret = BAD_FUNC_ARG;
    }

    CALLOC_ASNGETDATA(dataASN, tspTstInfoASN_Length, ret, NULL);

    if (ret == 0) {
        /* All fields empty - optional fields left empty when not present. */
        XMEMSET(tstInfo, 0, sizeof(TspTstInfo));

        /* Version is small - 1 is the only defined value. */
        GetASN_Int8Bit(&dataASN[TSPTSTINFOASN_IDX_VER], &tstInfo->version);
        /* Any policy accepted - caller checks it is the one expected. */
        GetASN_OID(&dataASN[TSPTSTINFOASN_IDX_POLICY], oidIgnoreType);
        /* Hash algorithm OID checked against known hash OIDs - caller
         * checks it is usable. */
        GetASN_OID(&dataASN[TSPTSTINFOASN_IDX_MI_ALG_OID], oidHashType);
        /* Hash copied into fixed size array - length checked. */
        tstInfo->imprint.hashSz = (word32)sizeof(tstInfo->imprint.hash);
        GetASN_Buffer(&dataASN[TSPTSTINFOASN_IDX_MI_MSG],
            tstInfo->imprint.hash, &tstInfo->imprint.hashSz);
        /* Accuracy fields default to zero when not present. Millis and
         * micros are limited to 1..999 - 16 bits enough. */
        GetASN_Int32Bit(&dataASN[TSPTSTINFOASN_IDX_ACC_SEC],
            &tstInfo->accuracy.seconds);
        GetASN_Int16Bit(&dataASN[TSPTSTINFOASN_IDX_ACC_MILLIS],
            &tstInfo->accuracy.millis);
        GetASN_Int16Bit(&dataASN[TSPTSTINFOASN_IDX_ACC_MICROS],
            &tstInfo->accuracy.micros);
        /* ordering defaults to FALSE when not present. */
        GetASN_Boolean(&dataASN[TSPTSTINFOASN_IDX_ORDERING],
            &tstInfo->ordering);
        /* Decode TSTInfo. */
        ret = GetASN_Items(tspTstInfoASN, dataASN, tspTstInfoASN_Length, 1,
            input, &idx, inSz);
    }
    /* Check all data used - input is one complete message. */
    if ((ret == 0) && (idx != inSz)) {
        ret = ASN_PARSE_E;
    }
    /* Hash must not be empty. */
    if ((ret == 0) && (tstInfo->imprint.hashSz == 0)) {
        ret = ASN_PARSE_E;
    }
    /* Accuracy millis and micros, when present, must be 1..999. */
    if ((ret == 0) &&
            (((dataASN[TSPTSTINFOASN_IDX_ACC_MILLIS].tag != 0) &&
              ((tstInfo->accuracy.millis == 0) ||
               (tstInfo->accuracy.millis > 999))) ||
             ((dataASN[TSPTSTINFOASN_IDX_ACC_MICROS].tag != 0) &&
              ((tstInfo->accuracy.micros == 0) ||
               (tstInfo->accuracy.micros > 999))))) {
        ret = ASN_PARSE_E;
    }
    if (ret == 0) {
        /* TSA policy referenced. */
        GetASN_OIDData(&dataASN[TSPTSTINFOASN_IDX_POLICY], &tstInfo->policy,
            &tstInfo->policySz);
        /* messageImprint hash algorithm - hash already copied. */
        tstInfo->imprint.hashAlgOID =
            dataASN[TSPTSTINFOASN_IDX_MI_ALG_OID].data.oid.sum;
        /* Serial number and time string referenced. */
        GetASN_GetConstRef(&dataASN[TSPTSTINFOASN_IDX_SERIAL],
            &tstInfo->serial, &tstInfo->serialSz);
        GetASN_GetConstRef(&dataASN[TSPTSTINFOASN_IDX_GENTIME],
            &tstInfo->genTime, &tstInfo->genTimeSz);
        /* genTime must be a valid GeneralizedTime of RFC 3161. */
        ret = TspCheckGenTimeSyntax(tstInfo->genTime, tstInfo->genTimeSz);
    }
    if (ret == 0) {
        /* Optional fields - pointer left NULL when not present. */
        if (GetASNItem_HaveIdx(dataASN[TSPTSTINFOASN_IDX_NONCE])) {
            GetASN_GetConstRef(&dataASN[TSPTSTINFOASN_IDX_NONCE],
                &tstInfo->nonce, &tstInfo->nonceSz);
        }
        if (GetASNItem_HaveIdx(dataASN[TSPTSTINFOASN_IDX_TSA])) {
            GetASN_GetConstRef(&dataASN[TSPTSTINFOASN_IDX_TSA], &tstInfo->tsa,
                &tstInfo->tsaSz);
        }
    }

    FREE_ASNGETDATA(dataASN, NULL);
    WOLFSSL_LEAVE("wc_TspTstInfo_Decode", ret);
    return ret;
}

/* ASN template for decoding TimeStampResp.
 * RFC 3161, 2.4.2 - Response Format
 *
 * PKIFreeText is a SEQUENCE OF UTF8String - not parsed by template.
 */
static const ASNItem tspRespASN[] = {
/* SEQ         */ { 0, ASN_SEQUENCE, 1, 1, 0 },
                                              /* status */
/* STAT_SEQ    */     { 1, ASN_SEQUENCE, 1, 1, 0 },
                                              /* status */
/* STAT        */         { 2, ASN_INTEGER, 0, 0, 0 },
                                              /* statusString */
/* STAT_STR    */         { 2, ASN_SEQUENCE, 1, 0, 1 },
                                              /* failInfo */
/* STAT_FAIL   */         { 2, ASN_BIT_STRING, 0, 0, 1 },
                                              /* timeStampToken */
/* TOKEN       */     { 1, ASN_SEQUENCE, 1, 0, 1 },
};
/* Named indices for tspRespASN. */
enum {
    TSPRESPASN_IDX_SEQ = 0,
    TSPRESPASN_IDX_STAT_SEQ,
    TSPRESPASN_IDX_STAT,
    TSPRESPASN_IDX_STAT_STR,
    TSPRESPASN_IDX_STAT_FAIL,
    TSPRESPASN_IDX_TOKEN
};
/* Number of items in ASN.1 template for decoding TimeStampResp. */
#define tspRespASN_Length (sizeof(tspRespASN) / sizeof(ASNItem))

/* ASN template for encoding TimeStampResp.
 * RFC 3161, 2.4.2 - Response Format
 *
 * statusString is encoded as a PKIFreeText with one UTF8String.
 */
#endif /* WOLFSSL_TSP_VERIFIER */

#ifdef WOLFSSL_TSP_RESPONDER
static const ASNItem tspRespEncASN[] = {
/* SEQ         */ { 0, ASN_SEQUENCE, 1, 1, 0 },
                                              /* status */
/* STAT_SEQ    */     { 1, ASN_SEQUENCE, 1, 1, 0 },
                                              /* status */
/* STAT        */         { 2, ASN_INTEGER, 0, 0, 0 },
                                              /* statusString */
/* STAT_STR_SEQ */        { 2, ASN_SEQUENCE, 1, 1, 1 },
/* STAT_STR    */             { 3, ASN_UTF8STRING, 0, 0, 0 },
                                              /* failInfo */
/* STAT_FAIL   */         { 2, ASN_BIT_STRING, 0, 0, 1 },
                                              /* timeStampToken */
/* TOKEN       */     { 1, ASN_SEQUENCE, 1, 0, 1 },
};
/* Named indices for tspRespEncASN. */
enum {
    TSPRESPENCASN_IDX_SEQ = 0,
    TSPRESPENCASN_IDX_STAT_SEQ,
    TSPRESPENCASN_IDX_STAT,
    TSPRESPENCASN_IDX_STAT_STR_SEQ,
    TSPRESPENCASN_IDX_STAT_STR,
    TSPRESPENCASN_IDX_STAT_FAIL,
    TSPRESPENCASN_IDX_TOKEN
};
/* Number of items in ASN.1 template for encoding TimeStampResp. */
#define tspRespEncASN_Length (sizeof(tspRespEncASN) / sizeof(ASNItem))

/* ASN template for a UTF8String of a PKIFreeText.
 * RFC 3161, 2.4.2.
 */
#endif /* WOLFSSL_TSP_RESPONDER */

#ifdef WOLFSSL_TSP_VERIFIER
static const ASNItem tspUtf8StrASN[] = {
/* STR */ { 0, ASN_UTF8STRING, 0, 0, 0 },
};
/* Number of items in ASN.1 template for a UTF8String of a PKIFreeText. */
#define tspUtf8StrASN_Length (sizeof(tspUtf8StrASN) / sizeof(ASNItem))

/* Get a reference to the first UTF8String in a PKIFreeText.
 *
 * @param [in]  input  Content of PKIFreeText SEQUENCE.
 * @param [in]  inSz   Length of content in bytes.
 * @param [out] str    First UTF8String's data.
 * @param [out] strSz  Length of first UTF8String's data in bytes.
 * @return  0 on success.
 * @return  ASN_PARSE_E when the encoding is invalid.
 */
static int TspGetPkiFreeTextStr(const byte* input, word32 inSz,
    const byte** str, word32* strSz)
{
    /* Template is small enough to declare data on the stack. */
    ASNGetData dataASN[tspUtf8StrASN_Length];
    int ret;
    word32 idx = 0;

    XMEMSET(dataASN, 0, sizeof(dataASN));

    /* Decode first UTF8String - any others are ignored. */
    ret = GetASN_Items(tspUtf8StrASN, dataASN, tspUtf8StrASN_Length, 0,
        input, &idx, inSz);
    if (ret == 0) {
        /* Reference the string's data for the caller. */
        GetASN_GetConstRef(&dataASN[0], str, strSz);
    }

    return ret;
}

#endif /* WOLFSSL_TSP_VERIFIER */

#ifdef WOLFSSL_TSP_RESPONDER
/* Encode a TimeStampResp.
 *
 * @param [in]      resp   TimeStampResp object to encode.
 * @param [out]     out    Buffer to hold encoding. May be NULL to get length.
 * @param [in, out] outSz  On in, length of buffer in bytes.
 *                         On out, length of encoding in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when resp or outSz is NULL.
 * @return  BUFFER_E when out is not NULL and encoding is longer than outSz.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
int wc_TspResponse_Encode(const TspResponse* resp, byte* out, word32* outSz)
{
    DECL_ASNSETDATA(dataASN, tspRespEncASN_Length);
    int ret = 0;
    word32 sz = 0;

    WOLFSSL_ENTER("wc_TspResponse_Encode");

    /* Validate parameters. */
    if ((resp == NULL) || (outSz == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    CALLOC_ASNSETDATA(dataASN, tspRespEncASN_Length, ret, NULL);

    if (ret == 0) {
        /* status. */
        SetASN_Int8Bit(&dataASN[TSPRESPENCASN_IDX_STAT], resp->status);
        /* statusString is optional - encoded as a PKIFreeText with one
         * UTF8String. */
        if (resp->statusString != NULL) {
            SetASN_Buffer(&dataASN[TSPRESPENCASN_IDX_STAT_STR],
                resp->statusString, resp->statusStringSz);
        }
        else {
            SetASNItem_NoOutNode(dataASN, tspRespEncASN,
                TSPRESPENCASN_IDX_STAT_STR_SEQ, tspRespEncASN_Length);
        }
        /* failInfo is optional - BIT STRING from the 32-bit flags word. */
        if (resp->failInfo != 0) {
            SetASN_Int32Bit(&dataASN[TSPRESPENCASN_IDX_STAT_FAIL],
                resp->failInfo);
        }
        else {
            SetASNItem_NoOutNode_ex(dataASN, tspRespEncASN, 0,
                TSPRESPENCASN_IDX_STAT_FAIL, tspRespEncASN_Length);
        }
        /* timeStampToken is optional - complete DER encoding. */
        if (resp->token != NULL) {
            SetASN_ReplaceBuffer(&dataASN[TSPRESPENCASN_IDX_TOKEN],
                resp->token, resp->tokenSz);
        }
        else {
            SetASNItem_NoOutNode_ex(dataASN, tspRespEncASN, 0,
                TSPRESPENCASN_IDX_TOKEN, tspRespEncASN_Length);
        }

        /* Calculate size of encoding. */
        ret = SizeASN_Items(tspRespEncASN, dataASN, tspRespEncASN_Length,
            &sz);
    }
    /* Write out encoding when buffer supplied. */
    if ((ret == 0) && (out != NULL)) {
        /* Check buffer is big enough to hold encoding. */
        if (sz > *outSz) {
            ret = BUFFER_E;
        }
        /* Length written must be the length calculated. */
        else if (SetASN_Items(tspRespEncASN, dataASN, tspRespEncASN_Length,
                out) != (int)sz) {
            ret = ASN_PARSE_E;
        }
    }
    if (ret == 0) {
        /* Return the length of the encoding. */
        *outSz = sz;
    }

    FREE_ASNSETDATA(dataASN, NULL);
    WOLFSSL_LEAVE("wc_TspResponse_Encode", ret);
    return ret;
}

#endif /* WOLFSSL_TSP_RESPONDER */

#ifdef WOLFSSL_TSP_VERIFIER
/* Decode a TimeStampResp.
 *
 * Pointers in resp reference into input - the buffer must remain available
 * while resp is in use.
 *
 * The TSTInfo of the timeStampToken is not validated or decoded - see
 * wc_TspTstInfo_VerifyWithPKCS7() and wc_TspTstInfo_Decode().
 *
 * @param [out] resp   TimeStampResp object to fill.
 * @param [in]  input  Buffer holding DER encoding.
 * @param [in]  inSz   Length of data in buffer in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when resp or input is NULL or inSz is 0.
 * @return  ASN_PARSE_E when the encoding is invalid.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
int wc_TspResponse_Decode(TspResponse* resp, const byte* input, word32 inSz)
{
    DECL_ASNGETDATA(dataASN, tspRespASN_Length);
    int ret = 0;
    word32 idx = 0;

    WOLFSSL_ENTER("wc_TspResponse_Decode");

    /* Validate parameters. */
    if ((resp == NULL) || (input == NULL) || (inSz == 0)) {
        ret = BAD_FUNC_ARG;
    }

    CALLOC_ASNGETDATA(dataASN, tspRespASN_Length, ret, NULL);

    if (ret == 0) {
        /* All fields empty - optional fields left empty when not present. */
        XMEMSET(resp, 0, sizeof(TspResponse));

        /* Status is small - 0 to 5 defined. */
        GetASN_Int8Bit(&dataASN[TSPRESPASN_IDX_STAT], &resp->status);
        /* failInfo BIT STRING data into the 32-bit flags word. */
        GetASN_Int32Bit(&dataASN[TSPRESPASN_IDX_STAT_FAIL], &resp->failInfo);
        /* Decode TimeStampResp. */
        ret = GetASN_Items(tspRespASN, dataASN, tspRespASN_Length, 1, input,
            &idx, inSz);
    }
    /* Check all data used - input is one complete message. */
    if ((ret == 0) && (idx != inSz)) {
        ret = ASN_PARSE_E;
    }
    /* statusString is optional - reference first UTF8String. */
    if ((ret == 0) && GetASNItem_HaveIdx(dataASN[TSPRESPASN_IDX_STAT_STR])) {
        const byte* freeText;
        word32 freeTextSz;

        /* Get the content of the PKIFreeText SEQUENCE and parse it. */
        GetASN_GetConstRef(&dataASN[TSPRESPASN_IDX_STAT_STR], &freeText,
            &freeTextSz);
        ret = TspGetPkiFreeTextStr(freeText, freeTextSz, &resp->statusString,
            &resp->statusStringSz);
    }
    if (ret == 0) {
        /* failInfo is optional. Length includes unused bits byte.
         * Shift up by the number of bytes not encoded - bit 0 of the named
         * bit string is the most significant bit of 32. A validly decoded BIT
         * STRING has 1..4 data bytes plus the unused-bits byte, so length is in
         * [2,5] here; bound it explicitly so a shift of 32 or a negative count
         * (undefined for a word32) cannot arise from a decode-path change. */
        if ((dataASN[TSPRESPASN_IDX_STAT_FAIL].tag != 0) &&
                (dataASN[TSPRESPASN_IDX_STAT_FAIL].length >= 2) &&
                (dataASN[TSPRESPASN_IDX_STAT_FAIL].length <= 5)) {
            resp->failInfo <<=
                (8 * (5 - dataASN[TSPRESPASN_IDX_STAT_FAIL].length));
        }
        /* timeStampToken is optional - complete DER encoding referenced. */
        if (GetASNItem_HaveIdx(dataASN[TSPRESPASN_IDX_TOKEN])) {
            resp->token = GetASNItem_Addr(dataASN[TSPRESPASN_IDX_TOKEN],
                input);
            resp->tokenSz = GetASNItem_Length(dataASN[TSPRESPASN_IDX_TOKEN],
                input);
        }
    }

    FREE_ASNGETDATA(dataASN, NULL);
    WOLFSSL_LEAVE("wc_TspResponse_Decode", ret);
    return ret;
}
#endif /* WOLFSSL_TSP_VERIFIER */

#ifdef HAVE_PKCS7

/* id-aa-signingCertificateV2: 1.2.840.113549.1.9.16.2.47. RFC 5035.
 * Not static - also used by wc_TspTstInfo_SignWithPkcs7() in tsp.c (declared in
 * tsp.h). */
const byte tspSigningCertV2Oid[] = {
    ASN_OBJECT_ID, 0x0b,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x2f
};

#ifdef WOLFSSL_TSP_VERIFIER
#ifndef NO_SHA
/* id-aa-signingCertificate: 1.2.840.113549.1.9.16.2.12. RFC 2634. */
static const byte tspSigningCertOid[] = {
    ASN_OBJECT_ID, 0x0b,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x0c
};
#endif
#endif /* WOLFSSL_TSP_VERIFIER */


/* ASN template for SigningCertificateV2.
 * RFC 5035, 3 - Attribute Certificate Definition
 *
 * First ESSCertIDv2 only - any issuerSerial, further ESSCertIDv2s and
 * policies are skipped on decode and not encoded.
 */
static const ASNItem tspSignCertV2ASN[] = {
/* SEQ         */ { 0, ASN_SEQUENCE, 1, 1, 0 },
                                              /* certs */
/* CERTS       */     { 1, ASN_SEQUENCE, 1, 1, 0 },
                                              /* ESSCertIDv2 */
/* CERTID      */         { 2, ASN_SEQUENCE, 1, 1, 0 },
                                              /* hashAlgorithm */
/* HASH_SEQ    */             { 3, ASN_SEQUENCE, 1, 1, 1 },
/* HASH_OID    */                 { 4, ASN_OBJECT_ID, 0, 0, 0 },
/* HASH_NULL   */                 { 4, ASN_TAG_NULL, 0, 0, 1 },
                                              /* certHash */
/* HASH        */             { 3, ASN_OCTET_STRING, 0, 0, 0 },
};
/* Named indices for tspSignCertV2ASN. */
enum {
    TSPSIGNCERTV2ASN_IDX_SEQ = 0,
    TSPSIGNCERTV2ASN_IDX_CERTS,
    TSPSIGNCERTV2ASN_IDX_CERTID,
    TSPSIGNCERTV2ASN_IDX_HASH_SEQ,
    TSPSIGNCERTV2ASN_IDX_HASH_OID,
    TSPSIGNCERTV2ASN_IDX_HASH_NULL,
    TSPSIGNCERTV2ASN_IDX_HASH
};
/* Number of items in ASN.1 template for SigningCertificateV2. */
#define tspSignCertV2ASN_Length (sizeof(tspSignCertV2ASN) / sizeof(ASNItem))

#ifdef WOLFSSL_TSP_VERIFIER
#ifndef NO_SHA
/* ASN template for SigningCertificate.
 * RFC 2634, 5.4 - Signing Certificate Attribute Definition
 *
 * First ESSCertID only - any issuerSerial, further ESSCertIDs and policies
 * are skipped on decode.
 */
static const ASNItem tspSignCertASN[] = {
/* SEQ         */ { 0, ASN_SEQUENCE, 1, 1, 0 },
                                              /* certs */
/* CERTS       */     { 1, ASN_SEQUENCE, 1, 1, 0 },
                                              /* ESSCertID */
/* CERTID      */         { 2, ASN_SEQUENCE, 1, 1, 0 },
                                              /* certHash */
/* HASH        */             { 3, ASN_OCTET_STRING, 0, 0, 0 },
};
/* Named indices for tspSignCertASN. */
enum {
    TSPSIGNCERTASN_IDX_SEQ = 0,
    TSPSIGNCERTASN_IDX_CERTS,
    TSPSIGNCERTASN_IDX_CERTID,
    TSPSIGNCERTASN_IDX_HASH
};
/* Number of items in ASN.1 template for SigningCertificate. */
#define tspSignCertASN_Length (sizeof(tspSignCertASN) / sizeof(ASNItem))
#endif /* !NO_SHA */
#endif /* WOLFSSL_TSP_VERIFIER */

#ifdef WOLFSSL_TSP_RESPONDER
/* Encode a SigningCertificateV2 with the hash of the signer's certificate.
 *
 * @param [in]      hashOID  Hash algorithm OID sum - hash of token signing.
 * @param [in]      cert     DER encoded certificate of signer.
 * @param [in]      certSz   Length of certificate in bytes.
 * @param [out]     out      Buffer to hold encoding.
 * @param [in, out] outSz    On in, length of buffer in bytes.
 *                           On out, length of encoding in bytes.
 * @param [in]      heap     Dynamic memory allocation hint.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when the hash algorithm is not usable.
 * @return  BUFFER_E when encoding is longer than outSz.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
int TspEncodeSigningCertV2(int hashOID, const byte* cert, word32 certSz,
    byte* out, word32* outSz, void* heap)
{
    DECL_ASNSETDATA(dataASN, tspSignCertV2ASN_Length);
    int ret = 0;
    word32 sz = 0;
    WC_DECLARE_VAR(digest, byte, WC_MAX_DIGEST_SIZE, heap);
    enum wc_HashType hashType;
    int hashSz = 0;

    WC_ALLOC_VAR_EX(digest, byte, WC_MAX_DIGEST_SIZE, heap,
        DYNAMIC_TYPE_DIGEST, return MEMORY_E);

    /* Get the digest size to check hash algorithm is available. */
    hashType = wc_OidGetHash(hashOID);
    hashSz = wc_HashGetDigestSize(hashType);
    if (hashSz <= 0) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        /* Hash certificate of token signer. */
        ret = wc_Hash(hashType, cert, certSz, digest, WC_MAX_DIGEST_SIZE);
    }

    CALLOC_ASNSETDATA(dataASN, tspSignCertV2ASN_Length, ret, heap);

    if (ret == 0) {
        /* SHA-256 is the default hash algorithm - not encoded. */
        if (hashOID == SHA256h) {
            SetASNItem_NoOutNode(dataASN, tspSignCertV2ASN,
                TSPSIGNCERTV2ASN_IDX_HASH_SEQ, tspSignCertV2ASN_Length);
        }
        else {
            SetASN_OID(&dataASN[TSPSIGNCERTV2ASN_IDX_HASH_OID], hashOID,
                oidHashType);
            /* No encoding available for an unknown OID sum. */
            if (dataASN[TSPSIGNCERTV2ASN_IDX_HASH_OID].data.buffer.data ==
                    NULL) {
                ret = ASN_UNKNOWN_OID_E;
            }
            /* No parameters with hash algorithm. */
            SetASNItem_NoOutNode_ex(dataASN, tspSignCertV2ASN, 0,
                TSPSIGNCERTV2ASN_IDX_HASH_NULL, tspSignCertV2ASN_Length);
        }
    }
    if (ret == 0) {
        /* certHash is the hash of the signer's certificate. */
        SetASN_Buffer(&dataASN[TSPSIGNCERTV2ASN_IDX_HASH], digest,
            (word32)hashSz);

        /* Calculate size of encoding. */
        ret = SizeASN_Items(tspSignCertV2ASN, dataASN,
            tspSignCertV2ASN_Length, &sz);
    }
    /* Write out encoding when buffer supplied. */
    if ((ret == 0) && (out != NULL)) {
        /* Check buffer is big enough to hold encoding. */
        if (sz > *outSz) {
            ret = BUFFER_E;
        }
        /* Length written must be the length calculated. */
        else if (SetASN_Items(tspSignCertV2ASN, dataASN,
                tspSignCertV2ASN_Length, out) != (int)sz) {
            ret = ASN_PARSE_E;
        }
    }
    if (ret == 0) {
        /* Return the length of the encoding. */
        *outSz = sz;
    }

    FREE_ASNSETDATA(dataASN, heap);
    WC_FREE_VAR_EX(digest, heap, DYNAMIC_TYPE_DIGEST);
    return ret;
}

#endif /* WOLFSSL_TSP_RESPONDER */

#ifdef WOLFSSL_TSP_VERIFIER

/* Find a decoded signed attribute by OID.
 *
 * @param [in] pkcs7  PKCS7 object with decoded signed attributes.
 * @param [in] oid    DER encoding of OBJECT IDENTIFIER.
 * @param [in] oidSz  Length of OBJECT IDENTIFIER in bytes.
 * @return  Decoded attribute when found.
 * @return  NULL when not found.
 */
static const PKCS7DecodedAttrib* TspFindAttrib(wc_PKCS7* pkcs7,
    const byte* oid, word32 oidSz)
{
    const PKCS7DecodedAttrib* attrib;

    /* Search the linked list for the OID. */
    for (attrib = pkcs7->decodedAttrib; attrib != NULL;
            attrib = attrib->next) {
        if ((attrib->oidSz == oidSz) &&
                (XMEMCMP(attrib->oid, oid, oidSz) == 0)) {
            break;
        }
    }

    return attrib;
}

/* Check the signing certificate attribute matches the signer's certificate.
 *
 * RFC 3161, 2.4.2: the signing certificate attribute of ESS must be present.
 * SigningCertificateV2 of RFC 5816 also accepted. The hash of the signer's
 * certificate must match the certHash of the first ESSCertID(v2).
 *
 * @param [in] pkcs7  PKCS7 object that verified the token.
 * @return  0 on success.
 * @return  TSP_VERIFY_E when no signing certificate attribute is found or
 *          the certificate hash does not match.
 * @return  HASH_TYPE_E when the hash algorithm is not available.
 * @return  ASN_PARSE_E when the attribute encoding is invalid.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
int TspCheckSigningCertAttr(wc_PKCS7* pkcs7)
{
    DECL_ASNGETDATA(dataASN, tspSignCertV2ASN_Length);
    int ret = 0;
    const PKCS7DecodedAttrib* attrib;
    const byte* certHash = NULL;
    word32 certHashSz = 0;
    word32 hashOID = SHA256h;
    enum wc_HashType hashType;
    int hashSz = 0;
    word32 idx = 0;
    WC_DECLARE_VAR(digest, byte, WC_MAX_DIGEST_SIZE, pkcs7->heap);

    WC_ALLOC_VAR_EX(digest, byte, WC_MAX_DIGEST_SIZE, pkcs7->heap,
        DYNAMIC_TYPE_DIGEST, return MEMORY_E);

    CALLOC_ASNGETDATA(dataASN, tspSignCertV2ASN_Length, ret, pkcs7->heap);

    if (ret == 0) {
        /* Look for SigningCertificateV2 first - RFC 5816. */
        attrib = TspFindAttrib(pkcs7, tspSigningCertV2Oid,
            (word32)sizeof(tspSigningCertV2Oid));
        if (attrib != NULL) {
            /* Any hash algorithm accepted - checked when hashing. */
            GetASN_OID(&dataASN[TSPSIGNCERTV2ASN_IDX_HASH_OID],
                oidIgnoreType);
            /* Decode first ESSCertIDv2 of SigningCertificateV2. */
            ret = GetASN_Items(tspSignCertV2ASN, dataASN,
                tspSignCertV2ASN_Length, 0, attrib->value, &idx,
                attrib->valueSz);
            if (ret == 0) {
                /* SHA-256 is the default hash algorithm. */
                if (dataASN[TSPSIGNCERTV2ASN_IDX_HASH_OID].tag != 0) {
                    hashOID =
                        dataASN[TSPSIGNCERTV2ASN_IDX_HASH_OID].data.oid.sum;
                }
                GetASN_GetConstRef(&dataASN[TSPSIGNCERTV2ASN_IDX_HASH],
                    &certHash, &certHashSz);
            }
        }
        else {
        #ifndef NO_SHA
            /* Fall back to SigningCertificate of ESS - RFC 2634. */
            attrib = TspFindAttrib(pkcs7, tspSigningCertOid,
                (word32)sizeof(tspSigningCertOid));
            if (attrib != NULL) {
                /* SHA-1 is the hash algorithm of ESSCertID. */
                hashOID = SHAh;
                /* Decode first ESSCertID of SigningCertificate. */
                ret = GetASN_Items(tspSignCertASN, dataASN,
                    tspSignCertASN_Length, 0, attrib->value, &idx,
                    attrib->valueSz);
                if (ret == 0) {
                    GetASN_GetConstRef(&dataASN[TSPSIGNCERTASN_IDX_HASH],
                        &certHash, &certHashSz);
                }
            }
            else
        #endif
            {
                /* The signing certificate attribute must be present. */
                WOLFSSL_MSG("TSP token has no signing certificate attribute");
                ret = TSP_VERIFY_E;
            }
        }
    }
    /* The hash algorithm must meet the minimum strength. */
    if (ret == 0) {
        ret = Tsp_CheckHashStrength(hashOID);
    }
    /* Compare against hash of the signer's certificate. */
    if (ret == 0) {
        /* Get the digest size to check hash algorithm is available. */
        hashType = wc_OidGetHash((int)hashOID);
        hashSz = wc_HashGetDigestSize(hashType);
        if (hashSz <= 0) {
            ret = HASH_TYPE_E;
        }
    }
    if (ret == 0) {
        /* Hash the certificate that verified the token. */
        ret = wc_Hash(hashType, pkcs7->verifyCert, pkcs7->verifyCertSz,
            digest, WC_MAX_DIGEST_SIZE);
    }
    /* certHash must be the hash of the signer's certificate. */
    if ((ret == 0) && ((certHashSz != (word32)hashSz) ||
            (XMEMCMP(certHash, digest, certHashSz) != 0))) {
        WOLFSSL_MSG("TSP signing certificate attribute hash mismatch");
        ret = TSP_VERIFY_E;
    }

    FREE_ASNGETDATA(dataASN, pkcs7->heap);
    WC_FREE_VAR_EX(digest, pkcs7->heap, DYNAMIC_TYPE_DIGEST);
    return ret;
}

/* ASN template for the SignedData of a TimeStampToken.
 * RFC 5652, 5.1 - SignedData Type
 *
 * Parsed only as far as needed to find the signerInfos.
 */
static const ASNItem tspTokenASN[] = {
/* SEQ         */ { 0, ASN_SEQUENCE, 1, 1, 0 },
                                              /* contentType */
/* TYPE        */     { 1, ASN_OBJECT_ID, 0, 0, 0 },
                                              /* content */
/* CONTENT     */     { 1, ASN_CONTEXT_SPECIFIC | 0, 1, 1, 0 },
                                              /* SignedData */
/* SD_SEQ      */         { 2, ASN_SEQUENCE, 1, 1, 0 },
                                              /* version */
/* VER         */             { 3, ASN_INTEGER, 0, 0, 0 },
                                              /* digestAlgorithms */
/* DIG_ALGS    */             { 3, ASN_SET, 1, 0, 0 },
                                              /* encapContentInfo */
/* ENCAP       */             { 3, ASN_SEQUENCE, 1, 0, 0 },
                                              /* certificates */
/* CERTS       */             { 3, ASN_CONTEXT_SPECIFIC | 0, 1, 0, 1 },
                                              /* crls */
/* CRLS        */             { 3, ASN_CONTEXT_SPECIFIC | 1, 1, 0, 1 },
                                              /* signerInfos */
/* SIGNERS     */             { 3, ASN_SET, 1, 0, 0 },
};
/* Named indices for tspTokenASN. */
enum {
    TSPTOKENASN_IDX_SEQ = 0,
    TSPTOKENASN_IDX_TYPE,
    TSPTOKENASN_IDX_CONTENT,
    TSPTOKENASN_IDX_SD_SEQ,
    TSPTOKENASN_IDX_VER,
    TSPTOKENASN_IDX_DIG_ALGS,
    TSPTOKENASN_IDX_ENCAP,
    TSPTOKENASN_IDX_CERTS,
    TSPTOKENASN_IDX_CRLS,
    TSPTOKENASN_IDX_SIGNERS
};
/* Number of items in ASN.1 template for the SignedData of a token. */
#define tspTokenASN_Length (sizeof(tspTokenASN) / sizeof(ASNItem))

/* Check the token has exactly one SignerInfo.
 *
 * RFC 3161, 2.4.2: the time-stamp token must contain a single SignerInfo.
 *
 * @param [in] token    Buffer holding DER encoding of token.
 * @param [in] tokenSz  Length of data in buffer in bytes.
 * @param [in] heap     Dynamic memory allocation hint.
 * @return  0 on success.
 * @return  ASN_PARSE_E when the encoding is invalid.
 * @return  TSP_VERIFY_E when there is not exactly one SignerInfo.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
int TspCheckOneSignerInfo(const byte* token, word32 tokenSz, void* heap)
{
    DECL_ASNGETDATA(dataASN, tspTokenASN_Length);
    int ret = 0;
    word32 idx = 0;
    const byte* signers = NULL;
    word32 signersSz = 0;
    int cnt = 0;

    CALLOC_ASNGETDATA(dataASN, tspTokenASN_Length, ret, heap);

    if (ret == 0) {
        /* Parse down to the signerInfos. */
        ret = GetASN_Items(tspTokenASN, dataASN, tspTokenASN_Length, 1,
            token, &idx, tokenSz);
    }
    if (ret == 0) {
        /* Count the SignerInfo SEQUENCEs in the SET. */
        GetASN_GetConstRef(&dataASN[TSPTOKENASN_IDX_SIGNERS], &signers,
            &signersSz);
        idx = 0;
        while ((ret == 0) && (idx < signersSz)) {
            byte tag = 0;
            int len = 0;

            if ((GetASNTag(signers, &idx, &tag, signersSz) < 0) ||
                    (tag != (ASN_SEQUENCE | ASN_CONSTRUCTED)) ||
                    (GetLength(signers, &idx, &len, signersSz) < 0)) {
                ret = ASN_PARSE_E;
            }
            else {
                /* Step over the SignerInfo. */
                idx += (word32)len;
                cnt++;
            }
        }
    }
    if ((ret == 0) && (cnt != 1)) {
        WOLFSSL_MSG("TSP token must have one SignerInfo");
        ret = TSP_VERIFY_E;
    }

    FREE_ASNGETDATA(dataASN, heap);
    return ret;
}

#endif /* WOLFSSL_TSP_VERIFIER */
#endif /* HAVE_PKCS7 */

#endif /* WOLFSSL_TSP && WOLFSSL_ASN_TEMPLATE && !NO_ASN */

#endif /* WOLFSSL_ASN_TSP_INCLUDED */
