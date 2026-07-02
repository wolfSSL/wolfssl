/*!
    \ingroup TSP

    \brief This function initializes a TimeStampReq structure for encoding.
    All fields are cleared and the version is set to 1. Set the message
    imprint with the hash algorithm and hash of the data to be time-stamped
    before encoding.

    \return 0 Returned on successfully initializing the request.
    \return BAD_FUNC_ARG Returned when req is NULL.

    \param [out] req Pointer to the TspRequest structure to initialize.

    _Example_
    \code
    TspRequest req;
    byte hash[WC_SHA256_DIGEST_SIZE];
    // hash the data to be time-stamped into hash

    wc_TspRequest_Init(&req);
    req.imprint.hashAlgOID = SHA256h;
    XMEMCPY(req.imprint.hash, hash, sizeof(hash));
    req.imprint.hashSz = (word32)sizeof(hash);
    req.certReq = 1;
    \endcode

    \sa wc_TspRequest_SetHashType
    \sa wc_TspRequest_Encode
    \sa wc_TspRequest_Decode
*/
int wc_TspRequest_Init(TspRequest* req);

/*!
    \ingroup TSP

    \brief This function sets the message imprint hash algorithm and hash size
    of a TimeStampReq from a hash type. After calling, fill
    req->imprint.hash with the digest of the data to be time-stamped.

    \return 0 Returned on successfully setting the hash algorithm.
    \return BAD_FUNC_ARG Returned when req is NULL.
    \return HASH_TYPE_E Returned when the hash algorithm is not available.
    \return BUFFER_E Returned when the digest is too big for the message
    imprint.

    \param [in,out] req Pointer to the TspRequest structure to update.
    \param [in] hashType Hash algorithm to use - e.g. WC_HASH_TYPE_SHA256.

    _Example_
    \code
    TspRequest req;
    byte hash[WC_SHA256_DIGEST_SIZE];
    // hash the data to be time-stamped into hash

    wc_TspRequest_Init(&req);
    wc_TspRequest_SetHashType(&req, WC_HASH_TYPE_SHA256);
    XMEMCPY(req.imprint.hash, hash, sizeof(hash));
    req.certReq = 1;
    \endcode

    \sa wc_TspRequest_Init
    \sa wc_TspRequest_GetHashType
    \sa wc_TspRequest_Encode
*/
int wc_TspRequest_SetHashType(TspRequest* req, enum wc_HashType hashType);

/*!
    \ingroup TSP

    \brief This function gets the message imprint hash type of a TimeStampReq.
    It maps the hash algorithm OID of the message imprint to a hash type. This
    is useful after decoding a request to learn which hash algorithm to use on
    the data to be time-stamped.

    \return 0 Returned on successfully getting the hash type.
    \return BAD_FUNC_ARG Returned when req or hashType is NULL.
    \return HASH_TYPE_E Returned when the message imprint hash algorithm is
    not a recognized hash.

    \param [in] req Pointer to the TspRequest structure to query.
    \param [out] hashType Set to the hash algorithm of the message imprint.

    _Example_
    \code
    TspRequest req;
    enum wc_HashType hashType;

    // decode req from a received request
    if (wc_TspRequest_GetHashType(&req, &hashType) != 0) {
        // hash algorithm not supported
    }
    \endcode

    \sa wc_TspRequest_SetHashType
    \sa wc_TspRequest_Decode
*/
int wc_TspRequest_GetHashType(const TspRequest* req,
    enum wc_HashType* hashType);

/*!
    \ingroup TSP

    \brief This function gets the message imprint hash of a TimeStampReq. The
    hash is copied into the caller's buffer.

    \return 0 Returned on successfully getting the hash.
    \return BAD_FUNC_ARG Returned when req, hash or hashSz is NULL.
    \return BUFFER_E Returned when the buffer is too small for the hash.

    \param [in] req Pointer to the TspRequest structure to query.
    \param [out] hash Buffer to hold the hash.
    \param [in,out] hashSz On in, the length of the buffer in bytes. On out,
    the length of the hash in bytes.

    _Example_
    \code
    TspRequest req;
    byte hash[WC_SHA256_DIGEST_SIZE];
    word32 hashSz = (word32)sizeof(hash);

    // decode req from a received request
    if (wc_TspRequest_GetHash(&req, hash, &hashSz) != 0) {
        // buffer too small
    }
    \endcode

    \sa wc_TspRequest_SetHash
*/
int wc_TspRequest_GetHash(const TspRequest* req, byte* hash, word32* hashSz);

/*!
    \ingroup TSP

    \brief This function sets the message imprint hash of a TimeStampReq. The
    hash and its length are copied into the message imprint. Set the hash
    algorithm separately with wc_TspRequest_SetHashType().

    \return 0 Returned on successfully setting the hash.
    \return BAD_FUNC_ARG Returned when req or hash is NULL or hashSz is 0.
    \return BUFFER_E Returned when hashSz is too big for the message imprint.

    \param [in,out] req Pointer to the TspRequest structure to update.
    \param [in] hash Hash of the data to be time-stamped.
    \param [in] hashSz Length of the hash in bytes.

    _Example_
    \code
    TspRequest req;
    byte hash[WC_SHA256_DIGEST_SIZE];
    // hash the data to be time-stamped into hash

    wc_TspRequest_Init(&req);
    wc_TspRequest_SetHashType(&req, WC_HASH_TYPE_SHA256);
    wc_TspRequest_SetHash(&req, hash, sizeof(hash));
    \endcode

    \sa wc_TspRequest_GetHash
    \sa wc_TspRequest_SetHashType
*/
int wc_TspRequest_SetHash(TspRequest* req, const byte* hash, word32 hashSz);

/*!
    \ingroup TSP

    \brief This function gets the nonce of a TimeStampReq. The nonce is copied
    into the caller's buffer. A length of 0 means no nonce is set.

    \return 0 Returned on successfully getting the nonce.
    \return BAD_FUNC_ARG Returned when req, nonce or nonceSz is NULL.
    \return BUFFER_E Returned when the buffer is too small for the nonce.

    \param [in] req Pointer to the TspRequest structure to query.
    \param [out] nonce Buffer to hold the nonce.
    \param [in,out] nonceSz On in, the length of the buffer in bytes. On out,
    the length of the nonce in bytes.

    _Example_
    \code
    TspRequest req;
    byte nonce[32];
    word32 nonceSz = (word32)sizeof(nonce);

    // decode req from a received request
    if (wc_TspRequest_GetNonce(&req, nonce, &nonceSz) != 0) {
        // buffer too small
    }
    \endcode

    \sa wc_TspRequest_SetNonce
*/
int wc_TspRequest_GetNonce(const TspRequest* req, byte* nonce, word32* nonceSz);

/*!
    \ingroup TSP

    \brief This function sets the nonce of a TimeStampReq. The nonce is a
    big-endian number that must not have a leading zero byte to encode -
    leading zero bytes are stripped, keeping at least one byte so an all-zero
    nonce becomes the number zero.

    \return 0 Returned on successfully setting the nonce.
    \return BAD_FUNC_ARG Returned when req or nonce is NULL or nonceSz is 0.
    \return BUFFER_E Returned when nonceSz is too big for the nonce field.

    \param [in,out] req Pointer to the TspRequest structure to update.
    \param [in] nonce Nonce as a big-endian number.
    \param [in] nonceSz Length of the nonce in bytes.

    _Example_
    \code
    TspRequest req;
    byte nonce[16];
    // fill nonce with random bytes

    wc_TspRequest_Init(&req);
    wc_TspRequest_SetNonce(&req, nonce, sizeof(nonce));
    \endcode

    \sa wc_TspRequest_GetNonce
*/
int wc_TspRequest_SetNonce(TspRequest* req, const byte* nonce, word32 nonceSz);

/*!
    \ingroup TSP

    \brief This function generates a random nonce for a TimeStampReq from a
    random number generator. A convenience over generating random bytes and
    calling wc_TspRequest_SetNonce(). The nonce is a minimal positive INTEGER:
    the top bit of the first byte is cleared so it is positive and the first
    byte is made non-zero so there is no leading zero byte.

    \return 0 Returned on successfully generating the nonce.
    \return BAD_FUNC_ARG Returned when req or rng is NULL or sz is 0.
    \return BUFFER_E Returned when sz is too big for the nonce field.
    \return Other Returned, negative, on random number generation failure.

    \param [in,out] req Pointer to the TspRequest structure to update.
    \param [in] rng Random number generator.
    \param [in] sz Length of the nonce to generate in bytes.

    _Example_
    \code
    TspRequest req;
    WC_RNG rng;

    wc_InitRng(&rng);
    wc_TspRequest_Init(&req);
    if (wc_TspRequest_GenerateNonce(&req, &rng, 16) != 0) {
        // error generating nonce
    }
    \endcode

    \sa wc_TspRequest_SetNonce
    \sa wc_TspRequest_GetNonce
*/
int wc_TspRequest_GenerateNonce(TspRequest* req, WC_RNG* rng, word32 sz);

/*!
    \ingroup TSP

    \brief This function gets the TSA policy of a TimeStampReq, copying it into
    the caller's buffer. The policy is the content of an OBJECT IDENTIFIER. A
    length of 0 means no policy is set.

    \return 0 Returned on successfully getting the policy.
    \return BAD_FUNC_ARG Returned when req, policy or policySz is NULL.
    \return BUFFER_E Returned when the buffer is too small for the policy.

    \param [in] req Pointer to the TspRequest structure.
    \param [out] policy Buffer to hold the policy.
    \param [in,out] policySz On in, length of the buffer in bytes. On out,
    length of the policy in bytes.

    _Example_
    \code
    TspRequest req;          // decoded request
    byte policy[32];
    word32 policySz = sizeof(policy);

    if (wc_TspRequest_GetPolicy(&req, policy, &policySz) != 0) {
        // error getting policy
    }
    \endcode

    \sa wc_TspRequest_SetPolicy
*/
int wc_TspRequest_GetPolicy(const TspRequest* req, byte* policy,
    word32* policySz);

/*!
    \ingroup TSP

    \brief This function sets the TSA policy of a TimeStampReq. The policy is
    the content of an OBJECT IDENTIFIER - the bytes after the type and length.
    It is copied into the request.

    \return 0 Returned on successfully setting the policy.
    \return BAD_FUNC_ARG Returned when req or policy is NULL or policySz is 0.
    \return BUFFER_E Returned when policySz is too big for the policy field.

    \param [in,out] req Pointer to the TspRequest structure to update.
    \param [in] policy Policy as OBJECT IDENTIFIER content.
    \param [in] policySz Length of the policy in bytes.

    _Example_
    \code
    TspRequest req;
    // OBJECT IDENTIFIER content for the policy
    static const byte policy[] = { 0x2b, 0x06, 0x01, 0x04, 0x01 };

    wc_TspRequest_Init(&req);
    wc_TspRequest_SetPolicy(&req, policy, sizeof(policy));
    \endcode

    \sa wc_TspRequest_GetPolicy
*/
int wc_TspRequest_SetPolicy(TspRequest* req, const byte* policy,
    word32 policySz);

/*!
    \ingroup TSP

    \brief This macro gets the certReq flag of a TimeStampReq. A non-zero
    value means the requester asked for the TSA certificate to be included
    in the response.

    \return The certReq flag: non-zero when the TSA certificate is requested,
    0 otherwise.

    \param [in] req Pointer to the TspRequest structure to query.

    _Example_
    \code
    TspRequest req;
    // decode req from a received request

    if (wc_TspRequest_GetCertReq(&req)) {
        // include the TSA certificate in the response
    }
    \endcode

    \sa wc_TspRequest_SetCertReq
*/
#define wc_TspRequest_GetCertReq(req)       ((req)->certReq)

/*!
    \ingroup TSP

    \brief This macro sets the certReq flag of a TimeStampReq. A non-zero
    value requests the TSA certificate to be included in the response. Any
    non-zero value is normalized to 1.

    \param [in,out] req Pointer to the TspRequest structure to update.
    \param [in] val Non-zero to request the TSA certificate, 0 otherwise.

    _Example_
    \code
    TspRequest req;

    wc_TspRequest_Init(&req);
    wc_TspRequest_SetCertReq(&req, 1);
    \endcode

    \sa wc_TspRequest_GetCertReq
*/
#define wc_TspRequest_SetCertReq(req, val)  \
    ((req)->certReq = (byte)((val) != 0))

/*!
    \ingroup TSP

    \brief This function encodes a TimeStampReq as DER - RFC 3161, 2.4.1.
    The message imprint is required. The policy, nonce and certReq fields
    are encoded when set. The nonce is a big-endian number and must not
    have a leading zero byte.

    \return 0 Returned on successfully encoding the request.
    \return BAD_FUNC_ARG Returned when req or outSz is NULL, the message
    imprint hash is not set, a field is too long for its array or the nonce
    has a leading zero byte.
    \return BUFFER_E Returned when out is not NULL and the encoding is
    longer than outSz.
    \return ASN_UNKNOWN_OID_E Returned when the hash algorithm is not
    recognized.
    \return MEMORY_E Returned on dynamic memory allocation failure.

    \param [in] req Pointer to the TspRequest structure to encode.
    \param [out] out Buffer to hold the encoding. May be NULL to get the
    length.
    \param [in,out] outSz On in, the length of the buffer in bytes. On out,
    the length of the encoding in bytes.

    _Example_
    \code
    TspRequest req;
    byte der[512];
    word32 derSz = (word32)sizeof(der);

    // initialize req and set the message imprint
    if (wc_TspRequest_Encode(&req, der, &derSz) != 0) {
        // error encoding request
    }
    // send der to the TSA
    \endcode

    \sa wc_TspRequest_Init
    \sa wc_TspRequest_Decode
*/
int wc_TspRequest_Encode(const TspRequest* req, byte* out, word32* outSz);

/*!
    \ingroup TSP

    \brief This function decodes a DER encoded TimeStampReq - RFC 3161,
    2.4.1. All fields are copied into the structure - the input buffer is
    not referenced after return. Only version 1 is supported - a request
    with another version fails to decode. Any policy OID is accepted - the
    caller checks it is one it supports. The hash algorithm is not checked
    to be available - the caller checks it is usable. Requests with
    extensions are not supported and fail to decode.

    \return 0 Returned on successfully decoding the request.
    \return BAD_FUNC_ARG Returned when req or input is NULL or inSz is 0.
    \return ASN_PARSE_E Returned when the encoding is invalid, the hash is
    empty or extensions are present.
    \return ASN_VERSION_E Returned when the version is not supported.
    \return ASN_UNKNOWN_OID_E Returned when the hash algorithm OID check
    fails.
    \return BUFFER_E Returned when the hash is longer than
    WC_TSP_MAX_HASH_SZ bytes, the policy is longer than MAX_OID_SZ bytes or
    the nonce is longer than MAX_TS_NONCE_SZ bytes.
    \return MEMORY_E Returned on dynamic memory allocation failure.

    \param [out] req Pointer to the TspRequest structure to fill.
    \param [in] input Buffer holding the DER encoding.
    \param [in] inSz Length of the data in the buffer in bytes.

    _Example_
    \code
    TspRequest req;
    byte* der;    // DER encoded request received
    word32 derSz; // length of DER encoded request

    if (wc_TspRequest_Decode(&req, der, derSz) != 0) {
        // error decoding request
    }
    \endcode

    \sa wc_TspRequest_Encode
    \sa wc_TspTstInfo_CheckRequest
*/
int wc_TspRequest_Decode(TspRequest* req, const byte* input, word32 inSz);

/*!
    \ingroup TSP

    \brief This function initializes a TSTInfo structure for encoding. All
    fields are cleared and the version is set to 1. The policy, message
    imprint, serial number and time are required for encoding.

    \return 0 Returned on successfully initializing the TSTInfo.
    \return BAD_FUNC_ARG Returned when tstInfo is NULL.

    \param [out] tstInfo Pointer to the TspTstInfo structure to initialize.

    _Example_
    \code
    TspTstInfo tst;

    wc_TspTstInfo_Init(&tst);
    // set policy, imprint and serial number; NULL genTime is current time
    \endcode

    \sa wc_TspTstInfo_Encode
    \sa wc_TspTstInfo_SignWithPkcs7
*/
int wc_TspTstInfo_Init(TspTstInfo* tstInfo);

/*!
    \ingroup TSP

    \brief This function gets the serial number of a TSTInfo. A reference is
    returned - the serial number is not copied and is valid while the TSTInfo
    references it.

    \return 0 Returned on successfully getting the serial number.
    \return BAD_FUNC_ARG Returned when tstInfo, serial or serialSz is NULL.

    \param [in] tstInfo Pointer to the TspTstInfo structure.
    \param [out] serial Serial number as a big-endian number.
    \param [out] serialSz Length of the serial number in bytes.

    _Example_
    \code
    TspTstInfo tst;          // decoded TSTInfo
    const byte* serial;
    word32 serialSz;

    if (wc_TspTstInfo_GetSerial(&tst, &serial, &serialSz) != 0) {
        // error getting serial number
    }
    \endcode

    \sa wc_TspTstInfo_SetSerial
*/
int wc_TspTstInfo_GetSerial(const TspTstInfo* tstInfo, const byte** serial,
    word32* serialSz);

/*!
    \ingroup TSP

    \brief This function sets the serial number of a TSTInfo. The serial number
    is a big-endian number that is referenced, not copied, and must remain
    available while the TSTInfo is used. Leading zero bytes are stripped,
    keeping at least one byte, so it has no leading zero byte and encodes - an
    all-zero serial number becomes zero.

    \return 0 Returned on successfully setting the serial number.
    \return BAD_FUNC_ARG Returned when tstInfo or serial is NULL or serialSz
    is 0.

    \param [in,out] tstInfo Pointer to the TspTstInfo structure to update.
    \param [in] serial Serial number as a big-endian number.
    \param [in] serialSz Length of the serial number in bytes.

    _Example_
    \code
    TspTstInfo tst;
    static const byte serial[] = { 0x01, 0x02, 0x03, 0x04 };

    wc_TspTstInfo_Init(&tst);
    wc_TspTstInfo_SetSerial(&tst, serial, sizeof(serial));
    \endcode

    \sa wc_TspTstInfo_GetSerial
*/
int wc_TspTstInfo_SetSerial(TspTstInfo* tstInfo, const byte* serial,
    word32 serialSz);

/*!
    \ingroup TSP

    \brief This function gets the TSA policy of a TSTInfo. A reference is
    returned - the policy is not copied and is valid while the TSTInfo
    references it. A length of 0 means no policy is present.

    \return 0 Returned on successfully getting the policy.
    \return BAD_FUNC_ARG Returned when tstInfo, policy or policySz is NULL.

    \param [in] tstInfo Pointer to the TspTstInfo structure.
    \param [out] policy Policy as OBJECT IDENTIFIER content.
    \param [out] policySz Length of the policy in bytes.

    _Example_
    \code
    TspTstInfo tst;          // decoded TSTInfo
    const byte* policy;
    word32 policySz;

    if (wc_TspTstInfo_GetPolicy(&tst, &policy, &policySz) != 0) {
        // error getting policy
    }
    \endcode

    \sa wc_TspTstInfo_SetPolicy
*/
int wc_TspTstInfo_GetPolicy(const TspTstInfo* tstInfo, const byte** policy,
    word32* policySz);

/*!
    \ingroup TSP

    \brief This function sets the TSA policy of a TSTInfo. The policy is the
    content of an OBJECT IDENTIFIER - it is referenced, not copied, and must
    remain available while the TSTInfo is used.

    \return 0 Returned on successfully setting the policy.
    \return BAD_FUNC_ARG Returned when tstInfo or policy is NULL or policySz
    is 0.

    \param [in,out] tstInfo Pointer to the TspTstInfo structure to update.
    \param [in] policy Policy as OBJECT IDENTIFIER content.
    \param [in] policySz Length of the policy in bytes.

    _Example_
    \code
    TspTstInfo tst;
    static const byte policy[] = { 0x2b, 0x06, 0x01, 0x04, 0x01 };

    wc_TspTstInfo_Init(&tst);
    wc_TspTstInfo_SetPolicy(&tst, policy, sizeof(policy));
    \endcode

    \sa wc_TspTstInfo_GetPolicy
*/
int wc_TspTstInfo_SetPolicy(TspTstInfo* tstInfo, const byte* policy,
    word32 policySz);

/*!
    \ingroup TSP

    \brief This function gets the message imprint of a TSTInfo - the hash and
    hash algorithm of the time-stamped data. Each output is optional - pass
    NULL to not retrieve it. The hash references the TSTInfo.

    \return 0 Returned on successfully getting the message imprint.
    \return BAD_FUNC_ARG Returned when tstInfo is NULL.

    \param [in] tstInfo Pointer to the TspTstInfo structure.
    \param [out] hashOID Hash algorithm OID sum. May be NULL.
    \param [out] hash Hash of the time-stamped data. May be NULL.
    \param [out] hashSz Length of the hash in bytes. May be NULL.

    _Example_
    \code
    TspTstInfo tst;          // decoded TSTInfo
    word32 hashOID;
    const byte* hash;
    word32 hashSz;

    if (wc_TspTstInfo_GetMsgImprint(&tst, &hashOID, &hash, &hashSz) != 0) {
        // error getting message imprint
    }
    \endcode

    \sa wc_TspTstInfo_SetMsgImprint
*/
int wc_TspTstInfo_GetMsgImprint(const TspTstInfo* tstInfo, word32* hashOID,
    const byte** hash, word32* hashSz);

/*!
    \ingroup TSP

    \brief This function sets the message imprint of a TSTInfo. The hash is the
    digest of the data being time-stamped - it is copied into the TSTInfo. The
    hash and algorithm are typically those of the request.

    \return 0 Returned on successfully setting the message imprint.
    \return BAD_FUNC_ARG Returned when tstInfo or hash is NULL or hashSz is 0.
    \return BUFFER_E Returned when hashSz is too big for the message imprint.

    \param [in,out] tstInfo Pointer to the TspTstInfo structure to update.
    \param [in] hashOID Hash algorithm OID sum: SHA256h, etc.
    \param [in] hash Hash of the data to time-stamp.
    \param [in] hashSz Length of the hash in bytes.

    _Example_
    \code
    TspTstInfo tst;
    byte hash[32];           // SHA-256 of the data, e.g. from the request

    wc_TspTstInfo_Init(&tst);
    wc_TspTstInfo_SetMsgImprint(&tst, SHA256h, hash, sizeof(hash));
    \endcode

    \sa wc_TspTstInfo_GetMsgImprint
*/
int wc_TspTstInfo_SetMsgImprint(TspTstInfo* tstInfo, word32 hashOID,
    const byte* hash, word32 hashSz);

/*!
    \ingroup TSP

    \brief This function gets the time of the time-stamp of a TSTInfo as a
    GeneralizedTime string of RFC 3161 - "YYYYMMDDhhmmss[.s...]Z". A reference
    is returned - the string is not copied and is valid while the TSTInfo
    references it.

    \return 0 Returned on successfully getting the time.
    \return BAD_FUNC_ARG Returned when tstInfo, genTime or genTimeSz is NULL.

    \param [in] tstInfo Pointer to the TspTstInfo structure.
    \param [out] genTime Time as a GeneralizedTime string.
    \param [out] genTimeSz Length of the string in bytes.

    _Example_
    \code
    TspTstInfo tst;          // decoded TSTInfo
    const byte* genTime;
    word32 genTimeSz;

    if (wc_TspTstInfo_GetGenTime(&tst, &genTime, &genTimeSz) != 0) {
        // error getting time
    }
    \endcode

    \sa wc_TspTstInfo_SetGenTime
    \sa wc_TspTstInfo_GetGenTimeAsTime
*/
int wc_TspTstInfo_GetGenTime(const TspTstInfo* tstInfo, const byte** genTime,
    word32* genTimeSz);

/*!
    \ingroup TSP

    \brief This function sets the time of the time-stamp of a TSTInfo. The
    genTime is a GeneralizedTime string of RFC 3161 - it is referenced, not
    copied, and must remain available while the TSTInfo is used. The syntax is
    checked on encode. Leave unset to use the current time on encode.

    \return 0 Returned on successfully setting the time.
    \return BAD_FUNC_ARG Returned when tstInfo or genTime is NULL or genTimeSz
    is 0.

    \param [in,out] tstInfo Pointer to the TspTstInfo structure to update.
    \param [in] genTime Time as a GeneralizedTime string.
    \param [in] genTimeSz Length of the string in bytes.

    _Example_
    \code
    TspTstInfo tst;
    static const byte genTime[] = "20260625120000Z";

    wc_TspTstInfo_Init(&tst);
    wc_TspTstInfo_SetGenTime(&tst, genTime, sizeof(genTime) - 1);
    \endcode

    \sa wc_TspTstInfo_GetGenTime
    \sa wc_TspTstInfo_SetGenTimeAsTime
*/
int wc_TspTstInfo_SetGenTime(TspTstInfo* tstInfo, const byte* genTime,
    word32 genTimeSz);

/*!
    \ingroup TSP

    \brief This function gets the accuracy of the time of a TSTInfo - the
    seconds, milliseconds and microseconds the genTime may be off by. Each
    output is optional - pass NULL to not retrieve it. A value of 0 means that
    part of the accuracy is not present.

    \return 0 Returned on successfully getting the accuracy.
    \return BAD_FUNC_ARG Returned when tstInfo is NULL.

    \param [in] tstInfo Pointer to the TspTstInfo structure.
    \param [out] seconds Accuracy in seconds. May be NULL.
    \param [out] millis Accuracy in milliseconds. May be NULL.
    \param [out] micros Accuracy in microseconds. May be NULL.

    _Example_
    \code
    TspTstInfo tst;          // decoded TSTInfo
    word32 seconds;
    word16 millis;
    word16 micros;

    if (wc_TspTstInfo_GetAccuracy(&tst, &seconds, &millis, &micros) != 0) {
        // error getting accuracy
    }
    \endcode

    \sa wc_TspTstInfo_SetAccuracy
*/
int wc_TspTstInfo_GetAccuracy(const TspTstInfo* tstInfo, word32* seconds,
    word16* millis, word16* micros);

/*!
    \ingroup TSP

    \brief This function sets the accuracy of the time of a TSTInfo - how far
    the genTime may be off. A value of 0 for a part means it is not present.
    Milliseconds and microseconds must be 1..999 - checked on encode.

    \return 0 Returned on successfully setting the accuracy.
    \return BAD_FUNC_ARG Returned when tstInfo is NULL.

    \param [in,out] tstInfo Pointer to the TspTstInfo structure to update.
    \param [in] seconds Accuracy in seconds.
    \param [in] millis Accuracy in milliseconds.
    \param [in] micros Accuracy in microseconds.

    _Example_
    \code
    TspTstInfo tst;

    wc_TspTstInfo_Init(&tst);
    wc_TspTstInfo_SetAccuracy(&tst, 1, 0, 0);   // accurate to one second
    \endcode

    \sa wc_TspTstInfo_GetAccuracy
*/
int wc_TspTstInfo_SetAccuracy(TspTstInfo* tstInfo, word32 seconds,
    word16 millis, word16 micros);

/*!
    \ingroup TSP

    \brief This function gets the nonce of a TSTInfo. A reference is returned -
    the nonce is not copied and is valid while the TSTInfo references it. A
    length of 0 means no nonce is present.

    \return 0 Returned on successfully getting the nonce.
    \return BAD_FUNC_ARG Returned when tstInfo, nonce or nonceSz is NULL.

    \param [in] tstInfo Pointer to the TspTstInfo structure.
    \param [out] nonce Nonce as a big-endian number.
    \param [out] nonceSz Length of the nonce in bytes.

    _Example_
    \code
    TspTstInfo tst;          // decoded TSTInfo
    const byte* nonce;
    word32 nonceSz;

    if (wc_TspTstInfo_GetNonce(&tst, &nonce, &nonceSz) != 0) {
        // error getting nonce
    }
    \endcode

    \sa wc_TspTstInfo_SetNonce
*/
int wc_TspTstInfo_GetNonce(const TspTstInfo* tstInfo, const byte** nonce,
    word32* nonceSz);

/*!
    \ingroup TSP

    \brief This function sets the nonce of a TSTInfo. The nonce is referenced,
    not copied, and must remain available while the TSTInfo is used. It must
    match the request's nonce. Leading zero bytes are stripped, keeping at
    least one byte, so it has no leading zero byte and encodes.

    \return 0 Returned on successfully setting the nonce.
    \return BAD_FUNC_ARG Returned when tstInfo or nonce is NULL or nonceSz is 0.

    \param [in,out] tstInfo Pointer to the TspTstInfo structure to update.
    \param [in] nonce Nonce as a big-endian number.
    \param [in] nonceSz Length of the nonce in bytes.

    _Example_
    \code
    TspTstInfo tst;
    const byte* nonce;       // the request's nonce
    word32 nonceSz;

    wc_TspTstInfo_Init(&tst);
    wc_TspTstInfo_SetNonce(&tst, nonce, nonceSz);
    \endcode

    \sa wc_TspTstInfo_GetNonce
*/
int wc_TspTstInfo_SetNonce(TspTstInfo* tstInfo, const byte* nonce,
    word32 nonceSz);

/*!
    \ingroup TSP

    \brief This function sets the values of a TSTInfo to respond to a request.
    A convenience for a TSA building a response: it echoes the request's
    message imprint (copied) and nonce (referenced), and sets the TSA's policy,
    serial number and time. Initialize the TSTInfo with wc_TspTstInfo_Init()
    first. The request, policy, serial and genTime buffers are referenced - not
    copied, except the imprint - and must remain available while the TSTInfo is
    used.

    \return 0 Returned on successfully setting the values.
    \return BAD_FUNC_ARG Returned when tstInfo, req, policy or serial is NULL or
    policySz or serialSz is 0.

    \param [in,out] tstInfo Pointer to the TspTstInfo structure to set.
    \param [in] req Decoded request being time-stamped.
    \param [in] policy TSA policy as OBJECT IDENTIFIER content.
    \param [in] policySz Length of the policy in bytes.
    \param [in] serial Serial number of the time-stamp - big-endian. Leading
    zero bytes are stripped.
    \param [in] serialSz Length of the serial number in bytes.
    \param [in] genTime Time of the time-stamp as a GeneralizedTime string.
    NULL to use the current time on encode.
    \param [in] genTimeSz Length of genTime in bytes - 0 when NULL.

    _Example_
    \code
    TspRequest req;          // decoded request
    TspTstInfo tst;
    static const byte policy[] = { 0x2b, 0x06, 0x01, 0x04, 0x01 };
    static const byte serial[] = { 0x01 };

    wc_TspTstInfo_Init(&tst);
    wc_TspTstInfo_SetFromRequest(&tst, &req, policy, sizeof(policy),
        serial, sizeof(serial), NULL, 0);
    \endcode

    \sa wc_TspTstInfo_Init
    \sa wc_TspTstInfo_SignWithPkcs7
*/
int wc_TspTstInfo_SetFromRequest(TspTstInfo* tstInfo, const TspRequest* req,
    const byte* policy, word32 policySz, const byte* serial, word32 serialSz,
    const byte* genTime, word32 genTimeSz);

/*!
    \ingroup TSP

    \brief This function encodes a TSTInfo as DER - RFC 3161, 2.4.2. The
    policy, message imprint and serial number are required. When genTime is
    NULL the current time is used - requires a real time clock and is not
    available with NO_ASN_TIME, USER_TIME or TIME_OVERRIDES. The TSTInfo is
    the content that a TSA signs into a time-stamp token - see
    wc_TspTstInfo_SignWithPkcs7() which encodes and signs in one call.

    \return 0 Returned on successfully encoding the TSTInfo.
    \return BAD_FUNC_ARG Returned when tstInfo or outSz is NULL, a required
    field is not set or empty, the hash is too long, the genTime is not a
    valid GeneralizedTime, the tsa is empty, the serial number or nonce is
    empty or has a leading zero byte or accuracy millis or micros is out of
    range.
    \return BUFFER_E Returned when out is not NULL and the encoding is
    longer than outSz.
    \return ASN_UNKNOWN_OID_E Returned when the hash algorithm is not
    recognized.
    \return ASN_TIME_E Returned when getting the current time failed.
    \return MEMORY_E Returned on dynamic memory allocation failure.

    \param [in] tstInfo Pointer to the TspTstInfo structure to encode.
    \param [out] out Buffer to hold the encoding. May be NULL to get the
    length.
    \param [in,out] outSz On in, the length of the buffer in bytes. On out,
    the length of the encoding in bytes.

    _Example_
    \code
    TspTstInfo tst;
    byte der[512];
    word32 derSz = (word32)sizeof(der);

    // initialize tst and set required fields
    if (wc_TspTstInfo_Encode(&tst, der, &derSz) != 0) {
        // error encoding TSTInfo
    }
    \endcode

    \sa wc_TspTstInfo_Init
    \sa wc_TspTstInfo_Decode
    \sa wc_TspTstInfo_SignWithPkcs7
*/
int wc_TspTstInfo_Encode(const TspTstInfo* tstInfo, byte* out, word32* outSz);

/*!
    \ingroup TSP

    \brief This function decodes a DER encoded TSTInfo - RFC 3161, 2.4.2.
    Pointers in the structure reference into the input buffer - the buffer
    must remain available while the structure is in use. The message
    imprint hash is copied. TSTInfos with extensions are not supported and
    fail to decode. See wc_TspTstInfo_VerifyWithPKCS7() which verifies a token and
    decodes its TSTInfo.

    \return 0 Returned on successfully decoding the TSTInfo.
    \return BAD_FUNC_ARG Returned when tstInfo or input is NULL or inSz
    is 0.
    \return ASN_PARSE_E Returned when the encoding is invalid, the hash is
    empty, accuracy millis or micros is out of range, the genTime is not a
    valid GeneralizedTime or extensions are present.
    \return ASN_UNKNOWN_OID_E Returned when the hash algorithm OID check
    fails.
    \return BUFFER_E Returned when the hash is longer than
    WC_TSP_MAX_HASH_SZ bytes.
    \return MEMORY_E Returned on dynamic memory allocation failure.

    \param [out] tstInfo Pointer to the TspTstInfo structure to fill.
    \param [in] input Buffer holding the DER encoding.
    \param [in] inSz Length of the data in the buffer in bytes.

    _Example_
    \code
    TspTstInfo tst;
    byte* der;    // DER encoded TSTInfo
    word32 derSz; // length of DER encoded TSTInfo

    if (wc_TspTstInfo_Decode(&tst, der, derSz) != 0) {
        // error decoding TSTInfo
    }
    \endcode

    \sa wc_TspTstInfo_Encode
    \sa wc_TspTstInfo_VerifyWithPKCS7
*/
int wc_TspTstInfo_Decode(TspTstInfo* tstInfo, const byte* input, word32 inSz);

/*!
    \ingroup TSP

    \brief This function checks the genTime of a TSTInfo is close enough to
    the current time - RFC 3161, 2.4.2: the requester verifies the genTime
    is within an acceptable period of the local trusted time. Any fraction
    of a second in the genTime is ignored. Requires a real time clock and
    is not available with NO_ASN_TIME, USER_TIME or TIME_OVERRIDES.

    \return 0 Returned when the genTime is within the acceptable period.
    \return BAD_FUNC_ARG Returned when tstInfo or its genTime is NULL.
    \return ASN_PARSE_E Returned when the genTime string is not valid.
    \return ASN_TIME_E Returned when getting the current time failed.
    \return TSP_VERIFY_E Returned when the genTime is outside the
    acceptable period.

    \param [in] tstInfo Pointer to the decoded TspTstInfo structure from a
    response.
    \param [in] tolerance Acceptable time around the current time in
    seconds.

    _Example_
    \code
    TspTstInfo tst;
    // verify token and decode TSTInfo into tst

    // accept a time-stamp within five minutes of the current time
    if (wc_TspTstInfo_CheckGenTime(&tst, 300) != 0) {
        // time-stamp is not fresh
    }
    \endcode

    \sa wc_TspTstInfo_VerifyWithPKCS7
    \sa wc_TspTstInfo_CheckRequest
*/
int wc_TspTstInfo_CheckGenTime(const TspTstInfo* tstInfo, word32 tolerance);

/*!
    \ingroup TSP

    \brief This function gets the time of the time-stamp of a TSTInfo as a
    time_t. The genTime GeneralizedTime string of RFC 3161 is parsed - any
    fraction of a second is ignored. The time is UTC. Not available with
    NO_ASN_TIME.

    \return 0 Returned on successfully getting the time.
    \return BAD_FUNC_ARG Returned when tstInfo, its genTime or t is NULL.
    \return ASN_PARSE_E Returned when the genTime string is not valid.

    \param [in] tstInfo Pointer to the TspTstInfo structure to query.
    \param [out] t Time of the time-stamp as seconds since the Unix epoch.

    _Example_
    \code
    TspTstInfo tst;
    time_t t;
    // verify token and decode TSTInfo into tst

    if (wc_TspTstInfo_GetGenTimeAsTime(&tst, &t) != 0) {
        // genTime is not valid
    }
    \endcode

    \sa wc_TspTstInfo_SetGenTimeAsTime
    \sa wc_TspTstInfo_GetGenTime
*/
int wc_TspTstInfo_GetGenTimeAsTime(const TspTstInfo* tstInfo, time_t* t);

/*!
    \ingroup TSP

    \brief This function sets the time of the time-stamp of a TSTInfo from a
    time_t. The time is formatted as a GeneralizedTime string of RFC 3161
    into the caller's buffer and referenced - the buffer must remain
    available while the TSTInfo is used and be at least
    ASN_GENERALIZED_TIME_SIZE bytes. The time is treated as UTC. Not
    available with NO_ASN_TIME.

    \return 0 Returned on successfully setting the time.
    \return BAD_FUNC_ARG Returned when tstInfo or buf is NULL.
    \return BUFFER_E Returned when bufSz is too small for the GeneralizedTime
    string.
    \return ASN_TIME_E Returned when the time could not be converted.

    \param [in,out] tstInfo Pointer to the TspTstInfo structure to update.
    \param [in] t Time of the time-stamp as seconds since the Unix epoch.
    \param [out] buf Buffer to hold the formatted GeneralizedTime.
    \param [in] bufSz Length of buffer in bytes.

    _Example_
    \code
    TspTstInfo tst;
    byte buf[ASN_GENERALIZED_TIME_SIZE];

    wc_TspTstInfo_Init(&tst);
    wc_TspTstInfo_SetGenTimeAsTime(&tst, wc_Time(NULL), buf, sizeof(buf));
    \endcode

    \sa wc_TspTstInfo_GetGenTimeAsTime
    \sa wc_TspTstInfo_SetGenTime
*/
int wc_TspTstInfo_SetGenTimeAsTime(TspTstInfo* tstInfo, time_t t, byte* buf,
    word32 bufSz);

/*!
    \ingroup TSP

    \brief This function gets the TSA name of a TSTInfo. The tsa - the DER
    encoding of a GeneralName - is referenced, not copied, and is valid
    while the TSTInfo references it. A length of 0 means no TSA name is
    present.

    \return 0 Returned on successfully getting the TSA name.
    \return BAD_FUNC_ARG Returned when tstInfo, tsa or tsaSz is NULL.

    \param [in] tstInfo Pointer to the TspTstInfo structure to query.
    \param [out] tsa TSA name as the DER encoding of a GeneralName.
    \param [out] tsaSz Length of the TSA name in bytes.

    _Example_
    \code
    TspTstInfo tst;
    const byte* tsa = NULL;
    word32 tsaSz = 0;
    // verify token and decode TSTInfo into tst

    wc_TspTstInfo_GetTsa(&tst, &tsa, &tsaSz);
    \endcode

    \sa wc_TspTstInfo_SetTsa
*/
int wc_TspTstInfo_GetTsa(const TspTstInfo* tstInfo, const byte** tsa,
    word32* tsaSz);

/*!
    \ingroup TSP

    \brief This function sets the TSA name of a TSTInfo. The tsa is the DER
    encoding of a GeneralName - it is referenced, not copied, and must
    remain available while the TSTInfo is used.

    \return 0 Returned on successfully setting the TSA name.
    \return BAD_FUNC_ARG Returned when tstInfo or tsa is NULL or tsaSz is 0.

    \param [in,out] tstInfo Pointer to the TspTstInfo structure to update.
    \param [in] tsa TSA name as the DER encoding of a GeneralName.
    \param [in] tsaSz Length of the TSA name in bytes.

    _Example_
    \code
    TspTstInfo tst;
    // DER encoding of a GeneralName for the TSA
    static const byte tsa[] = { 0x82, 0x03, 't', 's', 'a' };

    wc_TspTstInfo_Init(&tst);
    wc_TspTstInfo_SetTsa(&tst, tsa, sizeof(tsa));
    \endcode

    \sa wc_TspTstInfo_GetTsa
*/
int wc_TspTstInfo_SetTsa(TspTstInfo* tstInfo, const byte* tsa, word32 tsaSz);

/*!
    \ingroup TSP

    \brief This function initializes a TimeStampResp structure for
    encoding. All fields are cleared - the status is granted.

    \return 0 Returned on successfully initializing the response.
    \return BAD_FUNC_ARG Returned when resp is NULL.

    \param [out] resp Pointer to the TspResponse structure to initialize.

    _Example_
    \code
    TspResponse resp;

    wc_TspResponse_Init(&resp);
    resp.status = WC_TSP_PKISTATUS_GRANTED;
    // set the token created with wc_TspTstInfo_SignWithPkcs7()
    \endcode

    \sa wc_TspResponse_Encode
    \sa wc_TspResponse_Decode
*/
int wc_TspResponse_Init(TspResponse* resp);

/*!
    \ingroup TSP

    \brief This function encodes a TimeStampResp as DER - RFC 3161, 2.4.2.
    The status string, when set, is encoded as a PKIFreeText with one
    UTF8String. The failure information, when not zero, is encoded as a
    BIT STRING of the WC_TSP_FAIL_* flags. The token, when set, is the
    complete DER encoding from wc_TspTstInfo_SignWithPkcs7().

    \return 0 Returned on successfully encoding the response.
    \return BAD_FUNC_ARG Returned when resp or outSz is NULL.
    \return BUFFER_E Returned when out is not NULL and the encoding is
    longer than outSz.
    \return MEMORY_E Returned on dynamic memory allocation failure.

    \param [in] resp Pointer to the TspResponse structure to encode.
    \param [out] out Buffer to hold the encoding. May be NULL to get the
    length.
    \param [in,out] outSz On in, the length of the buffer in bytes. On out,
    the length of the encoding in bytes.

    _Example_
    \code
    TspResponse resp;
    byte der[4096];
    word32 derSz = (word32)sizeof(der);

    wc_TspResponse_Init(&resp);
    resp.status = WC_TSP_PKISTATUS_REJECTION;
    resp.failInfo = WC_TSP_FAIL_BAD_ALG;
    if (wc_TspResponse_Encode(&resp, der, &derSz) != 0) {
        // error encoding response
    }
    \endcode

    \sa wc_TspResponse_Init
    \sa wc_TspTstInfo_SignWithPkcs7
    \sa wc_TspResponse_Decode
*/
int wc_TspResponse_Encode(const TspResponse* resp, byte* out, word32* outSz);

/*!
    \ingroup TSP

    \brief This function decodes a DER encoded TimeStampResp - RFC 3161,
    2.4.2. Pointers in the structure reference into the input buffer - the
    buffer must remain available while the structure is in use. The TSTInfo
    of the token is not validated or decoded - see wc_TspTstInfo_VerifyWithPKCS7().

    \return 0 Returned on successfully decoding the response.
    \return BAD_FUNC_ARG Returned when resp or input is NULL or inSz is 0.
    \return ASN_PARSE_E Returned when the encoding is invalid.
    \return MEMORY_E Returned on dynamic memory allocation failure.

    \param [out] resp Pointer to the TspResponse structure to fill.
    \param [in] input Buffer holding the DER encoding.
    \param [in] inSz Length of the data in the buffer in bytes.

    _Example_
    \code
    TspResponse resp;
    byte* der;    // DER encoded response received
    word32 derSz; // length of DER encoded response

    if (wc_TspResponse_Decode(&resp, der, derSz) != 0) {
        // error decoding response
    }
    if ((resp.status != WC_TSP_PKISTATUS_GRANTED) &&
            (resp.status != WC_TSP_PKISTATUS_GRANTED_WITH_MODS)) {
        // time-stamp not granted - see resp.failInfo
    }
    \endcode

    \sa wc_TspResponse_Encode
    \sa wc_TspTstInfo_VerifyWithPKCS7
*/
int wc_TspResponse_Decode(TspResponse* resp, const byte* input, word32 inSz);

/*!
    \ingroup TSP

    \brief This function gets the status information of a TimeStampResp. Each
    output is optional - pass NULL to not retrieve it. The status string and
    failure information are present only when set; a NULL status string and a
    failure information of 0 mean they are absent.

    \return 0 Returned on successfully getting the status information.
    \return BAD_FUNC_ARG Returned when resp is NULL.

    \param [in] resp Pointer to the TspResponse structure to query.
    \param [out] status PKIStatus value - see TspPkiStatus. May be NULL.
    \param [out] str Status text, UTF-8 encoded with no NUL terminator. May be
    NULL.
    \param [out] strSz Length of the status text in bytes. May be NULL.
    \param [out] failInfo Failure information - WC_TSP_FAIL_* flags. May be
    NULL.

    _Example_
    \code
    TspResponse resp;
    word32 status = 0;
    const byte* str = NULL;
    word32 strSz = 0;
    word32 failInfo = 0;
    // decode resp from a received response

    wc_TspResponse_GetStatus(&resp, &status, &str, &strSz, &failInfo);
    \endcode

    \sa wc_TspResponse_SetStatus
    \sa wc_TspStatus_ToString
    \sa wc_TspFailInfo_ToString
*/
int wc_TspResponse_GetStatus(const TspResponse* resp, word32* status,
    const byte** str, word32* strSz, word32* failInfo);

/*!
    \ingroup TSP

    \brief This function sets the status information of a TimeStampResp. The
    status string, when not NULL, is referenced - not copied - and must
    remain available while the response is used; a NULL string clears the
    status text. The failure information is the WC_TSP_FAIL_* flags or 0 when
    not present.

    \return 0 Returned on successfully setting the status information.
    \return BAD_FUNC_ARG Returned when resp is NULL.

    \param [in,out] resp Pointer to the TspResponse structure to update.
    \param [in] status PKIStatus value - see TspPkiStatus.
    \param [in] str Status text, UTF-8 encoded with no NUL terminator. May be
    NULL.
    \param [in] strSz Length of the status text in bytes.
    \param [in] failInfo Failure information - WC_TSP_FAIL_* flags or 0.

    _Example_
    \code
    TspResponse resp;

    wc_TspResponse_Init(&resp);
    wc_TspResponse_SetStatus(&resp, WC_TSP_PKISTATUS_REJECTION, NULL, 0,
        WC_TSP_FAIL_BAD_ALG);
    \endcode

    \sa wc_TspResponse_GetStatus
*/
int wc_TspResponse_SetStatus(TspResponse* resp, word32 status,
    const byte* str, word32 strSz, word32 failInfo);

/*!
    \ingroup TSP

    \brief This function returns a human-readable string for a PKIStatus
    value - see TspPkiStatus. An unknown value returns a generic string.

    \return A NUL-terminated, human-readable string for the status. Never
    NULL.

    \param [in] status PKIStatus value - see TspPkiStatus.

    _Example_
    \code
    word32 status = 0;
    // get status from a decoded response

    printf("status: %s\n", wc_TspStatus_ToString(status));
    \endcode

    \sa wc_TspResponse_GetStatus
    \sa wc_TspFailInfo_ToString
*/
const char* wc_TspStatus_ToString(word32 status);

/*!
    \ingroup TSP

    \brief This function returns a human-readable string for a single
    PKIFailureInfo flag - a WC_TSP_FAIL_* value. An unknown value returns a
    generic string.

    \return A NUL-terminated, human-readable string for the failure
    information flag. Never NULL.

    \param [in] failInfo A single WC_TSP_FAIL_* flag.

    _Example_
    \code
    word32 failInfo = WC_TSP_FAIL_BAD_ALG;

    printf("failure: %s\n", wc_TspFailInfo_ToString(failInfo));
    \endcode

    \sa wc_TspResponse_GetStatus
    \sa wc_TspStatus_ToString
*/
const char* wc_TspFailInfo_ToString(word32 failInfo);

/*!
    \ingroup TSP

    \brief This function checks the TSTInfo of a response against the
    request sent - RFC 3161, 2.4.2. The version is checked, the message
    imprint must be the same and, when in the request, the nonce and policy
    must be matched. The nonce is compared exactly. The genTime and the
    token's signature are not validated here - see
    wc_TspTstInfo_VerifyWithPKCS7() and wc_TspTstInfo_CheckGenTime().

    \return 0 Returned when the TSTInfo matches the request.
    \return BAD_FUNC_ARG Returned when tstInfo or req is NULL.
    \return ASN_VERSION_E Returned when the version is not supported.
    \return TSP_VERIFY_E Returned when a field of the TSTInfo does not
    match the request.

    \param [in] tstInfo Pointer to the decoded TspTstInfo structure from
    the response.
    \param [in] req Pointer to the TspRequest structure sent.

    _Example_
    \code
    TspTstInfo tst;
    TspRequest req; // the request sent
    // verify token and decode TSTInfo into tst

    if (wc_TspTstInfo_CheckRequest(&tst, &req) != 0) {
        // token is not for the request
    }
    \endcode

    \sa wc_TspTstInfo_VerifyWithPKCS7
    \sa wc_TspTstInfo_CheckGenTime
    \sa wc_TspTstInfo_CheckTsaName
*/
int wc_TspTstInfo_CheckRequest(const TspTstInfo* tstInfo, const TspRequest* req);

/*!
    \ingroup TSP

    \brief This function checks the TSA name of a TSTInfo is the expected
    name. The TSA name must be present and be the same encoding as the
    expected name - the DER encodings of the GeneralNames are compared
    exactly. The TSA name is also checked against the signer's certificate
    in wc_TspTstInfo_VerifyWithPKCS7() when present.

    \return 0 Returned when the TSA name is the expected name.
    \return BAD_FUNC_ARG Returned when tstInfo or tsa is NULL or tsaSz
    is 0.
    \return TSP_VERIFY_E Returned when the TSA name is not present or does
    not match the expected name.

    \param [in] tstInfo Pointer to the decoded TspTstInfo structure from
    the response.
    \param [in] tsa Expected name as a DER encoding of a GeneralName.
    \param [in] tsaSz Length of the expected name in bytes.

    _Example_
    \code
    TspTstInfo tst;
    // dNSName GeneralName: tsa.wolfssl.com
    static const byte name[] = {
        0x82, 0x0f, 't', 's', 'a', '.', 'w', 'o', 'l', 'f',
        's', 's', 'l', '.', 'c', 'o', 'm'
    };
    // verify token and decode TSTInfo into tst

    if (wc_TspTstInfo_CheckTsaName(&tst, name, (word32)sizeof(name)) != 0) {
        // token is not from the expected TSA
    }
    \endcode

    \sa wc_TspTstInfo_VerifyWithPKCS7
    \sa wc_TspTstInfo_CheckRequest
*/
int wc_TspTstInfo_CheckTsaName(const TspTstInfo* tstInfo, const byte* tsa,
    word32 tsaSz);

/*!
    \ingroup TSP

    \brief This function verifies the message imprint of a TSTInfo against the
    original data. It hashes the data with the TSTInfo's message imprint hash
    algorithm and compares the result to the imprint hash - confirming the
    time-stamp is over the given data. The caller does not need to hash the
    data first.

    \return 0 Returned when the hash of the data matches the message imprint.
    \return BAD_FUNC_ARG Returned when tstInfo or data is NULL.
    \return HASH_TYPE_E Returned when the imprint's hash algorithm is not
    supported.
    \return TSP_VERIFY_E Returned when the hash of the data does not match the
    message imprint.
    \return Other Returned, negative, on a hashing failure.

    \param [in] tstInfo Pointer to the TspTstInfo structure.
    \param [in] data Data that was time-stamped.
    \param [in] dataSz Length of the data in bytes.

    _Example_
    \code
    TspTstInfo tst;          // verified TSTInfo from a token
    byte* data;              // the original data
    word32 dataSz;

    if (wc_TspTstInfo_VerifyData(&tst, data, dataSz) != 0) {
        // time-stamp is not over this data
    }
    \endcode

    \sa wc_TspTstInfo_VerifyWithPKCS7
    \sa wc_TspResponse_VerifyData
*/
int wc_TspTstInfo_VerifyData(const TspTstInfo* tstInfo, const byte* data,
    word32 dataSz);

/*!
    \ingroup TSP

    \brief This function creates a time-stamp token signed with the TSA's
    certificate and private key. A convenience wrapper around
    wc_TspTstInfo_SignWithPkcs7() that creates and disposes of the PKCS7
    object. The TSA's certificate is included in the token.

    \return 0 Returned on successfully creating the token.
    \return BAD_FUNC_ARG Returned when a pointer argument is NULL, a length is
    0 or the key type is not supported.
    \return HASH_TYPE_E Returned when the hash algorithm is not available.
    \return BUFFER_E Returned when the encoding is longer than outSz.
    \return MEMORY_E Returned on dynamic memory allocation failure.

    \param [in] tstInfo Pointer to the TspTstInfo structure to encode and sign.
    \param [in] cert DER encoded certificate of the TSA.
    \param [in] certSz Length of the certificate in bytes.
    \param [in] key DER encoded private key of the TSA.
    \param [in] keySz Length of the private key in bytes.
    \param [in] keyType Type of the private key - WC_PK_TYPE_RSA or
    WC_PK_TYPE_ECDSA_SIGN.
    \param [in] hashType Hash algorithm for the signature - e.g.
    WC_HASH_TYPE_SHA256.
    \param [in] rng Random number generator.
    \param [out] out Buffer to hold the encoding.
    \param [in,out] outSz On in, the length of the buffer in bytes. On out, the
    length of the encoding in bytes.

    _Example_
    \code
    TspTstInfo tst;          // TSTInfo set from the request
    byte token[2048];
    word32 tokenSz = (word32)sizeof(token);
    WC_RNG rng;

    wc_InitRng(&rng);
    if (wc_TspTstInfo_Sign(&tst, cert, certSz, key, keySz, WC_PK_TYPE_RSA,
            WC_HASH_TYPE_SHA256, &rng, token, &tokenSz) != 0) {
        // error creating token
    }
    \endcode

    \sa wc_TspTstInfo_SignWithPkcs7
    \sa wc_TspTstInfo_SetFromRequest
*/
int wc_TspTstInfo_Sign(const TspTstInfo* tstInfo,
    const byte* cert, word32 certSz, const byte* key, word32 keySz,
    enum wc_PkType keyType, enum wc_HashType hashType, WC_RNG* rng,
    byte* out, word32* outSz);

/*!
    \ingroup TSP

    \brief This function creates a time-stamp token - a CMS SignedData with
    the encoded TSTInfo as content of type id-ct-TSTInfo. The PKCS7 object
    must be initialized with the certificate and private key of the TSA,
    and the hash algorithm, encryption algorithm and RNG set. A
    SigningCertificateV2 signed attribute identifying the TSA's certificate
    is added as required by RFC 3161, 2.4.2. The TSA's certificate is
    included in the token - when the request did not set certReq set the
    PKCS7 object's noCerts field so that it is not.

    \return 0 Returned on successfully creating the token.
    \return BAD_FUNC_ARG Returned when tstInfo, pkcs7, out or outSz is NULL
    or the signer's certificate is not set.
    \return BUFFER_E Returned when the encoding is longer than outSz.
    \return MEMORY_E Returned on dynamic memory allocation failure.

    \param [in] tstInfo Pointer to the TspTstInfo structure to encode and
    sign.
    \param [in] pkcs7 Pointer to the PKCS7 object with the signer
    configured.
    \param [out] out Buffer to hold the encoding.
    \param [in,out] outSz On in, the length of the buffer in bytes. On out,
    the length of the encoding in bytes.

    _Example_
    \code
    wc_PKCS7* pkcs7;
    WC_RNG rng;
    TspTstInfo tst;
    byte token[4096];
    word32 tokenSz = (word32)sizeof(token);

    // initialize rng and tst
    pkcs7 = wc_PKCS7_New(NULL, INVALID_DEVID);
    wc_PKCS7_InitWithCert(pkcs7, tsaCert, tsaCertSz);
    pkcs7->rng = &rng;
    pkcs7->hashOID = SHA256h;
    pkcs7->encryptOID = RSAk;
    pkcs7->privateKey = tsaKey;
    pkcs7->privateKeySz = tsaKeySz;
    if (wc_TspTstInfo_SignWithPkcs7(&tst, pkcs7, token, &tokenSz) != 0) {
        // error creating token
    }
    wc_PKCS7_Free(pkcs7);
    \endcode

    \sa wc_TspTstInfo_Init
    \sa wc_TspResponse_Encode
    \sa wc_TspTstInfo_VerifyWithPKCS7
*/
int wc_TspTstInfo_SignWithPkcs7(const TspTstInfo* tstInfo, wc_PKCS7* pkcs7,
    byte* out, word32* outSz);

/*!
    \ingroup TSP

    \brief This function verifies a time-stamp token and decodes the
    TSTInfo content. The token must have a single SignerInfo and content of
    type id-ct-TSTInfo. The signature of the CMS SignedData is verified
    with the certificates in the token - when the token does not include
    certificates, initialize the PKCS7 object with the TSA's certificate.
    The signer's certificate must have a critical extended key usage of
    time-stamping only, a key usage that is signing only when present and
    be the certificate identified by the ESS signing certificate attribute.
    Only the certHash of the first ESSCertID(v2) of the attribute is
    checked. The TSA name of the TSTInfo, when present, must correspond to
    a subject name of the signer's certificate. Trust in the TSA's
    certificate must be established by the caller. Define
    WC_TSP_MIN_HASH_STRENGTH_BITS to require a minimum security strength of
    the hash algorithms used.

    Pointers in tstInfo reference the content of the PKCS7 object - the
    PKCS7 object and the token buffer must remain available while tstInfo
    is in use.

    \return 0 Returned on successfully verifying the token.
    \return BAD_FUNC_ARG Returned when pkcs7 or token is NULL or tokenSz
    is 0.
    \return PKCS7_OID_E Returned when the content is not a TSTInfo.
    \return EXTKEYUSAGE_E Returned when the signer's extended key usage is
    not critical or not time-stamping only.
    \return KEYUSAGE_E Returned when the signer's key usage is not for
    signing only.
    \return TSP_VERIFY_E Returned when the token does not have exactly one
    SignerInfo, no signing certificate attribute is found or it does not
    match the signer's certificate or the TSA name does not match the
    signer's certificate.
    \return HASH_TYPE_E Returned when a hash algorithm is not available or
    below WC_TSP_MIN_HASH_STRENGTH_BITS.
    \return ASN_PARSE_E Returned when an encoding is invalid.
    \return MEMORY_E Returned on dynamic memory allocation failure.

    \param [in] pkcs7 Pointer to an initialized PKCS7 object.
    \param [in,out] token Buffer holding the DER encoding of the token.
    \param [in] tokenSz Length of the data in the buffer in bytes.
    \param [out] tstInfo Pointer to the TspTstInfo structure to fill. May
    be NULL.

    _Example_
    \code
    wc_PKCS7* pkcs7;
    TspResponse resp;
    TspTstInfo tst;
    // decode response into resp and check status is granted

    pkcs7 = wc_PKCS7_New(NULL, INVALID_DEVID);
    wc_PKCS7_InitWithCert(pkcs7, NULL, 0);
    if (wc_TspTstInfo_VerifyWithPKCS7(pkcs7, (byte*)resp.token, resp.tokenSz,
            &tst) != 0) {
        // token did not verify
    }
    // check tst against the request and establish trust in the signer
    wc_PKCS7_Free(pkcs7); // tst references pkcs7 - free after use
    \endcode

    \sa wc_TspResponse_Decode
    \sa wc_TspTstInfo_CheckRequest
    \sa wc_TspTstInfo_CheckGenTime
    \sa wc_TspTstInfo_CheckTsaName
*/
int wc_TspTstInfo_VerifyWithPKCS7(wc_PKCS7* pkcs7, byte* token, word32 tokenSz,
    TspTstInfo* tstInfo);

/*!
    \ingroup TSP

    \brief This function verifies the time-stamp token of a response and
    decodes its TSTInfo content. A convenience wrapper around
    wc_TspTstInfo_VerifyWithPKCS7() that manages the PKCS7 object. The response
    must be granted and have a token. When cert is not NULL, the signer must
    be that trusted TSA certificate; the certificate is also used to verify
    the signature when the token does not include the signer's certificate.
    When cert is NULL the token must include the signer's certificate and
    trust must be established by other means.

    Pointers in tstInfo reference the token of the response - the response
    and its token buffer must remain available while tstInfo is in use.

    \return 0 Returned on successfully verifying the response.
    \return BAD_FUNC_ARG Returned when resp is NULL.
    \return TSP_VERIFY_E Returned when the response was not granted, has no
    token, the token does not verify or the signer is not the trusted TSA
    certificate.
    \return MEMORY_E Returned on dynamic memory allocation failure.

    \param [in] resp Pointer to the TspResponse structure with a token to
    verify.
    \param [in] cert DER encoded certificate of the trusted TSA. May be NULL
    when the token includes the signer's certificate.
    \param [in] certSz Length of the certificate in bytes.
    \param [out] tstInfo Pointer to the TspTstInfo structure to fill. May be
    NULL.

    _Example_
    \code
    TspResponse resp;
    TspTstInfo tst;
    // decode resp from a received response

    if (wc_TspResponse_Verify(&resp, tsaCert, tsaCertSz, &tst) != 0) {
        // response did not verify
    }
    \endcode

    \sa wc_TspTstInfo_VerifyWithPKCS7
    \sa wc_TspTstInfo_CheckRequest
    \sa wc_TspTstInfo_CheckGenTime
*/
int wc_TspResponse_Verify(TspResponse* resp, const byte* cert, word32 certSz,
    TspTstInfo* tstInfo);

/*!
    \ingroup TSP

    \brief This function verifies the time-stamp token of a response, trusting
    the signer via a certificate manager. A convenience wrapper around
    wc_TspTstInfo_VerifyWithPKCS7() that manages the PKCS7 object. The response
    must be granted and have a token. The token's signature is verified and the
    signer's certificate checked, then the signer's certificate is verified to
    chain to a trusted CA in the manager. The token must include the signer's
    certificate - the manager must hold the trust anchor and any intermediate
    CAs needed to build the chain. Certificates carried in the token are used
    to verify the token's signature but are not trusted as CAs.

    Pointers in tstInfo reference the token of the response - the response and
    its token buffer must remain available while tstInfo is in use.

    \return 0 Returned on successfully verifying the response.
    \return BAD_FUNC_ARG Returned when resp or cm is NULL.
    \return TSP_VERIFY_E Returned when the response was not granted, has no
    token, the token does not verify or the signer does not chain to a trusted
    CA.
    \return MEMORY_E Returned on dynamic memory allocation failure.

    \param [in] resp Pointer to the TspResponse structure with a token to
    verify.
    \param [in] cm WOLFSSL_CERT_MANAGER with the trusted CAs - passed as a void
    pointer to avoid an SSL layer dependency.
    \param [out] tstInfo Pointer to the TspTstInfo structure to fill. May be
    NULL.

    _Example_
    \code
    TspResponse resp;
    TspTstInfo tst;
    WOLFSSL_CERT_MANAGER* cm;  // loaded with the trust anchor and intermediates
    // decode resp from a received response

    if (wc_TspResponse_VerifyWithCm(&resp, cm, &tst) != 0) {
        // response did not verify
    }
    \endcode

    \sa wc_TspResponse_Verify
    \sa wc_TspResponse_VerifyData
*/
int wc_TspResponse_VerifyWithCm(TspResponse* resp, void* cm,
    TspTstInfo* tstInfo);

/*!
    \ingroup TSP

    \brief This function verifies the time-stamp token of a response and that
    it is over the given data. A convenience over wc_TspResponse_Verify() that
    also confirms the time-stamp is over the data - hashing the data with the
    token's message imprint algorithm and comparing to the imprint. The caller
    does not hash the data.

    \return 0 Returned on successfully verifying the response and data.
    \return BAD_FUNC_ARG Returned when resp or data is NULL.
    \return TSP_VERIFY_E Returned when the token does not verify or the data
    does not match the message imprint.
    \return HASH_TYPE_E Returned when the imprint's hash algorithm is not
    supported.
    \return MEMORY_E Returned on dynamic memory allocation failure.

    \param [in] resp Pointer to the TspResponse structure with a token to
    verify.
    \param [in] cert DER encoded certificate of the trusted TSA. May be NULL -
    see wc_TspResponse_Verify().
    \param [in] certSz Length of the certificate in bytes.
    \param [in] data Data that was time-stamped.
    \param [in] dataSz Length of the data in bytes.
    \param [out] tstInfo Pointer to the TspTstInfo structure to fill. May be
    NULL.

    _Example_
    \code
    TspResponse resp;
    byte* data;              // the original data
    word32 dataSz;
    // decode resp from a received response

    if (wc_TspResponse_VerifyData(&resp, tsaCert, tsaCertSz, data, dataSz,
            NULL) != 0) {
        // response did not verify or is not over this data
    }
    \endcode

    \sa wc_TspResponse_Verify
    \sa wc_TspTstInfo_VerifyData
*/
int wc_TspResponse_VerifyData(TspResponse* resp, const byte* cert,
    word32 certSz, const byte* data, word32 dataSz, TspTstInfo* tstInfo);
