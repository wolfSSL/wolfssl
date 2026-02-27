/*!
    \ingroup PKCS7

    \brief Callback used for a custom AES key wrap/unwrap operation.

    \return The size of the wrapped/unwrapped key written to the output buffer
    should be returned on success. A 0 return value or error code (< 0)
    indicates a failure.

    \param[in] key Specify the key to use.
    \param[in] keySz Size of the key to use.
    \param[in] in Specify the input data to wrap/unwrap.
    \param[in] inSz Size of the input data.
    \param[in] wrap 1 if the requested operation is a key wrap, 0 for unwrap.
    \param[out] out Specify the output buffer.
    \param[out] outSz Size of the output buffer.
*/
typedef int (*CallbackAESKeyWrapUnwrap)(const byte* key, word32 keySz,
        const byte* in, word32 inSz, int wrap, byte* out, word32 outSz);

/*!
    \ingroup PKCS7

    \brief This function initializes a PKCS7 structure with a DER-formatted
    certificate. To initialize an empty PKCS7 structure, one can pass in a NULL
    cert and 0 for certSz.

    \return 0 Returned on successfully initializing the PKCS7 structure
    \return MEMORY_E Returned if there is an error allocating memory
    with XMALLOC
    \return ASN_PARSE_E Returned if there is an error parsing the cert header
    \return ASN_OBJECT_ID_E Returned if there is an error parsing the
    encryption type from the cert
    \return ASN_EXPECT_0_E Returned if there is a formatting error in the
    encryption specification of the cert file
    \return ASN_BEFORE_DATE_E Returned if the date is before the certificate
    start date
    \return ASN_AFTER_DATE_E Returned if the date is after the certificate
    expiration date
    \return ASN_BITSTR_E Returned if there is an error parsing a bit string
    from the certificate
    \return ECC_CURVE_OID_E Returned if there is an error parsing the ECC
    key from the certificate
    \return ASN_UNKNOWN_OID_E Returned if the certificate is using an unknown
    key object id
    \return ASN_VERSION_E Returned if the ALLOW_V1_EXTENSIONS option is not
    defined and the certificate is a V1 or V2 certificate
    \return BAD_FUNC_ARG Returned if there is an error processing the
    certificate extension
    \return ASN_CRIT_EXT_E Returned if an unfamiliar critical extension is
    encountered in processing the certificate
    \return ASN_SIG_OID_E Returned if the signature encryption type is not
    the same as the encryption type of the certificate in the provided file
    \return ASN_SIG_CONFIRM_E Returned if confirming the certification
    signature fails
    \return ASN_NAME_INVALID_E Returned if the certificate’s name is not
    permitted by the CA name constraints
    \return ASN_NO_SIGNER_E Returned if there is no CA signer to verify
    the certificate’s authenticity

    \param pkcs7 pointer to the PKCS7 structure in which to
    store the decoded cert
    \param der pointer to a buffer containing a DER formatted ASN.1
    certificate with which to initialize the PKCS7 structure
    \param derSz size of the certificate buffer

    _Example_
    \code
    wc_PKCS7 pkcs7;
    byte derBuff[] = { }; // initialize with DER-encoded certificate
    if ( wc_PKCS7_InitWithCert(&pkcs7, derBuff, sizeof(derBuff)) != 0 ) {
    	// error parsing certificate into pkcs7 format
    }
    \endcode

    \sa wc_PKCS7_Free
*/
int  wc_PKCS7_InitWithCert(wc_PKCS7* pkcs7, byte* der, word32 derSz);

/*!
    \ingroup PKCS7

    \brief This function releases any memory allocated by a PKCS7 initializer.

    \return none No returns.

    \param pkcs7 pointer to the PKCS7 structure to free

    _Example_
    \code
    PKCS7 pkcs7;
    // initialize and use PKCS7 object

    wc_PKCS7_Free(pkcs7);
    \endcode

    \sa wc_PKCS7_InitWithCert
*/
void wc_PKCS7_Free(wc_PKCS7* pkcs7);

/*!
    \ingroup PKCS7

    \brief This function builds the PKCS7 data content type, encoding the
    PKCS7 structure into a buffer containing a parsable PKCS7 data packet.

    \return Success On successfully encoding the PKCS7 data into the buffer,
    returns the index parsed up to in the PKCS7 structure. This index also
    corresponds to the bytes written to the output buffer.
    \return BUFFER_E Returned if the given buffer is not large enough to hold
    the encoded certificate

    \param pkcs7 pointer to the PKCS7 structure to encode
    \param output pointer to the buffer in which to store the encoded
    certificate
    \param outputSz size available in the output buffer

    _Example_
    \code
    PKCS7 pkcs7;
    int ret;

    byte derBuff[] = { }; // initialize with DER-encoded certificate
    byte pkcs7Buff[FOURK_BUF];

    wc_PKCS7_InitWithCert(&pkcs7, derBuff, sizeof(derBuff));
    // update message and data to encode
    pkcs7.privateKey = key;
    pkcs7.privateKeySz = keySz;
    pkcs7.content = data;
    pkcs7.contentSz = dataSz;
    ... etc.

    ret = wc_PKCS7_EncodeData(&pkcs7, pkcs7Buff, sizeof(pkcs7Buff));
    if ( ret != 0 ) {
	    // error encoding into output buffer
    }
    \endcode

    \sa wc_PKCS7_InitWithCert
*/
int  wc_PKCS7_EncodeData(wc_PKCS7* pkcs7, byte* output,
                                       word32 outputSz);

/*!
    \ingroup PKCS7

    \brief This function builds the PKCS7 signed data content type, encoding
    the PKCS7 structure into a buffer containing a parsable PKCS7
    signed data packet. For RSA-PSS signers (WC_RSA_PSS), see \ref PKCS7_RSA_PSS.

    \return Success On successfully encoding the PKCS7 data into the buffer,
    returns the index parsed up to in the PKCS7 structure. This index also
    corresponds to the bytes written to the output buffer.
    \return BAD_FUNC_ARG Returned if the PKCS7 structure is missing one or
    more required elements to generate a signed data packet
    \return MEMORY_E Returned if there is an error allocating memory
    \return PUBLIC_KEY_E Returned if there is an error parsing the public key
    \return RSA_BUFFER_E Returned if buffer error, output too small or input
    too large
    \return BUFFER_E Returned if the given buffer is not large enough to hold
    the encoded certificate
    \return MP_INIT_E may be returned if there is an error generating
    the signature
    \return MP_READ_E may be returned if there is an error generating
    the signature
    \return MP_CMP_E may be returned if there is an error generating
    the signature
    \return MP_INVMOD_E may be returned if there is an error generating
    the signature
    \return MP_EXPTMOD_E may be returned if there is an error generating
    the signature
    \return MP_MOD_E may be returned if there is an error generating
    the signature
    \return MP_MUL_E may be returned if there is an error generating
    the signature
    \return MP_ADD_E may be returned if there is an error generating
    the signature
    \return MP_MULMOD_E may be returned if there is an error generating
    the signature
    \return MP_TO_E may be returned if there is an error generating
    the signature
    \return MP_MEM may be returned if there is an error generating the signature

    \param pkcs7 pointer to the PKCS7 structure to encode
    \param output pointer to the buffer in which to store the
    encoded certificate
    \param outputSz size available in the output buffer

    _Example_
    \code
    PKCS7 pkcs7;
    int ret;

    byte data[] = {}; // initialize with data to sign
    byte derBuff[] = { }; // initialize with DER-encoded certificate
    byte pkcs7Buff[FOURK_BUF];

    wc_PKCS7_InitWithCert(&pkcs7, derBuff, sizeof(derBuff));
    // update message and data to encode
    pkcs7.privateKey = key;
    pkcs7.privateKeySz = keySz;
    pkcs7.content = data;
    pkcs7.contentSz = dataSz;
    pkcs7.hashOID = SHAh;
    pkcs7.rng = &rng;
    ... etc.

    ret = wc_PKCS7_EncodeSignedData(&pkcs7, pkcs7Buff, sizeof(pkcs7Buff));
    if ( ret != 0 ) {
    	// error encoding into output buffer
    }

    wc_PKCS7_Free(&pkcs7);
    \endcode

    \sa wc_PKCS7_InitWithCert
    \sa wc_PKCS7_VerifySignedData
*/
int  wc_PKCS7_EncodeSignedData(wc_PKCS7* pkcs7,
                                       byte* output, word32 outputSz);

/*!
    \ingroup PKCS7

    \brief This function builds the PKCS7 signed data content type, encoding
    the PKCS7 structure into a header and footer buffer containing a parsable PKCS7
    signed data packet. This does not include the content.
    A hash must be computed and provided for the data

    \return 0=Success
    \return BAD_FUNC_ARG Returned if the PKCS7 structure is missing one or
    more required elements to generate a signed data packet
    \return MEMORY_E Returned if there is an error allocating memory
    \return PUBLIC_KEY_E Returned if there is an error parsing the public key
    \return RSA_BUFFER_E Returned if buffer error, output too small or input
    too large
    \return BUFFER_E Returned if the given buffer is not large enough to hold
    the encoded certificate
    \return MP_INIT_E may be returned if there is an error generating
    the signature
    \return MP_READ_E may be returned if there is an error generating
    the signature
    \return MP_CMP_E may be returned if there is an error generating
    the signature
    \return MP_INVMOD_E may be returned if there is an error generating
    the signature
    \return MP_EXPTMOD_E may be returned if there is an error generating
    the signature
    \return MP_MOD_E may be returned if there is an error generating
    the signature
    \return MP_MUL_E may be returned if there is an error generating
    the signature
    \return MP_ADD_E may be returned if there is an error generating
    the signature
    \return MP_MULMOD_E may be returned if there is an error generating
    the signature
    \return MP_TO_E may be returned if there is an error generating
    the signature
    \return MP_MEM may be returned if there is an error generating the signature

    \param pkcs7 pointer to the PKCS7 structure to encode
    \param hashBuf pointer to computed hash for the content data
    \param hashSz size of the digest
    \param outputHead pointer to the buffer in which to store the
    encoded certificate header
    \param outputHeadSz pointer populated with size of output header buffer
    and returns actual size
    \param outputFoot pointer to the buffer in which to store the
    encoded certificate footer
    \param outputFootSz pointer populated with size of output footer buffer
    and returns actual size

    _Example_
    \code
    PKCS7 pkcs7;
    int ret;
    byte derBuff[] = { }; // initialize with DER-encoded certificate
    byte data[] = {}; // initialize with data to sign
    byte pkcs7HeadBuff[FOURK_BUF/2];
    byte pkcs7FootBuff[FOURK_BUF/2];
    word32 pkcs7HeadSz = (word32)sizeof(pkcs7HeadBuff);
    word32 pkcs7FootSz = (word32)sizeof(pkcs7HeadBuff);
    enum wc_HashType hashType = WC_HASH_TYPE_SHA;
    byte   hashBuf[WC_MAX_DIGEST_SIZE];
    word32 hashSz = wc_HashGetDigestSize(hashType);

    wc_PKCS7_InitWithCert(&pkcs7, derBuff, sizeof(derBuff));
    // update message and data to encode
    pkcs7.privateKey = key;
    pkcs7.privateKeySz = keySz;
    pkcs7.content = NULL;
    pkcs7.contentSz = dataSz;
    pkcs7.hashOID = SHAh;
    pkcs7.rng = &rng;
    ... etc.

    // calculate hash for content
    ret = wc_HashInit(&hash, hashType);
    if (ret == 0) {
        ret = wc_HashUpdate(&hash, hashType, data, sizeof(data));
        if (ret == 0) {
            ret = wc_HashFinal(&hash, hashType, hashBuf);
        }
        wc_HashFree(&hash, hashType);
    }

    ret = wc_PKCS7_EncodeSignedData_ex(&pkcs7, hashBuf, hashSz, pkcs7HeadBuff,
        &pkcs7HeadSz, pkcs7FootBuff, &pkcs7FootSz);
    if ( ret != 0 ) {
        // error encoding into output buffer
    }

    wc_PKCS7_Free(&pkcs7);
    \endcode

    \sa wc_PKCS7_InitWithCert
    \sa wc_PKCS7_VerifySignedData_ex
*/
int wc_PKCS7_EncodeSignedData_ex(wc_PKCS7* pkcs7, const byte* hashBuf,
    word32 hashSz, byte* outputHead, word32* outputHeadSz, byte* outputFoot,
    word32* outputFootSz);

/*!
    \ingroup PKCS7

    \brief This function takes in a transmitted PKCS7 signed data message,
    extracts the certificate list and certificate revocation list, and then
    verifies the signature. It stores the extracted content in the given
    PKCS7 structure.

    \return 0 Returned on successfully extracting the information
    from the message
    \return BAD_FUNC_ARG Returned if one of the input parameters is invalid
    \return ASN_PARSE_E Returned if there is an error parsing the given pkiMsg
    \return PKCS7_OID_E Returned if the given pkiMsg is not a signed data type
    \return ASN_VERSION_E Returned if the PKCS7 signer info is not version 1
    \return MEMORY_E Returned if there is an error allocating memory
    \return PUBLIC_KEY_E Returned if there is an error parsing the public key
    \return RSA_BUFFER_E Returned if buffer error, output too small or
    input too large
    \return BUFFER_E Returned if the given buffer is not large enough to
    hold the encoded certificate
    \return MP_INIT_E may be returned if there is an error generating
    the signature
    \return MP_READ_E may be returned if there is an error generating
    the signature
    \return MP_CMP_E may be returned if there is an error generating
    the signature
    \return MP_INVMOD_E may be returned if there is an error generating
    the signature
    \return MP_EXPTMOD_E may be returned if there is an error generating
    the signature
    \return MP_MOD_E may be returned if there is an error generating
    the signature
    \return MP_MUL_E may be returned if there is an error generating
    the signature
    \return MP_ADD_E may be returned if there is an error generating
    the signature
    \return MP_MULMOD_E may be returned if there is an error generating
    the signature
    \return MP_TO_E may be returned if there is an error generating
    the signature
    \return MP_MEM may be returned if there is an error generating the signature

    \param pkcs7 pointer to the PKCS7 structure in which to store the parsed
    certificates
    \param pkiMsg pointer to the buffer containing the signed message to verify
    and decode
    \param pkiMsgSz size of the signed message

    _Example_
    \code
    PKCS7 pkcs7;
    int ret;
    byte pkcs7Buff[] = {}; // the PKCS7 signature

    wc_PKCS7_InitWithCert(&pkcs7, NULL, 0);
    // update message and data to encode
    pkcs7.privateKey = key;
    pkcs7.privateKeySz = keySz;
    pkcs7.content = data;
    pkcs7.contentSz = dataSz;
    ... etc.

    ret = wc_PKCS7_VerifySignedData(&pkcs7, pkcs7Buff, sizeof(pkcs7Buff));
    if ( ret != 0 ) {
    	// error encoding into output buffer
    }

    wc_PKCS7_Free(&pkcs7);
    \endcode

    \sa wc_PKCS7_InitWithCert
    \sa wc_PKCS7_EncodeSignedData
*/
int  wc_PKCS7_VerifySignedData(wc_PKCS7* pkcs7,
                                       byte* pkiMsg, word32 pkiMsgSz);


/*!
    \ingroup PKCS7

    \brief This function takes in a transmitted PKCS7 signed data message as
    hash/header/footer, then extracts the certificate list and certificate
    revocation list, and then verifies the signature. It stores the extracted
    content in the given PKCS7 structure.

    \return 0 Returned on successfully extracting the information
    from the message
    \return BAD_FUNC_ARG Returned if one of the input parameters is invalid
    \return ASN_PARSE_E Returned if there is an error parsing the given pkiMsg
    \return PKCS7_OID_E Returned if the given pkiMsg is not a signed data type
    \return ASN_VERSION_E Returned if the PKCS7 signer info is not version 1
    \return MEMORY_E Returned if there is an error allocating memory
    \return PUBLIC_KEY_E Returned if there is an error parsing the public key
    \return RSA_BUFFER_E Returned if buffer error, output too small or
    input too large
    \return BUFFER_E Returned if the given buffer is not large enough to
    hold the encoded certificate
    \return MP_INIT_E may be returned if there is an error generating
    the signature
    \return MP_READ_E may be returned if there is an error generating
    the signature
    \return MP_CMP_E may be returned if there is an error generating
    the signature
    \return MP_INVMOD_E may be returned if there is an error generating
    the signature
    \return MP_EXPTMOD_E may be returned if there is an error generating
    the signature
    \return MP_MOD_E may be returned if there is an error generating
    the signature
    \return MP_MUL_E may be returned if there is an error generating
    the signature
    \return MP_ADD_E may be returned if there is an error generating
    the signature
    \return MP_MULMOD_E may be returned if there is an error generating
    the signature
    \return MP_TO_E may be returned if there is an error generating
    the signature
    \return MP_MEM may be returned if there is an error generating the signature

    \param pkcs7 pointer to the PKCS7 structure in which to store the parsed
    certificates
    \param hashBuf pointer to computed hash for the content data
    \param hashSz size of the digest
    \param pkiMsgHead pointer to the buffer containing the signed message header
    to verify and decode
    \param pkiMsgHeadSz size of the signed message header
    \param pkiMsgFoot pointer to the buffer containing the signed message footer
    to verify and decode
    \param pkiMsgFootSz size of the signed message footer

    _Example_
    \code
    PKCS7 pkcs7;
    int ret;
    byte data[] = {}; // initialize with data to sign
    byte pkcs7HeadBuff[] = {}; // initialize with PKCS7 header
    byte pkcs7FootBuff[] = {}; // initialize with PKCS7 footer
    enum wc_HashType hashType = WC_HASH_TYPE_SHA;
    byte   hashBuf[WC_MAX_DIGEST_SIZE];
    word32 hashSz = wc_HashGetDigestSize(hashType);

    wc_PKCS7_InitWithCert(&pkcs7, NULL, 0);
    // update message and data to encode
    pkcs7.privateKey = key;
    pkcs7.privateKeySz = keySz;
    pkcs7.content = NULL;
    pkcs7.contentSz = dataSz;
    pkcs7.rng = &rng;
    ... etc.

    // calculate hash for content
    ret = wc_HashInit(&hash, hashType);
    if (ret == 0) {
        ret = wc_HashUpdate(&hash, hashType, data, sizeof(data));
        if (ret == 0) {
            ret = wc_HashFinal(&hash, hashType, hashBuf);
        }
        wc_HashFree(&hash, hashType);
    }

    ret = wc_PKCS7_VerifySignedData_ex(&pkcs7, hashBuf, hashSz, pkcs7HeadBuff,
        sizeof(pkcs7HeadBuff), pkcs7FootBuff, sizeof(pkcs7FootBuff));
    if ( ret != 0 ) {
        // error encoding into output buffer
    }

    wc_PKCS7_Free(&pkcs7);
    \endcode

    \sa wc_PKCS7_InitWithCert
    \sa wc_PKCS7_EncodeSignedData_ex
*/
int wc_PKCS7_VerifySignedData_ex(wc_PKCS7* pkcs7, const byte* hashBuf,
    word32 hashSz, byte* pkiMsgHead, word32 pkiMsgHeadSz, byte* pkiMsgFoot,
    word32 pkiMsgFootSz);

/*!
    \ingroup PKCS7

    \brief Set the callback function to be used to perform a custom AES key
    wrap/unwrap operation.

    \retval 0 Callback function was set successfully
    \retval BAD_FUNC_ARG Parameter pkcs7 is NULL

    \param pkcs7 pointer to the PKCS7 structure
    \param aesKeyWrapCb pointer to custom AES key wrap/unwrap function
*/
int wc_PKCS7_SetAESKeyWrapUnwrapCb(wc_PKCS7* pkcs7,
        CallbackAESKeyWrapUnwrap aesKeyWrapCb);

/*!
    \ingroup PKCS7

    \brief This function builds the PKCS7 enveloped data content type, encoding
    the PKCS7 structure into a buffer containing a parsable PKCS7 enveloped
    data packet.

    \return Success Returned on successfully encoding the message in enveloped
    data format, returns the size written to the output buffer
    \return BAD_FUNC_ARG: Returned if one of the input parameters is invalid,
    or if the PKCS7 structure is missing required elements
    \return ALGO_ID_E Returned if the PKCS7 structure is using an unsupported
    algorithm type. Currently, only DESb and DES3b are supported
    \return BUFFER_E Returned if the given output buffer is too small to store
    the output data
    \return MEMORY_E Returned if there is an error allocating memory
    \return RNG_FAILURE_E Returned if there is an error initializing the random
    number generator for encryption
    \return DRBG_FAILED Returned if there is an error generating numbers with
    the random number generator used for encryption
    \return NOT_COMPILED_IN may be returned if using an ECC key and wolfssl was
    built without HAVE_X963_KDF support

    \param pkcs7 pointer to the PKCS7 structure to encode
    \param output pointer to the buffer in which to store the encoded
    certificate
    \param outputSz size available in the output buffer

    _Example_
    \code
    PKCS7 pkcs7;
    int ret;

    byte derBuff[] = { }; // initialize with DER-encoded certificate
    byte pkcs7Buff[FOURK_BUF];

    wc_PKCS7_InitWithCert(&pkcs7, derBuff, sizeof(derBuff));
    // update message and data to encode
    pkcs7.privateKey = key;
    pkcs7.privateKeySz = keySz;
    pkcs7.content = data;
    pkcs7.contentSz = dataSz;
    ... etc.

    ret = wc_PKCS7_EncodeEnvelopedData(&pkcs7, pkcs7Buff, sizeof(pkcs7Buff));
    if ( ret < 0 ) {
    	// error encoding into output buffer
    }
    \endcode

    \sa wc_PKCS7_InitWithCert
    \sa wc_PKCS7_DecodeEnvelopedData
*/
int  wc_PKCS7_EncodeEnvelopedData(wc_PKCS7* pkcs7,
                                          byte* output, word32 outputSz);

/*!
    \ingroup PKCS7

    \brief This function unwraps and decrypts a PKCS7 enveloped data content
    type, decoding the message into output. It uses the private key of the
    PKCS7 object passed in to decrypt the message.

    Note that if the EnvelopedData is encrypted using an ECC key and the
    KeyAgreementRecipientInfo structure, then either the HAVE_AES_KEYWRAP
    build option should be enabled to enable the wolfcrypt built-in AES key
    wrap/unwrap functionality, or a custom AES key wrap/unwrap callback should
    be set with wc_PKCS7_SetAESKeyWrapUnwrapCb(). If neither of these is true,
    decryption will fail.

    \return On successfully extracting the information from the message,
    returns the bytes written to output
    \return BAD_FUNC_ARG Returned if one of the input parameters is invalid
    \return ASN_PARSE_E Returned if there is an error parsing the given pkiMsg
    \return PKCS7_OID_E Returned if the given pkiMsg is not an enveloped
    data type
    \return ASN_VERSION_E Returned if the PKCS7 signer info is not version 0
    \return MEMORY_E Returned if there is an error allocating memory
    \return ALGO_ID_E Returned if the PKCS7 structure is using an unsupported
    algorithm type. Currently, only DESb and DES3b are supported for
    encryption, with RSAk for signature generation
    \return PKCS7_RECIP_E Returned if there is no recipient found in the
    enveloped data that matches the recipient provided
    \return RSA_BUFFER_E Returned if there is an error during RSA signature
    verification due to buffer error, output too small or input too large.
    \return MP_INIT_E may be returned if there is an error during signature
    verification
    \return MP_READ_E may be returned if there is an error during signature
    verification
    \return MP_CMP_E may be returned if there is an error during signature
    verification
    \return MP_INVMOD_E may be returned if there is an error during signature
    verification
    \return MP_EXPTMOD_E may be returned if there is an error during signature
    verification
    \return MP_MOD_E may be returned if there is an error during signature
    verification
    \return MP_MUL_E may be returned if there is an error during signature
    verification
    \return MP_ADD_E may be returned if there is an error during signature
    verification
    \return MP_MULMOD_E may be returned if there is an error during signature
    verification
    \return MP_TO_E may be returned if there is an error during signature
    verification
    \return MP_MEM may be returned if there is an error during signature
    verification
    \return NOT_COMPILED_IN may be returned if the EnvelopedData is encrypted
    using an ECC key and wolfssl was built without HAVE_X963_KDF support

    \param pkcs7 pointer to the PKCS7 structure containing the private key with
    which to decode the enveloped data package
    \param pkiMsg pointer to the buffer containing the enveloped data package
    \param pkiMsgSz size of the enveloped data package
    \param output pointer to the buffer in which to store the decoded message
    \param outputSz size available in the output buffer

    _Example_
    \code
    PKCS7 pkcs7;
    byte received[] = { }; // initialize with received enveloped message
    byte decoded[FOURK_BUF];
    int decodedSz;

    // initialize pkcs7 with certificate
    // update key
    pkcs7.privateKey = key;
    pkcs7.privateKeySz = keySz;

    decodedSz = wc_PKCS7_DecodeEnvelopedData(&pkcs7, received,
        sizeof(received),decoded, sizeof(decoded));
    if ( decodedSz < 0 ) {
        // error decoding message
    }
    \endcode

    \sa wc_PKCS7_InitWithCert
    \sa wc_PKCS7_EncodeEnvelopedData
*/
int wc_PKCS7_DecodeEnvelopedData(wc_PKCS7* pkcs7, byte* pkiMsg,
        word32 pkiMsgSz, byte* output, word32 outputSz);

/*!
    \ingroup PKCS7

    \brief This function extracts the KeyAgreeRecipientIdentifier object from
    an EnvelopedData package containing a KeyAgreeRecipientInfo RecipientInfo
    object. Only the first KeyAgreeRecipientIdentifer found in the first
    RecipientInfo is copied. This function does not support multiple
    RecipientInfo objects or multiple RecipientEncryptedKey objects within an
    KeyAgreeRecipientInfo.

    \return Returns 0 on success.
    \return BAD_FUNC_ARG Returned if one of the input parameters is invalid.
    \return ASN_PARSE_E Returned if there is an error parsing the input message.
    \return PKCS7_OID_E Returned if the input message is not an enveloped
    data type.
    \return BUFFER_E Returned if there is not enough room in the output buffer.

    \param[in] in Input buffer containing the EnvelopedData ContentInfo message.
    \param[in] inSz Size of the input buffer.
    \param[out] out Output buffer.
    \param[in,out] outSz Output buffer size on input, Size written on output.
*/
int wc_PKCS7_GetEnvelopedDataKariRid(const byte * in, word32 inSz,
        byte * out, word32 * outSz);

/*!
    \ingroup PKCS7

    \brief This function unwraps and decrypts a PKCS7 encrypted data content
    type, decoding the message into output. It uses the encryption key of the
    PKCS7 object passed in via pkcs7->encryptionKey and
    pkcs7->encryptionKeySz to decrypt the message.

    \return On successfully extracting the information from the message,
    returns the bytes written to output
    \return BAD_FUNC_ARG Returned if one of the input parameters is invalid
    \return ASN_PARSE_E Returned if there is an error parsing the given pkiMsg
    \return PKCS7_OID_E Returned if the given pkiMsg is not an encrypted
    data type
    \return ASN_VERSION_E Returned if the PKCS7 signer info is not version 0
    \return MEMORY_E Returned if there is an error allocating memory
    \return BUFFER_E Returned if the encrypted content size is invalid

    \param pkcs7 pointer to the PKCS7 structure containing the encryption key with
    which to decode the encrypted data package
    \param pkiMsg pointer to the buffer containing the encrypted data package
    \param pkiMsgSz size of the encrypted data package
    \param output pointer to the buffer in which to store the decoded message
    \param outputSz size available in the output buffer

    _Example_
    \code
    PKCS7 pkcs7;
    byte received[] = { }; // initialize with received encrypted data message
    byte decoded[FOURK_BUF];
    int decodedSz;

    // initialize pkcs7 with certificate
    // update key
    pkcs7.encryptionKey = key;
    pkcs7.encryptionKeySz = keySz;

    decodedSz = wc_PKCS7_DecodeEncryptedData(&pkcs7, received,
        sizeof(received), decoded, sizeof(decoded));
    if ( decodedSz < 0 ) {
        // error decoding message
    }
    \endcode

    \sa wc_PKCS7_InitWithCert
*/
int wc_PKCS7_DecodeEncryptedData(wc_PKCS7* pkcs7, byte* pkiMsg,
        word32 pkiMsgSz, byte* output, word32 outputSz);

/*!
    \ingroup PKCS7

    \brief This function unwraps and decrypts a PKCS7 encrypted key package
    content type, decoding the message into output. If the wrapped content
    type is EncryptedData, the encryption key must be set in the pkcs7 input
    structure (via pkcs7->encryptionKey and pkcs7->encryptionKeySz). If the
    wrapped content type is EnvelopedData, the private key must be set in the
    pkcs7 input structure (via pkcs7->privateKey and pkcs7->privateKeySz).
    A wrapped content type of AuthEnvelopedData is not currently supported.

    This function will automatically call either wc_PKCS7_DecodeEnvelopedData()
    or wc_PKCS7_DecodeEncryptedData() depending on the wrapped content type.
    This function could also return any error code from either of those
    functions in addition to the error codes listed here.

    \return On successfully extracting the information from the message,
    returns the bytes written to output
    \return BAD_FUNC_ARG Returned if one of the input parameters is invalid
    \return ASN_PARSE_E Returned if there is an error parsing the given pkiMsg
    or if the wrapped content type is EncryptedData and support for
    EncryptedData is not compiled in (e.g. NO_PKCS7_ENCRYPTED_DATA is set)
    \return PKCS7_OID_E Returned if the given pkiMsg is not an encrypted
    key package data type

    \param pkcs7 pointer to the PKCS7 structure containing the private key or
    encryption key with which to decode the encrypted key package
    \param pkiMsg pointer to the buffer containing the encrypted key package message
    \param pkiMsgSz size of the encrypted key package message
    \param output pointer to the buffer in which to store the decoded output
    \param outputSz size available in the output buffer

    _Example_
    \code
    PKCS7 pkcs7;
    byte received[] = { }; // initialize with received encrypted data message
    byte decoded[FOURK_BUF];
    int decodedSz;

    // initialize pkcs7 with certificate
    // update key for expected EnvelopedData (example)
    pkcs7.privateKey = key;
    pkcs7.privateKeySz = keySz;

    decodedSz = wc_PKCS7_DecodeEncryptedKeyPackage(&pkcs7, received,
        sizeof(received), decoded, sizeof(decoded));
    if ( decodedSz < 0 ) {
        // error decoding message
    }
    \endcode

    \sa wc_PKCS7_InitWithCert
*/
int wc_PKCS7_DecodeEncryptedKeyPackage(wc_PKCS7 * pkcs7,
        byte * pkiMsg, word32 pkiMsgSz, byte * output, word32 outputSz);

/*!
    \ingroup PKCS7

    \brief This function provides access to a SymmetricKeyPackage attribute.

    \return 0 The requested attribute has been successfully located.
    attr and attrSz output variables are populated with the address and size of
    the attribute. The attribute will be in the same buffer passed in via the
    skp input pointer.
    \return BAD_FUNC_ARG One of the input parameters is invalid.
    \return ASN_PARSE_E An error was encountered parsing the input object.
    \return BAD_INDEX_E The requested attribute index was invalid.

    \param[in] skp Input buffer containing the SymmetricKeyPackage object.
    \param[in] skpSz Size of the SymmetricKeyPackage object.
    \param[in] index Index of the attribute to access.
    \param[out] attr Buffer in which to store the pointer to the requested
    attribute object.
    \param[out] attrSz Buffer in which to store the size of the requested
    attribute object.
*/
int wc_PKCS7_DecodeSymmetricKeyPackageAttribute(const byte * skp,
        word32 skpSz, size_t index, const byte ** attr, word32 * attrSz);

/*!
    \ingroup PKCS7

    \brief This function provides access to a SymmetricKeyPackage key.

    \return 0 The requested key has been successfully located.
    key and keySz output variables are populated with the address and size of
    the key. The key will be in the same buffer passed in via the
    skp input pointer.
    \return BAD_FUNC_ARG One of the input parameters is invalid.
    \return ASN_PARSE_E An error was encountered parsing the input object.
    \return BAD_INDEX_E The requested key index was invalid.

    \param[in] skp Input buffer containing the SymmetricKeyPackage object.
    \param[in] skpSz Size of the SymmetricKeyPackage object.
    \param[in] index Index of the key to access.
    \param[out] key Buffer in which to store the pointer to the requested
    key object.
    \param[out] keySz Buffer in which to store the size of the requested
    key object.
*/
int wc_PKCS7_DecodeSymmetricKeyPackageKey(const byte * skp,
        word32 skpSz, size_t index, const byte ** key, word32 * keySz);

/*!
    \ingroup PKCS7

    \brief This function provides access to a OneSymmetricKey attribute.

    \return 0 The requested attribute has been successfully located.
    attr and attrSz output variables are populated with the address and size of
    the attribute. The attribute will be in the same buffer passed in via the
    osk input pointer.
    \return BAD_FUNC_ARG One of the input parameters is invalid.
    \return ASN_PARSE_E An error was encountered parsing the input object.
    \return BAD_INDEX_E The requested attribute index was invalid.

    \param[in] osk Input buffer containing the OneSymmetricKey object.
    \param[in] oskSz Size of the OneSymmetricKey object.
    \param[in] index Index of the attribute to access.
    \param[out] attr Buffer in which to store the pointer to the requested
    attribute object.
    \param[out] attrSz Buffer in which to store the size of the requested
    attribute object.
*/
int wc_PKCS7_DecodeOneSymmetricKeyAttribute(const byte * osk,
        word32 oskSz, size_t index, const byte ** attr, word32 * attrSz);

/*!
    \ingroup PKCS7

    \brief This function provides access to a OneSymmetricKey key.

    \return 0 The requested key has been successfully located.
    key and keySz output variables are populated with the address and size of
    the key. The key will be in the same buffer passed in via the
    osk input pointer.
    \return BAD_FUNC_ARG One of the input parameters is invalid.
    \return ASN_PARSE_E An error was encountered parsing the input object.

    \param[in] osk Input buffer containing the OneSymmetricKey object.
    \param[in] oskSz Size of the OneSymmetricKey object.
    \param[out] key Buffer in which to store the pointer to the requested
    key object.
    \param[out] keySz Buffer in which to store the size of the requested
    key object.
*/
int wc_PKCS7_DecodeOneSymmetricKeyKey(const byte * osk,
        word32 oskSz, const byte ** key, word32 * keySz);

/*!
    \ingroup PKCS7
    \brief Creates new PKCS7 structure.

    \return Pointer to new PKCS7 structure on success
    \return NULL on error

    \param none No parameters

    _Example_
    \code
    PKCS7* pkcs7 = wolfSSL_PKCS7_new();
    if (pkcs7 != NULL) {
        // use pkcs7
        wolfSSL_PKCS7_free(pkcs7);
    }
    \endcode

    \sa wolfSSL_PKCS7_free
*/
PKCS7* wolfSSL_PKCS7_new(void);

/*!
    \ingroup PKCS7
    \brief Creates new PKCS7_SIGNED structure.

    \return Pointer to new PKCS7_SIGNED structure on success
    \return NULL on error

    \param none No parameters

    _Example_
    \code
    PKCS7_SIGNED* p7 = wolfSSL_PKCS7_SIGNED_new();
    if (p7 != NULL) {
        // use p7
        wolfSSL_PKCS7_SIGNED_free(p7);
    }
    \endcode

    \sa wolfSSL_PKCS7_SIGNED_free
*/
PKCS7_SIGNED* wolfSSL_PKCS7_SIGNED_new(void);

/*!
    \ingroup PKCS7
    \brief Frees PKCS7 structure.

    \return none No returns

    \param p7 PKCS7 structure to free

    _Example_
    \code
    PKCS7* pkcs7 = wolfSSL_PKCS7_new();
    wolfSSL_PKCS7_free(pkcs7);
    \endcode

    \sa wolfSSL_PKCS7_new
*/
void wolfSSL_PKCS7_free(PKCS7* p7);

/*!
    \ingroup PKCS7
    \brief Frees PKCS7_SIGNED structure.

    \return none No returns

    \param p7 PKCS7_SIGNED structure to free

    _Example_
    \code
    PKCS7_SIGNED* p7 = wolfSSL_PKCS7_SIGNED_new();
    wolfSSL_PKCS7_SIGNED_free(p7);
    \endcode

    \sa wolfSSL_PKCS7_SIGNED_new
*/
void wolfSSL_PKCS7_SIGNED_free(PKCS7_SIGNED* p7);

/*!
    \ingroup PKCS7
    \brief Decodes DER-encoded PKCS7 structure.

    \return Pointer to decoded PKCS7 structure on success
    \return NULL on error

    \param p7 Pointer to PKCS7 pointer (can be NULL)
    \param in Pointer to DER-encoded data
    \param len Length of DER data

    _Example_
    \code
    PKCS7* p7 = NULL;
    const unsigned char* der = ...; // DER data
    p7 = wolfSSL_d2i_PKCS7(&p7, &der, derLen);
    \endcode

    \sa wolfSSL_i2d_PKCS7
*/
PKCS7* wolfSSL_d2i_PKCS7(PKCS7** p7, const unsigned char** in, int len);

/*!
    \ingroup PKCS7
    \brief Decodes PKCS7 from BIO.

    \return Pointer to decoded PKCS7 structure on success
    \return NULL on error

    \param bio BIO to read from
    \param p7 Pointer to PKCS7 pointer (can be NULL)

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new_file("pkcs7.der", "rb");
    PKCS7* p7 = wolfSSL_d2i_PKCS7_bio(bio, NULL);
    \endcode

    \sa wolfSSL_i2d_PKCS7_bio
*/
PKCS7* wolfSSL_d2i_PKCS7_bio(WOLFSSL_BIO* bio, PKCS7** p7);

/*!
    \ingroup PKCS7
    \brief Encodes PKCS7 to BIO.

    \return Length written on success
    \return negative on error

    \param bio BIO to write to
    \param p7 PKCS7 structure to encode

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    int ret = wolfSSL_i2d_PKCS7_bio(bio, p7);
    \endcode

    \sa wolfSSL_d2i_PKCS7_bio
*/
int wolfSSL_i2d_PKCS7_bio(WOLFSSL_BIO *bio, PKCS7 *p7);

/*!
    \ingroup PKCS7
    \brief Encodes PKCS7 to DER.

    \return Length written on success
    \return negative on error

    \param p7 PKCS7 structure to encode
    \param out Pointer to output buffer pointer

    _Example_
    \code
    unsigned char* der = NULL;
    int len = wolfSSL_i2d_PKCS7(p7, &der);
    \endcode

    \sa wolfSSL_d2i_PKCS7
*/
int wolfSSL_i2d_PKCS7(PKCS7 *p7, unsigned char **out);

/*!
    \ingroup PKCS7
    \brief Creates signed PKCS7 message.

    \return Pointer to signed PKCS7 structure on success
    \return NULL on error

    \param signer Signer certificate
    \param pkey Private key
    \param certs Additional certificates
    \param in Input data BIO
    \param flags Operation flags

    _Example_
    \code
    PKCS7* p7 = wolfSSL_PKCS7_sign(cert, pkey, NULL, bio, 0);
    \endcode

    \sa wolfSSL_PKCS7_verify
*/
PKCS7* wolfSSL_PKCS7_sign(WOLFSSL_X509* signer, WOLFSSL_EVP_PKEY* pkey,
                          WOLFSSL_STACK* certs, WOLFSSL_BIO* in, int flags);

/*!
    \ingroup PKCS7
    \brief Verifies signed PKCS7 message.

    \return 1 on success
    \return 0 or negative on error

    \param p7 PKCS7 structure to verify
    \param certs Certificate stack
    \param store Certificate store
    \param in Input data BIO
    \param out Output BIO
    \param flags Operation flags

    _Example_
    \code
    int ret = wolfSSL_PKCS7_verify(p7, NULL, store, NULL, out, 0);
    \endcode

    \sa wolfSSL_PKCS7_sign
*/
int wolfSSL_PKCS7_verify(PKCS7* p7, WOLFSSL_STACK* certs,
                         WOLFSSL_X509_STORE* store, WOLFSSL_BIO* in,
                         WOLFSSL_BIO* out, int flags);

/*!
    \ingroup PKCS7
    \brief Finalizes PKCS7 structure with data.

    \return 1 on success
    \return 0 or negative on error

    \param pkcs7 PKCS7 structure
    \param in Input data BIO
    \param flags Operation flags

    _Example_
    \code
    int ret = wolfSSL_PKCS7_final(pkcs7, bio, 0);
    \endcode

    \sa wolfSSL_PKCS7_sign
*/
int wolfSSL_PKCS7_final(PKCS7* pkcs7, WOLFSSL_BIO* in, int flags);

/*!
    \ingroup PKCS7
    \brief Encodes certificates into PKCS7.

    \return 1 on success
    \return 0 or negative on error

    \param p7 PKCS7 structure
    \param certs Certificate stack
    \param out Output BIO

    _Example_
    \code
    int ret = wolfSSL_PKCS7_encode_certs(p7, certs, bio);
    \endcode

    \sa wolfSSL_PKCS7_to_stack
*/
int wolfSSL_PKCS7_encode_certs(PKCS7* p7, WOLFSSL_STACK* certs,
                               WOLFSSL_BIO* out);

/*!
    \ingroup PKCS7
    \brief Converts PKCS7 certificates to stack.

    \return Pointer to certificate stack on success
    \return NULL on error

    \param pkcs7 PKCS7 structure

    _Example_
    \code
    WOLFSSL_STACK* certs = wolfSSL_PKCS7_to_stack(pkcs7);
    \endcode

    \sa wolfSSL_PKCS7_encode_certs
*/
WOLFSSL_STACK* wolfSSL_PKCS7_to_stack(PKCS7* pkcs7);

/*!
    \ingroup PKCS7
    \brief Gets signer certificates from PKCS7.

    \return Pointer to signer certificate stack on success
    \return NULL on error

    \param p7 PKCS7 structure
    \param certs Certificate stack
    \param flags Operation flags

    _Example_
    \code
    WOLFSSL_STACK* signers = wolfSSL_PKCS7_get0_signers(p7, NULL, 0);
    \endcode

    \sa wolfSSL_PKCS7_verify
*/
WOLFSSL_STACK* wolfSSL_PKCS7_get0_signers(PKCS7* p7, WOLFSSL_STACK* certs,
                                          int flags);

/*!
    \ingroup PKCS7
    \brief Writes PKCS7 to BIO in PEM format.

    \return 1 on success
    \return 0 or negative on error

    \param bio Output BIO
    \param p7 PKCS7 structure

    _Example_
    \code
    int ret = wolfSSL_PEM_write_bio_PKCS7(bio, p7);
    \endcode

    \sa wolfSSL_SMIME_write_PKCS7
*/
int wolfSSL_PEM_write_bio_PKCS7(WOLFSSL_BIO* bio, PKCS7* p7);

/*!
    \ingroup PKCS7
    \brief Reads S/MIME PKCS7 from BIO.

    \return Pointer to PKCS7 structure on success
    \return NULL on error

    \param in Input BIO
    \param bcont Pointer to content BIO pointer

    _Example_
    \code
    WOLFSSL_BIO* cont = NULL;
    PKCS7* p7 = wolfSSL_SMIME_read_PKCS7(bio, &cont);
    \endcode

    \sa wolfSSL_SMIME_write_PKCS7
*/
PKCS7* wolfSSL_SMIME_read_PKCS7(WOLFSSL_BIO* in, WOLFSSL_BIO** bcont);

/*!
    \ingroup PKCS7
    \brief Writes PKCS7 to BIO in S/MIME format.

    \return 1 on success
    \return 0 or negative on error

    \param out Output BIO
    \param pkcs7 PKCS7 structure
    \param in Input data BIO
    \param flags Operation flags

    _Example_
    \code
    int ret = wolfSSL_SMIME_write_PKCS7(out, pkcs7, in, 0);
    \endcode

    \sa wolfSSL_SMIME_read_PKCS7
*/
int wolfSSL_SMIME_write_PKCS7(WOLFSSL_BIO* out, PKCS7* pkcs7,
                              WOLFSSL_BIO* in, int flags);

/*!
    \ingroup PKCS7
    \brief Creates new wc_PKCS7 structure.

    \return Pointer to new wc_PKCS7 structure on success
    \return NULL on error

    \param heap Heap hint
    \param devId Device ID

    _Example_
    \code
    wc_PKCS7* pkcs7 = wc_PKCS7_New(NULL, INVALID_DEVID);
    \endcode

    \sa wc_PKCS7_Init
*/
wc_PKCS7* wc_PKCS7_New(void* heap, int devId);

/*!
    \ingroup PKCS7
    \brief Sets unknown extension callback.

    \return none No returns

    \param pkcs7 PKCS7 structure
    \param cb Callback function

    _Example_
    \code
    wc_PKCS7_SetUnknownExtCallback(pkcs7, myCallback);
    \endcode

    \sa wc_PKCS7_Init
*/
void wc_PKCS7_SetUnknownExtCallback(wc_PKCS7* pkcs7,
                                    wc_UnknownExtCallback cb);

/*!
    \ingroup PKCS7
    \brief Initializes wc_PKCS7 structure.

    \return 0 on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param heap Heap hint
    \param devId Device ID

    _Example_
    \code
    wc_PKCS7 pkcs7;
    int ret = wc_PKCS7_Init(&pkcs7, NULL, INVALID_DEVID);
    \endcode

    \sa wc_PKCS7_New
*/
int wc_PKCS7_Init(wc_PKCS7* pkcs7, void* heap, int devId);

/*!
    \ingroup PKCS7
    \brief Adds certificate to PKCS7.

    \return 0 on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param der DER-encoded certificate
    \param derSz Certificate size

    _Example_
    \code
    int ret = wc_PKCS7_AddCertificate(&pkcs7, cert, certSz);
    \endcode

    \sa wc_PKCS7_Init
*/
int wc_PKCS7_AddCertificate(wc_PKCS7* pkcs7, byte* der, word32 derSz);

/*!
    \ingroup PKCS7
    \brief Gets attribute value from PKCS7.

    \return 0 on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param oid Attribute OID
    \param oidSz OID size
    \param out Output buffer
    \param outSz Output buffer size pointer

    _Example_
    \code
    byte value[256];
    word32 valueSz = sizeof(value);
    int ret = wc_PKCS7_GetAttributeValue(&pkcs7, oid, oidSz, value,
                                         &valueSz);
    \endcode

    \sa wc_PKCS7_Init
*/
int wc_PKCS7_GetAttributeValue(wc_PKCS7* pkcs7, const byte* oid,
                                word32 oidSz, byte* out, word32* outSz);

/*!
    \ingroup PKCS7
    \brief Sets signer identifier type.

    \return 0 on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param type Identifier type

    _Example_
    \code
    int ret = wc_PKCS7_SetSignerIdentifierType(&pkcs7, CMS_SKID);
    \endcode

    \sa wc_PKCS7_Init
*/
int wc_PKCS7_SetSignerIdentifierType(wc_PKCS7* pkcs7, int type);

/*!
    \ingroup PKCS7
    \brief Sets content type.

    \return 0 on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param contentType Content type OID
    \param sz OID size

    _Example_
    \code
    int ret = wc_PKCS7_SetContentType(&pkcs7, DATA, sizeof(DATA));
    \endcode

    \sa wc_PKCS7_Init
*/
int wc_PKCS7_SetContentType(wc_PKCS7* pkcs7, byte* contentType, word32 sz);

/*!
    \ingroup PKCS7
    \brief Gets padding size for block cipher.

    \return Padding size

    \param inputSz Input size
    \param blockSz Block size

    _Example_
    \code
    int padSz = wc_PKCS7_GetPadSize(dataSz, AES_BLOCK_SIZE);
    \endcode

    \sa wc_PKCS7_PadData
*/
int wc_PKCS7_GetPadSize(word32 inputSz, word32 blockSz);

/*!
    \ingroup PKCS7
    \brief Pads data for block cipher.

    \return 0 on success
    \return negative on error

    \param in Input data
    \param inSz Input size
    \param out Output buffer
    \param outSz Output buffer size
    \param blockSz Block size

    _Example_
    \code
    int ret = wc_PKCS7_PadData(data, dataSz, padded, paddedSz,
                               AES_BLOCK_SIZE);
    \endcode

    \sa wc_PKCS7_GetPadSize
*/
int wc_PKCS7_PadData(byte* in, word32 inSz, byte* out, word32 outSz,
                     word32 blockSz);

/*!
    \ingroup PKCS7
    \brief Sets custom subject key identifier.

    \return 0 on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param in SKID data
    \param inSz SKID size

    _Example_
    \code
    int ret = wc_PKCS7_SetCustomSKID(&pkcs7, skid, skidSz);
    \endcode

    \sa wc_PKCS7_Init
*/
int wc_PKCS7_SetCustomSKID(wc_PKCS7* pkcs7, const byte* in, word16 inSz);

/*!
    \ingroup PKCS7
    \brief Sets detached signature flag.

    \return 0 on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param flag Detached flag (1=detached, 0=attached)

    _Example_
    \code
    int ret = wc_PKCS7_SetDetached(&pkcs7, 1);
    \endcode

    \sa wc_PKCS7_Init
*/
int wc_PKCS7_SetDetached(wc_PKCS7* pkcs7, word16 flag);

/*!
    \ingroup PKCS7
    \brief Disables default signed attributes.

    \return 0 on success
    \return negative on error

    \param pkcs7 PKCS7 structure

    _Example_
    \code
    int ret = wc_PKCS7_NoDefaultSignedAttribs(&pkcs7);
    \endcode

    \sa wc_PKCS7_SetDefaultSignedAttribs
*/
int wc_PKCS7_NoDefaultSignedAttribs(wc_PKCS7* pkcs7);

/*!
    \ingroup PKCS7
    \brief Sets default signed attributes flag.

    \return 0 on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param flag Default attributes flag

    _Example_
    \code
    int ret = wc_PKCS7_SetDefaultSignedAttribs(&pkcs7, 1);
    \endcode

    \sa wc_PKCS7_NoDefaultSignedAttribs
*/
int wc_PKCS7_SetDefaultSignedAttribs(wc_PKCS7* pkcs7, word16 flag);

/*!
    \ingroup PKCS7
    \brief Allows degenerate PKCS7 (no signers).

    \return none No returns

    \param pkcs7 PKCS7 structure
    \param flag Allow degenerate flag

    _Example_
    \code
    wc_PKCS7_AllowDegenerate(&pkcs7, 1);
    \endcode

    \sa wc_PKCS7_Init
*/
void wc_PKCS7_AllowDegenerate(wc_PKCS7* pkcs7, word16 flag);

/*!
    \ingroup PKCS7
    \brief Gets signer subject identifier.

    \return 0 on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param out Output buffer
    \param outSz Output buffer size pointer

    _Example_
    \code
    byte sid[256];
    word32 sidSz = sizeof(sid);
    int ret = wc_PKCS7_GetSignerSID(&pkcs7, sid, &sidSz);
    \endcode

    \sa wc_PKCS7_Init
*/
int wc_PKCS7_GetSignerSID(wc_PKCS7* pkcs7, byte* out, word32* outSz);

/*!
    \ingroup PKCS7
    \brief Encodes signed FirmwarePackageData.

    \return Size of encoded data on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param privateKey Private key
    \param privateKeySz Private key size
    \param signOID Signature algorithm OID
    \param hashOID Hash algorithm OID
    \param content Content data
    \param contentSz Content size
    \param signedAttribs Signed attributes
    \param signedAttribsSz Signed attributes count
    \param output Output buffer
    \param outputSz Output buffer size

    _Example_
    \code
    int ret = wc_PKCS7_EncodeSignedFPD(&pkcs7, key, keySz, RSAk, SHAh,
                                       data, dataSz, NULL, 0, out, outSz);
    \endcode

    \sa wc_PKCS7_EncodeSignedData
*/
int wc_PKCS7_EncodeSignedFPD(wc_PKCS7* pkcs7, byte* privateKey,
                             word32 privateKeySz, int signOID, int hashOID,
                             byte* content, word32 contentSz,
                             PKCS7Attrib* signedAttribs,
                             word32 signedAttribsSz, byte* output,
                             word32 outputSz);

/*!
    \ingroup PKCS7
    \brief Encodes signed encrypted FirmwarePackageData.

    \return Size of encoded data on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param encryptKey Encryption key
    \param encryptKeySz Encryption key size
    \param privateKey Private key
    \param privateKeySz Private key size
    \param encryptOID Encryption algorithm OID
    \param signOID Signature algorithm OID
    \param hashOID Hash algorithm OID
    \param content Content data
    \param contentSz Content size
    \param unprotectedAttribs Unprotected attributes
    \param unprotectedAttribsSz Unprotected attributes count
    \param signedAttribs Signed attributes
    \param signedAttribsSz Signed attributes count
    \param output Output buffer
    \param outputSz Output buffer size

    _Example_
    \code
    int ret = wc_PKCS7_EncodeSignedEncryptedFPD(&pkcs7, encKey, encKeySz,
                                                key, keySz, AES256CBCb,
                                                RSAk, SHAh, data, dataSz,
                                                NULL, 0, NULL, 0, out,
                                                outSz);
    \endcode

    \sa wc_PKCS7_EncodeSignedFPD
*/
int wc_PKCS7_EncodeSignedEncryptedFPD(wc_PKCS7* pkcs7, byte* encryptKey,
                                     word32 encryptKeySz, byte* privateKey,
                                     word32 privateKeySz, int encryptOID,
                                     int signOID, int hashOID, byte* content,
                                     word32 contentSz,
                                     PKCS7Attrib* unprotectedAttribs,
                                     word32 unprotectedAttribsSz,
                                     PKCS7Attrib* signedAttribs,
                                     word32 signedAttribsSz, byte* output,
                                     word32 outputSz);

/*!
    \ingroup PKCS7
    \brief Encodes signed compressed FirmwarePackageData.

    \return Size of encoded data on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param privateKey Private key
    \param privateKeySz Private key size
    \param signOID Signature algorithm OID
    \param hashOID Hash algorithm OID
    \param content Content data
    \param contentSz Content size
    \param signedAttribs Signed attributes
    \param signedAttribsSz Signed attributes count
    \param output Output buffer
    \param outputSz Output buffer size

    _Example_
    \code
    int ret = wc_PKCS7_EncodeSignedCompressedFPD(&pkcs7, key, keySz, RSAk,
                                                 SHAh, data, dataSz, NULL,
                                                 0, out, outSz);
    \endcode

    \sa wc_PKCS7_EncodeSignedFPD
*/
int wc_PKCS7_EncodeSignedCompressedFPD(wc_PKCS7* pkcs7, byte* privateKey,
                                      word32 privateKeySz, int signOID,
                                      int hashOID, byte* content,
                                      word32 contentSz,
                                      PKCS7Attrib* signedAttribs,
                                      word32 signedAttribsSz, byte* output,
                                      word32 outputSz);

/*!
    \ingroup PKCS7
    \brief Encodes signed encrypted compressed FirmwarePackageData.

    \return Size of encoded data on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param encryptKey Encryption key
    \param encryptKeySz Encryption key size
    \param privateKey Private key
    \param privateKeySz Private key size
    \param encryptOID Encryption algorithm OID
    \param signOID Signature algorithm OID
    \param hashOID Hash algorithm OID
    \param content Content data
    \param contentSz Content size
    \param unprotectedAttribs Unprotected attributes
    \param unprotectedAttribsSz Unprotected attributes count
    \param signedAttribs Signed attributes
    \param signedAttribsSz Signed attributes count
    \param output Output buffer
    \param outputSz Output buffer size

    _Example_
    \code
    int ret = wc_PKCS7_EncodeSignedEncryptedCompressedFPD(&pkcs7, encKey,
                                                          encKeySz, key,
                                                          keySz, AES256CBCb,
                                                          RSAk, SHAh, data,
                                                          dataSz, NULL, 0,
                                                          NULL, 0, out,
                                                          outSz);
    \endcode

    \sa wc_PKCS7_EncodeSignedCompressedFPD
*/
int wc_PKCS7_EncodeSignedEncryptedCompressedFPD(wc_PKCS7* pkcs7,
                                               byte* encryptKey,
                                               word32 encryptKeySz,
                                               byte* privateKey,
                                               word32 privateKeySz,
                                               int encryptOID, int signOID,
                                               int hashOID, byte* content,
                                               word32 contentSz,
                                               PKCS7Attrib* unprotectedAttribs,
                                               word32 unprotectedAttribsSz,
                                               PKCS7Attrib* signedAttribs,
                                               word32 signedAttribsSz,
                                               byte* output, word32 outputSz);

/*!
    \ingroup PKCS7
    \brief Adds KTRI recipient.

    \return 0 on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param cert Recipient certificate
    \param certSz Certificate size
    \param options Options flags

    _Example_
    \code
    int ret = wc_PKCS7_AddRecipient_KTRI(&pkcs7, cert, certSz, 0);
    \endcode

    \sa wc_PKCS7_AddRecipient_KARI
*/
int wc_PKCS7_AddRecipient_KTRI(wc_PKCS7* pkcs7, const byte* cert,
                               word32 certSz, int options);

/*!
    \ingroup PKCS7
    \brief Adds KARI recipient.

    \return 0 on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param cert Recipient certificate
    \param certSz Certificate size
    \param keyWrapOID Key wrap algorithm OID
    \param keyAgreeOID Key agreement algorithm OID
    \param ukm User keying material
    \param ukmSz UKM size
    \param options Options flags

    _Example_
    \code
    int ret = wc_PKCS7_AddRecipient_KARI(&pkcs7, cert, certSz, AES256_WRAP,
                                         dhSinglePass_stdDH_sha256kdf_scheme,
                                         NULL, 0, 0);
    \endcode

    \sa wc_PKCS7_AddRecipient_KTRI
*/
int wc_PKCS7_AddRecipient_KARI(wc_PKCS7* pkcs7, const byte* cert,
                               word32 certSz, int keyWrapOID,
                               int keyAgreeOID, byte* ukm, word32 ukmSz,
                               int options);

/*!
    \ingroup PKCS7
    \brief Sets encryption key.

    \return 0 on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param key Encryption key
    \param keySz Key size

    _Example_
    \code
    int ret = wc_PKCS7_SetKey(&pkcs7, key, keySz);
    \endcode

    \sa wc_PKCS7_Init
*/
int wc_PKCS7_SetKey(wc_PKCS7* pkcs7, byte* key, word32 keySz);

/*!
    \ingroup PKCS7
    \brief Adds KEKRI recipient.

    \return 0 on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param keyWrapOID Key wrap algorithm OID
    \param kek Key encryption key
    \param kekSz KEK size
    \param keyID Key identifier
    \param keyIdSz Key ID size
    \param timePtr Time pointer
    \param otherOID Other OID
    \param otherOIDSz Other OID size
    \param other Other data
    \param otherSz Other data size
    \param options Options flags

    _Example_
    \code
    int ret = wc_PKCS7_AddRecipient_KEKRI(&pkcs7, AES256_WRAP, kek, kekSz,
                                          keyId, keyIdSz, NULL, NULL, 0,
                                          NULL, 0, 0);
    \endcode

    \sa wc_PKCS7_AddRecipient_KTRI
*/
int wc_PKCS7_AddRecipient_KEKRI(wc_PKCS7* pkcs7, int keyWrapOID, byte* kek,
                                word32 kekSz, byte* keyID, word32 keyIdSz,
                                void* timePtr, byte* otherOID,
                                word32 otherOIDSz, byte* other,
                                word32 otherSz, int options);

/*!
    \ingroup PKCS7
    \brief Sets password for PWRI.

    \return 0 on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param passwd Password
    \param pLen Password length

    _Example_
    \code
    int ret = wc_PKCS7_SetPassword(&pkcs7, password, passwordLen);
    \endcode

    \sa wc_PKCS7_AddRecipient_PWRI
*/
int wc_PKCS7_SetPassword(wc_PKCS7* pkcs7, byte* passwd, word32 pLen);

/*!
    \ingroup PKCS7
    \brief Adds PWRI recipient.

    \return 0 on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param passwd Password
    \param pLen Password length
    \param salt Salt
    \param saltSz Salt size
    \param kdfOID KDF algorithm OID
    \param prfOID PRF algorithm OID
    \param iterations Iteration count
    \param kekEncryptOID KEK encryption algorithm OID
    \param options Options flags

    _Example_
    \code
    int ret = wc_PKCS7_AddRecipient_PWRI(&pkcs7, password, passwordLen,
                                         salt, saltSz, PBKDF2_OID, HMACh,
                                         10000, AES256CBCb, 0);
    \endcode

    \sa wc_PKCS7_SetPassword
*/
int wc_PKCS7_AddRecipient_PWRI(wc_PKCS7* pkcs7, byte* passwd, word32 pLen,
                               byte* salt, word32 saltSz, int kdfOID,
                               int prfOID, int iterations,
                               int kekEncryptOID, int options);

/*!
    \ingroup PKCS7
    \brief Sets originator encryption context.

    \return 0 on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param ctx Context pointer

    _Example_
    \code
    int ret = wc_PKCS7_SetOriEncryptCtx(&pkcs7, myContext);
    \endcode

    \sa wc_PKCS7_SetOriDecryptCtx
*/
int wc_PKCS7_SetOriEncryptCtx(wc_PKCS7* pkcs7, void* ctx);

/*!
    \ingroup PKCS7
    \brief Sets originator decryption context.

    \return 0 on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param ctx Context pointer

    _Example_
    \code
    int ret = wc_PKCS7_SetOriDecryptCtx(&pkcs7, myContext);
    \endcode

    \sa wc_PKCS7_SetOriEncryptCtx
*/
int wc_PKCS7_SetOriDecryptCtx(wc_PKCS7* pkcs7, void* ctx);

/*!
    \ingroup PKCS7
    \brief Sets originator decryption callback.

    \return 0 on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param cb Callback function

    _Example_
    \code
    int ret = wc_PKCS7_SetOriDecryptCb(&pkcs7, myDecryptCallback);
    \endcode

    \sa wc_PKCS7_SetOriDecryptCtx
*/
int wc_PKCS7_SetOriDecryptCb(wc_PKCS7* pkcs7, CallbackOriDecrypt cb);

/*!
    \ingroup PKCS7
    \brief Adds ORI recipient.

    \return 0 on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param cb Originator encryption callback
    \param options Options flags

    _Example_
    \code
    int ret = wc_PKCS7_AddRecipient_ORI(&pkcs7, myEncryptCallback, 0);
    \endcode

    \sa wc_PKCS7_SetOriDecryptCb
*/
int wc_PKCS7_AddRecipient_ORI(wc_PKCS7* pkcs7, CallbackOriEncrypt cb,
                              int options);

/*!
    \ingroup PKCS7
    \brief Sets CEK wrap callback.

    \return 0 on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param wrapCEKCb Wrap CEK callback

    _Example_
    \code
    int ret = wc_PKCS7_SetWrapCEKCb(&pkcs7, myWrapCEKCallback);
    \endcode

    \sa wc_PKCS7_Init
*/
int wc_PKCS7_SetWrapCEKCb(wc_PKCS7* pkcs7, CallbackWrapCEK wrapCEKCb);

/*!
    \ingroup PKCS7
    \brief Sets RSA sign raw digest callback.

    \return 0 on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param cb Callback function

    _Example_
    \code
    int ret = wc_PKCS7_SetRsaSignRawDigestCb(&pkcs7, mySignCallback);
    \endcode

    \sa wc_PKCS7_Init
*/
int wc_PKCS7_SetRsaSignRawDigestCb(wc_PKCS7* pkcs7,
                                   CallbackRsaSignRawDigest cb);

/*!
    \ingroup PKCS7
    \brief Encodes authenticated enveloped data.

    \return Size of encoded data on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param output Output buffer
    \param outputSz Output buffer size

    _Example_
    \code
    int ret = wc_PKCS7_EncodeAuthEnvelopedData(&pkcs7, out, outSz);
    \endcode

    \sa wc_PKCS7_DecodeAuthEnvelopedData
*/
int wc_PKCS7_EncodeAuthEnvelopedData(wc_PKCS7* pkcs7, byte* output,
                                     word32 outputSz);

/*!
    \ingroup PKCS7
    \brief Decodes authenticated enveloped data.

    \return Size of decoded data on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param pkiMsg Input message
    \param pkiMsgSz Input message size
    \param output Output buffer
    \param outputSz Output buffer size

    _Example_
    \code
    int ret = wc_PKCS7_DecodeAuthEnvelopedData(&pkcs7, msg, msgSz, out,
                                               outSz);
    \endcode

    \sa wc_PKCS7_EncodeAuthEnvelopedData
*/
int wc_PKCS7_DecodeAuthEnvelopedData(wc_PKCS7* pkcs7, byte* pkiMsg,
                                     word32 pkiMsgSz, byte* output,
                                     word32 outputSz);

/*!
    \ingroup PKCS7
    \brief Encodes encrypted data.

    \return Size of encoded data on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param output Output buffer
    \param outputSz Output buffer size

    _Example_
    \code
    int ret = wc_PKCS7_EncodeEncryptedData(&pkcs7, out, outSz);
    \endcode

    \sa wc_PKCS7_DecodeEncryptedData
*/
int wc_PKCS7_EncodeEncryptedData(wc_PKCS7* pkcs7, byte* output,
                                 word32 outputSz);

/*!
    \ingroup PKCS7
    \brief Sets decode encrypted callback.

    \return 0 on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param decryptionCb Decryption callback

    _Example_
    \code
    int ret = wc_PKCS7_SetDecodeEncryptedCb(&pkcs7, myDecryptCallback);
    \endcode

    \sa wc_PKCS7_SetDecodeEncryptedCtx
*/
int wc_PKCS7_SetDecodeEncryptedCb(wc_PKCS7* pkcs7,
                                  CallbackDecryptContent decryptionCb);

/*!
    \ingroup PKCS7
    \brief Sets decode encrypted context.

    \return 0 on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param ctx Context pointer

    _Example_
    \code
    int ret = wc_PKCS7_SetDecodeEncryptedCtx(&pkcs7, myContext);
    \endcode

    \sa wc_PKCS7_SetDecodeEncryptedCb
*/
int wc_PKCS7_SetDecodeEncryptedCtx(wc_PKCS7* pkcs7, void* ctx);

/*!
    \ingroup PKCS7
    \brief Sets stream mode for PKCS7.

    \return 0 on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param flag Stream mode flag
    \param getContentCb Get content callback
    \param streamOutCb Stream output callback
    \param ctx Context pointer

    _Example_
    \code
    int ret = wc_PKCS7_SetStreamMode(&pkcs7, 1, getContent, streamOut,
                                     ctx);
    \endcode

    \sa wc_PKCS7_GetStreamMode
*/
int wc_PKCS7_SetStreamMode(wc_PKCS7* pkcs7, byte flag,
                           CallbackGetContent getContentCb,
                           CallbackStreamOut streamOutCb, void* ctx);

/*!
    \ingroup PKCS7
    \brief Gets stream mode setting.

    \return Stream mode flag

    \param pkcs7 PKCS7 structure

    _Example_
    \code
    int mode = wc_PKCS7_GetStreamMode(&pkcs7);
    \endcode

    \sa wc_PKCS7_SetStreamMode
*/
int wc_PKCS7_GetStreamMode(wc_PKCS7* pkcs7);

/*!
    \ingroup PKCS7
    \brief Sets no certificates flag.

    \return 0 on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param flag No certificates flag

    _Example_
    \code
    int ret = wc_PKCS7_SetNoCerts(&pkcs7, 1);
    \endcode

    \sa wc_PKCS7_GetNoCerts
*/
int wc_PKCS7_SetNoCerts(wc_PKCS7* pkcs7, byte flag);

/*!
    \ingroup PKCS7
    \brief Gets no certificates flag.

    \return No certificates flag

    \param pkcs7 PKCS7 structure

    _Example_
    \code
    int noCerts = wc_PKCS7_GetNoCerts(&pkcs7);
    \endcode

    \sa wc_PKCS7_SetNoCerts
*/
int wc_PKCS7_GetNoCerts(wc_PKCS7* pkcs7);

/*!
    \ingroup PKCS7
    \brief Encodes compressed data.

    \return Size of encoded data on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param output Output buffer
    \param outputSz Output buffer size

    _Example_
    \code
    int ret = wc_PKCS7_EncodeCompressedData(&pkcs7, out, outSz);
    \endcode

    \sa wc_PKCS7_DecodeCompressedData
*/
int wc_PKCS7_EncodeCompressedData(wc_PKCS7* pkcs7, byte* output,
                                  word32 outputSz);

/*!
    \ingroup PKCS7
    \brief Decodes compressed data.

    \return Size of decoded data on success
    \return negative on error

    \param pkcs7 PKCS7 structure
    \param pkiMsg Input message
    \param pkiMsgSz Input message size
    \param output Output buffer
    \param outputSz Output buffer size

    _Example_
    \code
    int ret = wc_PKCS7_DecodeCompressedData(&pkcs7, msg, msgSz, out,
                                            outSz);
    \endcode

    \sa wc_PKCS7_EncodeCompressedData
*/
int wc_PKCS7_DecodeCompressedData(wc_PKCS7* pkcs7, byte* pkiMsg,
                                  word32 pkiMsgSz, byte* output,
                                  word32 outputSz);
