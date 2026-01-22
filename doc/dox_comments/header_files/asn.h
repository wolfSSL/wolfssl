/*!
    \ingroup ASN
    \brief This function converts BER (Basic Encoding Rules) formatted data
    to DER (Distinguished Encoding Rules) format. BER allows indefinite
    length encoding while DER requires definite lengths. This function
    calculates definite lengths for all indefinite length items.

    \return 0 On success.
    \return ASN_PARSE_E If the BER data is invalid.
    \return BAD_FUNC_ARG If ber or derSz are NULL.
    \return BUFFER_E If der is not NULL and derSz is too small.

    \param ber pointer to the buffer containing BER formatted data
    \param berSz size of the BER data in bytes
    \param der pointer to buffer to store DER formatted data (can be NULL
    to calculate required size)
    \param derSz pointer to size of der buffer; updated with actual size
    needed or used

    \note This API is not public by default. Define WOLFSSL_PUBLIC_ASN to
    expose APIs marked WOLFSSL_ASN_API.

    _Example_
    \code
    byte ber[256] = { }; // BER encoded data
    byte der[256];
    word32 derSz = sizeof(der);

    int ret = wc_BerToDer(ber, sizeof(ber), der, &derSz);
    if (ret == 0) {
        // der now contains DER formatted data of length derSz
    }
    \endcode

    \sa wc_EncodeObjectId
*/
int wc_BerToDer(const byte* ber, word32 berSz, byte* der, word32* derSz);

/*!
    \ingroup ASN
    \brief This function frees a linked list of alternative names
    (DNS_entry structures). It deallocates each node and its associated
    name string, IP string, and RID string if present.

    \return none No return value.

    \param altNames pointer to the head of the alternative names linked list
    \param heap pointer to heap hint for memory deallocation (can be NULL)

    \note This API is not public by default. Define WOLFSSL_PUBLIC_ASN to
    expose APIs marked WOLFSSL_ASN_API.

    _Example_
    \code
    DNS_entry* altNames = NULL;
    // populate altNames with certificate alternative names

    FreeAltNames(altNames, NULL);
    // altNames list is now freed
    \endcode

    \sa AltNameNew
*/
void FreeAltNames(DNS_entry* altNames, void* heap);

/*!
    \ingroup ASN
    \brief This function sets an extended callback for handling unknown
    certificate extensions during certificate parsing. The callback
    receives additional context information compared to the basic
    callback.

    \return 0 On success.
    \return BAD_FUNC_ARG If cert is NULL.

    \param cert pointer to the DecodedCert structure
    \param cb callback function to handle unknown extensions
    \param ctx context pointer passed to the callback

    \note This API is not public by default. Define WOLFSSL_PUBLIC_ASN to
    expose APIs marked WOLFSSL_ASN_API.

    _Example_
    \code
    DecodedCert cert;

    int UnknownExtCallback(const byte* oid, word32 oidSz, int crit,
                          const byte* der, word32 derSz, void* ctx) {
        // handle unknown extension
        return 0;
    }

    wc_InitDecodedCert(&cert, derCert, derCertSz, NULL);
    wc_SetUnknownExtCallbackEx(&cert, UnknownExtCallback, myContext);
    wc_ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL);
    \endcode

    \sa wc_SetUnknownExtCallback
    \sa wc_InitDecodedCert
*/
int wc_SetUnknownExtCallbackEx(DecodedCert* cert,
                               wc_UnknownExtCallbackEx cb, void *ctx);

/*!
    \ingroup ASN
    \brief This function verifies the signature on a certificate using a
    certificate manager. It checks that the certificate is properly
    signed by a trusted CA.

    \return 0 On successful signature verification.
    \return ASN_SIG_CONFIRM_E If signature verification fails.
    \return Other negative values on error.

    \param cert pointer to the DER encoded certificate
    \param certSz size of the certificate in bytes
    \param heap pointer to heap hint for memory allocation (can be NULL)
    \param cm pointer to certificate manager containing trusted CAs

    _Example_
    \code
    byte cert[2048] = { }; // DER encoded certificate
    word32 certSz = sizeof(cert);
    WOLFSSL_CERT_MANAGER* cm;

    cm = wolfSSL_CertManagerNew();
    wolfSSL_CertManagerLoadCA(cm, "ca-cert.pem", NULL);

    int ret = wc_CheckCertSignature(cert, certSz, NULL, cm);
    if (ret == 0) {
        // certificate signature is valid
    }
    wolfSSL_CertManagerFree(cm);
    \endcode

    \sa wolfSSL_CertManagerNew
    \sa wolfSSL_CertManagerLoadCA
*/
int wc_CheckCertSignature(const byte* cert, word32 certSz, void* heap,
                          void* cm);

/*!
    \ingroup ASN
    \brief This function encodes an array of word16 values into an ASN.1
    Object Identifier (OID) in DER format. OIDs are used to identify
    algorithms, extensions, and other objects in certificates and
    cryptographic protocols.

    \return 0 On success.
    \return BAD_FUNC_ARG If in, inSz, or outSz are invalid.
    \return BUFFER_E If out is not NULL and outSz is too small.

    \param in pointer to array of word16 values representing OID components
    \param inSz number of components in the OID
    \param out pointer to buffer to store encoded OID (can be NULL to
    calculate size)
    \param outSz pointer to size of out buffer; updated with actual size

    _Example_
    \code
    word16 oid[] = {1, 2, 840, 113549, 1, 1, 11}; // sha256WithRSAEncryption
    byte encoded[32];
    word32 encodedSz = sizeof(encoded);

    int ret = wc_EncodeObjectId(oid, sizeof(oid)/sizeof(word16),
                                encoded, &encodedSz);
    if (ret == 0) {
        // encoded contains DER encoded OID
    }
    \endcode

    \sa wc_BerToDer
*/
int wc_EncodeObjectId(const word16* in, word32 inSz, byte* out,
                      word32* outSz);

/*!
    \ingroup ASN
    \brief This function sets the algorithm identifier in DER format. It
    encodes the algorithm OID and optional parameters based on the
    algorithm type and curve size.

    \return Length of the encoded algorithm identifier on success.
    \return Negative value on error.

    \param algoOID algorithm object identifier constant
    \param output pointer to buffer to store encoded algorithm ID
    \param type type of encoding (oidSigType, oidHashType, etc.)
    \param curveSz size of the curve for ECC algorithms (0 for non-ECC)

    _Example_
    \code
    byte algId[32];
    word32 len;

    len = SetAlgoID(CTC_SHA256wRSA, algId, oidSigType, 0);
    if (len > 0) {
        // algId contains encoded algorithm identifier
    }
    \endcode

    \sa wc_EncodeObjectId
*/
word32 SetAlgoID(int algoOID, byte* output, int type, int curveSz);

/*!
    \ingroup ASN
    \brief This function decodes a DER encoded Diffie-Hellman public key.
    It extracts the public key value from the DER encoding and stores it
    in the DhKey structure.

    \return 0 On success.
    \return BAD_FUNC_ARG If input, inOutIdx, key, or inSz are invalid.
    \return ASN_PARSE_E If the DER encoding is invalid.
    \return Other negative values on error.

    \param input pointer to buffer containing DER encoded public key
    \param inOutIdx pointer to index in buffer; updated to end of key
    \param key pointer to DhKey structure to store decoded public key
    \param inSz size of the input buffer

    _Example_
    \code
    byte derKey[256] = { }; // DER encoded DH public key
    word32 idx = 0;
    DhKey key;

    wc_InitDhKey(&key);
    int ret = wc_DhPublicKeyDecode(derKey, &idx, &key, sizeof(derKey));
    if (ret == 0) {
        // key now contains the decoded public key
    }
    wc_FreeDhKey(&key);
    \endcode

    \sa wc_InitDhKey
    \sa wc_DhKeyDecode
*/
int wc_DhPublicKeyDecode(const byte* input, word32* inOutIdx, DhKey* key,
                         word32 inSz);
