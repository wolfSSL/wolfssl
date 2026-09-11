/*!
    \ingroup PKCS12

    \brief This function creates a new empty WC_PKCS12 structure, using the
    default heap hint for dynamic memory. It is equivalent to calling
    wc_PKCS12_new_ex() with a NULL heap. The returned structure must be freed
    with wc_PKCS12_free().

    \return pointer Returns a pointer to a newly allocated WC_PKCS12 structure
    on success
    \return NULL Returned if the allocation fails

    \param none No parameters.

    _Example_
    \code
    WC_PKCS12* pkcs12 = wc_PKCS12_new();
    if (pkcs12 == NULL) {
        // error allocating PKCS12 structure
    }

    // use the PKCS12 structure

    wc_PKCS12_free(pkcs12);
    \endcode

    \sa wc_PKCS12_new_ex
    \sa wc_PKCS12_free
*/
WC_PKCS12* wc_PKCS12_new(void);

/*!
    \ingroup PKCS12

    \brief This function creates a new empty WC_PKCS12 structure, associating
    it with the heap hint given. The heap hint is stored in the structure and
    is used for every subsequent dynamic allocation and free made on behalf of
    this WC_PKCS12 object. The returned structure must be freed with
    wc_PKCS12_free().

    \return pointer Returns a pointer to a newly allocated WC_PKCS12 structure
    on success
    \return NULL Returned if the allocation fails

    \param heap pointer to a heap hint used for dynamic memory allocation, or
    NULL to use the default

    _Example_
    \code
    void* heap = NULL; // or a custom static memory heap hint
    WC_PKCS12* pkcs12 = wc_PKCS12_new_ex(heap);
    if (pkcs12 == NULL) {
        // error allocating PKCS12 structure
    }

    // use the PKCS12 structure

    wc_PKCS12_free(pkcs12);
    \endcode

    \sa wc_PKCS12_new
    \sa wc_PKCS12_free
*/
WC_PKCS12* wc_PKCS12_new_ex(void* heap);

/*!
    \ingroup PKCS12

    \brief This function frees a WC_PKCS12 structure and all of the memory
    associated with it, including the parsed authenticated safe and the MAC
    data. Passing NULL is safe and does nothing.

    \return none No returns.

    \param pkcs12 pointer to the WC_PKCS12 structure to free

    _Example_
    \code
    WC_PKCS12* pkcs12 = wc_PKCS12_new();

    // initialize and use the PKCS12 structure

    wc_PKCS12_free(pkcs12);
    \endcode

    \sa wc_PKCS12_new
    \sa wc_PKCS12_new_ex
*/
void wc_PKCS12_free(WC_PKCS12* pkcs12);

/*!
    \ingroup PKCS12

    \brief This function converts a DER-encoded PKCS #12 (PFX) buffer into a
    WC_PKCS12 structure. The raw contents of each ContentInfo are stored in the
    structure without being completely parsed or decoded; call
    wc_PKCS12_parse() afterwards to decrypt the bundle and recover the private
    key and certificates.

    \return 0 Returned on successfully decoding the PKCS #12 buffer
    \return BAD_FUNC_ARG Returned if der or pkcs12 is NULL
    \return ASN_PARSE_E Returned if there is an error parsing the PKCS #12
    structure
    \return ASN_VERSION_E Returned if the version in the bundle is not
    supported
    \return MEMORY_E Returned if there is an error allocating memory

    \param der pointer to a buffer holding the DER-encoded PKCS #12 bundle
    \param derSz size of the DER buffer
    \param pkcs12 pointer to an allocated WC_PKCS12 structure in which to store
    the decoded bundle

    _Example_
    \code
    WC_PKCS12* pkcs12 = NULL;
    byte der[] = { }; // initialize with a DER-encoded PKCS #12 bundle
    word32 derSz = sizeof(der);

    pkcs12 = wc_PKCS12_new();
    if (pkcs12 == NULL) {
        // error allocating PKCS12 structure
    }

    if (wc_d2i_PKCS12(der, derSz, pkcs12) != 0) {
        // error decoding PKCS12 bundle
    }

    wc_PKCS12_free(pkcs12);
    \endcode

    \sa wc_d2i_PKCS12_fp
    \sa wc_i2d_PKCS12
    \sa wc_PKCS12_parse
*/
int wc_d2i_PKCS12(const byte* der, word32 derSz, WC_PKCS12* pkcs12);

/*!
    \ingroup PKCS12

    \brief This function reads a DER-encoded PKCS #12 (PFX) file from the file
    system and decodes it into a WC_PKCS12 structure. If `*pkcs12` is NULL, a new
    WC_PKCS12 structure is allocated for the caller and returned through the
    pkcs12 argument; that structure is freed automatically if the decode fails.
    In either case, a successfully returned structure must be freed by the
    caller with wc_PKCS12_free(). This function is not available when
    NO_FILESYSTEM is defined.

    \return 0 Returned on successfully reading and decoding the file
    \return BAD_FUNC_ARG Returned if pkcs12 is NULL
    \return MEMORY_E Returned if there is an error allocating memory
    \return BAD_PATH_ERROR Returned if the file cannot be opened or read

    \param file path of the DER-encoded PKCS #12 file to read
    \param pkcs12 pointer to a WC_PKCS12 pointer. If `*pkcs12` is NULL, a new
    structure is allocated and returned here; otherwise the existing structure
    is used.

    _Example_
    \code
    WC_PKCS12* pkcs12 = NULL;

    // let wc_d2i_PKCS12_fp allocate the structure for us
    if (wc_d2i_PKCS12_fp("./certs/test-servercert.p12", &pkcs12) != 0) {
        // error reading or decoding the PKCS12 file
    }

    wc_PKCS12_free(pkcs12);
    \endcode

    \sa wc_d2i_PKCS12
    \sa wc_i2d_PKCS12
    \sa wc_PKCS12_parse
*/
int wc_d2i_PKCS12_fp(const char* file, WC_PKCS12** pkcs12);

/*!
    \ingroup PKCS12

    \brief This function encodes a WC_PKCS12 structure into a DER-encoded
    PKCS #12 (PFX) buffer. It supports three modes of operation, selected by
    the der and derSz arguments. Passing NULL for der queries the required
    buffer size only: the size is stored in `*derSz`, LENGTH_ONLY_E is
    returned, and no data is written. Passing a non-NULL der whose `*der` is
    NULL allocates a buffer of the required size and stores its address in
    `*der`, which the caller must free with XFREE() using DYNAMIC_TYPE_PKCS.
    Passing a non-NULL der whose `*der` points to a caller-supplied buffer
    writes the DER into that buffer, and returns BUFFER_E if a non-NULL derSz
    indicates that the buffer is too small. In that last case `*der` is
    advanced on success to one byte past the end of the encoded DER, following
    the usual i2d convention, so the caller must keep its own copy of the
    original pointer.

    \return Success On success, returns the size of the DER encoding in bytes
    \return LENGTH_ONLY_E Returned when der is NULL, indicating that only the
    required size was computed and stored in `*derSz`
    \return BAD_FUNC_ARG Returned if pkcs12 is NULL, if the structure holds no
    authenticated safe, or if both der and derSz are NULL
    \return BUFFER_E Returned if a caller-supplied buffer is too small to hold
    the encoding
    \return MEMORY_E Returned if there is an error allocating memory

    \param pkcs12 pointer to the WC_PKCS12 structure to encode
    \param der pointer to a buffer pointer in which to store the encoding, or
    NULL to query the required size
    \param derSz on a size query, receives the required size. When a
    caller-supplied buffer is used, holds the size of that buffer on input; a
    NULL value disables the buffer size check.

    _Example_
    \code
    WC_PKCS12* pkcs12 = NULL;
    byte* der = NULL;
    int derSz = 0;

    // pkcs12 previously created with wc_PKCS12_create or decoded with
    // wc_d2i_PKCS12

    // query the required size
    if (wc_i2d_PKCS12(pkcs12, NULL, &derSz) != LENGTH_ONLY_E) {
        // error getting the encoded size
    }

    // let wc_i2d_PKCS12 allocate the buffer for us
    if (wc_i2d_PKCS12(pkcs12, &der, NULL) <= 0) {
        // error encoding the PKCS12 bundle
    }

    XFREE(der, NULL, DYNAMIC_TYPE_PKCS);
    wc_PKCS12_free(pkcs12);
    \endcode

    \sa wc_d2i_PKCS12
    \sa wc_PKCS12_create
*/
int wc_i2d_PKCS12(WC_PKCS12* pkcs12, byte** der, int* derSz);

/*!
    \ingroup PKCS12

    \brief This function parses and decodes a WC_PKCS12 structure that was
    previously populated by wc_d2i_PKCS12() or wc_d2i_PKCS12_fp(). The MAC on
    the bundle is verified with the given password, the contents are decrypted,
    and the private key, the end entity certificate, and optionally the CA
    certificate chain are returned to the caller. The key and certificate are
    returned in newly allocated buffers which the caller is responsible for
    freeing: use XFREE(pkey, heap, DYNAMIC_TYPE_PUBLIC_KEY) for the key and
    XFREE(cert, heap, DYNAMIC_TYPE_PKCS) for the certificate, where heap is the
    heap hint associated with the WC_PKCS12 structure. The CA list, when
    requested, must be freed with wc_FreeCertList(). The private key is
    returned with the PKCS #8 header removed; use wc_PKCS12_parse_ex() if the
    PKCS #8 header should be kept.

    \note When USER_RSA is enabled this function may return a certificate that
    is not the pair of the returned key when RSA key pairs are used.

    \return 0 Returned on successfully parsing the PKCS #12 bundle
    \return BAD_FUNC_ARG Returned if pkcs12, psw, pkey, pkeySz, cert or certSz
    is NULL
    \return MAC_CMP_FAILED_E Returned if the MAC verification fails, which
    usually means the password is incorrect
    \return ASN_PARSE_E Returned if there is an error parsing the contents
    \return MEMORY_E Returned if there is an error allocating memory
    \return UNICODE_SIZE_E Returned if the password cannot be converted to the
    Unicode form required for key derivation

    \param pkcs12 pointer to a WC_PKCS12 structure holding a decoded bundle
    \param psw NULL-terminated password used to verify the MAC and decrypt the
    bundle
    \param[out] pkey receives a newly allocated buffer holding the DER-encoded
    private key
    \param[out] pkeySz receives the size of the private key buffer
    \param[out] cert receives a newly allocated buffer holding the DER-encoded
    certificate
    \param[out] certSz receives the size of the certificate buffer
    \param[out] ca optional. If non-NULL, receives a linked list of the
    remaining DER-encoded certificates found in the bundle. Free with
    wc_FreeCertList().

    _Example_
    \code
    WC_PKCS12* pkcs12 = NULL;
    byte* key = NULL;
    byte* cert = NULL;
    WC_DerCertList* ca = NULL;
    word32 keySz = 0;
    word32 certSz = 0;

    if (wc_d2i_PKCS12_fp("./certs/test-servercert.p12", &pkcs12) != 0) {
        // error reading the PKCS12 file
    }

    if (wc_PKCS12_parse(pkcs12, "password", &key, &keySz, &cert, &certSz,
                        &ca) != 0) {
        // error parsing the bundle, e.g. wrong password
    }

    // use the key, cert and ca chain

    XFREE(key, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    XFREE(cert, NULL, DYNAMIC_TYPE_PKCS);
    wc_FreeCertList(ca, NULL);
    wc_PKCS12_free(pkcs12);
    \endcode

    \sa wc_PKCS12_parse_ex
    \sa wc_d2i_PKCS12
    \sa wc_FreeCertList
*/
int wc_PKCS12_parse(WC_PKCS12* pkcs12, const char* psw,
        byte** pkey, word32* pkeySz, byte** cert, word32* certSz,
        WC_DerCertList** ca);

/*!
    \ingroup PKCS12

    \brief This function behaves exactly like wc_PKCS12_parse() but adds the
    keepKeyHeader argument, which controls whether the PKCS #8 header is left
    on the returned private key. Calling wc_PKCS12_parse() is equivalent to
    calling this function with keepKeyHeader set to 0. The same ownership rules
    as wc_PKCS12_parse() apply: free the key with XFREE(pkey, heap,
    DYNAMIC_TYPE_PUBLIC_KEY), the certificate with XFREE(cert, heap,
    DYNAMIC_TYPE_PKCS), and the CA list with wc_FreeCertList().

    \note When USER_RSA is enabled this function may return a certificate that
    is not the pair of the returned key when RSA key pairs are used.

    \return 0 Returned on successfully parsing the PKCS #12 bundle
    \return BAD_FUNC_ARG Returned if pkcs12, psw, pkey, pkeySz, cert or certSz
    is NULL
    \return MAC_CMP_FAILED_E Returned if the MAC verification fails, which
    usually means the password is incorrect
    \return ASN_PARSE_E Returned if there is an error parsing the contents
    \return MEMORY_E Returned if there is an error allocating memory
    \return UNICODE_SIZE_E Returned if the password cannot be converted to the
    Unicode form required for key derivation

    \param pkcs12 pointer to a WC_PKCS12 structure holding a decoded bundle
    \param psw NULL-terminated password used to verify the MAC and decrypt the
    bundle
    \param[out] pkey receives a newly allocated buffer holding the DER-encoded
    private key
    \param[out] pkeySz receives the size of the private key buffer
    \param[out] cert receives a newly allocated buffer holding the DER-encoded
    certificate
    \param[out] certSz receives the size of the certificate buffer
    \param[out] ca optional. If non-NULL, receives a linked list of the
    remaining DER-encoded certificates found in the bundle. Free with
    wc_FreeCertList().
    \param keepKeyHeader 0 to strip the PKCS #8 header from the returned key,
    any other value to keep it

    _Example_
    \code
    WC_PKCS12* pkcs12 = NULL;
    byte* key = NULL;
    byte* cert = NULL;
    WC_DerCertList* ca = NULL;
    word32 keySz = 0;
    word32 certSz = 0;

    // pkcs12 previously decoded with wc_d2i_PKCS12 or wc_d2i_PKCS12_fp

    // keep the PKCS #8 header on the returned private key
    if (wc_PKCS12_parse_ex(pkcs12, "password", &key, &keySz, &cert, &certSz,
                           &ca, 1) != 0) {
        // error parsing the bundle
    }

    XFREE(key, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    XFREE(cert, NULL, DYNAMIC_TYPE_PKCS);
    wc_FreeCertList(ca, NULL);
    wc_PKCS12_free(pkcs12);
    \endcode

    \sa wc_PKCS12_parse
    \sa wc_d2i_PKCS12
    \sa wc_FreeCertList
*/
int wc_PKCS12_parse_ex(WC_PKCS12* pkcs12, const char* psw,
        byte** pkey, word32* pkeySz, byte** cert, word32* certSz,
        WC_DerCertList** ca, int keepKeyHeader);

/*!
    \ingroup PKCS12

    \brief This function creates a new WC_PKCS12 structure from a DER-encoded
    private key, a DER-encoded certificate, and an optional list of extra
    certificates. The key and certificate are each placed in their own
    ContentInfo, optionally encrypted with the password given, and a MAC is
    computed over the result. The returned structure can be encoded to DER with
    wc_i2d_PKCS12() and must be freed with wc_PKCS12_free(). The nidKey and
    nidCert arguments select the password-based encryption applied to the key
    and to the certificate respectively. Supported values are
    PBE_SHA1_RC4_128, PBE_SHA1_DES, PBE_SHA1_DES3, PBE_AES128_CBC and
    PBE_AES256_CBC. Passing -1 stores the corresponding content unencrypted.

    \note The name and keyType arguments are accepted for API compatibility but
    are not currently used.

    \return pointer Returns a pointer to a newly created WC_PKCS12 structure on
    success
    \return NULL Returned if the RNG cannot be initialized, if memory
    allocation fails, if an unsupported nidKey or nidCert is given, or if the
    bundle cannot be built

    \param pass password to use for encryption and for the MAC
    \param passSz size of the password buffer
    \param name friendlyName to use. Not currently used.
    \param key buffer holding the DER-encoded private key
    \param keySz size of the key buffer
    \param cert buffer holding the DER-encoded certificate
    \param certSz size of the certificate buffer
    \param ca optional linked list of additional DER-encoded certificates to
    include, or NULL
    \param nidKey encryption to apply to the private key, or -1 for none
    \param nidCert encryption to apply to the certificate, or -1 for none
    \param iter number of iterations to use for the encryption. Values of 0 or
    less select WC_PKCS12_ITT_DEFAULT.
    \param macIter number of iterations to use when creating the MAC
    \param keyType flag for a signature and/or encryption key. Not currently
    used.
    \param heap pointer to a heap hint used for dynamic memory allocation, or
    NULL to use the default

    _Example_
    \code
    WC_PKCS12* pkcs12 = NULL;
    byte* der = NULL;
    char pass[] = "password";
    byte key[] = { };  // initialize with a DER-encoded private key
    byte cert[] = { }; // initialize with a DER-encoded certificate

    pkcs12 = wc_PKCS12_create(pass, sizeof(pass) - 1, NULL,
                              key, sizeof(key), cert, sizeof(cert), NULL,
                              PBE_AES256_CBC, PBE_AES256_CBC,
                              WC_PKCS12_ITT_DEFAULT, WC_PKCS12_ITT_DEFAULT,
                              0, NULL);
    if (pkcs12 == NULL) {
        // error creating the PKCS12 bundle
    }

    if (wc_i2d_PKCS12(pkcs12, &der, NULL) <= 0) {
        // error encoding the bundle to DER
    }

    XFREE(der, NULL, DYNAMIC_TYPE_PKCS);
    wc_PKCS12_free(pkcs12);
    \endcode

    \sa wc_i2d_PKCS12
    \sa wc_PKCS12_parse
    \sa wc_PKCS12_free
*/
WC_PKCS12* wc_PKCS12_create(char* pass, word32 passSz,
        char* name, byte* key, word32 keySz, byte* cert, word32 certSz,
        WC_DerCertList* ca, int nidKey, int nidCert, int iter, int macIter,
        int keyType, void* heap);

/*!
    \ingroup PKCS12

    \brief This function frees a WC_DerCertList linked list, including the DER
    buffer held by each node. It is used to release the CA certificate list
    returned by wc_PKCS12_parse() and wc_PKCS12_parse_ex(). The heap hint given
    must match the one associated with the WC_PKCS12 structure the list came
    from. Passing NULL for the list is safe and does nothing.

    \return none No returns.

    \param list pointer to the head of the WC_DerCertList to free
    \param heap pointer to the heap hint used when the list was allocated

    _Example_
    \code
    WC_DerCertList* ca = NULL;

    // ca populated by a previous call to wc_PKCS12_parse

    wc_FreeCertList(ca, NULL);
    \endcode

    \sa wc_PKCS12_parse
    \sa wc_PKCS12_parse_ex
*/
void wc_FreeCertList(WC_DerCertList* list, void* heap);
