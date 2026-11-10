/*!
    \ingroup HMAC

    \brief This function initializes an Hmac object, setting its
    encryption type, key and HMAC length.

    \return 0 Returned on successfully initializing the Hmac object
    \return BAD_FUNC_ARG Returned if the input type is invalid (see type param)
    \return MEMORY_E Returned if there is an error allocating memory for the
    structure to use for hashing
    \return HMAC_MIN_KEYLEN_E Returned when using a FIPS implementation
    and the key length specified is shorter than the minimum acceptable
    FIPS standard of 14 bytes

    \param hmac pointer to the Hmac object to initialize
    \param type type specifying which encryption method the Hmac object
    should use. Valid options are: WC_MD5, WC_SHA, WC_SHA256, WC_SHA384,
    WC_SHA512, WC_SHA3_224, WC_SHA3_256, WC_SHA3_384 or WC_SHA3_512
    \param key pointer to a buffer containing the key with which to
    initialize the Hmac object
    \param length length of the key

    _Example_
    \code
    Hmac hmac;
    byte key[] = { // initialize with key to use for encryption };
    if (wc_HmacSetKey(&hmac, WC_MD5, key, sizeof(key)) != 0) {
    	// error initializing Hmac object
    }
    \endcode

    \sa wc_HmacUpdate
    \sa wc_HmacFinal
*/
int wc_HmacSetKey(Hmac* hmac, int type, const byte* key, word32 keySz);

/*!
    \ingroup HMAC

    \brief This function updates the message to authenticate using HMAC.
    It should be called after the Hmac object has been initialized with
    wc_HmacSetKey. This function may be called multiple times to update
    the message to hash. After calling wc_HmacUpdate as desired, one should
    call wc_HmacFinal to obtain the final authenticated message tag.

    \return 0 Returned on successfully updating the message to authenticate
    \return MEMORY_E Returned if there is an error allocating memory for
    use with a hashing algorithm
    \return MISSING_KEY Returned for an Hmac named by id or label with no
    key bytes set when no device performs the operation

    \param hmac pointer to the Hmac object for which to update the message
    \param msg pointer to the buffer containing the message to append
    \param length length of the message to append

    _Example_
    \code
    Hmac hmac;
    byte msg[] = { // initialize with message to authenticate };
    byte msg2[] = { // initialize with second half of message };
    // initialize hmac
    if( wc_HmacUpdate(&hmac, msg, sizeof(msg)) != 0) {
    	// error updating message
    }
    if( wc_HmacUpdate(&hmac, msg2, sizeof(msg)) != 0) {
    	// error updating with second message
    }
    \endcode

    \sa wc_HmacSetKey
    \sa wc_HmacFinal
*/
int wc_HmacUpdate(Hmac* hmac, const byte* in, word32 sz);

/*!
    \ingroup HMAC

    \brief This function computes the final hash of an Hmac object's message.

    \return 0 Returned on successfully computing the final hash
    \return MEMORY_E Returned if there is an error allocating memory for
    use with a hashing algorithm
    \return MISSING_KEY Returned for an Hmac named by id or label with no
    key bytes set when no device performs the operation

    \param hmac pointer to the Hmac object for which to calculate the
    final hash
    \param hash pointer to the buffer in which to store the final hash.
    Should have room available as required by the hashing algorithm chosen

    _Example_
    \code
    Hmac hmac;
    byte hash[MD5_DIGEST_SIZE];
    // initialize hmac with MD5 as type
    // wc_HmacUpdate() with messages

    if (wc_HmacFinal(&hmac, hash) != 0) {
    	// error computing hash
    }
    \endcode

    \sa wc_HmacSetKey
    \sa wc_HmacUpdate
*/
int wc_HmacFinal(Hmac* hmac, byte* out);

/*!
    \ingroup HMAC

    \brief This function returns the largest HMAC digest size available
    based on the configured cipher suites.

    \return Success Returns the largest HMAC digest size available based
    on the configured cipher suites

    \param none No parameters.

    _Example_
    \code
    int maxDigestSz = wolfSSL_GetHmacMaxSize();
    \endcode

    \sa none
*/
int wolfSSL_GetHmacMaxSize(void);

/*!
    \ingroup HMAC

    \brief Single shot function for generating an HMAC. Initializes, keys,
    hashes the message and finalizes in one call. The full digest size tag of
    the hash type is always written.

    \return 0 on success
    \return BAD_FUNC_ARG if out or outSz is NULL, in is NULL with a non-zero
    inSz, key is NULL with a non-zero keySz, or type is invalid
    \return BUFFER_E if *outSz is smaller than the digest size of type
    \return MEMORY_E if allocating the HMAC context fails
    \return HMAC_MIN_KEYLEN_E may be returned in FIPS builds when the key is
    shorter than the FIPS minimum

    \param type hash type, such as WC_SHA256 or WC_SHA3_384
    \param out buffer to hold the tag
    \param outSz on input the size of out, at least the digest size of type
    (WC_MAX_DIGEST_SIZE always fits); on output the digest size
    \param in message to authenticate
    \param inSz length of the message
    \param key HMAC key; may be NULL when keySz is 0
    \param keySz length of the key

    _Example_
    \code
    byte   tag[WC_SHA256_DIGEST_SIZE];
    word32 tagSz = sizeof(tag);
    ret = wc_HmacGenerate(WC_SHA256, tag, &tagSz, msg, msgSz, key, keySz);
    \endcode

    \sa wc_HmacGenerate_ex
    \sa wc_HmacVerify
*/
int wc_HmacGenerate(int type, byte* out, word32* outSz,
                    const byte* in, word32 inSz,
                    const byte* key, word32 keySz);

/*!
    \ingroup HMAC

    \brief Same as wc_HmacGenerate, but uses caller provided storage for the
    HMAC context and takes a heap hint and device ID. The context is
    initialized with wc_HmacInit and released with wc_HmacFree inside this
    call, so it must not hold a live HMAC operation on entry.

    \return see wc_HmacGenerate; also BAD_FUNC_ARG if hmac is NULL
    \return WC_PENDING_E if a crypto callback device returned pending; the
    context has been freed and no tag was produced. The caller may call
    again, which starts a new operation.

    \param hmac storage for the HMAC context
    \param type hash type, such as WC_SHA256 or WC_SHA3_384
    \param out buffer to hold the tag
    \param outSz on input the size of out; on output the digest size
    \param in message to authenticate
    \param inSz length of the message
    \param key HMAC key; may be NULL when keySz is 0
    \param keySz length of the key
    \param heap heap hint for dynamic memory, or NULL
    \param devId device ID for crypto callbacks or async, or INVALID_DEVID

    _Example_
    \code
    Hmac   hmac;
    byte   tag[WC_SHA256_DIGEST_SIZE];
    word32 tagSz = sizeof(tag);
    ret = wc_HmacGenerate_ex(&hmac, WC_SHA256, tag, &tagSz, msg, msgSz,
                             key, keySz, NULL, devId);
    \endcode

    \sa wc_HmacGenerate
    \sa wc_HmacVerify_ex
*/
int wc_HmacGenerate_ex(Hmac* hmac, int type, byte* out, word32* outSz,
                       const byte* in, word32 inSz,
                       const byte* key, word32 keySz,
                       void* heap, int devId);

/*!
    \ingroup HMAC

    \brief Single shot function for validating an HMAC. Computes the tag over
    the message and compares it against check in constant time. Only full
    length tags are accepted.

    \return 0 if the tag matches
    \return MAC_CMP_FAILED_E if the tag does not match
    \return BAD_FUNC_ARG if check is NULL, checkSz is not the digest size of
    type, or any wc_HmacGenerate argument check fails
    \return MEMORY_E if allocating the HMAC context fails
    \return HMAC_MIN_KEYLEN_E may be returned in FIPS builds when the key is
    shorter than the FIPS minimum

    \param type hash type, such as WC_SHA256 or WC_SHA3_384
    \param check expected tag
    \param checkSz length of the expected tag; must equal the digest size of
    type
    \param in message that was authenticated
    \param inSz length of the message
    \param key HMAC key; may be NULL when keySz is 0
    \param keySz length of the key

    _Example_
    \code
    ret = wc_HmacVerify(WC_SHA256, tag, tagSz, msg, msgSz, key, keySz);
    if (ret == MAC_CMP_FAILED_E) {
        // reject the message
    }
    \endcode

    \sa wc_HmacVerify_ex
    \sa wc_HmacGenerate
*/
int wc_HmacVerify(int type, const byte* check, word32 checkSz,
                  const byte* in, word32 inSz,
                  const byte* key, word32 keySz);

/*!
    \ingroup HMAC

    \brief Same as wc_HmacVerify, but uses caller provided storage for the
    HMAC context and takes a heap hint and device ID. The context is
    initialized and freed inside this call.

    \return see wc_HmacVerify; also BAD_FUNC_ARG if hmac is NULL
    \return WC_PENDING_E if a crypto callback device returned pending; the
    context has been freed and the tag was not checked. The caller may call
    again, which starts a new operation.

    \param hmac storage for the HMAC context
    \param type hash type, such as WC_SHA256 or WC_SHA3_384
    \param check expected tag
    \param checkSz length of the expected tag; must equal the digest size of
    type
    \param in message that was authenticated
    \param inSz length of the message
    \param key HMAC key; may be NULL when keySz is 0
    \param keySz length of the key
    \param heap heap hint for dynamic memory, or NULL
    \param devId device ID for crypto callbacks or async, or INVALID_DEVID

    _Example_
    \code
    Hmac hmac;
    ret = wc_HmacVerify_ex(&hmac, WC_SHA256, tag, tagSz, msg, msgSz,
                           key, keySz, NULL, devId);
    \endcode

    \sa wc_HmacVerify
    \sa wc_HmacGenerate_ex
*/
int wc_HmacVerify_ex(Hmac* hmac, int type, const byte* check, word32 checkSz,
                     const byte* in, word32 inSz,
                     const byte* key, word32 keySz,
                     void* heap, int devId);

/*!
    \ingroup HMAC

    \brief This function provides access to a HMAC Key Derivation Function
    (HKDF). It utilizes HMAC to convert inKey, with an optional salt and
    optional info into a derived key, which it stores in out. The hash type
    defaults to MD5 if 0 or NULL is given.

    The HMAC configure option is --enable-hmac (on by default) or if building
    sources directly HAVE_HKDF

    \return 0 Returned upon successfully generating a key with the given inputs
    \return BAD_FUNC_ARG Returned if an invalid hash type is given (see type param)
    \return MEMORY_E Returned if there is an error allocating memory
    \return HMAC_MIN_KEYLEN_E May be returned when using a FIPS implementation
    and the key length specified is shorter than the minimum acceptable FIPS
    standard

    \param type hash type to use for the HKDF. Valid types are: WC_MD5, WC_SHA,
    WC_SHA256, WC_SHA384, WC_SHA512, WC_SHA3_224, WC_SHA3_256, WC_SHA3_384 or
    WC_SHA3_512
    \param inKey pointer to the buffer containing the key to use for KDF
    \param inKeySz length of the input key
    \param salt pointer to a buffer containing an optional salt. Use NULL
    instead if not using a salt
    \param saltSz length of the salt. Use 0 if not using a salt
    \param info pointer to a buffer containing optional additional info.
    Use NULL if not appending extra info
    \param infoSz length of additional info. Use 0 if not using additional info
    \param out pointer to the buffer in which to store the derived key
    \param outSz space available in the output buffer to store the
    generated key

    _Example_
    \code
    byte key[] = { // initialize with key };
    byte salt[] = { // initialize with salt };
    byte derivedKey[MAX_DIGEST_SIZE];

    int ret = wc_HKDF(WC_SHA512, key, sizeof(key), salt, sizeof(salt),
    NULL, 0, derivedKey, sizeof(derivedKey));
    if ( ret != 0 ) {
	    // error generating derived key
    }
    \endcode

    \sa wc_HmacSetKey
*/
int wc_HKDF(int type, const byte* inKey, word32 inKeySz,
                    const byte* salt, word32 saltSz,
                    const byte* info, word32 infoSz,
                    byte* out, word32 outSz);


/*!
    \ingroup HMAC

    \brief This function provides access to a HMAC Key Derivation Function
    (HKDF). It utilizes HMAC to convert inKey, with an optional salt
    into a derived key, which it stores in out. The hash type
    defaults to MD5 if 0 or NULL is given.

    The HMAC configure option is --enable-hmac (on by default) or if building
    sources directly HAVE_HKDF

    \return 0 Returned upon successfully generating a key with the given inputs
    \return BAD_FUNC_ARG Returned if an invalid hash type is given (see type param)
    \return MEMORY_E Returned if there is an error allocating memory
    \return HMAC_MIN_KEYLEN_E May be returned when using a FIPS implementation
    and the key length specified is shorter than the minimum acceptable FIPS
    standard

    \param type hash type to use for the HKDF. Valid types are: WC_MD5, WC_SHA,
    WC_SHA256, WC_SHA384, WC_SHA512, WC_SHA3_224, WC_SHA3_256, WC_SHA3_384 or
    WC_SHA3_512
    \param salt pointer to a buffer containing an optional salt. Use NULL
    instead if not using a salt
    \param saltSz length of the salt. Use 0 if not using a salt
    \param inKey pointer to the buffer containing the key to use for KDF
    \param inKeySz length of the input key
    \param out pointer to the buffer in which to store the derived key

    _Example_
    \code
    byte key[] = { // initialize with key };
    byte salt[] = { // initialize with salt };
    byte derivedKey[MAX_DIGEST_SIZE];

    int ret = wc_HKDF_Extract(WC_SHA512, salt, sizeof(salt), key, sizeof(key),
        derivedKey);
    if ( ret != 0 ) {
	    // error generating derived key
    }
    \endcode

    \sa wc_HKDF
    \sa wc_HKDF_Extract_ex
    \sa wc_HKDF_Expand
    \sa wc_HKDF_Expand_ex
*/
int wc_HKDF_Extract(
    int type,
    const byte* salt, word32 saltSz,
    const byte* inKey, word32 inKeySz,
    byte* out);

/*!
    \ingroup HMAC

    \brief This function provides access to a HMAC Key Derivation Function
    (HKDF). It utilizes HMAC to convert inKey, with an optional salt
    into a derived key, which it stores in out. The hash type
    defaults to MD5 if 0 or NULL is given. This is the _ex version adding
    heap hint and device identifier.

    The HMAC configure option is --enable-hmac (on by default) or if building
    sources directly HAVE_HKDF

    \return 0 Returned upon successfully generating a key with the given inputs
    \return BAD_FUNC_ARG Returned if an invalid hash type is given (see type param)
    \return MEMORY_E Returned if there is an error allocating memory
    \return HMAC_MIN_KEYLEN_E May be returned when using a FIPS implementation
    and the key length specified is shorter than the minimum acceptable FIPS
    standard
    \return WC_PENDING_E May be returned in a WOLF_CRYPTO_CB build when the
    registered crypto callback device has taken the request but not yet
    finished it. The caller must re-invoke with identical arguments until the
    result is no longer WC_PENDING_E; HKDF has no WC_ASYNC_DEV, so this is a
    poll and not a wc_AsyncWait(). In a WOLFSSL_ASYNC_CRYPT build the TLS 1.3
    key schedule resumes a pending HKDF request by re-invoking the callback
    with identical arguments; without WOLFSSL_ASYNC_CRYPT a device also used
    for TLS 1.3 must complete HKDF requests synchronously. wc_HKDF_ex()
    follows the same contract and re-issues its extract step on every retry,
    so a device that pends must serve a repeated identical request from its
    completed result. There is no request handle: a device should key its
    completion tracking on the output pointer plus the argument tuple, and
    one that cannot correlate a retry that way must not pend.

    \param type hash type to use for the HKDF. Valid types are: WC_MD5, WC_SHA,
    WC_SHA256, WC_SHA384, WC_SHA512, WC_SHA3_224, WC_SHA3_256, WC_SHA3_384 or
    WC_SHA3_512
    \param salt pointer to a buffer containing an optional salt. Use NULL
    instead if not using a salt
    \param saltSz length of the salt. Use 0 if not using a salt
    \param inKey pointer to the buffer containing the key to use for KDF
    \param inKeySz length of the input key
    \param out pointer to the buffer in which to store the derived key. Must be
    digest length per hash 'type'.  See wc_HmacSizeByType()
    \param heap  heap hint to use for memory. Can be NULL
    \param devId ID to use with crypto callbacks or async hardware. Set to INVALID_DEVID (-2) if not used

    _Example_
    \code
    byte key[] = { // initialize with key };
    byte salt[] = { // initialize with salt };
    byte derivedKey[MAX_DIGEST_SIZE];

    int ret = wc_HKDF_Extract_ex(WC_SHA512, salt, sizeof(salt), key, sizeof(key),
        derivedKey, NULL, INVALID_DEVID);
    if ( ret != 0 ) {
	    // error generating derived key
    }
    \endcode

    \sa wc_HKDF
    \sa wc_HKDF_Extract
    \sa wc_HKDF_Expand
    \sa wc_HKDF_Expand_ex
    \sa wc_HmacSizeByType
*/
int wc_HKDF_Extract_ex(
    int type,
    const byte* salt, word32 saltSz,
    const byte* inKey, word32 inKeySz,
    byte* out,
    void* heap, int devId);

/*!
    \ingroup HMAC

    \brief This function provides access to a HMAC Key Derivation Function
    (HKDF). It utilizes HMAC to convert inKey, with optional info into a
    derived key, which it stores in out. The hash type
    defaults to MD5 if 0 or NULL is given.

    The HMAC configure option is --enable-hmac (on by default) or if building
    sources directly HAVE_HKDF

    \return 0 Returned upon successfully generating a key with the given inputs
    \return BAD_FUNC_ARG Returned if an invalid hash type is given (see type param)
    \return MEMORY_E Returned if there is an error allocating memory
    \return HMAC_MIN_KEYLEN_E May be returned when using a FIPS implementation
    and the key length specified is shorter than the minimum acceptable FIPS
    standard

    \param type hash type to use for the HKDF. Valid types are: WC_MD5, WC_SHA,
    WC_SHA256, WC_SHA384, WC_SHA512, WC_SHA3_224, WC_SHA3_256, WC_SHA3_384 or
    WC_SHA3_512
    \param inKey pointer to the buffer containing the key to use for KDF
    \param inKeySz length of the input key
    \param info pointer to a buffer containing optional additional info.
    Use NULL if not appending extra info
    \param infoSz length of additional info. Use 0 if not using additional info
    \param out pointer to the buffer in which to store the derived key
    \param outSz space available in the output buffer to store the
    generated key

    _Example_
    \code
    byte key[] = { // initialize with key };
    byte salt[] = { // initialize with salt };
    byte derivedKey[MAX_DIGEST_SIZE];

    int ret = wc_HKDF_Expand(WC_SHA512, key, sizeof(key), NULL, 0,
        derivedKey, sizeof(derivedKey));
    if ( ret != 0 ) {
	    // error generating derived key
    }
    \endcode

    \sa wc_HKDF
    \sa wc_HKDF_Extract
    \sa wc_HKDF_Extract_ex
    \sa wc_HKDF_Expand_ex
*/
int wc_HKDF_Expand(
    int type,
    const byte* inKey, word32 inKeySz,
    const byte* info, word32 infoSz,
    byte* out, word32 outSz);

/*!
    \ingroup HMAC

    \brief This function provides access to a HMAC Key Derivation Function
    (HKDF). It utilizes HMAC to convert inKey, with optional info into a
    derived key, which it stores in out. The hash type
    defaults to MD5 if 0 or NULL is given. This is the _ex version adding
    heap hint and device identifier.

    The HMAC configure option is --enable-hmac (on by default) or if building
    sources directly HAVE_HKDF

    \return 0 Returned upon successfully generating a key with the given inputs
    \return BAD_FUNC_ARG Returned if an invalid hash type is given (see type param)
    \return MEMORY_E Returned if there is an error allocating memory
    \return HMAC_MIN_KEYLEN_E May be returned when using a FIPS implementation
    and the key length specified is shorter than the minimum acceptable FIPS
    standard
    \return WC_PENDING_E May be returned in a WOLF_CRYPTO_CB build when the
    registered crypto callback device has taken the request but not yet
    finished it. The caller must re-invoke with identical arguments until the
    result is no longer WC_PENDING_E; HKDF has no WC_ASYNC_DEV, so this is a
    poll and not a wc_AsyncWait(). In a WOLFSSL_ASYNC_CRYPT build the TLS 1.3
    key schedule resumes a pending HKDF request by re-invoking the callback
    with identical arguments; without WOLFSSL_ASYNC_CRYPT a device also used
    for TLS 1.3 must complete HKDF requests synchronously. wc_HKDF_ex()
    follows the same contract and re-issues its extract step on every retry,
    so a device that pends must serve a repeated identical request from its
    completed result. There is no request handle: a device should key its
    completion tracking on the output pointer plus the argument tuple, and
    one that cannot correlate a retry that way must not pend.

    \param type hash type to use for the HKDF. Valid types are: WC_MD5, WC_SHA,
    WC_SHA256, WC_SHA384, WC_SHA512, WC_SHA3_224, WC_SHA3_256, WC_SHA3_384 or
    WC_SHA3_512
    \param inKey pointer to the buffer containing the key to use for KDF
    \param inKeySz length of the input key
    \param info pointer to a buffer containing optional additional info.
    Use NULL if not appending extra info
    \param infoSz length of additional info. Use 0 if not using additional info
    \param out pointer to the buffer in which to store the derived key
    \param outSz space available in the output buffer to store the
    generated key
    \param heap  heap hint to use for memory. Can be NULL
    \param devId ID to use with crypto callbacks or async hardware. Set to INVALID_DEVID (-2) if not used

    _Example_
    \code
    byte key[] = { // initialize with key };
    byte salt[] = { // initialize with salt };
    byte derivedKey[MAX_DIGEST_SIZE];

    int ret = wc_HKDF_Expand_ex(WC_SHA512, key, sizeof(key), NULL, 0,
        derivedKey, sizeof(derivedKey), NULL, INVALID_DEVID);
    if ( ret != 0 ) {
	    // error generating derived key
    }
    \endcode

    \sa wc_HKDF
    \sa wc_HKDF_Extract
    \sa wc_HKDF_Extract_ex
    \sa wc_HKDF_Expand
*/
int wc_HKDF_Expand_ex(
    int type,
    const byte* inKey, word32 inKeySz,
    const byte* info, word32 infoSz,
    byte* out, word32 outSz,
    void* heap, int devId);

/*!
    \ingroup HMAC

    \brief This function provides access to RFC 5869
    HMAC-based Extract-and-Expand Key Derivation Function (HKDF) for TLS v1.3
    key derivation

    \return 0 Returned upon successfully generating a key with the given inputs
    \return BAD_FUNC_ARG Returned if an invalid hash type is given (see digest
    param), if prk is NULL, or if ikm is NULL and ikmLen is not 0
    \return MEMORY_E Returned if there is an error allocating memory
    \return HMAC_MIN_KEYLEN_E May be returned when using a FIPS implementation
    and the key length specified is shorter than the minimum acceptable FIPS
    standard

    \param prk     Generated pseudorandom key
    \param salt    salt. May be NULL, in which case saltLen is ignored
    \param saltLen length of the salt
    \param ikm     input keying material. May be NULL when ikmLen is 0
    \param ikmLen  length of the input keying material. 0 substitutes a digest
    length zeroed IKM per RFC 8446, not an empty IKM
    \param digest  hash type to use for the HKDF. Valid types are: WC_SHA256,
    WC_SHA384, WC_SHA512 or WC_SM3

    _Example_
    \code
    byte ikm[] = { // initialize with input keying material };
    byte salt[] = { // initialize with optional salt };
    byte prk[MAX_DIGEST_SIZE];

    int ret = wc_Tls13_HKDF_Extract(prk, salt, sizeof(salt), ikm, sizeof(ikm),
        WC_SHA512);
    if ( ret != 0 ) {
	    // error generating derived key
    }
    \endcode

    \sa wc_HKDF
    \sa wc_HKDF_Extract
    \sa wc_HKDF_Extract_ex
    \sa wc_HKDF_Expand
    \sa wc_Tls13_HKDF_Extract_ex
*/
int wc_Tls13_HKDF_Extract(
    byte* prk,
    const byte* salt, word32 saltLen,
    byte* ikm, word32 ikmLen, int digest);

/*!
    \ingroup HMAC

    \brief This function provides access to RFC 5869
    HMAC-based Extract-and-Expand Key Derivation Function (HKDF) for TLS v1.3
    key derivation. This is the _ex version adding heap hint and device identifier.

    \return 0 Returned upon successfully generating a key with the given inputs
    \return BAD_FUNC_ARG Returned if an invalid hash type is given (see digest
    param), if prk is NULL, or if ikm is NULL and ikmLen is not 0
    \return MEMORY_E Returned if there is an error allocating memory
    \return HMAC_MIN_KEYLEN_E May be returned when using a FIPS implementation
    and the key length specified is shorter than the minimum acceptable FIPS
    standard
    \return WC_PENDING_E May be returned in a WOLF_CRYPTO_CB build when the
    registered crypto callback device has taken the request but not yet
    finished it; the caller re-invokes with identical arguments until the
    result is no longer WC_PENDING_E. The TLS 1.3 key schedule does this in
    WOLFSSL_ASYNC_CRYPT builds.

    \param prk     Generated pseudorandom key
    \param salt    Salt. May be NULL; saltLen is then ignored unless a crypto
    callback handles the request
    \param saltLen Length of the salt
    \param ikm     Input keying material. May be NULL when ikmLen is 0
    \param ikmLen  Length of the input keying material. 0 substitutes a digest
    length zeroed IKM per RFC 8446, not an empty IKM
    \param digest  Hash type to use for the HKDF. Valid types are: WC_SHA256,
    WC_SHA384, WC_SHA512 or WC_SM3
    \param heap    Heap hint to use for memory. Can be NULL
    \param devId   ID to use with crypto callbacks or async hardware. Set to INVALID_DEVID (-2) if not used

    _Example_
    \code
    byte ikm[] = { // initialize with input keying material };
    byte salt[] = { // initialize with optional salt };
    byte prk[MAX_DIGEST_SIZE];

    int ret = wc_Tls13_HKDF_Extract_ex(prk, salt, sizeof(salt), ikm,
        sizeof(ikm), WC_SHA512, NULL, INVALID_DEVID);
    if ( ret != 0 ) {
	    // error generating derived key
    }
    \endcode

    \sa wc_HKDF
    \sa wc_HKDF_Extract
    \sa wc_HKDF_Extract_ex
    \sa wc_HKDF_Expand
    \sa wc_Tls13_HKDF_Extract
*/
int wc_Tls13_HKDF_Extract_ex(
    byte* prk,
    const byte* salt, word32 saltLen,
    byte* ikm, word32 ikmLen, int digest,
    void* heap, int devId);

/*!
    \ingroup HMAC

    \brief Expand data using HMAC, salt and label and info. TLS v1.3 defines
    this function for key derivation. This is the _ex version adding heap hint
    and device identifier.

    \return 0 Returned upon successfully generating a key with the given inputs
    \return BAD_FUNC_ARG Returned if an invalid hash type is given (see type param)
    \return MEMORY_E Returned if there is an error allocating memory
    \return HMAC_MIN_KEYLEN_E May be returned when using a FIPS implementation
    and the key length specified is shorter than the minimum acceptable FIPS
    standard
    \return WC_PENDING_E May be returned in a WOLF_CRYPTO_CB build when the
    registered crypto callback device has taken the request but not yet
    finished it; the caller re-invokes with identical arguments until the
    result is no longer WC_PENDING_E. The TLS 1.3 key schedule does this in
    WOLFSSL_ASYNC_CRYPT builds.

    \param okm         Generated pseudorandom key - output key material.
    \param okmLen      Length of generated pseudorandom key - output key material.
    \param prk         Salt - pseudo-random key.
    \param prkLen      Length of the salt - pseudo-random key.
    \param protocol    TLS protocol label.
    \param protocolLen Length of the TLS protocol label.
    \param info        Information to expand.
    \param infoLen     Length of the information.
    \param digest      Hash type to use for the HKDF. Valid types are: WC_SHA256, WC_SHA384 or WC_SHA512
    \param heap        Heap hint to use for memory. Can be NULL
    \param devId       ID to use with crypto callbacks or async hardware. Set to INVALID_DEVID (-2) if not used

    \sa wc_HKDF
    \sa wc_HKDF_Extract
    \sa wc_HKDF_Extract_ex
    \sa wc_HKDF_Expand
    \sa wc_Tls13_HKDF_Expand_Label
    \sa wc_Tls13_HKDF_Expand_Label_Alloc
*/
int wc_Tls13_HKDF_Expand_Label_ex(
    byte* okm, word32 okmLen,
    const byte* prk, word32 prkLen,
    const byte* protocol, word32 protocolLen,
    const byte* label, word32 labelLen,
    const byte* info, word32 infoLen,
    int digest,
    void* heap, int devId);

/*!
    \ingroup HMAC

    \brief Expand data using HMAC, salt and label and info. TLS v1.3 defines
    this function for key derivation.

    \return 0 Returned upon successfully generating a key with the given inputs
    \return BAD_FUNC_ARG Returned if an invalid hash type is given (see type param)
    \return MEMORY_E Returned if there is an error allocating memory
    \return HMAC_MIN_KEYLEN_E May be returned when using a FIPS implementation
    and the key length specified is shorter than the minimum acceptable FIPS
    standard

    \param okm         Generated pseudorandom key - output key material.
    \param okmLen      Length of generated pseudorandom key - output key material.
    \param prk         Salt - pseudo-random key.
    \param prkLen      Length of the salt - pseudo-random key.
    \param protocol    TLS protocol label.
    \param protocolLen Length of the TLS protocol label.
    \param info        Information to expand.
    \param infoLen     Length of the information.
    \param digest      Hash type to use for the HKDF. Valid types are: WC_SHA256, WC_SHA384 or WC_SHA512

    \sa wc_HKDF
    \sa wc_HKDF_Extract
    \sa wc_HKDF_Extract_ex
    \sa wc_HKDF_Expand
    \sa wc_Tls13_HKDF_Expand_Label_ex
    \sa wc_Tls13_HKDF_Expand_Label_Alloc
*/
int wc_Tls13_HKDF_Expand_Label(
    byte* okm, word32 okmLen,
    const byte* prk, word32 prkLen,
    const byte* protocol, word32 protocolLen,
    const byte* label, word32 labelLen,
    const byte* info, word32 infoLen,
    int digest);

/*!
    \ingroup HMAC

    \brief This functions is very similar to wc_Tls13_HKDF_Expand_Label(), but it
    allocates memory if the stack space usually used isn't enough. Expand data
    using HMAC, salt and label and info. TLS v1.3 defines this function for
    key derivation. This is the _ex version adding heap hint and device identifier.

    \return 0 Returned upon successfully generating a key with the given inputs
    \return BAD_FUNC_ARG Returned if an invalid hash type is given (see type param)
    \return MEMORY_E Returned if there is an error allocating memory
    \return HMAC_MIN_KEYLEN_E May be returned when using a FIPS implementation
    and the key length specified is shorter than the minimum acceptable FIPS
    standard
    \return WC_PENDING_E May be returned in a WOLF_CRYPTO_CB build when the
    registered crypto callback device has taken the request but not yet
    finished it; the caller re-invokes with identical arguments until the
    result is no longer WC_PENDING_E. The TLS 1.3 key schedule does this in
    WOLFSSL_ASYNC_CRYPT builds.

    \param okm         Generated pseudorandom key - output key material.
    \param okmLen      Length of generated pseudorandom key - output key material.
    \param prk         Salt - pseudo-random key.
    \param prkLen      Length of the salt - pseudo-random key.
    \param protocol    TLS protocol label.
    \param protocolLen Length of the TLS protocol label.
    \param info        Information to expand.
    \param infoLen     Length of the information.
    \param digest      Hash type to use for the HKDF. Valid types are: WC_SHA256, WC_SHA384 or WC_SHA512
    \param heap        Heap hint to use for memory. Can be NULL

    \sa wc_HKDF
    \sa wc_HKDF_Extract
    \sa wc_HKDF_Extract_ex
    \sa wc_HKDF_Expand
    \sa wc_Tls13_HKDF_Expand_Label
    \sa wc_Tls13_HKDF_Expand_Label_ex
*/
int wc_Tls13_HKDF_Expand_Label_Alloc(
    byte* okm, word32 okmLen,
    const byte* prk, word32 prkLen,
    const byte* protocol, word32 protocolLen,
    const byte* label, word32 labelLen,
    const byte* info, word32 infoLen,
    int digest, void* heap);
