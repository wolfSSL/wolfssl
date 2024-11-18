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

    \param type hash type to use for the HKDF. Valid types are: WC_MD5, WC_SHA,
    WC_SHA256, WC_SHA384, WC_SHA512, WC_SHA3_224, WC_SHA3_256, WC_SHA3_384 or
    WC_SHA3_512
    \param salt pointer to a buffer containing an optional salt. Use NULL
    instead if not using a salt
    \param saltSz length of the salt. Use 0 if not using a salt
    \param inKey pointer to the buffer containing the key to use for KDF
    \param inKeySz length of the input key
    \param out pointer to the buffer in which to store the derived key
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
    \return BAD_FUNC_ARG Returned if an invalid hash type is given (see type param)
    \return MEMORY_E Returned if there is an error allocating memory
    \return HMAC_MIN_KEYLEN_E May be returned when using a FIPS implementation
    and the key length specified is shorter than the minimum acceptable FIPS
    standard

    \param prk     Generated pseudorandom key
    \param salt    salt.
    \param saltLen length of the salt
    \param ikm     pointer to putput for keying material
    \param ikmLen  length of the input keying material buffer
    \param digest  hash type to use for the HKDF. Valid types are: WC_SHA256, WC_SHA384 or WC_SHA512

    _Example_
    \code
    byte secret[] = { // initialize with random key };
    byte salt[] = { // initialize with optional salt };
    byte masterSecret[MAX_DIGEST_SIZE];

    int ret = wc_Tls13_HKDF_Extract(secret, salt, sizeof(salt), 0,
        masterSecret, sizeof(masterSecret), WC_SHA512);
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
    \return BAD_FUNC_ARG Returned if an invalid hash type is given (see type param)
    \return MEMORY_E Returned if there is an error allocating memory
    \return HMAC_MIN_KEYLEN_E May be returned when using a FIPS implementation
    and the key length specified is shorter than the minimum acceptable FIPS
    standard

    \param prk     Generated pseudorandom key
    \param salt    Salt.
    \param saltLen Length of the salt
    \param ikm     Pointer to output for keying material
    \param ikmLen  Length of the input keying material buffer
    \param digest  Hash type to use for the HKDF. Valid types are: WC_SHA256, WC_SHA384 or WC_SHA512
    \param heap    Heap hint to use for memory. Can be NULL
    \param devId   ID to use with crypto callbacks or async hardware. Set to INVALID_DEVID (-2) if not used

    _Example_
    \code
    byte secret[] = { // initialize with random key };
    byte salt[] = { // initialize with optional salt };
    byte masterSecret[MAX_DIGEST_SIZE];

    int ret = wc_Tls13_HKDF_Extract_ex(secret, salt, sizeof(salt), 0,
        masterSecret, sizeof(masterSecret), WC_SHA512, NULL, INVALID_DEVID);
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
    this function for key derivation. This is the _ex version adding heap hint
    and device identifier.

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
