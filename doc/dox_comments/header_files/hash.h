/*!
    \ingroup wolfCrypt

    \brief This function will return the OID for the wc_HashType provided.

    \return OID returns value greater than 0
    \return HASH_TYPE_E hash type not supported.
    \return BAD_FUNC_ARG one of the provided arguments is incorrect.

    \param hash_type A hash type from the “enum  wc_HashType” such
    as “WC_HASH_TYPE_SHA256”.

    _Example_
    \code
    enum wc_HashType hash_type = WC_HASH_TYPE_SHA256;
    int oid = wc_HashGetOID(hash_type);
    if (oid > 0) {
    	// Success
    }
    \endcode

    \sa wc_HashGetDigestSize
    \sa wc_Hash
*/
int wc_HashGetOID(enum wc_HashType hash_type);

/*!
    \ingroup wolfCrypt

    \brief This function returns the size of the digest (output) for a
    hash_type. The returns size is used to make sure the output buffer
    provided to wc_Hash is large enough.

    \return Success A positive return value indicates the digest size
    for the hash.
    \return Error Returns HASH_TYPE_E if hash_type is not supported.
    \return Failure Returns BAD_FUNC_ARG if an invalid hash_type was used.

    \param hash_type A hash type from the “enum  wc_HashType” such as
    “WC_HASH_TYPE_SHA256”.

    _Example_
    \code
    int hash_len = wc_HashGetDigestSize(hash_type);
    if (hash_len <= 0) {
    WOLFSSL_MSG("Invalid hash type/len");
    return BAD_FUNC_ARG;
    }
    \endcode

    \sa wc_Hash
*/
int wc_HashGetDigestSize(enum wc_HashType hash_type);

/*!
    \ingroup wolfCrypt

    \brief This function performs a hash on the provided data buffer
    and returns it in the hash buffer provided.

    \return 0 Success, else error (such as BAD_FUNC_ARG or BUFFER_E).

    \param hash_type A hash type from the “enum  wc_HashType”
    such as “WC_HASH_TYPE_SHA256”.
    \param data Pointer to buffer containing the data to hash.
    \param data_len Length of the data buffer.
    \param hash Pointer to buffer used to output the final hash to.
    \param hash_len Length of the hash buffer.

    _Example_
    \code
    enum wc_HashType hash_type = WC_HASH_TYPE_SHA256;
    int hash_len = wc_HashGetDigestSize(hash_type);
    if (hash_len > 0) {
        int ret = wc_Hash(hash_type, data, data_len, hash_data, hash_len);
        if(ret == 0) {
		    // Success
        }
    }
    \endcode

    \sa wc_HashGetDigestSize
*/
int wc_Hash(enum wc_HashType hash_type,
    const byte* data, word32 data_len,
    byte* hash, word32 hash_len);

/*!
    \ingroup wolfCrypt

    \brief This function updates the hash in a wc_HashAlg object with the
    provided data. The hash algorithm used is the one stored in the
    wc_HashAlg object when it was initialized with wc_HashInit() or
    wc_HashInit_ex().

    \return 0 Success.
    \return BAD_FUNC_ARG hash is NULL, data is NULL while dataSz is greater
    than 0, the hash object was not initialized with a valid hash type, or
    type is not WC_HASH_TYPE_NONE and does not match the hash type used
    during initialization.
    \return HASH_TYPE_E the hash type stored in the hash object is not
    supported or not compiled in.
    \return Other negative error codes may be returned by the underlying
    hash algorithm's update function.

    \param hash Pointer to the wc_HashAlg object, previously initialized with
    wc_HashInit() or wc_HashInit_ex().
    \param type Must be either WC_HASH_TYPE_NONE or the same hash type that
    was used to initialize the hash object. The hash type stored in the hash
    object during initialization is always used to select the algorithm.
    Any other value results in BAD_FUNC_ARG.
    \param data Pointer to buffer containing the data to hash. May be NULL
    only if dataSz is 0.
    \param dataSz Length of the data buffer in bytes.

    _Example_
    \code
    wc_HashAlg hash;
    byte digest[WC_SHA256_DIGEST_SIZE];
    byte data[] = { 0x61, 0x62, 0x63 };
    int ret;

    ret = wc_HashInit(&hash, WC_HASH_TYPE_SHA256);
    if (ret == 0) {
        ret = wc_HashUpdate(&hash, WC_HASH_TYPE_SHA256, data, sizeof(data));
        if (ret == 0) {
            ret = wc_HashFinal(&hash, WC_HASH_TYPE_SHA256, digest);
        }
        wc_HashFree(&hash, WC_HASH_TYPE_SHA256);
    }
    \endcode

    \sa wc_HashFinal
    \sa wc_HashFree
*/
int wc_HashUpdate(wc_HashAlg* hash, enum wc_HashType type, const byte* data,
    word32 dataSz);

/*!
    \ingroup wolfCrypt

    \brief This function finalizes the hash in a wc_HashAlg object and
    writes the resulting digest to out. The hash algorithm used is the one
    stored in the wc_HashAlg object when it was initialized with
    wc_HashInit() or wc_HashInit_ex().

    \return 0 Success.
    \return BAD_FUNC_ARG hash or out is NULL, the hash object was not
    initialized with a valid hash type, or type is not WC_HASH_TYPE_NONE
    and does not match the hash type used during initialization.
    \return HASH_TYPE_E the hash type stored in the hash object is not
    supported or not compiled in.
    \return Other negative error codes may be returned by the underlying
    hash algorithm's final function.

    \param hash Pointer to the wc_HashAlg object, previously initialized with
    wc_HashInit() or wc_HashInit_ex().
    \param type Must be either WC_HASH_TYPE_NONE or the same hash type that
    was used to initialize the hash object. The hash type stored in the hash
    object during initialization is always used to select the algorithm.
    Any other value results in BAD_FUNC_ARG.
    \param out Pointer to the buffer to receive the digest. It must be at
    least as large as the digest size of the hash type the object was
    initialized with (see wc_HashGetDigestSize()).

    _Example_
    \code
    wc_HashAlg hash;
    byte digest[WC_SHA256_DIGEST_SIZE];
    byte data[] = { 0x61, 0x62, 0x63 };
    int ret;

    ret = wc_HashInit(&hash, WC_HASH_TYPE_SHA256);
    if (ret == 0) {
        ret = wc_HashUpdate(&hash, WC_HASH_TYPE_SHA256, data, sizeof(data));
        if (ret == 0) {
            ret = wc_HashFinal(&hash, WC_HASH_TYPE_SHA256, digest);
        }
        wc_HashFree(&hash, WC_HASH_TYPE_SHA256);
    }
    \endcode

    \sa wc_HashUpdate
    \sa wc_HashFree
    \sa wc_HashGetDigestSize
*/
int wc_HashFinal(wc_HashAlg* hash, enum wc_HashType type, byte* out);

/*!
    \ingroup wolfCrypt

    \brief This function frees any resources held by a wc_HashAlg object.
    The hash algorithm used is the one stored in the wc_HashAlg object when
    it was initialized with wc_HashInit() or wc_HashInit_ex(). The
    wc_HashAlg object itself is not freed.

    \return 0 Success.
    \return BAD_FUNC_ARG hash is NULL, the hash object was not initialized
    with a valid hash type, or type is not WC_HASH_TYPE_NONE and does not
    match the hash type used during initialization.
    \return HASH_TYPE_E the hash type stored in the hash object is not
    supported or not compiled in.

    \param hash Pointer to the wc_HashAlg object, previously initialized with
    wc_HashInit() or wc_HashInit_ex().
    \param type Must be either WC_HASH_TYPE_NONE or the same hash type that
    was used to initialize the hash object. The hash type stored in the hash
    object during initialization is always used to select the algorithm.
    Any other value results in BAD_FUNC_ARG.

    _Example_
    \code
    wc_HashAlg hash;

    if (wc_HashInit(&hash, WC_HASH_TYPE_SHA256) == 0) {
        // use hash
        wc_HashFree(&hash, WC_HASH_TYPE_SHA256);
    }
    \endcode

    \sa wc_HashUpdate
    \sa wc_HashFinal
*/
int wc_HashFree(wc_HashAlg* hash, enum wc_HashType type);

/*!
    \ingroup wolfCrypt

    \brief This function sets the flags of the underlying hash object in a
    wc_HashAlg object. The hash algorithm used is the one stored in the
    wc_HashAlg object when it was initialized with wc_HashInit() or
    wc_HashInit_ex(). Available when WOLFSSL_HASH_FLAGS is defined.

    \return 0 Success.
    \return BAD_FUNC_ARG hash is NULL, the hash object was not initialized
    with a valid hash type, or type is not WC_HASH_TYPE_NONE and does not
    match the hash type used during initialization.
    \return HASH_TYPE_E the hash type stored in the hash object is not
    supported or not compiled in.

    \param hash Pointer to the wc_HashAlg object, previously initialized with
    wc_HashInit() or wc_HashInit_ex().
    \param type Must be either WC_HASH_TYPE_NONE or the same hash type that
    was used to initialize the hash object. The hash type stored in the hash
    object during initialization is always used to select the algorithm.
    Any other value results in BAD_FUNC_ARG.
    \param flags Flags to set (for example WC_HASH_FLAG_ISCOPY).

    _Example_
    \code
    wc_HashAlg hash;

    if (wc_HashInit(&hash, WC_HASH_TYPE_SHA256) == 0) {
        wc_HashSetFlags(&hash, WC_HASH_TYPE_SHA256, WC_HASH_FLAG_NONE);
        wc_HashFree(&hash, WC_HASH_TYPE_SHA256);
    }
    \endcode

    \sa wc_HashGetFlags
*/
int wc_HashSetFlags(wc_HashAlg* hash, enum wc_HashType type, word32 flags);

/*!
    \ingroup wolfCrypt

    \brief This function gets the flags of the underlying hash object in a
    wc_HashAlg object. The hash algorithm used is the one stored in the
    wc_HashAlg object when it was initialized with wc_HashInit() or
    wc_HashInit_ex(). Available when WOLFSSL_HASH_FLAGS is defined.

    \return 0 Success.
    \return BAD_FUNC_ARG hash is NULL, the hash object was not initialized
    with a valid hash type, or type is not WC_HASH_TYPE_NONE and does not
    match the hash type used during initialization.
    \return HASH_TYPE_E the hash type stored in the hash object is not
    supported or not compiled in.

    \param hash Pointer to the wc_HashAlg object, previously initialized with
    wc_HashInit() or wc_HashInit_ex().
    \param type Must be either WC_HASH_TYPE_NONE or the same hash type that
    was used to initialize the hash object. The hash type stored in the hash
    object during initialization is always used to select the algorithm.
    Any other value results in BAD_FUNC_ARG.
    \param flags Pointer to receive the current flags. If NULL, no flags are
    returned.

    _Example_
    \code
    wc_HashAlg hash;
    word32 flags = 0;

    if (wc_HashInit(&hash, WC_HASH_TYPE_SHA256) == 0) {
        wc_HashGetFlags(&hash, WC_HASH_TYPE_SHA256, &flags);
        wc_HashFree(&hash, WC_HASH_TYPE_SHA256);
    }
    \endcode

    \sa wc_HashSetFlags
*/
int wc_HashGetFlags(wc_HashAlg* hash, enum wc_HashType type, word32* flags);

/*!
    \ingroup MD5

    \brief Convenience function, handles all the hashing and places the
    result into hash.

    \return 0 Returned upon successfully hashing the data.
    \return Memory_E memory error, unable to allocate memory. This is only
    possible with the small stack option enabled.

    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.
    \param hashLen Number of bytes to write to hash.

    _Example_
    \code
    const byte* data;
    word32 data_len;
    byte* hash;
    int ret;
    ...
    ret = wc_Md5Hash(data, data_len, hash);
    if (ret != 0) {
         // Md5 Hash Failure Case.
    }
    \endcode

    \sa wc_Md5Hash
    \sa wc_Md5Final
    \sa wc_InitMd5
*/
int wc_Md5Hash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief Convenience function, handles all the hashing and places the
    result into hash.

    \return 0 Returned upon successfully ….
    \return Memory_E memory error, unable to allocate memory. This is only
    possible with the small stack option enabled.

    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.

    _Example_
    \code
    none
    \endcode

    \sa wc_ShaHash
    \sa wc_ShaFinal
    \sa wc_InitSha
*/
int wc_ShaHash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief Convenience function, handles all the hashing and places the
    result into hash.

    \return 0 Success
    \return <0 Error

    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.

    _Example_
    \code
    none
    \endcode

    \sa wc_InitSha224
    \sa wc_Sha224Update
    \sa wc_Sha224Final
*/
int wc_Sha224Hash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief Convenience function, handles all the hashing and places the
    result into hash.

    \return 0 Returned upon successfully …
    \return Memory_E memory error, unable to allocate memory. This is only
    possible with the small stack option enabled.

    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.

    _Example_
    \code
    none
    \endcode

    \sa wc_Sha256Hash
    \sa wc_Sha256Final
    \sa wc_InitSha256
*/
int wc_Sha256Hash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief Convenience function, handles all the hashing and places the
    result into hash.

    \return 0 Returned upon successfully hashing the data
    \return Memory_E memory error, unable to allocate memory. This is only
    possible with the small stack option enabled.

    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.

    _Example_
    \code
    none
    \endcode

    \sa wc_Sha384Hash
    \sa wc_Sha384Final
    \sa wc_InitSha384
*/
int wc_Sha384Hash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief Convenience function, handles all the hashing and places the
    result into hash.

    \return 0 Returned upon successfully hashing the inputted data
    \return Memory_E memory error, unable to allocate memory. This is only
    possible with the small stack option enabled.

    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.

    _Example_
    \code
    none
    \endcode

    \sa wc_Sha512Hash
    \sa wc_Sha512Final
    \sa wc_InitSha512
*/
int wc_Sha512Hash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief Convenience function, handles all the hashing and places the
    result into hash.

    \return 0 Returned upon successfully hashing the data
    \return Memory_E memory error, unable to allocate memory. This is only
    possible with the small stack option enabled.

    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.

    _Example_
    \code
    none
    \endcode

    \sa wc_InitSha3_224
    \sa wc_Sha3_224_Update
    \sa wc_Sha3_224_Final
*/
int wc_Sha3_224Hash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief Convenience function, handles all the hashing and places the
    result into hash.

    \return 0 Returned upon successfully hashing the data
    \return Memory_E memory error, unable to allocate memory. This is only
    possible with the small stack option enabled.

    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.

    _Example_
    \code
    none
    \endcode

    \sa wc_InitSha3_256
    \sa wc_Sha3_256_Update
    \sa wc_Sha3_256_Final
*/
int wc_Sha3_256Hash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief Convenience function, handles all the hashing and places the
    result into hash.

    \return 0 Returned upon successfully hashing the data
    \return Memory_E memory error, unable to allocate memory. This is only
    possible with the small stack option enabled.

    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.

    _Example_
    \code
    none
    \endcode

    \sa wc_InitSha3_384
    \sa wc_Sha3_384_Update
    \sa wc_Sha3_384_Final
*/
int wc_Sha3_384Hash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief Convenience function, handles all the hashing and places the
    result into hash.

    \return 0 Returned upon successfully hashing the inputted data
    \return Memory_E memory error, unable to allocate memory. This is only
    possible with the small stack option enabled.

    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.

    _Example_
    \code
    none
    \endcode

    \sa wc_InitSha3_512
    \sa wc_Sha3_512_Update
    \sa wc_Sha3_512_Final
*/
int wc_Sha3_512Hash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief Convenience function, handles all the hashing and places the
    result into hash.

    \return 0 Returned upon successfully hashing the inputted data
    \return Memory_E memory error, unable to allocate memory. This is only
    possible with the small stack option enabled.

    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.

    _Example_
    \code
    none
    \endcode

    \sa wc_InitShake128
    \sa wc_Shake128_Update
    \sa wc_Shake128_Final
*/
int wc_Shake128Hash(const byte* data, word32 len, byte* hash,
                    word32 hashLen);

/*!
    \ingroup SHA

    \brief Convenience function, handles all the hashing and places the
    result into hash.

    \return 0 Returned upon successfully hashing the inputted data
    \return Memory_E memory error, unable to allocate memory. This is only
    possible with the small stack option enabled.

    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.
    \param hashLen Number of bytes to write to hash.

    _Example_
    \code
    none
    \endcode

    \sa wc_InitShake256
    \sa wc_Shake256_Update
    \sa wc_Shake256_Final
*/
int wc_Shake256Hash(const byte* data, word32 len, byte* hash,
                    word32 hashLen);


