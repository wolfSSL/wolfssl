/*!
    \ingroup SHA

    \brief This function initializes SHA3-224. This is automatically
    called by wc_Sha3_224Hash.

    \return 0 Returned upon successfully initializing

    \param sha3 pointer to the sha3 structure to use for encryption

    _Example_
    \code
    wc_Sha3 sha3[1];
    if ((ret = wc_InitSha3_224(sha3, NULL, INVALID_DEVID)) != 0) {
        WOLFSSL_MSG("wc_InitSha3_224 failed");
    }
    else {
        wc_Sha3_224_Update(sha3, data, len);
        wc_Sha3_224_Final(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_224Hash
    \sa wc_Sha3_224_Update
    \sa wc_Sha3_224_Final
*/
int wc_InitSha3_224(wc_Sha3* sha3, void* heap, int devId);

/*!
    \ingroup SHA

    \brief Can be called to continually hash the provided byte
    array of length len.

    \return 0 Returned upon successfully adding the data to the digest.

    \param sha3 pointer to the sha3 structure to use for encryption
    \param data the data to be hashed
    \param len length of data to be hashed

    _Example_
    \code
    wc_Sha3 sha3[1];
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha3_224(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_224 failed");
    }
    else {
        wc_Sha3_224_Update(sha3, data, len);
        wc_Sha3_224_Final(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_224Hash
    \sa wc_Sha3_224_Final
    \sa wc_InitSha3_224
*/
int wc_Sha3_224_Update(wc_Sha3* sha, const byte* data, word32 len);

/*!
    \ingroup SHA

    \brief Finalizes hashing of data. Result is placed into hash.
    Resets state of sha3 struct.

    \return 0 Returned upon successfully finalizing.

    \param sha3 pointer to the sha3 structure to use for encryption
    \param hash Byte array to hold hash value.

    _Example_
    \code
    wc_Sha3 sha3[1];
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha3_224(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_224 failed");
    }
    else {
       wc_Sha3_224_Update(sha3, data, len);
       wc_Sha3_224_Final(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_224Hash
    \sa wc_Sha3_224_GetHash
    \sa wc_InitSha3_224
*/
int wc_Sha3_224_Final(wc_Sha3* sha3, byte* hash);

/*!
    \ingroup SHA

    \brief Resets the wc_Sha3 structure.  Note: this is only supported
    if you have WOLFSSL_TI_HASH defined.

    \return none No returns.

    \param sha3 Pointer to the sha3 structure to be freed.

    _Example_
    \code
    wc_Sha3 sha3;
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha3_224(&sha3, NULL, INVALID_DEVID)) != 0) {
        WOLFSSL_MSG("wc_InitSha3_224 failed");
    }
    else {
        wc_Sha3_224_Update(&sha3, data, len);
        wc_Sha3_224_Final(&sha3, hash);
        wc_Sha3_224_Free(&sha3);
    }
    \endcode

    \sa wc_InitSha3_224
    \sa wc_Sha3_224_Update
    \sa wc_Sha3_224_Final
*/
void wc_Sha3_224_Free(wc_Sha3* sha3);

/*!
    \ingroup SHA

    \brief Gets hash data. Result is placed into hash.  Does not
    reset state of sha3 struct.

    \return 0 Returned upon successful copying of the hash.

    \param sha3 pointer to the sha3 structure to use for encryption
    \param hash Byte array to hold hash value.

    _Example_
    \code
    wc_Sha3 sha3[1];
    if ((ret = wc_InitSha3_224(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_224 failed");
    }
    else {
       wc_Sha3_224_Update(sha3, data, len);
       wc_Sha3_224_GetHash(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_224Hash
    \sa wc_Sha3_224_Final
    \sa wc_InitSha3_224
    \sa wc_Sha3_224_Copy
*/
int wc_Sha3_224_GetHash(wc_Sha3* sha3, byte* hash);

/*!
    \ingroup SHA

    \brief Copy the state of the hash.

    \return 0 Returned upon successful copying.

    \param sha3 pointer to the sha3 structure to copy
    \param dst  pointer to the sha3 structure to copy into

    _Example_
    \code
    wc_Sha3 sha3[1];
    wc_Sha3 sha3_dup[1];
    if ((ret = wc_InitSha3_224(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_224 failed");
    }
    else {
       wc_Sha3_224_Update(sha3, data, len);
       wc_Sha3_224_Copy(sha3, sha3_dup);
    }
    \endcode

    \sa wc_Sha3_224Hash
    \sa wc_Sha3_224_Final
    \sa wc_InitSha3_224
    \sa wc_Sha3_224_GetHash
*/
int wc_Sha3_224_Copy(wc_Sha3* sha3, wc_Sha3* dst);

/*!
    \ingroup SHA

    \brief This function initializes SHA3-256. This is automatically
    called by wc_Sha3_256Hash.

    \return 0 Returned upon successfully initializing

    \param sha3 pointer to the sha3 structure to use for encryption

    _Example_
    \code
    wc_Sha3 sha3[1];
    if ((ret = wc_InitSha3_256(sha3, NULL, INVALID_DEVID)) != 0) {
        WOLFSSL_MSG("wc_InitSha3_256 failed");
    }
    else {
        wc_Sha3_256_Update(sha3, data, len);
        wc_Sha3_256_Final(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_256Hash
    \sa wc_Sha3_256_Update
    \sa wc_Sha3_256_Final
*/
int wc_InitSha3_256(wc_Sha3* sha3, void* heap, int devId);

/*!
    \ingroup SHA

    \brief Can be called to continually hash the provided byte
    array of length len.

    \return 0 Returned upon successfully adding the data to the digest.

    \param sha3 pointer to the sha3 structure to use for encryption
    \param data the data to be hashed
    \param len length of data to be hashed

    _Example_
    \code
    wc_Sha3 sha3[1];
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha3_256(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_256 failed");
    }
    else {
        wc_Sha3_256_Update(sha3, data, len);
        wc_Sha3_256_Final(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_256Hash
    \sa wc_Sha3_256_Final
    \sa wc_InitSha3_256
*/
int wc_Sha3_256_Update(wc_Sha3* sha, const byte* data, word32 len);

/*!
    \ingroup SHA

    \brief Finalizes hashing of data. Result is placed into hash.
    Resets state of sha3 struct.

    \return 0 Returned upon successfully finalizing.

    \param sha3 pointer to the sha3 structure to use for encryption
    \param hash Byte array to hold hash value.

    _Example_
    \code
    wc_Sha3 sha3[1];
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha3_256(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_256 failed");
    }
    else {
       wc_Sha3_256_Update(sha3, data, len);
       wc_Sha3_256_Final(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_256Hash
    \sa wc_Sha3_256_GetHash
    \sa wc_InitSha3_256
*/
int wc_Sha3_256_Final(wc_Sha3* sha3, byte* hash);

/*!
    \ingroup SHA

    \brief Resets the wc_Sha3 structure.  Note: this is only supported
    if you have WOLFSSL_TI_HASH defined.

    \return none No returns.

    \param sha3 Pointer to the sha3 structure to be freed.

    _Example_
    \code
    wc_Sha3 sha3;
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha3_256(&sha3, NULL, INVALID_DEVID)) != 0) {
        WOLFSSL_MSG("wc_InitSha3_256 failed");
    }
    else {
        wc_Sha3_256_Update(&sha3, data, len);
        wc_Sha3_256_Final(&sha3, hash);
        wc_Sha3_256_Free(&sha3);
    }
    \endcode

    \sa wc_InitSha3_256
    \sa wc_Sha3_256_Update
    \sa wc_Sha3_256_Final
*/
void wc_Sha3_256_Free(wc_Sha3* sha3);

/*!
    \ingroup SHA

    \brief Gets hash data. Result is placed into hash.  Does not
    reset state of sha3 struct.

    \return 0 Returned upon successful copying of the hash.

    \param sha3 pointer to the sha3 structure to use for encryption
    \param hash Byte array to hold hash value.

    _Example_
    \code
    wc_Sha3 sha3[1];
    if ((ret = wc_InitSha3_256(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_256 failed");
    }
    else {
       wc_Sha3_256_Update(sha3, data, len);
       wc_Sha3_256_GetHash(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_256Hash
    \sa wc_Sha3_256_Final
    \sa wc_InitSha3_256
    \sa wc_Sha3_256_Copy
*/
int wc_Sha3_256_GetHash(wc_Sha3* sha3, byte* hash);

/*!
    \ingroup SHA

    \brief Copy the state of the hash.

    \return 0 Returned upon successful copying.

    \param sha3 pointer to the sha3 structure to copy
    \param dst  pointer to the sha3 structure to copy into

    _Example_
    \code
    wc_Sha3 sha3[1];
    wc_Sha3 sha3_dup[1];
    if ((ret = wc_InitSha3_256(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_256 failed");
    }
    else {
       wc_Sha3_256_Update(sha3, data, len);
       wc_Sha3_256_Copy(sha3, sha3_dup);
    }
    \endcode

    \sa wc_Sha3_256Hash
    \sa wc_Sha3_256_Final
    \sa wc_InitSha3_256
    \sa wc_Sha3_256_GetHash
*/
int wc_Sha3_256_Copy(wc_Sha3* sha3, wc_Sha3* dst);

/*!
    \ingroup SHA

    \brief This function initializes SHA3-384. This is automatically
    called by wc_Sha3_384Hash.

    \return 0 Returned upon successfully initializing

    \param sha3 pointer to the sha3 structure to use for encryption

    _Example_
    \code
    wc_Sha3 sha3[1];
    if ((ret = wc_InitSha3_384(sha3, NULL, INVALID_DEVID)) != 0) {
        WOLFSSL_MSG("wc_InitSha3_384 failed");
    }
    else {
        wc_Sha3_384_Update(sha3, data, len);
        wc_Sha3_384_Final(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_384Hash
    \sa wc_Sha3_384_Update
    \sa wc_Sha3_384_Final
*/
int wc_InitSha3_384(wc_Sha3* sha3, void* heap, int devId);

/*!
    \ingroup SHA

    \brief Can be called to continually hash the provided byte
    array of length len.

    \return 0 Returned upon successfully adding the data to the digest.

    \param sha3 pointer to the sha3 structure to use for encryption
    \param data the data to be hashed
    \param len length of data to be hashed

    _Example_
    \code
    wc_Sha3 sha3[1];
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha3_384(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_384 failed");
    }
    else {
        wc_Sha3_384_Update(sha3, data, len);
        wc_Sha3_384_Final(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_384Hash
    \sa wc_Sha3_384_Final
    \sa wc_InitSha3_384
*/
int wc_Sha3_384_Update(wc_Sha3* sha, const byte* data, word32 len);

/*!
    \ingroup SHA

    \brief Finalizes hashing of data. Result is placed into hash.
    Resets state of sha3 struct.

    \return 0 Returned upon successfully finalizing.

    \param sha3 pointer to the sha3 structure to use for encryption
    \param hash Byte array to hold hash value.

    _Example_
    \code
    wc_Sha3 sha3[1];
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha3_384(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_384 failed");
    }
    else {
       wc_Sha3_384_Update(sha3, data, len);
       wc_Sha3_384_Final(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_384Hash
    \sa wc_Sha3_384_GetHash
    \sa wc_InitSha3_384
*/
int wc_Sha3_384_Final(wc_Sha3* sha3, byte* hash);

/*!
    \ingroup SHA

    \brief Resets the wc_Sha3 structure.  Note: this is only supported
    if you have WOLFSSL_TI_HASH defined.

    \return none No returns.

    \param sha3 Pointer to the sha3 structure to be freed.

    _Example_
    \code
    wc_Sha3 sha3;
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha3_384(&sha3, NULL, INVALID_DEVID)) != 0) {
        WOLFSSL_MSG("wc_InitSha3_384 failed");
    }
    else {
        wc_Sha3_384_Update(&sha3, data, len);
        wc_Sha3_384_Final(&sha3, hash);
        wc_Sha3_384_Free(&sha3);
    }
    \endcode

    \sa wc_InitSha3_384
    \sa wc_Sha3_384_Update
    \sa wc_Sha3_384_Final
*/
void wc_Sha3_384_Free(wc_Sha3* sha3);

/*!
    \ingroup SHA

    \brief Gets hash data. Result is placed into hash.  Does not
    reset state of sha3 struct.

    \return 0 Returned upon successful copying of the hash.

    \param sha3 pointer to the sha3 structure to use for encryption
    \param hash Byte array to hold hash value.

    _Example_
    \code
    wc_Sha3 sha3[1];
    if ((ret = wc_InitSha3_384(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_38384ailed");
    }
    else {
       wc_Sha3_384_Update(sha3, data, len);
       wc_Sha3_384_GetHash(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_384Hash
    \sa wc_Sha3_384_Final
    \sa wc_InitSha3_384
    \sa wc_Sha3_384_Copy
*/
int wc_Sha3_384_GetHash(wc_Sha3* sha3, byte* hash);

/*!
    \ingroup SHA

    \brief Copy the state of the hash.

    \return 0 Returned upon successful copying.

    \param sha3 pointer to the sha3 structure to copy
    \param dst  pointer to the sha3 structure to copy into

    _Example_
    \code
    wc_Sha3 sha3[1];
    wc_Sha3 sha3_dup[1];
    if ((ret = wc_InitSha3_384(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_384 failed");
    }
    else {
       wc_Sha3_384_Update(sha3, data, len);
       wc_Sha3_384_Copy(sha3, sha3_dup);
    }
    \endcode

    \sa wc_Sha3_384Hash
    \sa wc_Sha3_384_Final
    \sa wc_InitSha3_384
    \sa wc_Sha3_384_GetHash
*/
int wc_Sha3_384_Copy(wc_Sha3* sha3, wc_Sha3* dst);

/*!
    \ingroup SHA

    \brief This function initializes SHA3-512. This is automatically
    called by wc_Sha3_512Hash.

    \return 0 Returned upon successfully initializing

    \param sha3 pointer to the sha3 structure to use for encryption

    _Example_
    \code
    wc_Sha3 sha3[1];
    if ((ret = wc_InitSha3_512(sha3, NULL, INVALID_DEVID)) != 0) {
        WOLFSSL_MSG("wc_InitSha3_512 failed");
    }
    else {
        wc_Sha3_512_Update(sha3, data, len);
        wc_Sha3_512_Final(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_512Hash
    \sa wc_Sha3_512_Update
    \sa wc_Sha3_512_Final
*/
int wc_InitSha3_512(wc_Sha3* sha3, void* heap, int devId);

/*!
    \ingroup SHA

    \brief Can be called to continually hash the provided byte
    array of length len.

    \return 0 Returned upon successfully adding the data to the digest.

    \param sha3 pointer to the sha3 structure to use for encryption
    \param data the data to be hashed
    \param len length of data to be hashed

    _Example_
    \code
    wc_Sha3 sha3[1];
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha3_512(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_512 failed");
    }
    else {
        wc_Sha3_512_Update(sha3, data, len);
        wc_Sha3_512_Final(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_512Hash
    \sa wc_Sha3_512_Final
    \sa wc_InitSha3_512
*/
int wc_Sha3_512_Update(wc_Sha3* sha, const byte* data, word32 len);

/*!
    \ingroup SHA

    \brief Finalizes hashing of data. Result is placed into hash.
    Resets state of sha3 struct.

    \return 0 Returned upon successfully finalizing.

    \param sha3 pointer to the sha3 structure to use for encryption
    \param hash Byte array to hold hash value.

    _Example_
    \code
    wc_Sha3 sha3[1];
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha3_512(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_512 failed");
    }
    else {
       wc_Sha3_512_Update(sha3, data, len);
       wc_Sha3_512_Final(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_512Hash
    \sa wc_Sha3_512_GetHash
    \sa wc_InitSha3_512
*/
int wc_Sha3_512_Final(wc_Sha3* sha3, byte* hash);

/*!
    \ingroup SHA

    \brief Resets the wc_Sha3 structure.  Note: this is only supported
    if you have WOLFSSL_TI_HASH defined.

    \return none No returns.

    \param sha3 Pointer to the sha3 structure to be freed.

    _Example_
    \code
    wc_Sha3 sha3;
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha3_512(&sha3, NULL, INVALID_DEVID)) != 0) {
        WOLFSSL_MSG("wc_InitSha3_512 failed");
    }
    else {
        wc_Sha3_512_Update(&sha3, data, len);
        wc_Sha3_512_Final(&sha3, hash);
        wc_Sha3_512_Free(&sha3);
    }
    \endcode

    \sa wc_InitSha3_512
    \sa wc_Sha3_512_Update
    \sa wc_Sha3_512_Final
*/
void wc_Sha3_512_Free(wc_Sha3* sha3);

/*!
    \ingroup SHA

    \brief Gets hash data. Result is placed into hash.  Does not
    reset state of sha3 struct.

    \return 0 Returned upon successful copying of the hash.

    \param sha3 pointer to the sha3 structure to use for encryption
    \param hash Byte array to hold hash value.

    _Example_
    \code
    wc_Sha3 sha3[1];
    if ((ret = wc_InitSha3_512(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_512 failed");
    }
    else {
       wc_Sha3_512_Update(sha3, data, len);
       wc_Sha3_512_GetHash(sha3, hash);
    }
    \endcode

    \sa wc_Sha3_512Hash
    \sa wc_Sha3_512_Final
    \sa wc_InitSha3_512
    \sa wc_Sha3_512_Copy
*/
int wc_Sha3_512_GetHash(wc_Sha3* sha3, byte* hash);

/*!
    \ingroup SHA

    \brief Copy the state of the hash.

    \return 0 Returned upon successful copying.

    \param sha3 pointer to the sha3 structure to copy
    \param dst  pointer to the sha3 structure to copy into

    _Example_
    \code
    wc_Sha3 sha3[1];
    wc_Sha3 sha3_dup[1];
    if ((ret = wc_InitSha3_512(sha3, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitSha3_512 failed");
    }
    else {
       wc_Sha3_512_Update(sha3, data, len);
       wc_Sha3_512_Copy(sha3, sha3_dup);
    }
    \endcode

    \sa wc_Sha3_512Hash
    \sa wc_Sha3_512_Final
    \sa wc_InitSha3_512
    \sa wc_Sha3_512_GetHash
*/
int wc_Sha3_512_Copy(wc_Sha3* sha3, wc_Sha3* dst);

/*!
    \ingroup SHA

    \brief This function initializes SHAKE-128. This is automatically
    called by wc_Shake128Hash.

    \return 0 Returned upon successfully initializing

    \param shake pointer to the shake structure to use for encryption

    _Example_
    \code
    wc_Shake shake[1];
    if ((ret = wc_InitShake128(shake, NULL, INVALID_DEVID)) != 0) {
        WOLFSSL_MSG("wc_InitShake128 failed");
    }
    else {
        wc_Shake128_Update(shake, data, len);
        wc_Shake128_Final(shake, hash);
    }
    \endcode

    \sa wc_Shake128Hash
    \sa wc_Shake128_Update
    \sa wc_Shake128_Final
*/
int wc_InitShake128(wc_Shake* shake, void* heap, int devId);

/*!
    \ingroup SHA

    \brief Can be called to continually hash the provided byte
    array of length len.

    \return 0 Returned upon successfully adding the data to the digest.

    \param shake pointer to the shake structure to use for encryption
    \param data the data to be hashed
    \param len length of data to be hashed

    _Example_
    \code
    wc_Shake shake[1];
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitShake128(shake, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitShake128 failed");
    }
    else {
        wc_Shake128_Update(shake, data, len);
        wc_Shake128_Final(shake, hash);
    }
    \endcode

    \sa wc_Shake128Hash
    \sa wc_Shake128_Final
    \sa wc_InitShake128
*/
int wc_Shake128_Update(wc_Shake* sha, const byte* data, word32 len);

/*!
    \ingroup SHA

    \brief Finalizes hashing of data. Result is placed into hash.
    Resets state of shake struct.

    \return 0 Returned upon successfully finalizing.

    \param shake pointer to the shake structure to use for encryption
    \param hash Byte array to hold hash value.
    \param hashLen Number of bytes to write to hash.

    _Example_
    \code
    wc_Shake shake[1];
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitShake128(shake, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitShake128 failed");
    }
    else {
       wc_Shake128_Update(shake, data, len);
       wc_Shake128_Final(shake, hash);
    }
    \endcode

    \sa wc_Shake128Hash
    \sa wc_Shake128_GetHash
    \sa wc_InitShake128
*/
int wc_Shake128_Final(wc_Shake* shake, byte* hash, word32 hashLen);

/*!
    \ingroup SHA

    \brief Called to absorb the provided byte array of length len. Cannot
    be called incrementally.

    \return 0 Returned upon successfully absorbed the data.

    \param shake pointer to the shake structure to use for encryption
    \param data the data to be absorbed
    \param len length of data to be absorbed

    _Example_
    \code
    wc_Shake shake[1];
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);
    byte out[2 * WC_SHA3_128_BLOCK_SIZE];
    int blocks = 2;

    if ((ret = wc_InitShake128(shake, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitShake128 failed");
    }
    else {
       wc_Shake128_Absorb(shake, data, len);
       wc_Shake128_SqueezeBlocks(shake, out, blocks);
    }
    \endcode

    \sa wc_Shake128_SqueezeBlocks
    \sa wc_InitShake128
*/
int wc_Shake128_Absorb(wc_Shake* sha, const byte* data, word32 len);

/*!
    \ingroup SHA

    \brief Squeeze out more blocks of data. Result is placed into out. Can be
    called inrementally.

    \return 0 Returned upon successfully squeezing.

    \param shake pointer to the shake structure to use for encryption
    \param hash Byte array to hold output.
    \param blocks Number of blocks to squeeze out. Each block is
    WC_SHA3_128_BLOCK_SIZE bytes in length.

    _Example_
    \code
    wc_Shake shake[1];
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);
    byte out[2 * WC_SHA3_128_BLOCK_SIZE];
    int blocks = 2;

    if ((ret = wc_InitShake128(shake, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitShake128 failed");
    }
    else {
       wc_Shake128_Absorb(shake, data, len);
       wc_Shake128_SqueezeBlocks(shake, out, blocks);
    }
    \endcode

    \sa wc_Shake128_Absorb
    \sa wc_InitShake128
*/
int wc_Shake128_SqueezeBlocks(wc_Shake* shake, byte* out, word32 blockCnt);

/*!
    \ingroup SHA

    \brief Resets the wc_Shake structure.  Note: this is only supported
    if you have WOLFSSL_TI_HASH defined.

    \return none No returns.

    \param shake Pointer to the shake structure to be freed.

    _Example_
    \code
    wc_Shake shake;
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitShake128(&shake, NULL, INVALID_DEVID)) != 0) {
        WOLFSSL_MSG("wc_InitShake128 failed");
    }
    else {
        wc_Shake128_Update(&shake, data, len);
        wc_Shake128_Final(&shake, hash);
        wc_Shake128_Free(&shake);
    }
    \endcode

    \sa wc_InitShake128
    \sa wc_Shake128_Update
    \sa wc_Shake128_Final
*/
void wc_Shake128_Free(wc_Shake* shake);

/*!
    \ingroup SHA

    \brief Gets hash data. Result is placed into hash.  Does not
    reset state of shake struct.

    \return 0 Returned upon successful copying of the hash.

    \param shake pointer to the shake structure to use for encryption
    \param hash Byte array to hold hash value.

    _Example_
    \code
    wc_Shake shake[1];
    if ((ret = wc_InitShake128(shake, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitShake128 failed");
    }
    else {
       wc_Shake128_Update(shake, data, len);
       wc_Shake128_GetHash(shake, hash);
    }
    \endcode

    \sa wc_Shake128Hash
    \sa wc_Shake128_Final
    \sa wc_InitShake128
    \sa wc_Shake128_Copy
*/
int wc_Shake128_GetHash(wc_Shake* shake, byte* hash);

/*!
    \ingroup SHA

    \brief Copy the state of the hash.

    \return 0 Returned upon successful copying.

    \param shake pointer to the shake structure to copy
    \param dst  pointer to the shake structure to copy into

    _Example_
    \code
    wc_Shake shake[1];
    wc_Shake shake_dup[1];
    if ((ret = wc_InitShake128(shake, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitShake128 failed");
    }
    else {
       wc_Shake128_Update(shake, data, len);
       wc_Shake128_Copy(shake, shake_dup);
    }
    \endcode

    \sa wc_Shake128Hash
    \sa wc_Shake128_Final
    \sa wc_InitShake128
    \sa wc_Shake128_GetHash
*/
int wc_Shake128_Copy(wc_Shake* src, wc_Sha3* dst);

/*!
    \ingroup SHA

    \brief This function initializes SHAKE-256. This is automatically
    called by wc_Shake256Hash.

    \return 0 Returned upon successfully initializing

    \param shake pointer to the shake structure to use for encryption

    _Example_
    \code
    wc_Shake shake[1];
    if ((ret = wc_InitShake256(shake, NULL, INVALID_DEVID)) != 0) {
        WOLFSSL_MSG("wc_InitShake256 failed");
    }
    else {
        wc_Shake256_Update(shake, data, len);
        wc_Shake256_Final(shake, hash, sizeof(hash));
    }
    \endcode

    \sa wc_Shake256Hash
    \sa wc_Shake256_Update
    \sa wc_Shake256_Final
*/
int wc_InitShake256(wc_Shake* shake, void* heap, int devId);

/*!
    \ingroup SHA

    \brief Can be called to continually hash the provided byte
    array of length len.

    \return 0 Returned upon successfully adding the data to the digest.

    \param shake pointer to the shake structure to use for encryption
    \param data the data to be hashed
    \param len length of data to be hashed

    _Example_
    \code
    wc_Shake shake[1];
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitShake256(shake, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitShake256 failed");
    }
    else {
        wc_Shake256_Update(shake, data, len);
        wc_Shake256_Final(shake, hash, sizeof(hash));
    }
    \endcode

    \sa wc_Shake256Hash
    \sa wc_Shake256_Final
    \sa wc_InitShake256
*/
int wc_Shake256_Update(wc_Shake* sha, const byte* data, word32 len);

/*!
    \ingroup SHA

    \brief Finalizes hashing of data. Result is placed into hash.
    Resets state of shake struct.

    \return 0 Returned upon successfully finalizing.

    \param shake pointer to the shake structure to use for encryption
    \param hash Byte array to hold hash value.
    \param hashLen Size of hash in bytes.

    _Example_
    \code
    wc_Shake shake[1];
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitShake256(shake, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitShake256 failed");
    }
    else {
       wc_Shake256_Update(shake, data, len);
       wc_Shake256_Final(shake, hash, sizeof(hash));
    }
    \endcode

    \sa wc_Shake256Hash
    \sa wc_Shake256_GetHash
    \sa wc_InitShake256
*/
int wc_Shake256_Final(wc_Shake* shake, byte* hash, word32 hashLen);

/*!
    \ingroup SHA

    \brief Called to absorb the provided byte array of length len. Cannot
    be called incrementally.

    \return 0 Returned upon successfully absorbed the data.

    \param shake pointer to the shake structure to use for encryption
    \param data the data to be absorbed
    \param len length of data to be absorbed

    _Example_
    \code
    wc_Shake shake[1];
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);
    byte out[2 * WC_SHA3_256_BLOCK_SIZE];
    int blocks = 2;

    if ((ret = wc_InitShake256(shake, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitShake256 failed");
    }
    else {
       wc_Shake256_Absorb(shake, data, len);
       wc_Shake256_SqueezeBlocks(shake, out, blocks);
    }
    \endcode

    \sa wc_Shake256_SqueezeBlocks
    \sa wc_InitShake256
*/
int wc_Shake256_Absorb(wc_Shake* sha, const byte* data, word32 len);

/*!
    \ingroup SHA

    \brief Squeeze out more blocks of data. Result is placed into out. Can be
    called incrementally.

    \return 0 Returned upon successfully squeezing.

    \param shake pointer to the shake structure to use for encryption
    \param hash Byte array to hold output.
    \param blocks Number of blocks to squeeze out. Each block is
    WC_SHA3_256_BLOCK_SIZE bytes in length.

    _Example_
    \code
    wc_Shake shake[1];
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);
    byte out[2 * WC_SHA3_256_BLOCK_SIZE];
    int blocks = 2;

    if ((ret = wc_InitShake256(shake, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitShake256 failed");
    }
    else {
       wc_Shake256_Absorb(shake, data, len);
       wc_Shake256_SqueezeBlocks(shake, out, blocks);
    }
    \endcode

    \sa wc_Shake256_Absorb
    \sa wc_InitShake256
*/
int wc_Shake256_SqueezeBlocks(wc_Shake* shake, byte* out, word32 blockCnt);

/*!
    \ingroup SHA

    \brief Resets the wc_Shake structure.  Note: this is only supported
    if you have WOLFSSL_TI_HASH defined.

    \return none No returns.

    \param shake Pointer to the shake structure to be freed.

    _Example_
    \code
    wc_Shake shake;
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitShake256(&shake, NULL, INVALID_DEVID)) != 0) {
        WOLFSSL_MSG("wc_InitShake256 failed");
    }
    else {
        wc_Shake256_Update(&shake, data, len);
        wc_Shake256_Final(&shake, hash, sizeof(hash));
        wc_Shake256_Free(&shake);
    }
    \endcode

    \sa wc_InitShake256
    \sa wc_Shake256_Update
    \sa wc_Shake256_Final
*/
void wc_Shake256_Free(wc_Shake* shake);

/*!
    \ingroup SHA

    \brief Gets hash data. Result is placed into hash.  Does not
    reset state of shake struct.

    \return 0 Returned upon successful copying of the hash.

    \param shake pointer to the shake structure to use for encryption
    \param hash Byte array to hold hash value.

    _Example_
    \code
    wc_Shake shake[1];
    if ((ret = wc_InitShake256(shake, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitShake256 failed");
    }
    else {
       wc_Shake256_Update(shake, data, len);
       wc_Shake256_GetHash(shake, hash);
    }
    \endcode

    \sa wc_Shake256Hash
    \sa wc_Shake256_Final
    \sa wc_InitShake256
    \sa wc_Shake256_Copy
*/
int wc_Shake256_GetHash(wc_Shake* shake, byte* hash);

/*!
    \ingroup SHA

    \brief Copy the state of the hash.

    \return 0 Returned upon successful copying.

    \param shake pointer to the shake structure to copy
    \param dst  pointer to the shake structure to copy into

    _Example_
    \code
    wc_Shake shake[1];
    wc_Shake shake_dup[1];
    if ((ret = wc_InitShake256(shake, NULL, INVALID_DEVID)) != 0) {
       WOLFSSL_MSG("wc_InitShake256 failed");
    }
    else {
       wc_Shake256_Update(shake, data, len);
       wc_Shake256_Copy(shake, shake_dup);
    }
    \endcode

    \sa wc_Shake256Hash
    \sa wc_Shake256_Final
    \sa wc_InitShake256
    \sa wc_Shake256_GetHash
*/
int wc_Shake256_Copy(wc_Shake* src, wc_Sha3* dst);

/*!
    \ingroup SHA

    \brief This function initializes a KMAC128 operation with a key and an
    optional customization string, per NIST SP 800-185. KMAC128 requires
    SHAKE128 (WOLFSSL_SHAKE128) and is enabled with WOLFSSL_KMAC.

    \return 0 Returned upon successfully initializing.
    \return BAD_FUNC_ARG Returned when kmac is NULL, or key/custom is NULL
    with a non-zero length.

    \param kmac pointer to the wc_Kmac structure to initialize.
    \param key the key bytes.
    \param keyLen length of the key in bytes.
    \param custom customization string, or NULL when customLen is 0.
    \param customLen length of the customization string in bytes.
    \param heap pointer to a heap hint, may be NULL.
    \param devId device identifier, or INVALID_DEVID.

    _Example_
    \code
    wc_Kmac kmac;
    byte key[32];
    byte data[] = { Data to authenticate };
    byte out[32];

    if (wc_InitKmac128(&kmac, key, sizeof(key), NULL, 0, NULL,
            INVALID_DEVID) == 0) {
        wc_Kmac128_Update(&kmac, data, sizeof(data));
        wc_Kmac128_Final(&kmac, out, sizeof(out));
        wc_Kmac128_Free(&kmac);
    }
    \endcode

    \sa wc_Kmac128_Update
    \sa wc_Kmac128_Final
    \sa wc_Kmac128_FinalXof
    \sa wc_Kmac128_Free
    \sa wc_Kmac128Hash
*/
int wc_InitKmac128(wc_Kmac* kmac, const byte* key, word32 keyLen,
    const byte* custom, word32 customLen, void* heap, int devId);

/*!
    \ingroup SHA

    \brief This function absorbs message data into a KMAC128 operation. It
    may be called any number of times before finalizing.

    \return 0 Returned upon successfully adding the data.
    \return BAD_FUNC_ARG Returned when kmac is NULL, or in is NULL with a
    non-zero length.

    \param kmac pointer to the wc_Kmac structure holding state.
    \param in the message data to authenticate.
    \param inLen length of the message data in bytes.

    _Example_
    \code
    wc_Kmac kmac;
    byte data[] = { Data to authenticate };

    if (wc_InitKmac128(&kmac, key, keyLen, NULL, 0, NULL,
            INVALID_DEVID) == 0) {
        wc_Kmac128_Update(&kmac, data, sizeof(data));
        wc_Kmac128_Final(&kmac, out, sizeof(out));
        wc_Kmac128_Free(&kmac);
    }
    \endcode

    \sa wc_InitKmac128
    \sa wc_Kmac128_Final
    \sa wc_Kmac128_Free
*/
int wc_Kmac128_Update(wc_Kmac* kmac, const byte* in, word32 inLen);

/*!
    \ingroup SHA

    \brief This function finalizes a KMAC128 operation, producing outLen
    bytes of output. The output length is bound into the result, so a KMAC
    with a different length is a different value.

    \return 0 Returned upon successfully finalizing.
    \return BAD_FUNC_ARG Returned when kmac is NULL, or out is NULL with a
    non-zero length.

    \param kmac pointer to the wc_Kmac structure holding state.
    \param out buffer to hold the output.
    \param outLen number of output bytes to produce.

    _Example_
    \code
    byte out[32];
    wc_Kmac128_Final(&kmac, out, sizeof(out));
    \endcode

    \sa wc_InitKmac128
    \sa wc_Kmac128_Update
    \sa wc_Kmac128_FinalXof
    \sa wc_Kmac128_Free
*/
int wc_Kmac128_Final(wc_Kmac* kmac, byte* out, word32 outLen);

/*!
    \ingroup SHA

    \brief This function finalizes a KMAC128 operation as an XOF
    (KMACXOF128). Unlike wc_Kmac128_Final, the output length is not bound
    into the result, so any amount of output may be requested.

    \return 0 Returned upon successfully finalizing.
    \return BAD_FUNC_ARG Returned when kmac is NULL, or out is NULL with a
    non-zero length.

    \param kmac pointer to the wc_Kmac structure holding state.
    \param out buffer to hold the output.
    \param outLen number of output bytes to produce.

    _Example_
    \code
    byte out[64];
    wc_Kmac128_FinalXof(&kmac, out, sizeof(out));
    \endcode

    \sa wc_InitKmac128
    \sa wc_Kmac128_Update
    \sa wc_Kmac128_Final
    \sa wc_Kmac128_Free
*/
int wc_Kmac128_FinalXof(wc_Kmac* kmac, byte* out, word32 outLen);

/*!
    \ingroup SHA

    \brief This function releases any resources associated with a KMAC128
    operation. Passing NULL is safe and does nothing.

    \param kmac pointer to the wc_Kmac structure to free, may be NULL.

    _Example_
    \code
    wc_Kmac128_Free(&kmac);
    \endcode

    \sa wc_InitKmac128
*/
void wc_Kmac128_Free(wc_Kmac* kmac);

/*!
    \ingroup SHA

    \brief This function computes a KMAC128 over a single message in one
    call, initializing, updating and finalizing internally.

    \return 0 Returned upon success.
    \return BAD_FUNC_ARG Returned when a required pointer is NULL with a
    non-zero length.

    \param key the key bytes.
    \param keyLen length of the key in bytes.
    \param custom customization string, or NULL when customLen is 0.
    \param customLen length of the customization string in bytes.
    \param in the message data to authenticate.
    \param inLen length of the message data in bytes.
    \param out buffer to hold the output.
    \param outLen number of output bytes to produce.

    _Example_
    \code
    byte key[32];
    byte data[] = { Data to authenticate };
    byte out[32];

    wc_Kmac128Hash(key, sizeof(key), NULL, 0, data, sizeof(data),
        out, sizeof(out));
    \endcode

    \sa wc_InitKmac128
    \sa wc_Kmac128_Update
    \sa wc_Kmac128_Final
*/
int wc_Kmac128Hash(const byte* key, word32 keyLen, const byte* custom,
    word32 customLen, const byte* in, word32 inLen, byte* out, word32 outLen);

/*!
    \ingroup SHA

    \brief This function computes a KMACXOF128 over a single message in one
    call. Like wc_Kmac128Hash but the output length is not bound into the
    result, so any amount of output may be requested.

    \return 0 Returned upon success.
    \return BAD_FUNC_ARG Returned when a required pointer is NULL with a
    non-zero length.

    \param key the key bytes.
    \param keyLen length of the key in bytes.
    \param custom customization string, or NULL when customLen is 0.
    \param customLen length of the customization string in bytes.
    \param in the message data to authenticate.
    \param inLen length of the message data in bytes.
    \param out buffer to hold the output.
    \param outLen number of output bytes to produce.

    _Example_
    \code
    byte key[32];
    byte data[] = { Data to authenticate };
    byte out[64];

    wc_Kmac128HashXof(key, sizeof(key), NULL, 0, data, sizeof(data),
        out, sizeof(out));
    \endcode

    \sa wc_InitKmac128
    \sa wc_Kmac128_FinalXof
    \sa wc_Kmac128Hash
*/
int wc_Kmac128HashXof(const byte* key, word32 keyLen, const byte* custom,
    word32 customLen, const byte* in, word32 inLen, byte* out, word32 outLen);

/*!
    \ingroup SHA

    \brief This function initializes a KMAC256 operation with a key and an
    optional customization string, per NIST SP 800-185. KMAC256 requires
    SHAKE256 (WOLFSSL_SHAKE256) and is enabled with WOLFSSL_KMAC.

    \return 0 Returned upon successfully initializing.
    \return BAD_FUNC_ARG Returned when kmac is NULL, or key/custom is NULL
    with a non-zero length.

    \param kmac pointer to the wc_Kmac structure to initialize.
    \param key the key bytes.
    \param keyLen length of the key in bytes.
    \param custom customization string, or NULL when customLen is 0.
    \param customLen length of the customization string in bytes.
    \param heap pointer to a heap hint, may be NULL.
    \param devId device identifier, or INVALID_DEVID.

    _Example_
    \code
    wc_Kmac kmac;
    byte key[32];
    byte data[] = { Data to authenticate };
    byte out[64];

    if (wc_InitKmac256(&kmac, key, sizeof(key), NULL, 0, NULL,
            INVALID_DEVID) == 0) {
        wc_Kmac256_Update(&kmac, data, sizeof(data));
        wc_Kmac256_Final(&kmac, out, sizeof(out));
        wc_Kmac256_Free(&kmac);
    }
    \endcode

    \sa wc_Kmac256_Update
    \sa wc_Kmac256_Final
    \sa wc_Kmac256_FinalXof
    \sa wc_Kmac256_Free
    \sa wc_Kmac256Hash
*/
int wc_InitKmac256(wc_Kmac* kmac, const byte* key, word32 keyLen,
    const byte* custom, word32 customLen, void* heap, int devId);

/*!
    \ingroup SHA

    \brief This function absorbs message data into a KMAC256 operation. It
    may be called any number of times before finalizing.

    \return 0 Returned upon successfully adding the data.
    \return BAD_FUNC_ARG Returned when kmac is NULL, or in is NULL with a
    non-zero length.

    \param kmac pointer to the wc_Kmac structure holding state.
    \param in the message data to authenticate.
    \param inLen length of the message data in bytes.

    _Example_
    \code
    wc_Kmac256_Update(&kmac, data, sizeof(data));
    \endcode

    \sa wc_InitKmac256
    \sa wc_Kmac256_Final
    \sa wc_Kmac256_Free
*/
int wc_Kmac256_Update(wc_Kmac* kmac, const byte* in, word32 inLen);

/*!
    \ingroup SHA

    \brief This function finalizes a KMAC256 operation, producing outLen
    bytes of output. The output length is bound into the result, so a KMAC
    with a different length is a different value.

    \return 0 Returned upon successfully finalizing.
    \return BAD_FUNC_ARG Returned when kmac is NULL, or out is NULL with a
    non-zero length.

    \param kmac pointer to the wc_Kmac structure holding state.
    \param out buffer to hold the output.
    \param outLen number of output bytes to produce.

    _Example_
    \code
    byte out[64];
    wc_Kmac256_Final(&kmac, out, sizeof(out));
    \endcode

    \sa wc_InitKmac256
    \sa wc_Kmac256_Update
    \sa wc_Kmac256_FinalXof
    \sa wc_Kmac256_Free
*/
int wc_Kmac256_Final(wc_Kmac* kmac, byte* out, word32 outLen);

/*!
    \ingroup SHA

    \brief This function finalizes a KMAC256 operation as an XOF
    (KMACXOF256). Unlike wc_Kmac256_Final, the output length is not bound
    into the result, so any amount of output may be requested.

    \return 0 Returned upon successfully finalizing.
    \return BAD_FUNC_ARG Returned when kmac is NULL, or out is NULL with a
    non-zero length.

    \param kmac pointer to the wc_Kmac structure holding state.
    \param out buffer to hold the output.
    \param outLen number of output bytes to produce.

    _Example_
    \code
    byte out[128];
    wc_Kmac256_FinalXof(&kmac, out, sizeof(out));
    \endcode

    \sa wc_InitKmac256
    \sa wc_Kmac256_Update
    \sa wc_Kmac256_Final
    \sa wc_Kmac256_Free
*/
int wc_Kmac256_FinalXof(wc_Kmac* kmac, byte* out, word32 outLen);

/*!
    \ingroup SHA

    \brief This function releases any resources associated with a KMAC256
    operation. Passing NULL is safe and does nothing.

    \param kmac pointer to the wc_Kmac structure to free, may be NULL.

    _Example_
    \code
    wc_Kmac256_Free(&kmac);
    \endcode

    \sa wc_InitKmac256
*/
void wc_Kmac256_Free(wc_Kmac* kmac);

/*!
    \ingroup SHA

    \brief This function computes a KMAC256 over a single message in one
    call, initializing, updating and finalizing internally.

    \return 0 Returned upon success.
    \return BAD_FUNC_ARG Returned when a required pointer is NULL with a
    non-zero length.

    \param key the key bytes.
    \param keyLen length of the key in bytes.
    \param custom customization string, or NULL when customLen is 0.
    \param customLen length of the customization string in bytes.
    \param in the message data to authenticate.
    \param inLen length of the message data in bytes.
    \param out buffer to hold the output.
    \param outLen number of output bytes to produce.

    _Example_
    \code
    byte key[32];
    byte data[] = { Data to authenticate };
    byte out[64];

    wc_Kmac256Hash(key, sizeof(key), NULL, 0, data, sizeof(data),
        out, sizeof(out));
    \endcode

    \sa wc_InitKmac256
    \sa wc_Kmac256_Update
    \sa wc_Kmac256_Final
*/
int wc_Kmac256Hash(const byte* key, word32 keyLen, const byte* custom,
    word32 customLen, const byte* in, word32 inLen, byte* out, word32 outLen);

/*!
    \ingroup SHA

    \brief This function computes a KMACXOF256 over a single message in one
    call. Like wc_Kmac256Hash but the output length is not bound into the
    result, so any amount of output may be requested.

    \return 0 Returned upon success.
    \return BAD_FUNC_ARG Returned when a required pointer is NULL with a
    non-zero length.

    \param key the key bytes.
    \param keyLen length of the key in bytes.
    \param custom customization string, or NULL when customLen is 0.
    \param customLen length of the customization string in bytes.
    \param in the message data to authenticate.
    \param inLen length of the message data in bytes.
    \param out buffer to hold the output.
    \param outLen number of output bytes to produce.

    _Example_
    \code
    byte key[32];
    byte data[] = { Data to authenticate };
    byte out[128];

    wc_Kmac256HashXof(key, sizeof(key), NULL, 0, data, sizeof(data),
        out, sizeof(out));
    \endcode

    \sa wc_InitKmac256
    \sa wc_Kmac256_FinalXof
    \sa wc_Kmac256Hash
*/
int wc_Kmac256HashXof(const byte* key, word32 keyLen, const byte* custom,
    word32 customLen, const byte* in, word32 inLen, byte* out, word32 outLen);


/*!
    \ingroup SHA

    \brief This function copies the state of a KMAC128 operation so it can be
    finalized more than once, for example over a common message prefix.

    \return 0 Returned upon success.
    \return BAD_FUNC_ARG Returned when src or dst is NULL.

    \param src pointer to the wc_Kmac structure to copy from.
    \param dst pointer to the wc_Kmac structure to copy into.

    _Example_
    \code
    wc_Kmac kmac;
    wc_Kmac copy;

    wc_InitKmac128(&kmac, key, keyLen, NULL, 0, NULL, INVALID_DEVID);
    wc_Kmac128_Update(&kmac, prefix, prefixLen);
    wc_Kmac128_Copy(&kmac, &copy);
    \endcode

    \sa wc_InitKmac128
    \sa wc_Kmac128_Update
    \sa wc_Kmac128_Final
*/
int wc_Kmac128_Copy(wc_Kmac* src, wc_Kmac* dst);

/*!
    \ingroup SHA

    \brief This function copies the state of a KMAC256 operation so it can be
    finalized more than once, for example over a common message prefix.

    \return 0 Returned upon success.
    \return BAD_FUNC_ARG Returned when src or dst is NULL.

    \param src pointer to the wc_Kmac structure to copy from.
    \param dst pointer to the wc_Kmac structure to copy into.

    _Example_
    \code
    wc_Kmac kmac;
    wc_Kmac copy;

    wc_InitKmac256(&kmac, key, keyLen, NULL, 0, NULL, INVALID_DEVID);
    wc_Kmac256_Update(&kmac, prefix, prefixLen);
    wc_Kmac256_Copy(&kmac, &copy);
    \endcode

    \sa wc_InitKmac256
    \sa wc_Kmac256_Update
    \sa wc_Kmac256_Final
*/
int wc_Kmac256_Copy(wc_Kmac* src, wc_Kmac* dst);

/*!
    \ingroup SHA

    \brief This function initializes a cSHAKE128 operation (customizable
    SHAKE, NIST SP 800-185) with a function-name and customization string.
    cSHAKE is enabled together with KMAC (WOLFSSL_KMAC). When both strings are
    empty, cSHAKE reduces to plain SHAKE128.

    \return 0 Returned upon successfully initializing.
    \return BAD_FUNC_ARG Returned when a required pointer is NULL.

    \param cshake pointer to the wc_Cshake structure to initialize.
    \param name function-name string (reserved for NIST-defined functions);
    use an empty string for application customization via custom.
    \param nameLen length of the function-name string in bytes.
    \param custom customization string, or NULL when customLen is 0.
    \param customLen length of the customization string in bytes.
    \param heap pointer to a heap hint, may be NULL.
    \param devId device identifier, or INVALID_DEVID.

    _Example_
    \code
    wc_Cshake cshake;
    byte out[32];

    if (wc_InitCshake128(&cshake, NULL, 0, custom, customLen, NULL,
            INVALID_DEVID) == 0) {
        wc_Cshake128_Update(&cshake, data, dataLen);
        wc_Cshake128_Final(&cshake, out, sizeof(out));
        wc_Cshake128_Free(&cshake);
    }
    \endcode

    \sa wc_Cshake128_Update
    \sa wc_Cshake128_Final
    \sa wc_Cshake128_Free
    \sa wc_Cshake128
*/
int wc_InitCshake128(wc_Cshake* cshake, const byte* name, word32 nameLen,
    const byte* custom, word32 customLen, void* heap, int devId);

/*!
    \ingroup SHA

    \brief This function absorbs message data into a cSHAKE128 operation.

    \return 0 Returned upon successfully adding the data.
    \return BAD_FUNC_ARG Returned when cshake is NULL, or in is NULL with a
    non-zero length.

    \param cshake pointer to the wc_Cshake structure holding state.
    \param in the message data.
    \param inLen length of the message data in bytes.

    _Example_
    \code
    wc_Cshake128_Update(&cshake, data, dataLen);
    \endcode

    \sa wc_InitCshake128
    \sa wc_Cshake128_Final
*/
int wc_Cshake128_Update(wc_Cshake* cshake, const byte* in, word32 inLen);

/*!
    \ingroup SHA

    \brief This function finalizes a cSHAKE128 operation, squeezing outLen
    bytes of output. cSHAKE is an XOF, so a longer squeeze extends a shorter
    one over the same input.

    \return 0 Returned upon successfully finalizing.
    \return BAD_FUNC_ARG Returned when cshake is NULL, or out is NULL with a
    non-zero length.

    \param cshake pointer to the wc_Cshake structure holding state.
    \param out buffer to hold the output.
    \param outLen number of output bytes to produce.

    _Example_
    \code
    byte out[32];
    wc_Cshake128_Final(&cshake, out, sizeof(out));
    \endcode

    \sa wc_InitCshake128
    \sa wc_Cshake128_Update
*/
int wc_Cshake128_Final(wc_Cshake* cshake, byte* out, word32 outLen);

/*!
    \ingroup SHA

    \brief This function releases any resources associated with a cSHAKE128
    operation. Passing NULL is safe and does nothing.

    \param cshake pointer to the wc_Cshake structure to free, may be NULL.

    _Example_
    \code
    wc_Cshake128_Free(&cshake);
    \endcode

    \sa wc_InitCshake128
*/
void wc_Cshake128_Free(wc_Cshake* cshake);

/*!
    \ingroup SHA

    \brief This function computes a cSHAKE128 over a single message in one
    call, initializing, updating and finalizing internally.

    \return 0 Returned upon success.
    \return BAD_FUNC_ARG Returned when a required pointer is NULL with a
    non-zero length.

    \param name function-name string, or NULL when nameLen is 0.
    \param nameLen length of the function-name string in bytes.
    \param custom customization string, or NULL when customLen is 0.
    \param customLen length of the customization string in bytes.
    \param in the message data.
    \param inLen length of the message data in bytes.
    \param out buffer to hold the output.
    \param outLen number of output bytes to produce.

    _Example_
    \code
    byte out[32];
    wc_Cshake128(NULL, 0, custom, customLen, data, dataLen, out, sizeof(out));
    \endcode

    \sa wc_InitCshake128
    \sa wc_Cshake128_Final
*/
int wc_Cshake128(const byte* name, word32 nameLen, const byte* custom,
    word32 customLen, const byte* in, word32 inLen, byte* out, word32 outLen);

/*!
    \ingroup SHA

    \brief This function initializes a cSHAKE256 operation (customizable
    SHAKE, NIST SP 800-185) with a function-name and customization string.
    cSHAKE is enabled together with KMAC (WOLFSSL_KMAC). When both strings are
    empty, cSHAKE reduces to plain SHAKE256.

    \return 0 Returned upon successfully initializing.
    \return BAD_FUNC_ARG Returned when a required pointer is NULL.

    \param cshake pointer to the wc_Cshake structure to initialize.
    \param name function-name string (reserved for NIST-defined functions);
    use an empty string for application customization via custom.
    \param nameLen length of the function-name string in bytes.
    \param custom customization string, or NULL when customLen is 0.
    \param customLen length of the customization string in bytes.
    \param heap pointer to a heap hint, may be NULL.
    \param devId device identifier, or INVALID_DEVID.

    _Example_
    \code
    wc_Cshake cshake;
    byte out[32];

    if (wc_InitCshake256(&cshake, NULL, 0, custom, customLen, NULL,
            INVALID_DEVID) == 0) {
        wc_Cshake256_Update(&cshake, data, dataLen);
        wc_Cshake256_Final(&cshake, out, sizeof(out));
        wc_Cshake256_Free(&cshake);
    }
    \endcode

    \sa wc_Cshake256_Update
    \sa wc_Cshake256_Final
    \sa wc_Cshake256_Free
    \sa wc_Cshake256
*/
int wc_InitCshake256(wc_Cshake* cshake, const byte* name, word32 nameLen,
    const byte* custom, word32 customLen, void* heap, int devId);

/*!
    \ingroup SHA

    \brief This function absorbs message data into a cSHAKE256 operation.

    \return 0 Returned upon successfully adding the data.
    \return BAD_FUNC_ARG Returned when cshake is NULL, or in is NULL with a
    non-zero length.

    \param cshake pointer to the wc_Cshake structure holding state.
    \param in the message data.
    \param inLen length of the message data in bytes.

    _Example_
    \code
    wc_Cshake256_Update(&cshake, data, dataLen);
    \endcode

    \sa wc_InitCshake256
    \sa wc_Cshake256_Final
*/
int wc_Cshake256_Update(wc_Cshake* cshake, const byte* in, word32 inLen);

/*!
    \ingroup SHA

    \brief This function finalizes a cSHAKE256 operation, squeezing outLen
    bytes of output. cSHAKE is an XOF, so a longer squeeze extends a shorter
    one over the same input.

    \return 0 Returned upon successfully finalizing.
    \return BAD_FUNC_ARG Returned when cshake is NULL, or out is NULL with a
    non-zero length.

    \param cshake pointer to the wc_Cshake structure holding state.
    \param out buffer to hold the output.
    \param outLen number of output bytes to produce.

    _Example_
    \code
    byte out[32];
    wc_Cshake256_Final(&cshake, out, sizeof(out));
    \endcode

    \sa wc_InitCshake256
    \sa wc_Cshake256_Update
*/
int wc_Cshake256_Final(wc_Cshake* cshake, byte* out, word32 outLen);

/*!
    \ingroup SHA

    \brief This function releases any resources associated with a cSHAKE256
    operation. Passing NULL is safe and does nothing.

    \param cshake pointer to the wc_Cshake structure to free, may be NULL.

    _Example_
    \code
    wc_Cshake256_Free(&cshake);
    \endcode

    \sa wc_InitCshake256
*/
void wc_Cshake256_Free(wc_Cshake* cshake);

/*!
    \ingroup SHA

    \brief This function computes a cSHAKE256 over a single message in one
    call, initializing, updating and finalizing internally.

    \return 0 Returned upon success.
    \return BAD_FUNC_ARG Returned when a required pointer is NULL with a
    non-zero length.

    \param name function-name string, or NULL when nameLen is 0.
    \param nameLen length of the function-name string in bytes.
    \param custom customization string, or NULL when customLen is 0.
    \param customLen length of the customization string in bytes.
    \param in the message data.
    \param inLen length of the message data in bytes.
    \param out buffer to hold the output.
    \param outLen number of output bytes to produce.

    _Example_
    \code
    byte out[32];
    wc_Cshake256(NULL, 0, custom, customLen, data, dataLen, out, sizeof(out));
    \endcode

    \sa wc_InitCshake256
    \sa wc_Cshake256_Final
*/
int wc_Cshake256(const byte* name, word32 nameLen, const byte* custom,
    word32 customLen, const byte* in, word32 inLen, byte* out, word32 outLen);


/*!
    \ingroup SHA

    \brief This function copies the state of a cSHAKE128 operation so it can be
    finalized more than once, for example over a common message prefix. dst
    must already be an initialized wc_Cshake.

    \return 0 Returned upon success.
    \return BAD_FUNC_ARG Returned when src or dst is NULL.

    \param src pointer to the wc_Cshake structure to copy from.
    \param dst pointer to the wc_Cshake structure to copy into.

    _Example_
    \code
    wc_Cshake cshake;
    wc_Cshake copy;

    wc_InitCshake128(&cshake, NULL, 0, custom, customLen, NULL, INVALID_DEVID);
    wc_InitCshake128(&copy, NULL, 0, custom, customLen, NULL, INVALID_DEVID);
    wc_Cshake128_Update(&cshake, prefix, prefixLen);
    wc_Cshake128_Copy(&cshake, &copy);
    \endcode

    \sa wc_InitCshake128
    \sa wc_Cshake128_Update
    \sa wc_Cshake128_Final
*/
int wc_Cshake128_Copy(wc_Cshake* src, wc_Cshake* dst);

/*!
    \ingroup SHA

    \brief This function copies the state of a cSHAKE256 operation so it can be
    finalized more than once, for example over a common message prefix. dst
    must already be an initialized wc_Cshake.

    \return 0 Returned upon success.
    \return BAD_FUNC_ARG Returned when src or dst is NULL.

    \param src pointer to the wc_Cshake structure to copy from.
    \param dst pointer to the wc_Cshake structure to copy into.

    _Example_
    \code
    wc_Cshake cshake;
    wc_Cshake copy;

    wc_InitCshake256(&cshake, NULL, 0, custom, customLen, NULL, INVALID_DEVID);
    wc_InitCshake256(&copy, NULL, 0, custom, customLen, NULL, INVALID_DEVID);
    wc_Cshake256_Update(&cshake, prefix, prefixLen);
    wc_Cshake256_Copy(&cshake, &copy);
    \endcode

    \sa wc_InitCshake256
    \sa wc_Cshake256_Update
    \sa wc_Cshake256_Final
*/
int wc_Cshake256_Copy(wc_Cshake* src, wc_Cshake* dst);
