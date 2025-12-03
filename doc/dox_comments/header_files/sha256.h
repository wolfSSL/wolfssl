/*!
    \ingroup SHA

    \brief This function initializes SHA256. This is automatically
    called by wc_Sha256Hash.

    \return 0 Returned upon successfully initializing

    \param sha256 pointer to the sha256 structure to use for encryption

    _Example_
    \code
    Sha256 sha256[1];
    if ((ret = wc_InitSha256(sha256)) != 0) {
        WOLFSSL_MSG("wc_InitSha256 failed");
    }
    else {
        wc_Sha256Update(sha256, data, len);
        wc_Sha256Final(sha256, hash);
    }
    \endcode

    \sa wc_Sha256Hash
    \sa wc_Sha256Update
    \sa wc_Sha256Final
*/
int wc_InitSha256(wc_Sha256* sha);

/*!
    \ingroup SHA

    \brief Can be called to continually hash the provided byte
    array of length len.

    \return 0 Returned upon successfully adding the data to the digest.

    \param sha256 pointer to the sha256 structure to use for encryption
    \param data the data to be hashed
    \param len length of data to be hashed

    _Example_
    \code
    Sha256 sha256[1];
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha256(sha256)) != 0) {
       WOLFSSL_MSG("wc_InitSha256 failed");
    }
    else {
        wc_Sha256Update(sha256, data, len);
        wc_Sha256Final(sha256, hash);
    }
    \endcode

    \sa wc_Sha256Hash
    \sa wc_Sha256Final
    \sa wc_InitSha256
*/
int wc_Sha256Update(wc_Sha256* sha, const byte* data, word32 len);

/*!
    \ingroup SHA

    \brief Finalizes hashing of data. Result is placed into hash.
    Resets state of sha256 struct.

    \return 0 Returned upon successfully finalizing.

    \param sha256 pointer to the sha256 structure to use for encryption
    \param hash Byte array to hold hash value.

    _Example_
    \code
    Sha256 sha256[1];
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha256(sha256)) != 0) {
       WOLFSSL_MSG("wc_InitSha256 failed");
    }
    else {
       wc_Sha256Update(sha256, data, len);
       wc_Sha256Final(sha256, hash);
    }
    \endcode

    \sa wc_Sha256Hash
    \sa wc_Sha256GetHash
    \sa wc_InitSha256
*/
int wc_Sha256Final(wc_Sha256* sha256, byte* hash);

/*!
    \ingroup SHA

    \brief Resets the Sha256 structure.  Note: this is only supported
    if you have WOLFSSL_TI_HASH defined.

    \return none No returns.

    \param sha256 Pointer to the sha256 structure to be freed.

    _Example_
    \code
    Sha256 sha256;
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha256(&sha256)) != 0) {
        WOLFSSL_MSG("wc_InitSha256 failed");
    }
    else {
        wc_Sha256Update(&sha256, data, len);
        wc_Sha256Final(&sha256, hash);
        wc_Sha256Free(&sha256);
    }
    \endcode

    \sa wc_InitSha256
    \sa wc_Sha256Update
    \sa wc_Sha256Final
*/
void wc_Sha256Free(wc_Sha256* sha256);

/*!
    \ingroup SHA

    \brief Gets hash data. Result is placed into hash.  Does not
    reset state of sha256 struct.

    \return 0 Returned upon successfully finalizing.

    \param sha256 pointer to the sha256 structure to use for encryption
    \param hash Byte array to hold hash value.

    _Example_
    \code
    Sha256 sha256[1];
    if ((ret = wc_InitSha256(sha256)) != 0) {
       WOLFSSL_MSG("wc_InitSha256 failed");
    }
    else {
       wc_Sha256Update(sha256, data, len);
       wc_Sha256GetHash(sha256, hash);
    }
    \endcode

    \sa wc_Sha256Hash
    \sa wc_Sha256Final
    \sa wc_InitSha256
*/
int wc_Sha256GetHash(wc_Sha256* sha256, byte* hash);

/*!
    \ingroup SHA

    \brief Used to initialize a Sha224 struct.

    \return 0 Success
    \return 1 Error returned because sha224 is null.

    \param sha224 Pointer to a Sha224 struct to initialize.

    _Example_
    \code
    Sha224 sha224;
    if(wc_InitSha224(&sha224) != 0)
    {
        // Handle error
    }
    \endcode

    \sa wc_Sha224Hash
    \sa wc_Sha224Update
    \sa wc_Sha224Final
*/
int wc_InitSha224(wc_Sha224* sha224);

/*!
    \ingroup SHA

    \brief Can be called to continually hash the provided byte array
    of length len.

    \return 0 Success
    \return 1 Error returned if function fails.
    \return BAD_FUNC_ARG Error returned if sha224 or data is null.

    \param sha224 Pointer to the Sha224 structure to use for encryption.
    \param data Data to be hashed.
    \param len Length of data to be hashed.

    _Example_
    \code
    Sha224 sha224;
    byte data[]; // Data to be hashed
    word32 len = sizeof(data);

    if ((ret = wc_InitSha224(&sha224)) != 0) {
       WOLFSSL_MSG("wc_InitSha224 failed");
    }
    else {
      wc_Sha224Update(&sha224, data, len);
      wc_Sha224Final(&sha224, hash);
    }
    \endcode

    \sa wc_InitSha224
    \sa wc_Sha224Final
    \sa wc_Sha224Hash
*/
int wc_Sha224Update(wc_Sha224* sha224, const byte* data, word32 len);

/*!
    \ingroup SHA

    \brief Finalizes hashing of data. Result is placed into hash.
    Resets state of sha224 struct.

    \return 0 Success
    \return <0 Error

    \param sha224 pointer to the sha224 structure to use for encryption
    \param hash Byte array to hold hash value.

    _Example_
    \code
    Sha224 sha224;
    byte data[]; // Data to be hashed
    word32 len = sizeof(data);

    if ((ret = wc_InitSha224(&sha224)) != 0) {
        WOLFSSL_MSG("wc_InitSha224 failed");
    }
    else {
        wc_Sha224Update(&sha224, data, len);
        wc_Sha224Final(&sha224, hash);
    }
    \endcode

    \sa wc_InitSha224
    \sa wc_Sha224Hash
    \sa wc_Sha224Update
*/
int wc_Sha224Final(wc_Sha224* sha224, byte* hash);

/*!
    \ingroup SHA
    \brief Initializes SHA256 with heap and device ID.

    \return 0 on success
    \return negative on error

    \param sha SHA256 structure
    \param heap Heap hint
    \param devId Device ID

    _Example_
    \code
    wc_Sha256 sha;
    int ret = wc_InitSha256_ex(&sha, NULL, INVALID_DEVID);
    \endcode

    \sa wc_InitSha256
*/
int wc_InitSha256_ex(wc_Sha256* sha, void* heap, int devId);

/*!
    \ingroup SHA
    \brief Gets raw hash without finalizing.

    \return 0 on success
    \return negative on error

    \param sha256 SHA256 structure
    \param hash Output hash buffer

    _Example_
    \code
    wc_Sha256 sha;
    byte hash[WC_SHA256_DIGEST_SIZE];
    int ret = wc_Sha256FinalRaw(&sha, hash);
    \endcode

    \sa wc_Sha256Final
*/
int wc_Sha256FinalRaw(wc_Sha256* sha256, byte* hash);

/*!
    \ingroup SHA
    \brief Transforms SHA256 block.

    \return 0 on success
    \return negative on error

    \param sha SHA256 structure
    \param data Block data

    _Example_
    \code
    wc_Sha256 sha;
    unsigned char block[WC_SHA256_BLOCK_SIZE];
    int ret = wc_Sha256Transform(&sha, block);
    \endcode

    \sa wc_Sha256Update
*/
int wc_Sha256Transform(wc_Sha256* sha, const unsigned char* data);

/*!
    \ingroup SHA
    \brief Hashes single block and outputs result.

    \return 0 on success
    \return negative on error

    \param sha SHA256 structure
    \param data Block data
    \param hash Output hash buffer

    _Example_
    \code
    wc_Sha256 sha;
    unsigned char block[WC_SHA256_BLOCK_SIZE];
    unsigned char hash[WC_SHA256_DIGEST_SIZE];
    int ret = wc_Sha256HashBlock(&sha, block, hash);
    \endcode

    \sa wc_Sha256Transform
*/
int wc_Sha256HashBlock(wc_Sha256* sha, const unsigned char* data,
    unsigned char* hash);

/*!
    \ingroup SHA
    \brief Grows SHA256 buffer with input data.

    \return 0 on success
    \return negative on error

    \param sha256 SHA256 structure
    \param in Input data
    \param inSz Input size

    _Example_
    \code
    wc_Sha256 sha;
    byte data[100];
    int ret = wc_Sha256_Grow(&sha, data, sizeof(data));
    \endcode

    \sa wc_Sha256Update
*/
int wc_Sha256_Grow(wc_Sha256* sha256, const byte* in, int inSz);

/*!
    \ingroup SHA
    \brief Copies SHA256 context.

    \return 0 on success
    \return negative on error

    \param src Source SHA256 structure
    \param dst Destination SHA256 structure

    _Example_
    \code
    wc_Sha256 src, dst;
    int ret = wc_Sha256Copy(&src, &dst);
    \endcode

    \sa wc_InitSha256
*/
int wc_Sha256Copy(wc_Sha256* src, wc_Sha256* dst);

/*!
    \ingroup SHA
    \brief Sets SHA256 size.

    \return none No returns

    \param sha256 SHA256 structure
    \param len Size to set

    _Example_
    \code
    wc_Sha256 sha;
    wc_Sha256SizeSet(&sha, 1000);
    \endcode

    \sa wc_Sha256Update
*/
void wc_Sha256SizeSet(wc_Sha256* sha256, word32 len);

/*!
    \ingroup SHA
    \brief Sets SHA256 flags.

    \return 0 on success
    \return negative on error

    \param sha256 SHA256 structure
    \param flags Flags to set

    _Example_
    \code
    wc_Sha256 sha;
    int ret = wc_Sha256SetFlags(&sha, WC_HASH_FLAG_WILLCOPY);
    \endcode

    \sa wc_InitSha256
*/
int wc_Sha256SetFlags(wc_Sha256* sha256, word32 flags);

/*!
    \ingroup SHA
    \brief Gets SHA256 flags.

    \return 0 on success
    \return negative on error

    \param sha256 SHA256 structure
    \param flags Pointer to store flags

    _Example_
    \code
    wc_Sha256 sha;
    word32 flags;
    int ret = wc_Sha256GetFlags(&sha, &flags);
    \endcode

    \sa wc_Sha256SetFlags
*/
int wc_Sha256GetFlags(wc_Sha256* sha256, word32* flags);

/*!
    \ingroup SHA
    \brief Initializes SHA224 with heap and device ID.

    \return 0 on success
    \return negative on error

    \param sha224 SHA224 structure
    \param heap Heap hint
    \param devId Device ID

    _Example_
    \code
    wc_Sha224 sha;
    int ret = wc_InitSha224_ex(&sha, NULL, INVALID_DEVID);
    \endcode

    \sa wc_InitSha224
*/
int wc_InitSha224_ex(wc_Sha224* sha224, void* heap, int devId);

/*!
    \ingroup SHA
    \brief Frees SHA224 resources.

    \return none No returns

    \param sha224 SHA224 structure

    _Example_
    \code
    wc_Sha224 sha;
    wc_InitSha224(&sha);
    wc_Sha224Free(&sha);
    \endcode

    \sa wc_InitSha224
*/
void wc_Sha224Free(wc_Sha224* sha224);

/*!
    \ingroup SHA
    \brief Grows SHA224 buffer with input data.

    \return 0 on success
    \return negative on error

    \param sha224 SHA224 structure
    \param in Input data
    \param inSz Input size

    _Example_
    \code
    wc_Sha224 sha;
    byte data[100];
    int ret = wc_Sha224_Grow(&sha, data, sizeof(data));
    \endcode

    \sa wc_Sha224Update
*/
int wc_Sha224_Grow(wc_Sha224* sha224, const byte* in, int inSz);

/*!
    \ingroup SHA
    \brief Gets SHA224 hash without finalizing.

    \return 0 on success
    \return negative on error

    \param sha224 SHA224 structure
    \param hash Output hash buffer

    _Example_
    \code
    wc_Sha224 sha;
    byte hash[WC_SHA224_DIGEST_SIZE];
    int ret = wc_Sha224GetHash(&sha, hash);
    \endcode

    \sa wc_Sha224Final
*/
int wc_Sha224GetHash(wc_Sha224* sha224, byte* hash);

/*!
    \ingroup SHA
    \brief Copies SHA224 context.

    \return 0 on success
    \return negative on error

    \param src Source SHA224 structure
    \param dst Destination SHA224 structure

    _Example_
    \code
    wc_Sha224 src, dst;
    int ret = wc_Sha224Copy(&src, &dst);
    \endcode

    \sa wc_InitSha224
*/
int wc_Sha224Copy(wc_Sha224* src, wc_Sha224* dst);

/*!
    \ingroup SHA
    \brief Sets SHA224 flags.

    \return 0 on success
    \return negative on error

    \param sha224 SHA224 structure
    \param flags Flags to set

    _Example_
    \code
    wc_Sha224 sha;
    int ret = wc_Sha224SetFlags(&sha, WC_HASH_FLAG_WILLCOPY);
    \endcode

    \sa wc_InitSha224
*/
int wc_Sha224SetFlags(wc_Sha224* sha224, word32 flags);

/*!
    \ingroup SHA
    \brief Gets SHA224 flags.

    \return 0 on success
    \return negative on error

    \param sha224 SHA224 structure
    \param flags Pointer to store flags

    _Example_
    \code
    wc_Sha224 sha;
    word32 flags;
    int ret = wc_Sha224GetFlags(&sha, &flags);
    \endcode

    \sa wc_Sha224SetFlags
*/
int wc_Sha224GetFlags(wc_Sha224* sha224, word32* flags);
