/*!
    \ingroup SHA

    \brief This function initializes SHA512. This is automatically called
    by wc_Sha512Hash.

    \return 0 Returned upon successfully initializing

    \param sha512 pointer to the sha512 structure to use for encryption

    _Example_
    \code
    Sha512 sha512[1];
    if ((ret = wc_InitSha512(sha512)) != 0) {
       WOLFSSL_MSG("wc_InitSha512 failed");
    }
    else {
       wc_Sha512Update(sha512, data, len);
       wc_Sha512Final(sha512, hash);
    }
    \endcode

    \sa wc_Sha512Hash
    \sa wc_Sha512Update
    \sa wc_Sha512Final
*/
int wc_InitSha512(wc_Sha512* sha);

/*!
    \ingroup SHA

    \brief Can be called to continually hash the provided byte array
    of length len.

    \return 0 Returned upon successfully adding the data to the digest.

    \param sha512 pointer to the sha512 structure to use for encryption
    \param data the data to be hashed
    \param len length of data to be hashed

    _Example_
    \code
    Sha512 sha512[1];
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha512(sha512)) != 0) {
       WOLFSSL_MSG("wc_InitSha512 failed");
    }
    else {
       wc_Sha512Update(sha512, data, len);
       wc_Sha512Final(sha512, hash);
    }
    \endcode

    \sa wc_Sha512Hash
    \sa wc_Sha512Final
    \sa wc_InitSha512
*/
int wc_Sha512Update(wc_Sha512* sha, const byte* data, word32 len);

/*!
    \ingroup SHA

    \brief Finalizes hashing of data. Result is placed into hash.

    \return 0 Returned upon successfully finalizing the hash.

    \param sha512 pointer to the sha512 structure to use for encryption
    \param hash Byte array to hold hash value.

    _Example_
    \code
    Sha512 sha512[1];
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha512(sha512)) != 0) {
        WOLFSSL_MSG("wc_InitSha512 failed");
    }
    else {
       wc_Sha512Update(sha512, data, len);
       wc_Sha512Final(sha512, hash);
    }
    \endcode

    \sa wc_Sha512Hash
    \sa wc_Sha512Final
    \sa wc_InitSha512
*/
int wc_Sha512Final(wc_Sha512* sha512, byte* hash);

/*!
    \ingroup SHA

    \brief This function initializes SHA384. This is automatically called
    by wc_Sha384Hash.

    \return 0 Returned upon successfully initializing

    \param sha384 pointer to the sha384 structure to use for encryption

    _Example_
    \code
    Sha384 sha384[1];
    if ((ret = wc_InitSha384(sha384)) != 0) {
       WOLFSSL_MSG("wc_InitSha384 failed");
    }
    else {
       wc_Sha384Update(sha384, data, len);
       wc_Sha384Final(sha384, hash);
    }
    \endcode

    \sa wc_Sha384Hash
    \sa wc_Sha384Update
    \sa wc_Sha384Final
*/
int wc_InitSha384(wc_Sha384* sha);

/*!
    \ingroup SHA

    \brief Can be called to continually hash the provided byte array
    of length len.

    \return 0 Returned upon successfully adding the data to the digest.

    \param sha384 pointer to the sha384 structure to use for encryption
    \param data the data to be hashed
    \param len length of data to be hashed

    _Example_
    \code
    Sha384 sha384[1];
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha384(sha384)) != 0) {
       WOLFSSL_MSG("wc_InitSha384 failed");
    }
    else {
       wc_Sha384Update(sha384, data, len);
       wc_Sha384Final(sha384, hash);
    }
    \endcode

    \sa wc_Sha384Hash
    \sa wc_Sha384Final
    \sa wc_InitSha384
*/
int wc_Sha384Update(wc_Sha384* sha, const byte* data, word32 len);

/*!
    \ingroup SHA

    \brief Finalizes hashing of data. Result is placed into hash.

    \return 0 Returned upon successfully finalizing.

    \param sha384 pointer to the sha384 structure to use for encryption
    \param hash Byte array to hold hash value.

    _Example_
    \code
    Sha384 sha384[1];
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha384(sha384)) != 0) {
       WOLFSSL_MSG("wc_InitSha384 failed");
    }
    else {
       wc_Sha384Update(sha384, data, len);
       wc_Sha384Final(sha384, hash);
    }
    \endcode

    \sa wc_Sha384Hash
    \sa wc_Sha384Final
    \sa wc_InitSha384
*/
int wc_Sha384Final(wc_Sha384* sha384, byte* hash);

/*!
    \ingroup SHA
    \brief Initializes SHA512 with heap and device ID.

    \return 0 on success
    \return negative on error

    \param sha SHA512 structure
    \param heap Heap hint
    \param devId Device ID

    _Example_
    \code
    wc_Sha512 sha;
    int ret = wc_InitSha512_ex(&sha, NULL, INVALID_DEVID);
    \endcode

    \sa wc_InitSha512
*/
int wc_InitSha512_ex(wc_Sha512* sha, void* heap, int devId);

/*!
    \ingroup SHA
    \brief Gets raw hash without finalizing.

    \return 0 on success
    \return negative on error

    \param sha512 SHA512 structure
    \param hash Output hash buffer

    _Example_
    \code
    wc_Sha512 sha;
    byte hash[WC_SHA512_DIGEST_SIZE];
    int ret = wc_Sha512FinalRaw(&sha, hash);
    \endcode

    \sa wc_Sha512Final
*/
int wc_Sha512FinalRaw(wc_Sha512* sha512, byte* hash);

/*!
    \ingroup SHA
    \brief Frees SHA512 resources.

    \return none No returns

    \param sha SHA512 structure

    _Example_
    \code
    wc_Sha512 sha;
    wc_InitSha512(&sha);
    wc_Sha512Free(&sha);
    \endcode

    \sa wc_InitSha512
*/
void wc_Sha512Free(wc_Sha512* sha);

/*!
    \ingroup SHA
    \brief Gets SHA512 hash without finalizing.

    \return 0 on success
    \return negative on error

    \param sha512 SHA512 structure
    \param hash Output hash buffer

    _Example_
    \code
    wc_Sha512 sha;
    byte hash[WC_SHA512_DIGEST_SIZE];
    int ret = wc_Sha512GetHash(&sha, hash);
    \endcode

    \sa wc_Sha512Final
*/
int wc_Sha512GetHash(wc_Sha512* sha512, byte* hash);

/*!
    \ingroup SHA
    \brief Copies SHA512 context.

    \return 0 on success
    \return negative on error

    \param src Source SHA512 structure
    \param dst Destination SHA512 structure

    _Example_
    \code
    wc_Sha512 src, dst;
    int ret = wc_Sha512Copy(&src, &dst);
    \endcode

    \sa wc_InitSha512
*/
int wc_Sha512Copy(wc_Sha512* src, wc_Sha512* dst);

/*!
    \ingroup SHA
    \brief Grows SHA512 buffer with input data.

    \return 0 on success
    \return negative on error

    \param sha512 SHA512 structure
    \param in Input data
    \param inSz Input size

    _Example_
    \code
    wc_Sha512 sha;
    byte data[100];
    int ret = wc_Sha512_Grow(&sha, data, sizeof(data));
    \endcode

    \sa wc_Sha512Update
*/
int wc_Sha512_Grow(wc_Sha512* sha512, const byte* in, int inSz);

/*!
    \ingroup SHA
    \brief Sets SHA512 flags.

    \return 0 on success
    \return negative on error

    \param sha512 SHA512 structure
    \param flags Flags to set

    _Example_
    \code
    wc_Sha512 sha;
    int ret = wc_Sha512SetFlags(&sha, WC_HASH_FLAG_WILLCOPY);
    \endcode

    \sa wc_InitSha512
*/
int wc_Sha512SetFlags(wc_Sha512* sha512, word32 flags);

/*!
    \ingroup SHA
    \brief Gets SHA512 flags.

    \return 0 on success
    \return negative on error

    \param sha512 SHA512 structure
    \param flags Pointer to store flags

    _Example_
    \code
    wc_Sha512 sha;
    word32 flags;
    int ret = wc_Sha512GetFlags(&sha, &flags);
    \endcode

    \sa wc_Sha512SetFlags
*/
int wc_Sha512GetFlags(wc_Sha512* sha512, word32* flags);

/*!
    \ingroup SHA
    \brief Transforms SHA512 block.

    \return 0 on success
    \return negative on error

    \param sha SHA512 structure
    \param data Block data

    _Example_
    \code
    wc_Sha512 sha;
    unsigned char block[WC_SHA512_BLOCK_SIZE];
    int ret = wc_Sha512Transform(&sha, block);
    \endcode

    \sa wc_Sha512Update
*/
int wc_Sha512Transform(wc_Sha512* sha, const unsigned char* data);

/*!
    \ingroup SHA
    \brief Initializes SHA512/224.

    \return 0 on success
    \return negative on error

    \param sha SHA512 structure

    _Example_
    \code
    wc_Sha512 sha;
    int ret = wc_InitSha512_224(&sha);
    \endcode

    \sa wc_Sha512_224Update
*/
int wc_InitSha512_224(wc_Sha512* sha);

/*!
    \ingroup SHA
    \brief Initializes SHA512/224 with heap and device ID.

    \return 0 on success
    \return negative on error

    \param sha SHA512 structure
    \param heap Heap hint
    \param devId Device ID

    _Example_
    \code
    wc_Sha512 sha;
    int ret = wc_InitSha512_224_ex(&sha, NULL, INVALID_DEVID);
    \endcode

    \sa wc_InitSha512_224
*/
int wc_InitSha512_224_ex(wc_Sha512* sha, void* heap, int devId);

/*!
    \ingroup SHA
    \brief Updates SHA512/224 hash with data.

    \return 0 on success
    \return negative on error

    \param sha SHA512 structure
    \param data Input data
    \param len Input size

    _Example_
    \code
    wc_Sha512 sha;
    byte data[100];
    int ret = wc_Sha512_224Update(&sha, data, sizeof(data));
    \endcode

    \sa wc_InitSha512_224
*/
int wc_Sha512_224Update(wc_Sha512* sha, const byte* data, word32 len);

/*!
    \ingroup SHA
    \brief Gets raw SHA512/224 hash without finalizing.

    \return 0 on success
    \return negative on error

    \param sha512 SHA512 structure
    \param hash Output hash buffer

    _Example_
    \code
    wc_Sha512 sha;
    byte hash[WC_SHA512_224_DIGEST_SIZE];
    int ret = wc_Sha512_224FinalRaw(&sha, hash);
    \endcode

    \sa wc_Sha512_224Final
*/
int wc_Sha512_224FinalRaw(wc_Sha512* sha512, byte* hash);

/*!
    \ingroup SHA
    \brief Finalizes SHA512/224 hash.

    \return 0 on success
    \return negative on error

    \param sha512 SHA512 structure
    \param hash Output hash buffer

    _Example_
    \code
    wc_Sha512 sha;
    byte hash[WC_SHA512_224_DIGEST_SIZE];
    int ret = wc_Sha512_224Final(&sha, hash);
    \endcode

    \sa wc_Sha512_224Update
*/
int wc_Sha512_224Final(wc_Sha512* sha512, byte* hash);

/*!
    \ingroup SHA
    \brief Frees SHA512/224 resources.

    \return none No returns

    \param sha SHA512 structure

    _Example_
    \code
    wc_Sha512 sha;
    wc_InitSha512_224(&sha);
    wc_Sha512_224Free(&sha);
    \endcode

    \sa wc_InitSha512_224
*/
void wc_Sha512_224Free(wc_Sha512* sha);

/*!
    \ingroup SHA
    \brief Gets SHA512/224 hash without finalizing.

    \return 0 on success
    \return negative on error

    \param sha512 SHA512 structure
    \param hash Output hash buffer

    _Example_
    \code
    wc_Sha512 sha;
    byte hash[WC_SHA512_224_DIGEST_SIZE];
    int ret = wc_Sha512_224GetHash(&sha, hash);
    \endcode

    \sa wc_Sha512_224Final
*/
int wc_Sha512_224GetHash(wc_Sha512* sha512, byte* hash);

/*!
    \ingroup SHA
    \brief Copies SHA512/224 context.

    \return 0 on success
    \return negative on error

    \param src Source SHA512 structure
    \param dst Destination SHA512 structure

    _Example_
    \code
    wc_Sha512 src, dst;
    int ret = wc_Sha512_224Copy(&src, &dst);
    \endcode

    \sa wc_InitSha512_224
*/
int wc_Sha512_224Copy(wc_Sha512* src, wc_Sha512* dst);

/*!
    \ingroup SHA
    \brief Sets SHA512/224 flags.

    \return 0 on success
    \return negative on error

    \param sha512 SHA512 structure
    \param flags Flags to set

    _Example_
    \code
    wc_Sha512 sha;
    int ret = wc_Sha512_224SetFlags(&sha, WC_HASH_FLAG_WILLCOPY);
    \endcode

    \sa wc_InitSha512_224
*/
int wc_Sha512_224SetFlags(wc_Sha512* sha512, word32 flags);

/*!
    \ingroup SHA
    \brief Gets SHA512/224 flags.

    \return 0 on success
    \return negative on error

    \param sha512 SHA512 structure
    \param flags Pointer to store flags

    _Example_
    \code
    wc_Sha512 sha;
    word32 flags;
    int ret = wc_Sha512_224GetFlags(&sha, &flags);
    \endcode

    \sa wc_Sha512_224SetFlags
*/
int wc_Sha512_224GetFlags(wc_Sha512* sha512, word32* flags);

/*!
    \ingroup SHA
    \brief Transforms SHA512/224 block.

    \return 0 on success
    \return negative on error

    \param sha SHA512 structure
    \param data Block data

    _Example_
    \code
    wc_Sha512 sha;
    unsigned char block[WC_SHA512_BLOCK_SIZE];
    int ret = wc_Sha512_224Transform(&sha, block);
    \endcode

    \sa wc_Sha512_224Update
*/
int wc_Sha512_224Transform(wc_Sha512* sha, const unsigned char* data);

/*!
    \ingroup SHA
    \brief Initializes SHA512/256.

    \return 0 on success
    \return negative on error

    \param sha SHA512 structure

    _Example_
    \code
    wc_Sha512 sha;
    int ret = wc_InitSha512_256(&sha);
    \endcode

    \sa wc_Sha512_256Update
*/
int wc_InitSha512_256(wc_Sha512* sha);

/*!
    \ingroup SHA
    \brief Initializes SHA512/256 with heap and device ID.

    \return 0 on success
    \return negative on error

    \param sha SHA512 structure
    \param heap Heap hint
    \param devId Device ID

    _Example_
    \code
    wc_Sha512 sha;
    int ret = wc_InitSha512_256_ex(&sha, NULL, INVALID_DEVID);
    \endcode

    \sa wc_InitSha512_256
*/
int wc_InitSha512_256_ex(wc_Sha512* sha, void* heap, int devId);

/*!
    \ingroup SHA
    \brief Updates SHA512/256 hash with data.

    \return 0 on success
    \return negative on error

    \param sha SHA512 structure
    \param data Input data
    \param len Input size

    _Example_
    \code
    wc_Sha512 sha;
    byte data[100];
    int ret = wc_Sha512_256Update(&sha, data, sizeof(data));
    \endcode

    \sa wc_InitSha512_256
*/
int wc_Sha512_256Update(wc_Sha512* sha, const byte* data, word32 len);

/*!
    \ingroup SHA
    \brief Gets raw SHA512/256 hash without finalizing.

    \return 0 on success
    \return negative on error

    \param sha512 SHA512 structure
    \param hash Output hash buffer

    _Example_
    \code
    wc_Sha512 sha;
    byte hash[WC_SHA512_256_DIGEST_SIZE];
    int ret = wc_Sha512_256FinalRaw(&sha, hash);
    \endcode

    \sa wc_Sha512_256Final
*/
int wc_Sha512_256FinalRaw(wc_Sha512* sha512, byte* hash);

/*!
    \ingroup SHA
    \brief Finalizes SHA512/256 hash.

    \return 0 on success
    \return negative on error

    \param sha512 SHA512 structure
    \param hash Output hash buffer

    _Example_
    \code
    wc_Sha512 sha;
    byte hash[WC_SHA512_256_DIGEST_SIZE];
    int ret = wc_Sha512_256Final(&sha, hash);
    \endcode

    \sa wc_Sha512_256Update
*/
int wc_Sha512_256Final(wc_Sha512* sha512, byte* hash);

/*!
    \ingroup SHA
    \brief Frees SHA512/256 resources.

    \return none No returns

    \param sha SHA512 structure

    _Example_
    \code
    wc_Sha512 sha;
    wc_InitSha512_256(&sha);
    wc_Sha512_256Free(&sha);
    \endcode

    \sa wc_InitSha512_256
*/
void wc_Sha512_256Free(wc_Sha512* sha);

/*!
    \ingroup SHA
    \brief Gets SHA512/256 hash without finalizing.

    \return 0 on success
    \return negative on error

    \param sha512 SHA512 structure
    \param hash Output hash buffer

    _Example_
    \code
    wc_Sha512 sha;
    byte hash[WC_SHA512_256_DIGEST_SIZE];
    int ret = wc_Sha512_256GetHash(&sha, hash);
    \endcode

    \sa wc_Sha512_256Final
*/
int wc_Sha512_256GetHash(wc_Sha512* sha512, byte* hash);

/*!
    \ingroup SHA
    \brief Copies SHA512/256 context.

    \return 0 on success
    \return negative on error

    \param src Source SHA512 structure
    \param dst Destination SHA512 structure

    _Example_
    \code
    wc_Sha512 src, dst;
    int ret = wc_Sha512_256Copy(&src, &dst);
    \endcode

    \sa wc_InitSha512_256
*/
int wc_Sha512_256Copy(wc_Sha512* src, wc_Sha512* dst);

/*!
    \ingroup SHA
    \brief Sets SHA512/256 flags.

    \return 0 on success
    \return negative on error

    \param sha512 SHA512 structure
    \param flags Flags to set

    _Example_
    \code
    wc_Sha512 sha;
    int ret = wc_Sha512_256SetFlags(&sha, WC_HASH_FLAG_WILLCOPY);
    \endcode

    \sa wc_InitSha512_256
*/
int wc_Sha512_256SetFlags(wc_Sha512* sha512, word32 flags);

/*!
    \ingroup SHA
    \brief Gets SHA512/256 flags.

    \return 0 on success
    \return negative on error

    \param sha512 SHA512 structure
    \param flags Pointer to store flags

    _Example_
    \code
    wc_Sha512 sha;
    word32 flags;
    int ret = wc_Sha512_256GetFlags(&sha, &flags);
    \endcode

    \sa wc_Sha512_256SetFlags
*/
int wc_Sha512_256GetFlags(wc_Sha512* sha512, word32* flags);

/*!
    \ingroup SHA
    \brief Transforms SHA512/256 block.

    \return 0 on success
    \return negative on error

    \param sha SHA512 structure
    \param data Block data

    _Example_
    \code
    wc_Sha512 sha;
    unsigned char block[WC_SHA512_BLOCK_SIZE];
    int ret = wc_Sha512_256Transform(&sha, block);
    \endcode

    \sa wc_Sha512_256Update
*/
int wc_Sha512_256Transform(wc_Sha512* sha, const unsigned char* data);

/*!
    \ingroup SHA
    \brief Initializes SHA384 with heap and device ID.

    \return 0 on success
    \return negative on error

    \param sha SHA384 structure
    \param heap Heap hint
    \param devId Device ID

    _Example_
    \code
    wc_Sha384 sha;
    int ret = wc_InitSha384_ex(&sha, NULL, INVALID_DEVID);
    \endcode

    \sa wc_InitSha384
*/
int wc_InitSha384_ex(wc_Sha384* sha, void* heap, int devId);

/*!
    \ingroup SHA
    \brief Gets raw SHA384 hash without finalizing.

    \return 0 on success
    \return negative on error

    \param sha384 SHA384 structure
    \param hash Output hash buffer

    _Example_
    \code
    wc_Sha384 sha;
    byte hash[WC_SHA384_DIGEST_SIZE];
    int ret = wc_Sha384FinalRaw(&sha, hash);
    \endcode

    \sa wc_Sha384Final
*/
int wc_Sha384FinalRaw(wc_Sha384* sha384, byte* hash);

/*!
    \ingroup SHA
    \brief Frees SHA384 resources.

    \return none No returns

    \param sha SHA384 structure

    _Example_
    \code
    wc_Sha384 sha;
    wc_InitSha384(&sha);
    wc_Sha384Free(&sha);
    \endcode

    \sa wc_InitSha384
*/
void wc_Sha384Free(wc_Sha384* sha);

/*!
    \ingroup SHA
    \brief Gets SHA384 hash without finalizing.

    \return 0 on success
    \return negative on error

    \param sha384 SHA384 structure
    \param hash Output hash buffer

    _Example_
    \code
    wc_Sha384 sha;
    byte hash[WC_SHA384_DIGEST_SIZE];
    int ret = wc_Sha384GetHash(&sha, hash);
    \endcode

    \sa wc_Sha384Final
*/
int wc_Sha384GetHash(wc_Sha384* sha384, byte* hash);

/*!
    \ingroup SHA
    \brief Copies SHA384 context.

    \return 0 on success
    \return negative on error

    \param src Source SHA384 structure
    \param dst Destination SHA384 structure

    _Example_
    \code
    wc_Sha384 src, dst;
    int ret = wc_Sha384Copy(&src, &dst);
    \endcode

    \sa wc_InitSha384
*/
int wc_Sha384Copy(wc_Sha384* src, wc_Sha384* dst);

/*!
    \ingroup SHA
    \brief Grows SHA384 buffer with input data.

    \return 0 on success
    \return negative on error

    \param sha384 SHA384 structure
    \param in Input data
    \param inSz Input size

    _Example_
    \code
    wc_Sha384 sha;
    byte data[100];
    int ret = wc_Sha384_Grow(&sha, data, sizeof(data));
    \endcode

    \sa wc_Sha384Update
*/
int wc_Sha384_Grow(wc_Sha384* sha384, const byte* in, int inSz);

/*!
    \ingroup SHA
    \brief Sets SHA384 flags.

    \return 0 on success
    \return negative on error

    \param sha384 SHA384 structure
    \param flags Flags to set

    _Example_
    \code
    wc_Sha384 sha;
    int ret = wc_Sha384SetFlags(&sha, WC_HASH_FLAG_WILLCOPY);
    \endcode

    \sa wc_InitSha384
*/
int wc_Sha384SetFlags(wc_Sha384* sha384, word32 flags);

/*!
    \ingroup SHA
    \brief Gets SHA384 flags.

    \return 0 on success
    \return negative on error

    \param sha384 SHA384 structure
    \param flags Pointer to store flags

    _Example_
    \code
    wc_Sha384 sha;
    word32 flags;
    int ret = wc_Sha384GetFlags(&sha, &flags);
    \endcode

    \sa wc_Sha384SetFlags
*/
int wc_Sha384GetFlags(wc_Sha384* sha384, word32* flags);

/*!
    \ingroup SHA
    \brief Transforms SHA384 block.

    \return 0 on success
    \return negative on error

    \param sha SHA384 structure
    \param data Block data

    _Example_
    \code
    wc_Sha384 sha;
    unsigned char block[WC_SHA384_BLOCK_SIZE];
    int ret = wc_Sha384Transform(&sha, block);
    \endcode

    \sa wc_Sha384Update
*/
int wc_Sha384Transform(wc_Sha384* sha, const unsigned char* data);
