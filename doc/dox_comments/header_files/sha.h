/*!
    \ingroup SHA

    \brief This function initializes SHA. This is automatically called
    by wc_ShaHash.

    \return 0 Returned upon successfully initializing

    \param sha pointer to the sha structure to use for encryption

    _Example_
    \code
    Sha sha[1];
    if ((ret = wc_InitSha(sha)) != 0) {
       WOLFSSL_MSG("wc_InitSha failed");
    }
    else {
       wc_ShaUpdate(sha, data, len);
       wc_ShaFinal(sha, hash);
    }
    \endcode

    \sa wc_ShaHash
    \sa wc_ShaUpdate
    \sa wc_ShaFinal
*/
int wc_InitSha(wc_Sha*);

/*!
    \ingroup SHA

    \brief Can be called to continually hash the provided byte array of
    length len.

    \return 0 Returned upon successfully adding the data to the digest.

    \param sha pointer to the sha structure to use for encryption
    \param data the data to be hashed
    \param len length of data to be hashed

    _Example_
    \code
    Sha sha[1];
    byte data[] = { // Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha(sha)) != 0) {
       WOLFSSL_MSG("wc_InitSha failed");
    }
    else {
       wc_ShaUpdate(sha, data, len);
       wc_ShaFinal(sha, hash);
    }
    \endcode

    \sa wc_ShaHash
    \sa wc_ShaFinal
    \sa wc_InitSha
*/
int wc_ShaUpdate(wc_Sha* sha, const byte* data, word32 len);

/*!
    \ingroup SHA

    \brief Finalizes hashing of data. Result is placed into hash.
    Resets state of sha struct.

    \return 0 Returned upon successfully finalizing.

    \param sha pointer to the sha structure to use for encryption
    \param hash Byte array to hold hash value.

    _Example_
    \code
    Sha sha[1];
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha(sha)) != 0) {
       WOLFSSL_MSG("wc_InitSha failed");
    }
    else {
       wc_ShaUpdate(sha, data, len);
       wc_ShaFinal(sha, hash);
    }
    \endcode

    \sa wc_ShaHash
    \sa wc_InitSha
    \sa wc_ShaGetHash
*/
int wc_ShaFinal(wc_Sha* sha, byte* hash);

/*!
    \ingroup SHA

    \brief Used to clean up memory used by an initialized Sha struct.

    \return No returns.

    \param sha Pointer to the Sha struct to free.

    _Example_
    \code
    Sha sha;
    wc_InitSha(&sha);
    // Use sha
    wc_ShaFree(&sha);
    \endcode

    \sa wc_InitSha
    \sa wc_ShaUpdate
    \sa wc_ShaFinal
*/
void wc_ShaFree(wc_Sha*);

/*!
    \ingroup SHA

    \brief Gets hash data. Result is placed into hash.  Does not reset state
    of sha struct.

    \return 0 Returned upon successfully finalizing.

    \param sha pointer to the sha structure to use for encryption
    \param hash Byte array to hold hash value.

    _Example_
    \code
    Sha sha[1];
    if ((ret = wc_InitSha(sha)) != 0) {
    WOLFSSL_MSG("wc_InitSha failed");
    }
    else {
        wc_ShaUpdate(sha, data, len);
        wc_ShaGetHash(sha, hash);
    }
    \endcode

    \sa wc_ShaHash
    \sa wc_ShaFinal
    \sa wc_InitSha
*/
int wc_ShaGetHash(wc_Sha* sha, byte* hash);

/*!
    \ingroup openSSL
    \brief Initializes SHA context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param sha SHA context to initialize

    _Example_
    \code
    WOLFSSL_SHA_CTX sha;
    int ret = wolfSSL_SHA_Init(&sha);
    \endcode

    \sa wolfSSL_SHA_Update
*/
int wolfSSL_SHA_Init(WOLFSSL_SHA_CTX* sha);

/*!
    \ingroup openSSL
    \brief Updates SHA hash with data.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param sha SHA context
    \param input Input data
    \param sz Input size

    _Example_
    \code
    WOLFSSL_SHA_CTX sha;
    unsigned char data[100];
    wolfSSL_SHA_Update(&sha, data, sizeof(data));
    \endcode

    \sa wolfSSL_SHA_Init
*/
int wolfSSL_SHA_Update(WOLFSSL_SHA_CTX* sha, const void* input,
    unsigned long sz);

/*!
    \ingroup openSSL
    \brief Finalizes SHA hash.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param input Output hash buffer
    \param sha SHA context

    _Example_
    \code
    WOLFSSL_SHA_CTX sha;
    unsigned char hash[WC_SHA_DIGEST_SIZE];
    wolfSSL_SHA_Final(hash, &sha);
    \endcode

    \sa wolfSSL_SHA_Update
*/
int wolfSSL_SHA_Final(byte* input, WOLFSSL_SHA_CTX* sha);

/*!
    \ingroup openSSL
    \brief Transforms SHA block.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param sha SHA context
    \param data Block data

    _Example_
    \code
    WOLFSSL_SHA_CTX sha;
    unsigned char block[WC_SHA_BLOCK_SIZE];
    wolfSSL_SHA_Transform(&sha, block);
    \endcode

    \sa wolfSSL_SHA_Update
*/
int wolfSSL_SHA_Transform(WOLFSSL_SHA_CTX* sha,
    const unsigned char* data);

/*!
    \ingroup openSSL
    \brief Initializes SHA1 context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param sha SHA1 context to initialize

    _Example_
    \code
    WOLFSSL_SHA_CTX sha;
    int ret = wolfSSL_SHA1_Init(&sha);
    \endcode

    \sa wolfSSL_SHA1_Update
*/
int wolfSSL_SHA1_Init(WOLFSSL_SHA_CTX* sha);

/*!
    \ingroup openSSL
    \brief Updates SHA1 hash with data.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param sha SHA1 context
    \param input Input data
    \param sz Input size

    _Example_
    \code
    WOLFSSL_SHA_CTX sha;
    unsigned char data[100];
    wolfSSL_SHA1_Update(&sha, data, sizeof(data));
    \endcode

    \sa wolfSSL_SHA1_Init
*/
int wolfSSL_SHA1_Update(WOLFSSL_SHA_CTX* sha, const void* input,
    unsigned long sz);

/*!
    \ingroup openSSL
    \brief Finalizes SHA1 hash.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param output Output hash buffer
    \param sha SHA1 context

    _Example_
    \code
    WOLFSSL_SHA_CTX sha;
    unsigned char hash[WC_SHA_DIGEST_SIZE];
    wolfSSL_SHA1_Final(hash, &sha);
    \endcode

    \sa wolfSSL_SHA1_Update
*/
int wolfSSL_SHA1_Final(byte* output, WOLFSSL_SHA_CTX* sha);

/*!
    \ingroup openSSL
    \brief Transforms SHA1 block.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param sha SHA1 context
    \param data Block data

    _Example_
    \code
    WOLFSSL_SHA_CTX sha;
    unsigned char block[WC_SHA_BLOCK_SIZE];
    wolfSSL_SHA1_Transform(&sha, block);
    \endcode

    \sa wolfSSL_SHA1_Update
*/
int wolfSSL_SHA1_Transform(WOLFSSL_SHA_CTX* sha,
    const unsigned char *data);

/*!
    \ingroup openSSL
    \brief Initializes SHA224 context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param sha SHA224 context to initialize

    _Example_
    \code
    WOLFSSL_SHA224_CTX sha;
    int ret = wolfSSL_SHA224_Init(&sha);
    \endcode

    \sa wolfSSL_SHA224_Update
*/
int wolfSSL_SHA224_Init(WOLFSSL_SHA224_CTX* sha);

/*!
    \ingroup openSSL
    \brief Updates SHA224 hash with data.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param sha SHA224 context
    \param input Input data
    \param sz Input size

    _Example_
    \code
    WOLFSSL_SHA224_CTX sha;
    unsigned char data[100];
    wolfSSL_SHA224_Update(&sha, data, sizeof(data));
    \endcode

    \sa wolfSSL_SHA224_Init
*/
int wolfSSL_SHA224_Update(WOLFSSL_SHA224_CTX* sha,
    const void* input, unsigned long sz);

/*!
    \ingroup openSSL
    \brief Finalizes SHA224 hash.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param output Output hash buffer
    \param sha SHA224 context

    _Example_
    \code
    WOLFSSL_SHA224_CTX sha;
    unsigned char hash[WC_SHA224_DIGEST_SIZE];
    wolfSSL_SHA224_Final(hash, &sha);
    \endcode

    \sa wolfSSL_SHA224_Update
*/
int wolfSSL_SHA224_Final(byte* output, WOLFSSL_SHA224_CTX* sha);

/*!
    \ingroup openSSL
    \brief Initializes SHA256 context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param sha256 SHA256 context to initialize

    _Example_
    \code
    WOLFSSL_SHA256_CTX sha;
    int ret = wolfSSL_SHA256_Init(&sha);
    \endcode

    \sa wolfSSL_SHA256_Update
*/
int wolfSSL_SHA256_Init(WOLFSSL_SHA256_CTX* sha256);

/*!
    \ingroup openSSL
    \brief Updates SHA256 hash with data.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param sha SHA256 context
    \param input Input data
    \param sz Input size

    _Example_
    \code
    WOLFSSL_SHA256_CTX sha;
    unsigned char data[100];
    wolfSSL_SHA256_Update(&sha, data, sizeof(data));
    \endcode

    \sa wolfSSL_SHA256_Init
*/
int wolfSSL_SHA256_Update(WOLFSSL_SHA256_CTX* sha,
    const void* input, unsigned long sz);

/*!
    \ingroup openSSL
    \brief Finalizes SHA256 hash.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param output Output hash buffer
    \param sha SHA256 context

    _Example_
    \code
    WOLFSSL_SHA256_CTX sha;
    unsigned char hash[WC_SHA256_DIGEST_SIZE];
    wolfSSL_SHA256_Final(hash, &sha);
    \endcode

    \sa wolfSSL_SHA256_Update
*/
int wolfSSL_SHA256_Final(byte* output, WOLFSSL_SHA256_CTX* sha);

/*!
    \ingroup openSSL
    \brief Transforms SHA256 block.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param sha256 SHA256 context
    \param data Block data

    _Example_
    \code
    WOLFSSL_SHA256_CTX sha;
    unsigned char block[WC_SHA256_BLOCK_SIZE];
    wolfSSL_SHA256_Transform(&sha, block);
    \endcode

    \sa wolfSSL_SHA256_Update
*/
int wolfSSL_SHA256_Transform(WOLFSSL_SHA256_CTX* sha256,
    const unsigned char *data);

/*!
    \ingroup openSSL
    \brief Initializes SHA384 context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param sha SHA384 context to initialize

    _Example_
    \code
    WOLFSSL_SHA384_CTX sha;
    int ret = wolfSSL_SHA384_Init(&sha);
    \endcode

    \sa wolfSSL_SHA384_Update
*/
int wolfSSL_SHA384_Init(WOLFSSL_SHA384_CTX* sha);

/*!
    \ingroup openSSL
    \brief Updates SHA384 hash with data.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param sha SHA384 context
    \param input Input data
    \param sz Input size

    _Example_
    \code
    WOLFSSL_SHA384_CTX sha;
    unsigned char data[100];
    wolfSSL_SHA384_Update(&sha, data, sizeof(data));
    \endcode

    \sa wolfSSL_SHA384_Init
*/
int wolfSSL_SHA384_Update(WOLFSSL_SHA384_CTX* sha,
    const void* input, unsigned long sz);

/*!
    \ingroup openSSL
    \brief Finalizes SHA384 hash.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param output Output hash buffer
    \param sha SHA384 context

    _Example_
    \code
    WOLFSSL_SHA384_CTX sha;
    unsigned char hash[WC_SHA384_DIGEST_SIZE];
    wolfSSL_SHA384_Final(hash, &sha);
    \endcode

    \sa wolfSSL_SHA384_Update
*/
int wolfSSL_SHA384_Final(byte* output, WOLFSSL_SHA384_CTX* sha);

/*!
    \ingroup openSSL
    \brief Initializes SHA512 context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param sha SHA512 context to initialize

    _Example_
    \code
    WOLFSSL_SHA512_CTX sha;
    int ret = wolfSSL_SHA512_Init(&sha);
    \endcode

    \sa wolfSSL_SHA512_Update
*/
int wolfSSL_SHA512_Init(WOLFSSL_SHA512_CTX* sha);

/*!
    \ingroup openSSL
    \brief Updates SHA512 hash with data.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param sha SHA512 context
    \param input Input data
    \param sz Input size

    _Example_
    \code
    WOLFSSL_SHA512_CTX sha;
    unsigned char data[100];
    wolfSSL_SHA512_Update(&sha, data, sizeof(data));
    \endcode

    \sa wolfSSL_SHA512_Init
*/
int wolfSSL_SHA512_Update(WOLFSSL_SHA512_CTX* sha,
    const void* input, unsigned long sz);

/*!
    \ingroup openSSL
    \brief Finalizes SHA512 hash.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param output Output hash buffer
    \param sha SHA512 context

    _Example_
    \code
    WOLFSSL_SHA512_CTX sha;
    unsigned char hash[WC_SHA512_DIGEST_SIZE];
    wolfSSL_SHA512_Final(hash, &sha);
    \endcode

    \sa wolfSSL_SHA512_Update
*/
int wolfSSL_SHA512_Final(byte* output, WOLFSSL_SHA512_CTX* sha);

/*!
    \ingroup openSSL
    \brief Transforms SHA512 block.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param sha512 SHA512 context
    \param data Block data

    _Example_
    \code
    WOLFSSL_SHA512_CTX sha;
    unsigned char block[WC_SHA512_BLOCK_SIZE];
    wolfSSL_SHA512_Transform(&sha, block);
    \endcode

    \sa wolfSSL_SHA512_Update
*/
int wolfSSL_SHA512_Transform(WOLFSSL_SHA512_CTX* sha512,
    const unsigned char* data);

/*!
    \ingroup openSSL
    \brief Initializes SHA512/224 context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param sha SHA512/224 context to initialize

    _Example_
    \code
    WOLFSSL_SHA512_CTX sha;
    int ret = wolfSSL_SHA512_224_Init(&sha);
    \endcode

    \sa wolfSSL_SHA512_224_Update
*/
int wolfSSL_SHA512_224_Init(WOLFSSL_SHA512_CTX* sha);

/*!
    \ingroup openSSL
    \brief Updates SHA512/224 hash with data.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param sha SHA512/224 context
    \param input Input data
    \param sz Input size

    _Example_
    \code
    WOLFSSL_SHA512_224_CTX sha;
    unsigned char data[100];
    wolfSSL_SHA512_224_Update(&sha, data, sizeof(data));
    \endcode

    \sa wolfSSL_SHA512_224_Init
*/
int wolfSSL_SHA512_224_Update(WOLFSSL_SHA512_224_CTX* sha,
    const void* input, unsigned long sz);

/*!
    \ingroup openSSL
    \brief Finalizes SHA512/224 hash.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param output Output hash buffer
    \param sha SHA512/224 context

    _Example_
    \code
    WOLFSSL_SHA512_224_CTX sha;
    unsigned char hash[WC_SHA512_224_DIGEST_SIZE];
    wolfSSL_SHA512_224_Final(hash, &sha);
    \endcode

    \sa wolfSSL_SHA512_224_Update
*/
int wolfSSL_SHA512_224_Final(byte* output,
    WOLFSSL_SHA512_224_CTX* sha);

/*!
    \ingroup openSSL
    \brief Transforms SHA512/224 block.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param sha512 SHA512/224 context
    \param data Block data

    _Example_
    \code
    WOLFSSL_SHA512_CTX sha;
    unsigned char block[WC_SHA512_BLOCK_SIZE];
    wolfSSL_SHA512_224_Transform(&sha, block);
    \endcode

    \sa wolfSSL_SHA512_224_Update
*/
int wolfSSL_SHA512_224_Transform(WOLFSSL_SHA512_CTX* sha512,
    const unsigned char* data);

/*!
    \ingroup openSSL
    \brief Initializes SHA512/256 context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param sha SHA512/256 context to initialize

    _Example_
    \code
    WOLFSSL_SHA512_CTX sha;
    int ret = wolfSSL_SHA512_256_Init(&sha);
    \endcode

    \sa wolfSSL_SHA512_256_Update
*/
int wolfSSL_SHA512_256_Init(WOLFSSL_SHA512_CTX* sha);

/*!
    \ingroup openSSL
    \brief Updates SHA512/256 hash with data.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param sha SHA512/256 context
    \param input Input data
    \param sz Input size

    _Example_
    \code
    WOLFSSL_SHA512_256_CTX sha;
    unsigned char data[100];
    wolfSSL_SHA512_256_Update(&sha, data, sizeof(data));
    \endcode

    \sa wolfSSL_SHA512_256_Init
*/
int wolfSSL_SHA512_256_Update(WOLFSSL_SHA512_256_CTX* sha,
    const void* input, unsigned long sz);

/*!
    \ingroup openSSL
    \brief Finalizes SHA512/256 hash.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param output Output hash buffer
    \param sha SHA512/256 context

    _Example_
    \code
    WOLFSSL_SHA512_256_CTX sha;
    unsigned char hash[WC_SHA512_256_DIGEST_SIZE];
    wolfSSL_SHA512_256_Final(hash, &sha);
    \endcode

    \sa wolfSSL_SHA512_256_Update
*/
int wolfSSL_SHA512_256_Final(byte* output,
    WOLFSSL_SHA512_256_CTX* sha);

/*!
    \ingroup openSSL
    \brief Transforms SHA512/256 block.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param sha512 SHA512/256 context
    \param data Block data

    _Example_
    \code
    WOLFSSL_SHA512_CTX sha;
    unsigned char block[WC_SHA512_BLOCK_SIZE];
    wolfSSL_SHA512_256_Transform(&sha, block);
    \endcode

    \sa wolfSSL_SHA512_256_Update
*/
int wolfSSL_SHA512_256_Transform(WOLFSSL_SHA512_CTX* sha512,
    const unsigned char* data);

/*!
    \ingroup SHA
    \brief Initializes SHA with heap and device ID.

    \return 0 on success
    \return negative on error

    \param sha SHA structure
    \param heap Heap hint
    \param devId Device ID

    _Example_
    \code
    wc_Sha sha;
    int ret = wc_InitSha_ex(&sha, NULL, INVALID_DEVID);
    \endcode

    \sa wc_InitSha
*/
int wc_InitSha_ex(wc_Sha* sha, void* heap, int devId);

/*!
    \ingroup SHA
    \brief Gets raw hash without finalizing.

    \return 0 on success
    \return negative on error

    \param sha SHA structure
    \param hash Output hash buffer

    _Example_
    \code
    wc_Sha sha;
    byte hash[WC_SHA_DIGEST_SIZE];
    int ret = wc_ShaFinalRaw(&sha, hash);
    \endcode

    \sa wc_ShaFinal
*/
int wc_ShaFinalRaw(wc_Sha* sha, byte* hash);

/*!
    \ingroup SHA
    \brief Copies SHA context.

    \return 0 on success
    \return negative on error

    \param src Source SHA structure
    \param dst Destination SHA structure

    _Example_
    \code
    wc_Sha src, dst;
    int ret = wc_ShaCopy(&src, &dst);
    \endcode

    \sa wc_InitSha
*/
int wc_ShaCopy(wc_Sha* src, wc_Sha* dst);

/*!
    \ingroup SHA
    \brief Transforms SHA block.

    \return 0 on success
    \return negative on error

    \param sha SHA structure
    \param data Block data

    _Example_
    \code
    wc_Sha sha;
    unsigned char block[WC_SHA_BLOCK_SIZE];
    int ret = wc_ShaTransform(&sha, block);
    \endcode

    \sa wc_ShaUpdate
*/
int wc_ShaTransform(wc_Sha* sha, const unsigned char* data);

/*!
    \ingroup SHA
    \brief Sets SHA size.

    \return none No returns

    \param sha SHA structure
    \param len Size to set

    _Example_
    \code
    wc_Sha sha;
    wc_ShaSizeSet(&sha, 1000);
    \endcode

    \sa wc_ShaUpdate
*/
void wc_ShaSizeSet(wc_Sha* sha, word32 len);

/*!
    \ingroup SHA
    \brief Sets SHA flags.

    \return 0 on success
    \return negative on error

    \param sha SHA structure
    \param flags Flags to set

    _Example_
    \code
    wc_Sha sha;
    int ret = wc_ShaSetFlags(&sha, WC_HASH_FLAG_WILLCOPY);
    \endcode

    \sa wc_InitSha
*/
int wc_ShaSetFlags(wc_Sha* sha, word32 flags);
