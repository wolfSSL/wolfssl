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
int wc_InitSha(wc_Sha* sha);

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
void wc_ShaFree(wc_Sha* sha);

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
