/*!
    \ingroup MD5

    \brief This function initializes md5. This is automatically
    called by wc_Md5Hash.

    \return 0 Returned upon successfully initializing.
    \return BAD_FUNC_ARG Returned if the Md5 structure is passed
    as a NULL value.

    \param md5 pointer to the md5 structure to use for encryption

    _Example_
    \code
    Md5 md5;
    byte* hash;
    if ((ret = wc_InitMd5(&md5)) != 0) {
       WOLFSSL_MSG("wc_Initmd5 failed");
    }
    else {
       ret = wc_Md5Update(&md5, data, len);
       if (ret != 0) {
    	 // Md5 Update Failure Case.
       }
       ret = wc_Md5Final(&md5, hash);
      if (ret != 0) {
    	// Md5 Final Failure Case.
      }
    }
    \endcode

    \sa wc_Md5Hash
    \sa wc_Md5Update
    \sa wc_Md5Final
*/
int wc_InitMd5(wc_Md5*);

/*!
    \ingroup MD5

    \brief Can be called to continually hash the provided byte array of
    length len.

    \return 0 Returned upon successfully adding the data to the digest.
    \return BAD_FUNC_ARG Returned if the Md5 structure is NULL or if
    data is NULL and len is greater than zero. The function should
    not return an error if the data parameter is NULL and len is zero.

    \param md5 pointer to the md5 structure to use for encryption
    \param data the data to be hashed
    \param len length of data to be hashed

    _Example_
    \code
    Md5 md5;
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitMd5(&md5)) != 0) {
       WOLFSSL_MSG("wc_Initmd5 failed");
    }
    else {
       ret = wc_Md5Update(&md5, data, len);
       if (ret != 0) {
    	 // Md5 Update Error Case.
       }
       ret = wc_Md5Final(&md5, hash);
       if (ret != 0) {
    	// Md5 Final Error Case.
       }
    }
    \endcode

    \sa wc_Md5Hash
    \sa wc_Md5Final
    \sa wc_InitMd5
*/
int wc_Md5Update(wc_Md5* md5, const byte* data, word32 len);

/*!
    \ingroup MD5

    \brief Finalizes hashing of data. Result is placed into hash. Md5
    Struct is reset. Note: This function will also return the result
    of calling IntelQaSymMd5() in the case that HAVE_INTEL_QA is defined.

    \return 0 Returned upon successfully finalizing.
    \return BAD_FUNC_ARG Returned if the Md5 structure or hash pointer
    is passed in NULL.

    \param md5 pointer to the md5 structure to use for encryption
    \param hash Byte array to hold hash value.

    _Example_
    \code
    md5 md5[1];
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitMd5(md5)) != 0) {
       WOLFSSL_MSG("wc_Initmd5 failed");
    }
    else {
       ret = wc_Md5Update(md5, data, len);
       if (ret != 0) {
    	// Md5 Update Failure Case.
       }
      ret = wc_Md5Final(md5, hash);
       if (ret != 0) {
	    // Md5 Final Failure Case.
       }
    }
    \endcode

    \sa wc_Md5Hash
    \sa wc_InitMd5
    \sa wc_Md5GetHash
*/
int wc_Md5Final(wc_Md5* md5, byte* hash);

/*!
    \ingroup MD5

    \brief Resets the Md5 structure.  Note: this is only supported if
    you have WOLFSSL_TI_HASH defined.

    \return none No returns.

    \param md5 Pointer to the Md5 structure to be reset.

    _Example_
    \code
    Md5 md5;
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitMd5(&md5)) != 0) {
        WOLFSSL_MSG("wc_InitMd5 failed");
    }
    else {
        wc_Md5Update(&md5, data, len);
        wc_Md5Final(&md5, hash);
        wc_Md5Free(&md5);
    }
    \endcode

    \sa wc_InitMd5
    \sa wc_Md5Update
    \sa wc_Md5Final
*/
void wc_Md5Free(wc_Md5*);

/*!
    \ingroup MD5

    \brief Gets hash data. Result is placed into hash.  Md5 struct
    is not reset.

    \return none No returns

    \param md5 pointer to the md5 structure to use for encryption.
    \param hash Byte array to hold hash value.

    _Example_
    \code
    md5 md5[1];
    if ((ret = wc_InitMd5(md5)) != 0) {
       WOLFSSL_MSG("wc_Initmd5 failed");
    }
    else {
       wc_Md5Update(md5, data, len);
       wc_Md5GetHash(md5, hash);
    }
    \endcode

    \sa wc_Md5Hash
    \sa wc_Md5Final
    \sa wc_InitMd5
*/
int  wc_Md5GetHash(wc_Md5* md5, byte* hash);

/*!
    \ingroup MD5
    \brief This function initializes an MD5 context for OpenSSL
    compatibility. This is a wrapper around wc_InitMd5.

    \return WOLFSSL_SUCCESS On successfully initializing
    \return WOLFSSL_FAILURE On failure

    \param md5 pointer to the WOLFSSL_MD5_CTX structure to initialize

    _Example_
    \code
    WOLFSSL_MD5_CTX md5;
    
    if (wolfSSL_MD5_Init(&md5) != WOLFSSL_SUCCESS) {
        // error initializing MD5
    }
    \endcode

    \sa wc_InitMd5
    \sa wolfSSL_MD5_Update
    \sa wolfSSL_MD5_Final
*/
int wolfSSL_MD5_Init(WOLFSSL_MD5_CTX* md5);

/*!
    \ingroup MD5
    \brief This function updates the MD5 hash with input data for
    OpenSSL compatibility. This is a wrapper around wc_Md5Update.

    \return WOLFSSL_SUCCESS On successfully updating the hash
    \return WOLFSSL_FAILURE On failure

    \param md5 pointer to the WOLFSSL_MD5_CTX structure
    \param input pointer to the data to hash
    \param sz length of the input data

    _Example_
    \code
    WOLFSSL_MD5_CTX md5;
    unsigned char data[] = "data to hash";
    
    wolfSSL_MD5_Init(&md5);
    if (wolfSSL_MD5_Update(&md5, data, sizeof(data)-1) !=
        WOLFSSL_SUCCESS) {
        // error updating MD5
    }
    \endcode

    \sa wc_Md5Update
    \sa wolfSSL_MD5_Init
    \sa wolfSSL_MD5_Final
*/
int wolfSSL_MD5_Update(WOLFSSL_MD5_CTX* md5, const void* input,
                      unsigned long sz);

/*!
    \ingroup MD5
    \brief This function finalizes the MD5 hash and outputs the result
    for OpenSSL compatibility. This is a wrapper around wc_Md5Final.

    \return WOLFSSL_SUCCESS On successfully finalizing the hash
    \return WOLFSSL_FAILURE On failure

    \param output pointer to buffer to store the hash (16 bytes)
    \param md5 pointer to the WOLFSSL_MD5_CTX structure

    _Example_
    \code
    WOLFSSL_MD5_CTX md5;
    unsigned char hash[WC_MD5_DIGEST_SIZE];
    unsigned char data[] = "data to hash";
    
    wolfSSL_MD5_Init(&md5);
    wolfSSL_MD5_Update(&md5, data, sizeof(data)-1);
    if (wolfSSL_MD5_Final(hash, &md5) != WOLFSSL_SUCCESS) {
        // error finalizing MD5
    }
    \endcode

    \sa wc_Md5Final
    \sa wolfSSL_MD5_Init
    \sa wolfSSL_MD5_Update
*/
int wolfSSL_MD5_Final(unsigned char* output, WOLFSSL_MD5_CTX* md5);

/*!
    \ingroup MD5
    \brief This function performs the MD5 transform operation on a
    single 64-byte block for OpenSSL compatibility. This is a
    lower-level function used internally.

    \return WOLFSSL_SUCCESS On successfully transforming the block
    \return WOLFSSL_FAILURE On failure

    \param md5 pointer to the WOLFSSL_MD5_CTX structure
    \param data pointer to 64-byte block to transform

    _Example_
    \code
    WOLFSSL_MD5_CTX md5;
    unsigned char block[WC_MD5_BLOCK_SIZE];
    
    wolfSSL_MD5_Init(&md5);
    // fill block with data
    if (wolfSSL_MD5_Transform(&md5, block) != WOLFSSL_SUCCESS) {
        // error transforming block
    }
    \endcode

    \sa wc_Md5Transform
    \sa wolfSSL_MD5_Update
*/
int wolfSSL_MD5_Transform(WOLFSSL_MD5_CTX* md5,
                         const unsigned char* data);

/*!
    \ingroup MD5
    \brief This function initializes an MD5 context with extended
    parameters, allowing specification of custom heap and device ID
    for hardware acceleration.

    \return 0 On successfully initializing
    \return BAD_FUNC_ARG If md5 is NULL

    \param md5 pointer to the wc_Md5 structure to initialize
    \param heap pointer to heap hint for memory allocation (can be
    NULL)
    \param devId device ID for hardware acceleration (use
    INVALID_DEVID for software only)

    _Example_
    \code
    wc_Md5 md5;
    void* heap = NULL;
    int devId = INVALID_DEVID;
    
    int ret = wc_InitMd5_ex(&md5, heap, devId);
    if (ret != 0) {
        // error initializing MD5
    }
    \endcode

    \sa wc_InitMd5
    \sa wc_Md5Update
    \sa wc_Md5Final
*/
int wc_InitMd5_ex(wc_Md5* md5, void* heap, int devId);

/*!
    \ingroup MD5
    \brief This function performs the MD5 transform operation on a
    single 64-byte block. This is a lower-level function used
    internally by wc_Md5Update.

    \return 0 On successfully transforming the block
    \return BAD_FUNC_ARG If md5 or data is NULL

    \param md5 pointer to the wc_Md5 structure
    \param data pointer to 64-byte block to transform

    _Example_
    \code
    wc_Md5 md5;
    byte block[WC_MD5_BLOCK_SIZE];
    
    wc_InitMd5(&md5);
    // fill block with data
    int ret = wc_Md5Transform(&md5, block);
    if (ret != 0) {
        // error transforming block
    }
    \endcode

    \sa wc_Md5Update
    \sa wc_InitMd5
*/
int wc_Md5Transform(wc_Md5* md5, const byte* data);

/*!
    \ingroup MD5
    \brief This function copies the state from one MD5 context to
    another. This is useful for saving intermediate hash states.

    \return 0 On successfully copying the context
    \return BAD_FUNC_ARG If src or dst is NULL

    \param src pointer to the source wc_Md5 structure
    \param dst pointer to the destination wc_Md5 structure

    _Example_
    \code
    wc_Md5 md5_src, md5_dst;
    byte data[] = "partial data";
    
    wc_InitMd5(&md5_src);
    wc_Md5Update(&md5_src, data, sizeof(data)-1);
    
    int ret = wc_Md5Copy(&md5_src, &md5_dst);
    if (ret != 0) {
        // error copying MD5 context
    }
    // md5_dst now has same state as md5_src
    \endcode

    \sa wc_InitMd5
    \sa wc_Md5Update
*/
int wc_Md5Copy(wc_Md5* src, wc_Md5* dst);

/*!
    \ingroup MD5
    \brief This function sets the message length in the MD5 context.
    This is used internally for handling message lengths.

    \return none No return value

    \param md5 pointer to the wc_Md5 structure
    \param len length value to set

    _Example_
    \code
    wc_Md5 md5;
    word32 len = 1024;
    
    wc_InitMd5(&md5);
    wc_Md5SizeSet(&md5, len);
    \endcode

    \sa wc_InitMd5
    \sa wc_Md5Update
*/
void wc_Md5SizeSet(wc_Md5* md5, word32 len);

/*!
    \ingroup MD5
    \brief This function sets flags on the MD5 context. This can be
    used to control MD5 behavior such as enabling specific features.

    \return 0 On successfully setting flags
    \return BAD_FUNC_ARG If md5 is NULL

    \param md5 pointer to the wc_Md5 structure
    \param flags flags to set on the MD5 context

    _Example_
    \code
    wc_Md5 md5;
    word32 flags = 0x01;
    
    wc_InitMd5(&md5);
    int ret = wc_Md5SetFlags(&md5, flags);
    if (ret != 0) {
        // error setting flags
    }
    \endcode

    \sa wc_Md5GetFlags
    \sa wc_InitMd5
*/
int wc_Md5SetFlags(wc_Md5* md5, word32 flags);

/*!
    \ingroup MD5
    \brief This function retrieves the flags from the MD5 context.

    \return 0 On successfully retrieving flags
    \return BAD_FUNC_ARG If md5 or flags is NULL

    \param md5 pointer to the wc_Md5 structure
    \param flags pointer to store the retrieved flags

    _Example_
    \code
    wc_Md5 md5;
    word32 flags;
    
    wc_InitMd5(&md5);
    int ret = wc_Md5GetFlags(&md5, &flags);
    if (ret != 0) {
        // error getting flags
    }
    \endcode

    \sa wc_Md5SetFlags
    \sa wc_InitMd5
*/
int wc_Md5GetFlags(wc_Md5* md5, word32* flags);
