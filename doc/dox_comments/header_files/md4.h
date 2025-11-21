/*!
    \ingroup MD4

    \brief This function initializes md4. This is automatically
    called by wc_Md4Hash.

    \return 0 Returned upon successfully initializing

    \param md4 pointer to the md4 structure to use for encryption

    _Example_
    \code
    md4 md4[1];
    if ((ret = wc_InitMd4(md4)) != 0) {
       WOLFSSL_MSG("wc_Initmd4 failed");
    }
    else {
       wc_Md4Update(md4, data, len);
       wc_Md4Final(md4, hash);
    }
    \endcode

    \sa wc_Md4Hash
    \sa wc_Md4Update
    \sa wc_Md4Final
*/
void wc_InitMd4(Md4*);

/*!
    \ingroup MD4

    \brief Can be called to continually hash the provided byte array
    of length len.

    \return 0 Returned upon successfully adding the data to the digest.

    \param md4 pointer to the md4 structure to use for encryption
    \param data the data to be hashed
    \param len length of data to be hashed

    _Example_
    \code
    md4 md4[1];
    byte data[] = { }; // Data to be hashed
    word32 len = sizeof(data);

    if ((ret = wc_InitMd4(md4)) != 0) {
       WOLFSSL_MSG("wc_Initmd4 failed");
    }
    else {
       wc_Md4Update(md4, data, len);
       wc_Md4Final(md4, hash);
    }
    \endcode

    \sa wc_Md4Hash
    \sa wc_Md4Final
    \sa wc_InitMd4
*/
void wc_Md4Update(Md4* md4, const byte* data, word32 len);

/*!
    \ingroup MD4

    \brief Finalizes hashing of data. Result is placed into hash.

    \return 0 Returned upon successfully finalizing.

    \param md4 pointer to the md4 structure to use for encryption
    \param hash Byte array to hold hash value.

    _Example_
    \code
    md4 md4[1];
    if ((ret = wc_InitMd4(md4)) != 0) {
        WOLFSSL_MSG("wc_Initmd4 failed");
    }
    else {
        wc_Md4Update(md4, data, len);
        wc_Md4Final(md4, hash);
    }
    \endcode

    \sa wc_Md4Hash
    \sa wc_Md4Final
    \sa wc_InitMd4
*/
void wc_Md4Final(Md4* md4, byte* hash);

/*!
    \ingroup MD4
    \brief This function initializes an MD4 context for OpenSSL
    compatibility. This is a wrapper around wc_InitMd4 for applications
    using the OpenSSL-compatible API.

    \return none No returns.

    \param md4 pointer to the WOLFSSL_MD4_CTX structure to initialize

    _Example_
    \code
    WOLFSSL_MD4_CTX md4;
    byte data[] = { /* data to hash */ };
    byte hash[WC_MD4_DIGEST_SIZE];
    
    wolfSSL_MD4_Init(&md4);
    wolfSSL_MD4_Update(&md4, data, sizeof(data));
    wolfSSL_MD4_Final(hash, &md4);
    \endcode

    \sa wolfSSL_MD4_Update
    \sa wolfSSL_MD4_Final
    \sa wc_InitMd4
*/
void wolfSSL_MD4_Init(WOLFSSL_MD4_CTX* md4);

/*!
    \ingroup MD4
    \brief This function updates an MD4 hash with additional data for
    OpenSSL compatibility. This is a wrapper around wc_Md4Update for
    applications using the OpenSSL-compatible API.

    \return none No returns.

    \param md4 pointer to the WOLFSSL_MD4_CTX structure to update
    \param data pointer to the data to hash
    \param len length of the data in bytes

    _Example_
    \code
    WOLFSSL_MD4_CTX md4;
    byte data[] = { /* data to hash */ };
    
    wolfSSL_MD4_Init(&md4);
    wolfSSL_MD4_Update(&md4, data, sizeof(data));
    \endcode

    \sa wolfSSL_MD4_Init
    \sa wolfSSL_MD4_Final
    \sa wc_Md4Update
*/
void wolfSSL_MD4_Update(WOLFSSL_MD4_CTX* md4, const void* data,
                        unsigned long len);

/*!
    \ingroup MD4
    \brief This function finalizes an MD4 hash and outputs the digest
    for OpenSSL compatibility. This is a wrapper around wc_Md4Final for
    applications using the OpenSSL-compatible API.

    \return none No returns.

    \param digest pointer to buffer to store the MD4 digest (16 bytes)
    \param md4 pointer to the WOLFSSL_MD4_CTX structure to finalize

    _Example_
    \code
    WOLFSSL_MD4_CTX md4;
    byte data[] = { /* data to hash */ };
    byte hash[WC_MD4_DIGEST_SIZE];
    
    wolfSSL_MD4_Init(&md4);
    wolfSSL_MD4_Update(&md4, data, sizeof(data));
    wolfSSL_MD4_Final(hash, &md4);
    \endcode

    \sa wolfSSL_MD4_Init
    \sa wolfSSL_MD4_Update
    \sa wc_Md4Final
*/
void wolfSSL_MD4_Final(unsigned char* digest, WOLFSSL_MD4_CTX* md4);
