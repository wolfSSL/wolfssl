/*!
    \ingroup Signature

    \brief This function returns the maximum size of the resulting signature.

    \return Returns SIG_TYPE_E if sig_type is not supported. Returns
    BAD_FUNC_ARG if sig_type was invalid. A positive return value indicates
    the maximum size of a signature.

    \param sig_type A signature type enum value such as
    WC_SIGNATURE_TYPE_ECC or WC_SIGNATURE_TYPE_RSA.
    \param key Pointer to a key structure such as ecc_key or RsaKey.
    \param key_len Size of the key structure.

    _Example_
    \code
    // Get signature length
    enum wc_SignatureType sig_type = WC_SIGNATURE_TYPE_ECC;
    ecc_key eccKey;
    word32 sigLen;
    wc_ecc_init(&eccKey);
    sigLen = wc_SignatureGetSize(sig_type, &eccKey, sizeof(eccKey));
    if (sigLen > 0) {
    	// Success
    }
    \endcode

    \sa wc_HashGetDigestSize
    \sa wc_SignatureGenerate
    \sa wc_SignatureVerify
*/
int wc_SignatureGetSize(enum wc_SignatureType sig_type,
    const void* key, word32 key_len);

/*!
    \ingroup Signature

    \brief This function validates a signature by hashing the data and
    using the resulting hash and key to verify the signature.

    \return 0 Success
    \return SIG_TYPE_E -231, signature type not enabled/ available
    \return BAD_FUNC_ARG -173, bad function argument provided
    \return BUFFER_E -132, output buffer too small or input too large.

    \param hash_type A hash type from the “enum  wc_HashType” such as
    “WC_HASH_TYPE_SHA256”.
    \param sig_type A signature type enum value such as
    WC_SIGNATURE_TYPE_ECC or WC_SIGNATURE_TYPE_RSA.
    \param data Pointer to buffer containing the data to hash.
    \param data_len Length of the data buffer.
    \param sig Pointer to buffer to output signature.
    \param sig_len Length of the signature output buffer.
    \param key Pointer to a key structure such as ecc_key or RsaKey.
    \param key_len Size of the key structure.

    _Example_
    \code
    int ret;
    ecc_key eccKey;

    // Import the public key
    wc_ecc_init(&eccKey);
    ret = wc_ecc_import_x963(eccPubKeyBuf, eccPubKeyLen, &eccKey);
    // Perform signature verification using public key
    ret = wc_SignatureVerify(
    WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_ECC,
    fileBuf, fileLen,
    sigBuf, sigLen,
    &eccKey, sizeof(eccKey));
    printf("Signature Verification: %s
    (%d)\n", (ret == 0) ? "Pass" : "Fail", ret);
    wc_ecc_free(&eccKey);
    \endcode

    \sa wc_SignatureGetSize
    \sa wc_SignatureGenerate
*/
int wc_SignatureVerify(
    enum wc_HashType hash_type, enum wc_SignatureType sig_type,
    const byte* data, word32 data_len,
    const byte* sig, word32 sig_len,
    const void* key, word32 key_len);

/*!
    \ingroup Signature

    \brief This function generates a signature from the data using a
    key. It first creates a hash of the data then signs the hash using the key.

    \return 0 Success
    \return SIG_TYPE_E -231, signature type not enabled/ available
    \return BAD_FUNC_ARG -173, bad function argument provided
    \return BUFFER_E -132, output buffer too small or input too large.

    \param hash_type A hash type from the “enum  wc_HashType”
    such as “WC_HASH_TYPE_SHA256”.
    \param sig_type A signature type enum value such as
    WC_SIGNATURE_TYPE_ECC or WC_SIGNATURE_TYPE_RSA.
    \param data Pointer to buffer containing the data to hash.
    \param data_len Length of the data buffer.
    \param sig Pointer to buffer to output signature.
    \param sig_len Length of the signature output buffer.
    \param key Pointer to a key structure such as ecc_key or RsaKey.
    \param key_len Size of the key structure.
    \param rng Pointer to an initialized RNG structure.

    _Example_
    \code
    int ret;
    WC_RNG rng;
    ecc_key eccKey;

    wc_InitRng(&rng);
    wc_ecc_init(&eccKey);

    // Generate key
    ret = wc_ecc_make_key(&rng, 32, &eccKey);

    // Get signature length and allocate buffer
    sigLen = wc_SignatureGetSize(sig_type, &eccKey, sizeof(eccKey));
    sigBuf = malloc(sigLen);

    // Perform signature verification using public key
    ret = wc_SignatureGenerate(
        WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_ECC,
        fileBuf, fileLen,
        sigBuf, &sigLen,
        &eccKey, sizeof(eccKey),
        &rng);
    printf("Signature Generation: %s
    (%d)\n", (ret == 0) ? "Pass" : "Fail", ret);

    free(sigBuf);
    wc_ecc_free(&eccKey);
    wc_FreeRng(&rng);
    \endcode

    \sa wc_SignatureGetSize
    \sa wc_SignatureVerify
*/
int wc_SignatureGenerate(
    enum wc_HashType hash_type, enum wc_SignatureType sig_type,
    const byte* data, word32 data_len,
    byte* sig, word32 *sig_len,
    const void* key, word32 key_len,
    WC_RNG* rng);

/*!
    \ingroup Signature
    \brief This function verifies a signature using a pre-computed hash.
    Unlike wc_SignatureVerify which hashes the data first, this function
    takes the hash directly and verifies the signature against it.
    If sig_type is WC_SIGNATURE_TYPE_RSA_W_ENC, hash data must be encoded
    with wc_EncodeSignature prior to calling.

    \return 0 Success
    \return SIG_TYPE_E Signature type not enabled/available
    \return BAD_FUNC_ARG Bad function argument provided
    \return BUFFER_E Output buffer too small or input too large

    \param hash_type A hash type from enum wc_HashType
    \param sig_type A signature type such as WC_SIGNATURE_TYPE_ECC or
    WC_SIGNATURE_TYPE_RSA
    \param hash_data Pointer to buffer containing the hash to verify
    \param hash_len Length of the hash buffer
    \param sig Pointer to buffer containing the signature
    \param sig_len Length of the signature buffer
    \param key Pointer to a key structure such as ecc_key or RsaKey
    \param key_len Size of the key structure

    _Example_
    \code
    ecc_key eccKey;
    byte hash[WC_SHA256_DIGEST_SIZE];
    byte sig[ECC_MAX_SIG_SIZE];
    word32 sigLen = sizeof(sig);

    wc_ecc_init(&eccKey);
    // import public key and compute hash
    int ret = wc_SignatureVerifyHash(WC_HASH_TYPE_SHA256,
                                     WC_SIGNATURE_TYPE_ECC, hash,
                                     sizeof(hash), sig, sigLen,
                                     &eccKey, sizeof(eccKey));
    if (ret == 0) {
        // signature verified
    }
    \endcode

    \sa wc_SignatureVerify
    \sa wc_SignatureGenerateHash
*/
int wc_SignatureVerifyHash(enum wc_HashType hash_type,
                           enum wc_SignatureType sig_type,
                           const byte* hash_data, word32 hash_len,
                           const byte* sig, word32 sig_len,
                           const void* key, word32 key_len);

/*!
    \ingroup Signature
    \brief This function generates a signature from a pre-computed hash.
    Unlike wc_SignatureGenerate which hashes the data first, this
    function takes the hash directly and signs it.
    If sig_type is WC_SIGNATURE_TYPE_RSA_W_ENC, hash data must be encoded
    with wc_EncodeSignature prior to calling.

    \return 0 Success
    \return SIG_TYPE_E Signature type not enabled/available
    \return BAD_FUNC_ARG Bad function argument provided
    \return BUFFER_E Output buffer too small or input too large

    \param hash_type A hash type from enum wc_HashType
    \param sig_type A signature type such as WC_SIGNATURE_TYPE_ECC or
    WC_SIGNATURE_TYPE_RSA
    \param hash_data Pointer to buffer containing the hash to sign
    \param hash_len Length of the hash buffer
    \param sig Pointer to buffer to output signature
    \param sig_len Pointer to length of signature output buffer
    \param key Pointer to a key structure such as ecc_key or RsaKey
    \param key_len Size of the key structure
    \param rng Pointer to an initialized RNG structure

    _Example_
    \code
    WC_RNG rng;
    ecc_key eccKey;
    byte hash[WC_SHA256_DIGEST_SIZE];
    byte sig[ECC_MAX_SIG_SIZE];
    word32 sigLen = sizeof(sig);

    wc_InitRng(&rng);
    wc_ecc_init(&eccKey);
    wc_ecc_make_key(&rng, 32, &eccKey);
    // compute hash
    int ret = wc_SignatureGenerateHash(WC_HASH_TYPE_SHA256,
                                       WC_SIGNATURE_TYPE_ECC, hash,
                                       sizeof(hash), sig, &sigLen,
                                       &eccKey, sizeof(eccKey), &rng);
    \endcode

    \sa wc_SignatureGenerate
    \sa wc_SignatureVerifyHash
*/
int wc_SignatureGenerateHash(enum wc_HashType hash_type,
                             enum wc_SignatureType sig_type,
                             const byte* hash_data, word32 hash_len,
                             byte* sig, word32 *sig_len,
                             const void* key, word32 key_len,
                             WC_RNG* rng);

/*!
    \ingroup Signature
    \brief This function generates a signature from a pre-computed hash
    with extended options. This is similar to wc_SignatureGenerateHash
    but allows optional verification of the signature after generation.

    \return 0 Success
    \return SIG_TYPE_E Signature type not enabled/available
    \return BAD_FUNC_ARG Bad function argument provided
    \return BUFFER_E Output buffer too small or input too large

    \param hash_type A hash type from enum wc_HashType
    \param sig_type A signature type such as WC_SIGNATURE_TYPE_ECC or
    WC_SIGNATURE_TYPE_RSA
    \param hash_data Pointer to buffer containing the hash to sign
    \param hash_len Length of the hash buffer
    \param sig Pointer to buffer to output signature
    \param sig_len Pointer to length of signature output buffer
    \param key Pointer to a key structure such as ecc_key or RsaKey
    \param key_len Size of the key structure
    \param rng Pointer to an initialized RNG structure
    \param verify If non-zero, verify the signature after generation

    _Example_
    \code
    WC_RNG rng;
    ecc_key eccKey;
    byte hash[WC_SHA256_DIGEST_SIZE];
    byte sig[ECC_MAX_SIG_SIZE];
    word32 sigLen = sizeof(sig);

    wc_InitRng(&rng);
    wc_ecc_init(&eccKey);
    wc_ecc_make_key(&rng, 32, &eccKey);
    int ret = wc_SignatureGenerateHash_ex(WC_HASH_TYPE_SHA256,
                                          WC_SIGNATURE_TYPE_ECC, hash,
                                          sizeof(hash), sig, &sigLen,
                                          &eccKey, sizeof(eccKey),
                                          &rng, 1);
    \endcode

    \sa wc_SignatureGenerateHash
    \sa wc_SignatureGenerate_ex
*/
int wc_SignatureGenerateHash_ex(enum wc_HashType hash_type,
                                enum wc_SignatureType sig_type,
                                const byte* hash_data, word32 hash_len,
                                byte* sig, word32 *sig_len,
                                const void* key, word32 key_len,
                                WC_RNG* rng, int verify);

/*!
    \ingroup Signature
    \brief This function generates a signature from data with extended
    options. This is similar to wc_SignatureGenerate but allows optional
    verification of the signature after generation.

    \return 0 Success
    \return SIG_TYPE_E Signature type not enabled/available
    \return BAD_FUNC_ARG Bad function argument provided
    \return BUFFER_E Output buffer too small or input too large

    \param hash_type A hash type from enum wc_HashType
    \param sig_type A signature type such as WC_SIGNATURE_TYPE_ECC or
    WC_SIGNATURE_TYPE_RSA
    \param data Pointer to buffer containing the data to hash and sign
    \param data_len Length of the data buffer
    \param sig Pointer to buffer to output signature
    \param sig_len Pointer to length of signature output buffer
    \param key Pointer to a key structure such as ecc_key or RsaKey
    \param key_len Size of the key structure
    \param rng Pointer to an initialized RNG structure
    \param verify If non-zero, verify the signature after generation

    _Example_
    \code
    WC_RNG rng;
    ecc_key eccKey;
    byte data[]; // data to sign
    byte sig[ECC_MAX_SIG_SIZE];
    word32 sigLen = sizeof(sig);

    wc_InitRng(&rng);
    wc_ecc_init(&eccKey);
    wc_ecc_make_key(&rng, 32, &eccKey);
    int ret = wc_SignatureGenerate_ex(WC_HASH_TYPE_SHA256,
                                      WC_SIGNATURE_TYPE_ECC, data,
                                      sizeof(data), sig, &sigLen,
                                      &eccKey, sizeof(eccKey), &rng, 1);
    \endcode

    \sa wc_SignatureGenerate
    \sa wc_SignatureGenerateHash_ex
*/
int wc_SignatureGenerate_ex(enum wc_HashType hash_type,
                            enum wc_SignatureType sig_type,
                            const byte* data, word32 data_len,
                            byte* sig, word32 *sig_len,
                            const void* key, word32 key_len,
                            WC_RNG* rng, int verify);
