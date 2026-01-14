/*!
    \ingroup BLAKE2

    \brief This function initializes a Blake2b structure for use with the
    Blake2 hash function.

    \return 0 Returned upon successfully initializing the Blake2b structure and
    setting the digest size.

    \param b2b pointer to the Blake2b structure to initialize
    \param digestSz length of the blake 2 digest to implement

    _Example_
    \code
    Blake2b b2b;
    // initialize Blake2b structure with 64 byte digest
    wc_InitBlake2b(&b2b, WC_BLAKE2B_DIGEST_SIZE);
    \endcode

    \sa wc_Blake2bUpdate
*/
int wc_InitBlake2b(Blake2b* b2b, word32 digestSz);

/*!
    \ingroup BLAKE2

    \brief This function updates the Blake2b hash with the given input data.
    This function should be called after wc_InitBlake2b, and repeated until
    one is ready for the final hash: wc_Blake2bFinal.

    \return 0 Returned upon successfully update the Blake2b structure with
    the given data
    \return -1 Returned if there is a failure while compressing the input data

    \param b2b pointer to the Blake2b structure to update
    \param data pointer to a buffer containing the data to append
    \param sz length of the input data to append

    _Example_
    \code
    int ret;
    Blake2b b2b;
    // initialize Blake2b structure with 64 byte digest
    wc_InitBlake2b(&b2b, WC_BLAKE2B_DIGEST_SIZE);

    byte plain[] = { // initialize input };

    ret = wc_Blake2bUpdate(&b2b, plain, sizeof(plain));
    if (ret != 0) {
        // error updating blake2b
    }
    \endcode

    \sa wc_InitBlake2b
    \sa wc_Blake2bFinal
*/
int wc_Blake2bUpdate(Blake2b* b2b, const byte* data, word32 sz);

/*!
    \ingroup BLAKE2

    \brief This function computes the Blake2b hash of the previously supplied
    input data. The output hash will be of length requestSz, or, if
    requestSz==0, the digestSz of the b2b structure. This function should be
    called after wc_InitBlake2b and wc_Blake2bUpdate has been processed for
    each piece of input data desired.

    \return 0 Returned upon successfully computing the Blake2b hash
    \return -1 Returned if there is a failure while parsing the Blake2b hash

    \param b2b pointer to the Blake2b structure to update
    \param final pointer to a buffer in which to store the blake2b hash.
    Should be of length requestSz
    \param requestSz length of the digest to compute. When this is zero,
    b2b->digestSz will be used instead

    _Example_
    \code
    int ret;
    Blake2b b2b;
    byte hash[WC_BLAKE2B_DIGEST_SIZE];
    // initialize Blake2b structure with 64 byte digest
    wc_InitBlake2b(&b2b, WC_BLAKE2B_DIGEST_SIZE);
    ... // call wc_Blake2bUpdate to add data to hash

    ret = wc_Blake2bFinal(&b2b, hash, WC_BLAKE2B_DIGEST_SIZE);
    if (ret != 0) {
        // error generating blake2b hash
    }
    \endcode

    \sa wc_InitBlake2b
    \sa wc_Blake2bUpdate
*/
int wc_Blake2bFinal(Blake2b* b2b, byte* final, word32 requestSz);

/*!
    \ingroup BLAKE2

    \brief Initialize an HMAC-BLAKE2b message authentication code computation.

    \return 0 Returned upon successfully initializing the HMAC-BLAKE2b MAC
    computation.

    \param b2b Blake2b structure to be used for the MAC computation.
    \param key pointer to the key
    \param key_len length of the key

    _Example_
    \code
    Blake2b b2b;
    int ret;
    byte key[] = {4, 5, 6};
    ret = wc_Blake2bHmacInit(&b2b, key);
    if (ret != 0) {
        // error generating HMAC-BLAKE2b
    }
    \endcode
*/
int wc_Blake2bHmacInit(Blake2b * b2b,
        const byte * key, size_t key_len);

/*!
    \ingroup BLAKE2

    \brief Update an HMAC-BLAKE2b message authentication code computation with
    additional input data.

    \return 0 Returned upon successfully updating the HMAC-BLAKE2b MAC
    computation.

    \param b2b Blake2b structure to be used for the MAC computation.
    \param in pointer to the input data
    \param in_len length of the input data

    _Example_
    \code
    Blake2b b2b;
    int ret;
    byte key[] = {4, 5, 6};
    byte data[] = {1, 2, 3};
    ret = wc_Blake2bHmacInit(&b2b, key, sizeof(key));
    ret = wc_Blake2bHmacUpdate(&b2b, data, sizeof(data));
    \endcode
*/
int wc_Blake2bHmacUpdate(Blake2b * b2b,
        const byte * in, size_t in_len);

/*!
    \ingroup BLAKE2

    \brief Finalize an HMAC-BLAKE2b message authentication code computation.

    \return 0 Returned upon successfully finalizing the HMAC-BLAKE2b MAC
    computation.

    \param b2b Blake2b structure to be used for the MAC computation.
    \param key pointer to the key
    \param key_len length of the key
    \param out output buffer to store computed MAC
    \param out_len length of output buffer

    _Example_
    \code
    Blake2b b2b;
    int ret;
    byte key[] = {4, 5, 6};
    byte data[] = {1, 2, 3};
    byte mac[WC_BLAKE2B_DIGEST_SIZE];
    ret = wc_Blake2bHmacInit(&b2b, key, sizeof(key));
    ret = wc_Blake2bHmacUpdate(&b2b, data, sizeof(data));
    ret = wc_Blake2bHmacFinalize(&b2b, key, sizeof(key), mac, sizezof(mac));
    \endcode
*/
int wc_Blake2bHmacFinal(Blake2b * b2b,
        const byte * key, size_t key_len,
        byte * out, size_t out_len);

/*!
    \ingroup BLAKE2

    \brief Compute the HMAC-BLAKE2b message authentication code of the given
    input data using the given key.

    \return 0 Returned upon successfully computing the HMAC-BLAKE2b MAC.

    \param in pointer to the input data
    \param in_len length of the input data
    \param key pointer to the key
    \param key_len length of the key
    \param out output buffer to store computed MAC
    \param out_len length of output buffer

    _Example_
    \code
    int ret;
    byte mac[WC_BLAKE2B_DIGEST_SIZE];
    byte data[] = {1, 2, 3};
    byte key[] = {4, 5, 6};
    ret = wc_Blake2bHmac(data, sizeof(data), key, sizeof(key), mac, sizeof(mac));
    if (ret != 0) {
        // error generating HMAC-BLAKE2b
    }
    \endcode
*/
int wc_Blake2bHmac(const byte * in, size_t in_len,
        const byte * key, size_t key_len,
        byte * out, size_t out_len);


/*!
    \ingroup BLAKE2

    \brief This function initializes a Blake2s structure for use with the
    Blake2 hash function.

    \return 0 Returned upon successfully initializing the Blake2s structure and
    setting the digest size.

    \param b2s pointer to the Blake2s structure to initialize
    \param digestSz length of the blake 2 digest to implement

    _Example_
    \code
    Blake2s b2s;
    // initialize Blake2s structure with 32 byte digest
    wc_InitBlake2s(&b2s, WC_BLAKE2S_DIGEST_SIZE);
    \endcode

    \sa wc_Blake2sUpdate
*/
int wc_InitBlake2s(Blake2s* b2s, word32 digestSz);

/*!
    \ingroup BLAKE2

    \brief This function updates the Blake2s hash with the given input data.
    This function should be called after wc_InitBlake2s, and repeated until
    one is ready for the final hash: wc_Blake2sFinal.

    \return 0 Returned upon successfully update the Blake2s structure with
    the given data
    \return -1 Returned if there is a failure while compressing the input data

    \param b2s pointer to the Blake2s structure to update
    \param data pointer to a buffer containing the data to append
    \param sz length of the input data to append

    _Example_
    \code
    int ret;
    Blake2s b2s;
    // initialize Blake2s structure with 32 byte digest
    wc_InitBlake2s(&b2s, WC_BLAKE2S_DIGEST_SIZE);

    byte plain[] = { // initialize input };

    ret = wc_Blake2sUpdate(&b2s, plain, sizeof(plain));
    if (ret != 0) {
        // error updating blake2s
    }
    \endcode

    \sa wc_InitBlake2s
    \sa wc_Blake2sFinal
*/
int wc_Blake2sUpdate(Blake2s* b2s, const byte* data, word32 sz);

/*!
    \ingroup BLAKE2

    \brief This function computes the Blake2s hash of the previously supplied
    input data. The output hash will be of length requestSz, or, if
    requestSz==0, the digestSz of the b2s structure. This function should be
    called after wc_InitBlake2s and wc_Blake2sUpdate has been processed for
    each piece of input data desired.

    \return 0 Returned upon successfully computing the Blake2s hash
    \return -1 Returned if there is a failure while parsing the Blake2s hash

    \param b2s pointer to the Blake2s structure to update
    \param final pointer to a buffer in which to store the blake2s hash.
    Should be of length requestSz
    \param requestSz length of the digest to compute. When this is zero,
    b2s->digestSz will be used instead

    _Example_
    \code
    int ret;
    Blake2s b2s;
    byte hash[WC_BLAKE2S_DIGEST_SIZE];
    // initialize Blake2s structure with 32 byte digest
    wc_InitBlake2s(&b2s, WC_BLAKE2S_DIGEST_SIZE);
    ... // call wc_Blake2sUpdate to add data to hash

    ret = wc_Blake2sFinal(&b2s, hash, WC_BLAKE2S_DIGEST_SIZE);
    if (ret != 0) {
        // error generating blake2s hash
    }
    \endcode

    \sa wc_InitBlake2s
    \sa wc_Blake2sUpdate
*/
int wc_Blake2sFinal(Blake2s* b2s, byte* final, word32 requestSz);

/*!
    \ingroup BLAKE2

    \brief Initialize an HMAC-BLAKE2s message authentication code computation.

    \return 0 Returned upon successfully initializing the HMAC-BLAKE2s MAC
    computation.

    \param b2s Blake2s structure to be used for the MAC computation.
    \param key pointer to the key
    \param key_len length of the key

    _Example_
    \code
    Blake2s b2s;
    int ret;
    byte key[] = {4, 5, 6};
    ret = wc_Blake2sHmacInit(&b2s, key);
    if (ret != 0) {
        // error generating HMAC-BLAKE2s
    }
    \endcode
*/
int wc_Blake2sHmacInit(Blake2s * b2s,
        const byte * key, size_t key_len);

/*!
    \ingroup BLAKE2

    \brief Update an HMAC-BLAKE2s message authentication code computation with
    additional input data.

    \return 0 Returned upon successfully updating the HMAC-BLAKE2s MAC
    computation.

    \param b2s Blake2s structure to be used for the MAC computation.
    \param in pointer to the input data
    \param in_len length of the input data

    _Example_
    \code
    Blake2s b2s;
    int ret;
    byte key[] = {4, 5, 6};
    byte data[] = {1, 2, 3};
    ret = wc_Blake2sHmacInit(&b2s, key, sizeof(key));
    ret = wc_Blake2sHmacUpdate(&b2s, data, sizeof(data));
    \endcode
*/
int wc_Blake2sHmacUpdate(Blake2s * b2s,
        const byte * in, size_t in_len);

/*!
    \ingroup BLAKE2

    \brief Finalize an HMAC-BLAKE2s message authentication code computation.

    \return 0 Returned upon successfully finalizing the HMAC-BLAKE2s MAC
    computation.

    \param b2s Blake2s structure to be used for the MAC computation.
    \param key pointer to the key
    \param key_len length of the key
    \param out output buffer to store computed MAC
    \param out_len length of output buffer

    _Example_
    \code
    Blake2s b2s;
    int ret;
    byte key[] = {4, 5, 6};
    byte data[] = {1, 2, 3};
    byte mac[WC_BLAKE2S_DIGEST_SIZE];
    ret = wc_Blake2sHmacInit(&b2s, key, sizeof(key));
    ret = wc_Blake2sHmacUpdate(&b2s, data, sizeof(data));
    ret = wc_Blake2sHmacFinalize(&b2s, key, sizeof(key), mac, sizezof(mac));
    \endcode
*/
int wc_Blake2sHmacFinal(Blake2s * b2s,
        const byte * key, size_t key_len,
        byte * out, size_t out_len);

/*!
    \ingroup BLAKE2

    \brief This function computes the HMAC-BLAKE2s message authentication code
    of the given input data using the given key.

    \return 0 Returned upon successfully computing the HMAC-BLAKE2s MAC.

    \param in pointer to the input data
    \param in_len length of the input data
    \param key pointer to the key
    \param key_len length of the key
    \param out output buffer to store computed MAC
    \param out_len length of output buffer

    _Example_
    \code
    int ret;
    byte mac[WC_BLAKE2S_DIGEST_SIZE];
    byte data[] = {1, 2, 3};
    byte key[] = {4, 5, 6};
    ret = wc_Blake2sHmac(data, sizeof(data), key, sizeof(key), mac, sizeof(mac));
    if (ret != 0) {
        // error generating HMAC-BLAKE2s
    }
    \endcode
*/
int wc_Blake2sHmac(const byte * in, size_t in_len,
        const byte * key, size_t key_len,
        byte * out, size_t out_len);
