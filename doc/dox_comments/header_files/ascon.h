/*!
    \ingroup ASCON
    \brief This function initializes the ASCON context for hashing.

    \return 0 on success.
    \return BAD_FUNC_ARG if the context pointer is NULL.

    \param a pointer to the ASCON context to initialize.

    _Example_
    \code
    wc_AsconHash256 a;
    byte data[] = {0x01, 0x02, 0x03};
    byte hash[ASCON_HASH256_SZ];

    if (wc_AsconHash256_Init(&a) != 0)
        // handle error
    if (wc_AsconHash256_Update(&ctx, data, sizeof(data)) != 0)
        // handle error
    if (wc_AsconHash256_Final(&ctx, hash, sizeof(hash)) != 0)
        // handle error
    // hash contains the final hash
    \endcode

    \sa wc_AsconHash256_Update
    \sa wc_AsconHash256_Final
    */
int wc_AsconHash256_Init(wc_AsconHash256* a);

/*!
    \ingroup ASCON
    \brief This function updates the ASCON hash with the input data.

    \return 0 on success.
    \return BAD_FUNC_ARG if the context or input pointer is NULL.

    \param ctx pointer to the ASCON context.
    \param in pointer to the input data.
    \param inSz size of the input data.

    _Example_
    \code
    wc_AsconHash256 a;
    byte data[] = {0x01, 0x02, 0x03};
    byte hash[ASCON_HASH256_SZ];

    if (wc_AsconHash256_Init(&a) != 0)
        // handle error
    if (wc_AsconHash256_Update(&ctx, data, sizeof(data)) != 0)
        // handle error
    if (wc_AsconHash256_Final(&ctx, hash, sizeof(hash)) != 0)
        // handle error
    // hash contains the final hash
    \endcode

    \sa wc_AsconHash256_Init
    \sa wc_AsconHash256_Final
    */
int wc_AsconHash256_Update(wc_AsconHash256* a, const byte* data, word32 dataSz);

/*!
    \ingroup ASCON
    \brief This function finalizes the ASCON hash and produces the output.

    \return 0 on success.
    \return BAD_FUNC_ARG if the context or output pointer is NULL.

    \param ctx pointer to the ASCON context.
    \param out pointer to the output buffer.
    \param outSz size of the output buffer, should be at least ASCON_HASH256_SZ.

    _Example_
    \code
    wc_AsconHash256 a;
    byte data[] = {0x01, 0x02, 0x03};
    byte hash[ASCON_HASH256_SZ];

    if (wc_AsconHash256_Init(&a) != 0)
        // handle error
    if (wc_AsconHash256_Update(&ctx, data, sizeof(data)) != 0)
        // handle error
    if (wc_AsconHash256_Final(&ctx, hash, sizeof(hash)) != 0)
        // handle error
    // hash contains the final hash
    \endcode

    \sa wc_AsconHash256_Init
    \sa wc_AsconHash256_Update
    */
int wc_AsconHash256_Final(wc_AsconHash256* a, byte* hash);

/*!
    \ingroup ASCON
    \brief This function allocates and initializes a new Ascon AEAD context.

    \return pointer to the newly allocated Ascon AEAD context
    \return NULL on failure.

    _Example_
    \code
    wc_AsconAEAD128* a = wc_AsconAEAD128_New();
    if (a == NULL) {
        // handle allocation error
    }
    wc_AsconAEAD128_Free(a);
    \endcode

    \sa wc_AsconAEAD128_Free
*/
wc_AsconAEAD128* wc_AsconAEAD128_New(void);

/*!
    \ingroup ASCON
    \brief This function frees the resources associated with the Ascon AEAD
           context.

    \param a pointer to the Ascon AEAD context to free.

    _Example_
    \code
    wc_AsconAEAD128* a = wc_AsconAEAD128_New();
    if (a == NULL) {
        // handle allocation error
    }
    // Use the context
    wc_AsconAEAD128_Free(a);
    \endcode

    \sa wc_AsconAEAD128_New
*/
void wc_AsconAEAD128_Free(wc_AsconAEAD128 *a);


/*!
    \ingroup ASCON
    \brief This function initializes an Ascon AEAD context.

    \return 0 on success.
    \return BAD_FUNC_ARG if the context or output pointer is NULL.

    \param a pointer to the Ascon AEAD context to initialize.

    _Example_
    \code
    AsconAead a;

    if (wc_AsconAEAD128_Init(&a) != 0)
        // handle error
    \endcode

    \sa wc_AsconAeadEncrypt
    \sa wc_AsconAeadDecrypt
    */
int wc_AsconAEAD128_Init(wc_AsconAEAD128* a);

/*!
    \ingroup ASCON
    \brief This function deinitializes an Ascon AEAD context. It does not
           free the context.

    \param a pointer to the Ascon AEAD context to deinitialize.

    _Example_
    \code
    AsconAead a;

    if (wc_AsconAEAD128_Init(&a) != 0)
        // handle error
    wc_AsconAEAD128_Clear(&a);
    \endcode

    \sa wc_AsconAeadEncrypt
    \sa wc_AsconAeadDecrypt
    */
void wc_AsconAEAD128_Clear(wc_AsconAEAD128 *a);

/*!
    \ingroup ASCON
    \brief This function sets the key for the Ascon AEAD context.

    \return 0 on success.
    \return BAD_FUNC_ARG if the context or key pointer is NULL.
    \return BAD_STATE_E if the key has already been set.

    \param a pointer to the initialized Ascon AEAD context.
    \param key pointer to the key buffer of length ASCON_AEAD128_KEY_SZ.

    _Example_
    \code
    wc_AsconAEAD128 a;
    byte key[ASCON_AEAD128_KEY_SZ] = { ... };

    if (wc_AsconAEAD128_Init(&a) != 0)
        // handle error
    if (wc_AsconAEAD128_SetKey(&a, key) != 0)
        // handle error
    \endcode

    \sa wc_AsconAEAD128_Init
    \sa wc_AsconAEAD128_SetNonce
    \sa wc_AsconAEAD128_SetAD
*/
int wc_AsconAEAD128_SetKey(wc_AsconAEAD128* a, const byte* key);

/*!
    \ingroup ASCON
    \brief This function sets the nonce for the Ascon AEAD context.

    \return 0 on success.
    \return BAD_FUNC_ARG if the context or nonce pointer is NULL.
    \return BAD_STATE_E if the nonce has already been set.

    \param a pointer to the initialized Ascon AEAD context.
    \param nonce pointer to the nonce buffer of length ASCON_AEAD128_NONCE_SZ.

    _Example_
    \code
    wc_AsconAEAD128 a;
    byte nonce[ASCON_AEAD128_NONCE_SZ] = { ... };

    if (wc_AsconAEAD128_Init(&a) != 0)
        // handle error
    if (wc_AsconAEAD128_SetNonce(&a, nonce) != 0)
        // handle error
    \endcode

    \sa wc_AsconAEAD128_Init
    \sa wc_AsconAEAD128_SetKey
    \sa wc_AsconAEAD128_SetAD
*/
int wc_AsconAEAD128_SetNonce(wc_AsconAEAD128* a, const byte* nonce);

/*!
    \ingroup ASCON
    \brief This function sets the associated data for the Ascon AEAD context.

    \return 0 on success.
    \return BAD_FUNC_ARG if the context or associated data pointer is NULL.
    \return BAD_STATE_E if the key or nonce has not been set.

    \param a pointer to the initialized Ascon AEAD context.
    \param ad pointer to the associated data buffer.
    \param adSz size of the associated data buffer.

    _Example_
    \code
    wc_AsconAEAD128 a;
    byte key[ASCON_AEAD128_KEY_SZ] = { ... };
    byte nonce[ASCON_AEAD128_NONCE_SZ] = { ... };
    byte ad[] = { ... };

    if (wc_AsconAEAD128_Init(&a) != 0)
        // handle error
    if (wc_AsconAEAD128_SetKey(&a, key) != 0)
        // handle error
    if (wc_AsconAEAD128_SetNonce(&a, nonce) != 0)
        // handle error
    if (wc_AsconAEAD128_SetAD(&a, ad, sizeof(ad)) != 0)
        // handle error
    \endcode

    \sa wc_AsconAEAD128_Init
    \sa wc_AsconAEAD128_SetKey
    \sa wc_AsconAEAD128_SetNonce
*/
int wc_AsconAEAD128_SetAD(wc_AsconAEAD128* a, const byte* ad, word32 adSz);

/*!
    \ingroup ASCON
    \brief This function encrypts a plaintext message using Ascon AEAD. The
           output is stored in the out buffer. The length of the output is
           equal to the length of the input.

    \return 0 on success.
    \return BAD_FUNC_ARG if the context or output pointer is NULL or the input
            is NULL while the input size is greater than 0.
    \return BAD_STATE_E if the key, nonce, or additional data has not been set
            or the context was previously used for decryption.

    \param a pointer to the initialized Ascon AEAD context.
    \param out pointer to the output buffer to store the ciphertext.
    \param in pointer to the input buffer containing the plaintext message.
    \param inSz length of the input buffer.

    _Example_
    \code
    wc_AsconAEAD128 a;
    byte key[ASCON_AEAD128_KEY_SZ] = { ... };
    byte nonce[ASCON_AEAD128_NONCE_SZ] = { ... };
    byte plaintext[PLAIN_TEXT_SIZE] = { ... };
    byte ciphertext[CIPHER_TEXT_SIZE];
    byte tag[ASCON_AEAD128_TAG_SZ] = { ... };

    if (wc_AsconAeadInit(&a) != 0)
        // handle error
    if (wc_AsconAEAD128_SetKey(&a, key) != 0)
        // handle error
    if (wc_AsconAEAD128_SetNonce(&a, nonce) != 0)
        // handle error
    if (wc_AsconAEAD128_SetAD(&a, ad, sizeof(ad)) != 0)
        // handle error
    if (wc_AsconAEAD128_EncryptUpdate(&a, ciphertext, plaintext,
                                      sizeof(plaintext)) != 0)
        // handle error
    if (wc_AsconAEAD128_EncryptFinal(&a, tag) != 0)
        // handle error
    \endcode

    \sa wc_AsconAeadInit
    \sa wc_AsconAEAD128_Clear
    \sa wc_AsconAEAD128_SetKey
    \sa wc_AsconAEAD128_SetNonce
    \sa wc_AsconAEAD128_SetAD
    \sa wc_AsconAEAD128_EncryptFinal
    \sa wc_AsconAEAD128_DecryptUpdate
    \sa wc_AsconAEAD128_DecryptFinal
    */
int wc_AsconAEAD128_EncryptUpdate(wc_AsconAEAD128* a, byte* out, const byte* in,
                                  word32 inSz);

/*!
    \ingroup ASCON
    \brief This function finalizes the encryption process using Ascon AEAD and
           produces the authentication tag.

    \return 0 on success.
    \return BAD_FUNC_ARG if the context or output pointer is NULL or the input
            is NULL while the input size is greater than 0.
    \return BAD_STATE_E if the key, nonce, or additional data has not been set
            or the context was previously used for decryption.

    \param a pointer to the initialized Ascon AEAD context.
    \param tag pointer to the output buffer to store the authentication tag.

    _Example_
    \code
    wc_AsconAEAD128 a;
    byte key[ASCON_AEAD128_KEY_SZ] = { ... };
    byte nonce[ASCON_AEAD128_NONCE_SZ] = { ... };
    byte plaintext[PLAIN_TEXT_SIZE] = { ... };
    byte ciphertext[CIPHER_TEXT_SIZE];
    byte tag[ASCON_AEAD128_TAG_SZ] = { ... };

    if (wc_AsconAeadInit(&a) != 0)
        // handle error
    if (wc_AsconAEAD128_SetKey(&a, key) != 0)
        // handle error
    if (wc_AsconAEAD128_SetNonce(&a, nonce) != 0)
        // handle error
    if (wc_AsconAEAD128_SetAD(&a, ad, sizeof(ad)) != 0)
        // handle error
    if (wc_AsconAEAD128_EncryptUpdate(&a, ciphertext, plaintext,
                                      sizeof(plaintext)) != 0)
        // handle error
    if (wc_AsconAEAD128_EncryptFinal(&a, tag) != 0)
        // handle error
    \endcode

    \sa wc_AsconAEAD128_Init
    \sa wc_AsconAEAD128_SetKey
    \sa wc_AsconAEAD128_SetNonce
    \sa wc_AsconAEAD128_SetAD
    \sa wc_AsconAEAD128_EncryptUpdate
    \sa wc_AsconAEAD128_DecryptUpdate
    \sa wc_AsconAEAD128_DecryptFinal
    */
int wc_AsconAEAD128_EncryptFinal(wc_AsconAEAD128* a, byte* tag);

/*!
    \ingroup ASCON
    \brief This function updates the decryption process using Ascon AEAD. The
           output is stored in the out buffer. The length of the output is
           equal to the length of the input.

    \return 0 on success.
    \return BAD_FUNC_ARG if the context or output pointer is NULL or the input
            is NULL while the input size is greater than 0.
    \return BAD_STATE_E if the key, nonce, or additional data has not been set
            or the context was previously used for encryption.

    \param a pointer to the initialized Ascon AEAD context.
    \param out pointer to the output buffer to store the plaintext.
    \param in pointer to the input buffer containing the ciphertext message.
    \param inSz length of the input buffer.

    _Example_
    \code
    wc_AsconAEAD128 a;
    byte key[ASCON_AEAD128_KEY_SZ] = { ... };
    byte nonce[ASCON_AEAD128_NONCE_SZ] = { ... };
    byte ciphertext[CIPHER_TEXT_SIZE] = { ... };
    byte plaintext[PLAIN_TEXT_SIZE];
    byte tag[ASCON_AEAD128_TAG_SZ] = { ... };

    if (wc_AsconAeadInit(&a) != 0)
        // handle error
    if (wc_AsconAEAD128_SetKey(&a, key) != 0)
        // handle error
    if (wc_AsconAEAD128_SetNonce(&a, nonce) != 0)
        // handle error
    if (wc_AsconAEAD128_SetAD(&a, ad, sizeof(ad)) != 0)
        // handle error
    if (wc_AsconAEAD128_DecryptUpdate(&a, plaintext, ciphertext,
                                      sizeof(ciphertext)) != 0)
        // handle error
    if (wc_AsconAEAD128_DecryptFinal(&a, tag) != 0)
        // handle error
    \endcode

    \sa wc_AsconAEAD128_Init
    \sa wc_AsconAEAD128_SetKey
    \sa wc_AsconAEAD128_SetNonce
    \sa wc_AsconAEAD128_SetAD
    \sa wc_AsconAEAD128_EncryptUpdate
    \sa wc_AsconAEAD128_EncryptFinal
    \sa wc_AsconAEAD128_DecryptFinal
    */
int wc_AsconAEAD128_DecryptUpdate(wc_AsconAEAD128* a, byte* out, const byte* in,
                                  word32 inSz);

/*!
    \ingroup ASCON
    \brief This function finalizes the decryption process using Ascon AEAD and
           verifies the authentication tag.

    \return 0 on success.
    \return BAD_FUNC_ARG if the context or tag pointer is NULL.
    \return BAD_STATE_E if the key, nonce, or additional data has not been set
            or the context was previously used for encryption.
    \return ASCON_AUTH_E if the authentication tag does not match.

    \param a pointer to the initialized Ascon AEAD context.
    \param tag pointer to the buffer containing the authentication tag to verify

    _Example_
    \code
    wc_AsconAEAD128 a;
    byte key[ASCON_AEAD128_KEY_SZ] = { ... };
    byte nonce[ASCON_AEAD128_NONCE_SZ] = { ... };
    byte ciphertext[CIPHER_TEXT_SIZE] = { ... };
    byte plaintext[PLAIN_TEXT_SIZE];
    byte tag[ASCON_AEAD128_TAG_SZ] = { ... };

    if (wc_AsconAeadInit(&a) != 0)
        // handle error
    if (wc_AsconAEAD128_SetKey(&a, key) != 0)
        // handle error
    if (wc_AsconAEAD128_SetNonce(&a, nonce) != 0)
        // handle error
    if (wc_AsconAEAD128_SetAD(&a, ad, sizeof(ad)) != 0)
        // handle error
    if (wc_AsconAEAD128_DecryptUpdate(&a, plaintext, ciphertext,
                                      sizeof(ciphertext)) != 0)
        // handle error
    if (wc_AsconAEAD128_DecryptFinal(&a, tag) != 0)
        // handle error
    \endcode

    \sa wc_AsconAEAD128_Init
    \sa wc_AsconAEAD128_SetKey
    \sa wc_AsconAEAD128_SetNonce
    \sa wc_AsconAEAD128_SetAD
    \sa wc_AsconAEAD128_DecryptUpdate
    \sa wc_AsconAEAD128_EncryptUpdate
    \sa wc_AsconAEAD128_EncryptFinal
    */
int wc_AsconAEAD128_DecryptFinal(wc_AsconAEAD128* a, const byte* tag);


