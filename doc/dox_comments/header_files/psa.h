/*!
    \ingroup PSA
    \brief This function enables PSA support on the given context.

    \param ctx pointer to the WOLFSSL_CTX object on which the PSA support must be enabled
    \return WOLFSSL_SUCCESS on success
    \return BAD_FUNC_ARG if ctx == NULL

    _Example_
    \code
    WOLFSSL_CTX *ctx;
    ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (!ctx)
        return NULL;
    ret = wolfSSL_CTX_psa_enable(ctx);
    if (ret != WOLFSSL_SUCCESS)
        printf("can't enable PSA on ctx");

    \endcode

    \sa wolfSSL_set_psa_ctx
*/
int wolfSSL_CTX_psa_enable(WOLFSSL_CTX *ctx);

/*!
    \ingroup PSA

    \brief This function setup the PSA context for the given SSL session

    \param ssl pointer to the WOLFSSL where the ctx will be enabled
    \param ctx pointer to a struct psa_ssl_ctx (must be unique for a ssl session)

    \return WOLFSSL_SUCCESS on success
    \return BAD_FUNC_ARG if ssl or ctx are NULL

    This function setup the PSA context for the TLS callbacks to the given SSL
    session. At the end of the session, the resources used by the context
    should be freed using wolfSSL_free_psa_ctx().

    _Example_
    \code
    // Create new ssl session
    WOLFSSL *ssl;
    struct psa_ssl_ctx psa_ctx = { 0 };
    ssl = wolfSSL_new(ctx);
    if (!ssl)
        return NULL;
    // setup PSA context
    ret = wolfSSL_set_psa_ctx(ssl, ctx);
    \endcode

    \sa wolfSSL_psa_set_private_key_id
    \sa wolfSSL_psa_free_psa_ctx
*/
int wolfSSL_set_psa_ctx(WOLFSSL *ssl, struct psa_ssl_ctx *ctx);

/*!
    \ingroup PSA
    \brief This function releases the resources used by a PSA context

    \param ctx pointer to a struct psa_ssl_ctx

    \sa wolfSSL_set_psa_ctx
*/
void wolfSSL_free_psa_ctx(struct psa_ssl_ctx *ctx);

/*!
    \ingroup PSA
    \brief This function set the private key used by an SSL session

    \param ctx pointer to a struct psa_ssl_ctx
    \param id PSA id of the key to be used as private key

    _Example_
    \code
    // Create new ssl session
    WOLFSSL *ssl;
    struct psa_ssl_ctx psa_ctx = { 0 };
    psa_key_id_t key_id;

    // key provisioning already done
    get_private_key_id(&key_id);

    ssl = wolfSSL_new(ctx);
    if (!ssl)
        return NULL;

    wolfSSL_psa_set_private_key_id(&psa_ctx, key_id);
    wolfSSL_set_psa_ctx(ssl, ctx);
    \endcode

    \sa wolfSSL_set_psa_ctx
*/

int wolfSSL_psa_set_private_key_id(struct psa_ssl_ctx *ctx,
                                               psa_key_id_t id);

/*!
    \ingroup PSA
    \brief This function generates random bytes using the PSA crypto API.
    This is a wrapper around the PSA random number generation functions.

    \return 0 On success
    \return Negative value on error

    \param out pointer to buffer to store random bytes
    \param sz number of random bytes to generate

    _Example_
    \code
    byte random[32];

    int ret = wc_psa_get_random(random, sizeof(random));
    if (ret != 0) {
        // error generating random bytes
    }
    \endcode

    \sa wc_RNG_GenerateBlock
*/
int wc_psa_get_random(unsigned char *out, word32 sz);

/*!
    \ingroup PSA
    \brief This function performs AES encryption or decryption using the
    PSA crypto API. It supports various AES modes through the algorithm
    parameter.

    \return 0 On success
    \return Negative value on error

    \param aes pointer to initialized Aes structure
    \param input pointer to input data buffer
    \param output pointer to output data buffer
    \param length length of data to process
    \param alg PSA algorithm identifier specifying the AES mode
    \param direction encryption (1) or decryption (0)

    _Example_
    \code
    Aes aes;
    byte key[16] = { }; // AES key
    byte input[16] = { }; // plaintext
    byte output[16];

    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesSetKey(&aes, key, sizeof(key), NULL, AES_ENCRYPTION);
    int ret = wc_psa_aes_encrypt_decrypt(&aes, input, output,
                                         sizeof(input),
                                         PSA_ALG_ECB_NO_PADDING, 1);
    \endcode

    \sa wc_AesEncrypt
    \sa wc_AesDecrypt
*/
int wc_psa_aes_encrypt_decrypt(Aes *aes, const uint8_t *input,
                               uint8_t *output, size_t length,
                               psa_algorithm_t alg, int direction);

/*!
    \ingroup AES
    \brief This function encrypts a single AES block. It performs
    encryption on exactly one block (16 bytes) of data.

    \return 0 On success
    \return Negative value on error

    \param aes pointer to initialized Aes structure
    \param inBlock pointer to 16-byte input block
    \param outBlock pointer to 16-byte output block

    _Example_
    \code
    Aes aes;
    byte key[16] = { }; // AES key
    byte inBlock[AES_BLOCK_SIZE] = { }; // plaintext block
    byte outBlock[AES_BLOCK_SIZE];

    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesSetKey(&aes, key, sizeof(key), NULL, AES_ENCRYPTION);
    int ret = wc_AesEncrypt(&aes, inBlock, outBlock);
    if (ret != 0) {
        // encryption error
    }
    \endcode

    \sa wc_AesDecrypt
    \sa wc_AesSetKey
*/
int wc_AesEncrypt(Aes *aes, const byte *inBlock, byte *outBlock);

/*!
    \ingroup AES
    \brief This function decrypts a single AES block. It performs
    decryption on exactly one block (16 bytes) of data.

    \return 0 On success
    \return Negative value on error

    \param aes pointer to initialized Aes structure
    \param inBlock pointer to 16-byte input block (ciphertext)
    \param outBlock pointer to 16-byte output block (plaintext)

    _Example_
    \code
    Aes aes;
    byte key[16] = { }; // AES key
    byte inBlock[AES_BLOCK_SIZE] = { }; // ciphertext block
    byte outBlock[AES_BLOCK_SIZE];

    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesSetKey(&aes, key, sizeof(key), NULL, AES_DECRYPTION);
    int ret = wc_AesDecrypt(&aes, inBlock, outBlock);
    if (ret != 0) {
        // decryption error
    }
    \endcode

    \sa wc_AesEncrypt
    \sa wc_AesSetKey
*/
int wc_AesDecrypt(Aes *aes, const byte *inBlock, byte *outBlock);
