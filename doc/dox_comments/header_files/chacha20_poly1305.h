/*!
    \ingroup ChaCha20Poly1305

    \brief This function encrypts an input message, inPlaintext, using the
    ChaCha20 stream cipher, into the output buffer, outCiphertext. It
    also performs Poly-1305 authentication (on the cipher text), and
    stores the generated authentication tag in the output buffer, outAuthTag.

    \return 0 Returned upon successfully encrypting the message
    \return BAD_FUNC_ARG returned if there is an error during the encryption
    process

    \param inKey pointer to a buffer containing the 32 byte key to use
    for encryption
    \param inIv pointer to a buffer containing the 12 byte iv to use for
    encryption
    \param inAAD pointer to the buffer containing arbitrary length additional
    authenticated data (AAD)
    \param inAADLen length of the input AAD
    \param inPlaintext pointer to the buffer containing the plaintext to
    encrypt
    \param inPlaintextLen the length of the plain text to  encrypt
    \param outCiphertext pointer to the buffer in which to store the ciphertext
    \param outAuthTag pointer to a 16 byte wide buffer in which to store the
    authentication tag

    _Example_
    \code
    byte key[] = { // initialize 32 byte key };
    byte iv[]  = { // initialize 12 byte key };
    byte inAAD[] = { // initialize AAD };

    byte plain[] = { // initialize message to encrypt };
    byte cipher[sizeof(plain)];
    byte authTag[16];

    int ret = wc_ChaCha20Poly1305_Encrypt(key, iv, inAAD, sizeof(inAAD),
    plain, sizeof(plain), cipher, authTag);

    if(ret != 0) {
    	// error running encrypt
    }
    \endcode

    \sa wc_ChaCha20Poly1305_Decrypt
    \sa wc_ChaCha_*
    \sa wc_Poly1305*
*/

int wc_ChaCha20Poly1305_Encrypt(
                const byte inKey[CHACHA20_POLY1305_AEAD_KEYSIZE],
                const byte inIV[CHACHA20_POLY1305_AEAD_IV_SIZE],
                const byte* inAAD, word32 inAADLen,
                const byte* inPlaintext, word32 inPlaintextLen,
                byte* outCiphertext,
                byte outAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE]);

/*!
    \ingroup ChaCha20Poly1305

    \brief This function decrypts input ciphertext, inCiphertext, using the
    ChaCha20 stream cipher, into the output buffer, outPlaintext. It also
    performs Poly-1305 authentication, comparing the given inAuthTag to an
    authentication generated with the inAAD (arbitrary length additional
    authentication data).  If a nonzero error code is returned, the output
    data, outPlaintext, is undefined.  However, callers must unconditionally
    zeroize the output buffer to guard against leakage of cleartext data.

    \return 0 Returned upon successfully decrypting and authenticating the
    message
    \return BAD_FUNC_ARG Returned if any of the function arguments do not
    match what is expected
    \return MAC_CMP_FAILED_E Returned if the generated authentication tag
    does not match the supplied inAuthTag.
    \return MEMORY_E Returned if internal buffer allocation failed.
    \return CHACHA_POLY_OVERFLOW Can be returned if input is corrupted.

    \param inKey pointer to a buffer containing the 32 byte key to use for
    decryption
    \param inIv pointer to a buffer containing the 12 byte iv to use for
    decryption
    \param inAAD pointer to the buffer containing arbitrary length additional
    authenticated data (AAD)
    \param inAADLen length of the input AAD
    \param inCiphertext pointer to the buffer containing the ciphertext to
    decrypt
    \param outCiphertextLen the length of the ciphertext to decrypt
    \param inAuthTag pointer to the buffer containing the 16 byte digest
    for authentication
    \param outPlaintext pointer to the buffer in which to store the plaintext

    _Example_
    \code
    byte key[]   = { // initialize 32 byte key };
    byte iv[]    = { // initialize 12 byte key };
    byte inAAD[] = { // initialize AAD };

    byte cipher[]    = { // initialize with received ciphertext };
    byte authTag[16] = { // initialize with received authentication tag };

    byte plain[sizeof(cipher)];

    int ret = wc_ChaCha20Poly1305_Decrypt(key, iv, inAAD, sizeof(inAAD),
    cipher, sizeof(cipher), authTag, plain);

    if(ret == MAC_CMP_FAILED_E) {
    	// error during authentication
    } else if( ret != 0) {
    	// error with function arguments
    }
    \endcode

    \sa wc_ChaCha20Poly1305_Encrypt
    \sa wc_ChaCha_*
    \sa wc_Poly1305*
*/

int wc_ChaCha20Poly1305_Decrypt(
                const byte inKey[CHACHA20_POLY1305_AEAD_KEYSIZE],
                const byte inIV[CHACHA20_POLY1305_AEAD_IV_SIZE],
                const byte* inAAD, word32 inAADLen,
                const byte* inCiphertext, word32 inCiphertextLen,
                const byte inAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE],
                byte* outPlaintext);

/*!
    \ingroup ChaCha20Poly1305
    \brief Compares two authentication tags in constant time to prevent
    timing attacks.

    \return 0 If tags match
    \return MAC_CMP_FAILED_E If tags do not match

    \param authTag First authentication tag
    \param authTagChk Second authentication tag to compare

    _Example_
    \code
    byte tag1[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    byte tag2[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];

    int ret = wc_ChaCha20Poly1305_CheckTag(tag1, tag2);
    if (ret != 0) {
        // tags do not match
    }
    \endcode

    \sa wc_ChaCha20Poly1305_Decrypt
*/
int wc_ChaCha20Poly1305_CheckTag(
                const byte authTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE],
                const byte authTagChk[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE]);

/*!
    \ingroup ChaCha20Poly1305
    \brief Initializes a ChaChaPoly_Aead structure for incremental
    encryption or decryption operations.

    \return 0 On success
    \return BAD_FUNC_ARG If parameters are invalid

    \param aead Pointer to ChaChaPoly_Aead structure to initialize
    \param inKey 32-byte encryption key
    \param inIV 12-byte initialization vector
    \param isEncrypt 1 for encryption, 0 for decryption

    _Example_
    \code
    ChaChaPoly_Aead aead;
    byte key[CHACHA20_POLY1305_AEAD_KEYSIZE];
    byte iv[CHACHA20_POLY1305_AEAD_IV_SIZE];

    int ret = wc_ChaCha20Poly1305_Init(&aead, key, iv, 1);
    if (ret != 0) {
        // error initializing
    }
    \endcode

    \sa wc_ChaCha20Poly1305_UpdateAad
    \sa wc_ChaCha20Poly1305_UpdateData
    \sa wc_ChaCha20Poly1305_Final
*/
int wc_ChaCha20Poly1305_Init(ChaChaPoly_Aead* aead,
                const byte inKey[CHACHA20_POLY1305_AEAD_KEYSIZE],
                const byte inIV[CHACHA20_POLY1305_AEAD_IV_SIZE],
                int isEncrypt);

/*!
    \ingroup ChaCha20Poly1305
    \brief Updates the AEAD context with additional authenticated data
    (AAD). Must be called after Init and before UpdateData.

    \return 0 On success
    \return BAD_FUNC_ARG If parameters are invalid

    \param aead Pointer to initialized ChaChaPoly_Aead structure
    \param inAAD Additional authenticated data
    \param inAADLen Length of AAD in bytes

    _Example_
    \code
    ChaChaPoly_Aead aead;
    byte aad[]; // AAD data

    wc_ChaCha20Poly1305_Init(&aead, key, iv, 1);
    int ret = wc_ChaCha20Poly1305_UpdateAad(&aead, aad, sizeof(aad));
    if (ret != 0) {
        // error updating AAD
    }
    \endcode

    \sa wc_ChaCha20Poly1305_Init
    \sa wc_ChaCha20Poly1305_UpdateData
*/
int wc_ChaCha20Poly1305_UpdateAad(ChaChaPoly_Aead* aead,
                const byte* inAAD, word32 inAADLen);

/*!
    \ingroup ChaCha20Poly1305
    \brief Encrypts or decrypts data incrementally. Can be called
    multiple times to process data in chunks.

    \return 0 On success
    \return BAD_FUNC_ARG If parameters are invalid

    \param aead Pointer to initialized ChaChaPoly_Aead structure
    \param inData Input data (plaintext or ciphertext)
    \param outData Output buffer for result
    \param dataLen Length of data to process

    _Example_
    \code
    ChaChaPoly_Aead aead;
    byte plain[]; // plaintext
    byte cipher[sizeof(plain)];

    wc_ChaCha20Poly1305_Init(&aead, key, iv, 1);
    wc_ChaCha20Poly1305_UpdateAad(&aead, aad, aadLen);
    int ret = wc_ChaCha20Poly1305_UpdateData(&aead, plain,
                                             cipher, sizeof(plain));
    \endcode

    \sa wc_ChaCha20Poly1305_Init
    \sa wc_ChaCha20Poly1305_Final
*/
int wc_ChaCha20Poly1305_UpdateData(ChaChaPoly_Aead* aead,
                const byte* inData, byte* outData, word32 dataLen);

/*!
    \ingroup ChaCha20Poly1305
    \brief Finalizes the AEAD operation and generates the
    authentication tag.

    \return 0 On success
    \return BAD_FUNC_ARG If parameters are invalid

    \param aead Pointer to ChaChaPoly_Aead structure
    \param outAuthTag Buffer to store 16-byte authentication tag

    _Example_
    \code
    ChaChaPoly_Aead aead;
    byte authTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];

    wc_ChaCha20Poly1305_Init(&aead, key, iv, 1);
    wc_ChaCha20Poly1305_UpdateAad(&aead, aad, aadLen);
    wc_ChaCha20Poly1305_UpdateData(&aead, plain, cipher, plainLen);
    int ret = wc_ChaCha20Poly1305_Final(&aead, authTag);
    \endcode

    \sa wc_ChaCha20Poly1305_Init
    \sa wc_ChaCha20Poly1305_UpdateData
*/
int wc_ChaCha20Poly1305_Final(ChaChaPoly_Aead* aead,
                byte outAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE]);

/*!
    \ingroup ChaCha20Poly1305
    \brief Initializes XChaCha20-Poly1305 AEAD with extended nonce.
    XChaCha20 uses a 24-byte nonce instead of 12-byte.

    \return 0 On success
    \return BAD_FUNC_ARG If parameters are invalid

    \param aead Pointer to ChaChaPoly_Aead structure
    \param ad Additional authenticated data
    \param ad_len Length of AAD
    \param inKey Encryption key
    \param inKeySz Key size (must be 32)
    \param inIV Initialization vector
    \param inIVSz IV size (must be 24 for XChaCha20)
    \param isEncrypt 1 for encryption, 0 for decryption

    _Example_
    \code
    ChaChaPoly_Aead aead;
    byte key[32];
    byte iv[24];
    byte aad[]; // AAD

    int ret = wc_XChaCha20Poly1305_Init(&aead, aad, sizeof(aad),
                                        key, 32, iv, 24, 1);
    \endcode

    \sa wc_XChaCha20Poly1305_Encrypt
    \sa wc_XChaCha20Poly1305_Decrypt
*/
int wc_XChaCha20Poly1305_Init(ChaChaPoly_Aead* aead,
                const byte *ad, word32 ad_len,
                const byte *inKey, word32 inKeySz,
                const byte *inIV, word32 inIVSz,
                int isEncrypt);

/*!
    \ingroup ChaCha20Poly1305
    \brief One-shot XChaCha20-Poly1305 encryption with 24-byte nonce.

    \return 0 On success
    \return BAD_FUNC_ARG If parameters are invalid
    \return BUFFER_E If dst_space is insufficient

    \param dst Output buffer for ciphertext and tag
    \param dst_space Size of output buffer
    \param src Input plaintext
    \param src_len Length of plaintext
    \param ad Additional authenticated data
    \param ad_len Length of AAD
    \param nonce 24-byte nonce
    \param nonce_len Nonce length (must be 24)
    \param key 32-byte encryption key
    \param key_len Key length (must be 32)

    _Example_
    \code
    byte key[32], nonce[24];
    byte plain[]; // plaintext
    byte cipher[sizeof(plain) + 16];

    int ret = wc_XChaCha20Poly1305_Encrypt(cipher, sizeof(cipher),
                                           plain, sizeof(plain),
                                           NULL, 0, nonce, 24,
                                           key, 32);
    \endcode

    \sa wc_XChaCha20Poly1305_Decrypt
*/
int wc_XChaCha20Poly1305_Encrypt(byte *dst, size_t dst_space,
                const byte *src, size_t src_len,
                const byte *ad, size_t ad_len,
                const byte *nonce, size_t nonce_len,
                const byte *key, size_t key_len);

/*!
    \ingroup ChaCha20Poly1305
    \brief One-shot XChaCha20-Poly1305 decryption with 24-byte nonce.

    \return 0 On success
    \return BAD_FUNC_ARG If parameters are invalid
    \return BUFFER_E If dst_space is insufficient
    \return MAC_CMP_FAILED_E If authentication fails

    \param dst Output buffer for plaintext
    \param dst_space Size of output buffer
    \param src Input ciphertext with tag
    \param src_len Length of ciphertext plus tag
    \param ad Additional authenticated data
    \param ad_len Length of AAD
    \param nonce 24-byte nonce
    \param nonce_len Nonce length (must be 24)
    \param key 32-byte decryption key
    \param key_len Key length (must be 32)

    _Example_
    \code
    byte key[32], nonce[24];
    byte cipher[]; // ciphertext + tag
    byte plain[sizeof(cipher) - 16];

    int ret = wc_XChaCha20Poly1305_Decrypt(plain, sizeof(plain),
                                           cipher, sizeof(cipher),
                                           NULL, 0, nonce, 24,
                                           key, 32);
    if (ret == MAC_CMP_FAILED_E) {
        // authentication failed
    }
    \endcode

    \sa wc_XChaCha20Poly1305_Encrypt
*/
int wc_XChaCha20Poly1305_Decrypt(byte *dst, size_t dst_space,
                const byte *src, size_t src_len,
                const byte *ad, size_t ad_len,
                const byte *nonce, size_t nonce_len,
                const byte *key, size_t key_len);
