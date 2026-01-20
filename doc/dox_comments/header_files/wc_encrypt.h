/*!
    \ingroup AES
    \brief Decrypts a cipher from the input buffer in, and places the
    resulting plain text in the output buffer out using cipher block
    chaining with AES. This function does not require an AES structure
    to be initialized. Instead, it takes in a key and an iv
    (initialization vector) and uses these to initialize an
    AES object and then decrypt the cipher text.

    \return 0 On successfully decrypting message
    \return BAD_ALIGN_E Returned on block align error
    \return BAD_FUNC_ARG Returned if key length is invalid or AES object
    is null during AesSetIV
    \return MEMORY_E Returned if WOLFSSL_SMALL_STACK is enabled and
    XMALLOC fails to instantiate an AES object.

    \param out pointer to the output buffer in which to store the plain
    text of the decrypted message
    \param in pointer to the input buffer containing cipher text to be
    decrypted
    \param inSz size of input message
    \param key 16, 24, or 32 byte secret key for decryption
    \param keySz size of key used for decryption

    _Example_
    \code
    int ret = 0;
    byte key[] = { some 16, 24, or 32 byte key };
    byte iv[]  = { some 16 byte iv };
    byte cipher[AES_BLOCK_SIZE * n]; //n being a positive integer making
    cipher some multiple of 16 bytes
    // fill cipher with cipher text
    byte plain [AES_BLOCK_SIZE * n];
    if ((ret = wc_AesCbcDecryptWithKey(plain, cipher, AES_BLOCK_SIZE, key,
    AES_BLOCK_SIZE, iv)) != 0 ) {
	// Decrypt Error
    }
    \endcode

    \sa wc_AesSetKey
    \sa wc_AesSetIV
    \sa wc_AesCbcEncrypt
    \sa wc_AesCbcDecrypt
*/
int  wc_AesCbcDecryptWithKey(byte* out, const byte* in, word32 inSz,
                                         const byte* key, word32 keySz,
                                         const byte* iv);

/*!
    \ingroup 3DES

    \brief This function decrypts the input ciphertext, in, and stores the
    resulting plaintext in the output buffer, out. It uses DES encryption
    with cipher block chaining (CBC) mode. This function is a substitute
    for wc_Des_CbcDecrypt, allowing the user to decrypt a message without
    directly instantiating a Des structure.

    \return 0 Returned upon successfully decrypting the given ciphertext
    \return MEMORY_E Returned if there is an error allocating space for a
    Des structure

    \param out pointer to the buffer in which to store the decrypted plaintext
    \param in pointer to the input buffer containing the encrypted ciphertext
    \param sz length of the ciphertext to decrypt
    \param key pointer to the buffer containing the 8 byte key to use for
    decryption
    \param iv pointer to the buffer containing the 8 byte iv to use for
    decryption. If no iv is provided, the iv defaults to 0

    _Example_
    \code
    int ret;
    byte key[] = { // initialize with 8 byte key };
    byte iv[]  = { // initialize with 8 byte iv };

    byte cipher[]  = { // initialize with ciphertext };
    byte decoded[sizeof(cipher)];

    if ( wc_Des_CbcDecryptWithKey(decoded, cipher, sizeof(cipher), key,
    iv) != 0) {
    	// error decrypting message
    }
    \endcode

    \sa wc_Des_CbcDecrypt
*/
int  wc_Des_CbcDecryptWithKey(byte* out,
                                          const byte* in, word32 sz,
                                          const byte* key, const byte* iv);

/*!
    \ingroup 3DES

    \brief This function encrypts the input plaintext, in, and stores the
    resulting ciphertext in the output buffer, out. It uses DES encryption
    with cipher block chaining (CBC) mode. This function is a substitute
    for wc_Des_CbcEncrypt, allowing the user to encrypt a message without
    directly instantiating a Des structure.

    \return 0 Returned after successfully encrypting data.
    \return MEMORY_E Returned if there's an error allocating memory for a
    Des structure.
    \return <0 Returned on any error during encryption.

    \param out Final encrypted data
    \param in Data to be encrypted, must be padded to Des block size.
    \param sz Size of input buffer.
    \param key Pointer to the key to use for encryption.
    \param iv Initialization vector

    _Example_
    \code
    byte key[] = { // initialize with 8 byte key };
    byte iv[]  = { // initialize with 8 byte iv };
    byte in[] = { // Initialize with plaintext };
    byte out[sizeof(in)];
    if ( wc_Des_CbcEncryptWithKey(&out, in, sizeof(in), key, iv) != 0)
    {
    	// error encrypting message
    }
    \endcode

    \sa wc_Des_CbcDecryptWithKey
    \sa wc_Des_CbcEncrypt
*/
int  wc_Des_CbcEncryptWithKey(byte* out,
                                          const byte* in, word32 sz,
                                          const byte* key, const byte* iv);

/*!
    \ingroup 3DES

    \brief This function encrypts the input plaintext, in, and stores
    the resulting ciphertext in the output buffer, out. It uses Triple
    DES (3DES) encryption with cipher block chaining (CBC) mode. This
    function is a substitute for wc_Des3_CbcEncrypt, allowing the user
    to encrypt a message without directly instantiating a Des3 structure.

    \return 0 Returned after successfully encrypting data.
    \return MEMORY_E Returned if there's an error allocating memory for
    a Des structure.
    \return <0 Returned on any error during encryption.

    \param out Final encrypted data
    \param in Data to be encrypted, must be padded to Des block size.
    \param sz Size of input buffer.
    \param key Pointer to the key to use for encryption.
    \param iv Initialization vector

    _Example_
    \code
    byte key[] = { // initialize with 8 byte key };
    byte iv[]  = { // initialize with 8 byte iv };

    byte in[] = { // Initialize with plaintext };
    byte out[sizeof(in)];

    if ( wc_Des3_CbcEncryptWithKey(&out, in, sizeof(in), key, iv) != 0)
    {
    	// error encrypting message
    }
    \endcode

    \sa wc_Des3_CbcDecryptWithKey
    \sa wc_Des_CbcEncryptWithKey
    \sa wc_Des_CbcDecryptWithKey
*/
int  wc_Des3_CbcEncryptWithKey(byte* out,
                                           const byte* in, word32 sz,
                                           const byte* key, const byte* iv);

/*!
    \ingroup 3DES

    \brief This function decrypts the input ciphertext, in, and stores
    the resulting plaintext in the output buffer, out. It uses Triple
    Des (3DES) encryption with cipher block chaining (CBC) mode. This
    function is a substitute for wc_Des3_CbcDecrypt, allowing the user
    to decrypt a message without directly instantiating a Des3 structure.

    \return 0 Returned upon successfully decrypting the given ciphertext
    \return MEMORY_E Returned if there is an error allocating space for
    a Des structure

    \param out pointer to the buffer in which to store the decrypted plaintext
    \param in pointer to the input buffer containing the encrypted ciphertext
    \param sz length of the ciphertext to decrypt
    \param key pointer to the buffer containing the 24 byte key to use
    for decryption
    \param iv pointer to the buffer containing the 8 byte iv to use for
    decryption. If no iv is provided, the iv defaults to 0

    _Example_
    \code
    int ret;
    byte key[] = { // initialize with 24 byte key };
    byte iv[]  = { // initialize with 8 byte iv };

    byte cipher[]  = { // initialize with ciphertext };
    byte decoded[sizeof(cipher)];

    if ( wc_Des3_CbcDecryptWithKey(decoded, cipher, sizeof(cipher),
    key, iv) != 0) {
    	// error decrypting message
    }
    \endcode

    \sa wc_Des3_CbcDecrypt
*/
int  wc_Des3_CbcDecryptWithKey(byte* out,
                                           const byte* in, word32 sz,
                                           const byte* key, const byte* iv);

/*!
    \ingroup AES
    \brief This function encrypts a plaintext message and stores the
    result in the output buffer. It uses AES encryption with cipher
    block chaining (CBC) mode. This function does not require an AES
    structure to be initialized. Instead, it takes in a key and an iv
    and uses these to encrypt the message.

    \return 0 On successfully encrypting the message
    \return BAD_ALIGN_E Returned on block align error
    \return BAD_FUNC_ARG Returned if key length is invalid
    \return MEMORY_E Returned if WOLFSSL_SMALL_STACK is enabled and
    XMALLOC fails to instantiate an AES object

    \param out pointer to the output buffer in which to store the
    ciphertext of the encrypted message
    \param in pointer to the input buffer containing plaintext to
    encrypt
    \param inSz size of input message
    \param key 16, 24, or 32 byte secret key for encryption
    \param keySz size of key used for encryption
    \param iv pointer to the 16 byte initialization vector to use

    _Example_
    \code
    byte key[]; // 16, 24, or 32 byte key
    byte iv[]; // 16 byte iv
    byte plain[]; // plaintext to encrypt
    byte cipher[sizeof(plain)];

    int ret = wc_AesCbcEncryptWithKey(cipher, plain, sizeof(plain),
                                      key, sizeof(key), iv);
    if (ret != 0) {
        // encryption error
    }
    \endcode

    \sa wc_AesCbcDecryptWithKey
    \sa wc_AesSetKey
    \sa wc_AesCbcEncrypt
*/
int wc_AesCbcEncryptWithKey(byte* out, const byte* in, word32 inSz,
                            const byte* key, word32 keySz,
                            const byte* iv);

/*!
    \ingroup Crypto
    \brief This function decrypts an encrypted key buffer using the
    provided password. It supports various encryption algorithms
    including DES, 3DES, and AES. The encryption information is
    provided in the EncryptedInfo structure.

    \return Length of decrypted key on success
    \return Negative value on error

    \param info pointer to EncryptedInfo structure containing encryption
    algorithm and parameters
    \param der pointer to the encrypted key buffer
    \param derSz size of the encrypted key buffer
    \param password pointer to the password buffer
    \param passwordSz size of the password
    \param hashType hash algorithm to use for key derivation

    _Example_
    \code
    EncryptedInfo info;
    byte encryptedKey[]; // encrypted key data
    byte password[] = "mypassword";

    int ret = wc_BufferKeyDecrypt(&info, encryptedKey,
                                  sizeof(encryptedKey), password,
                                  sizeof(password)-1, WC_SHA256);
    if (ret < 0) {
        // decryption error
    }
    \endcode

    \sa wc_BufferKeyEncrypt
*/
int wc_BufferKeyDecrypt(struct EncryptedInfo* info, byte* der,
                        word32 derSz, const byte* password,
                        int passwordSz, int hashType);

/*!
    \ingroup Crypto
    \brief This function encrypts a key buffer using the provided
    password. It supports various encryption algorithms including DES,
    3DES, and AES. The encryption information is provided in the
    EncryptedInfo structure.

    \return Length of encrypted key on success
    \return Negative value on error

    \param info pointer to EncryptedInfo structure containing encryption
    algorithm and parameters
    \param der pointer to the key buffer to encrypt
    \param derSz size of the key buffer
    \param password pointer to the password buffer
    \param passwordSz size of the password
    \param hashType hash algorithm to use for key derivation

    _Example_
    \code
    EncryptedInfo info;
    byte key[]; // key data to encrypt
    byte password[] = "mypassword";

    info.algo = AES256CBCb;
    int ret = wc_BufferKeyEncrypt(&info, key, sizeof(key), password,
                                  sizeof(password)-1, WC_SHA256);
    if (ret < 0) {
        // encryption error
    }
    \endcode

    \sa wc_BufferKeyDecrypt
*/
int wc_BufferKeyEncrypt(struct EncryptedInfo* info, byte* der,
                        word32 derSz, const byte* password,
                        int passwordSz, int hashType);
