/*!
    \ingroup AES
    \brief This function initializes an AES structure by setting the key and
    then setting the initialization vector.

    \return 0 On successfully setting key and initialization vector.
    \return BAD_FUNC_ARG Returned if key length is invalid.

    \param aes pointer to the AES structure to modify
    \param key 16, 24, or 32 byte secret key for encryption and decryption
    \param len length of the key passed in
    \param iv pointer to the initialization vector used to initialize the key
    \param dir Cipher direction. Set AES_ENCRYPTION to encrypt,  or
    AES_DECRYPTION to decrypt. Direction for some modes (CFB and CTR) is
    always AES_ENCRYPTION.

    _Example_
    \code
    Aes enc;
    int ret = 0;
    byte key[] = { some 16, 24 or 32 byte key };
    byte iv[]  = { some 16 byte iv };
    if (ret = wc_AesInit(&enc, HEAP_HINT, INVALID_DEVID) != 0) {
        // failed to initialize aes key
    }
    if (ret = wc_AesSetKey(&enc, key, AES_BLOCK_SIZE, iv,
    AES_ENCRYPTION) != 0) {
	// failed to set aes key
    }
    \endcode

    \sa wc_AesSetKeyDirect
    \sa wc_AesSetIV
*/
int  wc_AesSetKey(Aes* aes, const byte* key, word32 len,
                              const byte* iv, int dir);

/*!
    \ingroup AES
    \brief This function sets the initialization vector for a
    particular AES object. The AES object should be initialized before
    calling this function.

    \return 0 On successfully setting initialization vector.
    \return BAD_FUNC_ARG Returned if AES pointer is NULL.

    \param aes pointer to the AES structure on which to set the
    initialization vector
    \param iv initialization vector used to initialize the AES structure.
    If the value is NULL, the default action initializes the iv to 0.

    _Example_
    \code
    Aes enc;
    // set enc key
    byte iv[]  = { some 16 byte iv };
    if (ret = wc_AesSetIV(&enc, iv) != 0) {
	// failed to set aes iv
    }
    \endcode

    \sa wc_AesSetKeyDirect
    \sa wc_AesSetKey
*/
int  wc_AesSetIV(Aes* aes, const byte* iv);

/*!
    \ingroup AES
    \brief Encrypts a plaintext message from the input buffer in, and places
    the resulting cipher text in the output buffer out using cipher block
    chaining with AES. This function requires that the AES object has been
    initialized by calling AesSetKey before a message is able to be encrypted.
    This function assumes that the input message is AES block length aligned,
    and expects the input length to be a multiple of the block length, which
    will optionally be checked and enforced if WOLFSSL_AES_CBC_LENGTH_CHECKS
    is defined in the build configuration.  In order to assure block-multiple
    input, PKCS#7 style padding should be added beforehand. This differs from
    the OpenSSL AES-CBC methods which add the padding for you. To make the
    wolfSSL and corresponding OpenSSL functions interoperate, one should specify
    the -nopad option in the OpenSSL command line function so that it behaves
    like the wolfSSL AesCbcEncrypt method and does not add extra padding
    during encryption.

    \return 0 On successfully encrypting message.
    \return BAD_ALIGN_E: may be returned on block align error
    \return BAD_LENGTH_E will be returned if the input length isn't a
    multiple of the AES block length, when the library is built with
    WOLFSSL_AES_CBC_LENGTH_CHECKS.

    \param aes pointer to the AES object used to encrypt data
    \param out pointer to the output buffer in which to store the ciphertext
    of the encrypted message
    \param in pointer to the input buffer containing message to be encrypted
    \param sz size of input message

    _Example_
    \code
    Aes enc;
    int ret = 0;
    // initialize enc with wc_AesInit and wc_AesSetKey, using direction
    // AES_ENCRYPTION
    byte msg[AES_BLOCK_SIZE * n]; // multiple of 16 bytes
    // fill msg with data
    byte cipher[AES_BLOCK_SIZE * n]; // Some multiple of 16 bytes
    if ((ret = wc_AesCbcEncrypt(&enc, cipher, message, sizeof(msg))) != 0 ) {
	// block align error
    }
    \endcode

    \sa wc_AesInit
    \sa wc_AesSetKey
    \sa wc_AesSetIV
    \sa wc_AesCbcDecrypt
*/
int  wc_AesCbcEncrypt(Aes* aes, byte* out,
                                  const byte* in, word32 sz);

/*!
    \ingroup AES
    \brief Decrypts a cipher from the input buffer in, and places the
    resulting plain text in the output buffer out using cipher block chaining
    with AES. This function requires that the AES structure has been
    initialized by calling AesSetKey before a message is able to be decrypted.
    This function assumes that the original message was AES block length
    aligned, and expects the input length to be a multiple of the block length,
    which will optionally be checked and enforced if
    WOLFSSL_AES_CBC_LENGTH_CHECKS is defined in the build configuration.
    This differs from the OpenSSL AES-CBC methods, which add PKCS#7 padding
    automatically, and so do not require block-multiple input. To make the
    wolfSSL function and equivalent OpenSSL functions interoperate, one
    should specify the -nopad option in the OpenSSL command line function
    so that it behaves like the wolfSSL AesCbcEncrypt method and does not
    create errors during decryption.

    \return 0 On successfully decrypting message.
    \return BAD_ALIGN_E may be returned on block align error.
    \return BAD_LENGTH_E will be returned if the input length isn't a
    multiple of the AES block length, when the library is built with
    WOLFSSL_AES_CBC_LENGTH_CHECKS.

    \param aes pointer to the AES object used to decrypt data.
    \param out pointer to the output buffer in which to store the plain text
    of the decrypted message.
    size must be a multiple of AES_BLOCK_LENGTH, padded if necessary
    \param in pointer to the input buffer containing cipher text to be
    decrypted.
    size must be a multiple of AES_BLOCK_LENGTH, padded if necessary
    \param sz size of input message.

    _Example_
    \code
    Aes dec;
    int ret = 0;
    // initialize dec with wc_AesInit and wc_AesSetKey, using direction
    // AES_DECRYPTION
    byte cipher[AES_BLOCK_SIZE * n]; // some multiple of 16 bytes
    // fill cipher with cipher text
    byte plain [AES_BLOCK_SIZE * n];
    if ((ret = wc_AesCbcDecrypt(&dec, plain, cipher, sizeof(cipher))) != 0 ) {
	// block align error
    }
    \endcode

    \sa wc_AesInit
    \sa wc_AesSetKey
    \sa wc_AesCbcEncrypt
*/
int  wc_AesCbcDecrypt(Aes* aes, byte* out,
                                  const byte* in, word32 sz);

/*!
    \ingroup AES
    \brief Encrypts/Decrypts a message from the input buffer in, and places
    the resulting cipher text in the output buffer out using CTR mode with
    AES. This function is only enabled if WOLFSSL_AES_COUNTER is enabled at
    compile time. The AES structure should be initialized through AesSetKey
    before calling this function. Note that this function is used for both
    decryption and encryption. _NOTE:_ Regarding using same API for encryption
    and decryption. User should differentiate between Aes structures
    for encrypt/decrypt.

    \return int integer values corresponding to wolfSSL error or success
    status

    \param aes pointer to the AES object used to decrypt data
    \param out pointer to the output buffer in which to store the cipher
    text of the encrypted message
    size must be a multiple of AES_BLOCK_LENGTH, padded if necessary
    \param in pointer to the input buffer containing plain text to be encrypted
    size must be a multiple of AES_BLOCK_LENGTH, padded if necessary
    \param sz size of the input plain text

    _Example_
    \code
    Aes enc;
    Aes dec;
    // initialize enc and dec with wc_AesInit and wc_AesSetKeyDirect, using
    // direction AES_ENCRYPTION since the underlying API only calls Encrypt
    // and by default calling encrypt on a cipher results in a decryption of
    // the cipher

    byte msg[AES_BLOCK_SIZE * n]; //n being a positive integer making msg
    some multiple of 16 bytes
    // fill plain with message text
    byte cipher[AES_BLOCK_SIZE * n];
    byte decrypted[AES_BLOCK_SIZE * n];
    wc_AesCtrEncrypt(&enc, cipher, msg, sizeof(msg)); // encrypt plain
    wc_AesCtrEncrypt(&dec, decrypted, cipher, sizeof(cipher));
    // decrypt cipher text
    \endcode

    \sa wc_AesSetKey
*/
int wc_AesCtrEncrypt(Aes* aes, byte* out,
                                   const byte* in, word32 sz);

/*!
    \ingroup AES
    \brief This function is a one-block encrypt of the input block, in, into
    the output block, out. It uses the key of the provided AES structure, which
    should be initialized with wc_AesSetKey before calling this function.
    wc_AesSetKey should have been called with the iv set to NULL. This is only
    enabled if the configure option WOLFSSL_AES_DIRECT is enabled. __Warning:__
    In nearly all use cases ECB mode is considered to be less secure. Please
    avoid using ECB API’s directly whenever possible.

    \return int integer values corresponding to wolfSSL error or success
    status

    \param aes pointer to the AES object used to encrypt data
    \param out pointer to the output buffer in which to store the cipher
    text of the encrypted message
    \param in pointer to the input buffer containing plain text to be encrypted

    _Example_
    \code
    Aes enc;
    // initialize enc with wc_AesInit and wc_AesSetKey, using direction
    // AES_ENCRYPTION
    byte msg [AES_BLOCK_SIZE]; // 16 bytes
    // initialize msg with plain text to encrypt
    byte cipher[AES_BLOCK_SIZE];
    wc_AesEncryptDirect(&enc, cipher, msg);
    \endcode

    \sa wc_AesDecryptDirect
    \sa wc_AesSetKeyDirect
*/
int wc_AesEncryptDirect(Aes* aes, byte* out, const byte* in);

/*!
    \ingroup AES
    \brief This function is a one-block decrypt of the input block, in, into
    the output block, out. It uses the key of the provided AES structure, which
    should be initialized with wc_AesSetKey before calling this function.
    wc_AesSetKey should have been called with the iv set to NULL. This is only
    enabled if the configure option WOLFSSL_AES_DIRECT is enabled. __Warning:__
    In nearly all use cases ECB mode is considered to be less secure. Please
    avoid using ECB API’s directly whenever possible.

    \return int integer values corresponding to wolfSSL error or success
    status

    \param aes pointer to the AES object used to encrypt data
    \param out pointer to the output buffer in which to store the plain
    text of the decrypted cipher text
    \param in pointer to the input buffer containing cipher text to be
    decrypted

    _Example_
    \code
    Aes dec;
    // initialize enc with wc_AesInit and wc_AesSetKey, using direction
    // AES_DECRYPTION
    byte cipher [AES_BLOCK_SIZE]; // 16 bytes
    // initialize cipher with cipher text to decrypt
    byte msg[AES_BLOCK_SIZE];
    wc_AesDecryptDirect(&dec, msg, cipher);
    \endcode

    \sa wc_AesEncryptDirect
    \sa wc_AesSetKeyDirect
 */
int wc_AesDecryptDirect(Aes* aes, byte* out, const byte* in);

/*!
    \ingroup AES
    \brief This function is used to set the AES keys for CTR mode with AES.
    It initializes an AES object with the given key, iv
    (initialization vector), and encryption dir (direction). It is only
    enabled if the configure option WOLFSSL_AES_DIRECT is enabled.
    Currently wc_AesSetKeyDirect uses wc_AesSetKey internally. __Warning:__ In
    nearly all use cases ECB mode is considered to be less secure. Please avoid
    using ECB API’s directly whenever possible

    \return 0 On successfully setting the key.
    \return BAD_FUNC_ARG Returned if the given key is an invalid length.

    \param aes pointer to the AES object used to encrypt data
    \param key 16, 24, or 32 byte secret key for encryption and decryption
    \param len length of the key passed in
    \param iv initialization vector used to initialize the key
    \param dir Cipher direction. Set AES_ENCRYPTION to encrypt,  or
    AES_DECRYPTION to decrypt. (See enum in wolfssl/wolfcrypt/aes.h)
    (NOTE: If using wc_AesSetKeyDirect with Aes Counter mode (Stream cipher)
    only use AES_ENCRYPTION for both encrypting and decrypting)

    _Example_
    \code
    Aes enc;
    int ret = 0;
    byte key[] = { some 16, 24, or 32 byte key };
    byte iv[]  = { some 16 byte iv };

    if (ret = wc_AesInit(&enc, HEAP_HINT, INVALID_DEVID) != 0) {
        // failed to initialize aes key
    }
    if (ret = wc_AesSetKeyDirect(&enc, key, sizeof(key), iv,
    AES_ENCRYPTION) != 0) {
	// failed to set aes key
    }
    \endcode

    \sa wc_AesEncryptDirect
    \sa wc_AesDecryptDirect
    \sa wc_AesSetKey
*/
int  wc_AesSetKeyDirect(Aes* aes, const byte* key, word32 len,
                                const byte* iv, int dir);

/*!
    \ingroup AES
    \brief This function is used to set the key for AES GCM
    (Galois/Counter Mode). It initializes an AES object with the
    given key. It is only enabled if the configure option
    HAVE_AESGCM is enabled at compile time.

    \return 0 On successfully setting the key.
    \return BAD_FUNC_ARG Returned if the given key is an invalid length.

    \param aes pointer to the AES object used to encrypt data
    \param key 16, 24, or 32 byte secret key for encryption and decryption
    \param len length of the key passed in

    _Example_
    \code
    Aes enc;
    int ret = 0;
    byte key[] = { some 16, 24,32 byte key };
    if (ret = wc_AesInit(&enc, HEAP_HINT, INVALID_DEVID) != 0) {
        // failed to initialize aes key
    }
    if (ret = wc_AesGcmSetKey(&enc, key, sizeof(key)) != 0) {
	// failed to set aes key
    }
    \endcode

    \sa wc_AesGcmEncrypt
    \sa wc_AesGcmDecrypt
*/
int  wc_AesGcmSetKey(Aes* aes, const byte* key, word32 len);

/*!
    \ingroup AES
    \brief This function encrypts the input message, held in the buffer in,
    and stores the resulting cipher text in the output buffer out. It
    requires a new iv (initialization vector) for each call to encrypt.
    It also encodes the input authentication vector, authIn, into the
    authentication tag, authTag.

    \return 0 On successfully encrypting the input message

    \param aes - pointer to the AES object used to encrypt data
    \param out pointer to the output buffer in which to store the cipher text
    size must match in's size (sz)
    \param in pointer to the input buffer holding the message to encrypt
    size must be a multiple of AES_BLOCK_LENGTH, padded if necessary
    \param sz length of the input message to encrypt
    \param iv pointer to the buffer containing the initialization vector
    \param ivSz length of the initialization vector
    \param authTag pointer to the buffer in which to store the
    authentication tag
    \param authTagSz length of the desired authentication tag
    \param authIn pointer to the buffer containing the input
    authentication vector
    \param authInSz length of the input authentication vector

    _Example_
    \code
    Aes enc;
    // initialize Aes structure by calling wc_AesInit() and wc_AesGcmSetKey

    byte plain[AES_BLOCK_LENGTH * n]; //n being a positive integer
    making plain some multiple of 16 bytes
    // initialize plain with msg to encrypt
    byte cipher[sizeof(plain)];
    byte iv[] = // some 16 byte iv
    byte authTag[AUTH_TAG_LENGTH];
    byte authIn[] = // Authentication Vector

    wc_AesGcmEncrypt(&enc, cipher, plain, sizeof(cipher), iv, sizeof(iv),
			authTag, sizeof(authTag), authIn, sizeof(authIn));
    \endcode

    \sa wc_AesGcmSetKey
    \sa wc_AesGcmDecrypt
*/
int  wc_AesGcmEncrypt(Aes* aes, byte* out,
                                   const byte* in, word32 sz,
                                   const byte* iv, word32 ivSz,
                                   byte* authTag, word32 authTagSz,
                                   const byte* authIn, word32 authInSz);

/*!
    \ingroup AES
    \brief This function decrypts the input cipher text, held in the buffer
    in, and stores the resulting message text in the output buffer out.
    It also checks the input authentication vector, authIn, against the
    supplied authentication tag, authTag.  If a nonzero error code is returned,
    the output data is undefined.  However, callers must unconditionally zeroize
    the output buffer to guard against leakage of cleartext data.

    \return 0 On successfully decrypting and authenticating the input message
    \return AES_GCM_AUTH_E If the authentication tag does not match the
    supplied authentication code vector, authTag.

    \param aes pointer to the AES object used to encrypt data
    \param out pointer to the output buffer in which to store the message text
    size must match in's size (sz)
    \param in pointer to the input buffer holding the cipher text to decrypt
    size must be a multiple of AES_BLOCK_LENGTH, padded if necessary
    \param sz length of the cipher text to decrypt
    \param iv pointer to the buffer containing the initialization vector
    \param ivSz length of the initialization vector
    \param authTag pointer to the buffer containing the authentication tag
    \param authTagSz length of the desired authentication tag
    \param authIn pointer to the buffer containing the input
    authentication vector
    \param authInSz length of the input authentication vector

    _Example_
    \code
    Aes enc; //can use the same struct as was passed to wc_AesGcmEncrypt
    // initialize aes structure by calling wc_AesInit and wc_AesGcmSetKey
    // if not already done

    byte cipher[AES_BLOCK_LENGTH * n]; //n being a positive integer
    making cipher some multiple of 16 bytes
    // initialize cipher with cipher text to decrypt
    byte output[sizeof(cipher)];
    byte iv[] = // some 16 byte iv
    byte authTag[AUTH_TAG_LENGTH];
    byte authIn[] = // Authentication Vector

    wc_AesGcmDecrypt(&enc, output, cipher, sizeof(cipher), iv, sizeof(iv),
			authTag, sizeof(authTag), authIn, sizeof(authIn));
    \endcode

    \sa wc_AesGcmSetKey
    \sa wc_AesGcmEncrypt
*/
int  wc_AesGcmDecrypt(Aes* aes, byte* out,
                                   const byte* in, word32 sz,
                                   const byte* iv, word32 ivSz,
                                   const byte* authTag, word32 authTagSz,
                                   const byte* authIn, word32 authInSz);

/*!
    \ingroup AES
    \brief This function initializes and sets the key for a GMAC object
    to be used for Galois Message Authentication.

    \return 0 On successfully setting the key
    \return BAD_FUNC_ARG Returned if key length is invalid.

    \param gmac pointer to the gmac object used for authentication
    \param key 16, 24, or 32 byte secret key for authentication
    \param len length of the key

    _Example_
    \code
    Gmac gmac;
    key[] = { some 16, 24, or 32 byte length key };
    wc_AesInit(gmac.aes, HEAP_HINT, INVALID_DEVID); // Make sure devId updated
    wc_GmacSetKey(&gmac, key, sizeof(key));
    \endcode

    \sa wc_GmacUpdate
    \sa wc_AesInit
*/
int wc_GmacSetKey(Gmac* gmac, const byte* key, word32 len);

/*!
    \ingroup AES
    \brief This function generates the Gmac hash of the authIn input and
    stores the result in the authTag buffer. After running wc_GmacUpdate,
    one should compare the generated authTag to a known authentication tag
    to verify the authenticity of a message.

    \return 0 On successfully computing the Gmac hash.

    \param gmac pointer to the gmac object used for authentication
    \param iv initialization vector used for the hash
    \param ivSz size of the initialization vector used
    \param authIn pointer to the buffer containing the authentication
    vector to verify
    \param authInSz size of the authentication vector
    \param authTag pointer to the output buffer in which to store the Gmac hash
    \param authTagSz the size of the output buffer used to store the Gmac hash

    _Example_
    \code
    Gmac gmac;
    key[] = { some 16, 24, or 32 byte length key };
    iv[] = { some 16 byte length iv };

    wc_AesInit(gmac.aes, HEAP_HINT, INVALID_DEVID); // Make sure devId updated
    wc_GmacSetKey(&gmac, key, sizeof(key));
    authIn[] = { some 16 byte authentication input };
    tag[AES_BLOCK_SIZE]; // will store authentication code

    wc_GmacUpdate(&gmac, iv, sizeof(iv), authIn, sizeof(authIn), tag,
    sizeof(tag));
    \endcode

    \sa wc_GmacSetKey
    \sa wc_AesInit
*/
int wc_GmacUpdate(Gmac* gmac, const byte* iv, word32 ivSz,
                               const byte* authIn, word32 authInSz,
                               byte* authTag, word32 authTagSz);

/*!
    \ingroup AES
    \brief This function sets the key for an AES object using CCM
    (Counter with CBC-MAC). It takes a pointer to an AES structure and
    initializes it with supplied key.

    \return none

    \param aes aes structure in which to store the supplied key
    \param key 16, 24, or 32 byte secret key for encryption and decryption
    \param keySz size of the supplied key

    _Example_
    \code
    Aes enc;
    key[] = { some 16, 24, or 32 byte length key };

    wc_AesInit(&enc, HEAP_HINT, INVALID_DEVID); // Make sure devId updated
    wc_AesCcmSetKey(&enc, key, sizeof(key));
    \endcode

    \sa wc_AesCcmEncrypt
    \sa wc_AesCcmDecrypt
*/
int  wc_AesCcmSetKey(Aes* aes, const byte* key, word32 keySz);

/*!
    \ingroup AES

    \brief This function encrypts the input message, in, into the output
    buffer, out, using CCM (Counter with CBC-MAC). It subsequently
    calculates and stores the authorization tag, authTag, from the
    authIn input.

    \return none

    \param aes pointer to the AES object used to encrypt data
    \param out pointer to the output buffer in which to store the cipher text
    \param in pointer to the input buffer holding the message to encrypt
    \param sz length of the input message to encrypt
    \param nonce pointer to the buffer containing the nonce
    (number only used once)
    \param nonceSz length of the nonce
    \param authTag pointer to the buffer in which to store the
    authentication tag
    \param authTagSz length of the desired authentication tag
    \param authIn pointer to the buffer containing the input
    authentication vector
    \param authInSz length of the input authentication vector

    _Example_
    \code
    Aes enc;
    // initialize enc with wc_AesInit and wc_AesCcmSetKey

    nonce[] = { initialize nonce };
    plain[] = { some plain text message };
    cipher[sizeof(plain)];

    authIn[] = { some 16 byte authentication input };
    tag[AES_BLOCK_SIZE]; // will store authentication code

    wc_AesCcmEncrypt(&enc, cipher, plain, sizeof(plain), nonce, sizeof(nonce),
			tag, sizeof(tag), authIn, sizeof(authIn));
    \endcode

    \sa wc_AesCcmSetKey
    \sa wc_AesCcmDecrypt
*/
int  wc_AesCcmEncrypt(Aes* aes, byte* out,
                                   const byte* in, word32 inSz,
                                   const byte* nonce, word32 nonceSz,
                                   byte* authTag, word32 authTagSz,
                                   const byte* authIn, word32 authInSz);

/*!
    \ingroup AES

    \brief This function decrypts the input cipher text, in, into
    the output buffer, out, using CCM (Counter with CBC-MAC). It
    subsequently calculates the authorization tag, authTag, from the
    authIn input.  If a nonzero error code is returned, the output data is
    undefined.  However, callers must unconditionally zeroize the output buffer
    to guard against leakage of cleartext data.

    \return 0 On successfully decrypting the input message
    \return AES_CCM_AUTH_E If the authentication tag does not match the
    supplied authentication code vector, authTag.

    \param aes pointer to the AES object used to encrypt data
    \param out pointer to the output buffer in which to store the cipher text
    \param in pointer to the input buffer holding the message to encrypt
    \param sz length of the input cipher text to decrypt
    \param nonce pointer to the buffer containing the nonce
    (number only used once)
    \param nonceSz length of the nonce
    \param authTag pointer to the buffer in which to store the
    authentication tag
    \param authTagSz length of the desired authentication tag
    \param authIn pointer to the buffer containing the input
    authentication vector
    \param authInSz length of the input authentication vector

    _Example_
    \code
    Aes dec;
    // initialize dec with wc_AesInit and wc_AesCcmSetKey

    nonce[] = { initialize nonce };
    cipher[] = { encrypted message };
    plain[sizeof(cipher)];

    authIn[] = { some 16 byte authentication input };
    tag[AES_BLOCK_SIZE] = { authentication tag received for verification };

    int return = wc_AesCcmDecrypt(&dec, plain, cipher, sizeof(cipher),
    nonce, sizeof(nonce),tag, sizeof(tag), authIn, sizeof(authIn));
    if(return != 0) {
	// decrypt error, invalid authentication code
    }
    \endcode

    \sa wc_AesCcmSetKey
    \sa wc_AesCcmEncrypt
*/
int  wc_AesCcmDecrypt(Aes* aes, byte* out,
                                   const byte* in, word32 inSz,
                                   const byte* nonce, word32 nonceSz,
                                   const byte* authTag, word32 authTagSz,
                                   const byte* authIn, word32 authInSz);

/*!
    \ingroup AES

    \brief This is to initialize an AES-XTS context. It is up to user to call
    wc_AesXtsFree on aes key when done.

    \return 0 Success

    \param aes   AES keys for encrypt/decrypt process
    \param heap  heap hint to use for memory. Can be NULL
    \param devId ID to use with crypto callbacks or async hardware. Set to INVALID_DEVID (-2) if not used

    _Example_
    \code
    XtsAes aes;

    if(wc_AesXtsInit(&aes, NULL, INVALID_DEVID) != 0)
    {
        // Handle error
    }
    if(wc_AesXtsSetKeyNoInit(&aes, key, sizeof(key), AES_ENCRYPTION) != 0)
    {
        // Handle error
    }
    wc_AesXtsFree(&aes);
    \endcode

    \sa wc_AesXtsSetKey
    \sa wc_AesXtsSetKeyNoInit
    \sa wc_AesXtsEncrypt
    \sa wc_AesXtsDecrypt
    \sa wc_AesXtsFree
*/
int wc_AesXtsInit(XtsAes* aes, void* heap, int devId);


/*!
    \ingroup AES

    \brief This is to help with setting keys to correct encrypt or decrypt type,
    after first calling wc_AesXtsInit(). It is up to user to call wc_AesXtsFree
    on aes key when done.

    \return 0 Success

    \param aes   AES keys for encrypt/decrypt process
    \param key   buffer holding aes key | tweak key
    \param len   length of key buffer in bytes. Should be twice that of
    key size.
                 i.e. 32 for a 16 byte key.
    \param dir   direction, either AES_ENCRYPTION or AES_DECRYPTION

    _Example_
    \code
    XtsAes aes;

    if(wc_AesXtsInit(&aes, NULL, 0) != 0)
    {
        // Handle error
    }
    if(wc_AesXtsSetKeyNoInit(&aes, key, sizeof(key), AES_ENCRYPTION, NULL, 0)
       != 0)
    {
        // Handle error
    }
    wc_AesXtsFree(&aes);
    \endcode

    \sa wc_AesXtsEncrypt
    \sa wc_AesXtsDecrypt
    \sa wc_AesXtsFree
*/
int wc_AesXtsSetKeyNoInit(XtsAes* aes, const byte* key,
         word32 len, int dir);


/*!
    \ingroup AES

    \brief This is to help with setting keys to correct encrypt or
    decrypt type. It is up to user to call wc_AesXtsFree on aes key when done.

    \return 0 Success

    \param aes   AES keys for encrypt/decrypt process
    \param key   buffer holding aes key | tweak key
    \param len   length of key buffer in bytes. Should be twice that of
    key size.
                 i.e. 32 for a 16 byte key.
    \param dir   direction, either AES_ENCRYPTION or AES_DECRYPTION
    \param heap  heap hint to use for memory. Can be NULL
    \param devId ID to use with crypto callbacks or async hardware. Set to INVALID_DEVID (-2) if not used

    _Example_
    \code
    XtsAes aes;

    if(wc_AesXtsSetKey(&aes, key, sizeof(key), AES_ENCRYPTION, NULL, INVALID_DEVID) != 0)
    {
        // Handle error
    }
    wc_AesXtsFree(&aes);
    \endcode

    \sa wc_AesXtsInit
    \sa wc_AesXtsSetKeyNoInit
    \sa wc_AesXtsEncrypt
    \sa wc_AesXtsDecrypt
    \sa wc_AesXtsFree
*/
int wc_AesXtsSetKey(XtsAes* aes, const byte* key,
         word32 len, int dir, void* heap, int devId);

/*!
    \ingroup AES

    \brief Same process as wc_AesXtsEncrypt but uses a word64 type as the tweak
           value instead of a byte array. This just converts the word64 to a
           byte array and calls wc_AesXtsEncrypt.

    \return 0 Success

    \param aes    AES keys to use for block encrypt/decrypt
    \param out    output buffer to hold cipher text
    \param in     input plain text buffer to encrypt
    \param sz     size of both out and in buffers
    \param sector value to use for tweak

    _Example_
    \code
    XtsAes aes;
    unsigned char plain[SIZE];
    unsigned char cipher[SIZE];
    word64 s = VALUE;

    //set up keys with AES_ENCRYPTION as dir

    if(wc_AesXtsEncryptSector(&aes, cipher, plain, SIZE, s) != 0)
    {
        // Handle error
    }
    wc_AesXtsFree(&aes);
    \endcode

    \sa wc_AesXtsEncrypt
    \sa wc_AesXtsDecrypt
    \sa wc_AesXtsInit
    \sa wc_AesXtsSetKeyNoInit
    \sa wc_AesXtsSetKey
    \sa wc_AesXtsFree
*/
int wc_AesXtsEncryptSector(XtsAes* aes, byte* out,
         const byte* in, word32 sz, word64 sector);

/*!
    \ingroup AES

    \brief Same process as wc_AesXtsDecrypt but uses a word64 type as the tweak
           value instead of a byte array. This just converts the word64 to a
           byte array.

    \return 0 Success

    \param aes    AES keys to use for block encrypt/decrypt
    \param out    output buffer to hold plain text
    \param in     input cipher text buffer to decrypt
    \param sz     size of both out and in buffers
    \param sector value to use for tweak

    _Example_
    \code
    XtsAes aes;
    unsigned char plain[SIZE];
    unsigned char cipher[SIZE];
    word64 s = VALUE;

    //set up aes key with AES_DECRYPTION as dir and tweak with AES_ENCRYPTION

    if(wc_AesXtsDecryptSector(&aes, plain, cipher, SIZE, s) != 0)
    {
        // Handle error
    }
    wc_AesXtsFree(&aes);
    \endcode

    \sa wc_AesXtsEncrypt
    \sa wc_AesXtsDecrypt
    \sa wc_AesXtsInit
    \sa wc_AesXtsSetKeyNoInit
    \sa wc_AesXtsSetKey
    \sa wc_AesXtsFree
*/
int wc_AesXtsDecryptSector(XtsAes* aes, byte* out,
         const byte* in, word32 sz, word64 sector);

/*!
    \ingroup AES

    \brief AES with XTS mode. (XTS) XEX encryption with Tweak and cipher text
           Stealing.

    \return 0 Success

    \param aes   AES keys to use for block encrypt/decrypt
    \param out   output buffer to hold cipher text
    \param in    input plain text buffer to encrypt
    \param sz    size of both out and in buffers
    \param i     value to use for tweak
    \param iSz   size of i buffer, should always be AES_BLOCK_SIZE but having
                 this input adds a sanity check on how the user calls the
                 function.

    _Example_
    \code
    XtsAes aes;
    unsigned char plain[SIZE];
    unsigned char cipher[SIZE];
    unsigned char i[AES_BLOCK_SIZE];

    //set up key with AES_ENCRYPTION as dir

    if(wc_AesXtsEncrypt(&aes, cipher, plain, SIZE, i, sizeof(i)) != 0)
    {
        // Handle error
    }
    wc_AesXtsFree(&aes);
    \endcode

    \sa wc_AesXtsDecrypt
    \sa wc_AesXtsInit
    \sa wc_AesXtsSetKeyNoInit
    \sa wc_AesXtsSetKey
    \sa wc_AesXtsFree
*/
int wc_AesXtsEncrypt(XtsAes* aes, byte* out,
         const byte* in, word32 sz, const byte* i, word32 iSz);

/*!
    \ingroup AES

    \brief Same process as encryption but Aes key is AES_DECRYPTION type.

    \return 0 Success

    \param aes   AES keys to use for block encrypt/decrypt
    \param out   output buffer to hold plain text
    \param in    input cipher text buffer to decrypt
    \param sz    size of both out and in buffers
    \param i     value to use for tweak
    \param iSz   size of i buffer, should always be AES_BLOCK_SIZE but having
                 this input adds a sanity check on how the user calls the
                 function.

    _Example_
    \code
    XtsAes aes;
    unsigned char plain[SIZE];
    unsigned char cipher[SIZE];
    unsigned char i[AES_BLOCK_SIZE];

    //set up key with AES_DECRYPTION as dir and tweak with AES_ENCRYPTION

    if(wc_AesXtsDecrypt(&aes, plain, cipher, SIZE, i, sizeof(i)) != 0)
    {
        // Handle error
    }
    wc_AesXtsFree(&aes);
    \endcode

    \sa wc_AesXtsEncrypt
    \sa wc_AesXtsInit
    \sa wc_AesXtsSetKeyNoInit
    \sa wc_AesXtsSetKey
    \sa wc_AesXtsFree
*/
int wc_AesXtsDecrypt(XtsAes* aes, byte* out,
        const byte* in, word32 sz, const byte* i, word32 iSz);

/*!
    \ingroup AES

    \brief This is to free up any resources used by the XtsAes structure

    \return 0 Success

    \param aes AES keys to free

    _Example_
    \code
    XtsAes aes;

    if(wc_AesXtsSetKey(&aes, key, sizeof(key), AES_ENCRYPTION, NULL, 0) != 0)
    {
        // Handle error
    }
    wc_AesXtsFree(&aes);
    \endcode

    \sa wc_AesXtsEncrypt
    \sa wc_AesXtsDecrypt
    \sa wc_AesXtsInit
    \sa wc_AesXtsSetKeyNoInit
    \sa wc_AesXtsSetKey
*/
int wc_AesXtsFree(XtsAes* aes);


/*!
    \ingroup AES
    \brief Initialize Aes structure. Sets heap hint to be used and ID for use
    with async hardware. It is up to the user to call wc_AesFree on the Aes
    structure when done.
    \return 0 Success

    \param aes aes structure in to initialize
    \param heap heap hint to use for malloc / free if needed
    \param devId ID to use with crypto callbacks or async hardware. Set to INVALID_DEVID (-2) if not used

    _Example_
    \code
    Aes enc;
    void* hint = NULL;
    int devId = INVALID_DEVID; //if not using async INVALID_DEVID is default

    //heap hint could be set here if used

    wc_AesInit(&enc, hint, devId);
    \endcode

    \sa wc_AesSetKey
    \sa wc_AesSetIV
    \sa wc_AesFree
*/
int  wc_AesInit(Aes* aes, void* heap, int devId);

/*!
    \ingroup AES
    \brief free resources associated with the Aes structure when applicable.
    Internally may sometimes be a no-op but still recommended to call in all
    cases as a general best-practice (IE if application code is ported for use
    on new environments where the call is applicable).
    \return no return (void function)

    \param aes aes structure in to free

    _Example_
    \code
    Aes enc;
    void* hint = NULL;
    int devId = INVALID_DEVID; //if not using async INVALID_DEVID is default

    //heap hint could be set here if used

    wc_AesInit(&enc, hint, devId);
    // ... do some interesting things ...
    wc_AesFree(&enc);
    \endcode

    \sa wc_AesInit
*/
void wc_AesFree(Aes* aes);

/*!
    \ingroup AES

    \brief AES with CFB mode.

    \return 0 Success and negative error values on failure

    \param aes   AES keys to use for block encrypt/decrypt
    \param out   output buffer to hold cipher text must be at least as large
    as inputbuffer)
    \param in    input plain text buffer to encrypt
    \param sz    size of input buffer

    _Example_
    \code
    Aes aes;
    unsigned char plain[SIZE];
    unsigned char cipher[SIZE];

    //set up key with AES_ENCRYPTION as dir for both encrypt and decrypt

    if(wc_AesCfbEncrypt(&aes, cipher, plain, SIZE) != 0)
    {
        // Handle error
    }
    \endcode

    \sa wc_AesCfbDecrypt
    \sa wc_AesSetKey
*/
int wc_AesCfbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz);

/*!
    \ingroup AES

    \brief AES with CFB mode.

    \return 0 Success and negative error values on failure

    \param aes   AES keys to use for block encrypt/decrypt
    \param out   output buffer to hold decrypted text must be at least as large
    as inputbuffer)
    \param in    input buffer to decrypt
    \param sz    size of input buffer

    _Example_
    \code
    Aes aes;
    unsigned char plain[SIZE];
    unsigned char cipher[SIZE];

    //set up key with AES_ENCRYPTION as dir for both encrypt and decrypt

    if(wc_AesCfbDecrypt(&aes, plain, cipher, SIZE) != 0)
    {
        // Handle error
    }
    \endcode

    \sa wc_AesCfbEncrypt
    \sa wc_AesSetKey
*/
int wc_AesCfbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz);

/*!
    \ingroup AES

    \brief This function performs SIV (synthetic initialization vector)
    encryption as described in RFC 5297.

    \return 0 On successful encryption.
    \return BAD_FUNC_ARG If key, SIV, or output buffer are NULL. Also returned
    if the key size isn't 32, 48, or 64 bytes.
    \return Other Other negative error values returned if AES or CMAC operations
    fail.

    \param key Byte buffer containing the key to use.
    \param keySz Length of the key buffer in bytes.
    \param assoc Additional, authenticated associated data (AD).
    \param assocSz Length of AD buffer in bytes.
    \param nonce A number used once. Used by the algorithm in the same manner as
    the AD.
    \param nonceSz Length of nonce buffer in bytes.
    \param in Plaintext buffer to encrypt.
    \param inSz Length of plaintext buffer.
    \param siv The SIV output by S2V (see RFC 5297 2.4).
    \param out Buffer to hold the ciphertext. Should be the same length as the
    plaintext buffer.

    _Example_
    \code
    byte key[] = { some 32, 48, or 64 byte key };
    byte assoc[] = {0x01, 0x2, 0x3};
    byte nonce[] = {0x04, 0x5, 0x6};
    byte plainText[] = {0xDE, 0xAD, 0xBE, 0xEF};
    byte siv[AES_BLOCK_SIZE];
    byte cipherText[sizeof(plainText)];
    if (wc_AesSivEncrypt(key, sizeof(key), assoc, sizeof(assoc), nonce,
        sizeof(nonce), plainText, sizeof(plainText), siv, cipherText) != 0) {
        // failed to encrypt
    }
    \endcode

    \sa wc_AesSivDecrypt
*/


int wc_AesSivEncrypt(const byte* key, word32 keySz, const byte* assoc,
                     word32 assocSz, const byte* nonce, word32 nonceSz,
                     const byte* in, word32 inSz, byte* siv, byte* out);

/*!
    \ingroup AES
    \brief This function performs SIV (synthetic initialization vector)
    decryption as described in RFC 5297.  If a nonzero error code is returned,
    the output data is undefined.  However, callers must unconditionally zeroize
    the output buffer to guard against leakage of cleartext data.

    \return 0 On successful decryption.
    \return BAD_FUNC_ARG If key, SIV, or output buffer are NULL. Also returned
    if the key size isn't 32, 48, or 64 bytes.
    \return AES_SIV_AUTH_E If the SIV derived by S2V doesn't match the input
    SIV (see RFC 5297 2.7).
    \return Other Other negative error values returned if AES or CMAC operations
    fail.

    \param key Byte buffer containing the key to use.
    \param keySz Length of the key buffer in bytes.
    \param assoc Additional, authenticated associated data (AD).
    \param assocSz Length of AD buffer in bytes.
    \param nonce A number used once. Used by the underlying algorithm in the
    same manner as the AD.
    \param nonceSz Length of nonce buffer in bytes.
    \param in Ciphertext buffer to decrypt.
    \param inSz Length of ciphertext buffer.
    \param siv The SIV that accompanies the ciphertext (see RFC 5297 2.4).
    \param out Buffer to hold the decrypted plaintext. Should be the same length
    as the ciphertext buffer.

    _Example_
    \code
    byte key[] = { some 32, 48, or 64 byte key };
    byte assoc[] = {0x01, 0x2, 0x3};
    byte nonce[] = {0x04, 0x5, 0x6};
    byte cipherText[] = {0xDE, 0xAD, 0xBE, 0xEF};
    byte siv[AES_BLOCK_SIZE] = { the SIV that came with the ciphertext };
    byte plainText[sizeof(cipherText)];
    if (wc_AesSivDecrypt(key, sizeof(key), assoc, sizeof(assoc), nonce,
        sizeof(nonce), cipherText, sizeof(cipherText), siv, plainText) != 0) {
        // failed to decrypt
    }
    \endcode

    \sa wc_AesSivEncrypt
*/

int wc_AesSivDecrypt(const byte* key, word32 keySz, const byte* assoc,
                     word32 assocSz, const byte* nonce, word32 nonceSz,
                     const byte* in, word32 inSz, byte* siv, byte* out);







/*!
    \ingroup AES

    \brief This function performs AES EAX encryption and authentication as
    described in "EAX: A Conventional Authenticated-Encryption Mode"
    (https://eprint.iacr.org/2003/069). It is a "one-shot" API that performs
    all encryption and authentication operations in one function call.

    \return 0 on successful encryption.
    \return BAD_FUNC_ARG if input or output buffers are NULL. Also returned
    if the key size isn't a valid AES key size (16, 24, or 32 bytes)
    \return other negative error values returned if AES or CMAC operations
    fail.

    \param [in] key buffer containing the key to use
    \param [in] keySz length of the key buffer in bytes
    \param[out] out buffer to hold the ciphertext. Should be the same length as
    the plaintext buffer
    \param [in] in plaintext buffer to encrypt
    \param [in] inSz length of plaintext buffer
    \param [in] nonce the cryptographic nonce to use for EAX operations
    \param [in] nonceSz length of nonce buffer in bytes
    \param[out] authTag pointer to the buffer in which to store the
    authentication tag
    \param [in] authTagSz length of the desired authentication tag
    \param [in] authIn pointer to the buffer containing input data to authenticate
    \param [in] authInSz length of the input authentication data

    _Example_
    \code
    byte key[] = { some 32, 48, or 64 byte key };
    byte nonce[] = {0x04, 0x5, 0x6};
    byte plainText[] = {0xDE, 0xAD, 0xBE, 0xEF};
    byte authIn[] = {0x01, 0x2, 0x3};

    byte cipherText[sizeof(plainText)]; // output ciphertext
    byte authTag[length, up to AES_BLOCK_SIZE]; // output authTag

    if (wc_AesEaxEncrypt(key, sizeof(key),
                         cipherText, plainText, sizeof(plainText),
                         nonce, sizeof(nonce),
                         authTag, sizeof(authTag),
                         authIn, sizeof(authIn)) != 0) {
        // failed to encrypt
    }

    \endcode

    \sa wc_AesEaxDecryptAuth

*/
WOLFSSL_API int  wc_AesEaxEncryptAuth(const byte* key, word32 keySz, byte* out,
                                      const byte* in, word32 inSz,
                                      const byte* nonce, word32 nonceSz,
                                      /* output computed auth tag */
                                      byte* authTag, word32 authTagSz,
                                      /* input data to authenticate */
                                      const byte* authIn, word32 authInSz);
/*!
    \ingroup AES

    \brief This function performs AES EAX decryption and authentication as
    described in "EAX: A Conventional Authenticated-Encryption Mode"
    (https://eprint.iacr.org/2003/069). It is a "one-shot" API that performs
    all decryption and authentication operations in one function call.  If a
    nonzero error code is returned, the output data is undefined.
    However, callers must unconditionally zeroize the output buffer to guard
    against leakage of cleartext data.

    \return 0 on successful decryption
    \return BAD_FUNC_ARG if input or output buffers are NULL. Also returned
    if the key size isn't a valid AES key size (16, 24, or 32 bytes)
    \return AES_EAX_AUTH_E If the authentication tag does not match the
    supplied authentication code vector \c authTag
    \return other negative error values returned if AES or CMAC operations
    fail.

    \param [in] key byte buffer containing the key to use
    \param [in] keySz length of the key buffer in bytes
    \param[out] out buffer to hold the plaintext. Should be the same length as
    the input ciphertext buffer
    \param [in] in ciphertext buffer to decrypt
    \param [in] inSz length of ciphertext buffer
    \param [in] nonce the cryptographic nonce to use for EAX operations
    \param [in] nonceSz length of nonce buffer in bytes
    \param [in] authTag buffer that holds the authentication tag to check the
    authenticity of the data against
    \param [in] authTagSz Length of the input authentication tag
    \param [in] authIn pointer to the buffer containing input data to authenticate
    \param [in] authInSz length of the input authentication data

    _Example_
    \code
    byte key[] = { some 32, 48, or 64 byte key };
    byte nonce[] = {0x04, 0x5, 0x6};
    byte cipherText[] = {0xDE, 0xAD, 0xBE, 0xEF};
    byte authIn[] = {0x01, 0x2, 0x3};

    byte plainText[sizeof(cipherText)]; // output plaintext
    byte authTag[length, up to AES_BLOCK_SIZE]; // output authTag

    if (wc_AesEaxDecrypt(key, sizeof(key),
                         cipherText, plainText, sizeof(plainText),
                         nonce, sizeof(nonce),
                         authTag, sizeof(authTag),
                         authIn, sizeof(authIn)) != 0) {
        // failed to encrypt
    }

    \endcode

    \sa wc_AesEaxEncryptAuth

*/
WOLFSSL_API int  wc_AesEaxDecryptAuth(const byte* key, word32 keySz, byte* out,
                                      const byte* in, word32 inSz,
                                      const byte* nonce, word32 nonceSz,
                                      /* auth tag to verify against */
                                      const byte* authTag, word32 authTagSz,
                                      /* input data to authenticate */
                                      const byte* authIn, word32 authInSz);

/*!
    \ingroup AES
    \brief This function initializes an AesEax object for use in authenticated
    encryption or decryption. This function must be called on an AesEax
    object before using it with any of the AES EAX incremental API functions.
    It does not need to be called if using the one-shot EAX API functions.
    All AesEax instances initialized with this function need to be freed with
    a call to wc_AesEaxFree() when done using the instance.

    \return 0 on success
    \return error code on failure

    \param eax AES EAX structure holding the context of the AEAD operation
    \param key 16, 24, or 32 byte secret key for encryption and decryption
    \param keySz length of the supplied key in bytes
    \param nonce the cryptographic nonce to use for EAX operations
    \param nonceSz length of nonce buffer in bytes
    \param authIn (optional) input data to add to the authentication stream
    This argument should be NULL if not used
    \param authInSz size in bytes of the input authentication data

    _Example_
    \code
    AesEax eax;
    key[]   = { some 16, 24, or 32 byte length key };
    nonce[] = { some arbitrary length nonce };
    authIn[] = { some data to add to the authentication stream };
    plainText[] = {some plaintext data to encrypt};

    cipherText[sizeof(plainText)]; // buffer to hold cipherText
    authTag[length, up to AES_BLOCK_SIZE]; // buffer to hold computed auth data

    AesEax eax;

    if ((ret = wc_AesEaxInit(eax,
                             key, keySz,
                             nonce, nonceSz,
                             authIn, authInSz)) != 0) {
        goto cleanup;
    }

    // if we wanted to add more auth data, we could provide it at this point,
    // otherwise we use NULL for the authIn parameter, with authIn size of 0
    if ((ret = wc_AesEaxEncryptUpdate(eax,
                                      cipherText, plainText, sizeof(plainText),
                                      NULL, 0)) != 0) {
        goto cleanup;
    }

    if ((ret = wc_AesEaxEncryptFinal(eax, authTag, sizeof(authTag))) != 0) {
        goto cleanup;
    }

    cleanup:
        wc_AesEaxFree(eax);
    \endcode

    \sa wc_AesEaxEncryptUpdate
    \sa wc_AesEaxDecryptUpdate
    \sa wc_AesEaxAuthDataUpdate
    \sa wc_AesEaxEncryptFinal
    \sa wc_AesEaxDecryptFinal
    \sa wc_AesEaxFree

*/
WOLFSSL_API int  wc_AesEaxInit(AesEax* eax,
                               const byte* key, word32 keySz,
                               const byte* nonce, word32 nonceSz,
                               const byte* authIn, word32 authInSz);

/*!
    \ingroup AES
    \brief This function uses AES EAX to encrypt input data, and optionally, add
    more input data to the authentication stream. \c eax must have been
    previously initialized with a call to \ref wc_AesEaxInit.

    \return 0 on success
    \return error code on failure

    \param [in] eax AES EAX structure holding the context of the AEAD operation
    \param[out] out output buffer holding the ciphertext
    \param [in] in input buffer holding the plaintext to encrypt
    \param [in] inSz size in bytes of the input data buffer
    \param [in] authIn (optional) input data to add to the authentication stream
    This argument should be NULL if not used
    \param [in] authInSz size in bytes of the input authentication data

    _Example_
    \code
    AesEax eax;
    key[]   = { some 16, 24, or 32 byte length key };
    nonce[] = { some arbitrary length nonce };
    authIn[] = { some data to add to the authentication stream };
    plainText[] = {some plaintext data to encrypt};

    cipherText[sizeof(plainText)]; // buffer to hold cipherText
    authTag[length, up to AES_BLOCK_SIZE]; // buffer to hold computed auth data

    AesEax eax;

    if ((ret = wc_AesEaxInit(eax,
                             key, keySz,
                             nonce, nonceSz,
                             authIn, authInSz)) != 0) {
        goto cleanup;
    }

    // if we wanted to add more auth data, we could provide it at this point,
    // otherwise we use NULL for the authIn parameter, with authInSz of 0
    if ((ret = wc_AesEaxEncryptUpdate(eax,
                                      cipherText, plainText, sizeof(plainText),
                                      NULL, 0)) != 0) {
        goto cleanup;
    }

    if ((ret = wc_AesEaxEncryptFinal(eax, authTag, sizeof(authTag))) != 0) {
        goto cleanup;
    }

    cleanup:
        wc_AesEaxFree(eax);
    \endcode

    \sa wc_AesEaxInit
    \sa wc_AesEaxDecryptUpdate
    \sa wc_AesEaxAuthDataUpdate
    \sa wc_AesEaxEncryptFinal
    \sa wc_AesEaxDecryptFinal
    \sa wc_AesEaxFree

*/
WOLFSSL_API int  wc_AesEaxEncryptUpdate(AesEax* eax, byte* out,
                                        const byte* in, word32 inSz,
                                        const byte* authIn, word32 authInSz);

/*!
    \ingroup AES
    \brief This function uses AES EAX to decrypt input data, and optionally, add
    more input data to the authentication stream. \c eax must have been
    previously initialized with a call to \ref wc_AesEaxInit.

    \return 0 on success
    \return error code on failure

    \param [in] eax AES EAX structure holding the context of the AEAD operation
    \param[out] out output buffer holding the decrypted plaintext
    \param [in] in input buffer holding the ciphertext
    \param [in] inSz size in bytes of the input data buffer
    \param [in] authIn (optional) input data to add to the authentication stream
    This argument should be NULL if not used
    \param [in] authInSz size in bytes of the input authentication data


    _Example_
    \code
    AesEax eax;
    key[]   = { some 16, 24, or 32 byte length key };
    nonce[] = { some arbitrary length nonce };
    authIn[] = { some data to add to the authentication stream };
    cipherText[] = {some encrypted data};

    plainText[sizeof(cipherText)]; // buffer to hold decrypted data
    // auth tag is generated elsewhere by the encrypt AEAD operation
    authTag[length, up to AES_BLOCK_SIZE] = { the auth tag };

    AesEax eax;

    if ((ret = wc_AesEaxInit(eax,
                             key, keySz,
                             nonce, nonceSz,
                             authIn, authInSz)) != 0) {
        goto cleanup;
    }

    // if we wanted to add more auth data, we could provide it at this point,
    // otherwise we use NULL for the authIn parameter, with authInSz of 0
    if ((ret = wc_AesEaxDecryptUpdate(eax,
                                      plainText, cipherText, sizeof(cipherText),
                                      NULL, 0)) != 0) {
        goto cleanup;
    }

    if ((ret = wc_AesEaxDecryptFinal(eax, authTag, sizeof(authTag))) != 0) {
        goto cleanup;
    }

    cleanup:
        wc_AesEaxFree(eax);
    \endcode

    \sa wc_AesEaxInit
    \sa wc_AesEaxEncryptUpdate
    \sa wc_AesEaxAuthDataUpdate
    \sa wc_AesEaxEncryptFinal
    \sa wc_AesEaxDecryptFinal
    \sa wc_AesEaxFree

*/
WOLFSSL_API int  wc_AesEaxDecryptUpdate(AesEax* eax, byte* out,
                                        const byte* in, word32 inSz,
                                        const byte* authIn, word32 authInSz);
/*!
    \ingroup AES
    \brief This function adds input data to the authentication stream.
    \c eax must have been previously initialized with a call to
    \ref wc_AesEaxInit.

    \return 0 on success
    \return error code on failure

    \param eax AES EAX structure holding the context of the AEAD operation
    \param authIn input data to add to the authentication stream
    \param authInSz size in bytes of the input authentication data

    _Example_
    \code
    AesEax eax;
    key[]   = { some 16, 24, or 32 byte length key };
    nonce[] = { some arbitrary length nonce };
    authIn[] = { some data to add to the authentication stream };
    cipherText[] = {some encrypted data};

    plainText[sizeof(cipherText)]; // buffer to hold decrypted data
    // auth tag is generated elsewhere by the encrypt AEAD operation
    authTag[length, up to AES_BLOCK_SIZE] = { the auth tag };

    AesEax eax;

    // No auth data to add here
    if ((ret = wc_AesEaxInit(eax,
                             key, keySz,
                             nonce, nonceSz,
                             NULL, 0)) != 0) {
        goto cleanup;
    }

    // No auth data to add here, added later with wc_AesEaxAuthDataUpdate
    if ((ret = wc_AesEaxDecryptUpdate(eax,
                                      plainText, cipherText, sizeof(cipherText),
                                      NULL, 0)) != 0) {
        goto cleanup;
    }

    if ((ret = wc_AesEaxAuthDataUpdate(eax, authIn, sizeof(authIn))) != 0) {
        goto cleanup;
    }

    if ((ret = wc_AesEaxDecryptFinal(eax, authTag, sizeof(authTag))) != 0) {
        goto cleanup;
    }

    cleanup:
        wc_AesEaxFree(eax);
    \endcode

    \sa wc_AesEaxInit
    \sa wc_AesEaxEncryptUpdate
    \sa wc_AesEaxDecryptUpdate
    \sa wc_AesEaxEncryptFinal
    \sa wc_AesEaxDecryptFinal
    \sa wc_AesEaxFree

*/
WOLFSSL_API int  wc_AesEaxAuthDataUpdate(AesEax* eax,
                                       const byte* authIn, word32 authInSz);

/*!
    \ingroup AES
    \brief This function finalizes the encrypt AEAD operation, producing an auth
    tag over the current authentication stream. \c eax must have been previously
    initialized with a call to \ref wc_AesEaxInit. When done using the \c AesEax
    context structure, make sure to free it using \ref wc_AesEaxFree.

    \return 0 on success
    \return error code on failure

    \param eax AES EAX structure holding the context of the AEAD operation
    \param authTag[out] buffer that will hold the computed auth tag
    \param authTagSz size in bytes of \c authTag

    _Example_
    \code
    AesEax eax;
    key[]   = { some 16, 24, or 32 byte length key };
    nonce[] = { some arbitrary length nonce };
    authIn[] = { some data to add to the authentication stream };
    plainText[] = {some plaintext data to encrypt};

    cipherText[sizeof(plainText)]; // buffer to hold cipherText
    authTag[length, up to AES_BLOCK_SIZE]; // buffer to hold computed auth data

    AesEax eax;

    if ((ret = wc_AesEaxInit(eax,
                             key, keySz,
                             nonce, nonceSz,
                             authIn, authInSz)) != 0) {
        goto cleanup;
    }

    // if we wanted to add more auth data, we could provide it at this point,
    // otherwise we use NULL for the authIn parameter, with authInSz of 0
    if ((ret = wc_AesEaxEncryptUpdate(eax,
                                      cipherText, plainText, sizeof(plainText),
                                      NULL, 0)) != 0) {
        goto cleanup;
    }

    if ((ret = wc_AesEaxEncryptFinal(eax, authTag, sizeof(authTag))) != 0) {
        goto cleanup;
    }

    cleanup:
        wc_AesEaxFree(eax);
    \endcode

    \sa wc_AesEaxInit
    \sa wc_AesEaxEncryptUpdate
    \sa wc_AesEaxDecryptUpdate
    \sa wc_AesEaxAuthDataUpdate
    \sa wc_AesEaxDecryptFinal
    \sa wc_AesEaxFree

*/
WOLFSSL_API int wc_AesEaxEncryptFinal(AesEax* eax,
                                      byte* authTag, word32 authTagSz);

/*!
    \ingroup AES
    \brief This function finalizes the decrypt AEAD operation, finalizing the
    auth tag computation and checking it for validity against the user supplied
    tag. \c eax must have been previously initialized with a call to
    \ref wc_AesEaxInit. When done using the \c AesEax context structure, make
    sure to free it using \ref wc_AesEaxFree.

    \return 0 if data is authenticated successfully
    \return AES_EAX_AUTH_E if the authentication tag does not match the
    supplied authentication code vector \c authIn
    \return other error code on failure

    \param eax AES EAX structure holding the context of the AEAD operation
    \param authIn input auth tag to check computed auth tag against
    \param authInSz size in bytes of \c authIn

    _Example_
    \code
    AesEax eax;
    key[]   = { some 16, 24, or 32 byte length key };
    nonce[] = { some arbitrary length nonce };
    authIn[] = { some data to add to the authentication stream };
    cipherText[] = {some encrypted data};

    plainText[sizeof(cipherText)]; // buffer to hold decrypted data
    // auth tag is generated elsewhere by the encrypt AEAD operation
    authTag[length, up to AES_BLOCK_SIZE] = { the auth tag };

    AesEax eax;

    if ((ret = wc_AesEaxInit(eax,
                             key, keySz,
                             nonce, nonceSz,
                             authIn, authInSz)) != 0) {
        goto cleanup;
    }

    // if we wanted to add more auth data, we could provide it at this point,
    // otherwise we use NULL for the authIn parameter, with authInSz of 0
    if ((ret = wc_AesEaxDecryptUpdate(eax,
                                      plainText, cipherText, sizeof(cipherText),
                                      NULL, 0)) != 0) {
        goto cleanup;
    }

    if ((ret = wc_AesEaxDecryptFinal(eax, authTag, sizeof(authTag))) != 0) {
        goto cleanup;
    }

    cleanup:
        wc_AesEaxFree(eax);
    \endcode

    \sa wc_AesEaxInit
    \sa wc_AesEaxEncryptUpdate
    \sa wc_AesEaxDecryptUpdate
    \sa wc_AesEaxAuthDataUpdate
    \sa wc_AesEaxEncryptFinal
    \sa wc_AesEaxFree

*/
WOLFSSL_API int wc_AesEaxDecryptFinal(AesEax* eax,
                                      const byte* authIn, word32 authInSz);
/*!
    \ingroup AES

    \brief This frees up any resources, specifically keys, used by the Aes
    instance inside the AesEax wrapper struct. It should be called on the
    AesEax struct after it has been initialized with wc_AesEaxInit, and all
    desired EAX operations are complete.

    \return 0 Success

    \param eaxAES EAX instance to free

    _Example_
    \code
    AesEax eax;

    if(wc_AesEaxInit(eax, key, keySz, nonce, nonceSz, authIn, authInSz) != 0) {
        // handle errors, then free
        wc_AesEaxFree(&eax);
    }
    \endcode

    \sa wc_AesEaxInit
    \sa wc_AesEaxEncryptUpdate
    \sa wc_AesEaxDecryptUpdate
    \sa wc_AesEaxAuthDataUpdate
    \sa wc_AesEaxEncryptFinal
    \sa wc_AesEaxDecryptFinal
*/
WOLFSSL_API int wc_AesEaxFree(AesEax* eax);

/*!
    \ingroup AES
    \brief This function performs AES encryption using Ciphertext Stealing (CTS)
    mode. It is a one-shot API that handles all operations in a single call.

    \return 0 on successful encryption.
    \return BAD_FUNC_ARG if input arguments are invalid.
    \return other negative error codes for encryption failures.

    \param [in] key pointer to the AES key used for encryption.
    \param [in] keySz size of the AES key in bytes (16, 24, or 32 bytes).
    \param[out] out buffer to hold the encrypted ciphertext. Must be at least
    the size of the input.
    \param [in] in pointer to the plaintext input data to encrypt.
    \param [in] inSz size of the plaintext input data in bytes.
    \param [in] iv pointer to the initialization vector (IV) used for encryption.
    Must be 16 bytes.

    _Example_
    \code
        byte key[16] = { 0 };
        byte iv[16] = { 0 };
        byte plaintext[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
        byte ciphertext[sizeof(plaintext)];

        int ret = wc_AesCtsEncrypt(key, sizeof(key), ciphertext, plaintext,
            sizeof(plaintext), iv);
        if (ret != 0) {
        // handle encryption error
    }
    \endcode

    \sa wc_AesCtsDecrypt
*/
int wc_AesCtsEncrypt(const byte* key, word32 keySz, byte* out,
                     const byte* in, word32 inSz,
                     const byte* iv);

/*!
    \ingroup AES
    \brief This function performs AES encryption using Ciphertext Stealing (CTS)
     mode. It is a one-shot API that handles all operations in a single call.

    \return 0 on successful encryption.
    \return BAD_FUNC_ARG if input arguments are invalid.
    \return other negative error codes for encryption failures.

    \param [in] key pointer to the AES key used for encryption.
    \param [in] keySz size of the AES key in bytes (16, 24, or 32 bytes).
    \param[out] out buffer to hold the encrypted ciphertext. Must be at least
                 the same size as the input plaintext.
    \param [in] in pointer to the plaintext input data to encrypt.
    \param [in] inSz size of the plaintext input data in bytes.
    \param [in] iv pointer to the initialization vector (IV) used for encryption.
             Must be 16 bytes.
    _Example_
    \code
        byte key[16] = { 0 };
        byte iv[16] = { 0 };
        byte plaintext[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
        byte ciphertext[sizeof(plaintext)];
        int ret = wc_AesCtsEncrypt(key, sizeof(key), ciphertext, plaintext,
                                   sizeof(plaintext), iv);
        if (ret != 0) {
            // handle encryption error
        }
    \endcode
    \sa wc_AesCtsDecrypt
*/
int wc_AesCtsEncrypt(const byte* key, word32 keySz, byte* out,
                     const byte* in, word32 inSz,
                     const byte* iv);

/*!
    \ingroup AES
    \brief This function performs AES decryption using Ciphertext Stealing (CTS) mode.
           It is a one-shot API that handles all operations in a single call.
    \return 0 on successful decryption.
    \return BAD_FUNC_ARG if input arguments are invalid.
    \return other negative error codes for decryption failures.
    \param [in] key pointer to the AES key used for decryption.
    \param [in] keySz size of the AES key in bytes (16, 24, or 32 bytes).
    \param[out] out buffer to hold the decrypted plaintext. Must be at least
                 the same size as the input ciphertext.
    \param [in] in pointer to the ciphertext input data to decrypt.
    \param [in] inSz size of the ciphertext input data in bytes.
    \param [in] iv pointer to the initialization vector (IV) used for decryption.
             Must be 16 bytes.
    _Example_
    \code
        byte key[16] = { 0 };
        byte iv[16] = { 0 };
        byte ciphertext[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
        byte plaintext[sizeof(ciphertext)];
        int ret = wc_AesCtsDecrypt(key, sizeof(key), plaintext, ciphertext,
                                   sizeof(ciphertext), iv);
        if (ret != 0) {
            // handle decryption error
        }
    \endcode
    \sa wc_AesCtsEncrypt
*/
int wc_AesCtsDecrypt(const byte* key, word32 keySz, byte* out,
                     const byte* in, word32 inSz,
                     const byte* iv);

/*!
    \ingroup AES
    \brief This function performs an update step of the AES CTS encryption.
           It processes a chunk of plaintext and stores intermediate data.
    \return 0 on successful processing.
    \return BAD_FUNC_ARG if input arguments are invalid.
    \param [in] aes pointer to the Aes structure holding the context of the operation.
    \param[out] out buffer to hold the encrypted ciphertext. Must be large enough
                 to store the output from this update step.
    \param[out] outSz size in bytes of the output data written to the \c out buffer.
                    On input, it should contain the maximum number of bytes that can
                    be written to the \c out buffer.
    \param [in] in pointer to the plaintext input data to encrypt.
    \param [in] inSz size of the plaintext input data in bytes.
    _Example_
    \code
        Aes aes;
        wc_AesInit(&aes, NULL, INVALID_DEVID);
        byte key[16] = { 0 };
        byte iv[16] = { 0 };
        byte plaintext[] = { ... };
        byte ciphertext[sizeof(plaintext)];
        word32 outSz = sizeof(ciphertext);
        wc_AesSetKey(&aes, key, sizeof(key), iv, AES_ENCRYPTION);
        int ret = wc_AesCtsEncryptUpdate(&aes, ciphertext, &outSz, plaintext, sizeof(plaintext));
        if (ret != 0) {
            // handle error
        }
        wc_AesFree(&aes);
    \endcode
    \sa wc_AesCtsDecryptUpdate
*/
int wc_AesCtsEncryptUpdate(Aes* aes, byte* out, word32* outSz,
                           const byte* in, word32 inSz);

/*!
    \ingroup AES
    \brief This function finalizes the AES CTS encryption operation.
           It processes any remaining plaintext and completes the encryption.
    \return 0 on successful encryption completion.
    \return BAD_FUNC_ARG if input arguments are invalid.
    \param [in] aes pointer to the Aes structure holding the context of the operation.
    \param[out] out buffer to hold the final encrypted ciphertext. Must be large
                 enough to store any remaining ciphertext from this final step.
    \param[out] outSz size in bytes of the output data written to the \c out buffer.
                     On input, it should contain the maximum number of bytes that can
                     be written to the \c out buffer.
    _Example_
    \code
        Aes aes;
        wc_AesInit(&aes, NULL, INVALID_DEVID);
        byte key[16] = { 0 };
        byte iv[16] = { 0 };
        byte plaintext[] = { ... };
        byte ciphertext[sizeof(plaintext)];
        word32 outSz = sizeof(ciphertext);
        wc_AesSetKey(&aes, key, sizeof(key), iv, AES_ENCRYPTION);
        // Perform any required update steps using wc_AesCtsEncryptUpdate
        int ret = wc_AesCtsEncryptFinal(&aes, ciphertext, &outSz);
        if (ret != 0) {
            // handle error
        }
        wc_AesFree(&aes);
    \endcode
    \sa wc_AesCtsDecryptFinal
*/
int wc_AesCtsEncryptFinal(Aes* aes, byte* out, word32* outSz);

/*!
    \ingroup AES
    \brief This function performs an update step of the AES CTS decryption.
           It processes a chunk of ciphertext and stores intermediate data.
    \return 0 on successful processing.
    \return BAD_FUNC_ARG if input arguments are invalid.
    \param [in] aes pointer to the Aes structure holding the context of the operation.
    \param[out] out buffer to hold the decrypted plaintext. Must be large enough
                 to store the output from this update step.
    \param[out] outSz size in bytes of the output data written to the \c out buffer.
                     On input, it should contain the maximum number of bytes that can
                     be written to the \c out buffer.
    \param [in] in pointer to the ciphertext input data to decrypt.
    \param [in] inSz size of the ciphertext input data in bytes.
    _Example_
    \code
        Aes aes;
        wc_AesInit(&aes, NULL, INVALID_DEVID);
        byte key[16] = { 0 };
        byte iv[16] = { 0 };
        byte ciphertext[] = { ... };
        byte plaintext[sizeof(ciphertext)];
        word32 outSz = sizeof(plaintext);
        wc_AesSetKey(&aes, key, sizeof(key), iv, AES_DECRYPTION);
        int ret = wc_AesCtsDecryptUpdate(&aes, plaintext, &outSz, ciphertext, sizeof(ciphertext));
        if (ret != 0) {
            // handle error
        }
        wc_AesFree(&aes);
    \endcode
    \sa wc_AesCtsEncryptUpdate
*/
int wc_AesCtsDecryptUpdate(Aes* aes, byte* out, word32* outSz,
                           const byte* in, word32 inSz);

/*!
    \ingroup AES
    \brief This function finalizes the AES CTS decryption operation.
           It processes any remaining ciphertext and completes the decryption.
    \return 0 on successful decryption completion.
    \return BAD_FUNC_ARG if input arguments are invalid.
    \param [in] aes pointer to the Aes structure holding the context of the operation.
    \param[out] out buffer to hold the final decrypted plaintext. Must be large
                 enough to store any remaining plaintext from this final step.
    \param[out] outSz size in bytes of the output data written to the \c out buffer.
                     On input, it should contain the maximum number of bytes that can
                     be written to the \c out buffer.
    _Example_
    \code
        Aes aes;
        wc_AesInit(&aes, NULL, INVALID_DEVID);
        byte key[16] = { 0 };
        byte iv[16] = { 0 };
        byte ciphertext[] = { ... };
        byte plaintext[sizeof(ciphertext)];
        word32 outSz = sizeof(plaintext);
        wc_AesSetKey(&aes, key, sizeof(key), iv, AES_DECRYPTION);
        // Perform any required update steps using wc_AesCtsDecryptUpdate
        int ret = wc_AesCtsDecryptFinal(&aes, plaintext, &outSz);
        if (ret != 0) {
            // handle error
        }
        wc_AesFree(&aes);
    \endcode
    \sa wc_AesCtsEncryptFinal
*/
int wc_AesCtsDecryptFinal(Aes* aes, byte* out, word32* outSz);


/*!
    \ingroup AES
    \brief This function encrypts data using AES CFB-1 mode (1-bit
    feedback). It processes data one bit at a time, making it suitable
    for bit-oriented applications.

    \return 0 On success.
    \return BAD_FUNC_ARG If aes, out, or in is NULL.
    \return Other negative values on error.

    \param aes pointer to the AES structure containing the key
    \param out pointer to the output buffer to store encrypted data
    \param in pointer to the input buffer containing data to encrypt
    (packed to left, e.g., 101 is 0x90)
    \param sz size of input in bits

    _Example_
    \code
    Aes aes;
    byte key[16] = { }; // 128-bit key
    byte iv[16] = { }; // initialization vector
    byte plaintext[1] = { 0x90 }; // bits 101
    byte ciphertext[1];

    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesSetKey(&aes, key, 16, iv, AES_ENCRYPTION);
    int ret = wc_AesCfb1Encrypt(&aes, ciphertext, plaintext, 3);
    if (ret != 0) {
        // encryption failed
    }
    wc_AesFree(&aes);
    \endcode

    \sa wc_AesCfb1Decrypt
    \sa wc_AesCfb8Encrypt
*/
int wc_AesCfb1Encrypt(Aes* aes, byte* out, const byte* in, word32 sz);

/*!
    \ingroup AES
    \brief This function encrypts data using AES CFB-8 mode (8-bit
    feedback). It processes data one byte at a time, making it suitable
    for byte-oriented stream encryption.

    \return 0 On success.
    \return BAD_FUNC_ARG If aes, out, or in is NULL.
    \return Other negative values on error.

    \param aes pointer to the AES structure containing the key
    \param out pointer to the output buffer to store encrypted data
    \param in pointer to the input buffer containing data to encrypt
    \param sz size of input in bytes

    _Example_
    \code
    Aes aes;
    byte key[16] = { }; // 128-bit key
    byte iv[16] = { }; // initialization vector
    byte plaintext[10] = { }; // data to encrypt
    byte ciphertext[10];

    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesSetKey(&aes, key, 16, iv, AES_ENCRYPTION);
    int ret = wc_AesCfb8Encrypt(&aes, ciphertext, plaintext, 10);
    if (ret != 0) {
        // encryption failed
    }
    wc_AesFree(&aes);
    \endcode

    \sa wc_AesCfb8Decrypt
    \sa wc_AesCfb1Encrypt
*/
int wc_AesCfb8Encrypt(Aes* aes, byte* out, const byte* in, word32 sz);

/*!
    \ingroup AES
    \brief This function decrypts data using AES CFB-1 mode (1-bit
    feedback). It processes data one bit at a time, making it suitable
    for bit-oriented applications.

    \return 0 On success.
    \return BAD_FUNC_ARG If aes, out, or in is NULL.
    \return Other negative values on error.

    \param aes pointer to the AES structure containing the key
    \param out pointer to the output buffer to store decrypted data
    \param in pointer to the input buffer containing data to decrypt
    \param sz size of input in bits

    _Example_
    \code
    Aes aes;
    byte key[16] = { }; // 128-bit key
    byte iv[16] = { }; // initialization vector
    byte ciphertext[1] = { }; // encrypted bits
    byte plaintext[1];

    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesSetKey(&aes, key, 16, iv, AES_ENCRYPTION);
    int ret = wc_AesCfb1Decrypt(&aes, plaintext, ciphertext, 3);
    if (ret != 0) {
        // decryption failed
    }
    wc_AesFree(&aes);
    \endcode

    \sa wc_AesCfb1Encrypt
    \sa wc_AesCfb8Decrypt
*/
int wc_AesCfb1Decrypt(Aes* aes, byte* out, const byte* in, word32 sz);

/*!
    \ingroup AES
    \brief This function decrypts data using AES CFB-8 mode (8-bit
    feedback). It processes data one byte at a time, making it suitable
    for byte-oriented stream decryption.

    \return 0 On success.
    \return BAD_FUNC_ARG If aes, out, or in is NULL.
    \return Other negative values on error.

    \param aes pointer to the AES structure containing the key
    \param out pointer to the output buffer to store decrypted data
    \param in pointer to the input buffer containing data to decrypt
    \param sz size of input in bytes

    _Example_
    \code
    Aes aes;
    byte key[16] = { }; // 128-bit key
    byte iv[16] = { }; // initialization vector
    byte ciphertext[10] = { }; // encrypted data
    byte plaintext[10];

    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesSetKey(&aes, key, 16, iv, AES_ENCRYPTION);
    int ret = wc_AesCfb8Decrypt(&aes, plaintext, ciphertext, 10);
    if (ret != 0) {
        // decryption failed
    }
    wc_AesFree(&aes);
    \endcode

    \sa wc_AesCfb8Encrypt
    \sa wc_AesCfb1Decrypt
*/
int wc_AesCfb8Decrypt(Aes* aes, byte* out, const byte* in, word32 sz);

/*!
    \ingroup AES
    \brief This function encrypts data using AES OFB mode (Output
    Feedback). OFB mode turns a block cipher into a stream cipher by
    encrypting the IV and XORing with plaintext.

    \return 0 On success.
    \return BAD_FUNC_ARG If aes, out, or in is NULL.
    \return Other negative values on error.

    \param aes pointer to the AES structure containing the key
    \param out pointer to the output buffer to store encrypted data
    \param in pointer to the input buffer containing data to encrypt
    \param sz size of input in bytes

    _Example_
    \code
    Aes aes;
    byte key[16] = { }; // 128-bit key
    byte iv[16] = { }; // initialization vector
    byte plaintext[100] = { }; // data to encrypt
    byte ciphertext[100];

    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesSetKey(&aes, key, 16, iv, AES_ENCRYPTION);
    int ret = wc_AesOfbEncrypt(&aes, ciphertext, plaintext, 100);
    if (ret != 0) {
        // encryption failed
    }
    wc_AesFree(&aes);
    \endcode

    \sa wc_AesOfbDecrypt
    \sa wc_AesSetKey
*/
int wc_AesOfbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz);

/*!
    \ingroup AES
    \brief This function decrypts data using AES OFB mode (Output
    Feedback). In OFB mode, encryption and decryption are the same
    operation.

    \return 0 On success.
    \return BAD_FUNC_ARG If aes, out, or in is NULL.
    \return Other negative values on error.

    \param aes pointer to the AES structure containing the key
    \param out pointer to the output buffer to store decrypted data
    \param in pointer to the input buffer containing data to decrypt
    \param sz size of input in bytes

    _Example_
    \code
    Aes aes;
    byte key[16] = { }; // 128-bit key
    byte iv[16] = { }; // initialization vector
    byte ciphertext[100] = { }; // encrypted data
    byte plaintext[100];

    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesSetKey(&aes, key, 16, iv, AES_ENCRYPTION);
    int ret = wc_AesOfbDecrypt(&aes, plaintext, ciphertext, 100);
    if (ret != 0) {
        // decryption failed
    }
    wc_AesFree(&aes);
    \endcode

    \sa wc_AesOfbEncrypt
    \sa wc_AesSetKey
*/
int wc_AesOfbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz);

/*!
    \ingroup AES
    \brief This function encrypts data using AES ECB mode (Electronic
    Codebook). Warning: ECB mode is not recommended for most use cases
    as it does not provide semantic security. Each block is encrypted
    independently.

    \return 0 On success.
    \return BAD_FUNC_ARG If aes, out, or in is NULL.
    \return Other negative values on error.

    \param aes pointer to the AES structure containing the key
    \param out pointer to the output buffer to store encrypted data
    \param in pointer to the input buffer containing data to encrypt
    \param sz size of input in bytes (must be multiple of AES_BLOCK_SIZE)

    _Example_
    \code
    Aes aes;
    byte key[16] = { }; // 128-bit key
    byte plaintext[32] = { }; // data to encrypt
    byte ciphertext[32];

    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesSetKey(&aes, key, 16, NULL, AES_ENCRYPTION);
    int ret = wc_AesEcbEncrypt(&aes, ciphertext, plaintext, 32);
    if (ret != 0) {
        // encryption failed
    }
    wc_AesFree(&aes);
    \endcode

    \sa wc_AesEcbDecrypt
    \sa wc_AesSetKey
*/
int wc_AesEcbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz);

/*!
    \ingroup AES
    \brief This function decrypts data using AES ECB mode (Electronic
    Codebook). Warning: ECB mode is not recommended for most use cases
    as it does not provide semantic security. Each block is decrypted
    independently.

    \return 0 On success.
    \return BAD_FUNC_ARG If aes, out, or in is NULL.
    \return Other negative values on error.

    \param aes pointer to the AES structure containing the key
    \param out pointer to the output buffer to store decrypted data
    \param in pointer to the input buffer containing data to decrypt
    \param sz size of input in bytes (must be multiple of AES_BLOCK_SIZE)

    _Example_
    \code
    Aes aes;
    byte key[16] = { }; // 128-bit key
    byte ciphertext[32] = { }; // encrypted data
    byte plaintext[32];

    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesSetKey(&aes, key, 16, NULL, AES_DECRYPTION);
    int ret = wc_AesEcbDecrypt(&aes, plaintext, ciphertext, 32);
    if (ret != 0) {
        // decryption failed
    }
    wc_AesFree(&aes);
    \endcode

    \sa wc_AesEcbEncrypt
    \sa wc_AesSetKey
*/
int wc_AesEcbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz);

/*!
    \ingroup AES
    \brief This function sets the key and IV for AES CTR mode. It
    initializes the AES structure for counter mode encryption or
    decryption.

    \return 0 On success.
    \return BAD_FUNC_ARG If aes, key, or iv is NULL, or if key length
    is invalid.

    \param aes pointer to the AES structure to initialize
    \param key pointer to the key buffer (16, 24, or 32 bytes)
    \param len length of the key in bytes
    \param iv pointer to the initialization vector (16 bytes)
    \param dir cipher direction (always use AES_ENCRYPTION for CTR mode)

    _Example_
    \code
    Aes aes;
    byte key[16] = { }; // 128-bit key
    byte iv[16] = { }; // initialization vector

    wc_AesInit(&aes, NULL, INVALID_DEVID);
    int ret = wc_AesCtrSetKey(&aes, key, 16, iv, AES_ENCRYPTION);
    if (ret != 0) {
        // failed to set key
    }
    wc_AesFree(&aes);
    \endcode

    \sa wc_AesCtrEncrypt
    \sa wc_AesSetKey
*/
int wc_AesCtrSetKey(Aes* aes, const byte* key, word32 len, const byte* iv,
                    int dir);

/*!
    \ingroup AES
    \brief This function sets the key for AES GCM with an extended key
    update parameter. It allows for key updates in certain hardware
    implementations.

    \return 0 On success.
    \return BAD_FUNC_ARG If aes or key is NULL, or if key length is invalid.

    \param aes pointer to the AES structure to initialize
    \param key pointer to the key buffer (16, 24, or 32 bytes)
    \param len length of the key in bytes
    \param kup key update parameter for hardware implementations

    _Example_
    \code
    Aes aes;
    byte key[16] = { }; // 128-bit key

    wc_AesInit(&aes, NULL, INVALID_DEVID);
    int ret = wc_AesGcmSetKey_ex(&aes, key, 16, 0);
    if (ret != 0) {
        // failed to set key
    }
    wc_AesFree(&aes);
    \endcode

    \sa wc_AesGcmSetKey
    \sa wc_AesGcmInit
*/
int wc_AesGcmSetKey_ex(Aes* aes, const byte* key, word32 len, word32 kup);

/*!
    \ingroup AES
    \brief This function initializes an AES GCM cipher with key and IV.
    It can be called with NULL key to only set the IV, or with NULL IV
    to only set the key.

    \return 0 On success.
    \return BAD_FUNC_ARG If aes is NULL, or if parameters are invalid.
    \return MEMORY_E If dynamic memory allocation fails.

    \param aes pointer to the AES structure to initialize
    \param key pointer to the key buffer, or NULL to skip key setting
    \param len length of the key in bytes
    \param iv pointer to the IV/nonce buffer, or NULL to skip IV setting
    \param ivSz length of the IV/nonce in bytes

    _Example_
    \code
    Aes aes;
    byte key[16] = { }; // 128-bit key
    byte iv[12] = { }; // 96-bit nonce

    wc_AesInit(&aes, NULL, INVALID_DEVID);
    int ret = wc_AesGcmInit(&aes, key, 16, iv, 12);
    if (ret != 0) {
        // failed to initialize
    }
    wc_AesFree(&aes);
    \endcode

    \sa wc_AesGcmSetKey
    \sa wc_AesGcmEncrypt
*/
int wc_AesGcmInit(Aes* aes, const byte* key, word32 len, const byte* iv,
                  word32 ivSz);

/*!
    \ingroup AES
    \brief This function initializes an AES GCM cipher for encryption.
    It is a convenience wrapper around wc_AesGcmInit for encryption
    operations.

    \return 0 On success.
    \return BAD_FUNC_ARG If aes is NULL, or if parameters are invalid.

    \param aes pointer to the AES structure to initialize
    \param key pointer to the key buffer, or NULL to skip key setting
    \param len length of the key in bytes
    \param iv pointer to the IV/nonce buffer, or NULL to skip IV setting
    \param ivSz length of the IV/nonce in bytes

    _Example_
    \code
    Aes aes;
    byte key[16] = { }; // 128-bit key
    byte iv[12] = { }; // 96-bit nonce

    wc_AesInit(&aes, NULL, INVALID_DEVID);
    int ret = wc_AesGcmEncryptInit(&aes, key, 16, iv, 12);
    if (ret != 0) {
        // failed to initialize
    }
    wc_AesFree(&aes);
    \endcode

    \sa wc_AesGcmInit
    \sa wc_AesGcmEncryptUpdate
*/
int wc_AesGcmEncryptInit(Aes* aes, const byte* key, word32 len,
                         const byte* iv, word32 ivSz);

/*!
    \ingroup AES
    \brief This function initializes an AES GCM cipher for encryption and
    outputs the IV. This is useful when part of the IV is generated
    internally. Must call wc_AesGcmSetIV() before this function to set
    the fixed part of the IV.

    \return 0 On success.
    \return BAD_FUNC_ARG If aes, ivOut is NULL, or if ivOutSz doesn't
    match the cached nonce size.

    \param aes pointer to the AES structure to initialize
    \param key pointer to the key buffer, or NULL to skip key setting
    \param len length of the key in bytes
    \param ivOut pointer to buffer to receive the complete IV
    \param ivOutSz length of the IV output buffer in bytes

    _Example_
    \code
    Aes aes;
    byte key[16] = { }; // 128-bit key
    byte ivFixed[4] = { }; // fixed part of IV
    byte ivOut[12];
    WC_RNG rng;

    wc_InitRng(&rng);
    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesGcmSetIV(&aes, 12, ivFixed, 4, &rng);
    int ret = wc_AesGcmEncryptInit_ex(&aes, key, 16, ivOut, 12);
    if (ret != 0) {
        // failed to initialize
    }
    wc_AesFree(&aes);
    wc_FreeRng(&rng);
    \endcode

    \sa wc_AesGcmSetIV
    \sa wc_AesGcmEncryptUpdate
*/
int wc_AesGcmEncryptInit_ex(Aes* aes, const byte* key, word32 len,
                            byte* ivOut, word32 ivOutSz);

/*!
    \ingroup AES
    \brief This function performs an update step of AES GCM encryption.
    It processes plaintext and/or additional authentication data (AAD)
    in a streaming fashion.

    \return 0 On success.
    \return BAD_FUNC_ARG If aes is NULL, or if parameters are invalid.

    \param aes pointer to the AES structure
    \param out pointer to buffer to store ciphertext (can be NULL if sz=0)
    \param in pointer to plaintext to encrypt (can be NULL if sz=0)
    \param sz length of plaintext in bytes
    \param authIn pointer to additional authentication data (can be NULL)
    \param authInSz length of AAD in bytes

    _Example_
    \code
    Aes aes;
    byte key[16] = { }; // 128-bit key
    byte iv[12] = { }; // nonce
    byte plaintext[100] = { }; // data
    byte ciphertext[100];
    byte aad[20] = { }; // additional data

    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesGcmEncryptInit(&aes, key, 16, iv, 12);
    int ret = wc_AesGcmEncryptUpdate(&aes, ciphertext, plaintext, 100,
                                     aad, 20);
    if (ret != 0) {
        // encryption failed
    }
    wc_AesFree(&aes);
    \endcode

    \sa wc_AesGcmEncryptInit
    \sa wc_AesGcmEncryptFinal
*/
int wc_AesGcmEncryptUpdate(Aes* aes, byte* out, const byte* in, word32 sz,
                           const byte* authIn, word32 authInSz);

/*!
    \ingroup AES
    \brief This function finalizes AES GCM encryption and generates the
    authentication tag. This must be called after all data has been
    processed with wc_AesGcmEncryptUpdate.

    \return 0 On success.
    \return BAD_FUNC_ARG If aes or authTag is NULL, or if authTagSz is
    invalid.

    \param aes pointer to the AES structure
    \param authTag pointer to buffer to store the authentication tag
    \param authTagSz length of the authentication tag in bytes (typically
    12 or 16)

    _Example_
    \code
    Aes aes;
    byte key[16] = { }; // 128-bit key
    byte iv[12] = { }; // nonce
    byte plaintext[100] = { }; // data
    byte ciphertext[100];
    byte authTag[16];

    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesGcmEncryptInit(&aes, key, 16, iv, 12);
    wc_AesGcmEncryptUpdate(&aes, ciphertext, plaintext, 100, NULL, 0);
    int ret = wc_AesGcmEncryptFinal(&aes, authTag, 16);
    if (ret != 0) {
        // failed to generate tag
    }
    wc_AesFree(&aes);
    \endcode

    \sa wc_AesGcmEncryptUpdate
    \sa wc_AesGcmDecryptFinal
*/
int wc_AesGcmEncryptFinal(Aes* aes, byte* authTag, word32 authTagSz);

/*!
    \ingroup AES
    \brief This function initializes an AES GCM cipher for decryption.
    It is a convenience wrapper around wc_AesGcmInit for decryption
    operations.

    \return 0 On success.
    \return BAD_FUNC_ARG If aes is NULL, or if parameters are invalid.

    \param aes pointer to the AES structure to initialize
    \param key pointer to the key buffer, or NULL to skip key setting
    \param len length of the key in bytes
    \param iv pointer to the IV/nonce buffer, or NULL to skip IV setting
    \param ivSz length of the IV/nonce in bytes

    _Example_
    \code
    Aes aes;
    byte key[16] = { }; // 128-bit key
    byte iv[12] = { }; // 96-bit nonce

    wc_AesInit(&aes, NULL, INVALID_DEVID);
    int ret = wc_AesGcmDecryptInit(&aes, key, 16, iv, 12);
    if (ret != 0) {
        // failed to initialize
    }
    wc_AesFree(&aes);
    \endcode

    \sa wc_AesGcmInit
    \sa wc_AesGcmDecryptUpdate
*/
int wc_AesGcmDecryptInit(Aes* aes, const byte* key, word32 len,
                         const byte* iv, word32 ivSz);

/*!
    \ingroup AES
    \brief This function performs an update step of AES GCM decryption.
    It processes ciphertext and/or additional authentication data (AAD)
    in a streaming fashion.

    \return 0 On success.
    \return BAD_FUNC_ARG If aes is NULL, or if parameters are invalid.

    \param aes pointer to the AES structure
    \param out pointer to buffer to store plaintext (can be NULL if sz=0)
    \param in pointer to ciphertext to decrypt (can be NULL if sz=0)
    \param sz length of ciphertext in bytes
    \param authIn pointer to additional authentication data (can be NULL)
    \param authInSz length of AAD in bytes

    _Example_
    \code
    Aes aes;
    byte key[16] = { }; // 128-bit key
    byte iv[12] = { }; // nonce
    byte ciphertext[100] = { }; // encrypted data
    byte plaintext[100];
    byte aad[20] = { }; // additional data

    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesGcmDecryptInit(&aes, key, 16, iv, 12);
    int ret = wc_AesGcmDecryptUpdate(&aes, plaintext, ciphertext, 100,
                                     aad, 20);
    if (ret != 0) {
        // decryption failed
    }
    wc_AesFree(&aes);
    \endcode

    \sa wc_AesGcmDecryptInit
    \sa wc_AesGcmDecryptFinal
*/
int wc_AesGcmDecryptUpdate(Aes* aes, byte* out, const byte* in, word32 sz,
                           const byte* authIn, word32 authInSz);

/*!
    \ingroup AES
    \brief This function finalizes AES GCM decryption and verifies the
    authentication tag. This must be called after all data has been
    processed with wc_AesGcmDecryptUpdate.

    \return 0 On success.
    \return AES_GCM_AUTH_E If authentication tag verification fails.
    \return BAD_FUNC_ARG If aes or authTag is NULL, or if authTagSz is
    invalid.

    \param aes pointer to the AES structure
    \param authTag pointer to the authentication tag to verify
    \param authTagSz length of the authentication tag in bytes

    _Example_
    \code
    Aes aes;
    byte key[16] = { }; // 128-bit key
    byte iv[12] = { }; // nonce
    byte ciphertext[100] = { }; // encrypted data
    byte plaintext[100];
    byte authTag[16] = { }; // received tag

    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesGcmDecryptInit(&aes, key, 16, iv, 12);
    wc_AesGcmDecryptUpdate(&aes, plaintext, ciphertext, 100, NULL, 0);
    int ret = wc_AesGcmDecryptFinal(&aes, authTag, 16);
    if (ret != 0) {
        // authentication failed
    }
    wc_AesFree(&aes);
    \endcode

    \sa wc_AesGcmDecryptUpdate
    \sa wc_AesGcmEncryptFinal
*/
int wc_AesGcmDecryptFinal(Aes* aes, const byte* authTag, word32 authTagSz);

/*!
    \ingroup AES
    \brief This function sets an external IV for AES GCM. This allows
    using an IV that was generated externally or received from another
    source.

    \return 0 On success.
    \return BAD_FUNC_ARG If aes or iv is NULL, or if ivSz is invalid.

    \param aes pointer to the AES structure
    \param iv pointer to the IV/nonce buffer
    \param ivSz length of the IV/nonce in bytes

    _Example_
    \code
    Aes aes;
    byte key[16] = { }; // 128-bit key
    byte iv[12] = { }; // external nonce

    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesGcmSetKey(&aes, key, 16);
    int ret = wc_AesGcmSetExtIV(&aes, iv, 12);
    if (ret != 0) {
        // failed to set IV
    }
    wc_AesFree(&aes);
    \endcode

    \sa wc_AesGcmSetIV
    \sa wc_AesGcmInit
*/
int wc_AesGcmSetExtIV(Aes* aes, const byte* iv, word32 ivSz);

/*!
    \ingroup AES
    \brief This function sets the IV for AES GCM with optional random
    generation. It can generate part of the IV using an RNG, which is
    useful for ensuring IV uniqueness.

    \return 0 On success.
    \return BAD_FUNC_ARG If aes is NULL, or if parameters are invalid.
    \return Other negative values on RNG or other errors.

    \param aes pointer to the AES structure
    \param ivSz total length of the IV/nonce in bytes
    \param ivFixed pointer to the fixed part of the IV (can be NULL)
    \param ivFixedSz length of the fixed part in bytes
    \param rng pointer to initialized RNG for generating random part
    (can be NULL if ivFixedSz equals ivSz)

    _Example_
    \code
    Aes aes;
    byte key[16] = { }; // 128-bit key
    byte ivFixed[4] = { }; // fixed part
    WC_RNG rng;

    wc_InitRng(&rng);
    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesGcmSetKey(&aes, key, 16);
    int ret = wc_AesGcmSetIV(&aes, 12, ivFixed, 4, &rng);
    if (ret != 0) {
        // failed to set IV
    }
    wc_AesFree(&aes);
    wc_FreeRng(&rng);
    \endcode

    \sa wc_AesGcmSetExtIV
    \sa wc_AesGcmEncryptInit_ex
*/
int wc_AesGcmSetIV(Aes* aes, word32 ivSz, const byte* ivFixed,
                   word32 ivFixedSz, WC_RNG* rng);

/*!
    \ingroup AES
    \brief This function performs AES GCM encryption with extended
    parameters, including IV output. This is a one-shot encryption
    function that outputs the generated IV.

    \return 0 On success.
    \return BAD_FUNC_ARG If parameters are invalid.
    \return Other negative values on error.

    \param aes pointer to the AES structure
    \param out pointer to buffer to store ciphertext
    \param in pointer to plaintext to encrypt
    \param sz length of plaintext in bytes
    \param ivOut pointer to buffer to receive the IV
    \param ivOutSz length of the IV output buffer in bytes
    \param authTag pointer to buffer to store authentication tag
    \param authTagSz length of authentication tag in bytes
    \param authIn pointer to additional authentication data
    \param authInSz length of AAD in bytes

    _Example_
    \code
    Aes aes;
    byte key[16] = { }; // 128-bit key
    byte ivFixed[4] = { }; // fixed part
    byte ivOut[12];
    byte plaintext[100] = { }; // data
    byte ciphertext[100];
    byte authTag[16];
    WC_RNG rng;

    wc_InitRng(&rng);
    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesGcmSetKey(&aes, key, 16);
    wc_AesGcmSetIV(&aes, 12, ivFixed, 4, &rng);
    int ret = wc_AesGcmEncrypt_ex(&aes, ciphertext, plaintext, 100,
                                  ivOut, 12, authTag, 16, NULL, 0);
    if (ret != 0) {
        // encryption failed
    }
    wc_AesFree(&aes);
    wc_FreeRng(&rng);
    \endcode

    \sa wc_AesGcmEncrypt
    \sa wc_AesGcmSetIV
*/
int wc_AesGcmEncrypt_ex(Aes* aes, byte* out, const byte* in, word32 sz,
                        byte* ivOut, word32 ivOutSz, byte* authTag,
                        word32 authTagSz, const byte* authIn,
                        word32 authInSz);

/*!
    \ingroup AES
    \brief This function performs GMAC (Galois Message Authentication Code)
    generation. GMAC is essentially AES-GCM with no plaintext, used for
    authentication only.

    \return 0 On success.
    \return BAD_FUNC_ARG If parameters are invalid.
    \return Other negative values on error.

    \param key pointer to the key buffer
    \param keySz length of the key in bytes (16, 24, or 32)
    \param iv pointer to the IV/nonce buffer
    \param ivSz length of the IV/nonce in bytes
    \param authIn pointer to data to authenticate
    \param authInSz length of data to authenticate in bytes
    \param authTag pointer to buffer to store authentication tag
    \param authTagSz length of authentication tag in bytes
    \param rng pointer to initialized RNG (can be NULL if IV is complete)

    _Example_
    \code
    byte key[16] = { }; // 128-bit key
    byte iv[12] = { }; // nonce
    byte data[100] = { }; // data to authenticate
    byte authTag[16];

    int ret = wc_Gmac(key, 16, iv, 12, data, 100, authTag, 16, NULL);
    if (ret != 0) {
        // GMAC generation failed
    }
    \endcode

    \sa wc_GmacVerify
    \sa wc_AesGcmEncrypt
*/
int wc_Gmac(const byte* key, word32 keySz, byte* iv, word32 ivSz,
            const byte* authIn, word32 authInSz, byte* authTag,
            word32 authTagSz, WC_RNG* rng);

/*!
    \ingroup AES
    \brief This function verifies a GMAC (Galois Message Authentication
    Code). It computes the GMAC and compares it with the provided tag.

    \return 0 On successful verification.
    \return AES_GCM_AUTH_E If authentication tag verification fails.
    \return BAD_FUNC_ARG If parameters are invalid.
    \return Other negative values on error.

    \param key pointer to the key buffer
    \param keySz length of the key in bytes (16, 24, or 32)
    \param iv pointer to the IV/nonce buffer
    \param ivSz length of the IV/nonce in bytes
    \param authIn pointer to data to authenticate
    \param authInSz length of data to authenticate in bytes
    \param authTag pointer to the authentication tag to verify
    \param authTagSz length of authentication tag in bytes

    _Example_
    \code
    byte key[16] = { }; // 128-bit key
    byte iv[12] = { }; // nonce
    byte data[100] = { }; // data to authenticate
    byte authTag[16] = { }; // received tag

    int ret = wc_GmacVerify(key, 16, iv, 12, data, 100, authTag, 16);
    if (ret != 0) {
        // GMAC verification failed
    }
    \endcode

    \sa wc_Gmac
    \sa wc_AesGcmDecrypt
*/
int wc_GmacVerify(const byte* key, word32 keySz, const byte* iv,
                  word32 ivSz, const byte* authIn, word32 authInSz,
                  const byte* authTag, word32 authTagSz);

/*!
    \ingroup AES
    \brief This function sets the nonce for AES CCM mode. The nonce must
    be set before encryption or decryption operations.

    \return 0 On success.
    \return BAD_FUNC_ARG If aes or nonce is NULL, or if nonceSz is invalid.

    \param aes pointer to the AES structure
    \param nonce pointer to the nonce buffer
    \param nonceSz length of the nonce in bytes (7-13 bytes for CCM)

    _Example_
    \code
    Aes aes;
    byte key[16] = { }; // 128-bit key
    byte nonce[12] = { }; // nonce

    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesCcmSetKey(&aes, key, 16);
    int ret = wc_AesCcmSetNonce(&aes, nonce, 12);
    if (ret != 0) {
        // failed to set nonce
    }
    wc_AesFree(&aes);
    \endcode

    \sa wc_AesCcmEncrypt
    \sa wc_AesCcmSetKey
*/
int wc_AesCcmSetNonce(Aes* aes, const byte* nonce, word32 nonceSz);

/*!
    \ingroup AES
    \brief This function performs AES CCM encryption with extended
    parameters, including nonce output. This is useful when part of the
    nonce is generated internally.

    \return 0 On success.
    \return BAD_FUNC_ARG If parameters are invalid.
    \return Other negative values on error.

    \param aes pointer to the AES structure
    \param out pointer to buffer to store ciphertext
    \param in pointer to plaintext to encrypt
    \param sz length of plaintext in bytes
    \param ivOut pointer to buffer to receive the nonce
    \param ivOutSz length of the nonce output buffer in bytes
    \param authTag pointer to buffer to store authentication tag
    \param authTagSz length of authentication tag in bytes
    \param authIn pointer to additional authentication data
    \param authInSz length of AAD in bytes

    _Example_
    \code
    Aes aes;
    byte key[16] = { }; // 128-bit key
    byte nonce[12];
    byte plaintext[100] = { }; // data
    byte ciphertext[100];
    byte authTag[16];

    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesCcmSetKey(&aes, key, 16);
    int ret = wc_AesCcmEncrypt_ex(&aes, ciphertext, plaintext, 100,
                                  nonce, 12, authTag, 16, NULL, 0);
    if (ret != 0) {
        // encryption failed
    }
    wc_AesFree(&aes);
    \endcode

    \sa wc_AesCcmEncrypt
    \sa wc_AesCcmSetNonce
*/
int wc_AesCcmEncrypt_ex(Aes* aes, byte* out, const byte* in, word32 sz,
                        byte* ivOut, word32 ivOutSz, byte* authTag,
                        word32 authTagSz, const byte* authIn,
                        word32 authInSz);

/*!
    \ingroup AES
    \brief This function wraps a key using AES Key Wrap algorithm
    (RFC 3394). This is commonly used to securely transport
    cryptographic keys.

    \return Length of wrapped key in bytes on success.
    \return BAD_FUNC_ARG If parameters are invalid.
    \return Other negative values on error.

    \param key pointer to the key-encryption key
    \param keySz length of the key-encryption key in bytes
    \param in pointer to the key to wrap
    \param inSz length of the key to wrap in bytes
    \param out pointer to buffer to store wrapped key
    \param outSz size of output buffer in bytes
    \param iv pointer to IV (typically NULL to use default)

    _Example_
    \code
    byte kek[16] = { }; // key-encryption key
    byte keyToWrap[16] = { }; // key to wrap
    byte wrappedKey[24];

    int wrappedLen = wc_AesKeyWrap(kek, 16, keyToWrap, 16, wrappedKey,
                                   24, NULL);
    if (wrappedLen <= 0) {
        // key wrap failed
    }
    \endcode

    \sa wc_AesKeyUnWrap
    \sa wc_AesKeyWrap_ex
*/
int wc_AesKeyWrap(const byte* key, word32 keySz, const byte* in,
                  word32 inSz, byte* out, word32 outSz, const byte* iv);

/*!
    \ingroup AES
    \brief This function wraps a key using AES Key Wrap algorithm with
    an initialized AES structure. This allows reusing the same AES
    structure for multiple wrap operations.

    \return Length of wrapped key in bytes on success.
    \return BAD_FUNC_ARG If parameters are invalid.
    \return Other negative values on error.

    \param aes pointer to initialized AES structure
    \param in pointer to the key to wrap
    \param inSz length of the key to wrap in bytes
    \param out pointer to buffer to store wrapped key
    \param outSz size of output buffer in bytes
    \param iv pointer to IV (typically NULL to use default)

    _Example_
    \code
    Aes aes;
    byte kek[16] = { }; // key-encryption key
    byte keyToWrap[16] = { }; // key to wrap
    byte wrappedKey[24];

    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesSetKey(&aes, kek, 16, NULL, AES_ENCRYPTION);
    int wrappedLen = wc_AesKeyWrap_ex(&aes, keyToWrap, 16, wrappedKey,
                                      24, NULL);
    if (wrappedLen <= 0) {
        // key wrap failed
    }
    wc_AesFree(&aes);
    \endcode

    \sa wc_AesKeyWrap
    \sa wc_AesKeyUnWrap_ex
*/
int wc_AesKeyWrap_ex(Aes *aes, const byte* in, word32 inSz, byte* out,
                     word32 outSz, const byte* iv);

/*!
    \ingroup AES
    \brief This function unwraps a key using AES Key Unwrap algorithm
    (RFC 3394). This is used to securely receive cryptographic keys
    that were wrapped.

    \return Length of unwrapped key in bytes on success.
    \return BAD_FUNC_ARG If parameters are invalid.
    \return Other negative values on error.

    \param key pointer to the key-encryption key
    \param keySz length of the key-encryption key in bytes
    \param in pointer to the wrapped key
    \param inSz length of the wrapped key in bytes
    \param out pointer to buffer to store unwrapped key
    \param outSz size of output buffer in bytes
    \param iv pointer to IV (typically NULL to use default)

    _Example_
    \code
    byte kek[16] = { }; // key-encryption key
    byte wrappedKey[24] = { }; // wrapped key
    byte unwrappedKey[16];

    int unwrappedLen = wc_AesKeyUnWrap(kek, 16, wrappedKey, 24,
                                       unwrappedKey, 16, NULL);
    if (unwrappedLen <= 0) {
        // key unwrap failed
    }
    \endcode

    \sa wc_AesKeyWrap
    \sa wc_AesKeyUnWrap_ex
*/
int wc_AesKeyUnWrap(const byte* key, word32 keySz, const byte* in,
                    word32 inSz, byte* out, word32 outSz, const byte* iv);

/*!
    \ingroup AES
    \brief This function unwraps a key using AES Key Unwrap algorithm
    with an initialized AES structure. This allows reusing the same AES
    structure for multiple unwrap operations.

    \return Length of unwrapped key in bytes on success.
    \return BAD_FUNC_ARG If parameters are invalid.
    \return Other negative values on error.

    \param aes pointer to initialized AES structure
    \param in pointer to the wrapped key
    \param inSz length of the wrapped key in bytes
    \param out pointer to buffer to store unwrapped key
    \param outSz size of output buffer in bytes
    \param iv pointer to IV (typically NULL to use default)

    _Example_
    \code
    Aes aes;
    byte kek[16] = { }; // key-encryption key
    byte wrappedKey[24] = { }; // wrapped key
    byte unwrappedKey[16];

    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesSetKey(&aes, kek, 16, NULL, AES_ENCRYPTION);
    int unwrappedLen = wc_AesKeyUnWrap_ex(&aes, wrappedKey, 24,
                                          unwrappedKey, 16, NULL);
    if (unwrappedLen <= 0) {
        // key unwrap failed
    }
    wc_AesFree(&aes);
    \endcode

    \sa wc_AesKeyUnWrap
    \sa wc_AesKeyWrap_ex
*/
int wc_AesKeyUnWrap_ex(Aes *aes, const byte* in, word32 inSz, byte* out,
                       word32 outSz, const byte* iv);

/*!
    \ingroup AES
    \brief This function encrypts multiple consecutive sectors using AES XTS
    mode. It processes multiple sectors in sequence, automatically
    incrementing the sector number for each sector.

    \return 0 On success.
    \return BAD_FUNC_ARG If aes, out, or in is NULL, or if sectorSz is 0,
    or if sz is less than AES_BLOCK_SIZE.
    \return Other negative values on error.

    \param aes pointer to the XtsAes structure
    \param out pointer to buffer to store encrypted data
    \param in pointer to plaintext data to encrypt
    \param sz total length of data in bytes
    \param sector starting sector number for the tweak
    \param sectorSz size of each sector in bytes

    _Example_
    \code
    XtsAes aes;
    byte key[32] = { }; // 256-bit key
    byte plaintext[1024] = { }; // data
    byte ciphertext[1024];

    wc_AesXtsSetKey(&aes, key, 32, AES_ENCRYPTION, NULL, INVALID_DEVID);
    int ret = wc_AesXtsEncryptConsecutiveSectors(&aes, ciphertext,
                                                 plaintext, 1024, 0, 512);
    if (ret != 0) {
        // encryption failed
    }
    wc_AesXtsFree(&aes);
    \endcode

    \sa wc_AesXtsDecryptConsecutiveSectors
    \sa wc_AesXtsEncryptSector
*/
int wc_AesXtsEncryptConsecutiveSectors(XtsAes* aes, byte* out,
                                       const byte* in, word32 sz,
                                       word64 sector, word32 sectorSz);

/*!
    \ingroup AES
    \brief This function decrypts multiple consecutive sectors using AES XTS
    mode. It processes multiple sectors in sequence, automatically
    incrementing the sector number for each sector.

    \return 0 On success.
    \return BAD_FUNC_ARG If aes, out, or in is NULL, or if sectorSz is 0,
    or if sz is less than AES_BLOCK_SIZE.
    \return Other negative values on error.

    \param aes pointer to the XtsAes structure
    \param out pointer to buffer to store decrypted data
    \param in pointer to ciphertext data to decrypt
    \param sz total length of data in bytes
    \param sector starting sector number for the tweak
    \param sectorSz size of each sector in bytes

    _Example_
    \code
    XtsAes aes;
    byte key[32] = { }; // 256-bit key
    byte ciphertext[1024] = { }; // encrypted data
    byte plaintext[1024];

    wc_AesXtsSetKey(&aes, key, 32, AES_DECRYPTION, NULL, INVALID_DEVID);
    int ret = wc_AesXtsDecryptConsecutiveSectors(&aes, plaintext,
                                                 ciphertext, 1024, 0, 512);
    if (ret != 0) {
        // decryption failed
    }
    wc_AesXtsFree(&aes);
    \endcode

    \sa wc_AesXtsEncryptConsecutiveSectors
    \sa wc_AesXtsDecryptSector
*/
int wc_AesXtsDecryptConsecutiveSectors(XtsAes* aes, byte* out,
                                       const byte* in, word32 sz,
                                       word64 sector, word32 sectorSz);

/*!
    \ingroup AES
    \brief This function initializes streaming AES XTS encryption. It sets
    up the context for processing data in multiple update calls.

    \return 0 On success.
    \return BAD_FUNC_ARG If parameters are invalid.

    \param aes pointer to the XtsAes structure
    \param i pointer to the tweak/IV buffer
    \param iSz length of the tweak/IV in bytes
    \param stream pointer to XtsAesStreamData structure for streaming state

    _Example_
    \code
    XtsAes aes;
    struct XtsAesStreamData stream;
    byte key[32] = { }; // 256-bit key
    byte tweak[16] = { }; // tweak value

    wc_AesXtsSetKey(&aes, key, 32, AES_ENCRYPTION, NULL, INVALID_DEVID);
    int ret = wc_AesXtsEncryptInit(&aes, tweak, 16, &stream);
    if (ret != 0) {
        // initialization failed
    }
    wc_AesXtsFree(&aes);
    \endcode

    \sa wc_AesXtsEncryptUpdate
    \sa wc_AesXtsEncryptFinal
*/
int wc_AesXtsEncryptInit(XtsAes* aes, const byte* i, word32 iSz,
                         struct XtsAesStreamData *stream);

/*!
    \ingroup AES
    \brief This function initializes streaming AES XTS decryption. It sets
    up the context for processing data in multiple update calls.

    \return 0 On success.
    \return BAD_FUNC_ARG If parameters are invalid.

    \param aes pointer to the XtsAes structure
    \param i pointer to the tweak/IV buffer
    \param iSz length of the tweak/IV in bytes
    \param stream pointer to XtsAesStreamData structure for streaming state

    _Example_
    \code
    XtsAes aes;
    struct XtsAesStreamData stream;
    byte key[32] = { }; // 256-bit key
    byte tweak[16] = { }; // tweak value

    wc_AesXtsSetKey(&aes, key, 32, AES_DECRYPTION, NULL, INVALID_DEVID);
    int ret = wc_AesXtsDecryptInit(&aes, tweak, 16, &stream);
    if (ret != 0) {
        // initialization failed
    }
    wc_AesXtsFree(&aes);
    \endcode

    \sa wc_AesXtsDecryptUpdate
    \sa wc_AesXtsDecryptFinal
*/
int wc_AesXtsDecryptInit(XtsAes* aes, const byte* i, word32 iSz,
                         struct XtsAesStreamData *stream);

/*!
    \ingroup AES
    \brief This function performs an update step of streaming AES XTS
    encryption. It processes a chunk of data and can be called multiple
    times.

    \return 0 On success.
    \return BAD_FUNC_ARG If parameters are invalid.

    \param aes pointer to the XtsAes structure
    \param out pointer to buffer to store encrypted data
    \param in pointer to plaintext data to encrypt
    \param sz length of data in bytes
    \param stream pointer to XtsAesStreamData structure for streaming state

    _Example_
    \code
    XtsAes aes;
    struct XtsAesStreamData stream;
    byte key[32] = { }; // 256-bit key
    byte tweak[16] = { }; // tweak value
    byte plaintext[100] = { }; // data
    byte ciphertext[100];

    wc_AesXtsSetKey(&aes, key, 32, AES_ENCRYPTION, NULL, INVALID_DEVID);
    wc_AesXtsEncryptInit(&aes, tweak, 16, &stream);
    int ret = wc_AesXtsEncryptUpdate(&aes, ciphertext, plaintext, 100,
                                     &stream);
    if (ret != 0) {
        // encryption failed
    }
    wc_AesXtsFree(&aes);
    \endcode

    \sa wc_AesXtsEncryptInit
    \sa wc_AesXtsEncryptFinal
*/
int wc_AesXtsEncryptUpdate(XtsAes* aes, byte* out, const byte* in,
                           word32 sz, struct XtsAesStreamData *stream);

/*!
    \ingroup AES
    \brief This function performs an update step of streaming AES XTS
    decryption. It processes a chunk of data and can be called multiple
    times.

    \return 0 On success.
    \return BAD_FUNC_ARG If parameters are invalid.

    \param aes pointer to the XtsAes structure
    \param out pointer to buffer to store decrypted data
    \param in pointer to ciphertext data to decrypt
    \param sz length of data in bytes
    \param stream pointer to XtsAesStreamData structure for streaming state

    _Example_
    \code
    XtsAes aes;
    struct XtsAesStreamData stream;
    byte key[32] = { }; // 256-bit key
    byte tweak[16] = { }; // tweak value
    byte ciphertext[100] = { }; // encrypted data
    byte plaintext[100];

    wc_AesXtsSetKey(&aes, key, 32, AES_DECRYPTION, NULL, INVALID_DEVID);
    wc_AesXtsDecryptInit(&aes, tweak, 16, &stream);
    int ret = wc_AesXtsDecryptUpdate(&aes, plaintext, ciphertext, 100,
                                     &stream);
    if (ret != 0) {
        // decryption failed
    }
    wc_AesXtsFree(&aes);
    \endcode

    \sa wc_AesXtsDecryptInit
    \sa wc_AesXtsDecryptFinal
*/
int wc_AesXtsDecryptUpdate(XtsAes* aes, byte* out, const byte* in,
                           word32 sz, struct XtsAesStreamData *stream);

/*!
    \ingroup AES
    \brief This function finalizes streaming AES XTS encryption. It
    processes any remaining data and completes the encryption operation.

    \return 0 On success.
    \return BAD_FUNC_ARG If parameters are invalid.

    \param aes pointer to the XtsAes structure
    \param out pointer to buffer to store final encrypted data
    \param in pointer to final plaintext data to encrypt
    \param sz length of final data in bytes
    \param stream pointer to XtsAesStreamData structure for streaming state

    _Example_
    \code
    XtsAes aes;
    struct XtsAesStreamData stream;
    byte key[32] = { }; // 256-bit key
    byte tweak[16] = { }; // tweak value
    byte plaintext[50] = { }; // final data
    byte ciphertext[50];

    wc_AesXtsSetKey(&aes, key, 32, AES_ENCRYPTION, NULL, INVALID_DEVID);
    wc_AesXtsEncryptInit(&aes, tweak, 16, &stream);
    // ... update calls ...
    int ret = wc_AesXtsEncryptFinal(&aes, ciphertext, plaintext, 50,
                                    &stream);
    if (ret != 0) {
        // finalization failed
    }
    wc_AesXtsFree(&aes);
    \endcode

    \sa wc_AesXtsEncryptUpdate
    \sa wc_AesXtsEncryptInit
*/
int wc_AesXtsEncryptFinal(XtsAes* aes, byte* out, const byte* in,
                          word32 sz, struct XtsAesStreamData *stream);

/*!
    \ingroup AES
    \brief This function finalizes streaming AES XTS decryption. It
    processes any remaining data and completes the decryption operation.

    \return 0 On success.
    \return BAD_FUNC_ARG If parameters are invalid.

    \param aes pointer to the XtsAes structure
    \param out pointer to buffer to store final decrypted data
    \param in pointer to final ciphertext data to decrypt
    \param sz length of final data in bytes
    \param stream pointer to XtsAesStreamData structure for streaming state

    _Example_
    \code
    XtsAes aes;
    struct XtsAesStreamData stream;
    byte key[32] = { }; // 256-bit key
    byte tweak[16] = { }; // tweak value
    byte ciphertext[50] = { }; // final encrypted data
    byte plaintext[50];

    wc_AesXtsSetKey(&aes, key, 32, AES_DECRYPTION, NULL, INVALID_DEVID);
    wc_AesXtsDecryptInit(&aes, tweak, 16, &stream);
    // ... update calls ...
    int ret = wc_AesXtsDecryptFinal(&aes, plaintext, ciphertext, 50,
                                    &stream);
    if (ret != 0) {
        // finalization failed
    }
    wc_AesXtsFree(&aes);
    \endcode

    \sa wc_AesXtsDecryptUpdate
    \sa wc_AesXtsDecryptInit
*/
int wc_AesXtsDecryptFinal(XtsAes* aes, byte* out, const byte* in,
                          word32 sz, struct XtsAesStreamData *stream);

/*!
    \ingroup AES
    \brief This function retrieves the key size from an initialized AES
    structure. It returns the size of the key currently set in the AES
    object.

    \return 0 On success.
    \return BAD_FUNC_ARG If aes or keySize is NULL.

    \param aes pointer to the AES structure
    \param keySize pointer to word32 to store the key size in bytes

    _Example_
    \code
    Aes aes;
    byte key[16] = { }; // 128-bit key
    word32 keySize;

    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesSetKey(&aes, key, 16, NULL, AES_ENCRYPTION);
    int ret = wc_AesGetKeySize(&aes, &keySize);
    if (ret == 0) {
        // keySize now contains 16
    }
    wc_AesFree(&aes);
    \endcode

    \sa wc_AesSetKey
    \sa wc_AesInit
*/
int wc_AesGetKeySize(Aes* aes, word32* keySize);

/*!
    \ingroup AES
    \brief This function initializes an AES structure with an ID. This is
    useful for tracking or identifying specific AES instances in
    applications that manage multiple AES contexts.

    \note This API is only available when WOLF_PRIVATE_KEY_ID is defined,
    which is set for PKCS11 support.

    \return 0 On success.
    \return BAD_FUNC_ARG If aes or id is NULL, or if len is invalid.

    \param aes pointer to the AES structure to initialize
    \param id pointer to the ID buffer
    \param len length of the ID in bytes
    \param heap pointer to heap hint for memory allocation (can be NULL)
    \param devId device ID for hardware acceleration (use INVALID_DEVID
    for software)

    _Example_
    \code
    Aes aes;
    byte id[8] = { }; // unique identifier

    int ret = wc_AesInit_Id(&aes, id, 8, NULL, INVALID_DEVID);
    if (ret != 0) {
        // initialization failed
    }
    wc_AesFree(&aes);
    \endcode

    \sa wc_AesInit
    \sa wc_AesInit_Label
*/
int wc_AesInit_Id(Aes* aes, unsigned char* id, int len, void* heap,
                  int devId);

/*!
    \ingroup AES
    \brief This function initializes an AES structure with a label string.
    This is useful for tracking or identifying specific AES instances with
    human-readable names.

    \note This API is only available when WOLF_PRIVATE_KEY_ID is defined,
    which is set for PKCS11 support.

    \return 0 On success.
    \return BAD_FUNC_ARG If aes or label is NULL.

    \param aes pointer to the AES structure to initialize
    \param label pointer to the null-terminated label string
    \param heap pointer to heap hint for memory allocation (can be NULL)
    \param devId device ID for hardware acceleration (use INVALID_DEVID
    for software)

    _Example_
    \code
    Aes aes;

    int ret = wc_AesInit_Label(&aes, "MyAESContext", NULL, INVALID_DEVID);
    if (ret != 0) {
        // initialization failed
    }
    wc_AesFree(&aes);
    \endcode

    \sa wc_AesInit
    \sa wc_AesInit_Id
*/
int wc_AesInit_Label(Aes* aes, const char* label, void* heap, int devId);

/*!
    \ingroup AES
    \brief This function allocates and initializes a new AES structure.
    It returns a pointer to the allocated structure, which must be freed
    with wc_AesDelete when no longer needed. These New/Delete functions
    are exposed to support allocation of the structure using dynamic memory
    to provide better ABI compatibility.

    \note This API is only available when WC_NO_CONSTRUCTORS is not defined.
    WC_NO_CONSTRUCTORS is automatically defined when WOLFSSL_NO_MALLOC is
    defined.

    \return Pointer to allocated Aes structure on success.
    \return NULL on allocation failure.

    \param heap pointer to heap hint for memory allocation (can be NULL)
    \param devId device ID for hardware acceleration (use INVALID_DEVID
    for software)
    \param result_code pointer to int to store result code (can be NULL)

    _Example_
    \code
    int result;
    Aes* aes = wc_AesNew(NULL, INVALID_DEVID, &result);
    if (aes == NULL || result != 0) {
        // allocation or initialization failed
    }
    // use aes...
    wc_AesDelete(aes, &aes);
    \endcode

    \sa wc_AesDelete
    \sa wc_AesInit
*/
Aes* wc_AesNew(void* heap, int devId, int *result_code);

/*!
    \ingroup AES
    \brief This function frees an AES structure that was allocated with
    wc_AesNew. It also sets the pointer to NULL to prevent use-after-free.
    These New/Delete functions are exposed to support allocation of the
    structure using dynamic memory to provide better ABI compatibility.

    \note This API is only available when WC_NO_CONSTRUCTORS is not defined.
    WC_NO_CONSTRUCTORS is automatically defined when WOLFSSL_NO_MALLOC is
    defined.

    \return 0 On success.
    \return BAD_FUNC_ARG If aes or aes_p is NULL.

    \param aes pointer to the AES structure to free
    \param aes_p pointer to the AES pointer (will be set to NULL)

    _Example_
    \code
    Aes* aes = wc_AesNew(NULL, INVALID_DEVID, NULL);
    if (aes != NULL) {
        // use aes...
        int ret = wc_AesDelete(aes, &aes);
        // aes is now NULL
    }
    \endcode

    \sa wc_AesNew
    \sa wc_AesFree
*/
int wc_AesDelete(Aes* aes, Aes** aes_p);

/*!
    \ingroup AES
    \brief This function performs AES-SIV (Synthetic IV) encryption with
    extended parameters. AES-SIV provides nonce-misuse resistance and
    deterministic authenticated encryption.

    \return 0 On success.
    \return BAD_FUNC_ARG If parameters are invalid.
    \return Other negative values on error.

    \param key pointer to the key buffer (32, 48, or 64 bytes for SIV)
    \param keySz length of the key in bytes
    \param assoc pointer to array of associated data structures
    \param numAssoc number of associated data items
    \param nonce pointer to the nonce buffer (can be NULL)
    \param nonceSz length of the nonce in bytes
    \param in pointer to plaintext to encrypt
    \param inSz length of plaintext in bytes
    \param siv pointer to buffer to store the SIV (16 bytes)
    \param out pointer to buffer to store ciphertext

    _Example_
    \code
    byte key[32] = { }; // 256-bit key for AES-128-SIV
    AesSivAssoc assoc[1];
    byte aad[20] = { }; // associated data
    byte nonce[12] = { }; // nonce
    byte plaintext[100] = { }; // data
    byte siv[16];
    byte ciphertext[100];

    assoc[0].data = aad;
    assoc[0].sz = 20;

    int ret = wc_AesSivEncrypt_ex(key, 32, assoc, 1, nonce, 12,
                                  plaintext, 100, siv, ciphertext);
    if (ret != 0) {
        // encryption failed
    }
    \endcode

    \sa wc_AesSivDecrypt_ex
    \sa wc_AesSivEncrypt
*/
int wc_AesSivEncrypt_ex(const byte* key, word32 keySz,
                        const AesSivAssoc* assoc, word32 numAssoc,
                        const byte* nonce, word32 nonceSz, const byte* in,
                        word32 inSz, byte* siv, byte* out);

/*!
    \ingroup AES
    \brief This function performs AES-SIV (Synthetic IV) decryption with
    extended parameters. It verifies the SIV and decrypts the ciphertext.

    \return 0 On successful decryption and verification.
    \return AES_SIV_AUTH_E If SIV verification fails.
    \return BAD_FUNC_ARG If parameters are invalid.
    \return Other negative values on error.

    \param key pointer to the key buffer (32, 48, or 64 bytes for SIV)
    \param keySz length of the key in bytes
    \param assoc pointer to array of associated data structures
    \param numAssoc number of associated data items
    \param nonce pointer to the nonce buffer (can be NULL)
    \param nonceSz length of the nonce in bytes
    \param in pointer to ciphertext to decrypt
    \param inSz length of ciphertext in bytes
    \param siv pointer to the SIV to verify (16 bytes)
    \param out pointer to buffer to store plaintext

    _Example_
    \code
    byte key[32] = { }; // 256-bit key for AES-128-SIV
    AesSivAssoc assoc[1];
    byte aad[20] = { }; // associated data
    byte nonce[12] = { }; // nonce
    byte ciphertext[100] = { }; // encrypted data
    byte siv[16] = { }; // received SIV
    byte plaintext[100];

    assoc[0].data = aad;
    assoc[0].sz = 20;

    int ret = wc_AesSivDecrypt_ex(key, 32, assoc, 1, nonce, 12,
                                  ciphertext, 100, siv, plaintext);
    if (ret != 0) {
        // decryption or verification failed
    }
    \endcode

    \sa wc_AesSivEncrypt_ex
    \sa wc_AesSivDecrypt
*/
int wc_AesSivDecrypt_ex(const byte* key, word32 keySz,
                        const AesSivAssoc* assoc, word32 numAssoc,
                        const byte* nonce, word32 nonceSz, const byte* in,
                        word32 inSz, byte* siv, byte* out);
