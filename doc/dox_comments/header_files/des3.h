/*!
    \ingroup 3DES

    \brief This function sets the key and initialization vector (iv) for the
    Des structure given as argument. It also initializes and allocates space
    for the buffers needed for encryption and decryption, if these have not
    yet been initialized. Note: If no iv is provided (i.e. iv == NULL)
    the initialization vector defaults to an iv of 0.

    \return 0 On successfully setting the key and initialization vector for
    the Des structure

    \param des pointer to the Des structure to initialize
    \param key pointer to the buffer containing the 8 byte key with which to
    initialize the Des structure
    \param iv pointer to the buffer containing the 8 byte iv with which to
    initialize the Des structure. If this is not provided, the iv defaults to 0
    \param dir direction of encryption. Valid options are: DES_ENCRYPTION,
    and DES_DECRYPTION

    _Example_
    \code
    Des enc; // Des structure used for encryption
    int ret;
    byte key[] = { // initialize with 8 byte key };
    byte iv[]  = { // initialize with 8 byte iv };

    ret = wc_Des_SetKey(&des, key, iv, DES_ENCRYPTION);
    if (ret != 0) {
    	// error initializing des structure
    }
    \endcode

    \sa wc_Des_SetIV
    \sa wc_Des3_SetKey
*/
int  wc_Des_SetKey(Des* des, const byte* key,
                               const byte* iv, int dir);

/*!
    \ingroup 3DES

    \brief This function sets the initialization vector (iv) for the Des
    structure given as argument. When passed a NULL iv, it sets the
    initialization vector to 0.

    \return none No returns.

    \param des pointer to the Des structure for which to set the iv
    \param iv pointer to the buffer containing the 8 byte iv with which to
    initialize the Des structure. If this is not provided, the iv defaults to 0

    _Example_
    \code
    Des enc; // Des structure used for encryption
    // initialize enc with wc_Des_SetKey
    byte iv[]  = { // initialize with 8 byte iv };
    wc_Des_SetIV(&enc, iv);
    }
    \endcode

    \sa wc_Des_SetKey
*/
void wc_Des_SetIV(Des* des, const byte* iv);

/*!
    \ingroup 3DES

    \brief This function encrypts the input message, in, and stores the result
    in the output buffer, out. It uses DES encryption with cipher block
    chaining (CBC) mode.

    \return 0 Returned upon successfully encrypting the given input message

    \param des pointer to the Des structure to use for encryption
    \param out pointer to the buffer in which to store the encrypted ciphertext
    \param in pointer to the input buffer containing the message to encrypt
    \param sz length of the message to encrypt

    _Example_
    \code
    Des enc; // Des structure used for encryption
    // initialize enc with wc_Des_SetKey, use mode DES_ENCRYPTION

    byte plain[]  = { // initialize with message };
    byte cipher[sizeof(plain)];

    if ( wc_Des_CbcEncrypt(&enc, cipher, plain, sizeof(plain)) != 0) {
	    // error encrypting message
    }
    \endcode

    \sa wc_Des_SetKey
    \sa wc_Des_CbcDecrypt
*/
int  wc_Des_CbcEncrypt(Des* des, byte* out,
                                   const byte* in, word32 sz);

/*!
    \ingroup 3DES

    \brief This function decrypts the input ciphertext, in, and stores the
    resulting plaintext in the output buffer, out. It uses DES encryption
    with cipher block chaining (CBC) mode.

    \return 0 Returned upon successfully decrypting the given ciphertext

    \param des pointer to the Des structure to use for decryption
    \param out pointer to the buffer in which to store the decrypted plaintext
    \param in pointer to the input buffer containing the encrypted ciphertext
    \param sz length of the ciphertext to decrypt

    _Example_
    \code
    Des dec; // Des structure used for decryption
    // initialize dec with wc_Des_SetKey, use mode DES_DECRYPTION

    byte cipher[]  = { // initialize with ciphertext };
    byte decoded[sizeof(cipher)];

    if ( wc_Des_CbcDecrypt(&dec, decoded, cipher, sizeof(cipher)) != 0) {
    	// error decrypting message
    }
    \endcode

    \sa wc_Des_SetKey
    \sa wc_Des_CbcEncrypt
*/
int  wc_Des_CbcDecrypt(Des* des, byte* out,
                                   const byte* in, word32 sz);

/*!
    \ingroup 3DES

    \brief This function encrypts the input message, in, and stores the result
    in the output buffer, out. It uses Des encryption with Electronic
    Codebook (ECB) mode.

    \return 0: Returned upon successfully encrypting the given plaintext.

    \param des pointer to the Des structure to use for encryption
    \param out pointer to the buffer in which to store the encrypted message
    \param in pointer to the input buffer containing the plaintext to encrypt
    \param sz length of the plaintext to encrypt

    _Example_
    \code
    Des enc; // Des structure used for encryption
    // initialize enc with wc_Des_SetKey, use mode DES_ENCRYPTION

    byte plain[]  = { // initialize with message to encrypt };
    byte cipher[sizeof(plain)];

    if ( wc_Des_EcbEncrypt(&enc,cipher, plain, sizeof(plain)) != 0) {
    	// error encrypting message
    }
    \endcode

    \sa wc_Des_SetKe
*/
int  wc_Des_EcbEncrypt(Des* des, byte* out,
                                   const byte* in, word32 sz);

/*!
    \ingroup 3DES

    \brief This function encrypts the input message, in, and stores the
    result in the output buffer, out. It uses Des3 encryption with
    Electronic Codebook (ECB) mode. Warning: In nearly all use cases ECB
    mode is considered to be less secure. Please avoid using ECB API’s
    directly whenever possible.

    \return 0 Returned upon successfully encrypting the given plaintext

    \param des3 pointer to the Des3 structure to use for encryption
    \param out pointer to the buffer in which to store the encrypted message
    \param in pointer to the input buffer containing the plaintext to encrypt
    \param sz length of the plaintext to encrypt

    _Example_
    \code
    Des3 enc; // Des3 structure used for encryption
    // initialize enc with wc_Des3_SetKey, use mode DES_ENCRYPTION

    byte plain[]  = { // initialize with message to encrypt };
    byte cipher[sizeof(plain)];

    if ( wc_Des3_EcbEncrypt(&enc,cipher, plain, sizeof(plain)) != 0) {
        // error encrypting message
    }
    \endcode

    \sa wc_Des3_SetKey
*/
int wc_Des3_EcbEncrypt(Des3* des, byte* out,
                                   const byte* in, word32 sz);

/*!
    \ingroup 3DES

    \brief This function sets the key and initialization vector (iv) for
    the Des3 structure given as argument. It also initializes and allocates
    space for the buffers needed for encryption and decryption, if these
    have not yet been initialized. Note: If no iv is provided (i.e. iv ==
    NULL) the initialization vector defaults to an iv of 0.

    \return 0 On successfully setting the key and initialization vector
    for the Des structure

    \param des3 pointer to the Des3 structure to initialize
    \param key pointer to the buffer containing the 24 byte key with which
    to initialize the Des3 structure
    \param iv pointer to the buffer containing the 8 byte iv with which to
    initialize the Des3 structure. If this is not provided, the iv defaults
    to 0
    \param dir direction of encryption. Valid options are: DES_ENCRYPTION,
    and DES_DECRYPTION

    _Example_
    \code
    Des3 enc; // Des3 structure used for encryption
    int ret;
    byte key[] = { // initialize with 24 byte key };
    byte iv[]  = { // initialize with 8 byte iv };

    ret = wc_Des3_SetKey(&des, key, iv, DES_ENCRYPTION);
    if (ret != 0) {
    	// error initializing des structure
    }
    \endcode

    \sa wc_Des3_SetIV
    \sa wc_Des3_CbcEncrypt
    \sa wc_Des3_CbcDecrypt
*/
int  wc_Des3_SetKey(Des3* des, const byte* key,
                                const byte* iv,int dir);

/*!
    \ingroup 3DES

    \brief This function sets the initialization vector (iv) for the Des3
    structure given as argument. When passed a NULL iv, it sets the
    initialization vector to 0.

    \return none No returns.

    \param des pointer to the Des3 structure for which to set the iv
    \param iv pointer to the buffer containing the 8 byte iv with which to
    initialize the Des3 structure. If this is not provided, the iv
    defaults to 0

    _Example_
    \code
    Des3 enc; // Des3 structure used for encryption
    // initialize enc with wc_Des3_SetKey

    byte iv[]  = { // initialize with 8 byte iv };

    wc_Des3_SetIV(&enc, iv);
    }
    \endcode

    \sa wc_Des3_SetKey
*/
int  wc_Des3_SetIV(Des3* des, const byte* iv);

/*!
    \ingroup 3DES

    \brief This function encrypts the input message, in, and stores the
    result in the output buffer, out. It uses Triple Des (3DES) encryption
    with cipher block chaining (CBC) mode.

    \return 0 Returned upon successfully encrypting the given input message

    \param des pointer to the Des3 structure to use for encryption
    \param out pointer to the buffer in which to store the encrypted ciphertext
    \param in pointer to the input buffer containing the message to encrypt
    \param sz length of the message to encrypt

    _Example_
    \code
    Des3 enc; // Des3 structure used for encryption
    // initialize enc with wc_Des3_SetKey, use mode DES_ENCRYPTION

    byte plain[]  = { // initialize with message };
    byte cipher[sizeof(plain)];

    if ( wc_Des3_CbcEncrypt(&enc, cipher, plain, sizeof(plain)) != 0) {
	    // error encrypting message
    }
    \endcode

    \sa wc_Des3_SetKey
    \sa wc_Des3_CbcDecrypt
*/
int  wc_Des3_CbcEncrypt(Des3* des, byte* out,
                                    const byte* in,word32 sz);

/*!
    \ingroup 3DES

    \brief This function decrypts the input ciphertext, in, and stores the
    resulting plaintext in the output buffer, out. It uses Triple Des (3DES)
    encryption with cipher block chaining (CBC) mode.

    \return 0 Returned upon successfully decrypting the given ciphertext

    \param des pointer to the Des3 structure to use for decryption
    \param out pointer to the buffer in which to store the decrypted plaintext
    \param in pointer to the input buffer containing the encrypted ciphertext
    \param sz length of the ciphertext to decrypt

    _Example_
    \code
    Des3 dec; // Des structure used for decryption
    // initialize dec with wc_Des3_SetKey, use mode DES_DECRYPTION

    byte cipher[]  = { // initialize with ciphertext };
    byte decoded[sizeof(cipher)];

    if ( wc_Des3_CbcDecrypt(&dec, decoded, cipher, sizeof(cipher)) != 0) {
    	// error decrypting message
    }
    \endcode

    \sa wc_Des3_SetKey
    \sa wc_Des3_CbcEncrypt
*/
int  wc_Des3_CbcDecrypt(Des3* des, byte* out,
                                    const byte* in,word32 sz);

/*!
    \ingroup 3DES
    \brief This function decrypts the input ciphertext and stores the
    resulting plaintext in the output buffer. It uses DES encryption
    with Electronic Codebook (ECB) mode. Warning: In nearly all use
    cases ECB mode is considered to be less secure. Please avoid using
    ECB APIs directly whenever possible.

    \return 0 On successfully decrypting the given ciphertext

    \param des pointer to the Des structure to use for decryption
    \param out pointer to the buffer in which to store the decrypted
    plaintext
    \param in pointer to the input buffer containing the ciphertext
    \param sz length of the ciphertext to decrypt

    _Example_
    \code
    Des dec;
    byte cipher[]; // ciphertext to decrypt
    byte plain[sizeof(cipher)];

    wc_Des_SetKey(&dec, key, iv, DES_DECRYPTION);
    if (wc_Des_EcbDecrypt(&dec, plain, cipher, sizeof(cipher)) != 0) {
        // error decrypting message
    }
    \endcode

    \sa wc_Des_SetKey
    \sa wc_Des_EcbEncrypt
*/
int wc_Des_EcbDecrypt(Des* des, byte* out, const byte* in, word32 sz);

/*!
    \ingroup 3DES
    \brief This function decrypts the input ciphertext and stores the
    resulting plaintext in the output buffer. It uses Triple DES (3DES)
    encryption with Electronic Codebook (ECB) mode. Warning: In nearly
    all use cases ECB mode is considered to be less secure. Please
    avoid using ECB APIs directly whenever possible.

    \return 0 On successfully decrypting the given ciphertext

    \param des pointer to the Des3 structure to use for decryption
    \param out pointer to the buffer in which to store the decrypted
    plaintext
    \param in pointer to the input buffer containing the ciphertext
    \param sz length of the ciphertext to decrypt

    _Example_
    \code
    Des3 dec;
    byte cipher[]; // ciphertext to decrypt
    byte plain[sizeof(cipher)];

    wc_Des3_SetKey(&dec, key, iv, DES_DECRYPTION);
    if (wc_Des3_EcbDecrypt(&dec, plain, cipher, sizeof(cipher)) != 0) {
        // error decrypting message
    }
    \endcode

    \sa wc_Des3_SetKey
    \sa wc_Des3_EcbEncrypt
*/
int wc_Des3_EcbDecrypt(Des3* des, byte* out, const byte* in, word32 sz);

/*!
    \ingroup 3DES
    \brief This function initializes a Des3 structure for use with
    hardware acceleration and custom memory management. This is an
    extended version of the standard initialization that allows
    specification of heap hints and device IDs.

    \return 0 On successfully initializing the Des3 structure
    \return BAD_FUNC_ARG If des3 is NULL

    \param des3 pointer to the Des3 structure to initialize
    \param heap pointer to heap hint for memory allocation (can be NULL)
    \param devId device ID for hardware acceleration (use INVALID_DEVID
    for software only)

    _Example_
    \code
    Des3 des;
    void* heap = NULL;
    int devId = INVALID_DEVID;

    if (wc_Des3Init(&des, heap, devId) != 0) {
        // error initializing Des3 structure
    }
    \endcode

    \sa wc_Des3_SetKey
    \sa wc_Des3Free
*/
int wc_Des3Init(Des3* des3, void* heap, int devId);

/*!
    \ingroup 3DES
    \brief This function frees a Des3 structure and releases any
    resources allocated for it. This should be called when finished
    using the Des3 structure to prevent memory leaks.

    \return none No returns.

    \param des3 pointer to the Des3 structure to free

    _Example_
    \code
    Des3 des;
    wc_Des3Init(&des, NULL, INVALID_DEVID);
    wc_Des3_SetKey(&des, key, iv, DES_ENCRYPTION);
    // use des for encryption/decryption
    wc_Des3Free(&des);
    \endcode

    \sa wc_Des3Init
    \sa wc_Des3_SetKey
*/
void wc_Des3Free(Des3* des3);
