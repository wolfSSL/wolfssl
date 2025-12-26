/*!
    \ingroup Password

    \brief This function implements the Password Based Key Derivation
    Function 1 (PBKDF1), converting an input password with a concatenated salt
    into a more secure key, which it stores in output. It allows the user to
    select between SHA and MD5 as hash functions.

    \return 0 Returned on successfully deriving a key from the input password
    \return BAD_FUNC_ARG Returned if there is an invalid hash type given
    (valid type are: MD5 and SHA), iterations is less than 1, or the key
    length (kLen) requested is greater than the hash length of the provided hash
    \return MEMORY_E Returned if there is an error allocating memory for a
    SHA or MD5 object

    \param output pointer to the buffer in which to store the generated key.
    Should be at least kLen long
    \param passwd pointer to the buffer containing the password to use for
    the key derivation
    \param pLen length of the password to use for key derivation
    \param salt pointer to the buffer containing the salt to use for
    key derivation
    \param sLen length of the salt
    \param iterations number of times to process the hash
    \param kLen desired length of the derived key. Should not be longer
    than the digest size of the hash chosen
    \param hashType the hashing algorithm to use. Valid choices are WC_MD5 and WC_SHA

    _Example_
    \code
    int ret;
    byte key[WC_MD5_DIGEST_SIZE];
    byte pass[] = { }; // initialize with password
    byte salt[] = { }; // initialize with salt

    ret = wc_PBKDF1(key, pass, sizeof(pass), salt, sizeof(salt), 1000,
    sizeof(key), WC_MD5);
    if ( ret != 0 ) {
    	// error deriving key from password
    }
    \endcode

    \sa wc_PBKDF2
    \sa wc_PKCS12_PBKDF
*/
int wc_PBKDF1(byte* output, const byte* passwd, int pLen,
                      const byte* salt, int sLen, int iterations, int kLen,
                      int hashType);

/*!
    \ingroup Password

    \brief This function implements the Password Based Key Derivation
    Function 2 (PBKDF2), converting an input password with a concatenated
    salt into a more secure key, which it stores in output. It allows the user
    to select any of the supported HMAC hash functions, including: WC_MD5,
    WC_SHA, WC_SHA256, WC_SHA384, WC_SHA512, WC_SHA3_224, WC_SHA3_256,
    WC_SHA3_384 or WC_SHA3_512

    \return 0 Returned on successfully deriving a key from the input password
    \return BAD_FUNC_ARG Returned if there is an invalid hash type given or
    iterations is less than 1
    \return MEMORY_E Returned if there is an allocating memory for
    the HMAC object

    \param output pointer to the buffer in which to store the generated key.
    Should be kLen long
    \param passwd pointer to the buffer containing the password to use for
    the key derivation
    \param pLen length of the password to use for key derivation
    \param salt pointer to the buffer containing the salt to use for
    key derivation
    \param sLen length of the salt
    \param iterations number of times to process the hash
    \param kLen desired length of the derived key
    \param hashType the hashing algorithm to use. Valid choices are: WC_MD5,
    WC_SHA, WC_SHA256, WC_SHA384, WC_SHA512, WC_SHA3_224, WC_SHA3_256,
    WC_SHA3_384 or WC_SHA3_512

    _Example_
    \code
    int ret;
    byte key[64];
    byte pass[] = { }; // initialize with password
    byte salt[] = { }; // initialize with salt

    ret = wc_PBKDF2(key, pass, sizeof(pass), salt, sizeof(salt), 2048, sizeof(key),
    WC_SHA512);
    if ( ret != 0 ) {
    	// error deriving key from password
    }
    \endcode

    \sa wc_PBKDF1
    \sa wc_PKCS12_PBKDF
*/
int wc_PBKDF2(byte* output, const byte* passwd, int pLen,
                      const byte* salt, int sLen, int iterations, int kLen,
                      int hashType);

/*!
    \ingroup Password

    \brief This function implements the Password Based Key Derivation Function
    (PBKDF) described in RFC 7292 Appendix B. This function converts an input
    password with a concatenated salt into a more secure key, which it stores
    in output. It allows the user to select any of the supported HMAC hash
    functions, including: WC_MD5, WC_SHA, WC_SHA256, WC_SHA384, WC_SHA512,
    WC_SHA3_224, WC_SHA3_256, WC_SHA3_384 or WC_SHA3_512

    \return 0 Returned on successfully deriving a key from the input password
    \return BAD_FUNC_ARG Returned if there is an invalid hash type given,
    iterations is less than 1, or the key length (kLen) requested is greater
    than the hash length of the provided hash
    \return MEMORY_E Returned if there is an allocating memory
    \return MP_INIT_E may be returned if there is an error during key generation
    \return MP_READ_E may be returned if there is an error during key generation
    \return MP_CMP_E may be returned if there is an error during key generation
    \return MP_INVMOD_E may be returned if there is an error during
    key generation
    \return MP_EXPTMOD_E may be returned if there is an error during
    key generation
    \return MP_MOD_E may be returned if there is an error during key generation
    \return MP_MUL_E may be returned if there is an error during key generation
    \return MP_ADD_E may be returned if there is an error during key generation
    \return MP_MULMOD_E may be returned if there is an error during
    key generation
    \return MP_TO_E may be returned if there is an error during key generation
    \return MP_MEM may be returned if there is an error during key generation

    \param output pointer to the buffer in which to store the generated key.
    Should be kLen long
    \param passwd pointer to the buffer containing the password to use for
    the key derivation
    \param passLen length of the password to use for key derivation
    \param salt pointer to the buffer containing the salt to use
    for key derivation
    \param saltLen length of the salt
    \param iterations number of times to process the hash
    \param kLen desired length of the derived key
    \param hashType the hashing algorithm to use. Valid choices are: WC_MD5,
    WC_SHA, WC_SHA256, WC_SHA384, WC_SHA512, WC_SHA3_224, WC_SHA3_256,
    WC_SHA3_384 or WC_SHA3_512
    \param id this is a byte identifier indicating the purpose of key
    generation. It is used to diversify the key output, and should be
    assigned as follows: ID=1: pseudorandom bits are to be used as key
    material for performing encryption or decryption. ID=2: pseudorandom
    bits are to be used an IV (Initial Value) for encryption or decryption.
    ID=3: pseudorandom bits are to be used as an integrity key for MACing.

    _Example_
    \code
    int ret;
    byte key[64];
    byte pass[] = { }; // initialize with password
    byte salt[] = { }; // initialize with salt

    ret = wc_PKCS12_PBKDF(key, pass, sizeof(pass), salt, sizeof(salt), 2048,
    sizeof(key), WC_SHA512, 1);
    if ( ret != 0 ) {
    	// error deriving key from password
    }
    \endcode

    \sa wc_PBKDF1
    \sa wc_PBKDF2
*/
int wc_PKCS12_PBKDF(byte* output, const byte* passwd, int passLen,
                            const byte* salt, int saltLen, int iterations,
                            int kLen, int hashType, int id);

/*!
    \ingroup Password
    \brief Extended version of PBKDF1 with heap hint.

    \return 0 on success
    \return BAD_FUNC_ARG on invalid arguments
    \return MEMORY_E on memory allocation error

    \param key Output key buffer
    \param keyLen Key length
    \param iv Output IV buffer
    \param ivLen IV length
    \param passwd Password buffer
    \param passwdLen Password length
    \param salt Salt buffer
    \param saltLen Salt length
    \param iterations Iteration count
    \param hashType Hash algorithm type
    \param heap Heap hint for memory allocation

    _Example_
    \code
    byte key[16], iv[16];
    byte pass[] = "password";
    byte salt[] = "salt";
    int ret = wc_PBKDF1_ex(key, sizeof(key), iv, sizeof(iv),
        pass, sizeof(pass), salt, sizeof(salt), 1000, WC_SHA, NULL);
    \endcode

    \sa wc_PBKDF1
*/
int wc_PBKDF1_ex(byte* key, int keyLen, byte* iv, int ivLen,
    const byte* passwd, int passwdLen, const byte* salt, int saltLen,
    int iterations, int hashType, void* heap);

/*!
    \ingroup Password
    \brief Extended version of PBKDF2 with heap hint and device ID.

    \return 0 on success
    \return BAD_FUNC_ARG on invalid arguments
    \return MEMORY_E on memory allocation error

    \param output Output key buffer
    \param passwd Password buffer
    \param pLen Password length
    \param salt Salt buffer
    \param sLen Salt length
    \param iterations Iteration count
    \param kLen Key length
    \param hashType Hash algorithm type
    \param heap Heap hint for memory allocation
    \param devId Device ID for hardware acceleration

    _Example_
    \code
    byte key[32];
    byte pass[] = "password";
    byte salt[] = "salt";
    int ret = wc_PBKDF2_ex(key, pass, sizeof(pass), salt,
        sizeof(salt), 2048, sizeof(key), WC_SHA256, NULL,
        INVALID_DEVID);
    \endcode

    \sa wc_PBKDF2
*/
int wc_PBKDF2_ex(byte* output, const byte* passwd, int pLen,
    const byte* salt, int sLen, int iterations, int kLen,
    int hashType, void* heap, int devId);

/*!
    \ingroup Password
    \brief Extended version of PKCS12_PBKDF with heap hint.

    \return 0 on success
    \return BAD_FUNC_ARG on invalid arguments
    \return MEMORY_E on memory allocation error

    \param output Output key buffer
    \param passwd Password buffer
    \param passLen Password length
    \param salt Salt buffer
    \param saltLen Salt length
    \param iterations Iteration count
    \param kLen Key length
    \param hashType Hash algorithm type
    \param id Purpose identifier (1=key, 2=IV, 3=MAC)
    \param heap Heap hint for memory allocation

    _Example_
    \code
    byte key[32];
    byte pass[] = "password";
    byte salt[] = "salt";
    int ret = wc_PKCS12_PBKDF_ex(key, pass, sizeof(pass), salt,
        sizeof(salt), 2048, sizeof(key), WC_SHA256, 1, NULL);
    \endcode

    \sa wc_PKCS12_PBKDF
*/
int wc_PKCS12_PBKDF_ex(byte* output, const byte* passwd,int passLen,
    const byte* salt, int saltLen, int iterations, int kLen,
    int hashType, int id, void* heap);

/*!
    \ingroup Password
    \brief Implements scrypt key derivation function.

    \return 0 on success
    \return BAD_FUNC_ARG on invalid arguments
    \return MEMORY_E on memory allocation error

    \param output Output key buffer
    \param passwd Password buffer
    \param passLen Password length
    \param salt Salt buffer
    \param saltLen Salt length
    \param cost CPU/memory cost parameter (N)
    \param blockSize Block size parameter (r)
    \param parallel Parallelization parameter (p)
    \param dkLen Derived key length

    _Example_
    \code
    byte key[32];
    byte pass[] = "password";
    byte salt[] = "salt";
    int ret = wc_scrypt(key, pass, sizeof(pass), salt,
        sizeof(salt), 16384, 8, 1, sizeof(key));
    \endcode

    \sa wc_scrypt_ex
*/
int wc_scrypt(byte* output, const byte* passwd, int passLen,
    const byte* salt, int saltLen, int cost, int blockSize,
    int parallel, int dkLen);

/*!
    \ingroup Password
    \brief Extended scrypt with iteration count instead of cost.

    \return 0 on success
    \return BAD_FUNC_ARG on invalid arguments
    \return MEMORY_E on memory allocation error

    \param output Output key buffer
    \param passwd Password buffer
    \param passLen Password length
    \param salt Salt buffer
    \param saltLen Salt length
    \param iterations Iteration count
    \param blockSize Block size parameter (r)
    \param parallel Parallelization parameter (p)
    \param dkLen Derived key length

    _Example_
    \code
    byte key[32];
    byte pass[] = "password";
    byte salt[] = "salt";
    int ret = wc_scrypt_ex(key, pass, sizeof(pass), salt,
        sizeof(salt), 16384, 8, 1, sizeof(key));
    \endcode

    \sa wc_scrypt
*/
int wc_scrypt_ex(byte* output, const byte* passwd, int passLen,
    const byte* salt, int saltLen, word32 iterations, int blockSize,
    int parallel, int dkLen);
