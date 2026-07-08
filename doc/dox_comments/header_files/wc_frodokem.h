/*!
    \ingroup FRODO_KEM

    \brief Allocates and initializes a new FrodoKemKey on the heap. The
    returned pointer must be released with wc_FrodoKemKey_Delete().

    FrodoKEM is a conservative, unstructured-lattice key encapsulation
    mechanism. The type parameter is a base parameter set -
    WC_FRODOKEM_640_SHAKE (NIST level 1), WC_FRODOKEM_976_SHAKE
    (level 3) or WC_FRODOKEM_1344_SHAKE (level 5) - optionally OR'd with
    FRODOKEM_AES (generate matrix A with AES-128 instead of SHAKE-128)
    and/or FRODOKEM_EPHEMERAL (eFrodoKEM: ephemeral, no salt). Named
    combinations such as WC_FRODOKEM_640_AES and WC_EFRODOKEM_1344_SHAKE
    are provided.

    \return Pointer to a freshly allocated FrodoKemKey on success.
    \return NULL on allocation failure or if type is invalid.

    \param [in] type FrodoKEM key type: a base parameter set optionally
    OR'd with FRODOKEM_AES and/or FRODOKEM_EPHEMERAL.
    \param [in] heap Heap hint for dynamic memory allocation. May be
    NULL.
    \param [in] devId Device identifier for hardware crypto callbacks.
    Use INVALID_DEVID for software-only.

    _Example_
    \code
    FrodoKemKey* key = wc_FrodoKemKey_New(WC_FRODOKEM_640_SHAKE, NULL,
        INVALID_DEVID);
    if (key == NULL) {
        // allocation failed
    }
    // ... use key ...
    wc_FrodoKemKey_Delete(key, &key);
    \endcode

    \sa wc_FrodoKemKey_Delete
    \sa wc_FrodoKemKey_Init
*/
FrodoKemKey* wc_FrodoKemKey_New(int type, void* heap, int devId);

/*!
    \ingroup FRODO_KEM

    \brief Frees and zeros a heap-allocated FrodoKemKey previously
    returned by wc_FrodoKemKey_New(). On success the caller's pointer
    variable is set to NULL via key_p when key_p is not NULL.

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL.

    \param [in,out] key The FrodoKemKey to free.
    \param [in,out] key_p Optional address of the caller's pointer
    variable; when not NULL, it is set to NULL on success.

    \sa wc_FrodoKemKey_New
*/
int wc_FrodoKemKey_Delete(FrodoKemKey* key, FrodoKemKey** key_p);

/*!
    \ingroup FRODO_KEM

    \brief Initializes a FrodoKemKey object in place. The type parameter
    selects the FrodoKEM variant: a base parameter set
    (WC_FRODOKEM_640_SHAKE, WC_FRODOKEM_976_SHAKE or
    WC_FRODOKEM_1344_SHAKE) optionally OR'd with FRODOKEM_AES and/or
    FRODOKEM_EPHEMERAL.

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL or type has bits set outside a
    base parameter set, FRODOKEM_AES and FRODOKEM_EPHEMERAL.
    \return NOT_COMPILED_IN if type names a valid variant whose
    parameter set or matrix-A generation method was disabled at build
    time.

    \param [in,out] key Pointer to the FrodoKemKey to initialize.
    \param [in] type FrodoKEM key type: a base parameter set optionally
    OR'd with FRODOKEM_AES and/or FRODOKEM_EPHEMERAL.
    \param [in] heap Heap hint for dynamic memory allocation. May be
    NULL.
    \param [in] devId Device identifier for hardware crypto callbacks.

    _Example_
    \code
    FrodoKemKey key;
    int ret;

    ret = wc_FrodoKemKey_Init(&key, WC_FRODOKEM_640_SHAKE, NULL,
        INVALID_DEVID);
    if (ret != 0) {
        // error initializing key
    }
    // ... use key ...
    wc_FrodoKemKey_Free(&key);
    \endcode

    \sa wc_FrodoKemKey_Free
    \sa wc_FrodoKemKey_MakeKey
*/
int wc_FrodoKemKey_Init(FrodoKemKey* key, int type, void* heap,
    int devId);

/*!
    \ingroup FRODO_KEM

    \brief Releases the resources held by a FrodoKemKey initialized with
    wc_FrodoKemKey_Init() and zeroizes its secret material. The key
    object itself is not freed (it was not allocated by Init).

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL.

    \param [in,out] key The FrodoKemKey to free.

    \sa wc_FrodoKemKey_Init
*/
int wc_FrodoKemKey_Free(FrodoKemKey* key);

/*!
    \ingroup FRODO_KEM

    \brief Generates a FrodoKEM key pair into an initialized key using
    the provided random number generator. On success the key holds both
    the public and private keys, which can be serialized with
    wc_FrodoKemKey_EncodePublicKey() and wc_FrodoKemKey_EncodePrivateKey().

    \return 0 on success.
    \return BAD_FUNC_ARG if key or rng is NULL.
    \return MEMORY_E on allocation failure.
    \return A negative error code from the RNG or hashing on failure.

    \param [in,out] key An initialized FrodoKemKey to hold the generated
    key pair.
    \param [in] rng An initialized random number generator.

    _Example_
    \code
    FrodoKemKey key;
    WC_RNG rng;
    int ret;

    wc_InitRng(&rng);
    wc_FrodoKemKey_Init(&key, WC_FRODOKEM_640_SHAKE, NULL, INVALID_DEVID);

    ret = wc_FrodoKemKey_MakeKey(&key, &rng);
    if (ret != 0) {
        // error generating key pair
    }

    wc_FrodoKemKey_Free(&key);
    wc_FreeRng(&rng);
    \endcode

    \sa wc_FrodoKemKey_MakeKeyWithRandom
    \sa wc_FrodoKemKey_Encapsulate
    \sa wc_FrodoKemKey_EncodePublicKey
*/
int wc_FrodoKemKey_MakeKey(FrodoKemKey* key, WC_RNG* rng);

/*!
    \ingroup FRODO_KEM

    \brief Generates a FrodoKEM key pair from caller-supplied random
    bytes rather than an RNG. This is primarily for testing and known
    answer tests; production code should use wc_FrodoKemKey_MakeKey().
    The required length depends on the parameter set (for example
    WC_FRODOKEM_640_MAKEKEY_RAND_SZ for FrodoKEM-640).

    \return 0 on success.
    \return BAD_FUNC_ARG if key or rand is NULL, or len is not the
    length required for the key's parameter set.

    \param [in,out] key An initialized FrodoKemKey to hold the generated
    key pair.
    \param [in] rand Buffer of random bytes.
    \param [in] len Length of rand in bytes; must equal the parameter
    set's WC_FRODOKEM_<set>_MAKEKEY_RAND_SZ.

    \sa wc_FrodoKemKey_MakeKey
*/
int wc_FrodoKemKey_MakeKeyWithRandom(FrodoKemKey* key,
    const unsigned char* rand, int len);

/*!
    \ingroup FRODO_KEM

    \brief Returns, through len, the size in bytes of a ciphertext
    (encapsulation) for the key's parameter set. Use this to size the
    ct buffer passed to wc_FrodoKemKey_Encapsulate().

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL.

    \param [in] key An initialized FrodoKemKey.
    \param [out] len Set to the ciphertext size in bytes.

    \sa wc_FrodoKemKey_Encapsulate
    \sa wc_FrodoKemKey_SharedSecretSize
*/
int wc_FrodoKemKey_CipherTextSize(FrodoKemKey* key, word32* len);

/*!
    \ingroup FRODO_KEM

    \brief Returns, through len, the size in bytes of a shared secret
    for the key's parameter set. Use this to size the ss buffer passed
    to wc_FrodoKemKey_Encapsulate() and wc_FrodoKemKey_Decapsulate().

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL.

    \param [in] key An initialized FrodoKemKey.
    \param [out] len Set to the shared secret size in bytes.

    \sa wc_FrodoKemKey_CipherTextSize
    \sa wc_FrodoKemKey_Encapsulate
*/
int wc_FrodoKemKey_SharedSecretSize(FrodoKemKey* key, word32* len);

/*!
    \ingroup FRODO_KEM

    \brief Encapsulates to a public key: generates a random shared
    secret and the ciphertext that encapsulates it under key's public
    key. The key must hold a public key (from wc_FrodoKemKey_MakeKey()
    or wc_FrodoKemKey_DecodePublicKey()). Size the ct and ss buffers with
    wc_FrodoKemKey_CipherTextSize() and wc_FrodoKemKey_SharedSecretSize().

    \return 0 on success.
    \return BAD_FUNC_ARG if key, ct, ss or rng is NULL.
    \return BAD_STATE_E if key does not hold a public key.
    \return MEMORY_E on allocation failure.

    \param [in] key A FrodoKemKey holding a public key.
    \param [out] ct Buffer to receive the ciphertext.
    \param [out] ss Buffer to receive the shared secret.
    \param [in] rng An initialized random number generator.

    _Example_
    \code
    FrodoKemKey key;
    WC_RNG rng;
    word32 ctSz, ssSz;
    byte ct[WC_FRODOKEM_640_CIPHER_TEXT_SIZE];
    byte ss[WC_FRODOKEM_640_SS_SIZE];
    int ret;

    // key holds a decoded/generated public key
    wc_FrodoKemKey_CipherTextSize(&key, &ctSz);
    wc_FrodoKemKey_SharedSecretSize(&key, &ssSz);

    ret = wc_FrodoKemKey_Encapsulate(&key, ct, ss, &rng);
    if (ret != 0) {
        // error encapsulating
    }
    \endcode

    \sa wc_FrodoKemKey_Decapsulate
    \sa wc_FrodoKemKey_EncapsulateWithRandom
    \sa wc_FrodoKemKey_CipherTextSize
*/
int wc_FrodoKemKey_Encapsulate(FrodoKemKey* key, unsigned char* ct,
    unsigned char* ss, WC_RNG* rng);

/*!
    \ingroup FRODO_KEM

    \brief Encapsulates using caller-supplied random bytes rather than
    an RNG. This is primarily for testing and known answer tests;
    production code should use wc_FrodoKemKey_Encapsulate(). The required
    length depends on the parameter set (for example
    WC_FRODOKEM_640_ENC_RAND_SZ for FrodoKEM-640).

    \return 0 on success.
    \return BAD_FUNC_ARG if key, ct, ss or rand is NULL, or len is not
    the length required for the key's parameter set.
    \return BAD_STATE_E if key does not hold a public key.

    \param [in] key A FrodoKemKey holding a public key.
    \param [out] ct Buffer to receive the ciphertext.
    \param [out] ss Buffer to receive the shared secret.
    \param [in] rand Buffer of random bytes.
    \param [in] len Length of rand in bytes; must equal the parameter
    set's WC_FRODOKEM_<set>_ENC_RAND_SZ.

    \sa wc_FrodoKemKey_Encapsulate
*/
int wc_FrodoKemKey_EncapsulateWithRandom(FrodoKemKey* key,
    unsigned char* ct, unsigned char* ss, const unsigned char* rand,
    int len);

/*!
    \ingroup FRODO_KEM

    \brief Decapsulates a ciphertext to recover the shared secret using
    the key's private key. FrodoKEM is IND-CCA2 secure: a ciphertext
    that does not decrypt consistently yields a pseudo-random shared
    secret (implicit rejection) rather than an error, so decapsulation
    of a valid ciphertext reproduces the shared secret from
    encapsulation. Size the ss buffer with
    wc_FrodoKemKey_SharedSecretSize().

    \return 0 on success (a shared secret is always produced for a
    correctly sized ciphertext).
    \return BAD_FUNC_ARG if key, ss or ct is NULL, or len is not the
    ciphertext size for the key's parameter set.
    \return BAD_STATE_E if key does not hold a private key.
    \return MEMORY_E on allocation failure.

    \param [in] key A FrodoKemKey holding a private key.
    \param [out] ss Buffer to receive the shared secret.
    \param [in] ct The ciphertext to decapsulate.
    \param [in] len Length of ct in bytes; must equal the ciphertext
    size for the key's parameter set.

    _Example_
    \code
    FrodoKemKey key;
    word32 ssSz;
    byte ss[WC_FRODOKEM_640_SS_SIZE];
    int ret;

    // key holds a decoded/generated private key
    wc_FrodoKemKey_SharedSecretSize(&key, &ssSz);

    ret = wc_FrodoKemKey_Decapsulate(&key, ss, ct, ctSz);
    if (ret != 0) {
        // error decapsulating
    }
    \endcode

    \sa wc_FrodoKemKey_Encapsulate
    \sa wc_FrodoKemKey_SharedSecretSize
*/
int wc_FrodoKemKey_Decapsulate(FrodoKemKey* key, unsigned char* ss,
    const unsigned char* ct, word32 len);

/*!
    \ingroup FRODO_KEM

    \brief Decodes (imports) a FrodoKEM private key from its serialized
    form into an initialized key. The expected length matches
    wc_FrodoKemKey_PrivateKeySize() for the key's parameter set.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or in is NULL, or len is not the private
    key size for the key's parameter set.

    \param [in,out] key An initialized FrodoKemKey to hold the private
    key.
    \param [in] in The serialized private key.
    \param [in] len Length of in in bytes.

    \sa wc_FrodoKemKey_EncodePrivateKey
    \sa wc_FrodoKemKey_PrivateKeySize
    \sa wc_FrodoKemKey_Decapsulate
*/
int wc_FrodoKemKey_DecodePrivateKey(FrodoKemKey* key,
    const unsigned char* in, word32 len);

/*!
    \ingroup FRODO_KEM

    \brief Decodes (imports) a FrodoKEM public key from its serialized
    form into an initialized key. The expected length matches
    wc_FrodoKemKey_PublicKeySize() for the key's parameter set.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or in is NULL, or len is not the public
    key size for the key's parameter set.

    \param [in,out] key An initialized FrodoKemKey to hold the public
    key.
    \param [in] in The serialized public key.
    \param [in] len Length of in in bytes.

    \sa wc_FrodoKemKey_EncodePublicKey
    \sa wc_FrodoKemKey_PublicKeySize
    \sa wc_FrodoKemKey_Encapsulate
*/
int wc_FrodoKemKey_DecodePublicKey(FrodoKemKey* key,
    const unsigned char* in, word32 len);

/*!
    \ingroup FRODO_KEM

    \brief Returns, through len, the size in bytes of a serialized
    private key for the key's parameter set. Use this to size the buffer
    passed to wc_FrodoKemKey_EncodePrivateKey().

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL.

    \param [in] key An initialized FrodoKemKey.
    \param [out] len Set to the private key size in bytes.

    \sa wc_FrodoKemKey_EncodePrivateKey
    \sa wc_FrodoKemKey_DecodePrivateKey
*/
int wc_FrodoKemKey_PrivateKeySize(FrodoKemKey* key, word32* len);

/*!
    \ingroup FRODO_KEM

    \brief Returns, through len, the size in bytes of a serialized
    public key for the key's parameter set. Use this to size the buffer
    passed to wc_FrodoKemKey_EncodePublicKey().

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL.

    \param [in] key An initialized FrodoKemKey.
    \param [out] len Set to the public key size in bytes.

    \sa wc_FrodoKemKey_EncodePublicKey
    \sa wc_FrodoKemKey_DecodePublicKey
*/
int wc_FrodoKemKey_PublicKeySize(FrodoKemKey* key, word32* len);

/*!
    \ingroup FRODO_KEM

    \brief Encodes (exports) the private key held by key into its
    serialized form. The out buffer must be at least
    wc_FrodoKemKey_PrivateKeySize() bytes.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or out is NULL, or len is smaller than
    the private key size for the key's parameter set.
    \return BAD_STATE_E if key does not hold a private key.

    \param [in] key A FrodoKemKey holding a private key.
    \param [out] out Buffer to receive the serialized private key.
    \param [in] len Length of the out buffer in bytes.

    \sa wc_FrodoKemKey_DecodePrivateKey
    \sa wc_FrodoKemKey_PrivateKeySize
*/
int wc_FrodoKemKey_EncodePrivateKey(FrodoKemKey* key,
    unsigned char* out, word32 len);

/*!
    \ingroup FRODO_KEM

    \brief Encodes (exports) the public key held by key into its
    serialized form. The out buffer must be at least
    wc_FrodoKemKey_PublicKeySize() bytes.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or out is NULL, or len is smaller than
    the public key size for the key's parameter set.
    \return BAD_STATE_E if key does not hold a public key.

    \param [in] key A FrodoKemKey holding a public key.
    \param [out] out Buffer to receive the serialized public key.
    \param [in] len Length of the out buffer in bytes.

    \sa wc_FrodoKemKey_DecodePublicKey
    \sa wc_FrodoKemKey_PublicKeySize
*/
int wc_FrodoKemKey_EncodePublicKey(FrodoKemKey* key,
    unsigned char* out, word32 len);
