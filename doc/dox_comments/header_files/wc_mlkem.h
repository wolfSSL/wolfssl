/*!
    \ingroup ML_KEM

    \brief Allocates and initializes a new MlKemKey on the heap. The
    returned pointer must be released with wc_MlKemKey_Delete().

    ML-KEM (FIPS 203) is a quantum-resistant key encapsulation
    mechanism. The type parameter selects the variant: WC_ML_KEM_512
    (NIST security level 1), WC_ML_KEM_768 (level 3) or
    WC_ML_KEM_1024 (level 5).

    \return Pointer to a freshly allocated MlKemKey on success.
    \return NULL on allocation failure or if type is invalid.

    \param [in] type ML-KEM variant: WC_ML_KEM_512, WC_ML_KEM_768 or
    WC_ML_KEM_1024.
    \param [in] heap Heap hint for dynamic memory allocation. May be
    NULL.
    \param [in] devId Device identifier for hardware crypto callbacks.
    Use INVALID_DEVID for software-only.

    _Example_
    \code
    MlKemKey* key = wc_MlKemKey_New(WC_ML_KEM_768, NULL,
        INVALID_DEVID);
    if (key == NULL) {
        // allocation failed
    }
    // ... use key ...
    wc_MlKemKey_Delete(key, &key);
    \endcode

    \sa wc_MlKemKey_Delete
    \sa wc_MlKemKey_Init
*/
MlKemKey* wc_MlKemKey_New(int type, void* heap, int devId);

/*!
    \ingroup ML_KEM

    \brief Frees and zeros a heap-allocated MlKemKey previously
    returned by wc_MlKemKey_New(). On success the caller's pointer
    variable is set to NULL via key_p when key_p is not NULL.

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL.

    \param [in,out] key The MlKemKey to free.
    \param [in,out] key_p Optional address of the caller's pointer
    variable; when not NULL, it is set to NULL on success.

    \sa wc_MlKemKey_New
*/
int wc_MlKemKey_Delete(MlKemKey* key, MlKemKey** key_p);

/*!
    \ingroup ML_KEM

    \brief Initializes an MlKemKey object in place. The type parameter
    selects the ML-KEM variant and must be one of WC_ML_KEM_512,
    WC_ML_KEM_768 or WC_ML_KEM_1024.

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL or type is invalid.
    \return NOT_COMPILED_IN if type names a variant that was disabled
    at build time.

    \param [in,out] key Pointer to the MlKemKey to initialize.
    \param [in] type ML-KEM variant: WC_ML_KEM_512, WC_ML_KEM_768 or
    WC_ML_KEM_1024.
    \param [in] heap Heap hint for dynamic memory allocation. May be
    NULL.
    \param [in] devId Device identifier for hardware crypto callbacks.

    _Example_
    \code
    MlKemKey key;
    int ret;

    ret = wc_MlKemKey_Init(&key, WC_ML_KEM_768, NULL, INVALID_DEVID);
    if (ret != 0) {
        // error initializing key
    }
    // ... use key ...
    wc_MlKemKey_Free(&key);
    \endcode

    \sa wc_MlKemKey_Free
    \sa wc_MlKemKey_MakeKey
*/
int wc_MlKemKey_Init(MlKemKey* key, int type, void* heap, int devId);

/*!
    \ingroup ML_KEM

    \brief Releases resources held by an MlKemKey. After this call
    the object must be re-initialized with wc_MlKemKey_Init() before
    it can be used again. Safe to call with a NULL pointer.

    \return 0 on success, including when key is NULL.

    \param [in,out] key Pointer to the MlKemKey to free.

    \sa wc_MlKemKey_Init
*/
int wc_MlKemKey_Free(MlKemKey* key);

/*!
    \ingroup ML_KEM

    \brief Initializes an MlKemKey with a device-side key identifier.
    Equivalent to wc_MlKemKey_Init() but also stashes a binary id that
    a crypto callback can use to look up the underlying key material
    on the device. Only available when wolfSSL is built with
    WOLF_PRIVATE_KEY_ID.

    The id is copied into the key object; the caller may free its
    buffer immediately after this call returns.

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL, if id is NULL while len is
    non-zero, or if type is invalid.
    \return BUFFER_E if len is negative or exceeds MLKEM_MAX_ID_LEN.

    \param [in,out] key Pointer to the MlKemKey to initialize.
    \param [in] type ML-KEM variant identifier.
    \param [in] id Pointer to the device-side key identifier bytes.
    May be NULL when len is 0.
    \param [in] len Number of bytes in id. Must be in the range
    [0, MLKEM_MAX_ID_LEN].
    \param [in] heap Heap hint for dynamic memory allocation.
    \param [in] devId Device identifier for the crypto callback.

    \sa wc_MlKemKey_Init
    \sa wc_MlKemKey_Init_Label
    \sa wc_MlKemKey_Free
*/
int wc_MlKemKey_Init_Id(MlKemKey* key, int type, const unsigned char* id,
    int len, void* heap, int devId);

/*!
    \ingroup ML_KEM

    \brief Initializes an MlKemKey with a device-side key label.
    Equivalent to wc_MlKemKey_Init() but also stashes a label string
    that a crypto callback can use to look up the underlying key
    material on the device. Only available when wolfSSL is built with
    WOLF_PRIVATE_KEY_ID.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or label is NULL or type is invalid.

    \param [in,out] key Pointer to the MlKemKey to initialize.
    \param [in] type ML-KEM variant identifier.
    \param [in] label NUL-terminated device-side key label.
    \param [in] heap Heap hint for dynamic memory allocation.
    \param [in] devId Device identifier for the crypto callback.

    \sa wc_MlKemKey_Init
    \sa wc_MlKemKey_Init_Id
    \sa wc_MlKemKey_Free
*/
int wc_MlKemKey_Init_Label(MlKemKey* key, int type, const char* label,
    void* heap, int devId);

/*!
    \ingroup ML_KEM

    \brief Generates a new ML-KEM key pair using the provided RNG.
    Both the public and private components are populated on success.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or rng is NULL.
    \return MEMORY_E on allocation failure.

    \param [in,out] key Pointer to an initialized MlKemKey.
    \param [in] rng Pointer to an initialized WC_RNG.

    _Example_
    \code
    MlKemKey key;
    WC_RNG rng;

    wc_MlKemKey_Init(&key, WC_ML_KEM_768, NULL, INVALID_DEVID);
    wc_InitRng(&rng);

    if (wc_MlKemKey_MakeKey(&key, &rng) != 0) {
        // error generating key pair
    }
    \endcode

    \sa wc_MlKemKey_MakeKeyWithRandom
    \sa wc_MlKemKey_Encapsulate
    \sa wc_MlKemKey_Decapsulate
*/
int wc_MlKemKey_MakeKey(MlKemKey* key, WC_RNG* rng);

/*!
    \ingroup ML_KEM

    \brief Deterministic key generation: produces an ML-KEM key pair
    from the supplied 64 bytes of randomness instead of an RNG. Useful
    for known-answer tests and for applications that derive key
    randomness from another secret.

    \return 0 on success.
    \return BAD_FUNC_ARG if any required pointer is NULL or len is
    not 64.

    \param [in,out] key Pointer to an initialized MlKemKey.
    \param [in] rand Pointer to a buffer of randomness.
    \param [in] len Length of rand in bytes; must be 64.

    \sa wc_MlKemKey_MakeKey
*/
int wc_MlKemKey_MakeKeyWithRandom(MlKemKey* key, const unsigned char* rand,
    int len);

/*!
    \ingroup ML_KEM

    \brief Returns the ciphertext size in bytes for the variant
    selected on this key.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL.

    \param [in] key Pointer to an initialized MlKemKey.
    \param [out] len Receives the ciphertext size in bytes.

    \sa wc_MlKemKey_SharedSecretSize
    \sa wc_MlKemKey_Encapsulate
*/
int wc_MlKemKey_CipherTextSize(MlKemKey* key, word32* len);

/*!
    \ingroup ML_KEM

    \brief Returns the shared-secret size in bytes for ML-KEM. The
    value is the same (32 bytes) across all parameter sets but is
    queried programmatically for symmetry with
    wc_MlKemKey_CipherTextSize().

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL.

    \param [in] key Pointer to an initialized MlKemKey.
    \param [out] len Receives the shared-secret size in bytes.

    \sa wc_MlKemKey_CipherTextSize
*/
int wc_MlKemKey_SharedSecretSize(MlKemKey* key, word32* len);

/*!
    \ingroup ML_KEM

    \brief Encapsulates a fresh shared secret against the public key
    held in key. Produces a ciphertext that the holder of the
    corresponding private key can pass to wc_MlKemKey_Decapsulate() to
    recover the same shared secret.

    The ct buffer must be at least wc_MlKemKey_CipherTextSize() bytes
    and ss must be at least wc_MlKemKey_SharedSecretSize() bytes.

    \return 0 on success.
    \return BAD_FUNC_ARG if any required pointer is NULL.
    \return BAD_STATE_E if the public key has not been set.
    \return NOT_COMPILED_IN if wolfSSL was built with WC_NO_RNG.
    \return MEMORY_E on allocation failure inside the encapsulation
    routine.

    \param [in,out] key Pointer to an MlKemKey containing a public key.
    \param [out] ct Buffer that receives the ciphertext.
    \param [out] ss Buffer that receives the 32-byte shared secret.
    \param [in] rng Pointer to an initialized WC_RNG.

    _Example_
    \code
    MlKemKey key;
    unsigned char ct[WC_ML_KEM_768_CIPHER_TEXT_SIZE];
    unsigned char ss[WC_ML_KEM_SS_SZ];

    // ... key holds the recipient's public key ...
    if (wc_MlKemKey_Encapsulate(&key, ct, ss, &rng) != 0) {
        // error during encapsulation
    }
    // Send ct to the holder of the matching private key.
    \endcode

    \sa wc_MlKemKey_EncapsulateWithRandom
    \sa wc_MlKemKey_Decapsulate
*/
int wc_MlKemKey_Encapsulate(MlKemKey* key, unsigned char* ct,
    unsigned char* ss, WC_RNG* rng);

/*!
    \ingroup ML_KEM

    \brief Deterministic variant of wc_MlKemKey_Encapsulate(). Uses
    the supplied 32 bytes of randomness instead of consuming output
    from an RNG.

    \return 0 on success.
    \return BAD_FUNC_ARG if any required pointer is NULL or len is
    not 32.

    \param [in,out] key Pointer to an MlKemKey containing a public key.
    \param [out] ct Buffer that receives the ciphertext.
    \param [out] ss Buffer that receives the 32-byte shared secret.
    \param [in] rand Buffer of randomness.
    \param [in] len Length of rand in bytes; must be 32.

    \sa wc_MlKemKey_Encapsulate
*/
int wc_MlKemKey_EncapsulateWithRandom(MlKemKey* key, unsigned char* ct,
    unsigned char* ss, const unsigned char* rand, int len);

/*!
    \ingroup ML_KEM

    \brief Decapsulates a ciphertext using the private key held in key
    and recovers the shared secret produced by
    wc_MlKemKey_Encapsulate(). ML-KEM decapsulation is constant time
    and includes an implicit-rejection check on malformed ciphertexts
    (an attacker cannot learn the validity of ct from the runtime).

    The ss buffer must be at least wc_MlKemKey_SharedSecretSize()
    bytes and ct must be exactly wc_MlKemKey_CipherTextSize() bytes.

    \return 0 on success (a shared secret was written to ss).
    \return BAD_FUNC_ARG if any required pointer is NULL.
    \return BAD_STATE_E if the private key has not been set.
    \return BUFFER_E if len does not match the expected ciphertext
    size for the configured ML-KEM variant.
    \return NOT_COMPILED_IN if the key's ML-KEM variant was disabled
    at build time.
    \return MEMORY_E on allocation failure.

    \param [in,out] key Pointer to an MlKemKey with the private key.
    \param [out] ss Buffer that receives the 32-byte shared secret.
    \param [in] ct The ciphertext to decapsulate.
    \param [in] len Length of ct in bytes.

    \sa wc_MlKemKey_Encapsulate
    \sa wc_MlKemKey_CipherTextSize
*/
int wc_MlKemKey_Decapsulate(MlKemKey* key, unsigned char* ss,
    const unsigned char* ct, word32 len);

/*!
    \ingroup ML_KEM

    \brief Decodes a raw ML-KEM private key into key. The variant must
    already be selected on the key (typically via wc_MlKemKey_Init()
    or wc_MlKemKey_New()) and len must match the private key size for
    that variant.

    \return 0 on success.
    \return BAD_FUNC_ARG if any required pointer is NULL or len does
    not match the expected size.

    \param [in,out] key Pointer to an initialized MlKemKey.
    \param [in] in Raw private key bytes.
    \param [in] len Length of in in bytes.

    \sa wc_MlKemKey_EncodePrivateKey
    \sa wc_MlKemKey_PrivateKeySize
*/
int wc_MlKemKey_DecodePrivateKey(MlKemKey* key, const unsigned char* in,
    word32 len);

/*!
    \ingroup ML_KEM

    \brief Decodes a raw ML-KEM public key into key. The variant must
    already be selected on the key and len must match the public key
    size for that variant.

    \return 0 on success.
    \return BAD_FUNC_ARG if any required pointer is NULL or len does
    not match the expected size.

    \param [in,out] key Pointer to an initialized MlKemKey.
    \param [in] in Raw public key bytes.
    \param [in] len Length of in in bytes.

    \sa wc_MlKemKey_EncodePublicKey
    \sa wc_MlKemKey_PublicKeySize
*/
int wc_MlKemKey_DecodePublicKey(MlKemKey* key, const unsigned char* in,
    word32 len);

/*!
    \ingroup ML_KEM

    \brief Returns the encoded private key size in bytes for the
    variant selected on this key.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL.

    \param [in] key Pointer to an initialized MlKemKey.
    \param [out] len Receives the private key size in bytes.

    \sa wc_MlKemKey_PublicKeySize
*/
int wc_MlKemKey_PrivateKeySize(MlKemKey* key, word32* len);

/*!
    \ingroup ML_KEM

    \brief Returns the encoded public key size in bytes for the
    variant selected on this key.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL.

    \param [in] key Pointer to an initialized MlKemKey.
    \param [out] len Receives the public key size in bytes.

    \sa wc_MlKemKey_PrivateKeySize
*/
int wc_MlKemKey_PublicKeySize(MlKemKey* key, word32* len);

/*!
    \ingroup ML_KEM

    \brief Encodes the ML-KEM private key into out. The out buffer
    length must be exactly wc_MlKemKey_PrivateKeySize() bytes.

    \return 0 on success.
    \return BAD_FUNC_ARG if any required pointer is NULL.
    \return BAD_STATE_E if the private and public keys are not both
    set on the key object.
    \return BUFFER_E if len does not exactly equal the encoded
    private key size for the configured ML-KEM variant.
    \return NOT_COMPILED_IN if the key's ML-KEM variant was disabled
    at build time.

    \param [in] key Pointer to an MlKemKey with a private key.
    \param [out] out Buffer that receives the encoded private key.
    \param [in] len Length of out in bytes.

    \sa wc_MlKemKey_DecodePrivateKey
    \sa wc_MlKemKey_PrivateKeySize
*/
int wc_MlKemKey_EncodePrivateKey(MlKemKey* key, unsigned char* out,
    word32 len);

/*!
    \ingroup ML_KEM

    \brief Encodes the ML-KEM public key into out. The out buffer
    length must be exactly wc_MlKemKey_PublicKeySize() bytes.

    \return 0 on success.
    \return BAD_FUNC_ARG if any required pointer is NULL.
    \return BAD_STATE_E if the public key has not been set.
    \return BUFFER_E if len does not exactly equal the encoded public
    key size for the configured ML-KEM variant.
    \return NOT_COMPILED_IN if the key's ML-KEM variant was disabled
    at build time.

    \param [in] key Pointer to an MlKemKey with a public key.
    \param [out] out Buffer that receives the encoded public key.
    \param [in] len Length of out in bytes.

    \sa wc_MlKemKey_DecodePublicKey
    \sa wc_MlKemKey_PublicKeySize
*/
int wc_MlKemKey_EncodePublicKey(MlKemKey* key, unsigned char* out,
    word32 len);
