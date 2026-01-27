/*!
    \ingroup MLKEM

    \brief This function allocates and initializes an MlKemKey object.

    The returned key is initialized for the specified ML-KEM parameter set
    (WC_ML_KEM_512 / WC_ML_KEM_768 / WC_ML_KEM_1024, or KYBER* types when
    WOLFSSL_MLKEM_KYBER is enabled).

    \return pointer Returned upon success
    \return NULL Returned if allocation or initialization fails

    \param type ML-KEM parameter set identifier (WC_ML_KEM_512 / _768 / _1024,
                or KYBER512 / KYBER768 / KYBER1024 when enabled)
    \param heap pointer to a heap identifier, for use with memory overrides
    \param devId ID to use with crypto callbacks or async hardware.
                Set to INVALID_DEVID (-2) if not used.

    _Example_
    \code
    MlKemKey* kem = wc_MlKemKey_New(WC_ML_KEM_512, NULL, INVALID_DEVID);
    if (kem == NULL) {
        // error
    }
    \endcode

    \sa wc_MlKemKey_Delete
    \sa wc_MlKemKey_Init
*/
WOLFSSL_API MlKemKey *wc_MlKemKey_New(int type, void *heap, int devId);

/*!
    \ingroup MLKEM

    \brief This function frees an MlKemKey object allocated by wc_MlKemKey_New().

    If \p key_p is not NULL, it can be used to clear the caller's pointer.

    \return 0 Returned upon successfully freeing the key
    \return BAD_FUNC_ARGS Returned if key is NULL (implementation dependent)

    \param key pointer to the MlKemKey object to delete
    \param key_p optional pointer to the key pointer to be cleared (may be NULL)

    _Example_
    \code
    MlKemKey* kem = wc_MlKemKey_New(WC_ML_KEM_512, NULL, INVALID_DEVID);
    // ...
    wc_MlKemKey_Delete(kem, &kem); // kem becomes NULL (when supported)
    \endcode

    \sa wc_MlKemKey_New
*/
WOLFSSL_API int wc_MlKemKey_Delete(MlKemKey *key, MlKemKey **key_p);
/*!
    \ingroup MLKEM

    \brief This function initializes a provided MlKemKey structure.

    This API is used when MlKemKey is allocated by the caller (e.g., on stack).
    The key is initialized for the specified ML-KEM parameter set.

    \return 0 Returned upon successfully initializing the ML-KEM key structure
    \return BAD_FUNC_ARGS Returned if the key pointer evaluates to NULL
    \return MEMORY_E Returned if memory allocation fails (when applicable)

    \param key pointer to the MlKemKey structure to initialize
    \param type ML-KEM parameter set identifier (WC_ML_KEM_512 / _768 / _1024,
                or KYBER512 / KYBER768 / KYBER1024 when enabled)
    \param heap pointer to a heap identifier, for use with memory overrides
    \param devId ID to use with crypto callbacks or async hardware.
                Set to INVALID_DEVID (-2) if not used.

    _Example_
    \code
    MlKemKey kem;
    int ret = wc_MlKemKey_Init(&kem, WC_ML_KEM_512, NULL, INVALID_DEVID);
    if (ret != 0) {
        // error
    }
    \endcode

    \sa wc_MlKemKey_Free
    \sa wc_MlKemKey_MakeKey
*/
WOLFSSL_API int wc_MlKemKey_Init(MlKemKey *key, int type, void *heap, int devId);

/*!
    \ingroup MLKEM

    \brief This function frees resources associated with a provided MlKemKey structure.

    \return 0 Returned upon success
    \return BAD_FUNC_ARGS Returned if key is NULL (implementation dependent)

    \param key pointer to the MlKemKey structure to free

    _Example_
    \code
    MlKemKey kem;
    wc_MlKemKey_Init(&kem, WC_ML_KEM_512, NULL, INVALID_DEVID);

    // ... use kem ...

    wc_MlKemKey_Free(&kem);
    \endcode

    \sa wc_MlKemKey_Init
*/
WOLFSSL_API int wc_MlKemKey_Free(MlKemKey *key);
/*!
    \ingroup MLKEM

    \brief This function generates an ML-KEM public/private key pair.

    The MlKemKey must be initialized prior to calling.
    RNG must be initialized before use.

    \return 0 Returned upon successfully generating a key pair
    \return BAD_FUNC_ARGS Returned if key or rng is NULL
    \return RNG_FAILURE_E Returned if RNG fails (when applicable)

    \param key pointer to the initialized MlKemKey structure
    \param rng pointer to an initialized WC_RNG structure

    _Example_
    \code
    MlKemKey kem;
    WC_RNG rng;

    wc_InitRng(&rng);
    wc_MlKemKey_Init(&kem, WC_ML_KEM_512, NULL, INVALID_DEVID);

    wc_MlKemKey_MakeKey(&kem, &rng);

    wc_MlKemKey_Free(&kem);
    wc_FreeRng(&rng);
    \endcode

    \sa wc_MlKemKey_MakeKeyWithRandom
*/
WOLFSSL_API int wc_MlKemKey_MakeKey(MlKemKey *key, WC_RNG *rng);

/*!
    \ingroup MLKEM

    \brief This function generates an ML-KEM key pair using caller-provided randomness.

    The required random length is fixed per API contract and should be
    WC_ML_KEM_MAKEKEY_RAND_SZ bytes.

    \return 0 Returned upon success
    \return BAD_FUNC_ARGS Returned if key or rand is NULL
    \return BUFFER_E Returned if len is not the required size (when applicable)

    \param key pointer to the initialized MlKemKey structure
    \param rand pointer to random bytes used to generate the key pair
    \param len length of \p rand in bytes (expected WC_ML_KEM_MAKEKEY_RAND_SZ)

    _Example_
    \code
    byte r[WC_ML_KEM_MAKEKEY_RAND_SZ];
    // fill r with deterministic test vector, etc.

    wc_MlKemKey_MakeKeyWithRandom(&kem, r, sizeof(r));
    \endcode

    \sa wc_MlKemKey_MakeKey
*/
WOLFSSL_API int wc_MlKemKey_MakeKeyWithRandom(MlKemKey *key,
                                              const unsigned char *rand, int len);
/*!
    \ingroup MLKEM

    \brief This function returns the ciphertext size in bytes for the key's parameter set.

    \return 0 Returned upon success
    \return BAD_FUNC_ARGS Returned if key or len is NULL

    \param key pointer to the initialized MlKemKey structure
    \param len output pointer receiving ciphertext size in bytes

    _Example_
    \code
    word32 ctSz;
    wc_MlKemKey_CipherTextSize(&kem, &ctSz);
    \endcode

    \sa wc_MlKemKey_Encapsulate
    \sa wc_MlKemKey_Decapsulate
*/
WOLFSSL_API int wc_MlKemKey_CipherTextSize(MlKemKey *key, word32 *len);

/*!
    \ingroup MLKEM

    \brief This function returns the shared secret size in bytes for the key's parameter set.

    \return 0 Returned upon success
    \return BAD_FUNC_ARGS Returned if key or len is NULL

    \param key pointer to the initialized MlKemKey structure
    \param len output pointer receiving shared secret size in bytes

    _Example_
    \code
    word32 ssSz;
    wc_MlKemKey_SharedSecretSize(&kem, &ssSz);
    \endcode

    \sa wc_MlKemKey_Encapsulate
    \sa wc_MlKemKey_Decapsulate
*/
WOLFSSL_API int wc_MlKemKey_SharedSecretSize(MlKemKey *key, word32 *len);

/*!
    \ingroup MLKEM

    \brief This function returns the encoded private key size in bytes.

    \return 0 Returned upon success
    \return BAD_FUNC_ARGS Returned if key or len is NULL

    \param key pointer to the initialized MlKemKey structure
    \param len output pointer receiving private key size in bytes

    \sa wc_MlKemKey_EncodePrivateKey
    \sa wc_MlKemKey_DecodePrivateKey
*/
WOLFSSL_API int wc_MlKemKey_PrivateKeySize(MlKemKey *key, word32 *len);

/*!
    \ingroup MLKEM

    \brief This function returns the encoded public key size in bytes.

    \return 0 Returned upon success
    \return BAD_FUNC_ARGS Returned if key or len is NULL

    \param key pointer to the initialized MlKemKey structure
    \param len output pointer receiving public key size in bytes

    \sa wc_MlKemKey_EncodePublicKey
    \sa wc_MlKemKey_DecodePublicKey
*/
WOLFSSL_API int wc_MlKemKey_PublicKeySize(MlKemKey *key, word32 *len);
/*!
    \ingroup MLKEM

    \brief This function encapsulates a shared secret to an ML-KEM public key.

    On success, this function outputs:
      - ciphertext (\p ct) to be sent to the recipient
      - shared secret (\p ss) to be kept locally

    The caller must allocate \p ct and \p ss with appropriate sizes for the key type.
    Use wc_MlKemKey_CipherTextSize() and wc_MlKemKey_SharedSecretSize() to obtain sizes.

    \return 0 Returned upon success
    \return BAD_FUNC_ARGS Returned if key, ct, ss, or rng is NULL
    \return RNG_FAILURE_E Returned if RNG fails (when applicable)

    \param key pointer to the MlKemKey structure containing the recipient public key
    \param ct output buffer for ciphertext (size depends on key type)
    \param ss output buffer for shared secret (size depends on key type)
    \param rng pointer to an initialized WC_RNG structure

    _Example_
    \code
    word32 ctSz, ssSz;
    wc_MlKemKey_CipherTextSize(&peerPub, &ctSz);
    wc_MlKemKey_SharedSecretSize(&peerPub, &ssSz);

    byte* ct = XMALLOC(ctSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    byte* ss = XMALLOC(ssSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    wc_MlKemKey_Encapsulate(&peerPub, ct, ss, &rng);
    \endcode

    \sa wc_MlKemKey_Decapsulate
    \sa wc_MlKemKey_EncapsulateWithRandom
*/
WOLFSSL_API int wc_MlKemKey_Encapsulate(MlKemKey *key, unsigned char *ct,
                                        unsigned char *ss, WC_RNG *rng);

/*!
    \ingroup MLKEM

    \brief This function encapsulates using caller-provided randomness.

    The required random length is fixed per API contract and should be
    WC_ML_KEM_ENC_RAND_SZ bytes.

    \return 0 Returned upon success
    \return BAD_FUNC_ARGS Returned if key, ct, ss, or rand is NULL
    \return BUFFER_E Returned if len is not the required size (when applicable)

    \param key pointer to the MlKemKey structure containing the recipient public key
    \param ct output buffer for ciphertext (size depends on key type)
    \param ss output buffer for shared secret (size depends on key type)
    \param rand pointer to random bytes used for encapsulation
    \param len length of \p rand in bytes (expected WC_ML_KEM_ENC_RAND_SZ)

    _Example_
    \code
    byte r[WC_ML_KEM_ENC_RAND_SZ];
    // fill r with deterministic test vector, etc.

    wc_MlKemKey_EncapsulateWithRandom(&peerPub, ct, ss, r, sizeof(r));
    \endcode

    \sa wc_MlKemKey_Encapsulate
*/
WOLFSSL_API int wc_MlKemKey_EncapsulateWithRandom(MlKemKey *key,
                                                  unsigned char *ct, unsigned char *ss, const unsigned char *rand, int len);

/*!
    \ingroup MLKEM

    \brief This function decapsulates a shared secret using an ML-KEM private key.

    The ciphertext buffer \p ct must contain the ciphertext produced by
    wc_MlKemKey_Encapsulate(), and \p len must be the ciphertext length in bytes.
    Use wc_MlKemKey_CipherTextSize() to obtain the expected length.

    The caller must allocate \p ss with the correct size for the key type.
    Use wc_MlKemKey_SharedSecretSize() to obtain the size.

    \return 0 Returned upon success
    \return BAD_FUNC_ARGS Returned if key, ss, or ct is NULL
    \return BUFFER_E Returned if len is invalid (when applicable)

    \param key pointer to the MlKemKey structure containing the recipient private key
    \param ss output buffer for shared secret (size depends on key type)
    \param ct input buffer containing ciphertext
    \param len ciphertext length in bytes

    _Example_
    \code
    word32 ctSz, ssSz;

    wc_MlKemKey_CipherTextSize(&myPriv, &ctSz);
    wc_MlKemKey_SharedSecretSize(&myPriv, &ssSz);

    byte ss2[WC_ML_KEM_SS_SZ]; // if using fixed 32-byte SS
    wc_MlKemKey_Decapsulate(&myPriv, ss2, ct, ctSz);
    \endcode

    \sa wc_MlKemKey_Encapsulate
*/
WOLFSSL_API int wc_MlKemKey_Decapsulate(MlKemKey *key, unsigned char *ss,
                                        const unsigned char *ct, word32 len);
/*!
    \ingroup MLKEM

    \brief This function decodes an encoded private key into an MlKemKey object.

    The key object must be initialized for the intended parameter set.

    \return 0 Returned upon success
    \return BAD_FUNC_ARGS Returned if key or in is NULL
    \return BUFFER_E Returned if len is invalid (when applicable)

    \param key pointer to the initialized MlKemKey structure
    \param in input buffer containing the encoded private key
    \param len size of the input buffer in bytes

    \sa wc_MlKemKey_EncodePrivateKey
    \sa wc_MlKemKey_PrivateKeySize
*/
WOLFSSL_API int wc_MlKemKey_DecodePrivateKey(MlKemKey *key,
                                             const unsigned char *in, word32 len);

/*!
    \ingroup MLKEM

    \brief This function decodes an encoded public key into an MlKemKey object.

    The key object must be initialized for the intended parameter set.

    \return 0 Returned upon success
    \return BAD_FUNC_ARGS Returned if key or in is NULL
    \return BUFFER_E Returned if len is invalid (when applicable)

    \param key pointer to the initialized MlKemKey structure
    \param in input buffer containing the encoded public key
    \param len size of the input buffer in bytes

    \sa wc_MlKemKey_EncodePublicKey
    \sa wc_MlKemKey_PublicKeySize
*/
WOLFSSL_API int wc_MlKemKey_DecodePublicKey(MlKemKey *key,
                                            const unsigned char *in, word32 len);

/*!
    \ingroup MLKEM

    \brief This function encodes an ML-KEM private key to a byte buffer.

    The caller must allocate \p out with at least the size returned by
    wc_MlKemKey_PrivateKeySize().

    \return 0 Returned upon success
    \return BAD_FUNC_ARGS Returned if key or out is NULL
    \return BUFFER_E Returned if len is too small (when applicable)

    \param key pointer to the MlKemKey structure containing a private key
    \param out output buffer for encoded private key
    \param len size of the output buffer in bytes

    \sa wc_MlKemKey_DecodePrivateKey
    \sa wc_MlKemKey_PrivateKeySize
*/
WOLFSSL_API int wc_MlKemKey_EncodePrivateKey(MlKemKey *key, unsigned char *out,
                                             word32 len);

/*!
    \ingroup MLKEM

    \brief This function encodes an ML-KEM public key to a byte buffer.

    The caller must allocate \p out with at least the size returned by
    wc_MlKemKey_PublicKeySize().

    \return 0 Returned upon success
    \return BAD_FUNC_ARGS Returned if key or out is NULL
    \return BUFFER_E Returned if len is too small (when applicable)

    \param key pointer to the MlKemKey structure containing a public key
    \param out output buffer for encoded public key
    \param len size of the output buffer in bytes

    \sa wc_MlKemKey_DecodePublicKey
    \sa wc_MlKemKey_PublicKeySize
*/
WOLFSSL_API int wc_MlKemKey_EncodePublicKey(MlKemKey *key, unsigned char *out,
                                            word32 len);
