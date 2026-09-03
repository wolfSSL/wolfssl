/*!
    \ingroup MCELIECE_KEM

    \brief Allocates and initializes a new McElieceKey on the heap. The
    returned pointer must be released with wc_McElieceKey_Delete().

    Classic McEliece is a conservative, code-based key encapsulation
    mechanism built on binary Goppa codes (draft-josefsson-mceliece). The
    type parameter is a base parameter set - WC_MCELIECE_6688128,
    WC_MCELIECE_6960119 or WC_MCELIECE_8192128 (all NIST level 5) -
    optionally OR'd with MCELIECE_F (semi-systematic MatGen, which speeds
    up key generation) and/or MCELIECE_PC (plaintext confirmation). Named
    combinations such as WC_MCELIECE_6688128F and WC_MCELIECE_8192128PCF
    are provided. Public keys are large (~1 MB), so the key object holds
    heap-allocated buffers.

    \return Pointer to a freshly allocated McElieceKey on success.
    \return NULL on allocation failure or if type is invalid.

    \param [in] type McEliece key type: a base parameter set optionally
    OR'd with MCELIECE_F and/or MCELIECE_PC.
    \param [in] heap Heap hint for dynamic memory allocation. May be
    NULL.
    \param [in] devId Device identifier for hardware crypto callbacks.
    Use INVALID_DEVID for software-only.

    _Example_
    \code
    McElieceKey* key = wc_McElieceKey_New(WC_MCELIECE_6688128F, NULL,
        INVALID_DEVID);
    if (key == NULL) {
        // allocation failed
    }
    // ... use key ...
    wc_McElieceKey_Delete(key, &key);
    \endcode

    \sa wc_McElieceKey_Delete
    \sa wc_McElieceKey_Init
*/
McElieceKey* wc_McElieceKey_New(int type, void* heap, int devId);

/*!
    \ingroup MCELIECE_KEM

    \brief Frees and zeros a heap-allocated McElieceKey previously
    returned by wc_McElieceKey_New(), and clears the caller's pointer.

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL.

    \param [in,out] key The McElieceKey to free.
    \param [in,out] key_p Optional address of the caller's pointer to the
    key; set to NULL on return so the pointer cannot be reused. May be
    NULL.

    _Example_
    \code
    McElieceKey* key = wc_McElieceKey_New(WC_MCELIECE_8192128, NULL,
        INVALID_DEVID);
    // ... use key ...
    wc_McElieceKey_Delete(key, &key);
    // key is now NULL
    \endcode

    \sa wc_McElieceKey_New
*/
int wc_McElieceKey_Delete(McElieceKey* key, McElieceKey** key_p);

/*!
    \ingroup MCELIECE_KEM

    \brief Initializes a McElieceKey object in place (for a caller-owned,
    for example stack, object). The type parameter selects the parameter
    set as for wc_McElieceKey_New(). Release with wc_McElieceKey_Free().

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL or type has bits set outside a
    valid base parameter set and the MCELIECE_F / MCELIECE_PC modifiers.
    \return NOT_COMPILED_IN if type names a valid variant whose parameter
    set was not built into the library.

    \param [in,out] key Pointer to the McElieceKey to initialize.
    \param [in] type McEliece key type: a base parameter set optionally
    OR'd with MCELIECE_F and/or MCELIECE_PC.
    \param [in] heap Heap hint for dynamic memory allocation. May be
    NULL.
    \param [in] devId Device identifier for hardware crypto callbacks.
    Use INVALID_DEVID for software-only.

    _Example_
    \code
    McElieceKey key;
    int ret = wc_McElieceKey_Init(&key, WC_MCELIECE_6960119, NULL,
        INVALID_DEVID);
    if (ret == 0) {
        // ... use &key ...
        wc_McElieceKey_Free(&key);
    }
    \endcode

    \sa wc_McElieceKey_Free
    \sa wc_McElieceKey_New
*/
int wc_McElieceKey_Init(McElieceKey* key, int type, void* heap, int devId);

/*!
    \ingroup MCELIECE_KEM

    \brief Releases the heap buffers held by a McElieceKey initialized
    with wc_McElieceKey_Init() and zeroizes secret material. Does not free
    the key object itself.

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL.

    \param [in,out] key The McElieceKey to release.

    _Example_
    \code
    McElieceKey key;
    wc_McElieceKey_Init(&key, WC_MCELIECE_6688128, NULL, INVALID_DEVID);
    // ... use &key ...
    wc_McElieceKey_Free(&key);
    \endcode

    \sa wc_McElieceKey_Init
*/
int wc_McElieceKey_Free(McElieceKey* key);

/*!
    \ingroup MCELIECE_KEM

    \brief Generates a McEliece key pair into an initialized key object,
    using the supplied RNG (SeededKeyGen: a 32-byte delta seed is drawn
    and all retries are derived internally with SHAKE-256).

    \return 0 on success.
    \return BAD_FUNC_ARG if key or rng is NULL.
    \return NOT_COMPILED_IN if key generation was disabled
    (WOLFSSL_MCELIECE_NO_MAKE_KEY).
    \return A negative error code on RNG or generation failure.

    \param [in,out] key An initialized McElieceKey to populate.
    \param [in] rng An initialized WC_RNG.

    _Example_
    \code
    McElieceKey* key = wc_McElieceKey_New(WC_MCELIECE_6688128F, NULL,
        INVALID_DEVID);
    WC_RNG rng;
    wc_InitRng(&rng);
    int ret = wc_McElieceKey_MakeKey(key, &rng);
    \endcode

    \sa wc_McElieceKey_MakeKeyWithRandom
    \sa wc_McElieceKey_Encapsulate
*/
int wc_McElieceKey_MakeKey(McElieceKey* key, WC_RNG* rng);

/*!
    \ingroup MCELIECE_KEM

    \brief Generates a McEliece key pair from caller-supplied randomness
    rather than an RNG. Exactly the 32-byte delta seed is consumed; all
    internal retries are SHAKE-256 derived. Useful for reproducing known
    answer test vectors.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or rand is NULL, or len is not the
    required seed length.
    \return NOT_COMPILED_IN if key generation was disabled.

    \param [in,out] key An initialized McElieceKey to populate.
    \param [in] rand The 32-byte delta seed.
    \param [in] len Length of rand in bytes (must be 32).

    _Example_
    \code
    unsigned char delta[32] = { ... };
    int ret = wc_McElieceKey_MakeKeyWithRandom(key, delta, sizeof(delta));
    \endcode

    \sa wc_McElieceKey_MakeKey
*/
int wc_McElieceKey_MakeKeyWithRandom(McElieceKey* key,
    const unsigned char* rand, int len);

/*!
    \ingroup MCELIECE_KEM

    \brief Returns the ciphertext length in bytes for the key's parameter
    set (this depends on the base set and whether MCELIECE_PC is set).

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL.

    \param [in] key A McElieceKey with a resolved parameter set.
    \param [out] len The ciphertext length in bytes.

    _Example_
    \code
    word32 ctSz;
    wc_McElieceKey_CipherTextSize(key, &ctSz);
    unsigned char* ct = (unsigned char*)XMALLOC(ctSz, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    \endcode

    \sa wc_McElieceKey_Encapsulate
    \sa wc_McElieceKey_SharedSecretSize
*/
int wc_McElieceKey_CipherTextSize(const McElieceKey* key, word32* len);

/*!
    \ingroup MCELIECE_KEM

    \brief Returns the shared secret length in bytes (always 32 for
    Classic McEliece).

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL.

    \param [in] key A McElieceKey with a resolved parameter set.
    \param [out] len The shared secret length in bytes.

    _Example_
    \code
    word32 ssSz;
    wc_McElieceKey_SharedSecretSize(key, &ssSz);
    \endcode

    \sa wc_McElieceKey_CipherTextSize
    \sa wc_McElieceKey_Encapsulate
*/
int wc_McElieceKey_SharedSecretSize(const McElieceKey* key, word32* len);

/*!
    \ingroup MCELIECE_KEM

    \brief Returns the encoded public key length in bytes for the key's
    parameter set (approximately 1 MB).

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL.

    \param [in] key A McElieceKey with a resolved parameter set.
    \param [out] len The encoded public key length in bytes.

    _Example_
    \code
    word32 pubSz;
    wc_McElieceKey_PublicKeySize(key, &pubSz);
    \endcode

    \sa wc_McElieceKey_EncodePublicKey
    \sa wc_McElieceKey_PrivateKeySize
*/
int wc_McElieceKey_PublicKeySize(const McElieceKey* key, word32* len);

/*!
    \ingroup MCELIECE_KEM

    \brief Returns the encoded private key length in bytes for the key's
    parameter set.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL.

    \param [in] key A McElieceKey with a resolved parameter set.
    \param [out] len The encoded private key length in bytes.

    _Example_
    \code
    word32 privSz;
    wc_McElieceKey_PrivateKeySize(key, &privSz);
    \endcode

    \sa wc_McElieceKey_EncodePrivateKey
    \sa wc_McElieceKey_PublicKeySize
*/
int wc_McElieceKey_PrivateKeySize(const McElieceKey* key, word32* len);

/*!
    \ingroup MCELIECE_KEM

    \brief Encapsulates to a public key: draws a fixed-weight error
    vector from the RNG, computes the ciphertext, and derives the 32-byte
    shared secret via the Fujisaki-Okamoto transform. The key must have a
    public key set (from wc_McElieceKey_MakeKey() or
    wc_McElieceKey_DecodePublicKey()).

    \return 0 on success.
    \return BAD_FUNC_ARG if any argument is NULL.
    \return BAD_STATE_E if the key has no public key set.
    \return NOT_COMPILED_IN if encapsulation was disabled
    (WOLFSSL_MCELIECE_NO_ENCAPSULATE).

    \param [in] key A McElieceKey with a public key set.
    \param [out] ct Ciphertext buffer of wc_McElieceKey_CipherTextSize()
    bytes.
    \param [out] ss Shared secret buffer of 32 bytes.
    \param [in] rng An initialized WC_RNG.

    _Example_
    \code
    word32 ctSz, ssSz;
    wc_McElieceKey_CipherTextSize(key, &ctSz);
    wc_McElieceKey_SharedSecretSize(key, &ssSz);
    unsigned char ct[240], ss[32];
    int ret = wc_McElieceKey_Encapsulate(key, ct, ss, &rng);
    \endcode

    \sa wc_McElieceKey_Decapsulate
    \sa wc_McElieceKey_EncapsulateWithRandom
*/
int wc_McElieceKey_Encapsulate(McElieceKey* key, unsigned char* ct,
    unsigned char* ss, WC_RNG* rng);

/*!
    \ingroup MCELIECE_KEM

    \brief Encapsulates using caller-supplied randomness rather than an
    RNG. The bytes are consumed in fixed-weight rejection attempts; if the
    supplied randomness is exhausted before a valid error vector is found,
    an error is returned (unlike the RNG path, which draws more). Useful
    for reproducing known answer test vectors.

    \return 0 on success.
    \return BAD_FUNC_ARG if any argument is NULL or len is negative.
    \return BAD_STATE_E if the key has no public key set.
    \return BUFFER_E if the supplied randomness is exhausted before a
    valid error vector is found.
    \return MEMORY_E if a temporary allocation fails.
    \return NOT_COMPILED_IN if encapsulation was disabled.

    \param [in] key A McElieceKey with a public key set.
    \param [out] ct Ciphertext buffer of wc_McElieceKey_CipherTextSize()
    bytes.
    \param [out] ss Shared secret buffer of 32 bytes.
    \param [in] rand Randomness for the fixed-weight error draw.
    \param [in] len Length of rand in bytes.

    \sa wc_McElieceKey_Encapsulate
*/
int wc_McElieceKey_EncapsulateWithRandom(McElieceKey* key, unsigned char* ct,
    unsigned char* ss, const unsigned char* rand, int len);

/*!
    \ingroup MCELIECE_KEM

    \brief Decapsulates a ciphertext with the private key, recovering the
    32-byte shared secret. On a decoding failure the Fujisaki-Okamoto
    transform yields an implicit-rejection secret in constant time rather
    than signalling an error, so a wrong ciphertext does not leak.

    \return 0 on success (including the implicit-rejection case).
    \return BAD_FUNC_ARG if any argument is NULL.
    \return BUFFER_E if len is not the expected ciphertext length.
    \return BAD_STATE_E if the key has no private key set.
    \return NOT_COMPILED_IN if decapsulation was disabled
    (WOLFSSL_MCELIECE_NO_DECAPSULATE).

    \param [in] key A McElieceKey with a private key set.
    \param [out] ss Shared secret buffer of 32 bytes.
    \param [in] ct The ciphertext.
    \param [in] len Length of ct in bytes.

    _Example_
    \code
    unsigned char ss[32];
    int ret = wc_McElieceKey_Decapsulate(key, ss, ct, ctSz);
    \endcode

    \sa wc_McElieceKey_Encapsulate
*/
int wc_McElieceKey_Decapsulate(McElieceKey* key, unsigned char* ss,
    const unsigned char* ct, word32 len);

/*!
    \ingroup MCELIECE_KEM

    \brief Exports the public key in its standard byte encoding.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or out is NULL.
    \return BUFFER_E if len is smaller than the encoded public key size.
    \return BAD_STATE_E if the key has no public key set.

    \param [in] key A McElieceKey with a public key set.
    \param [out] out Output buffer of wc_McElieceKey_PublicKeySize() bytes.
    \param [in] len Length of out in bytes.

    \sa wc_McElieceKey_DecodePublicKey
    \sa wc_McElieceKey_PublicKeySize
*/
int wc_McElieceKey_EncodePublicKey(McElieceKey* key, unsigned char* out,
    word32 len);

/*!
    \ingroup MCELIECE_KEM

    \brief Imports a public key from its standard byte encoding into an
    initialized key object, so the key can be used for encapsulation. The
    unused padding bits are checked for parameter sets that require it.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or in is NULL, or the unused padding bits
    are non-zero.
    \return BUFFER_E if len does not match the public key size.
    \return MEMORY_E if the public key buffer could not be allocated.

    \param [in,out] key An initialized McElieceKey to load the key into.
    \param [in] in The encoded public key.
    \param [in] len Length of in in bytes.

    \sa wc_McElieceKey_EncodePublicKey
    \sa wc_McElieceKey_Encapsulate
*/
int wc_McElieceKey_DecodePublicKey(McElieceKey* key, const unsigned char* in,
    word32 len);

/*!
    \ingroup MCELIECE_KEM

    \brief Exports the private key in its standard byte encoding. The
    output contains secret material and should be protected.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or out is NULL.
    \return BUFFER_E if len is smaller than the encoded private key size.
    \return BAD_STATE_E if the key has no private key set.

    \param [in] key A McElieceKey with a private key set.
    \param [out] out Output buffer of wc_McElieceKey_PrivateKeySize()
    bytes.
    \param [in] len Length of out in bytes.

    \sa wc_McElieceKey_DecodePrivateKey
    \sa wc_McElieceKey_PrivateKeySize
*/
int wc_McElieceKey_EncodePrivateKey(McElieceKey* key, unsigned char* out,
    word32 len);

/*!
    \ingroup MCELIECE_KEM

    \brief Imports a private key from its standard byte encoding into an
    initialized key object, so the key can be used for decapsulation.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or in is NULL.
    \return BUFFER_E if len does not match the private key size.

    \param [in,out] key An initialized McElieceKey to load the key into.
    \param [in] in The encoded private key.
    \param [in] len Length of in in bytes.

    \sa wc_McElieceKey_EncodePrivateKey
    \sa wc_McElieceKey_Decapsulate
*/
int wc_McElieceKey_DecodePrivateKey(McElieceKey* key, const unsigned char* in,
    word32 len);
