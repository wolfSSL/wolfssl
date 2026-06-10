/*!
    \ingroup ML_DSA

    \brief Initializes a wc_MlDsaKey object. Must be called before any
    other ML-DSA operation. Use wc_MlDsaKey_Free() to release resources
    when done.

    ML-DSA (FIPS 204) is a quantum-resistant digital signature
    algorithm. Three parameter sets are defined and selected via
    wc_MlDsaKey_SetParams() after init:
      - WC_ML_DSA_44 (NIST security level 2),
      - WC_ML_DSA_65 (level 3),
      - WC_ML_DSA_87 (level 5).

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL.

    \param [in,out] key Pointer to the wc_MlDsaKey to initialize.
    \param [in] heap Heap hint for dynamic memory allocation. May be
    NULL.
    \param [in] devId Device identifier for hardware crypto callbacks.
    Use INVALID_DEVID for software-only.

    _Example_
    \code
    wc_MlDsaKey key;
    int ret;

    ret = wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID);
    if (ret != 0) {
        // error initializing key
    }
    ret = wc_MlDsaKey_SetParams(&key, WC_ML_DSA_65);
    // ... use key ...
    wc_MlDsaKey_Free(&key);
    \endcode

    \sa wc_MlDsaKey_Free
    \sa wc_MlDsaKey_SetParams
    \sa wc_MlDsaKey_MakeKey
*/
int wc_MlDsaKey_Init(wc_MlDsaKey* key, void* heap, int devId);

/*!
    \ingroup ML_DSA

    \brief Allocates and initializes a new wc_MlDsaKey on the heap.
    The returned pointer must be released with wc_MlDsaKey_Delete().
    Only available when wolfSSL is built without WC_NO_CONSTRUCTORS.

    \return Pointer to a freshly allocated wc_MlDsaKey on success.
    \return NULL on allocation failure.

    \param [in] heap Heap hint for dynamic memory allocation. May be
    NULL.
    \param [in] devId Device identifier for hardware crypto callbacks.
    Use INVALID_DEVID for software-only.

    _Example_
    \code
    wc_MlDsaKey* key = wc_MlDsaKey_New(NULL, INVALID_DEVID);
    if (key == NULL) {
        // allocation failed
    }
    // ... use key ...
    wc_MlDsaKey_Delete(key, &key);
    \endcode

    \sa wc_MlDsaKey_Delete
    \sa wc_MlDsaKey_Init
*/
wc_MlDsaKey* wc_MlDsaKey_New(void* heap, int devId);

/*!
    \ingroup ML_DSA

    \brief Frees and zeros a heap-allocated wc_MlDsaKey previously
    returned by wc_MlDsaKey_New(). On success the caller's pointer
    variable is set to NULL via key_p when key_p is not NULL. Only
    available when wolfSSL is built without WC_NO_CONSTRUCTORS.

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL.

    \param [in,out] key The wc_MlDsaKey to free.
    \param [in,out] key_p Optional address of the caller's pointer
    variable; when not NULL, it is set to NULL on success.

    \sa wc_MlDsaKey_New
*/
int wc_MlDsaKey_Delete(wc_MlDsaKey* key, wc_MlDsaKey** key_p);

/*!
    \ingroup ML_DSA

    \brief Initializes a wc_MlDsaKey with a device-side key
    identifier. Equivalent to wc_MlDsaKey_Init() but also stashes a
    binary id that a crypto callback can use to look up the underlying
    key material on the device. Only available when wolfSSL is built
    with WOLF_PRIVATE_KEY_ID.

    The id is copied into the key object; the caller may free its
    buffer immediately after this call returns.

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL.
    \return BUFFER_E if len is negative or exceeds MLDSA_MAX_ID_LEN.

    \param [in,out] key Pointer to the wc_MlDsaKey to initialize.
    \param [in] id Pointer to the device-side key identifier bytes.
    May be NULL when len is 0.
    \param [in] len Number of bytes in id; must be in
    [0, MLDSA_MAX_ID_LEN].
    \param [in] heap Heap hint for dynamic memory allocation. May be
    NULL.
    \param [in] devId Device identifier for the crypto callback.
    Should be a registered cb devId, not INVALID_DEVID.

    \sa wc_MlDsaKey_Init
    \sa wc_MlDsaKey_InitLabel
    \sa wc_MlDsaKey_Free
*/
int wc_MlDsaKey_InitId(wc_MlDsaKey* key, const unsigned char* id, int len,
    void* heap, int devId);

/*!
    \ingroup ML_DSA

    \brief Initializes a wc_MlDsaKey with a device-side key label.
    Equivalent to wc_MlDsaKey_Init() but also stashes a label string
    that a crypto callback can use to look up the underlying key
    material on the device. Only available when wolfSSL is built with
    WOLF_PRIVATE_KEY_ID.

    The label length is taken via XSTRLEN, so embedded NUL bytes
    terminate the label.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or label is NULL.
    \return BUFFER_E if label is empty or longer than
    MLDSA_MAX_LABEL_LEN.

    \param [in,out] key Pointer to the wc_MlDsaKey to initialize.
    \param [in] label NUL-terminated device-side key label string.
    \param [in] heap Heap hint for dynamic memory allocation. May be
    NULL.
    \param [in] devId Device identifier for the crypto callback.

    \sa wc_MlDsaKey_Init
    \sa wc_MlDsaKey_InitId
    \sa wc_MlDsaKey_Free
*/
int wc_MlDsaKey_InitLabel(wc_MlDsaKey* key, const char* label, void* heap,
    int devId);

/*!
    \ingroup ML_DSA

    \brief Selects the ML-DSA parameter set for this key. Must be
    called after wc_MlDsaKey_Init() and before key generation, signing
    or verifying.

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL or level is not a recognized
    parameter set.
    \return NOT_COMPILED_IN if level names a parameter set that was
    disabled at build time.

    \param [in,out] key Pointer to an initialized wc_MlDsaKey.
    \param [in] level Parameter set: WC_ML_DSA_44, WC_ML_DSA_65 or
    WC_ML_DSA_87.

    \sa wc_MlDsaKey_GetParams
    \sa wc_MlDsaKey_Init
*/
int wc_MlDsaKey_SetParams(wc_MlDsaKey* key, byte level);

/*!
    \ingroup ML_DSA

    \brief Retrieves the ML-DSA parameter set currently selected on
    this key.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or level is NULL.

    \param [in] key Pointer to an initialized wc_MlDsaKey.
    \param [out] level Receives WC_ML_DSA_44, WC_ML_DSA_65 or
    WC_ML_DSA_87.

    \sa wc_MlDsaKey_SetParams
*/
int wc_MlDsaKey_GetParams(wc_MlDsaKey* key, byte* level);

/*!
    \ingroup ML_DSA

    \brief Releases resources held by a wc_MlDsaKey. After this call
    the object must be re-initialized with wc_MlDsaKey_Init() before
    it can be used again. Safe to call with a NULL pointer.

    \param [in,out] key Pointer to the wc_MlDsaKey to free.

    \sa wc_MlDsaKey_Init
*/
void wc_MlDsaKey_Free(wc_MlDsaKey* key);

/*!
    \ingroup ML_DSA

    \brief Generates a new ML-DSA key pair using the provided RNG.
    The parameter set must already be set with wc_MlDsaKey_SetParams().
    Both the public and private key components are populated on
    success.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or rng is NULL.
    \return MEMORY_E on allocation failure.

    \param [in,out] key Pointer to a wc_MlDsaKey with parameters set.
    \param [in] rng Pointer to an initialized WC_RNG.

    _Example_
    \code
    wc_MlDsaKey key;
    WC_RNG rng;

    wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID);
    wc_MlDsaKey_SetParams(&key, WC_ML_DSA_65);
    wc_InitRng(&rng);

    if (wc_MlDsaKey_MakeKey(&key, &rng) != 0) {
        // error generating key pair
    }
    \endcode

    \sa wc_MlDsaKey_MakeKeyFromSeed
    \sa wc_MlDsaKey_SetParams
*/
int wc_MlDsaKey_MakeKey(wc_MlDsaKey* key, WC_RNG* rng);

/*!
    \ingroup ML_DSA

    \brief Deterministically generates an ML-DSA key pair from a
    32-byte seed. Useful for known-answer tests and for applications
    that derive the seed from another secret. The seed buffer must
    contain exactly 32 bytes.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or seed is NULL.

    \param [in,out] key Pointer to a wc_MlDsaKey with parameters set.
    \param [in] seed Pointer to a 32-byte seed buffer.

    \sa wc_MlDsaKey_MakeKey
*/
int wc_MlDsaKey_MakeKeyFromSeed(wc_MlDsaKey* key, const byte* seed);

/*!
    \ingroup ML_DSA

    \brief Signs a message with ML-DSA using the FIPS 204
    randomized-with-context signing API. Pass ctx=NULL and ctxLen=0
    for an empty context.

    On entry *sigLen is the size of the sig buffer; on success it is
    updated to the number of bytes written. Use wc_MlDsaKey_SigSize()
    or wc_MlDsaKey_GetSigLen() to determine the required buffer size.

    \return 0 on success.
    \return BAD_FUNC_ARG if any required pointer is NULL or ctxLen is
    invalid.
    \return BUFFER_E if the sig buffer is too small.

    \param [in,out] key Pointer to a wc_MlDsaKey with the private key.
    \param [in] ctx Optional context string (may be NULL when
    ctxLen=0).
    \param [in] ctxLen Length of ctx in bytes; must be 0 when ctx is
    NULL, and no greater than 255.
    \param [out] sig Buffer that receives the signature.
    \param [in,out] sigLen In: size of sig. Out: bytes written.
    \param [in] msg Message to sign.
    \param [in] msgLen Length of msg in bytes.
    \param [in] rng Pointer to an initialized WC_RNG.

    \sa wc_MlDsaKey_VerifyCtx
    \sa wc_MlDsaKey_SignCtxWithSeed
    \sa wc_MlDsaKey_SignCtxHash
*/
int wc_MlDsaKey_SignCtx(wc_MlDsaKey* key, const byte* ctx, byte ctxLen,
    byte* sig, word32* sigLen, const byte* msg, word32 msgLen, WC_RNG* rng);

/*!
    \ingroup ML_DSA

    \brief HashML-DSA signing variant: signs a pre-hashed message.
    The caller supplies the hash bytes and identifies the hash
    algorithm. This is the "pre-hash" mode of FIPS 204.

    \return 0 on success.
    \return BAD_FUNC_ARG if any required pointer is NULL, ctxLen is
    invalid, or hashAlg is not supported.
    \return BUFFER_E if the sig buffer is too small.

    \param [in,out] key Pointer to a wc_MlDsaKey with the private key.
    \param [in] ctx Optional context string (NULL when ctxLen=0).
    \param [in] ctxLen Length of ctx in bytes; no greater than 255.
    \param [out] sig Buffer that receives the signature.
    \param [in,out] sigLen In: size of sig. Out: bytes written.
    \param [in] hash The message digest to sign.
    \param [in] hashLen Length of hash in bytes.
    \param [in] hashAlg Hash algorithm identifier (e.g. WC_HASH_TYPE_SHA256).
    \param [in] rng Pointer to an initialized WC_RNG.

    \sa wc_MlDsaKey_SignCtx
    \sa wc_MlDsaKey_VerifyCtxHash
*/
int wc_MlDsaKey_SignCtxHash(wc_MlDsaKey* key, const byte* ctx, byte ctxLen,
    byte* sig, word32* sigLen, const byte* hash, word32 hashLen,
    int hashAlg, WC_RNG* rng);

/*!
    \ingroup ML_DSA

    \brief Legacy ML-DSA signing API without a context parameter.
    Only available when wolfSSL is built with WOLFSSL_MLDSA_NO_CTX.
    New code should call wc_MlDsaKey_SignCtx() with ctx=NULL and
    ctxLen=0 for a FIPS 204 compliant empty-context signature.

    \return See wc_MlDsaKey_SignCtx().

    \param [in,out] key Pointer to a wc_MlDsaKey with the private key.
    \param [out] sig Buffer that receives the signature.
    \param [in,out] sigLen In: size of sig. Out: bytes written.
    \param [in] msg Message to sign.
    \param [in] msgLen Length of msg in bytes.
    \param [in] rng Pointer to an initialized WC_RNG.

    \sa wc_MlDsaKey_SignCtx
    \sa wc_MlDsaKey_Verify
*/
int wc_MlDsaKey_Sign(wc_MlDsaKey* key, byte* sig, word32* sigLen,
    const byte* msg, word32 msgLen, WC_RNG* rng);

/*!
    \ingroup ML_DSA

    \brief Deterministic signing variant of wc_MlDsaKey_SignCtx(). The
    32-byte seed replaces the randomness an RNG would supply, so the
    same key/ctx/msg/seed always produces the same signature.

    \return See wc_MlDsaKey_SignCtx().

    \param [in,out] key Pointer to a wc_MlDsaKey with the private key.
    \param [in] ctx Optional context string (NULL when ctxLen=0).
    \param [in] ctxLen Length of ctx; no greater than 255.
    \param [out] sig Buffer that receives the signature.
    \param [in,out] sigLen In: size of sig. Out: bytes written.
    \param [in] msg Message to sign.
    \param [in] msgLen Length of msg in bytes.
    \param [in] seed 32-byte seed bytes.

    \sa wc_MlDsaKey_SignCtx
    \sa wc_MlDsaKey_SignCtxHashWithSeed
*/
int wc_MlDsaKey_SignCtxWithSeed(wc_MlDsaKey* key, const byte* ctx, byte ctxLen,
    byte* sig, word32* sigLen, const byte* msg, word32 msgLen,
    const byte* seed);

/*!
    \ingroup ML_DSA

    \brief Deterministic HashML-DSA signing: like
    wc_MlDsaKey_SignCtxHash() but uses the supplied 32-byte seed in
    place of an RNG.

    \return See wc_MlDsaKey_SignCtxHash().

    \param [in,out] key Pointer to a wc_MlDsaKey with the private key.
    \param [in] ctx Optional context string (NULL when ctxLen=0).
    \param [in] ctxLen Length of ctx; no greater than 255.
    \param [out] sig Buffer that receives the signature.
    \param [in,out] sigLen In: size of sig. Out: bytes written.
    \param [in] hash The message digest to sign.
    \param [in] hashLen Length of hash in bytes.
    \param [in] hashAlg Hash algorithm identifier.
    \param [in] seed 32-byte seed bytes.

    \sa wc_MlDsaKey_SignCtxHash
*/
int wc_MlDsaKey_SignCtxHashWithSeed(wc_MlDsaKey* key, const byte* ctx,
    byte ctxLen, byte* sig, word32* sigLen, const byte* hash,
    word32 hashLen, int hashAlg, const byte* seed);

/*!
    \ingroup ML_DSA

    \brief Signs a pre-computed mu value (the externally derived
    SHAKE256 hash of (tr || ctx || msg) per FIPS 204) using a
    deterministic 32-byte seed. Used by protocols that need to split
    the message-hashing step from the signing step.

    \return 0 on success.
    \return BAD_FUNC_ARG if any required pointer is NULL or muLen is
    not 64.
    \return BUFFER_E if the sig buffer is too small.

    \param [in,out] key Pointer to a wc_MlDsaKey with the private key.
    \param [out] sig Buffer that receives the signature.
    \param [in,out] sigLen In: size of sig. Out: bytes written.
    \param [in] mu The 64-byte mu value (SHAKE256 output).
    \param [in] muLen Length of mu; must be 64.
    \param [in] seed 32-byte seed bytes.

    \sa wc_MlDsaKey_VerifyMu
*/
int wc_MlDsaKey_SignMuWithSeed(wc_MlDsaKey* key, byte* sig, word32* sigLen,
    const byte* mu, word32 muLen, const byte* seed);

/*!
    \ingroup ML_DSA

    \brief Legacy seed-based signing API without a context parameter.
    Only available when wolfSSL is built with WOLFSSL_MLDSA_NO_CTX.
    New code should use wc_MlDsaKey_SignCtxWithSeed().

    \return See wc_MlDsaKey_SignCtxWithSeed().

    \param [in,out] key Pointer to a wc_MlDsaKey with the private key.
    \param [out] sig Buffer that receives the signature.
    \param [in,out] sigLen In: size of sig. Out: bytes written.
    \param [in] msg Message to sign.
    \param [in] msgLen Length of msg in bytes.
    \param [in] seed 32-byte seed bytes.

    \sa wc_MlDsaKey_SignCtxWithSeed
*/
int wc_MlDsaKey_SignWithSeed(wc_MlDsaKey* key, byte* sig, word32* sigLen,
    const byte* msg, word32 msgLen, const byte* seed);

/*!
    \ingroup ML_DSA

    \brief Verifies an ML-DSA signature produced by
    wc_MlDsaKey_SignCtx() or one of its variants. On entry res is set
    to 0; on success it is set to 1 when the signature is valid and
    left at 0 otherwise. The function's return value reports whether
    verification could be carried out at all; a bad signature is NOT a
    function-level error.

    \return 0 if verification completed (check res for the result).
    \return BAD_FUNC_ARG if any required pointer is NULL or ctxLen is
    invalid.

    \param [in,out] key Pointer to a wc_MlDsaKey with the public key.
    \param [in] sig Signature bytes to verify.
    \param [in] sigLen Length of sig in bytes.
    \param [in] ctx Optional context string (NULL when ctxLen=0).
    \param [in] ctxLen Length of ctx; no greater than 255.
    \param [in] msg Message that was signed.
    \param [in] msgLen Length of msg in bytes.
    \param [out] res Set to 1 on a valid signature, 0 otherwise.

    \sa wc_MlDsaKey_SignCtx
    \sa wc_MlDsaKey_VerifyCtxHash
    \sa wc_MlDsaKey_VerifyMu
*/
int wc_MlDsaKey_VerifyCtx(wc_MlDsaKey* key, const byte* sig, word32 sigLen,
    const byte* ctx, byte ctxLen, const byte* msg, word32 msgLen, int* res);

/*!
    \ingroup ML_DSA

    \brief Verifies a HashML-DSA signature where the message digest
    was supplied directly. See wc_MlDsaKey_VerifyCtx() for the
    semantics of res.

    \return 0 if verification completed (check res for the result).
    \return BAD_FUNC_ARG if any required pointer is NULL, ctxLen is
    invalid, or hashAlg is unsupported.

    \param [in,out] key Pointer to a wc_MlDsaKey with the public key.
    \param [in] sig Signature bytes to verify.
    \param [in] sigLen Length of sig in bytes.
    \param [in] ctx Optional context string (NULL when ctxLen=0).
    \param [in] ctxLen Length of ctx; no greater than 255.
    \param [in] hash The message digest that was signed.
    \param [in] hashLen Length of hash in bytes.
    \param [in] hashAlg Hash algorithm identifier.
    \param [out] res Set to 1 on a valid signature, 0 otherwise.

    \sa wc_MlDsaKey_SignCtxHash
    \sa wc_MlDsaKey_VerifyCtx
*/
int wc_MlDsaKey_VerifyCtxHash(wc_MlDsaKey* key, const byte* sig, word32 sigLen,
    const byte* ctx, byte ctxLen, const byte* hash, word32 hashLen,
    int hashAlg, int* res);

/*!
    \ingroup ML_DSA

    \brief Verifies a signature over a pre-computed 64-byte mu value
    (see wc_MlDsaKey_SignMuWithSeed()). See wc_MlDsaKey_VerifyCtx()
    for the semantics of res.

    \return 0 if verification completed (check res for the result).
    \return BAD_FUNC_ARG if any required pointer is NULL or muLen is
    not 64.

    \param [in,out] key Pointer to a wc_MlDsaKey with the public key.
    \param [in] sig Signature bytes to verify.
    \param [in] sigLen Length of sig in bytes.
    \param [in] mu The 64-byte mu value.
    \param [in] muLen Length of mu; must be 64.
    \param [out] res Set to 1 on a valid signature, 0 otherwise.

    \sa wc_MlDsaKey_SignMuWithSeed
*/
int wc_MlDsaKey_VerifyMu(wc_MlDsaKey* key, const byte* sig, word32 sigLen,
    const byte* mu, word32 muLen, int* res);

/*!
    \ingroup ML_DSA

    \brief Legacy ML-DSA verify API without a context parameter. Only
    available when wolfSSL is built with WOLFSSL_MLDSA_NO_CTX. New
    code should use wc_MlDsaKey_VerifyCtx() with ctx=NULL and
    ctxLen=0.

    \return See wc_MlDsaKey_VerifyCtx().

    \param [in,out] key Pointer to a wc_MlDsaKey with the public key.
    \param [in] sig Signature bytes to verify.
    \param [in] sigLen Length of sig in bytes.
    \param [in] msg Message that was signed.
    \param [in] msgLen Length of msg in bytes.
    \param [out] res Set to 1 on a valid signature, 0 otherwise.

    \sa wc_MlDsaKey_VerifyCtx
    \sa wc_MlDsaKey_Sign
*/
int wc_MlDsaKey_Verify(wc_MlDsaKey* key, const byte* sig, word32 sigLen,
    const byte* msg, word32 msgLen, int* res);

/*!
    \ingroup ML_DSA

    \brief Returns the size in bytes of the encoded private key for
    the parameter set selected on this key. Equivalent to
    wc_MlDsaKey_PrivSize() and provided for API compatibility.

    \return Encoded private key size in bytes on success (positive
    value).
    \return BAD_FUNC_ARG if key is NULL or no parameter set is
    selected.

    \param [in] key Pointer to a wc_MlDsaKey with parameters set.

    \sa wc_MlDsaKey_PrivSize
    \sa wc_MlDsaKey_PubSize
    \sa wc_MlDsaKey_SigSize
*/
int wc_MlDsaKey_Size(wc_MlDsaKey* key);

/*!
    \ingroup ML_DSA

    \brief Returns the size in bytes of the encoded private key for
    the parameter set selected on this key.

    \return Encoded private key size on success (positive value).
    \return BAD_FUNC_ARG if key is NULL or no parameter set is
    selected.

    \param [in] key Pointer to a wc_MlDsaKey with parameters set.

    \sa wc_MlDsaKey_PubSize
    \sa wc_MlDsaKey_GetPrivLen
*/
int wc_MlDsaKey_PrivSize(wc_MlDsaKey* key);

/*!
    \ingroup ML_DSA

    \brief Returns the size in bytes of the encoded public key for the
    parameter set selected on this key.

    \return Encoded public key size on success (positive value).
    \return BAD_FUNC_ARG if key is NULL or no parameter set is
    selected.

    \param [in] key Pointer to a wc_MlDsaKey with parameters set.

    \sa wc_MlDsaKey_PrivSize
    \sa wc_MlDsaKey_GetPubLen
*/
int wc_MlDsaKey_PubSize(wc_MlDsaKey* key);

/*!
    \ingroup ML_DSA

    \brief Returns the size in bytes of the signature produced by
    this key's parameter set.

    \return Signature size on success (positive value).
    \return BAD_FUNC_ARG if key is NULL or no parameter set is
    selected.

    \param [in] key Pointer to a wc_MlDsaKey with parameters set.

    \sa wc_MlDsaKey_GetSigLen
    \sa wc_MlDsaKey_SignCtx
*/
int wc_MlDsaKey_SigSize(wc_MlDsaKey* key);

/*!
    \ingroup ML_DSA

    \brief Writes the encoded private key size into *len. Equivalent
    information to wc_MlDsaKey_PrivSize() but uses an out-parameter
    style.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL, or no parameter set is
    selected.

    \param [in] key Pointer to a wc_MlDsaKey with parameters set.
    \param [out] len Receives the private key size in bytes.

    \sa wc_MlDsaKey_PrivSize
*/
int wc_MlDsaKey_GetPrivLen(wc_MlDsaKey* key, int* len);

/*!
    \ingroup ML_DSA

    \brief Writes the encoded public key size into *len. Equivalent
    information to wc_MlDsaKey_PubSize() but uses an out-parameter
    style.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL, or no parameter set is
    selected.

    \param [in] key Pointer to a wc_MlDsaKey with parameters set.
    \param [out] len Receives the public key size in bytes.

    \sa wc_MlDsaKey_PubSize
*/
int wc_MlDsaKey_GetPubLen(wc_MlDsaKey* key, int* len);

/*!
    \ingroup ML_DSA

    \brief Writes the signature size into *len. Equivalent
    information to wc_MlDsaKey_SigSize() but uses an out-parameter
    style.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL, or no parameter set is
    selected.

    \param [in] key Pointer to a wc_MlDsaKey with parameters set.
    \param [out] len Receives the signature size in bytes.

    \sa wc_MlDsaKey_SigSize
*/
int wc_MlDsaKey_GetSigLen(wc_MlDsaKey* key, int* len);

/*!
    \ingroup ML_DSA

    \brief Self-checks an ML-DSA key by recomputing the public key
    from the private and comparing against the stored public. Only
    available when wolfSSL is built with WOLFSSL_MLDSA_CHECK_KEY.

    \return 0 if the key is consistent.
    \return BAD_FUNC_ARG if key is NULL.
    \return PUBLIC_KEY_E if the recomputed public does not match.

    \param [in] key Pointer to a wc_MlDsaKey with both public and
    private parts populated.
*/
int wc_MlDsaKey_CheckKey(wc_MlDsaKey* key);

/*!
    \ingroup ML_DSA

    \brief Imports a raw ML-DSA public key. The parameter set must
    already be selected on the key. inLen must match the size returned
    by wc_MlDsaKey_PubSize() for the selected parameter set.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or in is NULL.
    \return BUFFER_E if inLen does not match the expected public key
    size.

    \param [in,out] key Pointer to a wc_MlDsaKey with parameters set.
    \param [in] in Raw public key bytes.
    \param [in] inLen Length of in in bytes.

    \sa wc_MlDsaKey_ExportPubRaw
    \sa wc_MlDsaKey_ImportPrivRaw
*/
int wc_MlDsaKey_ImportPubRaw(wc_MlDsaKey* key, const byte* in, word32 inLen);

/*!
    \ingroup ML_DSA

    \brief Imports a raw ML-DSA private key. The parameter set must
    already be selected. privSz must match the size returned by
    wc_MlDsaKey_PrivSize().

    \return 0 on success.
    \return BAD_FUNC_ARG if key or priv is NULL.
    \return BUFFER_E if privSz does not match the expected private key
    size.

    \param [in,out] key Pointer to a wc_MlDsaKey with parameters set.
    \param [in] priv Raw private key bytes.
    \param [in] privSz Length of priv in bytes.

    \sa wc_MlDsaKey_ExportPrivRaw
    \sa wc_MlDsaKey_ImportKey
*/
int wc_MlDsaKey_ImportPrivRaw(wc_MlDsaKey* key, const byte* priv,
    word32 privSz);

/*!
    \ingroup ML_DSA

    \brief Imports a raw ML-DSA key pair (private and public parts
    together). The parameter set must already be selected.

    \return 0 on success.
    \return BAD_FUNC_ARG if any required pointer is NULL.
    \return BUFFER_E if privSz or pubSz does not match the expected
    sizes.

    \param [in,out] key Pointer to a wc_MlDsaKey with parameters set.
    \param [in] priv Raw private key bytes.
    \param [in] privSz Length of priv.
    \param [in] pub Raw public key bytes.
    \param [in] pubSz Length of pub.

    \sa wc_MlDsaKey_ExportKey
*/
int wc_MlDsaKey_ImportKey(wc_MlDsaKey* key, const byte* priv, word32 privSz,
    const byte* pub, word32 pubSz);

/*!
    \ingroup ML_DSA

    \brief Exports the raw ML-DSA public key. On entry *outLen is the
    size of out; on success it is updated to the bytes written.

    \return 0 on success.
    \return BAD_FUNC_ARG if any required pointer is NULL.
    \return BUFFER_E if *outLen is smaller than the public key size.

    \param [in] key Pointer to a wc_MlDsaKey with a public key.
    \param [out] out Buffer that receives the public key.
    \param [in,out] outLen In: size of out. Out: bytes written.

    \sa wc_MlDsaKey_ImportPubRaw
*/
int wc_MlDsaKey_ExportPubRaw(wc_MlDsaKey* key, byte* out, word32* outLen);

/*!
    \ingroup ML_DSA

    \brief Exports the raw ML-DSA private key. On entry *outLen is the
    size of out; on success it is updated to the bytes written.

    \return 0 on success.
    \return BAD_FUNC_ARG if any required pointer is NULL.
    \return BUFFER_E if *outLen is smaller than the private key size.

    \param [in] key Pointer to a wc_MlDsaKey with a private key.
    \param [out] out Buffer that receives the private key.
    \param [in,out] outLen In: size of out. Out: bytes written.

    \sa wc_MlDsaKey_ImportPrivRaw
*/
int wc_MlDsaKey_ExportPrivRaw(wc_MlDsaKey* key, byte* out, word32* outLen);

/*!
    \ingroup ML_DSA

    \brief Exports both raw public and private ML-DSA key components
    in one call.

    \return 0 on success.
    \return BAD_FUNC_ARG if any required pointer is NULL.
    \return BUFFER_E if either buffer is too small.

    \param [in] key Pointer to a wc_MlDsaKey with both key parts.
    \param [out] priv Buffer that receives the private key.
    \param [in,out] privSz In: size of priv. Out: bytes written.
    \param [out] pub Buffer that receives the public key.
    \param [in,out] pubSz In: size of pub. Out: bytes written.

    \sa wc_MlDsaKey_ImportKey
*/
int wc_MlDsaKey_ExportKey(wc_MlDsaKey* key, byte* priv, word32 *privSz,
    byte* pub, word32 *pubSz);

/*!
    \ingroup ML_DSA

    \brief Parses an ML-DSA private key from a DER/ASN.1 encoded
    buffer (PKCS#8 OneAsymmetricKey). The parameter set is inferred
    from the algorithm identifier in the encoding, so it does NOT
    need to be set beforehand. On success *inOutIdx is advanced past
    the consumed bytes.

    Only available when WOLFSSL_MLDSA_NO_ASN1 is not defined.

    \return 0 on success.
    \return BAD_FUNC_ARG if any required pointer is NULL.
    \return ASN_PARSE_E on malformed encoding.

    \param [in,out] key Pointer to an initialized wc_MlDsaKey.
    \param [in] input DER-encoded private key bytes.
    \param [in] inSz Length of input in bytes.
    \param [in,out] inOutIdx In: offset into input where decoding
    starts. Out: offset past the consumed bytes.

    \sa wc_MlDsaKey_PrivateKeyToDer
    \sa wc_MlDsaKey_PublicKeyDecode
*/
int wc_MlDsaKey_PrivateKeyDecode(wc_MlDsaKey* key, const byte* input,
    word32 inSz, word32* inOutIdx);

/*!
    \ingroup ML_DSA

    \brief Parses an ML-DSA public key from a DER/ASN.1 encoded
    buffer (SubjectPublicKeyInfo). The parameter set is inferred from
    the algorithm identifier. On success *inOutIdx is advanced past
    the consumed bytes.

    \return 0 on success.
    \return BAD_FUNC_ARG if any required pointer is NULL.
    \return ASN_PARSE_E on malformed encoding.

    \param [in,out] key Pointer to an initialized wc_MlDsaKey.
    \param [in] input DER-encoded SPKI bytes.
    \param [in] inSz Length of input in bytes.
    \param [in,out] inOutIdx In: offset into input where decoding
    starts. Out: offset past the consumed bytes.

    \sa wc_MlDsaKey_PublicKeyToDer
*/
int wc_MlDsaKey_PublicKeyDecode(wc_MlDsaKey* key, const byte* input,
    word32 inSz, word32* inOutIdx);

/*!
    \ingroup ML_DSA

    \brief Encodes an ML-DSA public key to DER. When withAlg is
    non-zero the output is a full SubjectPublicKeyInfo (with
    AlgorithmIdentifier); when zero the output is the raw public key
    bytes.

    Pass NULL as output to query the required buffer size.

    \return Size of the encoded DER in bytes on success.
    \return BAD_FUNC_ARG if key is NULL or no parameter set is
    selected.
    \return BUFFER_E if output is non-NULL and inLen is smaller than
    the required size.

    \param [in] key Pointer to a wc_MlDsaKey with a public key.
    \param [out] output Buffer that receives the DER encoding, or
    NULL to query size.
    \param [in] inLen Size of output (ignored when output is NULL).
    \param [in] withAlg Non-zero to emit SubjectPublicKeyInfo, zero
    for the raw public key only.

    \sa wc_MlDsaKey_PublicKeyDecode
    \sa wc_MlDsaKey_KeyToDer
*/
int wc_MlDsaKey_PublicKeyToDer(wc_MlDsaKey* key, byte* output,
    word32 inLen, int withAlg);

/*!
    \ingroup ML_DSA

    \brief Encodes an ML-DSA key pair (public + private) to DER as a
    PKCS#8 OneAsymmetricKey structure. Pass NULL as output to query
    the required buffer size.

    \return Size of the encoded DER in bytes on success.
    \return BAD_FUNC_ARG if key is NULL or no parameter set is
    selected.
    \return MISSING_KEY if the private key has not been set.
    \return BUFFER_E if output is non-NULL and inLen is too small.

    \param [in] key Pointer to a wc_MlDsaKey with the private key.
    \param [out] output Buffer that receives the DER encoding, or
    NULL to query size.
    \param [in] inLen Size of output (ignored when output is NULL).

    \sa wc_MlDsaKey_PrivateKeyDecode
    \sa wc_MlDsaKey_PrivateKeyToDer
    \sa wc_MlDsaKey_PublicKeyToDer
*/
int wc_MlDsaKey_KeyToDer(wc_MlDsaKey* key, byte* output, word32 inLen);

/*!
    \ingroup ML_DSA

    \brief Encodes the ML-DSA private key to DER. Per FIPS 204 the
    private key encoding includes the public component, so this
    function is currently an alias of wc_MlDsaKey_KeyToDer() kept for
    API parity with other algorithms.

    \return Size of the encoded DER in bytes on success.
    \return Inherited error codes from wc_MlDsaKey_KeyToDer().

    \param [in] key Pointer to a wc_MlDsaKey with the private key.
    \param [out] output Buffer that receives the DER encoding, or
    NULL to query size.
    \param [in] inLen Size of output (ignored when output is NULL).

    \sa wc_MlDsaKey_KeyToDer
    \sa wc_MlDsaKey_PrivateKeyDecode
*/
int wc_MlDsaKey_PrivateKeyToDer(wc_MlDsaKey* key, byte* output,
    word32 inLen);
