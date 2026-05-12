/*!
    \ingroup SLH_DSA

    \brief Initializes an SLH-DSA key object with the specified parameter set.
    Must be called before any other SLH-DSA operation. Use wc_SlhDsaKey_Free()
    to release resources when done.

    SLH-DSA (FIPS 205) is a stateless hash-based digital signature algorithm.
    Parameter sets control the hash function (SHAKE or SHA2), security level
    (128, 192, 256), and speed/size tradeoff (s = small signatures,
    f = fast signing).

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL or param is invalid.

    \param [in,out] key Pointer to the SlhDsaKey to initialize.
    \param [in] param Parameter set to use. One of: SLHDSA_SHAKE128S,
    SLHDSA_SHAKE128F, SLHDSA_SHAKE192S, SLHDSA_SHAKE192F, SLHDSA_SHAKE256S,
    SLHDSA_SHAKE256F, SLHDSA_SHA2_128S, SLHDSA_SHA2_128F, SLHDSA_SHA2_192S,
    SLHDSA_SHA2_192F, SLHDSA_SHA2_256S, SLHDSA_SHA2_256F.
    \param [in] heap Pointer to heap hint for dynamic memory allocation.
    May be NULL.
    \param [in] devId Device identifier for hardware crypto callbacks.
    Use INVALID_DEVID for software-only.

    _Example_
    \code
    SlhDsaKey key;
    int ret;

    ret = wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID);
    if (ret != 0) {
        // error initializing key
    }
    // ... use key ...
    wc_SlhDsaKey_Free(&key);
    \endcode

    \sa wc_SlhDsaKey_Free
    \sa wc_SlhDsaKey_MakeKey
*/
int wc_SlhDsaKey_Init(SlhDsaKey* key, enum SlhDsaParam param,
    void* heap, int devId);

/*!
    \ingroup SLH_DSA

    \brief Frees resources associated with an SLH-DSA key object.

    \param [in,out] key Pointer to the SlhDsaKey to free. May be NULL.

    _Example_
    \code
    SlhDsaKey key;
    wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID);
    // ... use key ...
    wc_SlhDsaKey_Free(&key);
    \endcode

    \sa wc_SlhDsaKey_Init
*/
void wc_SlhDsaKey_Free(SlhDsaKey* key);

/*!
    \ingroup SLH_DSA

    \brief Generates a new SLH-DSA key pair using the RNG for randomness.
    The key must have been initialized with wc_SlhDsaKey_Init() first.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or rng is NULL, or key is not initialized.

    \param [in,out] key Pointer to an initialized SlhDsaKey.
    \param [in] rng Pointer to an initialized WC_RNG.

    _Example_
    \code
    SlhDsaKey key;
    WC_RNG rng;
    int ret;

    wc_InitRng(&rng);
    wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID);
    ret = wc_SlhDsaKey_MakeKey(&key, &rng);
    if (ret != 0) {
        // error generating key
    }
    \endcode

    \sa wc_SlhDsaKey_Init
    \sa wc_SlhDsaKey_MakeKeyWithRandom
*/
int wc_SlhDsaKey_MakeKey(SlhDsaKey* key, WC_RNG* rng);

/*!
    \ingroup SLH_DSA

    \brief Generates an SLH-DSA key pair from caller-provided seed material.
    This is the deterministic key generation interface — given the same seeds,
    the same key pair is produced.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or any seed pointer is NULL, or lengths
    do not match the parameter set's n value.

    \param [in,out] key Pointer to an initialized SlhDsaKey.
    \param [in] sk_seed Secret key seed (n bytes).
    \param [in] sk_seed_len Length of sk_seed.
    \param [in] sk_prf Secret key PRF seed (n bytes).
    \param [in] sk_prf_len Length of sk_prf.
    \param [in] pk_seed Public key seed (n bytes).
    \param [in] pk_seed_len Length of pk_seed.

    _Example_
    \code
    SlhDsaKey key;
    byte sk_seed[16], sk_prf[16], pk_seed[16]; // n=16 for 128-bit params
    int ret;

    // fill seeds with known values (e.g. from NIST test vectors)
    wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID);
    ret = wc_SlhDsaKey_MakeKeyWithRandom(&key,
        sk_seed, sizeof(sk_seed),
        sk_prf, sizeof(sk_prf),
        pk_seed, sizeof(pk_seed));
    \endcode

    \sa wc_SlhDsaKey_MakeKey
*/
int wc_SlhDsaKey_MakeKeyWithRandom(SlhDsaKey* key,
    const byte* sk_seed, word32 sk_seed_len,
    const byte* sk_prf, word32 sk_prf_len,
    const byte* pk_seed, word32 pk_seed_len);

/*!
    \ingroup SLH_DSA

    \brief Signs a message using the SLH-DSA external (pure) interface with
    deterministic randomness. This is FIPS 205 Algorithm 22 with opt_rand set
    to PK.seed. The message M is wrapped internally as
    M' = 0x00 || len(ctx) || ctx || M before signing.

    \return 0 on success.
    \return BAD_FUNC_ARG if key, msg, sig, or sigSz is NULL.
    \return BUFFER_E if the output buffer is too small.

    \param [in] key Pointer to a private SlhDsaKey.
    \param [in] ctx Context string for domain separation. May be NULL if
    ctxSz is 0.
    \param [in] ctxSz Length of the context string (0-255).
    \param [in] msg Pointer to the message to sign.
    \param [in] msgSz Length of the message.
    \param [out] sig Buffer to receive the signature.
    \param [in,out] sigSz On input, size of sig buffer. On output, actual
    signature length.

    _Example_
    \code
    SlhDsaKey key;
    byte sig[WC_SLHDSA_MAX_SIG_LEN];
    word32 sigSz = sizeof(sig);
    byte msg[] = "Hello World!";
    int ret;

    // key already generated via wc_SlhDsaKey_MakeKey()
    ret = wc_SlhDsaKey_SignDeterministic(&key, NULL, 0,
        msg, sizeof(msg), sig, &sigSz);
    \endcode

    \sa wc_SlhDsaKey_SignWithRandom
    \sa wc_SlhDsaKey_Sign
    \sa wc_SlhDsaKey_Verify
*/
int wc_SlhDsaKey_SignDeterministic(SlhDsaKey* key, const byte* ctx,
    byte ctxSz, const byte* msg, word32 msgSz, byte* sig, word32* sigSz);

/*!
    \ingroup SLH_DSA

    \brief Signs a message using the SLH-DSA external (pure) interface with
    caller-provided additional randomness. This is FIPS 205 Algorithm 22 with
    an explicit opt_rand value.

    \return 0 on success.
    \return BAD_FUNC_ARG if key, msg, sig, sigSz, or addRnd is NULL.

    \param [in] key Pointer to a private SlhDsaKey.
    \param [in] ctx Context string. May be NULL if ctxSz is 0.
    \param [in] ctxSz Length of the context string (0-255).
    \param [in] msg Pointer to the message to sign.
    \param [in] msgSz Length of the message.
    \param [out] sig Buffer to receive the signature.
    \param [in,out] sigSz On input, size of sig buffer. On output, actual
    signature length.
    \param [in] addRnd Additional randomness (n bytes, where n is the
    parameter set's security parameter).

    _Example_
    \code
    SlhDsaKey key;
    byte sig[WC_SLHDSA_MAX_SIG_LEN];
    word32 sigSz = sizeof(sig);
    byte msg[] = "Hello World!";
    byte addRnd[16]; // n=16 for 128-bit params
    int ret;

    wc_RNG_GenerateBlock(&rng, addRnd, sizeof(addRnd));
    ret = wc_SlhDsaKey_SignWithRandom(&key, NULL, 0,
        msg, sizeof(msg), sig, &sigSz, addRnd);
    \endcode

    \sa wc_SlhDsaKey_SignDeterministic
    \sa wc_SlhDsaKey_Sign
*/
int wc_SlhDsaKey_SignWithRandom(SlhDsaKey* key, const byte* ctx,
    byte ctxSz, const byte* msg, word32 msgSz, byte* sig, word32* sigSz,
    const byte* addRnd);

/*!
    \ingroup SLH_DSA

    \brief Signs a message using the SLH-DSA external (pure) interface with
    RNG-provided randomness. This is the general-purpose signing function
    that uses the WC_RNG for opt_rand.

    \return 0 on success.
    \return BAD_FUNC_ARG if key, msg, sig, sigSz, or rng is NULL.

    \param [in] key Pointer to a private SlhDsaKey.
    \param [in] ctx Context string. May be NULL if ctxSz is 0.
    \param [in] ctxSz Length of the context string (0-255).
    \param [in] msg Pointer to the message to sign.
    \param [in] msgSz Length of the message.
    \param [out] sig Buffer to receive the signature.
    \param [in,out] sigSz On input, size of sig buffer. On output, actual
    signature length.
    \param [in] rng Pointer to an initialized WC_RNG.

    _Example_
    \code
    SlhDsaKey key;
    WC_RNG rng;
    byte sig[WC_SLHDSA_MAX_SIG_LEN];
    word32 sigSz = sizeof(sig);
    byte msg[] = "Hello World!";
    int ret;

    ret = wc_SlhDsaKey_Sign(&key, NULL, 0,
        msg, sizeof(msg), sig, &sigSz, &rng);
    \endcode

    \sa wc_SlhDsaKey_SignDeterministic
    \sa wc_SlhDsaKey_Verify
*/
int wc_SlhDsaKey_Sign(SlhDsaKey* key, const byte* ctx,
    byte ctxSz, const byte* msg, word32 msgSz, byte* sig, word32* sigSz,
    WC_RNG* rng);

/*!
    \ingroup SLH_DSA

    \brief Verifies an SLH-DSA signature over a message using the external
    (pure) interface. This is FIPS 205 Algorithm 24. The message is wrapped
    internally as M' = 0x00 || len(ctx) || ctx || M before verification.

    \return 0 on success (signature valid).
    \return BAD_FUNC_ARG if key, msg, or sig is NULL, or ctx is NULL but
    ctxSz is greater than 0.
    \return BAD_LENGTH_E if sigSz does not match the parameter set's
    signature length.
    \return MISSING_KEY if the public key has not been set.
    \return SIG_VERIFY_E if the signature is invalid.

    \param [in] key Pointer to a public SlhDsaKey.
    \param [in] ctx Context string. May be NULL if ctxSz is 0.
    \param [in] ctxSz Length of the context string (0-255).
    \param [in] msg Pointer to the message to verify.
    \param [in] msgSz Length of the message.
    \param [in] sig Pointer to the signature to verify.
    \param [in] sigSz Length of the signature.

    _Example_
    \code
    SlhDsaKey key;
    byte sig[...]; // previously generated signature
    word32 sigSz;
    byte msg[] = "Hello World!";
    int ret;

    ret = wc_SlhDsaKey_Verify(&key, NULL, 0,
        msg, sizeof(msg), sig, sigSz);
    if (ret == 0) {
        // signature is valid
    }
    \endcode

    \sa wc_SlhDsaKey_Sign
    \sa wc_SlhDsaKey_SignDeterministic
*/
int wc_SlhDsaKey_Verify(SlhDsaKey* key, const byte* ctx,
    byte ctxSz, const byte* msg, word32 msgSz, const byte* sig,
    word32 sigSz);

/*!
    \ingroup SLH_DSA

    \brief Signs using the SLH-DSA internal interface with deterministic
    randomness. Unlike the external interface, M' is provided directly by
    the caller — no wrapping is performed. This corresponds to FIPS 205
    Algorithm 19 (slh_sign_internal) with opt_rand set to PK.seed.

    Use this when the ACVP signatureInterface=internal test framework or a
    protocol layer has already constructed M'. For HashSLH-DSA the caller
    builds M' as 0x01 || ctxSz || ctx || OID(hashType) || PHM and passes it
    in here, where PHM is the hash of the application message under hashType.

    \return 0 on success.
    \return BAD_FUNC_ARG if key, mprime, sig, or sigSz is NULL.
    \return BAD_LENGTH_E if sigSz is less than the parameter set's signature
    length.
    \return MISSING_KEY if the private key has not been set.

    \param [in] key Pointer to a private SlhDsaKey.
    \param [in] mprime Pointer to the pre-constructed M' message.
    \param [in] mprimeSz Length of M'.
    \param [out] sig Buffer to receive the signature.
    \param [in,out] sigSz On input, size of sig buffer. On output, actual
    signature length.

    _Example_
    \code
    SlhDsaKey key;
    byte sig[WC_SLHDSA_MAX_SIG_LEN];
    word32 sigSz = sizeof(sig);
    byte mprime[] = { ... }; // pre-constructed M'
    int ret;

    ret = wc_SlhDsaKey_SignMsgDeterministic(&key,
        mprime, sizeof(mprime), sig, &sigSz);
    \endcode

    \sa wc_SlhDsaKey_SignMsgWithRandom
    \sa wc_SlhDsaKey_VerifyMsg
    \sa wc_SlhDsaKey_SignDeterministic
    \sa wc_SlhDsaKey_SignHashDeterministic
*/
int wc_SlhDsaKey_SignMsgDeterministic(SlhDsaKey* key,
    const byte* mprime, word32 mprimeSz, byte* sig, word32* sigSz);

/*!
    \ingroup SLH_DSA

    \brief Signs using the SLH-DSA internal interface with caller-provided
    additional randomness. M' is provided directly — no wrapping is performed.
    This corresponds to FIPS 205 Algorithm 19 (slh_sign_internal) with an
    explicit opt_rand value. See wc_SlhDsaKey_SignMsgDeterministic for the M'
    layout used by HashSLH-DSA.

    \return 0 on success.
    \return BAD_FUNC_ARG if key, mprime, sig, sigSz, or addRnd is NULL.
    \return BAD_LENGTH_E if sigSz is less than the parameter set's signature
    length.
    \return MISSING_KEY if the private key has not been set.

    \param [in] key Pointer to a private SlhDsaKey.
    \param [in] mprime Pointer to the pre-constructed M' message.
    \param [in] mprimeSz Length of M'.
    \param [out] sig Buffer to receive the signature.
    \param [in,out] sigSz On input, size of sig buffer. On output, actual
    signature length.
    \param [in] addRnd Additional randomness (n bytes).

    _Example_
    \code
    SlhDsaKey key;
    byte sig[WC_SLHDSA_MAX_SIG_LEN];
    word32 sigSz = sizeof(sig);
    byte mprime[] = { ... };
    byte addRnd[16];
    int ret;

    wc_RNG_GenerateBlock(&rng, addRnd, sizeof(addRnd));
    ret = wc_SlhDsaKey_SignMsgWithRandom(&key,
        mprime, sizeof(mprime), sig, &sigSz, addRnd);
    \endcode

    \sa wc_SlhDsaKey_SignMsgDeterministic
    \sa wc_SlhDsaKey_VerifyMsg
    \sa wc_SlhDsaKey_SignHashWithRandom
*/
int wc_SlhDsaKey_SignMsgWithRandom(SlhDsaKey* key,
    const byte* mprime, word32 mprimeSz, byte* sig, word32* sigSz,
    const byte* addRnd);

/*!
    \ingroup SLH_DSA

    \brief Verifies an SLH-DSA signature using the internal interface. M' is
    provided directly — no wrapping is performed. This corresponds to FIPS 205
    Algorithm 20 (slh_verify_internal).

    \return 0 on success (signature valid).
    \return BAD_FUNC_ARG if key, mprime, or sig is NULL.
    \return BAD_LENGTH_E if sigSz does not match the parameter set's
    signature length.
    \return MISSING_KEY if the public key has not been set.
    \return SIG_VERIFY_E if the signature is invalid.

    \param [in] key Pointer to a public SlhDsaKey.
    \param [in] mprime Pointer to the pre-constructed M' message.
    \param [in] mprimeSz Length of M'.
    \param [in] sig Pointer to the signature to verify.
    \param [in] sigSz Length of the signature.

    _Example_
    \code
    SlhDsaKey key;
    byte sig[...]; // previously generated signature
    word32 sigSz;
    byte mprime[] = { ... };
    int ret;

    ret = wc_SlhDsaKey_VerifyMsg(&key,
        mprime, sizeof(mprime), sig, sigSz);
    if (ret == 0) {
        // signature is valid
    }
    \endcode

    \sa wc_SlhDsaKey_SignMsgDeterministic
    \sa wc_SlhDsaKey_Verify
    \sa wc_SlhDsaKey_VerifyHash
*/
int wc_SlhDsaKey_VerifyMsg(SlhDsaKey* key, const byte* mprime,
    word32 mprimeSz, const byte* sig, word32 sigSz);

/*!
    \ingroup SLH_DSA

    \brief Signs a caller-pre-hashed message digest using the SLH-DSA external
    (HashSLH-DSA) interface with deterministic randomness, per FIPS 205
    Algorithm 23 with the pre-hash domain separator (0x01). The caller must
    hash the application message with hashType first and pass the digest as
    hash; this function does NOT hash its input.

    \return 0 on success.
    \return BAD_FUNC_ARG if key, hash, sig, or sigSz is NULL.
    \return BAD_LENGTH_E if hashSz does not equal the digest size for hashType
    (32 for SHAKE128, 64 for SHAKE256 per FIPS 205 Section 10.2.2).
    \return NOT_COMPILED_IN if hashType is not supported in this build.
    \return MISSING_KEY if the private key has not been set.

    \param [in] key Pointer to a private SlhDsaKey.
    \param [in] ctx Context string. May be NULL if ctxSz is 0.
    \param [in] ctxSz Length of the context string (0-255).
    \param [in] hash Pointer to the pre-hashed message digest. hashSz must
    equal the digest size for hashType.
    \param [in] hashSz Length of the digest in bytes.
    \param [in] hashType Hash algorithm used for pre-hashing (selects OID).
    Supported: WC_HASH_TYPE_SHA224, WC_HASH_TYPE_SHA256, WC_HASH_TYPE_SHA384,
    WC_HASH_TYPE_SHA512, WC_HASH_TYPE_SHA512_224, WC_HASH_TYPE_SHA512_256,
    WC_HASH_TYPE_SHAKE128, WC_HASH_TYPE_SHAKE256, WC_HASH_TYPE_SHA3_224,
    WC_HASH_TYPE_SHA3_256, WC_HASH_TYPE_SHA3_384, WC_HASH_TYPE_SHA3_512.
    \param [out] sig Buffer to receive the signature.
    \param [in,out] sigSz On input, size of sig buffer. On output, actual
    signature length.

    _Example_
    \code
    SlhDsaKey key;
    byte sig[WC_SLHDSA_MAX_SIG_LEN];
    word32 sigSz = sizeof(sig);
    byte msg[] = "Hello World!";
    byte digest[WC_SHA256_DIGEST_SIZE];
    int ret;

    wc_Sha256Hash(msg, sizeof(msg), digest);
    ret = wc_SlhDsaKey_SignHashDeterministic(&key, NULL, 0,
        digest, sizeof(digest), WC_HASH_TYPE_SHA256, sig, &sigSz);
    \endcode

    \sa wc_SlhDsaKey_SignHashWithRandom
    \sa wc_SlhDsaKey_SignHash
    \sa wc_SlhDsaKey_VerifyHash
    \sa wc_SlhDsaKey_SignMsgDeterministic
*/
int wc_SlhDsaKey_SignHashDeterministic(SlhDsaKey* key,
    const byte* ctx, byte ctxSz, const byte* hash, word32 hashSz,
    enum wc_HashType hashType, byte* sig, word32* sigSz);

/*!
    \ingroup SLH_DSA

    \brief Signs a caller-pre-hashed message digest using the SLH-DSA external
    (HashSLH-DSA) interface with caller-provided additional randomness. The
    caller must hash the application message with hashType first and pass the
    digest as hash; this function does NOT hash its input.

    \return 0 on success.
    \return BAD_FUNC_ARG if key, hash, sig, sigSz, or addRnd is NULL.
    \return BAD_LENGTH_E if hashSz does not equal the digest size for hashType
    (32 for SHAKE128, 64 for SHAKE256 per FIPS 205 Section 10.2.2).
    \return NOT_COMPILED_IN if hashType is not supported in this build.

    \param [in] key Pointer to a private SlhDsaKey.
    \param [in] ctx Context string. May be NULL if ctxSz is 0.
    \param [in] ctxSz Length of the context string (0-255).
    \param [in] hash Pointer to the pre-hashed message digest. hashSz must
    equal the digest size for hashType.
    \param [in] hashSz Length of the digest in bytes.
    \param [in] hashType Hash algorithm used for pre-hashing (selects OID).
    \param [out] sig Buffer to receive the signature.
    \param [in,out] sigSz On input, size of sig buffer. On output, actual
    signature length.
    \param [in] addRnd Additional randomness (n bytes).

    \sa wc_SlhDsaKey_SignHashDeterministic
    \sa wc_SlhDsaKey_VerifyHash
    \sa wc_SlhDsaKey_SignMsgWithRandom
*/
int wc_SlhDsaKey_SignHashWithRandom(SlhDsaKey* key,
    const byte* ctx, byte ctxSz, const byte* hash, word32 hashSz,
    enum wc_HashType hashType, byte* sig, word32* sigSz, const byte* addRnd);

/*!
    \ingroup SLH_DSA

    \brief Signs a caller-pre-hashed message digest using the SLH-DSA external
    (HashSLH-DSA) interface with RNG-provided randomness. The caller must
    hash the application message with hashType first and pass the digest as
    hash; this function does NOT hash its input.

    \return 0 on success.
    \return BAD_FUNC_ARG if key, hash, sig, sigSz, or rng is NULL.
    \return BAD_LENGTH_E if hashSz does not equal the digest size for hashType
    (32 for SHAKE128, 64 for SHAKE256 per FIPS 205 Section 10.2.2).
    \return NOT_COMPILED_IN if hashType is not supported in this build.

    \param [in] key Pointer to a private SlhDsaKey.
    \param [in] ctx Context string. May be NULL if ctxSz is 0.
    \param [in] ctxSz Length of the context string (0-255).
    \param [in] hash Pointer to the pre-hashed message digest. hashSz must
    equal the digest size for hashType.
    \param [in] hashSz Length of the digest in bytes.
    \param [in] hashType Hash algorithm used for pre-hashing (selects OID).
    \param [out] sig Buffer to receive the signature.
    \param [in,out] sigSz On input, size of sig buffer. On output, actual
    signature length.
    \param [in] rng Pointer to an initialized WC_RNG.

    \sa wc_SlhDsaKey_SignHashDeterministic
    \sa wc_SlhDsaKey_VerifyHash
    \sa wc_SlhDsaKey_SignMsgDeterministic
*/
int wc_SlhDsaKey_SignHash(SlhDsaKey* key, const byte* ctx,
    byte ctxSz, const byte* hash, word32 hashSz, enum wc_HashType hashType,
    byte* sig, word32* sigSz, WC_RNG* rng);

/*!
    \ingroup SLH_DSA

    \brief Verifies an SLH-DSA signature using the external HashSLH-DSA
    interface (FIPS 205 Algorithm 25). The caller must hash the application
    message with hashType first and pass the digest as hash; this function
    does NOT hash its input.

    \return 0 on success (signature valid).
    \return BAD_FUNC_ARG if key, hash, or sig is NULL.
    \return BAD_LENGTH_E if sigSz does not match the parameter set, or if
    hashSz does not equal the digest size for hashType (32 for SHAKE128, 64
    for SHAKE256 per FIPS 205 Section 10.2.2).
    \return NOT_COMPILED_IN if hashType is not supported in this build.
    \return MISSING_KEY if the public key has not been set.
    \return SIG_VERIFY_E if the signature is invalid.

    \param [in] key Pointer to a public SlhDsaKey.
    \param [in] ctx Context string. May be NULL if ctxSz is 0.
    \param [in] ctxSz Length of the context string (0-255).
    \param [in] hash Pointer to the pre-hashed message digest. hashSz must
    equal the digest size for hashType.
    \param [in] hashSz Length of the digest in bytes.
    \param [in] hashType Hash algorithm used for pre-hashing (selects OID).
    Must match the hash used during signing.
    \param [in] sig Pointer to the signature to verify.
    \param [in] sigSz Length of the signature.

    _Example_
    \code
    SlhDsaKey key;
    byte sig[...];
    word32 sigSz;
    byte msg[] = "Hello World!";
    byte digest[WC_SHA256_DIGEST_SIZE];
    int ret;

    wc_Sha256Hash(msg, sizeof(msg), digest);
    ret = wc_SlhDsaKey_VerifyHash(&key, NULL, 0,
        digest, sizeof(digest), WC_HASH_TYPE_SHA256, sig, sigSz);
    if (ret == 0) {
        // signature is valid
    }
    \endcode

    \sa wc_SlhDsaKey_SignHashDeterministic
    \sa wc_SlhDsaKey_Verify
    \sa wc_SlhDsaKey_VerifyMsg
*/
int wc_SlhDsaKey_VerifyHash(SlhDsaKey* key, const byte* ctx,
    byte ctxSz, const byte* hash, word32 hashSz, enum wc_HashType hashType,
    const byte* sig, word32 sigSz);

/*!
    \ingroup SLH_DSA

    \brief Imports an SLH-DSA private key from a raw byte buffer. The buffer
    must contain the full private key (4*n bytes: SK.seed || SK.prf ||
    PK.seed || PK.root). After import, the key can be used for signing.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or in is NULL, or inLen does not match the
    expected private key size for the parameter set.

    \param [in,out] key Pointer to an initialized SlhDsaKey.
    \param [in] in Buffer containing the raw private key bytes.
    \param [in] inLen Length of the input buffer.

    _Example_
    \code
    SlhDsaKey key;
    byte privKey[...]; // 4*n bytes
    int ret;

    wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID);
    ret = wc_SlhDsaKey_ImportPrivate(&key, privKey, sizeof(privKey));
    \endcode

    \sa wc_SlhDsaKey_ExportPrivate
    \sa wc_SlhDsaKey_ImportPublic
*/
int wc_SlhDsaKey_ImportPrivate(SlhDsaKey* key, const byte* in,
    word32 inLen);

/*!
    \ingroup SLH_DSA

    \brief Imports an SLH-DSA public key from a raw byte buffer. The buffer
    must contain PK.seed || PK.root (2*n bytes). After import, the key can
    be used for verification.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or in is NULL, or inLen does not match the
    expected public key size.

    \param [in,out] key Pointer to an initialized SlhDsaKey.
    \param [in] in Buffer containing the raw public key bytes.
    \param [in] inLen Length of the input buffer.

    _Example_
    \code
    SlhDsaKey key;
    byte pubKey[...]; // 2*n bytes
    int ret;

    wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID);
    ret = wc_SlhDsaKey_ImportPublic(&key, pubKey, sizeof(pubKey));
    \endcode

    \sa wc_SlhDsaKey_ExportPublic
    \sa wc_SlhDsaKey_ImportPrivate
*/
int wc_SlhDsaKey_ImportPublic(SlhDsaKey* key, const byte* in,
    word32 inLen);

/*!
    \ingroup SLH_DSA

    \brief Checks the consistency of an SLH-DSA key. For a key with both
    private and public components, verifies that the public key matches the
    private key.

    \return 0 on success (key is valid).
    \return BAD_FUNC_ARG if key is NULL.

    \param [in] key Pointer to the SlhDsaKey to check.

    \sa wc_SlhDsaKey_MakeKey
    \sa wc_SlhDsaKey_ImportPrivate
*/
int wc_SlhDsaKey_CheckKey(SlhDsaKey* key);

/*!
    \ingroup SLH_DSA

    \brief Exports the private key from an SLH-DSA key object into a raw
    byte buffer (4*n bytes).

    \return 0 on success.
    \return BAD_FUNC_ARG if key, out, or outLen is NULL.
    \return BUFFER_E if the output buffer is too small.

    \param [in] key Pointer to the SlhDsaKey containing a private key.
    \param [out] out Buffer to receive the raw private key bytes.
    \param [in,out] outLen On input, size of out buffer. On output, bytes
    written.

    _Example_
    \code
    SlhDsaKey key;
    byte privKey[4 * 32]; // 4*n for 256-bit params
    word32 privKeySz = sizeof(privKey);
    int ret;

    ret = wc_SlhDsaKey_ExportPrivate(&key, privKey, &privKeySz);
    \endcode

    \sa wc_SlhDsaKey_ImportPrivate
    \sa wc_SlhDsaKey_ExportPublic
*/
int wc_SlhDsaKey_ExportPrivate(SlhDsaKey* key, byte* out,
    word32* outLen);

/*!
    \ingroup SLH_DSA

    \brief Exports the public key from an SLH-DSA key object into a raw
    byte buffer (2*n bytes: PK.seed || PK.root).

    \return 0 on success.
    \return BAD_FUNC_ARG if key, out, or outLen is NULL.
    \return BUFFER_E if the output buffer is too small.

    \param [in] key Pointer to the SlhDsaKey containing a public key.
    \param [out] out Buffer to receive the raw public key bytes.
    \param [in,out] outLen On input, size of out buffer. On output, bytes
    written.

    _Example_
    \code
    SlhDsaKey key;
    byte pubKey[2 * 32];
    word32 pubKeySz = sizeof(pubKey);
    int ret;

    ret = wc_SlhDsaKey_ExportPublic(&key, pubKey, &pubKeySz);
    \endcode

    \sa wc_SlhDsaKey_ImportPublic
    \sa wc_SlhDsaKey_ExportPrivate
*/
int wc_SlhDsaKey_ExportPublic(SlhDsaKey* key, byte* out,
    word32* outLen);

/*!
    \ingroup SLH_DSA

    \brief Returns the private key size in bytes for the key's parameter set.

    \return Private key size in bytes (4*n) on success.
    \return BAD_FUNC_ARG if key is NULL or not initialized.

    \param [in] key Pointer to an initialized SlhDsaKey.

    \sa wc_SlhDsaKey_PublicSize
    \sa wc_SlhDsaKey_SigSize
    \sa wc_SlhDsaKey_PrivateSizeFromParam
*/
int wc_SlhDsaKey_PrivateSize(SlhDsaKey* key);

/*!
    \ingroup SLH_DSA

    \brief Returns the public key size in bytes for the key's parameter set.

    \return Public key size in bytes (2*n) on success.
    \return BAD_FUNC_ARG if key is NULL or not initialized.

    \param [in] key Pointer to an initialized SlhDsaKey.

    \sa wc_SlhDsaKey_PrivateSize
    \sa wc_SlhDsaKey_SigSize
    \sa wc_SlhDsaKey_PublicSizeFromParam
*/
int wc_SlhDsaKey_PublicSize(SlhDsaKey* key);

/*!
    \ingroup SLH_DSA

    \brief Returns the signature size in bytes for the key's parameter set.

    \return Signature size in bytes on success.
    \return BAD_FUNC_ARG if key is NULL or not initialized.

    \param [in] key Pointer to an initialized SlhDsaKey.

    \sa wc_SlhDsaKey_PrivateSize
    \sa wc_SlhDsaKey_PublicSize
    \sa wc_SlhDsaKey_SigSizeFromParam
*/
int wc_SlhDsaKey_SigSize(SlhDsaKey* key);

/*!
    \ingroup SLH_DSA

    \brief Returns the private key size in bytes for the given parameter set
    without needing an initialized key object.

    \return Private key size in bytes (4*n) on success.
    \return BAD_FUNC_ARG if param is invalid.

    \param [in] param The SLH-DSA parameter set.

    \sa wc_SlhDsaKey_PrivateSize
*/
int wc_SlhDsaKey_PrivateSizeFromParam(enum SlhDsaParam param);

/*!
    \ingroup SLH_DSA

    \brief Returns the public key size in bytes for the given parameter set
    without needing an initialized key object.

    \return Public key size in bytes (2*n) on success.
    \return BAD_FUNC_ARG if param is invalid.

    \param [in] param The SLH-DSA parameter set.

    \sa wc_SlhDsaKey_PublicSize
*/
int wc_SlhDsaKey_PublicSizeFromParam(enum SlhDsaParam param);

/*!
    \ingroup SLH_DSA

    \brief Returns the signature size in bytes for the given parameter set
    without needing an initialized key object.

    \return Signature size in bytes on success.
    \return BAD_FUNC_ARG if param is invalid.

    \param [in] param The SLH-DSA parameter set.

    \sa wc_SlhDsaKey_SigSize
*/
int wc_SlhDsaKey_SigSizeFromParam(enum SlhDsaParam param);

/*!
    \ingroup SLH_DSA

    \brief Decodes a DER-encoded SLH-DSA private key in the PKCS#8
    OneAsymmetricKey format defined by RFC 9909. The privateKey OCTET STRING
    contains the raw concatenation SK.seed || SK.prf || PK.seed || PK.root
    (4*n bytes) directly, without a nested OCTET STRING wrapper as used by
    Ed25519/Ed448. The SLH-DSA parameter set is detected from the
    AlgorithmIdentifier OID and key->params is updated to match. Available
    only when WOLFSSL_SLHDSA_VERIFY_ONLY is not defined.

    On a failure that is detected before any write to key->sk
    (BAD_FUNC_ARG, header/OID parse errors, or wrong privateKey length), the
    key state is left untouched. On a failure detected after
    wc_SlhDsaKey_ImportPrivate has populated key->sk (a SHA-2 precompute
    error, or a trailing-field validation error), key->sk is scrubbed with
    ForceZero and the WC_SLHDSA_FLAG_PRIVATE/PUBLIC flags are cleared so
    flags can never claim valid bytes that were zeroed. In both rollback
    cases, key->params and inOutIdx are restored to their pre-call values.

    \return 0 on success.
    \return BAD_FUNC_ARG if input, inOutIdx, or key is NULL, or inSz is 0.
    \return ASN_PARSE_E if the DER cannot be parsed as an SLH-DSA private
    key (malformed input, wrong key size, or trailing-field violation).
    \return NOT_COMPILED_IN if the OID names an SLH-DSA variant that is not
    built into this library.

    \param [in] input DER-encoded key data.
    \param [in,out] inOutIdx On input, starting offset into input. On output,
    advanced past the parsed key (unchanged on failure).
    \param [in,out] key SLH-DSA key. Parameter set is auto-detected from the
    encoded OID.
    \param [in] inSz Total size of input in bytes.

    \sa wc_SlhDsaKey_KeyToDer
    \sa wc_SlhDsaKey_PublicKeyDecode
    \sa wc_SlhDsaKey_ImportPrivate
*/
int wc_SlhDsaKey_PrivateKeyDecode(const byte* input, word32* inOutIdx,
    SlhDsaKey* key, word32 inSz);

/*!
    \ingroup SLH_DSA

    \brief Decodes a DER-encoded SLH-DSA public key in the
    SubjectPublicKeyInfo (SPKI) format. The SLH-DSA parameter set is
    detected from the AlgorithmIdentifier OID and key->params is updated
    accordingly.

    As a fast path, if key->params is already set the function first hands
    the entire window from inOutIdx to inSz to wc_SlhDsaKey_ImportPublic.
    ImportPublic's length check is the disambiguator: a window of exactly
    2*n bytes is accepted as a raw public key (PK.seed || PK.root) and
    consumed in full; any other length is rejected and the function falls
    through to SPKI parsing. SPKI input always carries enough
    AlgorithmIdentifier/BIT STRING overhead that it never collides with the
    2*n raw length, so it falls through cleanly. The caller does not need
    to pre-trim the window to 2*n.

    On a failure detected before any write (BAD_FUNC_ARG or a malformed
    SPKI), the key state is left untouched. On a failure detected after
    ImportPublic has populated the public half of key->sk (a SHA-2
    precompute error), the public half sk[2*n .. 4*n] is scrubbed and
    WC_SLHDSA_FLAG_PUBLIC is cleared from the flags; the private half is
    left intact in case the caller imported it earlier. key->params and
    inOutIdx are restored to their pre-call values.

    \return 0 on success.
    \return BAD_FUNC_ARG if input, inOutIdx, or key is NULL, or inSz is 0.
    \return ASN_PARSE_E if the DER cannot be parsed as an SLH-DSA public
    key.
    \return NOT_COMPILED_IN if the OID names an SLH-DSA variant that is not
    built into this library.

    \param [in] input DER-encoded key data, or a raw 2*n public key when
    key->params is already set.
    \param [in,out] inOutIdx On input, starting offset into input. On output,
    advanced past the parsed key (unchanged on failure).
    \param [in,out] key SLH-DSA key. Parameter set is auto-detected from the
    encoded OID, or honored as-is in the raw fast path.
    \param [in] inSz Total size of input in bytes.

    \sa wc_SlhDsaKey_PublicKeyToDer
    \sa wc_SlhDsaKey_PrivateKeyDecode
    \sa wc_SlhDsaKey_ImportPublic
*/
int wc_SlhDsaKey_PublicKeyDecode(const byte* input, word32* inOutIdx,
    SlhDsaKey* key, word32 inSz);

/*!
    \ingroup SLH_DSA

    \brief Encodes an SLH-DSA private key to DER in the PKCS#8
    OneAsymmetricKey format defined by RFC 9909. The privateKey OCTET STRING
    contains the raw 4*n bytes (SK.seed || SK.prf || PK.seed || PK.root)
    directly, without the nested OCTET STRING wrapping used by Ed25519/Ed448.

    Available only when WOLFSSL_SLHDSA_VERIFY_ONLY is not defined and
    WC_ENABLE_ASYM_KEY_EXPORT is set.

    \return Size of the encoded DER in bytes on success. Pass NULL as output
    to query the required buffer size without writing.
    \return BAD_FUNC_ARG if key or key->params is NULL.
    \return MISSING_KEY if the private key has not been set.
    \return BUFFER_E if output is non-NULL and inLen is smaller than the
    required size.
    \return NOT_COMPILED_IN if key->params names an SLH-DSA variant whose
    parameter set is not built in.

    \param [in] key SLH-DSA key with a populated private key.
    \param [out] output Buffer to receive the DER encoding, or NULL to query
    the required size.
    \param [in] inLen Size of output in bytes (ignored when output is NULL).

    \sa wc_SlhDsaKey_PrivateKeyDecode
    \sa wc_SlhDsaKey_PrivateKeyToDer
    \sa wc_SlhDsaKey_PublicKeyToDer
*/
int wc_SlhDsaKey_KeyToDer(SlhDsaKey* key, byte* output, word32 inLen);

/*!
    \ingroup SLH_DSA

    \brief Encodes an SLH-DSA private key to DER. RFC 9909 packs
    SK.seed || SK.prf || PK.seed || PK.root into a single OCTET STRING, so
    SLH-DSA has no distinct private-only encoding. This function is an
    intentional alias of wc_SlhDsaKey_KeyToDer, kept for API parity with
    Ed25519/Ed448 which do have a separate private form.

    Available only when WOLFSSL_SLHDSA_VERIFY_ONLY is not defined and
    WC_ENABLE_ASYM_KEY_EXPORT is set.

    Return codes are inherited unchanged from wc_SlhDsaKey_KeyToDer.

    \return Size of the encoded DER in bytes on success. Pass NULL as output
    to query the required buffer size.
    \return BAD_FUNC_ARG if key or key->params is NULL.
    \return MISSING_KEY if the private key has not been set.
    \return BUFFER_E if output is non-NULL and inLen is smaller than the
    required size.
    \return NOT_COMPILED_IN if key->params names an SLH-DSA variant whose
    parameter set is not built in.

    \param [in] key SLH-DSA key with a populated private key.
    \param [out] output Buffer to receive the DER encoding, or NULL to query
    the required size.
    \param [in] inLen Size of output in bytes (ignored when output is NULL).

    \sa wc_SlhDsaKey_KeyToDer
    \sa wc_SlhDsaKey_PrivateKeyDecode
*/
int wc_SlhDsaKey_PrivateKeyToDer(SlhDsaKey* key, byte* output, word32 inLen);

/*!
    \ingroup SLH_DSA

    \brief Encodes an SLH-DSA public key to DER. When withAlg is non-zero
    the output is a full SubjectPublicKeyInfo structure (AlgorithmIdentifier
    plus BIT STRING). When withAlg is zero the output contains the raw
    public key bytes without the SPKI wrapping.

    Available only when WC_ENABLE_ASYM_KEY_EXPORT is set.

    \return Size of the encoded DER in bytes on success. Pass NULL as output
    to query the required buffer size.
    \return BAD_FUNC_ARG if key or key->params is NULL.
    \return BUFFER_E if output is non-NULL and inLen is smaller than the
    required size.
    \return NOT_COMPILED_IN if key->params names an SLH-DSA variant whose
    parameter set is not built in.

    \param [in] key SLH-DSA key with a populated public key.
    \param [out] output Buffer to receive the DER encoding, or NULL to query
    the required size.
    \param [in] inLen Size of output in bytes (ignored when output is NULL).
    \param [in] withAlg Non-zero to emit SubjectPublicKeyInfo (with
    AlgorithmIdentifier); zero to emit the raw public key only.

    \sa wc_SlhDsaKey_PublicKeyDecode
    \sa wc_SlhDsaKey_KeyToDer
*/
int wc_SlhDsaKey_PublicKeyToDer(SlhDsaKey* key, byte* output, word32 inLen,
    int withAlg);
