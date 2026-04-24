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
    (pure) interface. This is FIPS 205 Algorithm 23. The message is wrapped
    internally as M' = 0x00 || len(ctx) || ctx || M before verification.

    \return 0 on success (signature valid).
    \return BAD_FUNC_ARG if key, msg, or sig is NULL.
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
    the caller — no 0x00||len(ctx)||ctx||M wrapping is performed. This
    corresponds to FIPS 205 Algorithm 19 (slh_sign_internal) with opt_rand
    set to PK.seed.

    Use this when the CAVP test framework or protocol layer has already
    constructed M'.

    \return 0 on success.
    \return BAD_FUNC_ARG if key, mprime, sig, or sigSz is NULL.

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
*/
int wc_SlhDsaKey_SignMsgDeterministic(SlhDsaKey* key,
    const byte* mprime, word32 mprimeSz, byte* sig, word32* sigSz);

/*!
    \ingroup SLH_DSA

    \brief Signs using the SLH-DSA internal interface with caller-provided
    additional randomness. M' is provided directly — no wrapping is performed.
    This corresponds to FIPS 205 Algorithm 19 (slh_sign_internal) with an
    explicit opt_rand value.

    \return 0 on success.
    \return BAD_FUNC_ARG if key, mprime, sig, sigSz, or addRnd is NULL.

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
*/
int wc_SlhDsaKey_VerifyMsg(SlhDsaKey* key, const byte* mprime,
    word32 mprimeSz, const byte* sig, word32 sigSz);

/*!
    \ingroup SLH_DSA

    \brief Signs a pre-hashed message using the SLH-DSA external (HashSLH-DSA)
    interface with deterministic randomness. The message is hashed with the
    specified hash algorithm, then signed per FIPS 205 Algorithm 22 with the
    pre-hash domain separator (0x01).

    \return 0 on success.
    \return BAD_FUNC_ARG if key, msg, sig, or sigSz is NULL, or hashType
    is unsupported.

    \param [in] key Pointer to a private SlhDsaKey.
    \param [in] ctx Context string. May be NULL if ctxSz is 0.
    \param [in] ctxSz Length of the context string (0-255).
    \param [in] msg Pointer to the message to hash and sign.
    \param [in] msgSz Length of the message.
    \param [in] hashType Hash algorithm to use for pre-hashing. Supported:
    WC_HASH_TYPE_SHA256, WC_HASH_TYPE_SHA384, WC_HASH_TYPE_SHA512,
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
    int ret;

    ret = wc_SlhDsaKey_SignHashDeterministic(&key, NULL, 0,
        msg, sizeof(msg), WC_HASH_TYPE_SHA256, sig, &sigSz);
    \endcode

    \sa wc_SlhDsaKey_SignHashWithRandom
    \sa wc_SlhDsaKey_SignHash
    \sa wc_SlhDsaKey_VerifyHash
*/
int wc_SlhDsaKey_SignHashDeterministic(SlhDsaKey* key,
    const byte* ctx, byte ctxSz, const byte* msg, word32 msgSz,
    enum wc_HashType hashType, byte* sig, word32* sigSz);

/*!
    \ingroup SLH_DSA

    \brief Signs a pre-hashed message using the SLH-DSA external (HashSLH-DSA)
    interface with caller-provided additional randomness.

    \return 0 on success.
    \return BAD_FUNC_ARG if key, msg, sig, sigSz, or addRnd is NULL.

    \param [in] key Pointer to a private SlhDsaKey.
    \param [in] ctx Context string. May be NULL if ctxSz is 0.
    \param [in] ctxSz Length of the context string (0-255).
    \param [in] msg Pointer to the message to hash and sign.
    \param [in] msgSz Length of the message.
    \param [in] hashType Hash algorithm to use for pre-hashing.
    \param [out] sig Buffer to receive the signature.
    \param [in,out] sigSz On input, size of sig buffer. On output, actual
    signature length.
    \param [in] addRnd Additional randomness (n bytes).

    \sa wc_SlhDsaKey_SignHashDeterministic
    \sa wc_SlhDsaKey_VerifyHash
*/
int wc_SlhDsaKey_SignHashWithRandom(SlhDsaKey* key,
    const byte* ctx, byte ctxSz, const byte* msg, word32 msgSz,
    enum wc_HashType hashType, byte* sig, word32* sigSz, byte* addRnd);

/*!
    \ingroup SLH_DSA

    \brief Signs a pre-hashed message using the SLH-DSA external (HashSLH-DSA)
    interface with RNG-provided randomness.

    \return 0 on success.
    \return BAD_FUNC_ARG if key, msg, sig, sigSz, or rng is NULL.

    \param [in] key Pointer to a private SlhDsaKey.
    \param [in] ctx Context string. May be NULL if ctxSz is 0.
    \param [in] ctxSz Length of the context string (0-255).
    \param [in] msg Pointer to the message to hash and sign.
    \param [in] msgSz Length of the message.
    \param [in] hashType Hash algorithm to use for pre-hashing.
    \param [out] sig Buffer to receive the signature.
    \param [in,out] sigSz On input, size of sig buffer. On output, actual
    signature length.
    \param [in] rng Pointer to an initialized WC_RNG.

    \sa wc_SlhDsaKey_SignHashDeterministic
    \sa wc_SlhDsaKey_VerifyHash
*/
int wc_SlhDsaKey_SignHash(SlhDsaKey* key, const byte* ctx,
    byte ctxSz, const byte* msg, word32 msgSz, enum wc_HashType hashType,
    byte* sig, word32* sigSz, WC_RNG* rng);

/*!
    \ingroup SLH_DSA

    \brief Verifies an SLH-DSA signature over a pre-hashed message
    (HashSLH-DSA). The message is hashed with the specified hash algorithm
    before verification.

    \return 0 on success (signature valid).
    \return BAD_FUNC_ARG if key, msg, or sig is NULL.
    \return SIG_VERIFY_E if the signature is invalid.

    \param [in] key Pointer to a public SlhDsaKey.
    \param [in] ctx Context string. May be NULL if ctxSz is 0.
    \param [in] ctxSz Length of the context string (0-255).
    \param [in] msg Pointer to the message to hash and verify.
    \param [in] msgSz Length of the message.
    \param [in] hashType Hash algorithm used for pre-hashing. Must match the
    hash used during signing.
    \param [in] sig Pointer to the signature to verify.
    \param [in] sigSz Length of the signature.

    _Example_
    \code
    SlhDsaKey key;
    byte sig[...];
    word32 sigSz;
    byte msg[] = "Hello World!";
    int ret;

    ret = wc_SlhDsaKey_VerifyHash(&key, NULL, 0,
        msg, sizeof(msg), WC_HASH_TYPE_SHA256, sig, sigSz);
    if (ret == 0) {
        // signature is valid
    }
    \endcode

    \sa wc_SlhDsaKey_SignHashDeterministic
    \sa wc_SlhDsaKey_Verify
*/
int wc_SlhDsaKey_VerifyHash(SlhDsaKey* key, const byte* ctx,
    byte ctxSz, const byte* msg, word32 msgSz, enum wc_HashType hashType,
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
