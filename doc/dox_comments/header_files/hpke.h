/*!
    \ingroup HPKE

    \brief This function initializes an Hpke structure with a single
    KEM / KDF / AEAD ciphersuite triple and computes the RFC 9180 KEM and
    HPKE suite id strings used by the labeled KDF calls. It must be called
    before any other HPKE operation on that structure.

    \return 0 Returned on success.
    \return BAD_FUNC_ARG Returned when hpke is NULL, when kem, kdf or aead is 0,
    or when the requested KEM, KDF or AEAD is not one of the supported values
    (or its support was not compiled in).

    \param hpke pointer to the Hpke structure to initialize.
    \param kem KEM identifier: DHKEM_P256_HKDF_SHA256, DHKEM_P384_HKDF_SHA384,
    DHKEM_P521_HKDF_SHA512 or DHKEM_X25519_HKDF_SHA256.
    \param kdf KDF identifier: HKDF_SHA256, HKDF_SHA384 or HKDF_SHA512.
    \param aead AEAD identifier: HPKE_AES_128_GCM or HPKE_AES_256_GCM.
    \param heap pointer to a heap hint for dynamic allocations, may be NULL.

    _Example_
    \code
    Hpke hpke;
    int ret;

    ret = wc_HpkeInit(&hpke, DHKEM_X25519_HKDF_SHA256, HKDF_SHA256,
        HPKE_AES_128_GCM, NULL);
    if (ret != 0) {
        WOLFSSL_MSG("wc_HpkeInit failed");
    }
    \endcode

    \sa wc_HpkeGenerateKeyPair
    \sa wc_HpkeSealBase
    \sa wc_HpkeOpenBase
*/
int wc_HpkeInit(Hpke* hpke, int kem, int kdf, int aead, void* heap);

/*!
    \ingroup HPKE

    \brief This function generates a KEM key pair matching the KEM configured
    in the Hpke structure. The key is allocated on the heap and returned
    through keypair as a void pointer to the underlying wolfCrypt key type
    (ecc_key for the P-256/P-384/P-521 KEMs, curve25519_key for the X25519
    KEM). The caller owns the key and must release it with wc_HpkeFreeKey().

    \return 0 Returned on success.
    \return BAD_FUNC_ARG Returned when hpke, keypair or rng is NULL, or when
    the configured KEM is not supported.
    \return MEMORY_E Returned when allocation of the key structure fails.
    \return Any negative error code propagated from the underlying key
    generation routine.

    \param hpke pointer to an initialized Hpke structure.
    \param keypair address of a void pointer that receives the newly
    allocated key on success.
    \param rng pointer to an initialized WC_RNG used for key generation.

    _Example_
    \code
    Hpke hpke;
    WC_RNG rng;
    void* receiverKey = NULL;
    int ret;

    wc_InitRng(&rng);
    wc_HpkeInit(&hpke, DHKEM_X25519_HKDF_SHA256, HKDF_SHA256,
        HPKE_AES_128_GCM, NULL);

    ret = wc_HpkeGenerateKeyPair(&hpke, &receiverKey, &rng);
    if (ret != 0) {
        WOLFSSL_MSG("wc_HpkeGenerateKeyPair failed");
    }
    ...
    wc_HpkeFreeKey(&hpke, hpke.kem, receiverKey, hpke.heap);
    \endcode

    \sa wc_HpkeInit
    \sa wc_HpkeFreeKey
    \sa wc_HpkeSerializePublicKey
*/
int wc_HpkeGenerateKeyPair(Hpke* hpke, void** keypair, WC_RNG* rng);

/*!
    \ingroup HPKE

    \brief This function serializes the public part of a KEM key into the
    fixed-length wire format defined by RFC 9180 for the configured KEM
    (an uncompressed X9.63 point for the ECC KEMs, the raw 32-byte value for
    X25519). It is used to obtain the encapsulated key (the ephemeral public
    key) that the sender transmits to the receiver.

    \return 0 Returned on success.
    \return BAD_FUNC_ARG Returned when hpke, key, out or outSz is NULL, or
    when the configured KEM is not supported.
    \return BUFFER_E Returned when the buffer described by *outSz is too small
    for the serialized key.

    \param hpke pointer to an initialized Hpke structure.
    \param key void pointer to the KEM key whose public part is serialized.
    \param out buffer that receives the serialized public key. It must be at
    least DHKEM_P256_ENC_LEN / DHKEM_P384_ENC_LEN / DHKEM_P521_ENC_LEN
    (ECC KEMs) or DHKEM_X25519_ENC_LEN bytes; HPKE_Npk_MAX is safe for any
    supported KEM.
    \param outSz on input the capacity of out, on output the number of bytes
    written.

    _Example_
    \code
    Hpke hpke;
    WC_RNG rng;
    void* ephemeralKey = NULL;
    byte pubKey[HPKE_Npk_MAX];
    word16 pubKeySz = (word16)sizeof(pubKey);
    int ret;

    wc_InitRng(&rng);
    wc_HpkeInit(&hpke, DHKEM_X25519_HKDF_SHA256, HKDF_SHA256,
        HPKE_AES_128_GCM, NULL);
    wc_HpkeGenerateKeyPair(&hpke, &ephemeralKey, &rng);

    ret = wc_HpkeSerializePublicKey(&hpke, ephemeralKey, pubKey, &pubKeySz);
    if (ret != 0) {
        WOLFSSL_MSG("wc_HpkeSerializePublicKey failed");
    }
    ...
    wc_HpkeFreeKey(&hpke, hpke.kem, ephemeralKey, hpke.heap);
    \endcode

    \sa wc_HpkeDeserializePublicKey
    \sa wc_HpkeGenerateKeyPair
    \sa wc_HpkeSealBase
*/
int wc_HpkeSerializePublicKey(Hpke* hpke, void* key, byte* out, word16* outSz);

/*!
    \ingroup HPKE

    \brief This function parses a serialized KEM public key (as produced by
    wc_HpkeSerializePublicKey()) into a newly allocated wolfCrypt key
    structure matching the configured KEM. The key is returned through key
    and must be released with wc_HpkeFreeKey(). On failure any partially
    allocated key is freed and *key is set to NULL.

    \return 0 Returned on success.
    \return BAD_FUNC_ARG Returned when hpke, key or in is NULL, or when the
    configured KEM is not supported.
    \return BUFFER_E Returned when inSz is smaller than hpke->Npk.
    \return MEMORY_E Returned when allocation of the key structure fails.
    \return Any negative error code propagated from the underlying key import
    routine.

    \param hpke pointer to an initialized Hpke structure.
    \param key address of a void pointer that receives the newly allocated
    key on success.
    \param in buffer holding the serialized public key.
    \param inSz length of in in bytes; must be at least hpke->Npk.

    _Example_
    \code
    Hpke hpke;
    void* peerKey = NULL;
    int ret;

    ret = wc_HpkeDeserializePublicKey(&hpke, &peerKey, pubKey, pubKeySz);
    if (ret != 0) {
        WOLFSSL_MSG("wc_HpkeDeserializePublicKey failed");
    }
    ...
    wc_HpkeFreeKey(&hpke, hpke.kem, peerKey, hpke.heap);
    \endcode

    \sa wc_HpkeSerializePublicKey
    \sa wc_HpkeFreeKey
    \sa wc_HpkeOpenBase
*/
int wc_HpkeDeserializePublicKey(Hpke* hpke, void** key, const byte* in,
    word16 inSz);

/*!
    \ingroup HPKE

    \brief This function frees a KEM key previously returned by
    wc_HpkeGenerateKeyPair() or wc_HpkeDeserializePublicKey(). The kem
    argument selects how the key is torn down and must match the KEM the key
    was created for (typically hpke->kem). Passing a NULL keypair is a no-op.

    \return none No return value.

    \param hpke pointer to the Hpke structure (unused, accepted for symmetry).
    \param kem KEM identifier the key was created for, e.g. hpke->kem.
    \param keypair void pointer to the key to free.
    \param heap heap hint that was used when the key was allocated.

    _Example_
    \code
    wc_HpkeFreeKey(&hpke, hpke.kem, receiverKey, hpke.heap);
    \endcode

    \sa wc_HpkeGenerateKeyPair
    \sa wc_HpkeDeserializePublicKey
*/
void wc_HpkeFreeKey(Hpke* hpke, word16 kem, void* keypair, void* heap);

/*!
    \ingroup HPKE

    \brief This function runs the RFC 9180 base-mode sender setup: it
    encapsulates a shared secret to the receiver public key using the
    ephemeral key and runs the key schedule, leaving the HpkeBaseContext
    ready for one or more wc_HpkeContextSealBase() calls. The context is
    zeroed before use. The encapsulated key is not produced here; the caller
    serializes the ephemeral public key separately with
    wc_HpkeSerializePublicKey() and sends it to the receiver.

    \return 0 Returned on success.
    \return BAD_FUNC_ARG Returned when hpke, context, ephemeralKey or
    receiverKey is NULL, or when info is NULL while infoSz is non-zero.
    \return MEMORY_E Returned on allocation failure during setup.
    \return Any negative error code propagated from encapsulation or the key
    schedule.

    \param hpke pointer to an initialized Hpke structure.
    \param context pointer to an HpkeBaseContext to populate.
    \param ephemeralKey void pointer to the sender ephemeral KEM key pair.
    \param receiverKey void pointer to the receiver KEM public key.
    \param info buffer with the application-supplied info string, may be NULL
    when infoSz is 0.
    \param infoSz length of info in bytes.

    _Example_
    \code
    Hpke hpke;
    HpkeBaseContext ctx;
    int ret;

    ret = wc_HpkeInitSealContext(&hpke, &ctx, ephemeralKey, receiverKey,
        info, infoSz);
    if (ret != 0) {
        WOLFSSL_MSG("wc_HpkeInitSealContext failed");
    }
    \endcode

    \sa wc_HpkeContextSealBase
    \sa wc_HpkeInitOpenContext
    \sa wc_HpkeSerializePublicKey
*/
int wc_HpkeInitSealContext(Hpke* hpke, HpkeBaseContext* context,
    void* ephemeralKey, void* receiverKey, byte* info, word32 infoSz);

/*!
    \ingroup HPKE

    \brief This function encrypts (seals) one message with an HpkeBaseContext
    previously set up by wc_HpkeInitSealContext(). It may be called multiple
    times on the same context; each call derives a fresh nonce from the
    context sequence number and then increments it. The output holds ptSz
    bytes of ciphertext immediately followed by an hpke->Nt byte AEAD tag, so
    out must have room for at least ptSz + hpke->Nt bytes. hpke->Nt is
    HPKE_Nt_MAX (16) for the supported AES-GCM AEADs. This function takes no
    output length and does not bounds check out; sizing it to only ptSz
    overruns it by hpke->Nt bytes.

    \return 0 Returned on success.
    \return BAD_FUNC_ARG Returned when hpke, context or plaintext is NULL, or
    when aad is NULL while aadSz is non-zero, or when out is NULL.
    \return SEQ_OVERFLOW_E Returned when the context sequence number has
    reached its maximum, as required by RFC 9180.
    \return MEMORY_E Returned on allocation failure.
    \return Any negative error code propagated from AES-GCM.

    \param hpke pointer to an initialized Hpke structure.
    \param context pointer to an HpkeBaseContext set up for sealing.
    \param aad buffer with additional authenticated data, may be NULL when
    aadSz is 0.
    \param aadSz length of aad in bytes.
    \param plaintext buffer with the message to encrypt.
    \param ptSz length of plaintext in bytes.
    \param out buffer that receives the ciphertext followed by the AEAD tag;
    must be at least ptSz + hpke->Nt bytes.

    _Example_
    \code
    Hpke hpke;
    HpkeBaseContext ctx;
    byte out[64 + HPKE_Nt_MAX];
    int ret;

    ret = wc_HpkeInitSealContext(&hpke, &ctx, ephemeralKey, receiverKey,
        info, infoSz);
    if (ret == 0) {
        ret = wc_HpkeContextSealBase(&hpke, &ctx, aad, aadSz, msg, msgSz,
            out);
    }
    if (ret != 0) {
        WOLFSSL_MSG("wc_HpkeContextSealBase failed");
    }
    \endcode

    \sa wc_HpkeInitSealContext
    \sa wc_HpkeSealBase
    \sa wc_HpkeContextOpenBase
*/
int wc_HpkeContextSealBase(Hpke* hpke, HpkeBaseContext* context,
    byte* aad, word32 aadSz, byte* plaintext, word32 ptSz, byte* out);

/*!
    \ingroup HPKE

    \brief This function performs a one-shot RFC 9180 base-mode seal: it sets
    up a sender context from the ephemeral and receiver keys and encrypts a
    single message with it. It is equivalent to wc_HpkeInitSealContext()
    followed by one wc_HpkeContextSealBase() call. As with the streaming API,
    ciphertext holds ptSz bytes of ciphertext followed by an hpke->Nt byte
    AEAD tag and must be at least ptSz + hpke->Nt bytes; no output length is
    taken and the buffer is not bounds checked. The encapsulated key is
    obtained separately with wc_HpkeSerializePublicKey() on ephemeralKey.

    \return 0 Returned on success.
    \return BAD_FUNC_ARG Returned when hpke, ephemeralKey, receiverKey,
    plaintext or ciphertext is NULL, or when info/aad is NULL while its
    length is non-zero.
    \return MEMORY_E Returned on allocation failure.
    \return SEQ_OVERFLOW_E Returned on sequence-number overflow.
    \return Any negative error code propagated from encapsulation, the key
    schedule or AES-GCM.

    \param hpke pointer to an initialized Hpke structure.
    \param ephemeralKey void pointer to the sender ephemeral KEM key pair.
    \param receiverKey void pointer to the receiver KEM public key.
    \param info buffer with the info string, may be NULL when infoSz is 0.
    \param infoSz length of info in bytes.
    \param aad buffer with additional authenticated data, may be NULL when
    aadSz is 0.
    \param aadSz length of aad in bytes.
    \param plaintext buffer with the message to encrypt.
    \param ptSz length of plaintext in bytes.
    \param ciphertext buffer that receives the ciphertext followed by the
    AEAD tag; must be at least ptSz + hpke->Nt bytes.

    _Example_
    \code
    Hpke hpke;
    byte ciphertext[64 + HPKE_Nt_MAX];
    byte pubKey[HPKE_Npk_MAX];
    word16 pubKeySz = (word16)sizeof(pubKey);
    int ret;

    ret = wc_HpkeSealBase(&hpke, ephemeralKey, receiverKey, info, infoSz,
        aad, aadSz, msg, msgSz, ciphertext);
    if (ret == 0)
        ret = wc_HpkeSerializePublicKey(&hpke, ephemeralKey, pubKey,
            &pubKeySz);
    if (ret != 0) {
        WOLFSSL_MSG("wc_HpkeSealBase failed");
    }
    \endcode

    \sa wc_HpkeContextSealBase
    \sa wc_HpkeOpenBase
    \sa wc_HpkeSerializePublicKey
*/
int wc_HpkeSealBase(Hpke* hpke, void* ephemeralKey, void* receiverKey,
    byte* info, word32 infoSz, byte* aad, word32 aadSz, byte* plaintext,
    word32 ptSz, byte* ciphertext);

/*!
    \ingroup HPKE

    \brief This function runs the RFC 9180 base-mode receiver setup: it
    decapsulates the shared secret from the sender encapsulated key (pubKey)
    using the receiver private key and runs the key schedule, leaving the
    HpkeBaseContext ready for one or more wc_HpkeContextOpenBase() calls. The
    info string must match the one the sender used.

    \return 0 Returned on success.
    \return BAD_FUNC_ARG Returned when hpke, context, receiverKey or pubKey is
    NULL, or when info is NULL while infoSz is non-zero.
    \return MEMORY_E Returned on allocation failure during setup.
    \return Any negative error code propagated from decapsulation or the key
    schedule.

    \param hpke pointer to an initialized Hpke structure.
    \param context pointer to an HpkeBaseContext to populate.
    \param receiverKey void pointer to the receiver KEM key pair (with
    private key).
    \param pubKey buffer holding the sender serialized ephemeral public key.
    \param pubKeySz length of pubKey in bytes.
    \param info buffer with the info string, may be NULL when infoSz is 0.
    \param infoSz length of info in bytes.

    _Example_
    \code
    Hpke hpke;
    HpkeBaseContext ctx;
    int ret;

    ret = wc_HpkeInitOpenContext(&hpke, &ctx, receiverKey, pubKey, pubKeySz,
        info, infoSz);
    if (ret != 0) {
        WOLFSSL_MSG("wc_HpkeInitOpenContext failed");
    }
    \endcode

    \sa wc_HpkeContextOpenBase
    \sa wc_HpkeInitSealContext
    \sa wc_HpkeDeserializePublicKey
*/
int wc_HpkeInitOpenContext(Hpke* hpke, HpkeBaseContext* context,
    void* receiverKey, const byte* pubKey, word16 pubKeySz, byte* info,
    word32 infoSz);

/*!
    \ingroup HPKE

    \brief This function decrypts (opens) one message with an HpkeBaseContext
    previously set up by wc_HpkeInitOpenContext(). It may be called multiple
    times on the same context; each call derives a fresh nonce from the
    context sequence number and then increments it, so calls must be made in
    the same order the sender sealed the messages. ctSz is the length of the
    ciphertext body without the tag (it equals the plaintext length and the
    ptSz the sender passed): the hpke->Nt byte AEAD tag is read from
    ciphertext + ctSz, so the ciphertext buffer must hold ctSz + hpke->Nt
    bytes, and out must hold at least ctSz bytes.

    \return 0 Returned on success.
    \return BAD_FUNC_ARG Returned when hpke, context or ciphertext is NULL, or
    when aad is NULL while aadSz is non-zero, or when out is NULL.
    \return SEQ_OVERFLOW_E Returned when the context sequence number has
    reached its maximum, as required by RFC 9180.
    \return MEMORY_E Returned on allocation failure.
    \return AES_GCM_AUTH_E Returned when tag verification fails (wrong key,
    wrong info, wrong aad, out-of-order call or tampered ciphertext).

    \param hpke pointer to an initialized Hpke structure.
    \param context pointer to an HpkeBaseContext set up for opening.
    \param aad buffer with additional authenticated data, may be NULL when
    aadSz is 0.
    \param aadSz length of aad in bytes.
    \param ciphertext buffer holding the ciphertext body followed by the AEAD
    tag; must be at least ctSz + hpke->Nt bytes.
    \param ctSz length of the ciphertext body in bytes, excluding the tag.
    \param out buffer that receives the recovered plaintext; must be at least
    ctSz bytes.

    _Example_
    \code
    Hpke hpke;
    HpkeBaseContext ctx;
    byte out[64];
    int ret;

    ret = wc_HpkeInitOpenContext(&hpke, &ctx, receiverKey, pubKey, pubKeySz,
        info, infoSz);
    if (ret == 0) {
        ret = wc_HpkeContextOpenBase(&hpke, &ctx, aad, aadSz, ciphertext,
            ctSz, out);
    }
    if (ret != 0) {
        WOLFSSL_MSG("wc_HpkeContextOpenBase failed");
    }
    \endcode

    \sa wc_HpkeInitOpenContext
    \sa wc_HpkeOpenBase
    \sa wc_HpkeContextSealBase
*/
int wc_HpkeContextOpenBase(Hpke* hpke, HpkeBaseContext* context, byte* aad,
    word32 aadSz, byte* ciphertext, word32 ctSz, byte* out);

/*!
    \ingroup HPKE

    \brief This function performs a one-shot RFC 9180 base-mode open: it sets
    up a receiver context from the receiver key and the sender encapsulated
    key and decrypts a single message with it. It is equivalent to
    wc_HpkeInitOpenContext() followed by one wc_HpkeContextOpenBase() call.
    ctSz is the ciphertext body length without the tag (equal to the sender
    ptSz): ciphertext must hold ctSz + hpke->Nt bytes and plaintext must hold
    at least ctSz bytes.

    \return 0 Returned on success.
    \return BAD_FUNC_ARG Returned when hpke, receiverKey, pubKey, plaintext or
    ciphertext is NULL, when pubKeySz is 0, or when info/aad is NULL while its
    length is non-zero.
    \return MEMORY_E Returned on allocation failure.
    \return SEQ_OVERFLOW_E Returned on sequence-number overflow.
    \return AES_GCM_AUTH_E Returned when tag verification fails (wrong
    receiver key, wrong info, wrong aad or tampered ciphertext).
    \return Any negative error code propagated from decapsulation or the key
    schedule.

    \param hpke pointer to an initialized Hpke structure.
    \param receiverKey void pointer to the receiver KEM key pair (with
    private key).
    \param pubKey buffer holding the sender serialized ephemeral public key.
    \param pubKeySz length of pubKey in bytes; must be non-zero.
    \param info buffer with the info string, may be NULL when infoSz is 0.
    \param infoSz length of info in bytes.
    \param aad buffer with additional authenticated data, may be NULL when
    aadSz is 0.
    \param aadSz length of aad in bytes.
    \param ciphertext buffer holding the ciphertext body followed by the AEAD
    tag; must be at least ctSz + hpke->Nt bytes.
    \param ctSz length of the ciphertext body in bytes, excluding the tag.
    \param plaintext buffer that receives the recovered plaintext; must be at
    least ctSz bytes.

    _Example_
    \code
    Hpke hpke;
    byte plaintext[64];
    int ret;

    ret = wc_HpkeOpenBase(&hpke, receiverKey, pubKey, pubKeySz, info, infoSz,
        aad, aadSz, ciphertext, ctSz, plaintext);
    if (ret != 0) {
        WOLFSSL_MSG("wc_HpkeOpenBase failed");
    }
    \endcode

    \sa wc_HpkeContextOpenBase
    \sa wc_HpkeSealBase
    \sa wc_HpkeDeserializePublicKey
*/
int wc_HpkeOpenBase(Hpke* hpke, void* receiverKey, const byte* pubKey,
    word16 pubKeySz, byte* info, word32 infoSz, byte* aad, word32 aadSz,
    byte* ciphertext, word32 ctSz, byte* plaintext);
