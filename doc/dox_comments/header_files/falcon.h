/*!
    \ingroup Falcon

    \brief Initializes a falcon_key object with default settings (no heap
    hint, software-only). Must be called before any other Falcon operation.
    Call wc_falcon_set_level() to select a parameter set before generating or
    importing a key. Release resources with wc_falcon_free() when done.

    Falcon is a quantum-resistant lattice signature scheme. It has not been
    standardized by NIST yet, so the "falcon" API name is experimental and
    subject to change, and building it requires --enable-experimental.

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL.

    \param [in,out] key Pointer to the falcon_key to initialize.

    _Example_
    \code
    falcon_key key;
    int ret;

    ret = wc_falcon_init(&key);
    if (ret != 0) {
        // error initializing key
    }
    ret = wc_falcon_set_level(&key, 1); // Falcon-512
    // ... use key ...
    wc_falcon_free(&key);
    \endcode

    \sa wc_falcon_init_ex
    \sa wc_falcon_set_level
    \sa wc_falcon_free
*/
int wc_falcon_init(falcon_key* key);

/*!
    \ingroup Falcon

    \brief Initializes a falcon_key object with a heap hint and device
    identifier for hardware crypto callbacks.

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL.

    \param [in,out] key Pointer to the falcon_key to initialize.
    \param [in] heap Heap hint for dynamic memory allocation. May be NULL.
    \param [in] devId Device identifier for hardware crypto callbacks; use
    INVALID_DEVID for software-only.

    _Example_
    \code
    falcon_key key;
    int ret;

    ret = wc_falcon_init_ex(&key, NULL, INVALID_DEVID);
    if (ret != 0) {
        // error initializing key
    }
    ret = wc_falcon_set_level(&key, 5); // Falcon-1024
    // ... use key ...
    wc_falcon_free(&key);
    \endcode

    \sa wc_falcon_init
    \sa wc_falcon_set_level
    \sa wc_falcon_free
*/
int wc_falcon_init_ex(falcon_key* key, void* heap, int devId);

/*!
    \ingroup Falcon

    \brief Initializes a falcon_key object and associates it with a key
    identifier for use with a hardware crypto callback / secure element. Only
    available when built with WOLF_PRIVATE_KEY_ID.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or id is NULL, or len is out of range.

    \param [in,out] key Pointer to the falcon_key to initialize.
    \param [in] id Key identifier bytes.
    \param [in] len Length of id in bytes.
    \param [in] heap Heap hint. May be NULL.
    \param [in] devId Device identifier for the crypto callback.

    \sa wc_falcon_init_ex
    \sa wc_falcon_init_label
*/
int wc_falcon_init_id(falcon_key* key, const unsigned char* id, int len,
    void* heap, int devId);

/*!
    \ingroup Falcon

    \brief Initializes a falcon_key object and associates it with a text label
    for use with a hardware crypto callback / secure element. Only available
    when built with WOLF_PRIVATE_KEY_ID.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or label is NULL, or the label is invalid.

    \param [in,out] key Pointer to the falcon_key to initialize.
    \param [in] label NUL-terminated label string.
    \param [in] heap Heap hint. May be NULL.
    \param [in] devId Device identifier for the crypto callback.

    \sa wc_falcon_init_ex
    \sa wc_falcon_init_id
*/
int wc_falcon_init_label(falcon_key* key, const char* label, void* heap,
    int devId);

/*!
    \ingroup Falcon

    \brief Selects the Falcon parameter set (security level) for a key. Must be
    set before key generation or import.

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL or level is not 1 or 5.

    \param [in,out] key Pointer to the falcon_key.
    \param [in] level Parameter set: 1 for Falcon-512, 5 for Falcon-1024.

    \sa wc_falcon_get_level
    \sa wc_falcon_make_key
*/
int wc_falcon_set_level(falcon_key* key, byte level);

/*!
    \ingroup Falcon

    \brief Retrieves the Falcon parameter set (security level) currently set on
    a key.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or level is NULL, or no level has been set.

    \param [in] key Pointer to the falcon_key.
    \param [out] level Set to 1 (Falcon-512) or 5 (Falcon-1024).

    \sa wc_falcon_set_level
*/
int wc_falcon_get_level(falcon_key* key, byte* level);

/*!
    \ingroup Falcon

    \brief Frees a falcon_key object and securely zeros any key material it
    holds. The key may be re-initialized afterwards.

    \param [in,out] key Pointer to the falcon_key to free. May be NULL.

    \sa wc_falcon_init
    \sa wc_falcon_init_ex
*/
void wc_falcon_free(falcon_key* key);

/*!
    \ingroup Falcon

    \brief Generates a Falcon key pair into key. The parameter set must have
    been selected with wc_falcon_set_level() first. Not available in
    verify-only builds (WOLFSSL_FALCON_VERIFY_ONLY).

    \return 0 on success.
    \return BAD_FUNC_ARG if key or rng is NULL or the level is unset.
    \return MEMORY_E on allocation failure.

    \param [in,out] key Pointer to an initialized falcon_key with a level set.
    \param [in] rng Pointer to an initialized WC_RNG.

    _Example_
    \code
    falcon_key key;
    WC_RNG rng;
    int ret;

    wc_InitRng(&rng);
    wc_falcon_init(&key);
    wc_falcon_set_level(&key, 1);

    ret = wc_falcon_make_key(&key, &rng);
    if (ret != 0) {
        // error generating key
    }
    wc_falcon_free(&key);
    wc_FreeRng(&rng);
    \endcode

    \sa wc_falcon_set_level
    \sa wc_falcon_sign_msg
    \sa wc_falcon_check_key
*/
int wc_falcon_make_key(falcon_key* key, WC_RNG* rng);

/*!
    \ingroup Falcon

    \brief Signs a message with a Falcon private key, producing a compressed
    signature. On entry *outLen holds the size of the out buffer; on return it
    holds the signature length. Not available in verify-only builds.

    \return 0 on success.
    \return BAD_FUNC_ARG if a required pointer is NULL or the private key is not
    set.
    \return BUFFER_E if the out buffer is too small.

    \param [in] in Message to sign.
    \param [in] inLen Length of the message in bytes.
    \param [out] out Buffer to receive the signature.
    \param [in,out] outLen In: size of out; Out: signature length.
    \param [in] key Pointer to a falcon_key holding a private key.
    \param [in] rng Pointer to an initialized WC_RNG.

    _Example_
    \code
    byte sig[FALCON_MAX_SIG_SIZE];
    word32 sigLen = sizeof(sig);
    int ret;

    ret = wc_falcon_sign_msg(msg, msgLen, sig, &sigLen, &key, &rng);
    if (ret != 0) {
        // error signing
    }
    \endcode

    \sa wc_falcon_verify_msg
    \sa wc_falcon_make_key
    \sa wc_falcon_sig_size
*/
int wc_falcon_sign_msg(const byte* in, word32 inLen, byte* out, word32 *outLen,
    falcon_key* key, WC_RNG* rng);

/*!
    \ingroup Falcon

    \brief Verifies a Falcon signature over a message with a public key. On a
    completed verification *res is set to 1 when the signature is valid and 0
    otherwise; the function returns 0 in both cases. A non-zero return indicates
    an operational error.

    \return 0 on a completed verification (check *res for validity).
    \return BAD_FUNC_ARG if a required pointer is NULL or the public key is not
    set.

    \param [in] sig Signature to verify.
    \param [in] sigLen Length of the signature in bytes.
    \param [in] msg Message the signature is over.
    \param [in] msgLen Length of the message in bytes.
    \param [out] res Set to 1 if the signature is valid, 0 otherwise.
    \param [in] key Pointer to a falcon_key holding a public key.

    _Example_
    \code
    int res = 0;
    int ret;

    ret = wc_falcon_verify_msg(sig, sigLen, msg, msgLen, &res, &key);
    if (ret == 0 && res == 1) {
        // signature is valid
    }
    \endcode

    \sa wc_falcon_sign_msg
    \sa wc_falcon_import_public
*/
int wc_falcon_verify_msg(const byte* sig, word32 sigLen, const byte* msg,
    word32 msgLen, int* res, falcon_key* key);

/*!
    \ingroup Falcon

    \brief Imports a raw (Falcon-encoded) public key into key. The parameter
    level must have been set first so the expected length is known.

    \return 0 on success.
    \return BAD_FUNC_ARG if a pointer is NULL, the level is unset, or inLen does
    not match the expected public-key size.

    \param [in] in Encoded public key bytes.
    \param [in] inLen Length of in.
    \param [in,out] key Pointer to a falcon_key with a level set.

    \sa wc_falcon_export_public
    \sa wc_falcon_verify_msg
*/
int wc_falcon_import_public(const byte* in, word32 inLen, falcon_key* key);

/*!
    \ingroup Falcon

    \brief Imports a raw (Falcon-encoded) private key into key, without a public
    key. The parameter level must have been set first.

    \return 0 on success.
    \return BAD_FUNC_ARG if a pointer is NULL, the level is unset, or privSz is
    wrong.

    \param [in] priv Encoded private key bytes.
    \param [in] privSz Length of priv.
    \param [in,out] key Pointer to a falcon_key with a level set.

    \sa wc_falcon_import_private_key
    \sa wc_falcon_export_private
*/
int wc_falcon_import_private_only(const byte* priv, word32 privSz,
    falcon_key* key);

/*!
    \ingroup Falcon

    \brief Imports a raw Falcon private key and (optionally) public key into
    key. The parameter level must have been set first.

    \return 0 on success.
    \return BAD_FUNC_ARG if a required pointer is NULL, the level is unset, or a
    size is wrong.

    \param [in] priv Encoded private key bytes.
    \param [in] privSz Length of priv.
    \param [in] pub Encoded public key bytes. May be NULL.
    \param [in] pubSz Length of pub (0 if pub is NULL).
    \param [in,out] key Pointer to a falcon_key with a level set.

    \sa wc_falcon_import_private_only
    \sa wc_falcon_export_key
*/
int wc_falcon_import_private_key(const byte* priv, word32 privSz,
    const byte* pub, word32 pubSz, falcon_key* key);

/*!
    \ingroup Falcon

    \brief Exports the raw (Falcon-encoded) public key from key. On entry
    *outLen is the size of out; on return it is the number of bytes written.

    \return 0 on success.
    \return BAD_FUNC_ARG if a pointer is NULL or no public key is set.
    \return BUFFER_E if out is too small.

    \param [in] key Pointer to a falcon_key holding a public key.
    \param [out] out Buffer to receive the encoded public key.
    \param [in,out] outLen In: size of out; Out: bytes written.

    \sa wc_falcon_import_public
    \sa wc_falcon_pub_size
*/
int wc_falcon_export_public(falcon_key* key, byte* out, word32* outLen);

/*!
    \ingroup Falcon

    \brief Exports the raw (Falcon-encoded) private key from key.

    \return 0 on success.
    \return BAD_FUNC_ARG if a pointer is NULL or no private key is set.
    \return BUFFER_E if out is too small.

    \param [in] key Pointer to a falcon_key holding a private key.
    \param [out] out Buffer to receive the encoded private key.
    \param [in,out] outLen In: size of out; Out: bytes written.

    \sa wc_falcon_import_private_only
    \sa wc_falcon_priv_size
*/
int wc_falcon_export_private_only(falcon_key* key, byte* out, word32* outLen);

/*!
    \ingroup Falcon

    \brief Exports the raw (Falcon-encoded) private key from key. Equivalent to
    wc_falcon_export_private_only().

    \return 0 on success.
    \return BAD_FUNC_ARG if a pointer is NULL or no private key is set.
    \return BUFFER_E if out is too small.

    \param [in] key Pointer to a falcon_key holding a private key.
    \param [out] out Buffer to receive the encoded private key.
    \param [in,out] outLen In: size of out; Out: bytes written.

    \sa wc_falcon_export_private_only
    \sa wc_falcon_export_key
*/
int wc_falcon_export_private(falcon_key* key, byte* out, word32* outLen);

/*!
    \ingroup Falcon

    \brief Exports both the raw private and public keys from key in a single
    call. Each length parameter is In: buffer size, Out: bytes written.

    \return 0 on success.
    \return BAD_FUNC_ARG if a required pointer is NULL or a key half is missing.
    \return BUFFER_E if a buffer is too small.

    \param [in] key Pointer to a falcon_key holding a key pair.
    \param [out] priv Buffer to receive the encoded private key.
    \param [in,out] privSz In: size of priv; Out: bytes written.
    \param [out] pub Buffer to receive the encoded public key.
    \param [in,out] pubSz In: size of pub; Out: bytes written.

    \sa wc_falcon_import_private_key
*/
int wc_falcon_export_key(falcon_key* key, byte* priv, word32 *privSz,
    byte* pub, word32* pubSz);

/*!
    \ingroup Falcon

    \brief Checks the consistency of a Falcon key. Requires both key halves to
    be present. When the native signing core is compiled in, the stored public
    key h is additionally verified against the private key by checking the
    defining relation h*f == g (mod q); in verify-only or crypto-callback-only
    builds only the presence of both halves is checked.

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL or the level is unset.
    \return PUBLIC_KEY_E if either key half is missing, or if the public and
    private keys are cryptographically inconsistent.

    \param [in] key Pointer to a falcon_key to check.

    \sa wc_falcon_make_key
    \sa wc_falcon_import_private_key
*/
int wc_falcon_check_key(falcon_key* key);

/*!
    \ingroup Falcon

    \brief Returns the encoded private-key size in bytes for the key's
    parameter set (level).

    \return Private-key size in bytes on success.
    \return BAD_FUNC_ARG if key is NULL or the level is unset.

    \param [in] key Pointer to a falcon_key with a level set.

    \sa wc_falcon_priv_size
    \sa wc_falcon_pub_size
*/
int wc_falcon_size(falcon_key* key);

/*!
    \ingroup Falcon

    \brief Returns the encoded private-key size in bytes for the key's
    parameter set (level).

    \return Private-key size in bytes on success.
    \return BAD_FUNC_ARG if key is NULL or the level is unset.

    \param [in] key Pointer to a falcon_key with a level set.

    \sa wc_falcon_size
    \sa wc_falcon_export_private
*/
int wc_falcon_priv_size(falcon_key* key);

/*!
    \ingroup Falcon

    \brief Returns the encoded public-key size in bytes for the key's parameter
    set (level).

    \return Public-key size in bytes on success.
    \return BAD_FUNC_ARG if key is NULL or the level is unset.

    \param [in] key Pointer to a falcon_key with a level set.

    \sa wc_falcon_export_public
    \sa wc_falcon_priv_size
*/
int wc_falcon_pub_size(falcon_key* key);

/*!
    \ingroup Falcon

    \brief Returns the maximum signature size in bytes for the key's parameter
    set (level).

    \return Maximum signature size in bytes on success.
    \return BAD_FUNC_ARG if key is NULL or the level is unset.

    \param [in] key Pointer to a falcon_key with a level set.

    \sa wc_falcon_sign_msg
*/
int wc_falcon_sig_size(falcon_key* key);

/*!
    \ingroup Falcon

    \brief Decodes a DER/ASN.1 (PKCS#8) Falcon private key into key. On return
    *inOutIdx is advanced past the consumed input.

    \return 0 on success.
    \return ASN_PARSE_E or other negative error on a malformed input.

    \param [in] input DER-encoded private key.
    \param [in,out] inOutIdx In: offset to start; Out: offset after the key.
    \param [in,out] key Pointer to an initialized falcon_key.
    \param [in] inSz Total length of input.

    \sa wc_Falcon_PrivateKeyToDer
    \sa wc_Falcon_PublicKeyDecode
*/
int wc_Falcon_PrivateKeyDecode(const byte* input, word32* inOutIdx,
    falcon_key* key, word32 inSz);

/*!
    \ingroup Falcon

    \brief Decodes a DER/ASN.1 (SubjectPublicKeyInfo) Falcon public key into
    key. On return *inOutIdx is advanced past the consumed input.

    \return 0 on success.
    \return ASN_PARSE_E or other negative error on a malformed input.

    \param [in] input DER-encoded public key.
    \param [in,out] inOutIdx In: offset to start; Out: offset after the key.
    \param [in,out] key Pointer to an initialized falcon_key.
    \param [in] inSz Total length of input.

    \sa wc_Falcon_PublicKeyToDer
    \sa wc_Falcon_PrivateKeyDecode
*/
int wc_Falcon_PublicKeyDecode(const byte* input, word32* inOutIdx,
    falcon_key* key, word32 inSz);

/*!
    \ingroup Falcon

    \brief Encodes a Falcon private key (with its public key) as a DER/ASN.1
    (PKCS#8) structure. Pass a NULL output to query the required length.

    \return Number of bytes written (or required, if output is NULL) on success.
    \return BAD_FUNC_ARG or BUFFER_E on error.

    \param [in] key Pointer to a falcon_key holding a private key.
    \param [out] output Buffer to receive the DER. May be NULL to query length.
    \param [in] inLen Size of output in bytes.

    \sa wc_Falcon_PrivateKeyDecode
    \sa wc_Falcon_PrivateKeyToDer
*/
int wc_Falcon_KeyToDer(falcon_key* key, byte* output, word32 inLen);

/*!
    \ingroup Falcon

    \brief Encodes only the Falcon private key as a DER/ASN.1 (PKCS#8)
    structure. Pass a NULL output to query the required length.

    \return Number of bytes written (or required, if output is NULL) on success.
    \return BAD_FUNC_ARG or BUFFER_E on error.

    \param [in] key Pointer to a falcon_key holding a private key.
    \param [out] output Buffer to receive the DER. May be NULL to query length.
    \param [in] inLen Size of output in bytes.

    \sa wc_Falcon_PrivateKeyDecode
    \sa wc_Falcon_KeyToDer
*/
int wc_Falcon_PrivateKeyToDer(falcon_key* key, byte* output, word32 inLen);

/*!
    \ingroup Falcon

    \brief Encodes a Falcon public key as DER/ASN.1. When withAlg is non-zero
    the full SubjectPublicKeyInfo (with the algorithm identifier) is produced;
    otherwise only the raw public key bit string is written. Pass a NULL output
    to query the required length.

    \return Number of bytes written (or required, if output is NULL) on success.
    \return BAD_FUNC_ARG or BUFFER_E on error.

    \param [in] key Pointer to a falcon_key holding a public key.
    \param [out] output Buffer to receive the DER. May be NULL to query length.
    \param [in] inLen Size of output in bytes.
    \param [in] withAlg Non-zero to include the algorithm identifier.

    \sa wc_Falcon_PublicKeyDecode
*/
int wc_Falcon_PublicKeyToDer(falcon_key* key, byte* output, word32 inLen,
    int withAlg);
