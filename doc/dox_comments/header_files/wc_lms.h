/*!
    \ingroup LMS

    \brief Initializes an LmsKey object. Must be called before any
    other LMS/HSS operation. Use wc_LmsKey_Free() to release resources
    when done.

    LMS (Leighton-Micali Signatures) and the HSS multi-tree
    composition (RFC 8554, NIST SP 800-208) are STATEFUL hash-based
    signature schemes: each call to wc_LmsKey_Sign() consumes a
    one-time component of the private key, and reusing a one-time key
    breaks the security of the scheme. Applications MUST persist the
    private key state between sign calls; see wc_LmsKey_SetWriteCb()
    and wc_LmsKey_SetReadCb().

    After init the key is in state WC_LMS_STATE_INITED. The
    parameters must be set with wc_LmsKey_SetLmsParm() or
    wc_LmsKey_SetParameters() before generating or reloading a key.

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL.

    \param [in,out] key Pointer to the LmsKey to initialize.
    \param [in] heap Heap hint for dynamic memory allocation. May be
    NULL.
    \param [in] devId Device identifier for hardware crypto callbacks.
    Use INVALID_DEVID for software-only.

    _Example_
    \code
    LmsKey key;
    int ret;

    ret = wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    if (ret != 0) {
        // error initializing key
    }
    wc_LmsKey_SetLmsParm(&key, WC_LMS_PARM_L2_H10_W8);
    // ... use key ...
    wc_LmsKey_Free(&key);
    \endcode

    \sa wc_LmsKey_Free
    \sa wc_LmsKey_SetLmsParm
    \sa wc_LmsKey_SetParameters
    \sa wc_LmsKey_MakeKey
*/
int wc_LmsKey_Init(LmsKey* key, void* heap, int devId);

/*!
    \ingroup LMS

    \brief Initializes an LmsKey with a device-side key identifier.
    Equivalent to wc_LmsKey_Init() but also stashes a binary id that
    a crypto callback can use to look up the underlying key material
    on the device. Only available when wolfSSL is built with
    WOLF_PRIVATE_KEY_ID.

    The id is copied into the key object; the caller may free its
    buffer immediately after this call returns.

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL, or id is NULL while len > 0.
    \return BUFFER_E if len is negative or greater than
    LMS_MAX_ID_LEN.

    \param [in,out] key Pointer to the LmsKey to initialize.
    \param [in] id Pointer to the device-side key identifier bytes.
    May be NULL when len is 0.
    \param [in] len Number of bytes in id; must be in
    [0, LMS_MAX_ID_LEN].
    \param [in] heap Heap hint for dynamic memory allocation.
    \param [in] devId Device identifier for the crypto callback.

    \sa wc_LmsKey_Init
    \sa wc_LmsKey_InitLabel
    \sa wc_LmsKey_Free
*/
int wc_LmsKey_InitId(LmsKey* key, const unsigned char* id, int len,
    void* heap, int devId);

/*!
    \ingroup LMS

    \brief Initializes an LmsKey with a device-side key label.
    Equivalent to wc_LmsKey_Init() but also stashes a label string
    that a crypto callback can use to look up the underlying key
    material on the device. Only available when wolfSSL is built with
    WOLF_PRIVATE_KEY_ID.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or label is NULL.
    \return BUFFER_E if label is empty or longer than
    LMS_MAX_LABEL_LEN.

    \param [in,out] key Pointer to the LmsKey to initialize.
    \param [in] label NUL-terminated device-side key label.
    \param [in] heap Heap hint for dynamic memory allocation.
    \param [in] devId Device identifier for the crypto callback.

    \sa wc_LmsKey_Init
    \sa wc_LmsKey_InitId
*/
int wc_LmsKey_InitLabel(LmsKey* key, const char* label, void* heap,
    int devId);

/*!
    \ingroup LMS

    \brief Selects a predefined LMS/HSS parameter set by name. The
    enum wc_LmsParm encodes the tree depth (levels), per-tree height,
    Winternitz parameter and hash family in a single value. See the
    wc_LmsParm definition for the list of names available in a given
    build.

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL, or if lmsParm is not
    recognized or names a parameter set that was not compiled in.
    \return BAD_STATE_E if key is not in state WC_LMS_STATE_INITED.

    \param [in,out] key Pointer to an LmsKey in state
    WC_LMS_STATE_INITED.
    \param [in] lmsParm A wc_LmsParm constant (e.g.
    WC_LMS_PARM_L2_H10_W8).

    _Example_
    \code
    LmsKey key;

    wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    wc_LmsKey_SetLmsParm(&key, WC_LMS_PARM_L2_H10_W8);
    \endcode

    \sa wc_LmsKey_SetParameters
    \sa wc_LmsKey_GetParameters
    \sa wc_LmsKey_ParmToStr
*/
int wc_LmsKey_SetLmsParm(LmsKey* key, enum wc_LmsParm lmsParm);

/*!
    \ingroup LMS

    \brief Sets the LMS/HSS parameters individually. The default
    SHA-256/256 hash is used. For finer control over the hash family
    use wc_LmsKey_SetParameters_ex().

    The combination of parameters must match one of the allowed sets
    in RFC 8554:
      - levels:     1..8
      - height:     5, 10, 15, 20 (and 25 in some builds)
      - winternitz: 1, 2, 4, or 8

    The maximum number of signatures available from a key is
    2^(levels * height).

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL, or if the requested
    parameter combination is not supported in this build.
    \return BAD_STATE_E if key is not in state WC_LMS_STATE_INITED.

    \param [in,out] key Pointer to an LmsKey in state
    WC_LMS_STATE_INITED.
    \param [in] levels Number of Merkle-tree levels in the HSS chain.
    \param [in] height Height of each individual Merkle tree.
    \param [in] winternitz Winternitz parameter (1, 2, 4 or 8).

    \sa wc_LmsKey_SetParameters_ex
    \sa wc_LmsKey_SetLmsParm
    \sa wc_LmsKey_GetParameters
*/
int wc_LmsKey_SetParameters(LmsKey* key, int levels, int height,
    int winternitz);

/*!
    \ingroup LMS

    \brief Sets the LMS/HSS parameters individually with an explicit
    hash family selector.

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL, or if the requested
    parameter combination is not supported in this build.
    \return BAD_STATE_E if key is not in state WC_LMS_STATE_INITED.

    \param [in,out] key Pointer to an LmsKey in state
    WC_LMS_STATE_INITED.
    \param [in] levels Number of Merkle-tree levels.
    \param [in] height Height of each tree.
    \param [in] winternitz Winternitz parameter (1, 2, 4 or 8).
    \param [in] hash Hash family selector identifying SHA-256/256,
    SHA-256/192, SHAKE256/256 or SHAKE256/192, as supported by the
    build.

    \sa wc_LmsKey_SetParameters
    \sa wc_LmsKey_GetParameters_ex
*/
int wc_LmsKey_SetParameters_ex(LmsKey* key, int levels, int height,
    int winternitz, int hash);

/*!
    \ingroup LMS

    \brief Retrieves the LMS/HSS parameters previously set on this
    key.

    \return 0 on success.
    \return BAD_FUNC_ARG if any pointer is NULL or no parameters are
    set.

    \param [in] key Pointer to an LmsKey with parameters set.
    \param [out] levels Receives the number of tree levels.
    \param [out] height Receives the per-tree height.
    \param [out] winternitz Receives the Winternitz parameter.

    \sa wc_LmsKey_SetParameters
    \sa wc_LmsKey_GetParameters_ex
*/
int wc_LmsKey_GetParameters(const LmsKey* key, int* levels, int* height,
    int* winternitz);

/*!
    \ingroup LMS

    \brief Retrieves the LMS/HSS parameters and hash family selector
    from this key.

    \return 0 on success.
    \return BAD_FUNC_ARG if any pointer is NULL or no parameters are
    set.

    \param [in] key Pointer to an LmsKey with parameters set.
    \param [out] levels Receives the number of tree levels.
    \param [out] height Receives the per-tree height.
    \param [out] winternitz Receives the Winternitz parameter.
    \param [out] hash Receives the hash family selector.

    \sa wc_LmsKey_SetParameters_ex
*/
int wc_LmsKey_GetParameters_ex(const LmsKey* key, int* levels, int* height,
    int* winternitz, int* hash);

/*!
    \ingroup LMS

    \brief Registers the callback that wolfSSL invokes to persist
    updated private key state. Because LMS/HSS is stateful, the
    application MUST persist the private key after each successful
    sign before the signature is released to a peer; otherwise a
    crash or restart can lead to one-time key reuse and break the
    scheme.

    The callback receives the encoded private key bytes and returns
    one of the wc_LmsRc codes. WC_LMS_RC_SAVED_TO_NV_MEMORY signals a
    durable write; other return codes are treated as failures.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or write_cb is NULL.

    \param [in,out] key Pointer to an LmsKey.
    \param [in] write_cb Callback invoked to persist the private key.

    \sa wc_LmsKey_SetReadCb
    \sa wc_LmsKey_SetContext
    \sa wc_LmsKey_Sign
*/
int wc_LmsKey_SetWriteCb(LmsKey* key, wc_lms_write_private_key_cb write_cb);

/*!
    \ingroup LMS

    \brief Registers the callback that wolfSSL invokes to load
    persisted private key state. Used by wc_LmsKey_Reload() to bring
    a saved key back into memory for further signing.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or read_cb is NULL.

    \param [in,out] key Pointer to an LmsKey.
    \param [in] read_cb Callback invoked to load the private key.

    \sa wc_LmsKey_SetWriteCb
    \sa wc_LmsKey_SetContext
    \sa wc_LmsKey_Reload
*/
int wc_LmsKey_SetReadCb(LmsKey* key, wc_lms_read_private_key_cb read_cb);

/*!
    \ingroup LMS

    \brief Sets the opaque context pointer passed to both the read
    and write private-key callbacks. Typically used to carry a file
    handle, database connection, or other persistence-layer state.

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL.

    \param [in,out] key Pointer to an LmsKey.
    \param [in] context Application-defined pointer; may be NULL.

    \sa wc_LmsKey_SetReadCb
    \sa wc_LmsKey_SetWriteCb
*/
int wc_LmsKey_SetContext(LmsKey* key, void* context);

/*!
    \ingroup LMS

    \brief Generates a fresh LMS/HSS key pair. Parameters must
    already be set (via wc_LmsKey_SetLmsParm() or
    wc_LmsKey_SetParameters()) and read/write callbacks must be
    registered. The newly generated private key is persisted via the
    write callback before the function returns; on success the key
    transitions to state WC_LMS_STATE_OK.

    Key generation runtime grows quickly with the first tree's
    height: a 3-level h=5 tree is much faster than a 1-level h=15
    tree even though both yield the same total signature count.

    \return 0 on success.
    \return BAD_FUNC_ARG if any required pointer is NULL.
    \return MEMORY_E on allocation failure.

    \param [in,out] key Pointer to an LmsKey in state
    WC_LMS_STATE_PARMSET with callbacks set.
    \param [in] rng Pointer to an initialized WC_RNG.

    _Example_
    \code
    LmsKey key;
    WC_RNG rng;

    wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    wc_LmsKey_SetLmsParm(&key, WC_LMS_PARM_L2_H10_W8);
    wc_LmsKey_SetWriteCb(&key, my_write_cb);
    wc_LmsKey_SetReadCb(&key, my_read_cb);
    wc_LmsKey_SetContext(&key, &my_storage);
    wc_InitRng(&rng);

    if (wc_LmsKey_MakeKey(&key, &rng) != 0) {
        // error generating key
    }
    \endcode

    \sa wc_LmsKey_Sign
    \sa wc_LmsKey_Reload
*/
int wc_LmsKey_MakeKey(LmsKey* key, WC_RNG* rng);

/*!
    \ingroup LMS

    \brief Reloads a previously generated LMS/HSS private key from
    persistent storage using the registered read callback, restoring
    the key to a state where it can sign further messages. On success
    the key is in state WC_LMS_STATE_OK.

    The same parameters set at key-generation time must be reapplied
    to the LmsKey before calling Reload (the persisted blob is just
    the private key bytes; the parameter set is metadata the
    application owns).

    \return 0 on success.
    \return BAD_FUNC_ARG if any required pointer is NULL.
    \return WC_LMS_RC_* mapped error if the read callback fails.

    \param [in,out] key Pointer to an LmsKey with parameters and read
    callback set.

    \sa wc_LmsKey_MakeKey
    \sa wc_LmsKey_SetReadCb
*/
int wc_LmsKey_Reload(LmsKey* key);

/*!
    \ingroup LMS

    \brief Returns the size in bytes of the encoded private key for
    the parameter set selected on this key.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL.

    \param [in] key Pointer to an LmsKey with parameters set.
    \param [out] len Receives the private key size in bytes.

    \sa wc_LmsKey_GetPubLen
    \sa wc_LmsKey_GetSigLen
*/
int wc_LmsKey_GetPrivLen(const LmsKey* key, word32* len);

/*!
    \ingroup LMS

    \brief Returns the size in bytes of the LMS/HSS public key for
    the parameter set selected on this key.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL.

    \param [in] key Pointer to an LmsKey with parameters set.
    \param [out] len Receives the public key size in bytes.

    \sa wc_LmsKey_ExportPubRaw
    \sa wc_LmsKey_GetPrivLen
*/
int wc_LmsKey_GetPubLen(const LmsKey* key, word32* len);

/*!
    \ingroup LMS

    \brief Returns the LMS/HSS signature size in bytes for the
    parameter set selected on this key.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL.

    \param [in] key Pointer to an LmsKey with parameters set.
    \param [out] len Receives the signature size in bytes.

    \sa wc_LmsKey_Sign
*/
int wc_LmsKey_GetSigLen(const LmsKey* key, word32* len);

/*!
    \ingroup LMS

    \brief Signs msg with the LMS/HSS private key in key. On entry
    *sigSz is the size of the sig buffer; on success it is updated to
    the bytes written.

    Each successful sign call consumes a one-time component of the
    private key. The updated key state is persisted via the
    registered write callback BEFORE the new signature is returned to
    the caller. If the write callback fails the sign call fails and
    the signature is not released. When the supply of one-time keys
    is exhausted the key transitions to state WC_LMS_STATE_NOSIGS and
    further sign attempts return SIG_OTHER_E (or similar) -- query
    wc_LmsKey_SigsLeft() to detect this condition in advance.

    \return 0 on success.
    \return BAD_FUNC_ARG if any required pointer is NULL.
    \return BUFFER_E if *sigSz is smaller than the signature size.
    \return -1 (or similar) if all one-time keys have been used.

    \param [in,out] key Pointer to an LmsKey in state WC_LMS_STATE_OK.
    \param [out] sig Buffer that receives the signature.
    \param [in,out] sigSz In: size of sig. Out: bytes written.
    \param [in] msg Message to sign.
    \param [in] msgSz Length of msg in bytes.

    \sa wc_LmsKey_Verify
    \sa wc_LmsKey_SigsLeft
    \sa wc_LmsKey_SetWriteCb
*/
int wc_LmsKey_Sign(LmsKey* key, byte* sig, word32* sigSz, const byte* msg,
    int msgSz);

/*!
    \ingroup LMS

    \brief Returns the number of one-time signatures still available
    from this key. When the count reaches zero the key can no longer
    sign and should be retired.

    \return Non-negative number of remaining signatures on success.
    \return Negative error code on failure (e.g. BAD_FUNC_ARG if key
    is NULL).

    \param [in,out] key Pointer to an LmsKey in state WC_LMS_STATE_OK.

    \sa wc_LmsKey_Sign
*/
int wc_LmsKey_SigsLeft(LmsKey* key);

/*!
    \ingroup LMS

    \brief Releases resources held by an LmsKey. Safe to call with a
    NULL pointer. After this call the key is in state
    WC_LMS_STATE_FREED and must be re-initialized before reuse.

    \param [in,out] key Pointer to the LmsKey to free.

    \sa wc_LmsKey_Init
*/
void wc_LmsKey_Free(LmsKey* key);

/*!
    \ingroup LMS

    \brief Copies the public part of keySrc into keyDst. The
    destination key inherits the same parameters and may be used for
    verification; it does not carry the private key state and cannot
    sign. Useful for handing a verifier the minimal data it needs.

    \return 0 on success.
    \return BAD_FUNC_ARG if keyDst or keySrc is NULL.

    \param [in,out] keyDst Pointer to an initialized destination
    LmsKey.
    \param [in] keySrc Pointer to an LmsKey with the public key.

    \sa wc_LmsKey_ExportPub_ex
    \sa wc_LmsKey_ExportPubRaw
*/
int wc_LmsKey_ExportPub(LmsKey* keyDst, const LmsKey* keySrc);

/*!
    \ingroup LMS

    \brief Like wc_LmsKey_ExportPub() but the destination key is
    initialized fresh with the supplied heap and devId.

    \return 0 on success.
    \return BAD_FUNC_ARG if keyDst or keySrc is NULL.

    \param [in,out] keyDst Pointer to an LmsKey to populate.
    \param [in] keySrc Pointer to an LmsKey with the public key.
    \param [in] heap Heap hint for keyDst.
    \param [in] devId Device identifier for keyDst.

    \sa wc_LmsKey_ExportPub
*/
int wc_LmsKey_ExportPub_ex(LmsKey* keyDst, const LmsKey* keySrc, void* heap,
    int devId);

/*!
    \ingroup LMS

    \brief Exports the LMS/HSS public key as a raw byte string. On
    entry *outLen is the size of out; on success it is updated to the
    bytes written.

    \return 0 on success.
    \return BAD_FUNC_ARG if any required pointer is NULL.
    \return BUFFER_E if *outLen is smaller than the public key size.

    \param [in] key Pointer to an LmsKey.
    \param [out] out Buffer that receives the public key.
    \param [in,out] outLen In: size of out. Out: bytes written.

    \sa wc_LmsKey_ImportPubRaw
    \sa wc_LmsKey_GetPubLen
*/
int wc_LmsKey_ExportPubRaw(const LmsKey* key, byte* out, word32* outLen);

/*!
    \ingroup LMS

    \brief Imports a raw LMS/HSS public key into key. The key must be
    in state WC_LMS_STATE_INITED. Parameter information is recovered
    from the encoded header, after which the key transitions to
    state WC_LMS_STATE_VERIFYONLY.

    \return 0 on success.
    \return BAD_FUNC_ARG if any required pointer is NULL.
    \return BUFFER_E if inLen is too small.

    \param [in,out] key Pointer to an LmsKey in WC_LMS_STATE_INITED.
    \param [in] in Raw public key bytes.
    \param [in] inLen Length of in in bytes.

    \sa wc_LmsKey_ExportPubRaw
    \sa wc_LmsKey_Verify
*/
int wc_LmsKey_ImportPubRaw(LmsKey* key, const byte* in, word32 inLen);

/*!
    \ingroup LMS

    \brief Verifies an LMS/HSS signature against msg using the public
    key held in key. The function returns 0 only when the signature
    is valid; any other value indicates the signature was rejected.

    \return 0 on a valid signature.
    \return BAD_FUNC_ARG if any required pointer is NULL.
    \return SIG_VERIFY_E (or similar) if the signature is invalid or
    malformed.

    \param [in,out] key Pointer to an LmsKey with the public key set.
    \param [in] sig Signature bytes to verify.
    \param [in] sigSz Length of sig in bytes.
    \param [in] msg Message that was signed.
    \param [in] msgSz Length of msg in bytes.

    \sa wc_LmsKey_Sign
    \sa wc_LmsKey_ImportPubRaw
*/
int wc_LmsKey_Verify(LmsKey* key, const byte* sig, word32 sigSz,
    const byte* msg, int msgSz);

/*!
    \ingroup LMS

    \brief Returns a static, NUL-terminated string describing an LMS
    parameter set. Useful for logging and diagnostics.

    \return Pointer to a static string on success.
    \return NULL if lmsParm is not recognized.

    \param [in] lmsParm A wc_LmsParm constant.

    \sa wc_LmsKey_SetLmsParm
*/
const char* wc_LmsKey_ParmToStr(enum wc_LmsParm lmsParm);

/*!
    \ingroup LMS

    \brief Returns a pointer to the 16-byte LMS Key Identifier (I)
    embedded in the private key, together with its length. The
    returned pointer aliases internal key memory and is valid only
    until the key is freed.

    \return 0 on success.
    \return BAD_FUNC_ARG if any required pointer is NULL.

    \param [in,out] key Pointer to an LmsKey with a private key.
    \param [out] kid Receives a pointer to the I bytes.
    \param [out] kidSz Receives the length (16 / WC_LMS_I_LEN).

    \sa wc_LmsKey_GetKidFromPrivRaw
*/
int wc_LmsKey_GetKid(LmsKey* key, const byte** kid, word32* kidSz);

/*!
    \ingroup LMS

    \brief Returns a pointer to the LMS Key Identifier (I) within a
    raw encoded private key buffer, without requiring an LmsKey
    object. Used to look up the matching state record in persistent
    storage during reload.

    \return Pointer to the I bytes within priv on success.
    \return NULL if priv is NULL or privSz is too small to contain a
    valid header.

    \param [in] priv Encoded private key bytes.
    \param [in] privSz Length of priv in bytes.

    \sa wc_LmsKey_GetKid
*/
const byte* wc_LmsKey_GetKidFromPrivRaw(const byte* priv, word32 privSz);
