/*!
    \ingroup XMSS

    \brief Initializes an XmssKey object. Must be called before any
    other XMSS/XMSS^MT operation. Use wc_XmssKey_Free() to release
    resources when done.

    XMSS (eXtended Merkle Signature Scheme) and its multi-tree
    variant XMSS^MT (RFC 8391, NIST SP 800-208) are STATEFUL
    hash-based signature schemes: each call to wc_XmssKey_Sign()
    consumes a one-time component of the private key, and reusing a
    one-time key destroys the security of the scheme. Applications
    MUST persist the private key state between sign calls; see
    wc_XmssKey_SetWriteCb() and wc_XmssKey_SetReadCb().

    After init the key is in state WC_XMSS_STATE_INITED. The
    parameter set must be selected by name with
    wc_XmssKey_SetParamStr() before generating or reloading a key.

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL.

    \param [in,out] key Pointer to the XmssKey to initialize.
    \param [in] heap Heap hint for dynamic memory allocation. May be
    NULL.
    \param [in] devId Device identifier for hardware crypto callbacks.
    Use INVALID_DEVID for software-only.

    _Example_
    \code
    XmssKey key;
    int ret;

    ret = wc_XmssKey_Init(&key, NULL, INVALID_DEVID);
    if (ret != 0) {
        // error initializing key
    }
    wc_XmssKey_SetParamStr(&key, "XMSS-SHA2_10_256");
    // ... use key ...
    wc_XmssKey_Free(&key);
    \endcode

    \sa wc_XmssKey_Free
    \sa wc_XmssKey_SetParamStr
    \sa wc_XmssKey_MakeKey
*/
int wc_XmssKey_Init(XmssKey* key, void* heap, int devId);

/*!
    \ingroup XMSS

    \brief Initializes an XmssKey with a device-side key identifier.
    Equivalent to wc_XmssKey_Init() but also stashes a binary id that
    a crypto callback can use to look up the underlying key material
    on the device. Only available when wolfSSL is built with
    WOLF_PRIVATE_KEY_ID.

    The id is copied into the key object; the caller may free its
    buffer immediately after this call returns.

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL, or id is NULL while len > 0.
    \return BUFFER_E if len is negative or greater than
    XMSS_MAX_ID_LEN.

    \param [in,out] key Pointer to the XmssKey to initialize.
    \param [in] id Pointer to the device-side key identifier bytes.
    \param [in] len Number of bytes in id; must be in
    [0, XMSS_MAX_ID_LEN].
    \param [in] heap Heap hint for dynamic memory allocation.
    \param [in] devId Device identifier for the crypto callback.

    \sa wc_XmssKey_Init
    \sa wc_XmssKey_InitLabel
    \sa wc_XmssKey_Free
*/
int wc_XmssKey_InitId(XmssKey* key, const unsigned char* id, int len,
    void* heap, int devId);

/*!
    \ingroup XMSS

    \brief Initializes an XmssKey with a device-side key label.
    Equivalent to wc_XmssKey_Init() but also stashes a label string
    that a crypto callback can use to look up the underlying key
    material on the device. Only available when wolfSSL is built with
    WOLF_PRIVATE_KEY_ID.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or label is NULL.
    \return BUFFER_E if label is empty or longer than
    XMSS_MAX_LABEL_LEN.

    \param [in,out] key Pointer to the XmssKey to initialize.
    \param [in] label NUL-terminated device-side key label.
    \param [in] heap Heap hint for dynamic memory allocation.
    \param [in] devId Device identifier for the crypto callback.

    \sa wc_XmssKey_Init
    \sa wc_XmssKey_InitId
*/
int wc_XmssKey_InitLabel(XmssKey* key, const char* label, void* heap,
    int devId);

/*!
    \ingroup XMSS

    \brief Selects an XMSS or XMSS^MT parameter set by its RFC 8391
    name. Accepted names take the form
    "XMSS-<hash>_<height>_<n>" (single-tree) or
    "XMSSMT-<hash>_<total_height>/<layers>_<n>" (multi-tree), for
    example "XMSS-SHA2_10_256" or "XMSSMT-SHA2_20/2_256". The set of
    names actually accepted depends on the hash families and tree
    heights enabled at build time.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or str is NULL, or if the named
    parameter set is unknown or not compiled in.
    \return BAD_STATE_E if key is not in state WC_XMSS_STATE_INITED.

    \param [in,out] key Pointer to an XmssKey in state
    WC_XMSS_STATE_INITED.
    \param [in] str Parameter set name (NUL-terminated).

    _Example_
    \code
    XmssKey key;

    wc_XmssKey_Init(&key, NULL, INVALID_DEVID);
    wc_XmssKey_SetParamStr(&key, "XMSS-SHA2_10_256");
    \endcode

    \sa wc_XmssKey_GetParamStr
    \sa wc_XmssKey_MakeKey
*/
int wc_XmssKey_SetParamStr(XmssKey* key, const char* str);

/*!
    \ingroup XMSS

    \brief Retrieves the parameter set name currently selected on
    this key. The returned pointer is a static string and must not be
    freed by the caller.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or str is NULL, or no parameter set
    has been selected.

    \param [in] key Pointer to an XmssKey with a parameter set
    selected.
    \param [out] str Receives a pointer to a static parameter name
    string.

    \sa wc_XmssKey_SetParamStr
*/
int wc_XmssKey_GetParamStr(const XmssKey* key, const char** str);

/*!
    \ingroup XMSS

    \brief Registers the callback that wolfSSL invokes to persist
    updated private key state. Because XMSS/XMSS^MT is stateful, the
    application MUST persist the private key after each successful
    sign before the signature is released; otherwise a crash or
    restart can lead to one-time key reuse and break the scheme.

    The callback returns one of the wc_XmssRc codes;
    WC_XMSS_RC_SAVED_TO_NV_MEMORY signals a durable write.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or write_cb is NULL.

    \param [in,out] key Pointer to an XmssKey.
    \param [in] write_cb Callback invoked to persist the private key.

    \sa wc_XmssKey_SetReadCb
    \sa wc_XmssKey_SetContext
    \sa wc_XmssKey_Sign
*/
int wc_XmssKey_SetWriteCb(XmssKey* key, wc_xmss_write_private_key_cb write_cb);

/*!
    \ingroup XMSS

    \brief Registers the callback that wolfSSL invokes to load
    persisted private key state. Used by wc_XmssKey_Reload() to bring
    a saved key back into memory for further signing.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or read_cb is NULL.

    \param [in,out] key Pointer to an XmssKey.
    \param [in] read_cb Callback invoked to load the private key.

    \sa wc_XmssKey_SetWriteCb
    \sa wc_XmssKey_Reload
*/
int wc_XmssKey_SetReadCb(XmssKey* key, wc_xmss_read_private_key_cb read_cb);

/*!
    \ingroup XMSS

    \brief Sets the opaque context pointer passed to both the read
    and write private-key callbacks.

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL.

    \param [in,out] key Pointer to an XmssKey.
    \param [in] context Application-defined pointer; may be NULL.

    \sa wc_XmssKey_SetReadCb
    \sa wc_XmssKey_SetWriteCb
*/
int wc_XmssKey_SetContext(XmssKey* key, void* context);

/*!
    \ingroup XMSS

    \brief Generates a fresh XMSS/XMSS^MT key pair. The parameter set
    must already be selected via wc_XmssKey_SetParamStr() and the
    read/write callbacks must be registered. The newly generated
    private key is persisted via the write callback before the
    function returns; on success the key transitions to state
    WC_XMSS_STATE_OK.

    Key generation can be slow for large tree heights; XMSS^MT
    variants amortize the cost over multiple smaller trees and
    generate noticeably faster than equivalent single-tree XMSS
    parameter sets.

    \return 0 on success.
    \return BAD_FUNC_ARG if any required pointer is NULL.
    \return MEMORY_E on allocation failure.

    \param [in,out] key Pointer to an XmssKey in state
    WC_XMSS_STATE_PARMSET with callbacks set.
    \param [in] rng Pointer to an initialized WC_RNG.

    _Example_
    \code
    XmssKey key;
    WC_RNG rng;

    wc_XmssKey_Init(&key, NULL, INVALID_DEVID);
    wc_XmssKey_SetParamStr(&key, "XMSS-SHA2_10_256");
    wc_XmssKey_SetWriteCb(&key, my_write_cb);
    wc_XmssKey_SetReadCb(&key, my_read_cb);
    wc_XmssKey_SetContext(&key, &my_storage);
    wc_InitRng(&rng);

    if (wc_XmssKey_MakeKey(&key, &rng) != 0) {
        // error generating key
    }
    \endcode

    \sa wc_XmssKey_Sign
    \sa wc_XmssKey_Reload
*/
int wc_XmssKey_MakeKey(XmssKey* key, WC_RNG* rng);

/*!
    \ingroup XMSS

    \brief Reloads a previously generated XMSS/XMSS^MT private key
    from persistent storage using the registered read callback,
    restoring the key to a state where it can sign further messages.
    On success the key is in state WC_XMSS_STATE_OK.

    The same parameter set selected at key-generation time must be
    reapplied with wc_XmssKey_SetParamStr() before calling Reload.

    \return 0 on success.
    \return BAD_FUNC_ARG if any required pointer is NULL.
    \return WC_XMSS_RC_* mapped error if the read callback fails.

    \param [in,out] key Pointer to an XmssKey with parameters and
    read callback set.

    \sa wc_XmssKey_MakeKey
    \sa wc_XmssKey_SetReadCb
*/
int wc_XmssKey_Reload(XmssKey* key);

/*!
    \ingroup XMSS

    \brief Returns the size in bytes of the encoded private key for
    the parameter set selected on this key.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL.

    \param [in] key Pointer to an XmssKey with parameters set.
    \param [out] len Receives the private key size in bytes.

    \sa wc_XmssKey_GetPubLen
    \sa wc_XmssKey_GetSigLen
*/
int wc_XmssKey_GetPrivLen(const XmssKey* key, word32* len);

/*!
    \ingroup XMSS

    \brief Returns the size in bytes of the XMSS/XMSS^MT public key
    for the parameter set selected on this key.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL.

    \param [in] key Pointer to an XmssKey with parameters set.
    \param [out] len Receives the public key size in bytes.

    \sa wc_XmssKey_ExportPubRaw
*/
int wc_XmssKey_GetPubLen(const XmssKey* key, word32* len);

/*!
    \ingroup XMSS

    \brief Returns the signature size in bytes for the parameter set
    selected on this key.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL.

    \param [in] key Pointer to an XmssKey with parameters set.
    \param [out] len Receives the signature size in bytes.

    \sa wc_XmssKey_Sign
*/
int wc_XmssKey_GetSigLen(const XmssKey* key, word32* len);

/*!
    \ingroup XMSS

    \brief Signs msg with the XMSS/XMSS^MT private key in key. On
    entry *sigSz is the size of the sig buffer; on success it is
    updated to the bytes written.

    Each successful sign call consumes a one-time component of the
    private key. The updated key state is persisted via the
    registered write callback BEFORE the new signature is returned to
    the caller. If the write callback fails the sign call fails and
    the signature is not released. When the supply of one-time keys
    is exhausted the key transitions to state WC_XMSS_STATE_NOSIGS
    and further sign attempts fail -- query wc_XmssKey_SigsLeft() to
    detect this condition in advance.

    \return 0 on success.
    \return BAD_FUNC_ARG if any required pointer is NULL.
    \return BUFFER_E if *sigSz is smaller than the signature size.
    \return Negative error if all one-time keys have been used.

    \param [in,out] key Pointer to an XmssKey in state
    WC_XMSS_STATE_OK.
    \param [out] sig Buffer that receives the signature.
    \param [in,out] sigSz In: size of sig. Out: bytes written.
    \param [in] msg Message to sign.
    \param [in] msgSz Length of msg in bytes.

    \sa wc_XmssKey_Verify
    \sa wc_XmssKey_SigsLeft
    \sa wc_XmssKey_SetWriteCb
*/
int wc_XmssKey_Sign(XmssKey* key, byte* sig, word32* sigSz, const byte* msg,
    int msgSz);

/*!
    \ingroup XMSS

    \brief Returns the number of one-time signatures still available
    from this key. When the count reaches zero the key can no longer
    sign and should be retired.

    \return Non-negative number of remaining signatures on success.
    \return Negative error code on failure (e.g. BAD_FUNC_ARG if key
    is NULL).

    \param [in,out] key Pointer to an XmssKey in state
    WC_XMSS_STATE_OK.

    \sa wc_XmssKey_Sign
*/
int wc_XmssKey_SigsLeft(XmssKey* key);

/*!
    \ingroup XMSS

    \brief Releases resources held by an XmssKey. Safe to call with a
    NULL pointer. After this call the key is in state
    WC_XMSS_STATE_FREED and must be re-initialized before reuse.

    \param [in,out] key Pointer to the XmssKey to free.

    \sa wc_XmssKey_Init
*/
void wc_XmssKey_Free(XmssKey* key);

/*!
    \ingroup XMSS

    \brief Copies the public part of keySrc into keyDst. The
    destination key inherits the same parameter set and may be used
    for verification; it does not carry the private key state and
    cannot sign. Useful for handing a verifier the minimal data it
    needs.

    \return 0 on success.
    \return BAD_FUNC_ARG if keyDst or keySrc is NULL.

    \param [in,out] keyDst Pointer to an initialized destination
    XmssKey.
    \param [in] keySrc Pointer to an XmssKey with the public key.

    \sa wc_XmssKey_ExportPub_ex
    \sa wc_XmssKey_ExportPubRaw
*/
int wc_XmssKey_ExportPub(XmssKey* keyDst, const XmssKey* keySrc);

/*!
    \ingroup XMSS

    \brief Like wc_XmssKey_ExportPub() but the destination key is
    initialized fresh with the supplied heap and devId.

    \return 0 on success.
    \return BAD_FUNC_ARG if keyDst or keySrc is NULL.

    \param [in,out] keyDst Pointer to an XmssKey to populate.
    \param [in] keySrc Pointer to an XmssKey with the public key.
    \param [in] heap Heap hint for keyDst.
    \param [in] devId Device identifier for keyDst.

    \sa wc_XmssKey_ExportPub
*/
int wc_XmssKey_ExportPub_ex(XmssKey* keyDst, const XmssKey* keySrc,
    void* heap, int devId);

/*!
    \ingroup XMSS

    \brief Exports the XMSS/XMSS^MT public key as a raw byte string.
    On entry *outLen is the size of out; on success it is updated to
    the bytes written.

    \return 0 on success.
    \return BAD_FUNC_ARG if any required pointer is NULL.
    \return BUFFER_E if *outLen is smaller than the public key size.

    \param [in] key Pointer to an XmssKey.
    \param [out] out Buffer that receives the public key.
    \param [in,out] outLen In: size of out. Out: bytes written.

    \sa wc_XmssKey_ImportPubRaw
    \sa wc_XmssKey_GetPubLen
*/
int wc_XmssKey_ExportPubRaw(const XmssKey* key, byte* out, word32* outLen);

/*!
    \ingroup XMSS

    \brief Imports a raw XMSS public key into key. The key must be in
    state WC_XMSS_STATE_INITED and the parameter set must already be
    selected (the raw encoding does NOT carry the parameter set, so
    the caller must apply it via wc_XmssKey_SetParamStr() first). On
    success the key transitions to state WC_XMSS_STATE_VERIFYONLY.

    \return 0 on success.
    \return BAD_FUNC_ARG if any required pointer is NULL.
    \return BUFFER_E if inLen does not match the expected public key
    size.

    \param [in,out] key Pointer to an XmssKey with a parameter set.
    \param [in] in Raw public key bytes.
    \param [in] inLen Length of in in bytes.

    \sa wc_XmssKey_ImportPubRaw_ex
    \sa wc_XmssKey_ExportPubRaw
    \sa wc_XmssKey_Verify
*/
int wc_XmssKey_ImportPubRaw(XmssKey* key, const byte* in, word32 inLen);

/*!
    \ingroup XMSS

    \brief Like wc_XmssKey_ImportPubRaw() but explicitly declares
    whether the encoded key is single-tree XMSS or multi-tree XMSS^MT
    (pass non-zero for XMSS^MT, zero for XMSS).

    \return 0 on success.
    \return BAD_FUNC_ARG if any required pointer is NULL.
    \return BUFFER_E if inLen does not match the expected public key
    size.

    \param [in,out] key Pointer to an XmssKey with a parameter set.
    \param [in] in Raw public key bytes.
    \param [in] inLen Length of in in bytes.
    \param [in] is_xmssmt Non-zero if the key is XMSS^MT, zero if
    plain XMSS.

    \sa wc_XmssKey_ImportPubRaw
*/
int wc_XmssKey_ImportPubRaw_ex(XmssKey* key, const byte* in, word32 inLen,
    int is_xmssmt);

/*!
    \ingroup XMSS

    \brief Verifies an XMSS/XMSS^MT signature against msg using the
    public key held in key. The function returns 0 only when the
    signature is valid; any other value indicates the signature was
    rejected.

    \return 0 on a valid signature.
    \return BAD_FUNC_ARG if any required pointer is NULL.
    \return SIG_VERIFY_E (or similar) if the signature is invalid or
    malformed.

    \param [in,out] key Pointer to an XmssKey with the public key.
    \param [in] sig Signature bytes to verify.
    \param [in] sigSz Length of sig in bytes.
    \param [in] msg Message that was signed.
    \param [in] msgSz Length of msg in bytes.

    \sa wc_XmssKey_Sign
    \sa wc_XmssKey_ImportPubRaw
*/
int wc_XmssKey_Verify(XmssKey* key, const byte* sig, word32 sigSz,
    const byte* msg, int msgSz);
