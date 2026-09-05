/*!
    \ingroup KeyStore
    \brief Place plaintext key material into a device's key store. This is the
    counterpart to wc_KeyStore_ImportWrapped for devices that accept a key in
    the clear; a device holding keys that may never appear in plaintext
    declines it and offers only the wrapped form.

    keyType says what the material is for, which is what lets the device set
    the stored key's properties: a raw byte string cannot tell an AES key from
    an HMAC key of the same length. It also fixes the encoding, so no further
    argument is needed to say: a symmetric type takes the raw key bytes, and an
    asymmetric type takes DER, a private key as PKCS#8 PrivateKeyInfo and a
    public key as SubjectPublicKeyInfo. keySz is the length of that encoding
    in bytes either way.

    The caller owns the plaintext copy and should zeroize it once the import
    succeeds, for example with ForceZero().

    Key references are opaque byte strings, interpreted only by the device.
    They are the same identifier WOLF_PRIVATE_KEY_ID uses, so the bytes that
    name a key here are the bytes wc_ecc_init_id() or wc_AesInit_Id() take to
    bind a wolfCrypt object to that key.

    attrs sits at the end of the argument list rather than beside keyRef,
    because WC_KEYSTORE_ATTR_EXPORTABLE and WC_KEYSTORE_KEY_WRAP are both 1 and
    a swap between two adjacent control words would compile cleanly.

    \return 0 on success
    \return CRYPTOCB_UNAVAILABLE if no registered device handles the operation
    \return BAD_FUNC_ARG if keyRef or key is NULL, or either size is zero

    \param devId crypto callback device ID
    \param keyRef opaque reference naming where the key should land
    \param keyRefSz length of keyRef in bytes
    \param keyType what the key is for, from enum wc_KeyStoreKeyType
    \param key plaintext key material
    \param keySz length of key in bytes
    \param attrs attributes for the key being created, WC_KEYSTORE_ATTR_*
    \param ctx read-only caller context passed through to the device

    _Example_
    \code
    byte keyRef[8];
    byte aesKey[32];

    ret = wc_KeyStore_ImportPlain(devId, keyRef, sizeof(keyRef),
                                  WC_KEYSTORE_KEY_AES, aesKey, sizeof(aesKey),
                                  WC_KEYSTORE_ATTR_PERSISTENT, NULL);
    ForceZero(aesKey, sizeof(aesKey));
    if (ret != 0) {
        // handle error
    }
    \endcode

    \sa wc_KeyStore_ExportPlain
    \sa wc_KeyStore_ImportWrapped
    \sa wc_KeyStore_Delete
*/
int wc_KeyStore_ImportPlain(int devId,
    const byte* keyRef, word32 keyRefSz,
    word32 keyType, const byte* key, word32 keySz,
    word32 attrs, const void* ctx);

/*!
    \ingroup KeyStore
    \brief Read a stored key back as plaintext. Typically requires the key to
    have been created with WC_KEYSTORE_ATTR_EXPORTABLE, and many devices refuse
    this operation entirely; wc_KeyStore_ExportWrapped is the form that keeps
    the material inside the boundary.

    The encoding matches wc_KeyStore_ImportPlain(): raw bytes for a symmetric
    key, DER for an asymmetric one. Call wc_KeyStore_GetInfo() to learn which
    the stored key is.

    keySz is in/out: the capacity of key on entry, the number of bytes written
    on return. Passing key as NULL is a size query, which returns the size the
    device would produce through keySz.

    Call wc_KeyStore_GetInfo() first to learn whether the key is exportable,
    rather than attempting the export and interpreting the failure.

    \return 0 on success
    \return CRYPTOCB_UNAVAILABLE if no registered device handles the operation
    \return BAD_FUNC_ARG if keyRef or keySz is NULL, keyRefSz is zero, or key
    is non-NULL with a zero capacity

    \param devId crypto callback device ID
    \param keyRef opaque reference naming the key to export
    \param keyRefSz length of keyRef in bytes
    \param key buffer receiving the plaintext key, or NULL to query the size
    \param keySz in: capacity of key in bytes, out: bytes written
    \param ctx read-only caller context passed through to the device

    _Example_
    \code
    byte   out[32];
    word32 outSz = sizeof(out);

    ret = wc_KeyStore_ExportPlain(devId, keyRef, sizeof(keyRef),
                                  out, &outSz, NULL);
    if (ret != 0) {
        // handle error
    }
    \endcode

    \sa wc_KeyStore_ImportPlain
    \sa wc_KeyStore_ExportWrapped
    \sa wc_KeyStore_GetInfo
*/
int wc_KeyStore_ExportPlain(int devId,
    const byte* keyRef, word32 keyRefSz,
    byte* key, word32* keySz, const void* ctx);

/*!
    \ingroup KeyStore
    \brief Unwrap a key blob directly into a device's key store. The key
    material is never plaintext on this side of the boundary: the device
    unwraps it internally and the result exists only at keyRef.

    keyType says what the wrapped key is for. A bare RFC 3394 wrap
    (WC_KEYWRAP_FORMAT_AESKW) is a pure data transformation carrying no
    metadata, so for that format keyType is the device's only source. A vendor
    container that carries its own property word stays authoritative, and
    keyType is then a cross-check the device must refuse a mismatch on, since
    a mismatch means the right blob is going into the wrong kind of slot.

    Key references are opaque byte strings, interpreted only by the device.
    They are the same identifier WOLF_PRIVATE_KEY_ID uses, so the bytes that
    name a key here are the bytes wc_ecc_init_id() or wc_AesInit_Id() take to
    bind a wolfCrypt object to that key.

    \return 0 on success
    \return CRYPTOCB_UNAVAILABLE if no registered device handles the operation
    \return BAD_FUNC_ARG if keyRef or blob is NULL, if either size is zero, or
    if wrapKeyRef is NULL with a non-zero wrapKeyRefSz

    \param devId crypto callback device ID
    \param keyRef opaque reference naming where the key should land
    \param keyRefSz length of keyRef in bytes
    \param keyType what the wrapped key is for, from enum wc_KeyStoreKeyType,
    or WC_KEYSTORE_KEY_NONE to leave it to the container
    \param wrapKeyRef opaque reference naming the wrapping key, or NULL when
    the device uses an implicit one
    \param wrapKeyRefSz length of wrapKeyRef in bytes, zero when wrapKeyRef
    is NULL
    \param format container format, from enum wc_KeyWrapFormat
    \param blob the wrapped key blob
    \param blobSz length of blob in bytes
    \param attrs WC_KEYSTORE_ATTR_* for the key being created. Used only when
    the format carries no attributes of its own; a container that carries them
    wins and this is ignored. Call wc_KeyStore_GetInfo() afterwards to confirm
    what the import actually produced
    \param ctx read-only caller context passed through to the device

    _Example_
    \code
    byte keyRef[8];
    byte kekRef[8];

    ret = wc_KeyStore_ImportWrapped(devId, keyRef, sizeof(keyRef),
                                    WC_KEYSTORE_KEY_AES,
                                    kekRef, sizeof(kekRef),
                                    WC_KEYWRAP_FORMAT_AESKW,
                                    blob, blobSz,
                                    WC_KEYSTORE_ATTR_EXPORTABLE, NULL);
    if (ret != 0) {
        // handle error
    }
    \endcode

    \sa wc_KeyStore_ExportWrapped
    \sa wc_KeyStore_Delete
*/
int wc_KeyStore_ImportWrapped(int devId,
    const byte* keyRef, word32 keyRefSz, word32 keyType,
    const byte* wrapKeyRef, word32 wrapKeyRefSz,
    word32 format, const byte* blob, word32 blobSz,
    word32 attrs, const void* ctx);

/*!
    \ingroup KeyStore
    \brief Wrap a stored key under another stored key and emit the blob.
    Typically requires the key to have been created with
    WC_KEYSTORE_ATTR_EXPORTABLE, which is irrevocable on most hardware.

    blobSz is in/out: the capacity of blob on entry, the number of bytes
    written on return. Passing blob as NULL is a size query, which returns the
    size the device would produce through blobSz.

    \return 0 on success
    \return CRYPTOCB_UNAVAILABLE if no registered device handles the operation
    \return BAD_FUNC_ARG if keyRef or blobSz is NULL, if keyRefSz is zero, if
    blob is non-NULL with a zero capacity, or if wrapKeyRef is NULL with a
    non-zero wrapKeyRefSz

    \param devId crypto callback device ID
    \param keyRef opaque reference naming the key to wrap out
    \param keyRefSz length of keyRef in bytes
    \param wrapKeyRef opaque reference naming the wrapping key, or NULL when
    the device uses an implicit one
    \param wrapKeyRefSz length of wrapKeyRef in bytes, zero when wrapKeyRef
    is NULL
    \param format container format, from enum wc_KeyWrapFormat
    \param blob buffer receiving the wrapped key, or NULL to query the size
    \param blobSz in/out capacity then length, in bytes
    \param ctx read-only caller context passed through to the device

    _Example_
    \code
    word32 blobSz = 0;

    // ask how large the container will be
    ret = wc_KeyStore_ExportWrapped(devId, keyRef, sizeof(keyRef),
                                    kekRef, sizeof(kekRef),
                                    WC_KEYWRAP_FORMAT_AESKW,
                                    NULL, &blobSz, NULL);
    \endcode

    \sa wc_KeyStore_ImportWrapped
    \sa wc_KeyStore_GetInfo
*/
int wc_KeyStore_ExportWrapped(int devId,
    const byte* keyRef, word32 keyRefSz,
    const byte* wrapKeyRef, word32 wrapKeyRefSz,
    word32 format, byte* blob, word32* blobSz, const void* ctx);

/*!
    \ingroup KeyStore
    \brief Derive a new stored key from an existing one without either key
    touching RAM.

    Nothing in a derivation says what its result is for, so keyType does. A
    device that encodes the key's purpose inside its own key references may
    treat this as a cross-check, but it must not require that, since a
    reference is opaque to wolfCrypt and need carry no such field.

    Argument order follows the rule used throughout this API: no two
    interchangeable control words sit next to each other. keyType names the key
    being created and follows its reference, kdfType precedes the derivation
    data, and attrs moves to the tail rather than sit beside keyType, since
    WC_KEYSTORE_ATTR_EXPORTABLE and WC_KEYSTORE_KEY_WRAP are both 1.

    \return 0 on success
    \return CRYPTOCB_UNAVAILABLE if no registered device handles the operation
    \return BAD_FUNC_ARG if keyRef or srcKeyRef is NULL, or a size is zero

    \param devId crypto callback device ID
    \param keyRef opaque reference naming where the derived key should land
    \param keyRefSz length of keyRef in bytes
    \param keyType what the derived key is for, from enum wc_KeyStoreKeyType,
    or WC_KEYSTORE_KEY_NONE to leave it to the device
    \param srcKeyRef opaque reference naming the derivation key
    \param srcKeyRefSz length of srcKeyRef in bytes
    \param kdfType derivation function, from enum wc_KdfType.
    WC_KDF_TYPE_NONE asks for the device's own derivation, which is all many
    key stores offer
    \param deriv derivation data
    \param derivSz length of deriv in bytes, often fixed by the hardware
    \param attrs WC_KEYSTORE_ATTR_* requested for the key being created
    \param ctx read-only caller context passed through to the device

    _Example_
    \code
    ret = wc_KeyStore_Derive(devId, keyRef, sizeof(keyRef),
                             WC_KEYSTORE_KEY_AES,
                             parentRef, sizeof(parentRef),
                             WC_KDF_TYPE_NONE, deriv, sizeof(deriv),
                             WC_KEYSTORE_ATTR_EXPORTABLE, NULL);
    \endcode

    \sa wc_KeyStore_GetInfo
*/
int wc_KeyStore_Derive(int devId,
    const byte* keyRef, word32 keyRefSz, word32 keyType,
    const byte* srcKeyRef, word32 srcKeyRefSz,
    word32 kdfType, const byte* deriv, word32 derivSz,
    word32 attrs, const void* ctx);

/*!
    \ingroup KeyStore
    \brief Destroy a stored key. Deliberately separate from
    WC_ALGO_TYPE_FREE: freeing a wolfCrypt key object must never destroy the
    hardware key it refers to.

    \return 0 on success
    \return CRYPTOCB_UNAVAILABLE if no registered device handles the operation
    \return BAD_FUNC_ARG if keyRef is NULL or keyRefSz is zero

    \param devId crypto callback device ID
    \param keyRef opaque reference naming the key to destroy
    \param keyRefSz length of keyRef in bytes
    \param ctx read-only caller context passed through to the device

    _Example_
    \code
    ret = wc_KeyStore_Delete(devId, keyRef, sizeof(keyRef), NULL);
    \endcode

    \sa wc_KeyStore_ImportWrapped
*/
int wc_KeyStore_Delete(int devId, const byte* keyRef, word32 keyRefSz,
    const void* ctx);

/*!
    \ingroup KeyStore
    \brief Report what a slot holds: key type, size in bits, and attributes.

    Any WC_KEYSTORE_ATTR_* the device can represent is reported here, so a
    caller can ask whether an export is permitted rather than attempting one
    and interpreting the failure. Attributes the device cannot represent read
    as absent, and out parameters the device does not fill are cleared rather
    than left holding the caller's stack.

    \return 0 on success
    \return CRYPTOCB_UNAVAILABLE if no registered device handles the operation
    \return BAD_FUNC_ARG if keyRef is NULL or keyRefSz is zero

    \param devId crypto callback device ID
    \param keyRef opaque reference naming the key to query
    \param keyRefSz length of keyRef in bytes
    \param keyType out, a value from enum wc_KeyStoreKeyType
    \param keySz out, key size in bits
    \param attrs out, WC_KEYSTORE_ATTR_* the key carries
    \param ctx read-only caller context passed through to the device

    _Example_
    \code
    word32 keyType = 0, keySz = 0, attrs = 0;

    ret = wc_KeyStore_GetInfo(devId, keyRef, sizeof(keyRef),
                              &keyType, &keySz, &attrs, NULL);
    if (ret == 0 && (attrs & WC_KEYSTORE_ATTR_EXPORTABLE)) {
        // the key may be wrapped out
    }
    \endcode

    \sa wc_KeyStore_ExportWrapped
    \sa wc_KeyStore_Derive
*/
int wc_KeyStore_GetInfo(int devId, const byte* keyRef, word32 keyRefSz,
    word32* keyType, word32* keySz, word32* attrs, const void* ctx);
