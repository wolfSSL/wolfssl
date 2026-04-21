/*!
    \ingroup SHE
    \brief Initialize a SHE context with a heap hint and device ID.

    \return 0 on success
    \return BAD_FUNC_ARG if she is NULL

    \param she pointer to a wc_SHE structure to initialize
    \param heap heap hint for internal allocations, or NULL
    \param devId crypto callback device ID, or INVALID_DEVID for
    software-only operation

    _Example_
    \code
    wc_SHE she;
    int ret;
    ret = wc_SHE_Init(&she, NULL, INVALID_DEVID);
    if (ret == 0) {
        // use she context
    }
    wc_SHE_Free(&she);
    \endcode

    \sa wc_SHE_Init_Id
    \sa wc_SHE_Init_Label
    \sa wc_SHE_Free
*/
int wc_SHE_Init(wc_SHE* she, void* heap, int devId);

/*!
    \ingroup SHE
    \brief Initialize a SHE context with an opaque hardware key identifier.
    Useful when using crypto callbacks and additional info needs to be
    attached to the SHE context to determine slot or key group information.

    \return 0 on success
    \return BAD_FUNC_ARG if she is NULL, id is NULL when len > 0, or
    len exceeds WC_SHE_MAX_ID_LEN

    \param she pointer to a wc_SHE structure to initialize
    \param id opaque key identifier bytes
    \param len length of id in bytes (0 to WC_SHE_MAX_ID_LEN)
    \param heap heap hint for internal allocations, or NULL
    \param devId crypto callback device ID

    _Example_
    \code
    wc_SHE she;
    unsigned char myId[] = { 0x01, 0x02, 0x03 };
    int ret;
    ret = wc_SHE_Init_Id(&she, myId, sizeof(myId), NULL, myDevId);
    \endcode

    \sa wc_SHE_Init
    \sa wc_SHE_Init_Label
    \sa wc_SHE_Free
*/
int wc_SHE_Init_Id(wc_SHE* she, unsigned char* id, int len,
                    void* heap, int devId);

/*!
    \ingroup SHE
    \brief Initialize a SHE context with a human-readable key label.
    Useful when using crypto callbacks and additional info needs to be
    attached to the SHE context to determine slot or key group information.

    \return 0 on success
    \return BAD_FUNC_ARG if she or label is NULL, or label length exceeds
    WC_SHE_MAX_LABEL_LEN

    \param she pointer to a wc_SHE structure to initialize
    \param label NUL-terminated key label string
    \param heap heap hint for internal allocations, or NULL
    \param devId crypto callback device ID

    _Example_
    \code
    wc_SHE she;
    int ret;
    ret = wc_SHE_Init_Label(&she, "ecu-master-key", NULL, myDevId);
    \endcode

    \sa wc_SHE_Init
    \sa wc_SHE_Init_Id
    \sa wc_SHE_Free
*/
int wc_SHE_Init_Label(wc_SHE* she, const char* label,
                       void* heap, int devId);

/*!
    \ingroup SHE
    \brief Scrub all data and zero the SHE context. Safe to call on a
    NULL pointer.

    \param she pointer to a wc_SHE structure, or NULL

    _Example_
    \code
    wc_SHE she;
    wc_SHE_Init(&she, NULL, INVALID_DEVID);
    // ... use context ...
    wc_SHE_Free(&she);
    \endcode

    \sa wc_SHE_Init
*/
void wc_SHE_Free(wc_SHE* she);

/*!
    \ingroup SHE
    \brief Retrieve the UID from hardware via a crypto callback.
    Requires WOLF_CRYPTO_CB and that NO_WC_SHE_GETUID is not defined.

    \return 0 on success
    \return BAD_FUNC_ARG if she, uid, or uidSz is invalid
    \return CRYPTOCB_UNAVAILABLE if no callback is registered

    \param she initialized SHE context
    \param uid buffer to receive the 15-byte (120-bit) SHE UID
    \param uidSz size of uid buffer in bytes (must be >= WC_SHE_UID_SZ)
    \param ctx read-only caller context passed to the callback (e.g.
    challenge buffer, HSM handle)

    _Example_
    \code
    byte uid[WC_SHE_UID_SZ];
    int ret;
    ret = wc_SHE_GetUID(&she, uid, sizeof(uid), NULL);
    \endcode

    \sa wc_SHE_GetCounter
*/
int wc_SHE_GetUID(wc_SHE* she, byte* uid, word32 uidSz,
                   const void* ctx);

/*!
    \ingroup SHE
    \brief Retrieve the monotonic counter value from hardware via a crypto
    callback. The SHE spec uses a 28-bit counter. The caller should
    increment this value before passing to GenerateM1M2M3 or GenerateM4M5.
    Requires WOLF_CRYPTO_CB and that NO_WC_SHE_GETCOUNTER is not defined.

    \return 0 on success
    \return BAD_FUNC_ARG if she or counter is NULL
    \return CRYPTOCB_UNAVAILABLE if no callback is registered

    \param she initialized SHE context
    \param counter pointer to receive the current counter value
    \param ctx read-only caller context passed to the callback

    _Example_
    \code
    word32 counter;
    int ret;
    ret = wc_SHE_GetCounter(&she, &counter, NULL);
    \endcode

    \sa wc_SHE_GetUID
*/
int wc_SHE_GetCounter(wc_SHE* she, word32* counter,
                       const void* ctx);

/*!
    \ingroup SHE
    \brief Set custom KDF constants used in Miyaguchi-Preneel key derivation.
    Defaults are KEY_UPDATE_ENC_C and KEY_UPDATE_MAC_C from the SHE spec.
    Either pointer may be NULL to leave that constant unchanged.
    Requires WOLFSSL_SHE_EXTENDED.

    \return 0 on success
    \return BAD_FUNC_ARG if she is NULL or sizes are not WC_SHE_KEY_SZ
    when corresponding pointer is non-NULL

    \param she initialized SHE context
    \param encC 16-byte encryption derivation constant (CENC), or NULL
    \param encCSz must be WC_SHE_KEY_SZ (16) when encC is non-NULL
    \param macC 16-byte MAC derivation constant (CMAC), or NULL
    \param macCSz must be WC_SHE_KEY_SZ (16) when macC is non-NULL

    _Example_
    \code
    byte myEncC[WC_SHE_KEY_SZ] = { ... };
    byte myMacC[WC_SHE_KEY_SZ] = { ... };
    int ret;
    ret = wc_SHE_SetKdfConstants(&she, myEncC, WC_SHE_KEY_SZ,
                                  myMacC, WC_SHE_KEY_SZ);
    \endcode

    \sa wc_SHE_SetM2Header
    \sa wc_SHE_SetM4Header
    \sa wc_SHE_GenerateM1M2M3
*/
int wc_SHE_SetKdfConstants(wc_SHE* she,
                            const byte* encC, word32 encCSz,
                            const byte* macC, word32 macCSz);

/*!
    \ingroup SHE
    \brief Override the M2 cleartext header (first 16 bytes of M2 before
    encryption). When set, GenerateM1M2M3 uses this instead of auto-building
    from counter and flags. Requires WOLFSSL_SHE_EXTENDED.

    \return 0 on success
    \return BAD_FUNC_ARG if she or header is NULL, or headerSz is not
    WC_SHE_KEY_SZ

    \param she initialized SHE context
    \param header 16-byte cleartext header block
    \param headerSz must be WC_SHE_KEY_SZ (16)

    _Example_
    \code
    byte header[WC_SHE_KEY_SZ] = { ... };
    int ret;
    ret = wc_SHE_SetM2Header(&she, header, WC_SHE_KEY_SZ);
    \endcode

    \sa wc_SHE_SetKdfConstants
    \sa wc_SHE_SetM4Header
    \sa wc_SHE_GenerateM1M2M3
*/
int wc_SHE_SetM2Header(wc_SHE* she,
                        const byte* header, word32 headerSz);

/*!
    \ingroup SHE
    \brief Override the M4 cleartext counter block (16-byte block encrypted
    with K3). When set, GenerateM4M5 uses this instead of auto-building from
    counter. Requires WOLFSSL_SHE_EXTENDED.

    \return 0 on success
    \return BAD_FUNC_ARG if she or header is NULL, or headerSz is not
    WC_SHE_KEY_SZ

    \param she initialized SHE context
    \param header 16-byte cleartext counter block
    \param headerSz must be WC_SHE_KEY_SZ (16)

    _Example_
    \code
    byte header[WC_SHE_KEY_SZ] = { ... };
    int ret;
    ret = wc_SHE_SetM4Header(&she, header, WC_SHE_KEY_SZ);
    \endcode

    \sa wc_SHE_SetKdfConstants
    \sa wc_SHE_SetM2Header
    \sa wc_SHE_GenerateM4M5
*/
int wc_SHE_SetM4Header(wc_SHE* she,
                        const byte* header, word32 headerSz);

/*!
    \ingroup SHE
    \brief Import externally-provided M1/M2/M3 into the SHE context.
    Sets the generated flag so the callback for GenerateM4M5 can read
    M1/M2/M3 from the context to send to hardware. Requires WOLF_CRYPTO_CB
    and that NO_WC_SHE_IMPORT_M123 is not defined.

    \return 0 on success
    \return BAD_FUNC_ARG if she is NULL or any message size is incorrect

    \param she initialized SHE context
    \param m1 16-byte M1 message (UID | KeyID | AuthID)
    \param m1Sz must be WC_SHE_M1_SZ (16)
    \param m2 32-byte M2 message (encrypted counter|flags|pad|newkey)
    \param m2Sz must be WC_SHE_M2_SZ (32)
    \param m3 16-byte M3 message (CMAC over M1|M2)
    \param m3Sz must be WC_SHE_M3_SZ (16)

    _Example_
    \code
    int ret;
    ret = wc_SHE_ImportM1M2M3(&she,
              m1, WC_SHE_M1_SZ,
              m2, WC_SHE_M2_SZ,
              m3, WC_SHE_M3_SZ);
    \endcode

    \sa wc_SHE_GenerateM1M2M3
    \sa wc_SHE_GenerateM4M5
    \sa wc_SHE_LoadKey
*/
int wc_SHE_ImportM1M2M3(wc_SHE* she,
                          const byte* m1, word32 m1Sz,
                          const byte* m2, word32 m2Sz,
                          const byte* m3, word32 m3Sz);

/*!
    \ingroup SHE
    \brief Generate SHE key update messages M1, M2, and M3 and write them
    to caller-provided buffers. Uses Miyaguchi-Preneel AES-128 KDF to
    derive K1 and K2 from the authorizing key, AES-CBC to encrypt the
    new key (M2), and AES-CMAC for authentication (M3).

    \return 0 on success
    \return BAD_FUNC_ARG if any required pointer is NULL or sizes are
    incorrect

    \param she initialized SHE context
    \param uid 15-byte SHE UID (120-bit ECU/module identifier)
    \param uidSz must be WC_SHE_UID_SZ (15)
    \param authKeyId slot ID of the authorizing key (0-14)
    \param authKey 16-byte value of the authorizing key
    \param authKeySz must be WC_SHE_KEY_SZ (16)
    \param targetKeyId slot ID of the key being loaded (1-14)
    \param newKey 16-byte value of the new key to load
    \param newKeySz must be WC_SHE_KEY_SZ (16)
    \param counter 28-bit monotonic counter value (must be strictly greater
    than the counter stored in the target slot)
    \param flags key protection flags (lower 4 bits)
    \param m1 output buffer for M1 (16 bytes)
    \param m1Sz size of m1 buffer, must be >= WC_SHE_M1_SZ
    \param m2 output buffer for M2 (32 bytes)
    \param m2Sz size of m2 buffer, must be >= WC_SHE_M2_SZ
    \param m3 output buffer for M3 (16 bytes)
    \param m3Sz size of m3 buffer, must be >= WC_SHE_M3_SZ

    _Example_
    \code
    byte m1[WC_SHE_M1_SZ], m2[WC_SHE_M2_SZ], m3[WC_SHE_M3_SZ];
    int ret;
    ret = wc_SHE_GenerateM1M2M3(&she,
              uid, WC_SHE_UID_SZ,
              authKeyId, authKey, WC_SHE_KEY_SZ,
              targetKeyId, newKey, WC_SHE_KEY_SZ,
              counter, flags,
              m1, WC_SHE_M1_SZ,
              m2, WC_SHE_M2_SZ,
              m3, WC_SHE_M3_SZ);
    \endcode

    \sa wc_SHE_GenerateM4M5
    \sa wc_SHE_ImportM1M2M3
    \sa wc_SHE_LoadKey
*/
int wc_SHE_GenerateM1M2M3(wc_SHE* she,
                      const byte* uid, word32 uidSz,
                      byte authKeyId, const byte* authKey, word32 authKeySz,
                      byte targetKeyId, const byte* newKey, word32 newKeySz,
                      word32 counter, byte flags,
                      byte* m1, word32 m1Sz,
                      byte* m2, word32 m2Sz,
                      byte* m3, word32 m3Sz);

/*!
    \ingroup SHE
    \brief Generate SHE verification messages M4 and M5 and write them to
    caller-provided buffers. Uses Miyaguchi-Preneel AES-128 KDF to derive
    K3 and K4 from the new key, AES-ECB for the M4 counter block, and
    AES-CMAC for M5. Independent of M1/M2/M3 and can be called on a
    separate context.

    \return 0 on success
    \return BAD_FUNC_ARG if any required pointer is NULL or sizes are
    incorrect

    \param she initialized SHE context
    \param uid 15-byte SHE UID (same UID used for M1)
    \param uidSz must be WC_SHE_UID_SZ (15)
    \param authKeyId slot ID of the authorizing key (same as in M1)
    \param targetKeyId slot ID of the key being loaded (same as in M1)
    \param newKey 16-byte value of the new key
    \param newKeySz must be WC_SHE_KEY_SZ (16)
    \param counter 28-bit monotonic counter (same value as in M2)
    \param m4 output buffer for M4 (32 bytes)
    \param m4Sz size of m4 buffer, must be >= WC_SHE_M4_SZ
    \param m5 output buffer for M5 (16 bytes)
    \param m5Sz size of m5 buffer, must be >= WC_SHE_M5_SZ

    _Example_
    \code
    byte m4[WC_SHE_M4_SZ], m5[WC_SHE_M5_SZ];
    int ret;
    ret = wc_SHE_GenerateM4M5(&she,
              uid, WC_SHE_UID_SZ,
              authKeyId, targetKeyId,
              newKey, WC_SHE_KEY_SZ,
              counter,
              m4, WC_SHE_M4_SZ,
              m5, WC_SHE_M5_SZ);
    \endcode

    \sa wc_SHE_GenerateM1M2M3
    \sa wc_SHE_LoadKey_Verify
*/
int wc_SHE_GenerateM4M5(wc_SHE* she,
                      const byte* uid, word32 uidSz,
                      byte authKeyId, byte targetKeyId,
                      const byte* newKey, word32 newKeySz,
                      word32 counter,
                      byte* m4, word32 m4Sz,
                      byte* m5, word32 m5Sz);

/*!
    \ingroup SHE
    \brief One-shot convenience wrapper: Init, ImportM1M2M3, GenerateM4M5
    (via callback), Free. Dispatches to a hardware crypto callback that
    sends M1/M2/M3 to the HSM and returns M4/M5. Requires a valid devId
    (not INVALID_DEVID). Define NO_WC_SHE_LOADKEY to compile out.

    \return 0 on success
    \return BAD_FUNC_ARG if any required pointer is NULL or sizes are
    incorrect

    \param heap heap hint for internal allocations, or NULL
    \param devId crypto callback device ID (must not be INVALID_DEVID)
    \param m1 16-byte M1 input message
    \param m1Sz must be WC_SHE_M1_SZ (16)
    \param m2 32-byte M2 input message
    \param m2Sz must be WC_SHE_M2_SZ (32)
    \param m3 16-byte M3 input message
    \param m3Sz must be WC_SHE_M3_SZ (16)
    \param m4 output buffer for M4 (32 bytes)
    \param m4Sz size of m4 buffer, must be >= WC_SHE_M4_SZ
    \param m5 output buffer for M5 (16 bytes)
    \param m5Sz size of m5 buffer, must be >= WC_SHE_M5_SZ

    _Example_
    \code
    byte m4[WC_SHE_M4_SZ], m5[WC_SHE_M5_SZ];
    int ret;
    ret = wc_SHE_LoadKey(NULL, myDevId,
              m1, WC_SHE_M1_SZ,
              m2, WC_SHE_M2_SZ,
              m3, WC_SHE_M3_SZ,
              m4, WC_SHE_M4_SZ,
              m5, WC_SHE_M5_SZ);
    \endcode

    \sa wc_SHE_LoadKey_Id
    \sa wc_SHE_LoadKey_Label
    \sa wc_SHE_LoadKey_Verify
    \sa wc_SHE_ImportM1M2M3
    \sa wc_SHE_GenerateM4M5
*/
int wc_SHE_LoadKey(
    void* heap, int devId,
    const byte* m1, word32 m1Sz,
    const byte* m2, word32 m2Sz,
    const byte* m3, word32 m3Sz,
    byte* m4, word32 m4Sz,
    byte* m5, word32 m5Sz);

/*!
    \ingroup SHE
    \brief One-shot Load Key with an opaque hardware key identifier.
    Same as wc_SHE_LoadKey but initializes the context with wc_SHE_Init_Id.
    Define NO_WC_SHE_LOADKEY to compile out.

    \return 0 on success
    \return BAD_FUNC_ARG if any required pointer is NULL or sizes are
    incorrect

    \param id opaque key identifier bytes
    \param idLen length of id in bytes
    \param heap heap hint for internal allocations, or NULL
    \param devId crypto callback device ID (must not be INVALID_DEVID)
    \param m1 16-byte M1 input message
    \param m1Sz must be WC_SHE_M1_SZ (16)
    \param m2 32-byte M2 input message
    \param m2Sz must be WC_SHE_M2_SZ (32)
    \param m3 16-byte M3 input message
    \param m3Sz must be WC_SHE_M3_SZ (16)
    \param m4 output buffer for M4 (32 bytes)
    \param m4Sz size of m4 buffer, must be >= WC_SHE_M4_SZ
    \param m5 output buffer for M5 (16 bytes)
    \param m5Sz size of m5 buffer, must be >= WC_SHE_M5_SZ

    _Example_
    \code
    byte m4[WC_SHE_M4_SZ], m5[WC_SHE_M5_SZ];
    unsigned char keyId[] = { 0x01, 0x02 };
    int ret;
    ret = wc_SHE_LoadKey_Id(keyId, sizeof(keyId), NULL, myDevId,
              m1, WC_SHE_M1_SZ,
              m2, WC_SHE_M2_SZ,
              m3, WC_SHE_M3_SZ,
              m4, WC_SHE_M4_SZ,
              m5, WC_SHE_M5_SZ);
    \endcode

    \sa wc_SHE_LoadKey
    \sa wc_SHE_LoadKey_Label
    \sa wc_SHE_LoadKey_Verify_Id
*/
int wc_SHE_LoadKey_Id(
    unsigned char* id, int idLen,
    void* heap, int devId,
    const byte* m1, word32 m1Sz,
    const byte* m2, word32 m2Sz,
    const byte* m3, word32 m3Sz,
    byte* m4, word32 m4Sz,
    byte* m5, word32 m5Sz);

/*!
    \ingroup SHE
    \brief One-shot Load Key with a human-readable key label.
    Same as wc_SHE_LoadKey but initializes the context with
    wc_SHE_Init_Label. Define NO_WC_SHE_LOADKEY to compile out.

    \return 0 on success
    \return BAD_FUNC_ARG if any required pointer is NULL or sizes are
    incorrect

    \param label NUL-terminated key label string
    \param heap heap hint for internal allocations, or NULL
    \param devId crypto callback device ID (must not be INVALID_DEVID)
    \param m1 16-byte M1 input message
    \param m1Sz must be WC_SHE_M1_SZ (16)
    \param m2 32-byte M2 input message
    \param m2Sz must be WC_SHE_M2_SZ (32)
    \param m3 16-byte M3 input message
    \param m3Sz must be WC_SHE_M3_SZ (16)
    \param m4 output buffer for M4 (32 bytes)
    \param m4Sz size of m4 buffer, must be >= WC_SHE_M4_SZ
    \param m5 output buffer for M5 (16 bytes)
    \param m5Sz size of m5 buffer, must be >= WC_SHE_M5_SZ

    _Example_
    \code
    byte m4[WC_SHE_M4_SZ], m5[WC_SHE_M5_SZ];
    int ret;
    ret = wc_SHE_LoadKey_Label("ecu-master", NULL, myDevId,
              m1, WC_SHE_M1_SZ,
              m2, WC_SHE_M2_SZ,
              m3, WC_SHE_M3_SZ,
              m4, WC_SHE_M4_SZ,
              m5, WC_SHE_M5_SZ);
    \endcode

    \sa wc_SHE_LoadKey
    \sa wc_SHE_LoadKey_Id
    \sa wc_SHE_LoadKey_Verify_Label
*/
int wc_SHE_LoadKey_Label(
    const char* label,
    void* heap, int devId,
    const byte* m1, word32 m1Sz,
    const byte* m2, word32 m2Sz,
    const byte* m3, word32 m3Sz,
    byte* m4, word32 m4Sz,
    byte* m5, word32 m5Sz);

/*!
    \ingroup SHE
    \brief One-shot Load Key with M4/M5 verification. Same as wc_SHE_LoadKey
    but also compares the M4/M5 returned by the HSM against caller-provided
    expected values using constant-time comparison. Returns SIG_VERIFY_E on
    mismatch. The actual M4/M5 are still written to the output buffers on
    failure. Define NO_WC_SHE_LOADKEY to compile out.

    \return 0 on success
    \return SIG_VERIFY_E if M4/M5 do not match expected values
    \return BAD_FUNC_ARG if any required pointer is NULL or sizes are
    incorrect

    \param heap heap hint for internal allocations, or NULL
    \param devId crypto callback device ID (must not be INVALID_DEVID)
    \param m1 16-byte M1 input message
    \param m1Sz must be WC_SHE_M1_SZ (16)
    \param m2 32-byte M2 input message
    \param m2Sz must be WC_SHE_M2_SZ (32)
    \param m3 16-byte M3 input message
    \param m3Sz must be WC_SHE_M3_SZ (16)
    \param m4 output buffer for M4 (32 bytes)
    \param m4Sz size of m4 buffer, must be >= WC_SHE_M4_SZ
    \param m5 output buffer for M5 (16 bytes)
    \param m5Sz size of m5 buffer, must be >= WC_SHE_M5_SZ
    \param m4Expected expected M4 verification message to compare against
    \param m4ExpectedSz must be WC_SHE_M4_SZ (32)
    \param m5Expected expected M5 verification message to compare against
    \param m5ExpectedSz must be WC_SHE_M5_SZ (16)

    _Example_
    \code
    byte m4[WC_SHE_M4_SZ], m5[WC_SHE_M5_SZ];
    int ret;
    ret = wc_SHE_LoadKey_Verify(NULL, myDevId,
              m1, WC_SHE_M1_SZ,
              m2, WC_SHE_M2_SZ,
              m3, WC_SHE_M3_SZ,
              m4, WC_SHE_M4_SZ,
              m5, WC_SHE_M5_SZ,
              expectedM4, WC_SHE_M4_SZ,
              expectedM5, WC_SHE_M5_SZ);
    if (ret == SIG_VERIFY_E) {
        // M4/M5 mismatch
    }
    \endcode

    \sa wc_SHE_LoadKey
    \sa wc_SHE_LoadKey_Verify_Id
    \sa wc_SHE_LoadKey_Verify_Label
*/
int wc_SHE_LoadKey_Verify(
    void* heap, int devId,
    const byte* m1, word32 m1Sz,
    const byte* m2, word32 m2Sz,
    const byte* m3, word32 m3Sz,
    byte* m4, word32 m4Sz,
    byte* m5, word32 m5Sz,
    const byte* m4Expected, word32 m4ExpectedSz,
    const byte* m5Expected, word32 m5ExpectedSz);

/*!
    \ingroup SHE
    \brief One-shot Load Key with opaque key identifier and M4/M5
    verification. Combines wc_SHE_LoadKey_Id and wc_SHE_LoadKey_Verify.
    Define NO_WC_SHE_LOADKEY to compile out.

    \return 0 on success
    \return SIG_VERIFY_E if M4/M5 do not match expected values
    \return BAD_FUNC_ARG if any required pointer is NULL or sizes are
    incorrect

    \param id opaque key identifier bytes
    \param idLen length of id in bytes
    \param heap heap hint for internal allocations, or NULL
    \param devId crypto callback device ID (must not be INVALID_DEVID)
    \param m1 16-byte M1 input message
    \param m1Sz must be WC_SHE_M1_SZ (16)
    \param m2 32-byte M2 input message
    \param m2Sz must be WC_SHE_M2_SZ (32)
    \param m3 16-byte M3 input message
    \param m3Sz must be WC_SHE_M3_SZ (16)
    \param m4 output buffer for M4 (32 bytes)
    \param m4Sz size of m4 buffer, must be >= WC_SHE_M4_SZ
    \param m5 output buffer for M5 (16 bytes)
    \param m5Sz size of m5 buffer, must be >= WC_SHE_M5_SZ
    \param m4Expected expected M4 verification message
    \param m4ExpectedSz must be WC_SHE_M4_SZ (32)
    \param m5Expected expected M5 verification message
    \param m5ExpectedSz must be WC_SHE_M5_SZ (16)

    _Example_
    \code
    byte m4[WC_SHE_M4_SZ], m5[WC_SHE_M5_SZ];
    unsigned char keyId[] = { 0x01, 0x02 };
    int ret;
    ret = wc_SHE_LoadKey_Verify_Id(keyId, sizeof(keyId), NULL, myDevId,
              m1, WC_SHE_M1_SZ, m2, WC_SHE_M2_SZ, m3, WC_SHE_M3_SZ,
              m4, WC_SHE_M4_SZ, m5, WC_SHE_M5_SZ,
              expectedM4, WC_SHE_M4_SZ, expectedM5, WC_SHE_M5_SZ);
    \endcode

    \sa wc_SHE_LoadKey_Id
    \sa wc_SHE_LoadKey_Verify
    \sa wc_SHE_LoadKey_Verify_Label
*/
int wc_SHE_LoadKey_Verify_Id(
    unsigned char* id, int idLen,
    void* heap, int devId,
    const byte* m1, word32 m1Sz,
    const byte* m2, word32 m2Sz,
    const byte* m3, word32 m3Sz,
    byte* m4, word32 m4Sz,
    byte* m5, word32 m5Sz,
    const byte* m4Expected, word32 m4ExpectedSz,
    const byte* m5Expected, word32 m5ExpectedSz);

/*!
    \ingroup SHE
    \brief One-shot Load Key with key label and M4/M5 verification.
    Combines wc_SHE_LoadKey_Label and wc_SHE_LoadKey_Verify.
    Define NO_WC_SHE_LOADKEY to compile out.

    \return 0 on success
    \return SIG_VERIFY_E if M4/M5 do not match expected values
    \return BAD_FUNC_ARG if any required pointer is NULL or sizes are
    incorrect

    \param label NUL-terminated key label string
    \param heap heap hint for internal allocations, or NULL
    \param devId crypto callback device ID (must not be INVALID_DEVID)
    \param m1 16-byte M1 input message
    \param m1Sz must be WC_SHE_M1_SZ (16)
    \param m2 32-byte M2 input message
    \param m2Sz must be WC_SHE_M2_SZ (32)
    \param m3 16-byte M3 input message
    \param m3Sz must be WC_SHE_M3_SZ (16)
    \param m4 output buffer for M4 (32 bytes)
    \param m4Sz size of m4 buffer, must be >= WC_SHE_M4_SZ
    \param m5 output buffer for M5 (16 bytes)
    \param m5Sz size of m5 buffer, must be >= WC_SHE_M5_SZ
    \param m4Expected expected M4 verification message
    \param m4ExpectedSz must be WC_SHE_M4_SZ (32)
    \param m5Expected expected M5 verification message
    \param m5ExpectedSz must be WC_SHE_M5_SZ (16)

    _Example_
    \code
    byte m4[WC_SHE_M4_SZ], m5[WC_SHE_M5_SZ];
    int ret;
    ret = wc_SHE_LoadKey_Verify_Label("ecu-master", NULL, myDevId,
              m1, WC_SHE_M1_SZ, m2, WC_SHE_M2_SZ, m3, WC_SHE_M3_SZ,
              m4, WC_SHE_M4_SZ, m5, WC_SHE_M5_SZ,
              expectedM4, WC_SHE_M4_SZ, expectedM5, WC_SHE_M5_SZ);
    \endcode

    \sa wc_SHE_LoadKey_Label
    \sa wc_SHE_LoadKey_Verify
    \sa wc_SHE_LoadKey_Verify_Id
*/
int wc_SHE_LoadKey_Verify_Label(
    const char* label,
    void* heap, int devId,
    const byte* m1, word32 m1Sz,
    const byte* m2, word32 m2Sz,
    const byte* m3, word32 m3Sz,
    byte* m4, word32 m4Sz,
    byte* m5, word32 m5Sz,
    const byte* m4Expected, word32 m4ExpectedSz,
    const byte* m5Expected, word32 m5ExpectedSz);

/*!
    \ingroup SHE
    \brief Export a key from hardware in SHE loadable format (M1-M5).
    Some HSMs allow exporting certain key slots (e.g. RAM key) so they
    can be re-loaded later via the SHE key update protocol. Requires
    WOLF_CRYPTO_CB and that NO_WC_SHE_EXPORTKEY is not defined. Any
    output buffer may be NULL to skip that message.

    \return 0 on success
    \return BAD_FUNC_ARG if she is NULL
    \return CRYPTOCB_UNAVAILABLE if no callback is registered

    \param she initialized SHE context
    \param m1 output buffer for M1 (16 bytes), or NULL to skip
    \param m1Sz size of m1 buffer
    \param m2 output buffer for M2 (32 bytes), or NULL to skip
    \param m2Sz size of m2 buffer
    \param m3 output buffer for M3 (16 bytes), or NULL to skip
    \param m3Sz size of m3 buffer
    \param m4 output buffer for M4 (32 bytes), or NULL to skip
    \param m4Sz size of m4 buffer
    \param m5 output buffer for M5 (16 bytes), or NULL to skip
    \param m5Sz size of m5 buffer
    \param ctx read-only caller context passed to the callback

    _Example_
    \code
    byte m1[WC_SHE_M1_SZ], m2[WC_SHE_M2_SZ], m3[WC_SHE_M3_SZ];
    byte m4[WC_SHE_M4_SZ], m5[WC_SHE_M5_SZ];
    int ret;
    ret = wc_SHE_ExportKey(&she,
              m1, WC_SHE_M1_SZ,
              m2, WC_SHE_M2_SZ,
              m3, WC_SHE_M3_SZ,
              m4, WC_SHE_M4_SZ,
              m5, WC_SHE_M5_SZ,
              NULL);
    \endcode

    \sa wc_SHE_ImportM1M2M3
    \sa wc_SHE_LoadKey
*/
int wc_SHE_ExportKey(wc_SHE* she,
                      byte* m1, word32 m1Sz,
                      byte* m2, word32 m2Sz,
                      byte* m3, word32 m3Sz,
                      byte* m4, word32 m4Sz,
                      byte* m5, word32 m5Sz,
                      const void* ctx);

/*!
    \ingroup SHE
    \brief Miyaguchi-Preneel AES-128 one-way compression function.
    H_0 = 0, H_i = E_{H_{i-1}}(M_i) XOR M_i XOR H_{i-1}.
    Only valid for AES-128 where key size equals block size.
    This is an internal function exposed for testing purposes.

    \return 0 on success
    \return BAD_FUNC_ARG if any pointer is NULL

    \param aes caller-owned, already-initialized Aes structure
    \param in input data (e.g. BaseKey || KDF_Constant, 32 bytes)
    \param inSz length of input in bytes (zero-padded to block boundary)
    \param out output buffer for 16-byte compressed result

    _Example_
    \code
    Aes aes;
    byte input[32] = { ... };
    byte output[WC_SHE_KEY_SZ];
    int ret;
    wc_AesInit(&aes, NULL, INVALID_DEVID);
    ret = wc_SHE_AesMp16(&aes, input, sizeof(input), output);
    wc_AesFree(&aes);
    \endcode

    \sa wc_SHE_GenerateM1M2M3
    \sa wc_SHE_GenerateM4M5
*/
int wc_SHE_AesMp16(Aes* aes, const byte* in, word32 inSz,
                     byte* out);
