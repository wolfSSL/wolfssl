/*!
    \ingroup PKCS11
*/
int wc_Pkcs11_Initialize(Pkcs11Dev* dev, const char* library,
                                     void* heap);

/*!
    \ingroup PKCS11
*/
void wc_Pkcs11_Finalize(Pkcs11Dev* dev);

/*!
    \ingroup PKCS11

    \brief Sets up a token by slot id or name. A user PIN is copied into
    memory the token owns, which wc_Pkcs11Token_Final zeroizes and frees.
    Call wc_Pkcs11Token_Final before initializing the token again.
*/
int wc_Pkcs11Token_Init(Pkcs11Token* token, Pkcs11Dev* dev,
    int slotId, const char* tokenName, const unsigned char *userPin,
    int userPinSz);

/*!
    \ingroup PKCS11

    \brief Sets up a token by name. A user PIN is copied as by
    wc_Pkcs11Token_Init. Call wc_Pkcs11Token_Final before initializing the
    token again.
*/
int wc_Pkcs11Token_InitName(Pkcs11Token* token, Pkcs11Dev* dev,
    const char* tokenName, int tokenNameSz,
    const unsigned char* userPin, int userPinSz);

/*!
    \ingroup PKCS11
*/
void wc_Pkcs11Token_Final(Pkcs11Token* token);

/*!
    \ingroup PKCS11

    \brief Opens a session on the token that all later operations use, until
    wc_Pkcs11Token_Close. Without it, wc_Pkcs11StoreKey and generating a key
    with an id or label on the token return BAD_STATE_E, and a key with
    neither is generated in software.

    Calling this again while the session is open does nothing and keeps the
    session's read/write mode.

    \return 0 on success.
    \return BAD_FUNC_ARG when token is NULL.
    \return BAD_STATE_E when wc_Pkcs11Token_Open_ex discarded the PIN and its
    session was closed.
    \return WC_HW_E when opening the session or logging in fails. A session
    whose login failed is closed again.

    \param token Token to open the session on.
    \param readWrite 1 for a read-write session, 0 for read-only.

    \sa wc_Pkcs11Token_Open_ex
    \sa wc_Pkcs11Token_Close
 */
int wc_Pkcs11Token_Open(Pkcs11Token* token, int readWrite);

/*!
    \ingroup PKCS11

    \brief Opens a session as wc_Pkcs11Token_Open does. With discardPin set,
    the token's copy of the user PIN is zeroized and freed once this call has
    opened the session and logged it in, by its own login or because another
    token already logged the application in. A session that was already open
    keeps the PIN. The login then lasts while a session of the
    application is open. After wc_Pkcs11Token_Close, opening again returns
    BAD_STATE_E until wc_Pkcs11Token_Final and a new init with the PIN, and
    operations open sessions without logging in. Discarding the PIN is not
    safe while other threads use the token.

    \return 0 on success.
    \return BAD_FUNC_ARG when token is NULL.
    \return BAD_STATE_E when an earlier open discarded the PIN and its session
    was closed.
    \return WC_HW_E when opening the session or logging in fails. A session
    whose login failed is closed again.

    \param token Token to open the session on.
    \param readWrite 1 for a read-write session, 0 for read-only.
    \param discardPin 1 to discard the PIN once the session is logged in.

    \sa wc_Pkcs11Token_Open
    \sa wc_Pkcs11Token_Final
 */
int wc_Pkcs11Token_Open_ex(Pkcs11Token* token, int readWrite, int discardPin);

/*!
    \ingroup PKCS11

    \brief Closes the session opened with wc_Pkcs11Token_Open. It does not log
    out, so the application stays logged in while another of its sessions on
    the token is open.

    \param token Token whose session to close.

    \sa wc_Pkcs11Token_Open
 */
void wc_Pkcs11Token_Close(Pkcs11Token* token);

/*!
    \ingroup PKCS11

    \brief Creates the key on the token as a session object in the session
    opened with wc_Pkcs11Token_Open, so it lasts until that session closes.
    An ECC key
    gets the usages its flags ask for: sign for WC_ECC_FLAG_DEC_SIGN and
    derive for WC_ECC_FLAG_DERIVE. With neither flag it gets derive, plus sign
    when the key has an id or label, or only sign when PKCS#11 ECDH is not
    compiled in, as far as the token supports them. When
    the key has its public part and the token has ECDSA, the public part is
    stored too.

    \return 0 on success.
    \return BAD_FUNC_ARG when token is NULL.
    \return BAD_STATE_E when no session was opened with wc_Pkcs11Token_Open.
    \return MEMORY_E when memory allocation fails.
    \return NOT_COMPILED_IN when the key type is not supported, or the token
    lacks the mechanism for it or for a usage the key's flags ask for.
    \return WC_HW_E when a PKCS#11 call fails.

    \param token Token to store the key on.
    \param type Key type, one of enum Pkcs11KeyType.
    \param clear 1 to zeroize the private data in the software key after
    storing it.
    \param key Key object of that type.

    \sa wc_Pkcs11Token_Open
 */
int wc_Pkcs11StoreKey(Pkcs11Token* token, int type, int clear,
    void* key);

/*!
    \ingroup PKCS11
 */
int wc_Pkcs11_CryptoDevCb(int devId, wc_CryptoInfo* info,
    void* ctx);
