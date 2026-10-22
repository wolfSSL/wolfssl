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
*/
int wc_Pkcs11Token_Init(Pkcs11Token* token, Pkcs11Dev* dev,
    int slotId, const char* tokenName, const unsigned char *userPin,
    int userPinSz);

/*!
    \ingroup PKCS11
*/
void wc_Pkcs11Token_Final(Pkcs11Token* token);

/*!
    \ingroup PKCS11
 */
int wc_Pkcs11Token_Open(Pkcs11Token* token, int readWrite);

/*!
    \ingroup PKCS11
 */
void wc_Pkcs11Token_Close(Pkcs11Token* token);

/*!
    \ingroup PKCS11

    \brief Creates the key on the token as a session object, so it lasts only
    while a session opened with wc_Pkcs11Token_Open stays open. An ECC key
    gets the usages its flags ask for: sign for WC_ECC_FLAG_DEC_SIGN and
    derive for WC_ECC_FLAG_DERIVE. With neither flag it gets derive, plus sign
    when the key has an id or label, or only sign when PKCS#11 ECDH is not
    compiled in, as far as the token supports them. When
    the key has its public part and the token has ECDSA, the public part is
    stored too.

    \return 0 on success.
    \return BAD_FUNC_ARG when token is NULL.
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
