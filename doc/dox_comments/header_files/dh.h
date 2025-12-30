/*!
    \ingroup Diffie-Hellman

    \brief This function initializes a Diffie-Hellman key for use in
    negotiating a secure secret key with the Diffie-Hellman exchange protocol.

    \return none No returns.

    \param key pointer to the DhKey structure to initialize for use with
    secure key exchanges

    _Example_
    \code
    DhKey key;
    wc_InitDhKey(&key); // initialize DH key
    \endcode

    \sa wc_FreeDhKey
    \sa wc_DhGenerateKeyPair
*/
int wc_InitDhKey(DhKey* key);

/*!
    \ingroup Diffie-Hellman

    \brief This function frees a Diffie-Hellman key after it has been used to
    negotiate a secure secret key with the Diffie-Hellman exchange protocol.

    \return none No returns.

    \param key pointer to the DhKey structure to free

    _Example_
    \code
    DhKey key;
    // initialize key, perform key exchange

    wc_FreeDhKey(&key); // free DH key to avoid memory leaks
    \endcode

    \sa wc_InitDhKey
*/
int wc_FreeDhKey(DhKey* key);

/*!
    \ingroup Diffie-Hellman

    \brief This function generates a public/private key pair based on the
    Diffie-Hellman public parameters, storing the private key in priv and the
    public key in pub. It takes an initialized Diffie-Hellman key and an
    initialized rng structure.

    \return BAD_FUNC_ARG Returned if there is an error parsing one of the
    inputs to this function
    \return RNG_FAILURE_E Returned if there is an error generating a random
    number using rng
    \return MP_INIT_E May be returned if there is an error in the math library
    while generating the public key
    \return MP_READ_E May be returned if there is an error in the math library
    while generating the public key
    \return MP_EXPTMOD_E May be returned if there is an error in the math
    library while generating the public key
    \return MP_TO_E May be returned if there is an error in the math library
    while generating the public key

    \param key pointer to the DhKey structure from which to generate
    the key pair
    \param rng pointer to an initialized random number generator (rng) with
    which to generate the keys
    \param priv pointer to a buffer in which to store the private key
    \param privSz will store the size of the private key written to priv
    \param pub pointer to a buffer in which to store the public key
    \param pubSz will store the size of the private key written to pub

    _Example_
    \code
    DhKey key;
    int ret;
    byte priv[256];
    byte pub[256];
    word32 privSz, pubSz;

    wc_InitDhKey(&key); // initialize key
    // Set DH parameters using wc_DhSetKey or wc_DhKeyDecode
    WC_RNG rng;
    wc_InitRng(&rng); // initialize rng
    ret = wc_DhGenerateKeyPair(&key, &rng, priv, &privSz, pub, &pubSz);
    \endcode

    \sa wc_InitDhKey
    \sa wc_DhSetKey
    \sa wc_DhKeyDecode
*/
int wc_DhGenerateKeyPair(DhKey* key, WC_RNG* rng, byte* priv,
                                 word32* privSz, byte* pub, word32* pubSz);

/*!
    \ingroup Diffie-Hellman

    \brief This function generates an agreed upon secret key based on a local
    private key and a received public key. If completed on both sides of an
    exchange, this function generates an agreed upon secret key for symmetric
    communication. On successfully generating a shared secret key, the size of
    the secret key written will be stored in agreeSz.

    \return 0 Returned on successfully generating an agreed upon secret key
    \return MP_INIT_E May be returned if there is an error while generating
    the shared secret key
    \return MP_READ_E May be returned if there is an error while generating
    the shared secret key
    \return MP_EXPTMOD_E May be returned if there is an error while generating
    the shared secret key
    \return MP_TO_E May be returned if there is an error while generating the
    shared secret key

    \param key pointer to the DhKey structure to use to compute the shared key
    \param agree pointer to the buffer in which to store the secret key
    \param agreeSz will hold the size of the secret key after
    successful generation
    \param priv pointer to the buffer containing the local secret key
    \param privSz size of the local secret key
    \param otherPub pointer to a buffer containing the received public key
    \param pubSz size of the received public key

    _Example_
    \code
    DhKey key;
    int ret;
    byte priv[256];
    byte agree[256];
    word32 agreeSz;

    // initialize key, set key prime and base
    // wc_DhGenerateKeyPair -- store private key in priv
    byte pub[] = { // initialized with the received public key };
    ret = wc_DhAgree(&key, agree, &agreeSz, priv, sizeof(priv), pub,
    sizeof(pub));
    if ( ret != 0 ) {
    	// error generating shared key
    }
    \endcode

    \sa wc_DhGenerateKeyPair
*/
int wc_DhAgree(DhKey* key, byte* agree, word32* agreeSz,
                       const byte* priv, word32 privSz, const byte* otherPub,
                       word32 pubSz);

/*!
    \ingroup Diffie-Hellman

    \brief This function decodes a Diffie-Hellman key from the given input
    buffer containing the key in DER format. It stores the result in the
    DhKey structure.

    \return 0 Returned on successfully decoding the input key
    \return ASN_PARSE_E Returned if there is an error parsing the sequence
    of the input
    \return ASN_DH_KEY_E Returned if there is an error reading the private
    key parameters from the parsed input

    \param input pointer to the buffer containing the DER formatted
    Diffie-Hellman key
    \param inOutIdx pointer to an integer in which to store the index parsed
    to while decoding the key
    \param key pointer to the DhKey structure to initialize with the input key
    \param inSz length of the input buffer. Gives the max length that may
    be read

    _Example_
    \code
    DhKey key;
    word32 idx = 0;

    byte keyBuff[1024];
    // initialize with DER formatted key
    wc_DhKeyInit(&key);
    ret = wc_DhKeyDecode(keyBuff, &idx, &key, sizeof(keyBuff));

    if ( ret != 0 ) {
    	// error decoding key
    }
    \endcode

    \sa wc_DhSetKey
*/
int wc_DhKeyDecode(const byte* input, word32* inOutIdx, DhKey* key,
                           word32 inSz);

/*!
    \ingroup Diffie-Hellman

    \brief This function sets the key for a DhKey structure using the input
    private key parameters. Unlike wc_DhKeyDecode, this function does not
    require that the input key be formatted in DER format, and instead simply
    accepts the parsed input parameters p (prime) and g (base).

    \return 0 Returned on successfully setting the key
    \return BAD_FUNC_ARG Returned if any of the input parameters
    evaluate to NULL
    \return MP_INIT_E Returned if there is an error initializing the key
    parameters for storage
    \return ASN_DH_KEY_E Returned if there is an error reading in the
    DH key parameters p and g

    \param key pointer to the DhKey structure on which to set the key
    \param p pointer to the buffer containing the prime for use with the key
    \param pSz length of the input prime
    \param g pointer to the buffer containing the base for use with the key
    \param gSz length of the input base

    _Example_
    \code
    DhKey key;

    byte p[] = { // initialize with prime };
    byte g[] = { // initialize with base };
    wc_DhKeyInit(&key);
    ret = wc_DhSetKey(key, p, sizeof(p), g, sizeof(g));

    if ( ret != 0 ) {
    	// error setting key
    }
    \endcode

    \sa wc_DhKeyDecode
*/
int wc_DhSetKey(DhKey* key, const byte* p, word32 pSz, const byte* g,
                        word32 gSz);

/*!
    \ingroup Diffie-Hellman

    \brief This function loads the Diffie-Hellman parameters, p (prime)
    and g (base) out of the given input buffer, DER formatted.

    \return 0 Returned on successfully extracting the DH parameters
    \return ASN_PARSE_E Returned if an error occurs while parsing the DER
    formatted DH certificate
    \return BUFFER_E Returned if there is inadequate space in p or g to
    store the parsed parameters

    \param input pointer to a buffer containing a DER formatted
    Diffie-Hellman certificate to parse
    \param inSz size of the input buffer
    \param p pointer to a buffer in which to store the parsed prime
    \param pInOutSz pointer to a word32 object containing the available
    size in the p buffer. Will be overwritten with the number of bytes
    written to the buffer after completing the function call
    \param g pointer to a buffer in which to store the parsed base
    \param gInOutSz pointer to a word32 object containing the available size
    in the g buffer. Will be overwritten with the number of bytes written to
    the buffer after completing the function call

    _Example_
    \code
    byte dhCert[] = { initialize with DER formatted certificate };
    byte p[MAX_DH_SIZE];
    byte g[MAX_DH_SIZE];
    word32 pSz = MAX_DH_SIZE;
    word32 gSz = MAX_DH_SIZE;

    ret = wc_DhParamsLoad(dhCert, sizeof(dhCert), p, &pSz, g, &gSz);
    if ( ret != 0 ) {
    	// error parsing inputs
    }
    \endcode

    \sa wc_DhSetKey
    \sa wc_DhKeyDecode
*/
int wc_DhParamsLoad(const byte* input, word32 inSz, byte* p,
                            word32* pInOutSz, byte* g, word32* gInOutSz);

/*!
    \ingroup Diffie-Hellman
    \brief Encodes DH parameters to DER format for OpenSSL compatibility.

    \return Length of DER encoding on success
    \return Negative on error

    \param dh DH parameters to encode
    \param out Output buffer pointer (if *out is NULL, allocates buffer)

    _Example_
    \code
    WOLFSSL_DH* dh = wolfSSL_DH_new();
    unsigned char* der = NULL;
    int derSz = wolfSSL_i2d_DHparams(dh, &der);
    if (derSz > 0) {
        // use der buffer
        XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
    }
    \endcode

    \sa wolfSSL_DH_new
*/
int wolfSSL_i2d_DHparams(const WOLFSSL_DH *dh, unsigned char **out);

/*!
    \ingroup Diffie-Hellman
    \brief Allocates and initializes a new DH structure for OpenSSL
    compatibility.

    \return Pointer to WOLFSSL_DH on success
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_DH* dh = wolfSSL_DH_new();
    if (dh == NULL) {
        // error allocating DH
    }
    // use dh
    wolfSSL_DH_free(dh);
    \endcode

    \sa wolfSSL_DH_free
    \sa wolfSSL_DH_generate_key
*/
WOLFSSL_DH* wolfSSL_DH_new(void);

/*!
    \ingroup Diffie-Hellman
    \brief Creates a new DH structure with named group parameters.

    \return Pointer to WOLFSSL_DH on success
    \return NULL on failure

    \param nid Named group identifier (e.g., NID_ffdhe2048)

    _Example_
    \code
    WOLFSSL_DH* dh = wolfSSL_DH_new_by_nid(NID_ffdhe2048);
    if (dh == NULL) {
        // error creating DH with named group
    }
    \endcode

    \sa wolfSSL_DH_new
*/
WOLFSSL_DH* wolfSSL_DH_new_by_nid(int nid);

/*!
    \ingroup Diffie-Hellman
    \brief Frees a DH structure.

    \param dh DH structure to free

    _Example_
    \code
    WOLFSSL_DH* dh = wolfSSL_DH_new();
    // use dh
    wolfSSL_DH_free(dh);
    \endcode

    \sa wolfSSL_DH_new
*/
void wolfSSL_DH_free(WOLFSSL_DH* dh);

/*!
    \ingroup Diffie-Hellman
    \brief Duplicates a DH structure.

    \return Pointer to new WOLFSSL_DH on success
    \return NULL on failure

    \param dh DH structure to duplicate

    _Example_
    \code
    WOLFSSL_DH* dh = wolfSSL_DH_new();
    WOLFSSL_DH* dhCopy = wolfSSL_DH_dup(dh);
    \endcode

    \sa wolfSSL_DH_new
*/
WOLFSSL_DH* wolfSSL_DH_dup(WOLFSSL_DH* dh);

/*!
    \ingroup Diffie-Hellman
    \brief Increments reference count for DH structure.

    \return 1 on success
    \return 0 on failure

    \param dh DH structure to increment reference

    _Example_
    \code
    WOLFSSL_DH* dh = wolfSSL_DH_new();
    int ret = wolfSSL_DH_up_ref(dh);
    \endcode

    \sa wolfSSL_DH_free
*/
int wolfSSL_DH_up_ref(WOLFSSL_DH* dh);

/*!
    \ingroup Diffie-Hellman
    \brief Validates DH parameters.

    \return 1 on success
    \return 0 on failure

    \param dh DH parameters to check
    \param codes Output for validation error codes

    _Example_
    \code
    WOLFSSL_DH* dh = wolfSSL_DH_new();
    int codes;
    int ret = wolfSSL_DH_check(dh, &codes);
    if (ret != 1 || codes != 0) {
        // validation failed
    }
    \endcode

    \sa wolfSSL_DH_generate_key
*/
int wolfSSL_DH_check(const WOLFSSL_DH *dh, int *codes);

/*!
    \ingroup Diffie-Hellman
    \brief Returns size of DH key in bytes.

    \return Key size in bytes on success
    \return -1 on failure

    \param dh DH structure

    _Example_
    \code
    WOLFSSL_DH* dh = wolfSSL_DH_new();
    int size = wolfSSL_DH_size(dh);
    \endcode

    \sa wolfSSL_DH_new
*/
int wolfSSL_DH_size(WOLFSSL_DH* dh);

/*!
    \ingroup Diffie-Hellman
    \brief Generates DH public/private key pair.

    \return 1 on success
    \return 0 on failure

    \param dh DH structure with parameters set

    _Example_
    \code
    WOLFSSL_DH* dh = wolfSSL_DH_new();
    // set p and g parameters
    int ret = wolfSSL_DH_generate_key(dh);
    if (ret != 1) {
        // key generation failed
    }
    \endcode

    \sa wolfSSL_DH_compute_key
*/
int wolfSSL_DH_generate_key(WOLFSSL_DH* dh);

/*!
    \ingroup Diffie-Hellman
    \brief Computes shared secret from peer's public key.

    \return Length of shared secret on success
    \return -1 on failure

    \param key Output buffer for shared secret
    \param pub Peer's public key
    \param dh DH structure with private key

    _Example_
    \code
    WOLFSSL_DH* dh = wolfSSL_DH_new();
    wolfSSL_DH_generate_key(dh);
    byte secret[256];
    WOLFSSL_BIGNUM* peerPub = NULL; // peer's public key
    int secretSz = wolfSSL_DH_compute_key(secret, peerPub, dh);
    \endcode

    \sa wolfSSL_DH_generate_key
*/
int wolfSSL_DH_compute_key(unsigned char* key,
                          const WOLFSSL_BIGNUM* pub, WOLFSSL_DH* dh);

/*!
    \ingroup Diffie-Hellman
    \brief Computes shared secret with zero-padding to DH size.

    \return Length of shared secret on success
    \return -1 on failure

    \param key Output buffer for shared secret
    \param otherPub Peer's public key
    \param dh DH structure with private key

    _Example_
    \code
    WOLFSSL_DH* dh = wolfSSL_DH_new();
    wolfSSL_DH_generate_key(dh);
    byte secret[256];
    WOLFSSL_BIGNUM* peerPub = NULL;
    int secretSz = wolfSSL_DH_compute_key_padded(secret, peerPub, dh);
    \endcode

    \sa wolfSSL_DH_compute_key
*/
int wolfSSL_DH_compute_key_padded(unsigned char* key,
                                 const WOLFSSL_BIGNUM* otherPub,
                                 WOLFSSL_DH* dh);

/*!
    \ingroup Diffie-Hellman
    \brief Loads DH parameters from DER buffer.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param dh DH structure to load into
    \param derBuf DER-encoded DH parameters
    \param derSz Size of DER buffer

    _Example_
    \code
    WOLFSSL_DH* dh = wolfSSL_DH_new();
    byte derBuf[256];
    int ret = wolfSSL_DH_LoadDer(dh, derBuf, sizeof(derBuf));
    \endcode

    \sa wolfSSL_DH_new
*/
int wolfSSL_DH_LoadDer(WOLFSSL_DH* dh, const unsigned char* derBuf,
                      int derSz);

/*!
    \ingroup Diffie-Hellman
    \brief Sets optional private key length.

    \return 1 on success
    \return 0 on failure

    \param dh DH structure
    \param len Private key length in bits

    _Example_
    \code
    WOLFSSL_DH* dh = wolfSSL_DH_new();
    int ret = wolfSSL_DH_set_length(dh, 256);
    \endcode

    \sa wolfSSL_DH_generate_key
*/
int wolfSSL_DH_set_length(WOLFSSL_DH* dh, long len);

/*!
    \ingroup Diffie-Hellman
    \brief Sets DH parameters p, q, and g.

    \return 1 on success
    \return 0 on failure

    \param dh DH structure
    \param p Prime modulus (takes ownership)
    \param q Subgroup order (takes ownership, can be NULL)
    \param g Generator (takes ownership)

    _Example_
    \code
    WOLFSSL_DH* dh = wolfSSL_DH_new();
    WOLFSSL_BIGNUM *p = wolfSSL_BN_new();
    WOLFSSL_BIGNUM *g = wolfSSL_BN_new();
    // set p and g values
    int ret = wolfSSL_DH_set0_pqg(dh, p, NULL, g);
    \endcode

    \sa wolfSSL_DH_generate_key
*/
int wolfSSL_DH_set0_pqg(WOLFSSL_DH *dh, WOLFSSL_BIGNUM *p,
                       WOLFSSL_BIGNUM *q, WOLFSSL_BIGNUM *g);

/*!
    \ingroup Diffie-Hellman
    \brief Returns DH parameters for 2048-bit MODP group with 256-bit
    subgroup.

    \return Pointer to WOLFSSL_DH on success
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_DH* dh = wolfSSL_DH_get_2048_256();
    if (dh == NULL) {
        // error getting standard group
    }
    \endcode

    \sa wolfSSL_DH_new_by_nid
*/
WOLFSSL_DH* wolfSSL_DH_get_2048_256(void);

/*!
    \ingroup Diffie-Hellman
    \brief Returns FFDHE 2048-bit group parameters.

    \return Pointer to DhParams structure
    \return NULL if not compiled with HAVE_FFDHE_2048

    _Example_
    \code
    const DhParams* params = wc_Dh_ffdhe2048_Get();
    if (params != NULL) {
        // use params
    }
    \endcode

    \sa wc_Dh_ffdhe3072_Get
    \sa wc_Dh_ffdhe4096_Get
    \sa wc_Dh_ffdhe6144_Get
    \sa wc_Dh_ffdhe8192_Get
*/
const DhParams* wc_Dh_ffdhe2048_Get(void);

/*!
    \ingroup Diffie-Hellman
    \brief Returns FFDHE 3072-bit group parameters.

    \return Pointer to DhParams structure
    \return NULL if not compiled with HAVE_FFDHE_3072

    _Example_
    \code
    const DhParams* params = wc_Dh_ffdhe3072_Get();
    if (params != NULL) {
        // use params
    }
    \endcode

    \sa wc_Dh_ffdhe2048_Get
    \sa wc_Dh_ffdhe4096_Get
    \sa wc_Dh_ffdhe6144_Get
    \sa wc_Dh_ffdhe8192_Get
*/
const DhParams* wc_Dh_ffdhe3072_Get(void);

/*!
    \ingroup Diffie-Hellman
    \brief Returns FFDHE 4096-bit group parameters.

    \return Pointer to DhParams structure
    \return NULL if not compiled with HAVE_FFDHE_4096

    _Example_
    \code
    const DhParams* params = wc_Dh_ffdhe4096_Get();
    if (params != NULL) {
        // use params
    }
    \endcode

    \sa wc_Dh_ffdhe2048_Get
    \sa wc_Dh_ffdhe3072_Get
    \sa wc_Dh_ffdhe6144_Get
    \sa wc_Dh_ffdhe8192_Get
*/
const DhParams* wc_Dh_ffdhe4096_Get(void);

/*!
    \ingroup Diffie-Hellman
    \brief Returns FFDHE 6144-bit group parameters.

    \return Pointer to DhParams structure
    \return NULL if not compiled with HAVE_FFDHE_6144

    _Example_
    \code
    const DhParams* params = wc_Dh_ffdhe6144_Get();
    if (params != NULL) {
        // use params
    }
    \endcode

    \sa wc_Dh_ffdhe2048_Get
    \sa wc_Dh_ffdhe3072_Get
    \sa wc_Dh_ffdhe4096_Get
    \sa wc_Dh_ffdhe8192_Get
*/
const DhParams* wc_Dh_ffdhe6144_Get(void);

/*!
    \ingroup Diffie-Hellman
    \brief Returns FFDHE 8192-bit group parameters.

    \return Pointer to DhParams structure
    \return NULL if not compiled with HAVE_FFDHE_8192

    _Example_
    \code
    const DhParams* params = wc_Dh_ffdhe8192_Get();
    if (params != NULL) {
        // use params
    }
    \endcode

    \sa wc_Dh_ffdhe2048_Get
    \sa wc_Dh_ffdhe3072_Get
    \sa wc_Dh_ffdhe4096_Get
    \sa wc_Dh_ffdhe6144_Get
*/
const DhParams* wc_Dh_ffdhe8192_Get(void);

/*!
    \ingroup Diffie-Hellman
    \brief Initializes DH key with heap hint and device ID.

    \return 0 on success
    \return BAD_FUNC_ARG if key is NULL

    \param key DH key to initialize
    \param heap Heap hint for memory allocation
    \param devId Device ID for hardware acceleration

    _Example_
    \code
    DhKey key;
    int ret = wc_InitDhKey_ex(&key, NULL, INVALID_DEVID);
    if (ret != 0) {
        // error initializing key
    }
    \endcode

    \sa wc_InitDhKey
    \sa wc_FreeDhKey
*/
int wc_InitDhKey_ex(DhKey* key, void* heap, int devId);

/*!
    \ingroup Diffie-Hellman
    \brief Computes shared secret with constant-time operations.

    \return 0 on success
    \return BAD_FUNC_ARG if parameters are invalid
    \return BUFFER_E if output buffer too small

    \param key DH key with parameters
    \param agree Output buffer for shared secret
    \param agreeSz Input: buffer size, Output: secret size
    \param priv Private key
    \param privSz Private key size
    \param otherPub Peer's public key
    \param pubSz Peer's public key size

    _Example_
    \code
    DhKey key;
    byte agree[256], priv[256], pub[256];
    word32 agreeSz = sizeof(agree);
    int ret = wc_DhAgree_ct(&key, agree, &agreeSz, priv,
                           sizeof(priv), pub, sizeof(pub));
    \endcode

    \sa wc_DhAgree
*/
int wc_DhAgree_ct(DhKey* key, byte* agree, word32 *agreeSz,
                 const byte* priv, word32 privSz,
                 const byte* otherPub, word32 pubSz);

/*!
    \ingroup Diffie-Hellman
    \brief Sets DH key to use named group parameters.

    \return 0 on success
    \return BAD_FUNC_ARG if parameters are invalid

    \param key DH key to configure
    \param name Named group identifier

    _Example_
    \code
    DhKey key;
    wc_InitDhKey(&key);
    int ret = wc_DhSetNamedKey(&key, WC_FFDHE_2048);
    \endcode

    \sa wc_DhGetNamedKeyParamSize
*/
int wc_DhSetNamedKey(DhKey* key, int name);

/*!
    \ingroup Diffie-Hellman
    \brief Gets parameter sizes for named group.

    \return 0 on success
    \return BAD_FUNC_ARG if parameters are invalid

    \param name Named group identifier
    \param p Output for prime size
    \param g Output for generator size
    \param q Output for subgroup order size

    _Example_
    \code
    word32 pSz, gSz, qSz;
    int ret = wc_DhGetNamedKeyParamSize(WC_FFDHE_2048, &pSz, &gSz,
                                       &qSz);
    \endcode

    \sa wc_DhSetNamedKey
*/
int wc_DhGetNamedKeyParamSize(int name, word32* p, word32* g,
                              word32* q);

/*!
    \ingroup Diffie-Hellman
    \brief Gets minimum key size for named group.

    \return Minimum key size in bits
    \return 0 if invalid name

    \param name Named group identifier

    _Example_
    \code
    word32 minSize = wc_DhGetNamedKeyMinSize(WC_FFDHE_2048);
    \endcode

    \sa wc_DhSetNamedKey
*/
word32 wc_DhGetNamedKeyMinSize(int name);

/*!
    \ingroup Diffie-Hellman
    \brief Compares parameters against named group.

    \return 0 if parameters match named group
    \return Non-zero if parameters don't match

    \param name Named group identifier
    \param noQ 1 to skip q comparison
    \param p Prime modulus
    \param pSz Prime size
    \param g Generator
    \param gSz Generator size
    \param q Subgroup order
    \param qSz Subgroup order size

    _Example_
    \code
    byte p[256], g[256];
    int ret = wc_DhCmpNamedKey(WC_FFDHE_2048, 1, p, sizeof(p),
                              g, sizeof(g), NULL, 0);
    \endcode

    \sa wc_DhSetNamedKey
*/
int wc_DhCmpNamedKey(int name, int noQ, const byte* p, word32 pSz,
                    const byte* g, word32 gSz, const byte* q,
                    word32 qSz);

/*!
    \ingroup Diffie-Hellman
    \brief Copies named group parameters to buffers.

    \return 0 on success
    \return BAD_FUNC_ARG if parameters are invalid
    \return BUFFER_E if buffers too small

    \param name Named group identifier
    \param p Output buffer for prime
    \param pSz Input: buffer size, Output: prime size
    \param g Output buffer for generator
    \param gSz Input: buffer size, Output: generator size
    \param q Output buffer for subgroup order
    \param qSz Input: buffer size, Output: subgroup order size

    _Example_
    \code
    byte p[512], g[512], q[512];
    word32 pSz = sizeof(p), gSz = sizeof(g), qSz = sizeof(q);
    int ret = wc_DhCopyNamedKey(WC_FFDHE_2048, p, &pSz, g, &gSz,
                               q, &qSz);
    \endcode

    \sa wc_DhSetNamedKey
*/
int wc_DhCopyNamedKey(int name, byte* p, word32* pSz, byte* g,
                     word32* gSz, byte* q, word32* qSz);

/*!
    \ingroup Diffie-Hellman
    \brief Generates public key from private key.

    \return 0 on success
    \return BAD_FUNC_ARG if parameters are invalid

    \param key DH key with parameters set
    \param priv Private key
    \param privSz Private key size
    \param pub Output buffer for public key
    \param pubSz Input: buffer size, Output: public key size

    _Example_
    \code
    DhKey key;
    byte priv[256], pub[256];
    word32 pubSz = sizeof(pub);
    int ret = wc_DhGeneratePublic(&key, priv, sizeof(priv), pub,
                                 &pubSz);
    \endcode

    \sa wc_DhGenerateKeyPair
*/
int wc_DhGeneratePublic(DhKey* key, byte* priv, word32 privSz,
                       byte* pub, word32* pubSz);

/*!
    \ingroup Diffie-Hellman
    \brief Imports private and/or public key into DH key.

    \return 0 on success
    \return BAD_FUNC_ARG if parameters are invalid

    \param key DH key to import into
    \param priv Private key (can be NULL)
    \param privSz Private key size
    \param pub Public key (can be NULL)
    \param pubSz Public key size

    _Example_
    \code
    DhKey key;
    byte priv[256], pub[256];
    int ret = wc_DhImportKeyPair(&key, priv, sizeof(priv), pub,
                                sizeof(pub));
    \endcode

    \sa wc_DhExportKeyPair
*/
int wc_DhImportKeyPair(DhKey* key, const byte* priv, word32 privSz,
                      const byte* pub, word32 pubSz);

/*!
    \ingroup Diffie-Hellman
    \brief Exports private and public key from DH key.

    \return 0 on success
    \return BAD_FUNC_ARG if parameters are invalid
    \return BUFFER_E if buffers too small

    \param key DH key to export from
    \param priv Output buffer for private key
    \param pPrivSz Input: buffer size, Output: private key size
    \param pub Output buffer for public key
    \param pPubSz Input: buffer size, Output: public key size

    _Example_
    \code
    DhKey key;
    byte priv[256], pub[256];
    word32 privSz = sizeof(priv), pubSz = sizeof(pub);
    int ret = wc_DhExportKeyPair(&key, priv, &privSz, pub, &pubSz);
    \endcode

    \sa wc_DhImportKeyPair
*/
int wc_DhExportKeyPair(DhKey* key, byte* priv, word32* pPrivSz,
                      byte* pub, word32* pPubSz);

/*!
    \ingroup Diffie-Hellman
    \brief Validates public key value.

    \return 0 if public key is valid
    \return BAD_FUNC_ARG if parameters are invalid
    \return MP_VAL if public key is invalid

    \param prime Prime modulus
    \param primeSz Prime size
    \param pub Public key to validate
    \param pubSz Public key size

    _Example_
    \code
    byte prime[256], pub[256];
    int ret = wc_DhCheckPubValue(prime, sizeof(prime), pub,
                                 sizeof(pub));
    if (ret != 0) {
        // invalid public key
    }
    \endcode

    \sa wc_DhCheckPubKey
*/
int wc_DhCheckPubValue(const byte* prime, word32 primeSz,
                      const byte* pub, word32 pubSz);

/*!
    \ingroup Diffie-Hellman

    \brief Checks DH keys for pair-wise consistency per process in SP 800-56Ar3,
    section 5.6.2.1.4, method (b) for FFC.
*/
int wc_DhCheckKeyPair(DhKey* key, const byte* pub, word32 pubSz,
                        const byte* priv, word32 privSz);

/*!
    \ingroup Diffie-Hellman

    \brief Check DH private key for invalid numbers
*/
int wc_DhCheckPrivKey(DhKey* key, const byte* priv, word32 pubSz);

/*!
    \ingroup Diffie-Hellman
*/
int wc_DhCheckPrivKey_ex(DhKey* key, const byte* priv, word32 pubSz,
                            const byte* prime, word32 primeSz);

/*!
    \ingroup Diffie-Hellman
*/
int wc_DhCheckPubKey(DhKey* key, const byte* pub, word32 pubSz);

/*!
    \ingroup Diffie-Hellman
*/
int wc_DhCheckPubKey_ex(DhKey* key, const byte* pub, word32 pubSz,
                            const byte* prime, word32 primeSz);

/*!
    \ingroup Diffie-Hellman
*/
int wc_DhExportParamsRaw(DhKey* dh, byte* p, word32* pSz,
                       byte* q, word32* qSz, byte* g, word32* gSz);

/*!
    \ingroup Diffie-Hellman
*/
int wc_DhGenerateParams(WC_RNG *rng, int modSz, DhKey *dh);

/*!
    \ingroup Diffie-Hellman
*/
int wc_DhSetCheckKey(DhKey* key, const byte* p, word32 pSz,
                        const byte* g, word32 gSz, const byte* q, word32 qSz,
                        int trusted, WC_RNG* rng);

/*!
    \ingroup Diffie-Hellman
*/
int wc_DhSetKey_ex(DhKey* key, const byte* p, word32 pSz,
                        const byte* g, word32 gSz, const byte* q, word32 qSz);

/*!
    \ingroup Diffie-Hellman
 */
int wc_FreeDhKey(DhKey* key);
