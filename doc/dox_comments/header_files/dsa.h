/*!
    \ingroup DSA

    \brief This function initializes a DsaKey object in order to use it for
    authentication via the Digital Signature Algorithm (DSA).

    \return 0 Returned on success.
    \return BAD_FUNC_ARG Returned if a NULL key is passed in.

    \param key pointer to the DsaKey structure to initialize

    _Example_
    \code
    DsaKey key;
    int ret;
    ret = wc_InitDsaKey(&key); // initialize DSA key
    \endcode

    \sa wc_FreeDsaKey
*/
int wc_InitDsaKey(DsaKey* key);

/*!
    \ingroup DSA

    \brief This function frees a DsaKey object after it has been used.

    \return none No returns.

    \param key pointer to the DsaKey structure to free

    _Example_
    \code
    DsaKey key;
    // initialize key, use for authentication
    ...
    wc_FreeDsaKey(&key); // free DSA key
    \endcode

    \sa wc_FreeDsaKey
*/
void wc_FreeDsaKey(DsaKey* key);

/*!
    \ingroup DSA

    \brief This function signs the input digest and stores the result in the
    output buffer, out.

    \return 0 Returned on successfully signing the input digest
    \return MP_INIT_E may be returned if there is an error in processing the
    DSA signature.
    \return MP_READ_E may be returned if there is an error in processing the
    DSA signature.
    \return MP_CMP_E may be returned if there is an error in processing the
    DSA signature.
    \return MP_INVMOD_E may be returned if there is an error in processing the
    DSA signature.
    \return MP_EXPTMOD_E may be returned if there is an error in processing
    the DSA signature.
    \return MP_MOD_E may be returned if there is an error in processing the
    DSA signature.
    \return MP_MUL_E may be returned if there is an error in processing the
    DSA signature.
    \return MP_ADD_E may be returned if there is an error in processing the
    DSA signature.
    \return MP_MULMOD_E may be returned if there is an error in processing
    the DSA signature.
    \return MP_TO_E may be returned if there is an error in processing the
    DSA signature.
    \return MP_MEM may be returned if there is an error in processing the
    DSA signature.

    \param digest pointer to the hash to sign
    \param out pointer to the buffer in which to store the signature
    \param key pointer to the initialized DsaKey structure with which to
    generate the signature
    \param rng pointer to an initialized RNG to use with the signature
    generation

    _Example_
    \code
    DsaKey key;
    // initialize DSA key, load private Key
    int ret;
    WC_RNG rng;
    wc_InitRng(&rng);
    byte hash[] = { // initialize with hash digest };
    byte signature[40]; // signature will be 40 bytes (320 bits)

    ret = wc_DsaSign(hash, signature, &key, &rng);
    if (ret != 0) {
	    // error generating DSA signature
    }
    \endcode

    \sa wc_DsaVerify
*/
int wc_DsaSign(const byte* digest, byte* out,
                           DsaKey* key, WC_RNG* rng);

/*!
    \ingroup DSA

    \brief This function verifies the signature of a digest, given a private
    key. It stores whether the key properly verifies in the answer parameter,
    with 1 corresponding to a successful verification, and 0 corresponding to
    failed verification.

    \return 0 Returned on successfully processing the verify request. Note:
    this does not mean that the signature is verified, only that the function
    succeeded
    \return MP_INIT_E may be returned if there is an error in processing the
    DSA signature.
    \return MP_READ_E may be returned if there is an error in processing the
    DSA signature.
    \return MP_CMP_E may be returned if there is an error in processing the
    DSA signature.
    \return MP_INVMOD_E may be returned if there is an error in processing
    the DSA signature.
    \return MP_EXPTMOD_E may be returned if there is an error in processing
    the DSA signature.
    \return MP_MOD_E may be returned if there is an error in processing the
    DSA signature.
    \return MP_MUL_E may be returned if there is an error in processing the
    DSA signature.
    \return MP_ADD_E may be returned if there is an error in processing the
    DSA signature.
    \return MP_MULMOD_E may be returned if there is an error in processing
    the DSA signature.
    \return MP_TO_E may be returned if there is an error in processing the
    DSA signature.
    \return MP_MEM may be returned if there is an error in processing the
    DSA signature.

    \param digest pointer to the digest containing the subject of the signature
    \param sig pointer to the buffer containing the signature to verify
    \param key pointer to the initialized DsaKey structure with which to
    verify the signature
    \param answer pointer to an integer which will store whether the
    verification was successful

    _Example_
    \code
    DsaKey key;
    // initialize DSA key, load public Key

    int ret;
    int verified;
    byte hash[] = { // initialize with hash digest };
    byte signature[] = { // initialize with signature to verify };
    ret = wc_DsaVerify(hash, signature, &key, &verified);
    if (ret != 0) {
    	// error processing verify request
    } else if (answer == 0) {
    	// invalid signature
    }
    \endcode

    \sa wc_DsaSign
*/
int wc_DsaVerify(const byte* digest, const byte* sig,
                             DsaKey* key, int* answer);

/*!
    \ingroup DSA

    \brief This function decodes a DER formatted certificate buffer containing
    a DSA public key, and stores the key in the given DsaKey structure. It
    also sets the inOutIdx parameter according to the length of the input read.

    \return 0 Returned on successfully setting the public key for the DsaKey
    object
    \return ASN_PARSE_E Returned if there is an error in the encoding while
    reading the certificate buffer
    \return ASN_DH_KEY_E Returned if one of the DSA parameters is incorrectly
    formatted

    \param input pointer to the buffer containing the DER formatted DSA
    public key
    \param inOutIdx pointer to an integer in which to store the final index
    of the certificate read
    \param key pointer to the DsaKey structure in which to store the public key
    \param inSz size of the input buffer

    _Example_
    \code
    int ret, idx=0;

    DsaKey key;
    wc_InitDsaKey(&key);
    byte derBuff[] = { // DSA public key};
    ret = wc_DsaPublicKeyDecode(derBuff, &idx, &key, inSz);
    if (ret != 0) {
    	// error reading public key
    }
    \endcode

    \sa wc_InitDsaKey
    \sa wc_DsaPrivateKeyDecode
*/
int wc_DsaPublicKeyDecode(const byte* input, word32* inOutIdx,
                                      DsaKey* key, word32 inSz);

/*!
    \ingroup DSA

    \brief This function decodes a DER formatted certificate buffer containing
    a DSA private key, and stores the key in the given DsaKey structure. It
    also sets the inOutIdx parameter according to the length of the input read.

    \return 0 Returned on successfully setting the private key for the DsaKey
    object
    \return ASN_PARSE_E Returned if there is an error in the encoding while
    reading the certificate buffer
    \return ASN_DH_KEY_E Returned if one of the DSA parameters is incorrectly
    formatted

    \param input pointer to the buffer containing the DER formatted DSA
    private key
    \param inOutIdx pointer to an integer in which to store the final index
    of the certificate read
    \param key pointer to the DsaKey structure in which to store the private
    key
    \param inSz size of the input buffer

    _Example_
    \code
    int ret, idx=0;

    DsaKey key;
    wc_InitDsaKey(&key);
    byte derBuff[] = { // DSA private key };
    ret = wc_DsaPrivateKeyDecode(derBuff, &idx, &key, inSz);
    if (ret != 0) {
    	// error reading private key
    }
    \endcode

    \sa wc_InitDsaKey
    \sa wc_DsaPublicKeyDecode
*/
int wc_DsaPrivateKeyDecode(const byte* input, word32* inOutIdx,
                                       DsaKey* key, word32 inSz);

/*!
    \ingroup DSA

    \brief Convert DsaKey key to DER format, write to output (inLen),
    return bytes written.

    \return outLen Success, number of bytes written
    \return BAD_FUNC_ARG key or output are null or key->type is not
    DSA_PRIVATE.
    \return MEMORY_E Error allocating memory.

    \param key Pointer to DsaKey structure to convert.
    \param output Pointer to output buffer for converted key.
    \param inLen Length of key input.

    _Example_
    \code
    DsaKey key;
    WC_RNG rng;
    int derSz;
    int bufferSize = // Sufficient buffer size;
    byte der[bufferSize];

    wc_InitDsaKey(&key);
    wc_InitRng(&rng);
    wc_MakeDsaKey(&rng, &key);
    derSz = wc_DsaKeyToDer(&key, der, bufferSize);
    \endcode

    \sa wc_InitDsaKey
    \sa wc_FreeDsaKey
    \sa wc_MakeDsaKey
*/
int wc_DsaKeyToDer(DsaKey* key, byte* output, word32 inLen);

/*!
    \ingroup DSA

    \brief Create a DSA key.

    \return MP_OKAY Success
    \return BAD_FUNC_ARG Either rng or dsa is null.
    \return MEMORY_E Couldn't allocate memory for buffer.
    \return MP_INIT_E Error initializing mp_int

    \param rng Pointer to WC_RNG structure.
    \param dsa Pointer to DsaKey structure.

    _Example_
    \code
    WC_RNG rng;
    DsaKey dsa;
    wc_InitRng(&rng);
    wc_InitDsa(&dsa);
    if(wc_MakeDsaKey(&rng, &dsa) != 0)
    {
        // Error creating key
    }
    \endcode

    \sa wc_InitDsaKey
    \sa wc_FreeDsaKey
    \sa wc_DsaSign
*/
int wc_MakeDsaKey(WC_RNG *rng, DsaKey *dsa);

/*!
    \ingroup DSA

    \brief FIPS 186-4 defines valid for modulus_size values as
    (1024, 160) (2048, 256) (3072, 256)

    \return 0 Success
    \return BAD_FUNC_ARG rng or dsa is null or modulus_size is invalid.
    \return MEMORY_E Error attempting to allocate memory.

    \param rng pointer to wolfCrypt rng.
    \param modulus_size 1024, 2048, or 3072 are valid values.
    \param dsa Pointer to a DsaKey structure.

    _Example_
    \code
    DsaKey key;
    WC_RNG rng;
    wc_InitDsaKey(&key);
    wc_InitRng(&rng);
    if(wc_MakeDsaParameters(&rng, 1024, &genKey) != 0)
    {
        // Handle error
    }
    \endcode

    \sa wc_MakeDsaKey
    \sa wc_DsaKeyToDer
    \sa wc_InitDsaKey
*/
int wc_MakeDsaParameters(WC_RNG *rng, int modulus_size, DsaKey *dsa);

/*!
    \ingroup openSSL
    \brief Creates new DSA structure.

    \return WOLFSSL_DSA pointer on success
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_DSA* dsa = wolfSSL_DSA_new();
    if (dsa == NULL) {
        // handle error
    }
    \endcode

    \sa wolfSSL_DSA_free
*/
WOLFSSL_DSA* wolfSSL_DSA_new(void);

/*!
    \ingroup openSSL
    \brief Frees DSA structure.

    \return none No returns

    \param dsa DSA structure to free

    _Example_
    \code
    WOLFSSL_DSA* dsa = wolfSSL_DSA_new();
    // use dsa
    wolfSSL_DSA_free(dsa);
    \endcode

    \sa wolfSSL_DSA_new
*/
void wolfSSL_DSA_free(WOLFSSL_DSA* dsa);

/*!
    \ingroup openSSL
    \brief Prints DSA key to file pointer.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param fp File pointer to write to
    \param dsa DSA structure to print
    \param indent Indentation level

    _Example_
    \code
    WOLFSSL_DSA* dsa;
    FILE* fp = fopen("dsa_key.txt", "w");
    int ret = wolfSSL_DSA_print_fp(fp, dsa, 0);
    \endcode

    \sa wolfSSL_DSA_new
*/
int wolfSSL_DSA_print_fp(XFILE fp, WOLFSSL_DSA* dsa, int indent);

/*!
    \ingroup openSSL
    \brief Generates DSA key pair.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param dsa DSA structure with parameters set

    _Example_
    \code
    WOLFSSL_DSA* dsa = wolfSSL_DSA_new();
    // set parameters
    int ret = wolfSSL_DSA_generate_key(dsa);
    \endcode

    \sa wolfSSL_DSA_generate_parameters_ex
*/
int wolfSSL_DSA_generate_key(WOLFSSL_DSA* dsa);

/*!
    \ingroup openSSL
    \brief Generates DSA parameters.

    \return WOLFSSL_DSA pointer on success
    \return NULL on failure

    \param bits Key size in bits
    \param seed Seed buffer
    \param seedLen Seed length
    \param counterRet Counter return value
    \param hRet H return value
    \param cb Callback function
    \param CBArg Callback argument

    _Example_
    \code
    WOLFSSL_DSA* dsa = wolfSSL_DSA_generate_parameters(2048, NULL,
                                                       0, NULL, NULL,
                                                       NULL, NULL);
    \endcode

    \sa wolfSSL_DSA_generate_parameters_ex
*/
WOLFSSL_DSA* wolfSSL_DSA_generate_parameters(int bits,
    unsigned char* seed, int seedLen, int* counterRet,
    unsigned long* hRet, WOLFSSL_BN_CB cb, void* CBArg);

/*!
    \ingroup openSSL
    \brief Generates DSA parameters (extended version).

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param dsa DSA structure
    \param bits Key size in bits
    \param seed Seed buffer
    \param seedLen Seed length
    \param counterRet Counter return value
    \param hRet H return value
    \param cb Callback function

    _Example_
    \code
    WOLFSSL_DSA* dsa = wolfSSL_DSA_new();
    int ret = wolfSSL_DSA_generate_parameters_ex(dsa, 2048, NULL,
                                                 0, NULL, NULL,
                                                 NULL);
    \endcode

    \sa wolfSSL_DSA_generate_parameters
*/
int wolfSSL_DSA_generate_parameters_ex(WOLFSSL_DSA* dsa, int bits,
    unsigned char* seed, int seedLen, int* counterRet,
    unsigned long* hRet, void* cb);

/*!
    \ingroup openSSL
    \brief Gets DSA parameters p, q, g.

    \return none No returns

    \param d DSA structure
    \param p Pointer to store p parameter
    \param q Pointer to store q parameter
    \param g Pointer to store g parameter

    _Example_
    \code
    const WOLFSSL_BIGNUM *p, *q, *g;
    wolfSSL_DSA_get0_pqg(dsa, &p, &q, &g);
    \endcode

    \sa wolfSSL_DSA_set0_pqg
*/
void wolfSSL_DSA_get0_pqg(const WOLFSSL_DSA *d,
    const WOLFSSL_BIGNUM **p, const WOLFSSL_BIGNUM **q,
    const WOLFSSL_BIGNUM **g);

/*!
    \ingroup openSSL
    \brief Sets DSA parameters p, q, g.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param d DSA structure
    \param p P parameter
    \param q Q parameter
    \param g G parameter

    _Example_
    \code
    WOLFSSL_BIGNUM *p, *q, *g;
    // initialize p, q, g
    int ret = wolfSSL_DSA_set0_pqg(dsa, p, q, g);
    \endcode

    \sa wolfSSL_DSA_get0_pqg
*/
int wolfSSL_DSA_set0_pqg(WOLFSSL_DSA *d, WOLFSSL_BIGNUM *p,
    WOLFSSL_BIGNUM *q, WOLFSSL_BIGNUM *g);

/*!
    \ingroup openSSL
    \brief Gets DSA public and private keys.

    \return none No returns

    \param d DSA structure
    \param pub_key Pointer to store public key
    \param priv_key Pointer to store private key

    _Example_
    \code
    const WOLFSSL_BIGNUM *pub, *priv;
    wolfSSL_DSA_get0_key(dsa, &pub, &priv);
    \endcode

    \sa wolfSSL_DSA_set0_key
*/
void wolfSSL_DSA_get0_key(const WOLFSSL_DSA *d,
    const WOLFSSL_BIGNUM **pub_key,
    const WOLFSSL_BIGNUM **priv_key);

/*!
    \ingroup openSSL
    \brief Sets DSA public and private keys.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param d DSA structure
    \param pub_key Public key
    \param priv_key Private key

    _Example_
    \code
    WOLFSSL_BIGNUM *pub, *priv;
    // initialize pub, priv
    int ret = wolfSSL_DSA_set0_key(dsa, pub, priv);
    \endcode

    \sa wolfSSL_DSA_get0_key
*/
int wolfSSL_DSA_set0_key(WOLFSSL_DSA *d, WOLFSSL_BIGNUM *pub_key,
    WOLFSSL_BIGNUM *priv_key);

/*!
    \ingroup openSSL
    \brief Loads DSA key from DER buffer.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param dsa DSA structure
    \param derBuf DER encoded key buffer
    \param derSz DER buffer size

    _Example_
    \code
    WOLFSSL_DSA* dsa = wolfSSL_DSA_new();
    byte derBuf[2048];
    int ret = wolfSSL_DSA_LoadDer(dsa, derBuf, sizeof(derBuf));
    \endcode

    \sa wolfSSL_DSA_LoadDer_ex
*/
int wolfSSL_DSA_LoadDer(WOLFSSL_DSA* dsa, const unsigned char* derBuf,
    int derSz);

/*!
    \ingroup openSSL
    \brief Loads DSA key from DER buffer with options.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param dsa DSA structure
    \param derBuf DER encoded key buffer
    \param derSz DER buffer size
    \param opt Load options

    _Example_
    \code
    WOLFSSL_DSA* dsa = wolfSSL_DSA_new();
    byte derBuf[2048];
    int ret = wolfSSL_DSA_LoadDer_ex(dsa, derBuf, sizeof(derBuf),
                                     WOLFSSL_DSA_LOAD_PRIVATE);
    \endcode

    \sa wolfSSL_DSA_LoadDer
*/
int wolfSSL_DSA_LoadDer_ex(WOLFSSL_DSA* dsa,
    const unsigned char* derBuf, int derSz, int opt);

/*!
    \ingroup openSSL
    \brief Signs digest with DSA key.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param d Digest to sign
    \param sigRet Signature output buffer
    \param dsa DSA key

    _Example_
    \code
    byte digest[WC_SHA_DIGEST_SIZE];
    byte sig[40];
    int ret = wolfSSL_DSA_do_sign(digest, sig, dsa);
    \endcode

    \sa wolfSSL_DSA_do_verify
*/
int wolfSSL_DSA_do_sign(const unsigned char* d, unsigned char* sigRet,
    WOLFSSL_DSA* dsa);

/*!
    \ingroup openSSL
    \brief Verifies DSA signature.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param d Digest
    \param sig Signature
    \param dsa DSA key
    \param dsacheck Verification result

    _Example_
    \code
    byte digest[WC_SHA_DIGEST_SIZE];
    byte sig[40];
    int check;
    int ret = wolfSSL_DSA_do_verify(digest, sig, dsa, &check);
    \endcode

    \sa wolfSSL_DSA_do_sign
*/
int wolfSSL_DSA_do_verify(const unsigned char* d, unsigned char* sig,
    WOLFSSL_DSA* dsa, int *dsacheck);

/*!
    \ingroup openSSL
    \brief Gets DSA key size in bits.

    \return Key size in bits on success
    \return 0 on failure

    \param d DSA structure

    _Example_
    \code
    int bits = wolfSSL_DSA_bits(dsa);
    \endcode

    \sa wolfSSL_DSA_new
*/
int wolfSSL_DSA_bits(const WOLFSSL_DSA *d);

/*!
    \ingroup openSSL
    \brief Creates new DSA signature structure.

    \return WOLFSSL_DSA_SIG pointer on success
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_DSA_SIG* sig = wolfSSL_DSA_SIG_new();
    if (sig == NULL) {
        // handle error
    }
    \endcode

    \sa wolfSSL_DSA_SIG_free
*/
WOLFSSL_DSA_SIG* wolfSSL_DSA_SIG_new(void);

/*!
    \ingroup openSSL
    \brief Frees DSA signature structure.

    \return none No returns

    \param sig DSA signature structure to free

    _Example_
    \code
    WOLFSSL_DSA_SIG* sig = wolfSSL_DSA_SIG_new();
    // use sig
    wolfSSL_DSA_SIG_free(sig);
    \endcode

    \sa wolfSSL_DSA_SIG_new
*/
void wolfSSL_DSA_SIG_free(WOLFSSL_DSA_SIG *sig);

/*!
    \ingroup openSSL
    \brief Gets r and s values from DSA signature.

    \return none No returns

    \param sig DSA signature structure
    \param r Pointer to store r value
    \param s Pointer to store s value

    _Example_
    \code
    const WOLFSSL_BIGNUM *r, *s;
    wolfSSL_DSA_SIG_get0(sig, &r, &s);
    \endcode

    \sa wolfSSL_DSA_SIG_set0
*/
void wolfSSL_DSA_SIG_get0(const WOLFSSL_DSA_SIG *sig,
    const WOLFSSL_BIGNUM **r, const WOLFSSL_BIGNUM **s);

/*!
    \ingroup openSSL
    \brief Sets r and s values in DSA signature.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param sig DSA signature structure
    \param r R value
    \param s S value

    _Example_
    \code
    WOLFSSL_BIGNUM *r, *s;
    // initialize r, s
    int ret = wolfSSL_DSA_SIG_set0(sig, r, s);
    \endcode

    \sa wolfSSL_DSA_SIG_get0
*/
int wolfSSL_DSA_SIG_set0(WOLFSSL_DSA_SIG *sig, WOLFSSL_BIGNUM *r,
    WOLFSSL_BIGNUM *s);

/*!
    \ingroup openSSL
    \brief Converts DSA signature to DER format.

    \return Size on success
    \return negative on failure

    \param sig DSA signature structure
    \param out Output buffer pointer

    _Example_
    \code
    byte* der = NULL;
    int derSz = wolfSSL_i2d_DSA_SIG(sig, &der);
    \endcode

    \sa wolfSSL_d2i_DSA_SIG
*/
int wolfSSL_i2d_DSA_SIG(const WOLFSSL_DSA_SIG *sig, byte **out);

/*!
    \ingroup openSSL
    \brief Converts DER format to DSA signature.

    \return WOLFSSL_DSA_SIG pointer on success
    \return NULL on failure

    \param sig Pointer to DSA signature structure pointer
    \param pp DER buffer pointer
    \param length DER buffer length

    _Example_
    \code
    WOLFSSL_DSA_SIG* sig = NULL;
    const byte* der = derBuf;
    sig = wolfSSL_d2i_DSA_SIG(&sig, &der, derSz);
    \endcode

    \sa wolfSSL_i2d_DSA_SIG
*/
WOLFSSL_DSA_SIG* wolfSSL_d2i_DSA_SIG(WOLFSSL_DSA_SIG **sig,
    const unsigned char **pp, long length);

/*!
    \ingroup openSSL
    \brief Signs digest and returns DSA signature structure.

    \return WOLFSSL_DSA_SIG pointer on success
    \return NULL on failure

    \param digest Digest to sign
    \param inLen Digest length
    \param dsa DSA key

    _Example_
    \code
    byte digest[WC_SHA_DIGEST_SIZE];
    WOLFSSL_DSA_SIG* sig = wolfSSL_DSA_do_sign_ex(digest,
                                                  sizeof(digest),
                                                  dsa);
    \endcode

    \sa wolfSSL_DSA_do_verify_ex
*/
WOLFSSL_DSA_SIG* wolfSSL_DSA_do_sign_ex(const unsigned char* digest,
    int inLen, WOLFSSL_DSA* dsa);

/*!
    \ingroup openSSL
    \brief Verifies DSA signature structure.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param digest Digest
    \param digest_len Digest length
    \param sig DSA signature structure
    \param dsa DSA key

    _Example_
    \code
    byte digest[WC_SHA_DIGEST_SIZE];
    int ret = wolfSSL_DSA_do_verify_ex(digest, sizeof(digest),
                                       sig, dsa);
    \endcode

    \sa wolfSSL_DSA_do_sign_ex
*/
int wolfSSL_DSA_do_verify_ex(const unsigned char* digest,
    int digest_len, WOLFSSL_DSA_SIG* sig, WOLFSSL_DSA* dsa);

/*!
    \ingroup openSSL
    \brief Converts DSA parameters to DER format.

    \return Size on success
    \return negative on failure

    \param dsa DSA structure
    \param out Output buffer pointer

    _Example_
    \code
    byte* der = NULL;
    int derSz = wolfSSL_i2d_DSAparams(dsa, &der);
    \endcode

    \sa wolfSSL_d2i_DSAparams
*/
int wolfSSL_i2d_DSAparams(const WOLFSSL_DSA* dsa, unsigned char** out);

/*!
    \ingroup openSSL
    \brief Converts DER format to DSA parameters.

    \return WOLFSSL_DSA pointer on success
    \return NULL on failure

    \param dsa Pointer to DSA structure pointer
    \param der DER buffer pointer
    \param derLen DER buffer length

    _Example_
    \code
    WOLFSSL_DSA* dsa = NULL;
    const byte* der = derBuf;
    dsa = wolfSSL_d2i_DSAparams(&dsa, &der, derSz);
    \endcode

    \sa wolfSSL_i2d_DSAparams
*/
WOLFSSL_DSA* wolfSSL_d2i_DSAparams(WOLFSSL_DSA** dsa,
    const unsigned char** der, long derLen);

/*!
    \ingroup DSA
    \brief Initializes DSA key with heap hint.

    \return 0 on success
    \return negative on failure

    \param key DSA key structure
    \param h Heap hint for memory allocation

    _Example_
    \code
    DsaKey key;
    int ret = wc_InitDsaKey_h(&key, NULL);
    \endcode

    \sa wc_InitDsaKey
*/
int wc_InitDsaKey_h(DsaKey* key, void* h);

/*!
    \ingroup DSA
    \brief Signs digest with extended parameters.

    \return 0 on success
    \return negative on failure

    \param digest Digest to sign
    \param digestSz Digest size
    \param out Output signature buffer
    \param key DSA key
    \param rng Random number generator

    _Example_
    \code
    byte digest[WC_SHA_DIGEST_SIZE];
    byte sig[40];
    WC_RNG rng;
    int ret = wc_DsaSign_ex(digest, sizeof(digest), sig, &key,
                            &rng);
    \endcode

    \sa wc_DsaSign
*/
int wc_DsaSign_ex(const byte* digest, word32 digestSz, byte* out,
    DsaKey* key, WC_RNG* rng);

/*!
    \ingroup DSA
    \brief Verifies signature with extended parameters.

    \return 0 on success
    \return negative on failure

    \param digest Digest
    \param digestSz Digest size
    \param sig Signature buffer
    \param key DSA key
    \param answer Verification result

    _Example_
    \code
    byte digest[WC_SHA_DIGEST_SIZE];
    byte sig[40];
    int answer;
    int ret = wc_DsaVerify_ex(digest, sizeof(digest), sig, &key,
                              &answer);
    \endcode

    \sa wc_DsaVerify
*/
int wc_DsaVerify_ex(const byte* digest, word32 digestSz,
    const byte* sig, DsaKey* key, int* answer);

/*!
    \ingroup DSA
    \brief Sets DSA public key in output buffer.

    \return Size on success
    \return negative on failure

    \param output Output buffer
    \param key DSA key
    \param outLen Output buffer length
    \param with_header Include header flag

    _Example_
    \code
    byte output[256];
    int ret = wc_SetDsaPublicKey(output, &key, sizeof(output), 1);
    \endcode

    \sa wc_DsaKeyToPublicDer
*/
int wc_SetDsaPublicKey(byte* output, DsaKey* key, int outLen,
    int with_header);

/*!
    \ingroup DSA
    \brief Converts DSA key to public DER format.

    \return Size on success
    \return negative on failure

    \param key DSA key
    \param output Output buffer
    \param inLen Output buffer length

    _Example_
    \code
    byte output[256];
    int ret = wc_DsaKeyToPublicDer(&key, output, sizeof(output));
    \endcode

    \sa wc_SetDsaPublicKey
*/
int wc_DsaKeyToPublicDer(DsaKey* key, byte* output, word32 inLen);

/*!
    \ingroup DSA
    \brief Imports DSA parameters from raw format.

    \return 0 on success
    \return negative on failure

    \param dsa DSA key structure
    \param p P parameter string
    \param q Q parameter string
    \param g G parameter string

    _Example_
    \code
    DsaKey dsa;
    int ret = wc_DsaImportParamsRaw(&dsa, pStr, qStr, gStr);
    \endcode

    \sa wc_DsaImportParamsRawCheck
*/
int wc_DsaImportParamsRaw(DsaKey* dsa, const char* p, const char* q,
    const char* g);

/*!
    \ingroup DSA
    \brief Imports DSA parameters from raw format with validation.

    \return 0 on success
    \return negative on failure

    \param dsa DSA key structure
    \param p P parameter string
    \param q Q parameter string
    \param g G parameter string
    \param trusted Trust flag
    \param rng Random number generator

    _Example_
    \code
    DsaKey dsa;
    WC_RNG rng;
    int ret = wc_DsaImportParamsRawCheck(&dsa, pStr, qStr, gStr, 1,
                                         &rng);
    \endcode

    \sa wc_DsaImportParamsRaw
*/
int wc_DsaImportParamsRawCheck(DsaKey* dsa, const char* p,
    const char* q, const char* g, int trusted, WC_RNG* rng);

/*!
    \ingroup DSA
    \brief Exports DSA parameters to raw format.

    \return 0 on success
    \return negative on failure

    \param dsa DSA key structure
    \param p P parameter buffer
    \param pSz P parameter size (in/out)
    \param q Q parameter buffer
    \param qSz Q parameter size (in/out)
    \param g G parameter buffer
    \param gSz G parameter size (in/out)

    _Example_
    \code
    byte p[256], q[32], g[256];
    word32 pSz = sizeof(p), qSz = sizeof(q), gSz = sizeof(g);
    int ret = wc_DsaExportParamsRaw(&dsa, p, &pSz, q, &qSz, g,
                                    &gSz);
    \endcode

    \sa wc_DsaImportParamsRaw
*/
int wc_DsaExportParamsRaw(DsaKey* dsa, byte* p, word32* pSz, byte* q,
    word32* qSz, byte* g, word32* gSz);

/*!
    \ingroup DSA
    \brief Exports DSA key to raw format.

    \return 0 on success
    \return negative on failure

    \param dsa DSA key structure
    \param x Private key buffer
    \param xSz Private key size (in/out)
    \param y Public key buffer
    \param ySz Public key size (in/out)

    _Example_
    \code
    byte x[32], y[256];
    word32 xSz = sizeof(x), ySz = sizeof(y);
    int ret = wc_DsaExportKeyRaw(&dsa, x, &xSz, y, &ySz);
    \endcode

    \sa wc_DsaImportParamsRaw
*/
int wc_DsaExportKeyRaw(DsaKey* dsa, byte* x, word32* xSz, byte* y,
    word32* ySz);
