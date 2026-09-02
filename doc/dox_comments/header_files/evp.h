/*!
    \ingroup openSSL

    \brief Getter functions for the respective WOLFSSL_EVP_CIPHER pointers.
    wolfSSL_EVP_init() must be called once in the program first to populate
    these cipher strings. WOLFSSL_DES_ECB macro must be defined for
    wolfSSL_EVP_des_ede3_ecb().

    \return pointer Returns a WOLFSSL_EVP_CIPHER pointer for DES EDE3 operations.

    \param none No parameters.

    _Example_
    \code
    printf("block size des ede3 cbc = %d\n",
    wolfSSL_EVP_CIPHER_block_size(wolfSSL_EVP_des_ede3_cbc()));
    printf("block size des ede3 ecb = %d\n",
    wolfSSL_EVP_CIPHER_block_size(wolfSSL_EVP_des_ede3_ecb()));
    \endcode

    \sa wolfSSL_EVP_CIPHER_CTX_init
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_des_ede3_ecb(void);

/*!
    \ingroup openSSL

    \brief Getter functions for the respective WOLFSSL_EVP_CIPHER pointers.
    wolfSSL_EVP_init() must be called once in the program first to populate
    these cipher strings. WOLFSSL_DES_ECB macro must be defined for
    wolfSSL_EVP_des_ecb().

    \return pointer Returns a WOLFSSL_EVP_CIPHER pointer for DES operations.

    \param none No parameters.

    _Example_
    \code
    WOLFSSL_EVP_CIPHER* cipher;
    cipher = wolfSSL_EVP_des_cbc();
    …
    \endcode

    \sa wolfSSL_EVP_CIPHER_CTX_init
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_des_cbc(void);

/*!
    \ingroup openSSL

    \brief Function for initializing WOLFSSL_EVP_MD_CTX. This function is a
    wrapper for wolfSSL_EVP_DigestInit() because wolfSSL does not
    use WOLFSSL_ENGINE.

    \return SSL_SUCCESS If successfully set.
    \return SSL_FAILURE If not successful.

    \param ctx structure to initialize.
    \param type type of hash to do, for example SHA.
    \param impl engine to use. N/A for wolfSSL, can be NULL.

    _Example_
    \code
    WOLFSSL_EVP_MD_CTX* md = NULL;
    wolfCrypt_Init();
    md = wolfSSL_EVP_MD_CTX_new();
    if (md == NULL) {
        printf("error setting md\n");
        return -1;
    }
    printf("cipher md init ret = %d\n", wolfSSL_EVP_DigestInit_ex(md,
    wolfSSL_EVP_sha1(), e));
    //free resources
    \endcode

    \sa wolfSSL_EVP_MD_CTX_new
    \sa wolfCrypt_Init
    \sa wolfSSL_EVP_MD_CTX_free
*/
int wolfSSL_EVP_DigestInit_ex(WOLFSSL_EVP_MD_CTX* ctx,
                                     const WOLFSSL_EVP_MD* type,
                                     WOLFSSL_ENGINE *impl);

/*!
    \ingroup openSSL

    \brief Function for initializing WOLFSSL_EVP_CIPHER_CTX. This function is a
    wrapper for wolfSSL_CipherInit() because wolfSSL does not
    use WOLFSSL_ENGINE.

    \return SSL_SUCCESS If successfully set.
    \return SSL_FAILURE If not successful.

    \param ctx structure to initialize.
    \param type type of encryption/decryption to do, for example AES.
    \param impl engine to use. N/A for wolfSSL, can be NULL.
    \param key key to set .
    \param iv iv if needed by algorithm.
    \param enc encryption (1) or decryption (0) flag.

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx = NULL;
    WOLFSSL_ENGINE* e = NULL;
    unsigned char key[16];
    unsigned char iv[12];
    wolfCrypt_Init();
    ctx = wolfSSL_EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        printf("issue creating ctx\n");
        return -1;
    }

    printf("cipher init ex error ret = %d\n", wolfSSL_EVP_CipherInit_ex(NULL,
    EVP_aes_128_    cbc(), e, key, iv, 1));
    printf("cipher init ex success ret = %d\n", wolfSSL_EVP_CipherInit_ex(ctx,
    EVP_aes_128_c    bc(), e, key, iv, 1));
    // free resources
    \endcode

    \sa wolfSSL_EVP_CIPHER_CTX_new
    \sa wolfCrypt_Init
    \sa wolfSSL_EVP_CIPHER_CTX_free
*/
int  wolfSSL_EVP_CipherInit_ex(WOLFSSL_EVP_CIPHER_CTX* ctx,
                                    const WOLFSSL_EVP_CIPHER* type,
                                    WOLFSSL_ENGINE *impl,
                                    const unsigned char* key,
                                    const unsigned char* iv,
                                    int enc);

/*!
    \ingroup openSSL

    \brief Function for initializing WOLFSSL_EVP_CIPHER_CTX. This function is a
    wrapper for wolfSSL_EVP_CipherInit() because wolfSSL does not use
    WOLFSSL_ENGINE. Sets encrypt flag to be encrypt.

    \return SSL_SUCCESS If successfully set.
    \return SSL_FAILURE If not successful.

    \param ctx structure to initialize.
    \param type type of encryption to do, for example AES.
    \param impl engine to use. N/A for wolfSSL, can be NULL.
    \param key key to use.
    \param iv iv to use.

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx = NULL;
    wolfCrypt_Init();
    ctx = wolfSSL_EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        printf("error setting ctx\n");
        return -1;
    }
    printf("cipher ctx init ret = %d\n", wolfSSL_EVP_EncryptInit_ex(ctx,
    wolfSSL_EVP_aes_128_cbc(), e, key, iv));
    //free resources
    \endcode

    \sa wolfSSL_EVP_CIPHER_CTX_new
    \sa wolfCrypt_Init
    \sa wolfSSL_EVP_CIPHER_CTX_free
*/
int  wolfSSL_EVP_EncryptInit_ex(WOLFSSL_EVP_CIPHER_CTX* ctx,
                                    const WOLFSSL_EVP_CIPHER* type,
                                    WOLFSSL_ENGINE *impl,
                                    const unsigned char* key,
                                    const unsigned char* iv);

/*!
    \ingroup openSSL

    \brief Function for initializing WOLFSSL_EVP_CIPHER_CTX. This function is a
    wrapper for wolfSSL_EVP_CipherInit() because wolfSSL does not use
    WOLFSSL_ENGINE. Sets encrypt flag to be decrypt.

    \return SSL_SUCCESS If successfully set.
    \return SSL_FAILURE If not successful.

    \param ctx structure to initialize.
    \param type type of encryption/decryption to do, for example AES.
    \param impl engine to use. N/A for wolfSSL, can be NULL.
    \param key key to set .
    \param iv iv if needed by algorithm.
    \param enc encryption (1) or decryption (0) flag.

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx = NULL;
    WOLFSSL_ENGINE* e = NULL;
    unsigned char key[16];
    unsigned char iv[12];

    wolfCrypt_Init();

    ctx = wolfSSL_EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        printf("issue creating ctx\n");
        return -1;
    }

    printf("cipher init ex error ret = %d\n", wolfSSL_EVP_DecryptInit_ex(NULL,
    EVP_aes_128_    cbc(), e, key, iv, 1));
    printf("cipher init ex success ret = %d\n", wolfSSL_EVP_DecryptInit_ex(ctx,
    EVP_aes_128_c    bc(), e, key, iv, 1));
    // free resources
    \endcode

    \sa wolfSSL_EVP_CIPHER_CTX_new
    \sa wolfCrypt_Init
    \sa wolfSSL_EVP_CIPHER_CTX_free
*/
int  wolfSSL_EVP_DecryptInit_ex(WOLFSSL_EVP_CIPHER_CTX* ctx,
                                    const WOLFSSL_EVP_CIPHER* type,
                                    WOLFSSL_ENGINE *impl,
                                    const unsigned char* key,
                                    const unsigned char* iv);

/*!
    \ingroup openSSL

    \brief Function for encrypting/decrypting data. In buffer is added to be
    encrypted or decrypted and out buffer holds the results. outl will be the
    length of encrypted/decrypted information.

    \return SSL_SUCCESS If successful.
    \return SSL_FAILURE If not successful.

    \param ctx structure to get cipher type from.
    \param out buffer to hold output.
    \param outl adjusted to be size of output.
    \param in buffer to perform operation on.
    \param inl length of input buffer.

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx = NULL;
    unsigned char out[100];
    int outl;
    unsigned char in[100];
    int inl = 100;

    ctx = wolfSSL_EVP_CIPHER_CTX_new();
    // set up ctx
    ret = wolfSSL_EVP_CipherUpdate(ctx, out, outl, in, inl);
    // check ret value
    // buffer out holds outl bytes of data
    // free resources
    \endcode

    \sa wolfSSL_EVP_CIPHER_CTX_new
    \sa wolfCrypt_Init
    \sa wolfSSL_EVP_CIPHER_CTX_free
*/
int wolfSSL_EVP_CipherUpdate(WOLFSSL_EVP_CIPHER_CTX *ctx,
                                   unsigned char *out, int *outl,
                                   const unsigned char *in, int inl);

/*!
    \ingroup openSSL

    \brief This function performs the final cipher operations adding in
    padding. If WOLFSSL_EVP_CIPH_NO_PADDING flag is set in
    WOLFSSL_EVP_CIPHER_CTX structure then 1 is returned and no
    encryption/decryption is done. If padding flag is seti padding is added and
    encrypted when ctx is set to encrypt, padding values are checked when set
    to decrypt.

    \return 1 Returned on success.
    \return 0 If encountering a failure.

    \param ctx structure to decrypt/encrypt with.
    \param out buffer for final decrypt/encrypt.
    \param out1 size of out buffer when data has been added by function.

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx;
    int out1;
    unsigned char out[64];
    // create ctx
    wolfSSL_EVP_CipherFinal(ctx, out, &out1);
    \endcode

    \sa wolfSSL_EVP_CIPHER_CTX_new
*/
int  wolfSSL_EVP_CipherFinal(WOLFSSL_EVP_CIPHER_CTX *ctx,
                                   unsigned char *out, int *outl);

/*!
    \ingroup openSSL

    \brief Setter function for WOLFSSL_EVP_CIPHER_CTX structure key length.

    \return SSL_SUCCESS If successfully set.
    \return SSL_FAILURE If failed to set key length.

    \param ctx structure to set key length.
    \param keylen key length.

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx;
    int keylen;
    // create ctx
    wolfSSL_EVP_CIPHER_CTX_set_key_length(ctx, keylen);
    \endcode

    \sa wolfSSL_EVP_CIPHER_flags
*/
int  wolfSSL_EVP_CIPHER_CTX_set_key_length(WOLFSSL_EVP_CIPHER_CTX* ctx,
                                                     int keylen);

/*!
    \ingroup openSSL

    \brief This is a getter function for the ctx block size.

    \return size Returns ctx->block_size.

    \param ctx the cipher ctx to get block size of.

    _Example_
    \code
    const WOLFSSL_CVP_CIPHER_CTX* ctx;
    //set up ctx
    printf(“block size = %d\n”, wolfSSL_EVP_CIPHER_CTX_block_size(ctx));
    \endcode

    \sa wolfSSL_EVP_CIPHER_block_size
*/
int wolfSSL_EVP_CIPHER_CTX_block_size(const WOLFSSL_EVP_CIPHER_CTX *ctx);

/*!
    \ingroup openSSL

    \brief This is a getter function for the block size of cipher.

    \return size returns the block size.

    \param cipher cipher to get block size of.

    _Example_
    \code
    printf(“block size = %d\n”,
    wolfSSL_EVP_CIPHER_block_size(wolfSSL_EVP_aes_256_ecb()));
    \endcode

    \sa wolfSSL_EVP_aes_256_ctr
*/
int wolfSSL_EVP_CIPHER_block_size(const WOLFSSL_EVP_CIPHER *cipher);

/*!
    \ingroup openSSL

    \brief Setter function for WOLFSSL_EVP_CIPHER_CTX structure.

    \return none No returns.

    \param ctx structure to set flag.
    \param flag flag to set in structure.

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx;
    int flag;
    // create ctx
    wolfSSL_EVP_CIPHER_CTX_set_flags(ctx, flag);
    \endcode

    \sa wolfSSL_EVP_CIPHER_flags
    \sa wolfSSL_EVP_CIPHER_CTX_flags
*/
void wolfSSL_EVP_CIPHER_CTX_set_flags(WOLFSSL_EVP_CIPHER_CTX *ctx, int flags);

/*!
    \ingroup openSSL

    \brief Clearing function for WOLFSSL_EVP_CIPHER_CTX structure.

    \return none No returns.

    \param ctx structure to clear flag.
    \param flag flag value to clear in structure.

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx;
    int flag;
    // create ctx
    wolfSSL_EVP_CIPHER_CTX_clear_flags(ctx, flag);
    \endcode

    \sa wolfSSL_EVP_CIPHER_flags
    \sa wolfSSL_EVP_CIPHER_CTX_flags
*/
void wolfSSL_EVP_CIPHER_CTX_clear_flags(WOLFSSL_EVP_CIPHER_CTX *ctx, int flags);

/*!
    \ingroup openSSL

    \brief Setter function for WOLFSSL_EVP_CIPHER_CTX structure to use padding.

    \return SSL_SUCCESS If successfully set.
    \return BAD_FUNC_ARG If null argument passed in.

    \param ctx structure to set padding flag.
    \param padding 0 for not setting padding, 1 for setting padding.

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx;
    // create ctx
    wolfSSL_EVP_CIPHER_CTX_set_padding(ctx, 1);
    \endcode

    \sa wolfSSL_EVP_CIPHER_CTX_new
*/
int  wolfSSL_EVP_CIPHER_CTX_set_padding(WOLFSSL_EVP_CIPHER_CTX *c, int pad);


/*!
    \ingroup openSSL

    \brief Getter function for WOLFSSL_EVP_CIPHER_CTX structure. Deprecated v1.1.0

    \return unsigned long of flags/mode.

    \param ctx structure to get flag.

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx;
    unsigned long flags;
    ctx = wolfSSL_EVP_CIPHER_CTX_new()
    flags = wolfSSL_EVP_CIPHER_CTX_flags(ctx);
    \endcode

    \sa wolfSSL_EVP_CIPHER_CTX_new
    \sa wolfSSL_EVP_CIPHER_flags
*/
unsigned long wolfSSL_EVP_CIPHER_CTX_flags(const WOLFSSL_EVP_CIPHER_CTX *ctx);

/*!
    \ingroup openSSL

    \brief Getter functions for the AES Key Wrap WOLFSSL_EVP_CIPHER pointers
    of RFC 3394. The wrapped output is one block (8 bytes) longer than the
    input, and the input has to be a whole number of 8 byte blocks - use the
    _pad variants for input of any length. HAVE_AES_KEYWRAP must be defined,
    along with WOLFSSL_AES_128, WOLFSSL_AES_192 or WOLFSSL_AES_256 for the
    respective key size.

    \return pointer Returns a WOLFSSL_EVP_CIPHER pointer for AES key wrap.
    \return NULL when the key size is not compiled in.

    \param none No parameters.

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx = wolfSSL_EVP_CIPHER_CTX_new();
    wolfSSL_EVP_EncryptInit(ctx, wolfSSL_EVP_aes_256_wrap(), kek, NULL);
    \endcode

    \sa wolfSSL_EVP_aes_256_wrap_pad
    \sa wolfSSL_EVP_CIPHER_CTX_new
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_128_wrap(void);

/*!
    \ingroup openSSL
    \brief See wolfSSL_EVP_aes_128_wrap().
    \return pointer Returns a WOLFSSL_EVP_CIPHER pointer for AES key wrap.
    \param none No parameters.
    \sa wolfSSL_EVP_aes_128_wrap
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_192_wrap(void);

/*!
    \ingroup openSSL
    \brief See wolfSSL_EVP_aes_128_wrap().
    \return pointer Returns a WOLFSSL_EVP_CIPHER pointer for AES key wrap.
    \param none No parameters.
    \sa wolfSSL_EVP_aes_128_wrap
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_256_wrap(void);

/*!
    \ingroup openSSL

    \brief Getter functions for the AES Key Wrap with Padding
    WOLFSSL_EVP_CIPHER pointers of RFC 5649. Unlike the unpadded wrap, the
    input may be any length. WOLFSSL_AES_KEYWRAP_PADDING must be defined as
    well as HAVE_AES_KEYWRAP.

    \return pointer Returns a WOLFSSL_EVP_CIPHER pointer for padded AES key
    wrap.
    \return NULL when the key size is not compiled in.

    \param none No parameters.

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx = wolfSSL_EVP_CIPHER_CTX_new();
    wolfSSL_EVP_EncryptInit(ctx, wolfSSL_EVP_aes_256_wrap_pad(), kek, NULL);
    \endcode

    \sa wolfSSL_EVP_aes_128_wrap
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_128_wrap_pad(void);

/*!
    \ingroup openSSL
    \brief See wolfSSL_EVP_aes_128_wrap_pad().
    \return pointer Returns a WOLFSSL_EVP_CIPHER pointer for padded key wrap.
    \param none No parameters.
    \sa wolfSSL_EVP_aes_128_wrap_pad
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_192_wrap_pad(void);

/*!
    \ingroup openSSL
    \brief See wolfSSL_EVP_aes_128_wrap_pad().
    \return pointer Returns a WOLFSSL_EVP_CIPHER pointer for padded key wrap.
    \param none No parameters.
    \sa wolfSSL_EVP_aes_128_wrap_pad
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_256_wrap_pad(void);

/*!
    \ingroup openSSL

    \brief Returns the initialisation vector the context will use for the next
    operation. For the chaining modes that carry state between calls - CBC,
    CTR, OFB and CFB - this is the working IV, which advances as data is
    processed, and not the IV the context was set up with. For every other
    mode the IV the context was given is returned. The pointer is into the
    context and stays valid until the context is reset or freed.

    \return pointer Pointer to the IV for the next operation.
    \return NULL if ctx is NULL or the cipher has no IV.

    \param ctx WOLFSSL_EVP_CIPHER_CTX structure to read the IV from.

    _Example_
    \code
    const unsigned char* iv = wolfSSL_EVP_CIPHER_CTX_iv(ctx);
    \endcode

    \sa wolfSSL_EVP_CIPHER_CTX_iv_noconst
    \sa wolfSSL_EVP_CIPHER_CTX_iv_length
*/
const unsigned char* wolfSSL_EVP_CIPHER_CTX_iv(const WOLFSSL_EVP_CIPHER_CTX* ctx);

/*!
    \ingroup openSSL

    \brief The writable form of wolfSSL_EVP_CIPHER_CTX_iv(). The same pointer
    is returned; writing through it changes the IV the context will use next,
    so it should only be used where OpenSSL code would modify the IV in place.

    \return pointer Pointer to the IV for the next operation.
    \return NULL if ctx is NULL or the cipher has no IV.

    \param ctx WOLFSSL_EVP_CIPHER_CTX structure to read the IV from.

    \sa wolfSSL_EVP_CIPHER_CTX_iv
*/
unsigned char* wolfSSL_EVP_CIPHER_CTX_iv_noconst(WOLFSSL_EVP_CIPHER_CTX* ctx);

/*!
    \ingroup openSSL

    \brief Returns the "null" message digest, which produces no output. It is
    used where an API demands a digest but none is wanted.

    \return pointer Returns a WOLFSSL_EVP_MD pointer for the null digest.

    \param none No parameters.

    _Example_
    \code
    wolfSSL_EVP_DigestInit(ctx, wolfSSL_EVP_md_null());
    \endcode

    \sa wolfSSL_EVP_DigestInit
*/
const WOLFSSL_EVP_MD* wolfSSL_EVP_md_null(void);

/*!
    \ingroup openSSL

    \brief Copies out the raw private key of a key that has one - Ed25519,
    Ed448, X25519 and X448. Called with priv set to NULL it reports the size
    the key needs in len and does nothing else, which is how the size is
    normally discovered before a second call fetches the bytes. Called with a
    buffer, len holds its size on entry; if the buffer is too small the call
    fails and len is set to the size needed.

    \return 1 on success, or when reporting the size for a NULL buffer.
    \return 0 on failure, including a key type that has no raw form.

    \param pkey key to read the private key from.
    \param priv buffer to write the raw private key to, or NULL to ask for the
    size.
    \param len size of priv on entry; the size written, or needed, on return.

    _Example_
    \code
    size_t len = 0;
    unsigned char* priv;
    if (wolfSSL_EVP_PKEY_get_raw_private_key(pkey, NULL, &len) != 1)
        return -1;
    priv = (unsigned char*)XMALLOC(len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (wolfSSL_EVP_PKEY_get_raw_private_key(pkey, priv, &len) != 1)
        return -1;
    \endcode

    \sa wolfSSL_EVP_PKEY_get_raw_public_key
*/
int wolfSSL_EVP_PKEY_get_raw_private_key(const WOLFSSL_EVP_PKEY* pkey, unsigned char* priv, size_t* len);

/*!
    \ingroup openSSL

    \brief Copies out the raw public key of a key that has one - Ed25519,
    Ed448, X25519 and X448. The size is reported and the buffer handled
    exactly as for wolfSSL_EVP_PKEY_get_raw_private_key(). For an Ed25519 or
    Ed448 key holding only a private key the public key is derived, so a key
    read from a private key file answers this call.

    \return 1 on success, or when reporting the size for a NULL buffer.
    \return 0 on failure, including a key type that has no raw form.

    \param pkey key to read the public key from.
    \param pub buffer to write the raw public key to, or NULL to ask for the
    size.
    \param len size of pub on entry; the size written, or needed, on return.

    \sa wolfSSL_EVP_PKEY_get_raw_private_key
*/
int wolfSSL_EVP_PKEY_get_raw_public_key(const WOLFSSL_EVP_PKEY* pkey, unsigned char* pub, size_t* len);
