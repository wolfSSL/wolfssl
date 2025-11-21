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
    \brief Returns EVP_MD structure for MD4.

    \return Pointer to EVP_MD structure for MD4

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_MD* md = wolfSSL_EVP_md4();
    \endcode

    \sa wolfSSL_EVP_md5
*/
const WOLFSSL_EVP_MD* wolfSSL_EVP_md4(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_MD structure for MD5.

    \return Pointer to EVP_MD structure for MD5

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_MD* md = wolfSSL_EVP_md5();
    \endcode

    \sa wolfSSL_EVP_sha1
*/
const WOLFSSL_EVP_MD* wolfSSL_EVP_md5(void);

/*!
    \ingroup openSSL
    \brief Sets password prompt string.

    \return none No returns

    \param prompt Password prompt string

    _Example_
    \code
    wolfSSL_EVP_set_pw_prompt("Enter password:");
    \endcode

    \sa wolfSSL_EVP_read_pw_string
*/
void wolfSSL_EVP_set_pw_prompt(const char *prompt);

/*!
    \ingroup openSSL
    \brief Returns EVP_MD structure for MDC2.

    \return Pointer to EVP_MD structure for MDC2

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_MD* md = wolfSSL_EVP_mdc2();
    \endcode

    \sa wolfSSL_EVP_md5
*/
const WOLFSSL_EVP_MD* wolfSSL_EVP_mdc2(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_MD structure for SHA-1.

    \return Pointer to EVP_MD structure for SHA-1

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_MD* md = wolfSSL_EVP_sha1();
    \endcode

    \sa wolfSSL_EVP_sha256
*/
const WOLFSSL_EVP_MD* wolfSSL_EVP_sha1(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_MD structure for SHA-224.

    \return Pointer to EVP_MD structure for SHA-224

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_MD* md = wolfSSL_EVP_sha224();
    \endcode

    \sa wolfSSL_EVP_sha256
*/
const WOLFSSL_EVP_MD* wolfSSL_EVP_sha224(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_MD structure for SHA-256.

    \return Pointer to EVP_MD structure for SHA-256

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_MD* md = wolfSSL_EVP_sha256();
    \endcode

    \sa wolfSSL_EVP_sha384
*/
const WOLFSSL_EVP_MD* wolfSSL_EVP_sha256(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_MD structure for SHA-384.

    \return Pointer to EVP_MD structure for SHA-384

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_MD* md = wolfSSL_EVP_sha384();
    \endcode

    \sa wolfSSL_EVP_sha512
*/
const WOLFSSL_EVP_MD* wolfSSL_EVP_sha384(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_MD structure for SHA-512.

    \return Pointer to EVP_MD structure for SHA-512

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_MD* md = wolfSSL_EVP_sha512();
    \endcode

    \sa wolfSSL_EVP_sha256
*/
const WOLFSSL_EVP_MD* wolfSSL_EVP_sha512(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_MD structure for SHAKE-128.

    \return Pointer to EVP_MD structure for SHAKE-128

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_MD* md = wolfSSL_EVP_shake128();
    \endcode

    \sa wolfSSL_EVP_shake256
*/
const WOLFSSL_EVP_MD* wolfSSL_EVP_shake128(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_MD structure for SHAKE-256.

    \return Pointer to EVP_MD structure for SHAKE-256

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_MD* md = wolfSSL_EVP_shake256();
    \endcode

    \sa wolfSSL_EVP_shake128
*/
const WOLFSSL_EVP_MD* wolfSSL_EVP_shake256(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_MD structure for SHA3-224.

    \return Pointer to EVP_MD structure for SHA3-224

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_MD* md = wolfSSL_EVP_sha3_224();
    \endcode

    \sa wolfSSL_EVP_sha3_256
*/
const WOLFSSL_EVP_MD* wolfSSL_EVP_sha3_224(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_MD structure for SHA3-256.

    \return Pointer to EVP_MD structure for SHA3-256

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_MD* md = wolfSSL_EVP_sha3_256();
    \endcode

    \sa wolfSSL_EVP_sha3_384
*/
const WOLFSSL_EVP_MD* wolfSSL_EVP_sha3_256(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_MD structure for SHA3-384.

    \return Pointer to EVP_MD structure for SHA3-384

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_MD* md = wolfSSL_EVP_sha3_384();
    \endcode

    \sa wolfSSL_EVP_sha3_512
*/
const WOLFSSL_EVP_MD* wolfSSL_EVP_sha3_384(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_MD structure for SHA3-512.

    \return Pointer to EVP_MD structure for SHA3-512

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_MD* md = wolfSSL_EVP_sha3_512();
    \endcode

    \sa wolfSSL_EVP_sha3_256
*/
const WOLFSSL_EVP_MD* wolfSSL_EVP_sha3_512(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_MD structure for SM3.

    \return Pointer to EVP_MD structure for SM3

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_MD* md = wolfSSL_EVP_sm3();
    \endcode

    \sa wolfSSL_EVP_sha256
*/
const WOLFSSL_EVP_MD* wolfSSL_EVP_sm3(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for AES-128-ECB.

    \return Pointer to EVP_CIPHER structure for AES-128-ECB

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_128_ecb();
    \endcode

    \sa wolfSSL_EVP_aes_128_cbc
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_128_ecb(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for AES-192-ECB.

    \return Pointer to EVP_CIPHER structure for AES-192-ECB

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_192_ecb();
    \endcode

    \sa wolfSSL_EVP_aes_192_cbc
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_192_ecb(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for AES-256-ECB.

    \return Pointer to EVP_CIPHER structure for AES-256-ECB

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_256_ecb();
    \endcode

    \sa wolfSSL_EVP_aes_256_cbc
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_256_ecb(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for AES-128-CBC.

    \return Pointer to EVP_CIPHER structure for AES-128-CBC

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_128_cbc();
    \endcode

    \sa wolfSSL_EVP_aes_128_ecb
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_128_cbc(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for AES-192-CBC.

    \return Pointer to EVP_CIPHER structure for AES-192-CBC

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_192_cbc();
    \endcode

    \sa wolfSSL_EVP_aes_192_ecb
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_192_cbc(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for AES-256-CBC.

    \return Pointer to EVP_CIPHER structure for AES-256-CBC

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_256_cbc();
    \endcode

    \sa wolfSSL_EVP_aes_256_ecb
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_256_cbc(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for AES-128-CFB1.

    \return Pointer to EVP_CIPHER structure for AES-128-CFB1

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_128_cfb1();
    \endcode

    \sa wolfSSL_EVP_aes_128_cfb8
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_128_cfb1(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for AES-192-CFB1.

    \return Pointer to EVP_CIPHER structure for AES-192-CFB1

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_192_cfb1();
    \endcode

    \sa wolfSSL_EVP_aes_192_cfb8
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_192_cfb1(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for AES-256-CFB1.

    \return Pointer to EVP_CIPHER structure for AES-256-CFB1

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_256_cfb1();
    \endcode

    \sa wolfSSL_EVP_aes_256_cfb8
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_256_cfb1(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for AES-128-CFB8.

    \return Pointer to EVP_CIPHER structure for AES-128-CFB8

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_128_cfb8();
    \endcode

    \sa wolfSSL_EVP_aes_128_cfb128
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_128_cfb8(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for AES-192-CFB8.

    \return Pointer to EVP_CIPHER structure for AES-192-CFB8

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_192_cfb8();
    \endcode

    \sa wolfSSL_EVP_aes_192_cfb128
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_192_cfb8(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for AES-256-CFB8.

    \return Pointer to EVP_CIPHER structure for AES-256-CFB8

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_256_cfb8();
    \endcode

    \sa wolfSSL_EVP_aes_256_cfb128
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_256_cfb8(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for AES-128-CFB128.

    \return Pointer to EVP_CIPHER structure for AES-128-CFB128

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_128_cfb128();
    \endcode

    \sa wolfSSL_EVP_aes_128_cbc
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_128_cfb128(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for AES-192-CFB128.

    \return Pointer to EVP_CIPHER structure for AES-192-CFB128

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_192_cfb128();
    \endcode

    \sa wolfSSL_EVP_aes_192_cbc
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_192_cfb128(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for AES-256-CFB128.

    \return Pointer to EVP_CIPHER structure for AES-256-CFB128

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_256_cfb128();
    \endcode

    \sa wolfSSL_EVP_aes_256_cbc
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_256_cfb128(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for AES-128-OFB.

    \return Pointer to EVP_CIPHER structure for AES-128-OFB

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_128_ofb();
    \endcode

    \sa wolfSSL_EVP_aes_128_cbc
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_128_ofb(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for AES-192-OFB.

    \return Pointer to EVP_CIPHER structure for AES-192-OFB

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_192_ofb();
    \endcode

    \sa wolfSSL_EVP_aes_192_cbc
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_192_ofb(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for AES-256-OFB.

    \return Pointer to EVP_CIPHER structure for AES-256-OFB

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_256_ofb();
    \endcode

    \sa wolfSSL_EVP_aes_256_cbc
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_256_ofb(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for AES-128-XTS.

    \return Pointer to EVP_CIPHER structure for AES-128-XTS

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_128_xts();
    \endcode

    \sa wolfSSL_EVP_aes_256_xts
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_128_xts(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for AES-256-XTS.

    \return Pointer to EVP_CIPHER structure for AES-256-XTS

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_256_xts();
    \endcode

    \sa wolfSSL_EVP_aes_128_xts
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_256_xts(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for AES-128-GCM.

    \return Pointer to EVP_CIPHER structure for AES-128-GCM

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_128_gcm();
    \endcode

    \sa wolfSSL_EVP_aes_256_gcm
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_128_gcm(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for AES-192-GCM.

    \return Pointer to EVP_CIPHER structure for AES-192-GCM

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_192_gcm();
    \endcode

    \sa wolfSSL_EVP_aes_256_gcm
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_192_gcm(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for AES-256-GCM.

    \return Pointer to EVP_CIPHER structure for AES-256-GCM

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_256_gcm();
    \endcode

    \sa wolfSSL_EVP_aes_128_gcm
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_256_gcm(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for AES-128-CCM.

    \return Pointer to EVP_CIPHER structure for AES-128-CCM

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_128_ccm();
    \endcode

    \sa wolfSSL_EVP_aes_256_ccm
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_128_ccm(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for AES-192-CCM.

    \return Pointer to EVP_CIPHER structure for AES-192-CCM

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_192_ccm();
    \endcode

    \sa wolfSSL_EVP_aes_256_ccm
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_192_ccm(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for AES-256-CCM.

    \return Pointer to EVP_CIPHER structure for AES-256-CCM

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_256_ccm();
    \endcode

    \sa wolfSSL_EVP_aes_128_ccm
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_256_ccm(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for AES-128-CTR.

    \return Pointer to EVP_CIPHER structure for AES-128-CTR

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_128_ctr();
    \endcode

    \sa wolfSSL_EVP_aes_256_ctr
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_128_ctr(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for AES-192-CTR.

    \return Pointer to EVP_CIPHER structure for AES-192-CTR

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_192_ctr();
    \endcode

    \sa wolfSSL_EVP_aes_256_ctr
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_192_ctr(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for AES-256-CTR.

    \return Pointer to EVP_CIPHER structure for AES-256-CTR

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_256_ctr();
    \endcode

    \sa wolfSSL_EVP_aes_128_ctr
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_256_ctr(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for ARIA-128-GCM.

    \return Pointer to EVP_CIPHER structure for ARIA-128-GCM

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aria_128_gcm();
    \endcode

    \sa wolfSSL_EVP_aria_256_gcm
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aria_128_gcm(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for ARIA-192-GCM.

    \return Pointer to EVP_CIPHER structure for ARIA-192-GCM

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aria_192_gcm();
    \endcode

    \sa wolfSSL_EVP_aria_256_gcm
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aria_192_gcm(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for ARIA-256-GCM.

    \return Pointer to EVP_CIPHER structure for ARIA-256-GCM

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aria_256_gcm();
    \endcode

    \sa wolfSSL_EVP_aria_128_gcm
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aria_256_gcm(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for DES-ECB.

    \return Pointer to EVP_CIPHER structure for DES-ECB

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_des_ecb();
    \endcode

    \sa wolfSSL_EVP_des_cbc
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_des_ecb(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for DES-EDE3-ECB.

    \return Pointer to EVP_CIPHER structure for DES-EDE3-ECB

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_des_ede3_ecb();
    \endcode

    \sa wolfSSL_EVP_des_ede3_cbc
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_des_ede3_ecb(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for DES-CBC.

    \return Pointer to EVP_CIPHER structure for DES-CBC

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_des_cbc();
    \endcode

    \sa wolfSSL_EVP_des_ecb
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_des_cbc(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for DES-EDE3-CBC.

    \return Pointer to EVP_CIPHER structure for DES-EDE3-CBC

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_des_ede3_cbc();
    \endcode

    \sa wolfSSL_EVP_des_ede3_ecb
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_des_ede3_cbc(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for RC4.

    \return Pointer to EVP_CIPHER structure for RC4

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_rc4();
    \endcode

    \sa wolfSSL_EVP_aes_128_cbc
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_rc4(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for null cipher.

    \return Pointer to EVP_CIPHER structure for null cipher

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_enc_null();
    \endcode

    \sa wolfSSL_EVP_aes_128_cbc
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_enc_null(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for RC2-CBC.

    \return Pointer to EVP_CIPHER structure for RC2-CBC

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_rc2_cbc();
    \endcode

    \sa wolfSSL_EVP_rc4
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_rc2_cbc(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for ChaCha20-Poly1305.

    \return Pointer to EVP_CIPHER structure for ChaCha20-Poly1305

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_chacha20_poly1305();
    \endcode

    \sa wolfSSL_EVP_chacha20
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_chacha20_poly1305(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for ChaCha20.

    \return Pointer to EVP_CIPHER structure for ChaCha20

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_chacha20();
    \endcode

    \sa wolfSSL_EVP_chacha20_poly1305
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_chacha20(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for SM4-ECB.

    \return Pointer to EVP_CIPHER structure for SM4-ECB

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_sm4_ecb();
    \endcode

    \sa wolfSSL_EVP_sm4_cbc
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_sm4_ecb(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for SM4-CBC.

    \return Pointer to EVP_CIPHER structure for SM4-CBC

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_sm4_cbc();
    \endcode

    \sa wolfSSL_EVP_sm4_ecb
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_sm4_cbc(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for SM4-CTR.

    \return Pointer to EVP_CIPHER structure for SM4-CTR

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_sm4_ctr();
    \endcode

    \sa wolfSSL_EVP_sm4_cbc
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_sm4_ctr(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for SM4-GCM.

    \return Pointer to EVP_CIPHER structure for SM4-GCM

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_sm4_gcm();
    \endcode

    \sa wolfSSL_EVP_sm4_ccm
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_sm4_gcm(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_CIPHER structure for SM4-CCM.

    \return Pointer to EVP_CIPHER structure for SM4-CCM

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_sm4_ccm();
    \endcode

    \sa wolfSSL_EVP_sm4_gcm
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_sm4_ccm(void);

/*!
    \ingroup openSSL
    \brief Creates new EVP_ENCODE_CTX structure for base64 encoding.

    \return Pointer to new EVP_ENCODE_CTX structure on success
    \return NULL on failure

    \param none No parameters

    _Example_
    \code
    WOLFSSL_EVP_ENCODE_CTX* ctx = wolfSSL_EVP_ENCODE_CTX_new();
    if (ctx != NULL) {
        wolfSSL_EVP_EncodeInit(ctx);
    }
    \endcode

    \sa wolfSSL_EVP_ENCODE_CTX_free
    \sa wolfSSL_EVP_EncodeInit
*/
struct WOLFSSL_EVP_ENCODE_CTX* wolfSSL_EVP_ENCODE_CTX_new(void);

/*!
    \ingroup openSSL
    \brief Frees EVP_ENCODE_CTX structure.

    \return none No returns

    \param ctx EVP_ENCODE_CTX structure to free

    _Example_
    \code
    WOLFSSL_EVP_ENCODE_CTX* ctx = wolfSSL_EVP_ENCODE_CTX_new();
    wolfSSL_EVP_ENCODE_CTX_free(ctx);
    \endcode

    \sa wolfSSL_EVP_ENCODE_CTX_new
*/
void wolfSSL_EVP_ENCODE_CTX_free(WOLFSSL_EVP_ENCODE_CTX* ctx);

/*!
    \ingroup openSSL
    \brief Initializes EVP_ENCODE_CTX for base64 encoding.

    \return none No returns

    \param ctx EVP_ENCODE_CTX structure to initialize

    _Example_
    \code
    WOLFSSL_EVP_ENCODE_CTX* ctx = wolfSSL_EVP_ENCODE_CTX_new();
    wolfSSL_EVP_EncodeInit(ctx);
    \endcode

    \sa wolfSSL_EVP_EncodeUpdate
    \sa wolfSSL_EVP_EncodeFinal
*/
void wolfSSL_EVP_EncodeInit(WOLFSSL_EVP_ENCODE_CTX* ctx);

/*!
    \ingroup openSSL
    \brief Updates base64 encoding with input data.

    \return 1 on success
    \return 0 on failure

    \param ctx EVP_ENCODE_CTX structure
    \param out Output buffer for encoded data
    \param outl Pointer to output length
    \param in Input data to encode
    \param inl Input data length

    _Example_
    \code
    WOLFSSL_EVP_ENCODE_CTX* ctx = wolfSSL_EVP_ENCODE_CTX_new();
    unsigned char out[100];
    int outl;
    wolfSSL_EVP_EncodeInit(ctx);
    wolfSSL_EVP_EncodeUpdate(ctx, out, &outl, data, dataLen);
    \endcode

    \sa wolfSSL_EVP_EncodeInit
    \sa wolfSSL_EVP_EncodeFinal
*/
int wolfSSL_EVP_EncodeUpdate(WOLFSSL_EVP_ENCODE_CTX* ctx, unsigned char*out,
                              int *outl, const unsigned char*in, int inl);

/*!
    \ingroup openSSL
    \brief Finalizes base64 encoding.

    \return none No returns

    \param ctx EVP_ENCODE_CTX structure
    \param out Output buffer for final encoded data
    \param outl Pointer to output length

    _Example_
    \code
    WOLFSSL_EVP_ENCODE_CTX* ctx = wolfSSL_EVP_ENCODE_CTX_new();
    unsigned char out[100];
    int outl;
    wolfSSL_EVP_EncodeInit(ctx);
    wolfSSL_EVP_EncodeFinal(ctx, out, &outl);
    \endcode

    \sa wolfSSL_EVP_EncodeInit
    \sa wolfSSL_EVP_EncodeUpdate
*/
void wolfSSL_EVP_EncodeFinal(WOLFSSL_EVP_ENCODE_CTX* ctx, unsigned char*out,
                              int *outl);

/*!
    \ingroup openSSL
    \brief Encodes data to base64 in one operation.

    \return Length of encoded data on success
    \return Negative value on failure

    \param out Output buffer for encoded data
    \param in Input data to encode
    \param inLen Input data length

    _Example_
    \code
    unsigned char out[100];
    int len = wolfSSL_EVP_EncodeBlock(out, data, dataLen);
    \endcode

    \sa wolfSSL_EVP_DecodeBlock
*/
int wolfSSL_EVP_EncodeBlock(unsigned char *out, const unsigned char *in,
                             int inLen);

/*!
    \ingroup openSSL
    \brief Decodes base64 data in one operation.

    \return Length of decoded data on success
    \return Negative value on failure

    \param out Output buffer for decoded data
    \param in Input base64 data to decode
    \param inLen Input data length

    _Example_
    \code
    unsigned char out[100];
    int len = wolfSSL_EVP_DecodeBlock(out, b64Data, b64Len);
    \endcode

    \sa wolfSSL_EVP_EncodeBlock
*/
int wolfSSL_EVP_DecodeBlock(unsigned char *out, const unsigned char *in,
                             int inLen);

/*!
    \ingroup openSSL
    \brief Initializes EVP_ENCODE_CTX for base64 decoding.

    \return none No returns

    \param ctx EVP_ENCODE_CTX structure to initialize

    _Example_
    \code
    WOLFSSL_EVP_ENCODE_CTX* ctx = wolfSSL_EVP_ENCODE_CTX_new();
    wolfSSL_EVP_DecodeInit(ctx);
    \endcode

    \sa wolfSSL_EVP_DecodeUpdate
    \sa wolfSSL_EVP_DecodeFinal
*/
void wolfSSL_EVP_DecodeInit(WOLFSSL_EVP_ENCODE_CTX* ctx);

/*!
    \ingroup openSSL
    \brief Updates base64 decoding with input data.

    \return 1 on success
    \return 0 on failure
    \return -1 on decode error

    \param ctx EVP_ENCODE_CTX structure
    \param out Output buffer for decoded data
    \param outl Pointer to output length
    \param in Input base64 data to decode
    \param inl Input data length

    _Example_
    \code
    WOLFSSL_EVP_ENCODE_CTX* ctx = wolfSSL_EVP_ENCODE_CTX_new();
    unsigned char out[100];
    int outl;
    wolfSSL_EVP_DecodeInit(ctx);
    wolfSSL_EVP_DecodeUpdate(ctx, out, &outl, b64Data, b64Len);
    \endcode

    \sa wolfSSL_EVP_DecodeInit
    \sa wolfSSL_EVP_DecodeFinal
*/
int wolfSSL_EVP_DecodeUpdate(WOLFSSL_EVP_ENCODE_CTX* ctx, unsigned char*out,
                              int *outl, const unsigned char*in, int inl);

/*!
    \ingroup openSSL
    \brief Finalizes base64 decoding.

    \return 1 on success
    \return 0 on failure
    \return -1 on decode error

    \param ctx EVP_ENCODE_CTX structure
    \param out Output buffer for final decoded data
    \param outl Pointer to output length

    _Example_
    \code
    WOLFSSL_EVP_ENCODE_CTX* ctx = wolfSSL_EVP_ENCODE_CTX_new();
    unsigned char out[100];
    int outl;
    wolfSSL_EVP_DecodeInit(ctx);
    int ret = wolfSSL_EVP_DecodeFinal(ctx, out, &outl);
    \endcode

    \sa wolfSSL_EVP_DecodeInit
    \sa wolfSSL_EVP_DecodeUpdate
*/
int wolfSSL_EVP_DecodeFinal(WOLFSSL_EVP_ENCODE_CTX* ctx, unsigned char*out,
                             int *outl);

/*!
    \ingroup openSSL
    \brief Returns EVP_MD structure for BLAKE2b-512.

    \return Pointer to EVP_MD structure for BLAKE2b-512

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_MD* md = wolfSSL_EVP_blake2b512();
    \endcode

    \sa wolfSSL_EVP_blake2s256
*/
const WOLFSSL_EVP_MD* wolfSSL_EVP_blake2b512(void);

/*!
    \ingroup openSSL
    \brief Returns EVP_MD structure for BLAKE2s-256.

    \return Pointer to EVP_MD structure for BLAKE2s-256

    \param none No parameters

    _Example_
    \code
    const WOLFSSL_EVP_MD* md = wolfSSL_EVP_blake2s256();
    \endcode

    \sa wolfSSL_EVP_blake2b512
*/
const WOLFSSL_EVP_MD* wolfSSL_EVP_blake2s256(void);

/*!
    \ingroup openSSL
    \brief Initializes EVP library.

    \return none No returns

    \param none No parameters

    _Example_
    \code
    wolfSSL_EVP_init();
    \endcode

    \sa wolfSSL_EVP_cleanup
*/
void wolfSSL_EVP_init(void);

/*!
    \ingroup openSSL
    \brief Returns size of message digest in bytes.

    \return Size of digest in bytes
    \return 0 if type is NULL

    \param type EVP_MD structure

    _Example_
    \code
    const WOLFSSL_EVP_MD* md = wolfSSL_EVP_sha256();
    int size = wolfSSL_EVP_MD_size(md);
    \endcode

    \sa wolfSSL_EVP_MD_type
    \sa wolfSSL_EVP_MD_block_size
*/
int wolfSSL_EVP_MD_size(const WOLFSSL_EVP_MD* type);

/*!
    \ingroup openSSL
    \brief Returns NID (numeric identifier) of message digest.

    \return NID of message digest
    \return 0 if type is NULL

    \param type EVP_MD structure

    _Example_
    \code
    const WOLFSSL_EVP_MD* md = wolfSSL_EVP_sha256();
    int nid = wolfSSL_EVP_MD_type(md);
    \endcode

    \sa wolfSSL_EVP_MD_size
    \sa wolfSSL_EVP_MD_block_size
*/
int wolfSSL_EVP_MD_type(const WOLFSSL_EVP_MD* type);

/*!
    \ingroup openSSL
    \brief Returns flags for message digest.

    \return Flags for message digest
    \return 0 if md is NULL

    \param md EVP_MD structure

    _Example_
    \code
    const WOLFSSL_EVP_MD* md = wolfSSL_EVP_sha256();
    unsigned long flags = wolfSSL_EVP_MD_flags(md);
    \endcode

    \sa wolfSSL_EVP_MD_type
    \sa wolfSSL_EVP_MD_size
*/
unsigned long wolfSSL_EVP_MD_flags(const WOLFSSL_EVP_MD *md);

/*!
    \ingroup openSSL
    \brief Returns block size of message digest in bytes.

    \return Block size in bytes
    \return 0 if type is NULL

    \param type EVP_MD structure

    _Example_
    \code
    const WOLFSSL_EVP_MD* md = wolfSSL_EVP_sha256();
    int blockSize = wolfSSL_EVP_MD_block_size(md);
    \endcode

    \sa wolfSSL_EVP_MD_size
    \sa wolfSSL_EVP_MD_type
*/
int wolfSSL_EVP_MD_block_size(const WOLFSSL_EVP_MD* type);

/*!
    \ingroup openSSL
    \brief Returns public key type for message digest.

    \return Public key NID
    \return 0 if type is NULL

    \param type EVP_MD structure

    _Example_
    \code
    const WOLFSSL_EVP_MD* md = wolfSSL_EVP_sha256();
    int pkeyType = wolfSSL_EVP_MD_pkey_type(md);
    \endcode

    \sa wolfSSL_EVP_MD_type
*/
int wolfSSL_EVP_MD_pkey_type(const WOLFSSL_EVP_MD* type);

/*!
    \ingroup openSSL
    \brief Frees EVP_MD_CTX structure.

    \return none No returns

    \param ctx EVP_MD_CTX structure to free

    _Example_
    \code
    WOLFSSL_EVP_MD_CTX* ctx = wolfSSL_EVP_MD_CTX_new();
    wolfSSL_EVP_MD_CTX_free(ctx);
    \endcode

    \sa wolfSSL_EVP_MD_CTX_new
*/
void wolfSSL_EVP_MD_CTX_free(WOLFSSL_EVP_MD_CTX* ctx);

/*!
    \ingroup openSSL
    \brief Initializes EVP_MD_CTX structure.

    \return none No returns

    \param ctx EVP_MD_CTX structure to initialize

    _Example_
    \code
    WOLFSSL_EVP_MD_CTX ctx;
    wolfSSL_EVP_MD_CTX_init(&ctx);
    \endcode

    \sa wolfSSL_EVP_MD_CTX_cleanup
*/
void wolfSSL_EVP_MD_CTX_init(WOLFSSL_EVP_MD_CTX* ctx);

/*!
    \ingroup openSSL
    \brief Cleans up EVP_MD_CTX structure.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_MD_CTX structure to clean up

    _Example_
    \code
    WOLFSSL_EVP_MD_CTX ctx;
    wolfSSL_EVP_MD_CTX_init(&ctx);
    wolfSSL_EVP_MD_CTX_cleanup(&ctx);
    \endcode

    \sa wolfSSL_EVP_MD_CTX_init
*/
int wolfSSL_EVP_MD_CTX_cleanup(WOLFSSL_EVP_MD_CTX* ctx);

/*!
    \ingroup openSSL
    \brief Copies EVP_MD_CTX structure.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param out Destination EVP_MD_CTX structure
    \param in Source EVP_MD_CTX structure

    _Example_
    \code
    WOLFSSL_EVP_MD_CTX in, out;
    wolfSSL_EVP_MD_CTX_init(&in);
    wolfSSL_EVP_MD_CTX_init(&out);
    wolfSSL_EVP_MD_CTX_copy(&out, &in);
    \endcode

    \sa wolfSSL_EVP_MD_CTX_copy_ex
*/
int wolfSSL_EVP_MD_CTX_copy(WOLFSSL_EVP_MD_CTX *out,
                             const WOLFSSL_EVP_MD_CTX *in);

/*!
    \ingroup openSSL
    \brief Copies EVP_MD_CTX structure (extended version).

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param out Destination EVP_MD_CTX structure
    \param in Source EVP_MD_CTX structure

    _Example_
    \code
    WOLFSSL_EVP_MD_CTX* in = wolfSSL_EVP_MD_CTX_new();
    WOLFSSL_EVP_MD_CTX* out = wolfSSL_EVP_MD_CTX_new();
    wolfSSL_EVP_MD_CTX_copy_ex(out, in);
    \endcode

    \sa wolfSSL_EVP_MD_CTX_copy
*/
int wolfSSL_EVP_MD_CTX_copy_ex(WOLFSSL_EVP_MD_CTX *out,
                                const WOLFSSL_EVP_MD_CTX *in);

/*!
    \ingroup openSSL
    \brief Returns NID of message digest in context.

    \return NID of message digest
    \return 0 if ctx is NULL

    \param ctx EVP_MD_CTX structure

    _Example_
    \code
    WOLFSSL_EVP_MD_CTX* ctx = wolfSSL_EVP_MD_CTX_new();
    wolfSSL_EVP_DigestInit(ctx, wolfSSL_EVP_sha256());
    int type = wolfSSL_EVP_MD_CTX_type(ctx);
    \endcode

    \sa wolfSSL_EVP_MD_CTX_size
*/
int wolfSSL_EVP_MD_CTX_type(const WOLFSSL_EVP_MD_CTX *ctx);

/*!
    \ingroup openSSL
    \brief Returns size of message digest in context.

    \return Size of digest in bytes
    \return 0 if ctx is NULL

    \param ctx EVP_MD_CTX structure

    _Example_
    \code
    WOLFSSL_EVP_MD_CTX* ctx = wolfSSL_EVP_MD_CTX_new();
    wolfSSL_EVP_DigestInit(ctx, wolfSSL_EVP_sha256());
    int size = wolfSSL_EVP_MD_CTX_size(ctx);
    \endcode

    \sa wolfSSL_EVP_MD_CTX_type
*/
int wolfSSL_EVP_MD_CTX_size(const WOLFSSL_EVP_MD_CTX *ctx);

/*!
    \ingroup openSSL
    \brief Returns block size of message digest in context.

    \return Block size in bytes
    \return 0 if ctx is NULL

    \param ctx EVP_MD_CTX structure

    _Example_
    \code
    WOLFSSL_EVP_MD_CTX* ctx = wolfSSL_EVP_MD_CTX_new();
    wolfSSL_EVP_DigestInit(ctx, wolfSSL_EVP_sha256());
    int blockSize = wolfSSL_EVP_MD_CTX_block_size(ctx);
    \endcode

    \sa wolfSSL_EVP_MD_CTX_size
*/
int wolfSSL_EVP_MD_CTX_block_size(const WOLFSSL_EVP_MD_CTX *ctx);

/*!
    \ingroup openSSL
    \brief Returns NID of cipher.

    \return NID of cipher
    \return 0 if cipher is NULL

    \param cipher EVP_CIPHER structure

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_256_cbc();
    int nid = wolfSSL_EVP_CIPHER_nid(cipher);
    \endcode

    \sa wolfSSL_EVP_CIPHER_CTX_nid
*/
int wolfSSL_EVP_CIPHER_nid(const WOLFSSL_EVP_CIPHER *cipher);

/*!
    \ingroup openSSL
    \brief Initializes message digest context.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_MD_CTX structure to initialize
    \param type Message digest type

    _Example_
    \code
    WOLFSSL_EVP_MD_CTX* ctx = wolfSSL_EVP_MD_CTX_new();
    wolfSSL_EVP_DigestInit(ctx, wolfSSL_EVP_sha256());
    \endcode

    \sa wolfSSL_EVP_DigestUpdate
    \sa wolfSSL_EVP_DigestFinal
*/
int wolfSSL_EVP_DigestInit(WOLFSSL_EVP_MD_CTX* ctx,
                            const WOLFSSL_EVP_MD* type);

/*!
    \ingroup openSSL
    \brief Updates message digest with data.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_MD_CTX structure
    \param data Data to hash
    \param sz Data length

    _Example_
    \code
    WOLFSSL_EVP_MD_CTX* ctx = wolfSSL_EVP_MD_CTX_new();
    wolfSSL_EVP_DigestInit(ctx, wolfSSL_EVP_sha256());
    wolfSSL_EVP_DigestUpdate(ctx, data, dataLen);
    \endcode

    \sa wolfSSL_EVP_DigestInit
    \sa wolfSSL_EVP_DigestFinal
*/
int wolfSSL_EVP_DigestUpdate(WOLFSSL_EVP_MD_CTX* ctx, const void* data,
                              size_t sz);

/*!
    \ingroup openSSL
    \brief Finalizes message digest computation.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_MD_CTX structure
    \param md Output buffer for digest
    \param s Pointer to digest length

    _Example_
    \code
    WOLFSSL_EVP_MD_CTX* ctx = wolfSSL_EVP_MD_CTX_new();
    unsigned char md[32];
    unsigned int s;
    wolfSSL_EVP_DigestInit(ctx, wolfSSL_EVP_sha256());
    wolfSSL_EVP_DigestUpdate(ctx, data, dataLen);
    wolfSSL_EVP_DigestFinal(ctx, md, &s);
    \endcode

    \sa wolfSSL_EVP_DigestInit
    \sa wolfSSL_EVP_DigestUpdate
*/
int wolfSSL_EVP_DigestFinal(WOLFSSL_EVP_MD_CTX* ctx, unsigned char* md,
                             unsigned int* s);

/*!
    \ingroup openSSL
    \brief Finalizes message digest computation (extended version).

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_MD_CTX structure
    \param md Output buffer for digest
    \param s Pointer to digest length

    _Example_
    \code
    WOLFSSL_EVP_MD_CTX* ctx = wolfSSL_EVP_MD_CTX_new();
    unsigned char md[32];
    unsigned int s;
    wolfSSL_EVP_DigestInit(ctx, wolfSSL_EVP_sha256());
    wolfSSL_EVP_DigestUpdate(ctx, data, dataLen);
    wolfSSL_EVP_DigestFinal_ex(ctx, md, &s);
    \endcode

    \sa wolfSSL_EVP_DigestInit
    \sa wolfSSL_EVP_DigestFinal
*/
int wolfSSL_EVP_DigestFinal_ex(WOLFSSL_EVP_MD_CTX* ctx, unsigned char* md,
                                unsigned int* s);

/*!
    \ingroup openSSL
    \brief Finalizes XOF (extendable-output function) digest.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_MD_CTX structure
    \param md Output buffer for digest
    \param sz Desired output length

    _Example_
    \code
    WOLFSSL_EVP_MD_CTX* ctx = wolfSSL_EVP_MD_CTX_new();
    unsigned char md[64];
    wolfSSL_EVP_DigestInit(ctx, wolfSSL_EVP_shake256());
    wolfSSL_EVP_DigestUpdate(ctx, data, dataLen);
    wolfSSL_EVP_DigestFinalXOF(ctx, md, 64);
    \endcode

    \sa wolfSSL_EVP_DigestInit
    \sa wolfSSL_EVP_DigestUpdate
*/
int wolfSSL_EVP_DigestFinalXOF(WOLFSSL_EVP_MD_CTX* ctx, unsigned char* md,
                                size_t sz);

/*!
    \ingroup openSSL
    \brief Updates digest signing operation with data.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_MD_CTX structure
    \param d Data to sign
    \param cnt Data length

    _Example_
    \code
    WOLFSSL_EVP_MD_CTX* ctx = wolfSSL_EVP_MD_CTX_new();
    wolfSSL_EVP_DigestSignInit(ctx, NULL, wolfSSL_EVP_sha256(), NULL, pkey);
    wolfSSL_EVP_DigestSignUpdate(ctx, data, dataLen);
    \endcode

    \sa wolfSSL_EVP_DigestSignInit
    \sa wolfSSL_EVP_DigestSignFinal
*/
int wolfSSL_EVP_DigestSignUpdate(WOLFSSL_EVP_MD_CTX *ctx, const void *d,
                                  unsigned int cnt);

/*!
    \ingroup openSSL
    \brief Finalizes digest signing operation.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_MD_CTX structure
    \param sig Output buffer for signature
    \param siglen Pointer to signature length

    _Example_
    \code
    WOLFSSL_EVP_MD_CTX* ctx = wolfSSL_EVP_MD_CTX_new();
    unsigned char sig[256];
    size_t siglen = sizeof(sig);
    wolfSSL_EVP_DigestSignInit(ctx, NULL, wolfSSL_EVP_sha256(), NULL, pkey);
    wolfSSL_EVP_DigestSignUpdate(ctx, data, dataLen);
    wolfSSL_EVP_DigestSignFinal(ctx, sig, &siglen);
    \endcode

    \sa wolfSSL_EVP_DigestSignInit
    \sa wolfSSL_EVP_DigestSignUpdate
*/
int wolfSSL_EVP_DigestSignFinal(WOLFSSL_EVP_MD_CTX *ctx, unsigned char *sig,
                                 size_t *siglen);

/*!
    \ingroup openSSL
    \brief Updates digest verification operation with data.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_MD_CTX structure
    \param d Data to verify
    \param cnt Data length

    _Example_
    \code
    WOLFSSL_EVP_MD_CTX* ctx = wolfSSL_EVP_MD_CTX_new();
    wolfSSL_EVP_DigestVerifyInit(ctx, NULL, wolfSSL_EVP_sha256(), NULL,
                                  pkey);
    wolfSSL_EVP_DigestVerifyUpdate(ctx, data, dataLen);
    \endcode

    \sa wolfSSL_EVP_DigestVerifyInit
    \sa wolfSSL_EVP_DigestVerifyFinal
*/
int wolfSSL_EVP_DigestVerifyUpdate(WOLFSSL_EVP_MD_CTX *ctx, const void *d,
                                    size_t cnt);

/*!
    \ingroup openSSL
    \brief Finalizes digest verification operation.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_MD_CTX structure
    \param sig Signature to verify
    \param siglen Signature length

    _Example_
    \code
    WOLFSSL_EVP_MD_CTX* ctx = wolfSSL_EVP_MD_CTX_new();
    wolfSSL_EVP_DigestVerifyInit(ctx, NULL, wolfSSL_EVP_sha256(), NULL,
                                  pkey);
    wolfSSL_EVP_DigestVerifyUpdate(ctx, data, dataLen);
    int ret = wolfSSL_EVP_DigestVerifyFinal(ctx, sig, siglen);
    \endcode

    \sa wolfSSL_EVP_DigestVerifyInit
    \sa wolfSSL_EVP_DigestVerifyUpdate
*/
int wolfSSL_EVP_DigestVerifyFinal(WOLFSSL_EVP_MD_CTX *ctx,
                                   const unsigned char *sig, size_t siglen);

/*!
    \ingroup openSSL
    \brief Derives key and IV from password using message digest.

    \return Key length on success
    \return 0 on failure

    \param type Cipher type
    \param md Message digest type
    \param salt Salt value (8 bytes)
    \param data Password data
    \param sz Password length
    \param count Iteration count
    \param key Output buffer for key
    \param iv Output buffer for IV

    _Example_
    \code
    unsigned char key[32], iv[16];
    int keyLen = wolfSSL_EVP_BytesToKey(wolfSSL_EVP_aes_256_cbc(),
                                         wolfSSL_EVP_sha256(), salt,
                                         password, passLen, 1, key, iv);
    \endcode

    \sa wolfSSL_EVP_CipherInit
*/
int wolfSSL_EVP_BytesToKey(const WOLFSSL_EVP_CIPHER* type,
                            const WOLFSSL_EVP_MD* md, const byte* salt,
                            const byte* data, int sz, int count, byte* key,
                            byte* iv);

/*!
    \ingroup openSSL
    \brief Initializes EVP_CIPHER_CTX structure.

    \return none No returns

    \param ctx EVP_CIPHER_CTX structure to initialize

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX ctx;
    wolfSSL_EVP_CIPHER_CTX_init(&ctx);
    \endcode

    \sa wolfSSL_EVP_CIPHER_CTX_cleanup
*/
void wolfSSL_EVP_CIPHER_CTX_init(WOLFSSL_EVP_CIPHER_CTX* ctx);

/*!
    \ingroup openSSL
    \brief Cleans up EVP_CIPHER_CTX structure.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_CIPHER_CTX structure to clean up

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX ctx;
    wolfSSL_EVP_CIPHER_CTX_init(&ctx);
    wolfSSL_EVP_CIPHER_CTX_cleanup(&ctx);
    \endcode

    \sa wolfSSL_EVP_CIPHER_CTX_init
*/
int wolfSSL_EVP_CIPHER_CTX_cleanup(WOLFSSL_EVP_CIPHER_CTX* ctx);

/*!
    \ingroup openSSL
    \brief Controls EVP_CIPHER_CTX parameters.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_CIPHER_CTX structure
    \param type Control type
    \param arg Control argument
    \param ptr Control pointer

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx = wolfSSL_EVP_CIPHER_CTX_new();
    wolfSSL_EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    \endcode

    \sa wolfSSL_EVP_CIPHER_CTX_new
*/
int wolfSSL_EVP_CIPHER_CTX_ctrl(WOLFSSL_EVP_CIPHER_CTX *ctx, int type,
                                 int arg, void *ptr);

/*!
    \ingroup openSSL
    \brief Returns IV length of cipher context.

    \return IV length in bytes
    \return 0 if ctx is NULL

    \param ctx EVP_CIPHER_CTX structure

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx = wolfSSL_EVP_CIPHER_CTX_new();
    int ivLen = wolfSSL_EVP_CIPHER_CTX_iv_length(ctx);
    \endcode

    \sa wolfSSL_EVP_CIPHER_iv_length
*/
int wolfSSL_EVP_CIPHER_CTX_iv_length(const WOLFSSL_EVP_CIPHER_CTX* ctx);

/*!
    \ingroup openSSL
    \brief Returns IV length of cipher.

    \return IV length in bytes
    \return 0 if cipher is NULL

    \param cipher EVP_CIPHER structure

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_256_cbc();
    int ivLen = wolfSSL_EVP_CIPHER_iv_length(cipher);
    \endcode

    \sa wolfSSL_EVP_CIPHER_CTX_iv_length
*/
int wolfSSL_EVP_CIPHER_iv_length(const WOLFSSL_EVP_CIPHER* cipher);

/*!
    \ingroup openSSL
    \brief Returns key length of cipher.

    \return Key length in bytes
    \return 0 if cipher is NULL

    \param c EVP_CIPHER structure

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_aes_256_cbc();
    int keyLen = wolfSSL_EVP_Cipher_key_length(cipher);
    \endcode

    \sa wolfSSL_EVP_CIPHER_CTX_key_length
*/
int wolfSSL_EVP_Cipher_key_length(const WOLFSSL_EVP_CIPHER* c);

/*!
    \ingroup openSSL
    \brief Initializes cipher context for encryption or decryption.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_CIPHER_CTX structure
    \param type Cipher type
    \param key Encryption key
    \param iv Initialization vector
    \param enc 1 for encryption, 0 for decryption

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx = wolfSSL_EVP_CIPHER_CTX_new();
    wolfSSL_EVP_CipherInit(ctx, wolfSSL_EVP_aes_256_cbc(), key, iv, 1);
    \endcode

    \sa wolfSSL_EVP_CipherUpdate
    \sa wolfSSL_EVP_CipherFinal
*/
int wolfSSL_EVP_CipherInit(WOLFSSL_EVP_CIPHER_CTX* ctx,
                            const WOLFSSL_EVP_CIPHER* type,
                            const unsigned char* key,
                            const unsigned char* iv, int enc);

/*!
    \ingroup openSSL
    \brief Finalizes cipher operation (extended version).

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_CIPHER_CTX structure
    \param out Output buffer
    \param outl Pointer to output length
    \param enc 1 for encryption, 0 for decryption

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx = wolfSSL_EVP_CIPHER_CTX_new();
    unsigned char out[32];
    int outl;
    wolfSSL_EVP_CipherInit(ctx, wolfSSL_EVP_aes_256_cbc(), key, iv, 1);
    wolfSSL_EVP_CipherUpdate(ctx, out, &outl, data, dataLen);
    wolfSSL_EVP_CipherFinal_ex(ctx, out + outl, &outl, 1);
    \endcode

    \sa wolfSSL_EVP_CipherInit
    \sa wolfSSL_EVP_CipherUpdate
*/
int wolfSSL_EVP_CipherFinal_ex(WOLFSSL_EVP_CIPHER_CTX *ctx,
                                unsigned char *out, int *outl, int enc);

/*!
    \ingroup openSSL
    \brief Finalizes encryption operation.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_CIPHER_CTX structure
    \param out Output buffer
    \param outl Pointer to output length

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx = wolfSSL_EVP_CIPHER_CTX_new();
    unsigned char out[32];
    int outl;
    wolfSSL_EVP_EncryptInit(ctx, wolfSSL_EVP_aes_256_cbc(), key, iv);
    wolfSSL_EVP_EncryptUpdate(ctx, out, &outl, data, dataLen);
    wolfSSL_EVP_EncryptFinal(ctx, out + outl, &outl);
    \endcode

    \sa wolfSSL_EVP_EncryptInit
    \sa wolfSSL_EVP_EncryptUpdate
*/
int wolfSSL_EVP_EncryptFinal(WOLFSSL_EVP_CIPHER_CTX *ctx,
                              unsigned char *out, int *outl);

/*!
    \ingroup openSSL
    \brief Finalizes encryption operation (extended version).

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_CIPHER_CTX structure
    \param out Output buffer
    \param outl Pointer to output length

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx = wolfSSL_EVP_CIPHER_CTX_new();
    unsigned char out[32];
    int outl;
    wolfSSL_EVP_EncryptInit_ex(ctx, wolfSSL_EVP_aes_256_cbc(), NULL, key,
                                iv);
    wolfSSL_EVP_EncryptUpdate(ctx, out, &outl, data, dataLen);
    wolfSSL_EVP_EncryptFinal_ex(ctx, out + outl, &outl);
    \endcode

    \sa wolfSSL_EVP_EncryptInit_ex
    \sa wolfSSL_EVP_EncryptUpdate
*/
int wolfSSL_EVP_EncryptFinal_ex(WOLFSSL_EVP_CIPHER_CTX *ctx,
                                 unsigned char *out, int *outl);

/*!
    \ingroup openSSL
    \brief Finalizes decryption operation.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_CIPHER_CTX structure
    \param out Output buffer
    \param outl Pointer to output length

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx = wolfSSL_EVP_CIPHER_CTX_new();
    unsigned char out[32];
    int outl;
    wolfSSL_EVP_DecryptInit(ctx, wolfSSL_EVP_aes_256_cbc(), key, iv);
    wolfSSL_EVP_DecryptUpdate(ctx, out, &outl, data, dataLen);
    wolfSSL_EVP_DecryptFinal(ctx, out + outl, &outl);
    \endcode

    \sa wolfSSL_EVP_DecryptInit
    \sa wolfSSL_EVP_DecryptUpdate
*/
int wolfSSL_EVP_DecryptFinal(WOLFSSL_EVP_CIPHER_CTX *ctx,
                              unsigned char *out, int *outl);

/*!
    \ingroup openSSL
    \brief Finalizes decryption operation (extended version).

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_CIPHER_CTX structure
    \param out Output buffer
    \param outl Pointer to output length

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx = wolfSSL_EVP_CIPHER_CTX_new();
    unsigned char out[32];
    int outl;
    wolfSSL_EVP_DecryptInit_ex(ctx, wolfSSL_EVP_aes_256_cbc(), NULL, key,
                                iv);
    wolfSSL_EVP_DecryptUpdate(ctx, out, &outl, data, dataLen);
    wolfSSL_EVP_DecryptFinal_ex(ctx, out + outl, &outl);
    \endcode

    \sa wolfSSL_EVP_DecryptInit_ex
    \sa wolfSSL_EVP_DecryptUpdate
*/
int wolfSSL_EVP_DecryptFinal_ex(WOLFSSL_EVP_CIPHER_CTX *ctx,
                                 unsigned char *out, int *outl);

/*!
    \ingroup openSSL
    \brief Finalizes decryption operation (legacy version).

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_CIPHER_CTX structure
    \param out Output buffer
    \param outl Pointer to output length

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx = wolfSSL_EVP_CIPHER_CTX_new();
    unsigned char out[32];
    int outl;
    wolfSSL_EVP_DecryptInit(ctx, wolfSSL_EVP_aes_256_cbc(), key, iv);
    wolfSSL_EVP_DecryptUpdate(ctx, out, &outl, data, dataLen);
    wolfSSL_EVP_DecryptFinal_legacy(ctx, out + outl, &outl);
    \endcode

    \sa wolfSSL_EVP_DecryptFinal_ex
*/
int wolfSSL_EVP_DecryptFinal_legacy(WOLFSSL_EVP_CIPHER_CTX *ctx,
                                     unsigned char *out, int *outl);

/*!
    \ingroup openSSL
    \brief Frees EVP_CIPHER_CTX structure.

    \return none No returns

    \param ctx EVP_CIPHER_CTX structure to free

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx = wolfSSL_EVP_CIPHER_CTX_new();
    wolfSSL_EVP_CIPHER_CTX_free(ctx);
    \endcode

    \sa wolfSSL_EVP_CIPHER_CTX_new
*/
void wolfSSL_EVP_CIPHER_CTX_free(WOLFSSL_EVP_CIPHER_CTX *ctx);

/*!
    \ingroup openSSL
    \brief Resets EVP_CIPHER_CTX structure.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_CIPHER_CTX structure to reset

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx = wolfSSL_EVP_CIPHER_CTX_new();
    wolfSSL_EVP_CIPHER_CTX_reset(ctx);
    \endcode

    \sa wolfSSL_EVP_CIPHER_CTX_new
*/
int wolfSSL_EVP_CIPHER_CTX_reset(WOLFSSL_EVP_CIPHER_CTX *ctx);

/*!
    \ingroup openSSL
    \brief Returns NID of cipher in context.

    \return NID of cipher
    \return 0 if ctx is NULL

    \param ctx EVP_CIPHER_CTX structure

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx = wolfSSL_EVP_CIPHER_CTX_new();
    wolfSSL_EVP_CipherInit(ctx, wolfSSL_EVP_aes_256_cbc(), key, iv, 1);
    int nid = wolfSSL_EVP_CIPHER_CTX_nid(ctx);
    \endcode

    \sa wolfSSL_EVP_CIPHER_nid
*/
int wolfSSL_EVP_CIPHER_CTX_nid(const WOLFSSL_EVP_CIPHER_CTX *ctx);

/*!
    \ingroup openSSL
    \brief Returns key length of cipher context.

    \return Key length in bytes
    \return 0 if ctx is NULL

    \param ctx EVP_CIPHER_CTX structure

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx = wolfSSL_EVP_CIPHER_CTX_new();
    int keyLen = wolfSSL_EVP_CIPHER_CTX_key_length(ctx);
    \endcode

    \sa wolfSSL_EVP_Cipher_key_length
*/
int wolfSSL_EVP_CIPHER_CTX_key_length(WOLFSSL_EVP_CIPHER_CTX* ctx);

/*!
    \ingroup openSSL
    \brief Sets IV length of cipher context.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_CIPHER_CTX structure
    \param ivLen IV length in bytes

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx = wolfSSL_EVP_CIPHER_CTX_new();
    wolfSSL_EVP_CIPHER_CTX_set_iv_length(ctx, 12);
    \endcode

    \sa wolfSSL_EVP_CIPHER_CTX_iv_length
*/
int wolfSSL_EVP_CIPHER_CTX_set_iv_length(WOLFSSL_EVP_CIPHER_CTX* ctx,
                                          int ivLen);

/*!
    \ingroup openSSL
    \brief Sets IV of cipher context.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_CIPHER_CTX structure
    \param iv IV buffer
    \param ivLen IV length

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx = wolfSSL_EVP_CIPHER_CTX_new();
    unsigned char iv[16];
    wolfSSL_EVP_CIPHER_CTX_set_iv(ctx, iv, 16);
    \endcode

    \sa wolfSSL_EVP_CIPHER_CTX_get_iv
*/
int wolfSSL_EVP_CIPHER_CTX_set_iv(WOLFSSL_EVP_CIPHER_CTX* ctx, byte* iv,
                                   int ivLen);

/*!
    \ingroup openSSL
    \brief Gets IV from cipher context.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_CIPHER_CTX structure
    \param iv Output buffer for IV
    \param ivLen IV length

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx = wolfSSL_EVP_CIPHER_CTX_new();
    unsigned char iv[16];
    wolfSSL_EVP_CIPHER_CTX_get_iv(ctx, iv, 16);
    \endcode

    \sa wolfSSL_EVP_CIPHER_CTX_set_iv
*/
int wolfSSL_EVP_CIPHER_CTX_get_iv(WOLFSSL_EVP_CIPHER_CTX* ctx, byte* iv,
                                   int ivLen);

/*!
    \ingroup openSSL
    \brief Performs cipher operation on data.

    \return Number of bytes processed on success
    \return Negative value on failure

    \param ctx EVP_CIPHER_CTX structure
    \param dst Output buffer
    \param src Input buffer
    \param len Input length

    _Example_
    \code
    WOLFSSL_EVP_CIPHER_CTX* ctx = wolfSSL_EVP_CIPHER_CTX_new();
    unsigned char out[128];
    wolfSSL_EVP_CipherInit(ctx, wolfSSL_EVP_aes_256_cbc(), key, iv, 1);
    int len = wolfSSL_EVP_Cipher(ctx, out, data, dataLen);
    \endcode

    \sa wolfSSL_EVP_CipherInit
*/
int wolfSSL_EVP_Cipher(WOLFSSL_EVP_CIPHER_CTX* ctx, unsigned char* dst,
                       const unsigned char* src, unsigned int len);

/*!
    \ingroup openSSL
    \brief Gets cipher by NID.

    \return Pointer to EVP_CIPHER structure
    \return NULL if NID not found

    \param id Cipher NID

    _Example_
    \code
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_get_cipherbynid(NID_aes_256_cbc);
    \endcode

    \sa wolfSSL_EVP_CIPHER_nid
*/
const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_get_cipherbynid(int id);

/*!
    \ingroup openSSL
    \brief Gets message digest by NID.

    \return Pointer to EVP_MD structure
    \return NULL if NID not found

    \param id Message digest NID

    _Example_
    \code
    const WOLFSSL_EVP_MD* md = wolfSSL_EVP_get_digestbynid(NID_sha256);
    \endcode

    \sa wolfSSL_EVP_MD_type
*/
const WOLFSSL_EVP_MD* wolfSSL_EVP_get_digestbynid(int id);

/*!
    \ingroup openSSL
    \brief Assigns RSA key to EVP_PKEY structure.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param pkey EVP_PKEY structure
    \param key RSA key to assign

    _Example_
    \code
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_EVP_PKEY_new();
    WOLFSSL_RSA* rsa = wolfSSL_RSA_new();
    wolfSSL_EVP_PKEY_assign_RSA(pkey, rsa);
    \endcode

    \sa wolfSSL_EVP_PKEY_assign_EC_KEY
    \sa wolfSSL_EVP_PKEY_get0_RSA
*/
int wolfSSL_EVP_PKEY_assign_RSA(WOLFSSL_EVP_PKEY* pkey, WOLFSSL_RSA* key);

/*!
    \ingroup openSSL
    \brief Assigns EC key to EVP_PKEY structure.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param pkey EVP_PKEY structure
    \param key EC_KEY to assign

    _Example_
    \code
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_EVP_PKEY_new();
    WOLFSSL_EC_KEY* ec = wolfSSL_EC_KEY_new();
    wolfSSL_EVP_PKEY_assign_EC_KEY(pkey, ec);
    \endcode

    \sa wolfSSL_EVP_PKEY_assign_RSA
    \sa wolfSSL_EVP_PKEY_get0_EC_KEY
*/
int wolfSSL_EVP_PKEY_assign_EC_KEY(WOLFSSL_EVP_PKEY* pkey,
                                    WOLFSSL_EC_KEY* key);

/*!
    \ingroup openSSL
    \brief Assigns DSA key to EVP_PKEY structure.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param pkey EVP_PKEY structure
    \param key DSA key to assign

    _Example_
    \code
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_EVP_PKEY_new();
    WOLFSSL_DSA* dsa = wolfSSL_DSA_new();
    wolfSSL_EVP_PKEY_assign_DSA(pkey, dsa);
    \endcode

    \sa wolfSSL_EVP_PKEY_assign_RSA
    \sa wolfSSL_EVP_PKEY_get0_DSA
*/
int wolfSSL_EVP_PKEY_assign_DSA(WOLFSSL_EVP_PKEY* pkey, WOLFSSL_DSA* key);

/*!
    \ingroup openSSL
    \brief Assigns DH key to EVP_PKEY structure.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param pkey EVP_PKEY structure
    \param key DH key to assign

    _Example_
    \code
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_EVP_PKEY_new();
    WOLFSSL_DH* dh = wolfSSL_DH_new();
    wolfSSL_EVP_PKEY_assign_DH(pkey, dh);
    \endcode

    \sa wolfSSL_EVP_PKEY_assign_RSA
    \sa wolfSSL_EVP_PKEY_get0_DH
*/
int wolfSSL_EVP_PKEY_assign_DH(WOLFSSL_EVP_PKEY* pkey, WOLFSSL_DH* key);

/*!
    \ingroup openSSL
    \brief Gets RSA key from EVP_PKEY (no reference count increment).

    \return Pointer to RSA key
    \return NULL if pkey is NULL or not RSA

    \param pkey EVP_PKEY structure

    _Example_
    \code
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_EVP_PKEY_new();
    WOLFSSL_RSA* rsa = wolfSSL_EVP_PKEY_get0_RSA(pkey);
    \endcode

    \sa wolfSSL_EVP_PKEY_get1_RSA
    \sa wolfSSL_EVP_PKEY_assign_RSA
*/
WOLFSSL_RSA* wolfSSL_EVP_PKEY_get0_RSA(WOLFSSL_EVP_PKEY *pkey);

/*!
    \ingroup openSSL
    \brief Gets DSA key from EVP_PKEY (no reference count increment).

    \return Pointer to DSA key
    \return NULL if pkey is NULL or not DSA

    \param pkey EVP_PKEY structure

    _Example_
    \code
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_EVP_PKEY_new();
    WOLFSSL_DSA* dsa = wolfSSL_EVP_PKEY_get0_DSA(pkey);
    \endcode

    \sa wolfSSL_EVP_PKEY_get1_DSA
    \sa wolfSSL_EVP_PKEY_assign_DSA
*/
WOLFSSL_DSA* wolfSSL_EVP_PKEY_get0_DSA(WOLFSSL_EVP_PKEY *pkey);

/*!
    \ingroup openSSL
    \brief Gets RSA key from EVP_PKEY (increments reference count).

    \return Pointer to RSA key
    \return NULL if pkey is NULL or not RSA

    \param key EVP_PKEY structure

    _Example_
    \code
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_EVP_PKEY_new();
    WOLFSSL_RSA* rsa = wolfSSL_EVP_PKEY_get1_RSA(pkey);
    wolfSSL_RSA_free(rsa);
    \endcode

    \sa wolfSSL_EVP_PKEY_get0_RSA
    \sa wolfSSL_EVP_PKEY_set1_RSA
*/
WOLFSSL_RSA* wolfSSL_EVP_PKEY_get1_RSA(WOLFSSL_EVP_PKEY* key);

/*!
    \ingroup openSSL
    \brief Gets DSA key from EVP_PKEY (increments reference count).

    \return Pointer to DSA key
    \return NULL if pkey is NULL or not DSA

    \param key EVP_PKEY structure

    _Example_
    \code
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_EVP_PKEY_new();
    WOLFSSL_DSA* dsa = wolfSSL_EVP_PKEY_get1_DSA(pkey);
    wolfSSL_DSA_free(dsa);
    \endcode

    \sa wolfSSL_EVP_PKEY_get0_DSA
    \sa wolfSSL_EVP_PKEY_set1_DSA
*/
WOLFSSL_DSA* wolfSSL_EVP_PKEY_get1_DSA(WOLFSSL_EVP_PKEY* key);

/*!
    \ingroup openSSL
    \brief Gets DH key from EVP_PKEY (no reference count increment).

    \return Pointer to DH key
    \return NULL if key is NULL or not DH

    \param key EVP_PKEY structure

    _Example_
    \code
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_EVP_PKEY_new();
    WOLFSSL_DH* dh = wolfSSL_EVP_PKEY_get0_DH(pkey);
    \endcode

    \sa wolfSSL_EVP_PKEY_get1_DH
    \sa wolfSSL_EVP_PKEY_assign_DH
*/
WOLFSSL_DH* wolfSSL_EVP_PKEY_get0_DH(WOLFSSL_EVP_PKEY* key);

/*!
    \ingroup openSSL
    \brief Gets DH key from EVP_PKEY (increments reference count).

    \return Pointer to DH key
    \return NULL if key is NULL or not DH

    \param key EVP_PKEY structure

    _Example_
    \code
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_EVP_PKEY_new();
    WOLFSSL_DH* dh = wolfSSL_EVP_PKEY_get1_DH(pkey);
    wolfSSL_DH_free(dh);
    \endcode

    \sa wolfSSL_EVP_PKEY_get0_DH
    \sa wolfSSL_EVP_PKEY_set1_DH
*/
WOLFSSL_DH* wolfSSL_EVP_PKEY_get1_DH(WOLFSSL_EVP_PKEY* key);

/*!
    \ingroup openSSL
    \brief Sets RSA key in EVP_PKEY (increments reference count).

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param pkey EVP_PKEY structure
    \param key RSA key to set

    _Example_
    \code
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_EVP_PKEY_new();
    WOLFSSL_RSA* rsa = wolfSSL_RSA_new();
    wolfSSL_EVP_PKEY_set1_RSA(pkey, rsa);
    \endcode

    \sa wolfSSL_EVP_PKEY_get1_RSA
    \sa wolfSSL_EVP_PKEY_assign_RSA
*/
int wolfSSL_EVP_PKEY_set1_RSA(WOLFSSL_EVP_PKEY *pkey, WOLFSSL_RSA *key);

/*!
    \ingroup openSSL
    \brief Sets DSA key in EVP_PKEY (increments reference count).

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param pkey EVP_PKEY structure
    \param key DSA key to set

    _Example_
    \code
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_EVP_PKEY_new();
    WOLFSSL_DSA* dsa = wolfSSL_DSA_new();
    wolfSSL_EVP_PKEY_set1_DSA(pkey, dsa);
    \endcode

    \sa wolfSSL_EVP_PKEY_get1_DSA
    \sa wolfSSL_EVP_PKEY_assign_DSA
*/
int wolfSSL_EVP_PKEY_set1_DSA(WOLFSSL_EVP_PKEY *pkey, WOLFSSL_DSA *key);

/*!
    \ingroup openSSL
    \brief Sets DH key in EVP_PKEY (increments reference count).

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param pkey EVP_PKEY structure
    \param key DH key to set

    _Example_
    \code
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_EVP_PKEY_new();
    WOLFSSL_DH* dh = wolfSSL_DH_new();
    wolfSSL_EVP_PKEY_set1_DH(pkey, dh);
    \endcode

    \sa wolfSSL_EVP_PKEY_get1_DH
    \sa wolfSSL_EVP_PKEY_assign_DH
*/
int wolfSSL_EVP_PKEY_set1_DH(WOLFSSL_EVP_PKEY *pkey, WOLFSSL_DH *key);

/*!
    \ingroup openSSL
    \brief Sets EC key in EVP_PKEY (increments reference count).

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param pkey EVP_PKEY structure
    \param key EC_KEY to set

    _Example_
    \code
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_EVP_PKEY_new();
    WOLFSSL_EC_KEY* ec = wolfSSL_EC_KEY_new();
    wolfSSL_EVP_PKEY_set1_EC_KEY(pkey, ec);
    \endcode

    \sa wolfSSL_EVP_PKEY_get1_EC_KEY
    \sa wolfSSL_EVP_PKEY_assign_EC_KEY
*/
int wolfSSL_EVP_PKEY_set1_EC_KEY(WOLFSSL_EVP_PKEY *pkey,
                                  WOLFSSL_EC_KEY *key);

/*!
    \ingroup openSSL
    \brief Assigns key of specified type to EVP_PKEY.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param pkey EVP_PKEY structure
    \param type Key type (EVP_PKEY_RSA, EVP_PKEY_EC, etc.)
    \param key Key pointer

    _Example_
    \code
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_EVP_PKEY_new();
    WOLFSSL_RSA* rsa = wolfSSL_RSA_new();
    wolfSSL_EVP_PKEY_assign(pkey, EVP_PKEY_RSA, rsa);
    \endcode

    \sa wolfSSL_EVP_PKEY_assign_RSA
    \sa wolfSSL_EVP_PKEY_assign_EC_KEY
*/
int wolfSSL_EVP_PKEY_assign(WOLFSSL_EVP_PKEY *pkey, int type, void *key);

/*!
    \ingroup openSSL
    \brief Gets HMAC key from EVP_PKEY.

    \return Pointer to HMAC key
    \return NULL if pkey is NULL or not HMAC

    \param pkey EVP_PKEY structure
    \param len Pointer to receive key length

    _Example_
    \code
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_EVP_PKEY_new_mac_key(EVP_PKEY_HMAC,
                                                           NULL, key, keyLen);
    size_t len;
    const unsigned char* hmac = wolfSSL_EVP_PKEY_get0_hmac(pkey, &len);
    \endcode

    \sa wolfSSL_EVP_PKEY_new_mac_key
*/
const unsigned char* wolfSSL_EVP_PKEY_get0_hmac(const WOLFSSL_EVP_PKEY* pkey,
                                                 size_t* len);

/*!
    \ingroup openSSL
    \brief Initializes EVP_PKEY_CTX for signing operation.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_PKEY_CTX structure

    _Example_
    \code
    WOLFSSL_EVP_PKEY_CTX* ctx = wolfSSL_EVP_PKEY_CTX_new(pkey, NULL);
    wolfSSL_EVP_PKEY_sign_init(ctx);
    \endcode

    \sa wolfSSL_EVP_PKEY_sign
    \sa wolfSSL_EVP_PKEY_CTX_new
*/
int wolfSSL_EVP_PKEY_sign_init(WOLFSSL_EVP_PKEY_CTX *ctx);

/*!
    \ingroup openSSL
    \brief Signs data using EVP_PKEY_CTX.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_PKEY_CTX structure
    \param sig Output buffer for signature
    \param siglen Pointer to signature length
    \param tbs Data to be signed
    \param tbslen Data length

    _Example_
    \code
    WOLFSSL_EVP_PKEY_CTX* ctx = wolfSSL_EVP_PKEY_CTX_new(pkey, NULL);
    unsigned char sig[256];
    size_t siglen = sizeof(sig);
    wolfSSL_EVP_PKEY_sign_init(ctx);
    wolfSSL_EVP_PKEY_sign(ctx, sig, &siglen, data, dataLen);
    \endcode

    \sa wolfSSL_EVP_PKEY_sign_init
    \sa wolfSSL_EVP_PKEY_verify
*/
int wolfSSL_EVP_PKEY_sign(WOLFSSL_EVP_PKEY_CTX *ctx, unsigned char *sig,
                           size_t *siglen, const unsigned char *tbs,
                           size_t tbslen);

/*!
    \ingroup openSSL
    \brief Initializes EVP_PKEY_CTX for verification operation.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_PKEY_CTX structure

    _Example_
    \code
    WOLFSSL_EVP_PKEY_CTX* ctx = wolfSSL_EVP_PKEY_CTX_new(pkey, NULL);
    wolfSSL_EVP_PKEY_verify_init(ctx);
    \endcode

    \sa wolfSSL_EVP_PKEY_verify
    \sa wolfSSL_EVP_PKEY_CTX_new
*/
int wolfSSL_EVP_PKEY_verify_init(WOLFSSL_EVP_PKEY_CTX *ctx);

/*!
    \ingroup openSSL
    \brief Verifies signature using EVP_PKEY_CTX.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_PKEY_CTX structure
    \param sig Signature to verify
    \param siglen Signature length
    \param tbs Data that was signed
    \param tbslen Data length

    _Example_
    \code
    WOLFSSL_EVP_PKEY_CTX* ctx = wolfSSL_EVP_PKEY_CTX_new(pkey, NULL);
    wolfSSL_EVP_PKEY_verify_init(ctx);
    int ret = wolfSSL_EVP_PKEY_verify(ctx, sig, siglen, data, dataLen);
    \endcode

    \sa wolfSSL_EVP_PKEY_verify_init
    \sa wolfSSL_EVP_PKEY_sign
*/
int wolfSSL_EVP_PKEY_verify(WOLFSSL_EVP_PKEY_CTX *ctx,
                             const unsigned char *sig, size_t siglen,
                             const unsigned char *tbs, size_t tbslen);

/*!
    \ingroup openSSL
    \brief Initializes EVP_PKEY_CTX for parameter generation.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_PKEY_CTX structure

    _Example_
    \code
    WOLFSSL_EVP_PKEY_CTX* ctx = wolfSSL_EVP_PKEY_CTX_new_id(EVP_PKEY_EC,
                                                             NULL);
    wolfSSL_EVP_PKEY_paramgen_init(ctx);
    \endcode

    \sa wolfSSL_EVP_PKEY_paramgen
    \sa wolfSSL_EVP_PKEY_CTX_new_id
*/
int wolfSSL_EVP_PKEY_paramgen_init(WOLFSSL_EVP_PKEY_CTX *ctx);

/*!
    \ingroup openSSL
    \brief Sets EC curve NID for parameter generation.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_PKEY_CTX structure
    \param nid Curve NID

    _Example_
    \code
    WOLFSSL_EVP_PKEY_CTX* ctx = wolfSSL_EVP_PKEY_CTX_new_id(EVP_PKEY_EC,
                                                             NULL);
    wolfSSL_EVP_PKEY_paramgen_init(ctx);
    wolfSSL_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1);
    \endcode

    \sa wolfSSL_EVP_PKEY_paramgen
*/
int wolfSSL_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(WOLFSSL_EVP_PKEY_CTX *ctx,
                                                     int nid);

/*!
    \ingroup openSSL
    \brief Generates parameters for EVP_PKEY.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_PKEY_CTX structure
    \param pkey Pointer to receive generated EVP_PKEY

    _Example_
    \code
    WOLFSSL_EVP_PKEY_CTX* ctx = wolfSSL_EVP_PKEY_CTX_new_id(EVP_PKEY_EC,
                                                             NULL);
    WOLFSSL_EVP_PKEY* pkey = NULL;
    wolfSSL_EVP_PKEY_paramgen_init(ctx);
    wolfSSL_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1);
    wolfSSL_EVP_PKEY_paramgen(ctx, &pkey);
    \endcode

    \sa wolfSSL_EVP_PKEY_paramgen_init
    \sa wolfSSL_EVP_PKEY_keygen
*/
int wolfSSL_EVP_PKEY_paramgen(WOLFSSL_EVP_PKEY_CTX* ctx,
                               WOLFSSL_EVP_PKEY** pkey);

/*!
    \ingroup openSSL
    \brief Sets EC parameter encoding flag.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_PKEY_CTX structure
    \param flag Encoding flag

    _Example_
    \code
    WOLFSSL_EVP_PKEY_CTX* ctx = wolfSSL_EVP_PKEY_CTX_new_id(EVP_PKEY_EC,
                                                             NULL);
    wolfSSL_EVP_PKEY_CTX_set_ec_param_enc(ctx, OPENSSL_EC_NAMED_CURVE);
    \endcode

    \sa wolfSSL_EVP_PKEY_paramgen
*/
int wolfSSL_EVP_PKEY_CTX_set_ec_param_enc(WOLFSSL_EVP_PKEY_CTX *ctx,
                                           int flag);

/*!
    \ingroup openSSL
    \brief Initializes EVP_PKEY_CTX for key generation.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_PKEY_CTX structure

    _Example_
    \code
    WOLFSSL_EVP_PKEY_CTX* ctx = wolfSSL_EVP_PKEY_CTX_new_id(EVP_PKEY_RSA,
                                                             NULL);
    wolfSSL_EVP_PKEY_keygen_init(ctx);
    \endcode

    \sa wolfSSL_EVP_PKEY_keygen
    \sa wolfSSL_EVP_PKEY_CTX_new_id
*/
int wolfSSL_EVP_PKEY_keygen_init(WOLFSSL_EVP_PKEY_CTX *ctx);

/*!
    \ingroup openSSL
    \brief Generates key pair for EVP_PKEY.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_PKEY_CTX structure
    \param ppkey Pointer to receive generated EVP_PKEY

    _Example_
    \code
    WOLFSSL_EVP_PKEY_CTX* ctx = wolfSSL_EVP_PKEY_CTX_new_id(EVP_PKEY_RSA,
                                                             NULL);
    WOLFSSL_EVP_PKEY* pkey = NULL;
    wolfSSL_EVP_PKEY_keygen_init(ctx);
    wolfSSL_EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    wolfSSL_EVP_PKEY_keygen(ctx, &pkey);
    \endcode

    \sa wolfSSL_EVP_PKEY_keygen_init
    \sa wolfSSL_EVP_PKEY_paramgen
*/
int wolfSSL_EVP_PKEY_keygen(WOLFSSL_EVP_PKEY_CTX *ctx,
                             WOLFSSL_EVP_PKEY **ppkey);

/*!
    \ingroup openSSL
    \brief Returns key size in bits.

    \return Key size in bits
    \return 0 if pkey is NULL

    \param pkey EVP_PKEY structure

    _Example_
    \code
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_EVP_PKEY_new();
    int bits = wolfSSL_EVP_PKEY_bits(pkey);
    \endcode

    \sa wolfSSL_EVP_PKEY_size
    \sa wolfSSL_EVP_PKEY_type
*/
int wolfSSL_EVP_PKEY_bits(const WOLFSSL_EVP_PKEY *pkey);

/*!
    \ingroup openSSL
    \brief Checks if EVP_PKEY is of specified type.

    \return 1 if pkey matches type
    \return 0 otherwise

    \param pkey EVP_PKEY structure
    \param name Type name string

    _Example_
    \code
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_EVP_PKEY_new();
    if (wolfSSL_EVP_PKEY_is_a(pkey, "RSA")) {
        // pkey is RSA
    }
    \endcode

    \sa wolfSSL_EVP_PKEY_type
    \sa wolfSSL_EVP_PKEY_base_id
*/
int wolfSSL_EVP_PKEY_is_a(const WOLFSSL_EVP_PKEY *pkey, const char *name);

/*!
    \ingroup openSSL
    \brief Frees EVP_PKEY_CTX structure.

    \return none No returns

    \param ctx EVP_PKEY_CTX structure to free

    _Example_
    \code
    WOLFSSL_EVP_PKEY_CTX* ctx = wolfSSL_EVP_PKEY_CTX_new(pkey, NULL);
    wolfSSL_EVP_PKEY_CTX_free(ctx);
    \endcode

    \sa wolfSSL_EVP_PKEY_CTX_new
*/
void wolfSSL_EVP_PKEY_CTX_free(WOLFSSL_EVP_PKEY_CTX *ctx);

/*!
    \ingroup openSSL
    \brief Sets RSA padding mode.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_PKEY_CTX structure
    \param padding Padding mode

    _Example_
    \code
    WOLFSSL_EVP_PKEY_CTX* ctx = wolfSSL_EVP_PKEY_CTX_new(pkey, NULL);
    wolfSSL_EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
    \endcode

    \sa wolfSSL_EVP_PKEY_sign
    \sa wolfSSL_EVP_PKEY_verify
*/
int wolfSSL_EVP_PKEY_CTX_set_rsa_padding(WOLFSSL_EVP_PKEY_CTX *ctx,
                                          int padding);

/*!
    \ingroup openSSL
    \brief Sets signature message digest.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_PKEY_CTX structure
    \param md Message digest type

    _Example_
    \code
    WOLFSSL_EVP_PKEY_CTX* ctx = wolfSSL_EVP_PKEY_CTX_new(pkey, NULL);
    wolfSSL_EVP_PKEY_sign_init(ctx);
    wolfSSL_EVP_PKEY_CTX_set_signature_md(ctx, wolfSSL_EVP_sha256());
    \endcode

    \sa wolfSSL_EVP_PKEY_sign
*/
int wolfSSL_EVP_PKEY_CTX_set_signature_md(WOLFSSL_EVP_PKEY_CTX *ctx,
                                           const WOLFSSL_EVP_MD* md);

/*!
    \ingroup openSSL
    \brief Sets RSA key generation bit length.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_PKEY_CTX structure
    \param bits Key size in bits

    _Example_
    \code
    WOLFSSL_EVP_PKEY_CTX* ctx = wolfSSL_EVP_PKEY_CTX_new_id(EVP_PKEY_RSA,
                                                             NULL);
    wolfSSL_EVP_PKEY_keygen_init(ctx);
    wolfSSL_EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    \endcode

    \sa wolfSSL_EVP_PKEY_keygen
*/
int wolfSSL_EVP_PKEY_CTX_set_rsa_keygen_bits(WOLFSSL_EVP_PKEY_CTX *ctx,
                                              int bits);

/*!
    \ingroup openSSL
    \brief Sets RSA PSS salt length.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_PKEY_CTX structure
    \param saltlen Salt length in bytes

    _Example_
    \code
    WOLFSSL_EVP_PKEY_CTX* ctx = wolfSSL_EVP_PKEY_CTX_new(pkey, NULL);
    wolfSSL_EVP_PKEY_sign_init(ctx);
    wolfSSL_EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING);
    wolfSSL_EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, 32);
    \endcode

    \sa wolfSSL_EVP_PKEY_sign
*/
int wolfSSL_EVP_PKEY_CTX_set_rsa_pss_saltlen(WOLFSSL_EVP_PKEY_CTX *ctx,
                                              int saltlen);

/*!
    \ingroup openSSL
    \brief Sets RSA MGF1 message digest.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_PKEY_CTX structure
    \param md Message digest for MGF1

    _Example_
    \code
    WOLFSSL_EVP_PKEY_CTX* ctx = wolfSSL_EVP_PKEY_CTX_new(pkey, NULL);
    wolfSSL_EVP_PKEY_sign_init(ctx);
    wolfSSL_EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, wolfSSL_EVP_sha256());
    \endcode

    \sa wolfSSL_EVP_PKEY_sign
*/
int wolfSSL_EVP_PKEY_CTX_set_rsa_mgf1_md(WOLFSSL_EVP_PKEY_CTX *ctx,
                                          const WOLFSSL_EVP_MD *md);

/*!
    \ingroup openSSL
    \brief Sets RSA OAEP message digest.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_PKEY_CTX structure
    \param md Message digest for OAEP

    _Example_
    \code
    WOLFSSL_EVP_PKEY_CTX* ctx = wolfSSL_EVP_PKEY_CTX_new(pkey, NULL);
    wolfSSL_EVP_PKEY_encrypt_init(ctx);
    wolfSSL_EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    wolfSSL_EVP_PKEY_CTX_set_rsa_oaep_md(ctx, wolfSSL_EVP_sha256());
    \endcode

    \sa wolfSSL_EVP_PKEY_encrypt
*/
int wolfSSL_EVP_PKEY_CTX_set_rsa_oaep_md(WOLFSSL_EVP_PKEY_CTX *ctx,
                                          const WOLFSSL_EVP_MD *md);

/*!
    \ingroup openSSL
    \brief Initializes EVP_PKEY_CTX for key derivation.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_PKEY_CTX structure

    _Example_
    \code
    WOLFSSL_EVP_PKEY_CTX* ctx = wolfSSL_EVP_PKEY_CTX_new(pkey, NULL);
    wolfSSL_EVP_PKEY_derive_init(ctx);
    \endcode

    \sa wolfSSL_EVP_PKEY_derive
    \sa wolfSSL_EVP_PKEY_derive_set_peer
*/
int wolfSSL_EVP_PKEY_derive_init(WOLFSSL_EVP_PKEY_CTX *ctx);

/*!
    \ingroup openSSL
    \brief Sets peer key for key derivation.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_PKEY_CTX structure
    \param peer Peer's public key

    _Example_
    \code
    WOLFSSL_EVP_PKEY_CTX* ctx = wolfSSL_EVP_PKEY_CTX_new(pkey, NULL);
    wolfSSL_EVP_PKEY_derive_init(ctx);
    wolfSSL_EVP_PKEY_derive_set_peer(ctx, peerKey);
    \endcode

    \sa wolfSSL_EVP_PKEY_derive_init
    \sa wolfSSL_EVP_PKEY_derive
*/
int wolfSSL_EVP_PKEY_derive_set_peer(WOLFSSL_EVP_PKEY_CTX *ctx,
                                      WOLFSSL_EVP_PKEY *peer);

/*!
    \ingroup openSSL
    \brief Derives shared secret.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_PKEY_CTX structure
    \param key Output buffer for shared secret
    \param keylen Pointer to key length

    _Example_
    \code
    WOLFSSL_EVP_PKEY_CTX* ctx = wolfSSL_EVP_PKEY_CTX_new(pkey, NULL);
    unsigned char secret[64];
    size_t secretLen = sizeof(secret);
    wolfSSL_EVP_PKEY_derive_init(ctx);
    wolfSSL_EVP_PKEY_derive_set_peer(ctx, peerKey);
    wolfSSL_EVP_PKEY_derive(ctx, secret, &secretLen);
    \endcode

    \sa wolfSSL_EVP_PKEY_derive_init
    \sa wolfSSL_EVP_PKEY_derive_set_peer
*/
int wolfSSL_EVP_PKEY_derive(WOLFSSL_EVP_PKEY_CTX *ctx, unsigned char *key,
                             size_t *keylen);

/*!
    \ingroup openSSL
    \brief Controls EVP_PKEY_CTX with string parameters.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_PKEY_CTX structure
    \param name Control name
    \param value Control value

    _Example_
    \code
    WOLFSSL_EVP_PKEY_CTX* ctx = wolfSSL_EVP_PKEY_CTX_new(pkey, NULL);
    wolfSSL_EVP_PKEY_CTX_ctrl_str(ctx, "rsa_padding_mode", "pss");
    \endcode

    \sa wolfSSL_EVP_PKEY_CTX_set_rsa_padding
*/
int wolfSSL_EVP_PKEY_CTX_ctrl_str(WOLFSSL_EVP_PKEY_CTX *ctx,
                                   const char *name, const char *value);

/*!
    \ingroup openSSL
    \brief Decrypts data using EVP_PKEY_CTX.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_PKEY_CTX structure
    \param out Output buffer for decrypted data
    \param outlen Pointer to output length
    \param in Input encrypted data
    \param inlen Input data length

    _Example_
    \code
    WOLFSSL_EVP_PKEY_CTX* ctx = wolfSSL_EVP_PKEY_CTX_new(pkey, NULL);
    unsigned char out[256];
    size_t outlen = sizeof(out);
    wolfSSL_EVP_PKEY_decrypt_init(ctx);
    wolfSSL_EVP_PKEY_decrypt(ctx, out, &outlen, encrypted, encLen);
    \endcode

    \sa wolfSSL_EVP_PKEY_decrypt_init
    \sa wolfSSL_EVP_PKEY_encrypt
*/
int wolfSSL_EVP_PKEY_decrypt(WOLFSSL_EVP_PKEY_CTX *ctx, unsigned char *out,
                              size_t *outlen, const unsigned char *in,
                              size_t inlen);

/*!
    \ingroup openSSL
    \brief Initializes EVP_PKEY_CTX for decryption operation.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_PKEY_CTX structure

    _Example_
    \code
    WOLFSSL_EVP_PKEY_CTX* ctx = wolfSSL_EVP_PKEY_CTX_new(pkey, NULL);
    wolfSSL_EVP_PKEY_decrypt_init(ctx);
    \endcode

    \sa wolfSSL_EVP_PKEY_decrypt
    \sa wolfSSL_EVP_PKEY_CTX_new
*/
int wolfSSL_EVP_PKEY_decrypt_init(WOLFSSL_EVP_PKEY_CTX *ctx);

/*!
    \ingroup openSSL
    \brief Encrypts data using EVP_PKEY_CTX.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_PKEY_CTX structure
    \param out Output buffer for encrypted data
    \param outlen Pointer to output length
    \param in Input plaintext data
    \param inlen Input data length

    _Example_
    \code
    WOLFSSL_EVP_PKEY_CTX* ctx = wolfSSL_EVP_PKEY_CTX_new(pkey, NULL);
    unsigned char out[256];
    size_t outlen = sizeof(out);
    wolfSSL_EVP_PKEY_encrypt_init(ctx);
    wolfSSL_EVP_PKEY_encrypt(ctx, out, &outlen, plaintext, plainLen);
    \endcode

    \sa wolfSSL_EVP_PKEY_encrypt_init
    \sa wolfSSL_EVP_PKEY_decrypt
*/
int wolfSSL_EVP_PKEY_encrypt(WOLFSSL_EVP_PKEY_CTX *ctx, unsigned char *out,
                              size_t *outlen, const unsigned char *in,
                              size_t inlen);

/*!
    \ingroup openSSL
    \brief Initializes EVP_PKEY_CTX for encryption operation.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx EVP_PKEY_CTX structure

    _Example_
    \code
    WOLFSSL_EVP_PKEY_CTX* ctx = wolfSSL_EVP_PKEY_CTX_new(pkey, NULL);
    wolfSSL_EVP_PKEY_encrypt_init(ctx);
    \endcode

    \sa wolfSSL_EVP_PKEY_encrypt
    \sa wolfSSL_EVP_PKEY_CTX_new
*/
int wolfSSL_EVP_PKEY_encrypt_init(WOLFSSL_EVP_PKEY_CTX *ctx);

/*!
    \ingroup openSSL
    \brief Creates new EVP_PKEY with custom heap.

    \return Pointer to new EVP_PKEY structure
    \return NULL on failure

    \param heap Custom heap pointer

    _Example_
    \code
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_EVP_PKEY_new_ex(NULL);
    \endcode

    \sa wolfSSL_EVP_PKEY_new
    \sa wolfSSL_EVP_PKEY_free
*/
WOLFSSL_EVP_PKEY* wolfSSL_EVP_PKEY_new_ex(void* heap);

/*!
    \ingroup openSSL
    \brief Frees EVP_PKEY structure.

    \return none No returns

    \param key EVP_PKEY structure to free

    _Example_
    \code
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_EVP_PKEY_new();
    wolfSSL_EVP_PKEY_free(pkey);
    \endcode

    \sa wolfSSL_EVP_PKEY_new
*/
void wolfSSL_EVP_PKEY_free(WOLFSSL_EVP_PKEY* key);

/*!
    \ingroup openSSL
    \brief Returns maximum signature size in bytes.

    \return Maximum signature size
    \return 0 if pkey is NULL

    \param pkey EVP_PKEY structure

    _Example_
    \code
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_EVP_PKEY_new();
    int size = wolfSSL_EVP_PKEY_size(pkey);
    \endcode

    \sa wolfSSL_EVP_PKEY_bits
*/
int wolfSSL_EVP_PKEY_size(WOLFSSL_EVP_PKEY *pkey);

/*!
    \ingroup openSSL
    \brief Copies parameters from one EVP_PKEY to another.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param to Destination EVP_PKEY
    \param from Source EVP_PKEY

    _Example_
    \code
    WOLFSSL_EVP_PKEY* to = wolfSSL_EVP_PKEY_new();
    WOLFSSL_EVP_PKEY* from = wolfSSL_EVP_PKEY_new();
    wolfSSL_EVP_PKEY_copy_parameters(to, from);
    \endcode

    \sa wolfSSL_EVP_PKEY_missing_parameters
*/
int wolfSSL_EVP_PKEY_copy_parameters(WOLFSSL_EVP_PKEY *to,
                                      const WOLFSSL_EVP_PKEY *from);

/*!
    \ingroup openSSL
    \brief Checks if EVP_PKEY has missing parameters.

    \return 0 if parameters are present
    \return 1 if parameters are missing

    \param pkey EVP_PKEY structure

    _Example_
    \code
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_EVP_PKEY_new();
    if (wolfSSL_EVP_PKEY_missing_parameters(pkey)) {
        // parameters missing
    }
    \endcode

    \sa wolfSSL_EVP_PKEY_copy_parameters
*/
int wolfSSL_EVP_PKEY_missing_parameters(WOLFSSL_EVP_PKEY *pkey);

/*!
    \ingroup openSSL
    \brief Compares two EVP_PKEY structures.

    \return 1 if keys match
    \return 0 if keys don't match

    \param a First EVP_PKEY
    \param b Second EVP_PKEY

    _Example_
    \code
    WOLFSSL_EVP_PKEY* pkey1 = wolfSSL_EVP_PKEY_new();
    WOLFSSL_EVP_PKEY* pkey2 = wolfSSL_EVP_PKEY_new();
    if (wolfSSL_EVP_PKEY_cmp(pkey1, pkey2) == 1) {
        // keys match
    }
    \endcode

    \sa wolfSSL_EVP_PKEY_type
*/
int wolfSSL_EVP_PKEY_cmp(const WOLFSSL_EVP_PKEY *a,
                          const WOLFSSL_EVP_PKEY *b);

/*!
    \ingroup openSSL
    \brief Returns EVP_PKEY type.

    \return EVP_PKEY type constant
    \return NID_undef on error

    \param type Type value

    _Example_
    \code
    int type = wolfSSL_EVP_PKEY_type(EVP_PKEY_RSA);
    \endcode

    \sa wolfSSL_EVP_PKEY_base_id
    \sa wolfSSL_EVP_PKEY_id
*/
int wolfSSL_EVP_PKEY_type(int type);
