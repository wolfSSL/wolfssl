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
