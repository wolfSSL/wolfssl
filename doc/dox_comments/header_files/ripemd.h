/*!
    \ingroup RIPEMD

    \brief This function initializes a ripemd structure by initializing
    ripemd’s digest, buffer, loLen and hiLen.

    \return 0 returned on successful execution of the function. The RipeMd
    structure is initialized.
    \return BAD_FUNC_ARG returned if the RipeMd structure is NULL.

    \param ripemd pointer to the ripemd structure to initialize

    _Example_
    \code
    RipeMd md;
    int ret;
    ret = wc_InitRipeMd(&md);
    if (ret != 0) {
    	// Failure case.
    }
    \endcode

    \sa wc_RipeMdUpdate
    \sa wc_RipeMdFinal
*/
int wc_InitRipeMd(RipeMd*);

/*!
    \ingroup RIPEMD

    \brief This function generates the RipeMd digest of the data input and
    stores the result in the ripemd->digest buffer. After running
    wc_RipeMdUpdate, one should compare the generated ripemd->digest to a
    known authentication tag to verify the authenticity of a message.

    \return 0 Returned on successful execution of the function.
    \return BAD_FUNC_ARG Returned if the RipeMd structure is NULL or if data
    is NULL and len is not zero. This function should execute if data is NULL
    and len is 0.

    \param ripemd: pointer to the ripemd structure to be initialized with
    wc_InitRipeMd
    \param data data to be hashed
    \param len sizeof data in bytes

    _Example_
    \code
    const byte* data; // The data to be hashed
    ....
    RipeMd md;
    int ret;
    ret = wc_InitRipeMd(&md);
    if (ret == 0) {
    ret = wc_RipeMdUpdate(&md, plain, sizeof(plain));
    if (ret != 0) {
	// Failure case …
    \endcode

    \sa wc_InitRipeMd
    \sa wc_RipeMdFinal
*/
int wc_RipeMdUpdate(RipeMd* ripemd, const byte* data, word32 len);

/*!
    \ingroup RIPEMD

    \brief This function copies the computed digest into hash.  If there is a
    partial unhashed block, this method will pad the block with 0s, and
    include that block’s round in the digest before copying to hash. State
    of ripemd is reset.

    \return 0 Returned on successful execution of the function. The state of
    the RipeMd structure has been reset.
    \return BAD_FUNC_ARG Returned if the RipeMd structure or hash parameters
    are NULL.

    \param ripemd pointer to the ripemd structure to be initialized with
    wc_InitRipeMd, and containing hashes from wc_RipeMdUpdate. State will
    be reset
    \param hash buffer to copy digest to.  Should be RIPEMD_DIGEST_SIZE bytes

    _Example_
    \code
    RipeMd md;
    int ret;
    byte   digest[RIPEMD_DIGEST_SIZE];
    const byte* data; // The data to be hashed
    ...
    ret = wc_InitRipeMd(&md);
    if (ret == 0) {
    ret = wc_RipeMdUpdate(&md, plain, sizeof(plain));
    	if (ret != 0) {
    		// RipeMd Update Failure Case.
    }
    ret = wc_RipeMdFinal(&md, digest);
    if (ret != 0) {
    	// RipeMd Final Failure Case.
    }...
    \endcode

    \sa none
*/
int wc_RipeMdFinal(RipeMd* ripemd, byte* hash);

/*!
    \ingroup openSSL
    \brief Initializes RIPEMD context.

    \return none No returns

    \param ctx RIPEMD context to initialize

    _Example_
    \code
    WOLFSSL_RIPEMD_CTX ctx;
    wolfSSL_RIPEMD_Init(&ctx);
    \endcode

    \sa wolfSSL_RIPEMD_Update
*/
void wolfSSL_RIPEMD_Init(WOLFSSL_RIPEMD_CTX* ctx);

/*!
    \ingroup openSSL
    \brief Updates RIPEMD hash with data.

    \return none No returns

    \param ctx RIPEMD context
    \param data Input data
    \param len Input size

    _Example_
    \code
    WOLFSSL_RIPEMD_CTX ctx;
    unsigned char data[100];
    wolfSSL_RIPEMD_Update(&ctx, data, sizeof(data));
    \endcode

    \sa wolfSSL_RIPEMD_Init
*/
void wolfSSL_RIPEMD_Update(WOLFSSL_RIPEMD_CTX* ctx, const void* data,
    unsigned long len);

/*!
    \ingroup openSSL
    \brief Finalizes RIPEMD hash.

    \return none No returns

    \param hash Output hash buffer
    \param ctx RIPEMD context

    _Example_
    \code
    WOLFSSL_RIPEMD_CTX ctx;
    unsigned char hash[RIPEMD_DIGEST_SIZE];
    wolfSSL_RIPEMD_Final(hash, &ctx);
    \endcode

    \sa wolfSSL_RIPEMD_Update
*/
void wolfSSL_RIPEMD_Final(unsigned char* hash, WOLFSSL_RIPEMD_CTX* ctx);
