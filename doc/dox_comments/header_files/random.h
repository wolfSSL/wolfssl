/*!
    \ingroup Random

    \brief Init global Whitewood netRandom context

    \return 0 Success
    \return BAD_FUNC_ARG Either configFile is null or timeout is negative.
    \return RNG_FAILURE_E There was a failure initializing the rng.

    \param configFile Path to configuration file
    \param hmac_cb Optional to create HMAC callback.
    \param timeout A timeout duration.

    _Example_
    \code
    char* config = "path/to/config/example.conf";
    int time = // Some sufficient timeout value;

    if (wc_InitNetRandom(config, NULL, time) != 0)
    {
        // Some error occurred
    }
    \endcode

    \sa wc_FreeNetRandom
*/
int  wc_InitNetRandom(const char* configFile, wnr_hmac_key hmac_cb, int timeout);

/*!
    \ingroup Random

    \brief Free global Whitewood netRandom context.

    \return 0 Success
    \return BAD_MUTEX_E Error locking mutex on wnr_mutex

    \param none No returns.

    _Example_
    \code
    int ret = wc_FreeNetRandom();
    if(ret != 0)
    {
        // Handle the error
    }
    \endcode

    \sa wc_InitNetRandom
*/
int  wc_FreeNetRandom(void);

/*!
    \ingroup Random

    \brief Gets the seed (from OS) and key cipher for rng.  rng->drbg
    (deterministic random bit generator) allocated (should be deallocated
    with wc_FreeRng).  This is a blocking operation.

    \return 0 on success.
    \return MEMORY_E XMALLOC failed
    \return WINCRYPT_E wc_GenerateSeed: failed to acquire context
    \return CRYPTGEN_E wc_GenerateSeed: failed to get random
    \return BAD_FUNC_ARG wc_RNG_GenerateBlock input is null or sz exceeds
    MAX_REQUEST_LEN
    \return DRBG_CONT_FIPS_E wc_RNG_GenerateBlock: Hash_gen returned
    DRBG_CONT_FAILURE
    \return RNG_FAILURE_E wc_RNG_GenerateBlock: Default error.  rng’s
    status originally not ok, or set to DRBG_FAILED

    \param rng random number generator to be initialized for use
    with a seed and key cipher

    _Example_
    \code
    RNG  rng;
    int ret;

    #ifdef HAVE_CAVIUM
    ret = wc_InitRngCavium(&rng, CAVIUM_DEV_ID);
    if (ret != 0){
        printf(“RNG Nitrox init for device: %d failed”, CAVIUM_DEV_ID);
        return -1;
    }
    #endif
    ret = wc_InitRng(&rng);
    if (ret != 0){
        printf(“RNG init failed”);
        return -1;
    }
    \endcode

    \sa wc_InitRngCavium
    \sa wc_RNG_GenerateBlock
    \sa wc_RNG_GenerateByte
    \sa wc_FreeRng
    \sa wc_RNG_HealthTest
*/
int  wc_InitRng(WC_RNG* rng);

/*!
    \ingroup Random

    \brief Copies a sz bytes of pseudorandom data to output. Will
    reseed rng if needed (blocking).

    \return 0 on success
    \return BAD_FUNC_ARG an input is null or sz exceeds MAX_REQUEST_LEN
    \return DRBG_CONT_FIPS_E Hash_gen returned DRBG_CONT_FAILURE
    \return RNG_FAILURE_E Default error. rng’s status originally not
    ok, or set to DRBG_FAILED

    \param rng random number generator initialized with wc_InitRng
    \param output buffer to which the block is copied
    \param sz size of output in bytes

    _Example_
    \code
    RNG  rng;
    int  sz = 32;
    byte block[sz];

    int ret = wc_InitRng(&rng);
    if (ret != 0) {
        return -1; //init of rng failed!
    }

    ret = wc_RNG_GenerateBlock(&rng, block, sz);
    if (ret != 0) {
        return -1; //generating block failed!
    }
    \endcode

    \sa wc_InitRngCavium, wc_InitRng
    \sa wc_RNG_GenerateByte
    \sa wc_FreeRng
    \sa wc_RNG_HealthTest
*/
int  wc_RNG_GenerateBlock(WC_RNG* rng, byte* b, word32 sz);

/*!
    \ingroup Random

    \brief Calls wc_RNG_GenerateBlock to copy a byte of pseudorandom
    data to b. Will reseed rng if needed.

    \return 0 on success
    \return BAD_FUNC_ARG an input is null or sz exceeds MAX_REQUEST_LEN
    \return DRBG_CONT_FIPS_E Hash_gen returned DRBG_CONT_FAILURE
    \return RNG_FAILURE_E Default error.  rng’s status originally not
    ok, or set to DRBG_FAILED

    \param rng: random number generator initialized with wc_InitRng
    \param b one byte buffer to which the block is copied

    _Example_
    \code
    RNG  rng;
    int  sz = 32;
    byte b[1];

    int ret = wc_InitRng(&rng);
    if (ret != 0) {
        return -1; //init of rng failed!
    }

    ret = wc_RNG_GenerateByte(&rng, b);
    if (ret != 0) {
        return -1; //generating block failed!
    }
    \endcode

    \sa wc_InitRngCavium
    \sa wc_InitRng
    \sa wc_RNG_GenerateBlock
    \sa wc_FreeRng
    \sa wc_RNG_HealthTest
*/
int  wc_RNG_GenerateByte(WC_RNG* rng, byte* b);

/*!
    \ingroup Random

    \brief Should be called when RNG no longer needed in order to securely
    free drgb.  Zeros and XFREEs rng-drbg.

    \return 0 on success
    \return BAD_FUNC_ARG rng or rng->drgb null
    \return RNG_FAILURE_E Failed to deallocated drbg

    \param rng random number generator initialized with wc_InitRng

    _Example_
    \code
    RNG  rng;
    int ret = wc_InitRng(&rng);
    if (ret != 0) {
        return -1; //init of rng failed!
    }

    int ret = wc_FreeRng(&rng);
    if (ret != 0) {
        return -1; //free of rng failed!
    }
    \endcode

    \sa wc_InitRngCavium
    \sa wc_InitRng
    \sa wc_RNG_GenerateBlock
    \sa wc_RNG_GenerateByte,
    \sa wc_RNG_HealthTest
*/
int  wc_FreeRng(WC_RNG* rng);

/*!
    \ingroup Random

    \brief Creates and tests functionality of drbg.

    \return 0 on success
    \return BAD_FUNC_ARG seedA and output must not be null.  If reseed
    set seedB must not be null
    \return -1 test failed

    \param int reseed: if set, will test reseed functionality
    \param seedA: seed to instantiate drgb with
    \param seedASz: size of seedA in bytes
    \param seedB: If reseed set, drbg will be reseeded with seedB
    \param seedBSz: size of seedB in bytes
    \param output: initialized to random data seeded with seedB if
    seedrandom is set, and seedA otherwise
    \param outputSz: length of output in bytes

    _Example_
    \code
    byte output[SHA256_DIGEST_SIZE * 4];
    const byte test1EntropyB[] = ....; // test input for reseed false
    const byte test1Output[] = ....;   // testvector: expected output of
                                   // reseed false
    ret = wc_RNG_HealthTest(0, test1Entropy, sizeof(test1Entropy), NULL, 0,
                        output, sizeof(output));
    if (ret != 0)
        return -1;//healthtest without reseed failed

    if (XMEMCMP(test1Output, output, sizeof(output)) != 0)
        return -1; //compare to testvector failed: unexpected output

    const byte test2EntropyB[] = ....; // test input for reseed
    const byte test2Output[] = ....;   // testvector expected output of reseed
    ret = wc_RNG_HealthTest(1, test2EntropyA, sizeof(test2EntropyA),
                        test2EntropyB, sizeof(test2EntropyB),
                        output, sizeof(output));

    if (XMEMCMP(test2Output, output, sizeof(output)) != 0)
        return -1; //compare to testvector failed
    \endcode

    \sa wc_InitRngCavium
    \sa wc_InitRng
    \sa wc_RNG_GenerateBlock
    \sa wc_RNG_GenerateByte
    \sa wc_FreeRng
*/
int wc_RNG_HealthTest(int reseed, const byte* seedA, word32 seedASz,
        const byte* seedB, word32 seedBSz,
        byte* output, word32 outputSz);

/*!
    \ingroup Random
    \brief Generates seed from OS entropy source. Lower-level function
    used internally by wc_InitRng.

    \return 0 On success
    \return WINCRYPT_E Failed to acquire context (Windows)
    \return CRYPTGEN_E Failed to generate random (Windows)
    \return RNG_FAILURE_E Failed to read entropy

    \param os Pointer to OS_Seed structure
    \param output Buffer to store seed
    \param sz Size of seed in bytes

    _Example_
    \code
    OS_Seed os;
    byte seed[32];
    int ret = wc_GenerateSeed(&os, seed, sizeof(seed));
    \endcode

    \sa wc_InitRng
*/
int wc_GenerateSeed(OS_Seed* os, byte* output, word32 sz);

/*!
    \ingroup Random
    \brief Allocates and initializes new WC_RNG with optional nonce.

    \return Pointer to WC_RNG on success
    \return NULL on failure

    \param nonce Nonce buffer (can be NULL)
    \param nonceSz Nonce size
    \param heap Heap hint (can be NULL)

    _Example_
    \code
    WC_RNG* rng = wc_rng_new(NULL, 0, NULL);
    wc_rng_free(rng);
    \endcode

    \sa wc_rng_free
*/
WC_RNG* wc_rng_new(byte* nonce, word32 nonceSz, void* heap);

/*!
    \ingroup Random
    \brief Allocates and initializes WC_RNG with extended parameters.

    \return 0 On success
    \return BAD_FUNC_ARG If rng is NULL
    \return MEMORY_E Memory allocation failed

    \param rng Pointer to store WC_RNG pointer
    \param nonce Nonce buffer (can be NULL)
    \param nonceSz Nonce size
    \param heap Heap hint (can be NULL)
    \param devId Device ID (INVALID_DEVID for software)

    _Example_
    \code
    WC_RNG* rng;
    int ret = wc_rng_new_ex(&rng, NULL, 0, NULL, INVALID_DEVID);
    wc_rng_free(rng);
    \endcode

    \sa wc_rng_new
*/
int wc_rng_new_ex(WC_RNG **rng, byte* nonce, word32 nonceSz, void* heap,
                 int devId);

/*!
    \ingroup Random
    \brief Frees WC_RNG allocated with wc_rng_new.

    \param rng WC_RNG to free

    _Example_
    \code
    WC_RNG* rng = wc_rng_new(NULL, 0, NULL);
    wc_rng_free(rng);
    \endcode

    \sa wc_rng_new
*/
void wc_rng_free(WC_RNG* rng);

/*!
    \ingroup Random
    \brief Initializes WC_RNG with extended parameters.

    \return 0 On success
    \return BAD_FUNC_ARG If rng is NULL
    \return RNG_FAILURE_E Initialization failed

    \param rng WC_RNG to initialize
    \param heap Heap hint (can be NULL)
    \param devId Device ID (INVALID_DEVID for software)

    _Example_
    \code
    WC_RNG rng;
    int ret = wc_InitRng_ex(&rng, NULL, INVALID_DEVID);
    wc_FreeRng(&rng);
    \endcode

    \sa wc_InitRng
*/
int wc_InitRng_ex(WC_RNG* rng, void* heap, int devId);

/*!
    \ingroup Random
    \brief Initializes WC_RNG with nonce.

    \return 0 On success
    \return BAD_FUNC_ARG If rng is NULL
    \return RNG_FAILURE_E Initialization failed

    \param rng WC_RNG to initialize
    \param nonce Nonce buffer
    \param nonceSz Nonce size

    _Example_
    \code
    WC_RNG rng;
    byte nonce[16];
    int ret = wc_InitRngNonce(&rng, nonce, sizeof(nonce));
    wc_FreeRng(&rng);
    \endcode

    \sa wc_InitRng
*/
int wc_InitRngNonce(WC_RNG* rng, byte* nonce, word32 nonceSz);

/*!
    \ingroup Random
    \brief Initializes WC_RNG with nonce and extended parameters.

    \return 0 On success
    \return BAD_FUNC_ARG If rng is NULL
    \return RNG_FAILURE_E Initialization failed

    \param rng WC_RNG to initialize
    \param nonce Nonce buffer
    \param nonceSz Nonce size
    \param heap Heap hint (can be NULL)
    \param devId Device ID (INVALID_DEVID for software)

    _Example_
    \code
    WC_RNG rng;
    byte nonce[16];
    int ret = wc_InitRngNonce_ex(&rng, nonce, sizeof(nonce), NULL,
                                 INVALID_DEVID);
    wc_FreeRng(&rng);
    \endcode

    \sa wc_InitRngNonce
*/
int wc_InitRngNonce_ex(WC_RNG* rng, byte* nonce, word32 nonceSz,
                      void* heap, int devId);

/*!
    \ingroup Random
    \brief Sets callback for custom seed generation.

    \return 0 On success
    \return BAD_FUNC_ARG If cb is NULL

    \param cb Seed callback function

    _Example_
    \code
    int my_cb(OS_Seed* os, byte* out, word32 sz) { return 0; }
    wc_SetSeed_Cb(my_cb);
    \endcode

    \sa wc_GenerateSeed
*/
int wc_SetSeed_Cb(wc_RngSeed_Cb cb);

/*!
    \ingroup Random
    \brief Reseeds DRBG with new entropy.

    \return 0 On success
    \return BAD_FUNC_ARG If rng or seed is NULL
    \return RNG_FAILURE_E Reseed failed

    \param rng WC_RNG to reseed
    \param seed Seed buffer
    \param seedSz Seed size

    _Example_
    \code
    WC_RNG rng;
    byte seed[32];
    wc_InitRng(&rng);
    int ret = wc_RNG_DRBG_Reseed(&rng, seed, sizeof(seed));
    \endcode

    \sa wc_InitRng
*/
int wc_RNG_DRBG_Reseed(WC_RNG* rng, const byte* seed, word32 seedSz);

/*!
    \ingroup Random
    \brief Tests seed validity for DRBG.

    \return 0 If valid
    \return BAD_FUNC_ARG If seed is NULL
    \return ENTROPY_RT_E || ENTROPY_APT_E  Validation failed

    \param seed Seed to test
    \param seedSz Seed size

    _Example_
    \code
    byte seed[32];
    int ret = wc_RNG_TestSeed(seed, sizeof(seed));
    \endcode

    \sa wc_InitRng
*/
int wc_RNG_TestSeed(const byte* seed, word32 seedSz);

/*!
    \ingroup Random
    \brief RNG health test with extended parameters.

    \return 0 On success
    \return BAD_FUNC_ARG If required params NULL
    \return -1 Test failed

    \param reseed Non-zero to test reseeding
    \param nonce Nonce buffer (can be NULL)
    \param nonceSz Nonce size
    \param seedA Initial seed
    \param seedASz Initial seed size
    \param seedB Reseed buffer (required if reseed set)
    \param seedBSz Reseed size
    \param output Output buffer
    \param outputSz Output size
    \param heap Heap hint (can be NULL)
    \param devId Device ID (INVALID_DEVID for software)

    _Example_
    \code
    byte seedA[32], seedB[32], out[64];
    int ret = wc_RNG_HealthTest_ex(1, NULL, 0, seedA, 32, seedB, 32,
                                   out, 64, NULL, INVALID_DEVID);
    \endcode

    \sa wc_RNG_HealthTest
*/
int wc_RNG_HealthTest_ex(int reseed, const byte* nonce, word32 nonceSz,
                        const byte* seedA, word32 seedASz,
                        const byte* seedB, word32 seedBSz, byte* output,
                        word32 outputSz, void* heap, int devId);

/*!
    \ingroup Random
    \brief Gets raw entropy without DRBG processing.

    \return 0 On success
    \return BAD_FUNC_ARG If raw is NULL
    \return RNG_FAILURE_E Failed

    \param raw Buffer for entropy
    \param cnt Bytes to retrieve

    _Example_
    \code
    byte raw[32];
    int ret = wc_Entropy_GetRawEntropy(raw, sizeof(raw));
    \endcode

    \sa wc_Entropy_Get
*/
int wc_Entropy_GetRawEntropy(unsigned char* raw, int cnt);

/*!
    \ingroup Random
    \brief Gets processed entropy with specified bits.

    \return 0 On success
    \return BAD_FUNC_ARG If entropy is NULL
    \return RNG_FAILURE_E Failed

    \param bits Entropy bits required
    \param entropy Buffer for entropy
    \param len Buffer size

    _Example_
    \code
    byte entropy[32];
    int ret = wc_Entropy_Get(256, entropy, sizeof(entropy));
    \endcode

    \sa wc_Entropy_GetRawEntropy
*/
int wc_Entropy_Get(int bits, unsigned char* entropy, word32 len);

/*!
    \ingroup Random
    \brief Tests entropy source on demand.

    \return 0 On success
    \return RNG_FAILURE_E Test failed

    _Example_
    \code
    int ret = wc_Entropy_OnDemandTest();
    \endcode

    \sa wc_Entropy_Get
*/
int wc_Entropy_OnDemandTest(void);

/*!
    \ingroup Random

    \brief Runs the SHA-512 Hash_DRBG Known Answer Test (KAT) per
    SP 800-90A.  Instantiates a SHA-512 DRBG with seedA, optionally
    reseeds with seedB, generates output, and compares against known
    test vectors.  Available when WOLFSSL_DRBG_SHA512 is defined.

    \return 0 On success
    \return BAD_FUNC_ARG If seedA or output is NULL, or if reseed is
    set and seedB is NULL
    \return -1 Test failed

    \param reseed Non-zero to test reseeding
    \param seedA Initial entropy seed
    \param seedASz Size of seedA in bytes
    \param seedB Reseed entropy (required if reseed is set)
    \param seedBSz Size of seedB in bytes
    \param output Buffer to receive generated output
    \param outputSz Size of output in bytes

    _Example_
    \code
    byte output[WC_SHA512_DIGEST_SIZE * 4];
    const byte seedA[] = { ... };
    const byte seedB[] = { ... };

    ret = wc_RNG_HealthTest_SHA512(0, seedA, sizeof(seedA), NULL, 0,
                                   output, sizeof(output));
    if (ret != 0)
        return -1;

    ret = wc_RNG_HealthTest_SHA512(1, seedA, sizeof(seedA),
                                   seedB, sizeof(seedB),
                                   output, sizeof(output));
    if (ret != 0)
        return -1;
    \endcode

    \sa wc_RNG_HealthTest
    \sa wc_RNG_HealthTest_SHA512_ex
*/
int wc_RNG_HealthTest_SHA512(int reseed, const byte* seedA, word32 seedASz,
        const byte* seedB, word32 seedBSz,
        byte* output, word32 outputSz);

/*!
    \ingroup Random

    \brief Extended SHA-512 Hash_DRBG health test with nonce,
    personalization string, and additional input support.  Suitable
    for full ACVP / CAVP test vector validation.  Available when
    WOLFSSL_DRBG_SHA512 is defined.

    \return 0 On success
    \return BAD_FUNC_ARG If required params are NULL
    \return -1 Test failed

    \param reseed Non-zero to test reseeding
    \param nonce Nonce buffer (can be NULL)
    \param nonceSz Nonce size
    \param persoString Personalization string (can be NULL)
    \param persoStringSz Personalization string size
    \param seedA Initial entropy seed
    \param seedASz Initial seed size
    \param seedB Reseed entropy (required if reseed is set)
    \param seedBSz Reseed size
    \param additionalA Additional input for first generate (can be NULL)
    \param additionalASz Additional input A size
    \param additionalB Additional input for second generate (can be NULL)
    \param additionalBSz Additional input B size
    \param output Output buffer
    \param outputSz Output size
    \param heap Heap hint (can be NULL)
    \param devId Device ID (INVALID_DEVID for software)

    _Example_
    \code
    byte output[WC_SHA512_DIGEST_SIZE * 4];
    const byte seedA[] = { ... };
    const byte nonce[] = { ... };

    int ret = wc_RNG_HealthTest_SHA512_ex(0, nonce, sizeof(nonce),
                                          NULL, 0,
                                          seedA, sizeof(seedA),
                                          NULL, 0,
                                          NULL, 0, NULL, 0,
                                          output, sizeof(output),
                                          NULL, INVALID_DEVID);
    \endcode

    \sa wc_RNG_HealthTest_SHA512
    \sa wc_RNG_HealthTest_ex
*/
int wc_RNG_HealthTest_SHA512_ex(int reseed, const byte* nonce, word32 nonceSz,
        const byte* persoString, word32 persoStringSz,
        const byte* seedA, word32 seedASz,
        const byte* seedB, word32 seedBSz,
        const byte* additionalA, word32 additionalASz,
        const byte* additionalB, word32 additionalBSz,
        byte* output, word32 outputSz,
        void* heap, int devId);

/*!
    \ingroup Random

    \brief Disables the SHA-256 Hash_DRBG at runtime.  When disabled,
    newly initialized WC_RNG instances will not use the SHA-256 DRBG.
    If the SHA-512 DRBG is enabled (WOLFSSL_DRBG_SHA512), new RNG
    instances will use SHA-512 instead.  Requires HAVE_HASHDRBG.

    \return 0 On success

    _Example_
    \code
    wc_Sha256Drbg_Disable();
    // New WC_RNG instances will now use SHA-512 DRBG if available
    WC_RNG rng;
    wc_InitRng(&rng);
    \endcode

    \sa wc_Sha256Drbg_Enable
    \sa wc_Sha256Drbg_GetStatus
    \sa wc_Sha512Drbg_Disable
*/
int wc_Sha256Drbg_Disable(void);

/*!
    \ingroup Random

    \brief Re-enables the SHA-256 Hash_DRBG at runtime after a prior
    call to wc_Sha256Drbg_Disable().  Requires HAVE_HASHDRBG.

    \return 0 On success

    _Example_
    \code
    wc_Sha256Drbg_Disable();
    // ... use SHA-512 DRBG only ...
    wc_Sha256Drbg_Enable();
    // New WC_RNG instances can use SHA-256 DRBG again
    \endcode

    \sa wc_Sha256Drbg_Disable
    \sa wc_Sha256Drbg_GetStatus
*/
int wc_Sha256Drbg_Enable(void);

/*!
    \ingroup Random

    \brief Returns the current status of the SHA-256 Hash_DRBG
    (disabled or enabled).  Requires HAVE_HASHDRBG.

    \return 1 SHA-256 DRBG is disabled
    \return 0 SHA-256 DRBG is enabled

    _Example_
    \code
    if (wc_Sha256Drbg_GetStatus()) {
        printf("SHA-256 DRBG is off\n");
    }
    \endcode

    \sa wc_Sha256Drbg_Disable
    \sa wc_Sha256Drbg_Enable
*/
int wc_Sha256Drbg_GetStatus(void);

/*!
    \ingroup Random

    \brief Disables the SHA-512 Hash_DRBG at runtime.  When disabled,
    newly initialized WC_RNG instances will not use the SHA-512 DRBG.
    If the SHA-256 DRBG is still enabled, new RNG instances will fall
    back to SHA-256.  Available when WOLFSSL_DRBG_SHA512 is defined.
    Requires HAVE_HASHDRBG.

    \return 0 On success

    _Example_
    \code
    wc_Sha512Drbg_Disable();
    // New WC_RNG instances will now use SHA-256 DRBG
    WC_RNG rng;
    wc_InitRng(&rng);
    \endcode

    \sa wc_Sha512Drbg_Enable
    \sa wc_Sha512Drbg_GetStatus
    \sa wc_Sha256Drbg_Disable
*/
int wc_Sha512Drbg_Disable(void);

/*!
    \ingroup Random

    \brief Re-enables the SHA-512 Hash_DRBG at runtime after a prior
    call to wc_Sha512Drbg_Disable().  Available when WOLFSSL_DRBG_SHA512
    is defined.  Requires HAVE_HASHDRBG.

    \return 0 On success

    _Example_
    \code
    wc_Sha512Drbg_Disable();
    // ... use SHA-256 DRBG only ...
    wc_Sha512Drbg_Enable();
    // New WC_RNG instances can use SHA-512 DRBG again
    \endcode

    \sa wc_Sha512Drbg_Disable
    \sa wc_Sha512Drbg_GetStatus
*/
int wc_Sha512Drbg_Enable(void);

/*!
    \ingroup Random

    \brief Returns the current status of the SHA-512 Hash_DRBG
    (disabled or enabled).  Available when WOLFSSL_DRBG_SHA512 is
    defined.  Requires HAVE_HASHDRBG.

    \return 1 SHA-512 DRBG is disabled
    \return 0 SHA-512 DRBG is enabled

    _Example_
    \code
    if (wc_Sha512Drbg_GetStatus()) {
        printf("SHA-512 DRBG is off\n");
    }
    \endcode

    \sa wc_Sha512Drbg_Disable
    \sa wc_Sha512Drbg_Enable
*/
int wc_Sha512Drbg_GetStatus(void);
