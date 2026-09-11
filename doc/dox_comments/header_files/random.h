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
    \return ENTROPY_APT_E The adaptive proportion test failed.
    \return MEMORY_E Allocation failed.

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

    \par Supplying your own counter
    The entropy source samples a high resolution counter for timing jitter.
    CUSTOM_ENTROPY_TIMEHIRES overrides which counter it uses.  It is a build
    time macro, not a runtime callback: define it to the name of a function
    returning word64.  Requires HAVE_ENTROPY_MEMUSE (--enable-wolfEntropy).

    Without it, wolfentropy.c picks a counter in this order: a per platform
    hardware counter if it has one for the target, otherwise a counter thread
    when ENTROPY_MEMUSE_THREAD is set, otherwise the build fails.  A custom
    counter is checked before all of those and always wins, so on a platform
    with no hardware counter it means the counter thread is not used at all,
    and setting ENTROPY_MEMUSE_THREAD as well changes nothing.

    The counter needs resolution, not accuracy.  It only has to advance
    quickly, and need not be monotonic or related to wall clock time.

    \code
    // Replacing a hardware counter, on a platform that already has one.
    // Build with -DCUSTOM_ENTROPY_TIMEHIRES=my_cycle_counter
    word64 my_cycle_counter(void)
    {
        return (word64)board_read_cycle_count();
    }

    // Avoiding the counter thread, on a platform that has no hardware
    // counter and would otherwise spin one up.
    // Build with -DCUSTOM_ENTROPY_TIMEHIRES=my_tick
    word64 my_tick(void)
    {
        return (word64)my_rtos_tick_count();
    }
    \endcode
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
    \sa wc_Sha256Drbg_IsDisabled
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
    \sa wc_Sha256Drbg_IsDisabled
*/
int wc_Sha256Drbg_Enable(void);

/*!
    \ingroup Random

    \brief Returns whether the SHA-256 Hash_DRBG is currently disabled.
    Requires HAVE_HASHDRBG.

    \return 1 SHA-256 DRBG is disabled
    \return 0 SHA-256 DRBG is enabled (not disabled)

    _Example_
    \code
    if (wc_Sha256Drbg_IsDisabled()) {
        printf("SHA-256 DRBG is off\n");
    }
    \endcode

    \sa wc_Sha256Drbg_Disable
    \sa wc_Sha256Drbg_Enable
*/
int wc_Sha256Drbg_IsDisabled(void);

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
    \sa wc_Sha512Drbg_IsDisabled
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
    \sa wc_Sha512Drbg_IsDisabled
*/
int wc_Sha512Drbg_Enable(void);

/*!
    \ingroup Random

    \brief Returns whether the SHA-512 Hash_DRBG is currently disabled.
    Available when WOLFSSL_DRBG_SHA512 is defined.  Requires HAVE_HASHDRBG.

    \return 1 SHA-512 DRBG is disabled
    \return 0 SHA-512 DRBG is enabled (not disabled)

    _Example_
    \code
    if (wc_Sha512Drbg_IsDisabled()) {
        printf("SHA-512 DRBG is off\n");
    }
    \endcode

    \sa wc_Sha512Drbg_Disable
    \sa wc_Sha512Drbg_Enable
*/
int wc_Sha512Drbg_IsDisabled(void);

/*!
    \ingroup Random

    \brief Initialize a WC_RNG with instantiation-time security attributes.
    Identical to wc_InitRng_ex(), with a flags argument fixing attributes at
    birth: WC_RNG_INIT_FLAGS_LOCK_REQUIRED latches the sticky lock-required
    policy bit, so there is no reachable state in which the instance serves
    without its lock policy; WC_RNG_INIT_FLAGS_LOCK_INITIALLY constructs into
    a held lease, to be released with wc_RNG_lock_put();
    WC_RNG_INIT_FLAGS_USE_FULL_MUTEX layers a blocking wolfSSL_Mutex
    outermost around the lock latch, for user-mode sharing of one instance
    among threads (requires WC_RNG_HAVE_LOCK_FULL_MUTEX).

    \return 0 Success
    \return BAD_FUNC_ARG rng is null.
    \return NOT_COMPILED_IN A requested flag is not compiled in.

    \param rng The RNG object to initialize.
    \param heap Heap hint for dynamic allocation.
    \param devId Device id, or INVALID_DEVID.
    \param flags Bitwise-or of WC_RNG_INIT_FLAGS_* attributes.

    _Example_
    \code
    WC_RNG rng;
    if (wc_InitRng_ex2(&rng, NULL, INVALID_DEVID,
                       WC_RNG_INIT_FLAGS_LOCK_REQUIRED |
                       WC_RNG_INIT_FLAGS_LOCK_INITIALLY) != 0) {
        // error handling
    }
    // caller holds the lease from birth
    \endcode

    \sa wc_InitRng_ex
    \sa wc_InitRngNonce_ex2
    \sa wc_RNG_lock_get
    \sa wc_RNG_lock_put
*/
int wc_InitRng_ex2(WC_RNG* rng, void* heap, int devId, word32 flags);

/*!
    \ingroup Random

    \brief Initialize a WC_RNG with a caller-supplied nonce and
    instantiation-time security attributes.  The nonce semantics are those of
    wc_InitRngNonce_ex(); the flags semantics are those of wc_InitRng_ex2().

    \return 0 Success
    \return BAD_FUNC_ARG rng is null.
    \return NOT_COMPILED_IN A requested flag is not compiled in.

    \param rng The RNG object to initialize.
    \param nonce Optional nonce used as additional instantiation input.
    \param nonceSz Length of nonce in bytes.
    \param heap Heap hint for dynamic allocation.
    \param devId Device id, or INVALID_DEVID.
    \param flags Bitwise-or of WC_RNG_INIT_FLAGS_* attributes.

    \sa wc_InitRng_ex2
    \sa wc_InitRngNonce_ex
*/
int wc_InitRngNonce_ex2(WC_RNG* rng, const byte* nonce, word32 nonceSz,
                        void* heap, int devId, word32 flags);

/*!
    \ingroup Random

    \brief Read-only accessor for the RNG health status.  Returns the
    instance's enum wc_RngHealthState value (WC_DRBG_NOT_INIT, WC_DRBG_OK,
    WC_DRBG_FAILED, WC_DRBG_CONT_FAILED).

    \return WC_DRBG_OK The instance is in service.
    \return BAD_FUNC_ARG rng is null.

    \param rng The RNG object to interrogate.

    _Example_
    \code
    if (wc_RNG_GetStatus(&rng) != WC_DRBG_OK) {
        // instance is not serviceable
    }
    \endcode

    \sa wc_RNG_DRBG_Present
    \sa wc_RNG_DRBG_GetReseedCtr
*/
int wc_RNG_GetStatus(const WC_RNG* rng);

/*!
    \ingroup Random

    \brief Returns 1 if rng has an instantiated DRBG, else 0.  An in-service
    WC_RNG can lack one: instantiation bypasses the DRBG when the CPU has
    RDRAND (HAVE_INTEL_RDRAND).  DRBG-specific services (commanded reseed,
    banked next seeds, RBG chains) are unavailable on such instances.

    \return 1 rng has a live DRBG.
    \return 0 rng is null or has no DRBG.

    \param rng The RNG object to interrogate.

    \sa wc_RNG_GetStatus
    \sa wc_RNG_DRBG_ScheduleReseed
*/
int wc_RNG_DRBG_Present(const WC_RNG* rng);

/*!
    \ingroup Random

    \brief Report the DRBG's current reseed counter -- the number of generate
    operations since the last credited (re)seed, starting at 1.

    \return 0 Success
    \return BAD_FUNC_ARG rng or reseedCtr is null.
    \return WRONG_TYPE_OBJECT_E rng has no DRBG (RDRAND et al.).

    \param rng The RNG object to interrogate.
    \param reseedCtr Receives the counter.

    \sa wc_RNG_DRBG_Present
    \sa wc_RNG_DRBG_ScheduleReseed
*/
int wc_RNG_DRBG_GetReseedCtr(const WC_RNG* rng, wc_drbg_reseed_ctr_t* reseedCtr);

/*!
    \ingroup Random

    \brief Mark rng due for reseed: the next generate operation reseeds from
    the module's built-in or registered seed source before producing output.
    This can only shorten the current seed's remaining lifetime, never extend
    it.

    \return 0 Success
    \return BAD_FUNC_ARG rng is null.
    \return WRONG_TYPE_OBJECT_E rng has no DRBG (RDRAND et al.) -- a
    commanded reseed that cannot happen is not a success.

    \param rng The RNG object to schedule.

    \sa wc_RNG_DRBG_Reseed_Now
    \sa wc_RNG_DRBG_GetReseedCtr
*/
int wc_RNG_DRBG_ScheduleReseed(WC_RNG* rng);

/*!
    \ingroup Random

    \brief Immediately reseed rng from the module's built-in or registered
    seed source, with an optional nonce as additional input.  The credited
    reseed resets the reseed counter.

    \return 0 Success
    \return BAD_FUNC_ARG rng is null, or nonce is null with nonceSz nonzero.
    \return WRONG_TYPE_OBJECT_E rng has no DRBG (RDRAND et al.).
    \return DRBG_CONT_FIPS_E The continuous test failed; the DRBG is out of
    service.
    \return RNG_FAILURE_E The DRBG is out of service or reseeding failed.

    \param rng The RNG object to reseed.
    \param nonce Optional additional input.
    \param nonceSz Length of nonce in bytes.

    \sa wc_RNG_DRBG_ScheduleReseed
    \sa wc_RNG_DRBG_Reseed_Nonce
*/
int wc_RNG_DRBG_Reseed_Now(WC_RNG* rng, const byte* nonce, word32 nonceSz);

/*!
    \ingroup Random

    \brief Reseed rng's DRBG with caller-supplied seed material and an
    optional nonce as additional input.  The material is credited as entropy:
    the reseed counter resets.

    \return 0 Success
    \return BAD_FUNC_ARG rng or seed is null.
    \return WRONG_TYPE_OBJECT_E rng has no DRBG (RDRAND et al.).

    \param rng The RNG object to reseed.
    \param seed Seed material.
    \param seedSz Length of seed in bytes.
    \param nonce Optional additional input.
    \param nonceSz Length of nonce in bytes.

    \sa wc_RNG_DRBG_Reseed
    \sa wc_RNG_DRBG_Stir_Nonce
*/
int wc_RNG_DRBG_Reseed_Nonce(WC_RNG* rng, const byte* seed, word32 seedSz,
                             const byte *nonce, word32 nonceSz);

/*!
    \ingroup Random

    \brief Similar to wc_RNG_DRBG_Reseed(), except the caller-supplied
    material is mixed through the reseed derivation function without being
    credited as entropy: the reseed counter is not reset, so only the
    module's own seed source ever extends the instance's seed lifetime.

    \return 0 Success
    \return BAD_FUNC_ARG rng or seed is null.
    \return WRONG_TYPE_OBJECT_E rng has no DRBG (RDRAND et al.).

    \param rng The RNG object to stir.
    \param seed Material to mix in.
    \param seedSz Length of seed in bytes.

    \sa wc_RNG_DRBG_Reseed
    \sa wc_RNG_DRBG_Stir_Nonce
*/
int wc_RNG_DRBG_Stir(WC_RNG* rng, const byte* seed, word32 seedSz);

/*!
    \ingroup Random

    \brief The nonce-bearing form of wc_RNG_DRBG_Stir().

    \return 0 Success
    \return BAD_FUNC_ARG rng or seed is null.
    \return WRONG_TYPE_OBJECT_E rng has no DRBG (RDRAND et al.).

    \param rng The RNG object to stir.
    \param seed Material to mix in.
    \param seedSz Length of seed in bytes.
    \param nonce Optional additional input.
    \param nonceSz Length of nonce in bytes.

    \sa wc_RNG_DRBG_Stir
    \sa wc_RNG_DRBG_Reseed_Nonce
*/
int wc_RNG_DRBG_Stir_Nonce(WC_RNG* rng, const byte* seed,
                                        word32 seedSz, const byte *nonce,
                                        word32 nonceSz);

/*!
    \ingroup Random

    \brief Instantiate child as an SP 800-90C RBG-chain member subordinate to
    parent, drawing its seed material from parent's generate function in
    place of the module's seed source.  Every other aspect of instantiation
    is wc_InitRng_ex2()'s.  The child is tagged with stratum
    (parent's stratum + 1), sticky for the instance's lifetime even across
    subsequent source reseeds; its claimable security strength is capped by
    parent's, and it has no prediction resistance.  The caller must hold
    exclusive access to parent for the duration of the call; the spawn debits
    parent's reseed counter by one generate.

    \return 0 Success
    \return BAD_FUNC_ARG child or parent is null, or child equals parent.
    \return SEQ_OVERFLOW_E parent's stratum is at the representable maximum.

    \param child The caller-provided WC_RNG to instantiate (uninitialized).
    \param parent The chain parent to draw seed material from.
    \param flags Bitwise-or of WC_RNG_INIT_FLAGS_* attributes for the child.

    _Example_
    \code
    WC_RNG root, child;
    wc_InitRng(&root);
    if (wc_InitRngRBGC(&child, &root, WC_RNG_INIT_FLAGS_NONE) == 0) {
        // child serves independently; release with wc_FreeRng(&child)
    }
    \endcode

    \sa wc_InitRngNonceRBGC
    \sa wc_InitRngRBGC_New
    \sa wc_RNG_DRBG_ReseedRBGC
    \sa wc_RNG_DRBG_GetRBGCStratum
*/
int wc_InitRngRBGC(WC_RNG* child, WC_RNG* parent, word32 flags);

/*!
    \ingroup Random

    \brief The nonce-bearing form of wc_InitRngRBGC(): the nonce is used as
    additional instantiation input, as in wc_InitRngNonce_ex2().

    \return 0 Success
    \return BAD_FUNC_ARG child or parent is null, child equals parent, or
    nonce is null with nonceSz nonzero.
    \return SEQ_OVERFLOW_E parent's stratum is at the representable maximum.

    \param child The caller-provided WC_RNG to instantiate (uninitialized).
    \param parent The chain parent to draw seed material from.
    \param nonce Additional instantiation input.
    \param nonceSz Length of nonce in bytes.
    \param flags Bitwise-or of WC_RNG_INIT_FLAGS_* attributes for the child.

    \sa wc_InitRngRBGC
    \sa wc_InitRngNonceRBGC_New
*/
int wc_InitRngNonceRBGC(WC_RNG* child, WC_RNG* parent, const byte* nonce,
                        word32 nonceSz, word32 flags);

/*!
    \ingroup Random

    \brief The allocating form of wc_InitRngRBGC(): the child is allocated
    from parent's heap and returned through child.  Release with
    wc_rng_free().

    \return 0 Success
    \return BAD_FUNC_ARG child or parent is null.
    \return MEMORY_E Allocation failed.
    \return SEQ_OVERFLOW_E parent's stratum is at the representable maximum.

    \param child Receives the allocated, instantiated WC_RNG.
    \param parent The chain parent to draw seed material from.
    \param flags Bitwise-or of WC_RNG_INIT_FLAGS_* attributes for the child.

    \sa wc_InitRngRBGC
    \sa wc_InitRngNonceRBGC_New
*/
int wc_InitRngRBGC_New(WC_RNG** child, WC_RNG* parent, word32 flags);

/*!
    \ingroup Random

    \brief The allocating, nonce-bearing form of wc_InitRngRBGC().

    \return 0 Success
    \return BAD_FUNC_ARG child or parent is null, or nonce is null with
    nonceSz nonzero.
    \return MEMORY_E Allocation failed.
    \return SEQ_OVERFLOW_E parent's stratum is at the representable maximum.

    \param child Receives the allocated, instantiated WC_RNG.
    \param parent The chain parent to draw seed material from.
    \param nonce Additional instantiation input.
    \param nonceSz Length of nonce in bytes.
    \param flags Bitwise-or of WC_RNG_INIT_FLAGS_* attributes for the child.

    \sa wc_InitRngRBGC_New
    \sa wc_InitRngNonceRBGC
*/
int wc_InitRngNonceRBGC_New(WC_RNG** child, WC_RNG* parent, const byte* nonce,
                            word32 nonceSz, word32 flags);

/*!
    \ingroup Random

    \brief Reseed rng from root's generate output -- the SP 800-90C chain
    reseed -- with an optional nonce as additional input.  The reseed is
    credited (the reseed counter resets) and rng acquires root's stratum
    plus one.  The caller must hold exclusive access to both instances.

    \details Credited chain reseeds obey a no-downgrade rule: a
    primary-seeded (stratum-0) root is always accepted, and a chained
    (stratum > 0) root is accepted only when its stratum is strictly less
    than rng's -- the acquired stratum never increases, so reseed cycles
    are impossible by construction, consistent with SP 800-90C 7.1.2.2.
    Lateral (equal-stratum) and downgrading reseeds are refused with
    BAD_FUNC_ARG.  Building WC_RNG_NO_RBGC_RESEED restricts credited chain
    reseeds to primary-seeded roots.  Uncredited chain stirs
    (wc_RNG_DRBG_StirRBGC()) are exempt from all of this: they
    are stirs, claim nothing, and leave rng's stratum untouched.

    \return 0 Success
    \return BAD_FUNC_ARG rng or root is null, rng equals root, or the
    no-downgrade rule refuses root as a chain parent (see \details).
    \return WRONG_TYPE_OBJECT_E rng has no DRBG (RDRAND et al.).
    \return SEQ_OVERFLOW_E root's stratum is at the representable maximum.

    \param rng The chain member to reseed.
    \param root The chain parent to draw seed material from.
    \param nonce Optional additional input.
    \param nonceSz Length of nonce in bytes.

    \sa wc_InitRngRBGC
    \sa wc_RNG_DRBG_StirRBGC
    \sa wc_RNG_DRBG_Reseed_Now
*/
int wc_RNG_DRBG_ReseedRBGC(WC_RNG* rng, WC_RNG* root, const byte* nonce,
                           word32 nonceSz);

/*!
    \ingroup Random

    \brief The uncredited form of wc_RNG_DRBG_ReseedRBGC(): material from
    root is mixed in without resetting rng's reseed counter.

    \return 0 Success
    \return BAD_FUNC_ARG rng or root is null, or rng equals root.
    \return WRONG_TYPE_OBJECT_E rng has no DRBG (RDRAND et al.).

    \param rng The chain member to stir.
    \param root The chain parent to draw material from.
    \param nonce Optional additional input.
    \param nonceSz Length of nonce in bytes.

    \sa wc_RNG_DRBG_ReseedRBGC
    \sa wc_RNG_DRBG_Stir
    \details Unrestricted by the credited no-downgrade rule: any source
    stratum is accepted, and rng's reseed counter, stratum, and
    entropy-invalidated state are all left untouched -- an uncredited
    chain reseed is a stir, and a stir must never masquerade as recovery
    or promotion.

*/
int wc_RNG_DRBG_StirRBGC(WC_RNG* rng, WC_RNG* root,
                                      const byte* nonce, word32 nonceSz);

/*!
    \ingroup Random

    \brief Report rng's RBG-chain stratum: 0 for a root (never chain-seeded),
    n for a member seeded from a stratum-(n-1) parent.  The stratum is sticky
    for the instance's lifetime, even across subsequent source reseeds.

    \return 0 rng is a chain root.
    \return n The stratum, positive for a chain member.
    \return BAD_FUNC_ARG rng is null.

    \param rng The RNG object to interrogate.

    \sa wc_InitRngRBGC
    \sa wc_RNG_DRBG_GetNextSeedRBGCStratum
*/
int wc_RNG_DRBG_GetRBGCStratum(const WC_RNG* rng);

/*!
    \ingroup Random

    \brief Report the RBG-chain stratum of rng's banked next seed --
    race-free via the aperture protocol -- for provenance-aware consumers.

    \return 0 The banked seed has root (source) provenance.
    \return n The banked seed's stratum, positive for chain provenance.
    \return BAD_FUNC_ARG rng is null or has no DRBG.
    \return NOT_READY_E No banked seed is ready.

    \param rng The RNG object to interrogate.

    \sa wc_RNG_DRBG_GetRBGCStratum
    \sa wc_RNG_DRBG_NextSeedGenerate_RBGC
*/
int wc_RNG_DRBG_GetNextSeedRBGCStratum(const WC_RNG* rng);

/*!
    \ingroup Random

    \brief Bank up to n more bytes of next-seed material from the module's
    seed source, health-testing and publishing the bank when it completes.
    The fill is incremental and in-boundary; a scheduling daemon may call
    this without owning the instance -- the single-writer fill and the
    atomic aperture hand-off make it safe alongside a concurrent consumer.

    \return 0 Bytes were banked (bank may or may not yet be complete).
    \return ALREADY_E The bank is ready or being consumed.
    \return NOT_READY_E The health test could not run; simply retry.
    \return BAD_FUNC_ARG rng is null or n is 0.
    \return MISSING_RNG_E rng has no DRBG (RDRAND et al.).

    \param rng The RNG object whose bank to fill.
    \param n Maximum bytes to bank this call (clamped to space remaining).

    _Example_
    \code
    // scheduling daemon: fill incrementally until published
    int ret = wc_RNG_DRBG_NextSeedGenerate(rng, 16);
    if (ret == ALREADY_E) {
        // bank is ready; nothing to do until a consumer claims it
    }
    \endcode

    \sa wc_RNG_DRBG_NextSeedNow
    \sa wc_RNG_DRBG_NextSeedCurrent
    \sa wc_RNG_DRBG_NextSeedGenerate_RBGC
*/
int wc_RNG_DRBG_NextSeedGenerate(WC_RNG* rng, word32 n);

/*!
    \ingroup Random

    \brief The chain-sourced form of wc_RNG_DRBG_NextSeedGenerate(): the
    banked material is drawn from root's generate function, and the bank is
    tagged with root's stratum plus one for provenance-aware consumption.

    \return 0 Bytes were banked.
    \return ALREADY_E The bank is ready or being consumed.
    \return NOT_READY_E The health test could not run; simply retry.
    \return BAD_FUNC_ARG rng or root is null, or n is 0.
    \return MISSING_RNG_E rng has no DRBG (RDRAND et al.).
    \return SEQ_OVERFLOW_E root's stratum is at the representable maximum.

    \param rng The RNG object whose bank to fill.
    \param root The chain parent to draw material from.
    \param n Maximum bytes to bank this call.

    \sa wc_RNG_DRBG_NextSeedGenerate
    \sa wc_RNG_DRBG_GetNextSeedRBGCStratum
    \details Banking is bound for credited redemption, so the credited
    no-downgrade rule applies at bank time: a primary-seeded (stratum-0)
    root is always accepted, and a chained root only when its stratum is
    strictly less than rng's -- banking whose redemption would raise rng's
    stratum is refused with BAD_FUNC_ARG.  The banked material records
    root's stratum plus one, observable via
    wc_RNG_DRBG_GetNextSeedRBGCStratum(), and redemption
    (wc_RNG_DRBG_NextSeedNow()) carries it onto rng.

*/
int wc_RNG_DRBG_NextSeedGenerate_RBGC(WC_RNG* rng, WC_RNG *root, word32 n);

/*!
    \ingroup Random

    \brief Report the raw next-seed aperture value: a non-negative banked
    byte count (filling), WC_DRBG_NEXT_SEED_READY, or
    WC_DRBG_NEXT_SEED_CONSUMING.  The snapshot is racy by design; use it for
    scheduling and diagnostics, not for hand-off decisions.

    \return 0 Success
    \return BAD_FUNC_ARG rng or n is null.
    \return MISSING_RNG_E rng has no DRBG (RDRAND et al.).

    \param rng The RNG object to interrogate.
    \param n Receives the aperture value.

    \sa wc_RNG_DRBG_NextSeedGenerate
    \sa wc_RNG_DRBG_NextSeedNow
*/
int wc_RNG_DRBG_NextSeedCurrent(WC_RNG* rng, WC_ATOMIC_INT_ARG* n);

/*!
    \ingroup Random

    \brief Claim a ready next-seed bank and perform a source-free credited
    reseed with it -- safe in atomic context.  The bank empties (use-once)
    and the reseed counter resets.  The caller must own the instance.

    \return 0 Success
    \return NOT_READY_E No bank is ready.
    \return BAD_FUNC_ARG rng is null.
    \return MISSING_RNG_E rng has no DRBG (RDRAND et al.).

    \param rng The RNG object to reseed.

    _Example_
    \code
    // atomic-context consumer
    if (wc_RNG_DRBG_NextSeedNow(rng) == 0) {
        // freshly reseeded without touching the seed source
    }
    \endcode

    \sa wc_RNG_DRBG_NextSeedGenerate
    \sa wc_RNG_DRBG_NextSeedNow_Nonce
*/
int wc_RNG_DRBG_NextSeedNow(WC_RNG* rng);

/*!
    \ingroup Random

    \brief The nonce-bearing form of wc_RNG_DRBG_NextSeedNow(): the nonce is
    mixed in as uncredited additional input alongside the banked seed.

    \return 0 Success
    \return NOT_READY_E No bank is ready.
    \return BAD_FUNC_ARG rng is null, or nonce is null with nonceSz nonzero.
    \return MISSING_RNG_E rng has no DRBG (RDRAND et al.).
    \return DRBG_CONT_FIPS_E The continuous test failed; the DRBG is out of
    service.
    \return RNG_FAILURE_E The DRBG is out of service.

    \param rng The RNG object to reseed.
    \param nonce Additional input.
    \param nonceSz Length of nonce in bytes.

    \sa wc_RNG_DRBG_NextSeedNow
*/
int wc_RNG_DRBG_NextSeedNow_Nonce(WC_RNG* rng, const byte* nonce,
                                  word32 nonceSz);

/*!
    \ingroup Random

    \brief Bank caller-supplied material (up to
    WC_DRBG_NEXT_STIR_LEN bytes) in the uncredited accumulator
    beside the banked next seed.  Writer-safe without a lease
    (read-copy-store); if the accumulator is already full, the material is
    absorbed by xor.  Harvested entropy deposited here improves the instance
    without claiming credit.

    \return 0 Success
    \return BAD_FUNC_ARG rng or nonce is null, or nonceSz is 0.
    \return MISSING_RNG_E rng has no DRBG (RDRAND et al.).

    \param rng The RNG object whose accumulator to feed.
    \param nonce Material to bank.
    \param nonceSz Length of nonce in bytes.

    \sa wc_RNG_DRBG_NextStirNow
    \sa wc_RNG_DRBG_Stir
*/
int wc_RNG_DRBG_NextStirStore(WC_RNG* rng, const byte *nonce,
                                        word32 nonceSz);

/*!
    \ingroup Random

    \brief Stir the banked uncredited accumulator into the DRBG as an
    uncredited, source-free mix-in -- safe in atomic context; the reseed
    counter is not reset.  The caller must own the instance.

    \return 0 Success
    \return NOT_READY_E The accumulator is empty.
    \return BAD_FUNC_ARG rng is null.
    \return MISSING_RNG_E rng has no DRBG (RDRAND et al.).
    \return RNG_FAILURE_E The DRBG is out of service.

    \param rng The RNG object to stir.

    \sa wc_RNG_DRBG_NextStirStore
*/
int wc_RNG_DRBG_NextStirNow(WC_RNG* rng);

/*!
    \ingroup Random

    \brief Acquire rng's exclusive-ownership lock latch, spinning on the CAS
    until acquired, and or the caller's extra bits into the lock word.  On an
    instance without the lock-required policy the call is a successful no-op
    unless extra bits are supplied.

    \return 0 Success
    \return BAD_FUNC_ARG rng is null.
    \return BUSY_E The lock is held.
    \return NEEDS_RECOVERY_E The instance's entropy is invalidated (see
    wc_RNG_invalidate_entropy()); recover with a credited reseed before
    use.
    \return BAD_MUTEX_E (WC_RNG_HAVE_LOCK_FULL_MUTEX) The outer mutex failed.
    \return UNEXPECTED_STATE_E Spurious acquisition failure; retry.

    \param rng The RNG object to lock.
    \param extra_bits Caller-defined bits (above WC_RNG_LOCK_EXTRA_SHIFT) to
    set atomically with the acquisition, or 0.

    _Example_
    \code
    if (wc_RNG_lock_get(rng, 0) == 0) {
        ret = wc_RNG_GenerateBlock(rng, out, sizeof(out));
        wc_RNG_lock_put(rng, 0);
    }
    \endcode

    \sa wc_RNG_lock_put
    \sa wc_RNG_lock_get_conditional
    \sa wc_RNG_lock_read
*/
int wc_RNG_lock_get(WC_RNG* rng, WC_RNG_lock_arg_t extra_bits);

/*!
    \ingroup Random

    \brief The conditional form of wc_RNG_lock_get(): acquire only if the
    current extra bits equal expected_extra_bits, atomically replacing them
    with want_extra_bits on success.  Non-blocking with respect to the
    condition: a mismatch fails immediately rather than spinning.

    \return 0 Success
    \return BAD_FUNC_ARG rng is null.
    \return BUSY_E The lock is held, or the extra bits do not match
    expected_extra_bits.
    \return NEEDS_RECOVERY_E Entropy-invalidated and
    WC_RNG_LOCK_ENTROPY_INVALIDATED is not in expected_extra_bits.
    \return BAD_MUTEX_E (WC_RNG_HAVE_LOCK_FULL_MUTEX) The outer mutex
    failed.
    \return UNEXPECTED_STATE_E Spurious acquisition failure; retry.

    \param rng The RNG object to lock.
    \param expected_extra_bits The extra bits required for acquisition.
    \param want_extra_bits The extra bits to install on acquisition.

    \sa wc_RNG_lock_get
    \sa wc_RNG_lock_put_conditional
*/
int wc_RNG_lock_get_conditional(WC_RNG* rng,
                                WC_RNG_lock_arg_t expected_extra_bits,
                                WC_RNG_lock_arg_t want_extra_bits);

/*!
    \ingroup Random

    \brief Release rng's lock latch, clearing the supplied extra bits
    atomically with the release.

    \return 0 Success
    \return BAD_FUNC_ARG rng is null.
    \return OBJECT_NOT_LOCKED_E The latch is not held.
    \return NEEDS_RECOVERY_E Released successfully; informational notice that the
    instance is entropy-invalidated.

    \param rng The RNG object to unlock.
    \param extra_bits Caller-defined bits to clear with the release, or 0.

    \sa wc_RNG_lock_get
    \sa wc_RNG_lock_put_conditional
*/
int wc_RNG_lock_put(WC_RNG* rng, WC_RNG_lock_arg_t extra_bits);

/*!
    \ingroup Random

    \brief The conditional form of wc_RNG_lock_put(): release only if the
    current extra bits equal expected_extra_bits, atomically replacing them
    with want_extra_bits on success.

    \return 0 Success
    \return BAD_FUNC_ARG rng is null.
    \return BUSY_E The extra bits did not match expected_extra_bits.
    \return OBJECT_NOT_LOCKED_E The latch is not held.
    \return NEEDS_RECOVERY_E Released successfully; informational notice
    that the instance is entropy-invalidated.
    \return UNEXPECTED_STATE_E Spurious release failure.

    \param rng The RNG object to unlock.
    \param expected_extra_bits The extra bits required for release.
    \param want_extra_bits The extra bits to install on release.

    \sa wc_RNG_lock_put
    \sa wc_RNG_lock_get_conditional
*/
int wc_RNG_lock_put_conditional(WC_RNG* rng,
                                WC_RNG_lock_arg_t expected_extra_bits,
                                WC_RNG_lock_arg_t want_extra_bits);

/*!
    \ingroup Random

    \brief Read rng's lock word: the held/required latch bits, the
    entropy-invalidated bit, and any caller extra bits.  The snapshot is
    racy by design.

    \return 0 Success
    \return BAD_FUNC_ARG rng or state is null.

    \param rng The RNG object to interrogate.
    \param state Receives the lock word.

    \sa wc_RNG_lock_get
    \sa wc_RNG_invalidate_entropy
*/
int wc_RNG_lock_read(WC_RNG* rng, WC_RNG_lock_arg_t* state);

/*!
    \ingroup Random

    \brief Atomically set (or) the supplied caller extra bits in rng's lock
    word.  The caller should hold the latch.

    \return 0 Success
    \return BAD_FUNC_ARG rng is null.

    \param rng The RNG object to modify.
    \param extra_bits The bits to set.

    \sa wc_RNG_lock_add_extra
    \sa wc_RNG_lock_clear_extra
*/
int wc_RNG_lock_set_extra(WC_RNG* rng, WC_RNG_lock_arg_t extra_bits);

/*!
    \ingroup Random

    \brief Atomically add the supplied value to the caller extra-bits field
    of rng's lock word -- for counters carried above
    WC_RNG_LOCK_EXTRA_SHIFT.

    \return 0 Success
    \return BAD_FUNC_ARG rng is null.

    \param rng The RNG object to modify.
    \param extra_bits The value to add.

    \sa wc_RNG_lock_set_extra
    \sa wc_RNG_lock_clear_extra
*/
int wc_RNG_lock_add_extra(WC_RNG* rng, WC_RNG_lock_arg_t extra_bits);

/*!
    \ingroup Random

    \brief Atomically clear the supplied caller extra bits in rng's lock
    word.

    \return 0 Success
    \return BAD_FUNC_ARG rng is null.

    \param rng The RNG object to modify.
    \param extra_bits The bits to clear.

    \sa wc_RNG_lock_set_extra
    \sa wc_RNG_lock_add_extra
*/
int wc_RNG_lock_clear_extra(WC_RNG* rng, WC_RNG_lock_arg_t extra_bits);

/*!
    \ingroup Random

    \brief Mark rng's seed material untrusted -- for VM fork/resume and
    similar duplication events -- by latching the entropy-invalidated bit in
    the lock word.  An invalidated instance refuses service
    (NEEDS_RECOVERY_E) until recovery-reseeded.

    \return 0 Success
    \return BAD_FUNC_ARG rng is null.

    \param rng The RNG object to invalidate.

    _Example_
    \code
    // VM-resume handler
    (void)wc_RNG_invalidate_entropy(rng);
    // subsequent wc_RNG_lock_get() returns NEEDS_RECOVERY_E until recovery
    \endcode

    \sa wc_RNG_lock_get
    \sa wc_RNG_register_free_hook
*/
int wc_RNG_invalidate_entropy(WC_RNG* rng);

/*!
    \ingroup Random

    \brief Register a callback fired by wc_FreeRng() at teardown -- for
    external registries (e.g. a kernel-module registry that must reach every
    live RNG on a VM duplication event) that need to drop their reference
    when the object dies.

    \return 0 Success
    \return BAD_FUNC_ARG rng or free_hook is null.

    \param rng The RNG object to hook.
    \param free_hook The callback.
    \param arg Opaque argument passed to the callback.

    \sa wc_RNG_invalidate_entropy
    \sa wc_FreeRng
*/
int wc_RNG_register_free_hook(WC_RNG* rng, wc_RNG_free_hook_cb_t free_hook,
                              void *arg);

/*!
    \ingroup Random

    \brief Attach a random pool to rng: a buffer of size bytes of
    pre-generated output, filled by wc_RNG_Pool_Collect() and drained
    atomic-context-safely by wc_RNG_Pool_Extract().  The pool is released
    with the instance.

    \return 0 Success
    \return BAD_FUNC_ARG rng is null, or size is 0 or out of range.
    \return MEMORY_E Allocation failed.
    \return ALREADY_E The pool is already allocated.

    \param rng The RNG object to equip.
    \param size Pool capacity in bytes.

    _Example_
    \code
    wc_RNG_Pool_Alloc(rng, 256);
    wc_RNG_Pool_Collect(rng, 256);      // sleepable context
    word32 n = 16;
    if (wc_RNG_Pool_Extract(rng, out, &n) == 0) {
        // n bytes delivered, atomic-context-safe
    }
    \endcode

    \sa wc_RNG_Pool_Collect
    \sa wc_RNG_Pool_Extract
*/
int wc_RNG_Pool_Alloc(WC_RNG* rng, word32 size);

/*!
    \ingroup Random

    \brief Generate up to n bytes into rng's pool from rng itself.  The
    collect/extract hand-off is arbitrated by an atomic aperture word, so a
    single collector is safe alongside concurrent extractors.

    \return 0 Success
    \return ALREADY_E The pool is full or being drained.
    \return BAD_FUNC_ARG rng is null, has no pool, or n is 0.

    \param rng The RNG object whose pool to fill.
    \param n Maximum bytes to collect this call.

    \sa wc_RNG_Pool_Alloc
    \sa wc_RNG_Pool_Collect2
    \sa wc_RNG_Pool_Extract
*/
int wc_RNG_Pool_Collect(WC_RNG* rng, word32 n);

/*!
    \ingroup Random

    \brief The two-instance form of wc_RNG_Pool_Collect(): fill rng_dest's
    pool with output drawn from rng_src -- so a service instance's pool can
    be topped up by a daemon-owned generator.

    \return 0 Success
    \return ALREADY_E The pool is full or being drained.
    \return BAD_FUNC_ARG rng_dest or rng_src is null, or rng_dest has no
    pool, or n is 0.
    \return BAD_STATE_E The pool is not allocated.
    \return NOT_READY_E The source could not serve; retry later.

    \param rng_dest The RNG object whose pool to fill.
    \param rng_src The RNG object to draw output from.
    \param n Maximum bytes to collect this call.

    \sa wc_RNG_Pool_Collect
*/
int wc_RNG_Pool_Collect2(WC_RNG* rng_dest, WC_RNG* rng_src, word32 n);

/*!
    \ingroup Random

    \brief Drain up to *n bytes from rng's pool into out --
    atomic-context-safe.  On success *n reports the bytes actually
    delivered.

    \return 0 Success
    \return NOT_READY_E The pool is empty or being filled.
    \return BAD_FUNC_ARG rng, out, or n is null, or rng has no pool.
    \return BAD_STATE_E The pool is not allocated.
    \return RNG_FAILURE_E The instance is out of service.

    \param rng The RNG object whose pool to drain.
    \param out Receives the output.
    \param n In: bytes requested; out: bytes delivered.

    \sa wc_RNG_Pool_Collect
    \sa wc_RNG_Pool_Current
*/
int wc_RNG_Pool_Extract(WC_RNG* rng, byte* out, word32* n);

/*!
    \ingroup Random

    \brief Report the pool's current fill in bytes.  The snapshot is racy by
    design.

    \return 0 Success
    \return BAD_FUNC_ARG rng or n is null, or rng has no pool.

    \param rng The RNG object to interrogate.
    \param n Receives the fill.

    \sa wc_RNG_Pool_Extract
*/
int wc_RNG_Pool_Current(WC_RNG* rng, word32* n);

/*!
    \ingroup Random

    \brief Snapshot the global RNG debug counters (WC_RNG_DEBUG_STATS) --
    seeds and reseeds by provenance, generates, pool and bank traffic --
    into s, for later delta accounting with wc_rng_debug_stats_sum().

    \return 0 Success
    \return BAD_FUNC_ARG s is null.

    \param s Receives the snapshot.
    \param rng Optional instance for per-instance context, or null.

    \sa wc_rng_debug_stats_sum
    \sa wc_rng_debug_stats_restore
*/
int wc_rng_debug_stats_snap(struct wc_rng_debug_stats_snapshot *s,
                            const WC_RNG *rng);

/*!
    \ingroup Random

    \brief Restore the global RNG debug counters from a snapshot -- so a
    test can unwind its own accounting.

    \return 0 Success
    \return BAD_FUNC_ARG s is null.

    \param s The snapshot to restore from.
    \param rng Optional instance for per-instance context, or null.

    \sa wc_rng_debug_stats_snap
*/
int wc_rng_debug_stats_restore(const struct wc_rng_debug_stats_snapshot *s,
                               WC_RNG *rng);

/*!
    \ingroup Random

    \brief Accumulate the current global RNG debug counters into s --
    combined with a prior wc_rng_debug_stats_snap(), a delta accounting of
    the interval's RNG activity.

    \return 0 Success
    \return BAD_FUNC_ARG s is null.

    \param s The snapshot to accumulate into.
    \param rng Optional instance for per-instance context, or null.

    \sa wc_rng_debug_stats_snap
*/
int wc_rng_debug_stats_sum(struct wc_rng_debug_stats_snapshot *s,
                           const WC_RNG *rng);
