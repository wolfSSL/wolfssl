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

    One WC_RNG may be shared between threads for generating and reseeding:
    wc_RNG_GenerateBlock(), wc_RNG_DRBG_Reseed(), wc_RNG_DRBG_Reseed_Nonce()
    and wc_RNG_DRBG_Reseed_Now() each hold the instance lock.  So do the DRBG
    management calls: wc_RNG_DRBG_Stir(), wc_RNG_DRBG_Stir_Nonce() and
    wc_RNG_DRBG_ScheduleReseed(), and in --enable-rng-extras builds
    wc_RNG_DRBG_NextStirNow(), wc_RNG_DRBG_NextSeedNow() and
    wc_RNG_DRBG_NextSeedNow_Nonce().  The generate path calls their internal
    cores, which already run under the lock.

    wc_RNG_DRBG_ReseedRBGC() and wc_RNG_DRBG_StirRBGC() are the exception:
    they draw from a second instance, so locking both would put two instance
    locks in play at once, and two threads reseeding each other from the
    other could then wait on each other for good.  A caller that needs them
    on a shared instance stops the other threads first.

    WC_RNG_NO_AUTO_LOCK (configure --disable-rng-autolock) leaves the lock out;
    CMSIS-RTOS v1 builds have none, its mutex pool holds ten.  Every backend
    but a crypto callback runs with the lock held; a callback answers first,
    so it may fall back to the same instance.
    A seed callback runs with the lock held and must not use the RNG API.
    wc_InitRng*() and wc_FreeRng() do not lock; initialize only a new or
    freed WC_RNG, with no other thread using it.

    POSIX lets a forked child of a threaded process only exec.  Where the
    build has pthread_atfork(), unnamed POSIX semaphores and the dladdr()
    pin, fork handlers let the child keep using its WC_RNG: the parent holds
    every lock across fork() and the child releases them and reseeds, so
    each fork() waits for every live instance's generate in flight.  The
    child should use an instance it already has: wc_InitRng() there still
    waits on a mutex the handlers do not cover.  --disable-rng-autofork leaves
    them out; a user_settings build defines WC_RNG_AUTOFORK to turn them on.
    The child's reseed uses the configured allocator and seed source, which
    must therefore work after fork().  wolfCrypt_Init() or the first
    wc_InitRng() registers them; they can never be unregistered,
    so the library pins itself against dlclose().  They cover WC_RNG locks
    only, not clone(), vfork() or _Fork().  A fork() from inside a seed or
    hash callback works: that thread holds the lock, so the handler leaves
    it alone and the child frees it as usual.  A fork() called from a signal
    handler can hang the caller, if the signal caught a thread part-way
    through taking or releasing a lock; POSIX does not allow fork() from a
    signal handler with handlers like these anyway.  Values stay safe either
    way, with or without the handlers: the child reseeds on its pid change.

    Builds without the handlers, macOS among them, leave a forked child only
    exec(): a child that calls the RNG instead blocks for good if any thread
    held the instance lock at fork() time.  A fork() from
    a single threaded process is unaffected, since no lock can be held by a
    thread the child does not have.

    \return 0 on success.
    \return MEMORY_E XMALLOC or the fork handler registration failed
    \return WINCRYPT_E wc_GenerateSeed: failed to acquire context
    \return CRYPTGEN_E wc_GenerateSeed: failed to get random
    \return BAD_FUNC_ARG wc_RNG_GenerateBlock input is null or sz exceeds
    MAX_REQUEST_LEN
    \return DRBG_CONT_FIPS_E wc_RNG_GenerateBlock: Hash_gen returned
    DRBG_CONT_FAILURE
    \return ENTROPY_RT_E or ENTROPY_APT_E wc_InitRng: the SP 800-90B seed
    health test rejected the entropy gathered to instantiate
    \return RNG_FAILURE_E wc_RNG_GenerateBlock: Default error.  rng’s
    status originally not ok, or set to DRBG_FAILED
    \return BAD_MUTEX_E the lock that lets threads share this rng could not
    be created; define WC_RNG_NO_AUTO_LOCK to build without it

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
    \return ENTROPY_RT_E or ENTROPY_APT_E the SP 800-90B seed health test
    rejected the entropy gathered for a reseed
    \return NOT_READY_E a recovery reseed failed retryably with reseed
    runway remaining; the instance is not condemned and the call may be
    retried
    \return RNG_FAILURE_E Default error. rng’s status originally not
    ok, or set to DRBG_FAILED
    \return BAD_MUTEX_E the rng's lock could not be taken

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
int  wc_RNG_GenerateBlock(WC_RNG* rng, byte* output, word32 sz);

/*!
    \ingroup Random

    \brief Calls wc_RNG_GenerateBlock to copy a byte of pseudorandom
    data to b. Will reseed rng if needed.

    \return 0 on success
    \return BAD_FUNC_ARG an input is null or sz exceeds MAX_REQUEST_LEN
    \return DRBG_CONT_FIPS_E Hash_gen returned DRBG_CONT_FAILURE
    \return RNG_FAILURE_E Default error.  rng’s status originally not
    ok, or set to DRBG_FAILED
    \return BAD_MUTEX_E the rng's lock could not be taken

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

    \brief Tears down an RNG instance: zeroizes and releases its DRBG state.
    The WC_RNG must have come from wc_InitRng*() or be zeroed.

    \details wc_FreeRng() is a lock-protocol participant, not a lock-protocol
    client: it acquires the instance lock internally with destruction-specific
    semantics, and callers must not hold the lock across the call (never
    bracket wc_FreeRng() with wc_RNG_lock_get()/wc_RNG_lock_put() -- a caller
    already holding the lock uses wc_FreeRng_PreLocked() instead).  BUSY_E
    reports a live lease -- or, with WC_RNG_HAVE_POOL, a pool collector
    holding the ring's claim (wc_RNG_Pool_Collect2() mid-generate, or
    wc_RNG_Pool_Alloc() mid-attach): nothing was changed, and the call can
    be retried once the instance quiesces; the collector's hold is bounded
    (one generate, no in-line reseed).  STILL_REFERENCED_E reports that spawned
    RBGC children still reference the instance as their reseed parent: all
    cryptographically sensitive state has already been zeroized and the
    instance's status returns to the uninitialized state, but the object's
    memory must remain valid until the last child is freed, after which
    retrying wc_FreeRng() completes the teardown.  Reinitializing an instance
    after a nonzero return, other than through the documented preserve-flagged
    in-place reinit under a held lock, is forbidden.

    \return 0 on success
    \return BAD_FUNC_ARG rng is NULL
    \return BUSY_E the instance lock is held, or a pool collector holds the
    ring (WC_RNG_HAVE_POOL); nothing was done
    \return STILL_REFERENCED_E sensitive state was zeroized, but spawned
    children still reference the instance; retry after they are freed
    \return RNG_FAILURE_E state teardown failed

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

    \brief Tears down an RNG instance whose lock the caller already holds.

    \details The core of wc_FreeRng() for callers inside a held-lock bracket
    (a lease from wc_RNG_lock_get(), or a bank checkout): that the lock is
    held is verified on entry (the word cannot say by whom -- holding it is
    the caller's contract), no lock acquisition or release is performed, and the
    lock remains held on return, ready for an in-place reinitialization with
    the WC_RNG_INIT_FLAG_PRESERVE_LOCK semantics or for release by the
    caller.  BUSY_E is returned only for a pool collector holding the ring's
    claim (WC_RNG_HAVE_POOL; see wc_FreeRng()): it is a try-once refusal,
    never a wait, so it is safe from atomic context, and nothing was torn
    down -- the instance is intact for a retry.  STILL_REFERENCED_E has the
    same semantics as for wc_FreeRng(), and a retry while still holding the
    lock converges without a re-acquisition race.

    \return 0 on success
    \return BAD_FUNC_ARG rng is NULL
    \return OBJECT_NOT_LOCKED_E the instance requires locking and the caller
    does not hold the lock
    \return BUSY_E a pool collector holds the ring; nothing was done
    \return STILL_REFERENCED_E sensitive state was zeroized, but spawned
    children still reference the instance; retry after they are freed
    \return RNG_FAILURE_E state teardown failed

    \param rng random number generator initialized with wc_InitRng*(), with
    the instance lock held by the caller

    \sa wc_FreeRng
    \sa wc_RNG_lock_get
    \sa wc_RNG_lock_put
*/
int  wc_FreeRng_PreLocked(WC_RNG* rng);

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
    \return BAD_MUTEX_E the lock that lets threads share this rng could not
    be created

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
    \return BAD_MUTEX_E the lock that lets threads share this rng could not
    be created
    \return MEMORY_E the fork handlers could not be registered

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
    \return BAD_MUTEX_E the lock that lets threads share this rng could not
    be created
    \return MEMORY_E the fork handlers could not be registered

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
int wc_InitRngNonce(WC_RNG* rng, const byte* nonce, word32 nonceSz);

/*!
    \ingroup Random
    \brief Initializes WC_RNG with nonce and extended parameters.

    \return 0 On success
    \return BAD_FUNC_ARG If rng is NULL
    \return RNG_FAILURE_E Initialization failed
    \return BAD_MUTEX_E the lock that lets threads share this rng could not
    be created
    \return MEMORY_E the fork handlers could not be registered

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
int wc_InitRngNonce_ex(WC_RNG* rng, const byte* nonce, word32 nonceSz,
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
    \brief Reseeds DRBG with new entropy.  The material is credited: the
    reseed counter resets.

    \details In RBG-chain builds, a successful user-supplied reseed marks
    rng with the user-provenance stratum sentinel
    (WC_RNG_RBGC_USER_SEED_STRATUM).  When built with
    WC_RNG_RBGC_STRATUM_IMMUTABLE (required for FIPS), the stratum is never
    lowered, keeping instances whose credited seeding is of unknown
    provenance permanently distinguishable from ESV-seeded lineage, and a
    credited user-class reseed of any instance below the sentinel -- a
    primary-seeded root or an RBG-chain member alike -- is refused with
    WRONG_TYPE_OBJECT_E: the credited reseed would reset the reseed counter
    on unknown-provenance entropy while the immutable stratum continued to
    advertise vetted-provenance seeding.  Uncredited stirs
    (wc_RNG_DRBG_Stir()) remain available precisely because they claim
    nothing; in such builds only instances instantiated with
    wc_InitRngNonce_UserSeed() accept user-class reseeds.  The seed is not
    evaluated by wc_RNG_TestSeed() -- deliberately, so KAT harnesses can
    inject fixed vectors; calling it beforehand is the caller's
    responsibility.  While a reseed obligation stands (the reseed counter at
    its interval, or the entropy invalidated), a seed shorter than
    WC_DRBG_SEED_SZ is refused with BAD_LENGTH_E rather than allowed to
    clear the obligation.  A condemned instance (DRBG_FAILED) refuses with
    RNG_FAILURE_E: recovery is wc_FreeRng() then wc_InitRng*(), not in-place
    resurrection.

    \return 0 On success
    \return BAD_FUNC_ARG If rng or seed is NULL
    \return RNG_FAILURE_E Reseed failed, or rng is condemned (see \details)
    \return BAD_MUTEX_E the rng's lock could not be taken
    \return BAD_LENGTH_E seed is undersized while a reseed obligation
    stands (see \details).
    \return WRONG_TYPE_OBJECT_E rng has no DRBG (RDRAND et al.), or rng is
    below the user-provenance sentinel and the build is
    WC_RNG_RBGC_STRATUM_IMMUTABLE (see \details).

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
    birth: WC_RNG_INIT_FLAG_LOCK_REQUIRED latches the sticky lock-required
    policy bit, so there is no reachable state in which the instance serves
    without its lock policy; WC_RNG_INIT_FLAG_LOCK_INITIALLY constructs into
    a held lease, to be released with wc_RNG_lock_put();
    WC_RNG_INIT_FLAG_USE_FULL_MUTEX layers a blocking wolfSSL_Mutex
    outermost around the lock latch, for user-mode sharing of one instance
    among threads (requires WC_RNG_HAVE_LOCK_FULL_MUTEX).

    WC_RNG_INIT_FLAG_USE_AUTO_LOCK and WC_RNG_INIT_FLAG_NO_AUTO_LOCK decide,
    for this instance alone, whether the automatic per-call lock is created,
    whatever --enable-rng-autolock settled for the build.  Use the first when
    the instance will be shared between threads: a build without that lock
    refuses with NOT_COMPILED_IN rather than returning an instance the caller
    would wrongly believe is serialized.  Use the second to drop the per-call
    cost on an instance one thread owns; such an instance behaves as it does
    with the lock left out of the build, so sharing it between threads is a
    data race and, where the fork handlers exist, it is not fork covered.
    Setting both, or the first alongside WC_RNG_INIT_FLAG_USE_FULL_MUTEX,
    is BAD_FUNC_ARG in every build.

    Naming neither leaves it to the build: on by default, or off where
    --disable-rng-autolock-default (WC_RNG_AUTO_LOCK_DEFAULT_OFF) built the
    lock in without switching it on.  In such a build only the two flag
    forms, wc_InitRng_ex2() and wc_InitRngNonce_ex2(), can ask for the lock;
    wc_InitRng(), wc_InitRng_ex(), wc_rng_new() and wc_rng_new_ex() take no
    flags, so their instances go unlocked and cannot opt in.

    \return 0 Success
    \return BAD_FUNC_ARG rng is null, or the flags contradict each other.
    \return NOT_COMPILED_IN A requested flag is not compiled in.

    \param rng The RNG object to initialize.
    \param heap Heap hint for dynamic allocation.
    \param devId Device id, or INVALID_DEVID.
    \param flags Bitwise-or of WC_RNG_INIT_FLAG_* attributes.

    _Example_
    \code
    WC_RNG rng;
    if (wc_InitRng_ex2(&rng, NULL, INVALID_DEVID,
                       WC_RNG_INIT_FLAG_LOCK_REQUIRED |
                       WC_RNG_INIT_FLAG_LOCK_INITIALLY) != 0) {
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
    \param perso Optional personalization string (may be null).
    \param persoSz Length of perso in bytes.
    \param flags Bitwise-or of WC_RNG_INIT_FLAG_* attributes.

    \sa wc_InitRng_ex2
    \sa wc_InitRngNonce_ex
*/
int wc_InitRngNonce_ex2(WC_RNG* rng, const byte* nonce, word32 nonceSz,
                        const byte *perso, word32 persoSz,
                        void* heap, int devId, word32 flags);

/*!
    \ingroup Random

    \brief Instantiate the module-wide fallback RNG from the module's primary
    seed source (WC_RNG_HAVE_GLOBAL_FALLBACK_RNG).  The global fallback is a
    single, lock-disciplined (WC_RNG_INIT_FLAG_LOCK_REQUIRED), stratum-0
    instance that serves as a reseed root of last resort: an RBG-chain
    member whose retained parent is unavailable reseeds from it on the
    PollAndReSeed() ladder (under FIPS only when it is a sibling of the
    parent, per the SP 800-90C closed list of alternative sources), and in
    the kernel module the entropy daemon keeps it fresh.  It is never
    admitted as a spawn parent (see wc_InitRngNonceRBGC()).  The call takes
    the instance's lock for the duration; _LOCK_REQUIRED and
    _LOCK_INITIALLY are implied and need not be passed.

    \return 0 Success
    \return ALREADY_E Already instantiated.
    \return RNG_FAILURE_E, DRBG_CONT_FIPS_E The instance is condemned;
    release it with wc_RNG_global_fallback_free() before reinstantiating.
    \return BUSY_E, BAD_MUTEX_E The instance's lock could not be taken.
    \return Any error from wc_InitRngNonce_ex2().

    \param nonce Optional nonce used as additional instantiation input.
    \param nonceSz Length of nonce in bytes.
    \param perso Optional personalization string (may be null).
    \param persoSz Length of perso in bytes.
    \param heap Heap hint for dynamic allocation.
    \param devId Device id, or INVALID_DEVID.
    \param flags Bitwise-or of WC_RNG_INIT_FLAG_* attributes.

    \sa wc_RNG_global_fallback_init_user_seed
    \sa wc_RNG_global_fallback_get
    \sa wc_RNG_global_fallback_free
*/
int wc_RNG_global_fallback_init(const byte* nonce, word32 nonceSz,
                                const byte *perso, word32 persoSz,
                                void* heap, int devId, word32 flags);

/*!
    \ingroup Random

    \brief The user-seeded form of wc_RNG_global_fallback_init(): the
    fallback is instantiated from caller-supplied material, with the
    provenance consequences of wc_InitRngNonce_UserSeed() (stratum
    WC_RNG_RBGC_USER_SEED_STRATUM, so under FIPS it cannot serve as an
    alternative source for any module-seeded chain member).  For KAT
    harnesses and deterministic test rigs.

    \return 0 Success
    \return BAD_FUNC_ARG seed is null.
    \return Otherwise as for wc_RNG_global_fallback_init() and
    wc_InitRngNonce_UserSeed().

    \param seed Caller-supplied seed material, credited in place of the
    module's seed source.
    \param seedSz Length of seed in bytes; at least WC_DRBG_SEED_SZ.
    \param nonce Optional nonce used as additional instantiation input.
    \param nonceSz Length of nonce in bytes.
    \param perso Optional personalization string (may be null).
    \param persoSz Length of perso in bytes.
    \param heap Heap hint for dynamic allocation.
    \param devId Device id, or INVALID_DEVID.
    \param flags Bitwise-or of WC_RNG_INIT_FLAG_* attributes.

    \sa wc_RNG_global_fallback_init
    \sa wc_InitRngNonce_UserSeed
*/
int wc_RNG_global_fallback_init_user_seed(const byte* seed, word32 seedSz,
                                          const byte* nonce, word32 nonceSz,
                                          const byte *perso, word32 persoSz,
                                          void* heap, int devId, word32 flags);

/*!
    \ingroup Random

    \brief Obtain a pointer to the global fallback RNG, for use as an
    explicit reseed root (wc_RNG_DRBG_ReseedRBGC(), the next-seed banker)
    or for maintenance by a daemon.  No lock is taken: the instance is
    lock-required, so every operation on it goes through
    wc_RNG_lock_get()/wc_RNG_lock_put() as usual.  The pointer is refused
    unless the instance is in service, which is only possible after a
    successful wc_RNG_global_fallback_init*().

    \return 0 Success; *rng points at the instance.
    \return BAD_FUNC_ARG rng is null.
    \return NOT_READY_E, RNG_FAILURE_E, DRBG_CONT_FIPS_E The instance is
    not in service (as for wc_RNG_Status()).

    \param rng Receives the instance pointer.

    \sa wc_RNG_global_fallback_init
    \sa wc_RNG_Status
*/
int wc_RNG_global_fallback_get(WC_RNG **rng);

/*!
    \ingroup Random

    \brief Tear down the global fallback RNG: wc_FreeRng() on the instance,
    with that function's contract -- BUSY_E leaves it intact for a retry,
    STILL_REFERENCED_E means chain members still name it as a reseed root
    and its state has been zeroized.  After a successful return it can be
    instantiated again.

    \return As for wc_FreeRng().

    \sa wc_RNG_global_fallback_init
    \sa wc_FreeRng
*/
int wc_RNG_global_fallback_free(void);

/*!
    \ingroup Random

    \brief Initialize a WC_RNG instantiated from caller-supplied seed
    material, used in place of the module's seed source, with an optional
    nonce and personalization string.  Every other aspect of instantiation is
    wc_InitRngNonce_ex2()'s.  The instance is born at the user-provenance
    stratum sentinel (WC_RNG_RBGC_USER_SEED_STRATUM).

    \details The instance's credited seeding is of unknown provenance,
    permanently distinguishing it from ESV-seeded lineage; when built with
    WC_RNG_RBGC_STRATUM_IMMUTABLE (required for FIPS) the marking is
    irrevocable.  Under FIPS 140-3, seeding from caller material is not an
    approved entropy path; this function exists for KAT and ACVP-style
    harnesses that must inject fixed vectors, and for legacy
    interoperation.  The seed is deliberately exempt from the FIPS 140-3 IG 10.3.A /
    SP 800-90B health tests applied to module-gathered seed material:
    wc_RNG_TestSeed() is not called on it, so fixed KAT vectors are not
    rejected as non-random; calling wc_RNG_TestSeed() beforehand is the
    caller's responsibility where vetting is wanted.  A null seed is
    refused with BAD_FUNC_ARG, and an undersized seed (seedSz below
    WC_DRBG_SEED_SZ, including zero) with BAD_LENGTH_E: an argument mistake
    must not mint a primary-class (stratum-0) instance the caller believes
    is user-seeded.  Builds without WC_RNG_HAVE_RBGC refuse with
    NOT_COMPILED_IN -- the stratum bookkeeping that quarantines user
    provenance lives in the RBG-chain apparatus.  On instantiations that
    bypass the DRBG (HAVE_INTEL_RDRAND without HAVE_HASHDRBG), the seed,
    nonce, and personalization pass the shape and sizing checks and are
    then silently unused; gate on wc_RNG_DRBG_Present() where that
    matters.

    The exact instantiation input, for KAT harnesses: the Hash_DRBG
    entropy_input is seed truncated, or zero-padded, to WC_DRBG_SEED_SZ
    bytes when a nonce is supplied, and to WC_DRBG_SEED_SZ +
    WC_DRBG_SEED_SZ/2 bytes when nonceSz is 0 (the SP 800-90A
    entropy-plus-nonce form, the nonce half drawn from the same material);
    nonce (if any) and perso follow as for wc_InitRngNonce_ex2().  Material
    beyond that length is never consumed.  (Non-FIPS builds with
    WOLFSSL_RNG_USE_FULL_SEED use WC_DRBG_SEED_SZ - SEED_BLOCK_SZ and
    WC_DRBG_MAX_SEED_SZ - SEED_BLOCK_SZ respectively.)

    \return 0 Success
    \return BAD_FUNC_ARG rng or seed is null; or nonce or perso is null
    with its length nonzero; or the flags contradict each other.
    \return BAD_LENGTH_E seedSz is below WC_DRBG_SEED_SZ.
    \return NOT_COMPILED_IN The build lacks WC_RNG_HAVE_RBGC, or a
    requested flag is not compiled in.

    \param rng The RNG object to initialize.
    \param seed Caller-supplied seed material, credited in place of the
    module's seed source.
    \param seedSz Length of seed in bytes; at least WC_DRBG_SEED_SZ.
    \param nonce Optional nonce used as additional instantiation input.
    \param nonceSz Length of nonce in bytes.
    \param perso Optional personalization string (may be null).
    \param persoSz Length of perso in bytes.
    \param heap Heap hint for dynamic allocation.
    \param devId Device id, or INVALID_DEVID.
    \param flags Bitwise-or of WC_RNG_INIT_FLAG_* attributes.

    _Example_
    \code
    WC_RNG rng;
    const byte katSeed[WC_DRBG_SEED_SZ] = { ... };
    if (wc_InitRngNonce_UserSeed(&rng, katSeed, sizeof(katSeed),
                                 NULL, 0, NULL, 0,
                                 NULL, INVALID_DEVID,
                                 WC_RNG_INIT_FLAG_NONE) != 0) {
        // error handling
    }
    // rng reports WC_RNG_RBGC_USER_SEED_STRATUM via
    // wc_RNG_DRBG_GetRBGCStratum()
    \endcode

    \sa wc_InitRngNonce_ex2
    \sa wc_RNG_DRBG_Reseed_Nonce
    \sa wc_RNG_TestSeed
    \sa wc_RNG_DRBG_GetRBGCStratum
*/
int wc_InitRngNonce_UserSeed(WC_RNG* rng, const byte* seed, word32 seedSz,
                             const byte* nonce, word32 nonceSz,
                             const byte *perso, word32 persoSz,
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
*/
int wc_RNG_GetStatus(const WC_RNG* rng);

/*!
    \ingroup Random

    \brief The error-code form of wc_RNG_GetStatus(): 0 for an in-service
    instance, else the code its state maps to -- so a caller can gate on an
    instance, or percolate its state, with one call and no enum switch.  A
    pure status read: no lock is taken and nothing is propagated (contrast
    wc_RNG_entropy_needs_recovery(), which also delivers a pending epoch
    event and checks the reseed schedule).

    \return 0 In service (WC_DRBG_OK).
    \return NOT_READY_E Not instantiated, or torn down by wc_FreeRng()
    (WC_DRBG_NOT_INIT).
    \return RNG_FAILURE_E Condemned (WC_DRBG_FAILED): recovery is
    wc_FreeRng() then wc_InitRng*().
    \return DRBG_CONT_FIPS_E Failed a continuous test (WC_DRBG_CONT_FAILED).
    \return BAD_FUNC_ARG rng is null, or its state is not a known value.

    \param rng The RNG object to interrogate.

    \sa wc_RNG_GetStatus
    \sa wc_RNG_entropy_needs_recovery
*/
int wc_RNG_Status(const WC_RNG* rng);

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
*/
int wc_RNG_DRBG_ScheduleReseed(WC_RNG* rng);

/*!
    \ingroup Random

    \brief Immediately reseed rng from the module's built-in, registered, or
    associated seed source, with an optional nonce as additional input.  The
    credited reseed resets the reseed counter.

    \details For an SP 800-90C chain member (RBGC stratum > 0, in builds with
    instance locking), the seed source is found by a fallback ladder: the
    retained parent is tried first (nonblocking acquisition); if the parent
    is unavailable, the global fallback instance (under FIPS, only when it
    qualifies as a sibling of the parent -- both primary-seeded); and only
    then the module's primary seed source -- or, for an instance initialized
    with WC_RNG_INIT_FLAG_NO_PRIMARY_SEED, the reseed is deferred instead and
    the call reports the deferral.  For a root (stratum 0), the module's seed
    source serves directly.

    \return 0 Success
    \return BAD_FUNC_ARG rng is null, or nonce is null with nonceSz nonzero.
    \return WRONG_TYPE_OBJECT_E rng has no DRBG (RDRAND et al.).
    \return DRBG_CONT_FIPS_E The continuous test failed; the DRBG is out of
    service.
    \return NOT_READY_E The reseed failed retryably (or was deferred under
    WC_RNG_INIT_FLAG_NO_PRIMARY_SEED) with reseed runway remaining; the
    counter is not reset and the instance remains in service.
    \return RNG_FAILURE_E The DRBG is out of service, or the reseed failed
    with no reseed runway remaining; the instance is condemned.
    \return ENTROPY_RT_E or ENTROPY_APT_E The SP 800-90B seed health test
    rejected the gathered seed; the reseed did not happen and the instance
    remains usable until its reseed interval is reached.

    \param rng The RNG object to reseed.
    \param nonce Optional additional input.
    \param nonceSz Length of nonce in bytes.

    \sa wc_RNG_DRBG_ScheduleReseed
    \sa wc_RNG_DRBG_Reseed_Nonce
*/
int wc_RNG_DRBG_Reseed_Now(WC_RNG* rng, const byte* nonce, word32 nonceSz);

/*!
    \ingroup Random

    \brief The forced-primary form of wc_RNG_DRBG_Reseed_Now(): reseed rng
    directly from the module's primary (initial) randomness source, bypassing
    the chain fallback ladder, with an optional nonce as additional input.
    This is the SP 800-90A prediction-resistance primitive -- a reseed from a
    live entropy source immediately ahead of generation -- and is available
    to SP 800-90C chain members (RBGC stratum > 0) as well: the initial
    randomness source is on the SP 800-90C closed list of alternative
    sources, so the forced reseed is chain-conformant.

    \details Prediction resistance is a property of an atomic
    reseed-then-generate sequence, not of the reseed alone, so in builds
    with instance locking the instance must assert WC_RNG_LOCK_REQUIRED and
    the caller must hold its lock: take the lock, call this function, call
    wc_RNG_GenerateBlock(), and only then release.  Output generated outside
    that bracket carries no prediction-resistance claim.  Multithreaded
    builds without the locking facility cannot provide the bracket (nor a
    safe flags update) and refuse with NOT_COMPILED_IN; single-threaded
    builds proceed, their atomicity being trivial.  In
    WC_RNG_RBGC_STRATUM_IMMUTABLE builds (required for FIPS) the stratum
    label keeps its birth value -- the label records the chain construction
    -- while the live seed's provenance becomes primary; other builds
    relabel the instance stratum 0.  The prediction-resistance claim
    follows the label, not the seed: SP 800-90C (Table 1) reserves
    prediction resistance to a DRBG whose entropy source is accessed
    directly, which an RBG-chain member (stratum > 0) by construction is
    not, so under WC_RNG_RBGC_STRATUM_IMMUTABLE a chain member's output
    after this call is a conformant reseed-from-the-initial-source but
    carries no prediction-resistance claim; only a stratum-0 instance's
    does.  In relabeling builds the stratum-0 relabel is what the claim
    rides on.  The call performs a full inline seed
    acquisition, which with a slow entropy source can take tens of
    milliseconds; in kernel builds a non-blockable calling context is
    refused with BUSY_E, leaving the instance unharmed and the call
    retryable from a blockable context.

    \return 0 Success
    \return BAD_FUNC_ARG rng is null, or nonce is null with nonceSz nonzero.
    \return OBJECT_NOT_LOCKED_E The instance requires its lock and the
    caller does not hold it.
    \return WRONG_TYPE_OBJECT_E The instance has no DRBG (RDRAND et al.),
    does not assert WC_RNG_LOCK_REQUIRED (in builds with instance locking),
    or was initialized with WC_RNG_INIT_FLAG_NO_PRIMARY_SEED.
    \return NOT_COMPILED_IN Multithreaded build without the locking
    facility.
    \return BUSY_E The seed acquisition was refused in a non-blockable
    context; the instance remains in service.
    \return NOT_READY_E, RNG_FAILURE_E, DRBG_CONT_FIPS_E, ENTROPY_RT_E,
    ENTROPY_APT_E As for wc_RNG_DRBG_Reseed_Now().

    \param rng The RNG object to reseed; in builds with instance locking it
    must assert WC_RNG_LOCK_REQUIRED and be held by the caller.
    \param nonce Optional additional input.
    \param nonceSz Length of nonce in bytes.

    _Example_
    \code
    // prediction-resistant request: reseed and generate under one hold
    ret = wc_RNG_lock_get(rng, 0);
    if (ret == 0) {
        ret = wc_RNG_DRBG_Reseed_Now_Primary(rng, NULL, 0);
        if (ret == 0)
            ret = wc_RNG_GenerateBlock(rng, out_buf, out_len);
        (void)wc_RNG_lock_put(rng, 0);
    }
    \endcode

    \sa wc_RNG_DRBG_Reseed_Now
    \sa wc_RNG_DRBG_NextSeedGenerate_Primary
*/
int wc_RNG_DRBG_Reseed_Now_Primary(WC_RNG* rng, const byte* nonce,
                                   word32 nonceSz);

/*!
    \ingroup Random

    \brief Reseed rng's DRBG with caller-supplied seed material and an
    optional nonce as additional input, folded in a single derivation pass.
    The material is credited: the reseed counter resets.

    \details The single pass is one reseed operation over both inputs, not
    a reseed followed by a stir.  For refusal, sizing, provenance-sentinel,
    and wc_RNG_TestSeed() semantics, see wc_RNG_DRBG_Reseed().

    \return 0 Success
    \return RNG_FAILURE_E rng is condemned (status DRBG_FAILED): a
    condemned instance does not accept a credited reseed; recover with
    wc_FreeRng() then wc_InitRng*().
    \return BAD_FUNC_ARG rng or seed is null, or nonce is null with nonceSz
    nonzero.
    \return BAD_MUTEX_E the rng's lock could not be taken.
    \return BAD_LENGTH_E seed is undersized while a reseed obligation
    stands.
    \return WRONG_TYPE_OBJECT_E rng has no DRBG (RDRAND et al.), or rng is
    below the user-provenance sentinel and the build is
    WC_RNG_RBGC_STRATUM_IMMUTABLE.

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

    \details A standing recovery obligation refuses the stir: nothing
    mutates an entropy-invalidated or reseed-due DRBG except recovery.  In
    builds with instance locking, the obligation check also delivers any
    pending global epoch event into the instance (see
    wc_RNG_entropy_needs_recovery()).

    \return 0 Success
    \return BAD_FUNC_ARG rng or seed is null.
    \return WRONG_TYPE_OBJECT_E rng has no DRBG (RDRAND et al.).
    \return NEEDS_RECOVERY_E A recovery obligation stands (entropy
    invalidated, entropy epoch advanced, or reseed due); recover with a
    credited reseed first.
    \return RNG_FAILURE_E The instance is in a failed state.
    \return DRBG_CONT_FIPS_E The instance failed a continuous test.
    \return BAD_MUTEX_E The rng's lock could not be taken.

    \param rng The RNG object to stir.
    \param seed Material to mix in.
    \param seedSz Length of seed in bytes.

    \sa wc_RNG_DRBG_Reseed
    \sa wc_RNG_DRBG_Stir_Nonce
    \sa wc_RNG_entropy_needs_recovery
*/
int wc_RNG_DRBG_Stir(WC_RNG* rng, const byte* seed, word32 seedSz);

/*!
    \ingroup Random

    \brief The nonce-bearing form of wc_RNG_DRBG_Stir().

    \return 0 Success
    \return BAD_FUNC_ARG rng or seed is null.
    \return WRONG_TYPE_OBJECT_E rng has no DRBG (RDRAND et al.).
    \return NEEDS_RECOVERY_E A recovery obligation stands; see
    wc_RNG_DRBG_Stir().
    \return RNG_FAILURE_E The instance is in a failed state.
    \return DRBG_CONT_FIPS_E The instance failed a continuous test.
    \return BAD_MUTEX_E The rng's lock could not be taken.

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
    parent, drawing its seed material from parent's generate function in place
    of the module's seed source.  Every other aspect of instantiation is
    wc_InitRng_ex2()'s.  The child is tagged with stratum (parent's stratum +
    1), and is relabeled at each credited reseed based on the seed source's
    stratum unless built with WC_RNG_RBGC_STRATUM_IMMUTABLE (required for FIPS);
    its claimable security strength is capped by parent's, and it has no
    prediction resistance.  The caller must hold exclusive access to parent for
    the duration of the call; the spawn debits parent's reseed counter by one
    generate.

    RNGs instantiated by `wc_InitRng()` or `wc_InitRng_ex2()` are root RNGs
    corresponding to SP 800-90C Sec. 7.2.1.1; RNGs instantiated by
    `wc_InitRngRBGC()` or `wc_InitRngNonceRBGC()` from a root or from any deeper
    member correspond to the construction in Sec. 7.2.1.2.

    \return 0 Success
    \return BAD_FUNC_ARG child or parent is null, or child equals parent.
    \return SEQ_OVERFLOW_E parent's stratum is at the representable maximum.

    \param child The caller-provided WC_RNG to instantiate (uninitialized).
    \param parent The chain parent to draw seed material from.
    \param flags Bitwise-or of WC_RNG_INIT_FLAG_* attributes for the child.

    _Example_
    \code
    WC_RNG root, child;
    wc_InitRng(&root);
    if (wc_InitRngRBGC(&child, &root, WC_RNG_INIT_FLAG_NONE) == 0) {
        // child serves independently; release with wc_FreeRng(&child)
    }
    \endcode

    \sa wc_InitRng
    \sa wc_InitRng_ex2
    \sa wc_InitRngNonceRBGC
    \sa wc_InitRngRBGC_New
    \sa wc_RNG_DRBG_ReseedRBGC
    \sa wc_RNG_DRBG_GetRBGCStratum
*/
int wc_InitRngRBGC(WC_RNG* child, WC_RNG* parent, word32 flags);

/*!
    \ingroup Random

    \brief The allocating form of wc_InitRngRBGC(): the child is allocated
    from parent's heap and returned through child.  Release with
    wc_rng_free().  For further details, see wc_InitRngRBGC().

    \return 0 Success
    \return BAD_FUNC_ARG child or parent is null.
    \return MEMORY_E Allocation failed.
    \return SEQ_OVERFLOW_E parent's stratum is at the representable maximum.

    \param child Receives the allocated, instantiated WC_RNG.
    \param parent The chain parent to draw seed material from.
    \param flags Bitwise-or of WC_RNG_INIT_FLAG_* attributes for the child.

    \sa wc_InitRngRBGC
    \sa wc_InitRngNonceRBGC_New
*/
int wc_InitRngRBGC_New(WC_RNG** child, WC_RNG* parent, word32 flags);

/*!
    \ingroup Random

    \brief The allocating, nonce-bearing form of wc_InitRngRBGC().  For further
    details, see wc_InitRngRBGC() and wc_InitRngNonceRBGC().

    \return 0 Success
    \return BAD_FUNC_ARG child or parent is null, or nonce (or perso) is
    null with its length nonzero.
    \return MEMORY_E Allocation failed.
    \return SEQ_OVERFLOW_E parent's stratum is at the representable maximum.

    \param child Receives the allocated, instantiated WC_RNG.
    \param parent The chain parent to draw seed material from.
    \param nonce Additional instantiation input.
    \param nonceSz Length of nonce in bytes.
    \param perso Optional personalization string.
    \param persoSz Length of perso in bytes.
    \param flags Bitwise-or of WC_RNG_INIT_FLAG_* attributes for the child.

    \sa wc_InitRngRBGC_New
    \sa wc_InitRngNonceRBGC
*/
int wc_InitRngNonceRBGC_New(WC_RNG** child, WC_RNG* parent, const byte* nonce,
                            word32 nonceSz, const byte *perso, word32 persoSz,
                            word32 flags);

/*!
    \ingroup Random

    \brief Reseed rng from root's generate output -- the SP 800-90C chain
    reseed -- with an optional nonce as additional input.  The reseed is
    credited (the reseed counter resets); rng's stratum is updated to root's
    stratum + 1, unless built with WC_RNG_RBGC_STRATUM_IMMUTABLE (required for
    FIPS).  The caller must hold exclusive access to both instances.

    \details Credited chain reseeds obey a no-downgrade rule: a primary-seeded
    (stratum-0) root is always accepted, and a chained (stratum > 0) root is
    accepted only when its stratum is strictly less than rng's -- with strata
    sticky from init, credited seed material can only flow rootward-to-leafward,
    so reseed cycles are impossible by construction, consistent with SP 800-90C
    7.1.2.2.  Lateral (equal-stratum) and downgrading reseeds are refused with
    BAD_FUNC_ARG.  A successful credited reseed re-tags rng with the source's
    stratum plus one (or zero, for a primary source reseed) unless built with
    WC_RNG_RBGC_STRATUM_IMMUTABLE (required for FIPS).  When built with
    WC_RNG_RBGC_STRATUM_IMMUTABLE, a credited chain reseed into a
    primary-class (stratum-0) target is refused with WRONG_TYPE_OBJECT_E --
    chain-fed state must never wear the primary-class label.  Building
    WC_RNG_NO_RBGC_RESEED restricts credited chain reseeds to primary-seeded
    roots.  Uncredited chain stirs (wc_RNG_DRBG_StirRBGC()) are exempt from all
    of this: they are stirs, claim nothing, and leave rng's stratum untouched.

    This is the per-call form of chain maintenance: the root serves this one
    reseed and no relationship is retained, so it is the maintenance path for
    instances without a retained parent (including all instances in builds
    without instance locking) and the required path for externally
    orchestrated chains.  The global fallback instance is a legitimate root
    for this call, though it is forbidden as a retained parent.

    \return 0 Success
    \return BAD_FUNC_ARG rng or root is null, rng equals root, or the
    no-downgrade rule refuses root as a chain parent (see \details).
    \return WRONG_TYPE_OBJECT_E rng has no DRBG (RDRAND et al.), or rng is
    primary-class (stratum 0) and the build is
    WC_RNG_RBGC_STRATUM_IMMUTABLE (see \details).
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
    \return NEEDS_RECOVERY_E A recovery obligation stands on rng; see
    wc_RNG_DRBG_Stir().

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
    or promotion.  Conversely, a standing recovery obligation on rng
    refuses the stir outright (NEEDS_RECOVERY_E): nothing mutates an
    invalidated or reseed-due DRBG except recovery.

*/
int wc_RNG_DRBG_StirRBGC(WC_RNG* rng, WC_RNG* root,
                                      const byte* nonce, word32 nonceSz);

/*!
    \ingroup Random

    \brief Report rng's RBG-chain stratum: 0 for a root (never chain-seeded), n
    for a member seeded from a stratum-(n-1) parent.  If built with
    WC_RNG_RBGC_STRATUM_IMMUTABLE (required for FIPS), the stratum is sticky for
    the instance's lifetime, even across subsequent source reseeds; otherwise it
    follows the stratum of the most recent credited seed source.  A
    user-supplied reseed (wc_RNG_DRBG_Reseed()), where accepted, marks rng
    with WC_RNG_RBGC_USER_SEED_STRATUM regardless.

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

    \brief Bank up to n more bytes of next-seed material, health-testing
    and publishing the bank when it completes.  The fill is incremental and
    in-boundary; a scheduling daemon may call this without owning the
    instance -- the single-writer fill and the atomic aperture hand-off
    make it safe alongside a concurrent consumer.

    \details For an SP 800-90C chain member (RBGC stratum > 0, in builds
    with instance locking), the material is drawn by the same fallback
    ladder as wc_RNG_DRBG_Reseed_Now(): the retained parent first
    (nonblocking acquisition), then the global fallback instance (under
    FIPS, only when it qualifies as a sibling of the parent), then the
    module's primary seed source -- skipped for an instance initialized
    with WC_RNG_INIT_FLAG_NO_PRIMARY_SEED.  Chain-drawn material is
    banked with the source's stratum plus one, as by
    wc_RNG_DRBG_NextSeedGenerate_RBGC().  A fill whose source crossed an
    entropy-invalidation event mid-draw is retired (the bank is purged)
    rather than published.  For a root (stratum 0), the module's seed
    source serves directly.

    \return 0 Bytes were banked (bank may or may not yet be complete).
    \return ALREADY_E The bank is ready or being consumed.
    \return BUSY_E A competing producer holds the fill claim; retryable on
    a later cycle.
    \return NEEDS_RECOVERY_E The banked fill crossed a source invalidation
    event and was retired, or (under WC_RNG_INIT_FLAG_NO_PRIMARY_SEED) no
    chain source was available this cycle.
    \return ENTROPY_RT_E or ENTROPY_APT_E The SP 800-90B seed health test
    rejected the banked material, which is burned.
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

    \brief The forced-primary form of wc_RNG_DRBG_NextSeedGenerate(): the
    banked material is drawn directly from the module's primary (initial)
    randomness source, bypassing the chain fallback ladder, and the bank
    records stratum 0 (primary provenance), observable via
    wc_RNG_DRBG_GetNextSeedRBGCStratum().  On an SP 800-90C chain member,
    redemption of the primary-provenance bank is a promotion: the live seed
    becomes primary-sourced, and the stratum label follows unless built
    with WC_RNG_RBGC_STRATUM_IMMUTABLE (required for FIPS), whereby the
    birth label is kept while the live seed's provenance is primary.  Like
    the ladder form, the fill is incremental and in-boundary, safe for a
    scheduling daemon alongside a concurrent consumer.

    \return 0 Bytes were banked (bank may or may not yet be complete).
    \return ALREADY_E The bank is ready or being consumed.
    \return BUSY_E A competing producer holds the fill claim, or (in kernel
    builds) the primary seed acquisition was refused in a non-blockable
    context; retryable.
    \return NEEDS_RECOVERY_E The banked fill crossed a source invalidation
    event and was retired (the bank is purged).
    \return WRONG_TYPE_OBJECT_E rng was initialized with
    WC_RNG_INIT_FLAG_NO_PRIMARY_SEED.
    \return ENTROPY_RT_E or ENTROPY_APT_E The SP 800-90B seed health test
    rejected the banked material, which is burned.
    \return BAD_FUNC_ARG rng is null or n is 0.
    \return MISSING_RNG_E rng has no DRBG (RDRAND et al.).

    \param rng The RNG object whose bank to fill.
    \param n Maximum bytes to bank this call (clamped to space remaining).

    \sa wc_RNG_DRBG_NextSeedGenerate
    \sa wc_RNG_DRBG_NextSeedGenerate_RBGC
    \sa wc_RNG_DRBG_GetNextSeedRBGCStratum
    \sa wc_RNG_DRBG_Reseed_Now_Primary
*/
int wc_RNG_DRBG_NextSeedGenerate_Primary(WC_RNG* rng, word32 n);

/*!
    \ingroup Random

    \brief The chain-sourced form of wc_RNG_DRBG_NextSeedGenerate(): the
    banked material is drawn from root's generate function, and the bank is
    tagged with root's stratum plus one for provenance-aware consumption.

    \return 0 Bytes were banked.
    \return ALREADY_E The bank is ready or being consumed.
    \return ENTROPY_RT_E or ENTROPY_APT_E The SP 800-90B seed health test
    rejected the banked material, which is burned.
    \return BAD_FUNC_ARG rng or root is null, or n is 0.
    \return MISSING_RNG_E rng has no DRBG (RDRAND et al.).
    \return WRONG_TYPE_OBJECT_E rng is primary-class (stratum 0) and the
    build is WC_RNG_RBGC_STRATUM_IMMUTABLE (see \details).
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
    wc_RNG_DRBG_GetNextSeedRBGCStratum(); redemption (wc_RNG_DRBG_NextSeedNow())
    imparts the recorded stratum to the rng, unless built with
    WC_RNG_RBGC_STRATUM_IMMUTABLE (required for FIPS).  When built with
    WC_RNG_RBGC_STRATUM_IMMUTABLE, chain banking into a primary-class
    (stratum-0) target is likewise refused, with WRONG_TYPE_OBJECT_E.

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
int wc_RNG_DRBG_NextSeedCurrent(const WC_RNG* rng, WC_ATOMIC_INT_ARG* n);

/*!
    \ingroup Random

    \brief Claim a ready next-seed bank and perform a source-free credited
    reseed with it -- safe in atomic context.  The bank empties (use-once)
    and the reseed counter resets.  The caller must own the instance.

    \return 0 Success
    \return NOT_READY_E No bank is ready.
    \return NEEDS_RECOVERY_E A pending global epoch event was delivered
    into the instance (pre-event banked material purged, latch asserted);
    recover with a credited reseed, then re-bank.  A bank found READY under
    an already-delivered latch is post-event and redeems normally -- that
    redemption is the banked recovery path.
    \return BAD_FUNC_ARG rng is null.
    \return MISSING_RNG_E rng has no DRBG (RDRAND et al.).
    \return ENTROPY_RT_E or ENTROPY_APT_E A seed health test failed on
    the reseed this performs; the instance is condemned.

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
    \return NEEDS_RECOVERY_E Either a pending global epoch event was
    delivered before the claim (pre-event banked material purged, latch
    asserted -- see wc_RNG_DRBG_NextSeedNow()), or a purge crossed the
    consume: no material is adopted, the entropy-invalidated latch is
    (re-)asserted, and a recovery reseed is scheduled.
    \return NOT_READY_E No bank is ready.
    \return BAD_FUNC_ARG rng is null, or nonce is null with nonceSz nonzero.
    \return MISSING_RNG_E rng has no DRBG (RDRAND et al.).
    \return ENTROPY_RT_E or ENTROPY_APT_E A seed health test failed on
    the reseed this performs; the instance is condemned.
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
    WC_RNG_NEXT_STIR_LEN bytes) in the uncredited accumulator
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
    \return NOT_READY_E The accumulator is empty or still accumulating.
    \return NEEDS_RECOVERY_E A recovery obligation stands (reseed due,
    entropy invalidated, or entropy epoch advanced); nothing mutates a
    recovery-due DRBG except recovery.  See wc_RNG_DRBG_Stir().
    \return BUSY_E The accumulator was claimed by a racing consumer -- the
    stir is happening by another hand.
    \return BAD_FUNC_ARG rng is null.
    \return MISSING_RNG_E rng has no DRBG (RDRAND et al.).
    \return DRBG_CONT_FIPS_E The instance failed a continuous test.
    \return RNG_FAILURE_E The DRBG is out of service, or its hash failed
    mid-stir leaving a half-applied update -- the instance is then
    condemned (status DRBG_FAILED).

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
int wc_RNG_lock_read(const WC_RNG* rng, WC_RNG_lock_arg_t* state);

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
    similar duplication events: the reseed schedule is saturated, banked
    and pooled pre-event material is purged and wiped, and then (in builds
    with instance locking) the entropy-invalidated bit is latched in the
    lock word, stamping the instance with the delivered entropy epoch so
    one global event delivers once.  An invalidated instance refuses
    service (NEEDS_RECOVERY_E) until recovery-reseeded.

    \details Latch or condemn: if the latch itself cannot be asserted, the
    instance is condemned (status DRBG_FAILED) -- the latch is the only
    race-free quarantine mark, so its failure has no softer disposition.  A
    nonzero return from a purge step leaves the latch asserted and the
    instance quarantined, not condemned.  In builds without instance
    locking there is no latch; delivery is the purges plus the saturated
    reseed schedule, which the next generate honors.  A condemned bank
    instance is retired and recovered by the entropy daemon; a condemned
    leaf gets no daemon rescue -- its owner sees RNG_FAILURE_E from
    subsequent operations and recovers it with wc_FreeRng() then
    wc_InitRng*().

    \return 0 Success: purges complete, latch asserted (where built).
    \return BAD_FUNC_ARG rng is null.
    \return RNG_FAILURE_E (or other nonzero) A purge or the latch failed;
    the latch disposition is as described in \details.

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

    \brief Set runtime policy flags on an instantiated RNG.  Only the bits
    in WC_RNG_FLAGS_SETTABLE may be set this way (WC_RNG_FLAG_FAIL_FAST,
    WC_RNG_FLAG_ONLY_PRIMARY_SEED, WC_RNG_FLAG_NO_PRIMARY_SEED); the rest
    are structural, fixed by instantiation or by the module, and are
    refused.  A flag change is a read-modify-write of the instance, so it
    requires exclusive ownership: in WC_RNG_HAVE_LOCK builds the instance
    must have been instantiated with WC_RNG_INIT_FLAG_LOCK_REQUIRED and the
    caller must hold its lease; otherwise only SINGLE_THREADED builds
    support it.  WC_RNG_FLAG_FAIL_FAST makes a generate that would otherwise
    reseed in-line report instead -- NOT_READY_E for an exhausted reseed
    budget, NEEDS_RECOVERY_E for entropy invalidation -- leaving the DRBG
    in service; explicit reseed APIs are unaffected.  The same policy can be
    fixed at instantiation with WC_RNG_INIT_FLAG_FAIL_FAST.

    \return 0 Success
    \return BAD_FUNC_ARG rng is null, flags is 0 or includes a bit that is
    not settable, or flags would combine WC_RNG_FLAG_NO_PRIMARY_SEED with
    WC_RNG_FLAG_ONLY_PRIMARY_SEED.
    \return OBJECT_NOT_LOCKED_E rng requires a lease and the caller holds
    none.
    \return WRONG_TYPE_OBJECT_E rng is not lock-required (WC_RNG_HAVE_LOCK).
    \return NOT_COMPILED_IN No exclusivity facility (multithreaded build
    without WC_RNG_HAVE_LOCK), or WC_RNG_FLAG_NO_PRIMARY_SEED without
    WC_RNG_HAVE_RBGC.
    \return MISSING_RNG_E WC_RNG_FLAG_NO_PRIMARY_SEED on an instance with no
    chain parent to defer to.

    \param rng The RNG object.
    \param flags The bits to set.

    \sa wc_RNG_ClearFlags
    \sa wc_InitRngNonce_ex2
*/
int wc_RNG_SetFlags(WC_RNG* rng, word32 flags);

/*!
    \ingroup Random

    \brief Clear runtime policy flags on an instantiated RNG.  Only the bits
    in WC_RNG_FLAGS_CLEARABLE may be cleared (WC_RNG_FLAG_FAIL_FAST,
    WC_RNG_FLAG_ONLY_PRIMARY_SEED); WC_RNG_FLAG_NO_PRIMARY_SEED is set-only,
    since under FIPS it is a provenance commitment.  Same ownership
    precondition as wc_RNG_SetFlags().

    \return 0 Success
    \return BAD_FUNC_ARG rng is null, flags is 0 or includes a bit that is
    not clearable.
    \return OBJECT_NOT_LOCKED_E rng requires a lease and the caller holds
    none.
    \return WRONG_TYPE_OBJECT_E rng is not lock-required (WC_RNG_HAVE_LOCK).
    \return NOT_COMPILED_IN No exclusivity facility.

    \param rng The RNG object.
    \param flags The bits to clear.

    \sa wc_RNG_SetFlags
*/
int wc_RNG_ClearFlags(WC_RNG* rng, word32 flags);

/*!
    \ingroup Random

    \brief Read an instance's runtime flags (WC_RNG_FLAG_*) -- the
    read-only companion of wc_RNG_SetFlags()/wc_RNG_ClearFlags(), so an
    application can establish an instance's posture (seed-source policy,
    fail-fast, chain and lock discipline, bank-reference shell) without
    reaching into the object.  A plain load with no ownership
    precondition, like wc_RNG_Status(): authoritative when the caller holds
    the instance's lease, otherwise a snapshot.  A WC_RNG_FLAG_BANKREF shell
    reports its own flags, not those of the bank instance a draw through it
    would resolve to.

    \return 0 Success
    \return BAD_FUNC_ARG rng or flags is null.

    \param rng The RNG object to interrogate.
    \param flags Receives the flags.

    \sa wc_RNG_SetFlags
    \sa wc_RNG_ClearFlags
    \sa wc_RNG_Status
*/
int wc_RNG_GetFlags(const WC_RNG* rng, word32 *flags);

/*!
    \ingroup Random

    \brief Attach a random pool to rng: a buffer of size bytes of
    pre-generated output, filled by wc_RNG_Pool_Collect() and drained
    atomic-context-safely by wc_RNG_Pool_Extract().  The pool is released
    only by wc_FreeRng(), and an instance reinstantiated through
    wc_FreeRng() comes back poolless, so a collector re-equips it by
    calling this again -- the call is idempotent (ALREADY_E on a live
    ring) and needs no lease: the ring's lifecycle is arbitrated by an
    atomic aperture word, so it is safe against a concurrent
    wc_FreeRng() or wc_RNG_Pool_Collect2() on the same instance.

    \return 0 Success
    \return BAD_FUNC_ARG rng is null, or size is less than 2 or greater
    than 32767.
    \return MEMORY_E Allocation failed.
    \return ALREADY_E A pool is already attached (or being attached, or a
    collector is active on it).
    \return BAD_STATE_E The pool was released by wc_FreeRng() and the
    instance has not been reinstantiated since.

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

    \brief Generate up to n bytes into rng's pool from rng itself.
    Equivalent to wc_RNG_Pool_Collect2(rng, rng, n); see there for the
    contract.

    \return 0 Success, including the no-op cases: n is 0, or the pool is
    already full.
    \return BAD_FUNC_ARG rng is null.
    \return BAD_STATE_E No pool is attached.
    \return OBJECT_NOT_LOCKED_E rng requires a lease and the caller holds
    none.
    \return BUSY_E Another collector holds the ring, or a purge landed
    during the generate.
    \return NOT_READY_E A purge is pending the reader's acknowledgement
    (its next wc_RNG_Pool_Extract()), or the instance's own reseed budget
    is exhausted (this call never reseeds its source; see
    wc_RNG_Pool_Collect2()).
    \return NEEDS_RECOVERY_E The instance requires entropy recovery.

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
    be topped up by a daemon-owned generator.  No lease on rng_dest is
    needed: the collector claims the ring through its atomic aperture word
    for the duration of the generate (collectors are mutually exclusive;
    a second one gets BUSY_E at once), and the claim is what makes a
    concurrent wc_FreeRng() on rng_dest refuse with BUSY_E rather than
    free a buffer being written.  The generate runs with
    WC_RNG_FLAG_FAIL_FAST on rng_src (set transiently if rng_src does not
    carry it), so the claim is held for one bounded generate and never
    across an in-line reseed: this call never reseeds its source, and a
    source whose budget is exhausted or which requires recovery is reported,
    not serviced -- source upkeep belongs to the source's owner.  On a
    lock-required rng_src the caller must hold its lease.  Under
    WC_RNG_HAVE_RBGC, rng_src may not sit deeper in the RBG chain than
    rng_dest (SP 800-90C sect. 7.3.1 item 16).

    \return 0 Success, including the no-op cases: n is 0, or the pool is
    already full.
    \return BAD_FUNC_ARG rng_dest or rng_src is null, or rng_src's RBGC
    stratum is deeper than rng_dest's.
    \return BAD_STATE_E rng_dest has no pool attached.
    \return OBJECT_NOT_LOCKED_E rng_src requires a lease and the caller
    holds none.
    \return BUSY_E Another collector (or an allocator) holds the ring, or a
    purge landed during the generate.
    \return NOT_READY_E A purge is pending the reader's acknowledgement
    (its next wc_RNG_Pool_Extract()), or rng_src's reseed budget is
    exhausted.
    \return NEEDS_RECOVERY_E rng_src requires entropy recovery.
    \return Any other error from wc_RNG_GenerateBlock() on rng_src.

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
    delivered; on any error return *n is left unmodified.

    \return 0 Success
    \return NOT_READY_E The pool is empty or being filled.
    \return NEEDS_RECOVERY_E A pending global epoch event was delivered
    into the instance before serving: pre-event pooled output is purged,
    and the instance requires a credited reseed before further service.
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

    \brief Report the pool's current fill in bytes (0 when rng has no pool,
    or a purge is pending the reader's acknowledgement).  The snapshot is
    racy by design, and needs no lease.

    \return 0 Success
    \return BAD_FUNC_ARG rng or n is null.

    \param rng The RNG object to interrogate.
    \param n Receives the fill.

    \sa wc_RNG_Pool_Extract
*/
int wc_RNG_Pool_Current(const WC_RNG* rng, word32* n);

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

/*!
    \ingroup Random

    \brief Advances the process-global entropy epoch, marking every RNG
    instance's entropy as predating the current environment.

    \details The broadcast half of entropy invalidation, for events that
    invalidate all accumulated entropy at once (a VM fork or resume, a
    snapshot restore).  Each instance captures the global epoch when it
    acquires seed material; after the epoch advances, every instance reports
    NEEDS_RECOVERY_E from wc_RNG_entropy_needs_recovery() until its next
    credited reseed, which wc_RNG_GenerateBlock() performs inline on its next
    call.  The pending event is delivered into each instance -- purging its
    banked and pooled pre-event material via wc_RNG_invalidate_entropy() --
    at the instance's next detection point: a generate, a recovery query, a
    banked-seed redemption, or a pool extraction.  The call is lock-free and
    safe from any context that may call the atomic-increment primitive.

    \return The new (post-increment) global entropy epoch.

    \sa wc_RNG_entropy_needs_recovery
    \sa wc_RNG_invalidate_entropy
    \sa wc_RNG_GenerateBlock
*/
WC_ATOMIC_UINT_ARG wc_RNG_global_invalidate_entropy(void);

/*!
    \ingroup Random

    \brief Read the process-global entropy epoch: the count of
    wc_RNG_global_invalidate_entropy() events so far.  An instance whose
    stamp differs from this value has an undelivered event pending (see
    wc_RNG_entropy_needs_recovery(), which delivers it).  A relaxed
    snapshot, for diagnostics and for callers that want to notice an event
    without touching any instance; nothing is propagated.

    \return The current global epoch.

    \sa wc_RNG_global_invalidate_entropy
    \sa wc_RNG_entropy_needs_recovery
*/
WC_ATOMIC_UINT_ARG wc_RNG_get_global_entropy_epoch(void);

/*!
    \ingroup Random

    \brief Initializes an RNG instance seeded from a parent RNG, as an
    SP 800-90C RBG chain member, with an optional nonce and personalization
    string.

    \details The child is labeled with the parent's RBGC stratum plus one,
    recording its chain provenance.  In builds with instance locking, when the
    parent is a lock-disciplined instance (initialized with
    WC_RNG_INIT_FLAG_LOCK_REQUIRED) and the caller holds the parent's lock
    across the call, the child retains the parent for the instance's lifetime
    and reseeds from it automatically; the parent cannot complete teardown
    while retaining children (see wc_FreeRng()).  Otherwise the seeding is a
    one-time pull: the child is born chain-fed and correctly labeled, and
    ongoing chain maintenance -- scheduling credited reseeds against an
    appropriate root with wc_RNG_DRBG_ReseedRBGC() -- is the caller's
    responsibility.  Instances created by the wc_rng_new*() family are never
    retained as parents: their void destructor cannot report a still-pinned
    shell, so retention from them degrades to the one-time pull.  Under FIPS
    the retained relationship is required, not optional: the parent must be
    lock-disciplined and retainable, and a spawn from any other instance is
    refused.  The global fallback instance is forbidden as a
    parent in all configurations; its role as an explicit reseed root is
    unaffected.

    \return 0 on success
    \return BAD_FUNC_ARG a pointer argument is invalid, or parent is the
    global fallback instance
    \return WRONG_TYPE_OBJECT_E under FIPS, parent is not a lock-disciplined
    instance
    \return SEQ_OVERFLOW_E the parent's stratum cannot be incremented

    \param child the instance to initialize
    \param parent the seed-source instance
    \param nonce optional nonce buffer, NULL if unused
    \param nonceSz length of nonce in bytes
    \param perso optional personalization string, NULL if unused
    \param persoSz length of perso in bytes
    \param flags WC_RNG_INIT_FLAG_* values for the child; not inherited from
    the parent

    \sa wc_InitRngRBGC
    \sa wc_RNG_DRBG_ReseedRBGC
    \sa wc_FreeRng
*/
int wc_InitRngNonceRBGC(WC_RNG* child, WC_RNG* parent,
                        const byte* nonce, word32 nonceSz,
                        const byte *perso, word32 persoSz,
                        word32 flags);

/*!
    \ingroup Random

    \brief Reports whether an RNG instance has a standing obligation to
    acquire fresh entropy before further use.

    \details Checks the instance's health, its entropy epoch against the
    process-global epoch (see wc_RNG_global_invalidate_entropy()), its
    entropy-invalidation latch, and its reseed schedule.  Detection is also
    delivery: in builds with instance locking, a stale epoch is propagated
    into the instance on the spot, via wc_RNG_invalidate_entropy() --
    pre-event banked and pooled material purged, latch asserted, epoch
    stamped -- so a nonzero verdict means the instance's apertures are
    already post-purge and the latch carries the recovery obligation from
    then on.  The result is an unlocked snapshot: callers that do not
    otherwise pin the instance (by lease, lock, or gate) must treat the
    verdict as advisory, and the operating APIs re-establish it
    authoritatively under the instance lock.  An instance with no DRBG
    state, including one not yet initialized, vacuously needs no recovery.

    \return 0 no recovery is needed
    \return NEEDS_RECOVERY_E a credited reseed is required before the next
    generate (wc_RNG_GenerateBlock() performs this recovery inline)
    \return BAD_FUNC_ARG rng is NULL
    \return RNG_FAILURE_E the instance is in a failed state
    \return DRBG_CONT_FIPS_E the instance failed a continuous test

    \param rng the instance to query

    \sa wc_RNG_global_invalidate_entropy
    \sa wc_RNG_GenerateBlock
*/
int wc_RNG_entropy_needs_recovery(WC_RNG* rng);
