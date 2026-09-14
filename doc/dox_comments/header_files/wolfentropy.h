/*!
    \ingroup wolfEntropy
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
    \sa wc_Entropy_GetVersion
*/
int wc_Entropy_GetRawEntropy(unsigned char* raw, int cnt);

/*!
    \ingroup wolfEntropy
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
    \sa wc_Entropy_GetVersion

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
    \ingroup wolfEntropy
    \brief Tests entropy source on demand.

    \return 0 On success
    \return RNG_FAILURE_E Test failed

    _Example_
    \code
    int ret = wc_Entropy_OnDemandTest();
    \endcode

    \sa wc_Entropy_Get
    \sa wc_Entropy_GetVersion
*/
int wc_Entropy_OnDemandTest(void);

/*!
    \ingroup wolfEntropy
    \brief Tells you which version of wolfEntropy you are running.

    Handy for logs and reports.  The string belongs to wolfSSL: read
    it, do not change or free it.

    \return "wolfEntropy vX.Y.Zt" Version string.  Never NULL.

    _Example_
    \code
    printf("entropy source: %s\n", wc_Entropy_GetVersion());
    \endcode

    \sa wc_Entropy_Get
    \sa wc_Entropy_GetRawEntropy
    \sa wc_Entropy_OnDemandTest
*/
const char* wc_Entropy_GetVersion(void);
