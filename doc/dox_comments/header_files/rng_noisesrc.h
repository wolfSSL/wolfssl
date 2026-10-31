/*!
    \ingroup Random
    \brief Validates a generic SP800-90B noise source and runs its startup
    test.

    Built with WOLFSSL_NOISE_SRC (--enable-noisesrc).  For parts with a raw
    physical noise source but no TRNG: the caller supplies a callback
    returning one unconditioned octet, and this layer adds the SP800-90B 4.3
    startup test, the 4.4.1 Repetition Count and 4.4.2 Adaptive Proportion
    (sliding window) continuous tests, entropy-budget oversampling and a
    SHA3-256 conditioner.

    Fill the configuration members of the caller-owned wc_NoiseSrc, then call
    this.  The first call validates the configuration and derives rawPerSrc;
    every call runs the startup test for each source whose health-test state
    is empty, which after a test failure is the source that failed.  The other
    wc_NoiseSrc_* calls invoke it first.  A configuration member left zero
    selects a default:

    | Member | Default |
    |---|---|
    | hmin | WC_NOISE_HMIN_DEF (10, i.e. 0.1 bits per raw bit) |
    | margin | WC_NOISE_MARGIN_DEF (1) |
    | rctCutoff | WC_NOISE_RCT_CUTOFF_DEF (31) |
    | aptWindow | WC_NOISE_APT_WINDOW_DEF (512, also the maximum) |
    | aptCutoff | WC_NOISE_APT_CUTOFF_DEF (325) |
    | startupOctets | WC_NOISE_STARTUP_DEF (1536) |

    With the defaults each source gathers 320 raw octets per 32-octet output
    chunk.  Cutoffs must match the assumed hmin, or they either never trip or
    trip constantly.

    \return 0 On success.
    \return BAD_FUNC_ARG src is NULL, a required member is NULL, numSrc is
    not 1..WC_NOISE_SRC_MAX, hmin is over 100, a cutoff is below 2, aptWindow
    is over 512 or below aptCutoff, or startupOctets is below aptWindow.
    \return BUFFER_E workSz is smaller than numSrc * rawPerSrc.
    \return ENTROPY_RT_E or ENTROPY_APT_E A startup test failed; that source's
    state is reset and the next call retries it.
    \return Other negative values as returned by the sample callback.

    \param src Caller-owned noise source instance.

    _Example_
    \code
    static byte work[2 * WC_NOISE_RAW_PER_SRC(50, 2)];
    static wc_NoiseSrc src;

    src.sampleCb      = my_sample;
    src.tag           = "my-board-osc-entropy-v1";
    src.work          = work;
    src.workSz        = sizeof(work);
    src.startupOctets = 1024;
    src.numSrc        = 2;
    src.hmin          = 50;
    src.margin        = 2;
    src.rctCutoff     = 9;
    src.aptWindow     = 512;
    src.aptCutoff     = 71;
    ret = wc_NoiseSrc_Init(&src);
    \endcode

    \sa wc_NoiseSrc_GenerateSeed
    \sa wc_NoiseSrc_Free
*/
int wc_NoiseSrc_Init(wc_NoiseSrc* src);

/*!
    \ingroup Random
    \brief Wipes the work buffer and health-test state of a noise source.

    Configuration members are kept, so wc_NoiseSrc_Init() can be called again
    on the same instance.

    \param src Noise source instance.  NULL is ignored.

    _Example_
    \code
    wc_NoiseSrc_Free(&src);
    \endcode

    \sa wc_NoiseSrc_Init
*/
void wc_NoiseSrc_Free(wc_NoiseSrc* src);

/*!
    \ingroup Random
    \brief Produces conditioned seed material from a noise source.

    Per 32-octet chunk, gathers rawPerSrc octets from every source,
    health-tests them, and hashes tag, a big-endian chunk counter and each
    source's octets in index order with SHA3-256.  Only source 0 is credited
    with entropy; further sources are hashed in as defence in depth.

    On any failure the whole output buffer is wiped.  A health-test failure on
    any source resets that source's test state, so the next call reruns its
    startup test.

    \return 0 On success.
    \return BAD_FUNC_ARG src or output is NULL.
    \return ENTROPY_RT_E or ENTROPY_APT_E A health test failed.
    \return MEMORY_E Allocation failed (WOLFSSL_SMALL_STACK).
    \return Other negative values from wc_NoiseSrc_Init(), the sample callback
    or SHA3-256.

    \param src Noise source instance.
    \param output Buffer to fill.
    \param sz Octets to produce.

    _Example_
    \code
    byte seed[48];
    ret = wc_NoiseSrc_GenerateSeed(&src, seed, sizeof(seed));
    \endcode

    \sa wc_NoiseSrc_Init
    \sa wc_NoiseSrc_SelfTest
*/
int wc_NoiseSrc_GenerateSeed(wc_NoiseSrc* src, byte* output, word32 sz);

/*!
    \ingroup Random
    \brief Reads raw, unconditioned octets from one source of a noise source.

    For characterization and self-test only: no health tests run on these
    octets, so they are not fit for keying material, and they do not advance
    the continuous-test state.

    \return 0 On success.
    \return BAD_FUNC_ARG src or output is NULL, or srcIdx is out of range.
    \return Other negative values from wc_NoiseSrc_Init() or the sample
    callback; output is wiped on a callback error.

    \param src Noise source instance.
    \param output Buffer to fill.
    \param len Octets to read.
    \param srcIdx Source index, 0 .. numSrc - 1.

    _Example_
    \code
    byte raw[4096];
    ret = wc_NoiseSrc_GetRaw(&src, raw, sizeof(raw), 0);
    \endcode

    \sa wc_NoiseSrc_GenerateSeed
*/
int wc_NoiseSrc_GetRaw(wc_NoiseSrc* src, byte* output, word32 len,
    int srcIdx);

/*!
    \ingroup Random
    \brief Liveness check on the raw noise of every source.

    Each source must produce two differing gathers, and a gather must not be
    one repeated octet.  A source that fails has its health-test state reset,
    so the next call reruns its startup test.

    \return 0 On success.
    \return ENTROPY_RT_E A source failed the check.
    \return BUFFER_E The work buffer is too small for two gathers.
    \return Other negative values from wc_NoiseSrc_Init() or the sample
    callback.

    \param src Noise source instance.

    _Example_
    \code
    ret = wc_NoiseSrc_SelfTest(&src);
    \endcode

    \sa wc_NoiseSrc_GenerateSeed
*/
int wc_NoiseSrc_SelfTest(wc_NoiseSrc* src);
