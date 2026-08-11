/*!
    \ingroup PUF

    The SRAM PUF uses a configurable BCH(127,k,t) fuzzy extractor over GF(2^7)
    with HKDF key derivation. WC_PUF_BCH_T selects the error-correction
    strength (t=7, 10 default, 13, or 15) and WC_PUF_NUM_CODEWORDS (default 16)
    trades SRAM footprint and helper-data size (WC_PUF_HELPER_BYTES) against
    derived-key entropy. Only the (n - k) parity bits per codeword carry
    information; the leading k bits of each helper codeword are identically
    zero, so size OTP/flash accordingly. WC_PUF_HELPER_COMPACT stores only
    those parity bits, shrinking helper data to 39-72% of the default. It
    changes the stored format and so is opt-in; the default layout stays
    compatible with helper data enrolled by wolfSSL 5.9.2.

    Enrollment and reconstruction must use identical WC_PUF_BCH_T and
    WC_PUF_NUM_CODEWORDS (and the same hash); persist WC_PUF_PROFILE_ID with
    the helper data at enrollment and pass it to wc_PufReconstructEx, or
    compare it against wc_PufGetProfileId(), to catch a build mismatch.

    Every readout handed to wc_PufReadSram() is health tested first (see
    wc_PufCheckSram). A degenerate readout - all zero, all ones, or a repeating
    block - would otherwise pass cleanly through encoding, masking, decoding
    and HKDF and derive a key that is the same on every device.
    WC_PUF_HW_MIN_PCT and WC_PUF_HW_MAX_PCT (default 35 and 65) set the
    Hamming-weight band the readout must fall inside.

    The test rejects degenerate readouts, not every already-written region:
    ordinary firmware content - .data copied from flash, a string table, a
    previous boot stage - is identical on every device yet neither constant nor
    strongly biased, so it can pass. Sampling the region from reset, before
    .bss/.data initialization and before it is used as stack or heap, remains a
    requirement of correct NOLOAD placement rather than something this test can
    enforce.

    For a complete bare-metal example (tested on NUCLEO-H563ZI), see
    https://github.com/wolfSSL/wolfssl-examples/tree/master/puf
*/

/*!
    \ingroup PUF

    \brief Initialize a wc_PufCtx structure, zeroing all fields.
    Must be called before any other PUF operations.

    \return 0 on success
    \return BAD_FUNC_ARG if ctx is NULL

    \param ctx pointer to wc_PufCtx structure to initialize

    _Example_
    \code
    wc_PufCtx ctx;
    ret = wc_PufInit(&ctx);
    \endcode

    \sa wc_PufReadSram
    \sa wc_PufEnroll
    \sa wc_PufZeroize
*/
int wc_PufInit(wc_PufCtx* ctx);

/*!
    \ingroup PUF

    \brief Read raw SRAM data into the PUF context. The sramAddr should
    point to a NOLOAD linker section to preserve the power-on state. The
    required size, WC_PUF_RAW_BYTES, scales with WC_PUF_NUM_CODEWORDS
    (256 bytes at the default 16 codewords).

    The readout is health tested with wc_PufCheckSram() before it is accepted.
    A degenerate readout - typically a region already cleared by .bss init, the
    common bring-up mistake of sampling after C runtime startup - is rejected
    with PUF_READ_E, and the context is left unusable by wc_PufEnroll() and
    wc_PufReconstruct(). The test catches degenerate shapes, not every
    already-written region, so it does not remove the requirement to sample
    from reset.

    \return 0 on success
    \return BAD_FUNC_ARG if ctx or sramAddr is NULL
    \return PUF_READ_E if sramSz < WC_PUF_RAW_BYTES, or if the readout fails
    the health test

    \param ctx pointer to wc_PufCtx structure
    \param sramAddr pointer to raw SRAM memory region
    \param sramSz size of SRAM buffer (must be >= WC_PUF_RAW_BYTES)

    _Example_
    \code
    __attribute__((section(".puf_sram")))
    static volatile uint8_t puf_sram[WC_PUF_RAW_BYTES];
    wc_PufReadSram(&ctx, (const byte*)puf_sram, sizeof(puf_sram));
    \endcode

    \sa wc_PufInit
    \sa wc_PufCheckSram
    \sa wc_PufEnroll
    \sa wc_PufReconstruct
*/
int wc_PufReadSram(wc_PufCtx* ctx, const byte* sramAddr, word32 sramSz);

/*!
    \ingroup PUF

    \brief Health test a candidate raw SRAM readout without loading it into a
    context. Rejects a readout that cannot be SRAM power-on noise: any 128-bit
    block that is all zero or all ones, any block that repeats the block before
    it, or a total Hamming weight outside the WC_PUF_HW_MIN_PCT to
    WC_PUF_HW_MAX_PCT band (default 35% to 65% of WC_PUF_RAW_BITS).

    wc_PufReadSram() applies this test to every readout, so calling it directly
    is only needed to qualify a candidate SRAM region during board bring-up, or
    to report why a read was refused. onesCount is optional and is written
    whenever the size check passes - including when the readout is then
    rejected, so the measured bias of a rejected region is still available. It
    is left untouched when sramAddr is NULL or sramSz is short.

    \return 0 if the readout is plausible PUF material
    \return BAD_FUNC_ARG if sramAddr is NULL
    \return PUF_READ_E if sramSz < WC_PUF_RAW_BYTES, or if the readout fails
    any of the checks

    \param sramAddr pointer to raw SRAM memory region
    \param sramSz size of SRAM buffer (must be >= WC_PUF_RAW_BYTES)
    \param onesCount optional; receives the number of one bits in the first
    WC_PUF_RAW_BYTES of the readout, out of WC_PUF_RAW_BITS. Written whenever
    sramAddr is non-NULL and sramSz is large enough, whatever the verdict. It
    is a property of the raw PUF material, so treat it as a bring-up
    measurement and do not report it from production firmware

    _Example_
    \code
    word32 ones = 0;
    ret = wc_PufCheckSram((const byte*)puf_sram, sizeof(puf_sram), &ones);
    printf("PUF SRAM bias %u/%u ones, ret %d\n",
           (unsigned)ones, (unsigned)WC_PUF_RAW_BITS, ret);
    \endcode

    \sa wc_PufReadSram
    \sa wc_PufEnroll
*/
int wc_PufCheckSram(const byte* sramAddr, word32 sramSz, word32* onesCount);

/*!
    \ingroup PUF

    \brief Perform PUF enrollment. Encodes raw SRAM using the selected
    BCH(127,k,t) profile (WC_PUF_BCH_T) and generates public helper data
    (WC_PUF_HELPER_BYTES). After enrollment the context is ready for key
    derivation and identity retrieval.

    \return 0 on success
    \return BAD_FUNC_ARG if ctx is NULL
    \return PUF_ENROLL_E if enrollment fails

    \param ctx pointer to wc_PufCtx (must have SRAM data loaded)

    _Example_
    \code
    wc_PufEnroll(&ctx);
    XMEMCPY(helperData, ctx.helperData, WC_PUF_HELPER_BYTES);
    \endcode

    \sa wc_PufReadSram
    \sa wc_PufReconstruct
    \sa wc_PufDeriveKey
*/
int wc_PufEnroll(wc_PufCtx* ctx);

/*!
    \ingroup PUF

    \brief Reconstruct stable PUF bits from noisy SRAM using stored helper
    data. BCH error correction corrects up to WC_PUF_BCH_T bit flips per
    127-bit codeword. The helper data and build configuration must match the
    enrollment that produced them.

    \return 0 on success
    \return BAD_FUNC_ARG if ctx or helperData is NULL
    \return PUF_RECONSTRUCT_E on failure (too many bit errors or helperSz
    too small)

    \param ctx pointer to wc_PufCtx (must have SRAM data loaded)
    \param helperData pointer to helper data from previous enrollment
    \param helperSz size of helper data (>= WC_PUF_HELPER_BYTES)

    _Example_
    \code
    wc_PufReconstruct(&ctx, helperData, sizeof(helperData));
    \endcode

    \sa wc_PufEnroll
    \sa wc_PufDeriveKey
    \sa wc_PufGetIdentity
*/
int wc_PufReconstruct(wc_PufCtx* ctx, const byte* helperData, word32 helperSz);

/*!
    \ingroup PUF

    \brief Derive a cryptographic key from PUF stable bits using HKDF.
    Uses SHA-256 by default, or SHA3-256 when WC_PUF_SHA3 is defined.
    The info parameter provides domain separation for multiple keys.
    Requires HAVE_HKDF.

    \return 0 on success
    \return BAD_FUNC_ARG if ctx or key is NULL, or keySz is 0
    \return PUF_DERIVE_KEY_E if PUF not ready or HKDF fails

    \param ctx pointer to wc_PufCtx (must be enrolled or reconstructed)
    \param info optional context info for domain separation (may be NULL;
    when NULL, infoSz is treated as 0)
    \param infoSz size of info in bytes
    \param key output buffer for derived key
    \param keySz desired key size in bytes

    _Example_
    \code
    byte key[32];
    const byte info[] = "my-app-key";
    wc_PufDeriveKey(&ctx, info, sizeof(info), key, sizeof(key));
    \endcode

    \sa wc_PufEnroll
    \sa wc_PufReconstruct
    \sa wc_PufGetIdentity
*/
int wc_PufDeriveKey(wc_PufCtx* ctx, const byte* info, word32 infoSz,
                    byte* key, word32 keySz);

/*!
    \ingroup PUF

    \brief Retrieve the device identity hash (SHA-256 or SHA3-256 of stable
    bits). Deterministic for a given device.

    \return 0 on success
    \return BAD_FUNC_ARG if ctx or id is NULL
    \return PUF_IDENTITY_E if PUF not ready or idSz < WC_PUF_ID_SZ

    \param ctx pointer to wc_PufCtx (must be enrolled or reconstructed)
    \param id output buffer for identity hash
    \param idSz size of id buffer (>= WC_PUF_ID_SZ, 32 bytes)

    _Example_
    \code
    byte identity[WC_PUF_ID_SZ];
    wc_PufGetIdentity(&ctx, identity, sizeof(identity));
    \endcode

    \sa wc_PufEnroll
    \sa wc_PufReconstruct
    \sa wc_PufDeriveKey
*/
int wc_PufGetIdentity(wc_PufCtx* ctx, byte* id, word32 idSz);

/*!
    \ingroup PUF

    \brief Report the compile-time PUF profile parameters: field size m,
    codeword length n, message length k, error-correction capability t, and
    the number of codewords. Each output pointer is optional (may be NULL), but
    an all-NULL call is treated as a usage error. Enrollment and reconstruction
    firmware must agree on all of these (and the hash); persist
    WC_PUF_PROFILE_ID (which also encodes the hash selection) with the helper
    data and compare before reconstruction to detect a build mismatch.

    \return 0 on success
    \return BAD_FUNC_ARG if every output pointer is NULL

    \param m optional output for the GF field exponent (7 for GF(2^7))
    \param n optional output for the codeword length (127)
    \param k optional output for the message length (per WC_PUF_BCH_T)
    \param t optional output for the error-correction capability (WC_PUF_BCH_T)
    \param numCodewords optional output for WC_PUF_NUM_CODEWORDS

    _Example_
    \code
    int t, numCodewords;
    wc_PufGetParams(NULL, NULL, NULL, &t, &numCodewords);
    \endcode

    \sa wc_PufEnroll
    \sa wc_PufReconstruct
*/
int wc_PufGetParams(int* m, int* n, int* k, int* t, int* numCodewords);

/*!
    \ingroup PUF

    \brief Return the profile fingerprint the LIBRARY was compiled with. The
    WC_PUF_PROFILE_ID macro necessarily reflects the including application's
    own build, so comparing the two detects a library/application mismatch -
    including a differing hash selection - that no length check can see.

    \return the library's WC_PUF_PROFILE_ID

    _Example_
    \code
    if (wc_PufGetProfileId() != WC_PUF_PROFILE_ID) {
        /* library and application were built with different PUF settings */
    }
    \endcode

    \sa wc_PufGetParams
    \sa wc_PufReconstructEx
*/
word32 wc_PufGetProfileId(void);

/*!
    \ingroup PUF

    \brief Copy out the enrollment helper data. Use this rather than reading
    wc_PufCtx.helperData directly: the size varies with the selected profile
    and with WC_PUF_HELPER_COMPACT.

    \return 0 on success
    \return BAD_FUNC_ARG if ctx or helper is NULL
    \return PUF_ENROLL_E if the context is not enrolled, or helperSz is
    less than WC_PUF_HELPER_BYTES

    \param ctx pointer to an enrolled wc_PufCtx
    \param helper output buffer for the helper data
    \param helperSz size of helper in bytes (>= WC_PUF_HELPER_BYTES)

    _Example_
    \code
    byte helper[WC_PUF_HELPER_BYTES];
    wc_PufGetHelperData(&ctx, helper, sizeof(helper));
    \endcode

    \sa wc_PufEnroll
    \sa wc_PufReconstructEx
*/
int wc_PufGetHelperData(wc_PufCtx* ctx, byte* helper, word32 helperSz);

/*!
    \ingroup PUF

    \brief Reconstruct as wc_PufReconstruct, but first check the caller's
    stored profile id against the library's. Helper-data size does not depend
    on t in the default layout, so the length check alone cannot detect helper
    data enrolled by a differently configured build - which would otherwise
    decode to a silently wrong key. Persist WC_PUF_PROFILE_ID alongside the
    helper data at enrollment and pass it back here.

    \return 0 on success
    \return BAD_FUNC_ARG if ctx or helperData is NULL, or profileId does not
    match the library's profile
    \return PUF_RECONSTRUCT_E on failure (too many bit errors or helperSz
    too small)

    \param ctx pointer to wc_PufCtx (must have SRAM data loaded)
    \param helperData pointer to helper data from a previous enrollment
    \param helperSz size of helper data (>= WC_PUF_HELPER_BYTES)
    \param profileId the WC_PUF_PROFILE_ID recorded at enrollment

    _Example_
    \code
    wc_PufReconstructEx(&ctx, helper, sizeof(helper), savedProfileId);
    \endcode

    \sa wc_PufReconstruct
    \sa wc_PufGetProfileId
*/
int wc_PufReconstructEx(wc_PufCtx* ctx, const byte* helperData,
                        word32 helperSz, word32 profileId);

/*!
    \ingroup PUF

    \brief Securely zeroize all sensitive data in the PUF context using
    ForceZero. Call when PUF is no longer needed.

    \return 0 on success
    \return BAD_FUNC_ARG if ctx is NULL

    \param ctx pointer to wc_PufCtx to zeroize

    _Example_
    \code
    wc_PufZeroize(&ctx);
    \endcode

    \sa wc_PufInit
*/
int wc_PufZeroize(wc_PufCtx* ctx);

/*!
    \ingroup PUF

    \brief Inject synthetic SRAM test data for testing without hardware.
    Only available when WOLFSSL_PUF_TEST is defined.

    \return 0 on success
    \return BAD_FUNC_ARG if ctx or data is NULL
    \return PUF_READ_E if sz < WC_PUF_RAW_BYTES

    \param ctx pointer to wc_PufCtx
    \param data pointer to synthetic SRAM data
    \param sz size of data (>= WC_PUF_RAW_BYTES)

    _Example_
    \code
    byte testSram[WC_PUF_RAW_BYTES];
    wc_PufSetTestData(&ctx, testSram, sizeof(testSram));
    \endcode

    \sa wc_PufInit
    \sa wc_PufReadSram
*/
int wc_PufSetTestData(wc_PufCtx* ctx, const byte* data, word32 sz);
