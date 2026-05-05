/*!
    \ingroup PUF

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
    point to a NOLOAD linker section to preserve the power-on state.

    \return 0 on success
    \return BAD_FUNC_ARG if ctx or sramAddr is NULL
    \return PUF_READ_E if sramSz < WC_PUF_RAW_BYTES

    \param ctx pointer to wc_PufCtx structure
    \param sramAddr pointer to raw SRAM memory region
    \param sramSz size of SRAM buffer (must be >= WC_PUF_RAW_BYTES)

    _Example_
    \code
    __attribute__((section(".puf_sram")))
    static volatile uint8_t puf_sram[256];
    wc_PufReadSram(&ctx, (const byte*)puf_sram, sizeof(puf_sram));
    \endcode

    \sa wc_PufInit
    \sa wc_PufEnroll
    \sa wc_PufReconstruct
*/
int wc_PufReadSram(wc_PufCtx* ctx, const byte* sramAddr, word32 sramSz);

/*!
    \ingroup PUF

    \brief Perform PUF enrollment. Encodes raw SRAM using BCH(127,64,t=10)
    and generates public helper data. After enrollment the context is ready
    for key derivation and identity retrieval.

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
    data. BCH error correction (t=10) corrects up to 10 bit flips per
    127-bit codeword.

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
    \param sz size of data (>= WC_PUF_RAW_BYTES, 256 bytes)

    _Example_
    \code
    byte testSram[WC_PUF_RAW_BYTES];
    wc_PufSetTestData(&ctx, testSram, sizeof(testSram));
    \endcode

    \sa wc_PufInit
    \sa wc_PufReadSram
*/
int wc_PufSetTestData(wc_PufCtx* ctx, const byte* data, word32 sz);
