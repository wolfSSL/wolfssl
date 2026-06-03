/*!
    \ingroup HWPUF

    For a complete bare-metal example (tested on NUCLEO-H563ZI), see
    https://github.com/wolfSSL/wolfssl-examples/tree/master/puf
*/

/*!
    \ingroup HWPUF

    \brief Initialize a wc_HWPUF structure, zeroing all fields.
    Must be called before any other HWPUF operations.

    \return 0 on success
    \return BAD_FUNC_ARG if hwpuf is NULL

    \param hwpuf pointer to wc_HWPUF structure to initialize

    _Example_
    \code
    wc_HWPUF s_hwpuf;
    ret = wc_HWPUF_Init(&s_hwpuf);
    \endcode

    \sa wc_HWPUF_Init
    \sa wc_HWPUF_Deinit
    \sa wc_HWPUF_Unregister
*/
int wc_HWPUF_Register(wc_HWPUF* hwpuf, void* heap, int devId);

/*!
    \ingroup HWPUF

    \brief Initialize a wc_HWPUF structure, zeroing all fields.
    Must be called before any other HWPUF operations.

    \return 0 on success
    \return BAD_FUNC_ARG if hwpuf is NULL

    \param hwpuf pointer to wc_HWPUF structure to initialize

    _Example_
    \code
    wc_HWPUF s_hwpuf;
    ret = wc_HWPUF_Init(&s_hwpuf);
    \endcode

    \sa wc_HWPUF_Register
    \sa wc_HWPUF_Init
    \sa wc_HWPUF_Deinit
    \sa wc_HWPUF_Zeroize
*/
int wc_HWPUF_Unregister(wc_HWPUF* hwpuf);

/*!
    \ingroup HWPUF

    \brief Initialize a wc_HWPUF structure, zeroing all fields.
    Must be called before any other HWPUF operations.

    \return 0 on success
    \return BAD_FUNC_ARG if hwpuf is NULL

    \param hwpuf pointer to wc_HWPUF structure to initialize

    _Example_
    \code
    wc_HWPUF s_hwpuf;
    ret = wc_HWPUF_Init(&s_hwpuf);
    \endcode

    \sa wc_HWPUF_Deinit
    \sa wc_HWPUF_Enroll
    \sa wc_HWPUF_Start
    \sa wc_HWPUF_Zeroize
*/
int wc_HWPUF_Init(wc_HWPUF* hwpuf);

/*!
    \ingroup HWPUF

    \brief Initialize a wc_HWPUF structure, zeroing all fields.
    Must be called before any other HWPUF operations.

    \return 0 on success
    \return BAD_FUNC_ARG if hwpuf is NULL

    \param hwpuf pointer to wc_HWPUF structure to initialize

    _Example_
    \code
    wc_HWPUF s_hwpuf;
    ret = wc_HWPUF_Deinit(&s_hwpuf);
    \endcode

    \sa wc_HWPUF_Init
    \sa wc_HWPUF_Zeroize
*/
int wc_HWPUF_Deinit(wc_HWPUF* hwpuf);

/*!
    \ingroup HWPUF

    \brief Perform HWPUF enrollment. Encodes raw SRAM using BCH(127,64,t=10)
    and generates public helper data. After enrollment the context is ready
    for key derivation and identity retrieval.

    \return 0 on success
    \return BAD_FUNC_ARG if hwpuf is NULL
    \return HWPUF_ENROLL_E if enrollment fails

    \param hwpuf pointer to wc_HWPUF (must have SRAM data loaded)

    _Example_
    \code
    wc_HWPUF_Enroll(&s_hwpuf);
    XMEMCPY(helperData, hwpuf.helperData, WC_HWPUF_HELPER_BYTES);
    \endcode

    \sa wc_HWPUF_Start
    \sa wc_HWPUF_GetKey
*/
int wc_HWPUF_Enroll(wc_HWPUF* hwpuf);

/*!
    \ingroup HWPUF

    \brief Reconstruct stable HWPUF bits from noisy SRAM using stored helper
    data. BCH error correction (t=10) corrects up to 10 bit flips per
    127-bit codeword.

    \return 0 on success
    \return BAD_FUNC_ARG if hwpuf or helperData is NULL
    \return HWPUF_RECONSTRUCT_E on failure (too many bit errors or helperSz
    too small)

    \param hwpuf pointer to wc_HWPUF

    _Example_
    \code
    wc_HWPUF_Start(&s_hwpuf);
    \endcode

    \sa wc_HWPUF_Enroll
    \sa wc_HWPUF_GetKey
*/
int wc_HWPUF_Start(wc_HWPUF* hwpuf);

/*!
    \ingroup HWPUF

    \brief Derive a cryptographic key from HWPUF stable bits using HKDF.
    Uses SHA-256 by default, or SHA3-256 when WC_HWPUF_SHA3 is defined.
    The info parameter provides domain separation for multiple keys.
    Requires HAVE_HKDF.

    \return 0 on success
    \return BAD_FUNC_ARG if hwpuf or key is NULL, or keySz is 0
    \return HWPUF_DERIVE_KEY_E if HWPUF not ready or HKDF fails

    \param hwpuf pointer to wc_HWPUF (must be enrolled or reconstructed)
    \param info optional context info for domain separation (may be NULL;
    when NULL, infoSz is treated as 0)
    \param infoSz size of info in bytes
    \param key output buffer for derived key
    \param keySz desired key size in bytes

    _Example_
    \code
    byte key[32];
    const byte info[] = "my-app-key";
    wc_HWPUF_GetKey(&s_hwpuf, info, sizeof(info), key, sizeof(key));
    \endcode

    \sa wc_HWPUF_Start
*/
int wc_HWPUF_GenerateKey(wc_HWPUF* hwpuf, byte keyIdx, word32 keySz,
                         byte* keycode, word32 keycodeSz);

/*!
    \ingroup HWPUF

    \brief Derive a cryptographic key from HWPUF stable bits using HKDF.
    Uses SHA-256 by default, or SHA3-256 when WC_HWPUF_SHA3 is defined.
    The info parameter provides domain separation for multiple keys.
    Requires HAVE_HKDF.

    \return 0 on success
    \return BAD_FUNC_ARG if hwpuf or key is NULL, or keySz is 0
    \return HWPUF_DERIVE_KEY_E if HWPUF not ready or HKDF fails

    \param hwpuf pointer to wc_HWPUF (must be enrolled or reconstructed)
    \param info optional context info for domain separation (may be NULL;
    when NULL, infoSz is treated as 0)
    \param infoSz size of info in bytes
    \param key output buffer for derived key
    \param keySz desired key size in bytes

    _Example_
    \code
    byte key[32];
    const byte info[] = "my-app-key";
    wc_HWPUF_GetKey(&s_hwpuf, info, sizeof(info), key, sizeof(key));
    \endcode

    \sa wc_HWPUF_Enroll
    \sa wc_HWPUF_Start
*/
int wc_HWPUF_SetKey(wc_HWPUF* hwpuf, byte keyIdx,
                    byte* key, word32 keySz,
                    byte* keycode, word32 keycodeSz);

/*!
    \ingroup HWPUF

    \brief Derive a cryptographic key from HWPUF stable bits using HKDF.
    Uses SHA-256 by default, or SHA3-256 when WC_HWPUF_SHA3 is defined.
    The info parameter provides domain separation for multiple keys.
    Requires HAVE_HKDF.

    \return 0 on success
    \return BAD_FUNC_ARG if hwpuf or key is NULL, or keySz is 0
    \return HWPUF_DERIVE_KEY_E if HWPUF not ready or HKDF fails

    \param hwpuf pointer to wc_HWPUF (must be enrolled or reconstructed)
    \param info optional context info for domain separation (may be NULL;
    when NULL, infoSz is treated as 0)
    \param infoSz size of info in bytes
    \param key output buffer for derived key
    \param keySz desired key size in bytes

    _Example_
    \code
    byte key[32];
    const byte info[] = "my-app-key";
    wc_HWPUF_GetKey(&s_hwpuf, info, sizeof(info), key, sizeof(key));
    \endcode

    \sa wc_HWPUF_Enroll
    \sa wc_HWPUF_Start
*/
int wc_HWPUF_GetKey(wc_HWPUF* hwpuf, byte* keycode, word32 keycodeSz,
                    byte* key, word32 keySz);

/*!
    \ingroup HWPUF

    \brief Securely zeroize all sensitive data in the HWPUF context using
    ForceZero. Call when HWPUF is no longer needed.

    \return 0 on success
    \return BAD_FUNC_ARG if hwpuf is NULL

    \param hwpuf pointer to wc_HWPUF to zeroize

    _Example_
    \code
    wc_HWPUF_Zeroize(&s_hwpuf);
    \endcode

    \sa wc_HWPUF_Init
    \sa wc_HWPUF_Deinit
*/
int wc_HWPUF_Zeroize(wc_HWPUF* hwpuf);
