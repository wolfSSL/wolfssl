/*!
    \ingroup STM32

    \brief This function registers the STM32 DHUK (Device Hardware Unique Key)
    crypto-callback device. After registering at WC_DHUK_DEVID, bind an object
    to the device by setting its devId at init (wc_AesInit / wc_ecc_init_ex) and
    supply the per-key 256-bit seed as the key (wc_AesGcmSetKey) or via
    wc_ecc_import_wrapped_private; normal wolfCrypt AES / GMAC / ECDSA calls
    then run transparently with the working key derived inside the SAES.
    Available on STM32 builds with WOLFSSL_DHUK, WOLF_CRYPTO_CB, and a
    DHUK-capable SAES (WC_STM32_HAS_DHUK); on the CubeMX path it is also
    provided for CCB ECDSA.

    \return 0 Returned on success.
    \return <0 A negative error code is returned if device registration fails.

    \param devId the crypto-callback device id to register (use WC_DHUK_DEVID).

    _Example_
    \code
    Aes aes;
    wc_Stm32_DhukRegister(WC_DHUK_DEVID);
    wc_AesInit(&aes, NULL, WC_DHUK_DEVID);
    wc_AesGcmSetKey(&aes, seed, 32);
    wc_AesGcmEncrypt(&aes, NULL, NULL, 0, iv, ivSz, tag, tagSz, aad, aadSz);
    wc_AesFree(&aes);
    wc_Stm32_DhukUnRegister(WC_DHUK_DEVID);
    \endcode

    \sa wc_Stm32_DhukUnRegister
    \sa wc_ecc_import_wrapped_private
*/
int wc_Stm32_DhukRegister(int devId);

/*!
    \ingroup STM32

    \brief This function unregisters the STM32 DHUK crypto-callback device that
    was registered with wc_Stm32_DhukRegister. Call it once transparent
    DHUK / CCB operations are complete.

    \return none No return value.

    \param devId the crypto-callback device id to unregister (WC_DHUK_DEVID).

    _Example_
    \code
    wc_Stm32_DhukUnRegister(WC_DHUK_DEVID);
    \endcode

    \sa wc_Stm32_DhukRegister
*/
void wc_Stm32_DhukUnRegister(int devId);

/*!
    \ingroup STM32

    \brief This function performs a chip-bound DHUK AES key-wrap on the SAES
    (KEYSEL=HW, deterministic output) and is retained for provisioning wrapped
    key material. The wrap-key source is selected by aes->devId
    (WOLFSSL_DHUK_DEVID for the hardware DHUK, otherwise a software key in
    aes->key). An optional iv selects CBC instead of ECB. Available on STM32
    builds with WOLFSSL_DHUK and a DHUK-capable SAES.

    \return 0 Returned on success.
    \return BAD_FUNC_ARG Returned if a required pointer is NULL, if inSz is
    not a supported block size, if the iv is non-NULL with ivSz != 16, or
    (software-key path) if the wrapping key length is not 16 or 32.
    \return <0 A negative error code may be returned on a hardware error.

    \param aes pointer to an initialized Aes; aes->devId selects the wrap key.
    \param in pointer to the input key bytes to wrap.
    \param inSz length of in in bytes.
    \param out pointer to the output buffer for the wrapped key.
    \param outSz on input the size of out; on output the bytes written.
    \param iv optional 16-byte iv; NULL selects ECB, non-NULL selects CBC.
    \param ivSz length of iv in bytes when iv is non-NULL; must be 16.

    \sa wc_Stm32_DhukRegister
*/
int wc_Stm32_Aes_Wrap(struct Aes* aes, const byte* in, word32 inSz, byte* out,
    word32* outSz, const byte* iv, int ivSz);

/*!
    \ingroup STM32

    \brief This function brings up the STM32 CCB (Coupling and Chaining Bridge)
    peripheral and reports whether it is usable: it enables the CCB / PKA / SAES
    / RNG clocks, pulse-resets the engines, waits for BUSY to clear, and checks
    for an operation error. Bare-metal only (WOLFSSL_STM32_BARE). The
    transparent CCB sign path calls this internally, so most callers do not
    invoke it directly. Available on STM32 builds with WOLFSSL_STM32_CCB on
    CCB silicon (STM32U3 or STM32C5).

    \return 0 Returned when the CCB is up and usable.
    \return WC_TIMEOUT_E Returned if BUSY does not clear within the timeout.
    \return <0 A negative error code is returned if the CCB reports an error.

    \param none This function takes no parameters.

    \sa wc_Stm32_Ccb_EccMakeBlob
    \sa wc_Stm32_Ccb_EccSign
*/
int wc_Stm32_CcbInit(void);

/*!
    \ingroup STM32

    \brief This function creates an STM32 CCB ECDSA-signature blob from a clear
    private scalar on-device. The scalar is wrapped under the silicon DHUK; the
    returned blob (iv[16] + tag[16] + wrapped scalar) and the derived public key
    (pubX[32] / pubY[32]) can be persisted and later reloaded with
    wc_ecc_import_wrapped_private_ex. The hardware self-verifies the blob before
    returning. Currently P-256 (ECC_SECP256R1). Available on STM32 builds with
    WOLFSSL_STM32_CCB on CCB silicon (STM32U3 or STM32C5).

    \return 0 Returned on success.
    \return NOT_COMPILED_IN Returned if curveId is an unsupported curve.
    \return BAD_FUNC_ARG Returned if a required pointer is NULL or dLen is
    wrong.
    \return WC_TIMEOUT_E Returned if a hardware step times out.

    \param curveId the ECC curve id; currently ECC_SECP256R1.
    \param d pointer to the clear private scalar to wrap.
    \param dLen length of d in bytes.
    \param iv output buffer for the 16-byte blob iv.
    \param tag output buffer for the 16-byte blob authentication tag.
    \param wrapped output buffer for the wrapped scalar.
    \param wrappedSz on output the length of the wrapped scalar in bytes.
    \param pubX output buffer for the 32-byte public key X coordinate.
    \param pubY output buffer for the 32-byte public key Y coordinate.

    \sa wc_Stm32_Ccb_EccSign
    \sa wc_ecc_import_wrapped_private_ex
*/
int wc_Stm32_Ccb_EccMakeBlob(int curveId, const byte* d, word32 dLen,
    byte* iv, byte* tag, byte* wrapped, word32* wrappedSz,
    byte* pubX, byte* pubY);

/*!
    \ingroup STM32

    \brief This function signs a hash with an STM32 CCB ECDSA blob. The private
    scalar is unwrapped inside the hardware (SAES->PKA over the CCB local bus)
    and never enters software or crosses the system bus. The (r, s) signature is
    written to the caller's 32-byte buffers. Currently P-256 (ECC_SECP256R1).
    Available on STM32 builds with WOLFSSL_STM32_CCB on CCB silicon (STM32U3 or
    STM32C5). Most callers reach this transparently via wc_ecc_sign_hash on a
    WC_DHUK_DEVID key rather than calling it directly.

    \return 0 Returned on success.
    \return NOT_COMPILED_IN Returned if curveId is an unsupported curve.
    \return BAD_FUNC_ARG Returned if a required pointer is NULL.
    \return WC_TIMEOUT_E Returned if a hardware step times out.

    \param curveId the ECC curve id; currently ECC_SECP256R1.
    \param iv pointer to the 16-byte blob iv.
    \param tag pointer to the 16-byte blob authentication tag.
    \param wrapped pointer to the wrapped scalar from wc_Stm32_Ccb_EccMakeBlob.
    \param wrappedSz length of wrapped in bytes.
    \param hash pointer to the hash to sign.
    \param hashSz length of hash in bytes.
    \param r output buffer for the 32-byte signature r value.
    \param s output buffer for the 32-byte signature s value.

    \sa wc_Stm32_Ccb_EccMakeBlob
    \sa wc_ecc_sign_hash
*/
int wc_Stm32_Ccb_EccSign(int curveId, const byte* iv, const byte* tag,
    const byte* wrapped, word32 wrappedSz, const byte* hash, word32 hashSz,
    byte* r, byte* s);
