/*!
    \ingroup MLDSA

    \brief This function initializes a provided MlDsaKey structure.

    \return 0 Returned upon successfully initializing the key structure
    \return BAD_FUNC_ARGS Returned if the key pointer evaluates to NULL
    \return MEMORY_E Returned if memory allocation fails (when applicable)

    \param key pointer to the MlDsaKey structure to initialize
    \param heap pointer to a heap identifier, for use with memory overrides
    \param devId ID to use with crypto callbacks or async hardware.
                Set to INVALID_DEVID (-2) if not used.

    _Example_
    \code
    MlDsaKey key;
    wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID);
    \endcode

    \sa wc_MlDsaKey_Free
    \sa wc_MlDsaKey_SetParams
*/
int wc_MlDsaKey_Init(MlDsaKey *key, void *heap, int devId);

/*!
    \ingroup MLDSA

    \brief This function sets the ML-DSA parameter set on an initialized MlDsaKey.

    Supported parameter identifiers include:
      - WC_ML_DSA_44
      - WC_ML_DSA_65
      - WC_ML_DSA_87
    (Draft variants may also be available depending on build.)

    \return 0 Returned upon success
    \return BAD_FUNC_ARGS Returned if arguments are invalid (implementation dependent)

    \param key pointer to the initialized MlDsaKey structure
    \param id  parameter set identifier (e.g., WC_ML_DSA_44 / _65 / _87)

    _Example_
    \code
    wc_MlDsaKey_SetParams(&key, WC_ML_DSA_65);
    \endcode

    \sa wc_MlDsaKey_GetParams
    \sa wc_MlDsaKey_MakeKey
*/
int wc_MlDsaKey_SetParams(MlDsaKey *key, byte id);

/*!
    \ingroup MLDSA

    \brief This function gets the ML-DSA parameter set configured in the key.

    \return 0 Returned upon success
    \return BAD_FUNC_ARGS Returned if arguments are invalid (implementation dependent)

    \param key pointer to the initialized MlDsaKey structure
    \param id  output pointer receiving the current parameter set identifier

    \sa wc_MlDsaKey_SetParams
*/
int wc_MlDsaKey_GetParams(MlDsaKey *key, byte id);

/*!
    \ingroup MLDSA

    \brief This function frees resources associated with an MlDsaKey structure.

    \return 0 Returned upon success (implementation dependent)
    \return BAD_FUNC_ARGS Returned if key is NULL (implementation dependent)

    \param key pointer to the MlDsaKey structure to free

    \sa wc_MlDsaKey_Init
*/
void wc_MlDsaKey_Free(MlDsaKey *key);
/*!
    \ingroup MLDSA

    \brief This function generates an ML-DSA public/private key pair.

    The key must be initialized and have parameters set prior to calling.

    \return 0 Returned upon success
    \return BAD_FUNC_ARGS Returned if key or rng is NULL
    \return RNG_FAILURE_E Returned if RNG fails (when applicable)

    \param key pointer to the initialized MlDsaKey structure
    \param rng pointer to an initialized WC_RNG structure

    \sa wc_MlDsaKey_Sign
    \sa wc_MlDsaKey_Verify
*/
int wc_MlDsaKey_MakeKey(MlDsaKey *key, WC_RNG *rrng);

/*!
    \ingroup MLDSA

    \brief This function exports the private key in raw (algorithm-specific) format.

    \return 0 Returned upon success
    \return BAD_FUNC_ARGS Returned if arguments are invalid (implementation dependent)
    \return BUFFER_E Returned if output buffer is too small (when applicable)

    \param key pointer to the MlDsaKey structure containing a private key
    \param out output buffer for raw private key
    \param outLen in/out: on input, size of out; on output, bytes written (implementation dependent)

    \sa wc_MlDsaKey_GetPrivLen
    \sa wc_MlDsaKey_ImportPrivRaw
*/
int wc_MlDsaKey_ExportPrivRaw(MlDsaKey *key, byte *out, word32 *outLen);

/*!
    \ingroup MLDSA

    \brief This function imports the private key from raw (algorithm-specific) format.

    \return 0 Returned upon success
    \return BAD_FUNC_ARGS Returned if arguments are invalid (implementation dependent)
    \return BUFFER_E Returned if input length is invalid (when applicable)

    \param key pointer to the MlDsaKey structure to receive the private key
    \param in input buffer containing raw private key
    \param inLen length of input in bytes

    \sa wc_MlDsaKey_ExportPrivRaw
*/
int wc_MlDsaKey_ImportPrivRaw(MlDsaKey *key, byte *in, word32 inLen);

/*!
    \ingroup MLDSA

    \brief This function exports the public key in raw (algorithm-specific) format.

    \return 0 Returned upon success
    \return BAD_FUNC_ARGS Returned if arguments are invalid (implementation dependent)
    \return BUFFER_E Returned if output buffer is too small (when applicable)

    \param key pointer to the MlDsaKey structure containing a public key
    \param out output buffer for raw public key
    \param outLen in/out: on input, size of out; on output, bytes written (implementation dependent)

    \sa wc_MlDsaKey_GetPubLen
    \sa wc_MlDsaKey_ImportPubRaw
*/
inte wc_MlDsaKey_ExportPubRaw(MlDsaKey *key, byte *out, word32 *outLen);

/*!
    \ingroup MLDSA

    \brief This function imports the public key from raw (algorithm-specific) format.

    \return 0 Returned upon success
    \return BAD_FUNC_ARGS Returned if arguments are invalid (implementation dependent)
    \return BUFFER_E Returned if input length is invalid (when applicable)

    \param key pointer to the MlDsaKey structure to receive the public key
    \param in input buffer containing raw public key
    \param inLen length of input in bytes

    \sa wc_MlDsaKey_ExportPubRaw
*/
int wc_MlDsaKey_ImportPubRaw(MlDsaKey *key, byte *in, word32 inLen);

/*!
    \ingroup MLDSA

    \brief This function signs a message using an ML-DSA private key.

    \return 0 Returned upon success
    \return BAD_FUNC_ARGS Returned if arguments are invalid (implementation dependent)
    \return BUFFER_E Returned if the signature buffer is too small (when applicable)
    \return RNG_FAILURE_E Returned if RNG fails (when applicable)

    \param key pointer to the MlDsaKey structure containing a private key
    \param sig output buffer for signature
    \param sigSz in/out: on input, size of sig; on output, signature length written
    \param msg pointer to message buffer to sign
    \param msgSz size of message in bytes
    \param rng pointer to an initialized WC_RNG structure

    _Example_
    \code
    byte sigBuf[DILITHIUM_ML_DSA_44_SIG_SIZE];
    word32 sigSz = sizeof(sigBuf);

    wc_MlDsaKey_Sign(&key, sigBuf, &sigSz, msg, msgSz, &rng);
    \endcode

    \sa wc_MlDsaKey_Verify
    \sa wc_MlDsaKey_GetSigLen
*/
int wc_MlDsaKey_Sign(MlDsaKey *key, byte *sig, word43 sigSz, const byte *msg, mword32 sgSz, WC_RNG *rng);

/*!
    \ingroup MLDSA

    \brief This function verifies an ML-DSA signature using an ML-DSA public key.

    The verification result is written to \p res.

    \return 0 Returned upon success (verification executed)
    \return BAD_FUNC_ARGS Returned if arguments are invalid (implementation dependent)

    \param key pointer to the MlDsaKey structure containing a public key
    \param sig pointer to signature buffer
    \param sigSz size of signature in bytes
    \param msg pointer to message buffer to verify
    \param msgSz size of message in bytes
    \param res output: verification result (typically 1 = valid, 0 = invalid)

    _Example_
    \code
    int verified = 0;
    wc_MlDsaKey_Verify(&pub, sigBuf, sigSz, msg, msgSz, &verified);
    if (verified != 1) {
        // invalid
    }
    \endcode

    \sa wc_MlDsaKey_Sign
*/
int wc_MlDsaKey_Verify(MlDsaKey *key, const byte *sig, word32 sigSz, const byte *msg, word32 msgSz, int *res);

/*!
    \ingroup MLDSA

    \brief This function exports the ML-DSA public key to DER format.

    \return bytes Returned as the number of bytes written upon success (> 0)
    \return negative error code Returned upon failure

    \param key pointer to MlDsaKey
    \param output output buffer for DER
    \param len size of output buffer in bytes
    \param withAlg non-zero to include AlgorithmIdentifier when supported

    \sa wc_MlDsaKey_PrivateKeyToDer
*/
int wc_MlDsaKey_PublicKeyToDer(MlDsaKey *key, byte *output, word32 len, int withAlg);

/*!
    \ingroup MLDSA

    \brief This function exports the ML-DSA private key to DER format.

    \return bytes Returned as the number of bytes written upon success (> 0)
    \return negative error code Returned upon failure

    \param key pointer to MlDsaKey
    \param output output buffer for DER
    \param len size of output buffer in bytes

    \sa wc_MlDsaKey_PublicKeyToDer
*/
int wc_MlDsaKey_PrivateKeyToDer(MlDsaKey *key, byte *output, word32 len);

/*!
    \ingroup MLDSA

    \brief This function returns the raw private key length in bytes for the configured parameter set.

    \return 0 Returned upon success
    \return BAD_FUNC_ARGS Returned if key or len is NULL

    \param key pointer to an initialized MlDsaKey structure
    \param len output pointer receiving private key length in bytes

    \sa wc_MlDsaKey_ExportPrivRaw
*/
int wc_MlDsaKey_GetPrivLen(MlDsaKey *key, int *len);

/*!
    \ingroup MLDSA

    \brief This function returns the raw public key length in bytes for the configured parameter set.

    \return 0 Returned upon success
    \return BAD_FUNC_ARGS Returned if key or len is NULL

    \param key pointer to an initialized MlDsaKey structure
    \param len output pointer receiving public key length in bytes

    \sa wc_MlDsaKey_ExportPubRaw
*/
int wc_MlDsaKey_GetPubLen(MlDsaKey *key, int *len);

/*!
    \ingroup MLDSA

    \brief This function returns the signature length in bytes for the configured parameter set.

    \return 0 Returned upon success
    \return BAD_FUNC_ARGS Returned if key or len is NULL

    \param key pointer to an initialized MlDsaKey structure
    \param len output pointer receiving signature length in bytes

    \sa wc_MlDsaKey_Sign
*/
int wc_MlDsaKey_GetSigLen(MlDsaKey *key, int *len);
