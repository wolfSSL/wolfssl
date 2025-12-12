/*!
    \ingroup CMAC
    \brief Initialize the Cmac structure with defaults
    \return 0 on success
    \param cmac pointer to the Cmac structure
    \param key key pointer
    \param keySz size of the key pointer (16, 24 or 32)
    \param type Always WC_CMAC_AES = 1
    \param unused not used, exists for potential future use around compatibility

    _Example_
    \code
    Cmac cmac[1];
    ret = wc_InitCmac(cmac, key, keySz, WC_CMAC_AES, NULL);
    if (ret == 0) {
        ret = wc_CmacUpdate(cmac, in, inSz);
    }
    if (ret == 0) {
        ret = wc_CmacFinal(cmac, out, outSz);
    }
    \endcode

    \sa wc_InitCmac_ex
    \sa wc_CmacUpdate
    \sa wc_CmacFinal
    \sa wc_CmacFinalNoFree
    \sa wc_CmacFree
*/
int wc_InitCmac(Cmac* cmac,
                const byte* key, word32 keySz,
                int type, void* unused);

/*!
    \ingroup CMAC
    \brief Initialize the Cmac structure with defaults
    \return 0 on success
    \param cmac pointer to the Cmac structure
    \param key key pointer
    \param keySz size of the key pointer (16, 24 or 32)
    \param type Always WC_CMAC_AES = 1
    \param unused not used, exists for potential future use around compatibility
    \param heap pointer to the heap hint used for dynamic allocation. Typically used with our static memory option. Can be NULL.
    \param devId ID to use with crypto callbacks or async hardware. Set to INVALID_DEVID (-2) if not used

    _Example_
    \code
    Cmac cmac[1];
    ret = wc_InitCmac_ex(cmac, key, keySz, WC_CMAC_AES, NULL, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_CmacUpdate(cmac, in, inSz);
    }
    if (ret == 0) {
        ret = wc_CmacFinal(cmac, out, &outSz);
    }
    \endcode

    \sa wc_InitCmac_ex
    \sa wc_CmacUpdate
    \sa wc_CmacFinal
    \sa wc_CmacFinalNoFree
    \sa wc_CmacFree
*/
int wc_InitCmac_ex(Cmac* cmac,
                const byte* key, word32 keySz,
                int type, void* unused, void* heap, int devId);

/*!
    \ingroup CMAC
    \brief Add Cipher-based Message Authentication Code input data
    \return 0 on success
    \param cmac pointer to the Cmac structure
    \param in input data to process
    \param inSz size of input data

    _Example_
    \code
    ret = wc_CmacUpdate(cmac, in, inSz);
    \endcode

    \sa wc_InitCmac
    \sa wc_CmacFinal
    \sa wc_CmacFinalNoFree
    \sa wc_CmacFree
*/
int wc_CmacUpdate(Cmac* cmac,
                  const byte* in, word32 inSz);


/*!
    \ingroup CMAC
    \brief Generate the final result using Cipher-based Message Authentication Code, deferring context cleanup.
    \return 0 on success
    \param cmac pointer to the Cmac structure
    \param out pointer to return the result
    \param outSz pointer size of output (in/out)

    _Example_
    \code
    ret = wc_CmacFinalNoFree(cmac, out, &outSz);
    (void)wc_CmacFree(cmac);
    \endcode

    \sa wc_InitCmac
    \sa wc_CmacFinal
    \sa wc_CmacFinalNoFree
    \sa wc_CmacFree
*/
int wc_CmacFinalNoFree(Cmac* cmac,
                 byte* out, word32* outSz);

/*!
    \ingroup CMAC
    \brief Generate the final result using Cipher-based Message Authentication Code, and clean up the context with wc_CmacFree().
    \return 0 on success
    \param cmac pointer to the Cmac structure
    \param out pointer to return the result
    \param outSz pointer size of output (in/out)

    _Example_
    \code
    ret = wc_CmacFinal(cmac, out, &outSz);
    \endcode

    \sa wc_InitCmac
    \sa wc_CmacFinalNoFree
    \sa wc_CmacFinalNoFree
    \sa wc_CmacFree
*/
int wc_CmacFinal(Cmac* cmac,
                 byte* out, word32* outSz);

/*!
    \ingroup CMAC
    \brief Clean up allocations in a CMAC context.
    \return 0 on success
    \param cmac pointer to the Cmac structure

    _Example_
    \code
    ret = wc_CmacFinalNoFree(cmac, out, &outSz);
    (void)wc_CmacFree(cmac);
    \endcode

    \sa wc_InitCmac
    \sa wc_CmacFinalNoFree
    \sa wc_CmacFinal
    \sa wc_CmacFree
*/
int wc_CmacFree(Cmac* cmac);

/*!
    \ingroup CMAC
    \brief Single shot function for generating a CMAC
    \return 0 on success
    \param out pointer to return the result
    \param outSz pointer size of output (in/out)
    \param in input data to process
    \param inSz size of input data
    \param key key pointer
    \param keySz size of the key pointer (16, 24 or 32)

    _Example_
    \code
    ret = wc_AesCmacGenerate(mac, &macSz, msg, msgSz, key, keySz);
    \endcode

    \sa wc_AesCmacVerify
*/
int wc_AesCmacGenerate(byte* out, word32* outSz,
                       const byte* in, word32 inSz,
                       const byte* key, word32 keySz);

/*!
    \ingroup CMAC
    \brief Single shot function for validating a CMAC
    \return 0 on success
    \param check CMAC value to verify
    \param checkSz size of check buffer
    \param in input data to process
    \param inSz size of input data
    \param key key pointer
    \param keySz size of the key pointer (16, 24 or 32)

    _Example_
    \code
    ret = wc_AesCmacVerify(mac, macSz, msg, msgSz, key, keySz);
    \endcode

    \sa wc_AesCmacGenerate
*/
int wc_AesCmacVerify(const byte* check, word32 checkSz,
                     const byte* in, word32 inSz,
                     const byte* key, word32 keySz);


/*!
    \ingroup CMAC
    \brief Only used with WOLFSSL_HASH_KEEP when hardware requires single-shot and the updates must be cached in memory
    \return 0 on success
    \param in input data to process
    \param inSz size of input data

    _Example_
    \code
    ret = wc_CMAC_Grow(cmac, in, inSz)
    \endcode
*/
int wc_CMAC_Grow(Cmac* cmac, const byte* in, int inSz);

/*!
    \ingroup CMAC
    \brief Single shot AES-CMAC generation with extended parameters
    including heap and device ID.

    \return 0 on success
    \return BAD_FUNC_ARG if parameters are invalid

    \param cmac Pointer to Cmac structure (can be NULL for one-shot)
    \param out Buffer to store MAC output
    \param outSz Pointer to output size (in/out)
    \param in Input data to authenticate
    \param inSz Length of input data
    \param key AES key
    \param keySz Key size (16, 24, or 32 bytes)
    \param heap Heap hint for memory allocation (can be NULL)
    \param devId Device ID for hardware acceleration (use
    INVALID_DEVID for software)

    _Example_
    \code
    byte mac[AES_BLOCK_SIZE];
    word32 macSz = sizeof(mac);
    byte key[16], msg[64];

    int ret = wc_AesCmacGenerate_ex(NULL, mac, &macSz, msg,
                                    sizeof(msg), key, sizeof(key),
                                    NULL, INVALID_DEVID);
    \endcode

    \sa wc_AesCmacGenerate
    \sa wc_AesCmacVerify_ex
*/
int wc_AesCmacGenerate_ex(Cmac *cmac, byte* out, word32* outSz,
                          const byte* in, word32 inSz,
                          const byte* key, word32 keySz,
                          void* heap, int devId);

/*!
    \ingroup CMAC
    \brief Single shot AES-CMAC verification with extended parameters
    including heap and device ID.

    \return 0 on success
    \return BAD_FUNC_ARG if parameters are invalid
    \return MAC_CMP_FAILED_E if MAC verification fails

    \param cmac Pointer to Cmac structure (can be NULL for one-shot)
    \param check Expected MAC value to verify
    \param checkSz Size of expected MAC
    \param in Input data to authenticate
    \param inSz Length of input data
    \param key AES key
    \param keySz Key size (16, 24, or 32 bytes)
    \param heap Heap hint for memory allocation (can be NULL)
    \param devId Device ID for hardware acceleration (use
    INVALID_DEVID for software)

    _Example_
    \code
    byte mac[AES_BLOCK_SIZE];
    byte key[16], msg[64];

    int ret = wc_AesCmacVerify_ex(NULL, mac, sizeof(mac), msg,
                                  sizeof(msg), key, sizeof(key),
                                  NULL, INVALID_DEVID);
    if (ret == MAC_CMP_FAILED_E) {
        // MAC verification failed
    }
    \endcode

    \sa wc_AesCmacVerify
    \sa wc_AesCmacGenerate_ex
*/
int wc_AesCmacVerify_ex(Cmac* cmac, const byte* check, word32 checkSz,
                       const byte* in, word32 inSz,
                       const byte* key, word32 keySz,
                       void* heap, int devId);
