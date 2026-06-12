/*!
    \ingroup HWPUF

    For a complete bare-metal example (tested on LPC55S69), see
    https://github.com/wolfSSL/wolfBoot/tree/master/config/examples/lpc55s69-hwpuf.config
*/

/*!
    \ingroup HWPUF

    \brief Initialize the wc_HWPUF context and register the CryptoCb device.
    Must be called before any other HWPUF operations.

    \return 0 on success
    \return BAD_FUNC_ARG if hwpuf is NULL
    \return HWPUF_REGISTER_E if already registered
    \return CRYPTOCB_UNAVAILABLE if nothing to register

    \param hwpuf pointer to wc_HWPUF context to initialize
    \param heap heap hint, can be NULL
    \param devId device ID for crypto callbacks. Specify INVALID_DEVID to use
    the default compiled into the driver.

    _Example_
    \code
    wc_HWPUF s_hwpuf;
    ret = wc_HWPUF_Register(&s_hwpuf, NULL, INVALID_DEVID);
    \endcode

    \sa wc_HWPUF_Init
    \sa wc_HWPUF_Deinit
    \sa wc_HWPUF_Unregister
*/
int wc_HWPUF_Register(wc_HWPUF* hwpuf, void* heap, int devId);

/*!
    \ingroup HWPUF

    \brief Unregister the CryptoCb device and zero the wc_HWPUF context.
    
    \return 0 on success, or if not registered
    \return BAD_FUNC_ARG if hwpuf is NULL
    \return CRYPTOCB_UNAVAILABLE if nothing to unregister

    \param hwpuf pointer to wc_HWPUF context

    _Example_
    \code
    wc_HWPUF s_hwpuf;
    ret = wc_HWPUF_Unregister(&s_hwpuf);
    \endcode

    \sa wc_HWPUF_Register
    \sa wc_HWPUF_Init
    \sa wc_HWPUF_Deinit
    \sa wc_HWPUF_Zeroize
*/
int wc_HWPUF_Unregister(wc_HWPUF* hwpuf);

/*!
    \ingroup HWPUF

    \brief Initialize the hardware device into a functional state.
    May include turning on the clock and taking the peripheral out of reset.

    \return 0 on success, or if already initialized
    \return BAD_FUNC_ARG if hwpuf is NULL
    \return HWPUF_REGISTER_E if not registered
    \return HWPUF_INIT_E if hardware initialization failed, leaving device in
    a deinitialized state

    \param hwpuf pointer to wc_HWPUF context

    _Example_
    \code
    wc_HWPUF s_hwpuf;
    ret = wc_HWPUF_Init(&s_hwpuf);
    \endcode

    \sa wc_HWPUF_Start
    \sa wc_HWPUF_Deinit
    \sa wc_HWPUF_Unregister
*/
int wc_HWPUF_Init(wc_HWPUF* hwpuf);

/*!
    \ingroup HWPUF

    \brief Deinitialize the hardware device into a non-functional state.
    May include turning off the clock and putting the peripheral into reset.

    \return 0 on success
    \return BAD_FUNC_ARG if hwpuf is NULL
    \return HWPUF_REGISTER_E if not registered

    \param hwpuf pointer to wc_HWPUF context

    _Example_
    \code
    wc_HWPUF s_hwpuf;
    ret = wc_HWPUF_Deinit(&s_hwpuf);
    \endcode

    \sa wc_HWPUF_Unregister
    \sa wc_HWPUF_Init
*/
int wc_HWPUF_Deinit(wc_HWPUF* hwpuf);

/*!
    \ingroup HWPUF

    \brief Perform HWPUF enrollment. Enrollment is usually a one-time
    operation, which generates an activation code (or helper data).
    The activation code should be stored in NVM and used whenever the device
    is started for key operations, i.e., wc_HWPUF_Start().
    After a successful enrollment, device must go through a
    wc_HWPUF_Deinit() / wc_HWPUF_Init() cycle before wc_HWPUF_Start().

    \return 0 on success
    \return BAD_FUNC_ARG if hwpuf or actCode is NULL, or if invalid actCodeSz 
    \return HWPUF_INIT_E if not yet initialized
    \return HWPUF_ENROLL_E if already enrolled, or if enrollment failed

    \param hwpuf pointer to wc_HWPUF context
    \param actCode output buffer for activation code
    \param actCodeSz size of activation code (HWPUF_ACTIVATION_CODE_SIZE)

    _Example_
    \code
    wc_HWPUF s_hwpuf;
    byte activationCode[HWPUF_ACTIVATION_CODE_SIZE];
    ret = wc_HWPUF_Enroll(&s_hwpuf, activationCode, sizeof(activationCode));
    < write activationCode to nvm >
    \endcode

    \sa wc_HWPUF_Start
    \sa wc_HWPUF_Init
    \sa wc_HWPUF_Deinit
*/
int wc_HWPUF_Enroll(wc_HWPUF* hwpuf, byte* actCode, word32 actCodeSz);

/*!
    \ingroup HWPUF

    \brief Start the device with an activation code (helper data).
    Starting puts the device into a ready state for key operations.

    \return 0 on success
    \return BAD_FUNC_ARG if hwpuf or actCode is NULL, or if invalid actCodeSz 
    \return HWPUF_INIT_E if not yet initialized
    \return HWPUF_START_E if already started, or if start failed

    \param hwpuf pointer to wc_HWPUF context
    \param actCode pointer to the activation code
    \param actCodeSz size of activation code in bytes

    _Example_
    \code
    wc_HWPUF s_hwpuf;
    byte activationCode[HWPUF_ACTIVATION_CODE_SIZE];
    XMEMCPY(activationCode, nvm.activationCode, HWPUF_ACTIVATION_CODE_SIZE);
    ret = wc_HWPUF_Start(&s_hwpuf, activationCode, sizeof(activationCode));
    \endcode

    \sa wc_HWPUF_Init
    \sa wc_HWPUF_Deinit
    \sa wc_HWPUF_Enroll
*/
int wc_HWPUF_Start(wc_HWPUF* hwpuf, byte* actCode, word32 actCodeSz);

/*!
    \ingroup HWPUF

    \brief Generate a key and return a key code.
    The key code should be stored in NVM and used whenever the key is
    requested from the device, i.e., wc_HWPUF_GetKey().

    \return 0 on success
    \return BAD_FUNC_ARG if hwpuf NULL, or a problem with other params
    \return HWPUF_START_E if device is not started (ready)
    \return HWPUF_GENERATE_KEY_E if the device failed to generate the key

    \param hwpuf pointer to wc_HWPUF context
    \param keyIdx index to associate with the generated key/keyCode pair
    \param keySz size of the generated key in bytes
    \param keyCode output buffer for key code
    \param keyCodeSz size of the key code in bytes

    _Example_
    \code
    wc_HWPUF s_hwpuf;
    byte keyCode1[HWPUF_KEY_SIZE_TO_KEY_CODE_SIZE(32)];
    XMEMCPY(keyCode1, nvm.keyCode1, sizeof(keyCode1));
    ret = wc_HWPUF_GenerateKey(&s_hwpuf, 1, 32, keyCode1, sizeof(keyCode1));
    < write keyCode1 to nvm >
    \endcode

    \sa wc_HWPUF_Start
    \sa wc_HWPUF_SetKey
    \sa wc_HWPUF_GetKey
*/
int wc_HWPUF_GenerateKey(wc_HWPUF* hwpuf, byte keyIdx, word32 keySz,
                         byte* keyCode, word32 keyCodeSz);

/*!
    \ingroup HWPUF

    \brief Set a key into the device and return a key code.  
    The key code should be stored in NVM and used whenever the key is
    requested from the device, i.e., wc_HWPUF_GetKey().
    This is typically done in a secure factory, for pre-shared keys.

    \return 0 on success
    \return BAD_FUNC_ARG if hwpuf NULL, or a problem with other params
    \return HWPUF_START_E if device is not started (ready)
    \return HWPUF_SET_KEY_E if the device failed to set the key

    \param hwpuf pointer to wc_HWPUF context
    \param keyIdx index to associate with the generated key/keyCode pair
    \param key input buffer with key to set
    \param keySz size of the key to set in bytes
    \param keyCode output buffer for key code
    \param keyCodeSz size of the key code in bytes

    _Example_
    \code
    byte key2[16];
    byte keyCode2[HWPUF_KEY_SIZE_TO_KEY_CODE_SIZE(16)];
    XMEMCPY(key2, nvm.key2, sizeof(key2));
    ret = wc_HWPUF_SetKey(&s_hwpuf, 2, 16, key2, sizeof(key2),
                          keyCode2, sizeof(keyCode2));
    < write keyCode2 to nvm >
    \endcode

    \sa wc_HWPUF_GetKey
    \sa wc_HWPUF_GenerateKey
*/
int wc_HWPUF_SetKey(wc_HWPUF* hwpuf, byte keyIdx,
                    byte* key, word32 keySz,
                    byte* keyCode, word32 keyCodeSz);

/*!
    \ingroup HWPUF

    \brief Get a key from a key code

    \return 0 on success
    \return BAD_FUNC_ARG if hwpuf NULL, or a problem with other params
    \return HWPUF_START_E if device is not started (ready)
    \return HWPUF_GET_KEY_E if the device failed to get the key

    \param hwpuf pointer to wc_HWPUF context
    \param keyCode input buffer with key code
    \param keyCodeSz size of the key code in bytes
    \param key output buffer for key
    \param keySz size of the key in bytes

    _Example_
    \code
    byte key2[16];
    byte keyCode2[HWPUF_KEY_SIZE_TO_KEY_CODE_SIZE(16)];
    XMEMCPY(keyCode2, nvm.keyCode2, sizeof(keyCode2));
    ret = wc_HWPUF_GetKey(&s_hwpuf, keyCode2, sizeof(keyCode2),
                          key2, sizeof(key2));
    \endcode

    \sa wc_HWPUF_GenerateKey
    \sa wc_HWPUF_SetKey
    \sa wc_HWPUF_Start
*/
int wc_HWPUF_GetKey(wc_HWPUF* hwpuf, byte* keyCode, word32 keyCodeSz,
                    byte* key, word32 keySz);

/*!
    \ingroup HWPUF

    \brief Securely zeroize all sensitive data in both the device and context.
    Call when the device is no longer needed. Leaves the device in the
    deinitialized state.

    \return 0 on success
    \return BAD_FUNC_ARG if hwpuf is NULL
    \return HWPUF_ZEROIZE_E if the device failed the zeroize operation

    \param hwpuf pointer to wc_HWPUF context

    _Example_
    \code
    wc_HWPUF_Zeroize(&s_hwpuf);
    \endcode

    \sa wc_HWPUF_Deinit
*/
int wc_HWPUF_Zeroize(wc_HWPUF* hwpuf);
