/*!
    \ingroup CryptoCb

    \brief This function registers a unique device identifier (devID) and
    callback function for offloading crypto operations to external
    hardware such as Key Store, Secure Element, HSM, PKCS11 or TPM.

    For STSAFE with Crypto Callbacks example see
    wolfcrypt/src/port/st/stsafe.c and the wolfSSL_STSAFE_CryptoDevCb function.

    For TPM based crypto callbacks example see the wolfTPM2_CryptoDevCb
    function in wolfTPM src/tpm2_wrap.c

    \return CRYPTOCB_UNAVAILABLE to fallback to using software crypto
    \return 0 for success
    \return negative value for failure

    \param devId any unique value, not -2 (INVALID_DEVID)
    \param cb a callback function with prototype:
    typedef int (*CryptoDevCallbackFunc)(int devId, wc_CryptoInfo* info, void* ctx);

    _Example_
    \code
    #include <wolfssl/wolfcrypt/settings.h>
    #include <wolfssl/wolfcrypt/cryptocb.h>
    static int myCryptoCb_Func(int devId, wc_CryptoInfo* info, void* ctx)
    {
        int ret = CRYPTOCB_UNAVAILABLE;

        if (info->algo_type == WC_ALGO_TYPE_PK) {
        #ifndef NO_RSA
            if (info->pk.type == WC_PK_TYPE_RSA) {
                switch (info->pk.rsa.type) {
                    case RSA_PUBLIC_ENCRYPT:
                    case RSA_PUBLIC_DECRYPT:
                        // RSA public op
                        ret = wc_RsaFunction(
                            info->pk.rsa.in, info->pk.rsa.inLen,
                            info->pk.rsa.out, info->pk.rsa.outLen,
                            info->pk.rsa.type, info->pk.rsa.key,
                            info->pk.rsa.rng);
                        break;
                    case RSA_PRIVATE_ENCRYPT:
                    case RSA_PRIVATE_DECRYPT:
                        // RSA private op
                        ret = wc_RsaFunction(
                            info->pk.rsa.in, info->pk.rsa.inLen,
                            info->pk.rsa.out, info->pk.rsa.outLen,
                            info->pk.rsa.type, info->pk.rsa.key,
                            info->pk.rsa.rng);
                        break;
                }
            }
        #endif
        #ifdef HAVE_ECC
            if (info->pk.type == WC_PK_TYPE_ECDSA_SIGN) {
                // ECDSA
                ret = wc_ecc_sign_hash(
                    info->pk.eccsign.in, info->pk.eccsign.inlen,
                    info->pk.eccsign.out, info->pk.eccsign.outlen,
                    info->pk.eccsign.rng, info->pk.eccsign.key);
            }
        #endif
        #ifdef HAVE_ED25519
            if (info->pk.type == WC_PK_TYPE_ED25519_SIGN) {
                // ED25519 sign
                ret = wc_ed25519_sign_msg_ex(
                    info->pk.ed25519sign.in, info->pk.ed25519sign.inLen,
                    info->pk.ed25519sign.out, info->pk.ed25519sign.outLen,
                    info->pk.ed25519sign.key, info->pk.ed25519sign.type,
                    info->pk.ed25519sign.context,
                    info->pk.ed25519sign.contextLen);
            }
        #endif
        }
        return ret;
    }

    int devId = 1;
    wc_CryptoCb_RegisterDevice(devId, myCryptoCb_Func, &myCtx);
    wolfSSL_CTX_SetDevId(ctx, devId);
    \endcode

    \sa wc_CryptoCb_UnRegisterDevice
    \sa wolfSSL_SetDevId
    \sa wolfSSL_CTX_SetDevId
*/
int  wc_CryptoCb_RegisterDevice(int devId, CryptoDevCallbackFunc cb, void* ctx);

/*!
    \ingroup CryptoCb

    \brief This function un-registers a unique device identifier (devID)
    callback function.

    \return none No returns.

    \param devId any unique value, not -2 (INVALID_DEVID)

    _Example_
    \code
    wc_CryptoCb_UnRegisterDevice(devId);
    devId = INVALID_DEVID;
    wolfSSL_CTX_SetDevId(ctx, devId);
    \endcode

    \sa wc_CryptoCb_RegisterDevice
    \sa wolfSSL_SetDevId
    \sa wolfSSL_CTX_SetDevId
*/
void wc_CryptoCb_UnRegisterDevice(int devId);

/*!
    \ingroup CryptoCb
    \brief This function returns the default device ID for crypto
    callbacks. This is useful when you want to get the device ID that
    was set as the default for the library.

    \return The default device ID, or INVALID_DEVID if no default is set.

    _Example_
    \code
    int devId = wc_CryptoCb_DefaultDevID();
    if (devId != INVALID_DEVID) {
        // default device ID is set
    }
    \endcode

    \sa wc_CryptoCb_RegisterDevice
    \sa wc_CryptoCb_UnRegisterDevice
*/
int wc_CryptoCb_DefaultDevID(void);

/*!
    \ingroup CryptoCb
    \brief This function sets a callback for finding crypto devices.
    The callback is invoked when a device ID needs to be resolved to
    a device context. This is useful for dynamic device management.

    \return none No returns.

    \param cb callback function with prototype:
    typedef void* (*CryptoDevCallbackFind)(int devId);

    _Example_
    \code
    void* myDeviceFindCb(int devId) {
        // lookup device context by ID
        return deviceContext;
    }

    wc_CryptoCb_SetDeviceFindCb(myDeviceFindCb);
    \endcode

    \sa wc_CryptoCb_RegisterDevice
*/
void wc_CryptoCb_SetDeviceFindCb(CryptoDevCallbackFind cb);

/*!
    \ingroup CryptoCb
    \brief This function converts a wc_CryptoInfo structure to a
    human-readable string for debugging purposes. The string is printed
    to stdout and describes the cryptographic operation being performed.

    \return none No returns.

    \param info pointer to the wc_CryptoInfo structure to convert

    _Example_
    \code
    int myCryptoCb(int devId, wc_CryptoInfo* info, void* ctx) {
        // print debug info about the operation
        wc_CryptoCb_InfoString(info);

        // handle the operation
        return CRYPTOCB_UNAVAILABLE;
    }
    \endcode

    \sa wc_CryptoCb_RegisterDevice
*/
void wc_CryptoCb_InfoString(wc_CryptoInfo* info);
