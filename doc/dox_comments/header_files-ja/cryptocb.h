/*!
    \ingroup CryptoCb

    \brief この関数は、Key Store、Secure Element、HSM、PKCS11、TPMなどの外部ハードウェアへの暗号操作のオフロードのために、一意のデバイス識別子(devID)とコールバック関数を登録します。

    Crypto Callbacksを使用したSTSAFEの例については、wolfcrypt/src/port/st/stsafe.cとwolfSSL_STSAFE_CryptoDevCb関数を参照してください。

    TPMベースの暗号コールバックの例については、wolfTPM src/tpm2_wrap.cのwolfTPM2_CryptoDevCb関数を参照してください。

    \return CRYPTOCB_UNAVAILABLE ソフトウェア暗号の使用にフォールバックする場合
    \return 0 成功時
    \return 負の値 失敗時

    \param devId -2(INVALID_DEVID)以外の任意の一意の値
    \param cb 次のプロトタイプを持つコールバック関数:
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
                        // RSA公開鍵操作
                        ret = wc_RsaFunction(
                            info->pk.rsa.in, info->pk.rsa.inLen,
                            info->pk.rsa.out, info->pk.rsa.outLen,
                            info->pk.rsa.type, info->pk.rsa.key,
                            info->pk.rsa.rng);
                        break;
                    case RSA_PRIVATE_ENCRYPT:
                    case RSA_PRIVATE_DECRYPT:
                        // RSA秘密鍵操作
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
                // ED25519署名
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

    \brief この関数は、一意のデバイス識別子(devID)のコールバック関数の登録を解除します。

    \return none 戻り値なし。

    \param devId -2(INVALID_DEVID)以外の任意の一意の値

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
