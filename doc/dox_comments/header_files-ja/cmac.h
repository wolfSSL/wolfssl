/*!
    \ingroup CMAC
    \brief Cmac構造体をデフォルト値で初期化します
    \return 0 成功時
    \param cmac Cmac構造体へのポインタ
    \param key キーポインタ
    \param keySz キーポインタのサイズ(16、24、または32)
    \param type 常にWC_CMAC_AES = 1
    \param unused 使用されません。互換性に関する将来の使用の可能性のために存在します

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
    \brief Cmac構造体をデフォルト値で初期化します
    \return 0 成功時
    \param cmac Cmac構造体へのポインタ
    \param key キーポインタ
    \param keySz キーポインタのサイズ(16、24、または32)
    \param type 常にWC_CMAC_AES = 1
    \param unused 使用されません。互換性に関する将来の使用の可能性のために存在します
    \param heap 動的割り当てに使用されるヒープヒントへのポインタ。通常、静的メモリオプションで使用されます。NULLにできます。
    \param devId 暗号コールバックまたは非同期ハードウェアで使用するID。使用しない場合はINVALID_DEVID(-2)に設定します

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
    \brief 暗号ベースメッセージ認証コード入力データを追加します
    \return 0 成功時
    \param cmac Cmac構造体へのポインタ
    \param in 処理する入力データ
    \param inSz 入力データのサイズ

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
    \brief 暗号ベースメッセージ認証コードを使用して最終結果を生成し、コンテキストのクリーンアップを延期します。
    \return 0 成功時
    \param cmac Cmac構造体へのポインタ
    \param out 結果を返すポインタ
    \param outSz 出力のポインタサイズ(入出力)

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
    \brief 暗号ベースメッセージ認証コードを使用して最終結果を生成し、wc_CmacFree()でコンテキストをクリーンアップします。
    \return 0 成功時
    \param cmac Cmac構造体へのポインタ
    \param out 結果を返すポインタ
    \param outSz 出力のポインタサイズ(入出力)

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
    \brief CMACコンテキスト内の割り当てをクリーンアップします。
    \return 0 成功時
    \param cmac Cmac構造体へのポインタ

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
    \brief CMACを生成するためのシングルショット関数
    \return 0 成功時
    \param out 結果を返すポインタ
    \param outSz 出力のポインタサイズ(入出力)
    \param in 処理する入力データ
    \param inSz 入力データのサイズ
    \param key キーポインタ
    \param keySz キーポインタのサイズ(16、24、または32)

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
    \brief CMACを検証するためのシングルショット関数
    \return 0 成功時
    \param check 検証するCMAC値
    \param checkSz checkバッファのサイズ
    \param in 処理する入力データ
    \param inSz 入力データのサイズ
    \param key キーポインタ
    \param keySz キーポインタのサイズ(16、24、または32)

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
    \brief ハードウェアがシングルショットを必要とし、更新をメモリにキャッシュする必要がある場合にWOLFSSL_HASH_KEEPでのみ使用されます
    \return 0 成功時
    \param in 処理する入力データ
    \param inSz 入力データのサイズ

    _Example_
    \code
    ret = wc_CMAC_Grow(cmac, in, inSz)
    \endcode
*/
int wc_CMAC_Grow(Cmac* cmac, const byte* in, int inSz);