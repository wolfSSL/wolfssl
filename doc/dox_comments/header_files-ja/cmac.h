/*!
     \ingroup CMAC
     \brief Cmac構造体をデフォルト値で初期化します
     \return 成功したら0を返します
     \param cmac Cmac構造体へのポインタ
     \param key 鍵データへのポインタ
     \param keySz 鍵データのサイズ(16、24、または 32)
     \param type 常にWC_CMAC_AES（=1）
     \param unused 使用されていません。互換性に関する将来の潜在的な使用のために存在します

     _例_
     \code
     Cmac cmac[1];
     ret = wc_InitCmac(cmac、key、keySz、WC_CMAC_AES、NULL);
     if (ret == 0) {
         ret = wc_CmacUpdate(cmac、in、inSz);
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
                 const byte* key、word32 keySz、
                 int type、void* unused);

/*!
     \ingroup CMAC
     \brief Cmac構造体をデフォルト値で初期化します
     \return 成功したら0を返します
     \param cmac Cmac構造体へのポインタ
     \param key 鍵データへのポインタ
     \param keySz 鍵データのサイズ(16、24、または 32)
     \param type 常にWC_CMAC_AES（=1）
     \param unused 使用されていません。互換性に関する将来の潜在的な使用のために存在します
     \param heap 動的割り当てに使用されるヒープヒントへのポインタ。 通常、スタティックメモリオプションで使用されます。 NULLにすることができます。
     \param devId 非同期ハードウェアで使用するID。非同期ハードウェアを使用していない場合は、INVALID_DEVIDに設定します。

     _例_
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
                 int type, void* unused、void* heap, int devId);

/*!
     \ingroup CMAC
     \brief 暗号ベースのメッセージ認証コード入力データを追加
     \return 成功したら0を返します
     \param cmac Cmac構造体へのポインタ
     \param in 処理する入力データへのポインタ
     \param inSz 入力データのサイズ

     _例_
     \code
     ret = wc_CmacUpdate(cmac、in、inSz);
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
    \brief 暗号ベースのメッセージ認証コードの最終結果を生成します。ただし、使用したコンテキストのクリーンアップは行いません。
    \return 成功したら0を返します
    \param cmac Cmac構造体へのポインタ
    \param out 結果を格納するバッファへのポインタ
    \param outSz 結果出力先バッファのサイズ

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
     \brief 暗号ベースのメッセージ認証コードを使用して最終結果を生成します。加えて、内部でwc_CmacFreeを呼び出してコンテキスとをクリーンアップします。
     \return 成功したら0を返します
     \param cmac Cmac構造体へのポインタ
     \param out 結果を格納するバッファへのポインタ
     \param outSz 結果出力先バッファのサイズ

     _例_
     \code
     ret = wc_CmacFinal(cmac, out, &outSz);
     \endcode

     \sa wc_InitCmac
     \sa wc_CmacFinal
     \sa wc_CmacFinalNoFree
     \sa wc_CmacFree
*/
int wc_CmacFinal(Cmac* cmac,
                  byte* out, word32* outSz);

/*!
    \ingroup CMAC
    \brief CMAC処理中にCmac構造体内に確保されたオブジェクトを開放します。
    \return 成功したら0を返します
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
     \return 成功したら0を返します
     \param out 結果の出力先バッファへのポインタ
     \param outSz 出力のポインタサイズ (in/out)
     \param in 処理する入力データのポインタ
     \param inSz 入力データのサイズ
     \param key 鍵データへのポインタ
     \param keySz 鍵データのサイズ (16、24、または 32)

     _例_
     \code
     ret = wc_AesCmacGenerate(mac, &macSz, msg, msgSz, key, keySz);
     \endcode

     \sa wc_AesCmacVerify
*/
int wc_AesCmacGenerate(byte* out, word32* outSz,
                        const byte* in、word32 inSz、
                        const byte* key, word32 keySz);

/*!
     \ingroup CMAC
     \brief CMACを検証するためのシングルショット関数
     \return 成功したら0を返します
     \param check 検証対象となるCMAC処理結果データへのポインタ
     \param checkSz CMAC処理結果データのサイズ
     \param in 処理する入力データのポインタ
     \param inSz 入力データのサイズ
     \param key 鍵データへのポインタ
     \param keySz 鍵データのサイズ (16、24、または 32)

     _例_
     \code
     ret = wc_AesCmacVerify(mac, macSz, msg, msgSz, key, keySz);
     \endcode

     \sa wc_AesCmacGenerate
*/
int wc_AesCmacVerify(const byte* check, word32 checkSz,
                      const byte* in、word32 inSz、
                      const byte* key, word32 keySz);


/*!
     \ingroup CMAC
     \brief WOLFSSL_HASH_KEEPマクロ定義時のみ使用可能。ハードウェアがシングルショットを必要とし、更新をメモリにキャッシュする必要がある場合に使用します。
     \return 成功したら0を返します
     \param cmac Cmac構造体へのポインタ
     \param in 処理する入力データへのポインタ
     \param inSz 入力データのサイズ

     _例_
     \code
     ret = wc_CMAC_Grow(cmac、in、inSz)
     \endcode
*/
int wc_CMAC_Grow(Cmac* cmac, const byte* in, int inSz);
