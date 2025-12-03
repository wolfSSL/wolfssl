/*!
    \ingroup MD5

    \brief この関数はmd5を初期化します。これはwc_Md5Hashによって自動的に呼び出されます。

    \return 0 正常に初期化された場合に返されます。
    \return BAD_FUNC_ARG Md5構造体がNULL値として渡された場合に返されます。

    \param md5 暗号化に使用するmd5構造体へのポインタ

    _Example_
    \code
    Md5 md5;
    byte* hash;
    if ((ret = wc_InitMd5(&md5)) != 0) {
       WOLFSSL_MSG("wc_Initmd5 failed");
    }
    else {
       ret = wc_Md5Update(&md5, data, len);
       if (ret != 0) {
    	 // Md5 Update失敗のケース。
       }
       ret = wc_Md5Final(&md5, hash);
      if (ret != 0) {
    	// Md5 Final失敗のケース。
      }
    }
    \endcode

    \sa wc_Md5Hash
    \sa wc_Md5Update
    \sa wc_Md5Final
*/
int wc_InitMd5(wc_Md5*);

/*!
    \ingroup MD5

    \brief 長さlenの提供されたバイト配列を継続的にハッシュするために呼び出すことができます。

    \return 0 ダイジェストへのデータ追加に成功した場合に返されます。
    \return BAD_FUNC_ARG Md5構造体がNULLの場合、またはdataがNULLでlenがゼロより大きい場合に返されます。dataパラメータがNULLでlenがゼロの場合、関数はエラーを返すべきではありません。

    \param md5 暗号化に使用するmd5構造体へのポインタ
    \param data ハッシュ化されるデータ
    \param len ハッシュ化されるデータの長さ

    _Example_
    \code
    Md5 md5;
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitMd5(&md5)) != 0) {
       WOLFSSL_MSG("wc_Initmd5 failed");
    }
    else {
       ret = wc_Md5Update(&md5, data, len);
       if (ret != 0) {
    	 // Md5 Updateエラーのケース。
       }
       ret = wc_Md5Final(&md5, hash);
       if (ret != 0) {
    	// Md5 Finalエラーのケース。
       }
    }
    \endcode

    \sa wc_Md5Hash
    \sa wc_Md5Final
    \sa wc_InitMd5
*/
int wc_Md5Update(wc_Md5* md5, const byte* data, word32 len);

/*!
    \ingroup MD5

    \brief データのハッシュ化を完了します。結果はhashに格納されます。Md5構造体はリセットされます。注意：この関数は、HAVE_INTEL_QAが定義されている場合にIntelQaSymMd5()を呼び出した結果も返します。

    \return 0 正常に完了した場合に返されます。
    \return BAD_FUNC_ARG Md5構造体またはhashポインタがNULLで渡された場合に返されます。

    \param md5 暗号化に使用するmd5構造体へのポインタ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    md5 md5[1];
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitMd5(md5)) != 0) {
       WOLFSSL_MSG("wc_Initmd5 failed");
    }
    else {
       ret = wc_Md5Update(md5, data, len);
       if (ret != 0) {
    	// Md5 Update失敗のケース。
       }
      ret = wc_Md5Final(md5, hash);
       if (ret != 0) {
	    // Md5 Final失敗のケース。
       }
    }
    \endcode

    \sa wc_Md5Hash
    \sa wc_InitMd5
    \sa wc_Md5GetHash
*/
int wc_Md5Final(wc_Md5* md5, byte* hash);

/*!
    \ingroup MD5

    \brief Md5構造体をリセットします。注意：これはWOLFSSL_TI_HASHが定義されている場合にのみサポートされます。

    \return none 戻り値なし。

    \param md5 リセットするMd5構造体へのポインタ。

    _Example_
    \code
    Md5 md5;
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitMd5(&md5)) != 0) {
        WOLFSSL_MSG("wc_InitMd5 failed");
    }
    else {
        wc_Md5Update(&md5, data, len);
        wc_Md5Final(&md5, hash);
        wc_Md5Free(&md5);
    }
    \endcode

    \sa wc_InitMd5
    \sa wc_Md5Update
    \sa wc_Md5Final
*/
void wc_Md5Free(wc_Md5*);

/*!
    \ingroup MD5

    \brief ハッシュデータを取得します。結果はhashに格納されます。Md5構造体はリセットされません。

    \return none 戻り値なし

    \param md5 暗号化に使用するmd5構造体へのポインタ。
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    md5 md5[1];
    if ((ret = wc_InitMd5(md5)) != 0) {
       WOLFSSL_MSG("wc_Initmd5 failed");
    }
    else {
       wc_Md5Update(md5, data, len);
       wc_Md5GetHash(md5, hash);
    }
    \endcode

    \sa wc_Md5Hash
    \sa wc_Md5Final
    \sa wc_InitMd5
*/
int  wc_Md5GetHash(wc_Md5* md5, byte* hash);
