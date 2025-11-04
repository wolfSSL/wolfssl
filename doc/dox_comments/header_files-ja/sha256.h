/*!
    \ingroup SHA

    \brief この関数はSHA256を初期化します。これはwc_Sha256Hashによって自動的に呼び出されます。

    \return 0 初期化に成功した場合に返されます

    \param sha256 暗号化に使用するsha256構造体へのポインタ

    _Example_
    \code
    Sha256 sha256[1];
    if ((ret = wc_InitSha256(sha256)) != 0) {
        WOLFSSL_MSG("wc_InitSha256 failed");
    }
    else {
        wc_Sha256Update(sha256, data, len);
        wc_Sha256Final(sha256, hash);
    }
    \endcode

    \sa wc_Sha256Hash
    \sa wc_Sha256Update
    \sa wc_Sha256Final
*/
int wc_InitSha256(wc_Sha256*);

/*!
    \ingroup SHA

    \brief 長さlenの提供されたバイト配列を継続的にハッシュするために呼び出すことができます。

    \return 0 ダイジェストへのデータ追加に成功した場合に返されます。

    \param sha256 暗号化に使用するsha256構造体へのポインタ
    \param data ハッシュ化されるデータ
    \param len ハッシュ化されるデータの長さ

    _Example_
    \code
    Sha256 sha256[1];
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha256(sha256)) != 0) {
       WOLFSSL_MSG("wc_InitSha256 failed");
    }
    else {
        wc_Sha256Update(sha256, data, len);
        wc_Sha256Final(sha256, hash);
    }
    \endcode

    \sa wc_Sha256Hash
    \sa wc_Sha256Final
    \sa wc_InitSha256
*/
int wc_Sha256Update(wc_Sha256* sha, const byte* data, word32 len);

/*!
    \ingroup SHA

    \brief データのハッシュ化を完了します。結果はhashに格納されます。sha256構造体の状態をリセットします。

    \return 0 完了に成功した場合に返されます。

    \param sha256 暗号化に使用するsha256構造体へのポインタ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    Sha256 sha256[1];
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha256(sha256)) != 0) {
       WOLFSSL_MSG("wc_InitSha256 failed");
    }
    else {
       wc_Sha256Update(sha256, data, len);
       wc_Sha256Final(sha256, hash);
    }
    \endcode

    \sa wc_Sha256Hash
    \sa wc_Sha256GetHash
    \sa wc_InitSha256
*/
int wc_Sha256Final(wc_Sha256* sha256, byte* hash);

/*!
    \ingroup SHA

    \brief Sha256構造体をリセットします。注意: これはWOLFSSL_TI_HASHが定義されている場合にのみサポートされます。

    \return none 戻り値なし。

    \param sha256 解放するsha256構造体へのポインタ。

    _Example_
    \code
    Sha256 sha256;
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha256(&sha256)) != 0) {
        WOLFSSL_MSG("wc_InitSha256 failed");
    }
    else {
        wc_Sha256Update(&sha256, data, len);
        wc_Sha256Final(&sha256, hash);
        wc_Sha256Free(&sha256);
    }
    \endcode

    \sa wc_InitSha256
    \sa wc_Sha256Update
    \sa wc_Sha256Final
*/
void wc_Sha256Free(wc_Sha256*);

/*!
    \ingroup SHA

    \brief ハッシュデータを取得します。結果はhashに格納されます。sha256構造体の状態はリセットされません。

    \return 0 完了に成功した場合に返されます。

    \param sha256 暗号化に使用するsha256構造体へのポインタ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    Sha256 sha256[1];
    if ((ret = wc_InitSha256(sha256)) != 0) {
       WOLFSSL_MSG("wc_InitSha256 failed");
    }
    else {
       wc_Sha256Update(sha256, data, len);
       wc_Sha256GetHash(sha256, hash);
    }
    \endcode

    \sa wc_Sha256Hash
    \sa wc_Sha256Final
    \sa wc_InitSha256
*/
int wc_Sha256GetHash(wc_Sha256* sha256, byte* hash);

/*!
    \ingroup SHA

    \brief Sha224構造体を初期化するために使用されます。

    \return 0 成功
    \return 1 sha224がnullのためにエラーが返されます。

    \param sha224 初期化するSha224構造体へのポインタ。

    _Example_
    \code
    Sha224 sha224;
    if(wc_InitSha224(&sha224) != 0)
    {
        // エラーを処理
    }
    \endcode

    \sa wc_Sha224Hash
    \sa wc_Sha224Update
    \sa wc_Sha224Final
*/
int wc_InitSha224(wc_Sha224*);

/*!
    \ingroup SHA

    \brief 長さlenの提供されたバイト配列を継続的にハッシュするために呼び出すことができます。

    \return 0 成功
    \return 1 関数が失敗した場合にエラーが返されます。
    \return BAD_FUNC_ARG sha224またはdataがnullの場合にエラーが返されます。

    \param sha224 暗号化に使用するSha224構造体へのポインタ。
    \param data ハッシュ化されるデータ。
    \param len ハッシュ化されるデータの長さ。

    _Example_
    \code
    Sha224 sha224;
    byte data[] = { /* ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha224(&sha224)) != 0) {
       WOLFSSL_MSG("wc_InitSha224 failed");
    }
    else {
      wc_Sha224Update(&sha224, data, len);
      wc_Sha224Final(&sha224, hash);
    }
    \endcode

    \sa wc_InitSha224
    \sa wc_Sha224Final
    \sa wc_Sha224Hash
*/
int wc_Sha224Update(wc_Sha224* sha224, const byte* data, word32 len);

/*!
    \ingroup SHA

    \brief データのハッシュ化を完了します。結果はhashに格納されます。sha224構造体の状態をリセットします。

    \return 0 成功
    \return <0 エラー

    \param sha224 暗号化に使用するsha224構造体へのポインタ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    Sha224 sha224;
    byte data[] = { /* ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha224(&sha224)) != 0) {
        WOLFSSL_MSG("wc_InitSha224 failed");
    }
    else {
        wc_Sha224Update(&sha224, data, len);
        wc_Sha224Final(&sha224, hash);
    }
    \endcode

    \sa wc_InitSha224
    \sa wc_Sha224Hash
    \sa wc_Sha224Update
*/
int wc_Sha224Final(wc_Sha224* sha224, byte* hash);