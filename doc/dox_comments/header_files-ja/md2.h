/*!
    \ingroup MD2

    \brief この関数はmd2を初期化します。これはwc_Md2Hashによって自動的に呼び出されます。

    \return 0 初期化に成功した場合に返されます

    \param md2 暗号化に使用するmd2構造体へのポインタ

    _Example_
    \code
    md2 md2[1];
    if ((ret = wc_InitMd2(md2)) != 0) {
       WOLFSSL_MSG("wc_Initmd2 failed");
    }
    else {
       wc_Md2Update(md2, data, len);
       wc_Md2Final(md2, hash);
    }
    \endcode

    \sa wc_Md2Hash
    \sa wc_Md2Update
    \sa wc_Md2Final
*/
void wc_InitMd2(wc_Md2* md2);

/*!
    \ingroup MD2

    \brief 長さlenの提供されたバイト配列を継続的にハッシュするために呼び出すことができます。

    \return 0 ダイジェストへのデータ追加に成功した場合に返されます。

    \param md2 暗号化に使用するmd2構造体へのポインタ
    \param data ハッシュ化されるデータ
    \param len ハッシュ化されるデータの長さ

    _Example_
    \code
    md2 md2[1];
    byte data[] = { }; // ハッシュ化されるデータ
    word32 len = sizeof(data);

    if ((ret = wc_InitMd2(md2)) != 0) {
       WOLFSSL_MSG("wc_Initmd2 failed");
    }
    else {
       wc_Md2Update(md2, data, len);
       wc_Md2Final(md2, hash);
    }
    \endcode

    \sa wc_Md2Hash
    \sa wc_Md2Final
    \sa wc_InitMd2
*/
void wc_Md2Update(wc_Md2* md2, const byte* data, word32 len);

/*!
    \ingroup MD2

    \brief データのハッシュ化を完了します。結果はhashに格納されます。

    \return 0 完了に成功した場合に返されます。

    \param md2 暗号化に使用するmd2構造体へのポインタ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    md2 md2[1];
    byte data[] = { }; // ハッシュ化されるデータ
    word32 len = sizeof(data);

    if ((ret = wc_InitMd2(md2)) != 0) {
       WOLFSSL_MSG("wc_Initmd2 failed");
    }
    else {
       wc_Md2Update(md2, data, len);
       wc_Md2Final(md2, hash);
    }
    \endcode

    \sa wc_Md2Hash
    \sa wc_Md2Final
    \sa wc_InitMd2
*/
void wc_Md2Final(wc_Md2* md2, byte* hash);

/*!
    \ingroup MD2

    \brief 便利な関数で、すべてのハッシュ化を処理し、結果をhashに格納します。

    \return 0 データのハッシュ化に成功した場合に返されます。
    \return Memory_E メモリエラー、メモリを割り当てることができません。これはスモールスタックオプションが有効な場合にのみ発生します。

    \param data ハッシュ化するデータ
    \param len データの長さ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    none
    \endcode

    \sa wc_Md2Hash
    \sa wc_Md2Final
    \sa wc_InitMd2
*/
int  wc_Md2Hash(const byte* data, word32 len, byte* hash);
