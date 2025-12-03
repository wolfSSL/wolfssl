/*!
    \ingroup MD4

    \brief この関数はmd4を初期化します。これはwc_Md4Hashによって自動的に呼び出されます。

    \return 0 初期化に成功した場合に返されます

    \param md4 暗号化に使用するmd4構造体へのポインタ

    _Example_
    \code
    md4 md4[1];
    if ((ret = wc_InitMd4(md4)) != 0) {
       WOLFSSL_MSG("wc_Initmd4 failed");
    }
    else {
       wc_Md4Update(md4, data, len);
       wc_Md4Final(md4, hash);
    }
    \endcode

    \sa wc_Md4Hash
    \sa wc_Md4Update
    \sa wc_Md4Final
*/
void wc_InitMd4(Md4*);

/*!
    \ingroup MD4

    \brief 長さlenの提供されたバイト配列を継続的にハッシュするために呼び出すことができます。

    \return 0 ダイジェストへのデータ追加に成功した場合に返されます。

    \param md4 暗号化に使用するmd4構造体へのポインタ
    \param data ハッシュ化されるデータ
    \param len ハッシュ化されるデータの長さ

    _Example_
    \code
    md4 md4[1];
    byte data[] = { }; // ハッシュ化されるデータ
    word32 len = sizeof(data);

    if ((ret = wc_InitMd4(md4)) != 0) {
       WOLFSSL_MSG("wc_Initmd4 failed");
    }
    else {
       wc_Md4Update(md4, data, len);
       wc_Md4Final(md4, hash);
    }
    \endcode

    \sa wc_Md4Hash
    \sa wc_Md4Final
    \sa wc_InitMd4
*/
void wc_Md4Update(Md4* md4, const byte* data, word32 len);

/*!
    \ingroup MD4

    \brief データのハッシュ化を完了します。結果はhashに格納されます。

    \return 0 完了に成功した場合に返されます。

    \param md4 暗号化に使用するmd4構造体へのポインタ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    md4 md4[1];
    if ((ret = wc_InitMd4(md4)) != 0) {
        WOLFSSL_MSG("wc_Initmd4 failed");
    }
    else {
        wc_Md4Update(md4, data, len);
        wc_Md4Final(md4, hash);
    }
    \endcode

    \sa wc_Md4Hash
    \sa wc_Md4Final
    \sa wc_InitMd4
*/
void wc_Md4Final(Md4* md4, byte* hash);
