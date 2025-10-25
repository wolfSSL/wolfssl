/*!
    \ingroup SHA

    \brief この関数はSHA512を初期化します。これはwc_Sha512Hashによって自動的に呼び出されます。

    \return 0 初期化に成功した場合に返されます

    \param sha512 暗号化に使用するsha512構造体へのポインタ

    _Example_
    \code
    Sha512 sha512[1];
    if ((ret = wc_InitSha512(sha512)) != 0) {
       WOLFSSL_MSG("wc_InitSha512 failed");
    }
    else {
       wc_Sha512Update(sha512, data, len);
       wc_Sha512Final(sha512, hash);
    }
    \endcode

    \sa wc_Sha512Hash
    \sa wc_Sha512Update
    \sa wc_Sha512Final
*/
int wc_InitSha512(wc_Sha512*);

/*!
    \ingroup SHA

    \brief 長さlenの提供されたバイト配列を継続的にハッシュするために呼び出すことができます。

    \return 0 ダイジェストへのデータ追加に成功した場合に返されます。

    \param sha512 暗号化に使用するsha512構造体へのポインタ
    \param data ハッシュ化されるデータ
    \param len ハッシュ化されるデータの長さ

    _Example_
    \code
    Sha512 sha512[1];
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha512(sha512)) != 0) {
       WOLFSSL_MSG("wc_InitSha512 failed");
    }
    else {
       wc_Sha512Update(sha512, data, len);
       wc_Sha512Final(sha512, hash);
    }
    \endcode

    \sa wc_Sha512Hash
    \sa wc_Sha512Final
    \sa wc_InitSha512
*/
int wc_Sha512Update(wc_Sha512* sha, const byte* data, word32 len);

/*!
    \ingroup SHA

    \brief データのハッシュ化を完了します。結果はhashに格納されます。

    \return 0 ハッシュの完了に成功した場合に返されます。

    \param sha512 暗号化に使用するsha512構造体へのポインタ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    Sha512 sha512[1];
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha512(sha512)) != 0) {
        WOLFSSL_MSG("wc_InitSha512 failed");
    }
    else {
       wc_Sha512Update(sha512, data, len);
       wc_Sha512Final(sha512, hash);
    }
    \endcode

    \sa wc_Sha512Hash
    \sa wc_Sha512Final
    \sa wc_InitSha512
*/
int wc_Sha512Final(wc_Sha512* sha512, byte* hash);

/*!
    \ingroup SHA

    \brief この関数はSHA384を初期化します。これはwc_Sha384Hashによって自動的に呼び出されます。

    \return 0 初期化に成功した場合に返されます

    \param sha384 暗号化に使用するsha384構造体へのポインタ

    _Example_
    \code
    Sha384 sha384[1];
    if ((ret = wc_InitSha384(sha384)) != 0) {
       WOLFSSL_MSG("wc_InitSha384 failed");
    }
    else {
       wc_Sha384Update(sha384, data, len);
       wc_Sha384Final(sha384, hash);
    }
    \endcode

    \sa wc_Sha384Hash
    \sa wc_Sha384Update
    \sa wc_Sha384Final
*/
int wc_InitSha384(wc_Sha384*);

/*!
    \ingroup SHA

    \brief 長さlenの提供されたバイト配列を継続的にハッシュするために呼び出すことができます。

    \return 0 ダイジェストへのデータ追加に成功した場合に返されます。

    \param sha384 暗号化に使用するsha384構造体へのポインタ
    \param data ハッシュ化されるデータ
    \param len ハッシュ化されるデータの長さ

    _Example_
    \code
    Sha384 sha384[1];
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha384(sha384)) != 0) {
       WOLFSSL_MSG("wc_InitSha384 failed");
    }
    else {
       wc_Sha384Update(sha384, data, len);
       wc_Sha384Final(sha384, hash);
    }
    \endcode

    \sa wc_Sha384Hash
    \sa wc_Sha384Final
    \sa wc_InitSha384
*/
int wc_Sha384Update(wc_Sha384* sha, const byte* data, word32 len);

/*!
    \ingroup SHA

    \brief データのハッシュ化を完了します。結果はhashに格納されます。

    \return 0 完了に成功した場合に返されます。

    \param sha384 暗号化に使用するsha384構造体へのポインタ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    Sha384 sha384[1];
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha384(sha384)) != 0) {
       WOLFSSL_MSG("wc_InitSha384 failed");
    }
    else {
       wc_Sha384Update(sha384, data, len);
       wc_Sha384Final(sha384, hash);
    }
    \endcode

    \sa wc_Sha384Hash
    \sa wc_Sha384Final
    \sa wc_InitSha384
*/
int wc_Sha384Final(wc_Sha384* sha384, byte* hash);