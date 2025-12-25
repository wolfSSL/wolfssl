/*!
    \ingroup SHA

    \brief この関数はSHAを初期化します。これはwc_ShaHashによって自動的に呼び出されます。

    \return 0 初期化に成功した場合に返されます

    \param sha 暗号化に使用するsha構造体へのポインタ

    _Example_
    \code
    Sha sha[1];
    if ((ret = wc_InitSha(sha)) != 0) {
       WOLFSSL_MSG("wc_InitSha failed");
    }
    else {
       wc_ShaUpdate(sha, data, len);
       wc_ShaFinal(sha, hash);
    }
    \endcode

    \sa wc_ShaHash
    \sa wc_ShaUpdate
    \sa wc_ShaFinal
*/
int wc_InitSha(wc_Sha* sha);

/*!
    \ingroup SHA

    \brief 長さlenの提供されたバイト配列を継続的にハッシュするために呼び出すことができます。

    \return 0 ダイジェストへのデータ追加に成功した場合に返されます。

    \param sha 暗号化に使用するsha構造体へのポインタ
    \param data ハッシュ化されるデータ
    \param len ハッシュ化されるデータの長さ

    _Example_
    \code
    Sha sha[1];
    byte data[] = { // ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha(sha)) != 0) {
       WOLFSSL_MSG("wc_InitSha failed");
    }
    else {
       wc_ShaUpdate(sha, data, len);
       wc_ShaFinal(sha, hash);
    }
    \endcode

    \sa wc_ShaHash
    \sa wc_ShaFinal
    \sa wc_InitSha
*/
int wc_ShaUpdate(wc_Sha* sha, const byte* data, word32 len);

/*!
    \ingroup SHA

    \brief データのハッシュ化を完了します。結果はhashに格納されます。
    sha構造体の状態をリセットします。

    \return 0 完了に成功した場合に返されます。

    \param sha 暗号化に使用するsha構造体へのポインタ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    Sha sha[1];
    byte data[] = { ハッシュ化されるデータ };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha(sha)) != 0) {
       WOLFSSL_MSG("wc_InitSha failed");
    }
    else {
       wc_ShaUpdate(sha, data, len);
       wc_ShaFinal(sha, hash);
    }
    \endcode

    \sa wc_ShaHash
    \sa wc_InitSha
    \sa wc_ShaGetHash
*/
int wc_ShaFinal(wc_Sha* sha, byte* hash);

/*!
    \ingroup SHA

    \brief 初期化されたSha構造体によって使用されるメモリをクリーンアップするために使用されます。

    \return 戻り値なし。

    \param sha 解放するSha構造体へのポインタ。

    _Example_
    \code
    Sha sha;
    wc_InitSha(&sha);
    // shaを使用
    wc_ShaFree(&sha);
    \endcode

    \sa wc_InitSha
    \sa wc_ShaUpdate
    \sa wc_ShaFinal
*/
void wc_ShaFree(wc_Sha* sha);

/*!
    \ingroup SHA

    \brief ハッシュデータを取得します。結果はhashに格納されます。sha構造体の状態はリセットされません。

    \return 0 完了に成功した場合に返されます。

    \param sha 暗号化に使用するsha構造体へのポインタ
    \param hash ハッシュ値を保持するバイト配列。

    _Example_
    \code
    Sha sha[1];
    if ((ret = wc_InitSha(sha)) != 0) {
    WOLFSSL_MSG("wc_InitSha failed");
    }
    else {
        wc_ShaUpdate(sha, data, len);
        wc_ShaGetHash(sha, hash);
    }
    \endcode

    \sa wc_ShaHash
    \sa wc_ShaFinal
    \sa wc_InitSha
*/
int wc_ShaGetHash(wc_Sha* sha, byte* hash);
