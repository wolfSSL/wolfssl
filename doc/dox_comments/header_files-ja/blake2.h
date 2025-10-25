/*!
    \ingroup BLAKE2

    \brief この関数は、Blake2ハッシュ関数で使用するためのBlake2b構造体を初期化します。

    \return 0 Blake2b構造体の初期化とダイジェストサイズの設定に成功した場合に返されます。

    \param b2b 初期化するBlake2b構造体へのポインタ
    \param digestSz 実装するblake 2ダイジェストの長さ

    _Example_
    \code
    Blake2b b2b;
    // 64バイトダイジェストでBlake2b構造体を初期化
    wc_InitBlake2b(&b2b, 64);
    \endcode

    \sa wc_Blake2bUpdate
*/
int wc_InitBlake2b(Blake2b* b2b, word32 digestSz);

/*!
    \ingroup BLAKE2

    \brief この関数は、指定された入力データでBlake2bハッシュを更新します。この関数はwc_InitBlake2bの後に呼び出され、最終ハッシュ(wc_Blake2bFinal)の準備ができるまで繰り返されます。

    \return 0 指定されたデータでBlake2b構造体の更新に成功した場合に返されます
    \return -1 入力データの圧縮中に失敗した場合に返されます

    \param b2b 更新するBlake2b構造体へのポインタ
    \param data 追加するデータを含むバッファへのポインタ
    \param sz 追加する入力データの長さ

    _Example_
    \code
    int ret;
    Blake2b b2b;
    // 64バイトダイジェストでBlake2b構造体を初期化
    wc_InitBlake2b(&b2b, 64);

    byte plain[] = { // 入力を初期化 };

    ret = wc_Blake2bUpdate(&b2b, plain, sizeof(plain));
    if( ret != 0) {
    	// blake2bの更新エラー
    }
    \endcode

    \sa wc_InitBlake2b
    \sa wc_Blake2bFinal
*/
int wc_Blake2bUpdate(Blake2b* b2b, const byte* data, word32 sz);

/*!
    \ingroup BLAKE2

    \brief この関数は、以前に提供された入力データのBlake2bハッシュを計算します。出力ハッシュの長さはrequestSzになります。requestSz==0の場合は、b2b構造体のdigestSzが使用されます。この関数は、wc_InitBlake2bの後、および必要な各入力データに対してwc_Blake2bUpdateが処理された後に呼び出す必要があります。

    \return 0 Blake2bハッシュの計算に成功した場合に返されます
    \return -1 Blake2bハッシュの解析中に失敗した場合に返されます

    \param b2b 更新するBlake2b構造体へのポインタ
    \param final blake2bハッシュを格納するバッファへのポインタ。
    requestSzの長さである必要があります
    \param requestSz 計算するダイジェストの長さ。これがゼロの場合、
    代わりにb2b->digestSzが使用されます

    _Example_
    \code
    int ret;
    Blake2b b2b;
    byte hash[64];
    // 64バイトダイジェストでBlake2b構造体を初期化
    wc_InitBlake2b(&b2b, 64);
    ... // wc_Blake2bUpdateを呼び出してハッシュにデータを追加

    ret = wc_Blake2bFinal(&b2b, hash, 64);
    if( ret != 0) {
    	// blake2bハッシュの生成エラー
    }
    \endcode

    \sa wc_InitBlake2b
    \sa wc_Blake2bUpdate
*/
int wc_Blake2bFinal(Blake2b* b2b, byte* final, word32 requestSz);