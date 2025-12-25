/*!
    \ingroup Poly1305

    \brief この関数は、Poly1305コンテキスト構造体のキーを設定し、ハッシュ化のために初期化します。注意: wc_Poly1305Finalでメッセージハッシュを生成した後、セキュリティを確保するために新しいキーを設定する必要があります。

    \return 0 キーの設定とPoly1305構造体の初期化に成功した場合に返されます
    \return BAD_FUNC_ARG 指定されたキーが32バイトでない場合、またはPoly1305コンテキストがNULLの場合に返されます

    \param ctx 初期化するPoly1305構造体へのポインタ
    \param key ハッシュ化に使用するキーを含むバッファへのポインタ
    \param keySz バッファ内のキーのサイズ。32バイトである必要があります

    _Example_
    \code
    Poly1305 enc;
    byte key[] = { ハッシュ化に使用する32バイトのキーで初期化 };
    wc_Poly1305SetKey(&enc, key, sizeof(key));
    \endcode

    \sa wc_Poly1305Update
    \sa wc_Poly1305Final
*/
int wc_Poly1305SetKey(Poly1305* poly1305, const byte* key,
                                  word32 kySz);

/*!
    \ingroup Poly1305

    \brief この関数は、Poly1305構造体でハッシュ化するメッセージを更新します。

    \return 0 ハッシュ化するメッセージの更新に成功した場合に返されます
    \return BAD_FUNC_ARG Poly1305構造体がNULLの場合に返されます

    \param ctx ハッシュ化するメッセージを更新するPoly1305構造体へのポインタ
    \param m ハッシュに追加するメッセージを含むバッファへのポインタ
    \param bytes ハッシュ化するメッセージのサイズ

    _Example_
    \code
    Poly1305 enc;
    byte key[] = { }; // 暗号化に使用する32バイトのキーで初期化

    byte msg[] = { }; // ハッシュ化するメッセージで初期化
    wc_Poly1305SetKey(&enc, key, sizeof(key));

    if( wc_Poly1305Update(key, msg, sizeof(msg)) != 0 ) {
	    // ハッシュ化するメッセージの更新エラー
    }
    \endcode

    \sa wc_Poly1305SetKey
    \sa wc_Poly1305Final
*/
int wc_Poly1305Update(Poly1305* poly1305, const byte* m, word32 bytes);

/*!
    \ingroup Poly1305

    \brief この関数は、入力メッセージのハッシュを計算し、結果をmacに格納します。この関数を呼び出した後、キーをリセットする必要があります。

    \return 0 最終MACの計算に成功した場合に返されます
    \return BAD_FUNC_ARG Poly1305構造体がNULLの場合に返されます

    \param ctx MACを生成するために使用するPoly1305構造体へのポインタ
    \param mac MACを格納するバッファへのポインタ。
    POLY1305_DIGEST_SIZE(16バイト)幅である必要があります

    _Example_
    \code
    Poly1305 enc;
    byte mac[POLY1305_DIGEST_SIZE]; // 16バイトのmac用のスペース

    byte key[] = { }; // 暗号化に使用する32バイトのキーで初期化

    byte msg[] = { }; // ハッシュ化するメッセージで初期化
    wc_Poly1305SetKey(&enc, key, sizeof(key));
    wc_Poly1305Update(key, msg, sizeof(msg));

    if ( wc_Poly1305Final(&enc, mac) != 0 ) {
    	// 最終MACの計算エラー
    }
    \endcode

    \sa wc_Poly1305SetKey
    \sa wc_Poly1305Update
*/
int wc_Poly1305Final(Poly1305* poly1305, byte* tag);

/*!
    \ingroup Poly1305

    \brief キーがロードされた初期化済みのPoly1305構造体を受け取り、最新のTLS AEADパディングスキームを使用してMAC(タグ)を作成します。

    \return 0 成功
    \return BAD_FUNC_ARG ctx、input、またはtagがnullの場合、またはadditionalがnullでaddSzが0より大きい場合、またはtagSzがWC_POLY1305_MAC_SZ未満の場合に返されます。

    \param ctx 使用する初期化済みのPoly1305構造体
    \param additional 使用する追加データ
    \param addSz additionalバッファのサイズ
    \param input タグを作成する入力バッファ
    \param sz 入力バッファのサイズ
    \param tag 作成されたタグを保持するバッファ
    \param tagSz 入力タグバッファのサイズ(少なくともWC_POLY1305_MAC_SZ(16)である必要があります)

    _Example_
    \code
    Poly1305 ctx;
    byte key[] = { }; // ハッシュ化に使用する32バイトのキーで初期化
    byte additional[] = { }; // 追加データで初期化
    byte msg[] = { }; // メッセージで初期化
    byte tag[16];

    wc_Poly1305SetKey(&ctx, key, sizeof(key));
    if(wc_Poly1305_MAC(&ctx, additional, sizeof(additional), (byte*)msg,
    sizeof(msg), tag, sizeof(tag)) != 0)
    {
        // エラーを処理
    }
    \endcode

    \sa wc_Poly1305SetKey
    \sa wc_Poly1305Update
    \sa wcPoly1305Final
*/
int wc_Poly1305_MAC(Poly1305* ctx, const byte* additional, word32 addSz,
                    const byte* input, word32 sz, byte* tag, word32 tagSz);
