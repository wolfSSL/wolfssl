/*!
    \ingroup ChaCha

    \brief この関数は、ChaChaオブジェクトの初期化ベクトル(nonce)を設定し、暗号として使用するために初期化します。wc_Chacha_SetKeyを使用してキーが設定された後に呼び出す必要があります。暗号化のラウンドごとに異なるnonceを使用する必要があります。

    \return 0 初期化ベクトルの設定に成功した場合に返されます
    \return BAD_FUNC_ARG ctx入力引数の処理中にエラーが発生した場合に返されます

    \param ctx ivを設定するChaCha構造体へのポインタ
    \param inIv ChaCha構造体を初期化するための12バイトの初期化ベクトルを含むバッファへのポインタ
    \param counter ブロックカウンタが開始すべき値--通常はゼロ。

    _Example_
    \code
    ChaCha enc;
    // wc_Chacha_SetKeyでencを初期化
    byte iv[12];
    // ivを初期化
    if( wc_Chacha_SetIV(&enc, iv, 0) != 0) {
	    // ChaCha構造体の初期化エラー
    }
    \endcode

    \sa wc_Chacha_SetKey
    \sa wc_Chacha_Process
*/
int wc_Chacha_SetIV(ChaCha* ctx, const byte* inIv, word32 counter);

/*!
    \ingroup ChaCha

    \brief この関数は、バッファinputからテキストを処理し、暗号化または復号して、結果をバッファoutputに格納します。

    \return 0 入力の暗号化または復号に成功した場合に返されます
    \return BAD_FUNC_ARG ctx入力引数の処理中にエラーが発生した場合に返されます

    \param ctx ivを設定するChaCha構造体へのポインタ
    \param output 出力暗号文または復号された平文を格納するバッファへのポインタ
    \param input 暗号化する入力平文または復号する入力暗号文を含むバッファへのポインタ
    \param msglen 暗号化するメッセージまたは復号する暗号文の長さ

    _Example_
    \code
    ChaCha enc;
    // wc_Chacha_SetKeyとwc_Chacha_SetIVでencを初期化

    byte plain[] = { // 平文を初期化 };
    byte cipher[sizeof(plain)];
    if( wc_Chacha_Process(&enc, cipher, plain, sizeof(plain)) != 0) {
	    // ChaCha暗号の処理エラー
    }
    \endcode

    \sa wc_Chacha_SetKey
    \sa wc_Chacha_Process
*/
int wc_Chacha_Process(ChaCha* ctx, byte* cipher, const byte* plain,
                              word32 msglen);

/*!
    \ingroup ChaCha

    \brief この関数は、ChaChaオブジェクトのキーを設定し、暗号として使用するために初期化します。wc_Chacha_SetIVでnonceを設定する前、およびwc_Chacha_Processで暗号化に使用する前に呼び出す必要があります。

    \return 0 キーの設定に成功した場合に返されます
    \return BAD_FUNC_ARG ctx入力引数の処理中にエラーが発生した場合、またはキーが16バイトまたは32バイトでない場合に返されます

    \param ctx キーを設定するChaCha構造体へのポインタ
    \param key ChaCha構造体を初期化するための16バイトまたは32バイトのキーを含むバッファへのポインタ
    \param keySz 渡されるキーの長さ

    _Example_
    \code
    ChaCha enc;
    byte key[] = { // キーを初期化 };

    if( wc_Chacha_SetKey(&enc, key, sizeof(key)) != 0) {
	    // ChaCha構造体の初期化エラー
    }
    \endcode

    \sa wc_Chacha_SetIV
    \sa wc_Chacha_Process
*/
int wc_Chacha_SetKey(ChaCha* ctx, const byte* key, word32 keySz);
