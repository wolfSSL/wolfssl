/*!
    \ingroup Base_Encoding

    \brief この関数は、指定されたBase64エンコードされた入力inを復号し、結果を出力バッファoutに格納します。また、変数outLenに出力バッファに書き込まれたサイズを設定します。

    \return 0 Base64エンコードされた入力の復号に成功した場合に返されます
    \return BAD_FUNC_ARG 出力バッファが復号された入力を格納するには小さすぎる場合に返されます
    \return ASN_INPUT_E 入力バッファ内の文字がBase64の範囲([A-Za-z0-9+/=])外にある場合、またはBase64エンコードされた入力に無効な行末がある場合に返されます

    \param in 復号する入力バッファへのポインタ
    \param inLen 復号する入力バッファの長さ
    \param out 復号されたメッセージを格納する出力バッファへのポインタ
    \param outLen 出力バッファの長さへのポインタ。関数呼び出しの最後に書き込まれたバイト数で更新されます

    _Example_
    \code
    byte encoded[] = { // 復号するテキストを初期化 };
    byte decoded[sizeof(encoded)];
    // 少なくとも(sizeof(encoded) * 3 + 3) / 4のスペースが必要

    int outLen = sizeof(decoded);

    if( Base64_Decode(encoded,sizeof(encoded), decoded, &outLen) != 0 ) {
    	// 入力バッファの復号エラー
    }
    \endcode

    \sa Base64_Encode
    \sa Base16_Decode
*/
int Base64_Decode(const byte* in, word32 inLen, byte* out,
                               word32* outLen);

/*!
    \ingroup Base_Encoding

    \brief この関数は、指定された入力inをエンコードし、Base64エンコードされた結果を出力バッファoutに格納します。エスケープされた%0A行末の代わりに、従来の'\n'行末でデータを書き込みます。正常に完了すると、この関数はoutLenを出力バッファに書き込まれたバイト数に設定します。

    \return 0 Base64エンコードされた入力の復号に成功した場合に返されます
    \return BAD_FUNC_ARG 出力バッファがエンコードされた入力を格納するには小さすぎる場合に返されます
    \return BUFFER_E エンコード中に出力バッファのスペースが不足した場合に返されます

    \param in エンコードする入力バッファへのポインタ
    \param inLen エンコードする入力バッファの長さ
    \param out エンコードされたメッセージを格納する出力バッファへのポインタ
    \param outLen エンコードされたメッセージを格納する出力バッファの長さへのポインタ

    _Example_
    \code
    byte plain[] = { // エンコードするテキストを初期化 };
    byte encoded[MAX_BUFFER_SIZE];

    int outLen = sizeof(encoded);

    if( Base64_Encode(plain, sizeof(plain), encoded, &outLen) != 0 ) {
    	// 入力バッファのエンコードエラー
    }
    \endcode

    \sa Base64_EncodeEsc
    \sa Base64_Decode
*/

int Base64_Encode(const byte* in, word32 inLen, byte* out,
                                  word32* outLen);

/*!
    \ingroup Base_Encoding

    \brief この関数は、指定された入力inをエンコードし、Base64エンコードされた結果を出力バッファoutに格納します。'\n'行末の代わりに%0Aエスケープされた行末でデータを書き込みます。正常に完了すると、この関数はoutLenを出力バッファに書き込まれたバイト数に設定します。

    \return 0 Base64エンコードされた入力の復号に成功した場合に返されます
    \return BAD_FUNC_ARG 出力バッファがエンコードされた入力を格納するには小さすぎる場合に返されます
    \return BUFFER_E エンコード中に出力バッファのスペースが不足した場合に返されます
    \return ASN_INPUT_E 入力メッセージの復号処理中にエラーが発生した場合に返されます

    \param in エンコードする入力バッファへのポインタ
    \param inLen エンコードする入力バッファの長さ
    \param out エンコードされたメッセージを格納する出力バッファへのポインタ
    \param outLen エンコードされたメッセージを格納する出力バッファの長さへのポインタ

    _Example_
    \code
    byte plain[] = { // エンコードするテキストを初期化 };
    byte encoded[MAX_BUFFER_SIZE];

    int outLen = sizeof(encoded);

    if( Base64_EncodeEsc(plain, sizeof(plain), encoded, &outLen) != 0 ) {
    	// 入力バッファのエンコードエラー
    }
    \endcode

    \sa Base64_Encode
    \sa Base64_Decode
*/
int Base64_EncodeEsc(const byte* in, word32 inLen, byte* out,
                                  word32* outLen);

/*!
    \ingroup Base_Encoding

    \brief この関数は、指定された入力inをエンコードし、Base64エンコードされた結果を出力バッファoutに格納します。改行なしでデータを書き込みます。正常に完了すると、この関数はoutLenを出力バッファに書き込まれたバイト数に設定します。

    \return 0 Base64エンコードされた入力の復号に成功した場合に返されます
    \return BAD_FUNC_ARG 出力バッファがエンコードされた入力を格納するには小さすぎる場合に返されます
    \return BUFFER_E エンコード中に出力バッファのスペースが不足した場合に返されます
    \return ASN_INPUT_E 入力メッセージの復号処理中にエラーが発生した場合に返されます

    \param in エンコードする入力バッファへのポインタ
    \param inLen エンコードする入力バッファの長さ
    \param out エンコードされたメッセージを格納する出力バッファへのポインタ
    \param outLen エンコードされたメッセージを格納する出力バッファの長さへのポインタ

    _Example_
    \code
    byte plain[] = { // エンコードするテキストを初期化 };
    byte encoded[MAX_BUFFER_SIZE];
    int outLen = sizeof(encoded);
    if( Base64_Encode_NoNl(plain, sizeof(plain), encoded, &outLen) != 0 ) {
    	// 入力バッファのエンコードエラー
    }
    \endcode

    \sa Base64_Encode
    \sa Base64_Decode
*/

int Base64_Encode_NoNl(const byte* in, word32 inLen, byte* out,
                                  word32* outLen);

/*!
    \ingroup Base_Encoding

    \brief この関数は、指定されたBase16エンコードされた入力inを復号し、結果を出力バッファoutに格納します。また、変数outLenに出力バッファに書き込まれたサイズを設定します。

    \return 0 Base16エンコードされた入力の復号に成功した場合に返されます
    \return BAD_FUNC_ARG 出力バッファが復号された入力を格納するには小さすぎる場合、または入力長が2の倍数でない場合に返されます
    \return ASN_INPUT_E 入力バッファ内の文字がBase16の範囲([0-9A-F])外にある場合に返されます

    \param in 復号する入力バッファへのポインタ
    \param inLen 復号する入力バッファの長さ
    \param out 復号されたメッセージを格納する出力バッファへのポインタ
    \param outLen 出力バッファの長さへのポインタ。関数呼び出しの最後に書き込まれたバイト数で更新されます

    _Example_
    \code
    byte encoded[] = { // 復号するテキストを初期化 };
    byte decoded[sizeof(encoded)];
    int outLen = sizeof(decoded);

    if( Base16_Decode(encoded,sizeof(encoded), decoded, &outLen) != 0 ) {
    	// 入力バッファの復号エラー
    }
    \endcode

    \sa Base64_Encode
    \sa Base64_Decode
    \sa Base16_Encode
*/

int Base16_Decode(const byte* in, word32 inLen, byte* out, word32* outLen);

/*!
    \ingroup Base_Encoding

    \brief 入力をbase16出力にエンコードします。

    \return 0 成功
    \return BAD_FUNC_ARG in、out、またはoutLenがnullの場合、またはoutLenがinLenの2倍プラス1未満の場合に返されます。

    \param in エンコードする入力バッファへのポインタ。
    \param inLen 入力バッファの長さ。
    \param out 出力バッファへのポインタ。
    \param outLen 出力バッファの長さ。エンコードされた出力の長さに設定されます。

    _Example_
    \code
    byte in[] = { // エンコードする何かの内容 };
    byte out[NECESSARY_OUTPUT_SIZE];
    word32 outSz = sizeof(out);

    if(Base16_Encode(in, sizeof(in), out, &outSz) != 0)
    {
        // エンコードエラーを処理
    }
    \endcode

    \sa Base64_Encode
    \sa Base64_Decode
    \sa Base16_Decode
*/

int Base16_Encode(const byte* in, word32 inLen, byte* out, word32* outLen);