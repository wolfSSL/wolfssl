/*!
    \ingroup Compression

    \brief この関数は、ハフマン符号化を使用して指定された入力データを圧縮し、出力をoutに格納します。出力バッファは入力バッファよりも大きくする必要があることに注意してください。圧縮が不可能な特定の入力が存在する場合でも、ルックアップテーブルが必要になるためです。出力バッファにはsrcSz + 0.1% + 12を割り当てることが推奨されます。

    \return 入力データの圧縮に成功した場合、出力バッファに格納されたバイト数を返します
    \return COMPRESS_INIT_E 圧縮用のストリームの初期化中にエラーが発生した場合に返されます
    \return COMPRESS_E 圧縮中にエラーが発生した場合に返されます

    \param out 圧縮されたデータを格納する出力バッファへのポインタ
    \param outSz 格納に使用できる出力バッファのサイズ
    \param in 圧縮するメッセージを含むバッファへのポインタ
    \param inSz 圧縮する入力メッセージのサイズ
    \param flags 圧縮の動作を制御するフラグ。通常の解凍には0を使用します

    _Example_
    \code
    byte message[] = { // 圧縮するテキストを初期化 };
    byte compressed[(sizeof(message) + sizeof(message) * .001 + 12 )];
    // 少なくともsrcSz + .1% + 12を推奨

    if( wc_Compress(compressed, sizeof(compressed), message, sizeof(message),
    0) != 0){
    	// データの圧縮エラー
    }
    \endcode

    \sa wc_DeCompress
*/
int wc_Compress(byte* out, word32 outSz, const byte* in, word32 inSz, word32 flags);

/*!
    \ingroup Compression

    \brief この関数は、ハフマン符号化を使用して指定された圧縮データを解凍し、出力をoutに格納します。

    \return Success 入力データの解凍に成功した場合、出力バッファに格納されたバイト数を返します
    \return COMPRESS_INIT_E: 圧縮用のストリームの初期化中にエラーが発生した場合に返されます
    \return COMPRESS_E: 圧縮中にエラーが発生した場合に返されます

    \param out 解凍されたデータを格納する出力バッファへのポインタ
    \param outSz 格納に使用できる出力バッファのサイズ
    \param in 解凍するメッセージを含むバッファへのポインタ
    \param inSz 解凍する入力メッセージのサイズ

    _Example_
    \code
    byte compressed[] = { // 圧縮されたメッセージを初期化 };
    byte decompressed[MAX_MESSAGE_SIZE];

    if( wc_DeCompress(decompressed, sizeof(decompressed),
    compressed, sizeof(compressed)) != 0 ) {
    	// データの解凍エラー
    }
    \endcode

    \sa wc_Compress
*/
int wc_DeCompress(byte* out, word32 outSz, const byte* in, word32 inSz);