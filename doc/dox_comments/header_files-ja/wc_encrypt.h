/*!
    \ingroup AES
    \brief 入力バッファinから暗号を復号し、結果の平文をAESを使用した暗号ブロック連鎖を使用して出力バッファoutに格納します。この関数は、AES構造体を初期化する必要はありません。代わりに、キーとiv(初期化ベクトル)を受け取り、これらを使用してAESオブジェクトを初期化し、暗号文を復号します。

    \return 0 メッセージの復号に成功した場合
    \return BAD_ALIGN_E ブロックアライメントエラーが発生した場合に返されます
    \return BAD_FUNC_ARG AesSetIV中にキー長が無効またはAESオブジェクトがnullの場合に返されます
    \return MEMORY_E WOLFSSL_SMALL_STACKが有効で、XMALLOCがAESオブジェクトのインスタンス化に失敗した場合に返されます。

    \param out 復号されたメッセージの平文を格納する出力バッファへのポインタ
    \param in 復号する暗号文を含む入力バッファへのポインタ
    \param inSz 入力メッセージのサイズ
    \param key 復号用の16、24、または32バイトの秘密鍵
    \param keySz 復号に使用するキーのサイズ

    _Example_
    \code
    int ret = 0;
    byte key[] = { 16、24、または32バイトのキー };
    byte iv[]  = { 16バイトのiv };
    byte cipher[AES_BLOCK_SIZE * n]; //nは正の整数で、cipherを16バイトの倍数にする
    // cipherを暗号文で埋める
    byte plain [AES_BLOCK_SIZE * n];
    if ((ret = wc_AesCbcDecryptWithKey(plain, cipher, AES_BLOCK_SIZE, key,
    AES_BLOCK_SIZE, iv)) != 0 ) {
	// 復号エラー
    }
    \endcode

    \sa wc_AesSetKey
    \sa wc_AesSetIV
    \sa wc_AesCbcEncrypt
    \sa wc_AesCbcDecrypt
*/
int  wc_AesCbcDecryptWithKey(byte* out, const byte* in, word32 inSz,
                                         const byte* key, word32 keySz,
                                         const byte* iv);

/*!
    \ingroup 3DES

    \brief この関数は、入力暗号文inを復号し、結果の平文を出力バッファoutに格納します。暗号ブロック連鎖(CBC)モードのDES暗号化を使用します。この関数はwc_Des_CbcDecryptの代替で、ユーザーがDes構造体を直接インスタンス化せずにメッセージを復号できるようにします。

    \return 0 指定された暗号文の復号に成功した場合に返されます
    \return MEMORY_E Des構造体用のスペース割り当て中にエラーが発生した場合に返されます

    \param out 復号された平文を格納するバッファへのポインタ
    \param in 暗号化された暗号文を含む入力バッファへのポインタ
    \param sz 復号する暗号文の長さ
    \param key 復号に使用する8バイトのキーを含むバッファへのポインタ
    \param iv 復号に使用する8バイトのivを含むバッファへのポインタ。ivが提供されない場合、ivはデフォルトで0になります

    _Example_
    \code
    int ret;
    byte key[] = { // 8バイトのキーで初期化 };
    byte iv[]  = { // 8バイトのivで初期化 };

    byte cipher[]  = { // 暗号文で初期化 };
    byte decoded[sizeof(cipher)];

    if ( wc_Des_CbcDecryptWithKey(decoded, cipher, sizeof(cipher), key,
    iv) != 0) {
    	// メッセージの復号エラー
    }
    \endcode

    \sa wc_Des_CbcDecrypt
*/
int  wc_Des_CbcDecryptWithKey(byte* out,
                                          const byte* in, word32 sz,
                                          const byte* key, const byte* iv);

/*!
    \ingroup 3DES

    \brief この関数は、入力平文inを暗号化し、結果の暗号文を出力バッファoutに格納します。暗号ブロック連鎖(CBC)モードのDES暗号化を使用します。この関数はwc_Des_CbcEncryptの代替で、ユーザーがDes構造体を直接インスタンス化せずにメッセージを暗号化できるようにします。

    \return 0 データの暗号化に成功した後に返されます。
    \return MEMORY_E Des構造体用のメモリ割り当て中にエラーが発生した場合に返されます。
    \return <0 暗号化中の任意のエラーで返されます。

    \param out 最終的に暗号化されたデータ
    \param in 暗号化されるデータ。Desブロックサイズにパディングされている必要があります。
    \param sz 入力バッファのサイズ。
    \param key 暗号化に使用するキーへのポインタ。
    \param iv 初期化ベクトル

    _Example_
    \code
    byte key[] = { // 8バイトのキーで初期化 };
    byte iv[]  = { // 8バイトのivで初期化 };
    byte in[] = { // 平文で初期化 };
    byte out[sizeof(in)];
    if ( wc_Des_CbcEncryptWithKey(&out, in, sizeof(in), key, iv) != 0)
    {
    	// メッセージの暗号化エラー
    }
    \endcode

    \sa wc_Des_CbcDecryptWithKey
    \sa wc_Des_CbcEncrypt
*/
int  wc_Des_CbcEncryptWithKey(byte* out,
                                          const byte* in, word32 sz,
                                          const byte* key, const byte* iv);

/*!
    \ingroup 3DES

    \brief この関数は、入力平文inを暗号化し、結果の暗号文を出力バッファoutに格納します。暗号ブロック連鎖(CBC)モードのトリプルDES(3DES)暗号化を使用します。この関数はwc_Des3_CbcEncryptの代替で、ユーザーがDes3構造体を直接インスタンス化せずにメッセージを暗号化できるようにします。

    \return 0 データの暗号化に成功した後に返されます。
    \return MEMORY_E Des構造体用のメモリ割り当て中にエラーが発生した場合に返されます。
    \return <0 暗号化中の任意のエラーで返されます。

    \param out 最終的に暗号化されたデータ
    \param in 暗号化されるデータ。Desブロックサイズにパディングされている必要があります。
    \param sz 入力バッファのサイズ。
    \param key 暗号化に使用するキーへのポインタ。
    \param iv 初期化ベクトル

    _Example_
    \code
    byte key[] = { // 8バイトのキーで初期化 };
    byte iv[]  = { // 8バイトのivで初期化 };

    byte in[] = { // 平文で初期化 };
    byte out[sizeof(in)];

    if ( wc_Des3_CbcEncryptWithKey(&out, in, sizeof(in), key, iv) != 0)
    {
    	// メッセージの暗号化エラー
    }
    \endcode

    \sa wc_Des3_CbcDecryptWithKey
    \sa wc_Des_CbcEncryptWithKey
    \sa wc_Des_CbcDecryptWithKey
*/
int  wc_Des3_CbcEncryptWithKey(byte* out,
                                           const byte* in, word32 sz,
                                           const byte* key, const byte* iv);

/*!
    \ingroup 3DES

    \brief この関数は、入力暗号文inを復号し、結果の平文を出力バッファoutに格納します。暗号ブロック連鎖(CBC)モードのトリプルDes(3DES)暗号化を使用します。この関数はwc_Des3_CbcDecryptの代替で、ユーザーがDes3構造体を直接インスタンス化せずにメッセージを復号できるようにします。

    \return 0 指定された暗号文の復号に成功した場合に返されます
    \return MEMORY_E Des構造体用のスペース割り当て中にエラーが発生した場合に返されます

    \param out 復号された平文を格納するバッファへのポインタ
    \param in 暗号化された暗号文を含む入力バッファへのポインタ
    \param sz 復号する暗号文の長さ
    \param key 復号に使用する24バイトのキーを含むバッファへのポインタ
    \param iv 復号に使用する8バイトのivを含むバッファへのポインタ。ivが提供されない場合、ivはデフォルトで0になります

    _Example_
    \code
    int ret;
    byte key[] = { // 24バイトのキーで初期化 };
    byte iv[]  = { // 8バイトのivで初期化 };

    byte cipher[]  = { // 暗号文で初期化 };
    byte decoded[sizeof(cipher)];

    if ( wc_Des3_CbcDecryptWithKey(decoded, cipher, sizeof(cipher),
    key, iv) != 0) {
    	// メッセージの復号エラー
    }
    \endcode

    \sa wc_Des3_CbcDecrypt
*/
int  wc_Des3_CbcDecryptWithKey(byte* out,
                                           const byte* in, word32 sz,
                                           const byte* key, const byte* iv);
