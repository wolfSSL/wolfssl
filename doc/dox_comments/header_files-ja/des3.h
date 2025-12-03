/*!
    \ingroup 3DES

    \brief この関数は、引数として与えられたDes構造体の鍵と初期化ベクトル(iv)を設定します。また、暗号化と復号に必要なバッファがまだ初期化されていない場合、それらを初期化し、スペースを割り当てます。注意: ivが提供されない場合(つまりiv == NULL)、初期化ベクトルはデフォルトで0のivになります。

    \return 0 Des構造体の鍵と初期化ベクトルの設定に成功した場合

    \param des 初期化するDes構造体へのポインタ
    \param key Des構造体を初期化するための8バイトの鍵を含むバッファへのポインタ
    \param iv Des構造体を初期化するための8バイトのivを含むバッファへのポインタ。これが提供されない場合、ivはデフォルトで0になります
    \param dir 暗号化の方向。有効なオプションは: DES_ENCRYPTIONとDES_DECRYPTIONです

    _Example_
    \code
    Des enc; // 暗号化に使用されるDes構造体
    int ret;
    byte key[] = { // 8バイトの鍵で初期化 };
    byte iv[]  = { // 8バイトのivで初期化 };

    ret = wc_Des_SetKey(&des, key, iv, DES_ENCRYPTION);
    if (ret != 0) {
    	// des構造体の初期化エラー
    }
    \endcode

    \sa wc_Des_SetIV
    \sa wc_Des3_SetKey
*/
int  wc_Des_SetKey(Des* des, const byte* key,
                               const byte* iv, int dir);

/*!
    \ingroup 3DES

    \brief この関数は、引数として与えられたDes構造体の初期化ベクトル(iv)を設定します。NULLのivが渡された場合、初期化ベクトルを0に設定します。

    \return none 戻り値なし。

    \param des ivを設定するDes構造体へのポインタ
    \param iv Des構造体を初期化するための8バイトのivを含むバッファへのポインタ。これが提供されない場合、ivはデフォルトで0になります

    _Example_
    \code
    Des enc; // 暗号化に使用されるDes構造体
    // wc_Des_SetKeyでencを初期化
    byte iv[]  = { // 8バイトのivで初期化 };
    wc_Des_SetIV(&enc, iv);
    }
    \endcode

    \sa wc_Des_SetKey
*/
void wc_Des_SetIV(Des* des, const byte* iv);

/*!
    \ingroup 3DES

    \brief この関数は、入力メッセージinを暗号化し、結果を出力バッファoutに格納します。暗号ブロック連鎖(CBC)モードのDES暗号化を使用します。

    \return 0 指定された入力メッセージの暗号化に成功した場合に返されます

    \param des 暗号化に使用するDes構造体へのポインタ
    \param out 暗号化された暗号文を格納するバッファへのポインタ
    \param in 暗号化するメッセージを含む入力バッファへのポインタ
    \param sz 暗号化するメッセージの長さ

    _Example_
    \code
    Des enc; // 暗号化に使用されるDes構造体
    // wc_Des_SetKeyでencを初期化、モードDES_ENCRYPTIONを使用

    byte plain[]  = { // メッセージで初期化 };
    byte cipher[sizeof(plain)];

    if ( wc_Des_CbcEncrypt(&enc, cipher, plain, sizeof(plain)) != 0) {
	    // メッセージの暗号化エラー
    }
    \endcode

    \sa wc_Des_SetKey
    \sa wc_Des_CbcDecrypt
*/
int  wc_Des_CbcEncrypt(Des* des, byte* out,
                                   const byte* in, word32 sz);

/*!
    \ingroup 3DES

    \brief この関数は、入力暗号文inを復号し、結果の平文を出力バッファoutに格納します。暗号ブロック連鎖(CBC)モードのDES暗号化を使用します。

    \return 0 指定された暗号文の復号に成功した場合に返されます

    \param des 復号に使用するDes構造体へのポインタ
    \param out 復号された平文を格納するバッファへのポインタ
    \param in 暗号化された暗号文を含む入力バッファへのポインタ
    \param sz 復号する暗号文の長さ

    _Example_
    \code
    Des dec; // 復号に使用されるDes構造体
    // wc_Des_SetKeyでdecを初期化、モードDES_DECRYPTIONを使用

    byte cipher[]  = { // 暗号文で初期化 };
    byte decoded[sizeof(cipher)];

    if ( wc_Des_CbcDecrypt(&dec, decoded, cipher, sizeof(cipher)) != 0) {
    	// メッセージの復号エラー
    }
    \endcode

    \sa wc_Des_SetKey
    \sa wc_Des_CbcEncrypt
*/
int  wc_Des_CbcDecrypt(Des* des, byte* out,
                                   const byte* in, word32 sz);

/*!
    \ingroup 3DES

    \brief この関数は、入力メッセージinを暗号化し、結果を出力バッファoutに格納します。電子コードブック(ECB)モードのDes暗号化を使用します。

    \return 0: 指定された平文の暗号化に成功した場合に返されます。

    \param des 暗号化に使用するDes構造体へのポインタ
    \param out 暗号化されたメッセージを格納するバッファへのポインタ
    \param in 暗号化する平文を含む入力バッファへのポインタ
    \param sz 暗号化する平文の長さ

    _Example_
    \code
    Des enc; // 暗号化に使用されるDes構造体
    // wc_Des_SetKeyでencを初期化、モードDES_ENCRYPTIONを使用

    byte plain[]  = { // 暗号化するメッセージで初期化 };
    byte cipher[sizeof(plain)];

    if ( wc_Des_EcbEncrypt(&enc,cipher, plain, sizeof(plain)) != 0) {
    	// メッセージの暗号化エラー
    }
    \endcode

    \sa wc_Des_SetKe
*/
int  wc_Des_EcbEncrypt(Des* des, byte* out,
                                   const byte* in, word32 sz);

/*!
    \ingroup 3DES

    \brief この関数は、入力メッセージinを暗号化し、結果を出力バッファoutに格納します。電子コードブック(ECB)モードのDes3暗号化を使用します。警告: ほぼすべてのユースケースで、ECBモードは安全性が低いと考えられています。可能な限りECB APIを直接使用することは避けてください。

    \return 0 指定された平文の暗号化に成功した場合に返されます

    \param des3 暗号化に使用するDes3構造体へのポインタ
    \param out 暗号化されたメッセージを格納するバッファへのポインタ
    \param in 暗号化する平文を含む入力バッファへのポインタ
    \param sz 暗号化する平文の長さ

    _Example_
    \code
    Des3 enc; // 暗号化に使用されるDes3構造体
    // wc_Des3_SetKeyでencを初期化、モードDES_ENCRYPTIONを使用

    byte plain[]  = { // 暗号化するメッセージで初期化 };
    byte cipher[sizeof(plain)];

    if ( wc_Des3_EcbEncrypt(&enc,cipher, plain, sizeof(plain)) != 0) {
        // メッセージの暗号化エラー
    }
    \endcode

    \sa wc_Des3_SetKey
*/
int wc_Des3_EcbEncrypt(Des3* des, byte* out,
                                   const byte* in, word32 sz);

/*!
    \ingroup 3DES

    \brief この関数は、引数として与えられたDes3構造体の鍵と初期化ベクトル(iv)を設定します。また、暗号化と復号に必要なバッファがまだ初期化されていない場合、それらを初期化し、スペースを割り当てます。注意: ivが提供されない場合(つまりiv == NULL)、初期化ベクトルはデフォルトで0のivになります。

    \return 0 Des構造体の鍵と初期化ベクトルの設定に成功した場合

    \param des3 初期化するDes3構造体へのポインタ
    \param key Des3構造体を初期化するための24バイトの鍵を含むバッファへのポインタ
    \param iv Des3構造体を初期化するための8バイトのivを含むバッファへのポインタ。これが提供されない場合、ivはデフォルトで0になります
    \param dir 暗号化の方向。有効なオプションは: DES_ENCRYPTIONとDES_DECRYPTIONです

    _Example_
    \code
    Des3 enc; // 暗号化に使用されるDes3構造体
    int ret;
    byte key[] = { // 24バイトの鍵で初期化 };
    byte iv[]  = { // 8バイトのivで初期化 };

    ret = wc_Des3_SetKey(&des, key, iv, DES_ENCRYPTION);
    if (ret != 0) {
    	// des構造体の初期化エラー
    }
    \endcode

    \sa wc_Des3_SetIV
    \sa wc_Des3_CbcEncrypt
    \sa wc_Des3_CbcDecrypt
*/
int  wc_Des3_SetKey(Des3* des, const byte* key,
                                const byte* iv,int dir);

/*!
    \ingroup 3DES

    \brief この関数は、引数として与えられたDes3構造体の初期化ベクトル(iv)を設定します。NULLのivが渡された場合、初期化ベクトルを0に設定します。

    \return none 戻り値なし。

    \param des ivを設定するDes3構造体へのポインタ
    \param iv Des3構造体を初期化するための8バイトのivを含むバッファへのポインタ。これが提供されない場合、ivはデフォルトで0になります

    _Example_
    \code
    Des3 enc; // 暗号化に使用されるDes3構造体
    // wc_Des3_SetKeyでencを初期化

    byte iv[]  = { // 8バイトのivで初期化 };

    wc_Des3_SetIV(&enc, iv);
    }
    \endcode

    \sa wc_Des3_SetKey
*/
int  wc_Des3_SetIV(Des3* des, const byte* iv);

/*!
    \ingroup 3DES

    \brief この関数は、入力メッセージinを暗号化し、結果を出力バッファoutに格納します。暗号ブロック連鎖(CBC)モードのトリプルDes(3DES)暗号化を使用します。

    \return 0 指定された入力メッセージの暗号化に成功した場合に返されます

    \param des 暗号化に使用するDes3構造体へのポインタ
    \param out 暗号化された暗号文を格納するバッファへのポインタ
    \param in 暗号化するメッセージを含む入力バッファへのポインタ
    \param sz 暗号化するメッセージの長さ

    _Example_
    \code
    Des3 enc; // 暗号化に使用されるDes3構造体
    // wc_Des3_SetKeyでencを初期化、モードDES_ENCRYPTIONを使用

    byte plain[]  = { // メッセージで初期化 };
    byte cipher[sizeof(plain)];

    if ( wc_Des3_CbcEncrypt(&enc, cipher, plain, sizeof(plain)) != 0) {
	    // メッセージの暗号化エラー
    }
    \endcode

    \sa wc_Des3_SetKey
    \sa wc_Des3_CbcDecrypt
*/
int  wc_Des3_CbcEncrypt(Des3* des, byte* out,
                                    const byte* in,word32 sz);

/*!
    \ingroup 3DES

    \brief この関数は、入力暗号文inを復号し、結果の平文を出力バッファoutに格納します。暗号ブロック連鎖(CBC)モードのトリプルDes(3DES)暗号化を使用します。

    \return 0 指定された暗号文の復号に成功した場合に返されます

    \param des 復号に使用するDes3構造体へのポインタ
    \param out 復号された平文を格納するバッファへのポインタ
    \param in 暗号化された暗号文を含む入力バッファへのポインタ
    \param sz 復号する暗号文の長さ

    _Example_
    \code
    Des3 dec; // 復号に使用されるDes構造体
    // wc_Des3_SetKeyでdecを初期化、モードDES_DECRYPTIONを使用

    byte cipher[]  = { // 暗号文で初期化 };
    byte decoded[sizeof(cipher)];

    if ( wc_Des3_CbcDecrypt(&dec, decoded, cipher, sizeof(cipher)) != 0) {
    	// メッセージの復号エラー
    }
    \endcode

    \sa wc_Des3_SetKey
    \sa wc_Des3_CbcEncrypt
*/
int  wc_Des3_CbcDecrypt(Des3* des, byte* out,
                                    const byte* in,word32 sz);
