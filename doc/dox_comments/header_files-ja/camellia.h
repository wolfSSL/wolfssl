/*!
    \ingroup Camellia

    \brief この関数は、camelliaオブジェクトのキーと初期化ベクトルを設定し、暗号として使用するために初期化します。

    \return 0 キーと初期化ベクトルの設定に成功した場合に返されます
    \return BAD_FUNC_ARG 入力引数の1つの処理中にエラーが発生した場合に返されます
    \return MEMORY_E XMALLOCでメモリ割り当て中にエラーが発生した場合に返されます

    \param cam キーとivを設定するcamellia構造体へのポインタ
    \param key 暗号化と復号に使用する16、24、または32バイトのキーを含むバッファへのポインタ
    \param len 渡されるキーの長さ
    \param iv このcamellia構造体で使用する16バイトの初期化ベクトルを含むバッファへのポインタ

    _Example_
    \code
    Camellia cam;
    byte key[32];
    // キーを初期化
    byte iv[16];
    // ivを初期化
    if( wc_CamelliaSetKey(&cam, key, sizeof(key), iv) != 0) {
    	// camellia構造体の初期化エラー
    }
    \endcode

    \sa wc_CamelliaEncryptDirect
    \sa wc_CamelliaDecryptDirect
    \sa wc_CamelliaCbcEncrypt
    \sa wc_CamelliaCbcDecrypt
*/
int  wc_CamelliaSetKey(wc_Camellia* cam, const byte* key, word32 len,
                                   const byte* iv);

/*!
    \ingroup Camellia

    \brief この関数は、camelliaオブジェクトの初期化ベクトルを設定します。

    \return 0 キーと初期化ベクトルの設定に成功した場合に返されます
    \return BAD_FUNC_ARG 入力引数の1つの処理中にエラーが発生した場合に返されます

    \param cam ivを設定するcamellia構造体へのポインタ
    \param iv このcamellia構造体で使用する16バイトの初期化ベクトルを含むバッファへのポインタ

    _Example_
    \code
    Camellia cam;
    byte iv[16];
    // ivを初期化
    if( wc_CamelliaSetIV(&cam, iv) != 0) {
	// camellia構造体の初期化エラー
    }
    \endcode

    \sa wc_CamelliaSetKey
*/
int  wc_CamelliaSetIV(wc_Camellia* cam, const byte* iv);

/*!
    \ingroup Camellia

    \brief この関数は、提供されたcamelliaオブジェクトを使用して1ブロックの暗号化を行います。バッファinから最初の16バイトブロックを解析し、暗号化された結果をバッファoutに格納します。この関数を使用する前に、wc_CamelliaSetKeyを使用してcamelliaオブジェクトを初期化する必要があります。

    \return none 戻り値なし。

    \param cam 暗号化に使用するcamellia構造体へのポインタ
    \param out 暗号化されたブロックを格納するバッファへのポインタ
    \param in 暗号化する平文ブロックを含むバッファへのポインタ

    _Example_
    \code
    Camellia cam;
    // キーとivでcam構造体を初期化
    byte plain[] = { // 暗号化するメッセージで初期化 };
    byte cipher[16];

    wc_CamelliaEncryptDirect(&ca, cipher, plain);
    \endcode

    \sa wc_CamelliaDecryptDirect
*/
int  wc_CamelliaEncryptDirect(wc_Camellia* cam, byte* out,
                                                                const byte* in);

/*!
    \ingroup Camellia

    \brief この関数は、提供されたcamelliaオブジェクトを使用して1ブロックの復号を行います。バッファinから最初の16バイトブロックを解析し、復号して、結果をバッファoutに格納します。この関数を使用する前に、wc_CamelliaSetKeyを使用してcamelliaオブジェクトを初期化する必要があります。

    \return none 戻り値なし。

    \param cam 暗号化に使用するcamellia構造体へのポインタ
    \param out 復号された平文ブロックを格納するバッファへのポインタ
    \param in 復号する暗号文ブロックを含むバッファへのポインタ

    _Example_
    \code
    Camellia cam;
    // キーとivでcam構造体を初期化
    byte cipher[] = { // 復号する暗号化されたメッセージで初期化 };
    byte decrypted[16];

    wc_CamelliaDecryptDirect(&cam, decrypted, cipher);
    \endcode

    \sa wc_CamelliaEncryptDirect
*/
int  wc_CamelliaDecryptDirect(wc_Camellia* cam, byte* out,
                                                                const byte* in);

/*!
    \ingroup Camellia

    \brief この関数は、バッファinから平文を暗号化し、出力をバッファoutに格納します。暗号ブロック連鎖(CBC)モードのCamelliaを使用してこの暗号化を実行します。

    \return none 戻り値なし。

    \param cam 暗号化に使用するcamellia構造体へのポインタ
    \param out 暗号化された暗号文を格納するバッファへのポインタ
    \param in 暗号化する平文を含むバッファへのポインタ
    \param sz 暗号化するメッセージのサイズ

    _Example_
    \code
    Camellia cam;
    // キーとivでcam構造体を初期化
    byte plain[] = { // 復号する暗号化されたメッセージで初期化 };
    byte cipher[sizeof(plain)];

    wc_CamelliaCbcEncrypt(&cam, cipher, plain, sizeof(plain));
    \endcode

    \sa wc_CamelliaCbcDecrypt
*/
int wc_CamelliaCbcEncrypt(wc_Camellia* cam,
                                          byte* out, const byte* in, word32 sz);

/*!
    \ingroup Camellia

    \brief この関数は、バッファinから暗号文を復号し、出力をバッファoutに格納します。暗号ブロック連鎖(CBC)モードのCamelliaを使用してこの復号を実行します。

    \return none 戻り値なし。

    \param cam 暗号化に使用するcamellia構造体へのポインタ
    \param out 復号されたメッセージを格納するバッファへのポインタ
    \param in 暗号化された暗号文を含むバッファへのポインタ
    \param sz 暗号化するメッセージのサイズ

    _Example_
    \code
    Camellia cam;
    // キーとivでcam構造体を初期化
    byte cipher[] = { // 復号する暗号化されたメッセージで初期化 };
    byte decrypted[sizeof(cipher)];

    wc_CamelliaCbcDecrypt(&cam, decrypted, cipher, sizeof(cipher));
    \endcode

    \sa wc_CamelliaCbcEncrypt
*/
int wc_CamelliaCbcDecrypt(wc_Camellia* cam,
                                          byte* out, const byte* in, word32 sz);
