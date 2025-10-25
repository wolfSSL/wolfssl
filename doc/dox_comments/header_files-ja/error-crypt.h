/*!
    \ingroup Error

    \brief この関数は、特定のエラーコードに対するエラー文字列を指定されたバッファに格納します。

    \return none 戻り値なし。

    \param error 文字列を取得するエラーコード
    \param buffer エラー文字列を格納するバッファ。バッファは少なくともWOLFSSL_MAX_ERROR_SZ(80バイト)の長さである必要があります

    _Example_
    \code
    char errorMsg[WOLFSSL_MAX_ERROR_SZ];
    int err = wc_some_function();

    if( err != 0) { // エラーが発生
    	wc_ErrorString(err, errorMsg);
    }
    \endcode

    \sa wc_GetErrorString
*/
void wc_ErrorString(int err, char* buff);

/*!
    \ingroup Error

    \brief この関数は、特定のエラーコードに対するエラー文字列を返します。

    \return string エラーコードに対するエラー文字列を文字列リテラルとして返します。

    \param error 文字列を取得するエラーコード

    _Example_
    \code
    char * errorMsg;
    int err = wc_some_function();

    if( err != 0) { // エラーが発生
    	errorMsg = wc_GetErrorString(err);
    }
    \endcode

    \sa wc_ErrorString
*/
const char* wc_GetErrorString(int error);