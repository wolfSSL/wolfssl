/*!
    \ingroup Logging

    \brief この関数は、wolfSSLログメッセージを処理するために使用されるロギングコールバックを登録します。デフォルトでは、システムがサポートしている場合、stderrへのfprintf()が使用されますが、この関数を使用することでユーザーは任意の処理を行うことができます。

    \return Success 成功した場合、この関数は0を返します。
    \return BAD_FUNC_ARG 関数ポインタが提供されていない場合に返されるエラーです。

    \param log_function ロギングコールバックとして登録する関数。
    関数シグネチャは上記のプロトタイプに従う必要があります。

    _Example_
    \code
    int ret = 0;
    // ロギングコールバックのプロトタイプ
    void MyLoggingCallback(const int logLevel, const char* const logMessage);
    // カスタムロギングコールバックをwolfSSLに登録
    ret = wolfSSL_SetLoggingCb(MyLoggingCallback);
    if (ret != 0) {
	    // ロギングコールバックの設定に失敗
    }
    void MyLoggingCallback(const int logLevel, const char* const logMessage)
    {
	// カスタムロギング関数
    }
    \endcode

    \sa wolfSSL_Debugging_ON
    \sa wolfSSL_Debugging_OFF
*/
int wolfSSL_SetLoggingCb(wolfSSL_Logging_cb log_function);

/*!
    \ingroup Debug

    \brief ビルド時にロギングが有効になっている場合、この関数は実行時にロギングを有効にします。ビルド時にロギングを有効にするには、--enable-debugを使用するか、DEBUG_WOLFSSLを定義します。

    \return 0 成功時。
    \return NOT_COMPILED_IN このビルドでロギングが有効になっていない場合に返されるエラーです。

    \param none パラメータなし。

    _Example_
    \code
    wolfSSL_Debugging_ON();
    \endcode

    \sa wolfSSL_Debugging_OFF
    \sa wolfSSL_SetLoggingCb
*/
int  wolfSSL_Debugging_ON(void);

/*!
    \ingroup Debug

    \brief この関数は、実行時のロギングメッセージを無効にします。既に無効になっている場合、何も行われません。

    \return none 戻り値なし。

    \param none パラメータなし。

    _Example_
    \code
    wolfSSL_Debugging_OFF();
    \endcode

    \sa wolfSSL_Debugging_ON
    \sa wolfSSL_SetLoggingCb
*/
void wolfSSL_Debugging_OFF(void);