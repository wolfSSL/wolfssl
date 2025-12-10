/*!
    \ingroup wolfCrypt

    \brief wolfCryptで使用されるリソースを初期化するために使用されます。

    \return 0 成功時。
    \return <0 リソースの初期化に失敗した場合。

    \param none パラメータなし。

    _Example_
    \code
    ...
    if (wolfCrypt_Init() != 0) {
        WOLFSSL_MSG("Error with wolfCrypt_Init call");
    }
    \endcode

    \sa wolfCrypt_Cleanup
*/
int wolfCrypt_Init(void);

/*!
    \ingroup wolfCrypt

    \brief wolfCryptで使用されるリソースをクリーンアップするために使用されます。

    \return 0 成功時。
    \return <0 リソースのクリーンアップに失敗した場合。

    \param none パラメータなし。

    _Example_
    \code
    ...
    if (wolfCrypt_Cleanup() != 0) {
        WOLFSSL_MSG("Error with wolfCrypt_Cleanup call");
    }
    \endcode

    \sa wolfCrypt_Init
*/
int wolfCrypt_Cleanup(void);
