/*!
    \ingroup OCSP

    \brief OCSPコンテキストを割り当てて初期化します。

    この関数は、OCSP操作で使用するためのWOLFSSL_OCSP構造体を割り当てて初期化します。

    \param cm   証明書マネージャーへのポインタ。

    \return 成功時に割り当てられたWOLFSSL_OCSPへのポインタ
    \return 失敗時にNULL

    \sa wc_FreeOCSP
*/
WOLFSSL_OCSP* wc_NewOCSP(WOLFSSL_CERT_MANAGER* cm);

/*!
    \ingroup OCSP

    \brief OCSPコンテキストに関連付けられたリソースを解放します。

    この関数は、WOLFSSL_OCSP構造体に関連付けられたすべてのリソースを解放します。

    \param ocsp 解放するWOLFSSL_OCSP構造体へのポインタ。

    \return void

    \sa wc_NewOCSP
*/
void wc_FreeOCSP(WOLFSSL_OCSP* ocsp);

/*!
    \ingroup OCSP

    \brief 指定された証明書のOCSPレスポンスをチェックします。

    この関数は、特定の証明書のOCSPレスポンスを検証します。

    \param ocsp       WOLFSSL_OCSP構造体へのポインタ。
    \param cert       デコードされた証明書へのポインタ。
    \param response   OCSPレスポンスバッファへのポインタ。
    \param responseSz OCSPレスポンスバッファのサイズ。
    \param heap       オプションのヒープポインタ。

    \return 0 成功時
    \return <0 失敗時
*/
int wc_CheckCertOcspResponse(WOLFSSL_OCSP *ocsp, DecodedCert *cert, byte *response, int responseSz, void* heap);
